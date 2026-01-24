#!/usr/bin/env python3
import argparse
import sqlite3

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


CONT_COLS = [
    "total_bytes",
    "total_packets",
    "unique_src_ports",
    "flow_count",
    "avg_pkt_size",
    "bytes_per_flow",
    "pkts_per_flow",
    "burstiness",
]

EXTRA_COLS = [
    "port_well_known",
    "port_registered",
    "port_dynamic",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
]


def load_rows(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cols = CONT_COLS + EXTRA_COLS
    cur.execute(
        "SELECT total_bytes, total_packets, unique_src_ports, flow_count, "
        "avg_pkt_size, bytes_per_flow, pkts_per_flow, burstiness, "
        "CASE WHEN dst_port BETWEEN 1 AND 1023 THEN 1 ELSE 0 END AS port_well_known, "
        "CASE WHEN dst_port BETWEEN 1024 AND 49151 THEN 1 ELSE 0 END AS port_registered, "
        "CASE WHEN dst_port BETWEEN 49152 AND 65535 THEN 1 ELSE 0 END AS port_dynamic, "
        "CASE WHEN proto = 0 THEN 1 ELSE 0 END AS proto_tcp, "
        "CASE WHEN proto = 1 THEN 1 ELSE 0 END AS proto_udp, "
        "CASE WHEN proto = 2 THEN 1 ELSE 0 END AS proto_icmp, "
        "CASE WHEN proto NOT IN (0,1,2) THEN 1 ELSE 0 END AS proto_other "
        "FROM anomaly_windows;"
    )
    rows = cur.fetchall()
    conn.close()
    return cols, np.array(rows, dtype=np.float64)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    cols, data = load_rows(args.db)
    if data.shape[0] < 100:
        raise SystemExit("not enough data to train (need at least 100 windows)")

    cont = data[:, : len(CONT_COLS)]
    medians = np.median(cont, axis=0)
    iqrs = np.subtract(*np.percentile(cont, [75, 25], axis=0))

    cont = np.log1p(cont)
    cont = (cont - medians) / (iqrs + 1e-9)
    extra = data[:, len(CONT_COLS) :]
    features = np.concatenate([cont, extra], axis=1)

    model = IsolationForest(
        n_estimators=200,
        max_samples=256,
        contamination=0.005,
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=1,
    )
    model.fit(features)

    raw_scores = model.score_samples(features)
    score_min = float(raw_scores.min())
    score_max = float(raw_scores.max())

    joblib.dump(
        {
            "model": model,
            "medians": medians.tolist(),
            "iqrs": iqrs.tolist(),
            "cont_cols": CONT_COLS,
            "extra_cols": EXTRA_COLS,
            "score_min": score_min,
            "score_max": score_max,
        },
        args.out,
    )


if __name__ == "__main__":
    main()
