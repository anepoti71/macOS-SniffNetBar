#!/usr/bin/env python3
import argparse
import os
import sqlite3
import subprocess

import coremltools as ct
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestRegressor


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
    return np.array(rows, dtype=np.float64)


def normalize_cont(cont):
    medians = np.median(cont, axis=0)
    iqrs = np.subtract(*np.percentile(cont, [75, 25], axis=0))
    cont = np.log1p(cont)
    cont = (cont - medians) / (iqrs + 1e-9)
    return cont, medians, iqrs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True, help="Output .mlmodel path")
    parser.add_argument("--compile", action="store_true", help="Compile to .mlmodelc")
    args = parser.parse_args()

    data = load_rows(args.db)
    if data.shape[0] < 500:
        raise SystemExit("not enough data to train (need at least 500 windows)")

    cont = data[:, : len(CONT_COLS)]
    extra = data[:, len(CONT_COLS) :]
    cont, medians, iqrs = normalize_cont(cont)
    features = np.concatenate([cont, extra], axis=1)

    # Train IsolationForest as teacher
    iforest = IsolationForest(
        n_estimators=200,
        max_samples=256,
        contamination=0.005,
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=1,
    )
    iforest.fit(features)
    raw = iforest.score_samples(features)
    score_min = float(raw.min())
    score_max = float(raw.max())
    scores = 1.0 - (raw - score_min) / (score_max - score_min + 1e-9)

    # Train a Core ML-compatible regressor to approximate the score
    regressor = RandomForestRegressor(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        n_jobs=1,
    )
    regressor.fit(features, scores)

    feature_names = CONT_COLS + EXTRA_COLS
    mlmodel = ct.converters.sklearn.convert(
        regressor,
        input_features=feature_names,
        output_feature_names="score",
    )
    mlmodel.save(args.out)

    if args.compile:
        output_dir = os.path.splitext(args.out)[0] + ".mlmodelc"
        subprocess.check_call(["xcrun", "coremlcompiler", "compile", args.out, output_dir])


if __name__ == "__main__":
    main()
