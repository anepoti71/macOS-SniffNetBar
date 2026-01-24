#!/usr/bin/env python3
import json
import sys

import joblib
import numpy as np


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "missing model path"}))
        return 1

    model_path = sys.argv[1]
    bundle = joblib.load(model_path)

    model = bundle["model"]
    medians = np.array(bundle["medians"], dtype=np.float64)
    iqrs = np.array(bundle["iqrs"], dtype=np.float64)
    cont_cols = bundle["cont_cols"]
    score_min = float(bundle.get("score_min", -0.5))
    score_max = float(bundle.get("score_max", 0.5))

    payload = json.load(sys.stdin)

    cont_values = np.array([payload[c] for c in cont_cols], dtype=np.float64)
    cont_values = np.log1p(cont_values)
    cont_values = (cont_values - medians) / (iqrs + 1e-9)

    extra_cols = bundle.get("extra_cols", [])
    extra_values = np.array([payload[c] for c in extra_cols], dtype=np.float64)

    features = np.concatenate([cont_values, extra_values])
    raw = model.score_samples([features])[0]

    norm = (raw - score_min) / (score_max - score_min + 1e-9)
    score = 1.0 - max(0.0, min(1.0, norm))

    print(json.dumps({"score": float(score)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
