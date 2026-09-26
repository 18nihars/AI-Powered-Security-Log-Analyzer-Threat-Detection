"""
ml_detector.py
--------------
Unsupervised anomaly detection layer using scikit-learn's IsolationForest.

Why IsolationForest:
- No labeled attack data required (we rarely have clean labeled logs).
- Handles multi-dimensional behavioral features well.
- Cheap to retrain per batch of logs; fast at inference time.

The model scores every IP's behavior profile and flags the ones that are
"easy to isolate" from the rest of the crowd as anomalous. This catches
attack patterns that don't match a known rule signature (novel/zero-day
style behavioral anomalies), complementing rules.py.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "total_events", "failed_count", "fail_ratio", "unique_users",
    "unique_ports", "night_event_count", "events_per_minute",
    "avg_seconds_between_events", "min_seconds_between_events",
]


def run_anomaly_detection(feat_df: pd.DataFrame, contamination: float = 0.15, random_state: int = 42) -> pd.DataFrame:
    """Adds 'ml_anomaly_score' (0-1, higher = more anomalous) and
    'ml_is_anomaly' (bool) columns to a copy of feat_df."""
    df = feat_df.copy()

    if df.empty:
        df["ml_anomaly_score"] = []
        df["ml_is_anomaly"] = []
        return df

    X = df[FEATURE_COLUMNS].fillna(0).values

    # IsolationForest needs a reasonable sample size; with very few IPs the
    # notion of "outlier" is unstable, so we fall back to score 0 for tiny batches.
    if len(df) < 4:
        df["ml_anomaly_score"] = 0.0
        df["ml_is_anomaly"] = False
        return df

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=min(contamination, 0.5),
        random_state=random_state,
    )
    model.fit(X_scaled)

    # decision_function: higher = more normal, lower = more anomalous.
    raw_scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    # Normalize raw_scores to a 0-1 "anomaly score" (invert + min-max scale)
    inverted = -raw_scores
    min_v, max_v = inverted.min(), inverted.max()
    if max_v - min_v > 1e-9:
        normalized = (inverted - min_v) / (max_v - min_v)
    else:
        normalized = np.zeros_like(inverted)

    df["ml_anomaly_score"] = normalized
    df["ml_is_anomaly"] = preds == -1
    return df
