"""
threat_engine.py
-----------------
Combines rule_score (explainable, rule-based) and ml_anomaly_score
(unsupervised, behavioral) into one final threat score and a human-readable
classification. This is the "fusion" step referenced in the pipeline:

    Rule-based Detection + ML Anomaly Detection -> Threat Classification

Weighting: rules are trusted more (they're precise, low false-positive)
but ML catches things rules miss, so it still meaningfully moves the score.
"""

import pandas as pd
from .rules import evaluate_rules
from .ml_detector import run_anomaly_detection

RULE_WEIGHT = 0.65
ML_WEIGHT = 0.35


def classify(score: float) -> str:
    if score >= 0.75:
        return "Critical"
    if score >= 0.5:
        return "High"
    if score >= 0.25:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Normal"


def analyze(feat_df: pd.DataFrame) -> pd.DataFrame:
    """Runs rules + ML over the per-IP feature table and returns a results
    DataFrame ready to store/display, sorted by threat score descending."""
    scored = run_anomaly_detection(feat_df)

    rule_rows = scored.apply(lambda r: evaluate_rules(r.to_dict()), axis=1, result_type="expand")
    scored = pd.concat([scored, rule_rows], axis=1)

    scored["final_score"] = (
        RULE_WEIGHT * scored["rule_score"] + ML_WEIGHT * scored["ml_anomaly_score"]
    ).clip(0, 1)
    scored["classification"] = scored["final_score"].apply(classify)

    scored.sort_values("final_score", ascending=False, inplace=True)
    scored.reset_index(drop=True, inplace=True)
    return scored
