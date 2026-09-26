import pandas as pd
from app.ml_detector import run_anomaly_detection
from app.threat_engine import analyze, classify


def _fake_features(n=10):
    rows = []
    for i in range(n):
        rows.append({
            "ip": f"10.0.0.{i}",
            "total_events": 5, "failed_count": 1, "success_count": 4,
            "fail_ratio": 0.2, "unique_users": 1, "unique_ports": 1,
            "night_event_count": 0, "span_seconds": 300, "events_per_minute": 1.0,
            "avg_seconds_between_events": 60.0, "min_seconds_between_events": 10.0,
        })
    # inject one clear outlier
    rows.append({
        "ip": "203.0.113.9",
        "total_events": 500, "failed_count": 480, "success_count": 20,
        "fail_ratio": 0.96, "unique_users": 1, "unique_ports": 1,
        "night_event_count": 0, "span_seconds": 60, "events_per_minute": 500.0,
        "avg_seconds_between_events": 0.1, "min_seconds_between_events": 0.05,
    })
    return pd.DataFrame(rows)


def test_ml_adds_expected_columns():
    df = _fake_features()
    scored = run_anomaly_detection(df)
    assert "ml_anomaly_score" in scored.columns
    assert "ml_is_anomaly" in scored.columns
    assert scored["ml_anomaly_score"].between(0, 1).all()


def test_small_batches_fall_back_gracefully():
    df = _fake_features(n=1)  # 2 rows total, below the size threshold
    scored = run_anomaly_detection(df)
    assert (scored["ml_anomaly_score"] == 0.0).all()
    assert (scored["ml_is_anomaly"] == False).all()  # noqa: E712


def test_classify_thresholds():
    assert classify(0.0) == "Normal"
    assert classify(0.1) == "Low"
    assert classify(0.3) == "Medium"
    assert classify(0.6) == "High"
    assert classify(0.9) == "Critical"


def test_analyze_end_to_end_produces_sorted_scores():
    df = _fake_features()
    results = analyze(df)
    assert "final_score" in results.columns
    assert "classification" in results.columns
    # results must be sorted descending by final_score
    scores = results["final_score"].tolist()
    assert scores == sorted(scores, reverse=True)
    # the injected outlier should end up at (or near) the top
    assert results.iloc[0]["ip"] == "203.0.113.9"
