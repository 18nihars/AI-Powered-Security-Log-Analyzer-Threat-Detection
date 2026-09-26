from app.parser import parse_log_lines
from app.features import build_ip_features


def _lines_for_brute_force():
    lines = []
    for i in range(20):
        lines.append(
            f"2026-09-26 03:{i:02d}:00 ip=203.0.113.9 user=admin event=login status=failed port=22"
        )
    return lines


def test_feature_row_created_per_ip():
    lines = [
        "2026-09-26 09:00:00 ip=10.0.0.1 user=alice event=login status=success port=22",
        "2026-09-26 09:05:00 ip=10.0.0.2 user=bob event=login status=success port=22",
    ]
    df = parse_log_lines(lines)
    feat = build_ip_features(df)
    assert len(feat) == 2
    assert set(feat["ip"]) == {"10.0.0.1", "10.0.0.2"}


def test_failed_count_and_fail_ratio():
    df = parse_log_lines(_lines_for_brute_force())
    feat = build_ip_features(df)
    row = feat.iloc[0]
    assert row["failed_count"] == 20
    assert row["fail_ratio"] == 1.0
    assert row["unique_users"] == 1


def test_empty_dataframe_yields_empty_features():
    df = parse_log_lines([])
    feat = build_ip_features(df)
    assert feat.empty
    assert "ip" in feat.columns
