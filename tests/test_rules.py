from app.rules import evaluate_rules

BASE_ROW = {
    "failed_count": 0, "success_count": 0, "fail_ratio": 0.0,
    "unique_users": 1, "unique_ports": 1, "night_event_count": 0,
    "total_events": 1, "events_per_minute": 0.1,
}


def test_normal_traffic_triggers_no_rules():
    row = dict(BASE_ROW, total_events=5, failed_count=0, fail_ratio=0.0,
               unique_users=1, unique_ports=1, events_per_minute=0.5)
    result = evaluate_rules(row)
    assert result["rule_reasons"] == []
    assert result["rule_score"] == 0.0


def test_brute_force_pattern_triggers_rule():
    row = dict(BASE_ROW, failed_count=20, events_per_minute=5.0, total_events=20)
    result = evaluate_rules(row)
    assert any("Brute-force" in r for r in result["rule_reasons"])
    assert result["rule_score"] > 0


def test_credential_stuffing_triggers_rule():
    row = dict(BASE_ROW, unique_users=15, total_events=15, failed_count=14, fail_ratio=0.93)
    result = evaluate_rules(row)
    assert any("Credential stuffing" in r for r in result["rule_reasons"])


def test_port_scan_triggers_rule():
    row = dict(BASE_ROW, unique_ports=25, total_events=25)
    result = evaluate_rules(row)
    assert any("Port-scan" in r for r in result["rule_reasons"])


def test_rule_score_is_capped_at_one():
    row = dict(
        failed_count=100, success_count=0, fail_ratio=1.0,
        unique_users=50, unique_ports=50, night_event_count=100,
        total_events=100, events_per_minute=50.0,
    )
    result = evaluate_rules(row)
    assert result["rule_score"] <= 1.0
