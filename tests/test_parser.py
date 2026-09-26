from app.parser import parse_log_lines


def test_parses_well_formed_lines():
    lines = [
        "2026-09-26 03:14:07 ip=192.168.1.45 user=admin event=login status=failed port=22",
        "2026-09-26 03:14:11 ip=192.168.1.45 user=admin event=login status=success port=22",
    ]
    df = parse_log_lines(lines)
    assert len(df) == 2
    assert list(df.columns) == ["timestamp", "ip", "user", "event", "status", "port"]
    assert df.iloc[0]["ip"] == "192.168.1.45"
    assert df.iloc[0]["port"] == 22


def test_skips_malformed_lines_without_crashing():
    lines = [
        "this is not a log line",
        "2026-09-26 03:14:07 ip=10.0.0.1 user=bob event=login status=success port=443",
        "",
    ]
    df = parse_log_lines(lines)
    assert len(df) == 1
    assert df.iloc[0]["ip"] == "10.0.0.1"


def test_empty_input_returns_empty_dataframe_with_columns():
    df = parse_log_lines([])
    assert df.empty
    assert list(df.columns) == ["timestamp", "ip", "user", "event", "status", "port"]
