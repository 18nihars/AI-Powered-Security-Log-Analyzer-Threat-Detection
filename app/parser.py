"""
parser.py
---------
Reads raw log files and turns them into a clean pandas DataFrame.

Expected log line format (space-separated key=value pairs after the timestamp):
    2026-09-26 03:14:07 ip=192.168.1.45 user=admin event=login status=failed port=22

The parser is intentionally forgiving: any line that doesn't match the
expected shape is skipped and counted, rather than crashing the whole run.
"""

import re
import pandas as pd

LINE_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"event=(?P<event>\S+)\s+"
    r"status=(?P<status>\S+)\s+"
    r"port=(?P<port>\d+)"
)


def parse_log_file(path: str) -> pd.DataFrame:
    """Parse a log file on disk into a DataFrame. Returns an empty DataFrame
    with the right columns if nothing could be parsed."""
    with open(path, "r", errors="ignore") as f:
        raw_lines = f.readlines()
    return parse_log_lines(raw_lines)


def parse_log_lines(raw_lines) -> pd.DataFrame:
    records = []
    skipped = 0
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        m = LINE_REGEX.match(line)
        if not m:
            skipped += 1
            continue
        d = m.groupdict()
        records.append(d)

    columns = ["timestamp", "ip", "user", "event", "status", "port"]
    if not records:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["port"] = df["port"].astype(int)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if skipped:
        print(f"[parser] Skipped {skipped} unparseable line(s).")

    return df
