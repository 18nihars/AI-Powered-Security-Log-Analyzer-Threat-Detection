"""
features.py
------------
Turns raw per-event log rows into one feature row per source IP.
These features feed both the rule-based engine and the ML model.
"""

import pandas as pd

NIGHT_HOURS = set(list(range(0, 6)))  # 00:00 - 05:59 counted as "unusual"


def build_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(
            columns=[
                "ip", "total_events", "failed_count", "success_count",
                "fail_ratio", "unique_users", "unique_ports",
                "night_event_count", "span_seconds", "events_per_minute",
                "avg_seconds_between_events", "min_seconds_between_events",
            ]
        )

    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    df["is_night"] = df["hour"].isin(NIGHT_HOURS)

    rows = []
    for ip, g in df.groupby("ip"):
        g = g.sort_values("timestamp")
        total = len(g)
        failed = (g["status"] == "failed").sum()
        success = (g["status"] == "success").sum()
        unique_users = g["user"].nunique()
        unique_ports = g["port"].nunique()
        night_events = g["is_night"].sum()

        span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
        span = max(span, 1.0)  # avoid divide-by-zero for single-event IPs
        events_per_minute = total / (span / 60.0)

        diffs = g["timestamp"].diff().dt.total_seconds().dropna()
        avg_gap = diffs.mean() if len(diffs) else span
        min_gap = diffs.min() if len(diffs) else span

        rows.append({
            "ip": ip,
            "total_events": total,
            "failed_count": int(failed),
            "success_count": int(success),
            "fail_ratio": failed / total if total else 0.0,
            "unique_users": unique_users,
            "unique_ports": unique_ports,
            "night_event_count": int(night_events),
            "span_seconds": span,
            "events_per_minute": events_per_minute,
            "avg_seconds_between_events": avg_gap,
            "min_seconds_between_events": min_gap,
        })

    feat_df = pd.DataFrame(rows)
    feat_df.sort_values("total_events", ascending=False, inplace=True)
    feat_df.reset_index(drop=True, inplace=True)
    return feat_df
