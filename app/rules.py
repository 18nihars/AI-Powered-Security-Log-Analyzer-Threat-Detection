"""
rules.py
--------
Traditional, explainable "if this then that" security rules. These catch the
well-known attack signatures with zero false-negative risk on obvious cases,
and give a human-readable reason for every alert (something pure ML can't
do on its own).

Each rule returns a (triggered: bool, reason: str, score: float) so results
can be combined into a single rule_score per IP later.
"""

# ---- Tunable thresholds -----------------------------------------------
BRUTE_FORCE_FAILED_THRESHOLD = 15        # failed logins from one IP
BRUTE_FORCE_WINDOW_EVENTS_PER_MIN = 3.0  # and happening at this pace or faster
CRED_STUFFING_UNIQUE_USER_THRESHOLD = 10  # many distinct usernames tried
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 15     # many distinct ports touched
HIGH_FREQUENCY_EVENTS_PER_MIN = 10.0     # abnormal request rate
NIGHT_EVENT_RATIO_THRESHOLD = 0.6        # majority of activity at night
# -------------------------------------------------------------------------


def evaluate_rules(row: dict) -> dict:
    """Run all rules against one IP's feature row. Returns a dict with the
    list of triggered rule names/reasons and a cumulative rule_score (0-1+)."""
    triggered = []
    score = 0.0

    is_brute_force = (
        row["failed_count"] >= BRUTE_FORCE_FAILED_THRESHOLD
        and row["events_per_minute"] >= BRUTE_FORCE_WINDOW_EVENTS_PER_MIN
    )
    if is_brute_force:
        triggered.append(
            f"Brute-force pattern: {row['failed_count']} failed logins at "
            f"{row['events_per_minute']:.1f} events/min"
        )
        score += 0.4

    if row["unique_users"] >= CRED_STUFFING_UNIQUE_USER_THRESHOLD:
        triggered.append(
            f"Credential stuffing: {row['unique_users']} distinct usernames attempted"
        )
        score += 0.35

    if row["unique_ports"] >= PORT_SCAN_UNIQUE_PORT_THRESHOLD:
        triggered.append(
            f"Port-scan pattern: {row['unique_ports']} distinct ports touched"
        )
        score += 0.3

    if row["events_per_minute"] >= HIGH_FREQUENCY_EVENTS_PER_MIN:
        triggered.append(
            f"Abnormal request frequency: {row['events_per_minute']:.1f} events/min"
        )
        score += 0.2

    if row["total_events"] >= 5 and (row["night_event_count"] / row["total_events"]) >= NIGHT_EVENT_RATIO_THRESHOLD:
        triggered.append(
            f"Unusual login hours: {row['night_event_count']}/{row['total_events']} events between 12AM-6AM"
        )
        score += 0.15

    if row["failed_count"] >= 5 and row["fail_ratio"] >= 0.9:
        triggered.append(
            f"Repeated authentication failure: {row['fail_ratio']*100:.0f}% of attempts failed"
        )
        score += 0.2

    return {
        "rule_reasons": triggered,
        "rule_score": min(score, 1.0),
    }
