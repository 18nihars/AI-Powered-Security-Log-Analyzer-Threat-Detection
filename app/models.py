"""
models.py
---------
Minimal SQLite persistence layer using SQLAlchemy Core (no heavy ORM needed).
Stores each analysis run and the per-IP alert results so the dashboard can
show history, not just the latest run.
"""

import json
import datetime as dt
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Float,
    DateTime, Text, select, desc
)

DB_PATH = "sqlite:///data/threats.db"

engine = create_engine(DB_PATH, echo=False, future=True)
metadata = MetaData()

runs = Table(
    "runs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("filename", String),
    Column("created_at", DateTime, default=dt.datetime.utcnow),
    Column("total_events", Integer),
    Column("total_ips", Integer),
    Column("critical_count", Integer),
    Column("high_count", Integer),
)

alerts = Table(
    "alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("run_id", Integer),
    Column("ip", String),
    Column("classification", String),
    Column("final_score", Float),
    Column("rule_score", Float),
    Column("ml_anomaly_score", Float),
    Column("failed_count", Integer),
    Column("unique_users", Integer),
    Column("unique_ports", Integer),
    Column("events_per_minute", Float),
    Column("rule_reasons", Text),  # JSON-encoded list
)


def init_db():
    metadata.create_all(engine)


def save_run(filename: str, results_df) -> int:
    init_db()
    with engine.begin() as conn:
        res = conn.execute(
            runs.insert().values(
                filename=filename,
                created_at=dt.datetime.now(dt.timezone.utc),
                total_events=int(results_df["total_events"].sum()) if not results_df.empty else 0,
                total_ips=len(results_df),
                critical_count=int((results_df["classification"] == "Critical").sum()) if not results_df.empty else 0,
                high_count=int((results_df["classification"] == "High").sum()) if not results_df.empty else 0,
            )
        )
        run_id = res.inserted_primary_key[0]

        for _, row in results_df.iterrows():
            conn.execute(
                alerts.insert().values(
                    run_id=run_id,
                    ip=row["ip"],
                    classification=row["classification"],
                    final_score=float(row["final_score"]),
                    rule_score=float(row["rule_score"]),
                    ml_anomaly_score=float(row["ml_anomaly_score"]),
                    failed_count=int(row["failed_count"]),
                    unique_users=int(row["unique_users"]),
                    unique_ports=int(row["unique_ports"]),
                    events_per_minute=float(row["events_per_minute"]),
                    rule_reasons=json.dumps(row["rule_reasons"]),
                )
            )
    return run_id


def get_latest_run():
    init_db()
    with engine.connect() as conn:
        run_row = conn.execute(select(runs).order_by(desc(runs.c.id)).limit(1)).mappings().first()
        if not run_row:
            return None, []
        alert_rows = conn.execute(
            select(alerts).where(alerts.c.run_id == run_row["id"]).order_by(desc(alerts.c.final_score))
        ).mappings().all()
        alert_list = []
        for a in alert_rows:
            d = dict(a)
            d["rule_reasons"] = json.loads(d["rule_reasons"]) if d["rule_reasons"] else []
            alert_list.append(d)
        return dict(run_row), alert_list


def get_run_history(limit: int = 20):
    init_db()
    with engine.connect() as conn:
        rows = conn.execute(select(runs).order_by(desc(runs.c.id)).limit(limit)).mappings().all()
        return [dict(r) for r in rows]
