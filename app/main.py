"""
main.py
-------
Flask web app tying the whole pipeline together:

    Logs -> Parser -> Feature Extraction -> Rules + ML -> Threat Classification -> Dashboard

Routes:
    GET  /              Upload page
    POST /analyze       Upload a log file, run the pipeline, store results, redirect to dashboard
    GET  /dashboard      Latest run results (table + charts)
    GET  /api/alerts     Latest run results as JSON
    GET  /history        Past runs
    GET  /healthz        Liveness/readiness probe for container orchestration
"""

import os
import time
from flask import Flask, request, render_template, redirect, url_for, jsonify, flash

from .parser import parse_log_file
from .features import build_ip_features
from .threat_engine import analyze
from . import models
from .logging_config import logger

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

app = Flask(__name__)
# Secret key is read from the environment so nothing sensitive is hardcoded
# in source. The fallback is only for local/demo use — set FLASK_SECRET_KEY
# for anything beyond that.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me-before-deploying")  # nosec B105


@app.route("/healthz")
def healthz():
    """Liveness/readiness probe. Also verifies the DB is reachable so an
    orchestrator (Docker/Kubernetes) can catch a broken DB connection early."""
    try:
        models.init_db()
        db_ok = True
    except Exception as e:  # noqa: BLE001 - health checks must never crash
        logger.error(f"Health check DB failure: {e}")
        db_ok = False
    status = "ok" if db_ok else "degraded"
    code = 200 if db_ok else 503
    return jsonify({"status": status, "db": db_ok}), code


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    file = request.files.get("logfile")
    use_sample = request.form.get("use_sample")

    if use_sample:
        path = os.path.join(BASE_DIR, "data", "sample_auth.log")
        filename = "sample_auth.log"
        if not os.path.exists(path):
            flash("Sample log not found. Run generate_sample_logs.py first.")
            return redirect(url_for("index"))
    elif file and file.filename:
        filename = file.filename
        path = os.path.join(UPLOAD_DIR, filename)
        file.save(path)
    else:
        flash("Please choose a log file or use the sample log.")
        return redirect(url_for("index"))

    start = time.monotonic()
    df = parse_log_file(path)
    if df.empty:
        logger.warning(f"Upload '{filename}' produced zero parseable log lines")
        flash("No valid log lines were found. Check the expected log format in the README.")
        return redirect(url_for("index"))

    feat_df = build_ip_features(df)
    results_df = analyze(feat_df)
    run_id = models.save_run(filename, results_df)

    critical = int((results_df["classification"] == "Critical").sum())
    high = int((results_df["classification"] == "High").sum())
    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        f"Analyzed '{filename}': run_id={run_id} events={len(df)} ips={len(results_df)} "
        f"critical={critical} high={high} elapsed_ms={elapsed_ms}"
    )
    if critical:
        logger.warning(f"run_id={run_id} flagged {critical} Critical IP(s) in '{filename}'")

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    run, alerts_list = models.get_latest_run()
    if run is None:
        flash("No analysis runs yet. Upload a log file first.")
        return redirect(url_for("index"))

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Normal": 0}
    for a in alerts_list:
        counts[a["classification"]] = counts.get(a["classification"], 0) + 1

    return render_template("dashboard.html", run=run, alerts=alerts_list, counts=counts)


@app.route("/api/alerts")
def api_alerts():
    run, alerts_list = models.get_latest_run()
    return jsonify({"run": run, "alerts": alerts_list})


@app.route("/history")
def history():
    runs = models.get_run_history()
    return render_template("history.html", runs=runs)


if __name__ == "__main__":
    models.init_db()
    # Binding to 0.0.0.0 is intentional here: this is what makes the app
    # reachable from outside its Docker container. Debug mode is opt-in via
    # env var so it can never accidentally ship enabled.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)  # nosec B104
