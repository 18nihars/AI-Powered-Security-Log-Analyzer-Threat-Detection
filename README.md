# 🔐 AI-Powered Security Log Analyzer & Threat Detection

A Python system that analyzes authentication/server logs and detects
suspicious behavior by combining **traditional rule-based detection** with
**unsupervised machine learning anomaly detection**.

```
Logs
 ↓
Python Parser
 ↓
Feature Extraction
 ↓
Rule-based Detection ──┐
                        ├──▶ Threat Classification ──▶ Dashboard / Alerts
ML Anomaly Detection ──┘
```

## What it detects

| Threat | How it's caught |
|---|---|
| Brute-force login attempts | Rule: high failed-login count at a fast pace from one IP |
| Repeated failed authentication | Rule: failure ratio ≥ 90% for an IP with 5+ attempts |
| Suspicious / credential-stuffing IPs | Rule: one IP trying many distinct usernames |
| Unusual login times | Rule: majority of an IP's activity between 12 AM–6 AM |
| Port-scan patterns | Rule: one IP touching many distinct ports |
| Abnormal request frequency | Rule: high events-per-minute |
| **Novel / unlabeled anomalies** | **ML: IsolationForest** scores each IP's full behavioral profile and flags statistical outliers the rules above don't explicitly cover |

The final **threat score** per IP is a weighted blend of the rule score and
the ML anomaly score, mapped to a classification: `Critical / High / Medium /
Low / Normal`. Every alert lists the specific human-readable reason(s) it was
flagged — the rules give you explainability, the ML model gives you coverage
for attack patterns you didn't think to write a rule for.

## Tech stack

`Python · Pandas · Scikit-learn (IsolationForest) · Flask · SQLite (via SQLAlchemy) · Docker`

## Project structure

```
security_log_analyzer/
├── app/
│   ├── main.py            # Flask app & routes (incl. /healthz)
│   ├── parser.py           # Log file -> DataFrame
│   ├── features.py         # Per-IP behavioral feature extraction
│   ├── rules.py             # Rule-based detection engine
│   ├── ml_detector.py       # IsolationForest anomaly detection
│   ├── threat_engine.py     # Combines rules + ML -> final score/classification
│   ├── models.py             # SQLite persistence (runs + alerts)
│   ├── logging_config.py      # Structured JSON logging
│   └── templates/            # Dashboard HTML (upload page, dashboard, history)
├── tests/                      # Pytest unit + integration tests (19 tests)
├── .github/workflows/ci.yml     # CI pipeline: lint, SAST, dep scan, tests, image scan
├── data/
│   └── sample_auth.log        # Synthetic demo log (generated, see below)
├── generate_sample_logs.py     # Creates the synthetic demo log
├── requirements.txt
├── requirements-dev.txt         # Test/lint/SAST tooling, CI-only
├── Dockerfile                    # Non-root user + HEALTHCHECK
├── docker-compose.yml
├── Makefile                       # make test / lint / sast / scan-deps / all-checks
├── .pre-commit-config.yaml         # Local pre-push gates mirroring CI
├── SECURITY.md                      # Vulnerability disclosure policy
├── bandit.yaml / setup.cfg / pytest.ini
├── run.sh                            # One-command local run (venv + install + start)
└── README.md
```

---

## 🚀 How to run it

You have three options. Pick whichever is easiest for you.

### Option 1 — One-command script (local, no Docker)

```bash
unzip security_log_analyzer.zip
cd security_log_analyzer
chmod +x run.sh
./run.sh
```

This creates a virtual environment, installs dependencies, generates the
sample log if it isn't already there, and starts the app at
**http://localhost:5000**.

### Option 2 — Manual local setup

```bash
cd security_log_analyzer

# 1. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate the synthetic demo log (optional — one is already bundled,
#    but you can regenerate it or study how it's built)
python generate_sample_logs.py

# 4. Start the web app
python -m app.main
```

Then open **http://localhost:5000** in your browser.

### Option 3 — Docker (recommended for a clean, reproducible run)

```bash
cd security_log_analyzer
docker compose up --build
```

Then open **http://localhost:5000**. Data (including the SQLite DB) persists
in the `./data` folder on your host machine via a mounted volume.

To stop it: `docker compose down`.

---

## 🖱️ Using the app

1. Go to **http://localhost:5000** — the upload page.
2. Either:
   - Upload your own log file (see the required format below), or
   - Click **"Use sample_auth.log"** to instantly analyze the bundled
     synthetic log, which contains a brute-force burst, a credential-stuffing
     run, a port scan, and normal daily traffic mixed together.
3. You'll be redirected to the **Dashboard**, showing:
   - A count of alerts by severity (Critical/High/Medium/Low/Normal)
   - A per-IP table with the final threat score, the rule score, the ML
     anomaly score, and the specific reasons each IP was flagged
4. Visit **/history** to see every past analysis run stored in SQLite.
5. Hit **`GET /api/alerts`** to get the latest run's results as raw JSON
   (handy if you want to pipe this into another tool or a SIEM later).

---

## 📄 Log format

The parser expects one event per line, in this format:

```
<YYYY-MM-DD HH:MM:SS> ip=<ip address> user=<username> event=<login|access> status=<success|failed> port=<port number>
```

Example:

```
2026-09-26 03:14:07 ip=192.168.1.45 user=admin event=login status=failed port=22
```

If you want to feed in real logs from something like OpenSSH's `auth.log`,
write a small pre-processing script that reformats each line into the format
above (this keeps the parser simple and format-agnostic to any log source —
SSH, a custom API gateway, RDP, etc.).

---

## 🧠 How the detection works

1. **Parser** (`parser.py`) turns raw text lines into a structured Pandas
   DataFrame using a regex, skipping (and counting) any malformed lines.
2. **Feature extraction** (`features.py`) groups events by source IP and
   computes a behavioral profile: total events, failed/success counts, fail
   ratio, distinct usernames tried, distinct ports touched, night-time event
   count, events-per-minute, and timing gaps between events.
3. **Rule-based detection** (`rules.py`) runs explicit, tunable threshold
   rules (see the table above) against each IP's profile. Every triggered
   rule adds to a `rule_score` and produces a plain-English reason string.
4. **ML anomaly detection** (`ml_detector.py`) standardizes the numeric
   features and fits a Scikit-learn `IsolationForest` across all IPs in the
   batch, producing a normalized `ml_anomaly_score` (0–1) for each IP. This
   is unsupervised — it needs no labeled attack data, and it can catch
   attack shapes the rules don't explicitly encode.
5. **Threat engine** (`threat_engine.py`) blends `rule_score` (65% weight)
   and `ml_anomaly_score` (35% weight) into one `final_score`, then maps it
   to `Critical / High / Medium / Low / Normal`.
6. **Persistence & dashboard** (`models.py`, `main.py`, `templates/`) stores
   every run + its alerts in SQLite and renders them as a simple, dark-themed
   Flask dashboard.

### Tuning thresholds

All rule thresholds live at the top of `app/rules.py` as plain constants
(e.g. `BRUTE_FORCE_FAILED_THRESHOLD`, `PORT_SCAN_UNIQUE_PORT_THRESHOLD`).
Adjust them to fit your own traffic volume. The ML model's sensitivity is
controlled by the `contamination` parameter in `run_anomaly_detection()`
(default `0.15`, meaning it expects up to ~15% of IPs in a batch to be
anomalous — lower this for quieter, more conservative flagging).

---

## 🔧 Extending this project

Ideas if you want to build this out further (also good talking points for
interviews):

- Swap SQLite for PostgreSQL/MySQL for multi-user / production use.
- Add a background worker (Celery/APScheduler) to tail live log files
  instead of one-shot file uploads.
- Add email/Slack webhook alerts for `Critical` classifications.
- Add a `known_bad_ips` allow/deny list rule fed by a threat-intel feed.
- Retrain/version the IsolationForest model over rolling time windows and
  track drift.
- Add authentication to the dashboard itself before exposing it beyond
  localhost.

---

## 🛡️ DevSecOps layer

On top of the core detection pipeline, this project has a small but real
DevSecOps layer around it — the same practices you'd expect around any
service handling security-relevant data, kept intentionally lightweight.

### CI/CD pipeline (`.github/workflows/ci.yml`)

Runs automatically on every push/PR to `main` as two jobs:

1. **Lint, SAST, dependency scan, unit tests**
   - `flake8` — style/lint gate
   - `bandit` — static application security testing (SAST) on `app/`
   - `pip-audit` — scans `requirements.txt` against known CVE databases and
     fails the build on a vulnerable pinned dependency
   - `pytest` — the full test suite (19 tests covering the parser, feature
     extraction, rules engine, ML detector, threat engine, and Flask routes)
2. **Docker build & image scan** (runs only if job 1 passes)
   - Builds the production image
   - Scans it with **Trivy** for HIGH/CRITICAL OS and dependency
     vulnerabilities and fails the build if any are found

Run the exact same checks locally before you push:

```bash
pip install -r requirements-dev.txt
make all-checks        # lint + sast + scan-deps + test
# or individually: make lint / make sast / make scan-deps / make test
```

### Pre-commit hooks (`.pre-commit-config.yaml`)

Optional, but catches issues before they're even committed:

```bash
pip install pre-commit
pre-commit install
```

Runs `black` (formatting), `flake8` (lint), `bandit` (SAST), and
`detect-secrets` (stops committed API keys/credentials) on every commit.

### Runtime hardening

- **`/healthz` endpoint** — checks the app and its DB connection are alive;
  wired into the Docker image's `HEALTHCHECK` so an orchestrator (Docker,
  Kubernetes, ECS, etc.) can detect and restart a broken container
  automatically.
- **Non-root container user** — the Docker image creates and runs as an
  unprivileged `appuser` rather than root.
- **Structured JSON logging** (`app/logging_config.py`) — every analysis run
  logs a single-line JSON record (event counts, elapsed time, how many
  Critical/High alerts were found) to stdout, ready to ship to any log
  aggregator. Level is controlled via the `LOG_LEVEL` env var.
- **No hardcoded secrets** — the Flask session secret is read from the
  `FLASK_SECRET_KEY` env var (falls back to an obviously-labeled dev value
  only for local use); see `SECURITY.md` for the full policy.
- **Debug mode is opt-in** — `app.run(debug=...)` only enables the Werkzeug
  debugger if `FLASK_DEBUG=true` is explicitly set, so it can never
  accidentally ship enabled.

### Vulnerability disclosure

See [`SECURITY.md`](SECURITY.md) for the project's security policy and how
to report an issue.

---

## ⚠️ Notes & limitations

- This is an educational/portfolio project meant to demonstrate the
  detection pipeline end-to-end, not a hardened production SIEM.
- The bundled `sample_auth.log` is entirely synthetic (generated by
  `generate_sample_logs.py`) — no real user data or real attack traffic is
  included.
- `app.secret_key` in `main.py` is a hardcoded dev value — replace it with
  an environment-variable-based secret before deploying anywhere public.
- IsolationForest anomaly scores are relative to the batch of IPs in a
  single run — very small log files (a handful of IPs) won't give the ML
  layer enough signal to be meaningful (it falls back to a neutral score
  automatically in that case).

---

## 📌 Resume bullet

> Developed an AI-assisted security log analyzer combining rule-based
> detection and ML-based anomaly detection to identify brute-force attempts,
> suspicious IP activity, and abnormal authentication patterns.
