#!/usr/bin/env bash
# Convenience script: creates a venv (if missing), installs deps,
# generates the sample log, and starts the Flask dev server.
set -e

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install --quiet -r requirements.txt

if [ ! -f "data/sample_auth.log" ]; then
  echo "Generating sample log..."
  python generate_sample_logs.py
fi

echo "Starting server on http://localhost:5000 ..."
export FLASK_APP=app.main
python -m app.main
