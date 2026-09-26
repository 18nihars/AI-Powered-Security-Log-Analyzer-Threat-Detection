import os
import importlib

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Point the SQLite DB at a throwaway temp file so tests never touch
    # the real data/threats.db, and each test run starts from a clean DB.
    monkeypatch.chdir(tmp_path)
    os.makedirs("data", exist_ok=True)
    # Copy the bundled sample log so 'use_sample' works from the temp cwd.
    import shutil
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_src = os.path.join(repo_root, "data", "sample_auth.log")
    if os.path.exists(sample_src):
        shutil.copy(sample_src, os.path.join("data", "sample_auth.log"))

    import app.models as models
    importlib.reload(models)
    import app.main as main
    importlib.reload(main)

    main.app.config.update(TESTING=True)
    with main.app.test_client() as c:
        yield c


def test_healthz_returns_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_index_loads(client):
    r = client.get("/")
    assert r.status_code == 200


def test_analyze_with_sample_log_then_dashboard(client):
    r = client.post("/analyze", data={"use_sample": "1"})
    assert r.status_code == 302
    r = client.get("/dashboard", follow_redirects=True)
    assert r.status_code == 200


def test_api_alerts_json(client):
    client.post("/analyze", data={"use_sample": "1"})
    r = client.get("/api/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert "alerts" in data and "run" in data
