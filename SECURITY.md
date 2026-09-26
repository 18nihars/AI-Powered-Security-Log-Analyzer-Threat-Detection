# Security Policy

This is a portfolio/educational project, but it follows basic security
hygiene so the practices demonstrated here are actually sound.

## Supported versions

Only the `main` branch is maintained. There are no released version
branches to backport fixes to.

## Reporting a vulnerability

If you find a security issue in this project (e.g. an injection point in
the log parser, an auth bypass on the dashboard, a dependency with a known
CVE that isn't yet caught by CI), please open a private report rather than
a public issue:

1. Do not open a public GitHub issue with exploit details.
2. Describe the issue, the impact, and steps to reproduce.
3. Allow a reasonable window to address it before public disclosure.

## What this project already does to reduce risk

- **Dependency scanning** — `pip-audit` runs in CI on every push/PR and
  fails the build on known-vulnerable dependencies.
- **Static application security testing (SAST)** — `bandit` scans the
  Python source for common insecure patterns (e.g. unsafe deserialization,
  hardcoded secrets, shell injection) on every push/PR.
- **Container hardening** — the Docker image runs as a non-root user and
  exposes a `/healthz` endpoint for orchestrator health checks.
- **Input handling** — the log parser uses a strict regex and silently
  skips (rather than executes or evaluates) any line that doesn't match
  the expected format.
- **No secrets in the repo** — there are no API keys or credentials
  committed. `app.secret_key` in `app/main.py` is a placeholder dev value —
  replace it with a value from an environment variable before any real
  deployment.

## Known limitations (by design, for a demo project)

- The Flask dev server / bundled Gunicorn config has no built-in
  authentication in front of the dashboard — do not expose this publicly
  without adding an auth layer.
- SQLite is used for simplicity; it is not intended for concurrent
  multi-user production workloads.
