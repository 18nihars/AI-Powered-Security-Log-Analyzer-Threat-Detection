# Small DevSecOps convenience layer — same commands CI runs, runnable locally.

.PHONY: install install-dev test lint sast scan-deps scan-image docker-build run all-checks

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	pytest

lint:
	flake8 app tests --max-line-length=120

sast:
	bandit -r app -c bandit.yaml

scan-deps:
	pip-audit -r requirements.txt

docker-build:
	docker build -t security-log-analyzer:local .

scan-image: docker-build
	@echo "Requires Trivy installed locally: https://aquasecurity.github.io/trivy/"
	trivy image --severity HIGH,CRITICAL security-log-analyzer:local

run:
	python -m app.main

# Everything CI runs, in one shot, before you push.
all-checks: lint sast scan-deps test
	@echo "All checks passed."
