FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p data/uploads

# Run as a non-root user (DevSecOps basic: never run app containers as root)
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Lets Docker/Kubernetes detect a hung or broken app container automatically
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5000/healthz', timeout=3).status == 200 else 1)"

ENV FLASK_APP=app.main
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "2", "app.main:app"]
