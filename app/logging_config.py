"""
logging_config.py
------------------
Small DevSecOps concern: structured, consistent logging instead of bare
print() calls, so this app's logs are actually useful to ship to a log
aggregator (ELK, CloudWatch, etc.) in a real deployment.

Emits single-line JSON log records to stdout — container-friendly and easy
for any log shipper to parse. Controlled by the LOG_LEVEL env var
(default INFO).
"""

import json
import logging
import os
import sys
import time


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> logging.Logger:
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    return logging.getLogger("security_log_analyzer")


logger = configure_logging()
