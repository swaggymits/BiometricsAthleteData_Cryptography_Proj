"""
Structured logging configuration for the Cloud Server.

Replaces ad-hoc `print()` statements with proper Python `logging`, formatted
consistently and configurable via `config.settings.LOG_LEVEL`. This is a
baseline requirement for any production service: logs must be structured,
leveled (DEBUG/INFO/WARNING/ERROR), and easy to ship to a log aggregator
(e.g., CloudWatch, ELK, Datadog) in a real deployment.

Security note: request/response logging in `main_server.py` deliberately logs
`nonce`/`ciphertext` only (never raw biometric payloads), consistent with the
project's data-minimization design.
"""

from __future__ import annotations

import logging
import sys

from config import settings

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def configure_logging() -> None:
    """Configure the root logger once, at application startup."""
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format=_LOG_FORMAT,
        stream=sys.stdout,
    )
    # Quiet down noisy third-party loggers unless we're in DEBUG mode.
    if settings.LOG_LEVEL.upper() != "DEBUG":
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger, e.g. `get_logger(__name__)`."""
    return logging.getLogger(name)
