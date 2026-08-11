"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 6: Audit Logging & Anti-Black Market Protection

Implements the ``AuditLogger`` class — a lightweight, thread-safe CSV writer
that records every data-access event flowing through the FastAPI server.

Purpose & Compliance Context
-----------------------------
GDPR Art. 5(2) — Accountability Principle:
    The controller must be able to *demonstrate* compliance with all data
    protection principles.  Every access to (or denial of) biometric data is
    captured here with a UTC timestamp, the requesting party's role, the
    athlete's player_id, the action taken, and its outcome — forming a
    tamper-evident, human-readable evidence trail.

AAA Framework — Accounting:
    Authentication (API key) and Authorization (consent + RBAC) are enforced
    in ``main_server.py``.  This module fulfils the *Accounting* leg of the
    triad by ensuring that *every* authorized or denied access is traceable
    to a specific actor, time, and decision outcome.

Anti-Black Market Traceability:
    If decrypted biometric data were ever leaked or sold on the black market,
    investigators can cross-reference the leak timestamp against ``audit_log.csv``
    to identify exactly which user role accessed which player's data and when.
    Denied attempts (DENIED_RBAC_403, DENIED_GDPR_403) are also recorded, so
    repeated unauthorized probing is immediately visible in the log.

Design Decisions
----------------
- **CSV format** — human-readable, trivially parseable by pandas / Excel, and
  easy to ship to a SIEM (Splunk, ELK) or regulatory body without tooling.
- **Append-only writes** — the log file is never overwritten; new rows are
  always appended, preserving the immutable audit trail.
- **stdlib-only** — no third-party dependencies (``csv``, ``datetime``,
  ``os``, ``threading``), keeping the module lightweight and portable.
- **Thread-safe** — a ``threading.Lock`` serialises concurrent writes so that
  parallel FastAPI worker threads never corrupt the CSV.
"""

from __future__ import annotations

import csv
import os
import threading
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# CSV column schema (fixed; do not reorder — existing logs would break).
# ---------------------------------------------------------------------------
_CSV_HEADERS = [
    "timestamp",
    "user_id",
    "user_role",
    "player_id",
    "action",
    "status",
    "ip_address",
]


class AuditLogger:
    """
    Lightweight, thread-safe audit logger that writes access events to a CSV file.

    Each row represents a single data-access event and carries enough context
    to satisfy GDPR Art. 5(2) accountability requirements and support forensic
    investigation of potential biometric data leaks.

    Attributes:
        log_file_path (str): Filesystem path to the audit CSV file.
    """

    def __init__(self, log_file_path: str = "audit_log.csv") -> None:
        """
        Initialise the AuditLogger and ensure the CSV file exists with headers.

        If ``log_file_path`` does not exist, it is created and the header row
        is written immediately.  If the file already exists (e.g., server
        restart), it is left untouched — preserving all historical entries.

        Args:
            log_file_path (str): Path to the CSV audit log file.
                                  Defaults to ``"audit_log.csv"`` in the
                                  current working directory.
        """
        self.log_file_path = log_file_path
        self._lock = threading.Lock()
        self._initialise_log_file()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _initialise_log_file(self) -> None:
        """Create the CSV with header row if it does not already exist."""
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, mode="w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=_CSV_HEADERS)
                writer.writeheader()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_access(
        self,
        user_id: str,
        user_role: str,
        player_id: str,
        action: str,
        status: str,
        ip_address: str = "127.0.0.1",
    ) -> dict:
        """
        Record a single data-access event to the audit log.

        Generates an ISO 8601 UTC timestamp, appends the entry to the CSV
        file, and returns the logged entry as a plain dict for immediate
        inspection or chaining (e.g., embedding in the HTTP response for
        debugging, or unit-testing the exact values written).

        Args:
            user_id (str):     Identifier of the requesting party (e.g., their
                               role token or username — see module docstring).
            user_role (str):   RBAC role of the requesting party (e.g.,
                               ``"TEAM_DOCTOR"``, ``"EXTERNAL_COMPANY"``).
            player_id (str):   Athlete unique identifier whose data is being
                               accessed or whose request triggered the event.
            action (str):      A short, machine-readable action name:
                               ``TELEMETRY_INGEST``, ``CONSENT_GRANTED``,
                               ``CONSENT_REVOKED``, ``VIEW_BIOMETRIC_DATA``.
            status (str):      Outcome of the request:
                               ``SUCCESS``, ``SUCCESS_200``,
                               ``DENIED_GDPR_403``, ``DENIED_RBAC_403``.
            ip_address (str):  Client IP address extracted from the HTTP
                               request.  Defaults to ``"127.0.0.1"`` for
                               internal/test calls without a real remote addr.

        Returns:
            dict: The exact row that was written to the CSV, keyed by column
                  name, including the generated ``timestamp``.
        """
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        entry = {
            "timestamp": timestamp,
            "user_id": user_id,
            "user_role": user_role,
            "player_id": player_id,
            "action": action,
            "status": status,
            "ip_address": ip_address,
        }

        with self._lock:
            with open(self.log_file_path, mode="a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=_CSV_HEADERS)
                writer.writerow(entry)

        return entry

    def read_audit_log(self, player_id: Optional[str] = None) -> list[dict]:
        """
        Read audit log entries from the CSV file.

        Args:
            player_id (str, optional): If provided, return only rows where
                                       the ``player_id`` column matches this
                                       value exactly.  If ``None`` (default),
                                       all rows are returned.

        Returns:
            list[dict]: A list of row dicts, each keyed by CSV column name.
                        Returns an empty list if the file does not exist or
                        contains only a header row.
        """
        if not os.path.exists(self.log_file_path):
            return []

        with self._lock:
            with open(self.log_file_path, mode="r", newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)

        if player_id is not None:
            rows = [row for row in rows if row.get("player_id") == player_id]

        return rows
