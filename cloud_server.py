"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: Cloud Server — Persistent Mock Storage & Data Minimization Layer

This module implements the `CloudServer` class, which represents the ingestion
and storage backend that receives encrypted biometric telemetry from edge
`SecureGateway` instances over the network.

Security & Compliance Design (GDPR / CIA Triad):
-------------------------------------------------
1. Data Minimization (GDPR Art. 5(1)(c)):
   The cloud storage layer is architecturally forbidden from ever persisting
   plaintext biometric values. It only ever accepts and writes structures
   containing hex-encoded `nonce` and `ciphertext` fields (plus non-sensitive
   routing metadata such as `gateway_id`). Even a full database compromise
   (e.g., stolen `mock_db.json`) or an unauthorized third-party API read
   exposes nothing but authenticated ciphertext ("encrypted noise") —
   directly mitigating the tactical performance espionage threat model.

2. Storage Isolation:
   `CloudServer` never holds decryption keys itself and never calls
   `SecureGateway.decrypt_data()` internally during ingestion. Decryption is
   only ever performed out-of-band by an explicitly authorized caller holding
   the shared AES key (see `main_server.py`'s `authorize-decrypt` endpoint),
   keeping the "store" and "decrypt" trust boundaries strictly separated.

3. Availability (CIA Triad):
   Storage is persisted to a local JSON file (`mock_db.json`) so ingested
   records survive server restarts, simulating a durable (if simplistic)
   cloud persistence layer for this academic prototype.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List

# Fields that are ALLOWED to be persisted. Any payload containing keys outside
# this allow-list (e.g., accidental plaintext biometric fields) is rejected
# before it ever reaches disk — a defense-in-depth "storage isolation" gate.
_ALLOWED_RECORD_FIELDS = {
    "gateway_id",
    "device_id",
    "player_id",
    "sent_at",
    "nonce",
    "ciphertext",
    "received_at",
}

# Fields that MUST be present and MUST be hex strings — the only fields that
# are permitted to carry the actual cryptographic material.
_REQUIRED_HEX_FIELDS = ("nonce", "ciphertext")


def _is_hex_string(value: Any) -> bool:
    """Return True if `value` is a string containing only hexadecimal digits."""
    if not isinstance(value, str) or not value:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


class CloudServer:
    """
    Mock Cloud Server responsible for durable, encryption-only storage of
    incoming athlete biometric telemetry packets.

    Attributes:
        db_path (str): Filesystem path of the local JSON mock database.
    """

    def __init__(self, db_path: str = "mock_db.json") -> None:
        """
        Initialize the CloudServer and ensure the backing JSON file exists.

        Args:
            db_path (str): Path to the local mock database file.
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        if not os.path.exists(self.db_path):
            self._write_records([])

    def _read_records(self) -> List[Dict[str, Any]]:
        """Load all persisted records from `mock_db.json` (empty list if missing/corrupt)."""
        if not os.path.exists(self.db_path):
            return []
        try:
            with open(self.db_path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _write_records(self, records: List[Dict[str, Any]]) -> None:
        """Atomically persist the full list of records to `mock_db.json`."""
        with open(self.db_path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)

    @staticmethod
    def _validate_storage_isolation(record: Dict[str, Any]) -> None:
        """
        Enforce that a record is safe to persist: only hex-encoded ciphertext
        and nonce (plus benign routing metadata) — NEVER plaintext biometrics.

        Raises:
            ValueError: If the record contains disallowed fields, is missing
                        required cryptographic fields, or those fields are not
                        valid hex-encoded strings (i.e., look like plaintext).
        """
        unexpected_fields = set(record.keys()) - _ALLOWED_RECORD_FIELDS
        if unexpected_fields:
            raise ValueError(
                f"SECURITY FAILURE: refusing to store disallowed field(s) "
                f"{sorted(unexpected_fields)} — only encrypted telemetry may be persisted."
            )

        for field in _REQUIRED_HEX_FIELDS:
            if field not in record:
                raise ValueError(f"Missing required field '{field}' for encrypted storage.")
            if not _is_hex_string(record[field]):
                raise ValueError(
                    f"SECURITY FAILURE: field '{field}' is not a valid hex-encoded "
                    f"ciphertext/nonce — refusing to store possible plaintext leakage."
                )

    def store_encrypted_payload(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Persist a single encrypted telemetry record to `mock_db.json`.

        Args:
            record (Dict[str, Any]): Encrypted packet fields (gateway_id, device_id,
                                      player_id, sent_at, nonce, ciphertext, ...).

        Returns:
            Dict[str, Any]: The stored record (including any server-assigned metadata).

        Raises:
            ValueError: If the record fails the storage isolation check (see
                        `_validate_storage_isolation`), i.e., it is not purely
                        encrypted ciphertext/nonce.
        """
        self._validate_storage_isolation(record)

        with self._lock:
            records = self._read_records()
            records.append(record)
            self._write_records(records)

        return record

    def get_all_stored_records(self) -> List[Dict[str, Any]]:
        """
        Retrieve every stored encrypted record from `mock_db.json`.

        Since storage isolation guarantees only hex-encoded ciphertext/nonce
        are ever written, this method safely doubles as the "proof of
        encryption" endpoint: exposing its return value to any caller
        (authorized or not) reveals no biometric plaintext whatsoever.

        Returns:
            List[Dict[str, Any]]: All persisted encrypted telemetry records.
        """
        with self._lock:
            return self._read_records()
