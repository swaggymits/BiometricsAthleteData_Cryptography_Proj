"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: Cloud Server — Persistent Mock Storage & Data Minimization Layer
Week 5 Update: GDPR Consent Registry (Access Control & GDPR Consent Toggle)

This module implements two classes:

``CloudServer``
    The ingestion and storage backend that receives encrypted biometric
    telemetry from edge ``SecureGateway`` instances over the network.

``ConsentRegistry`` (NEW — Week 5)
    A thread-safe, in-memory registry that maps each ``player_id`` to their
    current GDPR consent flag (``privacy_toggle_consent: bool``).  It is the
    single source of truth for consent state consulted by the FastAPI
    ``authorize-decrypt`` endpoint before performing any decryption.

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

3. GDPR Consent Enforcement (NEW — Week 5, Art. 7 & Art. 17):
   ``ConsentRegistry.is_consent_granted()`` is called by the
   ``authorize-decrypt`` endpoint BEFORE the AES-256-GCM decryption step.
   If the athlete has set ``privacy_toggle_consent = False``, the endpoint
   returns HTTP 403 immediately — no key material is ever used, and no
   plaintext is ever reconstructed.  This enforces GDPR Art. 7(3) (right
   to withdraw consent) and Art. 17 (right to be forgotten / erasure).

4. Availability (CIA Triad):
   Storage is persisted to a local JSON file (`mock_db.json`) so ingested
   records survive server restarts, simulating a durable (if simplistic)
   cloud persistence layer for this academic prototype.  The consent
   registry is in-memory (appropriate for a prototype); a production system
   would persist it to a dedicated, audited consent database.
"""

from __future__ import annotations

import json
import os
import threading
import time
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

# ---------------------------------------------------------------------------
# Week 5: Role-Based Access Control (RBAC) — authorised decryption roles.
# Only roles listed here may receive decrypted biometric data.  Adding a
# new authorised role requires an explicit change here (allow-list design).
# ---------------------------------------------------------------------------
AUTHORIZED_DECRYPT_ROLES: frozenset[str] = frozenset({"TEAM_DOCTOR"})


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
        """Atomically persist the full list of records to `mock_db.json`.

        Writes to a sibling `.tmp` file first, then performs an atomic
        `os.replace()` so that a crash mid-write never leaves a corrupt
        (partially-written) database file on disk.
        """
        tmp_path = self.db_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)
        os.replace(tmp_path, self.db_path)

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

        A server-assigned `received_at` UTC ISO-8601 timestamp is injected
        automatically, providing an audit trail of when each packet arrived
        at the cloud ingestion layer (independent of the edge-side `sent_at`).

        Args:
            record (Dict[str, Any]): Encrypted packet fields (gateway_id, device_id,
                                      player_id, sent_at, nonce, ciphertext, ...).

        Returns:
            Dict[str, Any]: The stored record including the server-assigned `received_at`.

        Raises:
            ValueError: If the record fails the storage isolation check (see
                        `_validate_storage_isolation`), i.e., it is not purely
                        encrypted ciphertext/nonce.
        """
        stored_record = dict(record)
        stored_record["received_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        self._validate_storage_isolation(stored_record)

        with self._lock:
            records = self._read_records()
            records.append(stored_record)
            self._write_records(records)

        return stored_record

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

    def get_stored_records_page(
        self, offset: int = 0, limit: int = 50
    ) -> Dict[str, Any]:
        """
        Return a paginated slice of stored records.

        Args:
            offset (int): Zero-based index of the first record to return.
            limit (int): Maximum number of records to return (capped at 200).

        Returns:
            Dict[str, Any]: A dict with keys ``total``, ``offset``, ``limit``,
                            and ``records`` (the requested slice).
        """
        limit = min(max(1, limit), 200)
        offset = max(0, offset)
        with self._lock:
            all_records = self._read_records()
        page = all_records[offset: offset + limit]
        return {
            "total": len(all_records),
            "offset": offset,
            "limit": limit,
            "records": page,
        }

    def delete_record(self, index: int) -> Dict[str, Any]:
        """
        Delete a stored record by its zero-based position in the database.

        Implements GDPR Art. 17 "right to erasure": an authorised caller may
        request permanent removal of a specific encrypted record. The operation
        is atomic — the database is never left in a partially-written state.

        Args:
            index (int): Zero-based position of the record to delete.

        Returns:
            Dict[str, Any]: The deleted record (for confirmation/audit logging).

        Raises:
            IndexError: If ``index`` is outside the range of stored records.
        """
        with self._lock:
            records = self._read_records()
            if index < 0 or index >= len(records):
                raise IndexError(
                    f"Record index {index} is out of range "
                    f"(database contains {len(records)} record(s))."
                )
            deleted = records.pop(index)
            self._write_records(records)
        return deleted


# ---------------------------------------------------------------------------
# Week 5 — GDPR Consent Registry
# ---------------------------------------------------------------------------

class ConsentRegistry:
    """
    Thread-safe in-memory GDPR consent registry.

    Maps ``player_id`` → ``privacy_toggle_consent`` (bool) and is the single
    authoritative source consulted by the ``authorize-decrypt`` endpoint before
    any decryption is allowed.  It is intentionally separate from
    ``CloudServer`` so that the consent-management concern is cleanly isolated
    from the encrypted-storage concern.

    Default Consent Policy:
        Athletes NOT yet registered in the registry are assumed to have
        **granted** consent (``True``), matching the ``AthleteDashboard``
        default.  The moment an athlete explicitly revokes consent via
        ``POST /api/v1/athlete/consent``, this registry records ``False``
        and the decryption endpoint will start rejecting requests.

    Thread Safety:
        All public methods acquire ``self._lock`` before reading or writing
        the internal state dictionary, making the registry safe for concurrent
        use by multiple FastAPI worker threads / async tasks.
    """

    def __init__(self) -> None:
        """Initialise an empty consent registry with a reentrant lock."""
        self._lock = threading.Lock()
        # {player_id: privacy_toggle_consent}
        self._registry: Dict[str, bool] = {}

    def set_consent(self, player_id: str, consent_status: bool) -> None:
        """
        Store or update the GDPR consent flag for the specified athlete.

        Called by ``POST /api/v1/athlete/consent`` whenever an athlete
        (or their dashboard client) submits a consent status update.

        Args:
            player_id (str):      Unique athlete identifier.
            consent_status (bool): New GDPR consent value.

        Raises:
            ValueError: If ``player_id`` is empty / not a string.
            TypeError:  If ``consent_status`` is not a bool.
        """
        if not player_id or not isinstance(player_id, str):
            raise ValueError("player_id must be a non-empty string.")
        if not isinstance(consent_status, bool):
            raise TypeError(
                f"consent_status must be a bool, got {type(consent_status).__name__}."
            )
        with self._lock:
            self._registry[player_id] = consent_status

    def is_consent_granted(self, player_id: str) -> bool:
        """
        Return whether the specified athlete has granted biometric access consent.

        Unknown athletes (not yet in the registry) are treated as having
        granted consent (matching the ``AthleteDashboard`` default of
        ``privacy_toggle_consent = True``).

        Args:
            player_id (str): Unique athlete identifier.

        Returns:
            bool: ``True`` if consent is granted (or athlete is not registered);
                  ``False`` if the athlete has explicitly revoked consent.
        """
        with self._lock:
            return self._registry.get(player_id, True)

    def get_all_consent_states(self) -> Dict[str, bool]:
        """
        Return a snapshot of the full registry for audit/debug purposes.

        Returns:
            Dict[str, bool]: A copy of the internal ``{player_id: consent}``
                             mapping (copy prevents external mutation).
        """
        with self._lock:
            return dict(self._registry)
