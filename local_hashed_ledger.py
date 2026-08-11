"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 7: Local Hashed Ledger & Transfer Escrow Simulation

Implements the ``LocalHashedLedger`` class — a lightweight, stdlib-only
Python blockchain that maintains an immutable, append-only record of
athlete transfer events.

Purpose & Compliance Context
-----------------------------
Integrity (CIA Triad):
    Each block in the ledger contains the SHA-256 hash of its own content
    AND the hash of the previous block, forming a cryptographic chain.
    Any post-hoc modification of a committed transfer record — even a
    single character change — immediately invalidates the chain and is
    detected by ``validate_chain()``.  This directly implements the
    Integrity leg of the CIA triad for the transfer data pipeline.

Anti-Black Market Traceability:
    When a player's encrypted biometric data is transferred between clubs,
    the SHA-256 hash of those encrypted records is committed to the ledger.
    This creates an evidence trail: even if decrypted data is later leaked
    or sold, investigators can cross-reference the ledger to identify
    exactly which clubs held the records and when the transfer occurred.

Transfer Escrow Simulation:
    The ``escrow_deposit_verified`` field models a real-world payment escrow
    gate — a transfer block is only written once financial settlement is
    confirmed (simulated by a boolean in this academic prototype).  Rejecting
    unverified transfers prevents ledger entries from being created before the
    financial conditions are satisfied.

GDPR Art. 5(1)(f) — Integrity & Confidentiality:
    Personal data must be processed in a manner that ensures appropriate
    security, including protection against accidental or unlawful alteration.
    The SHA-256 chain validation mechanism directly implements this requirement
    for the transfer ledger.

Design Decisions
----------------
- **Append-only JSON file** — human-readable, trivially auditable, and
  replicable without a dedicated database engine.
- **Atomic writes** — write to a ``.tmp`` sibling file, then ``os.replace()``,
  so a crash mid-write never corrupts the ledger.
- **``sort_keys=True`` in SHA-256 serialisation** — guarantees deterministic
  hash computation regardless of Python dict insertion order.
- **stdlib-only** — ``hashlib``, ``json``, ``os``, ``threading``, ``datetime``;
  zero new dependencies.
- **Thread-safe** — a ``threading.Lock`` serialises all reads and writes.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class LocalHashedLedger:
    """
    Lightweight SHA-256 blockchain for athlete transfer records.

    Each block contains transfer metadata, the SHA-256 hash of the
    athlete's encrypted biometric payload (providing a tamper-evident
    data fingerprint), and a chain of cryptographic hashes linking every
    block to its predecessor — making any retroactive modification
    immediately detectable via ``validate_chain()``.

    Attributes:
        ledger_file_json (str): Filesystem path to the JSON ledger file.
    """

    def __init__(self, ledger_file_json: str = "ledger_file.json") -> None:
        """
        Initialise the ledger and ensure the backing file exists.

        If the ledger file is absent or empty, a **Genesis Block** is
        written immediately.  The Genesis Block anchors the chain:
        it has ``index=0``, ``previous_hash="0"``, and placeholder
        values for all transfer-specific fields.

        Args:
            ledger_file_json (str): Path to the local JSON ledger file.
                                     Defaults to ``"ledger_file.json"``
                                     in the current working directory.
        """
        self.ledger_file_json = ledger_file_json
        self._lock = threading.Lock()
        self._initialise_ledger()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _initialise_ledger(self) -> None:
        """Write a Genesis Block if the ledger file is absent or empty."""
        if os.path.exists(self.ledger_file_json):
            try:
                with open(self.ledger_file_json, encoding="utf-8") as fh:
                    existing = json.load(fh)
                if isinstance(existing, list) and len(existing) > 0:
                    return  # Ledger already has content — nothing to do.
            except (json.JSONDecodeError, OSError):
                pass  # Corrupt/empty file — re-create with genesis block.

        genesis_block = self._build_genesis_block()
        self._write_chain([genesis_block])

    def _build_genesis_block(self) -> dict:
        """Construct and return the Genesis Block (index 0)."""
        block: Dict[str, Any] = {
            "index": 0,
            "timestamp": self._utc_now(),
            "player_id": "GENESIS",
            "selling_club": "GENESIS",
            "buying_club": "GENESIS",
            "escrow_deposit_verified": False,
            "encrypted_payload_hash": "0",
            "previous_hash": "0",
            "hash": "",  # Placeholder — filled in below.
        }
        block["hash"] = self.calculate_sha256(block)
        return block

    def _read_chain(self) -> List[dict]:
        """Load all blocks from the JSON ledger (empty list on failure)."""
        if not os.path.exists(self.ledger_file_json):
            return []
        try:
            with open(self.ledger_file_json, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _write_chain(self, chain: List[dict]) -> None:
        """
        Atomically persist the full chain to the JSON ledger.

        Writes to a sibling ``.tmp`` file first, then performs an atomic
        ``os.replace()`` so that a crash mid-write never leaves a corrupt
        ledger on disk.
        """
        tmp_path = self.ledger_file_json + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(chain, fh, indent=2)
        os.replace(tmp_path, self.ledger_file_json)

    @staticmethod
    def _utc_now() -> str:
        """Return the current time as an ISO 8601 UTC string."""
        return (
            datetime.now(tz=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate_sha256(self, block: dict) -> str:
        """
        Compute the SHA-256 hash of a block dictionary.

        The block's own ``hash`` field is excluded before serialisation so
        that the hash is computed over the *content* of the block only.
        ``sort_keys=True`` guarantees a deterministic byte sequence
        regardless of Python dict insertion order.

        Args:
            block (dict): A block dictionary (may or may not contain a
                          ``"hash"`` key — it is always excluded).

        Returns:
            str: Lowercase hex-encoded SHA-256 digest.
        """
        block_copy = {k: v for k, v in block.items() if k != "hash"}
        serialised = json.dumps(block_copy, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    def append_transfer_block(self, transfer_data: dict) -> dict:
        """
        Build, hash, and append a new transfer block to the ledger.

        Constructs a new block from ``transfer_data`` plus chain-state
        metadata (``index``, ``timestamp``, ``previous_hash``), computes
        its SHA-256 hash, appends it atomically to the JSON ledger, and
        returns the committed block.

        Args:
            transfer_data (dict): Must contain the following keys:
                - ``player_id`` (str)
                - ``selling_club`` (str)
                - ``buying_club`` (str)
                - ``escrow_deposit_verified`` (bool)
                - ``encrypted_payload_hash`` (str)

        Returns:
            dict: The fully constructed and hashed block that was appended.

        Raises:
            ValueError: If any required field is missing from
                        ``transfer_data``.
        """
        required_fields = {
            "player_id", "selling_club", "buying_club",
            "escrow_deposit_verified", "encrypted_payload_hash",
        }
        missing = required_fields - set(transfer_data.keys())
        if missing:
            raise ValueError(
                f"transfer_data is missing required field(s): {sorted(missing)}"
            )

        with self._lock:
            chain = self._read_chain()
            last_block = chain[-1] if chain else {"hash": "0", "index": -1}

            new_block: Dict[str, Any] = {
                "index": last_block.get("index", -1) + 1,
                "timestamp": self._utc_now(),
                "player_id": transfer_data["player_id"],
                "selling_club": transfer_data["selling_club"],
                "buying_club": transfer_data["buying_club"],
                "escrow_deposit_verified": transfer_data["escrow_deposit_verified"],
                "encrypted_payload_hash": transfer_data["encrypted_payload_hash"],
                "previous_hash": last_block["hash"],
                "hash": "",  # Placeholder — filled in below.
            }
            new_block["hash"] = self.calculate_sha256(new_block)

            chain.append(new_block)
            self._write_chain(chain)

        return new_block

    def validate_chain(self) -> bool:
        """
        Verify the cryptographic integrity of the entire ledger chain.

        For every block (starting from index 1), this method:
        1. Recomputes the block's SHA-256 hash and compares it to the
           stored ``hash`` field — detecting any content modification.
        2. Verifies that ``block["previous_hash"]`` equals the preceding
           block's ``hash`` — detecting any block insertion, deletion,
           or reordering.

        Returns:
            bool: ``True`` if the chain is fully intact and unmodified;
                  ``False`` if any block fails either check (indicating
                  a data tampering or Man-in-the-Middle attack).

        Note:
            A single-block ledger (genesis only) is trivially valid.
            An empty ledger (file missing/corrupt) is also considered valid
            (vacuously true — nothing to verify).
        """
        with self._lock:
            chain = self._read_chain()

        if len(chain) <= 1:
            # Genesis-only or empty ledger — no links to validate.
            if chain:
                # Still verify the genesis block's own hash.
                genesis = chain[0]
                return self.calculate_sha256(genesis) == genesis.get("hash", "")
            return True

        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i - 1]

            # Check 1: recomputed hash must match stored hash.
            if self.calculate_sha256(current) != current.get("hash", ""):
                return False

            # Check 2: previous_hash must match the preceding block's hash.
            if current.get("previous_hash") != previous.get("hash"):
                return False

        return True

    def get_chain(self) -> List[dict]:
        """
        Return a copy of the full chain for inspection or API responses.

        Returns:
            List[dict]: All blocks currently in the ledger, in order.
        """
        with self._lock:
            return list(self._read_chain())
