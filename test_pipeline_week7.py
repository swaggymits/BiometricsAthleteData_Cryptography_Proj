"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 7: Local Hashed Ledger & Transfer Escrow Simulation
Integration Test Suite

Validates the full Week 7 end-to-end transfer pipeline, connecting all
7 modules (IoTDeviceMock → SecureGateway → CloudServer → ConsentRegistry
→ AuditLogger → LocalHashedLedger → FastAPI) in a single unified flow.

Test Coverage
-------------
1.  **LocalHashedLedger Unit Tests**
    - Genesis block is created with correct fields on first init.
    - ``calculate_sha256`` is deterministic and reproducible.
    - ``append_transfer_block`` returns a correctly structured block.
    - ``validate_chain()`` returns ``True`` on an untampered ledger.

2.  **Happy Path Transfer**
    Consent=True, Escrow=True → HTTP 200, block committed, ``chain_valid=True``,
    audit row ``TRANSFER_BLOCK_CREATED / SUCCESS_200`` present in CSV.

3.  **GDPR Blocked Transfer**
    Athlete revokes consent → HTTP 403, NO new block appended to ledger,
    audit row ``DENIED_GDPR_403`` present in CSV.

4.  **Escrow Blocked Transfer**
    ``escrow_deposit_verified=False`` → HTTP 400, NO new block appended,
    audit row ``TRANSFER_DENIED_ESCROW`` present in CSV.

5.  **MITM Tampering Detection**
    Append a valid transfer block → manually corrupt a character inside
    ``ledger_file.json`` → ``validate_chain()`` returns ``False``,
    proving the Integrity gate of the CIA Triad is enforced.

Architecture
------------
FastAPI's ``TestClient`` exercises the real ASGI application in-process.
Each test class uses isolated files (``ledger_test_week7.json``,
``mock_db_test_week7.json``, ``audit_log_test_week7.csv``) cleaned up
in ``tearDownClass`` to prevent cross-test pollution.
"""

from __future__ import annotations

import os
import unittest

from fastapi.testclient import TestClient

import cloud_server as cloud_server_module
import main_server
from audit_logger import AuditLogger
from cloud_server import ConsentRegistry
from config import settings
from iot_device import IoTDeviceMock
from local_hashed_ledger import LocalHashedLedger
from pipeline_week2 import adapt_to_schema
from secure_gateway import SecureGateway

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

API_KEY_HEADERS: dict[str, str] = {"X-API-Key": settings.CLOUD_API_KEY}
TRANSFER_HEADERS: dict[str, str] = {**API_KEY_HEADERS, "X-User-Role": "CLUB_ADMIN"}

TEST_DB_PATH = "mock_db_test_week7.json"
TEST_LEDGER_PATH = "ledger_test_week7.json"
TEST_AUDIT_LOG_PATH = "audit_log_test_week7.csv"

PLAYER_ID = "PLAYER-W7-001"
GATEWAY_ID = "GW-W7-TEST-01"
DEVICE_ID = "IOT-WBAN-W7-01"
SELLING_CLUB = "FC-SELLING-UNITED"
BUYING_CLUB = "FC-BUYING-CITY"

TRANSFER_PAYLOAD = {
    "player_id": PLAYER_ID,
    "selling_club": SELLING_CLUB,
    "buying_club": BUYING_CLUB,
    "escrow_deposit_verified": True,
}


def _build_test_client(
    db_path: str,
    ledger_path: str,
    audit_log_path: str,
) -> TestClient:
    """
    Patch the module-level singletons in ``main_server`` so each test class
    gets its own isolated DB, ledger, and audit log.
    """
    main_server.cloud_server = cloud_server_module.CloudServer(db_path=db_path)
    main_server.consent_registry = ConsentRegistry()
    main_server.audit_logger = AuditLogger(log_file_path=audit_log_path)
    main_server.ledger = LocalHashedLedger(ledger_file_json=ledger_path)
    return TestClient(main_server.app, raise_server_exceptions=True)


def _ingest_player_record(client: TestClient, player_id: str) -> None:
    """Helper: generate, encrypt, and ingest one biometric packet for player_id."""
    aes_key = os.urandom(32)
    gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=aes_key)
    device = IoTDeviceMock(device_id=DEVICE_ID, player_id=player_id)
    raw = device.generate_biometrics()
    schema_payload = adapt_to_schema(raw)
    encrypted = gateway.encrypt_data(schema_payload, device_id=DEVICE_ID, player_id=player_id)
    resp = client.post(
        "/api/v1/telemetry/ingest",
        headers=API_KEY_HEADERS,
        json={
            "gateway_id": encrypted["gateway_id"],
            "device_id": encrypted.get("device_id"),
            "player_id": encrypted.get("player_id"),
            "sent_at": encrypted.get("sent_at"),
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
        },
    )
    assert resp.status_code == 201, f"Ingest failed: {resp.text}"


def _cleanup(*paths: str) -> None:
    for p in paths:
        if os.path.exists(p):
            os.remove(p)


# ===========================================================================
# 1. LocalHashedLedger Unit Tests
# ===========================================================================

class TestLocalHashedLedgerUnit(unittest.TestCase):
    """Pure unit tests for LocalHashedLedger — no FastAPI server required."""

    UNIT_LEDGER = "ledger_unit_test_week7.json"

    def setUp(self) -> None:
        _cleanup(self.UNIT_LEDGER)

    def tearDown(self) -> None:
        _cleanup(self.UNIT_LEDGER)

    # --- Genesis Block ---

    def test_genesis_block_created_on_init(self) -> None:
        """__init__ must create a JSON file containing exactly one Genesis Block."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        self.assertTrue(os.path.exists(self.UNIT_LEDGER), "Ledger file must be created.")
        chain = ledger.get_chain()
        self.assertEqual(len(chain), 1, "Chain must have exactly one block (genesis).")
        genesis = chain[0]
        self.assertEqual(genesis["index"], 0)
        self.assertEqual(genesis["player_id"], "GENESIS")
        self.assertEqual(genesis["previous_hash"], "0")
        self.assertIn("hash", genesis)
        self.assertTrue(len(genesis["hash"]) == 64, "SHA-256 hash must be 64 hex chars.")

    def test_existing_ledger_not_overwritten(self) -> None:
        """Re-initialising a ledger that already has blocks must NOT create a new genesis."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        ledger.append_transfer_block({
            "player_id": "P-001", "selling_club": "A", "buying_club": "B",
            "escrow_deposit_verified": True, "encrypted_payload_hash": "aabbcc",
        })
        ledger2 = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        self.assertEqual(len(ledger2.get_chain()), 2, "Re-init must preserve existing blocks.")

    # --- calculate_sha256 ---

    def test_sha256_is_deterministic(self) -> None:
        """calculate_sha256 must return the same digest for the same block content."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        block = {
            "index": 1, "timestamp": "2026-01-01T00:00:00.000Z",
            "player_id": "P-001", "selling_club": "A", "buying_club": "B",
            "escrow_deposit_verified": True, "encrypted_payload_hash": "abc",
            "previous_hash": "0", "hash": "",
        }
        h1 = ledger.calculate_sha256(block)
        h2 = ledger.calculate_sha256(block)
        self.assertEqual(h1, h2, "SHA-256 must be deterministic.")
        self.assertEqual(len(h1), 64, "SHA-256 digest must be 64 hex chars.")

    def test_sha256_excludes_hash_field(self) -> None:
        """The block's own 'hash' field must be excluded from SHA-256 input."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        block_a = {"index": 1, "data": "test", "hash": "old_hash_value"}
        block_b = {"index": 1, "data": "test", "hash": "different_hash_value"}
        self.assertEqual(
            ledger.calculate_sha256(block_a),
            ledger.calculate_sha256(block_b),
            "Blocks differing only in their 'hash' field must produce identical SHA-256.",
        )

    def test_sha256_changes_on_content_modification(self) -> None:
        """Changing any non-hash field must produce a different SHA-256 digest."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        block_a = {"index": 1, "player_id": "P-001", "hash": ""}
        block_b = {"index": 1, "player_id": "P-TAMPERED", "hash": ""}
        self.assertNotEqual(
            ledger.calculate_sha256(block_a),
            ledger.calculate_sha256(block_b),
            "Different content must produce different SHA-256.",
        )

    # --- append_transfer_block ---

    def test_append_returns_correct_block_fields(self) -> None:
        """append_transfer_block must return a dict with all required ledger fields."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        transfer_data = {
            "player_id": "P-001", "selling_club": "Club-A", "buying_club": "Club-B",
            "escrow_deposit_verified": True, "encrypted_payload_hash": "deadbeef",
        }
        block = ledger.append_transfer_block(transfer_data)

        for field in (
            "index", "timestamp", "player_id", "selling_club", "buying_club",
            "escrow_deposit_verified", "encrypted_payload_hash", "previous_hash", "hash",
        ):
            self.assertIn(field, block, f"Block must contain field '{field}'.")

        self.assertEqual(block["index"], 1, "First transfer block must have index 1.")
        self.assertEqual(block["player_id"], "P-001")
        self.assertEqual(block["selling_club"], "Club-A")
        self.assertEqual(block["buying_club"], "Club-B")
        self.assertTrue(block["escrow_deposit_verified"])
        self.assertEqual(len(block["hash"]), 64, "SHA-256 hash must be 64 hex chars.")

    def test_append_links_previous_hash(self) -> None:
        """Each appended block must link to the previous block's hash."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        genesis_hash = ledger.get_chain()[0]["hash"]
        block = ledger.append_transfer_block({
            "player_id": "P-001", "selling_club": "A", "buying_club": "B",
            "escrow_deposit_verified": True, "encrypted_payload_hash": "abc",
        })
        self.assertEqual(
            block["previous_hash"], genesis_hash,
            "Block's previous_hash must equal the genesis block's hash.",
        )

    # --- validate_chain ---

    def test_validate_chain_true_on_clean_ledger(self) -> None:
        """validate_chain() must return True for an untampered ledger."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        ledger.append_transfer_block({
            "player_id": "P-001", "selling_club": "A", "buying_club": "B",
            "escrow_deposit_verified": True, "encrypted_payload_hash": "abc",
        })
        self.assertTrue(ledger.validate_chain(), "Clean ledger must validate as True.")

    def test_validate_chain_genesis_only(self) -> None:
        """A genesis-only ledger must also validate as True."""
        ledger = LocalHashedLedger(ledger_file_json=self.UNIT_LEDGER)
        self.assertTrue(ledger.validate_chain())


# ===========================================================================
# 2. Happy Path Transfer
# ===========================================================================

class TestHappyPathTransfer(unittest.TestCase):
    """
    Consent=True, Escrow=True →
    HTTP 200, block committed, chain_valid=True, audit row exists.
    """

    @classmethod
    def setUpClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        cls.client = _build_test_client(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        _ingest_player_record(cls.client, PLAYER_ID)

        cls.resp = cls.client.post(
            "/api/v1/transfer/process",
            json=TRANSFER_PAYLOAD,
            headers=TRANSFER_HEADERS,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)

    def test_returns_http_200(self) -> None:
        """Happy path transfer must return HTTP 200."""
        self.assertEqual(self.resp.status_code, 200, self.resp.text)

    def test_response_contains_block(self) -> None:
        """Response body must contain a 'block' dict with ledger fields."""
        body = self.resp.json()
        self.assertIn("block", body)
        block = body["block"]
        self.assertEqual(block["player_id"], PLAYER_ID)
        self.assertEqual(block["selling_club"], SELLING_CLUB)
        self.assertEqual(block["buying_club"], BUYING_CLUB)
        self.assertTrue(block["escrow_deposit_verified"])
        self.assertEqual(block["index"], 1, "First transfer block must be at index 1.")

    def test_chain_valid_true_in_response(self) -> None:
        """Response must report chain_valid=True after a clean commit."""
        self.assertTrue(self.resp.json()["chain_valid"])

    def test_ledger_contains_transfer_block(self) -> None:
        """The JSON ledger file must contain the committed transfer block."""
        ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
        chain = ledger.get_chain()
        # Index 0 = genesis, index 1 = transfer block.
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[1]["player_id"], PLAYER_ID)

    def test_validate_chain_true_post_transfer(self) -> None:
        """validate_chain() called independently must return True."""
        ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
        self.assertTrue(ledger.validate_chain())

    def test_audit_log_has_success_entry(self) -> None:
        """audit_log CSV must contain a TRANSFER_BLOCK_CREATED/SUCCESS_200 row."""
        audit = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = audit.read_audit_log(player_id=PLAYER_ID)
        transfer_entries = [
            e for e in entries
            if e["action"] == "TRANSFER_BLOCK_CREATED" and e["status"] == "SUCCESS_200"
        ]
        self.assertGreater(len(transfer_entries), 0, "TRANSFER_BLOCK_CREATED audit entry must exist.")
        self.assertEqual(transfer_entries[0]["user_role"], "CLUB_ADMIN")


# ===========================================================================
# 3. GDPR Blocked Transfer
# ===========================================================================

class TestGDPRBlockedTransfer(unittest.TestCase):
    """
    Consent=False →
    HTTP 403, NO new block added to ledger, audit row DENIED_GDPR_403.
    """

    @classmethod
    def setUpClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        cls.client = _build_test_client(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        _ingest_player_record(cls.client, PLAYER_ID)

        # Revoke consent before the transfer attempt.
        r = cls.client.post(
            "/api/v1/athlete/consent",
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": False},
            headers=API_KEY_HEADERS,
        )
        assert r.status_code == 200, f"Consent revocation failed: {r.text}"

        cls.resp = cls.client.post(
            "/api/v1/transfer/process",
            json=TRANSFER_PAYLOAD,
            headers=TRANSFER_HEADERS,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)

    def test_returns_http_403(self) -> None:
        """GDPR-blocked transfer must return HTTP 403."""
        self.assertEqual(self.resp.status_code, 403, self.resp.text)

    def test_error_message_mentions_gdpr(self) -> None:
        """Error detail must reference GDPR consent."""
        self.assertIn("GDPR consent", self.resp.json()["detail"])

    def test_no_block_added_to_ledger(self) -> None:
        """No transfer block must be appended to the ledger when GDPR blocks the request."""
        ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
        chain = ledger.get_chain()
        # Only the genesis block should exist (index 0).
        self.assertEqual(len(chain), 1, "Ledger must contain ONLY the genesis block.")

    def test_audit_log_has_gdpr_denial_entry(self) -> None:
        """Audit CSV must contain a DENIED_GDPR_403 entry for the player."""
        audit = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = audit.read_audit_log(player_id=PLAYER_ID)
        gdpr_entries = [e for e in entries if e["status"] == "DENIED_GDPR_403"]
        self.assertGreater(len(gdpr_entries), 0, "DENIED_GDPR_403 audit entry must exist.")


# ===========================================================================
# 4. Escrow Blocked Transfer
# ===========================================================================

class TestEscrowBlockedTransfer(unittest.TestCase):
    """
    Escrow=False →
    HTTP 400, NO new block added to ledger, audit row TRANSFER_DENIED_ESCROW.
    """

    @classmethod
    def setUpClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        cls.client = _build_test_client(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)
        _ingest_player_record(cls.client, PLAYER_ID)

        cls.resp = cls.client.post(
            "/api/v1/transfer/process",
            json={**TRANSFER_PAYLOAD, "escrow_deposit_verified": False},
            headers=TRANSFER_HEADERS,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        _cleanup(TEST_DB_PATH, TEST_LEDGER_PATH, TEST_AUDIT_LOG_PATH)

    def test_returns_http_400(self) -> None:
        """Escrow-blocked transfer must return HTTP 400."""
        self.assertEqual(self.resp.status_code, 400, self.resp.text)

    def test_error_message_mentions_escrow(self) -> None:
        """Error detail must reference escrow deposit."""
        self.assertIn("Escrow deposit not verified", self.resp.json()["detail"])

    def test_no_block_added_to_ledger(self) -> None:
        """No transfer block must be appended when the escrow gate blocks the request."""
        ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
        chain = ledger.get_chain()
        self.assertEqual(len(chain), 1, "Ledger must contain ONLY the genesis block.")

    def test_audit_log_has_escrow_denial_entry(self) -> None:
        """Audit CSV must contain a TRANSFER_DENIED_ESCROW entry for the player."""
        audit = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = audit.read_audit_log(player_id=PLAYER_ID)
        escrow_entries = [e for e in entries if e["status"] == "TRANSFER_DENIED_ESCROW"]
        self.assertGreater(len(escrow_entries), 0, "TRANSFER_DENIED_ESCROW audit entry must exist.")


# ===========================================================================
# 5. MITM Tampering Detection (CIA Triad — Integrity)
# ===========================================================================

class TestMITMTamperingDetection(unittest.TestCase):
    """
    Integrity (CIA Triad):
    Appending a valid transfer block and then manually corrupting a single
    character inside the ledger JSON must cause validate_chain() to return
    False — proving the SHA-256 chain detects Man-in-the-Middle tampering.
    """

    MITM_LEDGER = "ledger_mitm_test_week7.json"

    def setUp(self) -> None:
        _cleanup(self.MITM_LEDGER)
        self.ledger = LocalHashedLedger(ledger_file_json=self.MITM_LEDGER)
        # Append a real transfer block.
        self.ledger.append_transfer_block({
            "player_id": PLAYER_ID,
            "selling_club": SELLING_CLUB,
            "buying_club": BUYING_CLUB,
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "aabbccddeeff001122334455",
        })

    def tearDown(self) -> None:
        _cleanup(self.MITM_LEDGER)

    def test_validate_chain_true_before_tampering(self) -> None:
        """validate_chain() must return True before any tampering."""
        self.assertTrue(
            self.ledger.validate_chain(),
            "Chain must be valid before any modification.",
        )

    def test_mitm_player_id_corruption_detected(self) -> None:
        """
        MITM Tampering Attack Test:
        Changing the player_id inside ledger_file.json must invalidate the chain.
        This simulates an attacker altering a medical/performance record post-transfer.
        """
        with open(self.MITM_LEDGER, encoding="utf-8") as fh:
            raw = fh.read()

        # Replace the player's actual ID with a tampered value.
        tampered = raw.replace(PLAYER_ID, "TAMPERED-PLAYER-ID", 1)
        with open(self.MITM_LEDGER, "w", encoding="utf-8") as fh:
            fh.write(tampered)

        self.assertFalse(
            self.ledger.validate_chain(),
            "validate_chain() MUST return False when player_id is tampered.",
        )

    def test_mitm_encrypted_hash_corruption_detected(self) -> None:
        """
        Changing the encrypted_payload_hash inside the ledger must also
        invalidate the chain — detecting record substitution attacks.
        """
        with open(self.MITM_LEDGER, encoding="utf-8") as fh:
            raw = fh.read()

        tampered = raw.replace("aabbccddeeff001122334455", "0000000000000000000000000", 1)
        with open(self.MITM_LEDGER, "w", encoding="utf-8") as fh:
            fh.write(tampered)

        self.assertFalse(
            self.ledger.validate_chain(),
            "validate_chain() MUST return False when encrypted_payload_hash is tampered.",
        )

    def test_mitm_club_name_corruption_detected(self) -> None:
        """
        Changing the buying_club inside the ledger must invalidate the chain.
        This simulates an attacker altering the destination club in a transfer record.
        """
        with open(self.MITM_LEDGER, encoding="utf-8") as fh:
            raw = fh.read()

        tampered = raw.replace(BUYING_CLUB, "FC-FAKE-DESTINATION", 1)
        with open(self.MITM_LEDGER, "w", encoding="utf-8") as fh:
            fh.write(tampered)

        self.assertFalse(
            self.ledger.validate_chain(),
            "validate_chain() MUST return False when buying_club is tampered.",
        )

    def test_chain_length_unchanged_after_tampering(self) -> None:
        """
        Tampering with the file must NOT change the apparent chain length —
        proving that validation rejects corrupted data, not just missing data.
        """
        chain_before = self.ledger.get_chain()

        with open(self.MITM_LEDGER, encoding="utf-8") as fh:
            raw = fh.read()
        with open(self.MITM_LEDGER, "w", encoding="utf-8") as fh:
            fh.write(raw.replace(PLAYER_ID, "TAMPERED", 1))

        chain_after = self.ledger.get_chain()
        self.assertEqual(
            len(chain_before), len(chain_after),
            "Chain length must remain the same; validate_chain detects content, not presence.",
        )
        self.assertFalse(self.ledger.validate_chain())


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
