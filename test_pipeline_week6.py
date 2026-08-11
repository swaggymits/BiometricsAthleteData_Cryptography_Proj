"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 6: Audit Logging & Anti-Black Market Protection
Integration Test Suite

Validates 100% audit trail coverage across all access paths through
the ``/api/v1/telemetry/authorize-decrypt`` and related endpoints.

Test Coverage
-------------
1.  **AuditLogger Unit Tests**
    - CSV file created with correct headers on ``__init__``.
    - ``log_access()`` appends a row and returns the correct dict.
    - ``read_audit_log()`` returns all rows (unfiltered).
    - ``read_audit_log(player_id=...)`` filters correctly.

2.  **Traceability Test (Happy Path)**
    TEAM_DOCTOR performs valid decryption
    → Row appears in ``audit_log.csv`` with ``action=VIEW_BIOMETRIC_DATA``
      and ``status=SUCCESS_200``.

3.  **Leak Attempt Detection (RBAC Block)**
    EXTERNAL_COMPANY attempts decryption (consent granted, wrong role)
    → HTTP 403 returned AND row appears in CSV with ``status=DENIED_RBAC_403``.

4.  **GDPR Block Trace (Consent Revoked)**
    TEAM_DOCTOR attempts decryption after athlete revokes consent
    → HTTP 403 returned AND row appears in CSV with ``status=DENIED_GDPR_403``.

5.  **Audit Immutability Check**
    After multiple access events, every CSV entry must have:
    - A parseable ISO 8601 UTC timestamp.
    - A non-empty ``user_role`` field that matches the caller.
    - Entries ordered chronologically (append-only guarantee).

Architecture
------------
FastAPI's ``TestClient`` (backed by ``httpx``) exercises the real ASGI
application in-process — no separately running ``uvicorn`` server needed.
Isolated test files (``audit_log_test_week6.csv``, ``mock_db_test_week6.json``)
are cleaned up in ``tearDownClass`` to prevent cross-test pollution.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime

from fastapi.testclient import TestClient

import cloud_server as cloud_server_module
import main_server
from audit_logger import AuditLogger
from cloud_server import ConsentRegistry
from config import settings
from iot_device import IoTDeviceMock
from pipeline_week2 import adapt_to_schema
from secure_gateway import SecureGateway

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

API_KEY_HEADERS: dict[str, str] = {"X-API-Key": settings.CLOUD_API_KEY}

TEST_DB_PATH = "mock_db_test_week6.json"
TEST_AUDIT_LOG_PATH = "audit_log_test_week6.csv"

PLAYER_ID = "PLAYER-W6-001"
GATEWAY_ID = "GW-W6-TEST-01"
DEVICE_ID = "IOT-WBAN-W6-01"


def _build_test_client(db_path: str, audit_log_path: str) -> TestClient:
    """
    Patch the module-level singletons in ``main_server`` so each test class
    gets its own isolated database and audit log file.
    """
    main_server.cloud_server = cloud_server_module.CloudServer(db_path=db_path)
    main_server.consent_registry = ConsentRegistry()
    main_server.audit_logger = AuditLogger(log_file_path=audit_log_path)
    return TestClient(main_server.app, raise_server_exceptions=True)


def _encrypt_and_ingest(
    client: TestClient,
    gateway: SecureGateway,
    player_id: str,
    gateway_id: str,
    device_id: str,
) -> dict:
    """
    Helper: generate a biometric reading, encrypt it, ingest it via the API,
    and return the raw encrypted packet dict for use in decrypt tests.
    """
    device = IoTDeviceMock(device_id=device_id, player_id=player_id)
    raw_reading = device.generate_biometrics()
    schema_reading = adapt_to_schema(raw_reading)
    encrypted = gateway.encrypt_data(
        schema_reading,
        device_id=device_id,
        player_id=player_id,
    )
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
    return encrypted


# ===========================================================================
# 1. AuditLogger Unit Tests
# ===========================================================================

class TestAuditLoggerUnit(unittest.TestCase):
    """Pure unit tests for AuditLogger — no FastAPI server involved."""

    UNIT_LOG_PATH = "audit_log_unit_test_week6.csv"

    def setUp(self) -> None:
        """Remove the test CSV before each test to start fresh."""
        if os.path.exists(self.UNIT_LOG_PATH):
            os.remove(self.UNIT_LOG_PATH)

    def tearDown(self) -> None:
        """Clean up the test CSV after each test."""
        if os.path.exists(self.UNIT_LOG_PATH):
            os.remove(self.UNIT_LOG_PATH)

    # --- Initialisation ---

    def test_init_creates_csv_with_headers(self) -> None:
        """AuditLogger.__init__ must create the CSV file with the correct header row."""
        AuditLogger(log_file_path=self.UNIT_LOG_PATH)

        self.assertTrue(
            os.path.exists(self.UNIT_LOG_PATH),
            "CSV file should be created on __init__.",
        )

        with open(self.UNIT_LOG_PATH, encoding="utf-8") as fh:
            header_line = fh.readline().strip()

        self.assertEqual(
            header_line,
            "timestamp,user_id,user_role,player_id,action,status,ip_address",
            "First row must be the exact CSV header.",
        )

    def test_init_does_not_overwrite_existing_file(self) -> None:
        """If the log file already exists, __init__ must not erase its contents."""
        # Create a logger once so the file and headers exist.
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        logger.log_access(
            user_id="TEAM_DOCTOR",
            user_role="TEAM_DOCTOR",
            player_id="PLAYER-PERSIST",
            action="VIEW_BIOMETRIC_DATA",
            status="SUCCESS_200",
        )

        # Construct a second logger pointing at the same file.
        logger2 = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        rows = logger2.read_audit_log()

        self.assertEqual(
            len(rows), 1,
            "Re-opening the logger must not erase previously written entries.",
        )

    # --- log_access ---

    def test_log_access_returns_correct_dict(self) -> None:
        """log_access() must return a dict with all 7 fields populated correctly."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        entry = logger.log_access(
            user_id="TEAM_DOCTOR",
            user_role="TEAM_DOCTOR",
            player_id="PLAYER-001",
            action="VIEW_BIOMETRIC_DATA",
            status="SUCCESS_200",
            ip_address="10.0.0.1",
        )

        self.assertEqual(entry["user_id"], "TEAM_DOCTOR")
        self.assertEqual(entry["user_role"], "TEAM_DOCTOR")
        self.assertEqual(entry["player_id"], "PLAYER-001")
        self.assertEqual(entry["action"], "VIEW_BIOMETRIC_DATA")
        self.assertEqual(entry["status"], "SUCCESS_200")
        self.assertEqual(entry["ip_address"], "10.0.0.1")
        self.assertIn("timestamp", entry)
        self.assertTrue(
            entry["timestamp"].endswith("Z"),
            "Timestamp must be UTC ISO 8601 (ending in Z).",
        )

    def test_log_access_appends_row_to_csv(self) -> None:
        """log_access() must write exactly one new data row per call."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        logger.log_access("u1", "ROLE_A", "P-001", "ACTION_X", "SUCCESS")
        logger.log_access("u2", "ROLE_B", "P-002", "ACTION_Y", "DENIED_RBAC_403")

        rows = logger.read_audit_log()
        self.assertEqual(len(rows), 2, "Two calls → two rows in the CSV.")
        self.assertEqual(rows[0]["status"], "SUCCESS")
        self.assertEqual(rows[1]["status"], "DENIED_RBAC_403")

    def test_log_access_default_ip_address(self) -> None:
        """When ip_address is omitted, it should default to '127.0.0.1'."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        entry = logger.log_access("u1", "ROLE_A", "P-001", "ACTION", "SUCCESS")
        self.assertEqual(entry["ip_address"], "127.0.0.1")

    # --- read_audit_log ---

    def test_read_audit_log_returns_all_rows(self) -> None:
        """read_audit_log() with no filter must return all written rows."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        for i in range(5):
            logger.log_access("u", "ROLE", f"P-{i:03d}", "ACTION", "SUCCESS")

        rows = logger.read_audit_log()
        self.assertEqual(len(rows), 5)

    def test_read_audit_log_filters_by_player_id(self) -> None:
        """read_audit_log(player_id=X) must return only rows matching player_id X."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        logger.log_access("u", "ROLE", "TARGET-PLAYER", "ACTION", "SUCCESS")
        logger.log_access("u", "ROLE", "OTHER-PLAYER", "ACTION", "SUCCESS")
        logger.log_access("u", "ROLE", "TARGET-PLAYER", "ACTION", "SUCCESS")

        filtered = logger.read_audit_log(player_id="TARGET-PLAYER")
        self.assertEqual(len(filtered), 2)
        for row in filtered:
            self.assertEqual(row["player_id"], "TARGET-PLAYER")

    def test_read_audit_log_empty_file(self) -> None:
        """read_audit_log() on a freshly-created (header-only) file returns []."""
        logger = AuditLogger(log_file_path=self.UNIT_LOG_PATH)
        rows = logger.read_audit_log()
        self.assertEqual(rows, [])


# ===========================================================================
# 2. Traceability Test — Happy Path (TEAM_DOCTOR)
# ===========================================================================

class TestTraceability(unittest.TestCase):
    """
    Anti-Black Market Traceability:
    A successful decryption by TEAM_DOCTOR MUST leave a traceable row in the
    audit log, enabling forensic investigators to pinpoint exactly who accessed
    which athlete's biometrics and when.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Clean up any stale test artifacts before the test run.
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

        cls.aes_key = os.urandom(32)
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=cls.aes_key)
        cls.client = _build_test_client(
            db_path=TEST_DB_PATH,
            audit_log_path=TEST_AUDIT_LOG_PATH,
        )
        cls.encrypted_packet = _encrypt_and_ingest(
            cls.client, cls.gateway, PLAYER_ID, GATEWAY_ID, DEVICE_ID
        )

        # Perform the successful decrypt in setup so both test methods see
        # the SUCCESS_200 entry regardless of alphabetical execution order.
        cls.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={
                "record": cls.encrypted_packet,
                "aes_key_hex": cls.aes_key.hex(),
            },
            headers={
                **API_KEY_HEADERS,
                "X-User-Role": "TEAM_DOCTOR",
                "X-Player-Id": PLAYER_ID,
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

    def test_successful_decrypt_creates_audit_entry(self) -> None:
        """
        Traceability Test:
        POST /authorize-decrypt as TEAM_DOCTOR → HTTP 200
        AND a row with status=SUCCESS_200 must exist in the audit CSV.
        """
        # The actual decrypt call was made in setUpClass; verify the audit entry.
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        success_entries = [e for e in entries if e["status"] == "SUCCESS_200"]

        self.assertGreater(
            len(success_entries), 0,
            "At least one SUCCESS_200 entry must exist in the audit log for this player.",
        )
        entry = success_entries[0]
        self.assertEqual(entry["action"], "VIEW_BIOMETRIC_DATA")
        self.assertEqual(entry["user_role"], "TEAM_DOCTOR")
        self.assertEqual(entry["player_id"], PLAYER_ID)

    def test_audit_entry_contains_valid_timestamp(self) -> None:
        """
        The SUCCESS_200 audit entry's timestamp must be a parseable ISO 8601
        UTC string — ensuring the entry can be correlated with other system logs.
        """
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        success_entries = [e for e in entries if e["status"] == "SUCCESS_200"]
        self.assertGreater(len(success_entries), 0)

        ts_str = success_entries[0]["timestamp"].rstrip("Z")
        try:
            datetime.fromisoformat(ts_str)
        except ValueError:
            self.fail(f"Timestamp '{ts_str}Z' is not a valid ISO 8601 datetime.")


# ===========================================================================
# 3. Leak Attempt Detection — RBAC Block
# ===========================================================================

class TestLeakAttemptDetection(unittest.TestCase):
    """
    Anti-Black Market: if a data broker or external entity with an API key
    attempts to access biometric data under an unauthorized role, this must
    be blocked AND the attempt must be permanently recorded in the audit log.
    """

    @classmethod
    def setUpClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

        cls.aes_key = os.urandom(32)
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=cls.aes_key)
        cls.client = _build_test_client(
            db_path=TEST_DB_PATH,
            audit_log_path=TEST_AUDIT_LOG_PATH,
        )
        cls.encrypted_packet = _encrypt_and_ingest(
            cls.client, cls.gateway, PLAYER_ID, GATEWAY_ID, DEVICE_ID
        )

        # Perform both RBAC-denied requests in setup so all test methods see
        # the audit entries regardless of alphabetical execution order.
        for role in ("EXTERNAL_COMPANY", "ANALYST"):
            cls.client.post(
                "/api/v1/telemetry/authorize-decrypt",
                json={"record": cls.encrypted_packet, "aes_key_hex": cls.aes_key.hex()},
                headers={**API_KEY_HEADERS, "X-User-Role": role, "X-Player-Id": PLAYER_ID},
            )

    @classmethod
    def tearDownClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

    def test_external_company_gets_403(self) -> None:
        """EXTERNAL_COMPANY must receive HTTP 403 (RBAC denial)."""
        resp = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={
                "record": self.encrypted_packet,
                "aes_key_hex": self.aes_key.hex(),
            },
            headers={
                **API_KEY_HEADERS,
                "X-User-Role": "EXTERNAL_COMPANY",
                "X-Player-Id": PLAYER_ID,
            },
        )
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertIn("Insufficient Role Permissions", resp.json()["detail"])

    def test_rbac_denial_creates_audit_entry(self) -> None:
        """
        Leak Attempt Detection:
        RBAC denial must produce a DENIED_RBAC_403 row in the audit log,
        giving investigators a full record of the unauthorized access attempt.
        """
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        # Filter specifically for the EXTERNAL_COMPANY RBAC denial entry.
        rbac_entries = [
            e for e in entries
            if e["status"] == "DENIED_RBAC_403" and e["user_role"] == "EXTERNAL_COMPANY"
        ]

        self.assertGreater(
            len(rbac_entries), 0,
            "At least one DENIED_RBAC_403 entry must exist in the audit log.",
        )
        entry = rbac_entries[0]
        self.assertEqual(entry["action"], "VIEW_BIOMETRIC_DATA")
        self.assertEqual(entry["user_role"], "EXTERNAL_COMPANY")
        self.assertEqual(entry["player_id"], PLAYER_ID)

    def test_analyst_role_also_denied_and_traced(self) -> None:
        """ANALYST role must also produce HTTP 403 and a DENIED_RBAC_403 audit row."""
        # The ANALYST attempt was already made in setUpClass; verify the audit row.
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        analyst_denied = [
            e for e in entries
            if e["status"] == "DENIED_RBAC_403" and e["user_role"] == "ANALYST"
        ]
        self.assertGreater(len(analyst_denied), 0, "ANALYST denial must be traced.")


# ===========================================================================
# 4. GDPR Block Trace — Consent Revoked
# ===========================================================================

class TestGDPRBlockTrace(unittest.TestCase):
    """
    GDPR Accountability (Art. 5(2) + Art. 7(3)):
    When an athlete revokes consent, all subsequent decryption attempts must be
    blocked AND logged with status DENIED_GDPR_403, providing an auditable
    record that the system honoured the athlete's withdrawal of consent.
    """

    @classmethod
    def setUpClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

        cls.aes_key = os.urandom(32)
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=cls.aes_key)
        cls.client = _build_test_client(
            db_path=TEST_DB_PATH,
            audit_log_path=TEST_AUDIT_LOG_PATH,
        )
        cls.encrypted_packet = _encrypt_and_ingest(
            cls.client, cls.gateway, PLAYER_ID, GATEWAY_ID, DEVICE_ID
        )

        # Athlete revokes consent via the consent endpoint.
        resp = cls.client.post(
            "/api/v1/athlete/consent",
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": False},
            headers=API_KEY_HEADERS,
        )
        assert resp.status_code == 200, f"Consent revocation failed: {resp.text}"

        # Immediately attempt decryption as TEAM_DOCTOR so that the
        # DENIED_GDPR_403 audit entry exists before any test method runs.
        cls.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={"record": cls.encrypted_packet, "aes_key_hex": cls.aes_key.hex()},
            headers={**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

    def test_revoked_consent_returns_403(self) -> None:
        """TEAM_DOCTOR decryption attempt with revoked consent must return HTTP 403."""
        resp = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={
                "record": self.encrypted_packet,
                "aes_key_hex": self.aes_key.hex(),
            },
            headers={
                **API_KEY_HEADERS,
                "X-User-Role": "TEAM_DOCTOR",
                "X-Player-Id": PLAYER_ID,
            },
        )
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertIn("revoked biometric consent", resp.json()["detail"])

    def test_gdpr_denial_creates_audit_entry(self) -> None:
        """
        GDPR Block Trace:
        Access attempt after consent revocation must produce a DENIED_GDPR_403
        row in the audit log — providing a compliance record that GDPR Art. 7(3)
        (right to withdraw consent) was enforced.
        """
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        gdpr_entries = [e for e in entries if e["status"] == "DENIED_GDPR_403"]

        self.assertGreater(
            len(gdpr_entries), 0,
            "At least one DENIED_GDPR_403 entry must exist in the audit log.",
        )
        entry = gdpr_entries[0]
        self.assertEqual(entry["action"], "VIEW_BIOMETRIC_DATA")
        self.assertEqual(entry["user_role"], "TEAM_DOCTOR")
        self.assertEqual(entry["player_id"], PLAYER_ID)

    def test_consent_update_creates_audit_entry(self) -> None:
        """
        The consent revocation itself (POST /api/v1/athlete/consent) must also
        be recorded in the audit log as CONSENT_REVOKED / SUCCESS.
        """
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = logger.read_audit_log(player_id=PLAYER_ID)
        revoke_entries = [e for e in entries if e["action"] == "CONSENT_REVOKED"]

        self.assertGreater(
            len(revoke_entries), 0,
            "POST /api/v1/athlete/consent must produce a CONSENT_REVOKED audit entry.",
        )
        self.assertEqual(revoke_entries[0]["status"], "SUCCESS")


# ===========================================================================
# 5. Audit Immutability Check
# ===========================================================================

class TestAuditImmutability(unittest.TestCase):
    """
    Verifies the structural integrity of the audit log after a mixed sequence
    of access events — ensuring timestamps are valid ISO 8601, roles are
    preserved exactly, and entries appear in chronological order.
    """

    @classmethod
    def setUpClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

        cls.aes_key = os.urandom(32)
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=cls.aes_key)
        cls.client = _build_test_client(
            db_path=TEST_DB_PATH,
            audit_log_path=TEST_AUDIT_LOG_PATH,
        )
        cls.encrypted_packet = _encrypt_and_ingest(
            cls.client, cls.gateway, PLAYER_ID, GATEWAY_ID, DEVICE_ID
        )

        # 1. Successful decrypt (TEAM_DOCTOR)
        cls.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={"record": cls.encrypted_packet, "aes_key_hex": cls.aes_key.hex()},
            headers={**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
        )
        # 2. RBAC denial (EXTERNAL_COMPANY)
        cls.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={"record": cls.encrypted_packet, "aes_key_hex": cls.aes_key.hex()},
            headers={**API_KEY_HEADERS, "X-User-Role": "EXTERNAL_COMPANY", "X-Player-Id": PLAYER_ID},
        )
        # 3. Revoke consent and try again (GDPR denial)
        cls.client.post(
            "/api/v1/athlete/consent",
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": False},
            headers=API_KEY_HEADERS,
        )
        cls.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            json={"record": cls.encrypted_packet, "aes_key_hex": cls.aes_key.hex()},
            headers={**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for path in (TEST_AUDIT_LOG_PATH, TEST_DB_PATH):
            if os.path.exists(path):
                os.remove(path)

    def _get_player_entries(self) -> list[dict]:
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        return logger.read_audit_log(player_id=PLAYER_ID)

    def test_all_timestamps_are_valid_iso8601_utc(self) -> None:
        """Every audit entry timestamp must be a parseable UTC ISO 8601 datetime."""
        entries = self._get_player_entries()
        self.assertGreater(len(entries), 0)

        for entry in entries:
            ts = entry["timestamp"]
            self.assertTrue(
                ts.endswith("Z"),
                f"Timestamp '{ts}' must end with 'Z' to indicate UTC.",
            )
            try:
                datetime.fromisoformat(ts.rstrip("Z"))
            except ValueError:
                self.fail(f"Timestamp '{ts}' is not a valid ISO 8601 datetime.")

    def test_user_roles_preserved_exactly(self) -> None:
        """
        Each audit entry's user_role must match the role that was used in the
        request — roles must NEVER be mutated or normalized in the log.
        """
        entries = self._get_player_entries()
        roles_seen = {e["user_role"] for e in entries}

        self.assertIn("TEAM_DOCTOR", roles_seen, "TEAM_DOCTOR role must appear in log.")
        self.assertIn("EXTERNAL_COMPANY", roles_seen, "EXTERNAL_COMPANY role must appear in log.")

    def test_all_three_status_types_recorded(self) -> None:
        """
        After the setup sequence, all three audit status types must be present
        for this player: SUCCESS_200, DENIED_RBAC_403, DENIED_GDPR_403.
        """
        entries = self._get_player_entries()
        statuses_seen = {e["status"] for e in entries}

        self.assertIn("SUCCESS_200", statuses_seen, "SUCCESS_200 must be in audit log.")
        self.assertIn("DENIED_RBAC_403", statuses_seen, "DENIED_RBAC_403 must be in audit log.")
        self.assertIn("DENIED_GDPR_403", statuses_seen, "DENIED_GDPR_403 must be in audit log.")

    def test_entries_are_in_chronological_order(self) -> None:
        """
        Since the log is append-only, timestamps must be non-decreasing —
        verifying the immutability/ordering guarantee of the CSV trail.
        """
        entries = self._get_player_entries()
        timestamps = [
            datetime.fromisoformat(e["timestamp"].rstrip("Z"))
            for e in entries
        ]
        for i in range(1, len(timestamps)):
            self.assertGreaterEqual(
                timestamps[i],
                timestamps[i - 1],
                "Audit log entries must be in chronological (non-decreasing) order.",
            )

    def test_no_plaintext_biometrics_in_audit_log(self) -> None:
        """
        The audit log must never contain any raw biometric field names —
        ensuring data minimization is maintained even in the accounting trail.
        """
        BIOMETRIC_FIELD_NAMES = {
            "heart_rate", "vo2_max", "lactate_threshold",
            "muscle_oxygen", "core_temperature",
        }
        logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        all_entries = logger.read_audit_log()

        for entry in all_entries:
            row_values = " ".join(str(v) for v in entry.values()).lower()
            for field in BIOMETRIC_FIELD_NAMES:
                self.assertNotIn(
                    field, row_values,
                    f"Biometric field '{field}' must NEVER appear in the audit log.",
                )


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
