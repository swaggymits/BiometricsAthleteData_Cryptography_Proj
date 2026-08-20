"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Month 2 — Week 5: Access Control & GDPR Consent Toggle
Integration Test Suite

Validates the FULL Week 5 access-control pipeline:

Test Coverage
-------------
1.  **Consent Granted + Authorised Role (Happy Path)**
    ``privacy_toggle_consent = True`` + ``user_role = "TEAM_DOCTOR"``
    → Successful decryption (HTTP 200).

2.  **GDPR Revocation Block**
    ``privacy_toggle_consent = False`` + ``user_role = "TEAM_DOCTOR"``
    → HTTP 403 "Access Denied: Athlete has revoked biometric consent under GDPR."

3.  **Unauthorised Role Block**
    ``privacy_toggle_consent = True`` + ``user_role = "EXTERNAL_COMPANY"``
    → HTTP 403 "Access Denied: Insufficient Role Permissions."

4.  **Additional RBAC role verification**
    ``privacy_toggle_consent = True`` + ``user_role = "ANALYST"``
    → HTTP 403 "Access Denied: Insufficient Role Permissions."

5.  **Database Encryption Integrity Assertion**
    After all consent-toggle operations, ``mock_db.json`` must contain
    ZERO plaintext biometric field names / values — i.e., the consent
    toggle NEVER affects the encryption-at-rest guarantee.

6.  **AthleteDashboard Unit Tests**
    - ``__init__`` defaults, ``get_athlete_state()``.
    - ``update_consent()`` returns a correctly structured, HMAC-signed packet.
    - ``authenticate()`` succeeds with valid credentials and fails cleanly with invalid ones.
    - ``update_consent()`` correctly mutates ``privacy_toggle_consent``.

7.  **ConsentRegistry Unit Tests**
    - Default (unknown player) returns ``True``.
    - ``set_consent`` / ``is_consent_granted`` round-trip.
    - ``get_all_consent_states`` snapshot.

8.  **Consent Endpoint Tests**
    - ``POST /api/v1/athlete/consent`` accepts grant / revoke payloads.
    - Requires ``X-API-Key`` (401 without it).

Architecture used:
    FastAPI's ``TestClient`` (backed by ``httpx``) exercises the real ASGI
    application in-process — no separately running ``uvicorn`` server needed.
    Each test class uses an isolated ``mock_db_test_week5.json`` file that is
    torn down at the end of the class, preventing cross-test pollution.
"""

from __future__ import annotations

import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import server.cloud_server as cloud_server_module
import server.main_server as main_server
from evaluation.athlete_dashboard import AthleteDashboard
from server.cloud_server import ConsentRegistry
from server.config import settings
from edge.iot_device import IoTDeviceMock
from edge.pipeline_week2 import adapt_to_schema
from core.secure_gateway import SecureGateway

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

API_KEY_HEADERS: dict[str, str] = {"X-API-Key": settings.CLOUD_API_KEY}
TEST_DB_PATH = "mock_db_test_week5.json"

PLAYER_ID = "PLAYER-W5-001"
GATEWAY_ID = "GW-W5-TEST-01"
DEVICE_ID = "IOT-WBAN-W5-01"


# ---------------------------------------------------------------------------
# Helper: build the full request payload for /authorize-decrypt
# ---------------------------------------------------------------------------

def _build_decrypt_request(
    encrypted_packet: dict,
    shared_key: bytes,
    user_role: str,
    player_id: str,
    *,
    extra_headers: dict | None = None,
) -> tuple[dict, dict]:
    """
    Return ``(json_body, headers)`` ready for the ``authorize-decrypt`` endpoint.

    Extra headers allow individual tests to override values for edge-case checks.
    """
    headers: dict[str, str] = {
        **API_KEY_HEADERS,
        "X-User-Role": user_role,
        "X-Player-Id": player_id,
        **(extra_headers or {}),
    }
    body = {
        "record": {
            "gateway_id": encrypted_packet["gateway_id"],
            "device_id": encrypted_packet.get("device_id"),
            "player_id": encrypted_packet.get("player_id"),
            "sent_at": encrypted_packet.get("sent_at"),
            "nonce": encrypted_packet["nonce"],
            "ciphertext": encrypted_packet["ciphertext"],
        },
        "aes_key_hex": shared_key.hex(),
    }
    return body, headers


# ===========================================================================
# Test Suite 1 — AthleteDashboard Unit Tests
# ===========================================================================

class TestAthleteDashboard(unittest.TestCase):
    """Unit tests for the ``AthleteDashboard`` logic class (Week 5)."""

    def setUp(self) -> None:
        self.dashboard = AthleteDashboard(player_id=PLAYER_ID)

    # --- Construction & defaults ---

    def test_init_sets_player_id(self) -> None:
        self.assertEqual(self.dashboard.player_id, PLAYER_ID)

    def test_init_consent_defaults_to_true(self) -> None:
        self.assertTrue(
            self.dashboard.privacy_toggle_consent,
            "Default consent must be True (opt-in on enrollment).",
        )

    def test_init_login_status_defaults_to_false(self) -> None:
        self.assertFalse(
            self.dashboard.login_status,
            "Dashboard must start unauthenticated.",
        )

    def test_invalid_player_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            AthleteDashboard(player_id="")

    def test_invalid_player_id_type_raises(self) -> None:
        with self.assertRaises((ValueError, TypeError)):
            AthleteDashboard(player_id=None)  # type: ignore[arg-type]

    # --- get_athlete_state ---

    def test_get_athlete_state_returns_correct_keys(self) -> None:
        state = self.dashboard.get_athlete_state()
        self.assertIn("player_id", state)
        self.assertIn("privacy_toggle_consent", state)
        self.assertIn("login_status", state)

    def test_get_athlete_state_values_match_attributes(self) -> None:
        state = self.dashboard.get_athlete_state()
        self.assertEqual(state["player_id"], PLAYER_ID)
        self.assertTrue(state["privacy_toggle_consent"])
        self.assertFalse(state["login_status"])

    # --- update_consent ---

    def test_update_consent_revoke_changes_flag(self) -> None:
        self.dashboard.update_consent(False)
        self.assertFalse(
            self.dashboard.privacy_toggle_consent,
            "Revoking consent must set privacy_toggle_consent to False.",
        )

    def test_update_consent_grant_changes_flag(self) -> None:
        self.dashboard.update_consent(False)
        self.dashboard.update_consent(True)
        self.assertTrue(
            self.dashboard.privacy_toggle_consent,
            "Re-granting consent must set privacy_toggle_consent back to True.",
        )

    def test_update_consent_returns_signed_packet(self) -> None:
        packet = self.dashboard.update_consent(False)
        self.assertEqual(packet["player_id"], PLAYER_ID)
        self.assertFalse(packet["privacy_toggle_consent"])
        self.assertIn("issued_at", packet)
        self.assertIn("gdpr_basis", packet)
        self.assertIn("signature_hmac_sha256", packet)

    def test_update_consent_packet_gdpr_basis_revocation(self) -> None:
        packet = self.dashboard.update_consent(False)
        self.assertEqual(packet["gdpr_basis"], "GDPR_Art7_ConsentWithdrawal")

    def test_update_consent_packet_gdpr_basis_grant(self) -> None:
        packet = self.dashboard.update_consent(True)
        self.assertEqual(packet["gdpr_basis"], "GDPR_Art7_ConsentGranted")

    def test_update_consent_signature_is_hex_string(self) -> None:
        packet = self.dashboard.update_consent(True)
        sig = packet["signature_hmac_sha256"]
        # Must be a 64-char hex string (SHA-256 = 32 bytes = 64 hex chars)
        self.assertIsInstance(sig, str)
        self.assertEqual(len(sig), 64)
        bytes.fromhex(sig)  # raises ValueError if not valid hex

    def test_update_consent_type_error_on_non_bool(self) -> None:
        with self.assertRaises(TypeError):
            self.dashboard.update_consent("yes")  # type: ignore[arg-type]

    # --- authenticate ---

    def test_authenticate_success_sets_login_status(self) -> None:
        result = self.dashboard.authenticate(
            {"username": "athlete_admin", "password": "securePass123!"}
        )
        self.assertTrue(result, "Valid credentials must return True.")
        self.assertTrue(
            self.dashboard.login_status,
            "login_status must be True after successful authentication.",
        )

    def test_authenticate_wrong_password_returns_false(self) -> None:
        result = self.dashboard.authenticate(
            {"username": "athlete_admin", "password": "wrongPassword!"}
        )
        self.assertFalse(result)
        self.assertFalse(self.dashboard.login_status)

    def test_authenticate_unknown_user_returns_false(self) -> None:
        result = self.dashboard.authenticate(
            {"username": "unknown_user", "password": "irrelevant"}
        )
        self.assertFalse(result)

    def test_authenticate_missing_key_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.dashboard.authenticate({"username": "athlete_admin"})

    def test_authenticate_non_dict_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            self.dashboard.authenticate("not-a-dict")  # type: ignore[arg-type]


# ===========================================================================
# Test Suite 2 — ConsentRegistry Unit Tests
# ===========================================================================

class TestConsentRegistry(unittest.TestCase):
    """Unit tests for the in-memory ``ConsentRegistry`` (Week 5)."""

    def setUp(self) -> None:
        self.registry = ConsentRegistry()

    def test_unknown_player_defaults_to_consent_true(self) -> None:
        self.assertTrue(
            self.registry.is_consent_granted("PLAYER-UNKNOWN"),
            "Unknown athletes must default to consent = True.",
        )

    def test_set_and_get_consent_false(self) -> None:
        self.registry.set_consent("PLAYER-001", False)
        self.assertFalse(self.registry.is_consent_granted("PLAYER-001"))

    def test_set_and_get_consent_true(self) -> None:
        self.registry.set_consent("PLAYER-001", False)
        self.registry.set_consent("PLAYER-001", True)
        self.assertTrue(self.registry.is_consent_granted("PLAYER-001"))

    def test_multiple_players_independent(self) -> None:
        self.registry.set_consent("PLAYER-A", False)
        self.registry.set_consent("PLAYER-B", True)
        self.assertFalse(self.registry.is_consent_granted("PLAYER-A"))
        self.assertTrue(self.registry.is_consent_granted("PLAYER-B"))

    def test_get_all_consent_states_snapshot(self) -> None:
        self.registry.set_consent("P1", True)
        self.registry.set_consent("P2", False)
        snap = self.registry.get_all_consent_states()
        self.assertEqual(snap["P1"], True)
        self.assertEqual(snap["P2"], False)

    def test_snapshot_is_a_copy(self) -> None:
        self.registry.set_consent("P3", True)
        snap = self.registry.get_all_consent_states()
        snap["P3"] = False  # mutate the copy
        self.assertTrue(
            self.registry.is_consent_granted("P3"),
            "External mutation of the snapshot must not affect the registry.",
        )

    def test_invalid_player_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.registry.set_consent("", True)

    def test_non_bool_consent_raises(self) -> None:
        with self.assertRaises(TypeError):
            self.registry.set_consent("PLAYER-X", "yes")  # type: ignore[arg-type]


# ===========================================================================
# Test Suite 3 — FastAPI GDPR Consent & RBAC Integration Tests
# ===========================================================================

class TestWeek5Pipeline(unittest.TestCase):
    """
    End-to-end integration tests validating the Week 5 GDPR Consent Management
    and Role-Based Access Control (RBAC) enforcement via the FastAPI test client.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Isolate this test run's storage and consent registry from real state.
        main_server.cloud_server = cloud_server_module.CloudServer(db_path=TEST_DB_PATH)
        main_server.consent_registry = cloud_server_module.ConsentRegistry()
        cls.client = TestClient(main_server.app)

        # Shared AES key for all encrypt/decrypt operations in this suite.
        cls.shared_key: bytes = AESGCM.generate_key(bit_length=256)

        # IoT device and gateway fixtures.
        cls.device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=cls.shared_key)

        # Encrypt and ingest a single biometric packet that will be used by
        # the consent/RBAC tests.  Ingestion uses a fresh record each test
        # class setup to avoid cross-run contamination.
        raw = cls.device.generate_biometrics()
        schema_payload = adapt_to_schema(raw)
        cls.encrypted_packet: dict = cls.gateway.encrypt_data(
            schema_payload,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )
        cls.schema_payload = schema_payload

        ingest_resp = cls.client.post(
            "/api/v1/telemetry/ingest",
            headers=API_KEY_HEADERS,
            json={
                "gateway_id": cls.encrypted_packet["gateway_id"],
                "device_id": cls.encrypted_packet.get("device_id"),
                "player_id": cls.encrypted_packet.get("player_id"),
                "sent_at": cls.encrypted_packet.get("sent_at"),
                "nonce": cls.encrypted_packet["nonce"],
                "ciphertext": cls.encrypted_packet["ciphertext"],
            },
        )
        assert ingest_resp.status_code == 201, (
            f"Setup: ingest failed with {ingest_resp.status_code}: {ingest_resp.text}"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

    # ------------------------------------------------------------------
    # Helper: reset consent to True for PLAYER_ID before each test so
    # tests are fully independent of ordering.
    # ------------------------------------------------------------------

    def _grant_consent(self, player_id: str = PLAYER_ID) -> None:
        resp = self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": player_id, "privacy_toggle_consent": True},
        )
        self.assertEqual(resp.status_code, 200, resp.text)

    def _revoke_consent(self, player_id: str = PLAYER_ID) -> None:
        resp = self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": player_id, "privacy_toggle_consent": False},
        )
        self.assertEqual(resp.status_code, 200, resp.text)

    # ------------------------------------------------------------------
    # TEST 1: Consent Granted Path — TEAM_DOCTOR → HTTP 200
    # ------------------------------------------------------------------

    def test_01_consent_granted_team_doctor_gets_200(self) -> None:
        """
        Consent Granted Path:
        privacy_toggle_consent = True + user_role = 'TEAM_DOCTOR' → HTTP 200.
        """
        self._grant_consent()

        body, headers = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="TEAM_DOCTOR",
            player_id=PLAYER_ID,
        )
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(
            response.status_code, 200,
            f"[FAIL] Consent=True + TEAM_DOCTOR should yield 200. Got: {response.text}",
        )
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(
            data["decrypted_payload"],
            self.schema_payload,
            "Decrypted payload must exactly match the original schema payload.",
        )

    # ------------------------------------------------------------------
    # TEST 2: GDPR Revocation Path — TEAM_DOCTOR but consent = False → HTTP 403
    # ------------------------------------------------------------------

    def test_02_gdpr_revocation_blocks_team_doctor(self) -> None:
        """
        GDPR Revocation Path:
        privacy_toggle_consent = False + user_role = 'TEAM_DOCTOR' → HTTP 403.
        Revoked consent must block even an authorised role.
        """
        self._revoke_consent()

        body, headers = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="TEAM_DOCTOR",
            player_id=PLAYER_ID,
        )
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(
            response.status_code, 403,
            f"[FAIL] Consent=False must yield 403 regardless of role. Got: {response.status_code}",
        )
        detail = response.json().get("detail", "")
        self.assertIn(
            "revoked biometric consent under GDPR",
            detail,
            f"Response detail must reference GDPR consent revocation. Got: {detail!r}",
        )

        # Restore consent for subsequent tests.
        self._grant_consent()

    # ------------------------------------------------------------------
    # TEST 3: Unauthorised Role Path — EXTERNAL_COMPANY → HTTP 403
    # ------------------------------------------------------------------

    def test_03_unauthorized_role_external_company_gets_403(self) -> None:
        """
        Unauthorised Role Path:
        privacy_toggle_consent = True + user_role = 'EXTERNAL_COMPANY' → HTTP 403.
        """
        self._grant_consent()

        body, headers = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="EXTERNAL_COMPANY",
            player_id=PLAYER_ID,
        )
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(
            response.status_code, 403,
            f"[FAIL] EXTERNAL_COMPANY must be rejected with 403. Got: {response.status_code}",
        )
        detail = response.json().get("detail", "")
        self.assertIn(
            "Insufficient Role Permissions",
            detail,
            f"Response detail must reference RBAC failure. Got: {detail!r}",
        )

    # ------------------------------------------------------------------
    # TEST 4: Additional RBAC — ANALYST role → HTTP 403
    # ------------------------------------------------------------------

    def test_04_unauthorized_role_analyst_gets_403(self) -> None:
        """
        Authorised consent but insufficient role:
        privacy_toggle_consent = True + user_role = 'ANALYST' → HTTP 403.
        """
        self._grant_consent()

        body, headers = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="ANALYST",
            player_id=PLAYER_ID,
        )
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("Insufficient Role Permissions", response.json().get("detail", ""))

    # ------------------------------------------------------------------
    # TEST 5: Database Encryption Integrity After Consent Toggles
    # ------------------------------------------------------------------

    def test_05_database_remains_100_percent_encrypted_after_consent_toggles(
        self,
    ) -> None:
        """
        Assert mock_db.json contains ZERO plaintext biometric field names or
        values after multiple consent grant/revoke cycles.

        GDPR consent toggles MUST NOT alter the at-rest encryption guarantee.
        The database must remain 100% ciphertext regardless of consent state.
        """
        # Run a few consent toggles to exercise the code path.
        self._revoke_consent()
        self._grant_consent()
        self._revoke_consent()
        self._grant_consent()

        if not os.path.exists(TEST_DB_PATH):
            self.skipTest(f"Test DB {TEST_DB_PATH} not found — skip encryption assertion.")

        with open(TEST_DB_PATH, encoding="utf-8") as fh:
            db_contents = fh.read()

        # These are the plaintext biometric field names (keys in the JSON
        # schema) — none of them should appear verbatim in the database.
        plaintext_field_markers = [
            "heart_rate",
            "fatigue_index",
            "glucose_level",
            "gps_telemetry",
            "injury_risk",
            "latitude",
            "longitude",
            "speed_m_s",
        ]

        for marker in plaintext_field_markers:
            self.assertNotIn(
                marker,
                db_contents,
                f"SECURITY FAILURE: plaintext field '{marker}' found in {TEST_DB_PATH}! "
                f"Consent toggle must NOT break at-rest encryption.",
            )

        # Additionally verify every stored record has valid hex fields.
        db_records: list = json.loads(db_contents) if db_contents.strip() else []
        for record in db_records:
            self.assertIn("nonce", record, "Stored record missing 'nonce' field.")
            self.assertIn("ciphertext", record, "Stored record missing 'ciphertext' field.")
            # Confirm hex decodability (i.e., definitely not plaintext).
            bytes.fromhex(record["nonce"])
            bytes.fromhex(record["ciphertext"])

    # ------------------------------------------------------------------
    # TEST 6: Consent Endpoint Itself
    # ------------------------------------------------------------------

    def test_06_consent_endpoint_requires_api_key(self) -> None:
        """The consent endpoint must be protected by X-API-Key."""
        response = self.client.post(
            "/api/v1/athlete/consent",
            # No X-API-Key header
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
        )
        self.assertEqual(response.status_code, 401)

    def test_07_consent_endpoint_grant_returns_200(self) -> None:
        resp = self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["player_id"], PLAYER_ID)
        self.assertTrue(body["privacy_toggle_consent"])

    def test_08_consent_endpoint_revoke_returns_200(self) -> None:
        resp = self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": False},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["privacy_toggle_consent"])
        # Restore
        self._grant_consent()

    # ------------------------------------------------------------------
    # TEST 7: Missing required headers on authorize-decrypt
    # ------------------------------------------------------------------

    def test_09_authorize_decrypt_missing_role_header_returns_422(self) -> None:
        """If X-User-Role header is absent, FastAPI returns 422 (required header)."""
        self._grant_consent()
        body, _ = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="TEAM_DOCTOR",
            player_id=PLAYER_ID,
        )
        headers = {**API_KEY_HEADERS, "X-Player-Id": PLAYER_ID}  # no X-User-Role
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(response.status_code, 422)

    def test_10_authorize_decrypt_missing_player_id_header_returns_422(self) -> None:
        """If X-Player-Id header is absent, FastAPI returns 422 (required header)."""
        self._grant_consent()
        body, _ = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="TEAM_DOCTOR",
            player_id=PLAYER_ID,
        )
        headers = {**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR"}  # no X-Player-Id
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=headers,
            json=body,
        )
        self.assertEqual(response.status_code, 422)

    # ------------------------------------------------------------------
    # TEST 8: Consent revocation blocks even with correct credentials
    #         and then re-grant restores access
    # ------------------------------------------------------------------

    def test_11_consent_revoke_then_regrant_restores_access(self) -> None:
        """
        Lifecycle test: revoke → blocked → re-grant → access restored.
        This verifies the toggle is genuinely reversible.
        """
        # Step 1: Revoke
        self._revoke_consent()
        body, headers = _build_decrypt_request(
            self.encrypted_packet,
            self.shared_key,
            user_role="TEAM_DOCTOR",
            player_id=PLAYER_ID,
        )
        resp = self.client.post("/api/v1/telemetry/authorize-decrypt", headers=headers, json=body)
        self.assertEqual(resp.status_code, 403, "Revoked consent must block access.")

        # Step 2: Re-grant
        self._grant_consent()
        resp = self.client.post("/api/v1/telemetry/authorize-decrypt", headers=headers, json=body)
        self.assertEqual(resp.status_code, 200, "Re-granted consent must restore access.")
        self.assertEqual(resp.json()["status"], "success")


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
