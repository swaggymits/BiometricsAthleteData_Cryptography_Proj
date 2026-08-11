"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Task 1 — Week 8: Hybrid ECDH + AES-GCM Key Exchange
Integration & Unit Test Suite

Validates the complete Week 8 ECDH hybrid architecture across all layers:
  ecdh_key_exchange  →  SecureGateway  →  AthleteDashboard  →  CloudServer
  →  main_server (FastAPI ASGI) — end-to-end pipeline.

Test Coverage
-------------
1.  ``TestECDHKeyExchange``
    Unit tests for ``ecdh_key_exchange.py``:
    - Key pair generation produces distinct keys on every call.
    - Session key derivation is deterministic (same pair → same 32-byte key).
    - Mismatched key pairs yield different session keys (isolation).
    - Public-key serialisation round-trip preserves key identity.
    - ``build_session_info`` produces deterministic, pipe-delimited bytes.
    - ``derive_session_key`` raises ``TypeError`` on wrong argument types.
    - Deserialization of garbage PEM raises ``ValueError``.

2.  ``TestSecureGatewayHybrid``
    Unit tests for the new gateway methods:
    - ``encrypt_data_hybrid`` / ``decrypt_data_hybrid`` full round-trip.
    - Wrong private key → ``cryptography.exceptions.InvalidTag``.
    - Tampered ``ephemeral_public_key_pem`` → ``InvalidTag``.
    - Tampered ``ciphertext`` byte → ``InvalidTag``.
    - Tampered AAD field (player_id) → ``InvalidTag``.
    - Missing required hybrid packet field → ``KeyError``.
    - Original ``encrypt_data()`` / ``decrypt_data()`` still pass (backward compat).

3.  ``TestAthleteDashboardClubAuth``
    Unit tests for the club authorization control plane:
    - ``authorize_club`` / ``revoke_club`` / ``get_authorized_club_key`` lifecycle.
    - Double-revoke is idempotent (returns ``False``, does not raise).
    - Revoked GDPR consent blocks ``get_authorized_club_key`` even if club authorized.
    - Unauthorized club raises ``PermissionError``.
    - ``get_authorization_status`` snapshot is accurate throughout the lifecycle.

4.  ``TestHybridEndToEndPipeline``
    Integration (FastAPI ``TestClient``) — full flow:
    - Generate club EC key pair → athlete registers club key → gateway encrypts
      → ingest to server → club decrypts via ``/api/v1/telemetry/authorize-decrypt-hybrid``.
    - Club key revocation → ``authorize-decrypt-hybrid`` returns HTTP 403.
    - Revoked GDPR consent → ``authorize-decrypt-hybrid`` returns HTTP 403.
    - Unregistered club → ``authorize-decrypt-hybrid`` returns HTTP 403.
    - Wrong private key → ``authorize-decrypt-hybrid`` returns HTTP 401.
    - ``/api/v1/keys/register-club`` returns HTTP 200 with correct body.
    - ``/api/v1/keys/revoke-club`` is idempotent.

5.  ``TestMultiTenantIsolation``
    Security regression — two clubs with distinct key pairs:
    - Club A's private key cannot decrypt Club B's ciphertext (``InvalidTag``).
    - Club B's private key cannot decrypt Club A's ciphertext (``InvalidTag``).
    - Each club can decrypt their own ciphertext successfully.

Architecture
------------
``FastAPI``'s ``TestClient`` exercises the real ASGI application in-process.
Each integration test class uses isolated files (``mock_db_test_week8.json``,
``audit_log_test_week8.csv``, ``ledger_test_week8.json``) cleaned up in
``tearDownClass`` to prevent cross-test pollution.

All private-key PEM serialisation in these tests uses
``cryptography.hazmat.primitives.serialization`` directly — the same library
used by the production code — to avoid introducing additional dependencies.
"""

from __future__ import annotations

import os
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

import cloud_server as cloud_server_module
import main_server
from audit_logger import AuditLogger
from cloud_server import ConsentRegistry
from config import settings
from ecdh_key_exchange import (
    build_session_info,
    derive_session_key,
    deserialize_public_key,
    generate_ec_keypair,
    serialize_public_key,
)
from iot_device import IoTDeviceMock
from local_hashed_ledger import LocalHashedLedger
from pipeline_week2 import adapt_to_schema
from secure_gateway import SecureGateway

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

API_KEY_HEADERS: dict[str, str] = {"X-API-Key": settings.CLOUD_API_KEY}
DECRYPT_HYBRID_HEADERS: dict[str, str] = {
    **API_KEY_HEADERS,
    "X-User-Role": "TEAM_DOCTOR",
    "X-Player-Id": "PLAYER-W8-001",
}

TEST_DB_PATH = "mock_db_test_week8.json"
TEST_AUDIT_LOG_PATH = "audit_log_test_week8.csv"
TEST_LEDGER_PATH = "ledger_test_week8.json"

PLAYER_ID = "PLAYER-W8-001"
GATEWAY_ID = "GW-W8-TEST-01"
DEVICE_ID = "IOT-WBAN-W8-01"
CLUB_A_ID = "FC-BUYING-CITY-A"
CLUB_B_ID = "FC-BUYING-CITY-B"


def _serialize_private_key_pem(private_key) -> bytes:
    """Serialize a private key to unencrypted PEM bytes for test use."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _build_test_client(
    db_path: str = TEST_DB_PATH,
    audit_log_path: str = TEST_AUDIT_LOG_PATH,
    ledger_path: str = TEST_LEDGER_PATH,
) -> TestClient:
    """
    Patch module-level singletons in ``main_server`` so each test class gets
    its own isolated DB, audit log, ledger, and a fresh ClubKeyRegistry.
    """
    main_server.cloud_server = cloud_server_module.CloudServer(db_path=db_path)
    main_server.consent_registry = ConsentRegistry()
    main_server.audit_logger = AuditLogger(log_file_path=audit_log_path)
    main_server.ledger = LocalHashedLedger(ledger_file_json=ledger_path)
    main_server.club_key_registry = main_server.ClubKeyRegistry()
    return TestClient(main_server.app, raise_server_exceptions=True)


def _cleanup(*paths: str) -> None:
    for p in paths:
        if os.path.exists(p):
            os.remove(p)


def _cleanup_test_files() -> None:
    _cleanup(TEST_DB_PATH, TEST_AUDIT_LOG_PATH, TEST_LEDGER_PATH)


# ===========================================================================
# 1. ecdh_key_exchange Unit Tests
# ===========================================================================

class TestECDHKeyExchange(unittest.TestCase):
    """Pure unit tests for the ecdh_key_exchange module."""

    # --- generate_ec_keypair ---

    def test_generate_returns_private_and_public_key(self) -> None:
        """generate_ec_keypair() must return a (private, public) tuple."""
        priv, pub = generate_ec_keypair()
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePrivateKey,
            EllipticCurvePublicKey,
        )
        self.assertIsInstance(priv, EllipticCurvePrivateKey)
        self.assertIsInstance(pub, EllipticCurvePublicKey)

    def test_generate_produces_distinct_key_pairs(self) -> None:
        """Two calls must produce cryptographically independent key pairs."""
        _, pub1 = generate_ec_keypair()
        _, pub2 = generate_ec_keypair()
        pem1 = serialize_public_key(pub1)
        pem2 = serialize_public_key(pub2)
        self.assertNotEqual(pem1, pem2, "Two independently generated public keys must differ.")

    # --- serialize / deserialize_public_key ---

    def test_serialize_produces_pem_bytes(self) -> None:
        """serialize_public_key() must return bytes beginning with PEM header."""
        _, pub = generate_ec_keypair()
        pem = serialize_public_key(pub)
        self.assertIsInstance(pem, bytes)
        self.assertTrue(
            pem.startswith(b"-----BEGIN PUBLIC KEY-----"),
            "PEM must begin with standard header.",
        )

    def test_serialize_deserialize_roundtrip(self) -> None:
        """deserialize_public_key(serialize_public_key(pub)) must reproduce the same PEM."""
        _, pub = generate_ec_keypair()
        pem = serialize_public_key(pub)
        reconstructed = deserialize_public_key(pem)
        self.assertEqual(
            serialize_public_key(reconstructed),
            pem,
            "Round-trip serialization must preserve key identity.",
        )

    def test_deserialize_garbage_raises_value_error(self) -> None:
        """Passing invalid bytes to deserialize_public_key must raise ValueError."""
        with self.assertRaises(ValueError):
            deserialize_public_key(b"this is not a valid PEM key")

    def test_serialize_type_error_on_non_ec_key(self) -> None:
        """serialize_public_key() must raise TypeError for non-EC inputs."""
        with self.assertRaises(TypeError):
            serialize_public_key("not_a_key")  # type: ignore[arg-type]

    # --- derive_session_key ---

    def test_derive_session_key_returns_32_bytes(self) -> None:
        """derive_session_key() must always return exactly 32 bytes."""
        priv_a, pub_a = generate_ec_keypair()
        priv_b, pub_b = generate_ec_keypair()
        key = derive_session_key(priv_a, pub_b)
        self.assertEqual(len(key), 32, "Session key must be exactly 32 bytes (AES-256).")

    def test_derive_session_key_is_deterministic(self) -> None:
        """Same key pair + same session_info must always produce the same session key."""
        priv_a, pub_a = generate_ec_keypair()
        priv_b, pub_b = generate_ec_keypair()
        info = b"GW-01|PLAYER-77|FC-CITY"
        key1 = derive_session_key(priv_a, pub_b, session_info=info)
        key2 = derive_session_key(priv_a, pub_b, session_info=info)
        self.assertEqual(key1, key2, "HKDF derivation must be deterministic.")

    def test_ecdh_is_commutative(self) -> None:
        """
        ECDH is commutative: A.derive(B.pub) == B.derive(A.pub).
        This is the core invariant that makes ECDH work.
        """
        priv_a, pub_a = generate_ec_keypair()
        priv_b, pub_b = generate_ec_keypair()
        info = b"same-context"
        key_ab = derive_session_key(priv_a, pub_b, session_info=info)
        key_ba = derive_session_key(priv_b, pub_a, session_info=info)
        self.assertEqual(
            key_ab, key_ba,
            "ECDH must produce the same shared secret from both sides.",
        )

    def test_different_session_info_produces_different_keys(self) -> None:
        """Different session_info bytes must produce different session keys."""
        priv_a, pub_a = generate_ec_keypair()
        priv_b, pub_b = generate_ec_keypair()
        key1 = derive_session_key(priv_a, pub_b, session_info=b"context-A")
        key2 = derive_session_key(priv_a, pub_b, session_info=b"context-B")
        self.assertNotEqual(
            key1, key2,
            "Different session_info must produce different session keys (HKDF info binding).",
        )

    def test_mismatched_key_pairs_produce_different_keys(self) -> None:
        """Two unrelated key pairs must produce different session keys."""
        priv_a, pub_a = generate_ec_keypair()
        priv_b, pub_b = generate_ec_keypair()
        priv_c, pub_c = generate_ec_keypair()
        key_ab = derive_session_key(priv_a, pub_b)
        key_ac = derive_session_key(priv_a, pub_c)
        self.assertNotEqual(key_ab, key_ac, "Unrelated key pairs must yield distinct session keys.")

    def test_derive_type_error_on_wrong_key_type(self) -> None:
        """derive_session_key() must raise TypeError if arguments are wrong type."""
        priv_a, pub_a = generate_ec_keypair()
        with self.assertRaises(TypeError):
            derive_session_key("not_a_key", pub_a)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            derive_session_key(priv_a, "not_a_key")  # type: ignore[arg-type]

    # --- build_session_info ---

    def test_build_session_info_deterministic(self) -> None:
        """build_session_info() must return the same bytes for the same inputs."""
        info1 = build_session_info("GW-01", "PLAYER-77", "FC-CITY")
        info2 = build_session_info("GW-01", "PLAYER-77", "FC-CITY")
        self.assertEqual(info1, info2)

    def test_build_session_info_pipe_delimited(self) -> None:
        """build_session_info() must use pipe-delimited format."""
        info = build_session_info("GW-01", "PLAYER-77", "FC-CITY")
        self.assertEqual(info, b"GW-01|PLAYER-77|FC-CITY")

    def test_build_session_info_distinct_for_different_clubs(self) -> None:
        """Different club_id must produce different session_info bytes."""
        info_a = build_session_info("GW-01", "PLAYER-77", "FC-CITY-A")
        info_b = build_session_info("GW-01", "PLAYER-77", "FC-CITY-B")
        self.assertNotEqual(info_a, info_b)


# ===========================================================================
# 2. SecureGateway Hybrid Unit Tests
# ===========================================================================

class TestSecureGatewayHybrid(unittest.TestCase):
    """Unit tests for SecureGateway.encrypt_data_hybrid / decrypt_data_hybrid."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create a gateway, a club key pair, and encrypt a standard packet."""
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID)

        # Club key pair
        cls.club_priv, cls.club_pub = generate_ec_keypair()
        cls.club_pub_pem: bytes = serialize_public_key(cls.club_pub)
        cls.club_priv_pem: bytes = _serialize_private_key_pem(cls.club_priv)

        # Standard hybrid-encrypted payload
        cls.payload = "ECDH test telemetry payload"
        cls.packet = cls.gateway.encrypt_data_hybrid(
            cls.payload,
            cls.club_pub_pem,
            club_id=CLUB_A_ID,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )

    # --- Packet Structure ---

    def test_packet_contains_required_fields(self) -> None:
        """encrypt_data_hybrid() must include all required fields in the returned packet."""
        for field in ("gateway_id", "nonce", "ciphertext", "ephemeral_public_key_pem", "club_id"):
            self.assertIn(field, self.packet, f"Hybrid packet must contain field '{field}'.")

    def test_packet_gateway_id_correct(self) -> None:
        self.assertEqual(self.packet["gateway_id"], GATEWAY_ID)

    def test_packet_club_id_correct(self) -> None:
        self.assertEqual(self.packet["club_id"], CLUB_A_ID)

    def test_ephemeral_pem_is_valid_ec_key(self) -> None:
        """The embedded ephemeral PEM must deserialize to a valid EC public key."""
        pem = self.packet["ephemeral_public_key_pem"]
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        key = deserialize_public_key(pem)
        self.assertIsNotNone(key)

    # --- Happy Path Round-Trip ---

    def test_round_trip_string_payload(self) -> None:
        """encrypt_data_hybrid → decrypt_data_hybrid must recover the original string."""
        decrypted = self.gateway.decrypt_data_hybrid(self.packet, self.club_priv_pem)
        self.assertEqual(decrypted, self.payload)

    def test_round_trip_dict_payload(self) -> None:
        """Hybrid round-trip must work with a full validated BiometricPayload dict."""
        device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)
        raw = device.generate_biometrics()
        schema_payload = adapt_to_schema(raw)

        gw = SecureGateway(gateway_id=GATEWAY_ID)
        priv, pub = generate_ec_keypair()
        packet = gw.encrypt_data_hybrid(
            schema_payload,
            serialize_public_key(pub),
            club_id=CLUB_A_ID,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )
        decrypted = gw.decrypt_data_hybrid(
            packet,
            _serialize_private_key_pem(priv),
        )
        self.assertIsInstance(decrypted, dict)
        self.assertIn("heart_rate", decrypted)

    # --- Security: Wrong Key Attacks ---

    def test_wrong_private_key_raises_invalid_tag(self) -> None:
        """Using a different club's private key must raise InvalidTag."""
        wrong_priv, _ = generate_ec_keypair()
        wrong_priv_pem = _serialize_private_key_pem(wrong_priv)
        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data_hybrid(self.packet, wrong_priv_pem)

    def test_tampered_ephemeral_pem_raises_invalid_tag(self) -> None:
        """Replacing the ephemeral public key PEM with a different key must raise InvalidTag."""
        _, different_pub = generate_ec_keypair()
        different_pem = serialize_public_key(different_pub).decode("utf-8")
        tampered_packet = {**self.packet, "ephemeral_public_key_pem": different_pem}
        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data_hybrid(tampered_packet, self.club_priv_pem)

    def test_tampered_ciphertext_raises_invalid_tag(self) -> None:
        """Bit-flipping the ciphertext must raise InvalidTag (GCM integrity protection)."""
        ciphertext_bytes = bytearray(bytes.fromhex(self.packet["ciphertext"]))
        ciphertext_bytes[0] ^= 0xFF  # flip first byte
        tampered_packet = {**self.packet, "ciphertext": ciphertext_bytes.hex()}
        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data_hybrid(tampered_packet, self.club_priv_pem)

    def test_tampered_player_id_in_aad_raises_invalid_tag(self) -> None:
        """
        Changing player_id (AAD field) without re-encrypting must raise InvalidTag.
        Demonstrates that context-binding (AAD) prevents packet re-attribution attacks.
        """
        tampered_packet = {**self.packet, "player_id": "ATTACKER-PLAYER"}
        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data_hybrid(tampered_packet, self.club_priv_pem)

    def test_wrong_club_id_in_session_info_raises_invalid_tag(self) -> None:
        """
        Changing club_id (HKDF context field) must produce a different session key,
        causing InvalidTag — prevents cross-club ciphertext attribution.
        """
        tampered_packet = {**self.packet, "club_id": "FC-RIVAL-ATTACKER"}
        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data_hybrid(tampered_packet, self.club_priv_pem)

    def test_missing_required_field_raises_key_error(self) -> None:
        """A packet missing 'ephemeral_public_key_pem' must raise KeyError."""
        incomplete_packet = {k: v for k, v in self.packet.items() if k != "ephemeral_public_key_pem"}
        with self.assertRaises(KeyError):
            self.gateway.decrypt_data_hybrid(incomplete_packet, self.club_priv_pem)

    # --- Backward Compatibility ---

    def test_legacy_symmetric_encrypt_decrypt_still_works(self) -> None:
        """The original symmetric encrypt_data() / decrypt_data() must remain fully functional."""
        aes_key = os.urandom(32)
        gw_enc = SecureGateway(gateway_id=GATEWAY_ID, aes_key=aes_key)
        gw_dec = SecureGateway(gateway_id=GATEWAY_ID, aes_key=aes_key)
        packet = gw_enc.encrypt_data("legacy test", device_id=DEVICE_ID, player_id=PLAYER_ID)
        decrypted = gw_dec.decrypt_data(packet)
        self.assertEqual(decrypted, "legacy test")

    def test_get_public_key_pem_returns_valid_pem(self) -> None:
        """get_public_key_pem() must return a valid EC public key PEM."""
        pem = self.gateway.get_public_key_pem()
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))
        deserialize_public_key(pem)  # must not raise


# ===========================================================================
# 3. AthleteDashboard Club Authorization Unit Tests
# ===========================================================================

class TestAthleteDashboardClubAuth(unittest.TestCase):
    """Unit tests for the club authorization control plane on AthleteDashboard."""

    from athlete_dashboard import AthleteDashboard

    def _make_dashboard(self):
        from athlete_dashboard import AthleteDashboard
        return AthleteDashboard(PLAYER_ID)

    def _make_club_pem(self) -> bytes:
        _, pub = generate_ec_keypair()
        return serialize_public_key(pub)

    # --- authorize_club ---

    def test_authorize_club_stores_key(self) -> None:
        """authorize_club() must store the PEM so get_authorized_club_key() succeeds."""
        dash = self._make_dashboard()
        pem = self._make_club_pem()
        dash.authorize_club(CLUB_A_ID, pem)
        self.assertEqual(dash.get_authorized_club_key(CLUB_A_ID), pem)

    def test_authorize_club_invalid_id_raises_value_error(self) -> None:
        """Empty club_id must raise ValueError."""
        dash = self._make_dashboard()
        with self.assertRaises(ValueError):
            dash.authorize_club("", b"pem")

    def test_authorize_club_non_bytes_pem_raises_type_error(self) -> None:
        """Non-bytes PEM raises TypeError."""
        dash = self._make_dashboard()
        with self.assertRaises(TypeError):
            dash.authorize_club(CLUB_A_ID, "not_bytes")  # type: ignore[arg-type]

    # --- revoke_club ---

    def test_revoke_authorized_club_returns_true(self) -> None:
        """revoke_club() on an authorized club must return True."""
        dash = self._make_dashboard()
        dash.authorize_club(CLUB_A_ID, self._make_club_pem())
        result = dash.revoke_club(CLUB_A_ID)
        self.assertTrue(result)

    def test_revoke_unregistered_club_returns_false(self) -> None:
        """revoke_club() on an unregistered club must return False (idempotent)."""
        dash = self._make_dashboard()
        result = dash.revoke_club("FC-NOT-REGISTERED")
        self.assertFalse(result)

    def test_revoked_club_raises_permission_error(self) -> None:
        """After revoke_club(), get_authorized_club_key() must raise PermissionError."""
        dash = self._make_dashboard()
        dash.authorize_club(CLUB_A_ID, self._make_club_pem())
        dash.revoke_club(CLUB_A_ID)
        with self.assertRaises(PermissionError):
            dash.get_authorized_club_key(CLUB_A_ID)

    # --- get_authorized_club_key ---

    def test_unauthorized_club_raises_permission_error(self) -> None:
        """Requesting a key for a club not authorized must raise PermissionError."""
        dash = self._make_dashboard()
        with self.assertRaises(PermissionError):
            dash.get_authorized_club_key("FC-NEVER-AUTHORIZED")

    def test_revoked_gdpr_consent_blocks_key_retrieval(self) -> None:
        """
        GDPR consent revoked at the global level must block ALL club key retrieval,
        even if the club is individually authorized.
        """
        dash = self._make_dashboard()
        dash.authorize_club(CLUB_A_ID, self._make_club_pem())
        dash.update_consent(False)  # revoke global GDPR consent
        with self.assertRaises(PermissionError):
            dash.get_authorized_club_key(CLUB_A_ID)

    # --- get_authorization_status ---

    def test_authorization_status_empty_on_init(self) -> None:
        """New dashboard must report zero authorized clubs."""
        dash = self._make_dashboard()
        status = dash.get_authorization_status()
        self.assertEqual(status["authorized_club_count"], 0)
        self.assertEqual(status["authorized_clubs"], [])

    def test_authorization_status_updates_after_authorize(self) -> None:
        """Status must reflect authorized clubs after authorize_club() calls."""
        dash = self._make_dashboard()
        dash.authorize_club(CLUB_A_ID, self._make_club_pem())
        dash.authorize_club(CLUB_B_ID, self._make_club_pem())
        status = dash.get_authorization_status()
        self.assertEqual(status["authorized_club_count"], 2)
        self.assertIn(CLUB_A_ID, status["authorized_clubs"])
        self.assertIn(CLUB_B_ID, status["authorized_clubs"])

    def test_authorization_status_updates_after_revoke(self) -> None:
        """Status must remove a club after revoke_club()."""
        dash = self._make_dashboard()
        dash.authorize_club(CLUB_A_ID, self._make_club_pem())
        dash.revoke_club(CLUB_A_ID)
        status = dash.get_authorization_status()
        self.assertEqual(status["authorized_club_count"], 0)
        self.assertNotIn(CLUB_A_ID, status["authorized_clubs"])


# ===========================================================================
# 4. End-to-End Hybrid Pipeline Integration Tests
# ===========================================================================

class TestHybridEndToEndPipeline(unittest.TestCase):
    """
    Full integration: key generation → athlete authorizes club → gateway encrypts
    → ingest to server → club decrypts via /api/v1/telemetry/authorize-decrypt-hybrid.
    """

    @classmethod
    def setUpClass(cls) -> None:
        _cleanup_test_files()
        cls.client = _build_test_client()

        # Club A key pair
        cls.club_a_priv, cls.club_a_pub = generate_ec_keypair()
        cls.club_a_pub_pem: str = serialize_public_key(cls.club_a_pub).decode("utf-8")
        cls.club_a_priv_pem: str = _serialize_private_key_pem(cls.club_a_priv).decode("utf-8")

        # Register Club A via the API
        r = cls.client.post(
            "/api/v1/keys/register-club",
            headers=API_KEY_HEADERS,
            json={
                "club_id": CLUB_A_ID,
                "player_id": PLAYER_ID,
                "club_public_key_pem": cls.club_a_pub_pem,
            },
        )
        assert r.status_code == 200, f"Club registration failed: {r.text}"

        # Gateway encrypts a biometric payload for Club A
        cls.gateway = SecureGateway(gateway_id=GATEWAY_ID)
        device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)
        raw = device.generate_biometrics()
        cls.schema_payload = adapt_to_schema(raw)

        cls.hybrid_packet = cls.gateway.encrypt_data_hybrid(
            cls.schema_payload,
            serialize_public_key(cls.club_a_pub),
            club_id=CLUB_A_ID,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )

        # Ingest the hybrid packet to the server
        ingest_body = {
            "gateway_id": cls.hybrid_packet["gateway_id"],
            "device_id": cls.hybrid_packet.get("device_id"),
            "player_id": cls.hybrid_packet.get("player_id"),
            "sent_at": cls.hybrid_packet.get("sent_at"),
            "nonce": cls.hybrid_packet["nonce"],
            "ciphertext": cls.hybrid_packet["ciphertext"],
            "ephemeral_public_key_pem": cls.hybrid_packet["ephemeral_public_key_pem"],
            "club_id": cls.hybrid_packet["club_id"],
        }
        r = cls.client.post(
            "/api/v1/telemetry/ingest",
            headers=API_KEY_HEADERS,
            json=ingest_body,
        )
        assert r.status_code == 201, f"Ingest failed: {r.text}"

    @classmethod
    def tearDownClass(cls) -> None:
        _cleanup_test_files()

    # --- Club Registration ---

    def test_register_club_returns_200(self) -> None:
        """POST /api/v1/keys/register-club must return HTTP 200."""
        # Register a second club in a fresh request to check the response.
        _, new_pub = generate_ec_keypair()
        r = self.client.post(
            "/api/v1/keys/register-club",
            headers=API_KEY_HEADERS,
            json={
                "club_id": "FC-NEW-CLUB-TEST",
                "player_id": PLAYER_ID,
                "club_public_key_pem": serialize_public_key(new_pub).decode("utf-8"),
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["club_id"], "FC-NEW-CLUB-TEST")

    def test_register_club_invalid_pem_returns_422(self) -> None:
        """Submitting garbage PEM must return HTTP 422."""
        r = self.client.post(
            "/api/v1/keys/register-club",
            headers=API_KEY_HEADERS,
            json={
                "club_id": "FC-BAD-KEY",
                "player_id": PLAYER_ID,
                "club_public_key_pem": "this is not a valid PEM",
            },
        )
        self.assertEqual(r.status_code, 422, r.text)

    # --- Happy Path Hybrid Decryption ---

    def test_authorize_decrypt_hybrid_returns_200(self) -> None:
        """The authorized club must successfully decrypt via the hybrid endpoint."""
        r = self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers=DECRYPT_HYBRID_HEADERS,
            json={
                "record": {
                    "gateway_id": self.hybrid_packet["gateway_id"],
                    "device_id": self.hybrid_packet.get("device_id"),
                    "player_id": self.hybrid_packet.get("player_id"),
                    "sent_at": self.hybrid_packet.get("sent_at"),
                    "nonce": self.hybrid_packet["nonce"],
                    "ciphertext": self.hybrid_packet["ciphertext"],
                    "ephemeral_public_key_pem": self.hybrid_packet["ephemeral_public_key_pem"],
                    "club_id": self.hybrid_packet["club_id"],
                },
                "club_private_key_pem": self.club_a_priv_pem,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)

    def test_authorize_decrypt_hybrid_payload_contains_biometrics(self) -> None:
        """Decrypted payload must contain biometric fields."""
        r = self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers=DECRYPT_HYBRID_HEADERS,
            json={
                "record": {
                    "gateway_id": self.hybrid_packet["gateway_id"],
                    "device_id": self.hybrid_packet.get("device_id"),
                    "player_id": self.hybrid_packet.get("player_id"),
                    "sent_at": self.hybrid_packet.get("sent_at"),
                    "nonce": self.hybrid_packet["nonce"],
                    "ciphertext": self.hybrid_packet["ciphertext"],
                    "ephemeral_public_key_pem": self.hybrid_packet["ephemeral_public_key_pem"],
                    "club_id": self.hybrid_packet["club_id"],
                },
                "club_private_key_pem": self.club_a_priv_pem,
            },
        )
        body = r.json()
        self.assertIn("decrypted_payload", body)
        payload = body["decrypted_payload"]
        self.assertIsInstance(payload, dict)
        self.assertIn("heart_rate", payload)

    # --- Security Gates ---

    def test_wrong_private_key_returns_401(self) -> None:
        """Submitting a wrong private key must return HTTP 401."""
        # Ensure consent is granted for this player (may have been mutated by prior tests).
        self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
        )
        wrong_priv, _ = generate_ec_keypair()
        wrong_priv_pem = _serialize_private_key_pem(wrong_priv).decode("utf-8")
        r = self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers=DECRYPT_HYBRID_HEADERS,
            json={
                "record": {
                    "gateway_id": self.hybrid_packet["gateway_id"],
                    "device_id": self.hybrid_packet.get("device_id"),
                    "player_id": self.hybrid_packet.get("player_id"),
                    "sent_at": self.hybrid_packet.get("sent_at"),
                    "nonce": self.hybrid_packet["nonce"],
                    "ciphertext": self.hybrid_packet["ciphertext"],
                    "ephemeral_public_key_pem": self.hybrid_packet["ephemeral_public_key_pem"],
                    "club_id": self.hybrid_packet["club_id"],
                },
                "club_private_key_pem": wrong_priv_pem,
            },
        )
        self.assertEqual(r.status_code, 401, r.text)

    def test_unregistered_club_returns_403(self) -> None:
        """A club whose key has not been registered must receive HTTP 403."""
        # Ensure consent is granted for this player.
        self.client.post(
            "/api/v1/athlete/consent",
            headers=API_KEY_HEADERS,
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
        )
        # Use Club B (never registered)
        _, unregistered_pub = generate_ec_keypair()
        gw = SecureGateway(gateway_id=GATEWAY_ID)
        packet = gw.encrypt_data_hybrid(
            "test",
            serialize_public_key(unregistered_pub),
            club_id=CLUB_B_ID,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )
        unregistered_priv_pem = _serialize_private_key_pem(
            generate_ec_keypair()[0]
        ).decode("utf-8")
        r = self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers={**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
            json={
                "record": {
                    "gateway_id": packet["gateway_id"],
                    "nonce": packet["nonce"],
                    "ciphertext": packet["ciphertext"],
                    "ephemeral_public_key_pem": packet["ephemeral_public_key_pem"],
                    "club_id": packet["club_id"],
                },
                "club_private_key_pem": unregistered_priv_pem,
            },
        )
        self.assertEqual(r.status_code, 403, r.text)
        self.assertIn("not authorized", r.json()["detail"])

    def test_revoked_club_returns_403(self) -> None:
        """
        After revoking a club key via POST /api/v1/keys/revoke-club,
        the club must receive HTTP 403 on subsequent decrypt attempts.
        """
        # Register a transient club
        transient_priv, transient_pub = generate_ec_keypair()
        transient_club_id = "FC-TRANSIENT-REVOKE-TEST"
        self.client.post(
            "/api/v1/keys/register-club",
            headers=API_KEY_HEADERS,
            json={
                "club_id": transient_club_id,
                "player_id": PLAYER_ID,
                "club_public_key_pem": serialize_public_key(transient_pub).decode("utf-8"),
            },
        )
        gw = SecureGateway(gateway_id=GATEWAY_ID)
        packet = gw.encrypt_data_hybrid(
            "transient test",
            serialize_public_key(transient_pub),
            club_id=transient_club_id,
            device_id=DEVICE_ID,
            player_id=PLAYER_ID,
        )
        # Revoke the club
        self.client.post(
            "/api/v1/keys/revoke-club",
            headers=API_KEY_HEADERS,
            json={"club_id": transient_club_id, "player_id": PLAYER_ID},
        )
        # Attempt decrypt after revocation
        r = self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers={**API_KEY_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
            json={
                "record": {
                    "gateway_id": packet["gateway_id"],
                    "nonce": packet["nonce"],
                    "ciphertext": packet["ciphertext"],
                    "ephemeral_public_key_pem": packet["ephemeral_public_key_pem"],
                    "club_id": packet["club_id"],
                },
                "club_private_key_pem": _serialize_private_key_pem(transient_priv).decode("utf-8"),
            },
        )
        self.assertEqual(r.status_code, 403, r.text)

    def test_revoked_gdpr_consent_returns_403(self) -> None:
        """
        After GDPR consent revocation, /authorize-decrypt-hybrid must return HTTP 403
        regardless of the club's registration status.
        """
        # Temporarily revoke consent for this player in a fresh test client
        fresh_client = _build_test_client(
            db_path="mock_db_test_week8_gdpr.json",
            audit_log_path="audit_log_test_week8_gdpr.csv",
            ledger_path="ledger_test_week8_gdpr.json",
        )
        try:
            # Register Club A
            fresh_client.post(
                "/api/v1/keys/register-club",
                headers=API_KEY_HEADERS,
                json={
                    "club_id": CLUB_A_ID,
                    "player_id": PLAYER_ID,
                    "club_public_key_pem": self.club_a_pub_pem,
                },
            )
            # Revoke athlete GDPR consent
            fresh_client.post(
                "/api/v1/athlete/consent",
                headers=API_KEY_HEADERS,
                json={"player_id": PLAYER_ID, "privacy_toggle_consent": False},
            )
            # Attempt hybrid decrypt
            r = fresh_client.post(
                "/api/v1/telemetry/authorize-decrypt-hybrid",
                headers=DECRYPT_HYBRID_HEADERS,
                json={
                    "record": {
                        "gateway_id": self.hybrid_packet["gateway_id"],
                        "nonce": self.hybrid_packet["nonce"],
                        "ciphertext": self.hybrid_packet["ciphertext"],
                        "ephemeral_public_key_pem": self.hybrid_packet["ephemeral_public_key_pem"],
                        "club_id": self.hybrid_packet["club_id"],
                    },
                    "club_private_key_pem": self.club_a_priv_pem,
                },
            )
            self.assertEqual(r.status_code, 403, r.text)
            self.assertIn("GDPR", r.json()["detail"])
        finally:
            # Restore consent so subsequent tests in other classes are not affected.
            fresh_client.post(
                "/api/v1/athlete/consent",
                headers=API_KEY_HEADERS,
                json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
            )
            _cleanup(
                "mock_db_test_week8_gdpr.json",
                "audit_log_test_week8_gdpr.csv",
                "ledger_test_week8_gdpr.json",
            )

    def test_revoke_club_endpoint_idempotent(self) -> None:
        """Revoking the same club twice must return HTTP 200 both times (idempotent)."""
        for _ in range(2):
            r = self.client.post(
                "/api/v1/keys/revoke-club",
                headers=API_KEY_HEADERS,
                json={"club_id": "FC-IDEMPOTENT-TEST", "player_id": PLAYER_ID},
            )
            self.assertEqual(r.status_code, 200, r.text)

    def test_hybrid_packet_ingested_to_storage(self) -> None:
        """Hybrid packets must be stored with ephemeral_public_key_pem and club_id fields."""
        r = self.client.get("/api/v1/telemetry/stored-ciphertexts")
        self.assertEqual(r.status_code, 200)
        records = r.json()["records"]
        hybrid_records = [rec for rec in records if "ephemeral_public_key_pem" in rec]
        self.assertGreater(len(hybrid_records), 0, "At least one hybrid record must be stored.")

    def test_audit_log_records_successful_hybrid_decrypt(self) -> None:
        """A successful hybrid decryption must create a VIEW_BIOMETRIC_DATA_HYBRID/SUCCESS_200 audit entry."""
        # Perform one successful hybrid decrypt
        self.client.post(
            "/api/v1/telemetry/authorize-decrypt-hybrid",
            headers=DECRYPT_HYBRID_HEADERS,
            json={
                "record": {
                    "gateway_id": self.hybrid_packet["gateway_id"],
                    "device_id": self.hybrid_packet.get("device_id"),
                    "player_id": self.hybrid_packet.get("player_id"),
                    "sent_at": self.hybrid_packet.get("sent_at"),
                    "nonce": self.hybrid_packet["nonce"],
                    "ciphertext": self.hybrid_packet["ciphertext"],
                    "ephemeral_public_key_pem": self.hybrid_packet["ephemeral_public_key_pem"],
                    "club_id": self.hybrid_packet["club_id"],
                },
                "club_private_key_pem": self.club_a_priv_pem,
            },
        )
        audit = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)
        entries = audit.read_audit_log(player_id=PLAYER_ID)
        success_entries = [
            e for e in entries
            if e["action"] == "VIEW_BIOMETRIC_DATA_HYBRID" and e["status"] == "SUCCESS_200"
        ]
        self.assertGreater(len(success_entries), 0, "Audit log must record successful hybrid decryption.")


# ===========================================================================
# 5. Multi-Tenant Isolation Security Tests
# ===========================================================================

class TestMultiTenantIsolation(unittest.TestCase):
    """
    Security regression: two clubs with distinct key pairs must be cryptographically
    isolated — Club A's ciphertext cannot be decrypted with Club B's private key
    and vice versa.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Set up two clubs, each encrypting their own session."""
        cls.gateway_a = SecureGateway(gateway_id="GW-ISOLATION-A")
        cls.gateway_b = SecureGateway(gateway_id="GW-ISOLATION-B")

        # Club A key pair
        cls.priv_a, cls.pub_a = generate_ec_keypair()
        cls.priv_a_pem = _serialize_private_key_pem(cls.priv_a)

        # Club B key pair
        cls.priv_b, cls.pub_b = generate_ec_keypair()
        cls.priv_b_pem = _serialize_private_key_pem(cls.priv_b)

        # Club A's encrypted packet (only decryptable by Club A)
        cls.packet_for_a = cls.gateway_a.encrypt_data_hybrid(
            "Club A secret telemetry",
            serialize_public_key(cls.pub_a),
            club_id=CLUB_A_ID,
            player_id=PLAYER_ID,
        )

        # Club B's encrypted packet (only decryptable by Club B)
        cls.packet_for_b = cls.gateway_b.encrypt_data_hybrid(
            "Club B secret telemetry",
            serialize_public_key(cls.pub_b),
            club_id=CLUB_B_ID,
            player_id=PLAYER_ID,
        )

    def test_club_a_can_decrypt_own_packet(self) -> None:
        """Club A's private key must successfully decrypt Club A's packet."""
        result = self.gateway_a.decrypt_data_hybrid(self.packet_for_a, self.priv_a_pem)
        self.assertEqual(result, "Club A secret telemetry")

    def test_club_b_can_decrypt_own_packet(self) -> None:
        """Club B's private key must successfully decrypt Club B's packet."""
        result = self.gateway_b.decrypt_data_hybrid(self.packet_for_b, self.priv_b_pem)
        self.assertEqual(result, "Club B secret telemetry")

    def test_club_b_cannot_decrypt_club_a_packet(self) -> None:
        """
        Multi-Tenant Isolation: Club B's private key must NOT be able to decrypt
        Club A's ciphertext — InvalidTag proves cryptographic session isolation.
        """
        with self.assertRaises(InvalidTag):
            self.gateway_a.decrypt_data_hybrid(self.packet_for_a, self.priv_b_pem)

    def test_club_a_cannot_decrypt_club_b_packet(self) -> None:
        """
        Multi-Tenant Isolation: Club A's private key must NOT be able to decrypt
        Club B's ciphertext.
        """
        with self.assertRaises(InvalidTag):
            self.gateway_b.decrypt_data_hybrid(self.packet_for_b, self.priv_a_pem)

    def test_club_ids_in_packets_differ(self) -> None:
        """Packets for different clubs must carry different club_id fields."""
        self.assertNotEqual(
            self.packet_for_a["club_id"],
            self.packet_for_b["club_id"],
        )

    def test_ephemeral_keys_in_packets_differ(self) -> None:
        """Two independent gateways must produce distinct ephemeral public keys."""
        self.assertNotEqual(
            self.packet_for_a["ephemeral_public_key_pem"],
            self.packet_for_b["ephemeral_public_key_pem"],
        )


# ===========================================================================
# Entry Point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
