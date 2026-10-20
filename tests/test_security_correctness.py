"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Functional Security Correctness Test Suite (pytest)

This suite proves — with individual, independently-failing assertions — that
every cryptographic/security control used by the system actually works as
intended:

  * Confidentiality:   AES-256-GCM ciphertext never contains plaintext data.
  * Semantic security:  identical plaintexts encrypt to different ciphertexts
                         (unique nonces, no ciphertext collisions).
  * Integrity/auth:     any bit-flip in ciphertext is detected (InvalidTag).
  * Context binding:    AAD re-attribution (wrong player_id) is detected.
  * Replay protection:  stale packets are rejected; fresh packets pass.
  * Key agreement:      ECDH (P-256) + HKDF-SHA256 derives matching,
                         256-bit session keys, bound to session context.
  * Multi-tenant isolation: hybrid ECDH+AES-GCM data for one club cannot be
                         decrypted using another club's private key.
  * Schema validation:  malformed/out-of-range biometric payloads rejected.
  * Audit logging:      GDPR-style access log records both allowed and
                         denied accesses.
  * Ledger integrity:   SHA-256 hashed ledger detects any tampering.

Run:
    pytest tests/test_security_correctness.py -v
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization as _ser

from core.audit_logger import AuditLogger
from core.biometric_schema import validate_biometric_payload
from core.ecdh_key_exchange import (
    build_session_info,
    derive_session_key,
    deserialize_public_key,
    generate_ec_keypair,
    serialize_public_key,
)
from core.secure_gateway import SecureGateway
from ledger.local_hashed_ledger import LocalHashedLedger

SAMPLE_PAYLOAD: Dict[str, Any] = {
    "heart_rate": 172,
    "fatigue_index": 91.42,
    "glucose_level": 88.5,
    "gps_telemetry": {"lat": 37.9838, "lon": 23.7275, "speed_kmh": 27.6},
    "injury_risk": 0.63,
}

TEST_AUDIT_LOG_PATH = "audit_log_security_correctness_test.csv"
TEST_LEDGER_PATH = "ledger_file_security_correctness_test.json"


def _plaintext_leaked(ciphertext_hex: str) -> bool:
    """True if the exact plaintext JSON serialization appears inside ciphertext hex."""
    validated_payload = validate_biometric_payload(SAMPLE_PAYLOAD)
    plaintext_hex = json.dumps(validated_payload).encode("utf-8").hex()
    return plaintext_hex in ciphertext_hex


@pytest.fixture(autouse=True)
def _cleanup_artifacts():
    """Remove any test-generated audit log / ledger files before and after each test."""
    for path in (TEST_AUDIT_LOG_PATH, TEST_LEDGER_PATH):
        if os.path.exists(path):
            os.remove(path)
    yield
    for path in (TEST_AUDIT_LOG_PATH, TEST_LEDGER_PATH):
        if os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------------------
# 1. Schema validation
# ---------------------------------------------------------------------------
def test_schema_validation_accepts_valid_payload():
    validated = validate_biometric_payload(SAMPLE_PAYLOAD)
    assert validated["heart_rate"] == SAMPLE_PAYLOAD["heart_rate"]


def test_schema_validation_rejects_out_of_range_payload():
    bad_payload = dict(SAMPLE_PAYLOAD)
    bad_payload["injury_risk"] = 5.0  # out of [0, 1] range
    with pytest.raises(ValueError):
        validate_biometric_payload(bad_payload)


# ---------------------------------------------------------------------------
# 2. Symmetric AES-256-GCM: semantic security + confidentiality
# ---------------------------------------------------------------------------
def test_symmetric_encryption_nonce_uniqueness_and_no_collision():
    gw = SecureGateway(gateway_id="GW-TEST-SEC-01")
    packet_a = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")
    packet_b = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")

    assert packet_a["nonce"] != packet_b["nonce"]
    assert packet_a["ciphertext"] != packet_b["ciphertext"]


def test_symmetric_encryption_no_plaintext_leakage():
    gw = SecureGateway(gateway_id="GW-TEST-SEC-02")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")
    assert not _plaintext_leaked(packet["ciphertext"])


def test_symmetric_encryption_round_trip():
    gw = SecureGateway(gateway_id="GW-TEST-SEC-03")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")
    decrypted = gw.decrypt_data(packet)
    assert decrypted == validate_biometric_payload(SAMPLE_PAYLOAD)


def test_symmetric_encryption_aad_context_binding_detects_reattribution():
    gw = SecureGateway(gateway_id="GW-TEST-SEC-04")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")

    tampered = dict(packet)
    tampered["player_id"] = "PLAYER-ATTACKER"
    with pytest.raises(InvalidTag):
        gw.decrypt_data(tampered)


def test_symmetric_encryption_ciphertext_bitflip_detected():
    gw = SecureGateway(gateway_id="GW-TEST-SEC-05")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")

    tampered = dict(packet)
    flipped = bytearray.fromhex(tampered["ciphertext"])
    flipped[0] ^= 0xFF
    tampered["ciphertext"] = flipped.hex()

    with pytest.raises(InvalidTag):
        gw.decrypt_data(tampered)


# ---------------------------------------------------------------------------
# 3. Replay protection
# ---------------------------------------------------------------------------
def test_replay_protection_rejects_stale_packet():
    gw = SecureGateway(gateway_id="GW-TEST-REPLAY")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")

    stale_packet = dict(packet)
    stale_packet["sent_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))

    with pytest.raises(ValueError):
        gw.decrypt_data(stale_packet, max_age_seconds=60)


def test_replay_protection_accepts_fresh_packet():
    gw = SecureGateway(gateway_id="GW-TEST-REPLAY-2")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")
    decrypted = gw.decrypt_data(packet, max_age_seconds=60)
    assert decrypted == validate_biometric_payload(SAMPLE_PAYLOAD)


# ---------------------------------------------------------------------------
# 4. ECDH (P-256) + HKDF-SHA256 key agreement
# ---------------------------------------------------------------------------
def test_ecdh_shared_secret_agreement_matches():
    priv_a, pub_a = generate_ec_keypair()
    priv_b, pub_b = generate_ec_keypair()
    session_info = build_session_info(gateway_id="GW-01", player_id="PLAYER-01", club_id="FC-A")

    key_from_a = derive_session_key(priv_a, pub_b, session_info=session_info)
    key_from_b = derive_session_key(priv_b, pub_a, session_info=session_info)

    assert key_from_a == key_from_b
    assert len(key_from_a) == 32  # 256-bit


def test_ecdh_hkdf_context_binding_differentiates_sessions():
    priv_a, pub_a = generate_ec_keypair()
    _, pub_b = generate_ec_keypair()

    info_club_a = build_session_info(gateway_id="GW-01", player_id="PLAYER-01", club_id="FC-A")
    info_club_b = build_session_info(gateway_id="GW-01", player_id="PLAYER-01", club_id="FC-B")

    key_club_a = derive_session_key(priv_a, pub_b, session_info=info_club_a)
    key_club_b = derive_session_key(priv_a, pub_b, session_info=info_club_b)

    assert key_club_a != key_club_b


def test_ecdh_public_key_serialization_round_trip():
    _, pub_a = generate_ec_keypair()
    pem_a = serialize_public_key(pub_a)
    round_trip_pub = deserialize_public_key(pem_a)
    assert serialize_public_key(round_trip_pub) == pem_a


# ---------------------------------------------------------------------------
# 5. Hybrid ECDH + AES-256-GCM + multi-tenant isolation
# ---------------------------------------------------------------------------
def _make_private_pem(priv_key) -> bytes:
    return priv_key.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.PKCS8,
        encryption_algorithm=_ser.NoEncryption(),
    )


def test_hybrid_encryption_round_trip_and_no_leak():
    gateway = SecureGateway(gateway_id="GW-HYBRID-TEST")
    club_a_priv, club_a_pub = generate_ec_keypair()

    packet = gateway.encrypt_data_hybrid(
        SAMPLE_PAYLOAD,
        serialize_public_key(club_a_pub),
        club_id="FC-CLUB-A",
        device_id="IOT-01",
        player_id="PLAYER-01",
    )

    assert not _plaintext_leaked(packet["ciphertext"])

    decrypted = gateway.decrypt_data_hybrid(packet, _make_private_pem(club_a_priv))
    assert decrypted == validate_biometric_payload(SAMPLE_PAYLOAD)


def test_hybrid_encryption_multi_tenant_isolation_enforced():
    gateway = SecureGateway(gateway_id="GW-HYBRID-TEST-2")
    club_a_priv, club_a_pub = generate_ec_keypair()
    club_b_priv, _club_b_pub = generate_ec_keypair()

    packet_for_a = gateway.encrypt_data_hybrid(
        SAMPLE_PAYLOAD,
        serialize_public_key(club_a_pub),
        club_id="FC-CLUB-A",
        device_id="IOT-01",
        player_id="PLAYER-01",
    )

    # Club B must NOT be able to decrypt Club A's data with its own key.
    with pytest.raises(InvalidTag):
        gateway.decrypt_data_hybrid(packet_for_a, _make_private_pem(club_b_priv))


# ---------------------------------------------------------------------------
# 6. GDPR-style audit logging
# ---------------------------------------------------------------------------
def test_audit_logging_records_success_and_denied_access():
    logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)

    row_success = logger.log_access(
        user_id="TEAM_DOCTOR_01",
        user_role="TEAM_DOCTOR",
        player_id="PLAYER-01",
        action="VIEW_BIOMETRIC_DATA",
        status="SUCCESS_200",
    )
    row_denied = logger.log_access(
        user_id="EXTERNAL_COMPANY_99",
        user_role="EXTERNAL_COMPANY",
        player_id="PLAYER-01",
        action="VIEW_BIOMETRIC_DATA",
        status="DENIED_RBAC_403",
    )

    all_rows = logger.read_audit_log(player_id="PLAYER-01")

    assert os.path.exists(TEST_AUDIT_LOG_PATH)
    assert len(all_rows) == 2
    assert row_success["status"] == "SUCCESS_200"
    assert row_denied["status"] == "DENIED_RBAC_403"


# ---------------------------------------------------------------------------
# 7. SHA-256 hashed ledger integrity + tamper detection
# ---------------------------------------------------------------------------
def test_hashed_ledger_valid_before_tamper():
    ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
    ledger.append_transfer_block(
        {
            "player_id": "PLAYER-01",
            "selling_club": "FC-SELLING",
            "buying_club": "FC-CLUB-A",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-1",
        }
    )
    ledger.append_transfer_block(
        {
            "player_id": "PLAYER-02",
            "selling_club": "FC-CLUB-A",
            "buying_club": "FC-CLUB-B",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-2",
        }
    )
    assert ledger.validate_chain() is True


def test_hashed_ledger_detects_tampering():
    ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
    ledger.append_transfer_block(
        {
            "player_id": "PLAYER-01",
            "selling_club": "FC-SELLING",
            "buying_club": "FC-CLUB-A",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-1",
        }
    )
    ledger.append_transfer_block(
        {
            "player_id": "PLAYER-02",
            "selling_club": "FC-CLUB-A",
            "buying_club": "FC-CLUB-B",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-2",
        }
    )

    # Tamper with a committed block directly on disk without recomputing its hash.
    with open(TEST_LEDGER_PATH, "r", encoding="utf-8") as fh:
        chain = json.load(fh)
    chain[1]["buying_club"] = "FC-ATTACKER"
    with open(TEST_LEDGER_PATH, "w", encoding="utf-8") as fh:
        json.dump(chain, fh, indent=2)

    tampered_ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
    assert tampered_ledger.validate_chain() is False
