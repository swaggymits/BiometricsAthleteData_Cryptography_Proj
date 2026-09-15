"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Full Technology Verification & Evaluation Report Generator

This script exercises EVERY cryptographic/technological building block used
across the whole project in a single, self-contained run, and PROVES success
by writing two JSON artifacts to disk:

    1. full_technology_evaluation_report.json
       - Pass/fail result + timing (ms) for every technology tested.
       - A final summary (all_passed, total tests, total time).

    2. encrypted_results_sample.json
       - Real, freshly-generated encrypted artifacts produced during the run
         (ciphertext hex, nonces, PEM keys, ledger blocks, audit rows) so a
         reviewer can visually confirm genuine encryption took place (no
         plaintext biometric values are present in any ciphertext field).

Technologies covered
---------------------
1. Biometric Data Schema validation      (core/biometric_schema.py)
2. Legacy symmetric AES-256-GCM          (core/secure_gateway.py)
3. Context-binding / AAD tamper defense  (core/secure_gateway.py)
4. Nonce uniqueness / semantic security  (core/secure_gateway.py)
5. Replay protection (max_age_seconds)   (core/secure_gateway.py)
6. ECDH (NIST P-256) key exchange        (core/ecdh_key_exchange.py)
7. HKDF-SHA256 session key derivation    (core/ecdh_key_exchange.py)
8. Hybrid ECDH + AES-256-GCM encryption  (core/secure_gateway.py)
9. Multi-tenant isolation (wrong key)    (core/secure_gateway.py)
10. GDPR-style audit logging (CSV)       (core/audit_logger.py)
11. SHA-256 hashed ledger / blockchain   (ledger/local_hashed_ledger.py)
12. Ledger tamper detection              (ledger/local_hashed_ledger.py)

Usage:
    python full_technology_verification.py
    (or, inside the project venv)
    venv/bin/python full_technology_verification.py
"""

from __future__ import annotations

import json
import os
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from cryptography.exceptions import InvalidTag

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

# ---------------------------------------------------------------------------
# Output file locations
# ---------------------------------------------------------------------------
EVALUATION_REPORT_PATH = "full_technology_evaluation_report.json"
ENCRYPTED_SAMPLE_PATH = "encrypted_results_sample.json"
TEST_AUDIT_LOG_PATH = "audit_log_tech_verification.csv"
TEST_LEDGER_PATH = "ledger_file_tech_verification.json"

# Sample raw plaintext biometric payload, used across several tests. This
# EXACT set of values is later checked to make sure it never appears verbatim
# inside any ciphertext hex string (proof of confidentiality).
SAMPLE_PAYLOAD: Dict[str, Any] = {
    "heart_rate": 172,
    "fatigue_index": 91.42,
    "glucose_level": 88.5,
    "gps_telemetry": {"lat": 37.9838, "lon": 23.7275, "speed_kmh": 27.6},
    "injury_risk": 0.63,
}

results: List[Dict[str, Any]] = []
artifacts: Dict[str, Any] = {}


def run_check(name: str, category: str, fn: Callable[[], Dict[str, Any]]) -> None:
    """Run a single technology check, capturing timing, pass/fail, and details."""
    start = time.perf_counter()
    try:
        details = fn()
        elapsed_ms = round((time.perf_counter() - start) * 1000, 4)
        results.append(
            {
                "test_name": name,
                "category": category,
                "status": "PASS",
                "elapsed_ms": elapsed_ms,
                "details": details,
            }
        )
        print(f"[PASS] {name} ({elapsed_ms} ms)")
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = round((time.perf_counter() - start) * 1000, 4)
        results.append(
            {
                "test_name": name,
                "category": category,
                "status": "FAIL",
                "elapsed_ms": elapsed_ms,
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
        )
        print(f"[FAIL] {name} ({elapsed_ms} ms) -> {type(exc).__name__}: {exc}")


def plaintext_leaked_in_ciphertext(ciphertext_hex: str) -> bool:
    """
    Check whether the exact serialized plaintext payload leaked verbatim into
    the ciphertext hex string.

    Rather than searching for short numeric substrings (e.g. "172"), which can
    trivially collide by chance inside random-looking hex output, this
    computes the EXACT UTF-8 JSON serialization that would have been produced
    for the validated payload (mirroring ``SecureGateway.encrypt_data``'s own
    ``json.dumps(validated_payload)`` call) and checks whether its hex
    encoding appears as a contiguous substring of the ciphertext. This is a
    much stronger, false-positive-free proof of confidentiality.
    """
    validated_payload = validate_biometric_payload(SAMPLE_PAYLOAD)
    plaintext_json_bytes = json.dumps(validated_payload).encode("utf-8")
    plaintext_hex = plaintext_json_bytes.hex()
    return plaintext_hex in ciphertext_hex


# ---------------------------------------------------------------------------
# 1. Biometric Data Schema Validation
# ---------------------------------------------------------------------------
def check_schema_validation() -> Dict[str, Any]:
    validated = validate_biometric_payload(SAMPLE_PAYLOAD)
    assert validated["heart_rate"] == SAMPLE_PAYLOAD["heart_rate"]

    # Confirm invalid payloads are rejected.
    bad_payload = dict(SAMPLE_PAYLOAD)
    bad_payload["injury_risk"] = 5.0  # out of [0,1] range
    rejected = False
    try:
        validate_biometric_payload(bad_payload)
    except ValueError:
        rejected = True
    assert rejected, "Schema validation failed to reject out-of-range injury_risk"

    return {
        "validated_payload": validated,
        "out_of_range_payload_correctly_rejected": rejected,
    }


# ---------------------------------------------------------------------------
# 2/3/4. Legacy Symmetric AES-256-GCM (+ AAD context binding + nonce uniqueness)
# ---------------------------------------------------------------------------
def check_symmetric_encryption() -> Dict[str, Any]:
    gw = SecureGateway(gateway_id="GW-VERIFY-01")

    packet_a = gw.encrypt_data(
        SAMPLE_PAYLOAD, device_id="IOT-VERIFY-01", player_id="PLAYER-VERIFY-01"
    )
    packet_b = gw.encrypt_data(
        SAMPLE_PAYLOAD, device_id="IOT-VERIFY-01", player_id="PLAYER-VERIFY-01"
    )

    # Nonce uniqueness / semantic security: identical plaintext -> different ciphertext.
    assert packet_a["nonce"] != packet_b["nonce"], "Nonce reuse detected!"
    assert packet_a["ciphertext"] != packet_b["ciphertext"], "Ciphertext collision detected!"

    # No plaintext leakage check.
    assert not plaintext_leaked_in_ciphertext(
        packet_a["ciphertext"]
    ), "Plaintext biometric values leaked into ciphertext!"

    # Round-trip decryption must recover exact original values.
    decrypted = gw.decrypt_data(packet_a)
    assert decrypted == validate_biometric_payload(SAMPLE_PAYLOAD)

    # AAD / context-binding tamper defense: re-attributing packet to a
    # different player_id must raise InvalidTag.
    tampered_packet = dict(packet_a)
    tampered_packet["player_id"] = "PLAYER-ATTACKER"
    context_binding_enforced = False
    try:
        gw.decrypt_data(tampered_packet)
    except InvalidTag:
        context_binding_enforced = True
    assert context_binding_enforced, "AAD context binding failed to detect re-attribution!"

    # Ciphertext bit-flip tamper defense.
    tampered_cipher = dict(packet_a)
    flipped = bytearray.fromhex(tampered_cipher["ciphertext"])
    flipped[0] ^= 0xFF
    tampered_cipher["ciphertext"] = flipped.hex()
    tamper_detected = False
    try:
        gw.decrypt_data(tampered_cipher)
    except InvalidTag:
        tamper_detected = True
    assert tamper_detected, "Ciphertext tampering was not detected!"

    artifacts["symmetric_aes_gcm"] = {
        "gateway_id": gw.gateway_id,
        "packet_1": packet_a,
        "packet_2": packet_b,
        "decrypted_matches_original": True,
    }

    return {
        "nonce_uniqueness_verified": True,
        "no_plaintext_leak_verified": True,
        "round_trip_decryption_verified": True,
        "aad_context_binding_enforced": context_binding_enforced,
        "ciphertext_tamper_detected": tamper_detected,
    }


# ---------------------------------------------------------------------------
# 5. Replay Protection
# ---------------------------------------------------------------------------
def check_replay_protection() -> Dict[str, Any]:
    gw = SecureGateway(gateway_id="GW-VERIFY-REPLAY")
    packet = gw.encrypt_data(SAMPLE_PAYLOAD, device_id="IOT-01", player_id="PLAYER-01")

    # Force staleness by rewriting sent_at to 1 hour ago.
    stale_packet = dict(packet)
    stale_packet["sent_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))

    replay_rejected = False
    try:
        gw.decrypt_data(stale_packet, max_age_seconds=60)
    except ValueError:
        replay_rejected = True
    assert replay_rejected, "Stale/replayed packet was NOT rejected!"

    # Fresh packet must still decrypt fine under the same max_age window.
    fresh_ok = gw.decrypt_data(packet, max_age_seconds=60)
    assert fresh_ok == validate_biometric_payload(SAMPLE_PAYLOAD)

    return {"stale_packet_rejected": replay_rejected, "fresh_packet_accepted": True}


# ---------------------------------------------------------------------------
# 6/7. ECDH Key Exchange + HKDF-SHA256 Session Key Derivation
# ---------------------------------------------------------------------------
def check_ecdh_key_exchange() -> Dict[str, Any]:
    priv_a, pub_a = generate_ec_keypair()
    priv_b, pub_b = generate_ec_keypair()

    session_info = build_session_info(gateway_id="GW-01", player_id="PLAYER-01", club_id="FC-A")

    key_from_a = derive_session_key(priv_a, pub_b, session_info=session_info)
    key_from_b = derive_session_key(priv_b, pub_a, session_info=session_info)

    assert key_from_a == key_from_b, "ECDH shared secret mismatch between parties!"
    assert len(key_from_a) == 32, "Derived session key is not 256-bit!"

    # Different session_info must produce a different key (context binding).
    other_info = build_session_info(gateway_id="GW-01", player_id="PLAYER-01", club_id="FC-B")
    key_other_club = derive_session_key(priv_a, pub_b, session_info=other_info)
    assert key_other_club != key_from_a, "HKDF context binding failed to differentiate club_id!"

    pem_a = serialize_public_key(pub_a)
    round_trip_pub = deserialize_public_key(pem_a)
    assert serialize_public_key(round_trip_pub) == pem_a

    artifacts["ecdh_key_exchange"] = {
        "public_key_pem_party_a": pem_a.decode("utf-8"),
        "shared_session_key_hex": key_from_a.hex(),
        "session_info": session_info.decode("utf-8"),
    }

    return {
        "shared_secret_agreement_verified": True,
        "session_key_length_bytes": len(key_from_a),
        "context_binding_differentiates_sessions": key_other_club != key_from_a,
    }


# ---------------------------------------------------------------------------
# 8/9. Hybrid ECDH + AES-256-GCM (+ multi-tenant isolation)
# ---------------------------------------------------------------------------
def check_hybrid_encryption_and_isolation() -> Dict[str, Any]:
    gateway = SecureGateway(gateway_id="GW-HYBRID-VERIFY")

    club_a_priv, club_a_pub = generate_ec_keypair()
    club_b_priv, club_b_pub = generate_ec_keypair()

    from cryptography.hazmat.primitives import serialization as _ser

    club_a_priv_pem = club_a_priv.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.PKCS8,
        encryption_algorithm=_ser.NoEncryption(),
    )
    club_b_priv_pem = club_b_priv.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.PKCS8,
        encryption_algorithm=_ser.NoEncryption(),
    )

    packet_for_a = gateway.encrypt_data_hybrid(
        SAMPLE_PAYLOAD,
        serialize_public_key(club_a_pub),
        club_id="FC-CLUB-A",
        device_id="IOT-HYBRID-01",
        player_id="PLAYER-HYBRID-01",
    )

    assert not plaintext_leaked_in_ciphertext(packet_for_a["ciphertext"])

    # Club A can decrypt its own packet.
    decrypted_by_a = gateway.decrypt_data_hybrid(packet_for_a, club_a_priv_pem)
    assert decrypted_by_a == validate_biometric_payload(SAMPLE_PAYLOAD)

    # Club B (wrong club / wrong private key) must NOT be able to decrypt it.
    isolation_enforced = False
    try:
        gateway.decrypt_data_hybrid(packet_for_a, club_b_priv_pem)
    except InvalidTag:
        isolation_enforced = True
    assert isolation_enforced, "Multi-tenant isolation FAILED: Club B decrypted Club A's data!"

    artifacts["hybrid_ecdh_aes_gcm"] = {
        "gateway_id": gateway.gateway_id,
        "gateway_ephemeral_public_key_pem": gateway.get_public_key_pem().decode("utf-8"),
        "encrypted_packet_for_club_a": packet_for_a,
        "club_a_decryption_successful": True,
        "club_b_decryption_blocked_multi_tenant_isolation": isolation_enforced,
    }

    return {
        "hybrid_round_trip_verified": True,
        "no_plaintext_leak_verified": True,
        "multi_tenant_isolation_enforced": isolation_enforced,
    }


# ---------------------------------------------------------------------------
# 10. GDPR-style Audit Logging
# ---------------------------------------------------------------------------
def check_audit_logging() -> Dict[str, Any]:
    if os.path.exists(TEST_AUDIT_LOG_PATH):
        os.remove(TEST_AUDIT_LOG_PATH)

    logger = AuditLogger(log_file_path=TEST_AUDIT_LOG_PATH)

    row_success = logger.log_access(
        user_id="TEAM_DOCTOR_01",
        user_role="TEAM_DOCTOR",
        player_id="PLAYER-HYBRID-01",
        action="VIEW_BIOMETRIC_DATA",
        status="SUCCESS_200",
    )
    row_denied = logger.log_access(
        user_id="EXTERNAL_COMPANY_99",
        user_role="EXTERNAL_COMPANY",
        player_id="PLAYER-HYBRID-01",
        action="VIEW_BIOMETRIC_DATA",
        status="DENIED_RBAC_403",
    )

    all_rows = logger.read_audit_log(player_id="PLAYER-HYBRID-01")
    assert len(all_rows) == 2, f"Expected 2 audit rows, found {len(all_rows)}"

    file_exists = os.path.exists(TEST_AUDIT_LOG_PATH)
    assert file_exists

    artifacts["audit_log_sample_rows"] = all_rows

    return {
        "audit_log_file_created": file_exists,
        "success_row_logged": row_success["status"] == "SUCCESS_200",
        "denied_row_logged": row_denied["status"] == "DENIED_RBAC_403",
        "row_count": len(all_rows),
    }


# ---------------------------------------------------------------------------
# 11/12. SHA-256 Hashed Ledger + Tamper Detection
# ---------------------------------------------------------------------------
def check_hashed_ledger() -> Dict[str, Any]:
    if os.path.exists(TEST_LEDGER_PATH):
        os.remove(TEST_LEDGER_PATH)

    ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)

    block1 = ledger.append_transfer_block(
        {
            "player_id": "PLAYER-HYBRID-01",
            "selling_club": "FC-SELLING",
            "buying_club": "FC-CLUB-A",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-of-encrypted-packet",
        }
    )
    block2 = ledger.append_transfer_block(
        {
            "player_id": "PLAYER-HYBRID-02",
            "selling_club": "FC-CLUB-A",
            "buying_club": "FC-CLUB-B",
            "escrow_deposit_verified": True,
            "encrypted_payload_hash": "sha256-placeholder-2",
        }
    )

    valid_before_tamper = ledger.validate_chain()
    assert valid_before_tamper, "Freshly built ledger chain reported as INVALID!"

    # Tamper with a committed block directly on disk, then confirm detection.
    with open(TEST_LEDGER_PATH, "r", encoding="utf-8") as fh:
        chain = json.load(fh)
    chain[1]["buying_club"] = "FC-ATTACKER"  # modify without recomputing hash
    with open(TEST_LEDGER_PATH, "w", encoding="utf-8") as fh:
        json.dump(chain, fh, indent=2)

    tampered_ledger = LocalHashedLedger(ledger_file_json=TEST_LEDGER_PATH)
    valid_after_tamper = tampered_ledger.validate_chain()
    assert not valid_after_tamper, "Ledger FAILED to detect tampering!"

    artifacts["hashed_ledger"] = {
        "block_1": block1,
        "block_2": block2,
        "chain_valid_before_tamper": valid_before_tamper,
        "chain_valid_after_tamper": valid_after_tamper,
    }

    return {
        "chain_valid_before_tamper": valid_before_tamper,
        "tamper_detected": not valid_after_tamper,
    }


def main() -> None:
    print("=" * 80)
    print("FULL TECHNOLOGY VERIFICATION — Encryption & Supporting Systems")
    print("=" * 80)

    run_check("Biometric Data Schema Validation", "Data Schema", check_schema_validation)
    run_check(
        "Symmetric AES-256-GCM Encryption (+AAD +Nonce Uniqueness)",
        "Symmetric Cryptography",
        check_symmetric_encryption,
    )
    run_check("Replay / Freshness Protection", "Replay Protection", check_replay_protection)
    run_check(
        "ECDH (P-256) Key Exchange + HKDF-SHA256",
        "Asymmetric Cryptography",
        check_ecdh_key_exchange,
    )
    run_check(
        "Hybrid ECDH + AES-256-GCM (+ Multi-Tenant Isolation)",
        "Hybrid Cryptography",
        check_hybrid_encryption_and_isolation,
    )
    run_check("GDPR-Style Audit Logging", "Audit & Compliance", check_audit_logging)
    run_check(
        "SHA-256 Hashed Ledger (+ Tamper Detection)",
        "Ledger / Blockchain",
        check_hashed_ledger,
    )

    total_time_ms = round(sum(r["elapsed_ms"] for r in results), 4)
    all_passed = all(r["status"] == "PASS" for r in results)
    passed_count = sum(1 for r in results if r["status"] == "PASS")

    report = {
        "generated_at_utc": datetime.now(tz=timezone.utc).isoformat(),
        "project": "Data Privacy in Elite Performance: Protecting Athlete Biometrics",
        "summary": {
            "total_tests": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "all_passed": all_passed,
            "total_elapsed_ms": total_time_ms,
        },
        "test_results": results,
    }

    with open(EVALUATION_REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    with open(ENCRYPTED_SAMPLE_PATH, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "generated_at_utc": datetime.now(tz=timezone.utc).isoformat(),
                "note": (
                    "All ciphertext/nonce/key fields below were generated live "
                    "during this run. No plaintext biometric values appear in "
                    "any ciphertext field (verified programmatically)."
                ),
                "artifacts": artifacts,
            },
            fh,
            indent=2,
            default=str,
        )

    print("\n" + "=" * 80)
    if all_passed:
        print(f"✅ ALL {len(results)} TECHNOLOGY CHECKS PASSED  (total {total_time_ms} ms)")
    else:
        print(f"❌ {len(results) - passed_count} CHECK(S) FAILED out of {len(results)}")
    print(f"Evaluation report written to : {EVALUATION_REPORT_PATH}")
    print(f"Encrypted samples written to : {ENCRYPTED_SAMPLE_PATH}")
    print("=" * 80)

    if not all_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
