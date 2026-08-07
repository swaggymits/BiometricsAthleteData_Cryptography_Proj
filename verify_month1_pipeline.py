"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 4 — End-of-Month 1 Integration, Benchmarking & Technical Report

verify_month1_pipeline.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive end-to-end pipeline verification and early performance metrics
script for Month 1 of the Bachelor's Thesis evaluation.

Objectives (per Week 4 spec):
  1. Execute the complete Edge → Gateway → Cloud REST API pipeline using an
     in-process ``httpx.AsyncClient`` (no live server needed).
  2. Collect and report early evaluation metrics as requested by the instructor:
       • Encryption overhead (AES-256-GCM latency vs raw JSON serialisation)
       • Payload size overhead (raw JSON vs hex ciphertext, % increase)
       • API ingestion latency (POST /api/v1/telemetry/ingest)
       • Database isolation assertion (mock_db.json contains ZERO plaintext)
  3. Perform authorized decryption of every stored record via
     POST /api/v1/telemetry/authorize-decrypt and verify round-trip fidelity.
  4. Print a structured, thesis-grade benchmark report to stdout.

Usage:
    python verify_month1_pipeline.py                 # default 20 ticks
    python verify_month1_pipeline.py --ticks 50      # custom iteration count

Dependencies (all already in requirements.txt):
    cryptography, fastapi, httpx, pydantic, pydantic-settings
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from statistics import mean, stdev
from typing import Any, Dict, List, Tuple

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# We import the FastAPI ``app`` directly so we can drive it via
# ``httpx.AsyncClient(app=app, ...)``.  We must monkey-patch
# ``config.settings.MOCK_DB_PATH`` BEFORE importing ``main_server`` so the
# CloudServer inside it uses our temp db file.
import config as _config_module

# ── project imports ────────────────────────────────────────────────────────────
from iot_device import IoTDeviceMock
from pipeline_week2 import adapt_to_schema  # reuse existing adapter
from secure_gateway import SecureGateway

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

BANNER_WIDTH = 80
SENSITIVE_KEYWORDS = ("heart_rate", "fatigue_index", "glucose_level", "injury_risk")


def _banner(title: str, char: str = "═") -> None:
    print(f"\n{char * BANNER_WIDTH}")
    print(f"  {title}")
    print(f"{char * BANNER_WIDTH}")


def _section(title: str) -> None:
    print(f"\n{'─' * BANNER_WIDTH}")
    print(f"  >>  {title}")
    print(f"{'─' * BANNER_WIDTH}")


def _ok(msg: str) -> None:
    print(f"  [OK]  {msg}")


def _warn(msg: str) -> None:
    print(f"  [WARN] {msg}")


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def _metric(label: str, value: str) -> None:
    print(f"  {'·':>3}  {label:<45}  {value}")


# ──────────────────────────────────────────────────────────────────────────────
# Benchmark measurement helpers
# ──────────────────────────────────────────────────────────────────────────────

def _raw_json_bytes(schema_payload: Dict[str, Any]) -> bytes:
    """Return the UTF-8 JSON encoding of a schema payload (no encryption)."""
    return json.dumps(schema_payload, separators=(",", ":")).encode("utf-8")


def measure_encryption_overhead(
    gateway: SecureGateway,
    payloads: List[Dict[str, Any]],
) -> Tuple[List[float], List[float]]:
    """
    Measure per-tick wall-clock time (ms) for:
      - Raw JSON serialisation only (baseline, no crypto)
      - Full AES-256-GCM encryption via SecureGateway.encrypt_data()

    Uses a separate gateway instance for timing to avoid polluting the
    main gateway's nonce ledger with duplicate entries.

    Returns two parallel lists: (raw_ms_list, enc_ms_list).
    """
    raw_times: List[float] = []
    enc_times: List[float] = []

    timing_gw = SecureGateway(
        gateway_id=gateway.gateway_id, aes_key=gateway.aes_key
    )

    for payload in payloads:
        # --- baseline: pure JSON serialisation ---
        t0 = time.perf_counter()
        _ = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        raw_times.append((time.perf_counter() - t0) * 1_000)

        # --- full AES-256-GCM encryption ---
        t0 = time.perf_counter()
        _ = timing_gw.encrypt_data(
            payload,
            device_id=payload.get("device_id"),
            player_id=payload.get("player_id"),
        )
        enc_times.append((time.perf_counter() - t0) * 1_000)

    return raw_times, enc_times


def measure_payload_size_overhead(
    schema_payload: Dict[str, Any],
    encrypted_packet: Dict[str, Any],
) -> Tuple[int, int, float]:
    """
    Compare byte sizes of the raw JSON payload vs the hex-encoded ciphertext
    field only (the main cryptographic overhead carrier).

    Returns: (raw_bytes, cipher_bytes, pct_increase)
    """
    raw_bytes = len(_raw_json_bytes(schema_payload))
    cipher_bytes = len(encrypted_packet["ciphertext"].encode("ascii"))
    pct = ((cipher_bytes - raw_bytes) / raw_bytes) * 100
    return raw_bytes, cipher_bytes, pct


# ──────────────────────────────────────────────────────────────────────────────
# Database isolation assertion
# ──────────────────────────────────────────────────────────────────────────────

def assert_database_isolation(db_path: str) -> None:
    """
    Assert that mock_db.json contains ZERO occurrences of any sensitive
    biometric field name as a UTF-8 string.  Performed on the raw file bytes
    so no JSON encoding tricks can hide leakage.

    Raises SystemExit on assertion failure.
    """
    if not os.path.exists(db_path):
        _fail(f"mock_db.json not found at '{db_path}'.")

    with open(db_path, "rb") as fh:
        raw_bytes = fh.read()

    leaks: List[str] = []
    for keyword in SENSITIVE_KEYWORDS:
        if keyword.encode("utf-8") in raw_bytes:
            leaks.append(keyword)

    if leaks:
        _fail(
            f"SECURITY BREACH -- plaintext biometric keyword(s) detected in "
            f"mock_db.json: {leaks}"
        )
    _ok(
        f"Database Isolation verified -- 0/{len(SENSITIVE_KEYWORDS)} sensitive "
        f"keywords present in mock_db.json (only encrypted hex ciphertext stored)."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Main async pipeline
# ──────────────────────────────────────────────────────────────────────────────

async def run_pipeline(ticks: int = 20) -> None:
    _banner(
        "Week 4 -- Month 1 End-to-End Pipeline Verification & Benchmarking"
    )
    print(
        "  Thesis:  'Data Privacy in Elite Performance: Protecting Athlete Biometrics'"
    )
    print(f"  Ticks:   {ticks} biometric sensor readings")
    print(
        "  Engine:  AES-256-GCM  |  Transport: FastAPI in-process (httpx.AsyncClient)"
    )

    # ── Phase 0: temp database ─────────────────────────────────────────────────
    _section("Phase 0 -- Setup")
    tmp_db = tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, mode="w", encoding="utf-8"
    )
    tmp_db.write("[]")
    tmp_db.close()
    db_path = tmp_db.name

    # Patch BEFORE importing main_server so its CloudServer sees the temp path
    _config_module.settings.MOCK_DB_PATH = db_path
    API_KEY = _config_module.settings.CLOUD_API_KEY

    import importlib

    import main_server as _ms_module
    importlib.reload(_ms_module)          # re-bind CloudServer to temp db
    from main_server import app  # noqa: E402  (runtime import needed)

    _ok(f"Temporary database: {db_path}")
    _ok("FastAPI app loaded (in-process, no live server)")

    # ── Phase 1: init components ───────────────────────────────────────────────
    _section("Phase 1 -- Initialise Components")

    device = IoTDeviceMock(device_id="IOT-WBAN-001", player_id="PLAYER-77")
    shared_key: bytes = AESGCM.generate_key(bit_length=256)
    edge_gw = SecureGateway(gateway_id="GW-EDGE-BENCH-01", aes_key=shared_key)

    _ok(f"IoTDeviceMock   device_id={device.device_id}  player_id={device.player_id}")
    _ok(f"SecureGateway   gateway_id={edge_gw.gateway_id}  key=<256-bit AES>")

    # ── Phase 2: generate payloads ─────────────────────────────────────────────
    _section("Phase 2 -- Biometric Data Generation")

    raw_readings: List[Dict[str, Any]] = []
    schema_payloads: List[Dict[str, Any]] = []

    for _ in range(ticks):
        raw = device.generate_biometrics()
        schema = adapt_to_schema(raw)
        raw_readings.append(raw)
        schema_payloads.append(schema)

    _ok(f"Generated {ticks} biometric ticks from IoTDeviceMock")
    print("\n  Sample tick payload (tick #1):")
    for k, v in schema_payloads[0].items():
        print(f"    {k}: {v}")

    # ── Phase 3: encryption overhead ───────────────────────────────────────────
    _section("Phase 3 -- Encryption Overhead Measurement (AES-256-GCM vs Raw JSON)")

    raw_ms_list, enc_ms_list = measure_encryption_overhead(edge_gw, schema_payloads)
    overhead_ms_list = [e - r for e, r in zip(enc_ms_list, raw_ms_list)]

    avg_raw  = mean(raw_ms_list)
    avg_enc  = mean(enc_ms_list)
    avg_over = mean(overhead_ms_list)
    std_enc  = stdev(enc_ms_list) if len(enc_ms_list) > 1 else 0.0

    _metric("Avg raw JSON serialisation latency",   f"{avg_raw:.4f} ms")
    _metric("Avg AES-256-GCM encryption latency",   f"{avg_enc:.4f} ms  (stddev={std_enc:.4f})")
    _metric("Avg encryption overhead (delta)",       f"{avg_over:.4f} ms")
    _metric("Overhead ratio (enc / raw)",            f"{(avg_enc / max(avg_raw, 1e-9)):.2f}x")

    if avg_over < 2.0:
        _ok("Encryption overhead is negligible (<2 ms per tick) -- suitable for real-time use.")
    elif avg_over < 10.0:
        _warn(f"Encryption overhead is moderate ({avg_over:.2f} ms) -- acceptable for 1 Hz telemetry.")
    else:
        _warn(f"Encryption overhead is elevated ({avg_over:.2f} ms) -- may need review on constrained hardware.")

    # ── Phase 4: payload size overhead ─────────────────────────────────────────
    _section("Phase 4 -- Payload Size Overhead Analysis")

    sample_enc = edge_gw.encrypt_data(
        schema_payloads[0],
        device_id=device.device_id,
        player_id=device.player_id,
    )
    raw_bytes, cipher_bytes, pct_increase = measure_payload_size_overhead(
        schema_payloads[0], sample_enc
    )
    full_packet_bytes = len(
        json.dumps(sample_enc, separators=(",", ":")).encode()
    )

    _metric("Raw JSON payload size",                f"{raw_bytes} bytes")
    _metric("Hex ciphertext field size",            f"{cipher_bytes} bytes")
    _metric("Full encrypted packet size",           f"{full_packet_bytes} bytes")
    _metric("Ciphertext vs raw overhead",           f"+{pct_increase:.1f}%")
    _metric(
        "Full packet vs raw overhead",
        f"+{((full_packet_bytes - raw_bytes) / raw_bytes) * 100:.1f}%",
    )
    _ok(
        "AES-GCM ciphertext includes 16-byte (32 hex char) authentication tag -- "
        "overhead is deterministic and bounded."
    )

    # ── Phase 5 / 6 / 7: API calls (all within one AsyncClient session) ───────
    _section("Phase 5 -- API Ingestion (POST /api/v1/telemetry/ingest)")

    ingest_latencies_ms: List[float] = []
    encrypted_packets: List[Dict[str, Any]] = []
    ingest_failures: int = 0

    # httpx >= 0.20 requires ASGITransport; older versions accept app= directly.
    try:
        transport = httpx.ASGITransport(app=app)  # type: ignore[attr-defined]
        _client_kwargs: dict = {"transport": transport, "base_url": "http://testserver", "timeout": 30.0}
    except AttributeError:
        _client_kwargs = {"app": app, "base_url": "http://testserver", "timeout": 30.0}  # type: ignore[arg-type]

    async with httpx.AsyncClient(**_client_kwargs) as client:

        for tick_idx, schema_payload in enumerate(schema_payloads, start=1):
            enc_pkt = edge_gw.encrypt_data(
                schema_payload,
                device_id=device.device_id,
                player_id=device.player_id,
            )
            encrypted_packets.append(enc_pkt)

            t0 = time.perf_counter()
            response = await client.post(
                "/api/v1/telemetry/ingest",
                json=enc_pkt,
                headers={"X-API-Key": API_KEY},
            )
            latency_ms = (time.perf_counter() - t0) * 1_000
            ingest_latencies_ms.append(latency_ms)

            if response.status_code != 201:
                ingest_failures += 1
                _warn(
                    f"Tick {tick_idx}: ingest returned HTTP {response.status_code}: "
                    f"{response.text[:120]}"
                )
            elif tick_idx % 5 == 0 or tick_idx == 1:
                body = response.json()
                print(
                    f"  Tick {tick_idx:>3}/{ticks}  HTTP 201  "
                    f"stored_record_count={body['stored_record_count']}  "
                    f"latency={latency_ms:.2f} ms"
                )

        # ── Phase 6: verification read ─────────────────────────────────────────
        _section("Phase 6 -- Verification Read (GET /api/v1/telemetry/stored-ciphertexts)")

        get_t0 = time.perf_counter()
        read_resp = await client.get(
            "/api/v1/telemetry/stored-ciphertexts",
            params={"offset": 0, "limit": max(ticks, 1)},
        )
        read_latency_ms = (time.perf_counter() - get_t0) * 1_000

        if read_resp.status_code != 200:
            _fail(
                f"Expected HTTP 200 but got {read_resp.status_code}: {read_resp.text}"
            )

        # NOTE: /stored-ciphertexts now returns a paginated envelope
        # ({total, offset, limit, records}) rather than a bare list.
        stored_records: List[Dict[str, Any]] = read_resp.json()["records"]
        _ok(
            f"GET /api/v1/telemetry/stored-ciphertexts -> HTTP 200 ({read_latency_ms:.2f} ms)"
        )
        _ok(
            f"Records stored in database: {len(stored_records)} / {ticks} ticks ingested"
        )

        expected_records = ticks - ingest_failures
        if len(stored_records) != expected_records:
            _warn(
                f"Record count mismatch: expected {expected_records}, "
                f"got {len(stored_records)}"
            )

        missing_fields = sum(
            1
            for rec in stored_records
            if "nonce" not in rec or "ciphertext" not in rec
        )
        if missing_fields:
            _fail(
                f"{missing_fields} stored records are missing 'nonce'/'ciphertext' fields."
            )
        _ok(
            f"All {len(stored_records)} stored records contain required "
            f"'nonce' + 'ciphertext' hex fields."
        )

        # ── Phase 7: authorized decryption round-trip ──────────────────────────
        _section(
            "Phase 7 -- Authorized Decryption Round-Trip "
            "(POST /api/v1/telemetry/authorize-decrypt)"
        )

        # Week 5 AAA enforcement: decryption now requires (1) GDPR consent to
        # be granted for the athlete and (2) an authorised X-User-Role. Grant
        # consent up front so this benchmark measures the happy path.
        consent_resp = await client.post(
            "/api/v1/athlete/consent",
            json={"player_id": device.player_id, "privacy_toggle_consent": True},
            headers={"X-API-Key": API_KEY},
        )
        if consent_resp.status_code != 200:
            _fail(
                f"Failed to grant GDPR consent for {device.player_id}: "
                f"HTTP {consent_resp.status_code}: {consent_resp.text}"
            )
        _ok(f"GDPR consent granted for player_id={device.player_id}")

        decrypt_failures: int = 0
        decrypt_mismatches: int = 0
        decrypt_latencies_ms: List[float] = []
        aes_key_hex = shared_key.hex()

        for idx, enc_pkt in enumerate(encrypted_packets):
            body = {
                "record": enc_pkt,
                "aes_key_hex": aes_key_hex,
                "max_age_seconds": 3600.0,   # generous window for a benchmark
            }
            t0 = time.perf_counter()
            dec_resp = await client.post(
                "/api/v1/telemetry/authorize-decrypt",
                json=body,
                headers={
                    "X-API-Key": API_KEY,
                    "X-User-Role": "TEAM_DOCTOR",
                    "X-Player-Id": device.player_id,
                },
            )
            decrypt_latencies_ms.append((time.perf_counter() - t0) * 1_000)

            if dec_resp.status_code != 200:
                decrypt_failures += 1
                _warn(f"Decryption tick {idx + 1}: HTTP {dec_resp.status_code}")
                continue

            decrypted = dec_resp.json().get("decrypted_payload")
            if decrypted != schema_payloads[idx]:
                decrypt_mismatches += 1
                _warn(
                    f"Tick {idx + 1}: decrypted payload does not match original!"
                )

    success_count = ticks - decrypt_failures - decrypt_mismatches
    _ok(
        f"Decryption round-trip: {success_count}/{ticks} ticks authenticated "
        f"& matched original payload exactly."
    )
    if decrypt_failures:
        _warn(f"{decrypt_failures} decryption HTTP errors encountered.")
    if decrypt_mismatches:
        _fail(
            f"{decrypt_mismatches} decrypted payloads do NOT match original -- "
            "potential data integrity issue!"
        )

    # ── Phase 8: database isolation ────────────────────────────────────────────
    _section("Phase 8 -- Database Isolation Assertion (mock_db.json)")
    assert_database_isolation(db_path)

    # ── Summary report ─────────────────────────────────────────────────────────
    _banner("BENCHMARK REPORT -- Month 1 Early Evaluation Metrics", char="=")

    avg_ingest  = mean(ingest_latencies_ms)
    std_ingest  = stdev(ingest_latencies_ms) if len(ingest_latencies_ms) > 1 else 0.0
    min_ingest  = min(ingest_latencies_ms)
    max_ingest  = max(ingest_latencies_ms)
    avg_decrypt = mean(decrypt_latencies_ms) if decrypt_latencies_ms else 0.0
    std_decrypt = stdev(decrypt_latencies_ms) if len(decrypt_latencies_ms) > 1 else 0.0

    print()
    print("  +-- ENCRYPTION OVERHEAD -----------------------------------------+")
    _metric("Avg raw JSON serialisation latency",   f"{avg_raw:.4f} ms")
    _metric("Avg AES-256-GCM encryption latency",   f"{avg_enc:.4f} ms  (stddev={std_enc:.4f} ms)")
    _metric("Avg net encryption overhead",          f"{avg_over:.4f} ms")
    _metric("Overhead ratio",                       f"{(avg_enc / max(avg_raw, 1e-9)):.2f}x raw serialisation")
    print()
    print("  +-- PAYLOAD SIZE OVERHEAD ----------------------------------------+")
    _metric("Raw JSON payload",                     f"{raw_bytes} bytes")
    _metric("AES-GCM hex ciphertext",               f"{cipher_bytes} bytes")
    _metric("Full encrypted packet",                f"{full_packet_bytes} bytes")
    _metric("Ciphertext-only overhead",             f"+{pct_increase:.1f}% vs raw JSON")
    _metric(
        "Full packet overhead",
        f"+{((full_packet_bytes - raw_bytes) / raw_bytes) * 100:.1f}% vs raw JSON",
    )
    print()
    print("  +-- API INGESTION LATENCY (POST /ingest) -------------------------+")
    _metric("Ticks ingested",                      f"{ticks} / {ticks} ({ingest_failures} failures)")
    _metric("Avg ingestion latency",                f"{avg_ingest:.2f} ms  (stddev={std_ingest:.2f} ms)")
    _metric("Min / Max ingestion latency",          f"{min_ingest:.2f} ms / {max_ingest:.2f} ms")
    print()
    print("  +-- AUTHORIZED DECRYPTION LATENCY (POST /authorize-decrypt) -----+")
    _metric("Avg decryption API latency",           f"{avg_decrypt:.2f} ms  (stddev={std_decrypt:.2f} ms)")
    _metric("Round-trip integrity",                 f"{success_count}/{ticks} payloads verified")
    print()
    print("  +-- DATABASE ISOLATION (mock_db.json) ----------------------------+")
    _metric("Plaintext keyword leaks detected",     f"0 / {len(SENSITIVE_KEYWORDS)} keywords")
    _metric("Storage model",                        "hex-encoded AES-256-GCM ciphertext ONLY")
    _metric("GDPR compliance",                      "Data Protection by Design (Art. 25 GDPR)")
    print()
    print("  +-----------------------------------------------------------------+")

    # ── Verdict ────────────────────────────────────────────────────────────────
    _banner("VERIFICATION VERDICT", char="=")

    all_pass = (
        ingest_failures == 0
        and decrypt_failures == 0
        and decrypt_mismatches == 0
        and success_count == ticks
    )

    if all_pass:
        print()
        print("  [OK]  ALL CHECKS PASSED")
        print()
        print("  Month 1 pipeline is fully operational and security-verified:")
        print("   * Edge IoT sensor  ->  SecureGateway AES-256-GCM encryption")
        print("   * Encrypted payload  ->  Cloud REST API ingestion (zero plaintext)")
        print("   * Encrypted-only storage  ->  Authorized AES decryption round-trip")
        print("   * mock_db.json contains ZERO unencrypted biometric field names")
        print()
        print("  +================================================================+")
        print("  |        PHASE 1 COMPLETE -- Month 1  (100% Done)               |")
        print("  +================================================================+")
    else:
        print()
        _fail("ONE OR MORE VERIFICATION CHECKS FAILED -- see warnings above.")

    # ── Cleanup temp db ────────────────────────────────────────────────────────
    try:
        os.unlink(db_path)
    except OSError:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Week 4 -- Month 1 End-to-End Pipeline Verification & Benchmarking "
            "(Bachelor's Thesis: Data Privacy in Elite Performance)"
        )
    )
    parser.add_argument(
        "--ticks",
        type=int,
        default=20,
        metavar="N",
        help="Number of biometric sensor ticks to simulate (default: 20).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    asyncio.run(run_pipeline(ticks=args.ticks))
