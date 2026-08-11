"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 8: End-to-End Evaluation & Performance Benchmarking

Automated benchmarking suite that exercises the full 7-module pipeline
across 100+ simulated iterations and computes all instructor-specified
evaluation metrics.

Run directly:
    python benchmark_evaluation.py

Outputs:
    - Markdown-formatted metrics table to stdout
    - EVALUATION_RESULTS.json in the working directory

Metrics computed (per instructor specification):
    1. Successful Request Rate (%)
    2. Failed Request Rate (%)
    3. API Response Times (ms) per endpoint
    4. Encryption Overhead (ms) — raw JSON vs AES-256-GCM
    5. Decryption Overhead (ms)
    6. Throughput (req/sec) — peak batch ingestion
    7. Storage Overhead — raw vs ciphertext vs audit row vs ledger block (bytes + %)
"""

from __future__ import annotations

import json
import os
import statistics
import time
from typing import Any, Dict

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Bootstrap isolated test environment BEFORE importing main_server
# (prevents the module-level singletons from touching production files)
# ---------------------------------------------------------------------------
_BENCH_DB = "bench_mock_db.json"
_BENCH_AUDIT = "bench_audit_log.csv"
_BENCH_LEDGER = "bench_ledger.json"

os.environ.setdefault("MOCK_DB_PATH", _BENCH_DB)
os.environ.setdefault("AUDIT_LOG_PATH", _BENCH_AUDIT)
os.environ.setdefault("LEDGER_FILE_PATH", _BENCH_LEDGER)

# Force settings cache to reload with bench paths
import config as _cfg
_cfg.get_settings.cache_clear()

import audit_logger as _audit_mod
import cloud_server as _cs_mod
import local_hashed_ledger as _ledger_mod
import main_server as _ms

from audit_logger import AuditLogger
from cloud_server import ConsentRegistry
from iot_device import IoTDeviceMock
from local_hashed_ledger import LocalHashedLedger
from pipeline_week2 import adapt_to_schema
from secure_gateway import SecureGateway

ITERATIONS = 100
PLAYER_ID = "BENCH-PLAYER-001"
GATEWAY_ID = "BENCH-GW-001"
DEVICE_ID = "BENCH-IOT-001"
API_KEY = _cfg.get_settings().CLOUD_API_KEY
API_HEADERS = {"X-API-Key": API_KEY}


def _make_client() -> TestClient:
    """Rebuild all module-level singletons with isolated bench files."""
    _ms.cloud_server = _cs_mod.CloudServer(db_path=_BENCH_DB)
    _ms.consent_registry = ConsentRegistry()
    _ms.audit_logger = AuditLogger(log_file_path=_BENCH_AUDIT)
    _ms.ledger = LocalHashedLedger(ledger_file_json=_BENCH_LEDGER)
    return TestClient(_ms.app, raise_server_exceptions=False)


def _cleanup() -> None:
    for p in (_BENCH_DB, _BENCH_AUDIT, _BENCH_LEDGER):
        if os.path.exists(p):
            os.remove(p)


def _build_encrypted_packet(gateway: SecureGateway) -> dict:
    device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)
    raw = device.generate_biometrics()
    schema = adapt_to_schema(raw)
    enc = gateway.encrypt_data(schema, device_id=DEVICE_ID, player_id=PLAYER_ID)
    return {
        "gateway_id": enc["gateway_id"],
        "device_id": enc.get("device_id"),
        "player_id": enc.get("player_id"),
        "sent_at": enc.get("sent_at"),
        "nonce": enc["nonce"],
        "ciphertext": enc["ciphertext"],
    }, enc


# ---------------------------------------------------------------------------
# METRIC 1 & 2: Successful / Failed Request Rate + Metric 3: Response Times
# ---------------------------------------------------------------------------

def bench_request_rates_and_latency(client: TestClient, aes_key: bytes, gateway: SecureGateway) -> dict:
    print("  [1/7] Measuring request rates & response times...")

    # --- Ingest (expect 201) — reset rate limiter between each call ---
    ingest_times: list[float] = []
    success_count = 0
    for _ in range(ITERATIONS):
        _ms._rate_limit_store.clear()          # reset sliding-window between iterations
        packet, _ = _build_encrypted_packet(gateway)
        t0 = time.perf_counter()
        r = client.post("/api/v1/telemetry/ingest", json=packet, headers=API_HEADERS)
        ingest_times.append((time.perf_counter() - t0) * 1000)
        if r.status_code == 201:
            success_count += 1
    successful_rate = success_count / ITERATIONS * 100

    # --- Consent toggle (grant + revoke, expect 200) ---
    consent_times: list[float] = []
    for toggle in ([True, False] * (ITERATIONS // 2)):
        t0 = time.perf_counter()
        client.post(
            "/api/v1/athlete/consent",
            json={"player_id": PLAYER_ID, "privacy_toggle_consent": toggle},
            headers=API_HEADERS,
        )
        consent_times.append((time.perf_counter() - t0) * 1000)
    # Reset to granted for decrypt bench
    client.post(
        "/api/v1/athlete/consent",
        json={"player_id": PLAYER_ID, "privacy_toggle_consent": True},
        headers=API_HEADERS,
    )

    # --- Failed requests: RBAC denial (expect 403) ---
    fail_count = 0
    # Get one valid packet from storage
    stored = _ms.cloud_server.get_all_stored_records()
    if stored:
        sample = stored[0]
        for _ in range(ITERATIONS // 5):
            r = client.post(
                "/api/v1/telemetry/authorize-decrypt",
                json={"record": sample, "aes_key_hex": aes_key.hex()},
                headers={**API_HEADERS, "X-User-Role": "EXTERNAL_COMPANY", "X-Player-Id": PLAYER_ID},
            )
            if r.status_code == 403:
                fail_count += 1
    failed_rate = fail_count / (ITERATIONS // 5) * 100 if stored else 0

    # --- Authorize-decrypt (expect 200, TEAM_DOCTOR) ---
    decrypt_times: list[float] = []
    if stored:
        sample = stored[0]
        for _ in range(ITERATIONS // 5):
            t0 = time.perf_counter()
            client.post(
                "/api/v1/telemetry/authorize-decrypt",
                json={"record": sample, "aes_key_hex": aes_key.hex()},
                headers={**API_HEADERS, "X-User-Role": "TEAM_DOCTOR", "X-Player-Id": PLAYER_ID},
            )
            decrypt_times.append((time.perf_counter() - t0) * 1000)

    # --- Transfer (expect 200) ---
    transfer_times: list[float] = []
    for i in range(ITERATIONS // 10):
        t0 = time.perf_counter()
        client.post(
            "/api/v1/transfer/process",
            json={
                "player_id": PLAYER_ID,
                "selling_club": f"Club-A-{i}",
                "buying_club": f"Club-B-{i}",
                "escrow_deposit_verified": True,
            },
            headers={**API_HEADERS, "X-User-Role": "CLUB_ADMIN"},
        )
        transfer_times.append((time.perf_counter() - t0) * 1000)

    return {
        "successful_request_rate_pct": round(successful_rate, 2),
        "failed_request_rate_pct": round(failed_rate, 2),
        "avg_response_times_ms": {
            "ingest": round(statistics.mean(ingest_times), 3),
            "consent": round(statistics.mean(consent_times), 3),
            "authorize_decrypt": round(statistics.mean(decrypt_times), 3) if decrypt_times else 0.0,
            "transfer": round(statistics.mean(transfer_times), 3) if transfer_times else 0.0,
        },
    }


# ---------------------------------------------------------------------------
# METRIC 4 & 5: Encryption / Decryption Overhead
# ---------------------------------------------------------------------------

def bench_crypto_overhead(aes_key: bytes, gateway: SecureGateway) -> dict:
    print("  [2/7] Measuring encryption & decryption overhead...")

    device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)

    # Baseline: raw JSON serialisation only
    raw_times: list[float] = []
    for _ in range(ITERATIONS):
        raw = device.generate_biometrics()
        schema = adapt_to_schema(raw)
        t0 = time.perf_counter()
        json.dumps(schema)
        raw_times.append((time.perf_counter() - t0) * 1000)

    # AES-256-GCM encryption
    enc_times: list[float] = []
    encrypted_packets = []
    for _ in range(ITERATIONS):
        raw = device.generate_biometrics()
        schema = adapt_to_schema(raw)
        t0 = time.perf_counter()
        enc = gateway.encrypt_data(schema, device_id=DEVICE_ID, player_id=PLAYER_ID)
        enc_times.append((time.perf_counter() - t0) * 1000)
        encrypted_packets.append(enc)

    # AES-256-GCM decryption
    dec_times: list[float] = []
    for enc in encrypted_packets[:ITERATIONS]:
        t0 = time.perf_counter()
        gateway.decrypt_data(enc, max_age_seconds=None)
        dec_times.append((time.perf_counter() - t0) * 1000)

    enc_overhead = statistics.mean(enc_times) - statistics.mean(raw_times)

    return {
        "raw_json_serialise_ms": round(statistics.mean(raw_times), 4),
        "encryption_overhead_ms": round(max(enc_overhead, 0.0), 4),
        "decryption_overhead_ms": round(statistics.mean(dec_times), 4),
    }


# ---------------------------------------------------------------------------
# METRIC 6: Throughput (req/sec)
# ---------------------------------------------------------------------------

def bench_throughput(client: TestClient, gateway: SecureGateway) -> dict:
    print("  [3/7] Measuring throughput (req/sec)...")

    packets = []
    for _ in range(ITERATIONS):
        p, _ = _build_encrypted_packet(gateway)
        packets.append(p)

    # Clear the rate limiter so the burst measures raw processing speed,
    # not rate-limiter rejection latency (the limiter is a security feature,
    # not an application bottleneck — its effect is documented separately).
    _ms._rate_limit_store.clear()

    t_start = time.perf_counter()
    for p in packets:
        _ms._rate_limit_store.clear()
        client.post("/api/v1/telemetry/ingest", json=p, headers=API_HEADERS)
    elapsed = time.perf_counter() - t_start

    return {"throughput_req_per_sec": round(ITERATIONS / elapsed, 2)}


# ---------------------------------------------------------------------------
# METRIC 7: Storage Overhead
# ---------------------------------------------------------------------------

def bench_storage_overhead(aes_key: bytes, gateway: SecureGateway) -> dict:
    print("  [4/7] Measuring storage overhead...")

    device = IoTDeviceMock(device_id=DEVICE_ID, player_id=PLAYER_ID)
    raw = device.generate_biometrics()
    schema = adapt_to_schema(raw)

    # Raw biometric payload size
    raw_json = json.dumps(schema, separators=(",", ":"))
    raw_bytes = len(raw_json.encode("utf-8"))

    # Ciphertext envelope size (as stored in mock_db.json)
    enc = gateway.encrypt_data(schema, device_id=DEVICE_ID, player_id=PLAYER_ID)
    cipher_json = json.dumps({k: enc[k] for k in ("nonce", "ciphertext", "gateway_id", "player_id", "sent_at") if k in enc}, separators=(",", ":"))
    cipher_bytes = len(cipher_json.encode("utf-8"))

    # Audit log row size (CSV, one row)
    audit_row = f"2026-01-01T00:00:00.000Z,TEAM_DOCTOR,TEAM_DOCTOR,{PLAYER_ID},VIEW_BIOMETRIC_DATA,SUCCESS_200,127.0.0.1\r\n"
    audit_bytes = len(audit_row.encode("utf-8"))

    # Ledger block size (one JSON block)
    sample_block = {
        "index": 1, "timestamp": "2026-01-01T00:00:00.000Z",
        "player_id": PLAYER_ID, "selling_club": "Club-A", "buying_club": "Club-B",
        "escrow_deposit_verified": True,
        "encrypted_payload_hash": "a" * 64,
        "previous_hash": "b" * 64, "hash": "c" * 64,
    }
    ledger_block_bytes = len(json.dumps(sample_block, separators=(",", ":")).encode("utf-8"))

    overhead_pct = round((cipher_bytes - raw_bytes) / raw_bytes * 100, 2)

    return {
        "storage_overhead": {
            "raw_biometric_bytes": raw_bytes,
            "ciphertext_bytes": cipher_bytes,
            "audit_row_bytes": audit_bytes,
            "ledger_block_bytes": ledger_block_bytes,
            "ciphertext_overhead_pct": overhead_pct,
        }
    }


# ---------------------------------------------------------------------------
# MAIN — run all benchmarks and emit results
# ---------------------------------------------------------------------------

def run_all() -> Dict[str, Any]:
    print(f"\n{'='*62}")
    print("  Athlete Biometrics — Week 8 Benchmark Suite")
    print(f"  Iterations: {ITERATIONS}")
    print(f"{'='*62}")

    _cleanup()
    aes_key = os.urandom(32)
    gateway = SecureGateway(gateway_id=GATEWAY_ID, aes_key=aes_key)
    client = _make_client()

    rates = bench_request_rates_and_latency(client, aes_key, gateway)
    crypto = bench_crypto_overhead(aes_key, gateway)
    throughput = bench_throughput(client, gateway)
    storage = bench_storage_overhead(aes_key, gateway)

    results: Dict[str, Any] = {
        "benchmark_iterations": ITERATIONS,
        **rates,
        **crypto,
        **throughput,
        **storage,
    }

    _cleanup()
    return results


def print_markdown_table(r: Dict[str, Any]) -> None:
    rt = r["avg_response_times_ms"]
    st = r["storage_overhead"]

    print(f"\n{'='*62}")
    print("  EVALUATION METRICS — Week 8 Benchmark Results")
    print(f"{'='*62}\n")

    print("| # | Metric | Value |")
    print("|---|--------|-------|")
    print(f"| 1 | Successful Request Rate | **{r['successful_request_rate_pct']:.1f}%** |")
    print(f"| 2 | Failed Request Rate (expected 4xx) | **{r['failed_request_rate_pct']:.1f}%** |")
    print(f"| 3a | Avg Response Time — `/ingest` | **{rt['ingest']:.2f} ms** |")
    print(f"| 3b | Avg Response Time — `/consent` | **{rt['consent']:.2f} ms** |")
    print(f"| 3c | Avg Response Time — `/authorize-decrypt` | **{rt['authorize_decrypt']:.2f} ms** |")
    print(f"| 3d | Avg Response Time — `/transfer/process` | **{rt['transfer']:.2f} ms** |")
    print(f"| 4 | AES-256-GCM Encryption Overhead | **{r['encryption_overhead_ms']:.3f} ms** |")
    print(f"| 5 | AES-256-GCM Decryption Overhead | **{r['decryption_overhead_ms']:.3f} ms** |")
    print(f"| 6 | Peak Throughput | **{r['throughput_req_per_sec']:.1f} req/sec** |")
    print(f"| 7a | Storage — Raw Biometric JSON | **{st['raw_biometric_bytes']} bytes** |")
    print(f"| 7b | Storage — AES-256-GCM Ciphertext Envelope | **{st['ciphertext_bytes']} bytes** |")
    print(f"| 7c | Storage — Audit Log Row | **{st['audit_row_bytes']} bytes** |")
    print(f"| 7d | Storage — SHA-256 Ledger Block | **{st['ledger_block_bytes']} bytes** |")
    print(f"| 7e | Ciphertext Storage Overhead vs. Raw | **+{st['ciphertext_overhead_pct']:.1f}%** |")
    print()


if __name__ == "__main__":
    results = run_all()
    print_markdown_table(results)

    out_path = "EVALUATION_RESULTS.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"  Results saved → {out_path}\n")
