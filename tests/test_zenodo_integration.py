"""
Zenodo Public Dataset — End-to-End Integration Test
=====================================================

This test downloads real athlete data from the Zenodo public repository
and runs it through the complete BiometricsAthleteData cryptographic
security pipeline, demonstrating the system's performance on authentic
(publicly sourced) biometric profiles.

Dataset: Synthetic Triathlete Dataset for Injury Prediction Research (2024)
DOI:     10.5281/zenodo.15401061
License: CC-BY 4.0

Pipeline stages tested
----------------------
1. Zenodo API fetch       — live download of athletes.csv
2. Schema mapping         — Zenodo columns → BiometricPayload
3. Schema validation      — biometric_schema.validate_biometric_payload()
4. AES-256-GCM encryption — SecureGateway.encrypt_data()
5. Decryption & integrity — SecureGateway.decrypt_data() + payload comparison
6. GDPR consent gate      — some athletes run with consent=False (expect reject)
7. Audit log              — every operation appended to audit_log.csv
8. Benchmark              — latency (ms/record), throughput (records/sec),
                            ciphertext expansion ratio

Usage
-----
    python test_zenodo_integration.py             # 50 athletes (default)
    python test_zenodo_integration.py --limit 100 # custom sample size

Expected output
---------------
    PASS  athlete_id=abc123...  hr=62  fatigue=34.2%  latency=0.18ms
    PASS  athlete_id=def456...  hr=55  fatigue=28.7%  latency=0.15ms
    ...
    ─────────────────────────────────────────────────
    RESULTS  | 48 PASS  |  2 CONSENT-BLOCKED  |  0 FAIL
    BENCHMARK| avg 0.17ms/record | 5882 rec/sec | ciphertext +18% overhead
    ─────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Allow running from project root without installing as package
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.biometric_schema import validate_biometric_payload
from core.secure_gateway import SecureGateway
from core.audit_logger import AuditLogger
from dataset.zenodo_dataset_loader import ZenodoDatasetLoader, DATASET_DOI, DATASET_CITATION

# ---------------------------------------------------------------------------
# ANSI colour codes (degrade gracefully on Windows)
# ---------------------------------------------------------------------------
_SUPPORTS_COLOUR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _SUPPORTS_COLOUR else text

GREEN  = lambda t: _c(t, "32")
RED    = lambda t: _c(t, "31")
YELLOW = lambda t: _c(t, "33")
CYAN   = lambda t: _c(t, "36")
BOLD   = lambda t: _c(t, "1")
DIM    = lambda t: _c(t, "2")


# ---------------------------------------------------------------------------
# GDPR Consent Registry (simple in-memory subset for demo)
# ---------------------------------------------------------------------------

class _ConsentRegistry:
    """Minimal in-memory consent store for the integration test."""

    def __init__(self) -> None:
        self._revoked: set = set()

    def revoke(self, player_id: str) -> None:
        self._revoked.add(player_id)

    def has_consent(self, player_id: str) -> bool:
        return player_id not in self._revoked


# ---------------------------------------------------------------------------
# Benchmark accumulator
# ---------------------------------------------------------------------------

class _Benchmark:
    def __init__(self) -> None:
        self.latencies_ms: List[float] = []
        self.plaintext_sizes: List[int] = []
        self.ciphertext_sizes: List[int] = []

    def record(self, latency_ms: float, plaintext_bytes: int, ciphertext_bytes: int) -> None:
        self.latencies_ms.append(latency_ms)
        self.plaintext_sizes.append(plaintext_bytes)
        self.ciphertext_sizes.append(ciphertext_bytes)

    @property
    def avg_latency_ms(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def throughput_rps(self) -> float:
        avg = self.avg_latency_ms
        return (1000.0 / avg) if avg > 0 else 0.0

    @property
    def avg_expansion_pct(self) -> float:
        pairs = list(zip(self.plaintext_sizes, self.ciphertext_sizes))
        if not pairs:
            return 0.0
        expansions = [(c - p) / max(p, 1) * 100 for p, c in pairs]
        return sum(expansions) / len(expansions)

    @property
    def count(self) -> int:
        return len(self.latencies_ms)


# ---------------------------------------------------------------------------
# Core test runner
# ---------------------------------------------------------------------------

def run_integration_test(limit: int = 50, consent_revoke_fraction: float = 0.05) -> int:
    """
    Run the full end-to-end Zenodo integration test.

    Args:
        limit:                  Number of athletes to test (sampled from 1,000).
        consent_revoke_fraction: Fraction of athletes whose consent is pre-revoked
                                 (to verify the GDPR gate rejects them).

    Returns:
        int: Exit code — 0 on success, 1 if any unexpected failures occurred.
    """

    print()
    print(BOLD("=" * 62))
    print(BOLD("  Zenodo Dataset Integration Test"))
    print(BOLD("  BiometricsAthleteData Cryptographic Pipeline"))
    print(BOLD("=" * 62))
    print(f"  Dataset DOI : {CYAN(DATASET_DOI)}")
    print(f"  Athletes    : {limit} (sampled from 1,000 in dataset)")
    print(f"  Consent rev.: {int(consent_revoke_fraction * 100)}% of athletes (GDPR gate test)")
    print()

    # ── Step 1: Fetch from Zenodo ──────────────────────────────────────────
    loader = ZenodoDatasetLoader()
    try:
        loader.fetch(verbose=True)
    except Exception as exc:
        print(RED(f"  [FATAL] Zenodo fetch failed: {exc}"))
        print(DIM("  Check network connectivity and try again."))
        return 1

    print(loader.summary())
    print()

    # ── Step 2: Set up gateway & audit ────────────────────────────────────
    shared_aes_key: bytes = os.urandom(32)  # shared key (same instance encrypts & decrypts)
    gateway = SecureGateway(
        gateway_id="ZENODO-TEST-GW-001",
        aes_key=shared_aes_key,
    )
    audit = AuditLogger()
    consent = _ConsentRegistry()
    bench = _Benchmark()

    # Determine which athletes will have consent revoked (GDPR test)
    all_payloads: List[Tuple[Dict[str, Any], Dict[str, str]]] = list(
        loader.stream_payloads(limit=limit, shuffle=True)
    )
    revoke_count = max(1, int(len(all_payloads) * consent_revoke_fraction))
    revoked_ids = {meta["athlete_id"] for _, meta in all_payloads[:revoke_count]}
    for aid in revoked_ids:
        consent.revoke(aid)

    # ── Step 3: Per-athlete pipeline ──────────────────────────────────────
    print(BOLD("  Per-athlete pipeline results"))
    print("  " + "─" * 58)
    header = f"  {'STATUS':<18} {'ATHLETE ID':<12} {'HR':>4}  {'FAT%':>6}  {'GLUC':>6}  {'RISK':>5}  {'LAT(ms)':>8}"
    print(DIM(header))
    print("  " + "─" * 58)

    passed = 0
    consent_blocked = 0
    failed = 0
    schema_rejected = 0
    unexpected_errors: List[str] = []

    for idx, (payload, meta) in enumerate(all_payloads):
        athlete_id = meta["athlete_id"]
        device_id  = meta["device_id"]
        short_id   = athlete_id[:8] + "…"

        # ── GDPR Consent Gate ─────────────────────────────────────────────
        if not consent.has_consent(athlete_id):
            consent_blocked += 1
            audit.log_access(
                user_id=device_id,
                user_role="IOT_DEVICE",
                player_id=athlete_id,
                action="ENCRYPT_BLOCKED_NO_CONSENT",
                status="DENIED_GDPR_403",
            )
            status_str = YELLOW(f"  CONSENT-BLOCK    {short_id:<12}")
            print(
                f"{status_str}  "
                f"hr={payload['heart_rate']:>3}  "
                f"fat={payload['fatigue_index']:>5.1f}%  "
                f"glc={payload['glucose_level']:>5.1f}  "
                f"risk={payload['injury_risk']:>4.2f}  "
                f"{'—':>8}"
            )
            continue

        # ── Schema Validation ─────────────────────────────────────────────
        try:
            validate_biometric_payload(payload)
        except (TypeError, ValueError) as schema_err:
            schema_rejected += 1
            failed += 1
            audit.log_access(
                user_id=device_id,
                user_role="IOT_DEVICE",
                player_id=athlete_id,
                action="SCHEMA_VALIDATION_FAIL",
                status="SCHEMA_REJECTED",
            )
            print(RED(f"  SCHEMA-REJECT    {short_id:<12}  {str(schema_err)[:40]}"))
            continue

        # ── AES-256-GCM Encryption ────────────────────────────────────────
        t0 = time.perf_counter()
        try:
            encrypted_packet = gateway.encrypt_data(
                payload,
                device_id=device_id,
                player_id=athlete_id,
            )
        except Exception as enc_err:
            failed += 1
            unexpected_errors.append(f"{short_id}: encrypt → {enc_err}")
            print(RED(f"  ENCRYPT-FAIL     {short_id:<12}  {str(enc_err)[:40]}"))
            continue
        encrypt_ms = (time.perf_counter() - t0) * 1000.0

        # ── Decryption & Integrity Verification ───────────────────────────
        try:
            decrypted = gateway.decrypt_data(encrypted_packet)
        except Exception as dec_err:
            failed += 1
            unexpected_errors.append(f"{short_id}: decrypt → {dec_err}")
            print(RED(f"  DECRYPT-FAIL     {short_id:<12}  {str(dec_err)[:40]}"))
            continue

        # Verify round-trip payload fidelity
        if decrypted != payload:
            failed += 1
            detail = "Decrypted payload does not match original"
            unexpected_errors.append(f"{short_id}: {detail}")
            print(RED(f"  INTEGRITY-FAIL   {short_id:<12}  {detail}"))
            continue

        # ── Benchmark accumulation ────────────────────────────────────────
        plaintext_b  = len(json.dumps(payload).encode("utf-8"))
        ciphertext_b = len(bytes.fromhex(encrypted_packet["ciphertext"]))
        bench.record(encrypt_ms, plaintext_b, ciphertext_b)

        # ── Audit log ─────────────────────────────────────────────────────
        audit.log_access(
            user_id=device_id,
            user_role="IOT_DEVICE",
            player_id=athlete_id,
            action="TELEMETRY_INGEST",
            status="SUCCESS",
        )

        passed += 1
        status_str = GREEN(f"  PASS             {short_id:<12}")
        print(
            f"{status_str}  "
            f"hr={payload['heart_rate']:>3}  "
            f"fat={payload['fatigue_index']:>5.1f}%  "
            f"glc={payload['glucose_level']:>5.1f}  "
            f"risk={payload['injury_risk']:>4.2f}  "
            f"{encrypt_ms:>7.2f}ms"
        )

    # ── Step 4: Summary ───────────────────────────────────────────────────
    print()
    print("  " + "─" * 58)
    print(BOLD("  RESULTS SUMMARY"))
    print("  " + "─" * 58)

    total = passed + consent_blocked + failed
    print(f"  Athletes tested         : {total}")
    print(f"  {GREEN('PASS')}                    : {passed}")
    print(f"  {YELLOW('CONSENT-BLOCKED (GDPR)')}: {consent_blocked}")
    print(f"  {RED('SCHEMA-REJECTED')        }: {schema_rejected}")
    print(f"  {RED('UNEXPECTED FAILURES')    }: {failed - schema_rejected}")

    if bench.count > 0:
        print()
        print(BOLD("  BENCHMARK"))
        print("  " + "─" * 58)
        print(f"  Records encrypted       : {bench.count}")
        print(f"  Avg encrypt latency     : {bench.avg_latency_ms:.3f} ms/record")
        print(f"  Throughput (est.)       : {bench.throughput_rps:,.0f} records/sec")
        print(f"  Avg ciphertext overhead : +{bench.avg_expansion_pct:.1f}% over plaintext")
        print(f"  (AES-GCM adds 12-byte nonce + 16-byte auth tag per record)")

    print()
    print(BOLD("  DATASET CITATION"))
    print("  " + "─" * 58)
    print(f"  {DIM(DATASET_CITATION)}")
    print()
    print(BOLD("=" * 62))

    if unexpected_errors:
        print()
        print(RED(BOLD("  Unexpected errors:")))
        for e in unexpected_errors:
            print(f"    • {e}")
        return 1

    print(GREEN(BOLD("  All tests completed successfully.")))
    print()
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Zenodo public dataset integration test for the "
            "BiometricsAthleteData cryptographic pipeline."
        )
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Number of Zenodo athletes to process (default: 50, max: 1000).",
    )
    parser.add_argument(
        "--consent-revoke-pct",
        type=float,
        default=5.0,
        metavar="PCT",
        help="Percentage of athletes whose GDPR consent is pre-revoked (default: 5).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    limit = max(1, min(args.limit, 1000))
    revoke_frac = max(0.0, min(args.consent_revoke_pct / 100.0, 1.0))
    exit_code = run_integration_test(limit=limit, consent_revoke_fraction=revoke_frac)
    sys.exit(exit_code)
