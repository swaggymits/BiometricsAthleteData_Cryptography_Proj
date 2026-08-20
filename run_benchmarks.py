#!/usr/bin/env python3
"""
Docker benchmark runner — executes both evaluation scripts and copies
results to the /results volume mount (accessible on the host).
"""

import shutil
import subprocess
import sys

DIVIDER = "=" * 66


def main() -> int:
    print(f"\n{DIVIDER}")
    print("  Running Week 8 Benchmark Evaluation (100 iterations)...")
    print(f"{DIVIDER}\n")
    r1 = subprocess.run([sys.executable, "evaluation/benchmark_evaluation.py"], cwd="/app")

    print(f"\n{DIVIDER}")
    print("  Running System Evaluation (latency + throughput + GDPR)...")
    print(f"{DIVIDER}\n")
    r2 = subprocess.run([sys.executable, "system_evaluation.py"], cwd="/app")

    # Copy results to host-mounted volume
    for fname in ("EVALUATION_RESULTS.json", "SYSTEM_EVALUATION_RESULTS.json"):
        try:
            shutil.copy(f"/app/{fname}", f"/results/{fname}")
        except FileNotFoundError:
            print(f"  WARNING: {fname} not found — skipping copy.")

    print(f"\n{DIVIDER}")
    print("  Results copied to ./results/ on host.")
    print(f"{DIVIDER}\n")

    return max(r1.returncode, r2.returncode)


if __name__ == "__main__":
    sys.exit(main())
