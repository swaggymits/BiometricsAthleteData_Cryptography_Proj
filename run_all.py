"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Master Runner: Executes the ENTIRE project in one command.

This script runs, in order:
    1. All automated unit/integration tests (auto-discovered via unittest),
       covering Week 1 (SecureGateway, biometric_schema) and any future
       week's test_*.py files placed in the project root.
    2. The Week 2 IoT -> SecureGateway transmission pipeline demo.

Usage:
    python run_all.py
"""

from __future__ import annotations

import sys
import unittest


def run_all_tests() -> bool:
    """
    Auto-discover and run every test_*.py file in the project root.

    Returns:
        bool: True if all discovered tests passed, False otherwise.
    """
    print("=" * 80)
    print("STEP 1/2: Running full automated test suite (unittest discovery)")
    print("=" * 80)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="tests", pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


def run_pipeline_demo() -> None:
    """Run the Week 2 IoT Device -> SecureGateway transmission pipeline demo."""
    print("\n" + "=" * 80)
    print("STEP 2/2: Running Week 2 IoT -> SecureGateway transmission pipeline")
    print("=" * 80 + "\n")

    from edge.pipeline_week2 import run_pipeline
    run_pipeline(ticks=5, delay_seconds=1.0)


def main() -> None:
    """Entry point: run all tests, then the pipeline demo, and exit with proper status."""
    tests_passed = run_all_tests()

    if not tests_passed:
        print("\n❌ One or more tests FAILED. Skipping pipeline demo.")
        sys.exit(1)

    print("\n✅ All tests passed.\n")
    run_pipeline_demo()

    print("\n" + "=" * 80)
    print("✅ PROJECT RUN COMPLETE: All tests passed and pipeline executed successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()
