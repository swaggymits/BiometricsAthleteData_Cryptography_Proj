"""
conftest.py — Root pytest configuration.
Adds the project root to sys.path so that all packages
(core, server, edge, ledger, dataset, evaluation) are importable
from any test file regardless of working directory.
"""
import os
import sys

# Insert project root at the front of sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
