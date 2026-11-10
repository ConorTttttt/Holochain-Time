"""Expose Sprint 25 incident tests to the repository's existing unittest discovery.

CI and scripts/verify_local.sh use:
    python3 -m unittest discover -s scripts -p 'test_*.py'

Those commands do not descend into non-package scripts/ops/. Import the
existing Sprint 25 test classes here rather than silently skipping every
operational acceptance and redaction regression.
"""
from pathlib import Path
import sys

OPS = Path(__file__).resolve().parent / "ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from test_ops import (  # noqa: E402,F401 - re-exported for unittest discovery
    IncidentCases,
    PrivateJournalAndDiagnostics,
    RedactionAndAdapterTests,
)

# The Roughtime probe suite was added after this review branch diverged.
# Once integrated, expose it to the same root discovery job without making
# this branch depend on a file it did not originally contain.
if (OPS / "test_probe.py").is_file():
    from test_probe import ProbeTests  # noqa: E402,F401
