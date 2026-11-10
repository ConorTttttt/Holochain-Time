#!/usr/bin/env bash
# Offline-only Sprint 25 acceptance: no operator keys, no network, no deployment.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
# Both the direct suite and the standard scripts-root discovery must find
# operational acceptance and redaction regressions.
python3 -m unittest discover -s scripts/ops -p 'test_*.py' -v
python3 -m unittest discover -s scripts -p 'test_ops_*.py' -v
# The shipped policy must be parseable without production signer authorization.
python3 -B -c 'import sys;sys.path.insert(0,"scripts/ops");from monitor import read_policy;from pathlib import Path;assert not read_policy(Path("config/ops-monitor.example.json"))["oracle_signing_enabled"]'
echo 'Sprint 25 OFFLINE regression complete. Live operational emitter and alert acceptance NOT RUN.'
