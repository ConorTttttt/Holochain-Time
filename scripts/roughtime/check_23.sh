#!/usr/bin/env bash
# Sprint 23 offline acceptance smoke. NEVER counts as live independent-operator evidence.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s scripts/roughtime -p 'test_*.py' -v
cargo test -p vtime_core --test independent_sources --locked
cargo test -p vtime_core --test roughtime_acceptance --locked
cargo test -p vtime_core --test roughenough_interop --locked
cargo fmt --all -- --check
echo 'OFFLINE tests only; live independent operators and real Holochain still NOT RUN.'
