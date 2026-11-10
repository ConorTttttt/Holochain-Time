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
cargo fmt --manifest-path integration/conductor/Cargo.toml -- --check
# Compile the opt-in real-conductor test WITHOUT executing or faking live UDP.
cargo test --manifest-path integration/conductor/Cargo.toml --locked --test live_roughtime --no-run
echo 'OFFLINE/COMPILE ONLY; independent live operators and real Holochain still NOT RUN.'
