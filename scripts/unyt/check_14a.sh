#!/usr/bin/env bash
# Sprint 14A deterministic, no wallet / no funding tests.
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "Sprint 14A exact source SHA: $(git rev-parse HEAD)"
echo "Cargo.lock sha256: $(sha256sum Cargo.lock | cut -d' ' -f1)"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/unyt -p 'test_*.py' -v
# The tracked config must not validate. A successful result is a security fail.
if python3 scripts/unyt/testnet.py validate --config integration/unyt/testnet.example.json; then
  echo 'ERROR: template configuration unexpectedly passed validation' >&2
  exit 1
fi
cargo test -p unyt_harness --test templates --locked
cargo clippy -p unyt_harness --tests --locked -- -D warnings
echo 'Sprint 14A offline tests completed. No testnet deployment or financial acceptance implied.'
