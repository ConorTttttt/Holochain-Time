#!/usr/bin/env bash
# Sprint 35 SOURCE audit only. Does NOT execute production WASM/HSM/Unyt gates.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: bash scripts/audit35/run_local.sh <exact-40-hex-git-sha> <new-external-bundle-directory>" >&2
  exit 2
fi
expected="$1"
bundle="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$root"
export PYTHONDONTWRITEBYTECODE=1
python3 -B -m unittest discover -s scripts/audit35 -p 'test_*.py' -v
python3 -B scripts/audit35/package.py --expected-sha "$expected" --output-dir "$bundle"
python3 -B scripts/audit35/verify.py --expected-sha "$expected" --bundle "$bundle"
echo "SOURCE_AUDIT_BUNDLE_VERIFIED_ONLY sha=$expected"
echo "NOT RUN: Rust/Clippy/WASM/conductor, dependency advisories, external oracle, funded Unyt, independent security signoff"
echo "PRODUCTION_RELEASE=NO-GO"
