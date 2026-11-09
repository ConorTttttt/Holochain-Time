#!/usr/bin/env bash
# Run a real 3-agent Sweettest test against a TEST-ONLY packed DNA.
set -euo pipefail
if [[ $# -gt 0 && "$1" == "--help" ]]; then
 echo 'HC_VTIME_TEST_DNA=/absolute/test/vtime.dna HC_VTIME_TEST_MANIFEST=/absolute/test/dna.yaml bash scripts/run_conductor_smoke.sh'
 exit 0
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for cmd in git cargo rustc sha256sum python3; do
 command -v "$cmd" >/dev/null || { echo "BLOCKED: missing $cmd" >&2; exit 2; }
done
[[ -v HC_VTIME_TEST_DNA && -v HC_VTIME_TEST_MANIFEST ]] ||
 { echo "BLOCKED: supply test DNA and manifest env vars" >&2; exit 2; }
[[ -f "$HC_VTIME_TEST_DNA" && -f "$HC_VTIME_TEST_MANIFEST" ]] ||
 { echo 'BLOCKED: missing packed DNA or its source manifest' >&2; exit 2; }
python3 "$ROOT/scripts/check_test_dna_config.py" --manifest "$HC_VTIME_TEST_MANIFEST"
SHA="$(git -C "$ROOT" rev-parse --verify HEAD)"
[[ ! -v HC_VTIME_EXPECTED_SHA || "$SHA" == "$HC_VTIME_EXPECTED_SHA" ]] ||
 { echo 'BLOCKED: wrong commit SHA' >&2; exit 4; }
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] ||
 { echo 'BLOCKED: dirty tracked/untracked source tree' >&2; exit 4; }
REPORT="$ROOT/../hc-vtime-conductor-smoke-$SHA"
mkdir -p "$REPORT"
{
 echo "sha=$SHA"
 echo "test_dna_sha256=$(sha256sum "$HC_VTIME_TEST_DNA" | cut -d' ' -f1)"
 echo "manifest_sha256=$(sha256sum "$HC_VTIME_TEST_MANIFEST" | cut -d' ' -f1)"
 echo "rustc=$(rustc --version)"
 echo "scope=real Sweettest smoke only, not signed-quorum acceptance"
} > "$REPORT/provenance.txt"
finish() {
 status=$?; trap - EXIT
 echo "exit_code=$status" >> "$REPORT/provenance.txt"
 (cd "$REPORT" && sha256sum provenance.txt conductor-smoke.log > SHA256SUMS 2>/dev/null) || true
 echo "Evidence: $REPORT (exit=$status)" >&2
}
trap finish EXIT
cd "$ROOT"
cargo test --manifest-path integration/conductor/Cargo.toml --test smoke -- --nocapture \
  2>&1 | tee "$REPORT/conductor-smoke.log"
