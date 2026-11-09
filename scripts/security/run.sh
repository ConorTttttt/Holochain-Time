#!/usr/bin/env bash
# Sprint 16 fail-closed local evidence runner. Never runs against production DNA.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
usage() {
  echo "Usage: bash scripts/security/run.sh --dna /path/to/test-only-vtime.dna --expected-sha SHA [--fuzz-seconds 120]"
  echo "Requires a clean, exact-commit checkout, Python 3.11+, Holonix 0.7, cargo-fuzz/nightly for fuzzing."
}
DNA=""
EXPECTED="${HC_VTIME_EXPECTED_SHA:-}"
FUZZ_SECONDS=120
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dna) [[ $# -ge 2 ]] || { usage; exit 2; }; DNA=$2; shift 2 ;;
    --expected-sha) [[ $# -ge 2 ]] || { usage; exit 2; }; EXPECTED=$2; shift 2 ;;
    --fuzz-seconds) [[ $# -ge 2 ]] || { usage; exit 2; }; FUZZ_SECONDS=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "$DNA" && -f "$DNA" ]] || { echo "BLOCKED: test DNA required" >&2; exit 2; }
[[ "$FUZZ_SECONDS" =~ ^[0-9]+$ && "$FUZZ_SECONDS" -ge 30 && "$FUZZ_SECONDS" -le 3600 ]] || {
  echo "BLOCKED: --fuzz-seconds must be 30..3600" >&2; exit 2;
}
for cmd in git python3 cargo rustc sha256sum tee; do
  command -v "$cmd" >/dev/null || { echo "BLOCKED: missing $cmd" >&2; exit 2; }
done
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ -z "$EXPECTED" || "$SHA" == "$EXPECTED" ]] || {
  echo "BLOCKED: expected SHA mismatch" >&2; exit 4;
}
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "BLOCKED: dirty source checkout" >&2; exit 4;
}
DNA=$(cd "$(dirname "$DNA")" && pwd)/$(basename "$DNA")
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$(dirname "$ROOT")/hc-vtime-security-${SHA:0:12}-$STAMP-$$"
mkdir -p "$REPORT"
FAILURES=0
run_step() {
  local name=$1; shift
  printf '%s\n' "$ $*" > "$REPORT/$name.log"
  local status=0
  "$@" >> "$REPORT/$name.log" 2>&1 || status=$?
  printf '%s\t%s\n' "$name" "$status" >> "$REPORT/results.tsv"
  (( status == 0 )) || FAILURES=$((FAILURES + 1))
  printf '%s: exit=%s\n' "$name" "$status" >&2
}
{
  printf 'git_sha=%s\n' "$SHA"
  printf 'dna_sha256=%s\n' "$(sha256sum "$DNA" | cut -d' ' -f1)"
  printf 'utc_started=%s\n' "$(date -u +%FT%TZ)"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'python=%s\n' "$(python3 --version 2>&1)"
  printf 'fuzz_seconds_per_target=%s\n' "$FUZZ_SECONDS"
  printf 'test_only_signing_keys=true\n'
  printf 'independent_roughtime_operators_proven=false\n'
} > "$REPORT/provenance.txt"
printf 'step\texit_code\n' > "$REPORT/results.tsv"
cd "$ROOT"
run_step reporter_tests python3 -m unittest discover -s scripts/security -p 'test_*.py' -v
run_step rust_fmt cargo fmt --all -- --check
run_step fuzz_fmt cargo fmt --manifest-path fuzz/Cargo.toml -- --check
run_step core_security cargo test --workspace --locked -p vtime_core --test security_adversarial -- --nocapture
run_step workspace_tests cargo test --workspace --locked
run_step workspace_clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run_step conductor_witness env HC_VTIME_SIGNED_TEST_ONLY=1 HC_VTIME_TEST_DNA="$DNA" \
  cargo test --manifest-path integration/conductor/Cargo.toml --locked \
  --test security_witness -- --nocapture
run_step inventory python3 scripts/security/inventory.py \
  --expected-sha "$SHA" --out "$REPORT/dependency-inventory.json"
run_step corpus python3 scripts/security/make_fuzz_corpus.py --out "$REPORT/corpus"
# Capture exact tool version and nightly availability; do not silently skip.
run_step cargo_fuzz_version cargo +nightly fuzz --version
for target in roughtime_parser roughtime_exchange; do
  run_step "fuzz_$target" cargo +nightly fuzz run "$target" "$REPORT/corpus/$target" -- \
    -max_total_time="$FUZZ_SECONDS" -max_len=65536 \
    -artifact_prefix="$REPORT/"
done
printf 'failure_count=%s\n' "$FAILURES" >> "$REPORT/provenance.txt"
printf 'finished_utc=%s\n' "$(date -u +%FT%TZ)" >> "$REPORT/provenance.txt"
(
  cd "$REPORT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
echo "Security evidence: $REPORT (failed stages: $FAILURES)" >&2
[[ "$FAILURES" -eq 0 ]]
