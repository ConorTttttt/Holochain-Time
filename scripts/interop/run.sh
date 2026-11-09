#!/usr/bin/env bash
# Exact-commit Sprint 18 interoperability evidence, outside repository.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
usage() {
  echo "Usage: bash scripts/interop/run.sh --expected-sha SHA (--core-only | --signed-dna /absolute/path/to/test-only.dna)"
  echo "Requires clean checkout, Rust, Python 3, msgpack and cryptography."
}
EXPECTED=""
DNA=""
CORE_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-sha) [[ $# -ge 2 ]] || { usage; exit 2; }; EXPECTED=$2; shift 2 ;;
    --signed-dna) [[ $# -ge 2 ]] || { usage; exit 2; }; DNA=$2; shift 2 ;;
    --core-only) CORE_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "$EXPECTED" ]] || { echo "BLOCKED: explicit exact SHA required" >&2; exit 2; }
if [[ "$CORE_ONLY" -eq 1 && -n "$DNA" || "$CORE_ONLY" -eq 0 && -z "$DNA" ]]; then
  usage >&2
  exit 2
fi
for tool in git python3 cargo rustc sha256sum; do
  command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool" >&2; exit 2; }
done
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SHA" == "$EXPECTED" ]] || { echo "BLOCKED: SHA mismatch" >&2; exit 4; }
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "BLOCKED: dirty source checkout" >&2; exit 4;
}
if [[ "$CORE_ONLY" -eq 0 ]]; then
  [[ -s "$DNA" ]] || { echo "BLOCKED: packed signed test DNA missing" >&2; exit 4; }
  DNA=$(cd "$(dirname "$DNA")" && pwd)/$(basename "$DNA")
fi
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$(dirname "$ROOT")/hc-vtime-interop-${SHA:0:12}-$STAMP-$$"
mkdir -p "$REPORT"
{
  echo "git_sha=$SHA"
  echo "utc_started=$(date -u +%FT%TZ)"
  echo "mode=$([[ "$CORE_ONLY" -eq 1 ]] && echo core_only || echo signed_conductor)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "python=$(python3 --version 2>&1)"
  echo "workspace_lock_sha256=$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  echo "oracle_vector_sha256=$(sha256sum "$ROOT/integration/interop/fixtures/v1_oracle.json" | cut -d' ' -f1)"
  echo "roughtime_vector_sha256=$(sha256sum "$ROOT/integration/interop/fixtures/roughtime_rfc_v1.json" | cut -d' ' -f1)"
  if [[ "$CORE_ONLY" -eq 0 ]]; then
    echo "signed_test_dna_sha256=$(sha256sum "$DNA" | cut -d' ' -f1)"
  fi
  echo "independent_time_operators_proven=false"
} > "$REPORT/provenance.txt"
printf 'step\texit_code\n' > "$REPORT/results.tsv"
FAILURES=0
run_step() {
  local name=$1; shift
  local status=0
  printf '$ %s\n' "$*" > "$REPORT/$name.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$name.log" 2>&1 || status=$?
  printf '%s\t%s\n' "$name" "$status" >> "$REPORT/results.tsv"
  (( status == 0 )) || FAILURES=$((FAILURES + 1))
  echo "$name: exit=$status" >&2
}
run_step fixtures_python_regenerate python3 scripts/interop/generate_vectors.py --check
run_step fixtures_python_verify python3 scripts/interop/verify_vectors.py
run_step rust_fmt cargo fmt --all -- --check
run_step evidence_interop cargo test --workspace --locked -p vtime_core --test evidence_interop -- --nocapture
run_step roughenough_reference cargo test --workspace --locked -p vtime_core --test roughenough_interop -- --nocapture
run_step workspace_tests cargo test --workspace --locked
run_step workspace_clippy cargo clippy --workspace --all-targets --locked -- -D warnings
if [[ "$CORE_ONLY" -eq 0 ]]; then
  run_step signed_conductor env HC_VTIME_SIGNED_TEST_ONLY=1 HC_VTIME_TEST_DNA="$DNA" \
    cargo test --manifest-path integration/conductor/Cargo.toml --locked \
    --test signed_quorum -- --nocapture
fi
{
  printf 'failure_count=%s\n' "$FAILURES"
  printf 'utc_finished=%s\n' "$(date -u +%FT%TZ)"
  if [[ "$CORE_ONLY" -eq 1 ]]; then
    echo "host_conductor_acceptance=not_run"
  else
    echo "host_conductor_acceptance=attempted"
  fi
} >> "$REPORT/provenance.txt"
(
  cd "$REPORT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
echo "Interoperability evidence: $REPORT (failed stages: $FAILURES)" >&2
[[ "$FAILURES" -eq 0 ]]
