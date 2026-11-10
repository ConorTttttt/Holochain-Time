#!/usr/bin/env bash
# Sprint 26 GitHub-first OFFLINE validation. Never invoke funded Unyt credentials.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
usage() { echo "Usage: bash scripts/unyt/run_sprint26.sh --expected-sha <40-hex-git-sha>"; }
EXPECTED=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-sha) [[ $# -gt 1 ]] || { usage >&2; exit 2; }; EXPECTED=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$EXPECTED" =~ ^[a-f0-9]{40}$ ]] || { usage >&2; exit 2; }
for tool in git cargo rustc python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool" >&2; exit 3; }
done
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SHA" == "$EXPECTED" ]] || { echo "BLOCKED: Git SHA mismatch" >&2; exit 3; }
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "BLOCKED: dirty working tree" >&2; exit 3;
}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SHORT=$(printf '%.12s' "$SHA")
REPORT="$(dirname "$ROOT")/hc-vtime-sprint26-$SHORT-$STAMP-$$"
mkdir -p "$REPORT"
export PYTHONDONTWRITEBYTECODE=1
{
  echo "git_sha=$SHA"
  echo "utc_started=$(date -u +%FT%TZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "python=$(python3 --version 2>&1)"
  echo "workspace_lock_sha256=$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  echo "scenario_sha256=$(sha256sum "$ROOT/integration/unyt/sprint26_scenarios.json" | cut -d' ' -f1)"
  echo "funding_authorized=false"
  echo "testnet_transactions_performed=false"
  echo "native_unyt_peer_verified=false"
  echo "release_ready=false"
} > "$REPORT/provenance.txt"
printf 'stage\texit_code\n' > "$REPORT/results.tsv"
FAILED=0
run_step() {
  local label=$1; shift
  local status=0
  printf '$ %s\n' "$*" > "$REPORT/$label.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$label.log" 2>&1 || status=$?
  printf '%s\t%s\n' "$label" "$status" >> "$REPORT/results.tsv"
  if (( status != 0 )); then FAILED=$((FAILED + 1)); fi
  printf '%s: exit=%s\n' "$label" "$status" >&2
}
run_step python_dependencies python3 -c 'import msgpack, cryptography; print("independent v2 signature libraries available")'
run_step offline_unittests python3 -B -m unittest discover -s scripts/unyt -p 'test_*.py' -v
run_step rust_fmt cargo fmt --all -- --check
run_step rust_harness cargo test -p unyt_harness --locked -- --nocapture
run_step workspace_tests cargo test --workspace --locked
run_step workspace_clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run_step harness_clippy cargo clippy -p unyt_harness --tests --locked -- -D warnings
AUDIT_RC=0
(cd "$ROOT" && python3 -B scripts/unyt/sprint26_audit_run.py --report "$REPORT") \
  > "$REPORT/audit.json" 2> "$REPORT/audit-errors.log" || AUDIT_RC=$?
printf 'audit\t%s\n' "$AUDIT_RC" >> "$REPORT/results.tsv"
if (( AUDIT_RC != 0 )); then FAILED=$((FAILED + 1)); fi
{
  echo "utc_finished=$(date -u +%FT%TZ)"
  echo "failed_stages=$FAILED"
} >> "$REPORT/provenance.txt"
(
  cd "$REPORT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
cat "$REPORT/audit.json"
echo "Sprint 26 OFFLINE report: $REPORT (failed steps: $FAILED)" >&2
(( FAILED == 0 ))
