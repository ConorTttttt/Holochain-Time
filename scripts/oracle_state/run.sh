#!/usr/bin/env bash
# Sprint 24 native persistence acceptance. Process-crash tests SIGKILL only
# disposable test processes using PUBLIC test seed; no production oracle.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
usage() {
  echo "Usage: bash scripts/oracle_state/run.sh --expected-sha <40-hex-git-sha>"
  echo "Requires clean Unix checkout, Rust/Cargo, rustfmt, Clippy and Python 3."
}
EXPECTED=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-sha) [[ $# -ge 2 ]] || { usage; exit 2; }; EXPECTED=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$EXPECTED" =~ ^[a-f0-9]{40}$ ]] || { usage >&2; exit 2; }
for exe in git cargo rustc python3 sha256sum uname; do
  command -v "$exe" >/dev/null || { echo "BLOCKED: missing $exe" >&2; exit 3; }
done
[[ "$(uname -s)" == Linux || "$(uname -s)" == Darwin ]] || {
  echo "BLOCKED: journal requires a Unix filesystem with durable directory fsync" >&2; exit 3
}
SHA=$(git -C "$ROOT" rev-parse HEAD)
[[ "$SHA" == "$EXPECTED" ]] || { echo "BLOCKED: wrong commit $SHA" >&2; exit 4; }
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "BLOCKED: dirty working tree" >&2; exit 4
}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SHORT_SHA=$(printf '%.12s' "$SHA")
REPORT="$(dirname "$ROOT")/hc-vtime-oracle-s24-$SHORT_SHA-$STAMP-$$"
mkdir -p "$REPORT"
export PYTHONDONTWRITEBYTECODE=1
# Disable child-process crash core dumps; process_crash tests intentionally
# kill only the disposable oracle_crash_worker subprocess.
ulimit -c 0 || true
{
  echo "git_sha=$SHA"
  echo "utc_started=$(date -u +%FT%TZ)"
  echo "os=$(uname -s)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "python=$(python3 --version 2>&1)"
  echo "workspace_lock_sha256=$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  echo "signer_keys=test_seed_only"
  echo "signing_runtime_integrated=false"
  echo "external_rollback_protection_proven=false"
  echo "real_conductor_acceptance_proven=false"
  echo "release_ready=false"
} > "$REPORT/provenance.txt"
printf 'stage\texit_code\n' > "$REPORT/results.tsv"
FAILURES=0
run_step() {
  local name=$1; shift
  local status=0
  printf '$ %s\n' "$*" > "$REPORT/$name.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$name.log" 2>&1 || status=$?
  printf '%s\t%s\n' "$name" "$status" >> "$REPORT/results.tsv"
  if (( status != 0 )); then FAILURES=$((FAILURES + 1)); fi
  printf '%s: exit=%s\n' "$name" "$status" >&2
}
run_step reporter_tests python3 -B -m unittest discover -s scripts/oracle_state -p 'test_*.py' -v
run_step rust_fmt cargo fmt --all -- --check
run_step restart_safety cargo test -p vtime_oracle_state --locked --test restart_safety -- --nocapture
run_step process_crash cargo test -p vtime_oracle_state --locked --test process_crash -- --nocapture --test-threads=1
run_step backup_migration cargo test -p vtime_oracle_state --locked --test backup_migration -- --nocapture
run_step crate_clippy cargo clippy -p vtime_oracle_state --all-targets --locked -- -D warnings
run_step workspace_tests cargo test --workspace --locked
run_step workspace_clippy cargo clippy --workspace --all-targets --locked -- -D warnings
AUDIT_RESULT=0
(cd "$ROOT" && python3 -B scripts/oracle_state/audit.py --report "$REPORT") \
  > "$REPORT/audit.json" 2> "$REPORT/audit-errors.log" || AUDIT_RESULT=$?
printf 'audit\t%s\n' "$AUDIT_RESULT" >> "$REPORT/results.tsv"
if (( AUDIT_RESULT != 0 )); then FAILURES=$((FAILURES + 1)); fi
{
  echo "failed_stages=$FAILURES"
  echo "utc_completed=$(date -u +%FT%TZ)"
} >> "$REPORT/provenance.txt"
(
  cd "$REPORT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
cat "$REPORT/audit.json"
echo "Sprint 24 evidence: $REPORT (failed stages: $FAILURES)" >&2
(( FAILURES == 0 ))
