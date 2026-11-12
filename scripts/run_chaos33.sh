#!/usr/bin/env bash
# Sprint 33 immutable exact-SHA three-conductor baseline and opt-in fork lab.
# Separate SIGKILL / netns labs are opt-in and never implied by this runner.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
  cat <<'HELP'
Usage: bash scripts/run_chaos33.sh --expected-sha SHA --signed-report-dir /absolute/signed-quorum-report --ack-public-test-keys [--full --allow-same-key-fork-lab]

First run HC_VTIME_EXPECTED_SHA=... bash scripts/run_signed_quorum.sh on
the exact same SHA. Its report contains signed TEST-ONLY vtime.dna + provenance.
Default performs real signed delayed-DHT recovery tests, previous resilience and
restart baselines. --full adds the destructive same-test-key fork/warrant lab.
Unclean SIGKILL and genuine transport partitions require separate opt-in labs.
NEVER run with production keys, live app data or funds.
HELP
}
EXPECTED=""
SIGNED=""
ACK=0
FULL=0
FORK=0
while (( $# )); do
  case "$1" in
    --expected-sha) (( $# >= 2 )) || { usage >&2; exit 2; }; EXPECTED=$2; shift 2;;
    --signed-report-dir) (( $# >= 2 )) || { usage >&2; exit 2; }; SIGNED=$2; shift 2;;
    --ack-public-test-keys) ACK=1; shift;;
    --full) FULL=1; shift;;
    --allow-same-key-fork-lab) FORK=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
[[ -n "$EXPECTED" && "$SIGNED" = /* && "$ACK" -eq 1 ]] || {
  echo 'BLOCKED: exact SHA, absolute signed report and explicit test-key acknowledgement required' >&2; exit 2
}
if (( FULL != FORK )); then
  echo 'BLOCKED: --full and --allow-same-key-fork-lab must be used together' >&2; exit 2
fi
for exe in git cargo rustc python3 sha256sum; do
  command -v "$exe" >/dev/null || { echo "BLOCKED: missing $exe" >&2; exit 2; }
done
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SHA" == "$EXPECTED" && "$EXPECTED" =~ ^[a-f0-9]{40}$ ]] || {
  echo 'BLOCKED: exact current Git SHA mismatch' >&2; exit 4
}
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo 'BLOCKED: dirty checkout. Run from a clean exact-commit tree' >&2; exit 4
}
[[ -s "$SIGNED/vtime.dna" && -s "$SIGNED/provenance.txt" ]] || {
  echo 'BLOCKED: missing signed-test-only DNA/provenance report' >&2; exit 4
}
grep -Fqx "git_sha=$SHA" "$SIGNED/provenance.txt" || {
  echo 'BLOCKED: signed DNA built for another SHA or no provenance' >&2; exit 4
}
DNA_HASH=$(sha256sum "$SIGNED/vtime.dna" | cut -d' ' -f1)
grep -Fqx "packed_dna_sha256=$DNA_HASH" "$SIGNED/provenance.txt" || {
  echo 'BLOCKED: DNA checksum mismatch against signed test manifest' >&2; exit 4
}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$(dirname "$ROOT")/hc-vtime-sprint33-${SHA:0:12}-$STAMP-$$"
mkdir -p "$REPORT"
export HC_VTIME_SIGNED_TEST_ONLY=1
export HC_VTIME_TEST_DNA="$SIGNED/vtime.dna"
export PYTHONDONTWRITEBYTECODE=1
{
  echo "git_sha=$SHA"
  echo "mode=$([[ "$FULL" -eq 1 ]] && echo full_same_key_fork || echo baseline)"
  echo "utc_started=$(date -u +%FT%TZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "workspace_lock_sha256=$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  echo "conductor_lock_sha256=$(sha256sum "$ROOT/integration/conductor/Cargo.lock" | cut -d' ' -f1)"
  echo "signed_dna_sha256=$DNA_HASH"
  echo "test_only_signers=true"
  echo "physical_network_partition_proven=false"
  echo "unclean_sigkill_proven=false"
  echo "db_corruption_recovery_proven=false"
  echo "release_approved=false"
} > "$REPORT/provenance.txt"
printf 'step\texit_code\n' > "$REPORT/results.tsv"
FAILURES=0
finish() {
  local rc=$?
  trap - EXIT
  echo "shell_exit_code=$rc" >> "$REPORT/provenance.txt"
  echo "utc_completed=$(date -u +%FT%TZ)" >> "$REPORT/provenance.txt"
  ( cd "$REPORT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS ) || true
  echo "Sprint 33 evidence: $REPORT (shell exit=$rc; failed steps=$FAILURES)" >&2
}
trap finish EXIT
run_step() {
  local label=$1; shift
  local code=0
  printf '$ %s\n' "$*" > "$REPORT/$label.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$label.log" 2>&1 || code=$?
  printf '%s\t%s\n' "$label" "$code" >> "$REPORT/results.tsv"
  if (( code != 0 )); then FAILURES=$((FAILURES + 1)); fi
  printf 'Sprint 33 %s => exit %s\n' "$label" "$code" >&2
}
run_step python_negative python3 -B -m unittest discover -s scripts -p 'test_chaos33*.py' -v
run_step python_audit_negative python3 -B -m unittest scripts.test_audit_chaos33 -v
run_step workspace_fmt cargo fmt --all -- --check
run_step conductor_fmt cargo fmt --manifest-path integration/conductor/Cargo.toml -- --check
run_step workspace_tests cargo test --workspace --locked
run_step workspace_clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run_step conductor_clippy cargo clippy --manifest-path integration/conductor/Cargo.toml --all-targets --locked -- -D warnings
run_step wasm_build env 'RUSTFLAGS=--cfg getrandom_backend="custom" -C link-arg=--import-undefined' \
  cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime
run_step conductor_chaos cargo test --manifest-path integration/conductor/Cargo.toml \
  --locked --test chaos_recovery -- --nocapture --test-threads=1
run_step fork_baseline cargo test --manifest-path integration/conductor/Cargo.toml --locked \
  --test fork_recovery real_three_conductor_restart_preserves_signed_witnesses_without_false_clearance \
  -- --exact --nocapture --test-threads=1
run_step prior_resilience cargo test --manifest-path integration/conductor/Cargo.toml --locked \
  --test resilience -- --nocapture --test-threads=1
if (( FULL )); then
  run_step fork_injected cargo test --manifest-path integration/conductor/Cargo.toml --locked \
    --test fork_recovery real_same_agent_fork_issues_and_persists_warrant_across_observer_restart \
    -- --ignored --exact --nocapture --test-threads=1
fi
AUDIT=(python3 -B scripts/audit_chaos33.py --report "$REPORT")
if (( FULL )); then AUDIT+=(--require-fork); fi
AUDIT_CODE=0
(cd "$ROOT" && "${AUDIT[@]}") > "$REPORT/audit.json" 2> "$REPORT/audit-stderr.log" || AUDIT_CODE=$?
printf 'audit\t%s\n' "$AUDIT_CODE" >> "$REPORT/results.tsv"
if (( AUDIT_CODE != 0 )); then FAILURES=$((FAILURES + 1)); fi
cat "$REPORT/audit.json" >&2
(( FAILURES == 0 ))
