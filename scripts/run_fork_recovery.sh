#!/usr/bin/env bash
# Sprint 22, real signed test-only conductors. Never run on a deployed DNA.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
  cat <<'EOF'
Usage: bash scripts/run_fork_recovery.sh --expected-sha SHA --dna /abs/test-only/vtime.dna --ack-public-test-keys [--full --allow-same-key-fork-lab]

Default: signed three-conductor restart, previous Sprint 12 resilience, Rust
        classifier, workspace tests and Clippy. Reports BASELINE ONLY.
--full:  opt-in SAME-AGENT test-only double-conductor fork; assert actual
         integrated DHT warrant, preserved across observer restart.
Never point the fork lab at a production DNA, a real oracle key or deployed app.
EOF
}
EXPECTED=""
DNA=""
ACK=0
FULL=0
FORK_ACK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-sha) [[ $# -ge 2 ]] || { usage; exit 2; }; EXPECTED=$2; shift 2 ;;
    --dna) [[ $# -ge 2 ]] || { usage; exit 2; }; DNA=$2; shift 2 ;;
    --ack-public-test-keys) ACK=1; shift ;;
    --full) FULL=1; shift ;;
    --allow-same-key-fork-lab) FORK_ACK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$EXPECTED" && "$ACK" -eq 1 && -n "$DNA" ]] || {
  echo 'BLOCKED: exact SHA, signed test DNA and explicit public-fixture acknowledgement required' >&2
  usage >&2
  exit 2
}
if (( FULL && !FORK_ACK )); then
  echo 'BLOCKED: --full requires --allow-same-key-fork-lab' >&2; exit 2
fi
if (( !FULL && FORK_ACK )); then
  echo 'BLOCKED: fork acknowledgement requires --full' >&2; exit 2
fi
for exe in git cargo rustc python3 sha256sum; do
  command -v "$exe" >/dev/null || { echo "BLOCKED: missing $exe" >&2; exit 2; }
done
[[ -s "$DNA" ]] || { echo 'BLOCKED: signed test DNA does not exist' >&2; exit 2; }
DNA=$(cd "$(dirname "$DNA")" && pwd)/$(basename "$DNA")
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SHA" == "$EXPECTED" ]] || { echo "BLOCKED: SHA mismatch $SHA != $EXPECTED" >&2; exit 4; }
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "BLOCKED: dirty working tree; test the exact reviewed commit" >&2; exit 4
}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$(dirname "$ROOT")/hc-vtime-fork-recovery-${SHA:0:12}-$STAMP-$$"
mkdir -p "$REPORT"
export HC_VTIME_SIGNED_TEST_ONLY=1
export HC_VTIME_TEST_DNA="$DNA"
export PYTHONDONTWRITEBYTECODE=1
{
  printf 'git_sha=%s\n' "$SHA"
  printf 'utc_started=%s\n' "$(date -u +%FT%TZ)"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'python=%s\n' "$(python3 --version 2>&1)"
  printf 'workspace_lock_sha256=%s\n' "$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  printf 'conductor_lock_sha256=%s\n' "$(sha256sum "$ROOT/integration/conductor/Cargo.lock" | cut -d' ' -f1)"
  printf 'test_dna_sha256=%s\n' "$(sha256sum "$DNA" | cut -d' ' -f1)"
  printf 'fixture_keys_public=true\n'
  printf 'physical_network_partition_proven=false\n'
  printf 'unclean_crash_recovery_proven=false\n'
  printf 'real_world_operator_independence_proven=false\n'
  printf 'mode=%s\n' "$([[ "$FULL" == 1 ]] && echo warrant_fork_full || echo baseline_only)"
  printf 'release_approved=false\n'
} > "$REPORT/provenance.txt"
printf 'step\texit_code\n' > "$REPORT/results.tsv"
FAILURES=0
run_step() {
  local label=$1; shift
  local status=0
  printf '$ %s\n' "$*" > "$REPORT/$label.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$label.log" 2>&1 || status=$?
  printf '%s\t%s\n' "$label" "$status" >> "$REPORT/results.tsv"
  if (( status != 0 )); then FAILURES=$((FAILURES + 1)); fi
  printf 'Step %s: exit=%s\n' "$label" "$status" >&2
}
run_step python_audit_units python3 -B -m unittest scripts.test_audit_fork_recovery -v
run_step rust_fmt cargo fmt --all -- --check
run_step fixture_unit cargo test --manifest-path integration/conductor/Cargo.toml \
  --locked --lib fork_recovery -- --nocapture
run_step fork_baseline cargo test --manifest-path integration/conductor/Cargo.toml \
  --locked --test fork_recovery \
  real_three_conductor_restart_preserves_signed_witnesses_without_false_clearance \
  -- --exact --nocapture --test-threads=1
run_step prior_resilience cargo test --manifest-path integration/conductor/Cargo.toml \
  --locked --test resilience -- --nocapture --test-threads=1
run_step workspace_tests cargo test --workspace --locked
run_step clippy cargo clippy --workspace --all-targets --locked -- -D warnings
if (( FULL )); then
  run_step fork_injected cargo test --manifest-path integration/conductor/Cargo.toml \
    --locked --test fork_recovery \
    real_same_agent_fork_issues_and_persists_warrant_across_observer_restart \
    -- --ignored --exact --nocapture --test-threads=1
fi
auditor=(python3 -B scripts/audit_fork_recovery.py --report "$REPORT")
if (( FULL )); then auditor+=(--require-fork); fi
auditor_rc=0
(cd "$ROOT" && "${auditor[@]}") > "$REPORT/audit.json" 2> "$REPORT/audit-errors.log" || auditor_rc=$?
printf 'audit\t%s\n' "$auditor_rc" >> "$REPORT/results.tsv"
if (( auditor_rc != 0 )); then FAILURES=$((FAILURES + 1)); fi
cat "$REPORT/audit.json" >&2
{
  printf 'failure_count=%s\n' "$FAILURES"
  printf 'utc_completed=%s\n' "$(date -u +%FT%TZ)"
} >> "$REPORT/provenance.txt"
(
  cd "$REPORT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
echo "Fork/recovery report: $REPORT (failed steps: $FAILURES)" >&2
(( FAILURES == 0 ))
