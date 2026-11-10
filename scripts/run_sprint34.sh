#!/usr/bin/env bash
# Sprint 34 exact-commit offline acceptance: NO production runtime deployment.
set -euo pipefail
usage() {
  cat <<'HELP'
Usage: HC_VTIME_EXPECTED_SHA=$(git rev-parse HEAD) bash scripts/run_sprint34.sh
Runs stdlib Python auth tests, inherited Sprint 25 regressions and an injected
incident exercise. Produces an external SHA-bound report; no live runtime proof.
For real alerting, use the approved verified source probe and deployed producers.
HELP
}
[[ $# -eq 0 ]] || { [[ $# -eq 1 && "$1" == "--help" ]] && { usage; exit 0; }; usage >&2; exit 2; }
for exe in git python3 bash sha256sum; do
  command -v "$exe" >/dev/null || { echo "BLOCKED: missing $exe" >&2; exit 2; }
done
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHA="$(git -C "$ROOT" rev-parse --verify HEAD)"
EXPECTED="${HC_VTIME_EXPECTED_SHA:-}"
[[ "$EXPECTED" =~ ^[0-9a-f]{40}$ && "$SHA" == "$EXPECTED" ]] || {
  echo 'BLOCKED: full exact HEAD SHA required' >&2; exit 4
}
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo 'BLOCKED: dirty checkout' >&2; exit 4
}
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${HC_VTIME_SPRINT34_REPORT_DIR:-$(dirname "$ROOT")/hc-vtime-sprint34-${SHA:0:12}-$STAMP-$$}"
[[ "$REPORT" = /* && ! -e "$REPORT" ]] || {
  echo 'BLOCKED: report must be new absolute path' >&2; exit 4
}
case "$REPORT/" in "$ROOT/"*) echo 'BLOCKED: report must be outside checkout' >&2; exit 4;; esac
mkdir -m 0700 -p "$REPORT"
chmod 0700 "$REPORT"
export PYTHONDONTWRITEBYTECODE=1
{
  echo "git_sha=$SHA"
  echo "started_utc=$(date -u +%FT%TZ)"
  echo "python=$(python3 --version 2>&1)"
  echo "mode=injected_test_only"
  echo "actual_runtime_events_wired=false"
  echo "operator_independence_proven=false"
  echo "real_warrant_verified=false"
  echo "release_ready=false"
} > "$REPORT/provenance.txt"
printf 'step\texit_code\n' > "$REPORT/results.tsv"
FAILURES=0
finish() {
  local exit_code=$?
  trap - EXIT
  echo "completed_utc=$(date -u +%FT%TZ)" >> "$REPORT/provenance.txt"
  echo "shell_exit_code=$exit_code" >> "$REPORT/provenance.txt"
  (cd "$REPORT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS) || true
  echo "Sprint 34 injected-only report: $REPORT (shell status=$exit_code)" >&2
}
trap finish EXIT
run_step() {
  local label=$1; shift
  local status=0
  printf '$ %s\n' "$*" > "$REPORT/$label.log"
  (cd "$ROOT" && "$@") >> "$REPORT/$label.log" 2>&1 || status=$?
  printf '%s\t%d\n' "$label" "$status" >> "$REPORT/results.tsv"
  if (( status != 0 )); then FAILURES=$((FAILURES + 1)); fi
  echo "$label: exit=$status" >&2
}
run_step negative_tests python3 -B -m unittest scripts.test_ops34 -v
run_step sprint25_regressions python3 -B -m unittest scripts.test_ops_monitoring -v
run_step shell_syntax bash -n scripts/run_sprint34.sh
run_step incident_drill python3 -B -m scripts.ops34.drill --report-dir "$REPORT/drill"
AUDIT_CODE=0
(cd "$ROOT" && python3 -B scripts/audit_ops34.py --report "$REPORT") > "$REPORT/audit.json" 2> "$REPORT/audit-errors.log" || AUDIT_CODE=$?
printf 'audit\t%d\n' "$AUDIT_CODE" >> "$REPORT/results.tsv"
cat "$REPORT/audit.json" >&2
(( AUDIT_CODE == 0 && FAILURES == 0 ))
