#!/usr/bin/env bash
# Test hc-vtime sprint heads in detached worktrees; no merges or deployments.
set -euo pipefail
usage() {
cat <<'HELP'
Usage: bash scripts/test_sprints_local.sh [--sprint 1..6 | --all | --current] [--native-only] [--pack]
  --sprint N     Test original Sprint N remote branch in a detached worktree
  --all          Test all six original sprint branches sequentially
  --current      Test checked-out cumulative code (default)
  --native-only  Skip WASM compilation
  --pack         Also attempt DNA/hApp pack; reject placeholder keys
Results and logs: test-reports/local-<timestamp>/. No merge/deploy is performed.
HELP
}
MODE=current; SPRINT=; NATIVE_ONLY=0; PACK=0
while (($#)); do
 case "$1" in
  --sprint) [[ $# -ge 2 ]] || { echo 'Missing sprint number' >&2; exit 2; }; MODE=one; SPRINT="$2"; shift 2;;
  --all) MODE=all; shift;;
  --current) MODE=current; shift;;
  --native-only) NATIVE_ONLY=1; shift;;
  --pack) PACK=1; shift;;
  -h|--help) usage; exit 0;;
  *) echo "Unknown argument: $1" >&2; usage >&2; exit 2;;
 esac
done
if [[ "$MODE" == one && ! "$SPRINT" =~ ^[1-6]$ ]]; then
 echo 'Choose --sprint 1 through 6' >&2; exit 2
fi
if ((NATIVE_ONLY && PACK)); then echo '--pack requires WASM; remove --native-only' >&2; exit 2; fi
for cmd in git cargo rustc rustfmt; do
 if ! command -v "$cmd" >/dev/null 2>&1; then
  echo "BLOCKED: missing $cmd. Use a Holochain 0.7 Holonix development shell." >&2
  echo 'nix develop "github:holochain/holonix?ref=main-0.7"' >&2
  exit 2
 fi
done
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo 'Run inside a Git clone of Holochain-Time' >&2; exit 2; }
[[ -f "$ROOT/Cargo.lock" && -f "$ROOT/SPRINT_06.md" ]] || { echo 'Missing expected source. Checkout Sprint 7 test branch' >&2; exit 2; }
report="$ROOT/test-reports/local-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$report"
{
 printf 'date=%s\n' "$(date -u +%FT%TZ)"
 printf 'host=%s\n' "$(uname -a)"
 printf 'checkout=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
 cargo --version; rustc --version --verbose
 if command -v rustup >/dev/null; then rustup target list --installed; fi
 if command -v hc >/dev/null; then hc --version || true; fi
 if command -v holochain >/dev/null; then holochain --version || true; fi
} > "$report/environment.txt" 2>&1
printf 'sprint\tsha\tcheck\tstatus\tlog\n' > "$report/results.tsv"
echo "Report directory: $report"
export CARGO_TARGET_DIR="$ROOT/target"
branches=(
 'sprint/01-foundation-evidence-2026-11-09'
 'sprint/02-proof-witness-api-2026-11-09'
 'sprint/03-roughtime-packet-budgets-2026-11-09'
 'sprint/04-disable-unsafe-index-2026-11-09'
 'sprint/05-roughtime-first-quorum-2026-11-09'
 'sprint/06-oracle-batch-commitments-2026-11-09'
)
failed=0
created=()
cleanup() {
 local path
 for path in "${created[@]}"; do
  git -C "$ROOT" worktree remove --force "$path" >/dev/null 2>&1 || true
 done
}
trap cleanup EXIT
step() {
 local check="$1"; shift
 local logfile="$section/$check.log" state=PASS
 if ( cd "$checkout" && "$@" ) > "$logfile" 2>&1; then
  printf '[PASS] %-7s %s\n' "$sprint_label" "$check"
 else
  state=FAIL; failed=$((failed+1))
  printf '[FAIL] %-7s %s\n' "$sprint_label" "$check" >&2
  tail -n 14 "$logfile" >&2
 fi
 printf '%s\t%s\t%s\t%s\t%s\n' "$sprint_label" "$sha" "$check" "$state" "$logfile" >> "$report/results.tsv"
}
run_sprint() {
 sprint_label="$1"; checkout="$2"
 sha=$(git -C "$checkout" rev-parse HEAD)
 section="$report/sprint-$sprint_label"
 mkdir -p "$section"
 git -C "$checkout" status --short > "$section/git-status.txt"
 echo "--- Testing $sprint_label at $sha ---"
 step fmt cargo fmt --all -- --check
 step native cargo test --workspace --locked
 step clippy cargo clippy --workspace --all-targets --locked -- -D warnings
 case "$sprint_label" in
  1) step evidence-policy cargo test -p vtime_core --test evidence_policy --locked;;
  2|4) step coordinator cargo test -p vtime --lib --locked;;
  3) step roughtime cargo test -p vtime_core --test roughenough_interop --locked;;
  5) step evidence-policy cargo test -p vtime_core --test evidence_policy --locked;;
  6) step merkle-batch cargo test -p vtime_core batch::tests --locked;;
 esac
 if (( ! NATIVE_ONLY )); then
  step wasm env RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--import-undefined' \
    cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime
 fi
 if ((PACK)); then
  if ! command -v hc >/dev/null 2>&1; then
   echo 'BLOCKED: hc CLI missing' > "$section/pack.log"
   failed=$((failed+1))
   printf '%s\t%s\tpack\tBLOCKED\t%s\n' "$sprint_label" "$sha" "$section/pack.log" >> "$report/results.tsv"
  elif grep -q REPLACE_WITH "$checkout/dnas/vtime/workdir/dna.yaml"; then
   echo 'BLOCKED: DNA has placeholder keys; use verified test-only public keys' > "$section/pack.log"
   failed=$((failed+1))
   printf '%s\t%s\tpack\tBLOCKED\t%s\n' "$sprint_label" "$sha" "$section/pack.log" >> "$report/results.tsv"
  else
   step dna-pack hc dna pack dnas/vtime/workdir
   step happ-pack hc app pack workdir
  fi
 fi
}
if [[ "$MODE" == current ]]; then
 run_sprint current "$ROOT"
else
 if [[ "$MODE" == all ]]; then selected=(1 2 3 4 5 6); else selected=("$SPRINT"); fi
 for num in "${selected[@]}"; do
  branch="${branches[num-1]}"
  if ! git -C "$ROOT" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
   echo "BLOCKED: origin/$branch absent. Run git fetch origin." >&2
   failed=$((failed+1)); continue
  fi
  checkout=$(mktemp -d "${TMPDIR:-/tmp}/hc-vtime-sprint-$num-XXXXXXXX")
  rmdir "$checkout"
  git -C "$ROOT" worktree add --quiet --detach "$checkout" "refs/remotes/origin/$branch"
  created+=("$checkout")
  run_sprint "$num" "$checkout"
  git -C "$ROOT" worktree remove --force "$checkout"
  created=()
 done
fi
printf '\nFailures: %s | Results: %s/results.tsv\n' "$failed" "$report"
(( failed == 0 ))
