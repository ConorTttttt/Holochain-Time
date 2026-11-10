#!/usr/bin/env bash
# Sprint 31: real 10,240-link DHT spam in three test-only Holochain conductors.
# Creates disposable DNA in a detached worktree; never modifies sprint refs.
set -euo pipefail
if [[ "$#" -eq 1 && "$1" == --help ]]; then
  echo 'Usage: HC_VTIME_EXPECTED_SHA=$(git rev-parse HEAD) bash scripts/run_signed_quorum.sh'
  echo 'Requires Holonix 0.7, Rust, wasm32-unknown-unknown, hc, Python and Git.'
  exit 0
fi
[[ "$#" -eq 0 ]] || { echo 'BLOCKED: unknown argument' >&2; exit 2; }
for cmd in git cargo rustc python3 hc sha256sum tee; do
  command -v "$cmd" >/dev/null || { echo "BLOCKED: missing $cmd" >&2; exit 2; }
done
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SHA=$(git -C "$ROOT" rev-parse --verify HEAD)
EXPECTED=$(printenv HC_VTIME_EXPECTED_SHA || true)
[[ -z "$EXPECTED" || "$SHA" == "$EXPECTED" ]] || {
  echo 'BLOCKED: wrong commit SHA' >&2; exit 4;
}
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo 'BLOCKED: dirty worktree; test a clean exact-commit checkout' >&2; exit 4;
}
[[ -f "$ROOT/dnas/vtime/workdir/dna.yaml" ]] || {
  echo 'BLOCKED: DNA template not found' >&2; exit 2;
}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SHORT=$(printf '%.12s' "$SHA")
# Sprint 17 can collect this runner's artifacts in a single parent report.
# Never overwrite an older run, and keep all evidence outside source control.
REPORT="${HC_VTIME_SIGNED_REPORT_DIR:-$(dirname "$ROOT")/hc-vtime-sprint31-dht-spam-$SHORT-$STAMP-$BASHPID}"
[[ "$REPORT" = /* && ! -e "$REPORT" ]] || {
  echo 'BLOCKED: signed report directory must be an unused absolute path' >&2; exit 4;
}
case "$REPORT/" in "$ROOT/"*) echo 'BLOCKED: report must be outside checkout' >&2; exit 4;; esac
mkdir -p "$REPORT"
TEMP=$(mktemp -d "/tmp/vtime-quorum-XXXXXXXX")
rmdir "$TEMP"
finish() {
  rc=$?
  trap - EXIT
  echo "exit_code=$rc" >> "$REPORT/provenance.txt"
  (cd "$REPORT" && sha256sum provenance.txt *.log keys-public.json dna.yaml vtime.dna dht-spam-metrics.json > SHA256SUMS 2>/dev/null) || true
  git -C "$ROOT" worktree remove --force "$TEMP" >/dev/null 2>&1 || true
  echo "Evidence directory: $REPORT (exit $rc)" >&2
}
trap finish EXIT
{
  echo "git_sha=$SHA"
  echo "utc_started=$(date -u +%FT%TZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "hc=$(hc --version 2>&1 | tail -1)"
  echo "holochain=$(holochain --version 2>&1 | head -1)"
  echo 'conductor_library=holochain 0.7.1 (locked standalone harness)'
  echo "workspace_lock_sha256=$(sha256sum "$ROOT/Cargo.lock" | cut -d' ' -f1)"
  echo 'scope=real-conductor 10240 validated DHT links, not global completeness or production acceptance'
  echo 'operator_independence_proven=false'
} > "$REPORT/provenance.txt"
(
  cd "$ROOT"
  RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--import-undefined' \
    cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime --features vtime/dht-spam-test-only
) 2>&1 | tee "$REPORT/wasm-build.log"
echo "integrity_wasm_sha256=$(sha256sum "$ROOT/target/wasm32-unknown-unknown/release/vtime_integrity.wasm" | cut -d' ' -f1)" >> "$REPORT/provenance.txt"
echo "coordinator_wasm_sha256=$(sha256sum "$ROOT/target/wasm32-unknown-unknown/release/vtime.wasm" | cut -d' ' -f1)" >> "$REPORT/provenance.txt"
git -C "$ROOT" worktree add --quiet --detach "$TEMP" "$SHA"
ln -s "$ROOT/target" "$TEMP/target"
cargo run --manifest-path "$ROOT/integration/conductor/Cargo.toml" \
  --locked --target-dir "${HC_VTIME_CONDUCTOR_TARGET_DIR:-$ROOT/integration/conductor/target}" \
  --bin signed_test_keys --quiet > "$REPORT/keys-public.json" 2> "$REPORT/keys-build.log"
python3 "$TEMP/scripts/make_signed_test_manifest.py" \
  --template "$TEMP/dnas/vtime/workdir/dna.yaml" \
  --fixture-json "$REPORT/keys-public.json" \
  --out "$TEMP/dnas/vtime/workdir/dna.yaml" 2>&1 | tee "$REPORT/manifest-generation.log"
python3 "$TEMP/scripts/check_test_dna_config.py" \
  --manifest "$TEMP/dnas/vtime/workdir/dna.yaml" 2>&1 | tee "$REPORT/dna-preflight.log"
echo "manifest_sha256=$(sha256sum "$TEMP/dnas/vtime/workdir/dna.yaml" | cut -d' ' -f1)" >> "$REPORT/provenance.txt"
(cd "$TEMP" && hc dna pack dnas/vtime/workdir) 2>&1 | tee "$REPORT/dna-pack.log"
TEST_DNA="$TEMP/dnas/vtime/workdir/vtime.dna"
[[ -s "$TEST_DNA" ]] || { echo 'BLOCKED: packed test DNA missing' >&2; exit 4; }
echo "packed_dna_sha256=$(sha256sum "$TEST_DNA" | cut -d' ' -f1)" >> "$REPORT/provenance.txt"
cp "$TEST_DNA" "$REPORT/vtime.dna"
cp "$TEMP/dnas/vtime/workdir/dna.yaml" "$REPORT/dna.yaml"
if [[ -f "$TEMP/integration/conductor/Cargo.lock" ]]; then
  echo "conductor_lock_sha256=$(sha256sum "$TEMP/integration/conductor/Cargo.lock" | cut -d' ' -f1)" >> "$REPORT/provenance.txt"
fi
export HC_VTIME_TEST_DNA="$TEST_DNA"
export HC_VTIME_SIGNED_TEST_ONLY=1
export HC_VTIME_DHT_SPAM_TEST_ONLY=1
signed_status=0
cargo test --manifest-path "$ROOT/integration/conductor/Cargo.toml" \
  --locked --target-dir "${HC_VTIME_CONDUCTOR_TARGET_DIR:-$ROOT/integration/conductor/target}" \
  --test signed_quorum -- --nocapture 2>&1 | tee "$REPORT/signed-quorum.log" || signed_status=$?
echo "signed_quorum_command_exit=$signed_status" >> "$REPORT/provenance.txt"
smoke_status=0
cargo test --manifest-path "$ROOT/integration/conductor/Cargo.toml" \
  --locked --target-dir "${HC_VTIME_CONDUCTOR_TARGET_DIR:-$ROOT/integration/conductor/target}" \
  --test smoke -- --nocapture 2>&1 | tee "$REPORT/conductor-smoke.log" || smoke_status=$?
echo "conductor_smoke_command_exit=$smoke_status" >> "$REPORT/provenance.txt"
spam_status=0
cargo test --manifest-path "$ROOT/integration/conductor/Cargo.toml" \
  --locked --target-dir "${HC_VTIME_CONDUCTOR_TARGET_DIR:-$ROOT/integration/conductor/target}" \
  --test dht_spam -- --ignored --exact spammed_link_indexes_do_not_change_explicit_witnesses \
  --nocapture --test-threads=1 2>&1 | tee "$REPORT/dht-spam.log" || spam_status=$?
echo "dht_spam_command_exit=$spam_status" >> "$REPORT/provenance.txt"
if [[ "$spam_status" -eq 0 ]]; then
  python3 - "$REPORT/dht-spam.log" "$REPORT/dht-spam-metrics.json" <<'PY'
import json
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
marker = "HC_SPRINT31_DHT_SPAM "
found = [json.loads(line.split(marker, 1)[1]) for line in lines if marker in line]
assert len(found) == 1, "exactly one real conductor metrics record required"
data = found[0]
assert data["actual_conductor"] is True and data["links_inserted"] >= 10000
assert data["verified_requests"] == 128 and data["all_valid_proofs_preserved"] is True
assert data["over_budget_rejected"] is True and data["legacy_global_query_rejected"] is True
assert data["evidence_complete"] is False and data["production_release_ready"] is False
pathlib.Path(sys.argv[2]).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
PY
fi
[[ "$signed_status" -eq 0 && "$smoke_status" -eq 0 && "$spam_status" -eq 0 ]]
