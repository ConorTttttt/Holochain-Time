#!/usr/bin/env bash
# Reproduce native Rust/Clippy/WASM verification on an exact, clean commit.
# This does NOT run Holochain conductor or Unyt integration tests.
set -euo pipefail
cd "$(dirname "$0")/.."

for bin in git cargo rustc rustup sha256sum tee; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing $bin. Use a compatible Rust/Holochain 0.7 (Holonix) shell." >&2
    exit 2
  fi
done

commit="$(git rev-parse HEAD)"
expected="$(printenv HC_VTIME_EXPECTED_SHA || true)"
if [[ -n "$expected" && "$commit" != "$expected" ]]; then
  echo "Commit $commit does not match expected $expected" >&2
  exit 4
fi
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo 'Refusing to certify dirty worktree. Commit all source changes first.' >&2
  exit 4
fi
if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
  echo 'Missing target: rustup target add wasm32-unknown-unknown' >&2
  exit 2
fi

short="$(printf '%.12s' "$commit")"
report_dir="$(printenv HC_VTIME_VERIFICATION_DIR || true)"
if [[ -z "$report_dir" ]]; then
  report_dir="$(pwd)/../hc-vtime-verification-$short"
fi
mkdir -p "$report_dir"
report_dir="$(cd "$report_dir" && pwd)"
if [[ "$report_dir/" == "$(pwd)/"* ]]; then
  echo 'Report directory must be outside the Git repository.' >&2
  exit 4
fi
{
  echo "commit_sha=$commit"
  echo "expected_sha=$expected"
  echo "recorded_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "cargo_lock_sha256=$(sha256sum Cargo.lock | cut -d' ' -f1)"
  echo "wasm_targets=$(rustup target list --installed | paste -sd, -)"
  echo "worktree_clean=true"
} | tee "$report_dir/provenance.txt"

finish() {
  rc=$?
  trap - EXIT
  echo "overall_exit_code=$rc" >> "$report_dir/provenance.txt"
  (cd "$report_dir" && sha256sum provenance.txt *.log > SHA256SUMS 2>/dev/null) || true
  echo "Verification evidence: $report_dir" >&2
}
trap finish EXIT

set -o pipefail
cargo fmt --all -- --check 2>&1 | tee "$report_dir/format.log"
cargo fmt --manifest-path integration/conductor/Cargo.toml -- --check \
  2>&1 | tee "$report_dir/conductor-format.log"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py' \
  2>&1 | tee "$report_dir/python-tests.log"
cargo test --workspace --locked 2>&1 | tee "$report_dir/native-tests.log"
cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | tee "$report_dir/clippy.log"
RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--import-undefined' \
  cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime \
  2>&1 | tee "$report_dir/wasm-build.log"
echo 'Native, Clippy and WASM steps completed on this clean SHA. Conductor and Unyt checks remain pending.'
