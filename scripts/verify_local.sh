#!/usr/bin/env bash
# Native tests, all-targets lint, and wasm zome build, without GitHub Actions.
# Not a conductor integration test. Intended for a pinned Holochain 0.7 shell.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Cargo missing: enter a Holochain 0.7 development shell.' >&2; exit 2; }
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--import-undefined' cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime
echo 'Native/Clippy/WASM checks passed; conductor and Unyt acceptance remain required.'
