#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$HERE/../../../../.." && pwd)"
COORD_ROOT="${COORD_ROOT:-/workspace/stoffel-dev/stoffel-mpc-coordinator/.worktrees/browser-wasm-transport}"
PROGRAM="$HERE/program"
CERT_DIR="$HERE/artifacts/certs"
BYTECODE="$PROGRAM/target/debug/private_aggregation.stflb"

export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_CODEGEN_UNITS=1
export CARGO_INCREMENTAL=0
mkdir -p "$CERT_DIR"

cargo build -p stoffel-cli --manifest-path "$SDK_ROOT/Cargo.toml"
cargo build -p stoffel-vm-runner --bin stoffel-run --manifest-path "$SDK_ROOT/Cargo.toml" \
  --config "patch.crates-io.stoffel-mpc-coordinator-shared.path=\"$COORD_ROOT/crates/coord-shared\"" \
  --config "patch.crates-io.stoffel-mpc-coordinator-off-chain.path=\"$COORD_ROOT/crates/off-chain\""
cargo build -p stoffel-mpc-coordinator-bins --bin run-coord --manifest-path "$COORD_ROOT/Cargo.toml"
cargo build -p stoffel-mpc-coordinator-bins --bin generate-ids --manifest-path "$COORD_ROOT/Cargo.toml"

(
  cd "$PROGRAM"
  "$SDK_ROOT/target/debug/stoffel" check
  "$SDK_ROOT/target/debug/stoffel" build
)

for index in 0 1 2 3 4; do
  "$COORD_ROOT/target/debug/generate-ids" \
    --cert "$CERT_DIR/node-$index.cert.der" \
    --key "$CERT_DIR/node-$index.key.der" \
    --subject-alt-names localhost 127.0.0.1
done

npx -y wasm-pack build "$SDK_ROOT/crates/stoffel-browser-client" \
  --target web --dev --out-dir tests/fixtures/one-browser/pkg \
  --out-name stoffel_browser_client

(
  cd "$HERE"
  npm install --ignore-scripts --no-audit --no-fund
  npx playwright install chromium
)

PROGRAM_HASH="$(sha256sum "$BYTECODE" | cut -d' ' -f1)"
RUN_COORD="$COORD_ROOT/target/debug/run-coord" \
STOFFEL_RUN="$SDK_ROOT/target/debug/stoffel-run" \
BYTECODE="$BYTECODE" \
CERT_DIR="$CERT_DIR" \
PROGRAM_HASH="$PROGRAM_HASH" \
node "$HERE/harness.mjs"
