#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workspace=$(CDPATH= cd -- "$project/../.." && pwd)
if ! command -v cargo >/dev/null 2>&1; then
    # Optional workspace-local toolchain used by the original donor build.
    # Ordinary clones use the developer's existing Rust installation.
    if [ -x "$workspace/work/toolchain/cargo/bin/cargo" ]; then
        export CARGO_HOME="$workspace/work/toolchain/cargo"
        export RUSTUP_HOME="$workspace/work/toolchain/rustup"
        export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$workspace/work/target}"
        export PATH="$CARGO_HOME/bin:$PATH"
    else
        echo "Rust/cargo is required. Install Rust from https://rustup.rs and rerun this script." >&2
        exit 1
    fi
fi
cd "$project"
cargo build --release --locked
mkdir -p bin
cp "$CARGO_TARGET_DIR/release/rammesh" bin/rammesh
