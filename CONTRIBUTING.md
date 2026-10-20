# Contributing

RAMMesh is an experimental macOS Intel donor. Keep changes small and describe the resulting behavior, relevant validation and remaining limits.

Use the pinned Rust toolchain and macOS Command Line Tools:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

For donor/protocol/memory changes, also run the independent integration suite on a suitable Mac:

```sh
./scripts/build-local.sh
python3 scripts/validate.py --out results/local
```

Tests must be bounded, run on the machine explicitly selected for testing, clean up their own daemons and certificates, and leave system settings unchanged. Never weaken SIP, EFI, kernel security, swap or TLS validation as a test workaround. Do not contact another donor/borrower or modify a second machine without its owner's authorization.

Maintain fail-closed wiring, bounded frames/connections, checked ownership/ranges and wipe-before-reuse. Document changes to the protocol or handle lifetime. Avoid claims of transparent OS memory expansion or remote performance without evidence.

Do not commit private keys, certificates, raw logs, local addresses, user-specific paths, memory dumps, build outputs or `.env` files. Publish only deliberately sanitized benchmark summaries with hardware, OS, toolchain, transport, workload and timing definitions. Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
