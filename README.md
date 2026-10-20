# RAMMesh

A small Rust daemon that donates a bounded portion of a Mac's physical DRAM over mutually authenticated TLS.

RAMMesh implements remote allocation, read, write, free, SHA-256 verification, monitoring, quotas and clean shutdown. Its bulk data lives in anonymous memory wired with `mlock`; startup fails if the OS cannot wire the configured pool. No payload file, ramdisk or disk fallback is used.

**RAMMesh is an experimental memory service. It does not transparently add RAM to macOS, Chrome, or an Apple Silicon Mac's unified memory.** An application must use its explicit client API. Native system-wide borrowing remains a separate VM integration problem. Read the [borrower assessment](BORROWER-ASSESSMENT.md) for Exo, Infiniswap, MemCloud and the remaining work.

## Status

Developed and exercised on a 2016 Intel MacBook Pro, 16 GiB RAM, macOS Sequoia 15.8.1. The original donor validation passed 23 grouped integration checks and two unit tests. See [measured results](RESULTS.md) and the [sanitized benchmark JSON](docs/benchmarks/2026-10-20-intel-mac.json).

The initial supported and tested donor is **macOS on Intel**. Linux and Windows are unsupported. An Apple Silicon borrower and native transparent paging are future work. CI compiles and runs unit tests on an Intel macOS runner; it does not reproduce the original hardware/network benchmark.

## Build

Prerequisites: macOS, Apple's Command Line Tools (`clang` and the macOS SDK), Rust/rustup and OpenSSL/LibreSSL for generating development certificates. The repository pins Rust 1.99.1.

```sh
git clone https://github.com/kapunakap/rammesh.git
cd rammesh
./scripts/build-local.sh
```

The build script produces `bin/rammesh`. Standard `cargo build --release --locked` also works and produces `target/release/rammesh`.

## Run a donor and simulated borrower

Create owner-only development credentials, then start a conservative 128 MiB pool on loopback:

```sh
./scripts/make-pki.sh pki
./bin/rammesh serve --pki pki --capacity-mib 128
```

In another terminal in the repository:

```sh
./bin/rammesh stats --pki pki
./bin/rammesh demo --pki pki
./bin/rammesh bench --pki pki --rounds 3
./bin/rammesh hold --pki pki --mib 32 --seconds 30
```

These clients run on the donor to simulate borrowing over TCP/TLS. Stop the daemon with Control-C or SIGTERM. Shutdown closes client sockets, wipes allocations and the pool, then unlocks and unmaps it. No system service or login item is installed.

For LAN use, set `DONOR_IP` to a **specific private IP belonging to the donor**, then run:

```sh
./bin/rammesh serve --pki pki --listen "${DONOR_IP}:7443" --capacity-mib 128
```

Use the donor's actual RFC1918 private address. Wildcard and public-IP listening are refused. The client connects with `--addr "${DONOR_IP}:7443" --server-name rammesh-donor`.

A later borrower needs only `ca.crt`, `borrower.crt` and `borrower.key`, transferred through a trusted channel. Keep `donor.key` on the donor and `ca.key` offline. Certificates are not checked into Git. Development leaf certificates expire after 30 days; the CA after 365 days. The generator refuses to overwrite an existing PKI directory.

## Limits and memory lifetime

| Control | Default | Behavior |
|---|---:|---|
| `--capacity-mib` | 128 | Fixed wired pool; 1–4096 MiB and no more than 25% of physical RAM |
| `--session-mib` | Pool capacity | Page-rounded allocation quota for each TLS connection |
| `--reserve-mib` | 2048 | Startup estimated free + inactive memory must cover reserve plus pool; minimum reserve 1024 MiB |
| `--max-clients` | 4 | Includes incomplete TLS handshakes; configurable 1–16 |
| `--max-allocations` | 1024 | Global handle limit; configurable 1–65536 |
| `--idle-seconds` | 10 | Total deadline for handshake and each RPC, including the response |
| `--lease-seconds` | 3600 | Absolute connection lifetime; heartbeats do not renew it |
| Transfer size | 1 MiB | Maximum bytes in each read/write/verify operation |
| Connection admission | 16/second | Global fixed-window admission limit |
| Request rate | 10,000/second/session | Exceeding the limit closes the session |

**Every allocation belongs to one TLS connection and disappears when that connection closes.** Idle timeout, lease expiry, network failure, daemon shutdown, donor sleep or crash can invalidate every handle. Heartbeat with PING within the idle deadline. There is no reconnect recovery, replication or persistence. Preserve recoverable originals if data loss is unacceptable.

Freeing a block wipes it and returns space to the pool. The fixed pool remains wired until daemon shutdown; it does not shrink automatically. Existing data is never silently evicted. First-fit free extents coalesce, but fragmentation can reject a large allocation despite enough total free space.

Startup and new allocations require known, normal memory pressure. Admission uses free + inactive memory as a headroom estimate; inactive pages are not guaranteed immediately available RAM. New allocations fail if pressure is elevated or the reserve is breached. Start with the tested 128 MiB default and monitor before increasing it.

The configured cap strictly bounds donated storage. RSS also includes frame buffers, TLS state, thread stacks, allocator overhead and code. This is not a kernel-enforced cap on total process RSS.

## Security and RAM guarantees

- TLS 1.3, mandatory client certificate authentication, certificate-chain/server-name validation, and ALPN `rammesh/1`. Resumption and 0-RTT are disabled.
- No automatic peer trust, unauthenticated statistics endpoint or plaintext mode.
- Session ownership, checked byte ranges and bounded frames before body allocation. Page padding is inaccessible. Free and disconnect wipe the whole billed extent before reuse.
- Private keys must be owned regular files without group/other permission. Final-component key symlinks are refused.
- Explicit SHA-256 verification checks client-provided expected digests. TLS protects transport integrity; SHA-256 is not automatic ECC or repair.
- Bulk storage is `mmap(MAP_PRIVATE | MAP_ANON)`, Darwin tag 240, followed by required `mlock` and a full touch. `mincore` and Mach VM queries provide independent residency evidence.
- Process core dumps are disabled. Logs contain counters and errors, never payloads or private keys. Authenticated STATS reports pool usage, counters, system pressure, process ID and the mapping's virtual address for local inspection.

The donation pool stays resident during normal paging/compression while wired. Temporary network/TLS buffers are not all wired. Hibernation, privileged inspection and physical attacks are outside the process's guarantee. RAMMesh does not modify SIP, EFI, the kernel, swap, network configuration or power-management settings, and does not request a reboot.

The development CA grants access to any valid client-auth certificate it signs. Quotas are per session and global, not per physical device. Individual certificate revocation, enrollment, durable handles, pressure-driven pool resizing, fault recovery, sustained-operation qualification and independent security review remain production work. Use a trusted private network and development data.

## Test

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
./scripts/build-local.sh
python3 scripts/validate.py --out results/local
```

Full validation requires Python linked against OpenSSL with TLS 1.3. Older system Python/LibreSSL builds may lack it. The independent Python client creates temporary credentials and loopback donors, exercises at most 128 MiB wired, verifies authentication/limits/RAM retention/shutdown, runs a benchmark, and stops every donor. Results are ignored by Git because raw logs may contain local paths and network/process identifiers.

Optional `--self-lan YOUR_DONOR_IP` tests this donor's own interface address. It does not contact a second computer and does not measure two-host network throughput. The full native integration suite requires a suitable macOS environment with enough headroom and permission to wire the test pool; ordinary CI covers build, lint and unit tests.

## Layout

| File | Purpose |
|---|---|
| `src/memory.rs` | Wired pool, page allocator, quotas, wipe and RAM evidence |
| `src/main.rs` | Donor, limits, monitoring, shutdown and benchmark CLI |
| `src/client.rs` | Rust borrower API and absolute I/O deadlines |
| `src/tls.rs` | Mutual TLS and credential loading |
| `src/protocol.rs`, [PROTOCOL.md](PROTOCOL.md) | Bounded binary protocol |
| `src/macos.c` | Small read-only Mach memory/statistics shim |
| `scripts/validate.py` | Independent TLS/wire client and validation runner |

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under [MIT](LICENSE). Dependencies retain their own licenses; versions are recorded in `Cargo.lock`.
