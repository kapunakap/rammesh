# Initial donor validation

Measured on 20 October 2026 on a **2016 Intel MacBook Pro (MacBookPro13,3)** with an i7-6700HQ (2.60 GHz, 4 cores / 8 threads), **16 GiB LPDDR3**, macOS Sequoia 15.8.1 (24H32), native 4096-byte pages, and Rust 1.99.1.

These are results from the original donor build, not a performance guarantee for other machines. The published JSON omits private host/interface identifiers, IP addresses, local paths, process IDs, virtual addresses, raw logs and credentials. [Sanitized machine-readable results](docs/benchmarks/2026-10-20-intel-mac.json).

## Physical RAM evidence

An independent Python/OpenSSL client wrote **48 MiB of random data** in 1 MiB chunks and retained 48 expected SHA-256 digests rather than a full client-side mirror. After a five-second hold with heartbeats, server-side verification and full client readback hashes matched for every chunk.

The daemon's 64 MiB anonymous pool reported:

| Evidence | Before and after retention |
|---|---:|
| Successful `mlock` | Yes |
| Resident pages / total pages | 16,384 / 16,384 |
| `mincore` paged-out pages | 0 |
| Mach VM region swapped pages | 0 |
| Mach VM user wired count | 1 |
| External file pager | 0 |

Independent `vmmap` output identified Darwin memory tag 240 as **64.0M resident, 64.0M dirty, 0K swap**. The process physical footprint was approximately 67 MiB with that 64 MiB pool. Open-file inspection found no payload backing file. The separate 128 MiB benchmark pool also reported every page resident and zero swapped pages.

A child process with its own `RLIMIT_MEMLOCK` set to zero failed donor startup with `mlock failed; refusing pageable donation`. There was no pageable fallback. System swap settings were unchanged.

This proves wired anonymous storage during the tests. It does not claim zero disk I/O across the OS or guarantee that transient TLS buffers and hibernation can never create disk copies.

## Sequential TCP/TLS loopback

Native release build; one established mutually authenticated TLS 1.3 connection, three rounds, no pipelining. Client and donor ran on the **same Mac**. Timing includes each RPC and acknowledgment/response; result comparison is outside the read timer. Warm-ups are excluded. Each benchmark allocation was 32 MiB within a 128 MiB wired pool.

| Transfer | Write MiB/s | Read MiB/s | Write p50 / p99 | Read p50 / p99 | Samples/direction |
|---|---:|---:|---:|---:|---:|
| 4 KiB | 60.2 | 60.5 | 59.2 / 138.1 µs | 59.6 / 138.0 µs | 3,000 |
| 64 KiB | 352.1 | 347.5 | 159.5 / 364.0 µs | 161.5 / 355.0 µs | 768 |
| 1 MiB | 705.7 | 771.9 | 1.360 / 2.040 ms | 1.230 / 2.015 ms | 384 |

Every benchmark read was compared, and explicit SHA-256 checks passed before freeing allocations. The final pool had no outstanding allocations and one coalesced free extent.

An authenticated connection through the donor's own private LAN IP also passed allocate/write/read/free. This remained a same-host connection. **There is no measured two-Mac, Wi-Fi, Thunderbolt, M2 or Chrome result here.**

## Checks and scope

23 grouped integration checks passed: required certificates, CA and server-name checks, client certificate purpose, TLS 1.2/plaintext rejection, malformed/oversized frames, protocol validation, bounds and integer limits, ownership, freed-handle rejection, zeroed reuse, page accounting, session/global quotas, handle count, three concurrent borrowers, disconnect cleanup, incomplete-handshake caps, idle/absolute lease expiry, fail-closed wiring, reserve/listen/key-permission guards, RAM retention, SIGTERM/SIGINT, demo and benchmarks.

SIGTERM with 48 MiB allocated and an incomplete handshake completed in approximately **122 ms**, reporting zero remaining allocation bytes and releasing the full 64 MiB pool. This is a small-pool measurement, not a guarantee for larger configured pools.

Two Rust unit tests passed. Formatting and Clippy with warnings denied passed. The initial validation touched only the donor. No SIP, EFI, kernel, swap, firewall, network or power-management configuration was changed; no reboot occurred. All temporary donors were stopped and test credentials deleted.

The project remains a prototype. Native transparent borrowing, Apple Silicon client qualification, replication, reconnect recovery, production stress/failure testing and an independent security audit are outstanding. See [the borrower assessment](BORROWER-ASSESSMENT.md).
