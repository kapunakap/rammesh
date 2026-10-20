# Can the M2 transparently use this donor's RAM?

**The donor is usable through an explicit API today. Transparent expansion of native macOS memory for every application, including Chrome, is not implemented and has no supported user-space path identified in this research.** No M2 connection, inspection, installation or configuration was performed.

## Why the remaining work is substantial

A CPU cannot dereference a network allocation handle. The borrower's VM system would need to keep hot pages locally, move cold pages to the donor, fault them back into local physical memory on demand, track dirty versions and preserve correct reads/writes across threads and processes. Network-accessible bytes are a storage tier for pages, not additional CPU-addressable DRAM or GPU unified memory.

Apple's archived kernel guide explicitly says macOS does not support external pagers. Its discussion of VM maps also places deep VM changes inside the VM implementation rather than exposing a general plug-in interface. Although that guide is historical, current public XNU compressor backing-store code still manages swap through kernel-owned swapfile/vnode paths. I found no supported API that redirects arbitrary native application anonymous pages to a third-party TCP service. This is an assessment from the documented interfaces and source, not a claim that a research kernel implementation is theoretically impossible. [Apple VM guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/vm/vm.html), [XNU compressor backing store](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_compressor_backing_store.c).

DriverKit and system extensions expose particular hardware, network and security services; the documented families do not provide a system-wide anonymous-memory pager. A generic dext or VPN extension therefore does not solve the missing VM integration. Apple also documents extra signing, architecture and installation/security requirements for kernel extensions on Apple silicon. A working research kext is not assured: stable VM hooks may still be unavailable. No kernel or security changes were attempted. [DriverKit](https://developer.apple.com/documentation/driverkit), [Apple low-level extension guidance](https://developer.apple.com/documentation/systemextensions/implementing-drivers-system-extensions-and-kexts).

## What the three projects contribute

| Project | Actual mechanism and lesson | Applicability here |
|---|---|---|
| Exo | Distributed inference; schedules model work across machines using topology, memory and communication costs. Move computation near its data and send fewer, larger messages. | Useful application-level design; it does not extend arbitrary macOS heaps. Its current documented RDMA path requires Thunderbolt 5 and macOS 26.2, outside this Intel TB3 / M2 pairing. |
| Infiniswap | Linux remote paging through an RDMA-backed block device plus remote memory daemons. Separate a small control plane from page transfers and preserve headroom. | Direct inspiration for bounded donation and admission control. Its Linux kernel block driver and InfiniBand/RDMA stack do not run as a native macOS paging plug-in. |
| MemCloud | Rust distributed volatile block/KV storage with SDKs, plus an optional process allocator interceptor. Separate allocation handles, block operations and explicit lifetime/limits. | Closest application-level model to this donor. Its interceptor is a process-scoped experiment, not a universal macOS memory service. |

The implementation here is original. None of these projects or their installers was installed or executed. RAMMesh adopts explicit block operations and headroom ideas while using a small single-donor design, native `mlock`, bounded framing and certificate-based TLS. It does not implement their discovery, mesh, sharding, replication or RDMA protocols. [Exo README](https://github.com/exo-explore/exo), [Infiniswap repository](https://github.com/SymbioticLab/Infiniswap), [Infiniswap NSDI paper](https://www.usenix.org/system/files/conference/nsdi17/nsdi17-gu.pdf), [MemCloud repository](https://github.com/vibhanshu2001/memcloud).

MemCloud's guide injects a library with `DYLD_INSERT_LIBRARIES` and intercepts large malloc-family allocations. Its reviewed C source handles faults by fetching pages into local anonymous mappings. The sync thread shown only sleeps; a fetch failure substitutes zeros, and the fault path uses locks/network calls. Those observations mean the reviewed implementation does not establish safe eviction, coherent dirty-page writeback or fail-safe paging for arbitrary applications. This is a source-level assessment, not an executed MemCloud benchmark. [Interceptor guide](https://github.com/vibhanshu2001/memcloud/blob/main/docs/interceptor.md), [reviewed interceptor source](https://github.com/vibhanshu2001/memcloud/blob/main/interceptor/memcloud_vm.c).

## Chrome is especially unsuitable for a malloc-injection shortcut

Chromium documents several memory systems: PartitionAlloc, Blink's garbage-collected heaps, V8-managed memory, and shared/discardable mappings. Replacing a few dynamically linked allocator calls cannot cover all of them or all helper processes. [Chromium allocator documentation](https://chromium.googlesource.com/chromium/src/base/+/c784dfa39b8fea365753cc32e369d5371b3ee3f0/allocator/README.md).

Hardened Runtime and library validation also constrain dynamic-library injection. Their interaction depends on each signed executable's entitlements; this task did not inspect or modify the M2's Chrome installation. A controlled Chromium build could support an explicit remote cache or allocator experiment, but that would remain application-specific. No DYLD configuration, browser flags, signing changes or browser injection were attempted. [Apple Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime).

## Feasible routes and scope

| Route | Scope | Remaining work |
|---|---|---|
| Explicit Rust/C/Python application integration | Selected applications and caches that opt in | Native arm64 borrower, batching, local caching, recovery and workload benchmarks. Donor protocol is ready for this. |
| Controlled process pager/allocator | Programs built or launched for the experiment | Safe fault servicing, bounded local cache, dirty tracking, eviction, multithreaded coherence and allocator coverage. Cannot promise stock Chrome or all apps. |
| Linux guest with a suitable paging backend | Applications inside that guest only | An ARM-compatible backend for this TLS protocol, guest networking, recovery and validation. Infiniswap's existing RDMA implementation is not compatible with this TCP protocol. Host macOS apps remain outside the guest. |
| Native macOS VM integration | Potentially all native applications | Apple-supported pager integration or substantial kernel/VM research, supported hooks and signing/security feasibility, plus the correctness and failure work below. No supported drop-in implementation was found. |

Merely mounting remote RAM as a file system, building a RAM disk, changing `malloc`, or increasing a process's virtual address reservation does not insert this donor into macOS's global anonymous-memory pager. Replacing or relocating swap is outside the requested scope and was not attempted.

## Required correctness before OS pages could depend on it

1. **Page semantics and local cache.** Discover the borrower's native page size; do not assume the donor's measured 4 KiB pages. Respect mappings, copy-on-write, shared pages, protection changes, code signing and CPU/GPU memory restrictions. Apple identifies page-size differences between Intel and Apple silicon. [Apple porting guidance](https://developer.apple.com/documentation/apple-silicon/porting-your-macos-apps-to-apple-silicon).
2. **Dirty tracking and eviction.** Evict a local page only after its acknowledged, versioned remote copy is known valid. Prevent stale writes and concurrent fault races. Kernel fault processing must make progress without allocating pageable resources or blocking on itself under memory pressure.
3. **Failure policy.** A lost donor must never become a zero-filled page containing silently corrupted application state. Indispensable pages require replication, a recoverable fallback, or an explicit fatal failure policy. Donor sleep, restart, Wi-Fi loss and cable removal are normal failure cases on a laptop.
4. **Lifetime and admission protocol.** Current handles are session-bound, have an absolute lease and disappear on disconnect. A pager needs identity-bound allocations, negotiated revocation, drain/migration, reconnect fencing, quotas and pressure-driven capacity changes. A single volatile donor cannot provide high availability.
5. **Latency and throughput.** Batch transfers, prefetch, maintain a useful local working set, limit outstanding requests and avoid blocking UI threads on a network fault. Measure real links and application workloads before claiming any benefit.
6. **Security and operations.** Per-device certificates/quotas, revocation, upgrade/version negotiation, fault injection, protocol fuzzing, independent review and tested failure handling are necessary for unattended use.

## Network choices for this hardware

This donor currently uses 802.11ac Wi-Fi. Its four Thunderbolt 3 ports are disconnected. A future direct Thunderbolt networking link or wired Ethernet could reduce variability, but actual end-to-end throughput and latency have not been measured. The reported 40 Gb/s Thunderbolt bus capability is not measured TCP/IP payload speed. This build made only loopback and donor-to-itself LAN-address connections.

Apple lists Thunderbolt 3 / USB4 up to 40 Gb/s on the M2 Air. Exo's documented Thunderbolt 5 RDMA path therefore does not apply to this pair; do not infer RDMA support from a USB-C connector or install its setup scripts here. [Apple M2 Air specifications](https://support.apple.com/en-gb/111867), [Exo RDMA requirements](https://github.com/exo-explore/exo#enabling-rdma-on-macos).

For perspective, a nominal 1 Gb/s link has an absolute serialization ceiling of 125 MB/s before protocol overhead, and a 4 KiB transfer takes at least 32.8 microseconds just to serialize. Round trips, Wi-Fi contention, encryption and software processing add time. Remote memory is a plausible cold-data tier; it cannot match the latency and bandwidth of local DRAM. Whether it beats local SSD swap for a particular workload is unmeasured here.

The next concrete milestone is an opt-in arm64 borrower with a bounded local cache, tested later with explicit M2 authorization. Universal native macOS/Chrome expansion remains unfulfilled by the donor alone. Research reviewed on 20 October 2026; linked project `main` branches can change.
