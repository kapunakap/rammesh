#!/usr/bin/env python3
"""Independent TLS/wire client, security checks, RAM evidence and CLI benchmarks.

Requires Python linked against OpenSSL with TLS 1.3. No third-party Python packages.
All sockets target this Mac only. Test data and private keys stay in temporary files/RAM.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time

MIB = 1024 * 1024
MAX_FRAME = MIB + 64


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        data = sock.recv(n - len(out))
        if not data:
            raise EOFError("connection closed")
        out.extend(data)
    return bytes(out)


class Wire:
    def __init__(self, address, pki, role="borrower", name="rammesh-donor", cert=True, tls12=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(pki / "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
        if tls12:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["rammesh/1"])
        if cert:
            ctx.load_cert_chain(str(pki / f"{role}.crt"), str(pki / f"{role}.key"))
        self.sock = ctx.wrap_socket(socket.create_connection(address, timeout=5), server_hostname=name)
        self.sock.settimeout(5)

    def close(self):
        self.sock.close()

    def rpc(self, op, data=b"", expected=0):
        payload = bytes([op]) + data
        self.sock.sendall(struct.pack(">I", len(payload)) + payload)
        n, = struct.unpack(">I", exact(self.sock, 4))
        assert 0 < n <= MAX_FRAME, n
        reply = exact(self.sock, n)
        assert reply[0] == expected, (reply[0], expected, reply[1:100])
        return reply[1:]

    def alloc(self, n, expected=0):
        out = self.rpc(1, struct.pack(">Q", n), expected)
        return struct.unpack(">QQ", out) if expected == 0 else None

    def read(self, ident, offset, n, expected=0):
        return self.rpc(2, struct.pack(">QQI", ident, offset, n), expected)

    def write(self, ident, offset, data, expected=0):
        return self.rpc(3, struct.pack(">QQ", ident, offset) + data, expected)

    def free(self, ident, expected=0):
        self.rpc(4, struct.pack(">Q", ident), expected)

    def verify(self, ident, offset, n, digest, expected=0):
        return self.rpc(5, struct.pack(">QQI", ident, offset, n) + digest, expected)

    def stats(self):
        return json.loads(self.rpc(6))


def eventually(fn, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(0.03)
    raise AssertionError("condition not reached before deadline")


class Daemon:
    def __init__(self, binary, pki, out, label, *options):
        self.logpath = out / f"{label}-daemon.jsonl"
        self.log = self.logpath.open("w")
        settings = {"--pki": str(pki), "--listen": "127.0.0.1:0", "--capacity-mib": "64",
                    "--session-mib": "48", "--max-allocations": "64", "--idle-seconds": "3",
                    "--lease-seconds": "300"}
        settings.update(dict(zip(options[::2], options[1::2])))
        command = [str(binary), "serve"] + [v for pair in settings.items() for v in pair]
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE, stderr=self.log, text=True)
        if not select.select([self.process.stdout], [], [], 15)[0]:
            self.stop()
            raise AssertionError("donor did not become ready")
        line = self.process.stdout.readline()
        if not line:
            self.stop()
            raise AssertionError(self.logpath.read_text())
        self.ready = json.loads(line)
        self.log.write(line)
        self.log.flush()
        host, port = self.ready["listen"].rsplit(":", 1)
        self.address = (host, int(port))

    def stop(self, sig=signal.SIGTERM):
        if self.process.poll() is None:
            self.process.send_signal(sig)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("clean shutdown timed out")
        self.log.close()
        if self.process.stdout:
            self.process.stdout.close()


def main():
    parser = argparse.ArgumentParser()
    project = Path(__file__).resolve().parents[1]
    parser.add_argument("--binary", type=Path, default=project / "bin/rammesh")
    parser.add_argument("--out", type=Path, default=project / "results")
    parser.add_argument("--self-lan", help="This donor's own IPv4 address; never another computer")
    args = parser.parse_args()
    assert ssl.HAS_TLSv1_3, "Use a Python/OpenSSL build with TLS 1.3 support"
    binary = args.binary.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = []
    daemons = []
    clients = []

    def passed(name, **info):
        row = {"name": name, "status": "pass", **info}
        results.append(row)
        print(json.dumps(row), flush=True)

    def connect(address, pki, **kw):
        # Stay below the donor's explicit 16-new-connections/second limit.
        time.sleep(0.08)
        client = Wire(address, pki, **kw)
        clients.append(client)
        return client

    def closed(client):
        try:
            client.rpc(7)
        except (ssl.SSLError, OSError, EOFError):
            return True
        return False

    def capture(name, cmd):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        (out / name).write_text(p.stdout + p.stderr)
        return p.returncode

    try:
        with tempfile.TemporaryDirectory(prefix="rammesh-validation-") as scratch:
            scratch = Path(scratch)
            pki = scratch / "pki"
            foreign = scratch / "foreign"
            for dest in [pki, foreign]:
                subprocess.run(["sh", str(project / "scripts/make-pki.sh"), str(dest)],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            daemon = Daemon(binary, pki, out, "security")
            daemons.append(daemon)
            address = daemon.address
            evidence = daemon.ready["ram_evidence"]
            assert evidence["capacity_bytes"] == 64 * MIB
            assert evidence["mlock_succeeded"] and evidence["all_resident"]
            assert evidence["paged_out_pages"] == 0
            assert evidence["vm_region_query_ok"] and evidence["vm_region_external_pager"] == 0
            assert evidence["vm_region_user_wired_count"] >= 1
            assert evidence["vm_region_swapped_pages"] == 0
            passed("wired anonymous pool independently verified", evidence=evidence)

            a = connect(address, pki)
            assert a.sock.version() == "TLSv1.3"
            assert a.sock.selected_alpn_protocol() == "rammesh/1"
            a.rpc(7)
            passed("TLS 1.3 and authenticated RPC")
            for name, options in [
                ("client certificate required", {"cert": False}),
                ("server certificate hostname validated", {"name": "wrong-host.invalid"}),
                ("server-only certificate cannot authenticate borrower", {"role": "donor"}),
                ("TLS 1.2 refused", {"tls12": True}),
            ]:
                rejected = False
                try:
                    bad = connect(address, pki, **options)
                    bad.rpc(7)
                except (ssl.SSLError, OSError, EOFError):
                    rejected = True
                assert rejected, name
                passed(name)
            # A certificate from an unrelated CA, while still trusting the real donor CA.
            foreign_client = scratch / "foreign-client"
            foreign_client.mkdir()
            for filename, source in [("ca.crt", pki), ("borrower.crt", foreign), ("borrower.key", foreign)]:
                (foreign_client / filename).write_bytes((source / filename).read_bytes())
                (foreign_client / filename).chmod(0o600)
            rejected = False
            try:
                bad = connect(address, foreign_client)
                bad.rpc(7)
            except (ssl.SSLError, OSError, EOFError):
                rejected = True
            assert rejected
            passed("untrusted client CA refused")

            for n in [0, MAX_FRAME + 1, 0xffffffff]:
                bad = connect(address, pki)
                bad.sock.sendall(struct.pack(">I", n))
                try:
                    data = bad.sock.recv(16)
                    assert not data
                except (ssl.SSLError, OSError, EOFError):
                    pass
                bad.close()
            passed("zero and oversized frames close before reading a body")
            with socket.create_connection(address, timeout=5) as plain:
                plain.settimeout(5)
                plain.sendall(b"\x00\x00\x00\x01\x07")
                reply = plain.recv(16)
                assert not reply or reply[0] == 21  # TLS alert, never RPC success.
            passed("plaintext RPC refused")
            # Keep the authenticated owner alive after the preceding negative handshakes.
            a.close()
            a = connect(address, pki)
            for op in [1, 2, 3, 4, 5]:
                a.rpc(op, b"", expected=1)
            for op in [6, 7, 255]:
                a.rpc(op, b"extra", expected=1)
            passed("malformed requests and unknown operation rejected")

            ident, billed = a.alloc(2 * MIB + 17)
            assert billed == 2 * MIB + 4096
            for offset, n in [(0, MIB), (MIB, MIB), (2 * MIB, 17)]:
                data = os.urandom(n)
                digest = hashlib.sha256(data).digest()
                a.write(ident, offset, data)
                assert a.read(ident, offset, n) == data
                assert a.verify(ident, offset, n, digest) == digest
            a.verify(ident, 0, MIB, bytes(32), expected=5)
            a.read(ident, 2 * MIB + 16, 2, expected=2)
            a.read(ident, 0xffffffffffffffff, 1, expected=2)
            a.read(ident, 0, MIB + 1, expected=1)
            a.write(ident, 2 * MIB + 16, b"xx", expected=2)
            a.alloc(0, expected=3)
            a.alloc(0xffffffffffffffff, expected=3)
            b = connect(address, pki)
            b.read(ident, 0, 1, expected=2)
            b.write(ident, 0, b"x", expected=2)
            b.free(ident, expected=2)
            b.verify(ident, 0, 1, bytes(32), expected=2)
            a.free(ident)
            a.free(ident, expected=2)
            a.read(ident, 0, 1, expected=2)
            clean, _ = b.alloc(2 * MIB + 17)
            assert b.read(clean, 0, MIB) == bytes(MIB)
            b.free(clean)
            passed("allocation, read, write, SHA-256, corruption detection, bounds, ownership and zeroing")

            full_a, _ = a.alloc(48 * MIB)
            a.alloc(1, expected=3)
            full_b, _ = b.alloc(16 * MIB)
            b.alloc(1, expected=3)
            assert a.stats()["pool"]["used_bytes"] == 64 * MIB
            a.free(full_a)
            b.free(full_b)
            handles = [a.alloc(1)[0] for _ in range(64)]
            a.alloc(1, expected=3)
            for handle in handles:
                a.free(handle)
            passed("page accounting, 48 MiB session quota, 64 MiB global cap and handle limit")

            ident, _ = b.alloc(8 * MIB)
            b.write(ident, 0, os.urandom(MIB))
            b.close()
            eventually(lambda: a.stats()["pool"]["used_bytes"] == 0)
            passed("disconnect wipes and releases allocations")

            def concurrent_client(seed):
                c = Wire(address, pki)
                try:
                    ident, _ = c.alloc(4 * MIB)
                    data = hashlib.sha256(str(seed).encode()).digest() * 2048
                    for i in range(10):
                        c.write(ident, i * len(data), data)
                        assert c.read(ident, i * len(data), len(data)) == data
                    c.free(ident)
                finally:
                    c.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                list(executor.map(concurrent_client, range(3)))
            passed("three concurrent borrowers isolated under one global pool")

            a.close()
            time.sleep(0.15)
            blockers = [socket.create_connection(address, timeout=5) for _ in range(4)]
            try:
                time.sleep(0.1)
                with socket.create_connection(address, timeout=5) as extra:
                    extra.settimeout(5)
                    extra.sendall(b"hello")
                    try:
                        assert not extra.recv(16)
                    except ConnectionResetError:
                        pass
            finally:
                for blocker in blockers:
                    blocker.close()
            passed("connection cap includes incomplete TLS handshakes")
            time.sleep(0.2)
            idle = connect(address, pki)
            ident, _ = idle.alloc(MIB)
            time.sleep(3.4)
            assert closed(idle)
            idle.close()
            passed("idle connection timeout releases memory")
            monitor = connect(address, pki)
            assert monitor.stats()["pool"]["used_bytes"] == 0

            # Incompressible payload: retain only 48 SHA-256 digests at the client.
            ident, _ = monitor.alloc(48 * MIB)
            digests = []
            for i in range(48):
                data = os.urandom(MIB)
                digests.append(hashlib.sha256(data).digest())
                monitor.write(ident, i * MIB, data)
            del data
            evidence_before = monitor.stats()
            capture("vmmap-held-ram.txt", ["/usr/bin/vmmap", "-w", str(daemon.process.pid)])
            capture("open-files-held-ram.txt", ["/usr/sbin/lsof", "-nP", "-p", str(daemon.process.pid)])
            capture("process-held-ram.txt", ["/bin/ps", "-o", "pid,rss,vsz,pcpu,command", "-p", str(daemon.process.pid)])
            capture("vm-stat-held-ram.txt", ["/usr/bin/vm_stat"])
            # Idle deadline is 3 seconds, so heartbeat while waiting five seconds.
            for _ in range(5):
                time.sleep(1)
                monitor.rpc(7)
            for i, digest in enumerate(digests):
                monitor.verify(ident, i * MIB, MIB, digest)
                assert hashlib.sha256(monitor.read(ident, i * MIB, MIB)).digest() == digest
            evidence_after = monitor.stats()
            (out / "ram-evidence.json").write_text(json.dumps({"before": evidence_before, "after": evidence_after,
                "random_payload_bytes": 48 * MIB, "client_retained":"SHA-256 digests only, 1536 bytes"}, indent=2) + "\n")
            for e in [evidence_before["ram_evidence"], evidence_after["ram_evidence"]]:
                assert e["all_resident"] and e["vm_region_user_wired_count"] >= 1
                assert e["paged_out_pages"] == e["vm_region_swapped_pages"] == 0
                assert e["vm_region_external_pager"] == 0
            passed("48 MiB random payload retained and verified in wired anonymous RAM", held_seconds=5)

            # Shutdown with both live allocations and a stalled TLS handshake.
            stall = socket.create_connection(address, timeout=5)
            began = time.monotonic()
            daemon.stop()
            elapsed = time.monotonic() - began
            stall.close()
            assert daemon.process.returncode == 0
            entries = [json.loads(line) for line in daemon.logpath.read_text().splitlines()]
            shutdown = next(e for e in entries if e.get("event") == "clean_shutdown")
            assert shutdown["remaining_allocation_bytes"] == 0
            assert shutdown["released_locked_bytes"] == 64 * MIB
            assert elapsed < 3
            passed("SIGTERM closes active and stalled clients, wipes and unlocks pool", seconds=elapsed)

            # Process-local resource limit: no system-wide limit or swap changes.
            def no_memlock():
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
            p = subprocess.run([str(binary), "serve", "--pki", str(pki), "--capacity-mib", "16"],
                               preexec_fn=no_memlock, capture_output=True, text=True, timeout=10)
            assert p.returncode != 0 and "mlock failed" in p.stderr, p.stderr
            passed("mlock refusal fails closed with no pageable fallback", error=p.stderr.strip())
            for options, message in [(["--listen", "0.0.0.0:0"], "specific loopback"),
                                     (["--capacity-mib", "4097"], "between"),
                                     (["--reserve-mib", "16384"], "headroom")]:
                p = subprocess.run([str(binary), "serve", "--pki", str(pki)] + options,
                                   capture_output=True, text=True, timeout=10)
                assert p.returncode != 0 and message in p.stderr, p.stderr
            key = pki / "donor.key"
            key.chmod(0o644)
            try:
                p = subprocess.run([str(binary), "serve", "--pki", str(pki)],
                                   capture_output=True, text=True, timeout=10)
                assert p.returncode != 0 and "private key" in p.stderr
            finally:
                key.chmod(0o600)
            passed("unsafe listen, excessive size, reserve violation and exposed private key refused")

            lease = Daemon(binary, pki, out, "lease", "--lease-seconds", "2")
            daemons.append(lease)
            c = connect(lease.address, pki)
            c.alloc(MIB)
            began = time.monotonic()
            for _ in range(30):
                time.sleep(0.1)
                if closed(c):
                    break
            else:
                raise AssertionError("lease did not expire")
            assert time.monotonic() - began < 3
            lease.stop(signal.SIGINT)
            assert lease.process.returncode == 0
            passed("absolute lease expires despite heartbeats; SIGINT clean shutdown")

            # Larger but still conservative 128 MiB pool for throughput, on this Mac only.
            bench = Daemon(binary, pki, out, "benchmark", "--capacity-mib", "128", "--session-mib", "128",
                           "--idle-seconds", "10", "--max-allocations", "1024")
            daemons.append(bench)
            endpoint = f"{bench.address[0]}:{bench.address[1]}"
            for command in ["demo", "bench"]:
                p = subprocess.run([str(binary), command, "--pki", str(pki), "--addr", endpoint],
                                   check=True, capture_output=True, text=True, timeout=120)
                parsed = json.loads(p.stdout)
                (out / f"{command}.json").write_text(json.dumps(parsed, indent=2) + "\n")
            bench.stop()
            passed("release binary demo and three-round sequential loopback benchmark")

            if args.self_lan:
                # Binding requires the address to exist on THIS donor. No peer discovery or scanning.
                lan = Daemon(binary, pki, out, "self-lan", "--listen", f"{args.self_lan}:0",
                             "--capacity-mib", "16", "--session-mib", "16")
                daemons.append(lan)
                c = connect(lan.address, pki)
                ident, _ = c.alloc(4096)
                data = os.urandom(4096)
                c.write(ident, 0, data)
                assert c.read(ident, 0, 4096) == data
                c.free(ident)
                c.close()
                lan.stop()
                passed("donor's own LAN address accepts authenticated RPC", address=args.self_lan,
                       scope="same-host self-connection; not a second-Mac or Wi-Fi throughput measurement")
    finally:
        for client in clients:
            client.close()
        for daemon in daemons:
            daemon.stop()
        (out / "validation.json").write_text(json.dumps({"checks": results, "passed": len(results),
            "python_ssl": ssl.OPENSSL_VERSION, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=2) + "\n")
    print(f"PASS: {len(results)} checks; all test daemons stopped", flush=True)


if __name__ == "__main__":
    main()
