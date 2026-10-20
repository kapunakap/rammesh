use rammesh::{
    client::{Client, DeadlineTcp},
    memory::{MemoryInfo, Pool},
    protocol::*,
    tls,
};
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MIB: usize = 1024 * 1024;
const HELP: &str = "RAMMesh 0.1 — macOS wired-DRAM donor (TLS 1.3 + mandatory client certificates)
Usage:
  rammesh inspect
  rammesh serve --pki DIR [--listen 127.0.0.1:7443] [--capacity-mib 128]
      [--session-mib 128] [--reserve-mib 2048] [--max-clients 4]
      [--max-allocations 1024] [--idle-seconds 10] [--lease-seconds 3600]
  rammesh stats --pki DIR [--addr 127.0.0.1:7443] [--server-name rammesh-donor]
  rammesh demo --pki DIR [--addr ...] [--server-name ...]
  rammesh bench --pki DIR [--addr ...] [--server-name ...] [--rounds 3]
  rammesh hold --pki DIR [--addr ...] [--server-name ...] [--mib 32] [--seconds 30]
Every allocation belongs to its TLS connection and is wiped on free/disconnect.
The donor never persists payloads. The pool is fixed and mlocked; no pageable fallback.
Only specific loopback/private IP listen addresses are accepted. Ctrl-C / SIGTERM shuts down.";

struct Args {
    values: HashMap<String, String>,
}
impl Args {
    fn new(mut args: impl Iterator<Item = String>) -> io::Result<Self> {
        let mut values = HashMap::new();
        while let Some(k) = args.next() {
            if !k.starts_with("--") {
                return Err(io::Error::other("expected --option value"));
            }
            let v = args
                .next()
                .ok_or_else(|| io::Error::other("missing option value"))?;
            if values.insert(k, v).is_some() {
                return Err(io::Error::other("duplicate option"));
            }
        }
        Ok(Self { values })
    }
    fn get(&mut self, k: &str, default: &str) -> String {
        self.values.remove(k).unwrap_or_else(|| default.to_owned())
    }
    fn number(&mut self, k: &str, default: usize, min: usize, max: usize) -> io::Result<usize> {
        let n = self
            .get(k, &default.to_string())
            .parse::<usize>()
            .map_err(io::Error::other)?;
        if n < min || n > max {
            return Err(io::Error::other(format!(
                "{k} must be between {min} and {max}"
            )));
        }
        Ok(n)
    }
    fn done(self) -> io::Result<()> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "unknown options: {:?}",
                self.values.keys()
            )))
        }
    }
}
#[derive(Default)]
struct Metrics {
    connections: AtomicU64,
    auth_failures: AtomicU64,
    rejected_connections: AtomicU64,
    requests: AtomicU64,
    errors: AtomicU64,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
}
impl Metrics {
    fn json(&self) -> Value {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        json!({"connections_total":get(&self.connections),"auth_failures":get(&self.auth_failures),
        "rejected_connections":get(&self.rejected_connections),"requests":get(&self.requests),
        "errors":get(&self.errors),"read_bytes":get(&self.read_bytes),"write_bytes":get(&self.write_bytes)})
    }
}
type Sockets = Arc<Mutex<HashMap<u64, TcpStream>>>;
struct Session {
    id: u64,
    pool: Arc<Mutex<Pool>>,
    sockets: Sockets,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.pool.lock().unwrap().release_owner(self.id);
        self.sockets.lock().unwrap().remove(&self.id);
    }
}
type RpcResult = Result<Vec<u8>, (u8, String)>;
fn fail(code: u8, s: impl ToString) -> (u8, String) {
    (code, s.to_string())
}
fn process(
    owner: u64,
    frame: &[u8],
    pool: &Mutex<Pool>,
    metrics: &Metrics,
    reserve: u64,
    active: usize,
) -> RpcResult {
    let op = frame[0];
    let b = &frame[1..];
    let exact = |n| {
        if b.len() == n {
            Ok(())
        } else {
            Err(fail(1, "invalid request length"))
        }
    };
    match op {
        ALLOC => {
            exact(8)?;
            let memory = MemoryInfo::get().map_err(|e| fail(4, e))?;
            if !memory.allocation_allowed(reserve) {
                return Err(fail(4, "memory pressure or reserve guard"));
            }
            let (id, billed) = pool
                .lock()
                .unwrap()
                .alloc(owner, u64_at(b, 0))
                .map_err(|e| fail(3, e))?;
            let mut out = id.to_be_bytes().to_vec();
            out.extend((billed as u64).to_be_bytes());
            Ok(out)
        }
        READ => {
            exact(20)?;
            let n = u32_at(b, 16) as usize;
            if n > MAX_TRANSFER {
                return Err(fail(1, "transfer limit"));
            }
            let data = pool
                .lock()
                .unwrap()
                .read(owner, u64_at(b, 0), u64_at(b, 8), n)
                .map_err(|e| fail(2, e))?
                .to_vec();
            metrics.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(data)
        }
        WRITE => {
            if b.len() < 16 || b.len() - 16 > MAX_TRANSFER {
                return Err(fail(1, "invalid write size"));
            }
            pool.lock()
                .unwrap()
                .write(owner, u64_at(b, 0), u64_at(b, 8), &b[16..])
                .map_err(|e| fail(2, e))?;
            metrics
                .write_bytes
                .fetch_add((b.len() - 16) as u64, Ordering::Relaxed);
            Ok(vec![])
        }
        FREE => {
            exact(8)?;
            pool.lock()
                .unwrap()
                .free(owner, u64_at(b, 0))
                .map_err(|e| fail(2, e))?;
            Ok(vec![])
        }
        VERIFY => {
            exact(52)?;
            let n = u32_at(b, 16) as usize;
            if n > MAX_TRANSFER {
                return Err(fail(1, "transfer limit"));
            }
            let p = pool.lock().unwrap();
            let data = p
                .read(owner, u64_at(b, 0), u64_at(b, 8), n)
                .map_err(|e| fail(2, e))?;
            let digest = Sha256::digest(data);
            if digest.as_slice() != &b[20..] {
                return Err(fail(5, "SHA-256 integrity mismatch"));
            }
            Ok(digest.to_vec())
        }
        STATS => {
            exact(0)?;
            let p = pool.lock().unwrap();
            let stats = json!({"protocol":"rammesh/1","tls":"TLS1.3; mutual certificates; resumption disabled",
                "pool":p.stats(),"ram_evidence":p.memory.evidence().map_err(|e|fail(4,e))?,
                "system":MemoryInfo::get().map_err(|e|fail(4,e))?.json(),"metrics":metrics.json(),
                "active_connections":active,"reserve_bytes":reserve,"pid":std::process::id()});
            serde_json::to_vec(&stats).map_err(|e| fail(1, e))
        }
        PING => {
            exact(0)?;
            Ok(vec![])
        }
        _ => Err(fail(1, "unknown operation")),
    }
}
fn worker(
    tcp: TcpStream,
    session: Session,
    config: Arc<rustls::ServerConfig>,
    metrics: Arc<Metrics>,
    timeout: Duration,
    lease: Duration,
    reserve: u64,
) -> io::Result<()> {
    // Darwin accept() can inherit O_NONBLOCK from the polling listener.
    // Worker I/O is blocking with absolute deadlines; reset the accepted socket explicitly.
    tcp.set_nonblocking(false)?;
    tcp.set_nodelay(true)?;
    let mut conn = ServerConnection::new(config).map_err(io::Error::other)?;
    conn.set_buffer_limit(Some(64 * 1024));
    let mut stream = StreamOwned::new(conn, DeadlineTcp::new(tcp, timeout));
    while stream.conn.is_handshaking() {
        if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
            metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
    }
    if stream.conn.alpn_protocol() != Some(b"rammesh/1".as_slice()) {
        return Err(io::Error::other("ALPN mismatch"));
    }
    let expires = Instant::now() + lease;
    let mut rate_window = Instant::now();
    let mut operations = 0u32;
    loop {
        let remaining = expires
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::other("lease expired"))?;
        stream.sock.reset(timeout.min(remaining));
        let frame = read_frame(&mut stream)?;
        if rate_window.elapsed() >= Duration::from_secs(1) {
            rate_window = Instant::now();
            operations = 0;
        }
        operations += 1;
        if operations > 10_000 {
            return Err(io::Error::other("rate limit"));
        }
        metrics.requests.fetch_add(1, Ordering::Relaxed);
        let active = session.sockets.lock().unwrap().len();
        match process(session.id, &frame, &session.pool, &metrics, reserve, active) {
            Ok(data) => write_frame(&mut stream, 0, &data)?,
            Err((code, message)) => {
                metrics.errors.fetch_add(1, Ordering::Relaxed);
                write_frame(&mut stream, code, message.as_bytes())?;
            }
        }
    }
}
fn serve(mut args: Args) -> io::Result<()> {
    let pki = args.get("--pki", "pki");
    let addr: SocketAddr = args
        .get("--listen", "127.0.0.1:7443")
        .parse()
        .map_err(io::Error::other)?;
    let allowed = match addr.ip() {
        std::net::IpAddr::V4(a) => a.is_loopback() || a.is_private(),
        std::net::IpAddr::V6(a) => a.is_loopback() || a.is_unique_local(),
    };
    if !allowed {
        return Err(io::Error::other(
            "listen on a specific loopback or private LAN address",
        ));
    }
    let mib = args.number("--capacity-mib", 128, 1, 4096)?;
    let session_mib = args.number("--session-mib", mib, 1, mib)?;
    let reserve = args.number("--reserve-mib", 2048, 1024, 16384)? as u64 * MIB as u64;
    let max_clients = args.number("--max-clients", 4, 1, 16)?;
    let max_allocations = args.number("--max-allocations", 1024, 1, 65536)?;
    let timeout = Duration::from_secs(args.number("--idle-seconds", 10, 1, 120)? as u64);
    let lease = Duration::from_secs(args.number("--lease-seconds", 3600, 1, 86400)? as u64);
    args.done()?;
    let info = MemoryInfo::get()?;
    let capacity = mib * MIB;
    if capacity as u64 > info.physical / 4 {
        return Err(io::Error::other(
            "hard safety ceiling: at most 25% of physical RAM",
        ));
    }
    if !info.allocation_allowed(reserve + capacity as u64) {
        return Err(io::Error::other(
            "insufficient estimated headroom, unknown memory pressure, or elevated pressure",
        ));
    }
    let config = tls::server(Path::new(&pki))?;
    // Disable this process's core dumps only. No system setting or swap setting changes.
    if unsafe {
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let pool = Arc::new(Mutex::new(Pool::new(
        capacity,
        session_mib * MIB,
        max_allocations,
    )?));
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())?;
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let sockets: Sockets = Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Metrics::default());
    {
        let p = pool.lock().unwrap();
        println!(
            "{}",
            json!({"event":"ready","listen":listener.local_addr()?.to_string(),"pid":std::process::id(),
            "pool":p.stats(),"ram_evidence":p.memory.evidence()?,
            "max_clients":max_clients,"idle_seconds":timeout.as_secs(),"lease_seconds":lease.as_secs()})
        );
    }
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut id = 0u64;
    let mut health = Instant::now();
    let mut accept_window = Instant::now();
    let mut accepted_this_second = 0;
    let mut result = Ok(());
    while !shutdown.load(Ordering::Relaxed) {
        let mut i = 0;
        while i < workers.len() {
            if workers[i].is_finished() {
                let handle: thread::JoinHandle<()> = workers.swap_remove(i);
                if handle.join().is_err() {
                    shutdown.store(true, Ordering::Relaxed);
                    result = Err(io::Error::other("worker panicked"));
                }
            } else {
                i += 1;
            }
        }
        match listener.accept() {
            Ok((tcp, _)) => {
                if accept_window.elapsed() >= Duration::from_secs(1) {
                    accept_window = Instant::now();
                    accepted_this_second = 0;
                }
                accepted_this_second += 1;
                if sockets.lock().unwrap().len() >= max_clients || accepted_this_second > 16 {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    drop(tcp);
                    continue;
                }
                id += 1;
                metrics.connections.fetch_add(1, Ordering::Relaxed);
                let clone = match tcp.try_clone() {
                    Ok(c) => c,
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                };
                sockets.lock().unwrap().insert(id, clone);
                let session = Session {
                    id,
                    pool: pool.clone(),
                    sockets: sockets.clone(),
                };
                let (config, metrics) = (config.clone(), metrics.clone());
                let handle = thread::Builder::new()
                    .name(format!("rammesh-{id}"))
                    .stack_size(512 * 1024)
                    .spawn(move || {
                        if let Err(error) = worker(tcp, session, config, metrics, timeout, lease, reserve) {
                            eprintln!("{}",json!({"event":"session_closed","session":id,"reason":error.to_string()}));
                        }
                    });
                match handle {
                    Ok(h) => workers.push(h),
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        if health.elapsed() >= Duration::from_secs(5) {
            match MemoryInfo::get() {
                Ok(info) => eprintln!(
                    "{}",
                    json!({"event":"monitor","pool":pool.lock().unwrap().stats(),
                    "system":info.json(),"metrics":metrics.json()})
                ),
                Err(e) => {
                    result = Err(e);
                    shutdown.store(true, Ordering::Relaxed);
                }
            }
            health = Instant::now();
        }
    }
    drop(listener);
    for socket in sockets.lock().unwrap().values() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    for h in workers {
        if h.join().is_err() {
            result = Err(io::Error::other("worker panicked"));
        }
    }
    let remaining = pool.lock().unwrap().used;
    drop(pool); // Wipes, munlocks and unmaps after every worker has exited.
    eprintln!(
        "{}",
        json!({"event":"clean_shutdown","remaining_allocation_bytes":remaining,
        "released_locked_bytes":capacity,"metrics":metrics.json()})
    );
    result
}

fn pattern(size: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut out = vec![0; size];
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    out
}
fn percentiles(mut ns: Vec<u128>) -> Value {
    ns.sort_unstable();
    let p = |pct: usize| ns[(ns.len() - 1) * pct / 100] as f64 / 1000.;
    json!({"samples":ns.len(),"p50_us":p(50),"p95_us":p(95),"p99_us":p(99),"max_us":p(100)})
}
fn client_command(cmd: &str, mut args: Args) -> io::Result<()> {
    let pki = args.get("--pki", "pki");
    let addr: SocketAddr = args
        .get("--addr", "127.0.0.1:7443")
        .parse()
        .map_err(io::Error::other)?;
    let name = args.get("--server-name", "rammesh-donor");
    let rounds = if cmd == "bench" {
        args.number("--rounds", 3, 1, 20)?
    } else {
        0
    };
    let (mib, seconds) = if cmd == "hold" {
        (
            args.number("--mib", 32, 1, 4096)?,
            args.number("--seconds", 30, 1, 3600)?,
        )
    } else {
        (0, 0)
    };
    args.done()?;
    let mut client = Client::connect(addr, Path::new(&pki), &name)?;
    match cmd {
        "stats" => println!("{}", serde_json::to_string_pretty(&client.stats()?)?),
        "demo" => {
            let (id, _) = client.alloc((2 * MIB + 17) as u64)?;
            let mut expected = Sha256::new();
            let mut actual = Sha256::new();
            for (i, n) in [MIB, MIB, 17].into_iter().enumerate() {
                let bytes = pattern(n, 0xbadc0ffee + i as u64);
                let offset = (i * MIB) as u64;
                client.write(id, offset, &bytes)?;
                client.verify(id, offset, &bytes)?;
                expected.update(&bytes);
                actual.update(client.read(id, offset, n as u32)?);
            }
            let expected = expected.finalize();
            let actual = actual.finalize();
            if expected != actual {
                return Err(io::Error::other("round trip integrity failure"));
            }
            let evidence = client.stats()?;
            client.free(id)?;
            println!(
                "{}",
                json!({"event":"demo_pass","bytes":2*MIB+17,
                "sha256":format!("{actual:x}"),"evidence":evidence})
            );
        }
        "bench" => {
            let mut rows = vec![];
            for size in [4096, 65536, MIB] {
                let iterations = if size == 4096 {
                    1000
                } else if size == 65536 {
                    256
                } else {
                    128
                };
                let data = pattern(size, 0x12345678);
                let (id, _) = client.alloc((32 * MIB) as u64)?;
                for _ in 0..10 {
                    client.write(id, 0, &data)?;
                    client.read(id, 0, size as u32)?;
                }
                let mut writes = vec![];
                let mut reads = vec![];
                let mut write_secs = 0.;
                let mut read_secs = 0.;
                for _ in 0..rounds {
                    for i in 0..iterations {
                        let offset = (i % (32 * MIB / size) * size) as u64;
                        let t = Instant::now();
                        client.write(id, offset, &data)?;
                        let elapsed = t.elapsed();
                        write_secs += elapsed.as_secs_f64();
                        writes.push(elapsed.as_nanos());
                    }
                    for i in 0..iterations {
                        let offset = (i % (32 * MIB / size) * size) as u64;
                        let t = Instant::now();
                        let got = client.read(id, offset, size as u32)?;
                        let elapsed = t.elapsed();
                        read_secs += elapsed.as_secs_f64();
                        reads.push(elapsed.as_nanos());
                        if got != data {
                            return Err(io::Error::other("benchmark integrity failure"));
                        }
                    }
                }
                client.verify(id, 0, &data)?;
                client.free(id)?;
                let transferred = (rounds * iterations * size) as f64 / MIB as f64;
                rows.push(
                    json!({"block_bytes":size,"rounds":rounds,"iterations_per_round":iterations,
                    "write_mib_s":transferred/write_secs,"read_mib_s":transferred/read_secs,
                    "write_latency":percentiles(writes),"read_latency":percentiles(reads)}),
                );
            }
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"event":"benchmark","transport":"TLS1.3/mTLS TCP",
                "endpoint":addr.to_string(),"scope":"sequential RPC; established connection; same-Mac loopback when addr is loopback; no LAN measurement",
                "timing":"RPC elapsed; read comparison is outside measured interval; no pipelining",
                "rows":rows,"final_stats":client.stats()?})
                )?
            );
        }
        "hold" => {
            let (id, _) = client.alloc((mib * MIB) as u64)?;
            for i in 0..mib {
                client.write(id, (i * MIB) as u64, &pattern(MIB, i as u64 + 1))?;
            }
            println!("{}", json!({"event":"holding","evidence":client.stats()?}));
            for _ in 0..seconds {
                thread::sleep(Duration::from_secs(1));
                client.rpc(PING, &[])?;
            }
            for i in 0..mib {
                client.verify(id, (i * MIB) as u64, &pattern(MIB, i as u64 + 1))?;
            }
            println!(
                "{}",
                json!({"event":"hold_verified","evidence":client.stats()?})
            );
            client.free(id)?;
        }
        _ => return Err(io::Error::other("unknown command")),
    }
    Ok(())
}
fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    if cmd.is_empty() || cmd == "--help" || cmd == "help" {
        println!("{HELP}");
        return Ok(());
    }
    let args = Args::new(args)?;
    match cmd.as_str() {
        "inspect" => {
            args.done()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&MemoryInfo::get()?.json())?
            );
            Ok(())
        }
        "serve" => serve(args),
        "stats" | "demo" | "bench" | "hold" => client_command(&cmd, args),
        _ => Err(io::Error::other("unknown command; run rammesh --help")),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("rammesh: {e}");
        std::process::exit(1);
    }
}
