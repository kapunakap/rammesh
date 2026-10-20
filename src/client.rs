use crate::{protocol::*, tls};
use rustls::{ClientConnection, StreamOwned, pki_types::ServerName};
use sha2::{Digest, Sha256};
use std::{
    io,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

/// A total operation deadline, reset once per RPC, so trickled bytes cannot keep an RPC alive forever.
pub struct DeadlineTcp {
    pub tcp: TcpStream,
    pub deadline: Instant,
}
impl DeadlineTcp {
    pub fn new(tcp: TcpStream, timeout: Duration) -> Self {
        Self {
            tcp,
            deadline: Instant::now() + timeout,
        }
    }
    pub fn reset(&mut self, timeout: Duration) {
        self.deadline = Instant::now() + timeout;
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RPC deadline"))
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.remaining()?))?;
        self.tcp.read(b)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.remaining()?))?;
        self.tcp.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

pub struct Client {
    pub stream: StreamOwned<ClientConnection, DeadlineTcp>,
    timeout: Duration,
}
impl Client {
    pub fn connect(addr: SocketAddr, pki: &Path, name: &str) -> io::Result<Self> {
        let timeout = Duration::from_secs(10);
        let tcp = TcpStream::connect_timeout(&addr, timeout)?;
        tcp.set_nodelay(true)?;
        let mut conn = ClientConnection::new(
            tls::client(pki)?,
            ServerName::try_from(name.to_owned()).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        conn.set_buffer_limit(Some(64 * 1024));
        let mut stream = StreamOwned::new(conn, DeadlineTcp::new(tcp, timeout));
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        if stream.conn.alpn_protocol() != Some(b"rammesh/1".as_slice()) {
            return Err(io::Error::other("ALPN mismatch"));
        }
        Ok(Self { stream, timeout })
    }
    pub fn raw(&mut self, op: u8, data: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        self.stream.sock.reset(self.timeout);
        write_frame(&mut self.stream, op, data)?;
        let mut response = read_frame(&mut self.stream)?;
        let status = response.remove(0);
        Ok((status, response))
    }
    pub fn rpc(&mut self, op: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        let (status, data) = self.raw(op, data)?;
        if status != 0 {
            return Err(io::Error::other(format!(
                "remote status {status}: {}",
                String::from_utf8_lossy(&data)
            )));
        }
        Ok(data)
    }
    pub fn alloc(&mut self, n: u64) -> io::Result<(u64, u64)> {
        let b = self.rpc(ALLOC, &n.to_be_bytes())?;
        if b.len() != 16 {
            return Err(io::Error::other("invalid alloc response"));
        }
        Ok((u64_at(&b, 0), u64_at(&b, 8)))
    }
    pub fn read(&mut self, id: u64, offset: u64, n: u32) -> io::Result<Vec<u8>> {
        let mut b = id.to_be_bytes().to_vec();
        b.extend(offset.to_be_bytes());
        b.extend(n.to_be_bytes());
        self.rpc(READ, &b)
    }
    pub fn write(&mut self, id: u64, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut b = id.to_be_bytes().to_vec();
        b.extend(offset.to_be_bytes());
        b.extend(data);
        self.rpc(WRITE, &b)?;
        Ok(())
    }
    pub fn free(&mut self, id: u64) -> io::Result<()> {
        self.rpc(FREE, &id.to_be_bytes())?;
        Ok(())
    }
    pub fn verify(&mut self, id: u64, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut b = id.to_be_bytes().to_vec();
        b.extend(offset.to_be_bytes());
        b.extend((data.len() as u32).to_be_bytes());
        b.extend(Sha256::digest(data));
        self.rpc(VERIFY, &b)?;
        Ok(())
    }
    pub fn stats(&mut self) -> io::Result<serde_json::Value> {
        serde_json::from_slice(&self.rpc(STATS, &[])?).map_err(io::Error::other)
    }
}
