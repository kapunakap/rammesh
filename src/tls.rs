use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{
    fs::OpenOptions,
    io::{self, BufReader},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

fn open(path: PathBuf, private: bool) -> io::Result<std::fs::File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || (private && (m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() }))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private key must be an owned regular file with mode 0600 or 0400",
        ));
    }
    Ok(f)
}
fn certs(pki: &Path, name: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(open(pki.join(name), false)?)).collect()
}
fn key(pki: &Path, name: &str) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(open(pki.join(name), true)?))?
        .ok_or_else(|| io::Error::other("no private key in PEM"))
}
fn roots(pki: &Path) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in certs(pki, "ca.crt")? {
        roots.add(cert).map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::other("empty trusted CA"));
    }
    Ok(roots)
}
pub fn server(pki: &Path) -> io::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(pki)?),
        provider.clone(),
    )
    .build()
    .map_err(io::Error::other)?;
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(pki, "donor.crt")?, key(pki, "donor.key")?)
        .map_err(io::Error::other)?;
    c.alpn_protocols = vec![b"rammesh/1".to_vec()];
    c.max_fragment_size = Some(16384);
    // No session resumption: every connection must present its client certificate.
    c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    c.send_tls13_tickets = 0;
    Ok(Arc::new(c))
}
pub fn client(pki: &Path) -> io::Result<Arc<ClientConfig>> {
    let mut c =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_root_certificates(roots(pki)?)
            .with_client_auth_cert(certs(pki, "borrower.crt")?, key(pki, "borrower.key")?)
            .map_err(io::Error::other)?;
    c.alpn_protocols = vec![b"rammesh/1".to_vec()];
    c.max_fragment_size = Some(16384);
    c.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(c))
}
