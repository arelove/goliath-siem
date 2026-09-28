//! TLS for the listeners that face the network.
//!
//! A certificate chain and its private key are read from PEM files at start,
//! so that a missing or broken file fails there, not at the first sender.
//! Handshakes run in their own tasks, so that a sender that stalls in one
//! holds up no other.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;
use tracing::debug;

use crate::RunError;
use crate::config::TlsConfig;

/// How long a sender has to finish its handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Handshaken connections waiting to be served.
const READY: usize = 64;

/// An acceptor for `tls`, offering the protocols in `alpn`.
///
/// # Errors
///
/// Returns [`RunError::Config`] if a file cannot be read, holds no
/// certificate or key, or the key does not match the certificate.
pub(crate) fn acceptor(tls: &TlsConfig, alpn: &[&[u8]]) -> Result<TlsAcceptor, RunError> {
    let failed = |path: &Path, error: &dyn std::fmt::Display| {
        RunError::Config(format!("{}: {error}", path.display()))
    };
    let chain = CertificateDer::pem_file_iter(&tls.certificate)
        .map_err(|error| failed(&tls.certificate, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| failed(&tls.certificate, &error))?;
    if chain.is_empty() {
        return Err(failed(&tls.certificate, &"holds no certificate"));
    }
    let key = PrivateKeyDer::from_pem_file(&tls.key).map_err(|error| failed(&tls.key, &error))?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| RunError::Config(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| failed(&tls.key, &error))?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// A listener whose connections have finished a TLS handshake.
pub(crate) struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    address: SocketAddr,
    accepting: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    /// Accepts on `listener`, handshaking with `acceptor`.
    pub(crate) fn new(listener: TcpListener, acceptor: TlsAcceptor) -> io::Result<Self> {
        let address = listener.local_addr()?;
        let (sender, ready) = mpsc::channel(READY);
        let accepting = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Such as too many open files: wait rather than spin.
                        debug!(%error, "accepting a connection failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (acceptor, sender) = (acceptor.clone(), sender.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let _ = sender.send((stream, peer)).await;
                        }
                        Ok(Err(error)) => debug!(%peer, %error, "a TLS handshake failed"),
                        Err(_) => debug!(%peer, "a TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(Self {
            ready,
            address,
            accepting,
        })
    }

    /// The address it listens on.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// The next connection that has finished its handshake.
    pub(crate) async fn next(&mut self) -> (TlsStream<TcpStream>, SocketAddr) {
        match self.ready.recv().await {
            Some(ready) => ready,
            // The accepting task holds a sender for as long as it runs, and
            // it runs until this listener is dropped.
            None => std::future::pending().await,
        }
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        self.next().await
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.address)
    }
}
