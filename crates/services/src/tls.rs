// SPDX-License-Identifier: MPL-2.0

use std::{future::Future, io, pin::Pin, sync::Arc, task::{self, Poll}};

use hyper::server::{accept::Accept, conn::{AddrIncoming, AddrStream}};
use tokio_rustls::rustls as rustls;

impl Acceptor {
    pub fn bind(port: u16) -> hyper::Result<Self> {
        let addr = (norepi_site_util::bind::PUBLIC_ADDR, port).into();

        AddrIncoming::bind(&addr).map(Self::new)
    }

    fn new(incoming: AddrIncoming) -> Self {
        Self {
            config: Arc::new(config()),
            incoming,
        }
    }
}

fn config() -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs(), private_key())
        .expect("failed to build server configuration")
}

static FULLCHAIN: &[u8] = include_bytes!("tls/fullchain.pem");
static PRIVKEY: &[u8] = include_bytes!("tls/privkey.pem");

fn certs() -> Vec<rustls::Certificate> {
    rustls_pemfile::certs(&mut &*FULLCHAIN)
        .expect("failed to read full certificate chain")
        .into_iter()
        .map(rustls::Certificate)
        .collect()
}

fn private_key() -> rustls::PrivateKey {
    rustls_pemfile::pkcs8_private_keys(&mut &*PRIVKEY)
        .expect("failed to read RSA private keys")
        .into_iter()
        .map(rustls::PrivateKey)
        .next()
        .expect("private key is missing")
}

pub struct Acceptor {
    config: Arc<rustls::ServerConfig>,
    incoming: AddrIncoming,
}

impl Accept for Acceptor {
    type Conn = Stream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();

        match Pin::new(&mut pin.incoming).poll_accept(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                tracing::trace!("incoming request from {}", stream.remote_addr());

                // Note: this is where, in the future, we will want to deny incoming
                // connections from hosts that are so malicious they are not even worth
                // handshaking with.

                let handshake = tokio_rustls::TlsAcceptor::from(pin.config.clone())
                    .accept(stream);
                // FIXME: should we be blocking here?
                let result = tokio::runtime::Handle::current()
                    .block_on(handshake);

                Poll::Ready(Some(result))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub type Stream = tokio_rustls::server::TlsStream<AddrStream>;
