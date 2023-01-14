// SPDX-License-Identifier: MPL-2.0

use std::{future::Future as _, io, pin::Pin, sync::Arc, task::{self, Poll}};

use hyper::server::{accept::Accept, conn::{AddrIncoming, AddrStream}};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls as rustls;

impl Acceptor {
    pub fn new(incoming: AddrIncoming) -> Self {
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
            Poll::Ready(Some(result)) => {
                Poll::Ready(Some(result.map(|sock| {
                    let accept = tokio_rustls::TlsAcceptor::from(pin.config.clone()).accept(sock);

                    Stream { state: StreamState::Handshaking(accept) }
                })))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct Stream {
    state: StreamState,
}

enum StreamState {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

impl AsRef<AddrStream> for Stream {
    fn as_ref(&self) -> &AddrStream {
        match self.state {
            StreamState::Handshaking(ref accept) => accept.get_ref().unwrap(),
            StreamState::Streaming(ref stream) => stream.get_ref().0,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();

        match pin.state {
            StreamState::Handshaking(ref mut accept) => {
                match Pin::new(accept).poll(cx) {
                    Poll::Ready(Ok(mut stream)) => {
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        pin.state = StreamState::Streaming(stream);

                        result
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            StreamState::Streaming(ref mut stream) => {
                Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let pin = self.get_mut();

        match pin.state {
            StreamState::Handshaking(ref mut accept) => {
                match Pin::new(accept).poll(cx) {
                    Poll::Ready(Ok(mut stream)) => {
                        let result = Pin::new(&mut stream).poll_write(cx, buf);
                        pin.state = StreamState::Streaming(stream);

                        result
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            StreamState::Streaming(ref mut stream) => {
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.state {
            StreamState::Handshaking(_) => Poll::Ready(Ok(())),
            StreamState::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.state {
            StreamState::Handshaking(_) => Poll::Ready(Ok(())),
            StreamState::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
