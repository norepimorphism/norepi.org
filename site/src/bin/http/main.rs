// SPDX-License-Identifier: MPL-2.0

#![feature(byte_slice_trim_ascii, ip)]

use std::{
    env,
    fs,
    future::Future,
    io::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hyper::{
    header::{self, HeaderValue},
    http,
    server::conn::{AddrIncoming, AddrStream},
    service::{make_service_fn, service_fn, Service},
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
    Uri,
};
use tls_listener::rustls::{rustls as rustls, TlsAcceptor};

mod resource;

/// The *Server* header of a response to a successful request.
static SERVER: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
/// The *Allow* header of a response to a successful `OPTIONS` request.
static ALLOW: &str = "GET, HEAD, OPTIONS";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    norepi_site_util::run_async(run).await
}

async fn run() -> Result<(), hyper::Error> {
    let mut report = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(dirs::home_dir().unwrap_or_default().join("http.csv"))
        .expect("failed to open report file");
    if let Ok(meta) = report.metadata() {
        if meta.len() == 0 {
            writeln!(report, "Date,IP Address,TCP Port,HTTP Method,Resource URI,User Agent")
                .expect("failed to write CSV header");
        }
    }

    let report = csv::Writer::from_writer(report);
    let report = Arc::new(Mutex::new(report));
    serve(Arc::clone(&report)).await?;

    Arc::try_unwrap(report)
        .expect("Arc has other references")
        .into_inner()
        .expect("mutex is poisoned")
        .flush()
        .expect("failed to flush CSV writer");

    Ok(())
}

async fn serve(report: Arc<Mutex<csv::Writer<fs::File>>>) -> Result<(), hyper::Error> {
    let local_addr: SocketAddr = (norepi_site_util::bind::PUBLIC_ADDR, 443).into();

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(tls_certs(), tls_key())
        .expect("failed to build server configuration");
    let acceptor: TlsAcceptor = Arc::new(config).into();
    let listener = tls_listener::builder(acceptor)
        .listen(AddrIncoming::bind(&local_addr)?);

    Server::builder(listener)
        .serve(make_service_fn(move |sock| {
            // This closure is invoked for each remote connection, so we need to clone `report` to
            // use it.
            let report = Arc::clone(&report);

            let result = Ok::<_, http::Error>(create_service(report, sock));

            async move { result }
        }))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install shutdown signal handler")
        })
        .await
}

fn tls_certs() -> Vec<rustls::Certificate> {
    rustls_pemfile::certs(&mut &*norepi_site::cert::FULLCHAIN)
        .expect("failed to read full certificate chain")
        .into_iter()
        .map(rustls::Certificate)
        .inspect(|cert| {
            tracing::info!("using cert: {cert:?}");
        })
        .collect()
}

fn tls_key() -> rustls::PrivateKey {
    rustls_pemfile::pkcs8_private_keys(&mut &*norepi_site::cert::PRIVKEY)
        .expect("failed to read RSA private keys")
        .into_iter()
        .map(rustls::PrivateKey)
        .inspect(|key| {
            tracing::info!("using private key: {key:?}");
        })
        .next()
        .expect("private key is missing")
}

fn create_service(
    report: Arc<Mutex<csv::Writer<fs::File>>>,
    sock: &AddrStream,
) -> impl Sync + Service<
    Request<Body>,
    Response = Response<Body>,
    Error = http::Error,
    Future = impl Future<Output = Result<Response<Body>, http::Error>>
> {
    let remote_addr = sock.remote_addr();

    service_fn(move |req| {
        // This closure is invoked for each request, so we need to clone `report` to use it.
        let report = Arc::clone(&report);

        let result = handle_request(report, remote_addr, req);

        async move { result }
    })
}

fn handle_request(
    report: Arc<Mutex<csv::Writer<fs::File>>>,
    remote_addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    tracing::trace!("incoming request from {}", remote_addr);

    // Acquire the mutex lock.
    let mut report = report.lock().expect("mutex is poisoned");

    // | Date | IP Address | TCP Port | HTTP Method | Resource URI | User Agent |
    // |------|------------|----------|-------------|--------------|------------|
    let _ = report.write_field(chrono::Utc::now().to_string());
    let _ = report.write_field(remote_addr.ip().to_canonical().to_string());
    let _ = report.write_field(remote_addr.port().to_string());
    let _ = report.write_field(req.method().as_str());
    let _ = report.write_field(req.uri().to_string());
    let _ = report.write_field({
        req
            .headers()
            .get(header::USER_AGENT)
            .map(|it| it.as_bytes())
            .unwrap_or(b"")
    });
    // Terminate this record.
    let _ = report.write_record(None::<&[u8]>);

    // Release the mutex lock.
    drop(report);

    let remote_ip = remote_addr.ip();
    match norepi_site_db_hosts::client::get_host(remote_ip) {
        Ok(response) => {
            let is_blocked = match response {
                norepi_site_db_hosts::client::GetHostResponse::Found(host) => host.is_blocked(),
                norepi_site_db_hosts::client::GetHostResponse::NotFound => {
                    // Make a new entry for this host.
                    if let Err(e) = norepi_site_db_hosts::client::set_host(
                        remote_ip,
                        Default::default(),
                    ) {
                        tracing::error!(
                            "failed to insert DB entry for host {}. error: {:#?}",
                            remote_ip,
                            e,
                        );
                    }

                    false
                }
            };

            if is_blocked {
                tracing::warn!("request from {} was blocked", remote_ip);

                // RFC 9110, Section 15.5.4:
                //   The 403 (Forbidden) status code indicates that the server understood the
                //   request but refuses to fulfill it. A server that wishes to make public why the
                //   request has been forbidden can describe the reason in the response content (if
                //   any).
                //
                // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.5.4>.
                return resource::Builder::plaintext()
                    .status(StatusCode::FORBIDDEN)
                    .content(concat!(
                        "You are blocked from accessing norepi.org and its subdomains. If you",
                        " think this is a mistake, please shoot an email to norepi@protonmail.com.",
                    ))
                    .build()
                    .response();
            }
        }
        Err(e) => {
            tracing::error!(
                concat!(
                    "failed to check blocklist for host {}; defaulting to allowing request.",
                    " error: {:#?}",
                ),
                remote_ip,
                e,
            );
        }
    }

    respond(req)
}

fn respond(req: Request<Body>) -> Result<Response<Body>, http::Error> {
    // `req.uri()` is really a *request-target* as specified by Section 5.3 of RFC 7230; see
    // <https://httpwg.org/specs/rfc7230.html#request-target>.
    let req_target = req.uri();
    tracing::debug!("{} {}", req.method(), req_target);

    if target_is_malicious(req_target) {
        tracing::warn!("request is probably malicious");

        // TODO: in the future, this may incur a suspension or ban.
        return Response::builder().status(StatusCode::IM_A_TEAPOT).body(Body::empty());
    }

    let mut response = match req.method() {
        // RFC 9110, Section 9.3.1:
        //   The GET method request transfer of a current selected representation for the target
        //   resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.1>.
        &Method::GET => get(&req),
        // RFC 9110, Section 9.3.2:
        //   The HEAD method is identical to GET except that the server MUST NOT send content in the
        //   response.
        //   ...
        //   The server SHOULD send the same header fields in response to a HEAD request as it would
        //   have sent if the request method had been GET. However, a server MAY omit header fields
        //   for which a value is determined only while generating the content.
        //   ...
        //   ...a response to GET might contain Content-Length and Vary fields, for example, that
        //   are not generated within a HEAD response. These minor inconsistencies are considered
        //   preferable to generating and discarding the content for a HEAD request, since HEAD is
        //   usually requested for the sake of efficiency.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.2>.
        &Method::HEAD => {
            // TODO: Our approach is to generate a GET response and discard the body and irrelevant
            // fields, though RFC 9110 indicates that this is not preferred. Is there a significant
            // performance cost to doing this?
            get(&req).map(|mut response| {
                // Discard the body.
                *response.body_mut() = Body::empty();
                // TODO: Maybe discard *Content-Length* as well?

                response
            })
        }
        // RFC 9110, Section 9.3.7:
        //   The OPTIONS method request information about the communication options available for
        //   the target resource, at either the origin server or an intervening intermediary.
        //   ...
        //   A server generating a successful response to OPTIONS SHOULD send any header that might
        //   indicate optional features implemented by the server and applicable to the target
        //   resource (e.g., Allow), including potential extensions not defined by this
        //   specification.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.7>.
        &Method::OPTIONS => {
            let response = Response::builder().status(StatusCode::NO_CONTENT);

            // RFC 9110, Section 9.3.7:
            //   An OPTIONS request with an asterisk ("*") as the request target applies to the
            //   server in general rather than to a specific resource. Since a server's
            //   communication options typically depend on the resource, the "*" request is only
            //   useful as a "ping" or "no-op" type of method; it does nothing beyond allowing the
            //   client to test the capabilities of the server.
            if req_target.path().as_bytes() == b"*" {
                response.body(Body::empty())
            } else {
                response
                    // TODO: In the future, not all resources might implement the methods described
                    // by [`ALLOW`]. We should have a more fine-grained approach.
                    .header("Allow", ALLOW)
                    .body(Body::empty())
            }
        }
        // RFC 9110, Section 15.5.6:
        //   The 405 (Method Not Allowed) status code indicates that the method received in the
        //   request-line is known by the origin server but not supported by the target resource.
        //   The origin server MUST generate an Allow header field in a 405 response containing a
        //   list of the target resource's currently supported methods.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.5.6>.
        &Method::POST
        | &Method::PUT
        | &Method::DELETE
        | &Method::CONNECT
        | &Method::TRACE
        | &Method::PATCH => {
            resource::include_gen!("405"."html")
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Allow", ALLOW)
                .build()
                .response()
        }
        // RFC 9110, Section 15.6.2:
        //   The 501 (Not Implemented) status code indicates that the server does not support the
        //   functionality required to fulfill the request. This is the appropriate response when
        //   the server does not recognize the request method and is not capable of supporting it
        //   for any resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.6.2>.
        _ => {
            resource::include_gen!("501"."html")
                .status(StatusCode::NOT_IMPLEMENTED)
                .build()
                .response()
        }
    }?;

    // Append default response headers.

    let headers = response.headers_mut();
    // RFC 9110, Section 10.2.4:
    //   The "Server" header field contains information about the software used by the origin server
    //   to handle the request.... An origin server MAY generate a Server header field in its
    //   responses.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.10.2.4>.
    headers.insert(header::SERVER, HeaderValue::from_static(SERVER));

    Ok(response)
}

fn target_is_malicious(uri: &Uri) -> bool {
    let path = uri.path();
    if path == "/boaform/admin/formLogin" {
        return true;
    }

    let mut components = path.rsplit('/');
    if let Some(filename) = components.next() {
        if matches!(filename, "wlwmanifest.xml" | ".env") {
            return true;
        }
    }
    if components.any(|dir| matches!(dir, "wp-admin" | "wp-includes")) {
        return true;
    }

    false
}

fn get(req: &Request<Body>) -> Result<Response<Body>, http::Error> {
    let resource = match req.uri().path() {
        "/robots.txt" => resource::include_!("robots"."txt"),
        "/base.css" => resource::include_gen!("base"."css"),
        "/error.css" => resource::include_gen!("error"."css"),
        "/" => resource::include_gen!("index"."html"),
        "/contact" => resource::include_gen!("contact"."html"),
        "/noctane" => resource::include_gen!("noctane"."html"),
        "/source" => resource::include_gen!("source"."html"),
        "/abuseipdb-verification.html" => resource::include_!("abuseipdb-verification"."txt"),
        _ => resource::include_gen!("404"."html").status(StatusCode::NOT_FOUND),
    }
    .build();

    match resource.is_compatible_with_request(&req) {
        Ok(_) => resource.response(),
        Err(response) => {
            tracing::error!("content negotiation failed");

            // A response containing error information was returned.
            response
        }
    }
}
