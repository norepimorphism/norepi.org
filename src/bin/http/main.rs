// SPDX-License-Identifier: MPL-2.0

#![feature(byte_slice_trim_ascii, ip)]

use std::{env, fmt, fs, future::Future, io::Write as _, net::{Ipv4Addr, SocketAddr}, sync::{Arc, Mutex}};

use hyper::{
    header::HeaderValue,
    http,
    server::conn::{AddrIncoming, AddrStream},
    service::{make_service_fn, service_fn, Service},
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
};

use resource::{Builder as ResourceBuilder, Resource};

mod resource;

static SERVER: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
static ALLOW: &str = "GET, HEAD, OPTIONS";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    norepi_site::run(run).await
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
    let local_addr = (Ipv4Addr::UNSPECIFIED, 80).into();
    let incoming = AddrIncoming::bind(&local_addr)?;
    // let server = rustls::ServerConfig::builder()
    //     .with_safe_defaults()
    //     .with_no_client_auth()
    //     .with_single_cert(tls_certs(), tls_key())
    //     .expect("failed to build server configuration");

    Server::builder(incoming)
        .serve(make_service_fn(move |sock| {
            // This closure is invoked for each remote connection, so we need to clone `report` to
            // use it.
            let report = Arc::clone(&report);

            let result = Ok::<_, http::Error>(handle_remote(report, sock));

            async move { result }
        }))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install shutdown signal handler")
        })
        .await
}

#[allow(dead_code)]
fn tls_certs() -> Vec<rustls::Certificate> {
    rustls_pemfile::certs(&mut norepi_site::cert::FULLCHAIN)
        .expect("failed to read full certificate chain")
        .into_iter()
        .map(rustls::Certificate)
        .collect()
}

#[allow(dead_code)]
fn tls_key() -> rustls::PrivateKey {
    rustls_pemfile::rsa_private_keys(&mut norepi_site::cert::RSA_KEY)
        .expect("failed to read RSA private keys")
        .into_iter()
        .next()
        .map(rustls::PrivateKey)
        .expect("RSA private key is missing")
}

fn handle_remote<'report, 'sock>(
    report: Arc<Mutex<csv::Writer<fs::File>>>,
    sock: &AddrStream,
) -> impl Service<Request<Body>, Response = Response<Body>, Error = http::Error, Future = impl Future<Output = Result<Response<Body>, http::Error>> + Sync> {
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

    // | Date | IP Address | TCP Port | HTTP Method | Resouce URI | User Agent |
    // |------|------------|----------|-------------|-------------|------------|
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

    if let Some(entry) = norepi_site::blocklist::find(&remote_addr.ip()) {
        tracing::warn!("request was blocked: {:#?}", entry);

        // RFC 9110, Section 15.5.4:
        //   The 403 (Forbidden) status code indicates that the server understood
        //   the request but refuses to fulfill it. A server that wishes to make
        //   public why the request has been forbidden can describe the reason in
        //   the response content (if any).
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.5.4>.
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body({
                format!(
                    "You are blocked from accessing this webserver. Reason: {}",
                    entry.reason,
                )
                .into()
            })
    } else {
        respond(req)
    }
}

fn respond(req: Request<Body>) -> Result<Response<Body>, http::Error> {
    tracing::debug!(
        "{} {}",
        req.method(),
        // `req.uri()` is really a *request-target* as specified by Section 5.3 of RFC 7230; see
        // <https://httpwg.org/specs/rfc7230.html#request-target>.
        req.uri(),
    );

    let response = match req.method() {
        // RFC 9110, Section 9.3.1:
        //   The GET method request transfer of a current selected representation for the target
        //   resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.1>.
        &Method::GET => get(&req).response(),
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
            // fields, though RFC 9110 indicates that this is not preferred. Is there a signficiant
            // performance cost to doing this?
            get(&req).response().map(|mut res| {
                // Discard the body.
                *res.body_mut() = Body::empty();

                res
            })
        }
        // `OPTIONS` lists all HTTP methods supported by a resource in the `Allow` header.
        &Method::OPTIONS => {
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Allow", ALLOW)
                .body(Body::empty())
        }
        &Method::POST
        | &Method::PUT
        | &Method::DELETE
        | &Method::CONNECT
        | &Method::TRACE
        | &Method::PATCH => {
            resource::include!("405"."html")
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .build()
                .response()
        }
        // RFC 9110, Section 15.6.2:
        //   [501 (Not Implemented)] is the appropriate response when the server does not recognize
        //   the request method and is not capable of supporting it for any resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.6.2>.
        _ => {
            resource::include!("501"."html")
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

fn get(req: &Request<Body>) -> Result<Response<Body>, http::Error> {
    let resource = match req.uri().path() {
        "/" => resource::include!("index"."html"),
        "/base.css" => resource::include!("base"."css"),
        "/error.css" => resource::include!("error"."css"),
        "/contact" => resource::include!("contact"."html"),
        "/noctane" => resource::include!("noctane"."html"),
        "/source" => resource::include!("source"."html"),
        "/robots.txt" => resource::include!("robots"."txt"),
        _ => resource::include!("404"."html").status(StatusCode::NOT_FOUND),
    }
    .build();

    match resource.check_request_is_well_formed(&req) {
        Ok(_) => resource.response(),
        Err(res) => {
            tracing::error!("request was malformed");

            // The request was malformed, so a response containing error information was returned.
            res
        }
    }
}
