// SPDX-License-Identifier: MPL-2.0

#![feature(associated_type_bounds, byte_slice_trim_ascii, ip)]

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
    server::{accept::Accept, conn::{AddrIncoming, AddrStream}},
    service::{make_service_fn, service_fn, Service},
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
    Uri,
};
use tokio::io::{AsyncRead, AsyncWrite};

mod resource;

/// The *Server* header of a response to a successful request.
static SERVER: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
/// The *Allow* header of a response to a successful `OPTIONS` request.
static ALLOW: &str = "GET, HEAD, OPTIONS";

fn main() -> std::process::ExitCode {
    norepi_site_util::run_async(run)
}

async fn run() -> hyper::Result<()> {
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
    tokio::try_join!(
        serve::<Http>(Arc::clone(&report)),
        serve::<Https>(Arc::clone(&report)),
    )?;

    Arc::try_unwrap(report)
        .expect("Arc has other references")
        .into_inner()
        .expect("mutex is poisoned")
        .flush()
        .expect("failed to flush CSV writer");

    Ok(())
}

trait Protocol: 'static {
    type Incoming: Accept;

    fn incoming() -> hyper::Result<Self::Incoming>;

    fn addr_stream(stream: &<Self::Incoming as Accept>::Conn) -> &AddrStream;

    fn respond_to_request(req: Request<Body>) -> Result<Response<Body>, http::Error>;
}

async fn serve<P: Protocol>(report: Arc<Mutex<csv::Writer<fs::File>>>) -> hyper::Result<()>
where
    <P::Incoming as Accept>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    <P::Incoming as Accept>::Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Server::builder(P::incoming()?)
        .serve(make_service_fn(move |stream| {
            // This closure is invoked for each remote connection, so we need to clone `report` to
            // use it.
            let report = Arc::clone(&report);

            let stream = P::addr_stream(stream);
            let result = Ok::<_, http::Error>(create_service::<P>(report, stream));

            async move { result }
        }))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install shutdown signal handler")
        })
        .await?;

    Ok(())
}

fn create_service<P: Protocol>(
    report: Arc<Mutex<csv::Writer<fs::File>>>,
    stream: &AddrStream,
) -> impl Sync + Service<
    Request<Body>,
    Response = Response<Body>,
    Error = http::Error,
    Future = impl Future<Output = Result<Response<Body>, http::Error>>
> {
    let remote_addr = stream.remote_addr();

    service_fn(move |req| {
        // This closure is invoked for each request, so we need to clone `report` to use it.
        let report = Arc::clone(&report);

        let result = handle_request::<P>(report, remote_addr, req);

        async move { result }
    })
}

fn handle_request<P: Protocol>(
    report: Arc<Mutex<csv::Writer<fs::File>>>,
    remote_addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
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
    match norepi_site_host_db::client::get_host(remote_ip) {
        Ok(response) => {
            let is_blocked = match response {
                norepi_site_host_db::client::GetHostResponse::Found(host) => host.is_blocked(),
                norepi_site_host_db::client::GetHostResponse::NotFound => {
                    // Make a new entry for this host.
                    if let Err(e) = norepi_site_host_db::client::set_host(
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
                    .content(
                        b"You are blocked from accessing norepi.org and its subdomains. If you \
                        think this is a mistake, please shoot an email to norepi@protonmail.com.",
                    )
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

    P::respond_to_request(req)
}

struct Http;

impl Protocol for Http {
    type Incoming = AddrIncoming;

    fn incoming() -> hyper::Result<Self::Incoming> {
        norepi_site_services::sock::bind(80)
    }

    fn addr_stream(stream: &<Self::Incoming as hyper::server::accept::Accept>::Conn) -> &AddrStream {
        stream
    }

    fn respond_to_request(_req: Request<Body>) -> Result<Response<Body>, http::Error> {
        // Redirect to HTTPS.
        Response::builder()
            // RFC 9110, Section 15.4.2:
            //   The 301 (Moved Permanently) status code indicates that the target resource has been
            //   assigned a new permanent URI and any future references to this resource ought to
            //   use one of the enclosed URIs. The server is suggesting that a user agent with link-
            //   editing capability can permanently replace references to the target URI with one of
            //   the new references sent by the server.
            //
            //   The server SHOULD generate a Location header field in the response containing a
            //   preferred URI reference for the new permanent URI. The user agent MAY use the
            //   Location field for automatic redirection.
            //
            //   Note: For historical reasons, a user agent MAY change the request method from POST
            //   to GET for the subsequent request.

            // FIXME: if the UA sends a POST request next, should we allow them access to the site?
            // It would be nice (though not necessary) to support old browsers, including those
            // which do not support HTTPS.
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, "https://norepi.org")
            .body(Body::empty())
    }
}

struct Https;

impl Protocol for Https {
    type Incoming = norepi_site_services::tls::Acceptor;

    fn incoming() -> hyper::Result<Self::Incoming> {
        norepi_site_services::tls::Acceptor::bind(443)
    }

    fn addr_stream(stream: &<Self::Incoming as hyper::server::accept::Accept>::Conn) -> &AddrStream {
        stream.get_ref().0
    }

    fn respond_to_request(req: Request<Body>) -> Result<Response<Body>, http::Error> {
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
            //   The HEAD method is identical to GET except that the server MUST NOT send content in
            //   the response.
            //   ...
            //   The server SHOULD send the same header fields in response to a HEAD request as it
            //   would have sent if the request method had been GET. However, a server MAY omit
            //   header fields for which a value is determined only while generating the content.
            //   ...
            //   ...a response to GET might contain Content-Length and Vary fields, for example,
            //   that are not generated within a HEAD response. These minor inconsistencies are
            //   considered preferable to generating and discarding the content for a HEAD request,
            //   since HEAD is usually requested for the sake of efficiency.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.2>.
            &Method::HEAD => {
                // TODO: Our approach is to generate a GET response and discard the body and
                // irrelevant fields, though RFC 9110 indicates that this is not preferred. Is there
                // a significant performance cost to doing this?
                get(&req).map(|mut response| {
                    // Discard the body.
                    *response.body_mut() = Body::empty();
                    // TODO: Maybe discard *Content-Length* as well?

                    response
                })
            }
            // RFC 9110, Section 9.3.7:
            //   The OPTIONS method request information about the communication options available
            //   for the target resource, at either the origin server or an intervening
            //   intermediary.
            //   ...
            //   A server generating a successful response to OPTIONS SHOULD send any header that
            //   might indicate optional features implemented by the server and applicable to the
            //   target resource (e.g., Allow), including potential extensions not defined by this
            //   specification.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.7>.
            &Method::OPTIONS => {
                let response = Response::builder().status(StatusCode::NO_CONTENT);

                // RFC 9110, Section 9.3.7:
                //   An OPTIONS request with an asterisk ("*") as the request target applies to the
                //   server in general rather than to a specific resource. Since a server's
                //   communication options typically depend on the resource, the "*" request is only
                //   useful as a "ping" or "no-op" type of method; it does nothing beyond allowing
                //   the client to test the capabilities of the server.
                if req_target.path().as_bytes() == b"*" {
                    response.body(Body::empty())
                } else {
                    response
                        // TODO: In the future, not all resources might implement the methods
                        // described by [`ALLOW`]. We should have a more fine-grained approach.
                        .header(header::ALLOW, ALLOW)
                        .body(Body::empty())
                }
            }
            // RFC 9110, Section 15.5.6:
            //   The 405 (Method Not Allowed) status code indicates that the method received in the
            //   request-line is known by the origin server but not supported by the target
            //   resource. The origin server MUST generate an Allow header field in a 405 response
            //   containing a list of the target resource's currently supported methods.
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
            //   The 501 (Not Implemented) status code indicates that the server does not support
            //   the functionality required to fulfill the request. This is the appropriate response
            //   when the server does not recognize the request method and is not capable of
            //   supporting it  for any resource.
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
        //   The "Server" header field contains information about the software used by the origin
        //   server to handle the request.... An origin server MAY generate a Server header field in
        //   its responses.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.10.2.4>.
        headers.insert(header::SERVER, HeaderValue::from_static(SERVER));
        // RFC 6797, Section 6.1:
        //   The Strict-Transport-Security HTTP response header (STS header field) indicates to a UA
        //   that it MUST enforce the HSTS Policy in regards to the host emitting the response
        //   message containing this header field.
        //
        // See <https://www.rfc-editor.org/rfc/rfc6797#section-6.1>.
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(concat!(
                // RFC 6797, Section 6.1.1:
                //   The REQUIRED "max-age" directive specifies the number of seconds, after the
                //   reception of the STS header field, during which the UA regards the host (from
                //   whom the message was received) as a Known HSTS Host.

                // FIXME: we will want to bump this up over time. The recommended end goal is two
                //  years.
                "max-age=604800;",
                // RFC 6797, Section 6.1.2:
                //   The OPTIONAL "includeSubDomains" directive is a valueless directive which, if
                //   present (i.e., it is "asserted"), signals the UA that the HSTS policy applies
                //   applies to this HSTS host as well as any subdomains of the host's domain name.

                // Note: while technically made optional by the standard, this directive is a
                // prerequisite for HSTS preloading.
                "includeSubDomains",
            )),
        );

        Ok(response)
    }
}

fn target_is_malicious(uri: &Uri) -> bool {
    let path = uri.path();
    if matches!(
        path,
        "/boaform/admin/formLogin"
        // This is a honeypot.
        | "/you-may-be-banned-if-you-access-this-resource",
    ) {
        return true;
    }

    let mut components = path.rsplit('/');
    if let Some(filename) = components.next() {
        if matches!(filename, ".env") {
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
        "/favicon.ico" => resource::include_!("favicon"."png"),
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
