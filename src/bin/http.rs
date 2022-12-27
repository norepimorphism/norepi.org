// SPDX-License-Identifier: MPL-2.0

use http::HeaderValue;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
};

static SERVER: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
static ALLOW: &str = "GET, HEAD, OPTIONS";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    norepi_site::run(serve).await
}

async fn serve() -> Result<(), hyper::Error> {
    let addr = ([0; 4], 80).into();
    tracing::info!("Binding to {}", addr);

    Server::bind(&addr)
        .serve(make_service_fn(|sock: &AddrStream| {
            tracing::trace!("Incoming request from {}", sock.remote_addr());

            async move { Ok::<_, http::Error>(service_fn(respond)) }
        }))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install shutdown signal handler")
        })
        .await
}

macro_rules! res {
    ($filename:literal $(-> $status:ident)? $(,)?) => {{
        #[allow(unused_variables)]
        let status = StatusCode::OK;
        $(
            let status = StatusCode::$status;
        )?

        Resource {
            status,
            content: include_str!(concat!(env!("OUT_DIR"), "/gen/", $filename)),
        }
    }};
}

async fn respond(req: Request<Body>) -> Result<Response<Body>, http::Error> {
    tracing::debug!(
        "{} {}",
        req.method(),
        // `req.uri()` is really a *request-target* as specified by Section 5.3 of RFC 7230; see
        // <https://httpwg.org/specs/rfc7230.html#request-target>.
        req.uri(),
    );

    let mut res = match check_request_is_well_formed(&req) {
        Ok(_) => respond_to_well_formed_request(&req).await?,
        Err(res) => {
            // The request was malformed, so a response containing error information was returned.
            res?
        }
    };

    // Append default response headers.

    let headers = res.headers_mut();
    // RFC 9110, Section 8.5:
    //   The "Content-Language" header field describes the natural language(s) of the intended
    //   audience for the representation.
    //   ...
    //   Content-Language MAY be applied to any media type---it is not limited to textual documents.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.8.5>.
    headers.insert("Content-Language", HeaderValue::from_static("en"));
    // RFC 9110, Section 10.2.4:
    //   The "Server" header field contains information about the software used by the origin server
    //   to handle the request.... An origin server MAY generate a Server header field in its
    //   responses.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.10.2.4>.
    headers.insert("Server", HeaderValue::from_static(SERVER));

    Ok(res)
}

fn check_request_is_well_formed(
    req: &Request<Body>,
) -> Result<(), Result<Response<Body>, http::Error>> {
    let headers = req.headers();

    // RFC 9110, Section 15.5.7:
    //   The 406 (Not Acceptable) status code indicates that the target resource does not have a
    //   current representation that would be acceptable to the user agent, according to the
    //   proactive negotiation header fields received... and the server is unwilling to supply a
    //   default representation.
    //
    //   The server SHOULD generate contant containing a list of representation characteristics and
    //   corresponding resource identifiers from which the user or user agent can choose the one
    //   most appropriate.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.5.7>.
    let not_acceptable = || {
        Err(res!("406.html" -> NOT_ACCEPTABLE).build())
    };

    // RFC 9110, Section 12.5.2:
    //   Note: Accept-Charset is deprecated because UTF-8 has become nearly ubiquitous.... Most
    //   general-purpose user agents do not send Accept-Charset unless specifically configured to do
    //   so.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.2>.
    if let Some(value) = headers.get("Accept-Charset") {
        // Despite the deprecation, in the interest of compatibility, we will accept
        // `Accept-Charset` headers that request UTF-8.
        if !accept_charset_requests_utf8(value) {
            return not_acceptable();
        }
    }

    // RFC 9110, Section 12.5.3:
    //   When sent by a user agent in a request, Accept-Encoding indicates the content codings
    //   acceptable in a response.
    //   ...
    //   An "identity" token is used as a synonym for "no encoding" in order to communicate when no
    //   encoding is preferred.
    //
    // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.3>.
    if let Some(value) = headers.get("Accept-Encoding") {
        // Resource content will be returned as-is; hence, we will only accept `Accept-Encoding`
        // headers that request `identity`.
        if !accept_encoding_requests_identity(value) {
            // RFC 9110, Section 12.5.3:
            //   Servers that fail a request due to an unsupported content coding ought to respond
            //   with a 415 (Unsupported Media Type) status and include an Accept-Encoding header
            //   field in that response, allowing clients to distinguish between issues related to
            //   content codings and media types.
            return Err(res!("415.html" -> UNSUPPORTED_MEDIA_TYPE).build());
        }
    }

    if let Some(value) = headers.get("Accept-Language") {
        if !accept_language_requests_en(value) {
            return not_acceptable();
        }
    }

    Ok(())
}

fn accept_charset_requests_utf8(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();

    // RFC 9110, Section 12.5.2:
    //   The special value "*", if present in the Accept-Charset header field, matches every charset
    //   that is not mentioned elsewhere in the field.
    if bytes.contains(&b'*') {
        // If a `*` is present---even if it has a low priority---UTF-8 will be requested. Either
        // both UTF-8 and `*` are listed, in which case UTF-8 is obviously requested, or only `*` is
        // listed, in which case UTF-8 is indirectly requested through use of this wildcard.
        return true;
    }

    // We will also check if the field contains the case-insensitive literal "UTF-8", in which case
    // UTF-8 is explicitly requested.
    //
    // TODO: The algorithm used here is not particularly rigorous, and it may generate false
    // positives if a listed charset contains the case-insensitive string "utf-8" but *does not*, in
    // full, match the string "utf-8".
    let utf8_token = b"utf-8";
    if bytes
        // From `value`, generate overlapping byte sequences each with the length of `utf8_token`.
        .windows(utf8_token.len())
        // Test each byte sequence to see if it matches `utf8_token`.
        .find(|token| {
            // `Accept-Charset` is not case-sensitive, so we must be careful to compare
            // insensitively.
            token.eq_ignore_ascii_case(utf8_token)
        })
        .is_some()
    {
        return true;
    }

    false
}

fn accept_encoding_requests_identity(value: &HeaderValue) -> bool {
    if value.is_empty() {
        return true;
    }

    let bytes = value.as_bytes();

    if bytes.contains(&b'*') {
        return true;
    }

    let identity_token = b"identity";
    if bytes
        .windows(identity_token.len())
        .find(|token| token.eq_ignore_ascii_case(identity_token))
        .is_some()
    {
        return true;
    }

    false
}

fn accept_language_requests_en(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();

    // RFC 4647, Section 3.3.1:
    //   The special range "*" in a language priority list matches any tag.
    //
    // See <https://www.rfc-editor.org/rfc/rfc4647.html#section-3.3.1>.
    if bytes.contains(&b'*') {
        return true;
    }

    let en_token = b"en";
    if let Some(start_idx) = bytes
        .windows(en_token.len())
        .enumerate()
        .find(|(_, token)| token.eq_ignore_ascii_case(en_token))
        .map(|(idx, _)| idx)
    {
        let has_prev_whitespace = start_idx
            .checked_sub(1)
            .map(|idx| {
                // SAFETY: TODO
                unsafe { bytes.get_unchecked(idx) }.is_ascii_whitespace()
            })
            .unwrap_or(true);
        let has_next_whitespace = bytes
            .get(start_idx + en_token.len())
            .map(|c| c.is_ascii_whitespace())
            .unwrap_or(true);

        let is_full_word = has_prev_whitespace && has_next_whitespace;
        if is_full_word {
            return true;
        }
    }

    false
}

async fn respond_to_well_formed_request(
    req: &Request<Body>,
) -> Result<Response<Body>, http::Error> {
    match req.method() {
        // RFC 9110, Section 9.3.1:
        //   The GET method request transfer of a current selected representation for the target
        //   resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.1>.
        &Method::GET => get(req).await,
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
            get(req).await.map(|mut res| {
                // Discard the body.
                *res.body_mut() = Body::empty();
                // Discard headers that RFC 9110 suggests "might not [be] generated within a HEAD
                // response."
                for name in ["Content-Length", "Vary"] {
                    let _ = res.headers_mut().remove(name);
                }

                res
            })
        }
        // `OPTIONS` lists all HTTP methods supported by a resource in the `Allow` header.
        &Method::OPTIONS => {
            if req.uri() == "*" {
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
            } else {
                // The HTTP methods offered by *proxie*.
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
            res!("405.html" -> METHOD_NOT_ALLOWED).build()
        }
        // RFC 9110, Section 15.6.2:
        //   [501 (Not Implemented)] is the appropriate response when the server does not recognize
        //   the request method and is not capable of supporting it for any resource.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.6.2>.
        _ => res!("501.html" -> NOT_IMPLEMENTED).build(),
    }
}

async fn get(req: &Request<Body>) -> Result<Response<Body>, http::Error> {
    match req.uri().path() {
        "/" => res!("index.html"),
        "/base.css" => res!("base.css"),
        "/error.css" => res!("error.css"),
        "/contact" => res!("contact.html"),
        "/noctane" => res!("noctane.html"),
        "/source" => res!("source.html"),
        _ => res!("404.html" -> NOT_FOUND),
    }
    .build()
}

struct Resource {
    status: StatusCode,
    content: &'static str,
}

impl Resource {
    fn build(self) -> Result<Response<Body>, http::Error> {
        Response::builder()
            .status(self.status)
            .body(self.content.into())
    }
}
