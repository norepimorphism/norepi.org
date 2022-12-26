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
    // The `uri` here is really a *request-target* as specified by Section 5.3 of RFC 7230; see
    // <https://httpwg.org/specs/rfc7230.html#request-target>.
    let (method, uri) = (req.method(), req.uri());
    tracing::debug!("{} {}", method, uri);

    let mut res = match method {
        // `GET` returns the content of a resource in its response body.
        &Method::GET => get(&req).await,
        // `HEAD` is like `GET` but without the response body.
        &Method::HEAD => get(&req).await.map(|mut res| {
            *res.body_mut() = Body::empty();

            res
        }),
        // `OPTIONS` informs clients on which HTTP methods are available. `OPTIONS *` returns an
        // empty 204 response whereas anything else returns the available HTTP methods in an
        // `Allow` header.
        &Method::OPTIONS => {
            if uri == "*" {
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
        }
        _ => {
            res!("405.html" -> METHOD_NOT_ALLOWED)
                .build()
                .map(|res| {
                    res.headers_mut().insert("Allow", HeaderValue::from_static(ALLOW));

                    res
                })
        }
    }?;

    res.headers_mut().insert("Server", HeaderValue::from_static(SERVER));

    Ok(res)
}

pub async fn get(req: &Request<Body>) -> Result<Response<Body>, http::Error> {
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
