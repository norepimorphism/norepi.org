// SPDX-License-Identifier: MPL-2.0

use hyper::{header, http, Body, Response, StatusCode};

pub mod content_type;

pub use include;
pub use include_content;

macro_rules! include {
    ($file_base:literal . $file_ext:literal $(,)?) => {
        Builder::new(content_type::from_file_ext($file_ext))
            .content($crate::resource::include_content!(concat!($file_base, ".", $file_ext)))
    };
}

macro_rules! include_content {
    ($filename:expr $(,)?) => {
        include_str!(concat!(env!("OUT_DIR"), "/gen/", $filename))
    };
}

impl Builder {
    pub fn binary() -> Self {
        Self::new(conten)
    }

    pub fn css() -> Self {
        Self::new("text/css")
    }

    pub fn html() -> Self {
        Self::new("text/html")
    }

    pub fn plaintext() -> Self {
        Self::new("text/plain")
    }

    pub fn new(content_type: &'static str) -> Self {
        Self {
            content_type,
            status_code: None,
            content: None,
        }
    }
}

pub struct Builder {
    content_type: &'static str,
    status_code: Option<StatusCode>,
    content: Option<&'static str>,
}

impl Builder {
    pub fn status(&mut self, code: StatusCode) -> &mut Self {
        self.status_code = Some(code);

        self
    }

    pub fn content(&mut self, content: &'static str) -> &mut Self {
        self.content = Some(content);

        self
    }

    pub fn build(self) -> Result<Response<Body>, http::Error> {
        Response::builder()
            .status(self.status.unwrap_or(StatusCode::OK))
            .header(header::CONTENT_TYPE, self.content_type)
            .body(self.content.map(Body::from).unwrap_or_else(Body::empty))
    }
}
