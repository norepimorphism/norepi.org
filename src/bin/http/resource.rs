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
            language: None,
            content: None,
            status_code: None,
        }
    }
}

pub struct Builder {
    content_type: &'static str,
    language: Option<&'static str>,
    content: Option<&'static str>,
    status_code: Option<StatusCode>,
}

impl Builder {
    pub fn language(&mut self, code: &'static str) -> &mut Self {
        self.language = Some(code);

        self
    }

    pub fn content(&mut self, content: &'static str) -> &mut Self {
        self.content = Some(content);

        self
    }

    pub fn status(&mut self, code: StatusCode) -> &mut Self {
        self.status_code = Some(code);

        self
    }

    pub fn build(self) -> Resource {
        Resource {
            content_type: self.content_type,
            language: self.language.unwrap_or("en"),
            content: self.content.unwrap_or_default(),
            status_code: self.status_code.unwrap_or(StatusCode::OK),
        }
    }
}

pub struct Resource {
    pub content_type: &'static str,
    pub language: &'static str,
    pub content: &'static str,
    pub status_code: StatusCode,
}

impl Resource {
    pub fn response(self) -> Result<Response<Body>, http::Error> {
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, self.content_type)
            // RFC 9110, Section 8.5:
            //   The "Content-Language" header field describes the natural language(s) of the
            //   intended audience for the representation.
            //   ...
            //   Content-Language MAY be applied to any media type---it is not limited to textual
            //   documents.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.8.5>.
            .header(header::CONTENT_LANGUAGE, self.language)
            .body(self.content.into())
    }
}
