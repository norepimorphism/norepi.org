// SPDX-License-Identifier: MPL-2.0

use hyper::{header, http, Body, Response, StatusCode};

pub mod content_type;

pub use _include as include;
pub use include_content;

macro_rules! _include {
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
            charset: None,
            content: None,
            status_code: None,
        }
    }
}

pub struct Builder {
    content_type: &'static str,
    language: Option<&'static str>,
    charset: Option<&'static str>,
    content: Option<&'static str>,
    status_code: Option<StatusCode>,
}

impl Builder {
    pub fn language(&mut self, code: &'static str) -> &mut Self {
        self.language = Some(code);

        self
    }

    pub fn charset(&mut self, charset: &'static str) -> &mut Self {
        self.charset = Some(charset);

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
            charset: self.charset.unwrap_or("utf-8"),
            content: self.content.unwrap_or_default(),
            status_code: self.status_code.unwrap_or(StatusCode::OK),
        }
    }
}

pub struct Resource {
    pub content_type: &'static str,
    pub language: &'static str,
    pub charset: &'static str,
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

    pub fn check_request_is_well_formed(
        &self,
        req: &Request<Body>,
    ) -> Result<(), Result<Response<Body>, http::Error>> {
        let headers = req.headers();

        // RFC 9110, Section 15.5.7:
        //   The 406 (Not Acceptable) status code indicates that the target resource does not have a
        //   current representation that would be acceptable to the user agent, according to the
        //   proactive negotiation header fields received... and the server is unwilling to supply a
        //   default representation.
        //
        //   The server SHOULD generate contant containing a list of representation characteristics
        //   and corresponding resource identifiers from which the user or user agent can choose the
        //   one most appropriate.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.15.5.7>.
        let not_acceptable = || {
            Err(_include!("406"."html").status(StatusCode::NOT_ACCEPTABLE).build().response())
        };

        // RFC 9110, Section 12.5.2:
        //   Note: Accept-Charset is deprecated because UTF-8 has become nearly ubiquitous.... Most
        //   general-purpose user agents do not send Accept-Charset unless specifically configured
        //   to do so.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.2>.
        if let Some(value) = headers.get(header::ACCEPT_CHARSET) {
            tracing::warn!("Accept-Charset was received but is deprecated");

            if !self.matches_accept_charset(value) {
                tracing::error!("Accept-Charset header does not request {}", self.charset);
                return not_acceptable();
            }
        }

        // RFC 9110, Section 12.5.3:
        //   When sent by a user agent in a request, Accept-Encoding indicates the content codings
        //   acceptable in a response.
        //   ...
        //   When sent by a server in response, Accept-Encoding provides information about which
        //   content codings are preferred in the context of a subsequent request to the same
        //   resource.
        //   ...
        //   An "identity" token is used as a synonym for "no encoding" in order to communicate when
        //   no encoding is preferred.
        //   ...
        //   If no Accept-Encoding header field is in the request, any content coding is considered
        //   acceptable by the user agent.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.3>.
        if let Some(value) = headers.get(header::ACCEPT_ENCODING) {
            // Resource content will be returned as-is; hence, we will only accept `Accept-Encoding`
            // headers that request `identity`.
            if !self.matches_accept_encoding(value) {
                tracing::error!("Accept-Encoding header does not request identity");
                // RFC 9110, Section 12.5.3:
                //   Servers that fail a request due to an unsupported content coding ought to
                //   respond with a 415 (Unsupported Media Type) status and include an
                //   Accept-Encoding header field in that response, allowing clients to distinguish
                //   between issues related to content codings and media types.
                return Err({
                    _include!("415"."html")
                        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                        .build()
                        .response()
                        .map(|mut res| {
                            res.headers_mut().insert(
                                header::ACCEPT_ENCODING,
                                HeaderValue::from_static("identity"),
                            );

                            res
                        })
                });
            }
        }

        // RFC 9110, Section 12.5.4:
        //   The "Accept-Language" header field can be used by user agents to indicate the set of
        //   natural languages that are preferred in the response.
        //
        // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.4>.
        if let Some(value) = headers.get(header::ACCEPT_LANGUAGE) {
            if !self.matches_accept_language(value) {
                tracing::error!("Accept-Language header does not request {}", self.language);
                return not_acceptable();
            }
        }

        Ok(())
    }

    fn matches_accept_charset(&self, value: &HeaderValue) -> bool {
        let Ok(prefs) = iter_accept_prefs(value) else {
            // The header is malformed.
            return false;
        };

        for pref in prefs {
            // RFC 9110, Section 12.5.2:
            //   The special value "*", if present in the Accept-Charset header field, matches every
            //   charset that is not mentioned elsewhere in the field.
            if pref.is_acceptable_with_name(b"*") {
                return true;
            }

            if pref.is_acceptable_with_name(self.charset.as_bytes()) {
                return true;
            }
        }

        false
    }

    // TODO: Only supports identity.
    fn matches_accept_encoding(value: &HeaderValue) -> bool {
        // RFC 9110, Section 12.5.3:
        //   An Accept-Encoding header field with a field value that is empty implies that the user
        //   agent does not want any content coding in response.
        if value.is_empty() {
            // Ostensibly, "does not want any content coding" implies the `identity` value.
            return true;
        }

        let Ok(prefs) = iter_accept_prefs(value) else {
            // The header is malformed.
            return false;
        };

        // RFC 9110, Section 12.5.3:
        //   If the representation has no content coding, then it is acceptable by default unless
        //   specifically excluded by the Accept-Encoding header field stating either "identity;q=0"
        //   or "*;q=0" without a more specific entry for "identity".

        for pref in prefs {
            // RFC 9110, Section 12.5.3:
            //   The asterisk "*" symbol in an Accept-Encoding field matches any available content
            //   coding not explicitly listed in the field.
            if pref.is_inacceptable_with_name(b"*") {
                return false;
            }

            if pref.is_inacceptable_with_name(b"identity") {
                return false;
            }
        }

        true
    }

    fn matches_accept_language(&self, value: &HeaderValue) -> bool {
        let Ok(prefs) = iter_accept_prefs(value) else {
            // The header is malformed.
            return false;
        };

        for pref in prefs {
            // RFC 4647, Section 3.3.1:
            //   The special range "*" in a language priority list matches any tag.
            //
            // See <https://www.rfc-editor.org/rfc/rfc4647.html#section-3.3.1>.
            if pref.is_acceptable_with_name(b"*") {
                return true;
            }

            if pref.is_acceptable_with_name(self.language.as_bytes()) {
                return true;
            }
        }

        false
    }
}

fn iter_accept_prefs<'a>(
    value: &'a HeaderValue,
) -> Result<impl 'a + Iterator<Item = AcceptPreference<'a>>, ()> {
    value
        .as_bytes()
        // Preferences are separated by commas `,`. There are no trailing commas.
        .split(|c| *c == b',')
        // Names and qparams are separated by semicolons `;`. There are no trailing semicolons.
        .map(|pref| pref.split(|c| *c == b';'))
        .map(|mut parts| {
            // The first part of a preference is the name.
            let name = parts
                .next()
                // The name may be prefixed by whitespace.
                .map(|it| it.trim_ascii_start())
                // It is an error if the name is not present.
                .ok_or(())?;
            // The second part of a preference is the qparam. It is optional.
            let qparam = parts.next();
            let qvalue = match qparam {
                Some(it) => Some({
                    it
                        // The qparam may be prefixed by whitespace.
                        .trim_ascii_start()
                        // The qvalue is always prefixed by the string "q=". This string must appear
                        // as-is without alternative capitalization and without whitespace.
                        .strip_prefix(b"q=")
                        // It is an error if the "q=" prefix is not present.
                        .ok_or(())?
                }),
                None => None,
            };
            // It is an error if any additional parts are present.
            if parts.next().is_some() {
                return Err(());
            }

            Ok(AcceptPreference { name, qvalue })
        })
        .collect::<Vec<Result<AcceptPreference, ()>>>()
        .into_iter()
        .collect::<Result<Vec<AcceptPreference>, ()>>()
        .map(|inner| inner.into_iter())
}

struct AcceptPreference<'a> {
    name: &'a [u8],
    qvalue: Option<&'a [u8]>,
}

impl fmt::Display for AcceptPreference<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::str::from_utf8(self.name).unwrap_or("<err>"))?;
        if let Some(qvalue) = self.qvalue {
            write!(f, ";q={}", std::str::from_utf8(qvalue).unwrap_or("<err>"))?;
        }

        Ok(())
    }
}

impl<'a> AcceptPreference<'a> {
    fn is_acceptable_with_name(&'a self, name: &[u8]) -> bool {
        // We are careful to compare insensitively.
        self.name.eq_ignore_ascii_case(name) && self.is_acceptable()
    }

    fn is_inacceptable_with_name(&'a self, name: &[u8]) -> bool {
        // Note that this is *not* the same as `!is_acceptable_with_name`.
        self.name.eq_ignore_ascii_case(name) && self.is_inacceptable()
    }

    fn is_acceptable(&'a self) -> bool {
        // RFC 9110, Section 12.4.2:
        //   The weight is normalized to a real number in the range 0 through 1, where 0.001 is the
        //   least preferred and 1 is the most preferred; a value of 0 means "not acceptable". If no
        //   "q" parameter is present, the default weight is 1.
        self.qvalue.map(|val| {
            !matches!(val, b"0" | b"0." | b"0.0" | b"0.00" | b"0.000")
        })
        .unwrap_or(true)
    }

    fn is_inacceptable(&'a self) -> bool {
        !self.is_acceptable()
    }
}
