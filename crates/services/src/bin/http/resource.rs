// SPDX-License-Identifier: MPL-2.0

//! Logical files accessible through `GET` or `HEAD` requests at one or more URIs.

use std::{fmt, iter};

use hyper::{header::{self, HeaderValue}, http, Body, Request, Response, StatusCode};

pub mod mime;

/// Constructs a new [resource builder](`Builder`) for a file with the given extension.
///
/// The MIME media type is automatically derived from the file extension.
macro_rules! for_file_ext {
    ($ext:tt) => {
        $crate::resource::Builder::new($crate::resource::mime::from_file_ext!($ext))
    };
}

/// Constructs a new [resource builder](`Builder`) from the file at the given path.
///
/// The MIME media type is automatically derived from the file extension.
//
// TODO: find a better name
macro_rules! include_ {
    ($file_base:tt . $file_ext:tt $(,)?) => {
        $crate::resource::for_file_ext!($file_ext)
            .content(include_bytes!(concat!($file_base, ".", $file_ext)))
    };
}

/// Constructs a new [resource builder](`Builder`) from the file at the given path within the
/// `${OUT_DIR}/gen/` directory.
///
/// The MIME media type is automatically derived from the file extension.
macro_rules! include_gen {
    ($file_base:tt . $file_ext:tt $(,)?) => {
        $crate::resource::for_file_ext!($file_ext)
            .content(include_bytes!(concat!(env!("OUT_DIR"), "/gen/", $file_base, ".", $file_ext)))
    };
}

pub(crate) use for_file_ext;
pub(crate) use include_;
pub(crate) use include_gen;

impl Builder {
    /// Constructs a new builder for a plaintext resource.
    pub fn plaintext() -> Self {
        Self::new(mime::Type::PLAINTEXT)
    }

    /// Constructs a new builder for a resource with the given MIME media type.
    pub fn new(media_type: mime::Type<'static>) -> Self {
        Self {
            media_type,
            language: None,
            charset: None,
            encoding: None,
            extra_headers: Vec::new(),
            content: None,
            status_code: None,
        }
    }
}

/// A builder for a [`Resource`].
pub struct Builder {
    media_type: mime::Type<'static>,
    language: Option<&'static str>,
    charset: Option<&'static str>,
    encoding: Option<&'static str>,
    extra_headers: Vec<(&'static str, &'static str)>,
    content: Option<&'static [u8]>,
    status_code: Option<StatusCode>,
}

impl Builder {
    /// Sets the language tag of the resource.
    ///
    /// By default, this is `en` for textual resources and unset otherwise.
    ///
    /// Language tags are described in [RFC 5646].
    ///
    /// [RFC 5646]: https://datatracker.ietf.org/doc/html/rfc5646
    pub fn language(mut self, tag: &'static str) -> Self {
        self.language = Some(tag);

        self
    }

    /// Sets the character set, or *charset*, of the resource.
    ///
    /// By default, this is `utf-8` for textual resources and unset otherwise.
    pub fn charset(mut self, charset: &'static str) -> Self {
        self.charset = Some(charset);

        self
    }

    /// Sets the content coding of the resource.
    ///
    /// By default, this is unset.
    pub fn encoding(mut self, encoding: &'static str) -> Self {
        self.encoding = Some(encoding);

        self
    }

    /// Appends a response header to the resource.
    pub fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.extra_headers.push((name, value));

        self
    }

    /// Sets the content of the resource.
    ///
    /// By default, this is an empty slice.
    pub fn content(mut self, content: &'static [u8]) -> Self {
        self.content = Some(content);

        self
    }

    /// Sets the status code of the resource.
    ///
    /// By default, this is [`StatusCode::OK`].
    pub fn status(mut self, code: StatusCode) -> Self {
        self.status_code = Some(code);

        self
    }

    /// Constructs a resource from this builder, consuming it in the process.
    pub fn build(self) -> Resource {
        let is_textual = matches!(self.media_type.top, mime::TopLevel::Text);
        let or_textual_default = |option: Option<&'static str>, default| {
            option.or_else(|| if is_textual { Some(default) } else { None })
        };

        Resource {
            media_type: self.media_type,
            language: or_textual_default(self.language, "en"),
            charset: or_textual_default(self.charset, "utf-8"),
            encoding: self.encoding,
            extra_headers: self.extra_headers,
            content: self.content.unwrap_or_default(),
            status_code: self.status_code.unwrap_or(StatusCode::OK),
        }
    }
}

/// A logical file that is hosted on the webserver and is accessible through `GET` or `HEAD`
/// requests at one or more URIs.
pub struct Resource {
    /// The MIME media type of the content.
    pub media_type: mime::Type<'static>,
    /// The language tag that identifies the natural language the content is written in (or for).
    ///
    /// Language tags are described in [RFC 5646].
    ///
    /// [RFC 5646]: https://datatracker.ietf.org/doc/html/rfc5646
    pub language: Option<&'static str>,
    /// The character set, or *charset*, of the content.
    pub charset: Option<&'static str>,
    /// The content coding (e.g., compression), if any.
    pub encoding: Option<&'static str>,
    pub extra_headers: Vec<(&'static str, &'static str)>,
    /// The content.
    pub content: &'static [u8],
    /// The HTTP status code to be returned when accessing this resource.
    pub status_code: StatusCode,
}

impl Resource {
    /// Generates an HTTP response for this resource.
    pub fn response(self) -> Result<Response<Body>, http::Error> {
        let mut response = Response::builder()
            .status(self.status_code)
            // RFC 9110, Section 8.3:
            //   The "Content-Type" header field indicates the media type of the associated
            //   representation...
            //   ...
            //   A sender that generates a message containing content SHOULD generate a Content-Type
            //   header field in the message unless the intended media type of the enclosed
            //   representation is unknown to the sender.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.8.3>.
            .header(
                header::CONTENT_TYPE,
                iter::once(self.media_type.to_string())
                    .chain(self.charset.map(|it| format!("charset={it}")))
                    .collect::<Vec<String>>()
                    .join(";"),
            )
            // No need to MIME-sniff.
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
        if let Some(language) = self.language {
            // RFC 9110, Section 8.5:
            //   The "Content-Language" header field describes the natural language(s) of the
            //   intended audience for the representation.
            //   ...
            //   Content-Language MAY be applied to any media type---it is not limited to textual
            //   documents.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.8.5>.
            response = response.header(header::CONTENT_LANGUAGE, language);
        }
        let mut response = response
            // RFC 9110, Section 5.2:
            //   The "Cache-Control" header field is used to list directives for caches along the
            //   request/response chain. Cache directives are unidirectional, in that the presence
            //   of a directive in a request does not imply the same directive is present or copied
            //   in the response.
            //
            // See <https://httpwg.org/specs/rfc9111.html#rfc.section.5.2>.
            .header(
                header::CACHE_CONTROL,
                // RFC 9111, Section 5.2.2.1:
                //   The max-age response directive indicates that the response is to be considered
                //   stale after its age is greater than the specified number of seconds.
                //
                // See <https://httpwg.org/specs/rfc9111.html#rfc.section.5.2.2.1>.

                // TODO: don't hardcode this.
                "max-age=3600",
            )
            // RFC 9110, Section 12.5.5:
            //   The "Vary" header field in a response describes what parts of a request message,
            //   aside from the method and target URI, might have influenced the origin server's
            //   process for selecting the content of this response.
            //
            //   A Vary field value is either the wildcard member "*" or a list of request field
            //   names, known as the selecting header fields, that might have had a role in
            //   selecting the representation for this response.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.12.5.5>.
            .header(header::VARY, "accept-charset,accept-encoding,accept-language");
        if let Some(encoding) = self.encoding {
            // RFC 9110, Section 8.4:
            //   The "Content-Encoding" header field indicates what content codings have been
            //   applied to the representation, beyond those inherent in the media type, and thus
            //   what decoding mechanisms have to be applied in order to obtain data in the media
            //   type referenced by the Content-Type header field.
            //   ...
            //   If one or more encodings have been applied to a representation, the sender that
            //   applied the encodings MUST generate a Content-Encoding header field that lists the
            //   content codings in the order in which they were applied. Note that the coding named
            //   "identity" is reserved for its special role in Accept-Encoding and thus SHOULD NOT
            //   be included.
            //
            // See <https://httpwg.org/specs/rfc9110.html#rfc.section.8.4>.
            response = response.header(header::CONTENT_ENCODING, encoding);
        }

        if let Some(headers) = response.headers_mut() {
            for (name, value) in self.extra_headers {
                headers.append(name, HeaderValue::from_static(value));
            }
        }

        response.body(self.content.into())
    }

    /// Determines if this resource can satisfy content negotiation with the given request.
    ///
    /// If content negotiation is successful, `Ok(())` is returned. Otherwise, an error `Err(_)` is
    /// returned containing an HTTP response that describes what went wrong to the client.
    pub fn is_compatible_with_request(
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
            Err(include_gen!("406"."html").status(StatusCode::NOT_ACCEPTABLE).build().response())
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
            if !self.matches_accept_encoding(value) {
                let encoding = self.encoding.unwrap_or("identity");

                // RFC 9110, Section 12.5.3:
                //   Servers that fail a request due to an unsupported content coding ought to
                //   respond with a 415 (Unsupported Media Type) status and include an
                //   Accept-Encoding header field in that response, allowing clients to distinguish
                //   between issues related to content codings and media types.
                return Err({
                    include_gen!("415"."html")
                        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                        .build()
                        .response()
                        .map(|mut response| {
                            response.headers_mut().insert(
                                header::ACCEPT_ENCODING,
                                HeaderValue::from_static(encoding),
                            );

                            response
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

        let Some(charset) = self.charset else {
            // We don't specify a charset, so anything is fair game, I guess.
            return true;
        };

        for pref in prefs {
            if pref.is_acceptable_with_name(charset.as_bytes()) {
                return true;
            }

            // RFC 9110, Section 12.5.2:
            //   The special value "*", if present in the Accept-Charset header field, matches every
            //   charset that is not mentioned elsewhere in the field.
            if pref.is_acceptable_with_name(b"*") {
                return true;
            }
        }

        false
    }

    // TODO: Only supports identity.
    fn matches_accept_encoding(&self, value: &HeaderValue) -> bool {
        // RFC 9110, Section 12.5.3:
        //   An Accept-Encoding header field with a field value that is empty implies that the user
        //   agent does not want any content coding in response.
        if value.is_empty() {
            if self.encoding.is_some() {
                return false;
            } else {
                // Ostensibly, "does not want any content coding" implies the `identity` value.
                return true;
            }
        }

        let Ok(prefs) = iter_accept_prefs(value) else {
            // The header is malformed.
            return false;
        };

        if let Some(encoding) = self.encoding {
            for pref in prefs {
                if pref.is_acceptable_with_name(encoding.as_bytes()) {
                    return true;
                }

                // RFC 9110, Section 12.5.3:
                //   The asterisk "*" symbol in an Accept-Encoding field matches any available
                //   content coding not explicitly listed in the field.
                if pref.is_acceptable_with_name(b"*") {
                    return true;
                }
            }

            false
        } else {
            // RFC 9110, Section 12.5.3:
            //   If the representation has no content coding, then it is acceptable by default
            //   unless specifically excluded by the Accept-Encoding header field stating either
            //   "identity;q=0" or "*;q=0" without a more specific entry for "identity".

            for pref in prefs {
                if pref.is_inacceptable_with_name(b"identity") {
                    return false;
                }

                if pref.is_inacceptable_with_name(b"*") {
                    return false;
                }
            }

            true
        }
    }

    fn matches_accept_language(&self, value: &HeaderValue) -> bool {
        let Ok(prefs) = iter_accept_prefs(value) else {
            // The header is malformed.
            return false;
        };

        let Some(language) = self.language else {
            // We don't specify a language, so anything is fair game.
            return true;
        };

        for pref in prefs {
            if pref.is_acceptable_with_name(language.as_bytes()) {
                return true;
            }

            // RFC 4647, Section 3.3.1:
            //   The special range "*" in a language priority list matches any tag.
            //
            // See <https://www.rfc-editor.org/rfc/rfc4647.html#section-3.3.1>.
            if pref.is_acceptable_with_name(b"*") {
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
