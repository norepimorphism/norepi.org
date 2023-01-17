// SPDX-License-Identifier: MPL-2.0

//! MIME media types.
//!
//! [RFC 2046]: https://www.rfc-editor.org/rfc/rfc2046.html

use std::fmt;

/// Resolves a file extension to an associated MIME media type.
macro_rules! from_file_ext {
    ("css") => { $crate::resource::mime::Type::CSS };
    ("html") => { $crate::resource::mime::Type::HTML };
    ("png") => { $crate::resource::mime::Type::PNG };
    ("txt") => { $crate::resource::mime::Type::PLAINTEXT };
}
pub(crate) use from_file_ext;

impl Type<'static> {
    /// The `text/css` media type.
    pub const CSS: Self = Self::text("css");
    /// The `text/html` media type.
    pub const HTML: Self = Self::text("html");
    /// The `image/png` media type.
    pub const PNG: Self = Self::image("png");
    /// The `text/plain` media type.
    pub const PLAINTEXT: Self = Self::text("plain");
}

impl<'a> Type<'a> {
    /// Creates a new textual type.
    pub const fn text(sub: &'a str) -> Self {
        Self::new(TopLevel::Text, sub)
    }

    /// Creates a new image type.
    pub const fn image(sub: &'a str) -> Self {
        Self::new(TopLevel::Image, sub)
    }

    /// Creates a new audio type.
    pub const fn audio(sub: &'a str) -> Self {
        Self::new(TopLevel::Audio, sub)
    }

    /// Creates a new video type.
    pub const fn video(sub: &'a str) -> Self {
        Self::new(TopLevel::Video, sub)
    }

    /// Creates a new application type.
    pub const fn app(sub: &'a str) -> Self {
        Self::new(TopLevel::Application, sub)
    }

    /// Creates a new `Type` from a top-level type and subtype pair.
    pub const fn new(top: TopLevel, sub: &'a str) -> Self {
        Self { top, sub }
    }
}

/// A MIME media type.
pub struct Type<'a> {
    /// The top-level media type.
    pub top: TopLevel,
    /// The media subtype.
    pub sub: &'a str,
}

impl fmt::Display for Type<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.top.as_str())?;
        f.write_str("/")?;
        f.write_str(self.sub)?;

        Ok(())
    }
}

/// A top-level media type.
pub enum TopLevel {
    /// Textual information; `text`.
    Text,
    /// Image data; `image`.
    Image,
    /// Audio data; `audio`.
    Audio,
    /// Video data; `video`.
    Video,
    /// Miscellaneous data; `application`.
    Application,

    // Note: there are composite top-level types as well, but we don't need them (yet).
}

impl TopLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Application => "application",
        }
    }
}

impl fmt::Display for TopLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
