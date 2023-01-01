// SPDX-License-Identifier: MPL-2.0

/// Resolves a file extension to an associated MIME type.
macro_rules! from_file_ext {
    ("bin") => { $crate::resource::mime::BINARY };
    ("css") => { $crate::resource::mime::CSS };
    ("html") => { $crate::resource::mime::HTML };
    ("txt") => { $crate::resource::mime::PLAINTEXT };
}
pub(crate) use from_file_ext;

/// The `application/octet-stream` MIME type.
pub static BINARY: &str = "application/octet-stream";
/// The `text/css` MIME type.
pub static CSS: &str = "text/css";
/// The `text/html` MIME type.
pub static HTML: &str = "text/html";
/// The `text/plain` MIME type.
pub static PLAINTEXT: &str = "text/plain";
