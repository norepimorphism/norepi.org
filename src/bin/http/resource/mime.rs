// SPDX-License-Identifier: MPL-2.0

/// Expands an `ident` of a local item to its full path.
macro_rules! local_item {
    ($ident:ident) => {
        $crate::resource::content_type::$ident
    };
}

/// Resolves a file extension to an associated MIME type.
macro_rules! from_file_ext {
    ("bin") => { local_item!(BINARY) };
    ("css") => { local_item!(CSS) };
    ("html") => { local_item!(HTML) };
    ("txt") => { local_item!(PLAINTEXT) };
}
pub use from_file_ext;

/// The `application/octet-stream` MIME type.
pub static BINARY: &str = "application/octet-stream";
/// The `text/css` MIME type.
pub static CSS: &str = "text/css";
/// The `text/html` MIME type.
pub static HTML: &str = "text/html";
/// The `text/plain` MIME type.
pub static PLAINTEXT: &str = "text/plain";
