// SPDX-License-Identifier: MPL-2.0

pub use from_file_ext;

macro_rules! local_item {
    ($ident:ident) => {
        $crate::resource::content_type::$ident
    };
}

macro_rules! from_file_ext {
    ("bin") => { local_item!(BINARY) };
    ("css") => { local_item!(CSS) };
    ("html") => { local_item!(HTML) };
    ("txt") => { local_item!(PLAINTEXT) };
}

pub static BINARY: &str = "application/octet-stream";
pub static CSS: &str = "text/css";
pub static HTML: &str = "text/html";
pub static PLAINTEXT: &str = "text/plain";
