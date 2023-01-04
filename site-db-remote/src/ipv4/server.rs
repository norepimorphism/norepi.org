// SPDX-License-Identifier: MPL-2.0

use std::path::Path;

use table::Table;

mod table;

impl Server {
    pub fn open_table(path: impl AsRef<Path>) -> Result<Self, table::OpenFileError> {
        Ok(Self { ipv4: table::open_file(path)? })
    }
}

pub struct Server {
    ipv4: Table,
}

impl Server {
    pub fn start(&mut self) {

    }
}
