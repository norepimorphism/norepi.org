// SPDX-License-Identifier: MPL-2.0

use std::io::{self, Write as _};

use interprocess::local_socket::LocalSocketStream;

use crate::Request;

pub enum SendError {
    Connect(io::Error),
    WriteAll(io::Error),
}

pub fn send(req: Request) -> Result<(), SendError> {
    let stream = LocalSocketStream::connect(crate::SOCKET_NAME).map_err(SendError::Connect)?;
    stream.write_all(&req.encode()).map_err(SendError::WriteAll)?;
    // TODO

    Ok(())
}
