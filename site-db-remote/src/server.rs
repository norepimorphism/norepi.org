// SPDX-License-Identifier: MPL-2.0

use std::{io, path::Path};

use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};
use ipv4_table::Table;

use crate::wire::{self, OverTheWire as _};

mod ipv4_table;

#[derive(Debug)]
pub enum OpenError {
    Ipv4Table(ipv4_table::OpenFileError),
}

impl Server {
    pub fn open(ipv4_table: impl AsRef<Path>) -> Result<Self, OpenError> {
        Ok(Self {
            ipv4: ipv4_table::open_file(ipv4_table).map_err(OpenError::Ipv4Table)?,
        })
    }
}

pub struct Server {
    ipv4: Table,
}

#[derive(Debug)]
pub enum ServeError {
    /// The call to [`LocalSocketListener::bind`] failed.
    Bind(io::Error),
}

impl Server {
    pub fn serve(&mut self) -> Result<(), ServeError> {
        let listener = LocalSocketListener::bind(crate::SOCKET_NAME).map_err(ServeError::Bind)?;
        for mut stream in listener.incoming().filter_map(Result::ok) {
            match wire::RequestHeader::read_from_stream(&mut stream) {
                Ok(header) => {
                    if let Err(e) = self.respond(&mut stream, header) {
                        tracing::error!("{}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("failed to read request header from stream: {:#?}", e);
                }
            }
        }

        Ok(())
    }

    fn respond(&mut self, stream: &mut LocalSocketStream, header: wire::RequestHeader) -> Result<(), String> {
        use wire::{Action, RequestHeader, Protocol};

        let RequestHeader { proto, action, .. } = header;

        match (proto, action) {
            (Protocol::Ipv4, Action::GetHost) => self.respond_to_get_v4_host(stream),
            (Protocol::Ipv4, Action::SetHost) => self.respond_to_set_v4_host(stream),
            _ => todo!(),
        }
    }

    fn respond_to_get_v4_host(&mut self, stream: &mut LocalSocketStream) -> Result<(), String> {
        let payload = wire::GetV4HostPayload::read_from_stream(stream)
            .map_err(|e| format!("{:#?}", e))?;
        let entry = self.ipv4.entry(payload.ip)
            .map_err(|e| format!("{:#?}", e))?;

        let response = match entry {
            ipv4_table::HostEntry::Occupied(host) => {
                let host = bincode::deserialize(host)
                    .map_err(|e| format!("{}", e))?;

                wire::GetHostResponse::Found(host)
            }
            ipv4_table::HostEntry::Vacant(_) => {
                wire::GetHostResponse::NotFound
            }
        };

        response.write_to_stream(stream).map_err(|e| format!("{:#?}", e))
    }

    fn respond_to_set_v4_host(&mut self, stream: &mut LocalSocketStream) -> Result<(), String> {
        let payload = wire::SetV4HostPayload::read_from_stream(stream)
            .map_err(|e| format!("{:#?}", e))?;
        let entry = self.ipv4.entry(payload.ip)
            .map_err(|e| format!("{:#?}", e))?;
        let mut new_host = bincode::serialize(&payload.host)
            .map_err(|e| format!("{}", e))?;
        new_host.resize(ipv4_table::BLOCK_SIZE, 0);
        let new_host = ipv4_table::Block::try_from(new_host).unwrap();

        match entry {
            ipv4_table::HostEntry::Occupied(old_host) => {
                *old_host = new_host;
            }
            ipv4_table::HostEntry::Vacant(entry) => {
                if let Err(e) = entry.insert(new_host) {
                    return Err(format!("{:#?}", e))
                }
            }
        }

        Ok(())
    }
}
