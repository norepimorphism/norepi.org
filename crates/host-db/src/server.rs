// SPDX-License-Identifier: MPL-2.0

use std::{fmt, path::Path};

use error_stack::{IntoReport as _, Result, ResultExt as _};
use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};

use crate::wire::{self, OverTheWire as _};
use ipv4_table::Table;

mod ipv4_table;

#[derive(thiserror::Error, Debug)]
pub enum OpenError {
    #[error("failed to open IPv4 table")]
    Ipv4Table,
}

impl Server {
    pub fn open(ipv4_table: impl AsRef<Path> + fmt::Debug) -> Result<Self, OpenError> {
        Ok(Self {
            ipv4: ipv4_table::open_file(ipv4_table).change_context(OpenError::Ipv4Table)?,
        })
    }
}

pub struct Server {
    ipv4: Table,
}

#[derive(thiserror::Error, Debug)]
pub enum ServeError {
    /// The call to [`LocalSocketListener::bind`] failed.
    #[error("failed to bind socket listener")]
    Bind,
}

impl Server {
    pub fn serve(&mut self, should_quit: impl Fn() -> bool) -> Result<(), ServeError> {
        let listener = LocalSocketListener::bind(crate::SOCKET_NAME)
            .into_report()
            .change_context(ServeError::Bind)?;

        tracing::info!("Serving on '{}'...", crate::SOCKET_NAME);
        while !should_quit() {
            let Ok(mut stream) = listener.accept() else {
                continue;
            };

            match wire::RequestHeader::read_from_stream(&mut stream) {
                Ok(header) => {
                    match self.respond(&mut stream, header) {
                        Ok(ctrl) => if matches!(ctrl, ControlFlow::Return) {
                            break;
                        }
                        Err(report) => {
                            eprintln!("{report}");
                        }
                    }
                }
                Err(e) => {
                    let report = error_stack::report!(e)
                        .attach_printable("failed to read request header from stream")
                        .to_string();
                    eprintln!("{report}");
                }
            }
        }
        tracing::info!("Goodbye!");

        Ok(())
    }
}

enum ControlFlow {
    Continue,
    Return,
}

#[derive(thiserror::Error, Debug)]
enum RespondError {
    #[error("failed to respond to GetV4Host request")]
    GetV4Host,
    #[error("failed to respond to SetV4Host request")]
    SetV4Host,
}

impl Server {
    fn respond(
        &mut self,
        stream: &mut LocalSocketStream,
        header: wire::RequestHeader,
    ) -> Result<ControlFlow, RespondError> {
        use wire::{Action, RequestHeader, Protocol};

        let RequestHeader { proto, action, .. } = header;

        match (proto, action) {
            (Protocol::Control, Action::Die) => {
                return Ok(ControlFlow::Return);
            }
            (Protocol::Ipv4, Action::GetHost) => {
                self
                    .respond_to_get_v4_host(stream)
                    .change_context(RespondError::GetV4Host)?;
            }
            (Protocol::Ipv4, Action::SetHost) => {
                self
                    .respond_to_set_v4_host(stream)
                    .change_context(RespondError::SetV4Host)?;
            }
            _ => todo!(),
        }

        Ok(ControlFlow::Continue)
    }
}

#[derive(thiserror::Error, Debug)]
enum RespondToGetV4HostError {
    #[error("failed to read payload from stream")]
    ReadPayload,
    #[error("failed to obtain host entry")]
    GetHostEntry,
    #[error("failed to deserialize host record")]
    DeserializeHost,
    #[error("failed to write response to stream")]
    WriteResponse,
}

impl Server {
    fn respond_to_get_v4_host(
        &mut self, stream:
        &mut LocalSocketStream,
    ) -> Result<(), RespondToGetV4HostError> {
        let payload = wire::GetV4HostPayload::read_from_stream(stream)
            .change_context(RespondToGetV4HostError::ReadPayload)?;
        let entry = self.ipv4.entry(payload.ip)
            .change_context(RespondToGetV4HostError::GetHostEntry)?;

        let response = match entry {
            ipv4_table::HostEntry::Occupied(host) => {
                let host = bincode::deserialize(host)
                    .into_report()
                    .change_context(RespondToGetV4HostError::DeserializeHost)?;

                wire::GetHostResponse::Found(host)
            }
            ipv4_table::HostEntry::Vacant(_) => {
                wire::GetHostResponse::NotFound
            }
        };

        response.write_to_stream(stream).change_context(RespondToGetV4HostError::WriteResponse)
    }
}

#[derive(thiserror::Error, Debug)]
enum RespondToSetV4HostError {
    #[error("failed to read payload from stream")]
    ReadPayload,
    #[error("failed to obtain host entry")]
    GetHostEntry,
    #[error("failed to serialize host record")]
    SerializeHost,
    #[error("failed to insert host entry")]
    InsertHost,
}

impl Server {
    fn respond_to_set_v4_host(
        &mut self,
        stream: &mut LocalSocketStream,
    ) -> Result<(), RespondToSetV4HostError> {
        let payload = wire::SetV4HostPayload::read_from_stream(stream)
            .change_context(RespondToSetV4HostError::ReadPayload)?;
        let entry = self.ipv4.entry(payload.ip)
            .change_context(RespondToSetV4HostError::GetHostEntry)?;
        let mut new_host = bincode::serialize(&payload.host)
            .into_report()
            .change_context(RespondToSetV4HostError::SerializeHost)?;
        new_host.resize(ipv4_table::BLOCK_SIZE, 0);
        let new_host = ipv4_table::Block::try_from(new_host).unwrap();

        match entry {
            ipv4_table::HostEntry::Occupied(old_host) => {
                *old_host = new_host;
            }
            ipv4_table::HostEntry::Vacant(entry) => {
                entry.insert(new_host).change_context(RespondToSetV4HostError::InsertHost)?;
            }
        }

        Ok(())
    }
}
