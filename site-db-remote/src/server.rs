// SPDX-License-Identifier: MPL-2.0

use std::{io::{self, Read as _}, net::Ipv4Addr, path::Path};

use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};
use ipv4_table::Table;

use crate::wire::{Action, Request, Protocol};

mod ipv4_table;

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

pub enum StartError {
    Bind(io::Error),
}

impl Server {
    pub fn start(&mut self) -> Result<(), StartError> {
        let listener = LocalSocketListener::bind(crate::SOCKET_NAME).map_err(StartError::Bind)?;
        for mut stream in listener.incoming().filter_map(Result::ok) {
            let mut buf = [0; Request::SIZE];
            if stream.read_exact(&mut buf).is_ok() {
                match Request::decode(buf) {
                    Ok(req) => {
                        self.respond(&mut stream, req);
                    }
                    Err(e) => {
                        tracing::error!("{:#?}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn respond(&mut self, stream: &mut LocalSocketStream, req: Request) {
        let Request { proto, action, .. } = req;

        match (proto, action) {
            (Protocol::Ipv4, Action::GetHost) => {
                let mut buf = [0; 4];
                // TODO: don't unwrap.
                stream.read_exact(&mut buf).unwrap();

                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                // TODO: don't unwrap.
                match self.ipv4.entry(ip).unwrap() {
                    ipv4_table::HostEntry::Occupied(_host) => {
                        todo!()
                    }
                    ipv4_table::HostEntry::Vacant(_) => {
                        todo!()
                    }
                }
            }
            _ => todo!(),
        }
    }
}
