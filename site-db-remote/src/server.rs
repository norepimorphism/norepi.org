// SPDX-License-Identifier: MPL-2.0

use std::{io::{self, Read as _}, path::Path};

use interprocess::local_socket::LocalSocketListener;
use ipv4_table::Table;

use crate::{Request, RequestIntent, Protocol};

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
        for stream in listener.incoming().filter_map(Result::ok) {
            let mut buf = [0; 2];
            if stream.read_exact(&mut buf).is_ok() {
                match Request::decode(buf) {
                    Ok(req) => {
                        self.handle_request(req);
                    }
                    Err(e) => {
                        tracing::error!("{:#?}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_request(&mut self, req: Request) {
        let Request { proto, intent } = req;

        match proto {
            Protocol::Any => {
                self.handle_ipv4_request(intent);
                self.handle_ipv6_request(intent);
            }
            Protocol::Ipv4 => {
                self.handle_ipv4_request(intent);
            }
            Protocol::Ipv6 => {
                self.handle_ipv6_request(intent);
            }
        }
    }

    fn handle_ipv4_request(&mut self, intent: RequestIntent) {
        tracing::info!("IPV4 request");
        // TODO
    }

    fn handle_ipv6_request(&mut self, intent: RequestIntent) {
        tracing::info!("IPV6 request");
        // TODO
    }
}
