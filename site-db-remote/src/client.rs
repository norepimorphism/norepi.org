// SPDX-License-Identifier: MPL-2.0

use std::{io::{self, Read as _, Write as _}, net::{Ipv4Addr, Ipv6Addr}};

use interprocess::local_socket::LocalSocketStream;

use crate::{wire, Host};

pub trait Request: Into<wire::Request> {
    type Response: Response;
}

pub trait Response: Sized {
    type Error;

    fn decode(bytes: &[u8]) -> Result<Self, Self::Error>;
}

impl Response for Host {
    type Error = ();

    fn decode(_bytes: &[u8]) -> Result<Self, Self::Error> {
        todo!()
    }
}

pub struct GetV4Host {
    pub ip: Ipv4Addr,
}

impl Request for GetV4Host {
    type Response = Host;
}
impl From<GetV4Host> for wire::Request {
    fn from(req: GetV4Host) -> Self {
        Self {
            proto: wire::Protocol::Ipv4,
            action: wire::Action::GetHost,
            payload: {
                let mut buf = [0; wire::Request::PAYLOAD_SIZE];
                buf[..4].copy_from_slice(&req.ip.octets());

                buf
            },
        }
    }
}

pub struct GetV6Host {
    pub ip: Ipv6Addr,
}

impl Request for GetV6Host {
    type Response = Host;
}
impl From<GetV6Host> for wire::Request {
    fn from(req: GetV6Host) -> Self {
        Self {
            proto: wire::Protocol::Ipv6,
            action: wire::Action::GetHost,
            payload: {
                let mut buf = [0; wire::Request::PAYLOAD_SIZE];
                buf[..16].copy_from_slice(&req.ip.octets());

                buf
            },
        }
    }
}

pub enum RequestError<Req: Request> {
    Connect(io::Error),
    WriteAll(io::Error),
    ReadToEnd(io::Error),
    Decode(<<Req as Request>::Response as Response>::Error),
}

pub fn request<Req: Request>(req: Req) -> Result<Req::Response, RequestError<Req>> {
    let mut stream = LocalSocketStream::connect(crate::SOCKET_NAME)
        .map_err(RequestError::Connect)?;
    stream.write_all(&req.into().encode()).map_err(RequestError::WriteAll)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(RequestError::ReadToEnd)?;

    Req::Response::decode(&buf).map_err(RequestError::Decode)
}
