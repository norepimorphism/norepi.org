// SPDX-License-Identifier: MPL-2.0

use std::{io, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use interprocess::local_socket::LocalSocketStream;

use crate::{wire::{self, OverTheWire}, Host};
pub use wire::GetHostResponse;

pub fn kill_server() -> Result<(), RequestError<KillServer>> {
    let _ = request(KillServer)?;

    Ok(())
}

#[derive(Debug)]
pub enum GetHostError {
    V4(RequestError<GetV4Host>),
    V6(RequestError<GetV6Host>),
}

pub fn get_host(ip: IpAddr) -> Result<GetHostResponse, GetHostError> {
    match ip {
        IpAddr::V4(ip) => get_v4_host(ip).map_err(GetHostError::V4),
        IpAddr::V6(ip) => get_v6_host(ip).map_err(GetHostError::V6),
    }
}

pub fn get_v4_host(ip: Ipv4Addr) -> Result<GetHostResponse, RequestError<GetV4Host>> {
    request(GetV4Host { ip })
}

pub fn get_v6_host(ip: Ipv6Addr) -> Result<GetHostResponse, RequestError<GetV6Host>> {
    request(GetV6Host { ip })
}

#[derive(Debug)]
pub enum SetHostError {
    V4(RequestError<SetV4Host>),
    V6(RequestError<SetV6Host>),
}

pub fn set_host(ip: IpAddr, host: Host) -> Result<(), SetHostError> {
    match ip {
        IpAddr::V4(ip) => set_v4_host(ip, host).map_err(SetHostError::V4),
        IpAddr::V6(ip) => set_v6_host(ip, host).map_err(SetHostError::V6),
    }
}

pub fn set_v4_host(ip: Ipv4Addr, host: Host) -> Result<(), RequestError<SetV4Host>> {
    let _ = request(SetV4Host { ip, host })?;

    Ok(())
}

pub fn set_v6_host(ip: Ipv6Addr, host: Host) -> Result<(), RequestError<SetV6Host>> {
    let _ = request(SetV6Host { ip, host })?;

    Ok(())
}

pub trait Request {
    type Response: OverTheWire;
    type Payload: OverTheWire;

    fn header(&self) -> wire::RequestHeader;

    fn payload(self) -> Self::Payload;
}

pub struct KillServer;

impl Request for KillServer {
    type Response = wire::Empty;
    type Payload = wire::Empty;

    fn header(&self) -> wire::RequestHeader {
        wire::RequestHeader { proto: wire::Protocol::Control, action: wire::Action::Die }
    }

    fn payload(self) -> Self::Payload {
        wire::Empty
    }
}

#[derive(Debug)]
pub struct GetV4Host {
    pub ip: Ipv4Addr,
}

impl Request for GetV4Host {
    type Response = wire::GetHostResponse;
    type Payload = wire::GetV4HostPayload;

    fn header(&self) -> wire::RequestHeader {
        wire::RequestHeader { proto: wire::Protocol::Ipv4, action: wire::Action::GetHost }
    }

    fn payload(self) -> Self::Payload {
        wire::GetV4HostPayload { ip: self.ip }
    }
}

#[derive(Debug)]
pub struct GetV6Host {
    pub ip: Ipv6Addr,
}

impl Request for GetV6Host {
    type Response = wire::GetHostResponse;
    type Payload = wire::GetV6HostPayload;

    fn header(&self) -> wire::RequestHeader {
        wire::RequestHeader { proto: wire::Protocol::Ipv6, action: wire::Action::GetHost }
    }

    fn payload(self) -> Self::Payload {
        wire::GetV6HostPayload { ip: self.ip }
    }
}

#[derive(Debug)]
pub struct SetV4Host {
    pub ip: Ipv4Addr,
    pub host: Host,
}

impl Request for SetV4Host {
    type Response = wire::Empty;
    type Payload = wire::SetV4HostPayload;

    fn header(&self) -> wire::RequestHeader {
        wire::RequestHeader { proto: wire::Protocol::Ipv4, action: wire::Action::SetHost }
    }

    fn payload(self) -> Self::Payload {
        wire::SetV4HostPayload { ip: self.ip, host: self.host }
    }
}

#[derive(Debug)]
pub struct SetV6Host {
    pub ip: Ipv6Addr,
    pub host: Host,
}

impl Request for SetV6Host {
    type Response = wire::Empty;
    type Payload = wire::SetV6HostPayload;

    fn header(&self) -> wire::RequestHeader {
        wire::RequestHeader { proto: wire::Protocol::Ipv4, action: wire::Action::SetHost }
    }

    fn payload(self) -> Self::Payload {
        wire::SetV6HostPayload { ip: self.ip, host: self.host }
    }
}

#[derive(Debug)]
pub enum RequestError<Req: Request> {
    Connect(io::Error),
    WriteHeader(<wire::RequestHeader as OverTheWire>::WriteError),
    WritePayload(<<Req as Request>::Payload as OverTheWire>::WriteError),
    ReadResponse(<<Req as Request>::Response as OverTheWire>::ReadError),
}

pub fn request<Req: Request>(req: Req) -> Result<Req::Response, RequestError<Req>> {
    let mut stream = LocalSocketStream::connect(crate::SOCKET_NAME)
        .map_err(RequestError::Connect)?;
    req.header().write_to_stream(&mut stream).map_err(RequestError::WriteHeader)?;
    req.payload().write_to_stream(&mut stream).map_err(RequestError::WritePayload)?;

    <<Req as Request>::Response as OverTheWire>::read_from_stream(&mut stream)
        .map_err(RequestError::ReadResponse)
}
