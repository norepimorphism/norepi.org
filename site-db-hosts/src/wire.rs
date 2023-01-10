// SPDX-License-Identifier: MPL-2.0

use std::{convert::Infallible, io::{self, Read as _, Write as _}, net::{Ipv4Addr, Ipv6Addr}};

use error_stack::{IntoReport as _, Result, ResultExt as _};
use interprocess::local_socket::LocalSocketStream;

use crate::Host;

pub trait OverTheWire: Sized {
    type ReadError: error_stack::Context;
    type WriteError: error_stack::Context;

    fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError>;

    fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError>;
}

pub struct Empty;

impl OverTheWire for Empty {
    type ReadError = Infallible;
    type WriteError = Infallible;

    fn read_from_stream(_: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
        Ok(Self)
    }

    fn write_to_stream(self, _: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
        Ok(())
    }
}

macro_rules! impl_otw_from_field {
    ($ty:ty, $field:ident : $field_ty:ty $(,)?) => {
        impl OverTheWire for $ty {
            type ReadError = <$field_ty as OverTheWire>::ReadError;
            type WriteError = <$field_ty as OverTheWire>::WriteError;

            fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
                Ok(Self { $field: <$field_ty>::read_from_stream(stream)? })
            }

            fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
                self.$field.write_to_stream(stream)
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
pub enum ReadU8ArrayError {
    #[error("LocalSocketStream::read_exact() failed")]
    ReadExact,
    #[error("decoding failed")]
    Decode,
}

#[derive(thiserror::Error, Debug)]
pub enum WriteU8ArrayError {
    #[error("LocalSocketStream::write_all() failed")]
    WriteAll,
}

macro_rules! impl_otw_for_u8_array {
    ($ty:ty) => {
        impl OverTheWire for $ty
        where
            [(); <$ty>::SIZE]: Sized,
        {
            type ReadError = ReadU8ArrayError;
            type WriteError = WriteU8ArrayError;

            fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
                let mut buf = [0; <$ty>::SIZE];
                stream
                    .read_exact(&mut buf)
                    .into_report()
                    .change_context(ReadU8ArrayError::ReadExact)?;

                <$ty>::decode(buf).change_context(ReadU8ArrayError::Decode)
            }

            fn write_to_stream(
                self,
                stream: &mut LocalSocketStream,
            ) -> Result<(), Self::WriteError> {
                stream
                    .write_all(&self.encode())
                    .into_report()
                    .change_context(WriteU8ArrayError::WriteAll)
            }
        }
    };
}

macro_rules! impl_otw_for_u8 {
    ($ty:ty) => {
        impl OverTheWire for $ty {
            type ReadError = ReadU8ArrayError;
            type WriteError = WriteU8ArrayError;

            fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
                let mut buf = [0];
                stream
                    .read_exact(&mut buf)
                    .into_report()
                    .change_context(ReadU8ArrayError::ReadExact)?;

                <$ty>::decode(buf[0]).change_context(ReadU8ArrayError::Decode)
            }

            fn write_to_stream(
                self,
                stream: &mut LocalSocketStream,
            ) -> Result<(), Self::WriteError> {
                stream
                    .write_all(&[self.encode()])
                    .into_report()
                    .change_context(WriteU8ArrayError::WriteAll)
            }
        }
    };
}

pub trait U8ArrayCoding: Sized {
    const SIZE: usize;

    type DecodeError: error_stack::Context;

    fn decode(code: [u8; Self::SIZE]) -> Result<Self, Self::DecodeError>;

    fn encode(self) -> [u8; Self::SIZE];
}

pub trait U8Coding: Sized {
    type DecodeError: error_stack::Context;

    fn decode(code: u8) -> Result<Self, Self::DecodeError>;

    fn encode(self) -> u8;
}

#[derive(Clone, Copy, Debug)]
pub struct RequestHeader {
    pub proto: Protocol,
    pub action: Action,
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeRequestHeaderError {
    #[error("protocol is invalid")]
    InvalidProtocol,
    #[error("action is invalid")]
    InvalidAction,
}

impl_otw_for_u8_array!(RequestHeader);
impl U8ArrayCoding for RequestHeader {
    const SIZE: usize = 2;

    type DecodeError = DecodeRequestHeaderError;

    fn decode(code: [u8; Self::SIZE]) -> Result<Self, Self::DecodeError> {
        Ok(Self {
            proto: Protocol::decode(code[0]).change_context(DecodeRequestHeaderError::InvalidProtocol)?,
            action: Action::decode(code[1]).change_context(DecodeRequestHeaderError::InvalidAction)?,
        })
    }

    fn encode(self) -> [u8; Self::SIZE] {
        [self.proto.encode(), self.action.encode()]
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Control,
    Ipv4,
    Ipv6,
}

pub struct DecodeProtocolError;

impl_otw_for_u8!(Protocol);
impl U8Coding for Protocol {
    type DecodeError = DecodeProtocolError;

    fn decode(code: u8) -> Result<Self, Self::DecodeError> {
        match code {
            0 => Ok(Self::Control),
            1 => Ok(Self::Ipv4),
            2 => Ok(Self::Ipv6),
            _ => Err(error_stack::report!(DecodeProtocolError)),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Die,
    GetHost,
    SetHost,
}

pub struct DecodeActionError;

impl_otw_for_u8!(Action);
impl U8Coding for Action {
    type DecodeError = DecodeActionError;

    fn decode(code: u8) -> Result<Self, Self::DecodeError> {
        match code {
            0 => Ok(Self::Die),
            1 => Ok(Self::GetHost),
            2 => Ok(Self::SetHost),
            _ => Err(error_stack::report!(DecodeActionError)),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Self::Die => 0,
            Self::GetHost => 1,
            Self::SetHost => 2,
        }
    }
}

impl_otw_for_u8_array!(Ipv4Addr);
impl U8ArrayCoding for Ipv4Addr {
    const SIZE: usize = 4;

    type DecodeError = Infallible;

    fn decode(code: [u8; Self::SIZE]) -> Result<Self, Self::DecodeError> {
        Ok(Self::new(code[0], code[1], code[2], code[3]))
    }

    fn encode(self) -> [u8; Self::SIZE] {
        self.octets()
    }
}

impl_otw_for_u8_array!(Ipv6Addr);
impl U8ArrayCoding for Ipv6Addr {
    const SIZE: usize = 16;

    type DecodeError = Infallible;

    fn decode(code: [u8; Self::SIZE]) -> Result<Self, Self::DecodeError> {
        macro_rules! seg {
            ($i:expr) => { u16::from_be_bytes([code[2 * $i], code[(2 * $i) + 1]]) };
        }

        Ok(Self::new(
            seg!(0),
            seg!(1),
            seg!(2),
            seg!(3),
            seg!(4),
            seg!(5),
            seg!(6),
            seg!(7),
        ))
    }

    fn encode(self) -> [u8; Self::SIZE] {
        self.octets()
    }
}

#[derive(Debug)]
pub enum ReadHostError {
    ReadToEnd,
    Deserialize,
}

#[derive(Debug)]
pub enum WriteHostError {
    Serialize,
    WriteAll,
}

impl OverTheWire for Host {
    type ReadError = ReadHostError;
    type WriteError = WriteHostError;

    fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).into_report().change_context(ReadHostError::ReadToEnd)?;

        bincode::deserialize(buf.as_slice())
            .into_report()
            .change_context(ReadHostError::Deserialize)
    }

    fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
        let buf = bincode::serialize(&self)
            .into_report()
            .change_context(WriteHostError::Serialize)?;

        stream.write_all(buf.as_slice()).into_report().change_context(WriteHostError::WriteAll)
    }
}

pub struct GetV4HostPayload {
    pub ip: Ipv4Addr,
}
impl_otw_from_field!(GetV4HostPayload, ip: Ipv4Addr);

pub struct GetV6HostPayload {
    pub ip: Ipv6Addr,
}
impl_otw_from_field!(GetV6HostPayload, ip: Ipv6Addr);

pub struct SetV4HostPayload {
    pub ip: Ipv4Addr,
    pub host: Host,
}

#[derive(Debug)]
pub enum ReadSetV4HostPayloadError {
    ReadIp(ReadIpv4AddrError),
    ReadHost(ReadHostError),
}

#[derive(Debug)]
pub enum WriteSetV4HostPayloadError {
    WriteIp(io::Error),
    WriteHost(WriteHostError),
}

impl OverTheWire for SetV4HostPayload {
    type ReadError = ReadSetV4HostPayloadError;
    type WriteError = WriteSetV4HostPayloadError;

    fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
        let ip = Ipv4Addr::read_from_stream(stream).map_err(Self::ReadError::ReadIp)?;
        let host = Host::read_from_stream(stream).map_err(Self::ReadError::ReadHost)?;

        Ok(Self { ip, host })
    }

    fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
        self.ip.write_to_stream(stream).map_err(Self::WriteError::WriteIp)?;
        self.host.write_to_stream(stream).map_err(Self::WriteError::WriteHost)?;

        Ok(())
    }
}

pub struct SetV6HostPayload {
    pub ip: Ipv6Addr,
    pub host: Host,
}

#[derive(Debug)]
pub enum ReadSetV6HostPayloadError {
    ReadIp(ReadIpv6AddrError),
    ReadHost(ReadHostError),
}

#[derive(Debug)]
pub enum WriteSetV6HostPayloadError {
    WriteIp(io::Error),
    WriteHost(WriteHostError),
}

impl OverTheWire for SetV6HostPayload {
    type ReadError = ReadSetV6HostPayloadError;
    type WriteError = WriteSetV6HostPayloadError;

    fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
        let ip = Ipv6Addr::read_from_stream(stream).map_err(Self::ReadError::ReadIp)?;
        let host = Host::read_from_stream(stream).map_err(Self::ReadError::ReadHost)?;

        Ok(Self { ip, host })
    }

    fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
        self.ip.write_to_stream(stream).map_err(Self::WriteError::WriteIp)?;
        self.host.write_to_stream(stream).map_err(Self::WriteError::WriteHost)?;

        Ok(())
    }
}

pub enum HostStatus {
    Found,
    NotFound,
}

impl_otw_for_u8!(HostStatus);
impl U8Coding for HostStatus {
    type DecodeError = ();

    fn decode(code: u8) -> Result<Self, Self::DecodeError> {
        match code {
            0 => Ok(Self::NotFound),
            1 => Ok(Self::Found),
            _ => Err(()),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Self::NotFound => 0,
            Self::Found => 1,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub enum GetHostResponse {
    NotFound,
    Found(Host),
}

#[derive(Debug)]
pub enum ReadGetHostResponseError {
    ReadStatus(ReadHostStatusError),
    ReadHost(ReadHostError),
}

#[derive(Debug)]
pub enum WriteGetHostResponseError {
    WriteStatus(io::Error),
    WriteHost(WriteHostError),
}

impl OverTheWire for GetHostResponse {
    type ReadError = ReadGetHostResponseError;
    type WriteError = WriteGetHostResponseError;

    fn read_from_stream(stream: &mut LocalSocketStream) -> Result<Self, Self::ReadError> {
        let status = HostStatus::read_from_stream(stream)
            .map_err(Self::ReadError::ReadStatus)?;

        match status {
            HostStatus::NotFound => Ok(Self::NotFound),
            HostStatus::Found => {
                Ok(Self::Found(Host::read_from_stream(stream).map_err(Self::ReadError::ReadHost)?))
            }
        }
    }

    fn write_to_stream(self, stream: &mut LocalSocketStream) -> Result<(), Self::WriteError> {
        self.status().write_to_stream(stream).map_err(Self::WriteError::WriteStatus)?;
        if let Self::Found(host) = self {
            host.write_to_stream(stream).map_err(Self::WriteError::WriteHost)?;
        }

        Ok(())
    }
}

impl GetHostResponse {
    fn status(&self) -> HostStatus {
        match self {
            Self::NotFound => HostStatus::NotFound,
            Self::Found(_) => HostStatus::Found,
        }
    }
}
