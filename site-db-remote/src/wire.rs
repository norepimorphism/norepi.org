// SPDX-License-Identifier: MPL-2.0

pub type RawRequest = [u8; Request::SIZE];

#[derive(Debug)]
enum DecodeRequestError {
    InvalidProtocol,
    InvalidAction,
}

impl Request {
    pub fn decode(raw: RawRequest) -> Result<Self, DecodeRequestError> {
        Ok(Self {
            proto: Protocol::decode(raw[0]).ok_or(DecodeRequestError::InvalidProtocol)?,
            action: Action::decode(raw[1]).ok_or(DecodeRequestError::InvalidAction)?,
            // TODO: we shouldn't need to unwrap.
            payload: raw[2..].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Copy)]
pub struct Request {
    pub proto: Protocol,
    pub action: Action,
    pub payload: [u8; Self::PAYLOAD_SIZE],
}

impl Request {
    pub const SIZE: usize = 64;
    pub const PAYLOAD_SIZE: usize = Self::SIZE - 2;

    pub fn encode(self) -> RawRequest {
        let mut raw = [0; Self::SIZE];
        raw[0] = self.proto.encode();
        raw[1] = self.action.encode();
        raw[2..].copy_from_slice(&self.payload);

        raw
    }
}

impl Protocol {
    pub fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ipv4),
            1 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Protocol {
    Ipv4,
    Ipv6,
}

impl Protocol {
    pub fn encode(self) -> u8 {
        match self {
            Self::Ipv4 => 0,
            Self::Ipv6 => 1,
        }
    }
}

impl Action {
    pub fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::GetHost),
            1 => Some(Self::SetHost),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Action {
    GetHost,
    SetHost,
}

impl Action {
    pub fn encode(self) -> u8 {
        match self {
            Self::GetHost => 0,
            Self::SetHost => 1,
        }
    }
}
