// SPDX-License-Identifier: MPL-2.0

pub type RawNodeHandle = u32;

pub struct Table {
    ipv4_start: NodeHandle,
    root: [NodeHandle; 256],
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct NodeHandle(RawNodeHandle);

impl NodeHandle {
    pub fn raw(self) -> RawNodeHandle {
        self.0
    }

    pub fn index(self) -> u64 {
        u64::from(self.0) * std::mem::size_of::<Node>()
    }
}

pub struct OctetTable([Option<NodeHandle>; 256]);

pub enum Node {
    Link(OctetTable),
    Entry
}
