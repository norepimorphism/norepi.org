// SPDX-License-Identifier: MPL-2.0

//! A stupid-simple IPv4 table.

use std::{mem, net::Ipv4Addr, num::NonZeroU32};

use memmap::MmapMut;

use crate::Host;

/// The size, in bytes, of a [`Header`] or [`Node`].
const BLOCK_SIZE: usize = 1024;

/// Asserts that table blocks will be laid out in memory correctly.
///
/// This function should be called before reading or writing any blocks.
///
/// # Panics
///
/// If either [`Header`] or [`Node`] are not of size [`BLOCK_SIZE`], this function will panic.
fn check_layout() {
    let header_size = mem::size_of::<Header>();
    if header_size != BLOCK_SIZE {
        panic!("sizeof(Header) is {}; should be BLOCK_SIZE", header_size);
    }

    let node_size = mem::size_of::<Node>();
    if node_size != BLOCK_SIZE {
        panic!("sizeof(Node) is {}; should be BLOCK_SIZE", node_size);
    }
}

impl Table {
    pub fn new(mmap: MmapMut) -> Self {
        // Note: this will panic if it fails, but that's okay because everything would explode
        // otherwise.
        // TODO: can we call this in a .init constructor or something? Or is that like, a really bad
        // idea?
        check_layout();

        Self {
            header: Header::new(),
            mmap,
        }
    }
}

pub enum LoadError {
    TooBig,
    Empty,
    IncompleteHeader,
    InvalidHeader(bytemuck::PodCastError),
}

impl Table {
    pub fn load(mut mmap: MmapMut) -> Result<Self, LoadError> {
        // Note: this will panic if it fails, but that's okay because everything would explode
        // otherwise.
        check_layout();

        let len = mmap.len();
        if len == 0 {
            return Err(LoadError::Empty);
        }
        if len < BLOCK_SIZE {
            return Err(LoadError::IncompleteHeader);
        }

        let header = mmap.get_header_mut();
        let header: &mut Header = bytemuck::try_from_bytes_mut(header)
            .map_err(LoadError::InvalidHeader)?;
        let header = *header;

        Ok(Self { header, mmap })
    }
}

trait MmapExt {
    fn get_header(&self) -> &[u8] {
        self.get_block(0)
    }

    fn get_header_mut(&mut self) -> &mut [u8] {
        self.get_block_mut(0)
    }

    fn get_block(&self, index: usize) -> &[u8];

    fn get_block_mut(&mut self, index: usize) -> &mut [u8];
}

impl MmapExt for MmapMut {
    fn get_block(&self, index: usize) -> &[u8] {
        get_block_impl(index, |start, end| &self[start..end])
    }

    fn get_block_mut(&mut self, index: usize) -> &mut [u8] {
        get_block_impl(index, |start, end| &mut self[start..end])
    }
}

fn get_block_impl<'a, T: 'a + AsRef<[u8]>>(
    index: usize,
    get: impl 'a + FnOnce(usize, usize) -> T,
) -> T {
    let start = BLOCK_SIZE * index;
    let end = BLOCK_SIZE * (index + 1);
    let block = get(start, end);
    assert_eq!(block.as_ref().len(), BLOCK_SIZE);

    block
}

pub struct Table {
    header: Header,
    mmap: MmapMut,
}

impl Table {
    pub fn flush(&mut self) {
        let header = bytemuck::bytes_of(&self.header);
        // Write our copy of the header to the backing.
        let _ = self.mmap.get_header_mut().copy_from_slice(header);

        // TODO: should we catch errors?
        let _ = self.mmap.flush();
    }

    pub fn entry(&mut self, addr: Ipv4Addr) -> HostEntry {
        todo!()
    }
}

pub enum HostEntry<'a> {
    Occupied(&'a mut Host),
    Vacant(VacantHostEntry<'a>),
}

pub struct VacantHostEntry<'a> {
    subnet_elem: &'a mut Option<NodeHandle>,
}

impl<'a> VacantHostEntry<'a> {
    pub fn insert(self, host: Host) -> &'a mut Host {
        todo!()
    }
}

impl Header {
    fn new() -> Self {
        Self {
            next_free_node: Some(NodeHandle::first()),
            root: Subnet::default(),
        }
    }
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct Header {
    next_free_node: Option<NodeHandle>,
    root: Subnet,
}

// SAFETY: TODO
unsafe impl bytemuck::Pod for Header {}
// SAFETY: TODO
unsafe impl bytemuck::Zeroable for Header {}

impl NodeHandle {
    fn first() -> Self {
        Self {
            // TODO: replace this with [`NonZeroU32::MIN`] when stabilised.
            // SAFETY: 1 is nonzero.
            inner: unsafe { NonZeroU32::new_unchecked(1) },
        }
    }
}

/// A handle to a node.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct NodeHandle {
    // Nullable Pointer Optimization guarantees that `Option<NodeHandle>` is the same size as
    // `NodeHandle` because:
    // - `NodeHandle` is `repr(transparent)`;
    // - the only field within `NodeHandle` is of type `NonZero<U>`; and
    // - `U` is a builtin integer
    //
    // See the [`Option` documentation] or [*rustc* source code] for details.
    //
    // [`Option` documentation]: https://doc.rust-lang.org/std/option/index.html#representation
    // [*rustc* source code]: https://github.com/rust-lang/rust/blob/0740a93cc290a5419807d2e8c6c442354baf46b0/src/librustc_trans/adt.rs#L460-L476
    inner: NonZeroU32,
}

impl NodeHandle {
    fn next(&self) -> Option<Self> {
        Some(Self { inner: self.inner.checked_add(1)? })
    }

    fn index(self) -> u32 {
        self.inner.get()
    }
}

// The `repr(u32)` forces the discriminant to be of type `u32`.
#[repr(u32)]
enum Node {
    Subnet(Subnet),
    Host(Host),
}

impl Default for Subnet {
    fn default() -> Self {
        Self([None; 255])
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct Subnet([Option<NodeHandle>; 255]);

// SAFETY: TODO
unsafe impl bytemuck::Pod for Subnet {}
// SAFETY: TODO
unsafe impl bytemuck::Zeroable for Subnet {}
