// SPDX-License-Identifier: MPL-2.0

//! A stupid-simple IPv4 table.

use std::{mem, net::Ipv4Addr, num::NonZeroU32};

use norepi_site_db_types::{backing, Backing};

use crate::Host;

/// The size, in bytes, of a [`Header`] or [`Node`].
const BLOCK_SIZE: u64 = 1024;

impl<'b, B: Backing> Table<'b, B> {
    pub fn new(backing: &'b mut B) -> Self {
        // Note: this will panic if it fails, but that's okay because everything would explode
        // otherwise.
        // TODO: can we call this in a .init constructor or something? Or is that like, a really bad
        // idea?
        check_layout();

        Self {
            header: Header::new(),
            backing,
        }
    }
}

pub enum LoadError {
    BackingLen(backing::LenError),
    Empty,
    HeaderIsIncomplete,
    BackingRead(backing::ReadError),
}

impl<'b, B: Backing> Table<'b, B> {
    pub unsafe fn load(backing: &'b mut B) -> Result<Self, LoadError> {
        // Note: this will panic if it fails, but that's okay because everything would explode
        // otherwise.
        check_layout();

        let len = backing.len().map_err(LoadError::BackingLen)?;
        if len == 0 {
            return Err(LoadError::Empty);
        }
        if len < BLOCK_SIZE {
            return Err(LoadError::HeaderIsIncomplete);
        }

        #[cfg(target_pointer_width = "8")]
        {
            compile_error!("usize is too small to accomodate BLOCK_SIZE");
        }

        // TODO: do we really need to zero-initialize this array?
        let mut header = [0; mem::size_of::<Header>()];
        backing.read(0, &mut header).map_err(LoadError::BackingRead)?;
        // SAFETY: TODO
        let header: Header = mem::transmute(header);

        Ok(Self { header, backing })
    }
}

/// Asserts that table blocks will be laid out in memory correctly.
///
/// This function should be called before reading or writing any blocks.
///
/// # Panics
///
/// If either [`Header`] or [`Node`] are not of size [`BLOCK_SIZE`], this function will panic.
fn check_layout() {
    let header_size = u64::try_from(mem::size_of::<Header>()).unwrap();
    if header_size != BLOCK_SIZE {
        panic!("sizeof(Header) is {}; should be BLOCK_SIZE", header_size);
    }

    let node_size = u64::try_from(mem::size_of::<Node>()).unwrap();
    if node_size != BLOCK_SIZE {
        panic!("sizeof(Node) is {}; should be BLOCK_SIZE", node_size);
    }
}

pub struct Table<'b, B> {
    header: Header,
    backing: &'b mut B,
}

impl<'b, B: Backing> Table<'b, B> {
    pub fn flush(&mut self) {
        let header = std::slice::from_ref(&self.header);
        // SAFETY: TODO
        let header = unsafe {
            std::slice::from_raw_parts(
                header.as_ptr().cast::<u8>(),
                mem::size_of::<Header>(),
            )
        };
        // Write our copy of the header to the backing.
        // TODO: should we catch errors?
        let _ = self.backing.write(0, header);

        self.backing.flush();
    }

    pub fn entry(&mut self, addr: Ipv4Addr) -> HostEntry<'b> {
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
            next_free_node: NodeHandle::first(),
            root: Subnet::default(),
        }
    }
}

#[repr(packed(4))]
struct Header {
    next_free_node: NodeHandle,
    root: Subnet,
}

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

    /// The byte address of this node.
    fn addr(self) -> u64 {
        BLOCK_SIZE * u64::from(self.inner.get())
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
struct Subnet([Option<NodeHandle>; 255]);
