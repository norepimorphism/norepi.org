// SPDX-License-Identifier: MPL-2.0

//! A stupid-simple IPv4 table.
//!
//! The eponymous [`Table`] type is like a lookup table where the indices are
//! [IPv4 addresses](`Ipv4Addr`) and the elements are [`Host`] records.
//!
//! The primary API entrypoints are [`Table::new`] and [`Table::load`], which create a new table or
//! load an existing table, repsecively, from a memory-mapped buffer. [`open_file`] is a convenience
//! function that attempts to deserialize a table from a file, creating a new table if the file does
//! not exist. Once significant changes have been made to a table, the [`Table::flush`] method is
//! used to flush the changes to disk. The table is also flushed on drop.
//!
//! # Limitations
//!
//! The term 'deserialize' is used loosely. No serialization scheme is employed, so the table is
//! stored on disk exactly the same as in memory. This makes for fast reads and writes, but the
//! major limitation is that table files are not portable. No guarantees are made regarding
//! compatibility with other systems, and the on-disk format is not endian-agnostic, so table files
//! not work on systems with a different endianness than the system that created them.
//!
//! # Implementation
//!
//! An IPv4 table is like a [trie] where terminal nodes are [`Host`] records and where parent nodes
//! are implemented as lookup tables of children nodes. Alternatively, an IPv4 table is like a
//! linked list of lookup tables where each table represents a subnet and is indexed by one octet in
//! an IPv4 address.
//!
//! [trie]: https://en.wikipedia.org/wiki/Trie
//!
//! There are four levels of lookup tables. The first is the top-level table, of which only one
//! exists; this table represents the global IPv4 space with the subnet `0.0.0.0/0`. The top-level
//! table is indexed with the first octet of an IPv4 address. Each element in the top-level table
//! points to a second-level table, of which there are 256; a second-level table has the CIDR `/8`
//! and is indexed by the second octet. Each element in a second-level table points to a third-level
//! table, which is indexed by the third octet, and so on. Finally, fourth-level tables are indexed
//! by the fourth and final octet and return the record for the host with that full IP address.
//!
//! This makes [`Table`] *great* for forwards lookups but *terrible* for reverse lookups and
//! counting how many host records are stored.


use std::{fs, io, mem, net::Ipv4Addr, num::NonZeroU32, ops::Range, path::Path};

use memmap::{MmapMut, MmapOptions};

use crate::Host;

/// The size, in bytes, of a [`Header`] or [`Node`].
const BLOCK_SIZE: usize = 1024;

// Run [`check_layout`] at compile time.
const _: () = check_layout();

/// Asserts that table blocks will be laid out in memory correctly.
///
/// This function should be called in a `const` context at compile-time.
///
/// # Panics
///
/// If either [`Header`] or [`Node`] are not of size [`BLOCK_SIZE`], this function will panic.
#[allow(unused)]
const fn check_layout() {
    let header_size = mem::size_of::<Header>();
    const_panic::concat_assert!(
        header_size == BLOCK_SIZE,
        "Header size (",
        header_size,
        ") != BLOCK_SIZE (",
        BLOCK_SIZE,
        ")\n",
    );

    let node_size = mem::size_of::<Node>();
    const_panic::concat_assert!(
        node_size == BLOCK_SIZE,
        "Node size (",
        node_size,
        ") != BLOCK_SIZE (",
        BLOCK_SIZE,
        ")\n",
    );
}

/// An error returned by [`open_file`].
pub enum OpenFileError {
    /// The call to `File::open` failed.
    Open(io::Error),
    /// The call to [`MmapOptions::map`] failed.
    Map(io::Error),
    /// The call to [`Table::new`] or [`Table::load`] failed.
    CreateTable(CreateTableError),
}

/// Attempts to load a [table](`Table`) from the file at the given path, or creates a new table if
/// the file doesn't exist.
pub fn open_file(path: impl AsRef<Path>) -> Result<Table, OpenFileError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        // Open the file if it exists, or create it otherwise.
        .create(true)
        .open(path)
        .map_err(OpenFileError::Open)?;
    let file_is_new = match file.metadata() {
        Ok(meta) => meta.len() == 0,
        // If retrieving the metadata fails, we should err on the side of caution by trying to load
        // `file` as a valid table instead of potentially overwriting it if the file is, in fact,
        // not new.
        Err(_) => false,
    };
    let mmap_opts = MmapOptions::new();
    // SAFETY: the *memmap* documentation provides no clues as to what invariants must be upheld for
    // [`MmapOptions::map_mut`] to be 'safe', so I really couldn't tell you if this is safe or not.
    let mmap = unsafe { mmap_opts.map_mut(&file) }.map_err(OpenFileError::Map)?;

    if file_is_new {
        Table::new(mmap)
    } else {
        Table::load(mmap)
    }
    .map_err(OpenFileError::CreateTable)
}

/// An error returned by [`Table::new`] or [`Table::load`].
pub enum CreateTableError {
    /// The buffer is too small to contain a complete table header.
    ///
    /// This error is returned when the buffer is less than 1024 bytes in size.
    IncompleteHeader,
}

impl Table {
    /// Creates a new table, overwriting the content in the given buffer.
    ///
    /// # Arguments
    ///
    /// `mmap` is a mutable memory-mapped buffer.
    ///
    /// # Errors
    ///
    /// [`MmapError::IncompleteHeader`] is returned when `mmap` is less than 1024 bytes in size.
    pub fn new(mmap: MmapMut) -> Result<Self, CreateTableError> {
        Self::with_mmap(mmap, |_| Header::new())
    }

    /// Loads a table from the given buffer.
    ///
    /// Changes to the table are written back to the buffer.
    ///
    /// # Arguments
    ///
    /// `mmap` is a mutable memory-mapped buffer.
    pub fn load(mmap: MmapMut) -> Result<Self, CreateTableError> {
        Self::with_mmap(mmap, |mmap| {
            // SAFETY: [`with_mmap`] has guaranteed that the buffer contains a complete header.
            let header = unsafe { mmap.get_header_unchecked() };
            let header: &Header = bytemuck::from_bytes(header);

            mem::copy(header)
        })
    }

    fn with_mmap(
        mmap: MmapMut,
        get_header: impl FnOnce(&MmapMut) -> Header,
    ) -> Result<Self, CreateTableError> {
        match BufferSize::from_mmap(&mmap) {
            BufferSize::IncompleteHeader => Err(CreateTableError::IncompleteHeader),
            BufferSize::Blocks(block_count) => {
                Ok(Self {
                    header: get_header(&mmap),
                    mmap,
                    block_count,
                })
            }
        }
    }
}

impl BufferSize {
    fn from_mmap(mmap: &MmapMut) -> Self {
        Self::from(mmap.len())
    }
}

impl From<usize> for BufferSize {
    fn from(size: usize) -> Self {
        // The number of whole nodes that will fit into a buffer of the given size.
        let blocks = size / BLOCK_SIZE;

        if blocks == 0 {
            Self::IncompleteHeader
        } else {
            Self::Blocks(blocks)
        }
    }
}

/// The relevant size of a [buffer](`MmapMut`).
enum BufferSize {
    /// The buffer is too small to contain a complete [table header](`Header`).
    IncompleteHeader,
    /// The buffer contains a complete [header](`Header`) and can accomodate this number of blocks.
    ///
    /// This value is guaranteed to be at least one.
    Blocks(usize),
}

trait Buffer {
    /// Returns an immutable reference to the block with at the given index, or [`None`] if it
    /// doesn't exist.
    fn get_block(&self, index: usize) -> Option<&[u8]>;

    /// Returns a mutable reference to the block at the given index, or [`None`] if it doesn't
    /// exist.
    fn get_block_mut(&mut self, index: usize) -> Option<&mut [u8]>;

    /// Returns an immutable reference to the block at the given index without first asserting that
    /// it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the requested block.
    unsafe fn get_block_unchecked(&self, index: usize) -> &[u8];

    /// Returns a mutable reference to the block at the given index without first asserting that it
    /// exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the requested block.
    unsafe fn get_block_unchecked_mut(&mut self, index: usize) -> &mut [u8];
}

trait BufferExt {
    /// Returns an immutable reference to the table header without first asserting that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the table header.
    unsafe fn get_header_unchecked(&self) -> &[u8];

    /// Returns a mutable reference to the table header without first asserting that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the table header.
    unsafe fn get_header_unchecked_mut(&mut self) -> &mut [u8];
}

impl<T: Buffer> BufferExt for T {
    unsafe fn get_header_unchecked(&self) -> &[u8] {
        self.get_block_unchecked(0)
    }

    unsafe fn get_header_unchecked_mut(&mut self) -> &mut [u8] {
        self.get_block_unchecked_mut(0)
    }
}

impl Buffer for MmapMut {
    fn get_block(&self, index: usize) -> Option<&[u8]> {
        get_block_impl(index, |range| self.get(range))
    }

    fn get_block_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        get_block_impl(index, |range| self.get_mut(range))
    }

    unsafe fn get_block_unchecked(&self, index: usize) -> &[u8] {
        get_block_impl(index, |range| self.get_unchecked(range))
    }

    unsafe fn get_block_unchecked_mut(&mut self, index: usize) -> &mut [u8] {
        get_block_impl(index, |range| self.get_unchecked_mut(range))
    }
}

fn get_block_impl<'a, T: 'a>(
    index: usize,
    get: impl 'a + FnOnce(Range<usize>) -> T,
) -> T {
    let start = BLOCK_SIZE * index;
    let end = BLOCK_SIZE * (index + 1);
    let range = start..end;
    assert_eq!(range.len(), BLOCK_SIZE);

    get(range)
}

pub struct Table {
    header: Header,
    mmap: MmapMut,
    block_count: usize,
}

impl Table {
    pub fn flush(&mut self) -> io::Result<()> {
        let header = bytemuck::bytes_of(&self.header);
        // Write our copy of the header to the buffer.
        // SAFETY: [`with_mmap`] guaranteed that the buffer contains a complete header.
        let _ = unsafe { self.mmap.get_header_unchecked_mut() }.copy_from_slice(header);

        // TODO: should we take a more granular approach to flushing?
        self.mmap.flush()
    }

    pub fn entry(&mut self, addr: Ipv4Addr) -> Result<HostEntry, ()> {
        let subnet = &mut self.header.root;

        let mut octets = addr.octets().into_iter().peekable();
        while let Some(octet) = octets.next() {
            match subnet.get_mut(octet) {
                Some(node_handle) => {
                    let node_handle = mem::copy(node_handle);
                    drop(subnet);

                    if self.contains_node(node_handle) {

                    } else {

                    }
                }
                entry @ None => {
                    if octets.peek().is_none() {
                        // This is the last octet, and the host entry is vacant.
                        return Ok(HostEntry::vacant(entry));
                    } else {
                        // This is *not* the last octet. We need to create new subnets as well as
                        // the host entry.
                        todo!()
                    }
                }
            }
        }

        todo!()
    }

    fn contains_node(&self, node: NodeHandle) -> bool {
        self.contains_block(node.block_index())
    }

    fn contains_block(&self, index: usize) -> bool {
        index <= self.max_block_index()
    }

    fn max_block_index(&self) -> usize {
        // SAFETY: `block_count` was guaranteed by [`BufferSize::from_mmap`] to be at least one.
        unsafe { self.block_count.unchecked_sub(1) }
    }

    fn is_full(&self) -> bool {
        self.header.next_free_block_index > self.max_block_index()
    }

    fn alloc_node(&mut self) -> Option<NodeHandle> {
        if self.is_full() {
            None
        } else {
            // SAFETY: we can contain at least one more node.
            unsafe { self.alloc_node_unchecked() }
        }
    }

    unsafe fn alloc_node_unchecked(&mut self) -> Option<NodeHandle> {
        let free_index = &mut self.header.next_free_block_index;
        assert_ne!(*free_index, 0);

        let node = NodeHandle {
            // SAFETY: we just asserted that `free_index` is at least one.
            block_index: unsafe { NonZeroU32::new_unchecked(*free_index) },
        };
        *free_index += 1;

        Some(node)
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // Let's try to flush the table a few times in case the first couple attempts fail.
        for _ in 0..3 {
            if self.flush().is_ok() {
                return;
            }
        }
        tracing::error!("failed to flush table");
    }
}

impl<'a> HostEntry<'a> {
    fn vacant(subnet_elem: &'a mut Option<NodeHandle>) -> Self {
        Self::Vacant(VacantHostEntry { subnet_elem })
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
    pub fn insert(self, _host: Host) -> &'a mut Host {
        todo!()
    }
}

impl Header {
    fn new() -> Self {
        Self {
            next_free_block_index: NodeHandle::first().block_index(),
            root: Subnet::default(),
        }
    }
}

#[repr(C, packed(4))]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Clone, Copy)]
struct Header {
    next_free_block_index: u32,
    root: Subnet,
}

impl NodeHandle {
    fn first() -> Self {
        Self {
            // TODO: replace this with [`NonZeroU32::MIN`] when stabilised.
            // SAFETY: 1 is nonzero.
            block_index: unsafe { NonZeroU32::new_unchecked(1) },
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
    block_index: NonZeroU32,
}

// SAFETY: see the above notice on [`NodeHandle::inner`]. There are no illegal bit patterns because
// 0 is assigned to [`None`] and anything else is `Some(handle)` where `handle` is a valid
// [`NodeHandle`] backed by a nonzero, unsigned integer.
unsafe impl bytemuck::PodInOption for NodeHandle {}
unsafe impl bytemuck::ZeroableInOption for NodeHandle {}

impl NodeHandle {
    fn next(&self) -> Option<Self> {
        Some(Self { block_index: self.block_index.checked_add(1)? })
    }

    fn block_index(self) -> u32 {
        self.block_index.get()
    }

    fn index(&self) -> u32 {
        let block_index = self.block_index();
        // SAFETY: `block_index` is at least one, so this cannot underflow.
        let node_index = unsafe { block_index.unchecked_sub(1) };

        node_index
    }
}

// The `repr(u32)` forces the discriminant to be of type `u32`.
#[repr(C, u32)]
#[allow(unused)]
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

// SAFETY: `Subnet` is an array of POD and zeroable types. The reason we have to implement these
// traits manually is because the corresponding derives do not support arrays with 255 elements (but
// they work with 256).
unsafe impl bytemuck::Pod for Subnet {}
unsafe impl bytemuck::Zeroable for Subnet {}

impl Subnet {
    fn get_mut(&mut self, octet: u8) -> &mut Option<NodeHandle> {
        if octet == 256 {
            // TODO: I still haven't figured out how to handle 256.
            todo!()
        } else {
            let index = usize::from(octet);

            // SAFETY: accessing the array is bijective.
            unsafe { self.0.get_unchecked_mut(index) }
        }
    }
}
