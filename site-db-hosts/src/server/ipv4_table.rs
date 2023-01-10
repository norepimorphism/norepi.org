// SPDX-License-Identifier: MPL-2.0

//! A stupid-simple IPv4 table.
//!
//! The eponymous [`Table`] type is like a lookup table where the indices are
//! [IPv4 addresses](Ipv4Addr) and the elements are host records.
//!
//! The primary API entrypoints are [`Table::new`] and [`Table::load`], which create a new table or
//! load an existing table, respectively, from a memory-mapped buffer. [`open_file`] is a
//! convenience function that attempts to deserialize a table from a file, creating a new table if
//! the file does not exist. Once significant changes have been made to a table, the
//! [`Table::flush`] method is used to flush the changes to disk. The table is also flushed on drop.
//!
//! # Limitations
//!
//! The term 'deserialize' is used loosely. No serialization scheme is employed, so the table is
//! stored on disk exactly the same as in memory. This makes for fast reads and writes, but the
//! major limitation is that table files are not portable. No guarantees are made regarding
//! compatibility with other systems, and the on-disk format is not endian-agnostic, so table files
//! created on a system with endianness *A* will be read incorrectly on a system with endianness
//! *B*. Endianness information is not encoded in the on-disk format, either.
//!
//! This module will also fail to compile on systems where `usize` is less than 32 bits in width.
//!
//! # Implementation
//!
//! ## Design
//!
//! An IPv4 table is like a [trie] where terminal nodes are host records and where parent nodes are
//! implemented as lookup tables of children nodes. Alternatively, an IPv4 table is like a linked
//! list of lookup tables where each table represents a subnet and is indexed by one octet in an
//! IPv4 address.
//!
//! [trie]: https://en.wikipedia.org/wiki/Trie
//!
//! There are four levels of lookup tables---one for each octet in an IPv4 address. The first table
//! is the top-level table, of which only one exists; this table represents the global IPv4 space
//! with the subnet `0.0.0.0/0`. The top-level table is indexed with the first, or most-significant
//! octet of an IPv4 address. Each element in the top-level table points to a second-level table, of
//! which there are 256; a second-level table has the CIDR `/8` and is indexed by the second octet,
//! and so on. Finally, fourth-level tables are indexed by the fourth and last, or least-significant
//! octet and return the record for the host with that full IP address.
//!
//! This design makes `Table` *great* for forwards lookups but *terrible* for reverse lookups and
//! counting how many host records are stored.
//!
//! ## Format
//!
//! All table data is stored in a memory-backed buffer. The buffer is divided into logical *blocks*,
//! each 1024 bytes in size, without any padding between them. The first two blocks in a buffer are
//! special:
//! 1. **Table Header**: contains metadata about a table. Currently, the table header is only used
//!    for block allocation management.
//! 2. **The Top-level Subnet Table**: the top-level subnet table described in
//!    [Implementation](#implementation). It is an array of 256 pointers to second-level tables.
//!
//! The remaining blocks are inhabited by *nodes*, which refer collectively to the second-, third-,
//! and fourth-level subnet tables as well as host records. Nodes do not contain self-describing
//! metadata and their existence is known only by the subnet table that points to them. Nodes are
//! disambiguated by context; a node pointed to by a third-level subnet table is a fourth-level
//! table, whereas a node pointed to by a fourth-level table is a host record.

use std::{
    fmt,
    fs,
    io,
    marker::PhantomData,
    mem,
    net::Ipv4Addr,
    num::NonZeroU32,
    path::Path,
};

use error_stack::{IntoReport as _, Result, ResultExt as _};
use memmap2::{MmapMut, MmapOptions};
use smallvec::SmallVec;

/// The size, in bytes, of a block.
pub const BLOCK_SIZE: usize = 1024;

/// An untyped block.
pub type Block = [u8; BLOCK_SIZE];

// Run [`check_layout`] at compile time.
//
// Pretty cool trick, right?
const _: () = check_layout();

/// Asserts that table blocks will be laid out in memory correctly.
///
/// This function should be called in a `const` context at compile-time.
///
/// # Panics
///
/// If [`Header`] or [`Subnet`] are not of size [`BLOCK_SIZE`], this function will panic.
#[allow(unused)]
const fn check_layout() {
    macro_rules! assert_ty_size_eq {
        ($ty:ty, $exp_size:expr $(,)?) => {{
            let ty_size = mem::size_of::<$ty>();
            const_panic::concat_assert!(
                ty_size == $exp_size,
                stringify!($ty),
                " size (",
                ty_size,
                ") != ",
                stringify!($exp_size),
                " (",
                $exp_size,
                ")\n",
            );
        }};
    }

    assert_ty_size_eq!(Header, BLOCK_SIZE);
    assert_ty_size_eq!(Subnet, BLOCK_SIZE);
}

/// Losslessly converts a `u32` into a `usize`.
fn usize_from_u32(value: u32) -> usize {
    #[cfg(any(target_pointer_width = "8", target_pointer_width = "16"))]
    {
        compile_error!(
            "Target pointer width is less than 32 bits; cannot losslessly convert u32 to usize"
        );
    }

    // Note: we are guaranteed that the target pointer width is at least 32 bits, so this `as` cast
    // will not truncate any useful information.
    value as usize
}

/// An error returned by [`open_file`].
#[derive(thiserror::Error, Debug)]
pub enum OpenFileError {
    /// The call to [`fs::OpenOptions::open`] failed.
    #[error("std::fs::OpenOptions::open() failed")]
    Open,
    /// The call to [`MmapOptions::map_mut`] failed.
    #[error("memmap2::MmapOptions::map_mut() failed")]
    MapMut,
    /// The call to [`Table::new`] or [`Table::load`] failed.
    #[error("failed to create a table for the file")]
    CreateTable,
}

/// An error contained in [`OpenFileError`] that is instantiated when [`Table::new`] or
/// [`Table::load`] fail.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum CreateTableError {
    /// The call to [`Table::new`] failed.
    #[error("failed to create new table")]
    New,
    /// The call to [`Table::load`] failed.
    #[error("failed to load existing table")]
    Load,
}

/// Attempts to load a [table](Table) from the file at the given path, or creates a new table if
/// the file doesn't exist.
///
/// If the file doesn't exist, it is created with a size of 10,000 [blocks](Block). There is
/// currently no mechanism to resize a table after creation.
//
// FIXME: The initial block size should be customizable (maybe via a builder?) and tables should be
// resizable after creation. It's probably not that hard to implement, either.
#[tracing::instrument]
pub fn open_file(path: impl AsRef<Path> + fmt::Debug) -> Result<Table, OpenFileError> {
    const NEW_FILE_SIZE: u64 = 10_000 * (BLOCK_SIZE as u64);

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        // Open the file if it exists, or create it otherwise.
        .create(true)
        .truncate(false)
        .open(path)
        .into_report()
        .change_context(OpenFileError::Open)?;
    let file_is_new = match file.metadata() {
        Ok(meta) => meta.len() == 0,
        // If retrieving the metadata fails, we should err on the side of caution by trying to load
        // `file` as a valid table instead of potentially overwriting it if the file is, in fact,
        // not new.
        Err(_) => false,
    };
    if file_is_new {
        file.set_len(NEW_FILE_SIZE).expect("failed to set size of new table file");
    }

    let mmap_opts = MmapOptions::new();
    // SAFETY: ???
    // FIXME: the *memmap* documentation provides no clues as to what invariants must be upheld for
    // [`MmapOptions::map_mut`] to be 'safe', so I really couldn't tell you if this is safe or not.
    let mmap = unsafe { mmap_opts.map_mut(&file) }
        .into_report()
        .change_context(OpenFileError::MapMut)?;

    if file_is_new {
        Table::new(mmap).change_context(CreateTableError::New)
    } else {
        Table::load(mmap).change_context(CreateTableError::Load)
    }
    .change_context(OpenFileError::CreateTable)
}

/// An error returned by [`Table::new`].
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum NewTableError {
    /// The buffer is too small to contain a valid table.
    ///
    /// This error is returned when the buffer is less than 2048 bytes in size.
    #[error("buffer is smaller than 2048 bytes")]
    BufferTooSmall,
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
    /// [`NewTableError::BufferTooSmall`] is returned when `mmap` is less than 2048 bytes in size.
    pub fn new(mmap: MmapMut) -> Result<Self, NewTableError> {
        Self::with_mmap(
            mmap,
            |_| Header::new(),
            |_| Subnet::new(),
            NewTableError::BufferTooSmall,
        )
    }
}

/// An error returned by [`Table::load`].
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LoadTableError {
    /// The buffer is too small to contain a valid table.
    ///
    /// This error is returned when the buffer is less than 2048 bytes in size.
    #[error("buffer is smaller than 2048 bytes")]
    BufferTooSmall,
}

impl Table {
    /// Loads a table from the given buffer.
    ///
    /// Changes to the table are written back to the buffer.
    ///
    /// # Arguments
    ///
    /// `mmap` is a mutable memory-mapped buffer.
    ///
    /// # Errors
    ///
    /// [`LoadTableError::BufferTooSmall`] is returned when `mmap` is less than 2048 bytes in size.
    /// [`LoadTableError::InvalidHeaderStamp`] is returned if the table is invalid.
    pub fn load(mmap: MmapMut) -> Result<Self, LoadTableError> {
        Self::with_mmap(
            mmap,
            |mmap| {
                // SAFETY: [`with_mmap`] has guaranteed that the buffer contains a complete header.
                mem::copy(unsafe { mmap.get_header_unchecked() })
            },
            |mmap| {
                // SAFETY: [`with_mmap`] has guaranteed that the buffer contains a complete
                // top-level subnet.
                mem::copy(unsafe { mmap.get_top_level_subnet_unchecked() })
            },
            LoadTableError::BufferTooSmall,
        )
    }
}

impl Table {
    /// Creates a `Table` with the given strategies for obtaining the [header](Header) and top-level
    /// [subnet](Subnet).
    ///
    /// # Arguments
    ///
    /// `mmap` is a mutable memory-mapped buffer. `get_header` is a function that provides a header,
    /// and `get_top_level_subnet` is a function that provides a top-level subnet. `too_small_error`
    /// is an instance of an error type that is returned if [`BufferSize::from_mmap`] returns
    /// [`BufferSize::TooSmall`].
    ///
    /// Both `get_header` and `get_top_level_subnet` may assume that `mmap` is large enough to
    /// contain a header and top-level subnet.
    fn with_mmap<E: error_stack::Context>(
        mmap: MmapMut,
        get_header: impl FnOnce(&MmapMut) -> Header,
        get_top_level_subnet: impl FnOnce(&MmapMut) -> Subnet,
        too_small_error: E,
    ) -> Result<Self, E> {
        match BufferSize::from_mmap(&mmap) {
            BufferSize::TooSmall => Err(error_stack::report!(too_small_error)),
            BufferSize::Blocks(block_count) => {
                tracing::info!("block_count: {}", block_count);

                Ok(Self {
                    header: get_header(&mmap),
                    top_level_subnet: get_top_level_subnet(&mmap),
                    block_count,
                    mmap,
                })
            }
        }
    }
}

impl BufferSize {
    /// Generates a `BufferSize` from the size of a memory-backed buffer.
    fn from_mmap(mmap: &MmapMut) -> Self {
        Self::from(mmap.len())
    }
}

impl From<usize> for BufferSize {
    /// Generates a `BufferSize` from a size in bytes.
    fn from(size: usize) -> Self {
        // This is the number of whole nodes that will fit into a buffer of the given size.
        let blocks = size / BLOCK_SIZE;

        // We need at least two blocks to contain the header and top-level subnet.
        if blocks < 2 {
            Self::TooSmall
        } else {
            Self::Blocks(blocks)
        }
    }
}

/// The approximate size of a [buffer](MmapMut).
enum BufferSize {
    /// The buffer is too small to contain a complete [table header]`Header) and top-level
    /// [subnet](Subnet).
    TooSmall,
    /// The buffer contains a complete [header](Header) and top-level [subnet](Subnet) and can
    /// accommodate this number of blocks.
    ///
    /// This value is guaranteed to be at least two, including the header and top-level subnet.
    Blocks(usize),
}

/// Provides [`as_blocks`](AsBlocks::as_blocks) and [`as_blocks_mut`](AsBlocks::as_blocks_mut).
trait AsBlocks {
    /// Returns an immutable slice of [blocks](Block).
    fn as_blocks(&self) -> &[Block];

    /// Returns a mutable slice of [blocks](Block).
    fn as_blocks_mut(&mut self) -> &mut [Block];
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsBlocks for T {
    fn as_blocks(&self) -> &[Block] {
        self.as_ref().as_chunks::<BLOCK_SIZE>().0
    }

    fn as_blocks_mut(&mut self) -> &mut [Block] {
        self.as_mut().as_chunks_mut::<BLOCK_SIZE>().0
    }
}

trait Buffer {
    /// Returns an immutable reference to the block at the given index, or [`None`] if it doesn't
    /// exist.
    fn get_block(&self, index: usize) -> Option<&Block>;

    /// Returns a mutable reference to the block at the given index, or [`None`] if it doesn't
    /// exist.
    fn get_block_mut(&mut self, index: usize) -> Option<&mut Block>;

    /// Returns an immutable reference to the block at the given index without performing bounds
    /// checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the requested block.
    unsafe fn get_block_unchecked(&self, index: usize) -> &Block;

    /// Returns a mutable reference to the block at the given index without performing bounds
    /// checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the requested block.
    unsafe fn get_block_unchecked_mut(&mut self, index: usize) -> &mut Block;
}

impl<T: AsBlocks> Buffer for T {
    fn get_block(&self, index: usize) -> Option<&Block> {
        self.as_blocks().get(index)
    }

    fn get_block_mut(&mut self, index: usize) -> Option<&mut Block> {
        self.as_blocks_mut().get_mut(index)
    }

    unsafe fn get_block_unchecked(&self, index: usize) -> &Block {
        self.as_blocks().get_unchecked(index)
    }

    unsafe fn get_block_unchecked_mut(&mut self, index: usize) -> &mut Block {
        self.as_blocks_mut().get_unchecked_mut(index)
    }
}

trait BufferExt {
    /// Returns an immutable reference to the table header without performing bounds checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the table header.
    unsafe fn get_header_unchecked(&self) -> &Header;

    /// Returns a mutable reference to the table header without performing bounds checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the table header.
    unsafe fn get_header_unchecked_mut(&mut self) -> &mut Header;

    /// Returns an immutable reference to the top-level subnet table without performing bounds
    /// checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the top-level subnet.
    unsafe fn get_top_level_subnet_unchecked(&self) -> &Subnet;

    /// Returns a mutable reference to the top-level subnet table without performing bounds checks.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accommodate the top-level subnet.
    unsafe fn get_top_level_subnet_unchecked_mut(&mut self) -> &mut Subnet;

    /// Returns an immutable reference to the node with the given handle, or [`None`] if it doesn't
    /// exist.
    fn get_node(&self, handle: NodeHandle) -> Option<&Block>;

    /// Returns a mutable reference to the node with the given handle, or [`None`] if it doesn't
    /// exist.
    fn get_node_mut(&mut self, handle: NodeHandle) -> Option<&mut Block>;
}

impl<T: Buffer> BufferExt for T {
    unsafe fn get_header_unchecked(&self) -> &Header {
        bytemuck::from_bytes(self.get_block_unchecked(0))
    }

    unsafe fn get_header_unchecked_mut(&mut self) -> &mut Header {
        bytemuck::from_bytes_mut(self.get_block_unchecked_mut(0))
    }

    unsafe fn get_top_level_subnet_unchecked(&self) -> &Subnet {
        bytemuck::from_bytes(self.get_block_unchecked(1))
    }

    unsafe fn get_top_level_subnet_unchecked_mut(&mut self) -> &mut Subnet {
        bytemuck::from_bytes_mut(self.get_block_unchecked_mut(1))
    }

    fn get_node(&self, handle: NodeHandle) -> Option<&Block> {
        self.get_block(handle.block_index()?)
    }

    fn get_node_mut(&mut self, handle: NodeHandle) -> Option<&mut Block> {
        self.get_block_mut(handle.block_index()?)
    }
}

/// A stupid-simple IPv4 table.
#[derive(Debug)]
pub struct Table {
    header: Header,
    top_level_subnet: Subnet,
    block_count: usize,
    mmap: MmapMut,
}

impl Table {
    /// Writes-back changes to disk.
    ///
    /// This function is automatically called when a `Table` is [dropped](Drop), but you can call it
    /// more often if you like.
    pub fn flush(&mut self) -> io::Result<()> {
        // Write our copy of the header to the buffer.
        // SAFETY: [`with_mmap`] guaranteed that the buffer contains a complete header.
        *unsafe { self.mmap.get_header_unchecked_mut() } = self.header;
        // Write our copy of the top-level subnet to the buffer.
        // SAFETY: `with_mmap` also guaranteed that the buffer contains a complete top-level subnet.
        *unsafe { self.mmap.get_top_level_subnet_unchecked_mut() } = self.top_level_subnet;

        // Finally, flush everything to disk.
        // FIXME: should we take a more granular approach to flushing?
        self.mmap.flush()
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

/// An error returned by [`Table::entry`].
#[derive(thiserror::Error, Debug)]
pub enum TableEntryError {
    #[error("followed invalid node handle")]
    FollowedInvalidNodeHandle,
}

/// A view into a single host entry in a [table](Table), which may either be vacant or occupied.
///
/// This is constructed from [`Table::entry`] and is analogous to
/// [`hash_map::Entry`](std::collections::hash_map::Entry).
pub enum HostEntry<'a> {
    /// An occupied entry.
    Occupied(&'a mut Block),
    /// A vacant entry.
    Vacant(VacantHostEntry<'a>),
}

impl Table {
    /// Gets the host entry in the table corresponding to the given IP address for in-place
    /// manipulation.
    ///
    /// This method is analogous to [`HashMap::entry`](std::collections::HashMap).
    #[tracing::instrument(skip(self))]
    pub fn entry<'a>(&'a mut self, addr: Ipv4Addr) -> Result<HostEntry<'a>, TableEntryError> {
        // Foreword: The implementation of this method is fairly complicated due to constraints
        // imposed by the borrow-checker, *borrowck*. Namely, we cannot hold multiple exclusive
        // references to `self`, nor can we hold multiple exclusive references to the memory-backed
        // buffer in which all table blocks are contained. We must therefore be very careful in how
        // we borrow.
        //
        // The first trick is to call all necessary methods on `Self` and then destructure `self` to
        // ensure we cannot hold multiple exclusive references to it.
        //
        // The second trick is an egregious amount of `unsafe`, which we see in
        // [`VacantHostEntry::insert`].

        // This is necessary to allocate nodes, and we will use it later. We need to extract this
        // first before destructuring `self`.
        let max_block_index = self.max_block_index();
        // Destructure `self` so that we cannot hold multiple exclusive references to it.
        let Self {
            header,
            top_level_subnet,
            mmap,
            ..
        } = self;

        // `subnet_indices` is an iterator over the first three octets of the IP address, and
        // `host_index` is the last octet of the IP address. Both are used to index subnet tables,
        // but `subnet_indices` return another subnet table whereas a `host_index` returns an entry
        // to a host.
        let (mut subnet_indices, host_index) = {
            let octets = addr.octets();
            let host_index = octets[3];
            let subnet_indices = octets.into_iter().take(3);

            (subnet_indices, host_index)
        };

        // This is a mutable reference to the current subnet table we are investigating.
        //
        // The first iteration over `subnet_indices` uses `top_level_subnet`, and following
        // iterations reference subnet tables from the buffer.
        let mut current_subnet = top_level_subnet;

        while let Some(subnet_index) = subnet_indices.next() {
            // Let's see if this subnet table contains an entry for this octet.
            match current_subnet.get_mut(subnet_index) {
                // It does. This entry should represent another subnet table.
                &mut Some(next_subnet_handle) => {
                    // Next, we will attempt to obtain a reference to this next subnet table.

                    // We don't need this anymore.
                    drop(current_subnet);

                    match mmap.get_node_mut(next_subnet_handle) {
                        Some(subnet) => {
                            // Recurse to the next-level subnet table.
                            current_subnet = bytemuck::from_bytes_mut(subnet);
                            continue;
                        }
                        // The handle pointed to a subnet that does not exist.
                        None => {
                            error_stack::bail!(TableEntryError::FollowedInvalidNodeHandle);
                        }
                    }
                }
                // It does not contain an entry for this octet. We can assume that the host entry is
                // vacant.
                entry => {
                    // We will now construct a [`HostEntry::vacant`], but there is one problem:
                    // we would like to pass `header`, `entry`, and `mmap` to the `HostEntry` by
                    // reference, but doing do would violate borrowing rules. But, no worries, as
                    // we can pass them by pointers and figure out the borrowing stuff later.
                    return Ok(HostEntry::Vacant(VacantHostEntry {
                        insert_strategy: InsertHostStrategy::InsertSubnetsAndHost {
                            header: header as *mut Header,
                            max_block_index,
                            // Collect these into an inlined [`SmallVec`].
                            subnet_indices: subnet_indices
                                .chain(std::iter::once(host_index))
                                .collect(),
                            // Note: the object referenced by `entry` will not die when this
                            // function ends because the memory will still exist in `mmap`.
                            first_subnet_entry: entry as *mut Option<NodeHandle>,
                            mmap: mmap as *mut MmapMut,
                        },
                        _phantom: PhantomData,
                    }));
                }
            }
        }

        // At this point, `current_subnet` should contain host entries and not links to other
        // tables. We will rename it to reflect this.
        let host_table = current_subnet;

        // Does the host table contain an entry for this host?
        match host_table.get_mut(host_index) {
            // It does.
            &mut Some(host_handle) => {
                match mmap.get_node_mut(host_handle) {
                    Some(host) => {
                        Ok(HostEntry::Occupied(host))
                    }
                    None => Err(error_stack::report!(TableEntryError::FollowedInvalidNodeHandle)),
                }
            }
            // It does not, so the host entry is vacant.
            entry => {
                Ok(HostEntry::Vacant(VacantHostEntry {
                    insert_strategy: InsertHostStrategy::InsertHostOnly {
                        header: header as *mut Header,
                        max_block_index,
                        // Note: the object referenced by `entry` will not die when this function
                        // ends because the memory will still exist in `mmap`.
                        host_table_entry: entry as *mut Option<NodeHandle>,
                        mmap: mmap as *mut MmapMut,
                    },
                    _phantom: PhantomData,
                }))
            }
        }
    }

    /// The index of the last block after which no more blocks may be allocated.
    fn max_block_index(&self) -> usize {
        // SAFETY: `block_count` was guaranteed by [`BufferSize::from_mmap`] to be at least one.
        unsafe { self.block_count.unchecked_sub(1) }
    }
}

/// A view into a vacant host entry in a [`Table`].
///
/// This is part of the [`HostEntry`] `enum` and is analogous to
/// [`hash_map::VacantEntry`](std::collections::hash_map::VacantEntry).
pub struct VacantHostEntry<'a> {
    /// The strategy that [`insert`](VacantHostEntry::insert) should use.
    insert_strategy: InsertHostStrategy,
    _phantom: PhantomData<&'a ()>,
}

/// A strategy to insert a host into a [vacant entry](VacantHostEntry).
enum InsertHostStrategy {
    /// One or more subnet tables must be inserted in addition to the host.
    InsertSubnetsAndHost {
        header: *mut Header,
        max_block_index: usize,
        subnet_indices: SmallVec<[u8; 4]>,
        first_subnet_entry: *mut Option<NodeHandle>,
        mmap: *mut MmapMut,
    },
    /// Only the host need be inserted into the table.
    InsertHostOnly {
        header: *mut Header,
        max_block_index: usize,
        host_table_entry: *mut Option<NodeHandle>,
        mmap: *mut MmapMut,
    },
}

type InsertHostResult<'a> = Result<&'a mut Block, InsertHostError>;

/// An error returned by [`VacantHostEntry::insert`].
#[derive(thiserror::Error, Debug)]
pub enum InsertHostError {
    #[error("too many nodes")]
    TooManyNodes,
    #[error("buffer is out of space")]
    OutOfSpace,
}

impl<'a> VacantHostEntry<'a> {
    pub fn insert(self, new_host: Block) -> InsertHostResult<'a> {
        match self.insert_strategy {
            InsertHostStrategy::InsertSubnetsAndHost {
                header,
                max_block_index,
                subnet_indices,
                first_subnet_entry,
                mmap,
            } => {
                Self::insert_subnets_and_host(
                    header,
                    max_block_index,
                    subnet_indices,
                    first_subnet_entry,
                    mmap,
                    new_host,
                )
            }
            InsertHostStrategy::InsertHostOnly {
                header,
                max_block_index,
                host_table_entry,
                mmap,
            } => {
                Self::insert_host_only(header, max_block_index, host_table_entry, mmap, new_host)
            }
        }
    }

    fn insert_subnets_and_host(
        header: *mut Header,
        max_block_index: usize,
        subnet_indices: SmallVec<[u8; 4]>,
        first_subnet_entry: *mut Option<NodeHandle>,
        mmap: *mut MmapMut,
        new_host: Block,
    ) -> InsertHostResult<'a> {
        tracing::info!("inserting {} subnet tables", subnet_indices.len());

        let mut current_subnet_entry = first_subnet_entry;

        // On insertion, we need to generate new subnet tables for the remaining
        // octets.
        for next_subnet_index in subnet_indices {
            // Allocate a handle for the next subnet table.
            // SAFETY: no other variables were aliasing `header`, and we immediately discarded the
            // reference to avoid aliasing down the road.
            let handle = unsafe { &mut *header }
                .alloc_node(max_block_index)
                .ok_or(InsertHostError::TooManyNodes)?;
            // Replace the `None` entry in the current subnet table with a `Some(handle)` to the
            // next table.
            // SAFETY: no other variables were aliasing `current_subnet_entry`, and we immediately
            // discarded the reference.
            unsafe { *current_subnet_entry = Some(handle) };

            // Obtain a reference to this new subnet table.
            // SAFETY: no other variables were aliasing `mmap`. Note that `current_subnet` is now
            // borrowing from `mmap`, but that's okay for now.
            let current_subnet = unsafe { &mut *mmap }
                .get_node_mut(handle)
                .ok_or(InsertHostError::OutOfSpace)
                .map(|node| bytemuck::from_bytes_mut(node))?;
            // Initialize the new table.
            *current_subnet = Subnet::new();

            // Our next entry to fix is `current_subnet[next_subnet_index]`.
            current_subnet_entry = current_subnet.get_mut(next_subnet_index) as *mut _;
            // Note: `current_subnet` gets dropped here.
        }

        Self::insert_host_only(header, max_block_index, current_subnet_entry, mmap, new_host)
    }

    fn insert_host_only(
        header: *mut Header,
        max_block_index: usize,
        host_table_entry: *mut Option<NodeHandle>,
        mmap: *mut MmapMut,
        new_host: Block,
    ) -> InsertHostResult<'a> {
        // SAFETY: no other variables were aliasing `header`, and we immediately discarded the
        // reference.
        let handle = unsafe { &mut *header }
            .alloc_node(max_block_index)
            .ok_or(InsertHostError::TooManyNodes)?;
        // Replace the `None` entry with `Some(handle)`.
        // SAFETY: no other variables were aliasing `host_table_entry`, and we immediately discarded
        // the reference.
        unsafe { *host_table_entry = Some(handle); }

        // SAFETY: no other variables were aliasing `mmap`. Note that `host` is now borrowing from
        // `mmap`, but that's okay because this is the last of the unsafety.
        let host: &mut Block = unsafe { &mut *mmap }
            .get_node_mut(handle)
            .ok_or(InsertHostError::OutOfSpace)?;
        // Initialize the new host record.
        *host = new_host;

        Ok(host)
    }
}

/// A handle to a node.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct NodeHandle {
    // The only reason this type is [`NonZeroU32`] is because it exploits the Nullable Pointer
    // Optimization. There is no semantic significance to zero being unrepresentable. Also, this
    // value is not useful by itself because it represents neither a block or node index.
    //
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
    value: NonZeroU32,
}

// SAFETY: see the above notice on [`NodeHandle::inner`]. There are no illegal bit patterns because
// 0 is assigned to [`None`] and anything else is `Some(handle)` where `handle` is a valid
// [`NodeHandle`] backed by a nonzero, unsigned integer.
unsafe impl bytemuck::PodInOption for NodeHandle {}
unsafe impl bytemuck::ZeroableInOption for NodeHandle {}

impl NodeHandle {
    fn from_index(index: u32) -> Option<Self> {
        let value = index.checked_add(1)?;

        Some(Self {
            // SAFETY: `index` is positive and we have added one, so `value` must be at least one.
            value: unsafe { NonZeroU32::new_unchecked(value) },
        })
    }

    unsafe fn from_index_unchecked(index: u32) -> Self {
        Self { value: NonZeroU32::new_unchecked(index.unchecked_add(1)) }
    }

    fn first() -> Self {
        Self {
            // Note: [`NodeHandle::index`] will return 0, not 1.
            value: NonZeroU32::MIN,
        }
    }

    // FIXME: would this be useful for walking a table?
    #[allow(unused)]
    fn next(&self) -> Option<Self> {
        Some(Self { value: self.value.checked_add(1)? })
    }

    fn index(self) -> u32 {
        // SAFETY: `value` is nonzero, so it must be at least one.
        unsafe { self.value.get().unchecked_sub(1) }
    }

    fn block_index(self) -> Option<usize> {
        usize_from_u32(self.index()).checked_add(2)
    }
}

impl Header {
    fn new() -> Self {
        Self {
            next_free_node: NodeHandle::first().index(),
            reserved: [0; 1020],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct Header {
    next_free_node: u32,
    reserved: [u8; 1020],
}

impl Header {
    fn alloc_node(&mut self, max_block_index: usize) -> Option<NodeHandle> {
        if self.is_full(max_block_index) {
            tracing::error!("table is full");
            return None;
        }

        // SAFETY: we can contain at least one more node.
        unsafe { self.alloc_node_unchecked() }
    }

    fn is_full(&self, max_block_index: usize) -> bool {
        matches!(self.usage(max_block_index), TableUsage::Full)
    }
}

pub enum TableUsage {
    Full,
    NotFull {
        remaining_blocks: usize,
    }
}

impl Table {
    pub fn remaining_blocks(&self) -> usize {
        match self.usage() {
            TableUsage::Full => 0,
            TableUsage::NotFull { remaining_blocks: it } => it,
        }
    }

    pub fn usage(&self) -> TableUsage {
        self.header.usage(self.max_block_index())
    }
}

impl Header {
    fn usage(&self, max_block_index: usize) -> TableUsage {
        match NodeHandle::from_index(self.next_free_node) {
            Some(next_free_node) => {
                match next_free_node.block_index() {
                    Some(block_index) => {
                        if block_index <= max_block_index {
                            // SAFETY: TODO
                            let remaining_blocks = unsafe {
                                max_block_index.unchecked_sub(block_index)
                            };
                            tracing::debug!("remaining_blocks: {remaining_blocks}");

                            TableUsage::NotFull { remaining_blocks }
                        } else {
                            TableUsage::Full
                        }
                    }
                    None => {
                        // `next_free_node` is unrepresentable as a block index, so we cannot
                        // continue.
                        TableUsage::Full
                    }
                }
            }
            // `next_free_node` is unrepresentable as a node handle, so we cannot continue.
            None => TableUsage::Full,
        }
    }

    unsafe fn alloc_node_unchecked(&mut self) -> Option<NodeHandle> {
        // SAFETY: [`Table::is_full`] has guaranteed us that we can create a valid node handle from
        // `next_free_node`.
        let alloced_node = NodeHandle::from_index_unchecked(self.next_free_node);
        // SAFETY: `Table::is_full` has also guaranteed that we can increment `next_free_node`. This
        // is actually the same guarantee as being able to soundly call
        // [`NodeHandle::from_index_unchecked`].
        self.next_free_node = self.next_free_node.unchecked_add(1);

        tracing::debug!("alloced node with index {}", alloced_node.index());

        Some(alloced_node)
    }
}

// SAFETY: `Header` is a collection of POD types. The only reason we can't derive these traits is
// because `bytemuck` does not offer impls for an array like `[_; 1020]`.
unsafe impl bytemuck::Pod for Header {}
unsafe impl bytemuck::Zeroable for Header {}

impl Default for Subnet {
    fn default() -> Self {
        Self::new()
    }
}

impl Subnet {
    fn new() -> Self {
        Self([None; 256])
    }
}

#[repr(transparent)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Clone, Copy, Debug, PartialEq)]
struct Subnet([Option<NodeHandle>; 256]);

impl Subnet {
    #[tracing::instrument(skip(self))]
    fn get_mut(&mut self, octet: u8) -> &mut Option<NodeHandle> {
        let index = usize::from(octet);

        // SAFETY: accessing the array is bijective.
        unsafe { self.0.get_unchecked_mut(index) }
    }
}
