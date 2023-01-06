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
//! ## Design
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
//! The remaining blocks are inhabited by *nodes*, which refer collectively to subnet tables and
//! host records. Nodes do not contain self-describing metadata and their existence is known only
//! by the subnet table that points to them. Nodes are disambiguated by context.

use std::{
    fs,
    io,
    mem,
    net::Ipv4Addr,
    num::NonZeroU32,
    ops::Range,
    path::Path,
};

use memmap::{MmapMut, MmapOptions};
use smallvec::SmallVec;

use crate::Host;

/// The size, in bytes, of a block.
const BLOCK_SIZE: usize = 1024;

// Run [`check_layout`] at compile time.
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

fn usize_from_u32(value: u32) -> usize {
    // Note: this will always be OK because we are guaranteed by `cfg` directives that the target
    // pointer width is at least 32 bits.
    value as usize
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

/// An error contained in [`OpenFileError`].
pub enum CreateTableError {
    /// The call to [`Table::new`] failed.
    New(NewTableError),
    /// The call to [`Table::load`] failed.
    Load(LoadTableError),
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
    // SAFETY: ???
    // FIXME: the *memmap* documentation provides no clues as to what invariants must be upheld for
    // [`MmapOptions::map_mut`] to be 'safe', so I really couldn't tell you if this is safe or not.
    let mmap = unsafe { mmap_opts.map_mut(&file) }.map_err(OpenFileError::Map)?;

    if file_is_new {
        Table::new(mmap).map_err(CreateTableError::New)
    } else {
        Table::load(mmap).map_err(CreateTableError::Load)
    }
    .map_err(OpenFileError::CreateTable)
}

/// An error returned by [`Table::new`].
pub enum NewTableError {
    /// The buffer is too small to contain a valid table.
    ///
    /// This error is returned when the buffer is less than 2048 bytes in size.
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

pub enum LoadTableError {
    /// The buffer is too small to contain a valid table.
    ///
    /// This error is returned when the buffer is less than 2048 bytes in size.
    BufferTooSmall,
    /// The buffer contains an invalid table.
    InvalidHeaderStamp,
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
                let header = unsafe { mmap.get_header_unchecked() };

                mem::copy(bytemuck::from_bytes(header))
            },
            |mmap| {
                // SAFETY: [`with_mmap`] has guaranteed that the buffer contains a complete
                // top-level subnet.
                let subnet = unsafe { mmap.get_top_level_subnet_unchecked() };

                mem::copy(bytemuck::from_bytes(subnet))
            },
            LoadTableError::BufferTooSmall,
        )
    }
}

impl Table {
    /// Creates a `Table` with the given strategies for obtaining the [header](`Header`) and
    /// top-level [subnet](`Subnet`).
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
    fn with_mmap<E>(
        mmap: MmapMut,
        get_header: impl FnOnce(&MmapMut) -> Header,
        get_top_level_subnet: impl FnOnce(&MmapMut) -> Subnet,
        too_small_error: E,
    ) -> Result<Self, E> {
        match BufferSize::from_mmap(&mmap) {
            BufferSize::TooSmall => Err(too_small_error),
            BufferSize::Blocks(block_count) => {
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
        // This is the nnumber of whole nodes that will fit into a buffer of the given size.
        let blocks = size / BLOCK_SIZE;

        // We need at least two blocks to contain the header and top-level subnet. Any less is too
        // small.
        if blocks < 2 {
            Self::TooSmall
        } else {
            Self::Blocks(blocks)
        }
    }
}

/// The approximate size of a [buffer](`MmapMut`).
enum BufferSize {
    /// The buffer is too small to contain a complete [table header](`Header`) and top-level
    /// [subnet](`Subnet`).
    TooSmall,
    /// The buffer contains a complete [header](`Header`) and top-level [subnet](`Subnet`) and can
    /// accomodate this number of blocks.
    ///
    /// This value is guaranteed to be at least two, including the header and top-level subnet.
    Blocks(usize),
}

trait Indexable {
    fn translate_index(&self, index: usize) -> usize {
        index
    }
}

impl Indexable for MmapMut {}

trait BlockIndexable {
    fn block_range(&self, index: usize) -> Range<usize>;
}

impl<T: Indexable> BlockIndexable for T {
    /// The range, in bytes, that a block with the given index inhabits.
    fn block_range(&self, index: usize) -> Range<usize> {
        let start = self.translate_index(BLOCK_SIZE * index);
        let end = self.translate_index(BLOCK_SIZE * (index + 1));
        let range = start..end;
        assert_eq!(range.len(), BLOCK_SIZE);

        range
    }
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

impl<T: BlockIndexable + AsMut<[u8]> + AsRef<[u8]>> Buffer for T {
    fn get_block(&self, index: usize) -> Option<&[u8]> {
        self.as_ref().get(self.block_range(index))
    }

    fn get_block_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let range = self.block_range(index);

        self.as_mut().get_mut(range)
    }

    unsafe fn get_block_unchecked(&self, index: usize) -> &[u8] {
        self.as_ref().get_unchecked(self.block_range(index))
    }

    unsafe fn get_block_unchecked_mut(&mut self, index: usize) -> &mut [u8] {
        let range = self.block_range(index);

        self.as_mut().get_unchecked_mut(range)
    }
}

trait BufferExt {
    /// Returns an immutable reference to the block containing the table header without first
    /// asserting that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the table header.
    unsafe fn get_header_unchecked(&self) -> &[u8];

    /// Returns a mutable reference to the block containing the table header without first asserting
    /// that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the table header.
    unsafe fn get_header_unchecked_mut(&mut self) -> &mut [u8];

    /// Returns an immutable reference to the block containing the top-level subnet table without
    /// first asserting that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the top-level subnet.
    unsafe fn get_top_level_subnet_unchecked(&self) -> &[u8];

    /// Returns a mutable reference to the block containing the top-level subnet table without first
    /// asserting that it exists.
    ///
    /// # Safety
    ///
    /// The underlying buffer must be large enough to accomodate the top-level subnet.
    unsafe fn get_top_level_subnet_unchecked_mut(&mut self) -> &mut [u8];

    /// Returns an immutable reference to the node with the given handle, or [`None`] if it doesn't
    /// exist.
    fn get_node(&self, handle: NodeHandle) -> Option<&[u8]>;

    /// Returns a mutable reference to the node with the given handle, or [`None`] if it doesn't
    /// exist.
    fn get_node_mut(&mut self, handle: NodeHandle) -> Option<&mut [u8]>;
}

impl<T: Buffer> BufferExt for T {
    unsafe fn get_header_unchecked(&self) -> &[u8] {
        self.get_block_unchecked(0)
    }

    unsafe fn get_header_unchecked_mut(&mut self) -> &mut [u8] {
        self.get_block_unchecked_mut(0)
    }

    unsafe fn get_top_level_subnet_unchecked(&self) -> &[u8] {
        self.get_block_unchecked(1)
    }

    unsafe fn get_top_level_subnet_unchecked_mut(&mut self) -> &mut [u8] {
        self.get_block_unchecked_mut(1)
    }

    fn get_node(&self, handle: NodeHandle) -> Option<&[u8]> {
        self.get_block(handle.block_index()?)
    }

    fn get_node_mut(&mut self, handle: NodeHandle) -> Option<&mut [u8]> {
        self.get_block_mut(handle.block_index()?)
    }
}

/// A stupid-simple IPv4 table.
pub struct Table {
    header: Header,
    top_level_subnet: Subnet,
    block_count: usize,
    mmap: MmapMut,
}

impl Table {
    /// Writes-back changes to disk.
    ///
    /// This function is automatically called when a `Table` is [dropped](`Drop`), but you can call
    /// it more often if you like.
    pub fn flush(&mut self) -> io::Result<()> {
        let header = bytemuck::bytes_of(&self.header);
        // Write our copy of the header to the buffer.
        // SAFETY: [`with_mmap`] guaranteed that the buffer contains a complete header.
        unsafe { self.mmap.get_header_unchecked_mut() }.copy_from_slice(header);

        let top_level_subnet = bytemuck::bytes_of(&self.top_level_subnet);
        // Write our copy of the top-level subnet to the buffer.
        // SAFETY: `with_mmap` also guaranteed that the buffer contains a complete top-level subnet.
        unsafe { self.mmap.get_top_level_subnet_unchecked_mut() }
            .copy_from_slice(top_level_subnet);

        // Finally, flush everything to disk.
        // TODO: should we take a more granular approach to flushing?
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
#[derive(Debug)]
pub enum TableEntryError {
    FollowedInvalidNodeHandle,
    TooManyNodes,
    OutOfSpace,
}

pub enum HostEntry<'a> {
    Occupied(&'a mut Host),
    Vacant(VacantHostEntry<'a>),
}

impl Table {
    pub fn entry<'a>(&'a mut self, addr: Ipv4Addr) -> Result<HostEntry<'a>, TableEntryError> {
        // Foreword: The implementation of this method is fairly complicated due to constraints
        // imposed by the borrow-checker, *borrowck*. Namely, we cannot hold multiple exclusive
        // references to `self`, nor can we hold multiple exclusive references to the memory-backed
        // buffer in which all table blocks are contained. We must therefore be very careful in how
        // we borrow.

        // The first workaround is to call all necessary methods on `Self` and then destructure
        // `self` to ensure we cannot hold multiple exclusive references to it.

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

        // The second workaround is 'borrow-splitting', which is described for slices in [the
        // relevant Nomicon article]. In truth, we *can* hold multiple exclusive references to the
        // memory-backed buffer if they refer to different slices. We do this by breaking `mmap`
        // into smaller slices with `split_at_mut`. But, for [`NodeHandles`] to properly index these
        // smaller, offseted slices, we must maintain an 'offset counter' that tracks how far a
        // slice is from the beginning of `mmap`. The [`MmapView`] type contains both this offset
        // and the slice.
        //
        // [the relevant Nomicon article]: https://doc.rust-lang.org/nomicon/borrow-splitting.html

        /// A 'view' of a memory-backed buffer.
        struct MmapView<'a> {
            /// The offset of this view from the original `mmap` variable.
            offset: usize,
            /// The content of the view.
            inner: &'a mut [u8],
        }

        // Implementing these three traits gives us [`BlockIndexable`], [`Buffer`], and
        // [`BufferExt`] for free.

        impl Indexable for MmapView<'_> {
            fn translate_index(&self, index: usize) -> usize {
                index - self.offset
            }
        }
        impl AsRef<[u8]> for MmapView<'_> {
            fn as_ref(&self) -> &[u8] {
                self.inner
            }
        }
        impl AsMut<[u8]> for MmapView<'_> {
            fn as_mut(&mut self) -> &mut [u8] {
                self.inner
            }
        }

        impl<'a> MmapView<'a> {
            /// Creates a new view from the entirety of the given slice.
            fn of(inner: &'a mut [u8]) -> Self {
                Self { offset: 0, inner }
            }

            /// Splits this view into two smaller views, where the left view is before the given
            /// block index and the right view is after.
            fn split_at_block_start(self, block_index: usize) -> (Self, Self) {
                let Range { start, .. } = self.block_range(block_index);

                self.split_at(start)
            }

            /// Splits this view into two smaller views.
            fn split_at(self, mid: usize) -> (Self, Self) {
                let Self { offset, inner } = self;
                let (left, right) = inner.split_at_mut(mid);

                (
                    Self { offset, inner: left },
                    Self { offset: offset + mid, inner: right },
                )
            }
        }

        // This is our original view of `mmap`.
        let mmap_view = MmapView::of(mmap.as_mut());

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
        // This is the view from which `current_subnet` is borrowed.
        //
        // To begin, this variable is uninitialised because `current_subnet` does not yet borrow
        // from the buffer.
        let mut current_subnet_view: MmapView;

        /// Splits off a view at the given node handle, returning a mutable reference to the node if
        /// it exists, or `None` otherwise.
        ///
        /// In the `Some(_)` case, the original view is reassigned to the right side of the split,
        /// excluding the node itself, and a new view is assigned to the left side of the split that
        /// contains the node.
        ///
        /// The original view is not modified if `None` is returned.
        ///
        /// # Arguments
        ///
        /// `$handle` is the node handle. `$from` is the original view, and `$to` is the new view
        /// containing the resultant node.
        macro_rules! pop_node {
            ($to:ident [ $handle:expr ] $from:ident) => {
                match $handle.block_index() {
                    Some(block_index) => {
                        let Range { start, end } = $from.block_range(block_index);
                        #[allow(unused_assignments)]
                        {
                            ($to, $from) = $from.split_at(end);
                        }

                        $to.as_mut().get_mut(start..)

                    }
                    None => None,
                }
            };
        }

        // Can I has new nods?
        if let TableUsage::NotFull { next_free_block } = header.usage(max_block_index) {
            // Yes, and `next_free_block` points to the first unallocated block.
            let (
                mut occupied_blocks,
                mut free_blocks,
            ) = mmap_view.split_at_block_start(next_free_block);

            while let Some(subnet_index) = subnet_indices.next() {
                // Let's see if this subnet table contains an entry for this octet.
                match current_subnet.get_mut(subnet_index) {
                    // It does. This entry should represent another subnet table.
                    &mut Some(next_subnet_handle) => {
                        // Next, we will attempt to obtain a reference to this next subnet table.
                        match pop_node!(current_subnet_view [next_subnet_handle] occupied_blocks) {
                            // `occupied_blocks` is now constained to all blocks after `subnet`, and
                            // `subnet` itself is borrowed from `current_subnet_view`.
                            Some(subnet) => {
                                // Recurse to the next-level subnet table.
                                //
                                // Note: `current_subnet` now borrows from `current_subnet_view`.
                                current_subnet = bytemuck::from_bytes_mut(subnet);
                                continue;
                            }
                            // The handle pointed to a subnet that does not exist.
                            None => {
                                // This is a hard error, and we cannot continue.
                                return Err(TableEntryError::FollowedInvalidNodeHandle);
                            }
                        }
                    }
                    // It does not. We can assume that the host entry is vacant.
                    entry => {
                        // We will now constuct a [`HostEntry::vacant`], but there is one problem:
                        // `entry` borrows from `current_subnet`, and moving both would create a
                        // self-referential type. To avoid this, we will attempt to re-borrow
                        // `entry` from `self` instead.

                        let entry: *mut Option<NodeHandle> = entry as *mut _;
                        // We are careful to drop any variables that might alias `entry`.

                        // Note: dropping `occupied_blocks` will also drop `current_subnet` and
                        // `current_subnet_view`.
                        drop(occupied_blocks);
                        // Note: `header` currently borrows from `self`, so we need to copy it.
                        let header = mem::copy(header);

                        // SAFETY:
                        // - `entry` is not null.
                        // - `entry` should be properly aligned after [`bytemuck::from_bytes`].
                        // - `entry` is entirely within the bounds of a single allocated
                        //   object. It is borrwed directly from `self`.
                        // - `entry` is not aliased by any other variable.
                        let entry = unsafe { &mut *entry };

                        return Ok(HostEntry::Vacant(VacantHostEntry {
                            insert_strategy: InsertHostStrategy::InsertSubnetsAndHost {
                                header,
                                max_block_index,
                                // Collect these into an inlined [`SmallVec`].
                                subnet_indices: subnet_indices.collect(),
                                first_subnet_entry: entry,
                            },
                        }));
                    }
                }
            }

            // At this point, `current_subnet` should contain host entries and not links to other
            // tables. We will rename it to reflect this.
            let host_table = current_subnet;

            match host_table.get_mut(host_index) {
                &mut Some(host_handle) => {
                    match occupied_blocks.get_node_mut(host_handle) {
                        Some(block_index) => {
                            let MmapView { inner, .. } = occupied_blocks;

                            Ok(HostEntry::Occupied(bytemuck::from_bytes_mut(inner)))
                        }
                        None => Err(TableEntryError::FollowedInvalidNodeHandle),
                    }
                }
                entry => {
                    todo!()
                }
            }
        } else {
            tracing::warn!("table is full");

            todo!()
        }
    }

    fn max_block_index(&self) -> usize {
        // SAFETY: `block_count` was guaranteed by [`BufferSize::from_mmap`] to be at least one.
        unsafe { self.block_count.unchecked_sub(1) }
    }
}

pub struct VacantHostEntry<'a> {
    insert_strategy: InsertHostStrategy<'a>,
}

enum InsertHostStrategy<'a> {
    InsertSubnetsAndHost {
        header: Header,
        max_block_index: usize,
        subnet_indices: SmallVec<[u8; 3]>,
        first_subnet_entry: &'a mut Option<NodeHandle>,
    },
    InsertHostOnly,
}

type InsertHostResult<'a> = Result<&'a mut Host, InsertHostError>;

pub enum InsertHostError {
    TooManyNodes,
    OutOfSpace,
}

impl<'a> VacantHostEntry<'a> {
    pub fn insert(self, host: Host) -> InsertHostResult<'a> {
        match self.insert_strategy {
            InsertHostStrategy::InsertSubnetsAndHost {
                header,
                max_block_index,
                subnet_indices,
                first_subnet_entry,
            } => {
                Self::insert_subnets_and_host(
                    header,
                    max_block_index,
                    subnet_indices,
                    first_subnet_entry,
                    host,
                )
            }
            InsertHostStrategy::InsertHostOnly => {
                Self::insert_host_only()
            }
        }
    }

    fn insert_subnets_and_host(
        mut header: Header,
        max_block_index: usize,
        subnet_indices: impl IntoIterator<Item = u8>,
        first_subnet_entry: &'a mut Option<NodeHandle>,
        host: Host,
    ) -> InsertHostResult<'a> {
        let entry = first_subnet_entry;

        // On insertion, we need to generate new subnet tables for the remaining
        // octets.
        for next_subnet_index in subnet_indices {
            // Allocate a handle for the next subnet table.
            let handle = header
                .alloc_node(max_block_index)
                .ok_or(InsertHostError::TooManyNodes)?;
            // Replace the `None` entry in the current subnet table with a
            // `Some(handle)` to the next table.
            *entry = Some(handle);
            // `entry` might borrow from `current_subnet_view`, which is a
            // problem because we're about to reassign it. But, that's okay,
            // because we don't need this `entry` anymore.
            drop(entry);

            // Obtain a reference to this new subnet table.
            let current_subnet: &mut Subnet = /*pop_node!(current_subnet_view [handle] free_blocks)
                .ok_or(InsertHostError::OutOfSpace)
                .map(bytemuck::from_bytes_mut)?;*/todo!();
            // Initialize the new table.
            *current_subnet = Subnet::new();

            // Our next entry to fix is `current_subnet[next_subnet_index]`.
            entry = current_subnet.get_mut(next_subnet_index);
        }

        let handle = header
            .alloc_node(max_block_index)
            .ok_or(InsertHostError::TooManyNodes)?;
        // Replace the `None` entry with `Some(handle)`.
        *entry = Some(handle);
        drop(entry);

        let node: &mut Host = /*mmap
            .get_node_mut(handle)
            .ok_or(InsertHostError::OutOfSpace)
            .map(bytemuck::from_bytes_mut)?;*/todo!();

        // Initialize the new host record.
        *node = host;

        Ok(node)
    }

    fn insert_host_only() -> InsertHostResult<'a> {
        todo!()
    }
}

/// A handle to a node.
#[repr(transparent)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
struct Header {
    next_free_node: u32,
    reserved: [u8; 1020],
}

enum TableUsage {
    Full,
    NotFull {
        next_free_block: usize,
    }
}

impl Header {
    fn is_full(&self, max_block_index: usize) -> bool {
        matches!(self.usage(max_block_index), TableUsage::Full)
    }

    fn usage(&self, max_block_index: usize) -> TableUsage {
        match NodeHandle::from_index(self.next_free_node) {
            Some(next_free_node) => {
                match next_free_node.block_index() {
                    Some(block_index) => {
                        if block_index <= max_block_index {
                            TableUsage::NotFull { next_free_block: block_index }
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

    fn alloc_node(&mut self, max_block_index: usize) -> Option<NodeHandle> {
        if self.is_full(max_block_index) {
            None
        } else {
            // SAFETY: we can contain at least one more node.
            unsafe { self.alloc_node_unchecked() }
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
#[derive(bytemuck::Pod, bytemuck::Zeroable, Clone, Copy)]
struct Subnet([Option<NodeHandle>; 256]);

impl Subnet {
    fn get_mut(&mut self, octet: u8) -> &mut Option<NodeHandle> {
        let index = usize::from(octet);

        // SAFETY: accessing the array is bijective.
        unsafe { self.0.get_unchecked_mut(index) }
    }
}
