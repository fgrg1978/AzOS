// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The region layout. Everything is an aligned little-endian 64-bit word.
//!
//! ```text
//! word 0   magic "AZINSPCT"
//! word 1   FORMAT_VERSION (low 32) | class (high 32)
//! word 2   epoch (odd while the tree is being rebuilt)
//! word 3   region bytes (low 32) | node capacity (high 32)
//! word 4   node count (low 32) | value-word capacity (high 32)
//! word 5   value words used (low 32)
//! word 6   stamp: an opaque number the writer sets at each refresh
//! word 7   padding to a 64-byte line
//! then     node_cap nodes of 8 words, then word_cap value words
//!
//! node     word 0  seq (odd while its value is being written)
//!          word 1  kind (8) | name length (8) | value words (16) | value offset (32)
//!          word 2  first child (32) | next sibling (32); 0 = none
//!          word 3  parent (32) | depth (32)
//!          word 4-7 name, 32 bytes, NUL padded
//! values   u64, i64: one word. String and bytes: a length word, then the
//!          bytes. Histogram: one word per bucket.
//! ```
//! Node 0 is the root. It is never a child, so 0 doubles as "none".

/// Magic of every region.
pub const MAGIC: u64 = u64::from_le_bytes(*b"AZINSPCT");
/// The layout's version; a reader refuses any other.
pub const FORMAT_VERSION: u32 = 2;

pub(crate) const HEADER_WORDS: usize = 8;
pub(crate) const NODE_WORDS: usize = 8;
/// Value words the layout budgets per node when it divides a region between
/// the node table and the value area.
const VALUE_WORDS_PER_NODE: usize = 8;

pub(crate) const H_MAGIC: usize = 0;
pub(crate) const H_VERSION_CLASS: usize = 1;
pub(crate) const H_EPOCH: usize = 2;
pub(crate) const H_LEN_NODECAP: usize = 3;
pub(crate) const H_COUNT_WORDCAP: usize = 4;
pub(crate) const H_WORDS_USED: usize = 5;
pub(crate) const H_STAMP: usize = 6;

pub(crate) const N_SEQ: usize = 0;
pub(crate) const N_KIND: usize = 1;
pub(crate) const N_LINKS: usize = 2;
pub(crate) const N_PARENT: usize = 3;
pub(crate) const N_NAME: usize = 4;

/// Longest node name, in bytes.
pub const NAME_MAX: usize = 32;
/// Largest string (or bytes) capacity of a node, in bytes.
pub const STR_MAX: usize = 128;
/// Most buckets of a histogram.
pub const HIST_MAX: usize = 32;
/// Deepest nesting below the root.
pub const DEPTH_MAX: u32 = 8;
/// Reads of a seq or epoch a reader makes before it reports
/// [`Error::Contended`], and claims a writer makes before it does.
pub const SPIN_MAX: u32 = 4096;

/// Which region this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Class {
    /// Readable by any task that holds the MemObj.
    Public = 0,
    /// Handed out only against an admin warrant.
    Admin = 1,
}

impl Class {
    pub(crate) fn from_raw(v: u32) -> Option<Class> {
        match v {
            0 => Some(Class::Public),
            1 => Some(Class::Admin),
            _ => None,
        }
    }
}

/// What a node holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Dir = 0,
    U64 = 1,
    I64 = 2,
    Str = 3,
    Hist = 4,
    /// Bytes that are not text: a record in its wire form.
    Bytes = 5,
}

impl Kind {
    pub(crate) fn from_raw(v: u8) -> Option<Kind> {
        match v {
            0 => Some(Kind::Dir),
            1 => Some(Kind::U64),
            2 => Some(Kind::I64),
            3 => Some(Kind::Str),
            4 => Some(Kind::Hist),
            5 => Some(Kind::Bytes),
            _ => None,
        }
    }
}

/// A node of one epoch. Ids are indexes into the node table and mean
/// nothing after a rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(pub u32);

impl NodeId {
    /// The root directory.
    pub const ROOT: NodeId = NodeId(0);
}

/// Why an operation did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The memory is null, misaligned, or too small for a header.
    BadRegion,
    /// The first word is not [`MAGIC`].
    BadMagic,
    /// The region was written under another layout version.
    VersionMismatch { found: u32 },
    /// The region is of the other class than the one asked for.
    WrongClass { found: u32 },
    /// The header or a node contradicts the layout.
    Corrupt,
    /// A seq stayed odd for [`SPIN_MAX`] reads: a writer is mid-write (or was
    /// preempted there). Try again.
    Contended,
    /// The tree was rebuilt since the reader opened it: [`Reader::refresh`],
    /// look the node up again.
    ///
    /// [`Reader::refresh`]: crate::Reader::refresh
    Restructured,
    /// The node table or the value area is full.
    NoSpace,
    /// A name that is empty, longer than [`NAME_MAX`], or holds `/` or NUL.
    BadName,
    /// A sibling already has the name.
    Duplicate,
    /// Deeper than [`DEPTH_MAX`].
    TooDeep,
    /// A string or bytes capacity over [`STR_MAX`], or a histogram of 0 or over
    /// [`HIST_MAX`] buckets.
    BadSize,
    /// The id names no node of this epoch.
    BadNode,
    /// The node is not of the kind the operation is for.
    WrongKind,
}

/// How a region of `bytes` divides between the node table and the value area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub node_cap: u32,
    pub word_cap: u32,
}

impl Layout {
    /// `None` when the region cannot hold the header and two nodes.
    pub(crate) fn for_words(words: usize) -> Option<Layout> {
        let avail = words.checked_sub(HEADER_WORDS)?;
        let node_cap = avail / (NODE_WORDS + VALUE_WORDS_PER_NODE);
        if node_cap < 2 || words * 8 > u32::MAX as usize {
            return None;
        }
        let word_cap = avail - node_cap * NODE_WORDS;
        Some(Layout { node_cap: node_cap as u32, word_cap: word_cap as u32 })
    }

    pub(crate) fn node_word(&self, node: u32, field: usize) -> usize {
        HEADER_WORDS + node as usize * NODE_WORDS + field
    }

    pub(crate) fn value_word(&self, off: u32) -> usize {
        HEADER_WORDS + self.node_cap as usize * NODE_WORDS + off as usize
    }
}

pub(crate) fn lo(v: u64) -> u32 {
    v as u32
}

pub(crate) fn hi(v: u64) -> u32 {
    (v >> 32) as u32
}

pub(crate) fn pack(lo: u32, hi: u32) -> u64 {
    lo as u64 | (hi as u64) << 32
}

/// A node's value words, by kind and capacity.
pub(crate) fn value_words(kind: Kind, size: usize) -> usize {
    match kind {
        Kind::Dir => 0,
        Kind::U64 | Kind::I64 => 1,
        Kind::Str | Kind::Bytes => 1 + size.div_ceil(8),
        Kind::Hist => size,
    }
}
