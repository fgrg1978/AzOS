// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! On-disk structures of an azvol volume: constants, geometry, superblock,
//! inode record, extent and index entries, node header. Everything is
//! little-endian and fixed-offset; `decode` functions validate and return
//! [`Error::Corrupt`] instead of trusting a field.
//!
//! The byte-level description lives in the module doc of [`super`]; the
//! offsets here and in `tools/image/mkazvol.py` are the two implementations that
//! must agree (`tests/host/fs-tests/src/azvol_format.rs` cross-checks them).

use super::crc32c::crc32c_update;
use super::Error;

pub const BLOCK_SIZE: usize = 4096;
pub const BLOCK_LOG2: u32 = 12;
pub const BS: u64 = BLOCK_SIZE as u64;

pub const MAGIC: [u8; 8] = *b"AZVOLUME";
pub const VERSION: u32 = 1;

/// Superblock copy A and B. Far enough apart that one damaged flash page or
/// erase block does not take both.
pub const SB_SLOTS: [u64; 2] = [0, 64];
/// Blocks `[0, RESERVED_BLOCKS)` hold the two superblocks and nothing the
/// allocator may touch (room for boot code or a key header later).
pub const RESERVED_BLOCKS: u64 = 128;

/// A bitmap block carries `BLOCK_SIZE - 4` bytes of bits and a crc32c trailer.
pub const BITMAP_PAYLOAD: usize = BLOCK_SIZE - 4;
pub const BITMAP_BITS_PER_BLOCK: u64 = (BITMAP_PAYLOAD as u64) * 8;
/// One u32 crc32c per volume block, 1024 per csum-table block.
pub const CSUMS_PER_BLOCK: u64 = BS / 4;
/// A sealed volume's table entry per volume block: the 16-byte Poly1305 tag
/// and the 8-byte write sequence number the nonce is built from
/// ([`super::seal`]), 170 per table block (the last 16 bytes of a table
/// block are zero).
pub const SEAL_ENTRY_SIZE: usize = 24;
pub const SEALS_PER_BLOCK: u64 = BS / SEAL_ENTRY_SIZE as u64;

pub const INODE_SIZE: usize = 256;
pub const INODES_PER_BLOCK: u64 = (BLOCK_SIZE / INODE_SIZE) as u64;
/// Extent or index entries held inline in an inode record.
pub const INLINE_CAP: usize = 6;
pub const ENTRY_SIZE: usize = 32;
pub const NODE_HDR: usize = 32;
/// Entries per tree node block.
pub const NODE_CAP: usize = (BLOCK_SIZE - NODE_HDR) / ENTRY_SIZE;
/// Deepest root level a record may declare (`INLINE_CAP * NODE_CAP^3` extents).
pub const MAX_LEVEL: u8 = 3;
pub const NODE_MAGIC: u32 = 0x4E58_5A41; // "AZXN"

/// Extent flags this implementation understands. Anything else is refused
/// on read. There is no "sealed" flag (a volume is sealed or not, see
/// [`super::seal`]) and no "shared" bit: whether a snapshot still names a
/// block follows from the extent's generation and the retained generations
/// (see [`super::snap`]).
pub const EXT_KNOWN_FLAGS: u32 = 0;

/// Superblock incompat bit: the snapshot table and the dead list are in use.
/// Set exactly when either record is non-empty, so a volume without
/// snapshots stays readable by an implementation that has none. (A sealed
/// volume needs no bit: `key_alg != 0` is itself refused by an
/// implementation without that algorithm.)
pub const INCOMPAT_SNAPSHOTS: u32 = 1;
/// `ino` of the snapshot-table file and of the dead-list file in their
/// superblock records (and as the owner of their tree nodes). Both are
/// outside the inode number space.
pub const SNAP_OWNER: u64 = u64::MAX;
pub const DEAD_OWNER: u64 = u64::MAX - 1;

pub const MAX_NAME: usize = 255;
pub const ROOT_INO: u64 = 1;
/// Largest file offset: keeps `off + len` and block arithmetic in range.
pub const MAX_FILE_BYTES: u64 = 1 << 62;

#[inline]
pub fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
pub fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
pub fn rd64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
#[inline]
pub fn wr16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn div_ceil(a: u64, b: u64) -> u64 {
    a / b + (a % b != 0) as u64
}

/// Where the static regions of a volume of `block_count` blocks lie. Derived
/// from the block count and whether the volume is sealed; the superblock
/// stores the values too and the mount refuses a superblock whose copies
/// disagree with the derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub block_count: u64,
    pub bitmap_start: u64,
    pub bitmap_blocks: u64,
    pub csum_start: u64,
    /// Blocks of the per-block table: crc32c values (4 bytes a block), or on
    /// a sealed volume the tag and sequence entries (24 bytes a block).
    pub csum_blocks: u64,
    pub data_start: u64,
    /// The table holds AEAD entries ([`SEAL_ENTRY_SIZE`]) instead of crc32c.
    pub sealed: bool,
}

impl Geometry {
    /// Smallest volume: static regions plus room for the root, the inode
    /// table and a few files.
    pub const MIN_DATA_BLOCKS: u64 = 16;

    /// The layout of a plain (unsealed) volume.
    pub fn new(block_count: u64) -> Option<Geometry> {
        Geometry::for_volume(block_count, false)
    }

    /// A sealed volume's block number is a 32-bit nonce field, so it holds
    /// fewer than 2^32 blocks (16 TiB).
    pub fn for_volume(block_count: u64, sealed: bool) -> Option<Geometry> {
        if block_count > (1 << 40) || (sealed && block_count > u32::MAX as u64) {
            return None;
        }
        let bitmap_blocks = div_ceil(block_count, BITMAP_BITS_PER_BLOCK);
        let per_block = if sealed { SEALS_PER_BLOCK } else { CSUMS_PER_BLOCK };
        let csum_blocks = div_ceil(block_count, per_block);
        let bitmap_start = RESERVED_BLOCKS;
        let csum_start = bitmap_start.checked_add(bitmap_blocks)?;
        let data_start = csum_start.checked_add(csum_blocks)?;
        if block_count < data_start.checked_add(Self::MIN_DATA_BLOCKS)? {
            return None;
        }
        Some(Geometry { block_count, bitmap_start, bitmap_blocks, csum_start, csum_blocks, data_start, sealed })
    }

    /// Table block (index from `csum_start`) and byte offset of volume block
    /// `blk`'s entry.
    pub fn table_loc(&self, blk: u64) -> (u64, usize) {
        if self.sealed {
            (blk / SEALS_PER_BLOCK, (blk % SEALS_PER_BLOCK) as usize * SEAL_ENTRY_SIZE)
        } else {
            (blk / CSUMS_PER_BLOCK, (blk % CSUMS_PER_BLOCK) as usize * 4)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Free = 0,
    File = 1,
    Dir = 2,
    /// The inode table itself (only ever in the superblock).
    Table = 3,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        match v {
            0 => Some(Kind::Free),
            1 => Some(Kind::File),
            2 => Some(Kind::Dir),
            3 => Some(Kind::Table),
            _ => None,
        }
    }
}

/// One mapping of `nblocks` file blocks starting at `file_blk` to the same
/// number of volume blocks starting at `disk_blk`. 32 bytes on disk.
///
/// `gen` is the commit generation that wrote the data. It is what tells a
/// block written in the open transaction (safe to overwrite in place: no
/// committed tree names it) from a committed one (copy on write). On a
/// sealed volume the generation is also the high part of the block's write
/// sequence number, the nonce component ([`super::seal::seq`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub file_blk: u64,
    pub disk_blk: u64,
    pub nblocks: u32,
    pub flags: u32,
    pub gen: u64,
}

impl Extent {
    pub fn file_end(&self) -> u64 {
        self.file_blk + self.nblocks as u64
    }

    pub fn encode(&self) -> [u8; ENTRY_SIZE] {
        let mut b = [0u8; ENTRY_SIZE];
        wr64(&mut b, 0, self.file_blk);
        wr64(&mut b, 8, self.disk_blk);
        wr32(&mut b, 16, self.nblocks);
        wr32(&mut b, 20, self.flags);
        wr64(&mut b, 24, self.gen);
        b
    }

    pub fn decode(b: &[u8]) -> Extent {
        Extent {
            file_blk: rd64(b, 0),
            disk_blk: rd64(b, 8),
            nblocks: rd32(b, 16),
            flags: rd32(b, 20),
            gen: rd64(b, 24),
        }
    }
}

/// Entry of an index node: `child` is a node block of the level below, whose
/// first extent starts at file block `key`. `child_gen` must equal the
/// child's own header generation (a stale or misdirected node is refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEnt {
    pub key: u64,
    pub child: u64,
    pub child_gen: u64,
}

impl IndexEnt {
    pub fn encode(&self) -> [u8; ENTRY_SIZE] {
        let mut b = [0u8; ENTRY_SIZE];
        wr64(&mut b, 0, self.key);
        wr64(&mut b, 8, self.child);
        wr64(&mut b, 16, self.child_gen);
        b
    }

    pub fn decode(b: &[u8]) -> IndexEnt {
        IndexEnt { key: rd64(b, 0), child: rd64(b, 8), child_gen: rd64(b, 16) }
    }
}

/// Header of a tree node block (32 bytes, then `count` 32-byte entries).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeHdr {
    pub level: u16,
    pub count: u16,
    pub self_blk: u64,
    pub gen: u64,
    pub owner: u64,
}

impl NodeHdr {
    pub fn encode(&self, out: &mut [u8]) {
        wr32(out, 0, NODE_MAGIC);
        wr16(out, 4, self.level);
        wr16(out, 6, self.count);
        wr64(out, 8, self.self_blk);
        wr64(out, 16, self.gen);
        wr64(out, 24, self.owner);
    }

    pub fn decode(b: &[u8]) -> Result<NodeHdr, Error> {
        if rd32(b, 0) != NODE_MAGIC {
            return Err(Error::Corrupt("tree node magic"));
        }
        Ok(NodeHdr {
            level: rd16(b, 4),
            count: rd16(b, 6),
            self_blk: rd64(b, 8),
            gen: rd64(b, 16),
            owner: rd64(b, 24),
        })
    }
}

/// An inode record as stored (256 bytes), the extent root left as raw bytes.
///
/// ```text
///   0 ino u64   8 size u64   16 gen u64   24 ctime_ns u64   32 mtime_ns u64
///  40 link u64 (dir: parent; free slot: next free inode)
///  48 igen u32  52 kind u8  53 level u8  54 count u16  56 mode u16
///  58 flags u16 (0)  60 reserved u32   64 root: 6 x 32-byte entries
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeDisk {
    pub ino: u64,
    pub size: u64,
    pub gen: u64,
    pub ctime_ns: u64,
    pub mtime_ns: u64,
    pub link: u64,
    pub igen: u32,
    pub kind: Kind,
    pub level: u8,
    pub count: u16,
    pub mode: u16,
    pub root: [u8; INLINE_CAP * ENTRY_SIZE],
}

impl InodeDisk {
    /// The record of an auxiliary file (`ino` = [`SNAP_OWNER`] or
    /// [`DEAD_OWNER`]) with no content.
    pub fn empty_aux(ino: u64) -> InodeDisk {
        InodeDisk {
            ino,
            size: 0,
            gen: 0,
            ctime_ns: 0,
            mtime_ns: 0,
            link: 0,
            igen: 0,
            kind: Kind::Table,
            level: 0,
            count: 0,
            mode: 0,
            root: [0; INLINE_CAP * ENTRY_SIZE],
        }
    }

    /// An auxiliary file with no content is stored as zeros.
    pub fn is_empty_aux(&self) -> bool {
        self.size == 0 && self.count == 0
    }

    pub fn encode(&self, out: &mut [u8]) {
        for x in out[..INODE_SIZE].iter_mut() {
            *x = 0;
        }
        wr64(out, 0, self.ino);
        wr64(out, 8, self.size);
        wr64(out, 16, self.gen);
        wr64(out, 24, self.ctime_ns);
        wr64(out, 32, self.mtime_ns);
        wr64(out, 40, self.link);
        wr32(out, 48, self.igen);
        out[52] = self.kind as u8;
        out[53] = self.level;
        wr16(out, 54, self.count);
        wr16(out, 56, self.mode);
        out[64..64 + self.root.len()].copy_from_slice(&self.root);
    }

    pub fn decode(b: &[u8]) -> Result<InodeDisk, Error> {
        let kind = Kind::from_u8(b[52]).ok_or(Error::Corrupt("inode kind"))?;
        let level = b[53];
        let count = rd16(b, 54);
        if level > MAX_LEVEL || count as usize > INLINE_CAP {
            return Err(Error::Corrupt("inode root"));
        }
        if rd16(b, 58) != 0 {
            return Err(Error::Unsupported("inode flags"));
        }
        let mut root = [0u8; INLINE_CAP * ENTRY_SIZE];
        root.copy_from_slice(&b[64..64 + INLINE_CAP * ENTRY_SIZE]);
        Ok(InodeDisk {
            ino: rd64(b, 0),
            size: rd64(b, 8),
            gen: rd64(b, 16),
            ctime_ns: rd64(b, 24),
            mtime_ns: rd64(b, 32),
            link: rd64(b, 40),
            igen: rd32(b, 48),
            kind,
            level,
            count,
            mode: rd16(b, 56),
            root,
        })
    }
}

/// Offsets inside the superblock block, for readers outside this module.
pub mod sbo {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 8;
    pub const BLOCK_LOG2: usize = 12;
    pub const CRC: usize = 16;
    pub const INCOMPAT: usize = 20;
    pub const GENERATION: usize = 24;
    pub const BLOCK_COUNT: usize = 32;
    pub const UUID: usize = 40;
    pub const LABEL: usize = 56;
    pub const FREE_HEAD: usize = 88;
    pub const INODE_SLOTS: usize = 96;
    pub const USED_BLOCKS: usize = 104;
    pub const BITMAP_START: usize = 112;
    pub const BITMAP_BLOCKS: usize = 120;
    pub const CSUM_START: usize = 128;
    pub const CSUM_BLOCKS: usize = 136;
    pub const DATA_START: usize = 144;
    pub const ROOT_INO: usize = 152;
    pub const CREATED_NS: usize = 160;
    pub const KEY_ALG: usize = 192;
    pub const KEY_ID: usize = 200;
    pub const WRAPPED_KEY: usize = 216;
    pub const ITABLE: usize = 256;
    /// The snapshot-table file's record, all zero while there is none.
    pub const SNAPTAB: usize = 512;
    /// The dead-list file's record, all zero while there is none.
    pub const DEADLIST: usize = 768;
}

pub const LABEL_LEN: usize = 32;

/// The superblock (one 4096-byte block, two copies, newest valid wins).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub generation: u64,
    pub geo: Geometry,
    pub uuid: [u8; 16],
    pub label: [u8; LABEL_LEN],
    /// Head of the free inode-slot list (0 = none).
    pub free_head: u64,
    /// Slots in the inode table, slot 0 (reserved) included.
    pub inode_slots: u64,
    /// Set bits in the free-space map once the commit is complete.
    pub used_blocks: u64,
    pub created_ns: u64,
    /// Key slot: `key_alg == 0` means "not sealed", all three fields zero;
    /// [`super::seal::ALG_CHACHA20_POLY1305`] means every data-area block is
    /// sealed, `key_id` identifies the volume key (derived from it, see
    /// [`super::seal`]) and `wrapped_key` is reserved for per-user wrapped
    /// copies (must be zero for now).
    pub key_alg: u32,
    pub key_id: [u8; 16],
    pub wrapped_key: [u8; 40],
    /// The inode table is a file; its record lives here.
    pub itable: InodeDisk,
    /// The snapshot table and the dead list are files too ([`super::snap`]);
    /// an empty one ([`InodeDisk::empty_aux`]) is stored as zeros.
    pub snaptab: InodeDisk,
    pub deadlist: InodeDisk,
}

impl Superblock {
    pub fn encode(&self, out: &mut [u8]) {
        for x in out[..BLOCK_SIZE].iter_mut() {
            *x = 0;
        }
        out[..8].copy_from_slice(&MAGIC);
        wr32(out, sbo::VERSION, VERSION);
        wr32(out, sbo::BLOCK_LOG2, BLOCK_LOG2);
        let aux = !self.snaptab.is_empty_aux() || !self.deadlist.is_empty_aux();
        wr32(out, sbo::INCOMPAT, if aux { INCOMPAT_SNAPSHOTS } else { 0 });
        wr64(out, sbo::GENERATION, self.generation);
        wr64(out, sbo::BLOCK_COUNT, self.geo.block_count);
        out[sbo::UUID..sbo::UUID + 16].copy_from_slice(&self.uuid);
        out[sbo::LABEL..sbo::LABEL + LABEL_LEN].copy_from_slice(&self.label);
        wr64(out, sbo::FREE_HEAD, self.free_head);
        wr64(out, sbo::INODE_SLOTS, self.inode_slots);
        wr64(out, sbo::USED_BLOCKS, self.used_blocks);
        wr64(out, sbo::BITMAP_START, self.geo.bitmap_start);
        wr64(out, sbo::BITMAP_BLOCKS, self.geo.bitmap_blocks);
        wr64(out, sbo::CSUM_START, self.geo.csum_start);
        wr64(out, sbo::CSUM_BLOCKS, self.geo.csum_blocks);
        wr64(out, sbo::DATA_START, self.geo.data_start);
        wr64(out, sbo::ROOT_INO, ROOT_INO);
        wr64(out, sbo::CREATED_NS, self.created_ns);
        wr32(out, sbo::KEY_ALG, self.key_alg);
        out[sbo::KEY_ID..sbo::KEY_ID + 16].copy_from_slice(&self.key_id);
        out[sbo::WRAPPED_KEY..sbo::WRAPPED_KEY + 40].copy_from_slice(&self.wrapped_key);
        self.itable.encode(&mut out[sbo::ITABLE..sbo::ITABLE + INODE_SIZE]);
        if !self.snaptab.is_empty_aux() {
            self.snaptab.encode(&mut out[sbo::SNAPTAB..sbo::SNAPTAB + INODE_SIZE]);
        }
        if !self.deadlist.is_empty_aux() {
            self.deadlist.encode(&mut out[sbo::DEADLIST..sbo::DEADLIST + INODE_SIZE]);
        }
        let crc = sb_crc(out);
        wr32(out, sbo::CRC, crc);
    }

    /// Validate and parse one copy. Errors distinguish "not an azvol block"
    /// (`BadMagic`) from "an azvol block that does not check out".
    pub fn decode(b: &[u8]) -> Result<Superblock, Error> {
        if b[..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        if rd32(b, sbo::CRC) != sb_crc(b) {
            return Err(Error::Checksum(0));
        }
        if rd32(b, sbo::VERSION) != VERSION {
            return Err(Error::Unsupported("azvol version"));
        }
        if rd32(b, sbo::BLOCK_LOG2) != BLOCK_LOG2 {
            return Err(Error::Unsupported("block size"));
        }
        let incompat = rd32(b, sbo::INCOMPAT);
        if incompat & !INCOMPAT_SNAPSHOTS != 0 {
            return Err(Error::Unsupported("incompat feature"));
        }
        let key_alg = rd32(b, sbo::KEY_ALG);
        if key_alg != 0 && key_alg != super::seal::ALG_CHACHA20_POLY1305 {
            return Err(Error::Unsupported("key algorithm"));
        }
        if b[sbo::WRAPPED_KEY..sbo::WRAPPED_KEY + 40].iter().any(|&x| x != 0) {
            return Err(Error::Unsupported("wrapped key"));
        }
        let generation = rd64(b, sbo::GENERATION);
        if generation == 0 {
            return Err(Error::Corrupt("generation 0"));
        }
        let geo = Geometry::for_volume(rd64(b, sbo::BLOCK_COUNT), key_alg != 0).ok_or(Error::Corrupt("geometry"))?;
        if rd64(b, sbo::BITMAP_START) != geo.bitmap_start
            || rd64(b, sbo::BITMAP_BLOCKS) != geo.bitmap_blocks
            || rd64(b, sbo::CSUM_START) != geo.csum_start
            || rd64(b, sbo::CSUM_BLOCKS) != geo.csum_blocks
            || rd64(b, sbo::DATA_START) != geo.data_start
        {
            return Err(Error::Corrupt("geometry fields"));
        }
        if rd64(b, sbo::ROOT_INO) != ROOT_INO {
            return Err(Error::Corrupt("root inode"));
        }
        let inode_slots = rd64(b, sbo::INODE_SLOTS);
        let free_head = rd64(b, sbo::FREE_HEAD);
        let used_blocks = rd64(b, sbo::USED_BLOCKS);
        if inode_slots == 0 || inode_slots > (1 << 40) || free_head >= inode_slots {
            return Err(Error::Corrupt("inode slots"));
        }
        if used_blocks < geo.data_start || used_blocks > geo.block_count {
            return Err(Error::Corrupt("used blocks"));
        }
        let itable = InodeDisk::decode(&b[sbo::ITABLE..sbo::ITABLE + INODE_SIZE])?;
        if itable.kind != Kind::Table || itable.ino != 0 {
            return Err(Error::Corrupt("inode table record"));
        }
        if itable.size != inode_slots * INODE_SIZE as u64 {
            return Err(Error::Corrupt("inode table size"));
        }
        let snaptab = aux_record(b, sbo::SNAPTAB, SNAP_OWNER)?;
        let deadlist = aux_record(b, sbo::DEADLIST, DEAD_OWNER)?;
        // the feature bit says exactly whether the records exist
        if (incompat != 0) != (!snaptab.is_empty_aux() || !deadlist.is_empty_aux()) {
            return Err(Error::Corrupt("snapshot feature bit"));
        }
        if snaptab.is_empty_aux() && !deadlist.is_empty_aux() {
            return Err(Error::Corrupt("dead list without a snapshot table"));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[sbo::UUID..sbo::UUID + 16]);
        let mut label = [0u8; LABEL_LEN];
        label.copy_from_slice(&b[sbo::LABEL..sbo::LABEL + LABEL_LEN]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&b[sbo::KEY_ID..sbo::KEY_ID + 16]);
        let mut wrapped_key = [0u8; 40];
        wrapped_key.copy_from_slice(&b[sbo::WRAPPED_KEY..sbo::WRAPPED_KEY + 40]);
        Ok(Superblock {
            generation,
            geo,
            uuid,
            label,
            free_head,
            inode_slots,
            used_blocks,
            created_ns: rd64(b, sbo::CREATED_NS),
            key_alg,
            key_id,
            wrapped_key,
            itable,
            snaptab,
            deadlist,
        })
    }
}

/// Parse an auxiliary file's record at `at`: zeros mean "none".
fn aux_record(b: &[u8], at: usize, owner: u64) -> Result<InodeDisk, Error> {
    let raw = &b[at..at + INODE_SIZE];
    if raw.iter().all(|&x| x == 0) {
        return Ok(InodeDisk::empty_aux(owner));
    }
    let d = InodeDisk::decode(raw)?;
    if d.kind != Kind::Table || d.ino != owner || d.is_empty_aux() {
        return Err(Error::Corrupt("auxiliary file record"));
    }
    Ok(d)
}

/// crc32c of the superblock block with its own crc field read as zero.
fn sb_crc(b: &[u8]) -> u32 {
    let c = crc32c_update(0, &b[..sbo::CRC]);
    let c = crc32c_update(c, &[0, 0, 0, 0]);
    crc32c_update(c, &b[sbo::CRC + 4..BLOCK_SIZE])
}
