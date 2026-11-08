// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The superblock and the group descriptors.

use crate::{csum, le16, le32, BlockSource, Corrupt, Error, MountError, Volume};

const SB_OFFSET: u64 = 1024;
const SB_BYTES: usize = 1024;
const MAGIC: u16 = 0xEF53;

const COMPAT_HAS_JOURNAL: u32 = 0x4;

const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_EA_INODE: u32 = 0x400;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// What this parser reads. Every other bit (compression, a journal device,
/// meta_bg, MMP, dirdata, inline_data, encrypt, casefold, any bit it does
/// not know) refuses the mount. `ea_inode` is read: extended attributes are
/// not, so where their values live changes nothing here.
const INCOMPAT_READ: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR;

const RO_COMPAT_BIGALLOC: u32 = 0x200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x400;
/// Read-only compatible bits that change how a block is addressed. Every
/// other one only constrains a writer.
const RO_COMPAT_ADDRESSING: u32 = RO_COMPAT_BIGALLOC;

const CSUM_TYPE_CRC32C: u8 = 1;
/// `EXT4_MAX_DESC_SIZE`: the largest descriptor the superblock check admits.
const DESC_MAX: usize = 1024;

/// `bg_flags`: the group's inode table is not initialised.
const BG_INODE_UNINIT: u16 = 0x1;
/// `bg_checksum`'s offset in a descriptor.
const BG_CHECKSUM: usize = 0x1E;

/// The feature words as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    pub compat: u32,
    pub incompat: u32,
    pub ro_compat: u32,
}

impl Features {
    pub fn extents(&self) -> bool {
        self.incompat & INCOMPAT_EXTENTS != 0
    }
    pub fn is_64bit(&self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }
    pub fn filetype(&self) -> bool {
        self.incompat & INCOMPAT_FILETYPE != 0
    }
    pub fn metadata_csum(&self) -> bool {
        self.ro_compat & RO_COMPAT_METADATA_CSUM != 0
    }
    pub fn has_journal(&self) -> bool {
        self.compat & COMPAT_HAS_JOURNAL != 0
    }
}

/// What the parser keeps of the superblock.
#[derive(Clone, Copy, Debug)]
pub struct Super {
    pub block_size: u32,
    pub blocks_count: u64,
    pub free_blocks: u64,
    pub inodes_count: u32,
    pub free_inodes: u32,
    pub first_data_block: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u32,
    pub desc_size: u32,
    pub groups: u32,
    pub features: Features,
    /// The seed every metadata checksum starts from.
    pub csum_seed: u32,
    pub uuid: [u8; 16],
}

impl Super {
    pub(crate) fn read<S: BlockSource>(src: &mut S) -> Result<Super, MountError> {
        let mut b = [0u8; SB_BYTES];
        if src.len() < SB_OFFSET + SB_BYTES as u64 {
            return Err(MountError::Geometry);
        }
        src.read_at(SB_OFFSET, &mut b).map_err(|_| MountError::Io)?;
        // Fixed offsets inside a 1 KiB array: the reads below cannot miss.
        let r16 = |o| le16(&b, o).unwrap_or(0);
        let r32 = |o| le32(&b, o).unwrap_or(0);
        if r16(0x38) != MAGIC {
            return Err(MountError::BadMagic);
        }
        let features = Features { compat: r32(0x5C), incompat: r32(0x60), ro_compat: r32(0x64) };
        if features.incompat & INCOMPAT_RECOVER != 0 {
            return Err(MountError::NeedsRecovery);
        }
        let unread = features.incompat & !INCOMPAT_READ;
        if unread != 0 {
            return Err(MountError::Incompat(unread));
        }
        if features.ro_compat & RO_COMPAT_ADDRESSING != 0 {
            return Err(MountError::RoCompat(features.ro_compat & RO_COMPAT_ADDRESSING));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[0x68..0x78]);
        let csum_seed = if features.metadata_csum() {
            let ty = b[0x175];
            if ty != CSUM_TYPE_CRC32C {
                return Err(MountError::ChecksumType(ty));
            }
            if csum(!0, &b[..0x3FC]) != r32(0x3FC) {
                return Err(MountError::SuperChecksum);
            }
            if features.incompat & INCOMPAT_CSUM_SEED != 0 { r32(0x270) } else { csum(!0, &uuid) }
        } else {
            0
        };

        let log = r32(0x18);
        if log > 2 {
            return Err(MountError::BlockSize(log));
        }
        let block_size = 1024u32 << log;
        let rev = r32(0x4C);
        let inode_size = if rev == 0 { 128 } else { r16(0x58) as u32 };
        if !(128..=1024).contains(&inode_size) || !inode_size.is_power_of_two() || inode_size > block_size {
            return Err(MountError::InodeSize(inode_size));
        }
        let desc_size = if features.is_64bit() {
            let d = r16(0xFE) as u32;
            if !(64..=DESC_MAX as u32).contains(&d) || !d.is_power_of_two() || d > block_size {
                return Err(MountError::DescSize(d));
            }
            d
        } else {
            32
        };
        let hi = |o| if features.is_64bit() { (r32(o) as u64) << 32 } else { 0 };
        let blocks_count = r32(0x04) as u64 | hi(0x150);
        let free_blocks = r32(0x0C) as u64 | hi(0x158);
        let inodes_count = r32(0x00);
        let free_inodes = r32(0x10);
        let first_data_block = r32(0x14);
        let blocks_per_group = r32(0x20);
        let inodes_per_group = r32(0x28);
        let bits = block_size * 8;
        let medium_blocks = src.len() / block_size as u64;
        if blocks_count == 0
            || blocks_count > medium_blocks
            || first_data_block as u64 >= blocks_count
            || first_data_block != u32::from(block_size == 1024)
            || blocks_per_group == 0
            || blocks_per_group > bits
            || inodes_per_group == 0
            || inodes_per_group > bits
            || free_blocks > blocks_count
            || free_inodes > inodes_count
            || (rev != 0 && r32(0x54) < 11)
        {
            return Err(MountError::Geometry);
        }
        let groups = (blocks_count - first_data_block as u64).div_ceil(blocks_per_group as u64);
        let groups = u32::try_from(groups).map_err(|_| MountError::Geometry)?;
        if (groups as u64) * (inodes_per_group as u64) != inodes_count as u64 {
            return Err(MountError::Geometry);
        }
        // The descriptor table follows the superblock's block and must lie
        // inside the volume.
        let gdt_blocks = (groups as u64 * desc_size as u64).div_ceil(block_size as u64);
        if first_data_block as u64 + 1 + gdt_blocks > blocks_count {
            return Err(MountError::Geometry);
        }
        Ok(Super {
            block_size,
            blocks_count,
            free_blocks,
            inodes_count,
            free_inodes,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            desc_size,
            groups,
            features,
            csum_seed,
            uuid,
        })
    }

    /// Blocks one group's inode table takes.
    pub(crate) fn itable_blocks(&self) -> u64 {
        (self.inodes_per_group as u64 * self.inode_size as u64).div_ceil(self.block_size as u64)
    }
}

/// One group descriptor, the fields read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Group {
    pub inode_table: u64,
    pub flags: u16,
}

impl Group {
    /// Is the group's inode table uninitialised (no inode in it is in use)?
    pub(crate) fn inode_uninit(&self) -> bool {
        self.flags & BG_INODE_UNINIT != 0
    }
}

impl<S: BlockSource> Volume<S> {
    /// Read group `g`'s descriptor, checking its checksum.
    pub(crate) fn group(&mut self, g: u32) -> Result<Group, Error> {
        if g >= self.sb.groups {
            return Err(Corrupt::InodeRange.into());
        }
        let ds = self.sb.desc_size as usize;
        let bs = self.sb.block_size as u64;
        let at = g as u64 * ds as u64;
        let pblk = self.sb.first_data_block as u64 + 1 + at / bs;
        let mut d = [0u8; DESC_MAX];
        let d = &mut d[..ds];
        self.read_blocks(pblk, (at % bs) as usize, d)?;
        if self.sb.features.metadata_csum() {
            let stored = le16(d, BG_CHECKSUM)?;
            let mut c = csum(self.sb.csum_seed, &g.to_le_bytes());
            c = csum(c, &d[..BG_CHECKSUM]);
            c = csum(c, &[0, 0]);
            c = csum(c, &d[BG_CHECKSUM + 2..]);
            if c as u16 != stored {
                return Err(Corrupt::Checksum.into());
            }
        }
        let mut inode_table = le32(d, 0x08)? as u64;
        if self.sb.features.is_64bit() {
            inode_table |= (le32(d, 0x28)? as u64) << 32;
        }
        let g = Group { inode_table, flags: le16(d, 0x12)? };
        if g.flags & BG_INODE_UNINIT == 0
            && g.inode_table.checked_add(self.sb.itable_blocks()).is_none_or(|e| e > self.sb.blocks_count)
        {
            return Err(Corrupt::BlockRange.into());
        }
        Ok(g)
    }

    /// Read every descriptor once: a volume whose table is damaged anywhere is
    /// refused at mount, not at the first file that lives in the bad group.
    pub(crate) fn check_groups(&mut self) -> Result<(), MountError> {
        for g in 0..self.sb.groups {
            match self.group(g) {
                Ok(_) => {}
                Err(Error::Io) => return Err(MountError::Io),
                Err(_) => return Err(MountError::Group(g)),
            }
        }
        Ok(())
    }
}
