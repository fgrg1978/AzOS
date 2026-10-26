// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Change groups: many operations that become durable together or not at all.
//!
//! This is what the POSIX dance (write a temporary file, fsync it, rename it
//! over the target, fsync the directory) approximates, without the
//! temporary: `begin_group`, any number of `create`, `write`, `truncate` and
//! `unlink` across any number of files, then `commit_group`. The commit is
//! the ordinary commit of [`super::volume`], so a power cut leaves the
//! volume as it was at `begin_group` or with the whole group applied, never
//! with part of it. `abort_group` throws the group away without touching the
//! device: nothing of an open transaction reaches the bitmap, the checksum
//! table or a superblock before the commit, so rolling back is giving the
//! allocator its blocks back and forgetting the cached inodes.
//!
//! One group at a time. While it is open the plain `commit` (and `check`,
//! and snapshot create and delete) refuse with `GroupOpen`: the open
//! transaction is the group, and letting a periodic flusher make half of it
//! durable would defeat the point. Reads inside the group see its own
//! writes. Independent concurrent groups would need a generation per group
//! and a merge at commit; that is not built, because the volume is driven by
//! one `&mut` owner at a time and a kernel adapter serialises its users
//! around the group anyway.

use super::dev::BlockDev;
use super::volume::Volume;
use super::Error;

/// What `abort_group` needs that is not recoverable from the engine: the
/// superblock fields the operations change in place.
#[derive(Clone, Copy, Debug)]
pub(super) struct GroupSaved {
    free_head: u64,
    inode_slots: u64,
}

impl<D: BlockDev> Volume<D> {
    pub fn in_group(&self) -> bool {
        self.group.is_some()
    }

    /// Open a group. Work already written but not committed is committed
    /// first, so that the group starts from a durable state and an abort
    /// returns to exactly it.
    pub fn begin_group(&mut self) -> Result<(), Error> {
        self.begin()?;
        if self.group.is_some() {
            return Err(Error::GroupOpen);
        }
        self.commit()?;
        self.group = Some(GroupSaved { free_head: self.sb.free_head, inode_slots: self.sb.inode_slots });
        self.core.undo = Some(alloc::vec::Vec::new());
        Ok(())
    }

    /// Make the whole group durable, atomically. A group that changed
    /// nothing commits nothing. A failure poisons the handle, as any commit.
    pub fn commit_group(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.group.take().is_none() {
            return Err(Error::NoGroup);
        }
        self.core.undo = None;
        self.commit()
    }

    /// Discard the group: the volume is as `begin_group` found it.
    pub fn abort_group(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let saved = self.group.take().ok_or(Error::NoGroup)?;
        self.inodes.clear();
        self.sb.free_head = saved.free_head;
        self.sb.inode_slots = saved.inode_slots;
        self.core.rollback_txn();
        self.core.undo = None;
        Ok(())
    }
}
