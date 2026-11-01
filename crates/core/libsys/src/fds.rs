// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`SharedFds`]: the fd table the threads of a program share.

use crate::lock::Lock;
use crate::pure::{FdEntry, FdTable};

/// The process's fd table behind a [`Lock`]: threads of one
/// program share it, and each operation (a `close`'s check and release, a
/// `dup`'s search for a free fd and its store) is one hold, so two threads
/// cannot be given the same fd or close one handle twice. The kernel is
/// called after the hold ends, with the handle the table says to close.
pub struct SharedFds(Lock<FdTable>);

impl SharedFds {
    pub const fn new() -> Self {
        Self(Lock::new(FdTable::new()))
    }

    /// What `fd` is.
    pub fn get(&self, fd: u64) -> FdEntry {
        self.0.lock().fd_slot(fd)
    }

    /// The table a startup block describes replaces the current one.
    pub fn replace(&self, table: FdTable) {
        *self.0.lock() = table;
    }

    /// Close `fd`: `Err(())` if it was closed, else the handle the kernel must
    /// now close, if that was its last reference.
    #[allow(clippy::result_unit_err)]
    pub fn close(&self, fd: u64) -> Result<Option<u32>, ()> {
        let mut t = self.0.lock();
        if t.fd_slot(fd) == FdEntry::Closed {
            return Err(());
        }
        Ok(t.fd_release(fd))
    }

    /// [`FdTable::fd_alias`].
    pub fn dup(&self, fd: u64) -> Option<u64> {
        self.0.lock().fd_alias(fd)
    }

    /// [`FdTable::fd_alias_to`].
    #[allow(clippy::result_unit_err)]
    pub fn dup2(&self, old: u64, new: u64) -> Result<Option<u32>, ()> {
        self.0.lock().fd_alias_to(old, new)
    }

    /// [`FdTable::fd_put_handle`].
    pub fn put(&self, fd: u64, h: u32) -> Option<u32> {
        self.0.lock().fd_put_handle(fd, h)
    }
}
