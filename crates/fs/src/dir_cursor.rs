// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where the last listing of a directory stopped, so the `index`-th entry of
//! the next call is reached from there and not by replaying every cookie from
//! the start (a cookie is opaque: only the backend that made it can say where
//! the next entry is).

/// The cookie that follows entry `next - 1` of one directory.
pub struct DirCursor {
    key: u64,
    next: u32,
    cookie: u64,
}

impl DirCursor {
    pub const fn new() -> Self {
        DirCursor { key: 0, next: 0, cookie: 0 }
    }

    /// The directory a caller rooted at `root` names by `path`.
    pub fn key(root: &[u8], path: &[u8]) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &b in root.iter().chain(&[0u8]).chain(path) {
            h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
        h
    }

    /// The entry number and cookie to walk from to reach entry `index` of the
    /// directory `key`: the remembered stop when it is at or before `index`,
    /// else the start.
    pub fn resume(&self, key: u64, index: u32) -> (u32, u64) {
        if cfg!(feature = "dir-cursor-canary") {
            return (0, 0);
        }
        if self.next != 0 && self.key == key && self.next <= index {
            (self.next, self.cookie)
        } else {
            (0, 0)
        }
    }

    /// Entry `next - 1` of `key` was read; `cookie` follows it.
    pub fn note(&mut self, key: u64, next: u32, cookie: u64) {
        *self = DirCursor { key, next, cookie };
    }

    /// Forget the stop (the directory ended or a read failed).
    pub fn clear(&mut self) {
        *self = DirCursor::new();
    }
}

impl Default for DirCursor {
    fn default() -> Self {
        Self::new()
    }
}
