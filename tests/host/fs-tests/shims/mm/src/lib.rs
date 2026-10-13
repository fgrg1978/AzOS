// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, reduced to the page counters
//! `crates/fs/fs/src/procfs.rs`'s `/proc/meminfo` generator reads. procfs is
//! pulled into this suite for its `FileSystem` key rules; the numbers are
//! never asserted, so fixed values are enough.

pub mod pmm {
    pub fn total_pages() -> usize { 1024 }
    pub fn free_pages() -> usize { 512 }
    pub fn used_pages() -> usize { 512 }
}
