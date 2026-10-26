// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, reduced to what the file layer pulled here
//! reaches of it: the page cache's backing callback.

/// The page cache's backing callback: the REAL
/// `crates/core/mm/src/page_backing.rs` (core-only), under the path the real
/// crate exports it by (`azos_mm::pager`), for `crates/fs/src/pagecache.rs`.
#[path = "../../../../../../crates/core/mm/src/page_backing.rs"]
mod page_backing;

pub mod pager {
    pub use crate::page_backing::*;
}
