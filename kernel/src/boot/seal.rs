// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The end of hook installation: `.data.ro_after_init` goes read-only.
//!
//! Every function-pointer hook (`azos_common::ro_hook!`) and the x86_64 IDT
//! live in that linker section. The boot installs them while it is plain RW
//! data (the W^X pass maps it with the rest of `.data`); this step, run once
//! every installer has run and before any other CPU or user task does,
//! seals the hooks (a later `Hook::set` panics with the hook's name) and
//! remaps the section read-only in the kernel's table, and in the direct-map
//! alias of the image where there is one (x86_64). A kernel write that used
//! to turn a hook into an arbitrary call now faults.

use azos_drv_sys::kprintln;

/// PT_PROTECTION: tag the page-table pool with the supervisor key and deny
/// writes to it on this CPU; say which. Right after the seal, one CPU up.
#[cfg(feature = "pt-protection")]
pub(crate) fn lock_pt_pool() {
    use azos_mm::ptprot::Engaged;
    match azos_mm::vmm::engage_pt_protection() {
        // MARKER, asserted by the gate's `pt-protection` rows.
        Engaged::Locked { pages } => kprintln!("[MM] page tables: kernel-root tables write-protected ({} pool pages in use; user roots and DMA not covered)", pages),
        Engaged::SoftLocked { pages, remote } => kprintln!(
            "[MM] page tables: kernel-root tables read-only behind a software window ({} pool pages in use; {}; bug hardening, user roots and DMA not covered)",
            pages, if remote { "every CPU flushed at close" } else { "holds on the writing CPU only on SMP" }),
        Engaged::NoKey => kprintln!("[MM] page tables: kernel-root tables in use, not protected (no supervisor key on this CPU, software window off)"),
        Engaged::LockFailed => azos_drv_sys::kerr!("[MM] page tables: kernel-root tables NOT protected: the CPU has the supervisor key but denying writes to it did not take"),
        Engaged::Untaggable => azos_drv_sys::kerr!("[MM] page tables: kernel-root tables NOT protected: a pool page is not a 4 KiB leaf of the direct map"),
    }
}

/// Seal the hooks and make `.data.ro_after_init` read-only; read the page
/// table back and say so.
pub(crate) fn seal_ro_after_init() {
    // The flag first: it lives in the section, which is still writable here.
    azos_common::hook::seal();
    let pages = azos_mm::vmm::seal_ro_after_init();
    let rep = azos_mm::vmm::verify_ro_after_init();
    if pages != 0 && rep.is_clean() {
        // MARKER, asserted by the gate's `ro_after_init sealed` rows (S6).
        kprintln!("[MM] ro_after_init sealed: {} pages read-only (hooks, IDT)", pages);
    } else {
        azos_drv_sys::kerr!(
            "[MM] ro_after_init FAILED: {} pages remapped, {} checked, {} writable, \
             {} wrong-flags, {} unmapped, {} unsplit-mega, first bad {:#x}",
            pages, rep.checked, rep.write_exec, rep.wrong_flags, rep.unmapped,
            rep.unsplit_megapage, rep.first_bad,
        );
    }
}
