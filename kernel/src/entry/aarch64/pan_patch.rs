// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kconfig `A64_PAN=probe`: the boot-once rewrite of every `UserAccess`
//! window site (`azos_arch::sysregs::UserAccess`, `azos_trace::jump::
//! KIND_A64_PAN_*`). A site is linked as a `b` to a slow path that tests the
//! boot probe's answer; here, on the boot CPU before any secondary starts,
//! each becomes the `msr PAN, #0/#1` itself (the CPU has FEAT_PAN) or a
//! `nop` (an Armv8.0 core), through the one text-write path
//! (`azos_mm::text_poke`, W^X kept). After this a window costs exactly what
//! it costs under `require` or `n`. Never again after boot: MSR is not one
//! of the instructions the ARM ARM lets change under a running PE.
//!
//! Under `require`/`n` no site is linked and this does nothing. A kernel that
//! cannot patch (no alias slot, a refused write) keeps the branches and
//! stays correct; the census line says so.

use azos_trace::jump::{self, KeySite};

// The site emitter (arch-aarch64, which sees only azos_arch_api) mirrors the
// table's numbers; they must agree.
const _: () = assert!(azos_arch::sysregs::PAN_SITE_KEY == jump::KEY_A64_PAN);
const _: () = assert!(azos_arch::sysregs::PAN_SITE_KIND_CLR == jump::KIND_A64_PAN_CLR);
const _: () = assert!(azos_arch::sysregs::PAN_SITE_KIND_SET == jump::KIND_A64_PAN_SET);

/// The PAN sites the kernel links (none under `require`/`n`).
pub(crate) fn sites() -> impl Iterator<Item = &'static KeySite> {
    azos_trace::key_sites().iter().filter(|s| s.key == jump::KEY_A64_PAN)
}

fn word_at(s: &KeySite) -> u32 {
    // SAFETY: a site address from the linked table, inside the kernel text,
    // which is readable.
    unsafe { core::ptr::read_volatile(s.site as usize as *const u32) }
}

/// Rewrite every PAN site from the boot probe's answer; print the census.
pub(crate) fn patch(text_start: usize, text_end: usize) {
    use azos_arch_api::isa::{aarch64::PAN, ExtPolicy};
    if !matches!(PAN, ExtPolicy::Probe) {
        return;
    }
    let present = azos_arch::sysregs::pan_in_use();
    let state = if present { "pan=probed-present" } else { "pan=probed-absent" };
    // Gate canary: no rewrite; every site stays the slow-path branch.
    let skip = canary!("pan-patch-skip");
    if !skip && azos_mm::text_poke::alias().is_none() && azos_mm::text_poke::init(text_start, text_end).is_none() {
        azos_drv_sys::kwarn!("[PAN] boot patch ({}): no text alias, every site stays a branch", state);
    }
    let (mut total, mut done, mut refused) = (0usize, 0usize, 0usize);
    const BATCH: usize = 16;
    let mut batch: [(usize, u32); BATCH] = [(0, 0); BATCH];
    let mut n = 0usize;
    let flush = |b: &[(usize, u32)], done: &mut usize, refused: &mut usize| {
        if b.is_empty() {
            return;
        }
        match azos_mm::text_poke::write_words(b) {
            Ok(k) => *done += k,
            Err(e) => {
                *refused += b.len();
                azos_drv_sys::kerr!("[PAN] boot patch: text write refused ({:?})", e);
            }
        }
    };
    for s in sites() {
        total += 1;
        if skip || azos_mm::text_poke::alias().is_none() {
            continue;
        }
        match (s.pan_linked(), s.pan_word(present)) {
            (Ok(linked), Ok(want)) if word_at(s) == linked => {
                batch[n] = (s.site as usize, want);
                n += 1;
                if n == BATCH {
                    flush(&batch[..n], &mut done, &mut refused);
                    n = 0;
                }
            }
            _ => refused += 1,
        }
    }
    flush(&batch[..n], &mut done, &mut refused);
    let (mut patched, mut branch) = (0usize, 0usize);
    for s in sites() {
        let w = word_at(s);
        if s.pan_word(present) == Ok(w) {
            patched += 1;
        } else if s.pan_linked() == Ok(w) {
            branch += 1;
        }
    }
    let form = if present { "msr" } else { "nop" };
    if total > 0 && patched == total {
        azos_drv_sys::kprintln!(
            "[PAN] boot patch ({}): every site {}; {} sites, {} rewritten, {} refused, 0 branch",
            state, form, total, done, refused);
    } else {
        azos_drv_sys::kwarn!(
            "[PAN] boot patch ({}): {} of {} sites {}, {} still branch, {} refused",
            state, patched, total, form, branch, refused);
    }
}

// Every linked PAN site holds the word the boot probe asks for: the `msr`
// with FEAT_PAN, the `nop` without, never the slow-path branch. Canary:
// `canary=pan-patch-skip` leaves every site a branch; this test alone goes
// not ok.
#[cfg(feature = "ktest")]
azos_ktest::ktest! {
    fn a64_pan_sites_patched() {
        use azos_arch_api::isa::{aarch64::PAN, ExtPolicy};
        let n = sites().count();
        if !matches!(PAN, ExtPolicy::Probe) {
            return if n == 0 { Ok(()) } else { Err("a PAN site is linked outside A64_PAN=probe") };
        }
        if n == 0 {
            return Err("A64_PAN=probe links no PAN site: the walk saw nothing");
        }
        let present = azos_arch::sysregs::pan_in_use();
        for s in sites() {
            if s.pan_word(present) != Ok(word_at(s)) {
                return Err("a PAN site does not hold the probe's word (still the slow-path branch?)");
            }
        }
        Ok(())
    }
}
