// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot-once rewrite of the `SpinWait` probe sites (wave 15, N2b):
//! Linux's ALTERNATIVE for Kconfig RV_ZACAS / RV_ZAWRS / RV_ZIHINTPAUSE /
//! A64_LSE at `probe` (`crates/core/arch-api/src/spin.rs`,
//! `azos_trace::jump::KIND_*_ALT`).
//!
//! Every site is linked as its safe form (a branch to the out-of-line
//! LR/SC or LL/SC loop, or a nop), so each lock taken before this runs, and
//! every lock on a kernel that cannot patch, is correct on any core. Here,
//! from `ArchEntry::boot_patch` on the boot CPU before any secondary starts,
//! each site whose extension the boot probe confirmed (`SpinWait::
//! boot_site_wanted`) becomes the extension's instruction through the one
//! text-write path (`azos_mm::text_poke`, W^X kept). After this a probe
//! site costs what `require` costs: no flag load, no branch. Never again
//! after boot. Under `n`/`require` no site is linked and this prints
//! nothing.

use azos_arch::SpinWait as _;
use azos_trace::jump::{self, KeySite};

// The emitters (the ISA crates, which see only azos_arch_api) mirror the
// table's numbers; they must agree.
const _: () = assert!(azos_arch_api::spin::SITE_KEY_CAS == jump::KEY_SPIN_CAS);
const _: () = assert!(azos_arch_api::spin::SITE_KEY_WAIT == jump::KEY_SPIN_WAIT);
const _: () = assert!(azos_arch_api::spin::SITE_KEY_RELAX == jump::KEY_SPIN_RELAX);
const _: () = assert!(azos_arch_api::spin::SITE_KIND_RV_ALT == jump::KIND_RV_ALT);
const _: () = assert!(azos_arch_api::spin::SITE_KIND_A64_ALT == jump::KIND_A64_ALT);

/// The spin sites the kernel links (none outside `probe`).
pub(crate) fn sites() -> impl Iterator<Item = &'static KeySite> {
    azos_trace::key_sites()
        .iter()
        .filter(|s| matches!(s.key, jump::KEY_SPIN_CAS | jump::KEY_SPIN_WAIT | jump::KEY_SPIN_RELAX))
}

/// The word at a site.
pub(crate) fn word_at(s: &KeySite) -> u32 {
    insn_at(s.site as usize)
}

/// The 32-bit instruction at `va`: a riscv64 site may sit at 2 mod 4.
fn insn_at(va: usize) -> u32 {
    let p = va as *const u16;
    // SAFETY: a site address from the linked table (2-aligned), inside the
    // kernel text, which is readable.
    unsafe { core::ptr::read_volatile(p) as u32 | (core::ptr::read_volatile(p.add(1)) as u32) << 16 }
}

/// Does the site hold the word the boot probe asks for: the replacement
/// when its extension is in use, the linked form otherwise?
pub(crate) fn holds_wanted(s: &KeySite) -> bool {
    let w = word_at(s);
    if azos_arch::ARCH.boot_site_wanted(s.key) {
        s.alt_word() == Ok(w)
    } else {
        s.alt_is_linked(w) == Ok(true)
    }
}

/// Rewrite every wanted spin site; print the census and the first
/// rewritten site (its address and word, for a disassembly by hand).
pub(crate) fn patch(text_start: usize, text_end: usize) {
    let total = sites().count();
    if total == 0 {
        return;
    }
    // Gate canary: no rewrite; every site stays linked (the fallback).
    let skip = canary!("spin-patch-skip");
    if !skip && azos_mm::text_poke::alias().is_none() && azos_mm::text_poke::init(text_start, text_end).is_none() {
        azos_drv_sys::kwarn!("[SPIN] boot patch: no text alias, every site stays linked (the fallback)");
    }
    let (mut done, mut refused) = (0usize, 0usize);
    let mut first: Option<(u64, u32)> = None;
    const BATCH: usize = 16;
    let mut batch: [(usize, u32); BATCH] = [(0, 0); BATCH];
    let mut n = 0usize;
    let flush = |b: &[(usize, u32)], done: &mut usize, refused: &mut usize| {
        if b.is_empty() {
            return;
        }
        match azos_mm::text_poke::write_insns_boot(b) {
            Ok(k) => *done += k,
            Err(e) => {
                *refused += b.len();
                azos_drv_sys::kerr!("[SPIN] boot patch: text write refused ({:?})", e);
            }
        }
    };
    for s in sites() {
        if skip || azos_mm::text_poke::alias().is_none() || !azos_arch::ARCH.boot_site_wanted(s.key) {
            continue;
        }
        match (s.alt_is_linked(word_at(s)), s.alt_word()) {
            (Ok(true), Ok(want)) => {
                first.get_or_insert((s.site, want));
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
    let (mut held, mut alt) = (0usize, 0usize);
    for s in sites() {
        held += holds_wanted(s) as usize;
        alt += (s.alt_word() == Ok(word_at(s))) as usize;
    }
    let keys = |k: u32| sites().filter(|s| s.key == k).count();
    let line = |w: &mut dyn FnMut(core::fmt::Arguments)| w(format_args!(
        "[SPIN] boot patch: {} sites (cas {}, wait {}, relax {}), {} rewritten to the extension, {} linked, {} refused",
        total, keys(jump::KEY_SPIN_CAS), keys(jump::KEY_SPIN_WAIT), keys(jump::KEY_SPIN_RELAX),
        alt, total - alt, refused));
    if held == total && refused == 0 {
        line(&mut |a| azos_drv_sys::kprintln!("{}", a));
    } else {
        line(&mut |a| azos_drv_sys::kwarn!("{} ({} of {} hold the probe's word)", a, held, total));
    }
    if let Some((site, w)) = first {
        let now = insn_at(site as usize);
        azos_drv_sys::kprintln!("[SPIN] first rewritten site {:#x}: {:#010x} (wanted {:#010x}); {} written",
            site, now, w, done);
    }
}

// Every linked spin site holds the word the boot probe asks for: the
// extension's instruction where it was confirmed, the linked form (the
// fallback) elsewhere. Canary: `canary=spin-patch-skip` leaves every site
// linked; on a CPU with any probed extension this test alone goes not ok.
#[cfg(feature = "ktest")]
azos_ktest::ktest! {
    fn spin_sites_patched() {
        for s in sites() {
            if !holds_wanted(s) {
                return Err("a spin site does not hold the probe's word (still linked to the fallback?)");
            }
        }
        Ok(())
    }
}
