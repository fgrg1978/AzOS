// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `[ISA]` boot line and the refusals (config/Kconfig.arch, "Hardware
//! support model"; `azos_arch_api::isa`). Each ISA's boot hooks resolve
//! their extensions and call [`report`] once.
//!
//! Written straight to the UART, byte by byte, with no console lock and no
//! atomic read-modify-write: aarch64 calls it before the first lock, where
//! a level above the CPU (e.g. `+lse` codegen on an Armv8.0 core) would
//! fault on the lock's first LSE instruction instead of printing why.

use azos_arch_api::isa::{self, Ext};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

/// The UART, unlocked.
pub(crate) struct Raw;

impl Write for Raw {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            azos_drv_sys::uart::putc(b);
        }
        Ok(())
    }
}

/// Print the refusal and power off (PSCI SYSTEM_OFF / SBI shutdown), so a
/// QEMU run ends with the message as its last line.
pub(crate) fn refuse(f: impl FnOnce(&mut Raw) -> core::fmt::Result) -> ! {
    let _ = f(&mut Raw);
    let _ = Raw.write_str("\n");
    azos_arch_api::Boot::shutdown(&azos_arch::ARCH)
}

/// Print `msg` and power off: a configuration this machine cannot honour.
pub(crate) fn refuse_text(msg: &str) -> ! {
    refuse(|w| w.write_str(msg))
}

/// The CPU is below the baseline level: `missing` names the first feature
/// of the level it lacks. Never returns. Brings the UART up itself: on
/// aarch64 this runs before `uart::init` (register writes only, no lock),
/// and a second init right before the power-off is harmless elsewhere.
pub(crate) fn refuse_level(level: &str, missing: &str) -> ! {
    azos_drv_sys::uart::init();
    refuse(|w| isa::write_level_refusal(w, level, missing))
}

/// Print `[ISA] baseline=<level> <ext>=<state> ...`; refuse to boot when a
/// `require`d extension is missing.
pub(crate) fn report(level: &str, exts: &[Ext]) {
    let _ = isa::write_report(&mut Raw, level, exts);
    let _ = Raw.write_str("\n");
    if let Some(e) = isa::first_missing(exts) {
        refuse(|w| isa::write_refusal(w, e));
    }
    warn_user_access_fallbacks(exts);
    report_patch();
}

/// The hardware guards on the kernel's own access to user memory the `[ISA]`
/// report names: `(Ext::name, subject of the decision record)`. RISC-V has none
/// to probe: `sstatus.SUM` is architectural and always in use.
const USER_ACCESS_GUARDS: [(&str, u32); 3] = [("smep", 1), ("smap", 2), ("pan", 3)];

/// Bit `subject` is set for each guard in [`USER_ACCESS_GUARDS`] that Kconfig
/// left at `probe` and the CPU lacks; read by [`record_fallbacks`].
static FALLBACK: AtomicU64 = AtomicU64::new(0);

/// A `probe`d guard the CPU lacks is a quiet fallback to "every kernel access
/// to user memory is allowed" (an Armv8.0 Cortex-A53 has no PAN): say so on
/// the console, and keep the set for [`record_fallbacks`]. A single plain
/// store, as [`BUILD_ID`]: no read-modify-write this early on aarch64.
fn warn_user_access_fallbacks(exts: &[Ext]) {
    let mut absent = 0u64;
    for e in exts {
        let Some(&(_, subject)) = USER_ACCESS_GUARDS.iter().find(|(n, _)| *n == e.name) else { continue };
        if e.state() == isa::ExtState::Absent {
            absent |= 1 << subject;
            let _ = write!(
                Raw,
                "[SEC] warning: {} not present on this CPU ({}=probe): kernel accesses to user memory are not blocked by hardware; {}=require refuses such a CPU\n",
                e.name, e.symbol, e.symbol
            );
        }
    }
    FALLBACK.store(absent, Ordering::Release);
}

/// Write the decision record of each fallback [`warn_user_access_fallbacks`]
/// found (rule `hardening-fallback`, a refusal, so a durable receipt): called
/// once the decision sink and clock are installed, which the `[ISA]` report
/// precedes.
pub(crate) fn record_fallbacks() {
    let absent = FALLBACK.load(Ordering::Acquire);
    let isa = if cfg!(target_arch = "x86_64") { 2 } else if cfg!(target_arch = "aarch64") { 1 } else { 0 };
    for &(_, subject) in &USER_ACCESS_GUARDS {
        if absent & (1 << subject) != 0 {
            azos_decision::record(
                azos_decision::Rule::HardeningFallback,
                azos_decision::Verdict::Refuse,
                subject,
                [isa, 0, 0],
            );
        }
    }
}

// An empty executable input section for the `.text.patch_pool` output section
// of every linker script to collect: the linker gives an output section the
// flags of its inputs, and the pool has no input of its own, so without this it
// would be a non-executable ALLOC section. It sits apart from `.text.*` so the
// `.text` output section's `*(.text .text.*)` does not take it.
core::arch::global_asm!(".pushsection .patch_pool_anchor,\"ax\",%progbits", ".popsection");

extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static __patch_pool_start: u8;
    static __patch_pool_end: u8;
    static __azos_patch_start: u8;
    static __azos_patch_end: u8;
}

/// The kernel text `[start, end)`, the patch pool inside it.
pub(crate) fn text_range() -> (usize, usize) {
    (&raw const _text_start as usize, &raw const _text_end as usize)
}

/// The live-update patch pool `[start, end)` the linker laid out
/// (`LIVEPATCH_POOL_KIB`).
pub(crate) fn patch_pool() -> (usize, usize) {
    (&raw const __patch_pool_start as usize, &raw const __patch_pool_end as usize)
}

/// The `.azos_patch` table: the address of every function entry the
/// compiler left an entry slot at (`LIVEPATCH_ENTRY_NOPS`).
pub(crate) fn patch_sites() -> &'static [u64] {
    let (s, e) = (&raw const __azos_patch_start as usize, &raw const __azos_patch_end as usize);
    // SAFETY: the linker script aligns the section to 8 and fills it with
    // whole 8-byte entries (`tools/check_livepatch_layout.py` checks both);
    // it is read-only data for the life of the kernel.
    unsafe { core::slice::from_raw_parts(s as *const u64, (e - s) / azos_arch_api::isa::PATCH_SITE_BYTES) }
}

/// The kernel build-id, once [`report`] has computed it (four words, little
/// endian). Zero until then and always with Kconfig `LIVEPATCH` off.
static BUILD_ID: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// The kernel build-id: SHA-256 of `[_text_start, _text_end)` as linked
/// (`tools/check_livepatch_layout.py elf` computes the same from the ELF).
/// The text is hashed in `report`, before the first boot-time rewrite
/// (the PAN and spin sites, the static keys), so what is hashed is what the
/// linker wrote, whatever the CPU and the mask. `None` without `LIVEPATCH`.
pub(crate) fn build_id() -> Option<[u8; 32]> {
    let mut id = [0u8; 32];
    for (i, w) in BUILD_ID.iter().enumerate() {
        id[i * 8..i * 8 + 8].copy_from_slice(&w.load(Ordering::Acquire).to_le_bytes());
    }
    id.iter().any(|&b| b != 0).then_some(id)
}

/// Hash the text into [`BUILD_ID`] and print `[PATCH] build=<32 hex>` (the
/// first 16 bytes: a topology row pins 8 to 32).
fn compute_build_id() {
    if !azos_limits::LIVEPATCH {
        return;
    }
    let (s, e) = text_range();
    // SAFETY: the kernel's own text, mapped and readable at this point.
    let id = azos_crypto::sha256::sha256(unsafe { core::slice::from_raw_parts(s as *const u8, e - s) });
    for (i, w) in BUILD_ID.iter().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&id[i * 8..i * 8 + 8]);
        w.store(u64::from_le_bytes(b), Ordering::Release);
    }
    let _ = Raw.write_str("[PATCH] build=");
    for b in &id[..16] {
        let _ = write!(Raw, "{:02x}", b);
    }
    let _ = Raw.write_str("\n");
}

/// `[PATCH] pool=<KiB> sites=<n> entry_nops=<n>`: the live-update build hooks
/// (config/Kconfig.development) as the linker laid them out. The pool and site
/// table sizes come from the linker symbols, not from the Kconfig, so a
/// script that lost the section shows here; `entry_nops` is the Kconfig value
/// the compiler was given. With `LIVEPATCH`, the build-id line follows.
fn report_patch() {
    let (ps, pe) = patch_pool();
    let _ = isa::write_patch_line(
        &mut Raw,
        pe - ps,
        patch_sites().len() * isa::PATCH_SITE_BYTES,
        azos_limits::LIVEPATCH_ENTRY_NOPS,
    );
    let _ = Raw.write_str("\n");
    compute_build_id();
}
