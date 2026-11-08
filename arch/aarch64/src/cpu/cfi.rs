// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware control-flow integrity on aarch64: signed return addresses
//! (FEAT_PAuth, Kconfig `A64_PAUTH`) and the landing-pad groundwork for BTI
//! (FEAT_BTI, `A64_BTI`); plan item I4.
//!
//! The compiler half is `-Z branch-protection=bti,pac-ret`
//! (tools/build/kconfig_to_cargo.py, `cfi_rustflags`), kernel and user images: a
//! `paciasp` in the prologue and an `autiasp` before the return of every
//! non-leaf function, and a `bti` pad where one is needed. All of them are
//! HINT encodings, no-ops on a core without the extension, and `paciasp` /
//! `autiasp` stay no-ops until `SCTLR_EL1.EnIA` is set. This half turns the
//! signing on.
//!
//! # Signed returns
//!
//! * One key for the kernel, from [`azos_cfi_prepare`]: every CPU loads the
//!   same `APIAKey_EL1` (a task's signed return addresses sit on its own
//!   stack and survive a migration). Key A is also the key EL0 uses while
//!   `SCTLR_EL1.EnIA` is set, so with a single key ring 3 could run `pacia`
//!   and sign a value of its choosing, with a modifier of its choosing, under
//!   the kernel's key. Kconfig `A64_PAUTH_PROC_KEYS` closes that, see
//!   "Per-process keys" below.
//!
//! * The key is 128 bits from `RNDRRS` when FEAT_RNG is present and allowed
//!   (`A64_RNG`), mixed with the generic counter, the CPU ids and a stack
//!   address. Without FEAT_RNG the counter is all the entropy there is this
//!   early: the key is new on every boot but guessable to an attacker who
//!   knows the boot time closely. The device-tree seeds arrive after the
//!   first signed frame exists, and a key cannot change while frames are live.
//! * `EnIA` (and, with `A64_PAUTH_PROC_KEYS`, `EnIB`, `EnDA`, `EnDB`) flips with
//!   no signed frame live. The flip is [`_azos_cfi_enable`],
//!   an assembly leaf that boot.S calls on each CPU right before it enters
//!   Rust for good (`kernel_main`, `secondary_main`); the Rust code that ran
//!   before it (the MMU bring-up) did its `paciasp` and `autiasp` both as
//!   no-ops. Flipping inside a Rust function would turn its `autiasp` on
//!   against a return address it never signed.
//! * A CPU that cannot enable it while another did is not supported (the
//!   architecture wants PAuth uniform across the PEs).
//! * Backtraces: a saved return address is signed, `strip` it
//!   (kernel/src/prof.rs does, with `xpaclri`).
//!
//! # Per-process keys (Kconfig `A64_PAUTH_PROC_KEYS`)
//!
//! Every process has its own `APIA`, `APIB`, `APDA`, `APDB` and `APGA` keys
//! (`KEY_WORDS` words, `UserKeys`), drawn from the kernel DRBG when its image is
//! loaded and never visible to any other process or to the kernel.
//!
//! * **Lifetime** (the table is `azos_sched::pac`, `KeyTable` is the pure part
//!   here): a `spawn` and an `exec` draw fresh keys; a `fork` child and a
//!   thread copy their creator's. The copy is not a choice: a forked child
//!   returns through frames its parent signed on the copied stack, and fresh
//!   keys would fail every `autiasp` in it.
//! * **The kernel's own key stays installed in `APIAKey_EL1` whenever the
//!   hart runs in EL1.** The kernel signs with key A only, so key A is the
//!   one key that must change at the EL0 boundary: `trap_entry.S` writes the
//!   kernel key (`AZOS_PAC_KERNEL_KEY`) on every entry from EL0, before the
//!   first `paciasp`, and the process's key (`AZOS_PAC_USER_APIA[hart]`) just
//!   before the `eret` that returns to EL0 (`eret` is a context
//!   synchronization event: no `isb` on the way out, one on the way in).
//!   Frames the kernel signed while a task slept in a syscall are therefore
//!   valid whichever process ran in between.
//! * **The other four keys are not used by the kernel**, so they are written
//!   once per switch-in ([`load_user_keys`], called from
//!   `azos_sched::asid::prepare_switch`, with the process's `APIA` pair
//!   published for the exit path) and `eret` carries them to EL0. `EnIB`,
//!   `EnDA` and `EnDB` are set together with `EnIA` ([`enable_mask`]) so that
//!   ring-3 code built with the B key or data-pointer signing has a live,
//!   private key; `pacga` needs no enable bit.
//! * **Cost** (static, per syscall round trip): entry is a flag test, a
//!   2-word load, 2 `msr` and an `isb`; exit is a flag test, a 2-word load
//!   and 2 `msr`. A switch to a process costs 8 `msr` and the 2-word
//!   publish. Not measured (no boot this week).
//! * Without FEAT_RNG and with the pool still unseeded when a process is
//!   created, the keys come from [`derive_user_keys`]: the boot key (secret
//!   to ring 3), the generic counter and the slot, so they are distinct per
//!   process but not independent of the kernel key. The pool is seeded long
//!   before the first ring-3 process on every board that has a seed source.
//!
//! # BTI (Kconfig `A64_BTI_ENFORCE`)
//!
//! The pads are in the code. Enforcing them is the `GP` bit of the kernel
//! text's leaves (`vmm::guard_range`, after the W^X pass; the mmu's
//! `attr_bits` never sets it); that bit alone turns the check on, on every CPU
//! that sees the leaf. `SCTLR_EL1.BT1` ([`azos_bti_enable`], from boot.S next to
//! `_azos_cfi_enable`) is a different control: it makes `paciasp` stop being a
//! valid target of a `br` through a register other than x16/x17, the way the
//! compiler emits an indirect tail call under `bti`. Linux sets it with
//! kernel BTI too. The assembly
//! carries its own pads (`tools/lint/bti_pads_lint.py`), and `context_switch`
//! resumes a task through `ret x9`, which is not checked, because the resume
//! point is the instruction after a `bl`. Loaded text (modules, ring 3) is
//! guarded per ELF (`.note.gnu.property` BTI), not wholesale.
//!
//! # GCS (FEAT_GCS, Armv9.4; Kconfig `A64_GCS`, probed only)
//!
//! The hardware return stack, twin of the x86 CET shadow stack: with
//! `GCSCR_EL1.PCRSEL` set, `bl` pushes the return address at `GCSPR_EL1` and
//! `ret` pops it and raises a GCS exception on a mismatch. Mainline Linux
//! runs it for EL0 only; there is no kernel GCS to copy.
//!
//! **Not enabled, and what it waits for.** `GCSPR_EL1` must point at GCS
//! pages, and a GCS page is a stage-1 indirect permission (a `PIR_EL1`
//! nibble with the GCS encoding, 0x9, Linux sysreg.h `PIE_GCS`); Linux's
//! headers define no GCS page under the direct AP/XN bits. With `PCRSEL` on
//! and no GCS page, the first `bl` faults. The kernel's mappings can run on
//! S1PIE (Kconfig `A64_S1PIE`, `mmu::pie`): every produced index keeps its
//! direct meaning, index 4 is the kernel GCS page (`vmm::map_gcs`), and
//! `TCR2_EL1` is one composed value with `ptwin`'s POE on every CPU path. That
//! rules out the hypervisor stub and the split monitor until they save or
//! allow `TCR2_EL1`. A GCS therefore needs `A64_S1PIE` and a CPU that runs it
//! (`mmu::pie::on`). Until it is enabled the EL2 trampoline keeps
//! `HCRX_EL2.GCSEn` at 0 (`mmu/boot.rs`), so a `GCSCR_EL1` left set by reset
//! never takes effect.
//!
//! **What the GCS itself needs**, path by path (every transfer in the
//! kernel's assembly that is not a matched `bl`/`ret`):
//!
//! | path | under a kernel GCS |
//! |---|---|
//! | the GCS pages themselves | kernel GCS leaves (`vmm::map_gcs`, index 4) outside the linear map, and the frames' linear-map alias unmapped or read-only: through the alias a plain store still lands |
//! | a secondary or resumed CPU before `aarch64_secondary_stage1` | runs the direct permissions (a GCS leaf, AP=00 with UXN clear, reads there as kernel RW and EL0 execute-only), so `PCRSEL` flips only after that call and no EL0 runs before it |
//! | `context_switch` `ret x9` | save `GCSPR_EL1` in `TaskContext` before the `context_saving` release, load new's after; `x9 = CTX_PC = CTX_RA` is what new's own `bl context_switch` pushed, so the `ret` checks the saved PC |
//! | a new task's first switch (`lifecycle.rs`, `pc = ra = entry`) | its GCS is seeded with `entry` (`GCSSTR` with `GCSCR_EL1.STREn`, or the frame's linear alias before it is mapped as GCS) |
//! | `aarch64_ipc_resume_stub`, `ipc_ktest_resume_tramp` (IPC_FASTPATH_RESUME: `ipc_fast_start_at` rewrites `CTX_PC`, the frames it blocked in are abandoned) | the same rewrite resets the task's GCS to empty plus the stub's address, else the `ret x9` meets the abandoned `bl context_switch` entry |
//! | trap entry, `trap_return`, `_svc_native_return` `eret` | no GCS push or pop on an exception or an `eret`; the handlers' `bl`/`ret` pair up. The IRQ stack shares the task's GCS, so it is sized for task depth plus nesting |
//! | expected-fault fixup (`trap::fault::expected`) | `eret` to a label in the faulting function: no frame unwound, no change |
//! | `azos_cpu_save_run` / `azos_cpu_resume_restore` (`resume.rs`) | `GCSPR_EL1` in the `SaveArea`; the resume enables `GCSCR_EL1` and restores it before its `ret` |
//! | `_azos_cfi_enable` and its twin for GCS | `PCRSEL` cannot flip inside a function that later `ret`s on an empty GCS: inline in boot.S before `bl kernel_main`/`secondary_main` (which never return), or on each CPU's first `context_switch(NULL, ..)` |
//! | boot.S `br x9` (×2), `_azos_drop_to_el1` `bl`→`eret` | GCS still off there |
//! | lx-emul `switch` (`crates/drivers/lx/emul/src/switch/aarch64.rs`, `ret` onto another stack) | a GCS per lx stack, switched with `GCSSS1`/`GCSSS2` |
//! | EL2 (hypervisor stub, monitor) | `GCSEn` stays 0 for guests; a guest GCS needs `GCSCR_EL1`/`GCSPR_EL1` in the world switch and `VTCR_EL2.GCSH` |
//!
//! Encodings (Linux arch/arm64/tools/sysreg; instructions as LLVM 22 and
//! Apple clang assemble them): `GCSCR_EL1` S3_0_C2_C5_0 (PCRSEL 0, RVCHKEN 5,
//! EXLOCKEN 6, PUSHMEn 8, STREn 9), `GCSPR_EL1` S3_0_C2_C5_1 (PTR 63:3),
//! `GCSCRE0_EL1` S3_0_C2_C5_2 (nTR 10, no EXLOCKEN), `GCSPR_EL0`
//! S3_3_C2_C5_1, `ID_AA64PFR1_EL1.GCS` 47:44, `HCRX_EL2.GCSEn` 22,
//! `HFGRTR/HFGWTR_EL2` nGCS_EL1 53 and nGCS_EL0 52, `HFGITR_EL2` nGCSEPP 59,
//! nGCSSTR_EL1 58, nGCSPUSHM_EL1 57, `VTCR_EL2.GCSH` 40, `TCR2_EL1.PIE` 1;
//! `GCSPUSHM` = `sys #3, c7, c7, #0`, `GCSPOPM` = `sysl #3, c7, c7, #1`,
//! `GCSSS1` = `sys #3, c7, c7, #2`, `GCSSS2` = `sysl #3, c7, c7, #3`,
//! `GCSSTR x1, [x0]` = 0xd91f0c01, `GCSB DSYNC` = `hint #19`; the GCS
//! exception class is 0x2D and a data abort's ISS2.GCS bit 8 (Linux esr.h
//! `ESR_ELx_EC_GCS`, `ESR_ELx_GCS`), the `PIR_EL1` GCS nibble 0x9 (sysreg.h
//! `PIE_GCS`). Still to check against the Arm ARM (not reachable from here;
//! Linux names the field only): that `HCRX_EL2.GCSEn` 0 turns GCS off at EL1
//! and EL0 rather than only trapping its registers. The S1PIE row checks
//! that a plain store to a GCS page faults (`cfi_gcs_page_refuses_a_plain_store`).
//!
//! BTI and GCS are independent: `ret x9` is not BTI-checked and is
//! GCS-checked, a `br` is the reverse.

use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::sync::atomic::AtomicBool;

use crate::sysregs::SCTLR_EL1_ENIA;

/// The kernel's key, `[lo, hi]`, published by the boot CPU for every
/// secondary. `trap_entry.S` reads it by name (`AZOS_PAC_KERNEL_KEY`) on every
/// entry from EL0.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub static AZOS_PAC_KERNEL_KEY: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Nonzero once this build signs: the CPU has FEAT_PAuth and `EnIA` is on.
/// `trap_entry.S` skips the key swap at the EL0 boundary while it is 0 (the
/// key registers are UNDEFINED on a core without the extension).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub static AZOS_PAC_ON: AtomicU64 = AtomicU64::new(0);
/// The `APIA` key (`[lo, hi]`) of the process the hart will return to EL0
/// with, per hart (index `TPIDR_EL1`, 16 bytes each). Written by
/// [`load_user_keys`] on switch-in, read by `trap_entry.S` before `eret`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub static AZOS_PAC_USER_APIA: [[AtomicU64; 2]; azos_arch_api::tlb_gen::HARTS] =
    [const { [AtomicU64::new(0), AtomicU64::new(0)] }; azos_arch_api::tlb_gen::HARTS];
/// The boot CPU has a key and turned `EnIA` on: every other CPU must follow.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static KEY_READY: AtomicBool = AtomicBool::new(false);

/// `ID_AA64ISAR0_EL1.RNDR` (bits 63:60): FEAT_RNG.
pub const fn isar0_has_rng(isar0: u64) -> bool {
    (isar0 >> 60) & 0xf >= 1
}

/// SplitMix64: the mixer for the key words. Not a cipher: it only has to
/// spread the few real bits of a poor source over the whole key.
const fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The key from its raw sources. Chained, so every source moves both words
/// (pure: the host rows check that each input does, and that the words differ).
pub const fn derive_key(rng: [u64; 2], counter: u64, ids: u64, addr: u64) -> (u64, u64) {
    let s = splitmix64(addr);
    let s = splitmix64(s ^ ids);
    let s = splitmix64(s ^ counter);
    let s = splitmix64(s ^ rng[0]);
    let t = splitmix64(s ^ rng[1]);
    (splitmix64(t ^ 0x5851_F42D_4C95_7F2D), splitmix64(t.rotate_left(32) ^ 0xA5A5_A5A5_A5A5_A5A5))
}

/// Whether the SCTLR_EL1 word has the signing on.
pub const fn signing_on(sctlr: u64) -> bool {
    sctlr & SCTLR_EL1_ENIA != 0
}

/// `SCTLR_EL1.EnIB` (bit 30), `EnDA` (bit 27), `EnDB` (bit 13): the other
/// three keys' enables (`EnIA` is bit 31, `SCTLR_EL1_ENIA`).
pub const SCTLR_ENIB: u64 = 1 << 30;
pub const SCTLR_ENDA: u64 = 1 << 27;
pub const SCTLR_ENDB: u64 = 1 << 13;

/// The `SCTLR_EL1` bits `_azos_cfi_enable` sets: `EnIA` alone, or all four
/// enables when the processes have keys of their own (`proc_keys`). A key
/// that is enabled but not private would be one more shared key.
pub const fn enable_mask(proc_keys: bool) -> u64 {
    if proc_keys {
        SCTLR_EL1_ENIA | SCTLR_ENIB | SCTLR_ENDA | SCTLR_ENDB
    } else {
        SCTLR_EL1_ENIA
    }
}

/// The words of a process's key set: `APIA`, `APIB`, `APDA`, `APDB`, `APGA`,
/// each `[lo, hi]` (the order `KEY_*` index).
pub const KEY_WORDS: usize = 10;
/// Random bytes a [`UserKeys`] is drawn from.
pub const KEY_BYTES: usize = KEY_WORDS * 8;
/// Index of the `APIA` `[lo, hi]` pair in a [`UserKeys`].
pub const KEY_IA: usize = 0;
/// Index of the `APIB` pair.
pub const KEY_IB: usize = 2;
/// Index of the `APDA` pair.
pub const KEY_DA: usize = 4;
/// Index of the `APDB` pair.
pub const KEY_DB: usize = 6;
/// Index of the `APGA` pair.
pub const KEY_GA: usize = 8;

/// A process's five pointer-authentication keys.
pub type UserKeys = [u64; KEY_WORDS];

/// Keys from random bytes (little endian words).
pub fn keys_from_bytes(b: &[u8; KEY_BYTES]) -> UserKeys {
    let mut k = [0u64; KEY_WORDS];
    for (w, c) in k.iter_mut().zip(b.chunks_exact(8)) {
        let mut x = [0u8; 8];
        x.copy_from_slice(c);
        *w = u64::from_le_bytes(x);
    }
    k
}

/// The keys when the DRBG has nothing to give (still unseeded): every word a
/// chained SplitMix64 step of the boot key, the generic counter and the
/// process's table slot. Distinct per process (the slot and the counter move
/// every word) and unguessable without the kernel key, but not independent of
/// it: the draw from the pool is the real source.
pub const fn derive_user_keys(boot: (u64, u64), counter: u64, slot: u64) -> UserKeys {
    let mut s = splitmix64(boot.0 ^ slot.rotate_left(48));
    s = splitmix64(s ^ boot.1);
    s = splitmix64(s ^ counter);
    let mut k = [0u64; KEY_WORDS];
    let mut i = 0;
    while i < KEY_WORDS {
        s = splitmix64(s ^ (i as u64 + 1));
        k[i] = s;
        i += 1;
    }
    k
}

/// Whether `k` may be installed as a process's keys: its `APIA` is not the
/// kernel's and no key is all zero (a zero key is what an undrawn slot reads).
pub fn keys_usable(k: &UserKeys, kernel: (u64, u64)) -> bool {
    (k[KEY_IA], k[KEY_IA + 1]) != kernel && k.chunks_exact(2).all(|p| p[0] | p[1] != 0)
}

/// The keys of a new image: `random` when the pool gave bytes, else
/// [`derive_user_keys`]; and a set that is not [`keys_usable`] (one chance in
/// 2^64 per word from the pool, a bug from the derivation) is mixed until it
/// is. Never returns the kernel's key.
pub fn fresh_user_keys(random: Option<&[u8; KEY_BYTES]>, boot: (u64, u64), counter: u64, slot: u64) -> UserKeys {
    let mut k = match random {
        Some(b) => keys_from_bytes(b),
        None => derive_user_keys(boot, counter, slot),
    };
    let mut round = 0u64;
    while !keys_usable(&k, boot) {
        round += 1;
        k = derive_user_keys(boot, counter ^ round.rotate_left(32), slot ^ k[0]);
    }
    k
}

/// Every process's keys, by task slot. The words are atomics so the table is a
/// plain `static`: a slot is written only while no hart can be running the
/// task it belongs to (its creation, or its own `exec` on the hart that reads
/// it), and published by the same `Release` that makes the task runnable.
pub struct KeyTable<const N: usize> {
    set: [AtomicU64; N],
    words: [[AtomicU64; KEY_WORDS]; N],
}

impl<const N: usize> KeyTable<N> {
    /// An empty table: no slot has keys.
    pub const fn new() -> Self {
        Self {
            set: [const { AtomicU64::new(0) }; N],
            words: [const { [const { AtomicU64::new(0) }; KEY_WORDS] }; N],
        }
    }

    /// Give `slot` the keys `k` (a new image: `spawn`, `exec`). `false` for a
    /// slot out of range.
    pub fn draw(&self, slot: usize, k: &UserKeys) -> bool {
        if slot >= N {
            return false;
        }
        for (w, v) in self.words[slot].iter().zip(k) {
            w.store(*v, Ordering::Relaxed);
        }
        self.set[slot].store(1, Ordering::Release);
        true
    }

    /// `dst` gets `src`'s keys (a `fork` child, a thread: the same address
    /// space contents). A `src` without keys leaves `dst` without. `false`
    /// when either slot is out of range.
    pub fn inherit(&self, dst: usize, src: usize) -> bool {
        if dst >= N || src >= N {
            return false;
        }
        match self.get(src) {
            Some(k) => self.draw(dst, &k),
            None => {
                self.clear(dst);
                true
            }
        }
    }

    /// `slot` has no keys (a task slot being created: a stale set must not
    /// reach the next task that gets the slot).
    pub fn clear(&self, slot: usize) {
        if slot < N {
            self.set[slot].store(0, Ordering::Relaxed);
            for w in &self.words[slot] {
                w.store(0, Ordering::Relaxed);
            }
        }
    }

    /// The keys of `slot`, or `None` for a task that has none (a kernel task).
    pub fn get(&self, slot: usize) -> Option<UserKeys> {
        if slot >= N || self.set[slot].load(Ordering::Acquire) == 0 {
            return None;
        }
        let mut k = [0u64; KEY_WORDS];
        for (v, w) in k.iter_mut().zip(&self.words[slot]) {
            *v = w.load(Ordering::Relaxed);
        }
        Some(k)
    }
}

/// `APIAKeyLo_EL1` / `APIAKeyHi_EL1` by their encodings: an Armv8.3 name the
/// assembler may not accept at the base level.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn write_key(lo: u64, hi: u64) {
    // SAFETY: only reached after the ID registers said FEAT_PAuth is
    // implemented, so the registers exist; writing a key changes no code that
    // is running with `EnIA` clear.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C2_C1_0, {lo}",
            "msr S3_0_C2_C1_1, {hi}",
            "isb",
            lo = in(reg) lo, hi = in(reg) hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// The generic counter, ordered by an `isb`: one of the key sources.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn counter() -> u64 {
    let v: u64;
    // SAFETY: a read of the generic counter, readable at EL1.
    unsafe { core::arch::asm!("isb", "mrs {0}, CNTVCT_EL0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn cpu_ids() -> u64 {
    let (midr, mpidr): (u64, u64);
    // SAFETY: two ID register reads.
    unsafe {
        core::arch::asm!("mrs {0}, MIDR_EL1", "mrs {1}, MPIDR_EL1",
            out(reg) midr, out(reg) mpidr, options(nomem, nostack, preserves_flags));
    }
    midr.rotate_left(17) ^ mpidr
}

/// One `RNDRRS` word, or 0 when it kept saying no (Z set) for `RETRIES` reads.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn rndrrs() -> u64 {
    for _ in 0..azos_arch_api::entropy::RETRIES {
        let (v, ok): (u64, u64);
        // SAFETY: only called after the ID register said FEAT_RNG. NZCV is
        // written (no `preserves_flags`); not `pure`, so every read is new.
        unsafe {
            core::arch::asm!("mrs {v}, S3_3_C2_C4_1", "cset {ok}, ne",
                v = out(reg) v, ok = out(reg) ok, options(nostack, nomem));
        }
        if ok != 0 {
            return v;
        }
    }
    0
}

/// Per CPU, from boot.S, before [`_azos_cfi_enable`]: load this CPU's key
/// (the boot CPU makes it) and return the `SCTLR_EL1` enable bits to set
/// ([`enable_mask`]), or 0 for none. `primary` is 1 on the boot CPU.
///
/// 0 when Kconfig `A64_PAUTH` is `n`, when the CPU has no PAuth (a `require`
/// is refused later, by the `[ISA]` report), or, on a secondary, when the
/// boot CPU did not turn it on. Runs with `EnIA` clear, so this function's own
/// `paciasp`/`autiasp` are no-ops.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub extern "C" fn azos_cfi_prepare(primary: u64) -> u64 {
    if !azos_arch_api::isa::aarch64::PAUTH.allowed() || !super::features::detect().pauth {
        return 0;
    }
    if primary != 0 {
        let rng = if azos_arch_api::isa::aarch64::RNG.gate(isar0_has_rng(super::features::read_id_regs().isar0)) {
            [rndrrs(), rndrrs()]
        } else {
            [0, 0]
        };
        let probe = 0u8;
        let (lo, hi) = derive_key(rng, counter(), cpu_ids(), &probe as *const u8 as u64);
        AZOS_PAC_KERNEL_KEY[0].store(lo, Ordering::Relaxed);
        AZOS_PAC_KERNEL_KEY[1].store(hi, Ordering::Relaxed);
        KEY_READY.store(true, Ordering::Release);
    } else if !KEY_READY.load(Ordering::Acquire) {
        return 0;
    }
    write_key(AZOS_PAC_KERNEL_KEY[0].load(Ordering::Relaxed), AZOS_PAC_KERNEL_KEY[1].load(Ordering::Relaxed));
    // Published before any ring-3 entry exists: `trap_entry.S` swaps keys at
    // the EL0 boundary from now on.
    AZOS_PAC_ON.store(1, Ordering::Release);
    enable_mask(azos_limits::A64_PAUTH_PROC_KEYS)
}

/// Is `SCTLR_EL1.BT1` set: is `paciasp` strict (not a `br` target) at EL1?
/// This is not "BTI is enforced": the GP bit of the leaves is.
pub const fn pac_bt_strict(sctlr: u64) -> bool {
    sctlr & crate::sysregs::SCTLR_EL1_BT1 != 0
}

/// Per CPU, from boot.S: set `SCTLR_EL1.BT1` when Kconfig `A64_BTI_ENFORCE`
/// asks, `A64_BTI` allows and the CPU has FEAT_BTI (see [`pac_bt_strict`]).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub extern "C" fn azos_bti_enable() {
    if azos_limits::A64_BTI_ENFORCE && azos_arch_api::isa::aarch64::BTI.gate(super::features::detect().bti) {
        crate::sysregs::write_sctlr_el1(crate::sysregs::read_sctlr_el1() | crate::sysregs::SCTLR_EL1_BT1);
        // SAFETY: a context-synchronization event for the SCTLR write.
        unsafe { core::arch::asm!("isb", options(nomem, nostack, preserves_flags)) };
    }
}

/// Whether this CPU has `SCTLR_EL1.BT1` set.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn pac_bt_strict_this_cpu() -> bool {
    pac_bt_strict(crate::sysregs::read_sctlr_el1())
}

/// The kernel's key, `(lo, hi)`: what a process's keys must never equal.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn kernel_key() -> (u64, u64) {
    (AZOS_PAC_KERNEL_KEY[0].load(Ordering::Relaxed), AZOS_PAC_KERNEL_KEY[1].load(Ordering::Relaxed))
}

/// Whether the keys swap at the EL0 boundary on this boot: the CPU signs and
/// the build gives processes keys (Kconfig `A64_PAUTH_PROC_KEYS`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn proc_keys_active() -> bool {
    azos_limits::A64_PAUTH_PROC_KEYS && AZOS_PAC_ON.load(Ordering::Acquire) != 0
}

/// Install a process's keys on this hart for its next return to EL0: the
/// `APIA` pair goes to this hart's slot of [`AZOS_PAC_USER_APIA`] (the exit
/// path of `trap_entry.S` writes it), and `APIB`, `APDA`, `APDB`, `APGA` go to
/// the registers now. The kernel signs with `APIA` only, so those four are
/// safe to write in EL1; no `isb`, the `eret` that reaches EL0 is a context
/// synchronization event. Call with interrupts masked, on the hart that will
/// return to EL0, and only when [`proc_keys_active`].
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn load_user_keys(k: &UserKeys) {
    let hart: usize;
    // SAFETY: a read of this hart's id register, as `current_cpu_id()` does.
    unsafe { core::arch::asm!("mrs {0}, TPIDR_EL1", out(reg) hart, options(nomem, nostack, preserves_flags)) };
    if hart < AZOS_PAC_USER_APIA.len() {
        AZOS_PAC_USER_APIA[hart][0].store(k[KEY_IA], Ordering::Relaxed);
        AZOS_PAC_USER_APIA[hart][1].store(k[KEY_IA + 1], Ordering::Relaxed);
    }
    // SAFETY: only reached when `AZOS_PAC_ON` says the CPU has FEAT_PAuth, so
    // the registers exist; nothing in EL1 signs with these four keys.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C2_C1_2, {ib0}", // APIBKeyLo_EL1
            "msr S3_0_C2_C1_3, {ib1}", // APIBKeyHi_EL1
            "msr S3_0_C2_C2_0, {da0}", // APDAKeyLo_EL1
            "msr S3_0_C2_C2_1, {da1}", // APDAKeyHi_EL1
            "msr S3_0_C2_C2_2, {db0}", // APDBKeyLo_EL1
            "msr S3_0_C2_C2_3, {db1}", // APDBKeyHi_EL1
            "msr S3_0_C2_C3_0, {ga0}", // APGAKeyLo_EL1
            "msr S3_0_C2_C3_1, {ga1}", // APGAKeyHi_EL1
            ib0 = in(reg) k[KEY_IB], ib1 = in(reg) k[KEY_IB + 1],
            da0 = in(reg) k[KEY_DA], da1 = in(reg) k[KEY_DA + 1],
            db0 = in(reg) k[KEY_DB], db1 = in(reg) k[KEY_DB + 1],
            ga0 = in(reg) k[KEY_GA], ga1 = in(reg) k[KEY_GA + 1],
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Off bare-metal aarch64 nothing signs.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub extern "C" fn azos_cfi_prepare(_primary: u64) -> u64 {
    0
}

/// Whether this CPU signs return addresses now.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn signing_enabled() -> bool {
    signing_on(crate::sysregs::read_sctlr_el1())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(r#"
.section .text.azos_boot, "ax"
.globl _azos_cfi_enable
_azos_cfi_enable:
    hint    #38                      // bti jc: CFI landing pad
    // x0 = the enable bits `azos_cfi_prepare` returned (boot.S passes it
    // through): EnIA (bit 31), and with A64_PAUTH_PROC_KEYS EnIB (30), EnDA
    // (27), EnDB (13). Key A signs for EL1 and EL0; the others only EL0 uses.
    mrs     x9, SCTLR_EL1
    orr     x9, x9, x0
    msr     SCTLR_EL1, x9
    isb
    ret
"#);
