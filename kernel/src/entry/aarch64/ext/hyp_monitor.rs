// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side of the resident monitor (VIRT_SPLIT / Kconfig
//! HYP_MONITOR): the monitor blob `.incbin`'d into the `.hyp` section, and the
//! boot probe that proves it is up. The EL2 code itself is a separate image
//! (`crates/core/hyp-mon`); the kernel only starts it (the trampoline branch
//! in `arch/aarch64/src/mmu/boot.rs`) and talks to it over the ABI.
//!
//! The blob variant is chosen by feature so a gate canary that removes one
//! monitor mechanism links a differently-built monitor and turns one row red.

use azos_drv_sys::kprintln;
use azos_hyp_api::{
    is_monitor_call, words_to_out, DeriveReq, LockDesc, TextSite, CALL_GUARD_PAGES, CALL_KEY_DERIVE,
    CALL_KEY_ROOT_SET, CALL_LOCK_KERNEL_IMAGE, CALL_LOCK_RO_DATA, CALL_PIN, CALL_PROBE, CALL_TEXT_PATCH,
    INVARIANT_NAMES, KEY_LEN, KEY_ROOTS, LOCK_RAM_MAX, OK, PIN_FGT, TEXT_SITES_MAX,
};

// The blob, placed in `.hyp` (a non-exec `alloc` section the linker keeps out
// of the kernel's text/rodata ranges). `_hyp_blob_start` is the monitor's
// entry; the trampoline branches to it. One `.incbin` per build variant.
macro_rules! hyp_blob {
    ($file:literal) => {
        core::arch::global_asm!(
            concat!(
                ".section .hyp, \"a\"\n",
                ".balign 4096\n",
                ".globl _hyp_blob_start\n",
                "_hyp_blob_start:\n",
                ".incbin \"", env!("AZOS_OUT"), $file, "\"\n",
                ".balign 4096\n",
                ".globl _hyp_blob_end\n",
                "_hyp_blob_end:\n",
            )
        );
    };
}

#[cfg(not(any(
    feature = "hyp-mmu-off-canary",
    feature = "hyp-no-secondary-init-canary",
    feature = "hyp-hole-mapped-canary",
    feature = "hyp-tsc-off-canary",
    feature = "hyp-text-rw-canary",
    feature = "hyp-text-site-skip-canary",
    feature = "hyp-guard-skip-canary",
    feature = "hyp-pin-off-canary",
    feature = "hyp-kdf-salt-canary"
)))]
hyp_blob!("/build/aarch64/hyp-mon.bin");
#[cfg(feature = "hyp-mmu-off-canary")]
hyp_blob!("/build/aarch64/hyp-mon-mmu-off.bin");
#[cfg(feature = "hyp-no-secondary-init-canary")]
hyp_blob!("/build/aarch64/hyp-mon-no-secondary-init.bin");
#[cfg(feature = "hyp-hole-mapped-canary")]
hyp_blob!("/build/aarch64/hyp-mon-hole-mapped.bin");
#[cfg(feature = "hyp-tsc-off-canary")]
hyp_blob!("/build/aarch64/hyp-mon-tsc-off.bin");
#[cfg(feature = "hyp-text-rw-canary")]
hyp_blob!("/build/aarch64/hyp-mon-text-rw.bin");
#[cfg(feature = "hyp-text-site-skip-canary")]
hyp_blob!("/build/aarch64/hyp-mon-text-site-skip.bin");
#[cfg(feature = "hyp-guard-skip-canary")]
hyp_blob!("/build/aarch64/hyp-mon-guard-skip.bin");
#[cfg(feature = "hyp-pin-off-canary")]
hyp_blob!("/build/aarch64/hyp-mon-pin-off.bin");
#[cfg(feature = "hyp-kdf-salt-canary")]
hyp_blob!("/build/aarch64/hyp-mon-kdf-salt.bin");

/// Issue a monitor call (SMCCC: id in x0, args in x1..x3, results back in
/// x0..x4). An HVC, which the monitor traps at EL2.
#[inline]
fn monitor_call(id: u64, a1: u64) -> [u64; 4] {
    monitor_call2(id, a1, 0)
}

#[inline]
fn monitor_call2(id: u64, a1: u64, a2: u64) -> [u64; 4] {
    let r = monitor_call5(id, a1, a2);
    [r[0], r[1], r[2], r[3]]
}

#[inline]
fn monitor_call5(id: u64, a1: u64, a2: u64) -> [u64; 5] {
    let (mut x0, mut x1, mut x2, mut x3, mut x4) = (id, a1, a2, 0u64, 0u64);
    // SAFETY: the monitor is resident (HYP_MONITOR built it in and the
    // trampoline started it) before this runs.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            inout("x1") x1,
            inout("x2") x2,
            inout("x3") x3,
            inout("x4") x4,
        );
    }
    [x0, x1, x2, x3, x4]
}

/// The EL2 line of the boot banner for a split image: probe the monitor and
/// list the invariants it reports in force. The probe is the first EL1→EL2
/// call; a monitor that is wrong stops the boot here, not at a later attack.
pub(crate) fn report() {
    debug_assert!(is_monitor_call(CALL_PROBE));
    let r = monitor_call(CALL_PROBE, 0);
    if r[0] as i64 != OK {
        kprintln!("[BOOT] EL2:        monitor probe failed ({})", r[0] as i64);
        return;
    }
    let (abi, inv, pes) = (r[1], r[2], r[3]);
    kprintln!("[BOOT] EL2:        monitor up (abi {}, PEs {})", abi, pes);
    let mut first = true;
    for (bit, name) in INVARIANT_NAMES {
        if inv & bit != 0 {
            kprintln!("[BOOT] EL2:        invariant {} in force", name);
            first = false;
        }
    }
    if first {
        kprintln!("[BOOT] EL2:        no invariants reported");
    }
}

/// A secondary released through a spin table jumps to a kernel-written address
/// at EL2, past the monitor, and the monitor cannot intercept that. `found` is
/// how many spin-table CPUs the tree lists; any is a halt for a split image.
pub(crate) fn refuse_spin_table(found: usize) {
    if (found == 0 && !canary!("hyp-fake-spin-table")) || canary!("hyp-halt-skip") {
        return;
    }
    crate::boot::isa::refuse_text(
        "[BOOT] EL2:        refused: spin-table secondaries bypass the monitor (split never degrades)",
    )
}

/// Without a PSCI conduit a second PE cannot be started through the monitor,
/// so a split image with more than one CPU and no conduit halts.
pub(crate) fn refuse_no_conduit(no_conduit: bool, cpus: usize) {
    if !((no_conduit || canary!("hyp-fake-no-conduit")) && cpus > 1) || canary!("hyp-halt-skip") {
        return;
    }
    crate::boot::isa::refuse_text(
        "[BOOT] EL2:        refused: no PSCI conduit with more than one CPU (split never degrades)",
    )
}

extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _rodata_start: u8;
    static _rodata_end: u8;
    static __ro_after_init_start: u8;
    static __ro_after_init_end: u8;
    fn _aarch64_secondary_entry();
}

/// The descriptor the monitor reads by physical address: a static, since a
/// stack has none (`virt_to_phys` refuses the stack window).
static mut LOCK_DESC: LockDesc = LockDesc {
    text: [0; 2], rodata: [0; 2], ro_after_init: [0; 2], ram: [[0; 2]; LOCK_RAM_MAX], nram: 0, secondary_entry: 0,
    sites: 0, nsites: 0,
};

/// The trace static keys' sites (aarch64 `b`/`nop`), the only text the
/// kernel rewrites after the lock, for the monitor's table.
static mut LOCK_SITES: [TextSite; TEXT_SITES_MAX] = [TextSite::ZERO; TEXT_SITES_MAX];

/// `text_poke`'s back end after the lock.
fn text_patch(pa: usize, word: u32) -> bool {
    monitor_call2(CALL_TEXT_PATCH, pa as u64, word as u64)[0] as i64 == OK
}

fn pa_of(va: usize) -> u64 { azos_mm::addr::virt_to_phys(va) as u64 }
const S2_PAGE: u64 = 4096;
fn down(a: u64) -> u64 { a & !(S2_PAGE - 1) }
fn up(a: u64) -> u64 { (a + S2_PAGE - 1) & !(S2_PAGE - 1) }

/// Arm this PE's pin (`CALL_PIN`): from here its writes to `SCTLR_EL1`,
/// `TCR_EL1` and `TTBR1_EL1` are refused. Called once the PE has made its own
/// last write to them, and after a power-down. `(mode, PEs pinned)`.
fn pin_this_pe() -> Option<(u64, u64)> {
    let r = monitor_call(CALL_PIN, 0);
    (r[0] as i64 == OK).then_some((r[1], r[2]))
}

fn pin_mode(mode: u64) -> &'static str {
    if mode == PIN_FGT { "fgt" } else { "tvm" }
}

/// A secondary or a resumed PE: pinned as it comes online.
pub(crate) fn pin_secondary(cpu: usize) {
    match pin_this_pe() {
        #[cfg(feature = "hyp-pin-probe")]
        Some((mode, _)) => kprintln!("[HYP] pin: PE {} pinned ({})", cpu, pin_mode(mode)),
        #[cfg(not(feature = "hyp-pin-probe"))]
        Some(_) => {}
        None => kprintln!("[BOOT] EL2:        PE {} could not be pinned", cpu),
    }
}

/// Ticks for `PIN_COST_WRITES` rewrites of this PE's `TTBR0_EL1` with the
/// value it holds, each followed by a local TLB flush, as an address-space
/// switch does.
#[cfg(feature = "hyp-pin-probe")]
const PIN_COST_WRITES: u64 = 256;
#[cfg(feature = "hyp-pin-probe")]
fn ttbr0_ticks() -> u64 {
    let root = azos_arch::sysregs::read_ttbr0_el1() as usize;
    let t0 = azos_drv_sys::timebase::now();
    for _ in 0..PIN_COST_WRITES {
        azos_arch::sysregs::install_ttbr0_flush_local(root);
    }
    azos_drv_sys::timebase::now() - t0
}
#[cfg(feature = "hyp-pin-probe")]
static UNPINNED_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

const _: () = assert!(KEY_ROOTS == azos_crypto::keystore::ROOTS && KEY_LEN == azos_crypto::keystore::KEY_LEN);

/// A page each root is written into before it is donated: nothing else lives
/// in it, and the kernel never touches it again.
#[repr(C, align(4096))]
struct RootPage([u8; 4096]);
static mut ROOT_PAGES: [RootPage; KEY_ROOTS] = [const { RootPage([0; 4096]) }; KEY_ROOTS];

/// The request of `key_derive`, in the kernel's memory (a stack has no
/// physical address), one at a time.
static DERIVE_REQ: azos_sync::SpinLock<DeriveReqBuf> = azos_sync::SpinLock::new(DeriveReqBuf(DeriveReq::ZERO));
struct DeriveReqBuf(DeriveReq);

fn root_page_pa(slot: usize) -> u64 {
    pa_of(core::ptr::addr_of!(ROOT_PAGES) as usize + slot * 4096)
}

/// Keep root `slot` in the monitor: write it to its page, donate the page,
/// name the root. The caller wipes its own copy. A refusal leaves no root.
fn vault_store(slot: usize, root: &[u8; KEY_LEN]) -> bool {
    if slot >= KEY_ROOTS {
        return false;
    }
    let pa = root_page_pa(slot);
    let page = (core::ptr::addr_of_mut!(ROOT_PAGES) as *mut u8).wrapping_add(slot * 4096);
    // SAFETY: the page is this slot's alone, written once before it is donated.
    unsafe { core::ptr::copy_nonoverlapping(root.as_ptr(), page, KEY_LEN) };
    if monitor_call2(CALL_GUARD_PAGES, pa, 1)[0] as i64 != OK {
        // SAFETY: still the kernel's page.
        unsafe { core::ptr::write_bytes(page, 0, KEY_LEN) };
        return false;
    }
    monitor_call2(CALL_KEY_ROOT_SET, slot as u64, pa)[0] as i64 == OK
}

/// `HKDF-SHA256(salt, ikm = root slot, info)` by the monitor.
fn vault_kdf(slot: usize, salt: &[u8], info: &[u8], out: &mut [u8; KEY_LEN]) -> bool {
    let Some(req) = DeriveReq::new(salt, info) else { return false };
    let mut buf = DERIVE_REQ.lock();
    buf.0 = req;
    let r = monitor_call5(CALL_KEY_DERIVE, slot as u64, pa_of(&buf.0 as *const DeriveReq as usize));
    if r[0] as i64 != OK {
        return false;
    }
    *out = words_to_out([r[1], r[2], r[3], r[4]]);
    true
}

/// The split image's line about the keystore: no root's bytes are the kernel's.
pub(crate) fn report_roots(in_kernel: usize) {
    kprintln!("[BOOT] EL2:        keystore roots held by the kernel: {}", in_kernel);
}

/// From here every keystore root goes to the monitor the moment it is
/// installed, and key derivation asks the monitor. Before the first root.
pub(crate) fn install_vault() {
    azos_syscall::keys::set_root_vault(vault_store, vault_kdf);
}

/// Lock the kernel image at stage 2: text read-only and the only memory EL1
/// executes, rodata read-only, the secondary entry fixed (I1, I2). Called
/// with one PE up, after the boot-once text rewrites and the livepatch rows,
/// before `ro_after_init` is sealed. Everything the boot parsed before here
/// (the devices, the disk, the topology) ran pre-lock.
pub(crate) fn lock_image() {
    // SAFETY: linker symbols, only their addresses taken; one PE runs, and the
    // static is written once before the monitor reads it.
    let r = unsafe {
        let span = |a: &u8, b: &u8| [down(pa_of(a as *const u8 as usize)), up(pa_of(b as *const u8 as usize))];
        let (ram_pa, ram_len) = azos_mm::pmm::managed_range();
        let d = &mut *core::ptr::addr_of_mut!(LOCK_DESC);
        d.text = span(&_text_start, &_text_end);
        d.rodata = span(&_rodata_start, &_rodata_end);
        d.ro_after_init = span(&__ro_after_init_start, &__ro_after_init_end);
        d.ram[0] = [down(ram_pa as u64), up((ram_pa + ram_len) as u64)];
        d.nram = 1;
        d.secondary_entry = pa_of(_aarch64_secondary_entry as *const () as usize);
        let sites = &mut *core::ptr::addr_of_mut!(LOCK_SITES);
        let mut n = 0;
        for s in azos_trace::key_sites().iter().filter(|s| s.key < 32 && s.kind == azos_trace::jump::KIND_A64_B) {
            let (Ok(off), Ok(on)) = (s.word(false), s.word(true)) else { continue };
            if n == TEXT_SITES_MAX { break; }
            sites[n] = TextSite { pa: pa_of(s.site as usize), off, on };
            n += 1;
        }
        d.sites = pa_of(core::ptr::addr_of!(LOCK_SITES) as usize);
        d.nsites = n as u64;
        monitor_call(CALL_LOCK_KERNEL_IMAGE, pa_of(core::ptr::addr_of!(LOCK_DESC) as usize))
    };
    if r[0] as i64 == OK {
        azos_mm::text_poke::set_word_hook(text_patch);
        // SAFETY: written once above, before the call.
        let n = unsafe { (*core::ptr::addr_of!(LOCK_DESC)).nsites };
        kprintln!("[BOOT] EL2:        kernel image locked (text, rodata; {} key sites)", n);
        #[cfg(feature = "hyp-pin-probe")]
        UNPINNED_TICKS.store(ttbr0_ticks(), core::sync::atomic::Ordering::Relaxed);
        match pin_this_pe() {
            Some((mode, n)) => kprintln!("[BOOT] EL2:        pinned ({}), {} PE", pin_mode(mode), n),
            None => kprintln!("[BOOT] EL2:        pin refused"),
        }
    } else {
        kprintln!("[BOOT] EL2:        kernel image lock refused ({})", r[0] as i64);
    }
}

/// `ro_after_init` read-only at stage 2, right after the stage-1 seal.
pub(crate) fn lock_ro_data() {
    let r = monitor_call(CALL_LOCK_RO_DATA, 0);
    if r[0] as i64 == OK {
        kprintln!("[BOOT] EL2:        ro_after_init locked");
    } else {
        kprintln!("[BOOT] EL2:        ro_after_init lock refused ({})", r[0] as i64);
    }
    report();
    #[cfg(feature = "hyp-lock-probe")]
    text_write_probe();
    #[cfg(feature = "hyp-key-flip-probe")]
    key_flip_probe();
    #[cfg(feature = "hyp-guard-probe")]
    guard_probe();
    #[cfg(feature = "hyp-pin-probe")]
    pin_probe();
    #[cfg(feature = "hyp-key-root-probe")]
    key_root_probe();
}

/// How many records of `kind` the ring holds.
#[cfg(any(feature = "hyp-guard-probe", feature = "hyp-pin-probe", feature = "hyp-key-root-probe"))]
fn ring_count(kind: azos_hyp_api::Kind) -> u32 {
    let (mut cursor, mut n) = (0, 0);
    loop {
        let w = monitor_call(azos_hyp_api::CALL_VIOLATION_READ, cursor);
        if w[0] as i64 != OK {
            return n;
        }
        cursor = w[1];
        if azos_hyp_api::Violation::from_words(w[2], 0, 0, 0).kind == kind as u32 {
            n += 1;
        }
    }
}

/// A page the guard probe donates: nothing else lives in it.
#[cfg(feature = "hyp-guard-probe")]
#[repr(C, align(4096))]
struct ProbePage([u8; 4096]);
#[cfg(feature = "hyp-guard-probe")]
static mut PROBE_PAGE: ProbePage = ProbePage([0xA5; 4096]);

/// Feature `hyp-guard-probe` (the `hyp: R8` rows): donate a page, then ask for
/// the same page, and for a page of kernel text, which the monitor must
/// refuse and record; then read the donated page, which must fault. Never in
/// a real build.
#[cfg(feature = "hyp-guard-probe")]
fn guard_probe() {
    use azos_hyp_api::{Kind, CALL_GUARD_PAGES, INV_GUARDED};
    // SAFETY: only the address is taken.
    let (page, text) = unsafe { (pa_of(core::ptr::addr_of!(PROBE_PAGE) as usize), down(pa_of(&_text_start as *const u8 as usize))) };
    let r = monitor_call2(CALL_GUARD_PAGES, page, 1)[0] as i64;
    let (again, over_text) = (monitor_call2(CALL_GUARD_PAGES, page, 1)[0] as i64, monitor_call2(CALL_GUARD_PAGES, text, 1)[0] as i64);
    if r != OK || again == OK || over_text == OK {
        kprintln!("[HYP] PROBE FAILED: guard_pages gave {} / {} / {}", r, again, over_text);
        return;
    }
    kprintln!("[HYP] guard: the page is donated, a second donation and a page of text are refused");
    let refused = ring_count(Kind::CallRefused);
    if refused >= 2 {
        kprintln!("[HYP] guard: the ring holds {} refusals", refused);
    } else {
        kprintln!("[HYP] PROBE FAILED: the ring holds {} refusals", refused);
    }
    if monitor_call(CALL_PROBE, 0)[2] & INV_GUARDED == 0 {
        kprintln!("[HYP] PROBE FAILED: probe does not report guarded");
        return;
    }
    kprintln!("[HYP] guard: reading the donated page (must fault)");
    // SAFETY: the probe's purpose is this read; it must not return.
    let b = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PROBE_PAGE) as *const u8) };
    kprintln!("[HYP] PROBE FAILED: the donated page read {:#x}", b);
}

/// Feature `hyp-key-flip-probe` (the `hyp: R7` rows): flip a trace class's
/// static keys and back through the monitor, then ask it to write a word that
/// is no site. Never in a real build.
#[cfg(feature = "hyp-key-flip-probe")]
fn key_flip_probe() {
    let prev = azos_ipc::trace::set_mask(azos_trace::mask() ^ 1);
    let _ = azos_ipc::trace::set_mask(prev);
    kprintln!("[HYP] key flip through the monitor: done");
    let pa = pa_of(_aarch64_secondary_entry as *const () as usize) as usize;
    if text_patch(pa, 0xd503_201f) {
        kprintln!("[HYP] PROBE FAILED: text_patch wrote a word that is no site");
    } else {
        kprintln!("[HYP] text_patch of a non-site refused");
    }
}

/// Feature `hyp-lock-probe` (the `hyp: R4` rows): map a page of kernel text
/// writable at stage 1 and write it. Stage 2 must refuse: the boot dies in
/// the kernel page-fault path. Never in a real build.
#[cfg(feature = "hyp-lock-probe")]
fn text_write_probe() {
    use azos_arch_api::PagePerms;
    let kpt = azos_mm::vmm::kernel_pagetable();
    // SAFETY: a linker symbol; only its address is taken.
    let text_pa = down(pa_of(unsafe { &_text_start as *const u8 as usize })) as usize;
    let va = azos_mm::kstack::first_guard() & !(azos_arch::PAGE_SIZE - 1);
    if azos_mm::vmm::map(kpt, va, text_pa, PagePerms::KERNEL_RW).is_err() {
        kprintln!("[HYP] PROBE FAILED: no alias for the text page");
        return;
    }
    kprintln!("[HYP] PROBE: writing kernel text through a stage-1 RW alias (must fault)");
    // SAFETY: the probe's purpose is this write; it must not return.
    unsafe { core::ptr::write_volatile(va as *mut u8, 0) };
    kprintln!("[HYP] PROBE FAILED: kernel text written after the lock");
}

/// Feature `hyp-pin-probe` (the `hyp: R9` rows): write `TCR_EL1` and `SCTLR_EL1`
/// (a harmless bit of each) and read them back, which the pin must have
/// refused and put in the ring; write `TTBR0_EL1`, which must work; and time
/// `PIN_COST_WRITES` of those against the same before the pin. Never in a real
/// build.
#[cfg(feature = "hyp-pin-probe")]
fn pin_probe() {
    use azos_arch::sysregs::{read_sctlr_el1, read_tcr_el1, read_ttbr0_el1, write_sctlr_el1, write_tcr_el1};
    use azos_hyp_api::{Kind, INV_PINNED};
    if monitor_call(CALL_PROBE, 0)[2] & INV_PINNED == 0 {
        kprintln!("[HYP] PROBE FAILED: probe does not report pinned");
    }
    let before = ring_count(Kind::SysregRefused);
    if before != 0 {
        kprintln!("[HYP] PROBE FAILED: boot wrote a pinned register after the pin ({} refused)", before);
        return;
    }
    // TCR_EL1.TBI0 and SCTLR_EL1.UCT: nothing the kernel runs on depends on either.
    let (tcr, sctlr) = (read_tcr_el1(), read_sctlr_el1());
    write_tcr_el1(tcr ^ (1 << 37));
    let tcr_kept = read_tcr_el1() == tcr;
    write_sctlr_el1(sctlr ^ (1 << 15));
    let sctlr_kept = read_sctlr_el1() == sctlr;
    if !tcr_kept {
        write_tcr_el1(tcr);
        kprintln!("[HYP] PROBE FAILED: the TCR_EL1 write took effect");
    } else {
        kprintln!("[HYP] pin: TCR_EL1 write refused");
    }
    if !sctlr_kept {
        write_sctlr_el1(sctlr);
        kprintln!("[HYP] PROBE FAILED: the SCTLR_EL1 write took effect");
    } else {
        kprintln!("[HYP] pin: SCTLR_EL1 write refused");
    }
    let held = ring_count(Kind::SysregRefused) - before;
    if tcr_kept && sctlr_kept && held == 2 {
        kprintln!("[HYP] pin: the ring holds {} sysreg refusals", held);
    } else if tcr_kept && sctlr_kept {
        kprintln!("[HYP] PROBE FAILED: the ring holds {} sysreg refusals, not 2", held);
    }
    let ttbr0 = read_ttbr0_el1();
    azos_arch::sysregs::install_ttbr0_flush_local(ttbr0 as usize);
    if read_ttbr0_el1() == ttbr0 {
        kprintln!("[HYP] pin: TTBR0_EL1 write works");
    } else {
        kprintln!("[HYP] PROBE FAILED: the TTBR0_EL1 write was lost");
    }
    let (unpinned, pinned) = (UNPINNED_TICKS.load(core::sync::atomic::Ordering::Relaxed), ttbr0_ticks());
    kprintln!("[HYP] cost: {} TTBR0 writes took {} ticks unpinned, {} pinned", PIN_COST_WRITES, unpinned, pinned);
    if pinned > unpinned + unpinned / 2 {
        kprintln!("[HYP] cost: the TTBR0 trap is visible");
    }
}

/// Feature `hyp-key-root-probe` (the `hyp: R8` keystore rows): install a root
/// through the keystore, which the monitor takes; have the monitor derive from
/// it and compare with the same HKDF run here on the root the probe kept; ask
/// for a derive over the root's own page, which must be refused and recorded;
/// then read the root's page, which must fault. Never in a real build.
#[cfg(feature = "hyp-key-root-probe")]
fn key_root_probe() {
    use azos_crypto::keystore::Backend;
    use azos_hyp_api::{Kind, INV_KEY_ROOTS};
    let root: [u8; KEY_LEN] = core::array::from_fn(|i| 0xC3 ^ i as u8);
    // A root nothing installed at boot.
    let Some((backend, slot)) =
        [(Backend::Volume, 2usize), (Backend::TpmNv, 1)].into_iter().find(|(b, _)| !azos_syscall::keys::has_root(*b))
    else {
        kprintln!("[HYP] PROBE FAILED: every root slot is taken");
        return;
    };
    if !azos_syscall::keys::install_root(backend, &root) {
        kprintln!("[HYP] PROBE FAILED: the monitor did not take the root");
        return;
    }
    if monitor_call(CALL_PROBE, 0)[2] & INV_KEY_ROOTS == 0 {
        kprintln!("[HYP] PROBE FAILED: probe does not report key-roots");
    }
    let (salt, info): ([u8; 20], [u8; 54]) = (*b"azos keystore key v1", core::array::from_fn(|i| i as u8));
    let (mut got, mut want) = ([0u8; KEY_LEN], [0u8; KEY_LEN]);
    let derived = vault_kdf(slot, &salt, &info, &mut got);
    if derived && azos_crypto::hkdf::hkdf(&salt, &root, &info, &mut want) && got == want {
        kprintln!("[HYP] keys: the monitor derives the key the kernel would");
    } else {
        kprintln!("[HYP] PROBE FAILED: the monitor derived another key ({})", derived);
    }
    let before = ring_count(Kind::CallRefused);
    let r = monitor_call5(CALL_KEY_DERIVE, slot as u64, root_page_pa(slot));
    if r[0] as i64 != OK && ring_count(Kind::CallRefused) == before + 1 {
        kprintln!("[HYP] keys: a request over the root's own page is refused and recorded");
    } else {
        kprintln!("[HYP] PROBE FAILED: a request over the root's page gave {}", r[0] as i64);
    }
    kprintln!("[HYP] keys: reading the vaulted root (must fault)");
    // SAFETY: the probe's purpose is this read; it must not return.
    let b = unsafe { core::ptr::read_volatile((core::ptr::addr_of!(ROOT_PAGES) as usize + slot * 4096) as *const u8) };
    kprintln!("[HYP] PROBE FAILED: the vaulted root read {:#x}", b);
}
