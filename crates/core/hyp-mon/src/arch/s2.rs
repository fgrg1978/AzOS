// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stage-2 (F2): a permissive identity map with the monitor's own memory
//! a hole, turned on with `HCR_EL2.VM`, plus the fault path that reflects a
//! stage-2 abort back to EL1 and records it. The restrictive text/rodata/table
//! mappings are added at the lock (F4).
//!
//! The stage-2 descriptor encoder and table mapper are the kernel's, shared by
//! source (`#[path]`) so the split image and the hosted stub cannot drift.

#[path = "../../../../../arch/aarch64/src/ext/hv/stage2.rs"]
#[allow(dead_code)] // reason: shared by source with the hosted stub (ext/hv), which uses the rest
pub mod stage2;

use crate::state::{SpinLock, HYP};
use azos_hyp_api::{
    bump_tables, cause, guard_error, latch_after, lock_desc_error, text_site_error, Guarded, Kind, LockDesc, TextSite, DENIED,
    GUARD_RANGES_MAX, INVALID, INV_EL1_EXEC_TEXT_ONLY, INV_GUARDED, INV_HOST_S2, INV_IMAGE_RO, INV_RO_DATA,
    LOCK_RAM_MAX, NOT_SUPPORTED, OK, TEXT_SITES_MAX,
};
use core::sync::atomic::{AtomicU64, Ordering};
use stage2::{ExecOnly, MemType, S2Attrs, Stage2, TableMem, VtcrConfig};

/// Stage-2 table pool, carved in `.bss`. Enough for an identity map of RAM
/// with 1 GiB/2 MiB blocks and the sub-gigabyte split around the monitor hole.
/// The boot map keeps blocks to 2 MiB over this span (two gigabytes from the one
/// holding the monitor), the biggest block there.
const SPLIT_WINDOW: u64 = 2 << 30;
const SPLIT_BLOCK: u64 = 2 << 20;

/// The boot map and the locked map, built side by side, and the tables the
/// block splits of `guard_pages` take.
const POOL_TABLES: usize = 80;

// 8 KiB: a 40-bit IPA root is two concatenated tables and must be aligned to its size.
#[repr(align(8192))]
struct Pool([[u64; 512]; POOL_TABLES]);
static mut POOL: Pool = Pool([[0; 512]; POOL_TABLES]);
static POOL_NEXT: AtomicU64 = AtomicU64::new(0);

struct PoolMem;

impl TableMem for PoolMem {
    fn alloc_tables(&mut self, tables: u64) -> Option<u64> {
        // Contiguous, a run aligned to its own size (the pool is 8 KiB aligned).
        let start = bump_tables(&POOL_NEXT, tables, POOL_TABLES as u64)?;
        Some(unsafe { core::ptr::addr_of!(POOL.0[start as usize]) as u64 })
    }

    fn read(&self, entry_pa: u64) -> u64 {
        unsafe { core::ptr::read_volatile(entry_pa as *const u64) }
    }

    fn write(&mut self, entry_pa: u64, desc: u64) {
        unsafe { core::ptr::write_volatile(entry_pa as *mut u64, desc) };
    }
}

/// Build a permissive identity stage-2 over `[0, ram_top)` with the monitor's
/// image `[hole_pa, hole_pa + hole_len)` left unmapped (I1/I4), and turn stage
/// 2 on. Primary only, before any secondary enables it.
///
/// # Safety
/// Called once at EL2 with the EL2 stage-1 already on.
/// The monitor's own range, the boot map's config, and the locked map's root
/// and `ro_after_init` range (0 until the lock).
static HOLE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static IPA_CFG: AtomicU64 = AtomicU64::new(0);
static BOOT_ROOT: AtomicU64 = AtomicU64::new(0);
static LOCKED_ROOT: AtomicU64 = AtomicU64::new(0);
/// Serializes everything that rewrites live stage-2 entries after the first
/// PE is up: the guard calls, and the fault path that waits for them.
static GUARD_LOCK: SpinLock = SpinLock::new();
/// What was donated, and the RAM the lock named (none before it). Both are
/// read and written under `GUARD_LOCK`.
static mut GUARDED: Guarded = Guarded::new();
static mut RAM: [[u64; 2]; LOCK_RAM_MAX] = [[0; 2]; LOCK_RAM_MAX];
static NRAM: AtomicU64 = AtomicU64::new(0);
static mut IMAGE: [[u64; 2]; 3] = [[0; 2]; 3];
static IMAGE_SET: AtomicU64 = AtomicU64::new(0);
/// The kernel VAs of the three image ranges, for the pool lock's walk.
static IMAGE_VA: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static RO_RANGE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static LOCK_ONCE: AtomicU64 = AtomicU64::new(0);
/// The sites the lock listed, sorted by PA (`NSITES` of them), and the text
/// range they were checked against.
static mut SITES: [TextSite; TEXT_SITES_MAX] = [TextSite::ZERO; TEXT_SITES_MAX];
static NSITES: AtomicU64 = AtomicU64::new(0);
static RO_ONCE: AtomicU64 = AtomicU64::new(0);

fn parange() -> u8 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) v) };
    (v & 0xf) as u8
}

/// FEAT_XNX (`ID_AA64MMFR1_EL1.XNX`, bits 31:28): stage 2 can split execute
/// by level. Without it user code would have to be executable at EL1 too.
fn has_xnx() -> bool {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, ID_AA64MMFR1_EL1", out(reg) v) };
    (v >> 28) & 0xf != 0
}

/// Record which setup step refused and give back `INVALID`.
fn fail(why: u64) -> i64 {
    record_setup(why);
    INVALID
}

fn record_setup(why: u64) {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
    crate::record(Kind::SetupFailed, (mpidr & 0xff) as u32, why, 0, 0);
}

/// This PE's stage-2 registers set to `vtcr`/`vttbr` and `HCR_EL2.VM` on, with
/// this PE's own TLB cleared. Per-PE state: every PE that runs the host needs it.
fn enable_on_this_pe(vtcr: u64, vttbr: u64) {
    unsafe {
        core::arch::asm!(
            "msr VTCR_EL2, {vtcr}",
            "msr VTTBR_EL2, {vttbr}",
            "isb",
            "tlbi vmalls12e1",
            "dsb nsh",
            "isb",
            "mrs {t}, HCR_EL2",
            "orr {t}, {t}, {vm}",
            "msr HCR_EL2, {t}",
            "isb",
            vtcr = in(reg) vtcr,
            vttbr = in(reg) vttbr,
            vm = in(reg) 1u64, // HCR_EL2.VM
            t = out(reg) _,
        );
    }
}

/// Set once a PE other than the first has attached; the lock is refused after,
/// because its `install` reaches this PE's registers only on the PE that runs it.
static ATTACHED: AtomicU64 = AtomicU64::new(0);

/// Put the host stage 2 that is live now (the locked map once there is one)
/// on this PE, before EL1 runs here: a secondary coming up, or any PE coming
/// back from a power-down. Without it the PE runs the kernel with `HCR_EL2.VM`
/// clear and none of the stage-2 invariants hold on it. Canary
/// `hyp-secondary-s2-canary`: the attach is skipped.
pub fn attach_host_s2() {
    if cfg!(feature = "hyp-secondary-s2-canary") { return; }
    // Under the lock: the root read here cannot be replaced before this PE has it.
    GUARD_LOCK.lock();
    ATTACHED.store(1, Ordering::Release);
    let root = active_root();
    let regs = match s2_cfg() {
        Some(cfg) if root != 0 => {
            let mut mem = PoolMem;
            Stage2::attach(cfg, root, &mut mem).registers(0).ok()
        }
        _ => None,
    };
    GUARD_LOCK.unlock();
    // No map to attach (the boot PE's build failed): this PE must not run the host unconfined.
    let Some((vtcr, vttbr)) = regs else {
        loop {
            // SAFETY: parks this PE.
            unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
        }
    };
    enable_on_this_pe(vtcr, vttbr);
}

fn install(vttbr: u64, vtcr: u64) {
    unsafe {
        core::arch::asm!(
            "msr VTCR_EL2, {vtcr}",
            "msr VTTBR_EL2, {vttbr}",
            "isb",
            "tlbi vmalls12e1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) vtcr,
            vttbr = in(reg) vttbr,
        );
    }
}

// Canary `hyp-text-rw-canary`: text stays writable after the lock.
const TEXT: S2Attrs = S2Attrs { read: true, write: cfg!(feature = "hyp-text-rw-canary"), exec: true, mem: MemType::NormalWb, only: ExecOnly::El1 };
const RODATA: S2Attrs = S2Attrs { read: true, write: false, exec: false, mem: MemType::NormalWb, only: ExecOnly::Both };
const USER_RAM: S2Attrs = S2Attrs { read: true, write: true, exec: true, mem: MemType::NormalWb, only: ExecOnly::El0 };
/// A redistributor's first frame: readable, a write traps to `its::rd_write`.
const RD_RO: S2Attrs = S2Attrs { read: true, write: false, exec: false, mem: MemType::DeviceNgnre, only: ExecOnly::Both };
const RO_DATA_RW: S2Attrs = S2Attrs { read: true, write: true, exec: false, mem: MemType::NormalWb, only: ExecOnly::Both };

/// `lock_kernel_image(desc_pa)`: build the locked map beside the boot one
/// and switch to it. Refused after a first use, with a second PE up, without
/// FEAT_XNX, or with a descriptor `lock_desc_error` refuses.
pub fn lock_kernel_image(desc_pa: u64) -> i64 {
    GUARD_LOCK.lock();
    let r = lock_locked(desc_pa);
    GUARD_LOCK.unlock();
    r
}

fn lock_locked(desc_pa: u64) -> i64 {
    let mut taken = None;
    // The latch is taken once the descriptor and the site table are accepted: a
    // refusal for what the kernel passed leaves the lock free for a corrected call.
    if let Some(e) = latch_after(&LOCK_ONCE, || {
        if crate::PES_UP.load(Ordering::Acquire) > 1 || ATTACHED.load(Ordering::Acquire) != 0 { return Some(DENIED); }
        if !has_xnx() { return Some(NOT_SUPPORTED); }
        // SAFETY: the EL2 identity map covers RAM; the kernel is trusted until the lock.
        let d: LockDesc = unsafe { core::ptr::read_volatile(desc_pa as *const LockDesc) };
        let (hole, hole_end) = (HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed));
        // SAFETY: under `GUARD_LOCK`.
        let guarded = unsafe { *core::ptr::addr_of!(GUARDED) };
        if lock_desc_error(&d, hole, hole_end, guarded.as_slice()).is_some() { record_setup(cause::LOCK_DESC); return Some(INVALID); }
        // The site table, copied into the monitor before anything is locked.
        let n = d.nsites as usize;
        // SAFETY: one PE runs (checked above); the copy is the monitor's own.
        let sites = unsafe { &mut *core::ptr::addr_of_mut!(SITES) };
        for (i, slot) in sites.iter_mut().enumerate().take(n) {
            // SAFETY: the EL2 identity map covers RAM; the array is the kernel's, pre-lock.
            *slot = unsafe { core::ptr::read_volatile((d.sites as *const TextSite).add(i)) };
            if text_site_error(slot, d.text).is_some() { record_setup(cause::LOCK_SITE); return Some(INVALID); }
        }
        sites[..n].sort_unstable_by_key(|s| s.pa);
        NSITES.store(n as u64, Ordering::Release);
        taken = Some(d);
        None
    }) {
        return e;
    }
    let Some(d) = taken else { return DENIED };
    let (hole, hole_end) = (HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed));
    // SAFETY: under `GUARD_LOCK`.
    let guarded = unsafe { *core::ptr::addr_of!(GUARDED) };
    let cfg = match VtcrConfig::new(40, parange()) { Ok(c) => c, Err(_) => return fail(cause::LOCK_VTCR) };
    let mut mem = PoolMem;
    let mut s2 = match Stage2::new(cfg, &mut mem) { Ok(s) => s, Err(_) => return fail(cause::LOCK_ROOT) };
    let top = 1u64 << cfg.ipa_bits();
    // Devices: everything below, between and above the RAM ranges.
    let mut ram = d.ram;
    ram[..d.nram as usize].sort_unstable_by_key(|r| r[0]);
    let mut at = 0u64;
    for r in ram[..d.nram as usize].iter() {
        if r[0] > at && s2.map_run(at, at, r[0] - at, S2Attrs::MMIO).is_err() { return fail(cause::LOCK_DEVICE_MAP); }
        at = at.max(r[1]);
    }
    if at < top && s2.map_run(at, at, top - at, S2Attrs::MMIO).is_err() { return fail(cause::LOCK_DEVICE_MAP); }
    // RAM: cut around the monitor, the guarded pages and the three locked
    // ranges. An unused slot is the empty range 0..0, which no RAM run meets.
    let mut cuts: [(u64, u64, Option<S2Attrs>); 4 + GUARD_RANGES_MAX] = [(0, 0, None); 4 + GUARD_RANGES_MAX];
    cuts[..4].copy_from_slice(&[(hole, hole_end, None), (d.text[0], d.text[1], Some(TEXT)),
                                (d.rodata[0], d.rodata[1], Some(RODATA)), (d.ro_after_init[0], d.ro_after_init[1], Some(RO_DATA_RW))]);
    for (slot, g) in cuts[4..].iter_mut().zip(guarded.as_slice()) { *slot = (g[0], g[1], None); }
    cuts.sort_unstable_by_key(|c| c.0);
    for r in ram[..d.nram as usize].iter() {
        let mut p = r[0];
        for &(lo, hi, a) in cuts.iter() {
            if hi <= p || lo >= r[1] { continue; }
            if lo > p && s2.map_run(p, p, lo - p, USER_RAM).is_err() { return fail(cause::LOCK_RAM_MAP); }
            if let Some(a) = a {
                let ok = if a == RO_DATA_RW {
                    // Pages, so `lock_ro_data` rewrites them in place.
                    let mut q = lo;
                    let mut ok = true;
                    while q < hi { ok &= s2.map_page(q, q, a).is_ok(); q += stage2::S2_PAGE; }
                    ok
                } else {
                    s2.map_run(lo, lo, hi - lo, a).is_ok()
                };
                if !ok { return fail(cause::LOCK_RO_PAGES); }
            }
            p = hi;
        }
        if p < r[1] && s2.map_run(p, p, r[1] - p, USER_RAM).is_err() { return fail(cause::LOCK_RAM_MAP); }
    }
    // The SMMU's registers are the monitor's alone from here.
    let (wlo, whi) = super::smmu::window();
    if !cfg!(feature = "hyp-smmu-window-canary") {
        let mut q = wlo;
        while q < whi {
            if s2.split_to_page(q, &mut |_| ()).is_err() || s2.unmap_page(q).is_err() { return fail(cause::LOCK_SMMU_WINDOW); }
            q += stage2::S2_PAGE;
        }
    }
    // The ITS is the monitor's alone: its control frame goes, and each
    // redistributor's first frame is read-only (`its::rd_write` carries out a
    // write that is not an LPI table pointer).
    let (ilo, ihi) = super::its::ctl_window();
    let (rd, stride, ncpu) = super::its::rd_frames();
    if !cfg!(feature = "hyp-its-window-canary") {
        let mut q = ilo;
        while q < ihi {
            if s2.split_to_page(q, &mut |_| ()).is_err() || s2.unmap_page(q).is_err() { return fail(cause::LOCK_ITS_WINDOW); }
            q += stage2::S2_PAGE;
        }
    }
    if !cfg!(feature = "hyp-rd-open-canary") {
        for cpu in 0..ncpu {
            let mut q = rd + cpu * stride;
            while q < rd + cpu * stride + 0x1_0000 {
                if s2.split_to_page(q, &mut |_| ()).is_err() || s2.set_page_attrs(q, RD_RO).is_err() { return fail(cause::LOCK_RD_FRAMES); }
                q += stage2::S2_PAGE;
            }
        }
    }
    let (vtcr, vttbr) = match s2.registers(0) { Ok(r) => r, Err(_) => return fail(cause::LOCK_REGISTERS) };
    LOCKED_ROOT.store(s2.root(), Ordering::Release);
    IPA_CFG.store(parange() as u64, Ordering::Relaxed);
    // SAFETY: under `GUARD_LOCK`.
    unsafe {
        *core::ptr::addr_of_mut!(RAM) = d.ram;
        *core::ptr::addr_of_mut!(IMAGE) = [d.text, d.rodata, d.ro_after_init];
    }
    for (slot, va) in IMAGE_VA.iter().zip(d.va) { slot.store(va, Ordering::Relaxed); }
    NRAM.store(d.nram, Ordering::Release);
    IMAGE_SET.store(1, Ordering::Release);
    RO_RANGE[0].store(d.ro_after_init[0], Ordering::Relaxed);
    RO_RANGE[1].store(d.ro_after_init[1], Ordering::Relaxed);
    HYP.set_legal_entry(d.secondary_entry);
    install(vttbr, vtcr);
    HYP.set_invariant(INV_IMAGE_RO | INV_EL1_EXEC_TEXT_ONLY);
    super::smmu::locked(vtcr, s2.root());
    super::its::locked();
    OK
}

/// `lock_ro_data()`: the `ro_after_init` pages the lock mapped become
/// read-only. One-shot, after `lock_kernel_image`.
pub fn lock_ro_data() -> i64 {
    let root = LOCKED_ROOT.load(Ordering::Acquire);
    if root == 0 || RO_ONCE.swap(1, Ordering::AcqRel) != 0 { return DENIED; }
    let cfg = match VtcrConfig::new(40, IPA_CFG.load(Ordering::Relaxed) as u8) { Ok(c) => c, Err(_) => return INVALID };
    let mut mem = PoolMem;
    let mut s2 = Stage2::attach(cfg, root, &mut mem);
    let (lo, hi) = (RO_RANGE[0].load(Ordering::Relaxed), RO_RANGE[1].load(Ordering::Relaxed));
    let mut q = lo;
    while q < hi {
        if s2.set_page_attrs(q, RODATA).is_err() { return INVALID; }
        q += stage2::S2_PAGE;
    }
    unsafe { core::arch::asm!("dsb ishst", "tlbi vmalls12e1is", "dsb ish", "isb") };
    HYP.set_invariant(INV_RO_DATA);
    OK
}

/// Run `f` on what was donated and the monitor's own range, with `guard_pages`
/// held off.
pub fn with_guard<R>(f: impl FnOnce(&Guarded, u64, u64) -> R) -> R {
    GUARD_LOCK.lock();
    // SAFETY: under `GUARD_LOCK`.
    let r = f(unsafe { &*core::ptr::addr_of!(GUARDED) }, HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed));
    GUARD_LOCK.unlock();
    r
}

/// Like [`with_guard`], with the RAM the lock named (empty before it).
pub fn with_guard_ram<R>(f: impl FnOnce(&Guarded, &[[u64; 2]], u64, u64) -> R) -> R {
    GUARD_LOCK.lock();
    // SAFETY: under `GUARD_LOCK`.
    let r = unsafe {
        let ram = &*core::ptr::addr_of!(RAM);
        f(&*core::ptr::addr_of!(GUARDED), &ram[..NRAM.load(Ordering::Acquire) as usize], HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed))
    };
    GUARD_LOCK.unlock();
    r
}

/// The locked image ranges (text, rodata, `ro_after_init`); empty ranges before the lock.
pub fn image() -> [[u64; 2]; 3] {
    if IMAGE_SET.load(Ordering::Acquire) == 0 { return [[0; 2]; 3]; }
    // SAFETY: written once at the lock, before `IMAGE_SET` was published.
    unsafe { *core::ptr::addr_of!(IMAGE) }
}

/// The kernel VAs of the image ranges the lock named (text, rodata, `ro_after_init`).
pub fn image_va() -> [u64; 3] {
    [IMAGE_VA[0].load(Ordering::Relaxed), IMAGE_VA[1].load(Ordering::Relaxed), IMAGE_VA[2].load(Ordering::Relaxed)]
}

/// The monitor's own range.
pub fn monitor_range() -> (u64, u64) {
    (HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed))
}

/// The `VTCR_EL2` and the root of the stage 2 the host runs on now, which a
/// stream's stage 2 shares.
pub fn host_s2() -> Option<(u64, u64)> {
    let cfg = s2_cfg()?;
    match active_root() {
        0 => None,
        root => Some((cfg.value(), root)),
    }
}

/// Has `lock_kernel_image` built the locked map?
pub fn locked() -> bool {
    LOCKED_ROOT.load(Ordering::Acquire) != 0
}

/// The root the live stage-2 walks: the locked map once there is one.
fn active_root() -> u64 {
    match LOCKED_ROOT.load(Ordering::Acquire) {
        0 => BOOT_ROOT.load(Ordering::Acquire),
        r => r,
    }
}

fn s2_cfg() -> Option<VtcrConfig> {
    VtcrConfig::new(40, IPA_CFG.load(Ordering::Relaxed) as u8).ok()
}

/// Drop every cached stage-1 and stage-2 translation of the host, on all PEs,
/// and wait for it.
fn flush_host() {
    unsafe { core::arch::asm!("dsb ishst", "tlbi vmalls12e1is", "dsb ish", "isb") };
    super::smmu::host_s2_changed();
}

/// `guard_pages(pa, n)`: unmap `n` pages from the host stage-2, for good. A
/// block that holds them is split with break-before-make first; a PE that
/// walks through the entry meanwhile takes a translation fault, which `fault`
/// retries once this call has let go of `GUARD_LOCK`. Refused when the pages
/// are not RAM, overlap the monitor or a page already guarded, or the table
/// pool cannot cover the splits. Canary `hyp-guard-skip-canary`: everything
/// but the unmap.
pub fn guard_pages(pa: u64, n: u64) -> i64 {
    GUARD_LOCK.lock();
    let r = guard_locked(pa, n);
    GUARD_LOCK.unlock();
    r
}

fn guard_locked(pa: u64, n: u64) -> i64 {
    let root = active_root();
    let Some(cfg) = s2_cfg() else { return DENIED };
    if root == 0 { return DENIED; }
    let (hole, hole_end) = (HOLE[0].load(Ordering::Relaxed), HOLE[1].load(Ordering::Relaxed));
    // SAFETY: under `GUARD_LOCK`.
    let (guarded, ram, image) = unsafe {
        (&mut *core::ptr::addr_of_mut!(GUARDED), &*core::ptr::addr_of!(RAM), &*core::ptr::addr_of!(IMAGE))
    };
    let ram = &ram[..NRAM.load(Ordering::Acquire) as usize];
    let image = &image[..3 * IMAGE_SET.load(Ordering::Acquire) as usize];
    if guard_error(pa, n, ram, image, hole, hole_end, super::pt::pool_range(), guarded).is_some() { return INVALID; }
    // A 2 MiB table and a 1 GiB table per 2 MiB the range touches, at most.
    let splits = 2 * (n.div_ceil(512) + 1);
    if POOL_NEXT.load(Ordering::Acquire) + splits > POOL_TABLES as u64 { return NOT_SUPPORTED; }
    let end = pa + n * stage2::S2_PAGE;
    if !guarded.add(pa, end) { return NOT_SUPPORTED; }
    if !cfg!(feature = "hyp-guard-skip-canary") {
        let mut mem = PoolMem;
        let mut s2 = Stage2::attach(cfg, root, &mut mem);
        let mut broke = |_ipa: u64| flush_host();
        let mut q = pa;
        while q < end {
            if s2.split_to_page(q, &mut broke).is_err() || s2.unmap_page(q).is_err() {
                guarded.pop();
                flush_host();
                return INVALID;
            }
            q += stage2::S2_PAGE;
        }
        flush_host();
    }
    HYP.set_invariant(INV_GUARDED);
    OK
}

/// `len` bytes at `pa` become read-only for the host, splitting the blocks that
/// hold them. The pool's tables are written from EL2 alone from here on, and
/// the walker's accesses to them stay reads (the leaves carry AF).
pub fn pool_read_only(pa: u64, len: u64) -> i64 {
    GUARD_LOCK.lock();
    let r = pool_read_only_locked(pa, len);
    GUARD_LOCK.unlock();
    r
}

fn pool_read_only_locked(pa: u64, len: u64) -> i64 {
    let root = active_root();
    let Some(cfg) = s2_cfg() else { return DENIED };
    if root == 0 { return DENIED; }
    let splits = 2 * (len.div_ceil(2 << 20) + 1);
    if POOL_NEXT.load(Ordering::Acquire) + splits > POOL_TABLES as u64 { return NOT_SUPPORTED; }
    let mut mem = PoolMem;
    let mut s2 = Stage2::attach(cfg, root, &mut mem);
    let mut broke = |_ipa: u64| flush_host();
    let mut q = pa;
    while q < pa + len {
        if s2.split_to_page(q, &mut broke).is_err() || s2.set_page_attrs(q, RODATA).is_err() {
            flush_host();
            return INVALID;
        }
        q += stage2::S2_PAGE;
    }
    flush_host();
    OK
}

/// A translation fault on an address a guard call is remapping around: the
/// entry was invalid for the length of one break-before-make. Taking
/// `GUARD_LOCK` waits for the call, and a page that translates again after it
/// is retried, not recorded.
fn transient(esr: u64, ipa: u64) -> bool {
    if esr & 0x3c != 0x04 { return false; }
    let Some(cfg) = s2_cfg() else { return false };
    GUARD_LOCK.lock();
    let root = active_root();
    let mut mem = PoolMem;
    let live = root != 0 && Stage2::attach(cfg, root, &mut mem).translate(ipa).is_some();
    GUARD_LOCK.unlock();
    live
}

pub unsafe fn build_and_enable(hole_pa: u64, hole_len: u64, ram_top: u64) {
    HOLE[0].store(hole_pa, Ordering::Relaxed);
    HOLE[1].store(hole_pa + hole_len, Ordering::Relaxed);
    let parange = {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) v) };
        (v & 0xf) as u8
    };
    let cfg = match VtcrConfig::new(40, parange) {
        Ok(c) => c,
        Err(_) => return record_setup(cause::BOOT_VTCR),
    };
    let mut mem = PoolMem;
    let mut s2 = match Stage2::new(cfg, &mut mem) {
        Ok(s) => s,
        Err(_) => return record_setup(cause::BOOT_ROOT),
    };

    // Permissive: everything RAM-attributed, read/write/execute. The hole is a
    // gap in the two runs, so a host access to the monitor aborts at stage 2.
    // Around the monitor, which sits in the kernel image, no block bigger than
    // 2 MiB: a `guard_pages` before the lock then breaks one 2 MiB block, not a
    // gigabyte a stream with DMA in flight may be using.
    let hole_end = hole_pa + hole_len;
    let win_lo = hole_pa & !(SPLIT_WINDOW / 2 - 1);
    let win_hi = (win_lo + SPLIT_WINDOW).min(ram_top);
    let _ = s2.map_run(0, 0, win_lo, S2Attrs::RAM);
    let _ = s2.map_run_max(win_lo, win_lo, hole_pa - win_lo, S2Attrs::RAM, SPLIT_BLOCK);
    let _ = s2.map_run_max(hole_end, hole_end, win_hi.saturating_sub(hole_end), S2Attrs::RAM, SPLIT_BLOCK);
    let _ = s2.map_run(win_hi, win_hi, ram_top.saturating_sub(win_hi), S2Attrs::RAM);
    if cfg!(feature = "hyp-hole-mapped-canary") {
        // R2 red: map the hole too, so EL1 can reach monitor memory.
        let _ = s2.map_run(hole_pa, hole_pa, hole_len, S2Attrs::RAM);
    }

    let (vtcr, vttbr) = match s2.registers(0) {
        Ok(r) => r,
        Err(_) => return record_setup(cause::BOOT_REGISTERS),
    };
    BOOT_ROOT.store(s2.root(), Ordering::Release);
    IPA_CFG.store(parange as u64, Ordering::Relaxed);
    enable_on_this_pe(vtcr, vttbr);
    HYP.set_invariant(INV_HOST_S2);
}

/// Stage-2 abort from EL1: record it and reflect a synchronous data/instruction
/// abort into EL1, so the kernel's own abort handler reports the refusal
/// (the attack never takes effect — the write never reached memory).
pub fn fault(regs: *mut u64, esr: u64, is_instr: bool) {
    let far: u64;
    let hpfar: u64;
    let elr: u64;
    let spsr: u64;
    unsafe {
        core::arch::asm!("mrs {}, FAR_EL2", out(reg) far);
        core::arch::asm!("mrs {}, HPFAR_EL2", out(reg) hpfar);
        core::arch::asm!("mrs {}, ELR_EL2", out(reg) elr);
        core::arch::asm!("mrs {}, SPSR_EL2", out(reg) spsr);
    }
    // Faulting IPA: HPFAR holds bits [47:12] of the IPA, plus the page offset
    // of FAR.
    let ipa = ((hpfar & !0xf) << 8) | (far & 0xfff);
    if transient(esr, ipa) { return; }
    if !is_instr && super::its::rd_write(regs, esr, ipa) { return; }
    let pe = {
        let mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
        (mpidr & 0xff) as u32
    };
    crate::record(Kind::Stage2Fault, pe, esr, ipa, elr);
    reflect_to_el1(elr, spsr, far, is_instr);
}

/// Reflect the abort into EL1: set EL1's fault registers and redirect the
/// `eret` to EL1's own synchronous vector (`VBAR_EL1 + 0x200`, current EL with
/// SPx). The kernel then takes an ordinary EL1 abort at the offending PC.
fn reflect_to_el1(elr: u64, spsr: u64, far: u64, is_instr: bool) {
    // ESR_EL1 for a stage-1-looking abort: EC = IABORT/DABORT at current EL,
    // a permission fault (DFSC/IFSC = 0b001111), far valid.
    let ec: u64 = if is_instr { 0x21 } else { 0x25 };
    let esr_el1 = (ec << 26) | 0b001111;
    let vbar: u64;
    unsafe {
        core::arch::asm!("mrs {}, VBAR_EL1", out(reg) vbar);
        core::arch::asm!("msr FAR_EL1, {}", in(reg) far);
        core::arch::asm!("msr ESR_EL1, {}", in(reg) esr_el1);
        core::arch::asm!("msr ELR_EL1, {}", in(reg) elr);
        core::arch::asm!("msr SPSR_EL1, {}", in(reg) spsr);
        // Redirect this eret: resume EL1 at its sync-SPx vector, EL1h/DAIF masked.
        core::arch::asm!("msr ELR_EL2, {}", in(reg) vbar + 0x200);
        core::arch::asm!("msr SPSR_EL2, {}", in(reg) 0x3C5u64);
    }
}

/// `text_patch(pa, word)`: one of a listed site's two forms, written from EL2
/// (stage 2 does not apply here) and made visible to instruction fetch.
/// Canary `hyp-text-site-skip-canary`: any word anywhere in text.
pub fn text_patch(pa: u64, word: u64) -> i64 {
    if LOCKED_ROOT.load(Ordering::Acquire) == 0 { return DENIED; }
    let n = NSITES.load(Ordering::Acquire) as usize;
    // SAFETY: written once, at the lock, before NSITES was published.
    let sites: &[TextSite] = unsafe { &*core::ptr::slice_from_raw_parts(core::ptr::addr_of!(SITES) as *const TextSite, n) };
    let ok = match sites.binary_search_by_key(&pa, |s| s.pa) {
        Ok(i) => word as u32 as u64 == word && (word as u32 == sites[i].off || word as u32 == sites[i].on),
        Err(_) => false,
    };
    if !ok && !cfg!(feature = "hyp-text-site-skip-canary") { return DENIED; }
    // SAFETY: a 4-aligned text word (checked at the lock), mapped at EL2 by
    // the identity map.
    unsafe {
        core::ptr::write_volatile(pa as *mut u32, word as u32);
        core::arch::asm!("dc cvau, {p}", "dsb ish", "ic ivau, {p}", "dsb ish", "isb", p = in(reg) pa);
    }
    OK
}