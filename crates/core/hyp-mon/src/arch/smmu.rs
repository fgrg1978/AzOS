// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SMMUv3 as the monitor's: it brings the unit up with its own stream
//! table and queues, writes every Stream Table Entry itself and gives each one
//! the host's stage 2 (shared with the CPUs), so a stream reaches no memory
//! the host stage-2 does not map: not the image, not the monitor, not guarded
//! pages. The kernel keeps stage 1: a Context Descriptor of its own that the
//! entry names. From the lock the unit's registers are unmapped from the host,
//! so the kernel cannot turn it off or aim its queues or table elsewhere.
//!
//! Registers and entry layouts are the kernel driver's (`smmuv3_fmt.rs`, by
//! path). The unit lies below 1 GiB, where the monitor's own map is Device.

#[path = "../../../../drivers/iommu/src/smmuv3_fmt.rs"]
#[allow(dead_code)] // reason: shared by source with the kernel driver, which uses the rest
mod fmt;

use crate::state::{SpinLock, HYP};
use azos_hyp_api::{
    smmu_attach_error, smmu_init_error, DENIED, INVALID, INV_SMMU, NOT_SUPPORTED, OK, SMMU_BLOCK, SMMU_NESTED, SMMU_S2_ONLY,
    SMMU_STREAMS_MAX,
};
use core::sync::atomic::{AtomicU64, Ordering};
use fmt::*;

/// Polls a handshake waits before it calls the unit dead.
const POLL: u32 = 2_000_000;
const CMDQ_LOG2_MAX: u32 = 8;
const EVTQ_LOG2_MAX: u32 = 7;
const OVFLG: u32 = 1 << 31;
const CONS_ERR_MASK: u32 = 0x7f << 24;
const IDR0_S2P: u32 = 1 << 0;
const IDR5_GRAN4K: u32 = 1 << 4;

#[repr(C, align(16384))]
struct StreamTable([u64; SMMU_STREAMS_MAX as usize * STE_DWORDS]);
#[repr(C, align(4096))]
struct QueuePage([u64; 512]);

static mut STRTAB: StreamTable = StreamTable([0; SMMU_STREAMS_MAX as usize * STE_DWORDS]);
static mut CMDQ: QueuePage = QueuePage([0; 512]);
static mut EVTQ: QueuePage = QueuePage([0; 512]);

struct Unit {
    base: u64,
    nstreams: u64,
    cmdq_log2: u32,
    evtq_log2: u32,
    prod: u32,
    evt_cons: u32,
}

static LOCK: SpinLock = SpinLock::new();
static mut UNIT: Unit = Unit { base: 0, nstreams: 0, cmdq_log2: 0, evtq_log2: 0, prod: 0, evt_cons: 0 };
static UP: AtomicU64 = AtomicU64::new(0);
static WINDOW: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static LOCKED: AtomicU64 = AtomicU64::new(0);

fn pa<T>(p: *const T) -> u64 {
    p as u64
}

/// Make `[addr, addr + len)` visible to a unit that does not snoop the CPU's
/// caches, and wait.
fn clean(addr: u64, len: u64) {
    let mut a = addr & !15;
    while a < addr + len {
        // SAFETY: cache maintenance by VA on memory the monitor owns.
        unsafe { core::arch::asm!("dc civac, {a}", a = in(reg) a) };
        a += 16;
    }
    unsafe { core::arch::asm!("dsb sy") };
}

fn r32(u: &Unit, off: usize) -> u32 {
    // SAFETY: the unit's registers, mapped Device in the monitor's map.
    unsafe { core::ptr::read_volatile((u.base + off as u64) as *const u32) }
}

fn w32(u: &Unit, off: usize, v: u32) {
    // SAFETY: as `r32`.
    unsafe { core::ptr::write_volatile((u.base + off as u64) as *mut u32, v) }
}

fn w64(u: &Unit, off: usize, v: u64) {
    // SAFETY: as `r32`.
    unsafe { core::ptr::write_volatile((u.base + off as u64) as *mut u64, v) }
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..POLL {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn command(u: &mut Unit, cmd: [u64; 2]) -> bool {
    let size = 1u32 << u.cmdq_log2;
    let wrap = (size << 1) - 1;
    let full = |u: &Unit| (u.prod ^ r32(u, REG_CMDQ_CONS)) & wrap == size;
    if full(u) {
        let ok = wait_for(|| !full(u));
        if !ok {
            return false;
        }
    }
    let slot = (u.prod & (size - 1)) as usize * 2;
    // SAFETY: the monitor's queue page; `slot` is inside it.
    unsafe {
        let q = core::ptr::addr_of_mut!(CMDQ.0) as *mut u64;
        core::ptr::write_volatile(q.add(slot), cmd[0]);
        core::ptr::write_volatile(q.add(slot + 1), cmd[1]);
        clean(pa(q.add(slot)), 16);
    }
    u.prod = (u.prod + 1) & wrap;
    w32(u, REG_CMDQ_PROD, u.prod);
    true
}

/// `CMD_SYNC`, then wait for the queue to pass it (bounded).
fn sync(u: &mut Unit) -> bool {
    if !command(u, cmd_sync()) {
        return false;
    }
    let (size, target) = (1u32 << u.cmdq_log2, u.prod);
    let wrap = (size << 1) - 1;
    let ok = wait_for(|| {
        let c = r32(u, REG_CMDQ_CONS);
        c & CONS_ERR_MASK != 0 || c & wrap == target
    });
    ok && r32(u, REG_CMDQ_CONS) & CONS_ERR_MASK == 0
}

fn ste_ptr(sid: u64) -> *mut u64 {
    // SAFETY: `sid` is below the table's size (checked by the callers).
    unsafe { (core::ptr::addr_of_mut!(STRTAB.0) as *mut u64).add(sid as usize * STE_DWORDS) }
}

/// `smmu_init`: before the lock, once.
pub fn init(base: u64, size: u64, max_sid: u64) -> Result<u64, i64> {
    let (hole, hole_end) = super::s2::monitor_range();
    if smmu_init_error(base, size, max_sid, hole, hole_end).is_some() {
        return Err(INVALID);
    }
    LOCK.lock();
    let r = init_locked(base, size, max_sid);
    LOCK.unlock();
    r
}

fn init_locked(base: u64, size: u64, max_sid: u64) -> Result<u64, i64> {
    if UP.load(Ordering::Acquire) != 0 || super::s2::locked() {
        return Err(DENIED);
    }
    // SAFETY: under `LOCK`, before the unit is up.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    *u = Unit { base, nstreams: 0, cmdq_log2: 0, evtq_log2: 0, prod: 0, evt_cons: 0 };
    let (idr0, idr1, idr5) = (r32(u, REG_IDR0), r32(u, REG_IDR1), r32(u, REG_IDR5));
    // Both stages: a stream is stage 1 of the kernel under stage 2 of the host.
    if idr0 & IDR0_S1P == 0 || idr0 & IDR0_S2P == 0 || idr5 & IDR5_GRAN4K == 0 {
        return Err(NOT_SUPPORTED);
    }
    if idr0 & IDR0_TTF_MASK & IDR0_TTF_AARCH64 == 0 || idr1 & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET) != 0 {
        return Err(NOT_SUPPORTED);
    }
    let strtab_log2 = 32 - (max_sid.max(1) as u32).leading_zeros();
    let cmdq_log2 = ((idr1 >> 21) & 0x1f).min(CMDQ_LOG2_MAX);
    let evtq_log2 = ((idr1 >> 16) & 0x1f).min(EVTQ_LOG2_MAX);
    if strtab_log2 > idr1 & 0x3f || cmdq_log2 < 2 || evtq_log2 < 2 {
        return Err(NOT_SUPPORTED);
    }
    w32(u, REG_CR0, 0);
    if !wait_for(|| r32(u, REG_CR0ACK) == 0) {
        return Err(NOT_SUPPORTED);
    }
    w32(u, REG_CR1, CR1);
    w32(u, REG_CR2, CR2_PTM | CR2_RECINVSID);
    w32(u, REG_IRQ_CTRL, 0);
    let (strtab, cmdq, evtq) = (
        pa(core::ptr::addr_of!(STRTAB)),
        pa(core::ptr::addr_of!(CMDQ)),
        pa(core::ptr::addr_of!(EVTQ)),
    );
    // The unit writes the event queue: no dirty zero lines over its records.
    clean(evtq, 4096);
    clean(strtab, STE_BYTES << strtab_log2);
    w64(u, REG_STRTAB_BASE, strtab & 0x000f_ffff_ffff_ffc0);
    w32(u, REG_STRTAB_BASE_CFG, strtab_log2);
    w64(u, REG_CMDQ_BASE, (cmdq & 0x000f_ffff_ffff_ffe0) | cmdq_log2 as u64);
    w32(u, REG_CMDQ_PROD, 0);
    w32(u, REG_CMDQ_CONS, 0);
    w32(u, REG_CR0, CR0_CMDQEN);
    if !wait_for(|| r32(u, REG_CR0ACK) & CR0_CMDQEN != 0) {
        return Err(NOT_SUPPORTED);
    }
    u.nstreams = 1 << strtab_log2;
    u.cmdq_log2 = cmdq_log2;
    u.evtq_log2 = evtq_log2;
    if !(command(u, cmd_cfgi_all()) && command(u, cmd_tlbi_nsnh_all()) && sync(u)) {
        return Err(NOT_SUPPORTED);
    }
    w64(u, REG_EVTQ_BASE, (evtq & 0x000f_ffff_ffff_ffe0) | evtq_log2 as u64);
    w32(u, REG_EVTQ_PROD, 0);
    w32(u, REG_EVTQ_CONS, 0);
    w32(u, REG_CR0, CR0_CMDQEN | CR0_EVTQEN);
    if !wait_for(|| r32(u, REG_CR0ACK) & CR0_EVTQEN != 0) {
        return Err(NOT_SUPPORTED);
    }
    w32(u, REG_CR0, CR0_CMDQEN | CR0_EVTQEN | CR0_SMMUEN);
    if !wait_for(|| r32(u, REG_CR0ACK) & CR0_SMMUEN != 0) {
        return Err(NOT_SUPPORTED);
    }
    WINDOW[0].store(base, Ordering::Release);
    WINDOW[1].store(base + size, Ordering::Release);
    UP.store(1, Ordering::Release);
    Ok((idr5 & 7) as u64)
}

/// The register window the lock unmaps from the host (empty: no unit).
pub fn window() -> (u64, u64) {
    (WINDOW[0].load(Ordering::Acquire), WINDOW[1].load(Ordering::Acquire))
}

/// `smmu_attach`.
pub fn attach(sid: u64, mode: u64, cd_pa: u64) -> i64 {
    if UP.load(Ordering::Acquire) == 0 {
        return DENIED;
    }
    // SAFETY: `nstreams` is written once, before `UP`.
    let nstreams = unsafe { (*core::ptr::addr_of!(UNIT)).nstreams };
    let bad = super::s2::with_guard_ram(|g, ram, hole, hole_end| {
        smmu_attach_error(nstreams, sid, mode, cd_pa, ram, hole, hole_end, g).is_some()
    });
    if bad {
        return INVALID;
    }
    let Some((vtcr, root)) = super::s2::host_s2() else { return DENIED };
    let ste = match mode {
        SMMU_BLOCK => [0u64; STE_DWORDS],
        SMMU_S2_ONLY => encode_ste_s2(vtcr, root, 0),
        SMMU_NESTED => encode_ste_s2(vtcr, root, cd_pa),
        _ => return INVALID,
    };
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    let slot = ste_ptr(sid);
    let mut ok = true;
    // SAFETY: the stream's entry in the monitor's table; the unit reads it.
    unsafe {
        if core::ptr::read_volatile(slot) & STE_V != 0 {
            core::ptr::write_volatile(slot, 0);
            clean(pa(slot), 8);
            ok = command(u, cmd_cfgi_ste(sid as u32)) && sync(u);
        }
        // Dwords 1.. first, dword 0 (V and Config) last.
        for (i, w) in ste.iter().enumerate().skip(1) {
            core::ptr::write_volatile(slot.add(i), *w);
        }
        clean(pa(slot), STE_BYTES);
        core::ptr::write_volatile(slot, ste[0]);
        clean(pa(slot), 8);
    }
    ok = ok && command(u, cmd_cfgi_ste(sid as u32)) && command(u, cmd_tlbi_nh_all(0)) && sync(u);
    LOCK.unlock();
    if ok { OK } else { DENIED }
}

/// `smmu_flush`: the kernel's stage 1 changed; drop what the unit cached.
pub fn flush(sid: u64) -> i64 {
    if UP.load(Ordering::Acquire) == 0 {
        return DENIED;
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    let ok = sid < u.nstreams
        && command(u, cmd_cfgi_cd_all(sid as u32))
        && command(u, cmd_tlbi_nh_all(0))
        && sync(u);
    LOCK.unlock();
    if ok { OK } else { INVALID }
}

/// `smmu_event`: the oldest record, `[dword 0, dword 1, dword 2]`.
pub fn event() -> Option<[u64; 3]> {
    if UP.load(Ordering::Acquire) == 0 {
        return None;
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    let size = 1u32 << u.evtq_log2;
    let wrap = (size << 1) - 1;
    let prod = r32(u, REG_EVTQ_PROD);
    let out = if u.evt_cons != prod & wrap {
        let rec = pa(core::ptr::addr_of!(EVTQ)) + (u.evt_cons & (size - 1)) as u64 * 32;
        // SAFETY: a record of the monitor's queue page.
        unsafe {
            core::arch::asm!("dc ivac, {a}", "dsb sy", a = in(reg) rec);
            let w = rec as *const u64;
            let r = [core::ptr::read_volatile(w), core::ptr::read_volatile(w.add(1)), core::ptr::read_volatile(w.add(2))];
            u.evt_cons = (u.evt_cons + 1) & wrap;
            // Acknowledge an overflow by echoing the flag back in CONS.
            w32(u, REG_EVTQ_CONS, u.evt_cons | (prod & OVFLG));
            Some(r)
        }
    } else {
        None
    };
    LOCK.unlock();
    out
}

/// The host's stage 2 changed under the streams: drop the unit's copies of it.
pub fn host_s2_changed() {
    if UP.load(Ordering::Acquire) == 0 {
        return;
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    let _ = command(u, cmd_tlbi_s12_vmall(0)) && sync(u);
    LOCK.unlock();
}

/// The lock built the host's final stage 2: every live stream moves onto it,
/// and the unit's registers are the monitor's alone.
pub fn locked(_vtcr: u64, root: u64) {
    if UP.load(Ordering::Acquire) == 0 {
        return;
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    for sid in 0..u.nstreams {
        let slot = ste_ptr(sid);
        // SAFETY: the stream's entry; a translating one gets the new root in
        // its one dword (the control `VTCR` is the same).
        unsafe {
            let cfg = (core::ptr::read_volatile(slot) >> 1) & 7;
            if core::ptr::read_volatile(slot) & STE_V != 0 && (cfg == STE_CFG_S2_TRANS || cfg == STE_CFG_NESTED) {
                core::ptr::write_volatile(slot.add(3), root & STE3_S2TTB_MASK);
                clean(pa(slot.add(3)), 8);
            }
        }
    }
    let _ = command(u, cmd_cfgi_all()) && command(u, cmd_tlbi_s12_vmall(0)) && sync(u);
    LOCK.unlock();
    LOCKED.store(1, Ordering::Release);
    if !cfg!(feature = "hyp-smmu-window-canary") {
        HYP.set_invariant(INV_SMMU);
    }
}
