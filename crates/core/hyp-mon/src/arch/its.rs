// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The GICv3 ITS as the monitor's. The GIC masters memory without the host
//! stage-2 in the way: the LPI tables, the ITS tables and queue are physical
//! addresses it is given, and a MAPD command names the ITT it writes. So the
//! monitor holds all of them: it programs the ITS and the first redistributor
//! itself, with tables of its own, and issues the commands the kernel asks for
//! (`map_device`, `map_vector`), checking what each names. From the lock the
//! ITS control frame is unmapped from the host, and each redistributor's first
//! 64 KiB is read-only: a write to it is carried out here, except the two LPI
//! table pointers.
//!
//! Registers, commands and table encodings are the kernel driver's
//! (`gic_fmt.rs`, by path). The GIC lies below 1 GiB, where the monitor's own
//! map is Device.

#[path = "../../../../../arch/aarch64/src/irq/gic_fmt.rs"]
#[allow(dead_code)] // reason: shared by source with the kernel drivers, which use the rest
mod fmt;

use crate::state::{SpinLock, HYP};
use azos_hyp_api::{
    its_init_error, its_vector_error, mmio_store, rd_write_refused, Kind, DENIED, INVALID, INV_ITS, ITS_DEVICES_MAX,
    ITS_EVENTS_MAX, NOT_SUPPORTED, OK,
};
use core::sync::atomic::{AtomicU64, Ordering};
use fmt::*;

const ITS_MAX_SPINS: u32 = 1_000_000;
/// `log2(ITS_EVENTS_MAX) - 1`, the `id_bits` MAPD programs.
const EVENT_ID_BITS_MINUS1: u8 = 2;
/// An ITT entry is at most this many bytes (checked against nothing: the
/// kernel driver's own bound).
const ITT_ENTRY_BYTES_CAP: usize = 32;
const ITT_BYTES: usize = ITS_EVENTS_MAX as usize * ITT_ENTRY_BYTES_CAP;
const FRAME: u64 = 0x1_0000;

#[repr(C, align(4096))]
struct Page([u8; 4096]);
#[repr(C, align(256))]
#[derive(Clone, Copy)]
struct Itt([u8; ITT_BYTES]);
#[repr(C, align(4096))]
struct Prop([u8; lpi_prop_table_size(LPI_ID_BITS)]);
#[repr(C, align(65536))]
struct Pend([u8; 65536]);

static mut CMDQ: Page = Page([0; 4096]);
static mut DEVTAB: Page = Page([0; 4096]);
static mut COLTAB: Page = Page([0; 4096]);
static mut ITTS: [Itt; ITS_DEVICES_MAX as usize] = [Itt([0; ITT_BYTES]); ITS_DEVICES_MAX as usize];
static mut PROP: Prop = Prop([0; lpi_prop_table_size(LPI_ID_BITS)]);
static mut PEND: Pend = Pend([0; 65536]);

struct State {
    its: u64,
    rd: u64,
    stride: u64,
    ncpu: u64,
    wr: usize,
    target: u64,
    ndev: u64,
    devs: [u32; ITS_DEVICES_MAX as usize],
}

static LOCK: SpinLock = SpinLock::new();
static mut ST: State = State { its: 0, rd: 0, stride: 0, ncpu: 0, wr: 0, target: 0, ndev: 0, devs: [0; ITS_DEVICES_MAX as usize] };
static UP: AtomicU64 = AtomicU64::new(0);

fn pa<T>(p: *const T) -> u64 {
    p as u64
}

fn r32(a: u64) -> u32 {
    // SAFETY: a register of the GIC, mapped Device in the monitor's map.
    unsafe { core::ptr::read_volatile(a as *const u32) }
}
fn r64(a: u64) -> u64 {
    // SAFETY: as `r32`.
    unsafe { core::ptr::read_volatile(a as *const u64) }
}
fn w32(a: u64, v: u32) {
    // SAFETY: as `r32`.
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}
fn w64(a: u64, v: u64) {
    // SAFETY: as `r32`.
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..ITS_MAX_SPINS {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn submit(st: &mut State, cmd: ItsCommand) {
    // SAFETY: the monitor's queue page; `wr` is a multiple of 32 below 4096.
    unsafe {
        let q = (core::ptr::addr_of_mut!(CMDQ) as *mut u64).add(st.wr / 8);
        for (i, w) in cmd.iter().enumerate() {
            core::ptr::write_volatile(q.add(i), *w);
        }
        core::arch::asm!("dsb ishst");
    }
    st.wr = (st.wr + 32) % 4096;
    w64(st.its + regs::GITS_CWRITER as u64, st.wr as u64);
}

/// `SYNC`, then wait for `GITS_CREADR` to reach what was written (bounded).
fn drain(st: &mut State) -> bool {
    submit(st, cmd_sync(st.target));
    let (its, wr) = (st.its, st.wr as u64);
    wait_for(|| r64(its + regs::GITS_CREADR as u64) == wr)
}

/// `its_init`: before the lock, once.
pub fn init(its_base: u64, rd_base: u64, a3: u64) -> i64 {
    let (stride, ncpu) = (a3 & 0xffff_ffff, a3 >> 32);
    let (hole, hole_end) = super::s2::monitor_range();
    if its_init_error(its_base, rd_base, stride, ncpu, hole, hole_end).is_some() {
        return INVALID;
    }
    LOCK.lock();
    let r = init_locked(its_base, rd_base, stride, ncpu);
    LOCK.unlock();
    r
}

fn init_locked(its: u64, rd: u64, stride: u64, ncpu: u64) -> i64 {
    if UP.load(Ordering::Acquire) != 0 || super::s2::locked() {
        return DENIED;
    }
    // The pending table's address field is 64 KiB aligned: the blob is placed so.
    let (prop_pa, pend_pa) = (pa(core::ptr::addr_of!(PROP)), pa(core::ptr::addr_of!(PEND)));
    if pend_pa % FRAME != 0 {
        return NOT_SUPPORTED;
    }
    // SAFETY: under `LOCK`, before the ITS is up.
    let st = unsafe { &mut *core::ptr::addr_of_mut!(ST) };
    *st = State { its, rd, stride, ncpu, wr: 0, target: 0, ndev: 0, devs: [0; ITS_DEVICES_MAX as usize] };
    let ctlr = its + regs::GITS_CTLR as u64;
    if !wait_for(|| r32(ctlr) & regs::GITS_CTLR_QUIESCENT != 0) {
        return NOT_SUPPORTED;
    }
    let typer = r64(its + regs::GITS_TYPER as u64);
    if !typer_plpis(typer) {
        return NOT_SUPPORTED;
    }
    let hcc = typer_hcc(typer);
    w64(its + regs::GITS_CBASER as u64, cbaser_value(pa(core::ptr::addr_of!(CMDQ)), 0, true));
    w64(its + regs::GITS_CWRITER as u64, 0);
    // The slot whose reset `Type` is `ty` takes `table` (found, never assumed).
    let give = |ty: u8, table: u64, entries: usize| -> bool {
        for n in 0..8u64 {
            let off = its + regs::GITS_BASER0 as u64 + n * 8;
            let reset = r64(off);
            if baser_type(reset) != ty {
                continue;
            }
            if entries * baser_entry_size(reset) as usize > 4096 {
                return false;
            }
            w64(off, baser_value(reset, table, 0, true));
            return true;
        }
        false
    };
    if !give(BASER_TYPE_DEVICE, pa(core::ptr::addr_of!(DEVTAB)), ITS_DEVICES_MAX as usize) {
        return NOT_SUPPORTED;
    }
    if hcc == 0 && !give(BASER_TYPE_COLLECTION, pa(core::ptr::addr_of!(COLTAB)), 1) {
        return NOT_SUPPORTED;
    }
    w32(ctlr, r32(ctlr) | regs::GITS_CTLR_ENABLE);
    // LPIs on the first redistributor.
    w64(rd + GICR_PROPBASER_OFF as u64, propbaser_value(prop_pa, LPI_ID_BITS));
    w64(rd + GICR_PENDBASER_OFF as u64, pendbaser_value(pend_pa, true));
    if !wait_for(|| r32(rd) & GICR_CTLR_RWP == 0) {
        return NOT_SUPPORTED;
    }
    w32(rd, r32(rd) | GICR_CTLR_ENABLE_LPIS);
    let rd_typer = r64(rd + 0x0008);
    st.target = if typer_pta(typer) {
        collection_target_rdbase(rd)
    } else {
        collection_target_cpu_number(((rd_typer >> 8) & 0xffff) as u16)
    };
    submit(st, cmd_mapc(0, st.target, true));
    submit(st, cmd_invall(0));
    if !drain(st) {
        return NOT_SUPPORTED;
    }
    UP.store(1, Ordering::Release);
    OK
}

/// `its_map_device`.
pub fn map_device(dev: u64) -> Result<u64, i64> {
    if UP.load(Ordering::Acquire) == 0 {
        return Err(DENIED);
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let st = unsafe { &mut *core::ptr::addr_of_mut!(ST) };
    let r = if st.ndev >= ITS_DEVICES_MAX || dev > u32::MAX as u64 {
        Err(INVALID)
    } else {
        let slot = st.ndev;
        st.devs[slot as usize] = dev as u32;
        st.ndev += 1;
        let itt = pa(core::ptr::addr_of!(ITTS) as *const Itt) + slot * ITT_BYTES as u64;
        submit(st, cmd_mapd(dev as u32, EVENT_ID_BITS_MINUS1, itt, true));
        if drain(st) { Ok(slot) } else { Err(DENIED) }
    };
    LOCK.unlock();
    r
}

/// `its_map_vector(slot | event << 32, lpi)`.
pub fn map_vector(a1: u64, lpi: u64) -> i64 {
    if UP.load(Ordering::Acquire) == 0 {
        return DENIED;
    }
    LOCK.lock();
    // SAFETY: under `LOCK`.
    let st = unsafe { &mut *core::ptr::addr_of_mut!(ST) };
    let (slot, event) = (a1 & 0xffff_ffff, a1 >> 32);
    let lpi_hi = 1u64 << (LPI_ID_BITS as u32 + 1);
    let r = if its_vector_error(st.ndev, slot, event, lpi, LPI_INTID_BASE as u64, lpi_hi).is_some() {
        INVALID
    } else {
        let dev = st.devs[slot as usize];
        // Enable the LPI in the configuration table before the ITS can deliver
        // it, then MAPTI, then INV so the redistributor re-reads the entry.
        // SAFETY: `lpi` is inside the table (checked above).
        unsafe {
            let b = (core::ptr::addr_of_mut!(PROP) as *mut u8).add((lpi - LPI_INTID_BASE as u64) as usize);
            core::ptr::write_volatile(b, lpi_config_byte(LPI_DEFAULT_PRIORITY, true));
            core::arch::asm!("dsb ishst");
        }
        // Canary `hyp-its-skip-mapti-canary`: the event never resolves to the LPI.
        if !cfg!(feature = "hyp-its-skip-mapti-canary") {
            submit(st, cmd_mapti(dev, event as u32, lpi as u32, 0));
        }
        submit(st, cmd_inv(dev, event as u32));
        if drain(st) { OK } else { DENIED }
    };
    LOCK.unlock();
    r
}

/// The ITS control frame the lock unmaps from the host (empty: no ITS).
pub fn ctl_window() -> (u64, u64) {
    if UP.load(Ordering::Acquire) == 0 {
        return (0, 0);
    }
    // SAFETY: written once, before `UP`.
    let its = unsafe { (*core::ptr::addr_of!(ST)).its };
    (its, its + FRAME)
}

/// The redistributors' first frames the lock makes read-only: base, stride, count.
pub fn rd_frames() -> (u64, u64, u64) {
    if UP.load(Ordering::Acquire) == 0 {
        return (0, 0, 0);
    }
    // SAFETY: as `ctl_window`.
    let st = unsafe { &*core::ptr::addr_of!(ST) };
    (st.rd, st.stride, st.ncpu)
}

/// The lock protected the GIC.
pub fn locked() {
    if UP.load(Ordering::Acquire) != 0 && !cfg!(feature = "hyp-its-window-canary") && !cfg!(feature = "hyp-rd-open-canary") {
        HYP.set_invariant(INV_ITS);
    }
}

/// A write the host made to a read-only redistributor frame: carried out
/// unless it aims a LPI table pointer. `true` when it was handled here (the
/// store emulated or refused), `false` for any other abort.
pub fn rd_write(regs: *mut u64, esr: u64, ipa: u64) -> bool {
    if UP.load(Ordering::Acquire) == 0 {
        return false;
    }
    // SAFETY: written once, before `UP`.
    let st = unsafe { &*core::ptr::addr_of!(ST) };
    let in_frame = ipa >= st.rd
        && (ipa - st.rd) / st.stride < st.ncpu
        && (ipa - st.rd) % st.stride < FRAME;
    let Some((size, rt)) = mmio_store(esr).filter(|_| in_frame) else { return false };
    // SAFETY: `regs` holds x0..x30 as the vector saved them; Rt 31 is XZR.
    let value = if rt == 31 { 0 } else { unsafe { *regs.add(rt as usize) } };
    if rd_write_refused((ipa - st.rd) / st.stride, (ipa - st.rd) % st.stride, value) {
        let mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
        crate::record(Kind::MmioRefused, (mpidr & 0xff) as u32, esr, ipa, value);
    } else {
        // SAFETY: a register of the redistributor, Device in the monitor's map.
        unsafe {
            match size {
                1 => core::ptr::write_volatile(ipa as *mut u8, value as u8),
                2 => core::ptr::write_volatile(ipa as *mut u16, value as u16),
                4 => core::ptr::write_volatile(ipa as *mut u32, value as u32),
                _ => core::ptr::write_volatile(ipa as *mut u64, value),
            }
        }
    }
    // SAFETY: steps this PE's return address past the trapped store.
    unsafe { core::arch::asm!("mrs {t}, ELR_EL2", "add {t}, {t}, #4", "msr ELR_EL2, {t}", t = out(reg) _) };
    true
}
