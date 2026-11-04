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
pub mod stage2;

use crate::state::HYP;
use azos_hyp_api::{Kind, INV_HOST_S2};
use core::sync::atomic::{AtomicU64, Ordering};
use stage2::{S2Attrs, Stage2, TableMem, VtcrConfig};

/// Stage-2 table pool, carved in `.bss`. Enough for an identity map of RAM
/// with 1 GiB/2 MiB blocks and the sub-gigabyte split around the monitor hole.
const POOL_TABLES: usize = 32;

#[repr(align(4096))]
struct Pool([[u64; 512]; POOL_TABLES]);
static mut POOL: Pool = Pool([[0; 512]; POOL_TABLES]);
static POOL_NEXT: AtomicU64 = AtomicU64::new(0);

struct PoolMem;

impl TableMem for PoolMem {
    fn alloc_tables(&mut self, tables: u64) -> Option<u64> {
        // Contiguous, each table its own 4 KiB alignment (the pool is aligned
        // and the tables are 4 KiB, so any run is aligned).
        let start = POOL_NEXT.fetch_add(tables, Ordering::AcqRel);
        if start + tables > POOL_TABLES as u64 {
            return None;
        }
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
pub unsafe fn build_and_enable(hole_pa: u64, hole_len: u64, ram_top: u64) {
    let parange = {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) v) };
        (v & 0xf) as u8
    };
    let cfg = match VtcrConfig::new(40, parange) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut mem = PoolMem;
    let mut s2 = match Stage2::new(cfg, &mut mem) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Permissive: everything RAM-attributed, read/write/execute. The hole is a
    // gap in the two runs, so a host access to the monitor aborts at stage 2.
    let hole_end = hole_pa + hole_len;
    let _ = s2.map_run(0, 0, hole_pa, S2Attrs::RAM);
    let _ = s2.map_run(hole_end, hole_end, ram_top.saturating_sub(hole_end), S2Attrs::RAM);
    if cfg!(feature = "hyp-hole-mapped-canary") {
        // R2 red: map the hole too, so EL1 can reach monitor memory.
        let _ = s2.map_run(hole_pa, hole_pa, hole_len, S2Attrs::RAM);
    }

    let (vttbr, vtcr) = match s2.registers(0) {
        Ok(r) => r,
        Err(_) => return,
    };
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
    HYP.set_invariant(INV_HOST_S2);
}

/// Stage-2 abort from EL1: record it and reflect a synchronous data/instruction
/// abort into EL1, so the kernel's own abort handler reports the refusal
/// (the attack never takes effect — the write never reached memory).
pub fn fault(_regs: *mut u64, esr: u64, is_instr: bool) {
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
