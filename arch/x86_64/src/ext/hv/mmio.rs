// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory-mapped I/O of an x86 guest: finding out what the instruction that
//! faulted in the nested page tables was doing.
//!
//! RISC-V (`htinst`) and Arm (`ESR_EL2.ISV`) hand the monitor a decoded
//! access. SVM does not: a nested page fault gives the guest-physical address
//! and the kind of access, and the instruction is the monitor's to read and
//! decode. [`fetch`] gets its bytes (the CPU's decode assist when it left
//! them in the VMCB, else the guest's memory at `CS:RIP` through the guest's
//! own page tables, [`GuestMem`]) and [`decode`] reads them.
//!
//! The decoder knows the **MOV family** and nothing else:
//!
//! | bytes | instruction |
//! |-------|-------------|
//! | `88`, `89` | `mov r/m, r` (a store of 1, then 2, 4 or 8 bytes) |
//! | `8A`, `8B` | `mov r, r/m` (a load) |
//! | `C6 /0`, `C7 /0` | `mov r/m, imm` |
//! | `0F B6`, `0F B7` | `movzx r, r/m8`, `r/m16` |
//! | `0F BE`, `0F BF` | `movsx r, r/m8`, `r/m16` |
//! | `63` with `REX.W` | `movsxd r64, r/m32` |
//!
//! with the legacy prefixes (`66` operand size, `67` address size, the
//! segment overrides, which are ignored: the address is the fault's) and
//! `REX`. That is what a compiler emits for `read_volatile` /
//! `write_volatile` of an integer, which is how a driver touches a register.
//! Anything else (string instructions, a read-modify-write, `LOCK`, SIMD) is
//! `None`, and the vCPU stops on the fault visibly instead of being answered
//! with a guess.
//!
//! Pure: the host tests feed it encodings written out from the SDM (vol. 2
//! chapter 2, the ModRM and SIB tables).

use super::svm::{cr0, cr4, efer, off, GuestRegs, Vmcb};

/// A register or memory the monitor can read guest bytes from.
pub trait GuestMem {
    /// Fill `buf` from guest-physical `gpa`; `false` if any of it is not RAM.
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool;
}

/// The longest x86 instruction.
pub const MAX_INSN: usize = 15;

/// `VMCB` decode assist: the number of bytes fetched (`0xD0`) and the bytes
/// (`0xD1`..), on a CPU that records them for a nested page fault.
pub const OFF_INSN_LEN: usize = 0xD0;
pub const OFF_INSN_BYTES: usize = 0xD1;

/// What the guest was executing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// 64-bit mode (`EFER.LMA` with `CS.L`).
    Long,
    /// 32-bit protected mode (`CS.D`).
    Prot32,
}

impl Mode {
    /// The mode `vmcb` is in, if it is one the decoder knows (not real mode,
    /// not 16-bit protected mode).
    pub fn of(vmcb: &Vmcb) -> Option<Mode> {
        let attrib = vmcb.segment(off::CS).1;
        let (l, d) = (attrib >> 9 & 1 != 0, attrib >> 10 & 1 != 0);
        if vmcb.rd64(off::CR0) & cr0::PE == 0 {
            return None;
        }
        if vmcb.rd64(off::EFER) & efer::LMA != 0 && l {
            Some(Mode::Long)
        } else if d {
            Some(Mode::Prot32)
        } else {
            None
        }
    }
}

/// How a loaded value reaches the destination register.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Extend {
    /// `mov`: the access size is the register size.
    Move,
    /// `movzx`.
    Zero,
    /// `movsx`, `movsxd`.
    Sign,
}

/// One decoded access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Insn {
    /// Bytes of the instruction: how far to advance `RIP` once it is emulated.
    pub len: u8,
    pub write: bool,
    /// Bytes the access moves: 1, 2, 4 or 8.
    pub size: u8,
    /// The general register operand, in encoding order: `rax rcx rdx rbx rsp
    /// rbp rsi rdi r8..r15`.
    pub reg: u8,
    /// The register is `AH`/`CH`/`DH`/`BH` (an 8-bit operand 4..7 without `REX`);
    /// `reg` is then the full register's number (0..3).
    pub high8: bool,
    /// Bytes of the register a load writes: 1, 2, 4 or 8.
    pub dest: u8,
    pub extend: Extend,
    /// A store of an immediate (`reg` is then not read).
    pub imm: Option<u64>,
}

/// The mask of the low `bytes` bytes.
pub const fn mask(bytes: u8) -> u64 {
    if bytes >= 8 { u64::MAX } else { (1u64 << (bytes as u32 * 8)) - 1 }
}

/// Decode the instruction at the start of `code`.
pub fn decode(code: &[u8], mode: Mode) -> Option<Insn> {
    let at = |i: usize| code.get(i).copied();
    let (mut i, mut opsize16, mut addr67, mut rex) = (0usize, false, false, 0u8);
    loop {
        match at(i)? {
            0x66 => opsize16 = true,
            0x67 => addr67 = true,
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {}
            // LOCK, REPNE, REP: not on a MOV.
            0xF0 | 0xF2 | 0xF3 => return None,
            b @ 0x40..=0x4F if mode == Mode::Long => {
                rex = b;
                i += 1;
                break;
            }
            _ => break,
        }
        i += 1;
    }
    // 16-bit addressing (a `67` prefix in 32-bit mode) has another ModRM layout.
    if mode == Mode::Prot32 && addr67 {
        return None;
    }
    let w = rex & 8 != 0;
    let opsize: u8 = if w { 8 } else if opsize16 { 2 } else { 4 };
    let op = at(i)?;
    i += 1;
    // (store, access size, destination size, extend, immediate size, `/0` required)
    let (write, size, dest, extend, imm, slash0) = match op {
        0x88 => (true, 1, 1, Extend::Move, 0, false),
        0x89 => (true, opsize, opsize, Extend::Move, 0, false),
        0x8A => (false, 1, 1, Extend::Move, 0, false),
        0x8B => (false, opsize, opsize, Extend::Move, 0, false),
        0xC6 => (true, 1, 1, Extend::Move, 1, true),
        0xC7 => (true, opsize, opsize, Extend::Move, if opsize == 2 { 2 } else { 4 }, true),
        0x63 if w => (false, 4, 8, Extend::Sign, 0, false),
        0x0F => {
            let ext = at(i)?;
            i += 1;
            match ext {
                0xB6 => (false, 1, opsize, Extend::Zero, 0, false),
                0xB7 => (false, 2, opsize, Extend::Zero, 0, false),
                0xBE => (false, 1, opsize, Extend::Sign, 0, false),
                0xBF => (false, 2, opsize, Extend::Sign, 0, false),
                _ => return None,
            }
        }
        _ => return None,
    };
    let modrm = at(i)?;
    i += 1;
    let (md, rm) = (modrm >> 6, modrm & 7);
    if md == 3 {
        // A register operand: not a memory access.
        return None;
    }
    if slash0 && modrm >> 3 & 7 != 0 {
        return None;
    }
    let mut disp = match md {
        1 => 1,
        2 => 4,
        _ => 0,
    };
    if rm == 4 {
        let sib = at(i)?;
        i += 1;
        if md == 0 && sib & 7 == 5 {
            disp = 4;
        }
    } else if md == 0 && rm == 5 {
        // RIP-relative (64-bit mode) or a bare disp32 (32-bit mode).
        disp = 4;
    }
    i += disp;
    let mut value = None;
    if imm != 0 {
        let mut v = 0u64;
        for k in 0..imm as usize {
            v |= (at(i + k)? as u64) << (8 * k);
        }
        i += imm as usize;
        // imm32 is sign-extended to a 64-bit operand.
        if size == 8 {
            v = v as u32 as i32 as i64 as u64;
        }
        value = Some(v & mask(size));
    }
    if i > MAX_INSN || i > code.len() {
        return None;
    }
    let regf = (modrm >> 3 & 7) | (rex & 4) << 1;
    let high8 = size == 1 && dest == 1 && rex == 0 && (4..8).contains(&regf);
    Some(Insn {
        len: i as u8,
        write,
        size,
        reg: if high8 { regf - 4 } else { regf },
        high8,
        dest,
        extend,
        imm: value,
    })
}

/// General register `n` (`rax rcx rdx rbx rsp rbp rsi rdi r8..r15`).
pub fn gpr(vmcb: &Vmcb, regs: &GuestRegs, n: u8) -> u64 {
    match n {
        0 => vmcb.rd64(off::RAX),
        1 => regs.rcx,
        2 => regs.rdx,
        3 => regs.rbx,
        4 => vmcb.rd64(off::RSP),
        5 => regs.rbp,
        6 => regs.rsi,
        7 => regs.rdi,
        8 => regs.r8,
        9 => regs.r9,
        10 => regs.r10,
        11 => regs.r11,
        12 => regs.r12,
        13 => regs.r13,
        14 => regs.r14,
        _ => regs.r15,
    }
}

fn set_gpr(vmcb: &mut Vmcb, regs: &mut GuestRegs, n: u8, v: u64) {
    match n {
        0 => vmcb.wr64(off::RAX, v),
        1 => regs.rcx = v,
        2 => regs.rdx = v,
        3 => regs.rbx = v,
        4 => vmcb.wr64(off::RSP, v),
        5 => regs.rbp = v,
        6 => regs.rsi = v,
        7 => regs.rdi = v,
        8 => regs.r8 = v,
        9 => regs.r9 = v,
        10 => regs.r10 = v,
        11 => regs.r11 = v,
        12 => regs.r12 = v,
        13 => regs.r13 = v,
        14 => regs.r14 = v,
        _ => regs.r15 = v,
    }
}

/// The value a store writes: the source register's low `size` bytes, or the
/// immediate.
pub fn store_value(insn: &Insn, vmcb: &Vmcb, regs: &GuestRegs) -> u64 {
    match insn.imm {
        Some(v) => v,
        None => {
            let r = gpr(vmcb, regs, insn.reg);
            (if insn.high8 { r >> 8 } else { r }) & mask(insn.size)
        }
    }
}

/// Finish a load: write `value` (`insn.size` bytes, zero-extended) to the
/// destination register the way the instruction would, and step past it.
/// A 32-bit destination clears the register's upper half; a 16-bit and an
/// 8-bit one leave the rest of the register alone.
pub fn complete_load(insn: &Insn, vmcb: &mut Vmcb, regs: &mut GuestRegs, value: u64) {
    let v = match insn.extend {
        Extend::Sign => {
            let bits = insn.size as u32 * 8;
            (((value & mask(insn.size)) << (64 - bits)) as i64 >> (64 - bits)) as u64
        }
        _ => value & mask(insn.size),
    };
    let old = gpr(vmcb, regs, insn.reg);
    let new = match (insn.dest, insn.high8) {
        (8, _) => v,
        (4, _) => v & mask(4),
        (2, _) => old & !mask(2) | v & mask(2),
        (_, true) => old & !(0xFF << 8) | (v & 0xFF) << 8,
        _ => old & !mask(1) | v & mask(1),
    };
    set_gpr(vmcb, regs, insn.reg, new);
    skip(insn, vmcb);
}

/// Step past the instruction (a store, or a load once finished).
pub fn skip(insn: &Insn, vmcb: &mut Vmcb) {
    vmcb.wr64(off::RIP, vmcb.rd64(off::RIP).wrapping_add(insn.len as u64));
}

// ── fetching the instruction ────────────────────────────────────────────

/// Walk the guest's page tables: the guest-physical address `gva` is mapped
/// to, or `None`. Paging off is the identity; 4-level long-mode paging is
/// walked; the 32-bit paging modes are not (a guest on them is one `boot.S`
/// never runs).
pub fn translate(vmcb: &Vmcb, mem: &dyn GuestMem, gva: u64) -> Option<u64> {
    if vmcb.rd64(off::CR0) & cr0::PG == 0 {
        return Some(gva);
    }
    if vmcb.rd64(off::EFER) & efer::LMA == 0 || vmcb.rd64(off::CR4) & cr4::PAE == 0 {
        return None;
    }
    // Canonical 48-bit address.
    if ((gva as i64) << 16 >> 16) as u64 != gva {
        return None;
    }
    const ADDR: u64 = 0x000F_FFFF_FFFF_F000;
    let mut table = vmcb.rd64(off::CR3) & ADDR;
    for level in (0..4u32).rev() {
        let mut w = [0u8; 8];
        if !mem.read(table + ((gva >> (12 + 9 * level)) & 0x1FF) * 8, &mut w) {
            return None;
        }
        let pte = u64::from_le_bytes(w);
        if pte & 1 == 0 {
            return None;
        }
        // A 1 GiB (level 2) or 2 MiB (level 1) leaf.
        if level > 0 && pte & (1 << 7) != 0 {
            if level == 3 {
                return None;
            }
            let span = 1u64 << (12 + 9 * level);
            return Some((pte & ADDR & !(span - 1)) | (gva & (span - 1)));
        }
        if level == 0 {
            return Some((pte & ADDR) | (gva & 0xFFF));
        }
        table = pte & ADDR;
    }
    None
}

/// The bytes of the instruction at the guest's `CS:RIP`: the CPU's own copy
/// when the VMCB has one, else (`from_memory`) read from the guest's memory
/// (up to the end of the page when the next page is not mapped). Returns the
/// buffer and how many bytes of it are valid.
///
/// The memory read is a second look at bytes another vCPU can rewrite after
/// the exit, so the caller allows it only when no other vCPU runs.
pub fn fetch(vmcb: &Vmcb, mem: &dyn GuestMem, mode: Mode, from_memory: bool) -> Option<([u8; MAX_INSN], usize)> {
    let mut code = [0u8; MAX_INSN];
    let n = vmcb.rd8(OFF_INSN_LEN) as usize;
    if (1..=MAX_INSN).contains(&n) {
        for (k, b) in code.iter_mut().enumerate().take(n) {
            *b = vmcb.rd8(OFF_INSN_BYTES + k);
        }
        return Some((code, n));
    }
    if !from_memory {
        return None;
    }
    let base = if mode == Mode::Long { 0 } else { vmcb.segment(off::CS).3 };
    let mut have = 0;
    while have < MAX_INSN {
        let lin = base.wrapping_add(vmcb.rd64(off::RIP)).wrapping_add(have as u64);
        let lin = if mode == Mode::Prot32 { lin & 0xFFFF_FFFF } else { lin };
        let Some(gpa) = translate(vmcb, mem, lin) else { break };
        let chunk = (MAX_INSN - have).min(0x1000 - (lin & 0xFFF) as usize);
        if !mem.read(gpa, &mut code[have..have + chunk]) {
            break;
        }
        have += chunk;
    }
    (have > 0).then_some((code, have))
}
