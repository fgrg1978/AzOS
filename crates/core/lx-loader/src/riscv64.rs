// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 relocations (RISC-V ELF psABI, "Relocations" chapter), the subset
//! RFC-0053 6.2 keeps: everything a `-mcmodel=medany -mno-relax -fno-pic`
//! object can carry. Written from the psABI's formulas (`S + A - P` and the
//! instruction-field layouts of the unprivileged ISA manual), not from any
//! other loader's source.

use crate::{fits_signed, get16, get32, get_n, put16, put32, put_n, Error, RelocCtx, SHN_UNDEF};

pub(crate) const R_RISCV_NONE: u32 = 0;
pub(crate) const R_RISCV_32: u32 = 1;
pub(crate) const R_RISCV_64: u32 = 2;
pub(crate) const R_RISCV_BRANCH: u32 = 16;
pub(crate) const R_RISCV_JAL: u32 = 17;
pub(crate) const R_RISCV_CALL: u32 = 18;
pub(crate) const R_RISCV_CALL_PLT: u32 = 19;
pub(crate) const R_RISCV_GOT_HI20: u32 = 20;
pub(crate) const R_RISCV_PCREL_HI20: u32 = 23;
pub(crate) const R_RISCV_PCREL_LO12_I: u32 = 24;
pub(crate) const R_RISCV_PCREL_LO12_S: u32 = 25;
pub(crate) const R_RISCV_HI20: u32 = 26;
pub(crate) const R_RISCV_LO12_I: u32 = 27;
pub(crate) const R_RISCV_LO12_S: u32 = 28;
pub(crate) const R_RISCV_ADD8: u32 = 33;
pub(crate) const R_RISCV_ADD16: u32 = 34;
pub(crate) const R_RISCV_ADD32: u32 = 35;
pub(crate) const R_RISCV_ADD64: u32 = 36;
pub(crate) const R_RISCV_SUB8: u32 = 37;
pub(crate) const R_RISCV_SUB16: u32 = 38;
pub(crate) const R_RISCV_SUB32: u32 = 39;
pub(crate) const R_RISCV_SUB64: u32 = 40;
pub(crate) const R_RISCV_ALIGN: u32 = 43;
pub(crate) const R_RISCV_RVC_BRANCH: u32 = 44;
pub(crate) const R_RISCV_RVC_JUMP: u32 = 45;
pub(crate) const R_RISCV_RELAX: u32 = 51;
pub(crate) const R_RISCV_SUB6: u32 = 52;
pub(crate) const R_RISCV_SET6: u32 = 53;
pub(crate) const R_RISCV_SET8: u32 = 54;
pub(crate) const R_RISCV_SET16: u32 = 55;
pub(crate) const R_RISCV_SET32: u32 = 56;
pub(crate) const R_RISCV_32_PCREL: u32 = 57;
pub(crate) const R_RISCV_PLT32: u32 = 59;
pub(crate) const R_RISCV_SET_ULEB128: u32 = 60;
pub(crate) const R_RISCV_SUB_ULEB128: u32 = 61;

/// Instruction-field encoders: put an immediate into an existing
/// instruction word, keeping opcode and registers.
pub mod encode {
    /// I-type: imm[11:0] -> bits 31:20 (`addi`, `ld`, `jalr`).
    pub fn i_type(insn: u32, imm: i64) -> u32 {
        (insn & 0x000f_ffff) | (((imm as u32) & 0xfff) << 20)
    }
    /// S-type: imm[11:5] -> 31:25, imm[4:0] -> 11:7 (`sd`, `sw`).
    pub fn s_type(insn: u32, imm: i64) -> u32 {
        let i = imm as u32;
        (insn & 0x01ff_f07f) | ((i & 0xfe0) << 20) | ((i & 0x1f) << 7)
    }
    /// U-type: imm[31:12] -> 31:12 (`auipc`, `lui`); `hi20` is the 20-bit value.
    pub fn u_type(insn: u32, hi20: i64) -> u32 {
        (insn & 0xfff) | (((hi20 as u32) & 0xf_ffff) << 12)
    }
    /// B-type: imm[12|10:5] -> 31|30:25, imm[4:1|11] -> 11:8|7.
    pub fn b_type(insn: u32, off: i64) -> u32 {
        let o = off as u32;
        (insn & 0x01ff_f07f)
            | ((o >> 12) & 1) << 31
            | ((o >> 5) & 0x3f) << 25
            | ((o >> 1) & 0xf) << 8
            | ((o >> 11) & 1) << 7
    }
    /// J-type: imm[20|10:1|11|19:12] -> 31|30:21|20|19:12 (`jal`).
    pub fn j_type(insn: u32, off: i64) -> u32 {
        let o = off as u32;
        (insn & 0xfff)
            | ((o >> 20) & 1) << 31
            | ((o >> 1) & 0x3ff) << 21
            | ((o >> 11) & 1) << 20
            | ((o >> 12) & 0xff) << 12
    }
    /// CB format (`c.beqz`/`c.bnez`): offset[8|4:3] -> 12|11:10,
    /// offset[7:6|2:1|5] -> 6:5|4:3|2.
    pub fn cb_type(insn: u16, off: i64) -> u16 {
        let o = off as u16;
        (insn & 0xe383)
            | ((o >> 8) & 1) << 12
            | ((o >> 3) & 3) << 10
            | ((o >> 6) & 3) << 5
            | ((o >> 1) & 3) << 3
            | ((o >> 5) & 1) << 2
    }
    /// CJ format (`c.j`): offset[11|4|9:8|10|6|7|3:1|5] -> bits 12..2.
    pub fn cj_type(insn: u16, off: i64) -> u16 {
        let o = off as u16;
        (insn & 0xe003)
            | ((o >> 11) & 1) << 12
            | ((o >> 4) & 1) << 11
            | ((o >> 8) & 3) << 9
            | ((o >> 10) & 1) << 8
            | ((o >> 6) & 1) << 7
            | ((o >> 7) & 1) << 6
            | ((o >> 1) & 7) << 3
            | ((o >> 5) & 1) << 2
    }
    /// The `%pcrel_hi` / `%hi` split of a 32-bit signed value: `(hi20, lo12)`
    /// with `hi20 << 12 + lo12 == v` once `lo12` is sign-extended.
    pub fn hi_lo(v: i64) -> (i64, i64) {
        let hi = (v + 0x800) >> 12;
        (hi, v - (hi << 12))
    }
}

/// A relocation on a section that is not loaded is never applied, but the
/// two linker-relaxation markers mean the module was built without
/// `-mno-relax`, so its instruction sequences may assume a relaxing linker
/// ran: refused wherever they appear.
pub(crate) fn check_unplaced<'a>(rtype: u32, _target: usize) -> Result<(), Error<'a>> {
    match rtype {
        R_RISCV_ALIGN | R_RISCV_RELAX => Err(Error::UnsupportedReloc(rtype, _target)),
        _ => Ok(()),
    }
}

/// Whether `v` is reachable by an `auipc` + 12-bit pair.
fn fits_pcrel32(v: i64) -> bool {
    (-(1i64 << 31) - 0x800..(1i64 << 31) - 0x800).contains(&v)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply<'a>(
    rtype: u32,
    buf: &mut [u8],
    at: usize,
    p: u64,
    s: u64,
    a: i64,
    off: u64,
    ctx: &mut RelocCtx<'_, 'a, '_>,
    target: usize,
) -> Result<(), Error<'a>> {
    let v = s.wrapping_add(a as u64); // S + A
    let pc = v.wrapping_sub(p) as i64; // S + A - P
    use encode::*;
    match rtype {
        R_RISCV_NONE => Ok(()),
        R_RISCV_64 => put_n(buf, at, 8, v, rtype, off).map_err(widen),
        R_RISCV_32 => {
            if v > u32::MAX as u64 && !fits_signed(v as i64, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            put_n(buf, at, 4, v, rtype, off).map_err(widen)
        }
        R_RISCV_32_PCREL | R_RISCV_PLT32 => {
            if !fits_signed(pc, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            put_n(buf, at, 4, pc as u64, rtype, off).map_err(widen)
        }
        R_RISCV_BRANCH => {
            if pc & 1 != 0 || !fits_signed(pc, 13) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            put32(buf, at, b_type(i, pc), rtype, off).map_err(widen)
        }
        R_RISCV_JAL => {
            if pc & 1 != 0 || !fits_signed(pc, 21) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            put32(buf, at, j_type(i, pc), rtype, off).map_err(widen)
        }
        R_RISCV_CALL | R_RISCV_CALL_PLT => {
            // `auipc ra, %pcrel_hi(sym); jalr ra, %pcrel_lo(sym)(ra)`: one
            // relocation patches both words. No PLT: the target must be in
            // reach of the pair itself (RFC-0053 6.2, placement rule).
            if pc & 1 != 0 || !fits_pcrel32(pc) {
                return Err(Error::Overflow(rtype, off));
            }
            let (hi, lo) = hi_lo(pc);
            let auipc = get32(buf, at, rtype, off).map_err(widen)?;
            let jalr = get32(buf, at + 4, rtype, off).map_err(widen)?;
            put32(buf, at, u_type(auipc, hi), rtype, off).map_err(widen)?;
            put32(buf, at + 4, i_type(jalr, lo), rtype, off).map_err(widen)
        }
        R_RISCV_PCREL_HI20 => {
            if !fits_pcrel32(pc) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            put32(buf, at, u_type(i, hi_lo(pc).0), rtype, off).map_err(widen)
        }
        R_RISCV_PCREL_LO12_I | R_RISCV_PCREL_LO12_S => {
            // The symbol of a `%pcrel_lo` names the `auipc`, not the data:
            // the low part is the one of the PAIRED `PCREL_HI20`'s value.
            let lo = paired_hi_offset(ctx, rtype, off, p, target).map(|hv| hi_lo(hv).1)?;
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            let w = if rtype == R_RISCV_PCREL_LO12_I { i_type(i, lo) } else { s_type(i, lo) };
            put32(buf, at, w, rtype, off).map_err(widen)
        }
        R_RISCV_HI20 => {
            if !fits_signed(v as i64, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            put32(buf, at, u_type(i, hi_lo(v as i64).0), rtype, off).map_err(widen)
        }
        R_RISCV_LO12_I | R_RISCV_LO12_S => {
            let lo = hi_lo(v as i64).1;
            let i = get32(buf, at, rtype, off).map_err(widen)?;
            let w = if rtype == R_RISCV_LO12_I { i_type(i, lo) } else { s_type(i, lo) };
            put32(buf, at, w, rtype, off).map_err(widen)
        }
        R_RISCV_RVC_BRANCH => {
            if pc & 1 != 0 || !fits_signed(pc, 9) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get16(buf, at, rtype, off).map_err(widen)?;
            put16(buf, at, cb_type(i, pc), rtype, off).map_err(widen)
        }
        R_RISCV_RVC_JUMP => {
            if pc & 1 != 0 || !fits_signed(pc, 12) {
                return Err(Error::Overflow(rtype, off));
            }
            let i = get16(buf, at, rtype, off).map_err(widen)?;
            put16(buf, at, cj_type(i, pc), rtype, off).map_err(widen)
        }
        // Label differences (`.eh_frame`-style tables, jump tables): the
        // field is updated in place, modulo its width.
        R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64
        | R_RISCV_SUB8 | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64 => {
            let n = match rtype {
                R_RISCV_ADD8 | R_RISCV_SUB8 => 1,
                R_RISCV_ADD16 | R_RISCV_SUB16 => 2,
                R_RISCV_ADD32 | R_RISCV_SUB32 => 4,
                _ => 8,
            };
            let old = get_n(buf, at, n, rtype, off).map_err(widen)?;
            let new = if rtype <= R_RISCV_ADD64 { old.wrapping_add(v) } else { old.wrapping_sub(v) };
            put_n(buf, at, n, new, rtype, off).map_err(widen)
        }
        R_RISCV_SUB6 | R_RISCV_SET6 => {
            let old = get_n(buf, at, 1, rtype, off).map_err(widen)? as u8;
            let low = if rtype == R_RISCV_SUB6 { (old as u64).wrapping_sub(v) } else { v } as u8 & 0x3f;
            put_n(buf, at, 1, ((old & 0xc0) | low) as u64, rtype, off).map_err(widen)
        }
        R_RISCV_SET8 => put_n(buf, at, 1, v, rtype, off).map_err(widen),
        R_RISCV_SET16 => put_n(buf, at, 2, v, rtype, off).map_err(widen),
        R_RISCV_SET32 => put_n(buf, at, 4, v, rtype, off).map_err(widen),
        // Refused by name, each for its own reason: GOT_HI20 needs a GOT
        // (`-fno-pic` never emits it); ALIGN/RELAX mean linker relaxation was
        // on; the ULEB128 pair only appears in debug/unwind sections, never
        // in a loaded one; everything else (TLS, dynamic types) is outside
        // what an ET_REL module may carry here.
        R_RISCV_SET_ULEB128 | R_RISCV_SUB_ULEB128 | R_RISCV_ALIGN | R_RISCV_RELAX | R_RISCV_GOT_HI20 => {
            Err(Error::UnsupportedReloc(rtype, target))
        }
        _ => Err(Error::UnsupportedReloc(rtype, target)),
    }
}

/// `S + A - P` of the `PCREL_HI20` (or `CALL`) relocation the current
/// `PCREL_LO12_*` relocation pairs with. Its symbol is a label on the
/// `auipc` in the same section; the pair is found by that address.
fn paired_hi_offset<'a>(ctx: &mut RelocCtx<'_, 'a, '_>, rtype: u32, off: u64, p_lo: u64, target: usize) -> Result<i64, Error<'a>> {
    let m = ctx.module;
    // The LO12 relocation's own symbol: re-read it from the table at `off`.
    let count = (ctx.rela.size / crate::RELA_LEN as u64) as usize;
    let mut label: Option<u64> = None;
    for k in 0..count {
        let o = ctx.rela.offset as usize + k * crate::RELA_LEN;
        let r_off = crate::rd_u64(m.obj, o).ok_or(Error::Truncated)?;
        let info = crate::rd_u64(m.obj, o + 8).ok_or(Error::Truncated)?;
        if r_off == off && (info & 0xffff_ffff) as u32 == rtype {
            let (shndx, val) = m.sym_raw((info >> 32) as usize)?;
            if shndx == SHN_UNDEF || shndx as usize != target {
                return Err(Error::MissingHi20(off));
            }
            label = Some(val);
            break;
        }
    }
    let label = label.ok_or(Error::MissingHi20(off))?;
    for k in 0..count {
        let o = ctx.rela.offset as usize + k * crate::RELA_LEN;
        let r_off = crate::rd_u64(m.obj, o).ok_or(Error::Truncated)?;
        let info = crate::rd_u64(m.obj, o + 8).ok_or(Error::Truncated)?;
        let t = (info & 0xffff_ffff) as u32;
        if r_off == label && (t == R_RISCV_PCREL_HI20 || t == R_RISCV_GOT_HI20) {
            if t == R_RISCV_GOT_HI20 {
                return Err(Error::UnsupportedReloc(t, target));
            }
            let a = crate::rd_u64(m.obj, o + 16).ok_or(Error::Truncated)? as i64;
            let s = m.sym_value((info >> 32) as usize, ctx.bases, &mut *ctx.resolve)?;
            let p_hi = p_lo.wrapping_sub(off).wrapping_add(label);
            return Ok(s.wrapping_add(a as u64).wrapping_sub(p_hi) as i64);
        }
    }
    Err(Error::MissingHi20(off))
}

fn widen<'a>(e: Error<'static>) -> Error<'a> {
    e
}
