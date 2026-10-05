// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 relocations (ELF for the Arm 64-bit Architecture, "Relocation
//! codes"), the subset RFC-0053 6.2 keeps for a small-code-model, `-fno-pic`
//! `ET_REL` object. Written from the ABI's formulas and the A64 encodings,
//! not from any other loader's source. No veneers: a `CALL26` whose target is
//! beyond +-128 MiB is refused, and the server places the region within reach.

use crate::{fits_signed, get32, put32, put_n, Error};

pub(crate) const R_AARCH64_NONE: u32 = 0;
pub(crate) const R_AARCH64_ABS64: u32 = 257;
pub(crate) const R_AARCH64_ABS32: u32 = 258;
pub(crate) const R_AARCH64_PREL64: u32 = 260;
pub(crate) const R_AARCH64_PREL32: u32 = 261;
pub(crate) const R_AARCH64_MOVW_UABS_G0: u32 = 263;
pub(crate) const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
pub(crate) const R_AARCH64_MOVW_UABS_G1: u32 = 265;
pub(crate) const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
pub(crate) const R_AARCH64_MOVW_UABS_G2: u32 = 267;
pub(crate) const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
pub(crate) const R_AARCH64_MOVW_UABS_G3: u32 = 269;
pub(crate) const R_AARCH64_ADR_PREL_LO21: u32 = 274;
pub(crate) const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub(crate) const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub(crate) const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
pub(crate) const R_AARCH64_TSTBR14: u32 = 279;
pub(crate) const R_AARCH64_CONDBR19: u32 = 280;
pub(crate) const R_AARCH64_JUMP26: u32 = 282;
pub(crate) const R_AARCH64_CALL26: u32 = 283;
pub(crate) const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
pub(crate) const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
pub(crate) const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub(crate) const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;

/// A64 immediate-field encoders, keeping opcode and registers.
pub mod encode {
    /// `ADR`/`ADRP`: imm[1:0] -> 30:29 (immlo), imm[20:2] -> 23:5 (immhi).
    pub fn adr(insn: u32, imm21: i64) -> u32 {
        let i = imm21 as u32;
        (insn & !((3 << 29) | (0x7ffff << 5))) | ((i & 3) << 29) | (((i >> 2) & 0x7ffff) << 5)
    }
    /// `ADD (immediate)` / `LDR`/`STR (unsigned offset)`: imm12 -> 21:10.
    pub fn imm12(insn: u32, imm: u64) -> u32 {
        (insn & !(0xfff << 10)) | (((imm as u32) & 0xfff) << 10)
    }
    /// `B`/`BL`: imm26 (word offset) -> 25:0.
    pub fn imm26(insn: u32, off: i64) -> u32 {
        (insn & 0xfc00_0000) | (((off >> 2) as u32) & 0x03ff_ffff)
    }
    /// `B.cond`/`CBZ`/`CBNZ`: imm19 (word offset) -> 23:5.
    pub fn imm19(insn: u32, off: i64) -> u32 {
        (insn & !(0x7ffff << 5)) | ((((off >> 2) as u32) & 0x7ffff) << 5)
    }
    /// `TBZ`/`TBNZ`: imm14 (word offset) -> 18:5.
    pub fn imm14(insn: u32, off: i64) -> u32 {
        (insn & !(0x3fff << 5)) | ((((off >> 2) as u32) & 0x3fff) << 5)
    }
    /// `MOVZ`/`MOVK`: imm16 -> 20:5.
    pub fn imm16(insn: u32, v: u64) -> u32 {
        (insn & !(0xffff << 5)) | (((v as u32) & 0xffff) << 5)
    }
    /// The 4 KiB page of `x`.
    pub fn page(x: u64) -> u64 {
        x & !0xfff
    }
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
    target: usize,
) -> Result<(), Error<'a>> {
    use encode::*;
    let v = s.wrapping_add(a as u64); // S + A
    let pc = v.wrapping_sub(p) as i64; // S + A - P
    let patch = |buf: &mut [u8], f: &dyn Fn(u32) -> u32| -> Result<(), Error<'a>> {
        let i = get32(buf, at, rtype, off)?;
        put32(buf, at, f(i), rtype, off)?;
        Ok(())
    };
    match rtype {
        R_AARCH64_NONE => Ok(()),
        R_AARCH64_ABS64 => Ok(put_n(buf, at, 8, v, rtype, off)?),
        R_AARCH64_ABS32 => {
            if v > u32::MAX as u64 && !fits_signed(v as i64, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            Ok(put_n(buf, at, 4, v, rtype, off)?)
        }
        R_AARCH64_PREL64 => Ok(put_n(buf, at, 8, pc as u64, rtype, off)?),
        R_AARCH64_PREL32 => {
            if !fits_signed(pc, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            Ok(put_n(buf, at, 4, pc as u64, rtype, off)?)
        }
        R_AARCH64_ADR_PREL_LO21 => {
            if !fits_signed(pc, 21) {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| adr(i, pc))
        }
        R_AARCH64_ADR_PREL_PG_HI21 => {
            let pages = (page(v) as i64).wrapping_sub(page(p) as i64) >> 12;
            if !fits_signed(pages, 21) {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| adr(i, pages))
        }
        R_AARCH64_ADD_ABS_LO12_NC => patch(buf, &|i| imm12(i, v & 0xfff)),
        R_AARCH64_LDST8_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC
        | R_AARCH64_LDST128_ABS_LO12_NC => {
            let shift = match rtype {
                R_AARCH64_LDST8_ABS_LO12_NC => 0,
                R_AARCH64_LDST16_ABS_LO12_NC => 1,
                R_AARCH64_LDST32_ABS_LO12_NC => 2,
                R_AARCH64_LDST64_ABS_LO12_NC => 3,
                _ => 4,
            };
            let lo = v & 0xfff;
            // The scaled offset cannot express a misaligned address: the
            // access would land on a different byte. Refused, not rounded.
            if lo & ((1 << shift) - 1) != 0 {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| imm12(i, lo >> shift))
        }
        R_AARCH64_CALL26 | R_AARCH64_JUMP26 => {
            if pc & 3 != 0 || !fits_signed(pc, 28) {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| imm26(i, pc))
        }
        R_AARCH64_CONDBR19 => {
            if pc & 3 != 0 || !fits_signed(pc, 21) {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| imm19(i, pc))
        }
        R_AARCH64_TSTBR14 => {
            if pc & 3 != 0 || !fits_signed(pc, 16) {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| imm14(i, pc))
        }
        R_AARCH64_MOVW_UABS_G0 | R_AARCH64_MOVW_UABS_G0_NC
        | R_AARCH64_MOVW_UABS_G1 | R_AARCH64_MOVW_UABS_G1_NC
        | R_AARCH64_MOVW_UABS_G2 | R_AARCH64_MOVW_UABS_G2_NC
        | R_AARCH64_MOVW_UABS_G3 => {
            let (group, checked) = match rtype {
                R_AARCH64_MOVW_UABS_G0 => (0, true),
                R_AARCH64_MOVW_UABS_G0_NC => (0, false),
                R_AARCH64_MOVW_UABS_G1 => (1, true),
                R_AARCH64_MOVW_UABS_G1_NC => (1, false),
                R_AARCH64_MOVW_UABS_G2 => (2, true),
                R_AARCH64_MOVW_UABS_G2_NC => (2, false),
                _ => (3, false),
            };
            if checked && (v >> (16 * (group + 1))) != 0 {
                return Err(Error::Overflow(rtype, off));
            }
            patch(buf, &|i| imm16(i, v >> (16 * group)))
        }
        // TLS, GOT, the dynamic types and everything else: not something a
        // small-model `-fno-pic` ET_REL module carries.
        _ => Err(Error::UnsupportedReloc(rtype, target)),
    }
}
