// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 relocations (System V AMD64 psABI, "Relocation Types"), the subset
//! kept for a `-fno-pic` `ET_REL` object. Written from the ABI's formulas, not
//! from any other loader's source. Every field is a plain little-endian data
//! word (no instruction encoding to patch), so the whole job is the range
//! check: a `PC32` whose target is beyond +-2 GiB, or an absolute `32`/`32S`
//! whose address does not fit the field's zero/sign extension, is refused,
//! never truncated. Linux's own `.ko` are built `-mcmodel=kernel`, whose
//! absolute references are `32S`: they fit only a region in the top 2 GiB, so
//! a ring-3 server's low region refuses them by this check.

use crate::{fits_signed, put_n, Error};

pub(crate) const R_X86_64_NONE: u32 = 0;
pub(crate) const R_X86_64_64: u32 = 1;
pub(crate) const R_X86_64_PC32: u32 = 2;
pub(crate) const R_X86_64_PLT32: u32 = 4;
pub(crate) const R_X86_64_32: u32 = 10;
pub(crate) const R_X86_64_32S: u32 = 11;
pub(crate) const R_X86_64_PC64: u32 = 24;

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
    let v = s.wrapping_add(a as u64); // S + A
    let pc = v.wrapping_sub(p) as i64; // S + A - P
    match rtype {
        R_X86_64_NONE => Ok(()),
        R_X86_64_64 => Ok(put_n(buf, at, 8, v, rtype, off)?),
        R_X86_64_PC64 => Ok(put_n(buf, at, 8, pc as u64, rtype, off)?),
        // No PLT: a call's `PLT32` is its target's `PC32`, as in a static link.
        R_X86_64_PC32 | R_X86_64_PLT32 => {
            if !fits_signed(pc, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            Ok(put_n(buf, at, 4, pc as u64, rtype, off)?)
        }
        // Zero-extended by the instruction that reads it.
        R_X86_64_32 => {
            if v > u32::MAX as u64 {
                return Err(Error::Overflow(rtype, off));
            }
            Ok(put_n(buf, at, 4, v, rtype, off)?)
        }
        // Sign-extended: the low 2 GiB or the top 2 GiB of the address space.
        R_X86_64_32S => {
            if !fits_signed(v as i64, 32) {
                return Err(Error::Overflow(rtype, off));
            }
            Ok(put_n(buf, at, 4, v, rtype, off)?)
        }
        // GOT, TLS, the dynamic types and everything else: not something a
        // `-fno-pic` ET_REL module carries.
        _ => Err(Error::UnsupportedReloc(rtype, target)),
    }
}
