// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Static-key sites (wave 15, TRACE; Kconfig `KTRACE_STATIC_KEYS`): the
//! link-time table of patchable tracepoint branches and the two instruction
//! words each one can hold.
//!
//! Pure: no `asm!`, no memory access beyond the table's own fields, so the
//! host test suite pulls this file in by `#[path]` and checks the encoders
//! against assembler output on both ISAs.
//!
//! # A site
//!
//! Every tracepoint check is one naturally aligned 32-bit instruction in the
//! kernel text, linked as a branch to the class's mask test (`jal zero,
//! target` on riscv64, `b target` on aarch64) and recorded in the section
//! `.azos_keys` as a [`KeySite`]. Turning a class off rewrites its sites to
//! the ISA's nop, turning it on rewrites them back to the branch. The
//! branch target re-tests the runtime mask, so a site in either state, at
//! any moment of a change, runs correct code: that is why a kernel that
//! cannot patch keeps the branches and stays correct, only slower.

/// One table entry, as the `asm!` in `azos_trace` emits it: 24 bytes,
/// 8-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySite {
    /// The instruction's address (the kernel's VA of it).
    pub site: u64,
    /// Where the branch form jumps: the class's mask test.
    pub target: u64,
    /// The key: a trace class (`azos_abi::trace::TRACE_CLASS_*`).
    pub key: u32,
    /// The instruction form, [`KIND_RV_JAL`] or [`KIND_A64_B`].
    pub kind: u32,
}

/// riscv64: `jal zero, target` / `addi zero, zero, 0`.
pub const KIND_RV_JAL: u32 = 1;
/// aarch64: `b target` / `nop`.
pub const KIND_A64_B: u32 = 2;

/// aarch64 boot-once PAN sites (Kconfig `A64_PAN=probe`; not a trace key):
/// the `UserAccess` window's `msr PAN, #0` ([`KIND_A64_PAN_CLR`]) and its
/// closing `msr PAN, #1` ([`KIND_A64_PAN_SET`]). Linked as `b target`, a
/// slow path that tests the boot's probe answer at run time (correct before
/// any patch, on any core); rewritten ONCE, on the boot CPU before the
/// secondaries start, to the `msr` when the CPU has FEAT_PAN and to the nop
/// when it does not ([`KeySite::pan_word`]). Once only, because MSR is not in
/// the ARM ARM's list of instructions another PE may run while it changes
/// (B2.2.5; B and NOP are). Recorded under [`KEY_A64_PAN`] so the trace
/// patcher, which rewrites keys below 32 only, never touches them.
pub const KIND_A64_PAN_CLR: u32 = 3;
/// See [`KIND_A64_PAN_CLR`].
pub const KIND_A64_PAN_SET: u32 = 4;
/// The key of every PAN site (>= 32: no trace class).
pub const KEY_A64_PAN: u32 = 64;
/// aarch64 `msr PAN, #0` (MSR immediate: op1 0, CRn 4, CRm #imm, op2 4).
pub const A64_MSR_PAN_0: u32 = 0xd500_409f;
/// aarch64 `msr PAN, #1`.
pub const A64_MSR_PAN_1: u32 = 0xd500_419f;

/// `SpinWait` boot-once sites (wave 15, N2b; Kconfig RV_ZACAS / RV_ZAWRS /
/// RV_ZIHINTPAUSE / A64_LSE at `probe`; not trace keys): Linux's
/// ALTERNATIVE. The site is linked as the SAFE form, a branch to the
/// fallback ([`KEY_SPIN_CAS`]: the LR/SC or LL/SC loop) or a nop
/// ([`KEY_SPIN_WAIT`], [`KEY_SPIN_RELAX`]), so every CPU runs correct code
/// before any patch. The entry's `target` carries the two words instead of
/// an address: bits 0..32 the replacement instruction the assembler encoded
/// with the site's own registers (`amocas.w.aq a1, a0, (s0)`, `casa`,
/// `wrs.nto`, `pause`), bits 32..64 the linked word, or 0 when the linked
/// word is a branch of the site's ISA. The boot rewrites a site ONCE, on the
/// boot CPU before any secondary starts, to the replacement when the probe
/// found the extension; otherwise it stays linked.
pub const KIND_RV_ALT: u32 = 5;
/// See [`KIND_RV_ALT`]: an aarch64 site (linked branch: `b`).
pub const KIND_A64_ALT: u32 = 6;
/// The atomic-instruction sites (Zacas `amocas` on riscv64, LSE `cas*` and
/// `swp*` on aarch64).
pub const KEY_SPIN_CAS: u32 = 65;
/// The wait-hint sites (Zawrs `wrs.nto`).
pub const KEY_SPIN_WAIT: u32 = 66;
/// The relax sites (Zihintpause `pause`).
pub const KEY_SPIN_RELAX: u32 = 67;

/// riscv64 `nop` (`addi x0, x0, 0`), the 4-byte form (never `c.nop`).
pub const RV_NOP: u32 = 0x0000_0013;
/// aarch64 `nop`.
pub const A64_NOP: u32 = 0xd503_201f;

const RV_JAL_OPCODE: u32 = 0x6f;
const A64_B_OPCODE: u32 = 0x1400_0000;

/// `jal x0, to` placed at `from`: a signed, even offset within ±1 MiB.
pub fn rv_jal(from: u64, to: u64) -> Option<u32> {
    let off = to.wrapping_sub(from) as i64;
    if off & 1 != 0 || !(-(1 << 20)..(1 << 20)).contains(&off) {
        return None;
    }
    let o = off as u32;
    Some(((o >> 20) & 1) << 31 | ((o >> 1) & 0x3ff) << 21 | ((o >> 11) & 1) << 20 | ((o >> 12) & 0xff) << 12 | RV_JAL_OPCODE)
}

/// The offset a `jal x0` word encodes, if it is one.
pub fn rv_jal_offset(w: u32) -> Option<i64> {
    if w & 0xfff != RV_JAL_OPCODE {
        return None; // not JAL, or rd != x0
    }
    let imm = ((w >> 31) & 1) << 20 | ((w >> 21) & 0x3ff) << 1 | ((w >> 20) & 1) << 11 | ((w >> 12) & 0xff) << 12;
    Some(((imm << 11) as i32 >> 11) as i64)
}

/// `b to` placed at `from`: a signed offset, a multiple of 4, within ±128 MiB.
pub fn a64_b(from: u64, to: u64) -> Option<u32> {
    let off = to.wrapping_sub(from) as i64;
    if off & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&off) {
        return None;
    }
    Some(A64_B_OPCODE | ((off >> 2) as u32 & 0x03ff_ffff))
}

/// The offset a `b` word encodes, if it is one.
pub fn a64_b_offset(w: u32) -> Option<i64> {
    if w & 0xfc00_0000 != A64_B_OPCODE {
        return None;
    }
    Some((((w & 0x03ff_ffff) << 6) as i32 >> 4) as i64)
}

/// Why a site cannot be patched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteError {
    /// Not a 4-byte aligned address (a riscv64 site assembled compressed or
    /// misaligned, or a corrupt entry).
    Misaligned,
    /// A kind this build does not know.
    Kind,
    /// The branch cannot reach its target from the site.
    Range,
    /// The word at the site is neither this site's nop nor its branch.
    Unexpected,
}

impl KeySite {
    /// The word for `on` (the branch) or off (the nop).
    pub fn word(&self, on: bool) -> Result<u32, SiteError> {
        if self.site & 3 != 0 {
            return Err(SiteError::Misaligned);
        }
        match (self.kind, on) {
            (KIND_RV_JAL, false) => Ok(RV_NOP),
            (KIND_RV_JAL, true) => rv_jal(self.site, self.target).ok_or(SiteError::Range),
            (KIND_A64_B, false) => Ok(A64_NOP),
            (KIND_A64_B, true) => a64_b(self.site, self.target).ok_or(SiteError::Range),
            _ => Err(SiteError::Kind),
        }
    }

    /// The state `word` (read from the site) shows: `Ok(true)` the branch,
    /// `Ok(false)` the nop. Anything else is refused: a patcher that found
    /// some other word would be writing over code it did not put there.
    pub fn state(&self, word: u32) -> Result<bool, SiteError> {
        let on = self.word(true)?;
        let off = self.word(false)?;
        if word == on {
            Ok(true)
        } else if word == off {
            Ok(false)
        } else {
            Err(SiteError::Unexpected)
        }
    }

    /// A PAN site ([`KIND_A64_PAN_CLR`] / [`KIND_A64_PAN_SET`]): the word it
    /// is patched to, the `msr` when the CPU has FEAT_PAN (`present`) and
    /// the nop when it does not.
    pub fn pan_word(&self, present: bool) -> Result<u32, SiteError> {
        if self.site & 3 != 0 {
            return Err(SiteError::Misaligned);
        }
        match (self.kind, present) {
            (KIND_A64_PAN_CLR, true) => Ok(A64_MSR_PAN_0),
            (KIND_A64_PAN_SET, true) => Ok(A64_MSR_PAN_1),
            (KIND_A64_PAN_CLR | KIND_A64_PAN_SET, false) => Ok(A64_NOP),
            _ => Err(SiteError::Kind),
        }
    }

    /// A PAN site's linked form, the `b` to its slow path: the only word the
    /// boot patch overwrites.
    pub fn pan_linked(&self) -> Result<u32, SiteError> {
        match self.kind {
            KIND_A64_PAN_CLR | KIND_A64_PAN_SET => a64_b(self.site, self.target).ok_or(SiteError::Range),
            _ => Err(SiteError::Kind),
        }
    }
}

impl KeySite {
    /// An alternative site ([`KIND_RV_ALT`] / [`KIND_A64_ALT`]): the word the
    /// boot writes when the extension is in use.
    /// A riscv64 site may sit at 2 mod 4 (a 4-byte instruction in
    /// compressed code; the boot writes it in halves before any other hart
    /// runs); an aarch64 one is 4-aligned.
    pub fn alt_word(&self) -> Result<u32, SiteError> {
        match self.kind {
            KIND_RV_ALT if self.site & 1 != 0 => Err(SiteError::Misaligned),
            KIND_A64_ALT if self.site & 3 != 0 => Err(SiteError::Misaligned),
            KIND_RV_ALT | KIND_A64_ALT => Ok(self.target as u32),
            _ => Err(SiteError::Kind),
        }
    }

    /// Does `word` (read from the site) hold this alternative site's linked
    /// form: the recorded word, or, recorded as 0, a branch of its ISA (`jal
    /// zero` / `b`)? The only word the boot patch overwrites.
    pub fn alt_is_linked(&self, word: u32) -> Result<bool, SiteError> {
        self.alt_word()?;
        let linked = (self.target >> 32) as u32;
        Ok(match (self.kind, linked) {
            (KIND_RV_ALT, 0) => rv_jal_offset(word).is_some(),
            (KIND_A64_ALT, 0) => a64_b_offset(word).is_some(),
            (_, l) => word == l,
        })
    }
}

/// The entries of a raw `.azos_keys` image (`len` bytes at `bytes`, as the
/// linker laid it out), or `None` when the length is not a whole number of
/// entries.
pub fn parse(bytes: &[u8]) -> Option<impl Iterator<Item = KeySite> + '_> {
    const N: usize = core::mem::size_of::<KeySite>();
    if bytes.len() % N != 0 {
        return None;
    }
    Some(bytes.chunks_exact(N).map(|c| {
        let u64_at = |o: usize| u64::from_le_bytes(c[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(c[o..o + 4].try_into().unwrap());
        KeySite { site: u64_at(0), target: u64_at(8), key: u32_at(16), kind: u32_at(20) }
    }))
}

const _: () = assert!(core::mem::size_of::<KeySite>() == 24);
