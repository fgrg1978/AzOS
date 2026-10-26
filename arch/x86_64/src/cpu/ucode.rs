// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CPU microcode updates (Kconfig `X86_UCODE_LOAD`): the containers Intel and
//! AMD publish, the choice of the patch for this CPU, and the MSR writes that
//! load it. The kernel half (`kernel/src/entry/x86_64/ext/ucode.rs`) finds the
//! image among the boot modules, verifies its signature and records the
//! outcome; everything up to the write is pure and host-tested
//! (`tests/host/x86-platform-tests`, `ucode_tests.rs`), only the hardware half
//! at the end executes `wrmsr`.
//!
//! # The image
//!
//! The boot module (PVH `-initrd`, or `module_path: boot():/UCODE.BIN` on the
//! Limine ESP; `make ucode`, mk/firmware.mk) is an `RSIG` signature
//! (`azos_crypto::sig`) followed by the payload it signs:
//!
//! ```text
//! payload  0   8  magic "AZUCODE\0"
//!          8   4  version (1)
//!         12   4  sections that follow
//! section  0   4  tag: "INTL" (concatenated intel-ucode files)
//!                      "AMDC" (concatenated microcode_amd*.bin containers)
//!          4   4  body length in bytes
//!          8   8  zero
//!         16   n  body, then zero padding to a 16-byte boundary
//! ```
//!
//! The 112-byte Ed25519 `RSIG`, the 16-byte headers and the padding keep every
//! body 16-byte aligned in a page-aligned module, so every Intel update (its
//! sizes are multiples of 1 KiB) has its data where `IA32_BIOS_UPDT_TRIG`
//! wants it, 16-byte aligned.
//!
//! # The choice (what Linux does, `arch/x86/kernel/cpu/microcode/`)
//!
//! * **Intel.** An update names a CPU by its CPUID.1:EAX signature and a mask
//!   of platform flags (1 << `IA32_PLATFORM_ID[52:50]`), in its header or in a
//!   row of its extended signature table; the flags are either both 0 or they
//!   intersect. A matching update passes `intel_microcode_sanity_check`'s
//!   checks before it is written: header and loader version 1, consistent
//!   sizes, the dwords of header and data summing to 0, the extended table's
//!   own sum 0, and each extended row's signature + flags + checksum equal to
//!   the header's.
//! * **AMD.** A container's equivalence table maps CPUID.1:EAX to an
//!   equivalence id; a patch is for the CPUs whose id is its
//!   `processor_rev_id`, and for the family `0xF + processor_rev_id[15:12]`.
//!   The AMD CPU checks the patch's own signature; this file checks the
//!   container's structure.
//! * The newest patch for the CPU wins, and only when it is newer than the
//!   revision in force: nothing is ever downgraded.

use crate::cpu::features::Vendor;

/// The payload's magic.
pub const MAGIC: [u8; 8] = *b"AZUCODE\0";
/// The payload format this file reads.
pub const VERSION: u32 = 1;
/// Bytes of the payload header.
pub const HEADER_LEN: usize = 16;
/// Bytes of a section header; bodies start and end on this boundary.
pub const SECTION_LEN: usize = 16;
/// Section of concatenated Intel updates.
pub const TAG_INTEL: [u8; 4] = *b"INTL";
/// Section of concatenated AMD containers.
pub const TAG_AMD: [u8; 4] = *b"AMDC";

/// What the choice knows about this CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSig {
    pub vendor: Vendor,
    /// CPUID.1:EAX.
    pub sig: u32,
    /// Intel's platform flag, 1 << `IA32_PLATFORM_ID[52:50]`; 0 on a part
    /// before family 6 model 5, which has no such MSR (and on AMD).
    pub pf: u32,
    /// The revision in force: `IA32_BIOS_SIGN_ID[63:32]` (Intel),
    /// `MSR_AMD64_PATCH_LEVEL[31:0]` (AMD).
    pub rev: u32,
}

/// A patch for this CPU, in the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Patch {
    /// Offset of the update (Intel: its 48-byte header; AMD: the patch
    /// header that follows the section header) from the payload's start.
    pub off: usize,
    /// Its length.
    pub len: usize,
    /// The revision it brings.
    pub rev: u32,
}

/// What the payload has for this CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// The newest patch for this CPU; newer than the revision in force.
    Load(Patch),
    /// Patches for this CPU, none newer than the revision in force; `newest`
    /// is the newest of them.
    Current { newest: u32 },
    /// No patch names this CPU.
    None,
}

/// Why a payload was refused. Any of them refuses the whole image: it was
/// signed, so a malformed part is a broken build, not a patch to skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The payload header or a section header: magic, version, a length past
    /// the end, an unknown tag, a non-zero reserved word.
    Section,
    /// An Intel update's header: its versions or sizes.
    IntelHeader,
    /// An Intel update whose header and data do not sum to zero.
    IntelChecksum,
    /// An Intel update's extended signature table: its size, its count, its
    /// sum, or a row that does not balance against the header.
    IntelExtTable,
    /// An AMD container: magic, equivalence table type or size.
    AmdContainer,
    /// An AMD patch section: shorter than a patch header, or past the end.
    AmdPatch,
}

impl Error {
    pub const fn label(self) -> &'static str {
        match self {
            Error::Section => "the image's header or a section header is malformed",
            Error::IntelHeader => "an Intel update's header is malformed",
            Error::IntelChecksum => "an Intel update's checksum does not hold",
            Error::IntelExtTable => "an Intel update's extended signature table does not hold",
            Error::AmdContainer => "an AMD container's header or equivalence table is malformed",
            Error::AmdPatch => "an AMD patch section is malformed",
        }
    }
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

/// Call `f(tag, offset, body)` for each section of `payload` (offsets from
/// the payload's start). Every header is checked before the first call.
pub fn for_each_section(payload: &[u8], mut f: impl FnMut([u8; 4], usize, &[u8]) -> Result<(), Error>) -> Result<(), Error> {
    if payload.len() < HEADER_LEN || payload[..8] != MAGIC || u32_at(payload, 8) != Some(VERSION) {
        return Err(Error::Section);
    }
    let count = u32_at(payload, 12).ok_or(Error::Section)?;
    // Two passes: the structure first, so a truncated image is refused
    // before anything of it is believed.
    let walk = |f: &mut dyn FnMut([u8; 4], usize, &[u8]) -> Result<(), Error>| -> Result<(), Error> {
        let mut off = HEADER_LEN;
        for _ in 0..count {
            let h = payload.get(off..off + SECTION_LEN).ok_or(Error::Section)?;
            let tag: [u8; 4] = h[..4].try_into().map_err(|_| Error::Section)?;
            let len = u32_at(h, 4).ok_or(Error::Section)? as usize;
            if (tag != TAG_INTEL && tag != TAG_AMD) || h[8..].iter().any(|&b| b != 0) {
                return Err(Error::Section);
            }
            let body = off + SECTION_LEN;
            let end = body.checked_add(len).ok_or(Error::Section)?;
            let next = end.checked_next_multiple_of(SECTION_LEN).ok_or(Error::Section)?;
            if next > payload.len() {
                return Err(Error::Section);
            }
            f(tag, body, &payload[body..end])?;
            off = next;
        }
        if off == payload.len() { Ok(()) } else { Err(Error::Section) }
    };
    walk(&mut |_, _, _| Ok(()))?;
    walk(&mut f)
}

/// The patch for `cpu` in `payload` (the bytes after the `RSIG`). Only the
/// sections of the CPU's vendor are parsed (Hygon's parts take AMD's).
pub fn select(payload: &[u8], cpu: &CpuSig) -> Result<Choice, Error> {
    let want = match cpu.vendor {
        Vendor::Intel => TAG_INTEL,
        Vendor::Amd | Vendor::Hygon => TAG_AMD,
        Vendor::Unknown => return for_each_section(payload, |_, _, _| Ok(())).map(|()| Choice::None),
    };
    // (offset, len, rev) of the newest patch for the CPU, newer or not.
    let mut best: Option<Patch> = None;
    let mut keep = |p: Patch| {
        if best.is_none_or(|b| p.rev > b.rev) {
            best = Some(p);
        }
    };
    for_each_section(payload, |tag, base, body| {
        if tag != want {
            return Ok(());
        }
        if tag == TAG_INTEL {
            intel::scan(body, cpu.sig, cpu.pf, |off, len, rev| keep(Patch { off: base + off, len, rev }))
        } else {
            amd::scan(body, cpu.sig, |off, len, rev| keep(Patch { off: base + off, len, rev }))
        }
    })?;
    Ok(match best {
        Some(p) if p.rev > cpu.rev => Choice::Load(p),
        Some(p) => Choice::Current { newest: p.rev },
        None => Choice::None,
    })
}

/// The CPU's display family from CPUID.1:EAX (the extended family added
/// when the base is 0xF).
pub const fn family(sig: u32) -> u32 {
    let base = (sig >> 8) & 0xF;
    if base == 0xF { base + ((sig >> 20) & 0xFF) } else { base }
}

/// The CPU's display model from CPUID.1:EAX.
pub const fn model(sig: u32) -> u32 {
    let base = (sig >> 4) & 0xF;
    let f = (sig >> 8) & 0xF;
    if f == 0x6 || f == 0xF { base | ((sig >> 16) & 0xF) << 4 } else { base }
}

/// Intel's platform flag from `IA32_PLATFORM_ID` (MSR 0x17): bits 52:50
/// select one bit of the mask. A part before family 6 model 5 has no MSR,
/// and its flag is 0 (Linux `intel_collect_cpu_info`).
pub const fn intel_platform_flag(sig: u32, platform_id: u64) -> u32 {
    if model(sig) >= 5 || family(sig) > 6 { 1 << ((platform_id >> 50) & 7) } else { 0 }
}

/// Does Intel's (sig, pf) of this CPU name an update's (`sig2`, `pf2`)?
/// Processor flags are either both 0 or they intersect.
pub const fn intel_sig_matches(sig: u32, pf: u32, sig2: u32, pf2: u32) -> bool {
    sig == sig2 && ((pf == 0 && pf2 == 0) || pf & pf2 != 0)
}

/// The Intel microcode update format (SDM Vol. 3A §10.11, Linux
/// `microcode_intel.h`).
pub mod intel {
    use super::{u32_at, Error};

    /// Bytes of the update header.
    pub const HEADER: usize = 48;
    /// Data and total size of a header that leaves them 0 (the oldest
    /// format).
    const DEFAULT_DATA: usize = 2000;
    const DEFAULT_TOTAL: usize = 2048;
    /// Bytes of the extended signature table's header and of one row.
    const EXT_HEADER: usize = 20;
    const EXT_ROW: usize = 12;

    /// The fields of an update header the loader reads.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Header {
        pub rev: u32,
        pub sig: u32,
        pub cksum: u32,
        pub pf: u32,
        pub data_size: usize,
        pub total_size: usize,
    }

    /// The header at the start of `b`, its sizes resolved and bounded by `b`.
    pub fn header(b: &[u8]) -> Result<Header, Error> {
        let w = |off| u32_at(b, off).ok_or(Error::IntelHeader);
        let (hdrver, rev, sig, cksum, ldrver, pf) = (w(0)?, w(4)?, w(12)?, w(16)?, w(20)?, w(24)?);
        let (data, total) = match w(28)? as usize {
            0 => (DEFAULT_DATA, DEFAULT_TOTAL),
            d => (d, w(32)? as usize),
        };
        if hdrver != 1 || ldrver != 1 || data % 4 != 0 || total % 4 != 0
            || data.checked_add(HEADER).is_none_or(|n| n > total) || total > b.len()
        {
            return Err(Error::IntelHeader);
        }
        Ok(Header { rev, sig, cksum, pf, data_size: data, total_size: total })
    }

    /// The extended signature table of update `u` (header `h`): its bytes,
    /// empty when the update has none, its structure checked.
    fn ext_table<'a>(u: &'a [u8], h: &Header) -> Result<&'a [u8], Error> {
        let t = &u[HEADER + h.data_size..h.total_size];
        if t.is_empty() {
            return Ok(t);
        }
        let count = u32_at(t, 0).ok_or(Error::IntelExtTable)? as usize;
        if t.len() < EXT_HEADER || (t.len() - EXT_HEADER) % EXT_ROW != 0
            || count.checked_mul(EXT_ROW).and_then(|n| n.checked_add(EXT_HEADER)) != Some(t.len())
        {
            return Err(Error::IntelExtTable);
        }
        Ok(t)
    }

    /// The rows `(sig, pf, cksum)` of an extended table [`ext_table`] passed.
    fn ext_rows(t: &[u8]) -> impl Iterator<Item = (u32, u32, u32)> + '_ {
        let rows = if t.is_empty() { &t[..0] } else { &t[EXT_HEADER..] };
        rows.chunks_exact(EXT_ROW).map(|r| {
            let w = |o: usize| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
            (w(0), w(4), w(8))
        })
    }

    /// Does update `u` (header `h`) name the CPU (`sig`, `pf`), in its header
    /// or in its extended table?
    pub fn matches(u: &[u8], h: &Header, sig: u32, pf: u32) -> Result<bool, Error> {
        if super::intel_sig_matches(sig, pf, h.sig, h.pf) {
            return Ok(true);
        }
        Ok(ext_rows(ext_table(u, h)?).any(|(s, p, _)| super::intel_sig_matches(sig, pf, s, p)))
    }

    /// The sum of the dwords of `b` (a multiple of four bytes long).
    fn sum(b: &[u8]) -> u32 {
        b.chunks_exact(4).fold(0u32, |a, w| a.wrapping_add(u32::from_le_bytes([w[0], w[1], w[2], w[3]])))
    }

    /// The checks an update passes before it is written: the dwords of header
    /// and data sum to 0; the extended table's dwords sum to 0 and each of
    /// its rows balances against the header (`sig + pf + cksum` equal).
    pub fn check(u: &[u8], h: &Header) -> Result<(), Error> {
        // Canary (`x86-ucode-canary`): the checksum is not computed, so an
        // update with a corrupted byte passes; `a_corrupted_update_is_refused`
        // must fail.
        if !cfg!(feature = "x86-ucode-canary") && sum(&u[..HEADER + h.data_size]) != 0 {
            return Err(Error::IntelChecksum);
        }
        let t = ext_table(u, h)?;
        if t.is_empty() {
            return Ok(());
        }
        if sum(t) != 0 {
            return Err(Error::IntelExtTable);
        }
        let own = h.sig.wrapping_add(h.pf).wrapping_add(h.cksum);
        if ext_rows(t).any(|(s, p, c)| s.wrapping_add(p).wrapping_add(c) != own) {
            return Err(Error::IntelExtTable);
        }
        Ok(())
    }

    /// Call `f(offset, total_size, rev)` for each update of `body` (the
    /// concatenated files) that names the CPU and passes [`check`]. Every
    /// header on the way is checked: one that does not parse refuses the body.
    pub fn scan(body: &[u8], sig: u32, pf: u32, mut f: impl FnMut(usize, usize, u32)) -> Result<(), Error> {
        let mut off = 0;
        while off < body.len() {
            let u = &body[off..];
            let h = header(u)?;
            let u = &u[..h.total_size];
            if matches(u, &h, sig, pf)? {
                check(u, &h)?;
                f(off, h.total_size, h.rev);
            }
            off += h.total_size;
        }
        Ok(())
    }
}

/// The AMD container format (`microcode_amd*.bin`, Linux
/// `arch/x86/kernel/cpu/microcode/amd.c`).
pub mod amd {
    use super::{u16_at, u32_at, Error};

    /// A container's first word.
    pub const MAGIC: u32 = 0x0041_4d44;
    /// The container header: magic, the equivalence table's type, its size.
    const CONTAINER_HEADER: usize = 12;
    const EQUIV_TABLE_TYPE: u32 = 0;
    /// A patch section: type 1, size, then the patch.
    const PATCH_TYPE: u32 = 1;
    const SECTION_HEADER: usize = 8;
    /// One equivalence-table row: installed CPU (CPUID.1:EAX), the errata
    /// mask and compare, the equivalence id, a reserved half.
    const EQUIV_ROW: usize = 16;
    /// `struct microcode_header_amd`: `patch_id` at 4, `processor_rev_id`
    /// at 24.
    pub const PATCH_HEADER: usize = 64;

    /// The equivalence id the table `t` (rows only) gives CPUID.1:EAX `sig`.
    /// The table ends at its size or at a row whose installed CPU is 0.
    pub fn equiv_id(t: &[u8], sig: u32) -> Option<u16> {
        t.chunks_exact(EQUIV_ROW)
            .map(|r| (u32::from_le_bytes([r[0], r[1], r[2], r[3]]), u16::from_le_bytes([r[12], r[13]])))
            .take_while(|&(cpu, _)| cpu != 0)
            .find(|&(cpu, _)| cpu == sig)
            .map(|(_, id)| id)
    }

    /// The family a patch is for: `0xF + processor_rev_id[15:12]`.
    pub const fn patch_family(rev_id: u16) -> u32 {
        0xF + (rev_id as u32 >> 12)
    }

    /// Call `f(offset, len, patch_id)` for each patch of `body` (one or more
    /// containers back to back) for the CPU of CPUID.1:EAX `sig`: a patch
    /// whose `processor_rev_id` is the CPU's equivalence id in its container's
    /// table, for the CPU's family. A container with no row for the CPU is
    /// walked, not believed, to find the next one.
    pub fn scan(body: &[u8], sig: u32, mut f: impl FnMut(usize, usize, u32)) -> Result<(), Error> {
        let family = super::family(sig);
        let mut off = 0;
        while off < body.len() {
            let c = &body[off..];
            if u32_at(c, 0) != Some(MAGIC) || u32_at(c, 4) != Some(EQUIV_TABLE_TYPE) {
                return Err(Error::AmdContainer);
            }
            let eq_len = u32_at(c, 8).ok_or(Error::AmdContainer)? as usize;
            let eq_end = CONTAINER_HEADER.checked_add(eq_len).ok_or(Error::AmdContainer)?;
            if eq_len < EQUIV_ROW || eq_end > c.len() {
                return Err(Error::AmdContainer);
            }
            let id = equiv_id(&c[CONTAINER_HEADER..eq_end], sig);
            // The patch sections, up to the next container (or the end).
            let mut p = eq_end;
            while p < c.len() && u32_at(c, p) == Some(PATCH_TYPE) {
                let len = u32_at(c, p + 4).ok_or(Error::AmdPatch)? as usize;
                let start = p + SECTION_HEADER;
                let end = start.checked_add(len).ok_or(Error::AmdPatch)?;
                if len < PATCH_HEADER || end > c.len() {
                    return Err(Error::AmdPatch);
                }
                let rev_id = u16_at(c, start + 24).ok_or(Error::AmdPatch)?;
                if id == Some(rev_id) && patch_family(rev_id) == family {
                    f(off + start, len, u32_at(c, start + 4).ok_or(Error::AmdPatch)?);
                }
                p = end;
            }
            // Whatever follows must be the next container's header (the
            // loop's first check) or nothing.
            off += p;
        }
        Ok(())
    }
}

// ── The hardware half (bare-metal x86_64 only) ─────────────────────────────────────────

/// `IA32_PLATFORM_ID`.
pub const MSR_IA32_PLATFORM_ID: u32 = 0x17;
/// `IA32_BIOS_UPDT_TRIG`: the linear address of an Intel update's data.
pub const MSR_IA32_BIOS_UPDT_TRIG: u32 = 0x79;
/// `IA32_BIOS_SIGN_ID` (Intel) and `MSR_AMD64_PATCH_LEVEL` (AMD): the
/// revision in force.
pub const MSR_UCODE_REV: u32 = 0x8B;
/// `MSR_AMD64_PATCH_LOADER`: the linear address of an AMD patch.
pub const MSR_AMD64_PATCH_LOADER: u32 = 0xC001_0020;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hw {
    use super::*;
    use crate::cpu::features::{decode_ident, read_cpuid};
    use crate::cpu::{rdmsr, wrmsr};

    /// CPUID.1:ECX[31]: a hypervisor owns the microcode (Linux does not load
    /// it in a guest either): nothing here touches an MSR then.
    pub fn hypervisor() -> bool {
        read_cpuid().l1_ecx & (1 << 31) != 0
    }

    /// The revision in force on this CPU. Intel: write 0 to
    /// `IA32_BIOS_SIGN_ID`, execute CPUID.1, read its high half.
    pub fn revision(vendor: Vendor) -> u32 {
        match vendor {
            Vendor::Intel => {
                wrmsr(MSR_UCODE_REV, 0);
                let _ = core::arch::x86_64::__cpuid(1);
                (rdmsr(MSR_UCODE_REV) >> 32) as u32
            }
            Vendor::Amd | Vendor::Hygon => rdmsr(MSR_UCODE_REV) as u32,
            Vendor::Unknown => 0,
        }
    }

    /// This CPU, read: vendor and signature from CPUID, Intel's platform flag
    /// and the revision from their MSRs (both exist on every part the loader
    /// knows; an unknown vendor reads none).
    pub fn this_cpu() -> CpuSig {
        let r = read_cpuid();
        let vendor = decode_ident(&r).vendor;
        // The MSR is read only where `intel_platform_flag` says it exists.
        let pf = match vendor {
            Vendor::Intel if intel_platform_flag(r.l1_eax, 0) != 0 => intel_platform_flag(r.l1_eax, rdmsr(MSR_IA32_PLATFORM_ID)),
            _ => 0,
        };
        CpuSig { vendor, sig: r.l1_eax, pf, rev: revision(vendor) }
    }

    /// Load the patch at linear address `va` (`len` bytes, the update or
    /// patch [`select`] chose) and return the revision read back: the
    /// patch's own when the CPU took it.
    ///
    /// # Safety
    /// `va` is mapped and holds the whole patch; this CPU's interrupts are
    /// off, and its sibling threads are not loading at the same time.
    pub unsafe fn write(vendor: Vendor, va: usize, len: usize) -> u32 {
        match vendor {
            Vendor::Intel => {
                // Write back and invalidate the caches first (Linux does, for
                // what the update changes); the MSR takes the data, past the
                // 48-byte header.
                // SAFETY: CPL0; wbinvd only costs time.
                unsafe { core::arch::asm!("wbinvd", options(nostack, preserves_flags)) };
                wrmsr(MSR_IA32_BIOS_UPDT_TRIG, (va + intel::HEADER) as u64);
            }
            Vendor::Amd | Vendor::Hygon => {
                wrmsr(MSR_AMD64_PATCH_LOADER, va as u64);
                // Zen 1/2 keep a stale translation of the patch buffer (Linux
                // flushes it after the load, family 17h only).
                if family(read_cpuid().l1_eax) == 0x17 {
                    // SAFETY: CPL0; invlpg drops one translation.
                    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
                    let last = va + len.max(1) - 1;
                    if last >> 12 != va >> 12 {
                        // SAFETY: as above.
                        unsafe { core::arch::asm!("invlpg [{}]", in(reg) last, options(nostack, preserves_flags)) };
                    }
                }
            }
            Vendor::Unknown => return 0,
        }
        revision(vendor)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hw::{hypervisor, revision, this_cpu, write};
