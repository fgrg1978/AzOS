// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Limine boot protocol's facts and the decisions taken from them,
//! pure: the request identifiers and response layouts, the base-revision
//! handshake, the memory map reduced to the E820 entries the platform code
//! already reads, and the framebuffer / RSDP / SMBIOS / SMP / kernel-address
//! / module answers validated into one [`Snapshot`]. Limine loads a higher-half
//! kernel at a physical address of ITS choosing and maps it at the virtual
//! address the ELF links at; the kernel does not move itself to a fixed
//! place but records where it is ([`Snapshot::image_phys`], turned into the
//! slide `mmu::image_phys` applies) and runs there. Host-tested with
//! `#[path]` (`tests/host/x86-platform-tests`).
//!
//! **Provenance.** Written from the Limine protocol specification (PROTOCOL.md,
//! base revision 3) as the author recalls it, with no Limine binary or
//! header on hand to compare against. Every identifier and offset below is
//! therefore `[verify]` against a copy of `limine.h`, and nothing here has
//! been booted by a real Limine. Fields marked `[verify]` are the ones the
//! author is least sure of.
//!
//! Responses are reached through [`VirtMem`] (the kernel's live view in the
//! boot environment; a byte buffer in the host tests), never through a
//! struct cast, so the pointer-chasing is tested too.

/// Limine's common request magic. [verify]
pub const COMMON_MAGIC: [u64; 2] = [0xc7b1_dd30_df4c_8b88, 0x0a82_e883_a194_f07b];

/// The base-revision tag's first two words (the third is the revision). [verify]
pub const BASE_REVISION_MAGIC: [u64; 2] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc];
/// The base revision this kernel is written for. [verify]
pub const BASE_REVISION: u64 = 3;

/// `.limine_requests_start` marker words (lets the loader scan only the
/// requests section). [verify]
pub const REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];
/// `.limine_requests_end` marker words. [verify]
pub const REQUESTS_END_MARKER: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];

/// A request id: the common magic then the request's own two words.
pub const fn request_id(a: u64, b: u64) -> [u64; 4] {
    [COMMON_MAGIC[0], COMMON_MAGIC[1], a, b]
}

/// Request ids ([verify] each).
pub const ID_MEMMAP: [u64; 4] = request_id(0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62);
pub const ID_HHDM: [u64; 4] = request_id(0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b);
pub const ID_FRAMEBUFFER: [u64; 4] = request_id(0x9d58_27dc_d881_dd75, 0xa314_8604_f6fa_b11b);
pub const ID_RSDP: [u64; 4] = request_id(0xc5e7_7b6b_397e_7b43, 0x2763_7845_accd_cf3c);
pub const ID_SMBIOS: [u64; 4] = request_id(0x9e90_46f1_1e09_5391, 0xaa4a_520f_efbd_e5ee);
pub const ID_SMP: [u64; 4] = request_id(0x95a6_7b81_9a1b_857e, 0xa0b6_1b72_3b6a_73e0);
pub const ID_KERNEL_ADDRESS: [u64; 4] = request_id(0x71ba_7686_3cc5_5f63, 0xb264_4a48_c516_a487);
/// The module request (the files `module_path:` lines of limine.conf load):
/// both words checked against the v10 `BOOTX64.EFI`, which compares them as
/// immediates.
pub const ID_MODULE: [u64; 4] = request_id(0x3e7e_2797_02be_32af, 0xca1c_4f3b_d128_0cee);

/// Memory-map entry types (`LIMINE_MEMMAP_*`). [verify] (a newer spec adds
/// a "reserved but mapped" type; any unknown type maps to reserved.)
pub const MEMMAP_USABLE: u64 = 0;
pub const MEMMAP_RESERVED: u64 = 1;
pub const MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
pub const MEMMAP_ACPI_NVS: u64 = 3;
pub const MEMMAP_BAD_MEMORY: u64 = 4;
pub const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const MEMMAP_EXECUTABLE_AND_MODULES: u64 = 6;
pub const MEMMAP_FRAMEBUFFER: u64 = 7;

/// How far below the link address the loader's virtual base may be (ELF
/// headers ahead of the first section).
pub const MAX_HEADERS_BEFORE_IMAGE: u64 = 0x10_0000;

/// Entries kept from the loader's map (it carries a few dozen on QEMU).
pub const MAX_MMAP: usize = 256;
/// CPUs kept from the SMP response.
pub const MAX_CPUS: usize = 64;

/// One memory-map entry as the loader reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

/// A framebuffer the loader set up, with its address already physical.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FbInfo {
    pub phys: u64,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub red_size: u8,
    pub red_shift: u8,
    pub green_size: u8,
    pub green_shift: u8,
    pub blue_size: u8,
    pub blue_shift: u8,
}

impl FbInfo {
    /// Bytes the visible surface spans (`pitch * height`).
    pub const fn bytes(&self) -> u64 {
        self.pitch.saturating_mul(self.height)
    }
}

/// The SMP response, reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmpInfo {
    pub bsp_lapic_id: u32,
    pub x2apic: bool,
    /// CPUs the loader reported (may exceed `MAX_CPUS`).
    pub count: u64,
    /// LAPIC IDs of the first `min(count, MAX_CPUS)` CPUs, loader order.
    pub lapic_ids: [u32; MAX_CPUS],
}

/// Everything the loader's responses said, validated and copied out of
/// bootloader memory (which the boot gives back or reserves).
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    /// The revision the loader actually provides.
    pub loaded_revision: u64,
    pub hhdm: u64,
    pub kernel_phys: u64,
    pub kernel_virt: u64,
    /// Physical address the loader put the image's link address at.
    pub image_phys: u64,
    pub memmap: [MmapEntry; MAX_MMAP],
    pub n_memmap: usize,
    /// Physical address of the ACPI RSDP, 0 = none.
    pub rsdp: u64,
    /// Physical addresses of the SMBIOS entry points, 0 = none.
    pub smbios32: u64,
    pub smbios64: u64,
    pub fb: Option<FbInfo>,
    /// Framebuffers the loader reported (only the first is kept).
    pub fb_count: u64,
    pub smp: Option<SmpInfo>,
    /// The modules `(physical address, bytes)`, loader order.
    pub modules: [(u64, u64); super::bootinfo::MAX_MODULES],
    pub n_modules: usize,
    /// Modules the loader reported past `MAX_MODULES`.
    pub modules_dropped: u64,
    /// Why an optional response was dropped (the boot goes on without it).
    pub fb_error: Option<&'static str>,
    pub smp_error: Option<&'static str>,
    pub module_error: Option<&'static str>,
}

impl Snapshot {
    pub const EMPTY: Snapshot = Snapshot {
        loaded_revision: 0,
        hhdm: 0,
        kernel_phys: 0,
        kernel_virt: 0,
        image_phys: 0,
        memmap: [MmapEntry { base: 0, length: 0, kind: 0 }; MAX_MMAP],
        n_memmap: 0,
        rsdp: 0,
        smbios32: 0,
        smbios64: 0,
        fb: None,
        fb_count: 0,
        smp: None,
        modules: [(0, 0); super::bootinfo::MAX_MODULES],
        n_modules: 0,
        modules_dropped: 0,
        fb_error: None,
        smp_error: None,
        module_error: None,
    };

    pub fn memmap(&self) -> &[MmapEntry] {
        &self.memmap[..self.n_memmap]
    }

    pub fn modules(&self) -> &[(u64, u64)] {
        &self.modules[..self.n_modules]
    }
}

/// Why a response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The base-revision tag is not Limine's: the loader did not run us.
    NotLimine,
    /// The loader does not provide the base revision we ask for.
    UnsupportedRevision,
    NoMemmap,
    NoHhdm,
    NoKernelAddress,
    /// The kernel was loaded at a virtual address that is not its link
    /// address (a KASLR slide this position-dependent image cannot run at).
    KernelMoved,
    /// A response, or something it points to, is unreadable or inconsistent.
    Bad(&'static str),
}

/// A read-only view of the loader's address space. `read` returns `len`
/// bytes at virtual address `va`, or `None` if they are not all readable.
pub trait VirtMem {
    fn read(&self, va: u64, len: usize) -> Option<&[u8]>;
}

fn u64_at<M: VirtMem>(m: &M, va: u64) -> Option<u64> {
    let b = m.read(va, 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}
fn u32_at<M: VirtMem>(m: &M, va: u64) -> Option<u32> {
    let b = m.read(va, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u16_at<M: VirtMem>(m: &M, va: u64) -> Option<u16> {
    let b = m.read(va, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
fn u8_at<M: VirtMem>(m: &M, va: u64) -> Option<u8> {
    m.read(va, 1).map(|b| b[0])
}

/// The base-revision handshake. `words` is the three-word tag after the
/// loader ran: word 2 is zeroed when the revision we asked for is
/// supported; word 1 is replaced by the revision actually loaded (it keeps
/// the magic when the loader predates the field, meaning revision 0).
/// Returns the loaded revision. [verify]
pub fn check_base_revision(words: [u64; 3]) -> Result<u64, Error> {
    if words[0] != BASE_REVISION_MAGIC[0] {
        return Err(Error::NotLimine);
    }
    if words[2] != 0 {
        return Err(Error::UnsupportedRevision);
    }
    Ok(if words[1] == BASE_REVISION_MAGIC[1] { 0 } else { words[1] })
}

/// An address the loader reports for a firmware table (RSDP, SMBIOS): a
/// physical address under base revision 3, an HHDM virtual one before it.
/// Either way: subtract the HHDM offset when the address is above it.
pub fn normalize_pa(addr: u64, hhdm: u64) -> u64 {
    if addr != 0 && hhdm != 0 && addr >= hhdm { addr - hhdm } else { addr }
}

/// Map a Limine memory type to the E820 type the platform code reads.
///
/// Bootloader-reclaimable, executable/modules and framebuffer memory stay
/// RESERVED: the loader's parked APs still run in its memory, and the
/// framebuffer is device memory. Reclaiming the first two is a later step.
pub fn e820_kind(kind: u64) -> u32 {
    use super::bootinfo::{E820_ACPI, E820_NVS, E820_RAM, E820_RESERVED, E820_UNUSABLE};
    match kind {
        MEMMAP_USABLE => E820_RAM,
        MEMMAP_ACPI_RECLAIMABLE => E820_ACPI,
        MEMMAP_ACPI_NVS => E820_NVS,
        MEMMAP_BAD_MEMORY => E820_UNUSABLE,
        _ => E820_RESERVED,
    }
}

/// The loader's map as E820 entries, adjacent same-type ranges merged (the
/// loader splits RAM around its own allocations; the platform keeps
/// `MAX_MEM_ENTRIES`). Returns (entries stored, entries dropped).
pub fn to_e820(map: &[MmapEntry], out: &mut [super::bootinfo::MemEntry]) -> (usize, usize) {
    use super::bootinfo::MemEntry;
    let (mut n, mut dropped) = (0usize, 0usize);
    for e in map.iter().filter(|e| e.length != 0) {
        let kind = e820_kind(e.kind);
        if n > 0 && out[n - 1].kind == kind && out[n - 1].addr.saturating_add(out[n - 1].size) == e.base {
            out[n - 1].size = out[n - 1].size.saturating_add(e.length);
        } else if n < out.len() {
            out[n] = MemEntry { addr: e.base, size: e.length, kind, reserved: 0 };
            n += 1;
        } else {
            dropped += 1;
        }
    }
    (n, dropped)
}

// ── response parsing ────────────────────────────────────────────────────────

/// The response pointers the request structs hold after the loader ran
/// (0 = the loader answered nothing), plus the base-revision words.
#[derive(Clone, Copy, Debug, Default)]
pub struct Responses {
    pub base_revision: [u64; 3],
    pub memmap: u64,
    pub hhdm: u64,
    pub framebuffer: u64,
    pub rsdp: u64,
    pub smbios: u64,
    pub smp: u64,
    pub kernel_address: u64,
    pub module: u64,
}

fn parse_memmap<M: VirtMem>(m: &M, resp: u64, snap: &mut Snapshot) -> Result<(), Error> {
    // response: revision @0, entry_count @8, entries (pointer to pointers) @16
    let count = u64_at(m, resp + 8).ok_or(Error::Bad("memmap response"))?;
    let arr = u64_at(m, resp + 16).ok_or(Error::Bad("memmap response"))?;
    if count == 0 || count as usize > MAX_MMAP || arr == 0 {
        return Err(Error::Bad("memmap entry count"));
    }
    for i in 0..count {
        let p = u64_at(m, arr + i * 8).filter(|&p| p != 0).ok_or(Error::Bad("memmap entry pointer"))?;
        // entry: base @0, length @8, type @16
        let base = u64_at(m, p).ok_or(Error::Bad("memmap entry"))?;
        let length = u64_at(m, p + 8).ok_or(Error::Bad("memmap entry"))?;
        let kind = u64_at(m, p + 16).ok_or(Error::Bad("memmap entry"))?;
        if base.checked_add(length).is_none() {
            return Err(Error::Bad("memmap entry wraps"));
        }
        snap.memmap[i as usize] = MmapEntry { base, length, kind };
    }
    snap.n_memmap = count as usize;
    Ok(())
}

fn parse_framebuffer<M: VirtMem>(m: &M, resp: u64, hhdm: u64, snap: &mut Snapshot) -> Result<(), Error> {
    // response: revision @0, framebuffer_count @8, framebuffers (pointer to pointers) @16
    let count = u64_at(m, resp + 8).ok_or(Error::Bad("framebuffer response"))?;
    snap.fb_count = count;
    if count == 0 {
        return Ok(());
    }
    let arr = u64_at(m, resp + 16).ok_or(Error::Bad("framebuffer response"))?;
    let p = u64_at(m, arr).filter(|&p| p != 0).ok_or(Error::Bad("framebuffer pointer"))?;
    // framebuffer: address @0, width @8, height @16, pitch @24, bpp (u16) @32,
    // memory_model @34, red size/shift @35/36, green @37/38, blue @39/40. [verify]
    let rd = |off: u64| u64_at(m, p + off).ok_or(Error::Bad("framebuffer"));
    let (address, width, height, pitch) = (rd(0)?, rd(8)?, rd(16)?, rd(24)?);
    let bpp = u16_at(m, p + 32).ok_or(Error::Bad("framebuffer"))?;
    let model = u8_at(m, p + 34).ok_or(Error::Bad("framebuffer"))?;
    let mut c = [0u8; 6];
    for (i, slot) in c.iter_mut().enumerate() {
        *slot = u8_at(m, p + 35 + i as u64).ok_or(Error::Bad("framebuffer"))?;
    }
    if model != 1 {
        return Err(Error::Bad("framebuffer memory model is not RGB"));
    }
    if width == 0 || height == 0 || !matches!(bpp, 15 | 16 | 24 | 32) {
        return Err(Error::Bad("framebuffer geometry"));
    }
    let row = width.checked_mul(bpp.div_ceil(8) as u64).ok_or(Error::Bad("framebuffer geometry"))?;
    if pitch < row || pitch.checked_mul(height).is_none() {
        return Err(Error::Bad("framebuffer pitch"));
    }
    if address < hhdm || address - hhdm == 0 {
        return Err(Error::Bad("framebuffer address below the HHDM"));
    }
    snap.fb = Some(FbInfo {
        phys: address - hhdm,
        width,
        height,
        pitch,
        bpp,
        red_size: c[0],
        red_shift: c[1],
        green_size: c[2],
        green_shift: c[3],
        blue_size: c[4],
        blue_shift: c[5],
    });
    Ok(())
}

fn parse_smp<M: VirtMem>(m: &M, resp: u64) -> Result<SmpInfo, Error> {
    // response: revision @0, flags (u32) @8, bsp_lapic_id (u32) @12,
    // cpu_count @16, cpus (pointer to pointers) @24. mp_info: processor_id
    // (u32) @0, lapic_id (u32) @4. [verify]
    let flags = u32_at(m, resp + 8).ok_or(Error::Bad("smp response"))?;
    let bsp = u32_at(m, resp + 12).ok_or(Error::Bad("smp response"))?;
    let count = u64_at(m, resp + 16).ok_or(Error::Bad("smp response"))?;
    let arr = u64_at(m, resp + 24).ok_or(Error::Bad("smp response"))?;
    if count == 0 || arr == 0 {
        return Err(Error::Bad("smp cpu count"));
    }
    let mut info = SmpInfo { bsp_lapic_id: bsp, x2apic: flags & 1 != 0, count, lapic_ids: [0; MAX_CPUS] };
    for i in 0..count.min(MAX_CPUS as u64) {
        let p = u64_at(m, arr + i * 8).filter(|&p| p != 0).ok_or(Error::Bad("smp cpu pointer"))?;
        info.lapic_ids[i as usize] = u32_at(m, p + 4).ok_or(Error::Bad("smp cpu"))?;
    }
    Ok(info)
}

fn parse_modules<M: VirtMem>(m: &M, resp: u64, hhdm: u64, snap: &mut Snapshot) -> Result<(), Error> {
    // response: revision @0, module_count @8, modules (pointer to pointers)
    // @16. file: revision @0, address @8, size @16, then the path and the
    // media fields, unread.
    let count = u64_at(m, resp + 8).ok_or(Error::Bad("module response"))?;
    if count == 0 {
        return Ok(());
    }
    let arr = u64_at(m, resp + 16).filter(|&a| a != 0).ok_or(Error::Bad("module response"))?;
    let keep = count.min(snap.modules.len() as u64);
    for i in 0..keep {
        let p = u64_at(m, arr + i * 8).filter(|&p| p != 0).ok_or(Error::Bad("module pointer"))?;
        let address = u64_at(m, p + 8).ok_or(Error::Bad("module"))?;
        let size = u64_at(m, p + 16).ok_or(Error::Bad("module"))?;
        let pa = normalize_pa(address, hhdm);
        if size == 0 || pa == 0 || pa.checked_add(size).is_none() {
            return Err(Error::Bad("module address or size"));
        }
        snap.modules[i as usize] = (pa, size);
    }
    snap.n_modules = keep as usize;
    snap.modules_dropped = count - keep;
    Ok(())
}

/// Read every response into one validated [`Snapshot`]. The memory map, the
/// HHDM and the kernel address are required; the rest are optional (absent
/// = the field stays empty). `link_virt` is the address the image is linked
/// to run at (`_text_start`: `KERNEL_VA_OFFSET` + the script's link base).
pub fn parse<M: VirtMem>(m: &M, r: &Responses, link_virt: u64) -> Result<Snapshot, Error> {
    let mut snap = Snapshot::EMPTY;
    snap.loaded_revision = check_base_revision(r.base_revision)?;

    if r.hhdm == 0 {
        return Err(Error::NoHhdm);
    }
    snap.hhdm = u64_at(m, r.hhdm + 8).filter(|&h| h != 0).ok_or(Error::Bad("hhdm response"))?;

    if r.kernel_address == 0 {
        return Err(Error::NoKernelAddress);
    }
    // response: revision @0, physical_base @8, virtual_base @16
    snap.kernel_phys = u64_at(m, r.kernel_address + 8).ok_or(Error::Bad("kernel address response"))?;
    snap.kernel_virt = u64_at(m, r.kernel_address + 16).ok_or(Error::Bad("kernel address response"))?;
    // The loader's virtual base is the lowest address of the first segment:
    // the link address, or a little below it where the linker put the ELF
    // headers in front of the first section. Anything else is a slide.
    if snap.kernel_virt > link_virt || link_virt - snap.kernel_virt >= MAX_HEADERS_BEFORE_IMAGE {
        return Err(Error::KernelMoved);
    }
    snap.image_phys = snap.kernel_phys + (link_virt - snap.kernel_virt);

    if r.memmap == 0 {
        return Err(Error::NoMemmap);
    }
    parse_memmap(m, r.memmap, &mut snap)?;

    if r.rsdp != 0 {
        // response: revision @0, address @8
        let a = u64_at(m, r.rsdp + 8).ok_or(Error::Bad("rsdp response"))?;
        snap.rsdp = normalize_pa(a, snap.hhdm);
    }
    if r.smbios != 0 {
        // response: revision @0, entry_32 @8, entry_64 @16
        let a32 = u64_at(m, r.smbios + 8).ok_or(Error::Bad("smbios response"))?;
        let a64 = u64_at(m, r.smbios + 16).ok_or(Error::Bad("smbios response"))?;
        snap.smbios32 = normalize_pa(a32, snap.hhdm);
        snap.smbios64 = normalize_pa(a64, snap.hhdm);
    }
    // The optional answers never stop the boot: a bad one is dropped and
    // the reason kept for the log.
    if r.framebuffer != 0 {
        if let Err(Error::Bad(why)) = parse_framebuffer(m, r.framebuffer, snap.hhdm, &mut snap) {
            snap.fb = None;
            snap.fb_error = Some(why);
        }
    }
    if r.smp != 0 {
        match parse_smp(m, r.smp) {
            Ok(s) => snap.smp = Some(s),
            Err(Error::Bad(why)) => snap.smp_error = Some(why),
            Err(_) => {}
        }
    }
    if r.module != 0 {
        if let Err(Error::Bad(why)) = parse_modules(m, r.module, snap.hhdm, &mut snap) {
            snap.n_modules = 0;
            snap.module_error = Some(why);
        }
    }
    Ok(snap)
}
