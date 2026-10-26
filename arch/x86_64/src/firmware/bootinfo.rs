// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PVH boot protocol's facts and the decisions taken from them, pure:
//! the `hvm_start_info` layout, the E820 map reduced to the one RAM range
//! the common memory admission takes plus the holes inside it, the kernel
//! command line's `virtio_mmio.device=` entries, and the choice of the AP
//! trampoline page. Host-tested with `#[path]`
//! (`tests/host/x86-platform-tests`).

/// PVH `hvm_start_info` (xen/include/public/arch-x86/hvm/start_info.h).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HvmStartInfo {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    pub reserved: u32,
}

/// One PVH memory-map entry (E820 types).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemEntry {
    pub addr: u64,
    pub size: u64,
    pub kind: u32,
    pub reserved: u32,
}

/// One PVH module-list entry (`hvm_modlist_entry`): a file the loader put
/// in memory for the kernel (QEMU's `-initrd`; the Limine entry builds the
/// same list from its module response).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModEntry {
    pub paddr: u64,
    pub size: u64,
    pub cmdline_paddr: u64,
    pub reserved: u64,
}

/// The modules this boot keeps (the microcode image is the only user).
pub const MAX_MODULES: usize = 4;

pub const PVH_MAGIC: u32 = 0x336e_c578;
/// `HvmStartInfo::flags` bit the Limine entry sets on the PVH-shaped record
/// it builds from Limine's responses (a bit no Xen flag uses): the platform
/// code then knows the machine is a PC, not a microvm.
pub const START_INFO_LIMINE: u32 = 1 << 31;
pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const E820_ACPI: u32 = 3;
pub const E820_NVS: u32 = 4;
pub const E820_UNUSABLE: u32 = 5;

/// The map entries this boot keeps (PVH maps on QEMU carry well under ten).
pub const MAX_MEM_ENTRIES: usize = 64;

/// The span the PMM manages: from 0 to the end of the highest RAM entry
/// below `limit` (the PMM's own reach). Everything not RAM inside it is a
/// hole the caller reserves ([`for_each_hole`]). `None` without RAM.
pub fn ram_span(map: &[MemEntry], limit: u64) -> Option<(u64, u64)> {
    let end = map.iter()
        .filter(|e| e.kind == E820_RAM && e.size != 0)
        .map(|e| e.addr.saturating_add(e.size).min(limit))
        .filter(|&end| end > 0)
        .max()?;
    Some((0, end & !0xFFF))
}

/// Call `f(start, len)` for every page-aligned gap in `[0, end)` that no RAM
/// entry covers (reserved, ACPI, NVS, unusable, or simply absent), in
/// address order. Overlapping and unsorted entries are fine.
pub fn for_each_hole(map: &[MemEntry], end: u64, mut f: impl FnMut(u64, u64)) {
    // RAM ranges, page-shrunk (a partial page of RAM is not a usable page),
    // sorted by start: insertion sort into a fixed array.
    let mut ram = [(0u64, 0u64); MAX_MEM_ENTRIES];
    let mut n = 0;
    for e in map.iter().filter(|e| e.kind == E820_RAM) {
        let s = (e.addr + 0xFFF) & !0xFFF;
        let t = e.addr.saturating_add(e.size) & !0xFFF;
        if t <= s || n == MAX_MEM_ENTRIES {
            continue;
        }
        let mut i = n;
        while i > 0 && ram[i - 1].0 > s {
            ram[i] = ram[i - 1];
            i -= 1;
        }
        ram[i] = (s, t);
        n += 1;
    }
    let mut cursor = 0u64;
    for &(s, t) in &ram[..n] {
        if s >= end {
            break;
        }
        if s > cursor {
            f(cursor, s - cursor);
        }
        cursor = cursor.max(t);
    }
    if cursor < end {
        f(cursor, end - cursor);
    }
}

/// [`for_each_hole`] less the ranges `keep` (`(start, len)` each): the holes
/// the direct map leaves out. The kernel image and the boot modules are
/// memory the loader reports as reserved (Limine's executable-and-modules
/// memory), yet their frames stay in the direct map like every RAM frame the
/// kernel owns, so the ranges are cut out of the holes. A hole a range
/// splits comes out as two, in address order.
pub fn for_each_hole_except(map: &[MemEntry], end: u64, keep: &[(u64, u64)], mut f: impl FnMut(u64, u64)) {
    for_each_hole(map, end, |s, l| cut(s, s + l, keep, &mut f));
}

/// `[s, e)` less every range of `keep`, in address order. The first range
/// that overlaps splits it; the pieces go on against the ranges after it
/// (the ones before overlap neither piece).
fn cut(s: u64, e: u64, keep: &[(u64, u64)], f: &mut impl FnMut(u64, u64)) {
    let hit = keep.iter().position(|&(ks, kl)| kl != 0 && ks < e && s < ks.saturating_add(kl));
    let Some(i) = hit else {
        if s < e {
            f(s, e - s);
        }
        return;
    };
    let (ks, ke) = (keep[i].0, keep[i].0.saturating_add(keep[i].1));
    if s < ks {
        cut(s, ks, &keep[i + 1..], f);
    }
    if ke < e {
        cut(ke, e, &keep[i + 1..], f);
    }
}

/// Is `[pa, pa + len)` entirely inside one RAM entry?
pub fn is_ram(map: &[MemEntry], pa: u64, len: u64) -> bool {
    map.iter().any(|e| e.kind == E820_RAM && e.addr <= pa && pa.saturating_add(len) <= e.addr.saturating_add(e.size))
}

/// The AP trampoline page: a 4 KiB RAM page below 1 MiB, above the real-mode
/// IVT/BDA page, overlapping none of `avoid` (the start_info, the memory
/// map, the command line, the ACPI tables). `want` != 0 is a forced choice
/// (Kconfig `X86_AP_TRAMPOLINE_PA`), taken only if it passes the same
/// checks; 0 searches downward from the top of conventional memory.
pub fn pick_trampoline(map: &[MemEntry], avoid: &[(u64, u64)], want: u64) -> Option<u64> {
    let ok = |pa: u64| {
        pa & 0xFFF == 0
            && pa >= 0x1000
            && pa + 0x1000 <= 0x10_0000
            && is_ram(map, pa, 0x1000)
            && !avoid.iter().any(|&(s, l)| l != 0 && s < pa + 0x1000 && pa < s.saturating_add(l))
    };
    if want != 0 {
        return if ok(want) { Some(want) } else { None };
    }
    let mut pa = 0x9_F000u64;
    while pa >= 0x1000 {
        if ok(pa) {
            return Some(pa);
        }
        pa -= 0x1000;
    }
    None
}

/// Where the PMM's frame descriptors go: the lowest page-aligned address at
/// or above `min` with `bytes` of one RAM entry clear of every `avoid` span
/// (the kernel image, the boot information, the trampoline page), or `None`.
/// The PMM reserves everything below the descriptors' end, so the lower the
/// better, and the image can sit anywhere in RAM: the lowest fit is `min`, a
/// RAM entry's start, or the end of an avoided span.
pub fn pick_pmm_floor(map: &[MemEntry], avoid: &[(u64, u64)], bytes: u64, min: u64) -> Option<u64> {
    let up = |a: u64| (a.saturating_add(0xFFF)) & !0xFFF;
    let fits = |a: u64| {
        a >= min
            && is_ram(map, a, bytes)
            && !avoid.iter().any(|&(s, l)| l != 0 && s < a.saturating_add(bytes) && a < s.saturating_add(l))
    };
    let starts = map.iter().filter(|e| e.kind == E820_RAM).map(|e| up(e.addr));
    let ends = avoid.iter().map(|&(s, l)| up(s.saturating_add(l)));
    core::iter::once(up(min)).chain(starts).chain(ends).filter(|&a| fits(a)).min()
}

/// One `virtio_mmio.device=<size>@<base>:<irq>[:<id>]` entry (Linux's
/// syntax, which QEMU microvm appends when it boots without ACPI).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioMmio {
    pub base: u64,
    pub size: u64,
    pub gsi: u32,
}

/// A number with an optional `0x` prefix.
fn parse_num(s: &[u8]) -> Option<u64> {
    let (digits, radix) = match s {
        [b'0', b'x' | b'X', rest @ ..] => (rest, 16),
        _ => (s, 10),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in digits {
        let d = (c as char).to_digit(radix)? as u64;
        v = v.checked_mul(radix as u64)?.checked_add(d)?;
    }
    Some(v)
}

/// Linux `memparse`: a number with an optional K/M/G suffix.
fn parse_size(s: &[u8]) -> Option<u64> {
    let (num, shift) = match s.last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 10),
        b'm' | b'M' => (&s[..s.len() - 1], 20),
        b'g' | b'G' => (&s[..s.len() - 1], 30),
        _ => (s, 0),
    };
    parse_num(num)?.checked_mul(1u64 << shift)
}

/// Parse one entry's value (after the `=`).
pub fn parse_virtio_mmio_value(v: &[u8]) -> Option<VirtioMmio> {
    let at = v.iter().position(|&c| c == b'@')?;
    let size = parse_size(&v[..at])?;
    let rest = &v[at + 1..];
    let colon = rest.iter().position(|&c| c == b':')?;
    let base = parse_num(&rest[..colon])?;
    let irq_part = &rest[colon + 1..];
    let irq_end = irq_part.iter().position(|&c| c == b':').unwrap_or(irq_part.len());
    let gsi = parse_num(&irq_part[..irq_end])?;
    if size == 0 || base == 0 || gsi > u32::MAX as u64 {
        return None;
    }
    Some(VirtioMmio { base, size, gsi: gsi as u32 })
}

/// Every `virtio_mmio.device=` entry on `cmdline` (NUL or end terminated),
/// into `out`. Returns (stored, malformed); entries past `out` are dropped.
pub fn parse_virtio_mmio(cmdline: &[u8], out: &mut [VirtioMmio]) -> (usize, usize) {
    const KEY: &[u8] = b"virtio_mmio.device=";
    let end = cmdline.iter().position(|&c| c == 0).unwrap_or(cmdline.len());
    let (mut n, mut bad) = (0, 0);
    for tok in cmdline[..end].split(|&c| c == b' ' || c == b'\t' || c == b'\n') {
        if let Some(v) = tok.strip_prefix(KEY) {
            match parse_virtio_mmio_value(v) {
                Some(d) if n < out.len() => {
                    out[n] = d;
                    n += 1;
                }
                Some(_) => {}
                None => bad += 1,
            }
        }
    }
    (n, bad)
}

/// QEMU microvm's virtio-mmio IRQ layout when the command line does not
/// carry it (hw/i386/microvm.c `microvm_devices_init`): with the second
/// IOAPIC (GSI base 24) every transport has a line there, 24 of them; with
/// ACPI but one IOAPIC, GSIs 16..23; without ACPI, GSIs 5..12. Returns
/// (first GSI, transports).
pub const fn microvm_virtio_layout(acpi: bool, second_ioapic: bool) -> (u32, usize) {
    if second_ioapic {
        (24, 24)
    } else if acpi {
        (16, 8)
    } else {
        (5, 8)
    }
}
