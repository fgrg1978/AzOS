// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Limine response parsing on synthetic loader memory: the pointer chasing
//! (response -> array of pointers -> entry), the base-revision handshake,
//! the E820 reduction, the framebuffer / RSDP / SMP answers and where the
//! page allocator's frame descriptors go around an image the loader placed. Each refusal test corrupts one thing and checks the
//! error names it. (The image is not moved: where the loader put it is
//! recorded as a slide, tested with the paging code in `arch-tests`.)

use super::bootinfo::{self, MemEntry};
use super::limine::{self as lm, Error, MmapEntry, Responses, VirtMem};

const HHDM: u64 = 0xffff_8000_0000_0000;
const LINK_VIRT: u64 = 0xffff_ffff_8010_0000;
const KB: u64 = 1024;
const MB: u64 = 1024 * KB;

/// Loader memory: a byte image at a virtual base.
struct Mem {
    base: u64,
    bytes: Vec<u8>,
}

impl Mem {
    fn new(base: u64) -> Self {
        Mem { base, bytes: vec![0; 0x4000] }
    }
    fn put(&mut self, va: u64, data: &[u8]) {
        let off = (va - self.base) as usize;
        self.bytes[off..off + data.len()].copy_from_slice(data);
    }
    fn u64(&mut self, va: u64, v: u64) {
        self.put(va, &v.to_le_bytes());
    }
    fn u32(&mut self, va: u64, v: u32) {
        self.put(va, &v.to_le_bytes());
    }
}

impl VirtMem for Mem {
    fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let off = va.checked_sub(self.base)? as usize;
        self.bytes.get(off..off.checked_add(len)?)
    }
}

const B: u64 = HHDM + 0x10_0000; // where the synthetic loader memory lives
const OK_WORDS: [u64; 3] = [lm::BASE_REVISION_MAGIC[0], 3, 0];

fn memmap(m: &mut Mem, at: u64, entries: &[(u64, u64, u64)]) -> u64 {
    // response at `at`, pointer array at +0x100, entries at +0x400
    m.u64(at + 8, entries.len() as u64);
    m.u64(at + 16, at + 0x100);
    for (i, &(base, len, kind)) in entries.iter().enumerate() {
        let e = at + 0x400 + 24 * i as u64;
        m.u64(at + 0x100 + 8 * i as u64, e);
        m.u64(e, base);
        m.u64(e + 8, len);
        m.u64(e + 16, kind);
    }
    at
}

/// A complete, valid set of responses; the tests damage one at a time.
fn good() -> (Mem, Responses) {
    let mut m = Mem::new(B);
    let hhdm = B + 0x100;
    m.u64(hhdm + 8, HHDM);
    let ka = B + 0x200;
    m.u64(ka + 8, 0x3f00_0000);
    m.u64(ka + 16, LINK_VIRT);
    let mm = memmap(&mut m, B + 0x1000, &[
        (0, 0x9_f000, lm::MEMMAP_USABLE),
        (0x9_f000, 0x6_1000, lm::MEMMAP_RESERVED),
        (0x10_0000, 0x3ee0_0000, lm::MEMMAP_USABLE),
        (0x3f00_0000, 0x20_0000, lm::MEMMAP_EXECUTABLE_AND_MODULES),
        (0x3f20_0000, 0x10_0000, lm::MEMMAP_BOOTLOADER_RECLAIMABLE),
        (0xfd00_0000, 0x100_0000, lm::MEMMAP_FRAMEBUFFER),
    ]);
    let rsdp = B + 0x300;
    m.u64(rsdp + 8, 0xe_0000);
    let smbios = B + 0x320;
    m.u64(smbios + 8, HHDM + 0xf_0000);
    m.u64(smbios + 16, 0);
    // framebuffer: response, pointer array, one 1024x768x32 framebuffer
    let fbr = B + 0x340;
    let (arr, fb) = (B + 0x360, B + 0x380);
    m.u64(fbr + 8, 1);
    m.u64(fbr + 16, arr);
    m.u64(arr, fb);
    m.u64(fb, HHDM + 0xfd00_0000);
    m.u64(fb + 8, 1024);
    m.u64(fb + 16, 768);
    m.u64(fb + 24, 4096);
    m.put(fb + 32, &32u16.to_le_bytes());
    m.put(fb + 34, &[1, 8, 16, 8, 8, 8, 0]);
    // smp: x2apic off, bsp 0, three CPUs with lapic ids 0, 2, 4
    let smp = B + 0x3c0;
    m.u32(smp + 8, 0);
    m.u32(smp + 12, 0);
    m.u64(smp + 16, 3);
    m.u64(smp + 24, B + 0x3e0);
    for i in 0..3u64 {
        let info = B + 0x2000 + 32 * i;
        m.u64(B + 0x3e0 + 8 * i, info);
        m.u32(info, i as u32);
        m.u32(info + 4, 2 * i as u32);
    }
    // modules: two files, the first at an HHDM address, the second already
    // physical (both are normalised).
    let module = B + 0x3000;
    m.u64(module + 8, 2);
    m.u64(module + 16, B + 0x3020);
    for (i, (addr, size)) in [(HHDM + 0x3f10_0000, 0x1_2345u64), (0x3f18_0000, 0x200)].into_iter().enumerate() {
        let file = B + 0x3040 + 0x40 * i as u64;
        m.u64(B + 0x3020 + 8 * i as u64, file);
        m.u64(file + 8, addr);
        m.u64(file + 16, size);
    }
    let r = Responses {
        base_revision: OK_WORDS,
        memmap: mm,
        hhdm,
        framebuffer: fbr,
        rsdp,
        smbios,
        smp,
        kernel_address: ka,
        module,
    };
    (m, r)
}

#[test]
fn a_complete_set_of_responses_parses() {
    let (m, r) = good();
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert_eq!(s.loaded_revision, 3);
    assert_eq!(s.hhdm, HHDM);
    assert_eq!((s.kernel_phys, s.kernel_virt), (0x3f00_0000, LINK_VIRT));
    assert_eq!(s.n_memmap, 6);
    assert_eq!(s.memmap()[2], MmapEntry { base: 0x10_0000, length: 0x3ee0_0000, kind: lm::MEMMAP_USABLE });
    assert_eq!(s.rsdp, 0xe_0000);
    assert_eq!(s.smbios32, 0xf_0000, "a virtual SMBIOS address is normalised to physical");
    assert_eq!(s.smbios64, 0);
    let fb = s.fb.unwrap();
    assert_eq!((fb.phys, fb.width, fb.height, fb.pitch, fb.bpp), (0xfd00_0000, 1024, 768, 4096, 32));
    assert_eq!((fb.red_size, fb.red_shift, fb.green_shift, fb.blue_shift), (8, 16, 8, 0));
    assert_eq!(fb.bytes(), 4096 * 768);
    let smp = s.smp.unwrap();
    assert_eq!((smp.bsp_lapic_id, smp.x2apic, smp.count), (0, false, 3));
    assert_eq!(&smp.lapic_ids[..3], &[0, 2, 4]);
    assert_eq!(s.modules(), &[(0x3f10_0000, 0x1_2345), (0x3f18_0000, 0x200)]);
}

#[test]
fn the_base_revision_handshake() {
    let m = lm::BASE_REVISION_MAGIC;
    assert_eq!(lm::check_base_revision([m[0], 3, 0]), Ok(3), "supported: word 2 zeroed, word 1 the loaded revision");
    assert_eq!(lm::check_base_revision([m[0], m[1], 0]), Ok(0), "word 1 untouched: revision 0");
    assert_eq!(lm::check_base_revision([m[0], m[1], 3]), Err(Error::UnsupportedRevision), "word 2 left set: refused");
    assert_eq!(lm::check_base_revision([0, m[1], 0]), Err(Error::NotLimine));
}

#[test]
fn an_unsupported_base_revision_refuses_everything() {
    let (m, mut r) = good();
    r.base_revision = [lm::BASE_REVISION_MAGIC[0], lm::BASE_REVISION_MAGIC[1], 3];
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::UnsupportedRevision);
}

#[test]
fn the_required_responses_are_required() {
    let (m, r) = good();
    let mut x = r;
    x.memmap = 0;
    assert_eq!(lm::parse(&m, &x, LINK_VIRT).unwrap_err(), Error::NoMemmap);
    let mut x = r;
    x.hhdm = 0;
    assert_eq!(lm::parse(&m, &x, LINK_VIRT).unwrap_err(), Error::NoHhdm);
    let mut x = r;
    x.kernel_address = 0;
    assert_eq!(lm::parse(&m, &x, LINK_VIRT).unwrap_err(), Error::NoKernelAddress);
}

#[test]
fn the_optional_responses_are_optional() {
    let (m, r) = good();
    let x = Responses { framebuffer: 0, rsdp: 0, smbios: 0, smp: 0, module: 0, ..r };
    let s = lm::parse(&m, &x, LINK_VIRT).unwrap();
    assert!(s.fb.is_none() && s.smp.is_none());
    assert_eq!((s.rsdp, s.smbios32, s.smbios64), (0, 0, 0));
}

#[test]
fn a_kernel_loaded_at_another_virtual_address_is_refused() {
    let (mut m, r) = good();
    m.u64(r.kernel_address + 16, LINK_VIRT + 0x20_0000); // slid up
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::KernelMoved);
    m.u64(r.kernel_address + 16, LINK_VIRT - 0x20_0000); // or far below
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::KernelMoved);
}

#[test]
fn the_image_physical_address_follows_the_loaders_base() {
    let (mut m, r) = good();
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap().image_phys, 0x3f00_0000);
    // Headers ahead of the first section: the base is one page below the
    // link address, so the link address sits one page above the base.
    m.u64(r.kernel_address + 16, LINK_VIRT - 0x1000);
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap().image_phys, 0x3f00_1000);
}

#[test]
fn a_memory_map_pointing_nowhere_is_refused() {
    let (mut m, r) = good();
    m.u64(r.memmap + 0x100, 0);
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::Bad("memmap entry pointer"));
    let (mut m, r) = good();
    m.u64(r.memmap + 0x100, 0x1000); // below the loader memory
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::Bad("memmap entry"));
    let (mut m, r) = good();
    m.u64(r.memmap + 8, lm::MAX_MMAP as u64 + 1);
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::Bad("memmap entry count"));
    let (mut m, r) = good();
    m.u64(r.memmap + 0x400, 0x1000);
    m.u64(r.memmap + 0x400 + 8, u64::MAX); // an entry that wraps the address space
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap_err(), Error::Bad("memmap entry wraps"));
}

#[test]
fn the_rsdp_is_physical_whichever_way_the_loader_reports_it() {
    assert_eq!(lm::normalize_pa(HHDM + 0xe_0000, HHDM), 0xe_0000, "revision < 3: an HHDM address");
    assert_eq!(lm::normalize_pa(0xe_0000, HHDM), 0xe_0000, "revision 3: already physical");
    assert_eq!(lm::normalize_pa(0, HHDM), 0, "no table stays none");
    let (mut m, r) = good();
    m.u64(r.rsdp + 8, HHDM + 0xe_1000);
    assert_eq!(lm::parse(&m, &r, LINK_VIRT).unwrap().rsdp, 0xe_1000);
}

#[test]
fn the_memory_map_becomes_the_e820_the_platform_reads() {
    let (m, r) = good();
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    let mut out = [MemEntry::default(); bootinfo::MAX_MEM_ENTRIES];
    let (n, dropped) = lm::to_e820(s.memmap(), &mut out);
    assert_eq!(dropped, 0);
    // usable | reserved | usable | (kernel + bootloader + ... merged reserved) | framebuffer reserved
    assert_eq!(out[0], MemEntry { addr: 0, size: 0x9_f000, kind: bootinfo::E820_RAM, reserved: 0 });
    assert_eq!(out[1].kind, bootinfo::E820_RESERVED);
    assert_eq!(out[2], MemEntry { addr: 0x10_0000, size: 0x3ee0_0000, kind: bootinfo::E820_RAM, reserved: 0 });
    assert_eq!(out[3], MemEntry { addr: 0x3f00_0000, size: 0x30_0000, kind: bootinfo::E820_RESERVED, reserved: 0 },
        "the kernel's and the loader's ranges are adjacent reserved memory: one entry");
    assert_eq!(n, 5);
    // The platform's own reduction accepts it: RAM span and holes.
    assert_eq!(bootinfo::ram_span(&out[..n], u64::MAX), Some((0, 0x3ef0_0000)));
}

#[test]
fn every_limine_type_has_an_e820_type_and_unknown_ones_stay_reserved() {
    assert_eq!(lm::e820_kind(lm::MEMMAP_USABLE), bootinfo::E820_RAM);
    assert_eq!(lm::e820_kind(lm::MEMMAP_ACPI_RECLAIMABLE), bootinfo::E820_ACPI);
    assert_eq!(lm::e820_kind(lm::MEMMAP_ACPI_NVS), bootinfo::E820_NVS);
    assert_eq!(lm::e820_kind(lm::MEMMAP_BAD_MEMORY), bootinfo::E820_UNUSABLE);
    for k in [lm::MEMMAP_RESERVED, lm::MEMMAP_BOOTLOADER_RECLAIMABLE, lm::MEMMAP_EXECUTABLE_AND_MODULES,
              lm::MEMMAP_FRAMEBUFFER, 8, 99] {
        assert_eq!(lm::e820_kind(k), bootinfo::E820_RESERVED, "type {k}");
    }
}

#[test]
fn entries_past_the_platforms_capacity_are_counted_not_lost_silently() {
    // 40 alternating usable / reserved pages cannot merge: 40 entries into 16.
    let map: Vec<MmapEntry> = (0..40)
        .map(|i| MmapEntry {
            base: i * 0x1000,
            length: 0x1000,
            kind: if i % 2 == 0 { lm::MEMMAP_USABLE } else { lm::MEMMAP_RESERVED },
        })
        .collect();
    let mut out = [MemEntry::default(); 16];
    assert_eq!(lm::to_e820(&map, &mut out), (16, 24));
}

#[test]
fn a_gap_between_same_type_ranges_is_not_merged_over() {
    let map = [
        MmapEntry { base: 0x1000, length: 0x1000, kind: lm::MEMMAP_USABLE },
        MmapEntry { base: 0x3000, length: 0x1000, kind: lm::MEMMAP_USABLE },
    ];
    let mut out = [MemEntry::default(); 4];
    assert_eq!(lm::to_e820(&map, &mut out), (2, 0));
}

fn fb_mut(f: impl FnOnce(&mut Mem, u64)) -> Result<lm::Snapshot, Error> {
    let (mut m, r) = good();
    f(&mut m, B + 0x380);
    lm::parse(&m, &r, LINK_VIRT)
}

#[test]
fn a_bad_framebuffer_is_dropped_and_the_boot_goes_on() {
    let s = fb_mut(|m, fb| m.put(fb + 34, &[0])).unwrap();
    assert!(s.fb.is_none());
    assert_eq!(s.fb_error, Some("framebuffer memory model is not RGB"));

    let s = fb_mut(|m, fb| m.u64(fb + 24, 1024 * 4 - 4)).unwrap();
    assert_eq!(s.fb_error, Some("framebuffer pitch"), "a pitch shorter than a row");

    let s = fb_mut(|m, fb| m.put(fb + 32, &8u16.to_le_bytes())).unwrap();
    assert_eq!(s.fb_error, Some("framebuffer geometry"), "an indexed (8 bpp) mode");

    let s = fb_mut(|m, fb| m.u64(fb, 0x1000)).unwrap();
    assert_eq!(s.fb_error, Some("framebuffer address below the HHDM"));

    let s = fb_mut(|m, fb| m.u64(fb + 8, 0)).unwrap();
    assert_eq!(s.fb_error, Some("framebuffer geometry"), "zero width");

    // The map and the rest are intact either way.
    assert_eq!(s.n_memmap, 6);
    assert!(s.smp.is_some());
}

#[test]
fn zero_framebuffers_is_not_an_error() {
    let (mut m, r) = good();
    m.u64(r.framebuffer + 8, 0);
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert!(s.fb.is_none() && s.fb_error.is_none() && s.fb_count == 0);
}

#[test]
fn the_smp_response_reports_the_cpus_and_the_x2apic_mode() {
    let (mut m, r) = good();
    m.u32(r.smp + 8, 1);
    m.u32(r.smp + 12, 4);
    let smp = lm::parse(&m, &r, LINK_VIRT).unwrap().smp.unwrap();
    assert!(smp.x2apic);
    assert_eq!(smp.bsp_lapic_id, 4);
    // A broken CPU pointer drops the SMP answer, not the boot.
    let (mut m, r) = good();
    m.u64(B + 0x3e0 + 8, 0);
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert!(s.smp.is_none());
    assert_eq!(s.smp_error, Some("smp cpu pointer"));
}

#[test]
fn the_module_response_lists_the_files_and_a_bad_one_drops_only_itself() {
    // More modules than the platform keeps: counted.
    let (mut m, r) = good();
    let n = bootinfo::MAX_MODULES as u64 + 2;
    m.u64(r.module + 8, n);
    for i in 0..n {
        let file = B + 0x3200 + 0x40 * i;
        m.u64(B + 0x3100 + 8 * i, file);
        m.u64(file + 8, HHDM + 0x4000_0000 + 0x1000 * i);
        m.u64(file + 16, 0x1000);
    }
    m.u64(r.module + 16, B + 0x3100);
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert_eq!((s.n_modules, s.modules_dropped), (bootinfo::MAX_MODULES, 2));
    assert_eq!(s.modules()[1], (0x4000_1000, 0x1000));
    // An empty file drops the answer (no module is trusted), not the boot.
    let (mut m, r) = good();
    m.u64(B + 0x3040 + 0x40 + 16, 0);
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert_eq!((s.n_modules, s.module_error), (0, Some("module address or size")));
    // Zero modules is no error.
    let (mut m, r) = good();
    m.u64(r.module + 8, 0);
    let s = lm::parse(&m, &r, LINK_VIRT).unwrap();
    assert!(s.modules().is_empty() && s.module_error.is_none());
}

// ── the PMM floor around an image the loader placed ─────────────────────────

/// The memory map of a q35 under OVMF with 256 MiB: low RAM, a 7 MiB window
/// at 1 MiB that firmware reservations end, then the big span.
fn q35_map() -> Vec<MemEntry> {
    let e = |addr, size, kind| MemEntry { addr, size, kind, reserved: 0 };
    vec![
        e(0, 0x9_f000, bootinfo::E820_RAM),
        e(0x10_0000, 7 * MB, bootinfo::E820_RAM),
        e(0x80_0000, 0x1_0000, bootinfo::E820_RESERVED),
        e(0x81_0000, 0x6f8_0000 - 0x81_0000 + 0x1000_0000 - 0x6f8_0000, bootinfo::E820_RAM),
    ]
}

#[test]
fn the_descriptors_go_at_the_lowest_ram_above_the_first_mib() {
    let map = q35_map();
    // 1 MiB of descriptors, an image far up: the first MiB above 1 MiB.
    let image = (0xE00_0000u64, 10 * MB);
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[image], MB, MB), Some(MB));
    // Never below `min`, even where RAM starts at 0.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[], MB, 2 * MB), Some(2 * MB));
}

#[test]
fn the_descriptors_step_over_the_image_and_the_boot_information() {
    let map = q35_map();
    // The image sits where the descriptors would go: just after it.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[(MB, 3 * MB)], MB, MB), Some(4 * MB));
    // Boot information in the middle of the window pushes them past it too.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[(MB, 3 * MB), (4 * MB + 0x2000, 0x1000)], MB, MB),
               Some(4 * MB + 0x3000));
    // The window is too small for them after the image: the next RAM span.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[(MB, 6 * MB)], 4 * MB, MB), Some(0x81_0000));
}

#[test]
fn the_descriptors_need_one_ram_entry_and_a_fit() {
    let map = q35_map();
    // More than any entry holds, or RAM that is not there at all.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[], 0x2000_0000, MB), None);
    assert_eq!(bootinfo::pick_pmm_floor(&[], &[], 0x1000, MB), None);
    // A span past the reserved hole is not a fit across it.
    let e = |addr, size, kind| MemEntry { addr, size, kind, reserved: 0 };
    let split = [e(MB, MB, bootinfo::E820_RAM), e(2 * MB, MB, bootinfo::E820_RESERVED), e(3 * MB, MB, bootinfo::E820_RAM)];
    assert_eq!(bootinfo::pick_pmm_floor(&split, &[], MB + 0x1000, MB), None);
    assert_eq!(bootinfo::pick_pmm_floor(&split, &[], MB, MB), Some(MB));
    // The result is page-aligned though the spans need not be.
    assert_eq!(bootinfo::pick_pmm_floor(&map, &[(MB, 0x2345)], MB, MB), Some(MB + 0x3000));
}

#[test]
fn the_images_frames_are_cut_out_of_the_holes_the_direct_map_leaves() {
    let e = |addr, size, kind| MemEntry { addr, size, kind, reserved: 0 };
    // RAM, the loader's image (reserved), RAM: the image is one hole.
    let map = [e(0, 0x9_f000, bootinfo::E820_RAM), e(MB, 4 * MB, bootinfo::E820_RAM),
               e(5 * MB, 3 * MB, bootinfo::E820_RESERVED), e(8 * MB, 8 * MB, bootinfo::E820_RAM)];
    let collect = |keep| {
        let mut v = Vec::new();
        bootinfo::for_each_hole_except(&map, 16 * MB, &[keep], |s, l| v.push((s, l)));
        v
    };
    assert_eq!(collect((0, 0)), vec![(0x9_f000, MB - 0x9_f000), (5 * MB, 3 * MB)], "no kept range: the plain holes");
    // The image is the whole hole: gone from the list, the BIOS hole stays.
    assert_eq!(collect((5 * MB, 3 * MB)), vec![(0x9_f000, MB - 0x9_f000)]);
    // The image is part of the hole: the rest of it stays, on both sides.
    assert_eq!(collect((6 * MB, MB)), vec![(0x9_f000, MB - 0x9_f000), (5 * MB, MB), (7 * MB, MB)]);
    // The image starts at the hole's start / ends at its end.
    assert_eq!(collect((5 * MB, MB)), vec![(0x9_f000, MB - 0x9_f000), (6 * MB, 2 * MB)]);
    assert_eq!(collect((7 * MB, MB)), vec![(0x9_f000, MB - 0x9_f000), (5 * MB, 2 * MB)]);
    // A kept range in RAM, away from every hole, changes nothing.
    assert_eq!(collect((2 * MB, MB)), collect((0, 0)));
    // The image and a boot module in the same hole (Limine puts both in its
    // executable-and-modules memory), listed in either order: both kept,
    // the gaps between them still holes, in address order.
    let two = |keep: &[(u64, u64)]| {
        let mut v = Vec::new();
        bootinfo::for_each_hole_except(&map, 16 * MB, keep, |s, l| v.push((s, l)));
        v
    };
    let want = vec![(0x9_f000, MB - 0x9_f000), (5 * MB, MB / 2), (6 * MB, MB), (7 * MB + MB / 2, MB / 2)];
    assert_eq!(two(&[(5 * MB + MB / 2, MB / 2), (7 * MB, MB / 2)]), want);
    assert_eq!(two(&[(7 * MB, MB / 2), (5 * MB + MB / 2, MB / 2)]), want);
    // Overlapping kept ranges, and an empty one, cut once.
    assert_eq!(two(&[(5 * MB, 2 * MB), (6 * MB, 2 * MB), (0, 0)]), vec![(0x9_f000, MB - 0x9_f000)]);
}
