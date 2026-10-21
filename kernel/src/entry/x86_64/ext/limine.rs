// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Limine boot entry (Kconfig `X86_BOOT_LIMINE`, cargo feature
//! `x86-limine`): the request structs the loader fills, and
//! [`limine_prepare`], the Rust half of `_limine_start` (boot.S).
//!
//! **What Limine does differently from PVH.** It enters in 64-bit mode on
//! ITS page tables (a higher-half map of the kernel at wherever it loaded
//! it, plus an HHDM), with its own stack, GDT and IDT. This kernel needs
//! three things PVH gave it: a way to turn an image address into a physical
//! one (`mmu::image_phys`: the image is linked in the top 2 GiB, and where
//! the loader put it is a runtime fact, not a constant), boot.S's page
//! tables (0..4 GiB 1:1, the direct map, the image at its link address), and
//! its boot information as a PVH `hvm_start_info`. So `_limine_start` runs
//! this function on a static stack, before any switch of tables:
//!
//!   1. read the responses into a [`Snapshot`] (they live in loader memory
//!      that only the loader's tables map);
//!   2. record the slide between the physical address Limine gave the image
//!      and the one its link address implies, build the image map (4 KiB
//!      leaves, wherever the frames are) and refuse an image the map cannot
//!      hold or that lies where the 32-bit stages cannot reach;
//!   3. fill the same page-table statics boot.S fills, and the PVH-shaped
//!      record (E820 memory map, RSDP) `platform_impl::discover` reads;
//!   4. return the CR3 value; the asm installs it and continues at the same
//!      virtual addresses, into boot.S's shared 64-bit tail.
//!
//! The image is not copied and nothing assumes a physical address for it:
//! `plan_relocation` and the fixed 32 MiB link-time physical base are gone.
//! The loader's memory-map entry for the image is not RAM, so the page
//! allocator never sees those frames.
//!
//! Not done: no command line (the kernel-file request is not made), the
//! loader's parked APs are left to the INIT/SIPI path (their memory stays
//! reserved), 5-level paging is not requested, and the kernel is not
//! position-independent in virtual space: the loader's KASLR is off for a
//! non-relocatable ELF, so the virtual base is the link address (the next
//! step toward KASLR is `-C relocation-model=pie`, which this slide does not
//! need).
//!
//! Untested on a real Limine: see `azos_arch::firmware::limine` for the provenance of
//! the protocol constants (every one `[verify]`).

use core::cell::UnsafeCell;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use azos_arch::firmware::bootinfo::{HvmStartInfo, MemEntry, MAX_MEM_ENTRIES, PVH_MAGIC, START_INFO_LIMINE};
use azos_arch::firmware::limine::{self as lm, FbInfo, Responses, Snapshot, VirtMem};
use azos_arch::mmu::{image_phys, set_image_slide, slide_for, DIRECT_MAP_BASE, KERNEL_VA_OFFSET};

// ── the requests (section `.limine_requests`, kept by the linker script) ────

/// A request: the id, the revision we ask for, and the response pointer the
/// loader fills (read volatile: no one in Rust writes it).
#[repr(C)]
struct Request {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<u64>,
}
// SAFETY: written only by the loader, before the kernel runs; read volatile.
unsafe impl Sync for Request {}

impl Request {
    const fn new(id: [u64; 4]) -> Self {
        Request { id, revision: 0, response: UnsafeCell::new(0) }
    }
    fn response(&self) -> u64 {
        // SAFETY: a plain aligned u64 inside this static.
        unsafe { read_volatile(self.response.get()) }
    }
}

/// The SMP request: a request plus its `flags` word (bit 0 = x2APIC mode).
#[repr(C)]
struct SmpRequest {
    req: Request,
    flags: u64,
}
// SAFETY: as `Request`.
unsafe impl Sync for SmpRequest {}

/// Loader-visible words (markers, the base-revision tag); the loader writes
/// the tag, so it is interior-mutable.
#[repr(C)]
struct Words<const N: usize>(UnsafeCell<[u64; N]>);
// SAFETY: as `Request`.
unsafe impl<const N: usize> Sync for Words<N> {}

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START: Words<4> = Words(UnsafeCell::new(lm::REQUESTS_START_MARKER));
#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: Words<3> =
    Words(UnsafeCell::new([lm::BASE_REVISION_MAGIC[0], lm::BASE_REVISION_MAGIC[1], lm::BASE_REVISION]));
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_MEMMAP: Request = Request::new(lm::ID_MEMMAP);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_HHDM: Request = Request::new(lm::ID_HHDM);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_KERNEL_ADDRESS: Request = Request::new(lm::ID_KERNEL_ADDRESS);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_FRAMEBUFFER: Request = Request::new(lm::ID_FRAMEBUFFER);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_RSDP: Request = Request::new(lm::ID_RSDP);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_SMBIOS: Request = Request::new(lm::ID_SMBIOS);
#[used]
#[unsafe(link_section = ".limine_requests")]
static REQ_SMP: SmpRequest = SmpRequest { req: Request::new(lm::ID_SMP), flags: 0 };
#[used]
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END: Words<2> = Words(UnsafeCell::new(lm::REQUESTS_END_MARKER));

// ── boot-time state ─────────────────────────────────────────────────────────

/// Written by the boot CPU in `limine_prepare` (before anything else runs),
/// read-only after.
struct BootCell<T>(UnsafeCell<T>);
// SAFETY: one writer, before any reader.
unsafe impl<T> Sync for BootCell<T> {}

/// The PVH-shaped record `kernel_main`'s `fw_table` names.
#[repr(C)]
struct Record {
    si: HvmStartInfo,
    memmap: [MemEntry; MAX_MEM_ENTRIES],
}

/// Everything later boot code can ask about.
struct Handoff {
    snap: Snapshot,
    e820_dropped: usize,
}

static RECORD: BootCell<Record> = BootCell(UnsafeCell::new(Record {
    si: HvmStartInfo {
        magic: 0,
        version: 0,
        flags: 0,
        nr_modules: 0,
        modlist_paddr: 0,
        cmdline_paddr: 0,
        rsdp_paddr: 0,
        memmap_paddr: 0,
        memmap_entries: 0,
        reserved: 0,
    },
    memmap: [MemEntry { addr: 0, size: 0, kind: 0, reserved: 0 }; MAX_MEM_ENTRIES],
}));
static HANDOFF: BootCell<Handoff> =
    BootCell(UnsafeCell::new(Handoff { snap: Snapshot::EMPTY, e820_dropped: 0 }));

// Symbols boot.S and the linker script define.
unsafe extern "C" {
    static mut boot_pml4: [u64; 512];
    static mut boot_pdpt: [u64; 512];
    static mut boot_pdpt_hi: [u64; 512];
    static mut boot_pd: [[u64; 512]; 4];
    static mut pvh_start_info: u32;
    static _text_start: u8;
    static _kernel_end: u8;
}

/// Reads loader memory (the responses) through the loader's own tables.
struct LiveMem;

impl VirtMem for LiveMem {
    fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        // Everything the loader hands out is in the kernel half (HHDM or the
        // image); anything else is not a pointer it gave us.
        if va < 0xFFFF_8000_0000_0000 || va.checked_add(len as u64).is_none() {
            return None;
        }
        // SAFETY: a kernel-half address from the loader's responses, mapped
        // by the loader's tables, which are live until `_limine_start`
        // installs ours; read-only bytes.
        Some(unsafe { core::slice::from_raw_parts(va as *const u8, len) })
    }
}

// ── refusing: COM1, then power off ──────────────────────────────────────────

const COM1: u16 = 0x3F8;

fn com1_puts(s: &str) {
    use azos_arch::cpu::{inb, outb};
    for b in s.bytes() {
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, b);
    }
}

fn com1_hex(v: u64) {
    com1_puts("0x");
    for i in (0..16).rev() {
        let d = ((v >> (i * 4)) & 0xF) as u8;
        let c = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        let buf = [c];
        com1_puts(core::str::from_utf8(&buf).unwrap_or("?"));
    }
}

/// COM1 to 8N1, 115200 (as boot.S's `refuse_baseline`).
fn com1_init() {
    use azos_arch::cpu::outb;
    outb(COM1 + 3, 0x80);
    outb(COM1, 1);
    outb(COM1 + 1, 0);
    outb(COM1 + 3, 0x03);
}

/// The loader's memory map on COM1, one `base length type` line per entry:
/// a relocation refusal is only diagnosable from it.
fn dump_memmap(map: &[lm::MmapEntry]) {
    com1_init();
    com1_puts("\r\n[LIMINE] memmap (base length type):\r\n");
    for e in map {
        com1_puts("  ");
        com1_hex(e.base);
        com1_puts(" ");
        com1_hex(e.length);
        com1_puts(" ");
        com1_hex(e.kind);
        com1_puts("\r\n");
    }
}

/// Say why on COM1 (8N1, 115200, as boot.S's `refuse_baseline`) and stop,
/// through isa-debug-exit when QEMU has one.
fn refuse(why: &str, detail: Option<(&str, u64)>) -> ! {
    use azos_arch::cpu::{outb, outl};
    outb(COM1 + 3, 0x80);
    outb(COM1, 1);
    outb(COM1 + 1, 0);
    outb(COM1 + 3, 0x03);
    com1_puts("\r\n[LIMINE] refusing to boot: ");
    com1_puts(why);
    if let Some((label, v)) = detail {
        com1_puts(" (");
        com1_puts(label);
        com1_puts(" ");
        com1_hex(v);
        com1_puts(")");
    }
    com1_puts("\r\n");
    outl(0xF4, 1);
    azos_arch::cpu::halt_forever()
}

fn error_text(e: lm::Error) -> &'static str {
    match e {
        lm::Error::NotLimine => "the base-revision tag is not Limine's",
        lm::Error::UnsupportedRevision => "the loader does not support the base revision requested",
        lm::Error::NoMemmap => "no memory-map response",
        lm::Error::NoHhdm => "no HHDM response",
        lm::Error::NoKernelAddress => "no kernel-address response",
        lm::Error::KernelMoved => "the kernel was loaded at a slid virtual address (this image is not relocatable)",
        lm::Error::Bad(why) => why,
    }
}

fn map_error_text(e: azos_arch::smp::InstallError) -> &'static str {
    use azos_arch::mmu::ImageMapError as M;
    use azos_arch::smp::InstallError as E;
    match e {
        E::TablesAbove4GiB => "the kernel image is above 4 GiB: the AP start loads its tables with a 32-bit move",
        E::Image(M::TooManyTables) => "the kernel image is larger than Kconfig X86_IMAGE_MAX_MIB",
        E::Image(M::OutsideWindow) => "the kernel image leaves the first GiB of the top 2 GiB",
        E::Image(M::NotAligned) => "the kernel image or its slide is not page-aligned",
        E::Image(M::Empty) | E::NoTrampolinePage => "the kernel image is empty",
    }
}

// ── the Rust half of `_limine_start` ────────────────────────────────────────

/// Called by `_limine_start` on a static stack, in the loader's address
/// space. Returns the CR3 value for boot.S's tables; the image is where the
/// loader put it, and the slide that says so is recorded.
#[unsafe(no_mangle)]
pub extern "C" fn limine_prepare() -> u64 {
    // 1. The responses.
    // SAFETY: the loader's tag words in a static of ours; volatile reads.
    let base_revision = unsafe {
        let p = BASE_REVISION.0.get() as *const u64;
        [read_volatile(p), read_volatile(p.add(1)), read_volatile(p.add(2))]
    };
    let responses = Responses {
        base_revision,
        memmap: REQ_MEMMAP.response(),
        hhdm: REQ_HHDM.response(),
        framebuffer: REQ_FRAMEBUFFER.response(),
        rsdp: REQ_RSDP.response(),
        smbios: REQ_SMBIOS.response(),
        smp: REQ_SMP.req.response(),
        kernel_address: REQ_KERNEL_ADDRESS.response(),
    };
    let text_start = addr_of!(_text_start) as u64;
    let image_end = addr_of!(_kernel_end) as u64;
    let snap = match lm::parse(&LiveMem, &responses, text_start) {
        Ok(s) => s,
        Err(e) => refuse(error_text(e), None),
    };

    // 2. Where the image is: record it, then map it.
    set_image_slide(slide_for(text_start, snap.image_phys));
    // SAFETY: boot CPU, sole execution; the statics are ours, in the image's
    // .bss (zero from the loader).
    let image_pd = match unsafe { azos_arch::smp::build_image_map(text_start as usize, image_end as usize) } {
        Ok(pa) => pa,
        Err(e) => {
            dump_memmap(snap.memmap());
            refuse(map_error_text(e), Some(("image at", snap.image_phys)));
        }
    };

    // 3. boot.S's page tables, in Rust (the same maps, `boot.S` section 3):
    //    PML4[0] and PML4[DMB slot] -> the 1:1 PDPT (PA 0..4 GiB), PML4[KVA
    //    slot] -> PDPT_HI -> the image directory.
    // SAFETY: boot CPU, sole execution; the statics are boot.S's own, in the
    // image's .bss (zero from the loader).
    let cr3 = unsafe { build_tables(image_pd) };

    // The PVH-shaped record. It lives in the image; the platform code reads
    // it by physical address through the 1:1 map, and `pvh_start_info` is a
    // 32-bit word.
    // SAFETY: as above; RECORD/HANDOFF are ours.
    unsafe {
        let rec = &mut *RECORD.0.get();
        let record_pa = image_phys(RECORD.0.get() as u64);
        if record_pa >= 1 << 32 {
            refuse("the kernel image is above 4 GiB: its boot record cannot be read by the 32-bit word", Some(("at", record_pa)));
        }
        let (n, dropped) = lm::to_e820(snap.memmap(), &mut rec.memmap);
        rec.si = HvmStartInfo {
            magic: PVH_MAGIC,
            version: 1,
            flags: START_INFO_LIMINE,
            nr_modules: 0,
            modlist_paddr: 0,
            cmdline_paddr: 0,
            rsdp_paddr: snap.rsdp,
            memmap_paddr: image_phys(addr_of!(rec.memmap) as u64),
            memmap_entries: n as u32,
            reserved: 0,
        };
        let h = &mut *HANDOFF.0.get();
        h.snap = snap;
        h.e820_dropped = dropped;
        write_volatile(addr_of_mut!(pvh_start_info), record_pa as u32);
    }
    cr3
}

/// Fill boot.S's tables; the CR3 value (physical address of the PML4).
/// `image_pd` is the physical address of the image directory
/// (`smp::build_image_map`), which the KVA slot's PDPT names.
///
/// # Safety
/// Boot CPU, once, before the tables are used.
unsafe fn build_tables(image_pd: u64) -> u64 {
    const KVA_ROOT_SLOT: usize = ((KERNEL_VA_OFFSET >> 39) & 511) as usize;
    const DMB_ROOT_SLOT: usize = ((DIRECT_MAP_BASE >> 39) & 511) as usize;
    const KVA_PDPT_SLOT: usize = ((KERNEL_VA_OFFSET >> 30) & 511) as usize;
    const PRESENT_RW: u64 = 0x3;
    const LEAF_2M: u64 = 0x83; // P | RW | PS

    let pa = |p: *const u64| image_phys(p as u64);
    let pml4 = addr_of_mut!(boot_pml4) as *mut u64;
    let pdpt = addr_of_mut!(boot_pdpt) as *mut u64;
    let pdpt_hi = addr_of_mut!(boot_pdpt_hi) as *mut u64;
    let pd = addr_of_mut!(boot_pd) as *mut u64;
    // SAFETY (all writes): inside the statics' extents, the caller's contract.
    unsafe {
        write_volatile(pml4, pa(pdpt) | PRESENT_RW);
        write_volatile(pml4.add(KVA_ROOT_SLOT), pa(pdpt_hi) | PRESENT_RW);
        write_volatile(pml4.add(DMB_ROOT_SLOT), pa(pdpt) | PRESENT_RW);
        for i in 0..4usize {
            write_volatile(pdpt.add(i), (pa(pd) + 4096 * i as u64) | PRESENT_RW);
        }
        write_volatile(pdpt_hi.add(KVA_PDPT_SLOT), image_pd | PRESENT_RW);
        for j in 0..2048usize {
            write_volatile(pd.add(j), ((j as u64) << 21) | LEAF_2M);
        }
    }
    pa(pml4)
}

// ── what later boot code reads ──────────────────────────────────────────────

fn handoff() -> &'static Handoff {
    // SAFETY: written once in `limine_prepare`, before anything else ran.
    unsafe { &*HANDOFF.0.get() }
}

/// The framebuffer the loader set up (physical address), if any: for the
/// framebuffer console.
pub fn framebuffer() -> Option<FbInfo> {
    handoff().snap.fb
}

/// The `[LIMINE]` boot-log lines: what was loaded where, and the answers the
/// platform code does not read itself (framebuffer, SMBIOS, the loader's
/// view of the CPUs).
pub fn log_boot_info() {
    use azos_drv_sys::{kprintln, kwarn};
    let h = handoff();
    let s = &h.snap;
    kprintln!("[LIMINE] base revision {} (asked {}), HHDM {:#x}", s.loaded_revision, lm::BASE_REVISION, s.hhdm);
    kprintln!("[LIMINE] image linked at {:#x}, loaded at {:#x} (slide {:#x}), running in place: no copy",
              addr_of!(_text_start) as u64, s.image_phys, azos_arch::mmu::image_slide());
    if h.e820_dropped != 0 {
        kwarn!("[LIMINE] {} memory-map entries did not fit the platform's {}", h.e820_dropped, MAX_MEM_ENTRIES);
    }
    match s.fb {
        Some(f) => kprintln!(
            "[LIMINE] framebuffer {}x{}x{} pitch {} at {:#x} (r{}<<{} g{}<<{} b{}<<{}), {} reported",
            f.width, f.height, f.bpp, f.pitch, f.phys, f.red_size, f.red_shift, f.green_size,
            f.green_shift, f.blue_size, f.blue_shift, s.fb_count),
        None => match s.fb_error {
            Some(why) => kwarn!("[LIMINE] framebuffer dropped: {}", why),
            None => kprintln!("[LIMINE] no framebuffer"),
        },
    }
    if s.smbios32 != 0 || s.smbios64 != 0 {
        kprintln!("[LIMINE] SMBIOS entry points 32-bit {:#x}, 64-bit {:#x}", s.smbios32, s.smbios64);
    }
    match (s.smp, s.smp_error) {
        (Some(m), _) => {
            kprintln!("[LIMINE] SMP: {} CPU(s), BSP APIC id {}, x2APIC {}", m.count, m.bsp_lapic_id, m.x2apic);
            let kept = (m.count as usize).min(lm::MAX_CPUS);
            for (i, id) in m.lapic_ids[..kept].iter().enumerate() {
                kprintln!("[LIMINE]   cpu {} APIC id {}", i, id);
            }
        }
        (None, Some(why)) => kwarn!("[LIMINE] SMP response dropped: {}", why),
        (None, None) => kprintln!("[LIMINE] no SMP response"),
    }
}
