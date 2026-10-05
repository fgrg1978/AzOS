// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! UE01-UE04 — UEFI Boot support (scaffolding only).
//!
//! This crate is **opt-in** via the `uefi` feature on the kernel. When
//! enabled, the kernel gains an alternative boot path that expects to be
//! launched from EFI firmware (EDK2 on QEMU, U-Boot EFI on VisionFive 2)
//! instead of the traditional OpenSBI → S-mode flow.
//!
//! # Flow
//! ```text
//!  EFI firmware loads BOOTRISCV64.EFI
//!    ↓
//!  efi_main(handle, system_table)
//!    ├── GetMemoryMap() → EFI memory descriptors
//!    ├── ExitBootServices(handle, key)
//!    ├── build BootInfo { magic, mem_map_ptr, mem_map_len, ... }
//!    └── efi_handoff(&BootInfo) → kernel_main(0, bootinfo_ptr)
//! ```
//!
//! # Status
//! This is minimal scaffolding — the types and dispatch are here so the
//! kernel can detect BootInfo magic. Full PE/COFF packaging (UE03) and
//! the .efi image build tooling (UE04) are tracked separately and require
//! `llvm-objcopy --target=efi-app-riscv64` on the host.
//!
//! The `kernel_main(hart_id, dtb_or_info_ptr)` entry point looks for
//! `BOOT_INFO_MAGIC` at `*dtb_or_info_ptr`; if found, it parses
//! `BootInfo` instead of a raw DTB.

use core::sync::atomic::{AtomicU64, Ordering};

pub mod system_table;
pub use system_table::*;

// ───────────────────────────────────────────────────────────────────────────
// BootInfo — the handover structure from EFI stub to kernel_main.
// ───────────────────────────────────────────────────────────────────────────

/// Magic number placed at the start of `BootInfo`. The kernel uses this to
/// tell an EFI-delivered `BootInfo*` from a raw DTB pointer.
pub const BOOT_INFO_MAGIC: u64 = 0xB007_1F0_CAFE_D00D;

/// Current `BootInfo` struct version (bump on layout change).
pub const BOOT_INFO_VERSION: u32 = 1;

/// EFI memory-type constants (subset of the EFI spec).
pub const EFI_RESERVED_MEMORY_TYPE:     u32 = 0;
pub const EFI_LOADER_CODE:              u32 = 1;
pub const EFI_LOADER_DATA:              u32 = 2;
pub const EFI_BOOT_SERVICES_CODE:       u32 = 3;
pub const EFI_BOOT_SERVICES_DATA:       u32 = 4;
pub const EFI_RUNTIME_SERVICES_CODE:    u32 = 5;
pub const EFI_RUNTIME_SERVICES_DATA:    u32 = 6;
pub const EFI_CONVENTIONAL_MEMORY:      u32 = 7;
pub const EFI_UNUSABLE_MEMORY:          u32 = 8;
pub const EFI_ACPI_RECLAIM_MEMORY:      u32 = 9;
pub const EFI_ACPI_MEMORY_NVS:          u32 = 10;
pub const EFI_MEMORY_MAPPED_IO:         u32 = 11;
pub const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const EFI_PAL_CODE:                 u32 = 13;
pub const EFI_PERSISTENT_MEMORY:        u32 = 14;

/// EFI memory descriptor (per UEFI spec 2.10, 6.2).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EfiMemoryDescriptor {
    pub mem_type:      u32,
    pub _pad:          u32,
    pub phys_start:    u64,
    pub virt_start:    u64,
    pub num_pages:     u64,
    pub attribute:     u64,
}

/// Size of one EFI memory descriptor (the firmware may use a larger stride).
pub const EFI_MEMORY_DESCRIPTOR_SIZE: usize =
    core::mem::size_of::<EfiMemoryDescriptor>();

/// Handover structure from the EFI stub to `kernel_main`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    pub magic:        u64,
    pub version:      u32,
    pub _pad:         u32,
    pub mem_map_ptr:  u64,
    pub mem_map_len:  u32,
    pub mem_desc_size: u32,
    pub dtb_ptr:      u64,
    pub cmdline_ptr:  u64,
    pub cmdline_len:  u32,
    pub reserved:     u32,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic:         BOOT_INFO_MAGIC,
            version:       BOOT_INFO_VERSION,
            _pad:          0,
            mem_map_ptr:   0,
            mem_map_len:   0,
            mem_desc_size: EFI_MEMORY_DESCRIPTOR_SIZE as u32,
            dtb_ptr:       0,
            cmdline_ptr:   0,
            cmdline_len:   0,
            reserved:      0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC && self.version == BOOT_INFO_VERSION
    }

    /// Iterator over the memory descriptors stored at `mem_map_ptr`.
    /// # Safety
    /// Caller must ensure `mem_map_ptr` points to `mem_map_len` valid
    /// descriptors laid out with stride `mem_desc_size`.
    pub unsafe fn memory_descriptors(&self) -> EfiMemoryIter<'_> {
        EfiMemoryIter {
            base: self.mem_map_ptr as *const u8,
            stride: self.mem_desc_size as usize,
            remaining: self.mem_map_len as usize,
            _phantom: core::marker::PhantomData,
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Memory-map iterator.
// ───────────────────────────────────────────────────────────────────────────

pub struct EfiMemoryIter<'a> {
    base:      *const u8,
    stride:    usize,
    remaining: usize,
    _phantom:  core::marker::PhantomData<&'a ()>,
}

impl Iterator for EfiMemoryIter<'_> {
    type Item = EfiMemoryDescriptor;
    fn next(&mut self) -> Option<EfiMemoryDescriptor> {
        if self.remaining == 0 { return None; }
        let desc = unsafe { *(self.base as *const EfiMemoryDescriptor) };
        self.base = unsafe { self.base.add(self.stride) };
        self.remaining -= 1;
        Some(desc)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Handoff detection.
// ───────────────────────────────────────────────────────────────────────────

/// Address recorded by `efi_handoff` for diagnostics.
static HANDOFF_ADDR: AtomicU64 = AtomicU64::new(0);

/// Try to interpret `ptr` as a `&BootInfo`. Returns `Some` on magic match,
/// `None` otherwise (caller should fall back to raw-DTB interpretation).
///
/// # Safety
/// The pointer must be a valid readable address or zero. Passing an
/// unaligned or truncated region to this call is undefined behaviour.
pub unsafe fn boot_info_from_ptr(ptr: usize) -> Option<&'static BootInfo> {
    if ptr == 0 { return None; }
    if ptr % core::mem::align_of::<BootInfo>() != 0 { return None; }
    let info = &*(ptr as *const BootInfo);
    if info.is_valid() {
        HANDOFF_ADDR.store(ptr as u64, Ordering::Release);
        Some(info)
    } else {
        None
    }
}

pub fn handoff_addr() -> u64 {
    HANDOFF_ADDR.load(Ordering::Acquire)
}

// ───────────────────────────────────────────────────────────────────────────
// PE/COFF header constants (UE03) — for future llvm-objcopy packaging.
// ───────────────────────────────────────────────────────────────────────────

/// Little-endian 'MZ' DOS stub magic.
pub const PE_DOS_MAGIC:      u16 = 0x5A4D;
/// 'PE\0\0' signature.
pub const PE_NT_SIGNATURE:   u32 = 0x0000_4550;
/// Machine ID for RISC-V 64 (per Microsoft PE spec).
pub const PE_MACHINE_RISCV64: u16 = 0x5064;
/// Subsystem ID for EFI application.
pub const PE_SUBSYSTEM_EFI_APP: u16 = 10;

// ───────────────────────────────────────────────────────────────────────────
// Public re-exports for kernel_main path.
// ───────────────────────────────────────────────────────────────────────────

/// Convenience: the magic value caller should compare against `*ptr as u64`.
pub const KERNEL_MAIN_BOOTINFO_MAGIC: u64 = BOOT_INFO_MAGIC;

// ───────────────────────────────────────────────────────────────────────────
// EFI entry: efi_main — called by the PE/COFF stub.
// ───────────────────────────────────────────────────────────────────────────

/// Maximum EFI memory descriptors we'll copy before handoff. 512 × 40 B =
/// 20 KB reserved in `.bss` of the EFI stub; sufficient for typical boards.
pub const EFI_MAX_MEMORY_DESCRIPTORS: usize = 512;

/// Statically-allocated memory-map buffer used by `efi_main` after
/// ExitBootServices — we can't allocate pool at that point.
#[no_mangle]
pub static mut EFI_MEMORY_MAP_BUF:
    [EfiMemoryDescriptor; EFI_MAX_MEMORY_DESCRIPTORS] =
    [EfiMemoryDescriptor {
        mem_type: 0, _pad: 0,
        phys_start: 0, virt_start: 0,
        num_pages: 0, attribute: 0,
    }; EFI_MAX_MEMORY_DESCRIPTORS];

/// Statically-allocated `BootInfo` handed off to the kernel.
#[no_mangle]
pub static mut EFI_BOOT_INFO: BootInfo = BootInfo::empty();

/// EFI entry point called from `boot_efi.S`. Signature matches
/// the UEFI spec: `efi_main(image_handle, system_table)`.
///
/// # Safety
/// - Called once from EFI firmware in S-mode (or M-mode depending on firmware).
/// - Only UEFI conventions apply until `exit_boot_services` returns.
/// - After handoff the function diverges into the kernel; it never returns.
#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    if system_table.is_null() { halt(); }
    let st = &*system_table;

    // Query size required for the memory map.
    let mut map_size:    usize = 0;
    let mut map_key:     usize = 0;
    let mut desc_size:   usize = 0;
    let mut desc_ver:    u32   = 0;
    let bs = &*st.boot_services;

    // First call always returns EFI_BUFFER_TOO_SMALL and fills map_size.
    let _ = (bs.get_memory_map)(
        &mut map_size,
        core::ptr::null_mut(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );

    // Cap map_size to our buffer.
    let buf_cap_bytes =
        EFI_MAX_MEMORY_DESCRIPTORS * core::mem::size_of::<EfiMemoryDescriptor>();
    if map_size > buf_cap_bytes {
        map_size = buf_cap_bytes;
    }

    // Real call now that we have space.
    let _ = (bs.get_memory_map)(
        &mut map_size,
        (&raw mut EFI_MEMORY_MAP_BUF) as *mut _ as *mut core::ffi::c_void,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );

    // Build BootInfo while boot services still alive.
    let n_desc = if desc_size == 0 { 0 } else { map_size / desc_size };
    EFI_BOOT_INFO = BootInfo {
        magic:         BOOT_INFO_MAGIC,
        version:       BOOT_INFO_VERSION,
        _pad:          0,
        mem_map_ptr:   (&raw const EFI_MEMORY_MAP_BUF) as u64,
        mem_map_len:   n_desc as u32,
        mem_desc_size: desc_size as u32,
        dtb_ptr:       0,
        cmdline_ptr:   0,
        cmdline_len:   0,
        reserved:      0,
    };

    // Exit boot services — after this, EFI print etc. are gone.
    let _ = (bs.exit_boot_services)(image_handle, map_key);

    // Hand off to kernel_main. The calling convention between our EFI stub
    // and kernel_main is: a0 = hart_id (0 under firmware), a1 = *BootInfo.
    efi_handoff(&raw const EFI_BOOT_INFO);
}

// Jump to `kernel_main(0, &BOOT_INFO)`. Defined in `boot_efi.S` because
// it needs to reset the stack pointer and branch-not-link.
extern "C" {
    fn efi_handoff(boot_info: *const BootInfo) -> !;
}

/// Halt the hart. Used when EFI bootstrap fails.
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
