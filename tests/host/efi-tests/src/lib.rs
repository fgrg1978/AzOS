// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_efi` — UE01 BootInfo handoff +
//! UEFI memory-map iteration + PE/COFF constants.

#[cfg(test)]
mod tests {
    use azos_efi::{
        boot_info_from_ptr, BootInfo, EfiMemoryDescriptor,
        BOOT_INFO_MAGIC, BOOT_INFO_VERSION, EFI_MEMORY_DESCRIPTOR_SIZE,
        EFI_MAX_MEMORY_DESCRIPTORS,
        // EFI memory-type constants
        EFI_RESERVED_MEMORY_TYPE, EFI_LOADER_CODE, EFI_CONVENTIONAL_MEMORY,
        EFI_MEMORY_MAPPED_IO,
        // PE/COFF
        PE_DOS_MAGIC, PE_NT_SIGNATURE, PE_MACHINE_RISCV64,
        PE_SUBSYSTEM_EFI_APP,
        KERNEL_MAIN_BOOTINFO_MAGIC,
    };

    // ── Magic + version constants ──────────────────────────────

    #[test]
    fn boot_info_magic_is_distinctive() {
        // Magic is the in-tree literal 0xB007_1F0_CAFE_D00D.
        assert_eq!(BOOT_INFO_MAGIC, 0xB007_1F0_CAFE_D00D);
        // Re-export points at the same value (used by kernel_main).
        assert_eq!(KERNEL_MAIN_BOOTINFO_MAGIC, BOOT_INFO_MAGIC);
    }

    #[test]
    fn boot_info_version_starts_at_one() {
        // V1 is the first layout; bump when fields are added.
        assert_eq!(BOOT_INFO_VERSION, 1);
    }

    #[test]
    fn efi_memory_descriptor_size_matches_layout() {
        // Spec: u32+u32+u64+u64+u64+u64 = 4+4+8+8+8+8 = 40 bytes.
        assert_eq!(EFI_MEMORY_DESCRIPTOR_SIZE, 40);
        assert_eq!(
            EFI_MEMORY_DESCRIPTOR_SIZE,
            core::mem::size_of::<EfiMemoryDescriptor>(),
        );
    }

    #[test]
    fn efi_max_memory_descriptors_is_512() {
        // 512 × 40 B = 20 KiB static buffer; documented in lib.rs.
        assert_eq!(EFI_MAX_MEMORY_DESCRIPTORS, 512);
    }

    // ── BootInfo::empty + is_valid ─────────────────────────────

    #[test]
    fn empty_bootinfo_is_valid() {
        let bi = BootInfo::empty();
        assert!(bi.is_valid(), "BootInfo::empty() must pass is_valid()");
        assert_eq!(bi.magic, BOOT_INFO_MAGIC);
        assert_eq!(bi.version, BOOT_INFO_VERSION);
        assert_eq!(bi.mem_map_ptr, 0);
        assert_eq!(bi.mem_map_len, 0);
        assert_eq!(bi.mem_desc_size, EFI_MEMORY_DESCRIPTOR_SIZE as u32);
        assert_eq!(bi.dtb_ptr, 0);
        assert_eq!(bi.cmdline_ptr, 0);
        assert_eq!(bi.cmdline_len, 0);
    }

    #[test]
    fn is_valid_rejects_bad_magic() {
        let mut bi = BootInfo::empty();
        bi.magic = 0xDEAD_BEEF;
        assert!(!bi.is_valid());
    }

    #[test]
    fn is_valid_rejects_wrong_version() {
        let mut bi = BootInfo::empty();
        bi.version = BOOT_INFO_VERSION + 1;
        assert!(!bi.is_valid());
    }

    // ── boot_info_from_ptr ─────────────────────────────────────

    #[test]
    fn boot_info_from_null_ptr_returns_none() {
        let result = unsafe { boot_info_from_ptr(0) };
        assert!(result.is_none());
    }

    #[test]
    fn boot_info_from_unaligned_ptr_returns_none() {
        // Build a valid BootInfo, then offset the pointer by 1
        // so it's misaligned.  Impl guards via `ptr % align != 0`.
        let bi = Box::new(BootInfo::empty());
        let leaked: &'static BootInfo = Box::leak(bi);
        let aligned_ptr = leaked as *const BootInfo as usize;
        // Unaligned (aligned + 1) — alignment of BootInfo is 8.
        let bad = aligned_ptr + 1;
        let result = unsafe { boot_info_from_ptr(bad) };
        assert!(result.is_none(),
            "must reject misaligned ptr (saw alignment {}, got bad={:#x})",
            core::mem::align_of::<BootInfo>(), bad);
    }

    #[test]
    fn boot_info_from_valid_aligned_ptr_returns_some() {
        let bi = Box::new(BootInfo::empty());
        let leaked: &'static BootInfo = Box::leak(bi);
        let ptr = leaked as *const BootInfo as usize;
        let result = unsafe { boot_info_from_ptr(ptr) };
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.magic, BOOT_INFO_MAGIC);
    }

    #[test]
    fn boot_info_from_corrupted_ptr_returns_none() {
        let mut bi = BootInfo::empty();
        bi.magic = 0; // Corrupt magic
        let leaked: &'static BootInfo = Box::leak(Box::new(bi));
        let ptr = leaked as *const BootInfo as usize;
        let result = unsafe { boot_info_from_ptr(ptr) };
        assert!(result.is_none());
    }

    // ── EfiMemoryIter ──────────────────────────────────────────

    #[test]
    fn memory_iter_walks_all_descriptors() {
        // Build 3 descriptors with distinct mem_type values.
        let descs: Vec<EfiMemoryDescriptor> = (0..3).map(|i| {
            EfiMemoryDescriptor {
                mem_type: i as u32,
                _pad: 0,
                phys_start: (i as u64) * 0x1000,
                virt_start: 0,
                num_pages: 1,
                attribute: 0,
            }
        }).collect();

        let mut bi = BootInfo::empty();
        bi.mem_map_ptr = descs.as_ptr() as u64;
        bi.mem_map_len = 3;
        bi.mem_desc_size = EFI_MEMORY_DESCRIPTOR_SIZE as u32;

        let collected: Vec<EfiMemoryDescriptor> = unsafe {
            bi.memory_descriptors().collect()
        };
        assert_eq!(collected.len(), 3);
        for i in 0..3 {
            assert_eq!(collected[i].mem_type, i as u32);
            assert_eq!(collected[i].phys_start, (i as u64) * 0x1000);
        }
    }

    #[test]
    fn memory_iter_empty_when_len_is_zero() {
        let bi = BootInfo::empty();
        let collected: Vec<EfiMemoryDescriptor> = unsafe {
            bi.memory_descriptors().collect()
        };
        assert_eq!(collected.len(), 0);
    }

    #[test]
    fn memory_iter_respects_custom_stride() {
        // Firmware may use a stride larger than EFI_MEMORY_DESCRIPTOR_SIZE
        // (e.g. they extend the struct with extra fields).  Simulate
        // a 48-byte stride: place each descriptor 8 bytes apart from
        // the next struct end.
        const PADDED_STRIDE: usize = 48;
        let mut buf = vec![0u8; PADDED_STRIDE * 2];
        // First descriptor at offset 0.
        let d1 = EfiMemoryDescriptor {
            mem_type: 7, _pad: 0,
            phys_start: 0x8000_0000, virt_start: 0,
            num_pages: 4, attribute: 0,
        };
        // Second descriptor at offset PADDED_STRIDE.
        let d2 = EfiMemoryDescriptor {
            mem_type: 11, _pad: 0,
            phys_start: 0x1000_0000, virt_start: 0,
            num_pages: 1, attribute: 0,
        };
        unsafe {
            core::ptr::write(buf.as_mut_ptr() as *mut EfiMemoryDescriptor, d1);
            core::ptr::write(
                buf.as_mut_ptr().add(PADDED_STRIDE) as *mut EfiMemoryDescriptor,
                d2,
            );
        }
        let mut bi = BootInfo::empty();
        bi.mem_map_ptr = buf.as_ptr() as u64;
        bi.mem_map_len = 2;
        bi.mem_desc_size = PADDED_STRIDE as u32;

        let collected: Vec<EfiMemoryDescriptor> = unsafe {
            bi.memory_descriptors().collect()
        };
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].mem_type, 7);
        assert_eq!(collected[0].phys_start, 0x8000_0000);
        assert_eq!(collected[1].mem_type, 11);
        assert_eq!(collected[1].phys_start, 0x1000_0000);
    }

    // ── EFI memory-type constants (sanity vs UEFI spec) ────────

    #[test]
    fn efi_memory_types_match_uefi_spec() {
        // §6.2 of UEFI 2.10 — these aren't arbitrary, they're a
        // public ABI between firmware and kernel.
        assert_eq!(EFI_RESERVED_MEMORY_TYPE, 0);
        assert_eq!(EFI_LOADER_CODE, 1);
        assert_eq!(EFI_CONVENTIONAL_MEMORY, 7);
        assert_eq!(EFI_MEMORY_MAPPED_IO, 11);
    }

    // ── PE/COFF constants (sanity vs Microsoft PE spec) ────────

    #[test]
    fn pe_constants_are_well_known_values() {
        // 'MZ' DOS stub — must be the literal ASCII pair.
        assert_eq!(PE_DOS_MAGIC, 0x5A4D);
        assert_eq!(PE_DOS_MAGIC.to_le_bytes(), [b'M', b'Z']);
        // 'PE\0\0' — little-endian NT signature.
        assert_eq!(PE_NT_SIGNATURE, 0x0000_4550);
        assert_eq!(PE_NT_SIGNATURE.to_le_bytes(), [b'P', b'E', 0, 0]);
        // RISC-V 64 machine ID per Microsoft PE spec.
        assert_eq!(PE_MACHINE_RISCV64, 0x5064);
        // EFI application subsystem.
        assert_eq!(PE_SUBSYSTEM_EFI_APP, 10);
    }
}
