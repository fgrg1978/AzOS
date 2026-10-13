// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal EFI 2.x System Table bindings — only the fields we actually call.
//!
//! Based on UEFI spec 2.10 §4. Layout is stable across implementations.

use core::ffi::c_void;

// ─── Type aliases ──────────────────────────────────────────────────────────
pub type EfiHandle     = *mut c_void;
pub type EfiStatus     = usize;
pub type EfiTpl        = usize;
pub type EfiPhysicalAddress = u64;
pub type EfiVirtualAddress  = u64;

// ─── Status codes (subset) ─────────────────────────────────────────────────
const EFI_ERROR_BIT: usize = 1 << (usize::BITS - 1);
pub const EFI_SUCCESS:             EfiStatus = 0;
pub const EFI_LOAD_ERROR:          EfiStatus = EFI_ERROR_BIT | 1;
pub const EFI_INVALID_PARAMETER:   EfiStatus = EFI_ERROR_BIT | 2;
pub const EFI_UNSUPPORTED:         EfiStatus = EFI_ERROR_BIT | 3;
pub const EFI_BUFFER_TOO_SMALL:    EfiStatus = EFI_ERROR_BIT | 5;
pub const EFI_NOT_FOUND:           EfiStatus = EFI_ERROR_BIT | 14;

// ─── Allocate type and memory type ────────────────────────────────────────
pub const EFI_ALLOCATE_ANY_PAGES:     u32 = 0;
pub const EFI_ALLOCATE_MAX_ADDRESS:   u32 = 1;
pub const EFI_ALLOCATE_ADDRESS:       u32 = 2;

// ─── Table Header (common prefix) ──────────────────────────────────────────
#[repr(C)]
pub struct EfiTableHeader {
    pub signature:   u64,
    pub revision:    u32,
    pub header_size: u32,
    pub crc32:       u32,
    pub reserved:    u32,
}

// ─── Simple Text Output (enough for printing diagnostics) ──────────────────
#[repr(C)]
pub struct EfiSimpleTextOutputProtocol {
    pub reset:                unsafe extern "efiapi" fn(*mut Self, bool) -> EfiStatus,
    pub output_string:        unsafe extern "efiapi" fn(*mut Self, *const u16) -> EfiStatus,
    pub test_string:          unsafe extern "efiapi" fn(*mut Self, *const u16) -> EfiStatus,
    pub query_mode:           unsafe extern "efiapi" fn(*mut Self, usize, *mut usize, *mut usize) -> EfiStatus,
    pub set_mode:             unsafe extern "efiapi" fn(*mut Self, usize) -> EfiStatus,
    pub set_attribute:        unsafe extern "efiapi" fn(*mut Self, usize) -> EfiStatus,
    pub clear_screen:         unsafe extern "efiapi" fn(*mut Self) -> EfiStatus,
    pub set_cursor_position:  unsafe extern "efiapi" fn(*mut Self, usize, usize) -> EfiStatus,
    pub enable_cursor:        unsafe extern "efiapi" fn(*mut Self, bool) -> EfiStatus,
    pub mode:                 *mut c_void,
}

// ─── Boot Services (only what we need) ─────────────────────────────────────
#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,

    // Task priority
    pub raise_tpl:   *const c_void,
    pub restore_tpl: *const c_void,

    // Memory services
    pub allocate_pages: unsafe extern "efiapi" fn(
        alloc_type: u32,
        mem_type:   u32,
        pages:      usize,
        memory:     *mut EfiPhysicalAddress,
    ) -> EfiStatus,
    pub free_pages: unsafe extern "efiapi" fn(
        memory: EfiPhysicalAddress,
        pages:  usize,
    ) -> EfiStatus,
    pub get_memory_map: unsafe extern "efiapi" fn(
        mmap_size:        *mut usize,
        mmap:             *mut c_void,      // EfiMemoryDescriptor array
        mmap_key:         *mut usize,
        desc_size:        *mut usize,
        desc_version:     *mut u32,
    ) -> EfiStatus,
    pub allocate_pool:  *const c_void,
    pub free_pool:      *const c_void,

    // Event & timer — unused, listed as *const c_void to preserve struct layout
    pub create_event:        *const c_void,
    pub set_timer:           *const c_void,
    pub wait_for_event:      *const c_void,
    pub signal_event:        *const c_void,
    pub close_event:         *const c_void,
    pub check_event:         *const c_void,

    // Protocol handlers — unused
    pub install_protocol_interface:   *const c_void,
    pub reinstall_protocol_interface: *const c_void,
    pub uninstall_protocol_interface: *const c_void,
    pub handle_protocol:              *const c_void,
    pub reserved:                     *const c_void,
    pub register_protocol_notify:     *const c_void,
    pub locate_handle:                *const c_void,
    pub locate_device_path:           *const c_void,
    pub install_configuration_table:  *const c_void,

    // Image services — unused
    pub load_image:     *const c_void,
    pub start_image:    *const c_void,
    pub exit:           *const c_void,
    pub unload_image:   *const c_void,

    // Exit boot services
    pub exit_boot_services: unsafe extern "efiapi" fn(
        image_handle: EfiHandle,
        map_key:      usize,
    ) -> EfiStatus,

    // Misc
    pub get_next_monotonic_count: *const c_void,
    pub stall:                    *const c_void,
    pub set_watchdog_timer:       *const c_void,

    // More protocol handlers — unused tail
    pub connect_controller:      *const c_void,
    pub disconnect_controller:   *const c_void,
    pub open_protocol:           *const c_void,
    pub close_protocol:          *const c_void,
    pub open_protocol_information: *const c_void,
    pub protocols_per_handle:    *const c_void,
    pub locate_handle_buffer:    *const c_void,
    pub locate_protocol:         *const c_void,
    pub install_multiple_protocol_interfaces:   *const c_void,
    pub uninstall_multiple_protocol_interfaces: *const c_void,
    pub calculate_crc32:         *const c_void,
    pub copy_mem:                *const c_void,
    pub set_mem:                 *const c_void,
    pub create_event_ex:         *const c_void,
}

// ─── System Table ──────────────────────────────────────────────────────────
#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,

    pub firmware_vendor:   *const u16,
    pub firmware_revision: u32,

    pub console_in_handle: EfiHandle,
    pub con_in:            *mut c_void,

    pub console_out_handle: EfiHandle,
    pub con_out:            *mut EfiSimpleTextOutputProtocol,

    pub standard_error_handle: EfiHandle,
    pub std_err:               *mut EfiSimpleTextOutputProtocol,

    pub runtime_services: *mut c_void,
    pub boot_services:    *mut EfiBootServices,

    pub number_of_table_entries: usize,
    pub configuration_table:     *mut c_void,
}
