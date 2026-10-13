// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DFU 1.1 USB descriptors (§4).
//!
//! The device controller hands these to the host during enumeration.
//! Layout matches the USB-IF DFU 1.1 spec byte-for-byte; we use
//! named constants for every numeric value so the descriptors are
//! readable.

#![allow(dead_code)]

// ── Standard USB class codes for DFU (§4.1.2) ─────────────────

/// bInterfaceClass — Application-Specific (USB spec).
pub const DFU_INTERFACE_CLASS:             u8 = 0xFE;
/// bInterfaceSubClass — Device Firmware Update.
pub const DFU_INTERFACE_SUBCLASS:          u8 = 0x01;
/// bInterfaceProtocol — runtime (application is using the device
/// for its normal purpose, but DFU descriptor is also exposed).
pub const DFU_INTERFACE_PROTOCOL_RUNTIME:  u8 = 0x01;
/// bInterfaceProtocol — DFU mode (device is in firmware update
/// mode; no application class is available).
pub const DFU_INTERFACE_PROTOCOL_DFU:      u8 = 0x02;

// ── DFU Functional Descriptor (§4.1.3 Table 4.2) ──────────────

/// bDescriptorType — class-specific DFU functional descriptor.
pub const DFU_FUNC_DESCRIPTOR_TYPE: u8 = 0x21;
/// Total length of the functional descriptor in bytes.
pub const DFU_FUNC_DESCRIPTOR_LEN:  u8 = 9;

// bmAttributes bits (§4.1.3.1)
pub const DFU_ATTR_CAN_DOWNLOAD:             u8 = 1 << 0;
pub const DFU_ATTR_CAN_UPLOAD:               u8 = 1 << 1;
pub const DFU_ATTR_MANIFESTATION_TOLERANT:   u8 = 1 << 2;
pub const DFU_ATTR_WILL_DETACH:              u8 = 1 << 3;

/// Standard descriptor type codes (USB spec).
pub const DESC_TYPE_DEVICE:    u8 = 0x01;
pub const DESC_TYPE_CONFIG:    u8 = 0x02;
pub const DESC_TYPE_STRING:    u8 = 0x03;
pub const DESC_TYPE_INTERFACE: u8 = 0x04;
pub const DESC_TYPE_ENDPOINT:  u8 = 0x05;

/// Length of standard descriptors (USB spec).
pub const DESC_LEN_DEVICE:    u8 = 18;
pub const DESC_LEN_CONFIG:    u8 = 9;
pub const DESC_LEN_INTERFACE: u8 = 9;

// ── DFU Functional Descriptor builder ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionalDescriptor {
    pub bm_attributes:    u8,
    pub w_detach_timeout: u16,
    pub w_transfer_size:  u16,
    pub bcd_dfu_version:  u16,
}

impl FunctionalDescriptor {
    /// Default sane values for AZOS: download-only (no upload),
    /// manifestation-tolerant (device stays in DFU mode after
    /// download so the kernel can verify the signature before
    /// committing), 1 KiB chunks, DFU 1.1.
    pub const AZOS_DEFAULT: Self = Self {
        bm_attributes:
            DFU_ATTR_CAN_DOWNLOAD
            | DFU_ATTR_MANIFESTATION_TOLERANT
            | DFU_ATTR_WILL_DETACH,
        w_detach_timeout: 500,    // ms
        w_transfer_size:  1024,
        bcd_dfu_version:  0x0110, // DFU 1.1
    };

    /// Encode to the 9-byte wire format.
    pub const fn encode(self) -> [u8; DFU_FUNC_DESCRIPTOR_LEN as usize] {
        [
            DFU_FUNC_DESCRIPTOR_LEN,
            DFU_FUNC_DESCRIPTOR_TYPE,
            self.bm_attributes,
            (self.w_detach_timeout      & 0xFF) as u8,
            (self.w_detach_timeout >> 8 & 0xFF) as u8,
            (self.w_transfer_size      & 0xFF) as u8,
            (self.w_transfer_size >> 8 & 0xFF) as u8,
            (self.bcd_dfu_version      & 0xFF) as u8,
            (self.bcd_dfu_version >> 8 & 0xFF) as u8,
        ]
    }
}

// ── Higher-level descriptor builder ────────────────────────────

/// Builds the full descriptor blob the device controller returns
/// for `GET_DESCRIPTOR (CONFIGURATION)`: configuration descriptor
/// + interface descriptor + DFU functional descriptor.
///
/// No endpoints — DFU uses only the control endpoint (EP0).
pub struct DescriptorBuilder {
    pub interface_string_index: u8,
    pub config_string_index:    u8,
    pub bmax_power_2ma_units:   u8,  // 50 = 100 mA
    pub func: FunctionalDescriptor,
}

impl DescriptorBuilder {
    pub const fn new(func: FunctionalDescriptor) -> Self {
        Self {
            interface_string_index: 0,
            config_string_index:    0,
            bmax_power_2ma_units:   50,
            func,
        }
    }

    /// Length of the assembled descriptor blob.
    pub const fn total_length(&self) -> u16 {
        (DESC_LEN_CONFIG + DESC_LEN_INTERFACE + DFU_FUNC_DESCRIPTOR_LEN) as u16
    }

    /// Write the full descriptor blob into `out`. Returns the
    /// number of bytes written, or `None` if the buffer is too
    /// small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let total = self.total_length() as usize;
        if out.len() < total {
            return None;
        }
        let mut p = 0;

        // ── CONFIGURATION descriptor ──────────────────────────
        out[p     ] = DESC_LEN_CONFIG;
        out[p + 1 ] = DESC_TYPE_CONFIG;
        out[p + 2 ] = (self.total_length() & 0xFF) as u8;
        out[p + 3 ] = (self.total_length() >> 8) as u8;
        out[p + 4 ] = 1;                // bNumInterfaces
        out[p + 5 ] = 1;                // bConfigurationValue
        out[p + 6 ] = self.config_string_index;
        // bmAttributes: bit 7 reserved=1, bit 6 self-powered=1.
        out[p + 7 ] = 0b1100_0000;
        out[p + 8 ] = self.bmax_power_2ma_units;
        p += DESC_LEN_CONFIG as usize;

        // ── INTERFACE descriptor ──────────────────────────────
        out[p     ] = DESC_LEN_INTERFACE;
        out[p + 1 ] = DESC_TYPE_INTERFACE;
        out[p + 2 ] = 0;                // bInterfaceNumber
        out[p + 3 ] = 0;                // bAlternateSetting
        out[p + 4 ] = 0;                // bNumEndpoints — control EP only
        out[p + 5 ] = DFU_INTERFACE_CLASS;
        out[p + 6 ] = DFU_INTERFACE_SUBCLASS;
        out[p + 7 ] = DFU_INTERFACE_PROTOCOL_DFU;
        out[p + 8 ] = self.interface_string_index;
        p += DESC_LEN_INTERFACE as usize;

        // ── DFU functional descriptor ─────────────────────────
        let func_bytes = self.func.encode();
        out[p..p + func_bytes.len()].copy_from_slice(&func_bytes);
        p += func_bytes.len();

        Some(p)
    }
}
