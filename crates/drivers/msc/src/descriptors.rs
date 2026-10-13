// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! USB MSC descriptors.
//!
//! Layout per USB MSC BBB §3:
//!   configuration → interface → bulk-IN endpoint → bulk-OUT endpoint
//!
//! Interface class triple is 0x08 / 0x06 / 0x50 (Mass Storage,
//! SCSI transparent command set, BBB transport).

/// bInterfaceClass — Mass Storage.
pub const MSC_INTERFACE_CLASS:           u8 = 0x08;
/// bInterfaceSubClass — SCSI transparent command set (SPC-2+).
pub const MSC_INTERFACE_SUBCLASS_SCSI:   u8 = 0x06;
/// bInterfaceProtocol — Bulk-Only Transport.
pub const MSC_INTERFACE_PROTOCOL_BBB:    u8 = 0x50;

/// Max packet size for bulk endpoints on full-speed USB 2.0.
pub const MSC_BULK_EP_MAX_PACKET: u16 = 64;

const DESC_TYPE_CONFIG:    u8 = 0x02;
const DESC_TYPE_INTERFACE: u8 = 0x04;
const DESC_TYPE_ENDPOINT:  u8 = 0x05;

const DESC_LEN_CONFIG:    u8 = 9;
const DESC_LEN_INTERFACE: u8 = 9;
const DESC_LEN_ENDPOINT:  u8 = 7;

const EP_TRANSFER_TYPE_BULK: u8 = 0x02;

pub struct MscDescriptorBuilder {
    pub bulk_in_addr:  u8,  // e.g. 0x81 = EP1 IN
    pub bulk_out_addr: u8,  // e.g. 0x02 = EP2 OUT
    pub max_lun:       u8,  // GET_MAX_LUN returns this on EP0
    pub bmax_power_2ma: u8,
}

impl MscDescriptorBuilder {
    pub const fn new(bulk_in_addr: u8, bulk_out_addr: u8) -> Self {
        Self {
            bulk_in_addr,
            bulk_out_addr,
            max_lun: 0,
            bmax_power_2ma: 50,
        }
    }

    pub const fn total_length(&self) -> u16 {
        (DESC_LEN_CONFIG + DESC_LEN_INTERFACE + DESC_LEN_ENDPOINT * 2) as u16
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let total = self.total_length() as usize;
        if out.len() < total {
            return None;
        }
        let mut p = 0;

        // CONFIGURATION descriptor
        out[p     ] = DESC_LEN_CONFIG;
        out[p + 1 ] = DESC_TYPE_CONFIG;
        out[p + 2 ] = (self.total_length() & 0xFF) as u8;
        out[p + 3 ] = (self.total_length() >> 8) as u8;
        out[p + 4 ] = 1;              // bNumInterfaces
        out[p + 5 ] = 1;              // bConfigurationValue
        out[p + 6 ] = 0;              // iConfiguration
        out[p + 7 ] = 0b1100_0000;    // bmAttributes: reserved=1, self-powered=1
        out[p + 8 ] = self.bmax_power_2ma;
        p += DESC_LEN_CONFIG as usize;

        // INTERFACE descriptor
        out[p     ] = DESC_LEN_INTERFACE;
        out[p + 1 ] = DESC_TYPE_INTERFACE;
        out[p + 2 ] = 0;              // bInterfaceNumber
        out[p + 3 ] = 0;              // bAlternateSetting
        out[p + 4 ] = 2;              // bNumEndpoints (bulk-IN + bulk-OUT)
        out[p + 5 ] = MSC_INTERFACE_CLASS;
        out[p + 6 ] = MSC_INTERFACE_SUBCLASS_SCSI;
        out[p + 7 ] = MSC_INTERFACE_PROTOCOL_BBB;
        out[p + 8 ] = 0;              // iInterface
        p += DESC_LEN_INTERFACE as usize;

        // Bulk-IN endpoint
        out[p     ] = DESC_LEN_ENDPOINT;
        out[p + 1 ] = DESC_TYPE_ENDPOINT;
        out[p + 2 ] = self.bulk_in_addr;
        out[p + 3 ] = EP_TRANSFER_TYPE_BULK;
        out[p + 4 ] = (MSC_BULK_EP_MAX_PACKET & 0xFF) as u8;
        out[p + 5 ] = (MSC_BULK_EP_MAX_PACKET >> 8) as u8;
        out[p + 6 ] = 0;              // bInterval (bulk = ignored)
        p += DESC_LEN_ENDPOINT as usize;

        // Bulk-OUT endpoint
        out[p     ] = DESC_LEN_ENDPOINT;
        out[p + 1 ] = DESC_TYPE_ENDPOINT;
        out[p + 2 ] = self.bulk_out_addr;
        out[p + 3 ] = EP_TRANSFER_TYPE_BULK;
        out[p + 4 ] = (MSC_BULK_EP_MAX_PACKET & 0xFF) as u8;
        out[p + 5 ] = (MSC_BULK_EP_MAX_PACKET >> 8) as u8;
        out[p + 6 ] = 0;
        p += DESC_LEN_ENDPOINT as usize;

        Some(p)
    }
}
