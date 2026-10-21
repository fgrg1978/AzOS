// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SCSI over USB Bulk-Only Transport, both ends of the wire.
//!
//! - [`bbb`]: the Bulk-Only Transport wrappers, CBW and CSW, parsed and
//!   encoded by whichever end needs them.
//! - [`target`]: the command set a device answers (INQUIRY, READ CAPACITY,
//!   READ/WRITE(10), SYNCHRONIZE CACHE ...) over a [`target::BlockDevice`]:
//!   the USB MSC gadget (`azos_msc`) serves the board's storage as a stick.
//! - [`initiator`]: the command set a host sends: CDB builders and the parsers
//!   for the data that comes back: the USB mass-storage host driver
//!   (`azos_usb::class::msc`) drives a stick.
//!
//! Pure `no_std`, no allocation, no dependencies; `tests/host/scsi-tests`
//! checks the two ends against each other.

#![no_std]

pub mod bbb;
pub mod initiator;
pub mod target;
