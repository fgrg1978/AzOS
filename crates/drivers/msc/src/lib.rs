// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DEV03 — USB Mass Storage Class (MSC) gadget.
//!
//! Implements the **device side** of USB MSC Bulk-Only Transport
//! (BBB) — the wire protocol that makes the board appear as a USB
//! flash drive to a connected PC. The host can then mount the
//! kernel-owned filesystem (FAT32 on SD / eMMC) and copy files
//! interactively — useful as a debug aid for inspecting logs,
//! BOOTMETA, or replacing a wedged kernel image.
//!
//! ## Scope
//!
//! - **BBB protocol** (USB-IF "Mass Storage Bulk-Only Transport,
//!   rev 1.0", Sept 1999): CBW (Command Block Wrapper) / data
//!   stage / CSW (Command Status Wrapper) state machine.
//! - **Minimal SCSI command set** (SBC-3 + SPC-4 subsets) — just
//!   what stock OS drivers need to enumerate + read + write:
//!   `INQUIRY`, `TEST_UNIT_READY`, `READ_CAPACITY(10)`, `READ(10)`,
//!   `WRITE(10)`, `REQUEST_SENSE`, `MODE_SENSE(6)`, `SYNCHRONIZE_CACHE(10)`.
//! - **Descriptor builders** — config / interface / two bulk
//!   endpoints (IN + OUT). Mirror of `azos_dfu::descriptors`.
//! - **Block I/O trait** — `BlockDevice` abstracts the kernel's
//!   FAT32 / SD card backing store from the SCSI handler. Lets
//!   host tests use a `Vec<[u8; 512]>` as a mock disk.
//!
//! ## Out of scope
//!
//! - Real USB device controller programming (DWC2 register
//!   surface) — that's the `azos_drv_bus::usb_device` impl
//!   and needs hardware to validate.
//! - Boot-time selection (USB connected → DFU vs MSC vs both via
//!   USB Composite). Today the kernel picks ONE mode based on
//!   the recovery decision; multi-function is a follow-up.
//!
//! ## Scope: protocol only
//!
//! Same caveat as DEV02. The pure protocol layer + SCSI command
//! handling is exhaustively unit-tested on host; the USB
//! controller wiring is a stub until VF2 / K1 hardware arrives.

#![no_std]

pub mod bbb;
pub mod descriptors;
pub mod dispatch;
pub mod scsi;
pub mod state;

pub use bbb::{
    Cbw, Csw, CBW_SIGNATURE, CSW_SIGNATURE,
    CSW_STATUS_OK, CSW_STATUS_FAIL, CSW_STATUS_PHASE_ERROR,
    CBW_DIR_OUT, CBW_DIR_IN,
    CBW_TOTAL_LEN, CSW_TOTAL_LEN, CBW_CDB_MAX_LEN,
};
pub use descriptors::{
    MSC_INTERFACE_CLASS, MSC_INTERFACE_SUBCLASS_SCSI,
    MSC_INTERFACE_PROTOCOL_BBB,
    MSC_BULK_EP_MAX_PACKET, MscDescriptorBuilder,
};
pub use scsi::{
    BlockDevice, ScsiCommand, ScsiResponse, Sense,
    SCSI_OP_TEST_UNIT_READY, SCSI_OP_REQUEST_SENSE, SCSI_OP_INQUIRY,
    SCSI_OP_MODE_SENSE_6, SCSI_OP_READ_CAPACITY_10, SCSI_OP_READ_10,
    SCSI_OP_WRITE_10, SCSI_OP_SYNCHRONIZE_CACHE_10,
    MODE_PAGE_CACHING, MODE_PAGE_ALL, CACHING_WCE, mode_sense6_full_len,
    parse_scsi_command, execute_scsi,
};
pub use state::{MscPhase, MscStateMachine};
pub use dispatch::{
    block_bytes, dispatch_cbw, lba_range_in_bounds, Action, CbwTag,
    DISPATCH_IN_BUF_LEN, MSC_MAX_LUN,
};
