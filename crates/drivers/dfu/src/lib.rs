// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DEV02 — DFU 1.1 protocol state machine + USB descriptors.
//!
//! Implements the **device side** of the USB DFU 1.1 spec (USB-IF
//! "DFU_1.1.pdf", April 2004). When a AZOS board enters DFU mode
//! (recovery trigger — see [`ota::recovery`]), the USB device-mode
//! controller (DWC2 / DWC3 / similar) presents it as a DFU class
//! interface. A standard host tool like `dfu-util` can then push a
//! firmware image into the kernel-owned recovery slot without any
//! TCP/IP or filesystem available — the requirement that makes DFU
//! the right choice for "brick recovery".
//!
//! ## Scope
//!
//! - **State machine**: every legal DFU state transition (§6) +
//!   error transitions (§5.1.1). Pure data, exhaustively unit-tested.
//! - **Descriptors**: configuration / interface / DFU functional
//!   descriptor byte builders matching §4. The USB device controller
//!   driver hands these to the host during enumeration.
//! - **Request decoder**: parses USB Setup packets targeting the DFU
//!   class (§3.2) into typed [`DfuRequest`] variants.
//! - **Download / upload buffer accounting**: tracks how many bytes
//!   have been written into the staging area + the transfer's chunk
//!   layout per `wTransferSize`.
//!
//! Explicitly **out of scope** for this crate:
//! - The actual USB device controller register programming. That
//!   lives in `azos_drv_bus::usb_device` with a per-SoC impl
//!   (DWC2 on JH7110, etc). This crate is the controller-agnostic
//!   protocol layer.
//! - Persistent storage of the downloaded image. The caller passes
//!   in a `&dyn DfuStore` (deferred — see task #207's follow-up:
//!   DfuStore trait lands when the kernel-side hand-off is wired
//!   into `crates/core/ota/src/recovery.rs` post-hardware). Currently
//!   the staging buffer is opaque from the protocol's point of
//!   view — the state machine just tracks byte counts.
//!
//! ## Why a separate crate
//!
//! Mirrors the `azos_tftp` / `azos_ota` split: the wire
//! protocol is pure logic, host-testable, no_std, and lives away
//! from the kernel so a regression test suite can hammer the state
//! machine without QEMU.

#![no_std]

pub mod accumulator;
pub mod descriptors;
pub mod protocol;
pub mod state;

pub use accumulator::{AccumulatorError, ChunkAccumulator};

pub use descriptors::{
    DFU_INTERFACE_CLASS, DFU_INTERFACE_SUBCLASS,
    DFU_INTERFACE_PROTOCOL_RUNTIME, DFU_INTERFACE_PROTOCOL_DFU,
    DFU_FUNC_DESCRIPTOR_TYPE, DFU_FUNC_DESCRIPTOR_LEN,
    DFU_ATTR_CAN_DOWNLOAD, DFU_ATTR_CAN_UPLOAD,
    DFU_ATTR_MANIFESTATION_TOLERANT, DFU_ATTR_WILL_DETACH,
    DescriptorBuilder, FunctionalDescriptor,
};
pub use protocol::{
    DfuRequest, DfuRequestType,
    DFU_REQ_DETACH, DFU_REQ_DNLOAD, DFU_REQ_UPLOAD, DFU_REQ_GETSTATUS,
    DFU_REQ_CLRSTATUS, DFU_REQ_GETSTATE, DFU_REQ_ABORT,
    parse_setup_packet, SetupPacket,
};
pub use state::{
    DfuState, DfuStatus, DfuStateMachine,
    STATUS_OK, STATUS_ERR_TARGET, STATUS_ERR_FILE, STATUS_ERR_WRITE,
    STATUS_ERR_ERASE, STATUS_ERR_CHECK_ERASED, STATUS_ERR_PROG,
    STATUS_ERR_VERIFY, STATUS_ERR_ADDRESS, STATUS_ERR_NOTDONE,
    STATUS_ERR_FIRMWARE, STATUS_ERR_VENDOR, STATUS_ERR_USBR,
    STATUS_ERR_POR, STATUS_ERR_UNKNOWN, STATUS_ERR_STALLEDPKT,
};
