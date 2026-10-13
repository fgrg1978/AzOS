// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DFU 1.1 state machine (USB-IF DFU 1.1 spec §6).
//!
//! The state machine sees an **opaque transfer**: it counts bytes
//! the host writes (DNLOAD requests) but does not interpret them.
//! Persistence is the caller's job — typical flow is:
//!
//! 1. Host sends `SET_INTERFACE` to alt-setting 0 → state goes
//!    from `AppIdle` to `DfuIdle` (after `Detach` if started from
//!    runtime mode).
//! 2. Host sends `DNLOAD` with chunks of size `wTransferSize`.
//!    Each chunk advances state: `DfuIdle` → `DnloadSync` →
//!    `DnloadIdle` (after the device polls `GETSTATUS` and reports
//!    `OK`). Last chunk has length 0 → `ManifestSync` → `Manifest`
//!    → `ManifestWaitReset`.
//! 3. Host triggers USB bus reset → device re-enumerates as either
//!    runtime mode (manifestation tolerant) or DFU mode (not
//!    tolerant, ready for another download).
//!
//! Errors on any transition land in `Error` with an appropriate
//! `STATUS_ERR_*` code; the host clears via `CLR_STATUS`.

#![allow(dead_code)] // many bStatus codes unused on this build target

// ── bState (DFU 1.1 §6.1.2 Table 6.4) ─────────────────────────

/// DFU 1.1 device states. Numeric values are the wire encoding
/// (returned in DFU_GETSTATE / GETSTATUS responses).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DfuState {
    AppIdle              = 0,
    AppDetach            = 1,
    DfuIdle              = 2,
    DnloadSync           = 3,
    DnloadBusy           = 4,
    DnloadIdle           = 5,
    ManifestSync         = 6,
    Manifest             = 7,
    ManifestWaitReset    = 8,
    UploadIdle           = 9,
    Error                = 10,
}

impl DfuState {
    pub const fn as_u8(self) -> u8 { self as u8 }

    /// True iff the host can safely issue a DNLOAD from this state.
    pub const fn accepts_dnload(self) -> bool {
        matches!(self, DfuState::DfuIdle | DfuState::DnloadIdle)
    }

    /// True iff `GETSTATUS` will report a non-zero `bwPollTimeout`
    /// (i.e. the device is asking the host to wait before polling
    /// again — used during DnloadBusy / Manifest).
    pub const fn poll_timeout_ms(self) -> u32 {
        match self {
            // Conservative defaults; calling code can override per
            // physical erase/write time.
            DfuState::DnloadBusy => 5,
            DfuState::Manifest   => 25,
            _                    => 0,
        }
    }
}

// ── bStatus (DFU 1.1 §6.1.2 Table 6.3) ────────────────────────

pub const STATUS_OK:               u8 = 0x00;
pub const STATUS_ERR_TARGET:       u8 = 0x01;
pub const STATUS_ERR_FILE:         u8 = 0x02;
pub const STATUS_ERR_WRITE:        u8 = 0x03;
pub const STATUS_ERR_ERASE:        u8 = 0x04;
pub const STATUS_ERR_CHECK_ERASED: u8 = 0x05;
pub const STATUS_ERR_PROG:         u8 = 0x06;
pub const STATUS_ERR_VERIFY:       u8 = 0x07;
pub const STATUS_ERR_ADDRESS:      u8 = 0x08;
pub const STATUS_ERR_NOTDONE:      u8 = 0x09;
pub const STATUS_ERR_FIRMWARE:     u8 = 0x0A;
pub const STATUS_ERR_VENDOR:       u8 = 0x0B;
pub const STATUS_ERR_USBR:         u8 = 0x0C;
pub const STATUS_ERR_POR:          u8 = 0x0D;
pub const STATUS_ERR_UNKNOWN:      u8 = 0x0E;
pub const STATUS_ERR_STALLEDPKT:   u8 = 0x0F;

/// DFU_GETSTATUS response payload — 6 bytes on the wire.  Field
/// names are snake_case (Rust convention); the spec uses camelCase
/// (bStatus / bState / iString).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfuStatus {
    pub b_status:      u8,
    pub poll_timeout:  u32,   // 24-bit on the wire (little-endian)
    pub b_state:       DfuState,
    pub i_string:      u8,
}

impl DfuStatus {
    /// Encode as the 6-byte GETSTATUS reply.
    pub const fn encode(self) -> [u8; 6] {
        [
            self.b_status,
            (self.poll_timeout      & 0xFF) as u8,
            (self.poll_timeout >> 8 & 0xFF) as u8,
            (self.poll_timeout >>16 & 0xFF) as u8,
            self.b_state.as_u8(),
            self.i_string,
        ]
    }
}

// ── State machine ─────────────────────────────────────────────

/// Tracks the DFU state + accumulated download progress. Caller
/// owns the staging buffer.
#[derive(Clone, Copy, Debug)]
pub struct DfuStateMachine {
    state:            DfuState,
    last_status:      u8,
    pub bytes_written: usize,
    pub max_image_size: usize,
    /// Transfer size negotiated via the functional descriptor.
    pub transfer_size: u16,
}

impl DfuStateMachine {
    /// New machine in runtime (application) mode — the boot path
    /// when DFU is reached from "normal" operation.
    pub const fn new_runtime(max_image_size: usize, transfer_size: u16) -> Self {
        Self {
            state: DfuState::AppIdle,
            last_status: STATUS_OK,
            bytes_written: 0,
            max_image_size,
            transfer_size,
        }
    }

    /// New machine in DFU mode — the boot path when recovery
    /// triggered (button held, crash counter exceeded, etc.). The
    /// device re-enumerates already in `DfuIdle` so no Detach is
    /// required.
    pub const fn new_dfu_mode(max_image_size: usize, transfer_size: u16) -> Self {
        Self {
            state: DfuState::DfuIdle,
            last_status: STATUS_OK,
            bytes_written: 0,
            max_image_size,
            transfer_size,
        }
    }

    pub const fn state(&self) -> DfuState { self.state }
    pub const fn last_status(&self) -> u8 { self.last_status }

    /// Build a [`DfuStatus`] reply for `GETSTATUS`.
    pub const fn status(&self) -> DfuStatus {
        DfuStatus {
            b_status: self.last_status,
            poll_timeout: self.state.poll_timeout_ms(),
            b_state: self.state,
            i_string: 0,
        }
    }

    // ── Transitions ───────────────────────────────────────────

    /// DFU_DETACH from `AppIdle`. Transitions to `AppDetach`; the
    /// device then re-enumerates as DFU-mode (`new_dfu_mode`).
    pub fn detach(&mut self) -> Result<(), DfuError> {
        if self.state != DfuState::AppIdle {
            return self.into_error(STATUS_ERR_STALLEDPKT);
        }
        self.state = DfuState::AppDetach;
        Ok(())
    }

    /// DFU_DNLOAD with `chunk_len` bytes of new payload. Length 0
    /// signals "end of download" → `ManifestSync`.
    pub fn dnload(&mut self, chunk_len: u16) -> Result<(), DfuError> {
        if !self.state.accepts_dnload() {
            return self.into_error(STATUS_ERR_STALLEDPKT);
        }
        if chunk_len == 0 {
            self.state = DfuState::ManifestSync;
            return Ok(());
        }
        if chunk_len > self.transfer_size {
            return self.into_error(STATUS_ERR_STALLEDPKT);
        }
        let new_total = self.bytes_written.saturating_add(chunk_len as usize);
        if new_total > self.max_image_size {
            return self.into_error(STATUS_ERR_ADDRESS);
        }
        self.bytes_written = new_total;
        self.state = DfuState::DnloadSync;
        Ok(())
    }

    /// Host polled `GETSTATUS` while in `DnloadSync` — advance to
    /// `DnloadIdle` (caller has finished the per-chunk persistence).
    /// Or while in `ManifestSync` — advance to `Manifest`.
    pub fn finish_sync(&mut self) -> Result<(), DfuError> {
        match self.state {
            DfuState::DnloadSync => {
                self.state = DfuState::DnloadIdle;
                Ok(())
            }
            DfuState::ManifestSync => {
                self.state = DfuState::Manifest;
                Ok(())
            }
            _ => self.into_error(STATUS_ERR_STALLEDPKT),
        }
    }

    /// Caller has finished the manifestation (commit firmware to
    /// flash, verify signature, etc.). Advance to
    /// `ManifestWaitReset` — host will issue USB reset to boot
    /// the new image.
    pub fn finish_manifest(&mut self) -> Result<(), DfuError> {
        if self.state != DfuState::Manifest {
            return self.into_error(STATUS_ERR_STALLEDPKT);
        }
        self.state = DfuState::ManifestWaitReset;
        Ok(())
    }

    /// DFU_ABORT — host gives up on the current download/upload.
    /// Returns to `DfuIdle` from any non-error mid-transfer state.
    pub fn abort(&mut self) -> Result<(), DfuError> {
        match self.state {
            DfuState::DfuIdle | DfuState::DnloadSync | DfuState::DnloadIdle
            | DfuState::ManifestSync | DfuState::UploadIdle => {
                self.state = DfuState::DfuIdle;
                self.bytes_written = 0;
                self.last_status = STATUS_OK;
                Ok(())
            }
            _ => self.into_error(STATUS_ERR_STALLEDPKT),
        }
    }

    /// DFU_CLRSTATUS — clear error state, back to `DfuIdle`.
    pub fn clr_status(&mut self) -> Result<(), DfuError> {
        if self.state != DfuState::Error {
            return self.into_error(STATUS_ERR_STALLEDPKT);
        }
        self.state = DfuState::DfuIdle;
        self.last_status = STATUS_OK;
        self.bytes_written = 0;
        Ok(())
    }

    /// Drive the machine into `Error` with an explicit `STATUS_ERR_*` code.
    ///
    /// The caller owns persistence (see the module docs), so the caller is
    /// also the only party that can discover a *commit-time* failure — a
    /// refused image, a write that did not land, a flash erase that failed.
    /// Without this, such a caller has no way to say so: `into_error` is
    /// private, and the workaround in `kernel/src/dfu_recovery.rs` was to
    /// call `clr_status()` and rely on it being illegal from the current
    /// state so that it landed in `Error` as a side effect. That put a
    /// *misleading* code in `bStatus` (whatever `clr_status`'s own failure
    /// used, `ERR_STALLEDPKT`) and only worked by accident of which state we
    /// happened to be in — from `Error` it would have "succeeded" and reset
    /// the machine to `DfuIdle`, reporting OK for a failed commit.
    ///
    /// `bStatus` is the only channel DFU gives the device to explain itself,
    /// and this is the recovery path of last resort; a host that is told
    /// `ERR_STALLEDPKT` when the truth is "I refused your image" retries the
    /// same transfer forever.
    pub fn fail(&mut self, code: u8) {
        let _ = self.into_error(code);
    }

    fn into_error(&mut self, code: u8) -> Result<(), DfuError> {
        self.state = DfuState::Error;
        self.last_status = code;
        Err(DfuError(code))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfuError(pub u8);
