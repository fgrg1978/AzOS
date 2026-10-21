// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ESC register map and the two records a master writes to configure process
//! data: the FMMU (logical to physical mapping) and the sync manager (a
//! physical buffer with a direction and a mode). ETG.1000.4 section 6.

/// ESC type, revision, build: 6 bytes.
pub const TYPE: u16 = 0x0000;
/// Configured station address (16 bit), set by the master, matched by FPxx.
pub const STATION_ADDR: u16 = 0x0010;
/// DL status: port link and loop state.
pub const DL_STATUS: u16 = 0x0110;
/// AL control (16 bit): requested state in bits 0..3, error acknowledge bit 4.
pub const AL_CONTROL: u16 = 0x0120;
/// AL status (16 bit): current state in bits 0..3, error indication bit 4.
pub const AL_STATUS: u16 = 0x0130;
/// AL status code (16 bit): why a transition was refused.
pub const AL_STATUS_CODE: u16 = 0x0134;

/// Receive time, port 0 (32 bit), latched when a BWR to this address passes.
pub const RX_TIME_P0: u16 = 0x0900;
/// Receive time, port 1 (32 bit), latched together with port 0.
pub const RX_TIME_P1: u16 = 0x0904;
/// Local system time (64 bit), what the DC unit reads as "now".
pub const SYS_TIME: u16 = 0x0910;
/// Receive time of the ECAT processing unit (64 bit), latched with port 0.
pub const RX_TIME_PU: u16 = 0x0918;
/// System time offset (64 bit): system time = local time + this.
pub const SYS_TIME_OFFSET: u16 = 0x0920;
/// System time delay (32 bit): propagation delay from the reference clock.
pub const SYS_TIME_DELAY: u16 = 0x0928;

/// First FMMU record.
pub const FMMU_BASE: u16 = 0x0600;
/// Bytes per FMMU record.
pub const FMMU_LEN: usize = 16;
/// First sync manager record.
pub const SM_BASE: u16 = 0x0800;
/// Bytes per sync manager record.
pub const SM_LEN: usize = 8;
/// Start of the process data RAM; sync manager buffers live from here on.
pub const PDRAM_BASE: u16 = 0x1000;

/// Register address of FMMU `n`.
pub const fn fmmu_addr(n: u8) -> u16 {
    FMMU_BASE + (n as u16) * FMMU_LEN as u16
}

/// Register address of sync manager `n`.
pub const fn sm_addr(n: u8) -> u16 {
    SM_BASE + (n as u16) * SM_LEN as u16
}

/// Direction of an FMMU mapping, seen from the master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FmmuDir {
    /// Slave memory is read into the logical image (slave inputs).
    Read = 1,
    /// The logical image is written into slave memory (slave outputs).
    Write = 2,
}

/// One FMMU record: maps `len` bytes of the 32-bit logical address space onto
/// slave physical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fmmu {
    pub logical_start: u32,
    pub len: u16,
    pub logical_start_bit: u8,
    pub logical_stop_bit: u8,
    pub phys_start: u16,
    pub phys_start_bit: u8,
    pub dir: FmmuDir,
    pub enabled: bool,
}

impl Fmmu {
    /// A byte-aligned, enabled mapping.
    pub fn new(dir: FmmuDir, logical_start: u32, len: u16, phys_start: u16) -> Fmmu {
        Fmmu {
            logical_start,
            len,
            logical_start_bit: 0,
            logical_stop_bit: 7,
            phys_start,
            phys_start_bit: 0,
            dir,
            enabled: true,
        }
    }

    /// The register image, as written at [`fmmu_addr`].
    pub fn encode(&self) -> [u8; FMMU_LEN] {
        let mut b = [0u8; FMMU_LEN];
        b[0..4].copy_from_slice(&self.logical_start.to_le_bytes());
        b[4..6].copy_from_slice(&self.len.to_le_bytes());
        b[6] = self.logical_start_bit;
        b[7] = self.logical_stop_bit;
        b[8..10].copy_from_slice(&self.phys_start.to_le_bytes());
        b[10] = self.phys_start_bit;
        b[11] = self.dir as u8;
        b[12] = u8::from(self.enabled);
        b
    }

    /// Read a record back. `None` when the direction byte is neither read nor
    /// write (an unconfigured FMMU is all zeros).
    pub fn decode(b: &[u8; FMMU_LEN]) -> Option<Fmmu> {
        let dir = match b[11] & 0x03 {
            1 => FmmuDir::Read,
            2 => FmmuDir::Write,
            _ => return None,
        };
        Some(Fmmu {
            logical_start: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            len: u16::from_le_bytes([b[4], b[5]]),
            logical_start_bit: b[6] & 0x07,
            logical_stop_bit: b[7] & 0x07,
            phys_start: u16::from_le_bytes([b[8], b[9]]),
            phys_start_bit: b[10] & 0x07,
            dir,
            enabled: b[12] & 1 != 0,
        })
    }

    /// Whole bytes only: the mapping starts at bit 0 of its first byte and ends
    /// at bit 7 of its last.
    pub fn byte_aligned(&self) -> bool {
        self.logical_start_bit == 0 && self.logical_stop_bit == 7 && self.phys_start_bit == 0
    }
}

/// Sync manager control byte values. Bits 0..1 mode, 2..3 direction, 5 ECAT
/// event, 6 PDI event (7 watchdog trigger is left to the caller).
pub mod sm_control {
    /// Mailbox, written by the master, ECAT event enabled.
    pub const MAILBOX_OUT: u8 = 0x26;
    /// Mailbox, read by the master, ECAT event enabled.
    pub const MAILBOX_IN: u8 = 0x22;
    /// Three-buffer process data written by the master (outputs).
    pub const PROCESS_OUT: u8 = 0x64;
    /// Three-buffer process data read by the master (inputs).
    pub const PROCESS_IN: u8 = 0x20;
}

/// One sync manager record: a window of the slave's process data RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncManager {
    pub phys_start: u16,
    pub len: u16,
    pub control: u8,
    pub enabled: bool,
}

impl SyncManager {
    /// An enabled sync manager.
    pub fn new(phys_start: u16, len: u16, control: u8) -> SyncManager {
        SyncManager { phys_start, len, control, enabled: true }
    }

    /// The register image, as written at [`sm_addr`]. The status byte is read
    /// only and the PDI control byte is left at 0 (PDI does not deactivate it).
    pub fn encode(&self) -> [u8; SM_LEN] {
        let mut b = [0u8; SM_LEN];
        b[0..2].copy_from_slice(&self.phys_start.to_le_bytes());
        b[2..4].copy_from_slice(&self.len.to_le_bytes());
        b[4] = self.control;
        b[6] = u8::from(self.enabled);
        b
    }

    /// Read a record back.
    pub fn decode(b: &[u8; SM_LEN]) -> SyncManager {
        SyncManager {
            phys_start: u16::from_le_bytes([b[0], b[1]]),
            len: u16::from_le_bytes([b[2], b[3]]),
            control: b[4],
            enabled: b[6] & 1 != 0,
        }
    }
}
