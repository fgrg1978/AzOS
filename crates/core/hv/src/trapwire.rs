// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wire form of the device-model protocol: the trap and completion records
//! and the page they travel on.
//!
//! One file, two readers. The monitor (`crate::ring`, kernel side) produces
//! [`Trap`]s and consumes [`Completion`]s; `VMMD.ELF` (`userspace/services/vmmd`,
//! ring 3) consumes the traps and produces the completions. Both include this
//! file (vmmd by `#[path]`), so the layout has one source and neither side can
//! drift from the other. It depends on nothing.
//!
//! A guest access that lands in a window `Vm::window` registered is a **trap**:
//! one record on the trap ring, the vCPU waiting for its completion on the
//! completion ring. Both rings are one shared page; vmmd owns the consuming end
//! of the trap ring and the producing end of the completion ring, the monitor
//! the other two. Data moves through the rings; the only call is the sleep on
//! the event port that says the trap ring has an entry.
//!
//! The page (little-endian, 4096 bytes):
//!
//! | offset | what |
//! |-------:|------|
//! | `0x00` | `trap_head` (vmmd writes), `trap_tail` (monitor), `cpl_head` (monitor), `cpl_tail` (vmmd) — four `u32`, free-running |
//! | `0x40` | [`TRAPS`] trap records of [`TRAP_BYTES`] |
//! | `0x40 + TRAPS * 32` | [`TRAPS`] completion records of [`CPL_BYTES`] |
//!
//! A trap is `seq u32 | vcpu u8 | write u8 | len u8 | pad u8 | gpa u64 |
//! data u64 | pad 8` and a completion `seq u32 | status u32 | data u64`. The
//! indexes are free-running counters; the ring is full when they are
//! [`TRAPS`] apart.

// Each reader uses a part of the file.
#![allow(dead_code)]

pub const TRAPS: u32 = 64;
pub const TRAP_BYTES: usize = 32;
pub const CPL_BYTES: usize = 16;
pub const TRAP_AT: usize = 0x40;
pub const CPL_AT: usize = TRAP_AT + TRAPS as usize * TRAP_BYTES;
/// Bytes the shared page needs.
pub const PAGE_BYTES: usize = CPL_AT + TRAPS as usize * CPL_BYTES;
const _: () = assert!(PAGE_BYTES <= 4096);

/// Offset of the index vmmd advances when it takes a trap.
pub const TRAP_HEAD: usize = 0x00;
/// Offset of the index the monitor advances when it posts a trap.
pub const TRAP_TAIL: usize = 0x04;
/// Offset of the index the monitor advances when it takes a completion.
pub const CPL_HEAD: usize = 0x08;
/// Offset of the index vmmd advances when it answers.
pub const CPL_TAIL: usize = 0x0c;

/// One guest access to a device window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trap {
    pub seq: u32,
    pub vcpu: u8,
    /// A store (else a load).
    pub write: bool,
    /// Bytes accessed: 1, 2, 4 or 8.
    pub len: u8,
    pub gpa: u64,
    /// The value stored (a load: 0).
    pub data: u64,
}

/// Completion `status`.
pub mod cpl {
    /// Served; `data` is the loaded value.
    pub const OK: u32 = 0;
    /// No device answers there; a load reads 0 and a store is dropped.
    pub const NO_DEVICE: u32 = 1;
    /// An access size the bus does not decode (not 1, 2, 4 or 8 bytes).
    pub const BAD_ACCESS: u32 = 2;
}

/// The answer to a [`Trap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub seq: u32,
    pub status: u32,
    pub data: u64,
}

impl Trap {
    pub fn encode(&self) -> [u8; TRAP_BYTES] {
        let mut b = [0u8; TRAP_BYTES];
        b[0..4].copy_from_slice(&self.seq.to_le_bytes());
        b[4] = self.vcpu;
        b[5] = self.write as u8;
        b[6] = self.len;
        b[8..16].copy_from_slice(&self.gpa.to_le_bytes());
        b[16..24].copy_from_slice(&self.data.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; TRAP_BYTES]) -> Trap {
        Trap {
            seq: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            vcpu: b[4],
            write: b[5] != 0,
            len: b[6],
            gpa: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            data: u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        }
    }
}

impl Completion {
    pub fn encode(&self) -> [u8; CPL_BYTES] {
        let mut b = [0u8; CPL_BYTES];
        b[0..4].copy_from_slice(&self.seq.to_le_bytes());
        b[4..8].copy_from_slice(&self.status.to_le_bytes());
        b[8..16].copy_from_slice(&self.data.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; CPL_BYTES]) -> Completion {
        Completion {
            seq: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            status: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            data: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        }
    }
}
