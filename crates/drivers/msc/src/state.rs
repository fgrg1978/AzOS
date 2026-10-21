// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MSC Bulk-Only Transport state machine (USB MSC BBB §5.1).
//!
//! The endpoint loop drives:
//!
//!   `Idle` → `DataIn` / `DataOut` / `Status` → `Idle`
//!
//! With error transitions on signature mismatch (CBW) or stalled
//! endpoint that lands in `Reset` — the host issues
//! `MASS_STORAGE_RESET` + ClearFeature(HALT) on both bulk
//! endpoints, then the device returns to `Idle`.

/// MSC transport phase. The endpoint loop reads this to decide
/// what to do with the next bulk packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MscPhase {
    /// Awaiting the next CBW on the bulk-OUT endpoint.
    Idle,
    /// Reading data-out payload (host→device) for a WRITE.
    DataOut { remaining: u32 },
    /// Writing data-in payload (device→host) for an INQUIRY /
    /// READ / etc. `remaining` is bytes still to transmit.
    DataIn  { remaining: u32 },
    /// CBW + (optional) data complete; transmitting the CSW.
    Status,
    /// Error path — endpoints stalled, awaiting reset recovery.
    Reset,
}

#[derive(Clone, Copy, Debug)]
pub struct MscStateMachine {
    phase: MscPhase,
}

impl MscStateMachine {
    pub const fn new() -> Self {
        Self { phase: MscPhase::Idle }
    }

    pub const fn phase(&self) -> MscPhase { self.phase }

    /// Mark the next phase explicitly. Used by the BBB driver
    /// after parsing a CBW + handing the SCSI command to
    /// `execute_scsi`.
    pub fn set_phase(&mut self, p: MscPhase) {
        self.phase = p;
    }

    /// Host sent `MASS_STORAGE_RESET` on EP0 + ClearFeature(HALT)
    /// on both bulk endpoints. Phase returns to Idle.
    pub fn reset(&mut self) {
        self.phase = MscPhase::Idle;
    }
}

impl Default for MscStateMachine {
    fn default() -> Self { Self::new() }
}
