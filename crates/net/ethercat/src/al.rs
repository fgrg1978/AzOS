// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The application-layer (AL) state machine of an EtherCAT slave and the
//! master-side sequence that walks one slave from INIT to a target state.
//!
//! [`Bringup`] is sans-I/O: [`Bringup::request`] names the one datagram to
//! send next, [`Bringup::on_reply`] takes its answer. The caller frames the
//! datagram (see [`crate::frame`]), sends it, and decides how long to wait
//! between polls of the AL status; the sequencer only bounds how many it makes.

use crate::frame::{Addr, Cmd};
use crate::reg::{self, Fmmu, SyncManager};

/// AL control/status bit 4: error acknowledge (control) or indication (status).
pub const AL_ERROR_BIT: u8 = 0x10;

/// AL status codes the master acts on (ETG.1000.6 table 11).
pub mod status_code {
    pub const NONE: u16 = 0x0000;
    pub const UNSPECIFIED: u16 = 0x0001;
    pub const INVALID_STATE_CHANGE: u16 = 0x0011;
    pub const UNKNOWN_STATE: u16 = 0x0012;
    pub const INVALID_OUTPUT_CONFIG: u16 = 0x001D;
    pub const INVALID_INPUT_CONFIG: u16 = 0x001E;
    pub const SM_WATCHDOG: u16 = 0x001B;
}

/// An AL state. The numeric values are the register encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlState {
    Init = 0x01,
    PreOp = 0x02,
    /// Bootstrap, for firmware download only.
    Boot = 0x03,
    SafeOp = 0x04,
    Op = 0x08,
}

impl AlState {
    /// Decode the low nibble of an AL status byte.
    pub fn from_status(b: u8) -> Option<AlState> {
        match b & 0x0F {
            0x01 => Some(AlState::Init),
            0x02 => Some(AlState::PreOp),
            0x03 => Some(AlState::Boot),
            0x04 => Some(AlState::SafeOp),
            0x08 => Some(AlState::Op),
            _ => None,
        }
    }
}

/// Whether a master may request `to` while the slave is in `from`
/// (ETG.1000.6 figure 8: forward one step at a time, back any number, BOOT only
/// from and to INIT). Requesting the current state is a no-op and allowed.
pub fn transition_allowed(from: AlState, to: AlState) -> bool {
    use AlState::*;
    if from == to {
        return true;
    }
    match (from, to) {
        (Init, PreOp) | (Init, Boot) | (Boot, Init) => true,
        (PreOp, SafeOp) | (SafeOp, Op) => true,
        (PreOp, Init) | (SafeOp, Init) | (SafeOp, PreOp) | (Op, Init) | (Op, PreOp) | (Op, SafeOp) => true,
        _ => false,
    }
}

/// Why a bring-up stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringupError {
    /// The target must be PRE-OP, SAFE-OP or OP.
    BadTarget,
    /// A datagram came back with a working counter other than 1: the slave
    /// does not answer at that station address.
    NoResponse,
    /// The slave raised its error bit instead of entering `want`; `code` is the
    /// AL status code it reported. The error was acknowledged.
    Refused { want: AlState, code: u16 },
    /// The slave neither entered `want` nor raised an error within the polls.
    Timeout { want: AlState },
}

/// The datagram [`Bringup::request`] asks the caller to send. Always a
/// configured-address (FPRD or FPWR) command to the slave being brought up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub cmd: Cmd,
    pub addr: Addr,
    len: u8,
    data: [u8; reg::FMMU_LEN],
}

impl Request {
    fn write(station: u16, ado: u16, bytes: &[u8]) -> Request {
        let mut data = [0u8; reg::FMMU_LEN];
        data[..bytes.len()].copy_from_slice(bytes);
        Request { cmd: Cmd::Fpwr, addr: Addr::node(station, ado), len: bytes.len() as u8, data }
    }

    fn read(station: u16, ado: u16, len: u8) -> Request {
        Request { cmd: Cmd::Fprd, addr: Addr::node(station, ado), len, data: [0; reg::FMMU_LEN] }
    }

    /// Bytes to put in the datagram: the payload of a write, zeros of the read
    /// length for a read.
    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

/// What [`Bringup::request`] says to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Send this datagram and feed the answer to [`Bringup::on_reply`].
    Send(Request),
    /// The slave is in the target state and configured.
    Done,
    Failed(BringupError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Write the AL control register asking for `want`.
    Write(AlState),
    /// Read the AL status until it shows `want`.
    Poll(AlState),
    /// The slave flagged an error while we waited for `want`: read the code.
    ReadCode { want: AlState, seen: u8 },
    /// Acknowledge the error, then fail.
    Ack { want: AlState, seen: u8, code: u16 },
    /// Write sync manager `n`, then the next, then the FMMUs, then SAFE-OP.
    ConfigSm(usize),
    ConfigFmmu(usize),
    Done,
    Failed(BringupError),
}

/// Takes one slave, addressed by its configured station address, from whatever
/// state it is in to `target`: INIT (with error acknowledge), PRE-OP, sync
/// manager and FMMU configuration, SAFE-OP, OP, stopping at `target`.
pub struct Bringup<'a> {
    station: u16,
    target: AlState,
    sms: &'a [(u8, SyncManager)],
    fmmus: &'a [(u8, Fmmu)],
    max_polls: u16,
    polls_left: u16,
    phase: Phase,
}

impl<'a> Bringup<'a> {
    /// `sms` and `fmmus` pair a record with its index in the slave. They are
    /// written once, in PRE-OP, only when `target` is SAFE-OP or OP.
    /// `max_polls` bounds the AL status reads per state change.
    pub fn new(
        station: u16,
        target: AlState,
        sms: &'a [(u8, SyncManager)],
        fmmus: &'a [(u8, Fmmu)],
        max_polls: u16,
    ) -> Result<Self, BringupError> {
        if !matches!(target, AlState::PreOp | AlState::SafeOp | AlState::Op) {
            return Err(BringupError::BadTarget);
        }
        Ok(Bringup {
            station,
            target,
            sms,
            fmmus,
            max_polls,
            polls_left: max_polls,
            phase: Phase::Write(AlState::Init),
        })
    }

    /// The datagram to send next. Idempotent until [`Bringup::on_reply`].
    pub fn request(&self) -> Step {
        let st = self.station;
        match self.phase {
            Phase::Write(s) => {
                // Asking for INIT also acknowledges a latched error.
                let ack = if s == AlState::Init { AL_ERROR_BIT } else { 0 };
                Step::Send(Request::write(st, reg::AL_CONTROL, &[s as u8 | ack, 0]))
            }
            Phase::Poll(_) => Step::Send(Request::read(st, reg::AL_STATUS, 2)),
            Phase::ReadCode { .. } => Step::Send(Request::read(st, reg::AL_STATUS_CODE, 2)),
            Phase::Ack { seen, .. } => {
                Step::Send(Request::write(st, reg::AL_CONTROL, &[(seen & 0x0F) | AL_ERROR_BIT, 0]))
            }
            Phase::ConfigSm(i) => {
                let (n, sm) = self.sms[i];
                Step::Send(Request::write(st, reg::sm_addr(n), &sm.encode()))
            }
            Phase::ConfigFmmu(i) => {
                let (n, f) = self.fmmus[i];
                Step::Send(Request::write(st, reg::fmmu_addr(n), &f.encode()))
            }
            Phase::Done => Step::Done,
            Phase::Failed(e) => Step::Failed(e),
        }
    }

    /// Feed the answer to the datagram last returned by [`Bringup::request`].
    pub fn on_reply(&mut self, wkc: u16, data: &[u8]) {
        if matches!(self.phase, Phase::Done | Phase::Failed(_)) {
            return;
        }
        if wkc != 1 {
            self.phase = match self.phase {
                // The refusal is the better diagnosis; the ack is best effort.
                Phase::Ack { want, code, .. } => Phase::Failed(BringupError::Refused { want, code }),
                _ => Phase::Failed(BringupError::NoResponse),
            };
            return;
        }
        self.phase = match self.phase {
            Phase::Write(s) => {
                self.polls_left = self.max_polls;
                Phase::Poll(s)
            }
            Phase::Poll(want) => {
                let seen = data.first().copied().unwrap_or(0);
                if seen & AL_ERROR_BIT != 0 {
                    Phase::ReadCode { want, seen }
                } else if AlState::from_status(seen) == Some(want) {
                    self.reached(want)
                } else {
                    self.polls_left = self.polls_left.saturating_sub(1);
                    if self.polls_left == 0 {
                        Phase::Failed(BringupError::Timeout { want })
                    } else {
                        Phase::Poll(want)
                    }
                }
            }
            Phase::ReadCode { want, seen } => {
                let code = match data {
                    [lo, hi, ..] => u16::from_le_bytes([*lo, *hi]),
                    _ => status_code::NONE,
                };
                Phase::Ack { want, seen, code }
            }
            Phase::Ack { want, code, .. } => Phase::Failed(BringupError::Refused { want, code }),
            Phase::ConfigSm(i) => {
                if i + 1 < self.sms.len() {
                    Phase::ConfigSm(i + 1)
                } else {
                    self.after_sms()
                }
            }
            Phase::ConfigFmmu(i) => {
                if i + 1 < self.fmmus.len() {
                    Phase::ConfigFmmu(i + 1)
                } else {
                    Phase::Write(AlState::SafeOp)
                }
            }
            done_or_failed => done_or_failed,
        };
    }

    /// The state the slave has been confirmed in, and what follows.
    fn reached(&self, s: AlState) -> Phase {
        if s == self.target {
            return Phase::Done;
        }
        match s {
            AlState::Init => Phase::Write(AlState::PreOp),
            AlState::PreOp if !self.sms.is_empty() => Phase::ConfigSm(0),
            AlState::PreOp => self.after_sms(),
            AlState::SafeOp => Phase::Write(AlState::Op),
            // Op is only ever the target; Boot is never requested.
            AlState::Op | AlState::Boot => Phase::Done,
        }
    }

    fn after_sms(&self) -> Phase {
        if self.fmmus.is_empty() {
            Phase::Write(AlState::SafeOp)
        } else {
            Phase::ConfigFmmu(0)
        }
    }
}
