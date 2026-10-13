// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where a driver's code runs, as a row of the signed topology says it
//! (CAPS.TOML format 6).
//!
//! A driver that exists in two hosts from one source (the chip logic written
//! once, `crates/drivers/buzzer`: a kernel host that is called directly and a
//! ring-3 program that serves the same interface on an endpoint) has its
//! **placement** in its row:
//!
//! * `place = "kernel" | "ring3"`: the host the driver starts in
//!   ([`Host`]); `ring3` unless declared;
//! * `stateless = true`: the driver keeps nothing a restart cannot rebuild
//!   from its row and the device (the H10 flag), so it can be started on the
//!   other host with no state transfer. Only such a row may move at run
//!   time; a row without the flag stays where it is declared;
//! * `call_budget_us = N`: the time one call to the driver may take from the
//!   caller's side, the contract a move to the kernel is admitted against
//!   (0, the default: none declared, the driver is never promoted for cost).
//!
//! The row is the declaration; whether a move happens, and why, is decided
//! at run time by [`Elastic`] from what the driver is measured to cost and
//! from its faults, and every move leaves a `Rule::Placement` decision record
//! (`azos_decision`): [`Elastic::commit`], the one place the host changes,
//! writes it.
//!
//! * Fault: a `stateless` driver whose kernel host faulted restarts in ring 3
//!   (demote).
//! * Deadline: a `stateless` driver with a `call_budget_us` whose ring-3 calls
//!   break it moves into the kernel (promote), if the kernel host's measured
//!   cost fits the budget and the kernel host has not faulted within the
//!   hold-off. A refusal is a record too, with the cost the budget would have
//!   had to cover.

/// Where a driver runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Host {
    /// In the kernel: called directly, no message, no task switch.
    Kernel = 1,
    /// In a ring-3 program that serves the interface on an endpoint.
    Ring3 = 2,
}

impl Host {
    /// The row value: `"kernel"`, `"ring3"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"kernel" => Some(Host::Kernel),
            b"ring3" => Some(Host::Ring3),
            _ => None,
        }
    }

    /// The row value [`Host::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            Host::Kernel => "kernel",
            Host::Ring3 => "ring3",
        }
    }

    /// The host a record's `move` word names (1 = kernel, 2 = ring 3).
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Host::Kernel),
            2 => Some(Host::Ring3),
            _ => None,
        }
    }

    /// The other host.
    pub const fn other(self) -> Self {
        match self {
            Host::Kernel => Host::Ring3,
            Host::Ring3 => Host::Kernel,
        }
    }
}

/// A row's placement attributes (format 6): where it starts, whether it may
/// move, and the call budget a move to the kernel is admitted against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PlaceSpec {
    /// `place = ...`: the host the driver starts in.
    pub host: Host,
    /// `stateless = true`: the driver can be restarted on the other host
    /// with no state transfer.
    pub stateless: bool,
    /// `call_budget_us = N`: 0 for none.
    pub call_budget_us: u32,
}

impl PlaceSpec {
    /// What every row that declares nothing has: ring 3, fixed there.
    pub const DEFAULT: PlaceSpec = PlaceSpec { host: Host::Ring3, stateless: false, call_budget_us: 0 };

    /// Does the row declare anything (so the emitter writes it)?
    pub const fn is_default(&self) -> bool {
        matches!(self.host, Host::Ring3) && !self.stateless && self.call_budget_us == 0
    }

    /// May the driver of this row move between hosts at run time?
    pub const fn elastic(&self) -> bool {
        self.stateless
    }
}

// ── The controller ──────────────────────────────────────────────────────

/// Why a driver moved, or was asked to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Reason {
    /// The kernel host faulted: the driver restarts in ring 3.
    Fault = 1,
    /// The ring-3 host's measured call cost broke the row's budget: the
    /// driver moves into the kernel.
    Deadline = 2,
}

/// Why a move was not admitted (the `cause` of a refusal's `move` word).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Cause {
    /// The other host's measured cost does not fit the budget; the
    /// counter-offer is that cost.
    HostCost = 1,
    /// The other host has never been measured, so nothing can be admitted
    /// against it.
    Unmeasured = 2,
    /// The kernel host faulted, or could not be started, less than the hold-off
    /// ago: the driver is not moved back into the code that just failed.
    RecentFault = 3,
    /// The move was admitted and then could not be done (the other host did
    /// not start); the driver stays where it is.
    Failed = 4,
}

/// One move of a driver from a host to the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Move {
    /// The host the driver leaves.
    pub from: Host,
    /// The host it goes to.
    pub to: Host,
    /// Why.
    pub reason: Reason,
}

impl Move {
    /// The `move` word of a [`Rule::Placement`](azos_decision::Rule)
    /// record: `cause << 24 | reason << 16 | from << 8 | to` (`cause` 0 for a
    /// move that was made).
    pub const fn pack(self, cause: Option<Cause>) -> u64 {
        let c = match cause {
            Some(c) => c as u64,
            None => 0,
        };
        c << 24 | (self.reason as u64) << 16 | (self.from as u64) << 8 | self.to as u64
    }

    /// The move and cause a `move` word names.
    pub const fn unpack(w: u64) -> Option<(Move, Option<Cause>)> {
        let (to, from) = (Host::from_code(w as u8), Host::from_code((w >> 8) as u8));
        let reason = match (w >> 16) as u8 {
            1 => Reason::Fault,
            2 => Reason::Deadline,
            _ => return None,
        };
        let cause = match (w >> 24) as u8 {
            0 => None,
            1 => Some(Cause::HostCost),
            2 => Some(Cause::Unmeasured),
            3 => Some(Cause::RecentFault),
            4 => Some(Cause::Failed),
            _ => return None,
        };
        match (from, to) {
            (Some(from), Some(to)) => Some((Move { from, to, reason }, cause)),
            _ => None,
        }
    }
}

/// The numbers a move or a refusal is recorded with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Receipt {
    /// The move decided, or refused.
    pub mv: Move,
    /// The cost that decided it: the ring-3 host's worst call in the window
    /// (a promotion), or its last measured worst (a demotion; 0 if never).
    pub measured_ns: u64,
    /// The budget it was admitted against; on a refusal for [`Cause::HostCost`]
    /// the smallest budget that would have admitted it (the counter-offer).
    pub limit_ns: u64,
}

/// What the controller decides.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Nothing to do.
    Stay,
    /// Move the driver, then [`Elastic::commit`] it.
    Move(Receipt),
    /// The move is not admitted. Already recorded; the driver stays.
    Refused(Cause),
}

/// Calls the cost window remembers.
pub const WINDOW: usize = 16;

/// When a driver moves (Kconfig `PLACEMENT_*`, `azos_limits`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// Calls of the last [`WINDOW`] that must break the budget to ask for a
    /// promotion.
    pub misses: u8,
    /// How long after a fault in the kernel host a move back into the kernel
    /// is refused. A driver that faults in the kernel and is slow in ring 3
    /// would otherwise trade places for ever.
    pub holdoff_ns: u64,
}

impl Policy {
    /// The Kconfig values.
    pub const fn from_limits() -> Policy {
        Policy {
            misses: azos_limits::PLACEMENT_PROMOTE_MISSES as u8,
            holdoff_ns: azos_limits::PLACEMENT_HOLDOFF_S as u64 * 1_000_000_000,
        }
    }
}

/// The placement of one driver row at run time: the host it is in, what its
/// calls cost there, and whether it may move.
#[derive(Clone, Copy, Debug)]
pub struct Elastic {
    row: u32,
    spec: PlaceSpec,
    policy: Policy,
    host: Host,
    costs: [u64; WINDOW],
    n: usize,
    next: usize,
    kernel_ns: u64,
    ring3_ns: u64,
    fault_at: Option<u64>,
    latched: bool,
}

impl Elastic {
    /// The driver of topology row `row`, started on the host its row says.
    pub const fn new(row: u32, spec: PlaceSpec, policy: Policy) -> Elastic {
        Elastic {
            row,
            spec,
            policy,
            host: spec.host,
            costs: [0; WINDOW],
            n: 0,
            next: 0,
            kernel_ns: 0,
            ring3_ns: 0,
            fault_at: None,
            latched: false,
        }
    }

    /// The host the driver is in.
    pub const fn host(&self) -> Host {
        self.host
    }

    /// May the row's driver move at all (its row says `stateless`)?
    pub const fn is_elastic(&self) -> bool {
        self.spec.elastic()
    }

    /// The row's call budget in nanoseconds (0: none).
    pub const fn budget_ns(&self) -> u64 {
        self.spec.call_budget_us as u64 * 1000
    }

    /// The kernel host's measured worst call (0: not measured).
    pub const fn kernel_ns(&self) -> u64 {
        self.kernel_ns
    }

    /// Record the kernel host's measured worst call: the boot's calibration of
    /// the host it holds in reserve, and what a promotion is admitted against.
    pub fn set_kernel_cost(&mut self, ns: u64) {
        self.kernel_ns = ns;
    }

    fn worst(&self) -> u64 {
        self.costs[..self.n].iter().copied().max().unwrap_or(0)
    }

    fn misses(&self, budget: u64) -> usize {
        self.costs[..self.n].iter().filter(|&&c| c > budget).count()
    }

    fn faulted_recently(&self, now_ns: u64) -> bool {
        matches!(self.fault_at, Some(t) if now_ns.saturating_sub(t) < self.policy.holdoff_ns)
    }

    /// One call to the driver took `cost_ns`, from the caller's side. In
    /// ring 3, `misses` of the last [`WINDOW`] over the row's budget ask for a
    /// promotion, which is admitted when the kernel host's measured cost fits
    /// the budget and the host has not faulted within the hold-off. A refusal
    /// is recorded once per spell over the threshold, not once per call.
    pub fn observe(&mut self, cost_ns: u64, now_ns: u64) -> Decision {
        self.costs[self.next] = cost_ns;
        self.next = (self.next + 1) % WINDOW;
        self.n = (self.n + 1).min(WINDOW);
        let budget = self.budget_ns();
        match self.host {
            Host::Kernel => {
                // The kernel host's own cost, remeasured by its live calls.
                self.kernel_ns = self.worst();
                Decision::Stay
            }
            Host::Ring3 => {
                self.ring3_ns = self.worst();
                if !self.spec.elastic() || budget == 0 {
                    return Decision::Stay;
                }
                if self.misses(budget) < self.policy.misses as usize {
                    self.latched = false;
                    return Decision::Stay;
                }
                let mv = Move { from: Host::Ring3, to: Host::Kernel, reason: Reason::Deadline };
                let measured = self.ring3_ns;
                let why = if self.faulted_recently(now_ns) {
                    Some((Cause::RecentFault, budget))
                } else if self.kernel_ns == 0 {
                    Some((Cause::Unmeasured, budget))
                } else if self.kernel_ns > budget {
                    Some((Cause::HostCost, self.kernel_ns))
                } else {
                    None
                };
                match why {
                    None => Decision::Move(Receipt { mv, measured_ns: measured, limit_ns: budget }),
                    Some((cause, limit)) => self.refuse(Receipt { mv, measured_ns: measured, limit_ns: limit }, cause),
                }
            }
        }
    }

    /// The kernel host of the driver faulted at `now_ns` (a contained panic,
    /// seen by the supervisor). A `stateless` row restarts in ring 3 behind
    /// the same endpoint; any other row is the supervisor's to restart where
    /// it is ([`Decision::Stay`]). Always admitted: a fault is not a move the
    /// driver's cost can veto.
    pub fn fault(&mut self, now_ns: u64) -> Decision {
        if !self.spec.elastic() || self.host != Host::Kernel {
            return Decision::Stay;
        }
        self.fault_at = Some(now_ns);
        let mv = Move { from: Host::Kernel, to: Host::Ring3, reason: Reason::Fault };
        Decision::Move(Receipt { mv, measured_ns: self.ring3_ns, limit_ns: self.budget_ns() })
    }

    fn refuse(&mut self, r: Receipt, cause: Cause) -> Decision {
        if self.latched && r.mv.reason == Reason::Deadline {
            return Decision::Refused(cause);
        }
        self.latched = true;
        record_move(self.row, azos_decision::Verdict::Refuse, r.mv.pack(Some(cause)), r.measured_ns, r.limit_ns);
        Decision::Refused(cause)
    }

    /// The move `r` was made: the driver is on the other host now. **The one
    /// place the host changes, and it writes the record**: a move cannot be
    /// committed without its receipt.
    pub fn commit(&mut self, r: Receipt) {
        debug_assert!(r.mv.from == self.host);
        self.host = r.mv.to;
        self.n = 0;
        self.next = 0;
        self.latched = false;
        if !cfg!(feature = "placement-norecord-canary") {
            record_move(self.row, azos_decision::Verdict::Place, r.mv.pack(None), r.measured_ns, r.limit_ns);
        }
    }

    /// The move `r` was admitted and could not be done at `now_ns`: it is
    /// recorded as a refusal ([`Cause::Failed`]) and the driver stays. A host
    /// that could not be started counts as one that faulted: it is not tried
    /// again within the hold-off, or every slow call would ask for it again.
    pub fn failed(&mut self, r: Receipt, now_ns: u64) {
        if r.mv.reason == Reason::Deadline {
            self.fault_at = Some(now_ns);
        }
        record_move(self.row, azos_decision::Verdict::Refuse, r.mv.pack(Some(Cause::Failed)), r.measured_ns, r.limit_ns);
    }
}

fn record_move(row: u32, v: azos_decision::Verdict, word: u64, measured_ns: u64, limit_ns: u64) {
    azos_decision::record(azos_decision::Rule::Placement, v, row, [word, measured_ns, limit_ns]);
}
