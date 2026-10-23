// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Power` interface: the power family and the energy policy, for the
//! `POWER.ELF` tool and anything that holds the endpoint.
//!
//! Policy lives in user space (`userspace/services/power`); the kernel only
//! enforces limits (`azos_energy::policy`: the real-time deadline floor, the
//! safety path's WCET floor, the idle slack). So the setters answer with the
//! outcome and, when a kernel limit refused the value, the reason:
//!
//! * `OK` with value 0: applied;
//! * `REFUSED` with a `POLICY_REFUSED_*` value (`azos_abi::power`): refused
//!   by a kernel limit and recorded;
//! * any other outcome: the call itself failed (`DENIED`: the right is
//!   missing or the system is contained; `UNSUPPORTED`: no `energy` in the
//!   kernel; `BAD_ARGUMENT`).
//!
//! Observing ops need `READ`; every op that changes something needs `WRITE`.

//!
//! # Failure contract
//!
//! Every op declares what happens when the power service fails
//! (`#[on_failure]`) and how long it may take (`#[deadline_ns]`,
//! `#[budget_us]`). A failed power-off or reboot escalates to the safety path;
//! policy changes and reads degrade (the previous policy stays in force).
//! `shutdown`, `reboot`, `suspend`, `cpu_online` and `sync` declare no deadline: the call does
//! not return, or returns after the resume or the disks, so only the CPU budget of the request
//! is bounded.
//!
//! `shutdown` and `reboot` are `#[once_only]`: irreversible, sent once and
//! never retried by any transport (`userspace/lib/rpc` sends such an op once
//! and reports a lost answer as `NoConnection`).
//!
//! [`DevicePower`] and [`runtime`] below are the other half of this family:
//! the power state of one device, not of the machine.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "POWR").
pub const POWER_ID: u32 = 0x504F_5752;

#[azos_interface(id = 0x504F_5752, level = 1)]
pub trait Power {
    /// Orderly power-off. Does not return when served. Needs `WRITE`.
    ///
    /// `#[once_only]`: a power-off cannot be undone and a lost answer is the
    /// normal case (the machine is gone), so no layer ever sends it twice; the
    /// caller learns the outcome is unknown, not a second try.
    #[once_only]
    #[on_failure(escalate)]
    #[budget_us = 1_000]
    fn shutdown(&mut self) -> Out<()>;
    /// Orderly reboot. Does not return when served. Needs `WRITE`. `#[once_only]`
    /// for the reason of `shutdown`.
    #[once_only]
    #[on_failure(escalate)]
    #[budget_us = 1_000]
    fn reboot(&mut self) -> Out<()>;
    /// Suspend until the next interrupt; answers after the resume with `OK` and
    /// value 0. `REFUSED` with the `azos_drv_power::pm::suspend::Reason` code
    /// when the suspend did not happen (recorded). Needs `WRITE`.
    #[on_failure(degrade)]
    #[budget_us = 1_000]
    fn suspend(&mut self) -> Out<u32>;
    /// The scheduler tick rate, Hz. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn sched_hz(&self) -> Out<u64>;
    /// Set the scheduler tick rate (`POWER_SCHED_HZ_MIN..=POWER_SCHED_HZ_MAX`,
    /// else `BAD_ARGUMENT`). Needs `WRITE`.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_sched_hz(&mut self, hz: u64) -> Out<()>;
    /// Choose the governor: `POLICY_GOV_FIXED` or `POLICY_GOV_DEADLINE_FLOOR`.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_governor(&mut self, gov: u32) -> Out<u32>;
    /// Restrict domain `domain` to OPP indices `min..=max` (slowest first).
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> Out<u32>;
    /// Schedutil headroom, percent.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_headroom(&mut self, pct: u32) -> Out<u32>;
    /// Shortest interval between two governor evaluations, microseconds.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_rate_limit(&mut self, us: u32) -> Out<u32>;
    /// Deepest idle state the idle governor may pick; `POLICY_IDLE_UNLIMITED`
    /// lifts the limit.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_idle_depth(&mut self, depth: u32) -> Out<u32>;
    /// Cap domain `domain` at `mw` milliwatts; 0 lifts the cap. The kernel
    /// turns it into an OPP ceiling through the energy model.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_power_cap(&mut self, domain: u32, mw: u32) -> Out<u32>;
    /// Park the CPUs of `mask` (bit n = CPU n) and unpark the others.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_parked(&mut self, mask: u32) -> Out<u32>;
    /// Place tasks of QoS class `class` on the domains of `domains` only
    /// (bit d = domain d).
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn set_qos_domains(&mut self, class: u32, domains: u32) -> Out<u32>;
    /// Report the battery: the charge the power service estimated (percent)
    /// and the degrade level it runs at. The kernel holds its reserve from
    /// this charge and records every change of level.
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn report_battery(&mut self, soc_pct: u32, level: u32) -> Out<u32>;
    /// A policy state word (`POLICY_STATE_*`). Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn state(&self, sel: u32) -> Out<u64>;
    /// A policy statistics word (`POLICY_STATS_*`). Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn stats(&self, sel: u32) -> Out<u64>;
    /// Take CPU `cpu` offline (`on == 0`) or bring it back (`on == 1`). `OK`
    /// with the number of tasks moved off the CPU (offline) or of CPUs online
    /// (online); `REFUSED` with the `azos_sched::smp::hart_set::HotplugReason`
    /// code when the change did not happen (recorded as rule `cpu-hotplug`);
    /// `BAD_ARGUMENT` for `on > 1`; `UNSUPPORTED` without Kconfig `CPU_HOTPLUG`.
    /// Needs `WRITE`. Takes as long as the CPU needs to drain (milliseconds):
    /// no deadline, only the request's CPU budget is bounded, as `suspend`.
    #[on_failure(degrade)]
    #[budget_us = 1_000]
    fn cpu_online(&mut self, cpu: u32, on: u32) -> Out<u32>;
    /// Make every mounted filesystem durable: the page cache, the block cache
    /// and the journal written back, then each volume's disk flushed. What the
    /// power service asks before `shutdown` and `reboot` (owner decision
    /// 2026-10-23); the kernel's orderly path syncs again after it, for the
    /// callers that have no service. `OK` with the number of volumes synced;
    /// `FAULT` with the number that failed, or whose flush had not finished
    /// in Kconfig `POWER_OFF_STEP_TIMEOUT_MS`. Needs `WRITE`. Waits for the
    /// disks: no deadline, only the request's CPU budget is bounded, as
    /// `suspend`.
    #[idempotent]
    #[on_failure(degrade)]
    #[budget_us = 1_000]
    fn sync(&mut self) -> Out<u32>;
}

// ---------------------------------------------------------------------------
// Device runtime power management
// ---------------------------------------------------------------------------

/// The interface id of [`DevicePower`] (ASCII "DPWR").
pub const DEVICE_POWER_ID: u32 = 0x4450_5752;

/// [`DevicePower::state`]: the device is powered and serving.
pub const PM_ACTIVE: u32 = 0;
/// [`DevicePower::state`]: the device is suspended; the next use resumes it.
pub const PM_SUSPENDED: u32 = 1;

/// Longest idle timeout the interface takes (milliseconds): one hour.
pub const IDLE_TIMEOUT_MAX_MS: u32 = 3_600_000;

/// [`DevicePower::stats`] selectors: the idle timeout in force (ms, 0: never
/// autosuspends).
pub const PM_STAT_IDLE_TIMEOUT_MS: u32 = 0;
/// Wakelocks held now.
pub const PM_STAT_HELD: u32 = 1;
/// Suspends, explicit and automatic.
pub const PM_STAT_SUSPENDS: u32 = 2;
/// Of those, the ones the idle timeout caused.
pub const PM_STAT_AUTO_SUSPENDS: u32 = 3;
/// Resumes, explicit and on use.
pub const PM_STAT_RESUMES: u32 = 4;
/// Wakelocks granted.
pub const PM_STAT_GRANTED: u32 = 5;
/// Wakelocks released by their holder.
pub const PM_STAT_RELEASED: u32 = 6;
/// Wakelocks that lapsed (their deadline passed with the holder silent).
pub const PM_STAT_EXPIRED: u32 = 7;
/// Wakelocks refused (quota, ttl).
pub const PM_STAT_REFUSED: u32 = 8;
/// Suspends or resumes the device's callback failed.
pub const PM_STAT_CALLBACK_FAILS: u32 = 9;
/// Records written since the device started (the record ring keeps the last
/// [`runtime::RECORDS`]).
pub const PM_STAT_RECORDED: u32 = 10;
/// `PM_STAT_RECORD_BASE + k` is the `k`-th newest record, packed by
/// [`runtime::Record::pack`]: `0` when there is none yet.
pub const PM_STAT_RECORD_BASE: u32 = 16;

/// The power state of one device (runtime PM, owner decision 16-10).
///
/// Served by the driver of the device from its own endpoint, next to the
/// device's own interface; the power service holds the client. Policy
/// (which device suspends after how long) is the power service's; the
/// mechanism (the idle clock, the wakelock ledger, the records) is
/// [`runtime::RuntimePm`], one per device.
///
/// * A device is **active** or **suspended**. A suspended device resumes on
///   its next use (the driver does it, the client does not ask) or when
///   [`resume`](DevicePower::resume) is called.
/// * With an idle timeout set, a device nobody used for that long suspends
///   itself, unless a wakelock is live.
/// * A **wakelock** ([`hold`](DevicePower::hold)) keeps the device from
///   suspending until it is released or its deadline passes. It is a warrant
///   in the kernel's sense (`azos_ipc::cap::Warrant`): it names one holder's
///   claim (a lease id), it carries a deadline, and the ledger is bounded by a
///   quota, a count of live leases and the longest deadline it will grant, so
///   one client cannot pin a device awake for ever. A lease whose holder died
///   or forgot lapses at its deadline; every grant, release, lapse and
///   refusal is recorded.
///
/// Op classes: `state` and `stats` observe (`READ`); `idle`, `hold` and
/// `release` act (`WRITE`); `suspend`, `resume` and `set_idle_timeout`
/// control (`EXEC`). A ring-3 host is not shown the rights of the capability
/// the call came through, only its badge, so the classes travel in the badge:
/// the bits of [`runtime::CLASS_READ`], [`runtime::CLASS_WRITE`] and
/// [`runtime::CLASS_EXEC`], stamped by the signed topology on the grant
/// (the holder cannot choose it). The server ([`runtime::PmServer`]) answers
/// `DENIED` to an op whose class the badge does not carry, so a call with no
/// badge, or none of the classes, is refused entirely: the check fails closed.
#[azos_interface(id = 0x4450_5752, level = 1)]
pub trait DevicePower {
    /// [`PM_ACTIVE`] or [`PM_SUSPENDED`]. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn state(&self) -> Out<u32>;
    /// A counter or a record (`PM_STAT_*`); `BAD_ARGUMENT` for another
    /// selector. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn stats(&self, sel: u32) -> Out<u64>;
    /// Suspend now. `BUSY` while a wakelock is live, `FAULT` when the
    /// device's suspend callback failed (it stays active); served when it is
    /// already suspended. Needs `EXEC`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 20_000_000]
    #[budget_us = 5_000]
    fn suspend(&mut self) -> Out<()>;
    /// Resume now (also restarts the idle clock). `FAULT` when the device's
    /// resume callback failed (it stays suspended); served when it is already
    /// active. Needs `EXEC`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 20_000_000]
    #[budget_us = 5_000]
    fn resume(&mut self) -> Out<()>;
    /// The caller is done with the device: the idle clock starts now (it does
    /// not suspend by itself; the timeout does). Needs `WRITE`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn idle(&mut self) -> Out<()>;
    /// Autosuspend after `ms` without use; 0 never (the default of a device).
    /// `BAD_ARGUMENT` above [`IDLE_TIMEOUT_MAX_MS`]. Needs `EXEC`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn set_idle_timeout(&mut self, ms: u32) -> Out<()>;
    /// Take a wakelock for `ttl_ms` milliseconds: the lease id (non-zero).
    /// `BAD_ARGUMENT` for a ttl of 0 or one past the ledger's longest,
    /// `BUSY` when the quota of live leases is used. Needs `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn hold(&mut self, ttl_ms: u32) -> Out<u32>;
    /// Give a wakelock back. `NO_RESOURCE` for a lease that is not live (never
    /// granted, already released or lapsed). Needs `WRITE`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn release(&mut self, lease: u32) -> Out<()>;
}

/// The mechanism behind [`DevicePower`]: no clock, no device, no allocation.
/// The driver passes the time (`now_ns`, any monotonic clock) and the device's
/// callbacks, so the same state machine runs in a ring-3 driver and under the
/// host tests.
pub mod runtime {
    use super::*;
    use crate::outcome;

    /// Wakelocks one device can have live at once (the ledger's capacity; the
    /// quota may be lower).
    pub const LEASES: usize = 8;
    /// Records the ring keeps.
    pub const RECORDS: usize = 16;
    /// Lease ids are 24 bits (they travel inside a packed record).
    const ID_MASK: u32 = 0x00FF_FFFF;

    const NS_PER_MS: u64 = 1_000_000;

    /// Op class: observe (`state`, `stats`).
    pub const CLASS_READ: u8 = 1 << 0;
    /// Op class: act on behalf of the caller (`idle`, `hold`, `release`).
    pub const CLASS_WRITE: u8 = 1 << 1;
    /// Op class: control the device (`suspend`, `resume`, `set_idle_timeout`).
    pub const CLASS_EXEC: u8 = 1 << 2;
    /// Every class.
    pub const CLASS_ALL: u8 = CLASS_READ | CLASS_WRITE | CLASS_EXEC;

    /// The op classes a request may use: the low bits of the badge the kernel
    /// stamped in it ([`MSG_BADGED`](azos_abi::ipc_msg::MSG_BADGED) says the
    /// badge is meaningful), `0` for a request that carries none.
    pub fn classes_of(req: &azos_idl::MsgDesc) -> u8 {
        if req.flags & azos_abi::ipc_msg::MSG_BADGED == 0 {
            return 0;
        }
        (req.badge & CLASS_ALL as u64) as u8
    }

    /// Prefix of the task-hosted endpoints the drivers serve [`DevicePower`]
    /// on (`endpoint.pm-gpio`, `endpoint.pm-ina`): the driver's row holds
    /// `READ` on its endpoint (it serves), the power service's row holds the
    /// call right.
    pub const ENDPOINT_PREFIX: &str = "endpoint.pm-";
    /// The devices that serve it, by the name after [`ENDPOINT_PREFIX`]. A
    /// device's key is its index plus one (0 is no device).
    pub const DEVICES: [&str; 2] = ["gpio", "ina"];
    /// The device key sits above the op classes in the badge.
    pub const KEY_SHIFT: u32 = 8;

    /// The key of the device whose endpoint `target` names, `None` for any
    /// other target.
    pub fn endpoint_key(target: &str) -> Option<u32> {
        let name = target.strip_prefix(ENDPOINT_PREFIX)?;
        DEVICES.iter().position(|d| *d == name).map(|i| i as u32 + 1)
    }

    /// The key of the device called `name`.
    pub fn device_key(name: &str) -> Option<u32> {
        DEVICES.iter().position(|d| *d == name).map(|i| i as u32 + 1)
    }

    /// The badge the kernel stamps on a calling grant of the endpoint `target`
    /// with rights `perms` (`CapPerms` bits): the device's key, and the op
    /// classes the grant carries. Holding the grant at all is the right to
    /// observe ([`CLASS_READ`]: `READ` itself means *serve* on an endpoint, so
    /// it cannot spell the class); `WRITE` and `EXEC` map to their classes.
    /// `None` for a target that is no device's.
    pub fn grant_badge(target: &str, perms: u8) -> Option<u32> {
        let key = endpoint_key(target)?;
        Some(key << KEY_SHIFT | (CLASS_READ | perms & (CLASS_WRITE | CLASS_EXEC)) as u32)
    }

    /// The device key a badge stamped by [`grant_badge`] carries (0: none).
    pub const fn badge_key(badge: u32) -> u32 {
        badge >> KEY_SHIFT
    }

    /// What the ledger lets a device's wakelocks do: the quota of the
    /// warrants it grants.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Quota {
        /// Live leases at once (1..=[`LEASES`]).
        pub max_held: u8,
        /// Longest deadline a lease is granted for, milliseconds.
        pub max_ttl_ms: u32,
    }

    impl Quota {
        /// `max_held` is clamped to `1..=LEASES`, `max_ttl_ms` to at least 1.
        pub const fn new(max_held: u32, max_ttl_ms: u32) -> Quota {
            let held = if max_held == 0 {
                1
            } else if max_held > LEASES as u32 {
                LEASES as u32
            } else {
                max_held
            };
            Quota { max_held: held as u8, max_ttl_ms: if max_ttl_ms == 0 { 1 } else { max_ttl_ms } }
        }
    }

    /// What the device does on a transition. `false`: it could not.
    pub trait PmDevice {
        /// Power the device down (gate its clock, put the chip in its low
        /// state). The device is not used again until `resume`.
        fn suspend(&mut self) -> bool;
        /// Power the device up and bring it back to its working state.
        fn resume(&mut self) -> bool;
    }

    /// Why an op was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PmError {
        /// A wakelock is live.
        Held,
        /// The quota of live leases is used.
        Quota,
        /// A ttl of 0, or past the ledger's longest.
        Ttl,
        /// The lease is not live.
        NoLease,
        /// The device's callback failed.
        Callback,
    }

    impl PmError {
        /// The interface's outcome for it.
        pub const fn outcome(self) -> u32 {
            match self {
                PmError::Held | PmError::Quota => outcome::BUSY,
                PmError::Ttl => outcome::BAD_ARGUMENT,
                PmError::NoLease => outcome::NO_RESOURCE,
                PmError::Callback => outcome::FAULT,
            }
        }
    }

    /// What a record says happened.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Event {
        /// Suspended on request (`arg` 0).
        Suspend = 1,
        /// Suspended by the idle timeout (`arg` 0).
        AutoSuspend = 2,
        /// Resumed on request (`arg` 0).
        Resume = 3,
        /// Resumed because the device was used (`arg` 0).
        ResumeOnUse = 4,
        /// A wakelock was granted (`arg`: the lease).
        Grant = 5,
        /// A wakelock was released (`arg`: the lease).
        Release = 6,
        /// A wakelock lapsed (`arg`: the lease).
        Lapse = 7,
        /// A wakelock was refused (`arg`: the ttl asked, ms).
        Refuse = 8,
        /// A suspend or resume callback failed (`arg`: 1 for a resume).
        CallbackFailed = 9,
        /// A suspend was refused because a wakelock is live (`arg`: leases).
        SuspendHeld = 10,
    }

    impl Event {
        fn of(b: u8) -> Option<Event> {
            Some(match b {
                1 => Event::Suspend,
                2 => Event::AutoSuspend,
                3 => Event::Resume,
                4 => Event::ResumeOnUse,
                5 => Event::Grant,
                6 => Event::Release,
                7 => Event::Lapse,
                8 => Event::Refuse,
                9 => Event::CallbackFailed,
                10 => Event::SuspendHeld,
                _ => return None,
            })
        }
    }

    /// One entry of the record ring.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Record {
        pub t_ns: u64,
        pub event: Event,
        pub arg: u32,
    }

    impl Record {
        /// The record as one word: bits 63..32 the time in milliseconds
        /// (wrapping, 49 days), 31..24 the event, 23..0 the argument.
        pub fn pack(&self) -> u64 {
            ((self.t_ns / NS_PER_MS) as u32 as u64) << 32 | (self.event as u64) << 24 | (self.arg & ID_MASK) as u64
        }
        /// [`Record::pack`]'s inverse (the time to the millisecond, mod 2^32 ms).
        pub fn unpack(w: u64) -> Option<(u32, Event, u32)> {
            Some(((w >> 32) as u32, Event::of((w >> 24) as u8)?, (w & ID_MASK as u64) as u32))
        }
    }

    /// One wakelock: a warrant (an id naming it, a deadline bounding it).
    #[derive(Clone, Copy)]
    struct Lease {
        id: u32,
        expiry_ns: u64,
    }

    const NO_LEASE: Lease = Lease { id: 0, expiry_ns: 0 };

    /// Counters, never reset.
    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    pub struct Counters {
        pub suspends: u32,
        pub auto_suspends: u32,
        pub resumes: u32,
        pub granted: u32,
        pub released: u32,
        pub expired: u32,
        pub refused: u32,
        pub callback_fails: u32,
        pub recorded: u32,
    }

    /// The runtime power state of one device.
    pub struct RuntimePm {
        suspended: bool,
        idle_ns: u64,
        last_busy_ns: u64,
        quota: Quota,
        leases: [Lease; LEASES],
        next_id: u32,
        pub counters: Counters,
        ring: [Record; RECORDS],
    }

    const NO_RECORD: Record = Record { t_ns: 0, event: Event::Suspend, arg: 0 };

    impl RuntimePm {
        /// An active device that never autosuspends, last used at `now_ns`.
        pub const fn new(quota: Quota, now_ns: u64) -> RuntimePm {
            RuntimePm {
                suspended: false,
                idle_ns: 0,
                last_busy_ns: now_ns,
                quota,
                leases: [NO_LEASE; LEASES],
                next_id: 1,
                counters: Counters {
                    suspends: 0,
                    auto_suspends: 0,
                    resumes: 0,
                    granted: 0,
                    released: 0,
                    expired: 0,
                    refused: 0,
                    callback_fails: 0,
                    recorded: 0,
                },
                ring: [NO_RECORD; RECORDS],
            }
        }

        fn record(&mut self, t_ns: u64, event: Event, arg: u32) {
            let slot = self.counters.recorded as usize % RECORDS;
            self.ring[slot] = Record { t_ns, event, arg };
            self.counters.recorded = self.counters.recorded.wrapping_add(1);
        }

        /// The `k`-th newest record (0 the newest), if the ring has it.
        pub fn record_at(&self, k: usize) -> Option<Record> {
            let n = self.counters.recorded as usize;
            if k >= RECORDS.min(n) {
                return None;
            }
            Some(self.ring[(n - 1 - k) % RECORDS])
        }

        /// Is the device suspended?
        pub fn is_suspended(&self) -> bool {
            self.suspended
        }

        /// The idle timeout, milliseconds (0: never).
        pub fn idle_timeout_ms(&self) -> u32 {
            (self.idle_ns / NS_PER_MS) as u32
        }

        /// Set the idle timeout; 0 never. `Err(Ttl)` above
        /// [`IDLE_TIMEOUT_MAX_MS`].
        pub fn set_idle_timeout_ms(&mut self, ms: u32) -> Result<(), PmError> {
            if ms > IDLE_TIMEOUT_MAX_MS {
                return Err(PmError::Ttl);
            }
            self.idle_ns = ms as u64 * NS_PER_MS;
            Ok(())
        }

        /// Wakelocks live at `now_ns` (lapsed ones are not counted, and are
        /// dropped by the next op or `tick`).
        pub fn held(&self, now_ns: u64) -> u32 {
            self.leases.iter().filter(|l| l.id != 0 && l.expiry_ns > now_ns).count() as u32
        }

        /// Drop the leases whose deadline has passed, recording each.
        fn reap(&mut self, now_ns: u64) {
            for i in 0..LEASES {
                let l = self.leases[i];
                if l.id != 0 && l.expiry_ns <= now_ns {
                    self.leases[i] = NO_LEASE;
                    self.counters.expired += 1;
                    self.record(l.expiry_ns, Event::Lapse, l.id);
                }
            }
        }

        fn do_suspend<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64, auto: bool) -> Result<(), PmError> {
            if !dev.suspend() {
                self.counters.callback_fails += 1;
                self.record(now_ns, Event::CallbackFailed, 0);
                // The clock restarts, so a device whose callback keeps failing is
                // tried once per timeout, not once per tick.
                self.last_busy_ns = now_ns;
                return Err(PmError::Callback);
            }
            self.suspended = true;
            self.counters.suspends += 1;
            if auto {
                self.counters.auto_suspends += 1;
            }
            self.record(now_ns, if auto { Event::AutoSuspend } else { Event::Suspend }, 0);
            Ok(())
        }

        fn do_resume<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64, by_use: bool) -> Result<(), PmError> {
            if !dev.resume() {
                self.counters.callback_fails += 1;
                self.record(now_ns, Event::CallbackFailed, 1);
                return Err(PmError::Callback);
            }
            self.suspended = false;
            self.last_busy_ns = now_ns;
            self.counters.resumes += 1;
            self.record(now_ns, if by_use { Event::ResumeOnUse } else { Event::Resume }, 0);
            Ok(())
        }

        /// The device is about to be used: resume it if it is suspended, and
        /// start its idle clock. `Err(Callback)` when it could not be resumed
        /// (the use must fail).
        pub fn on_use<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64) -> Result<(), PmError> {
            self.reap(now_ns);
            if self.suspended {
                self.do_resume(dev, now_ns, true)?;
            }
            self.last_busy_ns = now_ns;
            Ok(())
        }

        /// The device has nothing more to do now: the idle clock starts at
        /// `now_ns`. It suspends nothing by itself.
        pub fn idle(&mut self, now_ns: u64) {
            self.reap(now_ns);
            self.last_busy_ns = self.last_busy_ns.max(now_ns);
        }

        /// Advance to `now_ns`: lapse the leases that are due and suspend the
        /// device when its idle timeout has run out with none live. The driver
        /// calls it whenever its wait ends.
        pub fn tick<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64) {
            self.reap(now_ns);
            if self.due(now_ns) {
                let _ = self.do_suspend(dev, now_ns, true);
            }
        }

        fn due(&self, now_ns: u64) -> bool {
            !self.suspended
                && self.idle_ns != 0
                && self.held(now_ns) == 0
                && now_ns.saturating_sub(self.last_busy_ns) >= self.idle_ns
        }

        /// Suspend on request. Served when already suspended.
        pub fn suspend<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64) -> Result<(), PmError> {
            self.reap(now_ns);
            if self.suspended {
                return Ok(());
            }
            let held = self.held(now_ns);
            if held != 0 {
                self.record(now_ns, Event::SuspendHeld, held);
                return Err(PmError::Held);
            }
            self.do_suspend(dev, now_ns, false)
        }

        /// Resume on request. Served when already active; either way the idle
        /// clock restarts.
        pub fn resume<D: PmDevice>(&mut self, dev: &mut D, now_ns: u64) -> Result<(), PmError> {
            self.reap(now_ns);
            if self.suspended {
                self.do_resume(dev, now_ns, false)?;
            }
            self.last_busy_ns = now_ns;
            Ok(())
        }

        /// Grant a wakelock for `ttl_ms`: its lease id.
        pub fn hold(&mut self, now_ns: u64, ttl_ms: u32) -> Result<u32, PmError> {
            self.reap(now_ns);
            if ttl_ms == 0 || ttl_ms > self.quota.max_ttl_ms {
                self.counters.refused += 1;
                self.record(now_ns, Event::Refuse, ttl_ms);
                return Err(PmError::Ttl);
            }
            if self.held(now_ns) >= self.quota.max_held as u32 {
                self.counters.refused += 1;
                self.record(now_ns, Event::Refuse, ttl_ms);
                return Err(PmError::Quota);
            }
            let Some(slot) = self.leases.iter().position(|l| l.id == 0) else {
                // The quota is at most the capacity, so this cannot happen.
                return Err(PmError::Quota);
            };
            let id = loop {
                let id = self.next_id;
                self.next_id = if id >= ID_MASK { 1 } else { id + 1 };
                if !self.leases.iter().any(|l| l.id == id) {
                    break id;
                }
            };
            self.leases[slot] = Lease { id, expiry_ns: now_ns.saturating_add(ttl_ms as u64 * NS_PER_MS) };
            self.counters.granted += 1;
            self.record(now_ns, Event::Grant, id);
            Ok(id)
        }

        /// Give a wakelock back. The idle clock restarts: a device that was
        /// held was in use.
        pub fn release(&mut self, now_ns: u64, id: u32) -> Result<(), PmError> {
            self.reap(now_ns);
            let Some(slot) = self.leases.iter().position(|l| l.id == id && id != 0) else {
                return Err(PmError::NoLease);
            };
            self.leases[slot] = NO_LEASE;
            self.counters.released += 1;
            self.last_busy_ns = self.last_busy_ns.max(now_ns);
            self.record(now_ns, Event::Release, id);
            Ok(())
        }

        /// The next instant [`RuntimePm::tick`] has something to do, or `None`
        /// (nothing is timed: a device suspended or with no timeout and no
        /// lease). The driver sleeps until then at most.
        pub fn next_deadline_ns(&self) -> Option<u64> {
            let lease = self.leases.iter().filter(|l| l.id != 0).map(|l| l.expiry_ns).min();
            let auto = if self.suspended || self.idle_ns == 0 {
                None
            } else {
                let latest = self.leases.iter().filter(|l| l.id != 0).map(|l| l.expiry_ns).max().unwrap_or(0);
                Some(self.last_busy_ns.saturating_add(self.idle_ns).max(latest))
            };
            match (lease, auto) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }

        /// A counter or record by [`DevicePower::stats`] selector.
        pub fn stat(&self, sel: u32, now_ns: u64) -> Option<u64> {
            let c = &self.counters;
            Some(match sel {
                PM_STAT_IDLE_TIMEOUT_MS => self.idle_timeout_ms() as u64,
                PM_STAT_HELD => self.held(now_ns) as u64,
                PM_STAT_SUSPENDS => c.suspends as u64,
                PM_STAT_AUTO_SUSPENDS => c.auto_suspends as u64,
                PM_STAT_RESUMES => c.resumes as u64,
                PM_STAT_GRANTED => c.granted as u64,
                PM_STAT_RELEASED => c.released as u64,
                PM_STAT_EXPIRED => c.expired as u64,
                PM_STAT_REFUSED => c.refused as u64,
                PM_STAT_CALLBACK_FAILS => c.callback_fails as u64,
                PM_STAT_RECORDED => c.recorded as u64,
                s if (PM_STAT_RECORD_BASE..PM_STAT_RECORD_BASE + RECORDS as u32).contains(&s) => {
                    self.record_at((s - PM_STAT_RECORD_BASE) as usize).map_or(0, |r| r.pack())
                }
                _ => return None,
            })
        }
    }

    /// [`DevicePower`] over a [`RuntimePm`], a device and the time of the
    /// request: what a driver's dispatcher serves.
    pub struct PmServer<'a, D: PmDevice> {
        pub pm: &'a mut RuntimePm,
        pub dev: &'a mut D,
        pub now_ns: u64,
        /// The op classes of this request ([`classes_of`]); an op outside
        /// them is answered `DENIED` and changes nothing.
        pub classes: u8,
    }

    impl<D: PmDevice> PmServer<'_, D> {
        /// Does this request carry the op class `class`?
        fn allows(&self, class: u8) -> bool {
            self.classes & class != 0
        }
    }

    fn done(r: Result<(), PmError>) -> Out<()> {
        match r {
            Ok(()) => Out::ok(()),
            Err(e) => Out::err(e.outcome()),
        }
    }

    impl<D: PmDevice> DevicePower for PmServer<'_, D> {
        fn state(&self) -> Out<u32> {
            if !self.allows(CLASS_READ) {
                return Out::err(outcome::DENIED);
            }
            Out::ok(if self.pm.is_suspended() { PM_SUSPENDED } else { PM_ACTIVE })
        }
        fn stats(&self, sel: u32) -> Out<u64> {
            if !self.allows(CLASS_READ) {
                return Out::err(outcome::DENIED);
            }
            match self.pm.stat(sel, self.now_ns) {
                Some(v) => Out::ok(v),
                None => Out::err(outcome::BAD_ARGUMENT),
            }
        }
        fn suspend(&mut self) -> Out<()> {
            if !self.allows(CLASS_EXEC) {
                return Out::err(outcome::DENIED);
            }
            done(self.pm.suspend(self.dev, self.now_ns))
        }
        fn resume(&mut self) -> Out<()> {
            if !self.allows(CLASS_EXEC) {
                return Out::err(outcome::DENIED);
            }
            done(self.pm.resume(self.dev, self.now_ns))
        }
        fn idle(&mut self) -> Out<()> {
            if !self.allows(CLASS_WRITE) {
                return Out::err(outcome::DENIED);
            }
            self.pm.idle(self.now_ns);
            Out::ok(())
        }
        fn set_idle_timeout(&mut self, ms: u32) -> Out<()> {
            if !self.allows(CLASS_EXEC) {
                return Out::err(outcome::DENIED);
            }
            done(self.pm.set_idle_timeout_ms(ms))
        }
        fn hold(&mut self, ttl_ms: u32) -> Out<u32> {
            if !self.allows(CLASS_WRITE) {
                return Out::err(outcome::DENIED);
            }
            match self.pm.hold(self.now_ns, ttl_ms) {
                Ok(id) => Out::ok(id),
                Err(e) => Out::err(e.outcome()),
            }
        }
        fn release(&mut self, lease: u32) -> Out<()> {
            if !self.allows(CLASS_WRITE) {
                return Out::err(outcome::DENIED);
            }
            done(self.pm.release(self.now_ns, lease))
        }
    }
}
