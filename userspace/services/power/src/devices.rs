// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power service's view of the devices' runtime power, pure: which devices
//! it tracks, what idle timeout each preset gives each class of device, and
//! what one look at a device reports. No syscall here (`main.rs` implements
//! [`DeviceLink`] over the `DevicePower` client of each device's endpoint),
//! so the host suite (`tests/host/power-tests`) drives the same code with a
//! scripted device.
//!
//! The mechanism is each driver's (`azos_devif::power::runtime::RuntimePm`:
//! the idle clock, the wakelock ledger, the record ring); the policy is here:
//! the idle timeout of a device follows the energy preset, and the service
//! keeps it applied, including after the driver restarted and forgot it. The
//! records a driver keeps are read from it and logged once each.

use azos_devif::power::runtime::{badge_key, device_key, Event, Record, CLASS_READ, RECORDS};
use azos_devif::power::{PM_STAT_RECORDED, PM_STAT_RECORD_BASE};

use crate::policy::Preset;

/// Devices the service tracks at most.
pub const MAX_DEVICES: usize = 4;

/// What a device is for, which decides how long it may sit idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Serves requests of a client and nothing else (a GPIO controller).
    Io,
    /// Feeds a safety decision (the battery monitor behind the failsafe
    /// levels): suspended only where the preset trades endurance for
    /// freshness, and the first read after the pause re-measures.
    Monitor,
}

/// One tracked device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The device's name in `azos_devif::power::runtime::DEVICES`: its
    /// `DevicePower` endpoint is `endpoint.pm-<name>` and the capability to it
    /// carries the device's key.
    pub name: &'static str,
    pub class: Class,
}

/// The devices of this build: the ring-3 drivers that serve `DevicePower`.
///
/// `DevicePower` is served by a task from a named endpoint, not hosted by the
/// kernel, so it has no host key in `azos_devif::IFACES` and `POWER.ELF`'s
/// profile needs no `ifaces` entry for it (that word gates the kernel-hosted
/// endpoints only, `SyscallFilter::iface_verdict`): what authorizes the calls
/// is the capability its row holds. The rows are the topology's
/// (`crates/core/topology/src/builder.rs`: each driver's row serves its
/// endpoint, `POWER.ELF`'s calls them with `EXEC`); the kernel stamps the
/// calling grant with the device's key and the op classes of its rights
/// (`azos_devif::power::runtime::grant_badge`), and [`resolve`] finds each
/// endpoint by that key, since ring 3 has no by-name lookup of a task-hosted
/// endpoint and its pool index is the topology's row order, not a contract.
pub const DEVICES: [Spec; 2] = [
    Spec { name: "gpio", class: Class::Io },
    Spec { name: "ina", class: Class::Monitor },
];

/// The handle of each tracked device's endpoint capability, by position in
/// [`DEVICES`]; `None` for a device the row does not grant.
///
/// `held(i)` answers for pool index `i` (`0..`[`azos_limits::IPC_ENDPOINTS`])
/// with the handle of the endpoint capability this task holds there and its
/// badge. A capability whose badge carries the device's key and the class
/// *observe* is that device's endpoint; the first one wins (a topology grants
/// each device once).
pub fn resolve<F: FnMut(u32) -> Option<(u32, u32)>>(mut held: F) -> [Option<u32>; MAX_DEVICES] {
    let mut out = [None; MAX_DEVICES];
    for i in 0..azos_limits::IPC_ENDPOINTS as u32 {
        let Some((handle, badge)) = held(i) else { continue };
        if badge as u8 & CLASS_READ == 0 || badge_key(badge) == 0 {
            continue;
        }
        for (slot, spec) in out.iter_mut().zip(DEVICES.iter()) {
            if slot.is_none() && device_key(spec.name) == Some(badge_key(badge)) {
                *slot = Some(handle);
            }
        }
    }
    out
}

/// The idle timeout a preset gives a class of device, milliseconds (0: never
/// autosuspends).
pub const fn idle_ms(p: Preset, c: Class) -> u32 {
    match (p, c) {
        (Preset::Performance, _) => 0,
        (Preset::Balanced, Class::Io) => 5_000,
        (Preset::Balanced, Class::Monitor) => 0,
        (Preset::Endurance, Class::Io) => 1_000,
        (Preset::Endurance, Class::Monitor) => 15_000,
    }
}

/// The idle timeout at degrade `level` (`DEGRADE_LEVEL_*`, 0 = none) under
/// `preset`, milliseconds: the preset's, shortened for a device that only
/// serves requests (the lower the charge, the sooner it sleeps), and none at
/// all for the monitor whose readings are what the level was chosen from: a
/// suspended battery monitor would hold a level on a stale charge.
pub const fn idle_ms_at(p: Preset, c: Class, level: u8) -> u32 {
    let base = idle_ms(p, c);
    match (c, level) {
        (_, 0) => base,
        (Class::Monitor, _) => if cfg!(feature = "pw-monitor-canary") { base } else { 0 },
        (Class::Io, 1) => cap_ms(base, 2_000),
        (Class::Io, 2) => cap_ms(base, 1_000),
        (Class::Io, _) => cap_ms(base, 250),
    }
}

/// `base` limited to `max`; a `base` of 0 (never) becomes `max`.
const fn cap_ms(base: u32, max: u32) -> u32 {
    if base == 0 || base > max { max } else { base }
}

/// The calls the service makes on a device.
pub trait DeviceLink {
    /// `DevicePower::stats(sel)`; `None` when the device did not answer.
    fn stats(&self, sel: u32) -> Option<u64>;
    /// `DevicePower::set_idle_timeout(ms)`; `true` when it was applied.
    fn set_idle_timeout(&mut self, ms: u32) -> bool;
}

/// What one look at a device found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The device did not answer (reported once, until it does).
    Unreachable,
    /// The device's counters went back: it restarted and lost its timeout.
    Restarted,
    /// The idle timeout now in force was applied.
    Applied(u32),
    /// A record the device wrote: its time (ms, wrapping), what, argument.
    Record { t_ms: u32, event: Event, arg: u32 },
    /// Records the ring overwrote before the service read them.
    Lost(u32),
}

/// What the service remembers of one device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tracked {
    /// Records read so far (the device's `PM_STAT_RECORDED` at the last look).
    seen: u32,
    /// The timeout applied, if one is.
    applied_ms: Option<u32>,
    /// Said so already.
    unreachable: bool,
}

impl Tracked {
    pub const fn new() -> Self {
        Tracked { seen: 0, applied_ms: None, unreachable: false }
    }

    /// One look at a device through `link`: report every change to `out`,
    /// oldest first, after seeing to it that the idle timeout in force is
    /// `want_ms` (the preset's, or the one of a degrade level: [`idle_ms_at`]).
    pub fn poll<L: DeviceLink>(&mut self, link: &mut L, want_ms: u32, out: &mut dyn FnMut(Change)) {
        let Some(recorded) = link.stats(PM_STAT_RECORDED).map(|w| w as u32) else {
            if !self.unreachable {
                self.unreachable = true;
                out(Change::Unreachable);
            }
            self.applied_ms = None;
            return;
        };
        self.unreachable = false;
        if recorded < self.seen {
            // Counters only grow: the driver restarted.
            self.seen = 0;
            self.applied_ms = None;
            out(Change::Restarted);
        }
        let want = want_ms;
        if self.applied_ms != Some(want) && link.set_idle_timeout(want) {
            self.applied_ms = Some(want);
            out(Change::Applied(want));
        }
        let fresh = recorded.wrapping_sub(self.seen);
        let read = fresh.min(RECORDS as u32);
        if fresh > read {
            out(Change::Lost(fresh - read));
        }
        for k in (0..read).rev() {
            let Some(w) = link.stats(PM_STAT_RECORD_BASE + k) else { break };
            if let Some((t_ms, event, arg)) = Record::unpack(w) {
                out(Change::Record { t_ms, event, arg });
            }
        }
        self.seen = recorded;
    }
}

/// The name of an event, for the log.
pub const fn event_name(e: Event) -> &'static str {
    match e {
        Event::Suspend => "suspend",
        Event::AutoSuspend => "autosuspend",
        Event::Resume => "resume",
        Event::ResumeOnUse => "resume-on-use",
        Event::Grant => "wakelock-granted",
        Event::Release => "wakelock-released",
        Event::Lapse => "wakelock-lapsed",
        Event::Refuse => "wakelock-refused",
        Event::CallbackFailed => "callback-failed",
        Event::SuspendHeld => "suspend-held",
    }
}
