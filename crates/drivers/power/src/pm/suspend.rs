// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System suspend: the order, and what undoes what.
//!
//! The machine goes to RAM in one sequence, and comes back by its reverse:
//!
//! ```text
//!   gates      the build allows it; the firmware has the call and the kernel a
//!              resume entry for it; no task holds a system power assertion;
//!              one CPU is online; the caller holds a wake source
//!   record     Rule::Suspend, Admit, state ENTER
//!   freeze     user tasks stop being picked (the stop class holds the CPU)
//!   quiesce    devices go down through runtime PM (DevicePower::suspend)
//!   save       the CPU and interrupt state the firmware will not keep
//!   enter      the firmware call; it returns here only on a refusal, or when
//!              the resume entry hands the CPU back
//!   restore    reverse of save
//!   unquiesce  reverse of quiesce
//!   thaw       reverse of freeze
//!   boot clock the suspended time is added to the boot offset (CLOCK_BOOTTIME)
//!   record     Rule::Suspend, Admit, state RESUME
//! ```
//!
//! A step that fails undoes the steps before it, newest first, and the suspend
//! is refused with a `Rule::Suspend` Refuse record: the machine is as it was.
//! A refusal at a gate does nothing at all.
//!
//! The sequence is this file's and nothing else's: the kernel (`kernel/src/boot/
//! energy.rs`) implements [`Platform`] with the real firmware, scheduler and
//! capability store; the host suite (`tests/host/power-tests/src/suspend.rs`)
//! implements it with a script and checks the order. No allocation, no clock
//! of its own, nothing that needs a target.

/// Why a suspend was refused. The numbers are the `reason` the `Power`
/// interface answers with (`Out::new(REFUSED, reason)`) and the low byte of the
/// record's third number; they are part of the record format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    /// Not built in (Kconfig `SYSTEM_SUSPEND`: never on a robot, industrial or
    /// automotive image, whose safety loop must keep running).
    Disabled = 1,
    /// The firmware does not implement the call (PSCI `SYSTEM_SUSPEND`, SBI
    /// `SUSP`), as its own probe answered.
    NoFirmware = 2,
    /// The kernel has no entry point for the firmware to resume at, and cannot
    /// come back from a suspend that loses the CPU's context.
    NoResumeEntry = 3,
    /// x86_64: S3 needs the `\_S3` object of the DSDT, which only an AML
    /// interpreter reads, and the kernel has none.
    NoAcpiS3 = 4,
    /// A CPU other than the caller's is online. Both firmware calls need every
    /// other CPU off. The sequence does not take them off itself: with
    /// `CPU_HOTPLUG` the caller does it first (`cpu_online` op, `Rule::CpuHotplug`),
    /// and this gate refuses while any is left.
    CpusOnline = 5,
    /// The caller holds no wake source: nothing it could be woken by.
    NoWakeSource = 6,
    /// The user tasks could not be frozen.
    FreezeFailed = 7,
    /// A device refused to go down (a wakelock is live, or its callback failed).
    DeviceBusy = 8,
    /// The CPU or interrupt state could not be saved.
    SaveFailed = 9,
    /// The firmware answered the call with an error instead of suspending.
    EnterFailed = 10,
    /// The scheduler cannot hold user tasks off the CPU yet: no dispatch path
    /// honours a freeze, and the stop class's per-CPU slot is not consulted
    /// by the dispatch the kernel runs.
    NoFreezer = 11,
    /// Another suspend is running.
    InProgress = 12,
    /// A task holds a system power assertion (the `powerassert` endpoint,
    /// `azos_energy::assertion`): it asked for the machine to stay awake while
    /// it works. The blockers are the live assertions.
    Asserted = 13,
}

impl Reason {
    /// The number the interface and the record carry.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The reason a code stands for (the low byte of a record's third number).
    pub const fn of(code: u8) -> Option<Reason> {
        Some(match code {
            1 => Reason::Disabled,
            2 => Reason::NoFirmware,
            3 => Reason::NoResumeEntry,
            4 => Reason::NoAcpiS3,
            5 => Reason::CpusOnline,
            6 => Reason::NoWakeSource,
            7 => Reason::FreezeFailed,
            8 => Reason::DeviceBusy,
            9 => Reason::SaveFailed,
            10 => Reason::EnterFailed,
            11 => Reason::NoFreezer,
            12 => Reason::InProgress,
            13 => Reason::Asserted,
            _ => return None,
        })
    }

    /// A name, for the console line.
    pub const fn name(self) -> &'static str {
        match self {
            Reason::Disabled => "not built in",
            Reason::NoFirmware => "firmware has no system suspend",
            Reason::NoResumeEntry => "no resume entry",
            Reason::NoAcpiS3 => "ACPI S3 needs AML",
            Reason::CpusOnline => "other CPUs online",
            Reason::NoWakeSource => "no wake source",
            Reason::FreezeFailed => "freeze failed",
            Reason::DeviceBusy => "device busy",
            Reason::SaveFailed => "save failed",
            Reason::EnterFailed => "firmware refused",
            Reason::NoFreezer => "no task freezer",
            Reason::InProgress => "another suspend is running",
            Reason::Asserted => "a task holds a power assertion",
        }
    }
}

/// A suspend that did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    /// How many things stood in the way: CPUs still online, devices that
    /// would not go down, 1 for a missing wake source or capability.
    pub blockers: u32,
    /// The firmware's own code, for [`Reason::EnterFailed`]; 0 otherwise.
    pub detail: i32,
}

impl Refusal {
    const fn of(reason: Reason) -> Refusal {
        Refusal { reason, blockers: 0, detail: 0 }
    }
}

/// The two clocks a suspend reads on either side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clocks {
    /// The monotonic clock, nanoseconds: the timer counter the kernel reads.
    pub mono_ns: u64,
    /// A clock that keeps running while the machine is suspended (an RTC, an
    /// always-on counter), nanoseconds on any origin; `None` when the platform
    /// has none.
    pub persistent_ns: Option<u64>,
}

/// How long the machine slept, from the clocks before and after: the time the
/// persistent clock advanced that the monotonic clock did not. The monotonic
/// clock counts the sleep when its counter kept running (then this is 0 and
/// `CLOCK_BOOTTIME` equals `CLOCK_MONOTONIC`, which is right), and misses it
/// when the counter stopped. 0 without a persistent clock on both sides: the
/// sleep is unknown, and an unknown sleep is not invented.
pub fn slept_ns(before: Clocks, after: Clocks) -> u64 {
    match (before.persistent_ns, after.persistent_ns) {
        (Some(b), Some(a)) => a.saturating_sub(b).saturating_sub(after.mono_ns.saturating_sub(before.mono_ns)),
        _ => 0,
    }
}

/// What a `Rule::Suspend` record says. The record's three numbers are
/// `state`, `blockers` and `reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Admit,
    Refuse,
}

/// `Record::state`: the suspend (entered, or refused when it was tried).
pub const STATE_ENTER: u64 = 1;
/// `Record::state`: the machine is back. The time it slept, in milliseconds,
/// is in the bits above the low byte.
pub const STATE_RESUME: u64 = 2;

/// One `Rule::Suspend` record, before the recorder gives it a subject (the
/// caller's domain) and a stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub verdict: Verdict,
    /// [`STATE_ENTER`], or [`STATE_RESUME`] `| slept_ms << 8`.
    pub state: u64,
    /// [`Refusal::blockers`]; on the resume record, the devices that did not
    /// come back.
    pub blockers: u64,
    /// [`Reason::code`] `| detail << 8`; 0 on an Admit.
    pub reason: u64,
}

/// What the kernel gives the sequence. Every method is one step; the sequence
/// decides the order and what is undone. Methods take `&self`: the kernel's
/// platform keeps its state in statics, the script of the host suite in cells.
pub trait Platform {
    /// The build allows system suspend (Kconfig `SYSTEM_SUSPEND`).
    fn enabled(&self) -> bool;

    /// The firmware has the call and the kernel the entry it needs, else why not.
    fn support(&self) -> Result<(), Reason>;

    /// System power assertions live now (`azos_energy::assertion`): each is a
    /// task's claim that the machine stays awake.
    fn assertions(&self) -> u32;

    /// CPUs online now, the caller's included.
    fn online_cpus(&self) -> u32;

    /// Wake sources `caller` holds: the interrupt capabilities of its table.
    /// Authority, not a list the kernel keeps: a task that holds none cannot
    /// have the machine woken by anything it controls.
    fn wake_sources(&self, caller: u32) -> u32;

    /// Stop user tasks from being picked. The caller, the drivers that
    /// quiesce and the kernel's own tasks are not user tasks for this.
    fn freeze(&self) -> Result<(), ()>;

    /// Reverse of [`freeze`](Platform::freeze).
    fn thaw(&self);

    /// Take every device down through runtime PM (`DevicePower::suspend`).
    /// All or nothing: on `Err(n)`, `n` devices would not go down and the ones
    /// that had are up again.
    fn quiesce(&self) -> Result<(), u32>;

    /// Bring the devices back up; returns how many did not come.
    fn unquiesce(&self) -> u32;

    /// Save what the firmware will not keep, and mask what must not interrupt.
    fn save(&self) -> Result<(), ()>;

    /// Reverse of [`save`](Platform::save).
    fn restore(&self);

    /// The firmware call. A suspend that worked returns `Ok` once the machine
    /// has resumed; `Err(code)` is the firmware refusing, and nothing slept.
    fn enter(&self) -> Result<(), i32>;

    /// The clocks now.
    fn clocks(&self) -> Clocks;

    /// The machine slept `ns` that the monotonic clock did not count: add it
    /// to the boot offset (`CLOCK_BOOTTIME`).
    fn add_boot_ns(&self, ns: u64);

    /// A decision record of `Rule::Suspend` about `subject` (the caller's domain).
    fn record(&self, subject: u32, r: Record);
}

/// What the sequence did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The machine slept and is back. `slept_ns` went to the boot offset;
    /// `unresumed` devices did not come back up.
    Resumed { slept_ns: u64, unresumed: u32 },
    Refused(Refusal),
}

impl Outcome {
    /// What the `Power::suspend` op answers: 0 for a resume, else the reason.
    pub const fn code(&self) -> u32 {
        match self {
            Outcome::Resumed { .. } => 0,
            Outcome::Refused(r) => r.reason.code(),
        }
    }
}

fn refuse<P: Platform + ?Sized>(p: &P, subject: u32, r: Refusal) -> Outcome {
    p.record(subject, Record {
        verdict: Verdict::Refuse,
        state: STATE_ENTER,
        blockers: r.blockers as u64,
        reason: r.reason.code() as u64 | (r.detail as u32 as u64) << 8,
    });
    Outcome::Refused(r)
}

/// Suspend the machine for the task `caller` and return when it is back, or
/// say why it did not go. What the caller holds decides the wake sources;
/// `subject` (its domain) is who the records are about.
pub fn run<P: Platform + ?Sized>(p: &P, caller: u32, subject: u32) -> Outcome {
    // ── gates: nothing is touched ──
    if !p.enabled() {
        return refuse(p, subject, Refusal::of(Reason::Disabled));
    }
    if let Err(reason) = p.support() {
        return refuse(p, subject, Refusal::of(reason));
    }
    let held = p.assertions();
    if held > 0 {
        return refuse(p, subject, Refusal { reason: Reason::Asserted, blockers: held, detail: 0 });
    }
    let others = p.online_cpus().saturating_sub(1);
    if others > 0 {
        return refuse(p, subject, Refusal { reason: Reason::CpusOnline, blockers: others, detail: 0 });
    }
    if p.wake_sources(caller) == 0 {
        return refuse(p, subject, Refusal { reason: Reason::NoWakeSource, blockers: 1, detail: 0 });
    }

    // ── down ──
    p.record(subject, Record { verdict: Verdict::Admit, state: STATE_ENTER, blockers: 0, reason: 0 });
    if p.freeze().is_err() {
        return refuse(p, subject, Refusal::of(Reason::FreezeFailed));
    }
    if let Err(busy) = p.quiesce() {
        p.thaw();
        return refuse(p, subject, Refusal { reason: Reason::DeviceBusy, blockers: busy, detail: 0 });
    }
    if p.save().is_err() {
        p.unquiesce();
        p.thaw();
        return refuse(p, subject, Refusal::of(Reason::SaveFailed));
    }

    // ── the sleep ──
    let before = p.clocks();
    let entered = p.enter();

    // ── up, in reverse ──
    p.restore();
    let unresumed = p.unquiesce();
    p.thaw();
    if let Err(code) = entered {
        return refuse(p, subject, Refusal { reason: Reason::EnterFailed, blockers: 0, detail: code });
    }
    let slept = slept_ns(before, p.clocks());
    if slept != 0 {
        p.add_boot_ns(slept);
    }
    p.record(subject, Record {
        verdict: Verdict::Admit,
        state: STATE_RESUME | (slept / 1_000_000) << 8,
        blockers: unresumed as u64,
        reason: 0,
    });
    Outcome::Resumed { slept_ns: slept, unresumed }
}
