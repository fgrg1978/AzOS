// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure hart-liveness accounting for [`crate::smp::wake_harts`].
//!
//! In its own file only so the host test runner (`tests/host/sched-wake-tests`)
//! can compile it: `smp.rs` reads `tp` with inline RISC-V assembly and links
//! against `_secondary_start`, so it can never leave the target. Nothing here
//! has a dependency, and `smp.rs` calls it rather than keeping a copy.
//!
//! # What "online" means, and why it is not a headcount
//!
//! `NUM_ONLINE_CPUS` is consumed as a **prefix bound**: `find_best_cpu` in
//! `scheduler.rs` iterates `0..num_online` and indexes `PER_CPU[i]` directly,
//! and `rebalance_from_offline_cpus(online, total)` treats `online..total` as
//! the dead harts whose ready queues must be drained. So the published number
//! must satisfy exactly one property — **every hart in `0..online` is
//! running** — and a plain count of successes does not satisfy it as soon as
//! there is a hole (hart 2 dead, hart 3 alive).
//!
//! The previous accounting seeded `online = 1` for the boot hart and then
//! incremented per success while a `prefix_intact` flag held. That is correct
//! if and only if the boot hart is hart **0**, because the seed is what claims
//! slot 0. Measured in QEMU virt, the boot hart was hart **2**: with any
//! `hart_start` failure the seeded 1 then stands for a hart nobody started.
//! Concretely, boot hart 2 with hart 0 failing published `online = 1`, i.e.
//! "hart 0 is alive" — the one hart that is not — so every unpinned task went
//! to a dead hart and `rebalance_from_offline_cpus(1, 4)` drained the *live*
//! boot hart's own queue onto it.
//!
//! Recording liveness as a bitmask and deriving the prefix afterwards makes
//! the result independent of which hart happens to boot, which is the whole
//! fix. The result stays conservative rather than unsafe: a live hart past a
//! hole sits idle (see [`stranded`]) instead of a dead hart receiving work.

/// Width of the liveness mask. Harts at or above this index cannot be
/// represented; the Kconfig `NR_CPUS` range stops at 64 for this reason (the
/// scheduler asserts `MAX_CPUS <= HART_MASK_BITS`).
pub const HART_MASK_BITS: usize = u64::BITS as usize;

/// Set the bit for `hart_id`, ignoring ids the mask cannot hold.
///
/// The bounds check is not decoration: `1u64 << hart_id` with `hart_id >= 64`
/// is an overflow, and under this profile (`overflow-checks = true`,
/// `panic = "abort"`) that is a board reset. `num_cpus` comes from the DTB.
#[inline]
pub fn mark_alive(mask: u64, hart_id: usize) -> u64 {
    if hart_id >= HART_MASK_BITS {
        return mask;
    }
    mask | (1u64 << hart_id)
}

/// Length of the longest run of live harts starting at hart 0, capped at
/// `num_cpus`. This is the value to publish as `NUM_ONLINE_CPUS`.
///
/// Returns 0 when hart 0 itself is dead — deliberately. Clamping to 1 would
/// assert that hart 0 is running when it is not, which is the failure this
/// whole module exists to avoid; both consumers already guard the zero case
/// (`rebalance_from_offline_cpus` returns early on `online == 0`,
/// `find_best_cpu` on `num_online <= 1`).
pub fn online_prefix(alive: u64, num_cpus: usize) -> usize {
    let n = num_cpus.min(HART_MASK_BITS);
    let mut count = 0;
    while count < n && (alive >> count) & 1 != 0 {
        count += 1;
    }
    count
}

/// Harts that are alive but sit past the first dead one, so the prefix
/// excludes them and they will never be given work.
///
/// Exists to be logged. Silently idling a working CPU is the kind of thing
/// that gets diagnosed months later as "SMP is slower than it should be".
pub fn stranded(alive: u64, num_cpus: usize) -> u64 {
    let n = num_cpus.min(HART_MASK_BITS);
    let p = online_prefix(alive, num_cpus);
    alive & low_mask(n) & !low_mask(p)
}

/// `bits` low bits set. Split out because `1u64 << 64` is an overflow panic,
/// and `bits == 64` is reachable through `HART_MASK_BITS`.
#[inline]
fn low_mask(bits: usize) -> u64 {
    if bits >= HART_MASK_BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

// ---------------------------------------------------------------------------
// CPU hotplug (Kconfig `CPU_HOTPLUG`): the decisions, pure.
//
// `smp.rs` does the work (firmware calls, queues, timers); what may be done,
// and where the work goes, is decided here so the host suite can drive it.
// The model is the prefix above: the CPUs in `0..online_prefix(alive)` are
// the ones the scheduler places work on, so a CPU can only leave from the
// top of the prefix and only the one right above it can join. That keeps
// every consumer of `NUM_ONLINE_CPUS` right without each learning a mask.
// ---------------------------------------------------------------------------

/// A hotplug request's direction. The numbers are the record's first number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HotplugOp {
    Offline = 0,
    Online = 1,
}

/// Why a hotplug request was refused or failed. The numbers are the reason the
/// `Power` interface answers with (`Out::new(REFUSED, reason)`) and the third
/// number of the `cpu-hotplug` record; they are part of the record format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HotplugReason {
    /// No such CPU: outside the possible mask.
    NotPossible = 1,
    /// The CPU is already in the state asked for.
    NoChange = 2,
    /// The boot CPU keeps the timekeeping and the first interrupt routes.
    BootCpu = 3,
    /// It would leave no CPU online.
    LastCpu = 4,
    /// The caller runs on the CPU: its own task would have to leave first.
    CallerCpu = 5,
    /// The CPU holds real-time state (a band task, an admitted reservation).
    RealTime = 6,
    /// The CPU is in `isolcpus`.
    Isolated = 7,
    /// A task is pinned to the CPU (a reservation, or a task the operator
    /// pinned): moving it would break the pin, so the change is refused.
    Pinned = 8,
    /// Not the CPU the prefix allows: offline takes the highest online CPU,
    /// online the first one past the prefix.
    NotAtPrefixEdge = 9,
    /// The firmware has no call to stop (or start) a CPU.
    NoFirmware = 10,
    /// Another hotplug change is running.
    Busy = 11,
    /// The CPU did not reach the point where it can stop (or start) in time;
    /// it is as it was.
    Timeout = 12,
    /// The firmware refused the stop or the start; the CPU is as it was.
    FirmwareRefused = 13,
    /// Online only: the CPU never stopped here, so there is no saved context
    /// to resume and no idle task of its own to run (a CPU that failed to
    /// start at boot had its queue, idle task included, moved off it).
    NeverStopped = 14,
}

impl HotplugReason {
    /// The number the interface and the record carry.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// A name, for the console line.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotPossible => "no such CPU",
            Self::NoChange => "already in that state",
            Self::BootCpu => "boot CPU",
            Self::LastCpu => "last online CPU",
            Self::CallerCpu => "caller runs there",
            Self::RealTime => "real-time state on the CPU",
            Self::Isolated => "isolated CPU",
            Self::Pinned => "task pinned to the CPU",
            Self::NotAtPrefixEdge => "not at the edge of the online prefix",
            Self::NoFirmware => "firmware has no CPU stop/start",
            Self::Busy => "another change is running",
            Self::Timeout => "timed out",
            Self::FirmwareRefused => "firmware refused",
            Self::NeverStopped => "CPU never ran here",
        }
    }
}

/// What the policy knows of the machine when a request arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine {
    /// Running CPUs (bit n = CPU n), as [`mark_alive`] builds it.
    pub alive: u64,
    /// CPUs the firmware reports (`nr_cpu_ids`): bits at or above are not CPUs.
    pub num_cpus: usize,
    /// The boot CPU.
    pub boot: usize,
    /// The CPU the request runs on.
    pub caller: usize,
    /// CPUs with real-time state now (a band task, a reservation).
    pub rt: u64,
    /// CPUs of `isolcpus`.
    pub isolated: u64,
    /// CPUs that were stopped here and hold a saved context.
    pub stopped: u64,
    /// The firmware can stop and start CPUs.
    pub firmware: bool,
    /// Another change is running.
    pub busy: bool,
}

/// The CPU mask bit for `cpu`, 0 when the mask cannot hold it.
#[inline]
const fn bit_of(cpu: usize) -> u64 {
    if cpu >= HART_MASK_BITS { 0 } else { 1u64 << cpu }
}

/// Whether CPU `cpu` may be taken offline, given `pinned` tasks pinned to it.
/// The checks run in the order a caller wants to hear them: the cheap and
/// permanent ones first, the ones that may pass later last.
pub fn check_offline(m: &Machine, cpu: usize, pinned: u32) -> Result<(), HotplugReason> {
    use HotplugReason as R;
    if cpu >= m.num_cpus.min(HART_MASK_BITS) {
        return Err(R::NotPossible);
    }
    if m.busy {
        return Err(R::Busy);
    }
    if m.alive & bit_of(cpu) == 0 {
        return Err(R::NoChange);
    }
    if cpu == m.boot {
        return Err(R::BootCpu);
    }
    if cpu == m.caller {
        return Err(R::CallerCpu);
    }
    if (m.alive & low_mask(m.num_cpus.min(HART_MASK_BITS))).count_ones() <= 1 {
        return Err(R::LastCpu);
    }
    if m.isolated & bit_of(cpu) != 0 {
        return Err(R::Isolated);
    }
    if m.rt & bit_of(cpu) != 0 {
        return Err(R::RealTime);
    }
    if !m.firmware {
        return Err(R::NoFirmware);
    }
    // The top of the prefix, or a CPU past a hole (alive but outside the
    // prefix, which holds no work): either way nothing at or below the
    // prefix is left with a hole under it.
    let p = online_prefix(m.alive, m.num_cpus);
    if cpu + 1 != p && cpu < p {
        return Err(R::NotAtPrefixEdge);
    }
    if pinned != 0 {
        return Err(R::Pinned);
    }
    Ok(())
}

/// Whether CPU `cpu` may be brought online.
pub fn check_online(m: &Machine, cpu: usize) -> Result<(), HotplugReason> {
    use HotplugReason as R;
    if cpu >= m.num_cpus.min(HART_MASK_BITS) {
        return Err(R::NotPossible);
    }
    if m.busy {
        return Err(R::Busy);
    }
    if m.alive & bit_of(cpu) != 0 {
        return Err(R::NoChange);
    }
    if m.stopped & bit_of(cpu) == 0 {
        return Err(R::NeverStopped);
    }
    if !m.firmware {
        return Err(R::NoFirmware);
    }
    // The first CPU past the prefix; a CPU further up would leave a hole.
    if cpu != online_prefix(m.alive, m.num_cpus) {
        return Err(R::NotAtPrefixEdge);
    }
    Ok(())
}

/// The liveness mask after `cpu` goes offline (`on == false`) or online.
pub fn alive_after(alive: u64, cpu: usize, on: bool) -> u64 {
    if on { mark_alive(alive, cpu) } else { alive & !bit_of(cpu) }
}

/// The CPU that takes over the timers and the work of `cpu`: the lowest live
/// CPU other than it. The same CPU every time, so a sleeper does not hop
/// around while CPUs come and go, and it is inside the prefix whenever any CPU
/// is (the prefix starts at CPU 0).
pub fn takeover_cpu(alive: u64, num_cpus: usize, cpu: usize) -> Option<usize> {
    let live = alive & low_mask(num_cpus.min(HART_MASK_BITS)) & !bit_of(cpu);
    if live == 0 { None } else { Some(live.trailing_zeros() as usize) }
}

/// What the drain of an offline CPU's ready queue does with one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Dequeue it and place it on another CPU.
    Move,
    /// The CPU's own idle task: it stays, it only runs here.
    KeepIdle,
    /// Pinned here, not the idle task: it cannot move. The request was
    /// refused for this before it started, so seeing one now means the pin
    /// came after the check and the change is undone.
    Pinned,
}

/// The drain's decision for one queued task.
pub const fn disposition(is_idle: bool, pinned: bool) -> Disposition {
    match (is_idle, pinned) {
        (true, _) => Disposition::KeepIdle,
        (false, true) => Disposition::Pinned,
        (false, false) => Disposition::Move,
    }
}
