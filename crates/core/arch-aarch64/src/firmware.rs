// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The calls into the firmware: PSCI v1.0 (Power State Coordination
//! Interface) and Arm semihosting.
//!
//! # PSCI
//!
//! ARM's standard SMC/HVC interface for shutdown, reboot, and
//! starting secondary CPUs. Function IDs from `ARM DEN 0022D.b`
//! Table 5-1.
//!
//! **Conduit selection.** PSCI calls can travel through either
//! `SMC` (handled by EL3 firmware — TF-A, OP-TEE) or `HVC`
//! (handled by EL2 — a hypervisor or, in our case, QEMU's
//! built-in PSCI emulator). The right one depends on the
//! platform: real hardware with ATF wants SMC; QEMU `-machine
//! virt` defaults to HVC (psci-conduit=hvc). We expose a runtime
//! selector so both work without a recompile.
//!
//! Default = HVC, which is what QEMU virt expects. Call
//! [`set_conduit`] before any PSCI call to switch to SMC on
//! platforms with EL3 firmware.

/// PSCI function IDs (32-bit + SMC32 convention; 64-bit variants
/// add `0x40000000` to the FID).
pub const PSCI_VERSION:        u32 = 0x84000000;
pub const PSCI_CPU_SUSPEND_64: u32 = 0xC4000001;
pub const PSCI_CPU_OFF:        u32 = 0x84000002;
pub const PSCI_CPU_ON_64:      u32 = 0xC4000003;
pub const PSCI_SYSTEM_SUSPEND_64: u32 = 0xC400000E;
pub const PSCI_SYSTEM_OFF:     u32 = 0x84000008;
pub const PSCI_SYSTEM_RESET:   u32 = 0x84000009;
pub const PSCI_FEATURES:       u32 = 0x8400000A;
pub const PSCI_AFFINITY_INFO_64: u32 = 0xC4000004;

/// PSCI standard return codes.
pub const PSCI_OK:                    i32 = 0;
pub const PSCI_NOT_SUPPORTED:         i32 = -1;
pub const PSCI_INVALID_PARAMS:        i32 = -2;
pub const PSCI_DENIED:                i32 = -3;
pub const PSCI_ALREADY_ON:            i32 = -4;
pub const PSCI_ON_PENDING:            i32 = -5;
pub const PSCI_INTERNAL_FAILURE:      i32 = -6;
pub const PSCI_NOT_PRESENT:           i32 = -7;
pub const PSCI_DISABLED:              i32 = -8;
pub const PSCI_INVALID_ADDRESS:       i32 = -9;

/// PSCI conduit selector — which instruction carries the call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Conduit {
    /// `HVC #0` — handled by EL2. Right for QEMU virt's emulated
    /// PSCI and for KVM guests; right whenever there is no EL3
    /// firmware (ATF/TF-A) installed.
    Hvc,
    /// `SMC #0` — handled by EL3. Right for production hardware
    /// running ATF/TF-A, OP-TEE, or any other secure-monitor that
    /// implements PSCI.
    Smc,
}

/// Active conduit. AtomicU8: 0 = HVC, 1 = SMC. Defaults to HVC
/// because QEMU virt (our primary aarch64 test target) routes
/// PSCI through HVC.
static CONDUIT: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

const CONDUIT_HVC: u8 = 0;
const CONDUIT_SMC: u8 = 1;

/// Override the active PSCI conduit. Safe to call from any EL;
/// takes effect on the next PSCI call.
pub fn set_conduit(c: Conduit) {
    let v = match c {
        Conduit::Hvc => CONDUIT_HVC,
        Conduit::Smc => CONDUIT_SMC,
    };
    CONDUIT.store(v, core::sync::atomic::Ordering::Release);
}

/// Read the currently active conduit.
pub fn conduit() -> Conduit {
    match CONDUIT.load(core::sync::atomic::Ordering::Acquire) {
        CONDUIT_SMC => Conduit::Smc,
        _ => Conduit::Hvc,
    }
}

/// Issue a PSCI call (or any other SMCCC fast call: `ext::mitigations` asks
/// the firmware for its speculation workarounds) through the active conduit. Returns the X0
/// register on return — for PSCI calls that's the standard return
/// code (see `PSCI_*` constants above). X4-X17 are declared clobbered: the
/// SMC Calling Convention lets the callee use them (v1.0 does not preserve
/// them), and the call is inlined into code with live registers.
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn psci_call(fn_id: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let mut x0: u64 = fn_id as u64;
    match conduit() {
        Conduit::Hvc => unsafe {
            core::arch::asm!(
                "hvc #0",
                inout("x0") x0,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack, preserves_flags),
            );
        },
        Conduit::Smc => unsafe {
            core::arch::asm!(
                "smc #0",
                inout("x0") x0,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack, preserves_flags),
            );
        },
    }
    x0 as i64
}

/// `PSCI_CPU_ON_64`: bring secondary CPU `target_cpu` (MPIDR
/// affinity) up at `entry_point_phys` with `context_id` placed in
/// the new CPU's X0 register.
#[cfg(target_arch = "aarch64")]
pub fn cpu_on(target_cpu: u64, entry_point_phys: u64, context_id: u64) -> i32 {
    psci_call(PSCI_CPU_ON_64, target_cpu, entry_point_phys, context_id) as i32
}

// ── Deep idle: CPU_SUSPEND, standby, retention and power-down ───────────────
//
// `Cpu::cpu_idle(depth)` enters the platform's `depth`-th idle state (device
// tree `cpu-idle-states`, in order) with `CPU_SUSPEND(arm,psci-suspend-param)`.
// A STANDBY or RETENTION state (power_state StateType 0) keeps the PE's whole
// context: the call returns on a wake-up event and execution goes on after it,
// as after a `wfi`. A POWER-DOWN state (StateType 1) loses it and resumes at
// the entry point given to the call, with the MMU off: the PE keeps its
// context in its `SaveArea` first, and resumes at the SECONDARY entry, which
// restores it (below). That needs the resume entry the kernel registers with
// [`set_resume`] (Kconfig `CPU_IDLE_POWERDOWN`); until it has, such a state is
// treated as absent, and the CPU enters the deepest standby state at or below
// the depth asked for, else `wfi`. A state with `local-timer-stop` stays
// absent either way: the PE's timer stops in it and nothing else wakes the PE
// for its own deadline.

/// Idle states per CPU the ladder keeps: the device tree reader's
/// `cpu-idle-states` bound (`azos_dtb::DT_ENERGY_CPU_IDLE`).
pub const IDLE_DEPTHS: usize = 4;

/// How the firmware reads a `CPU_SUSPEND` `power_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerStateFormat {
    /// StateID bits 15:0, StateType bit 16, PowerLevel bits 25:24.
    Original,
    /// StateID bits 27:0, StateType bit 30 (`PSCI_FEATURES` bit 1).
    Extended,
}

impl PowerStateFormat {
    /// StateType: 1 = power-down (the context is lost), 0 = standby or
    /// retention.
    pub const fn type_bit(self) -> u32 {
        match self {
            Self::Original => 1 << 16,
            Self::Extended => 1 << 30,
        }
    }
}

/// `power_state` loses the PE's context (a power-down state).
pub const fn power_state_loses_context(power_state: u32, format: PowerStateFormat) -> bool {
    power_state & format.type_bit() != 0
}

/// Whether, and how, `CPU_SUSPEND` can be called, from what the firmware
/// answers: `version` is `PSCI_VERSION` (`major << 16 | minor`, negative when
/// the call is not implemented) and `features` yields
/// `PSCI_FEATURES(CPU_SUSPEND_64)` (asked only for PSCI 1.0 and later, which
/// introduced it). PSCI 0.2 has `CPU_SUSPEND` and the original format.
pub fn suspend_format(version: i32, features: impl FnOnce() -> i32) -> Option<PowerStateFormat> {
    match version {
        v if v < 0 => None,
        v if v >> 16 == 0 => (v >= 2).then_some(PowerStateFormat::Original),
        _ => match features() {
            f if f < 0 => None,
            f if f & 2 != 0 => Some(PowerStateFormat::Extended),
            _ => Some(PowerStateFormat::Original),
        },
    }
}

/// `PSCI_FEATURES`: the answer for `fn_id`, a negative `PSCI_*` code if it is
/// not implemented.
#[cfg(target_arch = "aarch64")]
pub fn features(fn_id: u32) -> i32 {
    psci_call(PSCI_FEATURES, fn_id as u64, 0, 0) as i32
}

/// The `power_state` format of this firmware's `CPU_SUSPEND`, `None` when it
/// has none.
#[cfg(target_arch = "aarch64")]
pub fn probe_suspend_format() -> Option<PowerStateFormat> {
    let version = psci_call(PSCI_VERSION, 0, 0, 0) as i32;
    suspend_format(version, || features(PSCI_CPU_SUSPEND_64))
}

/// `CPU_SUSPEND` with a standby or retention `power_state`: returns the PSCI
/// code (0 once the PE has been woken). The entry point and context are
/// unused by such a state. The caller passes only a `power_state` that
/// [`SuspendState::enterable`] accepted: nothing here can tell the format.
#[cfg(target_arch = "aarch64")]
pub fn cpu_suspend_standby(power_state: u32) -> i32 {
    psci_call(PSCI_CPU_SUSPEND_64, power_state as u64, 0, 0) as i32
}

/// One `cpu-idle-states` entry, as far as entering it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspendState {
    /// `arm,psci-suspend-param`; `None` when the node has none.
    pub param: Option<u32>,
    /// `local-timer-stop`: the PE's timer stops in the state, and nothing here
    /// re-arms it from another source.
    pub local_timer_stop: bool,
}

impl SuspendState {
    /// The `power_state` this state can be entered with, or `None`: a state
    /// without a parameter, one that stops the local timer, and a power-down
    /// one are not entered.
    pub const fn enterable(&self, format: PowerStateFormat) -> Option<u32> {
        match self.param {
            Some(p) if !power_state_loses_context(p, format) && !self.local_timer_stop => Some(p),
            _ => None,
        }
    }
}

impl SuspendState {
    /// The `power_state` of a state that is entered only through the resume
    /// entry: a power-down one that does not stop the timer.
    pub const fn enterable_with_resume(&self, format: PowerStateFormat) -> Option<u32> {
        match self.param {
            Some(p) if power_state_loses_context(p, format) && !self.local_timer_stop => Some(p),
            _ => None,
        }
    }
}

/// What one `CPU_SUSPEND` return code means for the next idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspendOutcome {
    /// The PE slept and was woken.
    Slept,
    /// The call did not sleep, but may work next time (`DENIED`, an internal
    /// failure): wait with `wfi` now.
    Transient,
    /// The firmware does not implement the call or refuses this state for
    /// good: wait with `wfi` now and never ask for it again.
    Unusable,
}

/// Classify a `CPU_SUSPEND` return code.
pub const fn classify_suspend(code: i32) -> SuspendOutcome {
    match code {
        PSCI_OK => SuspendOutcome::Slept,
        PSCI_NOT_SUPPORTED | PSCI_INVALID_PARAMS => SuspendOutcome::Unusable,
        _ => SuspendOutcome::Transient,
    }
}

/// One CPU's idle states: which depths can be entered, and with what.
/// Written at boot (`install`) and by the CPU itself when the firmware refuses
/// a state for good (`retire`); read on every idle entry.
pub struct IdleLadder {
    param: [core::sync::atomic::AtomicU32; IDLE_DEPTHS],
    /// Bit `d - 1` set: depth `d` is a standby or retention state, enterable
    /// with `param[d - 1]`. A separate mask because 0 is a valid `power_state`
    /// (StateID 0, standby).
    live: core::sync::atomic::AtomicU8,
    /// Bit `d - 1` set: depth `d` is a power-down state, enterable once
    /// [`set_resume`] has given the kernel a resume entry.
    deep: core::sync::atomic::AtomicU8,
}

impl IdleLadder {
    /// No state enterable: every depth is `wfi`.
    pub const EMPTY: Self = Self {
        param: [const { core::sync::atomic::AtomicU32::new(0) }; IDLE_DEPTHS],
        live: core::sync::atomic::AtomicU8::new(0),
        deep: core::sync::atomic::AtomicU8::new(0),
    };

    /// Take the device tree's states (depth 1 is `states[0]`; depth 0 is
    /// `wfi` and is not listed). Returns the mask of depths enterable as
    /// themselves without a resume entry, bit `d - 1` for depth `d`; the
    /// power-down ones join them when [`set_resume`] is called, in any order.
    pub fn install(&self, states: &[SuspendState], format: PowerStateFormat) -> u8 {
        use core::sync::atomic::Ordering::{Relaxed, Release};
        let (mut live, mut deep) = (0u8, 0u8);
        for (i, s) in states.iter().take(IDLE_DEPTHS).enumerate() {
            if let Some(p) = s.enterable(format) {
                self.param[i].store(p, Relaxed);
                live |= 1 << i;
            } else if let Some(p) = s.enterable_with_resume(format) {
                self.param[i].store(p, Relaxed);
                deep |= 1 << i;
            }
        }
        self.deep.store(deep, Release);
        self.live.store(live, Release);
        live
    }

    /// The `power_state` to enter for `depth`: its own, else the deepest
    /// enterable one below it, else `None` (`wfi`).
    pub fn entry(&self, depth: u8) -> Option<u32> {
        self.entry_kind(depth).map(|(p, _)| p)
    }

    /// [`entry`](Self::entry) and whether the state is a power-down one
    /// (entered through the saved-context path).
    fn entry_kind(&self, depth: u8) -> Option<(u32, bool)> {
        use core::sync::atomic::Ordering::{Acquire, Relaxed};
        let top = (depth as usize).min(IDLE_DEPTHS);
        let deep = self.deep.load(Acquire);
        let live = self.live.load(Acquire);
        let usable = live | if resume_entry().is_some() { deep } else { 0 };
        (0..top).rev().find(|&i| usable & (1 << i) != 0).map(|i| (self.param[i].load(Relaxed), deep & (1 << i) != 0))
    }

    /// The depths that are power-down states the kernel can enter: bit `d - 1`
    /// for depth `d`, whether or not the resume entry is set yet. Their
    /// context is lost, so the energy model marks them
    /// (`azos_energy::PerfDomain::mark_context_loss`) and a CPU with
    /// real-time state is never put in one. A state that is not enterable at
    /// all (no parameter, `local-timer-stop`) is entered as a shallower one,
    /// so it is not here.
    pub fn powerdown_mask(&self) -> u8 {
        self.deep.load(core::sync::atomic::Ordering::Acquire)
    }

    /// The firmware refuses `power_state` for good: no depth uses it again.
    pub fn retire(&self, power_state: u32) {
        use core::sync::atomic::Ordering::{AcqRel, Relaxed};
        for i in 0..IDLE_DEPTHS {
            if (self.live.load(Relaxed) | self.deep.load(Relaxed)) & (1 << i) != 0
                && self.param[i].load(Relaxed) == power_state
            {
                self.live.fetch_and(!(1 << i), AcqRel);
                self.deep.fetch_and(!(1 << i), AcqRel);
            }
        }
    }

    /// Idle in `depth` through `suspend` (the firmware call for a standby or
    /// retention state, handed the `power_state`; a power-down one goes
    /// through [`cpu_suspend_powerdown`]). `true` when the CPU slept and was
    /// woken; `false` when the caller still has to wait (no state for this
    /// depth, or the call returned without sleeping).
    pub fn enter(&self, depth: u8, suspend: impl FnOnce(u32) -> i32) -> bool {
        let Some((p, deep)) = self.entry_kind(depth) else { return false };
        let code = if deep { cpu_suspend_powerdown(p) } else { suspend(p) };
        match classify_suspend(code) {
            SuspendOutcome::Slept => true,
            SuspendOutcome::Transient => false,
            SuspendOutcome::Unusable => {
                self.retire(p);
                false
            }
        }
    }
}

// ── A PE that stops and starts again (CPU hotplug) ──────────────────────────
//
// `CPU_OFF` ends the calling PE: it returns only with an error, and the PE is
// `OFF` until another PE starts it with `CPU_ON`. The kernel stops a PE through
// [`stop_current`], which keeps its context first, so a later `CPU_ON` at the
// secondary entry resumes it where it stopped (the saved-context path below)
// instead of booting it from nothing.

/// `AFFINITY_INFO` values (`ON`, `OFF`, `ON_PENDING`).
pub const AFFINITY_ON: i32 = 0;
pub const AFFINITY_OFF: i32 = 1;

/// The firmware has `CPU_OFF` and `AFFINITY_INFO`: PSCI 0.2 on (`version` is
/// `PSCI_VERSION`, negative when the call is not implemented).
pub const fn psci_has_cpu_off(version: i32) -> bool {
    version >= 2
}

/// Ask the firmware whether it can stop and start PEs.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn cpu_stop_available() -> bool {
    psci_has_cpu_off(psci_call(PSCI_VERSION, 0, 0, 0) as i32)
}

/// `AFFINITY_INFO(target_cpu, 0)`: [`AFFINITY_ON`], [`AFFINITY_OFF`], 2 for a
/// start pending, or a negative `PSCI_*` code. `target_cpu` is the MPIDR
/// affinity in PSCI's packing (`Mpidr::pack_for_psci`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn affinity_info(target_cpu: u64) -> i32 {
    psci_call(PSCI_AFFINITY_INFO_64, target_cpu, 0, 0) as i32
}

/// The finisher of a stop: `CPU_OFF` does not return when it works.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn finish_cpu_off(_arg: usize) -> isize {
    psci_call(PSCI_CPU_OFF, 0, 0, 0) as isize
}

/// Stop the calling PE, keeping its context. Returns [`RESUMED`] once a
/// `CPU_ON` has brought it back (it then runs on from this call), or the PSCI
/// code when the stop was refused (the PE never stopped).
///
/// # Safety
/// Interrupts masked, and nothing of this PE's may still be needed by the
/// others: its queues drained, its timers moved (`azos_sched::smp`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn stop_current() -> isize {
    // SAFETY: the caller's contract.
    unsafe { save_and_run(hart_now(), finish_cpu_off, 0) }
}

// ── Saved context: a power-down state, a stopped PE ─────────────────────────
//
// A PE that loses its context (a power-down `CPU_SUSPEND`, or a stop the kernel
// will undo) leaves it in its slot (the table given to [`set_resume`]) and is started again at the
// SECONDARY entry (`_aarch64_secondary_entry`, `kernel/src/entry/aarch64/asm/
// boot.S`), the same symbol `CPU_ON` boots every secondary PE through: past
// the EL drop, the per-PE registers, the boot stack, the MMU and the signed
// returns, the entry asks [`resume_area`] for a slot to restore, and
// a PE without one goes on to `secondary_main` as before. Restoring is
// `azos_cpu_resume_restore` (`kernel/src/entry/aarch64/resume.rs`): `TTBR0_EL1`
// (the entry has put the kernel table there, the idle task may be on another),
// the EL0 thread registers, then the registers the AAPCS64 keeps across a call,
// `sp` and `lr`, and it returns [`RESUMED`] from `azos_cpu_save_run`.
//
// The save side cleans the slot to the point of coherency before the firmware
// call: a power-down loses the PE's caches, and the entry reads it back.
//
// What is NOT kept, and so is redone by the resume hook ([`set_resume`]): the
// interrupt controller's per-PE state and the timer (the secondary start's
// `secondary_irq_init` and `secondary_timer_init`). The FP/SIMD file needs
// nothing: a PE idles with no task's registers live (`entry/aarch64/fp.rs`:
// `AARCH64_FP_LIVE` is clear while the idle task runs), and EL1 itself is
// soft-float.

/// What `azos_cpu_save_run` returns on the path that comes back through the
/// resume entry. No PSCI or SBI error code equals it.
pub const RESUMED: isize = isize::MAX;

/// A PE's saved context. 8-byte fields in the order `azos_cpu_save_run`
/// stores them; the asm takes the offsets from here.
#[repr(C, align(16))]
pub struct SaveArea {
    /// 1 from before the context is saved until the resume entry takes it (or
    /// the call that saved it returns): the secondary entry restores a slot
    /// only when it is pending.
    pub pending: core::sync::atomic::AtomicU64,
    /// `x19..=x29`.
    pub x: [u64; 11],
    pub lr: u64,
    pub sp: u64,
    pub sp_el0: u64,
    pub ttbr0: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub contextidr: u64,
}

impl SaveArea {
    pub const EMPTY: SaveArea = SaveArea {
        pending: core::sync::atomic::AtomicU64::new(0),
        x: [0; 11], lr: 0, sp: 0, sp_el0: 0, ttbr0: 0, tpidr_el0: 0, tpidrro_el0: 0, contextidr: 0,
    };
}

/// The resume entry, its hook and the slots, set once by the kernel at boot.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static SAVE_SLOTS: core::sync::atomic::AtomicPtr<SaveArea> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static SAVE_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static RESUME_ADDR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
azos_common::ro_hook! {
    static RESUME_HOOK: fn(usize);
}
azos_common::ro_hook! {
    static RESUME_PREPARE: fn(usize);
}

/// The kernel has a resume entry: `entry_phys` is the secondary entry's
/// PHYSICAL address (what `CPU_SUSPEND` takes as the entry point: the PE
/// starts with the MMU off), `hook` redoes the PE's controller and timer state
/// after a resume (given the CPU id), `prepare` runs on the PE just before it
/// saves its context (given the CPU id: the kernel cleans and invalidates the
/// PE's boot stack, which the entry uses with the MMU off and then on), and
/// `slots` points at one [`SaveArea`] per possible PE, `count` of them, owned
/// by the kernel (so they are linked only when the kernel asks for this path:
/// Kconfig `CPU_HOTPLUG`, `CPU_IDLE_POWERDOWN`). Boot CPU, before the idle
/// states are used.
///
/// # Safety
/// `slots` is valid for reads and writes of `count` areas for the life of the
/// kernel, and nothing else uses them.
pub unsafe fn set_resume(entry_phys: u64, hook: fn(usize), prepare: fn(usize), slots: *mut SaveArea, count: usize) {
    use core::sync::atomic::Ordering::Release;
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        SAVE_SLOTS.store(slots, Release);
        SAVE_COUNT.store(count, Release);
    }
    // The host has no PE to save: the slots are the kernel's business.
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    let _ = (slots, count);
    RESUME_HOOK.set(hook);
    RESUME_PREPARE.set(prepare);
    RESUME_ADDR.store(entry_phys, Release);
}

/// The resume entry, once the kernel has set one.
pub fn resume_entry() -> Option<u64> {
    match RESUME_ADDR.load(core::sync::atomic::Ordering::Acquire) {
        0 => None,
        e => Some(e),
    }
}

/// `cpu`'s slot, if the kernel gave one.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn slot(cpu: usize) -> Option<*mut SaveArea> {
    use core::sync::atomic::Ordering::Acquire;
    if cpu < SAVE_COUNT.load(Acquire) {
        // SAFETY: `set_resume`'s contract: `count` areas from `slots`.
        Some(unsafe { SAVE_SLOTS.load(Acquire).add(cpu) })
    } else {
        None
    }
}

/// The slot `cpu` must restore, taken once (`pending` cleared), or null: the
/// secondary entry's question (`azos_cpu_resume_check`, `kernel/src/entry/
/// aarch64/resume.rs`, which boot.S calls). Called with the boot stack, the MMU
/// and the vectors in place, before any other kernel code of the PE has run.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn resume_area(cpu: usize) -> *mut SaveArea {
    match slot(cpu) {
        // SAFETY: `slot` returned a valid area.
        Some(a) if unsafe { &(*a).pending }.swap(0, core::sync::atomic::Ordering::AcqRel) != 0 => a,
        _ => core::ptr::null_mut(),
    }
}

/// Keep this PE's context in its slot and call `finisher(arg)`. The finisher
/// is the firmware call that takes the PE away; it returns only on failure,
/// and its value is this function's. When the PE is started again at the
/// secondary entry the context is restored and this returns [`RESUMED`].
/// Masks interrupts around the whole sequence and puts the mask back.
///
/// # Safety
/// `cpu` is the calling PE's id, and a resume entry is set.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn save_and_run(cpu: usize, finisher: extern "C" fn(usize) -> isize, arg: usize) -> isize {
    use core::sync::atomic::Ordering::{Relaxed, Release};
    let Some(area) = slot(cpu) else { return PSCI_INVALID_PARAMS as isize };
    if let Some(f) = RESUME_PREPARE.get() {
        f(cpu);
    }
    let daif = irq_mask();
    // SAFETY: `slot` returned this PE's own area.
    unsafe { &(*area).pending }.store(1, Release);
    // SAFETY: `area` is this PE's own slot; the asm stores into it only.
    let r = unsafe { azos_cpu_save_run(area, finisher, arg) };
    // SAFETY: as above.
    unsafe { &(*area).pending }.store(0, Relaxed);
    if r == RESUMED {
        run_resume_hook(cpu);
    }
    irq_restore(daif);
    r
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn run_resume_hook(cpu: usize) {
    if let Some(f) = RESUME_HOOK.get() {
        f(cpu);
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn azos_cpu_save_run(area: *mut SaveArea, finisher: extern "C" fn(usize) -> isize, arg: usize) -> isize;
}

/// The calling PE's id (`TPIDR_EL1`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn hart_now() -> usize {
    crate::cpu::hart_id()
}

/// Mask IRQ and FIQ, returning the old `DAIF`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn irq_mask() -> u64 {
    let old: u64;
    // SAFETY: sets the I and F mask bits only.
    unsafe { core::arch::asm!("mrs {}, daif", "msr daifset, #3", out(reg) old, options(nomem, nostack)) };
    old
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn irq_restore(daif: u64) {
    // SAFETY: puts back what `irq_mask` found.
    unsafe { core::arch::asm!("msr daif, {}", in(reg) daif, options(nomem, nostack)) };
}

/// The finisher of a power-down suspend: `CPU_SUSPEND` with the secondary
/// entry as the entry point and the CPU id as the context. It returns only
/// when the PE did not power down (a PSCI code, 0 for a wake before it did).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn finish_cpu_suspend(power_state: usize) -> isize {
    let entry = resume_entry().unwrap_or(0);
    psci_call(PSCI_CPU_SUSPEND_64, power_state as u64, entry, hart_now() as u64) as isize
}

/// `CPU_SUSPEND` with a power-down `power_state`: the PE keeps its context,
/// powers down, and returns 0 once the resume entry has restored it. The PSCI
/// code when the call returned without a power-down. `PSCI_NOT_SUPPORTED`
/// while the kernel has no resume entry. The caller passes only a
/// `power_state` that [`SuspendState::enterable_with_resume`] accepted.
pub fn cpu_suspend_powerdown(power_state: u32) -> i32 {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if resume_entry().is_none() {
            return PSCI_NOT_SUPPORTED;
        }
        // SAFETY: the interrupt mask is `save_and_run`'s; the CPU id is the
        // calling PE's; the resume entry is set.
        match unsafe { save_and_run(hart_now(), finish_cpu_suspend, power_state as usize) } {
            RESUMED => PSCI_OK,
            err => err as i32,
        }
    }
    // Off the target there is no PE to save: what a firmware without the call says.
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = power_state;
        PSCI_NOT_SUPPORTED
    }
}

// ── System suspend: SYSTEM_SUSPEND, to RAM ─────────────────────────────────
//
// `SYSTEM_SUSPEND(entry_point_address, context_id)` (PSCI 1.0) puts the whole
// machine in its deepest state with the calling CPU the only one on. It does
// not return when it works: the CPU restarts at the entry point with the MMU
// and caches off and `context_id` in X0, like a `CPU_ON` target, having lost
// its context. A return is therefore an error code. The kernel does not call
// it unless it has an entry point (`RESUME_ENTRY`) that restores the context
// saved before the call; none exists yet, which is the refusal the sequence
// (`azos_drv_power::pm::suspend`) reports as `NoResumeEntry`.

/// The physical address `SYSTEM_SUSPEND` resumes the CPU at: the trampoline
/// that turns the MMU back on and returns into the saved context. None yet.
pub const RESUME_ENTRY: Option<u64> = None;

/// Why the kernel cannot suspend the system on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemSuspendMissing {
    /// The firmware does not implement `SYSTEM_SUSPEND`: its answer (a
    /// negative `PSCI_*` code; `PSCI_NOT_SUPPORTED` for a PSCI older than 1.0,
    /// which does not have the call).
    Firmware(i32),
    /// The firmware has it and the kernel has no [`RESUME_ENTRY`].
    ResumeEntry,
}

/// Whether `SYSTEM_SUSPEND` can be used, from what the firmware answers:
/// `version` is `PSCI_VERSION` (negative when the call is not implemented),
/// `features` yields `PSCI_FEATURES(SYSTEM_SUSPEND_64)` (asked only for PSCI
/// 1.0 and later, which introduced the call; non-negative when implemented),
/// and `entry` is the kernel's [`RESUME_ENTRY`]. The firmware's answer comes
/// first: a machine without the call needs no entry point.
pub fn system_suspend_available(
    version: i32,
    features: impl FnOnce() -> i32,
    entry: Option<u64>,
) -> Result<(), SystemSuspendMissing> {
    let code = match version {
        v if v < 0 => v,
        v if v >> 16 == 0 => PSCI_NOT_SUPPORTED,
        _ => features(),
    };
    if code < 0 {
        return Err(SystemSuspendMissing::Firmware(code));
    }
    entry.map(|_| ()).ok_or(SystemSuspendMissing::ResumeEntry)
}

/// Ask the firmware (`PSCI_VERSION`, `PSCI_FEATURES`) whether the kernel can
/// suspend the system.
#[cfg(target_arch = "aarch64")]
pub fn system_suspend_support() -> Result<(), SystemSuspendMissing> {
    let version = psci_call(PSCI_VERSION, 0, 0, 0) as i32;
    system_suspend_available(version, || features(PSCI_SYSTEM_SUSPEND_64), RESUME_ENTRY)
}

/// `SYSTEM_SUSPEND`: the machine suspends and resumes at `entry_point_phys`
/// with `context_id` in X0, so this returns only with the firmware's error
/// code. The caller has the other CPUs off and the context saved.
#[cfg(target_arch = "aarch64")]
pub fn system_suspend(entry_point_phys: u64, context_id: u64) -> i32 {
    psci_call(PSCI_SYSTEM_SUSPEND_64, entry_point_phys, context_id, 0) as i32
}

// ── Return-code decoding ────────────────────────────────────────────────

/// Decoded `PSCI_CPU_ON_64` outcome — the form a caller actually wants to
/// match on, rather than comparing a raw `i32` against the `PSCI_*`
/// constants by hand at every call site.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuOnOutcome {
    /// `PSCI_OK` — the target PE is now running at the given entry point.
    Success,
    /// `PSCI_ALREADY_ON` — the target PE was already on; not an error for
    /// a caller that just wants "on" as the end state.
    AlreadyOn,
    /// `PSCI_ON_PENDING` — another CPU_ON for this target is in flight.
    OnPending,
    InvalidParams,
    InvalidAddress,
    Denied,
    InternalFailure,
    NotSupported,
    Disabled,
    NotPresent,
    /// Any return code this decoder doesn't recognise, carried through
    /// unchanged so a caller can still log/report it.
    Unknown(i32),
}

/// Decode a raw PSCI return value (as read from X0) into a
/// [`CpuOnOutcome`]. Pure — no `target_arch` gate, no
/// `core::arch::asm!` — safe to run on any host, including this
/// project's Apple Silicon dev machines where `cargo test`'s own target
/// (`aarch64-apple-darwin`) makes `target_arch = "aarch64"` true (see
/// `gic.rs`'s header comment on the same trap).
///
/// Takes the UNTRUNCATED 64-bit return rather than an already-narrowed
/// `i32` and truncates it here via `as i32`: PSCI's calling convention
/// defines the status as a signed 32-bit value in the low word of X0 and
/// requires firmware to sign-extend it into the rest of the register, but
/// not every implementation does. `as i32` on a `u64`/`i64` keeps the low
/// 32 bits regardless of what the high 32 held, so a firmware that
/// zero-extended `-4` into `0x0000_0000_FFFF_FFFC` decodes identically to
/// one that properly sign-extended it into `0xFFFF_FFFF_FFFF_FFFC` —
/// tested explicitly below rather than assumed.
pub fn decode_cpu_on(raw_x0: i64) -> CpuOnOutcome {
    match raw_x0 as i32 {
        PSCI_OK => CpuOnOutcome::Success,
        PSCI_ALREADY_ON => CpuOnOutcome::AlreadyOn,
        PSCI_ON_PENDING => CpuOnOutcome::OnPending,
        PSCI_INVALID_PARAMS => CpuOnOutcome::InvalidParams,
        PSCI_INVALID_ADDRESS => CpuOnOutcome::InvalidAddress,
        PSCI_DENIED => CpuOnOutcome::Denied,
        PSCI_INTERNAL_FAILURE => CpuOnOutcome::InternalFailure,
        PSCI_NOT_SUPPORTED => CpuOnOutcome::NotSupported,
        PSCI_DISABLED => CpuOnOutcome::Disabled,
        PSCI_NOT_PRESENT => CpuOnOutcome::NotPresent,
        other => CpuOnOutcome::Unknown(other),
    }
}

/// [`cpu_on`] + [`decode_cpu_on`] in one call — the form SMP bring-up
/// code actually wants (match on outcome, not compare a raw code against
/// constants at every call site). `cpu_on` itself is untouched — existing
/// callers (`aarch64-smoke`) that want the raw code keep using it.
#[cfg(target_arch = "aarch64")]
pub fn cpu_on_checked(target_cpu: u64, entry_point_phys: u64, context_id: u64) -> CpuOnOutcome {
    decode_cpu_on(cpu_on(target_cpu, entry_point_phys, context_id) as i64)
}

/// `PSCI_SYSTEM_OFF`: shut the system down. Does not return.
#[cfg(target_arch = "aarch64")]
pub fn system_off() -> ! {
    let _ = psci_call(PSCI_SYSTEM_OFF, 0, 0, 0);
    // PSCI promises SYSTEM_OFF never returns. If it does (broken
    // firmware) we park forever.
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

/// `PSCI_SYSTEM_RESET`: warm reboot. Does not return.
#[cfg(target_arch = "aarch64")]
pub fn system_reset() -> ! {
    let _ = psci_call(PSCI_SYSTEM_RESET, 0, 0, 0);
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

// ── B2-06: conduit auto-detection ───────────────────────────────────────────
//
// The hardcoded HVC default above is right for QEMU virt without
// `virtualization=on` (entry at EL1, no real EL2 — see
// `select_conduit_from_entry_el`), but wrong once the guest has a real
// EL2 above EL1: `HVC` from EL1 then traps to *our own* EL2, which has
// no VBAR_EL2 handler, and hangs (see `mmu/boot.rs`'s CPTR_EL2 comment for
// the sibling bug this wave also fixed). Linux avoids hardcoding
// either conduit at all — it reads the `/psci` node's `method`
// property out of the FDT the boot protocol hands it in x0. We do the
// same as the primary path, and fall back to an entry-EL heuristic
// only when there's no usable FDT.

/// Find the PSCI conduit from the `/psci` node's `method` property in
/// a flattened devicetree (`"hvc"` or `"smc"`), and apply it via
/// [`set_conduit`].
///
/// Every offset this walk touches is checked against the header's own
/// declared bounds — `size_dt_struct` for the struct walk, `size_dt_strings`
/// for property names, both in turn checked against `totalsize` — before it
/// is read via `[u8]::get`, never raw indexing — a truncated, corrupt, or
/// adversarial FDT just makes the lookup return `false` at the first bad
/// offset, never a panic or an out-of-bounds read. Node/property-name
/// lengths are additionally capped (`MAX_NAME_LEN`) so a blob that never
/// places a NUL can't turn the scan into an unbounded one, and node nesting
/// is capped (`MAX_DEPTH`) so a blob with no matching `END_NODE` can't
/// either.
///
/// Audited 2026-09-23 against the DTB parser's own adversarial checklist
/// (header/bounds consistency, unterminated nodes, property lengths past
/// the end, string-table offsets outside the strings block, depth,
/// arithmetic): every arithmetic step already used `checked_add`/
/// `checked_sub` and every read went through `.get()`, so no input can
/// panic or read out of bounds. The one real gap this audit closed: neither
/// `strings` nor the struct walk was bounded by the header's OWN
/// `size_dt_strings`/`size_dt_struct` fields (only by `totalsize`), so a
/// property's `nameoff` landing past the true strings block — but still
/// inside the blob — resolved against whatever bytes followed it instead of
/// failing closed. Not independently exploitable (the caller of this
/// function already controls the whole blob, so crafting a real `method`
/// property costs nothing extra over exploiting this), but it is a spec-
/// conformance gap this audit is specifically checking for, so it is
/// closed rather than left as a note.
///
/// Returns `true` iff a `method` property naming a conduit we
/// recognise (`"hvc"` / `"smc"`) was found under a node named `psci`
/// or `psci@...` and applied. `fdt_ptr == 0`, a bad magic, or any
/// malformed structure returns `false` — the caller is expected to
/// fall back to [`select_conduit_from_entry_el`] in that case.
///
/// # Safety
///
/// `fdt_ptr`, if nonzero, must be a physical address readable as
/// ordinary memory for at least 40 bytes (enough to find
/// `totalsize`), with the MMU off or identity-mapped over that range
/// — true during early aarch64 boot, before any stage-1 translation
/// is enabled.
#[cfg(target_arch = "aarch64")]
pub unsafe fn select_conduit_from_fdt(fdt_ptr: u64) -> bool {
    const FDT_MAGIC: u32 = 0xd00d_feed;
    const MAX_TOTAL_LEN: u32 = 4 * 1024 * 1024; // sanity cap; real DTBs are KBs
    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_NOP: u32 = 4;
    const FDT_END: u32 = 9;
    const MAX_DEPTH: usize = 24;
    const MAX_NAME_LEN: usize = 64;

    #[inline]
    fn be32(d: &[u8], off: usize) -> Option<u32> {
        let b = d.get(off..off.checked_add(4)?)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    // The NUL-terminated byte string starting at `d[0]`, capped at
    // `max_len`; `None` if there's no NUL within that window (covers
    // both "ran past the slice" and "ran past the sanity cap").
    fn cstr(d: &[u8], max_len: usize) -> Option<&[u8]> {
        let window = d.get(..max_len.min(d.len()))?;
        let end = window.iter().position(|&b| b == 0)?;
        Some(&window[..end])
    }

    // The actual struct-block walk, split out so it can use `?` for
    // every bounds check instead of threading `Option` by hand.
    fn find_method(data: &[u8], strings: &[u8], off_dt_struct: usize) -> Option<Conduit> {
        let mut off = off_dt_struct;
        let mut psci_depth = [false; MAX_DEPTH];
        let mut depth: usize = 0;

        loop {
            let tok = be32(data, off)?;
            off = off.checked_add(4)?;
            if tok == FDT_BEGIN_NODE {
                let name = cstr(data.get(off..)?, MAX_NAME_LEN)?;
                let is_psci = name.starts_with(b"psci") && matches!(name.get(4), None | Some(b'@'));
                off = off.checked_add(name.len())?.checked_add(1)?; // + NUL
                off = off.checked_add(3)? & !3; // 4-byte pad, per FDT spec
                if depth >= MAX_DEPTH {
                    return None; // pathologically deep — bail, don't panic
                }
                psci_depth[depth] = is_psci;
                depth += 1;
            } else if tok == FDT_END_NODE {
                depth = depth.checked_sub(1)?; // END_NODE with no matching BEGIN
            } else if tok == FDT_PROP {
                let len = be32(data, off)? as usize;
                let nameoff = be32(data, off.checked_add(4)?)? as usize;
                let data_start = off.checked_add(8)?;
                let prop_data = data.get(data_start..data_start.checked_add(len)?)?;
                off = data_start.checked_add(len)?;
                off = off.checked_add(3)? & !3;

                let in_psci = depth > 0 && psci_depth[depth - 1];
                if in_psci {
                    let pname = cstr(strings.get(nameoff..)?, MAX_NAME_LEN)?;
                    if pname == b"method" {
                        return match cstr(prop_data, prop_data.len())? {
                            b"hvc" => Some(Conduit::Hvc),
                            b"smc" => Some(Conduit::Smc),
                            _ => None, // unrecognised conduit name
                        };
                    }
                }
            } else if tok == FDT_NOP {
                // no-op token, nothing to advance beyond the tag itself
            } else {
                // FDT_END or any unknown token: no /psci method found
                return None;
            }
        }
    }

    if fdt_ptr == 0 || fdt_ptr & 0x3 != 0 {
        return false; // null, or misaligned for a spec-valid FDT
    }

    // Only the fixed 40-byte header is trusted ahead of a validated
    // `total_len`; every access after this point goes through
    // `find_method`'s bounds-checked `.get(..)` calls.
    let head = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, 40) };
    if be32(head, 0) != Some(FDT_MAGIC) {
        return false;
    }
    let total_len = match be32(head, 4) {
        Some(n) if (40..=MAX_TOTAL_LEN).contains(&n) => n as usize,
        _ => return false,
    };
    let off_dt_struct = match be32(head, 8) {
        Some(n) => n as usize,
        None => return false,
    };
    let off_dt_strings = match be32(head, 12) {
        Some(n) => n as usize,
        None => return false,
    };
    // `size_dt_strings`/`size_dt_struct` (header words 8/9, offsets 32/36 —
    // within the same 40-byte `head` already read above, so this costs no
    // extra memory access). Audited 2026-09-23: the walk below already
    // bounds-checks every read against `total_len`, so an over-long
    // struct/strings block could never cause an out-of-bounds read or a
    // panic — but without these two fields it also never enforced the
    // header's OWN declared block lengths, so `strings` reached from
    // `off_dt_strings` all the way to `total_len`, not to
    // `off_dt_strings + size_dt_strings`. A property's `nameoff` landing
    // past the true strings block (but still inside the blob) would then
    // resolve against whatever bytes follow it — struct-block bytes, the
    // memory reservation map, padding — instead of failing closed. Bounding
    // both blocks to their declared lengths closes that: a `nameoff`
    // outside `size_dt_strings` (or a struct walk past `size_dt_struct`)
    // now hits this function's existing `.get()` bounds check and returns
    // `None`, same as any other malformed offset.
    let size_dt_strings = match be32(head, 32) {
        Some(n) => n as usize,
        None => return false,
    };
    let size_dt_struct = match be32(head, 36) {
        Some(n) => n as usize,
        None => return false,
    };
    let strings_end = match off_dt_strings.checked_add(size_dt_strings) {
        Some(e) if e <= total_len => e,
        _ => return false,
    };
    let struct_end = match off_dt_struct.checked_add(size_dt_struct) {
        Some(e) if e <= total_len => e,
        _ => return false,
    };

    let data = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, total_len) };
    let strings = match data.get(off_dt_strings..strings_end) {
        Some(s) => s,
        None => return false,
    };
    // A prefix of `data`, not `data[off_dt_struct..struct_end]`: `off` inside
    // `find_method` is an offset from the START of `data` (it doubles as the
    // absolute blob offset the FDT spec's alignment padding is computed
    // against), so the slice passed in must keep that same base — only its
    // END needs tightening, from `total_len` down to `struct_end`.
    let struct_block = match data.get(..struct_end) {
        Some(s) => s,
        None => return false,
    };

    match find_method(struct_block, strings, off_dt_struct) {
        Some(c) => {
            set_conduit(c);
            true
        }
        None => false,
    }
}

/// Fallback conduit choice for when [`select_conduit_from_fdt`] found
/// nothing usable — no valid FDT pointer, or a `/psci` node without a
/// recognised `method` property.
///
/// QEMU virt's PSCI is emulated by QEMU itself, not by real EL3/EL2
/// firmware, and which conduit it services depends on whether the
/// guest was given an EL2 at all:
///   - No EL2 (`virtualization=on` not set — entry lands directly at
///     EL1): there's no real EL2 for `HVC` to trap to, so QEMU
///     intercepts it itself as the PSCI service call. → HVC (this is
///     also `set_conduit`'s own default, and the config every
///     existing gate row before this wave exercised).
///   - EL2 present (`virtualization=on` — entry at EL2, we drop to
///     EL1 via `boot::drop_to_el1`): `HVC` from EL1 is now a real
///     architectural trap to *our own* EL2, which has no handler —
///     see the CPTR_EL2 comment in `mmu/boot.rs` for the sibling failure
///     mode. QEMU's PSCI shim answers `SMC` instead in this
///     configuration. → SMC.
///
/// `entered_at_el2` must be captured by the caller at the very top of
/// `_start` (before `_azos_drop_to_el1` runs, which is the only
/// place `CurrentEL` still reads the boot-time value).
#[cfg(target_arch = "aarch64")]
pub fn select_conduit_from_entry_el(entered_at_el2: bool) {
    set_conduit(if entered_at_el2 { Conduit::Smc } else { Conduit::Hvc });
}

// ── Semihosting ──────────────────────────────────────────────────────────
//
// Arm semihosting, the one call the kernel makes: `SYS_EXIT` with a status.
//
// QEMU's aarch64 `virt` machine has no power-off device that carries a
// status (PSCI `SYSTEM_OFF` exits 0 whatever happened), so the ktest runner
// leaves through semihosting when Kconfig KTEST_SEMIHOSTING_EXIT is on.
// QEMU must run with `-semihosting-config enable=on,target=native`;
// without it `HLT #0xF000` is an undefined instruction at EL1.

/// End the emulator with exit status `code`. Does not return; if the call
/// comes back (a host that ignores it), park with interrupts masked.
#[cfg(target_arch = "aarch64")]
pub fn semihosting_exit(code: u32) -> ! {
    /// Semihosting operation `SYS_EXIT` (0x18; the Angel name, not a kernel syscall).
    const ANGEL_SYS_EXIT: u32 = 0x18;
    /// `ADP_Stopped_ApplicationExit`: the reason under which the subcode is
    /// the exit status (AArch64 takes a two-word parameter block).
    const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;
    let block: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, code as u64];
    // SAFETY: the semihosting trap reads the two-word block at x1 (a live
    // stack array) and, with semihosting on, ends the emulator.
    unsafe {
        core::arch::asm!("msr daifset, #0xf", "hlt #0xf000",
            in("w0") ANGEL_SYS_EXIT, in("x1") block.as_ptr(), options(nostack));
    }
    loop {
        // SAFETY: parks this CPU; interrupts are masked above.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}
