// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// RISC-V SBI (Supervisor Binary Interface) wrappers.
///
/// SBI provides a standardized interface between S-mode (our kernel)
/// and M-mode firmware (OpenSBI). All calls are made via `ecall`.
///
/// Ported from kernel/arch/riscv64/sbi/sbi.h

/// SBI return value: error code + value.
#[repr(C)]
pub struct SbiRet {
    pub error: isize,
    pub value: isize,
}

// ---- SBI Extension IDs ----

pub const EXT_BASE: usize = 0x10;
pub const EXT_TIME: usize = 0x5449_4D45; // "TIME"
pub const EXT_IPI: usize = 0x0073_5049; // "sPI"
pub const EXT_RFENCE: usize = 0x5246_4E43; // "RFNC"
pub const EXT_HSM: usize = 0x0048_534D; // "HSM"
pub const EXT_SRST: usize = 0x5352_5354; // "SRST"
pub const EXT_SUSP: usize = 0x5355_5350; // "SUSP"

// ---- Base Extension Function IDs ----

pub const BASE_GET_SPEC_VERSION: usize = 0;
pub const BASE_GET_IMPL_ID: usize = 1;
pub const BASE_GET_IMPL_VERSION: usize = 2;
pub const BASE_PROBE_EXTENSION: usize = 3;

// ---- Timer Extension ----

pub const TIME_SET_TIMER: usize = 0;

// ---- IPI Extension ----

pub const IPI_SEND: usize = 0;

// ---- RFENCE Extension ----

pub const RFENCE_I: usize = 0;
pub const RFENCE_SFENCE_VMA: usize = 1;
pub const RFENCE_SFENCE_VMA_ASID: usize = 2;

// ---- HSM Extension ----

pub const HSM_HART_START: usize = 0;
pub const HSM_HART_STOP: usize = 1;
pub const HSM_HART_GET_STATUS: usize = 2;
pub const HSM_HART_SUSPEND: usize = 3;

// ---- Standard SBI error codes ----

pub const ERR_FAILED: isize = -1;
pub const ERR_NOT_SUPPORTED: isize = -2;
pub const ERR_INVALID_PARAM: isize = -3;
pub const ERR_DENIED: isize = -4;
pub const ERR_INVALID_ADDRESS: isize = -5;

// ---- System suspend: the SUSP extension, to RAM ----
//
// `sbi_system_suspend(sleep_type, resume_addr, opaque)` (SBI 2.0) puts the
// machine in its sleep state with the calling hart the only one running (every
// other hart must be stopped). It does not return when it works: the hart
// restarts in S-mode at `resume_addr` (a physical address) with `a0` = its
// hart id, `a1` = `opaque`, `satp` = 0 and `sstatus.SIE` = 0, having lost its
// context. A return is therefore an error code. The kernel does not call it
// unless it has a resume address (`RESUME_ENTRY`) that restores the context
// saved before the call; none exists yet, which is the refusal the sequence
// (`azos_drv_power::pm::suspend`) reports as `NoResumeEntry`.

pub const SUSP_SYSTEM_SUSPEND: usize = 0;
/// `sleep_type` 0: suspend to RAM, the only one the specification defines.
pub const SLEEP_TYPE_SUSPEND_TO_RAM: u32 = 0;

/// `SUSP` exists from SBI 2.0 (the version register is `major << 24 | minor`).
pub const fn spec_has_system_suspend(spec_version: usize) -> bool {
    spec_version >= 2 << 24
}

/// The physical address `system_suspend` resumes the hart at: the trampoline
/// that restores `satp` and returns into the saved context. None yet.
pub const RESUME_ENTRY: Option<usize> = None;

/// Why the kernel cannot suspend the system on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemSuspendMissing {
    /// The firmware does not implement `SUSP`: an SBI older than 2.0, or one
    /// whose probe of the extension answered 0 (OpenSBI answers that when its
    /// platform has no system-suspend operation).
    Firmware(isize),
    /// The firmware has it and the kernel has no [`RESUME_ENTRY`].
    ResumeEntry,
}

/// Whether `SUSP` can be used, from what the firmware answers: `spec_version`
/// is the SBI version register (0 when the base call failed), `probe` yields
/// the extension probe (non-zero when present; asked only for SBI 2.0 and
/// later), and `entry` is the kernel's [`RESUME_ENTRY`]. The firmware's answer
/// comes first: a machine without the call needs no resume address.
pub fn system_suspend_available(
    spec_version: usize,
    probe: impl FnOnce() -> usize,
    entry: Option<usize>,
) -> Result<(), SystemSuspendMissing> {
    if !spec_has_system_suspend(spec_version) || probe() == 0 {
        return Err(SystemSuspendMissing::Firmware(ERR_NOT_SUPPORTED));
    }
    entry.map(|_| ()).ok_or(SystemSuspendMissing::ResumeEntry)
}

/// Ask the firmware (spec version, extension probe) whether the kernel can
/// suspend the system.
pub fn system_suspend_support() -> Result<(), SystemSuspendMissing> {
    system_suspend_available(get_spec_version(), || probe_extension(EXT_SUSP), RESUME_ENTRY)
}

/// `sbi_system_suspend` to RAM: the machine suspends and the hart resumes at
/// `resume_addr` with `opaque` in `a1`, so this returns only with the
/// firmware's error code. The caller has the other harts stopped and the
/// context saved.
pub fn system_suspend(resume_addr: usize, opaque: usize) -> isize {
    call(EXT_SUSP, SUSP_SYSTEM_SUSPEND, SLEEP_TYPE_SUSPEND_TO_RAM as usize, firmware_addr(resume_addr), opaque).error
}

// ---- SRST Extension ----

pub const SRST_SYSTEM_RESET: usize = 0;
pub const SRST_TYPE_SHUTDOWN: usize = 0;
pub const SRST_TYPE_COLD_REBOOT: usize = 1;

/// Low-level SBI ecall with up to 6 arguments.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn sbi_call(ext: usize, fid: usize, args: [usize; 6]) -> SbiRet {
    let error: isize;
    let value: isize;

    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") args[0] as isize => error,
            inlateout("a1") args[1] as isize => value,
            in("a2") args[2],
            in("a3") args[3],
            in("a4") args[4],
            in("a5") args[5],
            in("a6") fid,
            in("a7") ext,
        );
    }

    SbiRet { error, value }
}

/// Off riscv64 there is no firmware (`tests/host/arch-tests` includes this
/// file for the idle-state logic below): every call answers `NOT_SUPPORTED`,
/// which is what an SBI without the extension answers.
#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
pub fn sbi_call(_ext: usize, _fid: usize, _args: [usize; 6]) -> SbiRet {
    SbiRet { error: ERR_NOT_SUPPORTED, value: 0 }
}

/// Simplified SBI call with 0-3 arguments.
#[inline(always)]
fn call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> SbiRet {
    sbi_call(ext, fid, [a0, a1, a2, 0, 0, 0])
}

// ---- Base Extension APIs ----

/// Get SBI specification version.
pub fn get_spec_version() -> usize {
    let ret = call(EXT_BASE, BASE_GET_SPEC_VERSION, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Get SBI implementation ID.
pub fn get_impl_id() -> usize {
    let ret = call(EXT_BASE, BASE_GET_IMPL_ID, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Get SBI implementation version.
pub fn get_impl_version() -> usize {
    let ret = call(EXT_BASE, BASE_GET_IMPL_VERSION, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Probe if an extension is available (returns non-zero if available).
pub fn probe_extension(ext_id: usize) -> usize {
    let ret = call(EXT_BASE, BASE_PROBE_EXTENSION, ext_id, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

// ---- Timer Extension ----

/// Set the timer for the current hart.
#[inline(always)]
pub fn set_timer(stime_value: u64) {
    call(EXT_TIME, TIME_SET_TIMER, stime_value as usize, 0, 0);
}

// ---- IPI Extension ----

/// Send an IPI to logical CPU `cpu`: SBI names the hart by its hardware id
/// (`mhartid`), which `azos_percpu` maps (the id `tp` holds is the dense
/// logical one). `ERR_INVALID_PARAM` for a CPU the map does not have.
pub fn send_ipi(cpu: usize) -> isize {
    match azos_percpu::hw_id(cpu) {
        Some(hart) => call(EXT_IPI, IPI_SEND, 1, hart, 0).error,
        None => ERR_INVALID_PARAM,
    }
}

// ---- RFENCE Extension ----

/// Remote fence.i on specified harts (`hart_mask` / `hart_mask_base` are
/// hardware hart ids; `usize::MAX` as the base is every hart).
pub fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> isize {
    call(EXT_RFENCE, RFENCE_I, hart_mask, hart_mask_base, 0).error
}

/// Remote sfence.vma on specified harts (hardware hart ids, as above).
pub fn remote_sfence_vma(
    hart_mask: usize,
    hart_mask_base: usize,
    start_addr: usize,
    size: usize,
) -> isize {
    sbi_call(EXT_RFENCE, RFENCE_SFENCE_VMA,
        [hart_mask, hart_mask_base, start_addr, size, 0, 0]).error
}

/// SBI RFENCE `remote_sfence_vma_asid`: `sfence.vma` of `[start_addr,
/// start_addr + size)` tagged `asid` on the harts in the mask (waits for
/// them, like [`remote_sfence_vma`]; hardware hart ids).
pub fn remote_sfence_vma_asid(
    hart_mask: usize,
    hart_mask_base: usize,
    start_addr: usize,
    size: usize,
    asid: usize,
) -> isize {
    sbi_call(EXT_RFENCE, RFENCE_SFENCE_VMA_ASID,
        [hart_mask, hart_mask_base, start_addr, size, asid, 0]).error
}

/// [`remote_sfence_vma`] on the logical CPUs in `cpus` (bit `i` = CPU `i`, as
/// the shootdown's masks are): translated to the hardware hart ids the SBI
/// takes, one call per group of harts a mask word reaches
/// (`azos_percpu::for_each_hw_group`). The first error, 0 when all worked.
pub fn remote_sfence_vma_cpus(cpus: usize, start_addr: usize, size: usize) -> isize {
    let mut rc = 0;
    azos_percpu::for_each_hw_group(cpus, |mask, base| {
        let e = remote_sfence_vma(mask, base, start_addr, size);
        if rc == 0 {
            rc = e;
        }
    });
    rc
}

/// [`remote_sfence_vma_asid`] on the logical CPUs in `cpus`, as
/// [`remote_sfence_vma_cpus`].
pub fn remote_sfence_vma_asid_cpus(cpus: usize, start_addr: usize, size: usize, asid: usize) -> isize {
    let mut rc = 0;
    azos_percpu::for_each_hw_group(cpus, |mask, base| {
        let e = remote_sfence_vma_asid(mask, base, start_addr, size, asid);
        if rc == 0 {
            rc = e;
        }
    });
    rc
}

// ---- HSM Extension ----

/// The address the firmware must be handed for a kernel address: SBI takes
/// physical addresses of code (a hart's start, a resume entry), and a slid
/// image (Kconfig `KASLR`) runs at a virtual one. The identity otherwise.
#[inline]
fn firmware_addr(va: usize) -> usize {
    crate::mmu::kaslr::phys_of(va as u64) as usize
}

/// Start logical CPU `cpu` at the given address (a kernel address of the
/// image: the firmware gets its physical address). The SBI takes the hart's
/// hardware id (`azos_percpu::hw_id`; `ERR_INVALID_PARAM` when the map has no
/// such CPU) and hands the entry `a0` = that id and `a1` = `opaque`: the
/// kernel passes the logical id, which the entry puts in `tp`.
pub fn hart_start(cpu: usize, start_addr: usize, opaque: usize) -> isize {
    match azos_percpu::hw_id(cpu) {
        Some(hart) => call(EXT_HSM, HSM_HART_START, hart, firmware_addr(start_addr), opaque).error,
        None => ERR_INVALID_PARAM,
    }
}

/// Stop the current hart.
pub fn hart_stop() -> isize {
    call(EXT_HSM, HSM_HART_STOP, 0, 0, 0).error
}

/// Get the status of logical CPU `cpu`'s hart.
pub fn hart_get_status(cpu: usize) -> isize {
    let Some(hart) = azos_percpu::hw_id(cpu) else { return ERR_INVALID_PARAM };
    let ret = call(EXT_HSM, HSM_HART_GET_STATUS, hart, 0, 0);
    if ret.error == 0 { ret.value } else { ret.error }
}

// ---- A hart that stops and starts again (CPU hotplug) ----
//
// `hart_stop` ends the calling hart: it returns only with an error, and the
// hart is then `STOPPED` until another hart starts it. The kernel stops a hart
// through [`stop_current`], which keeps its context first, so a later
// `hart_start` at the secondary entry resumes it where it stopped (the
// saved-context path below) instead of booting it from nothing.

/// `hart_get_status` values (`HSM_STATE_*` of the SBI specification).
pub const HSM_STATE_STARTED: isize = 0;
pub const HSM_STATE_STOPPED: isize = 1;

/// The firmware can stop and start harts: any SBI that has HSM (0.2 on).
pub fn hart_stop_available() -> bool {
    probe_extension(EXT_HSM) != 0
}

/// Is logical CPU `cpu`'s hart stopped, as the firmware says?
pub fn hart_is_stopped(cpu: usize) -> bool {
    hart_get_status(cpu) == HSM_STATE_STOPPED
}

/// The finisher of a stop: `hart_stop` does not return when it works.
extern "C" fn finish_hart_stop(_arg: usize) -> isize {
    hart_stop()
}

/// Stop the calling hart, keeping its context. Returns [`RESUMED`] once a
/// `hart_start` has brought it back (it then runs on from this call), or the
/// firmware's error when the stop was refused (the hart never stopped).
///
/// # Safety
/// Interrupts masked, and nothing of this hart's may still be needed by the
/// others: its queues drained, its timers moved (`azos_sched::smp`).
pub unsafe fn stop_current() -> isize {
    // SAFETY: the caller's contract.
    unsafe { save_and_run(hart_now(), finish_hart_stop, 0) }
}

// ---- Deep idle: HSM hart_suspend, retentive and non-retentive ----
//
// `Cpu::cpu_idle(depth)` enters the platform's `depth`-th idle state (device
// tree `cpu-idle-states`, in order) with `hart_suspend(riscv,sbi-suspend-param)`.
// A RETENTIVE suspend (type bit 31 clear) keeps the hart's whole state: the
// ecall returns on a wake-up event and execution goes on after it, exactly as
// after a `wfi`. A NON-RETENTIVE one (bit 31 set) resumes at a firmware-called
// address with nothing but `a0 = hartid`, `a1 = opaque`, `satp = 0`: the hart
// keeps its context in its `SaveArea` first, and resumes at the secondary
// entry, which restores it (below). That needs the resume entry the kernel
// registers with [`set_resume`] (Kconfig `CPU_IDLE_POWERDOWN`); until it has,
// such a state is treated as absent, and the hart enters the deepest
// retentive state at or below the depth asked for, else `wfi`. A state with
// `local-timer-stop` stays absent either way: the hart's timer stops in it
// and nothing else wakes the hart for its own deadline.

/// Idle states per hart the ladder keeps: the device tree reader's
/// `cpu-idle-states` bound (`azos_dtb::DT_ENERGY_CPU_IDLE`).
pub const IDLE_DEPTHS: usize = 4;

/// `hart_suspend` exists from SBI 0.3 (the version register is
/// `major << 24 | minor`).
pub const fn spec_has_hart_suspend(spec_version: usize) -> bool {
    spec_version >= 3
}

/// The firmware implements `hart_suspend`: a new enough SBI that has HSM.
pub fn hart_suspend_available() -> bool {
    spec_has_hart_suspend(get_spec_version()) && probe_extension(EXT_HSM) != 0
}

/// Bit 31 of an HSM `suspend_type`: set = non-retentive.
pub const SUSPEND_NON_RETENTIVE: u32 = 1 << 31;

/// A `suspend_type` that keeps the hart's state: bit 31 clear (0 is the
/// default retentive suspend, `0x1000_0000..=0x7fff_ffff` are
/// platform-specific retentive ones).
pub const fn suspend_is_retentive(suspend_type: u32) -> bool {
    suspend_type & SUSPEND_NON_RETENTIVE == 0
}

/// HSM `hart_suspend` with a retentive `suspend_type`: returns the SBI error
/// code (0 once the hart has been woken). The resume address and opaque value
/// are ignored for a retentive suspend, so they are not parameters. A
/// non-retentive type is refused here, `ERR_INVALID_PARAM`, without a call:
/// entering one would resume the hart somewhere with its context gone.
pub fn hart_suspend_retentive(suspend_type: u32) -> isize {
    if !suspend_is_retentive(suspend_type) {
        return ERR_INVALID_PARAM;
    }
    call(EXT_HSM, HSM_HART_SUSPEND, suspend_type as usize, 0, 0).error
}

/// One `cpu-idle-states` entry, as far as entering it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspendState {
    /// `riscv,sbi-suspend-param`; `None` when the node has none.
    pub param: Option<u32>,
    /// `local-timer-stop`: the hart's timer stops in the state, and nothing
    /// here re-arms it from another source.
    pub local_timer_stop: bool,
}

impl SuspendState {
    /// The `suspend_type` this state can be entered with, or `None`: a state
    /// without a parameter, one that stops the local timer, and a
    /// non-retentive one are not entered.
    pub const fn enterable(&self) -> Option<u32> {
        match self.param {
            Some(p) if suspend_is_retentive(p) && !self.local_timer_stop => Some(p),
            _ => None,
        }
    }
}

impl SuspendState {
    /// The `suspend_type` of a state that is entered only through the resume
    /// entry: non-retentive, and not one that stops the timer.
    pub const fn enterable_with_resume(&self) -> Option<u32> {
        match self.param {
            Some(p) if !suspend_is_retentive(p) && !self.local_timer_stop => Some(p),
            _ => None,
        }
    }
}

/// What one `hart_suspend` return code means for the next idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspendOutcome {
    /// The hart slept and was woken.
    Slept,
    /// The call did not sleep, but may work next time (`DENIED`, `FAILED`):
    /// wait with `wfi` now.
    Transient,
    /// The firmware does not implement the call or refuses this type for
    /// good: wait with `wfi` now and never ask for it again.
    Unusable,
}

/// Classify a `hart_suspend` error code.
pub const fn classify_suspend(error: isize) -> SuspendOutcome {
    match error {
        0 => SuspendOutcome::Slept,
        ERR_NOT_SUPPORTED | ERR_INVALID_PARAM => SuspendOutcome::Unusable,
        _ => SuspendOutcome::Transient,
    }
}

/// One hart's idle states: which depths can be entered, and with what.
/// Written at boot (`install`) and by the hart itself when the firmware
/// refuses a type for good (`retire`); read on every idle entry.
pub struct IdleLadder {
    param: [core::sync::atomic::AtomicU32; IDLE_DEPTHS],
    /// Bit `d - 1` set: depth `d` is a retentive state, enterable with
    /// `param[d - 1]`. A separate mask because 0 is a valid parameter (the
    /// default retentive suspend).
    live: core::sync::atomic::AtomicU8,
    /// Bit `d - 1` set: depth `d` is a non-retentive state, enterable once
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
    /// non-retentive ones join them when [`set_resume`] is called, in any order.
    pub fn install(&self, states: &[SuspendState]) -> u8 {
        use core::sync::atomic::Ordering::{Relaxed, Release};
        let (mut live, mut deep) = (0u8, 0u8);
        for (i, s) in states.iter().take(IDLE_DEPTHS).enumerate() {
            if let Some(p) = s.enterable() {
                self.param[i].store(p, Relaxed);
                live |= 1 << i;
            } else if let Some(p) = s.enterable_with_resume() {
                self.param[i].store(p, Relaxed);
                deep |= 1 << i;
            }
        }
        self.deep.store(deep, Release);
        self.live.store(live, Release);
        live
    }

    /// The `suspend_type` to enter for `depth`: its own, else the deepest
    /// enterable one below it, else `None` (`wfi`).
    pub fn entry(&self, depth: u8) -> Option<u32> {
        self.entry_kind(depth).map(|(p, _)| p)
    }

    /// [`entry`](Self::entry) and whether the state is non-retentive (entered
    /// through the saved-context path).
    fn entry_kind(&self, depth: u8) -> Option<(u32, bool)> {
        use core::sync::atomic::Ordering::{Acquire, Relaxed};
        let top = (depth as usize).min(IDLE_DEPTHS);
        let deep = self.deep.load(Acquire);
        let live = self.live.load(Acquire);
        let usable = live | if resume_entry().is_some() { deep } else { 0 };
        (0..top).rev().find(|&i| usable & (1 << i) != 0).map(|i| (self.param[i].load(Relaxed), deep & (1 << i) != 0))
    }

    /// The depths that are non-retentive states the kernel can enter: bit `d - 1`
    /// for depth `d`, whether or not the resume entry is set yet. Their
    /// context is lost, so the energy model marks them
    /// (`azos_energy::PerfDomain::mark_context_loss`) and a CPU with
    /// real-time state is never put in one. A state that is not enterable at
    /// all (no parameter, `local-timer-stop`) is entered as a shallower one,
    /// so it is not here.
    pub fn powerdown_mask(&self) -> u8 {
        self.deep.load(core::sync::atomic::Ordering::Acquire)
    }

    /// The firmware refuses `suspend_type` for good: no depth uses it again.
    pub fn retire(&self, suspend_type: u32) {
        use core::sync::atomic::Ordering::{AcqRel, Relaxed};
        for i in 0..IDLE_DEPTHS {
            if (self.live.load(Relaxed) | self.deep.load(Relaxed)) & (1 << i) != 0
                && self.param[i].load(Relaxed) == suspend_type
            {
                self.live.fetch_and(!(1 << i), AcqRel);
                self.deep.fetch_and(!(1 << i), AcqRel);
            }
        }
    }

    /// Idle in `depth` through `suspend` (the firmware call for a retentive
    /// state, handed the `suspend_type`; a non-retentive one goes through
    /// [`hart_suspend_nonretentive`]). `true` when the hart slept and was
    /// woken; `false` when the caller still has to wait (no state for this
    /// depth, or the call returned without sleeping).
    pub fn enter(&self, depth: u8, suspend: impl FnOnce(u32) -> isize) -> bool {
        let Some((p, deep)) = self.entry_kind(depth) else { return false };
        let code = if deep { hart_suspend_nonretentive(p) } else { suspend(p) };
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

// ---- Saved context: a non-retentive suspend, a stopped hart ----
//
// A hart that loses its context (a non-retentive `hart_suspend`, or a stop
// the kernel will undo) leaves it in its slot (the table given to [`set_resume`]) and is started
// again at the SECONDARY entry (`_secondary_start`, `kernel/src/entry/riscv64/
// asm/boot.S`), the same symbol `hart_start` boots every secondary hart
// through: past its stack and trap vector, the entry asks
// [`resume_area`] for a slot to restore, and a hart without one goes
// on to `secondary_main` as before. Restoring is `azos_cpu_resume_restore`
// (`kernel/src/entry/riscv64/resume.rs`): `satp` (published for the TLB
// shootdown first, as the context switch does), `stvec`, `sscratch`,
// `sstatus`, then the registers the C calling convention keeps across a call
// and `sp`, and it returns [`RESUMED`] from `azos_cpu_save_run`.
//
// What is NOT kept, and so is redone by the resume hook ([`set_resume`]): the
// interrupt controller's per-hart state and the timer (the secondary start's
// `secondary_irq_init` and `secondary_timer_init`). The floating-point file is
// not touched: the kernel and every native task run with `sstatus.FS = Off`
// (`sched::fp`), and a Linux task's file is saved by the context switch.

/// What `azos_cpu_save_run` returns on the path that comes back through the
/// resume entry. No firmware error code equals it.
pub const RESUMED: isize = isize::MAX;

/// A hart's saved context (the C calling convention's callee-saved registers,
/// `gp`, `tp`, and the translation and trap CSRs). 8-byte fields in the order
/// `azos_cpu_save_run` stores them; the asm takes the offsets from here.
#[repr(C, align(16))]
pub struct SaveArea {
    /// 1 from before the context is saved until the resume entry takes it (or
    /// the call that saved it returns): the secondary entry restores a slot
    /// only when it is pending.
    pub pending: core::sync::atomic::AtomicU64,
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    /// The logical CPU id (`tp` holds it in the kernel).
    pub tp: u64,
    pub s: [u64; 12],
    pub satp: u64,
    pub stvec: u64,
    pub sscratch: u64,
    pub sstatus: u64,
}

impl SaveArea {
    pub const EMPTY: SaveArea = SaveArea {
        pending: core::sync::atomic::AtomicU64::new(0),
        ra: 0, sp: 0, gp: 0, tp: 0, s: [0; 12], satp: 0, stvec: 0, sscratch: 0, sstatus: 0,
    };
}

/// The resume entry, its hook and the slots, set once by the kernel at boot.
static RESUME_ADDR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
azos_common::ro_hook! {
    static RESUME_HOOK: fn(usize);
}
static SAVE_SLOTS: core::sync::atomic::AtomicPtr<SaveArea> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static SAVE_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The kernel has a resume entry: `entry` is the secondary entry's address
/// (what `hart_suspend` takes as the resume address), `hook` redoes the hart's
/// controller and timer state after a resume (given the hart id), and `slots`
/// points at one [`SaveArea`] per possible hart, `count` of them, owned by the
/// kernel (so they are linked only when the kernel asks for this path:
/// Kconfig `CPU_HOTPLUG`, `CPU_IDLE_POWERDOWN`). Boot CPU, before the idle
/// states are used.
///
/// # Safety
/// `slots` is valid for reads and writes of `count` areas for the life of the
/// kernel, and nothing else uses them.
pub unsafe fn set_resume(entry: usize, hook: fn(usize), slots: *mut SaveArea, count: usize) {
    use core::sync::atomic::Ordering::Release;
    SAVE_SLOTS.store(slots, Release);
    SAVE_COUNT.store(count, Release);
    RESUME_HOOK.set(hook);
    RESUME_ADDR.store(entry, Release);
}

/// The resume entry, once the kernel has set one.
pub fn resume_entry() -> Option<usize> {
    match RESUME_ADDR.load(core::sync::atomic::Ordering::Acquire) {
        0 => None,
        e => Some(e),
    }
}

/// `hart`'s slot, if the kernel gave one.
fn slot(hart: usize) -> Option<*mut SaveArea> {
    use core::sync::atomic::Ordering::Acquire;
    if hart < SAVE_COUNT.load(Acquire) {
        // SAFETY: `set_resume`'s contract: `count` areas from `slots`.
        Some(unsafe { SAVE_SLOTS.load(Acquire).add(hart) })
    } else {
        None
    }
}

/// The slot `hart` must restore, taken once (`pending` cleared), or null: the
/// secondary entry's question (`azos_cpu_resume_check`, `kernel/src/entry/
/// riscv64/resume.rs`, which boot.S calls). Called with the boot stack and the
/// trap vector in place, before any other kernel code of the hart has run.
pub fn resume_area(hart: usize) -> *mut SaveArea {
    match slot(hart) {
        // SAFETY: `slot` returned a valid area.
        Some(a) if unsafe { &(*a).pending }.swap(0, core::sync::atomic::Ordering::AcqRel) != 0 => a,
        _ => core::ptr::null_mut(),
    }
}

/// Keep this hart's context in its slot and call `finisher(arg)`. The finisher
/// is the firmware call that takes the hart away; it returns only on failure,
/// and its value is this function's. When the hart is started again at the
/// secondary entry the context is restored and this returns [`RESUMED`].
///
/// # Safety
/// Interrupts masked on the calling hart (this masks them itself on riscv64
/// and puts the mask back), `hart` is the calling hart's id, and a resume
/// entry is set.
unsafe fn save_and_run(hart: usize, finisher: extern "C" fn(usize) -> isize, arg: usize) -> isize {
    use core::sync::atomic::Ordering::{Release, Relaxed};
    let Some(area) = slot(hart) else { return ERR_INVALID_PARAM };
    let irq = irq_mask();
    // SAFETY: `slot` returned this hart's own area.
    unsafe { &(*area).pending }.store(1, Release);
    // SAFETY: `area` is this hart's own slot; the asm stores into it only.
    let r = unsafe { azos_cpu_save_run(area, finisher, arg) };
    // SAFETY: as above.
    unsafe { &(*area).pending }.store(0, Relaxed);
    if r == RESUMED {
        run_resume_hook(hart);
    }
    irq_restore(irq);
    r
}

fn run_resume_hook(hart: usize) {
    if let Some(f) = RESUME_HOOK.get() {
        f(hart);
    }
}

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_cpu_save_run(area: *mut SaveArea, finisher: extern "C" fn(usize) -> isize, arg: usize) -> isize;
}

/// Off riscv64 there is no hart to save: the host answers what a firmware
/// without the call answers.
#[cfg(not(target_arch = "riscv64"))]
unsafe fn azos_cpu_save_run(_: *mut SaveArea, _: extern "C" fn(usize) -> isize, _: usize) -> isize {
    ERR_NOT_SUPPORTED
}

/// The calling hart's id (`tp`); 0 on the host.
#[inline]
fn hart_now() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        crate::cpu::hart_id()
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        0
    }
}

/// Mask supervisor interrupts, returning the old `sstatus.SIE`.
#[inline]
fn irq_mask() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        let old: usize;
        // SAFETY: clears sstatus.SIE only.
        unsafe { core::arch::asm!("csrrci {}, sstatus, 2", out(reg) old, options(nomem, nostack)) };
        old & 2
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        0
    }
}

#[inline]
fn irq_restore(old: usize) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: sets sstatus.SIE back to what `irq_mask` found.
    unsafe {
        core::arch::asm!("csrs sstatus, {}", in(reg) old, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = old;
}

/// The extern finisher of a non-retentive suspend: `hart_suspend` with the
/// secondary entry as the resume address and the hart id as the opaque value.
/// It returns only when the firmware refused (a successful non-retentive
/// suspend resumes at the entry instead).
extern "C" fn finish_hart_suspend(suspend_type: usize) -> isize {
    let entry = firmware_addr(resume_entry().unwrap_or(0));
    call(EXT_HSM, HSM_HART_SUSPEND, suspend_type, entry, hart_now()).error
}

/// HSM `hart_suspend` with a non-retentive `suspend_type`: the hart keeps its
/// context, sleeps, and returns 0 once the resume entry has restored it. The
/// SBI error code when the firmware refused (the hart did not sleep). A
/// retentive type is refused here, `ERR_INVALID_PARAM`, and so is any type
/// while the kernel has no resume entry (`ERR_NOT_SUPPORTED`).
pub fn hart_suspend_nonretentive(suspend_type: u32) -> isize {
    if suspend_is_retentive(suspend_type) {
        return ERR_INVALID_PARAM;
    }
    if resume_entry().is_none() {
        return ERR_NOT_SUPPORTED;
    }
    // SAFETY: the interrupt mask is `save_and_run`'s; the hart id is the
    // calling hart's; the resume entry is set.
    match unsafe { save_and_run(hart_now(), finish_hart_suspend, suspend_type as usize) } {
        RESUMED => 0,
        err => err,
    }
}

// ---- SRST Extension ----

/// System reset (shutdown or reboot).
pub fn system_reset(reset_type: usize, reset_reason: usize) -> isize {
    call(EXT_SRST, SRST_SYSTEM_RESET, reset_type, reset_reason, 0).error
}

/// Shutdown the system.
#[cfg(target_arch = "riscv64")]
pub fn shutdown() -> ! {
    system_reset(SRST_TYPE_SHUTDOWN, 0);
    // Should not return, but just in case:
    loop { crate::cpu::wfi(); }
}

/// Reboot the system.
#[cfg(target_arch = "riscv64")]
pub fn reboot() -> ! {
    system_reset(SRST_TYPE_COLD_REBOOT, 0);
    loop { crate::cpu::wfi(); }
}
