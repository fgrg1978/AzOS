// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Resolve the energy model at boot (kernel feature `energy`) and
//! hand it to the scheduler.
//!
//! Sources, in order: the installed topology's `[energy.domain.*]` sections,
//! then the DTB's `operating-points-v2` / `idle-states`, then (x86_64) the
//! core types the CPUs report through CPUID, then (Raspberry Pi) the ARM
//! clock range the firmware reports, with placeholder power, then none
//! (`azos_energy::resolve`). A model that fails validation is refused with
//! a `[ENERGY] ... REFUSED` line and the machine runs with none; nothing in
//! stages E0–E2 acts on a model, so a refusal costs nothing and a halt would.
//! The mode is the topology's alone (invariant I5).
//!
//! With `system-suspend` (Kconfig `SYSTEM_SUSPEND`) it also installs the
//! platform the `power` endpoint's `suspend` runs on ([`KernelSuspend`]): the
//! firmware, the scheduler and the capability store behind the sequence of
//! `azos_drv_power::pm::suspend`.

use crate::*;

/// The topology's energy spec: the mode and the model it declares, if any.
fn topology_spec() -> azos_energy::EnergySpec {
    azos_topology::get()
        .map(|t| *t.energy())
        .filter(|_| !cfg!(feature = "energy-model-canary"))
        .unwrap_or(azos_energy::EnergySpec::DEFAULT)
}

/// Resolve, validate, report and install. After `install_topology`, before
/// the scheduler starts.
///
/// x86_64: a machine whose CPUs report core types (hybrid parts) and whose
/// topology declares no model is resolved later, once its APs are up
/// ([`install_energy_after_smp`]): CPUID answers for the CPU that runs it.
pub(crate) fn install_energy(num_cpus: usize, dtb_ptr: usize) {
    let spec = topology_spec();
    let dt = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_energy(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) }
    } else {
        None
    };
    match &dt {
        Some(d) => kprintln!(
            "[ENERGY] dtb: {} cpu node(s), {} OPP table(s), {} idle state(s){}",
            d.cpus().len(), d.tables().len(), d.idle_states().len(),
            if d.truncated { " (truncated)" } else { "" },
        ),
        None => kprintln!("[ENERGY] dtb: none readable"),
    }
    let from_dtb = dt.as_ref().and_then(|d| azos_energy::dt::from_dt(d, &super::smp::cpu_of_dt_reg));
    // arch-only: x86 hybrid cores (CPUID core types and the TSC rate).
    #[cfg(target_arch = "x86_64")]
    if from_dtb.is_none() && !spec.model.is_present() && num_cpus > 1 {
        // The boot CPU records its own core type now; the others do as they
        // come up. A part that reports none has nothing to wait for.
        if crate::entry::x86_64::ext::hybrid_energy::boot_cpu_reports_a_core_type() {
            kprintln!("[ENERGY] cpuid: the boot CPU reports a core type; the model waits for the other CPUs");
            CPUID_PENDING.store(true, core::sync::atomic::Ordering::Release);
        }
    }
    // arch-only: x86 hybrid cores (CPUID core types and the TSC rate).
    #[cfg(target_arch = "x86_64")]
    if CPUID_PENDING.load(core::sync::atomic::Ordering::Acquire) {
        #[cfg(feature = "system-suspend")]
        install_suspend();
        return;
    }
    let (model, r) = azos_energy::resolve(&spec.model, from_dtb, None, firmware_model(dtb_ptr, num_cpus), num_cpus);
    install_model(model, r, spec, dt.as_ref(), num_cpus);
    #[cfg(feature = "system-suspend")]
    install_suspend();
}

/// The model the board's firmware makes from its clock range: the Raspberry Pi's
/// (`rpi_mbox::energy_model`: it enables the mailbox and probes the ARM clock,
/// so it runs before the thermal runtime is built, which reads that probe).
/// Asked on every Pi even when the topology or the DTB has a model: the
/// thermal runtime needs the probe either way, and `resolve` takes the model
/// only when nothing before it in the order declared one.
// arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
#[cfg(all(target_arch = "aarch64", feature = "thermal", feature = "rpi-firmware", not(feature = "thermal-smoke")))]
fn firmware_model(
    dtb_ptr: usize,
    num_cpus: usize,
) -> Option<Result<azos_energy::EnergyModel, azos_energy::ModelFault>> {
    crate::entry::aarch64::ext::rpi_mbox::energy_model(dtb_ptr, num_cpus)
}

/// No other board reports a clock range to build a model from.
// arch-only: as the aarch64 one.
#[cfg(not(all(target_arch = "aarch64", feature = "thermal", feature = "rpi-firmware", not(feature = "thermal-smoke"))))]
fn firmware_model(_dtb_ptr: usize, _num_cpus: usize) -> Option<Result<azos_energy::EnergyModel, azos_energy::ModelFault>> {
    None
}

/// x86_64: the model a machine's CPUs make from their core types, once every
/// CPU that started has recorded its own (`azos_arch::ext::hybrid`). Boot CPU,
/// from `wake_secondaries`, with the secondaries **held** in their entry
/// (`entry/x86_64/smp.rs`, `ENERGY_RELEASE`): none of them has enabled
/// interrupts or entered the scheduler, so this is `azos_sched::energy::install`
/// at boot, before any other CPU runs it, as for every other source. Does
/// nothing unless [`install_energy`] found the boot CPU reporting a core type
/// and left the model for this.
///
/// `online` is the prefix of CPUs that started (what the scheduler places on);
/// the model covers those. A CPU of it that recorded nothing refuses the model
/// (a guessed class could send a task to the wrong kind of core), and the line
/// names the CPUs; one that did not start is not in the model, and the line says
/// how many the model leaves out.
// arch-only: x86 hybrid cores (CPUID core types and the TSC rate).
#[cfg(target_arch = "x86_64")]
pub(crate) fn install_energy_after_smp(num_cpus: usize, online: usize) {
    use crate::entry::x86_64::ext::hybrid_energy::{recorded_class, tsc_khz};
    if !CPUID_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let spec = topology_spec();
    if online < num_cpus {
        azos_drv_sys::kwarn!(
            "[ENERGY] cpuid: {} of {} CPUs started; the model covers CPUs 0..{}",
            online, num_cpus, online,
        );
    }
    let reports = azos_energy::EnergyModel::from_core_reports(online, tsc_khz(), recorded_class);
    if reports.missing != 0 {
        azos_drv_sys::kwarn!(
            "[ENERGY] cpuid: CPU mask {:#x} started but recorded no core type: no model (every CPU's type is needed)",
            reports.missing,
        );
    }
    let (model, r) = azos_energy::resolve(&spec.model, None, reports.model, None, online);
    install_model(model, r, spec, None, online);
}

/// [`install_energy`] left the model for [`install_energy_after_smp`].
// arch-only: x86 hybrid cores (CPUID core types and the TSC rate).
#[cfg(target_arch = "x86_64")]
static CPUID_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Report a resolved model and install it with the seams its mode selects.
fn install_model(
    model: azos_energy::EnergyModel,
    r: azos_energy::model::Resolution,
    spec: azos_energy::EnergySpec,
    dt: Option<&azos_dtb::DtEnergy>,
    num_cpus: usize,
) {
    if let Some(f) = r.topology_fault {
        azos_drv_sys::kwarn!("[ENERGY] topology model REFUSED: {:?} — running with no model", f);
    }
    if let Some(f) = r.dtb_fault {
        azos_drv_sys::kwarn!("[ENERGY] dtb model REFUSED: {:?} — running with no model", f);
    }
    if let Some(f) = r.cpuid_fault {
        azos_drv_sys::kwarn!("[ENERGY] cpuid model REFUSED: {:?} — running with no model", f);
    }
    if let Some(f) = r.firmware_fault {
        azos_drv_sys::kwarn!("[ENERGY] firmware model REFUSED: {:?} — running with no model", f);
    }
    if let (azos_energy::ModelSource::Dtb, Some(d)) = (model.source, dt) {
        // The model raised these residencies to the exit latency; the DTB is
        // wrong, and the log line is the record of it.
        for r in azos_energy::dt::residencies_raised(d) {
            azos_drv_sys::kwarn!(
                "[ENERGY] dtb idle state '{}' (phandle {:#x}): min-residency-us {} is below its exit latency {} us, raised to it",
                core::str::from_utf8(r.name()).unwrap_or("?"), r.phandle, r.min_residency_us, r.exit_latency_us,
            );
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let model = {
        let mut m = model;
        if let (azos_energy::ModelSource::Dtb, Some(d)) = (m.source, dt) {
            install_idle_states(&mut m, d, num_cpus);
        }
        m
    };
    #[cfg(target_arch = "x86_64")]
    let model = report_idle_ladder(model, spec.mode, num_cpus);
    let seams = azos_energy::Seams::select(&model, spec.mode);
    azos_sched::energy::install(model, spec.mode, seams);
    install_battery();
    let tracker = azos_sched::energy::TRACKER;
    kprintln!(
        "[ENERGY] mode={} model={} domains={} opps={} tracker={} step={} ticks seams={:?}/{:?}/{:?}",
        spec.mode.as_str(), model.source.as_str(), model.domains().len(), model.opp_count(),
        match tracker {
            azos_energy::UtilTracker::Window { .. } => "window",
            azos_energy::UtilTracker::Pelt { .. } => "pelt",
        },
        tracker.step(), seams.placement, seams.governor, seams.idle,
    );
    for (i, d) in model.domains().iter().enumerate() {
        let top = d.opps().last().copied().unwrap_or(azos_energy::Opp::EMPTY);
        kprintln!(
            "[ENERGY] domain {}: cpus={:#x} opps={} top={} kHz cap={} {} mW idle={}",
            i, d.cpus, d.opps().len(), top.freq_khz, top.capacity, top.power_mw, d.idle_states().len(),
        );
        if model.source == azos_energy::ModelSource::Firmware {
            // The table is the firmware's range on a grid, with power nobody
            // measured: the line says so and lists every step.
            kprintln!(
                "[ENERGY] domain {}: OPPs from the firmware's clock range, power is a PLACEHOLDER (unmeasured; a signed topology replaces it)",
                i,
            );
            for (k, o) in d.opps().iter().enumerate() {
                kprintln!("[ENERGY]   opp {}: {} kHz cap={} {} mW (placeholder)", k, o.freq_khz, o.capacity, o.power_mw);
            }
        }
    }
}

/// System suspend on the kernel's own machinery. Its steps are the sequence's
/// (`azos_drv_power::pm::suspend::run`); what each is made of here:
///
/// * `support`: the firmware's own answer (PSCI `FEATURES`, the SBI probe, the
///   FADT), then the kernel's resume entry, then the freezer. A machine that
///   lacks any of the three says which, and `suspend` is refused with a record.
/// * `online_cpus`: the percpu online mask. Both firmware calls need every
///   other CPU off. The sequence takes none off itself: with `CPU_HOTPLUG` the
///   caller takes them off first (`power cpu N offline`, `Rule::CpuHotplug`);
///   a machine with a second CPU still online refuses.
/// * `wake_sources`: the interrupt capabilities in the caller's table.
/// * `quiesce`: no kernel-hosted driver implements runtime PM; the ring-3 half
///   (`DevicePower::suspend` of each driver) is the power service's, before it
///   asks. So here there is nothing to take down and nothing to refuse.
/// * `save` / `restore`: interrupts off on this CPU, and back.
/// * `enter`: the firmware call, which comes back only with an error until a
///   resume entry exists to hand the CPU back.
/// * `clocks`: the monotonic clock, and no persistent one (no RTC driver), so
///   a sleep the counter did not count is not known and is not invented.
#[cfg(feature = "system-suspend")]
struct KernelSuspend;

#[cfg(feature = "system-suspend")]
static KERNEL_SUSPEND: KernelSuspend = KernelSuspend;

/// The interrupt state `save` found, for `restore` (one CPU is online while a
/// suspend runs, and one suspend at a time: the gate).
#[cfg(feature = "system-suspend")]
static SAVED_IRQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "system-suspend")]
impl KernelSuspend {
    /// Whether the scheduler can hold user tasks off the CPU. Not yet: the
    /// fused dispatch the kernel runs does not consult the stop class's
    /// per-CPU slot (`azos_sched::classes::set_stop_task`), and no pick path
    /// skips a frozen task. The freezer is a dispatch change, not a call.
    const HAS_FREEZER: bool = false;
}

#[cfg(feature = "system-suspend")]
impl azos_drv_power::pm::suspend::Platform for KernelSuspend {
    fn enabled(&self) -> bool {
        // The build has the feature: Kconfig kept it off robot, industrial and
        // automotive images.
        true
    }

    fn support(&self) -> Result<(), azos_drv_power::pm::suspend::Reason> {
        use azos_arch::firmware::{system_suspend_support, SystemSuspendMissing as Missing};
        use azos_drv_power::pm::suspend::Reason;
        match system_suspend_support() {
            Ok(()) if !Self::HAS_FREEZER => Err(Reason::NoFreezer),
            Ok(()) => Ok(()),
            #[cfg(not(target_arch = "x86_64"))]
            Err(Missing::ResumeEntry) => Err(Reason::NoResumeEntry),
            #[cfg(target_arch = "x86_64")]
            Err(Missing::NoAml) => Err(Reason::NoAcpiS3),
            Err(_) => Err(Reason::NoFirmware),
        }
    }

    fn online_cpus(&self) -> u32 {
        azos_percpu::online().weight() as u32
    }

    fn wake_sources(&self, caller: u32) -> u32 {
        let mut n = 0;
        // The predicate counts and never matches: the scan visits every
        // interrupt capability of the table.
        let _ = azos_ipc::cap_store::with_table(caller, |t| {
            t.lookup_where(azos_abi::cap::ty::IRQ, |_, _, _| {
                n += 1;
                false
            })
        });
        n
    }

    fn freeze(&self) -> Result<(), ()> {
        if Self::HAS_FREEZER { Ok(()) } else { Err(()) }
    }

    fn thaw(&self) {}

    fn quiesce(&self) -> Result<(), u32> {
        Ok(())
    }

    fn unquiesce(&self) -> u32 {
        0
    }

    fn save(&self) -> Result<(), ()> {
        use azos_arch::Interrupts;
        SAVED_IRQ.store(azos_arch::ARCH.disable_all().0, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn restore(&self) {
        use azos_arch::Interrupts;
        azos_arch::ARCH.restore(azos_arch_api::InterruptState(SAVED_IRQ.load(core::sync::atomic::Ordering::Relaxed)));
    }

    fn enter(&self) -> Result<(), i32> {
        enter_firmware()
    }

    fn clocks(&self) -> azos_drv_power::pm::suspend::Clocks {
        azos_drv_power::pm::suspend::Clocks {
            mono_ns: azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ),
            persistent_ns: None,
        }
    }

    fn add_boot_ns(&self, ns: u64) {
        azos_mm::vdso::vdso_add_suspended(ns);
    }

    fn record(&self, subject: u32, r: azos_drv_power::pm::suspend::Record) {
        use azos_drv_power::pm::suspend::{Reason, Verdict};
        azos_drv_power::pm::record(subject, &r);
        match r.verdict {
            Verdict::Admit => kprintln!("[PM] suspend: state {} (domain {})", r.state & 0xFF, subject),
            Verdict::Refuse => kprintln!(
                "[PM] suspend refused: {} (blockers {}, domain {}, recorded)",
                Reason::of(r.reason as u8).map_or("?", Reason::name), r.blockers, subject,
            ),
        }
    }
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("energy: no firmware suspend call for this ISA: a new ISA names its `enter_firmware` here");

/// The firmware call. A suspend that works resumes at the resume entry and
/// never returns from the call, so a return is an error code. There is no entry
/// yet (`support` refused before this), hence no `Ok`.
#[cfg(all(feature = "system-suspend", target_arch = "aarch64"))]
fn enter_firmware() -> Result<(), i32> {
    use azos_arch::firmware::{system_suspend, PSCI_NOT_SUPPORTED, RESUME_ENTRY};
    Err(RESUME_ENTRY.map_or(PSCI_NOT_SUPPORTED, |e| system_suspend(e, 0)))
}

#[cfg(all(feature = "system-suspend", target_arch = "riscv64"))]
fn enter_firmware() -> Result<(), i32> {
    use azos_arch::firmware::{system_suspend, ERR_NOT_SUPPORTED, RESUME_ENTRY};
    Err(RESUME_ENTRY.map_or(ERR_NOT_SUPPORTED as i32, |e| system_suspend(e, 0) as i32))
}

/// x86_64: S3 is a PM1a control write whose `SLP_TYP` the kernel cannot read
/// (no AML), so it is never attempted.
#[cfg(all(feature = "system-suspend", target_arch = "x86_64"))]
fn enter_firmware() -> Result<(), i32> {
    Err(-1)
}

/// Install the platform and report whether this machine can use it.
#[cfg(feature = "system-suspend")]
fn install_suspend() {
    use azos_drv_power::pm::suspend::Platform;
    azos_drv_power::pm::install(&KERNEL_SUSPEND);
    match KERNEL_SUSPEND.support() {
        Ok(()) => kprintln!("[ENERGY] system suspend: available"),
        Err(why) => kprintln!("[ENERGY] system suspend: not available ({})", why.name()),
    }
}

/// Hand the topology's `[degrade.NAME]` rows to the energy policy: the power
/// service reads them back from the kernel and the kernel checks what it
/// reports against them.
fn install_battery() {
    use azos_energy::policy::{DegradeRow, POLICY_DEGRADE_ROWS_MAX};
    let mut rows = [DegradeRow { level: 0, battery_pct: 0, clear_pct: 0 }; POLICY_DEGRADE_ROWS_MAX];
    let mut n = 0;
    if let Some(t) = azos_topology::get() {
        for (slot, d) in rows.iter_mut().zip(t.degrades()) {
            *slot = DegradeRow { level: d.level as u8, battery_pct: d.battery_pct, clear_pct: d.clear_pct };
            n += 1;
        }
    }
    azos_sched::energy::install_battery(&rows[..n]);
}

/// Give the arch idle seam (`Cpu::cpu_idle(depth)`) what enters each depth of a
/// DTB-built model: the `arm,psci-suspend-param` / `riscv,sbi-suspend-param` of
/// the state that depth is. The model took the idle states of each domain's
/// first CPU node (`azos_energy::dt`), so every CPU of the domain gets that
/// node's list: the depth the governor picks means the same state on all of
/// them. The domain's mask names logical CPUs, so the node is found by its
/// `reg` (`domain_first_cpu`), not by the mask's lowest bit. A
/// state the arch cannot enter (no parameter, `local-timer-stop`, context
/// lost) is entered as the deepest one below it, or `wfi`; the line says which
/// depths are entered as themselves. The depths that lose the CPU's context (a
/// power-down `CPU_SUSPEND`, a non-retentive `hart_suspend`) are marked in the
/// model, so the idle task keeps a CPU with real-time state out of them
/// (`azos_energy::idle::allowed`). x86_64 enters its idle states by `mwait`
/// hint, not from the DTB ([`report_idle_ladder`] checks the model against them).
#[cfg(not(target_arch = "x86_64"))]
fn install_idle_states(model: &mut azos_energy::EnergyModel, dt: &azos_dtb::DtEnergy, num_cpus: usize) {
    use azos_arch::firmware::SuspendState;
    const _: () = assert!(azos_arch::firmware::IDLE_DEPTHS == azos_dtb::DT_ENERGY_CPU_IDLE);
    for i in 0..model.domains().len() {
        let d = model.domains()[i];
        let Some(first) = azos_energy::dt::domain_first_cpu(dt, d.cpus, &super::smp::cpu_of_dt_reg) else { continue };
        let mut states = [SuspendState { param: None, local_timer_stop: false }; azos_dtb::DT_ENERGY_CPU_IDLE];
        let listed = &first.idle_states[..first.n_idle as usize];
        for (slot, ph) in states.iter_mut().zip(listed) {
            if let Some(s) = dt.idle_states().iter().find(|s| s.phandle == *ph) {
                *slot = SuspendState { param: s.suspend_param, local_timer_stop: s.local_timer_stop };
            }
        }
        let (mut entered, mut lost) = (0u8, 0u8);
        for cpu in (0..num_cpus.min(32)).filter(|c| d.cpus >> c & 1 != 0) {
            entered |= azos_arch::ARCH.install_idle_states(cpu, &states[..listed.len()]);
            lost |= azos_arch::ARCH.idle_powerdown_depths(cpu);
        }
        model.mark_context_loss(i, lost);
        kprintln!(
            "[ENERGY] domain {}: idle states entered as themselves: depths {:#06b} of {}, losing the context: {:#06b}",
            i, entered, listed.len(), lost,
        );
    }
}

/// x86_64: give the model its idle list from the `mwait` ladder, and cap the
/// depth `Cpu::cpu_idle(depth)` enters at the first one the model understates.
/// Depth `d` is the model's idle state `d` (state 0 is `hlt`) and the ladder's
/// `d`-th state.
///
/// x86 has no DTB `idle-states`, so the ladder is the only source of real exit
/// latencies and residencies: a domain the topology declares without an `idle`
/// table gets `[hlt, ladder..]` ([`azos_arch::cpu::idle::Ladder::model_state`]).
/// A domain whose topology does list idle states keeps them, and they are
/// checked: the idle governor bounds its choice by the model's exit latency
/// against a real-time deadline (I3), and a model that claims less than the
/// state needs would have it sleep past the deadline, so the arch does not
/// enter that depth.
///
/// The ladder cannot make a model by itself: OPPs and their power are not
/// readable on x86 (no cpufreq driver), so with no topology `[energy.domain.*]`
/// there is no model (but a hybrid part's core types, [`install_energy_after_smp`]), the
/// idle governor is not selected and the CPUs stay on `hlt`; the log says so. The idle governor also needs the topology's mode to
/// be `balanced` or `endurance` (invariant I5).
#[cfg(target_arch = "x86_64")]
fn report_idle_ladder(
    model: azos_energy::EnergyModel,
    mode: azos_energy::EnergyMode,
    num_cpus: usize,
) -> azos_energy::EnergyModel {
    let ladder = azos_arch::cpu::idle::ladder();
    kprintln!("[ENERGY] x86 idle: hlt + {} {:?} state(s)", ladder.states().len(), ladder.wait());
    for (i, s) in ladder.states().iter().enumerate() {
        kprintln!("[ENERGY]   depth {}: {} hint {:#04x} exit {} us residency {} us", i + 1, s.name, s.hint, s.exit_latency_us, s.target_residency_us);
    }
    if !model.is_present() {
        if !ladder.states().is_empty() {
            kprintln!("[ENERGY] x86 idle: no energy model (the topology declares no [energy.domain.*] with OPPs): the idle CPUs stay on hlt");
        }
        return model;
    }
    let model = seed_idle_from_ladder(model, ladder, num_cpus);
    if !ladder.states().is_empty() && matches!(mode, azos_energy::EnergyMode::Performance) {
        kprintln!("[ENERGY] x86 idle: mode performance keeps the idle CPUs on hlt (balanced or endurance selects the idle governor)");
    }
    for (i, d) in model.domains().iter().enumerate() {
        let mut claims = [0u32; azos_energy::model::MAX_IDLE_STATES];
        let listed = d.idle_states().len().saturating_sub(1);
        for (c, st) in claims.iter_mut().zip(d.idle_states().iter().skip(1)) {
            *c = st.exit_latency_us;
        }
        let ok = ladder.depth_within_claims(&claims[..listed]);
        if (ok as usize) < listed {
            azos_drv_sys::kwarn!(
                "[ENERGY] domain {} idle depth {} claims exit {} us, the {} state it enters needs more (I3): depth capped at {}",
                i, ok + 1, claims[ok as usize], ladder.pick(ok + 1).map_or("?", |s| s.name), ok,
            );
            azos_arch::cpu::idle::cap_depth(ok);
        }
    }
    model
}

/// Fill every domain of `model` that lists no idle state with the ladder's
/// `[hlt, ladder..]`. The result is validated; if it is refused the model is
/// returned as it was (the ladder is then unused, which costs power, not
/// latency) and the refusal is logged.
#[cfg(target_arch = "x86_64")]
fn seed_idle_from_ladder(
    model: azos_energy::EnergyModel,
    ladder: &azos_arch::cpu::idle::Ladder,
    num_cpus: usize,
) -> azos_energy::EnergyModel {
    if ladder.states().is_empty() {
        return model;
    }
    let mut seeded = azos_energy::EnergyModel::from_source(model.source);
    let mut n = 0;
    for d in model.domains() {
        let mut d = *d;
        if d.idle_states().is_empty() {
            for depth in 0..=ladder.states().len() as u8 {
                let (name, exit, residency) = ladder.model_state(depth);
                let _ = d.push_idle(azos_energy::IdleState::new(name.as_bytes(), exit, residency, 0));
            }
            n += 1;
        }
        let _ = seeded.push_domain(d);
    }
    if n == 0 {
        return model;
    }
    match seeded.validate(num_cpus) {
        Ok(()) => {
            kprintln!("[ENERGY] x86 idle: {} domain(s) take [hlt + {} ladder state(s)] as their idle list", n, ladder.states().len());
            seeded
        }
        Err(f) => {
            azos_drv_sys::kwarn!("[ENERGY] x86 idle list from the ladder REFUSED: {:?} — idle stays as the topology declared it", f);
            model
        }
    }
}
