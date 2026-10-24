// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The board's clock and the thermal framework's user: the board's
//! [`Runtime`], built at boot, and the kernel task that ticks it.
//!
//! The clock half is Kconfig `ENERGY`'s (kernel feature `energy`): the board
//! object that moves the clocks is built whenever the board has one, and the
//! task is the energy governor's apply step, with or without a thermal zone.
//! The zone half is Kconfig `THERMAL`'s (kernel feature `thermal`): the device
//! tree's `thermal-zones` (on x86_64, the package zone from Kconfig) and the
//! sensors they read. A build without `THERMAL`, or a board whose tree
//! declares no zone, gets a runtime with no zone over a board object that
//! reads no sensor (`azos_thermal::runtime::NoSensor`).
//!
//! # Board
//!
//! Which board object the runtime is given is a fact of the hardware the hwbus
//! bound, not a Kconfig choice:
//!
//! * **VisionFive 2** (`vf2`): the `sfctemp` sensor ([`attach_sfctemp`], from
//!   its hwbus probe) and the CPU clock over the SoC clock framework
//!   (`azos_thermal::soc::SocCpuClock`, built under the framework's lock for
//!   each tick). The clock is the one the first CPU node names; the rate read
//!   at boot is the ceiling the unmoved supply is known to carry.
//! * **SpacemiT K1** (`k1` with `soc-k1`): the five-channel `TSEN` block
//!   ([`attach_k1_tsensor`], from its hwbus probe), and for each cluster its
//!   clock (the K1 clock provider of the SoC frameworks) and its supply (a P1
//!   PMIC buck reached over the I2C master, `hwbus::PmicI2c`) moved together
//!   by `azos_thermal::k1::K1Opp`: the rail before the clock going up, the
//!   clock before the rail going down, the voltages from the device tree's
//!   `opp-microvolt`. The clusters are read from the tree once, at boot
//!   (`azos_thermal::k1_soc::k1_plan`); a cluster the tree does not wire
//!   completely is left alone and its caps are refused.
//! * **Raspberry Pi** (aarch64, `brcm,bcm2835-mbox`; Pi 5 included): the
//!   VideoCore mailbox is both the sensor and the ARM clock (bound by the
//!   hardware bus, Kconfig RPI_FIRMWARE, `rpi_mbox::attach`). The energy step enables it and
//!   probes the clock before it resolves the model (the Pi's OPP table is the
//!   firmware's range, `rpi_mbox::energy_model`); the clock is an actuator only
//!   if that probe found a range that can move (`RpiFirmware::probe_clock`:
//!   rate, minimum, maximum); otherwise the object is the sensor alone and the
//!   framework raises the level instead.
//! * **x86_64**: the package sensor `azos_thermal::x86_sensor` probes from
//!   CPUID (Intel `coretemp`, AMD Zen over SMN; `entry/x86_64/ext/thermal_hw.rs`
//!   holds the hardware access), paired with `azos_thermal::x86`: the CPU's own
//!   level request (Intel HWP, AMD CPPC, probed by `azos_arch::cpu::pstate`; a
//!   register of another CPU goes through the function-call IPI in
//!   `thermal_hw`) as the actuator, and RAPL's package energy as a meter shown
//!   in the introspection tree's `thermal/`. A CPU with a sensor and no level request refuses every
//!   cap, so heat raises the degrade level and, at the critical trip, requests
//!   the shutdown. x86 has no device tree (its second boot argument is the
//!   firmware start-info) and the signed topology declares no thermal zones, so
//!   the one zone, the package, is `azos_thermal::x86_sensor::package_zone` over
//!   Kconfig `THERMAL_X86_PASSIVE_C` / `THERMAL_X86_HOT_C` /
//!   `THERMAL_X86_CRITICAL_C` / `THERMAL_X86_POLL_MS` ([`install_x86`]). A
//!   machine with no such sensor (QEMU TCG, any hypervisor) is refused by the
//!   probe, with the reason in the boot line, and has no zone and no task.
//! * Anything else (QEMU): no sensor and no actuator, so no runtime is built
//!   and no task exists (invariant I4: nothing changes).
//!
//! The sensors (`sfctemp`, the K1's `TSEN`, the x86 package sensor) are
//! `THERMAL`'s alone; the clocks (the JH7110's CPU clock, the K1's clusters,
//! the Pi's ARM clock, the x86 level request) are there with `ENERGY`. The
//! Pi's mailbox is both, so it is bound with `ENERGY`.
//!
//! # The tick
//!
//! The task sleeps the zones' polling delay (`Runtime::poll_interval_ms`: the
//! passive delay while a trip is active; with no zone, until woken), is woken
//! early when the governor's choice for a domain changes
//! (`azos_sched::energy::apply_take`), and each time:
//!
//! 1. asks the energy governor seam what it wants per domain
//!    (`azos_sched::energy::domain_opp`, none while the governor is `Fixed`)
//!    and the real-time density admitted on the domain's most loaded hart
//!    (the I1 floor's input);
//! 2. ticks the runtime: read the zones that are due, cap by the heat, never
//!    below the deadline or safety floor, set the clock;
//! 3. answers each choice to the governor (`azos_sched::energy::gov_ack`:
//!    applied, capped, refused by the actuator, no actuator), which asserts
//!    that every choice for a domain the board can move is answered within
//!    Kconfig `ENERGY_APPLY_DEADLINE_MS`;
//! 4. leaves every new record of the framework's ring as a console line and a
//!    `Rule::Thermal` decision (a trip that fired, a domain the floors keep
//!    hot, a level raise or fall, a lost sensor, the shutdown request);
//! 5. on a latched critical trip, powers the machine off in order.
//!
//! The K1 moves a supply over I2C, which no spin lock may be held across
//! (Kconfig `LOCK_MAX_HOLD_US`; a voltage step is several transfers), so its
//! tick holds none: the runtime is taken out of [`STATE`] for the tick
//! (`thermal/status` says `ticking`), each clock operation takes the
//! frameworks' lock for itself, and the rail is driven by the P1 buck's own
//! read and write with the effect recorded first.
//!
//! The task runs on the lowest CPU outside `RCU_NOCBS_CPUS` and `isolcpus`,
//! as the reclaim task is placed, below the real-time band. It never touches
//! a timer a real-time task owns.
//!
//! The degrade level the framework settles on shows in `thermal/level` and on
//! the console; no channel carries a kernel-originated level to the power
//! service yet (see the Kconfig help of `THERMAL`).
//!
//! # QEMU row
//!
//! With `thermal-smoke` the board is [`azos_thermal::fake::FakeBoard`] over the
//! smoke's scripted temperature and one fixture zone, so the row can show
//! throttle, degrade record and recovery on a machine with no sensor
//! (`kernel/src/smokes/thermal_smoke.rs`).

#[cfg(all(feature = "vf2", feature = "thermal", not(feature = "soc")))]
compile_error!("THERMAL on the VisionFive 2 needs SOC_FRAMEWORKS: the CPU clock it moves is the frameworks'");

use azos_energy::model::MAX_DOMAINS;
use azos_energy::thermal::{Event, LOG_LEN};
use azos_sync::SpinLock;
use azos_thermal::runtime::{event_name, stance, Inputs, Runtime, Stance};

use crate::kprintln;

/// The board object the runtime ticks over. The hardware itself lives in the
/// statics below; this says which one.
enum Board {
    /// VisionFive 2: `sfctemp` (with `THERMAL`) and the CPU clock of the SoC
    /// frameworks. The clock is `None` when the tree names none the
    /// frameworks have (the sensor, the levels and the shutdown still work;
    /// every cap is refused and raises the level instead); without `THERMAL`
    /// there is no board then.
    #[cfg(all(feature = "vf2", feature = "soc"))]
    Jh7110 { clock: Option<(azos_soc::clk::Clk, u32)> },
    /// SpacemiT K1: the `TSEN` block, and per cluster a clock and a P1 buck.
    #[cfg(all(feature = "soc-k1", feature = "k1"))]
    K1 {
        /// Which clock, rail and OPP table each cluster has (`None`: left
        /// alone).
        plan: azos_thermal::k1_soc::K1Plan,
        /// Moves that left a rail above what its clock needs (see
        /// `azos_thermal::k1`): the throttle took effect, the supply did not
        /// follow. Shown in `thermal/board`.
        lagged: u32,
    },
    /// Raspberry Pi: the VideoCore mailbox.
    // arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
    // The gate row builds the fake board instead, and never constructs this one.
    #[cfg(all(target_arch = "aarch64", feature = "rpi-firmware"))]
    #[cfg_attr(feature = "thermal-smoke", allow(dead_code))]
    Rpi,
    /// x86_64: the probed package sensor (`None`: no `THERMAL`, or none the
    /// probe found), and the level request and energy meter the CPU has; the
    /// board object is built from them for each tick (`thermal_hw::board`).
    // arch-only: MSRs and CPUID are x86; the gate row builds the fake board instead
    // and never constructs this one.
    #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
    X86 { kind: Option<azos_thermal::x86_sensor::Kind>, pc: azos_thermal::x86::X86Pstate },
    /// QEMU gate row: a scripted temperature and a clock that remembers.
    #[cfg(feature = "thermal-smoke")]
    Fake(azos_thermal::fake::FakeBoard),
}

impl Board {
    const fn name(&self) -> &'static str {
        match self {
            #[cfg(all(feature = "vf2", feature = "soc"))]
            Board::Jh7110 { .. } => "jh7110",
            #[cfg(all(feature = "soc-k1", feature = "k1"))]
            Board::K1 { .. } => "k1",
            // arch-only: as the variant.
            #[cfg(all(target_arch = "aarch64", feature = "rpi-firmware"))]
            Board::Rpi => "rpi",
            // arch-only: as the variant.
            #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
            Board::X86 { .. } => "x86",
            #[cfg(feature = "thermal-smoke")]
            Board::Fake(_) => "fake",
            // A build with no board object (QEMU without the row)
            // has no variant to name; the state is never populated.
            #[allow(unreachable_patterns)]
            _ => "none",
        }
    }
}

struct State {
    rt: Runtime,
    board: Board,
    /// Records of the framework's ring already left as decisions.
    reported: u32,
    /// The degrade level last reported.
    level: u8,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(None);

/// The state is out of [`STATE`] for a tick (`tick_once`).
static TICKING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

// ── JH7110: the sensor ───────────────────────────────────────────────────────

/// Where the `sfctemp` window was mapped (0: no sensor bound).
#[cfg(all(feature = "vf2", feature = "thermal"))]
static SFCTEMP_BASE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The JH7110 temperature sensor over its mapped window.
#[cfg(all(feature = "vf2", feature = "thermal"))]
struct SfcTempMmio(usize);

#[cfg(all(feature = "vf2", feature = "thermal"))]
impl azos_thermal::jh7110::SfcTempBus for SfcTempMmio {
    fn read32(&mut self, off: usize) -> u32 {
        // SAFETY: the window `hwbus::map_window` mapped for the bound node.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
    }
    fn write32(&mut self, off: usize, v: u32) {
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, v) }
    }
    fn delay_us(&mut self, us: u32) {
        let end = azos_drv_sys::timebase::now()
            .saturating_add(us as u64 * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000 + 1);
        while azos_drv_sys::timebase::now() < end {
            core::hint::spin_loop();
        }
    }
}

/// The `sfctemp` node's probe: power the sensor up and let it convert, and
/// remember the window for the tick.
#[cfg(all(feature = "vf2", feature = "thermal"))]
pub(super) fn attach_sfctemp(base: usize) {
    azos_thermal::jh7110::SfcTemp::new(SfcTempMmio(base)).start();
    SFCTEMP_BASE.store(base, core::sync::atomic::Ordering::Release);
}

/// A cluster clock the frameworks cannot name: every request is refused, so
/// the runtime raises the level instead of running hot unannounced.
#[cfg(all(feature = "vf2", feature = "thermal"))]
struct NoClock;

#[cfg(all(feature = "vf2", feature = "thermal"))]
impl azos_thermal::jh7110::CpuClock for NoClock {
    fn set_cpu_khz(&mut self, _khz: u32) -> Result<(), azos_energy::opp::ActuateError> {
        Err(azos_energy::opp::ActuateError::Unsupported)
    }
}

// ── K1: the sensor ──────────────────────────────────────────────────────────

/// Where the `TSEN` window was mapped (0: no sensor bound).
#[cfg(all(feature = "soc-k1", feature = "thermal"))]
static K1_TSENSOR_BASE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The K1 temperature block over its mapped window.
#[cfg(all(feature = "soc-k1", feature = "thermal"))]
struct K1TsensorMmio(usize);

#[cfg(all(feature = "soc-k1", feature = "thermal"))]
impl azos_thermal::k1::K1TsensorBus for K1TsensorMmio {
    fn read32(&mut self, off: usize) -> u32 {
        // SAFETY: the window `hwbus::map_window` mapped for the bound node;
        // `off` is one of the block's word-aligned register offsets (below
        // 0x100).
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
    }
    fn write32(&mut self, off: usize, v: u32) {
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, v) }
    }
}

/// The `k1-tsensor` node's probe: start the block (refused when the window
/// answers nothing or does not hold the start sequence) and remember the
/// window for the tick.
#[cfg(all(feature = "soc-k1", feature = "thermal"))]
pub(super) fn attach_k1_tsensor(base: usize) -> Result<(), azos_thermal::k1::StartError> {
    azos_thermal::k1::K1Tsensor::new(K1TsensorMmio(base)).start()?;
    K1_TSENSOR_BASE.store(base, core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Busy-wait `us` microseconds: the rail's ramp, between the rail write and
/// the clock that needs it.
#[cfg(all(feature = "soc-k1", feature = "k1"))]
fn busy_delay_us(us: u32) {
    let end = azos_drv_sys::timebase::now()
        .saturating_add(us as u64 * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000 + 1);
    while azos_drv_sys::timebase::now() < end {
        core::hint::spin_loop();
    }
}

/// The clock framework for the K1 actuator: each operation takes the
/// frameworks' lock for itself (a register access or two) and releases it, so
/// the rail's I2C transfers between two clock operations run with none held.
#[cfg(all(feature = "soc-k1", feature = "k1"))]
struct LockedClocks;

#[cfg(all(feature = "soc-k1", feature = "k1"))]
impl azos_thermal::k1_soc::K1Clocks for LockedClocks {
    fn rate(&mut self, clk: azos_soc::clk::Clk) -> Result<u64, azos_soc::Error> {
        super::soc::with(|_fdt, soc, bus, _fx| soc.clocks.rate(bus, clk)).unwrap_or(Err(azos_soc::Error::NoProvider))
    }
    fn round_rate(&mut self, clk: azos_soc::clk::Clk, hz: u64) -> Result<u64, azos_soc::Error> {
        super::soc::with(|_fdt, soc, bus, _fx| soc.clocks.round_rate(bus, clk, hz)).unwrap_or(Err(azos_soc::Error::NoProvider))
    }
    fn set_rate(&mut self, clk: azos_soc::clk::Clk, hz: u64) -> Result<u64, azos_soc::Error> {
        super::soc::with(|_fdt, soc, bus, fx| soc.clocks.set_rate(bus, fx, clk, hz)).unwrap_or(Err(azos_soc::Error::NoProvider))
    }
}

// ── Construction ────────────────────────────────────────────────────────────

/// Build the board's runtime over the model the energy step resolved: with
/// `THERMAL`, over the zones of the device tree at `dtb_ptr` (x86_64: the
/// package zone from Kconfig); with none, or without `THERMAL`, a runtime
/// with no zone, for the board's clock alone. After `install_energy` and
/// after the hwbus probes. Does nothing, and says why, on a board with
/// neither a zone nor a clock to move.
pub(crate) fn install(dtb_ptr: usize) {
    let model = azos_sched::energy::model();
    #[cfg(feature = "thermal-smoke")]
    {
        let _ = dtb_ptr;
        // The boot OPP is left unknown (a clock the firmware left where it
        // pleased), so the first request of the governor always reaches the
        // fake clock, whichever OPP it names.
        let rt = Runtime::new(azos_thermal::fake::fixture(model));
        let board = Board::Fake(azos_thermal::fake::FakeBoard::new(crate::smokes::thermal_smoke::temp));
        publish(rt, board, "fixture zone, scripted temperature");
    }
    // arch-only: x86_64 has no device tree; its zone comes from Kconfig.
    #[cfg(all(not(feature = "thermal-smoke"), target_arch = "x86_64"))]
    {
        let _ = dtb_ptr;
        install_x86(model);
    }
    #[cfg(all(not(feature = "thermal-smoke"), not(target_arch = "x86_64")))]
    {
        let dt = zones_of(dtb_ptr);
        let Some((rt, r, board)) = board_runtime(dt.as_ref(), model, dtb_ptr) else {
            match &dt {
                Some(dt) => kprintln!("[THERMAL] no sensor and clock pair for this board: {} zone(s) in the tree unused", dt.zones().len()),
                None => kprintln!("[THERMAL] no zone and no clock this board can move: no task"),
            }
            return;
        };
        if let Some(r) = &r {
            report_tree(r);
        }
        publish(rt, board, if r.is_some() { "device tree" } else { "no zone: the governor's clock alone" });
    }
}

/// The device tree's thermal zones at `dtb_ptr`, CPUs renumbered to the
/// logical ones; `None` (and why, on the console) when there is no tree, it
/// cannot be read or it declares no zone.
#[cfg(all(feature = "thermal", not(feature = "thermal-smoke"), not(target_arch = "x86_64")))]
fn zones_of(dtb_ptr: usize) -> Option<azos_dtb::DtThermal> {
    if dtb_ptr == 0 {
        kprintln!("[THERMAL] no device tree: no thermal zone");
        return None;
    }
    // SAFETY: the firmware's blob, parsed before by `early_main`.
    let dt = unsafe { azos_dtb::dtb_thermal(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) };
    let Some(mut dt) = dt else {
        kprintln!("[THERMAL] the device tree is not readable: no thermal zone");
        return None;
    };
    // A cooler names a CPU node; the model's masks name logical CPUs.
    azos_thermal::dt::cpus_by_logical(&mut dt, &super::smp::cpu_of_dt_reg);
    if dt.zones().is_empty() {
        kprintln!("[THERMAL] the device tree declares no thermal zone");
        return None;
    }
    Some(dt)
}

/// Without `THERMAL` no zone is read.
#[cfg(all(not(feature = "thermal"), not(target_arch = "x86_64")))]
fn zones_of(_dtb_ptr: usize) -> Option<azos_dtb::DtThermal> {
    None
}

/// The runtime over the zones of `dt`, or with no zone when there is none;
/// each domain's boot OPP from `boot_khz`. The report says what the tree had
/// that could not be used (`None`: no tree was read).
// arch-only: every x86_64 build has a board that can call it (the PC); an
// aarch64 build with the Raspberry Pi firmware, a riscv64 build with the
// VisionFive 2 or the K1.
#[cfg(all(
    not(feature = "thermal-smoke"),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", feature = "rpi-firmware"),
        all(feature = "vf2", feature = "soc"),
        all(feature = "soc-k1", feature = "k1")
    )
))]
fn runtime(
    dt: Option<&azos_dtb::DtThermal>,
    model: &azos_energy::EnergyModel,
    boot_khz: impl Fn(usize) -> Option<u32>,
) -> (Runtime, Option<azos_thermal::runtime::Report>) {
    match dt {
        Some(dt) => {
            let (rt, r) = Runtime::from_dt(dt, model, boot_khz);
            (rt, Some(r))
        }
        None => {
            let mut rt = Runtime::new(azos_energy::thermal::Thermal::new());
            rt.assume_boot(model, boot_khz);
            (rt, None)
        }
    }
}

/// x86_64: with `THERMAL`, probe the package sensor from CPUID and build its
/// zone from Kconfig; pair it (or, with no sensor, nothing) with the level
/// request and the energy meter the CPU has.
// arch-only: MSRs and CPUID are x86.
#[cfg(all(not(feature = "thermal-smoke"), target_arch = "x86_64"))]
fn install_x86(model: &azos_energy::EnergyModel) {
    use azos_thermal::x86::{boot_khz, Perf, X86Pstate};
    use crate::entry::x86_64::ext::thermal_hw;
    #[cfg(feature = "thermal")]
    let zone = package_zone(model);
    #[cfg(not(feature = "thermal"))]
    let zone: Option<(azos_thermal::x86_sensor::Kind, azos_dtb::DtThermal)> = None;
    let hw = thermal_hw::pstate_hw();
    kprintln!("[THERMAL] x86: level request {:?}, energy meter {:?}", hw.perf, hw.meter);
    // The level request is carried out for an OPP of the energy model: a
    // domain with one OPP (the CPUID model of a hybrid part) cannot be capped
    // and a machine with no model has no domain, so no request would ever be
    // made. Say so rather than leave a working actuator silently unused.
    let movable = model.domains().iter().any(|d| d.opps().len() >= 2);
    if hw.perf != Perf::None && !movable {
        azos_drv_sys::kwarn!(
            "[THERMAL] x86: the CPU takes level requests, but the energy model ({}) has no domain with two OPPs: no cap or governor request will be made (declare [energy.domain.*] OPPs in the topology)",
            model.source.as_str(),
        );
    }
    if zone.is_none() && (hw.perf == Perf::None || !movable) {
        kprintln!("[THERMAL] x86: no zone and no clock to move: no task");
        return;
    }
    let (kind, dt) = zone.unzip();
    // The clock the firmware left: the whole range of the part, which is each
    // domain's fastest OPP and what a cap is lifted back to.
    let (rt, r) = runtime(dt.as_ref(), model, |d| boot_khz(hw, model, d));
    if let Some(r) = &r {
        report_tree(r);
    }
    let source = if kind.is_some() { "Kconfig trips" } else { "no zone: the governor's clock alone" };
    publish(rt, Board::X86 { kind, pc: X86Pstate::new(hw, model) }, source);
}

/// x86_64: the package sensor the CPU has and its zone, from Kconfig
/// `THERMAL_X86_PASSIVE_C` / `THERMAL_X86_HOT_C` / `THERMAL_X86_CRITICAL_C` /
/// `THERMAL_X86_POLL_MS`; `None` (and why) when the probe finds none or the
/// trips are out of order.
// arch-only: MSRs and CPUID are x86.
#[cfg(all(feature = "thermal", not(feature = "thermal-smoke"), target_arch = "x86_64"))]
fn package_zone(model: &azos_energy::EnergyModel) -> Option<(azos_thermal::x86_sensor::Kind, azos_dtb::DtThermal)> {
    use crate::entry::x86_64::ext::thermal_hw;
    let kind = match thermal_hw::probe() {
        Ok(kind) => kind,
        Err(why) => {
            kprintln!("[THERMAL] x86: no temperature sensor: {}", why.name());
            return None;
        }
    };
    let (passive, hot, crit, poll) = (
        azos_limits::THERMAL_X86_PASSIVE_C as u32,
        azos_limits::THERMAL_X86_HOT_C as u32,
        azos_limits::THERMAL_X86_CRITICAL_C as u32,
        azos_limits::THERMAL_X86_POLL_MS as u32,
    );
    let Some(dt) = azos_thermal::x86_sensor::package_zone(model, passive, hot, crit, poll) else {
        kprintln!(
            "[THERMAL] x86: THERMAL_X86_PASSIVE_C {} < THERMAL_X86_HOT_C {} < THERMAL_X86_CRITICAL_C {} does not hold: no zone",
            passive, hot, crit,
        );
        return None;
    };
    Some((kind, dt))
}

/// Report the runtime and park it for the task.
fn publish(rt: Runtime, board: Board, source: &str) {
    kprintln!(
        "[THERMAL] board={} zones={} ({}) poll={} ms opps known={}",
        board.name(),
        rt.thermal.zones().len(),
        source,
        rt.poll_interval_ms().unwrap_or(0),
        (0..MAX_DOMAINS).filter(|&d| rt.dvfs.current(d).is_some()).count(),
    );
    *STATE.lock() = Some(State { rt, board, reported: 0, level: 0 });
}

/// The runtime for the hardware that is bound, if any: over the zones of
/// `dt` when the board's sensor is bound (`THERMAL`), else with no zone when
/// the board has a clock to move (x86_64 builds its runtime in
/// [`install_x86`]).
#[cfg(all(not(feature = "thermal-smoke"), not(target_arch = "x86_64")))]
fn board_runtime(
    dt: Option<&azos_dtb::DtThermal>,
    model: &azos_energy::EnergyModel,
    // Read by the K1 board only (its clusters come from the tree again).
    #[cfg_attr(not(all(feature = "soc-k1", feature = "k1")), allow(unused_variables))] dtb_ptr: usize,
) -> Option<(Runtime, Option<azos_thermal::runtime::Report>, Board)> {
    #[cfg(all(feature = "vf2", feature = "soc"))]
    {
        #[cfg(feature = "thermal")]
        let sensed = SFCTEMP_BASE.load(core::sync::atomic::Ordering::Acquire) != 0;
        #[cfg(not(feature = "thermal"))]
        let sensed = false;
        // The cluster clock and the rate it runs at: the ceiling the unmoved
        // supply carries, and the OPP the heat restores.
        let clock = super::soc::with(|fdt, soc, bus, _fx| {
            let clk = azos_thermal::soc::cpu_clock(fdt, &soc.clocks)?;
            let khz = u32::try_from(soc.clocks.rate(bus, clk).ok()? / 1000).ok()?;
            Some((clk, khz))
        })
        .flatten();
        let dt = dt.filter(|_| sensed);
        if dt.is_some() || clock.is_some() {
            if clock.is_none() {
                azos_drv_sys::kwarn!("[THERMAL] jh7110: no CPU clock the frameworks can move: caps will be refused");
            }
            let (rt, r) = runtime(dt, model, |d| clock.filter(|_| d == 0).map(|(_, khz)| khz));
            return Some((rt, r, Board::Jh7110 { clock }));
        }
    }
    #[cfg(all(feature = "soc-k1", feature = "k1"))]
    {
        #[cfg(feature = "thermal")]
        let sensed = K1_TSENSOR_BASE.load(core::sync::atomic::Ordering::Acquire) != 0;
        #[cfg(not(feature = "thermal"))]
        let sensed = false;
        let dt = dt.filter(|_| sensed);
        let planned = k1_plan(dtb_ptr, model).filter(|(p, _)| p.wires.iter().any(Option::is_some));
        if dt.is_some() || planned.is_some() {
            // No frameworks, or a tree the plan cannot be read from: the
            // sensor still protects the silicon (the critical trip), with no
            // clock to move; every cap is refused and raises the level instead.
            let (plan, boot) = planned.unwrap_or_default();
            let boot = |d: usize| boot.get(d).copied().flatten();
            let (rt, r) = match dt {
                Some(dt) => {
                    let (rt, r) = azos_thermal::k1::runtime_from_dt(dt, model, boot);
                    (rt, Some(r))
                }
                None => runtime(None, model, boot),
            };
            return Some((rt, r, Board::K1 { plan, lagged: 0 }));
        }
    }
    // arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
    #[cfg(all(target_arch = "aarch64", feature = "rpi-firmware"))]
    if let Some(built) = crate::entry::aarch64::ext::rpi_mbox::with(|fw| {
        // The ARM clock moves only if the energy step's probe found a range
        // that can move (`rpi_mbox::energy_model`): the Pi 5 and the other
        // boards give one, an emulated property channel (QEMU `raspi`) does
        // not, and then the object is the sensor alone and every cap is
        // refused (the level rises instead). With no zone and no such range
        // there is nothing to do.
        let clock = fw.clock();
        if dt.is_none() && clock.is_none() {
            return None;
        }
        match clock {
            Some(c) => kprintln!("[THERMAL] rpi: ARM clock {}..{} kHz", c.min_hz / 1000, c.max_hz / 1000),
            None => azos_drv_sys::kwarn!("[THERMAL] rpi: no ARM clock range the firmware lets us move: caps will be refused"),
        }
        let boot = fw.arm_khz();
        if boot.is_none() {
            azos_drv_sys::kwarn!("[THERMAL] rpi: the firmware did not report the ARM clock: it will not be restored after the heat");
        }
        Some(runtime(dt, model, |d| boot.filter(|_| d == 0)))
    })
    .flatten()
    {
        let (rt, r) = built;
        return Some((rt, r, Board::Rpi));
    }
    let _ = (dt, model);
    None
}

/// The K1's clusters as the tree and the frameworks describe them, and the
/// clock each runs at now (kHz, per domain of `model`; `None` for a cluster
/// that is left alone or whose clock cannot be read). Says on the console what
/// would otherwise leave the board doing nothing without a word: no energy
/// model, a cluster the tree does not wire completely, OPPs of the model that
/// have no row in the tree's table.
///
/// Only brief register reads happen under the frameworks' lock here; the
/// P1 buck is not touched (the plan keeps a copy of it and the tick drives it
/// with no lock held; its always-on pin was taken earlier, by
/// `soc::pin_pmic_always_on`).
#[cfg(all(not(feature = "thermal-smoke"), feature = "soc-k1", feature = "k1"))]
fn k1_plan(dtb_ptr: usize, model: &azos_energy::EnergyModel) -> Option<(azos_thermal::k1_soc::K1Plan, [Option<u32>; azos_thermal::k1::MAX_K1_DOMAINS])> {
    // SAFETY: the firmware's blob, parsed before by `early_main`.
    let energy = unsafe { azos_dtb::dtb_energy(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) }?;
    if model.domains().is_empty() {
        azos_drv_sys::kwarn!(
            "[THERMAL] k1: no energy model (the tree gives no usable one and the topology no rows): no cluster to move, the sensor still guards the critical trip"
        );
    }
    super::soc::with(|fdt, soc, bus, _fx| {
        let plan = azos_thermal::k1_soc::k1_plan(fdt, &energy, model, &soc.clocks, &soc.regulators);
        let mut boot = [None; azos_thermal::k1::MAX_K1_DOMAINS];
        for (d, w) in plan.wires.iter().enumerate() {
            boot[d] = w.and_then(|w| soc.clocks.rate(bus, w.clk).ok()).and_then(|hz| u32::try_from(hz / 1000).ok());
        }
        if plan.left_out != 0 {
            azos_drv_sys::kwarn!(
                "[THERMAL] k1: {} cluster(s) not wired completely (clock, a P1 buck behind cpu-supply, OPP table): left alone, their caps are refused",
                plan.left_out,
            );
        }
        for (d, n) in plan.unmatched.iter().enumerate() {
            if *n != 0 {
                azos_drv_sys::kwarn!(
                    "[THERMAL] k1: cluster {}: {} OPP(s) of the energy model have no row in the tree's table (another frequency, or over the rail): requests for them are refused",
                    d, n,
                );
            }
        }
        (plan, boot)
    })
}

#[cfg(not(feature = "thermal-smoke"))]
fn report_tree(r: &azos_thermal::runtime::Report) {
    if r.zones_dropped != 0 || r.trips_dropped != 0 || r.coolers_dropped != 0 || r.truncated {
        azos_drv_sys::kwarn!(
            "[THERMAL] tree: {} zone(s) kept; dropped {} zone(s), {} trip(s), {} cooling device(s){}",
            r.zones, r.zones_dropped, r.trips_dropped, r.coolers_dropped, if r.truncated { " (truncated)" } else { "" },
        );
    }
}

// ── The tick ────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

/// What the governor seam wants and the real-time ledger holds, per domain.
fn inputs(model: &azos_energy::EnergyModel) -> Inputs {
    use azos_sched::energy::{domain_admitted_ppm, domain_opp, policy_state, OPP_BOOT};
    let mut inp = Inputs::IDLE;
    // A governor that is not `Fixed` names an OPP; `Fixed` names none, and a
    // stale answer from before it was set back is not one.
    let governed = policy_state(azos_abi::power::POLICY_STATE_GOVERNOR).is_some_and(|g| g != azos_abi::power::POLICY_GOV_FIXED);
    for dom in 0..model.domains().len().min(MAX_DOMAINS) {
        inp.want[dom] = match domain_opp(dom) {
            OPP_BOOT => None,
            o if governed => Some(o as usize),
            _ => None,
        };
        inp.admitted_ppm[dom] = domain_admitted_ppm(dom);
    }
    inp
}

/// What a board's tick has to say beyond the settled state: the K1 reports a
/// move that left a rail above what its clock needs.
#[cfg(all(feature = "soc-k1", feature = "k1"))]
type Note = Option<azos_thermal::k1::RailLag>;
#[cfg(not(all(feature = "soc-k1", feature = "k1")))]
type Note = ();

/// Tick the runtime over its board, with the state out of its lock
/// ([`tick_once`]).
fn tick_board(st: &mut State, model: &azos_energy::EnergyModel, now: u64, inp: &Inputs) -> (azos_energy::thermal::Settled, Note) {
    let State { rt, board, .. } = st;
    #[allow(unused_mut)]
    let mut note = Note::default();
    // The canary never ticks a board, so nothing reads the model.
    #[cfg(feature = "thermal-tick-canary")]
    let settled = {
        let _ = model;
        rt.last()
    };
    #[cfg(not(feature = "thermal-tick-canary"))]
    let settled = match board {
        #[cfg(all(feature = "vf2", feature = "soc"))]
        Board::Jh7110 { clock } => {
            // A sensor that is not bound (base 0) is never read: its runtime
            // has no zone.
            #[cfg(feature = "thermal")]
            let sensor = azos_thermal::jh7110::SfcTemp::new(SfcTempMmio(SFCTEMP_BASE.load(core::sync::atomic::Ordering::Acquire)));
            match *clock {
                Some((clk, ceiling_khz)) => super::soc::with(|_fdt, soc, bus, fx| {
                    let clock = azos_thermal::soc::SocCpuClock { tree: &mut soc.clocks, bus, fx, clk, ceiling_khz };
                    #[cfg(feature = "thermal")]
                    let settled = rt.tick(&mut azos_thermal::jh7110::Jh7110 { sensor, clock }, model, now, inp);
                    #[cfg(not(feature = "thermal"))]
                    let settled = rt.tick(&mut azos_thermal::runtime::NoSensor(azos_thermal::jh7110::Cluster(clock)), model, now, inp);
                    settled
                })
                .unwrap_or_else(|| rt.last()),
                #[cfg(feature = "thermal")]
                None => rt.tick(&mut azos_thermal::jh7110::Jh7110 { sensor, clock: NoClock }, model, now, inp),
                // Without a sensor and a clock there is no board (`board_runtime`).
                #[cfg(not(feature = "thermal"))]
                None => rt.last(),
            }
        }
        #[cfg(all(feature = "soc-k1", feature = "k1"))]
        Board::K1 { plan, lagged } => {
            // No lock is held here: each clock access takes the frameworks'
            // lock for the one operation (`LockedClocks`), and the rail's I2C
            // transfers, hundreds of microseconds, run with none.
            let mut pmic = super::hwbus::PmicI2c;
            let mut gate = super::soc::GateSink;
            let hw = azos_thermal::k1_soc::SocK1Hw {
                clocks: LockedClocks,
                i2c: &mut pmic,
                fx: &mut gate,
                wires: plan.wires,
                delay: busy_delay_us,
            };
            let mut opp = azos_thermal::k1::K1Opp::new(hw);
            for (d, t) in plan.tables.iter().enumerate() {
                if let Some(t) = t {
                    opp.bind(d, *t);
                }
            }
            // A block that is not bound (base 0) is never read: its runtime
            // has no zone.
            #[cfg(feature = "thermal")]
            let (settled, mut opp) = {
                let base = K1_TSENSOR_BASE.load(core::sync::atomic::Ordering::Acquire);
                let mut b = azos_thermal::k1::K1::new(azos_thermal::k1::K1Tsensor::new(K1TsensorMmio(base)), opp);
                (rt.tick(&mut b, model, now, inp), b.opp)
            };
            #[cfg(not(feature = "thermal"))]
            let (settled, mut opp) = {
                let mut b = azos_thermal::runtime::NoSensor(opp);
                (rt.tick(&mut b, model, now, inp), b.0)
            };
            *lagged = lagged.wrapping_add(opp.lagged());
            note = opp.take_lag();
            settled
        }
        // arch-only: as the variant.
        #[cfg(all(target_arch = "aarch64", feature = "rpi-firmware"))]
        Board::Rpi => crate::entry::aarch64::ext::rpi_mbox::with(|fw| rt.tick(fw, model, now, inp))
            .unwrap_or_else(|| rt.last()),
        // arch-only: as the variant.
        #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
        Board::X86 { kind, pc } => {
            use crate::entry::x86_64::ext::thermal_hw::KernelPlatform;
            let settled = match *kind {
                #[cfg(feature = "thermal")]
                Some(kind) => rt.tick(&mut crate::entry::x86_64::ext::thermal_hw::board(kind, pc.actuator(KernelPlatform)), model, now, inp),
                // No sensor: a runtime with no zone, the clock alone.
                _ => rt.tick(&mut azos_thermal::runtime::NoSensor(pc.actuator(KernelPlatform)), model, now, inp),
            };
            // The package energy since the last tick: a counter read, whatever
            // the zone was due.
            pc.energy(&mut KernelPlatform, now);
            settled
        }
        #[cfg(feature = "thermal-smoke")]
        Board::Fake(fake) => rt.tick(fake, model, now, inp),
        // No board object in this build: the state is never populated.
        #[allow(unreachable_patterns)]
        _ => rt.last(),
    };
    // The canary and a build with no board object use none of them.
    let _ = (&inp, now, &board, model);
    (settled, note)
}

/// One evaluation: tick the runtime over the bound board, answer the
/// governor's choices and say what the ring gained. Returns the sleep until
/// the next one, milliseconds (`None`: no zone to poll, sleep until a choice
/// changes), and whether a critical trip asked for the shutdown. `None`
/// without a runtime.
///
/// The state is taken out of its lock for the tick and put back
/// (`thermal/status` says `ticking` meanwhile; only this task writes it): no
/// board's tick is short enough for a spin lock (audit K2-M9). The K1 steps a
/// rail over I2C, the Raspberry Pi asks the VideoCore by mailbox (replies in
/// milliseconds), x86 reads another CPU's MSRs by a function-call IPI, the
/// JH7110 moves a clock through the SoC frameworks.
fn tick_once() -> Option<(Option<u32>, bool)> {
    let model = azos_sched::energy::model();
    let inp = inputs(model);
    let now = now_ms();
    // Raised before the take, so a reader that finds no state knows why.
    TICKING.store(true, core::sync::atomic::Ordering::Release);
    let Some(mut owned) = STATE.lock().take() else {
        TICKING.store(false, core::sync::atomic::Ordering::Release);
        return None;
    };
    let (settled, note) = tick_board(&mut owned, model, now, &inp);
    let mut g = STATE.lock();
    *g = Some(owned);
    TICKING.store(false, core::sync::atomic::Ordering::Release);
    let st = g.as_mut()?;
    let rt = &mut st.rt;
    let wait = rt.poll_interval_ms();
    let applied = rt.applied;
    // The ring's new records, oldest first, copied out so the lines and the
    // decisions are left with the lock released.
    let fresh = rt.thermal.logged().wrapping_sub(st.reported).min(LOG_LEN as u32) as usize;
    let mut out = [None; LOG_LEN];
    for (k, slot) in out.iter_mut().enumerate().take(fresh) {
        *slot = rt.thermal.record(fresh - 1 - k);
    }
    st.reported = rt.thermal.logged();
    let before = st.level;
    st.level = settled.level;
    drop(g);

    // The governor's assertion: every choice it made is answered.
    for (dom, a) in applied.iter().enumerate() {
        if let (Some((target, a)), Some(choice)) = (a, inp.want[dom]) {
            azos_sched::energy::gov_ack(dom, choice as u8, *target as u8, *a);
        }
    }

    #[cfg(all(feature = "soc-k1", feature = "k1"))]
    if let Some(l) = note {
        azos_drv_sys::kwarn!(
            "[THERMAL] k1: cluster {} runs {} kHz and its rail did not reach {} uV (last known {} uV, {:?}): a supply above the clock's need, retried at the next move",
            l.domain, l.khz, l.want_uv, l.last_uv, l.err,
        );
    }
    #[cfg(not(all(feature = "soc-k1", feature = "k1")))]
    let _ = note;

    let mut level = before;
    for r in out.iter().flatten() {
        let rose = r.event == Event::Level && r.arg > level;
        if r.event == Event::Level {
            level = r.arg;
        }
        report(r, rose);
    }
    Some((wait, settled.shutdown))
}

/// Leave one record of the ring as a console line and a `Rule::Thermal`
/// decision.
fn report(r: &azos_energy::thermal::Record, level_rose: bool) {
    use azos_decision::{Rule, Verdict};
    let st = stance(r.event, level_rose);
    kprintln!(
        "[THERMAL] zone {} {} {} temp={} mdeg {}",
        r.zone, event_name(r.event), r.arg, r.temp_mdeg,
        match st { Stance::Acted => "(acted)", Stance::Declined => "(declined)", Stance::Relaxed => "(relaxed)" },
    );
    let verdict = match st {
        Stance::Acted => Verdict::Place,
        Stance::Declined => Verdict::Refuse,
        Stance::Relaxed => Verdict::Admit,
    };
    azos_decision::record(Rule::Thermal, verdict, r.zone as u32, [r.event as u64, r.arg as u64, r.temp_mdeg as u32 as u64]);
}

fn thermal_task(_: usize) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    // The governor wakes this task when a choice changes, and asserts it is
    // answered, for every domain of the model (one the board cannot move
    // answers so, and leaves the assertion).
    let domains = azos_sched::energy::model().domains().len().min(MAX_DOMAINS);
    azos_sched::energy::apply_install(azos_sched::current_task_tid(), (1u32 << domains) - 1);
    loop {
        let wait = match tick_once() {
            Some((wait, false)) => wait,
            Some((_, true)) => {
                kprintln!("[THERMAL] critical trip: orderly shutdown");
                azos_syscall::handlers::power_off_orderly()
            }
            None => return,
        };
        // With no zone the only reason to tick is a changed choice.
        let end = wait.map_or(u64::MAX, |ms| azos_drv_sys::timebase::now() + ms as u64 * per_ms);
        while azos_drv_sys::timebase::now() < end && !azos_sched::energy::apply_take() {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

/// Create the thermal task, on the lowest CPU outside the real-time ones (as
/// the reclaim task is placed). Nothing without a runtime.
pub(crate) fn create_task() {
    if STATE.lock().is_none() {
        return;
    }
    let isolated = azos_topology::get().map_or(0, |t| t.sched_config().isolcpus as usize);
    let rt = azos_sync::qsbr::NOCBS_CPUS | isolated;
    let Some(cpu) = azos_sync::qsbr_core::callback_cpu(azos_percpu::nr_cpu_ids(), rt, azos_percpu::cpu_possible) else {
        azos_drv_sys::kwarn!("[THERMAL] every CPU is real-time (RCU_NOCBS_CPUS {:#x}, isolcpus {:#x}): no thermal task, the zones are not read", azos_sync::qsbr::NOCBS_CPUS, isolated);
        return;
    };
    azos_sched::task_create_affinity("thermal", thermal_task, 0, azos_limits::THERMAL_TASK_PRIORITY as u32, cpu as i8);
    kprintln!("[SCHED] Created thermal task (prio {}, CPU {})", azos_limits::THERMAL_TASK_PRIORITY, cpu);
}

// ── The introspection tree: thermal/ ────────────────────────────────────────

/// Zones and domains the tree lists, at most.
#[cfg(feature = "inspect")]
const TREE_ZONES: usize = 8;

#[cfg(feature = "inspect")]
struct TreeIds {
    status: azos_inspect::NodeId,
    ticks: azos_inspect::NodeId,
    level: azos_inspect::NodeId,
    shutdown: azos_inspect::NodeId,
    records: azos_inspect::NodeId,
    zones: [Option<azos_inspect::NodeId>; TREE_ZONES],
    domains: [Option<(azos_inspect::NodeId, azos_inspect::NodeId)>; MAX_DOMAINS],
    /// K1: the rail moves that lagged their clock.
    #[cfg(all(feature = "soc-k1", feature = "k1"))]
    rail_lagged: azos_inspect::NodeId,
    /// x86: RAPL's package energy and power, when the meter reads.
    // arch-only: RAPL is the PC board's meter; no other board has it.
    #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
    package: (azos_inspect::NodeId, azos_inspect::NodeId),
}

#[cfg(feature = "inspect")]
static TREE: SpinLock<Option<TreeIds>> = SpinLock::new(None);

/// `thermal/{status, board, ticks, level, shutdown, records,
/// zones/<z>/active, domains/<d>/{cap, opp}}`, with `rail_lagged` on a K1 and
/// `package_energy_uj`, `package_power_mw` on a PC: `status` is `none` (no
/// thermal framework), `ticking` (a tick holds
/// the state) or `running`; `opp` is `u64::MAX` when the domain's operating
/// point is not known. The board, its zones and its domains are those
/// [`install`] found; the values are rewritten at each refresh.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_build(
    b: &mut azos_inspect::Builder<'_, '_>,
    root: azos_inspect::NodeId,
) -> Result<(), azos_inspect::Error> {
    let t = b.dir(root, "thermal")?;
    let mut ids = TreeIds {
        status: b.string(t, "status", 8, "none")?,
        ticks: azos_inspect::NodeId::ROOT,
        level: azos_inspect::NodeId::ROOT,
        shutdown: azos_inspect::NodeId::ROOT,
        records: azos_inspect::NodeId::ROOT,
        zones: [None; TREE_ZONES],
        domains: [None; MAX_DOMAINS],
        #[cfg(all(feature = "soc-k1", feature = "k1"))]
        rail_lagged: b.u64(t, "rail_lagged", 0)?,
        // arch-only: RAPL is the PC board's meter; no other board has it.
        #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
        package: (b.u64(t, "package_energy_uj", 0)?, b.u64(t, "package_power_mw", 0)?),
    };
    let (board, zones) = {
        let g = STATE.lock();
        match g.as_ref() {
            Some(st) => (st.board.name(), st.rt.thermal.zones().len().min(TREE_ZONES)),
            None => ("-", 0),
        }
    };
    b.string(t, "board", board.len().max(1), board)?;
    ids.ticks = b.u64(t, "ticks", 0)?;
    ids.level = b.u64(t, "level", 0)?;
    ids.shutdown = b.u64(t, "shutdown", 0)?;
    ids.records = b.u64(t, "records", 0)?;
    let zd = b.dir(t, "zones")?;
    for (z, slot) in ids.zones.iter_mut().enumerate().take(zones) {
        let d = b.dir(zd, &super::inspect_metrics::Num::name("", z as u64))?;
        *slot = Some(b.u64(d, "active", 0)?);
    }
    let dd = b.dir(t, "domains")?;
    let domains = azos_sched::energy::model().domains().len().min(MAX_DOMAINS);
    for (k, slot) in ids.domains.iter_mut().enumerate().take(domains) {
        let d = b.dir(dd, &super::inspect_metrics::Num::name("", k as u64))?;
        *slot = Some((b.u64(d, "cap", 0)?, b.u64(d, "opp", u64::MAX)?));
    }
    *TREE.lock_irqsave() = Some(ids);
    Ok(())
}

/// Rewrite the thermal values; the ones that were not published.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_refresh(w: &azos_inspect::Writer<'_>) -> u32 {
    let tg = TREE.lock_irqsave();
    let Some(ids) = tg.as_ref() else { return 0 };
    let mut bad = 0u32;
    let mut ok = |r: Result<(), azos_inspect::Error>| bad += r.is_err() as u32;
    let g = STATE.lock();
    let Some(st) = g.as_ref() else {
        let busy = TICKING.load(core::sync::atomic::Ordering::Acquire);
        ok(w.set_str(ids.status, if busy { "ticking" } else { "none" }));
        return bad;
    };
    let rt = &st.rt;
    ok(w.set_str(ids.status, "running"));
    ok(w.set_u64(ids.ticks, rt.ticks as u64));
    ok(w.set_u64(ids.level, rt.last().level as u64));
    ok(w.set_u64(ids.shutdown, rt.last().shutdown as u64));
    ok(w.set_u64(ids.records, rt.thermal.logged() as u64));
    for (z, id) in ids.zones.iter().enumerate() {
        if let Some(id) = id {
            ok(w.set_u64(*id, rt.thermal.active(z) as u64));
        }
    }
    for (d, id) in ids.domains.iter().enumerate() {
        if let Some((cap, opp)) = id {
            ok(w.set_u64(*cap, rt.thermal.cap_state(d) as u64));
            ok(w.set_u64(*opp, rt.dvfs.current(d).map_or(u64::MAX, |o| o as u64)));
        }
    }
    // Irrefutable where the K1 is the only board object.
    #[cfg(all(feature = "soc-k1", feature = "k1"))]
    #[allow(irrefutable_let_patterns)]
    if let Board::K1 { lagged, .. } = &st.board {
        ok(w.set_u64(ids.rail_lagged, *lagged as u64));
    }
    // Irrefutable where the PC is the only board object.
    // arch-only: RAPL is the PC board's meter; no other board has it.
    #[cfg(all(target_arch = "x86_64", not(feature = "thermal-smoke")))]
    #[allow(irrefutable_let_patterns)]
    if let Board::X86 { pc, .. } = &st.board {
        if pc.hw().meter != azos_thermal::x86::Meter::None {
            let e = pc.last_energy();
            ok(w.set_u64(ids.package.0, e.total_uj as u64));
            ok(w.set_u64(ids.package.1, e.power_mw as u64));
        }
    }
    bad
}

// ── What the QEMU row looks at ──────────────────────────────────────────────

/// The fake board's clocks (kHz per domain, 0 = never set), the evaluations
/// made, and a way to read the ring. `None` without a runtime, and while a
/// tick has the state out of its lock (the smoke's waits poll again).
#[cfg(feature = "thermal-smoke")]
pub(crate) fn smoke_view<R>(f: impl FnOnce(&Runtime, &[u32; MAX_DOMAINS]) -> R) -> Option<R> {
    let g = STATE.lock();
    let st = g.as_ref()?;
    // Irrefutable on riscv64 (the fake is the only board), not on aarch64.
    #[allow(irrefutable_let_patterns)]
    let Board::Fake(fake) = &st.board else { return None };
    Some(f(&st.rt, &fake.khz))
}
