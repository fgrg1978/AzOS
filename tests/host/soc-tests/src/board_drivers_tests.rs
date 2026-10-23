// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 board controllers (GPIO, I2C, PWM, watchdog, DMA controller,
//! temperature sensor) bind to their device-tree nodes through the hardware
//! bus: the real `crates/drivers/*/hwbus.ids` rows decide, the node gives the
//! window and the interrupt, and the SoC frameworks give the node its
//! resources before the driver is asked.
//!
//! This covers the row-to-device mapping and the order of the calls. The
//! kernel's probe arms (`kernel/src/boot/hwbus.rs`: map the window, hand the
//! base to `gpio_attach` / `i2c_attach` / ...) are board territory; the
//! window bookkeeping they end in is `tests/host/drivers-tests`'
//! `window_tests`.
//!
//! Canary (removes what a row relies on, the named rows must FAIL): take the
//! `boot` word off a line of `crates/drivers/{gpio,bus,actuator,sys,dmac}/hwbus.ids`
//! and `a_topology_only_image_still_binds_the_controllers_the_kernel_drives`
//! goes red; put the sys pad controller back in `crates/drivers/soc/hwbus.ids`
//! and every row here stops at the table builder, which refuses an id with two
//! owners.
use crate::bind_tests::{Rig, JH};
use crate::support::*;
use azos_hwbus::{
    Access as _,
    self as hw, Binding, Choice, Device, Drivers, Handle, NativeEntry, Pattern, Policy, ProbeError, State, Verdict,
};
use azos_soc::bind::Applied;
use azos_soc::boot::Storage;
use azos_soc::effect::{self, Op};
use azos_soc::fdt::Fdt;
use azos_soc::NodeId;

const RESET: u8 = effect::KIND_RESET;

/// Every native row the tree's `hwbus.ids` files carry, read from the files
/// themselves with every `if=` condition taken as met (the image these rows
/// are for: a VisionFive 2 with the thermal framework).
fn native_table() -> Vec<NativeEntry> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../crates/drivers");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("hwbus.ids"))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let mut out = Vec::new();
    let mut seen = std::collections::HashMap::new();
    for f in files {
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let (driver, selector) = (it.next().unwrap(), it.next().unwrap());
            let boot = it.any(|o| o == "boot");
            // One id has one owner (crates/drivers/hwbus/build.rs refuses it too).
            if let Some(other) = seen.insert(selector.to_string(), driver.to_string()) {
                assert_eq!(other, driver, "{selector} is claimed by {other} and {driver}");
            }
            let pattern = Pattern::parse(Box::leak(selector.to_string().into_boxed_str())).expect("a selector");
            out.push(NativeEntry { pattern, driver: Box::leak(driver.to_string().into_boxed_str()), boot });
        }
    }
    out
}

/// A node of the controllers' tree: where it is, what it is, its interrupt and
/// the reset line it asks for (a distinct one each, so the log says whose
/// resources were given; ids the JH7110 SYS CRG has as lines).
struct Node {
    name: &'static str,
    compat: &'static [&'static str],
    base: u32,
    size: u32,
    irq: u32,
    reset: u32,
}

const GPIO: Node = Node { name: "pinctrl@13040000", compat: &["starfive,jh7110-sys-pinctrl"], base: 0x1304_0000, size: 0x1_0000, irq: 86, reset: 20 };
const I2C2: Node = Node { name: "i2c@10050000", compat: &["snps,designware-i2c"], base: 0x1005_0000, size: 0x1_0000, irq: 38, reset: 21 };
const I2C5: Node = Node { name: "i2c@12050000", compat: &["snps,designware-i2c"], base: 0x1205_0000, size: 0x1_0000, irq: 41, reset: 22 };
const PWM: Node = Node { name: "pwm@120d0000", compat: &["starfive,jh7110-pwm", "opencores,pwm-v1"], base: 0x120d_0000, size: 0x1_0000, irq: 0, reset: 23 };
const WDT: Node = Node { name: "watchdog@13070000", compat: &["starfive,jh7110-wdt"], base: 0x1307_0000, size: 0x1_0000, irq: 92, reset: 26 };
const DMA: Node = Node { name: "dma-controller@16050000", compat: &["starfive,jh7110-axi-dma"], base: 0x1605_0000, size: 0x1_0000, irq: 73, reset: 27 };
const TEMP: Node = Node { name: "temperature-sensor@120e0000", compat: &["starfive,jh7110-temp"], base: 0x120e_0000, size: 0x1_0000, irq: 122, reset: 29 };
/// The crypto engine's ARM PL080 (`sdma@16008000`): nothing claims it.
const SDMA: Node = Node { name: "dma-controller@16008000", compat: &["arm,pl080", "arm,primecell"], base: 0x1600_8000, size: 0x1_0000, irq: 29, reset: 31 };

/// A JH7110-shaped tree with the nodes given (document order), plus a node a
/// board leaves `status = "disabled"` (the SoC's i2c0).
fn tree(nodes: &[&Node]) -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    for (name, ph, hz) in [("oscillator", OSC, 24_000_000), ("pll0", PLL0, 1_000_000_000), ("pll2", PLL2, 1_188_000_000)] {
        b.begin(name).str("compatible", "fixed-clock").cells("#clock-cells", &[0]).cells("clock-frequency", &[hz]).ph(ph).end();
    }
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");
    b.begin("clock-controller@13020000")
        .strs("compatible", &["starfive,jh7110-syscrg"])
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("clocks", &[OSC, PLL0, PLL2])
        .strs("clock-names", &["osc", "pll0_out", "pll2_out"])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    for n in nodes {
        b.begin(n.name)
            .strs("compatible", n.compat)
            .cells("reg", &[0, n.base, 0, n.size])
            .cells("resets", &[SYSCRG, n.reset]);
        if n.irq != 0 {
            b.cells("interrupts", &[n.irq]);
        }
        b.end();
    }
    b.begin("i2c@10030000")
        .strs("compatible", &["snps,designware-i2c"])
        .cells("reg", &[0, 0x1003_0000, 0, 0x10000])
        .str("status", "disabled")
        .end();
    b.end();
    b.finish()
}

/// What the kernel does with the blob (`enumerate_firmware`): one device per
/// enabled node, in document order, with the node it came from.
fn enumerate(blob: &[u8], bus: &mut hw::Bus) -> Vec<Handle> {
    let mut hs = Vec::new();
    // SAFETY: `blob` is a well-formed tree the builder made.
    unsafe {
        azos_dtb::dtb_devices(blob.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
            let name = std::str::from_utf8(d.name).unwrap();
            let dev = Device::dt(name, d.compatible, d.base, d.size, d.irq).with_dt_node(d.dt_node);
            hs.push(bus.add(dev, &mut Quiet).unwrap());
        })
        .unwrap();
    }
    hs
}

struct Quiet;
impl hw::Sink for Quiet {
    fn event(&mut self, _ev: &hw::Event<'_>) {}
}

/// The kernel's driver registry over a rig: the node's resources before the
/// driver (except for a driver whose node the SoC framework drives itself, the
/// `gpio` of the pad controller: `NO_RESOURCES` in `kernel/src/boot/hwbus.rs`),
/// and the probe recorded. The record-only driver (`soc`: the clock controller
/// the kernel brought up before the bus) neither asks for resources nor probes.
struct Registry<'r, 'p, 'f> {
    rig: &'r mut Rig<'p>,
    fdt: &'r Fdt<'f>,
    /// `(call, driver)` in the order the calls came.
    calls: Vec<(&'static str, String)>,
    /// `(driver, base, size, irq)` of each probe.
    probed: Vec<(String, u64, u64, u32)>,
    applied: Vec<Applied>,
}

impl Drivers for Registry<'_, '_, '_> {
    fn resources(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        if driver == "gpio" || driver == "soc" {
            return Ok(());
        }
        self.calls.push(("resources", driver.to_string()));
        let node = NodeId(dev.dt_node.expect("a tree device carries its node"));
        let a = self.rig.bind(self.fdt, node).map_err(|_| ProbeError::Resources)?;
        self.applied.push(a);
        Ok(())
    }
    fn release(&mut self, driver: &str, _h: Handle, _dev: &Device) {
        self.calls.push(("release", driver.to_string()));
    }
    fn probe(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        if driver == "soc" {
            return Ok(());
        }
        self.calls.push(("probe", driver.to_string()));
        self.probed.push((driver.to_string(), dev.base, dev.size, dev.irq));
        Ok(())
    }
    fn remove(&mut self, _driver: &str, _h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        Err(ProbeError::Busy)
    }
}

fn rules<'a>(native: &'a [NativeEntry], policy: Policy) -> hw::Rules<'a> {
    hw::Rules { native, linux: &[], rows: &[], policy }
}

/// Run `f` over a registry on the rig for `blob`.
fn with_registry<R>(blob: &[u8], f: impl FnOnce(&mut hw::Bus, &mut Registry<'_, '_, '_>, &[Handle]) -> R) -> R {
    let fdt = Fdt::parse(blob).unwrap();
    let mut st = Storage::new();
    let mut rig = Rig::new(&mut st, &fdt, JH);
    let mut bus = hw::Bus::new();
    let hs = enumerate(blob, &mut bus);
    let mut reg = Registry { rig: &mut rig, fdt: &fdt, calls: vec![], probed: vec![], applied: vec![] };
    f(&mut bus, &mut reg, &hs)
}

fn all_nodes() -> Vec<u8> {
    tree(&[&GPIO, &I2C2, &I2C5, &PWM, &WDT, &DMA, &TEMP, &SDMA])
}

#[test]
fn each_controller_binds_to_its_driver_with_the_window_and_interrupt_of_its_node() {
    let native = native_table();
    with_registry(&all_nodes(), |bus, reg, _| {
        bus.bind_all(&rules(&native, Policy::Auto), reg, &mut Quiet);
        let want: Vec<(String, u64, u64, u32)> = [
            ("gpio", &GPIO), ("i2c", &I2C2), ("i2c", &I2C5), ("pwm", &PWM),
            ("wdt", &WDT), ("dmac", &DMA), ("sfctemp", &TEMP),
        ]
        .iter()
        .map(|(d, n)| (d.to_string(), n.base as u64, n.size as u64, n.irq))
        .collect();
        assert_eq!(reg.probed, want, "document order, the node's window and first interrupt");
    });
}

#[test]
fn the_resources_come_first_for_every_controller_but_the_pad_controllers_gpio() {
    let native = native_table();
    with_registry(&all_nodes(), |bus, reg, _| {
        bus.bind_all(&rules(&native, Policy::Auto), reg, &mut Quiet);
        let calls: Vec<String> = reg.calls.iter().map(|(c, d)| format!("{c}:{d}")).collect();
        assert_eq!(
            calls,
            ["probe:gpio", "resources:i2c", "probe:i2c", "resources:i2c", "probe:i2c", "resources:pwm", "probe:pwm",
             "resources:wdt", "probe:wdt", "resources:dmac", "probe:dmac", "resources:sfctemp", "probe:sfctemp"]
        );
        // Each given node's own reset line came up, in the same order.
        let resets: Vec<u32> = reg.rig.ops().iter().filter(|o| o.0 == RESET && o.1 == Op::Deassert).map(|o| o.2).collect();
        assert_eq!(resets, [I2C2.reset, I2C5.reset, PWM.reset, WDT.reset, DMA.reset, TEMP.reset]);
        assert!(!resets.contains(&GPIO.reset), "the pad controller's node is the SoC framework's");
    });
}

#[test]
fn a_node_the_tree_does_not_have_is_an_absent_driver_not_a_fault() {
    let native = native_table();
    // No watchdog, no PWM, no DMA controller, no sensor; the SoC's disabled
    // i2c0 is in the tree and not a device.
    let blob = tree(&[&GPIO, &I2C2]);
    with_registry(&blob, |bus, reg, hs| {
        bus.bind_all(&rules(&native, Policy::Auto), reg, &mut Quiet);
        assert_eq!(hs.len(), 3, "the syscrg, the pad controller, one I2C: the disabled i2c0 is not listed");
        let drivers: Vec<&str> = reg.probed.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(drivers, ["gpio", "i2c"]);
        assert!(bus.iter().all(|(_, s)| s.state != State::ProbeFailed), "absence is not a probe failure");
    });
}

#[test]
fn a_node_that_is_not_the_controller_the_driver_is_for_binds_nothing() {
    let native = native_table();
    // The ARM PL080 beside the AXI DMA controller: no row names it.
    let blob = tree(&[&SDMA]);
    with_registry(&blob, |bus, reg, hs| {
        bus.bind_all(&rules(&native, Policy::Auto), reg, &mut Quiet);
        let sdma = hs[hs.len() - 1];
        assert_eq!(bus.get(sdma).unwrap().state, State::Unmatched);
        assert!(reg.probed.is_empty() && reg.calls.is_empty());
    });
}

#[test]
fn a_topology_only_image_still_binds_the_controllers_the_kernel_drives() {
    let native = native_table();
    with_registry(&all_nodes(), |bus, reg, hs| {
        bus.bind_all(&rules(&native, Policy::TopologyOnly), reg, &mut Quiet);
        // The seven controllers and the clock controller's record (the SoC
        // frameworks' own `boot` row) bind; the PL080 has no row and none is
        // refused by the policy.
        let bound = hs.iter().filter(|h| bus.get(**h).unwrap().state == State::Bound).count();
        assert_eq!(bound, 8, "{:?}", reg.calls);
        assert_eq!(reg.probed.len(), 7);
        assert!(bus.iter().all(|(_, s)| s.state != State::NotAdmitted && s.state != State::ProbeFailed));
    });
}

#[test]
fn the_pad_controller_is_the_gpio_not_a_record() {
    let native = native_table();
    let pad = Device::dt("pinctrl@13040000", b"starfive,jh7110-sys-pinctrl\0", 0x1304_0000, 0x1_0000, 86);
    assert_eq!(
        hw::decide(&pad, &native, &[], &[], Policy::TopologyOnly),
        Verdict::Bind(Choice::Native("gpio")),
        "the window is the board's GPIO; the SoC row for it moved to crates/drivers/gpio"
    );
    // Its neighbour, the AON pad controller, stays the framework's.
    let aon = Device::dt("pinctrl@17020000", b"starfive,jh7110-aon-pinctrl\0", 0x1702_0000, 0x1_0000, 85);
    assert_eq!(hw::decide(&aon, &native, &[], &[], Policy::Auto), Verdict::Bind(Choice::Native("soc")));
}

#[test]
fn the_safety_read_drivers_bind_in_their_own_stage_before_the_rest() {
    let native = native_table();
    with_registry(&all_nodes(), |bus, reg, hs| {
        let rules = rules(&native, Policy::TopologyOnly);
        // Stage 1 (after the SoC frameworks): the e-stop GPIO and the watchdog.
        let stage = |names: &'static [&'static str]| move |_: &Device, v: &Verdict<'_>| {
            matches!(v, Verdict::Bind(Choice::Native(n)) if names.contains(n))
        };
        bus.bind_where(&rules, reg, &mut Quiet, &stage(&["gpio", "wdt"]));
        let first: Vec<&str> = reg.probed.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(first, ["gpio", "wdt"]);
        assert_eq!(bus.get(hs[2]).unwrap().state, State::Detected, "the I2C waits for the robot hardware stage");
        // Stage 2 (`install_robot_hw`): the rest.
        bus.bind_where(&rules, reg, &mut Quiet, &stage(&["i2c", "pwm", "dmac", "sfctemp"]));
        let all: Vec<&str> = reg.probed.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(all, ["gpio", "wdt", "i2c", "i2c", "pwm", "dmac", "sfctemp"]);
        assert!(matches!(bus.get(hs[1]).unwrap().binding, Binding::Native(_)));
    });
}

// ── The device-window budget ───────────────────────────────────────────────

fn repo_file(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The upper bound of the device windows a VisionFive 2 image records
/// (`vmm::map_mmio_region`, one record each), counted from the sources that
/// create them:
///
/// - the console UART and the PLIC (`early_main`), plus the board's fixed
///   windows with every optional feature on (`BOARD_WINDOWS`, vf2 lines, the
///   display ones included);
/// - the SoC frameworks' register windows, at most `MAX_WINDOWS_JH7110` (a CRG that
///   is clock and reset provider shares one, so the bound is loose);
/// - one window per `map_window` arm of the hardware bus that a `vf2` image
///   compiles (the pad
///   controller's own, even though the framework maps it too: the record
///   de-duplicates, but the bound assumes the frameworks failed), and the I2C
///   arm once per bus it can attach.
fn vf2_window_bound() -> usize {
    let board = repo_file("kernel/src/entry/riscv64/board_map.rs");
    let fixed = board
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("#[cfg(") && l.contains("\"vf2\"") && !l.contains("not(") && l.contains("] ("))
        .count();
    let hwbus = repo_file("kernel/src/boot/hwbus.rs");
    // Only the arms a VisionFive 2 image compiles: the `#[cfg(..)]` line above
    // an arm names `vf2` (the Raspberry Pi mailbox and the K1's sensor are other
    // boards' windows).
    let mut cfg = "";
    let mut arms = 0;
    for l in hwbus.lines().map(str::trim) {
        if l.starts_with("#[cfg(") {
            cfg = l;
        } else if l.contains("map_window(dev)?") && cfg.contains("\"vf2\"") {
            arms += 1;
        }
    }
    let i2c = repo_file("crates/drivers/bus/src/i2c.rs");
    let buses: usize = i2c
        .lines()
        .find(|l| l.starts_with("pub const I2C_BUS_COUNT"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_end_matches(';').trim().parse().expect("a number"))
        .expect("I2C_BUS_COUNT");
    assert!(fixed >= 5 && arms >= 6 && buses >= 2, "the parse found fixed={fixed} arms={arms} buses={buses}");
    2 + fixed + azos_soc::boot::MAX_WINDOWS_JH7110 + arms + (buses - 1)
}

/// `default N if BOARD_VF2` of `MAX_MMIO_REGIONS` in the Kconfig.
fn vf2_window_default() -> usize {
    let k = repo_file("config/limits/Kconfig.limits");
    let block = k.split("config MAX_MMIO_REGIONS").nth(1).expect("the symbol");
    let block = block.split("\nconfig ").next().unwrap();
    block
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("default ")?.strip_suffix(" if BOARD_VF2")?.trim().parse().ok())
        .expect("a `default N if BOARD_VF2` line")
}

#[test]
fn the_vf2_window_budget_fits_the_kconfig_default() {
    // **Canary.** Delete the `default 32 if BOARD_VF2` line of MAX_MMIO_REGIONS
    // (the generic 16 is what the board had): the lookup finds none and this
    // row goes red; set it to 16 and the bound exceeds it. Add a `map_window`
    // arm to `kernel/src/boot/hwbus.rs` past the headroom: red as well. The
    // failure it guards: a full record makes the bind of a later controller
    // `Failed`, and when that controller is the GPIO the e-stop line is
    // silently absent.
    let (bound, default) = (vf2_window_bound(), vf2_window_default());
    assert!(bound <= default, "a VisionFive 2 can record {bound} device windows, MAX_MMIO_REGIONS defaults to {default}");
}
