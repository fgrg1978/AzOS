// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SoC PCIe host-controller bring-up (`azos_pci::host`) against a register
//! trace: the order of the init sequence, the windows programmed from fixture
//! DT `ranges` / `dma-ranges` cells, and the refusal of a link that stays
//! down. The mock models only what the sequences read back: a link status
//! that turns up at a virtual time, an MDIO acknowledge, and plain registers.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use azos_pci::host::{brcmstb, plda, *};
use azos_pci::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Rd(Region, u32),
    Wr(Region, u32, u32),
    Delay(u32),
    Perst(bool),
}

/// Link status model: reading `(region, off)` returns `bits` ORed in once the
/// virtual clock has reached `up_at_us`.
struct Link {
    region: Region,
    off: u32,
    bits: u32,
    up_at_us: u64,
}

struct Mock {
    regs: RefCell<HashMap<(Region, u32), u32>>,
    log: RefCell<Vec<Ev>>,
    clock_us: Cell<u64>,
    link: Option<Link>,
    /// The PHY never acknowledges an MDIO write.
    mdio_stuck: bool,
}

impl Mock {
    fn new() -> Self {
        Mock {
            regs: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            clock_us: Cell::new(0),
            link: None,
            mdio_stuck: false,
        }
    }
    fn with_reg(self, region: Region, off: u32, val: u32) -> Self {
        self.regs.borrow_mut().insert((region, off), val);
        self
    }
    fn with_link(mut self, region: Region, off: u32, bits: u32, up_at_us: u64) -> Self {
        self.link = Some(Link { region, off, bits, up_at_us });
        self
    }
    fn reg(&self, region: Region, off: u32) -> u32 {
        let dflt = if region == Region::Cfg { u32::MAX } else { 0 };
        self.regs.borrow().get(&(region, off)).copied().unwrap_or(dflt)
    }
    fn log(&self) -> Vec<Ev> {
        self.log.borrow().clone()
    }
    /// Values written to `(region, off)`, in order.
    fn writes(&self, region: Region, off: u32) -> Vec<u32> {
        self.log.borrow().iter().filter_map(|e| match *e {
            Ev::Wr(r, o, v) if r == region && o == off => Some(v),
            _ => None,
        }).collect()
    }
    fn delays(&self) -> Vec<u32> {
        self.log.borrow().iter().filter_map(|e| if let Ev::Delay(d) = e { Some(*d) } else { None }).collect()
    }
}

impl Bus for Mock {
    fn read32(&self, region: Region, off: u32) -> u32 {
        self.log.borrow_mut().push(Ev::Rd(region, off));
        let mut v = self.reg(region, off);
        if let Some(l) = &self.link {
            if l.region == region && l.off == off && self.clock_us.get() >= l.up_at_us {
                v |= l.bits;
            }
        }
        if region == Region::Apb && off == 0x1104 && !self.mdio_stuck {
            v &= !0x8000_0000; // DONE clears when the PHY took the word
        }
        v
    }
    fn write32(&self, region: Region, off: u32, val: u32) {
        self.log.borrow_mut().push(Ev::Wr(region, off, val));
        self.regs.borrow_mut().insert((region, off), val);
    }
    fn delay_us(&self, us: u32) {
        self.log.borrow_mut().push(Ev::Delay(us));
        self.clock_us.set(self.clock_us.get() + us as u64);
    }
}

impl Perst for Mock {
    fn set_perst(&self, asserted: bool) {
        self.log.borrow_mut().push(Ev::Perst(asserted));
    }
}

/// Every matcher must hit, each strictly after the previous one.
fn assert_order(log: &[Ev], steps: &[(&str, &dyn Fn(&Ev) -> bool)]) {
    let mut at = 0usize;
    for (name, m) in steps {
        match log[at..].iter().position(|e| m(e)) {
            Some(p) => at += p + 1,
            None => panic!("step `{name}` not found after event {at}; log: {log:#x?}"),
        }
    }
}

fn wr(region: Region, off: u32) -> impl Fn(&Ev) -> bool {
    move |e| matches!(*e, Ev::Wr(r, o, _) if r == region && o == off)
}
fn wr_val(region: Region, off: u32, val: u32) -> impl Fn(&Ev) -> bool {
    move |e| *e == Ev::Wr(region, off, val)
}
fn rd(region: Region, off: u32) -> impl Fn(&Ev) -> bool {
    move |e| *e == Ev::Rd(region, off)
}

// ---------------------------------------------------------------------
// Fixture DT cells
// ---------------------------------------------------------------------

/// `ranges` of a PCI host node: `phys.hi phys.mid phys.lo`, the CPU address
/// in `parent_ac` cells, the size in two cells. Space code in bits 25:24 of
/// `phys.hi`.
fn decode_ranges(cells: &[u32], parent_ac: usize) -> Vec<OutboundWindow> {
    let n = 3 + parent_ac + 2;
    cells
        .chunks_exact(n)
        .map(|e| {
            let join = |hi: u32, lo: u32| (hi as u64) << 32 | lo as u64;
            let cpu = if parent_ac == 2 { join(e[3], e[4]) } else { e[3] as u64 };
            let size = join(e[3 + parent_ac], e[4 + parent_ac]);
            OutboundWindow {
                space: if (e[0] >> 24) & 3 == 3 { MemSpace::Mem64 } else { MemSpace::Mem32 },
                window: HostWindow { cpu_base: cpu, bus_base: join(e[1], e[2]), size },
            }
        })
        .collect()
}

/// `dma-ranges` of a PCI host node: child (`phys.hi phys.mid phys.lo`),
/// parent (two cells), size (two cells).
fn decode_dma_ranges(cells: &[u32]) -> Vec<InboundWindow> {
    cells
        .chunks_exact(7)
        .map(|e| {
            let join = |hi: u32, lo: u32| (hi as u64) << 32 | lo as u64;
            InboundWindow { bus_base: join(e[1], e[2]), cpu_base: join(e[3], e[4]), size: join(e[5], e[6]) }
        })
        .collect()
}

/// VisionFive 2 (`jh7110.dtsi`, `pcie1`): `reg` "cfg" `<0x9 0xc0000000 0x0
/// 0x10000000>`; `ranges` below. [verify] against the board's DTB.
const VF2_CFG_BASE: u64 = 0x9_c000_0000;
const VF2_CFG_SIZE: u64 = 0x1000_0000;
/// PCI bus address the bridge's APB block answers at (an inbound window the
/// board sets up); fixture value.
const VF2_MSI_DOORBELL: u64 = 0x2c00_0000;
const VF2_RANGES: [u32; 14] = [
    0x8200_0000, 0x0, 0x3800_0000, 0x0, 0x3800_0000, 0x0, 0x0800_0000,
    0xc300_0000, 0x9, 0x8000_0000, 0x9, 0x8000_0000, 0x0, 0x4000_0000,
];

/// Raspberry Pi 5 RP1 root complex (`bcm2712.dtsi`, `pcie2`): representative
/// values, [verify] against the board's DTB. Mem32 maps CPU `0x1f_0000_0000`
/// to bus 0; the second window is shifted by 1 MiB to exercise the field
/// masks.
const PI5_RANGES: [u32; 14] = [
    0x0200_0000, 0x0, 0x0000_0000, 0x1f, 0x0000_0000, 0x0, 0xffff_fffc,
    0x4300_0000, 0x4, 0x0010_0000, 0x1b, 0x8010_0000, 0x0, 0x4000_0000,
];
/// `dma-ranges`: bus `0x10_0000_0000` -> CPU 0, 64 GiB.
const PI5_DMA_RANGES: [u32; 7] = [0x0200_0000, 0x10, 0x0, 0x0, 0x0, 0x10, 0x0];

// ---------------------------------------------------------------------
// PLDA / JH7110
// ---------------------------------------------------------------------

const STG: u32 = plda::STG_PCIE1_BASE; // 0x1f8
const STG_LNKSTA: u32 = STG + 0x170;

fn plda_cfg<'a>(out: &'a [OutboundWindow], inb: &'a [InboundWindow]) -> plda::PldaConfig<'a> {
    plda::PldaConfig {
        stg_base: STG,
        cfg_base: VF2_CFG_BASE,
        cfg_size: VF2_CFG_SIZE,
        outbound: out,
        inbound: inb,
        msi_doorbell: VF2_MSI_DOORBELL,
        link_timeout_us: plda::DEFAULT_LINK_TIMEOUT_US,
    }
}

fn plda_mock(up_at_us: u64) -> Mock {
    Mock::new().with_link(Region::Stg, STG_LNKSTA, 1 << 5, up_at_us)
}

#[test]
fn plda_init_sequence_order() {
    let out = decode_ranges(&VF2_RANGES, 2);
    let m = plda_mock(0);
    let r = plda::init(&m, &plda_cfg(&out, &[])).unwrap();
    assert_eq!(r.config, ConfigAccess::Ecam { size: VF2_CFG_SIZE });

    assert_order(&m.log(), &[
        ("root-port mode", &wr_val(Region::Stg, STG + 0xe8, 1 << 8)),
        ("PERST# asserted", &|e| *e == Ev::Perst(true)),
        ("function disable", &wr_val(Region::Apb, 0xb4, 1 << 15)),
        ("root port enable", &wr_val(Region::Apb, 0x80, 1)),
        ("class code", &wr_val(Region::Apb, 0x9c, 0x0604_0000)),
        ("PERST# hold", &|e| *e == Ev::Delay(100_000)),
        ("PERST# released", &|e| *e == Ev::Perst(false)),
        ("config settle", &|e| *e == Ev::Delay(100_000)),
        ("link poll", &rd(Region::Stg, STG_LNKSTA)),
        ("config ATR", &wr(Region::Apb, 0x810)),
        ("first memory ATR", &wr(Region::Apb, 0x830)),
    ]);
    // Mode and clock bits landed; the function select was put back to 0.
    assert_eq!(m.reg(Region::Stg, STG + 0xe8), 1 << 8);
    assert_eq!(m.reg(Region::Stg, STG + 0x7c), (2 << 18) | (1 << 22));
    assert_eq!(m.reg(Region::Stg, STG + 0x78), 0);
    assert_eq!(m.reg(Region::Apb, 0xb4), 1 << 15);
    // Functions 1, 2, 3 were selected in turn.
    assert_eq!(m.writes(Region::Stg, STG + 0x78), vec![1 << 17, 2 << 17, 3 << 17, 0]);
    assert_eq!(m.writes(Region::Stg, STG + 0x7c).len(), 2 + 3 + 1);
}

#[test]
fn plda_windows_programmed_from_fixture_ranges() {
    let out = decode_ranges(&VF2_RANGES, 2);
    assert_eq!(out.len(), 2);
    let m = plda_mock(0);
    plda::init(&m, &plda_cfg(&out, &[])).unwrap();

    // Entry 0: the ECAM window, configuration-type, translated to PCI 0.
    // 256 MiB -> size field 27 -> (27 << 1) | enable.
    assert_eq!(m.reg(Region::Apb, 0x810), 1);
    assert_eq!(m.reg(Region::Apb, 0x800), 0xc000_0000 | (27 << 1) | 1);
    assert_eq!(m.reg(Region::Apb, 0x804), 0x9);
    assert_eq!(m.reg(Region::Apb, 0x808), 0);
    assert_eq!(m.reg(Region::Apb, 0x80c), 0);
    // Entry 1: mem32 128 MiB at 0x38000000, bus == CPU.
    assert_eq!(m.reg(Region::Apb, 0x830), 0);
    assert_eq!(m.reg(Region::Apb, 0x820), 0x3800_0000 | (26 << 1) | 1);
    assert_eq!(m.reg(Region::Apb, 0x824), 0);
    assert_eq!(m.reg(Region::Apb, 0x828), 0x3800_0000);
    assert_eq!(m.reg(Region::Apb, 0x82c), 0);
    // Entry 2: mem64 1 GiB at 0x9_8000_0000.
    assert_eq!(m.reg(Region::Apb, 0x850), 0);
    assert_eq!(m.reg(Region::Apb, 0x840), 0x8000_0000 | (29 << 1) | 1);
    assert_eq!(m.reg(Region::Apb, 0x844), 0x9);
    assert_eq!(m.reg(Region::Apb, 0x848), 0x8000_0000);
    assert_eq!(m.reg(Region::Apb, 0x84c), 0x9);
    // No third memory entry.
    assert!(m.writes(Region::Apb, 0x860).is_empty());
}

#[test]
fn plda_translated_window_programs_bus_address_and_feeds_the_bar_allocator() {
    // The same 128 MiB seen by the CPU at 0x38000000 is PCI 0x1000_0000.
    let out = [OutboundWindow {
        space: MemSpace::Mem32,
        window: HostWindow { cpu_base: 0x3800_0000, bus_base: 0x1000_0000, size: 0x0800_0000 },
    }];
    let m = plda_mock(0);
    let r = plda::init(&m, &plda_cfg(&out, &[])).unwrap();
    assert_eq!(m.reg(Region::Apb, 0x820), 0x3800_0000 | (26 << 1) | 1, "source is the AXI address");
    assert_eq!(m.reg(Region::Apb, 0x828), 0x1000_0000, "translation target is the bus address");

    let (win, rep) = resolve_bar_window(Some(r.windows), "dtb", (0x4000_0000, 0x1000), None, 1 << 39);
    assert_eq!(rep.mem32.source, WindowSource::Translated);
    assert_eq!((rep.mem32.base, rep.mem32.cpu_base, rep.mem32.size), (0x1000_0000, 0x3800_0000, 0x0800_0000));
    assert!(!win.has_pref64());
}

#[test]
fn plda_inbound_window_from_dma_ranges() {
    // bus 0x1_0000_0000 -> CPU 0, 4 GiB.
    let inb = decode_dma_ranges(&[0x0200_0000, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0]);
    let m = plda_mock(0);
    plda::init(&m, &plda_cfg(&[], &inb)).unwrap();
    assert_eq!(m.reg(Region::Apb, 0x610), 4, "target: AXI4 master 0");
    assert_eq!(m.reg(Region::Apb, 0x600), (31 << 1) | 1);
    assert_eq!(m.reg(Region::Apb, 0x604), 1);
    assert_eq!(m.reg(Region::Apb, 0x608), 0);
    assert_eq!(m.reg(Region::Apb, 0x60c), 0);

    // No dma-ranges: the block's own translation is left alone.
    let m = plda_mock(0);
    plda::init(&m, &plda_cfg(&[], &[])).unwrap();
    assert!(m.writes(Region::Apb, 0x600).is_empty());
}

#[test]
fn plda_msi_hookup_point() {
    let m = plda_mock(0);
    let r = plda::init(&m, &plda_cfg(&[], &[])).unwrap();
    let msi = r.msi.unwrap();
    // The doorbell is the configured bus address, never a register offset,
    // and it is what the bridge was told to decode (IMSI_ADDR, written once).
    assert_eq!((msi.doorbell, msi.vectors, msi.data_base), (VF2_MSI_DOORBELL, 32, 0));
    assert_eq!(m.writes(Region::Apb, 0x190), vec![VF2_MSI_DOORBELL as u32]);
    assert_eq!((msi.status_off, msi.ack_off), (0x194, 0x194));
    assert_eq!(msi.summary, Some((0x184, 0x1000_0000)));
}

#[test]
fn plda_bad_msi_doorbell_is_refused_before_any_register() {
    for bad in [0x1_0000_0000u64, 0x2c00_0002, 0x190 | (1 << 40)] {
        let mut c = plda_cfg(&[], &[]);
        c.msi_doorbell = bad;
        let m = plda_mock(0);
        assert_eq!(plda::init(&m, &c).unwrap_err(), HostError::BadMsiDoorbell, "{bad:#x}");
        assert!(m.log().is_empty());
    }
}

#[test]
fn plda_link_down_does_not_write_the_msi_doorbell() {
    let m = plda_mock(u64::MAX);
    plda::init(&m, &plda_cfg(&[], &[])).unwrap_err();
    assert!(m.writes(Region::Apb, 0x190).is_empty());
}

#[test]
fn plda_link_up_late_reports_the_wait() {
    // The first check is at 200 ms; the link is up from 250 ms; checks are
    // 90 ms apart, so it is seen at 290 ms.
    let m = plda_mock(250_000);
    let r = plda::init(&m, &plda_cfg(&[], &[])).unwrap();
    assert_eq!(r.link_wait_us, 90_000);
}

#[test]
fn plda_link_down_is_refused_before_any_window_is_opened() {
    let out = decode_ranges(&VF2_RANGES, 2);
    let m = plda_mock(u64::MAX);
    let e = plda::init(&m, &plda_cfg(&out, &[])).unwrap_err();
    assert_eq!(e, HostError::LinkDown { waited_us: 900_000 });
    let log = m.log();
    assert_eq!(*log.last().unwrap(), Ev::Perst(true), "the endpoint is held in reset again");
    assert_eq!(m.delays().iter().map(|&d| d as u64).sum::<u64>(), 100_000 + 100_000 + 900_000);
    assert!(
        !log.iter().any(|e| matches!(*e, Ev::Wr(Region::Apb, o, _) if (0x600..0x900).contains(&o))),
        "no ATR entry may be written for a link that is down: {log:#x?}"
    );
}

#[test]
fn plda_refuses_bad_windows_without_touching_a_register() {
    let good = decode_ranges(&VF2_RANGES, 2);
    // Size not a power of two.
    let mut bad = good.clone();
    bad[1].window.size = 0x0600_0000;
    let m = plda_mock(0);
    assert_eq!(plda::init(&m, &plda_cfg(&bad, &[])).unwrap_err(), HostError::BadOutbound(1));
    assert!(m.log().is_empty());

    // Not aligned to its size.
    let mut bad = good.clone();
    bad[0].window.cpu_base = 0x3400_0000;
    let m = plda_mock(0);
    assert_eq!(plda::init(&m, &plda_cfg(&bad, &[])).unwrap_err(), HostError::BadOutbound(0));
    assert!(m.log().is_empty());

    // Too many for the table (entry 0 is the config window).
    let many = vec![good[0]; plda::MAX_ATR];
    let m = plda_mock(0);
    assert_eq!(plda::init(&m, &plda_cfg(&many, &[])).unwrap_err(), HostError::TooManyOutbound);
    assert!(m.log().is_empty());

    // The ECAM window itself.
    let mut c = plda_cfg(&good, &[]);
    c.cfg_size = 0x0c00_0000;
    let m = plda_mock(0);
    assert_eq!(plda::init(&m, &c).unwrap_err(), HostError::BadConfigWindow);
    assert!(m.log().is_empty());

    // Inbound.
    let inb = [InboundWindow { bus_base: 0x1000, cpu_base: 0, size: 0x2000 }];
    let m = plda_mock(0);
    assert_eq!(plda::init(&m, &plda_cfg(&good, &inb)).unwrap_err(), HostError::BadInbound(0));
    assert!(m.log().is_empty());
}

// ---------------------------------------------------------------------
// brcmstb / BCM2712
// ---------------------------------------------------------------------

const BR_STATUS: u32 = 0x4068;

fn br_cfg<'a>(out: &'a [OutboundWindow], inb: &'a [InboundWindow]) -> brcmstb::BrcmConfig<'a> {
    brcmstb::BrcmConfig { outbound: out, inbound: inb, link_timeout_us: brcmstb::DEFAULT_LINK_TIMEOUT_US }
}

/// A root complex whose link is up from `up_at_us`.
fn br_mock(up_at_us: u64) -> Mock {
    Mock::new()
        .with_reg(Region::Apb, BR_STATUS, 0x80)
        .with_reg(Region::Apb, 0x4304, 0x0800_0000 | 0x1)
        .with_link(Region::Apb, BR_STATUS, 0x30, up_at_us)
}

#[test]
fn brcm_init_sequence_order() {
    let out = decode_ranges(&PI5_RANGES, 2);
    let inb = decode_dma_ranges(&PI5_DMA_RANGES);
    let m = br_mock(0);
    let r = brcmstb::init(&m, &br_cfg(&out, &inb)).unwrap();
    assert_eq!(r.config, ConfigAccess::Indirect { index_off: 0x9000, data_off: 0x8000 });

    assert_order(&m.log(), &[
        ("PERST# asserted", &wr_val(Region::Apb, 0x4064, 0x0)),
        ("PERST# hold", &|e| *e == Ev::Delay(100_000)),
        ("bridge reset", &wr_val(Region::Apb, 0x9210, 0x2)),
        ("reset settle", &|e| *e == Ev::Delay(200)),
        ("bridge out of reset", &wr_val(Region::Apb, 0x9210, 0x0)),
        ("SerDes powered", &wr_val(Region::Apb, 0x4304, 0x1)),
        ("misc control", &wr(Region::Apb, 0x4008)),
        ("inbound BAR", &wr(Region::Apb, 0x402c)),
        ("root-complex check", &rd(Region::Apb, BR_STATUS)),
        ("class code", &wr(Region::Apb, 0x43c)),
        ("outbound window", &wr(Region::Apb, 0x400c)),
        ("PHY tuning", &wr_val(Region::Apb, 0x1104, 0x8000_1600)),
        ("MSI BAR", &wr(Region::Apb, 0x4044)),
        ("PERST# released", &wr_val(Region::Apb, 0x4064, 0x4)),
        ("config settle", &|e| *e == Ev::Delay(100_000)),
        ("link poll", &rd(Region::Apb, BR_STATUS)),
    ]);
    // Read-modify-write kept the neighbours: SCB access, UR mode, 512 B burst,
    // RCB MPS and 64 B modes.
    assert_eq!(m.reg(Region::Apb, 0x4008), 0x1000 | 0x2000 | (2 << 20) | 0x400 | 0x80);
    assert_eq!(m.reg(Region::Apb, 0x4304), 0x1);
}

#[test]
fn brcm_windows_programmed_from_fixture_ranges() {
    let out = decode_ranges(&PI5_RANGES, 2);
    let inb = decode_dma_ranges(&PI5_DMA_RANGES);
    let m = br_mock(0);
    brcmstb::init(&m, &br_cfg(&out, &inb)).unwrap();

    // Window 0: CPU 0x1f_0000_0000.. (0xfffffffc bytes) -> bus 0. In MiB the
    // base is 0x1f000 (low 12 bits 0, high 0x1f), the limit 0x1ffff (0xfff,
    // 0x1f).
    assert_eq!((m.reg(Region::Apb, 0x400c), m.reg(Region::Apb, 0x4010)), (0, 0));
    assert_eq!(m.reg(Region::Apb, 0x4070), 0xfff0_0000);
    assert_eq!(m.reg(Region::Apb, 0x4080), 0x1f);
    assert_eq!(m.reg(Region::Apb, 0x4084), 0x1f);
    // Window 1: CPU 0x1b_8010_0000 + 1 GiB -> bus 0x4_0010_0000. Base MiB
    // 0x1b801 (0x801, 0x1b), limit MiB 0x1bc00 (0xc00, 0x1b).
    assert_eq!((m.reg(Region::Apb, 0x4014), m.reg(Region::Apb, 0x4018)), (0x0010_0000, 0x4));
    assert_eq!(m.reg(Region::Apb, 0x4074), (0xc00 << 20) | (0x801 << 4));
    assert_eq!(m.reg(Region::Apb, 0x4088), 0x1b);
    assert_eq!(m.reg(Region::Apb, 0x408c), 0x1b);
    // Windows 2, 3 untouched.
    assert!(m.writes(Region::Apb, 0x401c).is_empty() && m.writes(Region::Apb, 0x4078).is_empty());

    // Inbound: RC BAR1, 64 GiB (size code 36 - 15 = 21) at bus 0x10_0000_0000,
    // UBUS remap to CPU 0 with access enabled.
    assert_eq!(m.reg(Region::Apb, 0x402c), 21);
    assert_eq!(m.reg(Region::Apb, 0x4030), 0x10);
    assert_eq!(m.reg(Region::Apb, 0x40ac), 1);
    assert_eq!(m.reg(Region::Apb, 0x40b0), 0);
    // Class code: only the low 24 bits are replaced.
    let m = br_mock(0).with_reg(Region::Apb, 0x43c, 0xab00_1234);
    brcmstb::init(&m, &br_cfg(&out, &inb)).unwrap();
    assert_eq!(m.reg(Region::Apb, 0x43c), 0xab06_0400);
}

#[test]
fn brcm_fifth_inbound_window_uses_the_second_register_bank() {
    // Five windows of 4 GiB: bus (i + 1) << 32 -> CPU i << 32.
    let inb: Vec<_> = (0..5u64)
        .map(|i| InboundWindow { bus_base: (i + 1) << 32, cpu_base: i << 32, size: 1 << 32 })
        .collect();
    let m = br_mock(0);
    brcmstb::init(&m, &br_cfg(&[], &inb)).unwrap();
    // Window 3 (last of the first bank) and windows 4, 5 (second bank).
    for (n, lo, remap) in [(3u64, 0x403c, 0x40bc), (4, 0x40d4, 0x410c), (5, 0x40dc, 0x4114)] {
        assert_eq!(m.reg(Region::Apb, lo), 17, "size code of 4 GiB (32 - 15)");
        assert_eq!(m.reg(Region::Apb, lo + 4), n as u32);
        assert_eq!(m.reg(Region::Apb, remap), 1);
        assert_eq!(m.reg(Region::Apb, remap + 4), (n - 1) as u32);
    }
}

#[test]
fn brcm_small_inbound_window_size_code() {
    // 4 KiB .. 32 KiB use the 0x1c.. codes.
    let inb = [InboundWindow { bus_base: 0x8000, cpu_base: 0x4000_0000, size: 0x1000 }];
    let m = br_mock(0);
    brcmstb::init(&m, &br_cfg(&[], &inb)).unwrap();
    assert_eq!(m.reg(Region::Apb, 0x402c), 0x8000 | 0x1c);
    assert_eq!(m.reg(Region::Apb, 0x40ac), 0x4000_0000 | 1);
}

#[test]
fn brcm_msi_doorbell_avoids_inbound_windows() {
    let hook = |inb: &[InboundWindow]| {
        let m = br_mock(0);
        let r = brcmstb::init(&m, &br_cfg(&[], inb)).unwrap();
        (m, r.msi)
    };
    // Fixture: nothing covers the low doorbell.
    let (m, msi) = hook(&decode_dma_ranges(&PI5_DMA_RANGES));
    let msi = msi.unwrap();
    assert_eq!((msi.doorbell, msi.vectors, msi.data_base), (0x0_ffff_fffc, 32, 0x6540));
    assert_eq!((msi.status_off, msi.ack_off, msi.summary), (0x4500, 0x4508, None));
    assert_eq!(m.reg(Region::Apb, 0x4044), 0xffff_fffd);
    assert_eq!(m.reg(Region::Apb, 0x4048), 0);
    assert_eq!(m.reg(Region::Apb, 0x404c), 0xffe0_6540);
    assert_eq!(m.reg(Region::Apb, 0x4514), u32::MAX, "vectors unmasked");

    // A window over the first 4 GiB moves it above.
    let (m, msi) = hook(&[InboundWindow { bus_base: 0, cpu_base: 0, size: 1 << 32 }]);
    assert_eq!(msi.unwrap().doorbell, 0xf_ffff_fffc);
    assert_eq!((m.reg(Region::Apb, 0x4044), m.reg(Region::Apb, 0x4048)), (0xffff_fffd, 0xf));

    // Both covered: MSIs are not offered and the MSI registers stay alone.
    let (m, msi) = hook(&[InboundWindow { bus_base: 0, cpu_base: 0, size: 1 << 36 }]);
    assert!(msi.is_none());
    assert!(m.writes(Region::Apb, 0x4044).is_empty());
}

#[test]
fn brcm_link_up_late_reports_the_wait() {
    // 100 ms PERST# hold, 200 + 200 + 200 us of setup, 100 ms settle: the
    // first check is at 200.6 ms. Up from 230 ms: seen after six 5 ms steps.
    let m = br_mock(230_000);
    let r = brcmstb::init(&m, &br_cfg(&[], &[])).unwrap();
    assert_eq!(r.link_wait_us, 30_000);
}

#[test]
fn brcm_link_down_is_refused_and_perst_asserted_again() {
    let m = br_mock(u64::MAX);
    let e = brcmstb::init(&m, &br_cfg(&[], &[])).unwrap_err();
    assert_eq!(e, HostError::LinkDown { waited_us: 100_000 });
    // PERSTB (active low) cleared by the last write to the control register.
    assert_eq!(*m.writes(Region::Apb, 0x4064).last().unwrap() & 0x4, 0);
    assert_eq!(m.writes(Region::Apb, 0x4064).len(), 3, "held, released, then asserted");
}

#[test]
fn brcm_half_up_link_is_down() {
    // Data-link active without PHY link-up (or the reverse) is not a link.
    for bits in [0x20u32, 0x10] {
        let m = Mock::new().with_reg(Region::Apb, BR_STATUS, 0x80 | bits);
        assert_eq!(
            brcmstb::init(&m, &br_cfg(&[], &[])).unwrap_err(),
            HostError::LinkDown { waited_us: 100_000 }
        );
    }
}

#[test]
fn brcm_endpoint_mode_and_dead_phy_are_refused() {
    let m = Mock::new().with_reg(Region::Apb, BR_STATUS, 0x30);
    assert_eq!(brcmstb::init(&m, &br_cfg(&[], &[])).unwrap_err(), HostError::NotRootComplex);
    // PERST# is held first, and never released on a refusal.
    let released = |m: &Mock| m.writes(Region::Apb, 0x4064).iter().any(|w| w & 0x4 != 0);
    assert!(!released(&m), "PERST# never released");

    let mut m = br_mock(0);
    m.mdio_stuck = true;
    assert_eq!(brcmstb::init(&m, &br_cfg(&[], &[])).unwrap_err(), HostError::MdioTimeout);
    assert!(!released(&m));
}

#[test]
fn brcm_refuses_bad_windows_without_touching_a_register() {
    let good = decode_ranges(&PI5_RANGES, 2);
    let run = |out: &[OutboundWindow], inb: &[InboundWindow]| {
        let m = br_mock(0);
        let e = brcmstb::init(&m, &br_cfg(out, inb)).unwrap_err();
        assert!(m.log().is_empty(), "{e:?} touched registers");
        e
    };
    // Not MiB aligned.
    let mut bad = good.clone();
    bad[1].window.cpu_base += 0x1000;
    assert_eq!(run(&bad, &[]), HostError::BadOutbound(1));
    // CPU address beyond the 40 bits the base/limit registers hold.
    let mut bad = good.clone();
    bad[0].window.cpu_base = 1 << 40;
    assert_eq!(run(&bad, &[]), HostError::BadOutbound(0));
    // A fifth window.
    assert_eq!(run(&vec![good[0]; 5], &[]), HostError::TooManyOutbound);
    // Sizes the RC BAR code cannot express: 2 KiB, 128 GiB, not a power of two.
    for size in [0x800u64, 1 << 37, 0x3000] {
        let inb = [InboundWindow { bus_base: 0, cpu_base: 0, size }];
        assert_eq!(run(&[], &inb), HostError::BadInbound(0), "size {size:#x}");
    }
    // Bus base not aligned to the size.
    let inb = [InboundWindow { bus_base: 0x1000_0000, cpu_base: 0, size: 1 << 32 }];
    assert_eq!(run(&[], &inb), HostError::BadInbound(0));
    // Eleven inbound windows.
    let inb = vec![InboundWindow { bus_base: 0, cpu_base: 0, size: 0x1000 }; 11];
    assert_eq!(run(&[], &inb), HostError::TooManyInbound);
}

// ---------------------------------------------------------------------
// Config access
// ---------------------------------------------------------------------

#[test]
fn ecam_port_reads_the_cfg_window() {
    let m = Mock::new().with_reg(Region::Cfg, 0x10_0000, 0x1234_1af4);
    let port = ConfigPort::new(&m, ConfigAccess::Ecam { size: 16 << 20 });
    assert!(function_exists(&port, Bdf::new(1, 0, 0)));
    assert_eq!(port.read16(Bdf::new(1, 0, 0), OFF_DEVICE_ID), 0x1234);
    assert!(!function_exists(&port, Bdf::new(1, 1, 0)), "nothing decodes there: all ones");
    assert_eq!(m.log()[0], Ev::Rd(Region::Cfg, 0x10_0000));
    // An offset past 4 KiB is nobody's.
    assert_eq!(port.read32(Bdf::new(1, 0, 0), 4096), u32::MAX);
}

#[test]
fn ecam_port_refuses_a_bus_past_the_window() {
    // A 16 MiB window covers buses 0..=15 (the JH7110 sizing); bus 16 would
    // read 16 MiB past the mapping.
    let size = 16u64 << 20;
    let m = Mock::new().with_reg(Region::Cfg, 0xf0_0000, 0x1234_1af4);
    let mut port = ConfigPort::new(&m, ConfigAccess::Ecam { size });
    assert_eq!(port.read32(Bdf::new(15, 0, 0), 0), 0x1234_1af4, "last bus is inside");
    m.log.borrow_mut().clear();
    for bdf in [Bdf::new(16, 0, 0), Bdf::new(255, 31, 7)] {
        assert_eq!(port.read32(bdf, 0), u32::MAX, "{bdf}");
        port.write32(bdf, 4, 7);
    }
    // The last dword of the last function is inside; the next one is not.
    assert_eq!(port.read32(Bdf::new(15, 31, 7), 4092), u32::MAX);
    assert_eq!(m.log(), vec![Ev::Rd(Region::Cfg, 0xf0_0000 + (31 << 15) + (7 << 12) + 4092)]);
    // A window smaller than a bus: only what fits.
    let m = Mock::new();
    let port = ConfigPort::new(&m, ConfigAccess::Ecam { size: 0x2000 });
    port.read32(Bdf::new(0, 0, 1), 4092);
    assert_eq!(port.read32(Bdf::new(0, 0, 2), 0), u32::MAX);
    assert_eq!(m.log(), vec![Ev::Rd(Region::Cfg, 0x1000 + 4092)]);
}

#[test]
fn indirect_port_goes_through_index_and_data() {
    let m = Mock::new()
        .with_reg(Region::Apb, 0x8000, 0x2712_14e4) // data window: the endpoint
        .with_reg(Region::Apb, 0x0, 0x2712_14e4 + 1); // the root complex itself
    let mut port = ConfigPort::new(&m, ConfigAccess::Indirect { index_off: 0x9000, data_off: 0x8000 });

    // Bus 0 device 0 is the root complex, directly, no index write.
    assert_eq!(port.read32(Bdf::new(0, 0, 0), 0), 0x2712_14e5);
    assert_eq!(m.log(), vec![Ev::Rd(Region::Apb, 0)]);

    // Bus 1 device 0: index = bus << 20 | dev << 15 | fn << 12, then data.
    m.log.borrow_mut().clear();
    assert_eq!(port.read32(Bdf::new(1, 0, 2), 0), 0x2712_14e4);
    assert_eq!(m.log(), vec![Ev::Wr(Region::Apb, 0x9000, (1 << 20) | (2 << 12)), Ev::Rd(Region::Apb, 0x8000)]);

    // Deeper buses are not filtered: index, then data at +offset.
    m.log.borrow_mut().clear();
    port.write32(Bdf::new(2, 5, 1), 0x10, 0xdead_beef);
    assert_eq!(
        m.log(),
        vec![Ev::Wr(Region::Apb, 0x9000, (2 << 20) | (5 << 15) | (1 << 12)), Ev::Wr(Region::Apb, 0x8010, 0xdead_beef)]
    );
}

#[test]
fn indirect_port_does_not_alias_a_point_to_point_link() {
    let m = Mock::new();
    let mut port = ConfigPort::new(&m, ConfigAccess::Indirect { index_off: 0x9000, data_off: 0x8000 });
    for bdf in [Bdf::new(0, 1, 0), Bdf::new(0, 0, 1), Bdf::new(1, 1, 0), Bdf::new(1, 31, 0)] {
        assert_eq!(port.read32(bdf, 0), u32::MAX, "{bdf}");
        port.write32(bdf, 4, 7);
    }
    assert!(m.log().is_empty(), "no bus traffic for functions that cannot exist");
}
