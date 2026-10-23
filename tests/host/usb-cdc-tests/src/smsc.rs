// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SMSC LAN95xx Ethernet function (`azos_usb::class::smsc95xx`) against a
//! fake LAN9514 behind the register-level xHCI mock: a register file answered
//! through the vendor requests (lite and PHY resets that take a few reads to
//! clear, an MII bridge to a PHY whose reset takes a few reads too), bursts of
//! frames with status words on bulk IN, frames with command words on bulk OUT.
//! And the same function through the kernel's NIC adapter (`usb_net.rs`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use azos_devif::outcome::{OK, UNSUPPORTED};
use azos_devif::Out;
use azos_drv_api::net::NetDevice;
use azos_usb::class::cdc::{Fail, SendError, State, FRAME_MAX};
use azos_usb::class::net::NetFunction;
use azos_usb::class::smsc95xx::*;
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::Clock;
use azos_usb_tests::devices::{config_desc, device_desc, ep, iface, DevRef, MockDev};
use azos_usb_tests::harness::Rig;
use azos_usb_tests::mock::{MockClock, MockMem};

const MAC: [u8; 6] = [0xb8, 0x27, 0xeb, 0x12, 0x34, 0x56];

type Smsc = Smsc95xx<'static, MockMem, MockClock>;

/// The chip's state, shared with the device model's vendor hook.
#[derive(Default)]
struct Chip {
    regs: HashMap<u16, u32>,
    phy: HashMap<u32, u32>,
    /// Reads left before LRST, PHY_RST and the BMCR reset bit clear.
    lrst_reads: u32,
    phy_rst_reads: u32,
    bmcr_reads: u32,
    /// Every register write, in order.
    writes: Vec<(u16, u32)>,
    /// A register whose access stalls.
    stall: Option<u16>,
}

fn chip_model(chip: Rc<RefCell<Chip>>) -> Box<dyn FnMut([u8; 8], &[u8]) -> Result<Vec<u8>, ()>> {
    Box::new(move |setup, out| {
        let mut c = chip.borrow_mut();
        let reg = u16::from_le_bytes([setup[4], setup[5]]);
        if c.stall == Some(reg) {
            return Err(());
        }
        match (setup[0], setup[1]) {
            (0xc0, REQ_READ_REGISTER) => {
                let mut v = *c.regs.get(&reg).unwrap_or(&0);
                if reg == HW_CFG && v & HW_CFG_LRST != 0 {
                    if c.lrst_reads == 0 {
                        v &= !HW_CFG_LRST;
                        c.regs.insert(reg, v);
                    } else {
                        c.lrst_reads -= 1;
                    }
                }
                if reg == PM_CTRL && v & PM_CTRL_PHY_RST != 0 {
                    if c.phy_rst_reads == 0 {
                        v &= !PM_CTRL_PHY_RST;
                        c.regs.insert(reg, v);
                    } else {
                        c.phy_rst_reads -= 1;
                    }
                }
                Ok(v.to_le_bytes().to_vec())
            }
            (0x40, REQ_WRITE_REGISTER) => {
                let v = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
                c.writes.push((reg, v));
                if reg == MII_ADDR {
                    let idx = (v >> 6) & 0x1f;
                    if v & MII_WRITE != 0 {
                        let d = *c.regs.get(&MII_DATA).unwrap_or(&0);
                        c.phy.insert(idx, d);
                    } else {
                        let mut d = *c.phy.get(&idx).unwrap_or(&0);
                        if idx == MII_BMCR && d & BMCR_RESET != 0 {
                            if c.bmcr_reads == 0 {
                                d &= !BMCR_RESET;
                                c.phy.insert(idx, d);
                            } else {
                                c.bmcr_reads -= 1;
                            }
                        }
                        c.regs.insert(MII_DATA, d);
                    }
                    // The MII bridge is never busy for long: clear at once.
                    c.regs.insert(MII_ADDR, v & !MII_BUSY);
                    return Ok(vec![]);
                }
                c.regs.insert(reg, v);
                Ok(vec![])
            }
            _ => Err(()),
        }
    })
}

/// A LAN9514's Ethernet function: high speed, one vendor interface with bulk
/// IN 1, bulk OUT 2 and an interrupt IN 3.
fn lan9514(chip: &Rc<RefCell<Chip>>) -> DevRef {
    let dd = device_desc(0x0200, 0xff, 0, 0xff, 64, VID_SMSC, 0xec00, 0, 0);
    let cfg = config_desc(1, &[iface(0, 0xff, 0, 0xff, vec![ep(0x81, 2, 512, 0), ep(0x02, 2, 512, 0), ep(0x83, 3, 16, 4)])]);
    let mut d = MockDev::new(3, dd, cfg);
    {
        let mut c = chip.borrow_mut();
        c.regs.insert(ID_REV, 0xec00_0002);
        c.lrst_reads = 2;
        c.phy_rst_reads = 1;
        c.bmcr_reads = 2;
    }
    d.vendor = Some(chip_model(chip.clone()));
    d.into_ref()
}

struct Handle<'a>(&'a RefCell<Smsc>);

impl UsbClass for Handle<'_> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        self.0.borrow_mut().attach(claim, vid_pid, triple, speed_port)
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        self.0.borrow_mut().detach(claim)
    }
}

struct Bench {
    rig: Rig,
    net: RefCell<Smsc>,
    dev: DevRef,
    chip: Rc<RefCell<Chip>>,
}

impl Bench {
    fn with(chip: Chip) -> Bench {
        let chip = Rc::new(RefCell::new(chip));
        let rig = Rig::new();
        let net = RefCell::new(Smsc95xx::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..], MAC));
        let dev = lan9514(&chip);
        rig.hw.attach_root(1, dev.clone());
        let mut b = Bench { rig, net, dev, chip };
        b.until(|b| !matches!(b.state(), State::Idle | State::Claimed | State::Setup), 3000);
        b
    }

    fn new() -> Bench {
        Bench::with(Chip::default())
    }

    fn state(&self) -> State {
        self.net.borrow().state()
    }

    fn turn(&mut self) {
        let mut h = UsbClassDirect(Handle(&self.net));
        let mut reg = Registry::new();
        reg.register(0, Smsc::rule(), &mut h).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        loop {
            let c = self.net.borrow().session_wanted();
            let Some(c) = c else { break };
            let mut s = self.rig.usb.session(c);
            self.net.borrow_mut().open(&mut s);
        }
        self.net.borrow_mut().service();
        self.rig.hw.clock().delay_us(1_000);
    }

    fn until(&mut self, mut done: impl FnMut(&mut Bench) -> bool, max: u32) -> bool {
        for _ in 0..max {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    fn run(&mut self, n: u32) {
        for _ in 0..n {
            self.turn();
        }
    }

    fn reg(&self, r: u16) -> u32 {
        *self.chip.borrow().regs.get(&r).unwrap_or(&0)
    }

    fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut out = vec![];
        let mut buf = vec![0u8; 2048];
        loop {
            let n = self.net.borrow_mut().recv(&mut buf);
            if n == 0 {
                break;
            }
            out.push(buf[..n].to_vec());
        }
        out
    }

    fn sent(&self) -> Vec<Vec<u8>> {
        self.dev.borrow().out_log.iter().filter(|(e, _)| *e == 2).map(|(_, d)| d.clone()).collect()
    }
}

fn eth(n: usize, tag: u8) -> Vec<u8> {
    let mut f = vec![0u8; n];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&MAC);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    for (i, b) in f.iter_mut().enumerate().skip(14) {
        *b = tag.wrapping_add(i as u8);
    }
    f
}

/// A frame as the chip hands it up: the status word, the frame, an FCS, the
/// padding to the next 32-bit boundary.
fn rx_entry(frame: &[u8], flagged: bool) -> Vec<u8> {
    let len = (frame.len() + FCS_LEN) as u32;
    let sts = len << RX_STS_FL_SHIFT | if flagged { RX_STS_ES } else { 0 };
    let mut v = sts.to_le_bytes().to_vec();
    v.extend_from_slice(frame);
    v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

// ---- Setup ----

#[test]
fn the_function_comes_up_with_its_mac_and_the_mac_running() {
    let b = Bench::new();
    assert_eq!(b.state(), State::Ready);
    assert_eq!(b.net.borrow().chip(), 0xec00);
    assert_eq!(NetFunction::mac(&*b.net.borrow()), MAC);
    assert_eq!(b.reg(ADDRL), u32::from_le_bytes([MAC[0], MAC[1], MAC[2], MAC[3]]));
    assert_eq!(b.reg(ADDRH), u16::from_le_bytes([MAC[4], MAC[5]]) as u32);
    let hw = b.reg(HW_CFG);
    assert_eq!(hw & (HW_CFG_BIR | HW_CFG_MEF | HW_CFG_BCE), HW_CFG_BIR | HW_CFG_MEF | HW_CFG_BCE);
    assert_eq!(hw & (HW_CFG_LRST | HW_CFG_RXDOFF), 0);
    assert_eq!(b.reg(BURST_CAP), (RX_BYTES / 512) as u32);
    let mac_cr = b.reg(MAC_CR);
    assert_eq!(mac_cr & (MAC_CR_TXEN | MAC_CR_RXEN | MAC_CR_MCPAS), MAC_CR_TXEN | MAC_CR_RXEN | MAC_CR_MCPAS);
    assert_eq!(mac_cr & (MAC_CR_PRMS | MAC_CR_BCAST), 0, "promiscuous off, broadcast received");
    assert_eq!(b.reg(TX_CFG), TX_CFG_ON);
    let phy = &b.chip.borrow().phy;
    assert_eq!(phy.get(&MII_ADVERTISE), Some(&ADVERTISE_ALL_PAUSE));
    assert_eq!(phy.get(&PHY_INT_MASK), Some(&PHY_INT_MASK_DEFAULT));
    assert_eq!(phy.get(&MII_BMCR), Some(&(BMCR_ANENABLE | BMCR_ANRESTART)));
}

#[test]
fn the_resets_are_waited_for_before_the_next_step() {
    let b = Bench::new();
    let w = &b.chip.borrow().writes;
    let pos = |reg: u16, v: u32| w.iter().position(|&x| x == (reg, v)).unwrap_or_else(|| panic!("{reg:#x}={v:#x} never written"));
    // The MAC address goes in after both resets, which took reads to clear.
    assert!(pos(HW_CFG, HW_CFG_LRST) < pos(PM_CTRL, PM_CTRL_PHY_RST));
    assert!(pos(PM_CTRL, PM_CTRL_PHY_RST) < pos(ADDRL, u32::from_le_bytes([MAC[0], MAC[1], MAC[2], MAC[3]])));
    // The receiver comes last, after the transmitter.
    let tx = w.iter().position(|&(r, v)| r == TX_CFG && v == TX_CFG_ON).unwrap();
    let rx = w.iter().rposition(|&(r, v)| r == MAC_CR && v & MAC_CR_RXEN != 0).unwrap();
    assert!(tx < rx);
}

#[test]
fn a_register_the_chip_refuses_fails_the_function() {
    let b = Bench::with(Chip { stall: Some(LED_GPIO_CFG), ..Chip::default() });
    assert!(matches!(b.state(), State::Failed(Fail::Control(_))), "{:?}", b.state());
    assert_eq!(NetFunction::mac(&*b.net.borrow()), [0; 6]);
}

#[test]
fn a_vendor_interface_of_another_chip_is_not_taken() {
    let rig = Rig::new();
    let mut s = Smsc95xx::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..], MAC);
    let claim = azos_usb::Claim::new(1, 0, 1).0;
    assert_eq!(s.attach(claim, 0x0bda_8153, 0xff_00_00, 3 << 8 | 1).code, UNSUPPORTED, "a Realtek r8153");
    assert_eq!(s.attach(claim, (VID_SMSC as u32) << 16 | 0xec00, 0xff_00_ff, 3 << 8 | 1).code, OK);
}

// ---- Data ----

#[test]
fn a_burst_of_frames_is_handed_up_frame_by_frame_without_the_fcs() {
    let mut b = Bench::new();
    let (f1, f2, f3) = (eth(60, 1), eth(1514, 2), eth(99, 3));
    let mut burst = rx_entry(&f1, false);
    burst.extend(rx_entry(&f2, false));
    burst.extend(rx_entry(&eth(70, 9), true));
    burst.extend(rx_entry(&f3, false));
    b.rig.hw.inject_in(&b.dev, 1, &burst);
    b.run(2);
    assert!(NetFunction::rx_pending(&*b.net.borrow()));
    assert_eq!(b.drain(), vec![f1, f2, f3]);
    let st = b.net.borrow().stats();
    assert_eq!((st.rx_frames, st.rx_errors), (3, 1), "the flagged frame is counted, not handed up");
}

#[test]
fn a_status_word_that_runs_past_the_transfer_ends_it() {
    let mut b = Bench::new();
    let f1 = eth(60, 1);
    let mut burst = rx_entry(&f1, false);
    // A status word that claims 1500 bytes, with 20 left.
    let lie = 1500u32 << RX_STS_FL_SHIFT;
    burst.extend(lie.to_le_bytes());
    burst.extend(eth(20, 7));
    b.rig.hw.inject_in(&b.dev, 1, &burst);
    b.run(2);
    assert_eq!(b.drain(), vec![f1]);
    assert_eq!(b.net.borrow().stats().ntb_malformed, 1);
    // The buffer went back: the next burst comes in.
    let f2 = eth(64, 4);
    b.rig.hw.inject_in(&b.dev, 1, &rx_entry(&f2, false));
    b.run(2);
    assert_eq!(b.drain(), vec![f2]);
}

#[test]
fn the_parser_never_reads_past_the_transfer() {
    assert_eq!(frame_at(64 << RX_STS_FL_SHIFT, 0, 68), Some((4, 60, false, 68)));
    assert_eq!(frame_at(65 << RX_STS_FL_SHIFT, 0, 72), Some((4, 61, false, 72)));
    assert_eq!(frame_at(65 << RX_STS_FL_SHIFT, 0, 68), None, "one byte past the end");
    assert_eq!(frame_at(3 << RX_STS_FL_SHIFT, 0, 68), None, "not even an FCS");
    assert_eq!(frame_at(RX_STS_FL_MASK << RX_STS_FL_SHIFT, usize::MAX - 2, 68), None);
}

#[test]
fn a_frame_goes_out_after_its_command_words() {
    let mut b = Bench::new();
    let f = eth(60, 5);
    assert_eq!(NetFunction::send(&mut *b.net.borrow_mut(), &f), Ok(()));
    b.run(1);
    let sent = b.sent();
    assert_eq!(sent.len(), 1);
    let s = &sent[0];
    assert_eq!(u32::from_le_bytes([s[0], s[1], s[2], s[3]]), TX_CMD_A_FIRST_SEG | TX_CMD_A_LAST_SEG | 60);
    assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 60);
    assert_eq!(&s[8..], &f[..]);
}

#[test]
fn a_transfer_ending_on_a_packet_boundary_gets_a_byte_of_padding() {
    let mut b = Bench::new();
    // 8 + 504 = 512: one byte more, stated in both command words.
    let f = eth(504, 6);
    assert_eq!(NetFunction::send(&mut *b.net.borrow_mut(), &f), Ok(()));
    b.run(1);
    let s = &b.sent()[0];
    assert_eq!(s.len(), 513);
    assert_eq!(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) & 0x7ff, 505);
    assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 505);
    assert_eq!(&s[8..512], &f[..]);
}

#[test]
fn lengths_outside_an_ethernet_frame_are_refused() {
    let b = Bench::new();
    let mut n = b.net.borrow_mut();
    assert_eq!(NetFunction::send(&mut *n, &[0; 13]), Err(SendError::BadLength));
    assert_eq!(NetFunction::send(&mut *n, &vec![0; FRAME_MAX + 1]), Err(SendError::BadLength));
}

#[test]
fn an_unplugged_function_is_cleaned_up_and_a_new_one_comes_up() {
    let mut b = Bench::new();
    b.rig.hw.detach_root(1);
    b.until(|b| b.state() == State::Idle, 500);
    assert_eq!(b.state(), State::Idle);
    let dev = lan9514(&b.chip);
    b.dev = dev.clone();
    b.rig.hw.attach_root(1, dev);
    b.until(|b| b.state() == State::Ready, 3000);
    assert_eq!(b.state(), State::Ready);
}

// ---- Through the kernel's adapter ----

#[test]
fn the_adapter_makes_the_function_a_nic() {
    use crate::usb_net::{Event, UsbNic};
    fn kick() {}
    let chip = Rc::new(RefCell::new(Chip::default()));
    let mut rig = Rig::new();
    let nic = UsbNic::new(
        Smsc95xx::new(crate::nic::SendMem(rig.hw.mem()), crate::nic::SendClock(rig.hw.clock()), u64::MAX, &rig.rings[..], MAC),
        kick,
    );
    let dev = lan9514(&chip);
    rig.hw.attach_root(1, dev.clone());
    let mut events = vec![];
    for _ in 0..3000 {
        // One rule: one registry entry.
        let [rule] = <Smsc95xx<'static, crate::nic::SendMem, crate::nic::SendClock> as NetFunction>::RULES else { panic!() };
        let mut h = UsbClassDirect(nic.class());
        let mut reg = Registry::new();
        reg.register(0, *rule, &mut h).unwrap();
        rig.usb.service(&mut reg);
        drop(reg);
        let e = nic.drive(&mut rig.usb);
        if e != Event::None {
            events.push(e);
        }
        if nic.is_ready() {
            break;
        }
        rig.hw.clock().delay_us(1_000);
    }
    assert_eq!(events, vec![Event::Up]);
    assert_eq!(nic.mac(), MAC);
    let f = eth(100, 8);
    assert_eq!(nic.send(&f), Ok(100));
    rig.hw.inject_in(&dev, 1, &rx_entry(&f, false));
    let mut h = UsbClassDirect(nic.class());
    let mut reg = Registry::new();
    reg.register(0, Smsc95xx::<crate::nic::SendMem, crate::nic::SendClock>::rule(), &mut h).unwrap();
    rig.usb.service(&mut reg);
    drop(reg);
    nic.drive(&mut rig.usb);
    let mut buf = [0u8; 2048];
    assert_eq!(nic.recv(&mut buf), Ok(100));
    assert_eq!(&buf[..100], &f[..]);
}
