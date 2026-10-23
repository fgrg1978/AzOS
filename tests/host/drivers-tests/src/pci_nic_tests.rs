// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device half e1000e and igc share (`crates/drivers/net/src/pci_nic.rs`),
//! driven through BOTH drivers' wire maps over a register file in host memory
//! and descriptors the test plays the controller for.
//!
//! One scenario, run once per driver, each with its own `static` NIC: the
//! doorbells must land at that driver's `RDT`/`TDT`/`ICR` and nowhere else,
//! and the descriptors must be that driver's format. A driver whose paths
//! were its own copy of the ring code would not go through `Nic` at all;
//! `Nic` is generic over `Wire`, so these tests are the proof that the two
//! drivers' register maps and encoders plug into the same ring code.
//!
//! Wired by `mod pci_nic_tests;` in `lib.rs`.

use super::e1000e::{
    E1000eWire, EXT, ICR_LSC, ICR_RXT0, REG_RDT as E_RDT, REG_STATUS, REG_TDT as E_TDT, RXD_STAT_DD, RXD_STAT_EOP,
    STATUS_LU,
};
use super::igc::{family, IgcWire, Model};
use super::pci_nic::{rings_drivable, IrqRegs, Mem, Nic, Wire};
use azos_dma::Direction;
use azos_drv_api::net::NetError;
use azos_drv_virtio::virtio::Dma;

const N: usize = 8;
const BUF: usize = 2048;
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const TOKEN: u32 = 7;

/// A register file big enough for both maps (the highest offset is igc's
/// `TXDCTL` at 0xe028).
struct Regs(&'static [core::sync::atomic::AtomicU32]);

impl Regs {
    fn new() -> Regs {
        let v: Vec<core::sync::atomic::AtomicU32> = (0..0x4000).map(|_| core::sync::atomic::AtomicU32::new(0)).collect();
        Regs(Box::leak(v.into_boxed_slice()))
    }
    fn addr(&self) -> usize {
        self.0.as_ptr() as usize
    }
    fn get(&self, off: usize) -> u32 {
        self.0[off / 4].load(core::sync::atomic::Ordering::SeqCst)
    }
    fn set(&self, off: usize, v: u32) {
        self.0[off / 4].store(v, core::sync::atomic::Ordering::SeqCst)
    }
}

/// What the controller writes back for a good single-descriptor frame of
/// `len` bytes, in the format `W` decodes.
fn writeback_for<W: Wire>(len: u16) -> u64 {
    let st = (RXD_STAT_DD | RXD_STAT_EOP) as u64;
    let wire_is_legacy_e1000e = W::NAME == "e1000e" && !EXT;
    if wire_is_legacy_e1000e {
        // Legacy: length 15:0, status 39:32.
        len as u64 | st << 32
    } else {
        // Extended / advanced: status 7:0, length 47:32.
        st | (len as u64) << 32
    }
}

struct Rig<W: Wire> {
    nic: &'static Nic<W, N, N>,
    mem: &'static Mem<N, N>,
    regs: Regs,
    tx_buf_bus: u64,
    rx_buf_bus: u64,
}

fn bring_up<W: Wire>(
    nic: &'static Nic<W, N, N>,
    mem: &'static Mem<N, N>,
    msi_token: Option<u32>,
    irq: IrqRegs,
) -> Rig<W> {
    let regs = Regs::new();
    // The link is up, so the link wait ends at once.
    regs.set(REG_STATUS, STATUS_LU);
    nic.set_bar(regs.addr(), irq);
    let dma = Dma::fallback();
    let rx_buf_bus = dma.map(mem.rx_buf(0) as *const u8, N * BUF, Direction::FromDevice).unwrap();
    let tx_buf_bus = dma.map(mem.tx_buf(0) as *const u8, N * BUF, Direction::ToDevice).unwrap();
    nic.prime(&dma, rx_buf_bus);
    nic.go_live(dma, rx_buf_bus, tx_buf_bus, MAC, 0, msi_token);
    Rig { nic, mem, regs, tx_buf_bus, rx_buf_bus }
}

/// The controller delivers one frame in receive descriptor `i`.
fn deliver<W: Wire>(rig: &Rig<W>, i: usize, payload: &[u8]) {
    // SAFETY: the test is the controller; slot `i` is posted and idle.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), rig.mem.rx_buf(i), payload.len());
        (*rig.mem.rx_desc(i)).hi = writeback_for::<W>(payload.len() as u16);
    }
}

fn scenario<W: Wire>(rig: &Rig<W>) {
    // go_live: ready, the station address published, and the first tail
    // write handed the controller every receive descriptor but one -- at
    // THIS driver's RDT.
    assert!(rig.nic.is_ready());
    assert_eq!(rig.nic.mac(), MAC);
    assert_eq!(rig.regs.get(W::RX.tail), (N - 1) as u32);
    // The posted descriptors carry their own buffers.
    for i in 0..N {
        // SAFETY: reading the test's own ring.
        let d = unsafe { *rig.mem.rx_desc(i) };
        assert_eq!(d.lo, rig.rx_buf_bus + (i * BUF) as u64);
    }

    // Transmit: the frame is copied, the descriptor is this driver's format,
    // and the doorbell is this driver's TDT.
    let frame: Vec<u8> = (0..60u8).collect();
    assert_eq!(rig.nic.send(&frame), Ok(60));
    // SAFETY: reading the test's own ring and buffer.
    unsafe {
        assert_eq!(*rig.mem.tx_desc(0), W::tx_frame(rig.tx_buf_bus, 60));
        assert_eq!(core::slice::from_raw_parts(rig.mem.tx_buf(0), 60), &frame[..]);
    }
    assert_eq!(rig.regs.get(W::TX.tail), 1);
    // Not completed by the controller yet: a second frame takes slot 1.
    assert_eq!(rig.nic.send(&frame[..14]), Ok(14));
    assert_eq!(rig.regs.get(W::TX.tail), 2);

    // A batch shares one doorbell.
    rig.nic.tx_batch_begin();
    assert_eq!(rig.nic.send(&frame), Ok(60));
    assert_eq!(rig.nic.send(&frame), Ok(60));
    assert_eq!(rig.regs.get(W::TX.tail), 2, "inside a batch the doorbell waits");
    rig.nic.tx_batch_end();
    assert_eq!(rig.regs.get(W::TX.tail), 4);

    // Refusals.
    assert_eq!(rig.nic.send(&[]), Err(NetError::BadLength));
    assert_eq!(rig.nic.send(&[0u8; 1515]), Err(NetError::BadLength));

    // Receive: nothing posted back yet reads as empty ...
    let mut buf = [0u8; 2048];
    assert_eq!(rig.nic.recv(&mut buf), Ok(0));
    // ... a frame the controller wrote is copied out and its descriptor
    // re-posted whole ...
    let payload: Vec<u8> = (0..100u8).map(|b| b ^ 0x5a).collect();
    deliver(rig, 0, &payload);
    assert_eq!(rig.nic.recv(&mut buf), Ok(100));
    assert_eq!(&buf[..100], &payload[..]);
    // SAFETY: reading the test's own ring.
    let d = unsafe { *rig.mem.rx_desc(0) };
    assert_eq!(d.lo, rig.rx_buf_bus);
    assert_eq!(d.hi, 0, "re-posted whole: the write-back is gone");
    // ... and the tail follows the consumed descriptor (batch of one on a
    // ring this small): `clean` is 1, so the tail is 0.
    assert_eq!(rig.regs.get(W::RX.tail), 0);

    // A frame with an error bit is dropped here and the next one delivered.
    // SAFETY: the test is the controller.
    unsafe {
        (*rig.mem.rx_desc(1)).hi = writeback_for::<W>(60) | if W::NAME == "e1000e" && !EXT { 1u64 << 40 } else { 1u64 << 24 };
    }
    deliver(rig, 2, &payload[..64]);
    assert_eq!(rig.nic.recv(&mut buf), Ok(64), "the errored frame is skipped");
}

/// **Discriminates.** e1000e's wire map through the shared paths: its
/// doorbells, its descriptor format. Point the shared code at igc's `RDT`
/// and the tail assertions of the first block fail.
#[test]
fn e1000e_wire_runs_through_the_shared_rings() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<E1000eWire, N, N> = Nic::new(&MEM);
    let rig = bring_up(&NIC, &MEM, None, E1000eWire::IRQ);
    scenario(&rig);
    // Only e1000e's registers were written: igc's queue block is untouched.
    assert_eq!(rig.regs.get(IgcWire::RX.tail), 0);
    assert_eq!(rig.regs.get(IgcWire::TX.tail), 0);
    assert_eq!(E_RDT, E1000eWire::RX.tail);
    assert_eq!(E_TDT, E1000eWire::TX.tail);
}

/// **Discriminates.** igc's wire map through the same code: advanced
/// descriptors, the queue block at 0xc000/0xe000.
#[test]
fn igc_wire_runs_through_the_shared_rings() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<IgcWire, N, N> = Nic::new(&MEM);
    let rig = bring_up(&NIC, &MEM, None, IgcWire::IRQ);
    scenario(&rig);
    assert_eq!(rig.regs.get(E1000eWire::RX.tail), 0);
    assert_eq!(rig.regs.get(E1000eWire::TX.tail), 0);
}

/// **Discriminates.** The interrupt hook reads the function's own `ICR`,
/// only answers its own vector, counts receive causes and refreshes the
/// cached link on a link-change cause; before `go_live` armed it, it
/// answers nothing. `other` is the interrupt block of the other family:
/// nothing is unmasked there.
fn irq_scenario<W: Wire>(nic: &'static Nic<W, N, N>, mem: &'static Mem<N, N>, irq: IrqRegs, other: IrqRegs) {
    assert!(!nic.irq_driven());
    let rig = bring_up(nic, mem, Some(TOKEN), irq);
    assert!(nic.irq_driven());
    assert!(!nic.msi_irq(TOKEN + 1), "another vector's interrupt is not ours");
    assert_eq!(nic.rx_irq_count(), 0);
    rig.regs.set(irq.icr, ICR_RXT0);
    assert!(nic.msi_irq(TOKEN));
    assert_eq!(nic.rx_irq_count(), 1, "the receive cause is read at ICR {:#x}", irq.icr);
    // Link goes down: the cause refreshes the cache and sends are refused
    // (with the interrupt armed the cache is the only source).
    rig.regs.set(REG_STATUS, 0);
    rig.regs.set(irq.icr, ICR_LSC);
    assert!(nic.msi_irq(TOKEN));
    assert_eq!(nic.rx_irq_count(), 1, "a link change is not a receive cause");
    assert_eq!(nic.send(&[0u8; 60]), Err(NetError::NotReady));
    // Back up.
    rig.regs.set(REG_STATUS, STATUS_LU);
    rig.regs.set(irq.icr, ICR_LSC);
    assert!(nic.msi_irq(TOKEN));
    assert_eq!(nic.send(&[0u8; 60]), Ok(60));
    // The mask was set at this function's IMS, and only there.
    assert_ne!(rig.regs.get(irq.ims), 0);
    assert_eq!(rig.regs.get(other.ims), 0, "IMS {:#x} is the other family's", other.ims);
}

#[test]
fn e1000e_interrupt_hook_uses_its_own_icr() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<E1000eWire, N, N> = Nic::new(&MEM);
    irq_scenario(&NIC, &MEM, E1000eWire::IRQ, family(Model::I225).irq);
}

#[test]
fn igc_interrupt_hook_uses_its_own_icr() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<IgcWire, N, N> = Nic::new(&MEM);
    irq_scenario(&NIC, &MEM, family(Model::I225).irq, family(Model::Igb).irq);
}

/// **Discriminates.** The igc driver on QEMU's 82576 (`Model::Igb`): the
/// interrupt block is the one at 0xc0, not the I225's at 0x1500, so the
/// receive cause the model raises is read and the mask is set where the
/// model looks. The previous driver read 0x1500 on every part: here it
/// counts no receive interrupt and the assertion on `rx_irq_count` fails.
#[test]
fn igc_on_an_82576_uses_the_igb_interrupt_block() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<IgcWire, N, N> = Nic::new(&MEM);
    irq_scenario(&NIC, &MEM, family(Model::Igb).irq, family(Model::I225).irq);
}

// ── A wedged transmit ring (`net-timeout`) ───────────────────────────────

/// The transmit budget of the NICs below: short, the host's time is real.
const TX_BUDGET_MS: u64 = 30;

/// What `restart` does on real hardware after `C::reset`, done by the test
/// as the controller: the rings primed again over the same buffers and the
/// NIC live again (`go_live`). Counts the restarts.
fn relive<W: Wire>(nic: &Nic<W, N, N>, mem: &'static Mem<N, N>, count: &core::sync::atomic::AtomicU32) -> bool {
    count.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let dma = Dma::fallback();
    let rx_buf_bus = dma.map(mem.rx_buf(0) as *const u8, N * BUF, Direction::FromDevice).unwrap();
    let tx_buf_bus = dma.map(mem.tx_buf(0) as *const u8, N * BUF, Direction::ToDevice).unwrap();
    nic.prime(&dma, rx_buf_bus);
    nic.go_live(dma, rx_buf_bus, tx_buf_bus, MAC, 0, None);
    true
}

/// Send until the watch fires (the controller never takes a frame): looks
/// 5 ms apart, well under the stall gap, so the guest is seen running.
fn send_until_wedged<W: Wire>(nic: &Nic<W, N, N>) -> std::time::Duration {
    let t0 = std::time::Instant::now();
    loop {
        match nic.send(&[0u8; 60]) {
            Err(NetError::NotReady) => return t0.elapsed(),
            Ok(_) | Err(NetError::QueueFull) => {}
            Err(e) => panic!("send answered {e:?}"),
        }
        assert!(t0.elapsed().as_secs() < 5, "a ring that never moves was never declared wedged");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// **Discriminates.** Frames the controller takes none of for the budget
/// make the send that sees it reset the NIC (the restart runs once, the NIC
/// is live again and sends) and record it (`net-timeout` action 2); a second
/// wedge finds the reset spent: the NIC is stopped (its engines off, sends
/// refused) and latched dead, recorded as action 5. A ring the controller
/// keeps draining never fires. Canary: drop the `expired` check in `send`
/// (the first loop's 5-second bound fires), or call `restart` again in the
/// `Latch` arm (the restart count is 2).
fn tx_timeout_scenario<W: Wire>(nic: &'static Nic<W, N, N>, mem: &'static Mem<N, N>, restart: fn(&Nic<W, N, N>) -> bool, count: &core::sync::atomic::AtomicU32) {
    use azos_drv_api::recovery::{Action, Class};
    crate::recovery_records::listen();
    let rig = bring_up(nic, mem, None);
    nic.set_restart(restart);

    // A ring the controller drains: no timeout, however long it runs.
    for i in 0..12 {
        assert_eq!(nic.send(&[0u8; 60]), Ok(60));
        // SAFETY: the test is the controller: it marks the frame sent.
        unsafe { (*mem.tx_desc(i % N)).hi |= (crate::e1000e::TXD_STAT_DD as u64) << 32 };
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(count.load(core::sync::atomic::Ordering::SeqCst), 0, "a moving ring was reset");

    let waited = send_until_wedged(nic);
    assert!(waited.as_millis() as u64 >= TX_BUDGET_MS - 5, "declared wedged after {waited:?}");
    assert_eq!(count.load(core::sync::atomic::Ordering::SeqCst), 1);
    assert!(nic.is_ready() && !nic.is_dead());
    assert_eq!(nic.resets(), 1);
    assert_eq!(nic.send(&[0u8; 60]), Ok(60), "the NIC did not carry on after its reset");

    send_until_wedged(nic);
    assert_eq!(count.load(core::sync::atomic::Ordering::SeqCst), 1, "reset twice");
    assert!(nic.is_dead() && !nic.is_ready());
    assert_eq!(nic.send(&[0u8; 60]), Err(NetError::NotReady));
    assert_eq!(rig.regs.get(crate::e1000e::REG_TCTL), 0, "the transmit engine still runs");
    let r: Vec<(Class, &str, Action)> = crate::recovery_records::taken().into_iter().map(|(c, d, a, _)| (c, d, a)).collect();
    assert_eq!(r, vec![(Class::Net, W::NAME, Action::Reset), (Class::Net, W::NAME, Action::Latched)]);
}

#[test]
fn e1000e_wedged_transmit_ring_is_reset_once_then_latched() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<E1000eWire, N, N> = Nic::with_tx_budget(&MEM, TX_BUDGET_MS);
    static COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    fn restart(nic: &Nic<E1000eWire, N, N>) -> bool {
        relive(nic, &MEM, &COUNT)
    }
    tx_timeout_scenario(&NIC, &MEM, restart, &COUNT);
}

#[test]
fn igc_wedged_transmit_ring_is_reset_once_then_latched() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<IgcWire, N, N> = Nic::with_tx_budget(&MEM, TX_BUDGET_MS);
    static COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    fn restart(nic: &Nic<IgcWire, N, N>) -> bool {
        relive(nic, &MEM, &COUNT)
    }
    tx_timeout_scenario(&NIC, &MEM, restart, &COUNT);
}

/// **Discriminates.** A sender that sends seldom (a DHCP or TCP retry, here
/// one frame per 100 ms, twice the stall gap) never sees its wedged ring run
/// out of budget by itself: the stall clock credits every gap between two
/// sends as time the guest did not run. The poller's look (`tx_watch`, every
/// 10 ms here, as the network poller does every `TX_LOOK_US`) keeps the gaps
/// short, so the ring is found wedged within its budget and the NIC reset.
/// Canary: `tx_watch` answering `None` without a look (the 2-second bound
/// fires: the sends alone never reset it).
#[test]
fn e1000e_a_seldom_sender_is_found_wedged_by_the_poller() {
    static MEM: Mem<N, N> = Mem::new();
    static NIC: Nic<E1000eWire, N, N> = Nic::with_tx_budget(&MEM, TX_BUDGET_MS);
    static COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    fn restart(nic: &Nic<E1000eWire, N, N>) -> bool {
        relive(nic, &MEM, &COUNT)
    }
    crate::recovery_records::listen();
    let _rig = bring_up(&NIC, &MEM, None);
    NIC.set_restart(restart);
    assert_eq!(NIC.send(&[0u8; 60]), Ok(60));
    assert!(NIC.tx_watch().is_some(), "a ring holding a frame asks for no look");
    let t0 = std::time::Instant::now();
    let mut last_send = t0;
    while COUNT.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(t0.elapsed().as_secs() < 2, "a seldom sender's wedged ring was never declared wedged");
        let _ = NIC.tx_watch();
        if last_send.elapsed().as_millis() >= 100 {
            let _ = NIC.send(&[0u8; 60]);
            last_send = std::time::Instant::now();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(NIC.is_ready() && !NIC.is_dead());
    assert_eq!(NIC.tx_watch(), None, "a reset ring still asks for a look");
}

/// Descriptors share cache lines, so a function whose DMA does not snoop the
/// CPU's caches is refused before anything is mapped; a coherent one is
/// driven.
#[test]
fn the_rings_are_refused_behind_a_master_that_does_not_snoop() {
    assert!(rings_drivable(&Dma::fallback()), "a coherent domain is driven");
    const BASE: u64 = 0xD00D_2000;
    azos_dma::registry::declare_mmio(BASE, BASE, azos_dma::registry::MmioView::coherent(false)).expect("declare once");
    assert!(!rings_drivable(&Dma::mmio(BASE as usize)), "a non-coherent domain must be refused");
}
