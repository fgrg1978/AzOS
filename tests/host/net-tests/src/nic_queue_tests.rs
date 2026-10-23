// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A NIC queue taken from the stack by a ring-3 program
//! (`crates/net/net/src/nic_queue.rs`): who may take one, and that the stack
//! does not see a taken one.
//!
//! **The real `nic_queue.rs` and `ip.rs` are in the loop.** The interfaces are
//! the real registry's and the route to the link peer is the real route
//! lookup; the receive pass's turn is `nic_queue::pass` driven with a scripted
//! NIC (`recv_batch`'s shape). The kernel's own receive loop (`lib.rs`) that
//! calls `pass` before its stack dispatch is not compiled here; it is the
//! `nicq` QEMU row's.

use crate::NET_SERIAL as SERIAL;
use crate::{ip, nic_queue};
use nic_queue::Refusal;
use std::sync::Mutex;

const MAC_A: [u8; 6] = [0x02, 0xAA, 0x00, 0x00, 0x00, 0x01];
const IP_A: [u8; 4] = [10, 1, 0, 2];
const MAC_B: [u8; 6] = [0x02, 0xBB, 0x00, 0x00, 0x00, 0x02];
const IP_B: [u8; 4] = [192, 168, 7, 2];
const BRAIN_ON_B: [u8; 4] = [192, 168, 7, 50];
const BRAIN_ON_A: [u8; 4] = [10, 1, 0, 50];

/// Frames the sink got: (interface, frame, stamp).
static SUNK: Mutex<Vec<(u8, Vec<u8>, u64)>> = Mutex::new(Vec::new());
/// Interfaces the sink's end was rung for.
static ENDED: Mutex<Vec<u8>> = Mutex::new(Vec::new());
/// The link peer the hook answers.
static PEER: Mutex<Option<[u8; 4]>> = Mutex::new(None);

fn sink(ifindex: u8, frame: &[u8], stamp: u64) {
    SUNK.lock().unwrap().push((ifindex, frame.to_vec(), stamp));
}

fn end(ifindex: u8) {
    ENDED.lock().unwrap().push(ifindex);
}

fn peer() -> Option<[u8; 4]> {
    *PEER.lock().unwrap()
}

struct Session {
    _g: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        nic_queue::reset_for_tests();
        ip::ifaces_reset_for_test();
    }
}

/// eth0 (index 1) `10.1.0.2/24` and eth1 (index 2) `192.168.7.2/24`, the hooks
/// installed, no link peer.
fn begin() -> Session {
    let g = Session { _g: SERIAL.lock().unwrap_or_else(|e| e.into_inner()) };
    azos_drv_irqchip::clint::set_test_time(70_000);
    ip::ifaces_reset_for_test();
    nic_queue::reset_for_tests();
    assert_eq!(ip::iface_attach(0, MAC_A, 1500, [0; 16]), Some(1));
    assert!(ip::iface_configure(1, IP_A, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::iface_attach(1, MAC_B, 1500, [0; 16]), Some(2));
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], [0; 4]));
    SUNK.lock().unwrap().clear();
    ENDED.lock().unwrap().clear();
    *PEER.lock().unwrap() = None;
    nic_queue::set_hooks(sink, end, peer);
    g
}

/// The NIC-queue refusal records written since `first`.
fn refusals(first: u64) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq >= first && r.rule == azos_decision::Rule::NicQueue as u8 {
            v.push(*r);
        }
    });
    v
}

/// A scripted NIC: hands out `frames` in batches of at most `batch`, the way
/// `NetDevice::recv_batch` does, and counts its calls.
struct Nic {
    frames: Vec<Vec<u8>>,
    batch: usize,
    calls: usize,
}

impl Nic {
    fn new(n: usize, batch: usize) -> Nic {
        Nic { frames: (0..n).map(|i| vec![i as u8; 60]).collect(), batch, calls: 0 }
    }

    fn recv(&mut self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
        self.calls += 1;
        let k = max.min(self.batch).min(self.frames.len());
        for fr in self.frames.drain(..k) {
            f(&fr);
        }
        k
    }
}

// ── Who may take a queue ────────────────────────────────────────────────────

/// **Discriminates.** The pure rule: a queue needs an interface with a NIC
/// and must exist; the primary interface and the link peer's egress are
/// refused whatever else holds; a queue already held is busy.
#[test]
fn the_verdict_refuses_the_primary_the_link_path_a_missing_queue_and_a_held_one() {
    assert_eq!(nic_queue::verdict(2, 0, true, false, None), Ok(()));
    assert_eq!(nic_queue::verdict(2, 0, false, false, None), Err(Refusal::NoNic));
    assert_eq!(nic_queue::verdict(2, nic_queue::QUEUES_PER_NIC, true, false, None), Err(Refusal::NoQueue));
    assert_eq!(nic_queue::verdict(ip::PRIMARY_IF, 0, true, false, None), Err(Refusal::Primary));
    assert_eq!(nic_queue::verdict(2, 0, true, false, Some(2)), Err(Refusal::LinkPath));
    assert_eq!(nic_queue::verdict(2, 0, true, false, Some(1)), Ok(()), "the link leaves by another interface");
    assert_eq!(nic_queue::verdict(2, 0, true, true, None), Err(Refusal::Taken));
}

/// **Discriminates.** eth1 is taken and answers its MAC; a second take is busy
/// until it is given back; eth0, the primary interface, is refused and the
/// refusal recorded with the task, the interface, the queue and why.
/// Canary: drop the `PRIMARY_IF` arm of `verdict` and eth0 is handed over.
#[test]
fn eth1_is_taken_once_and_the_primary_interface_is_refused_and_recorded() {
    let _s = begin();
    assert!(azos_decision::ON, "the decision ring is off: the record assertions would be vacuous");
    let first = azos_decision::total() + 1;
    assert_eq!(nic_queue::take(7, 2, 0), Ok(MAC_B));
    assert!(nic_queue::taken(2) && !nic_queue::taken(1));
    assert_eq!(nic_queue::take(8, 2, 0), Err(Refusal::Taken));
    assert_eq!(nic_queue::take(7, 1, 0), Err(Refusal::Primary));
    assert!(!nic_queue::taken(1), "a refused take takes nothing");
    assert_eq!(nic_queue::take(7, 2, 1), Err(Refusal::NoQueue));
    assert_eq!(nic_queue::take(7, 3, 0), Err(Refusal::NoNic), "no eth2");
    let r = refusals(first);
    assert_eq!(r.len(), 1, "only the refusal that protects the node is recorded: {r:?}");
    assert_eq!((r[0].subject, r[0].n), (7, [1, 0, Refusal::Primary.code()]));
    assert_eq!(r[0].verdict, azos_decision::Verdict::Refuse as u8);
    nic_queue::give_back(2);
    assert!(!nic_queue::taken(2));
    assert_eq!(nic_queue::take(8, 2, 0), Ok(MAC_B), "given back, it can be taken again");
}

/// **Discriminates.** With the link peer on eth1's subnet, the route to it
/// leaves by eth1, so eth1 is refused (the e-stop arrives on that path) and
/// recorded; with the peer on eth0's subnet, eth1 is free. Canary: drop the
/// `LinkPath` arm, or ask the hook for nothing, and the first take succeeds.
#[test]
fn the_interface_the_link_peer_is_reached_by_is_never_handed_over() {
    let _s = begin();
    let first = azos_decision::total() + 1;
    *PEER.lock().unwrap() = Some(BRAIN_ON_B);
    assert_eq!(ip::route(&BRAIN_ON_B).map(|e| e.ifindex), Some(2), "precondition: the peer is on eth1");
    assert_eq!(nic_queue::take(9, 2, 0), Err(Refusal::LinkPath));
    assert!(!nic_queue::taken(2));
    let r = refusals(first);
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].subject, r[0].n), (9, [2, 0, Refusal::LinkPath.code()]));
    *PEER.lock().unwrap() = Some(BRAIN_ON_A);
    assert_eq!(nic_queue::take(9, 2, 0), Ok(MAC_B), "the link leaves by eth0: eth1 may go");
}

// ── The stack does not see a taken queue ────────────────────────────────────

/// **Discriminates.** While eth1 is taken, its turn of the receive pass drains
/// the NIC into the sink, every frame with a stamp, in batches up to the
/// budget, and rings the sink's end once; the stack's own drain is not asked
/// for it (`pass` answers `Some`). eth0, not taken, is left to the stack
/// (`None`) and its NIC is not touched. Canary `nic-queue-blind-canary`:
/// `pass` ignores the take, answers `None` for eth1 too, and this fails (the
/// stack would get eth1's frames).
#[test]
fn a_taken_queue_goes_to_the_sink_and_the_stack_sees_none_of_it() {
    let _s = begin();
    assert_eq!(nic_queue::take(7, 2, 0), Ok(MAC_B));
    let mut a = Nic::new(3, 4);
    assert_eq!(nic_queue::pass(1, 64, &mut |m, f| a.recv(m, f)), None, "eth0 is the stack's");
    assert_eq!(a.calls, 0, "the stack's interface is not drained here");
    let mut b = Nic::new(5, 2);
    assert_eq!(nic_queue::pass(2, 64, &mut |m, f| b.recv(m, f)), Some(5));
    let got = SUNK.lock().unwrap().clone();
    assert_eq!(got.len(), 5);
    for (i, (ifx, frame, stamp)) in got.iter().enumerate() {
        assert_eq!((*ifx, frame[0]), (2, i as u8), "in ring order, all on eth1");
        assert!(*stamp > 0, "stamped at the driver boundary");
    }
    assert_eq!(*ENDED.lock().unwrap(), vec![2], "one doorbell chance per pass");
    assert!(!nic_queue::stack_may_send(2), "the stack sends nothing by a taken queue");
    assert!(nic_queue::stack_may_send(1));
}

/// **Discriminates.** The pass is bounded by its budget like the stack's
/// drain: a flood on a taken queue leaves frames for the next pass, and the
/// count says the budget ran out.
#[test]
fn a_taken_queue_is_drained_within_the_budget() {
    let _s = begin();
    assert_eq!(nic_queue::take(7, 2, 0), Ok(MAC_B));
    let mut b = Nic::new(10, 3);
    assert_eq!(nic_queue::pass(2, 4, &mut |m, f| b.recv(m, f)), Some(4));
    assert_eq!(b.frames.len(), 6);
    nic_queue::give_back(2);
    assert_eq!(nic_queue::pass(2, 4, &mut |m, f| b.recv(m, f)), None, "given back: the stack drains it again");
}
