// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `QUEUE_NICQ_*` ops (`crates/core/syscall/src/nicq.rs`):
// a NIC queue taken from the stack and run on two rings the program made.
//
// **What is real here.** The entry (`invoke::sys_invoke`) and its dispatch,
// the capability table, the region table (`memobj.rs`, the regions are real
// contiguous host pages), the ring code (`azos_rings`), the rules of who may
// take a queue (`azos_net::nic_queue` over the real interface registry), and
// the futex edge's record of every wake. **What is not.** The NIC: the
// receive pass's turn is `nicq::rx_sink`/`rx_end` called as the pass calls
// them, and a sent frame is the net shim's record (`shim_take_nicq_sent`).
//
// Included inside `mod handlers { .. }`, like `h3_hosts.rs`.

use super::harness::serial;
use azos_abi::cap::{CapPerms, CapHandle};
use azos_abi::error::Errno;
use azos_abi::invoke::{QUEUE_NICQ_ATTACH, QUEUE_NICQ_DETACH, QUEUE_NICQ_KICK, INVOKE_REGS};
use azos_abi::nic_queue::{self as nq, Desc};
use azos_ipc::cap::targets::NicQueue;
use azos_ipc::memobj::{memobj_create_cap, memobj_page_phys_ref, memobj_release_cap, MemPerms, MemSpec};
use azos_rings::region::{BytesProducer, RingStep, SlotInfo, SpscBytes, RING_HEAD};
use azos_sched::futex::{shim_take_calls, Key};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

/// Cap-store pool slot for this file; no other file in this crate binds 43.
const SLOT: usize = 43;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e43_0001);

const MAC_A: [u8; 6] = [0x02, 0xAA, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0xBB, 0x00, 0x00, 0x00, 0x02];

struct Scene {
    tid: u32,
    _g: super::harness::SerialGuard,
}

impl Drop for Scene {
    fn drop(&mut self) {
        crate::nicq::release_all(self.tid);
        azos_ipc::memobj::memobj_release_all(self.tid);
        ipc_task_pool::shim_kill(self.tid);
        azos_net::nic_queue::reset_for_tests();
        azos_net::ip::ifaces_reset_for_test();
    }
}

/// A ring-3 task with eth0 (the primary interface) and eth1 attached, no link
/// peer, no filter.
fn scene() -> Scene {
    let g = serial();
    let tid = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    azos_sched::scheduler::set_current_syscall_filter(azos_sched::filter::SyscallFilter::disabled());
    azos_net::nic_queue::reset_for_tests();
    azos_net::ip::ifaces_reset_for_test();
    assert_eq!(azos_net::ip::iface_attach(0, MAC_A, 1500, [0; 16]), Some(1));
    assert_eq!(azos_net::ip::iface_attach(1, MAC_B, 1500, [0; 16]), Some(2));
    let _ = azos_net::shim_take_nicq_sent();
    shim_take_calls();
    Scene { tid, _g: g }
}

/// The capability for queue `queue` of `ifindex`, with `perms`.
fn queue_cap(s: &Scene, ifindex: u8, queue: u8, perms: CapPerms) -> u64 {
    azos_ipc::cap_store::grant::<NicQueue>(s.tid, perms, nq::resource(ifindex, queue)).expect("a handle").raw().0 as u64
}

/// A ring region the program made: `pages` zero-filled contiguous pages.
/// The handle (every right) and the packed reference.
fn region(s: &Scene, pages: usize) -> (u64, u32) {
    let cap = memobj_create_cap(s.tid, pages, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    let r = azos_ipc::cap_store::get(s.tid, cap, CapPerms::READ).expect("the capability resolves");
    (cap.raw().0 as u64, r)
}

/// The program's view of the ring in region `r`, from the header the attach
/// wrote.
fn view(r: u32, pages: usize) -> SpscBytes {
    let phys = memobj_page_phys_ref(r, 0).expect("live").expect("a page");
    let base = azos_mm::addr::phys_to_virt(phys);
    SpscBytes::from_header(base, pages * azos_arch::PAGE_SIZE).expect("the attach described the ring")
}

fn invoke(handle: u64, op: u16, w0: u64, w1: u64) -> (i64, [u64; 6]) {
    let mut out = crate::dispatch::SyscallOut::new();
    let rc = crate::invoke::sys_invoke(handle, INVOKE_REGS | op as u64, w0, w1, 0, 0, &mut out);
    (rc, out.regs)
}

/// An attached queue on eth1: the queue handle, and the two regions.
struct Attached {
    q: u64,
    rx: (u64, u32),
    tx: (u64, u32),
}

const PAGES: usize = 2;

fn attach(s: &Scene) -> Attached {
    let q = queue_cap(s, 2, 0, CapPerms::RW);
    let (rx, tx) = (region(s, PAGES), region(s, PAGES));
    let (rc, rep) = invoke(q, QUEUE_NICQ_ATTACH, rx.0, tx.0);
    assert_eq!(rc, 0, "eth1's queue attaches");
    assert_eq!(nq::mac_of_word(rep[0]), MAC_B, "the reply names the interface's MAC");
    assert_eq!((rep[1], rep[2]), (nq::FRAME_MAX as u64, nq::STAMP_SW as u64));
    Attached { q, rx, tx }
}

/// Pop one item of the receive ring: its slot header, descriptor and frame.
fn pop(v: &SpscBytes) -> Option<(SlotInfo, Desc, Vec<u8>)> {
    let mut buf = vec![0u8; nq::SLOT_PAYLOAD];
    let (step, info) = v.try_pop(&mut buf);
    if step == RingStep::Blocked {
        return None;
    }
    let n = info.len as usize;
    Some((info, Desc::decode(&buf[..n]).expect("a descriptor"), buf[nq::DESC_BYTES..n].to_vec()))
}

/// A frame from `src` of `len` bytes.
fn frame(src: [u8; 6], len: usize, tag: u8) -> Vec<u8> {
    let mut f = vec![tag; len];
    f[..6].copy_from_slice(&[0x01, 0x1B, 0x19, 0, 0, 0]);
    if len >= 12 {
        f[6..12].copy_from_slice(&src);
    }
    f
}

/// A transmit item: the descriptor (`flags`), then the frame.
fn tx_item(flags: u8, f: &[u8]) -> Vec<u8> {
    let mut v = Desc { kind: nq::DESC_TX, flags, tx_seq: 0 }.encode().to_vec();
    v.extend_from_slice(f);
    v
}

/// **Discriminates.** The attach takes eth1 from the stack and lays both rings
/// out (the program reads their geometry from the headers); a frame of the
/// queue reaches the receive ring behind an `RX` descriptor flagged as a
/// software stamp, with that stamp; the reader that said it may sleep is rung
/// once, on the receive ring's head word. Canary: drop the `rx_sink` push and
/// the ring stays empty; drop `rx_end`'s wake and no wake is recorded.
#[test]
fn an_attached_queue_delivers_its_frames_stamped_on_the_receive_ring() {
    let s = scene();
    let a = attach(&s);
    assert!(azos_net::nic_queue::taken(2), "the stack no longer has eth1");
    let rx = view(a.rx.1, PAGES);
    assert!(rx.cap >= 2 && rx.slot_bytes == crate::nicq::SLOT_BYTES);
    // The program found the ring empty and announced it may sleep.
    assert!(matches!(rx.consumer_sleep(), azos_rings::region::RingSleep::Wait { .. }));
    let f = frame([0x02, 0x99, 0, 0, 0, 9], 60, 0x5A);
    crate::nicq::rx_sink(2, &f, 123_456);
    crate::nicq::rx_end(2);
    let (info, d, got) = pop(&rx).expect("the frame is on the ring");
    assert_eq!((d.kind, d.flags, d.tx_seq), (nq::DESC_RX, nq::STAMP_SW, 0));
    assert_eq!((info.acq_ns, info.seq), (123_456, 0));
    assert_eq!(got, f);
    let wakes: Vec<_> = shim_take_calls().into_iter().filter(|c| !c.is_wait).collect();
    assert_eq!(wakes.len(), 1, "one doorbell for the pass");
    assert_eq!(wakes[0].key, Key::Shared { obj: a.rx.1, offset: RING_HEAD as u32 });
    // eth0 is not attached: its frames are nobody's here.
    crate::nicq::rx_sink(1, &f, 1);
    assert!(pop(&rx).is_none());
}

/// **Discriminates.** A kick sends what the program pushed: a frame from the
/// interface's MAC leaves, and its stamped completion follows on the receive
/// ring with the transmit slot's sequence number; a frame from another MAC
/// and a frame shorter than an Ethernet header do not leave, the first one's
/// completion says so (`TX_REFUSED`), the second asked for none. Canary:
/// drop the source-MAC check and the foreign frame is sent (two frames on the
/// wire, a stamped completion for it).
#[test]
fn a_kick_sends_the_interfaces_frames_and_refuses_the_others() {
    let s = scene();
    let a = attach(&s);
    let tx = view(a.tx.1, PAGES);
    let mut prod = BytesProducer::new(tx);
    let good = frame(MAC_B, 64, 1);
    let foreign = frame(MAC_A, 64, 2);
    let short = frame(MAC_B, 10, 3);
    prod.push(0, &tx_item(nq::TX_STAMP, &good));
    if tx.cap >= 4 {
        prod.push(0, &tx_item(nq::TX_STAMP, &foreign));
        prod.push(0, &tx_item(0, &short));
    }
    let (rc, _) = invoke(a.q, QUEUE_NICQ_KICK, 0, 0);
    assert_eq!(rc, 1, "one frame left");
    let sent = azos_net::shim_take_nicq_sent();
    assert_eq!(sent, vec![(2, good.clone())], "only the interface's own frame, by eth1");
    let rx = view(a.rx.1, PAGES);
    let (info, d, f) = pop(&rx).expect("the stamped completion");
    assert_eq!((d.kind, d.flags, d.tx_seq, f.len()), (nq::DESC_TX_DONE, nq::STAMP_SW, 0, 0));
    assert!(info.acq_ns > 0, "the departure stamp");
    if tx.cap >= 4 {
        let (_, d, _) = pop(&rx).expect("the refused frame's completion");
        assert_eq!((d.kind, d.flags, d.tx_seq), (nq::DESC_TX_DONE, nq::TX_REFUSED, 1));
    }
    assert!(pop(&rx).is_none(), "the short frame asked for no completion");
    let (rc, _) = invoke(a.q, QUEUE_NICQ_KICK, 0, 0);
    assert_eq!(rc, 0, "an empty ring sends nothing");
}

/// **Discriminates.** The refusals of the attach: the primary interface
/// (`EPERM`), a queue the NIC does not have and an interface with no NIC
/// (`ENODEV`), a second attach of a held queue (`EBUSY`), one region for both
/// rings and a region too small for two slots (`EINVAL`), a queue capability
/// without `WRITE` (`ECAPPERMS`) and a receive region the kernel may not write
/// (`ECAPPERMS`). None of them takes anything from the stack.
#[test]
fn the_attach_refuses_the_primary_interface_and_every_malformed_request() {
    let s = scene();
    let (rx, tx) = (region(&s, PAGES), region(&s, PAGES));
    let try_attach = |ifx: u8, q: u8, perms: CapPerms, rx: u64, tx: u64| {
        invoke(queue_cap(&s, ifx, q, perms), QUEUE_NICQ_ATTACH, rx, tx).0
    };
    assert_eq!(try_attach(1, 0, CapPerms::RW, rx.0, tx.0), Errno::EPERM.to_syscall_ret(), "the primary interface");
    assert!(!azos_net::nic_queue::taken(1));
    assert_eq!(try_attach(2, 1, CapPerms::RW, rx.0, tx.0), Errno::ENODEV.to_syscall_ret(), "one queue per NIC");
    assert_eq!(try_attach(3, 0, CapPerms::RW, rx.0, tx.0), Errno::ENODEV.to_syscall_ret(), "no eth2");
    assert_eq!(try_attach(2, 0, CapPerms::RW, rx.0, rx.0), Errno::EINVAL.to_syscall_ret(), "one region for both");
    assert_eq!(try_attach(2, 0, CapPerms::READ, rx.0, tx.0), Errno::ECAPPERMS.to_syscall_ret(), "READ takes no queue");
    let ro = azos_ipc::cap::objref::grant_packed::<azos_ipc::cap::targets::Shm>(s.tid, CapPerms::READ, rx.1)
        .expect("a handle").raw().0 as u64;
    assert_eq!(try_attach(2, 0, CapPerms::RW, ro, tx.0), Errno::ECAPPERMS.to_syscall_ret(), "the kernel fills rx");
    assert!(!azos_net::nic_queue::taken(2), "nothing refused took eth1");
    assert_eq!(try_attach(2, 0, CapPerms::RW, rx.0, tx.0), 0);
    let (rx2, tx2) = (region(&s, PAGES), region(&s, PAGES));
    assert_eq!(try_attach(2, 0, CapPerms::RW, rx2.0, tx2.0), Errno::EBUSY.to_syscall_ret(), "held");
}

/// **Discriminates.** The attachment ends three ways, and each gives the queue
/// back to the stack: the detach, the owner's exit (`release_all`, the
/// kernel's task-exit hook), and the receive region going away (the next push
/// finds it gone). Canary: empty `release_all` and the second leg leaves eth1
/// taken after the exit.
#[test]
fn the_queue_goes_back_to_the_stack_on_detach_exit_and_a_lost_region() {
    let s = scene();
    let a = attach(&s);
    assert_eq!(invoke(a.q, QUEUE_NICQ_DETACH, 0, 0).0, 0);
    assert!(!azos_net::nic_queue::taken(2), "detached");
    assert_eq!(invoke(a.q, QUEUE_NICQ_KICK, 0, 0).0, Errno::ENOENT.to_syscall_ret(), "nothing to kick");

    let b = attach(&s);
    crate::nicq::release_all(s.tid);
    assert!(!azos_net::nic_queue::taken(2), "the owner's exit gives it back");
    let _ = b;

    let c = attach(&s);
    let rx_cap: azos_ipc::cap::Cap<azos_ipc::cap::targets::Shm> =
        azos_ipc::cap::Cap::from_raw(CapHandle::from_raw(c.rx.0 as u32));
    azos_ipc::cap_store::with_table(s.tid, |t| memobj_release_cap(s.tid, t, rx_cap)).expect("table").expect("freed");
    crate::nicq::rx_sink(2, &frame(MAC_A, 60, 7), 1);
    assert!(!azos_net::nic_queue::taken(2), "a lost receive ring ends the attachment");
    let _ = c.tx;
}
