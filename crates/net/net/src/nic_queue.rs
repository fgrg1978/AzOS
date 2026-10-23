// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interfaces whose NIC queue a ring-3 program took from the stack (the
//! packet rings of `ty::NIC_QUEUE`, `azos_abi::nic_queue`).
//!
//! The rings and the attachment are the syscall layer's
//! (`azos_syscall::nicq`): it owns the regions, this crate cannot see them.
//! What lives here is what the stack must do differently while a queue is
//! taken, and who may take one:
//!
//! * **The stack does not see a taken queue.** The receive pass hands its
//!   frames to the taker ([`pass`], the [`Sink`] the kernel installs) with
//!   the stamp read at the driver boundary, instead of to the packet sockets,
//!   ARP and IP; nothing the stack builds leaves by it ([`stack_may_send`],
//!   asked by `net_raw_send`), and the taker's frames leave by
//!   `crate::nic_queue_send`. The interface keeps its address and its
//!   routes: what the stack would send by it is refused, as by an interface
//!   whose NIC went away.
//! * **One queue per NIC.** Every backend of `azos_drv_net::net_device` runs
//!   one receive and one transmit ring ([`QUEUES_PER_NIC`]), so taking queue 0
//!   takes the whole NIC from the stack.
//! * **Who may take one** ([`verdict`]): the interface must have a NIC and the
//!   queue must exist; nobody else may hold it; and it must not carry what the
//!   node needs to stay reachable and stoppable. The primary interface is
//!   refused outright: it is the one every kernel service runs on (TCP's and
//!   IPv6's address, DHCP, DNS, SNTP, the default route). So is the interface
//!   the route to the link peer leaves by ([`set_hooks`]' `link_peer`, the
//!   brain the behavior task dials): the e-stop arrives on that connection.
//!   A refusal is a decision record (`Rule::NicQueue`).
//!
//! The capability that names the queue is the topology's choice (a row's
//! `nicq.eth<N>.<queue>`); these checks run at the attach, because a NIC can
//! come and go after the seed and the link peer's route can change.

use crate::ip::{self, IfIndex, MAX_IFS, PRIMARY_IF};
use core::sync::atomic::{AtomicBool, Ordering};

/// Queues of every NIC the stack drives: one receive and one transmit ring.
pub const QUEUES_PER_NIC: u8 = 1;

/// Why a queue was not taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The interface does not exist or has no NIC.
    NoNic,
    /// The NIC has no such queue.
    NoQueue,
    /// Another attachment holds it.
    Taken,
    /// It is the primary interface: the node's own stack runs on it.
    Primary,
    /// The route to the link peer (the e-stop's and the link's path) leaves
    /// by it.
    LinkPath,
}

impl Refusal {
    /// The `why` field of the `Rule::NicQueue` record (`Primary` and
    /// `LinkPath`, the refusals that protect the node); 0 for the others,
    /// which are not recorded.
    pub const fn code(self) -> u64 {
        match self {
            Refusal::Primary => 1,
            Refusal::LinkPath => 2,
            Refusal::NoNic | Refusal::NoQueue | Refusal::Taken => 0,
        }
    }
}

/// May queue `queue` of interface `ifindex` be taken? `has_nic`: the interface
/// exists and a NIC is attached to it; `taken`: an attachment holds it now;
/// `link_egress`: the interface the route to the link peer leaves by (`None`:
/// no link peer, or no route to it). Pure, so a host suite can drive it.
pub fn verdict(ifindex: IfIndex, queue: u8, has_nic: bool, taken: bool, link_egress: Option<IfIndex>) -> Result<(), Refusal> {
    if !has_nic {
        return Err(Refusal::NoNic);
    }
    if queue >= QUEUES_PER_NIC {
        return Err(Refusal::NoQueue);
    }
    if ifindex == PRIMARY_IF {
        return Err(Refusal::Primary);
    }
    if link_egress == Some(ifindex) {
        return Err(Refusal::LinkPath);
    }
    if taken {
        return Err(Refusal::Taken);
    }
    Ok(())
}

/// One received frame of a taken interface, and its stamp (ns of the
/// monotonic clock, read at the driver boundary). Runs in the receive pass,
/// with no lock of this crate held; it must not block.
pub type Sink = fn(ifindex: IfIndex, frame: &[u8], stamp_ns: u64);
/// The receive pass is done with a taken interface for now: the sink's
/// chance to ring its reader once for the frames it pushed.
pub type SinkEnd = fn(ifindex: IfIndex);
/// The address of the node's link peer, when it has one: the e-stop and the
/// link arrive from it.
pub type LinkPeer = fn() -> Option<[u8; 4]>;

azos_common::ro_hook! {
    static SINK: Sink;
}
azos_common::ro_hook! {
    static SINK_END: SinkEnd;
}
azos_common::ro_hook! {
    static LINK_PEER: LinkPeer;
}

/// Install the receive sink of the attachments and the link peer's address
/// (boot, once, before any task runs).
pub fn set_hooks(sink: Sink, end: SinkEnd, link_peer: LinkPeer) {
    SINK.set(sink);
    SINK_END.set(end);
    LINK_PEER.set(link_peer);
}

/// Taken interfaces, by `ifindex - 1`.
static TAKEN: [AtomicBool; MAX_IFS] = [const { AtomicBool::new(false) }; MAX_IFS];

fn slot(ifindex: IfIndex) -> Option<&'static AtomicBool> {
    TAKEN.get((ifindex as usize).checked_sub(1)?)
}

/// Is a queue of `ifindex` taken from the stack now?
#[inline]
pub fn taken(ifindex: IfIndex) -> bool {
    slot(ifindex).is_some_and(|t| t.load(Ordering::Acquire))
}

/// Take queue `queue` of `ifindex` from the stack for task `tid` (the subject
/// of a refusal's record), and answer the interface's MAC. From the return on
/// the receive pass hands the interface's frames to the sink and the stack
/// sends nothing by it.
pub fn take(tid: u32, ifindex: IfIndex, queue: u8) -> Result<[u8; 6], Refusal> {
    let iface = ip::iface_get(ifindex).filter(|i| i.attached());
    let link_egress = LINK_PEER.get().and_then(|f| f()).and_then(|peer| ip::route(&peer)).map(|e| e.ifindex);
    let now_taken = taken(ifindex);
    let r = verdict(ifindex, queue, iface.is_some(), now_taken, link_egress);
    let r = match (r, iface, slot(ifindex)) {
        (Ok(()), Some(i), Some(t)) => match t.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(i.mac),
            Err(_) => Err(Refusal::Taken),
        },
        (Ok(()), _, _) => Err(Refusal::NoNic),
        (Err(e), _, _) => Err(e),
    };
    if let Err(e) = r {
        if e.code() != 0 {
            azos_decision::record(
                azos_decision::Rule::NicQueue,
                azos_decision::Verdict::Refuse,
                tid,
                [ifindex as u64, queue as u64, e.code()],
            );
        }
    }
    r
}

/// Give `ifindex` back to the stack.
pub fn give_back(ifindex: IfIndex) {
    if let Some(t) = slot(ifindex) {
        t.store(false, Ordering::Release);
    }
}

/// May the stack send a frame by `ifindex`? Not while its queue is taken.
#[inline]
pub fn stack_may_send(ifindex: IfIndex) -> bool {
    !taken(ifindex)
}

/// The stamp of a frame crossing the driver boundary now: ns of the
/// monotonic clock.
#[inline]
pub fn stamp_now() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ)
}

/// The receive pass's turn on `ifindex`: when its queue is taken, drain up to
/// `budget` frames through `recv` (the NIC's `recv_batch`: at most `max`
/// frames handed to the callback, the count returned) into the sink, each
/// with its stamp, and return how many; `None` when the stack drains the
/// interface itself. A frame of a taken queue never reaches the stack: not
/// the packet sockets, not ARP, not IP.
pub fn pass(ifindex: IfIndex, budget: usize, recv: &mut dyn FnMut(usize, &mut dyn FnMut(&[u8])) -> usize) -> Option<usize> {
    if cfg!(feature = "nic-queue-blind-canary") || !taken(ifindex) {
        return None;
    }
    let sink = SINK.get();
    let mut deliver = |frame: &[u8]| {
        let stamp = stamp_now();
        if let Some(f) = sink {
            f(ifindex, frame, stamp);
        }
    };
    let mut got = 0usize;
    while got < budget {
        let n = recv(budget - got, &mut deliver);
        if n == 0 {
            break;
        }
        got += n;
    }
    if got != 0 {
        if let Some(end) = SINK_END.get() {
            end(ifindex);
        }
    }
    Some(got)
}

/// Host-test hygiene: no interface taken, no hook installed.
#[cfg(not(target_os = "none"))]
pub fn reset_for_tests() {
    for t in TAKEN.iter() {
        t.store(false, Ordering::Release);
    }
    SINK.clear_for_tests();
    SINK_END.clear_for_tests();
    LINK_PEER.clear_for_tests();
}
