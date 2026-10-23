// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What one frame costs on a NIC queue's rings against the socket path,
//! measured at boot (cargo feature `nicq-cost-probe`, never in a shipped
//! build).
//!
//! Runs once, in the net-poll task before its loop, on the primary interface
//! and its NIC, with the same 60-byte frames on both paths. Each lane is timed
//! with the timebase over `N` frames, three times, and the smallest is kept
//! (a preemption only adds):
//!
//! * **rx ring**: the frame pushed on a receive ring (`nicq::RxRing::push`,
//!   what the receive pass's sink does, with its stamp) and popped from it as
//!   ring 3 pops it (`SpscBytes::try_pop`);
//! * **rx socket**: the same frame, a UDP datagram to a kernel-owned socket,
//!   handed to IP (`ip::handle`, what the receive pass does) and copied out of
//!   the socket (`socket_recv`, the body of `recvfrom`);
//! * **tx ring**: the frame pushed on a transmit ring as ring 3 pushes it, then
//!   popped, checked (`nicq::tx_frame`) and handed to the NIC, what a kick does
//!   per frame;
//! * **tx socket**: the same datagram sent on the socket (`socket_sendto`, the
//!   body of `sendto`) to the limited broadcast, which leaves by the same NIC.
//!
//! **Not counted**, on either side: the kernel entry and exit. The socket path
//! pays one per datagram each way (`recvfrom`, `sendto`); the ring path pays
//! none per received frame (the futex wait only when the ring is empty) and
//! one kick per batch of sent frames. Under `-icount shift=0` one instruction
//! is one nanosecond of virtual time, so the `ns` it prints ARE instructions.

use azos_abi::nic_queue::{self as nq, Desc};
use azos_drv_sys::kprintln;
use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec};
use azos_net::nic_queue::stamp_now;
use azos_rings::region::{BytesProducer, RingStep, SpscBytes};
use azos_syscall::nicq::{tx_frame, RxRing, TxRing, SLOT_BYTES};

/// Frames per timed run.
const N: u32 = 256;
/// Slots of each probe ring.
const SLOTS: u32 = 8;
/// The UDP port the socket lanes use.
const PORT: u16 = 47_123;
/// Bytes of UDP payload: an Ethernet frame of 60 bytes in all.
const PAYLOAD: usize = 18;

/// A kernel region for a ring of [`SLOTS`]: its reference, its address and
/// its size.
fn region() -> Option<(u32, usize, usize)> {
    let pages = nq::ring_bytes(SLOTS).div_ceil(azos_arch::PAGE_SIZE);
    let (r, phys) = memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadWrite, false))?;
    Some((r, azos_mm::addr::phys_to_virt(phys), pages * azos_arch::PAGE_SIZE))
}

/// A UDP datagram of [`PAYLOAD`] bytes from `10.0.2.99:9999` to `ip`:[`PORT`],
/// in an Ethernet frame to `mac`.
fn udp_frame(mac: [u8; 6], ip: [u8; 4]) -> [u8; 60] {
    let mut f = [0u8; 60];
    f[..6].copy_from_slice(&mac);
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0x99, 0x99]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let src = [10, 0, 2, 99];
    let ipl = (20 + 8 + PAYLOAD) as u16;
    let h = &mut f[14..34];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&ipl.to_be_bytes());
    h[8] = 64;
    h[9] = 17;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&ip);
    let c = azos_net::ip::checksum(h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    let u = &mut f[34..42];
    u[0..2].copy_from_slice(&9999u16.to_be_bytes());
    u[2..4].copy_from_slice(&PORT.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + PAYLOAD) as u16).to_be_bytes());
    f
}

/// The smallest of three timed runs of `lane`, in ns per frame (hundredths).
fn per_frame(mut lane: impl FnMut() -> bool) -> Option<u64> {
    let mut best = u64::MAX;
    for _ in 0..3 {
        let t = stamp_now();
        for _ in 0..N {
            if !lane() {
                return None;
            }
        }
        best = best.min(stamp_now() - t);
    }
    Some(best * 100 / N as u64)
}

fn show(name: &str, v: Option<u64>) {
    match v {
        Some(v) => kprintln!("[NICQ-COST] {} {}.{:02} ns per frame (= instructions under -icount shift=0)", name, v / 100, v % 100),
        None => kprintln!("[NICQ-COST] {} FAILED: a step was refused, no number", name),
    }
}

pub(crate) fn nicq_cost_probe() {
    if !azos_drv_net::net_device::is_ready() {
        kprintln!("[NICQ-COST] no NIC, no number");
        return;
    }
    let (mac, ip) = (azos_net::net_get_mac(), azos_net::net_get_ip());
    let (Some(rxr), Some(txr)) = (region(), region()) else {
        kprintln!("[NICQ-COST] no region for the rings, no number");
        return;
    };
    let (Some(mut rx), Some(tx)) = (RxRing::lay_out(rxr.0, rxr.2), TxRing::lay_out(txr.0, txr.2)) else {
        kprintln!("[NICQ-COST] the rings did not lay out, no number");
        return;
    };
    let (Some(rxv), Some(txv)) = (SpscBytes::from_header(rxr.1, rxr.2), SpscBytes::from_header(txr.1, txr.2)) else {
        return;
    };
    debug_assert_eq!(rxv.slot_bytes, SLOT_BYTES);
    let frame = udp_frame(mac, ip);
    let mut slot = [0u8; nq::SLOT_PAYLOAD];

    show("rx ring", per_frame(|| {
        let ok = rx.push(Desc { kind: nq::DESC_RX, flags: nq::STAMP_SW, tx_seq: 0 }, &frame, stamp_now()).is_ok();
        ok && rxv.try_pop(&mut slot).0 != RingStep::Blocked
    }));

    let fd = azos_net::socket_create_owned(azos_net::AF_INET, azos_net::SOCK_DGRAM, 0, azos_net::SOCK_OWNER_KERNEL);
    let bound = fd >= 0
        && azos_net::socket_bind(fd, &azos_net::SockAddr { family: azos_net::AF_INET as u16, port: PORT, addr: [0; 4] }) >= 0;
    if bound {
        let mut buf = [0u8; 64];
        show("rx socket", per_frame(|| {
            azos_net::ip::handle(&frame[14..], &mac, &ip);
            azos_net::socket_recv(fd, &mut buf) == PAYLOAD as i32
        }));
    } else {
        kprintln!("[NICQ-COST] rx socket FAILED: no kernel UDP socket, no number");
    }

    let mut bcast = [0xFFu8; 60];
    bcast[6..12].copy_from_slice(&mac);
    let mut item = [0u8; nq::DESC_BYTES + 60];
    item[..nq::DESC_BYTES].copy_from_slice(&Desc { kind: nq::DESC_TX, flags: 0, tx_seq: 0 }.encode());
    item[nq::DESC_BYTES..].copy_from_slice(&bcast);
    // A send the NIC refuses (its transmit ring full: QEMU drains it on its
    // own time) is counted, not failed: both transmit lanes meet the same NIC.
    let nic = azos_net::ip::iface_get(azos_net::PRIMARY_IF).map_or(0, |i| i.nic as usize);
    let mut prod = BytesProducer::new(txv);
    let mut refused = 0u32;
    show("tx ring", per_frame(|| {
        prod.push(0, &item);
        let Ok(Some((info, _))) = tx.pop(&mut slot) else { return false };
        let Some(f) = tx_frame(&slot, info.len, mac).1 else { return false };
        refused += azos_drv_net::net_device::send(nic, f).is_err() as u32;
        true
    }));
    kprintln!("[NICQ-COST] tx ring: {} of {} sends refused by the NIC", refused, 3 * N);

    if bound {
        let dst = azos_net::SockAddr { family: azos_net::AF_INET as u16, port: PORT, addr: [255; 4] };
        let mut refused = 0u32;
        show("tx socket", per_frame(|| {
            refused += (azos_net::socket::socket_sendto(fd, &[0x5A; PAYLOAD], &dst) != PAYLOAD as i32) as u32;
            true
        }));
        kprintln!("[NICQ-COST] tx socket: {} of {} sends refused", refused, 3 * N);
    }
    if fd >= 0 {
        azos_net::socket_close(fd);
    }
}
