// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `PTPD.ELF`: the AzOS PTP daemon.
//!
//! A ring-3 program whose topology row is its whole authority: `WRITE` on the
//! kernel's `clock` endpoint (the right to move time), the kernel's view of
//! the node's `[clock]` row (`MemObj inspect.clock`) and the sockets
//! its transport needs. It is a PTP *slave*: it follows the best master it
//! hears, measures its wall clock against it and offers each measurement to
//! the kernel's `Clock` interface (`Clock::sample`, source PTP). The kernel's
//! discipline (`azos_drv_sys::clockdisc`) decides what to do with it: slew,
//! step or filter. The protocol engine is `port.rs` over `wire.rs` and
//! `bmc.rs`, tested on the host (`tests/host/ptpd-tests`); this file is the
//! host it runs on and the loop around it.
//!
//! **Transport**: IEEE 1588 over Ethernet (Annex F, EtherType 0x88F7, `l2.rs`)
//! on the NIC queue the row grants (`queue.rs`, Kconfig `PTPD_NIC_QUEUE`),
//! when the kernel hands it over; else over UDP, the multicast group
//! 224.0.1.129 on ports 319 (event) and 320 (general).
//!
//! **Domain**: the `ptp_domain` of the `[clock]` row of the topology. A node
//! whose row declares none takes no part in PTP: the program says so and ends.
//!
//! One thread: it drains the queue or the sockets, runs the timers and sleeps a
//! millisecond when nothing arrived. On the NIC queue every timestamp is the
//! queue's, read where the frame crossed the driver. Over UDP they are taken
//! after the datagram is taken off the socket, so the poll period bounds their
//! accuracy (see `port.rs`).

#![no_std]
#![no_main]

mod bmc;
mod l2;
mod link;
mod port;
mod queue;
mod wire;

use azos_abi::invoke::{pledge_case, pledge_class, CLASS_NET, CLASS_READ, CLASS_WRITE};
use azos_abi::syscall_nr::CASE_BLOCK_WAKE;
use azos_abi::time::ClockId;
use azos_inspect_lib::Inspector;
use azos_libsys as sys;
use core::fmt::Write;
use port::{Config, Event, Host, Port, Sampled};
use sys::dev::{ClockCall, ClockClient, Ep};

/// Idle wait of the loop, ms.
const IDLE_MS: u64 = 1;
/// Datagrams taken from one socket before the others get a turn.
const BURST: usize = 8;
/// Longest datagram or frame read.
const RX_MAX: usize = 512;
/// Wait between attempts to get an address or the two ports, ms.
const RETRY_MS: u64 = 1_000;

/// What the loop asks of the kernel once the sockets are open: the block/wake
/// calls (the idle sleep, the clock sample's call), and the ops of the data
/// path (the console line, the uptime fallback, the datagrams). Neither a
/// lookup, a close, a derive, an `openat` nor any other change of authority
/// is in it: `DOMAIN_PLEDGE` takes them away for good.
const STEADY: u32 = pledge_case(CASE_BLOCK_WAKE) | pledge_class(CLASS_READ) | pledge_class(CLASS_WRITE) | pledge_class(CLASS_NET);

/// A line of console output.
struct Line {
    b: [u8; 160],
    n: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.b.len() - self.n;
        let k = s.len().min(room);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

fn say(args: core::fmt::Arguments<'_>) {
    let mut l = Line { b: [0; 160], n: 0 };
    let _ = l.write_fmt(args);
    let _ = l.write_str("\n");
    let _ = sys::console_write(sys::STDOUT, &l.b[..l.n]);
}

/// The `[clock]` row's `ptp_domain`, from the kernel's view of it (`MemObj
/// inspect.clock`); `None` when the row declares none or the view cannot be
/// read.
fn read_domain() -> Option<u64> {
    let m = sys::inspect_map(azos_abi::cap::SHM_INSPECT_CLOCK).ok()?;
    // SAFETY: the mapping lives as long as the task, read-only, and the kernel
    // writes it only with aligned 64-bit stores.
    let mut tree = unsafe { Inspector::from_mapped(m, None) }.ok()?;
    tree.read_u64("clock/ptp_domain").ok()?
}

/// What the messages travel on.
enum Link {
    /// The NIC queue of the row.
    Eth(queue::Queue),
    /// UDP sockets: one bound to the event port, in the group, one to the
    /// general port.
    Udp { event: u32, general: u32 },
}

/// The kernel as the engine sees it.
struct Env {
    clock: ClockClient<Ep>,
    link: Link,
}

fn wall() -> i128 {
    sys::clock_now(ClockId::REAL).map_or(0, |t| t as i128)
}

/// The wall time of a stamp on the monotonic clock.
fn wall_of(stamp_ns: u64) -> i128 {
    l2::wall_of(stamp_ns, wall(), sys::vdso_now_ns())
}

impl Host for Env {
    fn send(&mut self, msg: &[u8]) -> Option<i128> {
        // Only Delay_Req is sent, and it is an event message.
        match &mut self.link {
            // The queue's departure stamp.
            Link::Eth(q) => q.send(msg).map(wall_of),
            Link::Udp { event, .. } => {
                // The software transmit timestamp: as late as the call allows.
                let t = wall();
                (sys::sendto_typed(*event, msg, Some(&sys::sockaddr_in(link::GROUP, link::PORT_EVENT))) > 0).then_some(t)
            }
        }
    }

    fn sample(&mut self, offset_ns: i64, delay_ns: u64) -> Sampled {
        match sys::dev::value(self.clock.sample(offset_ns, delay_ns, sys::dev::clock::SOURCE_PTP)) {
            Ok(sys::dev::clock::SLEWED) => Sampled::Slewed,
            Ok(sys::dev::clock::STEPPED) => Sampled::Stepped,
            Ok(sys::dev::clock::FILTERED) => Sampled::Filtered,
            Err(sys::dev::outcome::REFUSED) => Sampled::Refused,
            _ => Sampled::Failed,
        }
    }

    fn event(&mut self, e: Event) {
        match e {
            Event::Master(id) => say(format_args!("[ptpd] following grandmaster {:02x?}", id)),
            Event::MasterLost => say(format_args!("[ptpd] master lost")),
            Event::NoUtc => say(format_args!("[ptpd] master states no valid UTC offset on the PTP timescale: no sample")),
            Event::Sample { offset_ns, delay_ns, how } => {
                say(format_args!("[ptpd] offset {} ns, round trip {} ns: {:?}", offset_ns, delay_ns, how))
            }
        }
    }
}

/// A UDP socket bound to `port` in the PTP group.
fn udp(port: u16) -> Option<u32> {
    let cap = sys::socket_typed(2, 2, 0);
    if cap < 0 {
        return None;
    }
    let cap = cap as u32;
    if sys::bind_typed(cap, &sys::sockaddr_in([0, 0, 0, 0], port)) < 0 || sys::mcast_join_typed(cap, link::GROUP) < 0 {
        let _ = sys::close_typed(cap);
        return None;
    }
    Some(cap)
}

/// The two sockets and the clock identity the node's address makes. Waits for
/// the address and retries the ports: the daemon's row has `OnFailure`, so
/// ending would only restart it into the same wait.
fn open() -> (u32, u32, [u8; 8]) {
    let mut told = false;
    loop {
        let ip = sys::net_getip();
        if ip > 0 {
            if let Some(event) = udp(link::PORT_EVENT) {
                if let Some(general) = udp(link::PORT_GENERAL) {
                    return (event, general, link::ip_identity((ip as u32).to_be_bytes()));
                }
                let _ = sys::close_typed(event);
            }
            if !told {
                told = true;
                say(format_args!("[ptpd] cannot open ports 319 and 320 (taken?): retrying"));
            }
        }
        sys::sleep(RETRY_MS);
    }
}

/// Take what is queued on the medium: each message goes to the engine with its
/// arrival time. Whether anything came.
fn drain(env: &mut Env, port: &mut Port) -> bool {
    if matches!(env.link, Link::Eth(_)) {
        let mut f = [0u8; queue::FRAME_MAX];
        let mut any = false;
        for _ in 0..2 * BURST {
            let got = match &mut env.link {
                Link::Eth(q) => q.recv(&mut f),
                Link::Udp { .. } => None,
            };
            let Some((n, stamp)) = got else { break };
            any = true;
            // The arrival time is the queue's stamp.
            if let Some(msg) = l2::message(&f[..n]) {
                port.rx(env, stamp, wall_of(stamp), msg);
            }
        }
        return any;
    }
    let Link::Udp { event, general } = env.link else { return false };
    let mut buf = [0u8; RX_MAX];
    let mut any = false;
    for sock in [event, general] {
        for _ in 0..BURST {
            let n = sys::recvfrom_typed(sock, &mut buf, None);
            if n <= 0 {
                break;
            }
            // The arrival time, taken first.
            let (now, t_rx) = (sys::vdso_now_ns(), wall());
            any = true;
            port.rx(env, now, t_rx, &buf[..n as usize]);
        }
    }
    any
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    say(format_args!("[ptpd] AzOS PTP daemon"));
    let Some(domain) = link::domain_of(read_domain()) else {
        say(format_args!("[ptpd] the [clock] row declares no ptp_domain: this node takes no part in PTP"));
        sys::exit(0);
    };
    let Some(ep) = sys::dev::lookup(sys::dev::key::CLOCK, 0) else {
        say(format_args!("[ptpd] the row holds no clock endpoint: nothing to steer, not running (a topology to fix, not a failure to restart)"));
        sys::exit(0);
    };
    let (link, identity) = match queue::Queue::open(azos_limits::PTPD_RING_SLOTS as u32) {
        Ok(q) => {
            say(format_args!(
                "[ptpd] domain {}, IEEE 1588 over Ethernet on the row's NIC queue ({:02x?}), stamped at the driver",
                domain, q.mac
            ));
            let id = l2::mac_identity(q.mac);
            (Link::Eth(q), id)
        }
        Err(why) => {
            match why {
                queue::Unused::NotGranted => {}
                queue::Unused::NoMemory => say(format_args!("[ptpd] no memory for the NIC queue's rings: UDP instead")),
                queue::Unused::Refused(e) => say(format_args!("[ptpd] the kernel keeps the row's NIC queue (rc={}): UDP instead", e)),
            }
            let (event, general, identity) = open();
            say(format_args!("[ptpd] domain {}, IEEE 1588 over UDP", domain));
            (Link::Udp { event, general }, identity)
        }
    };
    let mut env = Env { clock: ClockClient::new(Ep(ep)), link };
    let mut port = Port::new(Config { domain, identity });
    // Setup is over: the program holds its queue or its sockets, its endpoint
    // and its console. Narrow to the steady state; a failure leaves it as wide
    // as it was.
    if sys::pledge(STEADY) < 0 {
        say(format_args!("[ptpd] cannot narrow to the steady state: running with the full call set"));
    }
    loop {
        let got = drain(&mut env, &mut port);
        port.tick(&mut env, sys::vdso_now_ns());
        if !got {
            match &mut env.link {
                Link::Eth(q) => q.wait(IDLE_MS),
                Link::Udp { .. } => sys::sleep(IDLE_MS),
            }
        }
    }
}
