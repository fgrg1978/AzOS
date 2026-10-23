// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! AzOS network stack — port of kernel/net/
//! Ethernet → ARP / IPv4 → ICMP / UDP / TCP → BSD socket API.
//! Polling-based (call net_poll() from timer tick or shell).

pub mod ethernet;
pub mod arp;
pub mod checksum;
pub mod ip;
// The packet-filter seam: ingress, egress and forward hooks of `ip`.
pub mod filter;
pub mod ipv6;
pub mod igmp;
pub mod udp;
// Pure sequence arithmetic, split out of tcp.rs so a host suite can reach it.
pub mod seq;
pub mod tcp;
pub mod wait;
// N8: one receive pass at a time (`net_poll`'s owner bit).
pub mod rx_owner;
// Interfaces whose NIC queue a ring-3 program took (`ty::NIC_QUEUE`).
pub mod nic_queue;
pub mod socket;
#[allow(dead_code)]
pub mod dhcp;
pub mod dns;
pub mod ntp;

azos_common::ro_hook! {
    /// Where the stack's random bytes come from, installed by the kernel at boot.
    ///
    /// A hook and not a call, the same seam as `set_cap_deny_recorder` in
    /// `crates/core/syscall`: the entropy pool is wired by the kernel, the one place
    /// that sees both it and this crate. While no source is installed, or the
    /// installed one answers `false` (pool unseeded — the boards today), each
    /// consumer keeps its runtime-counter mix: the DHCP xid, the DNS id and
    /// source port, the NTP nonce and the TCP ISN secret.
    static RANDOM_SOURCE: fn(&mut [u8]) -> bool;
}
/// Install the random source. `f` fills the whole slice and returns `true`,
/// or returns `false` and leaves the caller to its fallback. Called once at boot.
pub fn set_random_source(f: fn(&mut [u8]) -> bool) {
    RANDOM_SOURCE.set(f);
}

/// Fill `buf` from the installed source; `false` when there is none or it
/// has nothing to give.
pub fn net_random_fill(buf: &mut [u8]) -> bool {
    // Copy the pointer out: the source takes its own lock, and nesting the
    // two buys nothing.
    let f = RANDOM_SOURCE.get();
    match f {
        Some(f) => f(buf),
        None => false,
    }
}

// DEV01.2 — boot-time TFTP fetch (RFC 1350) wired over UDP.
// `tftp_client` moved to `crates/net/tftp/src/client.rs` (2026-09-05): it was
// boot-time netboot convenience, and it was the only edge from this core crate
// to a scaffolding one.


pub use socket::{
    socket_tcp_conn,
    socket_create, socket_bind, socket_connect,
    socket_listen, socket_listen_bound, socket_accept,
    socket_send, socket_recv, socket_close,
    SockAddr, AF_INET, SOCK_STREAM, SOCK_DGRAM, IPPROTO_TCP, IPPROTO_UDP,
    // Per-task socket ownership. `socket_create_owned` / `socket_accept_owned`
    // stamp the owning TID; `socket_owner` is what the syscall layer's gate
    // reads; `socket_release_all` is the task-exit hook. See `socket.rs`.
    socket_create_owned, socket_accept_owned, socket_owner,
    socket_release_all, SOCK_OWNER_KERNEL, MAX_SOCKETS,
    // Raw layer-2 sockets (kernel-owned): `proto` is the EtherType wanted
    // (`ETH_P_ALL` for all), `socket_bind` takes the interface in `port`.
    AF_PACKET, SOCK_RAW, ETH_P_ALL,
};

// The interface registry and the routing table (`ip.rs`): the kernel's boot
// code installs the topology's static routes through these, and the shell and
// the info syscall read them.
pub use ip::{Iface, IfIndex, Egress, Route, RouteError, MAX_IFS, PRIMARY_IF};

pub use ipv6::{
    ipv6_init, ipv6_link_local, ipv6_ready, udpv6_send,
    eui64_link_local, pseudo_checksum,
    ETH_TYPE_IPV6, IPV6_HDR_SIZE,
};

// ── Network configuration ─────────────────────────────────────────────────────

/// Default QEMU virt network (10.0.2.x/24 NAT).
pub const DEFAULT_IP:      [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_GATEWAY: [u8; 4] = [10, 0, 2, 2];
pub const DEFAULT_MASK:    [u8; 4] = [255, 255, 255, 0];

// ── Transport abstraction ─────────────────────────────────────────────────────
//
// On QEMU we use VirtIO net; on VF2 we use the Cadence MACB Ethernet driver.
// `azos_drv_net::net_device` picks between them ONCE, in `net_init`
// below (`net_device::select`) — these two functions used to each re-ask
// `eth::eth_is_ready()` themselves, a real cross-crate call that on QEMU
// (no `vf2` feature) always answers `false`, paid on every single frame of
// the hot path. They now read a cached choice instead.

/// The interface a frame leaves by: the one that owns its source MAC, which
/// every frame builder in the stack writes. A frame whose source is no
/// interface's (nothing builds one) leaves by the primary interface, as every
/// frame did when there was only one.
fn tx_link(frame: &[u8]) -> Option<(IfIndex, Iface)> {
    let mac = frame.get(6..12).and_then(|m| <&[u8; 6]>::try_from(m).ok());
    let ifindex = mac.and_then(ip::iface_by_mac).unwrap_or(PRIMARY_IF);
    ip::iface_get(ifindex).map(|i| (ifindex, i))
}

/// Send a raw Ethernet frame via the NIC of the interface it names. Refused
/// while a ring-3 program holds that interface's queue (`nic_queue`).
pub fn net_raw_send(frame: &[u8]) -> i32 {
    let Some((ifindex, link)) = tx_link(frame) else { return -1 };
    if !nic_queue::stack_may_send(ifindex) {
        return -1;
    }
    match azos_drv_net::net_device::send(link.nic as usize, frame) {
        Ok(n) => {
            // The frame may have started the ring's budget clock: the poller
            // must look at the ring within its cadence (`tx_watch`).
            tcp::note_tx_sent(azos_drv_net::net_device::tx_look_ticks());
            n as i32
        }
        Err(_) => -1,
    }
}

/// Send `frame` by the NIC of `ifindex`, whose queue a ring-3 program took
/// (`nic_queue`): the taker's own path, the one `net_raw_send` refuses the
/// stack. `false` when the queue is not taken (any more), the interface has
/// no NIC or the NIC refused the frame.
pub fn nic_queue_send(ifindex: IfIndex, frame: &[u8]) -> bool {
    if !nic_queue::taken(ifindex) {
        return false;
    }
    let Some(link) = ip::iface_get(ifindex).filter(|i| i.attached()) else { return false };
    azos_drv_net::net_device::send(link.nic as usize, frame).is_ok()
}

/// Receive a raw Ethernet frame from NIC `nic`.
/// Returns the number of bytes received, or 0 if none available.
fn net_raw_recv(nic: usize, buf: &mut [u8]) -> usize {
    azos_drv_net::net_device::recv(nic, buf).unwrap_or(0)
}

/// Initialize the network stack.
///
/// Must be called after the transport driver is ready (VirtIO net or MACB eth).
pub fn net_init() {
    // Seed the TCP ISN secret from runtime entropy so an attacker who has the
    // binary cannot predict every initial sequence number (RFC 6528). This
    // bare-metal target has no dedicated TRNG crate today, so we mix the
    // CLINT cycle counter at boot (unpredictable from static analysis) plus
    // each transport MAC. `tcp::init` (`isn_secret_from_pool`) already
    // replaces this seed outright with real entropy once a seeded source is
    // installed (`net_random_fill`) — this call stays the floor for boards
    // that never get one.
    let boot_time = azos_drv_sys::timebase::now();
    let seed = (boot_time as u32) ^ ((boot_time >> 32) as u32);
    tcp::isn_secret_seed(seed);

    // Number the NICs once — everything after this point
    // (`net_raw_send`/`net_raw_recv`) reads the cached table instead of
    // re-probing either device per frame. See `net_device`'s module doc.
    let nics = azos_drv_net::net_device::select();

    // Every NIC is an interface. The primary one keeps the address configured
    // for it before the probe (CONFIG.INI), or the QEMU-compatible default.
    if ip::iface_get(PRIMARY_IF).is_none() {
        ip::iface_configure(PRIMARY_IF, DEFAULT_IP, DEFAULT_MASK, DEFAULT_GATEWAY);
    }
    for nic in 0..nics {
        let mac = azos_drv_net::net_device::mac(nic);
        let ll = ipv6::eui64_link_local(&mac);
        if ip::iface_attach(nic as u8, mac, ip::ETH_MTU as u16, ll).is_none() {
            azos_drv_sys::kprintln!("[NET] NIC {} left unused: NET_MAX_INTERFACES ({}) reached",
                nic, MAX_IFS);
        }
    }

    if ip::iface_get(PRIMARY_IF).is_some_and(|i| i.attached()) {
        primary_up();
        if nics > 1 {
            azos_drv_sys::kprintln!("[NET] {} interfaces up", ip::iface_count());
        }
    }
}

/// The primary interface just got its NIC: start the layers that keep its
/// address (TCP, IPv6) and say so.
fn primary_up() {
    let Some(cfg) = ip::iface_get(PRIMARY_IF).filter(|i| i.attached()) else { return };
    tcp::init(cfg.mac, cfg.ip);
    // F22: IPv6 — compute link-local address from MAC (EUI-64).
    ipv6::ipv6_init(&cfg.mac);
    let ll = ipv6::ipv6_link_local();
    azos_drv_sys::kprintln!(
        "[NET] Stack ready — IP: {}.{}.{}.{}, GW: {}.{}.{}.{}",
        cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3],
        cfg.gateway[0], cfg.gateway[1], cfg.gateway[2], cfg.gateway[3],
    );
    azos_drv_sys::kprintln!(
        "[NET] IPv6 link-local: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
         {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        ll[0],ll[1],ll[2],ll[3],ll[4],ll[5],ll[6],ll[7],
        ll[8],ll[9],ll[10],ll[11],ll[12],ll[13],ll[14],ll[15]
    );
}

/// NIC `nic` joined the device table after [`net_init`] numbered the others (a
/// USB network function, `net_device::register_usb`): give it an interface. A
/// NIC that was attached before (the same function plugged in again) keeps its
/// interface and takes the MAC it states now. The first NIC of the machine
/// becomes the primary interface and starts TCP and IPv6 as `net_init` does.
/// The interface keeps its number when the NIC goes away: frames sent on it
/// fail until the NIC is back. `None` when the interface table is full.
pub fn net_nic_added(nic: usize) -> Option<IfIndex> {
    let primary_was_up = ip::iface_get(PRIMARY_IF).is_some_and(|i| i.attached());
    let mac = azos_drv_net::net_device::mac(nic);
    let ifindex = ip::iface_attach(nic as u8, mac, ip::ETH_MTU as u16, ipv6::eui64_link_local(&mac));
    match ifindex {
        None => azos_drv_sys::kprintln!("[NET] NIC {} left unused: NET_MAX_INTERFACES ({}) reached", nic, MAX_IFS),
        Some(PRIMARY_IF) if !primary_was_up => primary_up(),
        Some(_) => {}
    }
    ifindex
}

/// Poll for incoming packets and process them.
/// Should be called periodically (e.g. from timer handler or shell loop).
///
/// Drains up to `NET_RX_DRAIN_PER_POLL` frames per call (Kconfig) instead of
/// just one — otherwise the kernel falls behind under load.
/// The pass is one TX batch: the replies it sends and the RX buffers it
/// re-posts are announced to the NIC with one doorbell each, at the end of
/// the pass (`net_tx_batch_begin`).
///
/// Returns `true` when the budget ran out with frames possibly still
/// queued: the caller should run another pass soon rather than wait for an
/// interrupt that, with RX interrupts off for the drain, will not come.
pub fn net_poll() -> bool {
    // N8: one pass at a time, whoever calls. A caller that finds a pass in
    // progress returns at once; the owner runs one more pass for it.
    if azos_limits::CANARY_RUNTIME && RX_OWNER_BYPASS.load(core::sync::atomic::Ordering::Relaxed) {
        return net_poll_pass();
    }
    RX_OWNER.run(net_poll_pass)
}

/// The owner of the receive pass (N8): see [`rx_owner`].
static RX_OWNER: rx_owner::PassOwner = rx_owner::PassOwner::new();

/// Runtime canary `net-rx-two-consumers` (Kconfig `CANARY_RUNTIME` only):
/// every `net_poll` drains on its own again, as before N8.
static RX_OWNER_BYPASS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm the `net-rx-two-consumers` canary. Inert unless `CANARY_RUNTIME`.
pub fn set_rx_owner_bypass(on: bool) {
    RX_OWNER_BYPASS.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Runtime canary `net-rx-copy` (Kconfig `CANARY_RUNTIME` only): the
/// receive pass copies each frame out under the driver lock again.
static RX_COPY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm the `net-rx-copy` canary. Inert unless `CANARY_RUNTIME`.
pub fn set_rx_copy(on: bool) {
    RX_COPY.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Cycles spent in receive passes that took frames, and those frames.
static RX_PASS_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static RX_PASS_FRAMES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `net_poll` calls that found another pass in progress and left it a
/// request instead of draining (N8), since boot.
pub fn rx_pass_contended() -> u64 {
    RX_OWNER.contended()
}

/// Whether the net-poll task is running (it says so when it starts,
/// [`wait::note_poller_started`]): then it is the receive path's consumer and
/// an inline `net_poll` from another task only adds a request to its pass.
pub fn poller_running() -> bool {
    wait::poller_started()
}

/// One receive pass: the body of [`net_poll`], run by its owner only.
///
/// Every attached interface is drained in turn, each with the whole budget: a
/// flood on one link must not starve the others of their pass, and the total
/// stays bounded by `MAX_IFS` budgets. A frame is offered to the packet
/// sockets first (`socket::packet_rx`), then handled by its EtherType with the
/// MAC and address of the interface it arrived on.
fn net_poll_pass() -> bool {
    /// Bound the drain so we don't starve other tasks if the device is
    /// flooding (e.g. broadcast storm): `CONFIG_NET_RX_DRAIN_PER_POLL`, 64 by
    /// default ≈ one Ethernet line-rate burst.
    const MAX_DRAIN_PER_CALL: usize = azos_limits::NET_RX_DRAIN_PER_POLL;

    let t0 = azos_drv_sys::wcet::read_cycles();
    let mut drained = 0usize;
    let mut budget_hit = false;
    // The transmit rings' budget (Kconfig NET_TX_TIMEOUT_MS) is looked at
    // on every pass: a send alone looks too seldom (`TxWatch`).
    tcp::set_tx_watch_due(azos_drv_net::net_device::tx_watch());
    net_tx_batch_begin();
    for ifindex in 1..=MAX_IFS as IfIndex {
        let Some(link) = ip::iface_get(ifindex).filter(|i| i.attached()) else { continue };
        let (mac, addr, nic) = (link.mac, link.ip, link.nic as usize);
        // A queue a ring-3 program took: its frames go to the program's ring,
        // stamped at the driver boundary, and the stack sees none of them.
        let mut recv = |max: usize, f: &mut dyn FnMut(&[u8])| azos_drv_net::net_device::recv_batch(nic, max, f);
        if let Some(taken) = nic_queue::pass(ifindex, MAX_DRAIN_PER_CALL, &mut recv) {
            drained += taken;
            budget_hit |= taken == MAX_DRAIN_PER_CALL;
            continue;
        }
        let mut handle = |frame: &[u8]| {
            socket::packet_rx(ifindex, frame);
            if let Some((hdr, payload)) = ethernet::parse(frame) {
                match hdr.ethertype() {
                    ethernet::ETH_TYPE_ARP  => arp::handle(payload, &mac, &addr),
                    ethernet::ETH_TYPE_IP   => ip::handle(payload, &mac, &addr),
                    // The IPv6 stack is one global address on the primary
                    // interface (`ipv6.rs`); a frame from another link has
                    // no stack to go to.
                    ethernet::ETH_TYPE_IPV6 if ifindex == PRIMARY_IF =>
                        ipv6::ipv6_rx(payload, payload.len()),
                    _                       => {}
                }
            }
        };
        let mut taken = 0usize;
        if azos_limits::CANARY_RUNTIME && RX_COPY.load(core::sync::atomic::Ordering::Relaxed) {
            // Canary `net-rx-copy`: the path before N2 step 2, a lock and a
            // copy into a zeroed stack buffer per frame.
            let mut buf = [0u8; ethernet::ETH_FRAME_MAX];
            while taken < MAX_DRAIN_PER_CALL {
                let n = net_raw_recv(nic, &mut buf);
                if n == 0 { break; }
                taken += 1;
                handle(&buf[..n]);
            }
        } else {
            // IO-QUEUES N2 step 2: frames come in batches, by reference into
            // the NIC's own buffers (`NetDevice::recv_batch`).
            while taken < MAX_DRAIN_PER_CALL {
                let n = azos_drv_net::net_device::recv_batch(nic, MAX_DRAIN_PER_CALL - taken, &mut handle);
                if n == 0 { break; }
                taken += n;
            }
        }
        drained += taken;
        budget_hit |= taken == MAX_DRAIN_PER_CALL;
    }
    if drained != 0 {
        // Receive cost: the drain and the protocol work it did, per frame
        // (`ifconfig`). Cycles on riscv64 (instructions under -icount), TSC ticks
        // on x86_64; 0 where `read_cycles` has no counter (aarch64 without PMUv3).
        let dt = azos_drv_sys::wcet::read_cycles().wrapping_sub(t0);
        RX_PASS_CYCLES.fetch_add(dt, core::sync::atomic::Ordering::Relaxed);
        RX_PASS_FRAMES.fetch_add(drained as u64, core::sync::atomic::Ordering::Relaxed);
    }
    // End of the pass (N6): the ACKs this drain held leave now, one per
    // connection, however many of its segments arrived in the pass —
    // inside the TX batch, so they share its doorbell.
    if tcp::TCP_DELACK_PASS_FLUSH {
        tcp::flush_held_acks(false);
    }
    net_tx_batch_end();
    budget_hit
}

/// Open a TX batch on the active NIC: frames sent until
/// [`net_tx_batch_end`] may share one doorbell (at most `NET_TX_BATCH_MAX`
/// frames wait). Never hold one across a block or a yield: close it first,
/// or other tasks' frames wait with it. Nests.
#[inline]
pub fn net_tx_batch_begin() {
    azos_drv_net::net_device::tx_batch_begin();
}

/// Close the batch [`net_tx_batch_begin`] opened; announces its frames.
#[inline]
pub fn net_tx_batch_end() {
    azos_drv_net::net_device::tx_batch_end();
}

/// Send an ICMP ping to `dst_ip`, from the address of the interface its route
/// leaves by.  Returns 0 on success, -1 on ARP miss or when no route covers it.
pub fn net_ping(dst_ip: [u8; 4]) -> i32 {
    let Some(eg) = ip::route(&dst_ip) else { return -1 };
    let (mac, ip) = (eg.iface.mac, eg.iface.ip);

    // ICMP echo request (type=8, code=0)
    let mut icmp = [0u8; 16];
    icmp[0] = 8;  // type: echo request
    icmp[4] = 0;  // id hi
    icmp[5] = 1;  // id lo
    icmp[6] = 0;  // seq hi
    icmp[7] = 1;  // seq lo
    icmp[8..16].copy_from_slice(b"RobotOS!");
    let cs = ip::checksum(&icmp);
    let cb = cs.to_be_bytes();
    icmp[2] = cb[0];
    icmp[3] = cb[1];

    ip::send(&mac, &ip, &dst_ip, ip::IP_PROTO_ICMP, &icmp)
}

/// Print network interface information: every interface, then the static
/// routes.
pub fn net_info() {
    // Copy out, then print. `kprintln!` reaches the UART, whose write loop is
    // `while !can_write() {}` -- an MMIO poll on real hardware. Since K-C29
    // step 2 a `SpinLock` section is non-preemptible, so printing under a
    // lock made an unbounded hardware wait non-preemptible, and this function
    // is reachable from ring 3 at any time through `SYS_NET_INFO`.
    // `iface_get` and `routes` hand out copies, so no lock is held below.
    let mut any = false;
    for ifindex in 1..=MAX_IFS as IfIndex {
        let Some(cfg) = ip::iface_get(ifindex) else { continue };
        any = true;
        let name = ip::iface_name(ifindex);
        let name = core::str::from_utf8(&name).unwrap_or("eth?");
        let mac = &cfg.mac;
        azos_drv_sys::kconsoleln!(
            "[NET] {}: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  mtu {}",
            name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], cfg.mtu
        );
        azos_drv_sys::kconsoleln!(
            "[NET]       inet {}.{}.{}.{}  mask {}.{}.{}.{}",
            cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3],
            cfg.mask[0], cfg.mask[1], cfg.mask[2], cfg.mask[3],
        );
        azos_drv_sys::kconsoleln!(
            "[NET]       gw   {}.{}.{}.{}",
            cfg.gateway[0], cfg.gateway[1], cfg.gateway[2], cfg.gateway[3],
        );
        if cfg.attached() {
            let l = &cfg.ip6_link_local;
            azos_drv_sys::kconsoleln!(
                "[NET]       inet6 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7],
                l[8], l[9], l[10], l[11], l[12], l[13], l[14], l[15]);
        } else {
            azos_drv_sys::kconsoleln!("[NET]       (not ready — no NIC)");
        }
    }
    if !any {
        azos_drv_sys::kconsoleln!("[NET] eth0: (not ready — no NIC)");
    }
    for r in ip::routes().iter().flatten() {
        let name = ip::iface_name(r.ifindex);
        azos_drv_sys::kconsoleln!(
            "[NET] route {}.{}.{}.{}/{} via {}.{}.{}.{} dev {} metric {}",
            r.dest[0], r.dest[1], r.dest[2], r.dest[3], r.plen,
            r.via[0], r.via[1], r.via[2], r.via[3],
            core::str::from_utf8(&name).unwrap_or("eth?"), r.metric,
        );
    }
    let (pd, pdrop) = socket::packet_stats();
    if pd != 0 || pdrop != 0 {
        azos_drv_sys::kconsoleln!("[NET]       packet sockets: {} frames delivered, {} dropped", pd, pdrop);
    }
    // IO-QUEUES N1/N2: frames per doorbell is tx_frames / tx_doorbells.
    if let Some(q) = azos_drv_net::net_device::virtio_queue_stats() {
        azos_drv_sys::kconsoleln!(
            "[NET]       queues: tx {} frames {} doorbells {} skipped {} dropped, \
             rx {} frames {} doorbells {} skipped, {} irqs",
            q.tx_frames, q.tx_doorbells, q.tx_skipped, q.tx_dropped,
            q.rx_frames, q.rx_doorbells, q.rx_skipped, q.irqs);
    }
    // N8: `net_poll` calls that found a pass in progress and left the owner
    // a request rather than draining beside it.
    let (cy, fr) = (RX_PASS_CYCLES.load(core::sync::atomic::Ordering::Relaxed),
                    RX_PASS_FRAMES.load(core::sync::atomic::Ordering::Relaxed));
    azos_drv_sys::kconsoleln!("[NET]       rx passes: {} contended, {} frames in {} cycles ({} per frame)",
        rx_pass_contended(), fr, cy, if fr != 0 { cy / fr } else { 0 });
    let (fired, late) = tcp::timer_lateness();
    let tpus = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
    azos_drv_sys::kconsoleln!("[NET]       tcp timers: {} fired, latest {} us past its deadline",
        fired, late / tpus);
}

/// Set the primary interface's address configuration: address, mask and the
/// default gateway of the lease (or of `CONFIG.INI`). Refused, with nothing
/// changed, for a mask with a hole in it.
pub fn net_set_ip(ip: [u8; 4], mask: [u8; 4], gw: [u8; 4]) {
    if !ip::iface_configure(PRIMARY_IF, ip, mask, gw) { return; }
    // TCP caches its own copy for the checksum pseudo-header, and used to be
    // written only by `tcp::init`. Anything that changed the address later —
    // DHCP above all — left TCP checksumming against the old one, which drops
    // every segment silently.
    tcp::set_our_ip(ip);

    // M21 / U06-5: pre-resolve the gateway through the SAME solicited path
    // `ip::send`'s cache miss uses (`arp::send_request` + `ARP_PENDING`),
    // instead of leaving its first binding to whichever frame arrives
    // first. `arp.rs`'s own comment says "the gateway, which was inserted
    // at boot" — nothing in the tree ever called `arp::insert` for it, so
    // the first dial's `ip::send` ARPed cold, and one unsolicited "who has
    // <gateway>" from an attacker's `sha`, sent before that first dial,
    // planted the binding `learn_unsolicited` accepts — nobody had asked a
    // question yet to check it against. This does not close that window by
    // itself (the reply here can still race a forged one) — it moves the
    // question to configuration time, before any application traffic
    // exists to redirect, and gives the genuine gateway a head start over
    // an attacker who has to guess when configuration happens.
    if gw != [0, 0, 0, 0] {
        if let Some(link) = ip::iface_get(PRIMARY_IF).filter(|i| i.attached()) {
            arp::send_request(&link.mac, &ip, &gw);
        }
    }
}

/// Install one static route (a topology `[route.NAME]` row): `dest/plen` is
/// reached on the interface called `dev` (`"eth0"`), through `via`, or
/// directly on the link when `via` is `0.0.0.0`.
pub fn net_route_add(
    dest: [u8; 4], plen: u8, via: [u8; 4], dev: &[u8], metric: u32,
) -> Result<(), RouteError> {
    let ifindex = ip::iface_by_name(dev).ok_or(RouteError::NoSuchInterface)?;
    ip::route_add(dest, plen, via, ifindex, metric)
}

/// The primary interface, or an unconfigured, unattached stand-in before it
/// exists (everything zero): what the single-address consumers read.
fn primary() -> Iface {
    ip::iface_get(PRIMARY_IF).unwrap_or(Iface::detached([0; 4], [0; 4], [0; 4]))
}

/// Get the primary interface's IP address.
pub fn net_get_ip() -> [u8; 4] {
    primary().ip
}

/// Get the primary interface's default gateway.
pub fn net_get_gateway() -> [u8; 4] {
    primary().gateway
}

/// Get the primary interface's network mask.
pub fn net_get_mask() -> [u8; 4] {
    primary().mask
}

/// Get the primary interface's MAC address.
pub fn net_get_mac() -> [u8; 6] {
    primary().mac
}

/// Get the primary interface's config: (ip, mask, gateway).
pub fn net_get_config() -> ([u8; 4], [u8; 4], [u8; 4]) {
    let p = primary();
    (p.ip, p.mask, p.gateway)
}
