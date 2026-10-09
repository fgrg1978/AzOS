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
pub mod ipv6;
pub mod igmp;
pub mod udp;
// Pure sequence arithmetic, split out of tcp.rs so a host suite can reach it.
pub mod seq;
pub mod tcp;
pub mod wait;
// N8: one receive pass at a time (`net_poll`'s owner bit).
pub mod rx_owner;
pub mod socket;
#[allow(dead_code)]
pub mod dhcp;
pub mod dns;
pub mod ntp;
// E02 — multi-link transport (WiFi/LoRa/RF failover).
pub mod multilink;
pub mod lora;
pub mod rf;

/// Where the stack's random bytes come from, installed by the kernel at boot.
///
/// A hook and not a call, the same seam as `set_cap_deny_recorder` in
/// `crates/core/syscall`: the entropy pool is wired by the kernel, the one place
/// that sees both it and this crate. While no source is installed, or the
/// installed one answers `false` (pool unseeded — the boards today), each
/// consumer keeps its runtime-counter mix: the DHCP xid, the DNS id and
/// source port, the NTP nonce and the TCP ISN secret.
static RANDOM_SOURCE: azos_sync::SpinLock<Option<fn(&mut [u8]) -> bool>> =
    azos_sync::SpinLock::new(None);

/// Install the random source. `f` fills the whole slice and returns `true`,
/// or returns `false` and leaves the caller to its fallback. Called once at boot.
pub fn set_random_source(f: fn(&mut [u8]) -> bool) {
    *RANDOM_SOURCE.lock() = Some(f);
}

/// Fill `buf` from the installed source; `false` when there is none or it
/// has nothing to give.
pub fn net_random_fill(buf: &mut [u8]) -> bool {
    // Copy the pointer out: the source takes its own lock, and nesting the
    // two buys nothing.
    let f = *RANDOM_SOURCE.lock();
    match f {
        Some(f) => f(buf),
        None => false,
    }
}

// DEV01.2 — boot-time TFTP fetch (RFC 1350) wired over UDP.
// `tftp_client` moved to `crates/net/tftp/src/client.rs` (2026-09-05): it was
// boot-time netboot convenience, and it was the only edge from this core crate
// to a scaffolding one.

pub use multilink::{
    Transport, TransportError, MultiLinkTransport,
    MAX_LINKS,
    TRANSPORT_MAX_CONSEC_FAILURES,
    TRANSPORT_FAILOVER_TIMEOUT_TICKS,
    LINK_PROBE_INTERVAL_TICKS,
    LINK_QUALITY_DOWN, LINK_QUALITY_GOOD, LINK_QUALITY_UNKNOWN,
};
pub use lora::LoRaTransport;
pub use rf::{RfTransport, RF_MAX_PAYLOAD};

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
};

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

use azos_sync::SpinLock;

struct NetConfig {
    ip:      [u8; 4],
    mask:    [u8; 4],
    gateway: [u8; 4],
    mac:     [u8; 6],
    ready:   bool,
}

impl NetConfig {
    const fn new() -> Self {
        NetConfig {
            ip:      DEFAULT_IP,
            mask:    DEFAULT_MASK,
            gateway: DEFAULT_GATEWAY,
            mac:     [0; 6],
            ready:   false,
        }
    }
}

static NET_CFG: SpinLock<NetConfig> = SpinLock::new(NetConfig::new());

// ── Transport abstraction ─────────────────────────────────────────────────────
//
// On QEMU we use VirtIO net; on VF2 we use the Cadence MACB Ethernet driver.
// `azos_drv_net::net_device` picks between them ONCE, in `net_init`
// below (`net_device::select`) — these two functions used to each re-ask
// `eth::eth_is_ready()` themselves, a real cross-crate call that on QEMU
// (no `vf2` feature) always answers `false`, paid on every single frame of
// the hot path. They now read a cached choice instead.

/// Send a raw Ethernet frame via the active transport.
pub fn net_raw_send(frame: &[u8]) -> i32 {
    match azos_drv_net::net_device::send(frame) {
        Ok(n) => n as i32,
        Err(_) => -1,
    }
}

/// Receive a raw Ethernet frame from the active transport.
/// Returns the number of bytes received, or 0 if none available.
fn net_raw_recv(buf: &mut [u8]) -> usize {
    azos_drv_net::net_device::recv(buf).unwrap_or(0)
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

    // Choose the active NIC backend once — everything after this point
    // (`net_raw_send`/`net_raw_recv`) reads the cached choice instead of
    // re-probing either device per frame. See `net_device`'s module doc.
    let ready = azos_drv_net::net_device::select();
    let mac = azos_drv_net::net_device::mac();

    {
        let mut cfg = NET_CFG.lock();
        cfg.mac   = mac;
        cfg.ready = ready;
    }
    if ready {
        let cfg = NET_CFG.lock();
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

/// `net_poll` calls that found another pass in progress and left it a
/// request instead of draining (N8), since boot.
pub fn rx_pass_contended() -> u64 {
    RX_OWNER.contended()
}

/// Whether the net-poll task is running (it registers the network wait
/// hooks when it starts): then it is the receive path's consumer and an
/// inline `net_poll` from another task only adds a request to its pass.
pub fn poller_running() -> bool {
    wait::hooks_registered()
}

/// One receive pass: the body of [`net_poll`], run by its owner only.
fn net_poll_pass() -> bool {
    /// Bound the drain so we don't starve other tasks if the device is
    /// flooding (e.g. broadcast storm): `CONFIG_NET_RX_DRAIN_PER_POLL`, 64 by
    /// default ≈ one Ethernet line-rate burst.
    const MAX_DRAIN_PER_CALL: usize = azos_limits::NET_RX_DRAIN_PER_POLL;

    let (mac, ip) = {
        let cfg = NET_CFG.lock();
        (cfg.mac, cfg.ip)
    };

    let mut buf = [0u8; ethernet::ETH_FRAME_MAX];
    let mut drained = 0usize;
    net_tx_batch_begin();
    while drained < MAX_DRAIN_PER_CALL {
        let n = net_raw_recv(&mut buf);
        if n == 0 { break; }
        drained += 1;
        if let Some((hdr, payload)) = ethernet::parse(&buf[..n]) {
            match hdr.ethertype() {
                ethernet::ETH_TYPE_ARP  => arp::handle(payload, &mac, &ip),
                ethernet::ETH_TYPE_IP   => ip::handle(payload, &mac, &ip),
                ethernet::ETH_TYPE_IPV6 => ipv6::ipv6_rx(payload, payload.len()),
                _                       => {}
            }
        }
    }
    // End of the pass (N6): the ACKs this drain held leave now, one per
    // connection, however many of its segments arrived in the pass —
    // inside the TX batch, so they share its doorbell.
    if tcp::TCP_DELACK_PASS_FLUSH {
        tcp::flush_held_acks(false);
    }
    net_tx_batch_end();
    drained == MAX_DRAIN_PER_CALL
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

/// Send an ICMP ping to `dst_ip`.  Returns 0 on success, -1 on ARP miss.
pub fn net_ping(dst_ip: [u8; 4]) -> i32 {
    let (mac, ip) = {
        let cfg = NET_CFG.lock();
        (cfg.mac, cfg.ip)
    };

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

/// Print network interface information.
/// What `net_info` prints, lifted out from under the lock.
struct NetCfgSnapshot {
    mac: [u8; 6],
    ip: [u8; 4],
    mask: [u8; 4],
    gateway: [u8; 4],
    ready: bool,
}

pub fn net_info() {
    // Copy out, then print. `kprintln!` reaches the UART, whose write loop is
    // `while !can_write() {}` -- an MMIO poll on real hardware. Since K-C29
    // step 2 a `SpinLock` section is non-preemptible, so printing under this
    // lock made an unbounded hardware wait non-preemptible, and this function
    // is reachable from ring 3 at any time through `SYS_NET_INFO`.
    //
    // Four small fields; the copy costs nothing and the lock is now held for
    // the length of a struct copy instead of the length of a console.
    let (mac, ip, mask, gateway, ready) = {
        let cfg = NET_CFG.lock();
        (cfg.mac, cfg.ip, cfg.mask, cfg.gateway, cfg.ready)
    };
    let cfg = NetCfgSnapshot { mac, ip, mask, gateway, ready };
    let mac = &cfg.mac;
    azos_drv_sys::kconsoleln!(
        "[NET] eth0: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
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
    if !cfg.ready {
        azos_drv_sys::kconsoleln!("[NET]       (not ready — no VirtIO net)");
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
    azos_drv_sys::kconsoleln!("[NET]       rx passes: {} contended", rx_pass_contended());
    let (fired, late) = tcp::timer_lateness();
    let tpus = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
    azos_drv_sys::kconsoleln!("[NET]       tcp timers: {} fired, latest {} us past its deadline",
        fired, late / tpus);
}

/// Set a static IP configuration.
pub fn net_set_ip(ip: [u8; 4], mask: [u8; 4], gw: [u8; 4]) {
    let mac = {
        let mut cfg = NET_CFG.lock();
        cfg.ip      = ip;
        cfg.mask    = mask;
        cfg.gateway = gw;
        cfg.mac
    };
    // TCP caches its own copy for the checksum pseudo-header, and used to be
    // written only by `tcp::init`. Anything that changed the address later —
    // DHCP above all — left TCP checksumming against the old one, which drops
    // every segment silently. Done after releasing NET_CFG so the two locks are
    // never held at once.
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
        arp::send_request(&mac, &ip, &gw);
    }
}

/// Get current IP address.
pub fn net_get_ip() -> [u8; 4] {
    NET_CFG.lock().ip
}

/// Get current gateway address.
pub fn net_get_gateway() -> [u8; 4] {
    NET_CFG.lock().gateway
}

/// Get current network mask.
pub fn net_get_mask() -> [u8; 4] {
    NET_CFG.lock().mask
}

/// Get current MAC address.
pub fn net_get_mac() -> [u8; 6] {
    NET_CFG.lock().mac
}

/// Get full network config: (ip, mask, gateway).
pub fn net_get_config() -> ([u8; 4], [u8; 4], [u8; 4]) {
    let cfg = NET_CFG.lock();
    (cfg.ip, cfg.mask, cfg.gateway)
}
