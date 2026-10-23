// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Network bring-up: CONFIG.INI network settings and the NIC/stack install.

use crate::*;

/// Apply the configured network address (`net_ip`/`net_mask`/`net_gateway`
/// from CONFIG.INI, or the compiled QEMU-SLIRP-compatible defaults —
/// `crates/core/config`'s `CFG_NET_IP`/`CFG_NET_MASK`/`CFG_NET_GATEWAY` statics,
/// 10.0.2.15/24 gw 10.0.2.2 — if nothing set them) to the network stack.
///
/// Must run before `azos_net::net_init()`: that call caches the address
/// into the TCP layer, so a later `net_set_ip` would update `NET_CFG` but
/// leave TCP answering on the old one (the same ordering constraint
/// `net-smoke`'s own comment states for its MAC-derived override).
///
/// Shared between both `kernel_main`s: riscv64 had this inlined directly in
/// its own body until this hoist; aarch64 never called `azos_net::
/// net_set_ip` at all (same class of gap `install_topology`'s doc
/// describes — code nobody ported, not a deliberate omission), so its
/// stack ran with whatever `crates/net/net` itself defaults to instead of
/// these config-driven atomics.
///
/// `#[inline(always)]`: riscv64's call site had this inlined directly;
/// forcing the inline keeps that codegen unchanged (see
/// `install_ring3_seams`'s doc for the same rule applied there).
#[inline(always)]
pub(crate) fn install_net_config() {
    let ip  = azos_config::unpack_ip(
        azos_config::CFG_NET_IP.load(Ordering::Relaxed));
    let gw  = azos_config::unpack_ip(
        azos_config::CFG_NET_GATEWAY.load(Ordering::Relaxed));
    let mask = azos_config::unpack_ip(
        azos_config::CFG_NET_MASK.load(Ordering::Relaxed));
    azos_net::net_set_ip(ip, mask, gw);
    azos_net::ntp::set_exchange_sink(azos_syscall::clock::ntp_exchange);
    kprintln!("[CFG] net: {}.{}.{}.{} gw {}.{}.{}.{}",
        ip[0], ip[1], ip[2], ip[3], gw[0], gw[1], gw[2], gw[3]);
}

/// Start the `net-clients` task (Kconfig `NTP_CLIENT`): the SNTP client that
/// steers the wall clock. After the net-poll task is created, whose receive
/// path its exchanges wait on.
///
/// Shared between both `kernel_main`s: nothing in it is per ISA. Best-effort
/// priority, no hart pin: it sleeps for minutes and for an exchange waits on
/// the receive path like any caller.
pub(crate) fn start_net_clients() {
    if !azos_limits::NTP_CLIENT {
        return;
    }
    azos_sched::task_create("net-clients", net_clients_task, 0, azos_sched::DEFAULT_PRIORITY);
}

/// Compile the topology's `[firewall.NAME]` rows into the built-in packet
/// filter and install it (`azos_net::filter::Firewall`: first match wins, the
/// default policy is Kconfig `FIREWALL_INBOUND_DROP`, a flow table lets the
/// answer to an accepted flow through).
///
/// After `install_topology` (the rows live in the installed topology), before
/// any traffic that matters: the stack asks the filter at three hooks and, with
/// none installed, pays one branch. The filter is installed only if it could
/// refuse something: no row that refuses and an accepting default leaves the
/// stack as it was. A row with an IPv6 prefix judges IPv6 packets, one with an
/// IPv4 prefix IPv4 packets, one with no prefix both; a `forward` row with an
/// IPv6 prefix never matches (the stack does not route IPv6).
///
/// Shared between both `kernel_main`s: nothing in it is per ISA.
pub(crate) fn install_firewall() {
    use azos_net::filter::{self, FwRule, Hook, Verdict};
    use azos_topology::{FwAction, FwDir, FwProto};

    static FIREWALL: filter::Firewall = filter::Firewall::new();

    let rows = azos_topology::get().map_or(&[][..], |t| t.firewalls());
    let rules = rows.iter().map(|r| FwRule {
        hook: match r.dir {
            FwDir::In => Hook::Ingress,
            FwDir::Out => Hook::Egress,
            FwDir::Forward => Hook::Forward,
        },
        proto: match r.proto {
            FwProto::Any => 0,
            FwProto::Tcp => azos_net::ip::IP_PROTO_TCP,
            FwProto::Udp => azos_net::ip::IP_PROTO_UDP,
            FwProto::Icmp => azos_net::ip::IP_PROTO_ICMP,
        },
        port_lo: r.port_lo,
        port_hi: r.port_hi,
        net: r.addr.map_or([0; 16], |p| p.addr.bytes),
        net_len: r.addr.map_or(0, |p| p.len),
        net_v6: r.addr.is_some_and(|p| p.addr.v6),
        action: match r.action {
            FwAction::Allow => Verdict::Accept,
            FwAction::Drop => Verdict::Drop,
            FwAction::Reject => Verdict::Reject,
        },
    });

    // The flow table's hash key: pool bytes when a seeded source exists, the
    // clock otherwise.
    let mut key = [0u8; 8];
    if !azos_net::net_random_fill(&mut key) {
        key = azos_drv_sys::timebase::now().to_le_bytes();
    }
    let inbound = if azos_limits::FIREWALL_INBOUND_DROP { Verdict::Drop } else { Verdict::Accept };
    // `rows` holds at most `MAX_FIREWALL_ROWS`, the size of the rule table.
    let Some(n) = FIREWALL.load(inbound, rules, u64::from_le_bytes(key)) else {
        azos_drv_sys::kerr!("[FW] more rules than the table holds: no firewall installed");
        return;
    };
    if FIREWALL.needed() {
        filter::set_filter(&FIREWALL);
    }
    kprintln!("[FW] {} rule(s), IPv4 and IPv6, inbound default {}, {} flow slots: {}",
        n, if inbound == Verdict::Drop { "drop" } else { "accept" }, filter::CT_SLOTS,
        if filter::active() { "installed" } else { "nothing to refuse, not installed" });
}

/// Install the topology's `[route.NAME]` rows (CAPS.TOML format 7) in the
/// routing table of `crates/net/net` (`ip.rs`, "Interfaces and routes").
///
/// Runs once the topology is installed, which is after `net_init()` has
/// numbered the interfaces: a row's `dev` names one (`eth0`, `eth1`, ...), and
/// a row for an interface this board does not have is refused and reported,
/// not skipped silently. IPv6 rows are counted and left out: IPv6 egress is
/// not routed yet (`ipv6.rs` is single-interface and broadcasts).
pub(crate) fn install_static_routes() {
    let Some(topo) = azos_topology::get() else { return };
    let (mut added, mut v6) = (0usize, 0usize);
    for r in topo.routes() {
        if r.dest.addr.v6 {
            v6 += 1;
            continue;
        }
        let a = &r.dest.addr.bytes;
        let via = r.via.map_or([0u8; 4], |v| [v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]]);
        match azos_net::net_route_add([a[0], a[1], a[2], a[3]], r.dest.len, via, r.dev.as_bytes(), r.metric) {
            Ok(()) => added += 1,
            Err(e) => kprintln!("[NET] route {} refused: {:?}", r.name.as_str(), e),
        }
    }
    if added != 0 || v6 != 0 {
        kprintln!("[NET] {} static route(s) installed, {} IPv6 row(s) not routed", added, v6);
    }
}

/// Bring up the VirtIO-MMIO network device the hardware bus admits (feature
/// negotiation, queue setup, MAC read-back, DRIVER_OK) and the NIC's wiring.
/// Returns whether a NIC is up, this one, the virtio-pci one or the Intel one.
///
/// Shared between both `kernel_main`s. `azos_drv_virtio::virtio::net` has
/// never had a `target_arch` cfg in it — the driver itself is ISA-neutral,
/// only `crate::virtio::VIRTIO_MMIO_BASE`/`STRIDE`/`COUNT` (picked in
/// `virtio/mod.rs` from `platform::hw` on aarch64) differ per board. What
/// was missing was a CALLER on the aarch64 side: this function's body is
/// exactly what riscv64's `kernel_main` ran in place until this hoist,
/// aarch64's never ran any of it, and its own comments said so directly
/// ("no network bring-up on aarch64" — see the autorun/gpio-smoke hart
/// placement comments this task corrects alongside this call).
///
/// `#[inline(always)]`: same codegen-preservation rule as
/// `install_net_config` above.
#[inline(always)]
pub(crate) fn install_net() -> bool {
    // Remembered, not just printed: the conformance probe further down the
    // boot log has three checks that put bytes on the wire (limited
    // broadcast, subnet broadcast, multicast). With no NIC those cannot
    // pass, and until 2026-09-06 the probe counted them as FAILURES — so
    // every diskless/NIC-less boot printed `RFC 791 FAIL mask=0x40600000`
    // and nothing in the gate read the line, in either direction. A check
    // that cannot run is not a check that failed.
    // The hardware bus brings up the virtio-mmio NIC it admits (a virtio-pci
    // one came up in the PCI stage and owns the interface).
    super::hwbus::bind(&["virtio-net"]);
    let virtio_up = azos_drv_virtio::virtio::net::is_ready();
    // Kconfig DRV_E1000E / DRV_IGC: an Intel NIC the PCI stage brought up is a NIC too.
    let intel_up = azos_drv_net::net_device::pci_nic_ready();
    let nic_present = virtio_up || intel_up;
    if virtio_up {
        kprintln!("[NET] VirtIO net OK");
        // Runtime canary: a doorbell per frame again (batching and the
        // device's NO_NOTIFY ignored), so the doorbell count can be seen to
        // move back to one per frame.
        if canary!("net-kick-per-frame") {
            azos_drv_virtio::virtio::net::set_kick_every_frame(true);
            kprintln!("[CANARY] net-kick-per-frame: one doorbell per frame");
        }
        // Runtime canary: two receive passes may run at once again (N8).
        if canary!("net-rx-two-consumers") {
            azos_net::set_rx_owner_bypass(true);
            kprintln!("[CANARY] net-rx-two-consumers: every net_poll drains on its own");
        }
        // Runtime canary: a lock and a copy per received frame again.
        if canary!("net-rx-copy") {
            azos_net::set_rx_copy(true);
            kprintln!("[CANARY] net-rx-copy: one lock and one copy per received frame");
        }
        // Runtime canary: EVENT_IDX negotiated, interrupts switched by flags.
        if canary!("net-event-idx-flags") {
            azos_drv_virtio::virtio::net::set_event_idx_flags_canary(true);
            kprintln!("[CANARY] net-event-idx-flags: interrupts switched by avail.flags");
        }
        kprintln!("[NET] virtio-net EVENT_IDX: {}",
            if azos_drv_virtio::virtio::net::event_idx() { "on" } else { "off" });
        install_net_irq();
        if azos_limits::NET_TX_BATCH_SELFCHECK {
            net_tx_batch_selfcheck();
        }
    } else if !intel_up {
        kprintln!("[NET] VirtIO net not found (no NIC)");
    }
    nic_present
}

/// Kconfig `NET_TX_BATCH_SELFCHECK`: three frames inside one TX batch must
/// take no doorbell decision until the batch ends, and exactly one there
/// (with `NET_TX_BATCH_MAX` >= 3; a smaller bound decides every MAX frames)
/// (a decision is a doorbell rung, or one skipped because the device
/// reported NO_NOTIFY — which of the two depends on the device's timing,
/// the count of decisions does not). Under `canary=net-kick-per-frame`
/// every frame decides: FAIL. The frames are broadcasts of the local
/// experimental EtherType 0x88B5, which every receiver drops.
#[inline(never)]
fn net_tx_batch_selfcheck() {
    use azos_drv_virtio::virtio::net as vnet;
    const FRAMES: u64 = 3;
    let mut f = [0u8; 60];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&vnet::get_mac());
    f[12..14].copy_from_slice(&0x88B5u16.to_be_bytes());
    let decisions = |q: vnet::NetQueueStats| q.tx_doorbells + q.tx_skipped;
    let s0 = vnet::queue_stats();
    vnet::tx_batch_begin();
    let mut sent = 0u64;
    for _ in 0..FRAMES {
        if vnet::send(&f).is_ok() { sent += 1; }
    }
    let s1 = vnet::queue_stats();
    vnet::tx_batch_end();
    let s2 = vnet::queue_stats();
    let inside = decisions(s1) - decisions(s0);
    let at_end = decisions(s2) - decisions(s1);
    // NET_TX_BATCH_MAX below FRAMES rings inside the batch by design.
    let max = azos_limits::NET_TX_BATCH_MAX as u64;
    let (want_inside, want_end) = (FRAMES / max, (FRAMES % max != 0) as u64);
    let ok = sent == FRAMES && s2.tx_frames - s0.tx_frames == FRAMES
        && inside == want_inside && at_end == want_end;
    kprintln!("[NET] TX batch self-check: {} frames, doorbell decisions in batch {}, at flush {}: {}",
        sent, inside, at_end, if ok { "PASS" } else { "FAIL" });
}

/// The VisionFive 2's `gmac0` (Synopsys DesignWare QoS, `azos_drv_net::dwmac`):
/// bring the MAC and its PHY up, and with Kconfig `NET_RX_IRQ` wire its
/// interrupt source (PLIC source 7, `jh7110.dtsi`), switching the driver to
/// interrupt mode BEFORE the line is unmasked. When the NIC does not come up
/// the stack runs on whatever else it finds.
#[cfg(feature = "vf2")]
pub(crate) fn install_dwmac() {
    if let Err(e) = azos_drv_net::dwmac::board::init(azos_drv_net::dwmac::Config::JH7110_GMAC0) {
        azos_drv_sys::kerr!("[NET] gmac0 (DesignWare QoS) init failed: {:?}", e);
        return;
    }
    if azos_limits::NET_RX_IRQ {
        let line = azos_drv_base::platform::hw::ETH0_IRQ;
        let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
        if azos_drv_net::net_device::enable_irq(line) {
            crate::boot_hooks::net_mmio_unmask(hart, line);
            kprintln!("[NET] gmac0 RX interrupt: line {} -> hart {}", line, hart);
            crate::irq_thread::register(line);
        }
    }
}

/// Kconfig `NET_RX_IRQ`: wire the virtio-mmio NIC's interrupt line, so the
/// net poll task is woken by traffic instead of a 1 ms timer. The line is
/// per ISA (`boot_hooks::virtio_mmio_line`: PLIC/APLIC source, GIC SPI,
/// IOAPIC GSI); the driver is switched to IRQ mode BEFORE the line is
/// unmasked, so the first interrupt finds its handler armed. A virtio-pci
/// NIC (MSI) has no MMIO slot and is left as it is.
#[inline(always)]
fn install_net_irq() {
    if !azos_limits::NET_RX_IRQ {
        return;
    }
    let Some((slot, base)) = azos_drv_virtio::virtio::net::mmio_slot() else {
        return;
    };
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
    match crate::boot_hooks::virtio_mmio_line(slot, base) {
        Some(line) if azos_drv_virtio::virtio::net::enable_mmio_irq(line) => {
            crate::boot_hooks::net_mmio_unmask(hart, line);
            kprintln!("[NET] virtio-net-mmio slot {} RX interrupt: line {} -> hart {}",
                slot, line, hart);
            crate::irq_thread::register(line);
        }
        _ => kprintln!("[NET] virtio-net-mmio slot {}: no interrupt line here, polled", slot),
    }
}
