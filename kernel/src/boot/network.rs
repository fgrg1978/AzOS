// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kernel_main`'s network bring-up after the NIC probe (`install_net`): the
//! VisionFive 2's Ethernet and WiFi bridge, the two-node smoke's address, the
//! IP stack (`net_init`), the boot-time network smokes and the OTA listener,
//! before any real-time task exists.

use crate::*;

/// The network bring-up, in order (see the module doc). Inlined, as every
/// boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn start_network() {
    #[cfg(all(feature = "net", feature = "vf2"))]
    {
        // The board Ethernet is the Synopsys DesignWare QoS MAC (gmac0). The
        // Cadence driver `eth.rs` is not called: its register model is the
        // wrong IP's (NIC-MACB removes the VF2 half).
        install_dwmac();
        // Init UART1 bridge for ESP32-C3 WiFi relay
        let bridge_rc = azos_drv_bus::uart_bridge::bridge_init();
        if bridge_rc == 0 {
            kprintln!("[NET] UART1 bridge for ESP32 WiFi OK");
        }
    }
    // DEV01.5 — two-node network smoke (opt-in via `--features net-smoke`).
    //
    // Identity comes from the MAC that QEMU assigns per instance, so a single
    // kernel image serves both roles and no per-node disk image is needed:
    // last MAC octet 1 => server 10.0.0.1, 2 => client 10.0.0.2.
    //
    // Must run HERE, between the NIC probe (MAC is readable) and net_init()
    // (which caches the address into the TCP layer via `tcp::init`). Setting
    // the IP after net_init() would update NET_CFG but leave TCP answering on
    // the old address.
    #[cfg(feature = "net-smoke")]
    {
        let mac  = azos_drv_virtio::virtio::net::get_mac();
        let node = if mac[5] == 1 { 1u8 } else { 2u8 };
        let ip   = [10, 0, 0, node];
        azos_net::net_set_ip(ip, [255, 255, 255, 0], [10, 0, 0, 1]);
        kprintln!("[NETSMOKE] node={} ip=10.0.0.{} mac_octet={}", node, node, mac[5]);
    }

    #[cfg(feature = "net")]
    azos_net::net_init();
    kprintln!();

    // Runs HERE, before the scheduler starts preempting (see the "[SCHED]
    // Starting scheduler" line further down). After that point `kernel_main`
    // competes with ~30 tasks and, on a 1-hart QEMU, is starved to brief bursts
    // — 2000 polls need 1.9ms of CPU but took over 150 wall-seconds to
    // accumulate; this test polls for seconds and never finished. main.rs
    // already warns about this hazard ("late init code may never run to
    // completion").
    // DEV01.5 — two-node TCP smoke over a QEMU `socket` link.
    //
    // Real coverage, not a liveness ping: the client sends a deterministic
    // 256-byte pattern, the server echoes it, and the client compares every
    // byte. A single wrong or missing byte is a FAIL. This exercises ARP,
    // the IPv4 header checksum, the TCP handshake and — the reason it
    // exists — RX checksum validation in BOTH directions.
    //
    // Emits exactly one verdict line, `[NETSMOKE] PASS` or
    // `[NETSMOKE] FAIL <reason>`, so the harness can assert on it.
    #[cfg(feature = "net-smoke")]
    net_pair_smoke();

    // DEV01.6 — boot-time DHCP smoke (opt-in via `--features dhcp-smoke`).
    // Runs here, before the scheduler preempts, for the same reason as the
    // other smokes: `dhcp_start` polls, and a starved polling context turns a
    // fixed poll budget into a fraction of the time it was sized for. See
    // `run_dhcp_smoke`'s own doc for what it asserts.
    #[cfg(feature = "dhcp-smoke")]
    run_dhcp_smoke();

    // ── OTA auto-recv (early spawn) ──────────────────────────────────────────
    // Spawn the OTA TCP listener task BEFORE any RT-priority tasks. Once
    // rt-motor / flight-ctrl / sensor-ahrs are created and the timer ISR
    // starts preempting kernel_main on the boot CPU, late init code may
    // never run to completion. Spawning early guarantees the listener is
    // registered while the boot CPU is still single-tasking. Kconfig NET.
    #[cfg(feature = "net")]
    {
        let port = azos_config::CFG_OTA_AUTO_RECV_PORT.load(
            core::sync::atomic::Ordering::Relaxed);
        if port != 0 && port <= 65535 {
            // Kconfig TASK_OTA_RECV_PLACE (`general`: outside the CPUs of
            // the RT tasks).
            azos_sched::task_create_affinity(
                "ota-recv",
                azos_recovery::ota_recv_task_entry,
                port as usize,
                azos_sched::NET_POLL_PRIORITY,
                place::pin(place::OTA_RECV),
            );
            kprintln!("[OTA] Auto-recv task created on port {} (early)", port);
        }
    }

    kprintln!();
}
