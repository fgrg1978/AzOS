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
    kprintln!("[CFG] net: {}.{}.{}.{} gw {}.{}.{}.{}",
        ip[0], ip[1], ip[2], ip[3], gw[0], gw[1], gw[2], gw[3]);
}

/// Probe the VirtIO-MMIO window for a network device and bring its
/// transport up (feature negotiation, queue setup, MAC read-back,
/// DRIVER_OK). Returns whether a NIC was found.
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
    let nic_present = azos_drv_virtio::virtio::net::init().is_ok();
    if nic_present {
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
        install_net_irq();
        if azos_limits::NET_TX_BATCH_SELFCHECK {
            net_tx_batch_selfcheck();
        }
    } else {
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

/// Kconfig `NET_RX_IRQ`: wire the virtio-mmio NIC's interrupt line, so the
/// net poll task is woken by traffic instead of a 1 ms timer. The line is
/// per ISA (`boot_hooks::net_mmio_line`: PLIC/APLIC source, GIC SPI,
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
    match crate::boot_hooks::net_mmio_line(slot, base) {
        Some(line) if azos_drv_virtio::virtio::net::enable_mmio_irq(line) => {
            crate::boot_hooks::net_mmio_unmask(hart, line);
            kprintln!("[NET] virtio-net-mmio slot {} RX interrupt: line {} -> hart {}",
                slot, line, hart);
        }
        _ => kprintln!("[NET] virtio-net-mmio slot {}: no interrupt line here, polled", slot),
    }
}
