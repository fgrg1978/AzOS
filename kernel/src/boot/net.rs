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
    } else {
        kprintln!("[NET] VirtIO net not found (no NIC)");
    }
    nic_present
}
