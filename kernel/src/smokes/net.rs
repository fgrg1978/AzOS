// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The DHCP smoke.

use crate::*;

/// Boot-time DHCP smoke (opt-in via `--features dhcp-smoke`).
///
/// QEMU's user-mode backend runs a DHCP server on the gateway, so
/// `-netdev user,...` is all the infrastructure this needs. Asserts we
/// actually reach the Bound state and end up with a non-zero address in the
/// 10.0.2.x pool SLIRP hands out — not merely that `dhcp_start()` returned.
///
/// Must run after [`install_net`]/`net_init()` (needs a live transport) and
/// before the scheduler starts preempting (it busy-polls synchronously, not
/// through a task).
///
/// Shared between both `kernel_main`s: the body is pure `crates/net/net` API
/// (`dhcp::dhcp_start`, `net_poll`, `net_set_ip`, `net_get_ip`/
/// `net_get_gateway`), none of it RISC-V-specific — riscv64 had this
/// inlined directly in its own body; aarch64 gets the identical scenario
/// through the same call rather than a second copy.
///
/// `#[inline(always)]`: same codegen-preservation rule as `install_net`
/// above, applied even though this only affects the opt-in `dhcp-smoke`
/// build, not the default gate build.
#[cfg(feature = "dhcp-smoke")]
#[inline(always)]
pub(crate) fn run_dhcp_smoke() {
    // `dhcp_start` takes a `fn()` it calls once per receive attempt, and
    // only polls once itself per iteration. Pre-scheduler there is nothing
    // to yield TO, so the hook does the waiting instead: 200 attempts x 20k
    // polls is ~1.7s per phase at this placement, which is ample for a
    // server on the same host and still bounded.
    fn dhcp_smoke_wait() {
        for _ in 0..20_000 { azos_net::net_poll(); }
    }

    // Start from a deliberately wrong address so a PASS cannot be the
    // CONFIG.INI value surviving untouched.
    azos_net::net_set_ip([0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]);
    // virtio-pci IRQ mode: the NIC's per-vector MSI counts around the
    // exchange (RX is read only after an RX MSI there).
    azos_drv_virtio::virtio::net::print_msi_counts("before dhcp");

    if !azos_net::dhcp::dhcp_start(dhcp_smoke_wait) {
        kprintln!("[DHCPSMOKE] FAIL no-lease");
    } else {
        let ip = azos_net::net_get_ip();
        let gw = azos_net::net_get_gateway();
        if ip == [0, 0, 0, 0] {
            kprintln!("[DHCPSMOKE] FAIL bound-but-no-address");
        } else if ip[0] != 10 || ip[1] != 0 || ip[2] != 2 {
            // Not fatal in principle, but on QEMU user-mode it means we
            // parsed something other than the lease we were offered.
            kprintln!("[DHCPSMOKE] FAIL unexpected-subnet {}.{}.{}.{}",
                      ip[0], ip[1], ip[2], ip[3]);
        } else {
            kprintln!("[DHCPSMOKE] PASS ip={}.{}.{}.{} gw={}.{}.{}.{}",
                      ip[0], ip[1], ip[2], ip[3], gw[0], gw[1], gw[2], gw[3]);
        }
    }
    azos_drv_virtio::virtio::net::print_msi_counts("after dhcp");
}
