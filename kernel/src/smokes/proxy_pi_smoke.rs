// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! proxy-pi-smoke: the ring-3 GPIO driver serves a kernel client MORE urgent
//! than itself, on its own hart, past a task in between that never blocks.
//!
//! Three tasks, all pinned to the driver's hart (read live, not assumed):
//!   * the driver, `gpio_drv`, at its topology priority (24);
//!   * a hog at `HOG_PRIO` (20) that only yields — strict priority dispatch
//!     with no aging re-selects it over the driver on every yield;
//!   * a client at `CLIENT_PRIO` (14) calling through `UserDriverProxy`.
//!
//! The client blocks, so the hart goes to the next ready task — the hog, not
//! the driver. Only the donation (the client's 14 onto the driver for the
//! span of the wait) puts the driver ahead of the hog. With the old spinning
//! proxy the client never left the CPU and spun every attempt to its bound;
//! with the block and no donation (`proxy-donation-canary`) every attempt
//! ends at the 100 ms timeout and the verdict is the `FAIL TIMEOUT` line,
//! which only that path prints.
//!
//! The hog creates the client, so the hog is already on the hart when the
//! first request is queued. It stops when the client reports, or at a
//! real-time ceiling (timebase, not a yield count, which follows host load).
//! Started by `gpio_user_driver_smoke_task` after the driver has answered once.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_drv_sys::user_driver_proxy::{ProxyError, UserDriverProxy, PROXY_DONATIONS};

const CLIENT_PRIO: u32 = 14;
const HOG_PRIO: u32 = 20;
/// Attempts before the verdict: one answered attempt passes. More than
/// one only so a single timeout from host load does not fail the row; a
/// missing donation times out every one of them.
const ATTEMPTS: u32 = 3;
const HOG_CEILING_S: u64 = 5;
const GPIO_OP_PING: u32 = 0;
const PING_REPLY_TAG: u8 = 0xA5;

static DRIVER_TID: AtomicU32 = AtomicU32::new(0);
static DRIVER_BASE: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicBool = AtomicBool::new(false);
static HOG_YIELDS: AtomicU32 = AtomicU32::new(0);

pub fn start(driver_tid: u32) {
    let hart = azos_sched::task_cpu_affinity(driver_tid).unwrap_or(-1);
    let base = azos_sched::task_priority(driver_tid).unwrap_or(u32::MAX);
    if hart < 0 {
        kprintln!("[PROXYPI] FAIL setup: driver tid={} is not pinned (affinity {})",
                  driver_tid, hart);
        return;
    }
    if !(CLIENT_PRIO < HOG_PRIO && HOG_PRIO < base) {
        kprintln!("[PROXYPI] FAIL setup: need client {} < hog {} < driver {}",
                  CLIENT_PRIO, HOG_PRIO, base);
        return;
    }
    DRIVER_TID.store(driver_tid, Ordering::Release);
    DRIVER_BASE.store(base, Ordering::Release);
    azos_sched::task_create_affinity("proxypi-hog", hog, hart as usize, HOG_PRIO, hart);
}

fn hog(hart: usize) {
    azos_sched::task_create_affinity("proxypi-client", client, hart, CLIENT_PRIO,
                                         hart as i8);
    let end = now() + HOG_CEILING_S * TIMER_FREQ;
    while !DONE.load(Ordering::Acquire) && now() < end {
        HOG_YIELDS.fetch_add(1, Ordering::Relaxed);
        azos_sched::task_yield();
    }
}

fn client(hart: usize) {
    use azos_abi::cap::CapPerms;
    use azos_drv_api::{DriverIsolation, DriverManifest};
    let proxy = UserDriverProxy::new(DriverManifest::new(
        azos_driver_server::DRV_KIND_GPIO,
        "gpio-user",
        DriverIsolation::UserProcess { tid: 0 },
        CapPerms::RW,
    ));
    let driver = DRIVER_TID.load(Ordering::Acquire);
    let base = DRIVER_BASE.load(Ordering::Acquire);
    let mut out = [0u8; 8];
    for attempt in 1..=ATTEMPTS {
        let donations_before = PROXY_DONATIONS.load(Ordering::Relaxed);
        let t0 = now();
        let r = proxy.call(GPIO_OP_PING, &[0x5A], &mut out);
        let us = now().wrapping_sub(t0).saturating_mul(1_000_000) / TIMER_FREQ;
        let donations = PROXY_DONATIONS.load(Ordering::Relaxed)
            .wrapping_sub(donations_before);
        match r {
            Ok(n) if n >= 2 && out[0] == PING_REPLY_TAG => {
                let after = azos_sched::task_priority(driver).unwrap_or(u32::MAX);
                if donations == 0 {
                    kprintln!("[PROXYPI] FAIL answered with no donation (attempt {})",
                              attempt);
                } else if after != base {
                    kprintln!("[PROXYPI] FAIL not-restored: driver at {} after the reply, \
                               base {}", after, base);
                } else {
                    kprintln!("[PROXYPI] PASS client prio {} on hart {} answered in {}us \
                               (attempt {}) past a prio-{} task that never blocks; \
                               donations={}, driver back at {}",
                              CLIENT_PRIO, hart, us, attempt, HOG_PRIO, donations, after);
                    // Wave 9: the ring-3 floor. The hog keeps running.
                    azos_sched::task_create_affinity("proxypi-floor", floor_client,
                                                         hart, FLOOR_CLIENT_PRIO, hart as i8);
                    return;
                }
                DONE.store(true, Ordering::Release);
                return;
            }
            Ok(n) => {
                kprintln!("[PROXYPI] FAIL unexpected reply (len={}, out0={:#04x})", n, out[0]);
                DONE.store(true, Ordering::Release);
                return;
            }
            Err(ProxyError::Timeout) => {
                kprintln!("[PROXYPI] attempt {} of {} timed out after {}us",
                          attempt, ATTEMPTS, us);
            }
            Err(e) => {
                kprintln!("[PROXYPI] FAIL {:?} on attempt {}", e, attempt);
                DONE.store(true, Ordering::Release);
                return;
            }
        }
    }
    kprintln!("[PROXYPI] FAIL TIMEOUT: {} attempts, no reply from the driver on hart {} \
               (driver at {}, hog yielded {} times)",
              ATTEMPTS, hart,
              azos_sched::task_priority(driver).unwrap_or(u32::MAX),
              HOG_YIELDS.load(Ordering::Relaxed));
    DONE.store(true, Ordering::Release);
}

// ── Wave 9: a donation to a ring-3 driver stops at the ring-3 floor ────
//
// A kernel client in the hard-RT band (8) calls the same driver, on the
// same hart, past the same hog. The donation must lift the driver to 12
// (`RT_PRIORITY_THRESHOLD`, the floor the topology gives every ring-3
// row), not to 8. The verdict reads the priority the donation applied to
// the driver (`azos_sched::LAST_DONATION`, written by
// `donate_priority`) and the floored-donation counter across the call.
// `donation-floor-canary` removes the floor: the donation is then 8 and
// the verdict is `FAIL floor: ... below the ring-3 floor`, a line only
// that path prints.
const FLOOR_CLIENT_PRIO: u32 = 8;
const RING3_FLOOR: u32 = azos_sched::RT_PRIORITY_THRESHOLD;

fn floor_client(hart: usize) {
    use azos_abi::cap::CapPerms;
    use azos_drv_api::{DriverIsolation, DriverManifest};
    let proxy = UserDriverProxy::new(DriverManifest::new(
        azos_driver_server::DRV_KIND_GPIO,
        "gpio-user",
        DriverIsolation::UserProcess { tid: 0 },
        CapPerms::RW,
    ));
    let driver = DRIVER_TID.load(Ordering::Acquire);
    let base = DRIVER_BASE.load(Ordering::Acquire);
    let floored_before = azos_sched::DONATIONS_FLOORED.load(Ordering::Relaxed);
    azos_sched::LAST_DONATION.store(0, Ordering::Relaxed);
    let mut out = [0u8; 8];
    let mut answered = false;
    for _ in 0..ATTEMPTS {
        if let Ok(n) = proxy.call(GPIO_OP_PING, &[0x5A], &mut out) {
            answered = n >= 2 && out[0] == PING_REPLY_TAG;
            break;
        }
    }
    let floored = azos_sched::DONATIONS_FLOORED.load(Ordering::Relaxed)
        .wrapping_sub(floored_before);
    let last = azos_sched::LAST_DONATION.load(Ordering::Relaxed);
    let (to, lent) = ((last >> 32) as u32, last as u32);
    let after = azos_sched::task_priority(driver).unwrap_or(u32::MAX);
    if !answered {
        kprintln!("[PROXYPI] FAIL floor: client prio {} got no reply (driver at {})",
                  FLOOR_CLIENT_PRIO, after);
    } else if to != driver {
        kprintln!("[PROXYPI] FAIL floor: no donation to gpio_drv tid={} (last to tid={})",
                  driver, to);
    } else if lent < RING3_FLOOR {
        kprintln!("[PROXYPI] FAIL floor: gpio_drv was lent {}, below the ring-3 floor {} \
                   (client prio {})", lent, RING3_FLOOR, FLOOR_CLIENT_PRIO);
    } else if lent != RING3_FLOOR || floored == 0 {
        kprintln!("[PROXYPI] FAIL floor: lent {} with floored={}", lent, floored);
    } else if after != base {
        kprintln!("[PROXYPI] FAIL floor: driver at {} after the reply, base {}", after, base);
    } else {
        kprintln!("[PROXYPI] PASS floor: client prio {} on hart {} lent gpio_drv {} \
                   (the ring-3 floor), floored={}, driver back at {}",
                  FLOOR_CLIENT_PRIO, hart, lent, floored, after);
    }
    DONE.store(true, Ordering::Release);
}
