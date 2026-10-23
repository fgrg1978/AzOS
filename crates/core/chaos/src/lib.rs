// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fault injection registry (Kconfig `CHAOS`, kernel cargo feature `chaos`).
//!
//! A fixed set of named injection points ([`Point`]). The code at each point
//! asks [`fire`] whether to fail this time, and fails the way the real fault
//! would: the frame allocator answers `OutOfMemory`, the kernel heap a null
//! pointer, a channel send "ring full", the timer sweep runs as if the clock
//! were `CHAOS_TIMER_DELAY_US` behind (every due sleeper is woken that much
//! late, never lost), the tick rings an unsolicited IPI at another CPU (an
//! interrupt the receiver finds no cause for), a block read or write
//! answers an I/O error, and a kernel-placed controller stops answering one
//! command (the NVMe controller drops a completion, the virtio-net device
//! stops taking frames, the xHCI controller ignores a command), which is
//! what its driver's timeout policy (`azos_drv_api::recovery`) is for.
//!
//! A point is armed with a rate, one firing in `rate` calls on average
//! (`1` fires every time), optionally a skip count: the first `skip` calls
//! never fire, so a test can walk a failure through every step of a
//! multi-allocation sequence, and optionally a cap: after `times` firings the
//! point disarms itself, so a device timeout can be injected exactly once
//! (`:1:1`, the driver resets the device and carries on) or twice (`:1:2`,
//! the second timeout latches it dead). Which calls fire is decided by a per-point
//! xorshift generator seeded from `chaos_seed=` (default Kconfig
//! `CHAOS_SEED`) and the point's index: the same seed and the same call
//! order fail the same calls.
//!
//! Arming: [`arm`] from a test (immediate), or
//! `chaos=<name>:<rate>[:<times>][,...]` on the kernel command line ([`parse_cmdline`]), which takes effect only
//! at [`go_live`], once boot init is done: boot itself treats an allocation
//! failure as fatal, and that is not a degradation this registry measures.
//!
//! Off (feature `on` absent, every deployment profile, and refused with
//! `SECURE_BOOT_ENFORCED`): [`fire`] is a constant `false`, so every site
//! compiles to the code it was before. On: one load and a branch per site
//! call while the point is disarmed.
#![no_std]
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Built in.
pub const ON: bool = cfg!(feature = "on");

/// The injection points, by index into [`NAMES`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Point {
    /// `azos_mm::pmm` single-frame allocation answers `OutOfMemory`.
    FrameAlloc = 0,
    /// The kernel heap (`GlobalAlloc::alloc`) answers null. Every kernel
    /// heap allocation but `try_reserve`-style ones treats null as fatal, so
    /// this point is refused from the command line (test scope only).
    HeapAlloc = 1,
    /// `azos_ipc::kpipe::KPipe::write` answers "refused" before writing.
    IpcSend = 2,
    /// The timer sweep wakes sleepers `CHAOS_TIMER_DELAY_US` late.
    TimerWake = 3,
    /// The timer sweep rings an unsolicited IPI at the next online CPU.
    SpuriousIrq = 4,
    /// `azos_drv_block::blkdev` read or write answers an I/O error.
    DiskIo = 5,
    /// `azos_drv_block::nvme`: the completion of an I/O command is consumed
    /// and dropped, so the command runs out of its budget.
    NvmeCompletionDrop = 6,
    /// `azos_drv_virtio::virtio::net`: the device takes no transmitted
    /// frame back until it is reset, so the ring runs out of its budget.
    VirtioNetTxWedge = 7,
    /// `azos_usb::xhci`: a command is put on the ring without its doorbell,
    /// so the controller never answers it.
    XhciCommandDrop = 8,
}

/// Number of points.
pub const N: usize = 9;
/// Every point, in index order.
pub const POINTS: [Point; N] = [
    Point::FrameAlloc,
    Point::HeapAlloc,
    Point::IpcSend,
    Point::TimerWake,
    Point::SpuriousIrq,
    Point::DiskIo,
    Point::NvmeCompletionDrop,
    Point::VirtioNetTxWedge,
    Point::XhciCommandDrop,
];
/// The command-line name of every point, by index.
pub const NAMES: [&str; N] = [
    "frame-alloc",
    "heap-alloc",
    "ipc-send",
    "timer-wake",
    "spurious-irq",
    "disk-io",
    "nvme-completion-drop",
    "virtio-net-tx-wedge",
    "xhci-command-drop",
];

impl Point {
    pub const fn name(self) -> &'static str {
        NAMES[self as usize]
    }
    pub fn from_name(n: &[u8]) -> Option<Point> {
        NAMES.iter().position(|k| k.as_bytes() == n).map(|i| POINTS[i])
    }
}

struct Slot {
    /// 0: disarmed; otherwise one firing in `rate` calls.
    rate: AtomicU32,
    skip: AtomicU32,
    /// Firings left before the point disarms itself; [`UNCAPPED`]: no cap.
    left: AtomicU32,
    rng: AtomicU64,
    checked: AtomicU64,
    fired: AtomicU64,
    /// Armed by the command line, applied at [`go_live`].
    pending: AtomicU32,
    /// The command line's cap on firings (0: none), applied with `pending`.
    pending_times: AtomicU32,
}

#[allow(clippy::declare_interior_mutable_const)]
const SLOT: Slot = Slot {
    rate: AtomicU32::new(0),
    skip: AtomicU32::new(0),
    left: AtomicU32::new(UNCAPPED),
    rng: AtomicU64::new(0),
    checked: AtomicU64::new(0),
    fired: AtomicU64::new(0),
    pending: AtomicU32::new(0),
    pending_times: AtomicU32::new(0),
};
static SLOTS: [Slot; N] = [SLOT; N];
/// `Slot::left` of a point with no cap on its firings.
const UNCAPPED: u32 = u32::MAX;
static SEED: AtomicU64 = AtomicU64::new(azos_limits::CHAOS_SEED as u64);
/// Gate canary `canary=chaos-inert`: [`arm`] arms nothing.
static INERT: AtomicBool = AtomicBool::new(false);
/// Gate canary `canary=chaos-leak`: an injected frame-allocation failure
/// also loses one frame (read by `azos_mm::pmm` at its injection site only).
static LEAK: AtomicBool = AtomicBool::new(false);

/// Should the call at `p` fail this time? A constant `false` when off.
#[inline(always)]
pub fn fire(p: Point) -> bool {
    ON && SLOTS[p as usize].rate.load(Ordering::Relaxed) != 0 && fire_armed(p)
}

#[inline(never)]
fn fire_armed(p: Point) -> bool {
    let s = &SLOTS[p as usize];
    let rate = s.rate.load(Ordering::Relaxed);
    if rate == 0 {
        return false;
    }
    s.checked.fetch_add(1, Ordering::Relaxed);
    if s.skip.load(Ordering::Relaxed) != 0
        && s.skip.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |k| k.checked_sub(1)).is_ok()
    {
        return false;
    }
    let hit = rate == 1 || {
        let x = s
            .rng
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| Some(xorshift(x)))
            .map_or(1, xorshift);
        x % rate as u64 == 0
    };
    if !hit {
        return false;
    }
    // A capped point: take one of the firings left, and disarm with the
    // last (a racing caller that finds none left does not fire).
    if s.left.load(Ordering::Relaxed) != UNCAPPED {
        match s.left.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |l| l.checked_sub(1)) {
            Ok(1) => s.rate.store(0, Ordering::Release),
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    s.fired.fetch_add(1, Ordering::Relaxed);
    true
}

const fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

fn seed_for(p: Point) -> u64 {
    let s = SEED.load(Ordering::Relaxed) ^ (p as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    if s == 0 { 0x2545_F491_4F6C_DD1D } else { s }
}

/// Arm `p`: one firing in `rate` calls (`1`: every call; `0`: disarm),
/// after the first `skip` calls. The generator restarts from the seed, so
/// the same arming fails the same calls. A no-op under `canary=chaos-inert`.
pub fn arm(p: Point, rate: u32, skip: u32) {
    arm_times(p, rate, skip, 0);
}

/// [`arm`], and the point disarms itself after `times` firings (0: never).
pub fn arm_times(p: Point, rate: u32, skip: u32, times: u32) {
    if !ON || INERT.load(Ordering::Relaxed) {
        return;
    }
    let s = &SLOTS[p as usize];
    s.rate.store(0, Ordering::Relaxed);
    s.rng.store(seed_for(p), Ordering::Relaxed);
    s.skip.store(skip, Ordering::Relaxed);
    s.left.store(if times == 0 { UNCAPPED } else { times }, Ordering::Relaxed);
    s.rate.store(rate, Ordering::Release);
}

/// Disarm `p`; its counters stay.
pub fn disarm(p: Point) {
    SLOTS[p as usize].rate.store(0, Ordering::Release);
}

/// `(rate, calls checked while armed, calls failed)` of `p`.
pub fn stats(p: Point) -> (u32, u64, u64) {
    let s = &SLOTS[p as usize];
    (s.rate.load(Ordering::Relaxed), s.checked.load(Ordering::Relaxed), s.fired.load(Ordering::Relaxed))
}

/// Calls of `p` failed so far.
pub fn fired(p: Point) -> u64 {
    SLOTS[p as usize].fired.load(Ordering::Relaxed)
}

/// The seed in use.
pub fn seed() -> u64 {
    SEED.load(Ordering::Relaxed)
}

/// Arm every point the command line named (`chaos=`), at the end of boot
/// init. Returns how many were armed.
pub fn go_live() -> usize {
    let mut n = 0;
    for p in POINTS {
        let r = SLOTS[p as usize].pending.swap(0, Ordering::Relaxed);
        if r != 0 {
            arm_times(p, r, 0, SLOTS[p as usize].pending_times.swap(0, Ordering::Relaxed));
            n += 1;
        }
    }
    n
}

/// Gate canary `canary=chaos-inert` (the kernel calls it at boot).
pub fn set_inert() {
    INERT.store(true, Ordering::Relaxed);
}

/// Gate canary `canary=chaos-leak` (the kernel calls it at boot).
pub fn set_leak_canary() {
    LEAK.store(true, Ordering::Relaxed);
}

/// Is `canary=chaos-leak` armed? Read only where an injection already fired.
pub fn leak_canary() -> bool {
    ON && LEAK.load(Ordering::Relaxed)
}

/// What [`parse_cmdline`] could not take, for the kernel to warn about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmdlineIssue<'a> {
    /// Not `<point>:<rate>[:<times>]` with a known point, a decimal rate
    /// and, if given, a decimal cap of at least 1.
    Malformed(&'a [u8]),
    /// `heap-alloc`: the kernel's heap allocations are infallible, so a
    /// random null panics wherever it lands. Test scope only ([`arm`]).
    HeapRefused,
    /// `chaos_seed=` is not a decimal number.
    BadSeed(&'a [u8]),
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    s.iter().try_fold(0u64, |a, &c| c.is_ascii_digit().then(|| a * 10 + (c - b'0') as u64))
}

/// Parse `chaos=<name>:<rate>[:<times>][,<name>:<rate>[:<times>]]` and
/// `chaos_seed=<n>` from the kernel command line. The rates (and caps) are
/// held until [`go_live`]; the seed is set now. `issue` hears every word it could not take. Returns how many
/// points are pending.
pub fn parse_cmdline<'a>(line: &'a [u8], mut issue: impl FnMut(CmdlineIssue<'a>)) -> usize {
    if !ON {
        return 0;
    }
    let mut n = 0;
    for w in line.split(|&b| b == b' ' || b == 0) {
        if let Some(v) = w.strip_prefix(b"chaos_seed=") {
            match parse_u64(v) {
                Some(s) => SEED.store(s, Ordering::Relaxed),
                None => issue(CmdlineIssue::BadSeed(v)),
            }
        } else if let Some(list) = w.strip_prefix(b"chaos=") {
            for item in list.split(|&b| b == b',').filter(|i| !i.is_empty()) {
                let mut kv = item.splitn(3, |&b| b == b':');
                let (name, rate) = (kv.next().unwrap_or(&[]), kv.next().and_then(parse_u64));
                // No cap is 0; a cap given must be a number of at least 1.
                let times = kv.next().map_or(Some(0), |t| parse_u64(t).filter(|&t| t != 0 && t < UNCAPPED as u64));
                match (Point::from_name(name), rate, times) {
                    (Some(Point::HeapAlloc), _, _) => issue(CmdlineIssue::HeapRefused),
                    (Some(p), Some(r), Some(t)) if r != 0 && r <= u32::MAX as u64 => {
                        SLOTS[p as usize].pending.store(r as u32, Ordering::Relaxed);
                        SLOTS[p as usize].pending_times.store(t as u32, Ordering::Relaxed);
                        n += 1;
                    }
                    _ => issue(CmdlineIssue::Malformed(item)),
                }
            }
        }
    }
    n
}

/// The rate the command line set for `p`, not yet live (0: none).
pub fn pending(p: Point) -> u32 {
    SLOTS[p as usize].pending.load(Ordering::Relaxed)
}

/// The cap on firings the command line set for `p`, not yet live (0: none).
pub fn pending_times(p: Point) -> u32 {
    SLOTS[p as usize].pending_times.load(Ordering::Relaxed)
}

/// Set the command-line rate and cap of `p` (0: none), as [`parse_cmdline`]
/// would.
pub fn set_pending(p: Point, rate: u32, times: u32) {
    SLOTS[p as usize].pending.store(rate, Ordering::Relaxed);
    SLOTS[p as usize].pending_times.store(times, Ordering::Relaxed);
}

/// Set the seed, as `chaos_seed=` would. Applies to the next [`arm`].
pub fn set_seed(seed: u64) {
    SEED.store(seed, Ordering::Relaxed);
}
