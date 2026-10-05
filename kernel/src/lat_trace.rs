// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Masked-window tracer, kernel side (Kconfig `LAT_TRACE`, feature
//! `lat-trace`): the trap-exit guard, the `/proc/irqsoff` and
//! `/proc/preemptoff` read-out, and the console summary the latency rows
//! print.
//!
//! The bookkeeping is `azos_arch_api::lat` (reached through
//! `azos_arch::lat_hook::lat`); the hooks on every interrupt
//! mask/unmask, preemption-counter transition and trap entry/exit are in the
//! ISA crates and `crates/core/sync`. A *site* is a `&'static Location` pointer:
//! every hook is either `#[track_caller]` (so the site is the code that took
//! the lock or masked interrupts) or names its own line (trap entry/exit).
//!
//! Units: the tracer stores counter ticks. Under `-icount shift=0` one tick
//! is 100 instructions on riscv64 (10 MHz `time`) and one instruction on
//! aarch64 (1 GHz `CNTVCT_EL0`); [`ticks_to_ns`] converts with the board's
//! `TIMER_FREQ`.

use core::fmt::Write;
use core::panic::Location;

use azos_arch::lat_hook::lat::{self, Kind, SiteRecord};
use azos_drv_sys::kprintln;

/// Closes the interrupt-path window when the trap's resched step returns
/// (`trap_resched` / `aarch64_trap_resched`): every return path of that
/// function goes back to an interrupted context that had interrupts on.
pub struct IrqExit(pub &'static Location<'static>);

impl Drop for IrqExit {
    #[inline]
    fn drop(&mut self) {
        azos_arch::lat_hook::irq_exit(self.0);
    }
}

/// Counter ticks to nanoseconds on this board.
pub fn ticks_to_ns(t: u64) -> u64 {
    let f = azos_drv_sys::timebase::TIMER_FREQ.max(1);
    ((t as u128) * 1_000_000_000u128 / f as u128) as u64
}

/// `file:line` of a site, `-` for none.
pub struct Site(pub usize);

impl core::fmt::Display for Site {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 == 0 {
            return f.write_str("-");
        }
        // SAFETY: every non-zero site the hooks store is a
        // `&'static Location<'static>` cast to `usize`.
        let loc: &'static Location<'static> = unsafe { &*(self.0 as *const Location<'static>) };
        write!(f, "{}:{}", loc.file(), loc.line())
    }
}

/// The hart with the longest window of `kind`: `(hart, summary)`.
pub fn worst(kind: Kind) -> (usize, lat::Summary) {
    let mut best = (0usize, lat::summary(kind, 0));
    for h in 1..lat::HARTS {
        let s = lat::summary(kind, h);
        if s.max > best.1.max {
            best = (h, s);
        }
    }
    best
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Irq => "irq",
        Kind::Preempt => "preempt",
    }
}

/// Truncating writer over a byte slice.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.buf.len() - self.n;
        let take = s.len().min(room);
        self.buf[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

/// One procfs file: the worst window of `kind` over all harts, and the five
/// worst opening sites. Fits the 512-byte procfs read buffer.
fn render(kind: Kind, buf: &mut [u8]) -> usize {
    let mut w = BufWriter { buf, n: 0 };
    let (hart, s) = worst(kind);
    let mut windows = 0u64;
    let mut unpaired = 0u32;
    for h in 0..lat::HARTS {
        let x = lat::summary(kind, h);
        windows += x.windows;
        unpaired += x.unpaired;
    }
    let _ = writeln!(w, "{} max_ns {} hart {} windows {} unpaired {}",
                     kind_name(kind), ticks_to_ns(s.max), hart, windows, unpaired);
    let _ = writeln!(w, "start {}", Site(s.max_start));
    let _ = writeln!(w, "end {}", Site(s.max_end));
    let mut top = [SiteRecord::default(); 5];
    let n = lat::top_sites(kind, &mut top);
    for r in top.iter().take(n) {
        let _ = writeln!(w, "{} {} {}", ticks_to_ns(r.max), r.count, Site(r.site));
    }
    w.n
}

fn gen_irqsoff(buf: &mut [u8]) -> usize {
    render(Kind::Irq, buf)
}

fn gen_preemptoff(buf: &mut [u8]) -> usize {
    render(Kind::Preempt, buf)
}

/// Register `/proc/irqsoff` and `/proc/preemptoff`.
pub fn install_procfs() {
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"irqsoff", gen_irqsoff);
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"preemptoff", gen_preemptoff);
}

/// Console summary: per kind, every hart that closed a window, then the
/// `top` worst opening sites over all harts. Lines start `[LATTRACE]`.
pub fn print_summary(tag: &str, top: usize) {
    for kind in [Kind::Irq, Kind::Preempt] {
        let name = kind_name(kind);
        for h in 0..lat::HARTS {
            let s = lat::summary(kind, h);
            if s.windows == 0 && s.unpaired == 0 {
                continue;
            }
            kprintln!("[LATTRACE] {} {} hart {} max_ns={} windows={} unpaired={} sites_full={} start={} end={}",
                      tag, name, h, ticks_to_ns(s.max), s.windows, s.unpaired, s.sites_full,
                      Site(s.max_start), Site(s.max_end));
        }
        let mut recs = [SiteRecord::default(); 16];
        let n = lat::top_sites(kind, &mut recs);
        for (i, r) in recs.iter().take(n.min(top)).enumerate() {
            kprintln!("[LATTRACE] {} {} top{} max_ns={} count={} site={} end={}",
                      tag, name, i + 1, ticks_to_ns(r.max), r.count, Site(r.site), Site(r.end));
        }
    }
}
