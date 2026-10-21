// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Masked-window tracer, kernel side (Kconfig `LAT_TRACE`, feature
//! `lat-trace`): the trap-exit guard, the introspection tree's `latency/`
//! read-out, and the console summary the latency rows
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
#[cfg(feature = "inspect")]
struct BufWriter<'a> {
    buf: &'a mut [u8],
    n: usize,
}

#[cfg(feature = "inspect")]
impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.buf.len() - self.n;
        let take = s.len().min(room);
        self.buf[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

/// The worst opening sites the tree lists per kind.
#[cfg(feature = "inspect")]
const TOP: usize = 5;

#[cfg(feature = "inspect")]
#[derive(Clone, Copy)]
struct KindIds {
    max_ns: azos_inspect::NodeId,
    hart: azos_inspect::NodeId,
    windows: azos_inspect::NodeId,
    unpaired: azos_inspect::NodeId,
    start: azos_inspect::NodeId,
    end: azos_inspect::NodeId,
    top: [(azos_inspect::NodeId, azos_inspect::NodeId, azos_inspect::NodeId); TOP],
}

#[cfg(feature = "inspect")]
static TREE: azos_sync::SpinLock<Option<[KindIds; 2]>> = azos_sync::SpinLock::new(None);

/// Longest site the tree keeps (`file:line`).
#[cfg(feature = "inspect")]
const SITE_MAX: usize = 96;

/// `latency/{irqsoff, preemptoff}/{max_ns, hart, windows, unpaired, start,
/// end, top/<n>/{max_ns, count, site}}`: per kind, the worst window over all
/// harts (its hart, length and the sites that opened and closed it), the
/// windows and unpaired opens counted, and the five worst opening sites.
#[cfg(feature = "inspect")]
pub fn inspect_build(b: &mut azos_inspect::Builder<'_, '_>, root: azos_inspect::NodeId) -> Result<(), azos_inspect::Error> {
    let l = b.dir(root, "latency")?;
    let mut ids = [None, None];
    for (slot, name) in ids.iter_mut().zip(["irqsoff", "preemptoff"]) {
        let d = b.dir(l, name)?;
        let max_ns = b.u64(d, "max_ns", 0)?;
        let hart = b.u64(d, "hart", 0)?;
        let windows = b.u64(d, "windows", 0)?;
        let unpaired = b.u64(d, "unpaired", 0)?;
        let start = b.string(d, "start", SITE_MAX, "-")?;
        let end = b.string(d, "end", SITE_MAX, "-")?;
        let t = b.dir(d, "top")?;
        let mut top = [(azos_inspect::NodeId::ROOT, azos_inspect::NodeId::ROOT, azos_inspect::NodeId::ROOT); TOP];
        for (k, s) in top.iter_mut().enumerate() {
            let n = b.dir(t, &crate::boot::inspect_num(k as u64))?;
            *s = (b.u64(n, "max_ns", 0)?, b.u64(n, "count", 0)?, b.string(n, "site", SITE_MAX, "-")?);
        }
        *slot = Some(KindIds { max_ns, hart, windows, unpaired, start, end, top });
    }
    if let [Some(a), Some(p)] = ids {
        *TREE.lock_irqsave() = Some([a, p]);
    }
    Ok(())
}

/// Rewrite the latency values; the ones that were not published.
#[cfg(feature = "inspect")]
pub fn inspect_refresh(w: &azos_inspect::Writer<'_>) -> u32 {
    let Some(ids) = *TREE.lock_irqsave() else { return 0 };
    let mut bad = 0u32;
    let mut ok = |r: Result<(), azos_inspect::Error>| bad += r.is_err() as u32;
    for (kind, id) in [Kind::Irq, Kind::Preempt].into_iter().zip(ids) {
        let (hart, s) = worst(kind);
        let mut windows = 0u64;
        let mut unpaired = 0u64;
        for h in 0..lat::HARTS {
            let x = lat::summary(kind, h);
            windows += x.windows;
            unpaired += x.unpaired as u64;
        }
        ok(w.set_u64(id.max_ns, ticks_to_ns(s.max)));
        ok(w.set_u64(id.hart, hart as u64));
        ok(w.set_u64(id.windows, windows));
        ok(w.set_u64(id.unpaired, unpaired));
        let mut site = [0u8; SITE_MAX];
        ok(w.set_str(id.start, site_text(s.max_start, &mut site)));
        ok(w.set_str(id.end, site_text(s.max_end, &mut site)));
        let mut top = [SiteRecord::default(); TOP];
        let n = lat::top_sites(kind, &mut top);
        for (k, (m, c, st)) in id.top.iter().enumerate() {
            let r = top.get(k).filter(|_| k < n).copied().unwrap_or_default();
            ok(w.set_u64(*m, if k < n { ticks_to_ns(r.max) } else { 0 }));
            ok(w.set_u64(*c, if k < n { r.count as u64 } else { 0 }));
            ok(w.set_str(*st, if k < n { site_text(r.site, &mut site) } else { "-" }));
        }
    }
    bad
}

/// A site as `file:line` in `buf` (cut to it).
#[cfg(feature = "inspect")]
fn site_text(site: usize, buf: &mut [u8; SITE_MAX]) -> &str {
    let mut w = BufWriter { buf: &mut buf[..], n: 0 };
    let _ = write!(w, "{}", Site(site));
    let n = w.n;
    core::str::from_utf8(&buf[..n]).unwrap_or("?")
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

/// Wave 15 (TRACE): the `lat` class's source. Installed as `lat`'s
/// new-maximum hook at boot; each new longest window on a CPU becomes one
/// trace record (nothing unless Kconfig `KTRACE_CLASS_LAT` and its mask bit).
pub fn trace_new_max(kind: Kind, _hart: usize, len: u64, open_site: usize, close_site: usize) {
    azos_trace::lat_window(kind == Kind::Preempt, len, open_site, close_site);
}
