// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E02 — Multi-link Transport abstraction (WiFi/LoRa/RF failover).
//!
//! Defines the [`Transport`] trait implemented by each physical link
//! (WiFi/Ethernet TCP, LoRa over UART, RF modems, …) and a
//! [`MultiLinkTransport`] that owns up to [`MAX_LINKS`] of them and
//! transparently fails over when the currently active link degrades.
//!
//! Design:
//!   * Each transport reports `is_up()` and `link_quality()` (0..=255).
//!   * The multiplexer keeps them ordered by priority (index 0 = primary).
//!   * On every send/recv we track consecutive failures and last-RX time.
//!   * A link is marked "down" after
//!     [`TRANSPORT_MAX_CONSEC_FAILURES`] failed sends, **or**, while it
//!     is the active link, after no RX for
//!     [`TRANSPORT_FAILOVER_TIMEOUT_TICKS`] ticks.  RX staleness is only
//!     measured on the active link because that is the only one anything
//!     ever calls `recv()` on -- silence anywhere else says nothing.
//!   * When the active link goes down we fall back to the next-priority
//!     link that reports `is_up()`.  Every
//!     [`LINK_PROBE_INTERVAL_TICKS`] ticks we probe the (higher-priority)
//!     primary and switch back as soon as it recovers.
//!   * "Down" is not one bit: each link records *why* it is out, as a
//!     [`LinkDownReason`], because the three causes need different
//!     evidence to clear.  `is_up()` is conclusive against
//!     [`LinkDownReason::HardwareDown`] and worth nothing against the
//!     other two -- they exist precisely to catch a link that claims to
//!     be up while swallowing traffic -- so fail-back may not treat them
//!     alike.  See [`MultiLinkTransport::poll`].
//!
//! The implementation is `#![no_std]` and heap-free: all state lives in
//! fixed-size arrays.  A "tick" here is a monotonic counter supplied by
//! the caller (typically milliseconds from the CLINT).

// ── Tunables (no magic numbers) ────────────────────────────────────────────

/// Maximum number of physical links a [`MultiLinkTransport`] can hold.
/// Wheeled robot typically uses 3 links (WiFi + LoRa + RF); we reserve
/// one extra slot for future drone radios.
pub const MAX_LINKS: usize = 4;

/// Consecutive failed `send()` calls after which a link is considered down.
pub const TRANSPORT_MAX_CONSEC_FAILURES: u8 = 3;

/// No-RX timeout, in caller-supplied ticks (ms), after which a link is
/// considered down even if sends are reported as "successful" (useful for
/// half-open TCP connections).
pub const TRANSPORT_FAILOVER_TIMEOUT_TICKS: u64 = 5_000;

/// How often to re-probe a down primary link to see if it's back.
pub const LINK_PROBE_INTERVAL_TICKS: u64 = 2_000;

/// How long a link demoted for a reason `is_up()` cannot disprove
/// ([`LinkDownReason::ConsecutiveFailures`] or [`LinkDownReason::RxStale`])
/// stays out before fail-back gives it one retry anyway.
///
/// Deliberately longer than [`LINK_PROBE_INTERVAL_TICKS`]: those two
/// reasons are only reachable *while the hardware claims to be up*, so
/// the ordinary probe has no evidence to offer and re-admitting on the
/// ordinary cadence just hands the traffic back to a link we already
/// caught lying. One full [`TRANSPORT_FAILOVER_TIMEOUT_TICKS`] detection
/// window is the shortest defensible value: below it the link is back in
/// service before the mux could possibly have observed the same fault a
/// second time.
pub const LINK_SUSPECT_QUARANTINE_TICKS: u64 = TRANSPORT_FAILOVER_TIMEOUT_TICKS;

/// Link quality value returned when the underlying driver has no
/// meaningful signal metric (e.g. stub / UART transport).
pub const LINK_QUALITY_UNKNOWN: u8 = 128;

/// Link quality reported by a transport that is definitely down.
pub const LINK_QUALITY_DOWN: u8 = 0;

/// Link quality reported by a transport that is up and healthy but has
/// no extra signal information (e.g. plain Ethernet/UART).
pub const LINK_QUALITY_GOOD: u8 = 200;

// ── Error type ─────────────────────────────────────────────────────────────

/// Transport-layer error codes (kept simple — no `std::io::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Link reports `is_up() == false` (no hardware / not associated).
    NotReady,
    /// Underlying driver reported a transient failure.
    WouldBlock,
    /// Underlying driver reported a fatal send/recv error.
    Io,
    /// Caller buffer too small for the available data.
    BufTooSmall,
}

/// Why a link is not currently eligible to carry traffic.
///
/// One byte, `Copy`, stored per link -- this sits in `LinkSlot` on the
/// send/recv path, so it replaces the old single `down_marked: bool`
/// rather than sitting beside it.
///
/// **The point of the split is that the three causes clear on different
/// evidence.**  Treating them as one bit is what let fail-back reclaim a
/// link it had just failed away from:
///
/// | Reason | Set by | Cleared by |
/// |---|---|---|
/// | [`HardwareDown`](Self::HardwareDown) | `Transport::is_up() == false` | `is_up()` returning true -- directly observable from outside, so the fail-back probe can and does settle it. |
/// | [`ConsecutiveFailures`](Self::ConsecutiveFailures) | `consec_failures >= `[`TRANSPORT_MAX_CONSEC_FAILURES`] | `consec_failures` dropping back below the threshold, i.e. one successful send or recv on this link. |
/// | [`RxStale`](Self::RxStale) | no RX for [`TRANSPORT_FAILOVER_TIMEOUT_TICKS`] *while active* | `last_rx_tick` advancing, i.e. one successful recv on this link. |
///
/// The last two are only reachable while the hardware still claims to be
/// up, so `is_up()` is no evidence at all against them, and neither can
/// be re-tested from outside: nothing calls `recv()` on a non-active
/// link, and `send()`'s fallback loop skips links that are down.  So
/// fail-back gives them two exits that do not depend on evidence the mux
/// cannot obtain (see [`MultiLinkTransport::poll`]):
///
/// * the mux is **stranded** -- the active link is itself down and
///   nothing healthy exists -- in which case a suspect link beats none;
/// * the link has served [`LINK_SUSPECT_QUARANTINE_TICKS`], long enough
///   that the fault could have been re-observed, and gets one retry.
///
/// In practice the common recovery path is neither: a radio that heals
/// almost always re-associates first, which shows up as
/// `HardwareDown` -> `None` and is reclaimed on the ordinary cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkDownReason {
    /// Healthy: the link is eligible for selection.
    None = 0,
    /// The driver reports the link is not associated / has no hardware.
    HardwareDown = 1,
    /// [`TRANSPORT_MAX_CONSEC_FAILURES`] consecutive send/recv errors
    /// while the hardware still claimed to be up.
    ConsecutiveFailures = 2,
    /// No RX for [`TRANSPORT_FAILOVER_TIMEOUT_TICKS`] while the hardware
    /// still claimed to be up -- the half-open TCP case.
    RxStale = 3,
}

// ── Transport trait ────────────────────────────────────────────────────────

/// A single physical transport channel (WiFi / LoRa / RF).
///
/// Implementations MUST be non-blocking — `recv()` returns `WouldBlock`
/// when no data is available rather than busy-looping.
pub trait Transport {
    /// Send `data`.  Returns number of bytes written on success.
    fn send(&mut self, data: &[u8]) -> Result<usize, TransportError>;

    /// Receive into `buf`.  Returns number of bytes read on success.
    /// A `WouldBlock` return means "no data yet, try later".
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// `true` while the underlying hardware / link is associated.
    fn is_up(&self) -> bool;

    /// Signal strength / quality indicator, 0 = worst, 255 = best.
    /// Drivers without a real metric should return
    /// [`LINK_QUALITY_GOOD`] when up, [`LINK_QUALITY_DOWN`] otherwise.
    fn link_quality(&self) -> u8;

    /// Short human-readable identifier — useful for diagnostics.
    /// Defaults to the empty string.
    fn name(&self) -> &'static str { "" }
}

// ── Per-link bookkeeping ───────────────────────────────────────────────────

/// Internal tracking wrapper stored inside [`MultiLinkTransport`].
struct LinkSlot<'a> {
    transport:       &'a mut dyn Transport,
    priority:        u8,
    consec_failures: u8,
    last_rx_tick:    u64,
    last_probe_tick: u64,
    down_reason:     LinkDownReason,
}

impl<'a> LinkSlot<'a> {
    fn new(transport: &'a mut dyn Transport, priority: u8, now_ticks: u64) -> Self {
        Self {
            transport,
            priority,
            consec_failures: 0,
            last_rx_tick:    now_ticks,
            last_probe_tick: now_ticks,
            down_reason:     LinkDownReason::None,
        }
    }

    /// Recompute this link's [`LinkDownReason`] from its health counters
    /// and return it.  `is_active` says whether this is the slot the mux
    /// is currently handing traffic to.
    ///
    /// Reasons are checked most-authoritative first, so a link that is
    /// both hardware-down and failing reports `HardwareDown`.
    ///
    /// **`is_active` is not a convenience — it is what makes `RxStale`
    /// mean anything.** Nothing in this state machine ever calls `recv()`
    /// on a non-active slot, so RX silence on one is silence from a link
    /// *nobody is listening to*: asserting `RxStale` there is a false
    /// positive by construction, and it used to retire every idle backup
    /// [`TRANSPORT_FAILOVER_TIMEOUT_TICKS`] after it last carried traffic,
    /// leaving `find_healthy` with nothing to fail over to. So we neither
    /// assert `RxStale` for a non-active link nor clear one it already
    /// carries: a demotion for RX-staleness is *held* until the fail-back
    /// probe in [`MultiLinkTransport::poll`] retires the quarantine.
    fn refresh_health(&mut self, now_ticks: u64, is_active: bool) -> LinkDownReason {
        if !self.transport.is_up() {
            self.down_reason = LinkDownReason::HardwareDown;
            return self.down_reason;
        }
        if self.consec_failures >= TRANSPORT_MAX_CONSEC_FAILURES {
            self.down_reason = LinkDownReason::ConsecutiveFailures;
            return self.down_reason;
        }
        if is_active {
            // U06 §4 comment audit (2026-09-26): this claims staleness is
            // only considered "once the link has received at least one
            // byte" — but `last_rx_tick` is seeded to `now_ticks` at
            // creation (`:183`) and on `switch_to` (`:550`), not to 0, so
            // `rx_started` is true from the moment the slot exists unless
            // the clock itself reads 0 (only ever true at boot, before any
            // link is created). What this check actually guards against is
            // exactly that boot-time edge, not "no byte received yet".
            let rx_started = self.last_rx_tick > 0;
            let rx_stale = rx_started
                && now_ticks.saturating_sub(self.last_rx_tick)
                    >= TRANSPORT_FAILOVER_TIMEOUT_TICKS;
            self.down_reason = if rx_stale {
                LinkDownReason::RxStale
            } else {
                LinkDownReason::None
            };
        } else if self.down_reason != LinkDownReason::RxStale {
            // Hardware is up and the failure counter is under threshold,
            // so both of the reasons testable from here are disproved.
            // A held `RxStale` is the one thing this arm must not touch.
            self.down_reason = LinkDownReason::None;
        }
        self.down_reason
    }
}

// ── MultiLinkTransport ─────────────────────────────────────────────────────

/// Multiplexes N [`Transport`]s with automatic priority-based failover.
///
/// `tick()` must be fed a monotonic counter (milliseconds recommended).
/// All public methods are non-blocking.
pub struct MultiLinkTransport<'a> {
    links:      [Option<LinkSlot<'a>>; MAX_LINKS],
    link_count: usize,
    active_idx: usize,
    now_ticks:  u64,
}

impl<'a> Default for MultiLinkTransport<'a> {
    fn default() -> Self { Self::new() }
}

impl<'a> MultiLinkTransport<'a> {
    /// Create an empty multiplexer.
    pub const fn new() -> Self {
        Self {
            links: [
                const { None },
                const { None },
                const { None },
                const { None },
            ],
            link_count: 0,
            active_idx: 0,
            now_ticks:  0,
        }
    }

    /// Register a new transport.  Lower `priority` = preferred.
    /// Returns `Err(())` if the mux is full.
    pub fn add_link(
        &mut self,
        transport: &'a mut dyn Transport,
        priority: u8,
    ) -> Result<(), ()> {
        if self.link_count >= MAX_LINKS {
            return Err(());
        }
        self.links[self.link_count] =
            Some(LinkSlot::new(transport, priority, self.now_ticks));
        self.link_count += 1;
        self.sort_by_priority();
        Ok(())
    }

    /// Update the internal clock.  Call this before every
    /// [`send`](Self::send) / [`recv`](Self::recv) / [`poll`](Self::poll).
    pub fn tick(&mut self, now_ticks: u64) {
        self.now_ticks = now_ticks;
    }

    /// Number of registered links.
    pub fn link_count(&self) -> usize { self.link_count }

    /// Index of the currently active link (primary first on boot).
    pub fn active_index(&self) -> usize { self.active_idx }

    /// Returns name of the active link, or `""` if none.
    pub fn active_name(&self) -> &'static str {
        self.links[self.active_idx]
            .as_ref()
            .map(|s| s.transport.name())
            .unwrap_or("")
    }

    /// Quality of the currently active link.
    pub fn active_quality(&self) -> u8 {
        self.links[self.active_idx]
            .as_ref()
            .map(|s| s.transport.link_quality())
            .unwrap_or(LINK_QUALITY_DOWN)
    }

    /// Why link `idx` is not currently eligible, or
    /// [`LinkDownReason::None`] if it is healthy.
    ///
    /// An index with no link registered reports
    /// [`LinkDownReason::HardwareDown`] -- there is no hardware there.
    /// Out-of-range indices are answered, not indexed: `panic = "abort"`
    /// in this kernel, so a diagnostic accessor must not be able to reset
    /// the board.
    pub fn link_down_reason(&self, idx: usize) -> LinkDownReason {
        if idx >= MAX_LINKS {
            return LinkDownReason::HardwareDown;
        }
        self.links[idx]
            .as_ref()
            .map(|s| s.down_reason)
            .unwrap_or(LinkDownReason::HardwareDown)
    }

    /// Send `data` over the active link; if that fails, fall back to the
    /// next-healthiest link and retry.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.poll();
        // Try the active link first.
        if self.try_send(self.active_idx, data).is_ok() {
            return Ok(data.len());
        }
        // Active link failed — try every other link in priority order.
        for idx in 0..self.link_count {
            if idx == self.active_idx { continue; }
            if self.link_is_up(idx) && self.try_send(idx, data).is_ok() {
                self.switch_to(idx);
                return Ok(data.len());
            }
        }
        Err(TransportError::NotReady)
    }

    /// Receive from the active link.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.poll();
        let idx = self.active_idx;
        let now = self.now_ticks;
        let slot = match self.links[idx].as_mut() {
            Some(s) => s,
            None    => return Err(TransportError::NotReady),
        };
        match slot.transport.recv(buf) {
            Ok(n) if n > 0 => {
                slot.last_rx_tick    = now;
                slot.consec_failures = 0;
                // A byte actually arrived: the hardware is up, the
                // failure counter is zeroed and RX is fresh. That
                // disproves every reason at once.
                slot.down_reason     = LinkDownReason::None;
                Ok(n)
            }
            Ok(_) => Err(TransportError::WouldBlock),
            Err(TransportError::WouldBlock) => Err(TransportError::WouldBlock),
            Err(e) => {
                slot.consec_failures = slot.consec_failures.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Re-evaluate health of all links and, if the active one is down
    /// while a higher-priority link has come back, fail back.
    pub fn poll(&mut self) {
        let now = self.now_ticks;
        let active = self.active_idx;
        for (idx, slot_opt) in
            self.links.iter_mut().take(self.link_count).enumerate()
        {
            if let Some(slot) = slot_opt.as_mut() {
                slot.refresh_health(now, idx == active);
            }
        }

        // Fail over: if the active link is dead, pick the best healthy one.
        let active_down = self.links[self.active_idx]
            .as_ref()
            .map(|s| s.down_reason != LinkDownReason::None)
            .unwrap_or(true);
        if active_down {
            if let Some(next) = self.find_healthy(self.active_idx) {
                self.switch_to(next);
            }
        }

        // Still sitting on a link that is down? Then `find_healthy` came
        // back empty and there is no good link anywhere. That is the one
        // situation in which a link we suspect of lying beats what we
        // have, so fail-back below is allowed to retry one.
        let stranded = self.links[self.active_idx]
            .as_ref()
            .map(|s| s.down_reason != LinkDownReason::None)
            .unwrap_or(true);

        // Fail back: periodically try to return to a higher-priority link.
        //
        // This loop used to reclaim ANY link whose `is_up()` still
        // returned true, without consulting the down flag at all, and then
        // wipe the flag and both counters. Combined with `last_probe_tick`
        // only ever advancing when a probe fires, that made the quarantine
        // zero-length: `LINK_PROBE_INTERVAL_TICKS` (2000) is shorter than
        // `TRANSPORT_FAILOVER_TIMEOUT_TICKS` (5000), so by the time a link
        // was demoted for RX-staleness its probe was already overdue and
        // the SAME `poll()` call handed the traffic straight back to it.
        // Not a flap -- the RX-stale failover path never took effect at
        // all, and a half-open link kept every byte forever.
        //
        // Three things fix it, and all three are load-bearing:
        //   * `switch_to` stamps `last_probe_tick` on the link being LEFT,
        //     so a demoted link's quarantine has a length at all;
        //   * `refresh_health` no longer invents `RxStale` for links
        //     nobody is reading, and holds a real one across the demotion;
        //   * selection below consults the reason and re-admits each one
        //     only on evidence that actually bears on it.
        for idx in 0..self.active_idx {
            let reclaim = match self.links[idx].as_mut() {
                None => false,
                Some(slot) => {
                    let out_for = now.saturating_sub(slot.last_probe_tick);
                    if out_for < LINK_PROBE_INTERVAL_TICKS {
                        continue; // not due for a probe yet
                    }
                    let hw_up = slot.transport.is_up();
                    match slot.down_reason {
                        // Healthy as of this poll's `refresh_health`.
                        LinkDownReason::None => {
                            slot.last_probe_tick = now;
                            hw_up
                        }
                        // `refresh_health` clears this the instant
                        // `is_up()` comes back, so still seeing it here
                        // means the hardware is still down. Stamp anyway:
                        // this is the ordinary probe cadence.
                        LinkDownReason::HardwareDown => {
                            slot.last_probe_tick = now;
                            false
                        }
                        // The two reasons `is_up()` cannot disprove.
                        //
                        // NOTE the deliberate absence of a stamp on the
                        // decline path: while one of these reasons stands,
                        // `last_probe_tick` is left at the moment of
                        // demotion (`switch_to` sets it), so `out_for`
                        // reads as "how long this link has been
                        // quarantined" rather than "time since the last
                        // probe". Stamping here would restart the
                        // quarantine on every poll and it would never end.
                        LinkDownReason::ConsecutiveFailures
                        | LinkDownReason::RxStale => {
                            let served =
                                out_for >= LINK_SUSPECT_QUARANTINE_TICKS;
                            if hw_up && (stranded || served) {
                                slot.down_reason     = LinkDownReason::None;
                                slot.last_probe_tick = now;
                                true
                            } else {
                                false
                            }
                        }
                    }
                }
            };
            if reclaim {
                // `switch_to` resets `consec_failures` and `last_rx_tick`
                // for the link being adopted, which is what keeps a
                // just-cleared reason from being re-asserted by the very
                // next `refresh_health`, and stamps the quarantine on the
                // link being left.
                self.switch_to(idx);
                break;
            }
        }
    }

    // ── internal helpers ───────────────────────────────────────────────────

    fn try_send(&mut self, idx: usize, data: &[u8])
        -> Result<(), TransportError>
    {
        let slot = match self.links[idx].as_mut() {
            Some(s) => s,
            None    => return Err(TransportError::NotReady),
        };
        if !slot.transport.is_up() {
            slot.consec_failures = slot.consec_failures.saturating_add(1);
            return Err(TransportError::NotReady);
        }
        match slot.transport.send(data) {
            Ok(_) => {
                slot.consec_failures = 0;
                Ok(())
            }
            Err(e) => {
                slot.consec_failures = slot.consec_failures.saturating_add(1);
                Err(e)
            }
        }
    }

    fn link_is_up(&self, idx: usize) -> bool {
        self.links[idx]
            .as_ref()
            .map(|s| s.down_reason == LinkDownReason::None
                && s.transport.is_up())
            .unwrap_or(false)
    }

    fn find_healthy(&self, skip: usize) -> Option<usize> {
        for idx in 0..self.link_count {
            if idx == skip { continue; }
            if self.link_is_up(idx) { return Some(idx); }
        }
        None
    }

    fn switch_to(&mut self, idx: usize) {
        if idx == self.active_idx { return; }
        // The link we are leaving starts its quarantine NOW. Without this
        // its probe deadline stays whatever it was at `add_link`, which is
        // already in the past by the time anything demotes it -- so the
        // fail-back loop would reclaim it in the very same `poll()` that
        // failed away from it. This one line is what makes the quarantine
        // have a length at all.
        let leaving = self.active_idx;
        if let Some(slot) = self.links[leaving].as_mut() {
            slot.last_probe_tick = self.now_ticks;
        }
        self.active_idx = idx;
        if let Some(slot) = self.links[idx].as_mut() {
            slot.consec_failures = 0;
            slot.last_rx_tick    = self.now_ticks;
            slot.down_reason     = LinkDownReason::None;
        }
    }

    fn sort_by_priority(&mut self) {
        // Insertion sort — `link_count` is at most [`MAX_LINKS`].
        for i in 1..self.link_count {
            let mut j = i;
            while j > 0 {
                let swap = match (&self.links[j-1], &self.links[j]) {
                    (Some(a), Some(b)) => a.priority > b.priority,
                    _ => false,
                };
                if swap {
                    self.links.swap(j-1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
    }
}
