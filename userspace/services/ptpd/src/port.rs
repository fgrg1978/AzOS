// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The slave port: IEEE 1588 end-to-end delay measurement over UDP.
//!
//! The slave stamps a Sync on arrival (`t2`), learns the master's departure
//! time from the Sync or its Follow_Up (`t1`), sends a Delay_Req (`t3`) and
//! learns the master's arrival time from the Delay_Resp (`t4`). Offset and
//! delay come from all four ([`e2e_measure`]). The 802.1AS peer-delay
//! exchange is not here: it needs a raw Ethernet socket, which the kernel
//! keeps to itself (`crates/net/net/src/socket.rs`), so it comes with the
//! capability that grants one.
//!
//! The master is chosen by `bmc` (Announce, qualification, best dataset) and
//! the exchange ends in one number pair, which [`Host::sample`] hands to the
//! kernel's `Clock` interface. **The engine disciplines nothing**: the kernel's
//! PLL/FLL (`azos_drv_sys::clockdisc`) filters, slews or steps; this file only
//! has to measure the wall clock against the master correctly.
//!
//! **Sign and scale.** A sample is `offset_ns` = reference minus wall clock
//! (positive when the wall clock is behind: the opposite of PTP's
//! `offsetFromMaster`) and `delay_ns` = the exchange's round trip (twice the
//! mean path delay), the convention of the SNTP feeder. The master's timestamps
//! are on the PTP scale (TAI); the wall clock is UTC, so the master's times are
//! moved by the `currentUtcOffset` its Announce states before they meet the
//! wall clock's. A master that does not state a valid offset on the PTP
//! timescale ([`Foreign::utc_known`]) gives no sample at all: a 37 s error
//! offered to the discipline would be stepped into the clock.
//!
//! **What software timestamps cost.** Every `t2`/`t4` is the wall clock read
//! after the datagram was taken off the socket, every `t3` just before the send
//! call: the error is the receive path's latency (the poll period of the host
//! loop plus the kernel's queueing), one-sided, and half of it lands in the
//! offset. The rate ratio between the GM and this clock is not used: over a
//! Sync interval of 125 ms it is below a nanosecond at 10 ppm, far below the
//! timestamps' error.
//!
//! **What an exchange may pair.** The `(t1, t2)` of a Sync is used by every
//! Delay_Req sent while it is fresh and by none after: a Sync older than
//! [`STALE_SYNCS`] of the master's own Sync intervals is dropped (a master that
//! still announces but no longer syncs would otherwise have its last Sync paired
//! with a `t3`/`t4` taken arbitrarily later, and the offset would be off by half
//! the drift or step in between). The same holds when the wall clock moved
//! against the monotonic one between the stamps of an exchange by more than a
//! slew can ([`clock_moved`]), and after the kernel stepped it in answer to our
//! own sample: `t2` on the old clock and `t3` on the new one is a half-step
//! error fed straight back to the discipline.
//!
//! No sockets, no clock, no allocation: the host passes the time with every
//! message and reads the sends through [`Host`], so the whole exchange is
//! scripted on the host (`tests/host/ptpd-tests`).

use crate::bmc::{Foreign, Table, DEFAULT_INTERVAL_NS};
use crate::wire::{self, flag, mt, Body, Header, PortId, MSG_MAX, TS_1588};

/// What the kernel's discipline did with a sample (`Clock::sample`'s answer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sampled {
    Slewed,
    Stepped,
    Filtered,
    /// The step is one the clock will not make.
    Refused,
    /// The call did not reach the interface, or it failed.
    Failed,
}

/// What the engine tells its host to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Now following the grandmaster with this identity.
    Master([u8; 8]),
    /// The master went silent.
    MasterLost,
    /// The master's time is not on the PTP scale with a valid UTC offset: no
    /// sample is offered.
    NoUtc,
    /// A sample was offered.
    Sample { offset_ns: i64, delay_ns: u64, how: Sampled },
}

/// The world around the engine.
pub trait Host {
    /// Put `msg` on the wire. The software transmit timestamp: the wall clock
    /// read just before the send; `None` when the message did not leave.
    fn send(&mut self, msg: &[u8]) -> Option<i128>;
    /// Offer a measurement to the kernel's `Clock` interface.
    fn sample(&mut self, offset_ns: i64, delay_ns: u64) -> Sampled;
    /// Something to report.
    fn event(&mut self, e: Event);
}

/// The port's fixed parameters.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The `domainNumber` served (the topology's `[clock] ptp_domain`).
    pub domain: u8,
    /// This clock's identity (a PTP clock identity is any 8 bytes unique on
    /// the network).
    pub identity: [u8; 8],
}

/// Delay_Req interval until the master states one in a Delay_Resp.
pub const DELAY_REQ_INTERVAL_NS: u64 = 1_000_000_000;
/// The Sync interval assumed until a Sync states one.
pub const DEFAULT_SYNC_INTERVAL_NS: u64 = 1_000_000_000;
/// Sync intervals after which a Sync is too old to pair with a Delay_Req: a
/// lost Sync or two are bridged, a silent master is not.
pub const STALE_SYNCS: u64 = 3;
/// What two software timestamps of one exchange may disagree by, ns (the
/// receive path's latency, which the poll period of the host loop dominates).
const STAMP_JITTER_NS: i128 = 2_000_000;
/// How fast the wall clock may run against the monotonic one, parts per
/// million: the discipline's slew limit and frequency correction (500 ppm
/// each, `azos_drv_sys::clockdisc`) plus the oscillator.
const RATE_PPM_MAX: i128 = 1_500;
/// Intervals stated by a header are `2^n` seconds; the ones believed lie here.
const LOG_MIN: i8 = -7;
const LOG_MAX: i8 = 4;

/// The interval a header's `logMessageInterval` states, ns; `default` when it
/// states none (0x7F) or an absurd one.
fn interval_ns(log: i8, default: u64) -> u64 {
    if !(LOG_MIN..=LOG_MAX).contains(&log) {
        return default;
    }
    if log >= 0 {
        1_000_000_000u64 << log
    } else {
        1_000_000_000u64 >> -log
    }
}

/// The master's time (PTP scale) on the wall clock's scale (UTC).
fn to_utc(t: i128, utc_offset: i16) -> i128 {
    t - utc_offset as i128 * 1_000_000_000
}

/// What one exchange says about the wall clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measure {
    /// Reference minus wall clock.
    pub offset_ns: i64,
    /// The exchange's round trip.
    pub delay_ns: u64,
}

fn clamp_i64(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// The end-to-end exchange: `t1` the master's departure of Sync and `t4` its
/// arrival of Delay_Req (both on the master's scale, correction fields
/// already folded in), `t2` the slave's arrival of Sync and `t3` its departure
/// of Delay_Req (the wall clock).
///
/// The Sync leg takes `d_ms` and the Delay_Req leg `d_sm`, and the slave is
/// ahead of the master by `s`: `t2 - t1 = s + d_ms`, `t4 - t3 = -s + d_sm`. The
/// offset is `-s` estimated as `((t4 - t3) - (t2 - t1)) / 2`, which is exact
/// when the legs are equal and otherwise off by `(d_sm - d_ms) / 2`: a path
/// with asymmetric delay is a bias no measurement on that path can see. The
/// delay is the sum of the legs, exact either way.
pub fn e2e_measure(t1: i128, t2: i128, t3: i128, t4: i128) -> Measure {
    let (forward, back) = (t2 - t1, t4 - t3);
    Measure { offset_ns: clamp_i64((back - forward) / 2), delay_ns: (forward + back).max(0) as u64 }
}

/// Whether the wall clock moved against the monotonic clock between two
/// instants by more than slewing explains: `w0`/`m0` and `w1`/`m1` are the wall
/// and monotonic readings (ns) of the earlier and the later. A step; or the
/// clock was set by someone else.
pub fn clock_moved(w0: i128, m0: u64, w1: i128, m1: u64) -> bool {
    let mono = m1 as i128 - m0 as i128;
    let wall = w1 - w0;
    (wall - mono).abs() > STAMP_JITTER_NS + mono.abs() * RATE_PPM_MAX / 1_000_000
}

/// A Sync received, its Follow_Up awaited.
#[derive(Clone, Copy, Debug)]
struct SyncRx {
    seq: u16,
    /// Our arrival time.
    t2: i128,
    /// Monotonic time of the arrival (ns).
    at: u64,
    /// The Sync's correction field, ns.
    correction: i128,
}

/// A Sync whose departure time is known: `t1` (the master's, PTP scale, with
/// both correction fields added) and `t2` (ours).
#[derive(Clone, Copy, Debug)]
struct SyncDone {
    t1: i128,
    t2: i128,
    /// Monotonic time of the arrival (ns).
    at: u64,
}

/// A Delay_Req sent.
#[derive(Clone, Copy, Debug)]
struct DelayReqTx {
    seq: u16,
    /// Monotonic time it was sent (ns).
    at: u64,
    t3: i128,
    sync: SyncDone,
}

/// The slave port.
pub struct Port {
    cfg: Config,
    id: PortId,
    table: Table,
    master: Option<Foreign>,
    /// `NoUtc` was reported for this master.
    warned: bool,
    sync: Option<SyncRx>,
    last_sync: Option<SyncDone>,
    /// The master's Sync interval, ns.
    sync_interval: u64,
    dreq: Option<DelayReqTx>,
    dreq_seq: u16,
    next_dreq: u64,
    dreq_interval: u64,
}

impl Port {
    pub fn new(cfg: Config) -> Port {
        Port {
            cfg,
            id: PortId { clock: cfg.identity, port: 1 },
            table: Table::new(),
            master: None,
            warned: false,
            sync: None,
            last_sync: None,
            sync_interval: DEFAULT_SYNC_INTERVAL_NS,
            dreq: None,
            dreq_seq: 0,
            next_dreq: 0,
            dreq_interval: DELAY_REQ_INTERVAL_NS,
        }
    }

    fn header(&self, msg_type: u8, domain: u8, seq: u16) -> Header {
        Header::new(TS_1588, msg_type, domain, self.id, seq)
    }

    /// One message arrived. `now` is the monotonic clock (ns), `t_rx` the wall
    /// clock read as the datagram was taken off the socket.
    pub fn rx<H: Host>(&mut self, h: &mut H, now: u64, t_rx: i128, buf: &[u8]) {
        let Ok((hdr, body)) = wire::parse(buf) else { return };
        // Not ours: another profile, another domain, or this node's own message
        // back.
        if hdr.transport_specific != TS_1588 || hdr.domain != self.cfg.domain || hdr.source.clock == self.id.clock {
            return;
        }
        match body {
            Body::Announce(a) => {
                if hdr.flags & flag::ALTERNATE_MASTER == 0 && a.steps_removed < 255 {
                    let iv = interval_ns(hdr.log_interval, DEFAULT_INTERVAL_NS);
                    self.table.announce(hdr.source, hdr.flags, &a, iv, now);
                    self.select(h, now);
                }
            }
            Body::Sync { origin } => self.on_sync(&hdr, origin, now, t_rx),
            Body::FollowUp { precise_origin } => self.on_follow_up(&hdr, precise_origin),
            Body::DelayResp { receive, requesting } => self.on_delay_resp(h, &hdr, receive, requesting, now, t_rx),
            Body::DelayReq => {}
        }
    }

    /// The timers: master selection and expiry, the age of the last Sync, the
    /// next Delay_Req. Called often (every pass of the host loop).
    pub fn tick<H: Host>(&mut self, h: &mut H, now: u64) {
        self.select(h, now);
        // A master that stopped syncing leaves nothing to pair a Delay_Req with.
        let stale = self.sync_interval.saturating_mul(STALE_SYNCS);
        if self.last_sync.is_some_and(|s| now.saturating_sub(s.at) > stale) {
            self.last_sync = None;
        }
        if self.master.is_some() && self.last_sync.is_some() && now >= self.next_dreq {
            self.send_delay_req(h, now);
        }
    }

    /// Choose the master; start or stop following.
    fn select<H: Host>(&mut self, h: &mut H, now: u64) {
        let best = self.table.best(now);
        let same = match (&self.master, &best) {
            (Some(a), Some(b)) => a.sender == b.sender && a.data.identity == b.data.identity,
            (None, None) => true,
            _ => false,
        };
        if !same {
            // A new master: nothing measured against the old one carries over.
            self.sync = None;
            self.last_sync = None;
            self.dreq = None;
            self.sync_interval = DEFAULT_SYNC_INTERVAL_NS;
            self.warned = false;
            self.dreq_interval = DELAY_REQ_INTERVAL_NS;
            h.event(match &best {
                Some(b) => Event::Master(b.data.identity),
                None => Event::MasterLost,
            });
        }
        // Keep the freshest announced time scale of the master followed.
        self.master = best;
    }

    fn from_master(&self, hdr: &Header) -> bool {
        self.master.is_some_and(|m| m.sender == hdr.source)
    }

    fn on_sync(&mut self, hdr: &Header, origin: i128, at: u64, t_rx: i128) {
        if !self.from_master(hdr) {
            return;
        }
        self.sync_interval = interval_ns(hdr.log_interval, DEFAULT_SYNC_INTERVAL_NS);
        let correction = hdr.correction_ns();
        if hdr.flags & flag::TWO_STEP != 0 {
            self.sync = Some(SyncRx { seq: hdr.seq, t2: t_rx, at, correction });
        } else {
            // One-step: the Sync carries its own departure time.
            self.sync = None;
            self.last_sync = Some(SyncDone { t1: origin + correction, t2: t_rx, at });
        }
    }

    fn on_follow_up(&mut self, hdr: &Header, precise_origin: i128) {
        if !self.from_master(hdr) {
            return;
        }
        let Some(s) = self.sync.take_if(|s| s.seq == hdr.seq) else { return };
        self.last_sync = Some(SyncDone { t1: precise_origin + s.correction + hdr.correction_ns(), t2: s.t2, at: s.at });
    }

    /// Offer a measurement, unless the master's time cannot be placed on the
    /// wall clock's scale.
    fn offer<H: Host>(&mut self, h: &mut H, m: Measure) {
        let Some(master) = self.master else { return };
        if !master.utc_known() {
            if !self.warned {
                self.warned = true;
                h.event(Event::NoUtc);
            }
            return;
        }
        let how = h.sample(m.offset_ns, m.delay_ns);
        if how == Sampled::Stepped {
            // Every stamp taken so far is on the clock as it was.
            self.sync = None;
            self.last_sync = None;
            self.dreq = None;
        }
        h.event(Event::Sample { offset_ns: m.offset_ns, delay_ns: m.delay_ns, how });
    }

    fn send_delay_req<H: Host>(&mut self, h: &mut H, now: u64) {
        let Some(sync) = self.last_sync else { return };
        self.dreq_seq = self.dreq_seq.wrapping_add(1);
        let hdr = self.header(mt::DELAY_REQ, self.cfg.domain, self.dreq_seq);
        let mut out = [0u8; MSG_MAX];
        let n = wire::encode_request(&mut out, &hdr);
        // The next one is due whether or not this one gets an answer.
        self.next_dreq = now.saturating_add(self.dreq_interval);
        self.dreq = h.send(&out[..n]).map(|t3| DelayReqTx { seq: self.dreq_seq, at: now, t3, sync });
        if self.dreq.is_some_and(|d| clock_moved(sync.t2, sync.at, d.t3, now)) {
            // The wall clock was set since the Sync: nothing stamped before
            // pairs with what is stamped now.
            self.dreq = None;
            self.last_sync = None;
        }
    }

    fn on_delay_resp<H: Host>(&mut self, h: &mut H, hdr: &Header, receive: i128, requesting: PortId, now: u64, t_rx: i128) {
        if !self.from_master(hdr) || requesting != self.id {
            return;
        }
        let Some(d) = self.dreq.take_if(|d| d.seq == hdr.seq) else { return };
        let Some(m) = self.master else { return };
        // The master states the pace; it counts from the request it answers.
        self.dreq_interval = interval_ns(hdr.log_interval, self.dreq_interval).max(125_000_000);
        self.next_dreq = d.at.saturating_add(self.dreq_interval);
        if clock_moved(d.t3, d.at, t_rx, now) {
            // Set while the request was in flight: `t3` is on the old clock.
            self.last_sync = None;
            return;
        }
        // Both reference times on the wall clock's scale; the correction field
        // of the Delay_Resp is residence time spent on the way back.
        let t1 = to_utc(d.sync.t1, m.utc_offset);
        let t4 = to_utc(receive - hdr.correction_ns(), m.utc_offset);
        self.offer(h, e2e_measure(t1, d.sync.t2, d.t3, t4));
    }
}
