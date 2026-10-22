// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `metrics/` subtree of the introspection tree (Kconfig INSPECT): the
//! counters and gauges the kernel already keeps, as read-only nodes.
//!
//! ```text
//! metrics/trace/cpuN/{records, drops}                  (KTRACE)
//! metrics/sched/{switches_voluntary, switches_preempted, migrations}
//! metrics/energy/gov/{evals, changes, schedutil, deadline_floor, safety_floor}   (energy)
//! metrics/energy/idle/{by_slack, by_history, intercepts, i3_violations, picks/sN}
//! metrics/energy/domains/dN/opp
//! metrics/net/{packet/{delivered, dropped}, rx_drops/{..}, arp_txq/{..}, ethN/{mtu, attached, configured}}
//! metrics/memory/{zones/{pagetable,ring}_{free,total}, zpool/{..}}
//! metrics/decisions/{lost, unknown_rule, by_rule/<rule name>}
//! metrics/syscalls/{unshown, dN/{domain, none, authority, block_wake}}
//! metrics/storage/{written_bytes, unowned_bytes, unshown, dN/{domain, written_bytes}}
//! metrics/sync/<site>/{expired, lost}                  (bounded sleeps, `azos_sync::waitstat`)
//! metrics/wake/{total, offered, now_us, unshown, sources, dN/{domain, wakes, per_s}, rN}   (WAKE_RING_ENTRIES)
//! ```
//!
//! # Rate
//!
//! Nothing here runs per event. The values are read from the counters the
//! subsystems keep anyway, once per refresh of the `inspect` task
//! (INSPECT_REFRESH_MS), by [`refresh`]; no source gets a hook, and a source
//! that is not compiled in (ktrace, energy, the compressed pool) has no node.
//!
//! # What is a counter
//!
//! A counter node never decreases. Where the source cannot promise that, this
//! file does:
//!
//! * a 32-bit source is widened ([`Widen`]), so a wrap is not a drop;
//! * the scheduler keeps switch counts per task, and a slot's counts leave
//!   with its task; [`SwitchTally`] adds each task's growth since the last
//!   refresh instead of summing the live ones (a task that ran and exited
//!   between two refreshes loses its last stretch: the count is a lower
//!   bound, and says so);
//! * the decision recorder keeps a ring and no per-rule count; [`RuleTally`]
//!   walks the records written since the previous refresh. A record the ring
//!   overwrote before the walk got to it is counted in `decisions/lost`,
//!   never silently dropped.
//!
//! The exception is `syscalls/dN`: each is a **group** that shows one Domain
//! (`domain`: its key, whose low 16 bits are its table slot) and the kernel
//! entries it has made, by foundational case (`none`: a number with no case, a
//! Linux task's; `authority`; `block_wake`). It is a gauge of that Domain, not
//! of the group: the entries start again from zero when the Domain ends, and
//! the group then shows the next one that enters the kernel (`domain` says which
//! it is). A Domain is bound to a group the first time a refresh finds it with
//! entries and keeps it until it ends; the Domains past the groups are counted
//! in `unshown`. Entries per operation of a service is the measure of the
//! principle that a syscall is for changing authority or for sleeping (a service
//! that does one thing per ring entry has a ratio near zero). With Kconfig
//! `DOMAIN_ENTRY_COUNTERS` off nothing is counted and no group is ever bound.
//!
//! `storage/` is the write ledger (`azos_sched::domain::add_written`): the bytes
//! of block writes the device completed (a failed write, a flush and a discard
//! count nothing). `written_bytes` is the device total, a counter;
//! `unowned_bytes` the part of it that belongs to no live Domain (the kernel's
//! own writes and those of Domains that ended), a counter as well, so the two
//! stay meaningful when a Domain ends; the part of the live Domains is their
//! difference. `dN` are groups exactly as under `syscalls`, bound to the Domains
//! that have written, with the same gauge semantics and their own `unshown`.
//! This is the per-owner flash write volume that the energy accounting prices.
//!
//! `sync/` is the lost-wake evidence of the kernel's bounded sleeps
//! (`azos_sync::waitstat`, Kconfig `WAIT_SLICE_US`): per site that sleeps on a
//! deadline, the sleeps that ended at their deadline with no wake (`expired`)
//! and, of those, the ones whose condition had already become true (`lost`:
//! the event happened and its wake did not come within a slice). Both are
//! counters. A board boot that ends with every `lost` at 0 refutes a lost wake
//! at those sites; a nonzero one names the site.
//!
//! `wake/` is the wake attribution (`azos_sched::wake_log`, Kconfig
//! `WAKE_RING_ENTRIES`): every wake of a blocked task, with its source.
//! `total` counts them all (a counter: the Domains', the kernel tasks' and those
//! of the Domains that ended) and `offered` the ones the ring was offered (a
//! counter: the machine's own wakes, and a sample of the wakes tasks make,
//! `WAKE_RING_SAMPLE_LOG2`; a wake that found its slot taken by another is
//! offered and not logged, so the entries' numbers have a gap there). `rN` is
//! the N-th newest wake still in the ring (`r0` the newest), one histogram node
//! of [`WAKE_COLS`] numbers `[seq, at_us, src, line, domain, cpu, from_cpu]`:
//! its number, the clock in microseconds, the source (an index into `sources`,
//! the names separated by spaces), the interrupt line (for an `irq` wake, else
//! 0), the key of the Domain of the task woken (0: a kernel task; the same key
//! as a `dN/domain`), the CPU it was queued on and the CPU that woke it. A slot
//! that holds no wake yet, or one the ring was lapping while it was read, is
//! all zeros. `now_us` is the clock when the values were written, so an age is
//! `now_us - at_us`. `dN` are groups exactly as under `syscalls`, bound to the
//! Domains that have been woken (the gauge of that Domain: `wakes` of its tasks
//! since it began, `per_s` the rate over the last refresh), with their own
//! `unshown`. The wake counts are exact; the ring is the last wakes only.
//!
//! **No task ID is in the public region.** The region is one set of words every
//! task that holds `inspect.public` maps; it cannot show a reader its own
//! Domain's TIDs and hide the others', so it shows none: not the task woken,
//! not the waker. They are in the admin region, behind the task view
//! ([`build_admin_wake`]): `wake/{now_us, rN}` with `rN` of [`WAKE_ADMIN_COLS`]
//! numbers, the public row's seven and then `[tid, waker]`: the task woken and
//! the task that woke it (0 when the source names none: a deadline, a line, an
//! interrupt handler, the reaper). A slot the ring has no entry for is zeros,
//! as in the public region. [`public_wake_row`] and [`admin_wake_row`] are the
//! only places a row is made.
//!
//! A migration is the `WakePlacement` decision (the scheduler records only a
//! wake that moved a task to another CPU), so `sched/migrations` is that
//! rule's count, and is 0 in a build without the recorder.
//!
//! The first half of this file is plain Rust over `azos_inspect` and is
//! compiled by the host tests (`tests/host/inspect-tests/src/metrics.rs`);
//! the half that reads the kernel exists only on the kernel's target.

use azos_inspect::{Builder, Error, NodeId, Writer};

/// CPUs the trace and scheduler nodes can name.
pub(crate) const CPUS_MAX: usize = 64;
/// Decision rules the by-rule directory can hold.
pub(crate) const RULES_MAX: usize = 96;
/// Network interfaces the net directory can name.
pub(crate) const IFACES_MAX: usize = 8;
/// Idle states and power domains of the energy model (`azos_energy`).
pub(crate) const IDLE_STATES: usize = 4;
pub(crate) const ENERGY_DOMAINS: usize = 4;
/// Sites of bounded sleeps the sync directory can name.
pub(crate) const SITES_MAX: usize = 16;
/// Slots of the wake ring the tree can publish (Kconfig `WAKE_RING_ENTRIES` is
/// at most this), and the numbers of one (module doc).
pub(crate) const WAKE_MAX: usize = 64;
pub(crate) const WAKE_COLS: usize = 7;
/// The numbers of one entry in the admin region: [`WAKE_COLS`] and the TIDs.
pub(crate) const WAKE_ADMIN_COLS: usize = WAKE_COLS + 2;
/// Sources of a wake the tree can name, and the bytes of their names, joined.
pub(crate) const WAKE_SOURCES_MAX: usize = 16;
const WAKE_SOURCES_BYTES: usize = 128;
/// The leaves of a wake group: the Domain's key, its wakes, their rate.
const WAKE_GROUP: [&str; 3] = ["domain", "wakes", "per_s"];

const GOV: [&str; 5] = ["evals", "changes", "schedutil", "deadline_floor", "safety_floor"];
const IDLE: [&str; 4] = ["by_slack", "by_history", "intercepts", "i3_violations"];
const IDLE_PICK: [&str; IDLE_STATES] = ["s0", "s1", "s2", "s3"];
const PACKET: [&str; 2] = ["delivered", "dropped"];
const RX_DROPS: [&str; 3] = ["oversize", "ring_full", "truncated"];
const ARP_TXQ: [&str; 4] = ["queued", "sent", "dropped_full", "expired"];
const ZONES: [&str; 4] = ["pagetable_free", "pagetable_total", "ring_free", "ring_total"];
/// The counters a Domain keeps, by slot (`azos_sched::domain::ENTRY_SLOTS`).
const ENTRY_NAMES: [&str; 3] = ["none", "authority", "block_wake"];
/// The groups of `metrics/syscalls`: Domains shown at once.
pub(crate) const DOMAIN_GROUPS: usize = 4;
/// A group's published numbers: the Domain's key, then its entries.
const GROUP_COLS: usize = 1 + ENTRY_NAMES.len();
/// The counters a Domain keeps for `storage/dN`.
const SYNC_NAMES: [&str; 2] = ["expired", "lost"];
const STORAGE_NAMES: [&str; 1] = ["written_bytes"];
const STORAGE_COLS: usize = 1 + STORAGE_NAMES.len();
const ZPOOL: [&str; 7] = ["entries", "entries_max", "blobs", "segments", "segments_max", "live_bytes", "resident_bytes"];

/// What is compiled in and present: the shape of the subtree.
#[derive(Clone, Copy)]
pub(crate) struct Shape {
    pub cpus: usize,
    pub trace: bool,
    pub energy: bool,
    pub ifaces: usize,
    pub zpool: bool,
    /// How many decision rules there are, and their names by rule number.
    pub rules: usize,
    pub rule_name: fn(usize) -> &'static str,
    /// How many sites of bounded sleeps there are, and their names by site number.
    pub sites: usize,
    pub site_name: fn(usize) -> &'static str,
    /// Slots of the wake ring to publish (0: no `wake/`), and the sources a wake
    /// can have with their names by number.
    pub wake: usize,
    pub wake_sources: usize,
    pub wake_source_name: fn(usize) -> &'static str,
}

/// Everything one refresh publishes. Counters first, then gauges.
#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    pub trace_records: [u64; CPUS_MAX],
    pub trace_drops: [u64; CPUS_MAX],
    pub switches_voluntary: u64,
    pub switches_preempted: u64,
    pub migrations: u64,
    pub gov: [u64; GOV.len()],
    pub idle: [u64; IDLE.len()],
    pub idle_picks: [u64; IDLE_STATES],
    pub opp: [u64; ENERGY_DOMAINS],
    pub packet: [u64; PACKET.len()],
    pub rx_drops: [u64; RX_DROPS.len()],
    pub arp_txq: [u64; ARP_TXQ.len()],
    /// Per interface: `[mtu, attached, configured]`.
    pub iface: [[u64; 3]; IFACES_MAX],
    pub zones: [u64; ZONES.len()],
    pub zpool: [u64; ZPOOL.len()],
    pub by_rule: [u64; RULES_MAX],
    pub unknown_rule: u64,
    pub lost: u64,
    /// Per group: `[domain key, entries by case]`.
    pub groups: [[u64; GROUP_COLS]; DOMAIN_GROUPS],
    pub unshown: u64,
    /// The write ledger: device total, the part owned by no live Domain, and
    /// per group `[domain key, bytes written]`.
    pub written: u64,
    pub written_unowned: u64,
    pub storage_groups: [[u64; STORAGE_COLS]; DOMAIN_GROUPS],
    pub storage_unshown: u64,
    /// Per site: `[expired, lost]`.
    pub waits: [[u64; SYNC_NAMES.len()]; SITES_MAX],
    /// The wake attribution: wakes since boot, the clock (microseconds), the
    /// newest wakes (rows of [`WAKE_COLS`], newest first), and per group
    /// `[domain key, wakes]` with the rate of each.
    pub wake_total: u64,
    pub wake_offered: u64,
    pub wake_now_us: u64,
    pub wake_rows: [[u64; WAKE_COLS]; WAKE_MAX],
    pub wake_groups: [[u64; 2]; DOMAIN_GROUPS],
    pub wake_rate: [u64; DOMAIN_GROUPS],
    pub wake_unshown: u64,
}

impl Snapshot {
    pub(crate) const ZERO: Snapshot = Snapshot {
        trace_records: [0; CPUS_MAX],
        trace_drops: [0; CPUS_MAX],
        switches_voluntary: 0,
        switches_preempted: 0,
        migrations: 0,
        gov: [0; GOV.len()],
        idle: [0; IDLE.len()],
        idle_picks: [0; IDLE_STATES],
        opp: [0; ENERGY_DOMAINS],
        packet: [0; PACKET.len()],
        rx_drops: [0; RX_DROPS.len()],
        arp_txq: [0; ARP_TXQ.len()],
        iface: [[0; 3]; IFACES_MAX],
        zones: [0; ZONES.len()],
        zpool: [0; ZPOOL.len()],
        by_rule: [0; RULES_MAX],
        unknown_rule: 0,
        lost: 0,
        groups: [[0; GROUP_COLS]; DOMAIN_GROUPS],
        unshown: 0,
        written: 0,
        written_unowned: 0,
        storage_groups: [[0; STORAGE_COLS]; DOMAIN_GROUPS],
        storage_unshown: 0,
        waits: [[0; SYNC_NAMES.len()]; SITES_MAX],
        wake_total: 0,
        wake_offered: 0,
        wake_now_us: 0,
        wake_rows: [[0; WAKE_COLS]; WAKE_MAX],
        wake_groups: [[0; 2]; DOMAIN_GROUPS],
        wake_rate: [0; DOMAIN_GROUPS],
        wake_unshown: 0,
    };
}

/// A prefix and a decimal number, in a stack buffer (a node name).
pub(crate) struct Num {
    buf: [u8; 24],
    len: usize,
}

impl Num {
    pub(crate) fn name(prefix: &str, n: u64) -> Num {
        let mut s = Num { buf: [0; 24], len: 0 };
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{prefix}{n}"));
        s
    }
}

impl core::fmt::Write for Num {
    fn write_str(&mut self, t: &str) -> core::fmt::Result {
        let end = self.len + t.len();
        self.buf.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(t.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl core::ops::Deref for Num {
    type Target = str;
    fn deref(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// One logged wake as the ring has it, with what only the admin region may
/// show told apart from what the public one may.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct WakeEntry {
    pub seq: u64,
    pub at_us: u64,
    /// The source: an index into `wake/sources`.
    pub src: u8,
    /// The interrupt line of an `irq` wake, else 0: a number of the hardware.
    pub line: u32,
    /// The task woken, and the task that woke it (0: the source names none).
    /// Task IDs: they are not in a public row.
    pub tid: u32,
    pub waker: u32,
    /// The Domain key of the task woken (0: a kernel task).
    pub domain: u32,
    pub cpu: u8,
    pub from_cpu: u8,
}

/// The row of `metrics/wake/rN` in the public region: no task ID of any kind.
/// `[seq, at_us, src, line, domain, cpu, from_cpu]`.
pub(crate) fn public_wake_row(e: &WakeEntry) -> [u64; WAKE_COLS] {
    // The canary: the public row carries the TID of the task woken, in the
    // column of the line. `a_public_reader_never_sees_a_task_id` must fail.
    let line = if cfg!(feature = "wake-public-tid-canary") { u64::from(e.line) | u64::from(e.tid) << 8 } else { u64::from(e.line) };
    [e.seq, e.at_us, u64::from(e.src), line, u64::from(e.domain), u64::from(e.cpu), u64::from(e.from_cpu)]
}

/// The row of `wake/rN` in the admin region: the public row, then the TID of the
/// task woken and the waker's.
pub(crate) fn admin_wake_row(e: &WakeEntry) -> [u64; WAKE_ADMIN_COLS] {
    let p = public_wake_row(e);
    [p[0], p[1], p[2], u64::from(e.line), p[4], p[5], p[6], u64::from(e.tid), u64::from(e.waker)]
}

/// The admin tree's wake log: its nodes, built once ([`build_admin_wake`]),
/// written at every refresh ([`AdminWake::publish`]).
#[derive(Clone, Copy)]
pub(crate) struct AdminWake {
    now_us: NodeId,
    rows: [NodeId; WAKE_MAX],
    n: usize,
}

impl AdminWake {
    /// No wake log (the ring is off).
    pub(crate) const NONE: AdminWake = AdminWake { now_us: NodeId::ROOT, rows: [NodeId::ROOT; WAKE_MAX], n: 0 };

    /// Write the clock and `rows` (newest first) into the slots, zeros past
    /// the last: a reader stops at the first slot with no time. The values
    /// not published.
    pub(crate) fn publish(&self, w: &Writer<'_>, now_us: u64, rows: impl Iterator<Item = [u64; WAKE_ADMIN_COLS]>) -> u32 {
        if self.n == 0 {
            return 0;
        }
        let mut bad = w.set_u64(self.now_us, now_us).is_err() as u32;
        let mut rows = rows;
        for id in &self.rows[..self.n] {
            let row = rows.next().unwrap_or([0; WAKE_ADMIN_COLS]);
            bad += w.set_hist(*id, &row).is_err() as u32;
        }
        bad
    }
}

/// The wake log of the admin tree being built: `wake/{now_us, r0 ..}`, one
/// slot a ring entry (`slots`, at most [`WAKE_MAX`]), all zeros until the
/// first [`AdminWake::publish`]. Nothing for a ring of no slots.
pub(crate) fn build_admin_wake(b: &mut Builder<'_, '_>, slots: usize) -> Result<AdminWake, Error> {
    let mut a = AdminWake::NONE;
    if slots == 0 {
        return Ok(a);
    }
    let wk = b.dir(NodeId::ROOT, "wake")?;
    a.now_us = b.u64(wk, "now_us", 0)?;
    for k in 0..slots.min(WAKE_MAX) {
        a.rows[k] = b.hist_with(wk, &Num::name("r", k as u64), &[0; WAKE_ADMIN_COLS])?;
        a.n = k + 1;
    }
    Ok(a)
}

/// The node ids of the subtree; `NodeId::ROOT` marks a node that does not exist
/// in this shape.
pub(crate) struct Metrics {
    shape: Shape,
    trace: [[NodeId; 2]; CPUS_MAX],
    sw: [NodeId; 3],
    gov: [NodeId; GOV.len()],
    idle: [NodeId; IDLE.len()],
    idle_picks: [NodeId; IDLE_STATES],
    opp: [NodeId; ENERGY_DOMAINS],
    packet: [NodeId; PACKET.len()],
    rx_drops: [NodeId; RX_DROPS.len()],
    arp_txq: [NodeId; ARP_TXQ.len()],
    iface: [[NodeId; 3]; IFACES_MAX],
    zones: [NodeId; ZONES.len()],
    zpool: [NodeId; ZPOOL.len()],
    by_rule: [NodeId; RULES_MAX],
    unknown_rule: NodeId,
    lost: NodeId,
    groups: [[NodeId; GROUP_COLS]; DOMAIN_GROUPS],
    unshown: NodeId,
    written: NodeId,
    written_unowned: NodeId,
    storage_groups: [[NodeId; STORAGE_COLS]; DOMAIN_GROUPS],
    storage_unshown: NodeId,
    waits: [[NodeId; SYNC_NAMES.len()]; SITES_MAX],
    wake_total: NodeId,
    wake_offered: NodeId,
    wake_now: NodeId,
    wake_rows: [NodeId; WAKE_MAX],
    wake_groups: [[NodeId; 3]; DOMAIN_GROUPS],
    wake_unshown: NodeId,
}

const NONE: NodeId = NodeId::ROOT;

fn leaves(b: &mut Builder<'_, '_>, dir: NodeId, names: &[&str], out: &mut [NodeId]) -> Result<(), Error> {
    for (slot, name) in out.iter_mut().zip(names) {
        *slot = b.u64(dir, name, 0)?;
    }
    Ok(())
}

impl Metrics {
    /// Add the subtree under the root. Fails (and the caller leaves the
    /// subtree off) when the region cannot hold it or the shape names more
    /// than the arrays above.
    pub(crate) fn build(b: &mut Builder<'_, '_>, shape: Shape) -> Result<Metrics, Error> {
        if shape.cpus > CPUS_MAX
            || shape.ifaces > IFACES_MAX
            || shape.rules > RULES_MAX
            || shape.sites > SITES_MAX
            || shape.wake > WAKE_MAX
            || shape.wake_sources > WAKE_SOURCES_MAX
        {
            return Err(Error::BadSize);
        }
        let mut m = Metrics {
            shape,
            trace: [[NONE; 2]; CPUS_MAX],
            sw: [NONE; 3],
            gov: [NONE; GOV.len()],
            idle: [NONE; IDLE.len()],
            idle_picks: [NONE; IDLE_STATES],
            opp: [NONE; ENERGY_DOMAINS],
            packet: [NONE; PACKET.len()],
            rx_drops: [NONE; RX_DROPS.len()],
            arp_txq: [NONE; ARP_TXQ.len()],
            iface: [[NONE; 3]; IFACES_MAX],
            zones: [NONE; ZONES.len()],
            zpool: [NONE; ZPOOL.len()],
            by_rule: [NONE; RULES_MAX],
            unknown_rule: NONE,
            lost: NONE,
            groups: [[NONE; GROUP_COLS]; DOMAIN_GROUPS],
            unshown: NONE,
            written: NONE,
            written_unowned: NONE,
            storage_groups: [[NONE; STORAGE_COLS]; DOMAIN_GROUPS],
            storage_unshown: NONE,
            waits: [[NONE; SYNC_NAMES.len()]; SITES_MAX],
            wake_total: NONE,
            wake_offered: NONE,
            wake_now: NONE,
            wake_rows: [NONE; WAKE_MAX],
            wake_groups: [[NONE; 3]; DOMAIN_GROUPS],
            wake_unshown: NONE,
        };
        let root = b.dir(NodeId::ROOT, "metrics")?;

        if shape.trace {
            let t = b.dir(root, "trace")?;
            for cpu in 0..shape.cpus {
                let c = b.dir(t, &Num::name("cpu", cpu as u64))?;
                m.trace[cpu] = [b.u64(c, "records", 0)?, b.u64(c, "drops", 0)?];
            }
        }

        let s = b.dir(root, "sched")?;
        leaves(b, s, &["switches_voluntary", "switches_preempted", "migrations"], &mut m.sw)?;

        if shape.energy {
            let e = b.dir(root, "energy")?;
            let g = b.dir(e, "gov")?;
            leaves(b, g, &GOV, &mut m.gov)?;
            let i = b.dir(e, "idle")?;
            leaves(b, i, &IDLE, &mut m.idle)?;
            let p = b.dir(i, "picks")?;
            leaves(b, p, &IDLE_PICK, &mut m.idle_picks)?;
            let d = b.dir(e, "domains")?;
            for (n, slot) in m.opp.iter_mut().enumerate() {
                let dn = b.dir(d, &Num::name("d", n as u64))?;
                *slot = b.u64(dn, "opp", 0)?;
            }
        }

        let n = b.dir(root, "net")?;
        let p = b.dir(n, "packet")?;
        leaves(b, p, &PACKET, &mut m.packet)?;
        let r = b.dir(n, "rx_drops")?;
        leaves(b, r, &RX_DROPS, &mut m.rx_drops)?;
        let a = b.dir(n, "arp_txq")?;
        leaves(b, a, &ARP_TXQ, &mut m.arp_txq)?;
        for (i, slot) in m.iface.iter_mut().enumerate().take(shape.ifaces) {
            let d = b.dir(n, &Num::name("eth", i as u64))?;
            *slot = [b.u64(d, "mtu", 0)?, b.u64(d, "attached", 0)?, b.u64(d, "configured", 0)?];
        }

        let mem = b.dir(root, "memory")?;
        let z = b.dir(mem, "zones")?;
        leaves(b, z, &ZONES, &mut m.zones)?;
        if shape.zpool {
            let p = b.dir(mem, "zpool")?;
            leaves(b, p, &ZPOOL, &mut m.zpool)?;
        }

        let d = b.dir(root, "decisions")?;
        m.lost = b.u64(d, "lost", 0)?;
        m.unknown_rule = b.u64(d, "unknown_rule", 0)?;
        let by = b.dir(d, "by_rule")?;
        for (i, slot) in m.by_rule.iter_mut().enumerate().take(shape.rules) {
            *slot = b.u64(by, (shape.rule_name)(i), 0)?;
        }

        let sc = b.dir(root, "syscalls")?;
        m.unshown = b.u64(sc, "unshown", 0)?;
        for (g, ids) in m.groups.iter_mut().enumerate() {
            let d = b.dir(sc, &Num::name("d", g as u64))?;
            ids[0] = b.u64(d, "domain", 0)?;
            leaves(b, d, &ENTRY_NAMES, &mut ids[1..])?;
        }

        let st = b.dir(root, "storage")?;
        m.written = b.u64(st, "written_bytes", 0)?;
        m.written_unowned = b.u64(st, "unowned_bytes", 0)?;
        m.storage_unshown = b.u64(st, "unshown", 0)?;
        for (g, ids) in m.storage_groups.iter_mut().enumerate() {
            let d = b.dir(st, &Num::name("d", g as u64))?;
            ids[0] = b.u64(d, "domain", 0)?;
            leaves(b, d, &STORAGE_NAMES, &mut ids[1..])?;
        }

        let sy = b.dir(root, "sync")?;
        for (i, ids) in m.waits.iter_mut().enumerate().take(shape.sites) {
            let d = b.dir(sy, (shape.site_name)(i))?;
            leaves(b, d, &SYNC_NAMES, ids)?;
        }

        if shape.wake > 0 {
            let wk = b.dir(root, "wake")?;
            m.wake_total = b.u64(wk, "total", 0)?;
            m.wake_offered = b.u64(wk, "offered", 0)?;
            m.wake_now = b.u64(wk, "now_us", 0)?;
            m.wake_unshown = b.u64(wk, "unshown", 0)?;
            // The names are fixed for the boot: written here, never published again.
            let names = Joined::of(shape.wake_sources, shape.wake_source_name);
            b.string(wk, "sources", WAKE_SOURCES_BYTES, &names)?;
            for (g, ids) in m.wake_groups.iter_mut().enumerate() {
                let d = b.dir(wk, &Num::name("d", g as u64))?;
                leaves(b, d, &WAKE_GROUP, ids)?;
            }
            for (k, slot) in m.wake_rows.iter_mut().enumerate().take(shape.wake) {
                *slot = b.hist(wk, &Num::name("r", k as u64), WAKE_COLS)?;
            }
        }
        Ok(m)
    }

    /// Write every value of `s`; the number of writes that failed (a reader
    /// of an old epoch cannot cause one: only a rebuild invalidates ids, and
    /// the kernel does both from one task).
    pub(crate) fn publish(&self, w: &Writer<'_>, s: &Snapshot) -> u32 {
        let sh = &self.shape;
        let mut bad = 0u32;
        let mut put = |id: NodeId, v: u64| {
            if id != NONE && w.set_u64(id, v).is_err() {
                bad += 1;
            }
        };
        if sh.trace {
            for cpu in 0..sh.cpus {
                put(self.trace[cpu][0], s.trace_records[cpu]);
                put(self.trace[cpu][1], s.trace_drops[cpu]);
            }
        }
        put(self.sw[0], s.switches_voluntary);
        put(self.sw[1], s.switches_preempted);
        put(self.sw[2], s.migrations);
        if sh.energy {
            for (id, v) in self.gov.iter().zip(s.gov) {
                put(*id, v);
            }
            for (id, v) in self.idle.iter().zip(s.idle) {
                put(*id, v);
            }
            for (id, v) in self.idle_picks.iter().zip(s.idle_picks) {
                put(*id, v);
            }
            for (id, v) in self.opp.iter().zip(s.opp) {
                put(*id, v);
            }
        }
        for (id, v) in self.packet.iter().zip(s.packet) {
            put(*id, v);
        }
        for (id, v) in self.rx_drops.iter().zip(s.rx_drops) {
            put(*id, v);
        }
        for (id, v) in self.arp_txq.iter().zip(s.arp_txq) {
            put(*id, v);
        }
        for (ids, vals) in self.iface.iter().zip(s.iface).take(sh.ifaces) {
            for (id, v) in ids.iter().zip(vals) {
                put(*id, v);
            }
        }
        for (id, v) in self.zones.iter().zip(s.zones) {
            put(*id, v);
        }
        if sh.zpool {
            for (id, v) in self.zpool.iter().zip(s.zpool) {
                put(*id, v);
            }
        }
        for (id, v) in self.by_rule.iter().zip(s.by_rule).take(sh.rules) {
            put(*id, v);
        }
        put(self.unknown_rule, s.unknown_rule);
        put(self.lost, s.lost);
        for (ids, vals) in self.groups.iter().zip(s.groups) {
            for (id, v) in ids.iter().zip(vals) {
                put(*id, v);
            }
        }
        put(self.unshown, s.unshown);
        put(self.written, s.written);
        put(self.written_unowned, s.written_unowned);
        for (ids, vals) in self.storage_groups.iter().zip(s.storage_groups) {
            for (id, v) in ids.iter().zip(vals) {
                put(*id, v);
            }
        }
        put(self.storage_unshown, s.storage_unshown);
        for (ids, vals) in self.waits.iter().zip(s.waits).take(sh.sites) {
            for (id, v) in ids.iter().zip(vals) {
                put(*id, v);
            }
        }
        if sh.wake > 0 {
            put(self.wake_total, s.wake_total);
            put(self.wake_offered, s.wake_offered);
            put(self.wake_now, s.wake_now_us);
            put(self.wake_unshown, s.wake_unshown);
            for ((ids, vals), rate) in self.wake_groups.iter().zip(s.wake_groups).zip(s.wake_rate) {
                for (id, v) in ids.iter().zip([vals[0], vals[1], rate]) {
                    put(*id, v);
                }
            }
            for (id, row) in self.wake_rows.iter().zip(&s.wake_rows).take(sh.wake) {
                if w.set_hist(*id, row).is_err() {
                    bad += 1;
                }
            }
        }
        bad
    }
}

/// The names of the wake sources, in number order, separated by spaces: the
/// text of `wake/sources`.
pub(crate) struct Joined {
    buf: [u8; WAKE_SOURCES_BYTES],
    len: usize,
}

impl Joined {
    pub(crate) fn of(n: usize, name: fn(usize) -> &'static str) -> Joined {
        let mut j = Joined { buf: [0; WAKE_SOURCES_BYTES], len: 0 };
        for i in 0..n {
            // A list that does not fit is cut at a whole name (the build refuses
            // a shape past `WAKE_SOURCES_MAX`; the names are short).
            let t = name(i);
            let sep = usize::from(i > 0);
            if j.len + sep + t.len() > WAKE_SOURCES_BYTES {
                break;
            }
            if sep == 1 {
                j.buf[j.len] = b' ';
                j.len += 1;
            }
            j.buf[j.len..j.len + t.len()].copy_from_slice(t.as_bytes());
            j.len += t.len();
        }
        j
    }
}

impl core::ops::Deref for Joined {
    type Target = str;
    fn deref(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// Counters of 32 bits, widened to 64: a wrap adds, it does not subtract.
pub(crate) struct Widen<const N: usize> {
    last: [u32; N],
    total: [u64; N],
}

impl<const N: usize> Widen<N> {
    pub(crate) const fn new() -> Self {
        Widen { last: [0; N], total: [0; N] }
    }

    /// Counter `i` now reads `raw`; its widened total.
    pub(crate) fn feed(&mut self, i: usize, raw: u32) -> u64 {
        let (Some(last), Some(total)) = (self.last.get_mut(i), self.total.get_mut(i)) else { return 0 };
        *total += raw.wrapping_sub(*last) as u64;
        *last = raw;
        *total
    }
}

/// Context-switch counts that survive their tasks: each task's growth since
/// the previous refresh is added to the totals. A slot that now holds another
/// task (its tid changed) or whose counts went down starts from zero.
pub(crate) struct SwitchTally<const T: usize> {
    seen: [(u32, u64, u64); T],
    voluntary: u64,
    preempted: u64,
}

impl<const T: usize> SwitchTally<T> {
    pub(crate) const fn new() -> Self {
        SwitchTally { seen: [(0, 0, 0); T], voluntary: 0, preempted: 0 }
    }

    /// Start of a pass: call [`SwitchTally::task`] for each live slot.
    /// `slot` is the task slot, `tid` its task.
    pub(crate) fn task(&mut self, slot: usize, tid: u32, voluntary: u64, preempted: u64) {
        let Some(s) = self.seen.get_mut(slot) else { return };
        let (v0, p0) = if s.0 == tid && voluntary >= s.1 && preempted >= s.2 { (s.1, s.2) } else { (0, 0) };
        self.voluntary += voluntary - v0;
        self.preempted += preempted - p0;
        *s = (tid, voluntary, preempted);
    }

    /// `(voluntary, preempted)` totals so far.
    pub(crate) fn totals(&self) -> (u64, u64) {
        (self.voluntary, self.preempted)
    }
}

/// Per-rule counts of the decision recorder, from the records written since
/// the previous walk.
pub(crate) struct RuleTally {
    cursor: u64,
    pub counts: [u64; RULES_MAX],
    pub unknown: u64,
    pub lost: u64,
}

impl RuleTally {
    pub(crate) const fn new() -> Self {
        RuleTally { cursor: 0, counts: [0; RULES_MAX], unknown: 0, lost: 0 }
    }

    /// Count the records `cursor+1..=total`. `ring` is the recorder's ring
    /// size; `get(seq)` the rule of record `seq`, `None` when it is not (or
    /// no longer) readable. A record unreadable while still inside the ring
    /// is one a writer has claimed and not finished: the walk stops there and
    /// the next refresh resumes (so a record is never counted twice, and
    /// never skipped while it can still appear). Work per call is at most
    /// `ring` records.
    pub(crate) fn walk(&mut self, total: u64, ring: u64, rules: usize, mut get: impl FnMut(u64) -> Option<u8>) {
        // Everything older than the ring is gone whatever happens now.
        let oldest = total.saturating_sub(ring.saturating_sub(1)).max(1);
        if self.cursor + 1 < oldest {
            self.lost += oldest - (self.cursor + 1);
            self.cursor = oldest - 1;
        }
        while self.cursor < total {
            let seq = self.cursor + 1;
            match get(seq) {
                Some(rule) => match self.counts.get_mut(rule as usize) {
                    Some(c) if (rule as usize) < rules => *c += 1,
                    _ => self.unknown += 1,
                },
                None if seq >= oldest => return,
                None => self.lost += 1,
            }
            self.cursor = seq;
        }
    }
}

/// Which Domain each group of `metrics/syscalls` shows (module doc).
pub(crate) struct DomainGroups {
    /// The table slot a group is bound to; `None`: free.
    bound: [Option<usize>; DOMAIN_GROUPS],
}

impl DomainGroups {
    pub(crate) const fn new() -> Self {
        DomainGroups { bound: [None; DOMAIN_GROUPS] }
    }

    /// One refresh: fill `groups` and `unshown` from the Domain table.
    /// `slots` is its size and `get(slot)` the Domain alive in a slot, with its
    /// key and its `C` counters (a group row is the key, then the counters).
    pub(crate) fn pass<const C: usize, const R: usize>(
        &mut self,
        slots: usize,
        get: impl Fn(usize) -> Option<(u32, [u64; C])>,
        groups: &mut [[u64; R]; DOMAIN_GROUPS],
        unshown: &mut u64,
    ) {
        const { assert!(R == C + 1) };
        let row_of = |key: u32, e: [u64; C]| {
            let mut row = [0u64; R];
            row[0] = u64::from(key);
            row[1..].copy_from_slice(&e);
            row
        };
        // The Domains already shown, as they are now; a Domain that ended frees
        // its group.
        for (slot, row) in self.bound.iter_mut().zip(groups.iter_mut()) {
            *row = [0; R];
            match (*slot).and_then(&get) {
                Some((key, e)) => *row = row_of(key, e),
                None => *slot = None,
            }
        }
        // The Domains that have entered the kernel and are not shown yet.
        *unshown = 0;
        for s in 0..slots {
            if self.bound.contains(&Some(s)) {
                continue;
            }
            let Some((key, e)) = get(s).filter(|(_, e)| e.iter().any(|&n| n != 0)) else { continue };
            match self.bound.iter().position(Option::is_none) {
                Some(g) => {
                    self.bound[g] = Some(s);
                    groups[g] = row_of(key, e);
                }
                None => *unshown += 1,
            }
        }
    }
}

/// The rate of each wake group: wakes per second over the time between two
/// refreshes. A group that now shows another Domain than the last time, or whose
/// count went down, has no rate yet (0): a rate is the growth of one Domain.
pub(crate) struct WakeRate {
    prev: [(u64, u64); DOMAIN_GROUPS],
    last: [u64; DOMAIN_GROUPS],
    at_ms: Option<u64>,
}

impl WakeRate {
    pub(crate) const fn new() -> Self {
        WakeRate { prev: [(0, 0); DOMAIN_GROUPS], last: [0; DOMAIN_GROUPS], at_ms: None }
    }

    /// One refresh at `now_ms`: the rate of each group of `groups` (`[key, wakes]`).
    /// A refresh in the same millisecond as the last one is the same interval:
    /// it answers the rates already found.
    pub(crate) fn pass(&mut self, now_ms: u64, groups: &[[u64; 2]; DOMAIN_GROUPS]) -> [u64; DOMAIN_GROUPS] {
        let dt = self.at_ms.map(|t| now_ms.saturating_sub(t));
        if dt == Some(0) {
            return self.last;
        }
        let mut out = [0u64; DOMAIN_GROUPS];
        for ((rate, prev), g) in out.iter_mut().zip(self.prev.iter_mut()).zip(groups) {
            let (key, wakes) = (g[0], g[1]);
            if let Some(dt) = dt {
                if key != 0 && prev.0 == key && wakes >= prev.1 {
                    *rate = (wakes - prev.1).saturating_mul(1000) / dt;
                }
            }
            *prev = (key, wakes);
        }
        self.at_ms = Some(now_ms);
        self.last = out;
        out
    }
}

// ── The kernel's half ───────────────────────────────────────────────────────

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use azos_sync::kmutex::Mutex;

    struct State {
        m: Metrics,
        snap: Snapshot,
        wide: Widen<WIDE>,
        /// The tally of every task slot: 24 B x `MAX_TASKS`, 98 KB on fleet.
        /// In a static of its own: held by value here it was built on the
        /// stack of `build` (`tools/stack_frames.py`, fleet).
        switches: &'static mut SwitchTally<{ azos_sched::MAX_TASKS }>,
        rules: RuleTally,
        groups: DomainGroups,
        storage: DomainGroups,
        woken: DomainGroups,
        wake_rate: WakeRate,
    }

    const _: () = assert!(azos_limits::NR_CPUS as usize <= CPUS_MAX);
    const _: () = assert!(ENTRY_NAMES.len() == azos_sched::domain::ENTRY_SLOTS);
    const _: () = assert!(azos_decision::RULES.len() <= RULES_MAX);
    const _: () = assert!(azos_sync::waitstat::SITES <= SITES_MAX);
    const _: () = assert!(azos_sched::wake_log::ENTRIES <= WAKE_MAX);
    const _: () = assert!(azos_sched::wake_log::Src::ALL.len() <= WAKE_SOURCES_MAX);

    /// Slots of [`Widen`]: the trace's, then the 32-bit counters of the other
    /// sources in the order `gather` reads them.
    const W_TRACE: usize = 0;
    const W_GOV: usize = W_TRACE + 2 * CPUS_MAX;
    const W_IDLE: usize = W_GOV + GOV.len();
    const W_PICKS: usize = W_IDLE + IDLE.len();
    const W_RX: usize = W_PICKS + IDLE_STATES;
    const W_ARP: usize = W_RX + RX_DROPS.len();
    const WIDE: usize = W_ARP + ARP_TXQ.len();

    /// Set by `build` at boot; `refresh` runs from the `inspect` task. A
    /// sleeping mutex, not a spin lock: `gather` walks every task slot (four
    /// passes over `MAX_TASKS`), the decision ring and the wake ring, which
    /// must not run with interrupts masked. Nothing in interrupt context
    /// takes it.
    static STATE: Mutex<Option<State>> = Mutex::new(None);
    /// [`State::switches`]' storage; handed out by `build` (under `STATE`'s
    /// lock) and used only through the state.
    static mut SWITCHES: SwitchTally<{ azos_sched::MAX_TASKS }> = SwitchTally::new();

    fn rule_name(i: usize) -> &'static str {
        azos_decision::RULES.get(i).map_or("?", |r| r.name)
    }

    fn site_name(i: usize) -> &'static str {
        azos_sync::waitstat::Site::ALL.get(i).map_or("?", |s| s.name())
    }

    fn wake_source_name(i: usize) -> &'static str {
        azos_sched::wake_log::Src::ALL.get(i).map_or("?", |s| s.name())
    }

    /// A ring entry, its `detail` told into the line or the waker's TID by the
    /// source ([`azos_sched::wake_log::names_waker`]).
    fn wake_entry(w: &azos_sched::wake_log::Entry) -> WakeEntry {
        use azos_sched::wake_log::Src;
        let src = Src::from_u8(w.src);
        WakeEntry {
            seq: w.seq,
            at_us: ticks_to_us(w.at),
            src: w.src,
            line: if src == Some(Src::Irq) { w.detail } else { 0 },
            tid: w.tid,
            waker: if src.is_some_and(azos_sched::wake_log::names_waker) { w.detail } else { 0 },
            domain: w.domain,
            cpu: w.target_cpu,
            from_cpu: w.waker_cpu,
        }
    }

    /// The wake log of the admin tree being built (`wake/`): a slot a ring
    /// entry, for the task IDs the public region does not carry. Nothing when
    /// the ring is off.
    pub(crate) fn build_admin(b: &mut Builder<'_, '_>) -> Result<AdminWake, Error> {
        use azos_sched::wake_log;
        build_admin_wake(b, if wake_log::ENABLED { wake_log::ENTRIES } else { 0 })
    }

    /// Write the ring's entries into the admin wake log; the values not
    /// published.
    pub(crate) fn refresh_admin(w: &Writer<'_>, a: &AdminWake) -> u32 {
        use azos_sched::wake_log;
        if !wake_log::ENABLED {
            return 0;
        }
        let mut e = [wake_log::Entry::default(); WAKE_MAX];
        let n = wake_log::RING.snapshot(&mut e[..wake_log::ENTRIES]);
        a.publish(w, ticks_to_us(azos_drv_sys::timebase::now()), e[..n].iter().map(|w| admin_wake_row(&wake_entry(w))))
    }

    /// Ticks of the clock in microseconds.
    fn ticks_to_us(ticks: u64) -> u64 {
        azos_abi::time::ticks_to_ns(ticks, azos_drv_sys::timebase::TIMER_FREQ) / 1000
    }

    /// Add the subtree to the public tree being built and keep its ids.
    pub(crate) fn build(b: &mut Builder<'_, '_>, cpus: usize) -> Result<(), Error> {
        let shape = Shape {
            cpus,
            trace: azos_trace::ENABLED,
            energy: cfg!(feature = "energy"),
            ifaces: azos_net::ip::MAX_IFS.min(IFACES_MAX),
            zpool: azos_mm::zpool::ENABLED,
            rules: if azos_decision::ON { azos_decision::RULES.len() } else { 0 },
            rule_name,
            sites: azos_sync::waitstat::SITES,
            site_name,
            wake: azos_sched::wake_log::ENTRIES,
            wake_sources: azos_sched::wake_log::Src::ALL.len(),
            wake_source_name,
        };
        let m = Metrics::build(b, shape)?;
        let mut g = STATE.lock();
        // The previous state (if any) goes first: it holds the `&mut` to the tally.
        *g = None;
        // SAFETY: under `STATE`'s lock, with no state alive, and nothing else
        // names `SWITCHES`. The tally is reset from a constant, in place.
        let switches = unsafe {
            let p = core::ptr::addr_of_mut!(SWITCHES);
            p.write(const { SwitchTally::new() });
            &mut *p
        };
        *g = Some(State {
            m,
            snap: Snapshot::ZERO,
            wide: Widen::new(),
            switches,
            rules: RuleTally::new(),
            groups: DomainGroups::new(),
            storage: DomainGroups::new(),
            woken: DomainGroups::new(),
            wake_rate: WakeRate::new(),
        });
        Ok(())
    }

    /// Read every source once and publish. Returns the writes that failed.
    pub(crate) fn refresh(w: &Writer<'_>) -> u32 {
        let mut g = STATE.lock();
        let Some(st) = g.as_mut() else { return 0 };
        gather(st);
        st.m.publish(w, &st.snap)
    }

    fn gather(st: &mut State) {
        let sh = st.m.shape;
        let State { snap, wide, switches, rules, groups, storage, woken, wake_rate, .. } = st;

        if sh.trace {
            for cpu in 0..sh.cpus {
                let (records, drops) = azos_trace::cpu_stats(cpu);
                snap.trace_records[cpu] = wide.feed(W_TRACE + 2 * cpu, records);
                snap.trace_drops[cpu] = wide.feed(W_TRACE + 2 * cpu + 1, drops);
            }
        }

        for slot in 0..azos_sched::MAX_TASKS {
            if let Some((tid, v, p)) = azos_sched::task_switches_at(slot) {
                switches.task(slot, tid, v, p);
            }
        }
        (snap.switches_voluntary, snap.switches_preempted) = switches.totals();

        if azos_decision::ON {
            rules.walk(azos_decision::total(), azos_decision::ENTRIES as u64, sh.rules, |seq| {
                azos_decision::get(seq).map(|r| r.rule)
            });
            snap.by_rule = rules.counts;
            snap.unknown_rule = rules.unknown;
            snap.lost = rules.lost;
            snap.migrations = rules.counts[azos_decision::Rule::WakePlacement as usize];
        }

        #[cfg(feature = "energy")]
        {
            use azos_sched::energy;
            let g = energy::gov_stats();
            let raw = [g.evals, g.changes, g.why[0], g.why[1], g.why[2]];
            for (i, r) in raw.into_iter().enumerate() {
                snap.gov[i] = wide.feed(W_GOV + i, r);
            }
            let mut idle = [0u32; IDLE.len()];
            let mut picks = [0u64; IDLE_STATES];
            for cpu in 0..sh.cpus {
                let s = energy::idle_stats(cpu);
                for (acc, p) in picks.iter_mut().zip(s.picks) {
                    *acc += p as u64;
                }
                if cpu == 0 {
                    // The other counters are global: read them once.
                    idle = [s.by_slack, s.by_history, s.intercepts, s.i3_violations];
                }
            }
            for (i, r) in idle.into_iter().enumerate() {
                snap.idle[i] = wide.feed(W_IDLE + i, r);
            }
            snap.idle_picks = picks;
            for (d, o) in snap.opp.iter_mut().enumerate() {
                *o = energy::domain_opp(d) as u64;
            }
        }

        groups.pass(azos_sched::MAX_TASKS, azos_sched::domain::slot_entries, &mut snap.groups, &mut snap.unshown);

        storage.pass(
            azos_sched::MAX_TASKS,
            azos_sched::domain::slot_written,
            &mut snap.storage_groups,
            &mut snap.storage_unshown,
        );
        // A walk that meets a slot being taken again can read low or high
        // (`written_totals`): a counter keeps the larger reading.
        let (total, unowned) = azos_sched::domain::written_totals();
        snap.written = snap.written.max(total);
        snap.written_unowned = snap.written_unowned.max(unowned);

        if sh.wake > 0 {
            use azos_sched::wake_log;
            let now = azos_drv_sys::timebase::now();
            snap.wake_now_us = ticks_to_us(now);
            // The walk of the Domain table can miscount a slot being taken again:
            // a counter keeps the larger reading.
            snap.wake_total = snap.wake_total.max(azos_sched::domain::wakes_total());
            snap.wake_offered = wake_log::RING.offered();
            let mut e = [wake_log::Entry::default(); WAKE_MAX];
            let n = wake_log::RING.snapshot(&mut e[..sh.wake]);
            for (k, row) in snap.wake_rows.iter_mut().enumerate().take(sh.wake) {
                *row = match e[..n].get(k) {
                    Some(w) => public_wake_row(&wake_entry(w)),
                    None => [0; WAKE_COLS],
                };
            }
            woken.pass(
                azos_sched::MAX_TASKS,
                azos_sched::domain::slot_wakes,
                &mut snap.wake_groups,
                &mut snap.wake_unshown,
            );
            snap.wake_rate = wake_rate.pass(snap.wake_now_us / 1000, &snap.wake_groups);
        }

        // Counters of u64 that only ever grow: read as they are.
        for (row, site) in snap.waits.iter_mut().zip(azos_sync::waitstat::Site::ALL) {
            let (expired, lost) = azos_sync::waitstat::stats(site);
            *row = [expired, lost];
        }

        snap.packet = {
            let (delivered, dropped) = azos_net::socket::packet_stats();
            [delivered, dropped]
        };
        let (oversize, ring_full, truncated) = azos_net::udp::rx_drop_stats();
        for (i, r) in [oversize, ring_full, truncated].into_iter().enumerate() {
            snap.rx_drops[i] = wide.feed(W_RX + i, r);
        }
        let (queued, sent, dropped_full, expired) = azos_net::ip::arp_txq_stats();
        for (i, r) in [queued, sent, dropped_full, expired].into_iter().enumerate() {
            snap.arp_txq[i] = wide.feed(W_ARP + i, r);
        }
        for i in 0..sh.ifaces {
            // Interface indices start at 1.
            snap.iface[i] = match azos_net::ip::iface_get((i + 1) as u8) {
                Some(f) => [f.mtu as u64, f.attached() as u64, (f.ip != [0; 4]) as u64],
                None => [0; 3],
            };
        }

        for (i, z) in [azos_mm::zone::Zone::PageTable, azos_mm::zone::Zone::Ring].into_iter().enumerate() {
            let (free, total) = azos_mm::pmm::zone_pages(z);
            snap.zones[2 * i] = free as u64;
            snap.zones[2 * i + 1] = total as u64;
        }
        if sh.zpool {
            let z = azos_mm::pager::zpool_stats();
            snap.zpool = [
                z.entries as u64,
                azos_mm::zpool::ENTRIES as u64,
                z.blobs as u64,
                z.segments as u64,
                azos_mm::zpool::SEGMENTS as u64,
                z.live_bytes as u64,
                z.resident_bytes as u64,
            ];
        }
    }
}

#[cfg(target_os = "none")]
pub(crate) use kernel::{build, build_admin, refresh, refresh_admin};
