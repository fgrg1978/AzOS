// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the `metrics/` subtree of the introspection tree
//! (`kernel/src/boot/inspect_metrics.rs`, its plain-Rust half, included by
//! path) and for the text `toolbox inspect` prints from it
//! (`userspace/services/toolbox/src/metrics_view.rs`) and `why woke` prints
//! from `metrics/wake` (`userspace/services/why/src/woke.rs`).
//!
//! What the kernel half reads (the subsystems' counters) is not here; the
//! shape of the subtree, what a refresh publishes, the monotonicity of the
//! counters and the consistency under concurrent readers are.

#![allow(dead_code)]

#[path = "../../../../kernel/src/boot/inspect_metrics.rs"]
pub(crate) mod km;

#[path = "../../../../userspace/services/toolbox/src/metrics_view.rs"]
mod view;

// `why woke`: the reader of `metrics/wake`, over the tree this file publishes.
#[path = "../../../../userspace/services/why/src/woke.rs"]
mod woke;

use azos_inspect::{Class, Error, NodeId, Reader, Region, Value, Writer};
use azos_inspect_lib::Inspector;
use km::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::*};

/// The decision rules the fixture publishes: every rule of the real table,
/// so a rule added to `azos_decision::Rule` is a by-rule node here too.
fn rule_count() -> usize {
    azos_decision::RULES.len()
}
const WAKE_PLACEMENT: usize = 3;

fn rule_name(i: usize) -> &'static str {
    azos_decision::RULES.get(i).map_or("?", |r| r.name)
}

/// The sites of bounded sleeps the fixture publishes (the kernel's are
/// `azos_sync::waitstat::Site::ALL`; the node names are the only contract).
const SITE_NAMES: [&str; 9] = [
    "block_done", "block_space", "fat_sector", "fat_writeback", "claim", "dev_queue", "ads1115", "pager_store", "pager_swap",
];

fn site_name(i: usize) -> &'static str {
    SITE_NAMES.get(i).copied().unwrap_or("?")
}

fn words(pages: usize) -> Vec<AtomicU64> {
    (0..pages * 512).map(|_| AtomicU64::new(0)).collect()
}

/// The sources of a wake the fixture names: the kernel's are
/// `azos_sched::wake_log::Src::ALL`; the list in `wake/sources` is the contract.
const WAKE_SOURCE_NAMES: [&str; 4] = ["timer", "irq", "ipc_call", "reap"];
/// Slots of the wake ring the fixture publishes (Kconfig `WAKE_RING_ENTRIES`'s default).
const WAKE_SLOTS: usize = 32;

fn wake_source_name(i: usize) -> &'static str {
    WAKE_SOURCE_NAMES.get(i).copied().unwrap_or("?")
}

fn full(cpus: usize) -> Shape {
    Shape {
        cpus,
        trace: true,
        energy: true,
        ifaces: 2,
        zpool: true,
        rules: rule_count(),
        rule_name,
        sites: SITE_NAMES.len(),
        site_name,
        wake: WAKE_SLOTS,
        wake_sources: WAKE_SOURCE_NAMES.len(),
        wake_source_name,
    }
}

fn build(w: &Writer<'_>, shape: Shape) -> (Result<(), Error>, Option<Metrics>) {
    let mut m = None;
    let r = w.rebuild(|b| {
        m = Some(Metrics::build(b, shape)?);
        Ok(())
    });
    (r, m)
}

/// The nodes (directories included) `shape` adds, below the root.
fn expected_nodes(s: &Shape) -> usize {
    let mut n = 1; // metrics
    if s.trace {
        n += 1 + 3 * s.cpus;
    }
    n += 1 + 3; // sched
    if s.energy {
        n += 1 + (1 + 5) + (1 + 4 + 1 + 4) + (1 + 2 * 4);
    }
    n += 1 + (1 + 2) + (1 + 3) + (1 + 4) + s.ifaces * 4; // net
    n += 1 + (1 + 4); // memory/zones
    if s.zpool {
        n += 1 + 7;
    }
    n += 1 + 2 + 1 + s.rules; // decisions
    n += 1 + 1 + DOMAIN_GROUPS * 5; // syscalls: unshown, and per group a dir and four leaves
    n += 1 + 3 + DOMAIN_GROUPS * 3; // storage: written, unowned, unshown, and per group a dir and two leaves
    n += 1 + s.sites * 3; // sync: per site a dir, expired and lost
    if s.wake > 0 {
        n += 1 + 4 + 1 + DOMAIN_GROUPS * 4 + s.wake; // wake: total, offered, now_us, unshown, sources, per group a dir and three leaves, a node a slot
    }
    n
}

fn paths(r: &Reader<'_>) -> Vec<String> {
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    r.walk(&mut |info, v| {
        if info.depth == 0 {
            return;
        }
        stack.truncate(info.depth as usize - 1);
        stack.push(info.name.as_str().to_string());
        if !matches!(v, Value::Dir) {
            out.push(stack.join("/"));
        }
    })
    .unwrap();
    out
}

fn val(r: &Reader<'_>, path: &str) -> Option<u64> {
    let id = r.lookup(path).unwrap()?;
    match r.read(id).unwrap() {
        Value::U64(v) => Some(v),
        _ => None,
    }
}

// ── layout ─────────────────────────────────────────────────────────────────

#[test]
fn the_subtree_has_the_pinned_layout() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let shape = full(4);
    let (r, m) = build(&w, shape);
    r.unwrap();
    assert!(m.is_some());
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    for p in [
        "metrics/trace/cpu0/records",
        "metrics/trace/cpu3/drops",
        "metrics/sched/switches_voluntary",
        "metrics/sched/switches_preempted",
        "metrics/sched/migrations",
        "metrics/energy/gov/evals",
        "metrics/energy/gov/safety_floor",
        "metrics/energy/idle/i3_violations",
        "metrics/energy/idle/picks/s3",
        "metrics/energy/domains/d3/opp",
        "metrics/net/packet/dropped",
        "metrics/net/rx_drops/ring_full",
        "metrics/net/arp_txq/expired",
        "metrics/net/eth0/mtu",
        "metrics/net/eth1/configured",
        "metrics/memory/zones/ring_total",
        "metrics/memory/zpool/segments_max",
        "metrics/decisions/lost",
        "metrics/decisions/unknown_rule",
        "metrics/decisions/by_rule/deadline-admission",
        "metrics/decisions/by_rule/effect-record",
        "metrics/syscalls/unshown",
        "metrics/syscalls/d0/domain",
        "metrics/storage/written_bytes",
        "metrics/storage/unowned_bytes",
        "metrics/storage/unshown",
        "metrics/storage/d0/domain",
        "metrics/sync/block_done/expired",
        "metrics/sync/block_done/lost",
        "metrics/sync/pager_swap/lost",
        "metrics/wake/total",
        "metrics/wake/offered",
        "metrics/wake/now_us",
        "metrics/wake/unshown",
        "metrics/wake/d0/domain",
        "metrics/wake/d0/wakes",
        "metrics/wake/d3/per_s",
    ] {
        assert_eq!(val(&rd, p), Some(0), "{p}");
    }
    let last = format!("metrics/syscalls/d{}/block_wake", DOMAIN_GROUPS - 1);
    assert_eq!(val(&rd, &last), Some(0), "{last}");
    let last = format!("metrics/storage/d{}/written_bytes", DOMAIN_GROUPS - 1);
    assert_eq!(val(&rd, &last), Some(0), "{last}");
    // The wake ring: a histogram of seven numbers a slot (no task ID among them), none past the shape's.
    for k in [0, WAKE_SLOTS - 1] {
        let id = rd.lookup(&format!("metrics/wake/r{k}")).unwrap().expect("a slot");
        match rd.read(id).unwrap() {
            Value::Hist(h) => assert_eq!(h.buckets(), &[0u64; WAKE_COLS][..], "r{k}"),
            _ => panic!("r{k} is not a histogram"),
        }
    }
    assert_eq!(rd.lookup(&format!("metrics/wake/r{WAKE_SLOTS}")).unwrap(), None);
    match rd.read(rd.lookup("metrics/wake/sources").unwrap().unwrap()).unwrap() {
        Value::Str(t) => assert_eq!(t.as_str(), "timer irq ipc_call reap"),
        _ => panic!("sources is not a string"),
    }
    // Every node is a counter or gauge the walk finds once, and only those.
    let mut n = 0;
    rd.walk(&mut |_, _| n += 1).unwrap();
    assert_eq!(n - 1, expected_nodes(&shape), "nodes below the root");
    let all = paths(&rd);
    let mut sorted = all.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len(), "no path twice");
    assert!(all.iter().all(|p| p.starts_with("metrics/")));
}

#[test]
fn a_part_that_is_not_compiled_in_has_no_node() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let shape = Shape {
        cpus: 2,
        trace: false,
        energy: false,
        ifaces: 1,
        zpool: false,
        rules: 0,
        rule_name,
        sites: 1,
        site_name,
        wake: 0,
        wake_sources: 0,
        wake_source_name,
    };
    build(&w, shape).0.unwrap();
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    for gone in [
        "metrics/trace",
        "metrics/energy",
        "metrics/memory/zpool",
        "metrics/net/eth1",
        "metrics/decisions/by_rule/deadline-admission",
        "metrics/wake",
    ] {
        assert_eq!(rd.lookup(gone).unwrap(), None, "{gone}");
    }
    assert_eq!(rd.lookup("metrics/sync/fat_sector").unwrap(), None, "a site the shape lacks has no node");
    assert!(rd.lookup("metrics/sync/block_done/lost").unwrap().is_some());
    assert!(rd.lookup("metrics/net/eth0/mtu").unwrap().is_some());
    assert!(rd.lookup("metrics/decisions/by_rule").unwrap().is_some());
    let mut n = 0;
    rd.walk(&mut |_, _| n += 1).unwrap();
    assert_eq!(n - 1, expected_nodes(&shape));
}

#[test]
fn a_shape_larger_than_the_arrays_is_refused_whole() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    for shape in [
        Shape { cpus: CPUS_MAX + 1, ..full(1) },
        Shape { ifaces: IFACES_MAX + 1, ..full(1) },
        Shape { rules: RULES_MAX + 1, ..full(1) },
        Shape { sites: SITES_MAX + 1, ..full(1) },
        Shape { wake: WAKE_MAX + 1, ..full(1) },
        Shape { wake_sources: WAKE_SOURCES_MAX + 1, ..full(1) },
    ] {
        assert_eq!(build(&w, shape).0, Err(Error::BadSize));
    }
}

#[test]
fn every_rule_name_fits_a_node_name() {
    for r in azos_decision::RULES.iter() {
        let n = r.name;
        assert!(n.len() <= azos_inspect::NAME_MAX && !n.contains('/'), "{n}");
    }
}

#[test]
fn the_subtree_fits_the_default_region_next_to_the_base_tree() {
    // INSPECT_PUBLIC_PAGES defaults to 24 (config/kernel/Kconfig.trace; 12
    // when this test was written, which 16 CPUs and the 75 rules of the table
    // now overflow by a few nodes). The base tree is about 40 nodes plus two
    // per CPU (kernel/src/boot/inspect.rs); stand-ins for it come first; the
    // by-rule nodes are the whole decision table's, as in the kernel, and the
    // wake ring is the default's.
    for cpus in [1, 4, 8, 16] {
        let v = words(24);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let r = w.rebuild(|b| {
            for i in 0..40 + 2 * cpus {
                b.u64(NodeId::ROOT, &format!("base{i}"), 0)?;
            }
            Metrics::build(b, full(cpus)).map(|_| ())
        });
        assert_eq!(r, Ok(()), "{cpus} CPUs");
    }
    // A region too small cuts the subtree and says so; what was added stays whole.
    let v = words(4);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(16));
    assert!(r.is_err() && m.is_none());
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert!(rd.lookup("metrics/sched").unwrap().is_some() || rd.lookup("metrics").unwrap().is_some());
}

// ── publishing ─────────────────────────────────────────────────────────────

fn snap(k: u64) -> Snapshot {
    let mut s = Snapshot::ZERO;
    for c in 0..4 {
        s.trace_records[c] = k * 10 + c as u64;
        s.trace_drops[c] = k + c as u64;
    }
    s.switches_voluntary = k * 3;
    s.switches_preempted = k * 2;
    s.migrations = k;
    s.gov = [k, k, k, k, k];
    s.idle = [k, k, k, 0];
    s.idle_picks = [k, k, 0, 0];
    s.opp = [3, 2, 1, 0];
    s.packet = [k * 5, k];
    s.rx_drops = [k, 0, 0];
    s.arp_txq = [k, k, 0, 0];
    s.iface[0] = [1500, 1, 1];
    s.zones = [7, 8, 9, 10];
    s.zpool = [k, 64, k, 2, 8, k * 100, k * 4096];
    for (i, c) in s.by_rule.iter_mut().enumerate().take(rule_count()) {
        *c = k + i as u64;
    }
    s.lost = k / 2;
    s.waits[0] = [k * 7, k];
    s.waits[8] = [k, 0];
    s.wake_total = k * 100;
    s.wake_offered = k * 7;
    s.wake_now_us = k * 1_000_000;
    for (i, row) in s.wake_rows.iter_mut().enumerate().take(WAKE_SLOTS) {
        // seq, at_us, src, line, domain, cpu, from_cpu
        *row = [k * 100 - i as u64, k * 1_000_000 - 10 * i as u64, (i % 4) as u64, 30 + i as u64, 40 + i as u64, (i % 2) as u64, 1];
    }
    s.wake_groups[0] = [0x0001_0002, k * 7];
    s.wake_groups[1] = [0x0003_0004, k];
    s.wake_rate = [k * 2, k, 0, 0];
    s.wake_unshown = k / 3;
    s
}

#[test]
fn a_refresh_publishes_every_value_where_its_name_says() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(4));
    r.unwrap();
    let m = m.unwrap();
    assert_eq!(m.publish(&w, &snap(9)), 0);
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(val(&rd, "metrics/trace/cpu2/records"), Some(92));
    assert_eq!(val(&rd, "metrics/trace/cpu2/drops"), Some(11));
    assert_eq!(val(&rd, "metrics/sched/switches_voluntary"), Some(27));
    assert_eq!(val(&rd, "metrics/sched/migrations"), Some(9));
    assert_eq!(val(&rd, "metrics/energy/domains/d0/opp"), Some(3));
    assert_eq!(val(&rd, "metrics/energy/idle/picks/s1"), Some(9));
    assert_eq!(val(&rd, "metrics/net/packet/delivered"), Some(45));
    assert_eq!(val(&rd, "metrics/net/eth0/mtu"), Some(1500));
    assert_eq!(val(&rd, "metrics/net/eth1/mtu"), Some(0));
    assert_eq!(val(&rd, "metrics/memory/zones/pagetable_total"), Some(8));
    assert_eq!(val(&rd, "metrics/memory/zpool/resident_bytes"), Some(9 * 4096));
    assert_eq!(val(&rd, "metrics/decisions/by_rule/wake-placement"), Some(9 + 3));
    assert_eq!(val(&rd, "metrics/decisions/by_rule/effect-record"), Some(9 + 34));
    assert_eq!(val(&rd, "metrics/decisions/lost"), Some(4));
    assert_eq!(val(&rd, "metrics/sync/block_done/expired"), Some(63));
    assert_eq!(val(&rd, "metrics/sync/block_done/lost"), Some(9), "lost is its own node, not expired");
    assert_eq!(val(&rd, "metrics/sync/fat_sector/expired"), Some(0));
    assert_eq!(val(&rd, "metrics/sync/pager_swap/expired"), Some(9));
    assert_eq!(val(&rd, "metrics/sync/pager_swap/lost"), Some(0));
    assert_eq!(val(&rd, "metrics/wake/total"), Some(900));
    assert_eq!(val(&rd, "metrics/wake/offered"), Some(63));
    assert_eq!(val(&rd, "metrics/wake/now_us"), Some(9_000_000));
    assert_eq!(val(&rd, "metrics/wake/unshown"), Some(3));
    assert_eq!(val(&rd, "metrics/wake/d0/domain"), Some(0x0001_0002));
    assert_eq!(val(&rd, "metrics/wake/d0/wakes"), Some(63));
    assert_eq!(val(&rd, "metrics/wake/d0/per_s"), Some(18));
    assert_eq!(val(&rd, "metrics/wake/d1/wakes"), Some(9));
    assert_eq!(val(&rd, "metrics/wake/d1/per_s"), Some(9));
    assert_eq!(val(&rd, "metrics/wake/d2/wakes"), Some(0));
    // The ring: a node a slot, the newest first, every number where the doc says.
    let row = |k: usize| match rd.read(rd.lookup(&format!("metrics/wake/r{k}")).unwrap().unwrap()).unwrap() {
        Value::Hist(h) => h.buckets().to_vec(),
        _ => panic!("r{k} is not a histogram"),
    };
    assert_eq!(row(0), vec![900, 9_000_000, 0, 30, 40, 0, 1]);
    assert_eq!(row(5), vec![895, 8_999_950, 1, 35, 45, 1, 1]);
}

#[test]
fn values_of_a_part_that_is_off_are_not_written() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let shape = Shape { trace: false, energy: false, zpool: false, ..full(4) };
    let (r, m) = build(&w, shape);
    r.unwrap();
    // The snapshot carries values for parts the shape lacks: none may fail or land elsewhere.
    assert_eq!(m.unwrap().publish(&w, &snap(5)), 0);
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(val(&rd, "metrics/sched/switches_preempted"), Some(10));
}

// ── counters never decrease ────────────────────────────────────────────────

#[test]
fn a_32_bit_counter_widens_across_a_wrap() {
    let mut w = Widen::<2>::new();
    let mut prev = 0;
    for raw in [5u32, 100, u32::MAX - 1, u32::MAX, 3, 4, 50] {
        let t = w.feed(0, raw);
        assert!(t >= prev, "{raw}");
        prev = t;
    }
    assert_eq!(prev, (1u64 << 32) + 50);
    // Counters are independent, and a slot out of range reads 0.
    assert_eq!(w.feed(1, 7), 7);
    assert_eq!(w.feed(9, 7), 0);
}

#[test]
fn switch_counts_outlive_their_tasks_and_slots() {
    let mut t = SwitchTally::<4>::new();
    t.task(0, 10, 5, 2);
    t.task(1, 11, 1, 1);
    assert_eq!(t.totals(), (6, 3));
    // Growth only.
    t.task(0, 10, 9, 2);
    assert_eq!(t.totals(), (10, 3));
    // Task 10 exits; task 12 takes slot 0 and starts at 3.
    t.task(0, 12, 3, 0);
    assert_eq!(t.totals(), (13, 3));
    // Slot 1 is free for a pass: nothing is subtracted.
    t.task(0, 12, 4, 0);
    assert_eq!(t.totals(), (14, 3));
    // The same tid with a lower count (a reused tid): treated as new.
    t.task(0, 12, 1, 0);
    assert_eq!(t.totals(), (15, 3));
    // A slot past the table is ignored.
    t.task(9, 1, 1_000, 1_000);
    assert_eq!(t.totals(), (15, 3));
}

#[test]
fn rules_are_counted_once_each_across_refreshes() {
    let ring = 8;
    let log: Vec<u8> = vec![3, 3, 0, 1, 3, 40]; // record seq = index + 1; 40 is no rule
    let mut t = RuleTally::new();
    // First refresh sees 4 records.
    t.walk(4, ring, 35, |s| log.get(s as usize - 1).copied());
    assert_eq!((t.counts[3], t.counts[0], t.counts[1]), (2, 1, 1));
    // Second sees all 6; the first four are not counted again.
    t.walk(6, ring, 35, |s| log.get(s as usize - 1).copied());
    assert_eq!((t.counts[3], t.counts[0], t.counts[1], t.unknown, t.lost), (3, 1, 1, 1, 0));
    // Nothing new: nothing changes.
    t.walk(6, ring, 35, |s| log.get(s as usize - 1).copied());
    assert_eq!((t.counts[3], t.unknown), (3, 1));
}

#[test]
fn a_record_still_being_written_is_waited_for_not_lost() {
    let mut t = RuleTally::new();
    // Record 3 is claimed and unreadable; 4 is done.
    t.walk(4, 8, 35, |s| if s == 3 { None } else { Some(1) });
    assert_eq!((t.counts[1], t.lost), (2, 0), "stops before the claimed one");
    // It is written by the next refresh.
    t.walk(4, 8, 35, |_| Some(1));
    assert_eq!((t.counts[1], t.lost), (4, 0));
}

#[test]
fn records_the_ring_overwrote_are_counted_lost() {
    let mut t = RuleTally::new();
    t.walk(2, 4, 35, |_| Some(2));
    // 20 more records, ring of 4: only the last 4 can still be read.
    t.walk(22, 4, 35, |s| (s > 18).then_some(2));
    assert_eq!(t.counts[2], 2 + 4);
    assert_eq!(t.lost, 22 - 2 - 4);
    // An unreadable record that fell out of the ring while the walk waited on it.
    let mut u = RuleTally::new();
    u.walk(3, 4, 35, |s| if s == 2 { None } else { Some(0) });
    assert_eq!((u.counts[0], u.lost), (1, 0));
    u.walk(9, 4, 35, |s| (s > 5).then_some(0));
    assert_eq!(u.counts[0], 1 + 4);
    assert_eq!(u.lost, 9 - 1 - 4);
}

#[test]
fn counters_in_the_tree_never_decrease_over_many_refreshes() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(4));
    r.unwrap();
    let m = m.unwrap();
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    let counters: Vec<String> = paths(&rd)
        .into_iter()
        .filter(|p| !p.contains("/opp") && !p.contains("/eth") && !p.contains("/zones/") && !p.contains("/zpool/"))
        // The ring's slots are histograms, the newest wakes and not counters; the
        // source names are a string.
        .filter(|p| !p.starts_with("metrics/wake/r") && p != "metrics/wake/sources")
        .collect();
    assert!(counters.len() > 60);
    let (mut wide, mut sw, mut rules) = (Widen::<2>::new(), SwitchTally::<2>::new(), RuleTally::new());
    let mut last = vec![0u64; counters.len()];
    let mut x = 12345u64;
    let mut raw32 = u32::MAX - 100;
    let mut total = 0u64;
    for round in 0..300u64 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        raw32 = raw32.wrapping_add((x >> 40) as u32 % 40);
        total += (x >> 20) % 3;
        let mut s = Snapshot::ZERO;
        s.gov[0] = wide.feed(0, raw32);
        // Two tasks, one of which is replaced every 50 rounds.
        sw.task(0, 1, round * 2, round);
        sw.task(1, 100 + (round / 50) as u32, round % 50, 0);
        (s.switches_voluntary, s.switches_preempted) = sw.totals();
        rules.walk(total, 16, 35, |q| Some((q % 35) as u8));
        s.by_rule = rules.counts;
        s.lost = rules.lost;
        s.unknown_rule = rules.unknown;
        s.migrations = rules.counts[WAKE_PLACEMENT];
        assert_eq!(m.publish(&w, &s), 0);
        for (i, p) in counters.iter().enumerate() {
            let now = val(&rd, p).unwrap();
            assert!(now >= last[i], "{p} went {} -> {now} in round {round}", last[i]);
            last[i] = now;
        }
    }
    assert!(last[counters.iter().position(|p| p == "metrics/energy/gov/evals").unwrap()] > u32::MAX as u64);
    assert!(last[counters.iter().position(|p| p == "metrics/sched/migrations").unwrap()] > 0);
}

#[test]
fn readers_follow_a_writer_publishing_in_a_loop() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(4));
    r.unwrap();
    let m = m.unwrap();
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        let readers: Vec<_> = (0..3)
            .map(|_| {
                sc.spawn(|| {
                    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
                    let ids: Vec<NodeId> = [
                        "metrics/sched/switches_voluntary",
                        "metrics/trace/cpu1/records",
                        "metrics/decisions/by_rule/split-lock",
                    ]
                    .iter()
                    .map(|p| rd.lookup(p).unwrap().unwrap())
                    .collect();
                    let mut last = [0u64; 3];
                    let mut reads = 0u64;
                    while !done.load(Acquire) {
                        for (i, id) in ids.iter().enumerate() {
                            // A node mid-write is retried by the reader, never returned torn.
                            let Ok(Value::U64(x)) = rd.read(*id) else { continue };
                            // Before the writer's first publish every node still holds its zero.
                            if x == 0 {
                                continue;
                            }
                            assert!(x >= last[i], "node {i} went {} -> {x}", last[i]);
                            // Every published value is of the form 7k + node.
                            assert_eq!(x % 7, [0, 1, 6][i] % 7, "node {i} read {x}");
                            last[i] = x;
                            reads += 1;
                        }
                    }
                    reads
                })
            })
            .collect();
        for k in 1..=20_000u64 {
            let mut s = Snapshot::ZERO;
            s.switches_voluntary = 7 * k;
            s.trace_records[1] = 7 * k + 1;
            s.by_rule[6] = 7 * k + 6;
            m.publish(&w, &s);
        }
        done.store(true, Release);
        for r in readers {
            assert!(r.join().unwrap() > 0);
        }
    });
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(val(&rd, "metrics/sched/switches_voluntary"), Some(7 * 20_000));
}

// ── what toolbox prints ────────────────────────────────────────────────────

fn published() -> Vec<AtomicU64> {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(2));
    r.unwrap();
    m.unwrap().publish(&w, &snap(4));
    v
}

#[test]
fn the_path_stack_follows_a_walk() {
    let mut p = view::PathStack::new();
    assert_eq!(p.enter(1, "metrics"), "metrics");
    assert_eq!(p.enter(2, "sched"), "metrics/sched");
    assert_eq!(p.enter(3, "migrations"), "metrics/sched/migrations");
    assert_eq!(p.enter(2, "net"), "metrics/net");
    assert_eq!(p.enter(1, "inspect"), "inspect");
    // Too deep, depth 0, and a name that does not fit.
    assert_eq!(p.enter(0, "x"), "");
    assert_eq!(p.enter(view::DEPTH_MAX as u32 + 1, "x"), "");
    assert_eq!(p.enter(1, &"n".repeat(view::PATH_MAX + 1)), "");
    assert_eq!(p.enter(2, "child-of-nothing"), "");
}

#[test]
fn a_prefix_holds_a_node_and_what_is_below_it() {
    assert!(view::under("metrics", "metrics"));
    assert!(view::under("metrics", "metrics/sched/migrations"));
    assert!(view::under("metrics/", "metrics/sched"));
    assert!(view::under("metrics/sched", "metrics/sched/migrations"));
    assert!(!view::under("metrics/sched", "metrics/scheduler"));
    assert!(!view::under("metrics/sched", "metrics"));
    assert!(view::under("", "memory/pages_free"));
    assert!(!view::under("", ""));
    assert!(!view::under("metrics", ""));
}

#[test]
fn inspect_with_a_prefix_prints_the_leaves_under_it() {
    let v = published();
    let mut insp = Inspector::new(Region::from_atomics(&v), None).unwrap();
    let mut out = String::new();
    let mut path = view::PathStack::new();
    insp.walk(&mut |_, info, val| {
        let p = path.enter(info.depth, info.name.as_str());
        if view::under("metrics/sched", p) {
            if let Value::U64(x) = val {
                view::flat(&mut out, p, view::Val::U(*x)).unwrap();
            }
        }
    })
    .unwrap();
    assert_eq!(
        out,
        "metrics/sched/switches_voluntary = 12\nmetrics/sched/switches_preempted = 8\nmetrics/sched/migrations = 4\n"
    );
}

#[test]
fn the_perfetto_trace_has_a_counter_track_per_node() {
    let v = published();
    let mut insp = Inspector::new(Region::from_atomics(&v), None).unwrap();
    let mut out = String::new();
    view::trace_begin(&mut out).unwrap();
    for ts in [0u64, 250_123_456] {
        let mut path = view::PathStack::new();
        insp.walk(&mut |_, info, val| {
            let p = path.enter(info.depth, info.name.as_str());
            if let Value::U64(x) = val {
                if view::under("metrics/decisions", p) {
                    view::trace_counter(&mut out, p, ts, *x).unwrap();
                }
            }
        })
        .unwrap();
    }
    view::trace_end(&mut out).unwrap();
    assert!(out.starts_with("{\"traceEvents\":[\n{\"name\":\"process_name\""));
    assert!(out.ends_with("\n]}\n"));
    // One sample per node per pass: lost, unknown_rule, one per rule, twice.
    assert_eq!(out.matches("\"ph\":\"C\"").count(), 2 * (2 + rule_count()));
    assert!(out.contains(
        ",\n{\"name\":\"metrics/decisions/by_rule/wake-placement\",\"ph\":\"C\",\"ts\":250123.456,\"pid\":0,\"args\":{\"v\":7}}"
    ));
    assert!(out.contains("\"ts\":0.000,"));
    // Braces and brackets balance outside strings: every event is one object.
    let (mut depth, mut max, mut in_str, mut esc) = (0i32, 0, false, false);
    for c in out.chars() {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => {
                depth += 1;
                max = max.max(depth);
            }
            '}' | ']' => depth -= 1,
            _ => {}
        }
        assert!(depth >= 0);
    }
    assert_eq!(depth, 0);
    assert_eq!(max, 4, "{{traceEvents:[{{args:{{}}}}]}}");
}

#[test]
fn a_node_name_with_a_quote_cannot_break_the_trace() {
    let mut out = String::new();
    view::trace_counter(&mut out, "a\"b\\c\nd", 1, 2).unwrap();
    assert!(out.contains("\"name\":\"a\\\"b\\\\c\\u000ad\""), "{out}");
}

#[test]
fn flat_prints_every_kind() {
    let mut s = String::new();
    view::flat(&mut s, "a", view::Val::I(-3)).unwrap();
    view::flat(&mut s, "b", view::Val::S("legacy")).unwrap();
    view::flat(&mut s, "c", view::Val::H(&[1, 2, 3])).unwrap();
    assert_eq!(s, "a = -3\nb = legacy\nc = 1,2,3\n");
}

// ── kernel entries per Domain ──────────────────────────────────────────────

/// A fake Domain table: slot -> (key, entries by case).
fn table(rows: &[(usize, u32, [u64; 3])]) -> impl Fn(usize) -> Option<(u32, [u64; 3])> + '_ {
    move |slot| rows.iter().find(|r| r.0 == slot).map(|r| (r.1, r.2))
}

/// **A Domain that has entered the kernel is shown, by case, under the key
/// that names it; a Domain that never has is not shown at all.** The numbers
/// are read back through the tree, where a reader finds them.
#[test]
fn the_entries_of_a_domain_are_published_by_case() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(4));
    r.unwrap();
    let m = m.unwrap();
    // Slot 3 made 5 authority and 9 block/wake entries; slot 4 none; slot 6 a Linux task's 2.
    let rows = [(3, 0x0007_0003, [0, 5, 9]), (4, 0x0001_0004, [0, 0, 0]), (6, 0x0002_0006, [2, 0, 0])];
    let (mut g, mut snap) = (DomainGroups::new(), Snapshot::ZERO);
    g.pass(16, table(&rows), &mut snap.groups, &mut snap.unshown);
    assert_eq!(m.publish(&w, &snap), 0);
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(val(&rd, "metrics/syscalls/d0/domain"), Some(0x0007_0003));
    assert_eq!(val(&rd, "metrics/syscalls/d0/none"), Some(0));
    assert_eq!(val(&rd, "metrics/syscalls/d0/authority"), Some(5));
    assert_eq!(val(&rd, "metrics/syscalls/d0/block_wake"), Some(9));
    assert_eq!(val(&rd, "metrics/syscalls/d1/domain"), Some(0x0002_0006), "the Domain with no entries takes no group");
    assert_eq!(val(&rd, "metrics/syscalls/d1/none"), Some(2));
    assert_eq!(val(&rd, "metrics/syscalls/d2/domain"), Some(0), "a free group reads zero");
    assert_eq!(val(&rd, "metrics/syscalls/unshown"), Some(0));
}

/// **A group keeps its Domain while it lives, follows the table when the Domain
/// ends, and the Domains past the groups are counted, not lost.**
#[test]
fn a_group_keeps_its_domain_frees_with_it_and_overflow_is_counted() {
    let mut g = DomainGroups::new();
    let (mut groups, mut unshown) = ([[0u64; 4]; DOMAIN_GROUPS], 0u64);
    let n = DOMAIN_GROUPS + 3;
    let rows: Vec<(usize, u32, [u64; 3])> = (0..n).map(|i| (i + 1, 0x10000 + i as u32 + 1, [0, 1, 1])).collect();
    g.pass(32, table(&rows), &mut groups, &mut unshown);
    assert_eq!(unshown, 3, "three Domains past the groups");
    assert_eq!(groups[0][0], 0x10001);
    assert_eq!(groups[DOMAIN_GROUPS - 1][0], 0x10000 + DOMAIN_GROUPS as u64);
    // Domain in slot 1 ends and slot 2's entries grow: slot 2 keeps group 1.
    let rows: Vec<(usize, u32, [u64; 3])> = rows
        .into_iter()
        .filter(|r| r.0 != 1)
        .map(|mut r| {
            r.2[1] += 4;
            r
        })
        .collect();
    g.pass(32, table(&rows), &mut groups, &mut unshown);
    assert_eq!(groups[1][2], 5, "slot 2 stays in its group and its count grew");
    assert_eq!(groups[0][0], 0x10000 + DOMAIN_GROUPS as u64 + 1, "the freed group takes the first Domain left out");
    assert_eq!(unshown, 2);
}

/// A slot taken again by another Domain: its group shows the new key and the
/// new Domain's entries, which start from zero. The group is a gauge.
#[test]
fn a_slot_taken_by_another_domain_restarts_its_group() {
    let mut g = DomainGroups::new();
    let (mut groups, mut unshown) = ([[0u64; 4]; DOMAIN_GROUPS], 0u64);
    g.pass(8, table(&[(2, 0x0001_0002, [0, 50, 50])]), &mut groups, &mut unshown);
    assert_eq!(groups[0], [0x0001_0002, 0, 50, 50]);
    g.pass(8, table(&[(2, 0x0002_0002, [0, 1, 0])]), &mut groups, &mut unshown);
    assert_eq!(groups[0], [0x0002_0002, 0, 1, 0]);
}

/// A fake Domain table for the write ledger: slot -> (key, bytes written).
fn ledger(rows: &[(usize, u32, u64)]) -> impl Fn(usize) -> Option<(u32, [u64; 1])> + '_ {
    move |slot| rows.iter().find(|r| r.0 == slot).map(|r| (r.1, [r.2]))
}

/// **The bytes written for a Domain are published under the key that names it,
/// next to the device total and the part no live Domain owns; a Domain that
/// never wrote is not shown.** Read back through the tree.
#[test]
fn the_bytes_written_for_a_domain_are_published_with_the_totals() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(4));
    r.unwrap();
    let m = m.unwrap();
    // Slot 3 wrote 8 KiB, slot 4 nothing, slot 6 512 bytes.
    let rows = [(3, 0x0007_0003, 8192), (4, 0x0001_0004, 0), (6, 0x0002_0006, 512)];
    let (mut g, mut snap) = (DomainGroups::new(), Snapshot::ZERO);
    g.pass(16, ledger(&rows), &mut snap.storage_groups, &mut snap.storage_unshown);
    snap.written = 8192 + 512 + 4096;
    snap.written_unowned = 4096;
    assert_eq!(m.publish(&w, &snap), 0);
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(val(&rd, "metrics/storage/written_bytes"), Some(12800));
    assert_eq!(val(&rd, "metrics/storage/unowned_bytes"), Some(4096));
    assert_eq!(val(&rd, "metrics/storage/d0/domain"), Some(0x0007_0003));
    assert_eq!(val(&rd, "metrics/storage/d0/written_bytes"), Some(8192));
    assert_eq!(val(&rd, "metrics/storage/d1/domain"), Some(0x0002_0006), "the Domain that wrote nothing takes no group");
    assert_eq!(val(&rd, "metrics/storage/d1/written_bytes"), Some(512));
    assert_eq!(val(&rd, "metrics/storage/d2/domain"), Some(0), "a free group reads zero");
    assert_eq!(val(&rd, "metrics/storage/unshown"), Some(0));
    // The syscalls groups are another table: nothing leaked into them.
    assert_eq!(val(&rd, "metrics/syscalls/d0/domain"), Some(0));
}

/// The ledger's groups overflow like the entries': the Domains past them are
/// counted in `storage/unshown`.
#[test]
fn the_ledger_counts_the_domains_past_its_groups() {
    let mut g = DomainGroups::new();
    let (mut groups, mut unshown) = ([[0u64; 2]; DOMAIN_GROUPS], 0u64);
    let rows: Vec<(usize, u32, u64)> = (0..DOMAIN_GROUPS + 2).map(|i| (i + 1, 0x10000 + i as u32 + 1, 512)).collect();
    g.pass(32, ledger(&rows), &mut groups, &mut unshown);
    assert_eq!(unshown, 2);
    assert_eq!(groups[0], [0x10001, 512]);
}

// ── the wake attribution ───────────────────────────────────────────────────

#[test]
fn the_source_names_are_joined_by_spaces_and_cut_at_a_whole_name() {
    assert_eq!(&*Joined::of(WAKE_SOURCE_NAMES.len(), wake_source_name), "timer irq ipc_call reap");
    assert_eq!(&*Joined::of(0, wake_source_name), "");
    fn long(_: usize) -> &'static str {
        "0123456789012345678901234567890123456789012345678901234567890123"
    }
    // Two of 64 bytes and a separator fit 128 only without the separator's byte.
    assert_eq!(Joined::of(3, long).len(), 64, "the second name does not fit beside the first: cut whole, not in the middle");
}

#[test]
fn the_wake_rate_is_the_growth_of_one_domain_over_the_interval() {
    let mut r = WakeRate::new();
    let g = |a: [u64; 2], b: [u64; 2]| [a, b, [0; 2], [0; 2]];
    assert_eq!(r.pass(1_000, &g([7, 100], [8, 5])), [0; 4], "the first refresh has no interval");
    assert_eq!(r.pass(1_250, &g([7, 200], [8, 5])), [400, 0, 0, 0], "100 wakes in 250 ms");
    // A group that shows another Domain now starts again; so does a count that went down.
    assert_eq!(r.pass(1_500, &g([9, 900], [8, 4])), [0; 4]);
    assert_eq!(r.pass(1_750, &g([9, 1_150], [8, 9])), [1_000, 20, 0, 0]);
    // The same millisecond is the same interval.
    assert_eq!(r.pass(1_750, &g([9, 5_000], [8, 9])), [1_000, 20, 0, 0]);
    assert_eq!(r.pass(2_750, &g([9, 2_150], [8, 9])), [1_000, 0, 0, 0], "the last interval is from 1750");
    // A free group (key 0) has none.
    assert_eq!(r.pass(3_750, &g([0, 10], [0, 0])), [0; 4]);
}

#[test]
fn the_wake_groups_are_bound_to_the_domains_that_were_woken() {
    let rows = [(0usize, 0x10001u32, [3u64]), (5, 0x20005, [0]), (7, 0x30007, [9])];
    let get = |slot: usize| rows.iter().find(|r| r.0 == slot).map(|r| (r.1, r.2));
    let mut g = DomainGroups::new();
    let (mut groups, mut unshown) = ([[0u64; 2]; DOMAIN_GROUPS], 0);
    g.pass(16, get, &mut groups, &mut unshown);
    assert_eq!(groups[0], [0x10001, 3]);
    assert_eq!(groups[1], [0x30007, 9], "a Domain nobody woke is not shown");
    assert_eq!(groups[2], [0, 0]);
    assert_eq!(unshown, 0);
}

#[test]
fn a_kernel_without_the_ring_publishes_no_wake_values() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let shape = Shape { wake: 0, wake_sources: 0, ..full(2) };
    let (r, m) = build(&w, shape);
    r.unwrap();
    // The snapshot carries wake values: none may fail or land elsewhere.
    assert_eq!(m.unwrap().publish(&w, &snap(5)), 0);
    let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
    assert_eq!(rd.lookup("metrics/wake").unwrap(), None);
}

/// A wake as the ring has it: `(seq, at_us, src, line, waker, tid, domain, cpu, from_cpu)`.
fn wake(seq: u64, at_us: u64, src: u8, line: u32, waker: u32, tid: u32, domain: u32, cpu: u8, from_cpu: u8) -> WakeEntry {
    WakeEntry { seq, at_us, src, line, waker, tid, domain, cpu, from_cpu }
}

/// The two regions of a kernel that logged `entries` (the newest first): the
/// public one, and the admin one when `admin`, as `inspect.rs` publishes them.
fn regions(entries: &[WakeEntry], total: u64, now_us: u64, admin: bool) -> (Vec<AtomicU64>, Option<Vec<AtomicU64>>) {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, m) = build(&w, full(2));
    r.unwrap();
    let mut s = Snapshot::ZERO;
    s.wake_total = total;
    s.wake_offered = total / 6;
    s.wake_now_us = now_us;
    for (slot, e) in s.wake_rows.iter_mut().zip(entries) {
        *slot = public_wake_row(e);
    }
    s.wake_groups[0] = [0x0001_0002, 64];
    s.wake_rate[0] = 12;
    assert_eq!(m.unwrap().publish(&w, &s), 0);
    let a = admin.then(|| {
        let a = words(12);
        let w = Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
        let mut ids = None;
        w.rebuild(|b| {
            ids = Some(build_admin_wake(b, WAKE_SLOTS)?);
            Ok(())
        })
        .unwrap();
        assert_eq!(ids.unwrap().publish(&w, now_us, entries.iter().map(admin_wake_row)), 0);
        a
    });
    (v, a)
}

/// `why woke`'s report over `regions`.
fn woke_view(entries: &[WakeEntry], total: u64, now_us: u64, want: usize, admin: bool) -> Result<woke::Report, woke::ReadError> {
    let (v, a) = regions(entries, total, now_us, admin);
    let mut view = Inspector::new(Region::from_atomics(&v), a.as_ref().map(|a| Region::from_atomics(a))).unwrap();
    let mut report = woke::Report::new();
    woke::read(&mut view, want, &mut report)?;
    Ok(report)
}

fn woke_report(entries: &[WakeEntry], total: u64, now_us: u64, want: usize) -> Result<woke::Report, woke::ReadError> {
    woke_view(entries, total, now_us, want, false)
}

fn render(r: &woke::Report) -> String {
    let mut out = String::new();
    woke::render(r, &mut out).unwrap();
    out
}

/// Wakes of three Domains (a program's own, another's and a kernel task's), by
/// sources that name a waker and by those that do not, every task ID a number
/// that no other field holds.
fn wakes_of_three_domains() -> Vec<WakeEntry> {
    const SRC_IRQ: u8 = 1;
    const SRC_IPC: u8 = 2;
    vec![
        wake(41, 9_999_000, SRC_IRQ, 33, 0, 0xA0141, 0x10002, 1, 1),   // an interrupt line woke a task of Domain 0x10002
        wake(40, 9_950_000, SRC_IPC, 0, 0xB0209, 0xB0314, 0x30004, 0, 2), // a task of 0x30004's IPC call woke another of its own
        wake(39, 9_000_000, 0, 0, 0, 0xC0420, 0x10002, 3, 3),            // a deadline
        wake(38, 8_000_000, SRC_IPC, 0, 0xD0511, 0xD0612, 0x10002, 0, 0), // a task of 0x10002 woke another of 0x10002
        wake(37, 1_000_000, 3, 0, 0, 0xE0721, 0, 0, 0),                  // the reaper woke a kernel task
    ]
}

#[test]
fn why_woke_prints_each_wake_with_its_source_target_and_age() {
    let rows = wakes_of_three_domains();
    let r = woke_report(&rows, 42, 10_000_000, 16).unwrap();
    assert_eq!((r.n, r.total, r.view), (5, 42, woke::View::Public));
    let text = render(&r);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "42 wakes since boot, 7 offered to the ring; the last 5 logged below (public view: task IDs are in the admin region, which this program does not hold)"
    );
    assert!(lines[1].contains("SOURCE") && lines[1].contains("DOMAIN") && !lines[1].contains("WOKE"), "{}", lines[1]);
    // Age is the refresh clock minus the wake's; the source is the name the kernel listed.
    assert!(lines[2].starts_with("   1.0ms       41 irq        line 33"), "{}", lines[2]);
    assert!(lines[2].contains("0x10002") && lines[2].trim_end().ends_with(" 1"), "{}", lines[2]);
    // A wake a task made hides its waker; the machine's own name none.
    assert!(lines[3].contains("ipc_call") && lines[3].contains("(admin)") && lines[3].ends_with("0 (from 2)"), "{}", lines[3]);
    assert!(lines[4].contains("timer") && lines[4].contains(" - ") && lines[4].starts_with("   1.00s"), "{}", lines[4]);
    assert!(lines[6].contains("reap") && lines[6].contains("kernel") && lines[6].starts_with("   9.00s"), "{}", lines[6]);
    assert!(!text.contains("tid"), "a public listing names no task: {text}");
}

#[test]
fn why_woke_reads_the_admin_view_when_it_holds_the_log() {
    let rows = wakes_of_three_domains();
    let r = woke_view(&rows, 42, 10_000_000, 16, true).unwrap();
    assert_eq!((r.n, r.view), (5, woke::View::Admin));
    assert_eq!((r.rows[1].tid, r.rows[1].waker), (0xB0314, 0xB0209));
    assert_eq!((r.rows[0].tid, r.rows[0].waker, r.rows[0].line), (0xA0141, 0, 33), "a line, not a waker");
    let text = render(&r);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].ends_with("below (admin view)"), "{}", lines[0]);
    assert!(lines[1].contains("FROM") && lines[1].contains("WOKE") && lines[1].contains("DOMAIN"), "{}", lines[1]);
    assert!(lines[2].contains("line 33") && lines[2].contains(&format!("tid {}", 0xA0141)), "{}", lines[2]);
    assert!(lines[3].contains(&format!("tid {}", 0xB0209)) && lines[3].contains(&format!("tid {}", 0xB0314)), "{}", lines[3]);
    assert!(lines[3].contains("0x30004") && lines[3].ends_with("0 (from 2)"), "{}", lines[3]);
    assert!(lines[4].contains("timer") && lines[4].contains(" - "), "a deadline has no waker: {}", lines[4]);
    // The counters and the Domains are the public ones in either view.
    assert_eq!((r.total, r.offered), (42, 7));
    assert_eq!(r.groups[0].domain, 0x0001_0002);
}

/// An admin region the view holds but the log is not in (the tree was cut) is
/// the public view, and says so.
#[test]
fn an_admin_region_without_the_log_is_the_public_view() {
    let (v, _) = regions(&wakes_of_three_domains(), 42, 10_000_000, false);
    let a = words(12);
    let w = Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
    w.rebuild(|b| b.u64(NodeId::ROOT, "tasks_seen", 3).map(|_| ())).unwrap();
    let mut view = Inspector::new(Region::from_atomics(&v), Some(Region::from_atomics(&a))).unwrap();
    let mut report = woke::Report::new();
    woke::read(&mut view, 16, &mut report).unwrap();
    assert_eq!((report.view, report.n), (woke::View::Public, 5));
}

/// Every u64 a region holds, nodes and histograms and string bytes alike.
fn region_words(v: &[AtomicU64]) -> Vec<u64> {
    v.iter().map(|w| w.load(Relaxed)).collect()
}

/// The owner decision 21-10: a program without the admin right sees no task of
/// another Domain, at the source. The public region is one for every reader, so
/// the test is on its words: the same wakes with other task IDs publish the same
/// region, no word of it is a task ID, and a reader of it (`why woke`) has none.
/// The admin region carries them all.
#[test]
fn a_public_reader_never_sees_a_task_id() {
    let wakes = wakes_of_three_domains();
    let ids: Vec<u32> = wakes.iter().flat_map(|e| [e.tid, e.waker]).filter(|t| *t != 0).collect();
    assert_eq!(ids.len(), 7);
    let (public, admin) = regions(&wakes, 42, 10_000_000, true);

    // No word of the public region is a task ID (they are chosen not to collide with anything else).
    let pub_words = region_words(&public);
    for id in &ids {
        assert!(!pub_words.iter().any(|w| *w == u64::from(*id)), "task {id:#x} is in the public region");
    }
    // The region is a function of everything but the task IDs.
    let mut others = wakes.clone();
    for (k, e) in others.iter_mut().enumerate() {
        e.tid = if e.tid == 0 { 0 } else { 0x7000 + k as u32 };
        e.waker = if e.waker == 0 { 0 } else { 0x8000 + k as u32 };
    }
    let (other_public, other_admin) = regions(&others, 42, 10_000_000, true);
    assert_eq!(pub_words, region_words(&other_public), "the public region depends on a task ID");
    assert_ne!(
        region_words(admin.as_ref().unwrap()),
        region_words(other_admin.as_ref().unwrap()),
        "the admin region is where the task IDs are"
    );
    // What a reader of the public view gets: no task, a Domain instead.
    let r = woke_report(&wakes, 42, 10_000_000, 16).unwrap();
    assert!(r.rows[..r.n].iter().all(|row| row.tid == 0 && row.waker == 0));
    assert_eq!(r.rows[1].domain, 0x30004);

    // The admin region has every one of them, the task woken and its waker.
    let admin_words = region_words(admin.as_ref().unwrap());
    for id in &ids {
        assert!(admin_words.iter().any(|w| *w == u64::from(*id)), "task {id:#x} is not in the admin region");
    }
    let r = woke_view(&wakes, 42, 10_000_000, 16, true).unwrap();
    let seen: Vec<u32> = r.rows[..r.n].iter().flat_map(|row| [row.tid, row.waker]).filter(|t| *t != 0).collect();
    assert_eq!(seen, ids);
}

#[test]
fn the_admin_wake_log_has_the_entries_the_ring_has_and_a_clock() {
    let (_, admin) = regions(&wakes_of_three_domains()[..2], 9, 5_000, true);
    let a = admin.unwrap();
    let rd = Reader::open(Region::from_atomics(&a), Class::Admin).unwrap();
    assert_eq!(val(&rd, "wake/now_us"), Some(5_000));
    let row = |k: usize| match rd.read(rd.lookup(&format!("wake/r{k}")).unwrap().unwrap()).unwrap() {
        Value::Hist(h) => h.buckets().to_vec(),
        _ => panic!("not a histogram"),
    };
    // seq, at_us, src, line, domain, cpu, from_cpu, tid, waker
    assert_eq!(row(0), vec![41, 9_999_000, 1, 33, 0x10002, 1, 1, 0xA0141, 0]);
    assert_eq!(row(1), vec![40, 9_950_000, 2, 0, 0x30004, 0, 2, 0xB0314, 0xB0209]);
    assert_eq!(row(2), vec![0; WAKE_ADMIN_COLS], "a slot the ring has no entry for is zeros");
    assert_eq!(rd.lookup(&format!("wake/r{WAKE_SLOTS}")).unwrap(), None, "a slot a ring entry");
}

#[test]
fn why_woke_takes_the_newest_n_and_ends_at_the_first_empty_slot() {
    let rows: Vec<WakeEntry> = (0..5).map(|i| wake(100 - i, 5_000_000 - i * 10, 0, 0, 0, 7, 0x10002, 0, 0)).collect();
    let r = woke_report(&rows, 100, 5_000_000, 3).unwrap();
    assert_eq!(r.n, 3);
    assert_eq!((r.rows[0].seq, r.rows[2].seq), (100, 98), "newest first");
    let r = woke_report(&rows, 100, 5_000_000, 16).unwrap();
    assert_eq!(r.n, 5, "a slot with no wake in it is not a row");
    // The same in the admin view, whose slots past the entries are zeros too.
    let r = woke_view(&rows, 100, 5_000_000, 16, true).unwrap();
    assert_eq!((r.n, r.view), (5, woke::View::Admin));
    // A young boot: nothing woke yet.
    let r = woke_report(&[], 0, 1_000, 16).unwrap();
    assert_eq!(r.n, 0);
    assert!(render(&r).starts_with("0 wakes since boot, 0 offered to the ring; the last 0 logged below"));
    let r = woke_view(&[], 0, 1_000, 16, true).unwrap();
    assert_eq!((r.n, r.view), (0, woke::View::Admin));
}

#[test]
fn why_woke_names_the_domains_that_were_woken_with_their_rate() {
    let r = woke_report(&[], 1, 1, 16).unwrap();
    let text = render(&r);
    assert!(text.contains("woken Domains"), "{text}");
    assert!(text.contains("0x10002") && text.contains("64") && text.contains("12/s"), "{text}");
    // Only the groups that show a Domain are listed.
    assert_eq!(text.lines().filter(|l| l.contains("/s")).count(), 1, "{text}");
}

#[test]
fn a_source_the_kernel_did_not_list_prints_a_question_mark() {
    let r = woke_report(&[wake(1, 10, 15, 0, 0, 5, 0x10002, 0, 0)], 1, 20, 1).unwrap();
    assert_eq!(r.source(15), "?");
    assert!(render(&r).contains(" ? "), "{}", render(&r));
}

#[test]
fn why_woke_on_a_kernel_without_the_ring_says_it_is_off() {
    let v = words(12);
    let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
    let (r, _m) = build(&w, Shape { wake: 0, wake_sources: 0, ..full(2) });
    r.unwrap();
    let mut view = Inspector::new(Region::from_atomics(&v), None).unwrap();
    let mut report = woke::Report::new();
    assert_eq!(woke::read(&mut view, 4, &mut report).err(), Some(woke::ReadError::Off));
}

#[test]
fn an_age_keeps_three_digits() {
    let mut cases = vec![];
    for (us, want) in [
        (0, "0us"),
        (850, "850us"),
        (1_000, "1.0ms"),
        (12_345, "12.3ms"),
        (99_999, "99.9ms"),
        (100_000, "100ms"),
        (999_999, "999ms"),
        (1_000_000, "1.00s"),
        (4_520_000, "4.52s"),
        (59_999_999, "59.99s"),
        (187_000_000, "3m07s"),
    ] {
        let mut t = String::new();
        woke::age(&mut t, us).unwrap();
        cases.push((us, t.clone()));
        assert_eq!(t, want, "{us} us");
    }
    assert_eq!(cases.len(), 11);
}

#[test]
fn why_woke_arguments() {
    assert_eq!(woke::parse_count(&[]), Some(woke::DEFAULT_ROWS));
    assert_eq!(woke::parse_count(&["5"]), Some(5));
    assert_eq!(woke::parse_count(&["0"]), None);
    assert_eq!(woke::parse_count(&["65"]), None, "past the most the ring holds");
    assert_eq!(woke::parse_count(&["x"]), None);
    assert_eq!(woke::parse_count(&["1", "2"]), None);
}
