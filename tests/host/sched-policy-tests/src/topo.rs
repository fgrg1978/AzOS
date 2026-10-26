// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sched/src/topo.rs`: the topology levels built from the labels
//! of each source, the CPUID decoder on synthetic CPUID values, and the PPTT
//! parser of `arch/x86_64/src/firmware/acpi.rs` on synthetic tables.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod topo;`.

#[path = "../../../../crates/core/sched/src/topo.rs"]
#[allow(dead_code)]
mod subject;

#[path = "../../../../arch/x86_64/src/firmware/acpi.rs"]
#[allow(dead_code)]
mod acpi;

use subject::*;

/// `n` CPUs with the given labels, no capacity.
fn raw(labels: &[(u32, u32, u32, u32, u32)]) -> Vec<CpuRaw> {
    labels
        .iter()
        .map(|&(core, cluster, llc, node, package)| CpuRaw { core, cluster, llc, node, package, dmips: 0 })
        .collect()
}

fn masks(t: &Topology, level: Level, n: usize) -> Vec<Mask> {
    (0..n).map(|c| t.mask(level, c)).collect()
}

#[test]
fn a_device_tree_cpu_map_gives_core_cluster_and_package() {
    // Two clusters of two cores of two threads; the DT names no cache, node or
    // socket, so those default (LLC and node to the package, package to all).
    let r = raw(&[
        (0, 0, NONE, NONE, NONE),
        (0, 0, NONE, NONE, NONE),
        (1, 0, NONE, NONE, NONE),
        (1, 0, NONE, NONE, NONE),
        (2, 1, NONE, NONE, NONE),
        (2, 1, NONE, NONE, NONE),
        (3, 1, NONE, NONE, NONE),
        (3, 1, NONE, NONE, NONE),
    ]);
    let t = build(&r, Source::Dt);
    assert_eq!(masks(&t, Level::Smt, 8), [0x03, 0x03, 0x0c, 0x0c, 0x30, 0x30, 0xc0, 0xc0]);
    assert_eq!(masks(&t, Level::Cluster, 8), [0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0]);
    for l in [Level::Llc, Level::Node, Level::Package] {
        assert_eq!(masks(&t, l, 8), [0xff; 8], "{}", l.name());
    }
    assert!(!t.irregular);
}

#[test]
fn a_flat_core_list_has_no_cluster_level() {
    // No cluster, no thread: the cluster is the core, which is the CPU.
    let r = raw(&[(0, NONE, NONE, NONE, NONE), (1, NONE, NONE, NONE, NONE), (2, NONE, NONE, NONE, NONE)]);
    let t = build(&r, Source::Dt);
    assert_eq!(masks(&t, Level::Smt, 3), [1, 2, 4]);
    assert_eq!(masks(&t, Level::Cluster, 3), [1, 2, 4]);
    assert_eq!(masks(&t, Level::Package, 3), [7, 7, 7]);
}

#[test]
fn no_firmware_description_is_one_package_of_lone_cpus() {
    let t = build(&[CpuRaw::UNKNOWN; 4], Source::None);
    assert_eq!(masks(&t, Level::Smt, 4), [1, 2, 4, 8]);
    assert_eq!(masks(&t, Level::Cluster, 4), [1, 2, 4, 8]);
    assert_eq!(masks(&t, Level::Llc, 4), [0xf; 4]);
    assert_eq!(masks(&t, Level::Package, 4), [0xf; 4]);
    assert!(!t.capacity_known);
    assert_eq!((0..4).map(|c| t.capacity(c)).collect::<Vec<_>>(), [CAPACITY_SCALE; 4]);
}

#[test]
fn a_cpu_the_source_omits_is_alone_not_merged_with_the_rest() {
    // CPU 2 has no labels while its neighbours share core 0 and one package.
    let r = raw(&[(0, NONE, NONE, NONE, 0), (0, NONE, NONE, NONE, 0), (NONE, NONE, NONE, NONE, NONE)]);
    let t = build(&r, Source::Pptt);
    assert_eq!(masks(&t, Level::Smt, 3), [3, 3, 4]);
    assert_eq!(masks(&t, Level::Package, 3), [3, 3, 4]);
}

#[test]
fn two_packages_and_their_caches_nest() {
    // Two sockets of four CPUs, each socket two LLCs of two CPUs.
    let r = raw(&[
        (0, NONE, 10, NONE, 0),
        (1, NONE, 10, NONE, 0),
        (2, NONE, 11, NONE, 0),
        (3, NONE, 11, NONE, 0),
        (4, NONE, 20, NONE, 1),
        (5, NONE, 20, NONE, 1),
        (6, NONE, 21, NONE, 1),
        (7, NONE, 21, NONE, 1),
    ]);
    let t = build(&r, Source::Pptt);
    assert_eq!(masks(&t, Level::Llc, 8), [0x03, 0x03, 0x0c, 0x0c, 0x30, 0x30, 0xc0, 0xc0]);
    // Node unstated: the package.
    assert_eq!(masks(&t, Level::Node, 8), [0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0]);
    assert_eq!(masks(&t, Level::Package, 8), masks(&t, Level::Node, 8));
    assert_eq!(summary_of(&t, Level::Llc, 8), (4, 2, 2));
    assert_eq!(summary_of(&t, Level::Package, 8), (2, 4, 4));
}

/// `(groups, smallest, largest)` by the installed path's rule, on a built one.
fn summary_of(t: &Topology, level: Level, n: usize) -> (usize, u32, u32) {
    let ms = masks(t, level, n);
    let firsts: Vec<_> = ms.iter().enumerate().filter(|(i, m)| m.trailing_zeros() as usize == *i).collect();
    let w: Vec<u32> = firsts.iter().map(|(_, m)| m.count_ones()).collect();
    (firsts.len(), *w.iter().min().unwrap(), *w.iter().max().unwrap())
}

/// Every level is a partition: a mask is the same for each CPU in it, and
/// each level holds the one inside it.
fn assert_partitions(t: &Topology, n: usize) {
    for level in Level::ALL {
        for i in 0..n {
            let m = t.mask(level, i);
            assert_ne!(m & (1 << i), 0, "{} of {i} holds {i}", level.name());
            for j in (0..n).filter(|j| m & (1 << j) != 0) {
                assert_eq!(t.mask(level, j), m, "{}: {i} and {j} disagree", level.name());
            }
        }
    }
    for (inner, outer) in Level::ALL.iter().zip(&Level::ALL[1..]) {
        for i in 0..n {
            assert_eq!(t.mask(*inner, i) & !t.mask(*outer, i), 0, "{} in {}", inner.name(), outer.name());
        }
    }
}

#[test]
fn levels_that_do_not_nest_are_merged_into_partitions_and_reported() {
    // CPUs 0 and 1 are threads of one core, but the firmware puts them in two
    // clusters, the second of which also holds CPU 2: widening alone would
    // give cluster(0) = {0,1} and cluster(1) = {0,1,2}.
    let r = raw(&[(0, 5, NONE, NONE, NONE), (0, 6, NONE, NONE, NONE), (1, 6, NONE, NONE, NONE)]);
    let t = build(&r, Source::Pptt);
    assert!(t.irregular);
    assert_partitions(&t, 3);
    assert_eq!(masks(&t, Level::Cluster, 3), [0b111; 3]);
}

#[test]
fn every_regular_source_is_a_partition_and_not_irregular() {
    let tables = [
        raw(&[(0, 0, NONE, NONE, NONE), (0, 0, NONE, NONE, NONE), (1, 1, NONE, NONE, NONE)]),
        raw(&[(0, NONE, 10, NONE, 0), (1, NONE, 10, NONE, 0), (2, NONE, 11, NONE, 1)]),
        vec![CpuRaw::UNKNOWN; 5],
    ];
    for r in &tables {
        let t = build(r, Source::Pptt);
        assert_partitions(&t, r.len());
        assert!(!t.irregular);
    }
}

#[test]
fn a_cpu_missing_a_label_the_others_have_is_reported_not_left_asymmetric() {
    // CPU 2 states no node while 0 and 1 share node 7: its node defaults to
    // its package ({2} with the other two in package 0), which is not a
    // class the others agree with. The masks come out as partitions anyway.
    let r = raw(&[(0, NONE, NONE, 7, 0), (1, NONE, NONE, 7, 0), (2, NONE, NONE, NONE, 0)]);
    let t = build(&r, Source::Dt);
    assert_partitions(&t, 3);
    assert!(t.irregular);
}

#[test]
fn capacity_is_scaled_to_the_largest_cpu_only_when_every_cpu_states_it() {
    let mk = |d: [u32; 4]| -> Vec<CpuRaw> { d.iter().map(|&dmips| CpuRaw { dmips, ..CpuRaw::UNKNOWN }).collect() };
    let t = build(&mk([446, 446, 1024, 1024]), Source::Dt);
    assert!(t.capacity_known);
    assert_eq!((0..4).map(|c| t.capacity(c)).collect::<Vec<_>>(), [446, 446, 1024, 1024]);
    let t = build(&mk([512, 512, 2048, 2048]), Source::Dt);
    assert_eq!((0..4).map(|c| t.capacity(c)).collect::<Vec<_>>(), [256, 256, 1024, 1024]);
    // One CPU silent: nothing is known about the table.
    let t = build(&mk([446, 0, 1024, 1024]), Source::Dt);
    assert!(!t.capacity_known);
    assert_eq!((0..4).map(|c| t.capacity(c)).collect::<Vec<_>>(), [CAPACITY_SCALE; 4]);
    // A tiny CPU is never rounded to zero capacity.
    let t = build(&mk([1, 1, 1_000_000, 1_000_000]), Source::Dt);
    assert_eq!(t.capacity(0), 1);
}

#[test]
fn cpus_past_the_ceiling_are_ignored() {
    let r = vec![CpuRaw::UNKNOWN; MAX_CPUS + 8];
    let t = build(&r, Source::None);
    assert_eq!(t.mask(Level::Package, 0), u64::MAX);
    assert_eq!(t.mask(Level::Package, MAX_CPUS), 0, "a CPU past the ceiling has no mask");
}

#[test]
fn install_publishes_masks_capacities_and_the_source() {
    assert_eq!(installed(), 0);
    assert_eq!(mask(Level::Smt, 0), 0, "nothing before install");
    assert_eq!(capacity(0), CAPACITY_SCALE);
    let r: Vec<CpuRaw> = [(0u32, 100u32), (0, 100), (1, 200), (1, 200)]
        .iter()
        .map(|&(core, dmips)| CpuRaw { core, dmips, ..CpuRaw::UNKNOWN })
        .collect();
    install(&build(&r, Source::Dt));
    assert_eq!(installed(), 4);
    assert_eq!(source(), Source::Dt);
    assert!(capacity_known() && !irregular());
    assert_eq!((mask(Level::Smt, 0), mask(Level::Smt, 3)), (0b0011, 0b1100));
    assert_eq!((capacity(0), capacity(2)), (512, 1024));
    assert_eq!(mask(Level::Package, 9), 0, "a CPU it does not describe");
    assert_eq!(summary(Level::Smt), (2, 2, 2));
    assert_eq!(summary(Level::Package), (1, 4, 4));
}

// ── CPUID ────────────────────────────────────────────────────────────────────

type Leaf = (u32, u32, u32, u32);

/// A fake CPU answering `cpuid(leaf, sub)`.
struct Cpu {
    vendor: (u32, u32, u32), // EBX, EDX, ECX
    max_basic: u32,
    max_ext: u32,
    /// (leaf, sub) -> registers; anything else is zero.
    leaves: Vec<((u32, u32), Leaf)>,
}

const INTEL: (u32, u32, u32) = (0x756e_6547, 0x4965_6e69, 0x6c65_746e);
const AMD: (u32, u32, u32) = (0x6874_7541, 0x6974_6e65, 0x444d_4163);

impl Cpu {
    fn new(vendor: (u32, u32, u32), max_basic: u32, max_ext: u32) -> Self {
        Cpu { vendor, max_basic, max_ext, leaves: Vec::new() }
    }
    fn with(mut self, leaf: u32, sub: u32, regs: Leaf) -> Self {
        self.leaves.push(((leaf, sub), regs));
        self
    }
    /// Level `sub` of an extended-topology `leaf`: `kind`, `shift`, and a
    /// non-zero count of logical processors at the level.
    fn level(self, leaf: u32, sub: u32, kind: u32, shift: u32) -> Self {
        self.with(leaf, sub, (shift, 1 << shift.max(1), (kind << 8) | sub, 0))
    }
    /// Cache `sub` of a cache `leaf`: `kind` (1 data, 2 instr, 3 unified),
    /// `level`, and the logical processors sharing it.
    fn cache(self, leaf: u32, sub: u32, kind: u32, level: u32, sharing: u32) -> Self {
        self.with(leaf, sub, (kind | (level << 5) | ((sharing - 1) << 14), 0, 0, 0))
    }
    fn read(&self, leaf: u32, sub: u32) -> Leaf {
        if leaf == 0 {
            return (self.max_basic, self.vendor.0, self.vendor.2, self.vendor.1);
        }
        if leaf == 0x8000_0000 {
            return (self.max_ext, 0, 0, 0);
        }
        self.leaves.iter().find(|(k, _)| *k == (leaf, sub)).map_or((0, 0, 0, 0), |(_, v)| *v)
    }
    fn shape(&self) -> CpuidShape {
        cpuid_shape(|l, s| self.read(l, s))
    }
}

/// Topology of `n` CPUs whose APIC ids are `0..n`.
fn from_apic(shape: &CpuidShape, n: u32) -> Topology {
    let r: Vec<CpuRaw> = (0..n).map(|a| shape.ids(a, 0)).collect();
    build(&r, Source::Cpuid)
}

#[test]
fn intel_leaf_1f_gives_cores_modules_and_the_llc() {
    // 2 threads per core (shift 1), 2 cores per module (shift 2), 8 modules
    // per die (shift 5); L2 shared by a module, L3 by 16 logical processors.
    let c = Cpu::new(INTEL, 0x1f, 0x8000_0008)
        .level(0x1f, 0, 1, 1)
        .level(0x1f, 1, 2, 2)
        .level(0x1f, 2, 3, 5)
        .cache(4, 0, 1, 1, 2)
        .cache(4, 1, 2, 1, 2)
        .cache(4, 2, 3, 2, 4)
        .cache(4, 3, 3, 3, 16);
    let s = c.shape();
    assert_eq!(s.llc_sharing, 16, "L3 is the last level; the instruction cache is not counted");
    let t = from_apic(&s, 16);
    assert_eq!(masks(&t, Level::Smt, 16)[..4], [0x3, 0x3, 0xc, 0xc]);
    assert_eq!(masks(&t, Level::Cluster, 16)[..5], [0xf, 0xf, 0xf, 0xf, 0xf0]);
    assert_eq!(masks(&t, Level::Llc, 16), [0xffff; 16]);
    assert_eq!(masks(&t, Level::Package, 16), [0xffff; 16]);
    assert_eq!(summary_of(&t, Level::Cluster, 16), (4, 4, 4));
}

#[test]
fn leaf_1f_wins_over_0b_and_a_silent_1f_falls_back_to_0b() {
    // 0x1F present: its module level exists, 0xB's does not.
    let both = Cpu::new(INTEL, 0x1f, 0x8000_0008)
        .level(0x1f, 0, 1, 1)
        .level(0x1f, 1, 2, 2)
        .level(0x1f, 2, 3, 4)
        .level(0xb, 0, 1, 1)
        .level(0xb, 1, 2, 4);
    assert_ne!(both.shape().ids(5, 0).cluster, NONE, "module level read from 0x1F");
    // 0x1F's first level reports no processors: it is not there; 0xB is used.
    let silent = Cpu::new(INTEL, 0x1f, 0x8000_0008)
        .with(0x1f, 0, (0, 0, 0, 0))
        .level(0xb, 0, 1, 1)
        .level(0xb, 1, 2, 4);
    let ids = silent.shape().ids(5, 0);
    assert_eq!((ids.core, ids.cluster, ids.package), (2, NONE, 0));
}

#[test]
fn intel_die_level_is_the_node() {
    // smt 1, core 3 (dies of 8 threads), die 4, die group 6 (packages of 64).
    let c = Cpu::new(INTEL, 0x1f, 0x8000_0008)
        .level(0x1f, 0, 1, 1)
        .level(0x1f, 1, 2, 3)
        .level(0x1f, 2, 5, 4)
        .level(0x1f, 3, 6, 6);
    let t = from_apic(&c.shape(), 32);
    assert_eq!(t.mask(Level::Node, 0), 0xff);
    assert_eq!(t.mask(Level::Node, 8), 0xff00);
    assert_eq!(t.mask(Level::Package, 0), 0xffff_ffff);
}

#[test]
fn amd_zen_ccx_comes_from_the_l3_sharing_count() {
    // 32 threads in a package (core shift 5), SMT 2; L3 shared by 16 threads
    // (8 cores x 2): two core complexes. One node.
    let c = Cpu::new(AMD, 0x10, 0x8000_0020)
        .level(0xb, 0, 1, 1)
        .level(0xb, 1, 2, 5)
        .cache(0x8000_001d, 0, 1, 1, 2)
        .cache(0x8000_001d, 1, 2, 1, 2)
        .cache(0x8000_001d, 2, 3, 2, 2)
        .cache(0x8000_001d, 3, 3, 3, 16)
        .with(0x8000_001e, 0, (0, 0x100, 0, 0)); // 2 threads per core, 1 node
    let s = c.shape();
    assert_eq!(s.nodes_per_package, 1);
    let t = from_apic(&s, 32);
    assert_eq!(summary_of(&t, Level::Smt, 32), (16, 2, 2));
    assert_eq!(summary_of(&t, Level::Llc, 32), (2, 16, 16));
    assert_eq!(summary_of(&t, Level::Package, 32), (1, 32, 32));
    assert_eq!(summary_of(&t, Level::Cluster, 32), (16, 2, 2), "no module level: the core");
    assert_eq!(t.mask(Level::Node, 0), 0xffff_ffff, "one node: the package");
}

#[test]
fn amd_nodes_per_package_split_the_package() {
    // As above with two nodes per package (NPS2): the top bit of the
    // package-local id picks the node. A second socket follows at APIC 32.
    let c = Cpu::new(AMD, 0x10, 0x8000_0020)
        .level(0xb, 0, 1, 1)
        .level(0xb, 1, 2, 5)
        .cache(0x8000_001d, 0, 3, 3, 16)
        .with(0x8000_001e, 0, (0, 0x100, 1 << 8, 0)); // ECX[10:8] = 1: 2 nodes
    let s = c.shape();
    assert_eq!(s.nodes_per_package, 2);
    let t = from_apic(&s, 64);
    assert_eq!(t.mask(Level::Node, 0), 0xffff);
    assert_eq!(t.mask(Level::Node, 16), 0xffff_0000);
    assert_eq!(t.mask(Level::Node, 32), 0xffff_0000_0000);
    assert_eq!(t.mask(Level::Package, 0), 0xffff_ffff);
    assert_eq!(t.mask(Level::Package, 63), 0xffff_ffff_0000_0000);
}

#[test]
fn amd_without_an_extended_leaf_takes_smt_from_the_threads_per_core() {
    let c = Cpu::new(AMD, 0x6, 0x8000_0020).with(0x8000_001e, 0, (0, 0x100, 0, 0));
    let s = c.shape();
    let t = from_apic(&s, 4);
    assert_eq!(masks(&t, Level::Smt, 4), [0x3, 0x3, 0xc, 0xc]);
    // No level says where the package ends: one package.
    assert_eq!(masks(&t, Level::Package, 4), [0xf; 4]);
}

#[test]
fn a_cpu_that_reports_nothing_is_unknown() {
    let s = Cpu::new(INTEL, 0x2, 0x8000_0000).shape();
    assert_eq!(s, CpuidShape::NONE);
    let ids = s.ids(3, 0);
    assert_eq!((ids.core, ids.cluster, ids.llc, ids.node, ids.package), (3, NONE, NONE, NONE, NONE));
}

#[test]
fn an_instruction_cache_is_never_the_llc() {
    let c = Cpu::new(INTEL, 0x4, 0x8000_0000)
        .cache(4, 0, 3, 2, 4)
        .cache(4, 1, 2, 3, 64); // a level-3 instruction cache: skipped
    assert_eq!(c.shape().llc_sharing, 4);
}

// ── PPTT ─────────────────────────────────────────────────────────────────────

/// A synthetic PPTT: nodes are appended, and each call returns the table
/// offset the next one names as its parent or next level.
struct Pptt {
    b: Vec<u8>,
}

const PKG: u32 = 1;
const UID: u32 = 2;
const THREAD: u32 = 4;
const LEAF: u32 = 8;

impl Pptt {
    fn new() -> Self {
        let mut b = vec![0u8; 36];
        b[0..4].copy_from_slice(b"PPTT");
        Pptt { b }
    }
    /// A processor hierarchy node.
    fn node(&mut self, flags: u32, parent: u32, uid: u32, resources: &[u32]) -> u32 {
        let off = self.b.len() as u32;
        let len = 20 + 4 * resources.len();
        self.b.extend_from_slice(&[0, len as u8, 0, 0]);
        for v in [flags, parent, uid, resources.len() as u32] {
            self.b.extend_from_slice(&v.to_le_bytes());
        }
        for r in resources {
            self.b.extend_from_slice(&r.to_le_bytes());
        }
        off
    }
    /// A cache: `next` is the offset of the next level, 0 for none;
    /// `attrs` is the cache type (0 data, 1 instruction, 2 unified) << 2.
    fn cache(&mut self, next: u32, attrs: u8) -> u32 {
        let off = self.b.len() as u32;
        self.b.extend_from_slice(&[1, 24, 0, 0]);
        for v in [0x7fu32, next, 32 << 10, 64] {
            self.b.extend_from_slice(&v.to_le_bytes());
        }
        self.b.extend_from_slice(&[8, attrs, 64, 0]);
        off
    }
    fn table(&self) -> Vec<u8> {
        let mut b = self.b.clone();
        let len = b.len() as u32;
        b[4..8].copy_from_slice(&len.to_le_bytes());
        b
    }
}

fn parse(t: &[u8]) -> acpi::Pptt {
    let mut out = acpi::Pptt::EMPTY;
    acpi::parse_pptt(t, &mut out);
    out
}

fn raw_of(p: &acpi::Pptt) -> Vec<CpuRaw> {
    p.cpus()
        .iter()
        .map(|c| CpuRaw { core: c.core, cluster: c.cluster, llc: c.llc, node: NONE, package: c.package, dmips: 0 })
        .collect()
}

const UNIFIED: u8 = 2 << 2;
const DATA: u8 = 0;
const INSTR: u8 = 1 << 2;

/// Arm-like: a package with an L3, two clusters with an L2 each, two cores a
/// cluster with a private L1 pair.
fn arm_table() -> (Vec<u8>, [u32; 3]) {
    let mut p = Pptt::new();
    let l3 = p.cache(0, UNIFIED);
    let l2a = p.cache(l3, UNIFIED);
    let l2b = p.cache(l3, UNIFIED);
    let pkg = p.node(PKG, 0, 0, &[l3]);
    let ca = p.node(0, pkg, 0, &[l2a]);
    let cb = p.node(0, pkg, 0, &[l2b]);
    for (uid, parent, l2) in [(0, ca, l2a), (1, ca, l2a), (2, cb, l2b), (3, cb, l2b)] {
        let l1d = p.cache(l2, DATA);
        let l1i = p.cache(l2, INSTR);
        p.node(UID | LEAF, parent, uid, &[l1d, l1i]);
    }
    (p.table(), [pkg, ca, cb])
}

#[test]
fn pptt_labels_are_table_offsets_of_the_grouping_nodes() {
    assert_eq!(acpi::PPTT_NONE, NONE, "one value for 'not stated' on both sides");
    let (t, [pkg, ca, cb]) = arm_table();
    let p = parse(&t);
    assert_eq!(p.cpus().len(), 4);
    assert_eq!((p.malformed, p.cpus_skipped), (0, 0));
    let c: Vec<_> = p.cpus().iter().map(|c| (c.uid, c.cluster, c.package)).collect();
    assert_eq!(c, [(0, ca, pkg), (1, ca, pkg), (2, cb, pkg), (3, cb, pkg)]);
    // Every core is its own leaf; all four reach the L3 at the end of the chain.
    let cores: Vec<_> = p.cpus().iter().map(|c| c.core).collect();
    assert!(cores.windows(2).all(|w| w[0] != w[1]));
    assert!(p.cpus().iter().all(|c| c.llc == p.cpus()[0].llc && c.llc != NONE));
    assert_eq!(p.for_uid(2).map(|c| c.cluster), Some(cb));
    assert!(p.for_uid(9).is_none());
}

#[test]
fn pptt_builds_the_levels() {
    let (t, _) = arm_table();
    let topo = build(&raw_of(&parse(&t)), Source::Pptt);
    assert_eq!(masks(&topo, Level::Smt, 4), [1, 2, 4, 8]);
    assert_eq!(masks(&topo, Level::Cluster, 4), [0x3, 0x3, 0xc, 0xc]);
    assert_eq!(masks(&topo, Level::Llc, 4), [0xf; 4]);
    assert_eq!(masks(&topo, Level::Package, 4), [0xf; 4]);
    assert!(!topo.irregular);
}

#[test]
fn pptt_without_a_package_cache_ends_the_chain_at_the_cluster() {
    // The L2s are the last level: the package node has no cache at all.
    let mut p = Pptt::new();
    let l2a = p.cache(0, UNIFIED);
    let l2b = p.cache(0, UNIFIED);
    let pkg = p.node(PKG, 0, 0, &[]);
    let ca = p.node(0, pkg, 0, &[l2a]);
    let cb = p.node(0, pkg, 0, &[l2b]);
    for (uid, parent) in [(0, ca), (1, ca), (2, cb), (3, cb)] {
        p.node(UID | LEAF, parent, uid, &[]);
    }
    let topo = build(&raw_of(&parse(&p.table())), Source::Pptt);
    assert_eq!(masks(&topo, Level::Llc, 4), [0x3, 0x3, 0xc, 0xc]);
    assert_eq!(masks(&topo, Level::Package, 4), [0xf; 4]);
}

#[test]
fn pptt_the_outermost_cache_is_the_last_level_even_when_not_linked() {
    // The core's own chain ends at its L2; the package lists an L3 that no
    // next-level pointer reaches. The L3 is the last level.
    let mut p = Pptt::new();
    let l3 = p.cache(0, UNIFIED);
    let l2 = p.cache(0, UNIFIED);
    let l1 = p.cache(l2, DATA);
    let pkg = p.node(PKG, 0, 0, &[l3]);
    p.node(UID | LEAF, pkg, 0, &[l1]);
    assert_eq!(parse(&p.table()).cpus()[0].llc, l3);
}

#[test]
fn pptt_threads_share_the_core_node_and_a_flat_package_has_no_cluster() {
    // x86-like: package -> core -> two threads; the core's parent is the
    // package, so there is no cluster.
    let mut p = Pptt::new();
    let pkg = p.node(PKG, 0, 0, &[]);
    let c0 = p.node(0, pkg, 0, &[]);
    let c1 = p.node(0, pkg, 0, &[]);
    for (uid, parent) in [(0, c0), (1, c0), (2, c1), (3, c1)] {
        p.node(UID | THREAD | LEAF, parent, uid, &[]);
    }
    let pt = parse(&p.table());
    assert_eq!(pt.cpus().iter().map(|c| c.core).collect::<Vec<_>>(), [c0, c0, c1, c1]);
    assert!(pt.cpus().iter().all(|c| c.cluster == NONE && c.package == pkg));
    let topo = build(&raw_of(&pt), Source::Pptt);
    assert_eq!(masks(&topo, Level::Smt, 4), [0x3, 0x3, 0xc, 0xc]);
    assert_eq!(masks(&topo, Level::Cluster, 4), [0x3, 0x3, 0xc, 0xc], "no cluster: the core");
}

#[test]
fn pptt_nested_clusters_give_the_innermost_and_two_packages_stay_apart() {
    let mut p = Pptt::new();
    let mut leaves = Vec::new();
    for pkg_n in 0..2u32 {
        let pkg = p.node(PKG, 0, 0, &[]);
        let outer = p.node(0, pkg, 0, &[]);
        let inner = p.node(0, outer, 0, &[]);
        leaves.push((2 * pkg_n, inner, pkg));
        leaves.push((2 * pkg_n + 1, inner, pkg));
        for uid in [2 * pkg_n, 2 * pkg_n + 1] {
            p.node(UID | LEAF, inner, uid, &[]);
        }
    }
    let pt = parse(&p.table());
    for (cpu, (_, inner, pkg)) in pt.cpus().iter().zip(&leaves) {
        assert_eq!((cpu.cluster, cpu.package), (*inner, *pkg));
    }
    let topo = build(&raw_of(&pt), Source::Pptt);
    assert_eq!(masks(&topo, Level::Package, 4), [0x3, 0x3, 0xc, 0xc]);
}

#[test]
fn pptt_nodes_without_a_valid_uid_or_with_children_are_not_processors() {
    let mut p = Pptt::new();
    let pkg = p.node(PKG | UID, 0, 99, &[]); // has a uid, but it is a parent
    let core = p.node(UID | LEAF, pkg, 1, &[]);
    let _ = core;
    p.node(LEAF, pkg, 2, &[]); // no "uid valid" flag
    let pt = parse(&p.table());
    assert_eq!(pt.cpus().iter().map(|c| c.uid).collect::<Vec<_>>(), [1]);
}

#[test]
fn pptt_malformed_structures_are_counted_not_trusted() {
    let (mut t, _) = arm_table();
    // A node that claims more private resources than its length holds.
    let mut p = Pptt::new();
    p.node(UID | LEAF, 0, 1, &[]);
    let mut bad = p.table();
    bad[36 + 16] = 200; // number of private resources
    let pt = parse(&bad);
    assert_eq!((pt.cpus().len(), pt.malformed), (0, 1));
    // A truncated table: the last structure runs past the end.
    t.truncate(t.len() - 5);
    let pt = parse(&t);
    assert_eq!(pt.cpus().len(), 3);
    assert_eq!(pt.malformed, 1);
    // A parent loop must terminate: A -> B -> A, and a processor under A.
    let mut p = Pptt::new();
    let (a, b) = (36u32, 36 + 20);
    assert_eq!(p.node(0, b, 0, &[]), a);
    assert_eq!(p.node(0, a, 0, &[]), b);
    p.node(UID | LEAF, a, 5, &[]);
    let pt = parse(&p.table());
    assert_eq!(pt.cpus().iter().map(|c| (c.uid, c.package, c.llc)).collect::<Vec<_>>(), [(5, NONE, NONE)]);
}

#[test]
fn pptt_cache_chains_are_followed_to_the_end_and_a_loop_stops() {
    let mut p = Pptt::new();
    let l3 = p.cache(0, UNIFIED);
    let l2 = p.cache(l3, UNIFIED);
    let l1 = p.cache(l2, DATA);
    p.node(UID | LEAF, 0, 7, &[l1]);
    let pt = parse(&p.table());
    assert_eq!(pt.cpus()[0].llc, l3);
    // Two caches naming each other: bounded.
    let mut p = Pptt::new();
    let a = p.b.len() as u32;
    let b = a + 24;
    assert_eq!(p.cache(b, UNIFIED), a);
    assert_eq!(p.cache(a, UNIFIED), b);
    p.node(UID | LEAF, 0, 8, &[a]);
    let pt = parse(&p.table());
    assert_eq!(pt.cpus().len(), 1, "terminates");
}

#[test]
fn pptt_processors_past_the_table_capacity_are_counted() {
    let mut p = Pptt::new();
    for uid in 0..(acpi::MAX_PPTT_CPUS as u32 + 3) {
        p.node(UID | LEAF, 0, uid, &[]);
    }
    let pt = parse(&p.table());
    assert_eq!((pt.cpus().len(), pt.cpus_skipped), (acpi::MAX_PPTT_CPUS, 3));
}
