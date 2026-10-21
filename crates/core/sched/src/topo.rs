// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CPU topology: which CPUs share a core, a cluster, a last-level cache, a
//! node and a package, and how much work each CPU can do (pure, host-tested).
//!
//! The balancer, energy-aware placement and core scheduling all ask the same
//! question ("who is near this CPU?"), so it is answered once, here, at boot,
//! from whatever the firmware describes:
//!
//! * device tree (riscv64, aarch64): `/cpus/cpu-map` (socket, cluster, core,
//!   thread) and `capacity-dmips-mhz`, read by `azos_dtb::dtb_cpu_topology`;
//! * ACPI (x86_64, and aarch64 once it boots from ACPI): the PPTT, read by
//!   `azos_arch_x86_64::firmware::acpi::parse_pptt`;
//! * CPUID (x86_64 without a PPTT): the extended-topology leaves 0x1F / 0xB,
//!   the cache leaves 4 / 0x8000001D, and AMD's 0x8000001E, decoded by
//!   [`CpuidShape`].
//!
//! Each source reduces to one [`CpuRaw`] per CPU: opaque labels, equal when
//! two CPUs share that level, [`NONE`] when the source does not say. [`build`]
//! turns the labels into masks with one rule for every source, and fixes the
//! defaults for what a source leaves out.
//!
//! # Levels
//!
//! Innermost first, each a superset of the one before ([`Level`]):
//!
//! | level | CPUs that ... | when the source is silent |
//! |---|---|---|
//! | `Smt` | are hardware threads of one core | the CPU alone |
//! | `Cluster` | share a cluster / module / tile | the core (the level collapses) |
//! | `Llc` | share the last-level cache | the node |
//! | `Node` | share a memory node (die, NUMA node) | the package |
//! | `Package` | sit in one socket | every CPU (one package) |
//!
//! "Silent" means the whole source: a CPU whose label is [`NONE`] while its
//! siblings have one is its own group at the levels with no default above,
//! never merged with the labelled ones. Every level is a partition of the
//! CPUs (a mask is the class of each CPU in it). Where a firmware describes
//! levels that do not nest, the groups are merged until they do and
//! [`Topology::irregular`] says so, which the boot prints.
//!
//! # Capacity
//!
//! `capacity-dmips-mhz` is a CPU's performance per MHz, so it is the
//! microarchitectural part of capacity only (the frequency part is the energy
//! model's). It is normalised so the largest CPU is [`CAPACITY_SCALE`] (1024,
//! Linux's `SCHED_CAPACITY_SCALE`). Unless EVERY CPU states it, all CPUs are
//! 1024 (the same rule `azos_energy::dt` applies): half a table says nothing
//! about the other half. PPTT and CPUID carry no capacity.
//!
//! # Storage
//!
//! [`install`] publishes a [`Topology`] in atomics (no lock, no `unsafe`) for
//! the other harts; [`mask`] and [`capacity`] read it. CPU ids are the kernel's
//! (hart id on riscv64, logical id on aarch64 and x86_64), at most
//! [`MAX_CPUS`]: masks are one `u64`, as the Kconfig `NR_CPUS` range ends at
//! 64 and `hart_set` already assumes.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// CPUs a [`Topology`] holds: the Kconfig `NR_CPUS` ceiling (range 1..64).
pub const MAX_CPUS: usize = 64;

/// A set of CPUs: bit `n` is CPU `n`.
pub type Mask = u64;

/// A label a source does not give.
pub const NONE: u32 = u32::MAX;

/// Capacity of the largest CPU (Linux `SCHED_CAPACITY_SCALE`).
pub const CAPACITY_SCALE: u16 = 1024;

/// How far two CPUs are, innermost first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Smt = 0,
    Cluster = 1,
    Llc = 2,
    Node = 3,
    Package = 4,
}

/// Levels in a [`Topology`].
pub const LEVELS: usize = 5;

impl Level {
    /// Innermost first.
    pub const ALL: [Level; LEVELS] = [Level::Smt, Level::Cluster, Level::Llc, Level::Node, Level::Package];

    pub const fn name(self) -> &'static str {
        match self {
            Level::Smt => "smt",
            Level::Cluster => "cluster",
            Level::Llc => "llc",
            Level::Node => "node",
            Level::Package => "package",
        }
    }
}

/// Where the labels came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Source {
    /// No firmware description: every CPU alone at the inner levels, one
    /// package.
    None = 0,
    /// The device tree: `/cpus/cpu-map` and `capacity-dmips-mhz`.
    Dt = 1,
    /// ACPI PPTT.
    Pptt = 2,
    /// CPUID leaves.
    Cpuid = 3,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Source::None => "no firmware description",
            Source::Dt => "device tree",
            Source::Pptt => "ACPI PPTT",
            Source::Cpuid => "CPUID",
        }
    }
}

/// What a source says about one CPU. Labels are compared for equality only;
/// a label means the same thing for every CPU of one source and nothing across
/// sources. [`NONE`] / 0 when unsaid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuRaw {
    /// The core: CPUs with the same label are its hardware threads.
    pub core: u32,
    /// The cluster / module / tile that holds the core.
    pub cluster: u32,
    /// The last-level cache.
    pub llc: u32,
    /// The memory node (die, NUMA node).
    pub node: u32,
    /// The socket.
    pub package: u32,
    /// `capacity-dmips-mhz`, 0 if absent.
    pub dmips: u32,
}

impl CpuRaw {
    /// A CPU the source says nothing about.
    pub const UNKNOWN: CpuRaw = CpuRaw { core: NONE, cluster: NONE, llc: NONE, node: NONE, package: NONE, dmips: 0 };
}

/// The masks of every CPU at every level, and their capacities.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Topology {
    n: usize,
    masks: [[Mask; MAX_CPUS]; LEVELS],
    caps: [u16; MAX_CPUS],
    /// Where the labels came from.
    pub source: Source,
    /// Every CPU stated a `capacity-dmips-mhz`; otherwise all are
    /// [`CAPACITY_SCALE`].
    pub capacity_known: bool,
    /// The source's levels did not nest, or did not partition the CPUs, and
    /// groups were merged until they did.
    pub irregular: bool,
}

#[inline]
fn bit(cpu: usize) -> Mask {
    1u64 << cpu
}

/// Equal and stated.
#[inline]
fn same(a: u32, b: u32) -> bool {
    a != NONE && a == b
}

/// Masks of `n` CPUs by label equality: CPU `i` joins `j` when `eq(i, j)`.
fn group(n: usize, eq: impl Fn(usize, usize) -> bool) -> [Mask; MAX_CPUS] {
    let mut out = [0; MAX_CPUS];
    for i in 0..n {
        out[i] = bit(i);
        for j in 0..n {
            if eq(i, j) {
                out[i] |= bit(j);
            }
        }
    }
    out
}

/// Make `m[..n]` a partition: if CPU `j` is in the mask of CPU `i`, so is
/// everything in `j`'s mask and `i` is in `j`'s, until nothing changes.
fn partition(m: &mut [Mask; MAX_CPUS], n: usize) {
    loop {
        let mut changed = false;
        for i in 0..n {
            let mut new = m[i] | bit(i);
            for j in 0..n {
                if m[i] & bit(j) != 0 {
                    new |= m[j];
                }
                if m[j] & bit(i) != 0 {
                    new |= bit(j);
                }
            }
            if new != m[i] {
                m[i] = new;
                changed = true;
            }
        }
        if !changed {
            return;
        }
    }
}

/// Build the masks of `raw` (CPU `i` is `raw[i]`; entries past [`MAX_CPUS`] are
/// ignored).
pub fn build(raw: &[CpuRaw], source: Source) -> Topology {
    let n = raw.len().min(MAX_CPUS);
    let r = &raw[..n];
    let mut m = [[0; MAX_CPUS]; LEVELS];

    // A source with no socket at all describes one package.
    let no_package = r.iter().all(|c| c.package == NONE);
    m[Level::Smt as usize] = group(n, |i, j| same(r[i].core, r[j].core));
    m[Level::Package as usize] = group(n, |i, j| no_package || same(r[i].package, r[j].package));
    // The levels in between fall back on a neighbour when a CPU's label is not
    // stated: node on the package, LLC on the node, cluster on the core.
    let pkg = m[Level::Package as usize];
    m[Level::Node as usize] = {
        let g = group(n, |i, j| same(r[i].node, r[j].node));
        let mut o = [0; MAX_CPUS];
        for i in 0..n {
            o[i] = if r[i].node == NONE { pkg[i] } else { g[i] };
        }
        o
    };
    let node = m[Level::Node as usize];
    m[Level::Llc as usize] = {
        let g = group(n, |i, j| same(r[i].llc, r[j].llc));
        let mut o = [0; MAX_CPUS];
        for i in 0..n {
            o[i] = if r[i].llc == NONE { node[i] } else { g[i] };
        }
        o
    };
    let smt = m[Level::Smt as usize];
    m[Level::Cluster as usize] = {
        let g = group(n, |i, j| same(r[i].cluster, r[j].cluster));
        let mut o = [0; MAX_CPUS];
        for i in 0..n {
            o[i] = if r[i].cluster == NONE { smt[i] } else { g[i] };
        }
        o
    };

    // Nest: each level contains the one inside it, and is a partition of the
    // CPUs (the balancer treats a mask as the class of every CPU in it). A
    // firmware whose levels do not nest, or leave a CPU out of a group it is
    // in the mask of, is merged until they do.
    let mut irregular = false;
    for l in 0..LEVELS {
        let before = m[l];
        if l > 0 {
            for i in 0..n {
                m[l][i] |= m[l - 1][i];
            }
        }
        partition(&mut m[l], n);
        irregular |= m[l] != before;
    }

    let capacity_known = n != 0 && r.iter().all(|c| c.dmips != 0);
    let mut caps = [CAPACITY_SCALE; MAX_CPUS];
    if capacity_known {
        let max = r.iter().map(|c| c.dmips).max().unwrap_or(1) as u64;
        for i in 0..n {
            caps[i] = ((r[i].dmips as u64 * CAPACITY_SCALE as u64) / max).max(1) as u16;
        }
    }
    Topology { n, masks: m, caps, source, capacity_known, irregular }
}

impl Topology {
    /// The CPUs that share `level` with `cpu`, `cpu` included; 0 for a CPU
    /// not described.
    pub fn mask(&self, level: Level, cpu: usize) -> Mask {
        if cpu < self.n { self.masks[level as usize][cpu] } else { 0 }
    }

    /// `cpu`'s capacity, [`CAPACITY_SCALE`] for the largest.
    pub fn capacity(&self, cpu: usize) -> u16 {
        if cpu < self.n { self.caps[cpu] } else { CAPACITY_SCALE }
    }
}

/// `(groups, smallest, largest)` of a level whose CPU `i` has mask `mask_of(i)`:
/// how many groups it has, and the fewest and most CPUs in one.
fn summarize(n: usize, mask_of: impl Fn(usize) -> Mask) -> (usize, u32, u32) {
    let (mut groups, mut lo, mut hi) = (0, u32::MAX, 0);
    for i in 0..n {
        let m = mask_of(i);
        // A group is counted once, at its lowest CPU.
        if m.trailing_zeros() as usize == i {
            let w = m.count_ones();
            groups += 1;
            lo = lo.min(w);
            hi = hi.max(w);
        }
    }
    (groups, if groups == 0 { 0 } else { lo }, hi)
}

// ── The installed topology ───────────────────────────────────────────────────

static N: AtomicUsize = AtomicUsize::new(0);
static MASKS: [AtomicU64; LEVELS * MAX_CPUS] = [const { AtomicU64::new(0) }; LEVELS * MAX_CPUS];
static CAPS: [AtomicU16; MAX_CPUS] = [const { AtomicU16::new(CAPACITY_SCALE) }; MAX_CPUS];
static SOURCE: AtomicU8 = AtomicU8::new(0);
static KNOWN: AtomicBool = AtomicBool::new(false);
static IRREGULAR: AtomicBool = AtomicBool::new(false);

/// Publish `t` for every hart. Boot hart, before the balancer starts.
pub fn install(t: &Topology) {
    for level in Level::ALL {
        for i in 0..t.n {
            MASKS[level as usize * MAX_CPUS + i].store(t.mask(level, i), Ordering::Relaxed);
        }
    }
    for i in 0..t.n {
        CAPS[i].store(t.capacity(i), Ordering::Relaxed);
    }
    SOURCE.store(t.source as u8, Ordering::Relaxed);
    KNOWN.store(t.capacity_known, Ordering::Relaxed);
    IRREGULAR.store(t.irregular, Ordering::Relaxed);
    // Last, and Release: a reader that sees `n` sees everything above.
    N.store(t.n, Ordering::Release);
}

/// CPUs the installed topology describes; 0 before [`install`].
pub fn installed() -> usize {
    N.load(Ordering::Acquire)
}

/// The installed mask of `cpu` at `level`; 0 before [`install`] or for a CPU
/// it does not describe.
pub fn mask(level: Level, cpu: usize) -> Mask {
    if cpu < installed() { MASKS[level as usize * MAX_CPUS + cpu].load(Ordering::Relaxed) } else { 0 }
}

/// The installed capacity of `cpu`; [`CAPACITY_SCALE`] before [`install`].
pub fn capacity(cpu: usize) -> u16 {
    if cpu < installed() { CAPS[cpu].load(Ordering::Relaxed) } else { CAPACITY_SCALE }
}

/// Where the installed labels came from.
pub fn source() -> Source {
    match SOURCE.load(Ordering::Relaxed) {
        1 => Source::Dt,
        2 => Source::Pptt,
        3 => Source::Cpuid,
        _ => Source::None,
    }
}

/// The installed topology's capacities came from the firmware.
pub fn capacity_known() -> bool {
    KNOWN.load(Ordering::Relaxed)
}

/// The installed levels did not nest ([`Topology::irregular`]).
pub fn irregular() -> bool {
    IRREGULAR.load(Ordering::Relaxed)
}

/// [`Topology::summary`] of the installed topology.
pub fn summary(level: Level) -> (usize, u32, u32) {
    summarize(installed(), |i| mask(level, i))
}

// ── Core scheduling (Kconfig SCHED_CORE) ─────────────────────────────────────
//
// SMT siblings share the core's caches and buffers, so a task that runs next
// to a task of another Domain can read what it leaves there. With SCHED_CORE
// the siblings of a core run tasks of one Domain at a time: each hart
// publishes a [`Claim`] (the cookie of the task it is committed to run, the
// Domain key; 0 for idle), and the pick of a hart admits a task only when
// every sibling's claim is compatible with it. A task that is refused is put
// back and the hart takes another, or idles (force idle).
//
// Real-time keeps priority. A refused strong claim (a band task or a
// reservation) displaces the siblings' non-strong claims at once; a refused
// fair one only after it has waited `patience` (so a Domain does not starve
// behind a busy sibling Domain, nor a sibling pair ping-pong). The
// displacement is a `want` on the core: while it lasts, only claims
// compatible with it run on the core, and the siblings holding others are
// told to yield ([`CoreSched::must_yield`]) by the caller's doorbell. A strong
// claim is never displaced.
//
// Every claim is changed under a per-core lock held for a few loads, with
// interrupts off, taking no other lock, so a pair of harts cannot both pass
// the check against each other's old claim.

const CLAIM_LIVE: u64 = 1 << 32;
const CLAIM_STRONG: u64 = 1 << 33;
const CLAIM_BITS: u64 = CLAIM_LIVE | CLAIM_STRONG | 0xffff_ffff;
const WANT_OWNER_SHIFT: u32 = 40;

/// What a hart is committed to run, as its SMT siblings see it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claim(u64);

impl Claim {
    /// Nothing, or the idle task: compatible with every claim.
    pub const IDLE: Claim = Claim(0);

    /// A task of Domain `cookie`; `strong`: band or reservation (never
    /// displaced by a fair task).
    pub const fn task(cookie: u32, strong: bool) -> Claim {
        Claim(CLAIM_LIVE | cookie as u64 | if strong { CLAIM_STRONG } else { 0 })
    }

    pub const fn is_idle(self) -> bool {
        self.0 & CLAIM_LIVE == 0
    }

    pub const fn is_strong(self) -> bool {
        self.0 & CLAIM_STRONG != 0
    }

    /// May the two run on siblings at the same time.
    pub const fn compatible(self, other: Claim) -> bool {
        self.is_idle() || other.is_idle() || self.0 as u32 == other.0 as u32
    }

    /// Same Domain, or both idle: the claim's strength aside.
    const fn same_cookie(self, other: Claim) -> bool {
        if self.is_idle() || other.is_idle() {
            self.is_idle() && other.is_idle()
        } else {
            self.0 as u32 == other.0 as u32
        }
    }
}

/// The answer to [`CoreSched::admit`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admit {
    /// The claim is the hart's now. `kick`: siblings that were refused and
    /// may fit now (the core's cookie changed): ring their doorbells.
    Run { kick: Mask },
    /// A sibling holds an incompatible claim (or the core is reserved for
    /// another): the claim is not the hart's. The hart idles, or keeps its
    /// running task if that is compatible. `kick`: siblings to ring so they
    /// yield; `drain`: the refusal displaces them (the hart should not keep
    /// its own running task either, it holds the same cookie).
    Refuse { kick: Mask, drain: bool },
}

/// The claims of every hart and the per-core state. One static instance,
/// [`CORE`]; tests make their own.
pub struct CoreSched {
    /// Per hart: its claim.
    claim: [AtomicU64; MAX_CPUS],
    /// Per hart: when its candidate was first refused, 0 if it was not.
    since: [AtomicU64; MAX_CPUS],
    /// Per core (indexed by its lowest hart): the lock.
    lock: [AtomicBool; MAX_CPUS],
    /// Per core: harts whose candidate was refused and who idle for it.
    waiting: [AtomicU64; MAX_CPUS],
    /// Per core: the claim the core is reserved for and the hart that asked
    /// (`owner << WANT_OWNER_SHIFT`), 0 for none.
    want: [AtomicU64; MAX_CPUS],
    /// Per core: until when the reservation holds.
    want_until: [AtomicU64; MAX_CPUS],
}

/// The installed machine's claims.
pub static CORE: CoreSched = CoreSched::new();

impl CoreSched {
    pub const fn new() -> CoreSched {
        CoreSched {
            claim: [const { AtomicU64::new(0) }; MAX_CPUS],
            since: [const { AtomicU64::new(0) }; MAX_CPUS],
            lock: [const { AtomicBool::new(false) }; MAX_CPUS],
            waiting: [const { AtomicU64::new(0) }; MAX_CPUS],
            want: [const { AtomicU64::new(0) }; MAX_CPUS],
            want_until: [const { AtomicU64::new(0) }; MAX_CPUS],
        }
    }

    /// `cpu`'s claim.
    pub fn claim(&self, cpu: usize) -> Claim {
        Claim(self.claim[cpu].load(Ordering::Relaxed) & CLAIM_BITS)
    }

    fn core_of(smt: Mask) -> usize {
        smt.trailing_zeros() as usize
    }

    fn lock(&self, core: usize) {
        while self.lock[core].compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self, core: usize) {
        self.lock[core].store(false, Ordering::Release);
    }

    /// The reservation of `core` at `now`: `(claim, owner)`.
    fn live_want(&self, core: usize, now: u64) -> Option<(Claim, usize)> {
        let w = self.want[core].load(Ordering::Relaxed);
        if w == 0 || self.want_until[core].load(Ordering::Relaxed) <= now {
            return None;
        }
        Some((Claim(w & CLAIM_BITS), (w >> WANT_OWNER_SHIFT) as usize))
    }

    /// Try to make `cand` hart `cpu`'s claim. `smt` is `cpu`'s SMT mask
    /// ([`mask`] of [`Level::Smt`]); `now` a nonzero clock and `patience`
    /// how long a fair claim is refused before it displaces its siblings,
    /// in the same unit.
    pub fn admit(&self, smt: Mask, cpu: usize, cand: Claim, now: u64, patience: u64) -> Admit {
        let sibs = smt & !bit(cpu);
        let core = Self::core_of(smt | bit(cpu));
        self.lock(core);
        let want = self.live_want(core, now);
        let (mut conflicting, mut strong_held): (Mask, bool) = (0, false);
        let mut m = sibs;
        while m != 0 {
            let s = m.trailing_zeros() as usize;
            m &= m - 1;
            let c = self.claim(s);
            if !c.compatible(cand) {
                conflicting |= bit(s);
                strong_held |= c.is_strong();
            }
        }
        // A reservation by a fair claim yields to a strong candidate; one by a
        // strong claim holds against everything incompatible with it.
        let reserved = want.is_some_and(|(w, owner)| {
            owner != cpu && !w.compatible(cand) && !(cand.is_strong() && !w.is_strong())
        });
        let out = if cand.is_idle() || (conflicting == 0 && !reserved) {
            let old = self.claim(cpu);
            self.claim[cpu].store(cand.0, Ordering::Relaxed);
            // A hart that idles because its candidate was refused stays
            // waiting (and keeps its wait): the ring that ends it is the
            // siblings' next change of Domain.
            if !cand.is_idle() {
                self.since[cpu].store(0, Ordering::Relaxed);
                self.waiting[core].fetch_and(!bit(cpu), Ordering::Relaxed);
            }
            if let Some((w, owner)) = want {
                // The hart that reserved the core got what it asked for.
                if owner == cpu && !cand.is_idle() && w.compatible(cand) {
                    self.want[core].store(0, Ordering::Relaxed);
                }
            }
            let kick = if old.same_cookie(cand) { 0 } else { self.waiting[core].load(Ordering::Relaxed) & sibs };
            Admit::Run { kick }
        } else {
            self.waiting[core].fetch_or(bit(cpu), Ordering::Relaxed);
            let since = self.since[cpu].load(Ordering::Relaxed);
            let since = if since == 0 {
                self.since[cpu].store(now, Ordering::Relaxed);
                now
            } else {
                since
            };
            let insist = cand.is_strong() || now.saturating_sub(since) >= patience;
            // Displace only what is not strong, and not another hart's
            // standing reservation.
            let displaceable = !strong_held;
            let free = want.is_none_or(|(w, owner)| owner == cpu || (cand.is_strong() && !w.is_strong()));
            let drain = insist && displaceable && free;
            if drain {
                self.want[core].store(cand.0 | (cpu as u64) << WANT_OWNER_SHIFT, Ordering::Relaxed);
                self.want_until[core].store(now.saturating_add(patience.max(1)), Ordering::Relaxed);
            }
            Admit::Refuse { kick: if drain { conflicting } else { 0 }, drain }
        };
        self.unlock(core);
        out
    }

    /// Make `cand` hart `cpu`'s claim without asking: the first task of a hart
    /// (nothing to refuse it in favour of), or a hart with no idle task to fall
    /// back on. Returns the siblings to ring, as [`Admit::Run`].
    pub fn force(&self, smt: Mask, cpu: usize, cand: Claim) -> Mask {
        let core = Self::core_of(smt | bit(cpu));
        self.lock(core);
        let old = self.claim(cpu);
        self.claim[cpu].store(cand.0, Ordering::Relaxed);
        if !cand.is_idle() {
            self.since[cpu].store(0, Ordering::Relaxed);
            self.waiting[core].fetch_and(!bit(cpu), Ordering::Relaxed);
        }
        let kick = if old.same_cookie(cand) { 0 } else { self.waiting[core].load(Ordering::Relaxed) & smt & !bit(cpu) };
        self.unlock(core);
        kick
    }

    /// Does a sibling's reservation of the core displace what `cpu` runs
    /// now? The check is lock-free and may be a pick late: the reservation is
    /// held until its time runs out, and the pick that follows the doorbell
    /// asks again.
    pub fn must_yield(&self, smt: Mask, cpu: usize, now: u64) -> bool {
        let core = Self::core_of(smt | bit(cpu));
        match self.live_want(core, now) {
            Some((w, owner)) if owner != cpu => {
                let mine = self.claim(cpu);
                !mine.is_idle() && !mine.is_strong() && !mine.compatible(w)
            }
            _ => false,
        }
    }
}

/// What one pick on a core-scheduled hart needs to know. The queue and the
/// task table are the caller's, behind the closures of [`core_pick`].
#[derive(Clone, Copy, Debug)]
pub struct CorePick {
    /// The hart's SMT mask.
    pub smt: Mask,
    pub cpu: usize,
    /// A nonzero clock, and how long a fair claim waits before it displaces.
    pub now: u64,
    pub patience: u64,
    /// The task that ran here is still `Running`: it holds a claim that
    /// fits the siblings, and may keep the hart.
    pub old_runs: bool,
    /// ...and it is the idle task, which keeps the hart whatever was refused.
    pub old_idle: bool,
}

/// What [`core_pick`] decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CorePicked {
    /// `Some(task)`: switch to it (its claim is the hart's); `None`: the
    /// running task keeps the hart (its claim stands).
    pub run: Option<usize>,
    /// Candidates taken off the queue and not run: the caller puts every one
    /// back (`stash[..stashed]`).
    pub stashed: usize,
    /// Siblings to ring: they yield, or may fit now.
    pub kick: Mask,
}

/// Filter the pick `first` of a hart through its core.
///
/// `first` was taken off the queue. When its claim fits the siblings it runs.
/// When it does not, it goes to `stash` and `redraw` takes the next best off
/// the queue (`claim_of` gives a task's claim), up to `stash.len()` of them;
/// `worse(task)` says a redrawn task would not preempt the running one (the
/// scheduler's priority guard, for the candidate that was not the first).
/// With nothing that fits: the running task keeps the hart if it can (it
/// fits, and no sibling is being displaced for a refused candidate), else
/// the hart idles on `take_idle`'s task. `stash` holds at least 2.
pub fn core_pick(
    core: &CoreSched,
    c: &CorePick,
    first: usize,
    stash: &mut [usize],
    claim_of: impl Fn(usize) -> Claim,
    mut redraw: impl FnMut() -> Option<usize>,
    worse: impl Fn(usize) -> bool,
    take_idle: impl FnOnce() -> Option<usize>,
) -> CorePicked {
    let (mut cand, mut n, mut kick, mut drained) = (first, 0, 0, false);
    loop {
        match core.admit(c.smt, c.cpu, claim_of(cand), c.now, c.patience) {
            Admit::Run { kick: k } => return CorePicked { run: Some(cand), stashed: n, kick: kick | k },
            Admit::Refuse { kick: k, drain } => {
                kick |= k;
                drained |= drain;
            }
        }
        stash[n] = cand;
        n += 1;
        if n == stash.len() {
            break;
        }
        match redraw() {
            None => break,
            Some(next) => {
                if c.old_runs && worse(next) {
                    stash[n] = next;
                    n += 1;
                    break;
                }
                cand = next;
            }
        }
    }
    if c.old_runs && (c.old_idle || !drained) {
        return CorePicked { run: None, stashed: n, kick };
    }
    // The idle task may be the one `worse` stopped the scan at.
    let drawn = stash[..n].iter().position(|&t| claim_of(t).is_idle()).map(|k| {
        n -= 1;
        let t = stash[k];
        stash[k] = stash[n];
        t
    });
    match drawn.or_else(take_idle) {
        Some(idle) => {
            // An idle claim is always admitted.
            let (Admit::Run { kick: k } | Admit::Refuse { kick: k, .. }) =
                core.admit(c.smt, c.cpu, Claim::IDLE, c.now, c.patience);
            CorePicked { run: Some(idle), stashed: n, kick: kick | k }
        }
        None if c.old_runs => CorePicked { run: None, stashed: n, kick },
        None => {
            // The hart has nothing to run but what was refused: it is claimed
            // anyway (only a hart with no idle task gets here).
            let task = stash[0];
            n -= 1;
            stash[0] = stash[n];
            let k = core.force(c.smt, c.cpu, claim_of(task));
            CorePicked { run: Some(task), stashed: n, kick: kick | k }
        }
    }
}

// ── CPUID ────────────────────────────────────────────────────────────────────

/// Level types of leaf 0x1F / 0xB (`ECX[15:8]`), innermost first.
pub const CPUID_SMT: u8 = 1;
pub const CPUID_CORE: u8 = 2;
pub const CPUID_MODULE: u8 = 3;
pub const CPUID_TILE: u8 = 4;
pub const CPUID_DIE: u8 = 5;
pub const CPUID_DIEGRP: u8 = 6;

/// What CPUID says about the shape of the APIC id space. The same on every
/// CPU of a machine, so the boot CPU reads it once and applies it to the APIC
/// id the MADT gives each CPU (no CPU has to run the instruction itself).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuidShape {
    /// Per level type (index = type): bits to shift an APIC id right to get
    /// the id of the next level up (`EAX[4:0]` of the leaf's subleaf).
    shift: [u8; 7],
    /// Bit `t` set: level type `t` was reported.
    present: u8,
    /// Logical processors sharing the last-level cache (id-space size), 0 if
    /// unknown.
    pub llc_sharing: u32,
    /// Nodes per package (AMD leaf 0x8000001E), 1 when not reported.
    pub nodes_per_package: u8,
}

/// `ceil(log2(v))`; 0 for 0 and 1.
fn ceil_log2(v: u32) -> u8 {
    if v <= 1 { 0 } else { (32 - (v - 1).leading_zeros()) as u8 }
}

impl CpuidShape {
    /// Nothing reported.
    pub const NONE: CpuidShape = CpuidShape { shift: [0; 7], present: 0, llc_sharing: 0, nodes_per_package: 1 };

    /// Record level type `kind` with `shift`; types outside 1..=6 are ignored.
    pub fn set_level(&mut self, kind: u8, shift: u8) {
        if (1..=6).contains(&kind) {
            self.shift[kind as usize] = shift & 0x1f;
            self.present |= 1 << kind;
        }
    }

    fn has(&self, kind: u8) -> bool {
        self.present & (1 << kind) != 0
    }

    /// APIC id shifted right by level `kind`'s shift.
    fn above(&self, kind: u8, apic: u32) -> u32 {
        apic >> self.shift[kind as usize]
    }

    /// The outermost level reported above the SMT level: the SMT level alone
    /// says where a core ends, not where the package does.
    fn top(&self) -> Option<u8> {
        (2..=6u8).rev().find(|&k| self.has(k))
    }

    /// The labels of the CPU whose APIC id is `apic`.
    ///
    /// A level's shift gives the id of the group one level up, so: the core is
    /// `apic >> shift(SMT)` (the APIC id itself without SMT); the cluster is
    /// `apic >> shift(CORE)` when a module or tile level sits above the
    /// cores; the package is `apic >> shift(outermost level)`; the node is
    /// the die (`apic >> ` the shift of the level below DIE) on Intel, and on
    /// AMD the package's top `log2(nodes)` bits (the layout Linux assumes of
    /// leaf 0x8000001E); the LLC is `apic >> ceil(log2(sharing))`.
    pub fn ids(&self, apic: u32, dmips: u32) -> CpuRaw {
        let core = if self.has(CPUID_SMT) { self.above(CPUID_SMT, apic) } else { apic };
        let cluster =
            if self.has(CPUID_CORE) && (self.has(CPUID_MODULE) || self.has(CPUID_TILE)) {
                self.above(CPUID_CORE, apic)
            } else {
                NONE
            };
        let top = self.top();
        let package = top.map_or(NONE, |k| self.above(k, apic));
        let node = if self.has(CPUID_DIE) {
            [CPUID_TILE, CPUID_MODULE, CPUID_CORE]
                .into_iter()
                .find(|&k| self.has(k))
                .map_or(NONE, |k| self.above(k, apic))
        } else if self.nodes_per_package > 1 && top.is_some() {
            let pkg_shift = self.shift[top.unwrap_or(0) as usize];
            apic >> pkg_shift.saturating_sub(ceil_log2(self.nodes_per_package as u32))
        } else {
            NONE
        };
        let llc = if self.llc_sharing == 0 { NONE } else { apic >> ceil_log2(self.llc_sharing).min(31) };
        CpuRaw { core, cluster, llc, node, package, dmips }
    }
}

/// `CPUID` vendor string of AMD: `"AuthenticAMD"` as EBX, EDX, ECX.
const AMD_VENDOR: (u32, u32, u32) = (0x6874_7541, 0x6974_6e65, 0x444d_4163);

/// Read the shape through `cpuid(leaf, subleaf) -> (eax, ebx, ecx, edx)`:
/// leaf 0x1F when the CPU has it and reports a level, else 0xB; the last
/// level cache from leaf 4 (Intel) or 0x8000001D (AMD); on AMD, 0x8000001E for
/// the nodes per package and, when no extended-topology leaf names the SMT
/// level, the threads per core.
pub fn cpuid_shape(cpuid: impl Fn(u32, u32) -> (u32, u32, u32, u32)) -> CpuidShape {
    let mut s = CpuidShape::NONE;
    let (max_basic, vb, vc, vd) = cpuid(0, 0);
    let amd = (vb, vd, vc) == AMD_VENDOR;
    let max_ext = cpuid(0x8000_0000, 0).0;

    // Extended topology: a leaf whose subleaf 0 reports no level is absent.
    let leaf = [0x1Fu32, 0xB].into_iter().find(|&l| max_basic >= l && (cpuid(l, 0).1 & 0xffff) != 0);
    if let Some(l) = leaf {
        for sub in 0..8 {
            let (eax, _, ecx, _) = cpuid(l, sub);
            let kind = ((ecx >> 8) & 0xff) as u8;
            if kind == 0 {
                break;
            }
            s.set_level(kind, (eax & 0x1f) as u8);
        }
    }

    // Last-level cache: the highest data or unified level.
    let cache_leaf = if amd && max_ext >= 0x8000_001D {
        Some(0x8000_001Du32)
    } else if max_basic >= 4 {
        Some(4)
    } else {
        None
    };
    if let Some(l) = cache_leaf {
        let mut best_level = 0;
        for sub in 0..8 {
            let (eax, ..) = cpuid(l, sub);
            let (kind, level) = (eax & 0x1f, (eax >> 5) & 0x7);
            if kind == 0 {
                break;
            }
            // 1 data, 2 instruction, 3 unified.
            if kind != 2 && level > best_level {
                best_level = level;
                s.llc_sharing = ((eax >> 14) & 0xfff) + 1;
            }
        }
    }

    if amd && max_ext >= 0x8000_001E {
        let (_, ebx, ecx, _) = cpuid(0x8000_001E, 0);
        s.nodes_per_package = (((ecx >> 8) & 0x7) + 1) as u8;
        let threads = ((ebx >> 8) & 0xff) + 1;
        if !s.has(CPUID_SMT) && threads > 1 {
            s.set_level(CPUID_SMT, ceil_log2(threads));
        }
    }
    s
}
