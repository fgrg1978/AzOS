// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-CPU areas, CPU masks and `nr_cpu_ids`: the Linux model.
//!
//! | Linux                     | here                                   |
//! |---------------------------|----------------------------------------|
//! | `CONFIG_NR_CPUS`          | [`NR_CPUS`] (Kconfig `NR_CPUS`)         |
//! | `cpu_possible_mask`       | [`possible`], set once from the DTB     |
//! | `cpu_online_mask`         | [`online`], kept separate (hotplug-ready) |
//! | `nr_cpu_ids`              | [`nr_cpu_ids`] = last possible + 1      |
//! | `setup_per_cpu_areas()`   | [`area_bytes`] + [`attach_area`], called by the kernel for each possible CPU |
//! | `per_cpu_ptr(&v, cpu)`    | [`PerCpuRemote::ptr`]                   |
//!
//! **What is static and what is not.** [`NR_CPUS`] is a ceiling: it sizes the
//! masks (one bit per CPU) and each [`PerCpuRemote`] variable's pointer table (one
//! word per CPU). The per-CPU *state* is not sized by it: every variable
//! declared as a [`PerCpuRemote`] lives in the per-CPU areas, which the kernel
//! allocates at boot from the frame allocator for the CPUs the DTB names and
//! no others. A ceiling of 64 on a four-core board therefore costs 64 words
//! per variable, not 64 copies of the state.
//!
//! **How a CPU reaches its area.** The register that identifies the CPU
//! (`tp` on riscv64, `TPIDR_EL1` on aarch64) holds the CPU id, not a pointer,
//! and stays that way: `current_cpu_id()` reads it, `trap_entry.S` rebuilds
//! `tp` from it, and the context switch indexes `AZOS_HART_SATP` with it.
//! The id indexes each variable's pointer table instead — one load more than
//! a static array indexed by the same id, the same shape Linux uses on
//! riscv64 (`__per_cpu_offset[smp_processor_id()]`, which Linux reaches
//! through one more load than this, `thread_info->cpu`).
//!
//! **Out of range.** A CPU id at or above [`NR_CPUS`] panics on the table's
//! bounds check, as a static array did. A CPU id below it that has no area
//! (above `nr_cpu_ids`, or a hole in the possible mask) holds [`POISON`], a
//! non-canonical address on Sv39 and on aarch64, so a dereference faults at a
//! recognisable address instead of reading another CPU's state; [`PerCpuRemote::get`]
//! is the checked form that answers `None` and counts it ([`oor_count`]).
//!
//! **Scopes (owner decision 09-10, survey F6).** [`PerCpuRemote`] is the
//! storage: any CPU id reaches any CPU's instance, and what that access may
//! do is the user's contract. New code does not use it directly: the scope
//! types in `azos_sync::scope` wrap it — `PerCpu<T>` (this CPU only,
//! preemption off), `CpuOwned<T>` (a lock per CPU; another CPU's only from
//! task context) — and lockdep checks their rules. The variables still
//! declared as a bare [`PerCpuRemote`] are the ones whose access pattern is
//! none of those yet (each says which it wants).
//!
//! **Hotplug.** None yet. The possible mask is fixed at boot and areas are
//! never freed; the online mask is separate so that taking a CPU offline
//! later is a bit in [`online`] and nothing here moves.
#![no_std]

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The ceiling (Kconfig `NR_CPUS`): the largest CPU id plus one this build can
/// run. CPU id = hart id on riscv64, the boot-assigned logical id on aarch64.
pub const NR_CPUS: usize = azos_limits::NR_CPUS;
const _: () = assert!(NR_CPUS >= 1, "NR_CPUS must be at least 1");

/// Words in a [`CpuMask`].
pub const MASK_WORDS: usize = NR_CPUS.div_ceil(64);

/// The pointer a [`PerCpuRemote`] slot holds for a CPU without an area. Bits 63..39
/// are not a sign extension of bit 38 (Sv39) and bits 55..48 are not all
/// equal (aarch64, 48-bit or narrower VA, with or without top-byte-ignore), so
/// any access within 2^32 bytes of it is a translation fault on both ISAs.
pub const POISON: usize = 0xDEAD_C0DE_0000_0000;

/// Alignment of a per-CPU area, and the most a [`PerCpuRemote`] variable may ask
/// for. A page: areas come from the frame allocator.
pub const AREA_ALIGN: usize = 4096;

#[inline(always)]
const fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

// ── CPU masks ────────────────────────────────────────────────────────────────

/// A set of CPU ids below [`NR_CPUS`]: one bit each.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuMask([u64; MASK_WORDS]);

impl CpuMask {
    /// No CPU.
    pub const EMPTY: Self = Self([0; MASK_WORDS]);

    /// CPUs `0..n`, `n` cut to [`NR_CPUS`].
    pub const fn first_n(n: usize) -> Self {
        let n = if n > NR_CPUS { NR_CPUS } else { n };
        let mut w = [0u64; MASK_WORDS];
        let mut i = 0;
        while i < MASK_WORDS {
            let lo = i * 64;
            w[i] = if n >= lo + 64 {
                u64::MAX
            } else if n > lo {
                (1u64 << (n - lo)) - 1
            } else {
                0
            };
            i += 1;
        }
        Self(w)
    }

    /// Add `cpu`. `false`, and no change, when `cpu >= NR_CPUS`.
    pub fn set(&mut self, cpu: usize) -> bool {
        if cpu >= NR_CPUS {
            return false;
        }
        self.0[cpu / 64] |= 1 << (cpu % 64);
        true
    }

    /// Remove `cpu` (no-op past [`NR_CPUS`]).
    pub fn clear(&mut self, cpu: usize) {
        if cpu < NR_CPUS {
            self.0[cpu / 64] &= !(1 << (cpu % 64));
        }
    }

    /// Is `cpu` in the set? `false` past [`NR_CPUS`].
    #[inline]
    pub fn test(&self, cpu: usize) -> bool {
        cpu < NR_CPUS && self.0[cpu / 64] & (1 << (cpu % 64)) != 0
    }

    /// Number of CPUs in the set.
    pub fn weight(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Lowest CPU in the set.
    pub fn first(&self) -> Option<usize> {
        self.0
            .iter()
            .enumerate()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| i * 64 + w.trailing_zeros() as usize)
    }

    /// Highest CPU in the set.
    pub fn last(&self) -> Option<usize> {
        self.0
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| i * 64 + 63 - w.leading_zeros() as usize)
    }

    /// The CPUs in the set, ascending.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..NR_CPUS).filter(move |&c| self.test(c))
    }

    /// The raw words, lowest CPU first.
    pub fn words(&self) -> &[u64; MASK_WORDS] {
        &self.0
    }
}

/// A [`CpuMask`] several CPUs update at once.
pub struct AtomicCpuMask([AtomicU64; MASK_WORDS]);

impl AtomicCpuMask {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; MASK_WORDS])
    }

    /// Add `cpu`. `false` past [`NR_CPUS`].
    pub fn set(&self, cpu: usize) -> bool {
        if cpu >= NR_CPUS {
            return false;
        }
        self.0[cpu / 64].fetch_or(1 << (cpu % 64), Ordering::AcqRel);
        true
    }

    /// Remove `cpu`.
    pub fn clear(&self, cpu: usize) {
        if cpu < NR_CPUS {
            self.0[cpu / 64].fetch_and(!(1 << (cpu % 64)), Ordering::AcqRel);
        }
    }

    /// Is `cpu` in the set?
    #[inline]
    pub fn test(&self, cpu: usize) -> bool {
        cpu < NR_CPUS && self.0[cpu / 64].load(Ordering::Acquire) & (1 << (cpu % 64)) != 0
    }

    /// A snapshot (word by word: not atomic across words).
    pub fn load(&self) -> CpuMask {
        let mut m = CpuMask::EMPTY;
        for (d, s) in m.0.iter_mut().zip(self.0.iter()) {
            *d = s.load(Ordering::Acquire);
        }
        m
    }

    /// Replace the whole set (word by word).
    pub fn store(&self, m: &CpuMask) {
        for (d, s) in self.0.iter().zip(m.0.iter()) {
            d.store(*s, Ordering::Release);
        }
    }
}

impl Default for AtomicCpuMask {
    fn default() -> Self {
        Self::new()
    }
}

// ── possible / online / nr_cpu_ids ──────────────────────────────────────────

static POSSIBLE: AtomicCpuMask = AtomicCpuMask::new();
static ONLINE: AtomicCpuMask = AtomicCpuMask::new();
/// One past the highest possible CPU. 1 until [`set_possible`] runs: the boot
/// CPU is the only one that exists before the DTB is read.
static NR_CPU_IDS: AtomicUsize = AtomicUsize::new(1);

/// The CPUs this boot can ever run (the DTB's, cut to [`NR_CPUS`]).
pub fn possible() -> CpuMask {
    POSSIBLE.load()
}

/// The CPUs running now. A subset of [`possible`].
pub fn online() -> CpuMask {
    ONLINE.load()
}

/// Is `cpu` possible?
#[inline]
pub fn cpu_possible(cpu: usize) -> bool {
    POSSIBLE.test(cpu)
}

/// Is `cpu` online?
#[inline]
pub fn cpu_online(cpu: usize) -> bool {
    ONLINE.test(cpu)
}

/// Mark `cpu` online or offline. Refuses (returns `false`) a CPU that is not
/// possible: a CPU without an area cannot run.
pub fn set_cpu_online(cpu: usize, on: bool) -> bool {
    if !cpu_possible(cpu) {
        return false;
    }
    if on {
        ONLINE.set(cpu);
    } else {
        ONLINE.clear(cpu);
    }
    true
}

/// One past the highest possible CPU id: the bound every "for each CPU" walk
/// takes instead of [`NR_CPUS`].
#[inline]
pub fn nr_cpu_ids() -> usize {
    NR_CPU_IDS.load(Ordering::Relaxed)
}

/// Fix the possible set, once, at boot, before any area exists and before any
/// secondary CPU starts. `nr_cpu_ids` becomes its highest member plus one (1
/// for an empty mask).
pub fn set_possible(m: &CpuMask) {
    POSSIBLE.store(m);
    NR_CPU_IDS.store(m.last().map_or(1, |l| l + 1), Ordering::Relaxed);
}

/// The CPUs the platform firmware describes, as the boot hooks read them:
/// the one seam CPU discovery goes through. The boot hooks fill it from the
/// DTB's `/cpus` today (both ISAs); an ACPI MADT reader would fill the same
/// struct. Nothing in this crate parses firmware tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareCpus {
    /// CPUs the firmware names; 0 when it said nothing (no table, or one
    /// that did not parse).
    pub count: usize,
    /// The CPU id of the CPU running the boot (it is possible whatever
    /// `count` says).
    pub boot_cpu: usize,
    /// Where `count` came from, for the boot log ("DTB", "none").
    pub source: &'static str,
}

/// What the boot makes of the DTB's CPU count: `(nr_cpu_ids, clamped)`.
///
/// `dtb_count` 0 (no DTB, or one without `/cpus`) is 1: the boot CPU alone,
/// as Linux boots without firmware CPU information. More than [`NR_CPUS`] is
/// [`NR_CPUS`] with `clamped` set; the caller warns, and the CPUs above the
/// ceiling are never started.
pub const fn clamp_discovered(dtb_count: usize) -> (usize, bool) {
    if dtb_count == 0 {
        (1, false)
    } else if dtb_count > NR_CPUS {
        (NR_CPUS, true)
    } else {
        (dtb_count, false)
    }
}

// ── per-CPU variables ───────────────────────────────────────────────────────

/// Accesses through [`PerCpuRemote::get`] that found no area. **Must stay zero** on a
/// correct kernel; a self-check reads it.
static OOR: AtomicU32 = AtomicU32::new(0);

/// See [`OOR`].
pub fn oor_count() -> u32 {
    OOR.load(Ordering::Relaxed)
}

/// One per-CPU variable of type `T`: an instance in each CPU's area, reached
/// through a table of pointers indexed by CPU id — any CPU's, from any CPU
/// (Linux's `per_cpu_ptr`). The scope types in `azos_sync::scope` are built
/// on it (see the crate docs); a bare one is a variable not migrated yet.
///
/// Declared as a `static`; it holds no `T` itself. Before [`attach_area`] ran
/// for a CPU, that CPU's slot is [`POISON`].
pub struct PerCpuRemote<T> {
    ptrs: [AtomicPtr<T>; NR_CPUS],
    init: Option<unsafe fn(*mut T)>,
}

// SAFETY: the table is atomics; what a `T` instance allows across CPUs is the
// owner's contract, exactly as for the static array it replaces.
unsafe impl<T> Sync for PerCpuRemote<T> {}

impl<T> PerCpuRemote<T> {
    const UNSET: AtomicPtr<T> = AtomicPtr::new(core::ptr::without_provenance_mut(POISON));

    /// A variable whose initial value is all zero bytes (the area is zeroed).
    ///
    /// # Safety
    /// All-zero bytes must be a valid `T`.
    pub const unsafe fn zeroed() -> Self {
        Self { ptrs: [Self::UNSET; NR_CPUS], init: None }
    }

    /// A variable that `init` initialises in place, on zeroed memory, when its
    /// CPU's area is attached. `init` must write a valid `T` at the pointer.
    pub const fn with_init(init: unsafe fn(*mut T)) -> Self {
        Self { ptrs: [Self::UNSET; NR_CPUS], init: Some(init) }
    }

    /// `cpu`'s instance: a pointer into its area, or [`POISON`] if it has none.
    /// Panics if `cpu >= NR_CPUS` (the bounds check a static array had).
    #[inline(always)]
    pub fn ptr(&self, cpu: usize) -> *mut T {
        self.ptrs[cpu].load(Ordering::Relaxed)
    }

    /// `cpu`'s instance, or `None` (counted in [`oor_count`]) if `cpu` has no
    /// area: past [`NR_CPUS`], past `nr_cpu_ids`, or not possible.
    #[inline]
    pub fn get(&self, cpu: usize) -> Option<*mut T> {
        match self.ptrs.get(cpu).map(|p| p.load(Ordering::Relaxed)) {
            Some(p) if p as usize != POISON => Some(p),
            _ => {
                OOR.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Has `cpu` got an instance?
    #[inline]
    pub fn attached(&self, cpu: usize) -> bool {
        cpu < NR_CPUS && self.ptr(cpu) as usize != POISON
    }
}

/// What [`attach_area`] needs from a per-CPU variable, type-erased so one list
/// can name variables of different types.
pub trait PerCpuVar: Sync {
    /// Bytes of one instance.
    fn size(&self) -> usize;
    /// Alignment of one instance (at most [`AREA_ALIGN`]).
    fn align(&self) -> usize;
    /// Has `cpu` got an instance?
    fn attached(&self, cpu: usize) -> bool;
    /// Point `cpu`'s slot at `p` and initialise the instance there.
    ///
    /// # Safety
    /// `p` is zeroed, aligned to [`Self::align`], [`Self::size`] bytes long,
    /// owned by `cpu`'s area, and nothing reads `cpu`'s slot concurrently.
    unsafe fn attach(&self, cpu: usize, p: *mut u8);
}

impl<T> PerCpuVar for PerCpuRemote<T> {
    fn size(&self) -> usize {
        core::mem::size_of::<T>()
    }
    fn align(&self) -> usize {
        core::mem::align_of::<T>()
    }
    fn attached(&self, cpu: usize) -> bool {
        PerCpuRemote::attached(self, cpu)
    }
    unsafe fn attach(&self, cpu: usize, p: *mut u8) {
        let t = p as *mut T;
        if let Some(f) = self.init {
            // SAFETY: the caller's contract.
            unsafe { f(t) };
        }
        self.ptrs[cpu].store(t, Ordering::Relaxed);
    }
}

/// Bytes of one per-CPU area holding `vars` in order, each at its own
/// alignment, rounded up to [`AREA_ALIGN`]. 0 for no variables.
pub fn area_bytes(vars: &[&dyn PerCpuVar]) -> usize {
    let mut off = 0;
    for v in vars {
        assert!(v.align() <= AREA_ALIGN, "per-CPU variable aligned past AREA_ALIGN");
        off = align_up(off, v.align()) + v.size();
    }
    align_up(off, AREA_ALIGN)
}

/// Lay `vars` out in `cpu`'s area at `base` (the layout [`area_bytes`]
/// measured) and attach each one.
///
/// # Safety
/// `base` is [`AREA_ALIGN`]-aligned, `area_bytes(vars)` zeroed bytes used by
/// nothing else, `cpu < NR_CPUS`, and no CPU is using any of `vars` for `cpu`.
pub unsafe fn attach_area(vars: &[&dyn PerCpuVar], cpu: usize, base: *mut u8) {
    assert!(cpu < NR_CPUS && base as usize % AREA_ALIGN == 0);
    AREA_BASE[cpu].store(base as usize, Ordering::Relaxed);
    let mut off = 0;
    for v in vars {
        off = align_up(off, v.align());
        // SAFETY: inside the area, aligned (the caller's contract for `base`).
        unsafe { v.attach(cpu, base.add(off)) };
        off += v.size();
    }
}

static AREA_BASE: [AtomicUsize; NR_CPUS] = [const { AtomicUsize::new(0) }; NR_CPUS];

/// Where `cpu`'s area starts (kernel address), or 0 if it has none.
pub fn area_base(cpu: usize) -> usize {
    AREA_BASE.get(cpu).map_or(0, |a| a.load(Ordering::Relaxed))
}

/// [`area_base`], checked: `None`, counted in [`oor_count`], for a CPU without
/// an area.
pub fn checked_area(cpu: usize) -> Option<usize> {
    match area_base(cpu) {
        0 => {
            OOR.fetch_add(1, Ordering::Relaxed);
            None
        }
        b => Some(b),
    }
}
