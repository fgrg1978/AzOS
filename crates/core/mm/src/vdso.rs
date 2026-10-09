// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// vDSO — Virtual Dynamic Shared Object (M01).
///
/// A single read-only physical page is shared into every user process at a
/// fixed virtual address (VDSO_USER_BASE).  The kernel writes monotonic timing
/// data to this page under a seqlock; user-space reads it without issuing an
/// ecall, eliminating syscall overhead for the most common time queries.
///
/// ## Seqlock protocol
/// Writer (kernel, timer ISR — see `vdso_update()` for how concurrent
/// writers from multiple harts are serialized):
///   1. seq += 1  →  odd   (write in progress)
///   2. store data fields
///   3. seq += 1  →  even  (data stable)
///
/// Reader (user-space via libsys):
///   loop:
///     seq1 = load seq;  if seq1 is odd → spin
///     read data fields
///     seq2 = load seq;  if seq2 != seq1 → retry
///     // data is consistent
///
/// A classic seqlock only tolerates a SINGLE writer. On SMP, the timer ISR
/// fires on every hart, so `vdso_update()` claims the right to write with a
/// compare-exchange on `seq` itself before touching any data field — see the
/// doc comment on `vdso_update()` for why that (rather than gating on hart
/// identity, or a lock) is the correct and cheapest way to serialize writers
/// here.
///
/// VDSO_USER_BASE is exported to libsys so it can read without a syscall.

use azos_arch::ArchPlatform as _;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use azos_arch::PAGE_SIZE;
use crate::pmm;

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Fixed user-space virtual address of the vDSO page.
///
/// Defined in `azos_abi::vdso` — the one crate both this kernel-side
/// module and `crates/core/libsys` (a separate, ring-3 compilation) depend on —
/// and re-exported here so existing callers keep using
/// `azos_mm::vdso::VDSO_USER_BASE`. See that module's doc for why the
/// value is `0x2000_0000` and not the kernel's RAM/MMIO identity-mapped
/// range on any supported board.
pub use azos_abi::vdso::VDSO_USER_BASE;

/// Magic value stored at the start of the vDSO page.
pub const VDSO_MAGIC: u32 = 0x5644_534F; // "VDSO"

/// Kernel version encoded as (major << 16 | minor << 8 | patch).
pub const VDSO_KERNEL_VERSION: u32 = (0 << 16) | (1 << 8) | 0; // 0.1.0

/// [`VdsoData::flags`] bit 0: `rdtime` executes natively, so ring 3 reads the
/// counter without a trap (RFC-0041 §A). Clear where the `time` CSR is
/// emulated by M-mode firmware — there `rdtime` traps into OpenSBI and costs
/// more than `SYS_UPTIME` — and when the kernel is built to force the trap.
/// libsys mirrors the value (`crates/core/libsys/src/pure.rs`).
pub const VDSO_FLAG_RDTIME_NATIVE: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// VdsoData — layout of the vDSO page (first 32 bytes)
// ---------------------------------------------------------------------------

/// Data written by the kernel into the vDSO page.
///
/// # Safety
/// This struct is placed at a physical address returned by `pmm::alloc_page`.
/// All fields are accessed through raw pointers with volatile semantics.
/// The seqlock (seq field) guards consistency.
#[repr(C, align(8))]
pub struct VdsoData {
    /// VDSO_MAGIC — lets userspace verify the page is mapped correctly.
    pub magic: AtomicU32,
    /// Kernel version (major.minor.patch packed into u32).
    pub kernel_version: AtomicU32,
    /// Seqlock counter.  Even = data stable, odd = write in progress.
    pub seq: AtomicU32,
    /// Facts about this machine that ring 3 needs to choose a path. Bit 0 is
    /// [`VDSO_FLAG_RDTIME_NATIVE`]; the other bits are zero.
    ///
    /// Written **once**, by [`vdso_set_flags`] during boot, before any user
    /// task runs, and never changed: outside the seqlock like `timebase_hz`.
    pub flags: AtomicU32,
    /// Monotonic tick counter (incremented every timer IRQ).
    pub uptime_ticks: AtomicU64,
    /// Milliseconds since boot.
    pub uptime_ms: AtomicU64,
    /// Frequency of the RISC-V `time` counter, in Hz. **0 = not published.**
    ///
    /// **Why this and not an already-cooked time value.** `uptime_ticks` and
    /// `uptime_ms` are refreshed by the timer ISR, so their granularity is the
    /// tick period: at 100 Hz, **10 milliseconds**. Reading that page costs
    /// 28 ns and hands back a number that may be 10 ms stale — for a control
    /// loop at 40 Hz, with 25 ms windows, that is not a clock.
    ///
    /// Linux solves this by publishing the conversion parameters and letting
    /// the program read the hardware counter itself: its
    /// `__vdso_clock_gettime` gives exact nanoseconds for 406 ns. With the
    /// frequency here, a program issues `rdtime` — a user instruction,
    /// `scounteren.TM` is already enabled — and converts, keeping the accuracy
    /// without the trap.
    ///
    /// Written **once** in `vdso_init` and never changed, so it sits outside
    /// the seqlock deliberately: a reader never needs to retry for it.
    pub timebase_hz: AtomicU64,
    /// CPU capabilities ring 3 may use (`azos_abi::vdso::HWCAP_*`), the
    /// AT_HWCAP analogue. Written once by [`vdso_set_hwcap`] during boot,
    /// before the first user task; outside the seqlock like `flags`.
    pub hwcap: AtomicU64,
    /// The counter scale (`azos_abi::vdso::VDSO_COUNTER_*`): the counter at
    /// the conversion's base, the clock's ticks there, and the 32.32
    /// multiplier. Written once by [`vdso_set_counter_scale`] before the
    /// first user task (x86_64: the TSC's calibration, which never changes
    /// after boot); outside the seqlock like `timebase_hz`. Zero elsewhere.
    pub counter_base: AtomicU64,
    pub ticks_base: AtomicU64,
    pub counter_mult: AtomicU64,
}

// libsys reads the page by raw offset (`crates/core/libsys/src/lib.rs`,
// `vdso_read_u32` / `vdso_read_u64`), so the layout is ABI. A field moved here
// fails the build instead of handing ring 3 the wrong eight bytes.
const _: () = {
    assert!(core::mem::offset_of!(VdsoData, magic) == 0);
    assert!(core::mem::offset_of!(VdsoData, kernel_version) == 4);
    assert!(core::mem::offset_of!(VdsoData, seq) == 8);
    assert!(core::mem::offset_of!(VdsoData, flags) == 12);
    assert!(core::mem::offset_of!(VdsoData, uptime_ticks) == 16);
    assert!(core::mem::offset_of!(VdsoData, uptime_ms) == 24);
    assert!(core::mem::offset_of!(VdsoData, timebase_hz) == 32);
    assert!(core::mem::offset_of!(VdsoData, hwcap) == azos_abi::vdso::VDSO_HWCAP_OFFSET);
    assert!(core::mem::offset_of!(VdsoData, counter_base) == azos_abi::vdso::VDSO_COUNTER_BASE_OFFSET);
    assert!(core::mem::offset_of!(VdsoData, ticks_base) == azos_abi::vdso::VDSO_TICKS_BASE_OFFSET);
    assert!(core::mem::offset_of!(VdsoData, counter_mult) == azos_abi::vdso::VDSO_COUNTER_MULT_OFFSET);
};

// ---------------------------------------------------------------------------
// Kernel-side state
// ---------------------------------------------------------------------------

/// Physical address of the vDSO page (0 = not initialised).
static VDSO_PHYS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Kernel API
// ---------------------------------------------------------------------------

/// Allocate and initialise the vDSO page.  Called once during boot.
/// Publishes the counter frequency. Separate from [`vdso_update`] because it
/// is invariant: writing it every tick would be work for nothing.
pub fn vdso_set_timebase(hz: u64) {
    let phys = VDSO_PHYS.load(Ordering::Relaxed) as usize;
    if phys == 0 { return; }
    let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };
    data.timebase_hz.store(hz, Ordering::Release);
}

/// Publish [`VdsoData::flags`]. Called once during boot, after
/// [`vdso_init`] and before the first user task; a later call would change a
/// fact a running reader has already acted on.
pub fn vdso_set_flags(flags: u32) {
    let phys = VDSO_PHYS.load(Ordering::Relaxed) as usize;
    if phys == 0 { return; }
    let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };
    data.flags.store(flags, Ordering::Release);
}

/// Publish [`VdsoData::hwcap`]. Called once during boot, after
/// [`vdso_init`] and before the first user task.
pub fn vdso_set_hwcap(hwcap: u64) {
    let phys = VDSO_PHYS.load(Ordering::Relaxed) as usize;
    if phys == 0 { return; }
    let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };
    data.hwcap.store(hwcap, Ordering::Release);
}

/// Publish the counter scale (`VdsoData::counter_*`). Called once during
/// boot, after [`vdso_init`] and before the first user task.
pub fn vdso_set_counter_scale(counter_base: u64, ticks_base: u64, mult: u64) {
    let phys = VDSO_PHYS.load(Ordering::Relaxed) as usize;
    if phys == 0 { return; }
    let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };
    data.counter_base.store(counter_base, Ordering::Relaxed);
    data.ticks_base.store(ticks_base, Ordering::Relaxed);
    data.counter_mult.store(mult, Ordering::Release);
}

pub fn vdso_init() {
    if let Ok(page) = pmm::alloc_page() {
        let phys = page.as_usize();

        // Zero the page first.  Also redundant with `pmm::alloc_page`'s own
        // zero-fill (RFC-0045 Tier 0 item 3's dispatcher, same as the other
        // sites in this crate), but this call runs once per boot, not on a
        // hot path, so it stays as defense-in-depth rather than being
        // removed as dead work.
        // PHYSICAL page: zero it through the kernel's own view of it.
        unsafe { azos_arch::ARCH.zero_memory(crate::addr::phys_to_virt(phys), PAGE_SIZE); }

        // Write the magic and version (seq = 0 = stable, no data yet).
        let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };
        data.magic.store(VDSO_MAGIC, Ordering::Release);
        data.kernel_version.store(VDSO_KERNEL_VERSION, Ordering::Release);

        VDSO_PHYS.store(phys as u64, Ordering::Release);
    }
}

/// Return the physical address of the vDSO page, or 0 if not initialised.
pub fn vdso_phys() -> usize {
    VDSO_PHYS.load(Ordering::Acquire) as usize
}

/// Wave 13: where the riscv64 sigreturn trampoline is mapped in every user
/// address space, read-execute: the page after the vDSO's. riscv64 musl has
/// no `SA_RESTORER`, so a Linux signal handler returns to this address (`ra`)
/// and its two instructions issue `rt_sigreturn`. aarch64 musl passes its own
/// restorer and maps nothing here (its user MMIO window may start here).
pub const SIGTRAMP_USER_VA: usize = VDSO_USER_BASE + PAGE_SIZE;

static SIGTRAMP_PHYS: AtomicU64 = AtomicU64::new(0);

/// Allocate and fill the trampoline page (riscv64; a no-op elsewhere). Once,
/// at boot, before any user task exists: no hart has fetched from the page,
/// so no instruction cache holds a stale line of it.
pub fn sigtramp_init(code: &[u32]) {
    if !cfg!(target_arch = "riscv64") || SIGTRAMP_PHYS.load(Ordering::Relaxed) != 0 {
        return;
    }
    if let Ok(page) = pmm::alloc_page() {
        let phys = page.as_usize();
        let va = crate::addr::phys_to_virt(phys);
        unsafe {
            azos_arch::ARCH.zero_memory(va, PAGE_SIZE);
            for (i, w) in code.iter().enumerate().take(PAGE_SIZE / 4) {
                core::ptr::write_volatile((va as *mut u32).add(i), *w);
            }
        }
        // arch-only: the sigreturn trampoline page is riscv64's (the early
        // return above skips every other ISA).
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("fence.i") };
        SIGTRAMP_PHYS.store(phys as u64, Ordering::Release);
    }
}

/// The trampoline page's frame, 0 when there is none (aarch64, or before
/// [`sigtramp_init`]).
pub fn sigtramp_phys() -> usize {
    SIGTRAMP_PHYS.load(Ordering::Acquire) as usize
}


/// Update the vDSO timing data.  Called from the timer ISR — on every hart
/// in an SMP kernel, since each hart takes its own periodic timer interrupt.
///
/// Uses the seqlock write protocol: increment seq to odd, write, increment
/// to even.  This protocol is only sound with a SINGLE writer: two harts
/// racing the seq increment/store sequence can interleave and leave seq (and
/// the data fields) in an incoherent state that no reader-side retry can
/// detect.
///
/// Serializing writers by hart identity (e.g. "only hart 0 updates") was
/// considered and rejected: it would depend on `tp`/`hart_id()` correctly
/// identifying the running hart at the point this function is called from
/// deep inside the timer ISR. That is NOT a safe assumption in this kernel —
/// `crates/core/sched/src/task.rs` saves/restores `tp` as part of task context
/// (`CTX_TP`) so `current_cpu_id()` survives ordinary context switches, but
/// the EDF scheduler can migrate a task to a different physical hart, and the
/// migrated task's restored `tp` then reflects the hart it last ran on, not
/// the one it is running on now (tracked separately, at the
/// `context_switch.S:83` save). A hart whose
/// current task carries a stale `tp == 0` would wrongly believe itself to be
/// the sole writer, silently reopening the exact multi-writer race this
/// function exists to close — worse than not fixing the bug at all, because
/// the failure would be workload-dependent and invisible in easy testing.
///
/// Instead, writers are serialized without needing any hart identity: the
/// seqlock's own `seq` counter doubles as a claim ticket via
/// compare-exchange. A hart only proceeds to write if it wins the CAS that
/// flips `seq` from even to odd; every other hart (or a spurious re-entrant
/// call — see below) that loses the race, or sees `seq` already odd, simply
/// drops this tick's update and returns. That is harmless: the vDSO page is
/// refreshed again on the very next tick, by whichever hart gets there first
/// — there is no requirement that every tick be published, only that
/// published data is always internally consistent. This also protects
/// against IRQ-context re-entrancy on a single hart (e.g. a nested timer
/// interrupt while a write is still open): the odd-`seq` check makes a
/// reentrant call a no-op instead of corrupting an in-flight write.
///
/// Cost: one uncontended `compare_exchange` per timer tick on the common
/// path (no contention: SMP harts rarely race the exact same tick), which is
/// cheaper than an IRQ-safe lock (`SpinLock::lock_irqsave()` in
/// `crates/core/sync/src/spinlock.rs`) held across the write on every hart, every
/// tick, given this runs inside a WCET-budgeted ISR.
#[inline]
pub fn vdso_update(uptime_ticks: u64, uptime_ms: u64) {
    let phys = VDSO_PHYS.load(Ordering::Relaxed) as usize;
    if phys == 0 { return; }

    // SAFETY: phys is a valid page allocated at init time. Multiple harts
    // may call this concurrently; the CAS below ensures only the hart that
    // wins the even→odd transition of `seq` touches the data fields, making
    // this the sole writer for the duration of that write.
    let data = unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoData) };

    // Seqlock: claim the write by CAS'ing seq from even to even+1 (odd).
    // If seq is already odd, someone else's write is in flight — drop this
    // tick. If the CAS loses the race, someone else claimed it first —
    // drop this tick too. Either way the page is refreshed on the next tick.
    // Interrupts masked from the claim to the release (wave 13, RT7). The
    // write was written for the timer ISR, where they already are; since
    // wave 13 (3fcdc041) idle also calls this, with interrupts ON. A tick
    // between claim and release preempted idle with `seq` odd, and every
    // ring-3 reader (`vdso_now_ns`, `vdso_read_u64`: retry while odd) then
    // spun on it. On idle's own hart the spinning reader outranks idle, so
    // idle never ran to release it: a hang (abitest's `children_of`
    // deadline loop, hart 3 at its `seq` re-read, 1 in 10-20 loaded boots).
    use azos_arch::Interrupts;
    let irq = azos_arch::ARCH.disable_all();
    let seq = data.seq.load(Ordering::Acquire);
    if seq & 1 != 0 {
        azos_arch::ARCH.restore(irq);
        return;
    }
    if data
        .seq
        .compare_exchange(seq, seq.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        azos_arch::ARCH.restore(irq);
        return;
    }
    // `vdso-write-window` (gate row only): hold the write open for a while,
    // so an interrupt inside it, were it allowed, is all but certain.
    #[cfg(feature = "vdso-write-window")]
    for _ in 0..200_000u32 {
        core::hint::spin_loop();
    }

    // We won the claim: we are now the sole writer. The successful CAS used
    // Acquire ordering, so these stores cannot be hoisted above it.
    //
    // **Verified true (2026-09-06 audit), and the more important half of the
    // proof lives elsewhere.** This claim is only about program order on
    // this hart: Acquire on the CAS's success ordering is exactly the
    // language guarantee that no later memory op in this function can be
    // reordered before it, so it holds independent of what the reader does.
    // What makes the seqlock as a whole correct on RVWMO is the READER side,
    // and that reader is a hand-rolled seqlock, not `crates/core/sync::SeqLock` —
    // the crate that had a missing-acquire-fence bug fixed this same week.
    // `crates/core/libsys/src/lib.rs`'s `vdso_read_u64` (~line 182) reads `seq`
    // and the data field with plain `read_volatile`, not through an atomic
    // load, and brackets them with two standalone `fence(Ordering::Acquire)`
    // calls instead — the first stops the data read from being hoisted
    // before the `seq` read, the second stops the closing `seq` re-read from
    // being hoisted before the data read, matching the classic
    // read-seq/read-data/read-seq-again seqlock shape. It was checked as
    // part of this audit and found structurally sound, but it is a second,
    // independently-written implementation of the same primitive that
    // already had one RVWMO bug in this tree — it deserves the same
    // scrutiny `seqlock.rs` got, on its own, rather than inheriting a clean
    // bill of health from this comment.
    //
    // `uptime_ticks`/`uptime_ms` were sampled by the CALLER (kernel/src/trap/interrupt.rs, before
    // this hart necessarily won the race above) from two different sources —
    // a global `TICK_COUNT.fetch_add()` and `rdtime` respectively, read at
    // two different instants — so a hart that stalled between its own
    // sampling and winning a later CAS can carry a sample that is older in
    // one field but not necessarily the other. Publishing a sample that
    // regresses either field would walk the page's documented "monotonic"
    // data backwards for every user-space reader. Require the new sample to
    // dominate in BOTH fields before publishing; otherwise drop this tick's
    // update entirely (the seqlock still closes normally so no reader
    // spins) — the next tick that produces a fully-newer sample refreshes
    // the page. Both loads are Relaxed: we are the sole writer at this
    // point (we hold the claim), so no other write can race these reads.
    let published_ticks = data.uptime_ticks.load(Ordering::Relaxed);
    let published_ms = data.uptime_ms.load(Ordering::Relaxed);
    if uptime_ticks >= published_ticks && uptime_ms >= published_ms {
        data.uptime_ticks.store(uptime_ticks, Ordering::Release);
        data.uptime_ms.store(uptime_ms, Ordering::Release);
    }

    // Seqlock: close write (seq → even). Release ordering makes whichever
    // stores above ran visible to any reader whose seqlock retry-read
    // observes this new value (paired with the reader's Acquire fences in
    // `crates/core/libsys/src/lib.rs`).
    data.seq.store(seq.wrapping_add(2), Ordering::Release);
    azos_arch::ARCH.restore(irq);
}

// ===========================================================================
// Per-task page: the caller's own counters and its granted sensors
// (`SYS_VDSO_TASK_MAP` 594, `SYS_VDSO_SENSOR_BIND` 595)
// ===========================================================================
//
// ## Why a second page, and why it is not at a fixed address
//
// The page above is ONE frame mapped into every process: anything written
// there is read by everyone. A task's CPU time, its switch counts and its
// sensor readings are not everyone's, so they live in a page of their own —
// one frame per task-pool slot, mapped only into the task that asked for it.
//
// It is mapped on request (`SYS_VDSO_TASK_MAP`) into the caller's shm/MMIO
// window, not at a fixed address at exec, because that window is the one
// part of an address space the kernel already handles the way this page
// needs: `fork_cow` leaves it out of the child (so a child never reads its
// parent's counters through an inherited PTE) and exit teardown does not
// free its frames (so the kernel keeps owning this one). A fixed address
// would have needed both of those rules restated in `vmm` for a new frame.
//
// ## Scope: which task, which sensors
//
// * The page belongs to one task-pool SLOT and records its owner TID. The
//   publisher writes only when the task running on the hart IS the owner, and
//   a new owner of the slot gets the frame zeroed before its TID is published
//   (`task_page_claim`), so a task never sees its predecessor's numbers.
// * A sensor slot is published only if its bit is set in `sensor_mask`, and
//   the only writer of that mask is `SYS_VDSO_SENSOR_BIND`, which sets the
//   bit for the sensor type a `Cap<Sensor>` with `READ` names in the
//   caller's own table — the same check `SYS_SENSOR_READ_TYPED` makes. No
//   bit, no data: the page of a task holding no sensor capability carries
//   none.
//
// ## Freshness
//
// The publisher runs from the timer interrupt, for the task current on that
// hart (`task_page_publish`). A task reads its page only while it runs, and
// while it runs the page is refreshed at every timer interrupt on its hart,
// so the staleness bound is one tick period of its OWN run time (10 ms at the
// default 100 Hz), plus the time since it was last switched in on a fresh
// run. Every value is stamped (`last_sample`, per-sensor `stamp`) so a reader
// can check. Since layout version 2 each sensor slot also carries `acq_ns`,
// when the VALUE was acquired, which is what a staleness check needs: a
// cached value is republished at every tick with a fresh `stamp` and its
// original `acq_ns`.
//
// ## Seqlock
//
// One writer at a time per page: a task is current on one hart at a time,
// and the writer claims the page with the same even→odd compare-exchange as
// `vdso_update`, so a nested or concurrent attempt drops that tick instead of
// interleaving. `sensor_mask` is written outside the seqlock (one atomic
// `fetch_or` by the owner's own syscall) and read inside it.

use core::sync::atomic::AtomicUsize;

/// Sensor slots in the page: `SENSOR_TYPE_IMU` (0) ..= `SENSOR_TYPE_POWER` (9).
pub const VDSO_SENSOR_SLOTS: usize = 10;
/// Largest sensor payload a slot carries (IMU, 24 bytes, is the largest of
/// the fixed-size types; LiDAR and camera have no slot).
pub const VDSO_SENSOR_DATA_MAX: usize = 32;
/// `VdsoTaskPage::magic` ("VTSK").
pub const VDSO_TASK_MAGIC: u32 = 0x5654_534B;

/// One sensor's latest published value.
#[repr(C)]
pub struct VdsoSensorSlot {
    /// Publications of this sensor into this page; 0 = never published.
    pub seq: AtomicU32,
    /// Valid bytes in `data`.
    pub len: AtomicU32,
    /// Timebase counter when the value was sampled.
    pub stamp: AtomicU64,
    /// The payload, in `SYS_SENSOR_READ_TYPED`'s byte format for the type.
    pub data: [AtomicU64; VDSO_SENSOR_DATA_MAX / 8],
    /// Layout version 2: when the payload was ACQUIRED, vDSO-clock ns (the
    /// stamp `SYS_SENSOR_READ_TS` reports for the same read); 0 = unknown.
    /// `stamp` above is when it was PUBLISHED.
    pub acq_ns: AtomicU64,
    _pad: [u64; 1],
}

/// Layout of the per-task page (first 704 bytes; the rest is zero).
#[repr(C, align(64))]
pub struct VdsoTaskPage {
    pub magic: AtomicU32,
    pub version: AtomicU32,
    /// Seqlock over everything below except `owner_tid` and `sensor_mask`.
    pub seq: AtomicU32,
    /// TID this page belongs to. Written once per owner, before the owner can
    /// map it.
    pub owner_tid: AtomicU32,
    /// Timebase ticks charged to this task, sampled at timer interrupts:
    /// each interrupt charges the interval since the previous interrupt on
    /// the same hart to the task it finds running. Tick-granular.
    pub cpu_time: AtomicU64,
    /// `Task::switches_voluntary` at the last publication.
    pub switches_voluntary: AtomicU64,
    /// `Task::switches_preempted` at the last publication.
    pub switches_preempted: AtomicU64,
    /// `Task::ready_site` at the last publication: why the task last became
    /// runnable — low nibble the site (`sched::task::ready_site`: 1 create,
    /// 2 preempt, 3 kc24, 4 wake, 5 reap, 6 rebalance), high nibble the hart
    /// that did it. The scheduler keeps no record of WHICH wait reason the
    /// last wake satisfied (it resets `wait_reason` on every dispatch), so
    /// this is the finest "last wake reason" the kernel has.
    pub last_ready_site: AtomicU32,
    /// Bit `t`: `SYS_VDSO_SENSOR_BIND` accepted a `Cap<Sensor>` for type `t`.
    pub sensor_mask: AtomicU32,
    /// Publications of this page.
    pub publishes: AtomicU64,
    /// Timebase counter at the last publication.
    pub last_sample: AtomicU64,
    pub sensors: [VdsoSensorSlot; VDSO_SENSOR_SLOTS],
}

// libsys reads the page by the offsets in `azos_abi::vdso` (`VTP_*`),
// so the layout is ABI: a field moved here fails the build.
const _: () = {
    use core::mem::offset_of;
    use azos_abi::vdso as a;
    assert!(offset_of!(VdsoTaskPage, magic) == a::VTP_MAGIC);
    assert!(offset_of!(VdsoTaskPage, seq) == a::VTP_SEQ);
    assert!(offset_of!(VdsoTaskPage, owner_tid) == a::VTP_OWNER_TID);
    assert!(offset_of!(VdsoTaskPage, cpu_time) == a::VTP_CPU_TIME);
    assert!(offset_of!(VdsoTaskPage, switches_voluntary) == a::VTP_SW_VOLUNTARY);
    assert!(offset_of!(VdsoTaskPage, switches_preempted) == a::VTP_SW_PREEMPTED);
    assert!(offset_of!(VdsoTaskPage, last_ready_site) == a::VTP_LAST_READY_SITE);
    assert!(offset_of!(VdsoTaskPage, sensor_mask) == a::VTP_SENSOR_MASK);
    assert!(offset_of!(VdsoTaskPage, publishes) == a::VTP_PUBLISHES);
    assert!(offset_of!(VdsoTaskPage, last_sample) == a::VTP_LAST_SAMPLE);
    assert!(offset_of!(VdsoTaskPage, sensors) == a::VTP_SENSORS);
    assert!(core::mem::size_of::<VdsoSensorSlot>() == a::VTP_SENSOR_STRIDE);
    assert!(offset_of!(VdsoSensorSlot, data) == a::VTP_SENSOR_DATA);
    assert!(offset_of!(VdsoSensorSlot, acq_ns) == a::VTP_SENSOR_ACQ_NS);
    assert!(offset_of!(VdsoTaskPage, version) == a::VTP_VERSION);
    assert!(VDSO_SENSOR_SLOTS == a::VTP_SENSOR_SLOTS);
    assert!(VDSO_SENSOR_DATA_MAX == a::VTP_SENSOR_DATA_MAX);
    assert!(VDSO_TASK_MAGIC == a::VDSO_TASK_MAGIC);
    assert!(core::mem::size_of::<VdsoTaskPage>() <= PAGE_SIZE);
};

/// One task-pool slot's page.
struct TaskPageSlot {
    /// Frame, allocated on the slot's first map and kept for the boot.
    phys: AtomicUsize,
    /// TID the frame currently belongs to; 0 = nobody. The publisher's gate.
    owner: AtomicU32,
    /// Where the owner mapped it; 0 = not mapped yet.
    va: AtomicUsize,
}

const EMPTY_SLOT: TaskPageSlot =
    TaskPageSlot { phys: AtomicUsize::new(0), owner: AtomicU32::new(0), va: AtomicUsize::new(0) };

static TASK_PAGES: [TaskPageSlot; azos_limits::MAX_TASKS] =
    [EMPTY_SLOT; azos_limits::MAX_TASKS];

fn task_page(phys: usize) -> &'static VdsoTaskPage {
    // SAFETY: `phys` is a frame this module allocated and never frees.
    unsafe { &*(crate::addr::phys_to_virt(phys) as *const VdsoTaskPage) }
}

/// What [`task_page_claim`] handed back.
pub struct TaskPageClaim {
    pub phys: usize,
    /// The owner's earlier mapping, if it made one.
    pub mapped_va: Option<usize>,
}

/// Give slot `idx`'s page to `tid` (allocating the frame on first use).
///
/// A slot whose page belongs to another TID — a task that has exited, since
/// the slot is now `tid`'s — is unpublished, zeroed and re-initialised
/// before `tid` is written as its owner, in that order: the publisher reads
/// `owner` first and writes nothing to a page whose owner is not the task it
/// found running. `None` if `idx` is out of range or no frame is free.
///
/// Called only by the owner's own syscall. The publisher on the same hart may
/// interrupt it (O3.1); it then sees either the old owner (skips) or `tid`
/// with the page already initialised.
pub fn task_page_claim(idx: usize, tid: u32) -> Option<TaskPageClaim> {
    let slot = TASK_PAGES.get(idx)?;
    if tid == 0 { return None; }
    let mut phys = slot.phys.load(Ordering::Acquire);
    if phys == 0 {
        phys = pmm::alloc_page().ok()?.as_usize();
        slot.phys.store(phys, Ordering::Release);
    }
    if slot.owner.load(Ordering::Acquire) == tid {
        let va = slot.va.load(Ordering::Acquire);
        return Some(TaskPageClaim { phys, mapped_va: if va == 0 { None } else { Some(va) } });
    }
    slot.owner.store(0, Ordering::Release);
    slot.va.store(0, Ordering::Relaxed);
    // SAFETY: the frame is ours and nobody publishes into it while owner is 0.
    unsafe { azos_arch::ARCH.zero_memory(crate::addr::phys_to_virt(phys), PAGE_SIZE); }
    let page = task_page(phys);
    page.magic.store(VDSO_TASK_MAGIC, Ordering::Relaxed);
    page.version.store(azos_abi::vdso::VDSO_TASK_VERSION, Ordering::Relaxed);
    page.owner_tid.store(tid, Ordering::Relaxed);
    slot.owner.store(tid, Ordering::Release);
    Some(TaskPageClaim { phys, mapped_va: None })
}

/// Record where `tid` mapped slot `idx`'s page. Ignored unless `tid` owns it.
pub fn task_page_set_va(idx: usize, tid: u32, va: usize) {
    if let Some(slot) = TASK_PAGES.get(idx) {
        if slot.owner.load(Ordering::Acquire) == tid {
            slot.va.store(va, Ordering::Release);
        }
    }
}

/// Set the bit for `sensor_type` in `tid`'s page. The caller has checked the
/// capability. `false` if `tid` has no page in slot `idx` or the type has no slot.
pub fn task_page_bind_sensor(idx: usize, tid: u32, sensor_type: u32) -> bool {
    let Some(slot) = TASK_PAGES.get(idx) else { return false };
    if (sensor_type as usize) >= VDSO_SENSOR_SLOTS { return false; }
    if slot.owner.load(Ordering::Acquire) != tid { return false; }
    let phys = slot.phys.load(Ordering::Acquire);
    if phys == 0 { return false; }
    task_page(phys).sensor_mask.fetch_or(1 << sensor_type, Ordering::AcqRel);
    true
}

/// The facts the publisher copies, sampled by the caller from the scheduler.
pub struct TaskFacts {
    pub idx: usize,
    pub tid: u32,
    pub cpu_delta: u64,
    pub switches_voluntary: u64,
    pub switches_preempted: u64,
    pub ready_site: u32,
    pub now: u64,
}

/// Refresh the running task's page. Called from the timer interrupt.
///
/// `sample(t, buf)` fills `buf` with sensor type `t`'s current value and
/// returns its length, or `None` when that type cannot be sampled from an
/// interrupt (the caller decides which can); its slot then stays as it was
/// (`seq == 0` if never published).
#[inline]
/// `sample(t, buf)` fills `buf` with sensor `t` and answers `(bytes, acq_ns)`:
/// the payload length and when the value was acquired (vDSO-clock ns, 0 =
/// unknown), or `None` for a type it cannot sample here.
pub fn task_page_publish(f: &TaskFacts, sample: &dyn Fn(u32, &mut [u8; VDSO_SENSOR_DATA_MAX]) -> Option<(usize, u64)>) {
    let Some(slot) = TASK_PAGES.get(f.idx) else { return };
    if f.tid == 0 || slot.owner.load(Ordering::Acquire) != f.tid { return; }
    let phys = slot.phys.load(Ordering::Acquire);
    if phys == 0 { return; }
    let page = task_page(phys);

    let seq = page.seq.load(Ordering::Acquire);
    if seq & 1 != 0 { return; }
    if page.seq.compare_exchange(seq, seq.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed).is_err() {
        return;
    }
    page.cpu_time.fetch_add(f.cpu_delta, Ordering::Relaxed);
    page.switches_voluntary.store(f.switches_voluntary, Ordering::Relaxed);
    page.switches_preempted.store(f.switches_preempted, Ordering::Relaxed);
    page.last_ready_site.store(f.ready_site, Ordering::Relaxed);
    let mut mask = page.sensor_mask.load(Ordering::Acquire);
    while mask != 0 {
        let t = mask.trailing_zeros();
        mask &= mask - 1;
        let mut buf = [0u8; VDSO_SENSOR_DATA_MAX];
        if let Some((n, acq_ns)) = sample(t, &mut buf) {
            let s = &page.sensors[t as usize];
            for (i, w) in s.data.iter().enumerate() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[i * 8..i * 8 + 8]);
                w.store(u64::from_le_bytes(b), Ordering::Relaxed);
            }
            s.len.store(n.min(VDSO_SENSOR_DATA_MAX) as u32, Ordering::Relaxed);
            s.stamp.store(f.now, Ordering::Relaxed);
            s.acq_ns.store(acq_ns, Ordering::Relaxed);
            s.seq.fetch_add(1, Ordering::Relaxed);
        }
    }
    page.last_sample.store(f.now, Ordering::Relaxed);
    page.publishes.fetch_add(1, Ordering::Relaxed);
    page.seq.store(seq.wrapping_add(2), Ordering::Release);
}
