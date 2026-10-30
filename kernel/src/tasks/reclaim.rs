// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory reclaim task (Kconfig `MM_RECLAIM_COMPRESS`): the three reclaim
//! stages, run when memory is low.
//!
//! **When it runs.** Every `MM_RECLAIM_POLL_MS` the task looks at the free
//! frame count and at the Domains' charges; a pass runs when the frames in use
//! are at or above `MM_RECLAIM_HIGH_PCT` percent, or a Domain with a frame
//! limit has crossed its own high watermark. The page allocator runs under its
//! callers' locks and cannot wake a task, and a poll costs it nothing (no flag
//! on its hot path).
//!
//! **Pressure comes first.** Before a pass, each poll compares every Domain's
//! frame-budget level (`PageBudget::pressure_change`: normal, warning from the
//! high watermark, critical at the limit) with the one it last told, records a
//! `mem-pressure` decision for a change and queues one `PORT_EVENT_PRESSURE` on
//! the Port the Domain bound with `PORT_SRC_PRESSURE`. A Domain that is told it
//! crossed into `warning` is given this pass to give memory back (the allocator
//! of `azos_ualloc` drops its quarantine): its storm waits for the next poll,
//! when it is still over the mark if the program did not. A Domain that jumped
//! straight to `critical`, or has no Port bound, is not delayed.
//!
//! **Ages.** A Domain with a frame limit whose charge is above its low
//! watermark has its pages aged every `MM_AGING_INTERVAL_MS`
//! (`pager::age_space`): the Accessed bit of each resident anonymous page is
//! collected and cleared, and the page moves one of four generations older, or
//! back to the youngest when it was used (`azos_mm::aging`). A storm takes the
//! oldest generation first, so the page it compresses is the one idle longest,
//! not the one at the lowest address; a page the compressor gave up on is not
//! offered again until it is used. A Domain below its low watermark is not
//! aged, and the ages it had are dropped (as are those of a Domain that exited or
//! is locked), so the table holds only Domains that can be asked for pages. The pass runs
//! where the storm does, on the reclaim task's CPU.
//!
//! **What a pass does** (`azos_mm::zpool::reclaim_pass` fixes the order, the
//! host rows run it):
//!
//! 0. *Volatile objects.* Memory objects whose owner marked them droppable
//!    (`ATTR_VOLATILE`, `MemCtl::set_volatile`) give their frames up
//!    (`memobj_purge_volatile`): nothing is written or copied, so this is the
//!    cheapest frame there is. Enough to get from now to `MM_RECLAIM_LOW_PCT`
//!    percent in use, and only when the system as a whole is low. A Domain on a
//!    `mem = "locked"` row keeps its objects. One `Rule::Purge` record per object.
//! 1. *Page cache.* Writes back the cache's dirty pages and gives back the
//!    frames of clean ones (`memobj_paged_reclaim`), enough to get from now to
//!    `MM_RECLAIM_LOW_PCT` percent in use. Only when the system as a whole is
//!    low: a Domain over its watermark is not the page cache's doing.
//! 2. *Compression.* Every Domain over its high watermark gets one storm
//!    (`zpool::run_storm`): its resident anonymous pages, coldest generation
//!    first (see *Ages* below), leave their address spaces for the compressed
//!    pool until its charge is back at the low watermark
//!    (`pager::AnonReclaim`). The watermarks are declared
//!    with the Domain's frame limit, from its topology row (`mem_pages`;
//!    `domain::set_limit`), and a Domain without a limit has none. A Domain on
//!    a `mem = "locked"` row is never reclaimed (`PageBudget::storm_begin`).
//!    One `Rule::Compress` record per storm.
//! 3. *Swap.* When a storm ended because the pool had no room, one full pool
//!    segment is written to the swap area (`pager::swap_segment`) and
//!    compression is asked again. A swap file grows here when no slot is free.
//!
//! When memory is not low the poll gives a swap file that has been idle its
//! free tail back (`pager::swap_trim`).
//!
//! **Where it runs.** On a CPU outside `RCU_NOCBS_CPUS` and the topology's
//! `isolcpus` (the lowest one, as the RCU callback task is placed), at a
//! priority outside the real-time band. A pass is also refused if the CPU the
//! task finds itself on (by logical CPU id, which is what the mask is built
//! from) is in that set: the rule is decided on the running CPU's fact, not on
//! the placement alone. Real-time memory is not its business: a real-time row's
//! frames are committed at map time (`mem = "locked"` is never offered), and a
//! real-time task's mappings have no region to take a page from.
//!
//! **A restore is charged back.** The storm gives a stored page's charge back
//! to its Domain; the fault that restores it charges it again, without
//! refusing it (`PageBudget::charge_restore`), through the hook this file
//! installs (`pager::set_restore_hook`).

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use azos_decision::{Rule, Verdict};
use azos_ipc::port::{self as ports, PortEvent};
use azos_mm::budget::{Pressure, StormOutcome};
use azos_mm::pager::{self, Ages, AnonReclaim};
use azos_mm::zpool::{self, Round, Stages};
use azos_mm::{budget, pmm};
use azos_sched::domain;
use azos_sync::qsbr_core::cpu_in_mask;
use azos_sync::SpinLock;

use crate::kprintln;

/// The CPUs that are real-time: `RCU_NOCBS_CPUS | isolcpus` (bit n = CPU n).
static RT_CPUS: AtomicUsize = AtomicUsize::new(0);

/// Address spaces of one Domain a storm takes pages from. A Domain with more
/// is reclaimed from its first ones; the thread groups of one Domain are few.
const ROOTS_PER_DOMAIN: usize = 16;

/// The pages' ages, for every Domain (`azos_mm::aging`). Only the reclaim task
/// touches it, aging and storms alike.
static AGES: SpinLock<Ages> = SpinLock::new(Ages::new());

/// Domains (by slot) that have been told their page-age table overflowed: one
/// line per Domain slot per boot.
static OVERFLOWED: [AtomicBool; domain::DOMAINS_MAX] = [const { AtomicBool::new(false) }; domain::DOMAINS_MAX];

/// Domains (by slot) told `warning` at this poll with a Port to hear it: their
/// storm waits for the next poll. Rewritten by every [`announce_pressure`]; the
/// reclaim task alone.
static DEFER: [AtomicBool; domain::DOMAINS_MAX] = [const { AtomicBool::new(false) }; domain::DOMAINS_MAX];

/// Is the CPU this runs on one of the real-time ones? By the scheduler's
/// logical CPU id: the mask is built from CPU indices, and the architecture's
/// hart id need not equal one.
fn on_rt_cpu() -> bool {
    cpu_in_mask(RT_CPUS.load(SeqCst), azos_sched::smp::current_cpu_id())
}

/// Is memory below the system low watermark: `MM_RECLAIM_HIGH_PCT` percent of
/// the frames or more in use?
fn system_low() -> bool {
    budget::used_at_least(pmm::free_pages(), pmm::total_pages(), azos_limits::MM_RECLAIM_HIGH_PCT as u32)
}

/// Frames to give back to get from now to the low watermark.
fn frames_to_target() -> usize {
    let (total, free) = (pmm::total_pages(), pmm::free_pages());
    let want_free = total.saturating_sub(total * azos_limits::MM_RECLAIM_LOW_PCT as usize / 100) + 1;
    want_free.saturating_sub(free)
}

/// The Domain of the task in slot `idx`, if the slot holds a live task.
fn domain_of(idx: usize) -> Option<domain::Key> {
    azos_sched::tid_for_idx(idx)?;
    Some(azos_sched::task_domain(idx)).filter(|&k| k != domain::NONE)
}

/// Is `idx` the first slot that names the Domain `key`? Each Domain is
/// visited once per pass, at its lowest live slot.
fn first_slot_of(idx: usize, key: domain::Key) -> bool {
    (0..idx).all(|i| domain_of(i) != Some(key))
}

/// Run `f` on each live Domain once, with its key.
fn each_domain(mut f: impl FnMut(domain::Key)) {
    for idx in 0..azos_sched::MAX_TASKS {
        if let Some(key) = domain_of(idx) {
            if first_slot_of(idx, key) {
                f(key);
            }
        }
    }
}

/// Is some Domain over its own high watermark?
fn domain_over_high() -> bool {
    let mut over = false;
    each_domain(|key| over |= domain::budget(key).is_some_and(|b| b.over_high()));
    over
}

/// Tell `key`'s Port its Domain's pressure changed, if it did. Records the
/// change (`Rule::MemPressure`: new level, what is left of the limit, whether a
/// Port was told) and answers whether the Domain was just told `warning` and
/// should be given a poll before its storm.
fn announce_pressure(key: domain::Key) -> bool {
    let Some(b) = domain::budget(key) else { return false };
    let Some((from, to)) = b.pressure_change() else { return false };
    let told = domain::pressure_port(key).is_some_and(|bind| {
        let event = PortEvent { key: bind.key, source_type: ports::PORT_EVENT_PRESSURE, source_id: to as u32, code: 0, cpu: 0 };
        let live = ports::port_queue_event_bound(bind.port, bind.epoch, event);
        if !live {
            // The Port is gone (or its slot reused): nobody to tell any more.
            domain::clear_pressure_port(key, |now| *now == bind);
        }
        live
    });
    let left = u64::from(b.limit().saturating_sub(b.used()));
    azos_decision::record(Rule::MemPressure, Verdict::Admit, key, [to as u64, left, u64::from(told)]);
    told && from == Pressure::Normal && to == Pressure::Warning
}

/// [`announce_pressure`] for every live Domain, and the poll's list of the
/// ones whose storm waits.
fn announce_all() {
    for d in &DEFER {
        d.store(false, SeqCst);
    }
    each_domain(|key| {
        if announce_pressure(key) {
            DEFER[domain::index(key)].store(true, SeqCst);
        }
    });
}

/// Fill `roots` with the page-table roots of the Domain's tasks, each once;
/// how many.
fn roots_of(key: domain::Key, roots: &mut [usize; ROOTS_PER_DOMAIN]) -> usize {
    let mut n = 0;
    for idx in 0..azos_sched::MAX_TASKS {
        if domain_of(idx) != Some(key) {
            continue;
        }
        let Some(root) = azos_sched::tid_for_idx(idx).and_then(azos_sched::task_user_pt).filter(|&r| r != 0) else {
            continue;
        };
        if n < roots.len() && !roots[..n].contains(&root) {
            roots[n] = root;
            n += 1;
        }
    }
    n
}

/// Age the pages of the Domain `key` names (`pager::age_space` over each of its
/// address spaces) and note when. A table that could not hold every chunk is
/// said once per Domain slot: the pages left out are never offered.
fn age_domain(key: domain::Key, now: u64) {
    let Some(b) = domain::budget(key) else { return };
    let owner = domain::index(key);
    let mut roots = [0usize; ROOTS_PER_DOMAIN];
    let n = roots_of(key, &mut roots);
    let tally = {
        let mut ages = AGES.lock();
        ages.begin(owner);
        for &root in &roots[..n] {
            pager::age_space(root, owner, &mut ages);
        }
        ages.end(owner)
    };
    b.note_aged(now);
    if tally.overflow != 0 && !OVERFLOWED[owner].swap(true, SeqCst) {
        azos_drv_sys::kwarn!(
            "[RECLAIM] domain slot {}: {} chunks of pages did not fit the age table ({} pages tracked, MM_AGING_CHUNKS {}): their pages are never reclaimed",
            owner,
            tally.overflow,
            tally.pages,
            azos_mm::aging::CHUNKS
        );
    }
}

/// [`age_domain`] for every live Domain whose pages are due (`aging_due`: a
/// frame limit, a charge above the low watermark, an interval since the last
/// pass). A Domain on a `mem = "locked"` row is never reclaimed, so never aged.
/// The table then drops the chunks of every slot that is not aged at all (gone,
/// locked, at or under its low watermark).
fn age_all(interval: u64) {
    each_domain(|key| {
        let now = azos_drv_sys::timebase::now();
        if !domain::mem_locked(key) && domain::budget(key).is_some_and(|b| b.aging_due(now, interval)) {
            age_domain(key, now);
        }
    });
    // The chunks of a slot no pass will close: its last member exited, or it is
    // locked, or it went back under its low watermark. Without this they hold
    // table entries until some new occupant of the slot is aged.
    AGES.lock().retain_owners(|slot| {
        !domain::slot_mem_locked(slot) && domain::slot_budget(slot).is_some_and(|b| b.wants_aging())
    });
}

/// One storm of the Domain `key` names, if it is due. The pages it stored and
/// whether it ended for want of room in the pool.
fn storm(key: domain::Key, rt_hart: bool) -> Round {
    let none = Round::default();
    let Some(b) = domain::budget(key) else { return none };
    if !b.over_high() || DEFER[domain::index(key)].load(SeqCst) {
        return none;
    }
    let mut roots = [0usize; ROOTS_PER_DOMAIN];
    let n = roots_of(key, &mut roots);
    let owner = domain::index(key);
    // The storm stops at the low watermark; this only bounds a source that
    // keeps offering pages that do not come off (twice what it has to free).
    let max_steps = b.used().saturating_sub(b.low()).saturating_mul(2).max(1);
    let r = {
        let mut ages = AGES.lock();
        let mut source = AnonReclaim::new(&roots[..n], owner, &mut ages);
        zpool::run_storm(b, &mut source, domain::mem_locked(key), rt_hart, max_steps, azos_arch::PAGE_SIZE as u32)
    };
    let locked = canary!("storm-record-locked");
    let _ages = locked.then(|| AGES.lock());
    match r {
        Ok(rec) => {
            let verdict = match rec.outcome() {
                StormOutcome::Paid => Verdict::Admit,
                StormOutcome::Refused => Verdict::Refuse,
                StormOutcome::NoCandidate if locked => Verdict::Refuse,
                // In the ring with no pages, not on the medium: the Domain
                // sits at its watermark with nothing to compress, no refusal.
                StormOutcome::NoCandidate => Verdict::Admit,
            };
            azos_decision::record(Rule::Compress, verdict, key, rec.fields());
            Round { stored: rec.pages, full: rec.full }
        }
        // Below the watermark by now, locked, or a storm of this Domain
        // already running: not a storm, and nothing to record.
        Err(_) => none,
    }
}

/// The stages of a pass, on the running CPU.
struct Pass {
    rt_hart: bool,
}

impl Stages for Pass {
    fn purge(&mut self) {
        if system_low() {
            azos_ipc::memobj::memobj_purge_volatile(frames_to_target(), domain::mem_locked);
        }
    }

    fn page_cache(&mut self) {
        if system_low() {
            azos_ipc::memobj::memobj_paged_reclaim(frames_to_target());
        }
    }

    fn compress(&mut self) -> Round {
        let mut total = Round::default();
        each_domain(|key| {
            let r = storm(key, self.rt_hart);
            total.stored += r.stored;
            total.full |= r.full;
        });
        total
    }

    fn swap(&mut self) -> bool {
        pager::swap_segment(self.rt_hart)
    }

    fn still_low(&mut self) -> bool {
        system_low() || domain_over_high()
    }
}

/// The restore hook: the fault that brought a page back from the pool charges
/// the Domain slot the pool entry was stored for, the one whose storm gave the
/// charge back, and not whoever happens to be running (a kernel-side fault has
/// no task). Never refused: the page is already in memory and the access cannot
/// be undone.
fn charge_restore(owner: usize) {
    if let Some(b) = domain::slot_budget(owner) {
        b.charge_restore(1);
    }
}

fn reclaim_task(_: usize) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let poll = azos_limits::MM_RECLAIM_POLL_MS as u64 * per_ms;
    let aging = azos_limits::MM_AGING_INTERVAL_MS as u64 * per_ms;
    // Compression rounds a pass makes at most: one per swap slot it can fill,
    // and the first.
    let rounds = zpool::SWAP_SEGMENTS as u32 + 1;
    loop {
        let end = azos_drv_sys::timebase::now() + poll;
        while azos_drv_sys::timebase::now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
        announce_all();
        // A real-time CPU: the placement forbids it, the pass refuses it.
        if on_rt_cpu() {
            continue;
        }
        age_all(aging);
        if system_low() || domain_over_high() {
            zpool::reclaim_pass(&mut Pass { rt_hart: false }, rounds);
        } else {
            // Memory is fine: a swap file that has been idle gives back
            // the tail it grew for the last storm.
            pager::swap_trim();
        }
    }
}

/// Create the reclaim task (Kconfig `MM_RECLAIM_COMPRESS`, the module's
/// feature): on the lowest CPU outside the real-time ones. With no such CPU
/// there is no task, said once, and reclaim stays off for the boot.
pub(crate) fn create_reclaim_task() {
    let isolated = azos_topology::get().map_or(0, |t| t.sched_config().isolcpus as usize);
    let rt = azos_sync::qsbr::NOCBS_CPUS | isolated;
    let Some(cpu) = azos_sync::qsbr_core::callback_cpu(azos_percpu::nr_cpu_ids(), rt, azos_percpu::cpu_possible) else {
        azos_drv_sys::kwarn!("[RECLAIM] every CPU is real-time (RCU_NOCBS_CPUS {:#x}, isolcpus {:#x}): no reclaim task", azos_sync::qsbr::NOCBS_CPUS, isolated);
        return;
    };
    RT_CPUS.store(rt, SeqCst);
    pager::set_restore_hook(charge_restore);
    azos_sched::task_create_affinity("reclaim", reclaim_task, 0, azos_limits::MM_RECLAIM_PRIORITY as u32, cpu as i8);
    kprintln!(
        "[SCHED] Created reclaim task (prio {}, CPU {}, poll {} ms, watermarks {}%/{}%)",
        azos_limits::MM_RECLAIM_PRIORITY,
        cpu,
        azos_limits::MM_RECLAIM_POLL_MS,
        azos_limits::MM_RECLAIM_HIGH_PCT,
        azos_limits::MM_RECLAIM_LOW_PCT
    );
}
