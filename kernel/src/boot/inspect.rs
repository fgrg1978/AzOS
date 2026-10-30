// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's introspection tree (Kconfig INSPECT): what the scheduler,
//! memory and the decision recorder count, published as read-only memory.
//!
//! `install_inspect` creates the two regions (the public MemObj and, with
//! INSPECT_ADMIN_PAGES, the admin one), formats them (`crates/core/inspect`),
//! builds the tree, fills it once, and starts the `inspect` task, which
//! samples the counters every INSPECT_REFRESH_MS. A refresh is a task and not
//! a timer hook on purpose: the census walks every task slot, which is more
//! than a timer ISR may spend on each hart's tick.
//!
//! The regions are Contig MemObjs created read-only for any mapper: the
//! kernel writes them through its direct map.
//!
//! # How a task reaches them
//!
//! Like a kernel sensor stream, by a capability its topology row declares:
//! `MemObj inspect.public` (`READ|MAP`), and `MemObj inspect.admin` (`READ|MAP`) for a
//! task that also holds the full task view, the admin warrant
//! (`azos_ipc::inspect_region`). The task finds the `Cap<Shm>` with
//! `SYS_CAP_LOOKUP(Shm, SHM_INSPECT_PUBLIC | SHM_INSPECT_ADMIN)` and maps it
//! read-only; from then on every read is a load. The lookup and the map are
//! the only calls, and neither is per read. `TOOLBOX.ELF`'s `inspect` applet
//! is the first holder.
//!
//! There is no hook in the vDSO page for it: a word there that names a region
//! would not be authority (the capability is), and the task that reads the
//! tree finds the capability by its key, so the word would have no reader.
//!
//! Before the regions are published, `install_inspect` opens each one the way
//! a ring-3 reader does (`Reader::open`, then a lookup and a read) and
//! publishes nothing for a region that fails: a task is never handed a
//! region its own library would refuse.
//!
//! Public tree:
//!
//! ```text
//! inspect/{format_version, refresh_ms, refreshes}
//! sched/{tasks_ready, tasks_blocked, tasks_running,
//!        cpu/cpuN/{runq_len, moved_in, moved_out, rt_load_ppm, rt_band_ppm},
//!        blocked_on/{...}, rt/{...},
//!        balance/{...}}
//! memory/{page_size, pages_total, pages_free, pages_used, peak_user_pages,
//!         quota_refusals, domains}
//! decisions/{recorded, deny_dropped}
//! system/, fs/, drivers/, chaos/                                            (inspect_views.rs)
//! devices/<handle>/{name, identity, state, driver, base, size, irq}          (hwbus.rs)
//! metrics/{trace, sched, energy, net, memory, decisions, syscalls, storage}   (inspect_metrics.rs)
//! soc/, thermal/, latency/                                                   (soc.rs, thermal.rs, lat_trace.rs)
//! ```
//! Admin tree: `sched/tasks/<row>/{tid, name, state, priority, parent}`
//! (`inspect_tasks`), `wake/{now_us, rN}` (WAKE_RING_ENTRIES: the wake log
//! with the task IDs the public region does not carry,
//! `inspect_metrics::build_admin_wake`) and `decisions/records/<n>`
//! (`inspect_views::build_admin`). Its shape is built once, as the public
//! one's is; it is never rebuilt.
//!
//! # When a value is current
//!
//! What a reader acts on is written where it changes, before the change's
//! caller goes on, and a reader never waits for a refresh: the task list at
//! each task made, exited, freed or re-linked (`azos_sched::set_task_view_hook`),
//! the view regions' endpoints at each change in the endpoint pool and the
//! components' `start` when the boot launcher finds an image missing
//! (`inspect_views`), a decision record where it is recorded. The writes are
//! atomic stores under each node's seqlock, with no other lock: the shapes are
//! fixed, so they may run under the scheduler's and the pool's locks.
//!
//! The counters (every value of the public region, the wake log, and a listed
//! task's state and effective priority, which move at every switch) are
//! sampled by the `inspect` task every INSPECT_REFRESH_MS, the stamp of each
//! region its refresh count. The latency smoke, which reads back what the
//! tracer published, refreshes first ([`refresh_now`]).
//!
//! There is no per-CPU dispatch counter in the scheduler yet, so the per-CPU
//! number is the length of the CPU's run queue, under that name. `moved_in` and
//! `moved_out` are the fair tasks the load balancer (SCHED_BALANCE) moved onto
//! and off the CPU; `balance/` has the totals and the level they crossed.
//! `rt_load_ppm` and `rt_band_ppm` are the deadline reservations admitted on
//! the CPU and the band's part of them (`rt::hart_load`, what the next
//! admission is tested against), the kernel's own included: the IRQ thread's
//! on the boot CPU with IRQ_THREADED.

use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use azos_inspect::{Builder, Class, Error, NodeId, Reader, Region, Writer};
use azos_ipc::memobj::{self, MemPerms, MemSpec};
use azos_sync::SpinLock;

use super::inspect_metrics::{self, AdminWake, Num};
use super::inspect_tasks::{self, Task, TaskList};
/// The scheduler's blocked-task reasons, in `task_census` order.
const BLOCKED_ON: [&str; 5] = ["fast_client", "fast_server", "timer", "wait_queue", "other"];
const RT_STATS: [&str; 4] = ["band_throttles", "cbs_exhausted", "admitted", "refused"];
/// `fairq::BalanceStats`, in the order `refresh` writes them.
const BALANCE_STATS: [&str; 8] =
    ["pulled", "pushed", "within_cache", "across_node", "across_package", "idle_tries", "idle_empty", "busy"];

/// The nodes the refresh writes.
struct Ids {
    refreshes: NodeId,
    ready: NodeId,
    blocked: NodeId,
    running: NodeId,
    runq: [NodeId; azos_sched::MAX_CPUS],
    blocked_on: [NodeId; BLOCKED_ON.len()],
    rt: [NodeId; RT_STATS.len()],
    balance: [NodeId; BALANCE_STATS.len()],
    moved: [(NodeId, NodeId); azos_sched::MAX_CPUS],
    /// Per CPU: the admitted deadline density and its band part.
    rt_load: [(NodeId, NodeId); azos_sched::MAX_CPUS],
    pages_total: NodeId,
    pages_free: NodeId,
    pages_used: NodeId,
    peak_user_pages: NodeId,
    quota_refusals: NodeId,
    domains: NodeId,
    recorded: NodeId,
    deny_dropped: NodeId,
}

struct State {
    public: Writer<'static>,
    /// The admin region and its wake log's nodes.
    admin: Option<(Writer<'static>, AdminWake)>,
    ids: Ids,
    cpus: usize,
    refreshes: u64,
}

/// Handed from `install_inspect` (boot, no task yet) to the first refresh,
/// which moves it under [`STATE`].
static HANDOFF: SpinLock<Option<State>> = SpinLock::new(None);
/// The writers and the ids, for the `inspect` task and for [`refresh_now`]:
/// task context only (a refresh walks every task slot).
static STATE: azos_sync::kmutex::Mutex<Option<State>> = azos_sync::kmutex::Mutex::new(None);

/// Run `f` on the published state, if there is one.
fn with_state(f: impl FnOnce(&mut State)) {
    let mut g = STATE.lock();
    if g.is_none() {
        *g = HANDOFF.lock_irqsave().take();
    }
    if let Some(st) = g.as_mut() {
        f(st);
    }
}

/// Refresh every counter now rather than at the next period. Task context.
/// Nothing when the tree is off. The latency smoke's, which reads back what
/// the tracer published.
#[cfg(all(feature = "lat-trace", feature = "lat-smoke"))]
pub(crate) fn refresh_now() {
    with_state(|st| st.refresh());
}

/// Per task slot: its row of the task list, and its writer's flag
/// (`inspect_tasks::TaskList`).
static ROW_OF: [AtomicU8; azos_sched::MAX_TASKS] = [const { AtomicU8::new(0) }; azos_sched::MAX_TASKS];
static ROW_BUSY: [AtomicU8; azos_sched::MAX_TASKS] = [const { AtomicU8::new(0) }; azos_sched::MAX_TASKS];

/// The admin region's task list, published once at boot and never changed:
/// the scheduler's hook reads it with no lock.
static TASKS: AtomicPtr<TaskList<'static>> = AtomicPtr::new(core::ptr::null_mut());

fn task_list() -> Option<&'static TaskList<'static>> {
    // SAFETY: set once, to a leaked allocation that lives for good.
    unsafe { TASKS.load(Ordering::Acquire).as_ref() }
}

/// The scheduler's row of slot `i`, as the list shows it.
fn slot_row(i: usize) -> Option<Task> {
    azos_sched::task_row_at(i)
        .map(|r| Task { tid: r.tid, parent: r.parent, priority: r.priority, state: r.state, name: r.name })
}

/// `azos_sched::set_task_view_hook`: slot `i` changed. Any context.
fn task_changed(i: usize) {
    if let Some(l) = task_list() {
        l.note(i, &slot_row);
    }
}

/// A published region: its packed MemObj reference, its size, and the same
/// words the writer holds, for the reader check.
#[derive(Clone, Copy)]
struct Span {
    obj: u32,
    bytes: usize,
    words: Region<'static>,
}

/// The public region, once published: what [`public_str`] reads.
#[cfg(feature = "lat-trace")]
static PUBLIC_SPAN: SpinLock<Option<Span>> = SpinLock::new(None);

/// The string at `path` of the public tree, read as a ring-3 reader reads it
/// (`Reader::open`, a lookup, a read): for the latency smoke, which checks
/// what the tracer published. `None` when the tree is off or has no such
/// string.
#[cfg(feature = "lat-trace")]
pub(crate) fn public_str(path: &str) -> Option<azos_inspect::Str> {
    let at = (*PUBLIC_SPAN.lock_irqsave())?;
    let r = Reader::open(at.words, Class::Public).ok()?;
    match r.read(r.lookup(path).ok()??).ok()? {
        azos_inspect::Value::Str(s) => Some(s),
        _ => None,
    }
}

/// One kernel-owned region of `pages` pages, formatted as `class`.
fn make_region(pages: usize, class: Class) -> Option<(Writer<'static>, Span)> {
    let (obj, phys) = memobj::memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadOnly, false))?;
    let base = azos_mm::addr::phys_to_virt(phys) as *const u8;
    let bytes = pages * azos_arch::PAGE_SIZE;
    // SAFETY: the object's frames are the kernel's for good (it is never
    // freed) and mapped in the direct map; every access to them is an atomic
    // word (this writer, and the readers' loads).
    let region = unsafe { Region::from_raw(base, bytes) }.ok()?;
    Some((Writer::init(region, class).ok()?, Span { obj, bytes, words: region }))
}

/// Open `at` as a ring-3 reader would and read `probe`, a node the first
/// refresh has written.
fn reader_check(at: Span, class: Class, probe: &str) -> bool {
    let Ok(r) = Reader::open(at.words, class) else { return false };
    matches!(r.lookup(probe), Ok(Some(id)) if r.read(id).is_ok())
}

/// The tasks the admin region at `at` lists, read back as a ring-3 reader
/// reads them (the rows whose TID is not 0): the boot line says the list it
/// just filled is there.
fn listed(at: Span) -> usize {
    let Ok(r) = Reader::open(at.words, Class::Admin) else { return 0 };
    let Ok(Some(dir)) = r.lookup("sched/tasks") else { return 0 };
    let mut n = 0;
    let _ = r.children(dir, &mut |info, _| {
        if matches!(r.lookup_in(info.id, "tid"), Ok(Some(id)) if matches!(r.read(id), Ok(azos_inspect::Value::U64(t)) if t != 0)) {
            n += 1;
        }
    });
    n
}

/// Build, fill and publish the tree, and start the refresh task. Called once
/// from `kernel_main`, before the secondary harts start and before any task is
/// seeded a capability.
pub(crate) fn install_inspect(num_cpus: usize) {
    let pages = azos_limits::INSPECT_PUBLIC_PAGES as usize;
    let Some((public, pub_at)) = make_region(pages, Class::Public) else {
        azos_drv_sys::kwarn!("[INSPECT] no public region ({} pages): the tree stays off", pages);
        return;
    };
    let admin_pages = azos_limits::INSPECT_ADMIN_PAGES as usize;
    let admin = if admin_pages == 0 {
        None
    } else {
        let a = make_region(admin_pages, Class::Admin);
        if a.is_none() {
            azos_drv_sys::kwarn!("[INSPECT] no admin region ({} pages)", admin_pages);
        }
        a
    };
    let cpus = num_cpus.clamp(1, azos_sched::MAX_CPUS);
    let mut ids = None;
    let built = public.rebuild(|b| {
        ids = Some(build_public(b, cpus)?);
        Ok(())
    });
    let Some(ids) = ids else {
        azos_drv_sys::kwarn!("[INSPECT] the public tree does not fit {} pages ({:?}): the tree stays off", pages, built);
        return;
    };
    // The admin tree's shape, once: the task rows, the wake log, the records.
    let mut shape = inspect_tasks::Shape::EMPTY;
    #[cfg(any(feature = "decisions", feature = "decisions-durable"))]
    let mut records = [NodeId::ROOT; super::inspect_views::DECISION_ROWS];
    let admin = admin.map(|(w, at)| {
        let mut wake = AdminWake::NONE;
        let r = w.rebuild(|b| {
            inspect_tasks::build(b, azos_sched::MAX_TASKS, &mut shape)?;
            wake = inspect_metrics::build_admin(b)?;
            #[cfg(any(feature = "decisions", feature = "decisions-durable"))]
            super::inspect_views::build_admin(b, &mut records)?;
            Ok(())
        });
        if let Err(e) = r {
            azos_drv_sys::kwarn!(
                "[INSPECT] the admin tree does not hold {} task rows, the wake log and the decisions ({:?}): \
                 raise INSPECT_ADMIN_PAGES", azos_sched::MAX_TASKS.min(inspect_tasks::ROWS), e);
        }
        ((w, wake), at)
    });
    let (admin, admin_at) = match admin {
        Some((w, at)) => (Some(w), Some(at)),
        None => (None, None),
    };
    let mut st = State { public, admin, ids, cpus, refreshes: 0 };
    st.refresh();
    // The check a ring-3 reader's open would make, before any capability to
    // the regions exists.
    if !reader_check(pub_at, Class::Public, "sched/tasks_ready") {
        azos_drv_sys::kwarn!("[INSPECT] the public region does not open as a reader: the tree stays off");
        return;
    }
    let admin_at = admin_at.filter(|at| {
        let ok = reader_check(*at, Class::Admin, "sched/tasks");
        if !ok {
            azos_drv_sys::kwarn!("[INSPECT] the admin region does not open as a reader: it is not granted");
        }
        ok
    });
    azos_ipc::inspect_region::publish(pub_at.obj, admin_at.map(|at| at.obj));
    #[cfg(feature = "lat-trace")]
    {
        *PUBLIC_SPAN.lock_irqsave() = Some(pub_at);
    }
    // The view regions of the rows that declare one (`inspect_views`).
    super::inspect_views::install_views();
    azos_ipc::cap_seed::set_shm_inspect_minter(azos_ipc::kregion::seed_mint_any);
    let (nodes, node_cap, words, word_cap) = st.public.usage();
    azos_drv_sys::kprintln!(
        "[INSPECT] tree published: public region {} KiB ({}/{} nodes, {}/{} value words), reader check ok",
        pub_at.bytes / 1024, nodes, node_cap, words, word_cap);
    if let (Some(at), Some((w, _))) = (admin_at, st.admin.as_ref()) {
        // The task list and the records, written where they change from now
        // on: the hook first, then every slot as it stands (a task made
        // between the two is written twice, never missed).
        let list: &'static TaskList<'static> =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(TaskList::new(*w, shape, &ROW_OF, &ROW_BUSY)));
        TASKS.store(list as *const TaskList<'static> as *mut TaskList<'static>, Ordering::Release);
        azos_sched::set_task_view_hook(task_changed);
        for i in 0..azos_sched::MAX_TASKS {
            task_changed(i);
        }
        #[cfg(any(feature = "decisions", feature = "decisions-durable"))]
        super::inspect_views::install_records(*w, records);
        let (nodes, node_cap, words, word_cap) = w.usage();
        azos_drv_sys::kprintln!(
            "[INSPECT] admin region {} KiB ({} task rows, {} tasks listed, {}/{} nodes, {}/{} value words), granted against the task view, reader check ok",
            at.bytes / 1024, shape.rows(), listed(at), nodes, node_cap, words, word_cap);
    }
    *HANDOFF.lock_irqsave() = Some(st);
    // Off the real-time CPUs, as the thermal and reclaim tasks are: a refresh
    // walks every task slot.
    let isolated = azos_topology::get().map_or(0, |t| t.sched_config().isolcpus as usize);
    let rt = azos_sync::qsbr::NOCBS_CPUS | isolated;
    let cpu = azos_sync::qsbr_core::callback_cpu(azos_percpu::nr_cpu_ids(), rt, azos_percpu::cpu_possible);
    if cpu.is_none() {
        azos_drv_sys::kwarn!(
            "[INSPECT] every CPU is real-time (RCU_NOCBS_CPUS {:#x}, isolcpus {:#x}): the refresh task is not pinned",
            azos_sync::qsbr::NOCBS_CPUS, isolated);
    }
    azos_sched::task_create_affinity(
        "inspect", inspect_task, 0, azos_sched::DEFAULT_PRIORITY + 4, cpu.map_or(-1, |c| c as i8));
}

fn inspect_task(_arg: usize) {
    loop {
        azos_syscall::sleep::sleep_ms(azos_limits::INSPECT_REFRESH_MS as u64);
        with_state(|st| st.refresh());
    }
}

azos_ktest::ktest_late! {
    fn inspect_refresh_leaves_interrupts_as_they_were() {
        use azos_arch::Interrupts as _;
        let mut ran = false;
        with_state(|st| {
            st.refresh();
            ran = true;
        });
        // Masked, the runner would fail every later test for sleeping with
        // interrupts off, so the state is put back before the verdict.
        let on = azos_sync::preempt::irqs_enabled();
        if !on {
            azos_arch::ARCH.enable_all();
        }
        if !ran {
            return Err("no inspect state to refresh");
        }
        if on { Ok(()) } else { Err("a refresh returned with interrupts off") }
    }
}

fn build_public(b: &mut Builder<'_, 'static>, cpus: usize) -> Result<Ids, Error> {
    let root = NodeId::ROOT;
    let meta = b.dir(root, "inspect")?;
    b.u64(meta, "format_version", azos_inspect::FORMAT_VERSION as u64)?;
    b.u64(meta, "refresh_ms", azos_limits::INSPECT_REFRESH_MS as u64)?;
    let refreshes = b.u64(meta, "refreshes", 0)?;

    let sched = b.dir(root, "sched")?;
    let ready = b.u64(sched, "tasks_ready", 0)?;
    let blocked = b.u64(sched, "tasks_blocked", 0)?;
    let running = b.u64(sched, "tasks_running", 0)?;
    let cpu_dir = b.dir(sched, "cpu")?;
    let mut runq = [NodeId::ROOT; azos_sched::MAX_CPUS];
    let mut moved = [(NodeId::ROOT, NodeId::ROOT); azos_sched::MAX_CPUS];
    let mut rt_load = [(NodeId::ROOT, NodeId::ROOT); azos_sched::MAX_CPUS];
    for (i, slot) in runq.iter_mut().enumerate().take(cpus) {
        let c = b.dir(cpu_dir, &Num::name("cpu", i as u64))?;
        *slot = b.u64(c, "runq_len", 0)?;
        moved[i] = (b.u64(c, "moved_in", 0)?, b.u64(c, "moved_out", 0)?);
        rt_load[i] = (b.u64(c, "rt_load_ppm", 0)?, b.u64(c, "rt_band_ppm", 0)?);
    }
    let by = b.dir(sched, "blocked_on")?;
    let mut blocked_on = [NodeId::ROOT; BLOCKED_ON.len()];
    for (slot, name) in blocked_on.iter_mut().zip(BLOCKED_ON) {
        *slot = b.u64(by, name, 0)?;
    }
    let rt_dir = b.dir(sched, "rt")?;
    let mut rt = [NodeId::ROOT; RT_STATS.len()];
    for (slot, name) in rt.iter_mut().zip(RT_STATS) {
        *slot = b.u64(rt_dir, name, 0)?;
    }

    let bal_dir = b.dir(sched, "balance")?;
    let mut balance = [NodeId::ROOT; BALANCE_STATS.len()];
    for (slot, name) in balance.iter_mut().zip(BALANCE_STATS) {
        *slot = b.u64(bal_dir, name, 0)?;
    }

    let mem = b.dir(root, "memory")?;
    b.u64(mem, "page_size", azos_arch::PAGE_SIZE as u64)?;
    let pages_total = b.u64(mem, "pages_total", 0)?;
    let pages_free = b.u64(mem, "pages_free", 0)?;
    let pages_used = b.u64(mem, "pages_used", 0)?;
    let peak_user_pages = b.u64(mem, "peak_user_pages", 0)?;
    let quota_refusals = b.u64(mem, "quota_refusals", 0)?;
    let domains = b.u64(mem, "domains", 0)?;

    let dec = b.dir(root, "decisions")?;
    let recorded = b.u64(dec, "recorded", 0)?;
    let deny_dropped = b.u64(dec, "deny_dropped", 0)?;

    // The system's identity and counters; the topology's wiring is in the
    // view regions (`inspect_views::install_views`).
    if let Err(e) = super::inspect_views::build(b, root) {
        azos_drv_sys::kwarn!(
            "[INSPECT] the system subtrees do not fit {} pages ({:?}): raise INSPECT_PUBLIC_PAGES",
            azos_limits::INSPECT_PUBLIC_PAGES, e);
    }
    if let Err(e) = super::hwbus::inspect_build(b, root) {
        azos_drv_sys::kwarn!(
            "[INSPECT] the devices subtree does not fit {} pages ({:?}): raise INSPECT_PUBLIC_PAGES",
            azos_limits::INSPECT_PUBLIC_PAGES, e);
    }

    // The metrics subtree is last: if the region is short, it is what is cut,
    // not the tree above. A cut subtree is not published (its nodes stay
    // zero), and the boot says so.
    if let Err(e) = inspect_metrics::build(b, cpus) {
        azos_drv_sys::kwarn!(
            "[INSPECT] the metrics subtree does not fit {} pages ({:?}): raise INSPECT_PUBLIC_PAGES",
            azos_limits::INSPECT_PUBLIC_PAGES, e);
    }

    // The USB listing: a fixed-shape subtree, values rewritten on refresh.
    #[cfg(feature = "usb-host")]
    if let Err(e) = super::usb::inspect_build(b, root) {
        azos_drv_sys::kwarn!(
            "[INSPECT] the usb subtree does not fit {} pages ({:?}): raise INSPECT_PUBLIC_PAGES",
            azos_limits::INSPECT_PUBLIC_PAGES, e);
    }
    #[cfg(feature = "soc")]
    if let Err(e) = super::soc::inspect_build(b, root) {
        azos_drv_sys::kwarn!("[INSPECT] the soc subtree does not fit ({:?})", e);
    }
    #[cfg(feature = "energy")]
    if let Err(e) = super::thermal::inspect_build(b, root) {
        azos_drv_sys::kwarn!("[INSPECT] the thermal subtree does not fit ({:?})", e);
    }
    #[cfg(feature = "lat-trace")]
    if let Err(e) = crate::lat_trace::inspect_build(b, root) {
        azos_drv_sys::kwarn!("[INSPECT] the latency subtree does not fit ({:?})", e);
    }

    Ok(Ids {
        refreshes, ready, blocked, running, runq, blocked_on, rt, balance, moved, rt_load, pages_total, pages_free,
        pages_used, peak_user_pages, quota_refusals, domains, recorded, deny_dropped,
    })
}

impl State {
    /// Rewrite every value from its source; rebuild the admin task list.
    fn refresh(&mut self) {
        self.refreshes += 1;
        let (w, ids) = (&self.public, &self.ids);
        let mut bad = 0u32;
        let mut put = |id: NodeId, v: u64| {
            if w.set_u64(id, v).is_err() {
                bad += 1;
            }
        };
        put(ids.refreshes, self.refreshes);
        let (ready, blocked, running, per_cpu, _, _, by_reason) = azos_sched::task_census();
        put(ids.ready, ready as u64);
        put(ids.blocked, blocked as u64);
        put(ids.running, running as u64);
        for (id, n) in ids.runq.iter().zip(per_cpu).take(self.cpus) {
            put(*id, n as u64);
        }
        for (id, n) in ids.blocked_on.iter().zip(by_reason) {
            put(*id, n as u64);
        }
        let (throttles, exhausted, admitted, refused, _, _) = azos_sched::rt::stats();
        for (id, n) in ids.rt.iter().zip([throttles, exhausted, admitted, refused]) {
            put(*id, n as u64);
        }
        let b = azos_sched::scheduler::fairq::balance_stats();
        let hops = b.by_hop;
        for (id, n) in ids.balance.iter().zip([
            b.pulled, b.pushed, hops[0], hops[1], hops[2], b.idle_tries, b.idle_empty, b.busy,
        ]) {
            put(*id, n as u64);
        }
        for (cpu, (i, o)) in ids.moved.iter().enumerate().take(self.cpus) {
            let (moved_in, moved_out) = azos_sched::scheduler::fairq::balance_cpu_moves(cpu);
            put(*i, moved_in as u64);
            put(*o, moved_out as u64);
        }
        for (cpu, (t, b)) in ids.rt_load.iter().enumerate().take(self.cpus) {
            let l = azos_sched::rt::hart_load(cpu);
            put(*t, l.total_ppm as u64);
            put(*b, l.band_ppm as u64);
        }
        let total = azos_mm::pmm::total_pages();
        let free = azos_mm::pmm::free_pages();
        put(ids.pages_total, total as u64);
        put(ids.pages_free, free as u64);
        put(ids.pages_used, total.saturating_sub(free) as u64);
        put(ids.peak_user_pages, azos_sched::mm_peak_global() as u64);
        put(ids.quota_refusals, azos_sched::mm_quota_refusals() as u64);
        put(ids.domains, azos_sched::domain::count() as u64);
        put(ids.recorded, azos_decision::total());
        put(ids.deny_dropped, azos_decision::deny_dropped_total());
        bad += inspect_metrics::refresh(w);
        bad += super::inspect_views::refresh(w);
        bad += super::hwbus::inspect_refresh(w);
        #[cfg(feature = "usb-host")]
        {
            bad += super::usb::inspect_refresh(w);
        }
        #[cfg(feature = "soc")]
        {
            bad += super::soc::inspect_refresh(w);
        }
        #[cfg(feature = "energy")]
        {
            bad += super::thermal::inspect_refresh(w);
        }
        #[cfg(feature = "lat-trace")]
        {
            bad += crate::lat_trace::inspect_refresh(w);
        }
        w.stamp(self.refreshes);
        if let Some((a, wake)) = &self.admin {
            bad += inspect_metrics::refresh_admin(a, wake);
            if let Some(l) = task_list() {
                l.resample(&slot_row);
                if l.cut_unsaid() {
                    azos_drv_sys::kwarn!(
                        "[INSPECT] more tasks than the {} rows of the task list: the newest are not listed",
                        azos_sched::MAX_TASKS.min(inspect_tasks::ROWS));
                }
            }
            a.stamp(self.refreshes);
        }
        if bad != 0 {
            azos_drv_sys::kwarn!("[INSPECT] {} values were not published", bad);
        }
    }
}
