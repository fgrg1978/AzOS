// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Runtime gate canaries (Kconfig `CANARY_RUNTIME`).
//!
//! A gate canary breaks one property on purpose so the row that checks the
//! property can be seen to turn red. A cargo-feature canary needs a kernel
//! of its own; a runtime canary is armed for one boot by the kernel command
//! line, `canary=<name>[,<name>]` (`/chosen/bootargs`, QEMU `-append`), so
//! the canary row boots its base row's kernel.
//!
//! **Never on a hot path.** A `canary!` site costs a load and a bit test
//! every time it runs. The syscall, IPC, context-switch and fault paths keep
//! cargo-feature canaries, which compile to nothing.
//!
//! Off (`CANARY_RUNTIME=n`, every deployment profile, and always under the
//! `secure-boot-enforced` feature): `canary!` is a constant `false`, so the
//! parser, the names and the broken branch of every site compile out.
//!
//! A name used in the source must be listed in [`NAMES`]: `canary!("typo")`
//! fails to compile (the compile-error bucket a cargo feature also has).

use core::sync::atomic::{AtomicU64, Ordering};

/// Every runtime canary, by its command-line name. The bit of a name is its
/// index. Add a name here, then use it at its site with `canary!`.
pub(crate) const NAMES: &[&str] = &[
    // boot/early.rs: no task stack gets its guard page
    // (ktest `sched_stack_guards_unmapped`).
    "stack-guard-skip",
    // entry/x86_64/fp.rs: a fork's child gets the initial FP state, not the
    // parent's (ktest `x86_ring3_syscall_fork_fp`, x86_64 only).
    "x86-fork-fp-skip",
    // boot/chaos.rs: `azos_chaos::arm` arms nothing (every `chaos_*` ktest
    // but the parser's).
    "chaos-inert",
    // boot/chaos.rs: an injected frame failure loses a frame
    // (ktest `chaos_frame_alloc_no_leak`).
    "chaos-leak",
    // boot/chaos.rs: no decision record is written (ktests
    // `decision_admission_recorded`, `decision_cap_denial_recorded`,
    // `why_resolves_a_refused_reservation`).
    "decision-skip",
    // entry/x86_64/boot_hooks.rs `mmu_enabled`: the first kernel text page
    // is mapped 1:1 in the low half again (ktest `x86_low_half_maps_no_ram`,
    // x86_64 only).
    "x86-low-alias",
    // entry/x86_64/ext/tsc_watchdog.rs: the TSC is made to run four times the
    // watchdog's bound fast, so the watchdog must demote it (gate row
    // `x86_64: TSC watchdog demotes a skewed TSC (q35)`, x86_64 only).
    "x86-tsc-skew",
    // entry/aarch64/pan_patch.rs: the A64_PAN=probe sites are not rewritten
    // at boot (ktest `a64_pan_sites_patched`, aarch64 only).
    "pan-patch-skip",
    // boot/net.rs: the virtio-net driver rings a doorbell per frame and per
    // RX re-post, batches and NO_NOTIFY ignored (QEMU trace
    // `virtio_queue_notify` count == frames; gate rows `network: TX batch canary`).
    "net-kick-per-frame",
    // boot/sched.rs `rt_console_caller`: a real-time task's console output
    // waits for the wire (ktest `console_rt_lines_only_append`).
    "rt-console-own",
    // The same for the probe's ring-3 console writes only
    // (`uart::console_write_ring3`), after its kernel lines went out.
    "rt-console-own-user",
    // boot/net.rs: every `net_poll` drains the RX ring on its own again, no
    // single owner of the pass (N8; the OTA stress counts resets and lost
    // transfers, `[NET] rx passes: 0 contended`).
    "net-rx-two-consumers",
    // boot/net.rs: the receive pass copies each frame out under the driver
    // lock again, one lock per frame (N2 step 2; `ifconfig`'s rx cycles per
    // frame move back).
    "net-rx-copy",
    // boot/net.rs: with EVENT_IDX negotiated, interrupts are still switched
    // with avail.flags, which the device ignores (`ifconfig` irqs ~ frames).
    "net-event-idx-flags",
    // boot/seams.rs `fsync_request_as`: an io_ring OP_FSYNC flushes inline,
    // the submitter waiting on the device, and completes in the submit
    // (ktest `ioring_fsync_completes_after_flush`; the K1 "before" number).
    "ioring-fsync-inline",
    // boot/seams.rs `sync_all`: no volume is synced, by the power service's
    // `Power::sync` or by the orderly power-off (gate rows `sh: power-off
    // keeps a written file` and its canary).
    "power-off-sync-skip",
    // boot/seams.rs `clean_unmount`: the orderly power-off leaves the boot
    // volume mounted, so it is not marked clean and the next boot checks it
    // (gate row `boot count: orderly reboot`).
    "power-off-unmount-skip",
    // tasks/cam_capture.rs `camera_with_frame`: each consumer of the camera
    // frame ring captures and encodes a frame of its own again, as before
    // B2 (ktest `camera_one_encode_per_frame`).
    "camera-encode-per-consumer",
    // boot/sched.rs `create_ioring_worker_task`: an RT submitter's io_ring
    // file entries run inline again, so a disk boot's RT block-I/O check
    // panics (ktest `ioring_rt_file_entries_never_block`).
    "ioring-rt-inline",
    // kernel/src/ktest.rs (N1): two SpinLocks taken in both orders, then a
    // SpinLock held across a block-layer read; lockdep must report each
    // (ktest `lockdep_lock_order_consistent`,
    // `lockdep_no_spinlock_across_block_io`).
    "lockdep-abba",
    "lockdep-spin-blk",
    // kernel/src/ktest.rs (N1b): another CPU's CpuOwned from interrupt
    // context; a PerCpu reached with preemption on; an IRQ-safe class
    // taken with interrupts on; a SpinLock held twice LOCK_MAX_HOLD_US; a
    // Mutex contended by RT tasks on two CPUs (rule F7). Tests
    // `lockdep_scope_rules`, `lockdep_irq_safe_class_taken_irqsave`,
    // `lockdep_spinlock_hold_bounded`, `lockdep_rt_tasks_share_only_spinlocks`.
    "lockdep-scope-irq",
    "lockdep-scope-preempt",
    "lockdep-irq-inversion",
    "lockdep-hold",
    "lockdep-rt-pi",
    // kernel/src/ktest.rs `preempt_count_survives_irq_nesting`: the timer
    // interrupt's probe keeps the preempt guard it takes, a handler that is
    // not depth-balanced; the non-atomic per-hart count must come out wrong
    // and the test fail (Chain E commit 7).
    "preempt-isr-leak",
    // entry/<isa>/boot_hooks.rs `cpu_features`: the spin extensions are
    // claimed present whatever the CPU reports (RV_ZACAS/RV_ZAWRS,
    // A64_LSE, X86_WAITPKG at probe). riscv64: the execution probe must
    // refute the claim (`[SPIN] ... refuted`); aarch64/x86_64: the first
    // CAS or wait on a CPU without it traps (Undefined Instruction / #UD).
    "spin-ext-claim",
    // boot/entropy.rs `install_entropy`: the CPU's entropy instruction
    // (Zkr seed, RNDRRS, RDSEED/RDRAND) is not drawn, as on a CPU without
    // one: with no virtio-rng the pool stays unseeded. Also what the
    // persisted-seed rows boot with to model a board with no source at all
    // on QEMU `-cpu max` (aarch64 has no switch for FEAT_RNG).
    "entropy-cpu-skip",
    // boot/spin_patch.rs: the SpinWait probe sites are not rewritten at
    // boot; every site stays linked to the fallback (ktest
    // `spin_sites_patched`).
    "spin-patch-skip",
    // kernel/src/ktest.rs `power_off`: the run's verdict is dropped, so a
    // failed run powers off with a clean run's QEMU exit status (riscv64 0,
    // aarch64 0, x86_64 1); the gate's ktest rows must fail on the status
    // (rows `ktest exit status canary (rv|arm|x86)`).
    "ktest-exit-pass",
    // crates/core/ipc/src/irq_bind.rs: the budget rule is off. A throttle
    // leaves an idle interrupt line live and an ACK unmasks a line whose
    // handler's budget is spent (ktest `irq_storm_is_contained`).
    "irq-storm",
    "rcu-idle-qs-skip",
    "rcu-free-no-grace",
    "lockdep-rcu-sleep",
    // kernel/src/panic.rs `quiesce`: the panic handler does not stop the
    // other CPUs (no stop IPI, no wait); it still owns the console. The
    // `panic: other CPUs parked` rows must fail on the parked count.
    "panic-stop-skip",
    // The same, and the console is not claimed either: the panic report goes
    // out while the other CPUs keep printing, as before wave 15 GR5 (row
    // `panic: report not spliced by a console flood` must splice).
    "panic-quiesce-skip",
    // Not a canary: a mode of the `panic-splice-smoke` kernel (the command
    // line is read only here, before paging). Its culprit takes a kernel
    // page fault instead of panicking, so the `[FATAL]` halt path
    // (`panic::halt_begin`) is the one judged (rows `fatal: ...`). With
    // `panic-quiesce-skip` too, that report must splice.
    "panic-splice-fatal",
    // Not a canary either: the `panic-splice-smoke` kernel's handler panics
    // once more inside its report (`panic_splice_smoke::panic_in_report`), so
    // the nested path (`panic::nested`) is the one judged (rows `panic: a
    // panic inside the handler ...`).
    "panic-nested",
    // kernel/src/panic.rs `panic`: a panic inside the handler runs the whole
    // report again, as before 2026-10-24, instead of `nested`'s one line
    // (rows `panic: ... second report canary` must see a second banner).
    "panic-nested-report",
    // crates/core/ipc/src/ep_queue.rs `drain`: a server's death leaves its
    // accepted calls in service, so their callers are never completed
    // (ktest `ipc_server_death_completes_call_peer_died`).
    "ipc-no-peer-died",
    // crates/core/syscall/src/fastpath.rs: the IPC fast path (Kconfig
    // IPC_FASTPATH) is off for the boot, every fast call and reply takes the
    // ordinary dispatch (ktest `ipc_fastpath_taken_when_parked`).
    "ipc-force-slow",
    // crates/core/syscall/src/fastpath.rs: no side of the IPC fast path
    // leaves a resume point (Kconfig IPC_FASTPATH_RESUME), every resume
    // returns where it blocked (ktest `ipc_fastpath_resumes_at_the_point`).
    "ipc-resume-off",
    // crates/core/sched/src/scheduler.rs `direct_switch_block`: a task the
    // fast path parked that resumes where it blocked keeps its resume point
    // (ktests `ipc_fastpath_resume_point_*`).
    "ipc-resume-stale",
    // crates/core/sched/src/sc.rs `pick_in_precedence`: the class walk runs
    // the precedence backwards, idle first (ktest `sched_class_precedence`).
    "sched-class-invert",
    // sched/futex.rs: a futex requeue wakes every waiter on the source word
    // and moves none, the herd (ktest `futex_requeue_wakes_one_not_the_herd`).
    "futex-requeue-wake-all",
    // crates/core/sched/src/asid.rs `prepare_switch`: a hart switching into
    // an ASID of a newer generation does not flush, so a reused ASID meets
    // its previous owner's entries (ktest
    // `asid_rollover_no_stale_translation`).
    "asid-rollover-noflush",
    // crates/core/arch-api/src/tlb_gen.rs `note_ran`: a switch-in records
    // nothing in the per-address-space hart mask, so a shootdown misses the
    // harts that ran the space (ktest `tlb_space_mask_reaches_the_harts_that_ran`).
    "tlb-space-mask-drop",
    // crates/core/sched/src/asid.rs `alloc`: a re-tag ignores the space's
    // ASID record and takes a fresh ASID per thread, so one space carries
    // two ASIDs (ktest `asid_one_per_space_across_rollover`).
    "asid-per-thread",
    // crates/core/ipc/src/cap.rs `clear_all`: a table wipe (a task's exit)
    // does not count its endpoint send capabilities out, so no no-senders
    // notice follows a sender's exit (ktests
    // `ipc_no_senders_on_sender_exit`, `ipc_no_senders_once_after_staggered_exits`).
    "ipc-no-senders-wipe",
    // crates/core/ipc/src/port.rs `port_source_gone`: a destroyed source
    // stays bound and silent, so its waiter times out (ktest
    // `port_source_gone_wakes_the_waiter`).
    "port-no-vanish",
    // crates/core/ipc/src/ep_queue.rs `reply_warrant`: a reply on a warrant
    // whose call was already answered is delivered again
    // (ktest `ipc_reply_warrant_moves_to_worker_and_is_send_once`).
    "ipc-reply-twice",
    // crates/core/syscall/src/ipc_v2.rs `sys_ipc_accept_v2`: every call is
    // read as v1 (no badge, four words, one capability) (ktest
    // `ipc_v2_call_carries_caps_words_and_badge`).
    "ipc-v2-as-v1",
    // crates/core/ipc/src/ep_queue.rs `take_locked`: the v1 accept takes a
    // v2 call (four words, first capability) instead of refusing it (ktest
    // `ipc_v2_call_refused_by_v1_accept`).
    "ipc-v1-takes-v2",
    // crates/core/sync/src/waitgraph.rs `walk`: every chain walk stops after
    // one owner (ktests `waitgraph_transitive_chain`,
    // `waitgraph_dl_donor_and_attr_changed`, `waitgraph_depth_cap`).
    "pi-depth-1",
    // crates/core/sync/src/kmutex.rs `unlocked_for_io`: the mutex stays held
    // across the device wait, rule F1 (ktest `kmutex_unlocked_for_io`).
    "kmutex-io-held",
    // crates/core/sync/src/kmutex.rs `unlock_slow`: a release frees the word
    // with a waiter queued, so a newcomer overtakes it (KMUTEX_STEAL_RULE;
    // ktest `kmutex_steal_rule_holds_for_top_waiter`, WAIT_GRAPH y).
    "kmutex-steal-any",
    // crates/core/sync/src/kmutex.rs `lock_slow`: a held-back newcomer parks
    // on its word alone, after a widened window, so the word's ABA loses the
    // wake (ktest `kmutex_held_back_newcomer_is_in_the_graph`, WAIT_GRAPH y).
    "kmutex-park-aba",
    // crates/core/sched/src/classes.rs `on_task_exit`: the exit path keeps
    // the task's wait-graph state until its slot is reused (ktest
    // `waitgraph_exit_clears_state`, WAIT_GRAPH y).
    "exit-keeps-graph",
    // crates/core/sync/src/waitgraph.rs `task_exit`: an owner exiting with
    // waiters only detaches its objects, no OwnerDiedHook wakes them (ktest
    // `kmutex_owner_died_wakes_waiter`, WAIT_GRAPH y).
    "owner-died-silent",
    // crates/core/sync/src/held.rs `held_forget`: a task that exits
    // holding a Mutex stays counted in the held table (ktest
    // `kmutex_dead_holder_leaves_the_held_table`).
    "held-keeps-dead",
    // crates/core/sync/src/claim.rs `held_forget`: a task that exits owning
    // a claim stays counted in the F1 table (ktest
    // `claim_dead_owner_leaves_the_held_table`).
    "claim-held-keeps-dead",
    // crates/core/sync/src/claim.rs `acquire`: the owner keeps the claim's
    // exchange mutex, so a Mutex is held across its device waits, rule F1
    // (ktest `claim_holds_no_mutex_across_a_device_wait`).
    "claim-mutex-held",
    // crates/core/sync/src/pi_futex.rs `block_commit`: a PI futex waiter is
    // enqueued but the walk is dropped, so the word's owner is never boosted
    // (the RT-vs-normal inversion program; same binary on Linux; ktest
    // `futex_pi_boosts_the_owner` under WAIT_GRAPH + FUTEX_PI).
    "futex-pi-no-edge",
    // crates/core/sync/src/pi_futex.rs `exit_handover`: an owner that exits
    // holding a PI word with waiters leaves them asleep (ktest
    // `futex_pi_owner_exit_hands_over` under WAIT_GRAPH + FUTEX_PI).
    "futex-pi-exit-silent",
    // crates/core/sched/src/futex.rs `cmp_requeue_pi`: FUTEX_CMP_REQUEUE_PI
    // takes no PI word for the top waiter and wakes every waiter as a plain
    // wake, so FUTEX_WAIT_REQUEUE_PI returns EAGAIN owning nothing (ktest
    // `futex_requeue_pi_hands_the_mutex_over` under WAIT_GRAPH + FUTEX_PI).
    "futex-requeue-pi-plain",
    // crates/core/sched/src/futex.rs `cmp_requeue_pi`: FUTEX_CMP_REQUEUE_PI
    // enqueues no waiter on the PI word's wait-graph object by proxy; each
    // wakes requeued and runs its own LOCK_PI (N10d), so the owner is not
    // boosted while they sleep (ktest `futex_requeue_pi_hands_the_mutex_over`
    // under WAIT_GRAPH + FUTEX_PI).
    "futex-requeue-pi-no-proxy",
    // boot/sched.rs `console_drop_veto`: the ktest's probe task may not wait
    // for the console, so its line is dropped into the full deferred buffer
    // as before XC (ktest `console_task_line_waits_never_drops`).
    "console-drop",
    // crates/core/sched/src/classes.rs `dl_above_band`: a reservation is
    // ranked by its level again, so DL runs above the band only inside its
    // level (ktest `sched_dl_above_rt`).
    "sched-dl-in-level",
    // crates/core/syscall/src/schedctl.rs: an RT or DL binding skips the
    // time-warrant check, so a task promotes itself (ktest
    // `schedctl_self_promotion_refused`).
    "schedctl-no-warrant",
    // crates/core/sched/src/signal_state.rs `detach`: a process-directed
    // signal pending on a non-leader thread is dropped with the thread
    // (ktest `signal_retarget_on_thread_detach`).
    "sig-exit-drop",
    // crates/core/sched/src/classes.rs `graph_floored`: a wait-graph boost
    // lifts a ring-3 owner past RT_PRIORITY_THRESHOLD (ktest
    // `waitgraph_ring3_owner_floored`, WAIT_GRAPH y).
    "pi-ring3-unclamped",
    // crates/core/mm/src/vmm.rs `canary_private_l1`: a root built after the
    // boot gets a private copy of the first kernel-only slot's L1 instead of
    // a link (ktest `kernel_half_shared_by_every_root`, riscv64 only).
    "kernel-l1-copy",
    // crates/core/ipc/src/fastcall.rs `CallEdge::lend`: a fast call takes no
    // wait-graph edge, so its server is not boosted (ktest
    // `waitgraph_ipc_call_boosts_server`, WAIT_GRAPH y).
    "ipc-call-no-edge",
    // boot/early.rs (ktest.rs `lockdep_early_abba`): two SpinLocks taken in
    // both orders before the scheduler, an ABBA lockdep reports from boot
    // (ktest `lockdep_boot_phase_clean`).
    "lockdep-early-abba",
    // crates/core/actuation/src/logger.rs `logger_flush_now`: every flush
    // is held back while a latching SAFETY_ESTOP is pending, so its durable
    // write is deferred past the kill (rows `safety: kill switch (gpio)`,
    // no durable marker, and `safety: latch survives reboot`).
    "log-latch-defer",
    // crates/fs/fs/src/fat32.rs `ClaimPi::donate`: a FAT32 claim waiter
    // lends its priority to nobody, so the claim owner keeps its own while
    // the waiter blocks (ktest `fat_claim_waiter_donates_to_owner`).
    "claim-no-donate",
    // crates/core/sched/src/process.rs `kernel_ctx_addr_ok`: a task with no
    // user page table is no longer refused a user-range VA by the copy
    // helpers (ktest `copyout_refused_in_kernel_context`).
    "copyout-raw-kernel-ctx",
    // boot/sched.rs `task_release_all_resources`: a dying commander's wheels
    // are stopped after its writeback and device releases, not first (ktest
    // `motor_commander_exit_stops_its_wheels`).
    "commander-exit-late",
    // boot/early.rs: the device tree blob is not taken out of the page
    // allocator (ktest `mm_fdt_reserved`, riscv64 and aarch64).
    "fdt-reserve-skip",
    // entry/x86_64/arch_entry.rs `secondary_tlb_online`: an AP raises the
    // shootdown's scan bound but publishes no CR3, so a CPU that has only run
    // kernel tasks is no target of a kernel-wide shootdown or of
    // `icache_sync_all` (ktest `tlb_kernel_shootdown_names_every_online_cpu`,
    // x86_64 only).
    "x86-tlb-join-skip",
];
const _: () = assert!(NAMES.len() <= azos_limits::CANARY_RUNTIME_MAX as usize);

/// Words of the armed set: Kconfig `CANARY_RUNTIME_MAX` bits, rounded up.
const WORDS: usize = (azos_limits::CANARY_RUNTIME_MAX as usize).div_ceil(64);

/// The one task `rt-console-own` applies to (the ktest
/// `console_rt_lines_only_append`'s probe stores its own tid); `0`: none.
/// Only that task, so every other RT line of the boot (rt-motor's) keeps
/// the fixed path and the canary fails one test, not the run.
pub(crate) static RT_CONSOLE_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The one task `console-drop` applies to (the ktest
/// `console_task_line_waits_never_drops`'s probe stores its own tid); `0`:
/// none. Every other line of the boot keeps the wait.
pub(crate) static CONSOLE_DROP_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Built in, and not refused by a signed image or a release build (Kconfig
/// already makes CANARY_RUNTIME depend on BUILD_TYPE_DEV).
pub(crate) const ON: bool = azos_limits::CANARY_RUNTIME
    && azos_limits::BUILD_TYPE_DEV
    && !cfg!(feature = "secure-boot-enforced");

/// The armed canaries, one bit per [`NAMES`] index (bit `i % 64` of word
/// `i / 64`). Written once on the boot hart before any other hart or task
/// runs.
static ARMED: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The bit of `name`; a compile error (const evaluation) for a name not in
/// [`NAMES`].
pub(crate) const fn index(name: &str) -> usize {
    let mut i = 0;
    while i < NAMES.len() {
        if str_eq(NAMES[i], name) {
            return i;
        }
        i += 1;
    }
    panic!("canary!: name not listed in kernel/src/canary_rt.rs NAMES");
}

/// Is the canary in word `word`, bit `mask` armed? `canary!` passes both as
/// constants, so a site is one load and one bit test.
#[inline(always)]
pub(crate) fn armed(word: usize, mask: u64) -> bool {
    ON && ARMED[word].load(Ordering::Relaxed) & mask != 0
}

/// `canary!("name")`: is runtime canary `name` armed on this boot? A constant
/// `false` when `CANARY_RUNTIME` is off. Not for a hot path (module doc).
macro_rules! canary {
    ($name:literal) => {{
        const BIT: usize = $crate::canary_rt::index($name);
        const WORD: usize = BIT / 64;
        const MASK: u64 = 1 << (BIT % 64);
        $crate::canary_rt::armed(WORD, MASK)
    }};
}

/// Arm the canaries the command line names. Called once from `early_main`,
/// on the boot hart, before paging; `read` is the ISA's
/// `ArchEntry::kernel_cmdline` (device tree on riscv64/aarch64, PVH on x86_64).
pub(crate) fn arm_from_cmdline(read: impl FnOnce(&mut [u8]) -> Option<usize>) {
    if ON {
        arm(read);
    }
}

#[inline(never)]
fn arm(read: impl FnOnce(&mut [u8]) -> Option<usize>) {
    let mut line = [0u8; azos_limits::KERNEL_CMDLINE_MAX as usize];
    let Some(n) = read(&mut line) else {
        return;
    };
    let n = n.min(line.len());
    let Some(list) = line[..n].split(|&b| b == b' ').find_map(|w| w.strip_prefix(b"canary=")) else {
        return;
    };
    let mut bits = [0u64; WORDS];
    for name in list.split(|&b| b == b',').filter(|w| !w.is_empty()) {
        match NAMES.iter().position(|k| k.as_bytes() == name) {
            Some(i) => bits[i / 64] |= 1 << (i % 64),
            None => azos_drv_sys::kwarn!(
                "[CANARY] canary={} ignored: not a runtime canary",
                core::str::from_utf8(name).unwrap_or("?")
            ),
        }
    }
    for (w, b) in ARMED.iter().zip(bits) {
        w.store(b, Ordering::Relaxed);
    }
    for (i, k) in NAMES.iter().enumerate() {
        if bits[i / 64] & (1 << (i % 64)) != 0 {
            azos_drv_sys::kwarn!("[CANARY] armed: {} (this boot breaks its property on purpose)", k);
        }
    }
}
