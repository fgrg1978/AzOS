// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel tasks `kernel_main` creates once the scheduler is initialised
//! and before any secondary CPU runs, in its order: two stretches, with the
//! scheduler smokes between them (`smokes::spawn_sched_smokes`) and the
//! system smokes after (`smokes::spawn_system_smokes`).

use crate::*;

/// Number of worker tasks for the SMP stress test (Kconfig BOOT_SELFTESTS).
#[cfg(feature = "boot-selftests")]
const NUM_WORKERS: usize = 15;
/// Task slots the stress workers never take: what the rest of boot still
/// creates after them (kernel tasks, topology rows, the user shell).
#[cfg(feature = "boot-selftests")]
const WORKER_POOL_RESERVE: usize = 16;

/// The online-CPU estimate, one idle task per CPU, aarch64's scheduler
/// self-tests, sched-hooks smoke and system watchdog, and the recovery
/// console. Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn create_first_tasks(num_cpus: usize) {
    // Tell the scheduler how many CPUs are *expected* to come online so the
    // task_create calls below — which run before any secondary hart exists —
    // distribute evenly across all of them. This is an optimistic estimate
    // from the DTB, not a confirmation: secondary harts aren't started until
    // wake_harts() runs near the end of this function (after the UART SMP
    // lock is enabled and every task is enqueued — per-CPU ready queues
    // can't be touched cross-CPU once a hart is live). Once wake_harts()
    // reports how many harts actually started, NUM_ONLINE_CPUS is corrected
    // down to the real count so that later task creation (e.g. fork()) never
    // targets a hart that failed to start.
    azos_sched::smp::NUM_ONLINE_CPUS.store(num_cpus, Ordering::SeqCst);

    // One idle task per hart, each pinned to its own CPU.
    //
    // **WHY per-CPU and not the single CPU-0 idle this used to create.**
    // Ready queues are per-CPU, so a hart with an empty queue has nothing to
    // pick. `do_schedule` answers that by returning — and its comment says
    // "caller will idle", which is true for the timer-tick caller and **false
    // for `block_current`**, which returns through the syscall to ring 3. A
    // task that has already published `Blocked` therefore keeps executing: not
    // queued, not current anywhere the wakers look, and nobody will ever
    // dispatch it. Measured before this change: of 7850 blocks, **7830** hit
    // that return with the current task already `Blocked` (counters under
    // `ipc-census`; K-C26 genesis 2).
    //
    // With an idle per hart the queue is never empty, so `do_schedule` always
    // has something to switch to and a blocked task always yields its hart.
    // `IDLE_PRIORITY` is the lowest, so these never starve real work.
    //
    // `num_cpus` here is the DTB's optimistic count, taken before
    // `wake_harts()`. An idle pinned to a hart that never starts is harmless:
    // the K-C24 rescue moves tasks off dead harts, and a rescued idle is just
    // one more lowest-priority task.
    for cpu in 0..num_cpus {
        azos_sched::task_create_affinity(
            "idle", idle_task, 0, azos_sched::IDLE_PRIORITY, cpu as i8);
    }
    kprintln!("[SCHED] Created {} idle tasks (one per hart)", num_cpus);

    #[cfg(target_arch = "aarch64")]
    {
        // **Both on hart 0, pinned.** The property is two equal-priority
        // tasks sharing ONE hart and taking turns only because the scheduler
        // preempts them. Unpinned, placement put A on hart 0 and B on hart 1
        // and each ran alone: on `--features qemu` at `-smp 2` with the
        // ipctest disk, B sat on hart 1 behind `behavior` (priority 14,
        // rescued there from the absent hart 2) until A had finished all 60
        // iterations; without a disk B finished before A's first iteration.
        // Every such boot printed "did not interleave" (8/8 and 2/2). The rows
        // that passed booted without `qemu`: they passed by placement.
        // Boot self-tests (Kconfig BOOT_SELFTESTS), as the probe below.
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create_affinity(
            "phase3-a", phase3_task_a, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create_affinity(
            "phase3-b", phase3_task_b, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
        #[cfg(feature = "boot-selftests")]
        kprintln!("[SCHED] task A and task B created (priority {}, round-robin, \
                   {} iterations each, both on hart {})",
                   azos_sched::DEFAULT_PRIORITY, PHASE3_TARGET_ITERS, PHASE3_HART);

        // `install_sched_hooks`'s marker cluster — see that function's own doc.
        // Off by default (`sched-hooks-smoke` feature); compiles to nothing
        // otherwise. Spawned HERE, next to `phase3-a`/`phase3-b`, not right
        // after `install_sched_hooks()` above (riscv64's placement). Measured,
        // not assumed, that the earlier site does not work: spawned there, the
        // waitqueue task read back `counter at wake = 0` on every boot —
        // `wait()` returning long before the producer had done any work —
        // while the cap marker next to it read back correctly
        // from that same early point. THE CAUSE was not isolated (this ISA's
        // boot has enough moving parts between that point and this one — SMP
        // bring-up, GIC, the timer tick going live — that several are
        // plausible candidates and none was singled out); moved to here, all
        // three read back correctly on every boot tried (the gate row was
        // `aarch64: sched hooks`; the ktest `sched_hooks_wired` now).
        #[cfg(all(feature = "sched-hooks-smoke", not(feature = "ktest")))]
        sched_hooks_smoke::spawn();

        // Migration probe (item 7 of this task's brief) — a task that blocks
        // and is woken repeatedly, the ONLY placement path that can move an
        // unpinned task between cores (`crates/core/sched::scheduler::
        // wake_target_cpu` re-runs `find_best_cpu` on every wake;
        // `task_yield()` alone never does — see that function's own doc
        // comment). `phase3_task_a`/`b` above never block, so they cannot
        // migrate and are not evidence either way.
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create(
            "smp-migrate-probe", aarch64_migrate_probe_task, 0, azos_sched::DEFAULT_PRIORITY);
        #[cfg(feature = "boot-selftests")]
        kprintln!("[SCHED] Created smp-migrate-probe task");

        // Phase 16: the system watchdog — the SAME task riscv64 runs, from the
        // same shared `create_sys_wdt_task` (see its doc for the pin argument,
        // and `install_ota_boot_good_hook` above in the disk-gated block for the
        // half of this that closes the OTA rollback).
        //
        // HERE and not earlier, for two reasons that both have to hold:
        //   * it is a task, so it belongs with the other `task_create*` calls,
        //     after `NUM_ONLINE_CPUS` is published (a pin computed before that
        //     publish would be placed against a CPU count of 1) and before
        //     `wake_harts` below, whose rescue step can re-home anything the
        //     optimistic pre-wake placement stranded;
        //   * the hook it fires is installed further up this function, so
        //     "hook before spawn" holds on this ISA too.
        //
        // `num_cpus` is the same optimistic pre-`wake_harts` count the idle
        // tasks above are placed against, so a hart that fails to come up is
        // handled by that rescue and not by this line.
        create_sys_wdt_task(place::pin(place::SYS_WDT));
    }

    // Recovery console task: priority 13 (high normal — above workers, runs in RT task sleep gaps).
    // No CPU pin so it works on both 1-CPU and 4-CPU QEMU.
    //
    // It is the RECOVERY console. It parks until no user shell has
    // the console (`console_mode::wait_for_recovery`), and under
    // `CONSOLE_LOCKDOWN` or `RECOVERY_CONSOLE=n` it is not created at all.
    if azos_limits::CONSOLE_LOCKDOWN {
        kprintln!("[CONSOLE] lockdown: no kernel console task");
    } else if !azos_limits::RECOVERY_CONSOLE {
        kprintln!("[CONSOLE] no recovery console (RECOVERY_CONSOLE=n)");
    } else {
        azos_sched::task_create("recovery", recovery_task, 0,
                                azos_limits::TASK_RECOVERY_PRIORITY as u32);
        kprintln!("[SCHED] Created recovery task");
    }
}

/// The second stretch of task creation: the write-back, io_ring, RCU, reclaim
/// and thermal tasks, the disk and input interrupt wiring, the boot self-test
/// tasks and the vector state, the robot's control and sensor tasks, the
/// network tasks, the OTA boot-good hook and sys-wdt, the stress workers, the
/// CONFIG.INI truncation warnings, autorun, the interrupt thread, the driver
/// supervisor and the kernel-placed driver hosts, and the boot launcher.
/// Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn create_service_tasks(hart_id: usize) {
    // Create IPC/signal/service demo task (Phase 8).
    // Wave 15 (WRITEBACK): FAT32's write-back task, on every ISA whose boot
    // mounted the volume (Kconfig `FS_WRITEBACK`; a no-op with it off).
    if azos_fs::fat32_mounted() {
        create_fs_writeback_task();
    }
    // K1: the io_ring worker, which runs an RT submitter's file entries.
    create_ioring_worker_task();
    // N4: the RCU callback task (Kconfig RCU_QSBR; nothing with it off).
    create_rcu_callback_task();
    // The memory reclaim task (Kconfig MM_RECLAIM_COMPRESS; nothing with it off),
    // placed outside the real-time CPUs the topology has just published.
    #[cfg(feature = "mm-reclaim")]
    create_reclaim_task();
    // Kconfig ENERGY (and THERMAL): applies the governor's choices, reads the
    // zones and caps the clocks (nothing on a board with neither a clock to
    // move nor a zone).
    #[cfg(feature = "energy")]
    boot::thermal::create_task();
    // Wave 15: disk completions by interrupt (every ISA), once the
    // scheduler exists to put waiters to sleep.
    wire_virtio_blk_irq();
    // The SD/eMMC host's sleepers too (the boards' boot card, the QEMU row's).
    #[cfg(any(feature = "vf2", feature = "k1", feature = "mmc-flush-smoke"))]
    wire_mmc_irq();
    #[cfg(feature = "mmc-flush-smoke")]
    mmc_irq_smoke_spawn();
    // Kconfig DRV_NVME: the NVMe driver's waiters sleep too.
    #[cfg(feature = "nvme")]
    wire_nvme_irq();
    // Kconfig DRV_AHCI: the AHCI driver's waiters sleep too.
    #[cfg(feature = "ahci")]
    wire_ahci_irq();
    // Kconfig USB_XHCI / USB_DWC2: the `usb` task drains the controller the bus bound.
    #[cfg(feature = "usb-hc")]
    boot::usb::start_usb_task();
    // Keyboards and mice on virtio-input (Kconfig `DRV_VIRTIO_INPUT`).
    #[cfg(feature = "virtio-input")]
    wire_virtio_input_irq();
    // The PC's PS/2 keyboard and mouse (Kconfig `DRV_PS2`, x86_64).
    #[cfg(feature = "ps2")]
    wire_ps2_irq();
    // The virtio-sound device (Kconfig `DRV_VIRTIO_SND`): the bus bound it in
    // the settle stage (virtio-mmio) or the PCI stage; its sleep and, for
    // virtio-mmio, its line are wired now.
    #[cfg(feature = "virtio-snd")]
    boot::snd_irq::wire_virtio_snd_irq();
    // Boot self-test (Kconfig BOOT_SELFTESTS): the kernel's own byte pipe.
    #[cfg(feature = "boot-selftests")]
    azos_sched::task_create("ipc-demo", ipc_demo_task, 0, azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "boot-selftests")]
    kprintln!("[SCHED] Created ipc-demo task");

    // RVV vector-state sizing: read this hart's real `vlenb` (CSR 0xC22,
    // bytes per vector register) and either enable rvv_ctx_save/
    // rvv_ctx_restore at that width or refuse — the alternative to refusing
    // is the overrun this check replaces: rvv_ctx_save/restore used to
    // assume VLEN=128 unconditionally, and running that under QEMU's
    // `vlen=256` (the SpacemiT K1/X60's real width — `k1` composes `rvv`)
    // took a `[FATAL] Kernel page fault`, verified by hand 2026-09-26. Must
    // run before any task can be dispatched: context_switch_rvv.S calls
    // rvv_ctx_save/rvv_ctx_restore on every switch unconditionally, and both
    // no-op safely on the uninitialized sentinel until this runs (see
    // `VLEN_BYTES`'s doc comment in fp.rs) — this print is what keeps that
    // silent fallback from being silent in practice.
    // Kconfig `RV_V` = probe on a hart without V: `vlenb` would trap, so
    // the vector state stays uninitialised and the scalar kernels run.
    #[cfg(all(target_arch = "riscv64", feature = "rvv"))]
    #[cfg_attr(not(feature = "boot-selftests"), allow(unused_variables))]
    let rvv_state_saved = if azos_arch::fp::usable() {
        match azos_arch::fp::init_vector_state() {
            Ok(vlenb) => {
                kprintln!("[RVV] vlenb={} — vector state save/restore enabled", vlenb);
                true
            }
            Err(vlenb) => {
                kprintln!(
                    "[RVV] vlenb={} exceeds MAX_VLEN_BYTES={} — vector state save disabled, V not enabled for tasks",
                    vlenb, azos_arch::fp::MAX_VLEN_BYTES);
                false
            }
        }
    } else {
        kprintln!("[RVV] no V on this hart — scalar kernels, no vector state");
        false
    };

    // Create RVV benchmark task (Phase 11; Kconfig BOOT_SELFTESTS). Only where
    // every switch saves the vector state: the bench is preemptible.
    #[cfg(all(target_arch = "riscv64", feature = "rvv", feature = "boot-selftests"))]
    if rvv_state_saved {
        azos_sched::task_create("rvv-bench", rvv_bench_task, 0, azos_sched::DEFAULT_PRIORITY);
        kprintln!("[SCHED] Created rvv-bench task");
    }

    // RVV isolation probe: canary for the rvv_ctx_save/restore TID-vs-
    // offset-120 bug (crates/core/arch-riscv64/src/fp.rs). Two tasks, pinned to
    // the SAME hart (0) so a build that indexes VEC_STATES[] by hart id
    // instead of TID aliases them onto one slot and corrupts both, fill
    // v0-v31 with distinct patterns, yield to each other a few times, then
    // verify their own pattern survived.
    #[cfg(all(target_arch = "riscv64", feature = "rvv", feature = "rvv-isolation-probe"))]
    {
        azos_sched::task_create_affinity(
            "rvv-iso-0", rvv_isolation_probe_task, 0,
            azos_sched::DEFAULT_PRIORITY, 0);
        azos_sched::task_create_affinity(
            "rvv-iso-1", rvv_isolation_probe_task, 1,
            azos_sched::DEFAULT_PRIORITY, 0);
        kprintln!("[SCHED] Created rvv-iso-0/rvv-iso-1 tasks (RVV isolation probe) [hart 0]");
    }

    // Phase G1: behavior engine (runs without ML too — L0, L2, L3 work).
    // Pinned (Kconfig TASK_BEHAVIOR_PLACE: CPU 2 of 4) away from rt-motor +
    // flight-ctrl (prio 8, rt.0) and imu + sensor-ahrs (prio 8/14, rt.1),
    // as on hart 2 with those on harts 0 and 1. Without affinity the
    // scheduler was leaving `behavior` competing for hart 3 against
    // every other prio-14+ task, and the brain TCP dial never fired
    // inside the E2E window. Hart 2 is otherwise idle so we get
    // immediate scheduling.
    #[cfg(feature = "use-robot")]
    azos_sched::task_create_affinity(
        "behavior", behavior_task, 0,
        azos_sched::BEHAVIOR_PRIORITY, place::pin(place::BEHAVIOR));
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Created behavior task (subsumption L0-L3) [hart {}]", place::pin(place::BEHAVIOR));
    // Wave 15 (B1): the behavior task only queues its brain-link messages;
    // this task puts them on the socket. Below behavior on its hart, so a
    // closed TCP window never delays the subsumption loop.
    #[cfg(feature = "use-robot")]
    azos_sched::task_create_affinity(
        "brain-tx", brain_tx_task, 0,
        azos_limits::BRAIN_TX_PRIORITY as u32, place::pin(place::BEHAVIOR));
    // C1: camera frames on a brain connection of their own, only when
    // CONFIG.INI sets `behavior_camera_port` (applied at boot, above). Below
    // behavior on the same hart, so a camera send, capture or handshake never
    // delays the behavior loop.
    #[cfg(feature = "use-robot")]
    if azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed) != 0 {
        CAMERA_TX_TASK.store(true, core::sync::atomic::Ordering::Release);
        azos_sched::task_create_affinity(
            "camera-tx", camera_tx_task, 0,
            azos_sched::BEHAVIOR_PRIORITY + 1, place::pin(place::BEHAVIOR));
        kprintln!("[SCHED] Created camera-tx task (camera connection) [hart {}]", place::pin(place::BEHAVIOR));
    }
    // Hart 0: dedicated real-time control — PID loop pinned to avoid jitter.
    // The safety loops are exempt from the RT band budget (owner decision,
    // wave 11 SCHED-RT): never throttled when the band runs out.
    #[cfg(feature = "use-robot")]
    let rt_motor = azos_sched::task_create_affinity("rt-motor", rt_motor_task, 0,
        azos_sched::RT_MOTOR_PRIORITY, place::pin(place::CONTROL));
    #[cfg(feature = "use-robot")]
    azos_sched::rt::exempt_from_band_cap(rt_motor);
    // RT7: a panic in a safety task is never contained (panic policy).
    #[cfg(feature = "use-robot")]
    panic::register_safety_task(rt_motor, "rt-motor");
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Created rt-motor task (MotorCmd→PID→PWM + watchdog) [hart {}]", place::pin(place::CONTROL));

    // Dedicated sensor tasks (AQ0: IO-wait, priority-separated)
    #[cfg(feature = "use-robot")]
    let imu = azos_sched::task_create_affinity("imu", imu_task, 0,
        azos_sched::RT_MOTOR_PRIORITY, place::pin(place::SENSING)); // RT priority
    #[cfg(feature = "use-robot")]
    azos_sched::rt::exempt_from_band_cap(imu);
    // Wave 15 (S1): the imu task only queues its reads; where a controller
    // driver is compiled (DesignWare: VisionFive 2, Pi 5, Intel LPSS; the
    // K1's SpacemiT) this task runs the controller's steps (board validation
    // pending; the QEMU simulation completes at submit).
    #[cfg(all(feature = "use-robot", any(feature = "i2c-dw", feature = "k1")))]
    {
        install_i2c_service_kick();
        azos_sched::task_create("i2c-svc", i2c_service_task, 0,
            azos_limits::I2C_SERVICE_PRIORITY as u32);
    }
    #[cfg(feature = "use-robot")]
    azos_sched::task_create("odom", odom_task, 0, azos_sched::BEHAVIOR_PRIORITY);
    #[cfg(feature = "use-robot")]
    azos_sched::task_create("sensor-slow", sensor_slow_task, 0, azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Sensor tasks: imu(RT,100Hz) odom(50Hz) sensor-slow(10Hz)");

    // Fast-IPC slot census, diagnostic only. Gated so production builds and
    // ordinary QEMU runs never create the task at all.
    #[cfg(feature = "ipc-census")]
    {
        azos_sched::task_create(
            "ipc-census", ipc_census_task, 0, azos_sched::DEFAULT_PRIORITY);
        kprintln!("[SCHED] Created ipc-census task (ipc-trace: fast-IPC slot states)");
    }

    // Phase U1: dedicated network polling task — decouples net I/O from behavior loop.
    //
    // History: previously pinned to hart 2 alongside behavior to keep TCP
    // responsive when harts 0/1 are saturated by RT tasks (rt-motor, imu,
    // sensor-ahrs, flight-ctrl).  Empirically that pairing inverted: net-poll
    // was then a busy yield-loop (NET_POLL_PRIORITY=12, lower-number =
    // higher), so it never blocked and starved behavior (prio 14) on hart 2 —
    // behavior managed only ~3 iterations in 40 s under QEMU TCG bench
    // (vs the 10 Hz design point = 400 iterations).  Moved to hart 3 which
    // has no other pinned system task — same TCP responsiveness goal, no
    // starvation of behavior's control loop.  autorun (when present) also
    // lives on hart 3: it is NOT short-lived (it exec's into a ring-3 program
    // that serves requests forever) and yielding is not enough — see the
    // AUTORUN_PRIORITY block below for the starvation that caused and why the
    // loader is no longer created inside the real-time band. `net_poll_task`
    // itself stopped being a yield-loop in `b912aa2` (2026-09-03): it blocks
    // on a 1 kHz timer, so the argument above is history, not current
    // behaviour.
    // One placement on every ISA: Kconfig TASK_NET_POLL_PLACE (`last`, the
    // last CPU of this boot). riscv64 used to pin a literal 3, wrong under
    // `-smp` 1 or 2 and on the K1's 8 harts; aarch64's `-smp` varies across
    // gate rows (the `aarch64 network: NIC found + MAC` row expects CPU 1 at
    // `-smp 2`).
    // Kconfig NET: the wait hooks always, the task only once a NIC is bound
    // (`start_net_poll`; the USB network function creates it when it comes).
    #[cfg(feature = "net")]
    install_net_hooks();
    #[cfg(feature = "net")]
    start_net_poll();
    // Kconfig IOMMU_*: the log of what the IOMMU refused, drained by a task
    // (the unit's own interrupts stay off). Only when a unit is up.
    #[cfg(any(feature = "iommu-riscv", feature = "iommu-smmuv3", feature = "iommu-vtd", feature = "iommu-amdvi"))]
    if boot::iommu_up() {
        azos_sched::task_create("iommu-faults", boot::fault_task, 0,
                                azos_limits::TASK_IOMMU_FAULTS_PRIORITY as u32);
        kprintln!("[SCHED] Created iommu-faults task (every {} ms)", azos_limits::IOMMU_FAULT_POLL_MS);
    }
    #[cfg(feature = "net")]
    start_net_clients();

    // Phase I1: sensor + AHRS fusion task (~100 Hz).
    // Hart 1: sensor fusion — dedicated to avoid contention with motor PID on hart 0.
    #[cfg(feature = "use-robot")]
    azos_sched::task_create_affinity("sensor-ahrs", sensor_ahrs_task, 0,
        azos_sched::SENSOR_AHRS_PRIORITY, place::pin(place::SENSING));
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Created sensor-ahrs task (IMU+baro+GPS→AHRS→channels) [hart {}]", place::pin(place::SENSING));

    // Phase J+K: flight controller task (mixer + PID + failsafe).
    // Hart 0: flight controller — same hart as rt-motor for cache locality.
    #[cfg(feature = "use-robot")]
    let flight_ctrl = azos_sched::task_create_affinity("flight-ctrl", flight_control_task, 0,
        azos_sched::FLIGHT_CTRL_PRIORITY, place::pin(place::CONTROL));
    #[cfg(feature = "use-robot")]
    azos_sched::rt::exempt_from_band_cap(flight_ctrl);
    #[cfg(feature = "use-robot")]
    panic::register_safety_task(flight_ctrl, "flight-ctrl");
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Created flight-ctrl task (PID→mixer→ESC + failsafe) [hart {}]", place::pin(place::CONTROL));

    // Phase L: telemetry task (attitude + GPS → UDP).
    #[cfg(feature = "use-robot")]
    azos_sched::task_create("telemetry", telemetry_task, 0, azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "use-robot")]
    kprintln!("[SCHED] Created telemetry task (channels→UDP)");

    // The OTA boot-good mark, then the task that fires it — both shared with
    // aarch64's own `kernel_main` now, see each function's doc.
    //
    // Pinned, not placed. Default placement is half of why this task never ran
    // under load — see the measured matrix at `WATCHDOG_PRIORITY`, where
    // either the pin or the priority raise is enough on its own. Hart 2's only
    // other resident is `behavior` at 14, so a watchdog at 11 is always at the
    // top of that queue when its timer fires. Both changes are kept so that
    // neither is the single thing standing between this task and silence.
    install_ota_boot_good_hook();
    //
    // aarch64 created it above (in its own block, before its probes). Every
    // other ISA here the same watchdog, and with it the `log-flush` task it
    // owns (the periodic flush request, the deferred block I/O, LOCKDEP=y's
    // printer), on the same CPU (Kconfig TASK_SYS_WDT_PLACE). Before
    // `wake_secondaries` below, after `NUM_ONLINE_CPUS` (aarch64's reasons).
    #[cfg(not(target_arch = "aarch64"))]
    create_sys_wdt_task(place::pin(place::SYS_WDT));

    // Create stress-test workers (a boot self-test: Kconfig BOOT_SELFTESTS;
    // off, the boot creates none). find_least_loaded_cpu() distributes them
    // evenly across num_cpus CPUs (4 tasks per CPU for 16 total = 15+idle).
    // SKIP workers in test scenarios that need IO bandwidth (OTA E2E, etc.) —
    // 15 busy workers at DEFAULT_PRIORITY starve the listener task on a 4-CPU
    // QEMU and the test never sees any OTA data on the wire.
    // Skip the 15 DEFAULT_PRIORITY stress workers when *either* the
    // OTA receiver or the behavior (brain) server is configured. Same
    // reasoning in both cases: 15 busy-yield workers on 4 QEMU CPUs
    // pile up enough scheduler load to starve the listener / TCP-dial
    // task and the test never sees its event on the wire — the E2E
    // wheeled run found `behavior_task` never reached its loop because
    // 15 workers + ml-demo on CPU 3 kept the run queue full.
    #[cfg(feature = "boot-selftests")]
    let skip_for_ota = azos_config::CFG_OTA_AUTO_RECV_PORT
        .load(Ordering::Relaxed) != 0;
    #[cfg(feature = "boot-selftests")]
    let skip_for_brain = azos_config::BEHAVIOR_SERVER_PORT
        .load(Ordering::Relaxed) != 0;
    // `bench-minimal` boots only what a measurement needs, and these workers
    // are created with `try_task_create_affinity`, which the bench-minimal
    // gate in `task_create_affinity` never sees. On x86_64 (-smp 1) they were
    // still yielding when vsbench started: its first `sched-yield` batch
    // round-robined through them (4459 instructions per yield against a
    // per-call p50 of 256), which then made `switch-loaded` REFUSED.
    #[cfg(feature = "boot-selftests")]
    let skip_for_bench = cfg!(feature = "bench-minimal");
    #[cfg(feature = "boot-selftests")]
    if skip_for_ota || skip_for_brain || skip_for_bench {
        let reason = if skip_for_bench { "bench-minimal" }
            else if skip_for_ota { "ota_auto_recv_port" } else { "behavior_server_port" };
        kprintln!("[SCHED] Skipping {} stress-test workers ({} set)", NUM_WORKERS, reason);
    } else {
        // Optional load, so sized to what the pool can spare: the rest of
        // boot (kernel tasks, topology rows, the user shell) creates its
        // tasks with the infallible `task_create`, and a small profile
        // (embedded: MAX_TASKS = 32) panicked "task pool full" once wave 11
        // added the recovery console (gate 199).
        let spare = azos_sched::free_task_slots().saturating_sub(WORKER_POOL_RESERVE);
        let n = NUM_WORKERS.min(spare);
        for i in 0..n {
            if azos_sched::try_task_create_affinity("worker", worker_task, i,
                azos_sched::DEFAULT_PRIORITY, -1).is_none() {
                break;
            }
            kprintln!("[SCHED] Created worker task {}", i);
        }
        if n < NUM_WORKERS {
            kprintln!("[SCHED] {} of {} stress-test workers created ({} task slots kept free)",
                n, NUM_WORKERS, WORKER_POOL_RESERVE);
        }
    }
    kprintln!();

    // A truncated CONFIG.INI value means the kernel is running a configuration
    // nobody wrote. Say so before anything acts on it — the symptom otherwise
    // shows up somewhere unrelated (a cut autorun path reads as "file not
    // found", a cut IP as an unreachable host).
    {
        let cut = azos_config::cfg_truncated_count();
        if cut > 0 {
            azos_drv_sys::kwarn!("[CONFIG] WARNING: {} value(s) in CONFIG.INI exceeded {} \
                       bytes and were truncated — the running config is NOT \
                       what is on disk", cut, azos_config::MAX_VAL);
        }
        // The same failure one level up: lines past MAX_ENTRIES are dropped.
        // A 32-line preamble pushes `autorun` out, and a missing `autorun`
        // reads as "none configured" rather than "your file did not fit".
        let dropped = azos_config::cfg_dropped_count();
        if dropped > 0 {
            azos_drv_sys::kwarn!("[CONFIG] WARNING: {} line(s) in CONFIG.INI did not fit \
                       in {} entries and were dropped — the running config is \
                       NOT what is on disk", dropped, azos_config::MAX_ENTRIES);
        }
    }

    // Phase U4: autorun ELF — if CONFIG.INI has `autorun=<path>`, spawn a
    // task that loads and exec's that ELF at boot (e.g. brain client).
    // Kconfig AUTORUN: without it the key is not read.
    #[cfg(feature = "autorun")]
    if let Some(path) = azos_config::cfg_get(b"autorun") {
        if !path.is_empty() {
            // Copy path to a static buffer so the autorun task can access it.
            let len = path.len().min(AUTORUN_PATH_MAX - 1);
            let buf = unsafe { &mut *(&raw mut AUTORUN_PATH) };
            buf[..len].copy_from_slice(&path[..len]);
            buf[len] = 0;
            // Autorun is a one-shot ELF loader that must run promptly at boot,
            // then exec_user replaces it with the user process. It was given
            // priority 10 to escape the starvation it saw at DEFAULT_PRIORITY
            // on whatever hart it landed on, and pinned to hart 3 at the same
            // time. Two things were wrong with that pairing, and together they
            // killed the network:
            //
            //   * 10 is INSIDE the hard-real-time band
            //     (`RT_PRIORITY_THRESHOLD` = 12), where the tick refuses to
            //     preempt (`scheduler.rs`, `is_rt_priority` arm). So the task
            //     ran until it yielded, and `sys::yield_now()` re-selects the
            //     highest-priority ready task — itself.
            //   * The comment below it promised "once it exec's, the user
            //     process inherits a normal priority". Nothing does that:
            //     `exec_user` never touches `priority`, and the scheduler
            //     exposes no setter. The ring-3 program keeps the loader's.
            //
            // Net effect on the one configuration a real robot runs in — disk
            // present, so CONFIG.INI names an autorun, AND a NIC — was that
            // `net-poll` (priority 12, also hart 3) never ran a single
            // iteration. The RX ring was never drained: no ARP reply learned,
            // no SYN ever emitted, brain link permanently down. No gate
            // scenario caught it because every networked scenario boots
            // diskless and every disk-backed scenario boots without a NIC.
            //
            // So the loader runs at a normal priority, which is what the old
            // comment claimed and what a ring-3 program must have: pinned to
            // hart 3 it competes only with `net-poll`, which now blocks on a
            // timer every iteration (`b912aa2`, 2026-09-03) instead of
            // spinning, so the starvation the priority bump was reaching for
            // no longer exists. `userspace: the brain lies` is the scenario
            // that fails if this is put back.
            azos_sched::task_create_affinity("autorun", autorun_task, len,
                                        AUTORUN_PRIORITY, place::pin(place::AUTORUN));
            kprintln!("[SCHED] Created autorun task: {}",
                core::str::from_utf8(&path[..len]).unwrap_or("?"));
        }
    }

    // L5 (Kconfig IRQ_THREADED): the kernel thread that runs the bottom halves
    // of the kernel's own lines, on the boot CPU where the kernel routes them.
    irq_thread::start(hart_id);

    // The supervisor that restarts what the kernel itself starts
    // in ring 3 — the autorun image once it registers as a driver, the
    // component manager (which supervises every other `start = true` row
    // itself, the ring-3 host of the buzzer included) and the ML service
    // (`drv_supervisor::spawn_supervised`). Created only on a boot that can
    // start one of them, and here, from a kernel context, on purpose: a task
    // inherits its creator's page table root, and the successors it creates
    // must not inherit a dying ring-3 task's.
    let start_rows = azos_topology::get().is_some_and(|t| t.tasks().iter().any(|r| r.start));
    // A row that may move between hosts needs the supervisor task even if
    // nothing else does: it does the moves, and supervises the kernel host.
    let elastic_rows = azos_topology::get().is_some_and(|t| t.tasks().iter().any(|r| r.place.elastic()));
    {
        let autorun = cfg!(feature = "autorun")
            && azos_config::cfg_get(b"autorun").is_some_and(|p| !p.is_empty());
        let ml = cfg!(not(feature = "no-ml")) && ML_ENABLED.load(Ordering::Acquire);
        if autorun || start_rows || ml || elastic_rows {
            drv_supervisor::start();
        }
    }

    // Wave 11 (DRVPLACE): the INA219 placed in the kernel (Kconfig
    // DRV_INA219_PLACEMENT = kernel) is sampled by a kernel task; its
    // ring-3 host has no topology row then (`builder::INADRV_ROW`).
    #[cfg(feature = "ina219-kernel")]
    {
        // Supervised (wave 13): a contained panic in the host restarts it.
        let _ = drv_supervisor::start_kernel_host("ina219", ina219_host_task,
                                                  azos_sched::DEFAULT_PRIORITY);
        kprintln!("[INA219] placement: kernel (host task created)");
    }
    // The buzzer: its topology row says where it starts (Kconfig
    // DRV_BUZZER_PLACEMENT for the built-in one) and whether it may move
    // between its two hosts while the system runs (`crate::buzzer`). Placed
    // in the kernel, its host task is created here. The ring-3 host is the
    // component manager's whichever host the driver starts in (the standby
    // of a kernel placement); the controller only routes calls.
    if buzzer::init() == Some(azos_topology::placement::Host::Kernel) {
        // Supervised (wave 13): a contained panic in the host is the
        // controller's fault to decide on (demote), or a restart.
        let _ = drv_supervisor::start_kernel_host(buzzer::HOST_NAME, buzzer_host_task,
                                                  azos_sched::DEFAULT_PRIORITY);
        kprintln!("[BUZZER] placement: kernel (host task created)");
    }

    // The boot launcher: the component manager (which starts the other
    // `start = true` rows) and the rows that move between hosts. A task of
    // its own, like autorun: spawning reads each ELF off the volume.
    if start_rows {
        azos_sched::task_create("drv-launch", boot_launch_task, 0,
                                    azos_sched::DEFAULT_PRIORITY);
    }
}
