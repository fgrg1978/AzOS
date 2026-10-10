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
    // kernel_main: `install_procfs` is skipped
    // (ktest `procfs_entries_registered`).
    "procfs-skip",
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
    // `decision_admission_recorded`, `decision_cap_denial_recorded`).
    "decision-skip",
    // entry/x86_64/boot_hooks.rs `mmu_enabled`: the first kernel text page
    // is mapped 1:1 in the low half again (ktest `x86_low_half_maps_no_ram`,
    // x86_64 only).
    "x86-low-alias",
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
    // PiMutex contended by RT tasks on two CPUs (rule F7). Tests
    // `lockdep_scope_rules`, `lockdep_irq_safe_class_taken_irqsave`,
    // `lockdep_spinlock_hold_bounded`, `lockdep_rt_tasks_share_only_spinlocks`.
    "lockdep-scope-irq",
    "lockdep-scope-preempt",
    "lockdep-irq-inversion",
    "lockdep-hold",
    "lockdep-rt-pi",
    // entry/<isa>/boot_hooks.rs `cpu_features`: the spin extensions are
    // claimed present whatever the CPU reports (RV_ZACAS/RV_ZAWRS,
    // A64_LSE, X86_WAITPKG at probe). riscv64: the execution probe must
    // refute the claim (`[SPIN] ... refuted`); aarch64/x86_64: the first
    // CAS or wait on a CPU without it traps (Undefined Instruction / #UD).
    "spin-ext-claim",
    // boot/spin_patch.rs: the SpinWait probe sites are not rewritten at
    // boot; every site stays linked to the fallback (ktest
    // `spin_sites_patched`).
    "spin-patch-skip",
    // kernel/src/ktest.rs `power_off`: the run's verdict is dropped, so a
    // failed run powers off with a clean run's QEMU exit status (riscv64 0,
    // aarch64 0, x86_64 1); the gate's ktest rows must fail on the status
    // (rows `ktest exit status canary (rv|arm|x86)`).
    "ktest-exit-pass",
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
];
const _: () = assert!(NAMES.len() <= 64);

/// The one task `rt-console-own` applies to (the ktest
/// `console_rt_lines_only_append`'s probe stores its own tid); `0`: none.
/// Only that task, so every other RT line of the boot (rt-motor's) keeps
/// the fixed path and the canary fails one test, not the run.
pub(crate) static RT_CONSOLE_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Built in, and not refused by a signed image or a release build (Kconfig
/// already makes CANARY_RUNTIME depend on BUILD_TYPE_DEV).
pub(crate) const ON: bool = azos_limits::CANARY_RUNTIME
    && azos_limits::BUILD_TYPE_DEV
    && !cfg!(feature = "secure-boot-enforced");

/// The armed canaries, one bit per [`NAMES`] index. Written once on the boot
/// hart before any other hart or task runs.
static ARMED: AtomicU64 = AtomicU64::new(0);

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

#[inline(always)]
pub(crate) fn armed(bit: usize) -> bool {
    ON && ARMED.load(Ordering::Relaxed) & (1 << bit) != 0
}

/// `canary!("name")`: is runtime canary `name` armed on this boot? A constant
/// `false` when `CANARY_RUNTIME` is off. Not for a hot path (module doc).
macro_rules! canary {
    ($name:literal) => {{
        const BIT: usize = $crate::canary_rt::index($name);
        $crate::canary_rt::armed(BIT)
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
    let mut bits = 0u64;
    for name in list.split(|&b| b == b',').filter(|w| !w.is_empty()) {
        match NAMES.iter().position(|k| k.as_bytes() == name) {
            Some(i) => bits |= 1 << i,
            None => azos_drv_sys::kwarn!(
                "[CANARY] canary={} ignored: not a runtime canary",
                core::str::from_utf8(name).unwrap_or("?")
            ),
        }
    }
    ARMED.store(bits, Ordering::Relaxed);
    for (i, k) in NAMES.iter().enumerate() {
        if bits & (1 << i) != 0 {
            azos_drv_sys::kwarn!("[CANARY] armed: {} (this boot breaks its property on purpose)", k);
        }
    }
}
