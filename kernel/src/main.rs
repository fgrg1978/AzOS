// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AzOS - Hybrid RISC-V Kernel (Rust)
//!
//! Entry point for the kernel. Called from boot.S after hardware init.

#![no_std]
#![no_main]

extern crate alloc;

// Kconfig CANARY_RUNTIME: `canary=` on the command line arms a gate canary
// for one boot (`canary!`). First, so the macro is in scope everywhere.
#[macro_use]
mod canary_rt;
mod panic;
// Kconfig KTEST: the in-kernel test runner (crates/core/ktest is the registry).
#[cfg(feature = "ktest")]
mod ktest;
// Kconfig LOCKDEP: prints lockdep's reports and hold summary (task context).
mod lockdep_log;
// Panic record in reserved RAM, recovered into /fat/CRASH.LOG on the next
// boot (Kconfig `PSTORE_SIZE_KB`).
mod pstore;

// Each ISA's entry: asm stubs, boot hooks, trap-frame decode, interrupt
// controller (`entry/<isa>/`); the shared trap policy is `trap/`.
mod entry;
mod trap;

// The reserved tail of the boot medium: the link key, the entropy seed, the
// device record and the topology floor, past the end of the filesystem.
mod reserved_tail;

// The cold-restart supervisor for ring-3 drivers.
mod drv_supervisor;
// The buzzer's placement machinery is built for every image that has the
// driver row; the plays only the robot domain makes (behavior, sensors) are
// `use-robot`.
mod buzzer;

// Who has the console, the ring-3 user shell or the recovery console.
mod console_mode;

// Per-step timing of the behavior loop (`[BSTEP]`), see the module doc.
#[cfg(feature = "use-robot")]
mod behavior_step;

// The behavior loop's client of the ring-3 inference service, see the module
// doc; `behavior_infer` is the call itself, with no kernel in it.
#[cfg(all(feature = "use-robot", not(feature = "no-ml")))]
mod behavior_infer;
#[cfg(all(feature = "use-robot", not(feature = "no-ml")))]
mod behavior_ml;

// The Robot application domain (wave 11, DOMAIN): a .config that selects
// USE_ROBOT must be built with the `use-robot` feature, or the image
// would silently lack the robot it was configured for. Build through
// tools/build/kconfig_to_cargo.py, which emits the feature from the .config. The
// converse (the feature on, another domain in .config) is allowed.
const _: () = assert!(
    !azos_limits::USE_ROBOT || cfg!(feature = "use-robot"),
    "the .config selects USE_ROBOT but the kernel was built without the \
     `use-robot` feature: build with $(python3 tools/build/kconfig_to_cargo.py <config>)",
);
// Wave 15: the same rule for the two robot subsystems the .config can turn
// off (config/domains/Kconfig.robot RC_INPUT, GEOFENCE). On means compiled in.
const _: () = assert!(
    !azos_limits::RC_INPUT || cfg!(feature = "rc-input"),
    "the .config selects RC_INPUT but the kernel was built without the `rc-input` feature",
);
const _: () = assert!(
    !azos_limits::GEOFENCE || cfg!(feature = "geofence"),
    "the .config selects GEOFENCE but the kernel was built without the `geofence` feature",
);

// The sampling profiler's tick hook and panic backtrace (Kconfig `PROFILER`).
mod prof;

// Masked-window tracer read-out (Kconfig `LAT_TRACE`), see the module doc.
#[cfg(feature = "lat-trace")]
mod lat_trace;

// Worst-case wake-up latency rows (`lat-smoke`), see the module doc.
#[cfg(feature = "lat-smoke")]
mod lat_smoke;

// RT band budget and EDF + CBS rows (`sched-rt-smoke`), see the module doc.
#[cfg(feature = "sched-rt-smoke")]
mod rt_smoke;
// Admitted deadlines near the admission bound (`sched-rt-util`), see the module doc.
#[cfg(feature = "sched-rt-util")]
mod rt_util_smoke;

// The crate root used to hold every boot step, trap handler, kernel task and
// boot smoke in one file. They now live in these four module trees; each tree
// re-exports its items and this file glob-imports them, so every call site
// (`kernel_main`, `entry::*`, `boot_hooks`) keeps the bare name it had.
mod boot;
use boot::*;
mod tasks;
use tasks::*;
// Kconfig IRQ_THREADED: the kernel's own lines and the timer's housekeeping
// run their bottom halves in one kernel thread on a reservation.
mod irq_thread;
mod smokes;
// Empty in a build with no self-test and no smoke (Kconfig BOOT_SELFTESTS off).
#[allow(unused_imports)]
use smokes::*;
#[cfg(target_arch = "riscv64")]
use entry::riscv64::{irq::*, trap::*};

use core::arch::global_asm;
use core::sync::atomic::Ordering;
// NOT `#[cfg]`'d: read from the shared CONFIG.INI-apply block (kernel-main-
// merge task) and from `camera_send_frame`, both now unconditional.
use azos_config::ML_ENABLED;
use azos_drv_sys::kprintln;
// `flight_control_task`/`rt_motor_task` are read from the shared task
// roster (kernel-main-merge task) and so must resolve on every ISA.
// `txn_try_rollback` is called by each ISA's trap entry
// (`entry/<isa>/trap.rs`), which imports it itself.
#[cfg(feature = "use-robot")]
use azos_safety_core::{flight_ctrl::flight_control_task, rt_motor::rt_motor_task};
// NOT `#[cfg]`'d, unlike its three ex-neighbours above: `create_sys_wdt_task`
// is shared by both `kernel_main`s now, so this name has to resolve on both
// targets. A `use` left inside the riscv64 group is the exact shape that
// turned gate 136 red — see `feedback-run-gate-lints-at-integration`.
use azos_actuation::sys_wdt::system_wdt_task;
// `PAGE_SIZE` no longer used directly in this file (kernel-main-merge task):
// both ISAs' early-boot bodies that read it moved into their own
// `boot_hooks.rs`, which each `use azos_arch::mmu::PAGE_SIZE;` on its
// own — see `entry::riscv64::boot_hooks` / `entry::aarch64::boot_hooks`.
#[cfg(target_arch = "riscv64")]
use azos_arch::trap::{
    TrapFrame,
    INT_TIMER_S, INT_EXTERNAL_S, INT_SOFTWARE_S,
};
#[cfg(target_arch = "riscv64")]
use azos_arch::cpu;

/// Chain E cut 7: whether each ISA's lean native syscall entry branches the
/// two IPC fast calls straight to the frame that runs the fast path. Only
/// where the fast path is compiled in (Kconfig IPC_FASTPATH; off, the two
/// numbers take the ordinary entry and nothing is tested).
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))]
const IPC_FAST_ENTRY: bool = azos_syscall::fastpath::ENABLED;
/// The lower of the two numbers the branch tests; the other is two above it
/// (the test is `(num - IPC_FAST_LO) & !2 == 0`).
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))]
const IPC_FAST_LO: u64 = azos_abi::syscall_nr::SYS_IPC_FAST_REPLY_ACCEPT;
const _: () = assert!(azos_abi::syscall_nr::SYS_IPC_FAST_CALL_EP == azos_abi::syscall_nr::SYS_IPC_FAST_REPLY_ACCEPT + 2);

// ── Page size: one Kconfig choice, two routes into the build ────────────
//
// config/arch/Kconfig.isa's AARCH64_PAGE_* choice reaches `azos_limits` as
// PAGE_SHIFT (from `.config`) and `azos_arch_api` as the cargo feature
// `page-16k`/`page-64k` (tools/build/kconfig_to_cargo.py). Every page-table walk
// uses the second; budgets and Kconfig checks use the first. A build that
// passed `--features qemu` with a 16 KiB `.config`, or the reverse, stops
// here instead of booting with two page sizes.
const _: () = assert!(
    azos_arch_api::PAGE_SHIFT == azos_limits::PAGE_SHIFT,
    "page size mismatch: .config (azos_limits::PAGE_SHIFT) and the cargo features \
     (page-16k / page-64k -> azos_arch_api::PAGE_SHIFT) disagree; build with the \
     features tools/build/kconfig_to_cargo.py prints for this .config",
);

/// The CPU ceiling (Kconfig `NR_CPUS`, through `azos_percpu`): the bound on
/// every table assembly or early boot indexes by CPU id (`boot.S`'s range
/// check, `trap_hart_vectors`, the per-CPU stack-top tables). The name stays
/// `MAX_HARTS` because the asm takes it under that name; on riscv64 a CPU id
/// IS a hart id (`tp`), so the two bounds are one.
const MAX_HARTS: usize = azos_percpu::NR_CPUS;

// K-C29: `azos_sync::preempt` keeps one preemption-depth slot per hart and
// indexes it by `hart_id()` with NO clamp; `PER_CPU` and every other
// scheduler table are indexed by `current_cpu_id()` the same way. All of them
// now take their length from the one Kconfig symbol `NR_CPUS` (they were
// hand-written 8s and a private 4, tied by asserts). The asserts stay: they
// are what fails the build, not the robot, if a table is ever sized by
// anything else again.
const _: () = assert!(MAX_HARTS <= azos_sync::preempt::SLOTS);
const _: () = assert!(MAX_HARTS <= azos_sched::MAX_CPUS);

/// Boot stack of each secondary CPU (Kconfig `SECONDARY_STACK_SIZE_KB`,
/// 16 KiB by default): nested traps (288 B each), the scheduler and its Rust
/// callers until the CPU's first task switch.
const SECONDARY_STACK_SIZE: usize = azos_limits::SECONDARY_STACK_SIZE_BYTES;

/// Per-CPU interrupt stack, from Kconfig `INTERRUPT_STACK_SIZE_KB`.
///
/// The trap entry switches to this CPU's stack when the trap is an
/// interrupt, so the depth an interrupt costs is no longer charged to
/// whichever task happened to be running. See the block comment in either
/// ISA's `trap_entry.S`, which take it as `{irq_stack_size}`.
const IRQ_STACK_SIZE: usize = azos_limits::INTERRUPT_STACK_SIZE_BYTES;

/// The word the bottom of every interrupt stack carries, on both ISAs.
///
/// There is no guard page below an interrupt stack, so an overflow would
/// quietly eat whatever lies below it. riscv64's `trap_resched` reads this
/// word on the way out of every trap and aarch64 checks the boot CPU's after
/// its tick wait: cheap, and it turns a silent corruption into a message.
const IRQ_STACK_MAGIC: u64 = 0x4952_5153_5441_5A57; // "IRQSTAZW"

// ── Per-CPU stacks (wave 15, NRCPUS) ────────────────────────────────────
//
// These were `.bss` arrays of `MAX_HARTS` slots — secondary boot stacks and
// interrupt stacks, 24 KiB a CPU, 1.5 MiB at a ceiling of 64 — indexed by the
// asm with a `mul`. They now live in each secondary CPU's per-CPU area,
// allocated at boot for the possible CPUs only (`boot::setup_per_cpu_areas`),
// and the asm reaches them through two tables of one word per CPU. The
// tables stay static: the asm reads them by symbol, a secondary before its
// MMU is on. The boot CPU's interrupt stack is the one static stack left
// (`boot_irq_stack`): it is armed before interrupts are enabled, which is
// before the per-CPU areas exist.

/// Base (lowest address) of each CPU's interrupt stack, `INTERRUPT_STACK_SIZE`
/// bytes long, as a kernel virtual address; 0 for a CPU without one. Read by
/// both ISAs' `trap_entry.S` (`AZOS_IRQ_STACK_BASE[cpu id]`) on every
/// interrupt; written by `boot::arm_irq_stack` before that CPU can take one.
#[unsafe(no_mangle)]
pub static AZOS_IRQ_STACK_BASE: [core::sync::atomic::AtomicUsize; MAX_HARTS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_HARTS];

/// Initial `sp` of each secondary CPU, as a PHYSICAL address (the secondary
/// loads it with its MMU off; riscv64 maps the kernel 1:1, aarch64 adds
/// `KERNEL_VA_OFFSET` once the MMU is on); 0 parks the CPU. Read by both
/// ISAs' `boot.S` secondary entry; written by `boot::setup_per_cpu_areas`
/// before the secondaries are started.
#[unsafe(no_mangle)]
pub static AZOS_SECONDARY_SP: [core::sync::atomic::AtomicUsize; MAX_HARTS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_HARTS];

// The boot CPU's interrupt stack. `.bss`, so it is zeroes on disk;
// `clear_bss` in boot.S runs before any trap.
global_asm!(
    ".section .bss",
    // `.p2align`: 2^12 on every ISA (x86's `.align` counts bytes).
    ".p2align 12",
    ".global boot_irq_stack",
    "boot_irq_stack:",
    "    .space {size}",
    size = const IRQ_STACK_SIZE,
);

unsafe extern "C" {
    static boot_irq_stack: u8;
}

// Linker script symbols — section boundaries for W^X enforcement.
// Shared by both ISAs since Item 2 Stage 5 task 4: linker.ld and
// linker-aarch64.ld both define all six of these (same names, same
// section-boundary role), and aarch64's kernel_main now does its own
// W^X enforcement through `crates/core/mm::vmm` — the exact functions
// riscv64 calls below, not a copy.
unsafe extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _rodata_start: u8;
    static _rodata_end: u8;
    static _data_start: u8;
    static _kernel_end: u8;
    // `.data.ro_after_init`, page-aligned (every kernel linker script): the
    // set-once hooks and the x86_64 IDT, sealed read-only after boot.
    static __ro_after_init_start: u8;
    static __ro_after_init_end: u8;
}

// Boot stack — the linker scripts' `.stack` section after .bss and below
// _kernel_end: [_stack_redzone, _stack_start) is the red zone boot.S (either
// ISA's) paints with the stack, [_stack_start, _stack_end) the stack itself.
// Shared: both linker.ld and linker-aarch64.ld define a `.stack` section
// with these same three symbols, and `boot_stack_report` below — called
// from both ISAs' kernel_main — is the one reader.
unsafe extern "C" {
    static _stack_redzone: u8;
    static _stack_start: u8;
    static _stack_end: u8;
}

/// Fallback RAM size when DTB doesn't provide memory info. Shared by both
/// ISAs' `kernel_main`: QEMU `virt` defaults to 128 MiB of guest RAM on
/// riscv64 and on aarch64 alike (this task's own brief measured the
/// aarch64 case), so one constant serves both rather than two copies of
/// the same number.
const FALLBACK_MEM_SIZE: usize = 128 * 1024 * 1024;

use azos_limits::KERNEL_HEAP_SIZE_BYTES as HEAP_SIZE;


/// Number of worker tasks for the SMP stress test (Kconfig BOOT_SELFTESTS).
#[cfg(feature = "boot-selftests")]
const NUM_WORKERS: usize = 15;
/// Task slots the stress workers never take: what the rest of boot still
/// creates after them (kernel tasks, topology rows, the user shell).
#[cfg(feature = "boot-selftests")]
const WORKER_POOL_RESERVE: usize = 16;


// ── Per-arch boot hooks (kernel-main-merge task, 2026-09-24) ───────────────
// Declared here, not from `entry/riscv64/mod.rs` / `entry/aarch64/mod.rs`: these are
// new sibling modules of `entry`, not submodules of it (B2-04 owns
// `entry/riscv64/mod.rs`'s own trap-context work; this keeps the two files
// apart). Same public fn names/signatures on both ISAs — see each file's
// module doc for what it does per ISA.
//
// `arch_entry` is the same ISA's `ArchEntry` impl over those hooks plus the
// secondary-CPU steps; `kernel_main` and `boot::smp::secondary_main` reach
// the ISA only through `ARCH_ENTRY`. An ISA with neither file stops here.
#[cfg(target_arch = "riscv64")]
#[path = "entry/riscv64/boot_hooks.rs"]
mod boot_hooks;
#[cfg(target_arch = "riscv64")]
#[path = "entry/riscv64/arch_entry.rs"]
mod arch_entry;
#[cfg(target_arch = "aarch64")]
#[path = "entry/aarch64/boot_hooks.rs"]
mod boot_hooks;
#[cfg(target_arch = "aarch64")]
#[path = "entry/aarch64/arch_entry.rs"]
mod arch_entry;
#[cfg(target_arch = "x86_64")]
#[path = "entry/x86_64/boot_hooks.rs"]
mod boot_hooks;
#[cfg(target_arch = "x86_64")]
#[path = "entry/x86_64/arch_entry.rs"]
mod arch_entry;
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("kernel: no boot hooks for this target_arch: add \
    kernel/src/entry/<isa>/{boot_hooks,arch_entry}.rs (ArchEntry)");

/// This ISA's boot sequence: the arch contract's `ArchEntry`, zero-sized, so
/// every call through it is the hook body itself.
pub(crate) const ARCH_ENTRY: arch_entry::Entry = arch_entry::Entry;
use azos_arch::ArchEntry as _;

/// Early-boot output the shared `kernel_main` body needs past
/// `boot::early_main`'s return. `heap_start`/`kernel_end_aligned` are read
/// only by the riscv64 PMP audit block (`boot::report_security`), so the other
/// ISAs leave them unread; an allow on those two rather than a `cfg`, since
/// the generic early boot computes them on every ISA.
pub struct EarlyBoot {
    pub num_cpus: usize,
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub heap_start: usize,
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub kernel_end_aligned: usize,
    /// The DTB's `pci-host-ecam-generic` node (`azos_dtb::dtb_pci_host`),
    /// read during early boot. `None`: no DTB, or no such node.
    pub pci_host: Option<azos_dtb::PciHost>,
    /// The RAM the kernel manages, `[start, end)`: what the software-checked
    /// DMA domain allows a device to reach.
    pub ram: (u64, u64),
}
/// Kernel entry point. Called from boot.S on the boot CPU only, every ISA.
///
/// Boot flow:
///   1. **Early init**: UART, traps, firmware table, PMM, VMM, heap,
///      interrupt controller — `boot::early_main` (kernel/src/boot/early.rs),
///      generic, calling the ISA's `ArchEntry` hooks where the ISAs differ.
///   2. **Late init** (interrupts ON): storage, config, IPC, drivers,
///      scheduler — shared body below.
///   3. Secondary harts — per-ISA, see the `wake_secondaries` hook (`entry/<isa>/smp.rs`).
///   4. Hand off to the scheduler — per-ISA, see
///      `boot_hooks::arch_enter_scheduler`.
///
/// Unified from the former riscv64/aarch64 `kernel_main`s (kernel-main-merge
/// task, 2026-09-24; owner decision: fuse everything as-is, one shot). See
/// `ordering-decisions.md` for the per-block reasoning, and
/// `entry::riscv64::boot_hooks` / `entry::aarch64::boot_hooks` for what each
/// per-arch hook does.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(boot_hw_id: usize, dtb_ptr: usize) -> ! {
    let early = boot::early_main(boot_hw_id, dtb_ptr);
    // The boot CPU is logical CPU 0 whatever its hardware id (`boot_hw_id`:
    // riscv64's `mhartid` from OpenSBI, 0 on the other ISAs); every hook and
    // table below takes the logical id.
    let hart_id = boot::BOOT_CPU;
    // The kernel's own page table, live from here, maps the pstore region:
    // a panic from now on leaves a RAM record.
    pstore::arm();
    let num_cpus = early.num_cpus;
    // The per-CPU areas, one per possible CPU (the DTB's count, cut to
    // NR_CPUS by `boot::early_main`), from the frame allocator: after the
    // heap, before the scheduler, the first task and the secondaries.
    boot::setup_per_cpu_areas();

    // ══════════════════════════════════════════════════════════════════════
    //  LATE INIT — interrupts enabled, heap available, full hardware access
    // ══════════════════════════════════════════════════════════════════════

    // Phase 6: the hardware bus, entropy, PCI, the block device and the mounts.
    boot::bring_up_devices(&early, dtb_ptr, num_cpus);

    // Phase G2: CONFIG.INI, the OTA slots, the link and operator keys, the config applied.
    boot::recover_persistent_state();

    // ── Network init (uses IP/mask/gw set above) ─────────────────────────────
    // Init transport drivers first, then the IP/TCP/UDP stack. See
    // `install_net`'s own doc for the conformance-probe reasoning.
    #[cfg(feature = "net")]
    let nic_present = install_net();
    // Then the board NIC, the stack (net_init), the network smokes and the OTA listener.
    boot::start_network();

    // ── Early-boot synthetic bench capture (CFG_BENCH_BOOT) ───────────────
    // Quiescent context: hart 0 is the only running hart (secondaries wake at
    // scheduler::start), the timer ISR is still OFF (deferred until just
    // before scheduler::start), and all benched subsystems (ipc, fs/tmpfs,
    // net/arp, crypto, auth) are initialised by this point. That removes the
    // cross-hart rdcycle contention + timer preemption that make the SMP
    // behavior-task path noisy. Run once, emit, then halt — no need to reach
    // the (slow / -smp-1-hanging) full task system. Pair with QEMU -icount
    // for cross-run determinism. See crates/core/config CFG_BENCH_BOOT.
    #[cfg(all(feature = "qemu", feature = "use-robot"))]
    if azos_config::CFG_BENCH_BOOT.load(Ordering::Relaxed) {
        const BENCH_BOOT_ITERS: u64 = 100;
        azos_bench::run_all_quiescent(BENCH_BOOT_ITERS);
        kprintln!("[BENCH-RES] ── boot-bench complete, halting ──");
        loop {
            azos_arch::Cpu::wait_for_interrupt(&azos_arch::ARCH);
        }
    }

    // ---- ML ----
    // The MLP is a signed bundle (`/fat/BEHAVIOR.MBL`) that the ring-3 inference
    // service (`userspace/services/infsrv`) runs; the kernel carries no MLP of its own.
    #[cfg(feature = "no-ml")]
    kprintln!("[ML] Compile-time disabled (--features no-ml)");
    kprintln!();

    // ---- Phase C: ggml-nano / GGUF inference ----
    // Moved to the ring-3 inference service with the behavior loop's MLP: `infsrv`
    // reads /fat/POLICY.GGF and runs the three classifications when it
    // starts, printing the same `[GGUF] n/3 tests passed` verdict.

    // Phases D and 16: the crash counter, the PMP policy (riscv64), the stack canary.
    boot::report_security(&early);

    // ---- Phase 17: Robot Physical Integration ----

    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase 17: Robot Physical Integration");
    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Encoder sim: ticks in rt_motor_task → speed × iteration");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Odometry:    dead reckoning (dist_mm, heading_cdeg)");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Trajectory:  ring buffer ({} pts) + FAT32 CSV flush",
        azos_robot::TRAJ_CAP);
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] OTA:         A/B firmware slots (recovery console: ota recv/status/verify)");
    #[cfg(feature = "use-robot")]
    kprintln!();

    // Shared with aarch64's kernel_main — see `install_robot_hw`'s own doc
    // for why `robot_init()` (inside the next helper) stays a separate call
    // rather than living inside `install_robot_hw` itself (this ISA's own
    // `payload_init` interleave).
    install_robot_hw();
    // A board's PCF8563 needs the I2C controllers `install_robot_hw` brought up.
    #[cfg(feature = "rtc-pcf8563")]
    boot::rtc::install_i2c();
    // Payload + drivers + full sensor suite — see
    // `install_robot_payload_and_sensors`'s own doc for the merge-task
    // finding (this was riscv64-only; now shared) and the ordering
    // constraint (must follow network bring-up).
    install_robot_payload_and_sensors();
    // On a robot image, the camera's capture task.
    #[cfg(feature = "use-robot")]
    camera_capture_init();

    // ---- Phase G1: Subsumption Behavior Engine + VLA Protocol ----

    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!(" [BEHAVIOR] Phase G1: Subsumption Engine");
    #[cfg(feature = "use-robot")]
    kprintln!("   L0: emergency-stop  (IMU)");
    #[cfg(all(feature = "use-robot", not(feature = "no-ml")))]
    kprintln!("   L1: avoid-obstacle  (MLP)");
    #[cfg(feature = "use-robot")]
    kprintln!("   L2: remote-vla      (TCP)");
    #[cfg(feature = "use-robot")]
    kprintln!("   L3: explore         (wander)");
    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!();

    // ---- Phase 5: SMP + Scheduler ----

    kprintln!("========================================");
    kprintln!(" Phase 5: SMP Scheduler ({} CPUs)", num_cpus);
    kprintln!("========================================");
    kprintln!();

    // Every device the stages so far did not name is decided now, under the
    // built-in topology's device rows; the input devices wait for their
    // interrupt wiring below.
    #[cfg(feature = "virtio-input")]
    boot::hwbus::settle(&["virtio-input"]);
    #[cfg(not(feature = "virtio-input"))]
    boot::hwbus::settle(&[]);

    // AZOS Phase 1 W3 — install the static topology before the
    // scheduler so that future task spawns can pull their cap_table +
    // class assignment from the topology's declarations. Shared with aarch64's
    // kernel_main — see `install_topology`'s own doc.
    install_topology(num_cpus);
    // Kconfig VIRT: admit the topology's `[guest.NAME]` rows (the monitor's VMs).
    #[cfg(feature = "hv")]
    install_hv(num_cpus);
    #[cfg(feature = "net")]
    install_firewall();
    // The native volumes the topology declares (`[volume.NAME]`), mounted at
    // their rows' paths now that the rows and the partition table exist.
    install_azvol();
    // Kconfig MM_SWAP_BACKEND_FILE: the swap file, on whichever volume
    // holds its path (FAT32 was mounted above, azvol just now), before the
    // first task. A no-op for the other backends.
    boot::swap::install_swap_file();
    // The roots the keystore derives persistent keys from (the TPM's secret,
    // the volume's), now that the mounts and the entropy pool exist.
    boot::keys::install_keystore_roots();
    // The topology's rows (a signed file's, when there is one) replace the
    // built-in ones: bring every device to what they say.
    boot::hwbus::reconcile();
    // Kconfig BUILD_TYPE (dev: test machinery and the TEST key allowed).
    kprintln!("[BOOT] build type: {}", if azos_limits::BUILD_TYPE_CERTIFIABLE {
        "certifiable"
    } else if azos_limits::BUILD_TYPE_RELEASE {
        "release"
    } else {
        "dev"
    });
    // The kernel command line: `init=` (secure boot off) names this boot's
    // console program. Read before anything ring 3 starts.
    crate::console_mode::read_cmdline(dtb_ptr);
    // The framebuffer (Kconfig FB_GENERIC): the console mirrors the lines
    // printed from here on.
    #[cfg(feature = "fb-generic")]
    boot::fb::init(dtb_ptr);
    // The structured kernel log's ring (Kconfig KLOG): the lines printed so
    // far move from the early ring into the region ring 3 maps.
    boot::klog_region::install();
    // The terminal server's regions: the input event ring (before any input
    // line is enabled) and the console screen (the grid is up now).
    #[cfg(any(feature = "virtio-input", feature = "ps2", feature = "usb-hid", feature = "fb-console"))]
    boot::term_regions::install();
    // The energy model, from the topology just installed, else
    // the DTB, else none.
    #[cfg(feature = "energy")]
    install_energy(num_cpus, dtb_ptr);
    // Kconfig ENERGY (and THERMAL): the board's clock runtime over that model,
    // with the DTB's `thermal-zones` under THERMAL; its task is created below.
    #[cfg(feature = "energy")]
    boot::thermal::install(dtb_ptr);
    // Which CPUs share a core, a cluster, a cache, a node and a package, and
    // their capacities: from the DT, the ACPI PPTT or CPUID, for the balancer.
    boot::smp::install_topology(num_cpus, dtb_ptr);

    azos_sched::init();

    // (`install_sched_hooks()` now called much earlier — right after the
    // "Phase 6" banner, before `install_entropy()`; see that call site's
    // comment, ordering-decision #1.)
    //
    // Marker cluster for the four callbacks wired by `install_sched_hooks`
    // — see `sched_hooks_smoke`'s own doc. Off by default
    // (`sched-hooks-smoke` feature); compiles to nothing otherwise. Still
    // spawned here (well after the hooks are installed — installing them
    // earlier only widens that margin, function-pointer stores are
    // idempotent). riscv64 only: aarch64 spawns it from its own later site
    // below (the early one reads `counter at wake = 0` there), and the
    // cluster shares its statics, so spawning it from both sites printed
    // every `[SCHEDHOOKS]` line twice and doubled the waitqueue counter.
    #[cfg(all(feature = "sched-hooks-smoke", not(target_arch = "aarch64"), not(feature = "ktest")))]
    sched_hooks_smoke::spawn();

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

    // Wave 8: cross-hart TLB shootdown, observed (see `tlb_probe`). Runner on
    // hart 1, toucher on hart 2 (hart 3 is net-poll's); needs >= 3 harts.
    #[cfg(all(feature = "tlb-smoke", not(feature = "ktest")))]
    {
        if num_cpus >= 3 {
            azos_sched::task_create_affinity("tlb-probe", tlb_probe::runner, 2,
                                                 tlb_probe::PROBE_PRIO, 1);
            kprintln!("[SCHED] Created tlb-probe task (wave 8 shootdown) [harts 1,2]");
        } else {
            kprintln!("[TLB-SMOKE] SKIP: needs -smp >= 3, have {}", num_cpus);
        }
    }

    // Wave 11 (LAT): worst-case wake-up latency under load, see `lat_smoke`.
    #[cfg(feature = "lat-smoke")]
    lat_smoke::spawn(num_cpus);

    // Wave 11 (PIFAST): priority inversion through fast IPC, see the module.
    #[cfg(feature = "pifast-smoke")]
    smokes::pifast_smoke::spawn();
    // Wave 11 (SCHED-RT): band budget, EDF + CBS, admission, see `rt_smoke`.
    #[cfg(feature = "sched-rt-smoke")]
    rt_smoke::spawn();
    // Wave 15: admitted deadlines near the admission bound, see `rt_util_smoke`.
    #[cfg(feature = "sched-rt-util")]
    rt_util_smoke::spawn();
    // RT7: panic policy by profile, see `smokes::rt_panic_smoke`.
    #[cfg(feature = "rt-panic-canary")]
    smokes::rt_panic_smoke::spawn();
    // Wave 15 GR5: a panic while another CPU floods the console, see
    // `smokes::panic_splice_smoke`.
    #[cfg(feature = "panic-splice-smoke")]
    smokes::panic_splice_smoke::spawn();
    // RT7 (wave 13): a contained panic in a kernel-placed driver's host, and
    // its restart, see `smokes::drv_contain_smoke`.
    #[cfg(feature = "drv-contain-smoke")]
    smokes::drv_contain_smoke::spawn();
    // RT7 P2 (wave 13): timer sleepers racing early wakes on every hart, see
    // `smokes::timer_heap_smoke`.
    #[cfg(feature = "timer-heap-smoke")]
    smokes::timer_heap_smoke::spawn();
    // RT7 (wave 13): a tick deferred by a SpinLock counts as a preemption.
    #[cfg(all(feature = "preempt-account-smoke", not(feature = "ktest")))]
    smokes::preempt_account_smoke::spawn();
    // RT7 (wave 13): periodic-wake tail latency under ping-pong contention.
    #[cfg(feature = "tail-smoke")]
    smokes::tail_smoke::spawn();
    // The energy model and the utilisation signals.
    #[cfg(feature = "energy-smoke")]
    smokes::energy_smoke::spawn();
    // The thermal row: a scripted temperature through the real runtime.
    #[cfg(feature = "thermal-smoke")]
    smokes::thermal_smoke::spawn();

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

    // E11.AQ3 validation smoke: if a userspace gpio_drv was autorun'd, exercise
    // the ring-3 driver round-trip from a kernel task, on a hart other than the
    // autorun hart (3): the cross-hart case. The same-hart case — a client more
    // urgent than the driver, on the driver's hart — is `proxy-pi-smoke`,
    // started by this task once the driver has answered. QEMU-only: a
    // validation aid, not production. A boot self-test (Kconfig
    // BOOT_SELFTESTS), and on its own in the smokes it starts (`gpio-aq3-smoke`):
    // an image without gpio_drv used to wait out its whole retry budget.
    //
    // **Priority 16, not 13.** It was 13, which on hart 1 is ABOVE
    // `sensor-ahrs` at 14, while the proxy still waited for the reply with a
    // million-iteration `spin_loop()`: for the whole span of a wait
    // `sensor-ahrs` got no CPU, and `flight-ctrl` on hart 0 ages the attitude
    // it publishes for its failsafe. The proxy now blocks for the reply
    // (wave 8), so the wait no longer costs hart 1 anything; the priority
    // stays below the sensor loop because nothing needs it higher.
    #[cfg(any(feature = "gpio-aq3-smoke", all(feature = "qemu", feature = "boot-selftests")))]
    {
        const GPIO_SMOKE_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
        const GPIO_SMOKE_HART: i8 = 1;
        azos_sched::task_create_affinity(
            "gpio-aq3-smoke", gpio_user_driver_smoke_task, 0,
            GPIO_SMOKE_PRIORITY, GPIO_SMOKE_HART,
        );
        // sup-smoke: kill the ring-3 GPIO driver four times, after the AQ3
        // smoke is done with it.
        #[cfg(feature = "sup-smoke")]
        drv_supervisor::start_smoke();
    }
    #[cfg(feature = "orderly-reboot-smoke")]
    azos_sched::task_create_affinity("orderly-smoke", orderly_reboot_smoke_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "safe-mode-smoke")]
    azos_sched::task_create_affinity("safe-mode-probe", safe_mode_probe_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "power-off-durability-smoke")]
    azos_sched::task_create_affinity("durable-smoke", power_off_durability_smoke_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);

    // DRV1: the buzzer and INA219 functional test. Hart 1, default priority,
    // like `gpio-aq3-smoke`: it only waits and reads.
    #[cfg(feature = "ring3-drv-smoke")]
    azos_sched::task_create_affinity(
        "drv-smoke", ring3_drv_smoke::task, 0, azos_sched::DEFAULT_PRIORITY, 1,
    );

    // Wave 11: the topology's `start = true` drivers killed under supervision
    // (`drv_supervisor::supall`).
    #[cfg(feature = "supall-smoke")]
    drv_supervisor::start_supall_smoke();
    #[cfg(feature = "restart-smoke")]
    drv_supervisor::start_restart_smoke();

    // reflex-smoke: drive the ring-3 obstacle-avoidance daemon through a real
    // decision by moving the simulated rangefinder underneath it, and assert
    // it reacts. Without this, "reflex runs" only ever meant "reflex printed
    // its banner": with a clear road it correctly does nothing, so a working
    // daemon and a daemon whose sensor reads are all denied produce identical
    // output. That ambiguity is exactly what hid the missing capability grant.
    #[cfg(feature = "estop-gpio-smoke")]
    {
        // Hart 1, not hart 3 — that one is autorun's and net-poll's.
        //
        // DEFAULT priority, for the reason `gpio-aq3-smoke` above spells out.
        // Its body is millions of `task_yield`s, and a yield re-selects the
        // highest-priority ready task on the hart — which at 13 was this task,
        // above `sensor-ahrs` (14). The smoke starved the attitude publisher
        // for as long as it waited, in the very scenario that asserts a safety
        // path. Nothing here needs to outrank anything: it waits for other
        // tasks to make progress, so running in the gaps they leave is the
        // whole design.
        azos_sched::task_create_affinity(
            "estop-gpio-smoke", estop_gpio_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY, 1,
        );
    }

    #[cfg(feature = "console-splice-smoke")]
    {
        // Harts 1 and 2 so that, with `-smp 4`, the ring-3 writer and the
        // kernel printer contend from different harts; with `-smp 1` both are
        // rescued onto hart 0 and the contention is preemption + the timer ISR.
        azos_sched::task_create_affinity(
            "splice-w", console_splice_writer_task, 0,
            azos_sched::DEFAULT_PRIORITY, 1,
        );
        azos_sched::task_create_affinity(
            "splice-k", console_splice_kprint_task, 0,
            azos_sched::DEFAULT_PRIORITY, 2,
        );
    }

    #[cfg(feature = "reflex-smoke")]
    {
        // DEFAULT, not 13: same yield-loop-above-`sensor-ahrs` shape as
        // `estop-gpio-smoke` above, and the same fix.
        const REFLEX_SMOKE_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
        const REFLEX_SMOKE_HART: i8 = 1;   // not hart 3 — that is autorun's
        azos_sched::task_create_affinity(
            "reflex-smoke", reflex_smoke_task, 0,
            REFLEX_SMOKE_PRIORITY, REFLEX_SMOKE_HART,
        );
    }

    // envelope-smoke: drive the motor-envelope chokepoint with a command above the
    // per-robot-type cap and observe the refusal on the console.
    #[cfg(feature = "envelope-smoke")]
    {
        azos_sched::task_create(
            "envelope-smoke", envelope_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // geofence-smoke: arm a fence around the simulated GPS fix, feed the GPS
    // driver a fix outside it, and print the verdict L0 would act on.
    #[cfg(all(feature = "geofence-smoke", not(feature = "ktest")))]
    {
        azos_sched::task_create(
            "geofence-smoke", geofence_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // Wave 15 (RC input and geofence): one property per boot, see
    // `smokes::rc_fence`.
    #[cfg(feature = "rc-failsafe-smoke")]
    azos_sched::task_create("rc-failsafe-smoke", rc_failsafe_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "rc-stick-smoke")]
    azos_sched::task_create("rc-stick-smoke", rc_stick_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "fence-refuse-smoke")]
    azos_sched::task_create("fence-refuse-smoke", fence_refuse_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);

    // sensor-ts-smoke (wave 11): the IMU's acquisition stamp, from the driver
    // to the bus staleness check L0 reads (see `smokes::sensor_ts`).
    #[cfg(all(feature = "sensor-ts-smoke", not(feature = "ktest")))]
    {
        azos_sched::task_create(
            "sensor-ts-smoke", smokes::sensor_ts::sensor_ts_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // brain-lies-smoke: wait for the peer's unknown-packet frame and read the
    // SAFETY_UNKNOWN_PKT record back off the flight recorder. Priority is the
    // default, NOT the real-time band: a task in that band on the NIC's hart
    // is what starved `net-poll` when the brain-lies scenario was written, and
    // this one depends on exactly that link working.
    #[cfg(feature = "brain-lies-smoke")]
    {
        azos_sched::task_create(
            "brain-lies-smoke", brain_lies_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // cap-deny-smoke: read captest's forged-handle refusal back off the flight
    // recorder. Default priority for the same reason as the probe above.
    #[cfg(feature = "cap-deny-smoke")]
    {
        azos_sched::task_create(
            "cap-deny-smoke", cap_deny_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // disk-part-row: read captest's out-of-partition refusal back off the
    // flight recorder. Default priority, as the probes above.
    #[cfg(feature = "disk-part-row")]
    {
        azos_sched::task_create(
            "disk-part-row", disk_part_row_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // (OTA auto-recv listener was spawned earlier, right after net_init().)

    // ── Fork-refusal probe (opt-in only; never in a normal or board build) ──
    //
    // `sys_fork_impl` refuses from SIX distinct sites and, until 2026-09-25,
    // every one returned a bare `-1`. That cost a week: an aarch64
    // `fork+exit` `rc=-1` was mis-filed as a known gap because a `-1` in a log
    // cannot say WHICH site fired. Each site now bumps its own counter and
    // prints `[FORK] refusal site first hit: <name>` once, on the 0→1 edge.
    // A counter no row ever observes is indistinguishable from one that is not
    // wired, so the gate has to watch one fire — that is this probe's whole
    // job, on both ISAs.
    //
    // **POSITION IS THE WHOLE CORRECTNESS ARGUMENT, and the first placement was
    // wrong.** Site 1's test is `current_user_pt() == 0`, which reads
    // `PER_CPU[current_cpu_id()].current_idx`. Placed after
    // `arch_wake_secondaries`, the probe ran while OTHER harts were already
    // dispatching user tasks, and gate 180 caught it: one boot in seven
    // returned `rc=0` — a SUCCESSFUL fork — meaning that read landed on a slot
    // that had a user page table. Only `do_schedule` writes `current_idx`, and
    // only for its own hart, so on hart 0 (which had not scheduled yet) that
    // should be impossible. **That anomaly is NOT explained and is recorded as
    // an open finding, not fixed here** — see the memory note; it may be a real
    // `current_cpu_id()` defect under load.
    //
    // Here, before any secondary is woken and before hart 0 schedules, there is
    // exactly one running hart and no task has ever been current: the read is
    // unambiguous. Measured 6/6 `rc=-1` at the old position on a quiet host and
    // 7/7 here; the point of moving it is that the probe must not be able to
    // observe someone else's scheduler state at all.
    //
    // The call allocates nothing and cannot reach the five later sites. The
    // (since deleted) console `fork` command exercised the identical path with
    // the same zeroed `sepc`/`user_sp`/regs; this is that call without needing
    // typed input in QEMU's console, which is where an earlier attempt stalled.
    #[cfg(feature = "fork-refusal-probe")]
    {
        kprintln!("[FORK] refusal probe: calling fork from kernel context (must refuse)");
        let rc = azos_sched::process::sys_fork_impl(
            0, 0, &azos_sched::UserRegs::default());
        kprintln!("[FORK] refusal probe: rc={} (expected -1)", rc);
    }

    // Wave 15 (TRACE): the tracer's rings, one per CPU this boot brings up,
    // created before any secondary can record; the timestamps' rate is the
    // clock vDSO's (the live CNTFRQ_EL0 on aarch64). Nothing with KTRACE off.
    {
        let ts_hz = azos_drv_sys::timebase::freq();
        // SAFETY: linker-script symbols; only their addresses are taken.
        let text = unsafe { (&_text_start as *const u8 as usize, &_text_end as *const u8 as usize) };
        azos_ipc::trace::init(num_cpus, ts_hz, text);
        // Kconfig INSPECT: the introspection tree's regions and refresh task.
        #[cfg(feature = "inspect")]
        install_inspect(num_cpus);
        // Boot-once text rewrites (aarch64 `A64_PAN=probe`: every user-access
        // window site becomes `msr PAN` or `nop`), after the trace patcher's
        // alias exists and before any secondary runs the text.
        ARCH_ENTRY.boot_patch(text.0, text.1);
        // Kconfig LIVEPATCH: the signed topology's livepatch rows, applied
        // while one CPU runs. The grace period has nobody to wait for here:
        // `wake_harts` (below) is what sets the online mask, the boot CPU's
        // bit included, so `qsbr::Gp` starts with every CPU done and ends at
        // its first poll, with or without the QSBR clock hooks. A build
        // without LIVEPATCH refuses each row on the record.
        boot::install_livepatch();
        #[cfg(feature = "trace-cost-probe")]
        crate::smokes::trace_cost_probe(ts_hz);
        #[cfg(feature = "lat-trace")]
        azos_arch::lat_hook::lat::set_new_max_hook(crate::lat_trace::trace_new_max);
    }

    // Gate only: from here on every `current_cpu_id()` is checked against
    // the hardware id (`smokes/cpuid_probe.rs`).
    #[cfg(feature = "cpuid-probe")]
    crate::smokes::cpuid_probe::arm(num_cpus);

    // The idle-poll hook (`timebase::set_idle_poll_hook`): a deadline only the
    // timer interrupt observes is pending. Installed here, with the last of
    // the boot's hooks, because the seal below makes it read-only.
    azos_drv_sys::timebase::set_idle_poll_hook(idle_poll_wanted);
    // The saved-context path of CPU hotplug and the power-down idle states.
    boot_hooks::install_resume();

    // Every hook (`azos_common::ro_hook!`) is installed and the x86_64 IDT is
    // built: `.data.ro_after_init` goes read-only, before the ktests, any
    // secondary hart and the first task. A hook set from here on panics.
    // Runtime gate canary `canary=ro-seal-skip`: the hooks stay open and writable.
    if !canary!("ro-seal-skip") {
        boot::seal_ro_after_init();
    }

    // Kconfig KTEST: every registered test, then power off. Boot init is
    // done; no secondary hart is awake and no task has run.
    #[cfg(feature = "ktest")]
    ktest::run();

    // Kconfig CHAOS: the command line's injection points fire from here on.
    boot::chaos::go_live();

    ARCH_ENTRY.wake_secondaries(num_cpus);

    // The boot hart's timer interrupt stays off until the end of kernel_main
    // (see there); the other harts are already running tasks.

    // The same disagreement for Kconfig ENERGY, which emits the
    // `energy` feature. (The reverse, the feature without the symbol, is how
    // the gate's energy rows build against the stock QEMU .config.)
    #[cfg(not(feature = "energy"))]
    const _: () = assert!(
        !azos_limits::ENERGY,
        "CONFIG_ENERGY=y but the kernel was built without --features energy: \
         no utilisation tracking and no energy model are linked in"
    );

    // AZOS Phase 1 A4 — registry smoke. Register the static
    // UartDriver into the driver registry, then look it up by kind
    // and drive a write through `dyn Driver`. Proves the full
    // path (api → registry → lookup → trait dispatch →
    // hardware) end-to-end. Stays InKernel + isolated to this
    // smoke; the legacy `kprint!` macros are unchanged.
    {
        // Trait methods on `&dyn Driver` are accessible through the
        // return type itself — no explicit `use` needed.
        static UART_DRV: azos_drv_sys::uart_driver::UartDriver =
            azos_drv_sys::uart_driver::UartDriver::new();
        // The guard ends with the statement: no print under the registry lock.
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&UART_DRV);
        match reg {
            Ok(()) => kprintln!("[REG]  UART registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  UART register FAILED: {:?}", e),
        }
        let probe = azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .find_by_kind(/*DRV_KIND_UART*/ 0x0004);
        if let Some(drv) = probe {
            let _ = drv.init();
            let msg = b"[REG]  dyn Driver write via registry OK\n";
            match drv.handle_request(
                azos_drv_sys::uart_driver::UART_OP_WRITE,
                msg,
                &mut [],
            ) {
                Ok(_) => {} // bytes already printed by the driver
                Err(e) => azos_drv_sys::kerr!("[REG]  dyn Driver write FAILED: {:?}", e),
            }
        } else {
            kprintln!("[REG]  find_by_kind(UART) returned None");
        }

        // A3a.2 — register the second concrete `Driver` impl.
        // Validates that the trait + registry handle two unrelated
        // hardware families side by side (different DRV_KIND_*).
        static GPIO_DRV: azos_drv_gpio::gpio_driver::GpioDriver =
            azos_drv_gpio::gpio_driver::GpioDriver::new();
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&GPIO_DRV);
        match reg {
            Ok(()) => kprintln!("[REG]  GPIO registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  GPIO register FAILED: {:?}", e),
        }

        // A3a.3 — register the third concrete `Driver` impl.
        // Bus-oriented family; proves the trait scales across
        // hardware models (char / pin / bus).
        static I2C_DRV: azos_drv_bus::i2c_driver::I2cDriver =
            azos_drv_bus::i2c_driver::I2cDriver::new();
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&I2C_DRV);
        match reg {
            Ok(()) => kprintln!("[REG]  I2C  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  I2C  register FAILED: {:?}", e),
        }

        // A3a.4 — fourth: multi-parameter actuator (PWM).
        static PWM_DRV: azos_drv_actuator::pwm_driver::PwmDriver =
            azos_drv_actuator::pwm_driver::PwmDriver::new();
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&PWM_DRV);
        match reg {
            Ok(()) => kprintln!("[REG]  PWM  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  PWM  register FAILED: {:?}", e),
        }

        // A3a.5 — fifth: closed-loop controller (motor PID).
        // Pure software (no MMIO) — composes PWM + encoders.
        static MOTOR_DRV: azos_drv_actuator::motor_driver::MotorPidDriver =
            azos_drv_actuator::motor_driver::MotorPidDriver::new();
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&MOTOR_DRV);
        match reg {
            Ok(()) => kprintln!("[REG]  MTR  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  MTR  register FAILED: {:?}", e),
        }
    }

    // The network conformance probe and the loopback check: boot self-tests
    // (Kconfig BOOT_SELFTESTS, `smokes::net_conformance`), with the stack's
    // bring-up (Kconfig NET).
    #[cfg(all(feature = "boot-selftests", feature = "net"))]
    smokes::net_conformance::run(nic_present);
    #[cfg(not(all(feature = "boot-selftests", feature = "net")))]
    let _ = nic_present;

    // Wave 15 (SLAB): the heap's size-class cache, exercised in this
    // kernel's own environment (crates/core/mm/src/kheap.rs). Development
    // configurations only (`KHEAP_SLAB_DEBUG`); the gate's `kheap slab` rows
    // read this line.
    if azos_limits::KHEAP_SLAB && azos_limits::KHEAP_SLAB_DEBUG {
        match azos_mm::kheap::slab_selftest() {
            Ok((n, back)) => kprintln!(
                "[MM] Heap slab self-test: {} objects in {} classes, reclaim returned {} B: PASS",
                n, azos_limits::KHEAP_SLAB_CLASS_LIST.len(), back),
            Err(e) => kprintln!("[MM] Heap slab self-test FAILED: {}", e),
        }
    }

    // What the boot used: the heap and PMM figures the embedded budget is set
    // from.
    kprintln!("[MM] At scheduler start: heap {} B of {} KiB used, PMM {} of {} pages free",
        azos_mm::kheap::used(), azos_mm::kheap::size() >> 10,
        azos_mm::pmm::free_pages(), azos_mm::pmm::total_pages());

    // Wired-source delivery through APLIC -> IMSIC on
    // riscv64 AIA, counted by `irqchip::claim` (UART RX; nonzero only when
    // the console received input since the UART IRQ was enabled).
    // aarch64 twin: LPIs taken since the ITS self-test (the self-test runs
    // before this hart unmasks IRQs, so a completion's LPI may still be
    // pending there and only be taken once interrupts are on).
    #[cfg(target_arch = "aarch64")]
    if crate::boot_hooks::its_ready() {
        for (i, c) in crate::entry::aarch64::LPI_VECTOR_COUNT.iter().enumerate().take(2) {
            kprintln!("[ITS] LPI vector {} delivered {} time(s)", i,
                c.load(core::sync::atomic::Ordering::Acquire));
        }
    }
    azos_drv_virtio::virtio::net::print_msi_counts("at scheduler start");
    #[cfg(target_arch = "riscv64")]
    if azos_drv_irqchip::irqchip::is_aia() {
        kprintln!("[IRQ] AIA identity {} (uart) delivered {} time(s)",
            azos_drv_sys::uart::UART_IRQ,
            azos_drv_irqchip::irqchip::delivered(azos_drv_sys::uart::UART_IRQ));
    }
    // aarch64 twin: PL011 RX interrupts taken since `boot_hooks::console_irq` wired
    // the line (nonzero only when the console received input). The INTID
    // printed is the DTB-derived one the handler matches on.
    #[cfg(target_arch = "aarch64")]
    {
        let intid = crate::entry::aarch64::PL011_RX_INTID.load(core::sync::atomic::Ordering::Acquire);
        if intid != 0 {
            kprintln!("[IRQ] PL011 INTID {} (uart) delivered {} time(s)", intid,
                crate::entry::aarch64::PL011_RX_IRQS.load(core::sync::atomic::Ordering::Relaxed));
        } else {
            kprintln!("[IRQ] PL011 RX interrupt not wired: console polled");
        }
    }

    // WDT: arm the hardware watchdog (VF2/K1 only; a no-op under QEMU).
    // Shared call, same relative position on both ISAs (immediately before
    // entering the scheduler) — see each `arch_enter_scheduler`'s own doc
    // for why the feed-from-ISR precondition now holds on both.
    azos_actuation::watchdog::hw_init();
    // Wave 13 (owner decision, round 50): hart 0's idle keepalive runs only
    // while a watchdog is armed. What only a timer interrupt observes — the
    // K-C25 reaper — asks for a bounded idle sleep through the idle-poll hook
    // (installed before the seal above) instead (`timebase::IDLE_POLL_US`).
    match azos_drv_sys::timebase::idle_keepalive_us() {
        Some(us) => kprintln!("[WDT] idle keepalive on hart 0 every {} us (timeout {} ms / {})",
            us, azos_drv_sys::wdt::armed_timeout_ms(),
            azos_drv_sys::timer_arm::KEEPALIVES_PER_TIMEOUT),
        None => kprintln!("[WDT] no watchdog armed: no idle keepalive"),
    }

    // Gate only: the position the fork-refusal probe first sat at, where the
    // secondaries already run tasks and this hart has never scheduled.
    #[cfg(feature = "cpuid-probe")]
    crate::smokes::cpuid_probe::at_old_fork_probe_position(hart_id as usize, num_cpus);

    ARCH_ENTRY.enter_scheduler(hart_id)
}

/// The idle-poll hook (`timebase::set_idle_poll_hook`): a deadline only the
/// timer interrupt observes is pending — an orphaned wake stamp (K-C25).
fn idle_poll_wanted() -> bool {
    azos_sched::stamp_pending()
}
