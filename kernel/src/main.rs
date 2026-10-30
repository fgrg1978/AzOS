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
// off (config/subsys/Kconfig.robot RC_INPUT, GEOFENCE). On means compiled in.
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

/// Kconfig X86_64_LEVEL: the baseline x86_64's `boot.S` checks by CPUID before
/// any code compiled for it runs (`x86_level`, entry/x86_64/asm.rs), and the
/// level its boot line prints (`boot_hooks`).
// arch-only: x86_64's own baseline level; each ISA has its own.
#[cfg(target_arch = "x86_64")]
const X86_64_LEVEL: u32 = azos_arch_api::isa::x86_64::LEVEL_NUM as u32;

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

    // Phases 17 and G1: the robot hardware, payload and sensors, the behavior banner.
    boot::bring_up_robot();

    // Phase 5: the topology and what it declares, the console and log regions, then the scheduler.
    boot::init_scheduler(num_cpus, dtb_ptr);

    // The per-CPU idle tasks, aarch64's scheduler self-tests and watchdog, the recovery console.
    tasks::create_first_tasks(num_cpus);

    // The scheduler and real-time smokes (each feature-gated; none in a default image).
    smokes::spawn_sched_smokes(num_cpus);

    // The kernel's service, interrupt-wiring, robot, network and supervisor tasks, autorun.
    tasks::create_service_tasks(hart_id);

    // The ring-3 driver, safety and refusal smokes and the fork-refusal probe (feature-gated).
    smokes::spawn_system_smokes();

    // Wave 15 (TRACE): the tracer's rings, one per CPU this boot brings up,
    // created before any secondary can record; the timestamps are the raw
    // counter, unscaled, at its rate. Nothing with KTRACE off.
    {
        let ts_hz = azos_drv_sys::timebase::counter_freq();
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

    // The driver registry smoke: five drivers registered, one write through `dyn Driver`.
    smokes::driver_registry_smoke();

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
