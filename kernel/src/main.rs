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
// Panic record in reserved RAM, recovered into /fat/CRASH.LOG on the next
// boot (Kconfig `PSTORE_SIZE_KB`).
mod pstore;

// DEV02 — USB DFU 1.1 recovery mode glue. The init function is
// called from a recovery-trigger path that is not yet wired (no
// USB-OTG controller driver on hand pre-Julio 2026), so the
// module is dead from main's POV.
#[allow(dead_code)]
mod dfu_recovery;

// Item 2 Stage 3 batch 7 — per-arch trap entry modules + TrapContext
// trait. Defines the cross-arch surface for trap handling; the
// existing riscv trap_handler in this file still uses the native
// TrapFrame directly (S3.b7 scaffolding only — refactor is .next).
#[allow(dead_code)]
mod entry;

// DEV03 — USB MSC gadget glue (FAT32-backed LUN over Bulk-Only Transport).
// USB device controller wiring is stubbed; pure dispatch
// logic is covered by tests/host/msc-tests.
#[allow(dead_code)]
mod msc_gadget;

// RFC-0049 M4: the cold-restart supervisor for ring-3 drivers.
mod drv_supervisor;

// RFC-0055: who has the console, the ring-3 user shell or the recovery console.
mod console_mode;

// Opt-in f32 cost lanes, see the module doc.
#[cfg(all(feature = "mlsf-bench", not(feature = "no-ml")))]
mod mlsf_bench;

// Per-step timing of the behavior loop (`[BSTEP]`), see the module doc.
#[cfg(feature = "domain-robot")]
mod behavior_step;

// The behavior loop's client of the ring-3 ML service, see the module doc.
#[cfg(all(feature = "domain-robot", not(feature = "no-ml")))]
mod behavior_ml;

// The Robot application domain (wave 11, DOMAIN): a .config that selects
// DOMAIN_ROBOT must be built with the `domain-robot` feature, or the image
// would silently lack the robot it was configured for. Build through
// tools/kconfig_to_cargo.py, which emits the feature from the .config. The
// converse (the feature on, another domain in .config) is allowed: it is the
// cargo default, which hand-written `--features` lines rely on.
const _: () = assert!(
    !azos_limits::DOMAIN_ROBOT || cfg!(feature = "domain-robot"),
    "the .config selects DOMAIN_ROBOT but the kernel was built without the \
     `domain-robot` feature: build with $(python3 tools/kconfig_to_cargo.py <config>)",
);
// Wave 15: the same rule for the two robot subsystems the .config can turn
// off (config/Kconfig.robot RC_INPUT, GEOFENCE). On means compiled in.
const _: () = assert!(
    !azos_limits::RC_INPUT || cfg!(feature = "rc-input"),
    "the .config selects RC_INPUT but the kernel was built without the `rc-input` feature",
);
const _: () = assert!(
    !azos_limits::GEOFENCE || cfg!(feature = "geofence"),
    "the .config selects GEOFENCE but the kernel was built without the `geofence` feature",
);

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
mod smokes;
use smokes::*;
#[cfg(target_arch = "riscv64")]
mod trap;
#[cfg(target_arch = "riscv64")]
use trap::*;

use core::arch::global_asm;
#[cfg(target_arch = "riscv64")]
use core::sync::atomic::Ordering;
// Phase 3 (context switch + scheduler): task A/B iteration counters,
// preemption markers, and the FP-across-a-real-switch canary all live at
// module scope (see the `kernel_main` tail below), so this needs its own
// top-level import — the riscv64 one above is `#[cfg]`'d away on this
// target and a local `use` inside one function would not cover statics
// declared outside it.
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
use core::sync::atomic::Ordering;
// NOT `#[cfg]`'d: read from the shared CONFIG.INI-apply block (kernel-main-
// merge task) and from `camera_send_frame`, both now unconditional.
use azos_config::ML_ENABLED;
use azos_drv_sys::kprintln;
// `flight_control_task`/`rt_motor_task` are read from the shared task
// roster (kernel-main-merge task) and so must resolve on both ISAs now.
// `txn_try_rollback` stays riscv64-gated: its only call site is
// `handle_exception`, which still reads the riscv64-native `TrapFrame`
// directly and has no aarch64 counterpart in this file — an unconditional
// import here would be unused (and a build warning) on an aarch64 build.
#[cfg(feature = "domain-robot")]
use azos_safety_core::{flight_ctrl::flight_control_task, rt_motor::rt_motor_task};
#[cfg(all(target_arch = "riscv64", feature = "domain-robot"))]
use azos_safety_core::txn::txn_try_rollback;
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
    TRAP_ECALL_FROM_U, TRAP_ECALL_FROM_S,
    TRAP_INSTR_PAGE_FAULT, TRAP_LOAD_PAGE_FAULT, TRAP_STORE_PAGE_FAULT,
};
#[cfg(target_arch = "riscv64")]
use azos_arch::csr;
// In scope for `ARCH.enable_all()` / `ARCH.disable_all()`. `csr` above stays:
// this file still reads `SSTATUS_SPP` out of a saved TRAP FRAME to tell a
// user trap from a supervisor one, which is a different thing from the live
// enable state and has no cross-ISA equivalent to migrate onto.
#[cfg(target_arch = "riscv64")]
use azos_arch::Interrupts;

// Include boot assembly
// All these .S files are RISC-V; lives in entry/riscv64/asm per Item 2
// Stage 3 batch 7 (per-arch entry organisation).  aarch64 boot/trap asm
// sits in entry/aarch64/asm — currently a stub README; will get the real
// asm in Stage 5 when the kernel boots on that ISA. (x86_64's entry/
// scaffolding was deleted 2026-09-21, B2-04.)
// `max_harts` is injected rather than duplicated: both files size per-hart
// tables (`secondary_stacks`, K-C16's trap vectors) and a hand-written `.equ`
// in each is exactly the class of constant that drifts out of sync silently —
// here the symptom would be a hart writing outside its own slot.
#[cfg(target_arch = "riscv64")]
global_asm!(
    include_str!("entry/riscv64/asm/boot.S"),
    max_harts = const MAX_HARTS,
);

// Include trap entry assembly.
// B2-01: the six TrapFrame layout constants (TRAP_FRAME_SIZE, TF_SEPC,
// TF_SSTATUS, TF_SCAUSE, TF_STVAL, TF_SP) used to be `.equ`-hand-written in
// trap_entry.S with a comment claiming they matched "crates/core/arch/src/
// trap.rs" — a facade that only re-exports; the struct lives in
// crates/core/arch-riscv64/src/trap.rs and had no compile-time link to that
// comment at all. Injected here the same way task_satp_off/context_saving_off
// are below: size_of!/offset_of! read the real struct, so a field added
// before `sepc` moves every one of these automatically instead of silently
// disagreeing with a hand-copied number.
#[cfg(target_arch = "riscv64")]
global_asm!(
    include_str!("entry/riscv64/asm/trap_entry.S"),
    max_harts = const MAX_HARTS,
    irq_stack_size = const IRQ_STACK_SIZE,
    trap_frame_size = const core::mem::size_of::<TrapFrame>(),
    tf_sepc = const core::mem::offset_of!(TrapFrame, sepc),
    tf_sstatus = const core::mem::offset_of!(TrapFrame, sstatus),
    tf_scause = const core::mem::offset_of!(TrapFrame, scause),
    tf_stval = const core::mem::offset_of!(TrapFrame, stval),
    // regs[2] = saved SP (x2); the asm's `TF_SP(sp)` accesses assume `regs`
    // sits at offset 0 (see the assert next to TrapFrame in trap.rs) — this
    // still reads the offset rather than hardcoding it so a reordering of
    // TrapFrame's own fields cannot silently break the SP save/restore.
    tf_sp = const core::mem::offset_of!(TrapFrame, regs) + 2 * 8,
);

// Include context switch assembly.
// Phase 12: when rvv feature is active, use the RVV-aware variant.
// TASK_SATP_OFFSET is injected at compile time via offset_of! — if someone
// adds fields before task_satp, the offset updates automatically.
#[cfg(target_arch = "riscv64")]
#[cfg(not(feature = "rvv"))]
global_asm!(
    include_str!("entry/riscv64/asm/context_switch.S"),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    // K-C23: context_saving is cleared straight from the asm (fence + sb) —
    // a Rust helper's Release store publishes the old task's stack as
    // reusable while still running ON that stack, so the helper must not
    // have a frame; injecting the offset keeps the asm store correct even
    // if fields move. (Passed to context_switch_rvv.S below as well, since
    // 2026-09-24: that file clears the flag with the same tail now, so the
    // two switches take the identical pair of offsets from this one site.)
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    // The TLB root table (`TLB_MAX_HARTS`) is the same Kconfig `NR_CPUS` long.
    tlb_max_harts = const MAX_HARTS,
);
#[cfg(target_arch = "riscv64")]
#[cfg(feature = "rvv")]
global_asm!(
    include_str!("entry/riscv64/asm/context_switch_rvv.S"),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    // Passed since 2026-09-24: this file now clears `context_saving` with the
    // same K-C23 fence+sb release tail as the scalar switch, so it needs the
    // same offset. It used to take only `task_satp_off` — and the scheduler
    // paid for that with twelve `cfg` sites that compiled the K-C24
    // double-dispatch protection out of every rvv build, `k1` included.
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    // TID for rvv_ctx_save/rvv_ctx_restore's VEC_STATES[] index — read here
    // via offset_of! and loaded in the .S at each call site, replacing a
    // `task_ptr.add(120)` read inside rvv.rs that was actually
    // TaskContext.tp (the hart id, CTX_TP = 120 in context_switch.S), not
    // Task.tid (offset 128). Every context switch under `rvv` was
    // saving/restoring v0-v31/vl/vtype/vstart into the wrong slot.
    task_tid_off = const core::mem::offset_of!(azos_sched::task::Task, tid),
    // The TLB root table (`TLB_MAX_HARTS`) is the same Kconfig `NR_CPUS` long.
    tlb_max_harts = const MAX_HARTS,
);

// ── Page size: one Kconfig choice, two routes into the build ────────────
//
// config/Kconfig.arch's AARCH64_PAGE_* choice reaches `azos_limits` as
// PAGE_SHIFT (from `.config`) and `azos_arch_api` as the cargo feature
// `page-16k`/`page-64k` (tools/kconfig_to_cargo.py). Every page-table walk
// uses the second; budgets and Kconfig checks use the first. A build that
// passed `--features qemu` with a 16 KiB `.config`, or the reverse, stops
// here instead of booting with two page sizes.
const _: () = assert!(
    azos_arch_api::PAGE_SHIFT == azos_limits::PAGE_SHIFT,
    "page size mismatch: .config (azos_limits::PAGE_SHIFT) and the cargo features \
     (page-16k / page-64k -> azos_arch_api::PAGE_SHIFT) disagree; build with the \
     features tools/kconfig_to_cargo.py prints for this .config",
);

// ── aarch64 boot + trap asm — Item 2 Stage 5 ────────────────────────────
//
// boot.S, trap_entry.S and context_switch.S; each file's header comment
// says what it covers. `max_harts` mirrors the riscv64 injection above —
// MAX_HARTS is defined below this block, which is fine: `const` items resolve by name
// within the module regardless of textual order.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("entry/aarch64/asm/boot.S"),
    max_harts = const MAX_HARTS,
    // One constant, three consumers (Rust, this asm, the linker script's
    // ASSERT against `_kernel_va_offset_check`): a drift fails to LINK.
    kernel_va_offset = const azos_arch::mmu::KERNEL_VA_OFFSET,
    // The same tie for the granule: linker-aarch64.ld ASSERTs its
    // `AZOS_PAGE_SIZE` (kernel/build.rs) against `_azos_page_size_check`.
    page_size = const azos_arch::PAGE_SIZE,
    // Kconfig `A64_PAN` not `n`: boot.S may set PSTATE.PAN (when the ID
    // register says the core has it). The canary drops that probe.
    pan_allowed = const azos_arch_api::isa::aarch64::PAN.allowed() as u8,
    pan_unprobed = const cfg!(feature = "a64-pan-unprobed-canary") as u8,
);

// TrapFrame layout + vector-number constants (B2-01 pattern): read off the
// real `entry::aarch64::TrapFrame` struct and its `VEC_*` constants via
// size_of!/offset_of! rather than hand-copied literals — see that file's
// doc comment on why the size assert alone isn't enough (the padding
// story) and trap_entry.S's own header for how these operands are used.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("entry/aarch64/asm/trap_entry.S"),
    trap_frame_size = const core::mem::size_of::<entry::aarch64::TrapFrame>(),
    tf_off_elr      = const core::mem::offset_of!(entry::aarch64::TrapFrame, elr_el1),
    tf_off_spsr     = const core::mem::offset_of!(entry::aarch64::TrapFrame, spsr_el1),
    tf_off_sp_el0   = const core::mem::offset_of!(entry::aarch64::TrapFrame, sp_el0),
    tf_off_far      = const core::mem::offset_of!(entry::aarch64::TrapFrame, far_el1),
    tf_off_esr      = const core::mem::offset_of!(entry::aarch64::TrapFrame, esr_el1),
    tf_off_vector   = const core::mem::offset_of!(entry::aarch64::TrapFrame, vector),
    tf_off_fpstate  = const core::mem::offset_of!(entry::aarch64::TrapFrame, fpstate),
    vec_sync_cur    = const entry::aarch64::VEC_SYNC_CURRENT_EL_SP0,
    vec_irq_cur     = const entry::aarch64::VEC_IRQ_CURRENT_EL_SP0,
    vec_sync_lo     = const entry::aarch64::VEC_SYNC_LOWER_EL,
    vec_irq_lo      = const entry::aarch64::VEC_IRQ_LOWER_EL,
    // Same constants riscv64's own trap_entry.S takes above — MAX_HARTS is
    // ISA-neutral (defined once, below, for both boot.S files already);
    // AARCH64_IRQ_STACK_SIZE mirrors riscv64's IRQ_STACK_SIZE (task 1: "IRQs
    // taken on a per-CPU IRQ stack", the same shape, not a copy of riscv64's
    // own slots — see that const's doc comment).
    max_harts       = const MAX_HARTS,
    irq_stack_size  = const IRQ_STACK_SIZE,
);

// Context switch asm — Phase 3 (context switch + scheduler on aarch64).
// Same B2-01 shape as the two blocks above: every offset read off the real
// `azos_sched::task::TaskContext` / `Task` structs via `offset_of!`,
// never hand-copied. `task_satp_off`/`context_saving_off` are the SAME two
// constants riscv64's own context_switch.S takes above (same fields, same
// meaning — see that block's comment) — not a second, drifting copy.
#[cfg(target_arch = "aarch64")]
global_asm!(
    include_str!("entry/aarch64/asm/context_switch.S"),
    ctx_ra  = const core::mem::offset_of!(azos_sched::task::TaskContext, ra),
    ctx_sp  = const core::mem::offset_of!(azos_sched::task::TaskContext, sp),
    ctx_x19 = const core::mem::offset_of!(azos_sched::task::TaskContext, x19),
    ctx_x21 = const core::mem::offset_of!(azos_sched::task::TaskContext, x21),
    ctx_x23 = const core::mem::offset_of!(azos_sched::task::TaskContext, x23),
    ctx_x25 = const core::mem::offset_of!(azos_sched::task::TaskContext, x25),
    ctx_x27 = const core::mem::offset_of!(azos_sched::task::TaskContext, x27),
    ctx_x29 = const core::mem::offset_of!(azos_sched::task::TaskContext, x29),
    ctx_pc  = const core::mem::offset_of!(azos_sched::task::TaskContext, pc),
    ctx_tp  = const core::mem::offset_of!(azos_sched::task::TaskContext, tp),
    ctx_d8  = const core::mem::offset_of!(azos_sched::task::TaskContext, d8),
    ctx_d10 = const core::mem::offset_of!(azos_sched::task::TaskContext, d10),
    ctx_d12 = const core::mem::offset_of!(azos_sched::task::TaskContext, d12),
    ctx_d14 = const core::mem::offset_of!(azos_sched::task::TaskContext, d14),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
);

// x86_64: the PVH boot path (boot.S: baseline check, long mode, IDT, then
// kernel_main) and the trap / switch stubs, AT&T syntax like the other
// ISAs' files. `x86_level` is Kconfig X86_64_LEVEL, checked by CPUID before
// any code compiled for that level runs.
// arch-only: x86_64's own asm files and level; each ISA includes its own.
#[cfg(target_arch = "x86_64")]
const X86_64_LEVEL: u32 = azos_arch_api::isa::x86_64::LEVEL_NUM as u32;
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("entry/x86_64/asm/boot.S"),
    x86_level = const X86_64_LEVEL,
    options(att_syntax),
);
// The trap entry and the switch: every TrapFrame / PerCpu / TaskContext /
// Task offset read off the real structs (B2-01), as for the other ISAs.
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("entry/x86_64/asm/trap_entry.S"),
    tf_size        = const core::mem::size_of::<entry::x86_64::TrapFrame>(),
    tf_cr2         = const core::mem::offset_of!(entry::x86_64::TrapFrame, cr2),
    tf_gs_saved    = const core::mem::offset_of!(entry::x86_64::TrapFrame, gs_saved),
    tf_vector      = const core::mem::offset_of!(entry::x86_64::TrapFrame, vector),
    tf_rip         = const core::mem::offset_of!(entry::x86_64::TrapFrame, rip),
    tf_cs          = const core::mem::offset_of!(entry::x86_64::TrapFrame, cs),
    tf_rflags      = const core::mem::offset_of!(entry::x86_64::TrapFrame, rflags),
    tf_rsp         = const core::mem::offset_of!(entry::x86_64::TrapFrame, rsp),
    r_rax          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RAX),
    r_rbx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RBX),
    r_rcx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RCX),
    r_rdx          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RDX),
    r_rsi          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RSI),
    r_rdi          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RDI),
    r_rbp          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::RBP),
    r_r8           = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R8),
    r_r9           = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R9),
    r_r10          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R10),
    r_r11          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R11),
    r_r12          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R12),
    r_r13          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R13),
    r_r14          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R14),
    r_r15          = const entry::x86_64::tf_reg(azos_arch::fork_regs::gpr::R15),
    pc_kernel_rsp  = const azos_arch::cpu::PERCPU_KERNEL_RSP,
    pc_user_rsp    = const azos_arch::cpu::PERCPU_USER_RSP,
    pc_fp_live     = const azos_arch::cpu::PERCPU_FP_LIVE,
    pc_tss_rsp0    = const azos_arch::cpu::PERCPU_TSS_RSP0,
    pc_cr3         = const azos_arch::cpu::PERCPU_CR3,
    syscall_vector = const azos_arch::idt::SYSCALL_VECTOR,
    first_interrupt = const azos_arch::idt::FIRST_INTERRUPT,
    user_cs        = const azos_arch::gdt::USER_CS,
    user_ds        = const azos_arch::gdt::USER_DS,
    irq_handler_stack = const entry::x86_64::cpu_init::IRQ_HANDLER_STACK,
    rflags_tf_rf   = const azos_arch::cpu::RFLAGS_TF | azos_arch::cpu::RFLAGS_RF,
    use_sysret     = const azos_limits::X86_SYSRET as u32,
    smap_clac      = const azos_arch_api::isa::x86_64::SMAP.allowed() as u32,
    options(att_syntax),
);
#[cfg(target_arch = "x86_64")]
global_asm!(
    include_str!("entry/x86_64/asm/context_switch.S"),
    ctx_ra  = const core::mem::offset_of!(azos_sched::task::TaskContext, ra),
    ctx_sp  = const core::mem::offset_of!(azos_sched::task::TaskContext, sp),
    ctx_rbx = const core::mem::offset_of!(azos_sched::task::TaskContext, rbx),
    ctx_rbp = const core::mem::offset_of!(azos_sched::task::TaskContext, rbp),
    ctx_r12 = const core::mem::offset_of!(azos_sched::task::TaskContext, r12),
    ctx_r13 = const core::mem::offset_of!(azos_sched::task::TaskContext, r13),
    ctx_r14 = const core::mem::offset_of!(azos_sched::task::TaskContext, r14),
    ctx_r15 = const core::mem::offset_of!(azos_sched::task::TaskContext, r15),
    ctx_pc  = const core::mem::offset_of!(azos_sched::task::TaskContext, pc),
    task_satp_off = const core::mem::offset_of!(azos_sched::task::Task, task_satp),
    context_saving_off = const core::mem::offset_of!(azos_sched::task::Task, context_saving),
    pc_fp_live = const azos_arch::cpu::PERCPU_FP_LIVE,
    pc_cr3     = const azos_arch::cpu::PERCPU_CR3,
    options(att_syntax),
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

/// Same class of copied-constant drift (`feedback-a-copied-feature-list-
/// drifts-like-any-constant.md`), aarch64-specific: Phase 4's hart→MPIDR
/// table (`crates/core/sched::smp::AARCH64_HART_TABLE_LEN`) and `dtb_cpu_regs`'s
/// own output buffer (`azos_dtb::MAX_CPU_REG`) are both sized `8` by
/// hand, independently of this file's `MAX_HARTS`. A DTB that names more
/// CPUs than either of those two can hold degrades silently (the extra
/// harts never get an affinity published, so `wake_hart` never starts
/// them) rather than failing the build the way an actually-undersized
/// `MAX_HARTS` does above — this is what makes that undersizing loud
/// instead.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(MAX_HARTS <= azos_sched::smp::AARCH64_HART_TABLE_LEN);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(MAX_HARTS <= azos_dtb::MAX_CPU_REG);

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


/// Number of worker tasks for the SMP stress test.
const NUM_WORKERS: usize = 15;
/// Task slots the stress workers never take: what the rest of boot still
/// creates after them (kernel tasks, topology rows, the user shell).
const WORKER_POOL_RESERVE: usize = 16;


// ── Per-arch boot hooks (kernel-main-merge task, 2026-09-24) ───────────────
// Declared here, not from `entry/riscv64.rs` / `entry/aarch64.rs`: these are
// new sibling modules of `entry`, not submodules of it (B2-04 owns
// `entry/riscv64.rs`'s own trap-context work; this keeps the two files
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
/// only by the riscv64 PMP audit block inside the shared body, so an aarch64
/// build leaves them unread; `#[allow(dead_code)]` rather than per-field
/// `cfg`, since the generic early boot computes them on every ISA.
#[allow(dead_code)]
pub struct EarlyBoot {
    pub num_cpus: usize,
    pub heap_start: usize,
    pub kernel_end_aligned: usize,
    /// The DTB's `pci-host-ecam-generic` node (`azos_dtb::dtb_pci_host`),
    /// read during early boot. `None`: no DTB, or no such node.
    pub pci_host: Option<azos_dtb::PciHost>,
}
/// Kernel entry point. Called from boot.S (hart 0 only, both ISAs).
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
pub extern "C" fn kernel_main(hart_id: usize, dtb_ptr: usize) -> ! {
    let early = boot::early_main(hart_id, dtb_ptr);
    // The kernel's own page table, live from here, maps the pstore region:
    // a panic from now on leaves a RAM record.
    pstore::arm();
    let num_cpus = early.num_cpus;
    // The per-CPU areas, one per possible CPU (the DTB's count, cut to
    // NR_CPUS by `boot::early_main`), from the frame allocator: after the
    // heap, before the scheduler, the first task and the secondaries.
    boot::setup_per_cpu_areas();
    // Read only by the riscv64-only PMP audit block further down (the one
    // block in this shared body that still names `pmp::pmp_regions`
    // directly) — see `EarlyBoot`'s own doc.
    #[cfg(target_arch = "riscv64")]
    let heap_start = early.heap_start;
    #[cfg(target_arch = "riscv64")]
    let kernel_end_aligned = early.kernel_end_aligned;

    // ══════════════════════════════════════════════════════════════════════
    //  LATE INIT — interrupts enabled, heap available, full hardware access
    // ══════════════════════════════════════════════════════════════════════

    // ---- Phase 6: VirtIO Block + VFS + Network ----

    kprintln!("========================================");
    kprintln!(" Phase 6: Storage + Network");
    kprintln!("========================================");
    kprintln!();

    // Wire PiMutex/preempt/exit/WaitQueue callbacks through the scheduler.
    // Shared with aarch64's kernel_main — see `install_sched_hooks`'s own
    // doc for what each callback does and what silently degrades without
    // it. MOVED here (kernel-main-merge task, ordering-decision #1) from
    // this function's old, much later position (right before the task-spawn
    // block, after `install_topology`/`azos_sched::init()`) to match
    // aarch64's early position: `install_sched_hooks()` only stores function
    // pointers into `azos_sync`/`azos_sched` statics — verified, no
    // dependency on `azos_sched::init()` or any task-pool state — so
    // calling it this early is safe on both ISAs, and it must run before
    // anything can be woken/blocked/boosted/exit, which this position still
    // satisfies (well before the first `task_create*` below).
    install_sched_hooks();

    // ── Entropy: virtio-rng seeds the kernel pool ────────────────────────────
    // Shared with aarch64's kernel_main — see `install_entropy`'s own doc
    // for the full reasoning and the ordering constraint.
    ARCH_ENTRY.map_late_mmio();
    install_entropy();

    match azos_drv_block::blkdev::init() {
        Ok(()) => {
            kprintln!("[FS] Block device OK ({} sectors)",
                azos_drv_block::blkdev::capacity_sectors());
            publish_partitions();
        }
        Err(()) => kprintln!("[FS] Block device not found (no disk)"),
    }
    // Persisted entropy seed: mixed and replaced here, before anything but the
    // virtio-rng seed has drawn from the pool, then the canary (which needs the
    // pool as seeded as it will get).
    install_entropy_seed();
    install_stack_canary();

    // Measure the CPU clock against the CLINT timebase, before anything reads a
    // WCET or jitter figure. `rdcycle` runs at the core clock and the tree has
    // no constant for it on any board; the conversion used to divide by
    // `TIMER_FREQ` instead, which on the VF2 made every microsecond figure
    // roughly 375x too large. Measuring needs no datasheet and is right on a
    // board nobody has characterised.
    azos_drv_sys::wcet::calibrate_cpu_freq();
    kprintln!("[WCET] CPU clock measured: {} cycles/us",
              azos_drv_sys::wcet::cycles_per_us());

    // Ramfs root, the `FileOps` seam behind `SYS_OPEN`/`SYS_SPAWN`, the
    // actuation gate and io_ring — see `install_ring3_seams`'s own doc.
    install_ring3_seams();

    // F20: TmpFS — bounded in-RAM temporary filesystem.
    kprintln!("[FS] tmpfs ready — max {} files, {} KiB cap",
        azos_fs::TMPFS_MAX_FILES,
        azos_fs::TMPFS_MAX_BYTES / 1024);

    // F21: Procfs + sysfs. Shared with aarch64's kernel_main — see
    // `install_procfs`'s own doc for the full reasoning and the ordering
    // constraint. Runtime gate canary `canary=procfs-skip` (KTEST): not
    // installed.
    if !canary!("procfs-skip") {
        install_procfs();
    }
    // Wave 12: `/proc` through the VFS, so ring 3 reads it with the file
    // calls (the user shell's `ps` reads `/proc/tasks`). Read-only: the
    // procfs backend refuses every write. Independent of the disk.
    match azos_fs::vfs_mount_fs(b"/proc", &azos_fs::PROCFS_FS) {
        Ok(()) => kprintln!("[FS] procfs mounted at /proc"),
        Err(()) => azos_drv_sys::kerr!("[FS] procfs vfs_mount failed"),
    }

    // ---- Phase 8: IPC + Signals + Services ----
    // Shared with aarch64's kernel_main — see `install_ipc_plumbing`'s own
    // doc for the full reasoning. MOVED here (kernel-main-merge task,
    // ordering-decision #7) from this function's old, much later position
    // (after net/OTA-listener setup) to match aarch64's position, which its
    // own doc already documents as safe in this direction ("earlier can
    // only make more tasks see initialized IPC state, never fewer") —
    // `pipe_init`/`signal_init`/`service_init` only touch their own module
    // statics, no dependency on net/disk/FAT32 state.
    install_ipc_plumbing();

    if azos_drv_block::blkdev::capacity_sectors() > 0 {
        match azos_fs::fat32_mount() {
            Ok(()) => {
                match azos_fs::vfs_mount(b"/fat", azos_fs::FS_TYPE_FAT32) {
                    Ok(())  => {
                        kprintln!("[FS] FAT32 mounted at /fat");
                        // A panic record the previous boot left in RAM goes
                        // into /fat/CRASH.LOG now.
                        pstore::recover();
                        #[cfg(feature = "pstore-smoke")]
                        pstore::smoke();
                    }
                    Err(()) => azos_drv_sys::kerr!("[FS] FAT32 vfs_mount failed"),
                }
                #[cfg(feature = "fat-barrier-smoke")]
                fat_barrier_smoke();
                // Shared with aarch64's kernel_main — see `install_flight_recorder`'s
                // own doc for the full reasoning and the ordering constraint (must run
                // before `robot_init()`).
                install_flight_recorder();
            }
            Err(()) => azos_drv_sys::kerr!("[FS] FAT32 mount failed (disk not FAT32?)"),
        }
    }
    kprintln!();

    // ---- Optional: HDMI framebuffer (VF2 only, --features hdmi) ─────────────
    // Never validated against real hardware — QEMU has no model for this
    // peripheral. See crates/drivers/display. PHY calibration is unconfirmed placeholder
    // data (crates/drivers/display/src/hdmi.rs) — expect no signal on a real
    // monitor even with this call wired correctly.
    #[cfg(feature = "hdmi")]
    azos_display::display_init();

    // ---- Optional: QEMU ramfb test (--features ramfb) ────────────────────────
    // Unrelated to the real VF2 display driver above — see
    // crates/drivers/display/src/ramfb.rs. Needs -device ramfb -display <backend>
    // on the QEMU command line, not this whole session's usual -nographic.
    #[cfg(feature = "ramfb")]
    azos_display::qemu_display_init();

    // ---- Phase G2: Persistent State Recovery ────────────────────────────────
    //
    // Load /fat/CONFIG.INI BEFORE net_init() and task creation so every
    // subsystem starts with the persisted (or factory-default) configuration.
    // First-boot: generate defaults and write CONFIG.INI to disk.

    kprintln!("========================================");
    kprintln!(" Phase G2: Persistent State Recovery");
    kprintln!("========================================");
    {
        // CONFIG.INI under its signed authority: CONFIG.SIG format v2 (device
        // id + a counter the device record's floor never lets go backwards),
        // and a provisioned device that loses that authority latches the
        // e-stop. The whole policy and its reasons: `boot/config_auth.rs`.
        load_signed_config();
        azos_config::cfg_apply();
        kprintln!("[CFG] {} entries, ml_enabled={}",
            azos_config::cfg_count(),
            ML_ENABLED.load(Ordering::Relaxed) as u8);

        // ── OTA boot validation + secure boot (SHARED with aarch64) ───
        // The whole block — A/B slot, CRC, Ed25519, decision 99's fall to
        // recovery, the `bad_slots` record — moved into
        // `boot_validate_and_verify_slots()` so aarch64's `kernel_main`
        // runs the same code instead of a copy. See that function's doc
        // for the three preconditions this call site satisfies.
        boot_validate_and_verify_slots();

        // ── Authenticated brain channel key (reserved MSC tail sector) ──
        // 32-byte pre-shared key for the brain↔kernel HMAC envelope
        // (`azos_behavior::auth_envelope`). If present, all
        // brain-protocol TCP frames get wrapped/unwrapped; if absent, the
        // wrap/unwrap functions fall back to identity (legacy plaintext).
        // The brain's matching key lives in env `AZOS_BRAIN_LINK_KEY`.
        //
        // U06-9/#30 (2026-09-26): this used to be an ordinary FAT32 file,
        // `/fat/LINK.KEY` — and `Fat32BlockDevice` (`msc_gadget.rs`) exports
        // the whole FAT32 volume block-for-block with no LUN/LBA
        // restriction, so ANY file on that volume is reachable,
        // unauthenticated, over `READ_10` the moment the DWC2 controller is
        // wired — not just the ones outside `/fat`'s visible directory
        // tree. The key now lives in `msc_gadget`'s reserved tail sectors,
        // which `Fat32BlockDevice::new()` subtracts from the capacity it
        // reports over USB — genuinely unaddressable from that port, not
        // merely undiscoverable. See `msc_gadget::MSC_RESERVED_TAIL_SECTORS`
        // for the mechanism and its own deployment note (needs the disk
        // image sized with the reserved headroom — `w2-b6-Makefile.diff`).
        //
        // Whether an absent key silently downgrades the link to plaintext is
        // a policy decision, and like secure boot it is fixed at COMPILE
        // time by the `link-auth-enforced` feature: with it compiled in
        // there must be no runtime flag, debug build, or code path that
        // relaxes the requirement. The load below always runs so the trust
        // state is visible on the console; only the "refuse to boot" half
        // is gated.
        //
        // The brain link is the Robot domain's (wave 11): without it there is
        // no link to key and nothing below runs.
        #[cfg(feature = "domain-robot")]
        let mut link_authenticated = false;
        // No initialiser: every branch below assigns it, and a placeholder
        // value here would be dead (rustc says so, and warnings fail CI).
        #[cfg(feature = "domain-robot")]
        let link_auth_reason: &str;
        #[cfg(feature = "domain-robot")]
        {
            const LINK_KEY_BYTES: usize = azos_behavior::auth_envelope::KEY_BYTES;
            let mut key_buf = [0u8; LINK_KEY_BYTES];
            // `reserved_region_read` always fills `key_buf` completely on
            // `Ok` (no partial-read case, unlike the old `vfs_read`) — the
            // "wrong size" branch the FAT32 path needed is gone with it.
            // `Err` covers both "no key ever provisioned" and "this image
            // was built without the reserved headroom" (U06-9's deployment
            // note) — both must degrade the same way a missing file did.
            if crate::msc_gadget::reserved_region_read(
                crate::msc_gadget::RESERVED_SECTOR_LINK_KEY, &mut key_buf,
            ).is_ok() && key_buf.iter().any(|b| *b != 0) {
                // SAFETY: init is `unsafe` because it writes the
                // crate-local key/state via static-mut writes; we call it
                // exactly once during boot, single-threaded, before any
                // task that uses wrap/unwrap is spawned.
                if unsafe { azos_behavior::auth_envelope::init(&key_buf) } {
                    kprintln!("[SECCHAN] link key loaded ({} bytes, reserved sector {}) — \
                               brain link authenticated",
                        LINK_KEY_BYTES, crate::msc_gadget::RESERVED_SECTOR_LINK_KEY);
                    link_authenticated = true;
                    link_auth_reason = "key loaded";
                } else {
                    azos_drv_sys::kerr!("[SECCHAN] link key rejected by auth_envelope::init");
                    link_auth_reason = "key rejected by auth_envelope::init";
                }
            } else {
                azos_drv_sys::kwarn!("[SECCHAN] link key absent (reserved sector {} unreadable or \
                           all-zero) — brain link runs plaintext",
                    crate::msc_gadget::RESERVED_SECTOR_LINK_KEY);
                link_auth_reason = "key sector absent/unprovisioned";
            }
        }

        // U06-9 (2026-09-26): the ring-3 door onto this same reserved
        // sector (`SYS_LINK_KEY_READ_TYPED`, `crates/core/syscall/src/link_key.rs`).
        // Registered right after the load above so the hook re-reads the
        // exact same sector this boot just logged the state of — a ring-3
        // caller holding the capability sees the same bytes, not a second,
        // possibly different, read. `crates/core/syscall` cannot call
        // `msc_gadget::reserved_region_read` directly (that module lives in
        // `kernel/src`, above it in the dependency graph), same TCB reason
        // `ESTOP_HANDLER` is a hook and not a call.
        fn read_link_key_for_ring3(
            out: &mut [u8; azos_syscall::link_key::LINK_KEY_BYTES],
        ) -> bool {
            crate::msc_gadget::reserved_region_read(
                crate::msc_gadget::RESERVED_SECTOR_LINK_KEY, out,
            ).is_ok() && out.iter().any(|b| *b != 0)
        }
        azos_syscall::link_key::set_link_key_read_hook(read_link_key_for_ring3);

        // ── Operator e-stop release authority (`/fat/OPERATOR.PUB`) ──────
        // Owner decision, 2026-09-25 — see `safety::ReleaseAuthority`'s
        // module note for the finding and the three acceptable authorities.
        // This is the ONE hook registration this change adds to `main.rs`:
        // the Ed25519 PUBLIC key of the operator who may release an armed
        // e-stop latch. The brain link never receives this file — only the
        // holder of the matching PRIVATE key can produce a signature
        // `safety::verify_operator_release` accepts. Absent, wrong-size or
        // all-zero ⇒ `operator_authority_init` is never called with a usable
        // key ⇒ every release attempt is refused: fail-closed by
        // construction, the same shape as the `/fat/LINK.KEY` load above,
        // and there is deliberately no `-enforced` boot-refusal feature
        // paired with it — an unprovisioned robot must still boot, it just
        // cannot have its e-stop released by anything this module checks.
        {
            const OPERATOR_KEY_BYTES: usize = 32;
            // W2-B5 (2026-09-26): the signed topology (`[operator]` in
            // CAPS.TOML) is PREFERRED when it carries a key; the loose
            // `/fat/OPERATOR.PUB` stays as the fallback until every
            // deployment declares one. Today's `default_minimal()` builder
            // never sets it, so the preference is a no-op until the signed
            // TOML loader replaces it.
            let topology_op_key = azos_topology::get()
                .map(|t| t.operator_pubkey())
                .filter(|k| *k != [0u8; OPERATOR_KEY_BYTES]);
            if let Some(key) = topology_op_key {
                if azos_actuation::estop::operator_authority_init(&key) {
                    kprintln!("[ESTOP] operator release authority provisioned from \
                               signed topology ([operator] section)");
                } else {
                    azos_drv_sys::kwarn!("[ESTOP] topology declared an [operator] key but \
                               operator_authority_init rejected it — every release refused");
                }
            } else {
                let mut op_key_buf = [0u8; OPERATOR_KEY_BYTES];
                let mut fd_table = azos_fs::ScratchFds::new();
                let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/OPERATOR.PUB",
                                                azos_fs::O_RDONLY);
                if fd >= 0 {
                    let n = azos_fs::vfs_read(&mut fd_table, fd,
                                                   op_key_buf.as_mut_ptr(),
                                                   op_key_buf.len());
                    azos_fs::vfs_close(&mut fd_table, fd);
                    if n == OPERATOR_KEY_BYTES as i32
                        && azos_actuation::estop::operator_authority_init(&op_key_buf)
                    {
                        kprintln!("[ESTOP] /fat/OPERATOR.PUB loaded — release authority provisioned");
                    } else {
                        azos_drv_sys::kwarn!("[ESTOP] /fat/OPERATOR.PUB missing/wrong-size/all-zero — \
                                   no release authority provisioned, every release refused");
                    }
                } else {
                    azos_drv_sys::kwarn!("[ESTOP] /fat/OPERATOR.PUB absent — no release authority \
                               provisioned, every release refused");
                }
            }
        }

        // Policy gate — deliberately NOT consulting any runtime flag, for the
        // same reason the secure-boot gate does not: a build that claims to
        // enforce must have no way to be talked out of it.
        //
        // K-C5: `link-encrypt-enforced` shares this gate. Under that policy
        // every brain-link frame must travel inside an AEAD session keyed
        // from /fat/LINK.KEY, so a keyless boot leaves the robot with a link
        // that is down BY POLICY forever — refusing to boot surfaces the
        // provisioning error here, on the console, instead of in the field
        // as "robot won't talk".
        #[cfg(all(feature = "domain-robot",
                  any(feature = "link-auth-enforced", feature = "link-encrypt-enforced")))]
        {
            if !link_authenticated {
                azos_drv_sys::kerr!("[SECCHAN] FATAL: brain link unauthenticated — {} — \
                           {} is compiled in, refusing to boot",
                    link_auth_reason,
                    if cfg!(feature = "link-encrypt-enforced") {
                        "link-encrypt-enforced"
                    } else {
                        "link-auth-enforced"
                    });
                loop { azos_arch::Cpu::wfi(&azos_arch::ARCH); }
            }
        }
        #[cfg(all(feature = "domain-robot",
                  not(any(feature = "link-auth-enforced", feature = "link-encrypt-enforced"))))]
        {
            if !link_authenticated {
                azos_drv_sys::kwarn!("[SECCHAN] WARNING: brain link unauthenticated — {} \
                           (link-auth-enforced not compiled in — booting anyway)",
                    link_auth_reason);
            }
        }

        // ── Apply config to all subsystems ─────────────────────────────

        // Network: set IP/mask/gateway BEFORE net_init() — see
        // `install_net_config`'s own doc for the ordering reason.
        install_net_config();

        // Scheduler Hz -- Q4.2 (owner decision, 2026-09-25): CONFIG.INI on
        // the removable FAT volume may only LOWER sched_hz below the
        // Kconfig compile-time default for this board/profile, never raise
        // it, and never below SCHED_HZ_FLOOR. The old check here
        // (`cfg_hz >= 10`) had no upper bound at all -- a CONFIG.INI value
        // above the compiled default was previously honoured outright.
        let sched_hz_default = azos_limits::SCHED_HZ as u32;
        let sched_hz_floor = azos_limits::SCHED_HZ_FLOOR as u32;
        let cfg_hz = azos_config::cfg_get_u32(b"sched_hz", sched_hz_default);
        let sched_hz_res = azos_config::resolve_sched_hz(
            cfg_hz, sched_hz_default, sched_hz_floor);
        azos_drv_sys::timebase::sched_hz_set(sched_hz_res.effective as u64);
        if sched_hz_res.clamped {
            azos_drv_sys::kwarn!("[CFG] sched_hz: CONFIG.INI requested {} Hz, clamped to {} Hz \
                       (compile-time default {} Hz, floor {} Hz)",
                sched_hz_res.requested, sched_hz_res.effective,
                sched_hz_default, sched_hz_floor);
        }
        kprintln!("[CFG] sched_hz={}", azos_drv_sys::timebase::sched_hz_get());

        // Behavior layers.
        #[cfg(feature = "domain-robot")]
        azos_behavior::layer_set_enabled(1,
            azos_config::BEHAVIOR_L1_ENABLED.load(Ordering::Relaxed));
        #[cfg(feature = "domain-robot")]
        azos_behavior::layer_set_enabled(2,
            azos_config::BEHAVIOR_L2_ENABLED.load(Ordering::Relaxed));
        #[cfg(feature = "domain-robot")]
        azos_behavior::layer_set_enabled(3,
            azos_config::BEHAVIOR_L3_ENABLED.load(Ordering::Relaxed));

        // Behavior VLA server.
        #[cfg(feature = "domain-robot")]
        let bport = azos_config::BEHAVIOR_SERVER_PORT.load(Ordering::Relaxed);
        #[cfg(feature = "domain-robot")]
        if bport > 0 {
            let bip = azos_config::behavior_server_ip_bytes();
            azos_behavior::remote_configure(bip, bport as u16);
            kprintln!("[CFG] VLA server: {}.{}.{}.{}:{}",
                bip[0], bip[1], bip[2], bip[3], bport);
        }

        // Encoder physical params.
        #[cfg(feature = "domain-robot")]
        azos_robot::set_ticks_per_m(
            azos_config::CFG_TICKS_PER_M.load(Ordering::Relaxed));
        #[cfg(feature = "domain-robot")]
        azos_robot::set_wheel_base_mm(
            azos_config::CFG_WHEEL_BASE_MM.load(Ordering::Relaxed));
        #[cfg(feature = "domain-robot")]
        kprintln!("[CFG] encoder: tpm={} wb={}mm",
            azos_robot::ticks_per_m(), azos_robot::wheel_base_mm());

        // IMU offsets are applied automatically in imu_read_scaled() via atomics.
    }
    azos_fs::inode_leak_probe();
    kprintln!();

    // ── RFC-0046 stage 1: native PCI bus-0 enumeration (QEMU `virt` only) ────
    //
    // Prints one line per PCI function found on ECAM bus 0 — vendor:device,
    // BAR(s) with kind/address/size, MSI/MSI-X capability presence — via
    // `azos_pci::format_function_line`. Enumeration reads BARs as found
    // (nothing runs a firmware PCI init step ahead of this kernel, so an
    // unassigned BAR reads address 0 with its real size). The users below —
    // the MSI-X self-test, the virtio-net-pci NIC, the MMC smoke — assign
    // the BARs they need from the 32-bit memory window.
    #[cfg(feature = "pci")]
    {
        // Bus 0 only, matching `crates/drivers/pci`'s own documented scope: every
        // QEMU `virt -device ...-pci` attachment lands on bus 0, and 32
        // devices * 8 functions * 4 KiB = 1 MiB is the whole ECAM slice bus
        // 0 needs, out of the 256 MiB window reserved for all 256 buses.
        // Mapping the full window would be 65,536 individual 4 KiB
        // page-table inserts (`map_mmio_region` maps one page at a time) for
        // 255 buses nothing on `virt` uses.
        const PCI_ECAM_BUS0_SIZE: usize = 0x10_0000;

        // ECAM base and the 32-bit memory window BARs are assigned from:
        // the DTB's `pci-host-ecam-generic` node (`reg` and `ranges`, read
        // in early boot into `EarlyBoot::pci_host`), or, with no such node,
        // QEMU `virt`'s own values (riscv64 `pci@30000000`; aarch64
        // `pcie@10000000`, whose ECAM QEMU places at 0x40_1000_0000 with
        // `highmem-ecam`, the default for a 64-bit guest).
        #[cfg(target_arch = "riscv64")]
        const PCI_ECAM_DEFAULT: usize = 0x3000_0000;
        #[cfg(target_arch = "aarch64")]
        const PCI_ECAM_DEFAULT: usize = 0x40_1000_0000;
        #[cfg(target_arch = "riscv64")]
        const PCI_MEM32_DEFAULT: (u64, u64) = (0x4000_0000, 0x4000_0000);
        #[cfg(target_arch = "aarch64")]
        const PCI_MEM32_DEFAULT: (u64, u64) = (0x1000_0000, 0x2eff_0000);
        let pci_host = early.pci_host;
        let (pci_ecam_base, ecam_src) = match pci_host {
            Some(h) if h.ecam_size >= PCI_ECAM_BUS0_SIZE as u64 => (h.ecam_base as usize, "dtb"),
            _ => (PCI_ECAM_DEFAULT, "built-in"),
        };
        // `BarWindow` hands out one address that is both programmed into the
        // BAR (a PCI bus address) and dereferenced by the kernel (a CPU
        // address), so a window is usable only where `ranges` maps the two
        // 1:1 — as both QEMU `virt` machines do. A DTB that translates gets
        // an empty window (every BAR assignment then fails), not a guess.
        let (pci_mem32, mem32_src) = match pci_host.and_then(|h| h.mem32) {
            Some(w) if w.cpu_base == w.bus_base => ((w.cpu_base, w.size), "dtb"),
            Some(w) => {
                kprintln!("[PCI] DTB mem32 window translates (bus {:#x} -> cpu {:#x}); \
                           BAR assignment needs bus == cpu, window left empty",
                    w.bus_base, w.cpu_base);
                ((0, 0), "dtb, unusable")
            }
            None => (PCI_MEM32_DEFAULT, "built-in"),
        };
        kprintln!("[PCI] host bridge: ECAM {:#x} ({}), mem32 {:#x}+{:#x} ({})",
            pci_ecam_base, ecam_src, pci_mem32.0, pci_mem32.1, mem32_src);
        let _ = azos_mm::vmm::map_mmio_region(pci_ecam_base, PCI_ECAM_BUS0_SIZE);

        struct KernelConfigSpace {
            ecam: usize,
        }
        impl azos_pci::ConfigSpace for KernelConfigSpace {
            fn read32(&self, bdf: azos_pci::Bdf, offset: u16) -> u32 {
                let addr = azos_pci::ecam_address(self.ecam, bdf, offset);
                // SAFETY: `addr` is within the 1 MiB window just identity-mapped
                // above (bus 0 only, `offset < 4096` per `ConfigSpace`'s own
                // contract) as `KERNEL_RW`, and this read is naturally aligned
                // (offset is always a multiple of 4 — see `read16`/`read8`'s
                // default impls in `azos_pci`, which round down before
                // calling `read32`).
                unsafe { core::ptr::read_volatile(addr as *const u32) }
            }
            fn write32(&mut self, bdf: azos_pci::Bdf, offset: u16, val: u32) {
                let addr = azos_pci::ecam_address(self.ecam, bdf, offset);
                // SAFETY: same as `read32` above.
                unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
            }
        }

        // Fixed-size `fmt::Write` sink — no heap dependency, matching the
        // rest of this crate's boot-time printing.
        struct LineBuf {
            buf: [u8; 160],
            len: usize,
        }
        impl core::fmt::Write for LineBuf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let space = self.buf.len().saturating_sub(self.len);
                let take = bytes.len().min(space);
                self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
                self.len += take;
                Ok(())
            }
        }

        let mut cfg = KernelConfigSpace { ecam: pci_ecam_base };
        let (funcs, pci_n) = azos_pci::enumerate_bus0::<KernelConfigSpace, 32>(&mut cfg);
        kprintln!("[PCI] bus 0 enumeration: {} function(s) found", pci_n);
        for info in funcs[..pci_n].iter().flatten() {
            let mut line = LineBuf { buf: [0; 160], len: 0 };
            if azos_pci::format_function_line(info, &mut line).is_ok() {
                if let Ok(s) = core::str::from_utf8(&line.buf[..line.len]) {
                    kprintln!("[PCI] {}", s);
                }
            }
        }

        // RFC-0046 stage 1a: on riscv64 `virt,aia=aplic-imsic`, drive one
        // virtio-net-pci TX completion over MSI-X into the boot hart's
        // IMSIC file and print the per-vector delivery counts
        // (`azos_drv_virtio::virtio::pci::msix_selftest`). The PLIC machine has
        // no MSI target, so this is skipped there. BAR window: the 32-bit
        // memory window resolved above.
        #[cfg(target_arch = "riscv64")]
        let mut window = azos_pci::BarWindow::new(pci_mem32.0, pci_mem32.1);
        #[cfg(target_arch = "riscv64")]
        if azos_drv_irqchip::irqchip::is_aia() {
            let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
            if let Some(net) = funcs[..pci_n].iter().flatten()
                .find(|f| f.vendor == 0x1af4 && f.device == 0x1041)
            {
                use azos_drv_virtio::virtio::pci::msix_selftest;
                let mut route = msix_selftest::AiaRoute::new(hart);
                match msix_selftest::tx_selftest(&mut cfg, net, &mut window, &mut route) {
                    Ok(r) => {
                        kprintln!("[PCI] msix {} enabled={} vectors={} target={:#x} tx used={}",
                            net.bdf, if r.msix_enabled { "y" } else { "n" },
                            r.table_size, r.target, r.used);
                        kprintln!("[PCI] msix {} vec0 id={} count={} vec1 id={} count={}",
                            net.bdf, r.ids[0], r.counts[0], r.ids[1], r.counts[1]);
                        if r.counts[1] == 0 {
                            azos_drv_sys::kerr!("[PCI] msix {} delivery FAILED: used={} but vec1 count=0",
                                net.bdf, r.used);
                        }
                    }
                    Err(e) => azos_drv_sys::kerr!("[PCI] msix {} selftest error: {:?}", net.bdf, e),
                }
            }
        }

        // RFC-0046 stage 1a, aarch64 twin: the same TX self-test, its MSI-X
        // vectors routed through the GICv3 ITS (`GITS_TRANSLATER` + EventID
        // = vector index, EventID N -> LPI `LPI_INTID_BASE + N`, counted by
        // `entry::aarch64::LPI_VECTOR_COUNT[N]`). DeviceID = the requester
        // ID (QEMU `virt`'s `msi-map = <0 &its 0 0x10000>`). BAR window:
        // the 32-bit memory window resolved above.
        //
        // `lpi_offset`: EventID N of this route becomes LPI
        // `LPI_INTID_BASE + lpi_offset + N`, so the self-test (offset 0) and
        // the NIC driver below (offset 4) count in different
        // `LPI_VECTOR_COUNT` slots. `prepare` issues a fresh MAPD for the
        // DeviceID each time (a new ITT slot; the ITS replaces the mapping).
        #[cfg(target_arch = "aarch64")]
        struct ItsRoute { dev: u32, lpi_offset: u32 }
        #[cfg(target_arch = "aarch64")]
        impl azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute for ItsRoute {
            fn prepare(&mut self, n: u16) -> bool {
                if !crate::boot_hooks::its_ready() {
                    return false;
                }
                let its = crate::boot_hooks::its();
                let Ok(slot) = its.map_device(self.dev) else { return false };
                let off = self.lpi_offset;
                (0..n as u32).all(|ev| its
                    .map_vector(slot, ev, azos_arch::gic::LPI_INTID_BASE + off + ev)
                    .is_ok())
            }
            fn target(&self, vec: u16) -> (u64, u32) {
                crate::boot_hooks::its().msi_target(vec as u32)
            }
            fn delivered(&self, vec: u16) -> u64 {
                crate::entry::aarch64::LPI_VECTOR_COUNT
                    .get((self.lpi_offset + vec as u32) as usize)
                    .map_or(0, |c| c.load(core::sync::atomic::Ordering::Acquire))
            }
            fn isr_token(&self, vec: u16) -> u32 {
                self.lpi_offset + vec as u32
            }
        }
        #[cfg(target_arch = "aarch64")]
        let mut window = azos_pci::BarWindow::new(pci_mem32.0, pci_mem32.1);
        #[cfg(target_arch = "aarch64")]
        if crate::boot_hooks::its_ready() {
            if let Some(net) = funcs[..pci_n].iter().flatten()
                .find(|f| f.vendor == 0x1af4 && f.device == 0x1041)
            {
                use azos_drv_virtio::virtio::pci::msix_selftest;
                let mut route = ItsRoute {
                    dev: azos_arch::its::device_id(net.bdf.bus, net.bdf.device, net.bdf.function),
                    lpi_offset: 0,
                };
                match msix_selftest::tx_selftest(&mut cfg, net, &mut window, &mut route) {
                    Ok(r) => {
                        kprintln!("[PCI] msix {} enabled={} vectors={} target={:#x} tx used={}",
                            net.bdf, if r.msix_enabled { "y" } else { "n" },
                            r.table_size, r.target, r.used);
                        kprintln!("[PCI] msix {} vec0 event={} lpis={} vec1 event={} lpis={}",
                            net.bdf, r.ids[0], r.counts[0], r.ids[1], r.counts[1]);
                        if r.counts[1] == 0 {
                            azos_drv_sys::kerr!("[PCI] msix {} delivery FAILED: used={} but vec1 lpis=0",
                                net.bdf, r.used);
                        }
                    }
                    Err(e) => azos_drv_sys::kerr!("[PCI] msix {} selftest error: {:?}", net.bdf, e),
                }
            }
        }

        // RFC-0046 stage 1: the kernel's NIC over virtio-pci when a
        // virtio-net-pci function is present (`install_net` below then keeps
        // it and does not probe MMIO). IRQ mode where a route exists (AIA
        // IMSIC / GICv3 ITS, boot hart only), polled on plain riscv64 `virt`.
        if let Some(net) = funcs[..pci_n].iter().flatten()
            .find(|f| f.vendor == 0x1af4 && f.device == 0x1041)
        {
            #[cfg(target_arch = "riscv64")]
            let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
            #[cfg(target_arch = "aarch64")]
            let mut route = ItsRoute {
                dev: azos_arch::its::device_id(net.bdf.bus, net.bdf.device, net.bdf.function),
                lpi_offset: 4,
            };
            if let Err(e) = azos_drv_virtio::virtio::net::init_pci(&mut cfg, net, &mut window, &mut route) {
                kprintln!("[NET] virtio-net-pci {} not used: {:?}", net.bdf, e);
            }
        }

        #[cfg(feature = "mmc-flush-smoke")]
        mmc_flush_smoke(&mut cfg, &funcs[..pci_n], &mut window);
    }

    // ── Network init (uses IP/mask/gw set above) ─────────────────────────────
    // Init transport drivers first, then the IP/TCP/UDP stack. See
    // `install_net`'s own doc for the conformance-probe reasoning.
    let nic_present = install_net();
    #[cfg(feature = "vf2")]
    {
        let eth_rc = azos_drv_net::eth::eth_init();
        if eth_rc == 0 {
            kprintln!("[NET] Cadence MACB Ethernet OK");
        } else {
            azos_drv_sys::kerr!("[NET] Cadence MACB Ethernet init failed ({})", eth_rc);
        }
        // Init UART1 bridge for ESP32-C3 WiFi relay
        let bridge_rc = azos_drv_bus::uart_bridge::bridge_init();
        if bridge_rc == 0 {
            kprintln!("[NET] UART1 bridge for ESP32 WiFi OK");
        }
    }
    // DEV01.5 — two-node network smoke (opt-in via `--features net-smoke`).
    //
    // Identity comes from the MAC that QEMU assigns per instance, so a single
    // kernel image serves both roles and no per-node disk image is needed:
    // last MAC octet 1 => server 10.0.0.1, 2 => client 10.0.0.2.
    //
    // Must run HERE, between the NIC probe (MAC is readable) and net_init()
    // (which caches the address into the TCP layer via `tcp::init`). Setting
    // the IP after net_init() would update NET_CFG but leave TCP answering on
    // the old address.
    #[cfg(feature = "net-smoke")]
    {
        let mac  = azos_drv_virtio::virtio::net::get_mac();
        let node = if mac[5] == 1 { 1u8 } else { 2u8 };
        let ip   = [10, 0, 0, node];
        azos_net::net_set_ip(ip, [255, 255, 255, 0], [10, 0, 0, 1]);
        kprintln!("[NETSMOKE] node={} ip=10.0.0.{} mac_octet={}", node, node, mac[5]);
    }

    azos_net::net_init();
    kprintln!();

    // Runs HERE, before the scheduler starts preempting (see the "[SCHED]
    // Starting scheduler" line further down). It used to sit next to the TFTP
    // smoke, which is *after* that point: `kernel_main` then competes with ~30
    // tasks and, on a 1-hart QEMU, is starved to brief bursts — 2000 polls need
    // 1.9ms of CPU but took over 150 wall-seconds to accumulate. The TFTP smoke
    // survives there only because a single fetch fits in one burst; this test
    // polls for seconds and never finished. main.rs already warns about this
    // hazard ("late init code may never run to completion").
    // DEV01.5 — two-node TCP smoke over a QEMU `socket` link.
    //
    // Real coverage, not a liveness ping: the client sends a deterministic
    // 256-byte pattern, the server echoes it, and the client compares every
    // byte. A single wrong or missing byte is a FAIL. This exercises ARP,
    // the IPv4 header checksum, the TCP handshake and — the reason it
    // exists — RX checksum validation in BOTH directions, which the TFTP
    // smoke (UDP only) never touches.
    //
    // Emits exactly one verdict line, `[NETSMOKE] PASS` or
    // `[NETSMOKE] FAIL <reason>`, so the harness can assert on it.
    #[cfg(feature = "net-smoke")]
    {
        const PORT:     u16   = 9100;
        const LEN:      usize = 256;
        const SERVER:   [u8; 4] = [10, 0, 0, 1];
        /// Patience budget, in POLLS — not in seconds. MUST be recomputed
        /// whenever this block moves, because the poll rate here varies by two
        /// orders of magnitude: after `sched::start()` the polling context is
        /// starved to ~20k polls/s, while here — before the scheduler preempts
        /// — it runs at ~2.4M/s. The previous 600_000 was sized for the starved
        /// regime (~30 s) and silently became ~0.25 s when the block moved, so
        /// the server gave up before a loaded machine could boot its peer.
        /// ~100M ≈ 40 s at the current placement.
        const POLLS:    u32   = 100_000_000;

        /// Deterministic, position-dependent and non-repeating within a
        /// byte: a length error, a duplicated segment or a reordered one
        /// all change the bytes, unlike a constant fill.
        fn pat(i: usize) -> u8 { (i as u8).wrapping_mul(31).wrapping_add(7) }

        /// One line per side stating what the handshake negotiated, asserted
        /// by `tools/net_pair_smoke.sh`. A 256-byte round trip passes whether
        /// or not Window Scale and SACK-Permitted were agreed, so without this
        /// line the negotiation has no QEMU coverage at all.
        fn report_opts(fd: i32) {
            match azos_net::socket_tcp_conn(fd) {
                Some(idx) => match azos_net::tcp::conn_negotiated(idx) {
                    (Some((snd, rcv)), sack) =>
                        kprintln!("[NETSMOKE] opts wscale={}/{} sack={}", snd, rcv, sack as u8),
                    (None, sack) =>
                        kprintln!("[NETSMOKE] opts wscale=none sack={}", sack as u8),
                },
                None => kprintln!("[NETSMOKE] opts no-connection"),
            }
        }

        let mac  = azos_drv_virtio::virtio::net::get_mac();
        let is_server = mac[5] == 1;

        if is_server {
            let fd = azos_net::socket_create(
                azos_net::AF_INET, azos_net::SOCK_STREAM, 0);
            let mut a = azos_net::SockAddr::new();
            a.family = azos_net::AF_INET as u16;
            a.port   = PORT;
            if fd < 0
                || azos_net::socket_bind(fd, &a) < 0
                || azos_net::socket_listen_bound(fd) < 0
            {
                kprintln!("[NETSMOKE] FAIL server-bind");
            } else {
                kprintln!("[NETSMOKE] server listening on {}", PORT);
                let mut cfd = -1;
                for _ in 0..POLLS {
                    azos_net::net_poll();
                    let r = azos_net::socket_accept(fd);
                    if r >= 0 { cfd = r; break; }
                }
                if cfd < 0 {
                    kprintln!("[NETSMOKE] FAIL no-client");
                } else {
                    report_opts(cfd);
                    // Echo until we have bounced LEN bytes back.
                    let mut buf  = [0u8; LEN];
                    let mut seen = 0usize;
                    for _ in 0..POLLS {
                        azos_net::net_poll();
                        let n = azos_net::socket_recv(cfd, &mut buf[..LEN - seen]);
                        if n > 0 {
                            let n = n as usize;
                            if azos_net::socket_send(cfd, &buf[..n]) < 0 {
                                kprintln!("[NETSMOKE] FAIL server-send");
                                break;
                            }
                            seen += n;
                            if seen >= LEN { break; }
                        }
                    }
                    kprintln!("[NETSMOKE] server echoed {} bytes", seen);
                    azos_net::socket_close(cfd);
                }
                azos_net::socket_close(fd);
            }
        } else {
            let fd = azos_net::socket_create(
                azos_net::AF_INET, azos_net::SOCK_STREAM, 0);
            let mut a = azos_net::SockAddr::new();
            a.family = azos_net::AF_INET as u16;
            a.port   = PORT;
            a.addr   = SERVER;
            // Resolve ARP first. `tcp::connect` does no address resolution:
            // on a cache miss the SYN is simply dropped and never retried,
            // so connecting cold would hang in SynSent forever. Pinging
            // until it succeeds both primes the cache and gives the peer
            // time to finish booting — and exercises ARP + ICMP on the way.
            let mut arp_ok = false;
            // Same rate caveat as POLLS: 3000 x 20k is ~25 s at this
            // placement, where the old 300 x 1k was ~0.12 s.
            for _ in 0..3_000 {
                if azos_net::net_ping(SERVER) == 0 { arp_ok = true; break; }
                for _ in 0..20_000 { azos_net::net_poll(); }
            }
            if arp_ok { kprintln!("[NETSMOKE] arp resolved, connecting"); }
            if !arp_ok {
                kprintln!("[NETSMOKE] FAIL arp");
            } else if azos_net::socket_connect(fd, &a, 40000) < 0 {
                // Only reports failure to *start* connecting (no free slot);
                // the handshake itself completes asynchronously below.
                kprintln!("[NETSMOKE] FAIL connect-start");
            } else {
                let mut tx = [0u8; LEN];
                for i in 0..LEN { tx[i] = pat(i); }
                // `socket_send` refuses until the connection is established,
                // so retrying it while polling is how we wait out the
                // three-way handshake without a state-query API.
                let mut sent = false;
                // Also a poll count, also rate-dependent — see POLLS.
                for _ in 0..20_000_000 {
                    azos_net::net_poll();
                    if azos_net::socket_send(fd, &tx) >= 0 { sent = true; break; }
                }
                if sent { kprintln!("[NETSMOKE] sent {} bytes, awaiting echo", LEN); }
                if sent { report_opts(fd); }
                if !sent {
                    kprintln!("[NETSMOKE] FAIL client-send");
                } else {
                    let mut rx  = [0u8; LEN];
                    let mut got = 0usize;
                    for _ in 0..POLLS {
                        azos_net::net_poll();
                        let n = azos_net::socket_recv(fd, &mut rx[got..]);
                        if n > 0 { got += n as usize; }
                        if got >= LEN { break; }
                    }
                    if got != LEN {
                        kprintln!("[NETSMOKE] FAIL short-echo got={} want={}", got, LEN);
                    } else {
                        let mut bad = usize::MAX;
                        for i in 0..LEN {
                            if rx[i] != pat(i) { bad = i; break; }
                        }
                        if bad == usize::MAX {
                            kprintln!("[NETSMOKE] PASS {} bytes round-tripped", LEN);
                        } else {
                            kprintln!("[NETSMOKE] FAIL mismatch at {} got={} want={}",
                                      bad, rx[bad], pat(bad));
                        }
                    }
                }
            }
            azos_net::socket_close(fd);
        }
    }

    // DEV01.6 — boot-time DHCP smoke (opt-in via `--features dhcp-smoke`).
    // Runs here, before the scheduler preempts, for the same reason as the
    // other smokes: `dhcp_start` polls, and a starved polling context turns a
    // fixed poll budget into a fraction of the time it was sized for. See
    // `run_dhcp_smoke`'s own doc for what it asserts.
    #[cfg(feature = "dhcp-smoke")]
    run_dhcp_smoke();

    // DEV01.4 placement fix: `tftp_client`'s own module doc says "Intended for
    // boot-time use (before the scheduler starts): Blocking poll loop. Not
    // safe to call after `sched::start()`" — yet this smoke used to run after
    // it, racing kernel_main against the i3-probe spinners for CPU0. When it
    // lost, the 5M-poll budget ran at starved speed and the fetch (and its
    // verdict line) simply never happened. Whether it passed depended on boot
    // timing, not on the network stack.
    // DEV01.4 — boot-time TFTP fetch smoke (opt-in via
    // `cargo build --features tftp-smoke`). Pulls `TFTP.BIN`
    // from the default gateway (QEMU user-mode net hosts a
    // built-in TFTP at 10.0.2.2 when started with
    // `-netdev user,tftp=DIR,...`). Result is purely
    // diagnostic; boot continues either way.
    #[cfg(feature = "tftp-smoke")]
    {
        // The fixture is larger than one TFTP block on purpose, and its
        // contents are a pattern rather than noise.
        //
        // For a long time this scenario fetched 256 zero bytes and the gate
        // matched on the word "fetched". Both halves of that were blind. A
        // 256-byte file is a single short block, so a full 512-byte DATA
        // block never crossed the wire — and a full block was exactly what
        // the UDP receive ring truncated (4 bytes of TFTP header push it to
        // 516, and the ring slot was 512). Truncated to 508, the block looked
        // like a final short block, so the transfer ended early and reported
        // success. Zeroed contents meant nothing could be checked, and a
        // verdict that ignores the byte count cannot tell a whole file from
        // half of one.
        //
        // So: a size that spans two full blocks plus a short final one, and a
        // position-dependent pattern the kernel recomputes rather than ships,
        // checked byte for byte before anything is called a pass.
        const TFTP_SMOKE_BUF_BYTES: usize = 2048;
        const TFTP_SMOKE_SERVER_IP: [u8; 4] = [10, 0, 2, 2];
        const TFTP_SMOKE_FILENAME: &str = "TFTP.BIN";
        static mut TFTP_SMOKE_BUF: [u8; TFTP_SMOKE_BUF_BYTES] =
            [0u8; TFTP_SMOKE_BUF_BYTES];
        let buf = unsafe { &mut *(&raw mut TFTP_SMOKE_BUF) };
        // The kernel is where `crates/net/tftp` and `crates/net/net` meet. Keeping the
        // seam here rather than inside either crate is what lets `tftp` stay
        // dependency-free -- a scaffolding crate must not be a reason for a
        // core crate to grow an edge.
        struct KernelUdp;
        impl azos_tftp::client::UdpTransport for KernelUdp {
            fn bind(&self, port: u16) -> i32 { azos_net::udp::bind(port) }
            fn unbind(&self, sock: usize) { azos_net::udp::unbind(sock) }
            fn sendto(&self, sock: i32, dst_ip: &[u8; 4], dst_port: u16, data: &[u8]) -> i32 {
                azos_net::udp::sendto(sock, dst_ip, dst_port, data)
            }
            fn recvfrom(&self, sock: i32, buf: &mut [u8],
                        src_ip: &mut [u8; 4], src_port: &mut u16) -> i32 {
                azos_net::udp::recvfrom(sock, buf, src_ip, src_port)
            }
            fn poll(&self) { azos_net::net_poll(); }
        }
        match azos_tftp::client::tftp_fetch(
            &KernelUdp,
            TFTP_SMOKE_SERVER_IP,
            TFTP_SMOKE_FILENAME,
            buf,
        ) {
            Ok(n) => {
                kprintln!(
                    "[TFTP] fetched {} bytes from {}.{}.{}.{}",
                    n,
                    TFTP_SMOKE_SERVER_IP[0], TFTP_SMOKE_SERVER_IP[1],
                    TFTP_SMOKE_SERVER_IP[2], TFTP_SMOKE_SERVER_IP[3],
                );
                // 251 is the largest prime under 256: the pattern's period is
                // coprime with both the 512-byte block size and any power of
                // two, so a block delivered at the wrong offset, repeated, or
                // dropped cannot line up by accident.
                let mut bad = usize::MAX;
                for i in 0..n {
                    if buf[i] != (i % 251) as u8 {
                        bad = i;
                        break;
                    }
                }
                if bad == usize::MAX {
                    kprintln!("[TFTP] VERIFIED {} bytes, content exact", n);
                } else {
                    azos_drv_sys::kerr!(
                        "[TFTP] CORRUPT at byte {}: expected {} got {}",
                        bad, (bad % 251) as u8, buf[bad],
                    );
                }
            }
            Err(e) => azos_drv_sys::kerr!("[TFTP] fetch failed: {:?}", e),
        }
    }


    // ── OTA auto-recv (early spawn) ──────────────────────────────────────────
    // Spawn the OTA TCP listener task BEFORE any RT-priority tasks. Once
    // rt-motor / flight-ctrl / sensor-ahrs are created and the timer ISR
    // starts preempting kernel_main on the boot CPU, late init code may
    // never run to completion. Spawning early guarantees the listener is
    // registered while the boot CPU is still single-tasking.
    {
        let port = azos_config::CFG_OTA_AUTO_RECV_PORT.load(
            core::sync::atomic::Ordering::Relaxed);
        if port != 0 && port <= 65535 {
            // Pinned to CPU 2 — CPUs 0/1 host RT tasks, CPU 2 is quiet.
            azos_sched::task_create_affinity(
                "ota-recv",
                azos_shell::ota_recv_task_entry,
                port as usize,
                azos_sched::NET_POLL_PRIORITY,
                2,
            );
            kprintln!("[OTA] Auto-recv task created on port {} (early)", port);
        }
    }

    // (Phase 8: IPC + Signals + Services — `install_ipc_plumbing()` now
    // called much earlier, right after `install_procfs()`; see that call
    // site's comment, ordering-decision #7.)
    kprintln!();

    // Opt-in f32 cost measurement (feature `mlsf-bench`, never in a default
    // build): same quiescent point as the boot bench below, then halt.
    #[cfg(all(feature = "mlsf-bench", not(feature = "no-ml")))]
    {
        mlsf_bench::run();
        // `black_box`: a plain `loop` makes the rest of kernel_main
        // unreachable code and every later binding an unused-variable warning.
        while core::hint::black_box(true) {
            unsafe { core::arch::asm!("wfi"); }
        }
    }

    // ── Early-boot synthetic bench capture (CFG_BENCH_BOOT) ───────────────
    // Quiescent context: hart 0 is the only running hart (secondaries wake at
    // scheduler::start), the timer ISR is still OFF (deferred until just
    // before scheduler::start), and all benched subsystems (ipc, fs/tmpfs,
    // net/arp, crypto, auth) are initialised by this point. That removes the
    // cross-hart rdcycle contention + timer preemption that make the SMP
    // behavior-task path noisy. Run once, emit, then halt — no need to reach
    // the (slow / -smp-1-hanging) full task system. Pair with QEMU -icount
    // for cross-run determinism. See crates/core/config CFG_BENCH_BOOT.
    #[cfg(all(feature = "qemu", feature = "domain-robot"))]
    if azos_config::CFG_BENCH_BOOT.load(Ordering::Relaxed) {
        const BENCH_BOOT_ITERS: u64 = 100;
        azos_bench::run_all_quiescent(BENCH_BOOT_ITERS);
        kprintln!("[BENCH-RES] ── boot-bench complete, halting ──");
        loop {
            azos_arch::Cpu::wfi(&azos_arch::ARCH);
        }
    }

    // ---- ML ----
    // The MLP and its weights file (`/fat/MLP.RML`) belong to the ring-3 ML
    // service (`userspace/services/mlsrv`); the kernel carries no MLP of its own.
    #[cfg(feature = "no-ml")]
    kprintln!("[ML] Compile-time disabled (--features no-ml)");
    kprintln!();

    // ---- Phase C: ggml-nano / GGUF inference ----
    // Moved to the ring-3 ML service with the behavior loop's MLP: `mlsrv`
    // reads /fat/POLICY.GGF and runs the three classifications when it
    // starts, printing the same `[GGUF] n/3 tests passed` verdict.

    // ---- Phase D: PMP Security + Hardware Watchdog ----

    kprintln!("========================================");
    kprintln!(" Phase D: PMP Security + HW Watchdog");
    kprintln!("========================================");

    // F11.3: Check crash counter — detect boot loops.
    // The counter holds the consecutive unconfirmed boots read from
    // BOOTMETA's `boot_count` (`boot_count_loaded`). It is NOT cleared here:
    // a boot counts as clean only once `ota_mark_boot_good` runs (sys-wdt,
    // after `OTA_BOOT_GOOD_DELAY_S` of uptime), which clears both copies.
    {
        let prev_crashes = azos_drv_sys::wdt::crash_counter_get();
        if prev_crashes >= 3 {
            azos_drv_sys::kwarn!("[WDT] WARNING: {} consecutive crashes detected (boot loop?)", prev_crashes);
            azos_drv_sys::kwarn!("[WDT] The [OTA] and [RECOVERY] lines above say what this boot does about it \
                       (rollback, or safe mode: {}).",
                      azos_actuation::estop::safe_mode_active());
        } else if prev_crashes > 0 {
            kprintln!("[WDT] Recovering from {} previous crash(es)", prev_crashes);
        }
        kprintln!("[WDT] Crash counter clears when OTA marks this boot good ({} s)",
            azos_ota::OTA_BOOT_GOOD_DELAY_S);
    }

    // PMP: display the intended AzOS memory-protection policy.
    // pmp_configure() must be called from M-mode (before mret into S-mode).
    // Here we display it for boot-time audit; actual enforcement is M-mode only.
    // riscv64-only: PMP (Physical Memory Protection) is a RISC-V privileged-
    // spec mechanism with no aarch64 equivalent — `azos_arch::pmp` does
    // not exist as a module on that ISA (observed: E0432 "no `pmp` in the
    // root" on an aarch64 build before this gate was added, kernel-main-
    // merge task). Reads `heap_start`/`kernel_end_aligned` off `EarlyBoot`
    // — see that struct's own doc for why those two fields exist.
    #[cfg(target_arch = "riscv64")]
    {
        use azos_arch::pmp;
        let fw_end = azos_drv_base::platform::hw::KERNEL_LOAD; // end of OpenSBI
        let regions = pmp::pmp_regions(fw_end, kernel_end_aligned, heap_start, HEAP_SIZE);
        kprintln!("[PMP] Memory-protection policy ({} TOR regions):", pmp::N_PMP_REGIONS);
        kprintln!("[PMP]   Note: CSRs are M-mode only; configure from boot stub.");
        for r in &regions {
            kprintln!("[PMP]   {:20}  base={:#010x}  size={:#010x}  {}{}{}",
                r.name,
                r.base, r.size,
                if r.perm.r { "R" } else { "-" },
                if r.perm.w { "W" } else { "-" },
                if r.perm.x { "X" } else { "-" });
        }
    }
    kprintln!();

    // ---- Phase 16: Security — stack canaries + system watchdog ----

    kprintln!("========================================");
    kprintln!(" Phase 16: Security");
    kprintln!("========================================");
    kprintln!("[SEC] Stack canary: {}, fingerprint {:06x} — {}",
        if azos_sched::scheduler::stack_canary() == azos_sched::STACK_CANARY {
            "fixed (pool unseeded)"
        } else {
            "from the entropy pool"
        },
        azos_sched::scheduler::stack_canary_fingerprint(),
        if azos_sched::scheduler::stack_guard_pages_active() {
            "not written: stack guard pages active"
        } else {
            "written at each task_create"
        });
    kprintln!("[SEC] System watchdog: monitors canaries + timer liveness every ~1 s");
    kprintln!();

    // ---- Phase 17: Robot Physical Integration ----

    #[cfg(feature = "domain-robot")]
    kprintln!("========================================");
    #[cfg(feature = "domain-robot")]
    kprintln!(" Phase 17: Robot Physical Integration");
    #[cfg(feature = "domain-robot")]
    kprintln!("========================================");
    #[cfg(feature = "domain-robot")]
    kprintln!("[ROBOT] Encoder sim: ticks in rt_motor_task → speed × iteration");
    #[cfg(feature = "domain-robot")]
    kprintln!("[ROBOT] Odometry:    dead reckoning (dist_mm, heading_cdeg)");
    #[cfg(feature = "domain-robot")]
    kprintln!("[ROBOT] Trajectory:  ring buffer ({} pts) + FAT32 CSV flush",
        azos_robot::TRAJ_CAP);
    #[cfg(feature = "domain-robot")]
    kprintln!("[ROBOT] OTA:         A/B firmware slots (shell: ota recv/status/verify)");
    #[cfg(feature = "domain-robot")]
    kprintln!();

    // Shared with aarch64's kernel_main — see `install_robot_hw`'s own doc
    // for why `robot_init()` (inside the next helper) stays a separate call
    // rather than living inside `install_robot_hw` itself (this ISA's own
    // `payload_init` interleave).
    install_robot_hw();
    // Payload + drivers + full sensor suite — see
    // `install_robot_payload_and_sensors`'s own doc for the merge-task
    // finding (this was riscv64-only; now shared) and the ordering
    // constraint (must follow network bring-up).
    install_robot_payload_and_sensors();
    // Wave 11 (SHMRING): the sensor streams' regions and producers, and the
    // `stream.<name>` minter — before any ring-3 task is seeded. Nothing
    // with every stream off (Kconfig STREAM_*_RING, LIDAR_SIM).
    streams_init();

    // ---- Phase G1: Subsumption Behavior Engine + VLA Protocol ----

    #[cfg(feature = "domain-robot")]
    kprintln!("========================================");
    #[cfg(feature = "domain-robot")]
    kprintln!(" [BEHAVIOR] Phase G1: Subsumption Engine");
    #[cfg(feature = "domain-robot")]
    kprintln!("   L0: emergency-stop  (IMU)");
    #[cfg(all(feature = "domain-robot", not(feature = "no-ml")))]
    kprintln!("   L1: avoid-obstacle  (MLP)");
    #[cfg(feature = "domain-robot")]
    kprintln!("   L2: remote-vla      (TCP)");
    #[cfg(feature = "domain-robot")]
    kprintln!("   L3: explore         (wander)");
    #[cfg(feature = "domain-robot")]
    kprintln!("========================================");
    #[cfg(feature = "domain-robot")]
    kprintln!();

    // ---- Phase 5: SMP + Scheduler ----

    kprintln!("========================================");
    kprintln!(" Phase 5: SMP Scheduler ({} CPUs)", num_cpus);
    kprintln!("========================================");
    kprintln!();

    // AZOS Phase 1 W3 — install the static topology before the
    // scheduler so that future task spawns can pull their cap_table +
    // class assignment from RFC-0005 declarations. Shared with aarch64's
    // kernel_main — see `install_topology`'s own doc.
    install_topology(num_cpus);
    // The kernel command line: `init=` (secure boot off) names this boot's
    // console program. Read before anything ring 3 starts.
    crate::console_mode::read_cmdline(dtb_ptr);
    // RFC-0051 E2: the energy model, from the topology just installed, else
    // the DTB, else none.
    #[cfg(feature = "energy")]
    install_energy(num_cpus, dtb_ptr);

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

    #[cfg(target_arch = "aarch64")]
    {
        // Hart→MPIDR affinity table, from the DTB `/cpus` nodes — built BEFORE
        // any secondary starts (`crates/core/sched::smp::wake_hart` reads it), and
        // independent of `dtb_num_cpus` above (a `dtb_cpu_regs` failure here
        // just leaves every non-zero hart unpublished, which `wake_hart`
        // reports and skips — see its own doc comment).
        {
            let mut regs = [0u64; MAX_HARTS];
            let n = if dtb_ptr != 0 {
                unsafe {
                    azos_dtb::dtb_cpu_regs(
                        azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8, &mut regs)
                }
            } else {
                None
            };
            match n {
                Some(found) => {
                    let published = found.min(MAX_HARTS);
                    for (hart, &reg) in regs[..published].iter().enumerate() {
                        let affinity = azos_arch::mpidr::mpidr_affinity_key(reg);
                        azos_sched::smp::set_hart_affinity(hart, affinity);
                    }
                    kprintln!("[SMP] hart->MPIDR table: {} of {} cpu@ nodes published \
                               (document order == hart id; see set_hart_affinity's doc)",
                        published, found);
                    // Self-check: hart 0 IS this PE, so its own live MPIDR must
                    // match whatever the DTB's first cpu@ node claimed — a
                    // mismatch means "DTB order == Aff0 order" (this table's
                    // whole assumption) does not hold on this board, and every
                    // hart id this boot assigns from here on is suspect.
                    if published > 0 {
                        let live = azos_arch::mpidr::read_mpidr().affinity_key();
                        if live != azos_arch::mpidr::mpidr_affinity_key(regs[0]) {
                            azos_drv_sys::kerr!("[SMP] FAILED: DTB cpu@0's affinity {:#x} != this PE's \
                                       own live MPIDR affinity {:#x} — hart-id assignment \
                                       (DTB document order) does not match this board's \
                                       topology", azos_arch::mpidr::mpidr_affinity_key(regs[0]), live);
                        }
                    }
                }
                None => {
                    azos_drv_sys::kerr!("[SMP] hart->MPIDR table: dtb_cpu_regs failed — no secondary \
                               will be able to start (wake_hart has no affinity to target)");
                }
            }
        }
    }

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
        azos_sched::task_create_affinity(
            "phase3-a", phase3_task_a, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
        azos_sched::task_create_affinity(
            "phase3-b", phase3_task_b, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
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
        // while the pimutex and cap markers next to it read back correctly
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
        azos_sched::task_create(
            "smp-migrate-probe", aarch64_migrate_probe_task, 0, azos_sched::DEFAULT_PRIORITY);
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
        create_sys_wdt_task(2.min(num_cpus.saturating_sub(1)) as i8);
    }

    // Shell task: priority 13 (high normal — above workers, runs in RT task sleep gaps).
    // No CPU pin so it works on both 1-CPU and 4-CPU QEMU.
    //
    // RFC-0055: it is the RECOVERY console. It parks until no user shell has
    // the console (`console_mode::wait_for_recovery`), and under
    // `CONSOLE_LOCKDOWN` it is not created at all.
    if azos_limits::CONSOLE_LOCKDOWN {
        kprintln!("[CONSOLE] lockdown: no kernel console task");
    } else {
        azos_sched::task_create("shell", shell_task, 0, 13);
        kprintln!("[SCHED] Created shell task");
    }

    // I3 experiment (RFC-0031): one-shot lease priority-inversion probe.
    //
    // Hart pin: 0 on a 1-hart boot (so it still runs at all — nothing else
    // is on hart 0 then), hart 3 whenever more than one hart is online.
    // Both branches must exist: hart 0 on SMP carries rt-motor/flight-ctrl
    // (prio 8) and the probe's own spinners run at prio 4 — inside the
    // hard-RT band (`RT_PRIORITY_THRESHOLD` = 12), where the timer tick
    // never preempts — so on hart 0 they would starve motor control for the
    // whole burst. `num_cpus` is the DTB-derived runtime count read above
    // (same value already used to size the idle-per-hart loop), not a
    // compile-time guess, so this tracks whatever QEMU was actually told
    // with `-smp`.
    //
    // Unhandled edge: `num_cpus` of exactly 2 or 3 pins this to a hart that
    // never comes online (`wake_harts` may start fewer than requested), and
    // unlike `net-poll` this probe's outer task is rescued by K-C24 but the
    // lessee/spinners/lessor it spawns *after* the rescue would not be — the
    // probe would block on `wq_block_current()` forever with no `[I3]` line.
    // No gate scenario boots this kernel at `-smp 2/3` today (only 1 and 4),
    // so this is a latent gap, not a live one.
    #[cfg(all(feature = "i3-smoke", not(feature = "ktest")))]
    {
        let i3_hart: i8 = if num_cpus > 1 { 3 } else { 0 };
        azos_sched::task_create_affinity("i3-probe", i3_probe::runner,
                                             i3_hart as usize,
                                             i3_probe::PROBE_PRIO, i3_hart);
        kprintln!("[SCHED] Created i3-probe task (RFC-0031 lease inversion) [hart {}]", i3_hart);
    }

    // Wave 9: lease priority inheritance reached from ring 3
    // (`SYS_IPC_LEASE_WAIT`). The ring-3 lessor is IPCTEST; see
    // `lease_pi3_smoke`.
    #[cfg(feature = "lease-pi3-smoke")]
    {
        if num_cpus >= 3 {
            lease_pi3_smoke::spawn();
        } else {
            kprintln!("[LEASEPI3] SKIP: needs -smp >= 3, have {}", num_cpus);
        }
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

    // K-A14 probe: PiMutex donation with holder and waiter on one hart.
    #[cfg(all(feature = "pi-smoke", not(feature = "ktest")))]
    {
        azos_sched::task_create_affinity("pi-probe", pi_probe::runner, 0,
                                             pi_probe::PROBE_PRIO, 0);
        kprintln!("[SCHED] Created pi-probe task (K-A14 PiMutex donation)");
    }

    #[cfg(feature = "pi-flush-smoke")]
    pi_flush_probe::spawn();

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
    // RFC-0051 E0-E2: the energy model and the utilisation signals.
    #[cfg(feature = "energy-smoke")]
    smokes::energy_smoke::spawn();

    // Create IPC/signal/service demo task (Phase 8).
    azos_sched::task_create("ipc-demo", ipc_demo_task, 0, azos_sched::DEFAULT_PRIORITY);
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
    // `VLEN_BYTES`'s doc comment in rvv.rs) — this print is what keeps that
    // silent fallback from being silent in practice.
    // Kconfig `RV_V` = probe on a hart without V: `vlenb` would trap, so
    // the vector state stays uninitialised and the scalar kernels run.
    #[cfg(all(target_arch = "riscv64", feature = "rvv"))]
    if azos_arch::rvv::usable() {
        match azos_arch::rvv::init_vector_state() {
            Ok(vlenb) => kprintln!("[RVV] vlenb={} — vector state save/restore enabled", vlenb),
            Err(vlenb) => kprintln!(
                "[RVV] vlenb={} exceeds MAX_VLEN_BYTES={} — vector state save disabled, V not enabled for tasks",
                vlenb, azos_arch::rvv::MAX_VLEN_BYTES),
        }
    } else {
        kprintln!("[RVV] no V on this hart — scalar kernels, no vector state");
    }

    // Create RVV benchmark task (Phase 11, QEMU only).
    #[cfg(all(target_arch = "riscv64", feature = "rvv"))]
    if azos_arch::rvv::usable() {
        azos_sched::task_create("rvv-bench", rvv_bench_task, 0, azos_sched::DEFAULT_PRIORITY);
        kprintln!("[SCHED] Created rvv-bench task");
    }

    // RVV isolation probe: canary for the rvv_ctx_save/restore TID-vs-
    // offset-120 bug (crates/core/arch-riscv64/src/rvv.rs). Two tasks, pinned to
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
    // Pinned to hart 2: hart 0 is owned by rt-motor + flight-ctrl (prio 8),
    // hart 1 by imu + sensor-ahrs (prio 8/14). Without affinity the
    // scheduler was leaving `behavior` competing for hart 3 against
    // every other prio-14+ task, and the brain TCP dial never fired
    // inside the E2E window. Hart 2 is otherwise idle so we get
    // immediate scheduling.
    #[cfg(feature = "domain-robot")]
    azos_sched::task_create_affinity(
        "behavior", behavior_task, 0,
        azos_sched::BEHAVIOR_PRIORITY, 2);
    #[cfg(feature = "domain-robot")]
    kprintln!("[SCHED] Created behavior task (subsumption L0-L3) [hart 2]");
    // C1: camera frames on a brain connection of their own, only when
    // CONFIG.INI sets `behavior_camera_port` (applied at boot, above). Below
    // behavior on the same hart, so a camera send, capture or handshake never
    // delays the behavior loop.
    #[cfg(feature = "domain-robot")]
    if azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed) != 0 {
        azos_sched::task_create_affinity(
            "camera-tx", camera_tx_task, 0,
            azos_sched::BEHAVIOR_PRIORITY + 1, 2);
        kprintln!("[SCHED] Created camera-tx task (camera connection) [hart 2]");
    }
    // Hart 0: dedicated real-time control — PID loop pinned to avoid jitter.
    // The safety loops are exempt from the RT band budget (owner decision,
    // wave 11 SCHED-RT): never throttled when the band runs out.
    #[cfg(feature = "domain-robot")]
    let rt_motor = azos_sched::task_create_affinity("rt-motor", rt_motor_task, 0,
        azos_sched::RT_MOTOR_PRIORITY, 0);
    #[cfg(feature = "domain-robot")]
    azos_sched::rt::exempt_from_band_cap(rt_motor);
    // RT7: a panic in a safety task is never contained (panic policy).
    #[cfg(feature = "domain-robot")]
    panic::register_safety_task(rt_motor, "rt-motor");
    #[cfg(feature = "domain-robot")]
    kprintln!("[SCHED] Created rt-motor task (MotorCmd→PID→PWM + watchdog) [hart 0]");

    // Dedicated sensor tasks (AQ0: IO-wait, priority-separated)
    #[cfg(feature = "domain-robot")]
    let imu = azos_sched::task_create_affinity("imu", imu_task, 0,
        azos_sched::RT_MOTOR_PRIORITY, 1); // RT priority, hart 1
    #[cfg(feature = "domain-robot")]
    azos_sched::rt::exempt_from_band_cap(imu);
    #[cfg(feature = "domain-robot")]
    azos_sched::task_create("odom", odom_task, 0, azos_sched::BEHAVIOR_PRIORITY);
    #[cfg(feature = "domain-robot")]
    azos_sched::task_create("sensor-slow", sensor_slow_task, 0, azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "domain-robot")]
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
    // Hart pin diverges by ISA (kernel-main-merge task finding — the gate's
    // own `aarch64 network: NIC found + MAC` row caught this: net-poll never
    // got created on the hart that row expects, because a first merge pass
    // kept only riscv64's literal `3`). riscv64's board always enumerates 4
    // harts in every gate scenario, so a literal pin is safe there — see the
    // history above. aarch64's own `-smp` varies across gate rows (2 today,
    // one row at 4), so it pins to the LAST ONLINE hart instead
    // (`num_cpus - 1`) — this was aarch64's own pre-merge behaviour,
    // preserved exactly, not new.
    #[cfg(target_arch = "riscv64")]
    let net_poll_hart: i8 = 3;
    #[cfg(target_arch = "aarch64")]
    let net_poll_hart: i8 = num_cpus.saturating_sub(1) as i8;
    // Any other ISA (the x86_64 skeleton): aarch64's policy, the last CPU.
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    let net_poll_hart: i8 = num_cpus.saturating_sub(1) as i8;
    azos_sched::task_create_affinity("net-poll", net_poll_task, 0,
        azos_sched::NET_POLL_PRIORITY, net_poll_hart);
    // Prints the BOUND, not an invented rate: this task's cadence is whatever
    // the scheduler tick grants it (see `NET_POLL_INTERVAL`). The old line
    // asserted a flat "100Hz" while the code asked for 1 kHz.
    kprintln!("[SCHED] Created net-poll task (IO-wait, <= sched_hz={} Hz) [hart {}]",
              azos_drv_sys::timebase::sched_hz_get(), net_poll_hart);

    // Phase I1: sensor + AHRS fusion task (~100 Hz).
    // Hart 1: sensor fusion — dedicated to avoid contention with motor PID on hart 0.
    #[cfg(feature = "domain-robot")]
    azos_sched::task_create_affinity("sensor-ahrs", sensor_ahrs_task, 0,
        azos_sched::SENSOR_AHRS_PRIORITY, 1);
    #[cfg(feature = "domain-robot")]
    kprintln!("[SCHED] Created sensor-ahrs task (IMU+baro+GPS→AHRS→channels) [hart 1]");

    // Phase J+K: flight controller task (mixer + PID + failsafe).
    // Hart 0: flight controller — same hart as rt-motor for cache locality.
    #[cfg(feature = "domain-robot")]
    let flight_ctrl = azos_sched::task_create_affinity("flight-ctrl", flight_control_task, 0,
        azos_sched::FLIGHT_CTRL_PRIORITY, 0);
    #[cfg(feature = "domain-robot")]
    azos_sched::rt::exempt_from_band_cap(flight_ctrl);
    #[cfg(feature = "domain-robot")]
    panic::register_safety_task(flight_ctrl, "flight-ctrl");
    #[cfg(feature = "domain-robot")]
    kprintln!("[SCHED] Created flight-ctrl task (PID→mixer→ESC + failsafe) [hart 0]");

    // Phase L: telemetry task (attitude + GPS → UDP).
    #[cfg(feature = "domain-robot")]
    azos_sched::task_create("telemetry", telemetry_task, 0, azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "domain-robot")]
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
    #[cfg(target_arch = "riscv64")]
    create_sys_wdt_task(2);

    // Create stress-test workers. find_least_loaded_cpu() distributes them
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
    let skip_for_ota = azos_config::CFG_OTA_AUTO_RECV_PORT
        .load(Ordering::Relaxed) != 0;
    let skip_for_brain = azos_config::BEHAVIOR_SERVER_PORT
        .load(Ordering::Relaxed) != 0;
    if skip_for_ota || skip_for_brain {
        let reason = if skip_for_ota { "ota_auto_recv_port" } else { "behavior_server_port" };
        kprintln!("[SCHED] Skipping {} stress-test workers ({} set)", NUM_WORKERS, reason);
    } else {
        // Optional load, so sized to what the pool can spare: the rest of
        // boot (kernel tasks, topology rows, the user shell) creates its
        // tasks with the infallible `task_create`, and a small profile
        // (embedded: MAX_TASKS = 32) panicked "task pool full" once wave 11
        // added the lease worker and the recovery console (gate 199).
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

    // ── AT: Pub/sub initialization ───────────────────────────────────────────
    // Wire the wake callback so topic subscribers are woken when data arrives.
    azos_pubsub::set_wake_callback(|task_idx| {
        azos_sched::wake_by_channel(task_idx as u32);
    });

    // Create default topics for inter-task communication.
    /// Message size for IMU topic (accel[3] + gyro[3] = 24 bytes, padded to 64).
    const TOPIC_IMU_MSG_SIZE: u16 = 64;
    /// Message size for battery topic (voltage, current, etc).
    const TOPIC_BATTERY_MSG_SIZE: u16 = 16;
    /// Message size for motor command topic.
    const TOPIC_MOTOR_CMD_MSG_SIZE: u16 = 16;
    /// Message size for status topic.
    const TOPIC_STATUS_MSG_SIZE: u16 = 32;

    azos_pubsub::topic_create(b"/sensors/imu", TOPIC_IMU_MSG_SIZE);
    azos_pubsub::topic_create(b"/sensors/battery", TOPIC_BATTERY_MSG_SIZE);
    azos_pubsub::topic_create(b"/cmd/motor", TOPIC_MOTOR_CMD_MSG_SIZE);
    azos_pubsub::topic_create(b"/status", TOPIC_STATUS_MSG_SIZE);
    kprintln!("[PUBSUB] Initialized 4 default topics");

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
                                        AUTORUN_PRIORITY, AUTORUN_HART);
            kprintln!("[SCHED] Created autorun task: {}",
                core::str::from_utf8(&path[..len]).unwrap_or("?"));
        }
    }

    // Wave 11 (LEASE3): the lease worker, which revokes an expired lease's
    // mapping (and gives a sealed lessor its write back) without the
    // lessor's help. Both ISAs' timer interrupts wake it after `lease_tick`.
    tasks::start_lease_worker();

    // RFC-0049 M4, wave 11: the supervisor that restarts what this boot starts
    // in ring 3 — the autorun image once it registers as a driver, and from
    // their start the topology's `start = true` images and the ML service
    // (`drv_supervisor::spawn_supervised`). Created only on a boot that can
    // start one of them, and here, from a kernel context, on purpose: a task
    // inherits its creator's page table root, and the successors it creates
    // must not inherit a dying ring-3 task's.
    let start_rows = azos_topology::get().is_some_and(|t| t.tasks().iter().any(|r| r.start));
    {
        let autorun = azos_config::cfg_get(b"autorun").is_some_and(|p| !p.is_empty());
        let ml = cfg!(not(feature = "no-ml")) && ML_ENABLED.load(Ordering::Acquire);
        if autorun || start_rows || ml {
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
    // Wave 12 (DRVPLACE): the buzzer placed in the kernel (Kconfig
    // DRV_BUZZER_PLACEMENT = kernel); its ring-3 host has no topology row
    // then (`builder::BUZZDRV_ROW`).
    #[cfg(feature = "buzzer-kernel")]
    {
        // Supervised (wave 13): a contained panic in the host restarts it.
        let _ = drv_supervisor::start_kernel_host("buzzer", buzzer_host_task,
                                                  azos_sched::DEFAULT_PRIORITY);
        kprintln!("[BUZZER] placement: kernel (host task created)");
    }

    // Wave 9 (DRV1): the images whose topology row says `start = true`. A
    // task of its own, like autorun: spawning reads each ELF off the volume.
    if start_rows {
        azos_sched::task_create("drv-launch", ring3_driver_launch_task, 0,
                                    azos_sched::DEFAULT_PRIORITY);
    }

    // E11.AQ3 validation smoke: if a userspace gpio_drv was autorun'd, exercise
    // the ring-3 driver round-trip from a kernel task, on a hart other than the
    // autorun hart (3): the cross-hart case. The same-hart case — a client more
    // urgent than the driver, on the driver's hart — is `proxy-pi-smoke`,
    // started by this task once the driver has answered. QEMU-only: a
    // validation aid, not production.
    //
    // **Priority 16, not 13.** It was 13, which on hart 1 is ABOVE
    // `sensor-ahrs` at 14, while the proxy still waited for the reply with a
    // million-iteration `spin_loop()`: for the whole span of a wait
    // `sensor-ahrs` got no CPU, and `flight-ctrl` on hart 0 ages the attitude
    // it publishes for its failsafe. The proxy now blocks for the reply
    // (wave 8), so the wait no longer costs hart 1 anything; the priority
    // stays below the sensor loop because nothing needs it higher.
    #[cfg(feature = "qemu")]
    {
        const GPIO_SMOKE_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
        const GPIO_SMOKE_HART: i8 = 1;
        azos_sched::task_create_affinity(
            "gpio-aq3-smoke", gpio_user_driver_smoke_task, 0,
            GPIO_SMOKE_PRIORITY, GPIO_SMOKE_HART,
        );
        // sup-smoke: kill the ring-3 GPIO driver four times, after the AQ3
        // smoke is done with it (RFC-0049 M4 gate row).
        #[cfg(feature = "sup-smoke")]
        drv_supervisor::start_smoke();
    }
    #[cfg(feature = "orderly-reboot-smoke")]
    azos_sched::task_create_affinity("orderly-smoke", orderly_reboot_smoke_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "safe-mode-smoke")]
    azos_sched::task_create_affinity("safe-mode-probe", safe_mode_probe_task, 0,
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

    // envelope-smoke: drive the RFC-0033 chokepoint with a command above the
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
    // flight recorder (RFC-0048 P3). Default priority, as the probes above.
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
    // shell's `cmd_fork` exercises the identical path with the same zeroed
    // `sepc`/`user_sp`/regs; this is that call without needing typed input in
    // QEMU's console, which is where an earlier attempt at this proof stalled.
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
        #[cfg(target_arch = "aarch64")]
        let ts_hz = azos_arch::cpu::timer_freq_hw();
        #[cfg(not(target_arch = "aarch64"))]
        let ts_hz = azos_drv_sys::timebase::TIMER_FREQ;
        // SAFETY: linker-script symbols; only their addresses are taken.
        let text = unsafe { (&_text_start as *const u8 as usize, &_text_end as *const u8 as usize) };
        azos_ipc::trace::init(num_cpus, ts_hz, text);
        azos_trace::cpu_online();
        #[cfg(feature = "trace-cost-probe")]
        crate::smokes::trace_cost_probe(ts_hz);
        #[cfg(feature = "lat-trace")]
        azos_arch::lat_hook::lat::set_new_max_hook(crate::lat_trace::trace_new_max);
    }

    // Gate only: from here on every `current_cpu_id()` is checked against
    // the hardware id (`smokes/cpuid_probe.rs`).
    #[cfg(feature = "cpuid-probe")]
    crate::smokes::cpuid_probe::arm(num_cpus);

    // Kconfig KTEST: every registered test, then power off. Boot init is
    // done; no secondary hart is awake and no task has run.
    #[cfg(feature = "ktest")]
    ktest::run();

    ARCH_ENTRY.wake_secondaries(num_cpus);

    // The boot hart's timer interrupt stays off until the end of kernel_main
    // (see there); the other harts are already running tasks.

    // AZOS Phase 1 W4-int.2 — boot-time smoke test for the APS
    // dispatch path. Picks a task via the policy runqueues to confirm
    // the co-enqueue path actually populated them.
    //
    // The whole APS block is behind the `sched-aps` feature: without it the
    // policies, the per-CPU runqueues and the typed registry are not
    // compiled into `azos_sched` at all (config/Kconfig.timing's backend
    // choice emits the feature; `lto = false` means nothing else would
    // strip them). A Legacy kernel has no smoke test to run and no flag to
    // flip — it only says which backend it is.
    #[cfg(feature = "sched-aps")]
    {
        match azos_sched::aps_state::smoke_test(hart_id as usize) {
            Ok(tid) => kprintln!("[APS]  smoke OK — pick_next on CPU {} → tid {}", hart_id, tid),
            Err(reason) => kprintln!("[APS]  smoke FAIL on CPU {}: {}", hart_id, reason),
        }

        // AZOS Phase 1 W4-int.5 — exercise the APS dispatch toggle
        // atomically. The previous `[APS] smoke OK` print already verified
        // the policy runqueues are populated; this verifies the flag
        // atomic is usable. A long-running APS-active soak is W4-int.6
        // territory (not in Phase 1's exit criteria).
        let was = azos_sched::use_aps_dispatch(true);
        let _ = azos_sched::use_aps_dispatch(false);
        kprintln!("[APS]  dispatch toggle on/off OK (prev was {})", was);

        // Authoritative config-driven backend selection — supersedes the
        // diagnostic toggle above.  `SCHED_BACKEND_APS` is emitted by
        // azos_config from the Kconfig choice in config/Kconfig.timing; true
        // means the user selected APS, false means Legacy (the default).
        // Called once in the single-threaded boot path, before `start()`.
        if azos_limits::SCHED_BACKEND_APS {
            let _prev = azos_sched::use_aps_dispatch(true);
            kprintln!("[SCHED] config-selected backend: APS (experimental)");
        } else {
            kprintln!("[SCHED] config-selected backend: Legacy (default)");
        }
    }
    // No APS backend linked: Legacy is the only thing this kernel can
    // dispatch with, whatever `SCHED_BACKEND_APS` says. The const-assert
    // below makes the disagreement a build error instead of a boot-time
    // surprise, so a `cargo build` that forgot `--features sched-aps`
    // against an APS .config cannot silently produce a Legacy kernel.
    #[cfg(not(feature = "sched-aps"))]
    {
        const _: () = assert!(
            !azos_limits::SCHED_BACKEND_APS,
            "CONFIG_SCHED_BACKEND_APS=y but the kernel was built without \
             --features sched-aps: the APS backend is not linked in"
        );
        kprintln!("[SCHED] config-selected backend: Legacy (default)");
    }
    // RFC-0051: the same disagreement for Kconfig ENERGY, which emits the
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
    // RFC-0002 path (api → registry → lookup → trait dispatch →
    // hardware) end-to-end. Stays InKernel + isolated to this
    // smoke; the legacy `kprint!` macros are unchanged.
    {
        // Trait methods on `&dyn Driver` are accessible through the
        // return type itself — no explicit `use` needed.
        static UART_DRV: azos_drv_sys::uart_driver::UartDriver =
            azos_drv_sys::uart_driver::UartDriver::new();
        match azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .register(&UART_DRV)
        {
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
        match azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .register(&GPIO_DRV)
        {
            Ok(()) => kprintln!("[REG]  GPIO registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  GPIO register FAILED: {:?}", e),
        }

        // A3a.3 — register the third concrete `Driver` impl.
        // Bus-oriented family; proves the trait scales across
        // hardware models (char / pin / bus).
        static I2C_DRV: azos_drv_bus::i2c_driver::I2cDriver =
            azos_drv_bus::i2c_driver::I2cDriver::new();
        match azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .register(&I2C_DRV)
        {
            Ok(()) => kprintln!("[REG]  I2C  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  I2C  register FAILED: {:?}", e),
        }

        // A3a.4 — fourth: multi-parameter actuator (PWM).
        static PWM_DRV: azos_drv_actuator::pwm_driver::PwmDriver =
            azos_drv_actuator::pwm_driver::PwmDriver::new();
        match azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .register(&PWM_DRV)
        {
            Ok(()) => kprintln!("[REG]  PWM  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  PWM  register FAILED: {:?}", e),
        }

        // A3a.5 — fifth: closed-loop controller (motor PID).
        // Pure software (no MMIO) — composes PWM + encoders.
        static MOTOR_DRV: azos_drv_actuator::motor_driver::MotorPidDriver =
            azos_drv_actuator::motor_driver::MotorPidDriver::new();
        match azos_drv_base::runtime::registry::REGISTRY
            .lock()
            .register(&MOTOR_DRV)
        {
            Ok(()) => kprintln!("[REG]  MTR  registered into driver registry"),
            Err(e) => azos_drv_sys::kerr!("[REG]  MTR  register FAILED: {:?}", e),
        }

        // A5.next — exercise SYS_DRV_INVOKE end-to-end through the
        // *real* syscall handler (not just the trait directly).
        // Called from kernel context so `current_user_pt() == 0`
        // and the raw-copy path is taken; the userspace path will
        // be exercised by the brain client task later.
        let msg = b"[A5]   sys_drv_invoke UART write via syscall OK\n";
        // Wire-format constants, DERIVED. These were literals under a
        // comment saying they avoided "a kernel→abi Cargo dep" — a reason that
        // stopped being true when this crate took a real `azos_abi`
        // dependency for `DRV_KIND_*`, and the literal then sat here as the
        // last restatement of a syscall number after `1195b1e` removed the
        // other three. It hid from the gate's new literal check because it
        // used a DIFFERENT local name (`SYS_DRV_INVOKE_NR` for
        // `SYS_DRV_INVOKE`), which is exactly that check's documented blind
        // spot.
        const SYS_DRV_INVOKE_NR: u64 = azos_abi::syscall_nr::SYS_DRV_INVOKE;
        const DRV_KIND_UART_NR: u64 = azos_driver_server::DRV_KIND_UART as u64;
        const UART_OP_WRITE_NR: u64 = 0;
        let rc = azos_syscall::syscall_dispatch(
            SYS_DRV_INVOKE_NR,
            DRV_KIND_UART_NR,
            UART_OP_WRITE_NR,
            msg.as_ptr() as u64,
            msg.len() as u64,
            /* out_ptr */ 0,
            /* out_cap */ 0,
            /* sepc */ 0, /* user_sp */ 0,
            // Synthetic call from kernel context: there is no real trap frame,
            // and this can never be SYS_FORK, which is the only arm that reads
            // the register file (K-C11). `UserRegs::default()` rather than a
            // `[0u64; 32]` literal because `UserRegs` is ISA-shaped on
            // aarch64 (`azos_arch::fork_regs::ForkRegs`, 800 bytes —
            // GPRs + SP_EL0/SPSR_EL1/TPIDR_EL0/FP state — not `[u64; 32]`;
            // see that struct's module doc) — a bare `[0u64; 32]` here would
            // stop type-checking the day this file is built for aarch64.
            &azos_sched::UserRegs::default(),
        );
        if rc < 0 {
            kprintln!("[A5]   sys_drv_invoke returned errno {}", rc);
        }




    }

    // ── Protocol conformance: the bytes that go on the wire ────────────
    //
    // **Why this and not another round-trip test.** Everything else here that
    // exercises the network is **self-consistent**: we send ourselves a
    // datagram and check it arrives. A systematic error — byte order inverted
    // on write AND on read, say — would pass green and fail the day we talk to
    // a real machine.
    //
    // This compares against the standard, not against ourselves: an IPv4
    // header is built and the bytes **RFC 791** prescribes are asserted, at
    // their offsets, in network order.
    {
        use azos_net::ip;
        let src = [10u8, 0, 2, 15];
        let dst = [10u8, 0, 2, 99];
        let mut h = [0u8; ip::IP_HDR_MIN];
        ip::build_header(&mut h, ip::IP_PROTO_UDP, &src, &dst, 8);

        let mut bad = 0u32;
        // RFC 791 §3.1: version (high 4 bits) and IHL in 32-bit words. IPv4
        // with a minimum header ⇒ 0x45. A 0x54 here would be the nibbles
        // swapped, which is the classic silent failure.
        if h[0] != 0x45 { bad |= 1; }
        // Protocol at byte 9. UDP = 17.
        if h[9] != 17 { bad |= 2; }
        // Total length at 2..4, **big-endian**: 20 header + 8 payload.
        if u16::from_be_bytes([h[2], h[3]]) != 28 { bad |= 4; }
        // Addresses at 12..16 and 16..20, in network order (not byte-swapped).
        if h[12..16] != src || h[16..20] != dst { bad |= 8; }
        // RFC 1071: a well-formed header sums to 0xFFFF **including its own
        // checksum**, so the one's complement of that sum is 0. This validates
        // the checksum without recomputing it with the same code that produced
        // it, which would be tautological.
        if ip::checksum(&h) != 0 { bad |= 16; }

        // ── RFC 894: Ethernet frame ────────────────────────────────────
        //
        // Order: destination(6), source(6), ethertype(2) **big-endian**. IPv4
        // is 0x0800, and writing it reversed — 0x0008 — produces a frame no
        // switch will deliver and that our own stack would accept if it also
        // read it reversed.
        {
            use azos_net::ethernet;
            let dmac = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let smac = [0x52u8, 0x54, 0x00, 0x12, 0x34, 0x56];
            let mut f = [0u8; 64];
            let n = ethernet::build(&mut f, &dmac, &smac, ethernet::ETH_TYPE_IP, &[1, 2, 3, 4]);
            if f[0..6] != dmac { bad |= 32; }
            if f[6..12] != smac { bad |= 64; }
            if u16::from_be_bytes([f[12], f[13]]) != 0x0800 { bad |= 128; }
            if n != 14 + 4 { bad |= 256; }
        }

        // ── RFC 768 + 791: accept a HAND-BUILT datagram ────────────────
        //
        // **This is what separates interoperating from being self-consistent.**
        // Everything else builds the packet with our code and verifies it with
        // our code: a byte-order error in both directions would pass green.
        // Here the bytes are written by hand per the RFC and handed to the
        // parser: if it accepts them and extracts the right values, we
        // understand what a real machine sends.
        //
        // The UDP checksum is zero, which **RFC 768 explicitly permits** on
        // IPv4: "an all zero transmitted checksum value means that the
        // transmitter generated no checksum". Accepting it is part of the
        // standard.
        {
            use azos_net::{ip, udp};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            const P_DST: u16 = 7501;
            const P_SRC: u16 = 7502;
            let sock = udp::bind(P_DST);
            if sock < 0 {
                bad |= 512;
            } else {
                let payload = b"rfc768";
                let udp_len = 8 + payload.len();
                let total = ip::IP_HDR_MIN + udp_len;
                let mut pkt = [0u8; 64];
                // IPv4 header, by hand (RFC 791 §3.1).
                pkt[0] = 0x45;                                  // version 4, IHL 5
                pkt[1] = 0;                                     // DSCP/ECN
                pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
                pkt[6..8].copy_from_slice(&0u16.to_be_bytes());  // no flags, no offset
                pkt[8] = 64;                                    // TTL
                pkt[9] = 17;                                    // UDP
                // checksum at 10..12 left zero and computed below
                pkt[12..16].copy_from_slice(&[10, 0, 2, 200]);   // foreign source
                pkt[16..20].copy_from_slice(&me);                // destination: us
                let ck = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
                pkt[10..12].copy_from_slice(&ck.to_be_bytes());
                // UDP header, by hand (RFC 768): ports, length, checksum.
                let u = ip::IP_HDR_MIN;
                pkt[u..u + 2].copy_from_slice(&P_SRC.to_be_bytes());
                pkt[u + 2..u + 4].copy_from_slice(&P_DST.to_be_bytes());
                pkt[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                pkt[u + 6..u + 8].copy_from_slice(&0u16.to_be_bytes()); // no checksum
                pkt[u + 8..u + 8 + payload.len()].copy_from_slice(payload);

                ip::handle(&pkt[..total], &my_mac, &me);

                let mut buf = [0u8; 32];
                let mut src_ip = [0u8; 4];
                let mut src_port = 0u16;
                let n = udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
                if n != payload.len() as i32 { bad |= 1024; }
                else if &buf[..n as usize] != payload { bad |= 2048; }
                if src_port != P_SRC { bad |= 4096; }
                if src_ip != [10, 0, 2, 200] { bad |= 8192; }
                udp::close(sock);
            }
        }

        // ── RFC 793: accept a HAND-BUILT SYN ───────────────────────────
        //
        // The largest layer and the one most prone to silent error: `data_off`
        // lives in the **high 4 bits** of byte 12 and counts **32-bit words**,
        // not bytes. Getting that wrong yields a segment our own stack would
        // accept if it also read it wrong.
        //
        // And unlike UDP, **RFC 793 makes the checksum mandatory**: computed
        // over a pseudo-header (source, destination, zero, protocol, TCP
        // length) plus the segment. The SYN being accepted proves we validate
        // it properly; a miscomputed checksum here would make the stack drop
        // it and the state would not advance.
        {
            use azos_net::{ip, tcp};
            const P_LISTEN: u16 = 7601;
            const P_REMOTO: u16 = 7602;
            let me = azos_net::net_get_ip();
            let foreign = [10u8, 0, 2, 201];
            let idx = tcp::listen(P_LISTEN);
            if idx < 0 {
                bad |= 1 << 14;
            } else {
                let mut seg = [0u8; 20];
                seg[0..2].copy_from_slice(&P_REMOTO.to_be_bytes());
                seg[2..4].copy_from_slice(&P_LISTEN.to_be_bytes());
                seg[4..8].copy_from_slice(&0x0001_0000u32.to_be_bytes());  // seq
                seg[8..12].copy_from_slice(&0u32.to_be_bytes());           // ack
                seg[12] = 5 << 4;      // data offset = 5 words = 20 bytes
                seg[13] = 0x02;        // SYN
                seg[14..16].copy_from_slice(&8192u16.to_be_bytes());       // window
                // checksum at 16..18, zero while it is computed
                seg[18..20].copy_from_slice(&0u16.to_be_bytes());          // urgent

                // Pseudo-header + segment, RFC 793 §3.1.
                let mut ps = [0u8; 12 + 20];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[8] = 0;
                ps[9] = 6;                                                 // TCP
                ps[10..12].copy_from_slice(&20u16.to_be_bytes());
                ps[12..32].copy_from_slice(&seg);
                let ck = ip::checksum(&ps);
                seg[16..18].copy_from_slice(&ck.to_be_bytes());

                tcp::handle_checked(&foreign, &me, &seg);

                // **The listener stays in `Listen`; the SYN creates a NEW
                // connection.** That is what RFC 793 mandates — a listening
                // socket is not consumed by its first client — and the first
                // version of this test looked at the listener's slot and
                // failed. The stack was right and the assertion was wrong.
                //
                // A connection appearing in `SynRcvd` is the only signal that
                // the segment was understood IN FULL: ports, `data_off` in
                // 32-bit words, the SYN flag, and the pseudo-header checksum.
                // With any of those wrong it is dropped silently and there is
                // no transition.
                let mut seen = false;
                for i in 0..32 {
                    if tcp::conn_state(i) == tcp::TcpState::SynRcvd {
                        seen = true;
                        tcp::close(i);
                        break;
                    }
                }
                if !seen { bad |= 1 << 15; }
                tcp::close(idx as usize);
            }
        }

        // ── RFC 793 §3.1 + RFC 879 / 6691: the MSS option on the wire ──
        //
        // MSS negotiation was implemented and **never checked against the
        // standard**. The option walk is the classic place for a silent
        // error: it is a type/length/value list where a wrong `data_off`
        // makes it read payload as options, and where NOP padding and
        // unknown options must be skipped by their length byte rather than
        // assumed absent. Every one of those failures degrades silently to
        // the 536-byte default (RFC 879) — a working connection at a third
        // of the segment size, which no functional test would ever notice.
        {
            use azos_net::{ip, tcp};
            let me = azos_net::net_get_ip();
            let foreign = [10u8, 0, 2, 203];
            const P_L: u16 = 7402;

            // A SYN carrying: NOP, an unknown option (kind 250, len 4), then
            // MSS. The MSS is last on purpose — reaching it proves the walk
            // advances by the length byte instead of stopping at the first
            // thing it does not recognise.
            //
            // `mss_in` is checked against `mss_out` rather than a literal so
            // this reads as "what we advertised came back", and 1200 is
            // deliberately NOT 1460: a parser that ignored the option and
            // returned our own constant would pass against 1460.
            let probe = |opts: &[u8], port: u16| -> u16 {
                let hdr_words = (20 + opts.len()) / 4;
                let tlen = 20 + opts.len();
                let mut seg = [0u8; 40];
                seg[0..2].copy_from_slice(&port.to_be_bytes());
                seg[2..4].copy_from_slice(&P_L.to_be_bytes());
                seg[4..8].copy_from_slice(&0x0002_0000u32.to_be_bytes());
                seg[12] = (hdr_words as u8) << 4;
                seg[13] = 0x02;                                    // SYN
                seg[14..16].copy_from_slice(&8192u16.to_be_bytes());
                seg[20..20 + opts.len()].copy_from_slice(opts);

                let mut ps = [0u8; 12 + 40];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[9] = 6;
                ps[10..12].copy_from_slice(&(tlen as u16).to_be_bytes());
                ps[12..12 + tlen].copy_from_slice(&seg[..tlen]);
                let ck = ip::checksum(&ps[..12 + tlen]);
                seg[16..18].copy_from_slice(&ck.to_be_bytes());

                tcp::handle_checked(&foreign, &me, &seg[..tlen]);
                for i in 0..32 {
                    if tcp::conn_state(i) == tcp::TcpState::SynRcvd {
                        let m = tcp::conn_remote_mss(i);
                        tcp::close(i);
                        return m;
                    }
                }
                0
            };

            let l = tcp::listen(P_L);
            if l < 0 {
                bad |= 1 << 19;
            } else {
                // NOP(1) + unknown kind 250 len 4 + MSS 1200 + NOP padding
                // to a 4-byte boundary: 1 + 4 + 4 + 3 = 12 bytes.
                //
                // **The first version of this array was 8 bytes and the test
                // failed — my encoding was wrong, not the parser.** With MSS
                // starting at option offset 5 it needs bytes 5..9, and only
                // 0..8 existed, so the stack correctly refused a truncated
                // option and fell back to 536. Worth leaving written down:
                // this is the third time in this audit that a conformance
                // failure was the assertion rather than the code.
                if probe(&[1, 250, 4, 0, 0, 2, 4, 0x04, 0xB0, 1, 1, 1], 7501) != 1200 {
                    bad |= 1 << 18;
                }
                // No MSS option at all -> RFC 879 default of 536, NOT our own
                // 1460. Getting this wrong makes us oversend to a peer that
                // never asked for large segments.
                if probe(&[1, 1, 1, 1], 7502) != 536 {
                    bad |= 1 << 17;
                }
                // An advertised MSS of 0 is floored, not honoured: `send_data`
                // sizes every segment by it, so a peer could otherwise stall
                // us forever with one legal-looking option. Same defensive
                // floor Linux applies as tcp_min_snd_mss.
                if probe(&[2, 4, 0, 0, 1, 1, 1, 1], 7503) != 64 {
                    bad |= 1 << 16;
                }
                tcp::close(l as usize);
            }
        }

        // ── RFC 826: hand-built ARP ────────────────────────────────────
        //
        // An ARP request from a stranger must leave its (IP, MAC) pair in the
        // cache: **RFC 826 requires it even when the request is not for us**,
        // because whoever is asking will need an answer.
        //
        // The fixed fields are the classic home of silent error: `htype` and
        // `ptype` go in network order, and `hlen`/`plen` are **single bytes**,
        // not a u16 — reading them as a swapped pair gives 6 and 4 exchanged
        // and a cache that fills with garbage.
        {
            use azos_net::arp;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign_ip = [10u8, 0, 2, 202];
            let foreign_mac = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];

            let mut a = [0u8; 28];
            a[0..2].copy_from_slice(&1u16.to_be_bytes());       // htype: Ethernet
            a[2..4].copy_from_slice(&0x0800u16.to_be_bytes());  // ptype: IPv4
            a[4] = 6;                                            // hlen
            a[5] = 4;                                            // plen
            a[6..8].copy_from_slice(&1u16.to_be_bytes());       // oper: request
            a[8..14].copy_from_slice(&foreign_mac);               // sha
            a[14..18].copy_from_slice(&foreign_ip);               // spa
            a[18..24].copy_from_slice(&[0u8; 6]);               // tha: unknown
            a[24..28].copy_from_slice(&me);                     // tpa: us

            arp::handle(&a, &my_mac, &me);
            match arp::lookup(&foreign_ip) {
                Some(m) if m == foreign_mac => {}
                _ => bad |= 1 << 16,
            }
        }

        // ── RFC 768: UDP checksum with pseudo-header, and its rejection ─
        //
        // The previous test uses a zero checksum, which RFC 768 permits on
        // IPv4. This covers the other half — and above all **the negative**:
        // accepting a correct datagram proves nothing about validation,
        // because a stack that ignores the checksum accepts it too. Rejecting
        // a corrupt one does.
        {
            use azos_net::{ip, udp};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign = [10u8, 0, 2, 203];
            const P_DST: u16 = 7701;
            const P_SRC: u16 = 7702;
            let sock = udp::bind(P_DST);
            if sock < 0 {
                bad |= 1 << 17;
            } else {
                let payload = b"ck";
                let udp_len = 8 + payload.len();
                let mut u = [0u8; 16];
                u[0..2].copy_from_slice(&P_SRC.to_be_bytes());
                u[2..4].copy_from_slice(&P_DST.to_be_bytes());
                u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                u[8..8 + payload.len()].copy_from_slice(payload);
                // Pseudo-header + datagram (RFC 768).
                let mut ps = [0u8; 12 + 16];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[9] = 17;
                ps[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
                ps[12..12 + udp_len].copy_from_slice(&u[..udp_len]);
                let mut ck = ip::checksum(&ps[..12 + udp_len]);
                // RFC 768: a checksum that computes to zero is transmitted as
                // 0xFFFF, because zero means "no checksum".
                if ck == 0 { ck = 0xFFFF; }
                u[6..8].copy_from_slice(&ck.to_be_bytes());

                let entregar = |udp_bytes: &[u8]| {
                    let total = ip::IP_HDR_MIN + udp_bytes.len();
                    let mut pkt = [0u8; 64];
                    pkt[0] = 0x45;
                    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                    pkt[8] = 64;
                    pkt[9] = 17;
                    pkt[12..16].copy_from_slice(&foreign);
                    pkt[16..20].copy_from_slice(&me);
                    let ick = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
                    pkt[10..12].copy_from_slice(&ick.to_be_bytes());
                    pkt[ip::IP_HDR_MIN..total].copy_from_slice(udp_bytes);
                    ip::handle(&pkt[..total], &my_mac, &me);
                };

                // 1. With a correct checksum: must be delivered.
                entregar(&u[..udp_len]);
                let mut buf = [0u8; 16];
                if udp::recv(sock as usize, &mut buf) != payload.len() as i32 {
                    bad |= 1 << 18;
                }

                // 2. With one payload bit flipped and the checksum left
                //    stale: must be DROPPED.
                let mut roto = u;
                roto[8] ^= 0x01;
                entregar(&roto[..udp_len]);
                let mut b2 = [0u8; 16];
                if udp::recv(sock as usize, &mut b2) > 0 {
                    bad |= 1 << 19;   // a corrupt datagram was delivered
                }
                udp::close(sock);
            }
        }

        // ── RFC 792: hand-built ICMP echo ──────────────────────────────
        //
        // Answering a ping is the floor of interoperability: it is the first
        // thing anyone does to check whether a machine is alive.
        //
        // RFC 792 requires **returning identifier and sequence untouched** —
        // the pinger matches the reply to its request by those fields. A stack
        // that zeroed them would answer something the far end discards, and
        // from outside it would look unresponsive.
        {
            use azos_net::ip;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign = [10u8, 0, 2, 204];

            let mut icmp = [0u8; 12];
            icmp[0] = 8;                                        // echo request
            icmp[1] = 0;                                        // code
            icmp[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // identifier
            icmp[6..8].copy_from_slice(&0x0007u16.to_be_bytes()); // sequence
            icmp[8..12].copy_from_slice(b"ping");
            let ck = ip::checksum(&icmp);
            icmp[2..4].copy_from_slice(&ck.to_be_bytes());

            // A request with a correct checksum must be processed; the
            // handler validates `checksum(data) != 0` and drops on mismatch,
            // so if this construction were wrong there would be no reply and
            // no way to tell that apart from "not implemented". The premise is
            // checked before delivering.
            if ip::checksum(&icmp) != 0 { bad |= 1 << 20; }

            let total = ip::IP_HDR_MIN + icmp.len();
            let mut pkt = [0u8; 64];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 1;                                          // ICMP
            pkt[12..16].copy_from_slice(&foreign);
            pkt[16..20].copy_from_slice(&me);
            let ick = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
            pkt[10..12].copy_from_slice(&ick.to_be_bytes());
            pkt[ip::IP_HDR_MIN..total].copy_from_slice(&icmp);
            // The reply cannot be observed from here (it leaves via the NIC),
            // but a panic or a checksum drop would show: the value of this
            // delivery is that it exercises the whole path with foreign
            // bytes.
            ip::handle(&pkt[..total], &my_mac, &me);
        }

        // ── RFC 919/922: broadcast ─────────────────────────────────────
        //
        // This used to return -1 ALWAYS: a broadcast destination fell into
        // `arp::lookup` and nobody answers ARP for a broadcast address.
        // `dhcp.rs` sidestepped it with its own raw path; from ring 3 there
        // was no way at all.
        {
            use azos_net::ip;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            // Limited broadcast (RFC 919): never forwarded off the link.
            if nic_present
                && ip::send(&my_mac, &me, &[255, 255, 255, 255], ip::IP_PROTO_UDP, b"bcast") != 0 {
                bad |= 1 << 21;
            }
            // Subnet broadcast (RFC 922): network | ~mask.
            let m = azos_net::net_get_mask();
            let mut subnet = [0u8; 4];
            for i in 0..4 { subnet[i] = (me[i] & m[i]) | !m[i]; }
            if nic_present && ip::send(&my_mac, &me, &subnet, ip::IP_PROTO_UDP, b"bcast") != 0 {
                bad |= 1 << 22;
            }
        }

        // ── RFC 1112 / RFC 2236: IPv4 multicast and IGMPv2 ─────────────
        //
        // Multicast was **impossible in both directions** until now, and for
        // two different reasons — which is why testing only one would have
        // looked fine. RX: the destination filter admits our unicast and the
        // two broadcast forms and dropped 224.0.0.0/4 outright. TX: a group
        // destination fell into `arp::lookup`, and no host owns a group, so
        // nobody answers — the same failure broadcast had before RFC 919/922.
        {
            use azos_net::{igmp, ip};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();

            // §6.4 MAC mapping, and above all its **aliasing**: only the low
            // 23 bits travel, so the group's 24th bit is dropped and 32 groups
            // share one Ethernet address. Checked with a pair that collides on
            // purpose — if this ever became a straight copy of the low three
            // bytes, unicast-looking groups would map to wrong MACs and the
            // single-address case would still pass.
            if igmp::multicast_mac(&[224, 1, 2, 3]) != [0x01, 0x00, 0x5E, 0x01, 0x02, 0x03] {
                bad |= 1 << 23;
            }
            if igmp::multicast_mac(&[224, 128, 1, 1]) != igmp::multicast_mac(&[225, 0, 1, 1]) {
                bad |= 1 << 24;
            }

            // §4: 224.0.0.0/4 and nothing else. 223.255.255.255 is the last
            // unicast address and 240.0.0.0 the first reserved one; both
            // neighbours are checked because an off-by-one in the mask is the
            // realistic mistake, not a wild answer.
            if !igmp::is_multicast(&[224, 0, 0, 1]) || !igmp::is_multicast(&[239, 255, 255, 255])
                || igmp::is_multicast(&[223, 255, 255, 255]) || igmp::is_multicast(&[240, 0, 0, 0]) {
                bad |= 1 << 25;
            }

            // §6.1: every host is a permanent member of all-hosts without
            // joining, and a group nobody joined must NOT be admitted. The
            // negative is the half that proves the filter still filters.
            if !igmp::is_joined(&igmp::ALL_HOSTS) || igmp::is_joined(&[239, 9, 9, 9]) {
                bad |= 1 << 26;
            }

            const GRP: [u8; 4] = [239, 1, 2, 3];
            if igmp::join(&GRP) != 0 || !igmp::is_joined(&GRP) { bad |= 1 << 27; }
            // Non-multicast joins are refused: accepting one would put a
            // unicast address in the group table and admit a stranger's
            // traffic through the multicast branch of the filter.
            if igmp::join(&[10, 0, 2, 200]) != -1 { bad |= 1 << 28; }

            // RFC 2236 §2: the on-wire report is 8 bytes, type 0x16, max-resp
            // 0, and carries the group. The checksum is verified by the
            // RFC 1071 property (a correct message folds to 0), NOT by
            // recomputing it here — recomputing only proves the code agrees
            // with itself.
            let rep = igmp::build_message(igmp::IGMP_V2_REPORT, 0, &GRP);
            if rep[0] != 0x16 || rep[1] != 0 || rep[4..8] != GRP || ip::checksum(&rep) != 0 {
                bad |= 1 << 29;
            }

            // A joined group now survives the destination filter and its
            // datagram is delivered up the stack (IP_MULTICAST_LOOP default).
            // `ip::send` returning 0 is what was impossible before: with the
            // ARP path it returned -1.
            if nic_present && ip::send(&my_mac, &me, &GRP, ip::IP_PROTO_UDP, b"mcast") != 0 {
                bad |= 1 << 30;
            }

            // A **corrupt** query must be ignored. Same doctrine as the UDP
            // checksum: acting on a validated query proves nothing, because a
            // stack that skips validation acts on it too. Here it matters more
            // than usual — an accepted forged query makes us emit reports on
            // demand, which is a remote amplification primitive.
            let mut q = igmp::build_message(igmp::IGMP_MEMBERSHIP_QUERY, 100, &[0, 0, 0, 0]);
            q[3] ^= 0xFF;
            igmp::handle(&q);   // must not panic and must not act

            // Leaving restores the starting state, and leaving twice reports
            // "not a member" instead of silently succeeding.
            if igmp::leave(&GRP) != 0 || igmp::is_joined(&GRP) { bad |= 1 << 31; }
            if igmp::leave(&GRP) != -2 { bad |= 1 << 20; }
        }

        // ── RFC 1035: DNS response parsing ─────────────────────────────
        //
        // 458 lines of parser for data that arrives from a remote server, with
        // no test and no scenario until now. That combination is the one that
        // matters here: `panic = "abort"` plus `overflow-checks = true` means a
        // reachable panic in this parser is a **board reset an off-path
        // attacker can trigger**, which is exactly the class already found in
        // `ip.rs` (a crafted `total_length < ihl` produced a reversed range).
        //
        // These checks lock the defences in place rather than discovering
        // them: the parser is in good shape, and the value is that removing a
        // bound now fails the gate instead of shipping.
        let mut bad2 = 0u32;
        {
            use azos_net::dns;
            const TX: u16 = 0x1234;

            // A well-formed A answer that uses a compression pointer for the
            // answer NAME (RFC 1035 §4.1.4) -- the normal shape of every real
            // reply, and the one a naive parser gets wrong by treating 0xC0 as
            // a label length.
            let mut r = [0u8; 64];
            r[0..2].copy_from_slice(&TX.to_be_bytes());
            r[2] = 0x81; r[3] = 0x80;                    // QR=1, RD, RA, rcode=0
            r[5] = 1;                                     // qdcount=1
            r[7] = 1;                                     // ancount=1
            // question: "ab" (2-byte label) + root, QTYPE=A, QCLASS=IN
            r[12] = 2; r[13] = b'a'; r[14] = b'b'; r[15] = 0;
            r[17] = 1;                                    // QTYPE = A
            r[19] = 1;                                    // QCLASS = IN
            // answer record, starting at offset 20:
            //   20..22 NAME (pointer to the question name at offset 12)
            //   22..24 TYPE=A   24..26 CLASS=IN   26..30 TTL
            //   30..32 RDLENGTH=4                 32..36 RDATA
            //
            // **The first version of this had TTL and RDLENGTH two bytes off,
            // and the parser was right.** Fourth time in this audit a
            // conformance failure was the assertion rather than the code --
            // which is the argument for writing the offsets out as a map
            // rather than counting them in one's head.
            r[20] = 0xC0; r[21] = 12;
            r[23] = 1;                                    // TYPE = A
            r[25] = 1;                                    // CLASS = IN
            r[29] = 60;                                   // TTL = 60
            r[31] = 4;                                    // RDLENGTH = 4
            r[32] = 10; r[33] = 0; r[34] = 2; r[35] = 99; // RDATA = 10.0.2.99
            if dns::parse_response(&r[..36], TX) != Some([10, 0, 2, 99]) {
                bad2 |= 1 << 0;
            }

            // The anti-spoof gate: a different transaction id must be refused
            // even though every other byte is valid. Off-path forgery has to
            // guess this, and dropping the check would cost nothing visible.
            if dns::parse_response(&r[..36], TX ^ 0xFFFF).is_some() { bad2 |= 1 << 1; }

            // QR=0 is a *query*, not a response. Accepting one lets anything
            // that can reach our client port answer us.
            let mut q = r; q[2] = 0x01;
            if dns::parse_response(&q[..36], TX).is_some() { bad2 |= 1 << 2; }

            // rcode != 0 (here NXDOMAIN=3): an error carries no address.
            let mut e = r; e[3] = 0x83;
            if dns::parse_response(&e[..36], TX).is_some() { bad2 |= 1 << 3; }

            // ancount = 0 with the answer bytes still present: the header is
            // authoritative about how many records exist.
            let mut z = r; z[7] = 0;
            if dns::parse_response(&z[..36], TX).is_some() { bad2 |= 1 << 4; }

            // **A compression pointer loop.** RFC 1035 allows pointers to
            // point backwards; nothing stops a hostile server pointing one at
            // itself. Without the jump limit in `skip_name` this hangs the
            // kernel -- a remote denial of service in four bytes. Reaching the
            // assertion at all is the test: if it hangs, the scenario times
            // out and the gate goes red.
            let mut loopy = r;
            loopy[20] = 0xC0; loopy[21] = 20;   // answer name points to itself
            if dns::parse_response(&loopy[..36], TX).is_some() { bad2 |= 1 << 5; }

            // Truncation at every length: none may panic, and a header-only
            // response must not be read as an answer.
            for n in 0..36usize {
                if dns::parse_response(&r[..n], TX).is_some() { bad2 |= 1 << 6; }
            }

            // RDLENGTH pointing past the end of the buffer: the record claims
            // 200 bytes inside a 38-byte packet.
            let mut over = r; over[31] = 200;
            if dns::parse_response(&over[..36], TX).is_some() { bad2 |= 1 << 7; }
        }

        // ── RFC 5905: NTP server-reply header gate ─────────────────────
        //
        // Same reasoning as DNS: 335 lines, no test, no scenario, and it reads
        // a remote server's packet. Every rejection below is a real attack or
        // a real malfunction, not a hypothetical.
        {
            use azos_net::ntp;
            let mut good = [0u8; 48];
            good[0] = 0x24;          // LI=0, VN=4, mode=4 (server)
            good[1] = 2;             // stratum 2
            if !ntp::header_acceptable(&good) { bad2 |= 1 << 8; }

            // Mode 3 is a *client* packet. Accepting one means a peer that
            // simply echoes our request back can set our clock.
            let mut m = good; m[0] = 0x23;
            if ntp::header_acceptable(&m) { bad2 |= 1 << 9; }

            // LI=3: the server is telling us it is not synchronised itself.
            let mut li = good; li[0] = 0xE4;
            if ntp::header_acceptable(&li) { bad2 |= 1 << 10; }

            // Stratum 0 is kiss-o'-death: the timestamp fields carry a
            // four-character ASCII code, NOT a time. Parsing it as a clock
            // reads "DENY" as an epoch.
            let mut k = good; k[1] = 0;
            if ntp::header_acceptable(&k) { bad2 |= 1 << 11; }

            // Stratum 16 and above: unsynchronised.
            let mut u = good; u[1] = 16;
            if ntp::header_acceptable(&u) { bad2 |= 1 << 12; }

            // A short packet must be refused before any field is indexed.
            for n in 0..48usize {
                if ntp::header_acceptable(&good[..n]) { bad2 |= 1 << 13; }
            }
        }

        // ── RFC 4291 / 8200: IPv6 address architecture ─────────────────
        //
        // Every public predicate in `ipv6.rs` was untested. These are pure
        // functions over addresses, and the two below are the ones that are
        // silently wrong rather than obviously wrong: get either one subtly
        // off and the stack still boots, still answers pings, and simply
        // cannot be resolved by a neighbour.
        {
            use azos_net::ipv6;

            // RFC 4291 §2.5.6 / App. A. Two things get botched here: the
            // FF:FE inserted in the MIDDLE of the MAC (not appended), and the
            // **Universal/Local bit flip** in the first octet. QEMU's
            // 52:54:00:12:34:56 has bit 1 clear, so the flip must produce
            // 0x50 -- an implementation that forgot it yields 0x52 and the
            // address still looks plausible.
            let ll = ipv6::eui64_link_local(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
            let want_ll: [u8; 16] = [
                0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                0x50, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56,
            ];
            if ll != want_ll { bad2 |= 1 << 14; }

            // RFC 4291 §2.7.1: FF02::1:FFXX:XXXX over the low **24** bits.
            // Neighbour Solicitations for our address go to this group rather
            // than to all-nodes, so an interface that computes it wrongly is
            // simply unreachable -- and it fails silently, because everything
            // it initiates still works.
            let sn = ipv6::solicited_node(&want_ll);
            let want_sn: [u8; 16] = [
                0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56,
            ];
            if sn != want_sn { bad2 |= 1 << 15; }

            // Only the low 24 bits may participate: two addresses differing
            // above byte 13 must map to the SAME group. A version that hashed
            // more of the address would pass the single case above.
            let mut other = want_ll; other[8] ^= 0xFF; other[12] ^= 0xFF;
            if ipv6::solicited_node(&other) != want_sn { bad2 |= 1 << 16; }

            // §2.7: multicast is exactly FF00::/8, and all-nodes is FF02::1.
            if !ipv6::is_multicast(&want_sn) { bad2 |= 1 << 17; }
            if ipv6::is_multicast(&want_ll)  { bad2 |= 1 << 18; }
            let all_nodes: [u8; 16] = [0xFF, 0x02, 0,0,0,0,0,0, 0,0,0,0,0,0,0, 0x01];
            if !ipv6::is_all_nodes(&all_nodes) { bad2 |= 1 << 19; }
            if ipv6::is_all_nodes(&want_sn)    { bad2 |= 1 << 20; }

            // ── The receive path: destination filter and RFC 8200 §8.1 ──
            //
            // `ipv6_rx` returns nothing, so this observes its effect: a UDP
            // socket either receives the datagram or does not. Two things are
            // being locked in, and both have teeth.
            //
            // **The destination filter has already been a no-op once.** Its
            // own comment records that it used to end in `|| is_multicast(dst)`
            // — which admits every group address that exists, so anyone who
            // set the first byte to 0xFF reached the shared UDP dispatcher.
            // Membership, not format, has to be the filter, and the only way
            // to show that is to send to a group we did NOT join and watch it
            // not arrive.
            //
            // **RFC 8200 §8.1 inverts the IPv4 rule**: over IPv6 the UDP
            // checksum is mandatory, and a zero field is malformed rather than
            // "sender opted out". Carrying the IPv4 habit over is the natural
            // mistake, and it silently accepts corrupt datagrams.
            //
            // The valid checksum is produced with our own `pseudo_checksum`.
            // That is deliberately not a claim about the checksum arithmetic —
            // RFC 1071 covers that elsewhere; here it only has to be good
            // enough that the positive case is not rejected for the wrong
            // reason, so the filter result is what the assertion sees.
            let me6 = ipv6::ipv6_link_local();
            if ipv6::ipv6_ready() {
                use azos_net::udp;
                const P6: u16 = 7601;
                let sock = udp::bind(P6);
                if sock < 0 {
                    bad2 |= 1 << 21;
                } else {
                    let si = sock as usize;
                    // Build UDP: src 7602 -> dst P6, 4 bytes of payload.
                    let mut seg = [0u8; 12];
                    seg[0..2].copy_from_slice(&7602u16.to_be_bytes());
                    seg[2..4].copy_from_slice(&P6.to_be_bytes());
                    seg[4..6].copy_from_slice(&12u16.to_be_bytes());  // UDP length
                    seg[8..12].copy_from_slice(b"v6ok");
                    let peer: [u8; 16] = [
                        0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                        0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55,
                    ];
                    let ck = ipv6::pseudo_checksum(&peer, &me6, ipv6::NEXTHDR_UDP, &seg);
                    seg[6..8].copy_from_slice(&ck.to_be_bytes());

                    // Wrap in an IPv6 header addressed to `dst`.
                    let build = |dst: &[u8; 16], seg: &[u8; 12]| -> [u8; 52] {
                        let mut f = [0u8; 52];
                        f[0] = 0x60;                                   // version 6
                        f[4..6].copy_from_slice(&12u16.to_be_bytes()); // payload length
                        f[6] = ipv6::NEXTHDR_UDP;
                        f[7] = 64;                                     // hop limit
                        f[8..24].copy_from_slice(&peer);
                        f[24..40].copy_from_slice(dst);
                        f[40..52].copy_from_slice(seg);
                        f
                    };

                    let mut rx = [0u8; 16];

                    // (a) To a group we have NOT joined: must not arrive.
                    let never: [u8; 16] = [
                        0xFF, 0x02, 0,0,0,0,0,0, 0,0,0,0, 0xDE, 0xAD, 0xBE, 0xEF,
                    ];
                    ipv6::ipv6_rx(&build(&never, &seg), 52);
                    if udp::recv(si, &mut rx) > 0 { bad2 |= 1 << 22; }

                    // (b) Zero checksum to our own address: malformed over
                    //     IPv6, must not arrive.
                    let mut zck = seg; zck[6] = 0; zck[7] = 0;
                    ipv6::ipv6_rx(&build(&me6, &zck), 52);
                    if udp::recv(si, &mut rx) > 0 { bad2 |= 1 << 23; }

                    // (c) The positive case: our unicast address, valid
                    //     checksum. Without this the two rejections above
                    //     would also pass on a stack that drops everything.
                    ipv6::ipv6_rx(&build(&me6, &seg), 52);
                    let n = udp::recv(si, &mut rx);
                    if n != 4 || &rx[..4] != b"v6ok" { bad2 |= 1 << 24; }

                    udp::close(sock);
                }
            }
        }

        if bad2 != 0 {
            kprintln!("[NET]  RFC 1035/4291/5905 FAIL mask={:#x}", bad2);
        }

        if bad == 0 && bad2 == 0 && !nic_present {
            // Honest partial verdict. Saying "conformant" here would claim the
            // three wire sends passed when they were never attempted, and that
            // is the same overclaim the FAIL line made in the other direction.
            kprintln!("[NET]  RFC probe: broadcast/multicast wire sends SKIPPED (no NIC) - the rest conformant");
        } else if bad == 0 && bad2 == 0 {
            kprintln!("[NET]  RFC 791/894/768/792/793/826/879/919/922/1035/1112/2236/4291/5905 conformant - incl. rejection paths, TCP options, broadcast, multicast, DNS and NTP");
        } else {
            kprintln!("[NET]  RFC 791 FAIL mask={:#x} - b0={:#x} b9={} len={} ck={:#x}",
                bad, h[0], h[9], u16::from_be_bytes([h[2], h[3]]), ip::checksum(&h));
        }
    }

    // ── Loopback: boot smoke check ─────────────────────────────────────
    //
    // **Before this, a datagram to our own IP went out to the wire.**
    // `ip::send` went straight to `arp::lookup`, which finds no MAC for
    // ourselves, emitted a pointless ARP request and returned -1. Two local
    // processes could not talk over IP.
    //
    // The check is the return value: it used to be -1, it must now be 0. Done
    // here, in the shape of the other boot smokes (`[A5]`, `[REG]`), because
    // it runs in **every** QEMU scenario and therefore lands in `ci_check`
    // without a new scenario.
    //
    // Skipped when there is no IP yet: with `0.0.0.0` loopback is disabled on
    // purpose — `dst == our_ip` would hold for destination `0.0.0.0` — and a
    // failure here would be correct, not a defect.
    {
        let ip = azos_net::net_get_ip();
        if ip != [0, 0, 0, 0] {
            let mac = azos_net::net_get_mac();
            let probe = b"loopback-smoke";
            let rc = azos_net::ip::send(
                &mac, &ip, &ip, azos_net::ip::IP_PROTO_UDP, probe);
            if rc != 0 {
                azos_drv_sys::kerr!("[NET]  loopback FAIL rc={} - a local destination must not go to ARP", rc);
            } else {
                kprintln!("[NET]  loopback: local delivery OK (never reaches the wire)");

                // A full UDP round trip, not merely `ip::send` not failing.
                //
                // **This could not be written until today.** `socket_send`
                // refused anything that was not TCP and so did
                // `socket_connect`, so a UDP socket was receive-only: it could
                // be created and bound, and there was no way to give it a
                // destination.
                //
                // Both halves are exercised together here — connected UDP and
                // local delivery — which is what two robot processes need to
                // talk over IP without going through fast-IPC.
                use azos_net::socket::{self, SockAddr};
                const PUERTO: u16 = 7777;
                let rx = socket::socket_create(2, 2, 0);   // AF_INET, SOCK_DGRAM
                let tx = socket::socket_create(2, 2, 0);
                if rx >= 0 && tx >= 0 {
                    let dir = SockAddr { family: 2, port: PUERTO, addr: ip };
                    let ok_bind = socket::socket_bind(rx, &dir) == 0;
                    let ok_conn = socket::socket_connect(tx, &dir, 0) == 0;
                    let sent = socket::socket_send(tx, b"udp-loopback");
                    let mut buf = [0u8; 32];
                    let got = socket::socket_recv(rx, &mut buf);
                    if ok_bind && ok_conn && sent > 0 && got == sent
                        && &buf[..got as usize] == b"udp-loopback"
                    {
                        kprintln!("[NET]  UDP loopback: round trip OK ({} bytes)", got);
                    } else {
                        kprintln!("[NET]  UDP loopback FAIL: bind={} conn={} sent={} recv={}",
                            ok_bind, ok_conn, sent, got);
                    }
                    socket::socket_close(rx);
                    socket::socket_close(tx);
                } else {
                    azos_drv_sys::kerr!("[NET]  UDP loopback: could not create sockets");
                }
            }
        } else {
            kprintln!("[NET]  loopback: no IP assigned yet, check skipped");
        }
    }

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

    // RFC-0046 stage 1a: wired-source delivery through APLIC -> IMSIC on
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
    // while a watchdog is armed. What only a timer interrupt observes — lease
    // expiry, the K-C25 reaper — asks for a bounded idle sleep through this
    // hook instead (`timebase::IDLE_POLL_US`).
    azos_drv_sys::timebase::set_idle_poll_hook(idle_poll_wanted);
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
/// timer interrupt observes is pending — an orphaned wake stamp (K-C25) or a
/// lease with a deadline (`lease_tick`).
fn idle_poll_wanted() -> bool {
    azos_sched::stamp_pending() || azos_ipc::lease::lease_deadline_count() != 0
}
