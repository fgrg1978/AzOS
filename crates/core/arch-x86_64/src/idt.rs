// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 IDT: vector numbering, the exception table, and the pure gate
//! encoder. One IDT is shared by every CPU (the stubs are the same; what
//! differs per CPU is the TSS the IST indices refer to).
//!
//! Vectors 0..31 are the architectural exceptions. 32..255 are interrupts:
//! device IRQs (IOAPIC lines and MSIs, from the configured base up), the
//! IPI, and the LAPIC spurious vector, numbered by the kernel's Kconfig
//! (`X86_IRQ_VECTOR_BASE`, `X86_IPI_VECTOR`, `X86_SPURIOUS_VECTOR`). Every
//! one of the 256 has a stub; which are routed is the irqchip's business.
//!
//! Pure functions and tables only (no `asm!`), host-tested.

/// Number of IDT entries.
pub const VECTORS: usize = 256;
/// The first vector that is not an architectural exception.
pub const FIRST_INTERRUPT: usize = 32;

/// The value `syscall_entry` stores in `TrapFrame::vector`: outside 0..255,
/// so no IDT vector can be mistaken for a system call.
pub const SYSCALL_VECTOR: u64 = VECTORS as u64;

// ── Architectural exceptions (SDM Vol. 3A, Table 6-1) ─────────────────────
pub const DE: usize = 0;   // divide error
pub const DB: usize = 1;   // debug
pub const NMI: usize = 2;  // non-maskable interrupt
pub const BP: usize = 3;   // breakpoint (int3)
pub const OF: usize = 4;   // overflow (into)
pub const BR: usize = 5;   // BOUND range exceeded
pub const UD: usize = 6;   // invalid opcode
pub const NM: usize = 7;   // device not available
pub const DF: usize = 8;   // double fault
pub const TS: usize = 10;  // invalid TSS
pub const NP: usize = 11;  // segment not present
pub const SS: usize = 12;  // stack-segment fault
pub const GP: usize = 13;  // general protection
pub const PF: usize = 14;  // page fault
pub const MF: usize = 16;  // x87 FP error
pub const AC: usize = 17;  // alignment check
pub const MC: usize = 18;  // machine check
pub const XM: usize = 19;  // SIMD FP exception
pub const VE: usize = 20;  // virtualization exception
pub const CP: usize = 21;  // control protection (CET)
pub const HV: usize = 28;  // hypervisor injection (AMD SEV-SNP)
pub const VC: usize = 29;  // VMM communication (AMD SEV-ES)
pub const SX: usize = 30;  // security exception (AMD)

/// Mnemonic and name of each exception vector (reserved ones say so).
pub const EXCEPTION_NAMES: [&str; FIRST_INTERRUPT] = [
    "#DE divide error",
    "#DB debug",
    "NMI",
    "#BP breakpoint",
    "#OF overflow",
    "#BR bound range exceeded",
    "#UD invalid opcode",
    "#NM device not available",
    "#DF double fault",
    "coprocessor segment overrun",
    "#TS invalid TSS",
    "#NP segment not present",
    "#SS stack-segment fault",
    "#GP general protection",
    "#PF page fault",
    "reserved (15)",
    "#MF x87 floating-point error",
    "#AC alignment check",
    "#MC machine check",
    "#XM SIMD floating-point exception",
    "#VE virtualization exception",
    "#CP control protection",
    "reserved (22)",
    "reserved (23)",
    "reserved (24)",
    "reserved (25)",
    "reserved (26)",
    "reserved (27)",
    "#HV hypervisor injection",
    "#VC VMM communication",
    "#SX security exception",
    "reserved (31)",
];

/// The name of `vector`: an exception's, or "interrupt".
pub fn vector_name(vector: usize) -> &'static str {
    EXCEPTION_NAMES.get(vector).copied().unwrap_or("interrupt")
}

/// True for the exceptions where the CPU pushes an error code (the stub of
/// every other vector pushes a dummy 0 so the frame has one shape).
pub const fn has_error_code(vector: usize) -> bool {
    matches!(vector, DF | TS | NP | SS | GP | PF | AC | CP | VC | SX)
}

// ── IST assignment ─────────────────────────────────────────────────────────
//
// The three exceptions that can arrive with a stack that cannot be trusted:
// #DF (the fault was taken while pushing onto a broken stack), NMI and #MC
// (they ignore IF, so they can land inside `syscall_entry` before it has
// switched off the user RSP). Each gets its own known-good stack from the
// TSS. Every other vector uses the stack the CPU picks (RSP0 from ring 3,
// the current one from ring 0), and device interrupts then move to the
// per-CPU interrupt stack in software, as riscv64 and aarch64 do.

/// IST index (1-based, as the gate encodes it) of the #DF stack.
pub const IST_DOUBLE_FAULT: u8 = 1;
/// IST index of the NMI stack.
pub const IST_NMI: u8 = 2;
/// IST index of the #MC stack.
pub const IST_MACHINE_CHECK: u8 = 3;
/// IST stacks in use.
pub const IST_USED: usize = 3;

/// The IST index of `vector` (0 = no switch).
pub const fn ist_for(vector: usize) -> u8 {
    match vector {
        DF => IST_DOUBLE_FAULT,
        NMI => IST_NMI,
        MC => IST_MACHINE_CHECK,
        _ => 0,
    }
}

/// The gate DPL of `vector`: 3 for `int3` and `into` (ring 3 may raise
/// them on purpose, as on Linux), 0 for everything else, so a ring-3
/// `int $n` on any other vector is a #GP instead of a forged interrupt.
pub const fn dpl_for(vector: usize) -> u8 {
    match vector {
        BP | OF => 3,
        _ => 0,
    }
}

/// Gate types (descriptor bits 43:40).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateKind {
    /// IF cleared on entry. Every vector here uses this: the entry asm
    /// must run masked until the frame is saved and `swapgs` decided.
    Interrupt = 0xE,
    /// IF left as it was.
    Trap = 0xF,
}

/// Pack a 16-byte IDT gate: `handler` reached through code selector
/// `selector`, stack `ist` (0..7), privilege `dpl`, type `kind`. The two
/// halves are the low and high quadwords as they sit in memory.
pub const fn gate(handler: u64, selector: u16, ist: u8, dpl: u8, kind: GateKind) -> [u64; 2] {
    let attr: u64 = (1 << 7) | (((dpl & 3) as u64) << 5) | (kind as u64);
    let low = (handler & 0xFFFF)
        | ((selector as u64) << 16)
        | (((ist & 7) as u64) << 32)
        | (attr << 40)
        | (((handler >> 16) & 0xFFFF) << 48);
    [low, handler >> 32]
}

/// Decode a gate's handler address (the inverse of [`gate`]'s offset split).
pub const fn gate_handler(g: [u64; 2]) -> u64 {
    (g[0] & 0xFFFF) | (((g[0] >> 48) & 0xFFFF) << 16) | (g[1] << 32)
}

/// The entry this kernel installs for `vector`.
pub const fn kernel_gate(vector: usize, handler: u64, kernel_cs: u16) -> [u64; 2] {
    gate(handler, kernel_cs, ist_for(vector), dpl_for(vector), GateKind::Interrupt)
}
