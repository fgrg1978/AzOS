// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 GDT and TSS: the per-CPU segment table and its pure encoders.
//!
//! Long mode ignores segment base and limit for code and data; what is left
//! is privilege (DPL), the L bit, and the order of the selectors, which
//! `syscall`/`sysret` fix through `IA32_STAR`:
//!
//! | sel  | entry                | used by                                  |
//! |------|----------------------|------------------------------------------|
//! | 0x00 | null                 |                                          |
//! | 0x08 | kernel code, 64-bit  | `syscall` CS = STAR[47:32]               |
//! | 0x10 | kernel data          | `syscall` SS = STAR[47:32] + 8           |
//! | 0x1b | user data (DPL 3)    | `sysretq` SS = STAR[63:48] + 8, RPL 3    |
//! | 0x23 | user code, 64-bit    | `sysretq` CS = STAR[63:48] + 16, RPL 3   |
//! | 0x28 | TSS (16 bytes)       | `ltr`: RSP0 and the IST stacks           |
//!
//! There is no 32-bit user code segment: compat mode is not offered, so
//! STAR[63:48] (the `sysret` base) points one slot below user data and the
//! 32-bit `sysretl` target it would name does not exist.
//!
//! Pure functions only (no `asm!`): the host tests check the packing
//! (`tests/host/arch-stub-tests`), and `cpu.rs` installs the result.

/// Kernel code selector.
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data (and stack) selector.
pub const KERNEL_DS: u16 = 0x10;
/// User data (and stack) selector, RPL 3.
pub const USER_DS: u16 = 0x18 | 3;
/// User 64-bit code selector, RPL 3.
pub const USER_CS: u16 = 0x20 | 3;
/// The TSS selector (a 16-byte system descriptor: two GDT slots).
pub const TSS_SEL: u16 = 0x28;

/// GDT slots: null, kcode, kdata, udata, ucode, TSS low, TSS high.
pub const GDT_ENTRIES: usize = 7;

/// `IA32_STAR`: kernel CS for `syscall` in bits 47:32, the `sysret` base in
/// 63:48 (user SS = base + 8, user CS = base + 16, both with RPL 3).
pub const STAR: u64 = ((KERNEL_CS as u64) << 32) | (((USER_DS - 8) as u64) << 48);

// The `sysret` arithmetic, checked against the table above.
const _: () = assert!((USER_DS - 8) + 8 == USER_DS);
const _: () = assert!((USER_DS - 8) + 16 == USER_CS);
const _: () = assert!(KERNEL_CS + 8 == KERNEL_DS);

/// Access byte bits (descriptor bits 47:40).
const ACC_PRESENT: u64 = 1 << 7;
const ACC_CODE_DATA: u64 = 1 << 4; // S: code/data, not system
const ACC_EXEC: u64 = 1 << 3;
const ACC_RW: u64 = 1 << 1; // readable code / writable data
/// Accessed, preset: the CPU would otherwise write it into the GDT on the
/// first load of each selector.
const ACC_ACCESSED: u64 = 1;
/// Flags nibble (descriptor bits 55:52): L (64-bit code), D/B (32-bit
/// default size: data only; with L it is reserved) and G.
const FLAG_LONG: u64 = 1 << 1;
const FLAG_DB: u64 = 1 << 2;
const FLAG_GRAN: u64 = 1 << 3;

/// System descriptor type: available 64-bit TSS.
const TYPE_TSS_AVAILABLE: u64 = 0x9;

/// Pack a code/data segment descriptor. `base` and `limit` are ignored in
/// long mode but kept flat (0, 4 GiB) so a debugger reads sane values: the
/// result is bit for bit Linux's `GDT_ENTRY_INIT` for the same segment.
pub const fn segment(exec: bool, dpl: u8) -> u64 {
    let mut access = ACC_PRESENT | ACC_CODE_DATA | ACC_RW | ACC_ACCESSED | (((dpl & 3) as u64) << 5);
    let flags = if exec {
        access |= ACC_EXEC;
        FLAG_GRAN | FLAG_LONG
    } else {
        FLAG_GRAN | FLAG_DB
    };
    let limit: u64 = 0xF_FFFF;
    (limit & 0xFFFF) | (access << 40) | (((limit >> 16) & 0xF) << 48) | (flags << 52)
}

/// The two 8-byte halves of a 64-bit TSS descriptor for a TSS at `base`
/// with byte limit `limit` (size - 1).
pub const fn tss_descriptor(base: u64, limit: u32) -> [u64; 2] {
    let limit = limit as u64;
    let low = (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | ((ACC_PRESENT | TYPE_TSS_AVAILABLE) << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    [low, base >> 32]
}

/// The whole table for one CPU, with its TSS at `tss_base`.
pub const fn table(tss_base: u64) -> [u64; GDT_ENTRIES] {
    let tss = tss_descriptor(tss_base, (core::mem::size_of::<Tss>() - 1) as u32);
    [0, segment(true, 0), segment(false, 0), segment(false, 3), segment(true, 3), tss[0], tss[1]]
}

/// Number of IST slots in the TSS (IST1..IST7; an IDT gate's IST field 0
/// means "no stack switch").
pub const IST_SLOTS: usize = 7;

/// The 64-bit Task State Segment. Only RSP0 (the ring-3 -> ring-0 stack)
/// and the IST stacks matter; the I/O bitmap offset points past the limit,
/// so every port access from ring 3 faults (#GP).
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug)]
pub struct Tss {
    _reserved0: u32,
    /// RSP0..RSP2: the stack loaded on a privilege change to ring 0..2.
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// IST1..IST7.
    pub ist: [u64; IST_SLOTS],
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of the I/O permission bitmap from the TSS base.
    pub iomap_base: u16,
}

const _: () = assert!(core::mem::size_of::<Tss>() == 104);
const _: () = assert!(core::mem::offset_of!(Tss, rsp) == 4);
const _: () = assert!(core::mem::offset_of!(Tss, ist) == 36);
const _: () = assert!(core::mem::offset_of!(Tss, iomap_base) == 102);

/// Byte offset of RSP0 inside the TSS (`trap_entry.S` writes it on every
/// return to ring 3).
pub const TSS_RSP0: usize = core::mem::offset_of!(Tss, rsp);

impl Tss {
    /// All stacks zero, no I/O bitmap.
    pub const fn new() -> Self {
        Tss {
            _reserved0: 0,
            rsp: [0; 3],
            _reserved1: 0,
            ist: [0; IST_SLOTS],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: core::mem::size_of::<Tss>() as u16,
        }
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

/// The `lgdt`/`lidt` operand: a 16-bit limit and a 64-bit linear base.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct DescriptorPointer {
    pub limit: u16,
    pub base: u64,
}

const _: () = assert!(core::mem::size_of::<DescriptorPointer>() == 10);
