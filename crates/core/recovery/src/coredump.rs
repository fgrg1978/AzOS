// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The core file of a ring-3 task that a fault killed (Kconfig
//! `CRASHDUMP_CORE_KB`): an ELF64 core a debugger opens next to the task's
//! image, with the task's writable memory in the segments the byte budget
//! allows. The minidump (`crashdump.rs`) stays the record `why crash` reads;
//! this is the file `gdb` and `lldb` read.
//!
//! ```text
//!   ELF header (ET_CORE)      64
//!   program headers          56 each: PT_NOTE, then one PT_LOAD per writable run
//!   notes                     NT_PRSTATUS (the registers), NT_PRPSINFO (the
//!                             name), and an "AzOS" note holding the image's
//!                             SHA-256, the key of its symbol file
//!   segment bytes             the pages of each run that are resident
//! ```
//!
//! Only writable runs are dumped: the code and read-only data of the image
//! are in the file the debugger is given, so a dump of them would be the
//! same bytes twice. The run holding the stack pointer is dumped first and
//! from the stack pointer's page up, the rest in address order; what the
//! budget does not hold is counted in [`Written::dropped`], and a segment
//! holds only the resident pages from its start (`p_memsz == p_filesz`: a
//! page nobody touched is absent, not zero).
//!
//! The kernel fills the register array in the order of the ISA's
//! `user_regs_struct` (what `NT_PRSTATUS` carries on Linux, which is what the
//! debuggers decode): riscv64 `pc x1..x31`, aarch64 `x0..x30 sp pc pstate`,
//! x86_64 `r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax
//! rip cs eflags rsp ss fs_base gs_base ds es fs gs`.
//!
//! Depends on `core` only; the kernel encodes with it and the host tests run
//! it unchanged.

pub const EM_RISCV: u16 = 243;
pub const EM_AARCH64: u16 = 183;
pub const EM_X86_64: u16 = 62;

const EHDR: usize = 64;
const PHDR: usize = 56;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PF_R: u32 = 4;
const PF_W: u32 = 2;
const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
/// The vendor note's type: the image digest.
pub const NT_AZOS_IMAGE: u32 = 1;
/// `elf_prstatus` before `pr_reg`.
const PRSTATUS_HEAD: usize = 112;
/// `elf_prpsinfo`.
const PRPSINFO_BYTES: usize = 136;
const PAGE: u64 = 4096;

/// Most runs the encoder takes (the program header table is sized by it).
pub const MAX_RUNS: usize = 48;
/// Most registers (`pr_reg` of the widest ISA, aarch64: 34).
pub const MAX_REGS: usize = 34;

/// Longest [`slot_rel`] name.
pub const REL_MAX: usize = 16;

/// The name of core file slot `slot` (`0..16`) relative to the Domain's tree:
/// `CORE3.ELF`, an 8.3 name the FAT32 volume takes, next to the `CRASHn.DMP`
/// ring of the minidump.
pub fn slot_rel(slot: usize, out: &mut [u8; REL_MAX]) -> usize {
    let d = b"0123456789abcdef"[slot % 16];
    let name = [b'C', b'O', b'R', b'E', d, b'.', b'E', b'L', b'F'];
    out[..name.len()].copy_from_slice(&name);
    name.len()
}

/// One mapped run of the task, as `vmm::user_runs` reports it.
#[derive(Clone, Copy, Default)]
pub struct Run {
    pub start: u64,
    pub end: u64,
    pub write: bool,
}

/// What the file is about.
pub struct Task<'a> {
    pub machine: u16,
    pub tid: u32,
    /// The signal-like status the task was killed with.
    pub status: i32,
    pub name: &'a [u8],
    /// SHA-256 of the task's image.
    pub image: [u8; 32],
    pub sp: u64,
    /// `pr_reg`, in the order above.
    pub regs: &'a [u64],
}

/// Why no file was made.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The budget does not hold the headers and notes.
    Budget,
    /// Too many registers or runs for the layout.
    Shape,
}

/// What [`encode`] made.
#[derive(Debug, PartialEq, Eq)]
pub struct Written {
    /// Bytes of the file.
    pub len: usize,
    /// Segments in it.
    pub segments: usize,
    /// Bytes of writable runs left out (budget) or absent (not resident).
    pub dropped: u64,
}

fn put16(out: &mut [u8], at: usize, v: u16) {
    out[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(out: &mut [u8], at: usize, v: u64) {
    out[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// A note's size: header, name, descriptor, each padded to 4.
const fn note_bytes(name: usize, desc: usize) -> usize {
    12 + ((name + 3) & !3) + ((desc + 3) & !3)
}

fn put_note(out: &mut [u8], at: usize, name: &[u8], ty: u32, desc: usize) -> usize {
    put32(out, at, name.len() as u32);
    put32(out, at + 4, desc as u32);
    put32(out, at + 8, ty);
    out[at + 12..at + 12 + name.len()].copy_from_slice(name);
    at + 12 + pad4(name.len())
}

/// The runs worth dumping, in dump order: the writable run holding `sp`
/// first (from `sp`'s page), then the others by address. Returns how many of
/// `plan` are filled; `(start, end)` of each.
fn plan(runs: &[Run], sp: u64, plan: &mut [(u64, u64); MAX_RUNS]) -> usize {
    let mut n = 0;
    let stack = runs.iter().position(|r| r.write && r.start <= sp && sp < r.end);
    if let Some(i) = stack {
        plan[n] = (runs[i].start.max(sp & !(PAGE - 1)), runs[i].end);
        n += 1;
    }
    for (i, r) in runs.iter().enumerate() {
        if r.write && Some(i) != stack && r.end > r.start {
            plan[n] = (r.start, r.end);
            n += 1;
        }
    }
    n
}

/// Make the core file of `task` into `out`, at most `out.len()` bytes.
/// `runs` are the task's runs; `read(addr, buf)` fills `buf` from the task's
/// memory as far as it is resident and returns how many bytes (it never
/// commits a page).
pub fn encode(
    task: &Task,
    runs: &[Run],
    out: &mut [u8],
    mut read: impl FnMut(u64, &mut [u8]) -> usize,
) -> Result<Written, Refused> {
    if task.regs.len() > MAX_REGS || runs.len() > MAX_RUNS {
        return Err(Refused::Shape);
    }
    let mut chosen = [(0u64, 0u64); MAX_RUNS];
    let k = plan(runs, task.sp, &mut chosen);
    let prstatus = PRSTATUS_HEAD + task.regs.len() * 8 + 8;
    let notes = note_bytes(5, prstatus) + note_bytes(5, PRPSINFO_BYTES) + note_bytes(5, 32);
    let phnum = 1 + k;
    let notes_at = EHDR + phnum * PHDR;
    let mut at = notes_at + notes;
    if at > out.len() {
        return Err(Refused::Budget);
    }
    out[..at].fill(0);
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    put16(out, 16, ET_CORE);
    put16(out, 18, task.machine);
    put32(out, 20, 1);
    put64(out, 32, EHDR as u64);
    put16(out, 52, EHDR as u16);
    put16(out, 54, PHDR as u16);
    put16(out, 56, phnum as u16);

    let ph = EHDR;
    put32(out, ph, PT_NOTE);
    put64(out, ph + 8, notes_at as u64);
    put64(out, ph + 32, notes as u64);
    put64(out, ph + 40, notes as u64);
    put64(out, ph + 48, 4);

    let mut n = notes_at;
    let d = put_note(out, n, b"CORE\0", NT_PRSTATUS, prstatus);
    put32(out, d, task.status as u32 & 0x7f);
    put16(out, d + 12, task.status as u16 & 0x7f);
    put32(out, d + 32, task.tid);
    put32(out, d + 36, 0);
    put32(out, d + 40, task.tid);
    put32(out, d + 44, task.tid);
    for (i, r) in task.regs.iter().enumerate() {
        put64(out, d + PRSTATUS_HEAD + i * 8, *r);
    }
    n = d + ((prstatus + 3) & !3);
    let d = put_note(out, n, b"CORE\0", NT_PRPSINFO, PRPSINFO_BYTES);
    out[d + 1] = b'R';
    put32(out, d + 24, task.tid);
    let name = &task.name[..task.name.len().min(15)];
    out[d + 40..d + 40 + name.len()].copy_from_slice(name);
    n = d + PRPSINFO_BYTES;
    let d = put_note(out, n, b"AzOS\0", NT_AZOS_IMAGE, 32);
    out[d..d + 32].copy_from_slice(&task.image);

    let mut dropped: u64 = 0;
    for i in 0..k {
        let (start, end) = chosen[i];
        let want = (end - start) as usize;
        let room = out.len() - at;
        let take = want.min(room);
        let got = read(start, &mut out[at..at + take]);
        let p = EHDR + (1 + i) * PHDR;
        put32(out, p, PT_LOAD);
        put32(out, p + 4, PF_R | PF_W);
        put64(out, p + 8, at as u64);
        put64(out, p + 16, start);
        put64(out, p + 24, 0);
        put64(out, p + 32, got as u64);
        put64(out, p + 40, got as u64);
        put64(out, p + 48, 1);
        at += got;
        dropped += (want - got) as u64;
    }
    // The part of the stack run below the stack pointer's page is not in
    // `chosen`; it is not counted as dropped (the red zone is one page).
    Ok(Written { len: at, segments: k, dropped })
}
