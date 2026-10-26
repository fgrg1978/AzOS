// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The minidump of a ring-3 task that a fault killed: its layout, its bounds,
//! the file slots it is written to and the report `why crash` prints.
//!
//! **What is in a dump.** The registers of the trap, a bounded window of the
//! stack from the stack pointer up, the task's maps (runs of mapped pages and
//! their permissions: the executable run holding `pc` gives the image's load
//! address, which is what turns `pc` into a symbol), the last decision
//! records of the kernel (`crates/core/decision`: why the kernel refused or
//! denied what it did just before) and the SHA-256 of the task's image, the
//! key the symbol file of that exact build is stored under. A kernel panic is
//! not a dump: it keeps `/fat/CRASH.LOG` (`crates/fs/src/crash_log.rs`).
//!
//! **Where it goes.** The Log and a file (owner decision 16-10). The Log: a
//! record of task and status on the flight recorder's ring, and the dump
//! itself in the crash ring in the kernel (`kernel/src/trap/crash.rs`, left at
//! once, with no I/O on the fault path). The file: beneath the faulting
//! Domain's `Cap<Dir>` (never a global path): the ring's drain writes
//! [`slot_rel`] into the root of the first write tree the Domain holds. The
//! files are a ring of [`slot_rel`] names, so a crash loop cannot fill the
//! volume: the oldest slot is rewritten ([`next_slot`]). They sit in the
//! tree's root, not in a directory of their own, because the FAT32 backend
//! of the VFS names root-directory files only (`Fat32Fs::key_for`).
//!
//! **Why this file names nothing but `core`.** The kernel encodes with it,
//! `userspace/services/why` decodes and prints with it (`#[path]`, the same
//! source, so the tool cannot drift from the writer), and the host tests run
//! it unchanged (`tests/host/{panic-policy,regression}-tests`).
//!
//! **Layout** (little endian; every offset is a multiple of 4, every section
//! of 8):
//!
//! ```text
//!   0  magic "AZCD"        4  version u16        6  isa u8      7  nregs u8
//!   8  length u32 (the whole dump)              12  serial u32 (the file ring's, not in the CRC)
//!  16  crc32 u32 of bytes 20..length            20  tid u32     24  status i32
//!  28  cause u32           32  cpu u32          36  stack bytes u32
//!  40  maps u16  42  maps_total u16  44  decisions u16  46  pad u16
//!  48  ticks u64           56  pc u64           64  sp u64
//!  72  fault address u64   80  stack base u64   88  image sha256 [32]
//! 120  task name [32]     152  registers  nregs x u64
//!      maps       n x 24   (start u64, end u64, flags u32, pad u32)
//!      decisions  n x 48   (seq u64, rule u8, verdict u8, pad u16, subject u32, n0..n2 u64, ts u64)
//!      stack      bytes    (padded to 8)
//! ```

use core::fmt::{self, Write};

/// `"AZCD"`.
pub const MAGIC: [u8; 4] = *b"AZCD";
/// The layout version a reader refuses anything else than.
pub const VERSION: u16 = 1;
/// Bytes before the registers.
pub const HEADER_BYTES: usize = 152;
/// Bytes of the task name field.
pub const NAME_BYTES: usize = 32;

/// Most registers a dump holds (riscv64 32, aarch64 34, x86_64 19).
pub const MAX_REGS: usize = 40;
/// Most map runs a dump holds.
pub const MAX_MAPS: usize = 48;
/// Most decision records a dump holds.
pub const MAX_DECISIONS: usize = 32;
/// Most stack bytes a dump holds.
pub const MAX_STACK: usize = 4096;
/// Most slots of the file ring (a slot's hex digit is its name).
pub const MAX_SLOTS: usize = 16;

const MAP_BYTES: usize = 24;
const DECISION_BYTES: usize = 48;

/// The size of the largest dump for the given bounds: what a ring slot is
/// sized to, and the bound `encode` enforces by construction.
pub const fn max_bytes(stack: usize, maps: usize, decisions: usize) -> usize {
    HEADER_BYTES + MAX_REGS * 8 + maps * MAP_BYTES + decisions * DECISION_BYTES + ((stack + 7) & !7)
}

/// The largest dump any bounds of this layout can make.
pub const MAX_BYTES: usize = max_bytes(MAX_STACK, MAX_MAPS, MAX_DECISIONS);

/// `Map::flags`: readable, writable, executable.
pub const MAP_R: u32 = 1;
pub const MAP_W: u32 = 2;
pub const MAP_X: u32 = 4;

/// The ISA of a dump: the register names and their order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Isa {
    /// `x0..x31` (`x0` is zero), 32 registers.
    Riscv64 = 1,
    /// `x0..x30`, then `sp_el0`, `spsr_el1`, `tpidr_el0`.
    Aarch64 = 2,
    /// `rax rbx rcx rdx rsi rdi rbp r8..r15`, then `rsp rflags fs_base gs_base`.
    X86_64 = 3,
}

impl Isa {
    pub const fn from_raw(v: u8) -> Option<Isa> {
        match v {
            1 => Some(Isa::Riscv64),
            2 => Some(Isa::Aarch64),
            3 => Some(Isa::X86_64),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Isa::Riscv64 => "riscv64",
            Isa::Aarch64 => "aarch64",
            Isa::X86_64 => "x86_64",
        }
    }

    /// The name of register `i` of the dump.
    pub fn reg_name(self, i: usize) -> &'static str {
        const RV: [&str; 32] = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
        ];
        const A64: [&str; 34] = [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
            "x30", "sp_el0", "spsr_el1", "tpidr_el0",
        ];
        const X64: [&str; 19] = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rsp", "rflags", "fs_base", "gs_base",
        ];
        let t: &[&str] = match self {
            Isa::Riscv64 => &RV,
            Isa::Aarch64 => &A64,
            Isa::X86_64 => &X64,
        };
        t.get(i).copied().unwrap_or("?")
    }
}

/// One run of mapped user pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Map {
    pub start: u64,
    /// Exclusive.
    pub end: u64,
    /// [`MAP_R`] | [`MAP_W`] | [`MAP_X`].
    pub flags: u32,
}

/// One decision record (`azos_decision::Record`, the fields a reader needs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decision {
    pub seq: u64,
    pub rule: u8,
    pub verdict: u8,
    pub subject: u32,
    pub n: [u64; 3],
    pub ts: u64,
}

/// What `encode` is given.
#[derive(Clone, Copy, Debug)]
pub struct Dump<'a> {
    pub isa: Isa,
    pub tid: u32,
    /// The exit status the fault killed the task with (`128 + signal`).
    pub status: i32,
    /// The ISA's own cause (`scause`, the ESR exception class, the x86 error code).
    pub cause: u32,
    pub cpu: u32,
    /// The kernel clock, in timebase ticks.
    pub ticks: u64,
    pub pc: u64,
    pub sp: u64,
    pub fault_addr: u64,
    /// SHA-256 of the task's image; all zero when the build's table does not hold it.
    pub image: [u8; 32],
    pub name: &'a [u8],
    pub regs: &'a [u64],
    pub maps: &'a [Map],
    /// How many runs the task had (more than `maps.len()` when the list was cut).
    pub maps_total: u16,
    pub decisions: &'a [Decision],
    /// The VA of `stack[0]`.
    pub stack_base: u64,
    pub stack: &'a [u8],
}

/// Why `encode` or `decode` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `encode`: the output buffer cannot hold the dump.
    TooBig,
    /// `encode`: a section is past its bound ([`MAX_REGS`] ...).
    TooMany,
    /// `decode`: shorter than its header or than its own length field.
    Short,
    /// `decode`: not a dump.
    Magic,
    /// `decode`: another layout version.
    Version,
    /// `decode`: the sections do not add up to the length, or an ISA this reader lacks.
    Layout,
    /// `decode`: the CRC does not match (a write cut short).
    Torn,
}

/// CRC-32 (IEEE 802.3, reflected), bitwise: a dump is small and written once.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

fn put(out: &mut [u8], at: usize, v: &[u8]) {
    out[at..at + v.len()].copy_from_slice(v);
}

fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

/// The size `encode` would write for `d`, or `TooMany` for a section past its bound.
pub fn encoded_len(d: &Dump<'_>) -> Result<usize, Error> {
    if d.regs.len() > MAX_REGS || d.maps.len() > MAX_MAPS || d.decisions.len() > MAX_DECISIONS || d.stack.len() > MAX_STACK {
        return Err(Error::TooMany);
    }
    Ok(HEADER_BYTES + d.regs.len() * 8 + d.maps.len() * MAP_BYTES + d.decisions.len() * DECISION_BYTES
        + ((d.stack.len() + 7) & !7))
}

/// Write `d` to `out`: its length, or why it cannot be. The serial is zero
/// until the file ring stamps it ([`set_serial`]).
pub fn encode(d: &Dump<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(d)?;
    if out.len() < len {
        return Err(Error::TooBig);
    }
    let out = &mut out[..len];
    out.fill(0);
    put(out, 0, &MAGIC);
    put(out, 4, &VERSION.to_le_bytes());
    out[6] = d.isa as u8;
    out[7] = d.regs.len() as u8;
    put(out, 8, &(len as u32).to_le_bytes());
    put(out, 20, &d.tid.to_le_bytes());
    put(out, 24, &d.status.to_le_bytes());
    put(out, 28, &d.cause.to_le_bytes());
    put(out, 32, &d.cpu.to_le_bytes());
    put(out, 36, &(d.stack.len() as u32).to_le_bytes());
    put(out, 40, &(d.maps.len() as u16).to_le_bytes());
    put(out, 42, &d.maps_total.max(d.maps.len() as u16).to_le_bytes());
    put(out, 44, &(d.decisions.len() as u16).to_le_bytes());
    put(out, 48, &d.ticks.to_le_bytes());
    put(out, 56, &d.pc.to_le_bytes());
    put(out, 64, &d.sp.to_le_bytes());
    put(out, 72, &d.fault_addr.to_le_bytes());
    put(out, 80, &d.stack_base.to_le_bytes());
    put(out, 88, &d.image);
    let n = d.name.len().min(NAME_BYTES);
    put(out, 120, &d.name[..n]);
    let mut at = HEADER_BYTES;
    for r in d.regs {
        put(out, at, &r.to_le_bytes());
        at += 8;
    }
    for m in d.maps {
        put(out, at, &m.start.to_le_bytes());
        put(out, at + 8, &m.end.to_le_bytes());
        put(out, at + 16, &m.flags.to_le_bytes());
        at += MAP_BYTES;
    }
    for r in d.decisions {
        put(out, at, &r.seq.to_le_bytes());
        out[at + 8] = r.rule;
        out[at + 9] = r.verdict;
        put(out, at + 12, &r.subject.to_le_bytes());
        put(out, at + 16, &r.n[0].to_le_bytes());
        put(out, at + 24, &r.n[1].to_le_bytes());
        put(out, at + 32, &r.n[2].to_le_bytes());
        put(out, at + 40, &r.ts.to_le_bytes());
        at += DECISION_BYTES;
    }
    put(out, at, d.stack);
    let crc = crc32(&out[20..]);
    put(out, 16, &crc.to_le_bytes());
    Ok(len)
}

/// What a slot scan needs of a file, without checking it whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peek {
    pub serial: u32,
    pub tid: u32,
    pub len: u32,
}

/// The first bytes of a dump file (at least 24): its serial, task and length,
/// or `None` for anything that is not a dump of this version.
pub fn peek(b: &[u8]) -> Option<Peek> {
    if b.len() < 24 || b[..4] != MAGIC || get_u16(b, 4) != VERSION {
        return None;
    }
    Some(Peek { serial: get_u32(b, 12), tid: get_u32(b, 20), len: get_u32(b, 8) })
}

/// Stamp the file ring's serial into an encoded dump (outside the CRC).
pub fn set_serial(dump: &mut [u8], serial: u32) {
    put(dump, 12, &serial.to_le_bytes());
}

/// The dump `b` holds, checked whole.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    b: &'a [u8],
    isa: Isa,
}

/// Parse and verify a dump file (`b` may be longer than the dump).
pub fn decode(b: &[u8]) -> Result<View<'_>, Error> {
    if b.len() < HEADER_BYTES {
        return Err(Error::Short);
    }
    if b[..4] != MAGIC {
        return Err(Error::Magic);
    }
    if get_u16(b, 4) != VERSION {
        return Err(Error::Version);
    }
    let len = get_u32(b, 8) as usize;
    if len < HEADER_BYTES || len > b.len() {
        return Err(Error::Short);
    }
    let b = &b[..len];
    let isa = Isa::from_raw(b[6]).ok_or(Error::Layout)?;
    let (nregs, nmaps, ndec, nstack) = (b[7] as usize, get_u16(b, 40) as usize, get_u16(b, 44) as usize, get_u32(b, 36) as usize);
    if nregs > MAX_REGS || nmaps > MAX_MAPS || ndec > MAX_DECISIONS || nstack > MAX_STACK {
        return Err(Error::Layout);
    }
    if HEADER_BYTES + nregs * 8 + nmaps * MAP_BYTES + ndec * DECISION_BYTES + ((nstack + 7) & !7) != len {
        return Err(Error::Layout);
    }
    if crc32(&b[20..]) != get_u32(b, 16) {
        return Err(Error::Torn);
    }
    Ok(View { b, isa })
}

impl<'a> View<'a> {
    pub fn isa(&self) -> Isa {
        self.isa
    }
    pub fn serial(&self) -> u32 {
        get_u32(self.b, 12)
    }
    pub fn tid(&self) -> u32 {
        get_u32(self.b, 20)
    }
    pub fn status(&self) -> i32 {
        get_u32(self.b, 24) as i32
    }
    pub fn cause(&self) -> u32 {
        get_u32(self.b, 28)
    }
    pub fn cpu(&self) -> u32 {
        get_u32(self.b, 32)
    }
    pub fn ticks(&self) -> u64 {
        get_u64(self.b, 48)
    }
    pub fn pc(&self) -> u64 {
        get_u64(self.b, 56)
    }
    pub fn sp(&self) -> u64 {
        get_u64(self.b, 64)
    }
    pub fn fault_addr(&self) -> u64 {
        get_u64(self.b, 72)
    }
    pub fn stack_base(&self) -> u64 {
        get_u64(self.b, 80)
    }
    pub fn image(&self) -> &'a [u8] {
        &self.b[88..120]
    }
    /// The task name, up to its first NUL.
    pub fn name(&self) -> &'a [u8] {
        let n = &self.b[120..120 + NAME_BYTES];
        &n[..n.iter().position(|&c| c == 0).unwrap_or(NAME_BYTES)]
    }
    pub fn reg_count(&self) -> usize {
        self.b[7] as usize
    }
    pub fn reg(&self, i: usize) -> Option<u64> {
        (i < self.reg_count()).then(|| get_u64(self.b, HEADER_BYTES + i * 8))
    }
    pub fn map_count(&self) -> usize {
        get_u16(self.b, 40) as usize
    }
    /// Runs the task had, more than [`View::map_count`] when the list was cut.
    pub fn maps_total(&self) -> usize {
        get_u16(self.b, 42) as usize
    }
    pub fn map(&self, i: usize) -> Option<Map> {
        (i < self.map_count()).then(|| {
            let at = HEADER_BYTES + self.reg_count() * 8 + i * MAP_BYTES;
            Map { start: get_u64(self.b, at), end: get_u64(self.b, at + 8), flags: get_u32(self.b, at + 16) }
        })
    }
    pub fn decision_count(&self) -> usize {
        get_u16(self.b, 44) as usize
    }
    pub fn decision(&self, i: usize) -> Option<Decision> {
        (i < self.decision_count()).then(|| {
            let at = HEADER_BYTES + self.reg_count() * 8 + self.map_count() * MAP_BYTES + i * DECISION_BYTES;
            Decision {
                seq: get_u64(self.b, at),
                rule: self.b[at + 8],
                verdict: self.b[at + 9],
                subject: get_u32(self.b, at + 12),
                n: [get_u64(self.b, at + 16), get_u64(self.b, at + 24), get_u64(self.b, at + 32)],
                ts: get_u64(self.b, at + 40),
            }
        })
    }
    /// The stack window, from [`View::stack_base`] up.
    pub fn stack(&self) -> &'a [u8] {
        let at = HEADER_BYTES + self.reg_count() * 8 + self.map_count() * MAP_BYTES + self.decision_count() * DECISION_BYTES;
        &self.b[at..at + get_u32(self.b, 36) as usize]
    }
}

/// The name of the signal a kill status (`128 + signal`) stands for.
pub fn signal_name(status: i32) -> &'static str {
    match status - 128 {
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        _ => "signal",
    }
}

/// How the report names the kernel's decision rules and verdicts: the table
/// lives in `crates/core/decision`, which this file does not depend on.
#[derive(Clone, Copy)]
pub struct Names {
    pub rule: fn(u8) -> &'static str,
    pub verdict: fn(u8) -> &'static str,
}

fn hex(out: &mut impl Write, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(out, "{:02x}", b)?;
    }
    Ok(())
}

/// The report `why crash <tid>` prints: one line a fact, registers four to a
/// line, the stack as hex rows, the decisions oldest first.
pub fn write_report(v: &View<'_>, names: &Names, out: &mut impl Write) -> fmt::Result {
    write!(out, "crash dump {} ({}, layout v{})\n", v.serial(), v.isa().name(), VERSION)?;
    write!(out, "task    {} tid {} cpu {} at {} ticks\n", core::str::from_utf8(v.name()).unwrap_or("?"), v.tid(), v.cpu(), v.ticks())?;
    write!(out, "killed  {} (status {}), cause {:#x}, fault address {:#x}\n", signal_name(v.status()), v.status(), v.cause(), v.fault_addr())?;
    write!(out, "pc      {:#x}\nsp      {:#x}\n", v.pc(), v.sp())?;
    if v.image().iter().all(|&b| b == 0) {
        write!(out, "image   unknown (not in this build's table)\n")?;
    } else {
        write!(out, "image   sha256 ")?;
        hex(out, v.image())?;
        write!(out, "\n")?;
    }
    // The run holding the pc: the image's mapping, the base `pc` is an offset from.
    for i in 0..v.map_count() {
        if let Some(m) = v.map(i) {
            if m.flags & MAP_X != 0 && (m.start..m.end).contains(&v.pc()) {
                write!(out, "pc in   {:#x}-{:#x} (+{:#x})\n", m.start, m.end, v.pc() - m.start)?;
            }
        }
    }
    write!(out, "registers\n")?;
    for i in 0..v.reg_count() {
        if let Some(r) = v.reg(i) {
            write!(out, "  {:<9} {:#018x}{}", v.isa().reg_name(i), r, if i % 4 == 3 || i + 1 == v.reg_count() { "\n" } else { "" })?;
        }
    }
    write!(out, "maps ({} of {})\n", v.map_count(), v.maps_total())?;
    for i in 0..v.map_count() {
        if let Some(m) = v.map(i) {
            let f = |bit: u32, c: char| if m.flags & bit != 0 { c } else { '-' };
            write!(out, "  {:#018x}-{:#018x} {}{}{}\n", m.start, m.end, f(MAP_R, 'r'), f(MAP_W, 'w'), f(MAP_X, 'x'))?;
        }
    }
    let s = v.stack();
    write!(out, "stack at {:#x} ({} bytes)\n", v.stack_base(), s.len())?;
    for (row, chunk) in s.chunks(16).enumerate() {
        write!(out, "  {:#x}: ", v.stack_base() + (row * 16) as u64)?;
        hex(out, chunk)?;
        write!(out, "\n")?;
    }
    write!(out, "decisions (last {}, oldest first)\n", v.decision_count())?;
    for i in 0..v.decision_count() {
        if let Some(d) = v.decision(i) {
            write!(out, "  #{} {} {} subject {} [{}, {}, {}]\n", d.seq, (names.rule)(d.rule), (names.verdict)(d.verdict), d.subject, d.n[0], d.n[1], d.n[2])?;
        }
    }
    Ok(())
}

/// The one line of a dump in a listing: `why crash` with no task.
pub fn write_line(v: &View<'_>, out: &mut impl Write) -> fmt::Result {
    write!(out, "dump {} tid {} {} {} pc {:#x} at {} ticks\n",
        v.serial(), v.tid(), core::str::from_utf8(v.name()).unwrap_or("?"), signal_name(v.status()), v.pc(), v.ticks())
}

// ── The file ring ────────────────────────────────────────────────────────────

/// Longest [`slot_rel`] name.
pub const REL_MAX: usize = 16;

/// The name of file slot `slot` (`0..MAX_SLOTS`) relative to the Domain's tree:
/// `CRASH3.DMP`, an 8.3 name the FAT32 volume takes. The same name opens it
/// for reading beneath any `Cap<Dir>` that holds the tree.
pub fn slot_rel(slot: usize, out: &mut [u8; REL_MAX]) -> usize {
    let d = b"0123456789abcdef"[slot % MAX_SLOTS];
    let name = [b'C', b'R', b'A', b'S', b'H', d, b'.', b'D', b'M', b'P'];
    out[..name.len()].copy_from_slice(&name);
    name.len()
}

/// The directories, relative to the root `/`, that a Domain's write tree can
/// be in the topologies (`/fat`, `/tmp` and the installer's `/fat/PKG`): where
/// a reader holding the root directory looks for dumps. The kernel writes in
/// the root of whichever write tree the Domain's row holds, so a read-write
/// tree the topology (`crates/core/topology/src/builder.rs`) adds is added here.
pub const DUMP_DIRS: [&str; 3] = ["fat", "tmp", "fat/PKG"];

/// Longest [`slot_path`] (a [`DUMP_DIRS`] entry, `/`, a [`slot_rel`] name) and
/// the NUL that ends it.
pub const PATH_MAX: usize = 16 + 1 + REL_MAX + 1;

/// The NUL-terminated name of file slot `slot` in `dir` (a [`DUMP_DIRS`]
/// entry), relative to the root directory: `fat/CRASH3.DMP`. How many bytes,
/// the NUL not counted.
pub fn slot_path(dir: &str, slot: usize, out: &mut [u8; PATH_MAX]) -> usize {
    let d = dir.as_bytes();
    out[..d.len()].copy_from_slice(d);
    out[d.len()] = b'/';
    let mut rel = [0u8; REL_MAX];
    let k = slot_rel(slot, &mut rel);
    let n = d.len() + 1 + k;
    out[d.len() + 1..n].copy_from_slice(&rel[..k]);
    out[n] = 0;
    n
}

/// Which slot the next dump takes and the serial it gets: `serials[i]` is the
/// serial of slot `i`'s dump, `None` for an empty or unreadable slot. An empty
/// slot first, else the oldest (serials compare modulo 2^32); the new serial
/// follows the newest, so the order survives a reboot.
pub fn next_slot(serials: &[Option<u32>]) -> (usize, u32) {
    if serials.is_empty() {
        return (0, 1);
    }
    let newest = serials.iter().flatten().copied().reduce(|a, b| if b.wrapping_sub(a) as i32 > 0 { b } else { a });
    let serial = newest.map_or(1, |n| n.wrapping_add(1));
    if let Some(i) = serials.iter().position(|s| s.is_none()) {
        return (i, serial);
    }
    let oldest = serials.iter().enumerate().fold((0usize, serials[0].unwrap_or(0)), |(bi, bs), (i, s)| {
        let s = s.unwrap_or(0);
        if bs.wrapping_sub(s) as i32 > 0 { (i, s) } else { (bi, bs) }
    });
    (oldest.0, serial)
}
