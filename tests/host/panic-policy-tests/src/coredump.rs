// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The core file of a killed ring-3 task (`crates/core/recovery/src/coredump.rs`,
//! the real source pulled with `#[path]`): an ELF64 core with the registers in
//! `NT_PRSTATUS`, the writable runs as `PT_LOAD`, the stack run first and from
//! the stack pointer's page, and the budget honoured to the byte.

#[allow(dead_code)]
#[path = "../../../../crates/core/recovery/src/coredump.rs"]
mod core_elf;

use core_elf::{encode, Refused, Run, Task};

fn u16at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The task's memory: byte `i` of the run starting at `base` is `i as u8 ^ tag`.
fn mem(addr: u64, buf: &mut [u8]) -> usize {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (addr as usize + i) as u8;
    }
    buf.len()
}

const TEXT: Run = Run { start: 0x1_0000, end: 0x1_4000, write: false };
const DATA: Run = Run { start: 0x2_0000, end: 0x2_2000, write: true };
const STACK: Run = Run { start: 0x7fff_0000, end: 0x8000_0000, write: true };

fn task(regs: &[u64]) -> Task<'_> {
    Task { machine: core_elf::EM_AARCH64, tid: 7, status: 11, name: b"CRASHER.ELF", image: [0x5a; 32], sp: 0x7fff_8123, regs }
}

/// The program headers of a core file: `(type, offset, vaddr, filesz)`.
fn phdrs(f: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let n = u16at(f, 56) as usize;
    (0..n)
        .map(|i| {
            let p = 64 + 56 * i;
            (u32at(f, p), u64at(f, p + 8), u64at(f, p + 16), u64at(f, p + 32))
        })
        .collect()
}

#[test]
fn a_core_names_its_machine_registers_and_image() {
    let regs: Vec<u64> = (0..34).map(|i| 0x100 + i).collect();
    let mut out = vec![0u8; 1 << 16];
    let w = encode(&task(&regs), &[TEXT, DATA, STACK], &mut out, mem).unwrap();
    let f = &out[..w.len];
    assert_eq!(&f[..4], b"\x7fELF");
    assert_eq!(u16at(f, 16), 4, "ET_CORE");
    assert_eq!(u16at(f, 18), core_elf::EM_AARCH64);
    let ph = phdrs(f);
    assert_eq!(ph[0].0, 4, "PT_NOTE first");
    let note = &f[ph[0].1 as usize..(ph[0].1 + ph[0].3) as usize];
    assert_eq!(u32at(note, 8), 1, "NT_PRSTATUS");
    assert_eq!(&note[12..17], b"CORE\0");
    let desc = 12 + 8;
    assert_eq!(u32at(note, desc + 32), 7, "pr_pid");
    assert_eq!(u64at(note, desc + 112), 0x100, "the first register");
    assert_eq!(u64at(note, desc + 112 + 33 * 8), 0x100 + 33, "the last register");
    assert!(f.windows(32).any(|w| w == [0x5a; 32]), "the image digest is in an AzOS note");
    assert!(f.windows(11).any(|w| w == b"CRASHER.ELF"), "the name is in the process note");
}

#[test]
fn only_writable_runs_are_dumped_and_the_stack_goes_first_from_its_page() {
    let regs = [0u64; 34];
    let mut out = vec![0u8; 1 << 20];
    let w = encode(&task(&regs), &[TEXT, DATA, STACK], &mut out, mem).unwrap();
    let f = &out[..w.len];
    let loads: Vec<_> = phdrs(f).into_iter().filter(|p| p.0 == 1).collect();
    assert_eq!(loads.len(), 2, "the code run is left out");
    assert_eq!(loads[0].2, 0x7fff_8000, "the stack run starts at the stack pointer's page");
    assert_eq!(loads[0].3, 0x8000_0000 - 0x7fff_8000);
    assert_eq!(loads[1].2, DATA.start);
    // The bytes are the task's: byte at vaddr 0x20010 is its low address byte.
    let at = loads[1].1 as usize + 0x10;
    assert_eq!(f[at], 0x10);
    assert_eq!(w.dropped, 0);
}

#[test]
fn the_budget_is_kept_to_the_byte_and_the_loss_is_counted() {
    let regs = [0u64; 34];
    let mut big = vec![0u8; 1 << 20];
    let all = encode(&task(&regs), &[DATA, STACK], &mut big, mem).unwrap();
    let mut small = vec![0u8; all.len - 5000];
    let w = encode(&task(&regs), &[DATA, STACK], &mut small, mem).unwrap();
    assert!(w.len <= small.len(), "the file fits its budget");
    assert_eq!(w.len, small.len(), "and uses all of it");
    assert_eq!(w.dropped, 5000, "what did not fit is what is counted");
}

#[test]
fn a_budget_below_the_headers_is_refused() {
    let regs = [0u64; 34];
    let mut out = vec![0u8; 300];
    assert_eq!(encode(&task(&regs), &[DATA], &mut out, mem), Err(Refused::Budget));
}

#[test]
fn a_run_the_reader_cannot_read_is_a_segment_without_bytes() {
    let regs = [0u64; 34];
    let mut out = vec![0u8; 1 << 16];
    let w = encode(&task(&regs), &[DATA], &mut out, |_, _| 0).unwrap();
    let loads: Vec<_> = phdrs(&out[..w.len]).into_iter().filter(|p| p.0 == 1).collect();
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0].3, 0);
    assert_eq!(w.dropped, 0x2000);
}
