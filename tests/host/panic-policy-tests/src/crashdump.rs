// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The crash dump's layout and bounds (`crates/core/recovery/src/crashdump.rs`,
//! the real source pulled with `#[path]`): what a dump holds, that it cannot
//! outgrow its bound, that a cut or altered file is refused, and that the file
//! ring turns over in order.

#[allow(dead_code)]
#[path = "../../../../crates/core/recovery/src/crashdump.rs"]
mod cd;

use cd::{Decision, Dump, Error, Isa, Map};

fn dump<'a>(regs: &'a [u64], maps: &'a [Map], decs: &'a [Decision], stack: &'a [u8]) -> Dump<'a> {
    Dump {
        isa: Isa::Riscv64,
        tid: 12,
        status: 139,
        cause: 13,
        cpu: 1,
        ticks: 123_456,
        pc: 0x1_0040,
        sp: 0x7fff_f000,
        fault_addr: 0x10,
        image: [0xAB; 32],
        name: b"WHY.ELF",
        regs,
        maps,
        maps_total: maps.len() as u16,
        decisions: decs,
        stack_base: 0x7fff_f000,
        stack,
    }
}

fn sample() -> (Vec<u64>, Vec<Map>, Vec<Decision>, Vec<u8>) {
    let regs: Vec<u64> = (0..32).map(|i| 0x1000 + i).collect();
    let maps = vec![
        Map { start: 0x1_0000, end: 0x1_4000, flags: cd::MAP_R | cd::MAP_X },
        Map { start: 0x7fff_e000, end: 0x8000_0000, flags: cd::MAP_R | cd::MAP_W },
    ];
    let decs = vec![
        Decision { seq: 7, rule: 1, verdict: 3, subject: 12, n: [1, 2, 3], ts: 99 },
        Decision { seq: 8, rule: 2, verdict: 0, subject: 13, n: [4, 5, 6], ts: 100 },
    ];
    let stack: Vec<u8> = (0..37u8).collect();
    (regs, maps, decs, stack)
}

fn encoded() -> Vec<u8> {
    let (r, m, d, s) = sample();
    let mut out = vec![0u8; cd::MAX_BYTES];
    let n = cd::encode(&dump(&r, &m, &d, &s), &mut out).unwrap();
    out.truncate(n);
    out
}

/// **Every field survives the round trip**, registers, maps, decisions and the
/// stack window included, and the stack's odd length is not padded into the
/// data.
///
/// **Canary.** Write the maps one entry short: `maps.len()` differs.
#[test]
fn the_dump_round_trips() {
    let (r, m, d, s) = sample();
    let bytes = encoded();
    let v = cd::decode(&bytes).unwrap();
    assert_eq!((v.isa(), v.tid(), v.status(), v.cause(), v.cpu(), v.ticks()), (Isa::Riscv64, 12, 139, 13, 1, 123_456));
    assert_eq!((v.pc(), v.sp(), v.fault_addr(), v.stack_base()), (0x1_0040, 0x7fff_f000, 0x10, 0x7fff_f000));
    assert_eq!(v.image(), &[0xAB; 32][..]);
    assert_eq!(v.name(), b"WHY.ELF");
    assert_eq!(v.reg_count(), 32);
    assert!((0..32).all(|i| v.reg(i) == Some(r[i])));
    assert_eq!(v.reg(32), None);
    assert_eq!((v.map_count(), v.maps_total()), (2, 2));
    assert_eq!([v.map(0).unwrap(), v.map(1).unwrap()], [m[0], m[1]]);
    assert_eq!(v.map(2), None);
    assert_eq!(v.decision_count(), 2);
    assert_eq!([v.decision(0).unwrap(), v.decision(1).unwrap()], [d[0], d[1]]);
    assert_eq!(v.stack(), &s[..]);
}

/// **The size is exactly what `encoded_len` says, a multiple of 8, and never
/// above `MAX_BYTES`**, even for the fullest dump the layout allows; no
/// section may pass its bound.
///
/// **Canary.** Let `MAX_STACK` grow without `MAX_BYTES`: the full dump
/// overruns the bound and `encode` panics on the slice.
#[test]
fn a_dump_cannot_outgrow_its_bound() {
    let regs = [1u64; cd::MAX_REGS];
    let maps = [Map { start: 1, end: 2, flags: 1 }; cd::MAX_MAPS];
    let decs = [Decision::default(); cd::MAX_DECISIONS];
    let stack = [7u8; cd::MAX_STACK];
    let d = dump(&regs, &maps, &decs, &stack);
    assert_eq!(cd::encoded_len(&d), Ok(cd::MAX_BYTES));
    let mut out = vec![0u8; cd::MAX_BYTES];
    assert_eq!(cd::encode(&d, &mut out), Ok(cd::MAX_BYTES));
    assert_eq!(cd::MAX_BYTES % 8, 0);
    assert!(cd::decode(&out).is_ok());
    // A smaller bound is a smaller slot: the kernel sizes its ring slots by it.
    assert_eq!(cd::max_bytes(1024, 24, 16), cd::HEADER_BYTES + cd::MAX_REGS * 8 + 24 * 24 + 16 * 48 + 1024);
    let (r, m, ds, s) = sample();
    let small = dump(&r, &m, &ds, &s);
    assert!(cd::encoded_len(&small).unwrap() <= cd::max_bytes(64, 4, 2));
}

/// **A section past its bound is refused whole, and a buffer too small is
/// refused, never written short.**
///
/// **Canary.** Drop the `TooMany` check: 41 registers write over the maps.
#[test]
fn an_oversize_dump_is_refused() {
    let (r, m, d, s) = sample();
    let mut out = vec![0u8; cd::MAX_BYTES];
    let too_many_regs = [0u64; cd::MAX_REGS + 1];
    assert_eq!(cd::encode(&dump(&too_many_regs, &m, &d, &s), &mut out), Err(Error::TooMany));
    let big_stack = vec![0u8; cd::MAX_STACK + 1];
    assert_eq!(cd::encode(&dump(&r, &m, &d, &big_stack), &mut out), Err(Error::TooMany));
    let mut tiny = [0u8; 64];
    assert_eq!(cd::encode(&dump(&r, &m, &d, &s), &mut tiny), Err(Error::TooBig));
    assert!(tiny.iter().all(|&b| b == 0), "a refused dump writes nothing");
}

/// **A long task name is cut to its field, not into the registers.**
#[test]
fn a_long_name_is_cut() {
    let (r, m, d, s) = sample();
    let long = [b'N'; 64];
    let mut x = dump(&r, &m, &d, &s);
    x.name = &long;
    let mut out = vec![0u8; cd::MAX_BYTES];
    let n = cd::encode(&x, &mut out).unwrap();
    let v = cd::decode(&out[..n]).unwrap();
    assert_eq!(v.name().len(), cd::NAME_BYTES);
    assert_eq!(v.reg(0), Some(0x1000));
}

/// **A file cut short, altered, of another layout or not a dump is refused
/// with the reason**; a longer file (a slot rewritten by a shorter dump) reads
/// as its own length.
///
/// **Canary.** Skip the CRC: the flipped stack byte decodes.
#[test]
fn a_damaged_dump_is_refused() {
    let good = encoded();
    assert!(cd::decode(&good).is_ok());
    let mut longer = good.clone();
    longer.extend_from_slice(&[0xEE; 100]);
    assert!(cd::decode(&longer).is_ok(), "trailing bytes of an older, longer dump are not the dump");
    assert_eq!(cd::decode(&good[..good.len() - 1]).err(), Some(Error::Short));
    assert_eq!(cd::decode(&good[..10]).err(), Some(Error::Short));
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(cd::decode(&flipped).err(), Some(Error::Torn));
    let mut magic = good.clone();
    magic[0] = b'X';
    assert_eq!(cd::decode(&magic).err(), Some(Error::Magic));
    let mut version = good.clone();
    version[4] = 2;
    assert_eq!(cd::decode(&version).err(), Some(Error::Version));
    let mut layout = good.clone();
    layout[7] = 33;
    assert_eq!(cd::decode(&layout).err(), Some(Error::Layout));
    let mut isa = good.clone();
    isa[6] = 9;
    assert_eq!(cd::decode(&isa).err(), Some(Error::Layout));
}

/// **The file ring's serial is stamped after the dump is encoded and is not
/// part of its CRC**; `peek` reads it, and the task, from the first bytes.
#[test]
fn the_serial_is_stamped_outside_the_crc() {
    let mut b = encoded();
    assert_eq!(cd::peek(&b).unwrap().serial, 0);
    cd::set_serial(&mut b, 41);
    let v = cd::decode(&b).expect("a stamped dump still verifies");
    assert_eq!(v.serial(), 41);
    let p = cd::peek(&b[..24]).unwrap();
    assert_eq!((p.serial, p.tid, p.len as usize), (41, 12, b.len()));
    assert_eq!(cd::peek(&b[..23]), None);
    assert_eq!(cd::peek(b"not a dump at all, no, not at all"), None);
}

/// **The file ring takes an empty slot first, then the oldest, and the next
/// serial follows the newest, across a reboot and across the 32-bit wrap.**
///
/// **Canary.** Compare serials as plain numbers: the wrapped case takes the
/// slot holding the NEWEST dump.
#[test]
fn the_file_ring_turns_over_oldest_first() {
    assert_eq!(cd::next_slot(&[]), (0, 1));
    assert_eq!(cd::next_slot(&[None, None, None]), (0, 1));
    assert_eq!(cd::next_slot(&[Some(1), None, None]), (1, 2));
    assert_eq!(cd::next_slot(&[Some(1), Some(2), None]), (2, 3));
    // Full: the oldest goes.
    assert_eq!(cd::next_slot(&[Some(5), Some(3), Some(4)]), (1, 6));
    assert_eq!(cd::next_slot(&[Some(9), Some(10), Some(8)]), (2, 11));
    // An unreadable slot is an empty one.
    assert_eq!(cd::next_slot(&[Some(5), None, Some(4)]), (1, 6));
    // Across the wrap, 0 is newer than u32::MAX.
    assert_eq!(cd::next_slot(&[Some(u32::MAX), Some(0), Some(u32::MAX - 1)]), (2, 1));
    // Run it for a while: every slot is rewritten in turn, serials strictly rise.
    let mut slots = [None; 4];
    let mut last = 0;
    for step in 0..40u32 {
        let (i, serial) = cd::next_slot(&slots);
        assert_eq!(serial, last + 1);
        if step >= 4 {
            assert_eq!(i, (step % 4) as usize, "oldest first");
        }
        slots[i] = Some(serial);
        last = serial;
    }
}

/// **The slot names are 8.3 names in the tree's root and distinct**, so the
/// FAT32 volume takes them (its VFS names root-directory files only) and a
/// crash loop rewrites a fixed set.
#[test]
fn the_slot_names_are_8_3_and_distinct() {
    let mut seen = Vec::new();
    for slot in 0..cd::MAX_SLOTS {
        let mut rel = [0u8; cd::REL_MAX];
        let n = cd::slot_rel(slot, &mut rel);
        let name = std::str::from_utf8(&rel[..n]).unwrap().to_string();
        assert!(!name.contains('/'), "{name}");
        let (stem, ext) = name.split_once('.').unwrap();
        assert!(stem.len() <= 8 && ext.len() <= 3, "{name}");
        assert!(rel[n..].iter().all(|&b| b == 0), "the name is NUL-terminated by the buffer");
        assert!(!seen.contains(&name));
        seen.push(name);
    }
    assert_eq!(seen[3], "CRASH3.DMP");
    assert_eq!(seen[15], "CRASHf.DMP");
}

/// **The report names what a reader needs to symbolize**: the signal, the
/// image's hash, the executable run `pc` is in (its offset), the registers by
/// name, the maps, the stack and the decisions with the kernel's own names.
#[test]
fn the_report_says_where_the_task_died() {
    let mut b = encoded();
    cd::set_serial(&mut b, 3);
    let v = cd::decode(&b).unwrap();
    let names = cd::Names { rule: |r| if r == 1 { "cap-denial" } else { "deadline-admission" }, verdict: |v| ["admit", "refuse", "place", "deny"][v as usize] };
    let mut out = String::new();
    cd::write_report(&v, &names, &mut out).unwrap();
    for want in [
        "crash dump 3 (riscv64, layout v1)",
        "task    WHY.ELF tid 12 cpu 1 at 123456 ticks",
        "killed  SIGSEGV (status 139), cause 0xd, fault address 0x10",
        "pc      0x10040",
        "image   sha256 abababab",
        "pc in   0x10000-0x14000 (+0x40)",
        "  ra        0x0000000000001001",
        "maps (2 of 2)",
        "0x0000000000010000-0x0000000000014000 r-x",
        "0x000000007fffe000-0x0000000080000000 rw-",
        "stack at 0x7ffff000 (37 bytes)",
        "  0x7ffff000: 000102030405060708090a0b0c0d0e0f",
        "decisions (last 2, oldest first)",
        "  #7 cap-denial deny subject 12 [1, 2, 3]",
        "  #8 deadline-admission admit subject 13 [4, 5, 6]",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
    // An image the build's table does not hold says so, not a hash of zeros.
    let (r, m, d, s) = sample();
    let mut unknown = dump(&r, &m, &d, &s);
    unknown.image = [0; 32];
    let mut raw = vec![0u8; cd::MAX_BYTES];
    let n = cd::encode(&unknown, &mut raw).unwrap();
    let mut out = String::new();
    cd::write_report(&cd::decode(&raw[..n]).unwrap(), &names, &mut out).unwrap();
    assert!(out.contains("image   unknown"), "{out}");
}

/// **A listing is one line per dump.**
#[test]
fn a_listing_line_names_task_and_signal() {
    let b = encoded();
    let mut out = String::new();
    cd::write_line(&cd::decode(&b).unwrap(), &mut out).unwrap();
    assert_eq!(out, "dump 0 tid 12 WHY.ELF SIGSEGV pc 0x10040 at 123456 ticks\n");
}

/// **Each ISA names its registers in the order the kernel writes them.**
#[test]
fn the_register_names_follow_each_isas_order() {
    assert_eq!((Isa::Riscv64.reg_name(1), Isa::Riscv64.reg_name(2), Isa::Riscv64.reg_name(10)), ("ra", "sp", "a0"));
    assert_eq!((Isa::Aarch64.reg_name(30), Isa::Aarch64.reg_name(31), Isa::Aarch64.reg_name(33)), ("x30", "sp_el0", "tpidr_el0"));
    assert_eq!((Isa::X86_64.reg_name(0), Isa::X86_64.reg_name(15), Isa::X86_64.reg_name(18)), ("rax", "rsp", "gs_base"));
    assert_eq!(Isa::X86_64.reg_name(19), "?");
    assert_eq!(Isa::from_raw(0), None);
}
