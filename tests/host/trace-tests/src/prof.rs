// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/trace/src/prof.rs` (the sampling profiler's pure core),
//! pulled in by `#[path]`: the stack walker on synthetic frames, the sample
//! records, the aggregation, the ELF symbolization and the two outputs.

#[allow(dead_code)]
#[path = "../../../../crates/core/trace/src/prof.rs"]
mod prof;

use prof::*;

// ── A synthetic stack ───────────────────────────────────────────────────────

const BASE: u64 = 0x10_0000;
const TOP: u64 = BASE + 0x800;
const TEXT: (u64, u64) = (0x8000_0000, 0x8010_0000);

/// A stack of 256 words at `BASE`, and a reader over it.
struct Stack {
    w: Vec<u64>,
    reads: usize,
}

impl Stack {
    fn new() -> Stack {
        Stack { w: vec![0; 256], reads: 0 }
    }
    fn put(&mut self, a: u64, v: u64) {
        self.w[((a - BASE) / 8) as usize] = v;
    }
    fn read(&mut self, a: u64) -> Option<u64> {
        self.reads += 1;
        (a >= BASE && a + 8 <= TOP && a % 8 == 0).then(|| self.w[((a - BASE) / 8) as usize])
    }
    /// Lay a chain out for `l`: frame `k` at `fp(k)` saves `rets[k]` and the
    /// next frame pointer (0 after the last). Returns the first frame pointer.
    fn chain(&mut self, l: &Layout, rets: &[u64]) -> u64 {
        for (k, &r) in rets.iter().enumerate() {
            let fp = fp_of(k);
            self.put(fp.wrapping_add_signed(l.ra_off), r);
            self.put(fp.wrapping_add_signed(l.fp_off), if k + 1 < rets.len() { fp_of(k + 1) } else { 0 });
        }
        fp_of(0)
    }
}

/// Frame `k`'s frame pointer: 16-aligned, ascending, clear of the bottom.
fn fp_of(k: usize) -> u64 {
    BASE + 0x100 + 0x40 * k as u64
}

fn text(a: u64) -> bool {
    (TEXT.0..TEXT.1).contains(&a)
}

const PC: u64 = 0x8000_1000;

fn go(l: &Layout, s: &mut Stack, fp: u64, depth: usize) -> (Walk, Vec<u64>) {
    let mut out = vec![0u64; depth];
    let w = walk(l, PC, fp, BASE, TOP, text, |a| s.read(a), &mut out);
    out.truncate(w.depth);
    (w, out)
}

const ISAS: [(&str, Layout); 3] = [("riscv64", RISCV64), ("aarch64", AARCH64), ("x86_64", X86_64)];

// ── The walker ──────────────────────────────────────────────────────────────

#[test]
fn good_chain_on_every_isa() {
    let rets = [0x8000_2000, 0x8000_3000, 0x8000_4000, 0x8000_5000];
    for (name, l) in ISAS {
        let mut s = Stack::new();
        let fp = s.chain(&l, &rets);
        let (w, f) = go(&l, &mut s, fp, 16);
        assert_eq!(w, Walk { depth: 5, stop: Stop::End }, "{name}");
        assert_eq!(f, [PC, 0x8000_2000, 0x8000_3000, 0x8000_4000, 0x8000_5000], "{name}");
    }
}

#[test]
fn depth_limit_stops_the_walk_and_says_so() {
    let rets = [0x8000_2000, 0x8000_3000, 0x8000_4000, 0x8000_5000];
    for (name, l) in ISAS {
        let mut s = Stack::new();
        let fp = s.chain(&l, &rets);
        let (w, f) = go(&l, &mut s, fp, 3);
        assert_eq!(w, Walk { depth: 3, stop: Stop::Depth }, "{name}");
        assert_eq!(f, [PC, 0x8000_2000, 0x8000_3000], "{name}");
        // Exactly the chain's length is not "deeper than the limit".
        let (w, _) = go(&l, &mut s, fp, 5);
        assert_eq!(w, Walk { depth: 5, stop: Stop::Depth }, "{name}: the limit is checked first");
        let (w, _) = go(&l, &mut s, fp, 6);
        assert_eq!(w, Walk { depth: 5, stop: Stop::End }, "{name}");
        // A zero-length output records nothing.
        let (w, _) = go(&l, &mut s, fp, 0);
        assert_eq!(w.depth, 0, "{name}");
    }
}

#[test]
fn no_frame_pointer_is_just_the_pc() {
    for (name, l) in ISAS {
        let mut s = Stack::new();
        let (w, f) = go(&l, &mut s, 0, 8);
        assert_eq!((w, f), (Walk { depth: 1, stop: Stop::End }, vec![PC]), "{name}");
        assert_eq!(s.reads, 0, "{name}: nothing is read for a zero frame pointer");
    }
}

#[test]
fn a_loop_stops_at_the_repeat() {
    for (name, l) in ISAS {
        // A frame whose saved frame pointer is itself.
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000]);
        s.put(fp.wrapping_add_signed(l.fp_off), fp);
        let (w, f) = go(&l, &mut s, fp, 16);
        assert_eq!(w.stop, Stop::NotAscending, "{name}");
        assert_eq!(f, [PC, 0x8000_2000], "{name}: the frame before the repeat is kept");

        // A cycle of two: frame 0 -> frame 1 -> frame 0.
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000, 0x8000_4000]);
        s.put(fp_of(1).wrapping_add_signed(l.fp_off), fp_of(0));
        let (w, f) = go(&l, &mut s, fp, 16);
        assert_eq!(w.stop, Stop::NotAscending, "{name}");
        assert_eq!(f, [PC, 0x8000_2000, 0x8000_3000], "{name}");
        assert!(s.reads <= 8, "{name}: a loop does not read on and on");
    }
}

#[test]
fn bad_pointers_stop_the_walk_at_the_last_good_frame() {
    for (name, l) in ISAS {
        // Misaligned from the start (8 is aligned for x86_64, so use 4).
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000]);
        let (w, f) = go(&l, &mut s, fp + 4, 8);
        assert_eq!((w.stop, f.len()), (Stop::Misaligned, 1), "{name}");

        // The first frame pointer below the stack: a stale register.
        let (w, f) = go(&l, &mut s, BASE - 0x40, 8);
        assert_eq!((w.stop, f.len()), (Stop::Bounds, 1), "{name}");

        // ... or above it.
        let (w, f) = go(&l, &mut s, TOP + 0x40, 8);
        assert_eq!((w.stop, f.len()), (Stop::Bounds, 1), "{name}");

        // A record straddling the top (x86_64's 8-byte alignment allows it).
        if l == X86_64 {
            let (w, _) = go(&l, &mut s, TOP - 8, 8);
            assert_eq!(w.stop, Stop::Bounds, "{name}");
        }

        // The second link wild: frame 0 is good, its saved pointer is not.
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000]);
        s.put(fp.wrapping_add_signed(l.fp_off), 0xdead_beef_0000);
        let (w, f) = go(&l, &mut s, fp, 8);
        assert_eq!((w.stop, f), (Stop::Bounds, vec![PC, 0x8000_2000]), "{name}");

        // The second link below the first.
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000]);
        s.put(fp.wrapping_add_signed(l.fp_off), fp - 0x20);
        let (w, f) = go(&l, &mut s, fp, 8);
        assert_eq!((w.stop, f), (Stop::NotAscending, vec![PC, 0x8000_2000]), "{name}");

        // A return address that is not code (the stack itself, a small
        // integer): the frame is not believed.
        for bad in [BASE + 0x40, 0x42, u64::MAX] {
            let mut s = Stack::new();
            let fp = s.chain(&l, &[0x8000_2000, bad, 0x8000_4000]);
            let (w, f) = go(&l, &mut s, fp, 8);
            assert_eq!((w.stop, f), (Stop::BadReturn, vec![PC, 0x8000_2000]), "{name} {bad:#x}");
        }

        // A zero return address ends the chain cleanly.
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0, 0x8000_4000]);
        let (w, f) = go(&l, &mut s, fp, 8);
        assert_eq!((w.stop, f), (Stop::End, vec![PC, 0x8000_2000]), "{name}");
    }
}

#[test]
fn a_failed_read_is_a_read_fault_not_a_panic() {
    for (name, l) in ISAS {
        let mut s = Stack::new();
        let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000]);
        let mut n = 0;
        let mut out = [0u64; 8];
        // The user-stack case: the second frame's page is not mapped.
        let w = walk(&l, PC, fp, BASE, TOP, text, |a| {
            n += 1;
            if n > 2 { None } else { s.read(a) }
        }, &mut out);
        assert_eq!((w.depth, w.stop), (2, Stop::ReadFault), "{name}");
    }
}

#[test]
fn the_walk_never_reads_outside_the_stack() {
    for (name, l) in ISAS {
        for bad in [0u64, 8, BASE - 8, BASE + 4, TOP - 8, TOP, TOP + 8, u64::MAX, u64::MAX - 7, 1 << 63] {
            let mut s = Stack::new();
            let fp = s.chain(&l, &[0x8000_2000, 0x8000_3000]);
            s.put(fp.wrapping_add_signed(l.fp_off), bad);
            let mut out = [0u64; 8];
            let mut seen = Vec::new();
            walk(&l, PC, fp, BASE, TOP, text, |a| {
                seen.push(a);
                s.read(a)
            }, &mut out);
            assert!(seen.iter().all(|&a| a >= BASE && a + 8 <= TOP), "{name} {bad:#x}: read {seen:x?}");
        }
    }
}

// ── The record format ───────────────────────────────────────────────────────

fn roundtrip(depth: usize, user: bool, stop: Stop) {
    let frames: Vec<u64> = (0..depth as u64).map(|i| 0xffff_ffff_8000_0000 + i * 0x1234).collect();
    let mut recs = Vec::new();
    encode(7, user, Walk { depth, stop }, &frames, |ev, a| recs.push((ev, a)));
    assert_eq!(recs.len(), 1 + frame_records(depth), "depth {depth}");
    let mut asm = Assembler::new();
    let mut done = Vec::new();
    for (i, (ev, a)) in recs.iter().enumerate() {
        if let Some(s) = asm.feed(100 + i as u64, *ev, *a) {
            done.push(*s);
        }
    }
    assert_eq!(done.len(), 1, "depth {depth}: one sample, complete after the last record");
    let s = done[0];
    assert_eq!((s.ts, s.tid, s.user, s.stop, s.depth), (100, 7, user, stop, depth));
    assert_eq!(s.frames(), &frames[..]);
    assert_eq!((asm.torn, asm.samples), (0, 1));
}

#[test]
fn a_sample_survives_the_ring() {
    for depth in [1, 2, 3, 4, 15, 16, 17, 31, 32] {
        for (user, stop) in [(false, Stop::End), (true, Stop::Depth), (false, Stop::NoStack), (true, Stop::ReadFault)] {
            roundtrip(depth, user, stop);
        }
    }
}

#[test]
fn records_per_sample() {
    // 16 frames: the header carries the PC, 15 more make 8 records.
    assert_eq!(frame_records(0), 0);
    assert_eq!(frame_records(1), 0);
    assert_eq!(frame_records(2), 1);
    assert_eq!(frame_records(3), 1);
    assert_eq!(frame_records(16), 8);
    assert_eq!(frame_records(32), 16);
}

#[test]
fn every_stop_reason_fits_its_bits() {
    for b in 0..8u32 {
        let s = Stop::from_bits(b);
        assert_eq!(s as u32, b);
        assert_eq!(Stop::from_bits(meta(5, false, s) >> 9), s);
        assert_ne!(s.name(), "");
    }
    let m = meta(32, true, Stop::NoStack);
    assert_eq!((m & 0xff, m >> 8 & 1, m >> 9), (32, 1, 7));
}

#[test]
fn a_torn_sample_is_counted_and_never_reported() {
    let frames: Vec<u64> = (1..=6).map(|i| 0x8000_0000 + i * 16).collect();
    let mut recs = Vec::new();
    encode(1, false, Walk { depth: 6, stop: Stop::End }, &frames, |ev, a| recs.push((ev, a)));
    assert_eq!(recs.len(), 4);

    // The ring overwrote the head: frame records with no header.
    let mut asm = Assembler::new();
    for (ev, a) in &recs[1..] {
        assert!(asm.feed(0, *ev, *a).is_none());
    }
    assert_eq!((asm.torn, asm.samples), (3, 0));

    // The tail is not written yet, and the next sample starts.
    let mut asm = Assembler::new();
    for (ev, a) in &recs[..2] {
        assert!(asm.feed(0, *ev, *a).is_none());
    }
    // The next, complete sample is reported intact.
    let mut got = None;
    for (ev, a) in &recs {
        if let Some(s) = asm.feed(9, *ev, *a) {
            got = Some(*s);
        }
    }
    assert_eq!(asm.torn, 1);
    assert_eq!(got.unwrap().frames(), &frames[..]);
    assert_eq!(got.unwrap().ts, 9);

    // A header that claims 0 or too many frames is not a sample.
    let mut asm = Assembler::new();
    assert!(asm.feed(0, azos_abi::trace::TRACE_EV_PROF_SAMPLE, [1, 0, 0, 0]).is_none());
    assert!(asm.feed(0, azos_abi::trace::TRACE_EV_PROF_SAMPLE, [1, 33, 0, 0]).is_none());
    assert_eq!(asm.torn, 2);

    // Other classes' events are not the assembler's business.
    assert!(asm.feed(0, azos_abi::trace::TRACE_EV_SCHED_SWITCH, [1, 2, 3, 4]).is_none());
    assert_eq!(asm.torn, 2);
}

// ── Aggregation and folded output ───────────────────────────────────────────

struct Buf(Vec<u8>);
impl Sink for Buf {
    fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

struct Map(Vec<(u64, bool, &'static str)>);
impl Namer for Map {
    fn name(&self, addr: u64, user: bool) -> Option<&[u8]> {
        self.0.iter().find(|(a, u, _)| *a == addr && *u == user).map(|(_, _, n)| n.as_bytes())
    }
}

fn names() -> Map {
    Map(vec![
        (0x100, false, "main"),
        (0x200, false, "core::fmt::write"),
        (0x300, false, "with space;and semi"),
        (0x100, true, "user_main"),
    ])
}

#[test]
fn the_table_counts_distinct_stacks() {
    let mut t = StackTable::<4, 3>::new();
    assert_eq!(t.add(1, false, &[0x200, 0x100]), Some(0));
    assert_eq!(t.add(1, false, &[0x200, 0x100]), Some(0));
    assert_eq!(t.add(2, false, &[0x200, 0x100]), Some(1), "another task");
    assert_eq!(t.add(1, true, &[0x200, 0x100]), Some(2), "another mode");
    // Deeper than the table keeps: the innermost frames.
    assert_eq!(t.add(1, false, &[1, 2, 3, 4, 5]), Some(3));
    assert_eq!(t.add(1, false, &[1, 2, 3, 9]), Some(3), "same kept frames, same stack");
    assert_eq!(t.add(1, false, &[7]), None, "full");
    assert_eq!((t.samples, t.lost), (7, 1));
    assert_eq!(t.stacks().iter().map(|s| s.count).collect::<Vec<_>>(), [2, 1, 1, 2]);
}

#[test]
fn folded_output_is_outermost_first_with_counts() {
    let mut t = StackTable::<8, 8>::new();
    for _ in 0..3 {
        t.add(5, false, &[0x200, 0x100]);
    }
    t.add(5, false, &[0x300, 0x200, 0x100]);
    t.add(6, true, &[0x100, 0x4242]);
    let mut o = Buf(Vec::new());
    write_folded(&t, &names(), &mut o);
    assert_eq!(
        String::from_utf8(o.0).unwrap(),
        "kernel:tid5;main;core::fmt::write 3\n\
         kernel:tid5;main;core::fmt::write;with_space_and_semi 1\n\
         user:tid6;0x4242;user_main 1\n"
    );
}

// ── The Perfetto trace ──────────────────────────────────────────────────────

/// Is `s` one JSON value and nothing else? (A recursive-descent check: the
/// export must load in a strict parser, not just look right.)
fn json_ok(s: &str) -> bool {
    fn ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }
    fn val(b: &[u8], i: &mut usize) -> bool {
        ws(b, i);
        match b.get(*i) {
            Some(b'{') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b'}') {
                    *i += 1;
                    return true;
                }
                loop {
                    ws(b, i);
                    if !string(b, i) {
                        return false;
                    }
                    ws(b, i);
                    if b.get(*i) != Some(&b':') {
                        return false;
                    }
                    *i += 1;
                    if !val(b, i) {
                        return false;
                    }
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b'}') => {
                            *i += 1;
                            return true;
                        }
                        _ => return false,
                    }
                }
            }
            Some(b'[') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b']') {
                    *i += 1;
                    return true;
                }
                loop {
                    if !val(b, i) {
                        return false;
                    }
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b']') => {
                            *i += 1;
                            return true;
                        }
                        _ => return false,
                    }
                }
            }
            Some(b'"') => string(b, i),
            Some(c) if c.is_ascii_digit() || *c == b'-' => {
                let st = *i;
                while *i < b.len() && (b[*i].is_ascii_digit() || b"-.eE+".contains(&b[*i])) {
                    *i += 1;
                }
                *i > st
            }
            _ => false,
        }
    }
    fn string(b: &[u8], i: &mut usize) -> bool {
        if b.get(*i) != Some(&b'"') {
            return false;
        }
        *i += 1;
        while let Some(&c) = b.get(*i) {
            match c {
                b'"' => {
                    *i += 1;
                    return true;
                }
                b'\\' => *i += 2,
                c if c < 0x20 => return false,
                _ => *i += 1,
            }
        }
        false
    }
    let b = s.as_bytes();
    let mut i = 0;
    let ok = val(b, &mut i);
    ws(b, &mut i);
    ok && i == b.len()
}

#[test]
fn the_json_checker_rejects_what_a_parser_would() {
    assert!(json_ok("{\"a\":[1,2.5,\"x\\\"y\"],\"b\":{}}"));
    assert!(!json_ok("{\"a\":[1,]}"));
    assert!(!json_ok("{\"a\":1,}"));
    assert!(!json_ok("{\"a\":\"x\"y\"}"));
    assert!(!json_ok("[1,2"));
}

#[test]
fn the_perfetto_export_is_valid_json_with_nested_slices() {
    let mut t = StackTable::<8, 8>::new();
    let mut log = SampleLog::<16>::new();
    let a = t.add(5, false, &[0x200, 0x100]).unwrap();
    let b = t.add(6, true, &[0x100]).unwrap();
    let c = t.add(5, false, &[0x300, 0x100]).unwrap();
    // Two CPUs, a 10 ms period.
    log.push(1_000_000_000, 0, a);
    log.push(1_000_500_000, 1, b);
    log.push(1_010_000_000, 0, c);
    log.push(1_010_500_000, 1, b);
    log.push(1_020_000_000, 0, a);
    assert_eq!(period_ns(&log), 10_000_000);
    let mut o = Buf(Vec::new());
    let n = Map(vec![(0x200, false, "core::fmt::write"), (0x300, false, "has\"quote\\")]);
    write_perfetto(&t, &log, &n, &mut o);
    let s = String::from_utf8(o.0).unwrap();
    assert!(json_ok(&s), "{s}");
    assert!(s.starts_with("{\"traceEvents\":["), "{s}");
    // Two track names, then root + frames for each of the five samples.
    assert_eq!(s.matches("\"ph\":\"M\"").count(), 2);
    assert_eq!(s.matches("\"ph\":\"X\"").count(), (1 + 2) * 3 + (1 + 1) * 2);
    assert!(s.contains("\"name\":\"kernel tid 5\""), "{s}");
    assert!(s.contains("\"name\":\"user tid 6\""), "{s}");
    assert!(s.contains("\"name\":\"has\\\"quote\\\\\""), "{s}");
    // A sample lasts until the CPU's next one: cpu 0's first is 10 ms.
    assert!(s.contains("\"ts\":1000000.000,\"dur\":10000.000,\"pid\":0,\"tid\":0"), "{s}");
    // The last sample of a CPU lasts 1.5 periods at most, not forever.
    assert!(s.contains("\"ts\":1020000.000,\"dur\":15000.000"), "{s}");
}

#[test]
fn an_empty_profile_is_still_valid_json() {
    let t = StackTable::<2, 2>::new();
    let l = SampleLog::<2>::new();
    let mut o = Buf(Vec::new());
    write_perfetto(&t, &l, &names(), &mut o);
    assert!(json_ok(&String::from_utf8(o.0).unwrap()));
}

#[test]
fn the_log_drops_what_does_not_fit_and_says_so() {
    let mut l = SampleLog::<2>::new();
    for i in 0..5 {
        l.push(i, 0, 0);
    }
    assert_eq!((l.entries().len(), l.dropped), (2, 3));
}

// ── Symbolization ───────────────────────────────────────────────────────────

fn demangled(s: &str) -> String {
    let mut out = [0u8; 96];
    let n = demangle(s.as_bytes(), &mut out);
    String::from_utf8(out[..n].to_vec()).unwrap()
}

#[test]
fn rust_legacy_names_are_demangled() {
    assert_eq!(demangled("_ZN4core3fmt5write17h0123456789abcdefE"), "core::fmt::write");
    assert_eq!(demangled("_ZN10azos_sched9scheduler11do_schedule17hdeadbeefdeadbeefE"), "azos_sched::scheduler::do_schedule");
    assert_eq!(
        demangled("_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17h0123456789abcdefE"),
        "<T as core::convert::Into<U>>::into"
    );
    assert_eq!(demangled("_ZN4main17h0123456789abcdefE"), "main");
    // Not Rust's, or malformed: shown as it is.
    assert_eq!(demangled("trap_entry"), "trap_entry");
    assert_eq!(demangled("_ZN99xE"), "_ZN99xE");
    assert_eq!(demangled("_ZN"), "_ZN");
    // Truncated to the buffer, never past it.
    let mut small = [0u8; 8];
    assert_eq!(demangle(b"_ZN4core3fmt5writeE", &mut small), 8);
}

/// A minimal ELF64 with a symbol table: `syms` are
/// `(name, info, shndx, value, size)`.
fn elf(syms: &[(&str, u8, u16, u64, u64)], with_symtab: bool) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for &(name, info, shndx, value, size) in syms {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        symtab.extend_from_slice(&off.to_le_bytes());
        symtab.push(info);
        symtab.push(0);
        symtab.extend_from_slice(&shndx.to_le_bytes());
        symtab.extend_from_slice(&value.to_le_bytes());
        symtab.extend_from_slice(&size.to_le_bytes());
    }
    let mut f = vec![0u8; 64];
    let sym_off = f.len() as u64;
    f.extend_from_slice(&symtab);
    let str_off = f.len() as u64;
    f.extend_from_slice(&strtab);
    while f.len() % 8 != 0 {
        f.push(0);
    }
    let shoff = f.len() as u64;
    let sh = |ty: u32, off: u64, size: u64, link: u32, ent: u64| {
        let mut s = vec![0u8; 64];
        s[4..8].copy_from_slice(&ty.to_le_bytes());
        s[0x18..0x20].copy_from_slice(&off.to_le_bytes());
        s[0x20..0x28].copy_from_slice(&size.to_le_bytes());
        s[0x28..0x2c].copy_from_slice(&link.to_le_bytes());
        s[0x38..0x40].copy_from_slice(&ent.to_le_bytes());
        s
    };
    f.extend_from_slice(&sh(0, 0, 0, 0, 0));
    f.extend_from_slice(&sh(1, 0x1000, 0x1000, 0, 0)); // .text
    if with_symtab {
        f.extend_from_slice(&sh(2, sym_off, symtab.len() as u64, 3, 24));
    } else {
        f.extend_from_slice(&sh(1, 0, 0, 0, 0));
    }
    f.extend_from_slice(&sh(3, str_off, strtab.len() as u64, 0, 0));
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = 2;
    f[5] = 1;
    f[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
    f[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
    f[0x3c..0x3e].copy_from_slice(&4u16.to_le_bytes());
    f
}

struct Mem(Vec<u8>);
impl ReadAt for Mem {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> usize {
        let off = off as usize;
        if off >= self.0.len() {
            return 0;
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        n
    }
}

const FUNC: u8 = 2;
const NOTYPE: u8 = 0;
const OBJECT: u8 = 1;

fn symbols() -> Vec<u8> {
    elf(
        &[
            ("_ZN4core3fmt5write17h0123456789abcdefE", FUNC, 1, 0x1000, 0x100),
            ("inner", FUNC, 1, 0x1040, 0x20),
            ("asm_label", NOTYPE, 1, 0x2000, 0),
            ("undefined", FUNC, 0, 0x3000, 0x100),
            ("absolute", FUNC, 0xfff1, 0x4000, 0x100),
            ("data", OBJECT, 1, 0x5000, 0x100),
            ("sized_label", NOTYPE, 1, 0x6000, 0x40),
        ],
        true,
    )
}

#[test]
fn addresses_get_the_innermost_covering_symbol() {
    let mut r = Resolver::<16, 512>::new();
    for a in [0x1000, 0x1010, 0x1050, 0x105f, 0x1060, 0x10ff, 0x1100, 0x2000, 0x3010, 0x4010, 0x5010, 0x6010, 0x1010] {
        r.add(a);
    }
    assert_eq!(r.len(), 12, "a repeated address is one");
    assert_eq!(r.load(&mut Mem(symbols())), Ok(7));
    let n = |a| r.name_of(a).map(|b| String::from_utf8(b.to_vec()).unwrap());
    assert_eq!(n(0x1000).as_deref(), Some("core::fmt::write"), "the first byte");
    assert_eq!(n(0x1010).as_deref(), Some("core::fmt::write"));
    assert_eq!(n(0x1050).as_deref(), Some("inner"), "the nested symbol wins");
    assert_eq!(n(0x105f).as_deref(), Some("inner"), "its last byte");
    assert_eq!(n(0x1060).as_deref(), Some("core::fmt::write"), "just past it");
    assert_eq!(n(0x10ff).as_deref(), Some("core::fmt::write"));
    assert_eq!(n(0x1100), None, "the end is exclusive");
    assert_eq!(n(0x2000), None, "a symbol without a size is not used");
    assert_eq!(n(0x3010), None, "undefined");
    assert_eq!(n(0x4010), None, "absolute");
    assert_eq!(n(0x5010), None, "data");
    assert_eq!(n(0x6010).as_deref(), Some("sized_label"));
    assert_eq!(n(0x9999), None, "never asked");
}

#[test]
fn a_bad_elf_is_an_error_not_a_panic() {
    let mut r = Resolver::<4, 64>::new();
    r.add(0x1000);
    assert_eq!(r.load(&mut Mem(vec![])), Err(ElfError::Truncated));
    assert_eq!(r.load(&mut Mem(vec![0x41; 64])), Err(ElfError::NotElf));
    let mut be = symbols();
    be[5] = 2; // big endian
    assert_eq!(r.load(&mut Mem(be)), Err(ElfError::NotElf));
    let mut e32 = symbols();
    e32[4] = 1;
    assert_eq!(r.load(&mut Mem(e32)), Err(ElfError::NotElf));
    assert_eq!(r.load(&mut Mem(elf(&[], false))), Err(ElfError::NoSymtab), "stripped");
    let full = symbols();
    assert!(matches!(r.load(&mut Mem(full[..full.len() - 100].to_vec())), Err(ElfError::Truncated)));
    // A section header whose link is past the table.
    let mut bad = symbols();
    let shoff = u64::from_le_bytes(bad[0x28..0x30].try_into().unwrap()) as usize;
    bad[shoff + 128 + 0x28..shoff + 128 + 0x2c].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(r.load(&mut Mem(bad)), Err(ElfError::Truncated));
    assert_eq!(r.name_of(0x1000), None);
}

#[test]
fn a_full_resolver_counts_what_it_refused() {
    let mut r = Resolver::<2, 16>::new();
    for a in [0x1000, 0x1010, 0x1020, 0x1030] {
        r.add(a);
    }
    assert_eq!((r.len(), r.overflow), (2, 2));
    // 16 bytes of pool hold "core::fmt::write" (16) once, not twice.
    assert_eq!(r.load(&mut Mem(symbols())), Ok(1));
    assert_eq!(r.overflow, 3);
}

#[test]
fn a_symbol_table_larger_than_one_read_is_walked_whole() {
    // 300 functions of 16 bytes: ten pieces of 32.
    let names: Vec<String> = (0..300).map(|i| format!("f{i}")).collect();
    let syms: Vec<_> = names.iter().enumerate().map(|(i, n)| (n.as_str(), FUNC, 1u16, 0x1000 + 16 * i as u64, 16u64)).collect();
    // Entry 0 is the null symbol: function 30 ends the first piece, 31 starts the second.
    let probe = [0u64, 30, 31, 32, 127, 128, 299];
    let mut r = Resolver::<8, 128>::new();
    for i in probe {
        r.add(0x1000 + 16 * i + 3);
    }
    assert_eq!(r.load(&mut Mem(elf(&syms, true))), Ok(probe.len()));
    for i in probe {
        assert_eq!(r.name_of(0x1000 + 16 * i + 3).unwrap(), format!("f{i}").as_bytes());
    }
}

#[test]
fn kernel_and_user_addresses_use_their_own_files() {
    let (mut k, mut u) = (Resolver::<4, 64>::new(), Resolver::<4, 64>::new());
    k.add(0x1010);
    u.add(0x1010);
    k.load(&mut Mem(symbols())).unwrap();
    u.load(&mut Mem(elf(&[("user_fn", FUNC, 1, 0x1000, 0x100)], true))).unwrap();
    let n = Names { kernel: &k, user: &u };
    assert_eq!(n.name(0x1010, false).unwrap(), b"core::fmt::write");
    assert_eq!(n.name(0x1010, true).unwrap(), b"user_fn");
    assert_eq!(n.name(0x1010 + 0x1000, true), None);
}

// ── The v0 mangling ─────────────────────────────────────────────────────────

/// Real v0 symbols from the user programs of a riscv64 build (rustc's default
/// mangling): closures, vtable shims, inherent and trait impls, const and
/// type generics, backreferences, arrays, slices, tuples, references.
const V0: &[&str] = &[
    "_RNvCseQAC5qhML4_8tracectl6stream",
    "_RNvMs_Cs2cHg8s7VmDA_2shNtB4_3Env3get",
    "_RNvMs_Cs2cHg8s7VmDA_2shNtB4_3Env3set",
    "_RNCNvCsa5nMVxiemhJ_5lxsrv7lx_load0B3_",
    "_RNCNvNtCs2cHg8s7VmDA_2sh4path4join0B5_",
    "_RNCNvCs6UbaMsLSE9O_5power9state_cmd0B3_",
    "_RNCNvCsa5nMVxiemhJ_5lxsrv9run_linuxs_0B3_",
    "_RNCNvCsa5nMVxiemhJ_5lxsrv9run_linuxs0_0B3_",
    "_RNvCs1ZpbrR1utge_11azos_libsys11CONSOLE_CAP.0",
    "_RNvMs_Cs96Okb0FZPms_14azos_lx_loaderNtB4_6Module6str_at",
    "_RNCINvNtCs6UbaMsLSE9O_5power6policy5applyNtB6_6KernelE0B6_",
    "_RNCNvNtCs96Okb0FZPms_14azos_lx_loader7aarch645applys0_0B5_",
    "_RINvNtCs6UbaMsLSE9O_5power6policy9signatureNtB4_6KernelEB4_",
    "_RNvMNtCslxWhmXjnUzg_4core5sliceSy13binary_searchCseQAC5qhML4_8tracectl",
    "_RINvNtNtCseQAC5qhML4_8tracectl7profile4prof12write_foldedKj80_Kj20_EB6_",
    "_RINvMNtCslxWhmXjnUzg_4core5sliceSh12strip_prefixAhj3_ECseQAC5qhML4_8tracectl",
    "_RNvXNtCsjgtpER6L6iW_11azos_ualloc6nativeNtB2_9NativeSysNtNtB4_6engine3Sys3map",
    "_RNCNvMs_NtCsfj6MkIaqDFv_8azos_abi6ushellNtB6_12StartupBlock10from_bytess_0B8_",
    "_RNvXs2_NtCseQAC5qhML4_8tracectl7profileNtB5_6FileAtNtNtB5_4prof6ReadAt7read_at",
    "_RINvNtNtCseQAC5qhML4_8tracectl7profile4prof14write_perfettoKj80_Kj20_Kj400_EB6_",
    "_RNvYNvCsa5nMVxiemhJ_5lxsrv6exportINtNtNtCslxWhmXjnUzg_4core3ops8function5FnMutTRShEE8call_mutB4_",
    "_RNvYNvCsa5nMVxiemhJ_5lxsrv8host_abiINtNtNtCslxWhmXjnUzg_4core3ops8function5FnMutTRShEE8call_mutB4_",
    "_RNSNvYNvCsa5nMVxiemhJ_5lxsrv6exportINtNtNtCslxWhmXjnUzg_4core3ops8function6FnOnceTRShEE9call_once6vtableB6_",
    "_RNSNvYNvCsa5nMVxiemhJ_5lxsrv8host_abiINtNtNtCslxWhmXjnUzg_4core3ops8function6FnOnceTRShEE9call_once6vtableB6_",
    "_RNSNvYNCNvCsa5nMVxiemhJ_5lxsrv7lx_load0INtNtNtCslxWhmXjnUzg_4core3ops8function6FnOnceTRShEE9call_once6vtableB8_",
    "_RNSNvYNCNvCsa5nMVxiemhJ_5lxsrv9run_linuxs_0INtNtNtCslxWhmXjnUzg_4core3ops8function6FnOnceTRShEE9call_once6vtableB8_",
    "_RNvXsd_NtCslxWhmXjnUzg_4core5arrayAhj60_INtNtNtB7_3ops5index5IndexINtNtBH_5range7RangeTojEE5indexCsjgtpER6L6iW_11azos_ualloc",
    "_RNvXs2_CseOVMXvsXrBM_9azos_termINtB5_14TerminalClientINtCs8jKt1pPqcll_10azos_names8RenewingNtCs2cHg8s7VmDA_2sh7SysCallEENtB5_12TerminalCall14set_foregroundB1t_",
    "_RNvXs1_NtNtNtCslxWhmXjnUzg_4core4iter8adapters6filterINtB5_6FilterINtNtNtBb_5slice4iter5SplithNCNvCs8jKt1pPqcll_10azos_names10parse_line0ENCB1w_s_0ENtNtNtB9_6traits8iterator8Iterator4nextB1y_",
    "_RNvXs_NvNtNtNtNtCslxWhmXjnUzg_4core4iter6traits8iterator8Iterator10advance_byINtNtNtBe_5slice4iter5SplithNCNvNtCs1ZpbrR1utge_11azos_libsys4pure7cstr_at0ENtB4_13SpecAdvanceBy15spec_advance_byB1L_",
];

/// `name` without the generic arguments (`::<…>` and `Type<…>`): what the
/// profiler leaves out, so the reference demangler's output is comparable.
fn strip_generics(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let after_path = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_' || (i > 1 && b[i - 1] == ':' && b[i - 2] == ':'));
        if b[i] == '<' && after_path {
            if b[i - 1] == ':' {
                out.truncate(out.len() - 2);
            }
            let mut depth = 0;
            while i < b.len() {
                match b[i] {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    if out != s { strip_generics(&out) } else { out }
}

fn name(sym: &str, cap: usize) -> String {
    let mut out = vec![0u8; cap];
    let n = demangle(sym.as_bytes(), &mut out);
    assert!(n <= cap, "{sym}: wrote {n} into {cap}");
    String::from_utf8_lossy(&out[..n]).into_owned()
}

#[test]
fn v0_names_match_the_reference_demangler_minus_generics() {
    for sym in V0 {
        let want = strip_generics(&format!("{:#}", rustc_demangle::demangle(sym)));
        assert_eq!(name(sym, 400), want, "{sym}");
    }
}

#[test]
fn v0_names_read_as_rust_paths() {
    assert_eq!(name("_RNvCseQAC5qhML4_8tracectl3run", 64), "tracectl::run");
    assert_eq!(name("_RNvNtCslxWhmXjnUzg_4core3fmt5write", 64), "core::fmt::write");
    assert_eq!(name("_RNvMs_Cs2cHg8s7VmDA_2shNtB4_3Env3get", 64), "<sh::Env>::get");
    assert_eq!(name("_RNCNvCsa5nMVxiemhJ_5lxsrv9run_linuxs_0B3_", 64), "lxsrv::run_linux::{closure#1}");
    assert_eq!(name("_RINvNtCs6UbaMsLSE9O_5power6policy9signatureNtB4_6KernelEB4_", 64), "power::policy::signature");
    assert_eq!(name("_RNvCs1ZpbrR1utge_11azos_libsys11CONSOLE_CAP.0", 64), "azos_libsys::CONSOLE_CAP.0", "a suffix is kept");
    // The legacy scheme still works beside it.
    assert_eq!(name("_ZN4core3fmt5write17h0123456789abcdefE", 64), "core::fmt::write");
}

#[test]
fn nesting_up_to_the_limit_parses() {
    let ok = format!("_R{}C1a{}", "Nv".repeat(20), "1b".repeat(20));
    assert_eq!(name(&ok, 400), format!("a{}", "::b".repeat(20)));
}

#[test]
fn a_malformed_v0_name_is_shown_raw_and_never_overruns() {
    // A backreference to itself, or forward; a nesting far past the limit;
    // numbers that overflow; an identifier longer than the symbol.
    // Well formed, and nested far past what a real name is: refused, not recursed into.
    let deep = format!("_R{}C1a{}", "Nv".repeat(500), "1b".repeat(500));
    let long = format!("_RNvCs_{}a", "9".repeat(40));
    for bad in ["_R", "_RB_", "_RB0_", "_RNvB1_1a", "_RC", "_RCs_", "_RC99a", "_RNv", deep.as_str(), long.as_str(), "_RNvCs__3abc", "_RAj_"] {
        for cap in [0, 1, 8, 64] {
            let n = name(bad, cap);
            assert!(n.len() <= cap, "{bad}");
        }
        assert_eq!(name(bad, 4000), bad, "{bad}");
    }
}

#[test]
fn every_truncation_and_corruption_of_a_real_name_is_survivable() {
    for sym in V0 {
        let b = sym.as_bytes();
        for cut in 0..b.len() {
            let mut out = [0u8; 120];
            let n = demangle(&b[..cut], &mut out);
            assert!(n <= out.len(), "{sym} cut at {cut}");
        }
        for at in (2..b.len()).step_by(3) {
            for c in [b'0', b'9', b'_', b'B', b'E', b'N', b'I', b'K', b'z', b'$'] {
                let mut m = b.to_vec();
                m[at] = c;
                let mut out = [0u8; 120];
                let n = demangle(&m, &mut out);
                assert!(n <= out.len());
            }
        }
    }
}
