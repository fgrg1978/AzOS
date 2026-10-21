// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console backend: the guest's bytes to the term, the term's to the guest.

use crate::console::{Console, Guarded, Term, BURST, RATE_BPS, TAG};
use crate::harness::*;
use crate::mmio::Transport;

struct Port {
    t: Transport<Console<TestTerm>>,
    ram: Ram,
    rx: Queue,
    tx: Queue,
}

fn port() -> Port {
    let mut ram = Ram::new();
    let (rx, tx) = (Queue::new(0, 8), Queue::new(1, 8));
    let mut t = Transport::new(Console::new(TestTerm::default()));
    bring_up(&mut t, &mut ram, 0, &[&rx, &tx]);
    Port { t, ram, rx, tx }
}

#[test]
fn identity_is_a_console_with_no_features_but_version_1() {
    let mut p = port();
    assert_eq!(rd(&mut p.t, &mut p.ram, r::DEVICE_ID), 3);
    assert_eq!(rd(&mut p.t, &mut p.ram, r::DEVICE_FEATURES), 0);
    assert_eq!(p.t.access(r::CONFIG, false, 8, 0, &mut p.ram), 0);
}

#[test]
fn the_guests_bytes_reach_the_term_in_order() {
    let mut p = port();
    let a = p.ram.put(b"Linux version ");
    let b = p.ram.put(b"6.12\n");
    p.tx.post(&mut p.ram, &[(a, 14, false), (b, 5, false)]);
    let c = p.ram.put(b"login: ");
    p.tx.post(&mut p.ram, &[(c, 7, false)]);
    kick(&mut p.t, &mut p.ram, 1);
    assert_eq!(p.t.dev.term.out, b"Linux version 6.12\nlogin: ");
    assert_eq!(p.t.dev.out_bytes, 26);
    assert_eq!(p.tx.used_idx(&p.ram), 2);
    assert!(p.t.irq_level());
}

#[test]
fn a_long_write_is_handed_over_in_pieces_without_loss() {
    let mut p = port();
    let msg: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let a = p.ram.put(&msg);
    p.tx.post(&mut p.ram, &[(a, 1000, false)]);
    kick(&mut p.t, &mut p.ram, 1);
    assert_eq!(p.t.dev.term.out, msg);
}

#[test]
fn input_is_delivered_into_the_buffers_the_guest_offers() {
    let mut p = port();
    p.t.dev.term.input.extend(b"ls\n");
    let a = p.ram.put(&[0u8; 64]);
    p.rx.post(&mut p.ram, &[(a, 64, true)]);
    p.t.poll(&mut p.ram);
    assert_eq!(p.rx.used(&p.ram, 0).1, 3);
    assert_eq!(p.ram.get(a, 3), b"ls\n");
    assert!(p.t.irq_level());
}

#[test]
fn input_waits_for_a_buffer_and_a_small_buffer_takes_what_fits() {
    let mut p = port();
    p.t.dev.term.input.extend(b"hello world");
    p.t.poll(&mut p.ram);
    assert_eq!(p.rx.used_idx(&p.ram), 0, "no buffer offered yet");
    let (a, b) = (p.ram.alloc(5), p.ram.alloc(64));
    p.rx.post(&mut p.ram, &[(a, 5, true)]);
    p.rx.post(&mut p.ram, &[(b, 64, true)]);
    kick(&mut p.t, &mut p.ram, 0);
    assert_eq!(p.ram.get(a, 5), b"hello");
    assert_eq!(p.ram.get(b, 6), b" world");
    assert_eq!(p.t.dev.in_bytes, 11);
}

#[test]
fn no_input_leaves_the_buffers_with_the_guest() {
    let mut p = port();
    let a = p.ram.alloc(16);
    p.rx.post(&mut p.ram, &[(a, 16, true)]);
    p.t.poll(&mut p.ram);
    assert_eq!(p.rx.used_idx(&p.ram), 0);
    assert!(!p.t.irq_level());
}

/// What a guest's `bytes` come out as on the operator's console.
fn through_guard(bytes: &[u8]) -> Vec<u8> {
    let mut g = Guarded::new(TestTerm::default());
    g.write(bytes);
    g.inner.out
}

#[test]
fn a_line_is_marked_as_the_guests_and_text_passes_unchanged() {
    assert_eq!(through_guard(b"hello\nworld\n"), b"[vm0] hello\n[vm0] world\n");
    // A blank line costs its newline and no marker; a line in two writes is marked once.
    assert_eq!(through_guard(b"a\n\nb"), b"[vm0] a\n\n[vm0] b");
    let mut g = Guarded::new(TestTerm::default());
    g.write(b"half ");
    g.write(b"a line\n");
    assert_eq!(g.inner.out, b"[vm0] half a line\n");
}

#[test]
fn escape_sequences_and_control_bytes_cannot_reach_the_console() {
    // Clear screen, move the cursor, ring the bell, forge a kernel line with a
    // carriage return, delete, a high byte, NUL.
    let out = through_guard(b"\x1b[2J\x1b[H\x07\rKERNEL PANIC\x7f\xc3\xa9\0\n");
    assert!(out.iter().all(|&b| b == b'\n' || (0x20..=0x7e).contains(&b)), "{out:?}");
    assert!(!out.contains(&0x1b));
    assert!(out.starts_with(TAG), "even a forged line starts with the guest's marker");
    assert_eq!(out, b"[vm0] ?[2J?[H??KERNEL PANIC????\n");
}

#[test]
fn a_guest_that_prints_in_a_loop_loses_bytes_and_the_console_gets_one_notice() {
    let mut g = Guarded::new(TestTerm::default());
    g.tick(1_000_000_000);
    let line = [b'x'; 100];
    for _ in 0..200 {
        g.write(&line);
        g.write(b"\n");
    }
    let out = g.inner.out.len() as u64;
    assert!(out <= BURST, "{out} bytes passed in one burst");
    assert!(g.dropped > 15_000, "dropped {}", g.dropped);
    // Time passes: the bucket refills at the rate and the loss is reported once.
    g.inner.out.clear();
    g.tick(1_100_000_000); // 0.1 s: a few hundred bytes, below the reporting level
    assert!(g.inner.out.is_empty());
    g.tick(1_700_000_000);
    let text = String::from_utf8(g.inner.out.clone()).unwrap();
    assert!(text.contains(" bytes dropped\n") && text.starts_with("\n[vm0] "), "{text:?}");
    g.inner.out.clear();
    g.tick(1_800_000_000);
    assert!(g.inner.out.is_empty(), "the notice is not repeated");
    // And the guest can print again, at the rate.
    g.write(b"back\n");
    assert_eq!(g.inner.out, b"[vm0] back\n");
}

#[test]
fn the_rate_is_what_the_bucket_earns_and_a_long_silence_is_a_burst_no_more() {
    let mut g = Guarded::new(TestTerm::default());
    g.tick(5_000_000_000);
    g.write(&vec![b'a'; 4 * BURST as usize]);
    g.inner.out.clear();
    // One second later: RATE_BPS bytes (capped at the burst), so at most that much passes.
    g.tick(6_000_000_000);
    g.write(&vec![b'b'; 4 * BURST as usize]);
    assert!(g.inner.out.len() as u64 <= BURST.min(RATE_BPS) + 64, "{}", g.inner.out.len());
    // A very long silence is a full bucket, not a larger one.
    g.inner.out.clear();
    g.tick(500_000_000_000);
    g.write(&vec![b'c'; 8 * BURST as usize]);
    assert!(g.inner.out.len() as u64 <= BURST + 64, "{}", g.inner.out.len());
}

#[test]
fn the_guarded_console_has_no_input() {
    let mut g = Guarded::new(TestTerm::default());
    g.inner.input.extend(b"rm -rf\n");
    let mut buf = [0u8; 16];
    assert_eq!(g.read(&mut buf), 0);
}

#[test]
fn the_guard_sits_between_the_device_and_the_console() {
    let mut ram = Ram::new();
    let (rx, tx) = (Queue::new(0, 8), Queue::new(1, 8));
    let mut t = Transport::new(Console::new(Guarded::new(TestTerm::default())));
    bring_up(&mut t, &mut ram, 0, &[&rx, &tx]);
    let a = ram.put(b"\x1b[31mred\n");
    let mut tx = tx;
    tx.post(&mut ram, &[(a, 9, false)]);
    kick(&mut t, &mut ram, 1);
    assert_eq!(t.dev.term.inner.out, b"[vm0] ?[31mred\n");
}
