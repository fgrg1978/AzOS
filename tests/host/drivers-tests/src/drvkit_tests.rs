// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_drvkit`'s fakes: the register file, the port space and the clock every
//! migrated driver's host test stands on. A driver test is only as sharp as
//! its fake, so the fakes are pinned here.

use azos_drvkit::fake::{Access, FakeMmio, FakePorts, FakeTicks, PortAccess};
use azos_drvkit::{Mmio, PortIo, Ticks, Width};

/// The register file is little-endian and byte-addressed: a 32-bit write is
/// four bytes at consecutive offsets, and a narrower read sees part of it.
/// **Canary:** a fake that keeps words big-endian: the byte peeks and the
/// 16-bit read disagree, and so does every driver test that seeds registers by
/// byte (`pl031_over_the_register_file`).
#[test]
fn mmio_is_little_endian_and_logged() {
    let m = FakeMmio::<16>::new();
    m.write32(4, 0x1122_3344);
    assert_eq!([m.peek8(4), m.peek8(5), m.peek8(6), m.peek8(7)], [0x44, 0x33, 0x22, 0x11]);
    m.poke8(8, 0xaa);
    m.poke8(9, 0xbb);
    assert_eq!(m.read16(8), 0xbbaa);
    assert_eq!(m.read8(9), 0xbb);
    m.write64(8, 0x0102_0304_0506_0708);
    assert_eq!(m.read32(12), 0x0102_0304);
    assert_eq!(
        m.take_log(),
        [
            Access::Write { off: 4, width: 4, val: 0x1122_3344 },
            Access::Read { off: 8, width: 2, val: 0xbbaa },
            Access::Read { off: 9, width: 1, val: 0xbb },
            Access::Write { off: 8, width: 8, val: 0x0102_0304_0506_0708 },
            Access::Read { off: 12, width: 4, val: 0x0102_0304 },
        ]
    );
}

/// A write stores only the width it names; the neighbouring registers stay.
#[test]
fn mmio_write_touches_only_its_width() {
    let m = FakeMmio::<8>::new();
    m.write32(0, 0xffff_ffff);
    m.write8(1, 0x00);
    m.write16(2, 0x1234);
    assert_eq!(m.peek32(0), 0x1234_00ff);
    m.store(4, Width::W16, 0xdead_beef);
    assert_eq!(m.peek32(4), 0x0000_beef, "the value is cut to the width");
}

#[test]
#[should_panic(expected = "outside")]
fn mmio_refuses_an_offset_outside_the_block() {
    FakeMmio::<8>::new().read32(8);
}

#[test]
#[should_panic(expected = "outside")]
fn mmio_refuses_a_misaligned_access() {
    FakeMmio::<8>::new().read32(2);
}

#[test]
fn ports_hold_the_last_write_and_replay_a_queue() {
    let p = FakePorts::new();
    assert_eq!(p.inb(0x61), 0xff, "a floating bus");
    p.outb(0x61, 0x03);
    assert_eq!(p.inb(0x61), 0x03);
    p.queue(0x64, &[1, 2]);
    assert_eq!((p.inb(0x64), p.inb(0x64), p.inb(0x64)), (1, 2, 2));
    assert_eq!(p.take_log().len(), 6);
    p.outb(0x43, 0xb6);
    assert_eq!(p.take_log(), [PortAccess::Out { port: 0x43, val: 0xb6 }]);
}

#[test]
fn a_reference_is_a_window_too() {
    fn poke(m: impl Mmio) {
        m.write32(0, 7)
    }
    let m = FakeMmio::<4>::new();
    poke(&m);
    assert_eq!(m.peek32(0), 7);
}

/// A wait ends at its bound, polls the condition once more after it, and
/// returns as soon as the condition holds.
#[test]
fn wait_ends_at_the_bound_and_sees_a_late_event() {
    let t = FakeTicks::new(1_000_000, 1);
    let mut polls = 0;
    assert!(!t.wait_us(10, || {
        polls += 1;
        false
    }));
    assert!((11..=13).contains(&polls), "{polls} polls for a 10-tick bound");

    let t = FakeTicks::new(1_000_000, 1);
    let mut n = 0;
    assert!(t.wait_us(10, || {
        n += 1;
        n == 3
    }));
    assert_eq!(n, 3);
    assert_eq!(t.ticks_for_us(5), 5);
    assert_eq!(FakeTicks::new(24_000_000, 1).ticks_for_us(1), 24);
    assert_eq!(FakeTicks::new(32_768, 1).ticks_for_us(1), 1, "rounded up");
}
