// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the pure helpers in `crates/core/libsys`.
//!
//! **Scope, stated up front so this is not read as more than it is.** libsys
//! is 2703 lines and most of it is `ecall` wrappers whose correctness *is* the
//! syscall ABI — and that is already checked from ring 3 by `abitest`, with 75
//! assertions against the real kernel. Unit-testing a wrapper on the host
//! would exercise a function that cannot make the call it exists to make, and
//! would add a number without adding evidence.
//!
//! What is left is small and worth pinning: the arithmetic and the byte
//! layouts, where a mistake is silent because the syscall still succeeds.
//!
//! The functions are re-implemented here by inclusion, not by copy: the module
//! is pulled with `#[path]` so the code under test is the code that ships.

// The real file, pulled in. The full `lib.rs` cannot be `#[path]`-pulled --
// it is `#![no_std]` and its wrappers contain `ecall`, which does not
// assemble on aarch64 -- so the pure helpers live in their own module and this
// is that module, not a copy of it.
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/core/libsys/src/pure.rs"]
mod libsys;

#[cfg(test)]
mod clock {
    use super::libsys::ticks_to_ns;

    /// **The overflow the two-step form exists to avoid.** `t * 1e9 / hz`
    /// overflows u64 after ~30 minutes at 10 MHz. This checks the boundary
    /// directly: a tick count well past where the naive form dies must still
    /// convert, and must convert *correctly*.
    #[test]
    fn a_tick_count_that_overflows_the_naive_form_still_converts() {
        const HZ: u64 = 10_000_000;
        // Where `t * 1e9` overflows: t > u64::MAX / 1e9 ~= 1.8e10 ticks,
        // i.e. ~1844 s ~= 30 min at 10 MHz.
        let t = 3_600 * HZ;                 // one hour
        assert_eq!(ticks_to_ns(t, HZ), 3_600_000_000_000);
        let t = 86_400 * HZ;                // one day
        assert_eq!(ticks_to_ns(t, HZ), 86_400_000_000_000);
    }

    /// Monotonicity across the boundary: the clock must never go backwards.
    /// A wrapping multiply does not fail loudly — it returns a smaller number
    /// than the previous call, and a control loop reads that as negative
    /// elapsed time.
    #[test]
    fn the_clock_never_goes_backwards() {
        const HZ: u64 = 10_000_000;
        let mut prev = 0u64;
        // Step through the 30-minute cliff and well past it.
        for s in [0u64, 1, 1_000, 1_800, 1_844, 1_845, 2_000, 100_000] {
            let ns = ticks_to_ns(s * HZ, HZ);
            assert!(ns >= prev, "went backwards at {s}s: {prev} then {ns}");
            prev = ns;
        }
    }

    /// Sub-second precision must survive the division-first form. Rounding the
    /// remainder away would quantise the clock to whole seconds, which is
    /// exactly the 10 ms-granularity problem the vDSO change fixed.
    #[test]
    fn sub_second_precision_is_preserved() {
        const HZ: u64 = 10_000_000;
        assert_eq!(ticks_to_ns(1, HZ), 100, "one tick at 10 MHz is 100 ns");
        assert_eq!(ticks_to_ns(HZ / 2, HZ), 500_000_000, "half a second");
        assert_eq!(ticks_to_ns(HZ / 1000, HZ), 1_000_000, "one millisecond");
    }

    /// A timebase of zero must not divide. It is read from the vDSO page, and
    /// a kernel that has not published one leaves it zero — with
    /// `panic = "abort"` a division there is a board reset.
    #[test]
    fn a_zero_timebase_returns_zero_rather_than_dividing() {
        assert_eq!(ticks_to_ns(12_345, 0), 0);
    }

    /// A 1 GHz timebase, chosen as a test vector rather than as a board.
    /// **The K1 does not run at 1 GHz** — `platform.rs` gives it 24 MHz, from
    /// its DTS. The same stale figure sat in `wcet.rs` justifying a constant
    /// that named the wrong clock entirely. The conversion
    /// must not assume the emulator's value.
    #[test]
    fn other_timebases_convert_correctly() {
        assert_eq!(ticks_to_ns(1_000_000_000, 1_000_000_000), 1_000_000_000);
        assert_eq!(ticks_to_ns(1, 1_000_000_000), 1);
        assert_eq!(ticks_to_ns(3 * 24_000_000, 24_000_000), 3_000_000_000);
    }

    /// **The conversion libsys ships is the kernel's** (RFC-0044), and that
    /// one saturates. A counter past `u64::MAX` nanoseconds must read as the
    /// largest instant, never as a small one: a deadline computed from a
    /// wrapped clock would be in the past, and every sleep would return
    /// `Overrun` at once. The values above are all in range, so none of them
    /// could tell a wrapping copy from the shared function.
    #[test]
    fn a_counter_past_u64_nanoseconds_saturates_rather_than_wrapping() {
        assert_eq!(ticks_to_ns(u64::MAX, 10_000_000), u64::MAX);
        assert_eq!(ticks_to_ns(u64::MAX, 1), u64::MAX);
        // One second past the limit at 1 Hz, where a wrapping multiply lands
        // on a small number.
        assert_eq!(ticks_to_ns(u64::MAX / 1_000_000_000 + 1, 1), u64::MAX);
    }

    /// A deadline ring 3 computes in nanoseconds, converted to ticks the way
    /// the kernel does, is reached no earlier than ring 3's own clock says.
    /// This is what lets abitest assert `vdso_now_ns() >= deadline` after
    /// every `SYS_SLEEP_UNTIL`.
    #[test]
    fn a_deadline_converted_by_the_kernel_reads_back_at_or_after_itself() {
        use azos_abi::time::ns_to_ticks_ceil;
        for hz in [4_000_000u64, 10_000_000, 24_000_000] {
            for ns in [1u64, 99, 10_000_001, 1_000_000_007, 86_400_000_000_123] {
                assert!(ticks_to_ns(ns_to_ticks_ceil(ns, hz), hz) >= ns, "hz={hz} ns={ns}");
            }
        }
    }
}

#[cfg(test)]
mod vdso_flags {
    use super::libsys::{rdtime_is_native, VDSO_FLAG_RDTIME_NATIVE, VDSO_MAGIC};

    /// Bit 0 on a real page is the only thing that says native.
    #[test]
    fn bit_zero_on_a_real_page_is_native() {
        assert!(rdtime_is_native(VDSO_MAGIC, VDSO_FLAG_RDTIME_NATIVE));
        assert!(rdtime_is_native(VDSO_MAGIC, VDSO_FLAG_RDTIME_NATIVE | 0x8000_0000));
    }

    /// The default is the trap: a clear bit, or any other bit, leaves
    /// `uptime()` on `SYS_UPTIME`. A reader that took "flags non-zero" for
    /// native would read `rdtime` where the kernel has not said it is safe.
    #[test]
    fn a_clear_bit_or_another_bit_is_not_native() {
        assert!(!rdtime_is_native(VDSO_MAGIC, 0));
        assert!(!rdtime_is_native(VDSO_MAGIC, 0b10));
        assert!(!rdtime_is_native(VDSO_MAGIC, 0xFFFF_FFFE));
    }

    /// A page with the wrong magic is not a vDSO page, whatever its bytes say.
    #[test]
    fn a_page_with_the_wrong_magic_is_not_native() {
        assert!(!rdtime_is_native(0, VDSO_FLAG_RDTIME_NATIVE));
        assert!(!rdtime_is_native(VDSO_MAGIC ^ 1, u32::MAX));
    }

    /// The values libsys mirrors from `crates/core/mm/src/vdso.rs`.
    #[test]
    fn the_mirrored_constants_match_the_kernel_page() {
        assert_eq!(VDSO_MAGIC, 0x5644_534F, "\"VDSO\"");
        assert_eq!(VDSO_FLAG_RDTIME_NATIVE, 1);
    }
}

#[cfg(test)]
mod sockaddr {
    use super::libsys::{sockaddr_in, has_nul};

    /// **The family is little-endian and the port is big-endian, in the same
    /// struct.** Getting them the same way round is the classic mistake, it
    /// compiles, the syscall succeeds, and the packet goes to the wrong port.
    /// `abitest` proved this shape matters from ring 3; this pins the bytes.
    #[test]
    fn family_is_le_and_port_is_be() {
        let sa = sockaddr_in([10, 0, 2, 15], 0x1234);
        assert_eq!(&sa[0..2], &[2, 0], "AF_INET=2 little-endian");
        assert_eq!(&sa[2..4], &[0x12, 0x34], "port big-endian (network order)");
        assert_eq!(&sa[4..8], &[10, 0, 2, 15], "address in wire order");
        assert!(sa[8..].iter().all(|&b| b == 0), "tail must be zeroed");
    }

    /// A port whose two bytes differ is the only case that can tell the byte
    /// orders apart; 0 or 0x0101 would pass either way round.
    #[test]
    fn an_asymmetric_port_pins_the_order() {
        assert_eq!(&sockaddr_in([0; 4], 7)[2..4], &[0, 7]);
        assert_eq!(&sockaddr_in([0; 4], 0xFF00)[2..4], &[0xFF, 0]);
    }

    /// `has_nul` asks *contains*, not *ends with*: the kernel's
    /// `copy_cstr_from_user` stops at the first zero, so a 256-byte scratch
    /// buffer holding a short path plus slack is legal and must be accepted.
    /// Requiring a terminator at the end would reject every real caller.
    #[test]
    fn has_nul_means_contains_not_ends_with() {
        assert!(has_nul(b"/fat/X\0"), "trailing NUL");
        let mut padded = [0u8; 32];
        padded[..7].copy_from_slice(b"/fat/X\0");
        assert!(has_nul(&padded), "NUL followed by slack is still terminated");
        assert!(has_nul(b"\0abc"), "NUL first");
        assert!(!has_nul(b"/fat/X"), "no NUL anywhere must be rejected");
        assert!(!has_nul(b""), "empty slice has no NUL");
    }
}

/// The SPSC ring's decisions (wave 6): when a side may enter the kernel.
///
/// Single-threaded, so these pin the protocol's decisions, not its
/// concurrency; the two-task run is `vsbench`'s `ring-stream`, whose printed
/// kernel-entry count is the same property measured.
#[cfg(test)]
mod spsc_ring {
    use azos_spsc::{RingSleep, RingStep, SpscRing, RING_HEAD, RING_TAIL};

    #[repr(C, align(64))]
    struct Buf([u8; 4096]);

    fn ring(buf: &mut Buf, cap: u32) -> SpscRing {
        let r = SpscRing { base: buf.0.as_mut_ptr() as usize, cap };
        r.init();
        r
    }

    #[test]
    fn a_ring_that_is_neither_empty_nor_full_never_asks_for_the_kernel() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 8);
        for i in 0..8 { assert_eq!(r.try_push(i), RingStep::Done, "push {i}"); }
        assert_eq!(r.try_push(99), RingStep::Blocked, "full at capacity");
        for i in 0..8 { assert_eq!(r.try_pop(), (RingStep::Done, i), "FIFO"); }
        assert_eq!(r.try_pop().0, RingStep::Blocked, "empty");
    }

    #[test]
    fn a_consumer_that_announced_sleep_is_woken_by_the_next_push_only() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 8);
        assert_eq!(r.consumer_sleep(), RingSleep::Wait { addr: r.base + RING_HEAD, expected: 0 });
        assert_eq!(r.try_push(1), RingStep::DoneWake { addr: r.base + RING_HEAD });
        assert_eq!(r.try_push(2), RingStep::Done, "the flag was consumed by the first wake");
    }

    #[test]
    fn a_producer_that_announced_sleep_is_woken_by_the_next_pop_only() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 4);
        for i in 0..4 { r.try_push(i); }
        assert_eq!(r.producer_sleep(), RingSleep::Wait { addr: r.base + RING_TAIL, expected: 0 });
        assert_eq!(r.try_pop(), (RingStep::DoneWake { addr: r.base + RING_TAIL }, 0));
        assert_eq!(r.try_pop(), (RingStep::Done, 1));
    }

    #[test]
    fn a_sleeper_rechecks_after_announcing_and_retries_instead_of_sleeping() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 4);
        r.try_push(5);
        assert_eq!(r.consumer_sleep(), RingSleep::Retry, "not empty: no kernel entry");
        assert_eq!(r.try_push(6), RingStep::Done, "a withdrawn announcement costs no wake");
        let mut b2 = Buf([0; 4096]);
        let q = ring(&mut b2, 4);
        assert_eq!(q.producer_sleep(), RingSleep::Retry, "not full: no kernel entry");
    }

    #[test]
    fn a_woken_sleeper_withdraws_its_announcement() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 4);
        assert!(matches!(r.consumer_sleep(), RingSleep::Wait { .. }));
        r.consumer_woke();
        assert_eq!(r.try_push(1), RingStep::Done);
    }

    #[test]
    fn indices_wrap_through_u32_max() {
        let mut b = Buf([0; 4096]);
        let r = ring(&mut b, 4);
        let near = u32::MAX - 1;
        unsafe {
            core::ptr::write((r.base + RING_HEAD) as *mut u32, near);
            core::ptr::write((r.base + RING_TAIL) as *mut u32, near);
        }
        for i in 0..4 { assert_eq!(r.try_push(i), RingStep::Done); }
        assert_eq!(r.try_push(9), RingStep::Blocked);
        assert_eq!(r.len(), 4);
        for i in 0..4 { assert_eq!(r.try_pop(), (RingStep::Done, i)); }
    }

    // `SpscSlots<W>`: the same protocol with a `W`-word slot (wave 11,
    // SHMRING). The index code is shared with `SpscRing`, so these pin what
    // is new: whole slots move intact, slots do not overlap, and the wake
    // decisions are the same ones.
    use azos_spsc::SpscSlots;

    fn slots(buf: &mut Buf, cap: u32) -> SpscSlots<8> {
        let r = SpscSlots::<8> { base: buf.0.as_mut_ptr() as usize, cap };
        r.init();
        r
    }

    fn item(i: u64) -> [u64; 8] { core::array::from_fn(|k| (i << 8) | k as u64) }

    #[test]
    fn a_slot_ring_moves_whole_64_byte_items_in_order() {
        let mut b = Buf([0; 4096]);
        let r = slots(&mut b, 16);
        assert_eq!(SpscSlots::<8>::bytes(16), 256 + 16 * 64);
        for i in 0..16 { assert_eq!(r.try_push(&item(i)), RingStep::Done, "push {i}"); }
        assert_eq!(r.try_push(&item(99)), RingStep::Blocked, "full at capacity");
        let mut out = [0u64; 8];
        for i in 0..16 {
            assert_eq!(r.try_pop(&mut out), RingStep::Done);
            assert_eq!(out, item(i), "slot {i} intact and not overlapped");
        }
        assert_eq!(r.try_pop(&mut out), RingStep::Blocked, "empty");
    }

    #[test]
    fn a_slot_ring_wakes_only_an_announced_sleeper_once() {
        let mut b = Buf([0; 4096]);
        let r = slots(&mut b, 16);
        assert_eq!(r.consumer_sleep(), RingSleep::Wait { addr: r.base + RING_HEAD, expected: 0 });
        assert_eq!(r.try_push(&item(1)), RingStep::DoneWake { addr: r.base + RING_HEAD });
        // A batch after the first push: no further doorbell.
        for i in 2..9 { assert_eq!(r.try_push(&item(i)), RingStep::Done, "suppressed {i}"); }
        let mut q = Buf([0; 4096]);
        let f = slots(&mut q, 4);
        for i in 0..4 { f.try_push(&item(i)); }
        assert_eq!(f.producer_sleep(), RingSleep::Wait { addr: f.base + RING_TAIL, expected: 0 });
        let mut out = [0u64; 8];
        assert_eq!(f.try_pop(&mut out), RingStep::DoneWake { addr: f.base + RING_TAIL });
        assert_eq!(f.try_pop(&mut out), RingStep::Done);
    }

    #[test]
    fn a_slot_ring_wraps_through_u32_max() {
        let mut b = Buf([0; 4096]);
        let r = slots(&mut b, 4);
        unsafe {
            core::ptr::write((r.base + RING_HEAD) as *mut u32, u32::MAX - 1);
            core::ptr::write((r.base + RING_TAIL) as *mut u32, u32::MAX - 1);
        }
        for i in 0..4 { assert_eq!(r.try_push(&item(i)), RingStep::Done); }
        assert_eq!(r.try_push(&item(9)), RingStep::Blocked);
        assert_eq!(r.len(), 4);
        let mut out = [0u64; 8];
        for i in 0..4 { r.try_pop(&mut out); assert_eq!(out, item(i)); }
    }
}

/// Byte-slot rings with a kernel-style producer (wave 11, SHMRING):
/// `azos_spsc::{SpscBytes, BytesProducer}`.
#[cfg(test)]
mod spsc_bytes {
    use azos_spsc::{BytesProducer, Publish, RingSleep, RingStep, SpscBytes, RING_HEAD, RING_TAIL};

    const CAP: u32 = 4;
    const SLOT: u32 = 64;

    #[repr(C, align(64))]
    struct Buf([u8; 4096]);

    fn ring(b: &mut Buf) -> SpscBytes {
        SpscBytes { base: b.0.as_mut_ptr() as usize, cap: CAP, slot_bytes: SLOT }
    }

    #[test]
    fn items_arrive_intact_in_order_with_their_seq_and_stamp() {
        let mut b = Buf([0; 4096]);
        let mut p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        assert_eq!(p.push(7, b"abc"), Publish::Done);
        assert_eq!(p.push(8, &[9u8; 48]), Publish::Done);
        let mut out = [0u8; 64];
        let (st, info) = r.try_pop(&mut out);
        assert_eq!((st, info.len, info.seq, info.acq_ns), (RingStep::Done, 3, 0, 7));
        assert_eq!(&out[..3], b"abc");
        let (_, info) = r.try_pop(&mut out);
        assert_eq!((info.len, info.seq, info.acq_ns), (48, 1, 8));
        assert_eq!(&out[..48], &[9u8; 48]);
        assert_eq!(r.try_pop(&mut out).0, RingStep::Blocked);
    }

    #[test]
    fn a_payload_is_clamped_to_its_slot() {
        let mut b = Buf([0; 4096]);
        let mut p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        p.push(0, &[1u8; 200]);
        let mut out = [0u8; 256];
        let (_, info) = r.try_pop(&mut out);
        assert_eq!(info.len as usize, r.payload_max());
        assert_eq!(out[r.payload_max()], 0, "nothing past the slot's room was copied");
    }

    #[test]
    fn a_full_ring_drops_the_newest_and_never_blocks() {
        let mut b = Buf([0; 4096]);
        let mut p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        for i in 0..CAP { assert_eq!(p.push(0, &[i as u8]), Publish::Done); }
        assert_eq!(p.push(0, b"x"), Publish::Dropped);
        assert_eq!(p.push(0, b"y"), Publish::Dropped);
        assert_eq!((p.drops(), r.drops()), (2, 2), "counted, and visible to the consumer");
        let mut out = [0u8; 8];
        for i in 0..CAP {
            let (_, info) = r.try_pop(&mut out);
            assert_eq!((info.seq, out[0]), (i, i as u8), "the queued items, not the dropped ones");
        }
        assert_eq!(p.push(0, b"z"), Publish::Done);
        let (_, info) = r.try_pop(&mut out);
        assert_eq!(info.seq, CAP + 2, "the gap shows the two drops");
    }

    #[test]
    fn the_doorbell_rings_once_per_sleep_not_per_item() {
        let mut b = Buf([0; 4096]);
        let mut p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        assert_eq!(r.consumer_sleep(), RingSleep::Wait { addr: r.base + RING_HEAD, expected: 0 });
        assert_eq!(p.push(0, b"a"), Publish::Wake);
        assert_eq!(p.push(0, b"b"), Publish::Done);
        assert_eq!(p.push(0, b"c"), Publish::Done);
        assert_eq!(p.wakes(), 1);
    }

    #[test]
    fn a_consumer_builds_its_view_from_the_header_and_refuses_a_bad_one() {
        let mut b = Buf([0; 4096]);
        let p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        let v = SpscBytes::from_header(r.base, 4096).expect("the producer's geometry");
        assert_eq!((v.cap, v.slot_bytes), (CAP, SLOT));
        assert!(SpscBytes::from_header(r.base, 256).is_none(), "does not fit the mapping");
        unsafe { core::ptr::write((r.base + azos_spsc::RING_GEOM_CAP) as *mut u32, 3) };
        assert!(SpscBytes::from_header(r.base, 4096).is_none(), "cap not a power of two");
    }

    #[test]
    fn the_producer_publishes_its_wake_count_in_the_header() {
        let mut b = Buf([0; 4096]);
        let mut p = BytesProducer::new(ring(&mut b));
        let r = *p.ring();
        let mut out = [0u8; 8];
        r.consumer_sleep();
        p.push(0, b"a");
        r.try_pop(&mut out);
        r.consumer_sleep();
        p.push(0, b"b");
        assert_eq!((p.wakes(), r.wakes()), (2, 2));
    }

    #[test]
    fn a_hostile_tail_only_costs_its_own_stream() {
        let mut b = Buf([0xEE; 4096]);
        let r = ring(&mut b);
        let end = SpscBytes::bytes(CAP, SLOT);
        let mut p = BytesProducer::new(r);
        for bad in [5u32, u32::MAX / 2, 0xDEAD_BEEF] {
            unsafe { core::ptr::write((r.base + RING_TAIL) as *mut u32, bad) };
            for _ in 0..8 { let _ = p.push(0, &[0x11; 64]); }
        }
        assert!(b.0[end..].iter().all(|&x| x == 0xEE), "nothing written past the ring");
        assert!(p.drops() > 0, "a garbage tail reads as full");
        // A tail the consumer resets to the producer's head gives the
        // stream back.
        let head = unsafe { core::ptr::read((r.base + RING_HEAD) as *const u32) };
        unsafe { core::ptr::write((r.base + RING_TAIL) as *mut u32, head) };
        assert_eq!(p.push(0, b"ok"), Publish::Done);
    }
}

/// RFC-0055 (wave 11): the process fd table `dup`/`dup2` live in, and the
/// startup-block string helpers.
#[cfg(test)]
mod fd_table {
    use super::libsys::{cstr_at, env_lookup, FdEntry, FdTable};
    use azos_abi::ushell::{StartupFd, FD_CONSOLE, FD_HANDLE};

    #[test]
    fn without_a_startup_block_one_and_two_are_the_console() {
        let t = FdTable::new();
        assert_eq!(t.fd_slot(0), FdEntry::Closed);
        assert_eq!(t.fd_slot(1), FdEntry::Console);
        assert_eq!(t.fd_slot(2), FdEntry::Console);
        assert_eq!(t.fd_slot(99), FdEntry::Closed);
    }

    #[test]
    fn a_startup_block_sets_every_fd_and_aliases_one_handle() {
        let mut fds = [StartupFd::default(); 8];
        fds[0] = StartupFd { kind: FD_HANDLE, handle: 0x55 };
        fds[1] = StartupFd { kind: FD_HANDLE, handle: 0x77 };
        fds[2] = StartupFd { kind: FD_HANDLE, handle: 0x77 };
        fds[3] = StartupFd { kind: FD_CONSOLE, handle: 0 };
        let mut t = FdTable::fd_table_from_startup(&fds);
        assert_eq!(t.fd_slot(1), FdEntry::Handle(0x77));
        assert_eq!(t.fd_slot(3), FdEntry::Console);
        // `> f 2>&1`: one handle, two fds. Only the last close reaches the
        // kernel.
        assert_eq!(t.fd_release(1), None);
        assert_eq!(t.fd_release(2), Some(0x77));
        assert_eq!(t.fd_release(2), None, "closing a closed fd closes nothing");
    }

    /// **Canary.** Make `fd_release` return the handle on every close: the
    /// first assertion below sees `Some`.
    #[test]
    fn dup_and_dup2_alias_without_a_second_kernel_close() {
        let mut t = FdTable::new();
        t.fd_put_handle(3, 0x10);
        let d = t.fd_alias(3).unwrap();
        assert_eq!(d, 0, "the lowest closed fd");
        assert_eq!(t.fd_release(3), None, "fd 0 still names it");
        assert_eq!(t.fd_release(0), Some(0x10));
        t.fd_put_handle(4, 0x20);
        t.fd_put_handle(5, 0x30);
        assert_eq!(t.fd_alias_to(4, 5), Ok(Some(0x30)), "dup2 over the last fd of 0x30 closes it");
        assert_eq!(t.fd_slot(5), FdEntry::Handle(0x20));
        assert_eq!(t.fd_alias_to(4, 4), Ok(None));
        assert_eq!(t.fd_alias_to(6, 1), Err(()), "dup2 of a closed fd");
        assert_eq!(t.fd_alias_to(4, 8), Err(()), "past the table");
        // dup2 onto an fd that already names the same handle closes nothing.
        assert_eq!(t.fd_alias_to(5, 4), Ok(None));
    }

    #[test]
    fn strings_in_a_blob() {
        let blob = b"args\0two words\0\0";
        assert_eq!(cstr_at(blob, 0), Some(&b"args"[..]));
        assert_eq!(cstr_at(blob, 1), Some(&b"two words"[..]));
        assert_eq!(cstr_at(blob, 2), Some(&b""[..]));
        assert_eq!(cstr_at(blob, 3), None);
        let env = b"FOO=bar\0PATH=/fat\0FOOX=1\0";
        assert_eq!(env_lookup(env, b"FOO"), Some(&b"bar"[..]));
        assert_eq!(env_lookup(env, b"PATH"), Some(&b"/fat"[..]));
        assert_eq!(env_lookup(env, b"FO"), None, "a prefix is not a key");
        assert_eq!(env_lookup(b"A=1", b"A"), None, "an unterminated blob is not read");
    }
}
