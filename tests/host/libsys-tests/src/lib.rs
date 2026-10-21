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

// The ring-3 view of the io_ring page, pulled in as shipped (no syscalls in it).
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/core/libsys/src/ioring.rs"]
mod ioring;

// The kernel log sink's file ring (`userspace/services/logd`, Kconfig KLOG):
// the wire both ends share, and the pure store policy, as shipped.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;
#[allow(dead_code)]
#[path = "../../../../userspace/services/logd/src/store.rs"]
mod store;

// The toolbox's `log` tool: the filter and the layout of what it prints.
#[allow(dead_code)]
#[path = "../../../../userspace/services/toolbox/src/log_view.rs"]
mod log_view;

#[cfg(test)]
mod logd_store;
#[cfg(test)]
mod log_tool;

#[cfg(test)]
mod capdir;

#[cfg(test)]
mod ioring_open {
    use super::ioring::{Ring, RingError};

    /// An address the create did not give is refused before any use.
    /// Canary: drop the alignment/zero test and these two cases go red.
    #[test]
    fn a_missing_or_unaligned_page_is_refused() {
        assert_eq!(Ring::open(7, 0u64.to_le_bytes()).err(), Some(RingError::NoPage));
        assert_eq!(Ring::open(7, 4100u64.to_le_bytes()).err(), Some(RingError::NoPage));
    }

    /// A page-aligned address opens and keeps the capability and address.
    #[test]
    fn a_page_aligned_address_opens() {
        let r = Ring::open(7, 0x1000u64.to_le_bytes()).expect("aligned");
        assert_eq!((r.cap, r.va), (7, 0x1000));
    }
}

/// The entries the registered-buffer pushes write, read back as the kernel's
/// `SqEntry` (`opcode`/`flags` at 0/2, `param0..2` at 4/8/12, `addr`/`reg` at
/// 16/18) lays them out.
#[cfg(test)]
mod ioring_regbuf {
    use super::ioring::{Ring, OP_BUF_REGISTER, OP_BUF_UNREGISTER, OP_NET_RECV, SQE_F_FIXED, SQE_F_LINK, SQ_ENTRIES};

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    fn entry(page: &Page, i: usize) -> (u16, u16, u32, u32, u32, u16, u16, u64) {
        let b = &page.0[SQ_ENTRIES + i * 32..SQ_ENTRIES + (i + 1) * 32];
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        (u16_at(0), u16_at(2), u32_at(4), u32_at(8), u32_at(12), u16_at(16), u16_at(18),
         u64::from_le_bytes(b[24..32].try_into().unwrap()))
    }

    /// A fixed push sets `SQE_F_FIXED`, keeps the caller's flags, and puts the
    /// slot in `reg` with `addr` clear; the register pushes put the slot in the
    /// same field. **Canary:** write the slot into `addr`: every `reg` line goes red.
    #[test]
    fn the_buffer_pushes_name_the_slot_in_reg_and_set_the_fixed_flag() {
        let mut page = Box::new(Page([0; 4096]));
        let ring = Ring::open(1, (page.0.as_mut_ptr() as u64).to_le_bytes()).expect("aligned");
        assert!(ring.push_register(0x31, 100, 512, 2, 7));
        assert!(ring.push_fixed(OP_NET_RECV, 0x78, 2, 8, 64, SQE_F_LINK, 8));
        assert!(ring.push_unregister(2, 9));
        assert_eq!(entry(&page, 0), (OP_BUF_REGISTER, 0, 0x31, 100, 512, 0, 2, 7));
        assert_eq!(entry(&page, 1), (OP_NET_RECV, SQE_F_FIXED | SQE_F_LINK, 0x78, 8, 64, 0, 2, 8));
        assert_eq!(entry(&page, 2), (OP_BUF_UNREGISTER, 0, 0, 0, 0, 0, 2, 9));
        // The ordinary push still writes no flags and clears the sector words.
        assert!(ring.push(OP_NET_RECV, 1, 2, 3, 4));
        assert_eq!(entry(&page, 3), (OP_NET_RECV, 0, 1, 2, 3, 0, 0, 4));
    }
}

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

    /// **The conversion libsys ships is the kernel's** (absolute sleep), and that
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
    /// `uptime()` on `DOMAIN_UPTIME`. A reader that took "flags non-zero" for
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
    use azos_rings::region::{RingSleep, RingStep, SpscRing, RING_HEAD, RING_TAIL};

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
    use azos_rings::region::SpscSlots;

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
/// `azos_rings::region::{SpscBytes, BytesProducer}`.
#[cfg(test)]
mod spsc_bytes {
    use azos_rings::region::{BytesProducer, Publish, RingSleep, RingStep, SpscBytes, RING_HEAD, RING_TAIL};

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
        unsafe { core::ptr::write((r.base + azos_rings::region::RING_GEOM_CAP) as *mut u32, 3) };
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

/// The process fd table `dup`/`dup2` live in, and the
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

/// `azos_rings::region::trace`: the kernel tracer's per-CPU record rings (wave 15).
#[cfg(test)]
mod trace_ring;

/// `crates/core/trace/src/jump.rs`: static-key sites and encoders (wave 15).
#[cfg(test)]
mod jump_sites;

#[cfg(test)]
mod port_event {
    use super::libsys::{port_event_decode, PortEventInfo};

    /// **The 16-byte port event decodes key, type, code and source id from
    /// their wire offsets** (wave 15 N5b: the code is bytes 10..12, where the
    /// padding was). Canary: read the code from byte 9: `code` reads 0x1500.
    #[test]
    fn a_no_senders_event_decodes_its_code_from_bytes_10_and_11() {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        b[8] = azos_abi::syscall_nr::PORT_EVENT_NO_SENDERS;
        b[10..12].copy_from_slice(&(azos_abi::error::Errno::ENOSENDERS as u16).to_le_bytes());
        b[12..16].copy_from_slice(&0xABCDu32.to_le_bytes());
        assert_eq!(
            port_event_decode(&b),
            PortEventInfo { key: 0x1122_3344_5566_7788, source_type: 5, code: 213, cpu: 0, source_id: 0xABCD }
        );
    }

    /// **An IRQ event carries the CPU its line is routed to in byte 9** (where
    /// the padding was), apart from the code. Canary: read the CPU from byte 10:
    /// `cpu` reads 0 and `code` keeps the CPU's bytes.
    #[test]
    fn an_irq_event_decodes_its_cpu_from_byte_9() {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&0x55u64.to_le_bytes());
        b[8] = azos_abi::syscall_nr::PORT_EVENT_IRQ;
        b[azos_abi::syscall_nr::PORT_EVENT_CPU_OFFSET] = 3;
        b[12..16].copy_from_slice(&33u32.to_le_bytes());
        assert_eq!(
            port_event_decode(&b),
            PortEventInfo { key: 0x55, source_type: azos_abi::syscall_nr::PORT_EVENT_IRQ, code: 0, cpu: 3, source_id: 33 }
        );
    }
}

/// `clock_now`: MONO reads the monotonic reader, REAL, TAI and BOOT add the
/// vDSO's offsets to it, every other id is refused without reading any clock.
#[cfg(test)]
mod clock_now {
    use super::libsys::{clock_now_with, ClockError, ClockId, ClockOffsets};
    use core::cell::Cell;

    const OFFSETS: ClockOffsets = ClockOffsets { real: 1_000, tai: 1_037, boot: 7 };

    /// Reads on `id` with a monotonic reading of 42; the counts of reads of
    /// each reader.
    fn read(id: ClockId, offsets: ClockOffsets) -> (Result<u64, ClockError>, u32, u32) {
        let (m, o) = (Cell::new(0u32), Cell::new(0u32));
        let r = clock_now_with(
            id,
            || {
                m.set(m.get() + 1);
                42
            },
            || {
                o.set(o.get() + 1);
                offsets
            },
        );
        (r, m.get(), o.get())
    }

    #[test]
    fn mono_reads_the_reader_and_no_offset() {
        assert_eq!(read(ClockId::MONO, OFFSETS), (Ok(42), 1, 0));
    }

    /// **Canary.** Each served clock adds its own offset: swapping two of the
    /// offsets, or serving TAI as REAL, changes a row.
    #[test]
    fn real_tai_and_boot_add_their_own_offset() {
        assert_eq!(read(ClockId::REAL, OFFSETS), (Ok(42 + 1_000), 1, 1));
        assert_eq!(read(ClockId::TAI, OFFSETS), (Ok(42 + 1_037), 1, 1));
        assert_eq!(read(ClockId::BOOT, OFFSETS), (Ok(42 + 7), 1, 1));
        // Nothing set: every clock is the monotonic one.
        for id in [ClockId::REAL, ClockId::TAI, ClockId::BOOT] {
            assert_eq!(read(id, ClockOffsets::ZERO).0, Ok(42), "{id:?}");
        }
        // Saturates instead of wrapping.
        let huge = ClockOffsets { tai: u64::MAX, ..OFFSETS };
        assert_eq!(read(ClockId::TAI, huge).0, Ok(u64::MAX));
    }

    #[test]
    fn a_reserved_clock_is_unsupported_and_reads_nothing() {
        for id in [ClockId::TSC_RAW, ClockId::ptp(0), ClockId::tsn_domain(1), ClockId::vcpu(2), ClockId(0x00FF_FFFF), ClockId(0xFF00_0000), ClockId::new(ClockId::KIND_TAI, 1)] {
            assert_eq!(read(id, OFFSETS), (Err(ClockError::Unsupported), 0, 0), "{id:?}");
        }
    }
}

/// The clock offsets the vDSO publishes: the seqlock that carries them, the
/// leap table that turns REAL into TAI, and the BOOT word a sync leaves alone.
#[cfg(test)]
mod clock_offsets {
    use super::libsys::{ClockId, ClockOffsets, ClockWords, clock_now_with};
    use azos_abi::time::{tai_minus_utc, NS_PER_SEC};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The TAI-UTC table as the topology's `[clock]` row hands it over.
    const LEAPS: [(u64, u16); 3] = [(63_072_000, 10), (1_435_708_800, 36), (1_483_228_800, 37)];

    #[test]
    fn the_leap_table_gives_tai_minus_utc() {
        assert_eq!(tai_minus_utc(LEAPS, 63_071_999), None, "before the table");
        assert_eq!(tai_minus_utc(LEAPS, 63_072_000), Some(10), "its first second");
        assert_eq!(tai_minus_utc(LEAPS, 1_435_708_799), Some(10), "the second before the leap");
        assert_eq!(tai_minus_utc(LEAPS, 1_435_708_800), Some(36), "the leap's own second");
        assert_eq!(tai_minus_utc(LEAPS, 1_483_228_800), Some(37));
        assert_eq!(tai_minus_utc(LEAPS, u64::MAX), Some(37), "after the last entry");
        assert_eq!(tai_minus_utc([], 1_700_000_000), None, "an empty table");
        // A negative leap second (the offset goes down by one) is just a row.
        assert_eq!(tai_minus_utc([(0, 37), (100, 36)], 150), Some(36));
    }

    /// **Canary.** TAI = REAL + the leap offset in force at that UTC second,
    /// to the nanosecond, and both are the monotonic clock plus a constant:
    /// off by the table lookup (the wrong row, or none) fails the TAI rows.
    #[test]
    fn tai_is_real_plus_the_leap_offset() {
        let mono = 5 * NS_PER_SEC + 123;
        let unix = 1_700_000_000 * NS_PER_SEC + 456_789;
        let o = ClockOffsets::ZERO.with_wall(mono, unix, LEAPS);
        assert_eq!(o.real, unix - mono);
        assert_eq!(o.tai, o.real + 37 * NS_PER_SEC);
        // Read back through the clock reader, a second of monotonic time later.
        let later = mono + NS_PER_SEC;
        let at = |id| clock_now_with(id, || later, || o).unwrap();
        assert_eq!(at(ClockId::REAL), unix + NS_PER_SEC);
        assert_eq!(at(ClockId::TAI), unix + NS_PER_SEC + 37 * NS_PER_SEC);
        assert_eq!(at(ClockId::TAI) - at(ClockId::REAL), 37 * NS_PER_SEC);
        // The monotonic clock never moved.
        assert_eq!(at(ClockId::MONO), later);
        // An older wall time gets the older row.
        let old = ClockOffsets::ZERO.with_wall(0, 1_400_000_000 * NS_PER_SEC, LEAPS);
        assert_eq!(old.tai - old.real, 10 * NS_PER_SEC);
        // No table, or one that starts later: TAI equals UTC.
        assert_eq!(ClockOffsets::ZERO.with_wall(0, unix, []).tai, unix);
        assert_eq!(ClockOffsets::ZERO.with_wall(0, 10 * NS_PER_SEC, LEAPS).tai, 10 * NS_PER_SEC);
    }

    /// A wall-clock sync sets REAL and TAI and leaves BOOT alone: the time a
    /// machine slept does not change because its clock was corrected.
    /// **Canary:** `with_wall` clearing `boot` fails the second row.
    #[test]
    fn a_wall_sync_keeps_the_boot_offset() {
        let slept = ClockOffsets { real: 0, tai: 0, boot: 100 * NS_PER_SEC };
        let o = slept.with_wall(30 * NS_PER_SEC, 1_700_000_100 * NS_PER_SEC, LEAPS);
        assert_eq!((o.boot, o.real), (100 * NS_PER_SEC, 1_700_000_100 * NS_PER_SEC - 30 * NS_PER_SEC));
        let at = |id, mono: u64| clock_now_with(id, || mono, || o).unwrap();
        assert_eq!(at(ClockId::BOOT, 30 * NS_PER_SEC), 130 * NS_PER_SEC);
        assert_eq!(at(ClockId::REAL, 30 * NS_PER_SEC), 1_700_000_100 * NS_PER_SEC);
    }

    /// The writer keeps three words that move together; a reader running
    /// concurrently must never see a mix of two updates. The model writer
    /// sets `(n, n + 1, n + 2)`, so any mixed read breaks the pattern.
    /// **Canary:** with the generation re-check removed from `read`, this
    /// fails within a few thousand reads.
    #[test]
    fn offsets_read_consistently_under_update() {
        /// Stops the writers however the reader ends (a failed assert too).
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let words = ClockWords::new();
        let stop = AtomicBool::new(false);
        std::thread::scope(|sc| {
            let _stop = Stop(&stop);
            sc.spawn(|| {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    words.update(|_| ClockOffsets { real: n, tai: n + 1, boot: n + 2 });
                    // Rare in life; here a short pause between writes, so the
                    // reader is not starved by a writer that never leaves the
                    // window yet the windows are still hit.
                    for _ in 0..8 {
                        core::hint::spin_loop();
                    }
                }
            });
            // A second writer: writers exclude each other.
            sc.spawn(|| {
                let mut n = 1u64 << 40;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    words.update(|_| ClockOffsets { real: n, tai: n + 1, boot: n + 2 });
                    for _ in 0..8 {
                        core::hint::spin_loop();
                    }
                }
            });
            let mut last = [0u64; 2];
            // Read for a while, once both writers are running.
            while words.read() == ClockOffsets::ZERO {
                std::thread::yield_now();
            }
            let until = std::time::Instant::now() + std::time::Duration::from_millis(300);
            let mut reads = 0u64;
            while std::time::Instant::now() < until {
                reads += 1;
                let o = words.read();
                if o == ClockOffsets::ZERO {
                    continue; // before the first write
                }
                assert_eq!((o.tai, o.boot), (o.real + 1, o.real + 2), "torn read {o:?}");
                // Each writer's own sequence only moves forward.
                let w = (o.real >> 40) as usize & 1;
                {
                    assert!(o.real >= last[w], "went back: {} after {}", o.real, last[w]);
                    last[w] = o.real;
                }
            }
            assert!(reads > 1000, "only {reads} reads");
        });
    }

    #[test]
    fn update_sees_the_current_offsets_and_a_fresh_page_is_zero() {
        let words = ClockWords::new();
        assert_eq!(words.read(), ClockOffsets::ZERO);
        words.update(|o| ClockOffsets { boot: o.boot + 5, ..o });
        words.update(|o| ClockOffsets { boot: o.boot + 6, ..o });
        assert_eq!(words.read().boot, 11);
        // The page layout is ABI: 32 bytes at 88, 8-aligned.
        assert_eq!(core::mem::size_of::<ClockWords>(), 32);
        assert_eq!(core::mem::align_of::<ClockWords>(), 8);
        assert_eq!(azos_abi::vdso::VDSO_CLOCK_WORDS_OFFSET % 8, 0);
    }

    /// The `clockid_t` table the Linux personality, the Linux runtime and the
    /// C library all read.
    #[test]
    fn posix_clock_ids_map_to_native_clocks() {
        for (id, want) in [
            (0, Some(ClockId::REAL)),
            (1, Some(ClockId::MONO)),
            (4, Some(ClockId::MONO)),
            (5, Some(ClockId::REAL)),
            (6, Some(ClockId::MONO)),
            (7, Some(ClockId::BOOT)),
            (11, Some(ClockId::TAI)),
            (2, None),  // CLOCK_PROCESS_CPUTIME_ID
            (3, None),  // CLOCK_THREAD_CPUTIME_ID
            (8, None),
            (9, None),
            (10, None),
            (12, None),
            (u64::MAX, None),
        ] {
            assert_eq!(ClockId::from_posix(id), want, "clockid {id}");
        }
    }
}

// The TAP runner of the user-code harness (`azos_libsys::utest::run` gives it
// the console).
#[cfg(test)]
mod tap_runner {
    use azos_ktest::{tap, KTest, EARLY, LATE};

    fn ok() -> Result<(), &'static str> {
        Ok(())
    }
    fn bad() -> Result<(), &'static str> {
        Err("it broke")
    }

    static TESTS: [KTest; 4] = [
        KTest { name: "zeta", run: ok, phase: EARLY },
        KTest { name: "alpha", run: bad, phase: EARLY },
        KTest { name: "mid", run: ok, phase: EARLY },
        KTest { name: "late_one", run: ok, phase: LATE },
    ];

    fn report(tests: &'static [KTest]) -> (String, usize) {
        let mut text = String::new();
        let failed = tap::run(tests, &mut |l| text.push_str(l), |t| (t.run)());
        (text, failed)
    }

    /// The tests run in name order, each announces itself before it runs, a
    /// failure carries its reason, and the late test is not this runner's.
    ///
    /// **Canary.** Run in link order (iterate `tests` instead of `nth`): the
    /// numbers below move.
    #[test]
    fn runs_in_name_order_and_reports_tap() {
        let (text, failed) = report(&TESTS);
        assert_eq!(failed, 1);
        assert_eq!(
            text,
            "TAP version 14\n1..3\n# running alpha\nnot ok 1 - alpha # it broke\n# running mid\nok 2 - mid\n\
             # running zeta\nok 3 - zeta\n# 3 tests, 1 failed\n"
        );
    }

    /// A name registered twice is a bail-out before anything runs.
    #[test]
    fn a_duplicate_name_bails_out() {
        static DUP: [KTest; 2] = [KTest { name: "a", run: ok, phase: EARLY }, KTest { name: "a", run: ok, phase: EARLY }];
        let mut ran = 0;
        let mut text = String::new();
        let failed = tap::run(&DUP, &mut |l| text.push_str(l), |_| {
            ran += 1;
            Ok(())
        });
        assert_eq!((failed, ran), (1, 0));
        assert_eq!(text, "TAP version 14\nBail out! test a is registered twice\n");
    }

    /// No test: a plan of zero, no failure.
    #[test]
    fn an_empty_registry_passes() {
        static NONE: [KTest; 0] = [];
        let (text, failed) = report(&NONE);
        assert_eq!(failed, 0);
        assert_eq!(text, "TAP version 14\n1..0\n# 0 tests, 0 failed\n");
    }

    /// A reason longer than a line is cut at a character and the line still
    /// ends with a newline.
    #[test]
    fn a_long_reason_is_cut_not_refused() {
        fn long() -> Result<(), &'static str> {
            Err("é-this reason is far too long for one line of the report, ééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé")
        }
        static T: [KTest; 1] = [KTest { name: "t", run: long, phase: EARLY }];
        let (text, failed) = report(&T);
        assert_eq!(failed, 1);
        let line = text.lines().find(|l| l.starts_with("not ok")).unwrap();
        assert!(line.len() < 192 && line.starts_with("not ok 1 - t # é-this"), "{line}");
        assert!(text.ends_with("# 1 tests, 1 failed\n"));
    }
}
