// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the computation inside the driver class crates
//! (`crates/drivers/<class>`, `domains/robot/drivers`).
//!
//! **WHY.** 11274 lines, zero tests, and it is the crate that touches the
//! hardware: GPIO, PWM, I2C, SPI, VirtIO, MACB, camera, ESC, rangefinder.
//! Going to a board with the driver layer never once unit-tested is the
//! opposite of the order this project wants.
//!
//! **What this can and cannot reach.** Most of the crate is MMIO — reads and
//! writes to device registers that do not exist on a laptop, and whose
//! behaviour is the device's, not ours. What *is* ours is the arithmetic
//! wrapped around them, and that is where a mistake is silent: a control loop
//! that computes the wrong output still writes a perfectly valid PWM register.
//!
//! The modules are pulled in with `#[path]`, so their `crate::` paths resolve
//! to **this** crate. That is why the stand-ins below are plain modules at the
//! root rather than a separate shim crate: `crate::clint::TIMER_FREQ` inside
//! the driver becomes `crate::clint::TIMER_FREQ` here, and the real module
//! never has to change. A driver that names a module of ANOTHER driver class
//! crate (`azos_drv_irqchip::clint::TIMER_FREQ`, `azos_drv_sys::kprintln!`)
//! reaches the same root stand-ins through the `extern crate self` aliases
//! below, one per class crate the pulled files name.


extern crate self as azos_drv_base;
extern crate self as azos_drv_irqchip;
extern crate self as azos_drv_sys;
extern crate self as azos_drv_virtio;
extern crate self as azos_drv_block;
extern crate self as azos_drv_net;
extern crate self as azos_drv_dmac;

/// Stand-in for `crate::clint`, reduced to the one constant the drivers read.
/// QEMU's value, because that is what the rest of the tree calibrates against.
pub mod clint {
    pub const TIMER_FREQ: u64 = 10_000_000;

    /// Monotonic tick source. The block driver uses this for its wall-clock
    /// timeout, so it has to advance -- a constant would make any deadline
    /// either never expire or expire instantly.
    pub fn get_time() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        d.as_nanos() as u64 / 100          // 10 MHz ticks
    }
}

/// Stand-in for `crate::timebase`, the ISA-neutral name the tree's clock
/// reads migrated to (the real one delegates to `azos_arch::cpu::
/// now_ticks`, which is an instruction no host test can execute).
///
/// Delegates to [`clint::get_time`] above so there is ONE clock here: two
/// independent host clocks could disagree, and `blk.rs`'s wall-clock timeout
/// would then expire against a different timebase than the one a test reads.
pub mod timebase {
    /// Mirrors `azos_drv_sys::timebase::TIMER_FREQ`, which re-exports the
    /// same constant this shim already defines next door — one value, two
    /// names, so a test cannot read a different timebase than the code under
    /// test computes against.
    pub use super::clint::TIMER_FREQ;

    #[inline(always)]
    pub fn now() -> u64 {
        super::clint::get_time()
    }
}

/// `kprintln!` on the host. The drivers print diagnostics; swallowing them
/// would hide a message a failing test wants to show.
#[macro_export]
macro_rules! kprintln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}

/// The leveled forms (`crates/drivers/sys/src/uart.rs`): every level prints
/// on the host.
#[macro_export]
macro_rules! kerr {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kwarn {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kinfo {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kdebug {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsoleln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsole {
    ($($arg:tt)*) => { print!($($arg)*) };
}

/// `kprint!` (no newline) on the host. `i2c.rs`'s `i2c_scan` builds its address
/// grid a cell at a time with this, so pulling that module in needs both.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { print!($($arg)*) };
}

#[allow(dead_code)]
#[path = "../../../../crates/drivers/actuator/src/motor_pid.rs"]
mod motor_pid;

#[cfg(test)]
mod pid {
    use super::motor_pid::*;

    /// Proportional-only: output must be Kp x error, and the sign must follow
    /// the error. A sign inversion here drives the motor **away** from the
    /// setpoint — the classic runaway, and it looks like a mechanical fault.
    #[test]
    fn proportional_term_follows_the_error_sign() {
        let mut p = PidController::new(1, 0, 0);
        assert!(p.update(50, 0, 10) > 0, "under target must drive positive");
        let mut p = PidController::new(1, 0, 0);
        assert!(p.update(0, 50, 10) < 0, "over target must drive negative");
        let mut p = PidController::new(1, 0, 0);
        assert_eq!(p.update(0, 0, 10), 0, "no error, no output");
    }

    /// Output must be clamped to the PWM range. An unclamped controller does
    /// not fail here — it hands an out-of-range duty cycle to a register that
    /// silently truncates it, so the motor gets an arbitrary speed.
    #[test]
    fn output_is_clamped_to_the_pwm_range() {
        let mut p = PidController::new(1000, 0, 0);
        let hi = p.update(30_000, 0, 10);
        assert!(hi <= PID_OUTPUT_MAX, "output {hi} exceeds {PID_OUTPUT_MAX}");
        let mut p = PidController::new(1000, 0, 0);
        let lo = p.update(-30_000, 0, 10);
        assert!(lo >= PID_OUTPUT_MIN, "output {lo} below {PID_OUTPUT_MIN}");
    }

    /// **`dt_ms == 0` must not divide.** The derivative term divides by dt,
    /// and this kernel is `panic = "abort"`: a division by zero is a board
    /// reset, not an error. dt comes from a timer delta, so two ticks in the
    /// same millisecond reach it.
    #[test]
    fn zero_dt_returns_zero_rather_than_dividing() {
        let mut p = PidController::new(10, 10, 10);
        assert_eq!(p.update(100, 0, 0), 0);
    }

    /// **The i32 subtraction that used to trap.** `setpoint - measurement` is
    /// widened to i64 before subtracting; doing it the other way round
    /// overflows with `overflow-checks = true` whenever the operands are far
    /// apart, and `measurement` reaches `i32::MIN` because it is a velocity
    /// computed from encoder ticks a ring-3 task supplies. A trap there is not
    /// a caught error, it is a reset triggered from userspace.
    #[test]
    fn extreme_operands_do_not_overflow() {
        for (sp, meas) in [(i32::MAX, i32::MIN), (i32::MIN, i32::MAX),
                           (i32::MAX, i32::MAX), (i32::MIN, i32::MIN)] {
            let mut p = PidController::new(1, 1, 1);
            let out = p.update(sp, meas, 10);
            assert!(out >= PID_OUTPUT_MIN && out <= PID_OUTPUT_MAX,
                    "sp={sp} meas={meas} gave {out}");
        }
    }

    /// The integral term must accumulate while the error persists — that is
    /// what it is for. A controller whose integral silently stays zero reaches
    /// steady state with a permanent offset, which on a robot reads as "the
    /// left wheel is weaker".
    #[test]
    fn integral_accumulates_over_repeated_error() {
        let mut p = PidController::new(0, 1, 0);
        let first = p.update(10, 0, 100);
        let mut total = first;
        for _ in 0..5 { total = p.update(10, 0, 100); }
        assert!(total.abs() >= first.abs(),
                "integral did not accumulate: {first} then {total}");
    }
}

// The `NetDevice` trait + `EthNetDevice`/`VirtioNetDevice` adapters over
// `eth.rs`/`virtio/net.rs` reference `crate::net_device` — pulled in here so
// those two `impl NetDevice for ...` blocks (and `net_device`'s own
// `pick()` canaries) compile and run on the host, same as everything else
// in this file.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/net/src/net_device.rs"]
mod net_device;

// `unused_imports` too: `blk.rs` imports `kprintln` for paths this suite does
// not reach, which is the module's shape rather than a defect in it.
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/drivers/virtio/src/virtio/mod.rs"]
mod virtio;

// `blk.rs` names `crate::blkdev::FlushError` as its flush result, so the real
// `blkdev.rs` comes along. With neither `vf2` nor `k1` set it is the VirtIO
// backend, forwarding to the `virtio::blk` pulled in just above.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/block/src/blkdev.rs"]
mod blkdev;

// `blkdev::write` reports to the block layer's write observer (wave 14), a
// sibling module of `blkdev.rs` in its crate, so it comes along too.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/block/src/write_observer.rs"]
mod write_observer;

#[cfg(test)]
mod virtq {
    use super::virtio::*;

    /// A queue backed by real host memory, so the pointer arithmetic under
    /// test is exercised rather than avoided.
    ///
    /// Leaked on purpose: `Virtq` holds raw pointers and the tests outlive any
    /// scope a `Box` would give them.
    fn queue(num: u16) -> Virtq {
        // Built element-wise: the on-wire structs are `#[repr(C, packed)]`
        // and deliberately not `Copy`, so `[x; N]` does not apply. That is the
        // real layout the device sees, and the tests use it unchanged.
        let desc = Box::leak(Box::new(
            core::array::from_fn::<VirtqDesc, VIRTIO_QUEUE_SIZE, _>(
                |_| VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 })));
        let avail = Box::leak(Box::new(VirtqAvail {
            flags: 0, idx: 0, ring: [0; VIRTIO_QUEUE_SIZE], used_event: 0 }));
        let used = Box::leak(Box::new(VirtqUsed {
            flags: 0, idx: 0,
            ring: core::array::from_fn::<VirtqUsedElem, VIRTIO_QUEUE_SIZE, _>(
                |_| VirtqUsedElem { id: 0, len: 0 }),
            avail_event: 0 }));
        // Free list: 0 -> 1 -> ... -> num-1
        for i in 0..num as usize { desc[i].next = (i as u16) + 1; }
        let mut vq = Virtq::zeroed();
        vq.desc = desc.as_mut_ptr();
        vq.avail = avail;
        vq.used = used;
        vq.num = num;
        vq.free_head = 0;
        vq.free_count = num as u8;
        vq
    }

    /// **The device writes the used ring, so `id` is untrusted input.** An
    /// out-of-range id would be an OOB read in `desc.add(id)` one frame up the
    /// stack. Three things must all hold: the poll reports nothing, the fault
    /// is counted, and — the part that is easy to get wrong — the bad entry is
    /// **consumed anyway**, because leaving it would re-read the same corrupt
    /// entry forever and wedge the queue.
    #[test]
    fn an_out_of_range_used_id_is_refused_counted_and_consumed() {
        unsafe {
            let mut vq = queue(16);
            (*vq.used).ring[0] = VirtqUsedElem { id: 99, len: 4 };  // 99 >= 16
            (*vq.used).idx = 1;
            assert_eq!(virtq_poll_with_len(&mut vq), None, "must not hand back an OOB id");
            assert_eq!(vq.bad_completions, 1, "the fault must leave a trace");
            assert_eq!(vq.last_used_idx, 1, "the bad entry must be consumed");
            // And the queue must still work afterwards: a good entry follows.
            (*vq.used).ring[1] = VirtqUsedElem { id: 3, len: 8 };
            (*vq.used).idx = 2;
            assert_eq!(virtq_poll_with_len(&mut vq), Some((3, 8)),
                       "queue wedged after a bad completion");
        }
    }

    /// An uninitialised queue must report "empty", not divide by zero.
    /// `virtq_poll_with_len` takes `% vq.num`, and with `panic = "abort"` a
    /// division by zero is a board reset — reachable if a driver polls before
    /// its queue is set up.
    #[test]
    fn an_uninitialised_queue_reports_empty_rather_than_dividing() {
        unsafe {
            let mut vq = Virtq::zeroed();          // num = 0, used = null
            assert_eq!(virtq_poll_with_len(&mut vq), None);
            let mut vq = queue(16);
            vq.num = 0;                            // used non-null, num zero
            assert_eq!(virtq_poll_with_len(&mut vq), None);
        }
    }

    /// **A corrupted free list must fail the allocation, not index out of
    /// bounds.** `free_head` can hold the 0xFFFF terminator while
    /// `free_count` still claims descriptors are available; indexing then
    /// writes outside the table and panics in `desc_used[idx]`.
    #[test]
    fn a_corrupt_free_head_fails_the_allocation() {
        unsafe {
            let mut vq = queue(16);
            vq.free_head = 0xFFFF;                 // terminator, not an index
            assert_eq!(virtq_alloc_desc(&mut vq), None);
            let mut vq = queue(16);
            vq.free_head = 16;                     // one past the end
            assert_eq!(virtq_alloc_desc(&mut vq), None);
        }
    }

    /// Allocation must not hand the same descriptor out twice, and the count
    /// must reach zero exactly at the queue size — the same uniqueness
    /// property the page allocator has, and the same silent corruption if it
    /// fails.
    #[test]
    fn every_descriptor_is_allocated_once() {
        unsafe {
            let mut vq = queue(16);
            let mut seen = std::collections::HashSet::new();
            for _ in 0..16 {
                let i = virtq_alloc_desc(&mut vq).expect("16 descriptors are free");
                assert!(seen.insert(i), "descriptor {i} handed out twice");
                assert!(i < 16, "descriptor {i} out of range");
            }
            assert_eq!(vq.free_count, 0);
            assert_eq!(virtq_alloc_desc(&mut vq), None, "exhaustion must fail");
        }
    }

    /// **Freeing must scrub the descriptor, not just relink it.** A freed
    /// descriptor that keeps its old `flags` still looks like "has next" while
    /// `.next` now points into the free list, so a chain walk reaching it —
    /// a duplicate completion from a hostile device — follows the free list to
    /// the 0xFFFF terminator and indexes far outside the table.
    #[test]
    fn freeing_scrubs_the_descriptor_so_a_chain_walk_terminates() {
        unsafe {
            let mut vq = queue(16);
            let i = virtq_alloc_desc(&mut vq).unwrap();
            let d = vq.desc.add(i);
            (*d).addr = 0xDEAD_BEEF;
            (*d).len = 512;
            (*d).flags = 1;                        // VIRTQ_DESC_F_NEXT
            virtq_free_desc(&mut vq, i);
            assert_eq!({ (*d).addr }, 0, "a stale address must not survive");
            assert_eq!({ (*d).len }, 0, "a stale length must not survive");
            assert_eq!({ (*d).flags }, 0, "flags must not still say 'has next'");
            assert!(!vq.desc_used[i]);
        }
    }

    /// Freeing out of range, or freeing twice, must be refused. A double free
    /// would put one descriptor in the list twice and hand it to two owners.
    #[test]
    fn a_double_or_out_of_range_free_is_refused() {
        unsafe {
            let mut vq = queue(16);
            let before = vq.free_count;
            virtq_free_desc(&mut vq, 99);          // out of range
            assert_eq!(vq.free_count, before, "an out-of-range free changed state");
            let i = virtq_alloc_desc(&mut vq).unwrap();
            virtq_free_desc(&mut vq, i);
            let after_first = vq.free_count;
            virtq_free_desc(&mut vq, i);           // again
            assert_eq!(vq.free_count, after_first, "double free must be a no-op");
        }
    }

    /// **The entropy read hands the device a buffer it may write.** Without
    /// `VIRTQ_DESC_F_WRITE` a spec-conforming device refuses to fill a
    /// read-only buffer, so the seed read never completes and every boot with
    /// the device prints `[ENTROPY] FAILED:`. A stray NEXT flag would make the
    /// device walk into whatever `.next` names. Address and length must be the
    /// ones asked for: the device DMAs exactly there.
    #[test]
    fn the_rng_read_descriptor_is_a_single_device_writable_buffer() {
        unsafe {
            let mut vq = queue(16);
            let buf = [0u8; 48];
            let addr = buf.as_ptr() as u64;
            let i = rng::arm_read(&mut vq, addr, 48).expect("a free descriptor");
            let d = vq.desc.add(i);
            assert_eq!({ (*d).flags } & VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE,
                       "the device must be allowed to write the buffer");
            assert_eq!({ (*d).flags } & VIRTQ_DESC_F_NEXT, 0, "a read is one descriptor");
            assert_eq!({ (*d).addr }, addr);
            assert_eq!({ (*d).len }, 48);
            assert!(vq.desc_used[i], "the descriptor must be marked in use");
            assert_eq!(vq.free_count, 15);
        }
    }

    /// A full queue must refuse the read, not arm a descriptor it does not own.
    #[test]
    fn the_rng_read_is_refused_on_a_full_queue() {
        unsafe {
            let mut vq = queue(16);
            for _ in 0..16 { virtq_alloc_desc(&mut vq).unwrap(); }
            assert_eq!(rng::arm_read(&mut vq, 0x1000, 8), None);
        }
    }

    /// **Pins the RISC-V QEMU `virt` transport window.** `blk.rs`, `net.rs`
    /// and `rng.rs`'s `device` submodule used to each hardcode their own copy
    /// of this base/stride/count; the aarch64 port (2026-09-21) collapsed the
    /// three into one definition in `virtio::mod` (ISA-selected there — see
    /// its doc comment) so a second ISA needs one new `#[cfg]` arm instead of
    /// three edits that could drift out of sync with each other. This is a
    /// regression pin on the value that definition resolves to for a
    /// non-`aarch64`-bare-metal build (this crate's host target included) —
    /// confirmed against `hw/riscv/virt.c`'s `VIRT_VIRTIO` MemMapEntry.
    ///
    /// **Canary.** Change any literal here (e.g. `0x1000_1000` ->
    /// `0x2000_1000`, or `8` -> `4`) and this fails; every one of `blk::init`,
    /// `net::init` and `rng`'s device probe would silently scan the wrong
    /// address range on real RISC-V hardware with no compiler error, since
    /// `usize` arithmetic accepts any value.
    #[test]
    fn the_riscv_virt_transport_window_matches_qemus_virt_c() {
        assert_eq!(super::virtio::VIRTIO_MMIO_BASE, 0x1000_1000);
        assert_eq!(super::virtio::VIRTIO_MMIO_STRIDE, 0x1000);
        assert_eq!(super::virtio::VIRTIO_MMIO_COUNT, 8);
    }
}

#[cfg(test)]
mod virtio_net_device {
    use azos_drv_api::net::{NetDevice, NetError};
    use super::virtio::net::VirtioNetDevice;

    /// **Discriminates.** No MMIO on the host, so `init()` was never called
    /// and the device's own `ready` flag is false — `is_ready()` must say so
    /// rather than defaulting to `true`.
    #[test]
    fn uninitialised_device_is_not_ready() {
        assert!(!VirtioNetDevice.is_ready());
    }

    /// **Discriminates.** An empty frame must be refused before the device
    /// state is even touched — `send`'s old bare `Err(())` gave no way to
    /// tell this apart from "ring full"; the trait now can.
    #[test]
    fn an_empty_frame_is_a_bad_length_not_not_ready() {
        assert_eq!(VirtioNetDevice.send(&[]), Err(NetError::BadLength));
    }

    /// **Discriminates.** Oversized frame, same bucket as empty: rejected on
    /// length before the device is asked anything.
    #[test]
    fn an_oversized_frame_is_a_bad_length() {
        let huge = [0u8; 1515]; // TX_BUF_SIZE (1514) + 1
        assert_eq!(VirtioNetDevice.send(&huge), Err(NetError::BadLength));
    }

    /// **Discriminates.** A correctly-sized frame against a device that was
    /// never initialised must fail `NotReady`, not `QueueFull` — the two
    /// used to be indistinguishable behind `send`'s `Result<(), ()>`.
    #[test]
    fn a_well_sized_frame_against_an_unready_device_is_not_ready() {
        assert_eq!(VirtioNetDevice.send(&[0xAA; 64]), Err(NetError::NotReady));
    }

    /// **Discriminates.** `recv` on an unready device must report "nothing
    /// queued" (`Ok(0)`), matching `net_raw_recv`'s old direct use of
    /// `poll_recv`'s return value as a plain byte count with no error case.
    #[test]
    fn recv_on_an_unready_device_is_empty_not_an_error() {
        let mut buf = [0u8; 64];
        assert_eq!(VirtioNetDevice.recv(&mut buf), Ok(0));
    }

    /// **Discriminates.** All-zero MAC before `init()`.
    #[test]
    fn mac_is_zero_before_init() {
        assert_eq!(VirtioNetDevice.mac(), [0u8; 6]);
    }
}

// `unused_imports` as well as `dead_code`: without the `vf2` feature the file's
// stub half is compiled and its imports go unused, which is the module's own
// design rather than a defect in it.
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/drivers/net/src/eth.rs"]
mod eth;

#[cfg(test)]
mod macb_rx {
    use super::eth::rx_copy_len;

    /// The MACB values: a 13-bit length field against a 1536-byte DMA slot.
    const BUF_SIZE: usize = 1536;
    const LEN_MAX: usize = 0x1FFF;          // 8191, what the field can hold
    const ETH_FRAME_MAX: usize = 1514;      // what the one caller passes today

    /// **The bound that was missing.** The hardware writes the length, so it
    /// is untrusted: a device reporting the field's maximum must not produce a
    /// copy longer than the DMA slot, whatever the caller's buffer size. Read
    /// past it and `copy_nonoverlapping` walks into the next frame's buffer,
    /// then out of the static entirely, into memory the network stack parses.
    #[test]
    fn a_device_reported_length_cannot_exceed_the_dma_slot() {
        // A caller with a jumbo-sized buffer is the case the old bound missed.
        assert_eq!(rx_copy_len(LEN_MAX, 9000, BUF_SIZE), BUF_SIZE);
        assert_eq!(rx_copy_len(LEN_MAX, 65536, BUF_SIZE), BUF_SIZE);
        // And with no caller bound at all it still cannot exceed the slot.
        assert_eq!(rx_copy_len(usize::MAX, usize::MAX, BUF_SIZE), BUF_SIZE);
    }

    /// The caller's buffer still bounds it when that is the smaller of the
    /// two — dropping either `min` reopens a different overflow.
    #[test]
    fn the_callers_buffer_still_bounds_a_short_read() {
        assert_eq!(rx_copy_len(1000, 64, BUF_SIZE), 64);
        assert_eq!(rx_copy_len(LEN_MAX, 64, BUF_SIZE), 64);
    }

    /// The ordinary path must be untouched: a normal frame with today's caller
    /// copies exactly its own length, so the clamp cannot be truncating real
    /// traffic.
    #[test]
    fn a_normal_frame_is_copied_whole() {
        assert_eq!(rx_copy_len(60, ETH_FRAME_MAX, BUF_SIZE), 60);
        assert_eq!(rx_copy_len(ETH_FRAME_MAX, ETH_FRAME_MAX, BUF_SIZE), ETH_FRAME_MAX);
        assert_eq!(rx_copy_len(0, ETH_FRAME_MAX, BUF_SIZE), 0, "an empty frame is legal");
    }
}

#[cfg(test)]
mod eth_net_device {
    use super::eth::EthNetDevice;
    use azos_drv_api::net::{NetDevice, NetError};

    /// **Discriminates.** No `vf2` feature on this host build, so the stub
    /// half of `eth.rs` is what is under test: it must report not-ready, the
    /// same as it does before the driver was given a `NetDevice` face at
    /// all. A `NetDevice::is_ready` that hardcoded `true` fails this.
    #[test]
    fn stub_backend_is_never_ready() {
        assert!(!EthNetDevice.is_ready());
    }

    /// **Discriminates.** `eth_send` returns -1 on the stub unconditionally;
    /// the trait must turn that into `NotReady`, not `Ok`.
    #[test]
    fn stub_backend_refuses_to_send() {
        assert_eq!(EthNetDevice.send(&[1, 2, 3]), Err(NetError::NotReady));
    }

    /// **Discriminates.** `eth_recv` also returns -1 on the stub, and
    /// `net_raw_recv`'s old inline mapping treated that as "nothing
    /// available" (`Ok(0)`), not an error — the trait must match exactly, or
    /// `net_poll`'s drain loop (which stops at the first `Err`/0) changes
    /// behaviour on every QEMU boot, since QEMU never compiles `vf2`.
    #[test]
    fn stub_backend_recv_is_empty_not_an_error() {
        let mut buf = [0u8; 16];
        assert_eq!(EthNetDevice.recv(&mut buf), Ok(0));
    }

    /// **Discriminates.** All-zero MAC on the stub, same as before.
    #[test]
    fn stub_backend_mac_is_zero() {
        assert_eq!(EthNetDevice.mac(), [0u8; 6]);
    }
}

// can.rs has no hardware (MMIO) half at all right now — see the doc comment
// at the top of the file for why one was not added this session (the SoC
// register map is not derivable from anything in this repo, and even the
// already-decided MCP2515-over-SPI design cannot be wired up: `spi.rs` has
// no hardware path under `feature = "k1"`, and the board wiring — which
// bus/CS the chip sits on — is not recorded anywhere in-tree). What's tested
// here is exactly the roadmap's own stated gap: "frame packing/unpacking and
// ID handling (pure logic, already present and untested)".
#[allow(dead_code)]
#[path = "../../../../crates/drivers/bus/src/can.rs"]
mod can;

#[cfg(test)]
mod can_frames {
    use super::can::CanFrame;

    // Mirrors can.rs's private `CAN_STD_ID_MASK` / `CAN_EXT_ID_MASK` — those
    // constants aren't `pub`, so the mask value is duplicated here rather
    // than imported.
    const STD_MASK: u32 = 0x7FF;
    const EXT_MASK: u32 = 0x1FFF_FFFF;

    #[test]
    fn a_standard_id_is_masked_to_eleven_bits() {
        let f = CanFrame::standard(0x1ABC_DEF, &[]);
        assert_eq!(f.id, 0x1ABC_DEF & STD_MASK);
        assert!(!f.extended);
    }

    /// **The bug this pins.** `extended_frame` used to build its 29-bit mask
    /// and then hand the result to `standard`, which re-masked it down to 11
    /// bits — a 29-bit ID silently lost its top 18 bits while `extended`
    /// stayed `true`. A small ID (anything that fits in 11 bits) passes
    /// against both the buggy and the fixed code, so the id here is chosen
    /// to have bits set above bit 10 — that's the instant the two versions
    /// diverge.
    #[test]
    fn an_extended_id_keeps_bits_above_the_standard_range() {
        let id = 0x1AB_CDEF; // 25 significant bits, well past the 11-bit std range
        let f = CanFrame::extended_frame(id, &[]);
        assert_eq!(f.id, id & EXT_MASK);
        assert_ne!(
            f.id,
            id & STD_MASK,
            "would coincide with the bug's output for this id"
        );
        assert!(f.extended);
    }

    #[test]
    fn an_extended_id_beyond_29_bits_is_masked() {
        let f = CanFrame::extended_frame(0xFFFF_FFFF, &[]);
        assert_eq!(f.id, EXT_MASK);
        assert!(f.extended);
    }

    #[test]
    fn payload_longer_than_the_max_dlc_is_clamped_not_overrun() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let f = CanFrame::standard(0x10, &data);
        assert_eq!(f.dlc, 8);
        assert_eq!(&f.data[..], &data[..8]);
    }

    #[test]
    fn an_empty_payload_is_legal() {
        let f = CanFrame::standard(0x10, &[]);
        assert_eq!(f.dlc, 0);
    }
}

// rc.rs is all process-global statics (RC_READY / RC_MODE / RC_FAILSAFE /
// RC_CHANNELS), so — like can_driver_lifecycle below — its tests live in one
// `#[test]` function rather than several independent ones: `cargo test` runs
// tests concurrently by default, and two tests calling `rc_init` on the same
// statics would race and make the outcome depend on scheduling rather than
// the code.
#[allow(dead_code)]
#[path = "../../../../domains/robot/drivers/src/rc.rs"]
mod rc;

#[cfg(test)]
mod rc_failsafe {
    use super::rc::{self, RcMode};

    /// Both tests below drive `rc.rs`'s **global** driver state through
    /// `rc_init`, with different modes, and `cargo test` runs them on
    /// separate threads. Without this lock they race: one sets `Simulated`
    /// while the other is asserting `Sbus` is not ready, or the reverse.
    ///
    /// **Observed, not theorised.** On 2026-09-07
    /// `simulated_mode_still_reports_ready_with_failsafe_cleared` failed once
    /// and then passed 36/36 on three consecutive re-runs — the signature of
    /// a scheduling-dependent race, and the worst kind of red in a gate,
    /// because it looks like a regression in whatever was committed last.
    /// Adding three unrelated tests to this file was enough to change the
    /// interleaving and surface it.
    ///
    /// A module-level lock is enough HERE because `rc.rs` is the only global
    /// these two touch. That is a narrower claim than the crate-wide lock
    /// `tests/host/syscall-tests/src/harness.rs` takes, and it holds only while
    /// no other test in this file calls `rc_init` — a test that does must
    /// take this lock too.
    pub(super) static RC_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, surviving a poisoning from a previously failed test:
    /// one panic must not convert every sibling into a second failure and
    /// bury the original.
    pub(super) fn serial() -> std::sync::MutexGuard<'static, ()> {
        RC_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// **The bug this pins.** `rc_init(Sbus)` / `rc_init(Ppm)` used to behave
    /// exactly like `rc_init(Simulated)`: mark the driver ready, clear
    /// failsafe, and hand `rc_read()`'s caller the same fixed neutral-stick
    /// array forever — with no SBUS/PPM decoder in this file ever updating
    /// it. A flight controller trusting that as "I have a live transmitter
    /// link" would never see the RC-link-loss failsafe fire, no matter how
    /// long the (nonexistent) receiver had been unplugged. `rc_read()` must
    /// fail closed for these modes: not ready, so `None`, exactly like
    /// before any `rc_init` call at all.
    #[test]
    fn sbus_and_ppm_modes_fail_closed_with_no_decoder() {
        let _g = serial();
        for mode in [RcMode::Sbus, RcMode::Ppm] {
            rc::rc_init(mode);
            assert!(!rc::rc_is_ready(),
                "no decoder exists yet — the driver must not claim readiness");
            assert_eq!(rc::rc_read(), None,
                "a mode with no decoder must not hand out synthetic 'live' channel data");
        }
    }

    /// The negative half: this must not be a test that always passes.
    /// `Simulated` mode is the one path that legitimately *is* ready — it is
    /// documented, QEMU/host-only synthetic data, not a stand-in for a live
    /// transmitter — so it must clear failsafe and hand back `Some`. If this
    /// failed too, the assertions above would be testing a `rc_read()` that
    /// always returns `None` regardless of mode, which proves nothing about
    /// the Sbus/Ppm path specifically.
    #[test]
    fn simulated_mode_still_reports_ready_with_failsafe_cleared() {
        let _g = serial();
        rc::rc_init(RcMode::Simulated);
        assert!(rc::rc_is_ready(), "Simulated mode is the documented QEMU/host test path");
        let (_channels, failsafe) = rc::rc_read().expect("Simulated mode must be live");
        assert!(!failsafe, "Simulated mode's synthetic data is not a failsafe condition");
    }
}

/// The SBUS frame decoder in `rc.rs`.
///
/// **No lock here, deliberately.** Every function under test is pure —
/// `sbus_decode`, `sbus_channel_to_us` and `sbus_frame_to_pulses` touch no
/// static, so these tests do not race `rc_failsafe`'s and do not need its
/// `RC_SERIAL` mutex. If a test is ever added here that applies a decoded
/// frame to the driver globals (via `rc_set_channels`), it must take *that*
/// mutex — the one at the top of `rc_failsafe` — and not a second one, since
/// two mutexes serialize nothing against each other.
///
/// **What this can and cannot reach.** The transport is a UART at 100 kbaud,
/// 8E2, signal-inverted, and none of that is exercisable off the board. The
/// bit unpacking is, and it is the half that fails silently: a mis-shifted
/// channel is still a plausible stick position, and the flight code has no
/// way to tell it from a real one.
#[cfg(test)]
mod sbus_decoder {
    use super::rc::{
        sbus_channel_to_us, sbus_decode, sbus_frame_to_pulses, RC_PULSE_MAX_US, RC_PULSE_MIN_US,
        SBUS_END_BYTE, SBUS_FLAG_CH17, SBUS_FLAG_CH18, SBUS_FLAG_FAILSAFE, SBUS_FLAG_FRAME_LOST,
        SBUS_FRAME_LEN, SBUS_RAW_CENTER, SBUS_RAW_MAX, SBUS_RAW_MIN, SBUS_START_BYTE,
    };

    // ---------------------------------------------------------------------
    // The anchor frame, computed by hand — NOT by the code under test.
    //
    // Channels chosen so that the three boundary cases the packing can get
    // wrong all carry a value that is not zero and not symmetric:
    //
    //   ch0  = 172  = 0b000_1010_1100   (stream bits   0..10)
    //   ch1  = 992  = 0b011_1110_0000   (stream bits  11..21, crosses a byte)
    //   ch2  = 1811 = 0b111_0001_0011   (stream bits  22..32, spans 3 bytes)
    //   ch3..ch14 = 0                   (stream bits  33..164)
    //   ch15 = 1811 = 0b111_0001_0011   (stream bits 165..175, ends at byte 22)
    //
    // Bits are packed LSB-first starting at bit 0 of frame[1], so frame byte
    // `1+j` holds stream bits `8j..8j+7`:
    //
    //   frame[1]  bits  0..7  = ch0[0..7]              = 172 & 0xFF     = 0xAC
    //   frame[2]  bits  8..10 = ch0[8..10]  = 172>>8   = 0
    //             bits 11..15 = ch1[0..4]   = 992 & 0x1F = 0            = 0x00
    //   frame[3]  bits 16..21 = ch1[5..10]  = (992>>5) & 0x3F  = 31
    //             bits 22..23 = ch2[0..1]   = 1811 & 0x3 = 3, at bit 6
    //                                          31 | (3<<6) = 31+192    = 0xDF
    //   frame[4]  bits 24..31 = ch2[2..9]   = (1811>>2) & 0xFF = 452 & 0xFF
    //                                          = 196                   = 0xC4
    //   frame[5]  bit  32     = ch2[10]     = 1811>>10 = 1
    //             bits 33..39 = ch3[0..6]   = 0                         = 0x01
    //   frame[6..=20]                        = ch3..ch14 = 0            = 0x00
    //   frame[21] bits 160..164 = ch14[6..10] = 0
    //             bits 165..167 = ch15[0..2] = 1811 & 0x7 = 3, at bit 5
    //                                          3<<5 = 96               = 0x60
    //   frame[22] bits 168..175 = ch15[3..10] = (1811>>3) & 0xFF = 226  = 0xE2
    //
    // frame[23] is the flags byte, frame[24] the 0x00 footer.
    // ---------------------------------------------------------------------

    /// Build the anchor frame with a chosen flags byte. Only `frame[23]`
    /// varies; every channel byte is a literal from the arithmetic above.
    fn anchor_frame(flags: u8) -> [u8; SBUS_FRAME_LEN] {
        let mut f = [0u8; SBUS_FRAME_LEN];
        f[0] = SBUS_START_BYTE; // 0x0F
        f[1] = 0xAC;
        f[2] = 0x00;
        f[3] = 0xDF;
        f[4] = 0xC4;
        f[5] = 0x01;
        // f[6..=20] stay 0x00
        f[21] = 0x60;
        f[22] = 0xE2;
        f[23] = flags;
        f[24] = SBUS_END_BYTE; // 0x00
        f
    }

    /// The channel values `anchor_frame` encodes.
    const ANCHOR_CHANNELS: [u16; 16] = [
        172, 992, 1811, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 1811,
    ];

    /// A hand-built frame must decode to the hand-computed channel values.
    ///
    /// This is the anchor for everything below: the bytes come from the
    /// arithmetic in the comment above, not from an encoder, so a decoder
    /// that is self-consistently wrong still fails here.
    #[test]
    fn the_hand_built_frame_decodes_to_the_hand_computed_channels() {
        let d = sbus_decode(&anchor_frame(0x00)).expect("a well-formed frame must decode");
        assert_eq!(d.channels, ANCHOR_CHANNELS, "channel unpacking disagrees with the hand arithmetic");
    }

    /// The three bit-packing boundary cases, each named.
    ///
    /// - **ch0** starts at stream bit 0 and is the only channel whose low
    ///   byte is byte-aligned. A decoder that got only this one right would
    ///   pass a single-channel test and be wrong about the other fifteen.
    /// - **ch1** starts at bit 11: its low 5 bits are the *high* 5 bits of
    ///   frame[2] and its top 6 bits are the low 6 of frame[3]. This is the
    ///   first channel a byte-aligned reader gets wrong.
    /// - **ch15** ends at bit 175, the last bit of frame[22]. It must not
    ///   reach into frame[23] — see `flag_bits_do_not_leak_into_channel_15`.
    #[test]
    fn the_bit_packing_boundary_channels_are_each_correct() {
        let d = sbus_decode(&anchor_frame(0x00)).unwrap();
        assert_eq!(d.channels[0], 172, "ch0 occupies stream bits 0..10");
        assert_eq!(d.channels[1], 992, "ch1 crosses the frame[2]/frame[3] boundary");
        assert_eq!(d.channels[2], 1811, "ch2 spans three bytes: frame[3], frame[4], frame[5]");
        assert_eq!(d.channels[15], 1811, "ch15 is the last channel, ending at frame[22]");
    }

    /// A wrong start byte and a wrong end byte each give `None`.
    ///
    /// Framing failure means the channel bits are at unknown offsets. There
    /// is no partial result worth returning: a decoder that returned the
    /// channels anyway would hand the flight code stick positions read from
    /// the middle of some other frame.
    #[test]
    fn a_bad_start_or_end_byte_rejects_the_frame() {
        let mut bad_start = anchor_frame(0x00);
        bad_start[0] = 0x0E;
        assert_eq!(sbus_decode(&bad_start), None, "start byte must be 0x0F");

        let mut bad_end = anchor_frame(0x00);
        bad_end[24] = 0x04; // an SBUS2 telemetry footer, deliberately rejected
        assert_eq!(sbus_decode(&bad_end), None, "end byte must be 0x00");

        // And the same bytes with both framing bytes correct still decode,
        // so the two assertions above are not passing for some other reason.
        assert!(sbus_decode(&anchor_frame(0x00)).is_some());
    }

    /// **The failsafe bit, both ways.** This is the bit the whole RC-link-loss
    /// chain turns on: `domains/robot/safety-core/src/flight_ctrl.rs`'s flight loop passes the failsafe
    /// bool to `rc_frame_is_fresh_input`, which decides whether the frame
    /// refreshes `CH_RC_INPUT` and therefore whether `rc_age` ever grows.
    /// A decoder that reads bit 3 as always-clear makes the link look healthy
    /// forever; always-set makes it look dead forever.
    ///
    /// The two frames differ in exactly one byte, and the channels are
    /// asserted equal, so this also pins that the flags byte does not perturb
    /// the channel unpacking.
    #[test]
    fn the_failsafe_flag_is_read_both_ways() {
        let without = sbus_decode(&anchor_frame(0x00)).unwrap();
        let with = sbus_decode(&anchor_frame(SBUS_FLAG_FAILSAFE)).unwrap();

        assert!(!without.failsafe, "flags 0x00 is not a failsafe condition");
        assert!(with.failsafe, "flags bit 3 is the receiver reporting failsafe");
        assert_eq!(with.channels, without.channels,
            "the flags byte must not change any channel value");
    }

    /// Frame-lost is bit 2 and is a different fact from failsafe: one dropped
    /// frame, not loss of the transmitter. Reading bit 2 where bit 3 is meant
    /// would turn a normal transient into apparent link loss.
    #[test]
    fn frame_lost_and_failsafe_are_separate_bits() {
        let lost = sbus_decode(&anchor_frame(SBUS_FLAG_FRAME_LOST)).unwrap();
        assert!(lost.frame_lost, "flags bit 2 is frame-lost");
        assert!(!lost.failsafe, "frame-lost alone is not failsafe");

        let fs = sbus_decode(&anchor_frame(SBUS_FLAG_FAILSAFE)).unwrap();
        assert!(fs.failsafe);
        assert!(!fs.frame_lost, "failsafe alone is not frame-lost");

        let both = sbus_decode(&anchor_frame(SBUS_FLAG_FAILSAFE | SBUS_FLAG_FRAME_LOST)).unwrap();
        assert!(both.failsafe && both.frame_lost);
    }

    /// Bits 0 and 1 are digital channels 17 and 18, and must not be mistaken
    /// for the two status bits. An off-by-one in the flag masks shows up here
    /// as a frame that claims failsafe because a digital switch is on.
    #[test]
    fn the_digital_channel_bits_are_not_status_bits() {
        let d = sbus_decode(&anchor_frame(SBUS_FLAG_CH17 | SBUS_FLAG_CH18)).unwrap();
        assert!(d.ch17 && d.ch18, "flags bits 0 and 1 are digital channels 17 and 18");
        assert!(!d.failsafe, "a digital channel must never read as failsafe");
        assert!(!d.frame_lost, "a digital channel must never read as frame-lost");
    }

    /// ch15 ends at the last bit of frame[22]; the next byte is the flags.
    /// Setting every flag bit must leave every channel unchanged.
    ///
    /// **What actually keeps them apart is the `& 0x07FF` mask, not the
    /// decoder's read window** — established by mutation, not by reading the
    /// code: relaxing the window guard so ch15 *does* read frame[23] leaves
    /// this test green, because those bits land above bit 10 and the mask
    /// discards them. What does turn this red is a wrong shift for the third
    /// byte (`hi << 16` -> `hi << 13`), which walks the flags down into
    /// ch15's high bits. That is the bug class this pins.
    #[test]
    fn flag_bits_do_not_leak_into_channel_15() {
        let clean = sbus_decode(&anchor_frame(0x00)).unwrap();
        let noisy = sbus_decode(&anchor_frame(0xFF)).unwrap();
        assert_eq!(noisy.channels[15], clean.channels[15],
            "ch15 must not read any bit of the flags byte");
        assert_eq!(noisy.channels, clean.channels);
        assert!(noisy.failsafe && noisy.frame_lost && noisy.ch17 && noisy.ch18);
    }

    /// An independent check of the packing over all sixteen channels at once.
    ///
    /// The encoder here sets one bit at a time — a different algorithm from
    /// the decoder's three-byte shift window, so agreeing is evidence rather
    /// than tautology. It is a *supplement* to the hand-built anchor, not a
    /// replacement: a mismatch here cannot say which side is wrong, which is
    /// exactly why the literal frame above exists.
    #[test]
    fn every_channel_round_trips_through_a_bit_at_a_time_encoder() {
        // Distinct values, each < 2048, spread so no two channels share one.
        let mut want = [0u16; 16];
        for (i, w) in want.iter_mut().enumerate() {
            *w = (i as u16) * 127 + 91;
        }

        let mut f = [0u8; SBUS_FRAME_LEN];
        f[0] = SBUS_START_BYTE;
        f[24] = SBUS_END_BYTE;
        for (i, w) in want.iter().enumerate() {
            for b in 0..11 {
                if (w >> b) & 1 == 1 {
                    let stream_bit = i * 11 + b;
                    f[1 + stream_bit / 8] |= 1 << (stream_bit % 8);
                }
            }
        }

        let d = sbus_decode(&f).expect("a well-formed frame must decode");
        assert_eq!(d.channels, want);
        // Nothing was written to frame[23], so no flag may be set.
        assert!(!d.failsafe && !d.frame_lost && !d.ch17 && !d.ch18);
    }

    /// The raw-count to microsecond mapping, `us = raw * 5 / 8 + 880`.
    ///
    /// The two mid-range points are the ones that test the *formula*: the
    /// canonical stops 172 and 1811 land outside 1000..2000 and are produced
    /// by the clamp, so an offset error of a few tens of microseconds is
    /// invisible at those points and visible here.
    #[test]
    fn the_raw_to_microsecond_mapping_is_the_standard_affine_one() {
        // 500 * 5 = 2500; 2500 / 8 = 312 (truncated); 312 + 880 = 1192.
        assert_eq!(sbus_channel_to_us(500), 1192);
        // 1500 * 5 = 7500; 7500 / 8 = 937 (truncated); 937 + 880 = 1817.
        assert_eq!(sbus_channel_to_us(1500), 1817);
        // The three exact points of the affine map, all inside the clamp:
        // 192 -> 1000, 992 -> 1500, 1792 -> 2000.
        assert_eq!(sbus_channel_to_us(192), 1000);
        assert_eq!(sbus_channel_to_us(SBUS_RAW_CENTER), 1500, "centre must be mid-throw");
        assert_eq!(sbus_channel_to_us(1792), 2000);
    }

    /// The clamp, pinned separately from the slope.
    ///
    /// `rc_read` documents a 1000..2000 µs range and its callers scale
    /// against it. A transmitter set for extended travel must not turn into
    /// an out-of-range command; the unclamped count stays in
    /// `SbusFrame::channels` for anything that needs it.
    #[test]
    fn out_of_range_counts_are_clamped_to_the_documented_pulse_range() {
        assert_eq!(sbus_channel_to_us(0), RC_PULSE_MIN_US, "880 us raw, clamped");
        assert_eq!(sbus_channel_to_us(2047), RC_PULSE_MAX_US, "2159 us raw, clamped");
        // The canonical mechanical stops sit just outside, so they clamp too.
        assert_eq!(sbus_channel_to_us(SBUS_RAW_MIN), RC_PULSE_MIN_US, "172 -> 987, clamped");
        assert_eq!(sbus_channel_to_us(SBUS_RAW_MAX), RC_PULSE_MAX_US, "1811 -> 2011, clamped");
        for raw in [0u16, 172, 500, 992, 1500, 1811, 2047] {
            let us = sbus_channel_to_us(raw);
            assert!((RC_PULSE_MIN_US..=RC_PULSE_MAX_US).contains(&us),
                "raw {raw} produced {us} us, outside the documented range");
        }
    }

    /// The adaptation to the shape `rc_read` already returns: a `[u16; 16]`
    /// of microseconds. This is the only glue a future byte source needs
    /// between `sbus_decode` and `rc_set_channels`.
    #[test]
    fn a_decoded_frame_maps_onto_the_drivers_pulse_width_array() {
        let d = sbus_decode(&anchor_frame(0x00)).unwrap();
        let us = sbus_frame_to_pulses(&d);
        assert_eq!(us[0], 1000, "ch0 at the low stop");
        assert_eq!(us[1], 1500, "ch1 at centre");
        assert_eq!(us[2], 2000, "ch2 at the high stop");
        assert_eq!(us[3], 1000, "an unused channel reads 0 raw, clamped to the floor");
        assert_eq!(us[15], 2000);
        // Same length and element type as `rc_set_channels` takes.
        let _: &[u16; 16] = &us;
    }
}

/// Everything below shares one process-global static (`can.rs`'s `CAN`
/// driver), so it lives in a single `#[test]` function rather than several —
/// `cargo test` runs tests concurrently by default, and splitting a shared
/// mutable global across independently-scheduled tests would make the
/// outcome depend on run order and thread interleaving instead of the code.
/// `can_frames` above is safe to split because those tests never touch the
/// static; this one owns the whole driver lifecycle sequentially and tracks
/// running totals rather than assuming a clean slate at any point, because
/// nothing in `can_init`/`can_init_with_bitrate` resets buffers, filters or
/// counters (only `state` and `bitrate`).
#[cfg(test)]
mod can_driver_lifecycle {
    use super::can;
    use super::can::CanFrame;

    // Mirrors can.rs's private `CAN_RX_CAP` (16 slots, one always left empty
    // to disambiguate a full ring from an empty one).
    const RX_USABLE: usize = 15;

    #[test]
    fn lifecycle_send_filter_and_overflow_are_consistent() {
        assert!(matches!(can::can_get_state(), can::CanState::Uninit));

        can::can_init();
        assert!(matches!(can::can_get_state(), can::CanState::Active));
        assert_eq!(can::can_stats(), (0, 0, 0));

        // No filters yet: accept-all, loopback delivers what was sent.
        assert_eq!(can::can_send(&CanFrame::standard(0x123, &[1, 2, 3])), 0);
        assert_eq!(can::can_stats(), (1, 1, 0));
        let got = can::can_recv().expect("frame should have looped back");
        assert_eq!(got.id, 0x123);
        assert_eq!(&got.data[..got.dlc as usize], &[1, 2, 3]);
        assert!(can::can_recv().is_none());

        // A filter that only accepts 0x456 rejects 0x123. TX still counts
        // (the node did transmit); RX does not (it never crossed the
        // filter) — and this is filtering working as designed, not an
        // error, so `err_count` must not move either.
        assert!(can::can_add_filter(0x456, 0x7FF));
        let (rx0, tx0, err0) = can::can_stats();
        assert_eq!(can::can_send(&CanFrame::standard(0x123, &[])), 0);
        assert_eq!(can::can_stats(), (rx0, tx0 + 1, err0));
        assert!(can::can_recv().is_none());

        // A frame that matches the filter is still delivered.
        assert_eq!(can::can_send(&CanFrame::standard(0x456, &[9])), 0);
        assert_eq!(can::can_stats(), (rx0 + 1, tx0 + 2, err0));
        assert_eq!(can::can_recv().unwrap().id, 0x456);

        can::can_clear_filters();

        // **Overflow via `can_send`'s own loopback branch.** This pins the
        // discard-and-count fix directly: the old code called `rx_push` and
        // then unconditionally counted the frame as received, so a frame
        // dropped because the ring was full was still added to `rx_count` —
        // the same discipline the UDP receive path enforces, and the same
        // class of bug (a marker/counter that outlives what actually
        // survived).
        let (rx0, tx0, err0) = can::can_stats();
        for i in 0..RX_USABLE {
            assert_eq!(can::can_send(&CanFrame::standard(0x700 + i as u32, &[])), 0);
        }
        assert_eq!(can::can_available(), RX_USABLE);
        assert_eq!(can::can_stats(), (rx0 + RX_USABLE as u32, tx0 + RX_USABLE as u32, err0));

        // One more: the node still "transmits" (return value 0 — the bus
        // send itself did not fail) but the ring is full.
        assert_eq!(can::can_send(&CanFrame::standard(0x7AA, &[])), 0);
        let (rx1, tx1, err1) = can::can_stats();
        assert_eq!(rx1, rx0 + RX_USABLE as u32, "a full ring must not bump rx_count");
        assert_eq!(tx1, tx0 + RX_USABLE as u32 + 1);
        assert_eq!(err1, err0 + 1, "the drop must be discarded AND counted");
        assert_eq!(can::can_available(), RX_USABLE, "the dropped frame must not appear in the ring");

        for i in 0..RX_USABLE {
            let got = can::can_recv().expect("ring should still hold what fit, in order");
            assert_eq!(got.id, 0x700 + i as u32);
        }
        assert!(can::can_recv().is_none());

        // **Overflow via `can_inject`** — a separate call site into the same
        // ring, used by the shell/test-injection path rather than the
        // loopback TX path. Confirms the discard-and-count discipline holds
        // there too.
        let (rx0, tx0, err0) = can::can_stats();
        for i in 0..RX_USABLE {
            can::can_inject(&CanFrame::standard(0x500 + i as u32, &[]));
        }
        assert_eq!(can::can_available(), RX_USABLE);
        assert_eq!(can::can_stats(), (rx0 + RX_USABLE as u32, tx0, err0));

        can::can_inject(&CanFrame::standard(0x5AA, &[]));
        let (rx1, tx1, err1) = can::can_stats();
        assert_eq!(rx1, rx0 + RX_USABLE as u32, "a full ring must not bump rx_count");
        assert_eq!(tx1, tx0, "can_inject never touches tx_count");
        assert_eq!(err1, err0 + 1, "the drop must be discarded AND counted");
        assert_eq!(can::can_available(), RX_USABLE);

        for i in 0..RX_USABLE {
            let got = can::can_recv().expect("ring should still hold what fit, in order");
            assert_eq!(got.id, 0x500 + i as u32);
        }
        assert!(can::can_recv().is_none());
    }
}

// ── PWM control-register ownership domain ────────────────────────────────────
//
// **What this suite is for.** `HandleKind::Pwm(ch)` names a channel, and
// `pwm_control_allowed`/`pwm_control_reach` decide which channels a
// CONTROL-register write (enable/disable/set-period) actually lands on for a
// given `PwmDomain`. On the JH7110 (`vf2` — the real hardware target) that
// domain is `(8, shared_control = false)`: the OpenCores PTC core gives each
// channel its own `CNTR`/`HRC`/`LRC`/`CTRL` block, so a write named for
// channel N reaches only channel N. The `shared_control = true` branch of
// the same functions is still real code — some future board's control
// register may genuinely be shared — so it is exercised below against a
// synthetic domain rather than any current constant.
//
// **Why it is here and not in a QEMU scenario.** The `vf2` branch of `pwm.rs`
// is compiled out under QEMU — the sim path runs there instead — so no
// scenario in the gate can observe either domain's behaviour at all. The
// decision was extracted into `pwm_domain.rs` as a pure function precisely
// so the hardware shape could be tested on the host as a plain value, the
// same habit as `rc_frame_is_fresh_input` / `fd_access_allowed` /
// `irq_wait_ret`.
//
// `pwm_domain.rs` is pulled on its own rather than via `pwm.rs`: `pwm.rs`
// calls `SpinLock::get_mut_unchecked` on its panic path and the host sync
// shim deliberately does not provide it.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/actuator/src/pwm_domain.rs"]
mod pwm_domain;

#[cfg(test)]
mod pwm_ownership_domain {
    use super::pwm_domain::*;

    /// Helper: a caller holding exactly the listed channels.
    fn holder(held: &[u32]) -> impl Fn(u32) -> bool + '_ {
        move |c| held.contains(&c)
    }

    /// The shared-control shape, taken from the LIVE constant a `vf2` build
    /// gates on: `PWM_DOMAIN_VF2_DRIVER`, the SiFive layout `pwm.rs` still
    /// programs (the real part, `PWM_DOMAIN_INDEPENDENT_8`, is 8 independent
    /// channels). Using the real constant, not a synthetic one, means these
    /// tests fail if that constant ever drifts from `(4, true)` while the
    /// driver still shares `PWMCFG`.
    const SHARED_TEST_DOMAIN: PwmDomain = PWM_DOMAIN_VF2_DRIVER;

    /// **The mechanism a shared control register requires.** A task holding
    /// only channel 2 of a *shared* instance must not be able to reach
    /// channels 0, 1 and 3 through it.
    #[test]
    fn holding_one_channel_does_not_authorise_a_shared_control_write() {
        let only_two = holder(&[2]);
        assert!(!pwm_control_allowed(SHARED_TEST_DOMAIN, 2, &only_two),
            "Pwm(2) alone must not authorise a write that reaches 0, 1 and 3");
        // The reach is the evidence, not just the verdict: assert the mask so
        // a future change that makes the predicate refuse for some unrelated
        // reason cannot pass this test.
        assert_eq!(pwm_control_reach(SHARED_TEST_DOMAIN, 2), 0b1111,
            "a control write on a shared instance reaches every channel of it");
    }

    /// **The negative half.** Without this, the suite passes against a
    /// predicate that refuses everything — which would be a denial-of-service
    /// on the drivetrain dressed up as a security fix. A caller that holds
    /// every channel the write reaches must still be allowed through.
    #[test]
    fn holding_every_reached_channel_is_still_allowed() {
        let all_four = holder(&[0, 1, 2, 3]);
        for ch in 0..4 {
            assert!(pwm_control_allowed(SHARED_TEST_DOMAIN, ch, &all_four),
                "a caller holding the whole instance must be allowed on ch{ch}");
        }
    }

    /// Partial ownership is not ownership. `Pwm(0)` + `Pwm(1)` is the
    /// drivetrain's own pair, and it still must not be able to flip the
    /// shared enable line on behalf of channel 2 — because doing so also
    /// changes channel 3, which it does not hold. It must also be refused on
    /// its OWN channel 0: holding 0+1 does not cover the whole shared
    /// instance (0..3), so even a write named for a channel it holds reaches
    /// channel 3, which it does not.
    #[test]
    fn holding_some_of_the_reached_channels_is_refused() {
        let drivetrain = holder(&[0, 1]);
        assert!(!pwm_control_allowed(SHARED_TEST_DOMAIN, 0, &drivetrain),
            "0+1 does not cover the instance, so even ch0 is refused");
        assert!(!pwm_control_allowed(SHARED_TEST_DOMAIN, 2, &drivetrain),
            "0+1 certainly does not authorise a write named for ch2");
    }

    /// **Proves the split is modelled, not that everything is refused.** On
    /// an independent-channel instance (the simulation, and the real JH7110
    /// OpenCores PTC part) each channel has its own register block, so a
    /// write named for channel 2 reaches only channel 2 and `Pwm(2)` alone is
    /// sufficient. If this ever goes red alongside the shared-domain test
    /// passing, the predicate has stopped distinguishing the two shapes and
    /// has become a blanket deny.
    #[test]
    fn independent_channels_need_only_the_channel_named() {
        let only_two = holder(&[2]);
        assert!(pwm_control_allowed(PWM_DOMAIN_INDEPENDENT_8, 2, &only_two),
            "sim channels are independent; Pwm(2) is enough for ch2");
        assert_eq!(pwm_control_reach(PWM_DOMAIN_INDEPENDENT_8, 2), 1 << 2,
            "an independent instance reaches only the channel named");
        assert!(!pwm_control_allowed(PWM_DOMAIN_INDEPENDENT_8, 3, &only_two),
            "but it is still not authority over a channel it does not hold");
    }

    /// Out-of-range `ch` (at or past `channels`) must reach nothing and fall
    /// through to the driver's own bound check, which returns -1 — rather
    /// than being turned into an `E_PERM` that would let a caller map which
    /// channels exist by the difference between the two return codes. Uses
    /// channel 8, the first index past `PWM_DOMAIN_INDEPENDENT_8.channels` (8) and
    /// also past `PWM_MAX_CHANNELS` (8) — the capability space and the real
    /// hardware now agree on size, so there is no in-capability-space,
    /// off-hardware channel left to name; this only exercises the genuinely
    /// out-of-range case.
    #[test]
    fn a_channel_the_instance_does_not_have_reaches_nothing() {
        let nobody = holder(&[]);
        assert_eq!(pwm_control_reach(PWM_DOMAIN_INDEPENDENT_8, 8), 0);
        assert!(pwm_control_allowed(PWM_DOMAIN_INDEPENDENT_8, 8, &nobody),
            "out of range reaches no channel, so it needs no authority");
    }

    /// The build this suite runs on is a host build, so `PWM_DOMAIN` must
    /// resolve to the simulated shape. Pins the `cfg` selection itself: a
    /// mistake there would silently apply the wrong hardware model. Also
    /// pins both live constants' shapes directly.
    #[test]
    fn the_selected_domain_matches_the_compiled_target() {
        assert_eq!(PWM_DOMAIN, PWM_DOMAIN_INDEPENDENT_8,
            "a non-vf2 build drives the simulation, so that is its domain");
        assert!(!PWM_DOMAIN_INDEPENDENT_8.shared_control,
            "the OpenCores PTC core and the simulation have no shared control register");
        assert_eq!(PWM_DOMAIN_INDEPENDENT_8.channels, 8,
            "the OpenCores core has 8 independent channels, not 4");
        let drv = PWM_DOMAIN_VF2_DRIVER;
        assert!(drv.shared_control && drv.channels == 4,
            "the vf2 gate must describe the SiFive-layout driver pwm.rs compiles (4, shared PWMCFG)");
    }
}

// ── Which resource a driver call reaches ────────────────────────────────────
//
// `SYS_DRV_INVOKE` authorised with `CapTable::holds_kind_with`, which compares
// the capability's KIND and permissions and never its resource index. Drivers
// decode a resource from the caller's own payload, so a task holding
// `Cap<Gpio>(5)` reached pin 40 through the driver bridge while
// `sys_gpio_write` next door checked the pin correctly. `GpioDriver` is
// registered at boot, so that one was live rather than latent.
//
// The driver files themselves name hardware modules a host test cannot
// compile, so the decoding lives in `drv_resource.rs` — dependency-free, the
// same arrangement as `pwm_domain` — and each `Driver::request_resource` is a
// one-line delegation to it.

// Same reason as `pwm_domain` above: the non-test build of this crate
// compiles the module and calls none of it.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/base/src/drv_resource.rs"]
mod drv_resource;

#[cfg(test)]
mod driver_request_resource {
    use super::drv_resource::*;

    #[test]
    fn a_gpio_write_names_the_pin_it_lands_on() {
        // pin 40, little-endian, then the value byte.
        assert_eq!(gpio_request_resource(&[40, 0, 0, 0, 1]), Some(40));
    }

    #[test]
    fn a_gpio_payload_too_short_to_name_a_pin_names_none() {
        // Denies rather than guesses. Authorising on an index decoded out of
        // bytes the driver is about to reject as malformed is the wrong order.
        assert_eq!(gpio_request_resource(&[40, 0]), None);
        assert_eq!(gpio_request_resource(&[]), None);
    }

    #[test]
    fn the_i2c_encoding_matches_what_the_capability_packs() {
        // `Cap<I2c>`'s resource is `bus << 8 | addr`. Getting this wrong would
        // not fail loudly — the comparison would simply never match, and a
        // gate that always refuses looks like a working gate until something
        // legitimate is denied. Hence a literal, not a recomputation.
        assert_eq!(i2c_request_resource(&[1, 0x68, 0]), Some(0x0168));
        assert_eq!(i2c_request_resource(&[0, 0x76]), Some(0x0076));
        assert_eq!(i2c_request_resource(&[1]), None);
    }

    #[test]
    fn a_pwm_control_op_names_no_single_channel_even_though_it_takes_one() {
        // The distinction the whole finding turns on. Enable, disable and
        // set_period touch instance-wide bits on vf2, so the channel NAMED is
        // not the set REACHED; returning the named one would authorise a
        // narrow claim for a wide write. Those are gated by
        // `pwm_domain::pwm_control_allowed` instead.
        let ch2 = [2u8, 0, 0, 0];
        assert_eq!(pwm_request_resource(0, &ch2), None, "enable reaches the instance");
        assert_eq!(pwm_request_resource(1, &ch2), None, "disable reaches the instance");
        assert_eq!(pwm_request_resource(2, &ch2), None, "set_period reaches the instance");
    }

    #[test]
    fn a_pwm_duty_op_is_genuinely_per_channel() {
        // The negative half of the test above. Without it, returning `None`
        // for everything would pass — and `None` falls back to the kind-wide
        // check, which is exactly the weaker behaviour being replaced. A
        // blanket `None` would look like a fix and change nothing.
        let ch2 = [2u8, 0, 0, 0, 50];
        assert_eq!(pwm_request_resource(3, &ch2), Some(2), "set_duty writes PWMCMP");
        assert_eq!(pwm_request_resource(4, &ch2), Some(2), "set_duty_pct writes PWMCMP");
    }
}

// ── The motor bridge's pair rule ──────────────────────────────────────────

#[cfg(test)]
mod motor_bridge_pair_tests {
    use super::drv_resource::motor_bridge_op_needs_pair;

    /// The five ops that command the drivetrain need both wheels; the one
    /// that only reports state does not.
    ///
    /// **The exclusion is the assertion with teeth.** `MOTOR_OP_ENABLED` (3)
    /// mirrors `SYS_MOTOR_ENABLED_TYPED` (553), which is documented READ-only
    /// and explicitly not pair-wide, and whose handler takes the `READ` path
    /// with no pair call. A predicate that returned true for everything would
    /// satisfy the positive half of this test and make the bridge stricter
    /// than the typed syscall it exists to match.
    ///
    /// **Canary.** Change the predicate to `op <= 5`: the `ENABLED` assertion
    /// must go red while the five positives stay green.
    #[test]
    fn only_the_drivetrain_commanding_ops_need_the_pair() {
        for op in [0u32, 1, 2, 4, 5] {
            assert!(
                motor_bridge_op_needs_pair(op),
                "MOTOR_OP {op} commands the drivetrain and must need both wheels"
            );
        }
        assert!(
            !motor_bridge_op_needs_pair(3),
            "MOTOR_OP_ENABLED is READ-only in the typed path (553) and must not \
             become pair-wide only on the bridge"
        );
    }

    /// The numbers in the predicate ARE the `MOTOR_OP_*` constants.
    ///
    /// `drv_resource.rs` is dependency-free by design and this crate pulls in
    /// individual modules by `#[path]` rather than depending on
    /// `azos_drv_*`, so neither can import the constants. The predicate
    /// spells them as literals, and this reads `motor_driver.rs` as TEXT to
    /// join the two — the same trick, for the same reason, that
    /// `tests/host/seccomp-tests` uses on `dispatch.rs`.
    ///
    /// The failure it prevents is silent: renumbering an op would move the
    /// pair requirement onto a different operation, and a build over a stale
    /// literal says nothing.
    #[test]
    fn the_predicate_numbers_are_the_motor_op_constants() {
        let src = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../crates/drivers/actuator/src/motor_driver.rs"),
        )
        .expect("motor_driver.rs must be readable — this test IS the join");

        let mut seen = 0usize;
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("pub const MOTOR_OP_") else { continue };
            let Some((name, value)) = rest.split_once(": u32 = ") else { continue };
            let n: u32 = value
                .trim_end_matches(';')
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("MOTOR_OP_{name} is not a plain decimal"));
            seen += 1;
            // ENABLED only reports state; everything else commands the pair.
            let expect_pair = name != "ENABLED";
            assert_eq!(
                motor_bridge_op_needs_pair(n),
                expect_pair,
                "MOTOR_OP_{name} = {n}: predicate and constant disagree"
            );
        }
        assert_eq!(
            seen, 6,
            "expected 6 MOTOR_OP_* constants; the parse found {seen} — if an op \
             was added or removed, motor_bridge_op_needs_pair must be revisited"
        );
    }

    /// An op the driver does not implement is not pair-wide — and is refused
    /// by `handle_request`'s `_ => Err(BadOp)` regardless.
    #[test]
    fn an_unknown_op_is_not_pair_wide() {
        for op in [6u32, 7, 99, u32::MAX] {
            assert!(!motor_bridge_op_needs_pair(op));
        }
    }
}

// ── I2C bus serialisation ─────────────────────────────────────────────────
//
// `IC_TAR` (DesignWare offset 0x04) selects which slave the controller talks
// to. It is bus state, so {write IC_TAR, transfer} from two tasks on one bus
// can interleave and hand one caller the other's device — a wrong-sensor read
// that raises no error anywhere. The fix is a per-bus lock, and
// `i2c_bus_lock_slot` is the mapping that makes it per-bus.
//
// The whole module is pulled rather than a bare predicate file, because the
// constraint on this change was that no second file could be added to
// the driver crates (`crates/drivers/*`) (a new module needs a `mod` line in `lib.rs`). Pulling
// `i2c.rs` works here only because the DesignWare half is `#[cfg(feature =
// "vf2")]` and therefore absent on the host; what compiles below is the top
// level plus the simulation.
// `unused_imports` for the same reason as `virtio` above: `i2c.rs` ends with
// `pub use sim::*`, which re-exports the simulated entry points for the kernel.
// Nothing in this suite calls them, so the re-export is unused *here* — the
// module's shape, not a defect in it.
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/drivers/bus/src/i2c.rs"]
mod i2c;

// The INA219 chip logic, from the ring-3 driver (wave 9): no kernel crate
// names it any more. Pure (a `Bus` trait, no syscalls), so it goes in
// unmodified.
//
// Declared AFTER `i2c`, not before: the `#[allow(dead_code, unused_imports)]`
// above belongs to `i2c`, and inserting between an attribute and its item
// silently reattaches it — which is how a first attempt at this turned five
// of `i2c`'s items into warnings, and warnings fail this gate.
// The INA219 chip logic is a crate of its own (crates/drivers/ina219), the
// one source both placements compile; a dependency, not a `#[path]` module.
#[cfg(test)]
use azos_ina219 as ina219;

#[cfg(test)]
mod i2c_bus_locks {
    use super::i2c::{i2c_bus_lock_slot, I2C_BUS_COUNT, I2C_BUS_LOCKS};

    /// Serialises the tests in this module that take a lock in
    /// `I2C_BUS_LOCKS`.
    ///
    /// The array is one static shared by every test thread, and all three
    /// lock bus 0. Run in parallel, one test holding bus 0 makes another's
    /// "the bus was not released" check fail although the lock is correct:
    /// measured 2026-09-15 as 21 failures in 300 runs of the whole binary,
    /// every one in `two_callers_on_one_bus_cannot_hold_it_at_once`, and none
    /// when that test ran alone.
    static BUS_LOCK_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        BUS_LOCK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── The exclusion itself, which nothing tested until 2026-09-08 ───────
    //
    // Everything below this block checks the ARITHMETIC that picks a lock
    // slot. That is worth checking and it is not the property the locks exist
    // for: a mapping test passes just as happily on an array of one lock
    // aliased across every bus, or on a lock that does not exclude at all.
    //
    // The array used to live inside `mod dw_i2c`, which is
    // `#[cfg(feature = "vf2")]` and names MMIO, so no host test could reach
    // it. It was moved out — same reasoning already written for
    // `i2c_bus_lock_slot` — precisely so these three can exist.
    //
    // WHAT THESE DO NOT PROVE. On the host `SpinLock` is a `std::sync::Mutex`
    // (`tests/host/cap-tests/shims/sync`), so this is the DISCIPLINE — one holder
    // per bus, buses independent — and not the RISC-V spin, the preemption
    // guard, or the deadlock argument in `i2c.rs`'s doc comment. It is also
    // not a test that `i2c_read` takes the lock: that code is behind the same
    // `vf2` feature and stays out of reach here.

    /// Two callers on the SAME bus cannot both be inside a transfer.
    ///
    /// This is what `IC_TAR` needs: the slave address is bus state, not
    /// transaction state, so an interleaving reads the wrong device.
    #[test]
    fn two_callers_on_one_bus_cannot_hold_it_at_once() {
        let _serial = serial();
        let slot = i2c_bus_lock_slot(0).expect("bus 0 has a slot");
        let held = I2C_BUS_LOCKS[slot].lock();
        assert!(
            I2C_BUS_LOCKS[slot].try_lock().is_none(),
            "a second caller acquired bus 0 while a transfer was in progress",
        );
        drop(held);
        assert!(
            I2C_BUS_LOCKS[slot].try_lock().is_some(),
            "the bus was not released",
        );
    }

    /// And two callers on DIFFERENT buses do not wait for each other.
    ///
    /// The negative half, and the one that justifies per-bus granularity
    /// instead of one lock for the controller. `i2c.rs` argues it in prose —
    /// "two controllers share no `IC_TAR` and serialising them would cost
    /// throughput for nothing". Without this, collapsing the array to a
    /// single lock would keep every other test in this file green.
    #[test]
    fn two_buses_are_independent_locks() {
        let _serial = serial();
        assert!(I2C_BUS_COUNT >= 2, "otherwise this proves nothing");
        let a = i2c_bus_lock_slot(0).expect("bus 0");
        let b = i2c_bus_lock_slot(1).expect("bus 1");
        let _held_a = I2C_BUS_LOCKS[a].lock();
        assert!(
            I2C_BUS_LOCKS[b].try_lock().is_some(),
            "holding bus 0 blocked bus 1 — the buses share a lock",
        );
    }

    /// Under real contention, no two holders overlap.
    ///
    /// `try_lock` proves exclusion against a lock held on the SAME thread,
    /// which a lock that simply always succeeds would also pass. This drives
    /// it from several threads and keeps a flag that is only ever set inside
    /// the critical section: two overlapping holders see it already set.
    #[test]
    fn concurrent_callers_never_overlap_on_one_bus() {
        let _serial = serial();
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        static INSIDE: AtomicBool = AtomicBool::new(false);
        static OVERLAPS: AtomicUsize = AtomicUsize::new(0);
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        INSIDE.store(false, Ordering::SeqCst);
        OVERLAPS.store(0, Ordering::SeqCst);
        ENTERED.store(0, Ordering::SeqCst);

        let slot = i2c_bus_lock_slot(0).expect("bus 0");
        std::thread::scope(|sc| {
            for _ in 0..4 {
                sc.spawn(move || {
                    for _ in 0..500 {
                        let _g = I2C_BUS_LOCKS[slot].lock();
                        if INSIDE.swap(true, Ordering::SeqCst) {
                            OVERLAPS.fetch_add(1, Ordering::SeqCst);
                        }
                        ENTERED.fetch_add(1, Ordering::SeqCst);
                        std::hint::spin_loop();
                        INSIDE.store(false, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(ENTERED.load(Ordering::SeqCst), 2000, "not every pass ran");
        assert_eq!(
            OVERLAPS.load(Ordering::SeqCst), 0,
            "two callers were inside a bus-0 transfer at the same time",
        );
    }


    /// The property the per-bus scoping rests on. If two buses shared a slot
    /// they would share a lock, and two independent controllers would
    /// serialise against each other — the "one global lock" shape this change
    /// exists to avoid. Worse in the other direction: a mapping that collided
    /// only for *some* pair would look correct in a smoke test and quietly
    /// halve throughput on the pair that collides.
    #[test]
    fn distinct_buses_never_share_a_lock_slot() {
        let mut seen: Vec<usize> = Vec::new();
        for bus in 0..=u8::MAX {
            let Some(slot) = i2c_bus_lock_slot(bus) else { continue };
            assert!(
                !seen.contains(&slot),
                "bus {bus} maps to slot {slot}, already claimed by another bus — \
                 two controllers would share one lock"
            );
            seen.push(slot);
        }
        assert!(!seen.is_empty(), "no bus maps to a slot: nothing would be locked at all");
    }

    /// The bound that keeps the lock array indexable. The call sites use
    /// `.get()`, so violating this degrades to "the transfer is refused"
    /// rather than a panic — but a refused sensor read on a flying robot is
    /// not a good failure either, and this is the check that keeps it
    /// unreachable.
    #[test]
    fn every_slot_indexes_the_lock_array_in_bounds() {
        for bus in 0..=u8::MAX {
            if let Some(slot) = i2c_bus_lock_slot(bus) {
                assert!(
                    slot < I2C_BUS_COUNT,
                    "bus {bus} maps to slot {slot}, outside the {I2C_BUS_COUNT}-entry \
                     lock array"
                );
            }
        }
    }

    /// A bus with no slot must be refused, not silently run unlocked.
    ///
    /// This is the direction that fails dangerously: if `i2c_bus_lock_slot`
    /// returned `Some` for a bus outside the array, `.get()` would return
    /// `None` and the entry point would bail — but if it returned `None` for a
    /// bus that *does* have hardware, that bus would be refused entirely.
    /// Both are caught by pairing this with the test above.
    #[test]
    fn a_bus_past_the_array_has_no_slot() {
        for bus in I2C_BUS_COUNT..=u8::MAX as usize {
            assert_eq!(
                i2c_bus_lock_slot(bus as u8),
                None,
                "bus {bus} is past the {I2C_BUS_COUNT}-entry lock array and must have no slot"
            );
        }
    }

    /// The two buses the bring-up plan actually populates — an MPU-6050 at
    /// 0x68 and a BMP280 at 0x76 both sit on bus 0, and `bus_base` maps buses
    /// 0 and 1 — must both be lockable. A mapping that returned `None` for
    /// either would leave the real hardware unserialised while the two tests
    /// above still passed.
    #[test]
    fn the_buses_the_hardware_uses_are_lockable() {
        assert!(i2c_bus_lock_slot(0).is_some(), "bus 0 carries the IMU and the barometer");
        assert!(i2c_bus_lock_slot(1).is_some(), "bus 1 is mapped by bus_base");
    }
}

// ── Which SBUS bit becomes RC_FAILSAFE ────────────────────────────────────

/// `rc_apply_sbus_frame` is the one place the failsafe decision is made, and
/// this is where it is pinned.
///
/// **Takes `rc_failsafe`'s `RC_SERIAL`**, exactly as `sbus_decoder`'s doc
/// says any test touching the driver globals must — a second mutex would
/// serialize nothing against the tests that already drive `rc_init`.
#[cfg(test)]
mod sbus_failsafe_policy {
    use super::rc::{self, SbusFrame};
    use super::rc_failsafe::serial;

    fn frame(failsafe: bool, frame_lost: bool) -> SbusFrame {
        SbusFrame {
            channels: [rc::SBUS_RAW_CENTER; 16],
            failsafe,
            frame_lost,
            ch17: false,
            ch18: false,
        }
    }

    /// The receiver's own verdict (`failsafe`, flags bit 3) sets
    /// `RC_FAILSAFE`. A single lost frame (`frame_lost`, bit 2) does NOT.
    ///
    /// The second half is the decision, not a detail. `RC_FAILSAFE` gates
    /// whether a frame refreshes `CH_RC_INPUT`, so whether `rc_age` grows and
    /// `FailsafeAction::RTL` fires. `frame_lost` is set for one missing frame,
    /// which at 100 Hz happens with ordinary interference — feeding it would
    /// turn a glitch into a return-to-launch with propellers turning.
    ///
    /// **Canary.** Change `rc_apply_sbus_frame` to
    /// `frame.failsafe || frame.frame_lost`: the `frame_lost`-only assertion
    /// must go red while the other three stay green.
    #[test]
    fn only_the_receivers_verdict_becomes_rc_failsafe() {
        let _g = serial();
        rc::rc_init(rc::RcMode::Simulated);

        rc::rc_apply_sbus_frame(&frame(false, false));
        let (_, fs) = rc::rc_read().expect("Simulated mode is live");
        assert!(!fs, "a clean frame is not a failsafe");

        rc::rc_apply_sbus_frame(&frame(false, true));
        let (_, fs) = rc::rc_read().expect("still live");
        assert!(!fs, "frame_lost is ONE dropped frame, not a lost link");

        rc::rc_apply_sbus_frame(&frame(true, false));
        let (_, fs) = rc::rc_read().expect("still live");
        assert!(fs, "the receiver's own failsafe bit must set RC_FAILSAFE");

        rc::rc_apply_sbus_frame(&frame(true, true));
        let (_, fs) = rc::rc_read().expect("still live");
        assert!(fs, "both bits set is still a failsafe");
    }

    /// A good frame CLEARS a previously latched failsafe.
    ///
    /// Without this the test above passes against an implementation that only
    /// ever sets the flag — and a failsafe that never clears is a robot that
    /// never flies again after one interference burst.
    #[test]
    fn a_good_frame_clears_a_latched_failsafe() {
        let _g = serial();
        rc::rc_init(rc::RcMode::Simulated);

        rc::rc_apply_sbus_frame(&frame(true, false));
        assert!(rc::rc_read().expect("live").1, "precondition: latched");

        rc::rc_apply_sbus_frame(&frame(false, false));
        assert!(!rc::rc_read().expect("live").1, "a good frame must clear it");
    }
}

// ── An unconfigured INA219 must not report a healthy battery ──────────────
//
// The chip logic moved out of the kernel in wave 9 and into its own crate in
// wave 11 (`crates/drivers/ina219`, used above). It is a struct over a `Bus` trait now, not
// process-wide statics over the kernel's I2C, so each test owns its chip and
// its bus, and a reachable chip can finally be tested too.

#[cfg(test)]
mod ina219_no_fabricated_battery {
    use super::ina219::{Bus, Ina219, POWER_DATA_SIZE};

    /// A bus with an INA219 behind it, or with nothing (`present = false`).
    /// `writes` records every accepted write.
    struct FakeBus {
        present: bool,
        bus_voltage: u16,
        current: u16,
        writes: Vec<Vec<u8>>,
    }

    impl FakeBus {
        fn absent() -> Self {
            FakeBus { present: false, bus_voltage: 0, current: 0, writes: Vec::new() }
        }
        /// `mv` on the bus, `ma` drawn (0.1 mA LSB, as calibration 4096 sets).
        fn chip(mv: u16, ma: u16) -> Self {
            FakeBus { present: true, bus_voltage: (mv / 4) << 3, current: ma * 10, writes: Vec::new() }
        }
    }

    impl Bus for FakeBus {
        fn write(&mut self, data: &[u8]) -> bool {
            if self.present { self.writes.push(data.to_vec()); }
            self.present
        }
        fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool {
            if !self.present || buf.len() != 2 { return false; }
            let v = match reg { 0x02 => self.bus_voltage, 0x04 => self.current, _ => 0 };
            buf.copy_from_slice(&v.to_be_bytes());
            true
        }
    }

    /// **The composition that made "never initialised" read as "battery
    /// full".** Pinned as arithmetic: `mah_used` = 0 (nothing polled) ->
    /// `capacity_pct` = 100 -> `failsafe_level` = 0, "no battery failsafe".
    /// Correct arithmetic for a real full pack; it is asserted so that the
    /// guard in `read_power` is understood as load-bearing.
    #[test]
    fn the_unpolled_state_composes_into_a_full_battery() {
        let chip = Ina219::new();
        assert_eq!(chip.mah_used(), 0, "nothing has polled");
        assert_eq!(chip.capacity_pct(), 100);
        assert_eq!(chip.failsafe_level(), 0, "reads as 'no failsafe'");
    }

    /// So `read_power` must refuse while unconfigured: 0 bytes, the sensor
    /// dispatch's "no data", and the buffer untouched.
    ///
    /// **Canary.** Delete the `!self.initialized` half of the guard: this goes
    /// red while the arithmetic test above stays green.
    #[test]
    fn read_power_refuses_while_the_chip_is_unconfigured() {
        let chip = Ina219::new();
        let mut buf = [0xAAu8; POWER_DATA_SIZE];
        assert_eq!(chip.read_power(&mut buf), 0,
            "an unconfigured INA219 must report NO data, not a full battery");
        assert!(buf.iter().all(|&b| b == 0xAA), "the buffer must be untouched");
    }

    /// Wave 11 (DRVPLACE): `serve` is the request dispatch both hosts call
    /// (ring 3 per `DriverRequest`, the kernel per direct call), so the two
    /// placements answer from the same code. Its layouts are the
    /// `power_op` ABI: READ = the record, READ_TS = record + acq_ns,
    /// STATS = samples, failures, configured, charge.
    ///
    /// **Canary.** Swap the `samples`/`failures` fields in `serve`'s STATS
    /// arm, or drop the `acq_ns` copy from READ_TS: this goes red.
    #[test]
    fn serve_answers_the_power_op_layouts_from_the_chip_state() {
        use azos_abi::drv_kind::power_op;
        use azos_ina219::serve;
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        let mut out = [0xAAu8; 64];
        assert_eq!(serve(&chip, power_op::READ, 7, &mut out), Some(0), "unconfigured: no data");
        assert_eq!(serve(&chip, power_op::READ_TS, 7, &mut out), Some(0), "unconfigured: no data");
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 1_000);
        chip.poll(&mut bus, 101_000);
        let mut direct = [0u8; POWER_DATA_SIZE];
        assert_eq!(chip.read_power(&mut direct), POWER_DATA_SIZE);
        assert_eq!(serve(&chip, power_op::READ, 0, &mut out), Some(POWER_DATA_SIZE));
        assert_eq!(&out[..POWER_DATA_SIZE], &direct);
        assert_eq!(serve(&chip, power_op::READ_TS, 0x1122_3344_5566_7788, &mut out),
                   Some(power_op::POWER_TS_BYTES));
        assert_eq!(&out[..POWER_DATA_SIZE], &direct);
        assert_eq!(u64::from_le_bytes(out[POWER_DATA_SIZE..power_op::POWER_TS_BYTES].try_into().unwrap()),
                   0x1122_3344_5566_7788);
        assert_eq!(serve(&chip, power_op::STATS, 0, &mut out), Some(power_op::STATS_BYTES));
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 2, "two samples");
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 0, "no failures");
        assert_eq!(out[8], 1, "configured");
        assert_eq!(u64::from_le_bytes(out[9..17].try_into().unwrap()), 1500 * 100_000,
                   "1500 mA over the 100 ms between the two samples");
        assert_eq!(serve(&chip, 0x99, 0, &mut out), None, "an unknown op is refused");
        let mut short = [0u8; power_op::STATS_BYTES - 1];
        assert_eq!(serve(&chip, power_op::STATS, 0, &mut short), Some(0));
    }

    /// A buffer too small is refused independently of initialisation.
    #[test]
    fn a_short_buffer_is_refused_independently_of_initialisation() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 0);
        let mut small = [0u8; POWER_DATA_SIZE - 1];
        assert_eq!(chip.read_power(&mut small), 0);
    }

    /// **A chip that is not there stays unconfigured.** The in-kernel
    /// `ina219_init` marked the chip ready without checking that its writes
    /// landed, so an absent monitor then answered `read_power` from its boot
    /// defaults. Now the two configuration writes decide it.
    ///
    /// **Canary.** Make `init` set `initialized = true` unconditionally: the
    /// first assertion goes red.
    #[test]
    fn an_absent_chip_is_not_configured_and_reports_nothing() {
        let mut bus = FakeBus::absent();
        let mut chip = Ina219::new();
        assert!(!chip.init(&mut bus), "no device answered the configuration writes");
        assert!(!chip.is_initialized());
        chip.poll(&mut bus, 0);
        assert_eq!(chip.sample_count(), 0);
        assert_eq!(chip.read_failures(), 0, "an unconfigured chip is not polled at all");
        assert_eq!(chip.read_power(&mut [0u8; POWER_DATA_SIZE]), 0);
    }

    /// **A poll that cannot reach the chip must publish nothing.** Configured
    /// while present, then gone: every register read fails. Zero volts and
    /// zero amps would be a specific, alarming claim about the pack; the last
    /// good sample stays, `sample_count` does not move, `read_failures` does,
    /// one per poll (the first failed register aborts the poll).
    ///
    /// **Canary.** Decode `buf` in `read_register` whatever `Bus::read`
    /// returned: `sample_count` advances and the voltage drops to 0.
    #[test]
    fn a_poll_that_cannot_reach_the_chip_publishes_nothing() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 0);
        assert_eq!((chip.sample_count(), chip.voltage_mv()), (1, 7400));
        bus.present = false;
        for _ in 0..5 { chip.poll(&mut bus, 0); }
        assert_eq!(chip.sample_count(), 1, "a failed poll is not a sample");
        assert_eq!(chip.read_failures(), 5, "one failure per poll, visible");
        assert_eq!(chip.voltage_mv(), 7400, "the last good sample stays");
        assert!(!chip.sag_detected(), "a chip that stopped answering is not a sag");
    }

    /// The good path, which the in-kernel tests could not reach from the
    /// host: calibration then config written, the record decoded.
    #[test]
    fn a_configured_chip_publishes_the_record() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        assert_eq!(bus.writes, vec![vec![0x05, 0x10, 0x00], vec![0x00, 0x39, 0x9F]],
            "calibration 4096, then config 0x399F");
        chip.poll(&mut bus, 0);
        let mut b = [0u8; POWER_DATA_SIZE];
        assert_eq!(chip.read_power(&mut b), POWER_DATA_SIZE);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 7400);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 1500);
        assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0);
        assert_eq!((b[8], b[9], b[10], b[11]), (100, 0, 0, 0));
    }

    /// Sag: a drop of more than 500 mV between two samples, and only then.
    #[test]
    fn a_voltage_drop_past_the_threshold_is_a_sag() {
        let mut bus = FakeBus::chip(7400, 0);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 0);
        bus.bus_voltage = (7000 / 4) << 3;
        chip.poll(&mut bus, 0);
        assert!(!chip.sag_detected(), "400 mV is under the threshold");
        bus.bus_voltage = (6400 / 4) << 3;
        chip.poll(&mut bus, 0);
        assert!(chip.sag_detected(), "600 mV is past it");
    }

    /// mAh: summed raw (mA x us) and divided at read time. 36 000 intervals
    /// of 100 ms at 1 mA is 1 mAh; per-sample division would give 0.
    #[test]
    fn mah_integrates_without_per_poll_truncation() {
        let mut bus = FakeBus::chip(7400, 1);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        for i in 0..=36_000u64 { chip.poll(&mut bus, i * 100_000); }
        assert_eq!(chip.mah_used(), 1);
    }

    // ── Wave 10 (DRV2): the charge follows the clock, not a cadence ──────
    //
    // Each sample's current is weighted by the time the driver's clock
    // measured since the previous published sample. Before, every poll stood
    // for a nominal 1/`INA219_POLL_HZ` s, so a driver woken late (host load,
    // a lower-priority hart) under-counted the pack by exactly the lateness.
    //
    // **Canary** (by hand, DRV2 report): make `poll` add `current_ma x
    // 100_000` per sample, ignoring `now_us` — the fixed cadence it replaced.
    // The irregular-interval, slow-cadence, gap and backwards-clock tests go
    // red (4); the first-sample test stays green (no interval to weigh).

    /// The first sample has no interval behind it: no charge.
    #[test]
    fn the_first_sample_adds_no_charge() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 5_000_000);
        assert_eq!(chip.charge_ma_us(), 0);
    }

    /// Irregular intervals: 100 ms, 250 ms, 1 s at 1500 mA is 1500 mA x
    /// 1.35 s, not three nominal 100 ms periods.
    #[test]
    fn charge_is_current_times_the_measured_interval() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        for t in [0u64, 100_000, 350_000, 1_350_000] { chip.poll(&mut bus, t); }
        assert_eq!(chip.charge_ma_us(), 1500 * 1_350_000);
    }

    /// An hour at 1500 mA is 1500 mAh whatever the cadence: sampled every
    /// 250 ms here (a cadence-counting sum reads 600).
    #[test]
    fn an_hour_at_a_slow_cadence_is_still_the_hours_charge() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        for i in 0..=14_400u64 { chip.poll(&mut bus, i * 250_000); }
        assert_eq!(chip.mah_used(), 1500);
        assert_eq!(chip.capacity_pct(), 58, "(3600 - 1500) / 3600");
    }

    /// Failed reads publish no sample and leave the sample time where it
    /// was, so the next good sample covers the whole gap.
    #[test]
    fn a_failed_read_leaves_the_gap_to_the_next_good_sample() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 0);
        bus.present = false;
        for t in [100_000u64, 200_000, 300_000, 400_000, 500_000] { chip.poll(&mut bus, t); }
        assert_eq!(chip.charge_ma_us(), 0, "a failed read is not a sample");
        bus.present = true;
        chip.poll(&mut bus, 1_000_000);
        assert_eq!(chip.charge_ma_us(), 1500 * 1_000_000);
        assert_eq!(chip.sample_count(), 2);
    }

    /// A clock reading earlier than the last sample adds nothing (and does
    /// not wrap into an enormous interval).
    #[test]
    fn a_clock_that_went_backwards_adds_nothing() {
        let mut bus = FakeBus::chip(7400, 1500);
        let mut chip = Ina219::new();
        assert!(chip.init(&mut bus));
        chip.poll(&mut bus, 1_000_000);
        chip.poll(&mut bus, 500_000);
        assert_eq!(chip.charge_ma_us(), 0);
    }
}

// ── motor_pid_tick: the bounds that stop ring 3 resetting the board ──────
//
// `motor_pid_tick` had NO test of any kind — not here, not in the drivers
// crate, not on a booted machine. Its own source calls the saturating
// arithmetic "a security bound, not a robustness nicety", and it is right:
// `now`, `ticks_l` and `ticks_r` arrive from ring 3 through
// `SYS_MOTOR_TICK_TYPED` with no range validation on the way, this kernel is
// `panic = "abort"` with `overflow-checks = true`, and a spontaneous reset on
// a robot is a physical-safety event. A bound stated only in a comment is a
// bound nobody has checked.
//
// It cannot be exercised from ring 3. Doing so means writing hostile values
// into the live controller state `rt_motor_task` shares, which leaves the
// drivetrain driven from poisoned velocity — see the note in
// `userspace/tests/captest`. So it is pinned here, where the state is this test's
// own.
#[cfg(test)]
mod motor_pid_tick_bounds {
    use super::motor_pid::*;
    use std::sync::Mutex;

    /// One lock for the module. `motor_pid`'s state is process-wide statics
    /// (`PID_ENABLED`, `TICK_STATE`, `PID_CONTROLLERS`) and the runner uses
    /// several threads — the hazard the RC tests above fixed the same way.
    static PID_TICK_SERIAL: Mutex<()> = Mutex::new(());

    /// Take the lock AND state the precondition rather than inheriting it.
    /// `motor_pid_init` resets the controllers, zeroes the targets, clears
    /// `TICK_STATE` and enables closed-loop control — which is also exactly
    /// the state a real boot leaves behind.
    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = PID_TICK_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        motor_pid_init();
        g
    }

    /// **The exact two-call sequence the source names.** `now = 1` records the
    /// baseline, then `now = 0x8000_0000_0000_0001` makes `elapsed` ~2^63 and
    /// `elapsed * 1000` overflow u64. With `overflow-checks = true` an
    /// unsaturated multiply aborts, and abort here is a board reset triggered
    /// by a ring-3 argument.
    ///
    /// The assertion is that the call RETURNS. A panic fails the test by
    /// aborting the process, which is the strongest form the check can take.
    #[test]
    fn hostile_timestamp_does_not_overflow_the_elapsed_multiply() {
        let _g = begin();
        assert_eq!(motor_pid_tick(0, 0, 1), (0, 0), "first call records a baseline");
        let out = motor_pid_tick(0, 0, 0x8000_0000_0000_0001);
        // Saturating `dt_ms` becomes enormous, so the measured velocity rounds
        // to ~0 — "no motion measured", the safe reading. What must NOT happen
        // is a trap on the way here.
        assert!(out.0.abs() <= 100 && out.1.abs() <= 100,
                "PWM must stay in range after a saturated dt, got {out:?}");
    }

    /// **`u64::MAX` as the very first timestamp, then a small one.** The other
    /// direction of the same window: `wrapping_sub` is what keeps this from
    /// trapping, and a plain subtraction would abort on the second call.
    #[test]
    fn timestamp_going_backwards_does_not_trap() {
        let _g = begin();
        assert_eq!(motor_pid_tick(0, 0, u64::MAX), (0, 0));
        let out = motor_pid_tick(0, 0, 1);
        assert!(out.0.abs() <= 100 && out.1.abs() <= 100,
                "PWM must stay in range after a backwards clock, got {out:?}");
    }

    /// **Encoder deltas at the i64 extremes.** `i64::MAX` then `i64::MIN`
    /// overflows the subtraction, and the `* 1000` overflows well before that.
    /// Both are ring-3 arguments.
    ///
    /// And the result must be CLAMPED, not truncated: the source says a
    /// wrapped cast turns a huge positive velocity into a large negative one,
    /// which the PID answers by driving the motor the wrong way. So the check
    /// is not merely "it did not panic" — a wrapping build could survive and
    /// still command the opposite direction.
    #[test]
    fn extreme_encoder_deltas_saturate_rather_than_wrap() {
        let _g = begin();
        // A real dt: 10 ms at the QEMU timebase, so the divide is exercised
        // rather than short-circuited by `dt_ms == 0`.
        let t0 = 1_000_000u64;
        let dt = super::clint::TIMER_FREQ / 100;
        assert_eq!(motor_pid_tick(0, 0, t0), (0, 0));
        // THE ASSERTION IS THE SIGN, not the magnitude. Both a saturating and
        // a wrapping build clamp the final PWM to +-100, so `|pwm| <= 100`
        // cannot tell them apart — it would be a test that passes on the very
        // defect its own comment describes. Target is 0 and the wheel is
        // measured racing FORWARD, so the only correct answer is a NEGATIVE
        // command. A truncating `as i32` flips the velocity's sign and the
        // controller answers +100: full speed in the direction it was already
        // running away in. Measured: saturating gives (-100,-100) here and
        // (100,100) below.
        let out = motor_pid_tick(i64::MAX, i64::MAX, t0 + dt);
        assert!(out.0 <= 0 && out.1 <= 0,
                "a wheel measured racing forward must be commanded back, got {out:?}");
        assert!(out.0 >= -100 && out.1 >= -100, "PWM out of range: {out:?}");
        let out2 = motor_pid_tick(i64::MIN, i64::MIN, t0 + 2 * dt);
        assert!(out2.0 >= 0 && out2.1 >= 0,
                "a wheel measured racing backward must be commanded forward, got {out2:?}");
        assert!(out2.0 <= 100 && out2.1 <= 100, "PWM out of range: {out2:?}");
    }

    /// **Two ticks inside the same timer resolution must not divide.** `dt_ms`
    /// is computed from a timer delta, so two calls close together reach the
    /// derivative term with `dt == 0` — a division by zero, i.e. a reset. The
    /// documented answer is `(0, 0)`, not a smaller output.
    #[test]
    fn zero_elapsed_returns_zero_rather_than_dividing() {
        let _g = begin();
        assert_eq!(motor_pid_tick(0, 0, 5_000), (0, 0), "baseline");
        assert_eq!(motor_pid_tick(1_000, 1_000, 5_000), (0, 0),
                   "same timestamp must short-circuit before the divide");
    }

    /// **Disabled means disabled**, and it is the first line of the function
    /// for a reason: `motor_pid_enable(false)` is how the RT task is put into
    /// open-loop, and a tick that still computed would fight the direct PWM
    /// path for the same wheels.
    #[test]
    fn a_disabled_controller_computes_nothing() {
        let _g = begin();
        motor_pid_set_target(80, 80);
        motor_pid_enable(false);
        assert_eq!(motor_pid_tick(0, 0, 1_000), (0, 0));
        assert_eq!(motor_pid_tick(0, 0, 1_000 + super::clint::TIMER_FREQ / 100), (0, 0),
                   "a disabled controller must not answer a standing target");
        motor_pid_enable(true);
    }
}

// ── riscv64 ring-3 interrupt ownership (wave 9 IRQ4 item 2) ─────────────────
//
// `user_irq.rs`'s bitmaps build on the host; its controller half
// (`bind`/`mask`/`unmask`/`release`) is riscv64-only and not compiled here.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/irqchip/src/user_irq.rs"]
mod user_irq;

#[cfg(test)]
mod user_irq_tests {
    use super::user_irq::{bindable, dtb_trigger, mark, mark_kernel, note_dtb_trigger, owned, unmark};

    /// A line the kernel enabled for itself (the console, a virtio vector)
    /// is refused to ring 3; source 0 and sources past the table are too.
    ///
    /// Canary: drop `!test(&KERNEL, irq)` from `bindable` — line 10 binds.
    #[test]
    fn kernel_lines_and_out_of_range_sources_are_not_bindable() {
        mark_kernel(10);
        assert!(!bindable(10), "the console line is bindable");
        assert!(!mark(10));
        assert!(!owned(10));
        assert!(!bindable(0));
        assert!(!bindable(256));
        assert!(bindable(11));
    }

    /// Marking owns exactly that line; unmarking forgets exactly it.
    ///
    /// Canary: `fetch_and(!bit)` -> `fetch_and(bit)` in `clear` — the
    /// neighbour 13 loses its ownership.
    #[test]
    fn ownership_is_per_line() {
        assert!(mark(12));
        assert!(mark(13));
        assert!(owned(12) && owned(13) && !owned(14) && !owned(44));
        assert!(unmark(12));
        assert!(!owned(12));
        assert!(owned(13), "the neighbour lost its ownership");
        assert!(!unmark(12), "a line nobody owns was released");
    }

    /// The device tree's trigger reads back per source; an undescribed one
    /// is `None`, not level.
    #[test]
    fn dtb_triggers_read_back() {
        note_dtb_trigger(20, true);
        note_dtb_trigger(21, false);
        assert_eq!(dtb_trigger(20), Some(true));
        assert_eq!(dtb_trigger(21), Some(false));
        assert_eq!(dtb_trigger(22), None);
        note_dtb_trigger(20, false);
        assert_eq!(dtb_trigger(20), Some(false), "a later note overrides");
    }

    // ── Routing by affinity (wave 10 IRQ5) ──────────────────────────────────

    /// A pinned owner gets its pin, an unpinned one the hart it binds from;
    /// either only when that hart takes external interrupts, else the boot
    /// hart. Hart ids past the 32-bit ready set fall back too.
    ///
    /// Canaries: return `boot` unconditionally (the old rule) — the first
    /// assertion reads 0; drop the ready test — a pin to a hart that never
    /// came up (5) is honoured.
    #[test]
    fn a_line_follows_the_pin_then_the_binding_hart_then_the_boot_hart() {
        use super::user_irq::route_for;
        let ready = 0b1111; // harts 0..=3 took `hart_ready`
        assert_eq!(route_for(3, 1, ready, 0), 3, "a pinned owner's line goes to its pin");
        assert_eq!(route_for(2, 2, ready, 1), 2);
        assert_eq!(route_for(-1, 1, ready, 0), 1, "an unpinned owner's line goes where it binds");
        assert_eq!(route_for(5, 1, ready, 0), 0, "a pin to a hart that takes no interrupts");
        assert_eq!(route_for(-1, 6, ready, 2), 2, "a binding hart that takes no interrupts");
        assert_eq!(route_for(3, 1, 0b0001, 0), 0, "a secondary that never came up");
        assert_eq!(route_for(40, 1, u32::MAX, 0), 0, "a hart id past the ready set");
    }

    /// The route is per line and remembered until the next bind; a delivery
    /// is reported once per bind, only after it happened, and a new bind
    /// starts the report over.
    ///
    /// Canaries: skip the `TAKEN` reset in `set_route` — the report right
    /// after the rebind names the old delivery; test-and-set `REPORTED` with
    /// a plain load — the second `first_delivery` is `Some`.
    #[test]
    fn a_route_is_per_line_and_its_first_delivery_is_reported_once() {
        use super::user_irq::{first_delivery, note_hart_ready, note_taken, ready_mask, routed_hart, set_route};
        assert_eq!(routed_hart(40), None, "a line never bound has no route");
        set_route(40, 3);
        set_route(41, 1);
        assert_eq!(routed_hart(40), Some(3));
        assert_eq!(routed_hart(41), Some(1), "the neighbour's route");
        assert_eq!(first_delivery(40), None, "reported before any delivery");
        note_taken(40, 3);
        assert_eq!(first_delivery(40), Some(3));
        assert_eq!(first_delivery(40), None, "reported twice");
        note_taken(40, 3);
        assert_eq!(first_delivery(40), None, "a later delivery of the same bind");
        set_route(40, 2);
        assert_eq!(routed_hart(40), Some(2), "a later bind moves the line");
        assert_eq!(first_delivery(40), None, "the previous bind's delivery was reported again");
        note_taken(40, 2);
        assert_eq!(first_delivery(40), Some(2));
        assert_eq!(routed_hart(400), None, "a line past the table");
        note_hart_ready(2);
        assert_eq!(ready_mask() & 0b100, 0b100);
        let before = ready_mask();
        note_hart_ready(33);
        assert_eq!(ready_mask(), before, "hart 33 changed the ready set");
    }
}

// ── Console ownership and deferred kernel lines (wave 9) ────────────────────
//
// `console_defer.rs` is the protocol `uart::console_write_ring3` runs: ring 3
// owns the UART with interrupts on, and kernel output from any hart or
// interrupt handler goes into a bounded buffer the owner drains before it
// gives the console back. The kernel's lock is the UART spinlock; here it is
// a `Mutex`, and threads stand in for harts. The wire is a `Vec` that every
// writer pushes to ONE BYTE AT A TIME with a yield between, so two writers
// that are not excluded by the protocol interleave — the only thing keeping
// lines whole below is the protocol itself.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/console_defer.rs"]
mod console_defer;

#[cfg(test)]
mod console_ownership {
    use super::console_defer::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// `.0` is the UART spinlock; `.1` the line lock every console owner
    /// holds (`CONSOLE_LINE_LOCK` in the kernel).
    struct HostLock<const N: usize>(Mutex<ConsoleDefer<N>>, Mutex<()>);

    impl<const N: usize> DeferLock<N> for HostLock<N> {
        fn with<R>(&self, f: impl FnOnce(&mut ConsoleDefer<N>) -> R) -> R {
            f(&mut self.0.lock().unwrap())
        }
    }

    impl<const N: usize> HostLock<N> {
        fn new() -> Self { HostLock(Mutex::new(ConsoleDefer::new()), Mutex::new(())) }
        /// What a `kprintln!` in task context (interrupts on) does.
        fn kernel_line(&self, wire: &Wire, line: &[u8]) {
            kernel_print(self, true, || self.1.try_lock().ok(), &mut |b: &[u8]| wire.put_slow(b), &mut |sink: &mut dyn FnMut(&[u8])| sink(line));
        }
        /// What a `kprintln!` from an interrupt handler does: it may not own.
        fn isr_line(&self, wire: &Wire, line: &[u8]) {
            kernel_print(self, false, || self.1.try_lock().ok(), &mut |b: &[u8]| wire.put_slow(b), &mut |sink: &mut dyn FnMut(&[u8])| sink(line));
        }
        /// A ring-3 `write`: the line lock, then the owner protocol.
        fn ring3_write(&self, wire: &Wire, bytes: &[u8]) -> bool {
            let _line = self.1.lock().unwrap();
            owner_write(self, bytes, &mut |b: &[u8]| wire.put_slow(b), &mut |b: &[u8]| wire.put_slow(b))
        }
    }

    #[derive(Default)]
    struct Wire(Mutex<Vec<u8>>);

    impl Wire {
        /// Byte by byte, yielding between bytes: unexcluded writers splice.
        fn put_slow(&self, b: &[u8]) {
            for &c in b {
                self.0.lock().unwrap().push(c);
                std::thread::yield_now();
            }
        }
        fn text(&self) -> String { String::from_utf8(self.0.lock().unwrap().clone()).unwrap() }
    }

    fn ring_line(n: usize) -> Vec<u8> { format!("[R] n={n:05} ring-three-line-payload-0123456789 END\n").into_bytes() }
    fn kern_line(who: usize, n: usize) -> Vec<u8> { format!("[K{who}] k={n:06} kernel-line-payload-abcdefghij KEND\n").into_bytes() }

    fn dropped_lines(text: &str) -> usize {
        text.lines()
            .filter(|l| l.starts_with("[CONSOLE] dropped "))
            .map(|l| {
                let a = l.find('(').unwrap() + 1;
                let b = l[a..].find(' ').unwrap() + a;
                l[a..b].parse::<usize>().unwrap()
            })
            .sum()
    }

    /// The case gate 192b tripped on: a kernel line from an "interrupt
    /// handler" on the owner's own hart, while the owner is mid-line. It must
    /// return without waiting (the lock is free: the owner does not hold it
    /// across wire time), must not touch the wire, and must come out whole
    /// right after the ring-3 line.
    #[test]
    fn isr_line_while_owner_is_mid_line_is_deferred_not_spliced() {
        let lock = HostLock::<256>::new();
        let wire = Wire::default();
        let ring = b"[IPCTEST] ALL PASSED\n";
        let isr = b"[SCHED-DBG]   ASKS-SCHED 3\n";
        let mut fired = false;
        owner_write(
            &lock,
            ring,
            &mut |line: &[u8]| {
                let (a, b) = line.split_at(16);
                wire.put_slow(a);
                if !fired {
                    fired = true;
                    // The interrupt: `try_lock`, because a handler that had
                    // to wait for the owner here would be the deadlock.
                    let mut st = lock.0.try_lock().expect("owner holds the lock across wire time");
                    assert!(st.is_owned());
                    let before = wire.text();
                    st.kernel_write(isr, &mut |b: &[u8]| wire.put_slow(b));
                    assert_eq!(wire.text(), before, "an owned console took a kernel byte on the wire");
                }
                wire.put_slow(b);
            },
            &mut |b: &[u8]| wire.put_slow(b),
        );
        assert!(fired);
        assert_eq!(wire.text(), "[IPCTEST] ALL PASSED\n[SCHED-DBG]   ASKS-SCHED 3\n");
        let st = lock.0.lock().unwrap();
        assert!(!st.is_owned() && !st.has_residual());
    }

    /// Unowned, a kernel line goes straight to the wire — after anything a
    /// budget-limited release left behind, so order is kept.
    #[test]
    fn residual_goes_out_before_the_next_kernel_line() {
        let lock = HostLock::<256>::new();
        let wire = Wire::default();
        {
            let mut st = lock.0.lock().unwrap();
            st.take();
            st.kernel_write(b"old line\n", &mut |_: &[u8]| panic!("owned: must defer"));
            st.release(); // as after a spent DRAIN_BUDGET
        }
        lock.kernel_line(&wire, b"new line\n");
        assert_eq!(wire.text(), "old line\nnew line\n");
        assert!(!lock.0.lock().unwrap().has_residual());
    }

    /// Overflow: whole lines only, and the count reaches the wire.
    #[test]
    fn overflow_drops_whole_lines_and_reports_them() {
        let lock = HostLock::<64>::new();
        let wire = Wire::default();
        let lines: Vec<Vec<u8>> = (0..6).map(|i| format!("line-{i}-0123456789abcdef\n").into_bytes()).collect();
        let len = lines[0].len(); // 24
        {
            let mut st = lock.0.lock().unwrap();
            st.take();
            for l in &lines {
                st.kernel_write(l, &mut |_: &[u8]| panic!("owned: must defer"));
            }
            // Two lines fit (48 of 64); the third is cut back and dropped,
            // and so is every later one — the buffer has room for none.
            assert_eq!(st.len(), 2 * len);
            assert_eq!(st.high_water(), 64);
        }
        owner_drain(&lock, &mut |b: &[u8]| wire.put_slow(b), true);
        let text = wire.text();
        let expected = format!(
            "{}{}[CONSOLE] dropped {} kernel bytes (4 lines) while ring 3 held the console\n",
            String::from_utf8_lossy(&lines[0]), String::from_utf8_lossy(&lines[1]), 4 * len,
        );
        assert_eq!(text, expected);
        assert!(!lock.0.lock().unwrap().is_owned());
    }

    /// A line that arrives while the buffer is full and ENDS after the drain
    /// empties it is still dropped whole — its tail is not printed alone.
    #[test]
    fn a_dropped_line_stays_dropped_across_the_release() {
        let lock = HostLock::<16>::new();
        let wire = Wire::default();
        {
            let mut st = lock.0.lock().unwrap();
            st.take();
            st.kernel_write(b"0123456789ABCDE\n", &mut |_: &[u8]| unreachable!()); // exactly full
            st.kernel_write(b"partial-", &mut |_: &[u8]| unreachable!());          // kprint!, no newline
        }
        owner_drain(&lock, &mut |b: &[u8]| wire.put_slow(b), true);
        lock.kernel_line(&wire, b"rest-of-line\nnext\n");
        let text = wire.text();
        assert!(!text.contains("rest-of-line"), "{text}");
        assert!(text.starts_with("0123456789ABCDE\n"), "{text}");
        assert!(text.ends_with("next\n"), "{text}");
        // "partial-" (8 bytes) is reported at the drain, its tail and the
        // line it completes (13 bytes, 1 line) at the next kernel write.
        assert_eq!(dropped_lines(&text), 1, "{text}");
        assert!(text.contains("[CONSOLE] dropped 8 kernel bytes (0 lines)"), "{text}");
        assert!(text.contains("[CONSOLE] dropped 13 kernel bytes (1 lines)"), "{text}");
    }

    /// A kernel printer faster than the wire: the owner must still return
    /// (the drain budget), and still never let its line splice into a kernel
    /// line or a kernel line into it.
    ///
    /// Deterministic storm: every byte the owner drains fires an "interrupt"
    /// on its hart that appends a whole kernel line (the owner does not hold
    /// the lock while it writes, so the handler's `try_lock` succeeds). The
    /// buffer can therefore never be seen empty — without `DRAIN_BUDGET` the
    /// owner would never return (the canary for that hangs this test).
    #[test]
    fn owner_returns_under_a_kernel_flood() {
        let lock = HostLock::<1024>::new();
        let wire = Wire::default();
        let produced = std::cell::Cell::new(0usize);
        // One wire byte from the owner, one interrupt, one whole kernel line.
        let put_and_interrupt = |b: &[u8]| {
            for &c in b {
                wire.put_slow(&[c]);
                let mut st = lock.0.try_lock().expect("owner holds the lock across wire time");
                st.kernel_write(&kern_line(0, produced.get()), &mut |_: &[u8]| panic!("owned: must defer"));
                produced.set(produced.get() + 1);
            }
        };
        let mut budget_releases = 0;
        let t0 = std::time::Instant::now();
        for i in 0..20 {
            let spent = owner_write(
                &lock,
                &ring_line(i),
                &mut |b: &[u8]| put_and_interrupt(b),
                &mut |b: &[u8]| put_and_interrupt(b),
            );
            if spent {
                budget_releases += 1;
            }
        }
        let took = t0.elapsed();
        assert!(took < std::time::Duration::from_secs(60), "owner did not return promptly: {took:?}");
        assert!(budget_releases > 0, "the storm never outran the drain budget");
        // What each budget-limited release left is flushed by the next kernel
        // write (the next owner drains it first); be the last one.
        lock.kernel_line(&wire, b"");
        check_wire(&wire.text(), 20, &[produced.get()]);
        assert!(dropped_lines(&wire.text()) > 0, "a storm this size must overflow 1 KiB");
    }

    /// Every line on the wire is exactly one known line; ring lines all
    /// there in order; each kernel producer's lines in order; missing kernel
    /// lines covered by drop reports.
    fn check_wire(text: &str, ring_lines: usize, produced: &[usize]) {
        let mut next_ring = 0;
        let mut next_k = vec![0usize; produced.len()];
        let mut seen_k = 0usize;
        for l in text.lines() {
            let with_nl = format!("{l}\n");
            if l.starts_with("[R] ") {
                assert_eq!(with_nl.as_bytes(), &ring_line(next_ring)[..], "ring line spliced or out of order");
                next_ring += 1;
            } else if l.starts_with("[K") {
                let who: usize = l[2..3].parse().expect("kernel line torn");
                let n: usize = l[7..13].parse().expect("kernel line torn");
                assert_eq!(with_nl.as_bytes(), &kern_line(who, n)[..], "kernel line spliced: {l:?}");
                assert!(n >= next_k[who], "kernel line out of order: {l:?}");
                next_k[who] = n + 1;
                seen_k += 1;
            } else if l.starts_with("[CONSOLE] dropped ") {
            } else {
                panic!("a line that is none of the writers': {l:?}");
            }
        }
        assert_eq!(next_ring, ring_lines);
        let total: usize = produced.iter().sum();
        let missing = total - seen_k;
        assert!(missing <= dropped_lines(text), "{missing} kernel lines lost, {} reported dropped", dropped_lines(text));
    }

    /// Harts: three task-context kernel printers (which may take the console
    /// over to drain a residual), one "interrupt handler" printer (which may
    /// not), one ring-3 owner. Nothing excludes them but the protocol.
    #[test]
    fn concurrent_kernel_isr_and_ring3_writers_never_splice() {
        let lock = Arc::new(HostLock::<4096>::new());
        let wire = Arc::new(Wire::default());
        let stop = Arc::new(AtomicBool::new(false));
        let mut printers = Vec::new();
        for who in 0..4 {
            let (lock, wire, stop) = (lock.clone(), wire.clone(), stop.clone());
            printers.push(std::thread::spawn(move || {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    if who == 3 {
                        lock.isr_line(&wire, &kern_line(who, n));
                    } else {
                        lock.kernel_line(&wire, &kern_line(who, n));
                    }
                    n += 1;
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
                n
            }));
        }
        for i in 0..200 {
            lock.ring3_write(&wire, &ring_line(i));
        }
        stop.store(true, Ordering::SeqCst);
        let produced: Vec<usize> = printers.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(produced.iter().all(|&n| n > 0), "a printer never ran: {produced:?}");
        // Whatever a spent budget left behind is flushed by the next kernel
        // write; there is none after the join, so flush as that write would.
        lock.kernel_line(&wire, b"");
        check_wire(&wire.text(), 200, &produced);
        let st = lock.0.lock().unwrap();
        assert!(!st.is_owned() && !st.has_residual());
    }

    // ── Wave 10: the writer that finds a residual (owner decision 2026-09-28)

    /// What a budget-limited release leaves: `lines` kernel lines deferred,
    /// console unowned.
    fn leave_residual<const N: usize>(lock: &HostLock<N>, lines: usize) -> Vec<u8> {
        let mut all = Vec::new();
        let mut st = lock.0.lock().unwrap();
        st.take();
        for n in 0..lines {
            let l = kern_line(0, n);
            st.kernel_write(&l, &mut |_: &[u8]| panic!("owned: must defer"));
            all.extend_from_slice(&l);
        }
        st.release();
        assert!(st.has_residual());
        all
    }

    /// A wire that records how many bytes were written while the defer lock
    /// was HELD — the kernel's interrupts-masked window — per lock-held run.
    struct MaskedWire<'a, const N: usize> {
        lock: &'a HostLock<N>,
        wire: Wire,
        max_masked_run: std::cell::Cell<usize>,
        run: std::cell::Cell<usize>,
    }

    impl<'a, const N: usize> MaskedWire<'a, N> {
        fn new(lock: &'a HostLock<N>) -> Self {
            MaskedWire { lock, wire: Wire::default(), max_masked_run: 0.into(), run: 0.into() }
        }
        fn put(&self, b: &[u8]) {
            // Single-threaded tests only: the lock is busy iff this thread holds it.
            if self.lock.0.try_lock().is_err() {
                self.run.set(self.run.get() + b.len());
                self.max_masked_run.set(self.max_masked_run.get().max(self.run.get()));
            } else {
                self.run.set(0);
            }
            self.wire.put_slow(b);
        }
        fn task_line(&self, line: &[u8]) {
            kernel_print(self.lock, true, || self.lock.1.try_lock().ok(), &mut |b: &[u8]| self.put(b), &mut |sink: &mut dyn FnMut(&[u8])| sink(line));
            self.run.set(0);
        }
        fn isr_line(&self, line: &[u8]) {
            kernel_print(self.lock, false, || self.lock.1.try_lock().ok(), &mut |b: &[u8]| self.put(b), &mut |sink: &mut dyn FnMut(&[u8])| sink(line));
            self.run.set(0);
        }
    }

    /// Task context, residual waiting: the writer drains it as the OWNER —
    /// no byte of it goes out with the lock held — then its own line, in
    /// order, and gives the console and the line lock back.
    #[test]
    fn a_task_writer_drains_a_residual_with_the_lock_released() {
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 60); // 60 x 51 B = 3 KiB
        let w = MaskedWire::new(&lock);
        let own = kern_line(1, 0);
        w.task_line(&own);
        let mut expected = residual.clone();
        expected.extend_from_slice(&own);
        assert_eq!(w.wire.text().as_bytes(), &expected[..]);
        assert_eq!(w.max_masked_run.get(), 0, "residual bytes went out with the lock held");
        let st = lock.0.lock().unwrap();
        assert!(!st.is_owned() && !st.has_residual());
        assert!(lock.1.try_lock().is_ok(), "the line lock leaked");
    }

    /// Interrupt context (or a task that cannot take the line lock): it may
    /// not own the console. At most one `DRAIN_CHUNK` of the residual goes
    /// out in its hold, its own line is deferred BEHIND the rest, and the
    /// next task-context writer drains everything in order.
    #[test]
    fn an_isr_writer_helps_with_one_chunk_and_defers() {
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 60);
        let w = MaskedWire::new(&lock);
        let isr = kern_line(2, 0);
        w.isr_line(&isr);
        assert_eq!(w.wire.text().as_bytes(), &residual[..DRAIN_CHUNK], "not exactly one chunk of help");
        assert!(w.max_masked_run.get() <= DRAIN_CHUNK);
        assert!(!lock.0.lock().unwrap().is_owned(), "an interrupt handler took the console");
        let own = kern_line(1, 0);
        w.task_line(&own);
        let mut expected = residual.clone();
        expected.extend_from_slice(&isr);
        expected.extend_from_slice(&own);
        assert_eq!(w.wire.text().as_bytes(), &expected[..]);
        assert!(w.max_masked_run.get() <= DRAIN_CHUNK);
    }

    /// The line lock is busy (a ring-3 writer between its budget-limited
    /// release and its unlock): a task writer does not wait for it — it
    /// helps and defers, like an interrupt handler.
    #[test]
    fn a_task_writer_that_cannot_take_the_line_lock_does_not_wait() {
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 60);
        let w = MaskedWire::new(&lock);
        let own = kern_line(1, 0);
        {
            let _ring3 = lock.1.lock().unwrap();
            w.task_line(&own);
            assert_eq!(w.wire.text().as_bytes(), &residual[..DRAIN_CHUNK]);
            assert!(!lock.0.lock().unwrap().is_owned());
        }
        w.task_line(b"");
        let mut expected = residual.clone();
        expected.extend_from_slice(&own);
        assert_eq!(w.wire.text().as_bytes(), &expected[..]);
    }

    /// While a kernel writer drains as the owner it IS the owner: an
    /// interrupt-context line is deferred and comes out after the writer's
    /// own line, and a ring-3 writer cannot take the console (it would have
    /// to take the line lock the kernel writer holds).
    #[test]
    fn a_draining_kernel_writer_owns_the_console_like_ring3() {
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 4);
        let wire = Wire::default();
        let isr = kern_line(2, 0);
        let own = kern_line(1, 0);
        let mut fired = false;
        kernel_print(&lock, true, || lock.1.try_lock().ok(), &mut |b: &[u8]| {
            if !fired {
                fired = true;
                let mut st = lock.0.try_lock().expect("lock held across wire time");
                assert!(st.is_owned(), "draining without ownership");
                assert!(lock.1.try_lock().is_err(), "a ring-3 writer could take the console now");
                st.kernel_write(&isr, &mut |_: &[u8]| panic!("owned: must defer"));
            }
            wire.put_slow(b);
        }, &mut |sink: &mut dyn FnMut(&[u8])| sink(&own));
        // The interrupt fired during the drain of the residual, so its line
        // is drained right after it: before the writer's own line, which
        // goes out only once the buffer was seen empty.
        let mut expected = residual.clone();
        expected.extend_from_slice(&isr);
        expected.extend_from_slice(&own);
        assert_eq!(wire.text().as_bytes(), &expected[..]);
        assert!(!lock.0.lock().unwrap().is_owned());
    }

    /// Kernel printers faster than the wire while a task writer drains (one
    /// 51-byte line per 32 wire bytes; the 16 KiB buffer never overflows):
    /// its ONE budget runs out, and it must return with its own line
    /// deferred behind the residual (never ahead of older kernel lines), the
    /// console and the line lock released.
    #[test]
    fn a_draining_kernel_writer_returns_under_a_flood_and_keeps_order() {
        let lock = HostLock::<16384>::new();
        leave_residual(&lock, 1);
        let wire = Wire::default();
        let produced = std::cell::Cell::new(1usize);
        let sent = std::cell::Cell::new(0usize);
        let own = b"[K1] k=000000 kernel-line-payload-abcdefghij KEND\n".to_vec();
        kernel_print(&lock, true, || lock.1.try_lock().ok(), &mut |b: &[u8]| {
            for &c in b {
                wire.put_slow(&[c]);
                sent.set(sent.get() + 1);
                if sent.get() % 32 == 0 {
                    let mut st = lock.0.try_lock().expect("lock held across wire time");
                    st.kernel_write(&kern_line(0, produced.get()), &mut |_: &[u8]| panic!("owned: must defer"));
                    produced.set(produced.get() + 1);
                }
            }
        }, &mut |sink: &mut dyn FnMut(&[u8])| sink(&own));
        assert!(!wire.text().contains("[K1]"), "own line went out ahead of older deferred lines");
        {
            let st = lock.0.lock().unwrap();
            assert!(!st.is_owned() && st.has_residual());
        }
        assert!(lock.1.try_lock().is_ok(), "the line lock leaked");
        lock.kernel_line(&wire, b"");
        let text = wire.text();
        let k1 = text.find("[K1]").expect("own line lost");
        // Every [K0] line produced before the call returned precedes it.
        assert!(!text[k1..].contains("[K0]"), "a K0 line produced earlier came out after [K1]");
        check_wire(&text, 0, &[produced.get(), 1]);
        assert_eq!(dropped_lines(&text), 0, "the buffer was sized not to overflow");
    }

    /// The kernel shell's key echo (`uart::putc_locked`, one byte, task
    /// context): on the wire at once while nobody owns the console; while
    /// ring 3 owns it, deferred and out right after the ring-3 line instead
    /// of spliced into it.
    #[test]
    fn a_shell_echo_is_immediate_unless_the_console_is_owned() {
        let lock = HostLock::<256>::new();
        let wire = Wire::default();
        lock.kernel_line(&wire, b"a");
        assert_eq!(wire.text(), "a", "an unowned echo was not immediate");
        let mut fired = false;
        owner_write(&lock, b"[R] line\n", &mut |b: &[u8]| {
            let (x, y) = b.split_at(3);
            wire.put_slow(x);
            if !fired {
                fired = true;
                lock.isr_line(&wire, b"b"); // the shell task on another hart
                lock.kernel_line(&wire, b"c");
            }
            wire.put_slow(y);
        }, &mut |b: &[u8]| wire.put_slow(b));
        assert_eq!(wire.text(), "a[R] line\nbc");
    }

    // ── Wave 10 follow-up: idle drain, and no takeover under a spinlock ────

    /// A residual with no later writer (a quiet system): the idle loop's
    /// drain, gated on the lock-free `stranded` read, puts it on the wire as
    /// the owner (lock released between chunks) and leaves nothing behind.
    #[test]
    fn the_idle_loop_drains_a_stranded_residual() {
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 60);
        let stranded = lock.0.lock().unwrap().stranded();
        assert!(stranded, "a released residual must read as stranded");
        let w = MaskedWire::new(&lock);
        idle_drain(&lock, stranded, || lock.1.try_lock().ok(), &mut |b: &[u8]| w.put(b));
        assert_eq!(w.wire.text().as_bytes(), &residual[..], "the stranded line stayed stranded");
        assert_eq!(w.max_masked_run.get(), 0, "the idle drain wrote with the lock held");
        let st = lock.0.lock().unwrap();
        assert!(!st.stranded() && !st.is_owned());
        assert!(lock.1.try_lock().is_ok(), "the line lock leaked");
    }

    /// Nothing stranded: the idle pass touches no lock at all (the kernel's
    /// hot idle path is one relaxed load).
    #[test]
    fn the_idle_drain_takes_no_lock_when_nothing_is_stranded() {
        let lock = HostLock::<256>::new();
        let _held = lock.0.lock().unwrap(); // any lock attempt would deadlock
        let _line = lock.1.lock().unwrap();
        idle_drain(&lock, false, || -> Option<()> { panic!("tried the line lock") }, &mut |_: &[u8]| panic!("wrote"));
    }

    /// Owned is not stranded: while a writer owns the console it is the one
    /// draining, so the idle loop must not read that residual as stranded.
    #[test]
    fn an_owned_residual_is_not_stranded() {
        let lock = HostLock::<256>::new();
        let mut st = lock.0.lock().unwrap();
        st.take();
        st.kernel_write(b"deferred\n", &mut |_: &[u8]| panic!("owned: must defer"));
        assert!(st.has_residual() && !st.stranded());
    }

    /// A task-context writer that holds a spinlock (preemption depth > 0)
    /// must not take the console over: that would hold the spinlock across a
    /// preemptible drain. It helps with one chunk and defers, like an
    /// interrupt handler.
    #[test]
    fn a_writer_under_a_spinlock_does_not_take_over() {
        assert!(may_own(true, 0));
        assert!(!may_own(false, 0), "interrupt context may not own");
        assert!(!may_own(true, 1), "a spinlock holder may not own");
        let lock = HostLock::<8192>::new();
        let residual = leave_residual(&lock, 60);
        let w = MaskedWire::new(&lock);
        let own = kern_line(1, 0);
        let depth = 1; // inside a SpinLock critical section
        kernel_print(&lock, may_own(true, depth), || lock.1.try_lock().ok(), &mut |b: &[u8]| w.put(b), &mut |sink: &mut dyn FnMut(&[u8])| sink(&own));
        assert_eq!(w.wire.text().as_bytes(), &residual[..DRAIN_CHUNK], "a spinlock holder drained past one chunk");
        assert!(!lock.0.lock().unwrap().is_owned(), "a spinlock holder took the console");
    }

    // ── Wave 11: the wire is a TX ring that can be full ────────────────────
    //
    // Under the UART lock a kernel writer may not wait for the UART, so the
    // kernel's wire takes only what its TX ring has room for (`Wire::put`)
    // and the rest is deferred here, as if the console were owned.

    /// A TX ring with `free` bytes of room: `put` takes a prefix.
    struct RingWire {
        out: Vec<u8>,
        free: usize,
    }

    impl super::console_defer::Wire for RingWire {
        fn put(&mut self, b: &[u8]) -> usize {
            let n = b.len().min(self.free);
            self.out.extend_from_slice(&b[..n]);
            self.free -= n;
            n
        }
        fn put_all(&mut self, b: &[u8]) {
            self.out.extend_from_slice(b);
        }
        fn fits(&self, b: &[u8]) -> bool {
            b.len() <= self.free
        }
        fn room(&self) -> usize {
            self.free
        }
    }

    fn drain_all<const N: usize>(st: &mut ConsoleDefer<N>, w: &mut RingWire) {
        for _ in 0..10_000 {
            if !st.has_residual() {
                return;
            }
            // Room for the longest drop report (`DROP_MARKER_MAX`).
            w.free = 128;
            st.help(w);
        }
        panic!("residual never drained");
    }

    /// Less room than `LINE_RESERVE`: the whole line waits (nothing of it
    /// reaches the ring), and a later line goes behind it.
    #[test]
    fn a_line_with_no_room_to_start_is_deferred_whole() {
        let mut st = ConsoleDefer::<4096>::new();
        let mut w = RingWire { out: Vec::new(), free: LINE_RESERVE - 1 };
        let a = kern_line(1, 1);
        let b = kern_line(2, 2);
        st.kernel_line(&mut w, &mut |sink: &mut dyn FnMut(&[u8])| { sink(&a[..10]); sink(&a[10..]) });
        assert!(w.out.is_empty(), "a line started on a ring without LINE_RESERVE room");
        assert_eq!(st.len(), a.len());
        assert!(st.stranded(), "a deferred line nobody owns must read as stranded");
        w.free = 4096;
        st.kernel_line(&mut w, &mut |sink: &mut dyn FnMut(&[u8])| sink(&b));
        // `help` put one chunk of the residual out first; `b` went behind it.
        drain_all(&mut st, &mut w);
        assert_eq!(w.out, [a.clone(), b.clone()].concat());
    }

    /// A line longer than the room left: its head goes to the ring, its tail
    /// is deferred, and the next writer's line lands after the tail — never
    /// inside the first line.
    #[test]
    fn a_line_that_overruns_the_ring_continues_from_the_buffer_in_order() {
        let mut st = ConsoleDefer::<4096>::new();
        let long: Vec<u8> = [b"[LONG] ".as_slice(), &[b'x'; 400], b" END\n".as_slice()].concat();
        let next = kern_line(3, 3);
        let mut w = RingWire { out: Vec::new(), free: LINE_RESERVE + 10 };
        st.kernel_line(&mut w, &mut |sink: &mut dyn FnMut(&[u8])| { sink(&long[..7]); sink(&long[7..]) });
        assert_eq!(w.out.len(), LINE_RESERVE + 10, "the head did not fill the ring");
        assert_eq!(st.len(), long.len() - (LINE_RESERVE + 10));
        st.kernel_line(&mut w, &mut |sink: &mut dyn FnMut(&[u8])| sink(&next));
        drain_all(&mut st, &mut w);
        assert_eq!(w.out, [long.clone(), next.clone()].concat());
    }

    /// A drop report goes out whole or waits: with no room for it, it stays
    /// owed and the next line is deferred; once there is room both come out,
    /// the report whole.
    #[test]
    fn a_drop_report_without_room_waits_whole() {
        let mut st = ConsoleDefer::<16>::new();
        st.take();
        st.kernel_write(b"0123456789ABCDE\n", &mut |_: &[u8]| {}); // exactly full
        st.kernel_write(b"dropped-line\n", &mut |_: &[u8]| {});    // dropped
        let mut w = RingWire { out: Vec::new(), free: 4096 };
        let mut out = [0u8; 16];
        assert_eq!(st.owner_step(&mut out), Step::Bytes(16));
        st.release();
        assert!(st.has_residual(), "the drop report must still be owed");
        // No room for the report: it may not go out in part.
        w.free = 10;
        st.kernel_write(b"after\n", &mut w);
        assert!(w.out.is_empty(), "part of a drop report reached the wire");
        st.help(&mut w); // "after\n" (6 of the 10)
        st.help(&mut w); // the report: 4 bytes of room, so nothing
        assert_eq!(w.out, b"after\n", "part of a drop report reached the wire");
        drain_all(&mut st, &mut w);
        let text = String::from_utf8(w.out.clone()).unwrap();
        // Deferred bytes first, the report once the buffer is empty (the
        // protocol's order since wave 9) — and the report in one piece.
        assert_eq!(text, "after\n[CONSOLE] dropped 13 kernel bytes (1 lines) while ring 3 held the console\n");
    }
}

// ── ratelimit.rs: console report rate limit (wave 14, LOGLEVEL) ─────────────
#[allow(dead_code)] // only the test module calls it
#[path = "../../../../crates/drivers/sys/src/ratelimit.rs"]
mod ratelimit;

#[cfg(test)]
mod ratelimit_tests {
    use super::ratelimit::RateLimit;

    const HZ: u64 = 10_000_000; // QEMU riscv64's 10 MHz

    #[test]
    fn a_burst_then_silence_then_the_count() {
        let rl = RateLimit::new(3, 5);
        let t0 = 7 * HZ;
        for _ in 0..3 {
            assert_eq!(rl.check_at(t0, HZ), Some(0));
        }
        // Past the burst, inside the window: suppressed, counted.
        for i in 1..=4u64 {
            assert_eq!(rl.check_at(t0 + i, HZ), None);
        }
        // Still inside the 5 s window one tick before its end.
        assert_eq!(rl.check_at(t0 + 5 * HZ - 1, HZ), None);
        // A new window: prints, and reports the five it dropped.
        assert_eq!(rl.check_at(t0 + 5 * HZ, HZ), Some(5));
        // The count was handed over once.
        assert_eq!(rl.check_at(t0 + 5 * HZ + 1, HZ), Some(0));
    }

    #[test]
    fn the_first_report_at_tick_zero_opens_a_window() {
        let rl = RateLimit::new(1, 5);
        assert_eq!(rl.check_at(0, HZ), Some(0));
        assert_eq!(rl.check_at(1, HZ), None);
        // Stamped 1, not 0 ("no window yet"): the window ends a tick later.
        assert_eq!(rl.check_at(5 * HZ, HZ), None);
        assert_eq!(rl.check_at(5 * HZ + 1, HZ), Some(2));
    }

    #[test]
    fn a_zero_burst_prints_nothing_and_counts_everything() {
        let rl = RateLimit::new(0, 5);
        assert_eq!(rl.check_at(HZ, HZ), None);
        assert_eq!(rl.check_at(10 * HZ, HZ), None);
    }
}

// ── timer_arm.rs: the next timer event (wave 11 ONESHOT, RFC-0052 RT2) ──────
//
// `timebase` programs the comparator; `timer_arm.rs` decides the instant. The
// two cases the wave fixed: a busy hart whose comparator holds the next tick
// must move it when a task blocks on an earlier deadline, and the tick handler
// must program the nearest sleeper when it is earlier than the next tick (the
// aarch64 handler programmed `now + period` unconditionally).
#[allow(dead_code)] // only the test module calls it
#[path = "../../../../crates/drivers/sys/src/timer_arm.rs"]
mod timer_arm;

#[cfg(test)]
mod timer_arm_tests {
    use super::timer_arm::*;

    const PERIOD: u64 = 100_000; // 10 ms at QEMU's 10 MHz
    const KEEPALIVE: u64 = 1_000_000; // 100 ms
    const CEILING: u64 = 600_000_000; // 60 s

    fn ev(now: u64, nearest: Option<u64>, cap: Cap) -> u64 {
        next_event(now, nearest, cap, PERIOD, KEEPALIVE, CEILING)
    }

    #[test]
    fn busy_hart_programs_the_earlier_of_sleeper_and_tick() {
        assert_eq!(ev(1_000, None, Cap::Busy), 1_000 + PERIOD);
        // A sleeper 1 ms out on a 10 ms tick: the sleeper, not the tick.
        assert_eq!(ev(1_000, Some(11_000), Cap::Busy), 11_000);
        // A sleeper past the tick: the tick (preemption still fires).
        assert_eq!(ev(1_000, Some(1_000 + PERIOD + 1), Cap::Busy), 1_000 + PERIOD);
        // Equal: either is the same instant.
        assert_eq!(ev(1_000, Some(1_000 + PERIOD), Cap::Busy), 1_000 + PERIOD);
    }

    #[test]
    fn idle_hart0_keeps_the_keepalive_cap() {
        assert_eq!(ev(5, None, Cap::IdleKeepalive), 5 + KEEPALIVE);
        assert_eq!(ev(5, Some(5 + KEEPALIVE + 1), Cap::IdleKeepalive), 5 + KEEPALIVE);
        assert_eq!(ev(5, Some(50), Cap::IdleKeepalive), 50);
    }

    #[test]
    fn idle_other_hart_has_no_periodic_cap() {
        // Nearest sleeper wins even far past the busy period and the keepalive.
        assert_eq!(ev(5, Some(5 + 10 * KEEPALIVE), Cap::IdleCeiling), 5 + 10 * KEEPALIVE);
        // ... even past the ceiling: the ceiling is only for "nothing sleeps".
        assert_eq!(ev(5, Some(5 + 2 * CEILING), Cap::IdleCeiling), 5 + 2 * CEILING);
        assert_eq!(ev(5, None, Cap::IdleCeiling), 5 + CEILING);
    }

    #[test]
    fn caps_saturate_instead_of_overflowing() {
        // The suite builds with overflow-checks on, like the kernel: a plain
        // `now + period` here would panic the test.
        assert_eq!(ev(u64::MAX - 1, None, Cap::Busy), u64::MAX);
        assert_eq!(ev(u64::MAX - 1, None, Cap::IdleKeepalive), u64::MAX);
        assert_eq!(ev(u64::MAX - 1, None, Cap::IdleCeiling), u64::MAX);
        assert_eq!(ev(u64::MAX - 1, Some(7), Cap::Busy), 7);
    }

    #[test]
    fn a_block_moves_the_comparator_only_when_strictly_earlier() {
        let programmed = 1_000 + PERIOD;
        assert!(earlier_than_programmed(programmed, 11_000));
        assert!(!earlier_than_programmed(programmed, programmed));
        assert!(!earlier_than_programmed(programmed, programmed + 1));
        // A deadline already past is earlier: programming it fires at once.
        assert!(earlier_than_programmed(programmed, 1));
    }

    #[test]
    fn a_hart_that_never_armed_is_left_alone() {
        assert!(!earlier_than_programmed(NOT_ARMED, 1));
        assert!(!earlier_than_programmed(NOT_ARMED, u64::MAX));
    }

    /// The sequence the LAT row measures, on a hart that never goes idle:
    /// tick armed, a 1 ms sleeper blocks, its deadline fires, the handler
    /// re-arms. Each comparator value is the one the code computes.
    #[test]
    fn busy_hart_sequence_wakes_on_the_deadline_not_the_tick() {
        let mut programmed = ev(0, None, Cap::Busy); // boot: first tick
        assert_eq!(programmed, PERIOD);
        let d = 10_000; // block at t=0 on a 1 ms deadline
        if earlier_than_programmed(programmed, d) {
            programmed = d;
        }
        assert_eq!(programmed, d, "the block left the comparator on the tick");
        // The interrupt at d wakes the sleeper; nothing else sleeps.
        programmed = ev(d, None, Cap::Busy);
        assert_eq!(programmed, d + PERIOD);
        // The woken task blocks again 1 ms later.
        let d2 = 2 * d;
        assert!(earlier_than_programmed(programmed, d2));
    }

    /// Wave 13: hart 0's idle keepalive exists only with a watchdog armed, at
    /// timeout / KEEPALIVES_PER_TIMEOUT, and always leaves that many feeds
    /// inside one timeout.
    #[test]
    fn keepalive_follows_the_armed_watchdog() {
        assert_eq!(keepalive_us(0), None);
        assert_eq!(KEEPALIVES_PER_TIMEOUT, 4);
        assert_eq!(keepalive_us(500), Some(125_000));
        assert_eq!(keepalive_us(1), Some(250));
        assert_eq!(keepalive_us(u32::MAX), Some(u32::MAX as u64 * 1000 / 4));
        for t in [1u32, 3, 100, 500, 999, 10_000, 600_000] {
            let k = keepalive_us(t).unwrap();
            assert!(k * KEEPALIVES_PER_TIMEOUT <= t as u64 * 1000);
            assert!(k > 0);
        }
    }
}

// RFC-0055 (wave 11): the one owner of console input. Real code, pulled in.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/console_rx.rs"]
mod console_rx;

#[cfg(test)]
mod console_rx_owner {
    use super::console_rx::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn the_first_claim_wins_and_the_second_is_refused() {
        let o = RxOwner::new();
        assert_eq!(o.claim(42), Claim::Got);
        assert_eq!(o.claim(42), Claim::Already);
        assert_eq!(o.claim(RX_OWNER_KERNEL), Claim::Busy(42), "the recovery console must not read");
        assert_eq!(o.claim(43), Claim::Busy(42));
        assert_eq!(o.owner(), 42);
    }

    #[test]
    fn only_the_owner_releases_and_then_anyone_may_claim() {
        let o = RxOwner::new();
        o.claim(42);
        assert!(!o.release(43), "a task that does not own input cannot release it");
        assert_eq!(o.owner(), 42);
        assert!(o.release(42), "the owner's exit releases it");
        assert_eq!(o.owner(), RX_OWNER_NONE);
        assert_eq!(o.claim(RX_OWNER_KERNEL), Claim::Got);
        assert!(!o.release(RX_OWNER_NONE));
    }

    /// **Two readers never both own input**, raced on threads.
    ///
    /// **Canary.** Make `claim` a plain store: more than one thread reports
    /// `Got`.
    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        for _ in 0..200 {
            let o = Arc::new(RxOwner::new());
            let won = Arc::new(AtomicUsize::new(0));
            let hs: Vec<_> = (1..=8u32)
                .map(|t| {
                    let (o, won) = (o.clone(), won.clone());
                    std::thread::spawn(move || {
                        if o.claim(t) == Claim::Got {
                            won.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();
            for h in hs {
                h.join().unwrap();
            }
            assert_eq!(won.load(Ordering::SeqCst), 1);
        }
    }

    /// Wave 13: only the owner lends, one lend at a time, the lendee's exit
    /// ends it, and an owner that goes takes its lend with it.
    #[test]
    fn only_the_owner_lends_and_the_lend_ends_with_either() {
        let o = RxOwner::new();
        assert!(!o.lend(7, 9), "nobody owns input yet");
        assert_eq!(o.claim(7), Claim::Got);
        assert!(!o.lend(8, 9), "not the owner");
        assert!(!o.lend(7, 0), "TID 0 is no task");
        assert!(o.lend(7, 9));
        assert_eq!(o.lendee(), 9);
        assert!(!o.lend(7, 10), "one lend at a time");
        assert!(!o.end_lend(10));
        assert!(o.end_lend(9));
        assert_eq!(o.lendee(), 0);
        assert!(o.lend(7, 11));
        assert!(o.release(7));
        assert_eq!(o.lendee(), 0, "the owner's exit ends its lend");
    }
}

/// Wave 12 (DRVPLACE): the buzzer chip logic both hosts run
/// (`crates/drivers/buzzer`), against a recording PWM channel.
#[cfg(test)]
mod buzzer_chip {
    use azos_abi::drv_kind::buzzer_op;
    use azos_buzzer::{serve, Player, Pwm, DUTY_PCT, MAX_FREQ_HZ, TONE_ALERT};

    #[derive(Default)]
    struct Rec {
        period_ns: u32,
        duty_pct: u32,
        enabled: bool,
        refuse: bool,
    }

    impl Pwm for Rec {
        fn set_period_ns(&mut self, p: u32) -> bool { self.period_ns = p; !self.refuse }
        fn set_duty_pct(&mut self, d: u32) -> bool { self.duty_pct = d; !self.refuse }
        fn enable(&mut self) -> bool { self.enabled = true; !self.refuse }
        fn disable(&mut self) -> bool { self.enabled = false; !self.refuse }
    }

    fn tone(freq: u16, ms: u32) -> [u8; 6] {
        let f = freq.to_le_bytes();
        let d = ms.to_le_bytes();
        [f[0], f[1], d[0], d[1], d[2], d[3]]
    }

    /// What the gate's DRV1 smoke reads on the channel, in either placement:
    /// `ON 440` sets a 2272727 ns period at 50 % and enables; `OFF`
    /// disables; a 50 ms `TONE` ends on its own once 50 ms have elapsed.
    ///
    /// **Canary.** Make `start_step` skip `set_duty_pct`: the duty assertion
    /// is red.
    #[test]
    fn on_off_and_a_timed_tone_drive_the_channel() {
        let (mut p, mut pwm) = (Player::new(), Rec::default());
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::ON, &440u16.to_le_bytes()), Some(true));
        assert_eq!((pwm.period_ns, pwm.duty_pct, pwm.enabled), (2_272_727, DUTY_PCT, true));
        assert_eq!(p.park_ms(), 0, "a continuous tone is not timed");
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::OFF, &[]), Some(true));
        assert!(!pwm.enabled && p.silent());

        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::TONE, &tone(1000, 50)), Some(true));
        assert_eq!((pwm.period_ns, pwm.enabled), (1_000_000, true));
        assert_eq!(p.park_ms(), 50);
        p.elapse(&mut pwm, 49);
        assert!(pwm.enabled, "ended early");
        p.elapse(&mut pwm, 1);
        assert!(!pwm.enabled && p.silent(), "a 50 ms tone still sounding after 50 ms");
    }

    /// A pattern advances step by step, a late wake skips the steps it
    /// covers, and the clamps hold: frequency at `MAX_FREQ_HZ`, a zero
    /// frequency or duration stops.
    #[test]
    fn patterns_late_wakes_and_clamps() {
        let (mut p, mut pwm) = (Player::new(), Rec::default());
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::ALERT, &[]), Some(true));
        assert!(pwm.enabled);
        p.elapse(&mut pwm, 80);
        assert!(!pwm.enabled, "the gap after the first beep");
        p.elapse(&mut pwm, 60 + 80 + 60);
        assert!(pwm.enabled, "a late wake lands in the third beep");
        assert_eq!(pwm.period_ns, 1_000_000_000 / TONE_ALERT as u32);
        p.elapse(&mut pwm, 1_000);
        assert!(p.silent() && !pwm.enabled);

        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::TONE, &tone(u16::MAX, 10)), Some(true));
        assert_eq!(pwm.period_ns, 1_000_000_000 / MAX_FREQ_HZ as u32);
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::TONE, &tone(1000, 0)), Some(true));
        assert!(!pwm.enabled && p.silent());
        // Short input reads as zeros: a TONE with no duration stops.
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::TONE, &[0xE8, 0x03]), Some(true));
        assert!(p.silent());
    }

    /// An op the driver does not know changes nothing (`None`: the ring-3
    /// host answers `STATUS_BAD_OP`), and a refused register write is
    /// reported (`Some(false)`: the reply byte 0).
    #[test]
    fn unknown_ops_and_refused_writes() {
        let (mut p, mut pwm) = (Player::new(), Rec::default());
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::ON, &880u16.to_le_bytes()), Some(true));
        assert_eq!(serve(&mut p, &mut pwm, 0xDEAD, &[]), None);
        assert!(pwm.enabled && pwm.period_ns == 1_000_000_000 / 880, "an unknown op changed the sound");
        pwm.refuse = true;
        assert_eq!(serve(&mut p, &mut pwm, buzzer_op::BEEP, &[]), Some(false));
    }

    /// Both hosts carry the source marker the build script generated, and
    /// it names this crate and the hash it states.
    #[test]
    fn the_source_marker_names_the_crate_and_its_hash() {
        let m = core::str::from_utf8(&azos_buzzer::SOURCE_MARKER).unwrap();
        assert_eq!(m, format!("AZOS-CHIP-SRC buzzer {:016x}", azos_buzzer::SOURCE_HASH));
    }
}
