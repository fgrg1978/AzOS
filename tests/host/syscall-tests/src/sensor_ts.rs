// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `SYS_SENSOR_READ_TS` (606): the stamped sensor read.
//
// **What is real here.** `sys_sensor_read_ts`, `sys_sensor_read_typed`, the
// shared `sensor_read_into` arm table and `sensor_write_to_user`, against a
// real capability table and a real Sv39 page table (`copy_to_user` walks it).
//
// **What is not.** The sensor is the encoder pair `shims/robot` reports, with
// an acquisition stamp the test sets (`shim_set_encoder_acq`): the encoder
// arm takes its stamp from `encoder_read_stamped`, so the bytes asserted here
// are the arm's own, converted with the frequency the shim's timebase
// carries.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_abi::sensor_sample::{
    SensorSampleHdr, SENSOR_SAMPLE_HDR_LEN, SENSOR_SAMPLE_VERSION,
};
use azos_arch_api::PagePerms;
use azos_ipc::cap::targets::{Gpio, Sensor};
use std::sync::atomic::{AtomicU32, Ordering};

const SLOT: usize = 61;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7c20_0001);
/// A page mapped user-RW.
const SCRATCH: usize = 0x0075_0000;
const HDR: usize = SENSOR_SAMPLE_HDR_LEN;

struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap_store::reset(self.tid);
    }
}

fn ring3() -> Scene {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let scratch = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, scratch, PagePerms::USER_RW).expect("map");
    Scene { tid }
}

fn encoder_cap(tid: u32) -> u64 {
    azos_ipc::cap_store::grant::<Sensor>(tid, CapPerms::READ, SENSOR_TYPE_ENCODER as u32)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

fn user_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    assert!(azos_sched::copy_from_user(v.as_mut_ptr(), SCRATCH, n));
    v
}

fn fill_user(byte: u8, n: usize) {
    let v = vec![byte; n];
    assert!(azos_sched::copy_to_user(SCRATCH, v.as_ptr(), n));
}

/// **The header carries the arm's acquisition stamp, converted to vDSO-clock
/// nanoseconds, and the payload is 561's bytes for the same read.**
///
/// 2_500_000 ticks at the shim's `TIMER_FREQ` is the ns value
/// `azos_abi::time::ticks_to_ns` gives — the conversion libsys's
/// `vdso_now_ns` applies to its own counter, which is what makes the stamp
/// comparable with a ring-3 clock read.
///
/// **Canary.** Make the encoder arm pass `SampleMeta::at_ticks(0, 0)`: the
/// header reads `acq_ns == 0`.
#[test]
fn the_header_carries_the_acquisition_stamp_and_the_payload_is_the_typed_reads() {
    let _g = serial();
    let s = ring3();
    let cap = encoder_cap(s.tid);
    azos_robot::shim_set_encoder(1234, -5678);
    azos_robot::shim_set_encoder_acq(2_500_000);

    let n = sys_sensor_read_ts(cap, SCRATCH as u64, (HDR + 16) as u64);
    assert_eq!(n, (HDR + 16) as i64);
    let got = user_bytes(HDR + 16);
    let hdr = SensorSampleHdr::from_bytes(&got).expect("header parses");
    assert_eq!(hdr.version, SENSOR_SAMPLE_VERSION);
    assert_eq!(hdr.hdr_len as usize, HDR);
    assert_eq!(hdr.payload_len, 16);
    assert_eq!(hdr.flags, 0, "a counter read is a measurement, not synthetic");
    let want_ns = azos_abi::time::ticks_to_ns(2_500_000, azos_drv_sys::timebase::TIMER_FREQ);
    assert_ne!(want_ns, 0);
    assert_eq!(hdr.acq_ns, want_ns);

    let typed = sys_sensor_read_typed(cap, SCRATCH as u64, 16);
    assert_eq!(typed, 16);
    assert_eq!(&got[HDR..], &user_bytes(16)[..], "606's payload is 561's bytes");
}

/// **A buffer that cannot hold header + payload is refused with nothing
/// written**, header included — refused, never truncated, as 561 refuses.
///
/// **Canary.** Write the header before the payload copy is attempted: the
/// short call leaves a header in the buffer.
#[test]
fn a_short_buffer_is_refused_and_nothing_is_written() {
    let _g = serial();
    let s = ring3();
    let cap = encoder_cap(s.tid);
    azos_robot::shim_set_encoder_acq(7);
    for len in [0usize, HDR - 1, HDR, HDR + 15] {
        fill_user(0xEE, HDR + 16);
        assert_eq!(sys_sensor_read_ts(cap, SCRATCH as u64, len as u64), -1, "out_len {len}");
        assert!(user_bytes(HDR + 16).iter().all(|&b| b == 0xEE), "out_len {len} wrote bytes");
    }
}

/// **The capability is checked as 561 checks it**: a forged handle is
/// `-ECAPSTALE`, a `Cap<Gpio>` is `-ECAPKIND`, and neither reads the device.
#[test]
fn the_stamped_read_refuses_what_the_typed_read_refuses() {
    use azos_abi::error::Errno;
    let _g = serial();
    let s = ring3();
    let gpio = azos_ipc::cap_store::grant::<Gpio>(s.tid, CapPerms::READ, 3)
        .expect("cap table full")
        .raw()
        .as_raw() as u64;
    let reads = azos_robot::shim_encoder_reads();
    assert_eq!(sys_sensor_read_ts(0, SCRATCH as u64, 64), Errno::ECAPSTALE.to_syscall_ret());
    assert_eq!(sys_sensor_read_ts(gpio, SCRATCH as u64, 64), Errno::ECAPKIND.to_syscall_ret());
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a refused call read the encoders");
}

/// **An unknown acquisition time stays 0**, the "never fresh" value, rather
/// than being converted into a small nonzero number.
#[test]
fn an_unknown_stamp_is_reported_as_zero() {
    let _g = serial();
    let s = ring3();
    let cap = encoder_cap(s.tid);
    azos_robot::shim_set_encoder_acq(0);
    assert_eq!(sys_sensor_read_ts(cap, SCRATCH as u64, 64), (HDR + 16) as i64);
    let hdr = SensorSampleHdr::from_bytes(&user_bytes(HDR)).expect("header parses");
    assert_eq!(hdr.acq_ns, 0);
    assert!(!azos_abi::sensor_sample::sample_is_fresh_ns(hdr.acq_ns, u64::MAX / 2, u64::MAX));
}
