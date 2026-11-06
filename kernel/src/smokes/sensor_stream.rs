// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest of the sensor class's streams: a virtual IMU published at the IMU's
//! rate (Kconfig `SENSOR_IMU_HZ`) on the kernel's clock reaches a reader of
//! its own, every sample, in order, with the reader's overrun count at zero.
//!
//! The log cannot see a sample its producer never published, so the verdict
//! compares what the reader got with the acquisitions the producer was asked
//! to publish and checks the numbers carried in the records for a gap.
//!
//! **Canary**: the kernel feature `sensor-drop-canary` (the producer drops
//! every 10th sample): delivered falls short of the ticks, `not ok`.

use azos_drv_base::sensors::{board, value, Sensor, Source};
use azos_drv_sys::timebase::{now, vdso_ns, TIMER_FREQ};

/// A sensor of the IMU's shape that only this test feeds.
static VIRTUAL_IMU: Sensor = Sensor::new(board::IMU_SENSOR.channels(), Source::Stream);

/// Acquisitions to publish: two seconds at the default rate, and well past
/// the stream's depth, so the reader keeping up is what keeps the log whole.
const TICKS: u64 = 200;

azos_ktest::ktest_late! {
    fn sensors_virtual_imu_stream_loses_no_sample() {
        let period = TIMER_FREQ / azos_limits::SENSOR_IMU_HZ as u64;
        let Some(mut tx) = VIRTUAL_IMU.producer() else { return Err("the virtual IMU's producer was taken") };
        let mut rx = VIRTUAL_IMU.cursor();
        let (mut next, mut last, mut gaps) = (now(), 0i64, 0u32);
        for n in 1..=TICKS {
            next += period;
            while now() < next {
                azos_sched::task_block(azos_sched::WaitReason::Timer(next));
            }
            tx.publish(VIRTUAL_IMU.pack(&[n as i64; 6], 0, vdso_ns(now())));
            while let Some(s) = rx.next() {
                let Some(v) = value(VIRTUAL_IMU.channels(), &s, 0) else { return Err("a sample lacks its first axis") };
                gaps += (v != last + 1) as u32;
                last = v;
            }
        }
        crate::kprintln!("[KTEST] sensors: virtual IMU stream, {} acquisitions at {} Hz, delivered {}, overrun {}, gaps {}",
                         tx.acquired(), azos_limits::SENSOR_IMU_HZ, rx.delivered(), rx.overrun(), gaps);
        if rx.overrun() != 0 {
            Err("the reader was told it lost samples")
        } else if rx.delivered() != tx.acquired() || tx.acquired() != TICKS {
            Err("a sample the producer was asked to publish never reached the reader")
        } else if gaps != 0 {
            Err("the samples the reader got skip a number")
        } else {
            Ok(())
        }
    }
}
