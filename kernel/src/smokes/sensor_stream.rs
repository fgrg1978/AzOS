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

use azos_drv_base::sensors::{stream, value, Channel, Quantity, Sensor, Source, Stream, Unit};
use azos_drv_sys::timebase::{now, vdso_ns, TIMER_FREQ};

/// A sensor of an IMU's shape (six axes at its rate) that only this test feeds.
static SHAPE: [Channel; 6] =
    [Channel::new(Quantity::Acceleration, Unit::MilliG, 4, true, -2000, 2000, azos_limits::SENSOR_IMU_HZ as u32); 6];

static VIRTUAL_LOG: Stream = stream();
static VIRTUAL_IMU: Sensor = Sensor::new(&SHAPE, Source::Stream(&VIRTUAL_LOG));

/// Acquisitions to publish: two seconds at the configured rate, and at least
/// twenty (so the producer's every-10th drop shows at the lowest rate), well
/// past the stream's depth at the default rate, so the reader keeping up is
/// what keeps the log whole.
const TICKS: u64 = if azos_limits::SENSOR_IMU_HZ as u64 * 2 > 20 { azos_limits::SENSOR_IMU_HZ as u64 * 2 } else { 20 };

azos_ktest::ktest_late! {
    fn sensors_virtual_imu_stream_loses_no_sample() {
        let period = TIMER_FREQ / azos_limits::SENSOR_IMU_HZ as u64;
        let Some(mut tx) = VIRTUAL_IMU.producer() else { return Err("the virtual IMU's producer was taken") };
        let Some(mut rx) = VIRTUAL_IMU.cursor() else { return Err("the virtual IMU has no stream") };
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
