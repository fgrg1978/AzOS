// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sensor and telemetry tasks: IMU, odometry, slow sensors, AHRS, telemetry.

use crate::*;

/// IMU sensor task — reads the IMU at Kconfig `SENSOR_IMU_HZ` and publishes
/// into the IMU's streams (the sample, and the die temperature).
/// RT priority: IMU data must be fresh for safety layer L0.
///
/// Kconfig `IMU_SAMPLE_QUEUED` (default, wave 15 S1): an RT task only
/// enqueues. Each tick collects the burst read queued earlier (if it has
/// finished) and queues the next one; the bus's service step puts it on the
/// wire. A read that fails or is not finished yet publishes nothing, so the
/// stream's newest sample ages and L0's staleness check sees it.
/// `IMU_SAMPLE_POLLED`: the synchronous read in this task, as before.
pub(crate) fn imu_task(_: usize) {
    kprintln!("[IMU-TASK] Started ({} Hz, RT priority, {})", azos_limits::SENSOR_IMU_HZ,
              if azos_limits::IMU_SAMPLE_QUEUED { "queued reads" } else { "polled reads" });
    let imu_interval: u64 = azos_drv_sys::timebase::freq() / azos_limits::SENSOR_IMU_HZ as u64;
    let mut pending: Option<u32> = None;
    let mut tx = ImuStreams::take();
    loop {
        if azos_limits::IMU_SAMPLE_QUEUED {
            imu_queued_tick(&mut pending, &mut tx);
        } else if let Some((d, acq)) = azos_imu::imu_read_scaled_stamped() {
            // Stamped by the driver at the read: the stream's sample ages
            // from its acquisition, not from this publication.
            tx.publish(&d, acq);
        }
        let dl = azos_drv_sys::timebase::now() + imu_interval;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}

/// The `imu` task's two producers: the sample and the die temperature.
struct ImuStreams {
    imu: azos_drv_base::sensors::Producer<'static>,
    temp: azos_drv_base::sensors::Producer<'static>,
}

impl ImuStreams {
    fn take() -> Self {
        use azos_drv_base::sensors::board;
        Self {
            imu: board::IMU_SENSOR.producer().expect("IMU stream: second producer"),
            temp: board::IMU_TEMP_SENSOR.producer().expect("IMU temperature stream: second producer"),
        }
    }

    fn publish(&mut self, d: &azos_imu::ImuData, acq: u64) {
        use azos_drv_base::sensors::board;
        let ns = azos_drv_sys::timebase::vdso_ns(acq);
        let [ax, ay, az] = d.accel_mg.map(i64::from);
        let [gx, gy, gz] = d.gyro_mdps.map(i64::from);
        self.imu.publish(board::IMU_SENSOR.pack(&[ax, ay, az, gx, gy, gz], 0, ns));
        self.temp.publish(board::IMU_TEMP_SENSOR.pack(&[d.temp_cdeg as i64], 0, ns));
    }
}

/// One tick of the queued IMU path: collect the read in flight if it has
/// finished, then queue the next one (and collect it at once if the bus
/// finished it at submit: the QEMU simulation). Never waits.
fn imu_queued_tick(pending: &mut Option<u32>, tx: &mut ImuStreams) {
    let mut collect = |t: u32, pending: &mut Option<u32>| {
        if let Some(r) = azos_imu::imu_take(t) {
            *pending = None;
            if let Some((d, acq)) = r {
                tx.publish(&d, acq);
            }
        }
    };
    if let Some(t) = *pending {
        collect(t, pending);
    }
    if pending.is_none() {
        *pending = azos_imu::imu_submit(azos_drv_sys::timebase::now());
        if let Some(t) = *pending {
            collect(t, pending);
        }
    }
}

/// The I2C controllers' service step (`i2c::i2c_service`: DesignWare, K1) for
/// queued transactions, until the controller interrupt is wired. Sleeps
/// `I2C_SERVICE_POLL_US` between steps while a bus has work; parks
/// otherwise until a submit wakes it. Not in the RT band: it sleeps.
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
pub(crate) fn i2c_service_task(_: usize) {
    use azos_drv_sys::timebase::{freq, now};
    I2C_SVC_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    kprintln!("[I2C] service task started (board validation pending)");
    loop {
        let t = now();
        let mut busy = false;
        for bus in 0..azos_drv_bus::i2c::I2C_BUS_COUNT as u8 {
            busy |= azos_drv_bus::i2c::i2c_service(bus, t);
        }
        let wait = if busy {
            freq() * azos_limits::I2C_SERVICE_POLL_US as u64 / 1_000_000
        } else {
            freq() // a lost wake costs at most this
        };
        azos_sched::task_block(azos_sched::WaitReason::Timer(now() + wait.max(1)));
    }
}

#[cfg(any(feature = "i2c-dw", feature = "k1"))]
static I2C_SVC_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Boot, at the `i2c-svc` task's creation and before the seal: what a submit
/// calls to get its transaction serviced (a set-once hook).
#[cfg(any(feature = "i2c-dw", feature = "k1"))]
pub(crate) fn install_i2c_service_kick() {
    azos_drv_bus::i2c::set_service_kick(i2c_service_kick);
}

#[cfg(any(feature = "i2c-dw", feature = "k1"))]
fn i2c_service_kick() {
    let tid = I2C_SVC_TID.load(Ordering::Acquire);
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(
            tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

/// Odometry + encoder task at Kconfig `SENSOR_ODOM_HZ`.
pub(crate) fn odom_task(_: usize) {
    use azos_drv_base::sensors::board;
    kprintln!("[ODOM-TASK] Started ({} Hz)", azos_limits::SENSOR_ODOM_HZ);
    let odom_interval: u64 = azos_drv_sys::timebase::freq() / azos_limits::SENSOR_ODOM_HZ as u64;
    let mut odom_tx = board::ODOM_SENSOR.producer().expect("odometry stream: second producer");
    let mut enc_tx = board::ENCODER_SENSOR.producer().expect("encoder stream: second producer");
    loop {
        let ((el, er), acq) = azos_robot::encoder_read_stamped();
        azos_robot::odom_update_at(el, er, acq);
        let (d, h) = azos_robot::odom_get();
        let ns = azos_drv_sys::timebase::vdso_ns(acq);
        odom_tx.publish(board::ODOM_SENSOR.pack(&[d, h], 0, ns));
        enc_tx.publish(board::ENCODER_SENSOR.pack(&[el, er], 0, ns));
        let dl = azos_drv_sys::timebase::now() + odom_interval;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}

/// Slow sensor task: rangefinder + battery + digital lines at Kconfig
/// `SENSOR_SLOW_HZ`.
pub(crate) fn sensor_slow_task(_: usize) {
    use azos_drv_base::sensors::board;
    use azos_drv_sys::timebase::{now, vdso_ns};
    kprintln!("[SENSOR-SLOW] Started ({} Hz)", azos_limits::SENSOR_SLOW_HZ);
    let slow_interval: u64 = azos_drv_sys::timebase::freq() / azos_limits::SENSOR_SLOW_HZ as u64;
    let mut range_tx = board::RANGE_SENSOR.producer().expect("rangefinder stream: second producer");
    let mut battery_tx = board::BATTERY_SENSOR.producer().expect("battery stream: second producer");
    let mut flags_tx = board::FLAGS_SENSOR.producer().expect("digital-line stream: second producer");
    let line = |pin: u8| azos_drv_gpio::gpio::gpio_read(pin as u32) == 1;
    loop {
        let front = azos_drv_sensor::rangefinder::us_read_mm(0);
        let right = azos_drv_sensor::rangefinder::us_read_mm(1);
        if let Some(s) = board::range_sample(front, right, vdso_ns(now())) {
            range_tx.publish(s);
        }
        // No converter, or one that did not answer: nothing is published, and
        // the bus reads 0, "no reading" (at once if none ever was, once the last
        // sample is stale if one was). A made-up voltage below the safety
        // layer's thresholds read as a flat pack and held the e-stop on every
        // tick from boot under QEMU, which has no ADS1115.
        let mv = if azos_drv_sensor::ads1115::ads1115_is_initialized() {
            azos_drv_sensor::ads1115::ads1115_read_battery_mv(0, 2)
        } else {
            None
        };
        if let Some(s) = board::battery_sample(mv, vdso_ns(now())) {
            battery_tx.publish(s);
        }
        let (pir, sound, ir) = (
            line(azos_limits::SENSOR_PIR_GPIO as u8),
            line(azos_limits::SENSOR_SOUND_GPIO as u8),
            line(azos_limits::SENSOR_IR_GPIO as u8),
        );
        flags_tx.publish(board::flags_sample(pir, sound, ir, vdso_ns(now())));
        if azos_behavior::offline::offline_is_active() && (pir || sound || ir) {
            let _ = crate::buzzer::buzzer_beep();
        }
        let dl = azos_drv_sys::timebase::now() + slow_interval;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}

/// Phase I1: sensor + AHRS fusion task.
///
/// Reads IMU and barometer at ~100 Hz, publishes raw readings to CH_IMU /
/// CH_BARO, runs complementary filter, and publishes estimated attitude to
/// CH_ATTITUDE.
///
/// K-C27: the 100 Hz used to be claimed by "1 yield per iteration at 100 Hz
/// scheduler", which was false — `task_yield()` returns immediately when the
/// caller is the highest-priority runnable task, so this loop spun at
/// whatever rate the host emulated and, at priority 14, monopolised hart 1
/// against everything best-effort. It now sleeps to its design rate on the
/// same Timer idiom as `imu_task`; the fusion math already computes `dt_us`
/// from real CLINT time, so the rate change touches sampling cadence only.
pub(crate) fn sensor_ahrs_task(_: usize) {
    use azos_ahrs::{AhrsState, CH_IMU, CH_BARO, CH_ATTITUDE};
    use azos_gps::CH_GPS;
    use azos_nav::{CH_PROXIMITY, ProximityData};

    kprintln!("[AHRS] Phase I1+I2+I3+M: sensor fusion task (AHRS + GPS yaw + proximity)");

    // This task is each channel's one publisher. It is created once and never
    // restarted at its entry, so the handles live in locals.
    let mut imu_tx = CH_IMU.publisher().expect("CH_IMU: second publisher");
    let mut baro_tx = CH_BARO.publisher().expect("CH_BARO: second publisher");
    let mut att_tx = CH_ATTITUDE.publisher().expect("CH_ATTITUDE: second publisher");
    let mut gps_tx = CH_GPS.publisher().expect("CH_GPS: second publisher");
    let mut prox_tx = CH_PROXIMITY.publisher().expect("CH_PROXIMITY: second publisher");

    let mut gps_stream = azos_drv_base::sensors::board::GPS_SENSOR.producer().expect("GPS stream: second producer");

    // Fusion period: the IMU's rate (Kconfig `SENSOR_IMU_HZ`).
    let ahrs_interval: u64 = azos_drv_sys::timebase::freq() / azos_limits::SENSOR_IMU_HZ as u64;
    // The GPS is polled once per `SENSOR_SLOW_HZ` period.
    let gps_every = (azos_limits::SENSOR_IMU_HZ / azos_limits::SENSOR_SLOW_HZ).max(1) as u32;

    let mut ahrs = AhrsState::new();

    // Set reference pressure from first baro reading.
    if let Some(baro) = azos_baro::baro_read() {
        ahrs.set_ref_pressure(baro.pressure_pa);
        kprintln!("[AHRS] Reference pressure: {} Pa", baro.pressure_pa);
    }

    let mut last_time = azos_drv_sys::timebase::now();
    let mut gps_counter: u32 = 0;
    let mut prox_counter: u32 = 0;

    loop {
        let now = azos_drv_sys::timebase::now();

        // Compute dt in microseconds.
        let dt_ticks = now.wrapping_sub(last_time);
        let dt_us = (dt_ticks * 1_000_000 / azos_drv_sys::timebase::freq()) as u32;
        last_time = now;

        // Skip if dt is unreasonable (first iteration or timer wrap).
        if dt_us == 0 || dt_us > 1_000_000 {
            let dl = azos_drv_sys::timebase::now() + ahrs_interval;
            azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
            continue;
        }

        // Read IMU (~100 Hz).
        // The channels carry each value's ACQUISITION stamp (taken in its
        // driver), so `Channel::age` is the sample's age. The attitude is as
        // old as the IMU sample it integrates.
        if let Some((imu, imu_acq)) = azos_imu::imu_read_scaled_stamped() {
            imu_tx.publish(imu, imu_acq);

            // Read barometer. A failed read feeds the fusion no pressure: the
            // altitude holds and `CH_BARO` ages (no invented 101 325 Pa).
            let baro_pa = azos_baro::baro_read_stamped().map(|(baro, baro_acq)| {
                baro_tx.publish(baro, baro_acq);
                baro.pressure_pa
            });

            // Run AHRS fusion.
            let att = ahrs.update(&imu, baro_pa, dt_us);
            att_tx.publish(att, imu_acq);
        }

        // Poll GPS at `SENSOR_SLOW_HZ`.
        // Phase I3: GPS course-over-ground corrects AHRS yaw drift when moving.
        gps_counter += 1;
        if gps_counter >= gps_every {
            gps_counter = 0;
            if let Some(fix) = azos_gps::gps_read_stamped() {
                let pos = fix.pos;
                ahrs.update_gps(&pos);
                gps_tx.publish(pos, fix.acq);
                // The GPS stream, aged from the receiver's sentence (the
                // fix's acquisition stamp): a silent receiver's last fix
                // goes stale in the geofence instead of being re-stamped at
                // every poll.
                use azos_drv_base::sensors::board::GPS_SENSOR;
                let flags = if fix.synthetic { azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_SYNTHETIC as u32 } else { 0 };
                gps_stream.publish(GPS_SENSOR.pack(
                    &[pos.lat_deg7 as i64, pos.lon_deg7 as i64, pos.alt_mm as i64, pos.fix as i64, pos.sats as i64],
                    flags,
                    azos_drv_sys::timebase::vdso_ns(fix.acq),
                ));
            }
        }

        // Poll proximity sensors at ~20 Hz (every 5 iterations).
        prox_counter += 1;
        if prox_counter >= 5 {
            prox_counter = 0;
            use azos_drv_sensor::rangefinder;
            let us_n = rangefinder::us_count();
            let tof_n = rangefinder::tof_count();
            let mut prox = ProximityData::new();
            // US sensors: front(0), right(1), rear(2), left(3).
            for i in 0..us_n.min(4) {
                if let Some(d) = rangefinder::us_read_mm(i) {
                    prox.distances_mm[i as usize] = d as u16;
                }
            }
            // ToF sensors: down(4) index→0, forward(5) index→1.
            for i in 0..tof_n.min(2) {
                if let Some(d) = rangefinder::tof_read_mm(i) {
                    prox.distances_mm[4 + i as usize] = d;
                }
            }
            prox.count = us_n.min(4) + tof_n.min(2);
            prox_tx.publish(prox, now);
        }

        // Sleep to the next 100 Hz fusion tick (GPS divides this to ~10 Hz,
        // proximity to ~20 Hz via the counters above).
        let dl = azos_drv_sys::timebase::now() + ahrs_interval;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}

/// Phase L: telemetry task.
///
/// Periodically reads attitude, GPS, and flight state, serializes into
/// telemetry packets, and sends via UDP to the configured server.
/// Runs at ~10 Hz.
pub(crate) fn telemetry_task(_: usize) {
    use azos_ahrs::{CH_ATTITUDE, CH_IMU, CH_BARO};
    use azos_gps::CH_GPS;

    kprintln!("[TELEM] Phase L: telemetry task starting");

    let mut buf = [0u8; 64];
    let mut tick_count: u32 = 0;
    let mut udp_fd: i32 = -1;

    // Telemetry period: 10 Hz, the documented design rate.
    let telem_interval: u64 = azos_drv_sys::timebase::freq() / 10;

    loop {
        // K-C27: sleep to the 10 Hz design rate. The old "yield 10 times
        // (~100 ms)" assumed each yield waited a scheduler tick; a yield
        // with nothing outranking us returns immediately, so this loop was
        // a best-effort-band spinner.
        let dl = azos_drv_sys::timebase::now() + telem_interval;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));

        if !azos_telemetry::telem_is_active() {
            continue;
        }

        // Lazily create UDP socket.
        if udp_fd < 0 {
            udp_fd = azos_net::socket_create(
                azos_net::AF_INET, azos_net::SOCK_DGRAM, 0);
            if udp_fd < 0 { continue; }
        }

        tick_count += 1;

        let port = azos_telemetry::telem_port();
        let server_ip = azos_config::unpack_ip(
            azos_config::BEHAVIOR_SERVER_IP.load(Ordering::Relaxed));

        // Send TELEM_ATTITUDE every iteration (10 Hz).
        let att = CH_ATTITUDE.read().val;
        let gps = CH_GPS.read().val;
        let mode_val = match azos_flight::flight_mode() {
            azos_flight::FlightMode::Disarmed  => 0u8,
            azos_flight::FlightMode::Manual    => 1,
            azos_flight::FlightMode::Stabilize => 2,
            azos_flight::FlightMode::AltHold   => 3,
            azos_flight::FlightMode::PosHold   => 4,
            azos_flight::FlightMode::Auto      => 5,
            azos_flight::FlightMode::RTL       => 6,
            azos_flight::FlightMode::Land      => 7,
        };
        let armed = azos_flight::is_armed();

        let len = azos_telemetry::serialize_attitude(&mut buf, &att, &gps, mode_val, armed);
        if len > 0 {
            azos_net::udp::sendto(udp_fd, &server_ip, port, &buf[..len]);
            azos_telemetry::telem_inc_sent();
        }

        // Send TELEM_SENSORS every 2nd iteration (~5 Hz).
        if tick_count % 2 == 0 {
            let imu = CH_IMU.read().val;
            let baro = CH_BARO.read().val;
            let len = azos_telemetry::serialize_sensors(&mut buf, &imu, baro.pressure_pa);
            if len > 0 {
                azos_net::udp::sendto(udp_fd, &server_ip, port, &buf[..len]);
            }
        }
    }
}
