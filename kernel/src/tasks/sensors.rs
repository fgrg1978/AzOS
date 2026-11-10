// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The I2C controllers' service task and the telemetry task.

use crate::*;

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
        // sleep to the 10 Hz design rate. The old "yield 10 times
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
