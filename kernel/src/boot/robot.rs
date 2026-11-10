// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Robot payload and sensor install; `kernel_main`'s Phases 17 and G1.

use crate::*;

/// Robot payload + drivers + sensor bring-up (Phase 10 + Phase E1-O):
/// payload abstraction (E04), `robot_init()`, motor PID, the Phase H driver
/// set (CAN, PM), and the full sensor suite (IMU/baro/
/// GPS/rangefinders/CSI camera/WiFi/ESC/RC).
///
/// NEW shared behaviour on aarch64 (kernel-main-merge task, owner-authorized
/// in the merge brief): riscv64's `kernel_main` always ran this; aarch64's
/// never called any of it, so a ring-3 process there saw the whole payload/
/// motor/sensor subsystem as absent regardless of what the (QEMU-simulated)
/// hardware could answer — same "nothing called it here" gap class already
/// documented by `install_board_hw`/`install_topology`/`install_sched_hooks`.
/// None of the drivers called below (`payload`, `robot`, `motor_pid`, `spi`,
/// `can`, `pm`, `imu`, `baro`, `gps`, `rangefinder`, `csi`,
/// `esc`, `rc`) branch on `target_arch` in their own crates — the
/// same "simulated in QEMU on both ISAs" property `install_board_hw`'s own
/// doc establishes for GPIO/PWM/I2C — so this compiles and behaves
/// identically on both targets; the `#[cfg(feature = "k1")]`/`#[cfg(any(
/// feature = "vf2", feature = "k1"))]` blocks stay feature-gated, unrelated
/// to `target_arch`.
///
/// **Call only after `install_board_hw()` and after network bring-up**
/// (`install_net_config`/`install_net`/`net_init`) — the SPI/CAN/DMA/USB/PM
/// block assumes the network stack is already up; that
/// was already true on riscv64's existing call order and the unified
/// `kernel_main` keeps net before this helper on BOTH ISAs so the comment
/// stays true everywhere it is compiled (see the merge's ordering-decisions
/// note #4 — aarch64's pre-merge order called this before net, for no
/// stated reason).
#[inline(always)]
pub(crate) fn install_robot_payload_and_sensors() {
    #[cfg(feature = "use-robot")]
    {
        azos_safety_core::frames::set_buzzer(
            crate::buzzer::buzzer_beep, crate::buzzer::buzzer_alert, crate::buzzer::buzzer_off);
    }
    kprintln!("========================================");
    kprintln!(" Phase 10: Drivers + Robot Framework");
    kprintln!("========================================");
    kprintln!();

    // E04: Payload abstraction — spray, gripper, camera trigger
    #[cfg(feature = "use-robot")]
    azos_behavior::payload::payload_init();
    #[cfg(feature = "use-robot")]
    kprintln!("[PAYLOAD] E04: spray GPIO{}, gripper PWM ch{}, cam-trig GPIO{}",
        azos_behavior::payload::PAYLOAD_GPIO_SPRAY,
        azos_behavior::payload::PAYLOAD_PWM_GRIPPER,
        azos_behavior::payload::PAYLOAD_GPIO_CAM_TRIGGER);

    #[cfg(feature = "use-robot")]
    azos_robot::robot_init();
    #[cfg(feature = "use-robot")]
    azos_drv_actuator::motor_pid::motor_pid_init();

    // Phase H: additional drivers
    // `spi_init`/`usb_init` deleted here — no board
    // maps `SPI0_BASE`/`USB0_BASE` in its MMIO list and both register models
    // are unverified (see `platform.rs`'s VF2 checklist); re-add the day a
    // board's `boot_hooks.rs` maps them.
    azos_drv_bus::can::can_init();
    kprintln!("[HW] CAN initialized");

    kprintln!();

    // ---- Phase 11: RISC-V Vector Extension (RVV 1.0) ----
    //
    // Only compiled when --features rvv is passed (QEMU with -cpu rv64,v=true).
    // VisionFive 2 (SiFive U74) has no V extension — QEMU emulation only.

    #[cfg(feature = "rvv")]
    {
        kprintln!("========================================");
        kprintln!(" Phase 11: RVV 1.0 (VLEN=128, f32)");
        kprintln!("========================================");
        kprintln!();
    }
    #[cfg(feature = "rvv")]
    {
        kprintln!("========================================");
        kprintln!(" Phase 14: Virtual Camera Driver");
        kprintln!("========================================");
        kprintln!();
    }

    // ---- Phase E1+E2+G1+G2+H1+I1: Sensors + AHRS ----

    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase E1: Scheduler {} Hz", azos_drv_sys::timebase::sched_hz_get());
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase E2: IMU driver (MPU-6050)");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase G1: Barometer (BMP280)");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase G2: Persistent State Recovery");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase H1: Channel<T> middleware");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase I1: AHRS complementary filter");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase I2: GPS driver (NMEA)");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase J:  Flight controller (mixer+PID)");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase K:  RC input + failsafe");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase L:  Telemetry protocol");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase M:  Perception (rangefinder + CSI camera)");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase N:  Navigation + waypoints");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase O:  ESP32-C3 companion (WiFi)");
    #[cfg(feature = "use-robot")]
    kprintln!("========================================");

    #[cfg(feature = "use-robot")]
    azos_imu::imu_init(0, azos_imu::MPU6050_ADDR);
    #[cfg(feature = "use-robot")]
    azos_baro::baro_init(0, azos_baro::BMP280_ADDR);
    #[cfg(feature = "use-robot")]
    azos_gps::gps_init(1, 9600); // UART1, 9600 baud (standard GPS)

    // Phase M: rangefinder sensors (proximity).
    #[cfg(feature = "use-robot")]
    let _ = azos_drv_sensor::rangefinder::us_init(4);   // 4 ultrasonic (front/right/rear/left)
    #[cfg(feature = "use-robot")]
    let _ = azos_drv_sensor::rangefinder::tof_init(2);  // 2 ToF (down + forward)

    // Phase M2: MIPI CSI-2 camera (simulated on QEMU).
    #[cfg(feature = "use-robot")]
    azos_drv_sensor::csi::csi_init(
        azos_drv_sensor::csi::DEFAULT_WIDTH,
        azos_drv_sensor::csi::DEFAULT_HEIGHT,
        azos_drv_sensor::csi::PixFmt::Gray8,
    );

    #[cfg(feature = "use-robot")]
    azos_robot_drivers::esc::esc_init(4); // 4 ESC channels (QuadX)
    // The RC mode is chosen BY TARGET, not hardcoded.
    //
    // This line read `RcMode::Simulated` for every target, so a VisionFive 2
    // build came up with the receiver marked ready, failsafe cleared and fixed
    // neutral sticks — `rc_age` never grows, and the whole link-loss failsafe
    // chain (disarm / RTL) can never fire on the machine it exists to protect.
    // The variant is now `cfg`'d out of existence on board targets, so this
    // does not compile there; `RcMode::Sbus` fails CLOSED (not ready, held in
    // failsafe, `rc_read` returns `None`) until the SBUS byte source
    // (`rc_feed_byte`, called by the board's UART receive interrupt) decodes
    // a frame. Loud and useless beats quiet and fabricated.
    //
    // Compiled only with Kconfig `RC_INPUT` (feature `rc-input`); the
    // receiver's say in the safety path is crates/domains/robot/safety-core/src/enforce.rs.
    #[cfg(all(feature = "rc-input", not(any(feature = "vf2", feature = "k1", feature = "rpi5"))))]
    azos_robot_drivers::rc::rc_init(azos_robot_drivers::rc::RcMode::Simulated);
    #[cfg(all(feature = "rc-input", any(feature = "vf2", feature = "k1", feature = "rpi5")))]
    azos_robot_drivers::rc::rc_init(azos_robot_drivers::rc::RcMode::Sbus);
    kprintln!();
}

/// `kernel_main`'s Phases 17 and G1: the robot banner (a robot image), the
/// robot hardware, a board's PCF8563, the payload and sensors, the camera's
/// capture task, and the behavior engine's banner; the two install calls run
/// on every image. Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn bring_up_robot() {
    // ---- Phase 17: Robot Physical Integration ----

    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!(" Phase 17: Robot Physical Integration");
    #[cfg(feature = "use-robot")]
    kprintln!("========================================");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Encoder sim: ticks in rt_motor_task → speed × iteration");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Odometry:    dead reckoning (dist_mm, heading_cdeg)");
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] Trajectory:  ring buffer ({} pts) + FAT32 CSV flush",
        azos_robot::TRAJ_CAP);
    #[cfg(feature = "use-robot")]
    kprintln!("[ROBOT] OTA:         A/B firmware slots (recovery console: ota recv/status/verify)");
    #[cfg(feature = "use-robot")]
    kprintln!();

    // Shared with aarch64's kernel_main — see `install_board_hw`'s own doc
    // for why `robot_init()` (inside the next helper) stays a separate call
    // rather than living inside `install_board_hw` itself (this ISA's own
    // `payload_init` interleave).
    install_board_hw();
    // A board's PCF8563 needs the I2C controllers `install_board_hw` brought up.
    #[cfg(feature = "rtc-pcf8563")]
    boot::rtc::install_i2c();
    // Payload + drivers + full sensor suite — see
    // `install_robot_payload_and_sensors`'s own doc for the merge-task
    // finding (this was riscv64-only; now shared) and the ordering
    // constraint (must follow network bring-up).
    install_robot_payload_and_sensors();
    // On a robot image, the camera's capture task.
    #[cfg(feature = "use-robot")]
    camera_capture_init();

    // The behaviour engine is ring 3's (BRAINCLI.ELF): it chooses, the kernel
    // enforces (the robot enforcer, the effect loops, the gate).
    #[cfg(feature = "use-robot")]
    kprintln!("[BEHAVIOR] engine in ring 3; L0 (safety) enforced in the kernel");
}
