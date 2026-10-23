// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Robot hardware, payload and sensor install, partition publishing, and the
//! flight recorder with the e-stop latch replay.

use crate::*;

/// PWM/I2C bring-up + the robot motor-binding table
/// (the `pwm_channel_is_motor_bound`/`gpio_pin_is_motor_bound` guards,
/// and the `gpio-aq3-smoke`/`reflex-smoke` tasks, all need this).
///
/// On a board (`vf2`, `k1`) the controllers are the device tree's: the hardware
/// bus binds `i2c`, `pwm` and `sfctemp` (`vf2`) or `i2c` (`k1`: the
/// other K1 controllers have no native driver yet) to their nodes here, and
/// the thermal sensors of the boards that have one (the K1's temperature block,
/// the Raspberry Pi's mailbox; GPIO and the watchdog bound earlier,
/// `kernel_main`), and a node the tree lacks leaves its controller absent.
/// Everywhere else the hardware is simulated and
/// nothing describes it, so the I2C simulation's devices are populated here
/// (the GPIO and PWM simulations need no init).
///
/// Measured, not assumed: without the simulation's init, `i2c_init` never
/// having run left the simulated MPU-6050 unregistered, so `WHO_AM_I` read
/// `EIO`.
///
/// **`robot_init()` is deliberately NOT in this function** — it is the one
/// call riscv64's own tail places somewhere else in its interleave, after
/// `payload_init()`, so pulling it in here would reorder riscv64's own
/// `payload_init()` ahead of `robot_init()` to `robot_init()` ahead of
/// `payload_init()` the moment riscv64 called this helper — an actual
/// behaviour change and an objdump diff, not just a refactor. Both
/// `kernel_main`s call `azos_robot::robot_init()` themselves,
/// immediately after this function returns; aarch64's call site has none
/// of riscv64's `payload_init`/`motor_pid_init` machinery to interleave
/// with, so it simply follows. `#[inline(always)]` for the same reason
/// `install_ring3_seams`/`install_net_config` use it.
#[inline(always)]
pub(crate) fn install_robot_hw() {
    // The DesignWare I2C controllers the tree enables (the VisionFive 2's, the
    // Raspberry Pi 5 RP1's); an Intel LPSS one bound in the PCI stage already.
    #[cfg(feature = "i2c-dw")]
    super::hwbus::bind(&["i2c"]);
    #[cfg(feature = "vf2")]
    super::hwbus::bind(&["pwm", "sfctemp"]);
    // The K1's temperature block (Kconfig SOC_K1 and THERMAL).
    #[cfg(all(feature = "soc-k1", feature = "thermal"))]
    super::hwbus::bind(&["k1-tsensor"]);
    // The Raspberry Pi's VideoCore mailbox: the temperature and the ARM clock
    // the thermal task reads and moves (`boot::thermal`; the clock with ENERGY).
    // arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
    #[cfg(all(feature = "energy", target_arch = "aarch64"))]
    super::hwbus::bind(&["rpi-mbox"]);
    // The K1's I2C masters, and its PWM controllers: one node per channel (the
    // GPIO bound earlier, `bind_safety`). The DMA controller is not driven
    // there: no consumer.
    #[cfg(feature = "k1")]
    super::hwbus::bind(&["i2c", "pwm"]);
    // The PMIC's bus is attached: pin the always-on rails behind it (the
    // frameworks' build left them pending).
    #[cfg(all(feature = "k1", feature = "soc-k1"))]
    super::soc::pin_pmic_always_on();
    #[cfg(not(any(feature = "i2c-dw", feature = "k1")))]
    azos_drv_bus::i2c::i2c_init();
    // What the tree's nodes bound, not what the drivers could drive: a node the
    // tree lacks (or a bind that failed) leaves its controller absent.
    #[cfg(feature = "vf2")]
    kprintln!("[HW] GPIO {}, PWM {}, I2C {} of {} buses bound",
        if azos_drv_gpio::gpio::gpio_has_hardware() { "bound" } else { "ABSENT" },
        if azos_drv_actuator::pwm::pwm_has_hardware() { "bound" } else { "ABSENT" },
        azos_drv_bus::i2c::i2c_buses_attached(),
        azos_drv_bus::i2c::I2C_BUS_COUNT);
    #[cfg(feature = "k1")]
    kprintln!("[HW] GPIO {}, PWM {}, I2C {} of {} buses bound",
        if azos_drv_gpio::gpio::gpio_has_hardware() { "bound" } else { "ABSENT" },
        if azos_drv_actuator::pwm::pwm_has_hardware() { "bound" } else { "ABSENT" },
        azos_drv_bus::i2c::i2c_buses_attached(),
        azos_drv_bus::i2c::I2C_BUS_COUNT);
    #[cfg(not(any(feature = "vf2", feature = "k1", feature = "i2c-dw")))]
    kprintln!("[HW] GPIO ({} pins), PWM ({} ch), I2C ({} buses) ready",
        azos_drv_gpio::gpio::GPIO_MAX_PINS,
        azos_drv_actuator::pwm::PWM_MAX_CHANNELS,
        azos_drv_bus::i2c::I2C_BUS_COUNT);
    // A DesignWare I2C off the VisionFive 2 (the Pi 5, a PC): the GPIO and
    // PWM are still the simulations, the buses are what bound.
    #[cfg(all(feature = "i2c-dw", not(feature = "vf2")))]
    kprintln!("[HW] GPIO ({} pins), PWM ({} ch) simulated, I2C {} of {} buses bound",
        azos_drv_gpio::gpio::GPIO_MAX_PINS,
        azos_drv_actuator::pwm::PWM_MAX_CHANNELS,
        azos_drv_bus::i2c::i2c_buses_attached(),
        azos_drv_bus::i2c::I2C_BUS_COUNT);
}

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
/// documented by `install_robot_hw`/`install_topology`/`install_sched_hooks`.
/// None of the drivers called below (`payload`, `robot`, `motor_pid`, `spi`,
/// `can`, `pm`, `imu`, `baro`, `gps`, `rangefinder`, `csi`,
/// `esc`, `rc`) branch on `target_arch` in their own crates — the
/// same "simulated in QEMU on both ISAs" property `install_robot_hw`'s own
/// doc establishes for GPIO/PWM/I2C — so this compiles and behaves
/// identically on both targets; the `#[cfg(feature = "k1")]`/`#[cfg(any(
/// feature = "vf2", feature = "k1"))]` blocks stay feature-gated, unrelated
/// to `target_arch`.
///
/// **Call only after `install_robot_hw()` and after network bring-up**
/// (`install_net_config`/`install_net`/`net_init`) — the SPI/CAN/DMA/USB/PM
/// block's own comment below ("eth_init() already called above during
/// network init sequence") assumes the network stack is already up; that
/// was already true on riscv64's existing call order and the unified
/// `kernel_main` keeps net before this helper on BOTH ISAs so the comment
/// stays true everywhere it is compiled (see the merge's ordering-decisions
/// note #4 — aarch64's pre-merge order called this before net, for no
/// stated reason).
#[inline(always)]
pub(crate) fn install_robot_payload_and_sensors() {
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
    // U05-1/U05-2 (2026-09-26): `spi_init`/`usb_init` deleted here — no board
    // maps `SPI0_BASE`/`USB0_BASE` in its MMIO list and both register models
    // are unverified (see `platform.rs`'s VF2 checklist); re-add the day a
    // board's `boot_hooks.rs` maps them.
    azos_drv_bus::can::can_init();
    // eth_init() already called above during network init sequence.
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
    #[cfg(all(feature = "rvv", not(feature = "no-ml")))]
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
    azos_drv_sensor::rangefinder::us_init(4);   // 4 ultrasonic (front/right/rear/left)
    #[cfg(feature = "use-robot")]
    azos_drv_sensor::rangefinder::tof_init(2);  // 2 ToF (down + forward)

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
    // Wave 15: compiled only with Kconfig `RC_INPUT` (feature `rc-input`); the
    // receiver's say in the safety path is kernel/src/tasks/rc_safety.rs.
    #[cfg(all(feature = "rc-input", not(any(feature = "vf2", feature = "k1", feature = "rpi5"))))]
    azos_robot_drivers::rc::rc_init(azos_robot_drivers::rc::RcMode::Simulated);
    #[cfg(all(feature = "rc-input", any(feature = "vf2", feature = "k1", feature = "rpi5")))]
    azos_robot_drivers::rc::rc_init(azos_robot_drivers::rc::RcMode::Sbus);
    kprintln!();
}

/// Parse the medium's partition table and publish it, so a topology can mint
/// a `Cap<Disk>` scoped to one partition
/// (`crates/drivers/block/src/partition.rs`). Runs once, right after the block
/// device comes up and before any task exists.
///
/// Every QEMU image in the tree is a `mkfs.fat` superfloppy: LBA 0 is the
/// FAT32 boot sector, so this finds no table, publishes zero partitions, and
/// nothing becomes mintable — `Cap<Disk>` stays exactly as latent as before.
/// A table that is present but malformed publishes nothing either.
pub(crate) fn publish_partitions() {
    use azos_drv_block::partition::{parse, publish, Scheme, SECTOR};
    let cap = azos_drv_block::blkdev::capacity_sectors();
    let mut read = |lba: u64, buf: &mut [u8; SECTOR]| azos_drv_block::blkdev::read(lba, 1, buf);
    match parse(cap, &mut read) {
        Ok(t) => {
            publish(&t);
            match t.scheme {
                Scheme::None => kprintln!("[DISK] partitions: none (no table)"),
                Scheme::Mbr | Scheme::Gpt => {
                    kprintln!("[DISK] partitions: {} ({})", t.count,
                        if t.scheme == Scheme::Mbr { "MBR" } else { "GPT" });
                    for (i, p) in t.parts[..t.count].iter().enumerate() {
                        kprintln!("[DISK]   part {}: LBA {} + {}", i, p.start, p.sectors);
                    }
                }
            }
        }
        Err(e) => azos_drv_sys::kwarn!("[DISK] partition table refused: {:?}", e),
    }
}

/// Flight recorder + e-stop latch replay: mint the FAT32-backed log storage,
/// replay the durable latch record, arm the recorder, and re-record the
/// (possibly-updated) latch state so the NEXT boot sees this one's verdict.
///
/// **Call only after `fat32_mount()`/`vfs_mount(b"/fat", ...)` have already
/// succeeded** — this function does not attempt either itself, the same way
/// `install_net_config` does not itself call `net_init()`. Must run BEFORE
/// `robot_init()`/`install_robot_hw()`: the latch alone, no `motor_stop`/
/// `esc_disarm`, is deliberate — see the block below's own "e-stop latch"
/// comment for why that is safe only while no motor exists yet to stop and
/// no ESC is armed. And BEFORE `logger_init()` inside this same function —
/// see that call's own placement note; the ordering is internal to this
/// function, callers do not need to reproduce it themselves.
///
/// Shared between both `kernel_main`s: riscv64 had this inline in its own
/// FAT32-mount arm; aarch64 never called any of it, so the "was the e-stop
/// latched when we last shut down?" replay silently answered "not latched"
/// on every boot there, regardless of what the durable record said — no
/// error, no failing test, same silent-failure class `install_sched_hooks`
/// documents for its own four callbacks. riscv64 has a gate row for this
/// property (`safety: latch survives reboot`); `aarch64: flight recorder`
/// is its twin — same two-boots-one-image shape, this function is what
/// makes it possible on this ISA.
pub(crate) fn install_flight_recorder() {
    // The flight recorder, wired for safety events only.
    //
    // Here because this is the first point at which it has
    // anywhere to write. Deliberately best-effort: a board with no
    // disk, or a disk that is not FAT32, must still boot and still
    // drive motors. `push_event` is a no-op until `logger_init`
    // succeeds, so every call site added below is safe whether or
    // not this line worked.
    // The flight recorder's storage seam. `domains/robot/behavior` is
    // core and `crates/fs/fs` is scaffolding, so the recorder cannot
    // name FAT32 directly -- it declares what it needs and the
    // kernel, which is the composition root, supplies it. Same
    // shape as `KernelFileOps` for the file syscalls.
    //
    // The handle is VALIDATED rather than trusted. `LogHandle` is
    // an opaque u32 chosen by this implementation, and a stale one
    // arriving after a wrap-and-reopen must be refused, not
    // silently written to whatever file is open now: the whole
    // point of the recorder is that a record lands where the
    // reader will look for it.
    struct KernelLogStorage;
    static LOG_SLOT: azos_sync::SpinLock<
        Option<(u32, azos_fs::Fat32File)>
    > = azos_sync::SpinLock::new(None);
    static LOG_NEXT_HANDLE: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(1);

    impl KernelLogStorage {
        /// Resolve a handle to its file, or `Unavailable`. Every
        /// method goes through this so "stale handle" and "nothing
        /// open" are the same answer at every entry point.
        fn file(h: azos_actuation::logger::LogHandle)
            -> Result<azos_fs::Fat32File,
                      azos_actuation::logger::LogStorageError>
        {
            let slot = LOG_SLOT.lock();
            match *slot {
                Some((id, f)) if id == h.0 => Ok(f),
                _ => Err(azos_actuation::logger::LogStorageError::Unavailable),
            }
        }
    }

    impl azos_actuation::logger::LogStorage for KernelLogStorage {
        fn open(&self, serial: u32)
            -> Result<azos_actuation::logger::LogHandle,
                      azos_actuation::logger::LogStorageError>
        {
            use azos_actuation::logger::LogStorageError as E;
            let vol = azos_fs::fat32_mount_volume().map_err(|_| E::Unavailable)?;
            // Best-effort: the directory usually exists already.
            let _ = azos_fs::fat32_mkdir(vol, b"/LOG");

            let mut path = [0u8; 17];
            azos_actuation::logger::make_log_path(serial, &mut path);
            let flags = azos_fs::open_flags::WRITE
                | azos_fs::open_flags::CREATE
                | azos_fs::open_flags::TRUNCATE;
            let f = azos_fs::fat32_open(vol, &path, flags)
                .map_err(|_| E::Io)?;

            // Close whatever was open first: the recorder reopens
            // on wrap, and leaking the previous file would run the
            // FAT32 open-file table out over a long mission.
            let id = LOG_NEXT_HANDLE
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let mut slot = LOG_SLOT.lock();
            if let Some((_, old)) = slot.take() {
                let _ = azos_fs::fat32_close(old);
            }
            *slot = Some((id, f));
            Ok(azos_actuation::logger::LogHandle(id))
        }

        fn write(&self, h: azos_actuation::logger::LogHandle, buf: &[u8])
            -> Result<usize, azos_actuation::logger::LogStorageError>
        {
            let f = Self::file(h)?;
            azos_fs::fat32_write(f, buf)
                .map_err(|_| azos_actuation::logger::LogStorageError::Io)
        }

        fn fsync(&self, h: azos_actuation::logger::LogHandle)
            -> Result<(), azos_actuation::logger::LogStorageError>
        {
            let f = Self::file(h)?;
            azos_fs::fat32_fsync(f)
                .map_err(|_| azos_actuation::logger::LogStorageError::Io)
        }

        fn close(&self, h: azos_actuation::logger::LogHandle)
            -> Result<(), azos_actuation::logger::LogStorageError>
        {
            let f = Self::file(h)?;
            *LOG_SLOT.lock() = None;
            azos_fs::fat32_close(f)
                .map_err(|_| azos_actuation::logger::LogStorageError::Io)
        }
    }

    static KERNEL_LOG_STORAGE: KernelLogStorage = KernelLogStorage;
    azos_actuation::logger::logger_set_storage(&KERNEL_LOG_STORAGE);

    // ── The e-stop latch survives a reset ────────────────────────
    //
    // Owner decision, 2026-09-13: the last `SAFETY_ESTOP` in the
    // durable record decides whether this boot starts latched. The
    // decision is `replay_boot_latch`, a pure function the host
    // suite drives; this block is only the FAT32 half of its
    // read-only seam.
    //
    // HERE, and not after `logger_init`: that call opens serial 0
    // with TRUNCATE, which erases the file this reads.
    //
    // The latch alone, no `motor_stop`/`esc_disarm`: `robot_init`
    // has not run, so there is no motor to stop and no ESC armed,
    // and `motor_envelope` clamps every write from the first one.
    struct FatReplay {
        vol: azos_fs::Volume,
        file: Option<azos_fs::Fat32File>,
    }

    impl azos_actuation::logger::LogReplaySource for FatReplay {
        fn size(&mut self, serial: u32)
            -> Result<Option<u32>, azos_actuation::logger::LogStorageError>
        {
            use azos_actuation::logger::LogStorageError as E;
            let mut path = [0u8; 17];
            azos_actuation::logger::make_log_path(serial, &mut path);
            match azos_fs::fat32_open(self.vol, &path, azos_fs::open_flags::READ) {
                Ok(f) => {
                    let stat = azos_fs::fat32_file_stat(f);
                    let _ = azos_fs::fat32_close(f);
                    stat.map(|(_, size)| Some(size)).map_err(|_| E::Io)
                }
                // A medium that has never had a `/LOG` directory
                // resolves to this same `NotFound`.
                Err(azos_fs::FsError::NotFound) => Ok(None),
                Err(_) => Err(E::Io),
            }
        }

        fn open(&mut self, serial: u32)
            -> Result<(), azos_actuation::logger::LogStorageError>
        {
            let mut path = [0u8; 17];
            azos_actuation::logger::make_log_path(serial, &mut path);
            let f = azos_fs::fat32_open(self.vol, &path, azos_fs::open_flags::READ)
                .map_err(|_| azos_actuation::logger::LogStorageError::Io)?;
            self.file = Some(f);
            Ok(())
        }

        fn read(&mut self, buf: &mut [u8])
            -> Result<usize, azos_actuation::logger::LogStorageError>
        {
            use azos_actuation::logger::LogStorageError as E;
            let f = self.file.ok_or(E::Unavailable)?;
            azos_fs::fat32_read(f, buf).map_err(|_| E::Io)
        }

        fn close(&mut self) {
            if let Some(f) = self.file.take() {
                let _ = azos_fs::fat32_close(f);
            }
        }
    }

    use azos_actuation::logger::{BootLatch, BootReplay};
    let boot_replay = match azos_fs::fat32_mount_volume() {
        Ok(vol) => azos_actuation::logger::replay_boot(
            &mut FatReplay { vol, file: None }),
        // Mounted a moment ago and no volume now: the medium is
        // there and cannot be read, which fails safe.
        Err(_) => BootReplay::blank(BootLatch::Unreadable),
    };
    azos_actuation::boot_latch::apply(boot_replay);

    match azos_actuation::logger::logger_init() {
        Ok(())  => kprintln!("[LOG] flight recorder armed (safety events)"),
        Err(_)  => kprintln!("[LOG] flight recorder unavailable — console is the record"),
    }

    azos_actuation::boot_latch::record(boot_replay.latch);

    // aarch64 parity task S2: write a durable, LATCHING `SAFETY_ESTOP`
    // record on THIS boot, so the gate's second boot (same image) has
    // something for the replay above to find. ISA-neutral and off by
    // default — see the `aarch64: flight recorder` / `flight recorder:
    // latch survives reboot` gate rows for the two-boot harness this
    // feeds. Action 2 matches `kill_switch.rs`'s own latching write (a
    // real GPIO kill switch is riscv64's `safety: latch survives reboot`
    // row's trigger; this is the same durable-write API, `domains/robot/behavior`
    // is core and takes no ISA branch, called directly rather than through
    // a GPIO nobody has wired in QEMU on either ISA).
    #[cfg(feature = "estop-latch-smoke")]
    {
        match azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_ESTOP, 2, 0)
        {
            Ok(n)  => kprintln!("[ESTOPLATCHSMOKE] wrote durable SAFETY_ESTOP record ({} record(s) flushed)", n),
            Err(_) => kprintln!("[ESTOPLATCHSMOKE] FAILED: could not write durable SAFETY_ESTOP record"),
        }
        // Park the boot here. The gate builds the disk a power cut would
        // leave from QEMU's write log (`blklogwrites`), cut at the last flush;
        // anything this boot wrote after the line above (a periodic logger
        // flush, BOOTMETA) could add a flush that makes a missing one
        // invisible. Nothing after this point touches the disk.
        kprintln!("[ESTOPLATCHSMOKE] parked: no further disk I/O this boot");
        loop { core::hint::spin_loop(); }
    }
}
