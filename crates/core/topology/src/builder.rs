// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Programmatic topology builders.
//!
//! Useful when:
//!
//! - The kernel installs the built-in default topology at boot
//!   (`fill_default_minimal`, from `kernel/src/boot/topology.rs`); this is
//!   the topology every build boots today.
//! - Tests want to construct a topology without parsing TOML.
//!
//! Loading a signed TOML pair from FAT32 (`parser`, `verify`) is
//! implemented but not called by the kernel at boot.

use azos_abi::cap::{CapKind, CapPerms};

use crate::types::{
    CapSpec, ClassSpec, MaybeStr, PolicyKind, Preemption, SchedConfig, Topology,
};

// ──────────────────────────────────────────────────────────────────────────
// Static literals — used as borrows in the resulting topology
// ──────────────────────────────────────────────────────────────────────────

const NAME_SAFETY: &[u8] = b"safety_critical";
const NAME_HARD_RT: &[u8] = b"hard_rt";
const NAME_SOFT_RT: &[u8] = b"soft_rt";
const NAME_BEST_EFFORT: &[u8] = b"best_effort";
const NAME_IDLE: &[u8] = b"idle";

const TASK_SUPERVISOR: &[u8] = b"supervisor";
const TASK_BRAIN_LINK: &[u8] = b"brain_link";
// RFC-0003 migration phase P1: the autorun ELF (`kernel/src/tasks/loader.rs`'s
// `autorun_task`) is not spawned from a topology `TaskSpec` today — no
// name→spawn wiring exists yet, that's a separate piece of work — but its
// cap grants ARE looked up by this name (`find_task(b"autorun")`) so the
// P1 topology→cap_store bridge has something declarative to seed instead
// of the kernel hard-coding motor ids a second time.
const TASK_AUTORUN: &[u8] = b"autorun";
// RFC-0040 gap 2. Spawned processes look their row up by the IMAGE name
// (`spawn_policy`'s `topology_key = profile.image`, pinned by
// `tests/host/seccomp-tests`). No row was ever named after an image, so every
// `SYS_SPAWN` since RFC-0043 seeded exactly nothing — the mechanism was wired
// and had no data, which printed as `caps minted=0 (skipped 0)` and read like
// "this image declares none". This is the first such row.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_EPSRV_IMAGE: &[u8] = b"EPSRV.ELF";
/// The benchmark's server image. Same reasoning as `TASK_EPSRV_IMAGE`: the
/// role is the permission, the permission comes from the row, so the server
/// is its own image.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_VSSRV_IMAGE: &[u8] = b"VSSRV.ELF";

// ── Board service registry — owner decision 2026-09-24 ──────────────────────
//
// `Makefile`'s disk-image ELF list used to be hand-maintained and drifted
// from what the project actually is (robot-shaped, decided before the
// generic-hybrid pivot). The rule now: an ELF ships on a BOARD's FAT32
// volume iff the topology declares a service that ELF provides.
// `tools/gen_board_elfs.rs` (via `tests/host/topology-tests`'s `board_elfs`
// binary) reads this by taking every `TaskSpec` name in `default_minimal()`
// that ends in `.ELF`, built with every topology feature OFF — no board
// Cargo feature turns `cap-refusal-canary`/`ipc-endpoint-canary`/
// `profile-actuation` on (see `Cargo.toml`), so a board build is exactly
// this crate's own default. `EPSRV.ELF`/`VSSRV.ELF` above are correctly
// absent from that list: their own doc comments already say "nothing a
// robot runs".
//
// These three ARE unconditional, unlike EPSRV/VSSRV, because all three are
// real board programs — `CONFIG.INI`'s `autorun=` key picks exactly ONE of
// them to actually run at flash/boot time, so a fielded device can be
// reassigned a role by editing that key alone, without rebuilding or
// reflashing any binary. All three therefore belong on the volume
// regardless of which one is currently configured.
//
// **These rows carry no capabilities of their own, on purpose.** The kernel
// does not resolve the autorun task's capabilities by image name — it looks
// up the single generic `TASK_AUTORUN` row above (`find_task(b"autorun")`,
// `kernel/src/tasks/loader.rs`), which is RFC-0003 P1 migration debt this crate
// cannot close alone (that lookup is kernel code, out of this task's file
// ownership). So the actual grant a running `GPIODRV.ELF`/`REFLEX.ELF`/
// `BRAINCLI.ELF` gets still comes from `autorun`'s cap list above, no matter
// which of the three is configured. Putting a copy of those same grants here
// too would be the exact "a copied list drifts" failure this registry exists
// to end — two places asserting the same authority, one of them unread by
// anything.
//
// **Their class and priority ARE applied (wave 7).** The autorun loader and
// `SYS_SPAWN` look a program's scheduling row up by its IMAGE name first and
// fall back to `autorun` only when the image has no row, so each of these
// three runs as `best_effort`, priority 0 clamped to 24. Capabilities still
// come from `autorun` alone, as above.
const TASK_GPIODRV_IMAGE: &[u8] = b"GPIODRV.ELF";
const TASK_REFLEX_IMAGE: &[u8] = b"REFLEX.ELF";
const TASK_BRAINCLI_IMAGE: &[u8] = b"BRAINCLI.ELF";

/// The ring-3 ML inference service. Unlike the three rows above it is NOT an
/// `autorun` choice: the kernel's behavior task spawns it on every boot with
/// ML enabled (`kernel/src/behavior_ml.rs`), through the same path as
/// `SYS_SPAWN`, so its capabilities come from THIS row, by image name.
const TASK_MLSRV_IMAGE: &[u8] = b"MLSRV.ELF";

// Wave 9 (DRV1): the ring-3 buzzer and INA219 drivers (RFC-0040 rule 3).
// Unlike the three rows above, these rows DO carry capabilities, and they are
// read: the kernel starts every row with `start = true` with `SYS_SPAWN`'s
// machinery (`ring3_driver_launch_task`), which seeds a child from the row
// named after its IMAGE. `start` is set only under `ring3-driver-start`
// (QEMU; see `crates/core/topology/Cargo.toml`). Each holds exactly what its
// device needs: the right to register as that one driver kind, and the one
// PWM channel or I2C slave behind it.
/// The buzzer ring-3 host's image, the name of its row.
pub const TASK_BUZZDRV_IMAGE: &[u8] = b"BUZZDRV.ELF";
/// Wave 12 (DRVPLACE): does this topology declare the buzzer's ring-3 host
/// (`BUZZDRV.ELF`)? Only when the driver is placed in ring 3, Kconfig
/// `DRV_BUZZER_PLACEMENT`'s default; feature `buzzer-kernel` drops the row.
/// The kernel asserts this against the drivers crate's placement, as for
/// [`INADRV_ROW`].
pub const BUZZDRV_ROW: bool = cfg!(not(feature = "buzzer-kernel"));
/// The INA219 ring-3 host's image, the name of its row.
pub const TASK_INADRV_IMAGE: &[u8] = b"INADRV.ELF";
/// Wave 11 (DRVPLACE): does this topology declare the INA219's ring-3 host
/// (`INADRV.ELF`)? Only when the driver is placed in ring 3, Kconfig
/// `DRV_INA219_PLACEMENT`'s default; feature `ina219-kernel` (the kernel
/// placement) drops the row. The kernel asserts this against the drivers
/// crate's placement, so the two cannot disagree in a build that links.
/// `ina219-placement-canary` keeps the row under the kernel placement (and
/// the kernel skips its assertion): the gate row must then fail.
pub const INADRV_ROW: bool =
    cfg!(any(not(feature = "ina219-kernel"), feature = "ina219-placement-canary"));
/// `DRV_KIND_BUZZER` (0x0010) in decimal; `tests/host/topology-tests` holds the
/// two equal, as for `drv.1`.
const RESOURCE_DRV_BUZZER: &[u8] = b"drv.16";
/// `DRV_KIND_POWER_MON` (0x0011) in decimal.
const RESOURCE_DRV_POWER_MON: &[u8] = b"drv.17";
/// Wave 11 (SHMRING): the kernel sensor streams (`crates/core/ipc/src/stream_ring.rs`).
const RESOURCE_STREAM_LIDAR: &[u8] = b"stream.lidar";
const RESOURCE_STREAM_CAMERA: &[u8] = b"stream.camera";
/// Room for the autorun row's grants: its fixed list (feature-dependent) plus
/// the two streams.
const AUTORUN_CAPS_MAX: usize = 40;
/// The buzzer's PWM channel: free of both motors (channels 0 and 1) and of
/// `autorun`'s `pwm.4`.
const RESOURCE_PWM_BUZZER: &[u8] = b"pwm.5";
/// The INA219 at bus 1, address 0x40. READ|WRITE: configuring it is a write
/// to its calibration and config registers. No safety decision reads it
/// (the battery check reads the ADS1115), which is what puts it in ring 3.
const RESOURCE_I2C_INA219: &[u8] = b"bus.1/0x40";
/// Budget of a small ring-3 row (image, stack and page tables, no heap), in
/// topology pages (4 KiB, `memory::TOPOLOGY_PAGE`): 64, i.e. 256 KiB — unless
/// the base page is so large that the row's fixed minimum (a text page, a data
/// page, a stack page and three page-table pages, plus slack: 8 frames) is
/// more. Only an aarch64 64 KiB granule gets there (8 × 64 KiB = 512 KiB);
/// 4 and 16 KiB keep 64.
const RING3_SMALL_ROW_PAGES: u32 = {
    let min_frames: u64 = 8;
    let floor = crate::memory::units_for(min_frames, 1u64 << azos_limits::PAGE_SHIFT);
    if floor > 64 { floor as u32 } else { 64 }
};
/// Frame budget of each driver row: image, stack and page tables, no heap.
const RING3_DRIVER_MEM_PAGES: u32 = RING3_SMALL_ROW_PAGES;

/// The demo endpoint: `epsrv` serves it, the autorun program calls it.
///
/// One name, two roles, decided by the PERMISSION — `READ` serves, `WRITE`
/// calls — which is why no "server" field is needed here. Declaring `READ` on
/// two rows would be declaring two servers for one service and is refused by
/// `endpoint_named_cap`, reported as `SeedOutcome::Refused`.
#[cfg(feature = "ipc-endpoint-canary")]
const RESOURCE_ENDPOINT_DEMO: &[u8] = b"endpoint.demo";

/// The benchmark endpoint: `vssrv` serves it, `vsbench` calls it.
///
/// **Declared AFTER `endpoint.demo`, and that ordering is load-bearing.**
/// `cap_lookup` matches on the object's POOL INDEX, endpoints are created in
/// the order their capabilities are seeded, and ring 3 has no by-name lookup —
/// so `endpoint.demo` is index 0 only because nothing is created before it.
/// `tests/host/topology-tests` asserts that, so reordering these rows fails a
/// topology test instead of making `abitest` call the wrong service.
#[cfg(feature = "ipc-endpoint-canary")]
const RESOURCE_ENDPOINT_BENCH: &[u8] = b"endpoint.bench";

const RESOURCE_ESTOP: &[u8] = b"/safety/estop";
const RESOURCE_BRAIN: &[u8] = b"/brain/control";
// Matches the legacy `HandleKind::Motor(0)`/`Motor(1)` RW grant the autorun
// seed already makes (`kernel/src/tasks/loader.rs`) — dual-mode migration, both
// paths grant identical authority. `motor.N` is the RFC-0005 target
// convention (see `rfcs/RFC-0005-static-topology.md`'s worked example).
//
// Behind `profile-actuation` since 2026-09-21: a drivetrain is what a
// deployment has, not what a kernel has. See that feature in `Cargo.toml`.
#[cfg(feature = "profile-actuation")]
const RESOURCE_MOTOR_0: &[u8] = b"motor.0";
#[cfg(feature = "profile-actuation")]
const RESOURCE_MOTOR_1: &[u8] = b"motor.1";
// Matches the legacy `HandleKind::DriverRegistry(DRV_KIND_GPIO)` RW grant the
// autorun seed already makes. `1` is `azos_driver_server::DRV_KIND_GPIO`
// (0x0001) written in decimal, per the `drv.<kind>` target convention in
// `crates/core/ipc/src/cap_seed.rs`. This crate has no dependency on
// `driver_server` — parsing static configuration must not pull in the
// registry — so the number is a literal here and the two are held together by
// `tests/host/topology-tests`, which asserts them equal.
const RESOURCE_DRV_GPIO: &[u8] = b"drv.1";
/// `DRV_KIND_ML` (0x0012) in decimal: the ML service's registration right.
const RESOURCE_DRV_ML: &[u8] = b"drv.18";

// ── The three hardware families, granted per RESOURCE ────────────────────
//
// Until 2026-09-10 no ring-3 task was granted Gpio, I2c or Pwm at all, so the
// eleven typed syscalls behind them had no possible caller and the guards that
// protect the drivetrain from them had no exercise on a booted machine. Named
// resources, never a family in bulk: a grant is authority over one pin, one
// channel, one slave.
//
// `pwm.4` and `gpio.20` are free: motor 0 drives PWM channel 0 with direction
// pins 0 and 1, motor 1 channel 1 with pins 2 and 3 (`robot::robot_init`), and
// pins 13-15 carry the sensor-bus flags.
const RESOURCE_PWM_FREE:   &[u8] = b"pwm.4";
const RESOURCE_GPIO_FREE:  &[u8] = b"gpio.20";
// The simulated MPU-6050 (`i2c.rs` registers it at bus 0, address 0x68).
// Granted READ only — see the CapSpec below for why write access to this one
// address is a safety matter and not a convenience.
const RESOURCE_I2C_IMU:    &[u8] = b"bus.0/0x68";
// U06-9 (2026-09-26): the brain-link PSK, one per board. Bare kind name —
// `cap_seed::seed_one_cap_outcome`'s `CapKind::LinkKey` arm refuses any
// other target string rather than minting the singleton under a name that
// looks like it selected something.
const RESOURCE_LINK_KEY:   &[u8] = b"linkkey";
// Wave 9 (P9): read access to the kernel entropy pool. Bare kind name, same
// rule as `RESOURCE_LINK_KEY`.
const RESOURCE_ENTROPY:    &[u8] = b"entropy";

// AND THE TWO THAT MUST BE REFUSED AT USE — `cap-refusal-canary` ONLY.
//
// `pwm.0` is motor 0's duty channel and `gpio.0` is one of its direction pins.
// The kernel refuses both regardless of the capability —
// `pwm_channel_is_motor_bound` and `gpio_pin_is_motor_bound` in
// `crates/core/syscall/src/handlers.rs` — because reaching the H-bridge below
// `motor_set` bypasses the e-stop latch and the motor envelope together.
//
// That refusal was unreachable while nothing granted these, and the guard's
// own comment said so: "no caller today is the property that changes the first
// time someone declares a PWM cap". This is that declaration. Holding the
// capability and still being refused is the assertion; without the grant, a
// deleted guard would look exactly like a missing capability.
//
// **BEHIND A FEATURE SINCE 2026-09-11, and the feature is the point.** These
// two exist to make a REFUSAL observable, which is a property of the test
// suite, not of a robot. Left unconditional they were production topology: on
// a board, `autorun` held a capability naming motor 0's duty channel and one
// of its direction pins, and the only thing between that capability and the
// H-bridge was an `if` in a syscall handler. Defence in depth means the
// capability does not exist outside the build that asserts its refusal — the
// guard stays exactly as it is and keeps being the tested layer, and the grant
// stops being a standing authority nobody needs.
//
// `qemu` turns the feature on (`kernel/Cargo.toml`), so `userspace: capabilities`
// still mints them and still watches them be refused. `vf2`, `k1` and the
// default build do not.
#[cfg(feature = "cap-refusal-canary")]
const RESOURCE_PWM_MOTOR:  &[u8] = b"pwm.0";
#[cfg(feature = "cap-refusal-canary")]
const RESOURCE_GPIO_MOTOR: &[u8] = b"gpio.0";
// `mmio.0`, READ: index 0 of QEMU `virt`'s MMIO region table, the read-only
// goldfish RTC (`crates/drivers/base/src/platform.rs`, RFC-0043). `userspace/tests/captest`
// maps and reads it, and is refused WRITE on it. Behind the same feature as the
// two above: an index names a region of one board's table, and the board
// tables are empty, so a board topology has nothing to grant.
#[cfg(feature = "cap-refusal-canary")]
const RESOURCE_MMIO_RTC: &[u8] = b"mmio.0";
// QEMU `virt` kernels only: the board RTC again, writable (`mmio.2`), and its
// interrupt line, so `userspace/tests/captest` can raise an interrupt from ring 3,
// bind it, and prove it is delivered and re-armed only by its ACK. aarch64
// (wave 8): the PL031, `irq.34` (SPI 2). riscv64 (wave 9 IRQ4): the goldfish
// RTC, `irq.11` (PLIC/APLIC source 11). `topo_bare` / `topo_arch_*` (set by
// `build.rs`: a kernel target, or the emitter's `emit-target-*` feature):
// `tests/host/topology-tests` builds this crate for `aarch64-apple-darwin` with
// `cap-refusal-canary` on, and must keep seeing the host-shaped topology.
#[cfg(all(feature = "cap-refusal-canary", topo_bare))]
const RESOURCE_MMIO_RTC_RW: &[u8] = b"mmio.2";
#[cfg(all(feature = "cap-refusal-canary", topo_arch_aarch64))]
const RESOURCE_IRQ_RTC: &[u8] = b"irq.34";
// `disk.part.1`, READ|WRITE (RFC-0048 P3, wave 9): partition 1 of the table
// the kernel published — on the gate's partitioned image
// (`build/disk-parted.img`) a 64-sector raw partition after the FAT32 one — so
// `userspace/tests/captest` can write inside it and be refused one sector past it
// (`disk: partition cap refused from ring 3`). Behind its own feature, wired to
// nothing but that row's kernel build: a partition index names a sector range
// of one medium, and on any other image this grant either does not mint (no
// table: every other QEMU image is a bare FAT32 medium) or would name a range
// nobody chose.
#[cfg(feature = "disk-part-row")]
const RESOURCE_DISK_PART1: &[u8] = b"disk.part.1";
// `disk.part.0`, READ only (wave 10): the FAT32 volume of the same image. With
// it the row's task holds TWO readable partitions, so a read through the
// sentinel selector is refused as ambiguous and each read names its partition
// by handle — the disk calls' partition argument (owner decision), end to end.
#[cfg(feature = "disk-part-row")]
const RESOURCE_DISK_PART0: &[u8] = b"disk.part.0";
// Directory trees ring 3 may change (wave 10: mkdir, unlink, rmdir, rename and
// truncate need a `Cap<File>` WRITE tree covering the path). QEMU only, for
// `userspace/tests/captest`: `/fat`, the FAT32 volume, and `/tmp`, the ramfs
// directory its positive mkdir/rmdir use. A board topology grants no tree:
// nothing in ring 3 there changes the tree, and a grant is authority.
#[cfg(feature = "cap-refusal-canary")]
const RESOURCE_TREE_FAT: &[u8] = b"/fat";
#[cfg(feature = "cap-refusal-canary")]
const RESOURCE_TREE_TMP: &[u8] = b"/tmp";

#[cfg(all(feature = "cap-refusal-canary", topo_arch_riscv64))]
const RESOURCE_IRQ_RTC: &[u8] = b"irq.11";
// A line the capability range admits and QEMU `virt`'s interrupt controller
// does not implement, so `userspace/tests/captest` can see a bind of it refused with
// `-ENODEV` and nothing left bound (wave 10 IRQ5). riscv64: source 100 — the
// PLIC has 1..=95 (`riscv,ndev = <0x5f>`), the APLIC 1..=96
// (`riscv,num-sources = <0x60>`), the capability range is 1..128. aarch64:
// SPI 1000 — the capability range is 32..=1019, the GICv3 distributor's
// `ITLinesNumber` stops far below it.
#[cfg(all(feature = "cap-refusal-canary", topo_arch_riscv64))]
const RESOURCE_IRQ_ABSENT: &[u8] = b"irq.100";
#[cfg(all(feature = "cap-refusal-canary", topo_arch_aarch64))]
const RESOURCE_IRQ_ABSENT: &[u8] = b"irq.1000";
// Any other bare-metal ISA (the x86_64 skeleton): the CMOS RTC is legacy
// IRQ 8; an IOAPIC has 24 inputs, so 1000 is absent. Placeholders until the
// port's topology rows exist (build.rs emits no topo_arch_* for it).
#[cfg(all(feature = "cap-refusal-canary", topo_bare, not(any(topo_arch_riscv64, topo_arch_aarch64))))]
const RESOURCE_IRQ_RTC: &[u8] = b"irq.8";
#[cfg(all(feature = "cap-refusal-canary", topo_bare, not(any(topo_arch_riscv64, topo_arch_aarch64))))]
const RESOURCE_IRQ_ABSENT: &[u8] = b"irq.1000";
// The ten sensor types the legacy autorun seed already grants RO
// (`kernel/src/tasks/loader.rs`, `HandleKind::Sensor(st)` for st in 0..=9). Declared
// here so the typed mint comes from the topology rather than being hard-coded
// in the kernel a second time — the same dual-mode shape as the motors.
//
// **All ten, matching the legacy grant exactly, and the first draft of this
// declared only two.** The argument for narrowing was that a default topology
// should not hand ring 3 every sensor. It does not survive contact with what
// dual mode means: the legacy path grants all ten RO on the same boot, so a
// shorter typed list restricts NOTHING — it only makes the typed path
// unusable for the sensors it omits, which forces a migrated program back
// onto the untyped one. Narrowing has to happen on both paths at once or it
// is theatre.
//
// (The draft also justified the two by "the ones a ring-3 program actually
// reads". That was false: `userspace/` reads types 0, 1, 2, 3, 4 and 7.)
const RESOURCE_SENSORS: [&[u8]; 10] = [
    b"sensor.0", b"sensor.1", b"sensor.2", b"sensor.3", b"sensor.4",
    b"sensor.5", b"sensor.6", b"sensor.7", b"sensor.8", b"sensor.9",
];

/// The energy model the `energy-smoke` QEMU row boots with (`-smp 2`): a
/// "little" CPU 0 and a "big" CPU 1. Invented numbers; they only have to be a
/// model `EnergyModel::validate` accepts on two CPUs. The row checks that the
/// kernel reports exactly this (2 domains, 3 + 4 OPPs, 2 + 1 idle states).
#[cfg(all(feature = "energy-fake-model", not(feature = "energy-fake-balanced")))]
pub const FAKE_ENERGY_MODEL: &[u8] = br#"
[energy]
mode = "performance"

[energy.domain.little]
cpus = 1
opps = [
  { freq_khz = 400000, capacity = 160, power_mw = 30 },
  { freq_khz = 800000, capacity = 320, power_mw = 90 },
  { freq_khz = 1200000, capacity = 480, power_mw = 190 },
]
idle = [
  { name = "wfi", exit_latency_us = 1, target_residency_us = 1, power_mw = 8 },
  { name = "retention", exit_latency_us = 120, target_residency_us = 500, power_mw = 2 },
]

[energy.domain.big]
cpus = 2
opps = [ { freq_khz = 500000, capacity = 256, power_mw = 120 }, { freq_khz = 1000000, capacity = 512, power_mw = 300 },
  { freq_khz = 1500000, capacity = 768, power_mw = 600 },
  { freq_khz = 2000000, capacity = 1024, power_mw = 1100 } ]
idle = [ { name = "wfi", exit_latency_us = 1, target_residency_us = 1 } ]
"#;

/// The `energy-gov-smoke` row's model (RFC-0051 E3/E4): the same domains
/// in `balanced` mode, so `Seams::select` takes the `DeadlineFloor` governor
/// and the TEO-like idle governor, with a WCET reference clock per domain
/// (invariant I6: OPP 1 of each is the floor) and a `retention` state on the
/// big domain too (the E4 checks run on CPU 1).
#[cfg(feature = "energy-fake-balanced")]
pub const FAKE_ENERGY_MODEL: &[u8] = br#"
[energy]
mode = "balanced"

[energy.domain.little]
cpus = 1
wcet_ref_khz = 800000
opps = [
  { freq_khz = 400000, capacity = 160, power_mw = 30 },
  { freq_khz = 800000, capacity = 320, power_mw = 90 },
  { freq_khz = 1200000, capacity = 480, power_mw = 190 },
]
idle = [
  { name = "wfi", exit_latency_us = 1, target_residency_us = 1, power_mw = 8 },
  { name = "retention", exit_latency_us = 120, target_residency_us = 500, power_mw = 2 },
]

[energy.domain.big]
cpus = 2
wcet_ref_khz = 1000000
opps = [ { freq_khz = 500000, capacity = 256, power_mw = 120 }, { freq_khz = 1000000, capacity = 512, power_mw = 300 },
  { freq_khz = 1500000, capacity = 768, power_mw = 600 },
  { freq_khz = 2000000, capacity = 1024, power_mw = 1100 } ]
idle = [ { name = "wfi", exit_latency_us = 1, target_residency_us = 1 },
  { name = "retention", exit_latency_us = 120, target_residency_us = 500 } ]
"#;

/// Build the default minimal topology.
///
/// Five RFC-0004 scheduler classes + two seed tasks (`supervisor`,
/// `brain_link`). Budgets sum to **100 %** so admission_check passes.
///
/// All borrowed strings are `'static` literals declared above; the
/// returned `Topology<'static>` can be parked in a static slot.
pub fn default_minimal() -> Topology<'static> {
    let mut topo = Topology::empty();
    fill_default_minimal(&mut topo);
    topo
}

/// Write the default minimal topology into `topo`, which must be empty.
///
/// The kernel installs it with `state::init_with(fill_default_minimal)`,
/// straight into the static slot: a `Topology` is sized by the limits and is
/// megabytes on the fleet profile, more than the boot stack holds.
pub fn fill_default_minimal(topo: &mut Topology<'static>) {
    // Five classes — RFC-0004 default budgets, summing to exactly 100 %.
    let classes = [
        (
            NAME_SAFETY,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_SAFETY),
                cpu_budget_min_pct: 20,
                cpu_budget_max_pct: 100,
                policy: PolicyKind::Edf,
                priority_range: (0, 7),
                preemption: Preemption::Always,
                time_slice_ms: 0,
                admission_control: true,
            },
        ),
        (
            NAME_HARD_RT,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_HARD_RT),
                cpu_budget_min_pct: 30,
                cpu_budget_max_pct: 60,
                policy: PolicyKind::Edf,
                priority_range: (8, 15),
                preemption: Preemption::Always,
                time_slice_ms: 0,
                admission_control: true,
            },
        ),
        (
            NAME_SOFT_RT,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_SOFT_RT),
                cpu_budget_min_pct: 25,
                cpu_budget_max_pct: 60,
                policy: PolicyKind::Rr,
                priority_range: (16, 23),
                preemption: Preemption::TimerOnly,
                time_slice_ms: 10,
                admission_control: false,
            },
        ),
        (
            NAME_BEST_EFFORT,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_BEST_EFFORT),
                cpu_budget_min_pct: 20,
                cpu_budget_max_pct: 100,
                policy: PolicyKind::Cfs,
                priority_range: (24, 30),
                preemption: Preemption::TimerOnly,
                time_slice_ms: 0,
                admission_control: false,
            },
        ),
        (
            NAME_IDLE,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_IDLE),
                cpu_budget_min_pct: 5,
                cpu_budget_max_pct: 5,
                policy: PolicyKind::Sporadic,
                priority_range: (31, 31),
                preemption: Preemption::Never,
                time_slice_ms: 0,
                admission_control: false,
            },
        ),
    ];

    for (_, c) in classes.iter() {
        topo.push_class(*c)
            .expect("default_minimal_topology: too many classes");
    }

    // Tasks. Two seed tasks: a safety supervisor + the brain-link.
    topo.push_task(
        MaybeStr::from_bytes(TASK_SUPERVISOR),
        MaybeStr::from_bytes(NAME_SAFETY),
        0,
        &[CapSpec {
            kind: CapKind::Channel,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(RESOURCE_ESTOP), transfer: false,
        }],
    )
    .expect("default_minimal_topology: supervisor push failed");

    topo.push_task(
        MaybeStr::from_bytes(TASK_BRAIN_LINK),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        0,
        &[CapSpec {
            kind: CapKind::Channel,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(RESOURCE_BRAIN), transfer: false,
        }],
    )
    .expect("default_minimal_topology: brain_link push failed");

    // P1 migration seed for the autorun task: Motor(0)/Motor(1) RW, the GPIO
    // driver registration, the free PWM channel and GPIO pin, the IMU READ,
    // and the legacy autorun seed's ten Sensor(0..=9) READ grants. Every kind
    // declared here has a typed minter in `crates/core/ipc/src/cap_seed.rs`
    // (`seed_one_cap`); a kind without one would document a capability the
    // bridge can never mint — see that file's gap list.
    //
    // **`soft_rt` at 16, not `hard_rt` at 0 (wave 7).** This row's class was
    // never applied until wave 7, so `hard_rt`/0 described nothing that ran.
    // Applied literally it clamps to 8: inside the band the tick never
    // preempts (`RT_PRIORITY_THRESHOLD` = 12) and above `net-poll` (12) and
    // `sys-wdt` (11). That is the configuration `kernel/src/main.rs` records
    // (above `AUTORUN_PRIORITY`) as having starved `net-poll` off hart 3 and
    // killed the brain link — the `userspace: the brain lies` row fails if it
    // comes back. Every image without a row of its own (VSBENCH, ABITEST,
    // CAPTEST, IPCTEST, UHELLO…) runs under this one, so it states what they
    // have always run at: 16, the scheduler's default.
    let autorun_base: &[CapSpec] = &[
            // The drivetrain, and ONLY under `profile-actuation`. Without it
            // this row grants no way to move anything — the point of the
            // generic-microkernel pivot. `require_pair_write` still demands
            // WRITE on both, so a half-declared drivetrain is refused rather
            // than half-actuated. Under `flight-tool-drivetrain` (a gate
            // feature, wave 12) the drivetrain is `FLIGHT.ELF`'s instead:
            // one writer per motor (`motor_write_conflict`).
            #[cfg(all(feature = "profile-actuation", not(feature = "flight-tool-drivetrain")))]
            CapSpec {
                kind: CapKind::Motor,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_MOTOR_0), transfer: false,
        },
            #[cfg(all(feature = "profile-actuation", not(feature = "flight-tool-drivetrain")))]
            CapSpec {
                kind: CapKind::Motor,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_MOTOR_1), transfer: false,
        },
            // The right to register as the GPIO driver, and only that one —
            // the `userspace: ring-3 GPIO driver` scenario is a ring-3
            // program that legitimately registers. Declared here so the typed
            // mint comes from the topology rather than being hard-coded in
            // the kernel a second time, which is the whole point of the P1
            // bridge.
            CapSpec {
                kind: CapKind::DriverRegistry,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DRV_GPIO), transfer: false,
        },
            // The three hardware families — see the resource constants above
            // for why each target was chosen, and why the two motor-bound ones
            // are declared only under `cap-refusal-canary`.
            CapSpec {
                kind: CapKind::Pwm,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_FREE), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Pwm,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_MOTOR), transfer: false,
        },
            CapSpec {
                kind: CapKind::Gpio,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_FREE), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Gpio,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_MOTOR), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::MmioRegion,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RTC), transfer: false,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::MmioRegion,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RTC_RW), transfer: false,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Disk,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART1), transfer: false,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Disk,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART0), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::File,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_FAT), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::File,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_TMP), transfer: false,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Irq,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_RTC), transfer: false,
        },
            // READ, not RW — 2026-09-11. The same argument the sensor grants
            // below already make, applied to the one device where getting it
            // wrong is a safety property rather than a privacy one.
            //
            // `bus.0/0x68` is the MPU-6050, and it is what feeds
            // `behavior::safety::check_common`'s Falling, Spinning and tilt
            // checks — the L0 reflexes. A WRITE authority over it is the
            // authority to put the IMU to sleep (`PWR_MGMT_1`) or reset it,
            // which does not trip any alarm: the safety layer keeps reading,
            // gets a quiet device, and stops seeing the robot fall over.
            // Blinding the reflex layer is a strictly better attack than
            // commanding the motors, which the actuation gate refuses.
            //
            // Nothing loses anything: `i2c_read_cap` and `i2c_detect_cap` both
            // take `CapPerms::READ`, and `i2c_read_cap` carries the register
            // number as an argument — the register-pointer write happens
            // inside the driver, below the capability check. `userspace/tests/captest`
            // only detects and reads. The legacy untyped path grants no
            // `HandleKind::I2c` at all, so this is the whole of ring 3's I2C
            // authority and narrowing it is not theatre.
            CapSpec {
                kind: CapKind::I2c,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_I2C_IMU), transfer: false,
        },
            // READ only: the legacy seed grants these `HandlePerms::RO` and a
            // sensor read is a read. Granting WRITE would make the typed path
            // carry authority the untyped one never had.
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[0]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[1]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[2]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[3]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[4]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[5]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[6]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[7]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[8]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Sensor,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[9]), transfer: false,
        },
            // U06-9 (2026-09-26): the ring-3 door onto the reserved-sector
            // brain-link PSK (`SYS_LINK_KEY_READ_TYPED`). `brain_client` is
            // the one holder that reads it; every other autorun program
            // (`GPIODRV.ELF`/`REFLEX.ELF`) simply never calls the syscall
            // this grants no more authority to use than
            // `SYS_FILE_OPEN_TYPED` already gave them over the rest of
            // `/fat`. READ only — there is no write path, the key is
            // provisioned at image-build time, never by a running task.
            CapSpec {
                kind: CapKind::LinkKey,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_LINK_KEY), transfer: false,
        },
            // Wave 9 (P9): `SYS_ENTROPY_READ_TYPED`, the source of
            // `brain_client`'s ephemeral handshake keys. Like the link key,
            // the kernel withholds it from any image whose seccomp row does
            // not list the call (`kernel/src/tasks/loader.rs` autorun seeding), so
            // this row does not decide alone who gets it. READ only, never
            // transferable.
            CapSpec {
                kind: CapKind::Entropy,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false,
        },
            // RFC-0040 gap 2: the CALLER half of the demo endpoint. `WRITE` is
            // "may send a request", and nothing more — it claims no service
            // and cannot destroy one.
            #[cfg(feature = "ipc-endpoint-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DEMO), transfer: false,
        },
            // AFTER the demo endpoint, never before — see
            // `RESOURCE_ENDPOINT_BENCH` for what depends on that.
            #[cfg(feature = "ipc-endpoint-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BENCH), transfer: false,
        },
            // Last, so no earlier grant changes slot (wave 10 IRQ5).
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Irq,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_ABSENT), transfer: false,
        },
    ];
    // Wave 11 (SHMRING): the kernel sensor streams, appended after every
    // other grant (no earlier slot moves) and only when the stream is
    // configured in. Owner decision 2026-10-03: THIS row is the authority to
    // read the stream — holding the `Cap<Shm>` replaces the per-frame check
    // `SYS_SENSOR_READ_TYPED` makes (`crates/core/ipc/src/stream_ring.rs`).
    // READ|WRITE because the consumer stores its tail and wait flag in the
    // region; never DUP.
    let mut autorun_caps = [CapSpec::empty(); AUTORUN_CAPS_MAX];
    autorun_caps[..autorun_base.len()].copy_from_slice(autorun_base);
    let mut n = autorun_base.len();
    for (on, target) in [
        (azos_limits::STREAM_LIDAR_RING, RESOURCE_STREAM_LIDAR),
        (azos_limits::STREAM_CAMERA_RING, RESOURCE_STREAM_CAMERA),
    ] {
        if on {
            autorun_caps[n] = CapSpec {
                kind: CapKind::Shm,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(target), transfer: false,
            };
            n += 1;
        }
    }
    // Wave 12: `vsbench`'s `spawn+wait` lane starts `TOOLBOX.ELF` (as `true`)
    // through `SYS_SPAWN_EX`, which needs a launch grant on the image. QEMU
    // gate/bench topologies only (`ipc-endpoint-canary`, the feature that
    // already declares the benchmark's server row); after every other grant,
    // so no earlier slot moves. The child runs under TOOLBOX.ELF's own row
    // and profile, which grant it nothing of this row's.
    #[cfg(feature = "ipc-endpoint-canary")]
    {
        autorun_caps[n] = CapSpec {
            kind: CapKind::Launch,
            perms: CapPerms::EXEC,
            target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false,
        };
        n += 1;
    }
    topo.push_task(
        MaybeStr::from_bytes(TASK_AUTORUN),
        MaybeStr::from_bytes(NAME_SOFT_RT),
        16,
        &autorun_caps[..n],
    )
    .expect("default_minimal_topology: autorun push failed");
    // OWNER DECISION 102 — the autorun task's frame budget.
    //
    // 2048 pages = 8 MiB of heap and anonymous memory beyond the ELF image.
    // This row is shared by every ring-3 autorun program in the tree
    // (gpio_drv, abitest, captest, vsbench, reflex...), so it has to clear the
    // hungriest of them.
    //
    // MEASURED 2026-09-20, not guessed: `vsbench` peaks at **512 pages**
    // (2 MiB); `abitest` and `gpio_drv` reach **0** — they never grow the heap
    // at all. So 2048 is four times the observed maximum.
    //
    // The zeros are data rather than a broken instrument, and the reason is
    // the 512 beside them: the first version of that measurement reported 0
    // for all three, because the peak lived on `Task` and every one of these
    // programs exits before anything reads it. Three unlike programs agreeing
    // exactly is the instrument. `mm_peak_global` outlives the task.
    //
    // It is still a real ceiling, and that is the point. Scan unit 3 finding 3
    // was that ONE ring-3 task could walk `brk` until the allocator was empty:
    // the QEMU linker window is 32 MiB total, so a runaway loop took the kernel
    // heap, the copy-on-write break and every allocating safety path with it.
    // 8 MiB stops that while leaving four times the whole arena's worth of
    // headroom over anything observed.
    //
    // **What proves it is not binding anything today:** the gate asserts
    // on the counter — `mm_quota_refusals` must stay 0 across
    // every normal row. The day a program legitimately needs more, that row
    // goes red with the reason on the console instead of the program quietly
    // failing to allocate.
    //
    // Under `mem-quota-canary` the budget drops to 16 pages so a ring-3 probe
    // can reach it cheaply: 2048 would need an 8 MiB allocation to observe a
    // refusal, on a 32 MiB arena, which is a slow way to prove one comparison.
    //
    // RFC-0049 M1 (wave 8): the budget now covers EVERY frame the task holds
    // -- its ELF image, user stack and page tables included, which used to be
    // left out -- and the value is Kconfig's `AUTORUN_MEM_PAGES` (2048 on
    // edge, 256 on embedded, where 2048 x 2 would not be admitted in 16 MiB).
    // The canary's 64 leaves abitest room for its image, stack, tables, shm
    // and io_ring and still refuses a 256-page `brk` far short of it.
    //
    // Wave 9: the row declares no `instances`, so it has the default, 1: one
    // live autorun program. Its fork children are not instances; they live
    // inside the budget and the COW copy memory admission pays for.
    #[cfg(not(feature = "mem-quota-canary"))]
    topo.set_last_task_mem_pages(azos_limits::AUTORUN_MEM_PAGES as u32);
    #[cfg(feature = "mem-quota-canary")]
    topo.set_last_task_mem_pages(64);
    // The io_ring SQ poller is off unless a deployment declares it. Under
    // `sqpoll-bench` the autorun row may start one that parks after 20 ms of
    // an empty queue — what the vsbench SQPOLL lane measures, and nothing a
    // robot boots with.
    #[cfg(feature = "sqpoll-bench")]
    topo.set_last_task_sqpoll_idle_ms(20);


    // The infeasible pair `deadline-refusal-canary` exists to declare. Pushed
    // WITHOUT `.expect`-ing admission: `push_task` only checks structure, and
    // the feasibility refusal is `admission_check`'s, which `init_with` runs.
    #[cfg(feature = "deadline-refusal-canary")]
    for name in [&b"rt_canary_a"[..], &b"rt_canary_b"[..]] {
        topo.push_task_profiled(
            MaybeStr::from_bytes(name),
            MaybeStr::from_bytes(NAME_HARD_RT),
            8,
            &[],
            crate::deadline::SchedProfile { period_us: 10_000, runtime_us: 6_000, deadline_us: 0, cpu_mask: 1 },
        )
        .expect("default_minimal_topology: deadline canary push failed");
        // A band row with a profile must be `mem = "locked"` (wave 11), or the
        // refusal would be that one instead of the infeasibility tested here.
        topo.set_last_task_mem_pages(16);
        topo.set_last_task_mem_locked(true);
    }

    #[cfg(feature = "deadline-hart-canary")]
    topo.push_task_profiled(
        MaybeStr::from_bytes(b"rt_canary_far"),
        MaybeStr::from_bytes(NAME_HARD_RT),
        8,
        &[],
        crate::deadline::SchedProfile { period_us: 10_000, runtime_us: 1_000, deadline_us: 0, cpu_mask: 1 << 3 },
    )
    .expect("default_minimal_topology: hart canary push failed");
    // Locked, as every profiled band row must be (wave 11): see above.
    #[cfg(feature = "deadline-hart-canary")]
    {
        topo.set_last_task_mem_pages(16);
        topo.set_last_task_mem_locked(true);
    }

    // Wave 11 SCHED-RT rows: the two reservations the `edf` check of
    // `kernel/src/rt_smoke.rs` runs on, declared here so boot admission places
    // them (CPU 0, band, 75 % of it) and the kernel tasks named after them
    // attach to the placement (`topo_sched::row_reservation`).
    #[cfg(feature = "sched-rt-smoke")]
    for (name, profile) in [
        (&b"rt-edf-a"[..], crate::deadline::SchedProfile { period_us: 10_000, runtime_us: 1_500, deadline_us: 3_000, cpu_mask: 1 }),
        (&b"rt-edf-b"[..], crate::deadline::SchedProfile { period_us: 20_000, runtime_us: 5_000, deadline_us: 0, cpu_mask: 1 }),
    ] {
        topo.push_task_profiled(MaybeStr::from_bytes(name), MaybeStr::from_bytes(NAME_SAFETY), 4, &[], profile)
            .expect("default_minimal_topology: SCHED-RT row push failed");
        // A profiled band row must be `mem = "locked"`.
        topo.set_last_task_mem_pages(16);
        topo.set_last_task_mem_locked(true);
    }
    // And a band row WITHOUT a profile: a ring-3 task named after it stays at
    // the ring-3 floor (the `ring3` check).
    #[cfg(feature = "sched-rt-smoke")]
    topo.push_task(MaybeStr::from_bytes(b"rt-r3-noprof"), MaybeStr::from_bytes(NAME_SAFETY), 4, &[])
        .expect("default_minimal_topology: SCHED-RT row push failed");

    topo.set_sched_config(SchedConfig {
        partition_window_us: 10_000,
    });

    // RFC-0051 §9 question 1 (assistant default, owner to confirm): the energy
    // mode is the topology's, and every built-in profile says `performance`,
    // today's behaviour (I4). No model: a board's own topology declares one.
    #[cfg(all(feature = "energy", not(feature = "energy-fake-model")))]
    topo.set_energy(azos_energy::EnergySpec::DEFAULT);
    // The QEMU row's model, through the parser a signed SCHED.TOML takes.
    #[cfg(feature = "energy-fake-model")]
    topo.set_energy(
        crate::parser::parse_energy(FAKE_ENERGY_MODEL)
            .expect("default_minimal_topology: fake energy model does not parse"),
    );

    // Not under the canary: that topology is infeasible on purpose, and a debug
    // build would panic here instead of reaching the refusal being tested.
    #[cfg(not(feature = "deadline-refusal-canary"))]
    debug_assert!(topo.admission_check().is_ok());

    // Pushed LAST on purpose. `the_default_topology_has_one_writer_per_motor`
    // reports a conflict by TASK INDEX, so a row inserted in the middle moves
    // indices that other rows' tests pin and makes an unrelated test fail for
    // a reason that has nothing to do with it.
    //
    // RFC-0040 gap 2: the SERVER half, and the first topology row named after
    // an IMAGE rather than a role. `SYS_SPAWN` looks its child's row up by
    // `profile.image`, so this is the row a spawned `EPSRV.ELF` gets — and
    // the reason a spawned process can now hold any capability at all.
    //
    // `READ` is what claims the endpoint, so the serving side is declared by
    // its permission. The autorun row holds `WRITE` on the same name:
    // one object, two roles, no third field.
    //
    // **It names `EPSRV.ELF` and not `UHELLO.ELF` because this row IS the
    // role.** An image gets one row, so an image that serves only sometimes
    // cannot be expressed — and must not be attempted: the draft that gave
    // `uhello` a serve loop and let it decide at runtime hung as autorun,
    // where it held `WRITE` and accepted anyway. `SYS_IPC_FAST_ACCEPT` blocks
    // and nothing wakes a server nobody calls.
    #[cfg(feature = "ipc-endpoint-canary")]
    topo.push_task(
        MaybeStr::from_bytes(TASK_EPSRV_IMAGE),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        0,
        &[CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::READ,
            target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DEMO), transfer: false,
        }],
    )
    .expect("default_minimal_topology: EPSRV.ELF push failed");

    // RFC-0040 gap 2 stage 4 — the benchmark's server. `vsbench`'s IPC lane
    // used a `fork()`ed child, which can never be addressed by capability: a
    // forked child inherits no capability table and the endpoint's owner is
    // fixed when the capability is SEEDED, by image name. Retiring
    // `SYS_IPC_FAST_CALL` (108) therefore needed the peer to become an image.
    //
    // **`soft_rt` at 16, the client's class and priority (wave 7).** `vsbench`
    // runs under the `autorun` row (16). Declared `best_effort`/0 the server
    // is applied at 24, and the `ipc-roundtrip` lane then measures a
    // cross-bucket hand-off rather than the IPC path: measured with `-icount`,
    // 2277 -> 2403 instructions on aarch64 and 2659 -> 2789 on riscv64
    // (cause not isolated; a likely one: across buckets the direct switch's
    // paired histogram re-account no longer cancels,
    // `ipc_direct::pair_cancels`). Same bucket, the lane is unchanged.
    #[cfg(feature = "ipc-endpoint-canary")]
    topo.push_task(
        MaybeStr::from_bytes(TASK_VSSRV_IMAGE),
        MaybeStr::from_bytes(NAME_SOFT_RT),
        16,
        &[
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BENCH), transfer: false,
            },
            // Wave 11 (SHMRING): `vsbench`'s `drv-call` lane measures the
            // path a ring-3 client has to a ring-3 driver today, and this
            // image is the driver for its span. The power-monitor kind
            // because `SYS_SENSOR_READ_TYPED(sensor.9)` (a capability the
            // autorun row already holds) is a ring-3 call that reaches a
            // `UserDriverProxy`; on a boot where `INADRV.ELF` owns the kind
            // the registration is refused and the lane reports that.
            CapSpec {
                kind: CapKind::DriverRegistry,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DRV_POWER_MON), transfer: false,
            },
        ],
    )
    .expect("default_minimal_topology: VSSRV.ELF push failed");

    // Board service registry rows — see the block comment above
    // `TASK_GPIODRV_IMAGE`. Pushed LAST, after the (feature-gated) IPC
    // canary rows, so a board build (no features) keeps rows 0-2 exactly as
    // they were (supervisor, brain_link, autorun) and these land at 3-5;
    // gate builds with `ipc-endpoint-canary` keep EPSRV.ELF/VSSRV.ELF at
    // 3-4 and these land at 5-7. No existing index-pinned assertion moves.
    topo.push_task(MaybeStr::from_bytes(TASK_GPIODRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, &[])
        .expect("default_minimal_topology: GPIODRV.ELF push failed");
    topo.push_task(MaybeStr::from_bytes(TASK_REFLEX_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, &[])
        .expect("default_minimal_topology: REFLEX.ELF push failed");
    topo.push_task(MaybeStr::from_bytes(TASK_BRAINCLI_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, &[])
        .expect("default_minimal_topology: BRAINCLI.ELF push failed");

    // The ML service (see `TASK_MLSRV_IMAGE`). Pushed after the board rows so
    // no index another test pins moves.
    //
    // `soft_rt` at 16, the scheduler's default, and NOT the behavior task's
    // 14 (`hard_rt`): the service runs at 14 only while the loop is blocked
    // on it, because the proxy donates the loop's priority for that span, and
    // is blocked whenever no cycle is asking. A service that misbehaves
    // outside a call therefore competes at 16, not in the hard-real-time
    // band. The price is a donation per cycle, measured in the `[BSTEP]`
    // figures.
    //
    // Its one capability: register as `DRV_KIND_ML`, and only that kind.
    //
    // 64 pages (256 KiB) of frames: its image, stack and page tables, and two
    // model-file buffers in `.bss`; it never grows a heap.
    topo.push_task(
        MaybeStr::from_bytes(TASK_MLSRV_IMAGE),
        MaybeStr::from_bytes(NAME_SOFT_RT),
        16,
        &[CapSpec {
            kind: CapKind::DriverRegistry,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(RESOURCE_DRV_ML), transfer: false,
        }],
    )
    .expect("default_minimal_topology: MLSRV.ELF push failed");
    topo.set_last_task_mem_pages(RING3_SMALL_ROW_PAGES);

    // Wave 9 (DRV1) — the ring-3 drivers; see `TASK_BUZZDRV_IMAGE`. After the
    // board rows, so no index-pinned row above moves.
    //
    // **`best_effort` (0, clamped to 24), like GPIODRV.ELF** (owner decision
    // 2026-09-28; wave 9 had them at `soft_rt` 16). A client more urgent
    // than the driver donates its priority for the span of each request
    // (`UserDriverProxy`), so a request is served at the client's priority
    // (down to the ring-3 floor, 12). What 24 gives up is the driver's own
    // timing outside a request: a CPU-bound task above 24 on its hart delays
    // the end of a buzzer tone (measured once on aarch64 QEMU at boot: a
    // 50 ms tone switched off after 1578 ms), and delays INA219 samples. The
    // mAh sum no longer depends on that cadence: each sample is weighted by
    // the time the driver measured since the previous one (wave 10).
    // Wave 12 (DRVPLACE): the buzzer's ring-3 host has a row only when the
    // driver is placed in ring 3 ([`BUZZDRV_ROW`]).
    if BUZZDRV_ROW {
        topo.push_task(
            MaybeStr::from_bytes(TASK_BUZZDRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            0,
            &[
                CapSpec {
                    kind: CapKind::DriverRegistry,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_DRV_BUZZER), transfer: false,
                },
                CapSpec {
                    kind: CapKind::Pwm,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_PWM_BUZZER), transfer: false,
                },
            ],
        )
        .expect("default_minimal_topology: BUZZDRV.ELF push failed");
        topo.set_last_task_mem_pages(RING3_DRIVER_MEM_PAGES);
        #[cfg(all(feature = "ring3-driver-start", not(feature = "ring3-driver-start-canary")))]
        topo.set_last_task_start(true);
        // Gate only (`restart-smoke`): `restart = always`, so a clean exit of
        // the buzzer is restarted too.
        #[cfg(feature = "restart-smoke")]
        topo.set_last_task_restart(crate::types::RestartPolicy::Always);
    }
    // Wave 11 (DRVPLACE): the INA219's ring-3 host has a row only when the
    // driver is placed in ring 3 ([`INADRV_ROW`]). Placed in the kernel, the
    // row would be a dormant grant of `Cap<I2c>` on its chip to an image the
    // kernel does not run.
    if INADRV_ROW {
        topo.push_task(
            MaybeStr::from_bytes(TASK_INADRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            0,
            &[
                CapSpec {
                    kind: CapKind::DriverRegistry,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_DRV_POWER_MON), transfer: false,
                },
                CapSpec {
                    kind: CapKind::I2c,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_I2C_INA219), transfer: false,
                },
            ],
        )
        .expect("default_minimal_topology: INADRV.ELF push failed");
        topo.set_last_task_mem_pages(RING3_DRIVER_MEM_PAGES);
        #[cfg(feature = "ring3-driver-start")]
        topo.set_last_task_start(true);
        // Gate only (`restart-smoke`): `restart = no`, so not even a kill
        // of the INA219 driver is restarted.
        #[cfg(feature = "restart-smoke")]
        topo.set_last_task_restart(crate::types::RestartPolicy::No);
    }

    // RFC-0049 M1c gate row: `UHELLO.ELF` as a `mem = "locked"` row. Its
    // image is small, forks nothing and asks for no demand pages, which is
    // what a locked row may run; the row proves the task finishes with zero
    // page faults. Same class and priority as `autorun`, which it ran under
    // before it had a row, so only the memory policy changes.
    #[cfg(feature = "mem-locked-smoke")]
    {
        topo.push_task(MaybeStr::from_bytes(b"UHELLO.ELF"), MaybeStr::from_bytes(NAME_SOFT_RT), 16, &[])
            .expect("default_minimal_topology: UHELLO.ELF push failed");
        topo.set_last_task_mem_pages(64);
        topo.set_last_task_mem_locked(true);
        // Kconfig LOCKED_HUGE_LEAVES gate row: the same locked row with a
        // 4 MiB region mapped by two 2 MiB leaves at exec.
        #[cfg(feature = "huge-leaves-smoke")]
        topo.set_last_task_mem_huge_mib(4);
    }

    // RFC-0049 M1c: a locked row on an image whose seccomp profile may fork
    // (`ABITEST.ELF`, audit mode). The loader must refuse to run it under a
    // locked row.
    #[cfg(feature = "mem-locked-refusal-canary")]
    {
        topo.push_task(MaybeStr::from_bytes(b"ABITEST.ELF"), MaybeStr::from_bytes(NAME_SOFT_RT), 16, &[])
            .expect("default_minimal_topology: ABITEST.ELF push failed");
        topo.set_last_task_mem_pages(2048);
        topo.set_last_task_mem_locked(true);
    }

    // RFC-0049 M1b canary: one ring-3 row whose ceiling alone is 4 GiB, more
    // than any board this builds for. Memory admission must refuse the
    // topology and the kernel must halt before the first ring-3 task.
    #[cfg(feature = "mem-admission-canary")]
    {
        topo.push_task(MaybeStr::from_bytes(b"HOG.ELF"), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, &[])
            .expect("default_minimal_topology: HOG.ELF push failed");
        topo.set_last_task_mem_pages(1 << 20);
    }

    // Owner decision 2026-09-28: `SYS_SPAWN` refuses an image the topology has
    // no row for. `abitest` spawns `UHELLO.ELF` (its `spawn()` conformance
    // check), which until then ran with no row: no capabilities, the default
    // budget, the default priority. This is that row. No capabilities, as
    // before; `soft_rt` at 16, the class and priority of the `autorun` row its
    // parent runs under, so a parent that polls for it does not out-rank it.
    // Under `mem-locked-smoke` the image already has its (locked) row above.
    #[cfg(all(feature = "ipc-endpoint-canary", not(feature = "mem-locked-smoke")))]
    topo.push_task(MaybeStr::from_bytes(b"UHELLO.ELF"), MaybeStr::from_bytes(NAME_SOFT_RT), 16, &[])
        .expect("default_minimal_topology: UHELLO.ELF push failed");

    // RFC-0055 (wave 11): the user shell and its multicall tool image, pushed
    // after every other row (feature-gated ones included) so no index another
    // test pins moves. Unconditional: both are real board programs, so the
    // board volume ships them (`board_elfs`).
    //
    // `SH.ELF` holds no hardware authority: a command's authority is the row
    // of the image that runs it. What it holds is what the shell itself does:
    // the right to start `TOOLBOX.ELF` (`Cap<Launch>`, `SYS_SPAWN_EX` checks
    // it against the image the file's digest resolves to), and the directory
    // trees its redirections and `mkdir`/`rm` change (`/fat` and `/tmp`; only
    // `/tmp` under `CONSOLE_LOCKDOWN`). `start` follows Kconfig `USER_SHELL`;
    // the kernel launches this row after every other `start = true` row.
    //
    // Priorities (lower = more urgent): the shell at the top of `best_effort`
    // (24), every tool it starts below it (26). ^C reaches the shell as an RX
    // interrupt; at a better priority than a CPU-bound tool on its hart the
    // shell is picked at the next tick instead of waiting for the
    // equal-priority round robin to come back to it. A tool never out-ranks
    // its spawner either way (`fork_child_entry` yields until the spawner
    // publishes its hand-off). Gate row `sh: ctrl-c on one hart`.
    topo.push_task(
        MaybeStr::from_bytes(TASK_SH_IMAGE),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        SH_PRIORITY,
        if azos_limits::CONSOLE_LOCKDOWN { SH_CAPS_LOCKDOWN } else { SH_CAPS_UNLOCKED },
    )
    .expect("default_minimal_topology: SH.ELF push failed");
    topo.set_last_task_mem_pages(SH_MEM_PAGES);
    if azos_limits::USER_SHELL {
        topo.set_last_task_start(true);
    }
    // `restart` stays `on-failure` (wave 11): `exit` ends the shell with
    // code 0 and gives the console back to the kernel shell. `always` would
    // restart it instead (owner note, DRVPLACE).
    topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    // The tool image. It reads and writes the descriptors and pipe ends the
    // shell MOVES to it, and opens files read-only, which needs no grant. Its
    // one capability is the full `/proc` task view, for `ps` (wave 12), not
    // under `CONSOLE_LOCKDOWN`.
    topo.push_task(
        MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        TOOL_PRIORITY,
        if azos_limits::CONSOLE_LOCKDOWN { TOOLBOX_CAPS_LOCKDOWN } else { TOOLBOX_CAPS },
    )
        .expect("default_minimal_topology: TOOLBOX.ELF push failed");
    topo.set_last_task_mem_pages(TOOLBOX_MEM_PAGES);
    // A pipeline runs one instance per stage, and background jobs add more.
    topo.set_last_task_instances(TOOLBOX_INSTANCES);
    // RFC-0055 S5, the first privileged family: `POWER.ELF` (`power suspend`,
    // `reboot`, `shutdown`, `sched_hz`). Its row is the whole of its
    // authority: `Cap<Power>` (WRITE, and READ for the rate read), which
    // `SYS_POWER_TYPED` checks on every call. The shell holds only the right to start it, and not under
    // `CONSOLE_LOCKDOWN` (`SH_CAPS_LOCKDOWN`), so a locked-down shell is
    // refused at `SYS_SPAWN_EX`, recorded, not merely missing a PATH entry.
    topo.push_task(MaybeStr::from_bytes(TASK_POWER_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, POWER_CAPS)
        .expect("default_minimal_topology: POWER.ELF push failed");
    topo.set_last_task_mem_pages(POWER_MEM_PAGES);
    // Wave 12: the other privileged families, one tool each, the POWER.ELF
    // pattern: each row is the whole of its tool's authority, checked by its
    // family's typed call on every call, and the shell holds only the right
    // to start them, not under `CONSOLE_LOCKDOWN`.
    for (image, caps) in [
        (TASK_FLIGHT_IMAGE, FLIGHT_CAPS),
        (TASK_BEHAVIOR_IMAGE, FAMILY_POWER_CAPS),
        (TASK_CONFIG_IMAGE, FAMILY_POWER_CAPS),
        (TASK_OTA_IMAGE, FAMILY_POWER_CAPS),
    ] {
        topo.push_task(MaybeStr::from_bytes(image), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, caps)
            .expect("default_minimal_topology: family tool push failed");
        topo.set_last_task_mem_pages(POWER_MEM_PAGES);
    }
    // Wave 15 (TRACE): the tracer's reader, the POWER.ELF pattern. Its row is
    // the whole of its authority: `Cap<Trace>` (READ maps the rings, WRITE
    // sets the class mask), checked by `SYS_TRACE_CTL_TYPED` on every call,
    // and `/fat` read-write for `tracectl stream -o FILE`. The shell holds
    // only the right to start it, not under `CONSOLE_LOCKDOWN`. Pushed after
    // every earlier row, so no index another test pins moves.
    topo.push_task(MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, TRACECTL_CAPS)
        .expect("default_minimal_topology: TRACECTL.ELF push failed");
    topo.set_last_task_mem_pages(TRACECTL_MEM_PAGES);
    topo.set_last_task_instances(TRACECTL_INSTANCES);
    // RFC-0053 L0: the Linux driver server skeleton, only under `lx-server`
    // (Kconfig LINUX_DRIVERS + LX_SERVER_SKELETON). No capability at all: a
    // Linux server never holds an actuator (`Motor`, `Pwm`, `Gpio`, `Estop`),
    // and the skeleton needs nothing else (it opens its module read-only,
    // which needs no grant). `best_effort`: no real-time task may depend on
    // a Linux server (RFC-0053 3). `start = true`, so a volume that carries
    // LXSRV.ELF starts it; only the gate's `build/disk-lx.img` does.
    #[cfg(feature = "lx-server")]
    {
        topo.push_task(MaybeStr::from_bytes(TASK_LXSRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, &[])
            .expect("default_minimal_topology: LXSRV.ELF push failed");
        topo.set_last_task_mem_pages(LXSRV_MEM_PAGES);
        topo.set_last_task_start(true);
    }

    // RFC-0047 (wave 12), gate only (`linux-abi-test`): `LXHELLO.ELF`, a
    // static Linux binary built from `userspace/tests/lxhello/lxhello.c`,
    // run by the shell under the Linux personality. Its row is its whole
    // authority, as for a native image: `/tmp` only, so its
    // `openat(O_CREAT)` under `/fat` is refused by the tree gate and
    // recorded. Under `linux-abi-caps-canary` the row is granted `/fat`
    // read-write, the create succeeds, and the gate row's refusal marker is
    // missing (the canary). Pushed last so no index another test pins moves.
    #[cfg(feature = "linux-abi-test")]
    if LXHELLO_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_LXHELLO_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, LXHELLO_CAPS)
            .expect("default_minimal_topology: LXHELLO.ELF push failed");
        topo.set_last_task_mem_pages(LXHELLO_MEM_PAGES);
        topo.set_last_task_abi(crate::types::TaskAbi::Linux)
            .expect("default_minimal_topology: LXHELLO.ELF is a Linux row with no hardware capability");
    }
    // RFC-0047 stage 3: the third-party `BUSYBOX.ELF` (`make busybox`), a
    // Linux row holding only `/tmp`: its `sh` forks and runs applets under
    // the same row. Wave 13: not gate-only any more. A build whose `.config`
    // says `BUSYBOX` (USERSPACE_GPL + LINUX_ABI, default off) carries this
    // row and the shell's grant to start it, so a deployment that ships
    // BusyBox runs it from the shell; the gate's `linux-busybox-test` adds it
    // to a configuration without the Kconfig option.
    if BUSYBOX_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, BUSYBOX_CAPS)
            .expect("default_minimal_topology: BUSYBOX.ELF push failed");
        topo.set_last_task_mem_pages(BUSYBOX_MEM_PAGES);
        topo.set_last_task_abi(crate::types::TaskAbi::Linux)
            .expect("default_minimal_topology: BUSYBOX.ELF is a Linux row with no hardware capability");
    }
    // Wave 13 (THREADS), gate only (`linux-threads-test`): `LXTHR.ELF`
    // (`make lxthreads`), a static musl program using pthreads, a Linux row
    // holding only `/tmp`. Its frame budget covers four thread stacks
    // (musl maps about 140 KiB each) beside its own image and heap.
    #[cfg(feature = "linux-threads-test")]
    if LXTHR_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_LXTHR_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, &[TMP_RW])
            .expect("default_minimal_topology: LXTHR.ELF push failed");
        topo.set_last_task_mem_pages(LXTHR_MEM_PAGES);
        topo.set_last_task_abi(crate::types::TaskAbi::Linux)
            .expect("default_minimal_topology: LXTHR.ELF is a Linux row with no hardware capability");
    }
}

/// Does the built-in topology carry the `LXTHR.ELF` row? Gate builds
/// (`linux-threads-test`) with the Linux personality (wave 13).
pub const LXTHR_ROW: bool = cfg!(feature = "linux-threads-test") && azos_limits::LINUX_ABI;
/// The image name of the threads test (`make lxthreads`).
#[cfg(feature = "linux-threads-test")]
pub const TASK_LXTHR_IMAGE: &[u8] = b"LXTHR.ELF";
/// Frame budget of `LXTHR.ELF`: a 40 KiB static image, its heap, and up to
/// four 35-page thread stacks at once.
#[cfg(feature = "linux-threads-test")]
const LXTHR_MEM_PAGES: u32 = 384;

/// Does the built-in topology carry the `BUSYBOX.ELF` row? With the Linux
/// personality, when the `.config` says `BUSYBOX` (a deployment that ships
/// it) or the gate asks for it (`linux-busybox-test`).
pub const BUSYBOX_ROW: bool =
    (cfg!(feature = "linux-busybox-test") || azos_limits::BUSYBOX) && azos_limits::LINUX_ABI;

/// The third-party BusyBox image (RFC-0047 stage 3).
pub const TASK_BUSYBOX_IMAGE: &[u8] = b"BUSYBOX.ELF";
/// Frame budget of `BUSYBOX.ELF`: a static image of about 150 KiB, its heap,
/// stack and page tables, and its forked children's copy-on-write breaks.
const BUSYBOX_MEM_PAGES: u32 = 256;
/// `BUSYBOX.ELF`'s authority: `/tmp` read-write. Gate only
/// (`linux-exec-row-test`, wave 13): also `/fat` read-write and the grant to
/// `execve` `LXHELLO.ELF`, whose own row holds only `/tmp`: the exec'd image
/// must lose `/fat` (it runs with its target row's authority).
#[cfg(not(feature = "linux-exec-row-test"))]
const BUSYBOX_CAPS: &[CapSpec] = &[TMP_RW];
#[cfg(feature = "linux-exec-row-test")]
const BUSYBOX_CAPS: &[CapSpec] = &[
    TMP_RW,
    CapSpec { kind: CapKind::File, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"/fat"), transfer: false },
    LXHELLO_LAUNCH,
];

/// Wave 12: the flight tool's image (`flight arm | disarm`).
pub const TASK_FLIGHT_IMAGE: &[u8] = b"FLIGHT.ELF";
/// Wave 12: the behavior tool's image (`behavior status | enable | disable`).
pub const TASK_BEHAVIOR_IMAGE: &[u8] = b"BEHAVIOR.ELF";
/// Wave 12: the config tool's image (`config get | set`).
pub const TASK_CONFIG_IMAGE: &[u8] = b"CONFIG.ELF";
/// Wave 12: the OTA tool's image (`ota status | rollback`).
pub const TASK_OTA_IMAGE: &[u8] = b"OTA.ELF";

/// `FLIGHT.ELF`'s authority. `SYS_FLIGHT_TYPED` checks WRITE on both wheels
/// of the drivetrain (pair-wide, as the console's `flight arm`), and a motor
/// has ONE writer in a topology (`motor_write_conflict`): in this default
/// topology that is the `autorun` row (under `profile-actuation`), so the
/// flight tool holds nothing here and its calls are refused, recorded. A
/// deployment that flies from the operator shell grants the drivetrain to
/// `FLIGHT.ELF` in its signed topology instead of to its autorun program;
/// the gate does exactly that with `flight-tool-drivetrain`.
#[cfg(all(feature = "flight-tool-drivetrain", not(feature = "family-cap-canary")))]
const FLIGHT_CAPS: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Motor,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_0), transfer: false,
    },
    CapSpec {
        kind: CapKind::Motor,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_1), transfer: false,
    },
];
#[cfg(any(not(feature = "flight-tool-drivetrain"), feature = "family-cap-canary"))]
const FLIGHT_CAPS: &[CapSpec] = &[];

/// `BEHAVIOR.ELF`'s, `CONFIG.ELF`'s and `OTA.ELF`'s authority:
/// `Cap<Power>` (WRITE to change, READ to read), as `POWER.ELF`'s. Empty
/// under `family-cap-canary`: every operation is then refused by the
/// capability and recorded (gate row `sh: family tools refused without
/// their capability`).
#[cfg(not(feature = "family-cap-canary"))]
const FAMILY_POWER_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Power,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"power"), transfer: false,
}];
#[cfg(feature = "family-cap-canary")]
const FAMILY_POWER_CAPS: &[CapSpec] = &[];

/// The Linux driver server skeleton's image (RFC-0053 L0).
pub const TASK_LXSRV_IMAGE: &[u8] = b"LXSRV.ELF";
/// Frame budget of `LXSRV.ELF`: image and stack, a 64 KiB module buffer in
/// `.bss`, and the two module regions it maps (a few pages for the test
/// module); since RFC-0053 L1 also the Kbuild modules (LXBASE.KO, XZ_DEC.KO:
/// file copies and regions, about 14 pages), the 96 KiB host-allocator arena
/// and the xz fixture with its 48 KiB output (about 18 pages).
#[cfg(feature = "lx-server")]
const LXSRV_MEM_PAGES: u32 = 128;

/// Does the built-in topology carry the `LXHELLO.ELF` row? Gate builds
/// (`linux-abi-test`) of a kernel with the Linux personality (`LINUX_ABI`).
pub const LXHELLO_ROW: bool = cfg!(feature = "linux-abi-test") && azos_limits::LINUX_ABI;

/// The Linux personality's test image (RFC-0047), gate only.
#[cfg(feature = "linux-abi-test")]
pub const TASK_LXHELLO_IMAGE: &[u8] = b"LXHELLO.ELF";
/// Frame budget of `LXHELLO.ELF`: an 8 KiB image, its stack, a 16 KiB mmap
/// and two pages of brk.
#[cfg(feature = "linux-abi-test")]
const LXHELLO_MEM_PAGES: u32 = 48;
/// `/tmp` read-write (round 48: its fork test writes one inherited file
/// from parent and child); nothing under `/fat`.
#[cfg(all(feature = "linux-abi-test", not(feature = "linux-abi-caps-canary")))]
const LXHELLO_CAPS: &[CapSpec] = &[TMP_RW];
#[cfg(all(feature = "linux-abi-test", feature = "linux-abi-caps-canary"))]
const LXHELLO_CAPS: &[CapSpec] = &[TMP_RW, CapSpec {
    kind: CapKind::File,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat"), transfer: false,
}];
/// The `/tmp` tree, read-write.
const TMP_RW: CapSpec = CapSpec {
    kind: CapKind::File,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/tmp"), transfer: false,
};

/// `SH.ELF`'s authority outside `CONSOLE_LOCKDOWN`: [`SH_CAPS`], plus the
/// right to start `BUSYBOX.ELF` when the topology carries its row
/// ([`BUSYBOX_ROW`], wave 13), plus (gate only, `linux-abi-test`) the right
/// to start `LXHELLO.ELF`.
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_UNLOCKED: &[CapSpec] = if BUSYBOX_ROW { &SH_CAPS_WITH_BUSYBOX } else { SH_CAPS };
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_WITH_BUSYBOX: [CapSpec<'static>; SH_CAPS.len() + 1] = sh_caps_plus(&[BUSYBOX_LAUNCH]);
const BUSYBOX_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Launch,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false,
};
#[cfg(feature = "linux-abi-test")]
const LXHELLO_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Launch,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_LXHELLO_IMAGE), transfer: false,
};
/// Gate builds: the launch grants of the Linux test rows this build carries.
#[cfg(feature = "linux-abi-test")]
const LX_LAUNCHES: &[CapSpec] = &[
    LXHELLO_LAUNCH,
    #[cfg(feature = "linux-busybox-test")]
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false,
    },
    #[cfg(feature = "linux-threads-test")]
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_LXTHR_IMAGE), transfer: false,
    },
];
#[cfg(feature = "linux-abi-test")]
const SH_CAPS_UNLOCKED: &[CapSpec] = if BUSYBOX_ROW && !cfg!(feature = "linux-busybox-test") {
    &SH_CAPS_UNLOCKED_BB
} else {
    &SH_CAPS_UNLOCKED_LX
};
#[cfg(feature = "linux-abi-test")]
const SH_CAPS_UNLOCKED_LX: [CapSpec<'static>; SH_CAPS.len() + LX_LAUNCHES.len()] = sh_caps_plus(LX_LAUNCHES);
/// A `.config` with `BUSYBOX` (a deployment's row, wave 13) in a gate build
/// without `linux-busybox-test`: the gate's grants plus BusyBox's.
#[cfg(feature = "linux-abi-test")]
const SH_CAPS_UNLOCKED_BB: [CapSpec<'static>; SH_CAPS.len() + LX_LAUNCHES.len() + 1] =
    sh_caps_plus2(LX_LAUNCHES, &[BUSYBOX_LAUNCH]);

/// [`SH_CAPS`] followed by `extra`, as one array of exactly that length. It
/// replaced a list that copied `SH_CAPS[0]`, `SH_CAPS[1]`, ... by index,
/// which went stale each time a grant was added to `SH_CAPS` (twice in wave
/// 12).
const fn sh_caps_plus<const N: usize>(extra: &[CapSpec<'static>]) -> [CapSpec<'static>; N] {
    assert!(N == SH_CAPS.len() + extra.len(), "sh_caps_plus: N is SH_CAPS plus extra");
    let mut out = [SH_CAPS[0]; N];
    let mut i = 0;
    while i < SH_CAPS.len() {
        out[i] = SH_CAPS[i];
        i += 1;
    }
    let mut j = 0;
    while j < extra.len() {
        out[SH_CAPS.len() + j] = extra[j];
        j += 1;
    }
    out
}

/// [`sh_caps_plus`] with two lists of extra grants, in order.
#[cfg(feature = "linux-abi-test")]
const fn sh_caps_plus2<const N: usize>(a: &[CapSpec<'static>], b: &[CapSpec<'static>]) -> [CapSpec<'static>; N] {
    assert!(N == SH_CAPS.len() + a.len() + b.len(), "sh_caps_plus2: N is SH_CAPS plus both lists");
    let mut out = [SH_CAPS[0]; N];
    let mut i = 0;
    while i < SH_CAPS.len() {
        out[i] = SH_CAPS[i];
        i += 1;
    }
    let mut j = 0;
    while j < a.len() {
        out[SH_CAPS.len() + j] = a[j];
        j += 1;
    }
    let mut k = 0;
    while k < b.len() {
        out[SH_CAPS.len() + a.len() + k] = b[k];
        k += 1;
    }
    out
}

/// The power tool's image (RFC-0055 S5).
pub const TASK_POWER_IMAGE: &[u8] = b"POWER.ELF";
/// Frame budget of `POWER.ELF`: a small image with no buffers to speak of.
const POWER_MEM_PAGES: u32 = 32;
/// `POWER.ELF`'s authority. Empty under `power-cap-canary`: every operation is
/// then refused by the capability and recorded (gate row `sh: power refused
/// without Cap<Power>`).
#[cfg(not(feature = "power-cap-canary"))]
const POWER_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Power,
    // WRITE for every operation; READ for `power sched_hz` with no argument.
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"power"), transfer: false,
}];
#[cfg(feature = "power-cap-canary")]
const POWER_CAPS: &[CapSpec] = &[];

/// The tracer's reader (wave 15, TRACE).
pub const TASK_TRACECTL_IMAGE: &[u8] = b"TRACECTL.ELF";
/// Frame budget of `TRACECTL.ELF`: image, stack, its record batch and the
/// trace region's mapping (at most `MAX_SHM_PAGES`, 64 pages, booked to the
/// region, not here); 48 pages, as `TOOLBOX.ELF`.
const TRACECTL_MEM_PAGES: u32 = 48;
/// Live `TRACECTL.ELF` instances: the one reader (`stream`, the rings' only
/// consumer) and one controller (`start`/`stop`/`info`, which consume
/// nothing) beside it. Structural, not a tuning knob: a second reader would
/// race the first on every tail.
const TRACECTL_INSTANCES: u16 = 2;
/// `TRACECTL.ELF`'s authority: `Cap<Trace>` read-write, and `/fat`
/// read-write for a trace file. Under `trace-cap-canary` the tracer grant is
/// withheld: every control call is refused by the capability and recorded
/// (gate row `trace: refused without Cap<Trace>`).
#[cfg(not(feature = "trace-cap-canary"))]
const TRACECTL_CAPS: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Trace,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"trace"), transfer: false,
    },
    FAT_RW,
];
#[cfg(feature = "trace-cap-canary")]
const TRACECTL_CAPS: &[CapSpec] = &[FAT_RW];
/// The `/fat` tree, read-write.
const FAT_RW: CapSpec = CapSpec {
    kind: CapKind::File,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat"), transfer: false,
};

/// `SH.ELF`'s priority: the most urgent `best_effort` number. Under
/// `ushell-prio-canary` the two numbers are swapped, so a tool out-ranks the
/// shell and a CPU-bound one starves it on its hart.
#[cfg(not(feature = "ushell-prio-canary"))]
pub const SH_PRIORITY: u8 = 24;
/// See the default build's.
#[cfg(feature = "ushell-prio-canary")]
pub const SH_PRIORITY: u8 = 26;
/// The priority of every tool image the shell starts (`TOOLBOX.ELF`,
/// `POWER.ELF`): below the shell, inside `best_effort`.
#[cfg(not(feature = "ushell-prio-canary"))]
pub const TOOL_PRIORITY: u8 = 26;
/// See the default build's.
#[cfg(feature = "ushell-prio-canary")]
pub const TOOL_PRIORITY: u8 = 24;

/// Live `TOOLBOX.ELF` instances: a four-stage pipeline in the foreground and
/// four more in background jobs.
const TOOLBOX_INSTANCES: u16 = 8;

/// The user shell's image (RFC-0055).
pub const TASK_SH_IMAGE: &[u8] = b"SH.ELF";
/// The multicall tool image the shell's applets run in.
pub const TASK_TOOLBOX_IMAGE: &[u8] = b"TOOLBOX.ELF";
/// Frame budget of `SH.ELF`: image, stack, page tables and its static
/// buffers (history, line, environment); it has no heap.
const SH_MEM_PAGES: u32 = 64;
/// Frame budget of `TOOLBOX.ELF`.
const TOOLBOX_MEM_PAGES: u32 = 48;

const SH_CAPS: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_POWER_IMAGE), transfer: false,
    },
    // Wave 12: the other privileged tools, outside the lockdown only.
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_FLIGHT_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_BEHAVIOR_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_CONFIG_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_OTA_IMAGE), transfer: false,
    },
    // Wave 15 (TRACE): the tracer's reader.
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::File,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/fat"), transfer: false,
    },
    CapSpec {
        kind: CapKind::File,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/tmp"), transfer: false,
    },
    TASK_VIEW_CAP,
];

/// The full `/proc` task view (wave 12, owner round 48): `Cap<Task>` `READ`
/// on `"tasks"`. Without it `/proc/tasks` and `/proc/<tid>` show an image
/// only itself and its descendants (Linux `hidepid=2`). `SH.ELF` and
/// `TOOLBOX.ELF` (`ps`) hold it, and neither under `CONSOLE_LOCKDOWN`, which
/// withholds every grant beyond the shell's own work from the console path
/// (the recovery console's seed is empty there too).
pub const TASK_VIEW_CAP: CapSpec = CapSpec {
    kind: CapKind::Task,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"tasks"), transfer: false,
};

/// `TOOLBOX.ELF`'s authority outside `CONSOLE_LOCKDOWN`: the full task view,
/// for `ps`.
const TOOLBOX_CAPS: &[CapSpec] = &[TASK_VIEW_CAP];
/// Under `CONSOLE_LOCKDOWN`: nothing, as before wave 12.
const TOOLBOX_CAPS_LOCKDOWN: &[CapSpec] = &[];

/// Under `CONSOLE_LOCKDOWN`: the volume is not the shell's to change, and it
/// may not start a privileged tool (no launch grant on `POWER.ELF`).
const SH_CAPS_LOCKDOWN: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Launch,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::File,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/tmp"), transfer: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_minimal_is_well_formed() {
        let topo = default_minimal();
        assert_eq!(topo.classes_len(), 5);
        // supervisor, brain_link, autorun (P1 migration seed), the three
        // unconditional board service rows (GPIODRV.ELF/REFLEX.ELF/
        // BRAINCLI.ELF — see the block comment above `TASK_GPIODRV_IMAGE`),
        // the ML service (MLSRV.ELF) and the two ring-3 driver rows
        // (BUZZDRV.ELF/INADRV.ELF).
        assert_eq!(topo.tasks_len(), 9);
        assert!(topo.admission_check().is_ok());

        // Budgets sum to exactly 100.
        let total: u32 = topo
            .classes()
            .iter()
            .map(|c| c.cpu_budget_min_pct as u32)
            .sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn autorun_task_declares_both_drivetrain_motor_grants() {
        let topo = default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(TASK_AUTORUN))
            .expect("autorun task must be declared for the P1 bridge to seed");
        let caps = topo.caps_of(task);
        // Fixed 2026-09-26 (M40 / audit-flagged stale test): the row this
        // test reads grew, over several commits, to also carry the free
        // PWM channel, the free GPIO pin, the IMU (I2c, READ) and the ten
        // legacy `Sensor(0..=9)` READ grants (see the block comment above
        // `push_task`, which already listed all of these) — 14 entries
        // unconditionally, not 1. This assertion was never executed until
        // `tests/host/topology-tests` made this file's `#[cfg(test)]` module
        // reachable from a host binary (see that crate's own comment), so
        // the drift from "3 / 1" to "16 / 14" went unnoticed. Counting by
        // kind rather than pinning all 14-16 positions individually: the
        // property this test cares about is "the drivetrain, and ONLY the
        // drivetrain, is gated by `profile-actuation`" — everything else
        // present or absent is `cap-refusal-canary`'s concern, tested
        // elsewhere, and pinning its exact interleave here would make this
        // test fail for changes unrelated to what it is named for.
        let motor_count = caps.iter().filter(|c| c.kind == CapKind::Motor).count();
        let non_motor_count = caps.len() - motor_count;
        // Present regardless of `profile-actuation`: DriverRegistry(drv.1),
        // Pwm(free), Gpio(free), I2c(imu), Sensor × 10 = 14 (plus whatever
        // `cap-refusal-canary` adds, not exercised by this test — see
        // `tests/host/topology-tests`' cap-canary run for that half).
        assert_eq!(
            non_motor_count, 14,
            "non-motor grant count drifted — update this test AND check \
             whether the drift was intentional"
        );
        #[cfg(feature = "profile-actuation")]
        {
            assert_eq!(motor_count, 2, "the drivetrain is exactly Motor(0)+Motor(1)");
            assert!(caps.iter().any(|c| c.kind == CapKind::Motor
                && c.perms == CapPerms::RW
                && c.target == MaybeStr::from_bytes(RESOURCE_MOTOR_0)));
            assert!(caps.iter().any(|c| c.kind == CapKind::Motor
                && c.perms == CapPerms::RW
                && c.target == MaybeStr::from_bytes(RESOURCE_MOTOR_1)));
        }
        #[cfg(not(feature = "profile-actuation"))]
        {
            assert_eq!(motor_count, 0, "no motor capability without profile-actuation");
        }
        assert!(caps.iter().any(|c| c.kind == CapKind::DriverRegistry
            && c.perms == CapPerms::RW
            && c.target == MaybeStr::from_bytes(RESOURCE_DRV_GPIO)));
    }

    #[test]
    fn default_minimal_is_static() {
        // Compile-time check: the returned topology has 'static lifetime.
        fn assert_static<T: 'static>(_: &T) {}
        let topo = default_minimal();
        assert_static(&topo);
    }
}
