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

use crate::placement::{Host, PlaceSpec};
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
// `SYS_SPAWN_EX` since RFC-0043 seeded exactly nothing — the mechanism was wired
// and had no data, which printed as `caps minted=0 (skipped 0)` and read like
// "this image declares none". This is the first such row.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_EPSRV_IMAGE: &[u8] = b"EPSRV.ELF";
/// The benchmark's server image. Same reasoning as `TASK_EPSRV_IMAGE`: the
/// role is the permission, the permission comes from the row, so the server
/// is its own image.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_VSSRV_IMAGE: &[u8] = b"VSSRV.ELF";
/// The image `abitest` starts to watch processes live and die (`abichild`:
/// the behaviour is `argv[1]`). Test scaffolding like the two above: a row of
/// its own because a spawned image must have one, no capability but the right
/// to start itself.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_ABICHILD_IMAGE: &[u8] = b"ABICHILD.ELF";
/// The probe image `abitest` and `vsbench` spawn for their conformance and
/// benchmark lanes.
#[cfg(feature = "ipc-endpoint-canary")]
const TASK_UHELLO_IMAGE: &[u8] = b"UHELLO.ELF";

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
// `SYS_SPAWN_EX` look a program's scheduling row up by its IMAGE name first and
// fall back to `autorun` only when the image has no row, so each of these
// three runs as `best_effort`, priority 0 clamped to 24. Capabilities still
// come from `autorun` alone, as above.
const TASK_GPIODRV_IMAGE: &[u8] = b"GPIODRV.ELF";
const TASK_REFLEX_IMAGE: &[u8] = b"REFLEX.ELF";
const TASK_BRAINCLI_IMAGE: &[u8] = b"BRAINCLI.ELF";

/// The ring-3 ML inference service. Unlike the three rows above it is NOT an
/// `autorun` choice: the kernel's behavior task spawns it on every boot with
/// ML enabled (`kernel/src/behavior_ml.rs`), through the same path as
/// `SYS_SPAWN_EX`, so its capabilities come from THIS row, by image name.
const TASK_MLSRV_IMAGE: &[u8] = b"MLSRV.ELF";

// Wave 9 (DRV1): the ring-3 buzzer and INA219 drivers (RFC-0040 rule 3).
// Unlike the three rows above, these rows DO carry capabilities, and they are
// read: the kernel starts every row with `start = true` with `SYS_SPAWN_EX`'s
// machinery (`ring3_driver_launch_task`), which seeds a child from the row
// named after its IMAGE. `start` is set only under `ring3-driver-start`
// (QEMU; see `crates/core/topology/Cargo.toml`). Each holds exactly what its
// device needs: the right to register as that one driver kind, and the one
// PWM channel or I2C slave behind it.
/// The buzzer ring-3 host's image, the name of its row.
pub const TASK_BUZZDRV_IMAGE: &[u8] = b"BUZZDRV.ELF";
/// The host the buzzer starts in: Kconfig `DRV_BUZZER_PLACEMENT`, which the
/// kernel feature `buzzer-kernel` forwards (the kernel host). The row of
/// `BUZZDRV.ELF` exists either way: it is the ring-3 host's authority, which
/// a `stateless` driver needs when it is moved there.
pub const BUZZER_START_HOST: Host =
    if cfg!(feature = "buzzer-kernel") { Host::Kernel } else { Host::Ring3 };
/// The endpoint `BUZZDRV.ELF` serves the `Buzzer` interface on, and the
/// kernel calls it through (`azos_devif::buzzer::ENDPOINT`).
const RESOURCE_ENDPOINT_BUZZER: &[u8] = b"endpoint.buzzer";
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
/// `DRV_KIND_POWER_MON` (0x0011) in decimal.
const RESOURCE_DRV_POWER_MON: &[u8] = b"drv.17";
/// Wave 11 (SHMRING): the kernel sensor streams (`crates/core/ipc/src/stream_ring.rs`).
const RESOURCE_STREAM_LIDAR: &[u8] = b"stream.lidar";
const RESOURCE_STREAM_CAMERA: &[u8] = b"stream.camera";
/// Frame budget of one `ABICHILD.ELF` process: its image, a stack, the pages a
/// mode touches (at most eight of break) and the tables.
#[cfg(feature = "ipc-endpoint-canary")]
const ABICHILD_MEM_PAGES: u32 = 128;
/// Live `ABICHILD.ELF` processes at once: a process tree (`tree`,
/// `subreaper`) holds three, a spawn that follows a child's exit can overlap
/// its teardown.
#[cfg(feature = "ipc-endpoint-canary")]
const ABICHILD_INSTANCES: u16 = 8;
/// Room for the autorun row's grants: its fixed list (feature-dependent) plus
/// the two streams.
const AUTORUN_CAPS_MAX: usize = 40;
/// The buzzer's PWM channel: free of both motors (channels 0 and 1) and of
/// `autorun`'s `pwm.4`.
const RESOURCE_PWM_BUZZER: &[u8] = b"pwm.5";
/// The INA219 at bus 1, address 0x40. READ|WRITE: configuring it is a write
/// to its calibration and config registers. No safety decision reads it
/// (the battery check reads the ADS1115), which is what puts it in ring 3.
const RESOURCE_I2C_INA219: &[u8] = b"i2c.1.0x40";
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
/// `cap_lookup` matches on the object's POOL INDEX, ring 3 has no by-name
/// lookup, and the boot creates every named endpoint in row order before
/// anything is spawned (`kernel/src/boot/topology.rs` `declare_endpoints`) —
/// so `endpoint.demo` is index 0 because it is the first endpoint grant of the
/// rows. `tests/host/topology-tests` asserts that, so reordering these rows
/// fails a topology test instead of making `abitest` call the wrong service.
#[cfg(feature = "ipc-endpoint-canary")]
const RESOURCE_ENDPOINT_BENCH: &[u8] = b"endpoint.bench";

/// The terminal endpoint: `TERMD.ELF` serves the `Terminal` object on it
/// (`READ`), `NAMESD.ELF` holds the call right to lend (`WRITE`, `transfer`). Unlike the demo and bench endpoints
/// it is not a gate canary: the native shell session is the console program.
///
/// `SH.ELF` holds no grant on it: its row imports `term` and the name server
/// (`NAMESD.ELF`, which holds the lendable half) hands it a derived,
/// call-only capability. A name is never authority; the handle is.
const RESOURCE_ENDPOINT_TERM: &[u8] = b"endpoint.term";

/// The decisions endpoint: `DECISD.ELF` serves the `Decisions` object on it
/// (`READ`), `WHY.ELF` calls it (`WRITE`). Like `endpoint.term`, ring 3 finds
/// it by scanning the one endpoint capability its row holds.
const RESOURCE_ENDPOINT_DECISIONS: &[u8] = b"endpoint.decisions";

// Matches the legacy `HandleKind::Motor(0)`/`Motor(1)` RW grant the autorun
// seed already makes (`kernel/src/tasks/loader.rs`) — dual-mode migration, both
// paths grant identical authority. `motor.N` is the RFC-0005 target
// convention (see `rfcs/RFC-0005-static-topology.md`'s worked example).
//
// Behind `profile-actuation` since 2026-09-21: a drivetrain is what a
// deployment has, not what a kernel has. See that feature in `Cargo.toml`.
const RESOURCE_MOTOR_0: &[u8] = b"motor.0";
const RESOURCE_MOTOR_1: &[u8] = b"motor.1";
/// Does this topology declare the drivetrain: the build is a deployment that
/// actuates (`profile-actuation`) and Kconfig `TOPOLOGY_DRIVETRAIN` allows it
/// (it is n under `USE_DESKTOP`, where the neverallow rule
/// `desktop-grants-no-motor` would refuse the grants).
pub const DRIVETRAIN: bool = cfg!(feature = "profile-actuation") && azos_limits::TOPOLOGY_DRIVETRAIN;
/// The two grants of the drivetrain, in slot order.
const DRIVETRAIN_CAPS: [CapSpec<'static>; 2] = [
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_0), transfer: false,
    },
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_1), transfer: false,
    },
];
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
// Until 2026-09-10 no ring-3 task was granted a gpio, i2c or pwm endpoint at
// all, so the interfaces behind them had no possible caller and the guards
// that protect the drivetrain from them had no exercise on a booted machine. Named
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
const RESOURCE_I2C_IMU:    &[u8] = b"i2c.0.0x68";
// U06-9 (2026-09-26): the brain-link PSK, one per board, the kernel-hosted
// `linkkey` interface (`azos_devif`): the bare interface name, no resource --
// `"linkkey.0"` names nothing and is refused rather than minting the
// singleton under a name that looks like it selected something.
const RESOURCE_LINK_KEY:   &[u8] = b"linkkey";
// Wave 9 (P9): read access to the kernel entropy pool, the kernel-hosted
// `entropy` interface (`azos_devif`): the bare interface name, no resource.
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
// `mmio.<selector>`, READ: a QEMU `virt` device nothing drives, named by what
// it is (RFC-0043; the hardware bus resolves the selector to the device the
// machine enumerated): riscv64 the `sifive,test1` finisher, aarch64 the
// PL061 GPIO. `userspace/tests/captest` maps it, reads it, and is refused
// WRITE on it (the capability carries READ only). Behind the same feature as
// the two above: a selector names hardware of one machine, and a board
// topology has nothing to grant.
#[cfg(all(feature = "cap-refusal-canary", topo_arch_aarch64))]
const RESOURCE_MMIO_RO: &[u8] = b"mmio.dt:arm,pl061";
#[cfg(all(feature = "cap-refusal-canary", not(topo_arch_aarch64)))]
const RESOURCE_MMIO_RO: &[u8] = b"mmio.dt:sifive,test1";
// QEMU `virt` kernels only: the board RTC, writable, and its
// interrupt line, so `userspace/tests/captest` can raise an interrupt from ring 3,
// bind it, and prove it is delivered and re-armed only by its ACK. aarch64
// (wave 8): the PL031, `irq.34` (SPI 2). riscv64 (wave 9 IRQ4): the goldfish
// RTC, `irq.11` (PLIC/APLIC source 11). `topo_bare` / `topo_arch_*` (set by
// `build.rs`: a kernel target, or the emitter's `emit-target-*` feature):
// `tests/host/topology-tests` builds this crate for `aarch64-apple-darwin` with
// `cap-refusal-canary` on, and must keep seeing the host-shaped topology.
#[cfg(all(feature = "cap-refusal-canary", topo_arch_aarch64))]
const RESOURCE_MMIO_RTC_RW: &[u8] = b"mmio.dt:arm,pl031";
#[cfg(all(feature = "cap-refusal-canary", topo_bare, not(topo_arch_aarch64)))]
const RESOURCE_MMIO_RTC_RW: &[u8] = b"mmio.dt:google,goldfish-rtc";
#[cfg(all(feature = "cap-refusal-canary", topo_arch_aarch64))]
const RESOURCE_IRQ_RTC: &[u8] = b"irq.34";
// `block.part.1`, READ|WRITE (RFC-0048 P3, wave 9): partition 1 of the table
// the kernel published — on the gate's partitioned image
// (`build/disk-parted.img`) a 64-sector raw partition after the FAT32 one — so
// `userspace/tests/captest` can write inside it and be refused one sector past it
// (`disk: partition cap refused from ring 3`). Behind its own feature, wired to
// nothing but that row's kernel build: a partition index names a sector range
// of one medium, and on any other image this grant either does not mint (no
// table: every other QEMU image is a bare FAT32 medium) or would name a range
// nobody chose.
#[cfg(feature = "disk-part-row")]
const RESOURCE_DISK_PART1: &[u8] = b"block.part.1";
// `block.part.0`, READ only (wave 10): the FAT32 volume of the same image. With
// it the row's task holds TWO readable partitions, so each block entry names
// its partition by the endpoint's badge, end to end.
#[cfg(feature = "disk-part-row")]
const RESOURCE_DISK_PART0: &[u8] = b"block.part.0";
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
// The ten sensor types, as `sensor.<type>` endpoints of the `Sensor`
// interface (`azos_devif::sensor`), READ only. The autorun row declares all ten:
// which of them an image actually receives is narrowed at seeding to the
// images whose seccomp row lists the `sensor` interface, and a sensor the
// image's driver does not serve answers `NOT_READY`. (`userspace/` reads types
// 0, 1, 2, 3, 4 and 7, and 9 through the power-monitor proxy.)
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
        &[],
    )
    .expect("default_minimal_topology: supervisor push failed");

    topo.push_task(
        MaybeStr::from_bytes(TASK_BRAIN_LINK),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        0,
        &[],
    )
    .expect("default_minimal_topology: brain_link push failed");

    // P1 migration seed for the autorun task: Motor(0)/Motor(1) RW, the GPIO
    // driver registration, the free PWM channel and GPIO pin, the IMU READ,
    // and the ten `sensor.0`..`sensor.9` READ endpoints. Every kind
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
            // The right to register as the GPIO driver, and only that one —
            // the `userspace: ring-3 GPIO driver` scenario is a ring-3
            // program that legitimately registers. Declared here so the typed
            // mint comes from the topology rather than being hard-coded in
            // the kernel a second time, which is the whole point of the P1
            // bridge.
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DRV_GPIO), transfer: false,
        },
            // The three hardware families — see the resource constants above
            // for why each target was chosen, and why the two motor-bound ones
            // are declared only under `cap-refusal-canary`.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_FREE), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_MOTOR), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_FREE), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_MOTOR), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RO), transfer: false,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RTC_RW), transfer: false,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART1), transfer: false,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART0), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Node,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_FAT), transfer: false,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Node,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_TMP), transfer: false,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_RTC), transfer: false,
        },
            // READ, not RW — 2026-09-11. The same argument the sensor grants
            // below already make, applied to the one device where getting it
            // wrong is a safety property rather than a privacy one.
            //
            // `i2c.0.0x68` is the MPU-6050, and it is what feeds
            // `behavior::safety::check_common`'s Falling, Spinning and tilt
            // checks — the L0 reflexes. A WRITE authority over it is the
            // authority to put the IMU to sleep (`PWR_MGMT_1`) or reset it,
            // which does not trip any alarm: the safety layer keeps reading,
            // gets a quiet device, and stops seeing the robot fall over.
            // Blinding the reflex layer is a strictly better attack than
            // commanding the motors, which the actuation gate refuses.
            //
            // Nothing loses anything: the `I2c` interface's `read` and
            // `detect` both need `READ`, and `read` carries the register
            // number as an argument — the register-pointer write happens
            // inside the driver, below the capability check. `userspace/tests/captest`
            // only detects and reads. This is the whole of ring 3's I2C
            // authority and narrowing it is not theatre.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_I2C_IMU), transfer: false,
        },
            // READ only: the legacy seed grants these `HandlePerms::RO` and a
            // sensor read is a read. Granting WRITE would make the typed path
            // carry authority the untyped one never had.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[0]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[1]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[2]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[3]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[4]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[5]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[6]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[7]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[8]), transfer: false,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[9]), transfer: false,
        },
            // U06-9 (2026-09-26): the ring-3 door onto the reserved-sector
            // brain-link PSK (the kernel-hosted `linkkey` endpoint). `brain_client` is
            // the one holder that reads it; every other autorun program
            // (`GPIODRV.ELF`/`REFLEX.ELF`) simply never calls the syscall
            // this grants no more authority to use than
            // `DOMAIN_OPEN` already gave them over the rest of
            // `/fat`. READ only — there is no write path, the key is
            // provisioned at image-build time, never by a running task.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_LINK_KEY), transfer: false,
        },
            // Wave 9 (P9), an endpoint op since D6 part A: the kernel-hosted
            // `entropy` interface (`azos_devif::Entropy`), the source of
            // `brain_client`'s ephemeral handshake keys. READ only (the op
            // class that draws), never transferable.
            CapSpec {
                kind: CapKind::Endpoint,
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
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_ABSENT), transfer: false,
        },
    ];
    // Wave 11 (SHMRING): the kernel sensor streams, appended after every
    // other grant (no earlier slot moves) and only when the stream is
    // configured in. Owner decision 2026-10-03: THIS row is the authority to
    // read the stream — holding the `Cap<Shm>` replaces the per-frame check
    // the `Sensor` interface makes on every read (`crates/core/ipc/src/stream_ring.rs`).
    // READ|WRITE because the consumer stores its tail and wait flag in the
    // region; never DUP.
    let mut autorun_caps = [CapSpec::empty(); AUTORUN_CAPS_MAX];
    // The drivetrain, first, and ONLY when `DRIVETRAIN`. Without it this row
    // grants no way to move anything — the point of the generic-microkernel
    // pivot. `require_pair_write` still demands WRITE on both, so a
    // half-declared drivetrain is refused rather than half-actuated. Under
    // `flight-tool-drivetrain` (a gate feature, wave 12) the drivetrain is
    // `FLIGHT.ELF`'s instead: one writer per motor (`motor_write_conflict`).
    let mut n = 0;
    if DRIVETRAIN && !cfg!(feature = "flight-tool-drivetrain") {
        autorun_caps[..DRIVETRAIN_CAPS.len()].copy_from_slice(&DRIVETRAIN_CAPS);
        n = DRIVETRAIN_CAPS.len();
    }
    autorun_caps[n..n + autorun_base.len()].copy_from_slice(autorun_base);
    n += autorun_base.len();
    for (on, target) in [
        (azos_limits::STREAM_LIDAR_RING, RESOURCE_STREAM_LIDAR),
        (azos_limits::STREAM_CAMERA_RING, RESOURCE_STREAM_CAMERA),
    ] {
        if on {
            autorun_caps[n] = CapSpec {
                kind: CapKind::MemObj,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(target), transfer: false,
            };
            n += 1;
        }
    }
    // The programs a conformance or benchmark image starts through
    // `SYS_SPAWN_EX`, which needs a launch grant on the image it starts:
    // `vsbench`'s `spawn+wait` lane starts `TOOLBOX.ELF` (as `true`) and its
    // `ipc-roundtrip` lane `VSSRV.ELF`; `abitest` starts `ABICHILD.ELF` (the
    // processes it watches), `UHELLO.ELF` (a program whose profile refuses
    // its probe) and `EPSRV.ELF` (the server of `endpoint.demo`). QEMU
    // gate/bench topologies only (`ipc-endpoint-canary`, the feature that
    // already declares the benchmark's server row); after every other grant,
    // so no earlier slot moves. A child runs under its image's own row and
    // profile, which grant it nothing of this row's.
    #[cfg(feature = "ipc-endpoint-canary")]
    for image in [TASK_TOOLBOX_IMAGE, TASK_ABICHILD_IMAGE, TASK_UHELLO_IMAGE, TASK_EPSRV_IMAGE, TASK_VSSRV_IMAGE] {
        autorun_caps[n] = CapSpec {
            kind: CapKind::Node,
            perms: CapPerms::EXEC,
            target: MaybeStr::from_bytes(image), transfer: false,
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

    // The hardware bus rows of this image (`BUILTIN_DEVICE_ROWS`).
    for (name, select) in BUILTIN_DEVICE_ROWS {
        topo.push_device(crate::types::DeviceSpec {
            name: MaybeStr::from_bytes(name),
            select: MaybeStr::from_bytes(select),
            admit: true,
            driver: MaybeStr::from_bytes(&[]),
        })
        .expect("default_minimal_topology: device row push failed");
    }

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
    // an IMAGE rather than a role. `SYS_SPAWN_EX` looks its child's row up by
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
    // `SYS_IPC_FAST_CALL` therefore needed the peer to become an image.
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
            // because a `Sensor` read of `sensor.9` (a capability the
            // autorun row already holds) is a ring-3 call that reaches a
            // `UserDriverProxy`; on a boot where `INADRV.ELF` owns the kind
            // the registration is refused and the lane reports that.
            CapSpec {
                kind: CapKind::Device,
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
            kind: CapKind::Device,
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
    // The buzzer's ring-3 host. Its row exists whichever host the driver
    // starts in (`BUZZER_START_HOST`): the row is what the ring-3 host runs
    // with when the driver is, or is moved, there. `stateless`: the driver
    // keeps nothing a restart cannot rebuild, so it may move between its two
    // hosts at run time (`placement`); `call_budget_us` is the deadline a
    // call to it is held to.
    {
        topo.push_task(
            MaybeStr::from_bytes(TASK_BUZZDRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            0,
            &[
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BUZZER), transfer: false,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_PWM_BUZZER), transfer: false,
                },
            ],
        )
        .expect("default_minimal_topology: BUZZDRV.ELF push failed");
        topo.set_last_task_mem_pages(RING3_DRIVER_MEM_PAGES);
        topo.set_last_task_place(PlaceSpec {
            host: BUZZER_START_HOST,
            stateless: true,
            call_budget_us: azos_limits::DRV_BUZZER_CALL_BUDGET_US as u32,
        });
        // Started at boot only when the driver starts in ring 3; a driver
        // that starts in the kernel is started here when it is moved.
        #[cfg(all(feature = "ring3-driver-start", not(feature = "ring3-driver-start-canary")))]
        if BUZZER_START_HOST == Host::Ring3 {
            topo.set_last_task_start(true);
        }
        // Gate only (`restart-smoke`): `restart = no`, so not even a kill of
        // the buzzer driver is restarted.
        #[cfg(feature = "restart-smoke")]
        topo.set_last_task_restart(crate::types::RestartPolicy::No);
    }
    // Wave 11 (DRVPLACE): the INA219's ring-3 host has a row only when the
    // driver is placed in ring 3 ([`INADRV_ROW`]). Placed in the kernel, the
    // row would be a dormant grant of the `i2c` endpoint on its chip to an image the
    // kernel does not run.
    if INADRV_ROW {
        topo.push_task(
            MaybeStr::from_bytes(TASK_INADRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            0,
            &[
                CapSpec {
                    kind: CapKind::Device,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_DRV_POWER_MON), transfer: false,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_I2C_INA219), transfer: false,
                },
            ],
        )
        .expect("default_minimal_topology: INADRV.ELF push failed");
        topo.set_last_task_mem_pages(RING3_DRIVER_MEM_PAGES);
        #[cfg(feature = "ring3-driver-start")]
        topo.set_last_task_start(true);
        // Gate only (`restart-smoke`): `restart = always`, so a clean exit of
        // the INA219 driver is restarted too.
        #[cfg(feature = "restart-smoke")]
        topo.set_last_task_restart(crate::types::RestartPolicy::Always);
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

    // Owner decision 2026-09-28: `SYS_SPAWN_EX` refuses an image the topology has
    // no row for. `abitest` spawns `UHELLO.ELF` (its `spawn()` conformance
    // check), which until then ran with no row: no capabilities, the default
    // budget, the default priority. This is that row. No capabilities, as
    // before; `soft_rt` at 16, the class and priority of the `autorun` row its
    // parent runs under, so a parent that polls for it does not out-rank it.
    // Under `mem-locked-smoke` the image already has its (locked) row above.
    #[cfg(all(feature = "ipc-endpoint-canary", not(feature = "mem-locked-smoke")))]
    topo.push_task(MaybeStr::from_bytes(TASK_UHELLO_IMAGE), MaybeStr::from_bytes(NAME_SOFT_RT), 16, &[])
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
    topo.set_last_task_imports(SH_IMPORTS)
        .expect("default_minimal_topology: SH.ELF imports");
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
    // authority: the `power` endpoint (WRITE, and READ for the rate read), whose
    // ops check their class on every call. The shell holds only the right to start it, and not under
    // `CONSOLE_LOCKDOWN` (`SH_CAPS_LOCKDOWN`), so a locked-down shell is
    // refused at `SYS_SPAWN_EX`, recorded, not merely missing a PATH entry.
    topo.push_task(MaybeStr::from_bytes(TASK_POWER_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, POWER_CAPS)
        .expect("default_minimal_topology: POWER.ELF push failed");
    topo.set_last_task_mem_pages(POWER_MEM_PAGES);
    // `power serve` is a housekeeping loop: it re-checks the policy once a
    // period, and nobody waits on that wake-up. It declares itself
    // `QOS_BACKGROUND` and its row lets that tier's timer slack apply
    // (QOS_TIMER_TOLERANCE_ROWS_ONLY: the robot, industrial and automotive
    // presets give slack only to rows that say so).
    topo.set_last_task_timer_slack(true);
    // Wave 12: the other privileged families, one tool each, the POWER.ELF
    // pattern: each row is the whole of its tool's authority, checked by its
    // family's typed call on every call, and the shell holds only the right
    // to start them, not under `CONSOLE_LOCKDOWN`.
    for (image, caps) in [
        (TASK_FLIGHT_IMAGE, FLIGHT_CAPS),
        (TASK_BEHAVIOR_IMAGE, BEHAVIOR_CAPS),
        (TASK_CONFIG_IMAGE, CONFIG_CAPS),
        (TASK_OTA_IMAGE, OTA_CAPS),
    ] {
        topo.push_task(MaybeStr::from_bytes(image), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, caps)
            .expect("default_minimal_topology: family tool push failed");
        topo.set_last_task_mem_pages(POWER_MEM_PAGES);
    }
    // Wave 15 (TRACE): the tracer's reader, the POWER.ELF pattern. Its row is
    // the whole of its authority: `Cap<Trace>` (READ maps the rings, WRITE
    // sets the class mask), checked by the tracer's ops on every call,
    // and `/fat` read-write for `tracectl stream -o FILE`. The shell holds
    // only the right to start it, not under `CONSOLE_LOCKDOWN`. Pushed after
    // every earlier row, so no index another test pins moves.
    topo.push_task(MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, TRACECTL_CAPS)
        .expect("default_minimal_topology: TRACECTL.ELF push failed");
    topo.set_last_task_mem_pages(TRACECTL_MEM_PAGES);
    topo.set_last_task_instances(TRACECTL_INSTANCES);
    // The terminal server (`userspace/services/termd`, the Terminal object):
    // the console program of the native shell session. Its row is its whole
    // authority, `READ` on `endpoint.term` (it serves it); console input it
    // claims by `LOG_CONSOLE_WAIT`, as the shell did. The shell's row holds
    // `WRITE` on the same name. Same priority as the shell, so the interrupt
    // key is read as promptly as it was. `start` follows the console program
    // (below); `on-failure` like the shell: `hangup` ends it with code 0 and
    // gives the console back to the kernel shell.
    topo.push_task(MaybeStr::from_bytes(TASK_TERMD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SH_PRIORITY, TERMD_CAPS)
        .expect("default_minimal_topology: TERMD.ELF push failed");
    topo.set_last_task_mem_pages(TERMD_MEM_PAGES);
    topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    // The name server: the signed rows' `imports` are answered here. Its row
    // is its whole authority (serve `names`, lend `term`); it starts with the
    // native shell session, before the terminal server and the shell.
    topo.push_task(MaybeStr::from_bytes(TASK_NAMESD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SH_PRIORITY, NAMESD_CAPS)
        .expect("default_minimal_topology: NAMESD.ELF push failed");
    topo.set_last_task_mem_pages(NAMESD_MEM_PAGES);
    topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    // The decision server (`userspace/services/decisd`, the Decisions
    // object) and its client tool (`WHY.ELF`). The server's row is its whole
    // authority, `READ` on `endpoint.decisions`; the records it serves it
    // reads from `/proc/decisions.bin`, which needs no grant. `start` follows
    // Kconfig `DECISION_REFUSALS_DURABLE` / `DECISION_RECORDS_DEV`: without
    // either the kernel keeps no decisions and there is nothing to serve.
    // `why` holds `WRITE` on the same name and nothing else; the shell holds
    // the right to start it (`SH_CAPS`, not under `CONSOLE_LOCKDOWN`).
    topo.push_task(MaybeStr::from_bytes(TASK_DECISD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, DECISD_CAPS)
        .expect("default_minimal_topology: DECISD.ELF push failed");
    topo.set_last_task_mem_pages(DECISD_MEM_PAGES);
    topo.set_last_task_start(azos_limits::DECISION_REFUSALS_DURABLE || azos_limits::DECISION_RECORDS_DEV);
    topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    topo.push_task(MaybeStr::from_bytes(TASK_WHY_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, WHY_CAPS)
        .expect("default_minimal_topology: WHY.ELF push failed");
    topo.set_last_task_mem_pages(WHY_MEM_PAGES);
    // The package installer (`userspace/services/pkgd`, the Packages object)
    // and its client tool (`PKG.ELF`). The installer serves `endpoint.packages`
    // and holds a read-write tree on `/fat/PKG`, where it stages packages and
    // journals its decisions; the volume's other files it reads without a
    // grant (CAPS.TOM, CAPS.SIG, SCHED.TOM, to judge a package against the
    // signed topology). Neither row exists on a small board ([`PKGD_ROW`]),
    // where no package is expected and the buffers (Kconfig `PKG_MAX_KB`) and
    // two images are a cost. `PKG.ELF` holds `WRITE` on the same name and
    // nothing else; the shell holds the right to start it (not under
    // `CONSOLE_LOCKDOWN`).
    if PKGD_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_PKGD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, PKGD_CAPS)
            .expect("default_minimal_topology: PKGD.ELF push failed");
        topo.set_last_task_mem_pages(PKGD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
        topo.push_task(MaybeStr::from_bytes(TASK_PKG_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, PKG_CAPS)
            .expect("default_minimal_topology: PKG.ELF push failed");
        topo.set_last_task_mem_pages(PKG_MEM_PAGES);
    }
    // The RPC server (`userspace/services/rpcsrv`, Phase 9 step 1). With a peer
    // configured (Kconfig `RPC_PEER_NODE`) the built-in topology declares the
    // class `fleet` for it, exports `decisions` to the class and starts the
    // server; without one the row exists and exports nothing, so the proxy has
    // no one behind it. `why --remote` is the caller.
    topo.push_task(MaybeStr::from_bytes(TASK_RPCSRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, RPCSRV_CAPS)
        .expect("default_minimal_topology: RPCSRV.ELF push failed");
    topo.set_last_task_mem_pages(RPCSRV_MEM_PAGES);
    topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    if azos_limits::RPC_PEER_NODE != 0 {
        topo.push_peer(MaybeStr::from_bytes(b"fleet"), &[azos_limits::RPC_PEER_NODE as u32])
            .expect("default_minimal_topology: peer class push failed");
        topo.set_last_task_exports(&[crate::types::ExportSpec {
            endpoint: MaybeStr::from_bytes(b"decisions"),
            peer: MaybeStr::from_bytes(b"fleet"),
        }])
        .expect("default_minimal_topology: RPCSRV.ELF exports");
        topo.set_last_task_start(true);
    }
    // RFC-0053 L0: the Linux driver server skeleton, only under `lx-server`
    // (Kconfig LINUX_DRIVERS + LX_SERVER_SKELETON). One capability, READ on
    // the entropy pool, for its allocator (`LXSRV_CAPS`); never an actuator
    // (`Motor`, `Pwm`, `Gpio`, `Estop`): a Linux server holds none, and the
    // skeleton needs nothing else (it opens its module read-only, which
    // needs no grant). `best_effort`: no real-time task may depend on
    // a Linux server (RFC-0053 3). `start = true`, so a volume that carries
    // LXSRV.ELF starts it; only the gate's `build/disk-lx.img` does.
    #[cfg(feature = "lx-server")]
    {
        topo.push_task(MaybeStr::from_bytes(TASK_LXSRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), 0, LXSRV_CAPS)
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
        topo.set_last_task_mem_pages(LXHELLO_MEM_PAGES + LINUX_RUNTIME_PAGES);
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
        topo.set_last_task_mem_pages(BUSYBOX_MEM_PAGES + LINUX_RUNTIME_PAGES);
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
        topo.set_last_task_mem_pages(LXTHR_MEM_PAGES + LINUX_RUNTIME_PAGES);
        topo.set_last_task_abi(crate::types::TaskAbi::Linux)
            .expect("default_minimal_topology: LXTHR.ELF is a Linux row with no hardware capability");
    }
    // `abitest`'s children (see `TASK_ABICHILD_IMAGE`). Class and priority of
    // the autorun row its parent runs under, so a parent that polls for a
    // child does not out-rank it. A small budget and a few instances: a
    // child holds its image, a stack and the pages one mode touches, and
    // admission pays for every instance of the row. Pushed after every other
    // row, so no index another test pins moves.
    #[cfg(feature = "ipc-endpoint-canary")]
    {
        topo.push_task(
            MaybeStr::from_bytes(TASK_ABICHILD_IMAGE),
            MaybeStr::from_bytes(NAME_SOFT_RT),
            16,
            &[CapSpec {
                kind: CapKind::Node,
                perms: CapPerms::EXEC,
                target: MaybeStr::from_bytes(TASK_ABICHILD_IMAGE), transfer: false,
            }],
        )
        .expect("default_minimal_topology: ABICHILD.ELF push failed");
        topo.set_last_task_mem_pages(ABICHILD_MEM_PAGES);
        topo.set_last_task_instances(ABICHILD_INSTANCES);
    }
    // The console program (Kconfig CONSOLE_PROGRAM, "Userspace programs"):
    // its row says `start = true`. The native shell's row is pushed above;
    // BusyBox's with `BUSYBOX` (the choice selects it); any other image the
    // topology has a row for keeps that row; one it has none for gets a row
    // with no capability, `best_effort` at the shell's priority, last, so
    // no index another test pins moves. The kernel starts it after every
    // other `start = true` row (`kernel/src/tasks/loader.rs`).
    if let Some(name) = console_image() {
        let name = MaybeStr::from_bytes(name);
        if !topo.set_task_start(&name, true) {
            topo.push_task(name, MaybeStr::from_bytes(NAME_BEST_EFFORT), SH_PRIORITY, &[])
                .expect("default_minimal_topology: console program row push failed");
            topo.set_last_task_mem_pages(CONSOLE_MEM_PAGES);
            topo.set_last_task_start(true);
        }
        // The native shell session is two images: the console program is the
        // terminal server, and the shell it serves starts with it.
        if name.as_bytes() == TASK_TERMD_IMAGE {
            let _ = topo.set_task_start(&MaybeStr::from_bytes(TASK_SH_IMAGE), true);
            // ... and so is the name server it reaches the terminal through;
            // it starts before the console program (every other `start` row does).
            let _ = topo.set_task_start(&MaybeStr::from_bytes(TASK_NAMESD_IMAGE), true);
        }
    }
    // The row `neverallow-row-canary` exists to declare: a ring-3 image that
    // is not an actuation row holding a PWM channel with write access, which
    // `neverallow::RULES[0]` (`actuation-outside-actuation-row`) forbids. Pushed
    // last, after the debug_assert and every row a test pins an index of:
    // structure only, the refusal is `admission_check`'s.
    #[cfg(feature = "neverallow-row-canary")]
    topo.push_task(
        MaybeStr::from_bytes(b"NEVERALLOW.ELF"),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        0,
        &[CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(b"pwm.6"),
            transfer: false,
        }],
    )
    .expect("default_minimal_topology: neverallow canary push failed");
}

/// The `[device.NAME]` rows of the built-in topology: `(name, selector)`, each
/// admitting what it selects (`azos_hwbus::Pattern::parse` reads the selector).
///
/// They are what lets an image whose Kconfig `HWBUS_AUTOBIND` is
/// topology-only boot at all: the boot disk the signed topology is read from
/// and the network interface are bound by the hardware bus BEFORE any
/// topology file can be read, so the rows that admit them are compiled in
/// (`kernel/src/boot/hwbus.rs` binds with these first and reconciles with the
/// signed file's rows once it is installed). Hardware the kernel booted on
/// (the console, the interrupt controller) needs no row: its table entries
/// are `boot`.
///
/// QEMU machines (`qemu-devices`, turned on by the kernel's `qemu`): the
/// virtio-mmio disk, NIC, keyboard and entropy device, the virtio-pci NIC and
/// an NVMe controller. A board image lists the hardware its drivers bind.
#[cfg(feature = "qemu-devices")]
pub const BUILTIN_DEVICE_ROWS: &[(&[u8], &[u8])] = &[
    (b"virtio-blk", b"virtio:2"),
    (b"virtio-net", b"virtio:1"),
    (b"virtio-rng", b"virtio:4"),
    (b"virtio-input", b"virtio:18"),
    (b"virtio-net-pci", b"pci:1af4:1041"),
    (b"nvme", b"pciclass:010802:ffffff"),
];
/// See the QEMU build's.
#[cfg(not(feature = "qemu-devices"))]
pub const BUILTIN_DEVICE_ROWS: &[(&[u8], &[u8])] = &[];

/// The console program's image name (Kconfig `CONSOLE_PATH` without its
/// `/fat/`), `None` without one (`CONSOLE_PROGRAM_NONE`). `azos_limits`'
/// build script refuses a path that is not `/fat/NAME.ELF`.
pub const fn console_image() -> Option<&'static [u8]> {
    let p = azos_limits::CONSOLE_PATH.as_bytes();
    if p.len() <= 5 {
        return None;
    }
    let (_, name) = p.split_at(5);
    Some(name)
}

/// Frame budget of a console program the topology has no row of its own
/// for: the native shell's.
const CONSOLE_MEM_PAGES: u32 = SH_MEM_PAGES;

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
    CapSpec { kind: CapKind::Node, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"/fat"), transfer: false },
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

/// The rights of the family tools' endpoints (`FLIGHT.ELF`, `BEHAVIOR.ELF`,
/// `CONFIG.ELF`, `OTA.ELF`): `READ` observes and `WRITE` changes. Under
/// `family-cap-canary` they hold `READ` only, so every operation that changes
/// something is refused by the right, recorded and printed
/// (`[AUTHORITY] <cmd> REFUSED`; gate row `sh: family tools refused without
/// their capability`).
const FAMILY_PERMS: CapPerms = if cfg!(feature = "family-cap-canary") { CapPerms::READ } else { CapPerms::RW };

/// `FLIGHT.ELF`'s authority: `WRITE` on the `flight` endpoint, which the
/// topology admits only for a row that also holds `WRITE` on both wheels
/// (`flight_without_drivetrain`: arming is authority over the whole
/// drivetrain), and a motor has ONE writer (`motor_write_conflict`). In this
/// default topology that writer is the `autorun` row (under
/// `profile-actuation`), so the flight tool holds nothing and its calls are
/// refused, recorded. A deployment that flies from the operator shell grants
/// the drivetrain and the endpoint to `FLIGHT.ELF` in its signed topology
/// instead of to its autorun program; the gate does exactly that with
/// `flight-tool-drivetrain`. Under `family-cap-canary` it holds the endpoint
/// with `READ` only.
const FLIGHT_CAPS: &[CapSpec] = if cfg!(feature = "family-cap-canary") {
    &[CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::READ,
        target: MaybeStr::from_bytes(b"flight"), transfer: false,
    }]
} else if DRIVETRAIN && cfg!(feature = "flight-tool-drivetrain") {
    &[
        DRIVETRAIN_CAPS[0],
        DRIVETRAIN_CAPS[1],
        CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(b"flight"), transfer: false,
        },
    ]
} else {
    &[]
};

/// `BEHAVIOR.ELF`'s, `CONFIG.ELF`'s and `OTA.ELF`'s authority: the endpoint of
/// their interface, with [`FAMILY_PERMS`], as `POWER.ELF`'s.
const BEHAVIOR_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: FAMILY_PERMS,
    target: MaybeStr::from_bytes(b"behavior"), transfer: false,
}];
const CONFIG_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: FAMILY_PERMS,
    target: MaybeStr::from_bytes(b"config"), transfer: false,
}];
const OTA_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: FAMILY_PERMS,
    target: MaybeStr::from_bytes(b"ota"), transfer: false,
}];

/// The Linux driver server skeleton's image (RFC-0053 L0).
pub const TASK_LXSRV_IMAGE: &[u8] = b"LXSRV.ELF";
/// Frame budget of `LXSRV.ELF`: image and stack, a 64 KiB module buffer in
/// `.bss`, and the two module regions it maps (a few pages for the test
/// module); since RFC-0053 L1 also the Kbuild modules (LXBASE.KO, XZ_DEC.KO:
/// file copies and regions, about 14 pages), the 96 KiB host-allocator arena
/// and the xz fixture with its 48 KiB output (about 18 pages).
#[cfg(feature = "lx-server")]
const LXSRV_MEM_PAGES: u32 = 128;
/// `LXSRV.ELF`'s authority: READ on the kernel-hosted `entropy` endpoint,
/// which keys and randomizes the hardened allocator it links (`azos_ualloc`,
/// Kconfig `USER_ALLOC_*`). Like every interface grant the kernel withholds it
/// from an image whose seccomp row does not list the interface (the row does).
#[cfg(feature = "lx-server")]
const LXSRV_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false,
}];

/// Does the built-in topology carry the `LXHELLO.ELF` row? Gate builds
/// (`linux-abi-test`) of a kernel with the Linux personality (`LINUX_ABI`).
pub const LXHELLO_ROW: bool = cfg!(feature = "linux-abi-test") && azos_limits::LINUX_ABI;

/// Frames the Linux runtime takes from every Linux row's memory budget when it
/// hosts the personality (Kconfig `LINUX_RUNTIME`): its text, read-only data
/// and data+bss pages (`userspace/services/lxrt`, about 32 KiB), the page
/// tables of the window it is mapped in, and the stack it grows on the
/// program's own stack. 0 with the in-kernel personality.
const LINUX_RUNTIME_PAGES: u32 = if azos_limits::LINUX_RUNTIME { 16 } else { 0 };

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
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat"), transfer: false,
}];
/// The `/tmp` tree, read-write.
const TMP_RW: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/tmp"), transfer: false,
};

/// `SH.ELF`'s authority outside `CONSOLE_LOCKDOWN`: [`SH_CAPS`], plus the
/// right to start `BUSYBOX.ELF` when the topology carries its row
/// ([`BUSYBOX_ROW`], wave 13), plus (gate only, `linux-abi-test`) the right
/// to start `LXHELLO.ELF`.
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_UNLOCKED: &[CapSpec] = match (BUSYBOX_ROW, PKGD_ROW) {
    (false, false) => SH_CAPS,
    (true, false) => &SH_CAPS_WITH_BUSYBOX,
    (false, true) => &SH_CAPS_WITH_PKG,
    (true, true) => &SH_CAPS_WITH_BUSYBOX_PKG,
};
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_WITH_BUSYBOX: [CapSpec<'static>; SH_CAPS.len() + 1] = sh_caps_plus(&[BUSYBOX_LAUNCH]);
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_WITH_PKG: [CapSpec<'static>; SH_CAPS.len() + 1] = sh_caps_plus(&[PKG_LAUNCH]);
#[cfg(not(feature = "linux-abi-test"))]
const SH_CAPS_WITH_BUSYBOX_PKG: [CapSpec<'static>; SH_CAPS.len() + 2] = sh_caps_plus2(&[BUSYBOX_LAUNCH], &[PKG_LAUNCH]);
/// The shell's right to start the package tool, where the topology has it.
const PKG_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_PKG_IMAGE), transfer: false,
};
const BUSYBOX_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false,
};
#[cfg(feature = "linux-abi-test")]
const LXHELLO_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_LXHELLO_IMAGE), transfer: false,
};
/// Gate builds: the launch grants of the Linux test rows this build carries,
/// and the package tool's (the gate's classes all carry the installer's rows).
#[cfg(feature = "linux-abi-test")]
const _: () = assert!(PKGD_ROW, "linux-abi-test: the shell's launch list below includes PKG.ELF");
#[cfg(feature = "linux-abi-test")]
const LX_LAUNCHES: &[CapSpec] = &[
    LXHELLO_LAUNCH,
    PKG_LAUNCH,
    #[cfg(feature = "linux-busybox-test")]
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false,
    },
    #[cfg(feature = "linux-threads-test")]
    CapSpec {
        kind: CapKind::Node,
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
/// `POWER.ELF`'s authority: the `power` endpoint, `WRITE` for every operation
/// and `READ` for `power sched_hz` with no argument. Under `power-cap-canary`
/// it holds `READ` only, so every operation that changes something is refused
/// by the right, recorded and printed (gate row `sh: power refused without
/// the power right`).
const POWER_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: if cfg!(feature = "power-cap-canary") { CapPerms::READ } else { CapPerms::RW },
    target: MaybeStr::from_bytes(b"power"), transfer: false,
}];

/// The tracer's reader (wave 15, TRACE).
pub const TASK_TRACECTL_IMAGE: &[u8] = b"TRACECTL.ELF";
/// Frame budget of `TRACECTL.ELF`: image, stack, its record batch and the
/// trace region's mapping (at most `MAX_MEMOBJ_PAGES`, 64 pages, booked to the
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
        kind: CapKind::Log,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"trace"), transfer: false,
    },
    FAT_RW,
];
#[cfg(feature = "trace-cap-canary")]
const TRACECTL_CAPS: &[CapSpec] = &[FAT_RW];
/// The `/fat` tree, read-write.
const FAT_RW: CapSpec = CapSpec {
    kind: CapKind::Node,
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
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_POWER_IMAGE), transfer: false,
    },
    // Wave 12: the other privileged tools, outside the lockdown only.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_FLIGHT_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_BEHAVIOR_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_CONFIG_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_OTA_IMAGE), transfer: false,
    },
    // Wave 15 (TRACE): the tracer's reader.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), transfer: false,
    },
    // The decision query tool.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_WHY_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/fat"), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/tmp"), transfer: false,
    },
    TASK_VIEW_CAP,
];

/// The shell's way to the terminal: it holds NO grant on `endpoint.term`. Its
/// row says `imports = ["term"]` (`set_last_task_imports`), the kernel gives
/// it the call right on `endpoint.names` badged with its row, and the name
/// server lends it a derived, call-only capability on `endpoint.term` when it
/// asks. A name is never authority: the row lists what it may ask for.
const SH_IMPORTS: &[MaybeStr<'static>] = &[MaybeStr::from_bytes(b"term")];
/// The server half: `READ` claims the endpoint for `TERMD.ELF`.
const TERM_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_TERM), transfer: false,
};

/// The terminal server's image: the console program of the native shell
/// session (it owns console input; the shell is its client).
pub const TASK_TERMD_IMAGE: &[u8] = b"TERMD.ELF";
/// Frame budget of `TERMD.ELF`: image, stack, page tables and its static
/// discipline (line, history, type-ahead); it has no heap.
const TERMD_MEM_PAGES: u32 = 48;
/// `TERMD.ELF`'s authority: the right to serve `endpoint.term`. Console
/// input is claimed with `LOG_CONSOLE_WAIT`, which its seccomp profile lists;
/// it holds no other capability.
const TERMD_CAPS: &[CapSpec] = &[TERM_SERVE];

/// The name server's image (`userspace/services/namesd`): the Names object.
pub const TASK_NAMESD_IMAGE: &[u8] = b"NAMESD.ELF";
/// Frame budget of `NAMESD.ELF`: image, stack, page tables and its static
/// view buffer; it has no heap.
const NAMESD_MEM_PAGES: u32 = 32;
/// The server half of `endpoint.names`: `READ` claims it for `NAMESD.ELF`.
const NAMES_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"endpoint.names"), transfer: false,
};
/// What `NAMESD.ELF` may lend: the call right on `endpoint.term`, with `DUP`
/// (`transfer = true`) so the kernel can derive an attenuated copy for a
/// borrower. `WRITE` claims no service: `TERMD.ELF` stays the server.
const TERM_LEND: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_TERM), transfer: true,
};
/// `NAMESD.ELF`'s authority: to serve `endpoint.names`, and to lend the
/// endpoints listed here. Its row is the whole name space: there is no other.
const NAMESD_CAPS: &[CapSpec] = &[NAMES_SERVE, TERM_LEND];
/// The caller half of `endpoint.decisions`: the right to ask the decision
/// server, and nothing more (`WRITE` claims no service).
const DECISIONS_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: false,
};
/// The server half: `READ` claims the endpoint for `DECISD.ELF`.
const DECISIONS_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: false,
};

/// The decision server's image (`userspace/services/decisd`).
pub const TASK_DECISD_IMAGE: &[u8] = b"DECISD.ELF";
/// Frame budget of `DECISD.ELF`: image, stack, page tables and its static
/// table of decoded records (24 x 104 bytes) and file buffer (2 KiB); no heap.
const DECISD_MEM_PAGES: u32 = 48;
/// `DECISD.ELF`'s authority: the right to serve `endpoint.decisions`. It
/// reads `/proc/decisions.bin` read-only, which needs no grant.
const DECISD_CAPS: &[CapSpec] = &[DECISIONS_SERVE];

/// The decision query tool's image (`userspace/services/why`).
pub const TASK_WHY_IMAGE: &[u8] = b"WHY.ELF";
/// Frame budget of `WHY.ELF`: a `std` image (about 14 pages), the stack, and
/// the hardened allocator's blocks, which the kernel charges whole when they
/// are mapped (`USER_ALLOC_BLOCK_KB` per size class a run touches, the guard
/// pages holding no frame).
const WHY_MEM_PAGES: u32 = 64;
/// `WHY.ELF`'s authority: the right to ask `endpoint.decisions`, (`why
/// --remote`) the decision server of the peer node through its proxy, and READ
/// on the kernel-hosted `entropy` endpoint, which keys and randomizes the
/// allocator `std` brings (`azos_stdrt`; the row of its seccomp profile lists
/// the interface, so the grant is not withheld). The local endpoint is listed
/// first: the pool numbers endpoints in the order the topology first names
/// them, and the tool takes the second as the remote one.
const WHY_CAPS: &[CapSpec] = &[DECISIONS_CALL, RPC_DECISIONS_CALL, WHY_ENTROPY];
const WHY_ENTROPY: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false,
};

/// The package installer's endpoint: `PKGD.ELF` serves the `Packages` object
/// on it (`READ`), `PKG.ELF` calls it (`WRITE`).
const RESOURCE_ENDPOINT_PACKAGES: &[u8] = b"endpoint.packages";
/// The caller half of `endpoint.packages`: the right to ask the installer.
const PACKAGES_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PACKAGES), transfer: false,
};
/// The server half: `READ` claims the endpoint for `PKGD.ELF`.
const PACKAGES_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PACKAGES), transfer: false,
};
/// Where the installer stages: the one tree it may change.
const PKG_STAGE_TREE: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat/PKG"), transfer: false,
};

/// Does the built-in topology carry the package installer's two rows (and the
/// shell its right to start the tool)? Every class but a small board
/// (`HWCLASS_EMBEDDED`), like the Linux personality's.
pub const PKGD_ROW: bool = !azos_limits::HWCLASS_EMBEDDED;

/// The package installer's image (`userspace/services/pkgd`).
pub const TASK_PKGD_IMAGE: &[u8] = b"PKGD.ELF";
/// Frame budget of `PKGD.ELF`: its image and stack (256 KiB), the buffers it
/// reads a package, the signed topology and the staged packages' rows into
/// (Kconfig `PKG_MAX_KB`, `TOPOLOGY_CAPS_MAX_KB`, `TOPOLOGY_SCHED_MAX_KB`,
/// `PKG_MAX_STAGED` x `PKG_META_MAX_KB`, and the head of a package: its
/// header, key and signature at their ceilings, 13 KiB, and two texts) and the
/// topology it merges them into. `tests/host/pkg-tests` holds this above what
/// `azos_packages::Work` and a `Topology` take.
pub const PKGD_MEM_PAGES: u32 = {
    let kb = azos_limits::PKG_MAX_KB as u64
        + 13
        + 2 * azos_limits::PKG_META_MAX_KB as u64
        + azos_limits::TOPOLOGY_CAPS_MAX_KB as u64
        + azos_limits::TOPOLOGY_SCHED_MAX_KB as u64
        + azos_limits::PKG_MAX_STAGED as u64 * azos_limits::PKG_META_MAX_KB as u64;
    let topo = core::mem::size_of::<Topology<'static>>() as u64;
    (64 + kb.div_ceil(4) + topo.div_ceil(4096)) as u32
};
/// `PKGD.ELF`'s authority: the right to serve `endpoint.packages`, and the
/// staging tree.
const PKGD_CAPS: &[CapSpec] = &[PACKAGES_SERVE, PKG_STAGE_TREE];

/// The package tool's image (`userspace/services/pkg`).
pub const TASK_PKG_IMAGE: &[u8] = b"PKG.ELF";
/// Frame budget of `PKG.ELF`: a small image, a few stack buffers.
const PKG_MEM_PAGES: u32 = 32;
/// `PKG.ELF`'s authority: the right to ask `endpoint.packages`. It opens the
/// package file it is told to, which needs no grant.
const PKG_CAPS: &[CapSpec] = &[PACKAGES_CALL];

/// The proxy endpoint of `decisions` (`endpoint.rpc-decisions`): the local face
/// of the decision server of the peer node. The name starts with
/// [`PROXY_PREFIX`](crate::types::PROXY_PREFIX), which is what makes the kernel
/// treat it as a proxy (a real-time caller is refused) and `neverallow` allow
/// only `RPCSRV.ELF` to serve it.
const RPC_DECISIONS_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_RPC_DECISIONS), transfer: false,
};
/// The server half of the proxy: `READ` claims it for `RPCSRV.ELF`.
const RPC_DECISIONS_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_RPC_DECISIONS), transfer: false,
};
const RESOURCE_ENDPOINT_RPC_DECISIONS: &[u8] = b"endpoint.rpc-decisions";
/// What `RPCSRV.ELF` may lend to a peer: the call right on
/// `endpoint.decisions` with `DUP` (`transfer = true`), from which it derives
/// each peer session's attenuated, expiring warrant. `WRITE` claims no
/// service: `DECISD.ELF` stays the server.
const DECISIONS_LEND: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: true,
};

/// The RPC server's image (`userspace/services/rpcsrv`): transparent RPC.
pub const TASK_RPCSRV_IMAGE: &[u8] = crate::types::RPC_IMAGE;
/// Frame budget of `RPCSRV.ELF`: image, stack, a second thread's stack and its
/// static buffers (the engine's three message buffers, the reassembly slots,
/// the sessions with their dedupe windows: about 130 KiB); no heap.
const RPCSRV_MEM_PAGES: u32 = 128;
/// `RPCSRV.ELF`'s authority: to serve the proxy of each service it carries, and
/// to lend what its `export` key names. The classes and exports come from
/// Kconfig `RPC_PEER_NODE` here; a signed topology states its own.
const RPCSRV_CAPS: &[CapSpec] = &[RPC_DECISIONS_SERVE, DECISIONS_LEND];

/// The full `/proc` task view (wave 12, owner round 48): `Cap<Task>` `READ`
/// on `"tasks"`. Without it `/proc/tasks` and `/proc/<tid>` show an image
/// only itself and its descendants (Linux `hidepid=2`). `SH.ELF` and
/// `TOOLBOX.ELF` (`ps`) hold it, and neither under `CONSOLE_LOCKDOWN`, which
/// withholds every grant beyond the shell's own work from the console path
/// (the recovery console's seed is empty there too).
pub const TASK_VIEW_CAP: CapSpec = CapSpec {
    kind: CapKind::Domain,
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
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false,
    },
    CapSpec {
        kind: CapKind::Node,
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
        // ten `sensor.N` READ endpoints (see the block comment above
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
        let motor_count = caps.iter().filter(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("motor.")).count();
        let non_motor_count = caps.len() - motor_count;
        // Present regardless of `profile-actuation`: DriverRegistry(drv.1),
        // endpoint pwm.4, gpio.20, i2c.0.0x68, sensor.0..9 × 10 = 14 (plus whatever
        // `cap-refusal-canary` adds, not exercised by this test — see
        // `tests/host/topology-tests`' cap-canary run for that half).
        assert_eq!(
            non_motor_count, 14,
            "non-motor grant count drifted — update this test AND check \
             whether the drift was intentional"
        );
        if DRIVETRAIN {
            assert_eq!(motor_count, 2, "the drivetrain is exactly Motor(0)+Motor(1)");
            assert!(caps.iter().any(|c| c.kind == CapKind::Endpoint
                && c.perms == CapPerms::RW
                && c.target == MaybeStr::from_bytes(RESOURCE_MOTOR_0)));
            assert!(caps.iter().any(|c| c.kind == CapKind::Endpoint
                && c.perms == CapPerms::RW
                && c.target == MaybeStr::from_bytes(RESOURCE_MOTOR_1)));
        }
        else {
            assert_eq!(motor_count, 0, "no motor capability without the drivetrain");
        }
        assert!(caps.iter().any(|c| c.kind == CapKind::Device
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
