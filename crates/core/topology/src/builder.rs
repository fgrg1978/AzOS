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
    CapSpec, ClassSpec, MaybeStr, PolicyKind, PolicyScope, PolicySpec, Preemption, SchedConfig, Topology,
};

// ──────────────────────────────────────────────────────────────────────────
// Static literals — used as borrows in the resulting topology
// ──────────────────────────────────────────────────────────────────────────

const NAME_SAFETY: &[u8] = b"safety_critical";
const NAME_HARD_RT: &[u8] = b"hard_rt";
const NAME_SOFT_RT: &[u8] = b"soft_rt";
const NAME_BEST_EFFORT: &[u8] = b"best_effort";
const NAME_IDLE: &[u8] = b"idle";
/// The class of an interactive shell session: the interactive class
/// (`SchedClass::from_name`: fair-share at the latency QoS tier, reported as
/// `interactive`), and the one class whose tasks act as a human
/// user (`principal = "user"`), so the kernel labels them so and only they may
/// mint a declassification warrant (`endpoint::mint_badged_issued`).
const NAME_SESSION: &[u8] = b"session";

/// Classes the built-in topology declares: the five budget classes and
/// `session`. The Kconfig range of `TOPOLOGY_MAX_CLASSES` starts here, and this
/// asserts it again so a build whose limit is lower fails to compile instead of
/// panicking while the topology is filled at boot.
const BUILTIN_CLASSES: usize = 6;
const _: () = assert!(
    crate::types::MAX_CLASSES >= BUILTIN_CLASSES,
    "TOPOLOGY_MAX_CLASSES is below the classes of the built-in topology"
);

const TASK_SUPERVISOR: &[u8] = b"supervisor";
const TASK_BRAIN_LINK: &[u8] = b"brain_link";
// Migration phase P1: the autorun ELF (`kernel/src/tasks/loader.rs`'s
// `autorun_task`) is not spawned from a topology `TaskSpec` today — no
// name→spawn wiring exists yet, that's a separate piece of work — but its
// cap grants ARE looked up by this name (`find_task(b"autorun")`) so the
// P1 topology→cap_store bridge has something declarative to seed instead
// of the kernel hard-coding motor ids a second time.
const TASK_AUTORUN: &[u8] = b"autorun";
// Spawned processes look their row up by the IMAGE name
// (`spawn_policy`'s `topology_key = profile.image`, pinned by
// `tests/host/seccomp-tests`). No row was ever named after an image, so every
// `SYS_SPAWN_EX` since native spawn from a path landed seeded exactly nothing — the
// mechanism was wired
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
// `kernel/src/tasks/loader.rs`), which is capability-migration debt (phase P1) this crate
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
// three runs as `best_effort` at [`SERVICE_PRIORITY`], the number its row
// declares. Capabilities still come from `autorun` alone, as above.
const TASK_GPIODRV_IMAGE: &[u8] = b"GPIODRV.ELF";
const TASK_REFLEX_IMAGE: &[u8] = b"REFLEX.ELF";
const TASK_BRAINCLI_IMAGE: &[u8] = b"BRAINCLI.ELF";

/// The ring-3 inference service. Unlike the three rows above it is NOT an
/// `autorun` choice: the kernel's behavior task spawns it on every boot with
/// ML enabled (`kernel/src/behavior_ml.rs`), through the same path as
/// `SYS_SPAWN_EX`, so its capabilities come from THIS row, by image name. The
/// behavior task is also its client: it calls the `Infer` interface on
/// `endpoint.infer` with a capability the kernel mints for it
/// (`azos_syscall::kcall::endpoint_handle_badged`), not one a row grants.
const TASK_MLSRV_IMAGE: &[u8] = b"MLSRV.ELF";

// Wave 9 (DRV1): the ring-3 buzzer and INA219 drivers.
// Unlike the three rows above, these rows DO carry capabilities, and they are
// read: every row with `start = true` is started with `SYS_SPAWN_EX`'s
// machinery by the component manager, which seeds a child from the row named
// after its IMAGE. `start` is set only under `ring3-driver-start`
// (QEMU; see `crates/core/topology/Cargo.toml`). Each holds exactly what its
// device needs: the right to register as that one driver kind, and the one
// PWM channel or I2C slave behind it.
/// The buzzer ring-3 host's image, the name of its row.
pub const TASK_BUZZDRV_IMAGE: &[u8] = b"BUZZDRV.ELF";
/// The host the buzzer starts in: Kconfig `DRV_BUZZER_PLACEMENT`, which the
/// kernel feature `buzzer-kernel` forwards (the kernel host). The row of
/// `BUZZDRV.ELF` exists either way, and so does its `start = true`: the
/// component manager keeps the ring-3 host up whichever host the driver
/// starts in, so a driver that is moved (or demoted after a fault of the
/// kernel host) finds a ring-3 host already serving; the placement controller
/// only routes the kernel's calls (`kernel/src/buzzer.rs`).
pub const BUZZER_START_HOST: Host =
    if cfg!(feature = "buzzer-kernel") { Host::Kernel } else { Host::Ring3 };
/// The endpoint `BUZZDRV.ELF` serves the `Buzzer` interface on, and the
/// kernel calls it through (`azos_devif::buzzer::ENDPOINT`).
const RESOURCE_ENDPOINT_BUZZER: &[u8] = b"endpoint.buzzer";
/// The endpoints the ring-3 drivers serve `DevicePower` on, and the power
/// service calls (`azos_devif::power::runtime::ENDPOINT_PREFIX` and `DEVICES`;
/// this crate does not depend on `azos_devif`, `tests/host/topology-tests`
/// asserts the spellings agree). The driver's row holds `READ` (it serves); the
/// power row holds `EXEC`, which the kernel turns into the badge that carries
/// the device's key and the op classes of the grant (`cap_seed`). Ring 3 has no
/// by-name lookup for a task-hosted endpoint, so the power service finds each
/// one by that key.
const RESOURCE_ENDPOINT_PM_GPIO: &[u8] = b"endpoint.pm-gpio";
const RESOURCE_ENDPOINT_PM_INA: &[u8] = b"endpoint.pm-ina";
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
/// `INADRV.ELF`'s priority: `hard_rt`'s least urgent number, outside the band.
pub const INADRV_PRIORITY: u8 = 15;
/// `INADRV.ELF`'s EDF + CBS reservation. The period is the chip's sample
/// period, `1 / azos_ina219::INA219_POLL_HZ` (this crate does not depend on
/// the chip crate; `tests/host/topology-tests` asserts the two agree). The
/// budget, 5 ms of every 100 ms (5 % of one CPU), is far above one sample (a
/// few register-form `i2c` calls) and leaves room for the proxied reads a
/// period serves; the deadline is the period.
pub const INADRV_RT: crate::deadline::SchedProfile =
    crate::deadline::SchedProfile { period_us: 100_000, runtime_us: 5_000, deadline_us: 0, cpu_mask: 0 };
/// `DRV_KIND_POWER_MON` (0x0011) in decimal.
const RESOURCE_DRV_POWER_MON: &[u8] = b"drv.17";
/// Frame budget of one `ABICHILD.ELF` process, in topology pages (4 KiB,
/// `memory::TOPOLOGY_PAGE`): 128, i.e. its image, a stack, the pages a mode
/// touches (at most eight of break) and the tables, at 4 KiB frames. Under a
/// larger base page that is too few frames (128 units are eight 64 KiB frames,
/// and a child's image text, rodata and data, stack and tables take all eight,
/// so its first `mmap` was refused): the row is then given
/// [`ABICHILD_MIN_FRAMES`] whole frames, the same floor rule as
/// [`RING3_SMALL_ROW_PAGES`]. Nothing changes at 4 KiB or 16 KiB.
#[cfg(feature = "ipc-endpoint-canary")]
const ABICHILD_MEM_PAGES: u32 = {
    let floor = crate::memory::units_for(ABICHILD_MIN_FRAMES, 1u64 << azos_limits::PAGE_SHIFT);
    if floor > 128 { floor as u32 } else { 128 }
};
/// Frames a child needs whatever the base page: eight for its image, stack and
/// tables, eight for what a mode touches.
#[cfg(feature = "ipc-endpoint-canary")]
const ABICHILD_MIN_FRAMES: u64 = 16;
/// Live `ABICHILD.ELF` processes at once: a process tree (`tree`,
/// `subreaper`) holds three, a spawn that follows a child's exit can overlap
/// its teardown.
#[cfg(feature = "ipc-endpoint-canary")]
const ABICHILD_INSTANCES: u16 = 8;
/// Room for the autorun row's grants: its fixed list, which depends on the
/// features.
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
/// Budget of the `MLSRV.ELF` row, in topology pages: a small row's, plus what
/// its stack holds beyond the 16 KiB a small row counts: the 64 KiB main stack
/// the image asks for (`PT_GNU_STACK`, userspace/services/infsrv/build.rs: 12
/// pages more), which serves the endpoint now that the second, 44 KiB thread
/// (11 pages of `.bss`) is gone, and 4 pages kept until the row is measured on
/// a booted machine. The 64 pages of a small row were full already: image, the
/// 16 KiB stack, tables and the 64 KiB blob arena.
const MLSRV_MEM_PAGES: u32 = RING3_SMALL_ROW_PAGES + 16;

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

/// The virtual-machine monitor's control endpoint: `VMMD.ELF` serves the `VmCtl`
/// object on it (`READ`), `NAMESD.ELF` holds the call right to lend (`WRITE`,
/// `transfer`) and the tool image whose row imports `vmctl` (`TOOLBOX.ELF`,
/// the `vm` command) is lent a derived, call-only capability. Present with
/// the monitor's row ([`VMMD_ROW`]).
const RESOURCE_ENDPOINT_VMCTL: &[u8] = b"endpoint.vmctl";

/// The input endpoint: `INPUTD.ELF` serves the `Input` object on it (`READ`),
/// holds the call right with `transfer` on it (the capability its warrants are
/// derived from), and `TOOLBOX.ELF` calls it (`WRITE`: `input watch`). See
/// `azos_devif::input`.
const RESOURCE_ENDPOINT_INPUT: &[u8] = b"endpoint.input";
/// The compositor's endpoint: `COMPSRV.ELF` serves the `Compositor` object on it
/// (`READ`), and `TOOLBOX.ELF` calls it (`WRITE`: `window`). See
/// `azos_compositor`.
const RESOURCE_ENDPOINT_COMPOSITOR: &[u8] = b"endpoint.compositor";

/// The decisions endpoint: `DECISD.ELF` serves the `Decisions` object on it
/// (`READ`), `WHY.ELF` calls it (`WRITE`). Like `endpoint.term`, ring 3 finds
/// it by scanning the one endpoint capability its row holds.
const RESOURCE_ENDPOINT_DECISIONS: &[u8] = b"endpoint.decisions";

/// The `memctl` endpoint (`azos_devif::memctl`): the owner of a volatile
/// memory object says when reclaim may take it. `WRITE` is the right to change
/// that (`MLSRV.ELF` holds it, for its blob arena).
const RESOURCE_MEMCTL: &[u8] = b"memctl";

/// The inference endpoint: `MLSRV.ELF` (the inference broker) serves the
/// `Infer`, `Decisions` and `InferLog` interfaces on it (`READ`). The clients
/// are the rows of a deployment that call a model (`WRITE`, added by its
/// signed topology): a call carries the badge of the row that made it, and
/// that badge is the context the broker admits, accounts and answers.
const RESOURCE_ENDPOINT_INFER: &[u8] = b"endpoint.infer";

// Matches the legacy `HandleKind::Motor(0)`/`Motor(1)` RW grant the autorun
// seed already makes (`kernel/src/tasks/loader.rs`) — dual-mode migration, both
// paths grant identical authority. `motor.N` is the topology's target
// convention.
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
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_0), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(RESOURCE_MOTOR_1), transfer: false, ops: 0,
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
/// The ops of `linkkey` a task that needs only its own node identity may call:
/// `LinkKey::node_key`, the second op of the interface (bit n = op n, counted
/// from 1). Restated here because this crate does not depend on `azos_devif`;
/// `tests/host/topology-tests` holds it to `azos_devif::linkkey::NODE_KEY_OPS`.
pub const LINK_KEY_NODE_KEY_OPS: u64 = 1 << 2;
/// The grant of a task that needs its own node identity (`LinkKey::node_key`:
/// `RPCSRV.ELF`, `MCPD.ELF`): `READ` on `linkkey` with an op mask
/// that lists `node_key` and nothing else. `READ` unmasked also calls
/// `LinkKey::read`, the raw reserved-sector key, which is the device seed every
/// node key derives from; only `brain_client` (the link itself) holds it that
/// way. A compromised network-facing task with this grant can ask for its own
/// image's key and cannot read the seed: the kernel holds every call through
/// the capability to the mask before the interface runs.
const LINK_KEY_IDENTITY: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_LINK_KEY), transfer: false, ops: LINK_KEY_NODE_KEY_OPS,
};
// The kernel-hosted `keys` interface (`azos_devif::keys`): the bare interface
// name, no resource (the keystore is per owner, and the owner is the caller's).
const RESOURCE_KEYS:       &[u8] = b"keys";
/// The ops of `keys` a task that opens its signing key, reads the public part and
/// signs may call: `generate`, `public` and `sign`, the first, fourth and fifth
/// ops of the interface (bit n = op n, counted from 1). Restated here because this
/// crate does not depend on `azos_devif`; `tests/host/topology-tests` holds it to
/// `azos_devif::keys::SIGNER_OPS`.
pub const KEYS_SIGNER_OPS: u64 = 1 << 1 | 1 << 4 | 1 << 5;
/// The grant of a task that signs with a key the kernel keeps (`SSHD.ELF`: its
/// host key): `READ` (the public part, the signature) and `WRITE` (to open the
/// key) on `keys`, with an op mask that lists those three ops and nothing else.
/// The task cannot bring a key of its own in, derive from one, wrap one so that it
/// leaves, or destroy one: the kernel holds every call through the capability to
/// the mask before the interface runs. `EXEC` (wrapping) is not granted at all.
const KEYS_SIGNER: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(RESOURCE_KEYS), transfer: false, ops: KEYS_SIGNER_OPS,
};
/// The one op of `keys` the login service may call: `login`, the eleventh op
/// of the interface (bit n = op n, counted from 1). Restated here because this
/// crate does not depend on `azos_devif`; `tests/host/topology-tests` holds it
/// to `azos_devif::keys::LOGIN_OPS`.
pub const KEYS_LOGIN_OPS: u64 = 1 << 11;
/// The grant of the login service on `keys`: `EXEC` (the right `login` needs)
/// with an op mask that lists `login` and nothing else. The task cannot make,
/// use, wrap or destroy a key: the kernel holds every call through the
/// capability to the mask before the interface runs.
const KEYS_LOGIN: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(RESOURCE_KEYS), transfer: false, ops: KEYS_LOGIN_OPS,
};
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
// it is (the hardware bus resolves the selector to the device the
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
// Wave 8: the PL031, `irq.34` (SPI 2). riscv64 (wave 9 IRQ4): the goldfish
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
// `block.part.1`, READ|WRITE: partition 1 of the table
// the kernel published — on the gate's partitioned image
// (`$AZOS_OUT/build/disk-parted.img`) a 64-sector raw partition after the FAT32 one — so
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
// nothing in ring 3 there changes the tree, and a grant is authority. (Every
// row does hold the read-only root directory, `ROOT_RO`: it names, it changes
// nothing.)
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

/// The `energy-gov-smoke` row's model: the same domains
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
/// Five budget classes + two seed tasks (`supervisor`,
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
    // Five budget classes with default budgets summing to exactly 100 %, and
    // the `session` class (no reserved share).
    let classes: [(&[u8], ClassSpec); BUILTIN_CLASSES] = [
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
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::System,
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
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::System,
            },
        ),
        (
            NAME_SOFT_RT,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_SOFT_RT),
                cpu_budget_min_pct: 25,
                cpu_budget_max_pct: 60,
                policy: PolicyKind::Fair,
                priority_range: (16, 23),
                preemption: Preemption::TimerOnly,
                time_slice_ms: 10,
                admission_control: false,
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::System,
            },
        ),
        (
            NAME_BEST_EFFORT,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_BEST_EFFORT),
                cpu_budget_min_pct: 20,
                cpu_budget_max_pct: 100,
                policy: PolicyKind::Fair,
                priority_range: (24, 30),
                preemption: Preemption::TimerOnly,
                time_slice_ms: 0,
                admission_control: false,
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::System,
            },
        ),
        (
            NAME_IDLE,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_IDLE),
                cpu_budget_min_pct: 5,
                cpu_budget_max_pct: 5,
                policy: PolicyKind::Idle,
                priority_range: (31, 31),
                preemption: Preemption::Never,
                time_slice_ms: 0,
                admission_control: false,
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::System,
            },
        ),
        // Last, so no class index another test pins moves. No reserved
        // share (the five above already sum to 100 %): it draws on what
        // `best_effort` may, over the same priority range.
        (
            NAME_SESSION,
            ClassSpec {
                name: MaybeStr::from_bytes(NAME_SESSION),
                cpu_budget_min_pct: 0,
                cpu_budget_max_pct: 100,
                policy: PolicyKind::Fair,
                priority_range: (24, 30),
                preemption: Preemption::TimerOnly,
                time_slice_ms: 0,
                admission_control: false,
                envelope: crate::types::Envelope::Full,
                principal: crate::types::PrincipalKind::User,
            },
        ),
    ];

    for (_, c) in classes.iter() {
        topo.push_class(*c)
            .expect("default_minimal_topology: too many classes");
    }

    // The built-in topology is the development one: the classes its tasks run
    // in may delete stored data, send a first packet anywhere, write any
    // configuration key, apply an update and reserve as much of a hart as the
    // scheduler admits (`full`), as every image did before the effect gate held
    // those kinds to a row. The rows say so; a signed topology that wants a
    // Domain held declares the class and its rows (`delete`, `egress`,
    // `config`, `ota`, `rt_time`; Documentation/effects.md, "Storage and
    // network envelopes" and "Configuration, update and real-time-time
    // envelopes"). `safety_critical`, `hard_rt` and `idle` run no task that
    // deletes, sends, writes configuration or applies an update, and their
    // reservations are the kernel's own (`rt_smoke`, the loops of
    // `safety_critical`): they have no row, and no row is `full` too.
    for (class, names) in [
        (NAME_SOFT_RT, [b"dev_del_soft_rt" as &[u8], b"dev_out_soft_rt", b"dev_cfg_soft_rt", b"dev_ota_soft_rt", b"dev_rt_soft_rt"]),
        (NAME_BEST_EFFORT, [b"dev_del_best_effort" as &[u8], b"dev_out_best_effort", b"dev_cfg_best_effort", b"dev_ota_best_effort", b"dev_rt_best_effort"]),
        (NAME_SESSION, [b"dev_del_session" as &[u8], b"dev_out_session", b"dev_cfg_session", b"dev_ota_session", b"dev_rt_session"]),
    ] {
        use crate::types::EffectKind;
        let kinds = [EffectKind::Delete, EffectKind::Egress, EffectKind::Config, EffectKind::Ota, EffectKind::RtTime];
        for (name, kind) in names.into_iter().zip(kinds) {
            topo.push_envelope(crate::types::EnvelopeSpec {
                name: MaybeStr::from_bytes(name),
                kind,
                class: MaybeStr::from_bytes(class),
                level: crate::types::Envelope::Full,
            })
            .expect("default_minimal_topology: envelope push failed");
        }
    }

    // Tasks. Two seed tasks: a safety supervisor + the brain-link.
    topo.push_task(
        MaybeStr::from_bytes(TASK_SUPERVISOR),
        MaybeStr::from_bytes(NAME_SAFETY),
        0,
        &[],
    )
    .expect("default_minimal_topology: supervisor push failed");

    // A kernel task's row (read for admission, never applied); its number is
    // still one its class has, so no row of this topology relies on the clamp.
    topo.push_task(
        MaybeStr::from_bytes(TASK_BRAIN_LINK),
        MaybeStr::from_bytes(NAME_BEST_EFFORT),
        SERVICE_PRIORITY,
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
                target: MaybeStr::from_bytes(RESOURCE_DRV_GPIO), transfer: false, ops: 0,
        },
            // The three hardware families — see the resource constants above
            // for why each target was chosen, and why the two motor-bound ones
            // are declared only under `cap-refusal-canary`.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_FREE), transfer: false, ops: 0,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_PWM_MOTOR), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_FREE), transfer: false, ops: 0,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_GPIO_MOTOR), transfer: false, ops: 0,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RO), transfer: false, ops: 0,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_MMIO_RTC_RW), transfer: false, ops: 0,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART1), transfer: false, ops: 0,
        },
            #[cfg(feature = "disk-part-row")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_DISK_PART0), transfer: false, ops: 0,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Node,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_FAT), transfer: false, ops: 0,
        },
            #[cfg(feature = "cap-refusal-canary")]
            CapSpec {
                kind: CapKind::Node,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(RESOURCE_TREE_TMP), transfer: false, ops: 0,
        },
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_RTC), transfer: false, ops: 0,
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
                target: MaybeStr::from_bytes(RESOURCE_I2C_IMU), transfer: false, ops: 0,
        },
            // READ only: the legacy seed grants these `HandlePerms::RO` and a
            // sensor read is a read. Granting WRITE would make the typed path
            // carry authority the untyped one never had.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[0]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[1]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[2]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[3]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[4]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[5]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[6]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[7]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[8]), transfer: false, ops: 0,
        },
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_SENSORS[9]), transfer: false, ops: 0,
        },
            // U06-9 (2026-09-26): the ring-3 door onto the reserved-sector
            // brain-link PSK (the kernel-hosted `linkkey` endpoint). `brain_client` is
            // the one holder that reads it; every other autorun program
            // (`GPIODRV.ELF`/`REFLEX.ELF`) simply never calls the syscall
            // this grants no more authority to use than
            // the read-only root directory every row holds already gives them
            // over the rest of `/fat`. READ only — there is no write path, the key is
            // provisioned at image-build time, never by a running task.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_LINK_KEY), transfer: false, ops: 0,
        },
            // Wave 9 (P9), an endpoint op since D6 part A: the kernel-hosted
            // `entropy` interface (`azos_devif::Entropy`), the source of
            // `brain_client`'s ephemeral handshake keys. READ only (the op
            // class that draws), never transferable.
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0,
        },
            // The CALLER half of the demo endpoint. `WRITE` is
            // "may send a request", and nothing more — it claims no service
            // and cannot destroy one.
            #[cfg(feature = "ipc-endpoint-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DEMO), transfer: false, ops: 0,
        },
            // AFTER the demo endpoint, never before — see
            // `RESOURCE_ENDPOINT_BENCH` for what depends on that.
            #[cfg(feature = "ipc-endpoint-canary")]
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BENCH), transfer: false, ops: 0,
        },
            // Last, so no earlier grant changes slot (wave 10 IRQ5).
            #[cfg(all(feature = "cap-refusal-canary", topo_bare))]
            CapSpec {
                kind: CapKind::Device,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_IRQ_ABSENT), transfer: false, ops: 0,
        },
            // The root directory, read-only ([`ROOT_RO`]): the programs this
            // row hosts (the conformance and benchmark images, `relibc`
            // programs) open the files they always read beneath it. The write
            // trees above (`cap-refusal-canary`) are what lets one change any.
            ROOT_RO,
    ];
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
            target: MaybeStr::from_bytes(image), transfer: false, ops: 0,
        };
        n += 1;
    }
    // With Kconfig INSPECT, the introspection regions, last: the conformance
    // images read the kernel's devices there (`captest` finds a device's
    // handle in `devices/`) and watch the process trees they start in the
    // admin task list (`abitest`), granted against the task view listed
    // first; and `abitest` checks that a row which declares no view region is
    // granted none.
    if azos_limits::INSPECT {
        autorun_caps[n] = TASK_VIEW_CAP;
        autorun_caps[n + 1] = INSPECT_PUBLIC_CAP;
        n += 2;
        if azos_limits::INSPECT_ADMIN_PAGES != 0 {
            autorun_caps[n] = INSPECT_ADMIN_CAP;
            n += 1;
        }
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
    // Wave 8: the budget now covers EVERY frame the task holds
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

    // `CAPTEST.ELF`'s own row (feature `captest-row`): the shape of a ring-3
    // driver row that binds an interrupt line. With Kconfig `IRQ_THREADED` the
    // bind (`DEVICE_IRQ_BIND`) is refused for a task without a hard
    // reservation, and the generic `autorun` row declares none, so captest's
    // IRQ section ran against a rule its row could never satisfy. This row
    // declares one, and the budget rule is exercised as in production: the bind
    // is admitted on the reservation, the line is routed to its CPU, and the
    // whole program (it is the handler) runs inside the budget.
    //
    // * `hard_rt`, priority 12: the ring-3 floor, outside the band
    //   (`RT_BAND_THRESHOLD`), so the reservation needs no `mem = "locked"`.
    //   Locked is not available to this image anyway: its seccomp row is in
    //   audit mode (the raw probe of the retired `SYS_CAP_GRANT`, and the
    //   gate's `[AUTORUN] seccomp: ... (audit mode)` check), and
    //   `locked_compatible` refuses an audit-mode image a locked row.
    // * 5 ms of every 10 ms (50 % of one CPU, inside `hard_rt`'s 60 %): captest
    //   is the handler, so a smaller share would only slow the whole program
    //   down by its inverse; it is large enough that the 100 ms windows of the
    //   IRQ section (line held masked, second delivery) are not cut by a
    //   throttle.
    // * `cpu_mask` = CPU 3, the CPU the autorun loader is pinned to
    //   (`AUTORUN_HART`): `rt::reserve` places a pinned task on its pin only.
    //   A mask names real CPUs, and the install-time and boot admissions
    //   refuse a topology whose mask names none the board has (rows
    //   `topology: deadlines need real harts`), so the row exists only in the
    //   gate builds that boot captest on four CPUs.
    // * 512 pages, the autorun row's accounting for an image that peaks at
    //   19 pages beyond its heap use; caps still come from the `autorun` row.
    #[cfg(feature = "captest-row")]
    {
        topo.push_task_profiled(
            MaybeStr::from_bytes(b"CAPTEST.ELF"),
            MaybeStr::from_bytes(NAME_HARD_RT),
            12,
            &[],
            crate::deadline::SchedProfile { period_us: 10_000, runtime_us: 5_000, deadline_us: 0, cpu_mask: 1 << 3 },
        )
        .expect("default_minimal_topology: CAPTEST.ELF push failed");
        topo.set_last_task_mem_pages(512);
    }

    topo.set_sched_config(SchedConfig {
        partition_window_us: 10_000,
        isolcpus: 0,
    });

    // The hardware bus rows of this image (`BUILTIN_DEVICE_ROWS`).
    for (name, select) in BUILTIN_DEVICE_ROWS {
        topo.push_device(crate::types::DeviceSpec {
            name: MaybeStr::from_bytes(name),
            select: MaybeStr::from_bytes(select),
            admit: true,
            driver: MaybeStr::from_bytes(&[]),
            ..crate::types::DeviceSpec::empty()
        })
        .expect("default_minimal_topology: device row push failed");
    }

    // Question 1 (assistant default, owner to confirm): the energy
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
    // The SERVER half, and the first topology row named after
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
    //
    // At [`AUTORUN_SERVER_PRIORITY`], one above its client `autorun`: every
    // server outranks its clients (`Topology::server_not_above_client`).
    #[cfg(feature = "ipc-endpoint-canary")]
    topo.push_task(
        MaybeStr::from_bytes(TASK_EPSRV_IMAGE),
        MaybeStr::from_bytes(NAME_HARD_RT),
        AUTORUN_SERVER_PRIORITY,
        &[CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::READ,
            target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DEMO), transfer: false, ops: 0,
        }],
    )
    .expect("default_minimal_topology: EPSRV.ELF push failed");

    // The benchmark's server. `vsbench`'s IPC lane
    // used a `fork()`ed child, which can never be addressed by capability: a
    // forked child inherits no capability table and the endpoint's owner is
    // fixed when the capability is SEEDED, by image name. Retiring
    // `SYS_IPC_FAST_CALL` therefore needed the peer to become an image.
    //
    // **At [`AUTORUN_SERVER_PRIORITY`], one above its client** (owner decision
    // 2026-10-23: every server strictly outranks its clients). `vsbench` runs
    // under the `autorun` row (16). From wave 7 the row shared its client's
    // bucket (`soft_rt` 16), because across buckets the `ipc-roundtrip` lane
    // measures a cross-bucket hand-off as well as the IPC path: with
    // `-icount`, 2277 -> 2403 instructions on aarch64 and 2659 -> 2789 on
    // riscv64 at 24 (cause not isolated; a likely one: across buckets the
    // direct switch's paired histogram re-account no longer cancels,
    // `ipc_direct::pair_cancels`). The owner accepts that cost; at 15 against
    // 16 it is 2306 -> 2608 instructions per round trip on riscv64
    // (`VSBENCH_ICOUNT=1 VSBENCH_SMP=1`, bench-minimal kernel; 9893 -> 9943
    // ns/op on the product kernel), 2026-10-23.
    #[cfg(feature = "ipc-endpoint-canary")]
    topo.push_task(
        MaybeStr::from_bytes(TASK_VSSRV_IMAGE),
        MaybeStr::from_bytes(NAME_HARD_RT),
        AUTORUN_SERVER_PRIORITY,
        &[
            CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BENCH), transfer: false, ops: 0,
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
                target: MaybeStr::from_bytes(RESOURCE_DRV_POWER_MON), transfer: false, ops: 0,
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
    //
    // Each program row below exists when the volume carries its image
    // (Kconfig `USERSPACE_<IMAGE>`): always outside a small board, where
    // these images are not a choice; on one (HWCLASS_EMBEDDED) only what the
    // topology starts and what the config names. A row for an image the build
    // does not carry would hold authority nothing can use and be charged
    // memory admission for a program that cannot run (robot-embedded: 1344 of
    // its 1680 ceiling pages, and a 16 MiB board refused at boot).
    if azos_limits::USERSPACE_GPIODRV {
        topo.push_task(
            MaybeStr::from_bytes(TASK_GPIODRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            SERVICE_PRIORITY,
            // It serves `DevicePower` for the power service (runtime PM).
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PM_GPIO), transfer: false, ops: 0,
            }],
        )
            .expect("default_minimal_topology: GPIODRV.ELF push failed");
    }
    if azos_limits::USERSPACE_REFLEX {
        topo.push_task(MaybeStr::from_bytes(TASK_REFLEX_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, &[])
            .expect("default_minimal_topology: REFLEX.ELF push failed");
    }
    if azos_limits::USERSPACE_BRAINCLI {
        topo.push_task(MaybeStr::from_bytes(TASK_BRAINCLI_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, &[ROOT_RO])
            .expect("default_minimal_topology: BRAINCLI.ELF push failed");
    }

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
    // Its capabilities: serve `endpoint.infer` (the broker), mark its blob
    // arena droppable (`memctl`), and read the model files.
    //
    // 80 pages (320 KiB) of frames: its image, its stack (64 KiB,
    // `MLSRV_MEM_PAGES`) and page tables, the policy-file buffer in `.bss`, and
    // the blob arena (a volatile memory object, `INFSRV_BLOB_KIB`); it never
    // grows a heap.
    if azos_limits::USERSPACE_MLSRV {
        topo.push_task(
            MaybeStr::from_bytes(TASK_MLSRV_IMAGE),
            MaybeStr::from_bytes(NAME_SOFT_RT),
            16,
            &[
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_INFER), transfer: false, ops: 0,
                },
                // Marks its blob arena droppable between calls.
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::WRITE,
                    target: MaybeStr::from_bytes(RESOURCE_MEMCTL), transfer: false, ops: 0,
                },
                // Reads the model file it is told to load.
                ROOT_RO,
            ],
        )
        .expect("default_minimal_topology: MLSRV.ELF push failed");
        topo.set_last_task_mem_pages(MLSRV_MEM_PAGES);
    }

    // Wave 9 (DRV1) — the ring-3 drivers; see `TASK_BUZZDRV_IMAGE`. After the
    // board rows, so no index-pinned row above moves.
    //
    // **The buzzer: `best_effort` at [`SERVICE_PRIORITY`] (24), like
    // GPIODRV.ELF** (owner decision 2026-09-28; wave 9 had the drivers at
    // `soft_rt` 16; the INA219's row below has a reservation instead): above the
    // interactive session ([`SH_PRIORITY`], 26), never equal to it. A client
    // more urgent than the driver donates its priority for the span of each
    // request (`UserDriverProxy`), so a request is served at the client's
    // priority (down to the ring-3 floor, 12): that donation, not the row, is
    // what keeps `autorun` (16) from waiting on a driver below it. What 24
    // gives up is the driver's own timing outside a request: a CPU-bound task
    // above 24 on its hart delays the end of a buzzer tone (measured once on
    // aarch64 QEMU at boot: a 50 ms tone switched off after 1578 ms), and
    // delayed INA219 samples when that driver was here too. The mAh sum does
    // not depend on that cadence: each sample is weighted by the time the
    // driver measured since the previous one (wave 10).
    // The buzzer's ring-3 host. Its row exists whichever host the driver
    // starts in (`BUZZER_START_HOST`): the row is what the ring-3 host runs
    // with when the driver is, or is moved, there. `stateless`: the driver
    // keeps nothing a restart cannot rebuild, so it may move between its two
    // hosts at run time (`placement`); `call_budget_us` is the deadline a
    // call to it is held to.
    if azos_limits::USERSPACE_BUZZDRV {
        topo.push_task(
            MaybeStr::from_bytes(TASK_BUZZDRV_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            SERVICE_PRIORITY,
            &[
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_BUZZER), transfer: false, ops: 0,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_PWM_BUZZER), transfer: false, ops: 0,
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
        // Started at boot by the component manager whichever host the driver
        // starts in (see [`BUZZER_START_HOST`]): the ring-3 host is the
        // standby of a driver placed in the kernel.
        #[cfg(all(feature = "ring3-driver-start", not(feature = "ring3-driver-start-canary")))]
        topo.set_last_task_start(true);
        // Gate only (`restart-smoke`): `restart = no`, so not even a kill of
        // the buzzer driver is restarted.
        #[cfg(feature = "restart-smoke")]
        topo.set_last_task_restart(crate::types::RestartPolicy::No);
    }
    // Wave 11 (DRVPLACE): the INA219's ring-3 host has a row only when the
    // driver is placed in ring 3 ([`INADRV_ROW`]). Placed in the kernel, the
    // row would be a dormant grant of the `i2c` endpoint on its chip to an image the
    // kernel does not run.
    //
    // **The one ring-3 row with a real-time reservation** ([`INADRV_RT`]): the
    // driver's main thread is a periodic sampler (one sample of the chip per
    // `1 / INA219_POLL_HZ`, parked between samples), the workload EDF + CBS is
    // for, and `best_effort` let any CPU-bound task above it delay its samples
    // (see the drivers' comment above). `hard_rt` at 15, its least urgent
    // number: outside the band (`RT_BAND_THRESHOLD`), so the reservation
    // needs no `mem = "locked"`, and its unreserved `DevicePower` thread is the
    // least urgent a `hard_rt` task can be. Boot admission places the
    // reservation on a CPU (`cpu_mask` 0: any) and the task is pinned there
    // (`topo_sched::row_reservation`); the hard CBS caps what a runaway or a
    // flood of proxied reads can take to the reservation's share.
    if INADRV_ROW && azos_limits::USERSPACE_INADRV {
        topo.push_task_profiled(
            MaybeStr::from_bytes(TASK_INADRV_IMAGE),
            MaybeStr::from_bytes(NAME_HARD_RT),
            INADRV_PRIORITY,
            &[
                CapSpec {
                    kind: CapKind::Device,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_DRV_POWER_MON), transfer: false, ops: 0,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(RESOURCE_I2C_INA219), transfer: false, ops: 0,
                },
                // It serves `DevicePower` for the power service (runtime PM).
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PM_INA), transfer: false, ops: 0,
                },
            ],
            INADRV_RT,
        )
        .expect("default_minimal_topology: INADRV.ELF push failed");
        topo.set_last_task_mem_pages(RING3_DRIVER_MEM_PAGES);
        #[cfg(feature = "ring3-driver-start")]
        topo.set_last_task_start(true);
    }

    // Gate row: `UHELLO.ELF` as a `mem = "locked"` row. Its
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

    // A locked row on an image whose seccomp profile may fork
    // (`ABITEST.ELF`, audit mode). The loader must refuse to run it under a
    // locked row.
    #[cfg(feature = "mem-locked-refusal-canary")]
    {
        topo.push_task(MaybeStr::from_bytes(b"ABITEST.ELF"), MaybeStr::from_bytes(NAME_SOFT_RT), 16, &[])
            .expect("default_minimal_topology: ABITEST.ELF push failed");
        topo.set_last_task_mem_pages(2048);
        topo.set_last_task_mem_locked(true);
    }

    // Canary: one ring-3 row whose ceiling alone is 4 GiB, more
    // than any board this builds for. Memory admission must refuse the
    // topology and the kernel must halt before the first ring-3 task.
    #[cfg(feature = "mem-admission-canary")]
    {
        topo.push_task(MaybeStr::from_bytes(b"HOG.ELF"), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, &[])
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

    // Wave 11: the user shell and its multicall tool image, pushed
    // after every other row (feature-gated ones included) so no index another
    // test pins moves. Both are real board programs, so the board volume
    // ships them (`board_elfs`), and both have their row when it does.
    //
    // `SH.ELF` holds no hardware authority: a command's authority is the row
    // of the image that runs it. What it holds is what the shell itself does:
    // the right to start `TOOLBOX.ELF` (`Cap<Launch>`, `SYS_SPAWN_EX` checks
    // it against the image the file's digest resolves to), and the directory
    // trees its redirections and `mkdir`/`rm` change (`/fat` and `/tmp`; only
    // `/tmp` under `CONSOLE_LOCKDOWN`). `start` follows Kconfig `USER_SHELL`;
    // the kernel launches this row after every other `start = true` row.
    //
    // The shell is the interactive session, so its class is `session`: the
    // kernel gives the task the user principal (`apply_principal`), the only
    // way a task acts as one. A tool it starts runs under its own row.
    //
    // Priorities (lower = more urgent): the shell (26) below every server of
    // the session (the terminal server it calls, 25, and the login and name
    // servers, 24) and above every tool it starts (27). ^C does not depend on them:
    // the console's RX interrupt delivers it to the foreground job itself
    // (`console_signal`). The order keeps a tool from out-ranking its
    // spawner (`fork_child_entry` also yields until the spawner publishes its
    // hand-off). Gate row `sh: ctrl-c on one hart`.
    if azos_limits::USERSPACE_SH {
        topo.push_task(
            MaybeStr::from_bytes(TASK_SH_IMAGE),
            MaybeStr::from_bytes(NAME_SESSION),
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
        // SUBTREE-POLICY: the shell's jobs are clients. A job is a Domain beneath
        // the shell's, so this `subtree` row binds every program the shell starts
        // (and the shell) and creates no endpoint and no port, whatever its row
        // grants: a program typed at a prompt joins services other rows start, it
        // does not become one. What the shell can launch is its `Cap<Launch>`
        // list (`SH_CAPS_*`): the tool images, `PKG.ELF` and the Linux rows, none
        // of which creates either object. MemObjs are not limited (`PKG.ELF` sizes
        // one by the package). The kernel binds the row when it spawns the shell
        // (`families::install_policy`); a signed CAPS.TOM replaces it with its own.
        topo.push_policy(PolicySpec {
            name: MaybeStr::from_bytes(b"shjobs"),
            domain: MaybeStr::from_bytes(TASK_SH_IMAGE),
            scope: PolicyScope::Subtree,
            create_endpoints: false,
            create_ports: false,
            memobj_max_pages: 0,
        })
        .expect("default_minimal_topology: SH.ELF policy push failed");
    }
    // The tool image. It reads and writes the descriptors and pipe ends the
    // shell MOVES to it, and opens files beneath the read-only root directory. Its
    // capabilities are the full task view, for `ps` (wave 12), and with
    // Kconfig INSPECT the introspection regions, for `inspect`: none of them
    // under `CONSOLE_LOCKDOWN`.
    if azos_limits::USERSPACE_TOOLBOX {
        topo.push_task(
            MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE),
            MaybeStr::from_bytes(NAME_BEST_EFFORT),
            TOOL_PRIORITY,
            if azos_limits::CONSOLE_LOCKDOWN { TOOLBOX_CAPS_LOCKDOWN } else { TOOLBOX_CAPS },
        )
            .expect("default_minimal_topology: TOOLBOX.ELF push failed");
        topo.set_last_task_mem_pages(TOOLBOX_MEM_PAGES);
        // The `vm` command (Kconfig HV) launches a guest through the monitor's
        // `VmCtl`: the row imports `vmctl`, and the name server lends the call
        // right on `endpoint.vmctl`. Not under `CONSOLE_LOCKDOWN`, which withholds
        // every grant beyond the shell's own work from the console path.
        if VMMD_ROW && !azos_limits::CONSOLE_LOCKDOWN {
            topo.set_last_task_imports(TOOLBOX_IMPORTS)
                .expect("default_minimal_topology: TOOLBOX.ELF imports");
        }
        // A pipeline runs one instance per stage, and background jobs add more.
        topo.set_last_task_instances(TOOLBOX_INSTANCES);
    }
    // The first privileged family: `POWER.ELF` (`power suspend`,
    // `reboot`, `shutdown`, `sched_hz`). Its row is the whole of its
    // authority: the `power` endpoint (WRITE, and READ for the rate read), whose
    // ops check their class on every call. The shell holds only the right to start it, and not under
    // `CONSOLE_LOCKDOWN` (`SH_CAPS_LOCKDOWN`), so a locked-down shell is
    // refused at `SYS_SPAWN_EX`, recorded, not merely missing a PATH entry.
    if azos_limits::USERSPACE_POWER {
        topo.push_task(MaybeStr::from_bytes(TASK_POWER_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, POWER_CAPS)
            .expect("default_minimal_topology: POWER.ELF push failed");
        topo.set_last_task_mem_pages(POWER_MEM_PAGES);
        // `power serve` is a housekeeping loop: it re-checks the policy once a
        // period, and nobody waits on that wake-up. It declares itself
        // `QOS_BACKGROUND` and its row lets that tier's timer slack apply
        // (QOS_TIMER_TOLERANCE_ROWS_ONLY: the robot, industrial and automotive
        // presets give slack only to rows that say so).
        topo.set_last_task_timer_slack(true);
    }
    // Wave 12: the other privileged families, one tool each, the POWER.ELF
    // pattern: each row is the whole of its tool's authority, checked by its
    // family's typed call on every call, and the shell holds only the right
    // to start them, not under `CONSOLE_LOCKDOWN`.
    for (image, caps, shipped) in [
        (TASK_FLIGHT_IMAGE, FLIGHT_CAPS, azos_limits::USERSPACE_FLIGHT),
        (TASK_BEHAVIOR_IMAGE, BEHAVIOR_CAPS, azos_limits::USERSPACE_BEHAVIOR),
        (TASK_CONFIG_IMAGE, CONFIG_CAPS, azos_limits::USERSPACE_CONFIG),
        (TASK_OTA_IMAGE, OTA_CAPS, azos_limits::USERSPACE_OTA),
    ] {
        if !shipped {
            continue;
        }
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
    if azos_limits::USERSPACE_TRACECTL {
        topo.push_task(MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, TRACECTL_CAPS)
            .expect("default_minimal_topology: TRACECTL.ELF push failed");
        topo.set_last_task_mem_pages(TRACECTL_MEM_PAGES);
        topo.set_last_task_instances(TRACECTL_INSTANCES);
    }
    // The terminal server (`userspace/services/termd`, the Terminal object):
    // the console program of the native shell session. Its row is its whole
    // authority, `READ` on `endpoint.term` (it serves it); console input it
    // claims by `LOG_CONSOLE_WAIT`, as the shell did. The shell's row holds
    // `WRITE` on the same name. At [`CLIENT_SERVICE_PRIORITY`]: above the
    // shell it serves, so the interrupt key is read more promptly than the
    // shell runs, and below the login server it calls. `start` follows the console program
    // (below); `on-failure` like the shell: `hangup` ends it with code 0 and
    // gives the console back to the kernel shell.
    if azos_limits::USERSPACE_TERMD {
        topo.push_task(MaybeStr::from_bytes(TASK_TERMD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), CLIENT_SERVICE_PRIORITY, TERMD_CAPS)
            .expect("default_minimal_topology: TERMD.ELF push failed");
        topo.set_last_task_mem_pages(TERMD_MEM_PAGES);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The name server: the signed rows' `imports` are answered here. Its row
    // is its whole authority (serve `names`, lend `term`); it starts with the
    // native shell session, before the terminal server and the shell.
    if azos_limits::USERSPACE_NAMESD {
        topo.push_task(MaybeStr::from_bytes(TASK_NAMESD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, NAMESD_CAPS)
            .expect("default_minimal_topology: NAMESD.ELF push failed");
        topo.set_last_task_mem_pages(NAMESD_MEM_PAGES);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The decision server (`userspace/services/decisd`, the Decisions
    // object) and its client tool (`WHY.ELF`). The server's row is its whole
    // authority, `READ` on `endpoint.decisions`, and the admin introspection
    // region it reads the records from (`DECISD_CAPS`). `start` follows
    // Kconfig `DECISION_REFUSALS_DURABLE` / `DECISION_RECORDS_DEV`: without
    // either the kernel keeps no decisions and there is nothing to serve.
    // `why` holds `WRITE` on the same name and nothing else; the shell holds
    // the right to start it (`SH_CAPS`, not under `CONSOLE_LOCKDOWN`).
    if azos_limits::USERSPACE_DECISD {
        topo.push_task(MaybeStr::from_bytes(TASK_DECISD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, DECISD_CAPS)
            .expect("default_minimal_topology: DECISD.ELF push failed");
        topo.set_last_task_mem_pages(DECISD_MEM_PAGES);
        topo.set_last_task_start(azos_limits::DECISION_REFUSALS_DURABLE || azos_limits::DECISION_RECORDS_DEV);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    if azos_limits::USERSPACE_WHY {
        topo.push_task(MaybeStr::from_bytes(TASK_WHY_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, WHY_CAPS)
            .expect("default_minimal_topology: WHY.ELF push failed");
        topo.set_last_task_mem_pages(WHY_MEM_PAGES);
    }
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
        topo.push_task(MaybeStr::from_bytes(TASK_PKGD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, PKGD_CAPS)
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
    if azos_limits::USERSPACE_RPCSRV {
        topo.push_task(MaybeStr::from_bytes(TASK_RPCSRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), CLIENT_SERVICE_PRIORITY, RPCSRV_CAPS)
            .expect("default_minimal_topology: RPCSRV.ELF push failed");
        topo.set_last_task_mem_pages(RPCSRV_MEM_PAGES);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
        if azos_limits::RPC_PEER_NODE != 0 {
            // Pinned to the key of Kconfig `RPC_PEER_NOISE_PK`; empty pins none, and
            // the server has no session to open with a node it cannot tell apart.
            let pk = rpc_peer_noise_pk();
            let keys: &[[u8; 32]] = pk.as_slice();
            topo.push_peer(MaybeStr::from_bytes(b"fleet"), &[azos_limits::RPC_PEER_NODE as u32], keys, None)
                .expect("default_minimal_topology: peer class push failed");
            topo.set_last_task_exports(&[crate::types::ExportSpec {
                endpoint: MaybeStr::from_bytes(b"decisions"),
                peer: MaybeStr::from_bytes(b"fleet"),
            }])
            .expect("default_minimal_topology: RPCSRV.ELF exports");
            topo.set_last_task_start(true);
        }
    }
    // L0: the Linux driver server skeleton, only under `lx-server`
    // (Kconfig LINUX_DRIVERS + LX_SERVER_SKELETON). One capability, READ on
    // the entropy pool, for its allocator (`LXSRV_CAPS`); never an actuator
    // (`Motor`, `Pwm`, `Gpio`, `Estop`): a Linux server holds none, and the
    // skeleton needs nothing else (it opens its module read-only, which
    // needs no grant). `best_effort`: no real-time task may depend on
    // a Linux server; at [`SERVICE_PRIORITY`], the native drivers' number,
    // above the interactive session. `start = true`, so a volume that carries
    // LXSRV.ELF starts it; only the gate's `$AZOS_OUT/build/disk-lx.img` does.
    #[cfg(feature = "lx-server")]
    {
        topo.push_task(MaybeStr::from_bytes(TASK_LXSRV_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, LXSRV_CAPS)
            .expect("default_minimal_topology: LXSRV.ELF push failed");
        topo.set_last_task_mem_pages(LXSRV_MEM_PAGES);
        topo.set_last_task_start(true);
    }
    // Hypervisor H1 (Kconfig HV, `userspace/services/vmmd`): the ring-3 device
    // models of a guest. The guest holds no warrant; this row does, so the
    // guest's effects (its disk file, its console bytes, its frames) pass the
    // same envelope and leave the same record as a native task's. Started
    // wherever the hypervisor core is built: with no `[guest.NAME]` row there
    // is no `vm.0` and it exits at once. The built-in topology declares no
    // guest, so the row carries only `VMMD.ELF`'s own frames
    // (`VMMD_MEM_PAGES`); a signed `CAPS.TOML` that declares one writes this
    // row with `mem_pages` of at least `vmmd_pages(guests)` (the guest's RAM is
    // made by `VMMD.ELF` and charged to it), and the boot refuses the guest
    // when the row is short.
    if VMMD_ROW {
        // Kconfig `HV_EXAMPLE_GUEST` (AzOS inside AzOS, `make azos-guest`): one
        // guest, and the row budgets its frames.
        if EXAMPLE_GUEST_ROW {
            topo.push_guest(example_guest()).expect("default_minimal_topology: example guest push failed");
        }
        topo.push_task(MaybeStr::from_bytes(TASK_VMMD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, &VMMD_CAPS)
            .expect("default_minimal_topology: VMMD.ELF push failed");
        topo.set_last_task_mem_pages(vmmd_pages(topo.guests()) as u32);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }

    // Wave 12, gate only (`linux-abi-test`): `LXHELLO.ELF`, a
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
    // The third-party `BUSYBOX.ELF` (`make busybox`), a
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
        topo.push_task(MaybeStr::from_bytes(TASK_LXTHR_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, &[TMP_RW, ROOT_RO])
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
            &[
                CapSpec {
                    kind: CapKind::Node,
                    perms: CapPerms::EXEC,
                    target: MaybeStr::from_bytes(TASK_ABICHILD_IMAGE), transfer: false, ops: 0,
                },
                ROOT_RO,
                // The task list an orphan watches its adoption in.
                TASK_VIEW_CAP,
                INSPECT_PUBLIC_CAP,
                INSPECT_ADMIN_CAP,
            ][..if azos_limits::INSPECT && azos_limits::INSPECT_ADMIN_PAGES != 0 { 5 } else { 2 }],
        )
        .expect("default_minimal_topology: ABICHILD.ELF push failed");
        // Ring-3 port I/O (`abitest`'s `check_ioports`): one port, the POST
        // port 0x80 (nothing behind it on QEMU), where the build has a port
        // space that holds it; behind the refusal canaries' feature, so a
        // board topology grants no port to a test image.
        if cfg!(feature = "cap-refusal-canary") && azos_limits::X86_IOPORT_BITMAP_PORTS > 0x80 {
            assert!(
                topo.extend_task_caps(&MaybeStr::from_bytes(TASK_ABICHILD_IMAGE), &[CapSpec {
                    kind: CapKind::Device,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"ioport.128.1"), transfer: false, ops: 0,
                }]),
                "default_minimal_topology: ABICHILD.ELF port 0x80"
            );
        }
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
    // The Zenoh gateway (`userspace/services/zenohd`, Kconfig ZENOH_GW): a
    // client of one Zenoh router that publishes the kernel's decision records
    // as topics and, with Kconfig ZENOH_DECISIONS_KEY, serves the Decisions
    // ops as queryables. Its row is its whole authority: the call right
    // (`WRITE` + `transfer`) on `endpoint.decisions`, for the receipts, the
    // topics and the per-query warrants, and `READ` on `entropy`. No directory:
    // it opens no file (its configuration is Kconfig). Pushed after the
    // console program's row, so no index another test pins moves.
    if ZENOH_GW_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_ZENOHD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, ZENOHD_CAPS)
            .expect("default_minimal_topology: ZENOHD.ELF push failed");
        topo.set_last_task_mem_pages(ZENOHD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The PTP daemon (`userspace/services/ptpd`, Kconfig PTPD): a slave that
    // measures the wall clock against the best master it hears and offers each
    // measurement to the kernel's `Clock` interface. Its row is its whole
    // authority: `WRITE` on the kernel's `clock` endpoint (the right to move
    // time) and the kernel's view of the node's `[clock]` row, which names
    // the domain. A node whose `[clock]` row
    // declares no `ptp_domain` has the daemon end at once, so the built-in
    // topology declares one (Kconfig `PTPD_DOMAIN`) with the row. Pushed after
    // the Zenoh gateway, so no index another test pins moves.
    if PTPD_ROW {
        topo.set_clock(Some(azos_limits::PTPD_DOMAIN as u8), &[])
            .expect("default_minimal_topology: [clock] row failed");
        topo.push_task(MaybeStr::from_bytes(TASK_PTPD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, PTPD_CAPS)
            .expect("default_minimal_topology: PTPD.ELF push failed");
        topo.set_last_task_mem_pages(PTPD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The audio server (`userspace/services/audiod`, Kconfig AUDIOD): serves the
    // `Sound` interface on `endpoint.audio` and mixes its clients' streams into
    // the one playback stream it holds on the kernel's `sound.0`. A best-effort
    // service row with no profile: the task it spawns is the thread that
    // accepts calls, which needs no budget. The real-time work is the mixer's,
    // and the mixer thread asks for its own deadline reservation at start
    // (`SYS_SCHEDCTL` with the `time` warrant this row grants; Kconfig
    // `AUDIOD_PUMP_*`), which admission places like any runtime reservation.
    // At [`SERVICE_PRIORITY`], above its clients (`beep`, the shell), as every
    // server outranks the tasks that call it.
    // Pushed after the PTP daemon, so no index another test pins moves.
    if AUDIOD_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_AUDIOD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, AUDIOD_CAPS)
            .expect("default_minimal_topology: AUDIOD.ELF push failed");
        topo.set_last_task_mem_pages(AUDIOD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The relay of the QUIC link (`userspace/services/rpcquic`, Kconfig RPC_QUIC): the std
    // program that holds the QUIC stack and its TLS so `RPCSRV.ELF` does not. Its row
    // is its whole authority: `READ` on `entropy` (the handshake's keys and the
    // allocator's seed); the network is its seccomp profile's, and it holds no
    // lend right, no endpoint and no file. Started at boot with the server it
    // serves, and again when it fails (the server's probes bridge the gap).
    // Pushed after the gateway, so no index another test pins moves.
    if RPCQUIC_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_RPCQUIC_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, RPCQUIC_CAPS)
            .expect("default_minimal_topology: RPCQUIC.ELF push failed");
        topo.set_last_task_mem_pages(RPCQUIC_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The MCP bridge (`userspace/services/mcpd`, Kconfig MCP_BRIDGE): the
    // endpoints its row can call, as Model Context Protocol tools for one agent
    // host it dials. Its row is its whole authority: the call right
    // (`WRITE` + `transfer`) on `endpoint.decisions`, for the receipts and the
    // one interface the built-in catalog fronts, `READ` on `entropy`, `READ` on
    // `linkkey` masked to `node_key` (the root of the warrants it signs) and the
    // read-only root directory. A signed topology adds the call rights on the
    // endpoints it lets an agent reach (irreversible ones included: the bridge
    // only proposes those, a human confirms). Pushed after the Zenoh gateway,
    // so no index another test pins moves.
    if MCP_BRIDGE_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_MCPD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, MCPD_CAPS)
            .expect("default_minimal_topology: MCPD.ELF push failed");
        topo.set_last_task_mem_pages(MCPD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The SSH server (`userspace/services/sshd`, Kconfig SSHD: every preset but
    // the MCU kernel and a certifiable build): the node's remote door. Its row
    // is its whole authority: `READ` on `entropy` (the ephemeral keys),
    // `READ` and `WRITE` on `keys` masked to open a key, read its public part and
    // sign (the host key lives in the kernel's keystore and never reaches the
    // task), `/fat` read-write (it keeps `/fat/SSHAUTH.LOG`; see `SSHD_CAPS` for
    // why not narrower), the right to
    // start `TOOLBOX.ELF` and nothing else (a login is not the console: the
    // privileged tools are not on this list), the read-only root directory it
    // opens those beneath, and the kernel's view of the signed topology's logins.
    // The network is its seccomp profile's. Pushed after the MCP bridge, so no
    // index another test pins moves.
    if SSHD_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_SSHD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, SSHD_CAPS)
            .expect("default_minimal_topology: SSHD.ELF push failed");
        topo.set_last_task_mem_pages(SSHD_MEM_PAGES);
        // A login is a human's session: the server and, by inheritance at the
        // spawn, the images it starts act as a `User`, not as `System`.
        topo.set_last_task_principal(Some(crate::types::PrincipalKind::User));
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The login service (`userspace/services/logind`, Kconfig CONSOLE_LOGIN):
    // the console's way in. Its row is its whole authority (see `LOGIND_CAPS`):
    // serve `endpoint.login` to the terminal server, call the `login` op of
    // `keys`, start the shell as the user's session. It starts at boot with the
    // row, before the terminal server that calls it (the manager orders a row
    // after the rows that serve the endpoints it calls). Pushed after the SSH
    // server, so no index another test pins moves.
    if LOGIND_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_LOGIND_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, LOGIND_CAPS)
            .expect("default_minimal_topology: LOGIND.ELF push failed");
        topo.set_last_task_mem_pages(LOGIND_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The structured kernel log's sink (`userspace/services/logd`, Kconfig
    // KLOG): drains `MemObj klog.ring` (`READ|MAP`: the kernel is the only
    // writer) into `KLOGn.TXT` in the `/fat` tree and nothing else; it serves
    // and calls no endpoint. `start` follows KLOG: without the log there is no
    // ring to drain. Pushed before the component manager's row, as every row
    // that starts is, so its launch grant exists.
    if azos_limits::USERSPACE_LOGD {
        topo.push_task(MaybeStr::from_bytes(TASK_LOGD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), TOOL_PRIORITY, LOGD_CAPS)
            .expect("default_minimal_topology: LOGD.ELF push failed");
        topo.set_last_task_mem_pages(LOGD_MEM_PAGES);
        topo.set_last_task_start(azos_limits::KLOG);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The input server (`userspace/services/inputd`, Kconfig INPUTD): delivers
    // the input drivers' stream to the task that holds the focus. Its row is
    // its whole authority: `READ` on `endpoint.input` (it serves it) with the
    // call right and `transfer` in the same grant (the source its warrants are
    // derived from), the drivers' region `MemObj input.events`, which it
    // shares with the terminal server (each uses its own ring of it), and the
    // focus word `MemObj input.focus`, its alone. It reads no console byte. At
    // [`SERVICE_PRIORITY`]: above the session whose input it delivers and above
    // every caller (the compositor, the tools). Pushed before the component
    // manager's row, as every row that starts is.
    if INPUTD_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_INPUTD_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, INPUTD_CAPS)
            .expect("default_minimal_topology: INPUTD.ELF push failed");
        topo.set_last_task_mem_pages(INPUTD_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The compositor (`userspace/services/compositor`, Kconfig COMPOSITOR): the
    // sole holder of the kernel's `Display` interface and the trusted surface of
    // the Secure Attention Key. Its row is its whole authority: `READ` on
    // `endpoint.compositor` (it serves its clients), the three classes of
    // `display.0` (observe, draw, claim the screen), the call right on
    // `endpoint.input` with `EXEC` beside it, which the kernel badges as the
    // trusted surface's (`azos_devif::input::TRUSTED_BADGE`; the input server
    // grants the focus after a chord to this caller alone), and, where the
    // decision server runs, the call right on `endpoint.decisions` for the
    // "why was this refused" panel. At [`CLIENT_SERVICE_PRIORITY`]: below the
    // input and decision servers it calls, above the tools it serves. Pushed
    // after the input server's row, whose endpoint it needs, and before the
    // component manager's.
    if COMPOSITOR_ROW {
        topo.push_task(MaybeStr::from_bytes(TASK_COMPOSITOR_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), CLIENT_SERVICE_PRIORITY, COMPOSITOR_CAPS)
            .expect("default_minimal_topology: COMPSRV.ELF push failed");
        topo.set_last_task_mem_pages(COMPOSITOR_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
    }
    // The component manager (`userspace/services/compmgr`): the one row the
    // kernel starts at boot; it starts the others from this signed topology
    // (its `inspect.components` view) and supervises them. Only a build whose volume
    // carries its image (Kconfig USERSPACE_COMPMGR) has the row: a row for an
    // image that is not there would be started and refused at every boot.
    // Pushed after every row that
    // starts (a `start = true` row declared later would be missing from its
    // launch grants below) and before the gate-only rows. Its authority is the
    // view of the plan ([`INSPECT_COMPONENTS_CAP`]) and the
    // right to start each image the topology starts: `SYS_SPAWN_EX` checks a
    // `Cap<Launch>` on the image whoever the caller is, so the row grants
    // `EXEC` on every other `start = true` row, one by one. The child holds
    // what its own row grants, never the manager's.
    if COMPMGR_ROW {
        let mut caps = [CapSpec::empty(); MANAGER_CAPS_MAX];
        caps[0] = INSPECT_COMPONENTS_CAP;
        let mut n = 1;
        // Rows past the manager's table are not started either (it records
        // and skips them), so they get no grant.
        for r in topo.tasks().iter().filter(|r| manager_starts(r)).take(MANAGER_CAPS_MAX - 1) {
            caps[n] = CapSpec { kind: CapKind::Node, perms: CapPerms::EXEC, target: r.name, transfer: false, ops: 0 };
            n += 1;
        }
        topo.push_task(MaybeStr::from_bytes(TASK_COMPMGR_IMAGE), MaybeStr::from_bytes(NAME_BEST_EFFORT), SERVICE_PRIORITY, &caps[..n])
            .expect("default_minimal_topology: COMPMGR.ELF push failed");
        topo.set_last_task_mem_pages(COMPMGR_MEM_PAGES);
        topo.set_last_task_start(true);
        topo.set_last_task_restart(crate::types::RestartPolicy::OnFailure);
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
        TOOL_PRIORITY,
        &[CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(b"pwm.6"),
            transfer: false, ops: 0,
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
/// virtio-mmio disk, NIC, keyboard, display, sound and entropy device, the
/// virtio-pci NIC, display and sound device, an NVMe controller, an AHCI SATA host, QEMU's e1000e (82574L) and igb (82576), an xHCI host controller (`-device qemu-xhci`), and
/// `-M raspi3b`'s DWC2 USB host (the Raspberry Pi 3's). A board image lists the hardware its drivers bind.
#[cfg(feature = "qemu-devices")]
pub const BUILTIN_DEVICE_ROWS: &[(&[u8], &[u8])] = &[
    (b"virtio-blk", b"virtio:2"),
    (b"virtio-net", b"virtio:1"),
    (b"virtio-rng", b"virtio:4"),
    (b"virtio-input", b"virtio:18"),
    (b"virtio-gpu", b"virtio:16"),
    (b"virtio-net-pci", b"pci:1af4:1041"),
    (b"virtio-gpu-pci", b"pci:1af4:1050"),
    (b"virtio-snd", b"virtio:25"),
    (b"virtio-snd-pci", b"pci:1af4:1059"),
    (b"nvme", b"pciclass:010802:ffffff"),
    (b"ahci", b"pciclass:010601:ffffff"),
    (b"e1000e", b"pci:8086:10d3"),
    (b"igc", b"pci:8086:10c9"),
    (b"xhci", b"pciclass:0c0330:ffffff"),
    (b"dwc2", b"dt:brcm,bcm2835-usb"),
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

/// The third-party BusyBox image.
pub const TASK_BUSYBOX_IMAGE: &[u8] = b"BUSYBOX.ELF";
/// Frame budget of `BUSYBOX.ELF`: a static image of about 150 KiB, its heap,
/// stack and page tables, and its forked children's copy-on-write breaks.
///
/// 256 pages was not enough for `sh -c '...; ls /fat'` (gate row `linux:
/// busybox sh`, all three ISAs: `ls: can't open '/fat': Out of memory`). Its
/// libc grows the heap in 64 KiB chunks, each an `mmap` of 124 KiB (31 pages,
/// charged whole) trimmed by two `munmap`s, because the kernel places an
/// anonymous mapping at the break and does not take the address hint. The
/// shell holds 7 or 8 such chunks after start; the forked `ls` child is charged
/// for what it shares with it, and its next growth (opendir's buffer) asked
/// for 31 more pages past the 256: ENOMEM (traced on x86_64, 2026-10-23).
/// 512 leaves room for that growth and one more fork level.
const BUSYBOX_MEM_PAGES: u32 = 512;
/// `BUSYBOX.ELF`'s authority: `/tmp` read-write, and the read-only root
/// directory ([`ROOT_RO`]: it reads where it always could, and writes only
/// under `/tmp`). Gate only
/// (`linux-exec-row-test`, wave 13): also `/fat` read-write and the grant to
/// `execve` `LXHELLO.ELF`, whose own row holds only `/tmp`: the exec'd image
/// must lose the write on `/fat` (it runs with its target row's authority).
#[cfg(not(feature = "linux-exec-row-test"))]
const BUSYBOX_CAPS: &[CapSpec] = &[TMP_RW, ROOT_RO];
#[cfg(feature = "linux-exec-row-test")]
const BUSYBOX_CAPS: &[CapSpec] = &[
    TMP_RW,
    ROOT_RO,
    CapSpec { kind: CapKind::Node, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"/fat"), transfer: false, ops: 0 },
    LXHELLO_LAUNCH,
];

/// Wave 12: the flight tool's image (`flight arm | disarm`).
pub const TASK_FLIGHT_IMAGE: &[u8] = b"FLIGHT.ELF";
/// Wave 12: the behavior tool's image (`behavior status | enable | disable`).
pub const TASK_BEHAVIOR_IMAGE: &[u8] = b"BEHAVIOR.ELF";
/// Wave 12: the config tool's image (`config get | set`).
pub const TASK_CONFIG_IMAGE: &[u8] = b"CONFIG.ELF";
/// Wave 12: the OTA tool's image (`ota status | rollback | switch`).
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
        target: MaybeStr::from_bytes(b"flight"), transfer: false, ops: 0,
    }]
} else if DRIVETRAIN && cfg!(feature = "flight-tool-drivetrain") {
    &[
        DRIVETRAIN_CAPS[0],
        DRIVETRAIN_CAPS[1],
        CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::RW,
            target: MaybeStr::from_bytes(b"flight"), transfer: false, ops: 0,
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
    target: MaybeStr::from_bytes(b"behavior"), transfer: false, ops: 0,
}];
const CONFIG_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: FAMILY_PERMS,
    target: MaybeStr::from_bytes(b"config"), transfer: false, ops: 0,
}];
const OTA_CAPS: &[CapSpec] = &[CapSpec {
    kind: CapKind::Endpoint,
    perms: FAMILY_PERMS,
    target: MaybeStr::from_bytes(b"ota"), transfer: false, ops: 0,
}];

/// The Linux driver server skeleton's image.
pub const TASK_LXSRV_IMAGE: &[u8] = b"LXSRV.ELF";
/// Frame budget of `LXSRV.ELF`: image and stack, a 64 KiB module buffer in
/// `.bss`, and the two module regions it maps (a few pages for the test
/// module); since stage L1 also the Kbuild modules (LXBASE.KO, XZ_DEC.KO:
/// file copies and regions, about 14 pages), the 96 KiB host-allocator arena
/// and the xz fixture with its 48 KiB output (about 18 pages).
#[cfg(feature = "lx-server")]
const LXSRV_MEM_PAGES: u32 = 128;
/// `LXSRV.ELF`'s authority: READ on the kernel-hosted `entropy` endpoint,
/// which keys and randomizes the hardened allocator it links (`azos_ualloc`,
/// Kconfig `USER_ALLOC_*`). Like every interface grant the kernel withholds it
/// from an image whose seccomp row does not list the interface (the row does).
/// And the read-only root directory ([`ROOT_RO`]): the kernel modules it loads
/// are files it opens by path.
#[cfg(feature = "lx-server")]
const LXSRV_CAPS: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::READ,
        target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0,
    },
    ROOT_RO,
];

/// Does the built-in topology carry the `VMMD.ELF` row? Wherever the
/// hypervisor core is built (Kconfig `HV`, derived from `VIRT`).
pub const VMMD_ROW: bool = azos_limits::HV;
/// The virtual-machine monitor's image (hypervisor plan H1).
pub const TASK_VMMD_IMAGE: &[u8] = b"VMMD.ELF";
/// Does the built-in topology declare the example guest (Kconfig
/// `HV_EXAMPLE_GUEST`)? Only where the monitor's row exists.
pub const EXAMPLE_GUEST_ROW: bool = VMMD_ROW && azos_limits::HV_EXAMPLE_GUEST;
/// The backends of the example guest: the console its banner leaves by, the
/// disk and the NIC of an AzOS kernel's virtio drivers.
const EXAMPLE_GUEST_DEVICES: [&[u8]; 3] = [b"virtio-console", b"virtio-blk", b"virtio-net"];
const _: () = assert!(
    !EXAMPLE_GUEST_ROW || crate::types::GUEST_DEVICES >= EXAMPLE_GUEST_DEVICES.len(),
    "the example guest lists three backends: TOPOLOGY_GUEST_DEVICES is below 3"
);
/// The example guest's row: one vCPU, `HV_EXAMPLE_GUEST_MEM_MIB` of RAM, the
/// `cautious` envelope (its NIC may reach the network, nothing physical).
fn example_guest() -> crate::types::GuestSpec<'static> {
    let mut g = crate::types::GuestSpec::empty();
    g.name = MaybeStr::from_bytes(b"azos");
    g.cpus = 1;
    g.mem_mib = azos_limits::HV_EXAMPLE_GUEST_MEM_MIB as u32;
    for (slot, name) in g.devices.iter_mut().zip(EXAMPLE_GUEST_DEVICES) {
        *slot = MaybeStr::from_bytes(name);
    }
    g.devices_len = EXAMPLE_GUEST_DEVICES.len() as u8;
    g.envelope = crate::types::Envelope::Cautious;
    g
}
/// Frames `VMMD.ELF` needs for itself: its image and stack, the guest's state
/// and the control plane's thread stack (both in its image), the 36 KiB region
/// of the guest NIC's ring pair, the page of the trap rings and the console
/// ring a tool drains (about 40 pages, with room). The guest's RAM is on top
/// of it ([`vmmd_pages`]): the memory objects it is made of are created by
/// `VMMD.ELF` and charged to its Domain, the kernel only pins them until
/// `Vm::destroy`.
pub const VMMD_MEM_PAGES: u32 = 44;
/// Frames the row of `VMMD.ELF` has to budget to serve `guests`: its own
/// ([`VMMD_MEM_PAGES`]) and each guest's RAM (4 KiB pages, as every row's
/// `mem_pages`). The boot checks the row against it before admitting a guest
/// (`kernel/src/boot/hv.rs`).
pub fn vmmd_pages(guests: &[crate::types::GuestSpec<'_>]) -> u64 {
    VMMD_MEM_PAGES as u64 + guests.iter().map(|g| g.mem_mib as u64 * (1024 * 1024 / crate::memory::TOPOLOGY_PAGE)).sum::<u64>()
}
/// `VMMD.ELF`'s authority over the VM it serves, `vm.0`: `READ` (state and
/// config) and `EXEC` (create and give it back, attach its RAM, trap page and
/// NIC, register its device windows). Nothing on a running guest: that is the
/// vCPU's below.
const VMMD_VM: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ.union(CapPerms::EXEC),
    target: MaybeStr::from_bytes(b"vm.0"), transfer: false, ops: 0,
};
/// The vCPUs of one guest `VMMD.ELF` serves: a trap names its vCPU in a byte
/// and the monitor's kick mask has a bit for each (`vmmd`'s `life::VCPUS`,
/// which the monitor's host tests hold equal to this).
pub const VMMD_VCPUS_MAX: usize = 16;
/// The vCPU endpoints the built-in row grants: `vcpu.0.k` for each vCPU the
/// pool can hold (Kconfig `HV_MAX_VCPUS`), at most [`VMMD_VCPUS_MAX`]. A guest
/// row names its own CPU count and `VMMD.ELF` looks up one endpoint for
/// each; a vCPU the guest does not have is a grant nothing answers.
const VMMD_VCPU_GRANTS: usize = {
    let pool = azos_limits::HV_MAX_VCPUS as usize;
    if pool < VMMD_VCPUS_MAX { pool } else { VMMD_VCPUS_MAX }
};
const VMMD_VCPU_NAMES: [&[u8]; VMMD_VCPUS_MAX] = [
    b"vcpu.0.0", b"vcpu.0.1", b"vcpu.0.2", b"vcpu.0.3", b"vcpu.0.4", b"vcpu.0.5", b"vcpu.0.6", b"vcpu.0.7",
    b"vcpu.0.8", b"vcpu.0.9", b"vcpu.0.10", b"vcpu.0.11", b"vcpu.0.12", b"vcpu.0.13", b"vcpu.0.14", b"vcpu.0.15",
];
/// What it does to a vCPU: start and stop it (`EXEC`), raise a virtual
/// interrupt line and wake it when a device model has answered (`WRITE`), and
/// ask whether it runs or why it stopped (`READ`).
const fn vmmd_vcpu(k: usize) -> CapSpec<'static> {
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC),
        target: MaybeStr::from_bytes(VMMD_VCPU_NAMES[k]), transfer: false, ops: 0,
    }
}
/// The server half of `endpoint.vmctl`: `READ` claims it for `VMMD.ELF`.
const VMMD_CTL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_VMCTL), transfer: false, ops: 0,
};
/// Where the guest's disk image lives: the one tree it may change.
const VMMD_DISK_TREE: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat/VM"), transfer: false, ops: 0,
};
/// `VMMD.ELF`'s authority: its VM and its vCPUs, the endpoint it serves
/// `VmCtl` on, the disk image's tree, and the read-only root directory
/// ([`ROOT_RO`]) it names the image through. No motor, pin or network
/// authority: a guest's reach is exactly this.
const VMMD_CAPS: [CapSpec<'static>; VMMD_VCPU_GRANTS + 4] = {
    let mut caps = [ROOT_RO; VMMD_VCPU_GRANTS + 4];
    caps[0] = VMMD_VM;
    let mut k = 0;
    while k < VMMD_VCPU_GRANTS {
        caps[1 + k] = vmmd_vcpu(k);
        k += 1;
    }
    caps[1 + VMMD_VCPU_GRANTS] = VMMD_CTL;
    caps[2 + VMMD_VCPU_GRANTS] = VMMD_DISK_TREE;
    caps
};

/// Does the built-in topology carry the `LXHELLO.ELF` row? Gate builds
/// (`linux-abi-test`) of a kernel with the Linux personality (`LINUX_ABI`).
pub const LXHELLO_ROW: bool = cfg!(feature = "linux-abi-test") && azos_limits::LINUX_ABI;

/// Frames the Linux runtime takes from every Linux row's memory budget when it
/// hosts the personality (Kconfig `LINUX_RUNTIME`): its text, read-only data
/// and data+bss pages (`userspace/services/lxrt`, about 32 KiB), the page
/// tables of the window it is mapped in, and the stack it grows on the
/// program's own stack. 0 with the in-kernel personality.
const LINUX_RUNTIME_PAGES: u32 = if azos_limits::LINUX_RUNTIME { 16 } else { 0 };

/// The Linux personality's test image, gate only.
#[cfg(feature = "linux-abi-test")]
pub const TASK_LXHELLO_IMAGE: &[u8] = b"LXHELLO.ELF";
/// Frame budget of `LXHELLO.ELF`: an 8 KiB image, its stack, a 16 KiB mmap
/// and two pages of brk.
#[cfg(feature = "linux-abi-test")]
const LXHELLO_MEM_PAGES: u32 = 48;
/// `/tmp` read-write (round 48: its fork test writes one inherited file
/// from parent and child); nothing under `/fat`.
#[cfg(all(feature = "linux-abi-test", not(feature = "linux-abi-caps-canary")))]
const LXHELLO_CAPS: &[CapSpec] = &[TMP_RW, ROOT_RO];
#[cfg(all(feature = "linux-abi-test", feature = "linux-abi-caps-canary"))]
const LXHELLO_CAPS: &[CapSpec] = &[TMP_RW, ROOT_RO, CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat"), transfer: false, ops: 0,
}];
/// The tree on `/`, read-only: the task's root `Cap<Dir>`
/// (`azos_abi::invoke::ROOT_DIR_RESOURCE`). Every open of a ring-3 task is made
/// beneath a directory it holds, and a POSIX layer or a service that names its
/// files by absolute path resolves them against this one. It NAMES, it does
/// not write: an open or a call that changes the tree needs a write tree
/// (`FAT_RW`, `TMP_RW`, ...) covering the file, so a row holding only this one
/// reads (as every row could before the directory capability) and changes
/// nothing. Storage L12-B moves each service onto the narrower directory it
/// needs and drops this grant from the rows that no longer name a path.
const ROOT_RO: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"/"), transfer: false, ops: 0,
};
/// The `/tmp` tree, read-write.
const TMP_RW: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/tmp"), transfer: false, ops: 0,
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
    target: MaybeStr::from_bytes(TASK_PKG_IMAGE), transfer: false, ops: 0,
};
const BUSYBOX_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false, ops: 0,
};
#[cfg(feature = "linux-abi-test")]
const LXHELLO_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_LXHELLO_IMAGE), transfer: false, ops: 0,
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
        target: MaybeStr::from_bytes(TASK_BUSYBOX_IMAGE), transfer: false, ops: 0,
    },
    #[cfg(feature = "linux-threads-test")]
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_LXTHR_IMAGE), transfer: false, ops: 0,
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

/// The power tool's image.
pub const TASK_POWER_IMAGE: &[u8] = b"POWER.ELF";
/// Frame budget of `POWER.ELF`: a small image with no buffers to speak of.
const POWER_MEM_PAGES: u32 = 32;
/// `POWER.ELF`'s authority: the `power` endpoint, `WRITE` for every operation
/// and `READ` for `power sched_hz` with no argument, and `READ` of the power
/// monitor (`sensor.9`) whose samples the battery model is made from, and the
/// call right (`EXEC`) on the `DevicePower` endpoint of each device it manages
/// (`endpoint.pm-gpio`, and `endpoint.pm-ina` where the monitor has a ring-3
/// row). Under
/// `power-cap-canary` the `power` endpoint is `READ` only, so every operation
/// that changes something is refused by the right, recorded and printed (gate
/// row `sh: power refused without the power right`).
const POWER_CAPS: &[CapSpec] = if INADRV_ROW { &POWER_CAPS_ALL } else { &POWER_CAPS_ALL_BUT_INA };
const POWER_CAPS_ALL: [CapSpec; 4] = [
    POWER_CAPS_ALL_BUT_INA[0],
    POWER_CAPS_ALL_BUT_INA[1],
    POWER_CAPS_ALL_BUT_INA[2],
    POWER_PM_INA,
];
const POWER_CAPS_ALL_BUT_INA: [CapSpec; 3] = [
    CapSpec {
        kind: CapKind::Endpoint,
        perms: if cfg!(feature = "power-cap-canary") { CapPerms::READ } else { CapPerms::RW },
        target: MaybeStr::from_bytes(b"power"), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::READ,
        target: MaybeStr::from_bytes(b"sensor.9"), transfer: false, ops: 0,
    },
    // The `DevicePower` endpoints of the devices it manages: the calling
    // grant, `EXEC` (control: `set_idle_timeout`, `suspend`, `resume`), which
    // the kernel badges with the device's key and the classes read + exec.
    // The ina grant exists only where the driver has a ring-3 row
    // ([`INADRV_ROW`]): a grant on an endpoint nobody serves is dormant.
    CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PM_GPIO), transfer: false, ops: 0,
    },
];
const POWER_PM_INA: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PM_INA), transfer: false, ops: 0,
};

/// The tracer's reader (wave 15, TRACE).
pub const TASK_TRACECTL_IMAGE: &[u8] = b"TRACECTL.ELF";
/// Frame budget of `TRACECTL.ELF`: image, stack, its record batch and the
/// trace region's mapping (at most `MAX_MEMOBJ_PAGES`, 64 pages, booked to the
/// region, not here); 64 pages: the aarch64 image (hard-float userspace, a
/// page-aligned segment per permission) needs 55 at its spawn, and 48, the
/// `TOOLBOX.ELF` budget it was copied from, refused it.
const TRACECTL_MEM_PAGES: u32 = 64;
/// Live `TRACECTL.ELF` instances: the one reader (`stream`, the rings' only
/// consumer) and one controller (`start`/`stop`/`info`, which consume
/// nothing) beside it. Structural, not a tuning knob: a second reader would
/// race the first on every tail.
const TRACECTL_INSTANCES: u16 = 2;
/// `TRACECTL.ELF`'s authority: `Cap<Trace>` read-write, and `/fat`
/// read-write for a trace file (opened beneath the read-only root
/// directory, [`ROOT_RO`]; the `/fat` tree is the write authority). Under `trace-cap-canary` the tracer grant is
/// withheld: every control call is refused by the capability and recorded
/// (gate row `trace: refused without Cap<Trace>`).
#[cfg(not(feature = "trace-cap-canary"))]
const TRACECTL_CAPS: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Log,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"trace"), transfer: false, ops: 0,
    },
    FAT_RW,
    ROOT_RO,
];
#[cfg(feature = "trace-cap-canary")]
const TRACECTL_CAPS: &[CapSpec] = &[FAT_RW, ROOT_RO];
/// The `/fat` tree, read-write.
const FAT_RW: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat"), transfer: false, ops: 0,
};

// The ring-3 priorities (lower = more urgent; the fair class weighs a task by
// its number, `azos_sched::eevdf_core::weight_of_prio`). Every server strictly
// outranks every client it serves (`Topology::server_not_above_client`, owner
// decision 2026-10-23): the order is the rows' service graph, from the leaves
// up, and no server shares a bucket with a client.

/// The servers of the `autorun` row (16), `EPSRV.ELF` and `VSSRV.ELF`:
/// `hard_rt` 15, without a reservation, so the fair class runs them one
/// above their client.
pub const AUTORUN_SERVER_PRIORITY: u8 = 15;
/// The most urgent `best_effort` number: a service that calls no service
/// below it — the session's leaf servers (`NAMESD.ELF`, `LOGIND.ELF`,
/// `INPUTD.ELF`), the decision and package servers, the ring-3 device drivers
/// and the board programs. Above the shell, never equal to it.
pub const SERVICE_PRIORITY: u8 = 24;
/// A service that is itself a client of a [`SERVICE_PRIORITY`] row
/// (`TERMD.ELF` calls the login server, `COMPSRV.ELF` the input and decision
/// servers, `RPCSRV.ELF` the decision server): below the services it calls,
/// above its own clients.
pub const CLIENT_SERVICE_PRIORITY: u8 = 25;
/// `SH.ELF`'s priority: below every server of the session, above every tool
/// it starts.
pub const SH_PRIORITY: u8 = 26;
/// The priority of every tool image the shell starts (`TOOLBOX.ELF`,
/// `POWER.ELF`): below the shell, inside `best_effort`.
pub const TOOL_PRIORITY: u8 = 27;

/// Live `TOOLBOX.ELF` instances: Kconfig `TOOLBOX_INSTANCES` (a four-stage
/// pipeline and four background jobs; fewer on the embedded profile).
const TOOLBOX_INSTANCES: u16 = azos_limits::TOOLBOX_INSTANCES as u16;

/// The user shell's image.
pub const TASK_SH_IMAGE: &[u8] = b"SH.ELF";
/// The multicall tool image the shell's applets run in.
pub const TASK_TOOLBOX_IMAGE: &[u8] = b"TOOLBOX.ELF";
/// Frame budget of `SH.ELF`: image, stack, page tables and its static
/// buffers (history, line, environment); it has no heap.
const SH_MEM_PAGES: u32 = 64;
/// Frame budget of `TOOLBOX.ELF`: the image, its stack, its page tables and
/// the frames `beep` makes for its stream: two queue pages and a 16 KiB arena,
/// six pages on a 4 KiB granule (the budget grew from 48 by 16: the six and
/// headroom for a longer period).
const TOOLBOX_MEM_PAGES: u32 = 64;

/// What the shell holds outside `CONSOLE_LOCKDOWN`, before the launch grants
/// of the optional rows ([`SH_CAPS_UNLOCKED`]): [`SH_CAPS_BASE`], and with
/// Kconfig `USB_STORAGE_VOLUME` the stick's volume read-write ([`USB_RW`]),
/// so a redirection writes the crash log out to it (`cat /fat/CRASH.LOG >
/// /usb/CRASH.LOG`). No other row may change the stick; every row reads it
/// through [`ROOT_RO`] (the package tool opens a package there).
const SH_CAPS: &[CapSpec] = if azos_limits::USB_STORAGE_VOLUME { &SH_CAPS_WITH_USB } else { SH_CAPS_BASE };
const SH_CAPS_WITH_USB: [CapSpec<'static>; SH_CAPS_BASE.len() + 1] = caps_concat(SH_CAPS_BASE, &[USB_RW]);
/// The USB stick's volume, read-write.
const USB_RW: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(crate::types::USB_VOLUME_PATH), transfer: false, ops: 0,
};

/// `a` followed by `b`, as one array of exactly that length.
const fn caps_concat<const N: usize>(a: &[CapSpec<'static>], b: &[CapSpec<'static>]) -> [CapSpec<'static>; N] {
    assert!(N == a.len() + b.len(), "caps_concat: N is both lists");
    let mut out = [a[0]; N];
    let mut i = 0;
    while i < a.len() {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < b.len() {
        out[a.len() + j] = b[j];
        j += 1;
    }
    out
}

const SH_CAPS_BASE: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_POWER_IMAGE), transfer: false, ops: 0,
    },
    // Wave 12: the other privileged tools, outside the lockdown only.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_FLIGHT_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_BEHAVIOR_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_CONFIG_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_OTA_IMAGE), transfer: false, ops: 0,
    },
    // Wave 15 (TRACE): the tracer's reader.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TRACECTL_IMAGE), transfer: false, ops: 0,
    },
    // The decision query tool.
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_WHY_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/fat"), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/tmp"), transfer: false, ops: 0,
    },
    TASK_VIEW_CAP,
    // The root directory ([`ROOT_RO`]) the shell opens its paths beneath: a
    // redirection or `mkdir` changes only where `/fat` or `/tmp` (above)
    // covers it.
    ROOT_RO,
];

/// The shell's way to the terminal: it holds NO grant on `endpoint.term`. Its
/// row says `imports = ["term"]` (`set_last_task_imports`), the kernel gives
/// it the call right on `endpoint.names` badged with its row, and the name
/// server lends it a derived, call-only capability on `endpoint.term` when it
/// asks. A name is never authority: the row lists what it may ask for.
const SH_IMPORTS: &[MaybeStr<'static>] = &[MaybeStr::from_bytes(b"term")];
/// The tool image's way to the monitor: it holds NO grant on `endpoint.vmctl`;
/// its row imports `vmctl` (with the monitor's row present) and the name
/// server lends the call right.
const TOOLBOX_IMPORTS: &[MaybeStr<'static>] = &[MaybeStr::from_bytes(b"vmctl")];
/// The server half: `READ` claims the endpoint for `TERMD.ELF`.
const TERM_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_TERM), transfer: false, ops: 0,
};

/// The terminal server's image: the console program of the native shell
/// session (it owns console input; the shell is its client).
pub const TASK_TERMD_IMAGE: &[u8] = b"TERMD.ELF";
/// Frame budget of `TERMD.ELF`: image, stack, page tables and its static
/// discipline (line, history, type-ahead); it has no heap.
const TERMD_MEM_PAGES: u32 = 48;
/// Does the kernel have an input event ring for the terminal server to drain?
/// It does when a keyboard/mouse driver is configured (`kernel/src/boot/
/// term_regions.rs` makes the ring then, and only then).
pub const TERM_INPUT_RING: bool = azos_limits::DRV_VIRTIO_INPUT || azos_limits::DRV_PS2;
/// Does the kernel have a console screen region (the framebuffer console's
/// text, scrollback and overlay) for the terminal server to map?
pub const TERM_SCREEN_REGION: bool = azos_limits::FB_CONSOLE;
/// The input event ring, `READ|WRITE|MAP`: the server reads the events and
/// moves the ring's tail (`azos_ipc::kregion`).
const TERM_INPUT_EVENTS: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"input.events"), transfer: false, ops: 0,
};
/// The console screen region, `READ|WRITE|MAP`: the server reads the text and
/// the scrollback and writes the overlay it wants drawn.
const TERM_CONSOLE_SCREEN: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"console.screen"), transfer: false, ops: 0,
};
/// `TERMD.ELF`'s authority: the right to serve `endpoint.term`, and the two
/// kernel-owned regions it turns into keys and a mouse (`input.events` where
/// there is an input driver, `console.screen` where there is a framebuffer
/// console). Console input is claimed with `LOG_CONSOLE_WAIT`, which its
/// seccomp profile lists; it holds no other capability.
///
/// Behind a console login ([`LOGIND_ROW`]) it also holds the call right on
/// `endpoint.login` ([`LOGIN_CALL`]), listed after the endpoint it serves: the
/// credential its secure-attention prompt makes goes to the login service, and
/// the end of the session is asked of it.
const TERMD_CAPS: &[CapSpec] = match (LOGIND_ROW, TERM_INPUT_RING, TERM_SCREEN_REGION) {
    (false, true, true) => &[TERM_SERVE, TERM_INPUT_EVENTS, TERM_CONSOLE_SCREEN],
    (false, true, false) => &[TERM_SERVE, TERM_INPUT_EVENTS],
    (false, false, _) => &[TERM_SERVE],
    (true, true, true) => &[TERM_SERVE, LOGIN_CALL, TERM_INPUT_EVENTS, TERM_CONSOLE_SCREEN],
    (true, true, false) => &[TERM_SERVE, LOGIN_CALL, TERM_INPUT_EVENTS],
    (true, false, _) => &[TERM_SERVE, LOGIN_CALL],
};

/// The login endpoint: `LOGIND.ELF` serves the `Login` object on it (`READ`),
/// `TERMD.ELF` calls it (`WRITE`). Like `endpoint.term`, ring 3 finds it by
/// scanning the endpoint capabilities its row holds (the rights are in the
/// handle).
const RESOURCE_ENDPOINT_LOGIN: &[u8] = b"endpoint.login";
/// The server half of `endpoint.login`: `READ` claims it for `LOGIND.ELF`.
const LOGIN_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_LOGIN), transfer: false, ops: 0,
};
/// The caller half: the right to ask the login service, and nothing more
/// (`WRITE` claims no service).
const LOGIN_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_LOGIN), transfer: false, ops: 0,
};

/// The login service's image (`userspace/services/logind`).
pub const TASK_LOGIND_IMAGE: &[u8] = b"LOGIND.ELF";
/// Does the built-in topology carry the login service's row? Only for a build
/// with a console login (Kconfig `CONSOLE_LOGIN`) whose volume carries the image
/// (`USERSPACE_LOGIND`): without the image a `start = true` row would be launched
/// at every boot to fail. The row starts with it.
pub const LOGIND_ROW: bool = azos_limits::CONSOLE_LOGIN && azos_limits::USERSPACE_LOGIND;
/// Does the console wait for a login? The build has the login service and the
/// signed topology enrols at least one user (`logins`, the `[login.NAME]` rows).
/// Then the shell is the login service's to start, not the component manager's.
pub fn console_gated(logins: usize) -> bool {
    LOGIND_ROW && logins != 0
}
/// Is `spec` the terminal server's call right on the login service ([`LOGIN_CALL`])
/// on a console that is not gated? Then the spawn does not mint it: a terminal
/// server with no such right never asks, so a login service that is down cannot
/// lock a console nobody can log in to (the shell was started by the component
/// manager). With it, an unreachable service keeps the console locked. The gate is
/// the topology's, read once: `logins` is the number of its `[login.NAME]` rows.
pub fn login_call_withheld(spec: &CapSpec<'_>, logins: usize) -> bool {
    spec.kind == CapKind::Endpoint
        && spec.target.as_bytes() == RESOURCE_ENDPOINT_LOGIN
        && !spec.perms.contains(CapPerms::READ)
        && !console_gated(logins)
}
/// Frame budget of `LOGIND.ELF`: image, stack, page tables and its static
/// state; no heap.
const LOGIND_MEM_PAGES: u32 = 48;
/// The right to start the shell, the session of a user: `Cap<Launch>` on
/// `SH.ELF`, `SYS_SPAWN_EX` checks it against the image the file's digest
/// resolves to. The manager holds the same grant for the shell it starts when
/// nobody is enrolled.
const SH_LAUNCH: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::EXEC,
    target: MaybeStr::from_bytes(TASK_SH_IMAGE), transfer: false, ops: 0,
};
/// `LOGIND.ELF`'s authority: `READ` on `endpoint.login` (it serves it), `EXEC`
/// on `keys` masked to the `login` op ([`KEYS_LOGIN`]: it verifies a credential
/// and makes or uses no key), the right to start the shell ([`SH_LAUNCH`]), and
/// the kernel's view of the signed topology's logins ([`INSPECT_LOGINS_CAP`]:
/// whether anybody is enrolled). No file tree, no device, no socket, no entropy.
const LOGIND_CAPS: &[CapSpec] = &[LOGIN_SERVE, KEYS_LOGIN, SH_LAUNCH, INSPECT_LOGINS_CAP];

/// The component manager's image (`userspace/services/compmgr`).
pub const TASK_COMPMGR_IMAGE: &[u8] = b"COMPMGR.ELF";
/// Does the built-in topology carry the component manager's row? Only when
/// the board volume carries its image (Kconfig `USERSPACE_COMPMGR`, on by
/// default on every preset): without the image nothing could start it, and a
/// `start = true` row would be launched on every boot to fail.
pub const COMPMGR_ROW: bool = azos_limits::USERSPACE_COMPMGR;
/// Does a `start = true` row belong to the component manager? Every one but
/// the manager itself, the one image the kernel starts and supervises
/// (nothing in ring 3 could restart the manager). A row whose driver moves
/// between hosts at run time (`place.stateless`) is the manager's like any
/// other: its ring-3 host is always up, and the placement controller in the
/// kernel moves only the kernel's calls between the hosts, so no move ends
/// or starts a task.
pub fn manager_starts(r: &crate::types::TaskSpec<'_>) -> bool {
    r.start && r.name.as_bytes() != TASK_COMPMGR_IMAGE
}

/// The two endpoint columns of a row's line in the manager's view
/// (`inspect.components`, `kernel/src/boot/inspect_views.rs`): the endpoints the row
/// *serves*, then the ones it *needs*, each a comma list or `-`, in the form
/// `userspace/services/compmgr/src/tree.rs` matches them in: **every item is
/// the full endpoint name** (`endpoint.term`), so a need is a dependency on
/// whoever serves exactly that string.
///
/// *Served* are the task-hosted endpoints the row holds `READ` on. *Needed*
/// are the task-hosted endpoints it holds the calling half of (`WRITE`
/// without `READ`, not lent on: `transfer` marks the name server's lending
/// right, which is not a call) and, for a row that imports names, the
/// endpoints those names stand for: the import `term` is `endpoint.term`, and
/// every importing row holds the call right on `endpoint.names`
/// (`azos_ipc::cap_seed::seed_names_import`), so the name server is a need
/// too. A name is never authority, but it is a dependency: the shell cannot
/// ask for a terminal before the terminal server serves it.
pub fn manager_view_endpoints(
    topo: &Topology<'_>,
    row: &crate::types::TaskSpec<'_>,
    w: &mut impl core::fmt::Write,
) -> core::fmt::Result {
    use crate::types::endpoint_target;
    let task_hosted = |c: &&CapSpec<'_>| endpoint_target(c).is_some();
    let mut any = false;
    for c in topo
        .caps_of(row)
        .iter()
        .filter(task_hosted)
        .filter(|c| c.kind == CapKind::Endpoint && c.perms.contains(CapPerms::READ))
    {
        write!(w, "{}{}", if any { "," } else { "" }, c.target.as_str())?;
        any = true;
    }
    write!(w, "{} ", if any { "" } else { "-" })?;
    any = false;
    let calls = topo.caps_of(row).iter().filter(task_hosted).filter(|c| {
        c.kind == CapKind::Endpoint
            && c.perms.contains(CapPerms::WRITE)
            && !c.perms.contains(CapPerms::READ)
            && !c.transfer
    });
    for c in calls {
        write!(w, "{}{}", if any { "," } else { "" }, c.target.as_str())?;
        any = true;
    }
    let imports = topo.imports_of(row);
    if !imports.is_empty() {
        write!(w, "{}endpoint.names", if any { "," } else { "" })?;
        any = true;
    }
    for name in imports {
        write!(w, "{}endpoint.{}", if any { "," } else { "" }, name.as_str())?;
        any = true;
    }
    write!(w, "{}", if any { "" } else { "-" })
}
/// Capability slots of the manager's row: the root directory and one launch
/// grant per component. `userspace/services/compmgr` keeps at most
/// `tree::MAX_COMPONENTS` components (`tests/host/topology-tests` fails when
/// the two differ).
pub const MANAGER_CAPS_MAX: usize = 1 + 24;
/// Frame budget of `COMPMGR.ELF`: image, stack, page tables, its view buffer
/// and its table of components; it has no heap.
const COMPMGR_MEM_PAGES: u32 = 32;

/// The Zenoh gateway's image (`userspace/services/zenohd`).
pub const TASK_ZENOHD_IMAGE: &[u8] = b"ZENOHD.ELF";
/// Does the built-in topology carry the gateway's row (Kconfig `ZENOH_GW`)?
/// It starts at boot with the row.
pub const ZENOH_GW_ROW: bool = azos_limits::ZENOH_GW;
/// Frame budget of `ZENOHD.ELF`: image, stack, page tables, the hardened
/// allocator's size-class blocks (the codec allocates), the key table and two
/// batches of link buffers.
const ZENOHD_MEM_PAGES: u32 = 160;
/// `ZENOHD.ELF`'s authority: the call right on `endpoint.decisions` (the
/// receipts and the topics; `transfer` so the gateway derives the per-query
/// warrants from it) and `READ` on the kernel's `entropy` (its ZenohID and the
/// allocator's seed). The one lendable endpoint it holds; the gateway refuses
/// to run with a second, and has no directory.
const ZENOHD_CAPS: &[CapSpec] = &[
    DECISIONS_LEND,
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 },
];

/// The PTP daemon's image (`userspace/services/ptpd`).
pub const TASK_PTPD_IMAGE: &[u8] = b"PTPD.ELF";
/// Does the built-in topology carry the daemon's row (Kconfig `PTPD`)? It
/// starts at boot with the row.
pub const PTPD_ROW: bool = azos_limits::PTPD;
/// Frame budget of `PTPD.ELF`: image, stack, page tables and the receive
/// buffers on its stack; it has no heap.
const PTPD_MEM_PAGES: u32 = 32;
/// The kernel's clock interface (`azos_devif::clock`): the bare interface
/// name, no resource.
const RESOURCE_CLOCK: &[u8] = b"clock";
/// The `net` endpoint (`azos_devif::net`): the stack's resolver and SNTP state.
const RESOURCE_NET: &[u8] = b"net";
const RESOURCE_SOUND: &[u8] = b"sound.0";
/// `PTPD.ELF`'s authority: `WRITE` on `clock` (`Clock::sample` moves the wall
/// clock) and the kernel's view of the `[clock]` row ([`INSPECT_CLOCK_CAP`]:
/// the domain). The sockets of its transport are not capabilities of the row.
const PTPD_CAPS: &[CapSpec] = &[
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::WRITE, target: MaybeStr::from_bytes(RESOURCE_CLOCK), transfer: false, ops: 0 },
    INSPECT_CLOCK_CAP,
];

/// The audio server's image (`userspace/services/audiod`).
pub const TASK_AUDIOD_IMAGE: &[u8] = b"AUDIOD.ELF";
/// Does the built-in topology carry the audio server's row (Kconfig `AUDIOD`)?
/// It starts at boot with the row.
pub const AUDIOD_ROW: bool = azos_limits::AUDIOD;
/// Frame budget of `AUDIOD.ELF`: image, stack, page tables, 48 KiB of static
/// state (the mix pass and the stream table), the pump thread's 16 KiB stack,
/// the device stream's two queues and 16 KiB arena, and the clients' objects it
/// maps (a queue pair and an arena per stream).
const AUDIOD_MEM_PAGES: u32 = 192;
/// The `Sound` endpoint the audio server serves (`azos_devif::sound::ENDPOINT`).
const RESOURCE_ENDPOINT_AUDIO: &[u8] = b"endpoint.audio";
/// The kernel's time authority (`azos_devif::time`): `WRITE` on it is the
/// warrant `SYS_SCHEDCTL` asks before it binds a task to the band or a
/// deadline reservation.
const RESOURCE_TIME: &[u8] = b"time";
/// `AUDIOD.ELF`'s authority: to serve `endpoint.audio` (`READ`), the kernel's
/// `sound.0`, the one device stream it holds (`RW`), and the time warrant its
/// mixer thread presents for its deadline reservation (`WRITE` on `time`).
/// Nothing else.
const AUDIOD_CAPS: &[CapSpec] = &[
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_AUDIO), transfer: false, ops: 0 },
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::RW, target: MaybeStr::from_bytes(RESOURCE_SOUND), transfer: false, ops: 0 },
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::WRITE, target: MaybeStr::from_bytes(RESOURCE_TIME), transfer: false, ops: 0 },
];

/// The MCP bridge's image (`userspace/services/mcpd`).
pub const TASK_MCPD_IMAGE: &[u8] = b"MCPD.ELF";
/// Does the built-in topology carry the bridge's row (Kconfig `MCP_BRIDGE`)?
/// It starts at boot with the row.
pub const MCP_BRIDGE_ROW: bool = azos_limits::MCP_BRIDGE;
/// Frame budget of `MCPD.ELF`: image, stack, page tables, the hardened
/// allocator's size-class blocks (the codec allocates), the line buffer, the
/// proposals and the warrant ledger.
const MCPD_MEM_PAGES: u32 = 160;
/// `MCPD.ELF`'s authority: the call right on `endpoint.decisions` with
/// `transfer` (the receipts, and the per-call warrants it derives from the
/// endpoints it fronts), `READ` on `entropy` (its boot epoch and the
/// allocator's seed) and `READ` on `linkkey`, masked to `node_key` (the image's DICE identity, the
/// root of the warrants it signs: [`LINK_KEY_IDENTITY`], the same grant
/// `RPCSRV.ELF` has, used the same way),
/// and its view of the topology ([`INSPECT_MCP_CAP`]: the endpoints it fronts).
const MCPD_CAPS: &[CapSpec] = &[
    DECISIONS_LEND,
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 },
    LINK_KEY_IDENTITY,
    INSPECT_MCP_CAP,
];

/// The SSH server's image (`userspace/services/sshd`).
pub const TASK_SSHD_IMAGE: &[u8] = b"SSHD.ELF";
/// Does the built-in topology carry the SSH server's row (Kconfig `SSHD`: on
/// but for the MCU kernel, a certifiable build and the embedded profile)? It starts at boot with the
/// row.
pub const SSHD_ROW: bool = azos_limits::SSHD;
/// Frame budget of `SSHD.ELF`: image, stack, page tables, the hardened
/// allocator's blocks (packets, events, a session's buffers) and the mappings
/// of the four pipes a command takes.
const SSHD_MEM_PAGES: u32 = 192;
/// `SSHD.ELF`'s authority: `READ` on `entropy` (the DRBG: the ephemeral keys)
/// and `READ` and `WRITE` on `keys` masked to open a key, read its public part
/// and sign ([`KEYS_SIGNER`]: the host key, derived by the kernel for this image
/// on this board, which the task never holds; it has no `linkkey` grant, so
/// neither the raw board seed nor the node key reaches the one task that faces
/// the network), the `/fat` tree read-write ([`FAT_RW`]),
/// the right to start the tool image a command runs as, the read-only root
/// directory ([`ROOT_RO`]) and the kernel's view of the signed topology's
/// logins ([`INSPECT_LOGINS_CAP`]).
///
/// **The write tree is wider than the server needs, and that is the file
/// layer's limit, not a choice.** The server writes one file, the log of its
/// decisions. A tree covers a path only strictly
/// beneath it, so a tree of one file covers nothing, and the file layer opens
/// only files at the root of the volume (a file inside a directory cannot be
/// opened yet), so there is no directory to give it. When it can, the grant
/// becomes `/fat/SSH`. Until then the server can rewrite what the volume
/// holds; the logins are not on the volume, so they are out of its reach, and
/// the host key is not on it either. An image it
/// rewrites still has to match the table of digests the kernel spawns by. A
/// signed topology adds the launch grants of the images a login may run.
const SSHD_CAPS: &[CapSpec] = &[
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 },
    KEYS_SIGNER,
    FAT_RW,
    CapSpec { kind: CapKind::Node, perms: CapPerms::EXEC, target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false, ops: 0 },
    ROOT_RO,
    INSPECT_LOGINS_CAP,
];

/// The name server's image (`userspace/services/namesd`): the Names object.
pub const TASK_NAMESD_IMAGE: &[u8] = b"NAMESD.ELF";
/// Frame budget of `NAMESD.ELF`: image, stack, page tables and its static
/// state; it has no heap.
const NAMESD_MEM_PAGES: u32 = 32;
/// The server half of `endpoint.names`: `READ` claims it for `NAMESD.ELF`.
const NAMES_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"endpoint.names"), transfer: false, ops: 0,
};
/// What `NAMESD.ELF` may lend: the call right on `endpoint.term`, with `DUP`
/// and `TRANSFER` (`transfer = true`) so the kernel can derive an attenuated copy for a
/// borrower. `WRITE` claims no service: `TERMD.ELF` stays the server.
const TERM_LEND: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_TERM), transfer: true, ops: 0,
};
/// What `NAMESD.ELF` may lend of the monitor: the call right on
/// `endpoint.vmctl`, as [`TERM_LEND`] is for the terminal.
const VMCTL_LEND: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_VMCTL), transfer: true, ops: 0,
};
/// `NAMESD.ELF`'s authority: to serve `endpoint.names`, and to lend the
/// endpoints listed here (`vmctl` only where the monitor's row exists). Its
/// row is the whole name space: there is no other. Plus its view of the
/// topology ([`INSPECT_NAMES_CAP`]: the rows' imports, the pool index of each
/// endpoint it holds).
const NAMESD_CAPS: &[CapSpec] = if VMMD_ROW {
    &[NAMES_SERVE, TERM_LEND, VMCTL_LEND, INSPECT_NAMES_CAP]
} else {
    &[NAMES_SERVE, TERM_LEND, INSPECT_NAMES_CAP]
};
/// The caller half of `endpoint.decisions`: the right to ask the decision
/// server, and nothing more (`WRITE` claims no service).
const DECISIONS_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: false, ops: 0,
};
/// The server half: `READ` claims the endpoint for `DECISD.ELF`.
const DECISIONS_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: false, ops: 0,
};

/// The decision server's image (`userspace/services/decisd`).
pub const TASK_DECISD_IMAGE: &[u8] = b"DECISD.ELF";
/// Frame budget of `DECISD.ELF`: image, stack, page tables and its static
/// table of decoded records (24 x 104 bytes) and their copy; no heap.
const DECISD_MEM_PAGES: u32 = 48;
/// `DECISD.ELF`'s authority: the right to serve `endpoint.decisions`, and the
/// records it serves: the introspection tree's admin region (a record's
/// subject may be a task), granted against the task view, which the row lists
/// first; the public region for the refresh period.
/// Without an admin region (Kconfig INSPECT off, or INSPECT_ADMIN_PAGES 0)
/// there are no records to read, and the row asks for none.
const DECISD_CAPS: &[CapSpec] = if azos_limits::INSPECT && azos_limits::INSPECT_ADMIN_PAGES != 0 {
    &[DECISIONS_SERVE, TASK_VIEW_CAP, INSPECT_PUBLIC_CAP, INSPECT_ADMIN_CAP]
} else {
    &[DECISIONS_SERVE]
};

/// Does the built-in topology carry the input server's row? It does when the
/// drivers write its stream (Kconfig `INPUTD`) into a region that exists
/// ([`TERM_INPUT_RING`]).
pub const INPUTD_ROW: bool = azos_limits::INPUTD && TERM_INPUT_RING;
/// The input server's image (`userspace/services/inputd`).
pub const TASK_INPUTD_IMAGE: &[u8] = b"INPUTD.ELF";
/// Frame budget of `INPUTD.ELF`: image, stack, the service thread's 8 KiB
/// stack, page tables and its static state; no heap. 64 pages like the log
/// sink: the aarch64 image (hard-float userspace, a page-aligned segment per
/// permission) needs more than the 48 of the smaller services. The rings it
/// makes for holders are memory objects, booked to their regions.
const INPUTD_MEM_PAGES: u32 = 64;
/// `INPUTD.ELF`'s one grant of its endpoint: `READ` claims it for the server,
/// `WRITE` with `transfer` is the call right it derives its warrants from (each
/// with a badge only the server names, `azos_devif::input::warrant_badge`) and
/// lends. One grant, not two: `SYS_CAP_INFO` finds a capability by endpoint, and
/// of two on the same endpoint it answers the first, so the server could not
/// tell which one it holds.
const INPUT_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ.union(CapPerms::WRITE),
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_INPUT), transfer: true, ops: 0,
};
/// The caller half: the right to ask for the focus, and nothing more (`WRITE`
/// claims no service). It is unbadged and held by every program started through
/// `TOOLBOX.ELF`, so it is also the right to take the focus from the holder; after
/// the Secure Attention Key, with a compositor in the build, the input server
/// refuses it until the trusted surface ([`INPUT_TRUSTED`]) has taken the focus.
const INPUT_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_INPUT), transfer: false, ops: 0,
};
/// The drivers' region, `READ|WRITE|MAP`: the server reads the stream ring and
/// moves its tail. The terminal server maps the same object for the first ring.
const INPUTD_EVENTS: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"input.events"), transfer: false, ops: 0,
};
/// The focus word, `READ|WRITE|MAP`: the server writes who holds the keyboard,
/// the drivers read it. This row is the only one granted it (the terminal
/// server's grant of the events region is read-write, so the word has a page
/// of its own: `azos_ipc::kregion`).
const INPUTD_FOCUS: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"input.focus"), transfer: false, ops: 0,
};
/// `INPUTD.ELF`'s authority.
const INPUTD_CAPS: &[CapSpec] = &[INPUT_SERVE, INPUTD_EVENTS, INPUTD_FOCUS];

/// Does the built-in topology carry the compositor's row? It does when the
/// build has one (Kconfig `COMPOSITOR`, which needs a framebuffer and the input
/// server) and the input server's row exists for its trusted call right to be
/// served.
pub const COMPOSITOR_ROW: bool = azos_limits::COMPOSITOR && INPUTD_ROW;
/// The compositor's image (`userspace/services/compositor`).
pub const TASK_COMPOSITOR_IMAGE: &[u8] = b"COMPSRV.ELF";
/// Frame budget of `COMPSRV.ELF`: image, stack, the painter thread's 16 KiB
/// stack, page tables, the scene (a layer table, the 16 KiB cursor plane) and
/// the two panels' pixels (the banner's and the refusal panel's, about 200
/// KiB), 192 pages with no heap; plus the surface's bands (Kconfig
/// `COMPOSITOR_SURFACE_PAGES`). The bands are memory objects this server
/// creates, and a row's ceiling covers the shared memory it created
/// (`memory.rs`): at 192 alone a 640x480 screen's five 64-page bands (320
/// pages) could not all be made, and the server ran headless. The clients' buffers are theirs, charged to them.
const COMPOSITOR_MEM_PAGES: u32 = 192 + azos_limits::COMPOSITOR_SURFACE_PAGES as u32;
/// `COMPSRV.ELF`'s one grant of its endpoint: `READ` claims it for the server,
/// `WRITE` with `transfer` is the call right it derives each window's right from
/// (with a badge only the server names, `azos_compositor::window_badge`) and lends.
/// One grant, not two, for the reason [`INPUT_SERVE`] gives.
const COMPOSITOR_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ.union(CapPerms::WRITE),
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_COMPOSITOR), transfer: true, ops: 0,
};
/// The caller half: the right to attach a window and post its damage, and
/// nothing more (`WRITE` claims no service).
const COMPOSITOR_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_COMPOSITOR), transfer: false, ops: 0,
};
/// Connector 0 of the kernel's `Display` interface with all three classes:
/// `READ` observes it, `WRITE` makes surfaces and presents, `EXEC` claims the
/// screen. The one row that holds `WRITE` or `EXEC` on it.
const COMPOSITOR_DISPLAY: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC),
    target: MaybeStr::from_bytes(b"display.0"), transfer: false, ops: 0,
};
/// The trusted surface's call right on `endpoint.input`: `EXEC` beside the call
/// right, which the seeder (`azos_ipc::cap_seed`) stamps with
/// [`azos_devif::input::TRUSTED_BADGE`]. After the Secure Attention Key the input
/// server grants the focus to this caller alone (`userspace/services/inputd/src/
/// focus.rs`). Only this row holds it; [`INPUT_CALL`] is the plain one.
const INPUT_TRUSTED: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE.union(CapPerms::EXEC),
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_INPUT), transfer: false, ops: 0,
};
/// Does the decision server run (the `start` of its row)? Its call right is in
/// the compositor's row only then: a call on an endpoint nobody accepts waits
/// for ever.
const DECISD_RUNS: bool = azos_limits::DECISION_REFUSALS_DURABLE || azos_limits::DECISION_RECORDS_DEV;
/// `COMPSRV.ELF`'s authority.
const COMPOSITOR_CAPS: &[CapSpec] = if DECISD_RUNS {
    &[COMPOSITOR_SERVE, COMPOSITOR_DISPLAY, INPUT_TRUSTED, DECISIONS_CALL]
} else {
    &[COMPOSITOR_SERVE, COMPOSITOR_DISPLAY, INPUT_TRUSTED]
};

/// The kernel log's sink (`userspace/services/logd`).
pub const TASK_LOGD_IMAGE: &[u8] = b"LOGD.ELF";
/// Frame budget of `LOGD.ELF`: image, stack, page tables, its 4 KiB batch and
/// line buffers; no heap. The ring's mapping is booked to the region, not
/// here. 64 pages: the aarch64 image (hard-float userspace, a page-aligned
/// segment per permission) needs more than the 48 of the smaller services.
const LOGD_MEM_PAGES: u32 = 64;
/// The kernel log's ring, `READ|MAP`: the sink maps it and reads; the kernel
/// is the only writer (`azos_ipc::kregion`).
const LOGD_KLOG_RING: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"klog.ring"), transfer: false, ops: 0,
};
/// `LOGD.ELF`'s authority: the ring, and the `/fat` tree its files are written
/// in (opened beneath the read-only root directory, [`ROOT_RO`]).
const LOGD_CAPS: &[CapSpec] = &[LOGD_KLOG_RING, FAT_RW, ROOT_RO];

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
/// them, and the tool takes the second as the remote one. `why crash` reads the
/// crash dumps (`CRASHn.DMP`) the kernel leaves in the Domains' write trees,
/// beneath the read-only root directory ([`ROOT_RO`], found by its constant
/// resource, `sys::root_dir`); it writes nothing, so it holds no write tree.
/// `why woke` reads the wake log of the public introspection region
/// ([`INSPECT_PUBLIC_CAP`], Kconfig INSPECT, and not under the console
/// lockdown): metrics, no task names (the admin region and the task view are
/// not its).
const WHY_CAPS: &[CapSpec] = if azos_limits::INSPECT && !azos_limits::CONSOLE_LOCKDOWN {
    &[DECISIONS_CALL, RPC_DECISIONS_CALL, WHY_ENTROPY, ROOT_RO, INSPECT_PUBLIC_CAP]
} else {
    &[DECISIONS_CALL, RPC_DECISIONS_CALL, WHY_ENTROPY, ROOT_RO]
};
const WHY_ENTROPY: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0,
};

/// The package installer's endpoint: `PKGD.ELF` serves the `Packages` object
/// on it (`READ`), `PKG.ELF` calls it (`WRITE`).
const RESOURCE_ENDPOINT_PACKAGES: &[u8] = b"endpoint.packages";
/// The caller half of `endpoint.packages`: the right to ask the installer.
const PACKAGES_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PACKAGES), transfer: false, ops: 0,
};
/// The server half: `READ` claims the endpoint for `PKGD.ELF`.
const PACKAGES_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_PACKAGES), transfer: false, ops: 0,
};
/// Where the installer stages: the one tree it may change.
const PKG_STAGE_TREE: CapSpec = CapSpec {
    kind: CapKind::Node,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(b"/fat/PKG"), transfer: false, ops: 0,
};

/// Does the built-in topology carry the package installer's two rows (and the
/// shell its right to start the tool)? Every class but a small board
/// (`HWCLASS_EMBEDDED`), like the Linux personality's.
pub const PKGD_ROW: bool = !azos_limits::HWCLASS_EMBEDDED;

/// The package installer's image (`userspace/services/pkgd`).
pub const TASK_PKGD_IMAGE: &[u8] = b"PKGD.ELF";
/// Frame budget of `PKGD.ELF`: its image (a `std` program with TLS in it,
/// about 1 MiB), its stack and the heap of a handshake (`PKGD_STD_PAGES`), the buffers it
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
    (PKGD_STD_PAGES + kb.div_ceil(4) + topo.div_ceil(4096)) as u32
};
/// The part of `PKGD.ELF`'s budget that is not its buffers: a `std` image of
/// about 1 MiB (250 pages, `RPCQUIC.ELF`'s size class), the stack and a TLS
/// handshake's heap (the allocator's headers and quarantine included).
///
/// Only the image share is measured (0.85 to 1.0 MiB, riscv64 to x86_64, so up
/// to 253 pages). The other ~260 pages are a ceiling for the stack and the
/// handshake's heap, not a measurement: it stays an estimate until a boot with
/// the installer's row reports its peak (`[AUTORUN]`/census `[MEM]` rows).
/// The boot loader's staging copy is not part of it, nor of the census peak:
/// those frames are charged to no Domain and go back before the program's
/// budget is installed.
const PKGD_STD_PAGES: u64 = 512;
/// READ on the kernel-hosted `ota` endpoint: the installer reads which slot is
/// the inactive one (`Ota::status`) to stage a whole-system update into it. It
/// holds no WRITE, so the slot switch stays the kernel's and `OTA.ELF`'s. Like
/// every interface grant the kernel withholds it from an image whose seccomp
/// row does not list the interface (the row does).
const PKG_OTA_STATUS: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"ota"), transfer: false, ops: 0,
};
/// READ on the kernel's `entropy` endpoint: the installer's TLS handshake draws
/// its keys from the pool (the std port's random source), and its allocator is
/// keyed from it. The seccomp row lists the interface.
const PKG_ENTROPY: CapSpec = CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 };
/// `PKGD.ELF`'s authority: the right to serve `endpoint.packages`, the
/// staging tree, to read the boot slots and to draw entropy. It opens the
/// packages by path beneath the read-only root directory ([`ROOT_RO`]); the
/// staging tree is its write authority. The network it dials for `fetch` is its
/// seccomp profile's (the socket ops), as for the relay of the QUIC link.
const PKGD_CAPS: &[CapSpec] = &[PACKAGES_SERVE, PKG_STAGE_TREE, PKG_OTA_STATUS, PKG_ENTROPY, ROOT_RO];

/// The package tool's image (`userspace/services/pkg`).
pub const TASK_PKG_IMAGE: &[u8] = b"PKG.ELF";
/// Frame budget of `PKG.ELF`: a small image and a few stack buffers
/// ([`PKG_IMAGE_PAGES`]) and the file it is told to install, held whole.
///
/// The tool reads the file into a memory object it creates and hands the
/// installer that object (the budget covers "shared memory it created"), so the
/// file is in its budget at once: at most Kconfig `PKG_MAX_KB`, the largest
/// package the installer accepts, so the largest file the tool holds. A budget
/// of the image alone refused the object ("cannot open the package file") for
/// a file past ~30 KiB. The budget is a ceiling, not a reservation (the frames
/// are taken as the object is filled), but the memory admission adds it up
/// with every other row's. A bundle too large for it does not go through the
/// tool at all: the installer fetches it itself (`pkg fetch-update`).
pub const PKG_MEM_PAGES: u32 = (PKG_IMAGE_PAGES + (azos_limits::PKG_MAX_KB as u64).div_ceil(4)) as u32;
/// The part of `PKG.ELF`'s budget that is not the file: a small image, its
/// stack and page tables.
const PKG_IMAGE_PAGES: u64 = 32;
/// `PKG.ELF`'s authority: the right to ask `endpoint.packages`. It opens the
/// package file it is told to, beneath the read-only root directory
/// ([`ROOT_RO`]).
const PKG_CAPS: &[CapSpec] = &[PACKAGES_CALL, ROOT_RO];

/// The proxy endpoint of `decisions` (`endpoint.rpc-decisions`): the local face
/// of the decision server of the peer node. The name starts with
/// [`PROXY_PREFIX`](crate::types::PROXY_PREFIX), which is what makes the kernel
/// treat it as a proxy (a real-time caller is refused) and `neverallow` allow
/// only `RPCSRV.ELF` to serve it.
const RPC_DECISIONS_CALL: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_RPC_DECISIONS), transfer: false, ops: 0,
};
/// The server half of the proxy: `READ` claims it for `RPCSRV.ELF`.
const RPC_DECISIONS_SERVE: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_RPC_DECISIONS), transfer: false, ops: 0,
};
const RESOURCE_ENDPOINT_RPC_DECISIONS: &[u8] = b"endpoint.rpc-decisions";
/// What `RPCSRV.ELF` may lend to a peer: the call right on
/// `endpoint.decisions` with `DUP` and `TRANSFER` (`transfer = true`), from which it derives
/// each peer session's attenuated, expiring warrant. `WRITE` claims no
/// service: `DECISD.ELF` stays the server.
const DECISIONS_LEND: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_DECISIONS), transfer: true, ops: 0,
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
///
/// Plus the two secrets of the Noise handshake, `READ` on each of the kernel's
/// `entropy` (the ephemeral keys) and `READ` on `linkkey` masked to `node_key`
/// ([`LINK_KEY_IDENTITY`]: the node's static key, derived from the board key, which the task never
/// reads); the seccomp row lists the same two interfaces.
const RPCSRV_CAPS: &[CapSpec] = &[
    RPC_DECISIONS_SERVE,
    DECISIONS_LEND,
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 },
    LINK_KEY_IDENTITY,
    // Its view of the topology: the peers, the exports of what it holds.
    INSPECT_RPC_CAP,
];

/// The relay's image (`userspace/services/rpcquic`): the QUIC leg of the RPC link.
pub const TASK_RPCQUIC_IMAGE: &[u8] = b"RPCQUIC.ELF";
/// Does the built-in topology carry the relay's row? With Kconfig `RPC_QUIC` (which
/// needs a peer, `azos_limits` refuses the build otherwise); the image is built and
/// shipped either way.
pub const RPCQUIC_ROW: bool = azos_limits::RPC_QUIC;
/// Frame budget of `RPCQUIC.ELF`: a `std` image of about 1 MiB (250 pages), the
/// stack and a thread's, and the heap: the connection's state, its stream
/// buffers and the TLS handshake's.
const RPCQUIC_MEM_PAGES: u32 = 1024;
/// `RPCQUIC.ELF`'s authority: `READ` on the kernel's `entropy` endpoint.
const RPCQUIC_CAPS: &[CapSpec] = &[
    CapSpec { kind: CapKind::Endpoint, perms: CapPerms::READ, target: MaybeStr::from_bytes(RESOURCE_ENTROPY), transfer: false, ops: 0 },
];

/// The peer's static Noise key of Kconfig `RPC_PEER_NOISE_PK` (64 hex digits)
/// as a list of one key, or none when the option is empty. A value that is not
/// 64 hex digits (or is all zero) is a configuration error: the build says so
/// rather than pin nothing.
fn rpc_peer_noise_pk() -> Option<[u8; 32]> {
    let t = azos_limits::RPC_PEER_NOISE_PK.as_bytes();
    if t.is_empty() {
        return None;
    }
    assert!(t.len() == 64, "RPC_PEER_NOISE_PK must be 64 hex digits");
    let nib = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("RPC_PEER_NOISE_PK must be 64 hex digits"),
    };
    let mut k = [0u8; 32];
    for (i, o) in k.iter_mut().enumerate() {
        *o = nib(t[2 * i]) << 4 | nib(t[2 * i + 1]);
    }
    assert!(k != [0u8; 32], "RPC_PEER_NOISE_PK must not be all zero");
    Some(k)
}

/// The full task view (wave 12, owner round 48): `Cap<Task>` `READ` on
/// `"tasks"`, the warrant the admin introspection region is granted against
/// (its task list, the wake log, the decisions): without it a row that asks
/// for `inspect.admin` is refused it. `SH.ELF`, `DECISD.ELF` and
/// `TOOLBOX.ELF` (`ps`) hold it, and neither under `CONSOLE_LOCKDOWN`, which
/// withholds every grant beyond the shell's own work from the console path
/// (the recovery console's seed is empty there too).
pub const TASK_VIEW_CAP: CapSpec = CapSpec {
    kind: CapKind::Domain,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(b"tasks"), transfer: false, ops: 0,
};

/// `READ` on the kernel's `net` endpoint: `host` asks its resolver, `ntp` reads
/// the SNTP client's state. Observation only (`Net` needs `READ` for both ops).
const TOOLBOX_NET_CAP: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_NET), transfer: false, ops: 0,
};

/// `READ` on the kernel's `clock` endpoint: `ntp` shows how the discipline
/// stands (`Clock::status`). Not the right to move time, which only the PTP
/// daemon holds.
const TOOLBOX_CLOCK_CAP: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::READ,
    target: MaybeStr::from_bytes(RESOURCE_CLOCK), transfer: false, ops: 0,
};

/// `READ|WRITE` on the kernel's `sound.0` endpoint (Kconfig DRV_VIRTIO_SND):
/// `beep` opens a playback stream, posts periods and drains it. `WRITE` runs a
/// stream; capture is a different stream whose `open` also needs the `mic`
/// effect of the row's class, which no tool of this image asks for.
const TOOLBOX_SOUND_CAP: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::RW,
    target: MaybeStr::from_bytes(RESOURCE_SOUND), transfer: false, ops: 0,
};

/// The call right on the audio server's endpoint (Kconfig AUDIOD), lent
/// (`transfer = true`, which is what gives a row `DUP`: never its letters) so
/// the tool can derive the badged copy the server tells its streams apart by
/// (`cap_derive`): `beep` plays through the server when the row holds this,
/// and the row then holds no `sound.0` (the device has one holder). `WRITE`
/// only: `READ` is the grant that serves the endpoint.
const TOOLBOX_AUDIO_CAP: CapSpec = CapSpec {
    kind: CapKind::Endpoint,
    perms: CapPerms::WRITE,
    target: MaybeStr::from_bytes(RESOURCE_ENDPOINT_AUDIO), transfer: true, ops: 0,
};

/// `TOOLBOX.ELF`'s authority outside `CONSOLE_LOCKDOWN`, in order: the full
/// task view, for `ps`; the introspection regions (Kconfig INSPECT), the admin
/// one after the task view, whose grant asks the table for it (the admin
/// warrant); `READ` on the `net` and `clock` endpoints (`host`, `ntp`); the
/// audio server's endpoint when the build has it (Kconfig AUDIOD), else the
/// sound endpoint when the build has the device (`beep`); the read-only root
/// directory ([`ROOT_RO`]); and the call rights on the input server's and the
/// compositor's endpoints with their rows.
const TOOLBOX_CAPS_BUILT: ([CapSpec<'static>; 9], usize) = {
    let mut caps = [ROOT_RO; 9];
    let mut n = 0;
    caps[n] = TASK_VIEW_CAP;
    n += 1;
    if azos_limits::INSPECT {
        caps[n] = INSPECT_PUBLIC_CAP;
        n += 1;
        if azos_limits::INSPECT_ADMIN_PAGES != 0 {
            caps[n] = INSPECT_ADMIN_CAP;
            n += 1;
        }
    }
    caps[n] = TOOLBOX_NET_CAP;
    caps[n + 1] = TOOLBOX_CLOCK_CAP;
    n += 2;
    if AUDIOD_ROW {
        caps[n] = TOOLBOX_AUDIO_CAP;
        n += 1;
    } else if azos_limits::DRV_VIRTIO_SND {
        caps[n] = TOOLBOX_SOUND_CAP;
        n += 1;
    }
    caps[n] = ROOT_RO;
    n += 1;
    // With the input server's row, the call right on `endpoint.input` (`input
    // watch` asks it for the focus), after the root.
    if INPUTD_ROW {
        caps[n] = INPUT_CALL;
        n += 1;
    }
    // With the compositor's row, the call right on its endpoint (`window` attaches
    // a window of its own), after the input server's.
    if COMPOSITOR_ROW {
        caps[n] = COMPOSITOR_CALL;
        n += 1;
    }
    (caps, n)
};
const TOOLBOX_CAPS: &[CapSpec] = TOOLBOX_CAPS_BUILT.0.split_at(TOOLBOX_CAPS_BUILT.1).0;

/// The public introspection region (Kconfig INSPECT), `READ|MAP`: `inspect`
/// maps it and walks the kernel's tree with loads (`azos_ipc::inspect_region`).
const INSPECT_PUBLIC_CAP: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"inspect.public"), transfer: false, ops: 0,
};

/// The admin introspection region, `READ|MAP`: the tasks' names and states.
/// Granted only to a row that also lists [`TASK_VIEW_CAP`] before it.
const INSPECT_ADMIN_CAP: CapSpec = CapSpec {
    kind: CapKind::MemObj,
    perms: CapPerms::READ.union(CapPerms::MAP),
    target: MaybeStr::from_bytes(b"inspect.admin"), transfer: false, ops: 0,
};
/// A view region of the introspection tree (`azos_ipc::inspect_region`):
/// `READ|MAP` on `inspect.<view>`, the signed topology's wiring one service
/// needs, granted only to the rows that declare it.
const fn inspect_view(target: &'static [u8]) -> CapSpec<'static> {
    CapSpec { kind: CapKind::MemObj, perms: CapPerms::READ.union(CapPerms::MAP), target: MaybeStr::from_bytes(target), transfer: false, ops: 0 }
}
/// The name server's view: the rows' imports, the endpoints it holds.
const INSPECT_NAMES_CAP: CapSpec = inspect_view(b"inspect.names");
/// The RPC server's view: the peers, the exports of the endpoints it holds.
const INSPECT_RPC_CAP: CapSpec = inspect_view(b"inspect.rpc");
/// The MCP bridge's view: the endpoints it holds with the call and lend right.
const INSPECT_MCP_CAP: CapSpec = inspect_view(b"inspect.mcp");
/// The component manager's view: the plan it starts.
const INSPECT_COMPONENTS_CAP: CapSpec = inspect_view(b"inspect.components");
/// The logins of the signed topology (`[login.NAME]` rows).
const INSPECT_LOGINS_CAP: CapSpec = inspect_view(b"inspect.logins");
/// The topology's `[clock]` row.
const INSPECT_CLOCK_CAP: CapSpec = inspect_view(b"inspect.clock");

/// Under `CONSOLE_LOCKDOWN`: no task view and no introspection region, as
/// before wave 12; the tools still read files, beneath the read-only root.
const TOOLBOX_CAPS_LOCKDOWN: &[CapSpec] = &[ROOT_RO];

/// Under `CONSOLE_LOCKDOWN`: the volume is not the shell's to change, and it
/// may not start a privileged tool (no launch grant on `POWER.ELF`). It still
/// reads (the root directory, read-only) and writes `/tmp`.
const SH_CAPS_LOCKDOWN: &[CapSpec] = &[
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::EXEC,
        target: MaybeStr::from_bytes(TASK_TOOLBOX_IMAGE), transfer: false, ops: 0,
    },
    CapSpec {
        kind: CapKind::Node,
        perms: CapPerms::RW,
        target: MaybeStr::from_bytes(b"/tmp"), transfer: false, ops: 0,
    },
    ROOT_RO,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_minimal_is_well_formed() {
        let topo = default_minimal();
        assert_eq!(topo.classes_len(), 6);
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
