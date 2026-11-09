# AzOS changelog

All notable changes to AzOS are recorded here, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There are no tagged
releases yet. The ABI crate keeps its own file,
[`crates/core/abi/CHANGELOG.md`](crates/core/abi/CHANGELOG.md).

## [Unreleased]

### Added

- The ring-3 behaviour engine (`BRAINCLI.ELF`) asks the inference service for
  L1's verdict every cycle, within Kconfig `ML_REPLY_TIMEOUT_US`, and holds a
  stop on any missing one (no reply in time, a refusal, an unsigned or
  unknown model, a reply that is not a class); the rangefinders stay the floor
  under the model. `MLSRV.ELF` starts by its own row again; the engine's
  seccomp row gains `SYS_THREAD_CREATE`, the futex calls, `SYS_MO_UNMAP` and
  the `frame` and `infer` interfaces, and the autorun row a badged `WRITE`
  grant on `endpoint.infer`, withheld from every other image. The engine sends
  the camera's frames on its brain link (`PKT_CAMERA`, Kconfig
  `BRAIN_CAMERA_PERIOD_MS`, renamed from `CAMERA_TX_CAPTURE_PERIOD_MS`), and
  the brain's `PKT_PREDICT` biases L1 towards turning away earlier, never
  faster than the layers chose.

- The flight recorder keeps its durable records (the e-stop latch and release,
  the release nonce floor and key pin, the write-ahead effect and stop records,
  every other safety record) in one single-producer queue per CPU instead of one
  overwrite ring (Kconfig `LOG_QUEUES`, `LOG_QUEUE_ENTRIES`,
  `LOG_QUEUE_SAFETY_RESERVE`, which replace `LOG_RING_ENTRIES` and
  `LOG_RING_SAFETY_RESERVE`). Nothing is evicted: a full queue refuses the new
  record (an effect with `Why::RingFull`, anything else counted in
  `events_dropped`), where the ring evicted the oldest; the effect pin and the
  latch pin are gone. A writer handle another CPU holds is waited for (a
  bounded time) rather than reported as a full queue, and an effect refused
  for it gets `Why::RecorderBusy`; a safety record or a stop whose queue is full
  goes to another queue; every push that reaches the flush watermark wakes the
  flusher. The flusher writes the records in push order across CPUs and keeps
  a batch in RAM until an `Ok` fsync of a file that holds it (the rotation's
  fsync result included, and never on the rotation's word after the batch's own
  fsync failed), writing it again otherwise; a latch or release carried into a
  newer file is written as history (record flag 2), which the replay does not
  take the latch from
  ([Documentation/effects.md](Documentation/effects.md#durability-invariants-of-the-recorder)).
- An ext4 volume, read-only, parsed and served in ring 3 (Kconfig
  `FS_EXT4_RING3`, on for the desktop and server presets): `EXT4D.ELF` reads its
  partition through its block capability with a native parser
  (`userspace/lib/ext4`: extents and the block map, htree directories read as
  linear, symlinks, `64bit`, `metadata_csum` checked; `inline_data`,
  `encrypt`, `casefold`, `meta_bg`, `mmp`, `bigalloc`, blocks over 4 KiB and a
  journal that needs recovery refused at mount with the reason) and serves the
  file protocol on `endpoint.ext4`; the kernel mounts it from a `[volume.NAME]`
  row with `format = "ext4"` through `azos_fs::endpoint::EndpointFs`, so a
  program reading the mount cannot tell it from FAT32. The server's row holds
  `READ` on its partition, its endpoint and the shared region `MemObj
  fs.share`, nothing else; a short read the server does not call the end is
  refused ([Documentation/storage.md](Documentation/storage.md)).
- Extension contract level 4: an extension registers its hard-deadline loops
  over an effect as `ext_api::EffectLoop` descriptors (`BootHook::EffectLoop`:
  name, body, priority), and the base creates each one at the task phase on the
  effect loops' CPU (Kconfig `TASK_CONTROL_PLACE`), exempt from the real-time
  band's budget and registered as a safety task. The robot registers `rt-motor`
  and `flight-ctrl`; the kernel's task list no longer names them
  ([Documentation/effects.md](Documentation/effects.md)).

- Extension contract level 5: `ext_api::Enforcer` checks (name, period,
  tick), run by one kernel enforcement task (`enforce`, a safety task on the
  watchdog's CPU). The robot's enforcer judges the sensor bus with the safety
  layer (L0) and the drivetrain loop applies the verdict as a cap on every
  command whoever chose it; it also retires the payload pulse, latches the
  e-stop on an RC link loss or kill switch, and arms and latches the geofence.
  The behaviour loop keeps only the RC sticks.

- The robot's sensor producers (imu, odom, sensor-slow, sensor-ahrs) are
  created by the robot manifest's task hook with the priorities it declares;
  `azos_sched` keeps the generic `HARD_RT_PRIORITY` band in place of the
  robot-named control and sensing priorities.

- The `Authority` interface (`endpoint.authority`): a ring-3 engine stages a
  protocol frame (`put`, 48 bytes a piece) and submits it (`frame`); the
  extension that owns the protocol answers it in the kernel. The robot answers
  the brain protocol's authority frames there (e-stop, degraded mode,
  semantic level, the operator's e-stop and device-hold release, payload and
  configuration effects, an actuator command's confidence, unknown types
  recorded): one handler, which the kernel's own brain link and its UART
  bridge now call instead of two copies of the dispatch.

- `Motor::command(left, right)`: the drivetrain's command published to its
  effect loop, both wheels' effects through the gate, `(0, 0)` always carried
  out, motion refused while halted, and a dead commander's command stopped:
  the ring-3 behaviour engine's output path.

- The robot's behaviour engine runs in ring 3. `BRAINCLI.ELF`, the robot disk
  image's autorun, is the engine and the one brain link: it chooses among L1
  (avoid an obstacle the rangefinders see), L2 (the brain's command for 2 s)
  and L3 (explore while a session is up), as the kernel's layer switches allow
  (`Behavior::status`), publishes with `Motor::command`, and hands the brain's
  authority frames to the kernel (`endpoint.authority`). It runs without a
  brain when the image has no link key. The kernel keeps the enforcement: the
  safety layer's cap (L0), the e-stop latch and the operator's release, the RC
  override (which outranks the engine and survives its death), the geofence,
  the envelope and the effect loops. Every motor write is capped by the
  safety layer's fresh verdict (a stale one stops); relaxing a restriction
  needs the operator's signed warrant; the UART bridge carries only the
  e-stop, straight to the kernel. `MLSRV.ELF` is not started while it has no
  client; the
  `[BENCH-RES]` sweep and the WCET report are a QEMU boot task.

### Removed

- The kernel's behaviour, brain-tx and camera-tx tasks
  (`kernel/src/tasks/{behavior,brain_link,camera}.rs`, `kernel/src/behavior_*.rs`),
  the arbiter, layers, remote, brain-tx, camera-tx, offline, skill, habit,
  balance and ML-link modules of `azos_behavior`, the multi-stream framing
  (`crates/net/multi-stream`, `multi_stream=`), the brain-tx Kconfig
  (`config/subsys/Kconfig.brain`), `NO_ML`, `TASK_BEHAVIOR_PLACE`,
  `ML_REPLY_TIMEOUT_US`, the `ml_enabled` and `behavior_camera_port` keys, and
  the robot-named priorities of `azos_sched` (the manifest declares each task's),
  the kernel-side brain link (`encrypt_link`), the frame handler's
  `PKT_PREDICT` arm, and the UART bridge's brain role.
  The camera's frames reach ring 3 through the `Frame` interface only.

- kibi, the ported terminal editor, is back as `KIBI.ELF` (Kconfig
  `USERSPACE_KIBI`, on for the desktop and server presets): the shell lends the
  first stage of a foreground job a terminal of its own (`Terminal::lend_job`,
  interface level 2: a call right badged with the job, offered in the spawn's
  move list as fd 0), the terminal server answers that badge only while the job
  has the focus and only for size, mode, echo and input, and revokes it and puts
  the shell's mode back when the focus returns. The std runtime reads fd 0
  through it and `std::os::azos::terminal` (feature `azos_ext`) gives raw mode,
  echo and the size ([Documentation/design/user-shell.md](Documentation/design/user-shell.md)).

- `SYS_SPAWN_EX` hands an endpoint call capability to the child (`Move::kind =
  MOVE_KIND_ENDPOINT`, request version 2): a badged call right the caller holds
  with `TRANSFER`, moved with the call right alone, its badge and its place in
  the warrant tree kept, so the server that minted the badge revokes it where
  it sits. Only into a row that names the endpoint in the new CAPS.TOML
  format-8 task key `receives = ["term"]` (which grants nothing); a required
  entry the row does not receive is `-EACCES`, an offered one (`MOVE_F_OFFER`)
  is skipped. A badge the kernel stamped at seeding (a warrant-tree root) is
  never handed on, the endpoints move after every other entry, and a spawn
  refused after the moves (the startup block included) undoes them, destroying
  a handed endpoint copy. A badge the kernel stamped at seeding
  (`Warrant::STAMPED`, kept by every copy) is never handed on. Lending console
  input on the owner's behalf takes an unbadged call right (a job's badged
  copy is not one). The terminal server finds its rights by the endpoint they
  name (`SYS_CAP_INFO` `CAP_INFO_ENDPOINT`), and a login right its row grants
  and it does not hold keeps the console locked; admission refuses `transfer`
  on a call right on `endpoint.login`. Admission refuses a
  received name no row serves or one the row also imports ([Documentation/abi.md](Documentation/abi.md)).

- The native basic utilities (`userspace/lib/coreutils`, run by `COREUTIL.ELF`, an image whose row holds the root directory and the shell's write trees and nothing else):
  `cp mv rm mkdir rmdir touch stat du df find head tail grep sort uniq tr cut tee
  date env pwd basename dirname seq printf` with the common flags, over a `Host`
  trait so they are tested on the host; `chmod chown chgrp umask ln kill mkfifo`
  answer with what the system has instead. `mkdir` and `rm` are applets, no
  longer shell builtins.

- The sensor class (`azos_drv_base::sensors`): every sensor is an instance with
  channels (quantity, unit, width, range, rate), served by the `Sensor`
  interface and published as a stream (`azos_rings::Log`: one writer, readers
  with their own cursor and an overrun count). The board's ten sensors keep the
  topology's `sensor.<n>` numbers; the IMU, odometry, encoders, rangefinders,
  battery, GPS and digital lines are streams their tasks publish into and the
  behavior task's sensor bus reads whole; the thermal zones read their
  temperature from instances (`sfctemp`, the K1's channels, the Pi's firmware,
  the x86 package sensor). A reading that is not there is not published (the
  battery and rangefinder no longer answer an invented value), the GPS record is
  14 bytes, and the rates and digital-line pins are Kconfig
  ([Documentation/drivers.md](Documentation/drivers.md)).
- The io_ring carries IDL calls: one entry kind, `OP_CALL`, names a
  kernel-hosted endpoint and a message window in the ring's data buffer, and is
  decided with the checks of `SYS_IPC_CALL` (the owner's profile, the handle in
  the owner's table, the capability's op mask, the op's class) through the
  interface's own dispatch. The seven device opcodes are deleted; `brain_client`
  reads its sensors with one submit and sends its ring motor command as one
  `speed` entry per wheel ([Documentation/ipc.md](Documentation/ipc.md)).
- Updates and advisories on the device: `pkg outdated` asks the configured
  package source for its signed index (`INDEX.AZX`, verified like a package) and
  prints, per staged package, the installed and the available version and whether
  it is behind or below a security floor; `pkg upgrade [NAME | --all]` installs
  the newer build the index pins through the normal signed path, never a
  downgrade and never below the floor. With Kconfig `PKG_SEC_FLOOR_ENFORCE`
  (default on outside development builds) the kernel refuses to launch a program
  of a package installed below its floor, with a `Rule::ExecGrant` record. The
  `Packages` interface is at level 2
  ([Documentation/services.md](Documentation/services.md)).
- The compositor (Kconfig `COMPOSITOR`, `COMPSRV.ELF`, the `Compositor`
  interface): the sole holder of the kernel's `Display` interface. Clients attach
  windows (a memory object with a damage ring in its first page; the attach lends
  a call right bound to the window); it composes them with the pixel engine into
  one surface of contiguous bands and presents only the damage. It is the
  trusted surface of the Secure Attention Key: the input server now refuses
  `take_focus` to every caller but the compositor, whose row holds a call right
  on `endpoint.input` with a kernel-stamped badge, until the compositor has drawn
  the trusted-path banner (and the "why was this refused" panel, read from the
  decision server) and taken the focus itself. This closes the accepted limit of
  the input server. The toolbox's `window` is a client.
  ([Documentation/services.md](Documentation/services.md))
- virtio-sound (Kconfig `DRV_VIRTIO_SND`): the virtio 1.2 sound device on
  virtio-mmio and PCI (jack, PCM and channel-map queries, SET_PARAMS, prepare,
  start, stop, release; transmit and receive queues over a pinned arena;
  completions by interrupt), served by the kernel's `Sound` interface on
  `sound.0`. A client opens a stream on two period queues and an arena, posts
  periods and drains; a capture stream also needs the `mic` effect. The toolbox's
  `beep [MS]` plays a tone through it. `SYS_MO_CREATE` accepts the kind
  `SHM_KIND_CONTIG` from ring 3. ([Documentation/drivers.md](Documentation/drivers.md))
- Console login (Kconfig `CONSOLE_LOGIN`, default n): the terminal server's secure-attention
  key (Ctrl+Alt+Del, or `^]` on a serial line) ends the session and runs a login prompt that
  no other program can read; the credential is checked by the kernel's new `login` op of
  `keys` against the user's `[login.NAME]` row (a verifier made from the board's root, not a
  password hash); success arms a one-shot grant that the login service (`LOGIND.ELF`) spends
  with `SPAWN_F_USER` to start the shell in a Domain subtree owned by the user
  (`owner_root`, inherited down the subtree).
  Every attempt is a `login` decision record, durable whatever the verdict. With nobody enrolled the
  console is unchanged and recorded. The `login_enroll` host tool (`tests/host/logind-tests`, built from the kernel's own derivation) computes a verifier.
- SpacemiT K1 GPIO and PWM: the `k1` build no longer refuses to compile for
  them. `spacemit,k1-gpio` (four banks of 32 pins, a level write is one store
  to a set or clear register) and `spacemit,k1-pwm` (one controller per channel,
  the channel being the hardware PWM number) bind from the device tree. The
  K1's PDMA is not driven (nothing takes a DMA channel). A K1 development
  type-check takes `k1.config` plus `CONFIG_BUILD_TYPE_DEV=y`
  ([Documentation/drivers.md](Documentation/drivers.md)).
- The input server (Kconfig `INPUTD`, `INPUTD.ELF`, the `Input` interface): the
  input drivers' events are delivered only to the task that holds the focus.
  Focus is a warrant: `take_focus` lends a capability on the server's endpoint
  (call right only, badge only the server names) and a ring of the holder's own
  events; the next grant revokes the warrant and closes the ring. Ctrl+Alt+Delete
  is never delivered: it takes the focus away and is counted on a read-only
  trusted-path page. The terminal server keeps the console. `input watch`,
  `input status` and `input sak` (toolbox) are its first clients.
- Whole-system update over the network: `pkg fetch-update`
  (`Packages::fetch_update`) has the installer get an AZUM bundle from the
  source `/fat/PKG/SOURCE.CFG` names (HTTPS, or TFTP in a development build)
  and stage it into the inactive slot as `pkg update FILE` does. The signed
  manifest and the part hashes decide, never the connection.
- FAT32 files in subdirectories: create, write, unlink, truncate and rename
  work below the root (a FAT32 key is the canonical path; a file renames across
  directories in one journal record). `/fat/PKG/SYS_B/KERN.BIN`, the installer's
  journal and the shell's `echo > /fat/D1/A.TXT` used to fail. The installer no
  longer takes `.` and `..` of a listing for entries, and `pkg` can hold a file
  up to `PKG_MAX_KB` (its frame budget refused anything past ~30 KiB).
- Development package source: in a development build (Kconfig `PKG_FETCH_TFTP`,
  `BUILD_TYPE_DEV` only) `pkg fetch` can read a signed package from the
  development host's TFTP server instead of a pinned HTTPS one
  ([Documentation/services.md](Documentation/services.md)). The installer
  verifies it exactly as a package on the disk. The kernel's own boot-time
  TFTP smoke is gone: the client now runs in `pkgd`, in ring 3.
- Kernel image randomization on aarch64, riscv64 and x86_64 (Kconfig `KASLR`
  n/probe/require; [Documentation/security.md](Documentation/security.md)),
  with allocator hardening (`SLAB_HARDENED`, `ALLOC_RANDOM`), set-once hooks in
  `.data.ro_after_init` sealed read-only after boot, a holder-table reference
  count for memory objects, nospec on io_ring ids, and stricter ARP, IGMP,
  DHCP, DNS, NTP and Neighbour Discovery parsers.
- aarch64: the EL2 trampoline writes `HCRX_EL2` whole on every core with
  FEAT_HCX (0, plus `TCR2En` on a core with FEAT_TCR2, but under the
  hypervisor stub), not only in `A64_POE` builds, so `GCSEn` is 0 and no guarded control stack is on at EL1
  or EL0. `A64_GCS` now defaults to `n`; it is still probed and reported only,
  because a kernel GCS needs the kernel's mappings on FEAT_S1PIE first
  ([Documentation/security.md](Documentation/security.md), "Control-flow
  integrity").
- aarch64 stage-1 indirect permissions (Kconfig `A64_S1PIE` n/probe/require,
  default `n`, not with `HV` or `HYP_MONITOR`): a writable leaf also carries
  DBM, so its UXN/PXN/DBM/AP[1] index alone says what it grants; `PIR_EL1` and
  `PIRE0_EL1` give the eight indices the page-table code produces their direct
  meaning (overlays applied) and nothing to the rest but the kernel GCS page
  (`vmm::map_gcs`, `Mmu::pte_make_gcs_leaf`), the step a kernel guarded control
  stack waits for. `TCR2_EL1` is one composed value (POE and PIE) on every CPU
  path, and the EL2 trampoline grants it and both registers
  ([Documentation/security.md](Documentation/security.md), "Control-flow
  integrity").
- aarch64: `TCR2_EL1` is zeroed before the MMU comes up on every entry path
  (the boot CPU, each secondary and each resumed PE) wherever FEAT_TCR2 is
  implemented, in every build but the split monitor's and the hypervisor
  stub's, as Linux's `__cpu_setup` does: its UNKNOWN reset PIE or POE bits no
  longer apply to the boot identity map, which closes that exposure for
  `A64_POE` too when the kernel enters at EL1.
- Initial import of the tree.
  - **Kernel:** `kernel/` (boot sequence, trap entry and boot hooks for
    riscv64, aarch64 and x86_64, kernel tasks, panic handler) over the core
    crates in `crates/core/`: the ABI (`abi`), the architecture API and one
    implementation per ISA (`arch-api`, `arch-riscv64`, `arch-aarch64`,
    `arch-x86_64`), the scheduler (`sched`), memory management (`mm`), IPC and
    capabilities (`ipc`), the system-call layer (`syscall`), the capability
    topology (`topology`), signed packages (`pkg`), the interface definition
    language (`idl`, `idl-macros`, `devif`), the introspection tree
    (`inspect`), the actuation authority (`actuation`), decision records
    (`decision`), the tracer (`trace`), the in-kernel test registry (`ktest`),
    OTA and secure boot (`ota`, `crypto`) and the hypervisor core (`hv`).
  - **Drivers, storage and network:** one crate per driver class under
    `crates/drivers/`; `crates/fs` (VFS, FAT32, tmpfs, azvol, page cache,
    crash log); `crates/net/` (the TCP/IP stack, an encrypted link, a stream
    multiplexer, a TFTP client).
  - **User space:** ring-3 services, drivers, libraries and test programs under
    `userspace/`; the native `std` SDK (`sdk/`); the relibc port
    (`userspace/lib/relibc-azos`); the optional Linux personality
    (`crates/core/linux-abi`, `crates/core/syscall/src/linux.rs`,
    `userspace/lib/linux_rt`); Linux driver glue (`crates/drivers/lx/`).
  - **Other kernels and domains:** AzOS-micro for parts without an MMU
    (`micro/`); the robot domain (`crates/domains/robot/`).
  - **Build and tests:** the Kconfig tree, presets and defconfigs (`Kconfig`,
    `config/`), the Makefile split under `mk/`, build, check and signing tools
    (`tools/`), host test crates (`tests/host/`), fuzz targets (`tests/fuzz/`)
    and TLA+ models (`formal/`).
