# `azos_abi` — Changelog

All notable changes to the AZOS ABI crate. **The ABI is not stable and no
compatibility is promised**: it has no users outside this tree, so anything
here may change. This file records the changes. Earlier revisions described a
frozen `v1.x` ABI; that was never true. The versioning rules below are the
SemVer convention the crate was written to, not a commitment:

- **PATCH**: documentation, additional `#[doc]` comments, internal
  refactoring that doesn't change any `pub` item.
- **MINOR**: new `pub` items (e.g., a new syscall number at the next
  unused slot, a new `CapKind` variant, a new errno).
- **MAJOR**: removing or changing the wire format of any existing
  `pub` item. Requires an RFC supersede.

## [Unreleased]

Phase 9 step 1 (transparent RPC).

- **Added** `Errno::ERTPROXY` (217): `SYS_IPC_CALL_V2` refuses, before queueing,
  a call from a real-time task (class safety-critical, hard or soft real-time)
  to a proxy endpoint, one the topology names `endpoint.rpc-<service>`; the
  call would wait on a link. The topology refuses the same pairing at
  admission (`neverallow` rule `proxy-endpoint-not-realtime`).
- **Removed** `Errno::ENOCONNECTION` (214), which was reserved for a remote
  endpoint: a remote call's lost link is `azos_idl::IdlError::NoConnection`, a
  status of the reply, because a kernel completion code could not say which of
  a dead server and a dead link it was.
- **Removed** `cap::reserved_kind::PROXY` (12): a proxy for a remote service is
  an `Endpoint` the topology names `rpc-...`, not a kind.

D6 part B, the native table: thirty-four calls in families, and `invoke` for everything else.

- **Changed** `ty::MMIO` and `DOMAIN_MMIO_MAP`: the capability's resource and the
  op's `w0` are the handle of a hardware-bus device (its slot index), not
  an index into a board table. The op maps the device's register window,
  writable only if the capability carries WRITE (it was a per-region flag of
  the table); a handle that names no live device, a device a kernel driver
  owns or may still take, a device whose probe failed and a device with no
  window are `EINVAL`; the `SAFETY_CAP_DENIED` record
  of a refusal carries the handle (it carried the region's base). The
  topology grants it as `mmio.<selector>`.
- **Removed** `drv_kind::DRV_KIND_BUZZER` and `drv_kind::buzzer_op`: the buzzer
  is the `Buzzer` interface (`azos_devif::buzzer`) served from an endpoint, not
  a driver-server kind with a request protocol.
- **Changed** the syscall table is 34 calls, dense from 1 (`SYS_NR_RESERVED_UPPER`
  35), in families: handles (`SYS_CAP_INFO` 1, `SYS_CAP_CLOSE`, `SYS_CAP_DERIVE`,
  `SYS_CAP_REVOKE`), domain (`SYS_SPAWN_EX`, `SYS_THREAD_CREATE`,
  `SYS_THREAD_EXIT`, `SYS_EXIT`, `SYS_ALERT`, `SYS_GETPID`), time and scheduling
  (`SYS_YIELD`, `SYS_SLEEP_UNTIL`, `SYS_SCHEDCTL`), memory (`SYS_MO_CREATE`,
  `SYS_MO_MAP`, `SYS_MO_UNMAP`), IPC (the four fast calls, the four v2 calls,
  `SYS_RING_SETUP`, `SYS_RING_ENTER`, `SYS_PORT_WAIT`), futex, foreign ABI
  (`SYS_FOREIGN_ENTRY` 30, `SYS_FOREIGN_RESUME` 31), `SYS_INVOKE` 32,
  `SYS_SERVICE_DISCOVER` 33 and `SYS_FOREIGN_FORK` 34, added at the end. Every number moved; the fast
  call (`SYS_IPC_FAST_CALL_EP`) stays two above `SYS_IPC_FAST_REPLY_ACCEPT`,
  which the lean trap entries test. `syscall_nr.rs` is rewritten around the
  table.
- **Added** `DEVICE_IRQ_BIND` and `DEVICE_IRQ_ACK`, the ops of an interrupt line's
  `Device` capability (`ty::IRQ`): the line is bound to an event port by the
  line's own handle (`w0` port handle, `w1` key, `w2` the CPU, or
  `DEVICE_IRQ_CPU_ANY`), every interrupt queues a `PORT_EVENT_IRQ` on the port,
  and the ACK unmasks the line (1 when the handler's budget is spent and the line
  stays masked until the reservation is replenished). **Removed**
  `DOMAIN_IRQ_BIND`, `DOMAIN_IRQ_WAIT`, `DOMAIN_IRQ_ACK` and the port source
  `PORT_SRC_IRQ`: a line has one way to be bound, and it reports through a port
  (the wake-task binding with its pending bit is gone). `PORT_SRC_TIMER` is 2
  and `PORT_SRC_ENDPOINT` 3 now.
- **Added** `SYS_INVOKE` and the `invoke` module: `invoke(handle, op, words)` on
  an object the caller holds a handle to. The op is `kind << 12 | class << 8 |
  index`; the kernel refuses an op of another kind than the handle's. Register
  form (`INVOKE_REGS`): four words in `a2..a5`, replies in `a1..a4`;
  descriptor form: `a2` points at a `MsgDesc`. `DOMAIN_SELF` is the caller's own
  domain, a handle no table stores. The console is a `Log` capability
  (`ty::CONSOLE`) seeded into every task. Op classes: `READ`, `WRITE`, `WAIT`,
  `CTL`, `ADMIN` for every kind and, for the domain, `FS_OPEN`, `FS_MUTATE`,
  `MODULE`, `NET`, `DRIVER`.
- **Added** `SYS_CAP_INFO` (lookup, directory tree, query), `SYS_CAP_DERIVE`
  (badge, rights, expiry; `SYS_CAP_MINT_BADGED` and `SYS_CAP_DUP` folded in),
  `SYS_CAP_REVOKE` (the subtree below a handle, the handle kept) and
  `SYS_CAP_CLOSE` (one close for any handle).
- **Added** `ABI_VERSION` 2 with consumers: the `.note.azos.abi` ELF note
  `libsys` embeds (`ABI_NOTE_TYPE`, name `AZOS`) which the loader checks, the
  vDSO word at `vdso::VDSO_ABI_VERSION_OFFSET` (84), and `libsys::abi_matches`.
- **Added** `SLEEP_RELATIVE` (flag of `SYS_SLEEP_UNTIL`): `a0` is a duration, not
  a deadline.
- **Removed** the calls that are ops now: the file and namespace calls
  (`SYS_OPEN`..`SYS_STATFS`, `SYS_FILE_*_TYPED`, `SYS_FSYNC_TYPED`,
  `SYS_CLOSE`, `SYS_CLOSE_TYPED`, `SYS_MOUNT`, `SYS_SYNC`, `SYS_CHDIR`,
  `SYS_GETCWD` (the last four unimplemented or untrue)), the network calls
  (`SYS_SOCKET*`, `SYS_BIND`, `SYS_CONNECT`, `SYS_SEND*`, `SYS_RECV*`,
  `SYS_MCAST_*`, `SYS_LISTEN`, `SYS_ACCEPT`, `SYS_NET_*`), the info calls
  (`SYS_UPTIME`, `SYS_MEMINFO`, `SYS_TASKINFO`), `SYS_WAIT`, `SYS_WAIT_STATUS`,
  `SYS_WAITPID`, `SYS_BRK`, `SYS_VDSO_TASK_MAP`, `SYS_MODULE_VERIFY`,
  `SYS_MODULE_MAP_X`, the interrupt and driver-registration calls
  (`SYS_DRV_IRQ_WAIT`, `SYS_DRV_IRQ_ACK`, `SYS_IRQ_BIND`,
  `SYS_DRIVER_REGISTER_TYPED`, `SYS_DRIVER_UNREGISTER_TYPED`), the driver loop
  (`SYS_DRIVER_FETCH_REQ`, `SYS_DRIVER_REPLY`, `SYS_DRIVER_REPLY_FETCH`,
  `SYS_DRIVER_REPLY_WAIT`), `SYS_MMIO_MAP`, the notify words
  (`SYS_NOTIFY_WAIT`, `SYS_NOTIFY_WAKE`, `SYS_NOTIFY_ROBUST`), the port ops
  (`SYS_PORT_CREATE_TYPED`..`SYS_PORT_DESTROY_TYPED`), the lease calls,
  `SYS_ENDPOINT_CREATE_TYPED`, `SYS_PIPE_TYPED`, `SYS_EXIT_STATS`,
  `SYS_SERVICE_REGISTER`, `SYS_SERVICE_HEARTBEAT`, `SYS_TASK_SUBREAPER`,
  `SYS_SECCOMP`, `SYS_TRACE_CTL_TYPED`, the console calls
  (`SYS_PUTCHAR`, `SYS_GETCHAR`, `SYS_WRITE`, `SYS_CONSOLE_WAIT`),
  `SYS_TEST`, `SYS_ALLOC_DEMAND`, `SYS_DRIVER_POLL_EVENT`, `SYS_DRIVER_STATS`
  and `SYS_SLEEP`. Each is an op in `invoke` (the file `invoke.rs` names them)
  or folded into one of the calls above.
- **Removed** the native process calls with no op to replace them: `SYS_FORK`,
  `SYS_FORK_COW`, `SYS_EXEC`, `SYS_EXECPATH` and the path-named `SYS_SPAWN`
  (they were ops of the domain for a time, in classes `PROCESS` and `SPAWN`,
  and those classes and the four ops are gone). `SYS_SPAWN_EX` is the only
  native process creation call, and needs a launch capability for the image.
  The Linux personality's `execve` is the kernel's own, and its `fork` (and
  the ring-3 runtime's) is `SYS_FOREIGN_FORK`.
- **Added** `SYS_FOREIGN_FORK`, the foreign-ABI family's process copy: a
  copy-on-write copy of the caller, refused with `-EPERM` unless the caller
  registered a foreign entry (`SYS_FOREIGN_ENTRY`), which is the authority; an
  image's profile must list it, so a native program has no fork unless its row
  says so (two test images list it for peers that are copies of them). The
  child holds the caller's descriptors and pipe ends at the same handles and
  the capabilities of its own topology row. The domain op numbers after the
  removed ops moved down by four (`DOMAIN_NOTIFY_WAIT` is 41).
- **Removed** the v1 message channel: `SYS_CHAN_CREATE_TYPED`,
  `SYS_CHAN_WRITE_TYPED`, `SYS_CHAN_READ_TYPED`, `ty::CHANNEL`,
  `PORT_SRC_CHANNEL`, `PORT_EVENT_CHANNEL`, `OP_CHAN_SEND`, `OP_CHAN_RECV` (ring
  opcodes 14 and 15 are unassigned) and Kconfig `MAX_CHANNELS`. Port source
  type 0 is now no source. `ty::IORING` is `Queue` class 0.
- **Renamed** `SYS_SHM_CREATE_TYPED` to `SYS_MO_CREATE`, `SYS_SHM_MAP_TYPED` to
  `SYS_MO_MAP` (anonymous memory when `a0` is 0, which `SYS_MMAP` was),
  `SYS_SHM_RELEASE_TYPED` to `SYS_MO_UNMAP` (anonymous memory when `a0` is 0,
  which `SYS_MUNMAP` was), `SYS_IORING_CREATE_TYPED` to `SYS_RING_SETUP`,
  `SYS_IORING_SUBMIT_TYPED` to `SYS_RING_ENTER` and `SYS_TASK_KILL` to
  `SYS_ALERT`.


D6 part A, kernel-hosted endpoints: a device or a kernel service is an endpoint op, not a number or a kind.

- **Changed** `CapKind` is eight generic kinds plus `Null`: Endpoint 1, MemObj 2,
  Queue 3, Port 4, Domain 5, Node 6, Device 7, Log 8 (Thread joins in part B;
  Vm, Vcpu and Proxy are reserved numbers). What a kind holds is a class, and
  the pair is `CapType` (kind in the low four bits of the handle's six-bit type
  field, class in the high two): `ty::{ENDPOINT, SHM, LEASE, CHANNEL, IORING,
  PORT, TASK, FILE, LAUNCH, SOCKET, PIPE, IRQ, MMIO, DRIVER_REGISTRY, TRACE}`.
  `CapHandle::pack` and `slot_word::{encode, ty, ty_is}` take a `CapType`;
  `SYS_CAP_LOOKUP` takes the type raw (a `CapType::raw()` value, so a lease is
  18, not 25); a denial is recorded under `CapKind::denial_code`, which is the
  discriminant (every Device denial is 7, the detail word carries the
  resource). The topology words are `endpoint`, `memobj`, `queue`, `port`,
  `domain`, `node`, `device`, `log`; the class is read from the target text.
  A `Node` handle stays below the sign bit on rv32 (the micro kernel).

- **Added** endpoints owned by the kernel (`azos_ipc::endpoint::kernel_host`):
  `SYS_IPC_CALL_V2` and the register form of `SYS_IPC_FAST_CALL_EP` serve them
  in place (`crates/core/syscall/src/khost.rs`). Rights on such a capability
  are op classes (`READ` observe, `WRITE` act, `EXEC` control) and any one of
  them may call it; the badge is the resource. `SYS_CAP_LOOKUP(Endpoint, key
  << 32 | badge)` finds a task's capability to one (libsys
  `cap_lookup_host`). The interfaces are in `crates/core/devif`
  (`azos_devif`), outcomes in `azos_devif::outcome`.
- **Removed** `SYS_ENTROPY_READ_TYPED` (596), `ENTROPY_READ_MAX` and
  `CapKind::Entropy` (tag 24): the pool is the `entropy` interface (`draw`,
  at most six words per call), granted by `endpoint = "entropy"`.

- **Removed** `SYS_LINK_KEY_READ_TYPED` (591), `LINK_KEY_READ_BYTES`,
  `SYS_SHUTDOWN` (270), `SYS_REBOOT` (271), `SYS_POWER_TYPED` (614),
  `SYS_FLIGHT_TYPED` (615), `SYS_BEHAVIOR_TYPED` (616), `SYS_CONFIG_TYPED`
  (617), `SYS_OTA_TYPED` (618), `POWER_OP_SUSPEND`..`POWER_OP_SCHED_HZ_SET`, and
  `CapKind::{Power, LinkKey}` (tags 18 and 23). They are the interfaces
  `linkkey`, `power`, `flight`, `behavior`, `config` and `ota` of
  `azos_devif`, granted by `endpoint = "<iface>"` rows. Configuration keys and
  values cross as NUL-padded words (24 and 32 bytes).
- **Changed** `SyscallFilter` carries an `ifaces` word (the kernel-hosted
  interfaces the image may call; `ImageProfile::ifaces`): 348 bytes at the
  default list length.

- **Removed** `SYS_GPIO_READ_TYPED`..`SYS_PWM_SET_DUTY_PCT_TYPED` (539-549),
  `I2C_TYPED_MAX_BYTES`, `SYS_DRV_INVOKE` (311) with
  `DRIVER_INVOKE_MAX_INPUT_BYTES`/`_OUTPUT_BYTES`, and `CapKind::{Gpio, I2c,
  Pwm}` (tags 8, 9, 10). They are the interfaces `gpio`, `i2c` and `pwm` of
  `azos_devif`, granted by `endpoint = "gpio.<pin>"`, `"i2c.<bus>.<addr>"` and
  `"pwm.<channel>"` rows; the register form serves `gpio` and `pwm`, an I2C
  transfer carries at most 32 bytes (`azos_devif::i2c::MAX_BYTES`) and the
  io_ring op keeps its 256-byte window. `SYS_DRV_INVOKE` had no ring-3 caller:
  the driver registry stays a kernel-internal table.
- **Removed** `SYS_SENSOR_READ_TYPED` (561), `SYS_SENSOR_READ_TS` (606),
  `SYS_VDSO_SENSOR_BIND` (595), `CapKind::Sensor` (tag 7, recorder code 1),
  `SensorSampleHdr` with its layout constants, and libsys `sensor_read_typed`,
  `sensor_read_ts` and `vdso_sensor_bind`. They are the `sensor` interface of
  `azos_devif` (`read` returns a `Sample`: the record, at most 24 bytes, with
  its flags and its acquisition stamp on the vDSO clock; `bind_vdso`), granted
  by `endpoint = "sensor.<type>"` rows (READ only). The topology words
  `sensor` and `encoder` are gone. The LiDAR scan and the camera frame do not
  fit a reply: they answer `UNSUPPORTED` and keep the stream rings and the
  io_ring's `READ_SENSOR` op (gated by the `sensor` interface). A camera frame
  has no ring-3 path without `STREAM_CAMERA_RING`.
- **Removed** `CapKind::{AiSession, NetConfig, TimeWarrant}` (tags 15, 20, 29),
  `SYS_NET_SETIP` (262) with libsys `net_setip`, and the topology words
  `ai-session`, `service-call` and `time`. `AiSession` and `NetConfig` had no
  consumer (nothing ring 3 held could be checked against them; the kernel sets
  the address directly), and a ring-3 readdress call returns with the Net
  endpoint of part B. The time warrant of `SYS_SCHEDCTL` is a `time` endpoint
  (`endpoint = "time"`, `WRITE`; it serves no op, the kernel reads the capability).
- **Removed** the RFC-0002 bridge calls `SYS_DRV_REGISTER` (300),
  `SYS_DRV_UNREGISTER` (301, a stub) and `SYS_DRV_GET_DEVICE` (310) with libsys
  `drv_register`: nothing registered a driver by name any more (the typed
  registration is the path) and nothing read the name back. The AQ2 table
  stays for `SYS_DRV_HEARTBEAT`.
- **Removed** `SYS_DISK_INFO` (280), `SYS_DISK_READ` (281), `SYS_DISK_WRITE`
  (282), `SYS_DISK_SIZE` (283), `DISK_SEL_ONLY`, the libsys `disk_*` wrappers,
  `CapKind::Disk` (tag 19, recorder code 11), `disk_cap.rs` and the topology
  word `disk`. Partition-scoped raw access is the `block` interface of
  `azos_devif`, granted by `endpoint = "block.part.<n>"` (badge `n + 1`; the
  whole-medium resource 0 has no spelling). Decisions taken for the data path
  (D1, owner may reverse): (1) a sector is 512 bytes and a reply 64, so the
  data moves through the io_ring (`OP_BLOCK_READ` 20, `OP_BLOCK_WRITE` 21;
  gated by the `block` interface, `READ` / `WRITE`, writes refused while
  contained) and not through a lent `MemObj`, which a kernel-hosted endpoint
  cannot take yet; (2) an entry names whole sectors inside the 2 KiB data
  window (four at most) and a first sector below 2^32 in its `addr` and `reg`
  fields, partition-relative as before; (3) the partition-scope refusal is
  recorded under the endpoint kind with the badge and the write bit (the
  console line reads `[BLOCK] scope:`); (4) the sentinel selector and the
  "ambiguous with two partitions" refusal are gone: each entry names its
  partition by the badge. `SYS_MOUNT` is refused to every ring-3 caller (the
  whole-disk capability it asked for was never minted).
- **Removed** the typed motor calls `SYS_MOTOR_SPEED_TYPED`..`SYS_MOTOR_RESET_TYPED`
  (550-555, 560, 576, 578, 584), `SYS_ROBOT_ESTOP` (325), `MOTOR_TICK_OUT_BYTES`,
  the libsys wrappers with `MOTOR_DIR_*` and `PROFILE_MOTOR`, `CapKind::Motor`,
  the `targets::Motor` marker and the SENSOR and MOTOR seccomp role profiles
  (the role ids are now `UNRESTRICTED` 0, `NET` 1, `MINIMAL` 2). The drivetrain
  is the `motor` interface of `azos_devif` (`speed`, `drive`, `direction`,
  `angle`, the PID ops and `estop`), granted by `endpoint = "motor.<wheel>"`
  rows (feature `profile-actuation`). The halt rule stays in the motor layer.
- **Removed** the untyped device calls with no ring-3 user or no minter:
  `SYS_GPIO_INFO` (203), `SYS_PWM_INFO` (214), `SYS_I2C_SCAN` (222),
  `SYS_I2C_INFO` (223), `SYS_MOTOR_CREATE` (230), `SYS_MOTOR_INFO` (234),
  `SYS_SENSOR_INFO` (330), `SYS_SENSOR_ADD` (331), `SYS_ADC_READ` (410),
  `SYS_BUZZER_TONE` (420), `SYS_BUZZER_OFF` (421), and `CapKind::{Adc, Buzzer}`
  (tags 16 and 17). Every ring-3 call of them was refused (no table held the
  kind) or a printer for the kernel console.

D6 part A, transfer expiry: a capability can be lent for a time.

- **Changed** `CapDesc` (the v2 message descriptor's capability entry) is 16
  bytes: it gains `expiry_ns` (absolute nanoseconds on the MONO clock, the unit
  of `Warrant::expiry_ns`; 0 = the sender's own). `MsgDesc` is 224 bytes
  (`caps` at 80, `deadline` at 208, `clock_id` at 216). The kernel derives the
  receiver's copy with the earlier of the entry's and the sender's own deadline
  (a DUP entry is a new warrant link, a MOVE entry narrows the moved slot's);
  a non-zero value at or before the clock is refused with `-EDEADLINE` and one
  decision record before anything moves. The receiver reads 0. `azos_idl`:
  `Lent::dup_until`; `Writer::cap_dup` takes the deadline.

Energy policy: user space sets the energy seams, the kernel keeps the limits (no new number or kind).

- **Added** `SYS_POWER_TYPED` (614) operations 6..=12 (`POWER_OP_POLICY_*`) under
  the same `Cap<Power>` (`WRITE` to set, `READ` to read): governor, OPP range per
  domain, schedutil headroom, rate limit, idle-depth limit, and two readers (state
  and statistics words). A setter returns `0` (applied), a positive
  `POLICY_REFUSED_*` code (a kernel limit refused it and recorded it: the WCET
  floor, the admitted real-time floor, the hard ranges), or a negative errno;
  without the kernel feature `energy` they answer `-ENOSYS`.
- **Added** `SYS_SCHEDCTL` (638) hint form `SCHEDCTL_HINT_QOS` (`a1` = 4, `a2` =
  level 0..=3): the caller's QoS hint, no warrant, recorded in the scheduling
  context's `qos_id`. The timer heap reads it (QoS timer tolerance, Kconfig
  `QOS_TIMER_TOLERANCE`): a fair task's timers get its tier's slack, a
  real-time or deadline task's never do. The levels are `QOS_DEFAULT`,
  `QOS_LATENCY`, `QOS_THROUGHPUT`, `QOS_BACKGROUND` (new `pub` constants).

D6 foreign ABI: trap reflect and resume for a ring-3 runtime (the ABI cut allows these two numbers).

- **Added** `SYS_FOREIGN_ENTRY` (640) and `SYS_FOREIGN_RESUME` (641), the
  "foreign ABI" family (`azos_abi::foreign`); `SYS_NR_RESERVED_UPPER` is 642.
  A thread that registered an entry has its next trap reflected: a
  `ForeignFrame` (every register, 272 bytes on every ISA) is pushed on its
  stack and it returns to the entry; `SYS_FOREIGN_RESUME(frame)` restores it.
  libsys `foreign_entry`, `foreign_resume`.
- **Changed** the per-image syscall bitmap covers 672 numbers (it was 640);
  `SyscallFilter` is 344 bytes at the default list length.

D4/L6 MemObj: one memory object (D0: no new number or kind).

- **Changed** `SYS_SHM_CREATE_TYPED` (533): `a1` is a creation word with fields
  (access mode `1:0`, kind `15:8`, attributes `23:16`, `SHM_CREATE_CLONE` bit 24,
  source capability `63:32`); `0` and `1` keep their meaning. Ring 3 creates Anon
  objects; `SHM_ATTR_VOLATILE` is reserved (`-EINVAL`). A clone is a copy-on-write
  snapshot of the capability named in `63:32`.
- **Changed** `SYS_SHM_MAP_TYPED` (574): the mapping is bounded by the
  capability's rights. A `READ` capability of a writable object maps it
  read-only (it was `-ECAPPERMS`).
- **Changed** `SYS_SHM_MAP_TYPED` (574) `a1`: `0` maps; `SHM_MAP_OP_PROTECT`
  (with `SHM_MAP_PROT_WRITE`) changes the access of the caller's mapping of the
  object the capability names, never past what the map allowed (`-ECAPPERMS`),
  nor while a lease's seal holds it or a clone shares its frames (`-EBUSY`).
  libsys passes `a1 = 0` explicitly for a map. No `SYS_MPROTECT` change.
- **Added** `FAST_CALL_CAP_SHARE` (bit 32 of `SYS_IPC_FAST_CALL_EP`'s `a5`): the
  capability is shared (a derived copy, the sender keeps its handle and, for a
  `Cap<Shm>`, its mapping) instead of moved. libsys `fast_ipc_call_ep_sharing`.
- **Changed** the IPC transfer's MOVE entry for a `Cap<Shm>`: the references, the
  ownership and the memory charge go to the receiver and the sender's mapping is
  removed. A DUP entry stays a SHARE.
- **Changed** `SYS_ALLOC_DEMAND` (404): the private Anon MemObj; same contract.

P0 clock (wave 15): clock ids and the message deadline.

- **Added** `time::ClockId` (a `u32`: kind in the high byte, index in the low
  24 bits; `MONO` = 0; `REAL`, `TSC_RAW`, `ptp(n)`, `tsn_domain(n)`, `vcpu(n)`
  reserved) and libsys `clock_now(ClockId)` (MONO from the vDSO, the rest
  `Unsupported`).
- **Changed** `MsgDesc`: `deadline: u64` and `clock_id: u32` (+ `_pad`) are a
  tail after `caps`; the struct is 160 bytes and the kernel always copies all
  of it (deadline 0 = none). `MSG_VERSION` stays 1.
- **Added** `Errno::EDEADLINE` (216): `SYS_IPC_CALL_V2` refuses a call whose
  deadline has already passed, before it is queued. A clock other than MONO is
  `-EINVAL`. The server reads the caller's deadline and clock in the
  descriptor it accepts.

N5 (wave 15): the endpoint object.

- **Removed** `SYS_IPC_FAST_CALL` (108), the fast call addressed by a raw
  TID; it joins `RETIRED_SYSCALLS`. `SYS_IPC_FAST_CALL_EP` (582) is the only
  fast call.
- **Added** `Errno::EPEERDIED` (211) and `Errno::EREVOKED` (212): a fast call
  completed without an answer because the endpoint's serving task died, or
  the endpoint was destroyed, while the call was queued or in service (582
  returns `-211` / `-212` instead of `-1`). `Errno::ENOSENDERS` (213) and
  `Errno::ENOCONNECTION` (214) are reserved.
- **Added** `Errno::EV1ACCEPT` (215), N11c: `SYS_IPC_CALL_V2` returns it when
  its server takes the call with the v1 accept; the server sees nothing and
  every capability the call carried goes back to the caller.
- **Changed** the fast-call handle layout (opaque to ring 3): with Kconfig
  `IPC_ENDPOINT_QUEUES` the low bits name the CALLER's call record, not a
  slot of a 64-entry table.

TRACE (wave 15).

- **Added** `SYS_TRACE_CTL_TYPED` (632): `a0` = `Cap<Trace>`, `a1` = op
  (`azos_abi::trace::TRACE_OP_*`: `INFO`, `MAP`, `GET_MASK`, `SET_MASK`,
  `REGION_BYTES`), `a2` = the new class mask for `SET_MASK`. The kernel
  tracer's control: maps the per-CPU trace rings (layout in
  `azos_spsc::trace`) and reads or sets the runtime class mask. A member of
  `CAP_TYPED_SYSCALLS`.
- **Added** `CapKind::Trace` (28, denial code 28): granted only by a topology
  row (the word `"trace"`, resource 0).
- **Added** `azos_abi::trace`: the operations, the class bits
  (`TRACE_CLASS_*`) and the event ids (`TRACE_EV_*`, `(class << 8) | n`).
- **Changed** `SYS_NR_RESERVED_UPPER` 632 → 633.

LINUXP.

- **Changed** a native `SYS_FORK` child inherits its parent's files and pipe
  ends as duplicates sharing the open description, at the parent's exact
  handles, and holds its own topology row's capabilities (minted for it, never
  copied from the parent); every other parent handle is stale in it.
- **Changed** `SYS_MMAP` honours `prot` (security): `PROT_READ` maps
  read-only pages (a store faults, 128+SIGSEGV), `PROT_READ | PROT_WRITE`
  read-write ones, `0` reserves the range and maps nothing, `PROT_EXEC` is
  refused. It used to map read-write whatever `prot` said; callers that
  passed `0` for a read-write mapping now pass 3. The Linux personality
  answers `mprotect` (read and write exactly, never execute).
- **Added** threads: `SYS_THREAD_CREATE` (620), `SYS_THREAD_EXIT` (621),
  `SYS_FUTEX_WAIT` (622), `SYS_FUTEX_WAKE` (623), and the bounds
  `GROUP_THREADS_MAX` (16) and `GROUPS_MAX` (8). The threads of a process
  share its address space, capability table and descriptor table. `SYS_EXIT`
  from any thread ends the process. Objects other than descriptors and
  capabilities (sockets, ports, endpoints, channels, shared-memory mappings,
  rings, leases) stay booked to the thread that created them and go when it
  exits.

Debts.

- **Added** `SYS_TASK_SUBREAPER` (619), `a0` = `SUBREAPER_GET` (0) /
  `SUBREAPER_SET` (1) / `SUBREAPER_CLEAR` (2): the caller's child-subreaper
  mark, Linux's `PR_SET_CHILD_SUBREAPER`.
- **Changed** a user task's children are re-parented when it exits, as on
  Linux: to the nearest live ancestor marked a child subreaper, else to the
  autorun image's task (init), else to nobody (parent 0). The exit notices of
  its children that exited unreaped move with them, instead of being dropped.
  `waitpid`/`wait_status`, `/proc/tasks` and `getppid` follow the new parent.
  A kernel task's children keep the link they had.

Leftovers.

- **Changed** `/proc/tasks` lists only the reader itself and its descendants,
  and `/proc/<tid>` (new: that one task's line) names nothing for any other
  TID, as Linux `hidepid=2`. The whole list needs `Cap<Task>` `READ` on the
  target `"tasks"` (resource 0), the first meaning `CapKind::Task` has ever
  been minted with; `SH.ELF`, `TOOLBOX.ELF` and the recovery console hold it
  outside `CONSOLE_LOCKDOWN`.
- **Changed** `CAPS.TOML` key `lease_seal` is a format-2 key, as `restart`:
  a file without `format = 2` before its first section that carries it is
  refused (`FieldNeedsFormat`), not read.
- **Changed** exit notices are kept until the parent reaps them or exits, as
  Linux keeps zombies: none is dropped any more (the 32-entry table evicted
  the oldest). While unreaped notices hold the task slots that are free,
  `SYS_FORK` and `SYS_SPAWN`/`SYS_SPAWN_EX` are refused as when the task table
  is full. Kconfig `SCHED_EXIT_NOTES` is retired (one notice per task slot).
- **Added** `SYS_EXIT_STATS` selectors `EXIT_STAT_NOTICE_DROPS` (5, zero by
  construction) and `EXIT_STAT_NOTICE_REFUSALS` (6).
- **Added** the privileged families' typed calls (RFC-0055 S5), the ring-3
  forms of the console's `flight`, `behavior`, `config` and `ota` commands,
  each the capability in `a0`, checked first and recorded on refusal, each
  listed by its tool's seccomp profile only, and members of
  `CAP_TYPED_SYSCALLS`: `SYS_FLIGHT_TYPED` (615, `Cap<Motor>` WRITE on both
  wheels; `FLIGHT_OP_ARM`/`_DISARM`), `SYS_BEHAVIOR_TYPED` (616, `Cap<Power>`;
  `BEHAVIOR_OP_ENABLE`/`_DISABLE`/`_STATUS`), `SYS_CONFIG_TYPED` (617,
  `Cap<Power>`; `CONFIG_OP_GET`/`_SET`, any key needs WRITE to set),
  `SYS_OTA_TYPED` (618, `Cap<Power>`; `OTA_OP_STATUS`, a packed word, and
  `OTA_OP_ROLLBACK`). Constants in `azos_abi::families`. The scheduler
  rate needs no call of its own: it is `SYS_POWER_TYPED`'s ops 4/5.

LXL0 (RFC-0053 stage L0b): the module loader's two calls.

- **Added** `SYS_MODULE_VERIFY` (630) and `SYS_MODULE_MAP_X` (631), and
  `MODULE_MAX_BYTES` (4 MiB). Assigned only in a kernel built with the
  `lx-loader` feature; `-ENOSYS` elsewhere.
- **Changed** `SYS_NR_RESERVED_UPPER` 615 → 632 (615..=618 are the leftovers'
  families above; 619..=629 left free).

LEASE3: LEASE2's multiplexed encodings get numbers of their own.

- **Added** `SYS_NOTIFY_ROBUST` (612): `a0` = word, `a1` = op
  (`NOTIFY_ROBUST_ADD` 1 / `NOTIFY_ROBUST_DEL` 2; anything else `-EINVAL`).
  Same codes as the LEASE2 ops below.
- **Added** `SYS_IPC_LEASE_ACCEPT_MAP` (613): `a0` = lessor TID (`-EINVAL`
  above `u32::MAX`), `a1` = `*mut u64` for the mapping's address. Same
  semantics as LEASE2's flagged accept.
- **Changed** `SYS_NOTIFY_WAIT` (592): `a1[32..]` is `-EINVAL` again; the
  `NOTIFY_OP_ROBUST_*` constants are removed (now `NOTIFY_ROBUST_*`).
- **Changed** `SYS_IPC_LEASE_ACCEPT` (112): `a0` bit 32
  (`LEASE_ACCEPT_RETIRED_MAP_BIT`, formerly `LEASE_ACCEPT_MAP`) is `-EINVAL`;
  other `a0 > u32::MAX` stay -1; `a1` is not read.
- **Changed** `SYS_NR_RESERVED_UPPER` 612 → 614.
- **Added** `LEASE_GRANT_SEAL` (`1 << 32` in `SYS_IPC_LEASE_GRANT_TYPED`'s
  `a1`, whose high half was narrowed away before): the producer-side write
  seal. The caller's own mapping of the region is read-only (TLB shot down)
  until the lease ends, then writable again; a write in between kills the
  caller. A mapping the caller makes during the seal is read-only for good.
  Any other bit in `a1[32..]` is `-EINVAL`. A topology row with
  `lease_seal = true` (new `CAPS.TOML` key) refuses an unsealed grant from
  its task with `-EACCES`.
- **Added** `EXIT_STAT_LEASE_SEAL_FAULTS` (4), a `SYS_EXIT_STATS` selector:
  lessor writes refused by a seal.
- **Changed** lease expiry: an expired lease's lessee mapping (and a sealed
  lessor's write) is revoked by a kernel worker without the lessor's wait or
  free; on aarch64 lease deadlines are enforced at all (the tick never ran
  `lease_tick` before).
- **Changed** `SYS_PORT_BIND_TYPED` (575) channel/io_ring sources: a binding
  is removed when the capability it was made through is revoked (or its
  holder exits) and follows it when it is moved. A capability revoked or
  moved during the bind answers `-ECAPSTALE`.

SHMRING: kernel sensor streams in shared memory.

- **Added** `cap::SHM_STREAM_LIDAR` (`0x5354_0000`) and `cap::SHM_STREAM_CAMERA`
  (`0x5354_0001`):
  `SYS_CAP_LOOKUP(CapKind::Shm, key)` answers the task's `Cap<Shm>` to that
  kernel stream (seeded by a topology row declaring `Shm stream.lidar` /
  `stream.camera`). The region holds a `azos_spsc::SpscBytes` ring whose
  layout (header words, `SlotInfo` slot header, `RING_DROPS`) is now part of
  the ABI: the kernel produces, ring 3 consumes. No new syscall number.

SENSORTS: an acquisition timestamp on every sensor sample.

- **Added** `SYS_SENSOR_READ_TS` (606): `a0` = `Cap<Sensor>` (`READ`), `a1` =
  buffer, `a2` = its length. Writes a `sensor_sample::SensorSampleHdr` (16
  bytes: `version` u8 = 1, `hdr_len` u8 = 16, `flags` u16, `payload_len` u32,
  `acq_ns` u64, all LE) and then `SYS_SENSOR_READ_TYPED`'s bytes for the same
  read. `acq_ns` is when the value was acquired, on the vDSO clock; 0 =
  unknown. `SENSOR_SAMPLE_FLAG_SYNTHETIC` marks a simulated source. 561 is
  unchanged.
- **Added** per-task vDSO page layout version 2 (`VDSO_TASK_VERSION`,
  `VTP_VERSION`): each sensor slot carries `acq_ns` at `VTP_SENSOR_ACQ_NS`
  (48, the slot's former padding), inside the page seqlock. Version-1 offsets
  are unchanged.
- **Added** `drv_kind::power_op::READ_TS` (2): the power record and its
  `acq_ns` (`POWER_TS_BYTES` = 20). A driver without it answers no bytes.

LEASE2: robust notify words and leases that unmap the lessee. No
new syscall number: both use argument space the kernel refused before.

- **Added** `SYS_NOTIFY_WAIT` (592) ops in `a1[32..]`: `NOTIFY_OP_ROBUST_ADD`
  (1) / `NOTIFY_OP_ROBUST_DEL` (2) register / drop the word at `a0` as a
  robust lock word of the caller (low half of `a1` and `a2` must be 0). Was
  `-EINVAL` (`expected` wider than 32 bits). Codes: `-EACCES` read-only
  region, `-EQUOTA` per-task share (32) used, `-ENOSPC` table (64) full,
  `-ENOENT` drop of an unregistered word.
- **Added** `ROBUST_TID_MASK` / `ROBUST_OWNER_DIED` / `ROBUST_WAITERS`
  (Linux's robust-futex layout). When a task exits or execs while a word it
  registered holds its TID, the kernel writes `OWNER_DIED` (keeping
  `WAITERS`) and wakes every waiter.
- **Added** `SYS_NOTIFY_WAIT` return `NOTIFY_WAIT_OWNER_DIED` (2): woken by
  that sweep.
- **Added** `LEASE_ACCEPT_MAP` (`1 << 32` in `SYS_IPC_LEASE_ACCEPT`'s `a0`,
  which was refused with -1 above `u32::MAX`): accept and map the leased
  region; `a1` (read only with the flag) receives the address; returns the
  lease id. The mapping is the lease's: return, expiry, the lessor's free or
  exit remove it from the lessee with a TLB shootdown, and a later access
  kills the lessee.
- **Added** `EXIT_STAT_LEASE_REVOKED_FAULTS` (3), a `SYS_EXIT_STATS`
  selector: user faults attributed to a revoked lease mapping.

PORTWAIT: a port waits on several kinds of source, with a deadline.

- **Added** `SYS_PORT_WAIT_UNTIL_TYPED` (604): `a0` = `Cap<Port>` (`READ`),
  `a1` = out pointer (16 bytes, `SYS_PORT_POLL_TYPED`'s layout), `a2` =
  absolute deadline in nanoseconds on the time counter (`u64::MAX` none,
  a past instant polls). Returns 16 with an event, 0 when the deadline
  passed first, or `-Errno` (`-EBUSY` when the scheduler refused to block).
- **Added** `PORT_BIND_F_REMOVE` (`0x100` in `SYS_PORT_BIND_TYPED`'s `a1`):
  remove the channel, io_ring or timer sources of that type bound with the
  key in `a3`; `-ENOENT` when there was none.
- **Changed** `SYS_PORT_BIND_TYPED` (575) binds channel (0, a `Cap<Channel>`
  with `READ`), io_ring (1, a `Cap<IoRing>` with `READ`) and timer (3, an
  absolute deadline in ns) sources, which answered `-ENOSYS` before. New
  refusals: `-EBUSY` (the channel or ring reports to another live port),
  `-EMFILE` also for a full source table (Kconfig `MAX_PORT_SOURCES`). Events
  carry source type 1 channel, 2 io_ring, 3 IRQ, 4 timer; `source_id` is the
  capability handle the channel or ring was bound with, 0 for a timer.
- **Changed** (behaviour) `SYS_PORT_POLL_TYPED` (531) and
  `SYS_PORT_WAIT_TYPED` (577) also report those sources; 577 sleeps no later
  than the port's earliest armed timer.

USHELL (RFC-0055): the ring-3 user shell.

- **Added** `SYS_PIPE_TYPED` (607): two `Cap<Pipe>` handles (read end
  `READ|DUP`, write end `WRITE|DUP`) minted into the caller's table; `a1` =
  `PIPE_NONBLOCK` or 0. Reads, writes and closes are 564/565/566, which now
  dispatch on the handle's kind: a read of an empty pipe blocks (0 at end of
  file), a write of at most `PIPE_ATOMIC` (4096) bytes is all-or-block,
  `-EPIPE` when no reader is left, `-EINTR` on a stop request. Per-task quota
  `MAX_PIPES / 2` (`-EQUOTA`).
- **Added** `SYS_SPAWN_EX` (608): `SYS_SPAWN` plus a `ushell::SpawnReq`
  (version 1, 184 bytes): argv, environment, working directory,
  `SPAWN_F_DIE_WITH_PARENT`, and a move list of at most 8 entries giving the
  caller's `Cap<File>` descriptors and `Cap<Pipe>` ends to the child as its
  fds 0..=7 (rights kept or lowered; `MOVE_CONSOLE` for a console fd). Needs a
  `Cap<Launch>` with `EXEC` for the image the file's digest resolves to.
  The child finds a `ushell::StartupBlock` (`"KSB1"`, 120 bytes) at the top
  of its stack, its address in `a1` (`x1`) at entry — `a0` stays 0, as the
  spawn hand-off zeroes it like fork's. `SPAWN_F_MAP_TASK_PAGE` is reserved
  and refused (`-EINVAL`).
- **Added** `SYS_CONSOLE_WAIT` (609): one blocking wait over console bytes
  (raw, no echo), the caller's children's exit notices (`-EINTR`) and a
  timeout; the first call with a buffer makes the caller console input's one
  owner (`-EBUSY` for anyone else) until it exits.
- **Added** `SYS_TASK_KILL` (611): stop a DESCENDANT (`-ESRCH` for anything
  else, absent included): `KILL_REQUEST` ends its waits with `-EINTR`,
  `KILL_FORCE` ends it at its next syscall or interrupt from user mode with
  exit code `128 + signo`; `KILL_SUBTREE`.
- **Changed** `SYS_NR_RESERVED_UPPER` 611 → 612.
- **Added** `SYS_POWER_TYPED` (614, RFC-0055 S5): `a0` = `Cap<Power>`, `a1` =
  an operation of the new module `power` (`POWER_OP_SUSPEND`, `_REBOOT`,
  `_SHUTDOWN`, `_SCHED_HZ_GET`, `_SCHED_HZ_SET`), `a2` = its argument. The
  capability first (`WRITE`; `READ` for the rate read), refusals recorded;
  reboot and shutdown orderly as 270/271. In `CAP_TYPED_SYSCALLS`.
- **Changed** `SYS_NR_RESERVED_UPPER` 612 → 615 (612 and 613 are assigned on
  a parallel branch, LEASE3, and left free here).
- **Added** `CapKind::Pipe` (26) and `CapKind::Launch` (27, topology word
  `"launch"`, target an image name, perm `x`); errnos `EINTR` (4), `EPIPE`
  (32); module `ushell` (layouts with size/offset asserts, `layout_startup`,
  `StartupBlock::from_bytes`, flag and limit constants).

EXIT2: the exit notice follows the teardown.

- **Added** `SYS_EXIT_STATS` (605): `a0` = an `EXIT_STAT_*` selector
  (`EXIT_STAT_EXIT_TEARDOWNS` 0, `EXIT_STAT_REUSE_TEARDOWNS` 1,
  `EXIT_STAT_EARLY_NOTICES` 2); returns that counter, or `-EINVAL`.
- **Changed** (behaviour, no wire change) `SYS_WAIT`, `SYS_WAIT_STATUS` and
  `SYS_WAITPID` report a child only after its exit hook and address-space
  teardown have run: the pages it held are free when the call returns. Still
  `WNOHANG`; a caller polling for a lower-priority child must sleep between
  looks, not yield.

ML service data files.

- **Added** `ml_srv::WEIGHTS_PATH` (`/fat/MLP.RML`, an 8.3 name; the file was
  `MLP.RMLP`, which the FAT32 driver never resolved) and
  `ml_srv::POLICY_PATH` (`/fat/POLICY.GGF`), NUL-terminated, the paths
  `userspace/services/mlsrv` opens.

DRV2: ring-3 drivers park instead of polling.

- **Changed** `drv_kind::power_op::STATS` writes 17 bytes (`STATS_BYTES`,
  added): the previous nine, then `charge_ma_us: u64` (LE), the INA219
  driver's integrated charge, each sample weighted by the time its clock
  measured since the previous one.
- **Documented** `SYS_BUZZER_TONE` (420) returns once the tone has started,
  not when it ends (the existing behaviour).
- No new syscall: the blocking driver fetch is `SYS_DRIVER_REPLY_WAIT` (610,
  added earlier). 604, allocated for it, stays free.

PROXY3.

- **Added** `SYS_IPC_LEASE_GRANT_TYPED` (603): grants a lease on the shared
  memory region a `Cap<Shm>` (READ) names, with the arguments of the raw
  call it replaces (cap, lessee, expiry).
- **Retired** 111, the raw-id lease grant: ring 3 had no way to learn a
  region id. The in-kernel `lease_grant` is unchanged. 604..=609 stay free.

FS3 (owner decisions of 2026-09-28).

- **Changed** `SYS_DISK_READ`/`SYS_DISK_WRITE` (281/282) take a fourth
  argument, `a3` = partition selector: a `Cap<Disk>` handle naming the
  partition (or the whole disk), or `DISK_SEL_ONLY` (0, `CAP_NULL`) for the
  caller's only disk capability. With 0 a holder of two or more partitions
  is still refused as ambiguous (`-99`); with a handle it is admitted. A bad
  handle answers `-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS`, a selector above
  `u32::MAX` `-EINVAL`. A ring-3 write through either form answers `-EAGAIN`
  while degraded mode is armed.
- **Changed** `SYS_DISK_SIZE` (283) takes the same selector in `a0`, needs
  the capability (READ; `-99` without one) and reports the PARTITION's
  sectors to a partition holder, the medium's to a whole-disk holder.
- **Added** `DISK_SEL_ONLY` (0).
- **Changed** `SYS_MKDIR` (252), `SYS_UNLINK` (253), `SYS_RMDIR` (597),
  `SYS_RENAME` (598) and `SYS_TRUNCATE` (599) need, from ring 3, a
  `Cap<File>` with WRITE naming a directory tree that covers the path
  (topology kind `"file"`, target the tree's absolute root; the resource is
  at or above `0x4000_0000`, never a descriptor). Create, remove and rename
  need the path strictly under the root; truncate may name the root.
  `-EACCES` without one, `-EINVAL` for a relative path or a `.`/`..`
  component, `-EAGAIN` for a holder while degraded mode is armed. A tree
  capability handed to a descriptor call is `-ECAPKIND`.

Integration: numbers and kinds taken by the changes below, merged.

- **Added** `SYS_ENTROPY_READ_TYPED` (596, `CapKind::Entropy` = 24),
  `SYS_IPC_LEASE_WAIT` (602, `CapKind::Lease` = 25) and
  `SYS_DRIVER_REPLY_WAIT` (610: 581 that parks the driver on an empty queue
  until a request is queued or its park ends; a stop request wakes it and it
  exits at that call, like the other driver-side calls).
- **Added** driver kinds `DRV_KIND_BUZZER` (0x10), `DRV_KIND_POWER_MON`
  (0x11) and `DRV_KIND_ML` (0x12).
- **Changed** `SYS_NR_RESERVED_UPPER` is 611: 610 is the highest number in
  use; 603..=609 were allocated to fronts that did not take them and stay
  free.

The rest of the RFC-0048 P2 file surface.

- **Added** `SYS_RMDIR` (597), `SYS_RENAME` (598), `SYS_TRUNCATE` (599),
  `SYS_FSYNC_TYPED` (600, a `Cap<File>` in `a0`, a `CAP_TYPED_SYSCALLS`
  member) and `SYS_STATFS` (601, layout `STATFS_BYTES` = 48 and the
  `STATFS_OFF_*` offsets). `SYS_NR_RESERVED_UPPER` grows from 600 to 602
  (611 after the integration, above).
- **Added** errnos `ENAMETOOLONG` (36) and `ENOTEMPTY` (39), Linux's values.
- **Changed** `SYS_DISK_READ`/`SYS_DISK_WRITE` (281/282): for a holder of a
  partition-scoped `Cap<Disk>` the sector is relative to its partition (the
  kernel adds the start); holding more than one partition with the needed
  permission is refused as ambiguous. Whole-disk callers are unchanged.

RFC-0049 M1: instances per topology row.

- **Added** topology row field `instances = N` (1..=`MAX_TASKS`, default 1).
  Memory admission counts the row's budget N times, and twice per instance
  only when the row's image can fork (its seccomp profile lists `SYS_FORK`
  (12) or `SYS_FORK_COW` (403), or is audit-mode; `autorun` and rows naming no
  shipped image count as forking).
- **Changed** `SYS_SPAWN` (17), `SYS_EXEC` and `SYS_EXECPATH` return `-1`
  when the image's row already has N live spawned or exec'd instances. Fork
  children are not instances (`SYS_FORK` is bounded by the memory budget).
  A program with no row of its own is not counted.

RFC-0049 stage M4: a cold-restart supervisor for ring-3 drivers.

- **Added** `exit_status::KILLED_KILL = 137` (128 + SIGKILL): the exit status
  of a ring-3 driver the kernel asked to stop. It exits at its next
  driver-side call (driver-server fetch, reply, reply+fetch, reply+wait or
  poll).
- **Changed** a ring-3 driver started by the autorun loader that registered a
  driver-server kind is restarted from the same image when it dies, up to 3
  times; the death after the third restart is final. Across the restart its
  driver-server kind stays registered (requests submitted meanwhile are
  queued for the successor), its named endpoints keep their generation (a
  client's `Cap<Endpoint>` stays valid; a call answers "unserved" until the
  successor re-claims it), and its service names stay `Stopped`.
- **Changed** `SYS_DRIVER_REGISTER_TYPED` (556) succeeds when the caller
  already owns the kind (it refreshes the slot's MMIO/IRQ fields);
  `SYS_SERVICE_REGISTER` succeeds when the name is a `Stopped` entry held for
  the caller. Both were refused before.

RFC-0049 stage M1: per-task frame budgets that count every frame.

- **Changed** a task's frame budget (the topology row's `mem_pages`) now
  covers its ELF image, user stack and page tables, its shared-memory regions
  (charged to the creator until freed) and io_ring pages, and a
  `SYS_ALLOC_DEMAND` (404) reservation when it is made (untouched pages come
  back at `SYS_MUNMAP`). `SYS_EXEC`/`SYS_EXECPATH`/`SYS_SPAWN` return `-1` for
  an image whose address space alone exceeds its row's budget.
- **Changed** a ring-3 image runs under the budget of the row named after it,
  else `autorun`'s (autorun), else Kconfig `RING3_MEM_PAGES_DEFAULT` (spawn).
- **Added** topology row field `mem = "locked"` (default `"ceiling"`): the
  task may not call `SYS_FORK` (12), `SYS_FORK_COW` (403) or
  `SYS_ALLOC_DEMAND` (404) (`-1`/`-EPERM`), and an image whose seccomp
  profile is audit-mode or lists them is refused under such a row. Topology
  section `[pipeline.NAME]` with `dma_kb`.

FSPRE (RFC-0048 stage 0).

- **Added** `syscall_nr::STAT_BYTES = 64` and the `STAT_OFF_*` offsets: the
  record `SYS_STAT` writes (size `u64`, mode, nlink, uid, gid, three `u64`
  times, two reserved words). `SYS_STAT` was a `-1` stub and now returns it.
- **Changed** `SYS_MOUNT` from a `-1` stub to a mount behind the whole-disk
  `Cap<Disk>` WRITE (types `tmpfs`, `fat32`); ring 3 is refused.
- **Changed** `SYS_LSEEK`: the offset is the whole 64-bit register (it was
  cut to `i32`), and so is the returned position.
- **Changed** `CapKind::Disk` gains a topology spelling, `disk.part.<n>`: a
  capability for ONE partition of the table the kernel parsed at boot
  (resource `n + 1`); resource 0 stays the whole medium.

V: notify/wait, and the per-task vDSO page.

- **Added** `syscall_nr::SYS_NOTIFY_WAIT = 592` / `SYS_NOTIFY_WAKE = 593`: a
  futex-shaped wait/wake on a `u32` inside a shared-memory region the caller
  has mapped, keyed by (region, offset) — never by an address. Not in
  `CAP_TYPED_SYSCALLS`: they take no handle; the authority is the caller's
  recorded mapping, which only `SYS_SHM_MAP_TYPED` with `Cap<Shm>` `READ`
  creates.
- **Added** `syscall_nr::SYS_VDSO_TASK_MAP = 594`: maps the caller's own
  per-task vDSO page read-only into its shm/MMIO window and returns the
  address. The page carries the caller's CPU time (sampled at timer
  interrupts), voluntary/preempted switch counts, the `ready_site` tag of its
  last dispatch, and the sensors it bound, under a seqlock.
- **Added** `syscall_nr::SYS_VDSO_SENSOR_BIND = 595`: publishes the sensor a
  `Cap<Sensor>` (`READ`) names into the caller's page. Added to
  `CAP_TYPED_SYSCALLS`.
- **Added** `vdso::VDSO_TASK_MAGIC` and the `vdso::VTP_*` byte offsets of the
  per-task page, the one definition `crates/core/mm` asserts and `crates/core/libsys`
  reads.

U06-9 (owner decision, 2026-09-26).

- **Added** `syscall_nr::SYS_LINK_KEY_READ_TYPED = 591`: copies the 32-byte
  brain-link PSK from the kernel's reserved sector into a user buffer,
  refused unless the caller holds `Cap<LinkKey>` READ. Replaces
  `brain_client`'s own read of `/fat/LINK.KEY`, now that the kernel keeps the
  key off the exported FAT volume (`kernel/src/msc_gadget.rs`,
  `RESERVED_SECTOR_LINK_KEY`). Added to `CAP_TYPED_SYSCALLS`.
- **Added** `syscall_nr::LINK_KEY_READ_BYTES = 32`.
- **Added** `cap::CapKind::LinkKey` (23): a singleton capability, like
  `Buzzer` — one brain-link key per board, resource always `0`. `abi-tests`'
  `ALL_KINDS` and `kind_from_raw_recognises_all` extended accordingly.

io_ring entries and SQ polling (the ring page is ABI; `crates/core/ipc/src/io_ring.rs`
pins its offsets, `crates/core/libsys/src/ioring.rs` is ring 3's copy).

- **Added** ring opcodes, each checked against its typed twin's seccomp row
  and the owner's capability: `OP_FILE_READ` 12 / `OP_FILE_WRITE` 13
  (`SYS_FILE_*_TYPED`), `OP_CHAN_SEND` 14 / `OP_CHAN_RECV` 15
  (`SYS_CHAN_WRITE/READ_TYPED`), `OP_TIMER` 16 (`SYS_SLEEP_UNTIL`; completes 1
  if passed, else parks and completes 0), `OP_NOTIFY_WAIT` 17 (`-ENOSYS` until
  the kernel has a notify primitive), `OP_SQPOLL_START` 18 (`-EPERM` unless
  the owner's topology row declares `sqpoll_idle_ms`).
- **Added** ring page word `sq_flags` at offset 3600: `SQ_F_SQPOLL` (1),
  `SQ_F_NEED_WAKEUP` (2). On a polled ring `SYS_IORING_SUBMIT_TYPED` is only a
  wake-up and answers 0.
- **Changed** a refused ring entry for a missing device capability is now
  recorded as `SAFETY_CAP_DENIED_TYPED`, charged to the ring's owner.

RFC-0041 §A and §E.

- **Changed** `SYS_IORING_CREATE_TYPED` (536) writes the ring page's user
  address, mapped user RW and never executable, instead of 0; a kernel caller
  still receives the physical address.
- **Changed** `SYS_IORING_SUBMIT_TYPED` (537) executes entries, each checked
  for the submitter's seccomp profile, the owner's capability and, for writes,
  containment. A refused entry completes with
  `syscall_nr::IORING_CQE_F_REFUSED` (**added**, 1) and `-Errno`; a full
  completion queue answers `-EBUSY` and runs nothing. It answered `-EIO`
  before.
- **Changed** `SYS_MMAP` refuses `PROT_EXEC` (4) with `-EINVAL`.
- **Changed** `cap::CapHandle`'s bitfield moved from the snapshot's 4-bit
  kind / 4-bit perms / 8-bit generation / 16-bit slot to **6-bit kind /
  4-bit perms / 13-bit generation / 9-bit slot** (`crates/core/abi/src/cap.rs`
  `KIND_BITS`/`PERMS_BITS`/`GEN_BITS`/`SLOT_BITS`). Reasons on record in the
  source: `SLOT_BITS` grew 8→9 (256 slots was not enough for a fleet
  kernel's per-task table; `GEN_BITS` grew accordingly, 8→13, to keep
  forgery resistance as the slot count grew); `KIND_BITS` grew 4→6 because
  more than 16 `CapKind` variants now exist (documented 2026-09-26; not
  previously recorded here — a reader of only this changelog's "Initial ABI
  snapshot" section below would still have the old layout).
- The vDSO page's word at offset 12 is `flags`; bit 0 means ring 3 may read
  the time counter with `rdtime`. The layout does not move.

POSIX subset, step 1 (owner decisions 42, 43).

- **Removed** `SYS_KILL`, `SYS_SIGNAL`, `SYS_SIGRETURN`, `SYS_SIGPENDING`,
  `SYS_SIGPROCMASK`, `SYS_PAUSE`, `SYS_ALARM` (350-356) and `SYS_PIPE`,
  `SYS_DUP`, `SYS_DUP2` (360-362), now listed in `RETIRED_SYSCALLS`. No
  ring-3 image called them except abitest's pipe check.

RFC-0044.

- **Added** `syscall_nr::SYS_SLEEP_UNTIL = 590`: block until an absolute
  deadline in nanoseconds on the `time` counter; returns `1` without blocking
  when the deadline has already passed.
- **Added** `time::{ns_to_ticks_ceil, ticks_to_ns, NS_PER_SEC}`, the
  conversions the kernel and ring 3 share.
- `SYS_SLEEP` (15) keeps its number, argument and return value; it now blocks
  instead of running for the interval, and converts with the board's timer
  frequency.

RFC-0043.

- **Added** `syscall_nr::SYS_SPAWN = 17`: start a process from the image at
  a path, under that image's seccomp profile and topology capabilities.
- **Removed** `syscall_nr::SYS_DRV_MMAP` (302), now listed in
  `RETIRED_SYSCALLS`: ring 3 maps MMIO only through `SYS_MMIO_MAP`. No
  ring-3 program called it.
- **Changed** `syscall_nr::SYS_MMIO_MAP` (509): `a0` is an index into the
  board's MMIO region table, no longer a physical base, and `a1` is the
  access, `CapPerms` bits `READ` or `READ | WRITE`, no longer a size. The
  kernel maps exactly the table's range, read-only unless WRITE was asked.
  `EINVAL` for an index above `u32::MAX` or outside the table or any other
  access word, `EACCES` for WRITE on a read-only region, `-1` without the
  capability. No ring-3 program called the old form.
- **Changed** `cap::CapKind::MmioRegion`: the capability's resource is the
  region index. The `SAFETY_CAP_DENIED` record still carries the region's
  base, looked up from the table, and 0 for an index outside it.

## [0.1.0-pre] — early snapshot (2026-05-14)

**Initial ABI snapshot.** Nothing in this crate is locked.

### Public surface at the snapshot

- **`ABI_VERSION: u32 = 1`** — the ABI generation tag.
- **`cap::CapHandle`** — `#[repr(transparent)] u32` wire-format
  capability handle. Bitfield: 4-bit kind, 4-bit perms, 8-bit
  generation, 16-bit slot.
- **`cap::CapKind`** — `#[repr(u8)]` enum, 16 variants:
  `Null` `Channel` `Shm` `Port` `Irq` `MmioRegion` `IoRing` `Sensor`
  `Gpio` `I2c` `Pwm` `Motor` `File` `Socket` `Task` `AiSession`.
- **`cap::CapPerms`** — `#[repr(transparent)] u8` bitfield:
  `READ=0b0001` `WRITE=0b0010` `EXEC=0b0100` `DUP=0b1000`.
- **`cap::CAP_NULL`** — the all-zeros invalid handle.
- **`error::Errno`** — `#[repr(i64)]` enum with POSIX-aligned codes
  in `1..=99` and AZOS-specific codes in `200..=299`. Notable
  AZOS additions: `ECAPKIND=200` `ECAPPERMS=201` `ECAPSTALE=202`
  `ETOPOLOGY=203` `ESAFETY=204` `EAUTH=205` `EREPLAY=206`
  `EOTASIG=207` `EROLLBACK=208` `EQUOTA=209` `EABIVERSION=210`.
- **`syscall_nr::*`** — 70+ syscall numbers at the snapshot:
  - 0..=19 process control
  - 20..=29 file I/O
  - 100..=119 IPC
  - 200..=229 GPIO/PWM/I2C
  - 230..=249 motor + sysinfo
  - 250..=269 filesystem + network
  - 270..=299 system control / disk / FDT
  - 300..=319 driver-server
  - 320..=349 robot control + platform
  - 350..=369 signals + pipes
  - 370..=389 sockets
  - 390..=399 service manager
  - 400..=429 memory + ADC + buzzer
  - 430..=499 security (seccomp + future)
  - 500..=529 IO ring / channels / MMIO / IRQ / ports / handles /
    trace / drivers
  - **528..=549 reserved for cap-typed migrations**
    (`SYS_CHAN_WRITE_TYPED=528`, `SYS_CHAN_READ_TYPED=529`)
- **`types::*`** — `#[repr(C)]` size-stable structs:
  `SensorState` (48 B), `MotorOutput` (12 B), `RobotInfo` (8 B),
  `SafetyProfile` (24 B).
- **`SYS_NR_RESERVED_UPPER: u64 = 600`** — bound below which new
  numbers will be allocated.

### Verification

- `tests/host/abi-tests/` host suite: 18 tests covering pack/unpack,
  errno round-trip, size stability, number assignments.
- All sizes asserted at compile time via `core::mem::size_of`.

### Lineage

This crate was introduced with the first snapshot (RFC-0008). The bitfield
layout of `CapHandle` and the `Cap<T>` typed wrapper that uses it
trace to RFC-0003.

## Upgrade discipline (a convention, not a promise)

- A v1.x release **may** add new syscall numbers, new `CapKind`
  variants, new `Errno` codes, or new `#[repr(C)]` types.
- A v1.x release **must not**:
  - Remove or rename any existing `pub` item.
  - Change the numeric value of any `Errno` or syscall number.
  - Change the size or layout of any `#[repr(C)]` type.
  - Repurpose any bit in `CapHandle`.
- ABI breakage requires an RFC supersede, a major version bump, and
  a 12-month deprecation window (RFC-0016).
