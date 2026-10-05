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
