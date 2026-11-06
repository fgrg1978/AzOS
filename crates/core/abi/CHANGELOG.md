# `azos_abi` changelog

Changes to the ABI crate (`crates/core/abi`), in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There are no tagged
releases. `ABI_VERSION` (`crates/core/abi/src/lib.rs`) is 3. The tree-wide
changelog is [`../../../CHANGELOG.md`](../../../CHANGELOG.md).

## [Unreleased]

### Changed

- The io_ring layout is version 3 (`IO_RING_VERSION`): `OP_CALL` (14) carries an
  IDL call on a kernel-hosted endpoint in a message window of the data buffer
  (`CALL_WORDS`, `CALL_WINDOW`), and the device opcodes are gone (below).
- `CapHandle` is `kind 6 | generation 16 | slot 10`. The rights left the handle
  (`CAP_INFO_QUERY` reads them), so the generation is the slot word's whole field.

### Removed

- The io_ring device opcodes `OP_READ_SENSOR` (1), `OP_WRITE_GPIO` (2),
  `OP_READ_GPIO` (3), `OP_I2C_READ` (4), `OP_I2C_WRITE` (5), `OP_PWM_SET` (6) and
  `OP_MOTOR_SPEED` (7): a device is an `OP_CALL` of its interface. The numbers
  now answer `-ENOSYS`.
- The absolute-path ops of the domain: `DOMAIN_STAT` (0x500D), `DOMAIN_READDIR`
  (0x500E), `DOMAIN_STATFS` (0x500F), `DOMAIN_MKDIR` (0x5614), `DOMAIN_UNLINK`
  (0x5615), `DOMAIN_RMDIR` (0x5616), `DOMAIN_RENAME` (0x5617) and
  `DOMAIN_TRUNCATE` (0x5618) (`CLASS_READ` 13-15 and `CLASS_FS_MUTATE` 20-24,
  in `RETIRED_OPS`, not reused; the dispatcher's default arm answers them). A
  name is beneath a directory handle: the `NODE_*AT` ops below.
- The driver-server ABI: the `drv_kind` module (`DRV_KIND_*`, `power_op`), the
  `ty::DRIVER_REGISTRY` type (`Device` class 2, not reused) and the six
  `DOMAIN_DRIVER_*` ops (`CLASS_DRIVER` 39, 40, 44-47, not reused; the
  dispatcher's default arm answers them). A ring-3 driver serves its class's
  IDL interface on an endpoint.
- `DEVICE_IRQ_BIND` (0x7901, `CLASS_DRIVER` 1, in `RETIRED_OPS`, not reused):
  an interrupt line is bound to a port by the port's `PORT_BIND` with
  `PORT_SRC_IRQ` (below). `DEVICE_IRQ_ACK` stays.

### Added

- `PORT_SRC_IRQ = 7`: `PORT_BIND` of a `ty::IRQ` handle (`w1`), its CPU in
  `w3` (`DEVICE_IRQ_CPU_ANY`), an MSI slot's message replied in `a1..a3`; with
  `PORT_BIND_F_REMOVE` the caller's binding goes and the port gets a
  `PORT_EVENT_SOURCE_GONE` (`EREVOKED`). The bind needs the line's op class
  (`DRIVER` of a `Device`) in the image's profile as well as the port's.
- `DEVICE_DMA_MAP` (0x7903) and `DEVICE_DMA_UNMAP` (0x7904) on a `ty::MMIO`
  handle, and their direction words `DMA_TO_DEVICE` 0, `DMA_FROM_DEVICE` 1,
  `DMA_BIDIRECTIONAL` 2: a ring-3 `SHM_KIND_CONTIG` object given to a device
  no kernel driver owns; replies bus address, length and coherence. Refused
  for a device no IOMMU confines unless Kconfig `DMA_RING3_WITHOUT_IOMMU`; under
  that rule a topology's writable window on a device that masters the bus is
  not granted either.
- The `Entropy` interface is at level 2: `feed` (`WRITE`) mixes what a
  ring-3 entropy device read into the pool, credited only as Kconfig
  `ENTROPY_RING3_FEED` says (mix-only by default).

- The `*at` ops of a directory handle (`Cap<Dir>`): `NODE_STATAT` (0x6011),
  `NODE_READDIR` (0x6012; size, directory flag and name-cut flag as reply
  words), `NODE_STATFS` (0x6013), `NODE_MKDIRAT` (0x6614), `NODE_UNLINKAT`
  (0x6615, with `UNLINK_DIR` for an empty directory), `NODE_RENAMEAT` (0x6616)
  and `NODE_TRUNCATEAT` (0x6617). `CLASS_FS_MUTATE` is a `Node` class. Their
  numbers are the `Node` and `Dir` IDL interfaces' (`azos_devif::fs`).
- `syscall_nr::IO_MAX_BYTES`: the most one file read or write moves.

- Initial import of the crate. It holds everything that crosses the
  user/kernel boundary, as `no_std` code with no `unsafe`:

  | Module | Contents |
  |---|---|
  | `syscall_nr` | The 33 native system-call numbers and their argument conventions |
  | `invoke` | The op numbers of `SYS_INVOKE`, by handle kind and op class |
  | `cap` | The capability handle wire format: `CapHandle`, `CapKind`, `CapType`, `CapPerms` |
  | `error` | Error codes returned across the system-call boundary |
  | `types` | `#[repr(C)]` types shared by user space and the kernel |
  | `ipc_msg` | `MsgDesc`, the message descriptor of the v2 call |
  | `io_ring` | The io_ring page layout, opcodes and flags |
  | `foreign` | The foreign-ABI family (`SYS_FOREIGN_*`) |
  | `vdso` | The vDSO address and layout offsets |
  | `ushell` | The spawn request block, the startup block and console flags |
  | `exit_status` | Exit statuses the kernel assigns when it kills a task |
  | `families` | Selectors of the flight, behavior, config and OTA families |
  | `rt_levels` | The cross-level admission rule for deadline reservations |
  | `trace` | Event classes and ids of the kernel tracer |
  | `time` | Conversions between nanoseconds and the `time` counter |
  | `power`, `sensor_sample` | Layouts of the power interface and sensor samples |

- `ty::IOPORT` (`Device` class 3), a range of I/O ports (`cap::ioport_range`,
  `cap::ioport_bounds`), and `DEVICE_IOPORT_ENABLE`, the op that opens it
  to the calling thread (x86_64; `-ENODEV` where the ISA has no ports).
  `SYS_CAP_CLOSE` on it revokes it, and the ports close in every thread of
  the holder that opened them.
- `SYS_MO_CREATE` takes the memory-object kind `SHM_KIND_CONTIG` (one
  physically contiguous run, for memory a device reads or writes) from ring 3,
  without the swappable, volatile or clone fields.
