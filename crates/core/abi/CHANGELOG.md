# `azos_abi` changelog

Changes to the ABI crate (`crates/core/abi`), in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There are no tagged
releases. `ABI_VERSION` (`crates/core/abi/src/lib.rs`) is 2. The tree-wide
changelog is [`../../../CHANGELOG.md`](../../../CHANGELOG.md).

## [Unreleased]

### Added

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
  | `drv_kind` | `DRV_KIND_*` identifiers of the driver registry |
  | `rt_levels` | The cross-level admission rule for deadline reservations |
  | `trace` | Event classes and ids of the kernel tracer |
  | `time` | Conversions between nanoseconds and the `time` counter |
  | `power`, `sensor_sample` | Layouts of the power interface and sensor samples |

- `SYS_MO_CREATE` takes the memory-object kind `SHM_KIND_CONTIG` (one
  physically contiguous run, for memory a device reads or writes) from ring 3,
  without the swappable, volatile or clone fields.
