# AzOS changelog

All notable changes to AzOS are recorded here, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There are no tagged
releases yet. The ABI crate keeps its own file,
[`crates/core/abi/CHANGELOG.md`](crates/core/abi/CHANGELOG.md).

## [Unreleased]

### Added

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
    `crates/drivers/`; `crates/fs/fs` (VFS, FAT32, tmpfs, azvol, page cache,
    crash log); `crates/net/` (the TCP/IP stack, an encrypted link, a stream
    multiplexer, a TFTP client).
  - **User space:** ring-3 services, drivers, libraries and test programs under
    `userspace/`; the native `std` SDK (`sdk/`); the relibc port
    (`userspace/lib/relibc-azos`); the optional Linux personality
    (`crates/core/linux-abi`, `crates/core/syscall/src/linux.rs`,
    `userspace/lib/linux_rt`); Linux driver glue (`lx/`).
  - **Other kernels and domains:** AzOS-micro for parts without an MMU
    (`micro/`); the robot domain (`domains/robot/`).
  - **Build and tests:** the Kconfig tree, presets and defconfigs (`Kconfig`,
    `config/`), the Makefile split under `mk/`, build, check and signing tools
    (`tools/`), host test crates (`tests/host/`), fuzz targets (`tests/fuzz/`)
    and TLA+ models (`formal/`).
