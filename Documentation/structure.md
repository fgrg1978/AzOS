# Source tree structure

This page maps every top-level directory and every crate under `crates/`, then
shows the per-ISA layout that the three architecture ports share. Paths are
relative to the repository root. For the design behind the layout see
[overview.md](overview.md); for how the pieces are built see
[building.md](building.md).

Contents: [Top level](#top-level) | [crates/core](#cratescore) |
[crates/drivers](#cratesdrivers) | [crates/fs and crates/net](#cratesfs-and-cratesnet) |
[crates/lib](#crateslib) |
[crates/domains/robot](#cratesdomainsrobot) | [Per-ISA layout](#per-isa-layout) |
[kernel/](#kernel) | [userspace/](#userspace) | [Tests and tools](#tests-and-tools)

## Top level

| Path | Contents |
|---|---|
| `kernel/` | The kernel image: `kernel_main`, boot steps, per-ISA entry code, kernel tasks, panic handler, the linker scripts' shared include. |
| `arch/` | The architecture crates: `api/` (`azos_arch_api`, the cross-ISA contract), `facade/` (`azos_arch`, re-exports the build's ISA crate), and one crate per ISA, `riscv/` (`azos_arch_riscv64`), `aarch64/`, `x86_64/`, each with its kernel linker scripts in `boot/`. |
| `crates/` | Kernel libraries, in six groups: `core/`, `drivers/`, `fs/`, `net/`, `lib/`, and `domains/robot/` (the optional robot application domain, linked only when the image selects it). |
| `userspace/` | Ring-3 programs: `services/`, `drivers/`, `lib/`, `tests/`, `bench/`, plus `image_hashes.py`, `rustc_stable_metadata.py` (the `RUSTC_WRAPPER` that keeps each ring-3 ELF's bytes a function of source and toolchain, since the seccomp image profiles bind them by SHA-256) and `x86_64-azos-user.json` (the target spec the x86_64 ring-3 programs are built for). |
| `sdk/` | The native `std` SDK: target specs, linker scripts and the `std` overlay. Its own test program is `userspace/tests/sdktest`. |
| `micro/` | AzOS-micro, the MMU-less MCU kernel (riscv32imac, M-mode, PMP region domains, static tasks from the signed topology in `micro/topology/`). It is its own workspace and links the main kernel's pure crates; `make micro` builds it. |
| `config/` | The Kconfig fragments (`Kconfig.*`) and `defconfigs/`. The root `Kconfig` sources them. One fragment, `Kconfig.userspace` (the programs under `userspace/`), is generated at every parse by `tools/build/gen_userspace_kconfig.py` and is not committed. |
| `mk/` | Makefile fragments included by the top-level `Makefile`: `vars.mk`, `kernel.mk`, `userspace.mk`, `images.mk`, `system.mk`, `host.mk`, `qemu.mk`, `lints.mk`, `fetch.mk`, `firmware.mk`. |
| `tools/` | The host tools (Python and shell), one directory per role (see [Tests and tools](#tests-and-tools)); `tools/image/boot.cmd` is the U-Boot script that boots slots A/B/R from the SD card. |
| `tests/` | `host/` (host-side test crates), `fuzz/` (fuzz targets), plus the emulator runner scripts `qemu_boot.sh` and `run_all.sh`. |
| `formal/` | `tla/` (TLA+ models `cap_table` and `topology_load`, each with its `.cfg`), `INVARIANTS.md` and `README.md`. |
| `third_party/` | `vendor/` (vendored crates) and its pin `VENDOR_PIN`; the third-party source trees `busybox/`, `limine/`, `linux/`, `lvgl/`, `relibc/`, `u-boot/` (gitlinks in `.gitmodules`, `update = none`, fetched here by `tools/build/third_party_fetch.sh`); `busybox.fragment` (the BusyBox configuration `make busybox` adds to allnoconfig); `patches/`. |
| `LICENSES/` | Licence texts: Apache-2.0, GPL-2.0-only, MIT. |

Top-level files: `Cargo.toml` (workspace) and `Cargo.lock`, `Kconfig`, `Makefile`,
`rust-toolchain.toml`, `deny.toml`, `REUSE.toml`, `LICENSE`,
`NOTICE`, `README.md`, `CONTRIBUTING.md`, `CLA.md`, `SECURITY.md`, `CHANGELOG.md`,
`ROADMAP.md`, `ARCHITECTURE.md` (a map, see [../ARCHITECTURE.md](../ARCHITECTURE.md)).

Source: the directories above; `Cargo.toml`, `Makefile`, `Kconfig`.

## crates/core

| Crate (directory under `crates/core/`) | Package | What it holds |
|---|---|---|
| `abi` | `azos_abi` | The user/kernel boundary: syscall numbers, error codes, `#[repr(C)]` shared types, the capability handle format, the vDSO base, the io_ring page layout. `no_std`, `forbid(unsafe_code)`. |
| `actuation` | `azos_actuation` | The authority over irreversible effects: e-stop latch, effect gate, safe state, flight recorder, watchdogs. |
| `azos-config` | `azos-config` | Build-time `.config` reader and Rust constant emitter (host crate). |
| `limits` | `azos_limits` | Compile-time constants generated from `.config`. |
| `config` | `azos_config` | Persistent `KEY=VALUE` runtime configuration store. |
| `bytepipe` | `azos_bytepipe` | The POSIX byte pipe as a ring in a shared-memory region. |
| `channel` | `azos_channel` | Latest-value channels: a one-slot `Log` plus a timestamp. |
| `rings` | `azos_rings` | The ring shapes (`Queue`, `Log`, `region`) and the SPSC protocol under them. |
| `chaos` | `azos_chaos` | Fault-injection registry with named injection points (Kconfig `CHAOS`). |
| `common` | `azos_common` | Shared basics: error type, panic policy, path helpers, WCET helpers, the global "panicked" flag. |
| `crypto` | `azos_crypto` | Cryptographic primitives (hashes, ciphers, signatures), `no_std`. |
| `decision` | `azos_decision` | Explainable decision records and durable refusal receipts. |
| `devif` | `azos_devif` | The interfaces of what the kernel hosts and a driver endpoint serves (gpio, i2c, spi, can, uart, pwm, motor, sensor, block, clock, entropy, power, time, vm, vm control, buzzer, adc, link key, display, input, sound, inference, keys, memory-object control, the network name and time services), and the outcome code every op answers. |
| `idl` | `azos_idl` | The AzOS interface definition language: traits annotated with `#[azos_interface]` and their wire form. |
| `idl-macros` | `azos_idl_macros` | The proc-macro behind `#[azos_interface(id, level, words)]`. |
| `ext-api` | `azos_ext_api` | The contract between the base kernel and an extension: effect providers, effect loops, enforcers, boot hooks. |
| `hyp-api` | `azos_hyp_api` | The ABI between the kernel and the resident monitor: call ids, status codes, the invariants `probe` reports. |
| `hyp-mon` | `azos_hyp_mon` | The aarch64 resident monitor (`VIRT_SPLIT`), entered at EL2 before EL1 runs. |
| `image` | `azos_image` | What the image loader needs about a static ELF image, native or Linux: where its program headers land. |
| `records` | `azos_records` | The kernel's record substrate: the kernel log, decision records, actuation telemetry and security records, one ring each. |
| `seclog` | `azos_seclog` | The sealed security log: the format, chain, sealer and verifier of the records, and the line `logd` writes. |
| `energy` | `azos_energy` | Utilisation tracking, energy model, placement / governor / idle seams, OPP bookkeeping. |
| `hv` | `azos_hv` | The hypervisor core: guest admission, VM objects, guest memory, vCPU loop, virtual LAPIC/IOAPIC. |
| `inspect` | `azos_inspect` | The introspection tree: typed nodes in a region the kernel alone writes. |
| `ipc` | `azos_ipc` | Capabilities (`cap`, `cap_store`, `objref`), endpoints and queues, ports, memory objects, io_ring, kernel pipes, fast-call plumbing. |
| `ktest` | `azos_ktest` | The in-kernel test registry (`ktest!`). |
| `libsys` | `azos_libsys` | The ring-3 syscall wrapper library. |
| `libsys-macros` | `azos_libsys_macros` | `#[main]` and `#[test]` for ring-3 programs. |
| `linux-abi` | `azos_linux_abi` | The pure half of the Linux personality: Linux syscall numbers, translation, and state. |
| `lx-loader` | `azos_lx_loader` | Loader for relocatable (`ET_REL`) Linux driver modules. |
| `mm` | `azos_mm` | Physical frames and the buddy allocator, slab / kernel heap, page tables and mappings, COW, demand paging, page cache backing, swap and compressed pool, W^X rules, the vDSO page. |
| `ota` | `azos_ota` | A/B slot management, update image format, secure-boot checks. |
| `percpu` | `azos_percpu` | Per-CPU areas, CPU masks and `nr_cpu_ids`. |
| `pkg` | `azos_pkg` | Signed application packages: container, metadata, verification, admission, receipts. |
| `recovery` | `azos_recovery` | The recovery console, a small kernel-task console on the UART. |
| `sched` | `azos_sched` | Tasks and processes, EEVDF fair class, EDF/CBS real-time band, scheduling contexts, futex, seccomp profiles, timer heap, ASIDs, supervisor decisions. |
| `stdrt` | `azos_stdrt` | The runtime under Rust `std` on `*-unknown-azos`. |
| `sync` | `azos_sync` | Spinlocks, queued spinlocks, sleeping locks, wait queues, priority-inheritance futexes, QSBR RCU, lockdep, wait graph. |
| `syscall` | `azos_syscall` | The kernel side of the syscall layer: dispatch, handlers for each family and for `SYS_INVOKE` ops. |
| `topology` | `azos_topology` | The signed static topology: parser, types, admission, `neverallow` assertions, placement, verification. |
| `trace` | `azos_trace` | The kernel event tracer: one lock-free ring per CPU. |
| `wcet-macro` | `wcet-macro` | The `#[wcet(N_us)]` proc-macro for per-function time budgets. |

Source: `crates/core/*/Cargo.toml` and the `//!` header of each `lib.rs`.

## crates/drivers

| Crate (directory under `crates/drivers/`) | What it holds |
|---|---|
| `api` | Class traits for block, console and network devices, and the device-timeout policy. Host-compatible. |
| `base` | The board description (`platform::hw`). |
| `sys` | System devices every image needs: console UART and `kprint!`, the monotonic clock and timer programming, the hardware watchdog, WCET measurement. |
| `soc` | SoC resource frameworks a driver asks of the SoC first: clock tree, reset lines, regulators, pin control, power domains. |
| `dma` | The DMA mapping API (`DmaDomain`) and the domains that need no hardware. |
| `iommu` | IOMMU support behind one interface. |
| `irqchip` | Which interrupt controller a boot uses and who owns each external line. |
| `hwbus` | The runtime hardware bus (device table logic). |
| `bus` | I2C, SPI, CAN, USB host and device controllers, the UART bridge, and the kernel's `hwbus` instance. |
| `pci` | PCI/PCIe enumeration over ECAM, against an injected config space. |
| `dtb` | The flattened device tree parser (`no_std`, no heap). |
| `fb` | The generic framebuffer object fed by whichever source the platform has. |
| `display` | A DC8200 display-controller and HDMI TX framebuffer driver, and a QEMU `ramfb` framebuffer source. The crate's cargo features are `vf2` (DC8200/HDMI body) and `qemu` (`ramfb`); the kernel's `hdmi` and `ramfb` features enable them. |
| `block` | Block device backend selection, SD/eMMC driver, partition table parser. |
| `nvme` | The NVMe wire protocol: encodings and arithmetic only. |
| `virtio` | VirtIO transport (MMIO and PCI) and the block, network and entropy devices. |
| `virtio-proto` | What VirtIO says on the wire, compiled by the `virtio` drivers and by `vmmd`'s device models: MMIO registers, status and feature bits, the split virtqueue layout, the block and network request formats (`no_std`, no `unsafe`). |
| `net` | NIC backend selection and the Ethernet MAC driver. |
| `scsi` | SCSI over USB Bulk-Only Transport, both ends: the CBW/CSW wrappers, the target command set (what a device answers) and the initiator side (the USB mass-storage host driver). |
| `input` | Input devices and what keyboards share. |
| `usb-hid` | The USB HID class driver (keyboards and mice) over the USB host: report descriptor parser, report decoder, authorization. |
| `usb` | The native USB host (Kconfig `USB_HOST`, `USB_XHCI`): the xHCI controller driver, the DWC3 dual-role check, the USB core (enumeration, descriptors, hubs, pipes, hot-plug events), the class-driver interface, the mass-storage and CDC (ACM, ECM, NCM) class drivers, and the `lsusb`-style listing. The kernel half is `kernel/src/boot/usb.rs`. |
| `gpio` | The pin controller and its `Driver` registration. |
| `actuator` | PWM, the motor PID loop and the buzzer's kernel host. |
| `rc-esc` | `azos_robot_drivers`: the ESC outputs for brushless motors (over `actuator`'s PWM) and the RC receiver (SBUS / PPM). |
| `buzzer` | Piezo buzzer chip logic, one source for both placements. |
| `ina219` | INA219 power-monitor chip logic, one source for both placements. |
| `sensor` | INA219, ADS1115 ADC, LD19 LiDAR, range finders, MIPI CSI-2 camera interface. |
| `baro`, `imu`, `gps` | BMP280 barometer, MPU-6050 IMU, NMEA GPS parser. |
| `camera`, `cam-ring` | A virtual camera; the frame class's pool (refcounted buffers, one producer, many readers). |
| `thermal` | The thermal framework's runtime (the part that touches hardware). |
| `power` | System suspend. |
| `tpm` | The TPM 2.0 TIS/FIFO and CRB interfaces and the commands. |
| `rtc` | Real-time clocks behind one `Rtc` trait: goldfish, PL031, MC146818 CMOS, PCF8563 over I2C. |
| `firmware` | A firmware mailbox property-protocol encoder. The crate is a single source file at the crate directory root, which its `Cargo.toml` declares as the library root. |
| `kill-switch` | The physical kill switch: its boot-time report and the task that takes its edges and latches the e-stop. |
| `kit` | What a driver reaches the machine through: the `Mmio`, `PortIo` and `Ticks` traits a driver is written over. |
| `pcspk` | The PC speaker as the buzzer chip logic's PWM channel (8254 PIT channel 2). |
| `virtio-rng` | The virtio entropy device on the virtio-mmio transport. |
| `lx` | The Linux driver compatibility layer (not one crate): `emul/` (the Rust base), `glue/` (the C module built against a pinned Linux tree), and the lists it is checked against: `HOST_ABI` (every symbol the Linux driver server exports to modules), `DEVICE_SOURCES` (the Linux leaf drivers whose ids the hardware bus matches), `FS_EXT4_UNRESOLVED` (the imports of the ext4 module set). |
| `chip_source.rs` | Not a crate: a file `include!`d by the build scripts of `buzzer` and `ina219` to fingerprint their source. |

Source: `crates/drivers/*/Cargo.toml` and each `lib.rs` header.

## crates/fs and crates/net

| Crate | What it holds |
|---|---|
| `crates/fs` (`azos_fs`) | The VFS, FAT32, tmpfs, block cache, page cache, crash log, pstore, and `azvol` (the native volume format with snapshots and per-block authenticated encryption). |
| `crates/net/stack` (`azos_net`) | Ethernet, ARP, IPv4/IPv6, ICMP, UDP, TCP, DHCP, DNS, NTP, IGMP, NAT, packet filter, BSD-style sockets. Polling-based. |
| `crates/net/ethercat` (`azos_ethercat`) | EtherCAT master protocol logic, `no_std`: frame and datagram builder and parser, the slave-side records a master writes, the AL state machine, distributed-clock arithmetic. It owns no socket or clock; the cyclic loop is the caller's. Tested by `tests/host/ethercat-tests`. |
| `crates/net/tftp` | A TFTP client: the protocol state machine and a fetch loop over a caller-supplied UDP socket. Used by the package installer in development builds (`PKG_FETCH_TFTP`). |

Source: `crates/fs/src/lib.rs`, `crates/net/stack/src/lib.rs`, `crates/net/*/Cargo.toml`.

## crates/lib

| Crate (directory under `crates/lib/`) | What it holds |
|---|---|
| `control/flight-math` | The pure flight math (`azos_flight_math`) the flight controller shares with host tests. |
| `control/ahrs` | Attitude and heading estimation (`azos_ahrs`). |

Source: `crates/lib/*/*/Cargo.toml`.

## crates/domains/robot

| Crate (directory under `crates/domains/robot/`) | What it holds |
|---|---|
| `safety-core` | The safety path of the actuation authority: the motor gate (`actuation.rs`), the real-time motor loop (`rt_motor.rs`), flight control (`flight_ctrl.rs`), the transactional control ticks rolled back on a synchronous exception (`txn.rs`). |
| `degrade-policy` | The graded degrade levels and their speed ceilings (leaf crate). |
| `behavior` | The kernel-side robot behaviour: the safety layer (L0), brain-protocol framing, payload drivers, RC policy, the sensor bus and the layer switches the ring-3 engine reads. |
| `sensors` | The sensors the robot extension produces, at the instance numbers the topology's `sensor.<n>` endpoints name. |
| `flight` | Flight controller (mixer, PID, modes); its pure math is `crates/lib/control/flight-math`. |
| `nav` | Waypoints, mission, occupancy grid, obstacle avoidance. |
| `telemetry` | The binary telemetry protocol. |
| `robot` | Robot framework: PID controller, motor control, sensor abstraction. |
| `bench` | Synthetic microbenchmarks for kernel subsystems. |

Source: `crates/domains/robot/*/Cargo.toml`, `config/axes/Kconfig.use`.

## Per-ISA layout

The three ports share one file layout, checked by `tools/lint/arch_layout_lint.py`.
A module is a top-level name in a directory: a `.rs` file, a `.S` file or a
directory of that name.
ISA-only code goes under `ext/`; every arch crate and every entry directory has
one.

### arch/<isa>/src

| Module | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| `api_impl` | yes | yes | no (the contract impls are in `lib.rs`) |
| `cache` | yes | yes | no |
| `cpu` | yes | yes (`cpu/`) | yes (`cpu/`) |
| `ext/` | yes | yes | yes |
| `firmware` | yes | yes | yes (`firmware/`) |
| `fork_regs` | no | yes | yes |
| `fp` | yes | yes | yes |
| `irq` | yes (`irq/`) | yes (`irq/`) | yes (`irq/`) |
| `lat_hook` | yes | yes | no |
| `mmu` | yes | yes (`mmu/`) | yes |
| `platform_impl` | yes | yes | yes |
| `pmu` | yes | yes | yes |
| `seed` | yes | yes | yes |
| `smp` | no | yes | yes |
| `spin` | yes | yes | yes |
| `timer` | no | yes | yes |
| `tlb` | yes | no | yes |
| `trap` | yes | no | yes (`trap/`) |

Where a module is absent, the function lives elsewhere: riscv64 has no
`fork_regs` because its fork snapshot is the trap frame's own `[u64; 32]`
register file (`azos_sched::task::UserRegs`); the riscv64 timer is the
CLINT/ACLINT in `arch/riscv/src/irq/clint.rs` and its secondary-hart start is in
`kernel/src/entry/riscv64/smp.rs`; the aarch64 TLB invalidation is in `mmu` and
`api_impl`, and its trap frame is in `kernel/src/entry/aarch64/mod.rs`; x86_64 has no `cache`
(its DMA is cache-coherent), no `lat_hook` (the masked-window tracer is not built
there), and its `Cpu`, `Interrupts` and `Mmu` impls sit in `lib.rs`.

The one module outside the shared set that sits outside `ext/` is aarch64's
`sysregs.rs` (the system-register accessors).

`ext/` per ISA:

| ISA | `arch/<isa>/src/ext/` |
|---|---|
| riscv64 | `napot.rs` (Svnapot 64 KiB leaves), `pmp.rs` (physical memory protection), `ssqosid.rs` (the `srmcfg` resource-partition tag), `hv/` (H extension primitives) |
| aarch64 | `mitigations.rs`, `sha2_ce.rs` (SHA-256 on the crypto extension), `tlbi_range.rs`, `wfxt.rs`, `hv/` (EL2 primitives) |
| x86_64 | `ap_trampoline.S` (AP real-mode start), `hybrid.rs` (the core type each logical processor reports, for the energy model), `mitigations.rs`, `retpoline.rs`, `splitlock.rs`, `hv/` (SVM primitives, declared at the crate root) |

### kernel/src/entry/<isa>

| Module | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| `mod.rs` | yes | yes | yes |
| `arch_entry.rs` (the `ArchEntry` impl) | yes | yes | yes |
| `boot_hooks.rs` (what the hooks do) | yes | yes | yes |
| `asm/` (`boot.S`, `context_switch.S`, `trap_entry.S`) | yes | yes | yes |
| `board_map.rs` (device windows) | yes | yes | no (memory map comes from the loader and ACPI, `kernel/src/entry/x86_64/ext/limine.rs`) |
| `fp.rs` | no (the riscv64 crate's `fp` and `context_switch.S` save FP state) | yes | yes |
| `irq.rs` | yes | yes | yes |
| `resume.rs` | yes | yes | yes |
| `smp.rs` | yes | yes | yes |
| `trap.rs` | yes | yes | yes |
| `ext/` | `hv.rs`, `zicboz.rs` | `hv_vectors.rs`, `its_route.rs` (PCI MSI routes through the GICv3 ITS, feature `pci`), `pan_patch.rs`, `rpi_mbox.rs` (the VideoCore mailbox as the thermal board object, feature `thermal`), `selftests.rs` | `cpu_init.rs`, `hv.rs`, `hybrid.rs` (core types for the energy model, feature `energy`), `limine.rs`, `thermal_hw.rs` (the thermal board object's MSR and PCI access, feature `thermal`) |

Extra asm files outside the shared set: `kernel/src/entry/riscv64/asm/context_switch_rvv.S` (the
vector-extension variant) and `kernel/src/entry/x86_64/asm/ap_entry.S` (the application-processor
long-mode entry).

Source: `tools/lint/arch_layout_lint.py` (`REQUIRED`), `arch/*/src/`,
`kernel/src/entry/*/`.

## kernel/

| Path | Contents |
|---|---|
| `kernel/src/main.rs` | `kernel_main`, the one entry for all ISAs: its boot sequence, each phase a call into `boot/`, `tasks/` or `smokes/`; the constants and statics the entry asm and the linker scripts share. |
| `kernel/src/boot/` | Boot install steps run in order, one module per subsystem; `early.rs` holds `early_main`; `kernel_main`'s phases are `devices.rs` (Phase 6, with `pci.rs`'s `bring_up`), `persist.rs` (G2), `network.rs`, `security.rs` (D and 16), `robot.rs`'s `bring_up_robot` (17 and G1) and `sched_init.rs` (5). |
| `kernel/src/entry/` | Per-ISA entry code (above); `entry/<isa>/asm.rs` assembles that ISA's asm files. |
| `kernel/src/trap/` | The generic trap layer: `syscall.rs`, `fault.rs`, `irq.rs`, `kernel.rs`, `frame.rs`, `crash.rs`. |
| `kernel/src/tasks/` | Kernel tasks created by `kernel_main`, grouped by subsystem; `create.rs` creates them in its order. |
| `kernel/src/smokes/` | Boot self-tests and feature-gated boot smokes; `mod.rs` spawns them in `kernel_main`'s order. |
| `kernel/src/*.rs` | Single-purpose modules: `panic.rs`, `pstore.rs`, `ktest.rs`, `drv_supervisor.rs`, `irq_thread.rs`, `console_mode.rs`, and others. |
| `kernel/linker-common.ld` | The shared boot-stack sizing, `INCLUDE`d by every kernel linker script. The scripts, one per image family and ISA, are `arch/<isa>/boot/linker*.ld`. Three fragments there are `INCLUDE`d at the end: `image-header-riscv64.ld` (the Linux RISC-V Image header fields), `reloc-riscv64.ld` (the KASLR relocation table of the riscv64 MMU images) and `boot-pa-x86_64.ld` (the physical addresses the x86_64 32-bit boot stage names). |
| `kernel/build.rs` | Linker-script parameters for the translation granule. |
| `kernel/Cargo.toml` | The feature table. Its `default` list is empty: Kconfig supplies the features. |

Source: `kernel/src/boot/mod.rs`, `kernel/src/tasks/mod.rs`, `kernel/src/trap/mod.rs`,
`kernel/Cargo.toml`.

## userspace/

Each program is its own Cargo package (most carry their own `[workspace]`
marker, and the root `Cargo.toml` excludes them) and is built for the target
ISA by the `mk/userspace.mk` rules.

| Directory | Contents |
|---|---|
| `services/` | `compmgr` (component manager), `sh` and `toolbox` (shell and tools), `termd` (terminal server), `namesd` (name server), `logd` (sink of the structured kernel log and the sealed security log), `coreutil` (multicall image of the basic utilities), `ext4d` (read-only ext4 server), `logind` and `sshd` (login service, SSH server), `pkgd` and `pkg` (package installer), `decisd` and `why` (decision server and query), `inputd` (input server), `compositor` (display server and trusted surface), `power`, `tracectl`, `mcpd`, `ptpd`, `audiod` (audio server), `zenohd`, `rpcsrv` and `rpcquic`, `vmmd` (virtual machine monitor), `lxsrv` and `lxrt` (Linux driver server, Linux runtime), `infsrv` (inference broker; its client is the robot engine), `famtools` (four small tool images: behavior, config, flight, ota), and the robot-domain `brain_client` (the ring-3 behaviour engine and brain link) and `reflex`. |
| `drivers/` | Ring-3 hosts of drivers: `buzz_drv`, `ina_drv`, `gpio_drv`, `rng_drv`. |
| `lib/` | Libraries for ring-3 programs: `compose` (the compositor's pixel engine), `compositor`, `decisions`, `inspect`, `names`, `packages`, `power`, `term` (typed objects over IPC); `rpc`, `quic`, `tls`, `zenoh`, `mcp`, `ml`, `ualloc` (hardened allocator), `linux_rt`, `relibc-azos` (overlay for the relibc C library); `coreutils` (the basic utilities, over a `Host` trait), `ext4` (the read-only ext4 parser), `srv` (the ring-3 server runtime), `login` (the `Login` object and the credential the login service checks); `tls-probe` (a rustls client/server handshake run over memory or a stream). |
| `tests/` | Ring-3 test programs: `abitest` and `abichild` (the processes it spawns), `captest`, `ipctest`, `hello`, `uhello` (a minimal `no_std` program over `libsys`), `epsrv`, `syscall_test`, the `lx*` programs (`lxbench`, `lxhello`, `lxmod`, `lxthreads`) and `relibc`. |
| `bench/` | `latbench`, `vsbench`, `vssrv`: ring-3 measurement programs. |

Source: `userspace/*/`, the header of each program's `main.rs`.

## Tests and tools

| Path | Contents |
|---|---|
| `tests/host/` (one `<name>-tests` crate per area, plus `flight-sim`) | One host-side (`std`) crate per area, built with the host toolchain. Most build the real pure modules of a kernel crate with `#[path]` or link the crate itself, against small shims for the target-specific parts. |
| `tests/fuzz/` | Fuzz targets for parsers and decoders: config, dtb, elf, brain-link, fs, gguf, net, sh, topology. |
| `tests/qemu_boot.sh`, `tests/run_all.sh` | The emulator scenario runners. |
| `tools/build/` | What `make` runs while it builds: the Kconfig bridge (`kconfig_to_cargo.py`, `gen_userspace_kconfig.py`), the SDK and user-link helpers, the third-party fetch and builds; `make_help.txt` is `make help`. |
| `tools/gate/` | The gate: `ci_check.sh` (`make ci`), its short tiers `gate_tier.sh` (`make check0`, `make check1`), its row table `gate_rows.tsv` and the helpers its rows run. |
| `tools/lint/` | Checks of the tree and of built images (`make lint`); `tools_layout.py` holds this layout and checks it. |
| `tools/image/` | Disk images, packages, model bundles and their checks; `boot.cmd`. |
| `tools/sign/` | Key generation, signatures and the provisioning records written on a disk image. The keys themselves are not in git: they live in tools/keys/, which every checkout makes for itself. |
| `tools/bench/` | Benchmarks against Linux (`vsbench_compare.sh` and its aarch64 and x86_64 versions). |
| `tools/dev/` | Run, flash, serve and debug by hand: QEMU and guest launchers, UART and TFTP servers, OTA senders, the board farm. |
| `tools/lib/` | The modules the other tools import: `out_dir.py` (the output root) and `azos_tools.py` (the checkout root, and the path to every other tool). |
| `tools/forensic/` | `seclog_verify`, the offline checker of an exported security log. |
| `tools/dev/farm/` | Host-side scripts that run a test kernel on an attached device and read the result from its console; `boot.cmd`, the board's U-Boot script that boots it over TFTP. |

Source: `tests/`, `tools/`.
