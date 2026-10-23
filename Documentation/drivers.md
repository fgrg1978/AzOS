# Drivers

This page describes how hardware reaches drivers: how devices are found and matched, where a driver's code runs, how drivers talk to the rest of the system, what a driver may ask of the SoC, and how DMA and interrupts are handled. The CPU side is in [hal.md](hal.md); drivers that come from the Linux kernel tree are in [linux.md](linux.md).

## Overview

| Piece | Path | Role |
|---|---|---|
| Driver API | `crates/drivers/api` (`azos_drv_api`) | `Driver` trait, `DriverManifest`, `DriverIsolation`, `MmioRange`, the lock-free `Registry`, and class traits for block, console and network devices. Host-testable. |
| Driver base | `crates/drivers/base` (`azos_drv_base`) | The board description (`platform::hw`) and the in-kernel driver registry static. No MMIO of its own. |
| Hardware bus | `crates/drivers/hwbus` (`azos_hwbus`), instance in `crates/drivers/bus/src/hwbus.rs` | Device objects, match tables, bind policy. |
| Enumerators | `crates/drivers/pci`, `crates/drivers/dtb`, `crates/drivers/virtio`, `kernel/src/boot/hwbus.rs` | Find PCI/PCIe functions, device-tree nodes and virtio-mmio windows. |
| Ring-3 driver framework | `crates/drivers/driver_server` | Registry and request queue for drivers that run as user processes. |
| Device interfaces | `crates/core/idl`, `crates/core/devif` | Typed interfaces a driver serves, from one definition. |
| SoC frameworks | `crates/drivers/soc` | Clock, reset, regulator, pin control, power domains. |
| DMA and IOMMU | `crates/drivers/dma`, `crates/drivers/iommu` | Mapping API, bounce decision, cache maintenance, IOMMU units. |
| Interrupts | `crates/core/ipc/src/irq_bind.rs`, `crates/drivers/irqchip`, `kernel/src/irq_thread.rs` | Line ownership, binding to event ports, budgets. |

`Driver` methods all take `&self`: the registry hands out `&'static dyn Driver`, so a driver manages its own interior mutability. `DriverIsolation` names where a driver's code runs: `InKernel`, `UserProcess { tid }`, or `Hypervisor` (reserved). `Registry` holds at most `REGISTRY_MAX_DRIVERS` entries and refuses a second driver of the same `kind`.

Source: `crates/drivers/api/src/lib.rs`, `crates/drivers/base/src/lib.rs`.

## Discovery: the hardware bus

The hardware bus finds devices, gives each a `Device` object and a `Handle`, and binds drivers to them. The logic (`azos_hwbus`) has no arch code, locks or I/O and is host-tested. `azos_drv_bus::hwbus` holds the kernel's static `Bus` and two lookups the capability layer needs. `kernel/src/boot/hwbus.rs` holds what only the kernel can do: the enumerators and the driver registry that turns a table's driver name into a probe call.

A `Handle` is what a `Device` capability names. `BusKind` says which enumerator found a device:

| `BusKind` | Found by |
|---|---|
| `Pci` | A PCI/PCIe function behind the ECAM window (or the legacy port pair). |
| `Dt` | A device-tree node that carries both `compatible` and `reg`. |
| `VirtioMmio` | A populated virtio-mmio window. |

A `Device` record is fixed-size: a `Name`; the `kind`; a `PciId` (bus/device/function, vendor, device id, class) for PCI functions; the virtio device id for virtio-mmio; the `compatible` list (`COMPAT_LEN` bytes, NUL-separated, most specific first) for device-tree nodes; the first register window (`base`, `size`); the first interrupt (`irq`); the DMA reach (`dma_mask`) and coherence (`dma_coherent`); and the device-tree node offset (`dt_node`) the SoC frameworks resolve a device's `clocks`, `resets`, supplies, pin states and power domains from.

### Selectors

One spelling serves the driver id files, the topology's `[device.*]` rows and `mmio.<selector>` grants (`Pattern` in `crates/drivers/hwbus/src/pattern.rs`):

| Form | Matches |
|---|---|
| `pci:VVVV:DDDD` | Vendor and device id, hex, `*` for any |
| `pciclass:CCCCCC:MMMMMM` | Class code (base, sub class, programming interface) and the mask that counts |
| `dt:<compatible>` | A device-tree `compatible` string |
| `virtio:<id>` | A virtio device id, decimal |

`azos_drv_bus::hwbus::resolve` also accepts `<selector>#N` for the Nth match in slot order.

### Match tables

- **Native table.** Every driver crate that owns hardware declares its ids in an `hwbus.ids` file next to its `Cargo.toml`. One line per id: `<driver> <selector> [boot] [if=<KCONFIG_SYMBOL>]`. A line whose symbol is not `y` in `.config` is left out, so a driver the image does not compile claims nothing. `crates/drivers/hwbus/build.rs` turns every `crates/drivers/*/hwbus.ids` into the `NATIVE` table.
- **Linux table.** Ids of Linux leaf drivers, read from their `MODULE_DEVICE_TABLE` by `tools/lx_device_table.py` (see [linux.md](linux.md)), become the `LINUX` table.
- **Overlap checks.** The build fails, naming the ids, if a native pattern overlaps a Linux one or two native drivers claim overlapping patterns.
- **`boot` entries.** Hardware the kernel drives outside the bus (the console UART, interrupt controllers and timers, the PCI host bridge, the firmware framebuffer, the SoC clock/reset/power controllers) is marked `boot`. It binds to a driver that only records the fact, so ring 3 is never handed a window the kernel is using. No policy or topology row can unbind it.

Source ids files: `crates/drivers/{block,display,dma,fb,irqchip,pci,soc,sys,virtio}/hwbus.ids`.

### Binding policy

`HWBUS_AUTOBIND` (Kconfig) selects the `Policy`:

| `Policy` | Behaviour |
|---|---|
| `Auto` | Bind whatever the match tables match. |
| `TopologyOnly` | Detect everything; bind only what a `[device.*]` row of the signed topology admits. A device the tables match but no row admits is `NotAdmitted` and recorded as a decision ("detected, not admitted"). |

`decide` is pure: tables, policy and topology rows in, a `Verdict` out. The order is: a `boot` native entry; then the first topology row whose selector names the device (it may refuse the device, name the native driver to use, or only admit it); then the native table; then the Linux table. A native entry always beats a Linux one for the same device.

A device moves through `State`: `Detected`, `Bound`, `ProbeFailed`, `Unbound`, `NotAdmitted`, `Unmatched`. `Binding` records the owner: `None`, `Native(name)` or `Linux { class }`. A native probe can answer `ProbeError::NoSuchDriver`, `Busy` or `Failed`. `Bus::unbind`, `rebind` and `reconcile` bring bound devices to what the installed signed topology says. A Linux class server is started only once one of its ids matched a device (`Bus::linux_class_wanted`).

Drivers bind in stages, because they depend on each other's order (entropy before PCI bring-up, the disk before the filesystem, the NIC after the scheduler hooks). `bind` takes the drivers one stage wants; `settle` closes the last stage and reports the rest. The boot prints one `[HWBUS]` line per outcome and lists devices in the introspection tree's `devices/`.

### Ring-3 access to a device's registers

`user_window(handle)` returns the register window ring 3 may map for a device (used by `DOMAIN_MMIO_MAP`). It answers `None` for a stale handle, a device with no window, or a device a kernel driver owns or may still take. `claim_user_window` books the mapping so no kernel driver is bound to the device afterwards.

Source: `crates/drivers/hwbus/src/{lib,bus,device,pattern,policy,tables}.rs`, `crates/drivers/hwbus/build.rs`, `crates/drivers/bus/src/hwbus.rs`, `kernel/src/boot/hwbus.rs`, `config/subsys/Kconfig.drivers`.

## Discovery: PCI and PCIe

`azos_pci` is pure logic over an injected `ConfigSpace` trait (no raw pointers, no target assembly, no `unsafe`), so the same code runs under host tests against a fake configuration space. The virtio-pci transport (`crates/drivers/virtio/src/virtio/pci.rs`) is built against the same types.

Scope: one ECAM segment, no ARI, no SR-IOV, no hot-plug, no I/O-space BARs.

| Step | Items |
|---|---|
| Address math | `Bdf`, `ecam_address`, `Bdf::requester_id` (the key IOMMUs and the GICv3 ITS identify a function by) |
| Enumeration | `enumerate_tree` walks bus 0 and the buses behind PCI-to-PCI bridges; `set_bus_numbers` numbers bridges the firmware left unnumbered; `probe_function` / `FunctionInfo` |
| Capabilities | `walk_capabilities` (bounded by `CAP_WALK_MAX_HOPS`), `parse_msi`, `parse_msix`, MSI-X table and pending-bit helpers, `program_msix_entry` |
| BARs | `decode_bars`, `assign_bar` |
| Bridge windows | `place_behind_bridges` sizes the windows of bridges around what sits behind them (`BridgePlan`, `BridgeWindows`) |
| Window resolution | `resolve_bar_window` picks the host-bridge windows and reports where they came from (`WindowSource`, `WindowReport`) |

### Windows, bus addresses and translation

`window.rs` places BARs from the host bridge's windows. Two address spaces meet there:

- **PCI bus addresses** are what the pools hand out and what BARs and bridge windows are programmed with.
- **CPU addresses** are what the kernel maps and a driver dereferences. A host bridge may translate (device-tree `ranges` with `bus != cpu`), so `BarWindow::bar_cpu_addr` is the one way from a bus address to a CPU address.

Two windows exist: the 32-bit window (below 4 GiB; the only place a non-prefetchable BAR can live behind a bridge) and a 64-bit prefetchable window above it, where prefetchable 64-bit BARs go while it lasts. A firmware that states windows (`ranges`) is believed; otherwise built-in defaults apply. A window the kernel's address space cannot map is clipped to that reach, never used blindly. A `Pool` is a bump allocator over one bus-address range; BAR sizes are powers of two and a BAR is naturally aligned. BARs behind bridges whose address was fixed ahead of their driver are held in a bounded reservation table (`MAX_RESERVED`); the overflow is placed on demand.

The device-tree side is `azos_dtb`: `PciHost` describes a `pci-host-ecam-generic` node (ECAM window, I/O, 32-bit and 64-bit memory windows as `PciWindow`, and a DMA mask), `decode_pci_ranges` reads the `ranges` property, and `dma_ranges_limit` reads `dma-ranges` (see [DMA](#dma)).

### SoC host controllers

Some SoC PCIe controllers are not brought up by firmware. `crates/drivers/pci/src/host/` holds the bring-up flow that runs before `enumerate_tree` can see a function. Two controllers: `plda` (PLDA XpressRICH root port plus the SoC's syscon) and `brcmstb` (Broadcom brcmstb root complex). Each follows one flow:

1. Validate the inputs; no register is touched on a refusal.
2. Hold the endpoint in reset (PERST# asserted for `PERST_HOLD_US`) and set root-complex mode.
3. Program the outbound windows (CPU to PCI, from `ranges`) and the inbound ones (PCI to CPU, from `dma-ranges`).
4. Release PERST#, wait for the link, refuse a link that stays down.
5. Return how configuration space is reached (`ConfigAccess`, usable as a `ConfigSpace` through `ConfigPort`), the windows for `resolve_bar_window`, and where MSIs land (`MsiHookup`).

Register access goes through a `Bus` trait, so each sequence host-tests against a trace of reads, writes and delays. Clocks, resets, PHY and regulators are done before `init`, through the SoC frameworks below.

The kernel runs the flow before the enumeration (Kconfig `PCI_SOC_HOST`, `kernel/src/boot/pci.rs`). It finds the bridge on the hardware bus by `compatible` (`starfive,jh7110-pcie`, `brcm,bcm2712-pcie`; `host::dt::Controller`), reads the node through the SoC frameworks' view of the tree (`host::dt`: `reg` by name, `ranges`, `dma-ranges`; for PLDA also the STG syscon, `linux,pci-domain` and `perst-gpios`), gives it its clocks, resets, power domains and `default` pin state with `boot::soc::bind`, maps the register blocks and calls `plda::init` / `brcmstb::init`. The VisionFive 2's PERST# is a pin of the SYS pad controller, driven through the GPIO driver and claimed so the robot GPIO bring-up does not tri-state it later. What the frameworks do not model (the JH7110's PCIe clocks and PHY) is counted in the boot line and left as the firmware set it. A link that stays down is a boot line and no enumeration: the QEMU `virt` ECAM defaults are tried on the `qemu` board only. `KernelConfigSpace` is the enumerated space in every case: an ECAM window, the x86_64 port pair, a brought-up SoC bridge (`ConfigPort`), or nothing. One bridge is brought up; the VisionFive 2's second controller and the MSI routes (`HostReport::msi`) are not wired.

Source: `crates/drivers/pci/src/{lib,window,bridge}.rs`, `crates/drivers/pci/src/host/{mod,plda,brcmstb,dt}.rs`, `crates/drivers/dtb/src/lib.rs`, `kernel/src/boot/pci.rs`, `kernel/src/main.rs` (the PCI bring-up).

## Discovery: device tree and virtio-mmio

`azos_dtb` is a flattened-device-tree parser with no allocation and no dependencies. It rejects a blob whose `totalsize` is below the header size or above a hard cap before walking it. It yields `DtbInfo` (what the kernel needs to configure itself) and, for the hardware bus, `DtDevice`: an enabled node with `compatible` and `reg`, its first interrupt, its depth, its DMA reach (`dma_mask`) and whether it or an ancestor carries `dma-coherent` (`dma_coherent`; `false` means "nothing declared"). It also decodes the energy, thermal and CPU-topology nodes the other frameworks consume, and the interrupt-controller trigger types (`IrqController`, `IrqTriggers`).

Virtio devices appear either as populated virtio-mmio windows (the transport reports the device id; selector `virtio:<id>`) or as PCI functions (modern ids, selector `pci:1af4:...`). `azos_drv_virtio` provides both transports and the block, network, entropy, input, GPU and sound devices; the block and network class crates select a virtio backend through the class traits in `azos_drv_api`.

Source: `crates/drivers/dtb/src/lib.rs`, `crates/drivers/virtio/src/`.

## Placement: kernel or ring 3

A driver's chip logic can be written once and hosted in two places: in the kernel, called directly in the caller's context, or in a ring-3 process behind the kernel's driver proxy.

**The ring-3 path.** A ring-3 task registers as the driver for a hardware kind (`DOMAIN_DRIVER_REGISTER`, with a capability). A typed hardware call whose driver runs in ring 3 becomes a `DriverRequest` (`azos_drv_sys::user_driver_proxy`), is queued by `driver_submit_request`, and the client blocks until the reply is published. The driver loops on `DOMAIN_DRIVER_REPLY_WAIT`, which publishes a reply and waits for the next request in one call. Hardware interrupts reach the driver through `driver_signal_irq` and the driver loop's fetch. Two Kconfig knobs shape the proxy: `PROXY_SPIN_US` (how long a client polls before it blocks, only while the driver runs on another hart) and `PROXY_REPLY_TIMEOUT_MS`.

**Choosing the host.** A driver that exists in both hosts has a placement choice in `config/subsys/Kconfig.drivers` (`DRV_INA219_PLACEMENT`, `DRV_BUZZER_PLACEMENT`; `DRV_RING3_DEFAULT` sets the starting value of every such choice to `ring3`). The signed topology can also say it, in the driver's row:

| Row key | Meaning |
|---|---|
| `place = "kernel" \| "ring3"` | The host the driver starts in (`Host`); `ring3` unless declared. |
| `stateless = true` | The driver keeps nothing a restart cannot rebuild from its row and the device; only such a row may move between hosts at run time. |
| `call_budget_us = N` | The time one call may take from the caller's side; 0 declares none. |

At run time `azos_topology::placement::Elastic` decides moves and `Elastic::commit`, the one place the host changes, writes a `Rule::Placement` decision record. A stateless driver whose kernel host faulted is served from its ring-3 host, which the component manager started at boot and keeps up (the controller routes calls and never starts or ends a ring-3 host; it hands the PWM channel over with each move, and the kernel's `Pwm` service refuses the ring-3 host's writes to the buzzer's channel while the kernel host holds it). A stateless driver with a `call_budget_us` whose ring-3 calls break the budget moves into the kernel, if the kernel host's measured cost fits and it has not faulted within the hold-off; a refusal is recorded too (`DRV_BUZZER_CALL_BUDGET_US` is the build-time value for the buzzer row).

**Drivers a safety decision reads have no placement choice.** The closed rule in `config/subsys/Kconfig.drivers` is that a driver a safety decision reads always runs in the kernel. `tools/kconfig_to_cargo.py` enforces it: it refuses a `.config` that sets `CONFIG_DRV_<NAME>_PLACEMENT_RING3=y` for any name in `SAFETY_READ_DRIVERS` (`CLINT`, `PLIC`, `WDT`, `PWM`, `GPIO`, `MOTOR`, `MOTOR_PID`, `ESC`, `RC`, `I2C`, `IMU`, `RANGEFINDER`, `ADS1115`, `UART`, `VIRTIO_BLK`, `MMC`).

Ring-3 driver programs in the tree: `userspace/drivers/gpio_drv` (`GPIODRV.ELF`, which registers for the GPIO driver kind, answers proxy requests and serves the device-power interface), `userspace/drivers/buzz_drv` (`BUZZDRV.ELF`) and `userspace/drivers/ina_drv` (`INADRV.ELF`). The latter two host the chip logic of `crates/drivers/buzzer` and `crates/drivers/ina219`; their kernel hosts are in `crates/drivers/actuator` and the kernel feature `ina219-kernel`. A ring-3 driver that serves the device-power interface keeps a wakelock ledger (`DEVICE_WAKELOCKS`, `DEVICE_WAKELOCK_TTL_MAX_MS`).

Source: `crates/drivers/driver_server/src/lib.rs`, `crates/drivers/sys/src/user_driver_proxy.rs`, `crates/core/topology/src/placement.rs`, `config/subsys/Kconfig.drivers`, `tools/kconfig_to_cargo.py`, `userspace/drivers/`.

**A kernel-placed controller that stops answering** follows one policy (`azos_drv_api::recovery`, owner decision 2026-10-23): a block command past its budget (virtio-blk, NVMe, AHCI), a NIC transmit ring whose announced frames the device takes none of for `NET_TX_TIMEOUT_MS` (virtio-net on both transports, e1000e, igc; Linux's netdev watchdog default, 5 s) or an xHCI command left unanswered for its second makes the driver stop the device, confirm the stop, and program it again over the same memory, `DEVICE_TIMEOUT_RESETS` times per boot (default 1). The next timeout latches it dead until reboot. A block command the reset abandoned fails with `HwStatus::Reset` and is not retried; a NIC drops the frames in its ring; an xHCI controller (halted, HCRST, Controller Not Ready clear, DCBAA, command ring, event ring and scratchpads given again) forgets every device, so the USB core removes each one (its transfers end `Disconnected`, its class drivers are told) and enumerates the ports again, and a class driver sees its device go away and come back with a new generation. The block and NIC budgets are measured in time the guest ran (`StallClock`); a NIC ring that holds frames is looked at by every send and by the network poller every `TX_LOOK_US` (25 ms), so the stall clock never takes the gap between two seldom sends for a stopped guest. Every reset and latch is a `block-timeout` / `net-timeout` / `usb-host-fault` decision record (`action` 2 reset, 5 latched with its resets spent, 6 the reset did not bring it back). A host system error or host controller error an xHCI controller reports (USBSTS.HSE, USBSTS.HCE) takes the same policy as a timeout (owner decision 2026-10-23): one reset, shared with the timeouts, then the next fault of any cause latches it; the record carries the cause (`azos_usb::xhci::Fault`). The SD/eMMC hosts reset on every failed command (`mmc.rs`: the SDHCI command and data lines; `dwmshc.rs`: the controller, FIFO and DMA) and never latch, so the policy has nothing to change there. Kconfig CHAOS injects each timeout for the gate (`nvme-completion-drop`, `virtio-net-tx-wedge`, `xhci-command-drop`, `crates/core/chaos`): `chaos=<point>:1:1` once (the rows `... timeout resets once`), `chaos=<point>:1` every time (`... second timeout latches`).

## Device interfaces

A device is not a syscall number and not a capability kind. A task that may read a pin or command a wheel holds an `Endpoint` capability whose badge names the resource and whose rights (`READ` observes, `WRITE` acts, `EXEC` controls) are the op classes it may use. The call is `ipc_call` on that endpoint with a request in the IDL's wire form. The kernel serves the interface itself for a driver it hosts (a kernel-hosted endpoint, `azos_ipc::endpoint::kernel_host`); a ring-3 driver serves the same trait from its own endpoint; the client stub does not know which.

**IDL.** An interface is a Rust trait annotated `#[azos_interface(id = N, level = L)]`. One op table generates:

| Generated item | Role |
|---|---|
| `<Name>Client<T: Transport>` | Endpoint-call stub: packs arguments into a `MsgDesc`, calls the transport, unpacks the reply |
| `<Name>Idl::dispatch` | Server dispatcher: decodes the op and arguments, calls the implementation, encodes the reply |
| `<Name>Direct<S>` | Direct-call stub: the same call in process with no message (the kernel-host placement) |
| `<Name>Call` | The caller's trait, implemented by both stubs, so users do not know where the implementation is placed |
| `<Name>Idl::OPS` | The op table (`OpInfo` per method) |

Wire form: word 0 is the header (`id << 32 | level << 16 | op`), then each argument in order (a scalar is one word, an array its elements, a `Cap<T>` one capability entry with mode MOVE, a `Lent<T>` a presence word and, when present, one DUP entry with explicit rights and a deadline). The reply's word 0 is the status (0 served, otherwise an `IdlError` status), then the return value. Op numbers count from 1 in trait order; op 0 is never valid. A server serves a request whose level is at most its own (`IdlError::LevelTooNew` otherwise).

The macro enforces at compile time: shapes fit the inline words and the capability entries; at most one of `#[idempotent]`, `#[at_most_once]`, `#[once_only]` per method; the failure contract `#[on_failure(degrade | safe_state | restart | escalate)]`, `#[deadline_ns = N]`, `#[budget_us = N]` (a `#[once_only]` op must declare `on_failure`); and a lint against integer file descriptors, `errno` and text or paths as authority. Every op answers with a typed outcome (`azos_devif::outcome::Out`), never an `errno`.

**Registry.** `azos_devif::IFACES` lists every interface the kernel can host. The `name` is the word a topology row uses (`endpoint = "gpio.17"`), followed by a resource spelling that becomes the badge.

| Interface (`name`) | Resource spelling |
|---|---|
| `entropy`, `linkkey`, `power`, `flight`, `behavior`, `config`, `ota`, `time`, `clock`, `net`, `memctl`, `keys` | none |
| `gpio` | pin number |
| `i2c` | `<bus>.<address>` |
| `spi` | `<bus>.<chip select>` |
| `pwm` | channel |
| `motor` | wheel |
| `sensor` | sensor type |
| `block` | `part.<n>` (partition `n`) |
| `can` | controller |
| `uart` | port |
| `adc` | channel |
| `vm`, `vcpu` | `<n>`, `<n>.<k>` |

The buzzer interface (`azos_devif::buzzer`) is outside this registry; the buzzer driver serves it from its kernel host (called directly) or from `BUZZDRV.ELF`.

Source: `crates/core/idl/src/lib.rs`, `crates/core/idl-macros/src/lib.rs`, `crates/core/devif/src/lib.rs`.

## USB host

The USB host is native (Kconfig `USB_HOST`, `USB_XHCI`, `USB_DWC2`; not on a small board, `HWCLASS_EMBEDDED`). `crates/drivers/usb` (`azos_usb`) is pure `no_std`: it reaches the machine only through three traits (`Regs`, `Memory`, `Clock`), and `tests/host/usb-tests` runs the whole flow against a register-level xHCI mock with a tree of fake devices and hubs. The kernel half is `kernel/src/boot/usb.rs`.

| Layer | What it does |
|---|---|
| `xhci` | The controller: capability, operational and runtime registers; the command ring; the event ring of interrupter 0 with Event Handler Busy; transfer rings with Link TRBs and the cycle bit; scratchpad buffers (the split Max Scratchpad Buffers field); the device context base array; 32- or 64-byte contexts (HCCPARAMS1.CSZ); port status change handling. DMA memory is one arena allocated under the device's limit (the DMA mask, narrowed to 32 bits when AC64 is clear) and mapped once through its `DmaDomain`; a transfer buffer a class driver supplies is checked against the same limit and refused (`Status::Bounce`), not bounced, and TRBs are split at 64 KiB boundaries. |
| `dwc2` | The DesignWare USB 2.0 OTG core in host mode (Kconfig `USB_DWC2`; the Raspberry Pi's `brcm,bcm2835-usb`, `brcm,bcm2708-usb`, `snps,dwc2`), buffer DMA, polled. It presents the xHCI driver's model in software, so the core above it is the same one (`usbcore::hc::Hc` holds either controller): `HPRT0` read as PORTSC (a disconnect and the end of a software-timed port reset become change bits), a slot is a USB address set by the driver's own SET_ADDRESS, each endpoint a queue of descriptors whose head gets a host channel, which runs its stages (setup, data, status) or its data split by the channel's size and packet-count limits, with the data toggle read back from `HCTSIZ`; completions carry xHCI codes. The partial last packet of an IN goes through the channel's bounce page and is copied through `Memory::cpu_of`, so a device that sends more than asked is babble, never an overrun. Not done: split transactions (a full- or low-speed device behind a high-speed hub is refused at its address), isochronous and high-bandwidth endpoints, OTG. `tests/host/usb-tests` (`dwc2`) runs it against a register-level DWC2 mock over the same fake devices. |
| `usbcore` | Enumeration (debounce, port reset, Enable Slot, Address Device, descriptors, BOS, strings, SET_CONFIGURATION), descriptor parsing (`desc`: device, configuration, interface, endpoint, SuperSpeed companion, BOS, hub), hubs (USB 2 and USB 3: hub depth, port power, the status-change endpoint, port reset, route strings, the transaction translator fields), hot-plug events (a `Queue` of `UsbEvent`), pipes: control, bulk, interrupt and isochronous IN (a transfer on an isochronous pipe is one service interval, queued as an Isoch TRB with its burst fields; the endpoint of any alternate setting opens by naming the setting in bits 15:8 of `pipe_open`'s argument, from the table of every setting's endpoint that `desc` keeps; a lost interval completes with its code and does not halt the endpoint). |
| `class` | The class-driver interface: two IDL interfaces, `UsbClass` (served by a class driver: `attach`, `detach`) and `UsbDevice` (served by the core for one claim: `info`, `endpoint`, `pipe_open`, `pipe_close`), the `Claim` a driver holds, and the `Registry` of drivers and match rules. |
| `listing` | The first class driver: a watcher on every device whose rows the kernel publishes as `usb/devN/{present, slot, vendor, product, class, subclass, protocol, speed, root_port}` in the introspection tree (no procfs). |
| `class::msc` | The mass-storage class driver (Kconfig `USB_STORAGE`): Bulk-Only Transport and SCSI (`azos_scsi`: INQUIRY, TEST UNIT READY, READ CAPACITY(10), READ/WRITE(10), SYNCHRONIZE CACHE(10), REQUEST SENSE) over the pipes of one claim, one command at a time, with the stall and CSW recovery of BBB 6.6/6.7. Pure; `block/src/usb_msc.rs` wraps it as an `HwQueue` with a request queue of its own (the stick never becomes the boot disk). A UAS interface (protocol 0x62) is detected and declined; a transport error or a command over `USB_MSC_TIMEOUT_MS` fails the disk until it is unplugged (Reset Recovery is not implemented). |
| `class::cdc` | The communications class drivers (Kconfig `USB_CDC`): CDC-ECM and CDC-NCM (NTB-16, with the device's alignment, divisor, remainder and size limits) as a NIC, and CDC-ACM as a `Uart` (SET_LINE_CODING, DTR/RTS on attach, bytes as chunks). A function is two claims (the communications interface, then its data interface, checked against the union descriptor); ECM and NCM select the data interface's alternate setting that has endpoints. Receive buffers are held until the stack has taken their frames, so the device is flow-controlled by the stack; no zero-length packets are queued, so a transmission that fills its last packet is padded by one byte. `net/src/usb_net.rs` wraps the network function (this one or `class::smsc95xx`) as a `NetDevice` behind one lock and `net_device::register_usb` puts it in the NIC table when it is ready; `kernel/src/boot/usb.rs` registers it, drives it from the `usb` task, gives the stack an interface (`net_nic_added`) and wakes the network poller when frames wait. One network function at a time. The serial function (CDC-ACM, `CdcAcm`, a `Uart`) is a port of the kernel's `Uart` table (`crates/core/syscall/src/devices.rs`): `kernel/src/boot/usb/serial.rs` puts it behind a sleeping lock as a `SerialLine`, and when the function is ready the `usb` task offers it with `plug_line` as `uart.2` (the table is the companion-radio bridge's `uart.1` plus the plug slots, one for now because the class driver serves one serial function), and withdraws it with `unplug_line` when the device goes, which drops whatever was attached. A task whose topology row grants `uart.2` attaches its queues exactly as on `uart.1` (an unplugged port answers `NO_RESOURCE`); the table's spin lock is never held while a line works (every op copies the line out, runs on the copy and publishes only if the slot is still the one it started from). With Kconfig `USB_CDC_CONSOLE` the kernel holds `uart.2` itself with a client that has no queues (`attach_client`, `CdcAcm::attach_kernel`): the console's output (a tap behind the same hook point as the framebuffer mirror, `uart::set_console_tee`, copying into a ring without waiting) goes to the device with CR LF, and the device's bytes enter the console's RX ring (`rx_push`) like a keyboard's, so a PC or a board with no UART has a console over USB; a task cannot take or end the kernel's hold. QEMU cannot exercise it (`-device usb-serial` is an FTDI adapter, which no class driver claims, not CDC-ACM): the protocol, the kernel hold and the unplug are covered by `tests/host/usb-cdc-tests` over the xHCI mock, the table by `tests/host/syscall-tests` (`h3_hosts`), and the whole path needs a board or a PC with a CDC-ACM gadget (`g_serial`, a Pico or an ESP32-S3 USB-CDC) in the testing week. Sizes: `USB_CDC_BUFS`, `USB_CDC_NTB_KB`, `USB_CDC_CONSOLE_BYTES`; the console's line rate is `USB_CDC_CONSOLE_BAUD`. |
| `class::smsc95xx` | The SMSC LAN95xx Ethernet function (Kconfig `USB_SMSC95XX`; the Raspberry Pi 3 B's, behind the LAN9514's hub): the chip's registers through two vendor requests (the core lets the holder of a device's only interface send vendor requests to the device), a setup script (lite and PHY resets waited for, the MAC address, multi-frame bulk-in with a burst cap of one buffer, LEDs, all multicast, the PHY autonegotiating 10/100 with pause, then transmit and receive), bulk-in bursts of frames with status words, one frame per bulk-out transfer after its command words (one byte of Ethernet padding when the transfer would end on a packet boundary). It and the CDC network function are `class::net::NetFunction`s, the one shape `net/src/usb_net.rs` makes a NIC of. The MAC address is the device tree's `local-mac-address` of the `usb424,ec00` node, else a locally administered random one. `tests/host/usb-cdc-tests` (`smsc`) runs it against a fake chip. |
| `class::uvc` | The USB video class driver (Kconfig `USB_UVC`): a UVC 1.0/1.1/1.5 camera as the producer of the camera frame ring (`azos_cam_ring::FrameSink`). It walks the class-specific descriptors (video control header, streaming input header, MJPEG and YUY2 formats and frames, the endpoint of every alternate setting), picks Motion-JPEG over YUY2 and the frame and interval closest to the wanted size and rate (a Motion-JPEG frame larger than the one wanted only if the camera bounds it under what one brain-link camera packet carries; else the raw format, else the camera is failed `NoFormat`), negotiates with PROBE/COMMIT (26 or 34 bytes by `bcdUVC`), and streams only while the ring has a reader: COMMIT, the pipe of the smallest isochronous setting that carries `dwMaxPayloadTransferSize` (or the bulk endpoint), `PIPE_DEPTH` transfers outstanding. A frame is the payloads between two FID toggles (or up to EOF) appended to a slot of the ring and committed only if whole: a payload with the error bit, a lost interval, a stream that began mid-frame a frame longer than the slot or a JPEG longer than a camera packet carries drops that frame (counted as `oversize`; `camera_packet` counts and says once a JPEG it cannot send, and states the JPEG's own size in the header). One camera, no still images, no H.264, no camera controls; a high-speed isochronous camera needs `USB_PIPE_DEPTH` 32 and the `usb` task napping 1 ms (the default with this driver), and what a board sustains is a test-week measurement. `kernel/src/boot/usb.rs` wires it, `kernel/src/tasks/cam_capture.rs` stands the CSI task down while a camera is the source and converts raw YUY2 frames to the link's JPEG when the sender reads them. |

**Pipes carry data; calls carry authority.** A pipe is a pair of `Queue` rings: the class driver pushes `Transfer { tag, dir, setup, buf, len }` and pops `Completion { tag, status, actual }`; `buf` is a bus address of a buffer the driver owns. The ring depth (`USB_PIPE_DEPTH`) is the most transfers a driver may have outstanding. No Linux URB exists, and no class driver or syscall number is added: new functions are IDL interfaces on endpoints, so a class driver is placed in the kernel or in ring 3 and the core does not know which.

**Confinement.** A driver holds a claim on one interface (`slot << 24 | interface << 16 | generation`; the generation is bumped at each enumeration of the slot, so a claim kept past an unplug names nothing). Through it a driver can open only the endpoints of its interface, and send only the control requests that address its interface or its endpoints, plus the standard reads every driver may make. Class and vendor requests to the device or to a hub port, SET_CONFIGURATION and the other device-wide standard requests are the core's, except a vendor request to a device (not a hub) whose only interface the claim holds: the function is then the whole device, and vendor functions (a USB Ethernet chip's registers) are reached that way.

**USB HID (Kconfig `USB_HID`).** `crates/drivers/usb-hid` (`azos_usb_hid`, no unsafe code, no allocation) is the first class driver that moves data: keyboards and mice, so a PC with no UART and no PS/2 has a console. `HidClass` registers for every interface of class 3 and, after each `Usb::service`, advances each claimed interface: it **authorizes** the device, reads the interface's report descriptor through the control pipe, parses it, sends `SET_IDLE(0)`, and keeps four interrupt IN transfers queued in one DMA page it allocates per interface (no call per report). The parser (`report`) is the HID 1.11 item machine: usage page, logical range, report size/count/ID, push/pop, usage ranges and lists, extended usages, long items skipped; it keeps the fields it can name, a key (keyboard page, as a run of bits or an array of usages), a button, a relative or absolute axis (X, Y, wheel, AC Pan), and only under the application collection they belong to (a gamepad's axes are nobody's). The decoder keeps the keys and buttons down per report ID, so a bitmap, an array of six and a mix are all diffs: within one report modifiers go first, then releases, then presses (Shift and `a` together are `A`); a report full of ErrorRollOver changes nothing; axes are sign-extended; absolute positions are scaled to `0..=ABS_MAX`. A device that does not give its descriptor and is a boot keyboard or mouse (subclass 1) is asked for the boot protocol (`SET_PROTOCOL(0)`) and read with the appendix-B layouts, parsed by the same parser. A USB keyboard repeats nothing in hardware: the key held repeats after `USB_HID_REPEAT_DELAY_MS` every `USB_HID_REPEAT_PERIOD_MS`. The driver emits `(type, code, value)` to a `Sink`; the kernel's (`kernel/src/boot/usb_hid.rs`) runs each key through `azos_drv_input::keymap::route` and ends where PS/2 and virtio-input end: a console byte in the UART's RX ring, or a packed event in the ring the terminal server drains. Pushing is done with interrupts masked on the hart (the other producers run in interrupt context; the `usb` task does not), and the console's parked reader is woken afterwards. Not driven: LEDs (Caps Lock is a software state), consumer-page keys, gamepads and touch digitizers, output reports.

**virtio-sound (Kconfig `DRV_VIRTIO_SND`).** `crates/drivers/virtio/src/virtio/snd.rs` (wire format in `snd_proto.rs`, against virtio 1.2 section 5.14) drives the sound device on virtio-mmio (`virtio:25`) and on PCI (`pci:1af4:1059`, one MSI-X vector for the control, transmit and receive queues). Bring-up reads the jacks, the PCM streams and the channel maps and picks a run point (48 kHz when the device has it, else the best below, else the lowest above; the channel count is the stream's); a request on the control queue is waited with `DeviceWait`'s pattern, bounded. A period is a three-descriptor chain (the `xfer` header, the samples in the client's arena, the status), so the samples are never copied; the arena is a `Contig` memory object the kernel pins for the stream's life, which is why `SYS_MO_CREATE` takes the kind `SHM_KIND_CONTIG` from ring 3 (frames charged to the creator's Domain). `stop` is STOP, RELEASE and PREPARE, so every period in flight comes back flagged cancelled; a capture drain keeps the short period; an xrun is counted and flagged on the next period. The interrupt handlers take no lock and only wake the device pump (`dev-pump`, `crates/core/syscall/src/devices.rs`), which in task context reaps the used rings and moves the periods between the driver and the client's `ready` and `done` queues (`sound_host.rs`). The client side is the kernel-hosted `Sound` interface on the endpoint `sound.0` (`azos_devif::sound`): `open` takes the two queues and the arena, `start`, `stop`, `drain` and `close` change what the stream may do, and the samples never cross a call. A capture stream needs `AUDIO_CAPTURE` and the `mic` effect of the requester's class (the caller's, or, through the audio server, the client's) and writes an `audio-capture` decision naming the requester. The toolbox's `beep [MS]` plays a 440 Hz tone through it and prints how many periods came back played; its row (`TOOLBOX.ELF`) holds `READ|WRITE` on `sound.0` only in a build with the device. Not driven: control elements (volume, mute), hot-plugged jacks, a second device, any format outside signed 16, 24 (in 32), 32-bit and float 32.

**Authorization.** A device names its own class, so the driver does not bind to what it claims to be: `authorize::decide` answers from the build's policy (`USB_HID_ADMIT`, `USB_BIND_MAX_TIER`, `USB_HID_REFUSE_COMPOSITE`) and the core's facts about the device, in this order: no row admits the class (1), the device hangs below more hubs than trusted (2), the device also has a storage, communications or wireless interface (3); otherwise 0. Every answer is a decision record of the rule `usb-authorize` (subject: the root port; numbers: vendor/product, the interface's class triple, the reason), a refusal is also a durable receipt, and a refused device is not spoken to. The hardware bus's `[device.*]` rows cannot select a USB device yet (their selectors are PCI ids, device-tree names, virtio ids), so there is no signed per-device row: a build whose bus binds only what its topology admits defaults `USB_HID_ADMIT` to n.

**What is not here yet.** UAS, more than one serial function (the table has one plug slot), DHCP and address configuration for a secondary interface that comes with a USB adapter, the interface registry entry and capability minting for `UsbClass`/`UsbDevice` over endpoints (ring-3 placement), the MSI-X route for interrupter 0 (the `usb` task polls every `USB_POLL_MS`), isochronous OUT endpoints, streams, USB 3 link power management, and a second controller.

Source: `crates/drivers/usb/src/`, `crates/drivers/usb/hwbus.ids`, `crates/drivers/usb-hid/src/`, `crates/drivers/scsi/`, `crates/drivers/block/src/usb_msc.rs`, `crates/drivers/net/src/usb_net.rs`, `kernel/src/boot/usb.rs`, `kernel/src/boot/usb_hid.rs`, `config/subsys/Kconfig.usb`, `tests/host/usb-tests/`, `tests/host/usb-hid-tests/`, `tests/host/scsi-tests/`.

## SoC resource frameworks

`azos_soc` is what a driver asks the SoC for before it can touch its device. Five frameworks share one shape: a provider (the hardware half: registers, no reference counts) and a manager (the policy half: resolves the consumer's phandle properties, counts users, walks the parent chain, commits every change as an effect).

| Framework | Consumer property | Provider trait | Manager |
|---|---|---|---|
| Clock tree | `clocks` / `clock-names` | `clk::ClockOps` | `clk::ClockTree` |
| Reset lines | `resets` / `reset-names` | `reset::ResetOps` | `reset::Resets` |
| Regulators | `<name>-supply` | `regulator::RegulatorOps` | `regulator::Regulators` |
| Pin control | `pinctrl-names`, `pinctrl-N` | `pinctrl::PinctrlOps` | `pinctrl::Pinctrl` |
| Power domains | `power-domains` / `power-domain-names` | `pd::PowerDomainOps` | `pd::PowerDomains` |

Behaviour of each manager, from the module documentation:

- **Clocks** are reference-counted, gated parents first on the way up and children first on the way down. Each clock has at most one parent, local (`Parent::Local`) or one of the controller's inputs (`Parent::Input`, resolved by `ClockTree::link`).
- **Resets** have one owner at a time; the manager keeps no count.
- **Regulators** hold reference-counted enables and voltage requests held to the node's `regulator-min-microvolt` / `regulator-max-microvolt`; `regulator-always-on` rails are switched on at boot.
- **Pin control** applies a named state (a list of configuration nodes) through the nearest registered pad controller; a state is not transactional.
- **Power domains** are reference-counted: the first user powers the domain on and the last powers it off. Domains do not nest.

The consumer lookup (`consumer`) returns the provider node and argument bytes; the argument cell count is the provider's `#clock-cells`, `#reset-cells` or `#power-domain-cells`. `fdt` is a bounds-checked read-only view of a device tree for boot-time probing. `fixed` holds the register-less providers (`fixed-clock`, `regulator-fixed`); `jh7110` holds the StarFive JH7110 clock, reset and power-management providers. `boot` scans a tree into provider slots (`Storage::scan`) and registers them with the managers (`Soc::build`). Register access is one trait, `Bus` (`read32` / `write32` over physical addresses); there is no allocator, no lock and no static, and every operation takes `&mut`.

### Changes are recorded effects

A clock, reset, rail, pin-mux or power-domain change is an `Effect` (`kind`, `op`, `class`, `provider`, `id`, `value`). The manager hands the effect to an `EffectSink` before it touches a register; a refused effect leaves the hardware alone. The order is structural: no manager calls a provider's hardware op except through the internal `issue` function.

| Class | Applies to | On a sink that cannot record |
|---|---|---|
| `Safe` | A change toward quiescence: gate a clock, assert a reset, cut a rail, power a domain off | Goes ahead anyway |
| `Reversible` | Everything else | Refused (`Error::Refused(receipt)`) |

`Op` values are `Enable`, `Disable`, `SetRate`, `Assert`, `Deassert`, `SetVoltage`, `SetMux`, `SetBias`, `PowerOn`, `PowerOff`; the kinds on the wire are `KIND_CLOCK` (2) to `KIND_POWER_DOMAIN` (6). The kernel's sink, `GateSink` in `kernel/src/boot/soc.rs`, forwards to the write-ahead effect gate (`azos_actuation::effect_gate::record`), which commits the record to the flight recorder's ring before the register write, and refuses a change the ring cannot hold unless it moves toward quiescence. For that reason cargo feature `soc` depends on `effect-gate` (Kconfig `EFFECT_WRITE_AHEAD`; the frameworks themselves are `SOC_FRAMEWORKS`).

The kernel builds the managers once at boot from the device tree: one leaked allocation holds the providers, the managers sit behind one lock, provider register windows are mapped there, and nothing is written to hardware until a consumer asks. The controllers' windows are claimed by the hardware bus as the kernel's (`crates/drivers/soc/hwbus.ids`, driver `soc`). `crates/drivers/thermal/src/soc.rs` implements a CPU clock over the clock framework, and the kernel's thermal task is its consumer on the VisionFive 2.

**The consumer.** `bind::bind(soc, fdt, bus, fx, node)` gives a device what its node names, in this order: `power-domains` powered on; `assigned-clock-rates` applied to `assigned-clocks` (a `0` rate is left alone); every `clocks` entry enabled; every `resets` entry deasserted; the pin state named `default` (`Pinctrl::select`). Each step is the manager's own, so each is a recorded effect that reaches the sink before its register. The tree is read first, so a malformed list or an out-of-range specifier fails the bind before any hardware is touched. A failure unwinds what was done, newest first, with the quiescent operations (power off, clock disable, reset assert), which the sinks never refuse; a clock rate and the pin mux are not undone, because the frameworks have no inverse. An entry whose provider the image does not have (`NoProvider`) is skipped and counted in `Applied::unmodelled`: the firmware left it as it is. `bind::unbind` recomputes the same lists and reverses them (the `sleep` pin state if the node names one, resets asserted, clocks disabled, domains off). A node without any of the properties, such as QEMU `virt`'s `ns16550a`, binds to nothing.

Only a native kernel driver is a consumer. The hardware bus calls `Drivers::resources` before it asks a native driver to `probe` a device that carries a node, and `Drivers::release` after a failed probe or a successful `remove`; the kernel's registry (`kernel/src/boot/hwbus.rs`) answers with `boot::soc::bind` / `unbind`. A Linux class server and a ring-3 driver never reach it: they request through their device interface. The `boot` hardware (console, interrupt controllers, these controllers) is brought up before the frameworks exist and is not a consumer. There is no boot-time pass over the tree. Today no device that reaches this path has a node with these properties on the QEMU images. On the VisionFive 2 the GPIO (the sys pin controller), I2C, PWM, watchdog, DMA controller and temperature sensor are consumers: each has an `hwbus.ids` row (`boot`, so no policy or topology can take a kernel-driven controller away), the probe arm maps the node's `reg` and hands the base to the driver's `attach` (`gpio_attach`, `pwm_attach`, `i2c_attach`, `wdt_attach`, `dma_attach`; `azos_drv_base::window` keeps it), and a tree without the node leaves the driver absent, not failed. Order in `kernel_main`: the safety-read ones (`gpio`, which carries the e-stop line, and `wdt`) bind right after the SoC frameworks are installed and before any task exists; `i2c` (bus numbers in tree order), `pwm`, `dmac` and `sfctemp` bind with the robot hardware; on a Raspberry Pi the VideoCore mailbox (`rpi-mbox`, `brcm,bcm2835-mbox`) binds there too. `sfctemp` and `rpi-mbox` are the thermal task's sensors (`kernel/src/boot/thermal.rs`), which keeps their windows. The `gpio` driver shares the pad controller's window with the SoC pinctrl framework, which owns that node's clock, reset and pin state, so the bus does not ask for them again. On the SpacemiT K1 the I2C controllers (`spacemit,k1-i2c`) bind the same way (`hwbus.ids`, `boot`, `if=BOARD_K1`) and are the only K1 controllers with a native driver so far; a controller's clock and reset belong to the APBC controller, which has no provider in the SoC frameworks (the bind skips them as unmodelled), so they are the firmware's. The microSD controller (`starfive,jh7110-mmc`, a Synopsys DesignWare MSHC; the `dw-mshc` driver, `azos_drv_block::dwmshc`) is a consumer too: its row is `boot`, it binds in the stage right before the block device is brought up, and its probe arm reads the node's interrupt, `fifo-depth` and the rate of the `ciu` clock the bus has just enabled (a controller whose rate the clock framework cannot answer does not bind) and refuses the `non-removable` eMMC node. The K1's MMC blocks are SDHCI (`spacemit,k1-sdhci`) and keep `mmc.rs` with a window from `platform.rs`. The Ethernet MACs (`starfive,jh7110-dwmac`) take their windows from `platform.rs` and do not bind through the bus yet; each becomes a consumer the same way when it gets its `hwbus.ids` row and probe arm.
Source: `crates/drivers/soc/src/`, `kernel/src/boot/soc.rs`, `kernel/src/boot/hwbus.rs`, `crates/core/actuation/src/effect_gate.rs`.

## DMA

Every driver that does DMA reaches memory through a domain (`azos_dma`), so turning on an IOMMU changes what the crate returns and not every driver. A driver takes a `DmaAddr` from `DmaDomain::map` and hands that to the device, never the physical address directly.

| Domain | Behaviour |
|---|---|
| `IdentityDomain` | No IOMMU, no checking; the bus address is the physical address. |
| `SoftState` | No IOMMU, but every mapping is checked in software against the RAM the kernel may share and against what the device can address, and recorded so a double unmap is caught. It cannot stop a device that ignores its descriptors. |
| IOMMU domain (`azos_iommu::IoDomain`) | Also makes the hardware refuse every page that is not mapped. |

`DomainKind` reports which one (`Identity`, `Soft`, `Iommu(flavour)`). Two traits split the work: `DomainOps` is the `&mut self` bookkeeping a host test drives; `DmaDomain` is the `&self` object a driver holds, made from the first by a lock in `kernel/src/boot/dma.rs`. `enable` starts enforcement once a driver's buffers are mapped; `allow_msi` opens the doorbell page a message-signalled interrupt writes. The default domain is chosen by `DMA_DOMAIN_SOFT` or `DMA_DOMAIN_IDENTITY`. `registry` maps a device (PCI requester id, or a platform device's base address through `declare_mmio` / `domain_for_mmio`) to its domain; `domain_for` is called at probe.

### Addressing limits

A device whose DMA stops short of the top of RAM (a 32-bit master on a machine with memory above 4 GiB, a bus whose `dma-ranges` end early) must be given memory under its limit. The limit comes from the device tree: `dma_ranges_limit` returns the highest CPU physical address a device behind a bus can reach (`u64::MAX` when nothing restricts it). A window that is offset or does not start at 0 yields `DMA_UNREACHABLE` (0): the refusal is explicit instead of a mask the controller would misread. `alloc_below(src, mask, len)` takes memory from the page allocator through `PageSource` and keeps only what fits; because the allocator has no ranged allocation, the pages that do not fit are held until one does, bounded by `MAX_MISSES`, and a source whose free memory is mostly above the mask is refused (`DmaError::NeedsBounce`) rather than drained. `needs_bounce` is the pure decision: false when an IOMMU is active, otherwise whether the buffer lies outside the device's `AddrRange`.

### Cache coherence

A coherent device needs nothing. A non-coherent master needs, per transfer, a `clean` before the device runs (write back dirty lines) and a `flush` (clean plus invalidate) before a device write and after the device ran; a bare invalidate is never used, because a buffer that does not start and end on a cache line shares edge lines with neighbours. `CacheOp`, `op_for_device(dir)` and `op_for_cpu(dir)` pick the operation from the `Direction` (`ToDevice`, `FromDevice`, `Bidirectional`); the `Maintain` trait lets a host test drive the same sequence. The boot installs the pair, only when the hardware has it: riscv64 Zicbom `cbo.clean` / `cbo.flush` or, on a core without Zicbom (the JH7110's U74), the `Flush64` register of the SiFive composable cache controller the device tree names (`sifive,ccache0`, `starfive,jh7110-ccache`; `azos_dma::ccache` walks the 64-byte physical lines of a range, the controller has no clean-only operation so the same flush serves both halves), aarch64 `dc cvac` / `dc civac`, and nothing on x86_64, which is coherent. Coherence is a property of the master: `DMA_NONCOHERENT` sets the platform default and a device-tree `dma-coherent` property, recorded by the hardware bus, turns maintenance off for the devices that declare it. With `DMA_NONCOHERENT` the boot refuses to continue where no cache maintenance is available.

Source: `crates/drivers/dma/src/`, `kernel/src/boot/dma.rs`, `crates/drivers/dtb/src/lib.rs`, `config/subsys/Kconfig.drivers`.

## IOMMU

`azos_iommu` puts four IOMMU flavours behind one interface.

| Unit (`src/`) | Hardware | Device key | Page-table format |
|---|---|---|---|
| `riscv.rs` | RISC-V IOMMU (a PCI function) | Requester id through the device directory table | Sv39 / Sv48 |
| `smmuv3.rs` | Arm SMMUv3 | StreamID (the requester id) through a linear stream table | LPAE stage 1, 4 KiB granule |
| `vtd.rs` | Intel VT-d (legacy mode) | Root table by bus, context table by devfn | Second-level |
| `amdvi.rs` | AMD-Vi | Device table indexed by requester id | v1 host page table |

All four use 4 KiB tables of 512 eight-byte entries (`pgtable.rs`). Only 4 KiB leaves are built, because a superpage would let a device reach its neighbours. A write-only mapping is not expressible on RISC-V or Arm stage 1, so a request for write-only is granted read-write there; `Perm` is a floor, never a ceiling.

The structure:

- `IommuUnit` is one unit (`flavour`, `pt_format`, `attach`, `flush`, `poll_faults`); `UnitHandle` is a unit shared between domains behind the kernel's lock.
- Per device, a unit is told one `DomainMode`: `Block` (every access refused and recorded), `Bypass` (untranslated), or `Translate { root_pa }`.
- `IoDomain` is one device's I/O page table and the mappings in it. IOVA equals physical address: the table holds exactly the pages a driver mapped, with the permission the direction needs, so a driver keeps using the physical addresses it has. A page shared by two mappings is mapped for the union of their permissions. The granularity is the page, so a buffer that shares a page with other data leaves that data reachable; page-aligning buffers closes it.
- Scope: one translation stage. No ATS, no PASID, no nested translation, no interrupt remapping. Fault queues are polled (`IOMMU_FAULT_POLL_MS`); the units leave interrupt generation off.

Kernel wiring (`iommu_init` in `kernel/src/boot/dma.rs`, cargo features `iommu-riscv`, `iommu-smmuv3`, `iommu-vtd`, `iommu-amdvi`; Kconfig `IOMMU_RISCV`, `IOMMU_SMMUV3`, `IOMMU_VTD`, `IOMMU_AMDVI`, all on by default where the ISA has PCI, plus `IOMMU_BYPASS` and `IOMMU_DOMAINS`): after PCI enumeration and before any PCI driver, the boot finds the unit through the firmware (the hardware bus's `riscv-iommu` PCI function on riscv64 and `smmuv3` device-tree node on aarch64, both in `crates/drivers/iommu/hwbus.ids` and bound record-only so ring 3 never gets their registers; the ACPI DMAR / IVRS on x86_64), brings it up and places each enumerated function. A function whose driver maps all its DMA through its domain (virtio-net/gpu/snd over PCI, e1000e, igc, xHCI) gets a translating domain of its own: after the driver maps its buffers, `Dma::enable` points the unit at the domain's page table, and a DMA to an unmapped page is then refused and logged by the fault task. A function whose driver hands its device physical addresses (NVMe, AHCI) stays in pass-through, said per function. A function no kernel driver binds is blocked (ring 3 has no DMA path yet). `IOMMU_BYPASS` puts every function in pass-through. Each translating device has its own cache tag (SMMUv3 ASID, RISC-V PSCID, VT-d / AMD-Vi domain id), so no device hits another's cached translation and a flush names one device; an AMD-Vi entry blocks with `V` and `TV` set and no permission (an all-zero entry would pass DMA through untranslated), and every entry of a fresh table starts that way.

Source: `crates/drivers/iommu/src/`, `kernel/src/boot/dma.rs`.

## Interrupts as scheduled objects

A hardware line is bound to an event port, and the cost of serving it is a reservation the scheduler admits.

**Binding.** A ring-3 driver binds a line with `DEVICE_IRQ_BIND` on its `Device` capability: the line is routed to one CPU and every interrupt on it queues a `PORT_EVENT_IRQ` event on the driver's port. The top half is minimal: the external-interrupt handler masks the line, completes it at the controller, and calls `irq_dispatch`, which queues the event and wakes the port's waiter. The event carries the CPU the line is routed to (byte 9 of the 16-byte event, `PortEvent::cpu`): where the interrupt was taken and, for a handler pinned there (`IRQ_THREADED`, the reservation's CPU), where it is woken; and the wake is logged as that line's (`why woke`, `Documentation/observability.md`). The line stays masked until the driver calls `DEVICE_IRQ_ACK` (mask-until-ACK), so a level device that has not been quietened is not taken again on return. Which lines ring 3 may bind, and who owns the rest, is tracked per controller (`mark_kernel`, `route_for` in `crates/drivers/irqchip/src/user_irq.rs` for the PLIC/APLIC; the GIC has its counterpart in `azos_arch_aarch64::irq::gic`); a line the kernel enabled for itself cannot be bound. A binding holds the port's packed (index, generation) reference plus an epoch, compared at delivery; a mismatch queues nothing and is counted (`irq_port_drops`).

**Budget (`IRQ_THREADED`).** With `IRQ_THREADED`, the handler is the task that bound the line and must run on a hard reservation (CBS, `azos_sched::rt`); the bind is refused (`BindError::Budget`) for a task without one. The line is routed to the CPU the reservation was admitted on. The rule: a line whose handler ran out of budget stays masked until the budget is replenished. `irq_sc_throttle` tells the binding table when a reservation that serves lines is throttled or replenished; while throttled an idle line is masked and marked held, and its ACK does not unmask it (`Ack::Held`). Each overrun leaves a `Rule::IrqBudget` decision record. Without `IRQ_THREADED`, any task may bind and the ACK always unmasks.

**Kernel lines use the same mechanism.** With `IRQ_THREADED`, one kernel thread (`irq-thread`, pinned to the boot CPU, on its own hard reservation: `IRQ_THREAD_BUDGET_PCT` of `IRQ_THREAD_PERIOD_US` at `IRQ_THREAD_PRIORITY`) binds every kernel-registered line to an event port exactly as a ring-3 driver does. The per-ISA top half masks, completes and dispatches; the thread runs the handler that used to run in the interrupt (the console FIFO drain, virtio completions). The timer keeps its top half. Lines of the PLIC/APLIC and the GIC are threaded, because both latch an edge that arrives while the line is masked; the x86_64 IOAPIC does not, so no kernel line is registered there. Until the thread runs, or if its reservation is refused, every line stays inline.

**Message-signalled interrupts.** A line number with `MSI_LINE` set names a slot (`MSI_LINE | k`), not a controller input. The bind allocates a vector (x86_64: a LAPIC vector; riscv64 with AIA: an IMSIC identity), enables it on the CPU, and replies with the address and data the device must write. The unbind returns the vector. An MSI cannot be masked at the controller, so a delivery to a binding whose handler is out of budget is dropped at the top half and counted (`irq_msi_drops`). Platforms that do not deliver MSI to ring 3 refuse the slot (`msi_supported` in `LineHooks`).

Source: `crates/core/ipc/src/irq_bind.rs`, `crates/core/abi/src/invoke.rs`, `crates/drivers/irqchip/src/`, `kernel/src/irq_thread.rs`, `config/kernel/Kconfig.sched`.

## SpacemiT K1 bring-up

The K1 (BananaPi BPI-F3) builds from `config/defconfigs/robot-sbc-riscv64+k1.config`, a release image that needs the fleet's signing key. The same board as a development build (the TEST key allowed) is that file plus `CONFIG_BUILD_TYPE_DEV=y`, with no second defconfig to keep in step; it type-checks with no board and no fleet key:

```
cp config/defconfigs/robot-sbc-riscv64+k1.config "$AZOS_OUT/k1-dev.config"
echo CONFIG_BUILD_TYPE_DEV=y >> "$AZOS_OUT/k1-dev.config"
TOPOLOGY_PUBKEY_PATH="$PWD/tools/keys/test_pub.bin" \
  make ARCH=riscv64 check CHECK_DEFCONFIG_riscv64="$AZOS_OUT/k1-dev.config"
```

Its controllers come from the device tree, like the VisionFive 2's:

| Controller | Node | Driver | Used by |
|---|---|---|---|
| GPIO | `gpio@d4019000` (`spacemit,k1-gpio`), four banks of 32 pins behind set/clear registers | `gpio_k1` | the e-stop line and its panic-time drive, the motors' direction pins, the payload and camera-trigger pins, the sensor task's input pins, the `Gpio` interface |
| PWM | `pwm@d401a000` + n * 0x400 (`spacemit,k1-pwm`), one controller per channel | `pwm_k1` | the motors' speed, the buzzer, the ESC outputs, the `Pwm` interface (the gripper's 50 Hz servo period is refused, see below) |

GPIO pins are the controller's own numbers (bank * 32 + bit); the kernel exposes the first 64. A PWM channel number is the hardware PWM number of the node (`pwm0` is channel 0), whichever nodes the tree enables; the kernel drives `pwm0` to `pwm7`. The function clock sets the period range, 78 ns to 5.12 ms at 12.8 MHz: the motor loop and the buzzer fit, a 50 Hz servo period is refused. The clock, reset and pin-mux state of both belong to the APBC controller and the pad controller, which the SoC frameworks do not model yet; the K1 runs on what the firmware left. The K1's PDMA is not driven: nothing takes a DMA channel, so the DMA entry points answer "no controller" and copies run on the CPU.

## Native driver list

All crates are `no_std`. "Chip logic" crates contain no host-specific code and are hosted by a kernel task or by a ring-3 program.

| Path | Package | Contents |
|---|---|---|
| `crates/drivers/api` | `azos_drv_api` | Driver API surface, class traits for block, console, network |
| `crates/drivers/base` | `azos_drv_base` | Board description, in-kernel driver registry |
| `crates/drivers/driver_server` | `azos_driver_server` | Ring-3 driver registry and request queue |
| `crates/drivers/hwbus` | `azos_hwbus` | Hardware bus logic |
| `crates/drivers/bus` | `azos_drv_bus` | I2C (`i2c_driver`, `i2c`, `i2c_txn` the DesignWare engine, `i2c_k1` the SpacemiT K1 engine), SPI, CAN, the UART bridge to the companion radio, the `hwbus` instance |
| `crates/drivers/pci` | `azos_pci` | PCI/PCIe enumeration, BAR and bridge-window placement, SoC host controllers |
| `crates/drivers/dtb` | `azos_dtb` | Device-tree parser |
| `crates/drivers/irqchip` | `azos_drv_irqchip` | PLIC-or-AIA selection, ring-3 line ownership (the controllers themselves are in `azos_arch::irq`) |
| `crates/drivers/soc` | `azos_soc` | Clock, reset, regulator, pin control, power-domain frameworks |
| `crates/drivers/dma` | `azos_dma` | DMA domains, bounce decision, cache maintenance |
| `crates/drivers/dmac` | `azos_drv_dmac` | DMA controller (simulation on QEMU, the JH7110's on VF2; none driven on the K1) |
| `crates/drivers/iommu` | `azos_iommu` | RISC-V IOMMU, SMMUv3, VT-d, AMD-Vi |
| `crates/drivers/sys` | `azos_drv_sys` | Console UART and deferred console lines, monotonic clock and timer programming, hardware watchdog, WCET points, the kernel-side proxy for ring-3 drivers |
| `crates/drivers/virtio` | `azos_drv_virtio` | virtio MMIO and PCI transports; block, network, entropy, input, GPU (2D scanout) and sound (PCM streams) devices |
| `crates/drivers/block` | `azos_drv_block` | Backend selection (`blkdev`: virtio or SD/eMMC), SD/eMMC (`mmc`), NVMe (`nvme`), AHCI SATA (`ahci`), partition table parser, device queue |
| `crates/drivers/nvme` | `azos_nvme` | NVMe wire protocol (register layout, queue arithmetic, command encodings); no MMIO |
| `crates/drivers/usb` | `azos_usb` | Native USB host: xHCI driver, USB core (enumeration, hubs, pipes incl. isochronous IN, hot-plug events), class-driver interface, `lsusb` listing, mass-storage, CDC and video class drivers; hardware behind `Regs`, `Memory`, `Clock` |
| `crates/drivers/usb-hid` | `azos_usb_hid` | USB HID class driver: report descriptor parser (usages to evdev codes), report decoder, boot-protocol fallback, autorepeat, device authorization (`usb-authorize` records); events go to a `Sink` the kernel ends in the console ring and the terminal server's event ring |
| `crates/drivers/net` | `azos_drv_net` | NIC backend selection (`net_device`), Ethernet MACs (`eth`: Cadence MACB/GEM; `dwmac`: Synopsys DesignWare QoS with its MDIO/PHY, the VisionFive 2's gmac0), Intel e1000e over PCI (`e1000e`, Kconfig `DRV_E1000E`), Intel I225/I226 2.5 GbE over PCI (`igc`, Kconfig `DRV_IGC`; advanced descriptors, built on `e1000e`'s wire half) |
| `crates/drivers/input` | `azos_drv_input` | i8042 and PS/2 keyboard and mouse, scancode and keymap, input event ring |
| `crates/drivers/fb` | `azos_fb` | Generic framebuffer fed by virtio-gpu, ramfb, a bootloader framebuffer or a device-tree `simple-framebuffer`; a flip hook for a source that scans out a copy; text console and panic screen behind features |
| `crates/drivers/display` | `azos_display` | ramfb, and a DC8200 plus HDMI TX framebuffer driver behind the `hdmi` feature |
| `crates/drivers/gpio` | `azos_drv_gpio` | GPIO pin controller (the K1's registers in `gpio_k1`) |
| `crates/drivers/actuator` | `azos_drv_actuator` | PWM (the K1's registers in `pwm_k1`), motor driver, motor PID loop, the buzzer's kernel host |
| `crates/drivers/buzzer` | `azos_buzzer` | Piezo buzzer chip logic over a PWM channel |
| `crates/drivers/ina219` | `azos_ina219` | INA219 power monitor chip logic |
| `crates/drivers/sensor` | `azos_drv_sensor` | INA219, ADS1115 ADC, LD19 lidar, rangefinders, MIPI CSI-2 camera interface |
| `crates/drivers/baro` | `azos_baro` | BMP280 barometer over I2C |
| `crates/drivers/imu` | `azos_imu` | MPU-6050 IMU over I2C |
| `crates/drivers/gps` | `azos_gps` | NMEA parser |
| `crates/drivers/camera` | `azos_camera` | Virtual camera |
| `crates/drivers/cam-ring` | `azos_cam_ring` | Lock-free single-producer frame ring and a one-producer, many-consumer ring |
| `crates/drivers/npu` | `azos_drv_npu` | NPU driver |
| `crates/drivers/thermal` | `azos_thermal` | Thermal runtime: zones from the device tree, sensor and clock seams, per-board objects (the K1's carries the rail with the clock) |
| `crates/drivers/power` | `azos_drv_power` | System suspend, power management, the Raspberry Pi's PM block (watchdog, reboot and power-off without PSCI) |
| `crates/drivers/tpm` | `azos_tpm` | TPM 2.0 TIS/FIFO protocol and commands over MMIO or SPI |
| `crates/drivers/rtc` | `azos_rtc` | Real-time clocks (goldfish, PL031, MC146818, PCF8563); seeds the wall clock at boot (`kernel/src/boot/rtc.rs`, see [time.md](time.md#real-time-clock)) |
| `crates/drivers/scsi` | `azos_scsi` | SCSI over USB Bulk-Only Transport, both ends: CBW/CSW, the target (device-side) command set, the initiator (host) CDB builders and parsers |
| `crates/drivers/firmware` | `azos_firmware` | Firmware mailbox client (`rpi_mailbox.rs`) used by the thermal runtime |
| `userspace/drivers/gpio_drv`, `buzz_drv`, `ina_drv` | | Ring-3 drivers (`GPIODRV.ELF`, `BUZZDRV.ELF`, `INADRV.ELF`) |

Source: `crates/drivers/*/Cargo.toml` and each crate's `src/lib.rs`.
