<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Virtualization

AzOS has a hypervisor core in the kernel (`crates/core/hv`) and a ring-3 virtual-machine
monitor (`userspace/services/vmmd`). A guest is a virtual machine that the signed topology
declares. The kernel owns what only the kernel can, the stage-2 tables and the vCPU threads;
the monitor serves the guest's devices. This page describes the roles, the per-ISA layer,
the `Vm` and `Vcpu` interfaces, the monitor's device models, and the rules a guest row is
admitted by. Configuration options are in [config.md](config.md); the monitor as a service is
in [services.md](services.md).

The design rule: a guest holds no warrant. The device models that serve its devices are a
ring-3 task, and that task holds the capabilities, so every effect a guest causes passes the
same envelope and leaves the same record as an effect of a native task.

## Roles and options

Source: `config/axes/Kconfig.virt`, `config/axes/Kconfig.virt`, `config/arch/Kconfig.isa`,
`kernel/src/boot/hv.rs`, `crates/core/hv/src/admit.rs`.

The role is the `VIRT` axis. Any role but `none` builds the hypervisor core (`HV` is derived
from `VIRT`, never asked).

| `VIRT` | Meaning | Harts |
|---|---|---|
| `NONE` | The kernel hosts no guest. | |
| `HOSTED` | Guests run beside the kernel, which keeps its own drivers. | vCPUs share the harts that hold no deadline reservation |
| `SPLIT` | A small resident monitor owns the virtualization extension and the kernel runs as its first guest (the aarch64 EL2 stub shape). | as hosted |
| `STATIC` | Guests are pinned to harts and memory fixed in the signed topology; none is created at run time. | a hart of its own per vCPU |

The defaults come from the preset: industrial and automotive use `STATIC`; desktop and
server use `HOSTED` on x86_64 and `SPLIT` on aarch64; the confidential security posture
starts at `SPLIT`; everything else is `NONE`.

| Option | What |
|---|---|
| `HV` | Derived: the hypervisor core is built (kernel feature `hv`). |
| `HV_REQUIRE` | Refuse to boot when the CPU cannot host the guests. Default on for `STATIC`; otherwise the boot prints why and goes on without guests. |
| `HV_MAX_VCPUS` | The vCPU pool, 1 to 64 over all guests (default 8, 4 on embedded); 32 bytes of RAM per vCPU, and on aarch64 about 3 KiB more of static RAM per vCPU (the world-switch block and the list-register queue). The built-in row of `VMMD.ELF` is granted an endpoint for each of the first 16. |
| `HV_EXAMPLE_GUEST`, `HV_EXAMPLE_GUEST_MEM_MIB` | The built-in topology declares one `[guest.azos]` row (one vCPU, 1 to 32 MiB, default 24; `virtio-console`, `virtio-blk`, `virtio-net`; envelope `cautious`), and `VMMD.ELF`'s row budgets its frames. Default `n`; only the `qemu-hv-guest` and `qemu-aarch64-hv-guest` defconfigs set it. `make azos-guest` (`tools/dev/run_guest.sh`) builds that host with a volume carrying `/fat/VM/DISK.IMG` and a flat image `/fat/VM/GUEST.BIN`; the monitor loads ELF64 images, and the one it asks for at start-up is `/fat/VM/KERNEL.ELF` (below). |
| `RV_H`, `X86_SVM`, `X86_VMX` | The CPU extension, each `n` / `probe` / `require` (see [config.md](config.md)). On aarch64 the boot trampoline keeps EL2 when it was entered there. |
| `TOPOLOGY_MAX_GUESTS`, `TOPOLOGY_GUEST_DEVICES` | Guest rows and device entries per row the topology holds (`config/subsys/Kconfig.topology`). |
| `MAX_MEMOBJS` | A guest's RAM is memory-object frames, so the rows' `mem_mib` add up to at most half the table of memory objects (`config/limits/Kconfig.limits`). |

A CPU that cannot host guests, or a role of `none`, is "no hypervisor, with the reason" on the
boot line, never a boot failure (`HV_REQUIRE` refuses before that). The `qemu-hv` and
`qemu-x86_64-hv` defconfigs set `HOSTED`, `qemu-aarch64-hv` sets `SPLIT`, each with
`MAX_MEMOBJS=256`; the `qemu-hv-guest` and `qemu-aarch64-hv-guest` defconfigs add the example
guest. QEMU needs the extension turned
on (`-cpu rv64,h=true`, `virtualization=on`, `-cpu max,svm=on`; `tools/dev/qemu.sh` lists the
modes). Build commands are in [building.md](building.md).

## The hypervisor core

Source: `crates/core/hv/src/lib.rs`.

The core is what is the same on the three ISAs. It touches no hardware and no scheduler: what
differs per ISA sits behind `azos_arch_api::Hypervisor`, and the kernel objects it uses
(memory objects, the event port, the thread of a vCPU) are the caller's, so the whole core runs
under host tests (`tests/host/hv-tests`, and `tests/host/vmmd-tests` for the far end of the
trap ring).

| Module | What it holds |
|---|---|
| `admit` | The boot admission of the guest rows: role, hardware, harts, memory, backends. |
| `vm` | `Vm` and the table of them: lifecycle, stage-2 root, RAM and trap page attached, device windows, start and stop of the vCPUs. |
| `vcpu` | `Vcpu`: its hart set, pending interrupt lines and run state; the rule that keeps real-time harts clear of it. |
| `backend` | The backends a row names, and the envelope's ceiling on their reach. |
| `run` | The vCPU loop: enter, route the exit, post a trap to the device model, wait for its answer. |
| `ring`, `trapwire` | The monitor's end of the trap and completion rings, and their wire form shared with `VMMD.ELF`. |
| `stage2` | Guest-physical mapping over the frames of a memory object. |
| `vlapic`, `vioapic` | The virtual local APIC and IOAPIC of an x86 guest. |
| `vplic` | The virtual PLIC of a riscv64 guest (`sifive,plic-1.0.0`): priorities, pending and enable bits, per-context threshold, claim and complete. |

Placement of a guest's pieces:

- A vCPU may use only the harts that hold no deadline reservation (`vcpu::allowed`). Admission
  applies the rule to the topology's placement, `Vcpu::set_affinity` to every mask a caller
  asks for, and `vcpu::pick_hart` to the hart a started vCPU's thread is created on.
- A vCPU is a kernel thread while it runs.
- Data moves through rings (`trapwire`); the calls are authority (attach, start, stop) and the
  one sleep on the event port.

### What an exit becomes

Source: `crates/core/hv/src/run.rs`, `crates/core/hv/src/vplic.rs`.

| Exit | Served as |
|---|---|
| Decoded MMIO load or store in the window of the VM's interrupt controller (riscv64: the PLIC) | Served in place by `RunHost::intc_mmio`: no trap, no device model. |
| Decoded MMIO load or store in a registered window | A `Trap` posted on the ring; the vCPU waits for its `Completion`, the device model's answer. |
| Decoded MMIO anywhere else | A bus that answers 0 and drops stores. |
| A store to a window of a backend the VM's envelope forbids | Refused: dropped and recorded as `Rule::GuestEgress`, before any device model sees it. |
| `Wait` (`wfi`, `wfe`, `hlt`) | The thread sleeps until a virtual interrupt is raised or a stop is asked. |
| `HostInterrupt` | The thread gives the hart up and enters again. |
| `Hypercall` (the firmware interface a guest boots through: the SBI on riscv64, PSCI and SMCCC on aarch64) | Served by the ISA through `Hypervisor::hypercall`: answered (the fences it asked of other vCPUs done before the guest runs on), or the vCPU ends, or the guest ends the machine (SBI `system_reset`, PSCI `SYSTEM_OFF` / `SYSTEM_RESET`: `fault::SHUTDOWN`). |
| Anything else (CPUID, trapped system registers, port I/O, undecoded stage-2 faults, shutdown, a hypercall the ISA does not serve) | The vCPU faults: the thread ends and `fault_code` says why. |

`Vcpu::stop` sets a flag the loop reads before every entry and while it waits for a device
model, and a host interrupt ends an entry, so a guest that never exits still stops within a
timer tick.

## The ISA layer

Source: `arch/api/src/lib.rs`, `arch/riscv64/src/ext/hv/mod.rs`,
`arch/aarch64/src/ext/hv/mod.rs`, `arch/x86_64/src/ext/hv/mod.rs`.

`HvKind` names the hardware virtualization an ISA gives the monitor:

| `HvKind` | Extension | Guest runs in | Second-stage tables |
|---|---|---|---|
| `RiscvH` | RISC-V H extension | VS-mode | G-stage, `hgatp` (Sv39x4 / Sv48x4) |
| `ArmEl2` | ARMv8 EL2 | EL1 | stage-2, `VTTBR_EL2` |
| `X86Svm` | AMD SVM | `VMRUN` with a VMCB | nested page tables |
| `X86Vmx` | Intel VMX | `VMLAUNCH` with a VMCS | extended page tables (`EPTP`); the fallback when SVM is not usable |

The `Hypervisor` trait is the same on every ISA:

| Method | What |
|---|---|
| `kind`, `status` | Which extension this is; `HvStatus::Usable(kind)` or `Absent(reason)`. |
| `gpa_bits` | Width of the guest-physical address space the tables serve. |
| `stage2_create`, `stage2_map`, `stage2_unmap`, `stage2_translate`, `stage2_flush`, `stage2_destroy` | The second-stage tables over a `StageTableMem` the kernel lends. Every ISA maps the guest in 4 KiB units (`STAGE_PAGE`) whatever the kernel's page size. |
| `decode_exit` | Turn a `RawExit` (the ISA's trap registers) into the common `Exit`. |
| `can_enter`, `enter` | Run the vCPU of a `GuestCtx` on this hart until the guest stops, and say why. `can_enter` defaults to `false` and `enter` to `Exit::InvalidState`; where `can_enter` answers `false`, `Vcpu::start` is refused with `UNSUPPORTED`. riscv64 answers `true` where H is usable: `enter` loads the VM's control CSRs and the vCPU's `vs*` CSRs, runs it and takes them off the hart again with host interrupts off, so no other task sees a guest's `scounteren` or `senvcfg`. aarch64 answers `true` when the EL2 stub is resident and the CPU has the GICv3 system registers (`ext/hv/vcpu.rs`). x86_64 answers `true` when SVM or VMX probes usable and the kernel registered its host (`ext/hv/vcpu.rs`). |
| `hypercall` | Serve an `Exit::Hypercall` through the kernel's `HypercallHost` (start a vCPU, arm the guest timer, fence other vCPUs). riscv64 serves the SBI (`ext/hv/sbi.rs`: BASE, TIME, IPI, RFENCE, HSM, SRST); aarch64 serves PSCI and SMCCC from the VM's vCPU states (`ext/hv/psci.rs`, `serve.rs`), never forwarding them to the firmware. x86_64 serves none (default `Unserved`, so a `VMMCALL` faults the vCPU); an AP's INIT and startup IPI go through the virtual local APIC (`ext/hv/apic.rs`). |
| `remote_fence` | Carry out a fence one vCPU asked of another (SBI RFENCE), on the target's CPU before it enters. |
| `guest_holder_key`, `guest_msi_ids`, `guest_msi_line` | The guest interrupt files: who holds this hart's file, how many message-signalled identities a guest file implements (riscv64 with AIA guest files; 0 elsewhere, so `Vcpu::inject_msi` is unsupported). |

`Exit` is `Fault { gpa, access }`, `Mmio(MmioAccess)`, `Pio(PioAccess)`, `Hypercall`, `Cpuid`,
`SysReg { write }`, `Wait`, `HostInterrupt`, `Shutdown`, `InvalidState` or `Other(u64)`.

What each ISA's `ext/hv` holds:

| ISA | Files |
|---|---|
| riscv64 | `csr` (H-extension CSRs, one source), `probe` (device-tree ISA string and a trap probe of `hstatus`), `gstage` (page-table encoder, `hgatp`, builder and walker, `hfence.gvma`), `vscsr` (the guest-visible `vs*` CSRs: save, restore, load), `enter` (VS-mode entry and exit vector, register frame), `guest` (one vCPU's entry: first-entry registers, the completed MMIO access, `hvip` from the lines, the `vs*` CSRs on and off the hart), `fault` (decode of `scause`, `htval`, `htinst`), `inject` (`hvip` injection, the Sstc guest timer, the guest MSI identities), `sbi` (the SBI a guest calls, served by the monitor; nothing is forwarded to the host's firmware) |
| aarch64 | `stub` (the resident EL2 stub: vector table, HVC handler and world switch, kept when the boot is entered at EL2), `world` (the block the world switch reads and writes, a guest's traps and `HCR_EL2`), `vcpu` (`Hypervisor::enter`: the vCPU pool of `HV_MAX_VCPUS` slots and the entry loop around the stub), `stage2` (`VTCR_EL2` / `VTTBR_EL2` tables over memory-object frames), `vgic` (the GICv3 list-register model), `vtimer` (`CNTVOFF_EL2`, `CNTHCTL_EL2`, the virtual timer), `inject` (the virtual timer's PPI and the monitor's lines as SPIs through the list registers), `psci` and `serve` (a guest's `HVC` / `SMC`) |
| x86_64 | `probe` (CPUID and the firmware-lockable MSRs for AMD and Intel), `svm` (the VMCB layout, intercepts, the consistency checks of `VMRUN`), `npt` (nested page tables built with the kernel's PTE builder), `exit` (decode of `#VMEXIT`), `entry` (the PVH and startup-IPI start states), `inject` (events and the interrupt window), `cpuid` and `msr` (what the guest sees and the permission map), `mmio` (the decode of a device access that faulted), `apic` and `serve` (the exits that need no device model, over the vCPU's local APIC), `vcpu` (`Hypervisor::enter`: builds a vCPU on its first entry, then loops `VMRUN`, decode, serve and returns only what the monitor's loop must handle; port I/O nobody serves reads as an empty bus; the kernel gives it page frames and the VM's virtual APICs through `VmHost`), `hw` (`EFER.SVME`, `VM_HSAVE_PA`, `VMRUN`, the CPU the entry runs on; bare metal only), and for Intel: `vmx` (the VMCS field encodings, the control resolution against the capability MSRs, the translation between the VMCB image the service works on and the VMCS, the exit decode into the SVM words `exit` decodes, the entry loop over a `VmxCpu`), `ept` (extended page tables: their own entry format and builder) and `vmx_hw` (`VMXON`, `VMLAUNCH`/`VMRESUME`, `VMREAD`/`VMWRITE`; bare metal only). QEMU's TCG has no VMX, so the instruction layer is not exercised by the host tests; the pure half is host-tested against the SDM's numbers |

Everything that is arithmetic runs under the host tests (`tests/host/arch-tests`,
`tests/host/arch-stub-tests`); only the hardware accessors are bare-metal.

## The Vm and Vcpu interfaces

Source: `crates/core/devif/src/vm.rs`, `crates/core/hv/src/vm.rs`, `crates/core/syscall/src/vm.rs`.

The control plane of a guest is two kernel-hosted IDL interfaces. VM `n` is the endpoint `vm.<n>`
(the row's position; badge `n + 1`) and its vCPU `k` is `vcpu.<n>.<k>` (badge `(n + 1) << 8 | k`).
The rights are the usual op classes: `READ` observes, `WRITE` acts on a running guest, `EXEC`
controls its life and layout. The data plane is not calls: a guest's device accesses reach the
monitor on the trap ring.

`Vm` (id `0x564D_0001`):

| Op | Right | What |
|---|---|---|
| `state` | `READ` | 0 admitted, 1 created. |
| `config` | `READ` | `[cpus, mem_mib, envelope \| devices << 8 \| vmid << 16, backends, ram_base]`; the envelope is 0 full, 1 cautious, 2 slow, 3 contained; `backends` holds the kind of each device, 4 bits each from the lowest. |
| `create` | `EXEC` | Build the stage-2 tables. `BUSY` unless admitted; `UNSUPPORTED` where the CPU gives no extension; `FAULT` when memory ran out. |
| `destroy` | `EXEC` | Give back the tables, the RAM and every attachment. `BUSY` unless created, and while a vCPU runs. |
| `window` | `EXEC` | Give backend `device` the range `[base, base + len)` of `space` (`SPACE_MMIO` or `SPACE_PIO`): guest accesses there are served by its device model. `BAD_ARGUMENT` for an empty or overlapping range, a range inside RAM or a device the row does not list. |
| `ram` | `EXEC` | Attach a memory object as guest RAM at a page-aligned guest-physical address inside `[ram_base, ram_base + mem_mib MiB)`. The object must be a read-write memory object the caller made, not shared with a clone and not swappable; the kernel pins it until `destroy`. |
| `traps` | `EXEC` | Attach the trap page (`TRAP_PAGE_BYTES`) and the event port that wakes the monitor; once per VM. |
| `net` | `EXEC` | Attach the ring region of the guest's NIC; once per VM. Refused (`REFUSED`, recorded as a guest-egress refusal) when the VM's envelope allows no network. |

`Vcpu` (id `0x564D_0002`):

| Op | Right | What |
|---|---|---|
| `pending` | `READ` | The virtual interrupt lines raised and not yet taken, bit `n` for line `n`. |
| `inject` | `WRITE` | Raise virtual interrupt line `irq` (0..64). `BUSY` unless the VM is created. Where the guest has a PLIC (riscv64) `irq` is a PLIC source (1..63) instead, reported as an edge: the PLIC routes it to the contexts that enabled it, and the guest's accesses to the PLIC window are served by the monitor without a trap (`RunHost::intc_mmio`). |
| `set_affinity` | `EXEC` | Run only on the harts of `mask`, less the ones that hold a deadline reservation or are offline; answers the mask in effect. `REFUSED` for a vCPU the topology pinned. Takes effect at the next `start`. |
| `start` | `EXEC` | Start the vCPU at guest-physical `pc` with `arg` in its first argument register, as a kernel thread. `BUSY` unless the VM is created with all its RAM and the trap page attached; `UNSUPPORTED` where the ISA cannot enter a guest; `REFUSED` when every hart it may use holds a deadline reservation. |
| `stop` | `EXEC` | Ask the vCPU to stop; its thread ends at the next exit. |
| `kick` | `WRITE` | Wake the vCPU if it waits for a device model's answer on the completion ring. |
| `state` | `READ` | `RUN_STOPPED`, `RUN_RUNNING` or `RUN_FAULTED` in the low 8 bits; for a fault the exit that ended it in the rest; for a running vCPU `RUN_PAUSED` (bit 8) once the thread holds the guest. |
| `pause` | `EXEC` | Hold the guest: the thread stops entering it at its next look (a host tick at most), keeps every register and the interrupt lines raised meanwhile, and the guest's clock does not count the time the whole guest is held. `BUSY` when the vCPU does not run or a pause is already asked. |
| `resume` | `EXEC` | Let a held guest run on. `BUSY` when the vCPU does not run or no pause is asked. |
| `inject_msi` | `WRITE` | riscv64: make message-signalled interrupt `id` (`1..=48`) pending in the guest file the vCPU holds (it gets one if it has none; the file is its hart's IMSIC guest file, so the vCPU then stays on that hart). A monitor that holds a device's `Cap<Irq>` makes this call when the port delivers the notification. `UNSUPPORTED` where the ISA or the machine gives guests no such file (no H, `RV_AIA` off, an IMSIC without guest-index bits); `BAD_ARGUMENT` for an `id` outside what it can raise; `BUSY` unless the VM is created. |

## The monitor and its backends

Source: `userspace/services/vmmd/src/main.rs`, `userspace/services/vmmd/src/model.rs`,
`userspace/services/vmmd/src/mmio.rs`, `userspace/services/vmmd/src/virtq.rs`,
`userspace/services/vmmd/src/blk.rs`, `userspace/services/vmmd/src/net.rs`,
`userspace/services/vmmd/src/console.rs`, `userspace/services/vmmd/src/ringlink.rs`,
`userspace/services/vmmd/src/store.rs`, `userspace/services/vmmd/src/life.rs`,
`userspace/services/vmmd/src/ctl.rs`, `userspace/services/vmmd/src/dtb.rs`,
`userspace/services/vmmd/src/pvh.rs`, `userspace/services/vmmd/src/loader.rs`,
`userspace/services/vmmd/src/guest.rs`, `userspace/services/vmmd/src/trap.rs`,
`userspace/services/toolbox/src/vm.rs`, `crates/core/hv/src/backend.rs`.

`VMMD.ELF` does the following, in order:

1. Finds `vm.0` and its `vcpu.0.k` endpoints and reads `Vm::config`. A VM left created by a
   monitor that ended is stopped and given back first. It then serves `VmCtl` (below) on a
   service thread; everything after this step runs when a guest is asked for (`vm start`, or the
   start-up request of step 5), from `ctl::Control::create`.
2. Calls `Vm::create`, then makes the guest's RAM one memory object at a time (a memory object
   holds at most `MAX_MEMOBJ_PAGES` pages), maps each into its own task and attaches it with
   `Vm::ram`. The RAM, the trap page and the NIC ring are charged to the monitor's Domain, so the
   `mem_pages` of its row must cover the guest's `mem_mib`; the boot refuses a guest the row
   cannot hold (`vmmd_pages` in `crates/core/topology/src/builder.rs`). A task holds at most
   `USER_WINDOW_RANGES` (16) mappings, its other regions included, so the monitor maps less than
   4 MiB of guest RAM (16 objects of 256 KiB); past that the RAM is partial, the monitor logs
   "guest RAM is partial" and no device model works.
3. Makes the trap page and an event port and attaches both with `Vm::traps`.
4. Registers one MMIO window per backend it has a model for (`Vm::window`) and attaches the
   NIC's ring region (`Vm::net`).
5. Loads a kernel when asked (below): an ELF64 executable of the host's ISA read beneath
   `/fat/VM`, with the description of the machine it boots into placed next to it, then starts
   vCPU 0 at the entry with that description's address in the boot register. At start-up the
   monitor asks for `/fat/VM/KERNEL.ELF`, if the volume has one, through the same calls a tool
   makes.
6. Serves: sleeps on the event port, answers each trap on the completion ring, kicks the vCPUs it
   answered, and raises the interrupt lines the answers raised with `Vcpu::inject`.
7. Looks at the vCPUs periodically; one that left (a shutdown, or a fault) ends the guest, so the
   others are stopped and the VM is given back with the memory objects the monitor made for it.
   The row is free again for the next `create`.

### What a guest boots into

There is no firmware below a guest kernel, so the monitor writes the description of the machine
next to the kernel (`dtb.rs`, `pvh.rs`, `life.rs`; one platform table, `dtb::platform`, gives the
device windows and lines to the models, the tree and the PVH command line alike):

| ISA | Description | Entry |
|---|---|---|
| riscv64 | a flattened device tree: memory, one `cpu` per vCPU (enable method `sbi`), the PLIC, the virtio-mmio devices of the row, `bootargs`, `stdout-path` | the ELF entry, `a1` the tree |
| aarch64 | a flattened device tree: memory, the CPUs (`psci`, method `hvc`), the generic timer, a GICv3, the devices, `bootargs`, `stdout-path` | the ELF entry, `x0` the tree |
| x86_64 | the PVH `hvm_start_info`: memory map, and a command line that carries a `virtio_mmio.device=` entry for each device | the kernel's PVH entry note, `ebx` the start_info, 32-bit protected mode |

The owner's command line is the first line of `/fat/VM/CMDLINE`. A guest asked for fewer CPUs or
less memory than its row declares is told so in this description; the kernel still attaches all of
the row's memory, which the guest never sees.

### Launching a guest from the shell (`VmCtl`)

`VMMD.ELF` serves the `VmCtl` interface (`crates/core/devif/src/vmctl.rs`) on `endpoint.vmctl`.
The name server lends the call right on it to the rows that import `vmctl` (`TOOLBOX.ELF`, not
under `CONSOLE_LOCKDOWN`): **the caller's authority is its warrant for that endpoint**. A service
thread accepts each call and hands it to the monitor's loop, which owns the machine; the state
machine is `ctl.rs`.

| Command | Call | Effect |
|---|---|---|
| `vm list` | `list` | the table: one entry per row the monitor serves (state, CPUs, memory, how the last run ended) |
| `vm start <row\|image> [--image NAME] [--cpus N] [--mem MIB]` | `create`, `start` | builds the machine of a signed row (a number; its kernel is `KERNEL.ELF`) or of row 0 with a kernel image beneath `/fat/VM` (a name; `--image` spells out a name that is all digits); smaller than the row, never larger |
| `vm stop <id>` | `stop` | ends the guest and gives the machine back |
| `vm pause <id>` | `pause` | holds the running guest (every vCPU stops entering guest mode and keeps its state; the guest's clock does not count the time held); the table reads `pausing` until every vCPU took the hold, then `paused` |
| `vm resume <id>` | `resume` | lets a held guest run on |
| `vm console <id>` | `console` | lends a ring (one producer, the monitor; one consumer, the tool) with the guest's console output |

Every refusal answers a receipt: the cause, the number that explains it (the ceiling a request
exceeded, the loader's error) and a serial of the refusals the monitor has made; the monitor logs
the same line. A pause is refused with a receipt when the guest does not run (`NOT_RUNNING`), is
already held (`ALREADY_PAUSED`) or the kernel refuses a vCPU (`PAUSE_REFUSED`); a resume when it is
not held (`NOT_PAUSED`). The guest has one clock for all its vCPUs: the time every running vCPU
held the guest together is taken off it, so a vCPU the guest starts later (SBI `hart_start`, PSCI
`CPU_ON`, an AP's SIPI, or a restart) reads the clock the running ones read. A single vCPU held
while another runs does not stop the clock. The monitor's device models keep running while the
guest is held, and `stop` ends a held guest like any other.

The row of a guest lists its backends by name in `devices`. The position in that list is the
device index every interface uses. A device is a virtio-mmio window of `WINDOW` bytes at
`MMIO_BASE + index * WINDOW` with interrupt line `irq_line(index)` (`dtb::platform` has the
ISA's base window and first line).

| Backend | Row name | Reach | Model in `vmmd` |
|---|---|---|---|
| `Backend::Blk` | `virtio-blk` | the disk image | `blk.rs` over a `BlockStore`, a file opened through the row's directory capability |
| `Backend::Net` | `virtio-net` | the network | `net.rs` over a `Link`; `ringlink.rs` is a pair of frame rings in shared memory, whose other end nothing in the tree bridges to a network |
| `Backend::Console` | `virtio-console` | the monitor's console | `console.rs`; output is filtered to printable ASCII, marked with the guest's name and rate limited; no input |
| `Backend::Rng` | `virtio-rng` | none (inert) | no model in `vmmd`: reads as an empty bus |
| `Backend::Input` | `virtio-input` | none (inert) | no model in `vmmd`: reads as an empty bus |
| `Backend::Gpio` | `gpio` | a physical pin | no model in `vmmd`: reads as an empty bus |

The transport is virtio-mmio version 2 (`VIRTIO_F_VERSION_1` is mandatory, so the net header is
12 bytes). The guest is untrusted: `virtq.rs` trusts nothing in guest memory (an avail index past
the queue, a descriptor past the table, a loop, an address outside RAM), and a queue found corrupt
flags the device `NEEDS_RESET`. Guest memory is reached only through `GuestMem`, whose access
outside the RAM range fails and touches nothing. A disk request is checked against the capacity
and the read-only flag before the store sees it, and the store works on a bounded budget per call.
A frame the guest sends is dropped when it is too large or its source address is not the MAC the
guest was given.

### The envelope as a ceiling

The row's `envelope` is the ceiling on the effects the guest may cause through its backends. A
store to a window of a backend whose reach is past the ceiling is refused at the trap; loads are
never egress.

| Envelope | Farthest reach |
|---|---|
| `full` | a physical pin |
| `cautious` | the network |
| `slow` | the disk image |
| `contained` | none: the guest causes no effect at all |

## Guest rows and admission

Source: `crates/core/topology/src/types.rs`, `crates/core/topology/src/parser.rs`,
`crates/core/hv/src/admit.rs`, `kernel/src/boot/hv.rs`.

A guest is a `[guest.NAME]` row of the signed topology.

| Key | Meaning |
|---|---|
| `cpus` | Virtual CPUs, 1 to 255. Required. |
| `mem_mib` | Guest RAM in MiB, at least 1. Required. |
| `envelope` | `full`, `cautious`, `slow` or `contained`. Required: there is no default, because a guest is untrusted code. |
| `devices` | The backends, each 1 to 24 bytes of `[A-Za-z0-9_-]`, none twice. Defaults to none. |
| `passthrough` | Format 8: physical devices named for the guest itself, none twice and none also in `devices`. Parsed, checked and emitted by the topology; the hypervisor core and the monitor do not read it, so no device is handed to a guest. |
| `static`, `pcpus`, `mem_base` | Format 8: a static partition (its physical CPUs as a mask of `cpus` bits, its memory at a 4 KiB-aligned `mem_base`, overlapping no other static guest). Parsed and checked by the topology; admission does not read them (a static plan comes from `VIRT_STATIC`). |

Each key appears at most once; an unknown key is a parse error. The guest's RAM starts at the
address of the platform's own machine model (`default_ram_base`): `0x8000_0000` on RISC-V,
`0x4000_0000` on ARM, 0 on x86.

`admit` answers once at boot, before any VM exists, from facts the boot hands it. The rows are
admitted as a set; the first rule that fails refuses all of them with a boot line, and nothing is
written to the decision ring. The rules, in order:

| `Refusal` | Rule |
|---|---|
| `RoleNone` | The image's role is `none`. |
| `NoHypervisor(reason)` | The CPU has no usable extension. |
| `TooManyVms` | More rows than the table. |
| `NoHart` | Every online hart holds a deadline reservation. |
| `TooManyVcpus` | The rows' `cpus` exceed the pool (`HV_MAX_VCPUS`). |
| `Memory` | The rows' `mem_mib` exceed what the host has free. |
| `RamCeiling` | The rows' RAM is more than the memory-object table can describe. |
| `UnknownDevice` | A row lists a backend nobody serves. |
| `NotEnoughHarts` | A static partition needs a hart per vCPU and there are fewer. |

No rows at all is always an empty plan. In the plan, hosted and split guests may run on
every non-real-time online hart; a static guest takes the next free harts, lowest first, and
each of its vCPUs is pinned to one.

An accepted row becomes a VM with the endpoint `vm.<n>`. A VM owns no memory until a holder of
`EXEC` on that endpoint calls `create`. The signed topology that declares a guest also writes the row of
`VMMD.ELF`, with `mem_pages` of at least `vmmd_pages(guests)`; the built-in topology declares no
guest and carries only the monitor's own frames (`VMMD_MEM_PAGES`), unless `HV_EXAMPLE_GUEST`
adds its row.
