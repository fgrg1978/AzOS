# Linux integration

Three separate mechanisms connect AzOS to Linux. They do not share code, and each has its own boundary.

| Path | What runs | Where | Licence boundary |
|---|---|---|---|
| [Linux personality](#path-1-the-linux-personality) | Unmodified static Linux user programs | In the kernel (translation table) or in a ring-3 runtime inside the program's own address space | None: the personality is AzOS code that implements Linux's syscall ABI |
| [Linux kernel driver slice](#path-2-the-linux-kernel-driver-slice-lx) | Unmodified Linux kernel modules (`.ko`) | Ring-3 server processes (`lxsrv`) | GPL-2.0-only code lives only in `lx/glue/`, `third_party/linux` and the built `.ko` files |
| [Linux as a guest](#path-3-linux-as-a-guest-under-the-hypervisor) | A guest kernel in a virtual machine | Behind the hypervisor core, with device models in a ring-3 monitor | None: the guest is data in a memory object |

Related pages: [hal.md](hal.md) for the `Hypervisor` trait and the trap layer; [drivers.md](drivers.md) for the hardware bus that matches Linux driver ids and for DMA and interrupt handling.

## Path 1: the Linux personality

A task whose signed topology row says `abi = "linux"` traps with Linux system call numbers. The personality answers them. It is selected per task by the row, never by the image: a row says it or the task is native, so no native task ever reaches the Linux table.

Source: `crates/core/syscall/src/linux.rs`, `crates/core/linux-abi/src/lib.rs`, `crates/core/topology/src/types.rs`, `config/Kconfig.linux`.

### What a Linux row may hold

`TaskAbi` is `Native` or `Linux`. A Linux row may hold only capabilities of kind `CapKind::Node` (`TaskAbi::linux_may_hold`); any other capability refuses the whole topology (`AdmissionError::LinuxRowHoldsHardware`). A Linux program reaches the machine only through files and sockets that native tasks serve. The in-kernel table's call numbers are the asm-generic table that riscv64 and aarch64 share (`azos_linux_abi::nr`); the table covers those two ISAs. x86_64 has the personality only in the ring-3 runtime, which translates Linux's x86-64 numbers and registers (`azos_linux_abi::x86_64`).

### Two hosts for the same personality

| | In-kernel translation | Ring-3 runtime |
|---|---|---|
| Kconfig | `LINUX_ABI` | `LINUX_RUNTIME` (requires `LINUX_ABI`; not on a 16 KiB or 64 KiB aarch64 granule, not on the embedded profile) |
| Where Linux state lives | A small pool in the kernel keyed by thread id (descriptor table, working directory, signal state, umask) | In the program's own address space, in `userspace/lib/linux_rt` |
| What the kernel knows | The Linux syscall table (`crates/core/syscall/src/linux.rs`); the filter verdict `FilterVerdict::Linux` | Nothing Linux-specific: two native calls, `SYS_FOREIGN_ENTRY` and `SYS_FOREIGN_RESUME`, and a per-thread mode bit |
| Cost per Linux call | One trap | One trap, one resume |

With `LINUX_RUNTIME` the in-kernel table answers nothing: the kernel reflects the trap to the runtime and keeps no Linux state for the task. Both hosts are in the tree.

**In-kernel translation.** `scheduler::current_syscall_verdict` returns `FilterVerdict::Linux` for a Linux task (one bit of the per-CPU filter word, set at context switch from `Task::abi`) and the syscall dispatch hands the trap to `linux.rs` instead of the native table. With `LINUX_ABI` off the bit is never set and the branch folds away. In the generic syscall flow ([hal.md](hal.md#generic-trap-layer)) a Linux task's number has no foundational case, so its entry is counted in slot 0.

**Ring-3 runtime.** The foreign-ABI family is defined in `crates/core/abi/src/foreign.rs`.

- `SYS_FOREIGN_ENTRY` registers the runtime's trap entry. `SYS_FOREIGN_RESUME(frame)` restores a register frame and returns to the foreign program.
- A registered thread is in one of two modes, a per-thread bit published through the same per-CPU filter word the native path already loads: *runtime* (a trap is a native system call, filtered by the image profile) and *foreign* (a trap is reflected to the entry). There is no address-range test and no selector byte.
- A trap taken in foreign mode is not executed. The kernel pushes a `ForeignFrame` (every register of the trapping thread; the program counter is the instruction after the trap) on the thread's own user stack, below the stack pointer and the ABI red zone, 16-byte aligned, switches to runtime mode, and enters the registered entry with the frame address in the first argument register and in the stack pointer. The runtime writes the result into the frame and calls `SYS_FOREIGN_RESUME`.
- Only the flag bits in `FLAGS_USER_MASK` come from a resumed frame, so a frame can change neither privilege level nor interrupt mask. Floating-point and vector state and the thread pointer are not in the frame; the runtime is built soft-float and must not touch them.
- A thread created by `SYS_FOREIGN_FORK` or `SYS_THREAD_CREATE` from a registered thread starts in runtime mode with the same entry. The Linux `execve` clears the registration.
- The runtime image is `userspace/services/lxrt`, linked at the runtime window (`RUNTIME_BASE`, `RUNTIME_LIMIT`) and embedded in the kernel image (`kernel/src/boot/seams.rs`), so the kernel's signature covers it. The kernel maps it into a Linux process at spawn. `userspace/lib/linux_rt` (`Runtime::dispatch`, with the `Native` trait for its native calls) holds the descriptor table, working directory, umask and signal state of the process.

### Authority is not widened

- Every call that touches a kernel object goes through the native handler a native task would use, with the task's own capability table. A file is opened by the same tree gate and minted as the same `Cap<File>`; a pipe is the same `Cap<Shm>` region with a byte ring (`azos_ipc::kpipe`, `azos_bytepipe`).
- **Seccomp runs after translation.** Before each native call the personality asks the task's filter about the native number (`reach`); a refusal kills the task as it would a native one. A Linux image's profile lists the native numbers `azos_linux_abi::TABLE` says its calls reach, and `tests/host/seccomp-tests` derives the profile from that table.
- The runtime's native calls meet the row's seccomp profile and capability tables as any native call does. A foreign program that jumps into the runtime gets the image's authority and no more.

### Syscall mapping

`azos_linux_abi::TABLE` lists every Linux number the personality answers with the native numbers its translation may reach. An empty list means the call is answered from the personality's own state or from a capability the task already holds. Anything not in the table answers `-ENOSYS` and is recorded.

| Linux calls | Native reach |
|---|---|
| `getcwd`, `dup`, `fcntl`, `ioctl`, `lseek`, `umask`, `uname`, `clock_gettime`, `getpid`, `getppid`, `getuid`, `geteuid`, `getgid`, `getegid`, `gettid`, `sched_getaffinity`, `prctl`, `set_tid_address`, `set_robust_list`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `sigaltstack`, `rt_sigreturn` | None (personality state) |
| `openat`, `chdir`, `getdents64`, `newfstatat`, `fstat`, `read`, `readv`, `write`, `writev`, `brk`, `wait4` | `SYS_INVOKE` (plus `SYS_CAP_CLOSE` for `openat`) |
| `close`, `dup3` | `SYS_CAP_CLOSE` |
| `pipe2` | `SYS_MO_CREATE`, `SYS_CAP_CLOSE` |
| `mmap`, `mprotect` | `SYS_MO_MAP` (`mprotect` changes read and write only; it never adds execute) |
| `munmap` | `SYS_MO_UNMAP` |
| `exit`, `exit_group` | `SYS_EXIT` |
| `futex` | `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` |
| `nanosleep`, `rt_sigsuspend` | `SYS_SLEEP_UNTIL` |
| `sched_yield` | `SYS_YIELD` |
| `kill`, `tkill`, `tgkill` | `SYS_ALERT` |
| `clone` | `SYS_FOREIGN_FORK`, `SYS_CAP_CLOSE`, `SYS_THREAD_CREATE` (fork and vfork shapes, and threads with `CLONE_THREAD`) |
| `execve` | `SYS_INVOKE`, `SYS_CAP_CLOSE` (into another Linux row only with a launch grant) |

Bounds that Kconfig sets: `LINUX_ROBUST_LIST_LIMIT` (robust futex list entries walked at a thread's exit; the list is untrusted memory, so the walk is bounded) and `LINUX_IO_MAX` (bytes one read, write, readv or writev moves; a call asking for more returns a short count, and `readv`/`writev` use one bounce buffer and make one transfer).

### Third-party Linux programs

`USERSPACE_GPL` is the switch without which no third-party GPL program is built or placed in an image. `BUSYBOX` (requires `USERSPACE_GPL` and `LINUX_ABI`) builds a pinned BusyBox release from a tarball already on disk, checks its SHA-256, and builds it static with `zig cc`; it runs as `BUSYBOX.ELF` under its own row with `abi = "linux"`. The `make busybox` target refuses, naming what is missing, without `zig` or the tarball or on a digest mismatch. `make busybox-source-offer` writes the source offer.

## Path 2: the Linux kernel driver slice (`lx/`)

Unmodified Linux kernel modules run in ring-3 server processes, one process per driver class, through a compatibility layer, over a pinned Linux tree. A server holds no actuator capability, and no safety decision reads its output. The kernel never links a Linux object.

Source: `lx/`, `crates/core/lx-loader`, `crates/core/syscall/src/module_ops.rs`, `userspace/services/lxsrv`, `config/Kconfig.linux`, `tools/lx_*`.

### Pieces

| Piece | Path | Role |
|---|---|---|
| Pinned tree | `third_party/linux` (a shallow submodule, `update = none`), `lx/LINUX_PIN` | A tag of the kernel.org stable tree, with its tag object and commit. `tools/lx_fetch_linux.sh` is the one way to fetch it (shallow and sparse). Kconfig `LX_LINUX_PIN` must equal the pinned tag. |
| Glue | `lx/glue/lxbase.c`, `lx/glue/Kbuild` | `lxbase.ko`: the base of the layer, compiled by Linux's own Kbuild against the pinned tree. It exports the Linux symbols the validated modules import and forwards them to the host ABI. GPL-2.0-only. |
| Host ABI | `lx/HOST_ABI` | Every symbol `lxsrv` exports to modules: `lxh_alloc`, `lxh_free`, `lxh_hwcap`, and the C string and memory functions. Plain scalars and pointers, no Linux type. |
| Compatibility base | `lx/emul` (`lx_emul`) | A `no_std` Rust crate that re-implements the behaviour of Linux core APIs drivers call (allocation, locks, timers, workqueues, RCU, `printk`, the device model, reference counts, the exported-symbol table) with fixed-capacity containers and generation-checked handles. No Linux source is copied. |
| Loader | `crates/core/lx-loader` (`azos_lx_loader`) | Turns a relocatable `.ko` into code and data a ring-3 server can run. |
| Kernel half of loading | `crates/core/syscall/src/module_ops.rs` | `DOMAIN_MODULE_VERIFY` and `DOMAIN_MODULE_MAP_X`. |
| Server | `userspace/services/lxsrv` (`LXSRV.ELF`) | Runs the whole module path; its topology row (kernels with the `lx-server` feature) grants one capability, READ on the kernel entropy pool, which keys its allocator. |
| Module build | `tools/lx_kbuild/`, `make lx-kbuild` | Runs Kbuild for riscv64 and aarch64 in a pinned container with no network and the tree mounted read-only; `make lx-kbuild-repro` rebuilds from scratch and requires identical `.ko` hashes. |
| Device ids | `lx/DEVICE_SOURCES`, `tools/lx_device_table.py` | See [Leaf drivers](#leaf-drivers-and-the-hardware-bus). |
| Licence lint | `tools/lx_license_lint.py` | See [Licence boundary](#licence-boundary). |

### The module path

The loader is three pure steps (`azos_lx_loader`; it allocates nothing and holds no state, and the host tests in `tests/host/lx-loader-tests` run the code the server runs):

1. `Module::parse` checks the header (ELF64, little-endian, `ET_REL`, riscv64 or aarch64) and every section header against the file length.
2. `Module::layout` places every allocated section in one of two regions: text (`SHF_EXECINSTR`) and data (everything else, `.rodata` included).
3. `Module::load` copies the bytes, resolves each undefined symbol through the caller's table, and applies relocations.

Modules are compiled with `-mcmodel=medany -mno-relax` (riscv64) or the small code model with `-mgeneral-regs-only` (aarch64), `-fno-pic -fno-common`. That rules out a GOT, a PLT, TLS, IFUNC and the dynamic-linking relocation types, and the loader refuses each by name (`Error::RefusedSection`, `RefusedSymbol`, `UnsupportedReloc`) instead of mis-applying it. A branch that does not reach its target is refused, never truncated. Sections named `.altinstructions` or `.alternative` are refused too. `admit` adds the two checks a Linux loader makes on `.modinfo`: a GPL-compatible licence tag (`license_is_gpl_compatible`) and the exact `vermagic`.

The kernel decides whether bytes may run at all, because this tree's rules forbid the obvious loader: `mmap` refuses `PROT_EXEC`, there is no `mprotect` that adds execute, and every executable is bound to a SHA-256 the build computed.

1. The server reads the module file and hands the file bytes to `DOMAIN_MODULE_VERIFY`. The kernel hashes them and looks the module name up in `MODULE_SHA256`, a table `tools/module_hashes.py` generates into the kernel image (the signed artefact). On a match it grants a one-shot token bound to the caller's thread id and the module's length; otherwise the refusal is recorded (`module_refusals`, a console line).
2. The server lays the module out in two anonymous regions (text, data), resolves its imports (the host ABI first, then the exports, `__ksymtab`, of modules loaded earlier) and relocates it.
3. The server calls `DOMAIN_MODULE_MAP_X` with the token and the text range. The kernel consumes the token, checks the range (at most the verified length rounded up to a page, every page the caller's own private read-write page), and flips it read-write to read-execute one PTE update per page (`vmm::set_user_range_exec`). Data stays read-write and never executable; text is never writable and executable at once.
4. The server calls the module's init function.

The digest covers the input bytes, not the relocated text. A server that is already compromised can write code into the range between steps 1 and 3; the range bound limits that to one module's worth of pages per verification. The relocation engine runs in ring 3 because a kernel that relocated would parse untrusted input in supervisor mode. `LX_MODULE_TOKENS` sizes the token table; a token is dropped when its task exits. The two calls exist only with the `lx-loader` feature (`LINUX_DRIVERS` with `LX_SERVER_SKELETON`).

`LXSRV.ELF` also probes the token rules: a forged token, a range larger than the verified module and a token used twice are each refused. Its test module `LXTEST.KO` is compiled by `make` for both ISAs from this project's own C (`userspace/tests/lxmod/lxtest.c`), with no Linux header.

### Module set and symbol discipline

`lxbase.ko` is built first and every other module after it. The rules, in `tools/lx_license_lint.py --ko DIR` over the Kbuild output:

| Rule | Checks |
|---|---|
| K1 | Every `.ko` carries a GPL-compatible `license` and `vermagic` equal to the pinned release, `SMP preempt` and the ISA. |
| K2 | `lxbase.ko` imports only the host ABI (`lx/HOST_ABI`). |
| K3 | Every other module imports only the host ABI and symbols exported by modules earlier in the order. An unprovided Linux symbol fails the build, not the boot. |
| K4 | No image (kernel ELF or userspace ELF) has a symbol named like one a `.ko` defines. |
| K0 | An empty `.ko` set or image set is a failure, so a row cannot pass by finding nothing. |

The filesystem set (`<isa>/fs/*.ko`: `crc16`, `mbcache`, `jbd2`, `ext4`, built by `make lx-kbuild` from `fs/ext4`, `fs/jbd2`, `fs/mbcache.c` and `lib/crc/crc16.c`) is held to K1 and K4. Its imports are not K3-gated. `lx/FS_EXT4_UNRESOLVED` lists, per ISA, the imports of that set that neither `lx/HOST_ABI` nor an earlier module exports, and `tests/host/lx-loader-tests` fails when the list differs from the set the built modules compute. A symbol leaves the list in the change that provides it.

The Kconfig menu "Linux compatibility" (`config/Kconfig.linux`) defines `LINUX_DRIVERS` and one option per class: filesystems (`LX_FS_EXT2`, `LX_FS_EXT4_RO`, `LX_FS_EXT4_RW`; Linux filesystems use the native `BlockDevice`, and the ext4 options are read-only without journal replay or read-write with `jbd2`), USB (`LX_USB_XHCI`, `LX_USB_DWC3`, `LX_USB_HID`, `LX_USB_STORAGE`, `LX_USB_CDC`, `LX_USB_UVC`), and further classes (`LX_SND_ASOC`, `LX_DRM_PANEL`, `LX_IIO`, `LX_WIFI`, `LX_BLUETOOTH`). `LX_ACCEPT_UNCONFINED_DMA` is the build-time acceptance a DMA-capable class needs on a board without an IOMMU. The configuration validator in `crates/core/limits/build.rs` refuses a `.config` that sets any class option or `LX_ACCEPT_UNCONFINED_DMA`, and `LINUX_DRIVERS` builds only together with `LX_SERVER_SKELETON`. The boolean enable and class options (`LINUX_DRIVERS`, `LX_SERVER_SKELETON`, the `LX_FS_*`, `LX_USB_*` and later-class options, `LX_ACCEPT_UNCONFINED_DMA`) default to `n`. The non-boolean symbols have their own defaults: `LX_MODULE_TOKENS` is a count (the pinned tag is `lx/LINUX_PIN`, not a Kconfig option). A small board (`HWCLASS_EMBEDDED`) cannot enable `LINUX_DRIVERS` at all.

### Leaf drivers and the hardware bus

`lx/DEVICE_SOURCES` lists the Linux leaf drivers whose ids the hardware bus matches, one `<lxsrv class> <path under third_party/linux>` line each. `tools/lx_device_table.py` reads each file's `MODULE_DEVICE_TABLE`, and `crates/drivers/hwbus/build.rs` turns the ids into the `LINUX` match table (see [drivers.md](drivers.md#match-tables)). The build refuses an id that is also in a native `hwbus.ids`. At bind time the native table is consulted first. A class server (`lxsrv-<class>`) is launched only when one of its ids matched a device the bus admitted (`Bus::linux_class_wanted`; the topology row marks the task as the server of a class).

A leaf-driver server drives devices only through ring-3 capabilities: a mapped register window (`DOMAIN_MMIO_MAP`), interrupt binding with `DEVICE_IRQ_BIND`, and the DMA and IOMMU services described in [drivers.md](drivers.md#dma). Because a bus master can write any physical address on a machine with no IOMMU, a DMA class there is meant to build only with `LX_ACCEPT_UNCONFINED_DMA` set, so the acceptance is a recorded build-time act.

### Licence boundary

The project is `Apache-2.0 OR GPL-2.0-only`. The Rust in the Linux layer (`lx/emul`, `crates/core/lx-loader`, `userspace/services/lxsrv`) includes no Linux header and keeps that licence. The rule `tools/lx_license_lint.py` enforces is: no GPL-only source, symbol or object outside `lx/glue/` and `third_party/`.

| Rule | Checks (over `git ls-files`) |
|---|---|
| T1 | Every SPDX line under `lx/glue/` says exactly `GPL-2.0-only`, and every source file there has one. |
| T2 | Outside `lx/glue/` and `third_party/`, every SPDX expression offers `Apache-2.0`. |
| T3 | Outside `lx/glue/` and `third_party/`, no C or assembly source includes a Linux kernel header (`<linux/...>`, `<asm/...>`, `<asm-generic/...>`). |
| T4 | No `Cargo.toml` outside `lx/glue/` depends on a path inside it. |
| T5 | `third_party/linux` is named only by the files allowed to. |
| A1 | No symbol of the GPL glue appears in a kernel ELF, a userspace ELF or a module. |
| A2 | Every `build/lx/*.ko` of the output root carries the project's own licence tag (`Dual Apache/GPL`). |
| K0 to K4 | The module rules above. |
| `--pin` | `lx/LINUX_PIN`'s commit equals the submodule gitlink and the checkout's HEAD, and the checkout has no local change. |

An image that contains a Linux module is distributed as GPL-2.0-only as a whole; shipping it requires offering the corresponding source. The default image contains no Linux-derived object.

## Path 3: Linux as a guest under the hypervisor

A guest kernel is not a separate component. It is a virtual machine the signed topology declares, hosted by the same hypervisor core as any other guest. Nothing in `crates/core/hv` or `userspace/services/vmmd` is specific to Linux; this section describes the path any unmodified guest kernel takes, and the boundary around it.

Source: `crates/core/hv`, `crates/core/arch-api/src/lib.rs` (the `Hypervisor` trait), `userspace/services/vmmd`, `crates/core/devif/src/vm.rs`, `config/Kconfig.hv`, `config/Kconfig.preset`.

### Roles and hardware

`VIRT` (Kconfig, `config/Kconfig.preset`) is the role of the image:

| Role | Meaning |
|---|---|
| `none` | The kernel hosts no guest. |
| `hosted` | Guests run beside the kernel, which keeps its own drivers. |
| `split` | A small resident monitor owns the virtualization extension and the kernel runs as its first guest (the aarch64 EL2 stub shape). |
| `static` | Guests are pinned to harts and memory fixed in the signed topology; none is created at run time. |

Anything but `none` builds the hypervisor core (`HV`, `HV_MAX_VCPUS`; `HV_REQUIRE` makes the boot halt when the CPU gives no usable extension, otherwise the role runs as `none` with the reason in the boot line). The CPU extension is probed per ISA under the n / probe / require policy (`RV_H`, `X86_SVM`, `X86_VMX`; EL2 on aarch64; see [hal.md](hal.md#extension-model)).

The ISA seam is the `Hypervisor` trait (`HvImpl` in each ISA crate's `ext/hv`):

| Item | Role |
|---|---|
| `kind`, `status` | Which extension (`HvKind`: `RiscvH`, `ArmEl2`, `X86Svm`, `X86Vmx`) and whether this boot can host a guest (`HvStatus::Usable` or `Absent(reason)`). |
| `stage2_create`, `stage2_map`, `stage2_unmap`, `stage2_translate`, `stage2_flush`, `stage2_destroy` | Guest-physical tables, over a `StageTableMem` the kernel supplies. |
| `decode_exit` | Raw exit state (`RawExit`) to `Exit`. |
| `can_enter`, `enter` | Whether the ISA's entry primitive runs a guest. A vCPU is refused rather than started where `can_enter` is false. |

### The hypervisor core

`azos_hv` is what is the same on the three ISAs. It touches no hardware and no scheduler, so it runs under the host tests (`tests/host/hv-tests`, and `tests/host/vmmd-tests` for the far end of the trap ring).

| Module | Holds |
|---|---|
| `admit` | The boot admission of the guest rows: role, hardware, harts, memory, backends. |
| `vm` | `Vm` and its table: lifecycle (admitted, created, started, destroyed), stage-2 root, RAM and trap page, device windows. |
| `vcpu` | `Vcpu`: hart set, pending interrupt lines, run state. |
| `backend` | The backends a row names, and the envelope's ceiling on their reach. |
| `run` | The vCPU loop: enter, route the exit, post a trap to the device model, wait for its answer. |
| `ring`, `trapwire` | The monitor's end of the trap and completion rings, and their wire form, shared with `VMMD.ELF`. |
| `stage2` | Guest-physical mapping over the frames of a memory object. |
| `vlapic`, `vioapic` | The virtual local APIC and IOAPIC of an x86 guest, as pure models. |

A guest is a `[guest.NAME]` row of the signed topology. It lists its backends in `devices = [...]` (the position is the device index every interface uses), its CPUs, memory, and an `envelope`. Guest RAM is memory-object frames that `VMMD.ELF` creates and charges to its own domain; the kernel pins them and holds a reference until `destroy`. The `mem_pages` of the `VMMD.ELF` row must budget its own frames plus the guests' RAM, and the boot refuses the guests when the row is short. Guests are controlled through the kernel-hosted `vm.<n>` and `vcpu.<n>.<k>` interfaces (`azos_devif::vm`).

**vCPU placement.** A vCPU may use only harts that hold no deadline reservation (`vcpu::allowed`). Admission applies the rule to the topology's placement, `Vcpu::set_affinity` to every mask a caller asks for, and `vcpu::pick_hart` to the hart a started vCPU's thread is created on. A started vCPU is a kernel thread running the `run` loop.

**The loop.** `run` is the same on all three ISAs; the kernel supplies a `RunHost` (the lock around the monitor's tables, the ring page, the event port, sleeping).

| Exit | Served as |
|---|---|
| Decoded MMIO load or store in a registered window | A `Trap` posted on the ring; the vCPU waits for its `Completion`. |
| Decoded MMIO anywhere else | A bus that answers 0 and drops stores. |
| A store to a window of a backend the envelope forbids | Refused: dropped and recorded as `Rule::GuestEgress`. |
| `Wait` (`wfi`, `hlt`) | The thread sleeps until a virtual interrupt is raised or a stop is asked. |
| `HostInterrupt` | The thread gives up the hart and enters again. |
| Anything else (hypercalls, CPUID, trapped system registers, port I/O, undecoded stage-2 faults) | The vCPU faults: the thread ends and `fault_code` says why. |

### The monitor and its warrants

The kernel owns what only it can: the stage-2 tables and the vCPU threads. Everything a guest does with a device is served by `VMMD.ELF`, a ring-3 program whose topology row is its whole authority. The guest holds no capability; the monitor's backends do. The disk is a file opened through the `Cap<Dir>` of the row, the console is the console the task writes, the NIC is a ring pair. What a guest can cause is what those handles can cause, through the same gate and record as any native task.

`vmmd` runs the device models, which are pure and host-tested (`tests/host/vmmd-tests`): `mmio` (the virtio-mmio transport), `virtq` (the split queue, which trusts nothing the guest wrote), `blk`, `net`, `console`, the trap protocol (`trap`) and the per-VM step (`model`). Its loop:

1. Find `vm.0` and its vCPU endpoints, read `Vm::config` (CPUs, RAM, which backend sits at which device index) and `create` the VM.
2. Make the guest's RAM, one memory object at a time, map each into the monitor and attach it with `Vm::ram`.
3. Make the trap page and an event port and attach them with `Vm::traps`.
4. Register one MMIO window per backend it has a model for (`Vm::window`), and attach the NIC's ring region (`Vm::net`, which the VM's envelope may refuse).
5. If the volume has a guest image (`/fat/VM/GUEST.BIN`, a flat binary), copy it to the start of RAM and start every vCPU there, vCPU `k` with `k` in its first argument register.
6. Serve: sleep on the event port, answer each trap on the completion ring, kick the vCPUs answered, and raise the interrupt lines the answers raised (`Vcpu::inject`).
7. Watch the vCPUs; one that left ends the guest, the others are stopped, the VM is given back and the monitor exits.

**The trap ring.** A guest access to a registered window is one record on the trap ring, and the vCPU waits for its completion on the completion ring. Both rings are one 4096-byte shared page (`azos_hv::trapwire`, included by both sides so the layout has one source): `vmmd` owns the consuming end of the trap ring and the producing end of the completion ring; the monitor owns the other two. Data moves through the rings; the only call is the sleep on the event port. The page is the other side's to write, so the consumer treats every index and record as untrusted, and a completion for a vCPU that waits for nothing is dropped.

### Envelope and backends

A backend is one of `Blk` (`virtio-blk`), `Net` (`virtio-net`), `Console` (`virtio-console`), `Rng` (`virtio-rng`), `Input` (`virtio-input`) or `Gpio` (`gpio`). The row's `envelope` is the ceiling on the effects the guest may cause through its backends. Each backend has a `Reach`, nearest first; the envelope names the farthest it allows, and a guest store to a backend past that is refused at the trap, before any device model sees it. Loads are never egress.

| Envelope | Farthest reach allowed | Backends within reach |
|---|---|---|
| `full` | A physical pin (`Physical`) | All |
| `cautious` | The network (`Net`) | All but `Gpio` |
| `slow` | The disk image (`Disk`) | `Rng`, `Input`, `Console`, `Blk` |
| `contained` | None | `Rng`, `Input` cause no effect outside the guest; the rest are refused |

`Rng` and `Input` have reach `Inert`, `Console` has `Console`, `Blk` has `Disk`, `Net` has `Net`, `Gpio` has `Physical`.

### Boundary summary

- A guest runs in a stage-2 address space made of memory-object frames charged to the monitor's domain.
- Its devices are the monitor's handles; the kernel enforces the envelope at the trap.
- Its vCPUs never run on a hart that holds a deadline reservation.
- The guest kernel image is data the monitor copies in; no Linux code runs in the kernel or in the monitor.
