# Linux driver slices in ring 3

> **Status:** draft
> **Supersedes:** none
> **Superseded by:** none

## Summary

The next three slices of the Linux driver layer ([linux.md](../linux.md#path-2-the-linux-kernel-driver-slice-lx)) are ext4 (Kconfig `LX_FS_EXT4_RO`, then `LX_FS_EXT4_RW`), the URB adapter for the HID quirk drivers, and the IMX219 sensor pilot. This note lists the Linux sources each one needs at the pinned tag, and specifies what running the ext4 module set in a ring-3 server needs on all three ISAs, with no GPL code in ring 0: a fixed low window for module memory, a virtual interrupt flag, and per-CPU state and `current` without privileged registers. On the module set as built, interrupt state needs no kernel mechanism on any ISA, and per-CPU state needs none on riscv64 and x86_64 while a server runs its Linux code on one thread. The kernel side is the window, the aarch64 thread pointer kept per task for a Linux class server, and a per-thread base register once a server runs more than one thread.

Source: `lx/FS_EXT4_UNRESOLVED`, `lx/DEVICE_SOURCES`, `tools/lx_fetch_linux.sh`, `tools/lx_kbuild/`.

## Motivation

`ext4.ko`, `jbd2.ko` and `mbcache.ko` already build for every ISA and pass the module rules, but they are built to run in ring 0. In ring 3 their privileged instructions fault. Their per-CPU and `current` accesses assume registers that a user thread cannot read, and the x86_64 code model reaches its symbols through sign-extended 32-bit absolute addresses. Each of these needs an answer before the slice can provide the symbols `lx/FS_EXT4_UNRESOLVED` still lists. Hosting the modules in the kernel instead would answer all of them at once, at the cost of GPL code in ring 0. That option is rejected.

Source: `lx/FS_EXT4_UNRESOLVED`, `crates/core/lx-loader/src/lib.rs`.

## Detailed design

### Sources each slice needs

Every file below is part of the pinned commit, and `tools/lx_fetch_linux.sh` checks each one out. The sparse set controls what is checked out, not what is fetched: the depth-1 fetch brings every blob of the commit. Adding a file to the set therefore downloads nothing.

| Slice | Compiled by Kbuild | Read, or re-implemented in `lx/emul` | How its server is chosen |
|---|---|---|---|
| ext4 | `fs/ext4/`, `fs/jbd2/`, `fs/mbcache.c`, `lib/crc/crc16.c` | The files that export the symbols `lx/FS_EXT4_UNRESOLVED` lists: in `fs/`, `buffer.c`, `inode.c`, `dcache.c`, `libfs.c`, `fs_parser.c`, `fs-writeback.c`, `mnt_idmapping.c`, `read_write.c`, `seq_file.c`, `stat.c`, `attr.c`, `bad_inode.c`, `namespace.c`, `open.c`, `super.c`, `filesystems.c`, `ioctl.c`, `sync.c`, `d_path.c`, `file.c`, `file_attr.c`, `file_table.c`, `fserror.c`, `namei.c` and `splice.c`; `fs/iomap/{fiemap,seek,direct-io,swapfile}.c`; `block/{bdev,blk-core,bio,blk-lib,blk-flush,blk-ioc}.c`; files under `mm/`, `kernel/` and `lib/` (already in the set); `init/main.c`, `init/version.c` and `drivers/char/random.c`; on aarch64, `drivers/clocksource/arm_arch_timer.c` | Kconfig `LX_FS_EXT4_RO` |
| URB adapter | `drivers/hid/{hid-core,hid-input,hid-quirks,hid-generic}.c` with `hid-ids.h` and `hid-haptic.h`, `drivers/hid/usbhid/`, and the leaves `hid-multitouch.c` and `hid-playstation.c` | `drivers/usb/core/{urb,message,driver,usb,hub}.c`, `drivers/input/{input,input-mt,ff-core,ff-memless}.c` | usb and hid ids, which are not a hwbus bus kind yet |
| Sensor pilot | `drivers/media/i2c/imx219.c`, `drivers/media/v4l2-core/`, `drivers/media/mc/` | `drivers/i2c/i2c-core-base.c`, `drivers/regulator/{core,devres}.c`, `drivers/clk/clk.c`, `drivers/gpio/{gpiolib,gpiolib-devres}.c`, and `property.c`, `power/runtime.c` and `regmap/` under `drivers/base/` (already in the set) | `lx/DEVICE_SOURCES`: `media drivers/media/i2c/imx219.c`, the selector `dt:sony,imx219` |

For ext4, each symbol in `lx/FS_EXT4_UNRESOLVED` was mapped to the file that holds its `EXPORT_SYMBOL` at the pinned commit. The mapping skips other architectures and the configurations the Kbuild does not use: `mm/nommu.c` (no MMU), and `rcu/tiny.c` and `locking/rtmutex_api.c` under the Linux `kernel/` directory (tiny RCU and PREEMPT_RT). 399 of the 401 symbols map directly. `get_random_u16` and `get_random_u32` are exported through a macro in `drivers/char/random.c`.

For the two leaves, the list holds the files that export the symbols their sources call by name. The exact import set is the one `tools/lx_license_lint.py --ko` computes over the first Kbuild of each leaf. Each slice records that set the way the ext4 set is recorded.

Source: `tools/lx_fetch_linux.sh`, `lx/DEVICE_SOURCES`, `tools/lx_device_table.py`.

### What the ext4 module set executes

The counts below come from disassembling `ext4.ko`, `jbd2.ko` and `mbcache.ko`, in that order, as `tools/lx_kbuild` builds them at the pinned tag. `crc16.ko` contains none of these instructions.

| | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| `current` | `tp`, a general register: 180, 47 and 10 instructions use it | `mrs xN, SP_EL0`: 73, 25 and 2 | `%gs:const_current_task(%rip)`: 44 in `ext4.ko` |
| Per-CPU base | `__per_cpu_offset[cpu]`, an imported array | `mrs xN, TPIDR_EL1`: 5 in `ext4.ko`. The 5 `TPIDR_EL2` reads are the VHE alternative, which is unreachable once the Kbuild drops the alternatives table | `%gs:sym(%rip)`: 97, 25 and 3 accesses, all `R_X86_64_PC32`. In `ext4.ko` they reach `const_current_task` (44), `__preempt_count` (39), the module's own `.data..percpu` (4), `this_cpu_off` (1) and `cpu_number` (1) |
| Inline interrupt state | In `ext4.ko`: 11 `csrrci rd, sstatus, SIE` saves and their 11 `csrs sstatus` restores (the generic per-CPU operations, which mask interrupts), and 9 `csrs`/`csrc sstatus` of `SUM` (inline user access in `__ext4_ioctl`) | none | none (no `cli`, `sti`, `pushf` or `popf`) |
| Imported interrupt state | `_raw_spin_lock_irqsave`, `_raw_spin_unlock_irqrestore` | the same | the same |

Every privileged instruction in this table faults in user mode: an illegal-instruction trap on riscv64, an undefined instruction on aarch64. The x86_64 entries are `%gs`-relative memory accesses, not privileged instructions, and they work in ring 3 as long as the GS base is right.

Source: `tools/lx_kbuild/kbuild-in.sh` (`strip_opt_alts`), `tools/lx_kbuild/arm64.config`.

### 1. A fixed low window for module memory

Every user address today lies below `USER_STACK_TOP`, which is the board's `RAM_BASE`, or 2 GiB when `RAM_BASE` is 0. That keeps all user memory below 2 GiB on every board in `crates/drivers/base/src/platform.rs`, so each module's reach holds: x86_64 `R_X86_64_32S` absolutes, riscv64 `medany` (±2 GiB PC-relative) and aarch64 ADRP (±4 GiB). This holds only as a side effect of how the boards lay out memory, not as a rule anything enforces. Native `SYS_MO_MAP` ignores its address hint and places mappings above the break, and the Linux personality refuses `MAP_FIXED`. The loader refuses a relocation that does not reach instead of truncating it, so a layout change would cost a refused module, not corrupted code.

The window makes the property explicit and checked:

- Kconfig `LX_MODULE_WINDOW_BASE` and `LX_MODULE_WINDOW_SIZE`, per ISA. The build refuses a window that ends above 2 GiB or above the board's user ceiling, or that overlaps the server image.
- A fixed, no-replace placement flag on the existing `SYS_MO_MAP`, so no new syscall number. The kernel honours it only inside the window and only for a task whose topology row is the server of a Linux class (`lx_class`). It refuses an overlap with `EEXIST`. The break and hint-less mappings never allocate inside the window.
- `DOMAIN_MODULE_MAP_X` refuses a text range outside the window.

The server image, whose symbols the modules import, is linked low in every ISA's user layout (`sdk/ld/user_*.ld`: 0x10000 on aarch64 and x86_64, 0x200000 on riscv64). Both of its relocation reaches therefore hold: the x86_64 absolute range and the riscv64 and aarch64 PC-relative range.

Source: `crates/core/sched/src/process.rs` (`USER_STACK_TOP`), `crates/core/syscall/src/handlers.rs` (`sys_mmap`), `crates/core/syscall/src/linux.rs` (`sys_mmap`), `crates/core/syscall/src/module_ops.rs` (`sys_module_map_x`).

### 2. A virtual interrupt flag

An interrupt reaches a server only as a notification its loop passes to `Env::run_irq`, between tasks. Module code is never interrupted by a Linux handler. "Interrupts disabled" is therefore the server's own state, and `lx/emul` keeps it:

- The imported `_raw_spin_lock_irqsave` family raises an atomic depth and returns a flags word, and the matching restore lowers the depth again. Inside that depth a sleeping call is refused and counted, as in any other atomic context. This covers all three ISAs.
- The inline riscv64 sites are rewritten by the loader in `Module::load`, after the copy and before any relocation. This runs in ring 3, before `DOMAIN_MODULE_MAP_X`. The rewrites:
  - `csrrci rd, sstatus, SIE` becomes `addi rd, zero, SR_SIE`, so the code reads "interrupts were enabled". Its value only feeds the matching restore.
  - `csrs sstatus, rs`, `csrc sstatus, rs`, and `csrci`/`csrsi sstatus, SIE` with `rd = x0` become `nop`.
  - `csrr rd, sstatus` is refused, not rewritten. Its value would be used, a constant would lie inside an `irqsave` section, and a call into the virtual flag does not fit one instruction slot without a free link register. The set contains none.

  An inline save and restore pair brackets a per-CPU operation that cannot block, so the pair does not need to touch the depth. `SUM` has no meaning in a server: the "user" pointer an ioctl handler sees is the server's own memory.
- The rewriter decodes each text section linearly from its start; riscv64 takes the instruction length from the low bits. A text section with a `$d` mapping symbol (data among the code) is refused, so a linear decode is sound. A host test checks that the decode lands on every symbol of the set's text. The rewriter changes only the exact encodings listed here. Two `SYSTEM` instructions run in user mode and are kept: `ebreak` (`BUG()`, `WARN()`; 132 in `ext4.ko`, 38 in `jbd2.ko`) and `rdtime` (2 in `ext4.ko`; AzOS sets `scounteren.TM` at boot). Any other `SYSTEM`-opcode instruction refuses the module, naming the section, the offset and the encoding, the way an unsupported relocation does. That covers a CSR other than `sstatus` and `time` (`cycle` and `instret` included), `ecall`, `sret`, `wfi` and `sfence.vma`.

The digest covers the input bytes, and the rewrite is a fixed function of them, as relocation is. It gives a compromised server nothing it could not already do between `DOMAIN_MODULE_VERIFY` and `DOMAIN_MODULE_MAP_X`.

Source: `lx/emul/src/sched.rs` (atomic context), `crates/core/lx-loader/src/lib.rs` (`Module::layout`, `Error`).

### 3. Per-CPU state and `current`

A server runs all of its Linux code on one AzOS thread ([Threads in the server](../linux.md#threads-in-the-server)). To Linux that thread is one CPU, whose per-CPU offset is 0. Each per-CPU variable is then used at its loaded address. The module's `.data..percpu` is loaded as data, and the server defines the per-CPU symbols the modules import as plain variables.

- **x86_64.** Every `%gs` access is `%gs:sym(%rip)`, whose effective address is the GS base plus the address of `sym`. The user GS base is 0 for every task: a fresh image enters ring 3 with zero FS and GS bases, a fork copies its parent's, and nothing else writes the GS base. `CR4.FSGSBASE` is off, so ring 3 cannot write it either. So `%gs:sym` is `sym`, and no kernel change is needed. The server defines `const_current_task`, `__preempt_count`, `this_cpu_off` (0) and `cpu_number` (0), and its task switch writes `const_current_task`.
- **aarch64.** The loader rewrites `mrs xN, SP_EL0` to `mrs xN, TPIDR_EL0`. `TPIDR_EL0` is writable at EL0. The server's task switch writes the current task's address there, and the server keeps no thread pointer of its own in `TPIDR_EL0` while Linux code runs. The kernel keeps `TPIDR_EL0` per task for a Linux task and for a Linux class server's tasks (`switch_slow` in `crates/core/sched/src/fp.rs`). It uses the same per-slot save and restore for both, and only switches from or to such a task pay for it. A spawn marks the slot when its row names an `lx_class` (`TaskInit::lx_class`), and a thread or fork child of the server inherits the mark. A native task's value is not kept. `mrs xN, TPIDR_EL1` and `mrs xN, TPIDR_EL2` become `movz xN, #0`. Refusing them instead would refuse `ext4.ko`. Its 5 `TPIDR_EL1` reads are `__kern_my_cpu_offset`, and 0 is the exact offset of the server's one CPU. The 5 `TPIDR_EL2` reads are the VHE replacement tails left in `.text` after the alternatives table is stripped: unreachable, and given the same value. Kept as they are: hints, barriers, `brk` and `ldtr`/`sttr`, which run at EL0. Every other system-register access refuses the module. That includes `TPIDR_EL0` itself, which now holds `current`. Also refused: `msr` of a `PSTATE` field (`DAIFSet`, `PAN`), `sys`/`sysl`, `svc`/`hvc`/`smc`, and `eret`.
- **riscv64.** `tp` is a general register, which the kernel preserves for every task (`crates/core/abi/src/syscall_nr.rs`: `sp`, `gp` and `tp` are kept across a syscall, and a trap saves every register). The server's task switch sets `tp` to the current task, `smp_processor_id()` reads 0 from the task's `thread_info`, and `__per_cpu_offset` is the server's one-entry array. Nothing is rewritten and nothing changes in the kernel.

A server that runs Linux code on more than one thread has more than one CPU, and the base has to differ per thread:

- **x86_64:** a per-thread user GS base. The kernel keeps a per-task value for the GS swap and writes it only at thread creation, as it does the FS base (`fs_base_to_load`). FSGSBASE stays off.
- **aarch64:** a per-thread `TPIDRRO_EL0`, which is kernel-written and read-only at EL0. It replaces the `movz xN, #0` rewrite with `mrs xN, TPIDRRO_EL0`.
- **riscv64:** nothing. The CPU number lives in the task's `thread_info`, and `__per_cpu_offset` is the server's array.

The ext4 slice does not need these: it runs on one thread. They are built with the first server that runs more than one. On aarch64 the per-task `TPIDR_EL0` already gives each thread its own `current`.

Source: `kernel/src/entry/x86_64/trap.rs` (`IA32_KERNEL_GS_BASE` at the first entry and after a fork), `crates/core/arch-x86_64/src/cpu/mod.rs` (`fs_base_to_load`), `crates/core/sched/src/fp.rs` (`TPIDR_EL0`), `lx/emul/src/switch/`.

### No GPL code in ring 0

The kernel's part is the window (a flag and its checks) and, on aarch64, `TPIDR_EL0` kept per task for a Linux class server, all in project code. The rewriter lives in `crates/core/lx-loader`, and the virtual interrupt flag and per-CPU symbols in `lx/emul` and `lxsrv`. All of it is project Rust under the project licence. Linux code stays in `lxbase.ko` and the Linux modules, mapped only in the server.

Source: `tools/lx_license_lint.py` (T1 to T5, A1).

### Next fronts

1. **lx-module-window** (kernel, three ISAs): the Kconfig window, the fixed no-replace flag on `SYS_MO_MAP` for Linux class servers, the break kept out of the window, and the window check in `DOMAIN_MODULE_MAP_X`. Host tests in `tests/host/syscall-tests`, each with a canary.
2. **lx-insn-rewrite** (`crates/core/lx-loader`, ring 3): the riscv64 `sstatus` rewrites and the aarch64 `SP_EL0`/`TPIDR_EL1`/`TPIDR_EL2` rewrites, with a refusal for anything else privileged. Host tests in `tests/host/lx-loader-tests` over the built filesystem set: no privileged instruction is left, and the canary is a module with one other CSR.
3. **lx-tpidr-el0** (kernel, aarch64): `TPIDR_EL0` saved and restored per task for the slots whose topology row names an `lx_class`, not only for Linux-personality tasks. Tested with a ktest whose canary keeps only the Linux-personality slots.
4. **lx-virtual-irq** (`lx/emul`): the `irqsave` family over an atomic depth, with sleeping inside it refused and counted.
5. **lx-percpu-single** (`lx/emul`, `lxsrv`): the per-CPU and `current` symbols, written at each task switch on all three ISAs.
6. **ext4-lx-slice** itself: the symbols `lx/FS_EXT4_UNRESOLVED` lists, over fronts 1 to 5.
7. **Deferred until a multi-threaded server exists:** the x86_64 per-thread user GS base and the aarch64 per-thread `TPIDRRO_EL0`.

## Drawbacks

- A fixed window gives module memory the same addresses on every boot. The server can pick a random offset inside the window from the entropy capability it already holds.
- The rewriter is a second pass over module text, and it has to track every privileged encoding a new module brings. It refuses an unknown one by name instead of guessing, so a new module can need a rewriter change before it loads.
- One thread per server serialises all of its Linux code, as `lx/emul` already does.

## Rationale and alternatives

- **Host the modules in the kernel (Linux's own model).** Rejected: it puts GPL code and Linux's failure modes in ring 0.
- **Trap and emulate in the kernel.** Rejected: an instruction emulator for an untrusted server would run in supervisor mode, and every per-CPU operation on riscv64 and every `current` read on aarch64 would cost a trap.
- **Rebuild the modules with different code generation.** Rejected for now: Linux offers no option that moves `current` off `SP_EL0` or makes riscv64 per-CPU operations stop masking interrupts. Changing the flags would change the pinned build that `make lx-kbuild-repro` reproduces.
- **A per-thread base register from the start.** Rejected for the first slice: no server needs one yet.
- **aarch64 `current` without a kernel change.** The loader could rewrite `mrs xN, SP_EL0` into a PC-relative literal load (`ldr xN, <slot>`, ±1 MiB) of a "current" word that it places in a read-write page within reach of every module's text. This works only while all of a server's Linux code runs on one thread, because the word is shared by every thread of the address space. It also ties the layout to the 1 MiB reach. Kept as the fallback if the per-task `TPIDR_EL0` costs more on the switch path than it saves.

## Prior art

- Linux applies its own instruction patch tables at module load (`apply_alternatives` in `arch/*/kernel/alternative.c`). The rewriter is the same idea, done in ring 3 and limited to a fixed list of encodings.
- Genode's `dde_linux` runs unmodified Linux drivers in user space over a re-implemented `lx_emul`, with cooperative tasks and emulated per-CPU state.
- NetBSD rump kernels run kernel code in user processes over a hypercall layer that stands in for the privileged parts.

## Unresolved questions

- Whether a later slice reads interrupt state, for example `irqs_disabled()` under lockdep. The Kbuild configuration has lockdep off.
- The window's default per ISA, which depends on the server image layout on each board.

## Future possibilities

- The usb and hid bus kinds in `tools/lx_device_table.py`, which turn the URB adapter's leaves into `lx/DEVICE_SOURCES` lines.
- Per-thread bases for multi-threaded servers, as listed under the next fronts.
