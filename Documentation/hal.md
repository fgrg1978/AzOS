# Hardware abstraction layer

The kernel runs on riscv64, aarch64 and x86_64 from one source tree. Shared code asks for CPU, interrupt, MMU, boot and hypervisor services through a contract crate; each ISA has one crate that implements it; a thin facade picks the implementation at compile time. This page describes that structure, the model for optional CPU extensions, the generic trap layer, and the three lints that keep the layout from drifting.

Related pages: [drivers.md](drivers.md) covers the device side (buses, DMA, interrupt routing); [linux.md](linux.md) covers the Linux integration paths, including the hypervisor guest path that sits on the `Hypervisor` trait described below.

## Layers

| Layer | Path | Role |
|---|---|---|
| Contract | `crates/core/arch-api` (`azos_arch_api`) | Traits and ISA-neutral helpers. No hardware access except `core` atomics. |
| ISA crates | `crates/core/arch-riscv64`, `crates/core/arch-aarch64`, `crates/core/arch-x86_64` | One implementation of the contract per ISA, plus ISA-only modules under `ext/`. |
| Facade | `crates/core/arch` (`azos_arch`) | Re-exports the active ISA crate and names its singleton `ARCH` and its type `ArchImpl`. |
| Kernel entry | `kernel/src/entry/<isa>/` | Boot assembly, the trap stub, the register-frame decode and the `ArchEntry` hooks for that ISA. |
| Generic trap policy | `kernel/src/trap/` | Syscall, fault and interrupt policy, written once. |

Source: `crates/core/arch-api/src/lib.rs`, `crates/core/arch/src/lib.rs`.

## The `arch-api` contract

`azos_arch_api` is `#![no_std]`. The traits fall into three groups: the original per-subsystem traits, the platform contract, and the optional services.

| Trait | Captures | Representative methods |
|---|---|---|
| `Cpu` | Identity, idle, clock, per-CPU base register | `hart_id`, `wfi`, `cpu_idle(depth)`, `halt`, `now_ticks`, `percpu_base`, `set_percpu_base` |
| `Interrupts` | Local interrupt enable, timer deadline, IPI | `disable_all` / `restore` (with the `InterruptState` token), `enable_all`, `interrupts_enabled`, `set_timer_deadline`, `send_ipi` |
| `Mmu` | Page-table entry encoding for a level-aware radix tree; TLB maintenance | `levels`, `vpn`, `pte_make_table`, `pte_make_leaf`, `pte_perms`, `pte_share_cow`, `pte_break_cow`, `pte_make_demand`, `pte_make_marker`, `switch_pt`, `flush_tlb_*`, `tlb_shootdown`, `block_change_needs_bbm` |
| `Boot` | Machine lifecycle and secondary-hart start | `shutdown`, `reboot`, `hart_start` (returns `HartStartError`) |
| `Vector` | Optional SIMD kernels with a scalar fallback | `dot_f32` |
| `SpinWait` | Spin-wait hints and compare-and-swap | `cpu_relax`, `cas32`, `cas64`, `swap32`, `tas_acquire32`, `qlock_acquire32`, `wait_hint32`, `wait_while32`, `wait_while64` |
| `Hypervisor` | Hardware virtualization: stage-2 tables, exit decode, guest entry | `kind`, `status`, `stage2_create`, `stage2_map`, `stage2_unmap`, `decode_exit`, `can_enter`, `enter` |
| `ArchPlatform` | ISA primitives shared crates need | `dcache_clean`, `icache_sync_all`, `flush_tlb_page_all`, `zero_memory`, `cpu_seed`, `user_root_word`, `install_user_root_local`, `user_access` |
| `ArchEntry` | The kernel's boot sequence, per ISA | See [Boot hooks](#boot-hooks) |

Design points that the module documentation states and the code follows:

- **The MMU trait encodes entries; it does not walk tables.** `crates/core/mm` owns the walk (allocating tables, splitting superpages, copy-on-write and demand-paging policy). The trait deals in raw `u64` entry words plus a `level`, because a leaf test depends on level on aarch64 and not on riscv64. Trait level 0 is the leaf level on every ISA. Copy-on-write and demand markers are software bits in the entry (riscv64 RSW, aarch64 software bits, x86_64 available bits); `PageMarker` and `pte_make_marker` use the same seam on a not-present entry.
- **Page size is a build-time constant.** `PAGE_SHIFT` and `PAGE_SIZE` are free constants chosen by the cargo features `page-16k` and `page-64k` (neither means 4 KiB; both is a `compile_error!`). `PageAlign` is a zero-sized type with that alignment, for statics that must sit on a page boundary.
- **`Interrupts::restore` restores the enable state only.** It must not write back other architectural state captured with it.
- **`Cpu::cpu_idle` is the single idle seam.** Depth 0 is `wfi`; deeper depths map to the platform's idle-state table where the ISA can enter one, and fall back to a shallower state otherwise. It returns the measured sleep in microseconds (`ticks_to_us` is the shared conversion).
- **`Cpu::now_ticks` is monotonic, not wall-clock.** Units are platform-defined; the same timebase as `Interrupts::set_timer_deadline`.
- **Hart count is not an ISA fact.** It comes from firmware discovery (device tree, ACPI), so it is deliberately not in `Cpu`.
- **Controller programming is not in the contract.** PLIC, GIC and IOAPIC register programming live in the ISA crate's `irq` module; the contract exposes only the kernel's notion of interrupt enable, deadline and IPI. Which controller a boot drives is `irqchip_probe`'s decision from the device tree: PLIC or AIA on riscv64, GICv3 or GICv2 (`arm,gic-400`, `arm,cortex-a15-gic`) on aarch64; the callers of `azos_arch::irq::gic` do not know which.

Most `ArchPlatform` and `ArchEntry` methods are required, so a new ISA learns what it must provide from the compiler. A few have defaults:

| Item | Default |
|---|---|
| `ArchPlatform::user_root_asid`, `user_root_with_asid` | No ASID tagging (0 / word unchanged) |
| `ArchPlatform::publish_user_root`, `flush_tlb_all_contexts_local` | No-op |
| `ArchPlatform::tlb_space_key`, `user_root_frame` | 0, and `tlb_space_key`, respectively |
| `ArchEntry::CONSOLE_MMIO` | `true` (the console UART is a memory-mapped window) |
| `ArchEntry::pmm_floor` | The end of the kernel image |
| `Mmu::root_entries`, `pte_global_bit`, `asid_bits`, `contig_run_pages` and the contiguous-run helpers | Root table as large as `entries_per_table`, no global bit, no ASID bits, no contiguous runs |
| `Hypervisor::can_enter`, `enter` | `false`, and `Exit::InvalidState` |

### Helper modules

| Module | Contents |
|---|---|
| `isa` | The extension policy model; see [Extension model](#extension-model). |
| `spin` | `SpinWait`, `CasOrder`, the boot-patch site keys, and the out-of-line slow paths `lock_slow32` and `tas_slow32`. |
| `tlb_gen` | Per-hart TLB generation, so an address-space switch can skip a flush when no shootdown was missed; the optional per-address-space hart mask. |
| `contig` | ISA-neutral arithmetic for runs of contiguous level-0 leaves (aarch64 contiguous hint, riscv64 Svnapot). x86_64 reports run length 0. |
| `entropy` | The CPU entropy instruction as a seed source: `CpuSeed`, `CpuCredit`. |
| `lat` | Masked-window tracer bookkeeping, compiled only with the `lat-trace` feature. |

Source: `crates/core/arch-api/src/lib.rs`, `contract.rs`, `isa.rs`, `spin.rs`, `tlb_gen.rs`, `contig.rs`, `entropy.rs`, `lat.rs`.

### Boot hooks

`ArchEntry` is implemented by the kernel (`kernel/src/entry/<isa>/arch_entry.rs`), not by the ISA crates, because the hooks drive kernel subsystems. The kernel instantiates it as the zero-sized constant `ARCH_ENTRY` in `kernel/src/main.rs`, so a call through it compiles to the hook body. The shared early boot (`kernel/src/boot/early.rs`) owns the step order and log lines and calls the hooks at the points where ISAs differ.

| Step group | Hooks |
|---|---|
| Before and around the console | `pre_console`, `trap_init`, `boot_banner` |
| Firmware table | `firmware_table`, `kernel_cmdline`, `firmware_memory`, `firmware_done`, `reserve_firmware_table`, `pmm_floor` |
| Interrupt controller and timer | `irqchip_probe`, `timer_probe`, `irq_trigger_controller`, `irq_triggers`, `irqchip_init`, `irq_enable_early`, `console_irq`, `line_hooks`, `irq_routing_init`, `timer_init` |
| CPU features | `cpu_features` |
| Memory map | `kernel_mmio_windows`, `mmu_enabled`, `restrict_low_half`, `verify_guards`, `post_heap`, `map_late_mmio` |
| Patching and self-tests | `boot_patch`, `boot_selftests` |
| SMP | `smp_probe`, `wake_secondaries`, `enter_scheduler`, and the secondary-CPU hooks `secondary_tlb_online`, `secondary_irq_init`, `secondary_timer_init`, `secondary_publish_online` |
| vDSO clock | `timebase_hz`, `vdso_clock`, `vdso_counter_scale` |

`LineHooks` is a table of function pointers (`release`, `mask`, `unmask` and the `msi_*` set) the kernel installs once so the ring-3 interrupt binding table stays free of interrupt-controller code. `FirmwareMemory` is the RAM and CPU summary `firmware_memory` returns.

Source: `crates/core/arch-api/src/contract.rs`, `kernel/src/boot/early.rs`, `kernel/src/boot/smp.rs`, `kernel/src/main.rs`.

## The facade

`azos_arch` selects one ISA crate by `target_arch` and re-exports everything in it (`pub use azos_arch_<isa>::*`). It also gives the active implementation a uniform name:

- `azos_arch::ARCH` is the zero-sized singleton (`RISCV64`, `AARCH64` or `X86_64_ARCH` in the ISA crates).
- `azos_arch::ArchImpl` is its type, for associated items such as `<ArchImpl as Mmu>::PAGE_SIZE`.

```rust
use azos_arch::{Interrupts, ARCH};
let prev = ARCH.disable_all();
// critical section
ARCH.restore(prev);
```

Every method on the singletons is `#[inline]`, so a call through `ARCH` is static: no `dyn`, no table.

Selection rules:

- riscv64 and aarch64 are selected by `target_arch`. The aarch64 branch also requires `target_os = "none"`, so a host `cargo test` on an aarch64 machine does not pull in EL1 system-register assembly.
- The cargo feature `stub` selects `azos_arch_x86_64` on any target. Off x86_64 its contract methods are `todo!()`s naming the x86 mechanism, so a shared crate that reaches past the contract fails to check under `stub`.
- A bare-metal target with no port hits a `compile_error!` instead of getting an empty facade.

Callers can also reach ISA modules the facade re-exports (`cpu`, `mmu`, `irq`, `ext`, and so on) directly. The facade lint below tracks and ratchets those references.

Source: `crates/core/arch/src/lib.rs`, `crates/core/arch/Cargo.toml`.

## Extension model

Each ISA has a baseline level and a list of optional extensions. The baseline is the only thing code generation assumes; each extension is a three-way `make config` choice.

| Policy (`ExtPolicy`) | Kconfig member | Meaning |
|---|---|---|
| `Never` | `<EXT>_NEVER` | Never used, even if the CPU has it. The path is compiled out or never selected, and the vDSO hwcap word hides it. |
| `Probe` | `<EXT>_PROBE` (the default) | Compiled in; used only if the boot probe finds it, with a fallback otherwise. |
| `Require` | `<EXT>_REQUIRE` | Part of the baseline. Code may assume it; the boot refuses a CPU without it. |

At boot each policy is combined with the probe result into an `ExtState`: `Off`, `Present`, `Absent`, `Required` or `Missing`. `ExtPolicy::gate(present)` is the selection input a code path uses (the hardware's answer unless the policy is `Never`). The boot prints one line, `[ISA] baseline=<level> <name>=<state> ...`, with `n`, `probed-present`, `probed-absent`, `required` or `MISSING` per extension. A `Missing` extension, or a CPU below the baseline level, produces an `[ISA] FATAL:` refusal that names the Kconfig symbol to change.

The per-ISA tables live in `azos_arch_api::isa::{riscv64, aarch64, x86_64}` as `ExtPolicy` constants built from the generated `azos_limits` constants. Every ISA's table compiles on every build; an unselected ISA's choices read as `Probe` and nothing consumes them.

| ISA | Baseline levels | Extension policies (names in `isa.rs`) |
|---|---|---|
| riscv64 | `rv64imac`, `rv64gc`, `rv64gcv` | `ZICBOZ`, `ZICBOM`, `SSTC`, `SVPBMT`, `SVNAPOT`, `SVINVAL`, `ZBA`, `ZBB`, `ZBS`, `V`, `AIA`, `ZAWRS`, `ZACAS`, `ZIHINTPAUSE`, `ZKR`, `H`, `SSQOSID`, `PMU` |
| aarch64 | `armv8.0` to `armv8.5` | `LSE`, `PAN`, `CRC32`, `PAUTH`, `BTI`, `MTE`, `SVE`, `AES`, `PMULL`, `SHA2`, `RNG`, `E0PD`, `WFXT`, `TLBIRANGE`, `PMU`, and the speculation mitigations `MIT_SPECTRE_V2`, `MIT_SSB`, `MIT_BHB` |
| x86_64 | `x86-64`, `x86-64-v2`, `x86-64-v3`, `x86-64-v4` | `SSE4_2`, `POPCNT`, `XSAVE`, `AVX`, `AVX2`, `AVX512*`, `BMI1`, `BMI2`, `FMA`, `AES`, `PCLMULQDQ`, `SHA_NI`, `RDRAND`, `RDSEED`, `PCID`, `INVPCID`, `SMEP`, `SMAP`, `UMIP`, `X2APIC`, `TSC_DEADLINE`, `WAITPKG`, `SVM`, `VMX`, `PMU`, and the `MIT_*` mitigation set |

### Probe sites that rewrite themselves

A `Probe` extension that replaces a hot-path instruction (compare-and-swap, a wait hint, a relax hint) is a boot-once patch site. `SpinWait` documents the table:

| ISA | `cas32` / `cas64` | `wait_hint*` | `cpu_relax` |
|---|---|---|---|
| riscv64 | Zacas `amocas` | Zawrs `lr` + `wrs.nto` | `pause` (Zihintpause) |
| aarch64 | LSE `CAS` | `sevl` / `wfe` / `ldaxr` / `wfe` | `isb` |
| x86_64 | `lock cmpxchg` | WAITPKG `umonitor` / `umwait` | `pause` |

The provided `SpinWait` bodies are the fallback every ISA has without the extension (`core::sync::atomic`, a relax loop); an ISA overrides what it has a better instruction for. Under `Never` only the fallback is compiled. Under `Require` the extension is inlined with no branch. Under `Probe` (riscv64, aarch64) each use is a site in the `.azos_keys` section, linked as the safe form and rewritten once on the boot CPU, before secondaries start, if the probe found the extension (`ArchEntry::boot_patch`, `kernel/src/boot/spin_patch.rs`, site keys `SITE_KEY_CAS`, `SITE_KEY_WAIT`, `SITE_KEY_RELAX`). After boot a probe site costs what a `Require` site costs. Callers never name an ISA. Orderings are explicit (`CasOrder`: relaxed, acquire, release, acquire-release) and never sequentially consistent.

Source: `crates/core/arch-api/src/isa.rs`, `crates/core/arch-api/src/spin.rs`, `config/arch/Kconfig.isa`, `kernel/src/boot/spin_patch.rs`.

## Per-ISA layout

`tools/arch_layout_lint.py` holds a required set of top-level modules for three directories. A module outside that set must sit under `ext/` (ISA-only code goes there). Where an ISA does not have a required module, or keeps an extra module outside `ext/`, the lint lists the exception with its reason; the tables below give the required set and then those exceptions.

| Directory | Required modules |
|---|---|
| `crates/core/arch-<isa>/src` | `api_impl`, `cache`, `cpu`, `ext`, `firmware`, `fork_regs`, `fp`, `irq`, `lat_hook`, `mmu`, `platform_impl`, `seed`, `smp`, `spin`, `timer`, `tlb`, `trap` |
| `kernel/src/entry/<isa>` | `arch_entry`, `asm`, `board_map`, `boot_hooks`, `ext`, `fp`, `irq`, `resume`, `smp`, `trap` |
| `kernel/src/entry/<isa>/asm` | `boot.S`, `context_switch.S`, `trap_entry.S` |

A module name is the stem of `foo.rs` or `foo.S`, or a directory `foo/`.

**Required modules an ISA lacks** (`ALLOW_MISSING`). The ISAs do not all expose the full set today:

| ISA | Directory | Missing module | Reason given in the lint |
|---|---|---|---|
| riscv64 | ISA crate | `fork_regs` | No such module yet |
| riscv64 | ISA crate | `smp` | Secondary harts start from `kernel/src/entry/riscv64/smp.rs` (SBI HSM `hart_start`) |
| riscv64 | ISA crate | `timer` | The timer is the CLINT/ACLINT in `irq/clint.rs` |
| riscv64 | kernel entry | `fp` | FP state is saved by the ISA crate's `fp` and `context_switch.S`; no entry hook |
| aarch64 | ISA crate | `tlb` | TLBI sequences live in `mmu` and `api_impl` |
| aarch64 | ISA crate | `trap` | The `TrapFrame` lives in `kernel/src/entry/aarch64/mod.rs` |
| x86_64 | ISA crate | `api_impl` | The `Cpu`, `Interrupts` and `Mmu` impls are inline in `lib.rs` |
| x86_64 | ISA crate | `cache` | x86 DMA is cache-coherent; no maintenance operations to host |
| x86_64 | ISA crate | `lat_hook` | `lat-trace` is not implemented on x86_64 |
| x86_64 | kernel entry | `board_map` | The memory map comes from Limine (`entry/x86_64/ext/limine.rs`) and ACPI, not a board table |

**Extra modules outside `ext/`** (`ALLOW_EXTRA`):

| ISA | Module | Note in the lint |
|---|---|---|
| aarch64 | ISA crate `sysregs` | System register accessors; belongs under `ext/` (the move is pending: its uses repoint across the kernel, mm, sched and the host suites at once) |
| riscv64 | `asm/context_switch_rvv.S` | The RVV context-switch variant (`rvv` feature) |
| x86_64 | `asm/ap_entry.S` | The AP long-mode entry (SIPI start) |

ISA-only modules otherwise sit in each ISA's `ext/`:

| ISA | ISA crate `ext/` | Kernel entry `ext/` |
|---|---|---|
| riscv64 | `pmp`, `hv`, `napot` | `hv`, `zicboz` |
| aarch64 | `hv`, `mitigations`, `sha2_ce`, `tlbi_range`, `wfxt` | `hv_vectors`, `pan_patch`, `selftests` |
| x86_64 | `hv`, `mitigations`, `retpoline`, `splitlock` | `cpu_init`, `hv`, `limine` |

Each ISA crate's `lib.rs` also re-exports the contract (`pub use azos_arch_api::{...}`), so a caller written against `azos_arch` sees the same names on every ISA. On x86_64 the hypervisor module is declared as `hv` at the crate root with `#[path = "ext/hv/mod.rs"]` and re-exported as `azos_arch::HvImpl`, because it builds on the crate's `mmu` module.

Source: `crates/core/arch-*/src/lib.rs`, `crates/core/arch-*/src/ext/mod.rs`, `kernel/src/entry/*/ext/mod.rs`, `tools/arch_layout_lint.py`.

## Generic trap layer

What the kernel does when the hardware traps is written once in `kernel/src/trap/` and instantiated per ISA by generics. A build has one frame type and one services type, so there is one instantiation of each function and no virtual call on the syscall path. The same sources compile on the host against fake frames and services (`tests/host/trap-tests`).

| File | Policy |
|---|---|
| `frame.rs` | `Frame` (the common view of a saved frame), `TrapClass`, `KernelFault`, `EntryKind`, `Cow`, `Disposition`, and the services traits `SyscallServices`, `FaultServices`, `IrqServices` |
| `syscall.rs` | The syscall flow `enter` and its `prologue` (entry tracepoint, entry counted by foundational case) |
| `fault.rs` | Page-fault policy `page_fault`, exception policy `exception`, the fatal tail `fatal_note` |
| `irq.rs` | The interrupt bracket `arm`, the shared tick work `tick_work`, the reschedule point `resched_exit` and the per-CPU `Resched` flags |
| `kernel.rs` | `Kernel`, the one implementation of the services over scheduler, memory manager, tracer and console; `ArchFrame`; the static `RESCHED` |
| `crash.rs` | The ring-3 crash dump (cargo feature `crashdump`) |

`frame.rs`, `syscall.rs`, `fault.rs` and `irq.rs` name nothing outside `core` and `azos_abi`; everything else they need is a method of a services trait, implemented once in `kernel.rs`.

**What an ISA supplies.** `Frame` is the decode: `class`, `came_from_user`, `fault_cause`, `fault_addr`, `fault_is_write`, `pc`, `syscall_number`, `syscall_arg`, `set_syscall_return`, `skip_syscall`, `user_kill_status` (the signal a bad instruction earns), and the register dump `print` and `print_kernel_fault`. `ArchFrame` adds the parts that name kernel types: how the IPC fast path reads the frame, how the argument list and the fork snapshot are built, how an `exec` frame is laid out, how signals are delivered. The assembly stub (`asm/trap_entry.S`, with its control-flow landing pads), the cause decode and the interrupt controller (`irq.rs`: claim, end-of-interrupt, the line ladder) stay in `kernel/src/entry/<isa>/`. ISA-specific exception cases come back through `FaultServices::arch_page_fault` and `arch_exception`, which return a `Disposition` (`Resume`, `Default`, `Fatal`, `Kill`).

**Rules the policy implements.**

- Syscall flow, in order: interrupts on; the seccomp filter verdict; the prologue; the call (a number-only shortcut, the IPC fast path, or the dispatch); result, exit tracepoint and the step over the trap instruction; at the return to user mode, an `exec`'s new frame and signal work. A Linux task's number is not in the native table, so its entry is counted in slot 0 with no case.
- Faults: a fault from user mode kills that task, never the kernel; a fault from the kernel is fatal. A page fault tries copy-on-write (for a write), then demand paging; what neither resolves ends the task with `SIGSEGV`.
- Interrupts: a handler runs on the hart's interrupt stack and may only raise the reschedule flag (`Resched::request`); `resched_exit` spends it from the entry assembly once `sp` is back on the interrupted task's own stack.

Source: `kernel/src/trap/mod.rs`, `frame.rs`, `syscall.rs`, `fault.rs`, `irq.rs`, `kernel.rs`, `crash.rs`; per-ISA `kernel/src/entry/<isa>/trap.rs` and `asm/trap_entry.S`.

## Lints

Three scripts under `tools/` keep the structure above from eroding. Each has a `--self-test` mode that builds synthetic violations and fails unless every rule turns the lint red. Each exits non-zero on a finding.

| Script | What it checks |
|---|---|
| `tools/arch_cfg_lint.py` | Shared code must neither vanish on a new ISA nor reach past the facade. Two ratchets. |
| `tools/arch_layout_lint.py` | The three ISAs expose the same module set (table above). |
| `tools/trap_lint.py` | Dispatch logic stays in `kernel/src/trap/`, out of `kernel/src/entry/<isa>/`. |

### `arch_cfg_lint.py`

**Part 1: `cfg(target_arch)` branches that vanish.** A positive `target_arch` guard outside the arch crates (an outer `#[cfg]`, an inner `#![cfg]`, or an `if cfg!(..) { }` without `else`) is a violation unless it is covered by one of:

- a predicate that mentions `target_arch` under `not(...)` (it is the else branch);
- a chain of adjacent sibling items, each guarded by a `target_arch` cfg, where some member is an else branch or contains `compile_error!`;
- a file-level `compile_error!` guard for unknown ISAs;
- a `cfg!(..)` used as a value, or as an `if` condition with an `else`;
- a `// arch-only: <why>` comment directly above it, recording a reviewed decision that the code has no counterpart elsewhere.

A `riscv64` / `aarch64` pair is not a complement: it vanishes on x86_64. `cfg_attr` is exempt. Files that build for one ISA only (`kernel/src/entry/<isa>*`, `<isa>_*.rs`) are exempt.

**Part 2: facade bypass.** A facade reference is a path `azos_arch::<module>...` whose module is not present on all three ISA crates (`csr`, `sbi`, `rvv`, `sysregs`, `gic`, `mpidr`, `fp_state`, `fpu`, `hw`, `cbo` and so on), or `irq::<chip>` (`irq::plic`, `irq::gic`, `irq::apic`), or anything under `ext::`. The module sets are read by name from each arch crate's `lib.rs` and `irq/mod.rs`, so a rename inside an arch crate moves nothing. `use azos_arch::{..}` groups count one per leaf, and `use azos_arch::csr;` counts the import and each later use.

**Ratchet.** `tools/arch_cfg_lint.baseline` lists per-file counts for each part (the `[facade]` section holds part 2). A file above its count, or a file not listed with any violation, fails. A file below its count passes and is reported. `--update-baseline` lowers the cfg counts and refuses to raise any; `--update` rewrites the facade section and may raise a count, as the explicit step after a rename.

| Invocation | Effect |
|---|---|
| `python3 tools/arch_cfg_lint.py` | Both ratchets |
| `... --facade` | Facade ratchet only |
| `... --list [PATH]`, `--list-facade [PATH]` | Every violation or facade reference, with line |
| `... --update-baseline`, `--update` | Rewrite the cfg part (lower only) or the facade part |
| `... --self-test` | Canaries on built fixtures |

### `arch_layout_lint.py`

Compares the module sets of the three directories in the [Per-ISA layout](#per-isa-layout) table. It fails when:

1. a required module is missing on an ISA and the gap is not in `ALLOW_MISSING`;
2. an `ALLOW_MISSING` row is stale (the module exists, is not required, or names an unknown ISA);
3. a module outside the required set sits at the top level of a directory instead of under `ext/`, and is not in `ALLOW_EXTRA`;
4. an `ALLOW_EXTRA` row is stale (the module is gone, or is required now);
5. an arch or entry directory has no `ext/`.

Every allowlist row carries its reason, and the lint turns red when a row stops being true, so a gap that closes must be deleted from the list.

### `trap_lint.py`

Fails when:

1. a source in `kernel/src/entry/<isa>/` names a syscall number (`SYS_*`);
2. an entry source calls the fault policy (copy-on-write and demand-paging handlers, the kill and fatal-tail functions) or the syscall filter and dispatch entry points;
3. a syscall number in `crates/core/abi/src/syscall_nr.rs` has no foundational case row in `SYSCALL_CASE` (`CASE_AUTHORITY` or `CASE_BLOCK_WAKE`), or a row names a number that does not exist, or a row's case is not one of the two;
4. one of the host-testable files (`frame.rs`, `syscall.rs`, `fault.rs`, `irq.rs`) names a kernel crate: they may name `core` and `azos_abi` only.

Comments and string literals are not scanned. A line meant to break a rule anyway carries `trap-lint: ok` in a trailing comment.

Source: `tools/arch_cfg_lint.py`, `tools/arch_cfg_lint.baseline`, `tools/arch_layout_lint.py`, `tools/trap_lint.py`, `tools/ci_check.sh`.
