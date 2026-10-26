# aarch64: masking interrupts across the trap return

A system call runs with interrupts enabled, so the code that leaves the kernel
must close them again before it writes the registers that hold the return
state. This note records why, which windows that rule closes on aarch64, and
what was ruled out. riscv64 has the same hazard and solves it by CSR ordering;
this note covers only aarch64.

## Contents

1. The rule
2. The hazard
3. The window, step by step
4. Where the mask sits
5. Ruled out
6. Regression probe

## 1. The rule

Every path that returns to EL0 masks all four DAIF classes with
`msr DAIFSet, #0xf` before it writes `ELR_EL1`, `SPSR_EL1`, `SP_EL0` or
`TTBR0_EL1`, and before `PAC_EXIT` loads the process's pointer-authentication
key. `eret` then restores the mask from the saved `SPSR_EL1` in the same
instant it restores the program counter, so nothing stays masked past the trap.

The generic syscall flow switches interrupts on for the body of a call
(`interrupts_on` in `kernel/src/trap/syscall.rs`, implemented in
`kernel/src/trap/kernel.rs` as `ARCH.enable_all()`, which `api_impl.rs` runs as
`sysregs::enable_irq`, `msr DAIFClr, #2`, in
`arch/aarch64/src/sysregs.rs`). On the way out the return code is
responsible for closing them.

Source: `kernel/src/trap/syscall.rs`, `kernel/src/trap/kernel.rs`,
`arch/aarch64/src/api_impl.rs`, `arch/aarch64/src/sysregs.rs`.

## 2. The hazard

Hardware masks `DAIF.I` on every exception entry, so the entry side is safe.
The return side is not, for two reasons.

- Once a syscall has run `enable_all`, `DAIF.I` stays clear until something
  masks it again. Writing `SPSR_EL1` only sets the `PSTATE` that `eret` will
  restore; it does not change the hart's own live `DAIF`. aarch64 has no single
  register whose write both sets the target state and clears the live mask.
- A real interrupt that lands after the writes of `ELR_EL1` and `SPSR_EL1` and
  before `eret` takes a nested EL1 exception. Exception entry unconditionally
  overwrites both registers with the interrupted program counter and `PSTATE`.
  The nested trap's own return resumes exactly where the outer return was
  interrupted, but it does not restore the outer frame's saved values, because
  the outer code never reads them a second time. When the outer return reaches
  its `eret`, `ELR_EL1` and `SPSR_EL1` hold whatever the nested trap left, not
  the syscall's return state, and the hart jumps to a wrong address.

The nested trap builds its own frame lower on the kernel stack, so there is no
memory overlap with the outer frame. The defect is purely the two registers.

This is the aarch64 counterpart of the riscv64 hazard in which a trap between
the write of `sepc` and the write of `sstatus` clobbers `sepc`. riscv64 closes
it by writing `sstatus` first (`trap_return` in
`kernel/src/entry/riscv64/asm/trap_entry.S`). aarch64 has no free reorder, so it
spends one mask instruction.

There is no analogue of the riscv64 `sscratch` problem. riscv64 has one stack
pointer and a software swap with `sscratch` that tags whether the trap came from
S-mode or U-mode. aarch64 banks `SP_EL0` and `SP_EL1` in hardware, and exception
entry always runs on `SP_EL1` with no software swap. No software stack-pointer
swap exists anywhere in `trap_entry.S`.

Source: `kernel/src/entry/aarch64/asm/trap_entry.S`,
`kernel/src/entry/riscv64/asm/trap_entry.S`.

## 3. The window, step by step

Order of operations in the return tail of `kernel/src/entry/aarch64/asm/trap_entry.S`,
read as if interrupts were open at that step. The tail has no FP/SIMD restore:
the kernel is soft-float, so the interrupted code's FP registers are still in
the hardware, and user FP state is saved lazily by the context switch.

| Step | Hazard with interrupts open | Why |
|---|---|---|
| `msr ELR_EL1` | **opens** | A nested exception overwrites it. |
| `msr SPSR_EL1` | open | Same. |
| `PAC_EXIT`: the process's `APIAKey*_EL1` (Kconfig `A64_PAUTH_PROC_KEYS`, a return to EL0 only) | open | A nested EL1 exception from EL1 runs with whatever key is loaded, the process's instead of the kernel's. |
| `msr SP_EL0` | safe | A separate banked register; a nested EL1 exception never touches it. |
| `TTBR0_EL1` switch, `isb`, `tlbi`, `dsb`, `isb` | not a data hazard | `TTBR0_EL1` survives nesting and kernel text is mapped through `TTBR1`, so a nested handler runs unaffected. It is still inside the masked window, for uniformity. This step runs only when a new table is supplied (an `exec` hand-off, or the first entry of a fresh or forked task); an ordinary return does not write `TTBR0_EL1`. |
| General-register restore | safe | A nested trap saves and restores the general registers around itself. |
| `add sp, sp, #TRAP_FRAME_SIZE` | safe | Part of the tail. |
| `eret` | **closes** | Restores `PC` from `ELR_EL1` and `PSTATE`, including `DAIF`, from `SPSR_EL1`. |

With the mask taken first, none of the steps between the mask and `eret` can
take an interrupt.

Source: `kernel/src/entry/aarch64/asm/trap_entry.S`.

## 4. Where the mask sits

Every return to EL0 goes through one of the following, and each masks before it
touches the return registers.

- `trap_return`: the first instruction is `msr DAIFSet, #0xf`. It covers both
  ways into the tail, the fall-through after a synchronous exception or system
  call and the branch from the interrupt path.
- `aarch64_ret_to_user` and `aarch64_ret_to_user_tls`: a task's first entry into
  a fresh image and a forked child's first entry. The caller builds an ordinary
  `TrapFrame` on its kernel stack; the stub masks, points `sp` at the frame,
  loads the new table root into `x19`, and branches to `trap_return_masked`,
  the label just after the mask in `trap_return`. The TLS variant also writes
  `TPIDR_EL0` after the mask, on the hart about to `eret`. The mask is first, so
  the move of `sp` is covered as well.
- `_svc_native_return`: the exit of the lean native system-call entry
  (`SYSCALL_LEAN_ENTRY`) has its own copy of the mask ahead of its register
  writes, because it does not restore through `trap_return`.
- `aarch64_ipc_resume_stub`: the resume point of the IPC fast path does not
  return on its own. It selects `_svc_native_return` for a frame the lean entry
  saved and `trap_return` for a fully saved one, so both are covered.

All of them mask every DAIF class, not only `I`, so one convention serves the
whole file.

Source: `kernel/src/entry/aarch64/asm/trap_entry.S`,
`kernel/src/entry/aarch64/trap.rs`.

## 5. Ruled out

- **`ESR_EL1` and `FAR_EL1`.** Read once into the frame at entry and never read
  again by the return tail, so a nested trap clobbering the live registers is
  irrelevant.
- **`context_switch.S`.** It touches `DAIF` nowhere. A task that is switched in
  resumes inside its own kernel path and leaves through one of the masked tails
  above. The interrupt arm never calls `enable_all`, so on that path the hart is
  still hardware-masked when the tail starts; the hazard is specific to the
  system-call return path.
- **The boot-time unmask.** The one-time `enable_all` in `boot_hooks.rs` that
  starts steady-state interrupt delivery is unrelated to the per-syscall enable.
- **A global "current trap frame" pointer.** None exists on aarch64. The `exec`
  hand-off writes to the frame only through the `&mut TrapFrame` it was given, so
  a nested interrupt's own dispatch cannot alias it.

Source: `kernel/src/entry/aarch64/asm/context_switch.S`,
`kernel/src/entry/aarch64/boot_hooks.rs`, `kernel/src/entry/aarch64/trap.rs`.

## 6. Regression probe

The opt-in kernel feature `irq-in-syscall-probe` adds a reserved syscall number
that the entry intercepts before dispatch. Its own `enable_all` starts the
clock, and it spins reading the generic timer across several timer ticks with
interrupts enabled. A return tail without the mask would wedge, or corrupt
another task's kernel stack, on a nested interrupt in the window; a clean return
after many ticks is evidence that the window is closed, not proof from one
non-crash. The feature is shared with riscv64 and is not part of any default
build.

Source: `kernel/Cargo.toml` (`irq-in-syscall-probe`),
`kernel/src/entry/aarch64/trap.rs`, `kernel/src/entry/riscv64/trap.rs`.
