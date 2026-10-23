# Trap and address-space switch cost

A control loop pays the kernel for every trap it takes and every time the
scheduler changes address space. This note describes how the kernel keeps both
small: one generic trap layer written once for all three ISAs, a lean entry for
native system calls, calls that fold two traps into one, time reads that need no
trap, and address-space switches that keep the TLB. It describes the code as it
is; it does not say how fast any of it is.

## Contents

1. The generic trap layer
2. Per-ISA entry
3. Time without a trap
4. The timer
5. Reply and accept in one trap
6. The driver server loop
7. A control period through `io_ring`
8. Address-space switches that keep the TLB
9. Limits

## 1. The generic trap layer

The policy for what the kernel does on a trap is written once, over a common
view of a saved frame, and shared by riscv64, aarch64 and x86_64.

- `Frame` (in `kernel/src/trap/frame.rs`) is the decoded view of an ISA's trap
  frame: which register is the syscall number, how the cause register
  classifies the trap (`TrapClass`: interrupt, syscall, page fault, other
  exception), whether a fault was a write.
- Three service traits, `SyscallServices`, `FaultServices` and `IrqServices`,
  are what the policy asks of the rest of the kernel. `kernel/src/trap/kernel.rs`
  implements them once, over the scheduler, the memory manager and the tracer.
- The policy files are `syscall.rs` (the syscall flow), `fault.rs` (page-fault
  and exception policy, the fatal tail) and `irq.rs` (the interrupt bracket and
  the reschedule point). They name nothing outside `core` and `azos_abi`, so
  the host test crate `tests/host/trap-tests` compiles them unchanged against
  fake frames.
- Generics, not trait objects: a build has one frame type and one services
  type, so there is one instantiation of each function and no virtual call on
  the trap path.
- `tools/trap_lint.py`, a row of `make check0` (`tools/gate_tier.sh n0`),
  fails if dispatch logic (a syscall number, the page-fault policy, the fatal
  tail) reappears under `kernel/src/entry/`, or if one of the four policy files
  names a kernel crate.

The syscall flow (`enter` in `kernel/src/trap/syscall.rs`) runs in this order:

1. `probe`: a build-time hook that can answer a reserved number before anything
   else.
2. Interrupts are switched on. The trap return masks them again before it
   touches the return address (see
   [aarch64 trap-return windows](arch/aarch64-trap-return-windows.md)).
3. The filter verdict (`azos_syscall::syscall_verdict`). A native task's number
   is checked against its seccomp profile before anything else; a denied call
   kills the task. A Linux-personality task's number is not looked up here: it
   is sent to the personality, which checks the profile on each native call
   its translation reaches.
4. The prologue (`prologue`): the entry tracepoint, the entry counted in the
   running Domain under the call's foundational case (`syscall_case`), and the
   Domain's pledge mask, which refuses the call with `EACCES` before it runs.
5. The call itself. A native call may be answered from its number alone
   (`azos_syscall::syscall_register_only`: `SYS_GETPID`, `SYS_YIELD`), may take
   the IPC fast path when the lean entry selected it, or goes to the table. The
   table `SYSCALL_TABLE` in `crates/core/syscall/src/dispatch.rs` is indexed by
   the number and holds one handler per syscall. Operations on a handle the
   caller holds are not syscalls: they are ops of `SYS_INVOKE`
   (`crates/core/syscall/src/invoke.rs`), selected by the handle's type and an
   op word.
6. The result is written, the exit tracepoint fires, the trap instruction is
   stepped over.
7. If the call was an `exec`, the new image's frame is entered
   (`azos_sched::ExecHandoff`); otherwise pending return work (signals, foreign
   traps) runs.

A call that returns more than one register uses `SyscallOut`
(`crates/core/syscall/src/syscall_out.rs`), a write-back channel of
`SYSCALL_OUT_REGS` words that the entry copies into the frame only when the
handler marked it written.

Source: `kernel/src/trap/mod.rs`, `kernel/src/trap/frame.rs`,
`kernel/src/trap/syscall.rs`, `kernel/src/trap/kernel.rs`,
`crates/core/syscall/src/dispatch.rs`, `crates/core/syscall/src/syscall_out.rs`,
`tools/trap_lint.py`, `tests/host/trap-tests`.

## 2. Per-ISA entry

Each ISA keeps what only it can do under `kernel/src/entry/<isa>/`: the
assembly stub that saves and restores the frame
(`asm/trap_entry.S`), the register decode and cause classification (`trap.rs`),
and the interrupt-controller code (`irq.rs`).

**Native calls save less.** The native syscall ABI
(`crates/core/abi/src/syscall_nr.rs`, "Register contract") lets ring 3 rely on
the callee-saved registers, the stack, thread and global pointers, the link
register and the call's output registers, and nothing else. With Kconfig
`SYSCALL_LEAN_ENTRY`, a native task's syscall takes an entry that does not
store the clobbered registers and returns them zeroed, so nothing the kernel
left in them reaches ring 3. Every other trap takes the full save, and so does
every Linux-personality task (whose ABI preserves everything) on riscv64 and
aarch64. There the entry tells the two apart by a tag in the frame, written once when the task
first enters user mode and never by a trap: a user trap whose cause equals the
frame's tag is a native task's syscall. On x86_64 only a `syscall` instruction
reaches `syscall_entry`, and the Linux ABI clobbers `rcx` and `r11` as well, so
every `syscall`, Linux tasks' included, takes the lean path.

| ISA | Lean entry | What is clobbered and zeroed |
|---|---|---|
| riscv64 | `trap_from_user` in `asm/trap_entry.S` | `t0`-`t6`, `a7` |
| aarch64 | `_svc_native` | `x10`-`x17` |
| x86_64 | `syscall_entry` | `rcx`, `r11` (which `sysret` loads) |

**The IPC fast-path branch.** With Kconfig `IPC_FASTPATH`, the lean entry tests
the syscall number against the pair `SYS_IPC_FAST_REPLY_ACCEPT` and
`SYS_IPC_FAST_CALL_EP` (the ABI keeps them two apart, which the kernel asserts
in `kernel/src/main.rs`, so one subtract-and-mask tests both) and branches to a
frame that runs `azos_syscall::fastpath::entry` directly. A call whose peer is
parked in the matching wait is finished there without the syscall table; any
precondition that does not hold falls back to the ordinary path with nothing
done. `crates/core/syscall/src/fastpath.rs` lists the preconditions. The
hand-off to the peer uses the scheduler's own direct switch, so none of that
switch's bookkeeping is skipped.

**Resume points.** With `IPC_FASTPATH_RESUME`, a task that blocks in the fast
path's hand-off leaves a resume stub (`riscv64_ipc_resume_stub`,
`aarch64_ipc_resume_stub`, `x86_64_ipc_resume_stub`). The next call that claims
it finishes its syscall for it, writing the result straight into its saved
frame and pointing its saved context at the stub, which leaves through the
syscall exit. Any other wake resumes the task where it blocked.

**Interrupts** are taken on the interrupted stack and run on the hart's own
interrupt stack; a pending reschedule is spent on the way out, on the
interrupted stack.

Source: `kernel/src/entry/riscv64/asm/trap_entry.S`,
`kernel/src/entry/aarch64/asm/trap_entry.S`,
`kernel/src/entry/x86_64/asm/trap_entry.S`, `kernel/src/entry/*/trap.rs`,
`crates/core/syscall/src/fastpath.rs`, `config/kernel/Kconfig.ipc`
(`SYSCALL_LEAN_ENTRY`, `IPC_FASTPATH`, `IPC_FASTPATH_RESUME`).

## 3. Time without a trap

Reading the clock is a read of a shared page, not a system call.

- The kernel publishes a vDSO page at `VDSO_USER_BASE`
  (`crates/core/mm/src/vdso.rs`). It holds the tick count and milliseconds
  (refreshed by the timer interrupt, so only as fine as the tick), the counter
  frequency `timebase_hz`, a `flags` word and, on x86_64, the conversion from
  the TSC to the kernel clock.
- `vdso_now_ns` in `crates/core/libsys/src/lib.rs` reads the hardware counter
  itself and converts it with the published frequency, so the result is exact
  rather than tick-granular. The counter is `rdtime` on riscv64, `cntvct_el0`
  on aarch64, and `rdtsc` plus the published scale on x86_64.
- On riscv64 the boot hart reads the `time` CSR once under a private trap
  vector (`azos_arch::cpu::time_readable`) and sets `VDSO_FLAG_RDTIME_NATIVE`
  when no trap reached S-mode. U-mode then reads it too: the SBI firmware sets
  `mcounteren.TM` and the kernel sets `scounteren.TM` on every hart. On a hart
  without the CSR in hardware OpenSBI emulates the read in M-mode, for S and U
  alike; that still beats the system call, whose handler reads the same CSR.
  x86_64 sets the flag when it publishes the counter scale.
  `vdso_rdtime_native` is what libsys tests. On aarch64 `cntvct_el0` never
  traps from EL0, so `vdso_now_ns` reads it without looking at the flag.
  With the flag clear, `uptime`
  falls back to `DOMAIN_UPTIME` through `uptime_ecall`, which returns the same
  counter, so a caller cannot tell the paths apart except by cost.
- Kernel feature `vdso-force-syscall` leaves the flag clear (and, on x86_64,
  publishes no counter scale), so the trap can be forced for comparison.
- `clock_now` adds the published offsets of the real, TAI and boot clocks,
  under their own seqlock, to the monotonic reading.

Source: `crates/core/mm/src/vdso.rs`, `crates/core/abi/src/vdso.rs`,
`crates/core/libsys/src/lib.rs`, `crates/core/libsys/src/pure.rs`,
`kernel/src/boot/seams.rs`, `kernel/Cargo.toml`.

## 4. The timer

Programming the next timer interrupt has a choice on riscv64 and x86_64.

- Without Sstc the timer is programmed with the SBI `set_timer` call, a trip
  into firmware. With Sstc it is one write to the `stimecmp` CSR.
- `timer_select` (`crates/core/arch-riscv64/src/irq/clint.rs`) chooses once, at
  boot: Sstc only when the device tree's ISA string declares it and a probe
  confirms that S-mode can actually read `stimecmp`. The probe reads the CSR
  once under a private trap vector, because the device tree says the hart
  implements the CSR but only M-mode state (`menvcfg.STCE`) says S-mode may use
  it, and an illegal instruction there would stop the board.
- The decision is held in a boot-time atomic and `set_timer` reads it; it is not
  re-tested per program. It is made on the boot hart only.
- Kconfig `RV_SSTC_NEVER`, `RV_SSTC_PROBE` (default) and `RV_SSTC_REQUIRE` set
  the policy.
- x86_64 writes the TSC-deadline MSR when CPUID.1:ECX[24] reports it and
  Kconfig `X86_TSC_DEADLINE_*` allows it, else the LAPIC one-shot counter
  calibrated against the TSC (`select_mode` in
  `crates/core/arch-x86_64/src/timer.rs`, once, on the boot CPU).
- aarch64 (the generic timer) has one mechanism. All three are reached through
  `Interrupts::set_timer_deadline` in `azos_arch_api`.

Source: `crates/core/arch-riscv64/src/irq/clint.rs`,
`crates/core/arch-riscv64/src/api_impl.rs`, `crates/core/arch-x86_64/src/timer.rs`,
`crates/core/arch-api/src/isa.rs`, `config/arch/Kconfig.isa`.

## 5. Reply and accept in one trap

A server loop would otherwise take two traps per request: reply to the one just
served, then accept the next. `SYS_IPC_FAST_REPLY_ACCEPT` does both.

- **Registers.** `a0` is the handle from the previous accept; the four reply
  words are `a2..a5`. `a1` is not read: libsys preloads the accept's
  not-written sentinel there, so `FastRequest::delivered` keeps its meaning. The
  reply words therefore sit one register later than in `SYS_IPC_FAST_REPLY`.
  Results are those of `SYS_IPC_FAST_ACCEPT`, with `a6` carrying the handle of
  a capability that moved with the next request.
- **Reply failure is fail-fast.** The accept writes every output register
  (`SYSCALL_OUT_REGS`), so no register is left to report the reply's outcome
  beside an accepted request. A reply that is not delivered therefore accepts
  nothing and returns at once: `-2` for a stale handle, `-3` for any other
  refusal. The server still holds its answer and knows it went nowhere. `-1`
  keeps the accept's meaning: the reply was delivered and nothing arrived
  within the accept's bounded wait.
- **One lock hold.** The reply and the first accept attempt share one hold of
  the fast-IPC lock (`azos_ipc::fastcall::reply_then_accept`). The client's
  wake rides on the accept, either at once when a request is already waiting,
  or folded into the block so the server can switch straight to that client.
- **Seccomp.** A profile row that lists `SYS_IPC_FAST_REPLY_ACCEPT` grants both
  halves. Rows are derived from the calls each binary issues
  (`tests/host/seccomp-tests`), so a rule requiring the plain reply and accept
  next to the combined call would force rows to list calls their binary never
  makes.
- The client side of the same model is `SYS_IPC_FAST_CALL_EP`: a call and the
  wait for its reply in one trap.

Precedent: seL4 `ReplyRecv` and L4 `ReplyWait` on the server side; Zircon's
`zx_channel_call` on the client side.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/syscall/src/dispatch.rs`
(`fast_ipc_reply_accept`), `crates/core/libsys/src/lib.rs`
(`fast_ipc_reply_accept`), `crates/core/sched/src/seccomp.rs`,
`crates/core/ipc` (`fastcall`).

## 6. The driver server loop

A ring-3 driver's loop has the same shape and the same fold.

- `DOMAIN_DRIVER_REPLY_FETCH` publishes the reply and fetches the next request
  in one call. Arguments: the driver kind, a pointer to the reply (null when no
  reply is owed), a pointer to the request buffer. It returns `0` (reply
  published if given, request written) or `-1` (reply published if given, queue
  empty). Any other return did nothing: a permission error for a task that is
  not the kind's driver, `-4` for a request buffer that is null or not
  writable, `-3` for a reply that cannot be read or published.
- **Every refusal runs before the reply is published** (`sys_driver_reply_fetch`
  in `crates/core/syscall/src/handlers.rs`). A driver told "failed" must be able
  to send the reply again; a duplicate for a token whose polling client has not
  read it would replace that token's entry.
- `DOMAIN_DRIVER_REPLY_WAIT` is the same call that parks the driver while the
  queue is empty, for at most a bounded time. A driver on the polling form is
  runnable for as long as it lives and its hart never idles; the parking form
  lets a service that answers a few requests a second sleep the rest of the
  time. `gpio_drv` and `ina_drv` in `userspace/drivers/` serve on it
  (`buzz_drv` serves its interface over IPC v2 instead). A client that
  waits on the reply donates its priority to the driver after the wake.
- Replies are delivered into a row owned by the request's waiter
  (`ReplyWaiters` in `crates/drivers/driver_server/src/reply_wait.rs`), so a
  second client's reply cannot overwrite the first's before it is taken. A
  reply with no waiter goes to the kind's polling ring.

Source: `crates/core/abi/src/invoke.rs`, `crates/core/syscall/src/handlers.rs`,
`crates/core/syscall/src/invoke.rs`, `crates/core/libsys/src/lib.rs`
(`drv_srv_reply_fetch`), `crates/drivers/driver_server/src/reply_wait.rs`.

## 7. A control period through `io_ring`

A period with N sensor reads and M actuator writes would take N+M traps. An
`io_ring` carries them as entries in one shared page, and one `SYS_RING_ENTER`
runs them.

- **Execution.** The kernel installs an `IoRingOps` table at boot with
  `io_ring_register_ops` (`kernel/src/boot/seams.rs`). Its entries call the
  functions the matching typed calls call; there is no parallel implementation.
  The table is `KERNEL_IORING_OPS` in `crates/core/syscall/src/ioring_ops.rs`.
  The page also carries a data buffer for larger results.
- **Rules.** What makes this safer than a plain batching interface is that each
  entry is authorized as the call it stands for would be:
  1. **Seccomp and pledge per entry.** `opcode_gate` maps each opcode to the
     syscall, the kernel-hosted interface key, or the `SYS_INVOKE` op it stands
     for, and the ring owner's profile, then its Domain's pledge mask, is
     consulted for it. The profile is always the
     owner's, including when a kernel-side poller runs the ring, so a
     capability and a profile of two different tasks never combine to admit an
     entry. A filter on the ring's submit call alone would never see the
     operations inside the ring; this one does.
  2. **Capability per entry.** The owner must hold a capability for the object
     the entry names (a sensor type, a pin, a bus and address, a channel, a
     file), with read rights for a read and write rights for an act. A refused
     entry completes with `CQE_F_REFUSED` set and a negative error.
  3. **Actuation authority unchanged.** Motor, PWM and GPIO writes reach the
     same gates as their typed calls. Containment refuses a write entry exactly
     as it refuses the typed call (`write_contained`).
  4. **Bounded work per submit.** At most `RING_SQ_SIZE` entries run per
     submit, and never one whose completion the completion queue has no room
     for. The submit runs at the caller's priority and is preemptible between
     entries.
- **Beyond sensors and actuators.** The same table serves file read and write,
  block read and write, `fsync`, timers, futex-word waits and network send and
  receive. Entries that must wait park on the ring (up to Kconfig
  `IORING_MAX_PARKED` at a time, each holding a reserved completion slot) and complete in a later
  pass. A file entry is handed to a worker instead of running in the submit, and
  a block entry is queued on the block request layer and completed by the worker
  (Kconfig `IORING_ASYNC`; without it only a real-time submitter's file entries
  are handed off, Kconfig `IORING_WORKER`).
- **Submission polling is opt-in.** `OP_SQPOLL_START` starts a kernel task that
  consumes the submission queue without a trap. It is allowed only for a row
  whose topology declares `sqpoll_idle_ms`, and every entry it runs is
  authorized exactly as a submitted one.

Source: `crates/core/ipc/src/io_ring.rs`, `crates/core/syscall/src/ioring_ops.rs`,
`kernel/src/boot/seams.rs`, `crates/core/abi/src/syscall_nr.rs`
(`SYS_RING_SETUP`, `SYS_RING_ENTER`).

## 8. Address-space switches that keep the TLB

With Kconfig `TLB_RETAIN` (default on), switching between user address spaces
installs the incoming root with its address-space tag and does not flush the
TLB, so a task that comes back finds its translations still cached. The tag is
`satp.ASID` on riscv64, `TTBR0_EL1.ASID` with not-global user leaves on
aarch64, and the PCID with the CR3 no-flush bit on x86_64.

**Generations** (`crates/core/sched/src/asid.rs`; the same scheme as Linux
arm64's `asid.c`).
- ASIDs are handed out from 1 up to the highest the hardware and Kconfig
  `ASID_BITS` allow. ASID 0 is the kernel's. Within one generation an ASID names
  at most one address space.
- When the ASIDs run out the generation advances (a rollover). Each hart
  records the generation its TLB is clean for (`HART_TLB_GEN` in
  `crates/core/arch-api/src/tlb_gen.rs`). A switch into an address space of
  generation `g` flushes if and only if the hart's recorded value is not `g`, so
  after a rollover every hart flushes once before running any ASID of the new
  generation, and an ASID reused across generations never meets its previous
  owner's entries.
- An address space whose ASID belongs to an older generation takes a fresh one
  the next time it is switched in (`prepare_switch`). One ASID per address
  space per generation: the per-space record is keyed by the root frame, so the
  first thread of a space to be switched in after a rollover re-tags the whole
  space and the others adopt its ASID.
- The width is probed at boot, not assumed: `ARCH.asid_bits()` reads
  `satp.ASID` written all-ones on riscv64, `ID_AA64MMFR0_EL1.ASIDBits` on
  aarch64, and uses 12 bits of PCID on x86_64. `set_hw_asid_bits` narrows
  `ASID_BITS` to what the MMU implements. A hart with no ASID bits flushes on
  every switch, as does a build with `TLB_RETAIN` off.
- The switch code reads a per-hart word set by `prepare_switch`
  (`AZOS_TLB_SWITCH_FLUSH` in `context_switch.S`): keep the TLB, flush when the
  root changes, or flush even when it does not (a rollover or a skipped
  shootdown).

**Shootdowns.** A hart that ran an address space and switched away still holds
its entries, so a change to the space's page tables must reach it.
- A shootdown that cannot reach a hart marks it stale; its next switch flushes
  (`mark_space_stale`).
- With `TLB_SPACE_MASK` (riscv64 and x86_64; aarch64 invalidates by hardware
  broadcast and records nothing), a table keyed by root frame records which
  harts ran each space in the current generation, and a shootdown marks only
  those harts stale.
- With `TLB_ASID_SCOPED`, a shootdown invalidates only the target space's ASID.
  On riscv64 that is `sfence.vma` with an ASID operand locally and the SBI
  `remote_sfence_vma_asid` call remotely, with the all-ASID form for a hart
  still running the space under an older generation's ASID
  (`crates/core/arch-riscv64/src/tlb.rs`). On aarch64 it is `TLBI ASIDE1IS` or
  `TLBI VAE1IS` on the recorded ASID, falling back to the all-ASID form when a
  CPU's generation differs from the record. On x86_64 the IPIs already reach
  only the CPUs on the root; with INVPCID the shooter invalidates the space's
  PCID directly.

**Global kernel mappings.** On riscv64, with Kconfig `RV_KERNEL_GLOBAL`, kernel
leaves in the kernel-only top-level slots carry the Sv39 global bit, so their
translations are shared by every ASID. Those slots are linked, not copied, into
every user root, which is what makes a global entry sound: every root maps them
identically (`kernel_global_bit` and `copy_kernel_entries_to_user` in
`crates/core/mm/src/vmm.rs`). Leaves in slots shared with user code, such as
low device windows, never get the bit: a global entry matches under any ASID,
so it is sound only at an address every root maps the same way. User leaves
never carry it. aarch64 keeps its kernel half in `TTBR1_EL1`, which is global
by construction.

**Why not keep flushing.** A flush on every switch is simple and always correct,
and an ASID-tagged TLB forgoes nothing but that simplicity. The cost is an
allocator whose bugs are silent isolation failures, which is why the generation
rule is the whole of the design: a switch never installs an ASID from an older
generation without a flush, and a rollover or an unreachable shootdown always
ends in one. Kconfig `TLB_RETAIN` off restores the flush on every switch, to
rule the TLB out when chasing a stale translation. `ASID_BITS` can be lowered
to force rollovers, and the runtime canary `asid-rollover-noflush`
(`kernel/src/canary_rt.rs`) removes the rollover flush so the isolation test
must fail.

Source: `crates/core/sched/src/asid.rs`, `crates/core/arch-api/src/tlb_gen.rs`,
`crates/core/arch-riscv64/src/tlb.rs`, `crates/core/arch-aarch64/src/api_impl.rs`,
`kernel/src/entry/riscv64/asm/context_switch.S`,
`kernel/src/entry/aarch64/asm/context_switch.S`,
`kernel/src/entry/x86_64/asm/context_switch.S`, `kernel/src/boot/early.rs`,
`crates/core/mm/src/vmm.rs`, `config/kernel/Kconfig.mm` (`TLB_RETAIN`, `ASID_BITS`,
`TLB_SPACE_MASK`, `TLB_ASID_SCOPED`, `RV_KERNEL_GLOBAL`).

## 9. Limits

- The fast paths fall back to the ordinary path on any unmet precondition; they
  are an optimization of the common case, not a different contract.
- Reply failure on the combined call costs one extra trap, on a path that only a
  server bug or a dead exchange reaches.
- `io_ring` puts an op table inside the trusted computing base; the per-entry
  rules above are more code on the path that can move an actuator.
- Time reads on riscv64 depend on knowing that `rdtime` is native; where the
  kernel does not know, the flag stays clear and the trap is taken.
- The Sstc decision is made on the boot hart. A system whose harts differ in
  Sstc support or firmware setup would be mis-selected on the others.
- The ASID mechanism trades a simple flush for an allocator; its correctness
  rests on the generation rule above.
- Prior art: seL4 `ReplyRecv` and L4 `ReplyWait` (combined server call); Zircon
  (`zx_channel_call`, vDSO clock); Linux (arm64 `asid.c` generations, the vDSO
  `clock_gettime`, `io_uring` and its seccomp gap); the RISC-V Sstc extension and
  the SBI RFENCE extension.

Source: `kernel/src/trap/syscall.rs`, `crates/core/syscall/src/fastpath.rs`,
`crates/core/arch-riscv64/src/irq/clint.rs`, `crates/core/ipc/src/io_ring.rs`,
`crates/core/sched/src/asid.rs`.
