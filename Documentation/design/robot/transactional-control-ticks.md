# Transactional control ticks

A recoverable CPU fault inside the hard-real-time control loop would, by
default, end in the kernel's abort policy: the kernel stops the motors, logs,
and halts. For a robot in motion that is the worst available outcome. This
note describes the mechanism that lets the motor control task survive one
class of fault by stopping the motors and restarting the task, the four
constraints that make it safe, and which architectures it covers.

## Coverage

Source: `crates/domains/robot/safety-core/src/txn.rs`, `kernel/src/entry/riscv64/trap.rs`, `kernel/src/entry/aarch64/trap.rs`, `kernel/src/entry/x86_64/trap.rs`

The hook, `txn_try_rollback(recoverable) -> Option<(sp, pc)>`, has no ISA code:
each ISA's trap entry decodes whether the fault is in the whitelist and was
taken in kernel mode, and writes the returned restart point into its own frame.

* **riscv64**: a misaligned load or store (AMO included) taken in S-mode, in
  `arch_exception`. The frame's `regs[2]` (sp) and `sepc` are rewritten.
* **aarch64**: an EL1 Alignment fault (`ESR_EL1.EC` 0x25, DFSC `0b100001`,
  `azos_arch::sysregs::el1_alignment_fault`). It is a data abort, so it is
  decoded in `arch_page_fault`, ahead of the page-fault policy; every other
  abort, and this one when the rollback declines it, keeps that policy. With
  `SCTLR_EL1.A` clear, an ordinary Normal-memory access never takes it; an
  exclusive or acquire/release access off its natural alignment, or any Device
  memory access, does. The frame holds no EL1 stack pointer (it sits on
  `SP_EL1` itself), so the trap returns to `aarch64_txn_restart`, which loads
  sp from x0 and calls the entry in x1.
* **x86_64**: nothing to take. Ring 0 never raises #AC for a misaligned
  access (it is checked at CPL 3 only), and a kernel split lock already
  resumes with detection off on that CPU.

The mechanism is part of the robot profile (feature `use-robot`) and is selected
by Kconfig `CONTROL_TXN_TICKS`, default on. With it off, the rollback branch is
a compile-time constant `false` and the trap handler is unchanged.

## Mechanism

Source: `crates/domains/robot/safety-core/src/txn.rs`, `crates/domains/robot/safety-core/src/rt_motor.rs`, `crates/domains/robot/robot/src/lib.rs`

**Checkpoint.** One slot holds the armed task's id, a stack pointer and a
program counter. It belongs to the task, not to a CPU: a fault of any other
task is never restarted on the control task's stack. `rt_motor_task` arms it at the top of the task, before its loop, with
`txn_arm(azos_sched::current_task_stack_top(), rt_motor_task as usize)`: the
task's clean stack top and its own entry address.

**Rollback.** The ISA's trap entry calls `txn_try_rollback` before its generic
policy. If the fault is whitelisted, was taken by the armed task in kernel mode
and the restart budget is not exhausted (`txn_rule.rs`), the hook:

1. disarms the slot and counts the restart (`TXN_RESTART_STREAK`, `TXN_ABORTS`);
2. requests a stop with `motor_cmd_zero()`;
3. returns the checkpoint stack and the task entry, which the trap entry writes
   into its frame (see Coverage), and the trap returns there.

The task then restarts at its entry. Restarting at a function entry rather than
mid-tick needs no setjmp/longjmp: the prologue rebuilds the frame and the task
never returns. The task re-arms on re-entry, and that re-arm reports the
restart: a `[TXN]` console line and a `SAFETY_TXN_ROLLBACK` record, written
from task context (the trap writes none).

**Stopping.** `motor_cmd_zero` is one atomic `fetch_max` of a timestamp
(`MOTOR_ZERO_AT`, in `crates/domains/robot/robot/src/lib.rs`); a command published after it overrides it, and the reader
(`motor_cmd_read`) resolves the two. It takes no lock, so it is safe from trap
context on any hart. The stop takes effect on the next control tick of the
restarted task. A duty already written to the PWM peripheral by an earlier
command stays on the wire until then. There is no tick-local staging of the
outputs: the guarantee is about the command channel, not about the actuator.

## The four constraints

Source: `crates/domains/robot/safety-core/src/txn.rs`

**1. A conservative cause whitelist.** Only misaligned load and misaligned store
(riscv64 `TRAP_LOAD_MISALIGNED`, `TRAP_STORE_MISALIGNED`; aarch64 the EL1
Alignment fault) are recoverable. The
plausible transient is bad alignment in data coming from outside the loop,
such as a field of a sensor frame. Illegal instruction is excluded because it
is almost always a real defect (corrupt code, a bad function pointer) that must
surface and not be rolled back. Page faults and `ecall` keep their own handlers.
A rollback that masks bugs is worse than the halt it replaces.

**2. A clean restart stack.** The restart sets the stack pointer to the task's
clean stack top, not to the value live at fault time. Capturing a mid-function
stack pointer and jumping to the pre-prologue entry would run the prologue
again on every restart and descend one frame each time.

**3. An abort budget.** The task re-arms at its entry before a deterministic
fault recurs, so disarming on rollback alone would restart forever, with the
motors stopped and no escalation. `MAX_TXN_RESTARTS` (8) bounds consecutive
restarts. When the streak reaches it, `txn_try_rollback` declines and the fault
takes the fatal path. `txn_note_tick_complete`, called at the end of every
completed control iteration, clears the streak, so one-off transients never
accumulate toward the budget. In the steady state that call is a single relaxed
load; it stores only on the tick after a rollback.

**4. No lock is held when a whitelisted fault can occur.** The restart resets
the stack pointer and re-enters at the task entry, so destructors of the
abandoned stack never run. The control tick holds spin locks across its
computation (`TICK_STATE` and `PID_CONTROLLERS` in
`crates/drivers/actuator/src/motor_pid.rs`). A whitelisted fault taken while one
is held would leak the guard, and the next acquire would deadlock. This is safe
only because the whitelist is misaligned load and store alone and the tick
touches only aligned, typed data, so no whitelisted fault is reachable inside a
locked region.  This
is a precondition, not a property the mechanism checks. Widening the whitelist,
or adding a raw unaligned access to the tick, requires auditing every lock held
in the armed region.

## Limitations

Source: `crates/domains/robot/safety-core/src/txn.rs`, `crates/domains/robot/safety-core/src/rt_motor.rs`

* Restarting the task is coarser than resuming the tick: locals of the task
  (its safe-mode flag, its edge-trigger state) are lost.
* The recoverable set is a policy, and getting it wrong in either direction has
  a cost: too narrow and a survivable fault halts the machine, too wide and a
  real defect is hidden. Illegal instruction and page faults are outside it.
* Only the motor control task is covered. The flight control task has no
  checkpoint.
* The checkpoint table has `MAX_TXN_HARTS` (8) slots. On a hart with a higher
  index `txn_arm` stores nothing and a fault takes the fatal path.
* The trap-handler hook is permanent surface in the most safety-critical code.
  It is reachable only with the checkpoint armed and a whitelisted cause, and
  with the option off it is compiled out.
