# Transactional control ticks

A recoverable CPU fault inside the hard-real-time control loop would, by
default, end in the kernel's abort policy: the kernel stops the motors, logs,
and halts. For a robot in motion that is the worst available outcome. This
note describes the mechanism that lets the motor control task survive one
class of fault by stopping the motors and restarting the task, the four
constraints that make it safe, and which architectures it covers.

## Coverage

Source: `domains/robot/safety-core/src/txn.rs`, `kernel/src/entry/riscv64/trap.rs`, `kernel/src/entry/aarch64/trap.rs`, `kernel/src/entry/x86_64/trap.rs`

The rollback exists on **riscv64 only**. The trap hook, `txn_try_rollback`, is
compiled for `target_arch = "riscv64"` and has one caller, `arch_exception` in
`kernel/src/entry/riscv64/trap.rs`. It rewrites a RISC-V `TrapFrame` and has no
counterpart written against the exception frames of aarch64 or x86_64. On those architectures the control task still arms its
checkpoint and clears its streak (`txn_arm`, `txn_note_tick_complete` compile
everywhere), but no trap handler consults it, so a fault in the control loop
takes the generic fatal path. Giving another architecture the mechanism means a
rollback hook against its own exception frame.

The mechanism is part of the robot profile (feature `use-robot`) and is selected
by Kconfig `CONTROL_TXN_TICKS`, default on. With it off, the rollback branch is
a compile-time constant `false` and the trap handler is unchanged.

## Mechanism

Source: `domains/robot/safety-core/src/txn.rs`, `domains/robot/safety-core/src/rt_motor.rs`, `domains/robot/robot/src/lib.rs`

**Checkpoint.** A per-hart slot holds `armed`, a stack pointer and a program
counter. `rt_motor_task` arms it at the top of the task, before its loop, with
`txn_arm(azos_sched::current_task_stack_top(), rt_motor_task as usize)`: the
task's clean stack top and its own entry address.

**Rollback.** `arch_exception` calls `txn_try_rollback(frame, cause)` first,
before the generic exception policy. If the cause is whitelisted, the hart's
checkpoint is armed and the restart budget is not exhausted, the hook:

1. disarms the slot and counts the restart (`TXN_RESTART_STREAK`, `TXN_ABORTS`);
2. requests a stop with `motor_cmd_zero()`;
3. rewrites the saved frame, `regs[2]` (sp) to the checkpoint stack and `sepc`
   to the task entry;
4. returns `true`, and the trap returns with `Disposition::Resume`.

The task then restarts at its entry. Restarting at a function entry rather than
mid-tick needs no setjmp/longjmp: the prologue rebuilds the frame and the task
never returns. The task re-arms on re-entry.

**Stopping.** `motor_cmd_zero` is one atomic store of a timestamp
(`MOTOR_ZERO_AT`); a command published after it overrides it, and the reader
(`motor_cmd_read`) resolves the two. It takes no lock, so it is safe from trap
context on any hart. The stop takes effect on the next control tick of the
restarted task. A duty already written to the PWM peripheral by an earlier
command stays on the wire until then. There is no tick-local staging of the
outputs: the guarantee is about the command channel, not about the actuator.

## The four constraints

Source: `domains/robot/safety-core/src/txn.rs`

**1. A conservative cause whitelist.** Only misaligned load and misaligned store
(`TRAP_LOAD_MISALIGNED`, `TRAP_STORE_MISALIGNED`) are recoverable. The
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

Source: `domains/robot/safety-core/src/txn.rs`, `domains/robot/safety-core/src/rt_motor.rs`

* Restarting the task is coarser than resuming the tick: locals of the task
  (its safe-mode flag, its edge-trigger state) are lost.
* The recoverable set is a policy, and getting it wrong in either direction has
  a cost: too narrow and a survivable fault halts the machine, too wide and a
  real defect is hidden. Illegal instruction and page faults are outside it.
* Only the motor control task is covered. The flight control task has no
  checkpoint.
* The trap-handler hook is permanent surface in the most safety-critical code.
  It is reachable only with the checkpoint armed and a whitelisted cause, and
  with the option off it is compiled out.
