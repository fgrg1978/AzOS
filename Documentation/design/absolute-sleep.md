# Absolute sleep

A periodic task needs to wake at fixed instants, not "one period after the
last time I looked". `SYS_SLEEP_UNTIL` blocks the caller until a deadline on
the monotonic clock, so a loop that adds its period to the previous deadline
costs one trap per period and does not drift.

## Summary

Source: `crates/core/abi/src/syscall_nr.rs` (`SYS_SLEEP_UNTIL`, `SLEEP_RELATIVE`),
`crates/core/syscall/src/sleep.rs` (`sys_sleep_until`).

- `SYS_SLEEP_UNTIL` is syscall number 12. `a0` is the deadline in nanoseconds
  on the monotonic clock; `a1` is a flags word.
- Flag `SLEEP_RELATIVE` (`a1 = 1`) reinterprets `a0` as a duration from now.
  This is the only relative sleep in the ABI: libsys `sleep(ms)` is a wrapper
  around it. A flag the kernel does not know returns `-EINVAL`.
- Return `0`: the caller blocked and the clock reached the deadline.
  Return `1`: the deadline had already passed at entry and the caller did not
  block. A periodic loop therefore sees an overrun in the same call.

## Why a relative sleep is not enough

Source: `crates/core/libsys/src/lib.rs` (`sleep_until_ns`).

A loop that sleeps `period - elapsed` has to read the clock, compute, and then
block. The time between the read and the block is lost on every iteration and
accumulates. An absolute deadline moves that arithmetic out of the loop: the
caller keeps `next`, adds the period each turn and hands the kernel the same
kind of number every time. This is the reason POSIX has
`clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)`. A deadline that has
already passed also needs a defined answer, which is the return value `1`.

## Clock and unit

Source: `crates/core/abi/src/time.rs`, `crates/drivers/sys/src/timebase.rs`,
`crates/core/libsys/src/lib.rs` (`vdso_now_ns`, `vdso_timebase_hz`).

- The clock is the architecture's free-running monotonic counter, read through
  `azos_drv_sys::timebase::now`, which delegates to the `Cpu` trait of
  `crates/core/arch-api`. Its origin is the counter's zero (reset), and it is
  not wall-clock time.
- The ABI unit is nanoseconds. The counter frequency is a per-board number
  (`TIMER_FREQ`), so a raw tick count is never a duration, and the same
  nanosecond deadline means the same interval on every board.
- Ring 3 reads the same clock without a trap. The kernel publishes the counter
  frequency in the vDSO page; `vdso_now_ns` reads the counter directly and
  converts with `ticks_to_ns`. Where the page says the counter is not directly readable (the riscv64
  `time` CSR may be emulated), the read goes through an `ecall`; on aarch64
  the counter register is always readable from user mode.
- The kernel converts a deadline to ticks with `ns_to_ticks_ceil`, which rounds
  **up**, so a task is never woken before its deadline. The conversion splits
  the value at the second so that no intermediate product needs 128 bits; it is
  exact for counter frequencies up to 10^8 Hz and saturates rather than wraps
  above that. `ticks_to_ns` is the inverse, rounding down, and returns 0 for a
  zero frequency (a vDSO page that publishes none).
- `ClockId` in the same file names other clocks (`MONO`, `REAL`, `TAI`,
  `BOOT`); `SYS_SLEEP_UNTIL` always uses the monotonic one.

## Blocking and waking

Source: `crates/core/syscall/src/sleep.rs` (`block_until`),
`crates/core/sched/src/wait.rs` (`wake_expired_timers`),
`crates/drivers/sys/src/timebase.rs` (`set_next_tick_smart`).

- The task blocks on `WaitReason::Timer(deadline)`, the same reason kernel tasks
  sleep on, so a sleeping task does not occupy its hart.
- The timer interrupt wakes expired sleepers (`wake_expired_timers`) and
  programs the hart's next interrupt at the earlier of the nearest sleeping
  deadline (`nearest_timer_deadline`) and the next scheduler tick
  (`set_next_tick_smart`). A deadline more than one tick away wakes on time; a
  nearer one waits for the interrupt that is already programmed.
- There are no signals, hence no `EINTR`. A wake stamped for another reason
  before the deadline makes the task block again; the call returns only once
  the counter is at or past the deadline.
- A task that is killed while sleeping leaves the sleep at its next syscall
  instead of sleeping out its deadline.
- If the scheduler refuses the block because preemption is disabled on the hart,
  the caller waits on the counter in place instead of re-entering the
  scheduler in a loop.

## Related interfaces

Source: `crates/core/ipc/src/io_ring.rs` (`OP_TIMER`),
`crates/core/libsys/src/lib.rs`, `crates/core/linux-abi/src/lib.rs`,
`crates/core/sched/src/seccomp.rs`.

- **libsys.** `sleep_until_ns(deadline_ns)` returns `SleepResult::Slept`,
  `Overrun` or `Refused(errno)`. `clock_nanosleep_abs` is the POSIX-shaped
  wrapper: 0 once the deadline has passed, the kernel's negative code if the
  call was refused. `sleep(ms)` issues the relative form.
- **I/O ring.** `OP_TIMER` is the same deadline as a ring completion: it
  completes with `1` when the deadline has already passed, otherwise it parks
  and completes with `0` in the first pass at or after the deadline. It is
  checked against the syscall filter row of `SYS_SLEEP_UNTIL` before it parks.
- **Linux personality.** `nanosleep` and `rt_sigsuspend` in the table of
  `crates/core/linux-abi/src/lib.rs` map onto `SYS_SLEEP_UNTIL`.
- **Syscall filters.** A seccomp profile in `crates/core/sched/src/seccomp.rs`
  must list the syscall explicitly; an image that sleeps needs it in its row.

## Interface shape

Source: `crates/core/syscall/src/sleep.rs`, `crates/core/ipc/src/io_ring.rs`.

- **One call, two forms.** The absolute deadline is the default meaning of
  `a0`. The relative form is the `SLEEP_RELATIVE` flag on the same call, for
  callers that do not keep a deadline.
- **Nanoseconds, not ticks.** The deadline is in nanoseconds so that the
  number means the same interval on every board.
- **No timer object.** A periodic loop needs one call per period and no
  handle. When a deadline is one event among several, the I/O ring's
  `OP_TIMER` carries it as a completion.
- **Overrun is a flag, not a measurement.** The call returns `1` when the
  deadline had already passed. The caller holds the deadline and can read the
  clock without a trap if it wants the lateness.

## Limitations

Source: `crates/drivers/sys/src/timebase.rs`, `crates/core/abi/src/time.rs`.

- Wake-up precision is bounded by the timer interrupt: a deadline nearer than
  the already-programmed interrupt is served by that interrupt.
- The counter is monotonic only. Comparing readings across a reboot is
  meaningless, and nothing steers it.
