# Time

This document describes how the kernel keeps time: the monotonic counter, the clock ids a task can read, how wall-clock, TAI and boot time are derived from it and published in the vDSO page, the discipline that steers the wall clock, the `Clock` interface, and the NTP and PTP sources. Related documents: [scheduler.md](scheduler.md) for timer sleepers and the tick, [energy.md](energy.md) for suspend (which feeds the boot clock).

## Model

One clock is never moved: the monotonic counter. Every other clock is the monotonic reading plus an offset, and only the offsets change.

```text
MONO = counter converted to nanoseconds
REAL = MONO + real      (UTC, Unix epoch)
TAI  = MONO + tai       (REAL plus the TAI-UTC seconds in force)
BOOT = MONO + boot      (MONO plus the time spent suspended)
```

A time source (the SNTP client, the PTP daemon) moves `real` and `tai` through the clock discipline; before any of them has spoken the board's real-time clock seeds them once at boot (see [Real-time clock](#real-time-clock)). A system suspend whose counter stopped moves `boot`. Because the monotonic clock underneath never steps, deadlines built on it stay true when the wall clock is corrected. Until a source (or the RTC) has set the wall clock, `REAL` and `TAI` read like `MONO`, and `BOOT` reads like `MONO` until a suspend finds the counter stopped across the sleep.

Source: `crates/core/abi/src/time.rs` (`ClockOffsets`, `clock_now_with`).

## The monotonic counter

`azos_drv_sys::timebase::now()` returns the counter in ticks; `timebase::TIMER_FREQ` is its frequency in Hz (Kconfig `TIMER_FREQ`). A raw tick count is not a duration: divide by `TIMER_FREQ`. The counter is read through the architecture trait: `Cpu::now_ticks`.

| ISA | Counter |
|---|---|
| riscv64 | the `time` CSR (`rdtime`) |
| aarch64 | the virtual count register `CNTVCT_EL0` |
| x86_64 | the invariant TSC (`rdtsc`), converted to `TIMER_FREQ` ticks |

`azos_abi::time` converts between nanoseconds and ticks with two functions both sides use: `ns_to_ticks_ceil(ns, freq)` rounds up, so a deadline converted here is never reached early; `ticks_to_ns(ticks, freq)` rounds down and returns 0 for a zero frequency. Both split the value at the second to avoid wide intermediates and saturate rather than wrap.

Source: `crates/drivers/sys/src/timebase.rs`, `crates/core/arch-api/src/lib.rs` (`Cpu::now_ticks`), `crates/core/arch-riscv64/src/api_impl.rs`, `crates/core/arch-aarch64/src/api_impl.rs`, `crates/core/arch-x86_64/src/lib.rs`, `crates/core/abi/src/time.rs`, `config/arch/Kconfig.platform` (`TIMER_FREQ`).

## Clock ids

A `ClockId` is one `u32`: the kind in bits 24..32, an index in bits 0..24. `ClockId::MONO` is raw 0, so a zero-filled field names the monotonic clock.

| Kind | Constant | Status | Reads as |
|---|---|---|---|
| 0 | `KIND_MONO` | served | the monotonic clock |
| 1 | `KIND_REAL` | served | `MONO + real` (UTC, Unix epoch) |
| 6 | `KIND_TAI` | served | `MONO + tai` (Unix epoch, no leap seconds) |
| 7 | `KIND_BOOT` | served | `MONO + boot` |
| 2 | `KIND_TSC_RAW` | reserved | the raw hardware counter |
| 3 | `KIND_PTP` | reserved | PTP hardware clock `index` |
| 4 | `KIND_TSN_DOMAIN` | reserved | time-sensitive-networking domain `index` |
| 5 | `KIND_VCPU` | reserved | virtual time of vCPU `index` |

A reserved id is a number a caller can name; reading it returns `ClockError::Unsupported`, so it is refused instead of silently read on the wrong clock. `clock_now_with(id, mono, offsets)` is the one reader: it calls `mono` and `offsets` only if the id needs them.

`ClockId::from_posix` is the one table the Linux personality, the Linux runtime and the C library use for POSIX `clockid_t` numbers:

| `clockid_t` | Number | Clock |
|---|---|---|
| `CLOCK_REALTIME`, `CLOCK_REALTIME_COARSE` | 0, 5 | `REAL` |
| `CLOCK_MONOTONIC`, `CLOCK_MONOTONIC_RAW`, `CLOCK_MONOTONIC_COARSE` | 1, 4, 6 | `MONO` |
| `CLOCK_BOOTTIME` | 7 | `BOOT` |
| `CLOCK_TAI` | 11 | `TAI` |

Any other number (the CPU-time clocks, an unknown id) is not served and the Linux `clock_gettime` answers `EINVAL`.

Source: `crates/core/abi/src/time.rs` (`ClockId`, `posix_clock`, `ClockError`), `crates/core/syscall/src/linux.rs` (`sys_clock_gettime`).

## The vDSO page

A read-only page is mapped into every user process at `VDSO_USER_BASE` (`azos_abi::vdso`). The kernel writes it; ring 3 reads it without a system call. Two seqlocks protect the time data:

* the page's `seq` covers the per-tick fields (`uptime_ticks`, `uptime_ms`), refreshed by the timer interrupt and by an idle hart as it wakes;
* the clock words have their own generation, so a time source writing rarely and from task context never makes the tick drop an update.

Fields written once at boot, outside the seqlock: `timebase_hz` (the counter frequency, 0 if not published), `flags` (bit 0, `VDSO_FLAG_RDTIME_NATIVE`: ring 3 may read the counter without a trap), and, where the counter ring 3 reads does not run at the kernel clock's rate (x86_64's TSC), `counter_base`, `ticks_base`, `counter_mult` (`VDSO_COUNTER_*` offsets): `ticks = ticks_base + ((counter - counter_base) * mult) >> 32`.

The clock words are `ClockWords` at `VDSO_CLOCK_WORDS_OFFSET` (88): a generation word and the three offsets `real`, `tai`, `boot`. The kernel writes with `ClockWords::update` (writers exclude each other by claiming the odd generation; interrupts must be masked); readers use `ClockWords::read`, which only loads and retries while a write is open or completed in between. All three offsets are zero until a source sets them.

Source: `crates/core/mm/src/vdso.rs` (`VdsoData`, `vdso_update`), `crates/core/abi/src/vdso.rs` (offsets), `crates/core/abi/src/time.rs` (`ClockWords`).

## Reading a clock from ring 3

`azos_libsys::clock_now(id)` returns nanoseconds on any served clock with no system call: `vdso_now_ns()` (read the counter, convert with the page's frequency) plus the offset `vdso_clock_offsets()` read from the page. `vdso_now_ns` returns 0 if the page publishes no frequency; on every ISA but aarch64 it falls back to a system call when the page says the counter is not natively readable (`VDSO_FLAG_RDTIME_NATIVE` clear). `MONO` reads no offset.

Kernel code uses the same arithmetic: `azos_mm::vdso::clock_offsets()` with `clock_now_with`.

Source: `crates/core/mm/src/vdso.rs` (`VdsoData`, `vdso_update`, `clock_offsets`), `crates/core/abi/src/vdso.rs`, `crates/core/libsys/src/lib.rs` (`vdso_now_ns`, `vdso_clock_offsets`, `clock_now`), `crates/core/abi/src/time.rs` (`ClockWords`).

## TAI, REAL and BOOT

**REAL.** When a source sets the wall clock to `unix_ns` at monotonic `mono_ns`, `real = unix_ns - mono_ns` (saturating at 0).

**TAI.** `tai = real + leap * 1e9`, where `leap` is `tai_minus_utc(table, unix_secs)`: the offset of the last table entry whose first second is not after the current Unix second. The table is the topology's `[clock]` row, `leaps = ["unix:offset", ...]`, oldest first. Each entry's time is later than the one before and the offset moves by exactly one second per entry; an offset of 0 is refused. With no row, or a time before the first entry, `leap` is 0 and TAI equals UTC (as Linux's `CLOCK_TAI` does with no offset set). Every accepted sample re-derives TAI against the table, so a leap second that has passed since is picked up.

**BOOT.** `vdso_add_suspended(ns)` adds to `boot`. System suspend calls it with the time the machine slept that the monotonic counter did not count, computed from a persistent clock on both sides (`suspend::slept_ns`). Without a persistent clock the sleep is unknown and `boot` is not changed. A time sync keeps `boot`.

Source: `crates/core/abi/src/time.rs` (`ClockOffsets::with_wall`, `tai_minus_utc`), `crates/core/mm/src/vdso.rs` (`vdso_step_wall`, `vdso_slew_wall`, `vdso_add_suspended`), `crates/core/topology/src/types.rs` (`ClockSpec`, `LeapEntry`, `set_clock`), `crates/drivers/power/src/pm/suspend.rs` (`slept_ns`).

## Clock discipline

`azos_drv_sys::clockdisc::Discipline` is a phase-locked loop and a frequency-locked loop that steer the wall clock (`real`, and `tai` with it) toward a reference. It holds no hardware and no global state: the caller passes monotonic nanoseconds and applies what it returns. The kernel's instance, and the path to the vDSO page, is `azos_syscall::clock`.

A measurement is `offset_ns` (reference minus our wall clock at the same instant; positive when we are behind) and `delay_ns` (the exchange's round trip), with a source label (`source::NTP` or `source::PTP`).

| Action | Rule |
|---|---|
| **Filter** | a sample whose delay exceeds `max_delay_ns`, or twice the smallest of the last `DELAYS` (8) delays plus `DELAY_SLACK_NS`, is `Filtered` (queued behind a busy link) |
| **First sample** | the clock has never been set: `Stepped` unconditionally |
| **Slew** | `|offset| <= step_ns`: the offset becomes the phase still to remove, removed exponentially with time constant `PLL_GAIN * tc_ns`, at no more than `max_slew_ppb`; the frequency loop updates the standing correction `freq_ppb` from the rate error the sample interval shows (no update from an interval under `MIN_FREQ_INTERVAL_NS`) |
| **Step** | `step_ns < |offset| <= panic_ns`: stepped only after `confirm` consecutive samples that agree with each other; until then `Filtered` |
| **Refuse** | `|offset| > panic_ns` once the clock has been set: `Refused`, nothing moves |

`Params::DEFAULT`: step threshold 128 ms, panic threshold 1000 s, 500 ppm limits on frequency and slew, a 16 s time constant, a 1 s delay ceiling, two samples to confirm. At 500 ppm the wall clock cannot go backwards while slewing.

The kernel applies the discipline (`azos_syscall::clock`):

* `feed` advances the loop to now, reads the real offset the page publishes, takes the sample, and under the same lock applies a step with `vdso_step_wall` (a slewed sample also re-derives TAI).
* `tick()` is called from the timer interrupt on every hart; it returns at once unless the discipline has something standing (`ACTIVE`) and `PERIOD_NS` (8 ms) has passed. It never waits for the lock; the next tick applies what accrued. It moves the offsets with `vdso_slew_wall`.
* A step made, and a step refused, is a decision record: `Rule::ClockStep` (verdict `Admit` or `Refuse`, subject `ClockId::REAL`, numbers: the clock, the delta, the threshold crossed). The records are written after the lock is dropped.

Source: `crates/drivers/sys/src/clockdisc.rs`, `crates/core/syscall/src/clock.rs`.

## The `Clock` interface

`azos_devif::clock::Clock` (interface id `CLOCK_ID`, ASCII "CLCK") is how a time source outside the kernel offers measurements. The kernel hosts it on the `clock` endpoint (`endpoint = "clock"`). The wall clock is the only clock a source can move, so no op names a clock.

| Op | Right | Meaning |
|---|---|---|
| `sample(offset_ns, delay_ns, source)` | `WRITE` | offer a measurement; `source` must be `SOURCE_NTP` or `SOURCE_PTP` (else `BAD_ARGUMENT`). Answers `SLEWED` (0), `STEPPED` (1) or `FILTERED` (2); `REFUSED` when the offset is a step the clock will not make |
| `status()` | `READ` | `Status { state, source, freq_ppb, phase_ns, steps, rejected }`; `state` is `STATE_UNSET`, `STATE_SYNCED` or `STATE_SEEDED` (set from the RTC at boot, no reference has measured it yet) |
| `rtc_read()` | `READ` | the real-time clock's time, UTC seconds since 1970-01-01. `NO_RESOURCE` without an RTC, `NOT_READY` when the chip says its time is lost, `FAULT` on a bus failure |
| `rtc_set(unix_secs)` | `WRITE` | set the real-time clock (not the wall clock). An effect of kind `KIND_CLOCK`. `BAD_ARGUMENT` for a time the chip cannot hold, `NO_RESOURCE` without an RTC, `FAULT` on a bus failure, `REFUSED` when the effect gate refuses the record |

`WRITE` is required because `sample` moves time and `rtc_set` changes what the next boot believes; it is checked before the source and before the discipline decides.

Source: `crates/core/devif/src/clock.rs`, `crates/core/syscall/src/clock.rs` (`Server`).

## Real-time clock

The board's battery-backed clock (`azos_rtc`, Kconfig `DRV_RTC`) is the wall clock's starting point and the place a reference leaves its answer.

| Chip | Machine | Time as | Found by |
|---|---|---|---|
| goldfish RTC | QEMU `virt`, riscv64 | 64-bit nanoseconds | hardware bus, `dt:google,goldfish-rtc` |
| PL031 | QEMU `virt`, aarch64 | 32-bit seconds | hardware bus, `dt:arm,pl031` (PrimeCell IDs checked) |
| MC146818 | every PC, x86_64 | BCD or binary calendar, 12 or 24 hour | ports 0x70/0x71 (floating ports, status D reading 0xff, are "no device") |
| PCF8563 | boards (Kconfig `DRV_RTC_PCF8563`) | BCD calendar over I2C at 0x51 | bus `RTC_PCF8563_I2C_BUS`, after the I2C controllers are up |

Every chip reads and sets UTC seconds since the epoch through one trait (`Rtc::read`, `Rtc::set`). A chip that keeps a calendar goes through `azos_rtc::civil`; it holds 2000..=2099 and a set outside that is `Range`. The CMOS read is a snapshot between two updates (it waits for `UIP` to clear, bounded by `RTC_UIP_POLLS`, and believes two readings that agree); the goldfish read takes the low word first because that read latches the high word. A chip that says its time is not to be trusted (PCF8563 `VL`, CMOS `VRT`, registers that are not a date) answers `Lost`. The memory-mapped chips are not bound to a driver on the hardware bus: the kernel reads and loads the time and touches nothing else, so a task holding the device capability can still map the window.

**Seeding.** `kernel/src/boot/rtc.rs` reads the chip once, before the network. A time before `RTC_FLOOR_YEAR` (a battery reset to 2000, a chip nobody set) or one the chip calls lost is reported and not used. Any other time becomes the wall clock (`azos_syscall::clock::seed_wall`): a step, recorded as `Rule::ClockStep` (`Admit`, threshold 0). The discipline is not told. It stays `Unset`, so the first NTP or PTP sample steps without confirming and is not bounded by the panic threshold (an RTC may be years off); `Clock::status` reports `STATE_SEEDED` until then. A clock a reference already set is not seeded.

**Write-back.** When a sample steps the wall clock (`Verdict::Stepped`, from either source), `persist_wall` sets the RTC to the wall clock's seconds, so the next boot starts from a time a reference gave. A failed write-back is a boot-log line, not an error. The set is an effect of kind `KIND_CLOCK` (subject `0xff00`, `a0` the clock id, `a1` the seconds saturated to 32 bits): with `EFFECT_WRITE_AHEAD` its record is committed before the chip is written; `rtc_set` from a task is the same effect, charged to that task.

Source: `crates/drivers/rtc/src/`, `kernel/src/boot/rtc.rs`, `crates/core/syscall/src/clock.rs` (`seed_wall`, `persist_wall`, `RtcHost`).

## SNTP

`azos_net::ntp` is the kernel's SNTP client: a unicast UDP request to the time server (port 123), single request and reply, retries with backoff (`ntp_sync_with_yield`, which yields the CPU instead of spinning while it waits). The kernel installs `azos_syscall::clock::ntp_exchange` as the exchange sink at boot (`ntp::set_exchange_sink`), so each successful exchange reaches the discipline with source `NTP`.

The exchanges are started by the `net-clients` task (`kernel/src/tasks/net_clients.rs`, Kconfig `NTP_CLIENT`; the same task keeps a DHCP lease). The server is the one a DHCP lease names in option 42 (`ntp::set_leased_server`) while the lease names one, else the address of Kconfig `NTP_SERVER`: a dotted quad as it is, a name through the stack's resolver before every exchange (the resolver's cache keeps an answer five minutes). With neither, nothing is sent. After a success the next exchange is `NTP_INTERVAL_S` seconds away; after a failure 16 s, doubling up to that period. `TOOLBOX.ELF`'s `ntp` shows the client's server and last exchange (`Net::ntp_status`) and the discipline's state (`Clock::status`).

An `Exchange` holds the four timestamps: the client's transmit and receive on the monotonic clock (T1, T4), the server's receive and transmit as Unix nanoseconds (T2, T3). `Exchange::measure(real_offset_ns)` gives `offset = ((T2 - T1) + (T3 - T4)) / 2` and `delay = (T4 - T1) - (T3 - T2)`, never negative.

A reply is accepted only if all of these hold:

* a request is outstanding, and the reply comes from the configured server's address and port 123;
* the header qualifies (`header_acceptable`): server mode, not "unsynchronised" (leap indicator 3), stratum 1 to 15 (stratum 0 is a kiss-o'-death);
* it echoes the 64-bit nonce the client put in its transmit timestamp, drawn from the kernel entropy pool when a seeded source is installed;
* its transmit timestamp is non-zero and, in NTP era 0, not before 2020-01-01; the era bit is honoured, so a time past 2036 is accepted.

Source: `crates/net/net/src/ntp.rs`, `kernel/src/boot/net.rs` (`install_net_config`).

## PTP

`PTPD.ELF` (`userspace/services/ptpd`) is a ring-3 PTP slave. Its topology row is its whole authority: `WRITE` on the `clock` endpoint, the kernel's view of the `[clock]` row (`MemObj inspect.clock`) and the sockets its transport needs.

* **Transport.** IEEE 1588 over UDP, the multicast group 224.0.1.129, port 319 (event) and 320 (general). Raw-Ethernet (802.1AS) is not part of the daemon's transport: it needs a packet socket, which the kernel keeps to itself.
* **Domain.** `ptp_domain` of the node's `[clock]` row, published by the kernel as `clock/ptp_domain` in the `inspect.clock` view region (Kconfig `PTPD`). A node whose row declares none takes no part: the daemon says so and ends.
* **Protocol.** The best master clock algorithm for a slave-only ordinary clock (`bmc.rs`), then end-to-end delay measurement from Sync, Follow_Up, Delay_Req and Delay_Resp (`port.rs`, wire format in `wire.rs`). The master's PTP-scale (TAI) timestamps are moved by the `currentUtcOffset` its Announce states before they meet the wall clock; a master that does not state a valid offset gives no sample.
* **Timestamps.** Software timestamps, taken after a datagram is taken off the socket.
* **Feeding the kernel.** Each exchange ends in one `(offset_ns, delay_ns)` pair, offered with `Clock::sample` and source `SOURCE_PTP`. The daemon disciplines nothing itself; the kernel's loops filter, slew or step.

Source: `userspace/services/ptpd/src/main.rs`, `userspace/services/ptpd/src/port.rs`, `userspace/services/ptpd/src/bmc.rs`, `userspace/services/ptpd/src/wire.rs`, `userspace/services/ptpd/src/link.rs`, `kernel/src/boot/inspect_views.rs` (`gen_proc_clock`).

## Sleeping and deadlines

* **`SYS_SLEEP_UNTIL`** blocks the caller on the counter. `a0` is an absolute deadline in nanoseconds on the monotonic clock (converted with `ns_to_ticks_ceil`), or, with `SLEEP_RELATIVE` in `a1`, a duration from now. It returns 0 after blocking, 1 if the deadline had already passed at entry, and `-EINVAL` for an unknown flag. The caller waits on `WaitReason::Timer`; the timer interrupt wakes expired sleepers and programs the next interrupt for the nearest deadline. `azos_libsys::clock_nanosleep_abs` is the POSIX shape over it.
* **Message deadlines.** A call carries `MsgDesc::deadline` and `MsgDesc::clock_id`. The kernel serves one clock there: any `clock_id` other than `ClockId::MONO` is refused with `-EINVAL`. A non-zero deadline at or before now is refused with `-EDEADLINE` and a `Rule::DeadlineExpired` decision record, before the call is queued.
* **Tick rate.** `timebase::sched_hz_get` is the scheduler tick rate (Kconfig `SCHED_HZ`); the comparator is programmed at the earlier of the next tick and the nearest timer deadline, so a sleeper wakes on time between ticks (see [scheduler.md](scheduler.md)).

Source: `crates/core/syscall/src/sleep.rs`, `crates/core/abi/src/syscall_nr.rs` (`SYS_SLEEP_UNTIL`, `SLEEP_RELATIVE`), `crates/core/syscall/src/ipc_deadline.rs`, `crates/core/abi/src/ipc_msg.rs` (`MsgDesc`), `crates/drivers/sys/src/timebase.rs`.
