// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 piezo buzzer driver: the ring-3 host of `crates/drivers/buzzer`.
//!
//! It serves the `Buzzer` interface (`azos_devif::buzzer`) on the endpoint
//! its topology row grants it, `endpoint.buzzer` (`READ`: serving). Whoever
//! holds a `WRITE` capability on the endpoint calls it through the generated
//! `BuzzerClient`: the kernel's callers do (`azos_syscall::kcall`), and so
//! could any ring-3 task whose row said so. The same chip logic is the kernel
//! host of the driver (`crates/drivers/actuator`, called directly); the
//! topology row's placement says which of the two runs, and a `stateless` row
//! such as this one can be moved between them while the system runs.
//!
//! The PWM controller itself stays in the kernel (rule 1): this program
//! reaches it only through the `Pwm` interface's register-form calls, which
//! the kernel serves per channel and refuses on any motor-bound channel, and,
//! on the buzzer's own channel, while the driver is placed in the kernel (the
//! channel has one holder at a time; this host is kept up, idle, for a
//! demotion). It
//! holds no state a restart cannot rebuild: a sound that was playing when it
//! ended is simply not played.
//!
//! Every op is answered BEFORE the sound finishes: a tone request returns
//! once the tone has started. A tone, a beep or a pattern is a list of steps
//! the chip logic plays against the vDSO clock, so the caller never waits
//! for a melody. A new request replaces whatever is playing.
//!
//! Two threads, because a call can arrive while a step is due: the main
//! thread accepts calls (`SYS_IPC_ACCEPT_V2` waits for nothing but a call),
//! the timer thread advances the steps, parked on a futex until the current
//! one is due or a call has changed the sound. The chip logic is behind one
//! lock they share; the lock is held across a handful of register-form PWM
//! calls (served on the caller's own stack by the kernel, never queued) and
//! never across a wait.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_buzzer::{Driver, Pwm, BUZZER_PWM_CHANNEL, SOURCE_MARKER};
use azos_devif::{BuzzerIdl, MsgDesc};
use azos_libsys as sys;
use sys::dev::{PwmCall, PwmClient, Regs};

/// The monotonic clock in milliseconds (vDSO), or `None` when the kernel
/// publishes no clock (the page reads 0).
fn clock_ms() -> Option<u64> {
    match sys::vdso_now_ns() {
        0 => None,
        ns => Some(ns / 1_000_000),
    }
}

/// The buzzer's channel through the `Pwm` interface, which the kernel serves
/// per channel (and refuses on any motor-bound one).
struct EpPwm(PwmClient<Regs>);

impl Pwm for EpPwm {
    fn set_period_ns(&mut self, period_ns: u32) -> bool {
        sys::dev::succeeded(self.0.set_period(period_ns))
    }
    fn set_duty_pct(&mut self, pct: u32) -> bool {
        sys::dev::succeeded(self.0.set_duty_pct(pct))
    }
    fn enable(&mut self) -> bool {
        sys::dev::succeeded(self.0.enable())
    }
    fn disable(&mut self) -> bool {
        sys::dev::succeeded(self.0.disable())
    }
}

/// What the two threads share: the chip logic and the clock it was last
/// advanced to.
struct State {
    drv: Driver<EpPwm>,
    last_ms: u64,
}

struct Shared {
    lock: AtomicBool,
    state: UnsafeCell<Option<State>>,
}
// SAFETY: `state` is touched only with `lock` held (`with`).
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared { lock: AtomicBool::new(false), state: UnsafeCell::new(None) };

/// Bumped by the main thread whenever a call may have changed the sound; the
/// timer thread's futex word.
static CHANGED: AtomicU32 = AtomicU32::new(0);

/// Run `f` on the shared state. Spins (yielding) while the other thread has
/// it: its critical sections are a few register-form calls long.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while SHARED.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: the lock is held.
    let r = match unsafe { (*SHARED.state.get()).as_mut() } {
        Some(st) => Some(f(st)),
        None => None,
    };
    SHARED.lock.store(false, Ordering::Release);
    r.expect("buzz_drv: state used before it was set up")
}

/// Play the time that passed since the last advance first, so a request that
/// does not replace the sound does not stretch the step. No clock: only a
/// park that ran to its end is known (`ran_ms`).
fn catch_up(st: &mut State, ran_ms: u32) {
    let e = match clock_ms() {
        Some(t) => {
            let e = t.saturating_sub(st.last_ms).min(u32::MAX as u64) as u32;
            st.last_ms = t;
            e
        }
        None => ran_ms,
    };
    st.drv.elapse(e);
}

/// Longest the timer thread parks with nothing timed (ms): a lost wake costs
/// at most this.
const IDLE_PARK_MS: u32 = 1_000;

/// The timer thread's stack.
#[repr(C, align(16))]
struct Stack([u8; 8192]);
static mut TIMER_STACK: Stack = Stack([0; 8192]);

extern "C" fn timer_thread(_: u64, _: u64, _: u64) -> ! {
    loop {
        // Read the word BEFORE looking at the sound: a call that lands in
        // between changes it and the wait returns at once.
        let seen = CHANGED.load(Ordering::Acquire);
        let park = with(|st| {
            catch_up(st, 0);
            st.drv.player.park_ms()
        });
        let ms = if park == 0 { IDLE_PARK_MS } else { park };
        let _ = sys::futex_wait(&CHANGED, seen, ms as u64 * 1_000_000);
        // A park that ran to its end with no clock is the only time known.
        if clock_ms().is_none() {
            with(|st| st.drv.elapse(ms));
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let Some(pwm) = sys::dev::lookup(sys::dev::key::PWM, BUZZER_PWM_CHANNEL) else {
        sys::println(b"[buzzdrv] FAILED: no pwm endpoint for the buzzer channel");
        sys::exit(1);
    };
    // Silent before serving, as the kernel host leaves the channel. While the
    // driver is placed in the kernel this host is a standby and the kernel
    // refuses its writes to the channel (`Pwm` is served per channel, and the
    // buzzer's has one holder), so this cuts nothing the kernel host plays; the
    // refusals are ignored, as is a timed step of a sound left over from before
    // a move.
    // SAFETY: no other thread exists yet.
    unsafe {
        *SHARED.state.get() = Some(State {
            drv: Driver::new(EpPwm(PwmClient::new(Regs(pwm)))),
            last_ms: clock_ms().unwrap_or(0),
        });
    }
    // The stack is the timer thread's alone, and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(TIMER_STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(timer_thread, top, 0, core::ptr::null_mut()) < 0 {
        sys::println(b"[buzzdrv] FAILED: no thread for the timed steps");
        sys::exit(1);
    }
    sys::println(b"[buzzdrv] serving the Buzzer interface on endpoint.buzzer");
    // The chip-logic source this host runs (`tools/chip_source_check.py`).
    sys::print(b"[buzzdrv] ");
    sys::println(&SOURCE_MARKER);

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let mut rep = MsgDesc::default();
        with(|st| {
            catch_up(st, 0);
            let _ = BuzzerIdl::dispatch(&mut st.drv, &req, &mut rep);
        });
        // The timer thread re-reads the park: a new sound may be due sooner.
        CHANGED.fetch_add(1, Ordering::Release);
        let _ = sys::futex_wake(&CHANGED, 1);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}
