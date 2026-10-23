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
//! **The channel.** On a PC the buzzer is the PC speaker (`crates/drivers/
//! pcspk`): PIT channel 2 and port 0x61, which this program drives itself
//! through the I/O ports its row grants (`ioport.66.2`, `ioport.97.1`;
//! `DEVICE_IOPORT_ENABLE` opens them to each of its two threads), once a
//! silent check has seen the counter tick. Where the row grants no port (the
//! ISAs without a port space) or the check fails (a machine with no
//! speaker), the channel is the `Pwm` interface's, below.
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

use core::sync::atomic::{AtomicU32, Ordering};

use azos_buzzer::{Driver, Pwm, BUZZER_PWM_CHANNEL, SOURCE_MARKER};
use azos_devif::{BuzzerIdl, MsgDesc};
use azos_libsys as sys;
use azos_pcspk::{PcSpeaker, Ports, PORT_GATE, RANGE_GATE, RANGE_PIT};
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

/// The PC speaker's two port ranges, open to the calling thread.
struct SpeakerPorts {
    pit: sys::IoPorts,
    gate: sys::IoPorts,
}

impl SpeakerPorts {
    /// Open both ranges to the calling thread: `None` when the row grants
    /// them not, or the ISA has no port space.
    fn open() -> Option<Self> {
        let pit = sys::ioport_open(RANGE_PIT.0, RANGE_PIT.1).ok()?;
        let gate = sys::ioport_open(RANGE_GATE.0, RANGE_GATE.1).ok()?;
        Some(SpeakerPorts { pit, gate })
    }

    /// Give both ranges up: the channel is the `Pwm` interface's after all.
    fn close(self) {
        let _ = (self.pit.close(), self.gate.close());
    }

    fn range(&self, port: u16) -> &sys::IoPorts {
        if port == PORT_GATE { &self.gate } else { &self.pit }
    }
}

impl Ports for SpeakerPorts {
    fn inb(&mut self, port: u16) -> u8 {
        self.range(port).inb(port)
    }
    fn outb(&mut self, port: u16, v: u8) {
        self.range(port).outb(port, v)
    }
}

/// The buzzer's channel: the PC speaker, or the kernel's PWM channel.
enum Channel {
    Speaker(PcSpeaker<SpeakerPorts>),
    Pwm(EpPwm),
}

impl Pwm for Channel {
    fn set_period_ns(&mut self, period_ns: u32) -> bool {
        match self {
            Channel::Speaker(s) => s.set_period_ns(period_ns),
            Channel::Pwm(p) => p.set_period_ns(period_ns),
        }
    }
    fn set_duty_pct(&mut self, pct: u32) -> bool {
        match self {
            Channel::Speaker(s) => s.set_duty_pct(pct),
            Channel::Pwm(p) => p.set_duty_pct(pct),
        }
    }
    fn enable(&mut self) -> bool {
        match self {
            Channel::Speaker(s) => s.enable(),
            Channel::Pwm(p) => p.enable(),
        }
    }
    fn disable(&mut self) -> bool {
        match self {
            Channel::Speaker(s) => s.disable(),
            Channel::Pwm(p) => p.disable(),
        }
    }
}

/// The period of the speaker's silent check (1 kHz), and the reads of
/// `OUT2` it may take to see both levels: at an `in` per few hundred
/// nanoseconds, many periods.
const CHECK_PERIOD_NS: u32 = 1_000_000;
const CHECK_READS: u32 = 1 << 16;

/// Set when the channel is the speaker: the timer thread opens the ports
/// for itself before it touches the channel.
static SPEAKER: AtomicBool = AtomicBool::new(false);

/// The PC speaker, when this thread can open its ports and its counter
/// ticks; `None` otherwise.
fn speaker() -> Option<PcSpeaker<SpeakerPorts>> {
    let mut spk = PcSpeaker::new(SpeakerPorts::open()?);
    if !spk.counter_runs(CHECK_PERIOD_NS, CHECK_READS) {
        sys::println(b"[buzzdrv] PC speaker ports open, PIT channel 2 does not tick: using the pwm endpoint");
        spk.into_ports().close();
        return None;
    }
    sys::println(b"[buzzdrv] PC speaker: PIT channel 2 ticks, ports 0x42-0x43 and 0x61 open in ring 3");
    Some(spk)
}

/// What the two threads share: the chip logic and the clock it was last
/// advanced to.
struct State {
    drv: Driver<Channel>,
    last_ms: u64,
}

static SHARED: sys::Lock<Option<State>> = sys::Lock::new(None);

/// Bumped by the main thread whenever a call may have changed the sound; the
/// timer thread's futex word.
static CHANGED: AtomicU32 = AtomicU32::new(0);

/// Run `f` on the shared state. Spins (yielding) while the other thread has
/// it: its critical sections are a few register-form calls long.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let r = SHARED.lock().as_mut().map(f);
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
    // The ports are open per thread: this one ends a tone too.
    if SPEAKER.load(Ordering::Acquire) && SpeakerPorts::open().is_none() {
        sys::println(b"[buzzdrv] FAILED: the timer thread cannot open the speaker's ports");
        sys::exit(1);
    }
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
    let channel = match speaker() {
        Some(spk) => {
            SPEAKER.store(true, Ordering::Release);
            Channel::Speaker(spk)
        }
        None => match sys::dev::lookup(sys::dev::key::PWM, BUZZER_PWM_CHANNEL) {
            Some(pwm) => Channel::Pwm(EpPwm(PwmClient::new(Regs(pwm)))),
            None => {
                sys::println(b"[buzzdrv] FAILED: no pwm endpoint for the buzzer channel");
                sys::exit(1);
            }
        },
    };
    // Silent before serving, as the kernel host leaves the channel. While the
    // driver is placed in the kernel this host is a standby and the kernel
    // refuses its writes to the channel (`Pwm` is served per channel, and the
    // buzzer's has one holder), so this cuts nothing the kernel host plays; the
    // refusals are ignored, as is a timed step of a sound left over from before
    // a move.
    *SHARED.lock() = Some(State {
        drv: Driver::new(channel),
        last_ms: clock_ms().unwrap_or(0),
    });
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
