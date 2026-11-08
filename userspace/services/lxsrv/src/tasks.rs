// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The server's cooperative loop: `lx_emul`'s [`Env`] on this process's one
//! thread, with stacks the server maps and the vDSO clock as its time.
//!
//! Each task stack is anonymous memory with its lowest page unmapped again,
//! so a task that runs off its stack faults on the hole instead of writing
//! into the mapping below it (`lx_emul` also checks a canary word at the
//! base on every switch back). Native tasks map at the break, which only
//! grows, so nothing is ever placed in the hole later.
//!
//! [`run_scene`] drives the blocking primitives a Linux driver's probe
//! reaches on real stacks and the real clock, and prints one `[LXSRV] tasks:`
//! line the gate row keys on. Between passes the server sleeps in
//! `SYS_SLEEP_UNTIL` until the deadline [`Env::run_once`] returns.

use core::cell::{Cell, UnsafeCell};

use azos_libsys as sys;
use lx_emul::lock::{Completion, Mutex, TaskId, WaitQueueHead};
use lx_emul::sched::CurrentState;
use lx_emul::timer::msecs_to_jiffies;
use lx_emul::workqueue::WorkHandle;
use lx_emul::Env;

use super::{dec, line, mix};

/// Task stacks: three kernel threads and the kworker.
const STACKS: usize = 4;
/// Bytes of one task stack, Linux's `THREAD_SIZE` on 64-bit.
const STACK_BYTES: usize = 16 * 1024;
/// The whole scene's wall-clock budget.
const BUDGET_NS: u64 = 5_000_000_000;
const MS: u64 = 1_000_000;
const SLEEP_MS: u64 = 20;
const TIMEOUT_MS: u64 = 10;
const WORK_DELAY_MS: u64 = 30;
const DEPTH: u64 = 8;
const STOP_CODE: i32 = 7;
const ORDER: &[u8] = b"abcdefg";

struct EnvCell(UnsafeCell<Env>);
// SAFETY: single-threaded process; only `run_scene` and the tasks it runs
// (on this same thread) reach the environment.
unsafe impl Sync for EnvCell {}
/// In a static so it never moves once it holds stacks (`Env::add_stack`).
static ENV: EnvCell = EnvCell(UnsafeCell::new(Env::new()));

/// What the tasks share and what the line reports.
struct Scene {
    lock: Mutex,
    done: Completion,
    never: Completion,
    wq: WaitQueueHead,
    flag: Cell<bool>,
    order: Cell<[u8; 8]>,
    n: Cell<usize>,
    errors: Cell<u32>,
    looper: Cell<Option<TaskId>>,
    sleep_ns: Cell<u64>,
    deep_ok: Cell<bool>,
    timeout_left: Cell<u64>,
    timeout_ns: Cell<u64>,
    event_left: Cell<u64>,
    stop_code: Cell<i32>,
}

impl Scene {
    fn mark(&self, c: u8) {
        let mut o = self.order.get();
        let n = self.n.get();
        if n < o.len() {
            o[n] = c;
            self.order.set(o);
        }
        self.n.set(n + 1);
    }

    fn check<T, E>(&self, r: Result<T, E>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(_) => {
                self.errors.set(self.errors.get() + 1);
                None
            }
        }
    }
}

fn scene(data: usize) -> &'static Scene {
    // SAFETY: `data` is the address of the `Scene` in `run_scene`'s frame,
    // which outlives every pass that runs a task or a work item.
    unsafe { &*(data as *const Scene) }
}

/// A call chain whose every frame holds a value across the sleep at its
/// bottom: a register or a frame the switch failed to keep changes the result.
fn deep(env: &mut Env, s: &Scene, n: u64, acc: u64) -> u64 {
    if n == 0 {
        let t0 = sys::vdso_now_ns();
        s.check(env.msleep(SLEEP_MS));
        s.sleep_ns.set(sys::vdso_now_ns().saturating_sub(t0));
        return acc;
    }
    let x = mix(acc, n);
    let r = deep(env, s, n - 1, core::hint::black_box(x));
    mix(r, x)
}

fn deep_reference(n: u64, acc: u64) -> u64 {
    if n == 0 {
        return acc;
    }
    let x = mix(acc, n);
    mix(deep_reference(n - 1, x), x)
}

/// Holds the mutex across a sleep, waits for the contender's completion,
/// then stops the looper.
fn holder(env: &mut Env, data: usize) -> i32 {
    let s = scene(data);
    s.check(env.mutex_lock(&s.lock));
    s.deep_ok.set(deep(env, s, DEPTH, 1) == deep_reference(DEPTH, 1));
    s.mark(b'a');
    s.check(env.mutex_unlock(&s.lock));
    s.check(env.wait_for_completion(&s.done));
    s.mark(b'e');
    if let Some(id) = s.looper.get() {
        if let Some(code) = s.check(env.kthread_stop(id)) {
            s.stop_code.set(code);
        }
    }
    s.mark(b'g');
    0
}

/// Sleeps on the held mutex, then waits for the delayed work's event.
fn contender(env: &mut Env, data: usize) -> i32 {
    let s = scene(data);
    s.check(env.mutex_lock(&s.lock));
    s.mark(b'b');
    s.check(env.mutex_unlock(&s.lock));
    let left = s.check(env.wait_event_timeout(&s.wq, |_| s.flag.get(), msecs_to_jiffies(1000)));
    s.event_left.set(left.unwrap_or(0));
    s.mark(b'd');
    env.complete(&s.done);
    0
}

/// Times out on a completion nobody signals, then sleeps until stopped.
fn looper(env: &mut Env, data: usize) -> i32 {
    let s = scene(data);
    let t0 = sys::vdso_now_ns();
    let left = s.check(env.wait_for_completion_timeout(&s.never, msecs_to_jiffies(TIMEOUT_MS)));
    s.timeout_ns.set(sys::vdso_now_ns().saturating_sub(t0));
    s.timeout_left.set(left.unwrap_or(u64::MAX));
    while !env.kthread_should_stop() {
        env.set_current_state(CurrentState::Sleeping);
        s.check(env.schedule_timeout(msecs_to_jiffies(1000)));
    }
    s.mark(b'f');
    STOP_CODE
}

fn raise_flag(env: &mut Env, _w: WorkHandle) {
    let s = scene(env.user);
    s.flag.set(true);
    s.mark(b'c');
    env.wake_up(&s.wq);
}

/// `len` bytes of stack above one unmapped guard page.
fn guarded_stack(len: usize) -> Option<*mut u8> {
    let page = sys::PAGE_SIZE;
    let base = sys::mmap(0, (len + page) as u64, sys::PROT_READ | sys::PROT_WRITE, 0, sys::MAP_ANON_FD, 0);
    if base <= 0 || sys::munmap(base as u64, page as u64) != 0 {
        return None;
    }
    Some((base as usize + page) as *mut u8)
}

/// The time the passes run at. The gate's canary build feeds a clock that
/// jumps a second per pass and never sleeps: the row must see the sleeps
/// end early.
#[cfg(not(feature = "tasks-clock-canary"))]
fn pass_time(_env: &Env) -> u64 {
    sys::vdso_now_ns()
}
#[cfg(feature = "tasks-clock-canary")]
fn pass_time(env: &Env) -> u64 {
    env.clock.now_ns().max(sys::vdso_now_ns()) + 1_000_000_000
}

/// Run the scene to the end, print its line; true on PASS.
pub fn run_scene() -> bool {
    // SAFETY: see `EnvCell`; nothing else holds a reference.
    let env = unsafe { &mut *ENV.0.get() };
    #[cfg(not(feature = "tasks-clock-canary"))]
    env.clock.set_source(sys::vdso_now_ns);
    for _ in 0..STACKS {
        let Some(base) = guarded_stack(STACK_BYTES) else {
            line(&[b"[LXSRV] tasks: FAIL: no memory for a task stack"]);
            return false;
        };
        // SAFETY: a fresh mapping only this environment uses, for good; the
        // environment is a static and never moves.
        if unsafe { env.add_stack(base, STACK_BYTES) }.is_err() {
            line(&[b"[LXSRV] tasks: FAIL: a task stack was refused"]);
            return false;
        }
    }
    let s = Scene {
        lock: Mutex::new(),
        done: Completion::new(),
        never: Completion::new(),
        wq: WaitQueueHead::new(),
        flag: Cell::new(false),
        order: Cell::new([b'-'; 8]),
        n: Cell::new(0),
        errors: Cell::new(0),
        looper: Cell::new(None),
        sleep_ns: Cell::new(0),
        deep_ok: Cell::new(false),
        timeout_left: Cell::new(u64::MAX),
        timeout_ns: Cell::new(0),
        event_left: Cell::new(0),
        stop_code: Cell::new(-1),
    };
    let data = &s as *const Scene as usize;
    env.user = data;
    let start = sys::vdso_now_ns();
    env.clock.set_now_ns(start);
    let spawned = env.kthread_run(holder, data).is_some() && env.kthread_run(contender, data).is_some() && {
        s.looper.set(env.kthread_run(looper, data));
        s.looper.get().is_some()
    };
    let work = env.init_delayed_work(raise_flag, 0).ok();
    let queued = work.is_some_and(|w| env.queue_delayed_work(w, msecs_to_jiffies(WORK_DELAY_MS)) == Ok(true));

    let mut passes = 0u64;
    let mut over = false;
    loop {
        let now = pass_time(env);
        if sys::vdso_now_ns().saturating_sub(start) > BUDGET_NS {
            over = true;
            break;
        }
        passes += 1;
        match env.run_once(now) {
            None => break,
            Some(t) if !cfg!(feature = "tasks-clock-canary") && t > now => {
                let _ = sys::sleep_until_ns(t.min(start + BUDGET_NS));
            }
            Some(_) => {}
        }
    }
    if let Some(w) = work {
        let _ = env.free_work(w);
    }
    env.user = 0;

    let st = env.stats();
    let o = s.order.get();
    let order = &o[..s.n.get().min(o.len())];
    let slept = s.sleep_ns.get() >= SLEEP_MS * MS;
    let timed_out = s.timeout_left.get() == 0 && s.timeout_ns.get() >= TIMEOUT_MS * MS;
    let errors = s.errors.get() as u64 + st.stack_overflows as u64 + st.atomic_sleeps as u64 + st.would_block as u64;
    let checks: [(bool, &[u8]); 9] = [
        (spawned && queued, b"a task or the delayed work could not start"),
        (!over, b"the scene ran past its budget"),
        (slept, b"msleep(20) did not sleep 20 ms on the vDSO clock"),
        (order == ORDER, b"the tasks did not run in the order abcdefg"),
        (s.deep_ok.get(), b"a frame below the sleep lost its value"),
        (timed_out, b"wait_for_completion_timeout(10 ms) did not time out after 10 ms"),
        (s.event_left.get() > 0, b"wait_event_timeout was not woken by the work item"),
        (s.stop_code.get() == STOP_CODE, b"kthread_stop did not return the thread's code"),
        (errors == 0, b"a primitive failed or the loop counted a misuse"),
    ];
    let why = checks.iter().find(|(ok, _)| !ok).map(|(_, w)| *w);
    let mut d = [[0u8; 21]; 7];
    let [d0, d1, d2, d3, d4, d5, d6] = &mut d;
    line(&[b"[LXSRV] tasks: order ", order, b", msleep(20) ", dec((s.sleep_ns.get() / 1000) as i64, d0),
           b" us, completion timeout(10) ", dec((s.timeout_ns.get() / 1000) as i64, d1), b" us, kthread_stop ",
           dec(s.stop_code.get() as i64, d2), b", passes ", dec(passes as i64, d3), b", errors ", dec(errors as i64, d4),
           b", stacks ", dec(STACKS as i64, d5), b"x", dec((STACK_BYTES / 1024) as i64, d6), b" KiB guarded: ",
           if why.is_none() { b"PASS" } else { b"FAIL: " }, why.unwrap_or(b"")]);
    why.is_none()
}
