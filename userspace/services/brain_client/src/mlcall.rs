// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The engine's inference call: the system-call half of `ml.rs`.
//!
//! A blocked `SYS_IPC_CALL` has no timeout of its own, and an inference service
//! that is alive and not answering must not hold the engine, which publishes
//! the motor command and keeps the brain link. So a helper thread makes the
//! call, one at a time, and the engine waits for it with a futex timeout: a
//! call that does not come back in the budget is a missing verdict
//! (`ml::cycle`), and so is every cycle until it does.
//!
//! The helper owns the capability on `endpoint.infer` and the two one-page
//! tensor objects, lent to the service on every call (`ml::Lending`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use azos_libsys as sys;
use sys::dev::{Cap, Ep};

use crate::behave::Ml;
use crate::ml::{self, Caller, MlOutcome, TensorMem, OUTPUT_BYTES, POISON_BITS};

/// The helper's stack: a call's descriptor, the client stub and the frames
/// under them.
const STACK_BYTES: usize = 8 * 1024;

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);
static mut STACK: Stack = Stack([0; STACK_BYTES]);

/// Request `REQ` is published by the engine (the only writer) after
/// `READINGS` and `DEADLINE_NS`; the helper answers by writing `RESULT` and
/// then `DONE`, both to the request's number.
static REQ: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
/// `front_mm | right_mm << 16`.
static READINGS: AtomicU32 = AtomicU32::new(0);
/// The call's absolute deadline, nanoseconds on the monotonic clock.
static DEADLINE_NS: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicU32 = AtomicU32::new(0);

/// A one-page memory object this task made and mapped.
struct Page {
    cap: u32,
    base: *mut u32,
}

impl Page {
    fn new() -> Option<Page> {
        let cap = sys::shm_create_typed(1, sys::SHM_RW);
        if cap <= 0 {
            return None;
        }
        let va = sys::shm_map_typed(cap as u32);
        if va <= 0 {
            return None;
        }
        Some(Page { cap: cap as u32, base: va as usize as *mut u32 })
    }
}

/// What the helper holds for the life of the process.
struct Client {
    ep: u32,
    input: Page,
    output: Page,
}

static mut CLIENT: Option<Client> = None;

/// The two tensor objects as `ml::infer_once` reads and writes them. The
/// service maps the same pages, so every access is volatile.
struct Mem<'a>(&'a Client);

impl TensorMem for Mem<'_> {
    fn prepare(&mut self, input: [u32; 4]) -> bool {
        // SAFETY: each page is one mapped page this task owns until exit; the
        // stores stay inside the first 16 and 12 bytes.
        unsafe {
            for (i, w) in input.iter().enumerate() {
                self.0.input.base.add(i).write_volatile(w.to_le());
            }
            for i in 0..OUTPUT_BYTES / 4 {
                self.0.output.base.add(i).write_volatile(POISON_BITS.to_le());
            }
        }
        true
    }

    fn output(&mut self) -> Option<[u32; 3]> {
        // SAFETY: as in `prepare`.
        Some(unsafe { core::array::from_fn(|i| u32::from_le(self.0.output.base.add(i).read_volatile())) })
    }
}

extern "C" fn helper(_: u64, _: u64, _: u64) -> ! {
    // SAFETY: written once by `start` before this thread exists, never again.
    let c = unsafe { (*core::ptr::addr_of!(CLIENT)).as_ref() }.expect("client set before the helper starts");
    let mut seen = 0u32;
    loop {
        let req = REQ.load(Ordering::Acquire);
        if req == seen {
            let _ = sys::futex_wait(&REQ, seen, 0);
            continue;
        }
        seen = req;
        let r = READINGS.load(Ordering::Relaxed);
        let a = ml::infer_once(
            Ep(c.ep),
            &mut Mem(c),
            Cap::<sys::dev::infer::Tensor>::from_raw(c.input.cap),
            Cap::<sys::dev::infer::Tensor>::from_raw(c.output.cap),
            ml::BEHAVIOR_MODEL_REF,
            DEADLINE_NS.load(Ordering::Relaxed),
            r as u16,
            (r >> 16) as u16,
        );
        RESULT.store(a.outcome.to_word(), Ordering::Relaxed);
        DONE.store(req, Ordering::Release);
        let _ = sys::futex_wake(&DONE, 1);
    }
}

struct Helper;

impl Caller for Helper {
    fn busy(&self) -> bool {
        REQ.load(Ordering::Relaxed) != DONE.load(Ordering::Acquire)
    }

    fn call(&mut self, front_mm: u16, right_mm: u16, budget_ns: u64) -> Option<MlOutcome> {
        let deadline = sys::vdso_now_ns().saturating_add(budget_ns);
        READINGS.store(front_mm as u32 | (right_mm as u32) << 16, Ordering::Relaxed);
        DEADLINE_NS.store(deadline, Ordering::Relaxed);
        let seq = REQ.load(Ordering::Relaxed).wrapping_add(1);
        REQ.store(seq, Ordering::Release);
        let _ = sys::futex_wake(&REQ, 1);
        loop {
            let done = DONE.load(Ordering::Acquire);
            if done == seq {
                return Some(MlOutcome::from_word(RESULT.load(Ordering::Relaxed)));
            }
            let left = deadline.saturating_sub(sys::vdso_now_ns());
            if left == 0 {
                return None;
            }
            let _ = sys::futex_wait(&DONE, done, left);
        }
    }
}

/// How the engine stands with the service.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// The topology grants no inference endpoint: no model is asked.
    Off,
    /// It grants one and the client could not be set up: every verdict is
    /// missing.
    Down,
    Up,
}

/// Look up the endpoint and start the helper.
pub fn start() -> Link {
    let ep = sys::cap_lookup_endpoint(ml::INFER_ENDPOINT, azos_abi::cap::CapPerms::WRITE.bits() as u8, 0);
    if ep <= 0 {
        return Link::Off;
    }
    let (Some(input), Some(output)) = (Page::new(), Page::new()) else { return Link::Down };
    // SAFETY: single-threaded until the thread below starts; written once.
    unsafe { CLIENT = Some(Client { ep: ep as u32, input, output }) };
    // The stack is the helper's alone and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(helper, top, 0, core::ptr::null_mut()) < 0 {
        return Link::Down;
    }
    Link::Up
}

/// This cycle's verdict on the two readings, within the budget
/// (`ML_REPLY_TIMEOUT_US`).
pub fn ask(link: Link, front_mm: u16, right_mm: u16) -> (Ml, Option<MlOutcome>) {
    match link {
        Link::Off => (Ml::Off, None),
        Link::Down => (Ml::Missing, Some(MlOutcome::Unavailable)),
        Link::Up => {
            let o = ml::cycle(&mut Helper, front_mm, right_mm, azos_limits::ML_REPLY_TIMEOUT_US * 1_000);
            (ml::verdict_of(o), Some(o))
        }
    }
}
