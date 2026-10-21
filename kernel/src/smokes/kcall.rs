// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel as a caller of an endpoint a task serves (Phase 4 elasticity),
//! every ISA. Kernel tasks make the v2 calls through `azos_syscall::kcall`,
//! the transport the placement of a driver uses.
//!
//! * `kernel_endpoint_call_reaches_a_task_server`: a task serves the `Buzzer`
//!   interface on a named endpoint (the ring-3 driver's shape: v2 accept,
//!   generated dispatcher, v2 reply); a kernel task calls it with the
//!   generated client stub over `KernelEndpoint`, and through `BuzzerPlaced`
//!   with the endpoint arm and then the direct arm, and the three agree.
//! * `kernel_endpoint_call_is_refused_under_a_spinlock`: the same call made
//!   with a spinlock held, and from the closure of `cap_store::with_table`,
//!   is refused with `-EBUSY` before anything is queued, and counted; the
//!   same call outside a lock is not refused for that reason.
//!   Canary `kcall-atomic-canary`: the guard is skipped, `not ok`.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};

use azos_abi::error::Errno;
use azos_abi::ipc_msg::MsgDesc;
use azos_abi::syscall_nr::{SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2};
use azos_devif::{outcome, Buzzer, BuzzerCall, BuzzerClient, BuzzerDirect, BuzzerIdl, BuzzerPlaced, Out};
use azos_ipc::cap::CapPerms;
use azos_syscall::kcall::{self, KernelEndpoint};
use azos_syscall::SyscallOut;

const PRIO: u32 = 12;
const NOT_YET: i64 = i64::MIN;
const SERVED_EP: &[u8] = b"kcall.buzzer";
const GUARD_EP: &[u8] = b"kcall.guard";

fn dispatch(num: u64, a: [u64; 6], out: &mut SyscallOut) -> i64 {
    let regs = azos_sched::UserRegs::default();
    azos_syscall::syscall_dispatch_out(num, a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, &regs, out)
}

/// A buzzer that counts what it was asked and refuses an alert, so the
/// outcome code has something to carry.
#[derive(Default)]
struct Counting {
    tones: u32,
    alerts: u32,
}

impl Buzzer for Counting {
    fn tone(&mut self, _: u32, _: u32) -> Out<()> { self.tones += 1; Out::ok(()) }
    fn on(&mut self, _: u32) -> Out<()> { Out::ok(()) }
    fn off(&mut self) -> Out<()> { Out::ok(()) }
    fn beep(&mut self) -> Out<()> { Out::ok(()) }
    fn alert(&mut self) -> Out<()> { self.alerts += 1; Out::err(outcome::FAULT) }
    fn startup(&mut self) -> Out<()> { Out::ok(()) }
}

static SERVER_READY: AtomicBool = AtomicBool::new(false);
static SERVER_SERVED: AtomicU32 = AtomicU32::new(0);
/// Calls the server is to take before it ends (the client's three stubs).
const CALLS: u32 = 3;
static CLIENT: AtomicI64 = AtomicI64::new(NOT_YET);

fn server(_: usize) {
    let me = azos_sched::current_task_tid();
    if azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, SERVED_EP).is_none() {
        return;
    }
    SERVER_READY.store(true, Ordering::Release);
    let mut drv = Counting::default();
    let mut out = SyscallOut::new();
    while SERVER_SERVED.load(Ordering::Acquire) < CALLS {
        let mut req = MsgDesc::default();
        let h = dispatch(SYS_IPC_ACCEPT_V2, [&mut req as *mut MsgDesc as u64, 0, 0, 0, 0, 0], &mut out);
        if h < 0 {
            continue;
        }
        let mut rep = MsgDesc::default();
        let _ = BuzzerIdl::dispatch(&mut drv, &req, &mut rep);
        let _ = dispatch(SYS_IPC_REPLY_V2, [h as u64, &rep as *const MsgDesc as u64, 0, 0, 0, 0], &mut out);
        SERVER_SERVED.fetch_add(1, Ordering::AcqRel);
    }
}

fn client(_: usize) {
    let Some(h) = kcall::endpoint_handle(SERVED_EP) else {
        CLIENT.store(-1, Ordering::Release);
        return;
    };
    // The same handle again: the kernel mints one capability per task.
    if kcall::endpoint_handle(SERVED_EP) != Some(h) {
        CLIENT.store(-2, Ordering::Release);
        return;
    }
    let mut c = BuzzerClient::new(KernelEndpoint(h));
    let step = if c.tone(440, 50) != Ok(Out::ok(())) {
        -3
    } else if c.alert() != Ok(Out::err(outcome::FAULT)) {
        -4
    } else {
        // Through the placed value: the endpoint arm (the server counts it),
        // then the direct arm (its own driver, no message).
        let mut p: BuzzerPlaced<Counting, KernelEndpoint> = BuzzerPlaced::Endpoint(BuzzerClient::new(KernelEndpoint(h)));
        let via_ep = p.tone(1, 1);
        let mut p: BuzzerPlaced<Counting, KernelEndpoint> = BuzzerPlaced::Direct(BuzzerDirect(Counting::default()));
        let direct = p.tone(1, 1);
        if via_ep != Ok(Out::ok(())) {
            -5
        } else if direct != Ok(Out::ok(())) {
            -6
        } else {
            1
        }
    };
    CLIENT.store(step, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn kernel_endpoint_call_reaches_a_task_server() {
        azos_sched::task_create_affinity("kcall-srv", server, 0, PRIO, -1);
        crate::ktest::wait("the server never claimed its endpoint", || SERVER_READY.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("kcall-cli", client, 0, PRIO, -1);
        crate::ktest::wait("the caller never returned", || CLIENT.load(Ordering::Acquire) != NOT_YET)?;
        match CLIENT.load(Ordering::Acquire) {
            1 => {}
            -1 => return Err("the kernel could not mint the caller a capability on the endpoint"),
            -2 => return Err("a second endpoint_handle minted another capability"),
            -3 => return Err("a tone through the generated client stub was not served"),
            -4 => return Err("the server's outcome code did not travel back in the reply"),
            -5 => return Err("the placed value's endpoint arm was not served"),
            _ => return Err("the placed value's direct arm was not served"),
        }
        // Three calls reached the server: tone, alert, and the placed tone.
        if SERVER_SERVED.load(Ordering::Acquire) != 3 {
            return Err("the server did not take exactly the three calls made through the endpoint");
        }
        Ok(())
    }
}

static GUARD_RC: [AtomicI64; 3] = [const { AtomicI64::new(NOT_YET) }; 3];
static GUARD_REFUSALS: AtomicU32 = AtomicU32::new(0);

fn guard_client(_: usize) {
    let me = azos_sched::current_task_tid();
    let Some(h) = kcall::endpoint_handle(GUARD_EP) else { return };
    let mut m = MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    let before = kcall::atomic_refusals();
    // Outside any lock: nobody serves the endpoint, so the call fails for
    // that reason (-1), not for being made where it may not block.
    let free = kcall::call(h, &mut m).err();
    GUARD_RC[0].store(free.unwrap_or(0), Ordering::Release);
    // With a spinlock held.
    let lock = azos_sync::SpinLock::new(());
    let under_lock = {
        let _g = lock.lock();
        kcall::call(h, &mut m).err()
    };
    GUARD_RC[1].store(under_lock.unwrap_or(0), Ordering::Release);
    // From the closure of `cap_store::with_table`: the capability table's lock
    // is held for the closure.
    let under_table = azos_ipc::cap_store::with_table(me, |_| kcall::call(h, &mut m).err()).flatten();
    GUARD_RC[2].store(under_table.unwrap_or(0), Ordering::Release);
    GUARD_REFUSALS.store(kcall::atomic_refusals().wrapping_sub(before), Ordering::Release);
}

azos_ktest::ktest_late! {
    fn kernel_endpoint_call_is_refused_under_a_spinlock() {
        azos_sched::task_create_affinity("kcall-guard", guard_client, 0, PRIO, -1);
        crate::ktest::wait("the caller never returned", || GUARD_RC[2].load(Ordering::Acquire) != NOT_YET)?;
        let busy = Errno::EBUSY.to_syscall_ret();
        if GUARD_RC[0].load(Ordering::Acquire) == busy {
            return Err("a call made where it may block was refused as atomic");
        }
        if GUARD_RC[1].load(Ordering::Acquire) != busy {
            return Err("a call made with a spinlock held was not refused with -EBUSY");
        }
        if GUARD_RC[2].load(Ordering::Acquire) != busy {
            return Err("a call made inside cap_store::with_table's closure was not refused with -EBUSY");
        }
        if GUARD_REFUSALS.load(Ordering::Acquire) != 2 {
            return Err("the refusals under the locks were not both counted");
        }
        Ok(())
    }
}
