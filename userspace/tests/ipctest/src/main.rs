// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 IPC probe.
//!
//! WHY THIS EXISTS
//!
//! `SYS_IPC_FAST_CALL` / `_ACCEPT` / `_REPLY` have existed for months, are
//! documented, and — until this binary — **had never been executed from ring
//! 3**. The same was true of the ownership gates added to `shm`, `port` and
//! `io_ring`, and of the whole `Cap<T>` typed family. Five serious fast-IPC
//! defects survived in a tree whose CI was green, because green meant "it
//! compiles", not "it runs".
//!
//! This binary runs them. It is the difference between work done and work
//! verified.
//!
//! WHAT IT ASSERTS, AND WHY EACH HALF MATTERS
//!
//!   A. **Fast-IPC round trip: 8 clients x 200 calls, under `-smp 4`.** The
//!      parent is the server and answers in a loop with NO delay between
//!      accept and reply; eight `fork()`ed children hammer it. Each client
//!      asserts the word it collects is the *reply*, not its own *request* —
//!      that is IPC-2, where `fast_ipc_accept` marked a claimed slot
//!      `Replied` while `words` still held the request, so any wake between
//!      accept and reply made the client collect its own question as the
//!      answer.
//!
//!      1600 calls, not one. `SYS_IPC_FAST_CALL` allocates the slot, wakes
//!      the server, and only *then* blocks; on four harts the server can
//!      reply inside that window and the wake is lost, leaving the client
//!      asleep for good. A one-shot test passes over that race roughly
//!      always, and a `sleep` between accept and reply hides it outright.
//!      Progress is printed every 32 iterations so a hang reads as "child 3
//!      wedged at seq=137", not as "never started".
//!
//!      The server replies through `SYS_IPC_FAST_REPLY_ACCEPT` (RFC-0041 §C):
//!      every answer but the last shares its trap with the next accept, so
//!      the same 1600 calls are the combined call's round trip.
//!
//!   B. **Server impersonation.** `slot_idx` is a small integer the caller
//!      chooses, so a task that is not the server can reply into someone
//!      else's exchange. Three tasks: a server, a client, and the parent as
//!      the impostor sweeping all 64 slots with a poison word. BOTH halves
//!      are asserted — that every impostor reply is *refused*, and that the
//!      legitimate client still wakes with the *legitimate* word. The sweep
//!      also issues the combined call on every slot, and each must answer
//!      -3 and accept nothing.
//!
//!      The second half is the one this project keeps skipping. The reflex
//!      loop was declared verified off a log line saying it had decided to
//!      back up, while the motors were driving forward into the obstacle at
//!      full speed. A rejected return code proves a decision; only the
//!      client's collected payload proves the actuation.
//!
//!   C. **Ownership gates nobody executed.** A full typed shm map/write/
//!      release cycle in one task; 2,100 map/release cycles of a 64-page
//!      region that must all map at one address, more than the shm/MMIO
//!      window holds if a release did not give its addresses back; then a
//!      *different* task sweeping the
//!      parent's own `Cap<Shm>`, `Cap<Port>` and `Cap<IoRing>` handles looking
//!      for one that resolves. Both halves again: the owner must succeed where
//!      the stranger is refused, or the test would also pass against a kernel
//!      that denies everyone. The stranger uses the parent's exact handle
//!      values out of shared statics — a forked child holds only its
//!      inherited descriptors and its row's capabilities (wave 13), and every
//!      parent handle on anything else is stale in it, so every one must
//!      answer `-ECAPSTALE`.
//!
//!   D. **Typed capability past task 64.** `MAX_TASKS` is 64 and TIDs are
//!      monotone, so a TID-indexed cap table went permanently dead on a
//!      long-lived board once it had created its 64th task — the exact
//!      reason the tables were re-indexed by pool slot. This forks and
//!      reaps enough short-lived tasks to push the TID counter past 64,
//!      then mints and uses typed caps from a task whose TID is above it.
//!
//!   E. **Fast IPC actually carries the request.** Phases A and B prove an
//!      exchange completes and that an impostor cannot answer it; neither
//!      proves the server was told *what* was asked, because both reply a
//!      constant. `SYS_IPC_FAST_ACCEPT` returned only the slot index and
//!      threw away the caller TID and the four request words, so a ring-3
//!      server could answer but not answer *anything in particular* — a
//!      wake primitive wearing an RPC's documentation. This phase forks a
//!      server and a client, the client derives its request from its own
//!      TID, the server replies a function of all four received words, and
//!      the parent recomputes that function independently. A kernel that
//!      delivers nothing, zeros, or a stale payload fails it.
//!
//!   F. **A typed channel, from ring 3.** RFC-0040 gap 1's `Cap<Channel>`
//!      family (create/write/read/close, 573/528/529/566) has host tests and,
//!      until this phase, no ring-3 caller. A channel capability is not
//!      inherited across `fork` (a runtime object is in no row), so this runs in
//!      one task: create, write, read the bytes back, then close and confirm
//!      the handle is stale.
//!
//!   G. **Reply+accept on a stale handle.** `SYS_IPC_FAST_REPLY_ACCEPT` must
//!      answer -2 for a stale handle, distinct from phase B's -3, and accept
//!      nothing. The parent replies to one heartbeat call, holds the next one
//!      on the same slot, and replies+accepts with the first call's handle;
//!      the held exchange must still answer afterwards.
//!
//!   H. **One `Cap<Shm>` region mapped in two tasks.** A forked client
//!      creates and maps a region, writes a word into it, and MOVES the
//!      capability to its parent's endpoint with the call
//!      (`SYS_IPC_FAST_CALL_EP`, `a5`). The server maps the capability that
//!      arrived and must read the client's word; it writes one of its own
//!      before replying, and the client must read that through its own
//!      mapping. Both directions, or a kernel that gave the server a copy of
//!      the page passes. The client then asks the kernel to map the moved
//!      handle again and must be told it is stale: the capability moved, it
//!      was not duplicated.
//!
//! WHAT IT DOES NOT DO
//!
//!   * No timing. `latbench` owns that, and a wall-clock threshold in a gate
//!     measures the host's load rather than the kernel.
//!   * No `wait()`. `sys_wait` is `-1  // Phase 8+`, so children report their
//!     verdicts to the parent over the fast-IPC mailbox below instead. A
//!     fast-IPC call is addressed by TID and needs no inherited capability,
//!     which a forked child — holding only its descriptors and its row's — does not have.
//!   * No assertion on a specific errno for the fast-IPC path. Denials there
//!     are `-1` from dispatch; the typed path answers `-Errno` and those
//!     phases DO name the code.

#![no_std]
#![no_main]

// The raw fork in `spawn` selects its trap instruction per ISA; on
// an ISA with no branch the build stops here instead of losing the trap.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("ipctest: no syscall instruction for this ISA (riscv64, aarch64, x86_64)");

use azos_libsys as sys;

// ── Test bookkeeping ────────────────────────────────────────────────────────

static mut FAILURES: u32 = 0;
static mut CHECKS: u32 = 0;

/// One log line, assembled in a stack buffer and emitted with a **single**
/// `write`.
///
/// The first version of this file printed each line as five or six separate
/// `sys::print` calls. With nine tasks running on four harts the kernel
/// interleaved them mid-line and the log came out as
/// `A/forked all clients rc=[IPCTEST] child=8` — two different tasks spliced
/// into one line. Progress output whose only job is to say *which* child
/// wedged *where* is worthless if the child index and the sequence number can
/// come from different tasks. One syscall per line makes each line atomic at
/// the UART.
struct Line {
    buf: [u8; 128],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0u8; 128], n: 0 }
    }

    fn s(&mut self, b: &[u8]) -> &mut Self {
        let room = self.buf.len() - self.n;
        let take = if b.len() < room { b.len() } else { room };
        self.buf[self.n..self.n + take].copy_from_slice(&b[..take]);
        self.n += take;
        self
    }

    /// Signed decimal. The `i64` widening keeps `isize::MIN` from overflowing
    /// on negation — `overflow-checks = true` plus `panic = "abort"` makes
    /// that a board reset, not a wrong number.
    fn i(&mut self, v: isize) -> &mut Self {
        if v < 0 {
            self.s(b"-");
        }
        let mut n = if v < 0 { (v as i64).unsigned_abs() } else { v as u64 };
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        self.s(&tmp[i..])
    }

    fn flush(&mut self) {
        self.s(b"\n");
        sys::print(&self.buf[..self.n]);
        self.n = 0;
    }
}

fn report(name: &[u8], ok: bool, rc: isize) {
    let mut l = Line::new();
    l.s(if ok { b"[IPCTEST]   ok   " } else { b"[IPCTEST]  FAIL  " });
    l.s(name).s(b" rc=").i(rc);
    l.flush();
    // `overflow-checks = true` and `panic = "abort"`: a wrapping increment
    // here would reset the board. Saturating cannot.
    unsafe {
        CHECKS = CHECKS.saturating_add(1);
        if !ok {
            FAILURES = FAILURES.saturating_add(1);
        }
    }
}

/// The kernel must return exactly `want`.
fn expect_eq(name: &[u8], rc: isize, want: isize) {
    report(name, rc == want, rc);
}

/// The kernel must reject this call.
fn expect_err(name: &[u8], rc: isize) {
    report(name, rc < 0, rc);
}

/// The kernel must return something strictly positive.
fn expect_pos(name: &[u8], rc: isize) {
    report(name, rc > 0, rc);
}

/// A plain boolean assertion; `rc` is printed for context either way.
fn expect_true(name: &[u8], ok: bool, rc: isize) {
    report(name, ok, rc);
}

/// `Errno` values from the typed path (`azos_abi::error`). libsys does not
/// re-export them (it deliberately does not depend on `abi` at that layer), so
/// the ones this file asserts on are named here.
const E_ECAPSTALE: isize = -202;
const E_EBUSY: isize = -16;
const E_EAGAIN: isize = -11;
const E_ENOENT: isize = -2;
const E_EPERM: isize = -1;

// ── Child → parent mailbox, over fast IPC ────────────────────────────────────
//
// Every child reports its verdicts to the parent with `SYS_IPC_FAST_CALL`,
// addressed by the parent's TID. Fast IPC needs no inherited object: a forked
// child holds no runtime object of its parent's (wave 13: only its descriptors
// and its row's capabilities), so the kernel channel this
// mailbox used before — reached through a `Cap<Channel>` — would be
// unreachable from a child. A TID is not a capability, so it survives the fork
// as a plain integer in a static.
//
// A post is one call carrying `[MBOX_MAGIC | tag, value, 0, 0]`. The parent is
// the fast-IPC server: `pump()` accepts one post, files it into the
// mailbox, and replies `0` to unblock the child. Phase A's own server loop
// files posts the same way, so a child's verdict and a phase-A protocol call
// share one accept path.
//
// The accept blocks until some task calls this TID, so a child that dies
// without posting would leave the parent blocked for good. A heartbeat child
// (`heartbeat_main`) calls the parent every `HB_PERIOD_MS`, which bounds every
// such accept: `wait_tag` and phase A's server loop both read their deadline
// at least once per period.

/// Budget for one child verdict, in milliseconds of real `mtime`. Generous
/// on purpose: this kernel runs a benchmark suite, a brain-link handshake
/// spinning at ~400k yields per two seconds, and a telemetry task alongside
/// the test, and a starved child that eventually answers must not be reported
/// as a dead one. The QEMU scenario's own 180 s ceiling is the real backstop.
const WAIT_MS: u32 = 20_000;

/// How often the heartbeat child calls the parent, in milliseconds: how late
/// a blocked accept notices that a deadline has passed.
const HB_PERIOD_MS: u64 = 500;
/// Consecutive refused heartbeat calls after which the heartbeat child exits.
/// A call to an exited parent is refused at once, so this ends the child with
/// the run.
const HB_GIVE_UP: u32 = 40;
/// Wait between refused heartbeat calls, in milliseconds.
const HB_RETRY_MS: u64 = 50;

const MBOX_LEN: usize = 32;

/// Top bits of a mailbox post's word 0, above every value a phase-A request
/// word (`REQ_MAGIC` = 0x0011_xxxx) or reply word (`REPLY_MAGIC` =
/// 0x0022_xxxx) can hold, so the parent's one accept path tells a verdict from
/// a protocol call by inspection. The tag is in the low bits.
const MBOX_MAGIC: u64 = 0x00AB_0000;
const MBOX_TAG_MASK: u64 = 0x0000_FFFF;

const TAG_S2_TID: u8 = 3;
const TAG_S2_RC: u8 = 4;
const TAG_CLIENT_GOT: u8 = 5;
/// RFC-0040 gap 3 tightness probe (phase B): 1 if a capability at a slot the
/// fork grant never touched resolved to anything, 0 if it was correctly
/// refused. See `phase_b_client`.
const TAG_CLIENT_TIGHT: u8 = 1;
const TAG_GUESS_SHM: u8 = 6;
const TAG_GUESS_PORT: u8 = 7;
const TAG_GUESS_RING: u8 = 8;
const TAG_T_TID: u8 = 9;
const TAG_T_MASK: u8 = 10;
/// Phase E: server TID, what the server saw, and the client's TID + reply.
const TAG_E_SRV_TID: u8 = 12;
const TAG_E_SRV_SAW: u8 = 13;
const TAG_E_CLI_TID: u8 = 14;
const TAG_E_CLI_GOT: u8 = 15;
/// Phase A clients report at `TAG_CHILD_BASE + child_index`; the base is
/// above every fixed tag and `TAG_CHILD_BASE + RT_CHILDREN` stays inside
/// `MBOX_LEN`.
const TAG_CHILD_BASE: u8 = 16;
/// RFC-0040 gap 2, the CALL direction: 1 if `phase_b_client`'s raw-TID call
/// straight to root — its GRANDPARENT, not its parent — was ever accepted, 0
/// if it was refused. See `phase_b_client`'s ancestor-call probe.
const TAG_CLIENT_ANCESTOR_CALL: u8 = 24;
/// Phase H: server TID, what the server saw, and the client's verdict.
const TAG_H_SRV_TID: u8 = 25;
const TAG_H_SRV_SAW: u8 = 26;
const TAG_H_CLI: u8 = 27;
/// Wave 11 phases R and W: the robust-word server's verdict mask.
const TAG_R: u8 = 28;
/// Verdict of the `fork()` register canary.
const TAG_CANARY: u8 = 11;
/// Heartbeat calls ride the mailbox path under this tag: filed like any post,
/// never awaited.
const TAG_HEARTBEAT: u8 = 2;

static mut MBOX: [u32; MBOX_LEN] = [0; MBOX_LEN];
static mut MSEEN: [u8; MBOX_LEN] = [0; MBOX_LEN];

/// The parent's TID, set in `_start` before any `fork()`. Every child posts
/// to it.
static mut PARENT_TID: u32 = 0;

// **The mailbox addresses the parent by TID, not by capability**, and that is
// not an oversight. RFC-0040 gap 2 stage 4 converted it to an endpoint and the
// conversion was reverted on 2026-09-21 with the `fork()` capability
// inheritance it depended on: a child's capability table held nothing of its
// parent's, so there was no handle here to call with. Reaching the parent by capability needs a
// bootstrap grant at fork — RFC-0040 gap 3.
//
// Gap 3 landed (`endpoint_inherit_at_fork`, `crates/core/ipc/src/endpoint.rs`) and
// phases B and E now use it for their REAL exchange (see
// `phase_b_server`/`phase_e_server`). The mailbox itself deliberately stays
// on TID.
//
// **Most posters here are direct children of `PARENT_TID` (root)** —
// `fork_reg_canary`, `heartbeat_main`, `phase_a_client`, `phase_c_guesser`,
// `phase_d_probe`, and the phase B/E SERVERS all fork straight from root, so
// `post()` (which targets `PARENT_TID`) is exactly their real kernel parent.
// `phase_b_client` and `phase_e_client` are the exceptions: each is forked
// from its own phase's server, making it root's GRANDCHILD. Since
// `SYS_IPC_FAST_CALL` (108) now checks its raw-TID destination against the
// caller's own parent (RFC-0040 gap 2, the CALL direction) — nothing wider —
// a grandchild's post to `PARENT_TID` would be refused outright. Those two
// post to their real, immediate parent instead (`post_to`, with the target
// handed down through `spawn`'s `arg`), and that parent relays the message on
// to root (`relay_one`). Converting the mailbox itself to a capability would
// still need delegation past one hop, out of gap 3's scope; the relay is the
// gap-2-compatible fix that does not touch gap 3 at all.


// `addr_of!` rather than plain indexing: these statics are written by this
// task only, but taking a reference to a `static mut` is a lint the CI
// warning gate treats as a failure. Raw-pointer access says what is meant and
// keeps the build clean.
fn mbox_set(tag: usize, v: u32) {
    if tag >= MBOX_LEN {
        return;
    }
    unsafe {
        core::ptr::addr_of_mut!(MBOX).cast::<u32>().add(tag).write(v);
        core::ptr::addr_of_mut!(MSEEN).cast::<u8>().add(tag).write(1);
    }
}

fn mbox_get(tag: usize) -> Option<u32> {
    if tag >= MBOX_LEN {
        return None;
    }
    unsafe {
        if core::ptr::addr_of!(MSEEN).cast::<u8>().add(tag).read() == 0 {
            None
        } else {
            Some(core::ptr::addr_of!(MBOX).cast::<u32>().add(tag).read())
        }
    }
}

/// True if `word0` is a mailbox post; files it when so. Shared by `pump` and
/// phase A's server loop, so a verdict that lands on either accept path is
/// recorded exactly once.
fn file_if_mailbox(word0: u64, word1: u64) -> bool {
    if word0 & !MBOX_TAG_MASK == MBOX_MAGIC {
        mbox_set((word0 & MBOX_TAG_MASK) as usize, word1 as u32);
        true
    } else {
        false
    }
}

/// [`post`], addressed explicitly rather than at `PARENT_TID`.
///
/// RFC-0040 gap 2, the CALL direction: `SYS_IPC_FAST_CALL` (108) now checks
/// its raw-TID destination against the caller's own kernel parent
/// (`fast_ipc_tid_dest_for`). `PARENT_TID` names the ROOT task — correct for
/// every direct child, wrong for a grandchild or deeper, whose real parent is
/// whatever spawned it. `phase_b_client`/`phase_e_client` are exactly that:
/// forked from `phase_b_server`/`phase_e_server`, not from root. They call
/// this with their real parent's TID (handed down through `spawn`'s `arg`,
/// the same static-before-fork trick `PARENT_TID` itself uses), and that
/// immediate parent relays the post on to root — see `relay_one`.
fn post_to(srv: u32, tag: u8, v: u32) {
    let words = [MBOX_MAGIC | tag as u64, v as u64, 0, 0];
    let mut tries = 0u32;
    while sys::fast_ipc_call(srv, words).is_none() && tries < 400 {
        sys::sleep(2);
        tries = tries.saturating_add(1);
    }
}

/// Child side: post one verdict to `PARENT_TID`, and block until it is filed.
/// Retries a refused call (server not yet in a state to accept, or all slots
/// busy) rather than losing the verdict — a dropped verdict reads as a
/// timeout, i.e. as a hang that did not happen.
///
/// Only valid for a DIRECT child of `PARENT_TID` — see [`post_to`] for a
/// grandchild or deeper.
fn post(tag: u8, v: u32) {
    post_to(unsafe { PARENT_TID }, tag, v)
}

/// Parent side: accept ONE fast-IPC post on this TID and file it into the
/// mailbox. A non-mailbox call is not expected outside phase A; it is answered
/// `0` so its sender does not wedge.
///
/// One request, not a drain. `SYS_IPC_FAST_ACCEPT` has no non-blocking form:
/// with nothing pending it blocks on `FastIpcServer(tid)` for up to eight
/// wakes, and the only waker is a `SYS_IPC_FAST_CALL` addressed to this TID.
/// A loop that accepts until the queue is empty therefore never returns once
/// it is: the canary's post was filed, the next accept blocked with every
/// child gone, and `wait_tag` never read its deadline. Returning after each
/// request hands control back to the caller's mailbox check. The heartbeat
/// child (`heartbeat_main`) is what makes that return come in time when no
/// post is on its way; its call is answered `0`, i.e. one period.
fn pump() {
    if let Some(req) = sys::fast_ipc_accept_req() {
        file_if_mailbox(req.words[0], req.words[1]);
        sys::fast_ipc_reply(req.handle, [0, 0, 0, 0]);
    }
}

/// A server one hop below root: accept ONE fast-IPC call on this task, and if
/// it is a mailbox post — as [`post_to`] shapes it — relay it on to root under
/// the same tag and value. A non-mailbox call is answered `0` and dropped,
/// same as `pump`'s own rule, and for the same reason (its sender must not
/// wedge).
///
/// Used by `phase_b_server`/`phase_e_server` to pass along a verdict from
/// their OWN child, who is root's grandchild and — since `SYS_IPC_FAST_CALL`
/// now only reaches the caller's own parent (RFC-0040 gap 2) — cannot post to
/// root directly any more. The relay costs one extra accept on a path that
/// already does two (the real exchange plus this), sequenced by the client's
/// own program order: it posts before the real call and again after, so
/// there is never more than one pending message here at a time.
fn relay_one() {
    if let Some(req) = sys::fast_ipc_accept_req() {
        sys::fast_ipc_reply(req.handle, [0, 0, 0, 0]);
        if req.delivered && req.words[0] & !MBOX_TAG_MASK == MBOX_MAGIC {
            let tag = (req.words[0] & MBOX_TAG_MASK) as u8;
            let v = req.words[1] as u32;
            post(tag, v);
        }
    }
}

/// Heartbeat child: call the parent every `HB_PERIOD_MS` for the whole run.
///
/// Every accept the parent blocks in (`pump`, phase A's server loop) returns
/// at the next heartbeat, so their deadlines are read even when the child
/// they wait for died without posting. The call is a mailbox post under
/// `TAG_HEARTBEAT`, so both accept paths file it and neither counts it.
///
/// The child makes one call at a time, which `hb_hold` relies on. A call to
/// an exited parent is refused at once, so `HB_GIVE_UP` consecutive refusals
/// end the child with the run.
fn heartbeat_main() -> ! {
    let srv = unsafe { PARENT_TID };
    let words = [MBOX_MAGIC | TAG_HEARTBEAT as u64, 0, 0, 0];
    let mut refused = 0u32;
    loop {
        match sys::fast_ipc_call(srv, words) {
            Some(_) => {
                refused = 0;
                sys::sleep(HB_PERIOD_MS);
            }
            None => {
                refused = refused.saturating_add(1);
                if refused >= HB_GIVE_UP {
                    sys::exit(0);
                }
                sys::sleep(HB_RETRY_MS);
            }
        }
    }
}

/// Parent side: accept the heartbeat child's next call and hold it, unreplied.
/// Returns the held request, or `None` if no heartbeat arrived within four
/// periods.
///
/// Phase B's impostor sweep replies to every slot index. This task is the
/// server of a heartbeat call, so a reply landing on that slot would be
/// accepted — correctly — and counted as an impostor success. Holding the call
/// pins it: the heartbeat makes one call at a time, so while this one is held
/// no other heartbeat call exists, and the sweep skips the held slot. Posts
/// that arrive before the heartbeat are filed and answered as usual.
fn hb_hold() -> Option<sys::FastRequest> {
    let deadline = sys::uptime() + 4 * HB_PERIOD_MS as isize * ticks_per_ms();
    while sys::uptime() < deadline {
        if let Some(req) = sys::fast_ipc_accept_req() {
            if req.words[0] == (MBOX_MAGIC | TAG_HEARTBEAT as u64) {
                return Some(req);
            }
            file_if_mailbox(req.words[0], req.words[1]);
            sys::fast_ipc_reply(req.handle, [0, 0, 0, 0]);
        }
    }
    None
}

/// Ticks per millisecond of the [`sys::uptime`] counter — read LIVE from the
/// vDSO page's published `timebase_hz` (`sys::vdso_timebase_hz`), never a
/// compile-time constant.
///
/// **This replaced a hardcoded `10_000`, documented as "CLINT ticks per
/// millisecond on QEMU virt (`mtime` runs at 10 MHz)" — true for riscv64's
/// CLINT, which really is a fixed 10 MHz
/// (`crates/drivers/sys/src/timebase.rs`: `TIMER_FREQ`), and silently wrong for
/// aarch64.** `sys::uptime()` there is `CNTVCT_EL0`
/// (`crates/core/arch-aarch64/src/timer.rs::now_ticks`), ticking at whatever
/// `CNTFRQ_EL0` reads LIVE at boot
/// (`kernel/src/entry/aarch64/boot_hooks.rs`, `arch_timer::freq_hz()`) — on
/// this QEMU build measured at 1 GHz (`[TIMER] CNTFRQ_EL0: 1000000000 Hz`),
/// not 10 MHz. Every `WAIT_MS`-based deadline in this file (`wait_tag`,
/// `hb_hold`, phase A's stall bound) multiplied its millisecond budget by the
/// wrong constant, so a nominal 20 s budget was actually enforced as ~200 ms
/// of real time on aarch64 — 100x short. `phase_b`'s sequencing alone
/// (`B_CLIENT_DELAY` + `B_IMPOSTOR_DELAY` + `B_SERVER_HOLD` = 650 ms of
/// deliberate `sys::sleep`s before the client can even post its verdict)
/// exceeds that shrunk budget outright, which is why `wait_tag(TAG_CLIENT_GOT,
/// ..)` — the first blocking wait phase B takes after the sweep — timed out
/// deterministically (5/5 hand runs, 2026-09-25) and every later `wait_tag` in
/// the same phase passed: by the time those ran, the mailbox already held the
/// answer (`mbox_get` is checked before blocking), so their own shrunk budget
/// never mattered. **Not a lost cross-hart wake** — `tools/ci_check.sh`'s
/// `aarch64_ipctest_row` comment and this project's own standing lesson ["a
/// tick count is a per-board number"] both already said so; this was the one
/// place in this binary that still baked one in as if it were a global
/// constant, on top of a userspace-facing `sys::uptime()` this project has
/// documented, elsewhere, as ISA- and board-specific for exactly this reason.
///
/// Falls back to the RISC-V constant only if the vDSO page is absent or
/// unpublished (`hz == 0`) — should not happen past boot on either ISA today,
/// kept only to avoid a divide-by-zero.
fn ticks_per_ms() -> isize {
    let hz = sys::vdso_timebase_hz();
    if hz == 0 { 10_000 } else { (hz / 1000) as isize }
}

/// Parent side: wait up to `ms` for a tagged verdict. Returns `None` on
/// timeout.
///
/// The mailbox is read BEFORE accepting: phase A's server loop may already
/// have filed the verdict, and an accept with no post coming blocks.
///
/// The `ms` bound comes from the heartbeat child. `pump()` blocks until some
/// task calls this TID, and the heartbeat calls every `HB_PERIOD_MS`, so the
/// deadline is read within about one period of passing even when the awaited
/// child died without posting. If the heartbeat child itself is gone, the
/// bound falls back to the QEMU scenario's 180 s ceiling ("no verdict
/// printed").
///
/// The deadline is read from `uptime()` rather than accumulated from the
/// `sleep()` argument. Under load this kernel's timer jitter reaches whole
/// seconds (`[JITTER] timer_isr max_ns 2003100000`), so counting nominal
/// milliseconds turns a 5 s budget into an unpredictable wall-clock wait —
/// which is how a starved child gets misreported as a dead one.
fn wait_tag(tag: u8, ms: u32) -> Option<u32> {
    let deadline = sys::uptime() + ms as isize * ticks_per_ms();
    loop {
        if let Some(v) = mbox_get(tag as usize) {
            return Some(v);
        }
        if sys::uptime() >= deadline {
            return None;
        }
        pump();
        sys::sleep(2);
    }
}

// ── fork(), and the register state it does not give the child ──────────────
//
// **KERNEL DEFECT, found by this probe.** `fork_child_entry` enters the child
// through `sret_to_user` (`crates/core/sched/src/process.rs:412`), which restores
// only `pc`, `sp` and `satp` and explicitly zeroes `a0`..`a7`. Nothing copies
// the parent's `ra`, `gp`, `tp`, `t0`-`t6` or `s0`-`s11`: the child resumes
// user code with whatever those registers held in the *kernel* task that ran
// `fork_child_entry`.
//
// Two consequences, both observed:
//   * Any value the compiler kept in a callee-saved register is corrupt in
//     the child. The first version of this file passed each client its index
//     as a function argument; all eight children printed `child=0`, because
//     the loop counter lived in an s-register.
//   * `ra` is garbage, so **the child cannot return from the function that
//     called `fork`** — it would jump to a kernel address. The child path
//     below therefore ends in a diverging call and never returns.
//
// It is also a kernel-to-ring-3 information leak: whatever the kernel left in
// s0-s11 is readable from U-mode.
//
// [`fork_reg_canary`] asserts this directly and **is expected to fail until
// the kernel copies the parent's registers**. It is left red on purpose; the
// scaffolding below is what lets the *other* phases still run, and it is
// scaffolding, not a silenced assertion — the defect keeps its own failing
// check.

/// Value planted in `s11` across the fork ecall by [`fork_reg_canary`].
const FORK_CANARY: u64 = 0x5AFE_C0DE;
/// `SYS_FORK`. Issued as raw asm because the canary has to survive in a
/// specific register across the `ecall`, which a normal wrapper cannot
/// express.
const NR_FORK: u64 = 12;

/// Roles a forked child can take. Passed through **memory**, never through a
/// register or an argument — see the note above.
const ROLE_A_CLIENT: u32 = 1;
const ROLE_B_SERVER: u32 = 2;
const ROLE_B_CLIENT: u32 = 3;
const ROLE_C_GUESSER: u32 = 4;
const ROLE_D_EXIT: u32 = 5;
const ROLE_D_PROBE: u32 = 6;
const ROLE_CANARY: u32 = 7;
const ROLE_E_SERVER: u32 = 8;
const ROLE_E_CLIENT: u32 = 9;
const ROLE_HEARTBEAT: u32 = 10;
const ROLE_H_SERVER: u32 = 11;
const ROLE_H_CLIENT: u32 = 12;
const ROLE_R_SERVER: u32 = 13;
const ROLE_R_CLIENT: u32 = 14;
const ROLE_W_LESSEE: u32 = 15;
const ROLE_W_SPINNER: u32 = 16;
const ROLE_P_SERVER: u32 = 17;
const ROLE_P_CLIENT: u32 = 18;
const ROLE_S_SEALED: u32 = 19;
const ROLE_S_RESTORED: u32 = 20;
const ROLE_S_LATE_MAP: u32 = 21;
const ROLE_X_LESSEE: u32 = 22;
const ROLE_X_SEALED: u32 = 23;

static mut ROLE: u32 = 0;
static mut ROLE_ARG: u32 = 0;
/// `s11` as the CHILD sees it after the fork ecall.
static mut FORK_S11: u64 = 0;
/// `s11` as the PARENT sees it after the same ecall. Separate static: both
/// sides run the same code, and a single slot would only ever hold whichever
/// of the two wrote last — which for a COW fork is neither, since the write
/// lands in each task's own copy of the page.
static mut FORK_S11_PARENT: u64 = 0;

/// Fork, and run `role` in the child. Returns the child TID to the parent;
/// **never returns in the child**.
///
/// `role` and `arg` are written to statics *before* the ecall and re-read
/// from statics afterwards. Reading the parameters back would read registers
/// the child never received.
fn spawn(role: u32, arg: u32) -> isize {
    unsafe {
        ROLE = role;
        ROLE_ARG = arg;
    }
    let pid: isize;
    let observed: u64;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") NR_FORK,
            lateout("a0") pid,
            // `inout` on an explicit register: the canary is materialised in
            // s11 before the ecall and read back after it. In the child that
            // read returns whatever the kernel left there — which is the
            // measurement `fork_reg_canary` reports.
            inout("s11") FORK_CANARY => observed,
            // ── USERSPACE MITIGATION FOR A KERNEL DEFECT — DELETE WHEN FIXED
            //
            // Declaring every callee-saved register clobbered forces the
            // compiler to spill them to the stack before the ecall and reload
            // them after. The stack IS inherited correctly (same `sp`, COW
            // copy of the page), so the child comes back with usable values.
            //
            // Without this the child does not survive its first memory
            // access. Measured, not guessed: the compiler hoisted the address
            // of a static into `s10` before the ecall and emitted
            // `sd s11,24(s10)` after it; in the child `s10` held the kernel's
            // leftover `0x80605000`, the store went to `0x80605018`, and the
            // kernel answered `[PAGE FAULT] Killing user task`. Any forked
            // child is one hoisted base register away from that.
            //
            // This is NOT the fix and must not be read as one. The fix is for
            // `sret_to_user`'s fork path to copy the parent's register file;
            // `fork_reg_canary` stays red until it does. This list only buys
            // the other phases the chance to run at all — a probe whose every
            // child is killed before its first instruction measures nothing.
            // `sp`, `gp` and `tp` cannot be listed (rustc reserves them);
            // `gp` is safe here only because `user.ld` defines no
            // `__global_pointer$`, so nothing is gp-relative.
            out("ra") _,
            out("t0") _, out("t1") _, out("t2") _, out("t3") _,
            out("t4") _, out("t5") _, out("t6") _,
            // `s0`/`s1` cannot be listed either (LLVM reserves them), which is
            // why the child's first act is a PC-relative call into
            // `child_main` rather than a store through a base register that
            // might have been materialised before the ecall.
            out("s2") _, out("s3") _, out("s4") _,
            out("s5") _, out("s6") _, out("s7") _, out("s8") _,
            out("s9") _, out("s10") _,
            out("a1") _, out("a2") _, out("a3") _,
            out("a4") _, out("a5") _, out("a6") _,
            options(nostack),
        );
        // aarch64 twin (phase 6 prep). **No aarch64 kernel exec/fork path
        // exists yet** — this compiles for forward parity only; the defect
        // this mitigates is documented against the RISC-V `sret_to_user`
        // fork path above and has no aarch64 counterpart to measure until
        // that path exists. `x20` stands in for `s11`, the same role: a
        // callee-saved register the compiler must spill/reload around the
        // trap rather than assume survives it — NOT `x19`, which LLVM
        // reserves internally on this target and refuses as an `asm!`
        // operand (`error: invalid register 'x19'`, measured). `x29` (frame
        // pointer) and `x18` (platform register) are excluded too, like
        // RISC-V's `s0`/`s1`/`sp`/`gp`/`tp` — reserved by rustc/LLVM here,
        // not listable.
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") NR_FORK,
            lateout("x0") pid,
            inout("x20") FORK_CANARY => observed,
            out("lr") _,
            out("x1") _, out("x2") _, out("x3") _, out("x4") _,
            out("x5") _, out("x6") _, out("x7") _,
            out("x9") _, out("x10") _, out("x11") _, out("x12") _,
            out("x13") _, out("x14") _, out("x15") _, out("x16") _, out("x17") _,
            out("x21") _, out("x22") _, out("x23") _, out("x24") _,
            out("x25") _, out("x26") _, out("x27") _, out("x28") _,
            options(nostack),
        );
        // x86_64 twin. `r12` stands in for `s11`: a callee-saved register the
        // compiler may not assume survives the trap. `rbx` and `rbp` cannot be
        // listed (LLVM reserves them), like RISC-V's `s0`/`s1`. Every other
        // general register is declared clobbered for the same reason as above;
        // `syscall` itself writes rcx and r11.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") NR_FORK as isize => pid,
            inout("r12") FORK_CANARY => observed,
            out("rdi") _, out("rsi") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _,
            out("rcx") _, out("r11") _,
            out("r13") _, out("r14") _, out("r15") _,
            options(nostack),
        );
    }
    if pid == 0 {
        // CHILD. Only `pc`, `sp` and `a0` are ours.
        //
        // `observed` is handed on as an ARGUMENT rather than stored here: an
        // argument travels in `a0`, and the call is a PC-relative `auipc`
        // +`jalr`, so neither depends on a register the child never received.
        // Storing it here instead compiled to `sd s11,24(s10)` with `s10`
        // materialised *before* the ecall — and that store killed the child.
        child_main(observed);
    }
    unsafe { FORK_S11_PARENT = observed };
    pid
}

/// Child entry. Diverges — the child must never return through `ra`, which
/// holds whatever the kernel left in it.
///
/// Every static read below is addressed with a `auipc` computed *inside* this
/// function, i.e. after the fork, so no base register predates the ecall.
fn child_main(observed_s11: u64) -> ! {
    unsafe { FORK_S11 = observed_s11 };
    let role = unsafe { ROLE };
    let arg = unsafe { ROLE_ARG };
    // Announce before doing anything else. A child that dies between `fork`
    // and its first useful instruction is otherwise indistinguishable from a
    // child that was never scheduled, and this kernel does not always print a
    // fault when it kills one. `ROLE_D_EXIT` is excluded because phase D
    // spawns ninety of them.
    if role != ROLE_D_EXIT {
        let mut l = Line::new();
        l.s(b"[IPCTEST] child_main role=").i(role as isize)
            .s(b" arg=").i(arg as isize)
            .s(b" tid=").i(sys::getpid())
            .s(b" s11=").i(observed_s11 as isize);
        l.flush();
    }
    match role {
        ROLE_A_CLIENT => phase_a_client(arg),
        ROLE_B_SERVER => phase_b_server(),
        ROLE_B_CLIENT => phase_b_client(arg),
        ROLE_C_GUESSER => phase_c_guesser(),
        ROLE_D_EXIT => sys::exit(0),
        ROLE_D_PROBE => phase_d_probe(),
        ROLE_E_SERVER => phase_e_server(),
        ROLE_E_CLIENT => phase_e_client(arg),
        ROLE_HEARTBEAT => heartbeat_main(),
        ROLE_H_SERVER => phase_h_server(),
        ROLE_H_CLIENT => phase_h_client(arg),
        ROLE_R_SERVER => phase_r_server(),
        ROLE_R_CLIENT => phase_r_client(),
        ROLE_W_LESSEE => phase_w_lessee(arg),
        ROLE_W_SPINNER => phase_w_spinner(arg),
        ROLE_P_SERVER => phase_p_server(),
        ROLE_P_CLIENT => phase_p_client(arg),
        ROLE_S_SEALED => phase_s_child(S_SEALED),
        ROLE_S_RESTORED => phase_s_child(S_RESTORED),
        ROLE_S_LATE_MAP => phase_s_child(S_LATE_MAP),
        ROLE_X_LESSEE => phase_x_lessee(arg),
        ROLE_X_SEALED => phase_x_sealed(),
        ROLE_CANARY => {
            let seen = unsafe { FORK_S11 };
            post(TAG_CANARY, if seen == FORK_CANARY { 1 } else { 0 });
            sys::exit(0)
        }
        _ => sys::exit(0),
    }
}

/// Does `fork()` hand the child the parent's callee-saved registers?
///
/// Expected RED until `sret_to_user`'s fork path copies them. Asserting it
/// separately is what keeps the workaround above from hiding the defect: the
/// other phases route their parameters through memory and pass, this one
/// tests the register file itself and fails.
fn fork_reg_canary() {
    let pid = spawn(ROLE_CANARY, 0);
    if pid < 0 {
        expect_err(b"0/fork for canary (unexpected failure)", pid);
        return;
    }
    // The parent's own registers are trivially intact; assert it anyway, so a
    // failure here separates "fork corrupts the CALLER" from "fork does not
    // populate the CHILD".
    expect_true(
        b"0/fork preserves the parent's s11",
        unsafe { FORK_S11_PARENT } == FORK_CANARY,
        unsafe { FORK_S11_PARENT } as isize,
    );
    match wait_tag(TAG_CANARY, WAIT_MS) {
        Some(1) => expect_true(b"0/fork preserves the child's s11", true, 1),
        Some(v) => expect_true(b"0/fork preserves the child's s11", false, v as isize),
        None => expect_true(b"0/canary child reported at all", false, -1),
    }
}

// ── Phase A: fast-IPC round trip, N clients × M iterations ─────────────────
//
// Shape taken verbatim from the scenario written at the end of
// `tests/host/sched-wake-tests/src/lib.rs` by the lane that closed the
// `wake_pending` half of K-C10. The parent is the SERVER; N forked children
// are the CLIENTS.
//
// **There is NO delay between ACCEPT and REPLY, on purpose.** That is the
// whole point: `SYS_IPC_FAST_CALL` allocates the slot, wakes the server, and
// only *then* blocks the caller. A server that answers inside that window on
// another hart has its `wake_fast_ipc_client` land on a task that is not yet
// blocked, the wake is lost, and the client sleeps forever. A `sleep()`
// between accept and reply makes the client always reach `task_block` first
// and hides the bug — a test that hides the bug it exists to find is worse
// than no test.
//
// **This needs `-smp >= 2`.** On one hart the interleaving cannot occur and
// this phase proves nothing. Ring 3 has no way to read the hart count — there
// is no syscall for it (`sys_taskinfo` is `0`, `SYS_PLATFORM_INFO` is a stub)
// — so the requirement is stated in the log and enforced by the `-smp 4` on
// the QEMU command line in `tools/ci_check.sh`. Naming the gap is the honest
// option; asserting something ring 3 cannot observe is not.
//
// The server reads the request now (`SYS_IPC_FAST_ACCEPT` delivers the caller
// TID and the four words), but this phase does not depend on it: it replies
// `REPLY_MAGIC + slot_idx`, and each client asserts the word it collects lies
// in the reply range and is **not** its own request word. That still catches
// IPC-2 exactly — a client collecting its own question as the answer —
// because every request word is unique per (child, iteration). A child's
// final verdict rides the same accept path as a mailbox post; the server
// files it and does not count it as served.

/// Clients forked for the race. The scenario asks for N ≥ 8.
const RT_CHILDREN: u32 = 8;
/// Calls per client. The scenario asks for M ≥ 200.
const RT_ITERS: u32 = 200;
/// Progress cadence, in iterations. Outside any measured batch (nothing is
/// timed here) and rare enough that the ~160 us cost of a UART write cannot
/// dominate. Its only job is to make a hang read as "wedged at seq=137".
const RT_PROGRESS: u32 = 32;
/// Server progress cadence. Printed between a reply and the next accept —
/// never between accept and reply, which would widen exactly the window the
/// phase is trying to close on.
const RT_SRV_PROGRESS: u32 = 256;

const REQ_MAGIC: u64 = 0x0011_0000;
const REPLY_MAGIC: u64 = 0x0022_0000;
/// Request words are `REQ_MAGIC + idx * RT_STRIDE + k`, so no two clients and
/// no two iterations ever share one. `RT_ITERS` must stay below this.
const RT_STRIDE: u64 = 1024;

/// A refused `fast_ipc_call` that took at least this many CLINT ticks was
/// almost certainly blocked and then woken with nothing to collect (the
/// spurious-wake signature); a faster one is an immediate rejection. QEMU
/// virt's mtime runs at 10 MHz, so this is ~100 us. **Heuristic**, and
/// labelled as such in the output: `a0` carries the reply word and the error
/// code in the same register, so ring 3 has no way to tell the two apart
/// exactly.
const RT_SPURIOUS_TICKS: isize = 1000;

/// Pack a client's four counters into one mailbox word. `RT_ITERS` is 200, so
/// every field fits in a byte.
fn pack4(a: u32, b: u32, c: u32, d: u32) -> u32 {
    (a & 0xFF) | ((b & 0xFF) << 8) | ((c & 0xFF) << 16) | ((d & 0xFF) << 24)
}

fn phase_a_client(idx: u32) -> ! {
    let srv = unsafe { PARENT_TID };
    let mut ok = 0u32;
    let mut refused = 0u32;
    let mut refused_slow = 0u32;
    let mut echoed = 0u32;
    let mut bad = 0u32;

    let mut k = 0u32;
    while k < RT_ITERS {
        if k % RT_PROGRESS == 0 {
            let mut l = Line::new();
            l.s(b"[IPCTEST] child=").i(idx as isize).s(b" seq=").i(k as isize);
            l.flush();
        }
        let seq = REQ_MAGIC + idx as u64 * RT_STRIDE + k as u64;
        let t0 = sys::uptime();
        match sys::fast_ipc_call(srv, [seq, 0, 0, 0]) {
            Some(w) => {
                if w == seq {
                    // IPC-2: the slot still held the request when the client
                    // collected. This is the defect the phase exists for.
                    echoed = echoed.saturating_add(1);
                } else if w >= REPLY_MAGIC && w < REPLY_MAGIC + sys::FAST_IPC_MAX_SLOTS as u64 {
                    ok = ok.saturating_add(1);
                } else {
                    bad = bad.saturating_add(1);
                }
            }
            None => {
                refused = refused.saturating_add(1);
                if sys::uptime() - t0 >= RT_SPURIOUS_TICKS {
                    refused_slow = refused_slow.saturating_add(1);
                }
            }
        }
        k += 1;
    }

    let mut l = Line::new();
    l.s(b"[IPCTEST] child=").i(idx as isize)
        .s(b" done=").i(ok as isize)
        .s(b" refused=").i(refused as isize)
        .s(b" (blocked-first=").i(refused_slow as isize)
        .s(b") echo=").i(echoed as isize)
        .s(b" bad=").i(bad as isize);
    l.flush();

    post(TAG_CHILD_BASE + idx as u8, pack4(ok, refused, echoed, bad));
    sys::exit(0);
}

/// Phase A's progress check: `true` once `served` has not moved for `stall`
/// ticks. Reads the clock only when called.
fn a_stalled(served: u32, seen_served: &mut u32, seen_at: &mut isize, stall: isize) -> bool {
    let now = sys::uptime();
    if served != *seen_served {
        *seen_served = served;
        *seen_at = now;
        return false;
    }
    now - *seen_at >= stall
}

fn phase_a_race() {
    sys::println(b"[IPCTEST] A: fast-IPC race loop (needs -smp >= 2)");
    let me = sys::getpid();
    if me <= 0 {
        expect_err(b"A/getpid", me);
        return;
    }

    let mut forked = 0u32;
    while forked < RT_CHILDREN {
        // Index goes through `ROLE_ARG`, i.e. through memory. Passed as an
        // argument it arrived as 0 in every child — see the fork note above.
        let p = spawn(ROLE_A_CLIENT, forked);
        if p < 0 {
            break;
        }
        forked += 1;
    }
    expect_eq(b"A/forked all clients", forked as isize, RT_CHILDREN as isize);
    if forked == 0 {
        return;
    }

    // Server loop. Tight on purpose — see the header. A `fast_ipc_call` from a
    // client is a protocol call (answered `REPLY_MAGIC + slot`, counted); a
    // child's verdict rides the same path as a mailbox post and is filed, not
    // counted.
    let total = forked.saturating_mul(RT_ITERS);
    let mut served = 0u32;
    let mut accept_fail = 0u32;
    let mut reply_fail = 0u32;
    // Progress deadline: `WAIT_MS` with no call served ends the loop, so a
    // client that died mid-run costs FAIL lines instead of a hang. Read only
    // when a mailbox post (a verdict, or the heartbeat at least once per
    // `HB_PERIOD_MS`) or a failed accept arrives, never per served call: the
    // loop is tight on purpose.
    let stall = WAIT_MS as isize * ticks_per_ms();
    let mut seen_served = 0u32;
    let mut seen_at = sys::uptime();
    let mut stalled = false;
    // Each answer rides the trap of the next accept (`fast_ipc_reply_accept`,
    // RFC-0041 §C): `owed` holds the reply for the request just taken until
    // the next turn sends it. A refused reply accepted nothing, so a plain
    // accept follows it. The last reply has no accept after it and goes out
    // alone below the loop.
    let mut owed: Option<(u64, [u64; sys::FAST_IPC_MAX_WORDS])> = None;
    let mut combined = 0u32;
    while served < total {
        let next = match owed.take() {
            Some((handle, words)) => match sys::fast_ipc_reply_accept(handle, words) {
                Ok(next) => {
                    combined = combined.saturating_add(1);
                    next
                }
                Err(_) => {
                    reply_fail = reply_fail.saturating_add(1);
                    sys::fast_ipc_accept_req()
                }
            },
            None => sys::fast_ipc_accept_req(),
        };
        match next {
            Some(req) => {
                if file_if_mailbox(req.words[0], req.words[1]) {
                    // A child's verdict or the heartbeat. Unblock it on the
                    // next turn, do not count it.
                    owed = Some((req.handle, [0, 0, 0, 0]));
                    if a_stalled(served, &mut seen_served, &mut seen_at, stall) {
                        stalled = true;
                        break;
                    }
                    continue;
                }
                // The handle carries a generation tag; the index is decoded
                // ONLY to compose the magic word the client validates.
                // Replying with the index instead of the handle would reopen
                // the ABA.
                owed = Some((req.handle, [REPLY_MAGIC + req.slot as u64, 0, 0, 0]));
                served = served.saturating_add(1);
                if served % RT_SRV_PROGRESS == 0 {
                    let mut l = Line::new();
                    l.s(b"[IPCTEST] server served=").i(served as isize);
                    l.flush();
                }
            }
            None => {
                // A woken-with-nothing-pending accept. Bounded so the server
                // cannot spin forever if every client has died.
                accept_fail = accept_fail.saturating_add(1);
                if accept_fail > total {
                    break;
                }
                if a_stalled(served, &mut seen_served, &mut seen_at, stall) {
                    stalled = true;
                    break;
                }
            }
        }
    }
    if let Some((handle, words)) = owed.take() {
        if sys::fast_ipc_reply(handle, words) != 0 {
            reply_fail = reply_fail.saturating_add(1);
        }
    }
    if stalled {
        let mut l = Line::new();
        l.s(b"[IPCTEST] server stalled: no call served for ").i(WAIT_MS as isize).s(b" ms");
        l.flush();
    }
    let mut l = Line::new();
    l.s(b"[IPCTEST] server served=").i(served as isize)
        .s(b" accept_fail=").i(accept_fail as isize)
        .s(b" reply_fail=").i(reply_fail as isize)
        .s(b" combined=").i(combined as isize);
    l.flush();

    expect_eq(b"A/server served every call", served as isize, total as isize);
    expect_eq(b"A/no failed reply", reply_fail as isize, 0);

    let mut i = 0u32;
    let mut all_ok = 0u32;
    while i < forked {
        match wait_tag(TAG_CHILD_BASE + i as u8, WAIT_MS) {
            Some(v) => {
                let ok = v & 0xFF;
                let refused = (v >> 8) & 0xFF;
                let echoed = (v >> 16) & 0xFF;
                let bad = (v >> 24) & 0xFF;
                all_ok = all_ok.saturating_add(ok);
                expect_eq(b"A/child completed every call", ok as isize, RT_ITERS as isize);
                expect_eq(b"A/child never refused", refused as isize, 0);
                expect_eq(b"A/reply != own request (IPC-2)", echoed as isize, 0);
                expect_eq(b"A/reply word in range", bad as isize, 0);
            }
            None => expect_true(b"A/child reported at all", false, i as isize),
        }
        i += 1;
    }

    let mut l = Line::new();
    l.s(b"[IPCTEST] all=").i(all_ok as isize).s(b" of ").i(total as isize);
    l.s(if all_ok == total { b" OK" } else { b" INCOMPLETE" });
    l.flush();
}

// ── Phase B: server impersonation ───────────────────────────────────────────

const GOOD2: u64 = 0x0033_0001;
const POISON: u64 = 0x0044_0BAD;
const REQ2: u64 = 0x0055_0002;

/// Milliseconds. The impostor must sweep while the exchange is live: after
/// the client has called and the server has claimed the slot, but before the
/// server answers.
const B_CLIENT_DELAY: u64 = 50;
const B_IMPOSTOR_DELAY: u64 = 200;
const B_SERVER_HOLD: u64 = 400;

/// Endpoint capabilities root holds before it creates any: its row's. Set
/// before the first fork.
static mut ROW_EP_COUNT: u32 = 0;

/// How many endpoint pool indexes this task holds a capability on.
fn count_endpoints() -> u32 {
    (0..64u32).filter(|&i| sys::cap_lookup(sys::CapKind::Endpoint as u8, i) > 0).count() as u32
}

/// The endpoint pool index of the endpoint this server created, found by its
/// own handle, set before it forks a client (the static-before-fork mechanism
/// `PARENT_TID` uses), so the client can name the grant it inherits.
static mut OWN_EP_INDEX: u32 = u32::MAX;

/// Find the pool index `ep` (this task's own endpoint) names: the one index
/// whose lookup answers with exactly that handle.
fn note_own_endpoint(ep: isize) {
    if ep <= 0 { return; }
    for i in 0..64u32 {
        if sys::cap_lookup(sys::CapKind::Endpoint as u8, i) == ep {
            unsafe { OWN_EP_INDEX = i };
            return;
        }
    }
}

/// The handle of the endpoint capability the fork grant
/// (`endpoint_inherit_at_fork`) gave this client on its parent's endpoint,
/// looked up by that endpoint's index.
///
/// It used to be computed as `(slot 0, generation 1)`: the first grant into
/// an empty table. Since wave 13 (NATFORK) a native fork child's table is not
/// empty when that grant lands: it holds its inherited descriptors at the
/// parent's handles and its row's capabilities, so the grant takes some
/// other free slot, and the handle has to be asked for.
fn inherited_endpoint_handle() -> u32 {
    let i = unsafe { OWN_EP_INDEX };
    let h = sys::cap_lookup(sys::CapKind::Endpoint as u8, i);
    if h > 0 { h as u32 } else { 0 }
}

fn phase_b_server() -> ! {
    let me = sys::getpid();
    let mut l = Line::new();
    l.s(b"[IPCTEST] B: server tid=").i(me);
    l.flush();

    // RFC-0040 gap 3: the fork grant mints a capability to an endpoint the
    // PARENT itself owns (`owner_tid == parent_tid`), so this server must
    // create and own the endpoint, and the client must be forked from THIS
    // task — not from the root, which would make client and server
    // siblings, a relation the grant does not cover. Both happen here,
    // before the client can exist at all.
    let ep = sys::endpoint_create_typed();
    note_own_endpoint(ep);
    if ep < 0 {
        post(TAG_S2_RC, 3);
        sys::exit(0);
    }
    // `me` rides along as `arg` (the same static-before-fork mechanism
    // `PARENT_TID` uses): the client is root's GRANDCHILD, so `PARENT_TID` in
    // its own memory still names root, not this task, and RFC-0040 gap 2's
    // CALL-direction check refuses a raw-TID call to anything but the
    // caller's real parent. The client posts its two mailbox verdicts to
    // `me` instead of root (`post_to`), and `relay_one` below passes each one
    // on.
    let cp = spawn(ROLE_B_CLIENT, me as u32);
    // Announced only now — after the client exists — because `phase_b`'s
    // impostor-sweep window is timed from this post. Announcing any earlier
    // would let the sweep start before there is anything to sweep around.
    post(TAG_S2_TID, me as u32);
    if cp < 0 {
        post(TAG_S2_RC, 4);
        sys::exit(0);
    }

    // **No relay before this accept.** `relay_one`'s own reply is a full
    // round trip through `post` — it blocks until ROOT pumps it, and root
    // does not pump between `TAG_S2_TID` and the impostor sweep (it sleeps,
    // then sweeps). A relay here would leave THIS task parked mid-round-trip
    // for that whole window, unable to call `fast_ipc_accept()`, so REQ2
    // would still be sitting `Pending` — not `Accepted` and held — when the
    // sweep runs, and every `fast_ipc_reply` in it would be refused by the
    // "never accepted" state gate instead of the ownership gate the sweep
    // exists to exercise. Still green, proving something weaker. So this
    // accept is entered exactly where the pre-gap-2 code entered it, and the
    // client (see `phase_b_client`) does not send ANYTHING here — its three
    // verdicts are all deferred to after the real reply below, when root is
    // already in `wait_tag`'s own pump loop and can take the round trip.
    match sys::fast_ipc_accept() {
        Some(handle) => {
            // Hold the claimed slot open so the impostor gets a real window.
            sys::sleep(B_SERVER_HOLD);
            let rc = sys::fast_ipc_reply(handle, [GOOD2, 0, 0, 0]);
            post(TAG_S2_RC, if rc == 0 { 0 } else { 1 });
        }
        None => post(TAG_S2_RC, 2),
    }

    // The client's three verdicts (tightness probe, real-exchange result,
    // ancestor-call probe — see `phase_b_client`), all posted only now, in
    // that order, and all relayed on to root the same way.
    relay_one();
    relay_one();
    relay_one();

    sys::exit(0);
}

fn phase_b_client(immediate_parent: u32) -> ! {
    let mut l = Line::new();
    l.s(b"[IPCTEST] B: client tid=").i(sys::getpid());
    l.flush();
    sys::sleep(B_CLIENT_DELAY);

    // Tightness probe (RFC-0040 gap 3): this task holds exactly one endpoint
    // capability more than its row gives (`ROW_EP_COUNT`, what root holds
    // before it creates anything): the grant on its parent's own endpoint. A
    // second one would mean the fork grant minted more than the single
    // relation it is supposed to — the failure shape of the design reverted
    // on 2026-09-21, which inherited by capability CLASS instead of by
    // ownership. (It probed slot 1 for emptiness until wave 13: a native fork
    // child now holds its row's capabilities and its inherited descriptors,
    // so slot 1 is no longer necessarily free.)
    //
    // Measured now, but NOT posted
    // yet. Every post below is a full round trip through `phase_b_server`'s
    // `relay_one` (see there for why), and `phase_b_server` cannot service
    // one of those until AFTER it has entered `fast_ipc_accept()` for the
    // real exchange below — posting here, before that, would park this
    // client mid-round-trip and leave the server unable to accept REQ2 in
    // time for the impostor sweep to find it held.
    let leaked = count_endpoints() != unsafe { ROW_EP_COUNT } + 1;

    // RFC-0040 gap 3: this task is `phase_b_server`'s own child, so it
    // reaches the endpoint through the fork-inherited capability instead of
    // a guessed TID.
    let got = sys::fast_ipc_call_ep(inherited_endpoint_handle(), [REQ2, 0, 0, 0]);

    // The three verdicts, posted only now — after the real exchange above
    // has been accepted, held, and answered. `post_to`, not `post`: this
    // task is root's grandchild (forked from `phase_b_server`, not from
    // root), so `SYS_IPC_FAST_CALL`'s parent-only rule (RFC-0040 gap 2) only
    // lets it reach `immediate_parent` — the server relays each one on to
    // root (`relay_one`, called three times, order-agnostic: it relays
    // whatever it next accepts under that message's own tag).
    //
    // **Send order here does not matter — see `phase_b`'s wait order for the
    // interaction that does.** There is a pre-existing, documented,
    // under-investigation aarch64 cross-hart wake gap
    // (`tools/ci_check.sh`'s `aarch64_ipctest_row`, tolerated as exactly one
    // failure named `B/client reported at all`). This relay adds two more
    // round trips where there used to be none, giving that gap more
    // surface. Reordering these three posts did NOT change which check it
    // lands on — root's WAIT order is what did; see `phase_b`.
    post_to(immediate_parent, TAG_CLIENT_TIGHT, if leaked { 1 } else { 0 });
    post_to(
        immediate_parent,
        TAG_CLIENT_GOT,
        match got {
            Some(w) => w as u32,
            None => u32::MAX,
        },
    );

    // RFC-0040 gap 2, the CALL direction — the probe, not the plumbing
    // above. `PARENT_TID` in this task's own memory names ROOT (inherited
    // verbatim through two forks), but this task's real kernel parent is
    // `immediate_parent` (`phase_b_server`). A raw-TID call straight to
    // `PARENT_TID` therefore targets a GRANDPARENT, not a parent, and must
    // be refused by `fast_ipc_tid_dest_for`.
    //
    // The word deliberately does not match the `MBOX_MAGIC` pattern: this
    // is not a mailbox post, and must not be mistaken for one if it is ever
    // (wrongly) delivered.
    //
    // **Why this discriminates and a call to a dead/unrelated TID would
    // not.** Root is ALIVE and already running a generic accept loop
    // (`pump`/`wait_tag`) that answers ANY delivered call with `0` — mailbox
    // shaped or not. So with the check disabled this call would actually be
    // ACCEPTED and answered, `Some(0)`; with it enabled, refused at the
    // syscall boundary before root ever sees it, `None`. A target that
    // cannot or would not answer collapses both outcomes into the same
    // "never returns / refused" observation and proves nothing — see
    // `fast_ipc_tid_dest_for`'s own doc for why parent, not any live TID, is
    // the rule.
    let ancestor_accepted =
        sys::fast_ipc_call(unsafe { PARENT_TID }, [0xDEAD_BEEFu64, 0, 0, 0]).is_some();
    post_to(
        immediate_parent,
        TAG_CLIENT_ANCESTOR_CALL,
        if ancestor_accepted { 1 } else { 0 },
    );

    sys::exit(0);
}

fn phase_b() {
    sys::println(b"[IPCTEST] B: server impersonation");

    // Hold the heartbeat's call BEFORE the server exists (RFC-0040 gap 3:
    // the client is now forked from INSIDE `phase_b_server`, not spawned by
    // this task after a wait, so this task no longer controls when the
    // client starts counting down its own `B_CLIENT_DELAY`). `hb_hold`'s own
    // bound is up to four heartbeat periods (2 s); taking it first keeps it
    // from running concurrently with the server/client/sweep margins below
    // (50 ms / 200 ms / 400 ms), all timed from the server's own start. A
    // hold that ate into those margins could push the sweep past the
    // legitimate reply — every impostor answer refused on an already-freed
    // slot, green, and proving nothing.
    let held = hb_hold();
    expect_true(b"B/heartbeat call held for the sweep", held.is_some(), 0);
    let held_slot = held.as_ref().map(|r| r.slot as usize);

    let sp = spawn(ROLE_B_SERVER, 0);
    if sp < 0 {
        expect_err(b"B/fork-server (unexpected failure)", sp);
        return;
    }
    // The server posts only after it has created its endpoint AND forked
    // the client — the "both parties exist, sweep window starts now" signal
    // this task used to get by spawning the client itself.
    match wait_tag(TAG_S2_TID, WAIT_MS) {
        Some(_) => {}
        None => {
            expect_true(b"B/server announced its TID", false, -1);
            return;
        }
    }

    // Impostor half. This task is neither the server nor the client of the
    // exchange now in flight; every one of these must be refused.
    sys::sleep(B_IMPOSTOR_DELAY);
    let mut accepted = 0u32;
    let mut not_fail_fast = 0u32;
    let mut slot = 0usize;
    while slot < sys::FAST_IPC_MAX_SLOTS {
        // Raw indices = generation 0. They are still well-formed handles, so
        // this sweep still exercises the ownership gate — and now the
        // generation gate too, as soon as a slot has been recycled.
        // The held heartbeat call is this task's own exchange, not an
        // impostor target.
        if held_slot != Some(slot) {
            if sys::fast_ipc_reply(slot as u64, [POISON, 0, 0, 0]) >= 0 {
                accepted = accepted.saturating_add(1);
            }
            // The combined call (RFC-0041 §C) must refuse the reply half the
            // same way and then accept nothing: -3, at once. A kernel that
            // went on to the accept would block here, with the heartbeat held
            // so no call on its way but the legitimate server's post: it takes
            // that post (counted here, and the server's report never arrives)
            // or holds the phase to the scenario's deadline.
            if !matches!(sys::fast_ipc_reply_accept(slot as u64, [POISON, 0, 0, 0]), Err(-3)) {
                not_fail_fast = not_fail_fast.saturating_add(1);
            }
        }
        slot += 1;
    }
    // Decision.
    expect_eq(b"B/impostor replies refused", accepted as isize, 0);
    expect_eq(b"B/impostor reply+accept refused, nothing accepted", not_fail_fast as isize, 0);
    // Let the heartbeat go. Its handle is still live: the sweep skipped its
    // slot.
    if let Some(req) = held {
        expect_eq(b"B/held heartbeat released", sys::fast_ipc_reply(req.handle, [0, 0, 0, 0]), 0);
    }

    // Actuation. The half this project keeps skipping: a refused return code
    // is not proof the payload did not land.
    //
    // **Waited before the tightness probe below, on purpose — see
    // `phase_b_client`'s ordering note.** Root's sweep does not pump; its
    // first blocked accept afterward that must be woken by an incoming call
    // (rather than one already sitting Pending) is the one the pre-existing
    // aarch64 cross-hart wake gap catches. Waiting GOT first keeps that first
    // woken accept where the gate already tolerates it failing
    // (`B/client reported at all`), not on the tightness probe.
    match wait_tag(TAG_CLIENT_GOT, WAIT_MS) {
        Some(w) if w as u64 == GOOD2 => {
            expect_true(b"B/client got the real reply", true, w as isize)
        }
        Some(w) if w as u64 == POISON => {
            expect_true(b"B/client got the real reply (POISONED)", false, w as isize)
        }
        Some(w) => expect_true(b"B/client got the real reply", false, w as isize),
        None => expect_true(b"B/client reported at all", false, -1),
    }

    // RFC-0040 gap 3 tightness probe: the child's table must hold exactly
    // the one capability the relation grants, nothing at any other slot.
    match wait_tag(TAG_CLIENT_TIGHT, WAIT_MS) {
        Some(v) => expect_eq(b"B/fork grant is tight (nothing at an untouched slot)", v as isize, 0),
        None => expect_true(b"B/client reported the tightness probe", false, -1),
    }
    match wait_tag(TAG_S2_RC, WAIT_MS) {
        Some(rc) => expect_eq(b"B/legit server replied ok", rc as isize, 0),
        None => expect_true(b"B/legit server reported at all", false, -1),
    }

    // RFC-0040 gap 2, the CALL direction: a raw-TID call from this
    // grandchild straight to its GRANDPARENT (root) must be refused —
    // `fast_ipc_tid_dest_for` allows only the caller's own parent. See the
    // probe in `phase_b_client` for why root, being alive and already
    // answering everything it accepts, is what makes this discriminate.
    match wait_tag(TAG_CLIENT_ANCESTOR_CALL, WAIT_MS) {
        Some(v) => expect_eq(
            b"B/grandchild's raw-TID call to its grandparent is refused",
            v as isize,
            0,
        ),
        None => expect_true(b"B/client reported the ancestor-call probe", false, -1),
    }
}

// ── Phase G: reply+accept on a stale handle ─────────────────────────────────
//
// `SYS_IPC_FAST_REPLY_ACCEPT` answers -2 for a stale handle, apart from the -3
// phase B sees, and accepts nothing either way (RFC-0041 §C). An old handle is
// not enough to reach -2: `fast_ipc_reply` checks state and ownership before
// the generation, so a handle to a FREED slot is only refused. This task must
// be serving that slot again under a newer generation. The heartbeat provides
// exactly that: its calls come one at a time and `alloc_slot` takes the lowest
// free slot, so with no other exchange in flight two consecutive heartbeat
// calls land on one slot, the free between them having advanced the
// generation.

/// Attempts at two consecutive heartbeat calls on one slot.
const G_TRIES: u32 = 4;

fn phase_g_stale_reply_accept() {
    sys::println(b"[IPCTEST] G: reply+accept on a stale handle");
    let mut tries = 0u32;
    while tries < G_TRIES {
        tries += 1;
        let first = match hb_hold() {
            Some(r) => r,
            None => break,
        };
        expect_eq(b"G/first heartbeat released", sys::fast_ipc_reply(first.handle, [0, 0, 0, 0]), 0);
        let second = match hb_hold() {
            Some(r) => r,
            None => break,
        };
        if second.slot != first.slot {
            // Another exchange took the lowest free slot in between. Let this
            // call go and try again.
            sys::fast_ipc_reply(second.handle, [0, 0, 0, 0]);
            continue;
        }
        // `first.handle` names a slot this task serves, accepted, under the
        // generation of an exchange that is over.
        let code = match sys::fast_ipc_reply_accept(first.handle, [POISON, 0, 0, 0]) {
            Ok(Some(_)) => 0,
            Ok(None) => -1,
            Err(e) => e,
        };
        expect_eq(b"G/stale handle answers -2, nothing accepted", code, -2);
        // Neither answered nor disturbed: the live exchange's own handle still
        // delivers. A reply that ignored the generation would have landed
        // POISON here, and this reply would be refused.
        expect_eq(b"G/live exchange still answers", sys::fast_ipc_reply(second.handle, [0, 0, 0, 0]), 0);
        return;
    }
    expect_true(b"G/two heartbeat calls on one slot", false, tries as isize);
}

// ── Phase C: typed shm / port / io_ring ownership ────────────────────────────
//
// The stranger sweep reuses the parent's OWN capability handles, read out of
// these statics. A forked child holds only its inherited descriptors and its
// row's capabilities, and a parent handle on a runtime object is stale in it
// (`natfork`), so every handle must fail to resolve there — that is the
// property, and `-ECAPSTALE` is the exact answer for a stale handle.

/// The parent's typed handles, shared with the forked stranger through memory.
static mut OWNED_SHM: u32 = 0;
static mut OWNED_PORT: u32 = 0;
static mut OWNED_RING: u32 = 0;

const SHM_MAGIC: u64 = 0x0066_1234_5678_9ABC;

/// Full lifecycle inside one task: create, map, write, read back, reject the
/// double map, release, and confirm the handle is stale afterwards.
fn phase_c_cycle() {
    sys::println(b"[IPCTEST] C: typed shm map/write/release cycle");

    let cap = sys::shm_create_typed(2, sys::SHM_RW);
    expect_pos(b"C/shm_create_typed 2 pages RW", cap);
    if cap <= 0 {
        return;
    }
    let cap = cap as u32;

    let va = sys::shm_map_typed(cap);
    expect_pos(b"C/shm_map_typed (creator)", va);
    if va <= 0 {
        return;
    }

    // A store fault here kills the task and the run ends with no verdict, so
    // announce the address first: the log then says which line faulted.
    let mut l = Line::new();
    l.s(b"[IPCTEST] C: writing shm va=").i(va);
    l.flush();
    let p = va as *mut u64;
    let read_back = unsafe {
        core::ptr::write_volatile(p, SHM_MAGIC);
        core::ptr::read_volatile(p)
    };
    expect_true(
        b"C/shm page is readable+writable",
        read_back == SHM_MAGIC,
        (read_back & 0xFFFF) as isize,
    );

    // One mapping per (task, region): a second map of a region this task
    // already maps answers -EBUSY.
    expect_eq(b"C/second shm_map_typed -EBUSY", sys::shm_map_typed(cap), E_EBUSY);

    // Release unmaps this task's mapping, gives back every reference this task
    // holds on the region (the creation reference and the map's), which frees
    // it, and REVOKES the capability (W3-F5).
    expect_eq(b"C/shm_release_typed", sys::shm_release_typed(cap), 0);

    // The capability was revoked, so the same handle now names an empty slot.
    expect_eq(b"C/shm_map_typed after release [stale]", sys::shm_map_typed(cap), E_ECAPSTALE);
}

/// Map/release cycles of the largest region, more than the shm/MMIO window
/// holds if a release never gave its addresses back. The window was one cursor
/// for the whole board that nothing lowered: about 2,000 cycles used it up and
/// every later shm and MMIO map failed. Every cycle must map at the first
/// cycle's address.
const WINDOW_CYCLES: usize = 2100;
const WINDOW_REGION_PAGES: u64 = 64;

fn phase_c_window_reuse() {
    sys::println(b"[IPCTEST] C: shm window addresses reused across map/release cycles");
    let mut first: isize = 0;
    for cycle in 0..WINDOW_CYCLES {
        let cap = sys::shm_create_typed(WINDOW_REGION_PAGES, sys::SHM_RW);
        let (va, released) = if cap > 0 {
            (sys::shm_map_typed(cap as u32), sys::shm_release_typed(cap as u32))
        } else {
            (cap, 0)
        };
        if cycle == 0 {
            first = va;
        }
        if cap <= 0 || va <= 0 || va != first || released != 0 {
            let mut l = Line::new();
            l.s(b"[IPCTEST] C: window cycle ").i(cycle as isize);
            l.s(b" cap=").i(cap).s(b" va=").i(va);
            l.s(b" first=").i(first).s(b" release=").i(released);
            l.flush();
            expect_true(b"C/window addresses reused every cycle", false, va);
            return;
        }
    }
    expect_true(b"C/window addresses reused every cycle", true, first);
}

fn phase_c_guesser() -> ! {
    // The parent's exact handles. This task holds only its descriptors and its
    // row's capabilities, so each must be stale here.
    let (shm, port, ring) = unsafe { (OWNED_SHM, OWNED_PORT, OWNED_RING) };
    let mut shm_hits = 0u32;
    let mut port_hits = 0u32;
    let mut ring_hits = 0u32;

    // shm: map and release attempts.
    if sys::shm_map_typed(shm) != E_ECAPSTALE {
        shm_hits = shm_hits.saturating_add(1);
    }
    if sys::shm_release_typed(shm) != E_ECAPSTALE {
        shm_hits = shm_hits.saturating_add(1);
    }

    // io_ring: submit and destroy attempts.
    if sys::ioring_submit_typed(ring) != E_ECAPSTALE {
        ring_hits = ring_hits.saturating_add(1);
    }
    if sys::ioring_destroy_typed(ring) != E_ECAPSTALE {
        ring_hits = ring_hits.saturating_add(1);
    }

    // port: poll, bind and destroy attempts, and — last — a blocking wait.
    // A wrongly resolved wait cap would block on the port with no event
    // queued and this child would never report, timing out the tag; the
    // correct `-ECAPSTALE` returns at once.
    let mut ev = [0u8; sys::PORT_EVENT_BYTES];
    if sys::port_poll_typed(port, &mut ev) != E_ECAPSTALE {
        port_hits = port_hits.saturating_add(1);
    }
    if sys::port_bind_typed(port, sys::PORT_SRC_IRQ, 0, 0xBAD) != E_ECAPSTALE {
        port_hits = port_hits.saturating_add(1);
    }
    if sys::port_destroy_typed(port) != E_ECAPSTALE {
        port_hits = port_hits.saturating_add(1);
    }
    if sys::port_wait_typed(port, &mut ev) != E_ECAPSTALE {
        port_hits = port_hits.saturating_add(1);
    }

    post(TAG_GUESS_SHM, shm_hits);
    post(TAG_GUESS_PORT, port_hits);
    post(TAG_GUESS_RING, ring_hits);
    sys::exit(0);
}

/// Offsets into the ring page, `io_ring::IoRing` in `crates/core/ipc/src/io_ring.rs`,
/// where assertions pin them: `sq_tail` 4, the SQ at 8 (32 × 32 B), `cq_head`
/// 1032, `cq_tail` 1036, the CQ at 1040 (32 × 16 B).
const RING_SQ_TAIL: usize = 4;
const RING_SQ_ENTRIES: usize = 8;
const RING_CQ_HEAD: usize = 1032;
const RING_CQ_TAIL: usize = 1036;
const RING_CQ_ENTRIES: usize = 1040;
/// `CqEntry::flags` bit `CQE_F_REFUSED`: the kernel refused the entry.
const RING_CQE_F_REFUSED: u32 = 1;
const RING_OP_NOP: u16 = 0;
const RING_OP_READ_SENSOR: u16 = 1;

/// Write SQE `idx` on the page at `va`: opcode @0, param0..2 @4/8/12,
/// user_data @24 (`io_ring::SqEntry`).
unsafe fn ring_put_sqe(va: usize, idx: usize, opcode: u16, p0: u32, p1: u32, p2: u32, tag: u64) {
    let e = va + RING_SQ_ENTRIES + idx * 32;
    core::ptr::write_bytes(e as *mut u8, 0, 32);
    core::ptr::write_volatile(e as *mut u16, opcode);
    core::ptr::write_volatile((e + 4) as *mut u32, p0);
    core::ptr::write_volatile((e + 8) as *mut u32, p1);
    core::ptr::write_volatile((e + 12) as *mut u32, p2);
    core::ptr::write_volatile((e + 24) as *mut u64, tag);
}

/// CQE `idx` on the page at `va`: `(user_data, result, flags)`.
unsafe fn ring_cqe(va: usize, idx: usize) -> (u64, i32, u32) {
    let c = va + RING_CQ_ENTRIES + idx * 16;
    (
        core::ptr::read_volatile(c as *const u64),
        core::ptr::read_volatile((c + 8) as *const i32),
        core::ptr::read_volatile((c + 12) as *const u32),
    )
}

/// **The ring page in ring 3, and seccomp per entry (RFC-0041 §E).**
///
/// The create's out-word is the address of the ring page in this task. The
/// ring must execute an entry written there and complete it there: a NOP
/// tagged with a value only this task wrote comes back in the CQE at that
/// address, so the page is mapped writable, readable, and is the kernel's.
///
/// IPCTEST's seccomp row does not list `SYS_SENSOR_READ_TYPED` (561), and this
/// task holds no sensor capability. A sensor read submitted through the ring
/// must complete **refused by the profile**: `-EPERM` with the refusal flag,
/// while the submit itself answers 1. `-ECAPPERMS` (-201) there would mean the
/// profile was never asked per entry and only the capability stopped it —
/// Linux's `io_uring` gap. Canary for the scenario: list 561 in the row, and
/// this line reads -201.
fn phase_c_ring(ring: u32, va: usize) {
    let aligned = va != 0 && va % 4096 == 0;
    expect_true(b"C/owner ioring_create_typed wrote a page address", aligned, va as isize);
    if !aligned {
        return;
    }
    unsafe {
        let tail = core::ptr::read_volatile((va + RING_CQ_TAIL) as *const u32);
        expect_eq(b"C/owner ring page reads a fresh cq_tail", tail as isize, 0);

        ring_put_sqe(va, 0, RING_OP_NOP, 0, 0, 0, 0x1C7E_57AA);
        core::ptr::write_volatile((va + RING_SQ_TAIL) as *mut u32, 1);
        expect_eq(b"C/owner ioring_submit_typed NOP", sys::ioring_submit_typed(ring), 1);
        let (tag, result, flags) = ring_cqe(va, 0);
        expect_true(b"C/owner NOP completion at the page address", tag == 0x1C7E_57AA, tag as isize);
        expect_eq(b"C/owner NOP result", result as isize, 0);
        expect_eq(b"C/owner NOP not refused", flags as isize, 0);
        core::ptr::write_volatile((va + RING_CQ_HEAD) as *mut u32, 1);

        ring_put_sqe(va, 1, RING_OP_READ_SENSOR, 1, 0, 16, 0x5E45);
        core::ptr::write_volatile((va + RING_SQ_TAIL) as *mut u32, 2);
        expect_eq(b"C/owner ioring_submit_typed sensor", sys::ioring_submit_typed(ring), 1);
        let (tag, result, flags) = ring_cqe(va, 1);
        expect_true(b"C/owner sensor completion tag", tag == 0x5E45, tag as isize);
        expect_eq(b"C/owner sensor entry refused by seccomp -EPERM", result as isize, E_EPERM);
        expect_eq(b"C/owner sensor entry carries CQE_F_REFUSED", (flags & RING_CQE_F_REFUSED) as isize, 1);
        core::ptr::write_volatile((va + RING_CQ_HEAD) as *mut u32, 2);
    }
}

fn phase_c_gates() {
    sys::println(b"[IPCTEST] C: cross-task ownership gates (typed)");

    // Owner half first — without it this passes against a kernel that denies
    // everybody, which is the same mistake as validating a decision and never
    // the actuation.
    let shm = sys::shm_create_typed(1, sys::SHM_RW);
    let port = sys::port_create_typed();
    // The create writes the ring page's address in this task's address space.
    let mut ring_va = [0u8; 8];
    let ring = sys::ioring_create_typed(&mut ring_va);
    expect_pos(b"C/owner shm_create_typed", shm);
    expect_pos(b"C/owner port_create_typed", port);
    expect_pos(b"C/owner ioring_create_typed", ring);
    if shm <= 0 || port <= 0 || ring <= 0 {
        return;
    }
    let (shm, port, ring) = (shm as u32, port as u32, ring as u32);
    unsafe {
        OWNED_SHM = shm;
        OWNED_PORT = port;
        OWNED_RING = ring;
    }
    // The owner's handles reach their objects: the map returns a VA, the
    // empty port polls -EAGAIN, a timer far in the future binds (and its
    // removal by key finds it), and the ring executes what is written on its
    // page. Each is an answer that means "resolved, and the object
    // answered", never the -ECAPSTALE the stranger gets.
    expect_pos(b"C/owner shm_map_typed", sys::shm_map_typed(shm));
    let mut ev = [0u8; sys::PORT_EVENT_BYTES];
    expect_eq(b"C/owner port_poll_typed -EAGAIN", sys::port_poll_typed(port, &mut ev), E_EAGAIN);
    expect_eq(b"C/owner port_bind_timer(far future)", sys::port_bind_timer(port, u64::MAX - 1, 0xC0DE), 0);
    expect_eq(b"C/owner port_unbind_typed(timer)", sys::port_unbind_typed(port, sys::PORT_SRC_TIMER, 0xC0DE), 0);
    phase_c_ring(ring, u64::from_le_bytes(ring_va) as usize);

    // Stranger half.
    let gp = spawn(ROLE_C_GUESSER, 0);
    if gp < 0 {
        expect_err(b"C/fork-guesser (unexpected failure)", gp);
        return;
    }
    match wait_tag(TAG_GUESS_SHM, WAIT_MS) {
        Some(n) => expect_eq(b"C/stranger resolved no shm cap", n as isize, 0),
        None => expect_true(b"C/guesser reported shm", false, -1),
    }
    match wait_tag(TAG_GUESS_PORT, WAIT_MS) {
        Some(n) => expect_eq(b"C/stranger resolved no port cap", n as isize, 0),
        None => expect_true(b"C/guesser reported port", false, -1),
    }
    match wait_tag(TAG_GUESS_RING, WAIT_MS) {
        Some(n) => expect_eq(b"C/stranger resolved no io_ring cap", n as isize, 0),
        None => expect_true(b"C/guesser reported ring", false, -1),
    }

    // The owner's objects still work after the stranger's sweep, then are
    // given back: the pools are 16 deep and phase D creates a lot of tasks.
    expect_eq(b"C/owner port_poll_typed still resolves", sys::port_poll_typed(port, &mut ev), E_EAGAIN);
    expect_eq(b"C/owner port_destroy_typed", sys::port_destroy_typed(port), 0);
    expect_eq(b"C/owner shm_release_typed", sys::shm_release_typed(shm), 0);
    expect_eq(b"C/owner ioring_destroy_typed", sys::ioring_destroy_typed(ring), 0);
}

// Retired untyped IPC numbers (105/503/506/511 and the rest) are pinned by
// `abitest`, whose audit-mode profile lets a raw probe reach the dispatcher
// and be recorded. Under IPCTEST's enforcing profile the filter answers `-1`
// before the dispatcher, so a probe here could not tell a retired number from
// a reassigned one — the reason that check lives in `abitest`, not here.

// ── Phase D: typed capability past task 64 ──────────────────────────────────

/// How many short-lived tasks to create before the typed-cap probe. TIDs are
/// monotone from 1 and the kernel has already used a couple of dozen by the
/// time userspace runs, so this comfortably clears `MAX_TASKS` = 64 with
/// margin — but the probe reports the TID it actually got rather than
/// trusting the arithmetic.
const D_SPAWNS: u32 = 90;
/// Milliseconds between spawns, after each child is reaped
/// ([`D_REAP_MS`]).
const D_SPAWN_GAP: u64 = 2;
/// How long phase D waits to reap each child. Wave 12: an exit notice is
/// kept until the parent reaps it, as a Linux zombie, and holds the place of
/// a task slot while it waits — 90 unreaped children would leave the rest of
/// this run no fork at all. Reaping does not undo what the phase is for: the
/// TIDs stay spent (they are never reused).
const D_REAP_MS: u32 = 2_000;
/// The pool can still be momentarily full; a refused fork is retried, not
/// treated as fatal, up to this many times.
const D_MAX_REFUSALS: u32 = 40;

const D_BIT_PORT_CREATE: u32 = 1;
const D_BIT_PORT_POLL_EMPTY: u32 = 2;
const D_BIT_PORT_DESTROY: u32 = 4;
const D_BIT_SHM_CREATE: u32 = 8;
const D_BIT_SHM_ACQUIRE: u32 = 16;
const D_MASK_ALL: u32 =
    D_BIT_PORT_CREATE | D_BIT_PORT_POLL_EMPTY | D_BIT_PORT_DESTROY | D_BIT_SHM_CREATE | D_BIT_SHM_ACQUIRE;

fn phase_d_probe() -> ! {
    post(TAG_T_TID, sys::getpid() as u32);

    let mut mask = 0u32;

    let cap = sys::port_create_typed();
    if cap > 0 {
        mask |= D_BIT_PORT_CREATE;
        let mut ev = [0u8; sys::PORT_EVENT_BYTES];
        // A port with nothing bound has an empty queue, so the typed poll
        // must report empty (-EAGAIN) rather than a cap error. Both are
        // negative; the point of the check is that the cap *resolved* far
        // enough to reach the queue at all, which a dead cap table cannot do.
        if sys::port_poll_typed(cap as u32, &mut ev) < 0 {
            mask |= D_BIT_PORT_POLL_EMPTY;
        }
        if sys::port_destroy_typed(cap as u32) == 0 {
            mask |= D_BIT_PORT_DESTROY;
        }
    }

    let shm = sys::shm_create_typed(1, sys::SHM_RW);
    if shm > 0 {
        mask |= D_BIT_SHM_CREATE;
        let mut info = [0u8; sys::SHM_INFO_BYTES];
        if sys::shm_acquire_typed(shm as u32, &mut info) == sys::SHM_INFO_BYTES as isize {
            mask |= D_BIT_SHM_ACQUIRE;
        }
        // One release gives back the acquire's reference and the create's.
        sys::shm_release_typed(shm as u32);
    }

    post(TAG_T_MASK, mask);
    sys::exit(0);
}

fn phase_d() {
    sys::println(b"[IPCTEST] D: typed cap past task 64");

    let mut created = 0u32;
    let mut refused = 0u32;
    while created < D_SPAWNS && refused < D_MAX_REFUSALS {
        let p = spawn(ROLE_D_EXIT, 0);
        if p < 0 {
            refused = refused.saturating_add(1);
            sys::sleep(5);
            continue;
        }
        created = created.saturating_add(1);
        let _ = reap_within(p as u32, D_REAP_MS);
        sys::sleep(D_SPAWN_GAP);
    }
    let mut l = Line::new();
    l.s(b"[IPCTEST] D: spawned ").i(created as isize)
        .s(b" task(s), fork refused ").i(refused as isize).s(b" time(s)");
    l.flush();

    let p = spawn(ROLE_D_PROBE, 0);
    if p < 0 {
        expect_err(b"D/fork-probe (unexpected failure)", p);
        return;
    }

    let tid = match wait_tag(TAG_T_TID, WAIT_MS) {
        Some(t) => t,
        None => {
            expect_true(b"D/probe announced its TID", false, -1);
            return;
        }
    };
    // The whole point of the phase. If this fails the phase proved nothing,
    // so say so with the number instead of reporting a green mask.
    expect_true(b"D/probe TID > MAX_TASKS(64)", tid > 64, tid as isize);

    match wait_tag(TAG_T_MASK, WAIT_MS) {
        Some(m) => expect_eq(b"D/typed caps work at high TID", m as isize, D_MASK_ALL as isize),
        None => expect_true(b"D/probe reported its mask", false, -1),
    }
    let _ = reap_within(p as u32, D_REAP_MS);
}

// ── Phase E: fast-IPC carries the REQUEST, not just the wake ────────────────
//
// Phase B already proves a fast-IPC exchange can complete and that an
// impostor cannot answer it. It does **not** prove the exchange transports
// anything: its server replies a constant, so it would pass unchanged on a
// kernel that told the server nothing but "someone called you". That is
// exactly what `SYS_IPC_FAST_ACCEPT` did until CARRIL 4 — it read
// `(slot, caller_tid, words)` from `fast_ipc_accept` and returned only the
// slot, while its own comment claimed the words were written into the
// server's trap frame by a waker that does not exist.
//
// This phase closes that hole with an echo *transform*: the client derives
// its request from its own TID, the server answers a value computed from all
// four request words, and the parent — which knows the client's TID and can
// compute the same function independently — asserts the answer. A server
// that never saw the request cannot produce it, and neither can a kernel
// that delivers stale or zeroed registers.
//
// **Three-way diagnosis, on purpose.** `fast_ipc_accept_req` pre-loads a
// sentinel into `a1` and reports `delivered = false` when the kernel did not
// write it back. So a red phase E says *which* of three things is true:
//   * `E/server received the request payload` FAIL → the trap handler in
//     `kernel/src/main.rs` still calls `syscall_dispatch` (the shim) instead
//     of `syscall_dispatch_out`, and the kernel-side delivery is inert;
//   * that check passes but `E/server saw the exact request words` FAILs →
//     a real delivery bug;
//   * nothing reports at all → K-C12, the forked child that never runs.
// Without the sentinel the first two are the same failing assertion, and a
// report would have to hedge between them.

/// Tag in the top bits of request word 0, so a stray word is not mistaken
/// for a request.
const E_REQ_TAG: u64 = 0x00E0_0000;
/// Tag in the top bits of the reply, same reason.
const E_REPLY_TAG: u64 = 0x0070_0000;
/// What the server answers when the kernel did not hand it the payload.
/// Distinct from every legal reply, so the client's verdict says "undelivered"
/// rather than "wrong value".
const E_UNDELIVERED: u64 = 0x0071_0000;

const E_SAW_DELIVERED: u32 = 1;
const E_SAW_WORDS: u32 = 2;
const E_SAW_CALLER: u32 = 4;
/// Set whenever the accept itself succeeded, delivered or not. Without it
/// `mask == 0` would mean two different things — "the accept returned None"
/// and "the accept succeeded but the kernel wrote no payload" — and all three
/// verdict lines below would print `rc=0` for either. `mask == 0` now means
/// no accept; `mask == 8` means accepted and undelivered.
const E_SAW_ACCEPTED: u32 = 8;

/// The request a client with TID `tid` sends. A pure function of the TID, so
/// the parent can reconstruct it without a second back-channel.
fn e_request(tid: u32) -> [u64; sys::FAST_IPC_MAX_WORDS] {
    let t = tid as u64;
    [
        E_REQ_TAG | (t & 0xFFFF),
        t.wrapping_mul(7).wrapping_add(0x1003),
        t.wrapping_mul(11).wrapping_add(0x2005),
        t.wrapping_mul(13).wrapping_add(0x3007),
    ]
}

/// The transform the server applies. Depends on **all four** words, so a
/// server that received only word 0 cannot produce it either.
///
/// Masked into 20 bits and tagged: the result travels back through `a0`,
/// where a negative `i64` means "call failed", and through the 32-bit
/// mailbox. Both constrain it to small non-negative values.
fn e_reply(w: &[u64; sys::FAST_IPC_MAX_WORDS]) -> u64 {
    E_REPLY_TAG | ((w[0] ^ w[1] ^ w[2] ^ w[3]) & 0x000F_FFFF)
}

fn phase_e_server() -> ! {
    let me = sys::getpid();
    let mut l = Line::new();
    l.s(b"[IPCTEST] E: server tid=").i(me);
    l.flush();

    // RFC-0040 gap 3, same shape as phase B: this task must own the
    // endpoint and fork the client itself for the inherited capability to
    // reach it.
    let ep = sys::endpoint_create_typed();
    note_own_endpoint(ep);
    if ep < 0 {
        post(TAG_E_SRV_TID, me as u32);
        post(TAG_E_SRV_SAW, 0);
        sys::exit(0);
    }
    // `me` as `arg`, same reason as `phase_b_server`: the client is root's
    // grandchild and cannot post to root directly any more (RFC-0040 gap 2).
    let cp = spawn(ROLE_E_CLIENT, me as u32);
    post(TAG_E_SRV_TID, me as u32);
    if cp < 0 {
        post(TAG_E_SRV_SAW, 0);
        sys::exit(0);
    }

    // Relay 1: the client's `TAG_E_CLI_TID` announcement, posted before its
    // real call — see `phase_b_server`'s `relay_one` for the shape.
    relay_one();

    match sys::fast_ipc_accept_req() {
        Some(req) => {
            let mut mask = E_SAW_ACCEPTED;
            if req.delivered {
                mask |= E_SAW_DELIVERED;
                // The client embeds its own `getpid()` in word 0; the kernel
                // reports the caller TID independently. Agreement between the
                // two is what verifies the TID half of the delivery — a
                // constant would verify nothing.
                if (req.words[0] & 0xFFFF) == (req.caller_tid as u64 & 0xFFFF) {
                    mask |= E_SAW_CALLER;
                }
                if req.words == e_request(req.caller_tid) {
                    mask |= E_SAW_WORDS;
                }
            }
            let mut l = Line::new();
            l.s(b"[IPCTEST] E: server slot=").i(req.slot as isize)
                .s(b" from=").i(req.caller_tid as isize)
                .s(b" delivered=").i(req.delivered as isize)
                .s(b" w0=").i(req.words[0] as isize);
            l.flush();
            post(TAG_E_SRV_SAW, mask);

            let answer = if req.delivered { e_reply(&req.words) } else { E_UNDELIVERED };
            sys::fast_ipc_reply(req.handle, [answer, 0, 0, 0]);
        }
        // No accept: nothing was claimed, so there is nothing to reply to and
        // no slot is leaked here. The client, however, is still blocked on
        // its own slot until its bounded retry gives up — which is why this
        // phase runs before A rather than sharing tasks with it.
        None => post(TAG_E_SRV_SAW, 0),
    }

    // Relay 2: the client's post-exchange `TAG_E_CLI_GOT` verdict, sent only
    // after the real call above has already been answered.
    relay_one();

    sys::exit(0);
}

fn phase_e_client(immediate_parent: u32) -> ! {
    let me = sys::getpid() as u32;
    // `post_to`, not `post`: this task is root's grandchild (forked from
    // `phase_e_server`), so RFC-0040 gap 2's parent-only rule only lets it
    // reach `immediate_parent` — the server relays this on to root.
    post_to(immediate_parent, TAG_E_CLI_TID, me);
    let words = e_request(me);
    // RFC-0040 gap 3: this task is `phase_e_server`'s own child (see
    // `phase_b_client`'s `inherited_endpoint_handle` for why the handle is
    // deterministic).
    let got = sys::fast_ipc_call_ep(inherited_endpoint_handle(), words);
    post_to(
        immediate_parent,
        TAG_E_CLI_GOT,
        match got {
            Some(w) => w as u32,
            None => u32::MAX,
        },
    );
    sys::exit(0);
}

fn phase_e() {
    sys::println(b"[IPCTEST] E: fast-IPC request delivery (echo transform)");

    let sp = spawn(ROLE_E_SERVER, 0);
    if sp < 0 {
        expect_err(b"E/fork-server (unexpected failure)", sp);
        return;
    }
    // RFC-0040 gap 3: the server forks the client itself (see phase B), so
    // this only waits for the server's own announcement now.
    match wait_tag(TAG_E_SRV_TID, WAIT_MS) {
        Some(_) => {}
        None => {
            expect_true(b"E/server announced its TID", false, -1);
            return;
        }
    }
    let ctid = match wait_tag(TAG_E_CLI_TID, WAIT_MS) {
        Some(t) => t,
        None => {
            // K-C12 territory: the child got a positive TID and never ran.
            expect_true(b"E/client announced its TID", false, -1);
            return;
        }
    };

    match wait_tag(TAG_E_SRV_SAW, WAIT_MS) {
        Some(mask) => {
            expect_true(
                b"E/server accepted the call",
                mask & E_SAW_ACCEPTED != 0,
                mask as isize,
            );
            expect_true(
                b"E/server received the request payload",
                mask & E_SAW_DELIVERED != 0,
                mask as isize,
            );
            expect_true(
                b"E/server saw the caller TID",
                mask & E_SAW_CALLER != 0,
                mask as isize,
            );
            expect_true(
                b"E/server saw the exact request words",
                mask & E_SAW_WORDS != 0,
                mask as isize,
            );
        }
        None => expect_true(b"E/server reported at all", false, -1),
    }

    // Actuation: the request reaching the server is only half of an RPC. The
    // parent recomputes the expected answer from the client's TID alone, so
    // this passes only if the reply is genuinely a function of the request.
    let want = e_reply(&e_request(ctid)) as isize;
    match wait_tag(TAG_E_CLI_GOT, WAIT_MS) {
        Some(w) if w as u64 == E_UNDELIVERED => expect_true(
            b"E/client got the transformed reply (UNDELIVERED)",
            false,
            w as isize,
        ),
        Some(w) => expect_eq(b"E/client got the transformed reply", w as isize, want),
        None => expect_true(b"E/client reported at all", false, -1),
    }
}

// ── Phase H: one `Cap<Shm>` region, two tasks ───────────────────────────────
//
// Same three-task shape as phase E: root forks the server, the server creates
// an endpoint and forks the client, the client reaches the server through the
// fork-inherited endpoint capability and posts its verdict through the server
// (`relay_one`). What travels is a `Cap<Shm>`, MOVED with the call.

/// Word 0 of the client's call, so the server can tell it from a mailbox post.
const H_REQ_TAG: u64 = 0x0048_0000;
/// Written by the client at offset 0 before the call; the server must read it.
const H_WORD_CLIENT: u64 = 0x4B45_524E_4F53_4331;
/// Written by the server at offset 8 before replying; the client must read it.
const H_WORD_SERVER: u64 = 0x4B45_524E_4F53_5331;

// Server verdict bits (`TAG_H_SRV_SAW`).
const H_SRV_ACCEPTED: u32 = 1;
const H_SRV_CAP_ARRIVED: u32 = 2;
const H_SRV_MAPPED: u32 = 4;
const H_SRV_SAW_CLIENT: u32 = 8;
// Client verdict bits (`TAG_H_CLI`).
const H_CLI_CREATED: u32 = 1;
const H_CLI_MAPPED: u32 = 2;
const H_CLI_ANSWERED: u32 = 4;
const H_CLI_SAW_SERVER: u32 = 8;
const H_CLI_HANDLE_STALE: u32 = 16;

fn phase_h_server() -> ! {
    let me = sys::getpid();
    let ep = sys::endpoint_create_typed();
    note_own_endpoint(ep);
    if ep < 0 {
        post(TAG_H_SRV_TID, me as u32);
        post(TAG_H_SRV_SAW, 0);
        sys::exit(0);
    }
    let cp = spawn(ROLE_H_CLIENT, me as u32);
    post(TAG_H_SRV_TID, me as u32);
    if cp < 0 {
        post(TAG_H_SRV_SAW, 0);
        sys::exit(0);
    }

    let mut mask = 0u32;
    if let Some(req) = sys::fast_ipc_accept_req() {
        mask |= H_SRV_ACCEPTED;
        if req.delivered && req.words[0] == H_REQ_TAG && req.moved_cap != sys::NO_CAP_TO_MOVE {
            mask |= H_SRV_CAP_ARRIVED;
            let va = sys::shm_map_typed(req.moved_cap);
            let mut l = Line::new();
            l.s(b"[IPCTEST] H: server mapped the moved Cap<Shm> rc=").i(va);
            l.flush();
            if va > 0 {
                mask |= H_SRV_MAPPED;
                let base = va as usize as *mut u64;
                // SAFETY: `va` is this task's mapping of a one-page RW region.
                unsafe {
                    if core::ptr::read_volatile(base) == H_WORD_CLIENT {
                        mask |= H_SRV_SAW_CLIENT;
                    }
                    core::ptr::write_volatile(base.add(1), H_WORD_SERVER);
                }
            }
        }
        post(TAG_H_SRV_SAW, mask);
        sys::fast_ipc_reply(req.handle, [H_REQ_TAG + 1, 0, 0, 0]);
    } else {
        post(TAG_H_SRV_SAW, 0);
    }
    // The client's verdict, posted after the exchange above.
    relay_one();
    sys::exit(0);
}

fn phase_h_client(immediate_parent: u32) -> ! {
    let mut mask = 0u32;
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    if cap > 0 {
        mask |= H_CLI_CREATED;
        let cap = cap as u32;
        let va = sys::shm_map_typed(cap);
        if va > 0 {
            mask |= H_CLI_MAPPED;
            let base = va as usize as *mut u64;
            // SAFETY: `va` is this task's mapping of a one-page RW region.
            unsafe { core::ptr::write_volatile(base, H_WORD_CLIENT) };
            let got = sys::fast_ipc_call_ep_moving(
                inherited_endpoint_handle(), [H_REQ_TAG, 0, 0, 0], cap);
            if got.map(|w| w[0]) == Some(H_REQ_TAG + 1) {
                mask |= H_CLI_ANSWERED;
            }
            // SAFETY: the mapping outlives the move (it is this task's, not
            // the capability's).
            if unsafe { core::ptr::read_volatile(base.add(1)) } == H_WORD_SERVER {
                mask |= H_CLI_SAW_SERVER;
            }
            // Moved, not copied: the handle this task used is gone.
            if sys::shm_map_typed(cap) == E_ECAPSTALE {
                mask |= H_CLI_HANDLE_STALE;
            }
        }
    }
    post_to(immediate_parent, TAG_H_CLI, mask);
    sys::exit(0);
}

fn phase_h() {
    sys::println(b"[IPCTEST] H: one Cap<Shm> region mapped in two tasks (moved capability)");

    let sp = spawn(ROLE_H_SERVER, 0);
    if sp < 0 {
        expect_err(b"H/fork-server (unexpected failure)", sp);
        return;
    }
    if wait_tag(TAG_H_SRV_TID, WAIT_MS).is_none() {
        expect_true(b"H/server announced its TID", false, -1);
        return;
    }
    match wait_tag(TAG_H_SRV_SAW, WAIT_MS) {
        Some(m) => {
            expect_true(b"H/server accepted the call", m & H_SRV_ACCEPTED != 0, m as isize);
            expect_true(b"H/the Cap<Shm> arrived with the call", m & H_SRV_CAP_ARRIVED != 0, m as isize);
            expect_true(b"H/server mapped the moved Cap<Shm>", m & H_SRV_MAPPED != 0, m as isize);
            expect_true(b"H/server reads the client's write", m & H_SRV_SAW_CLIENT != 0, m as isize);
        }
        None => expect_true(b"H/server reported at all", false, -1),
    }
    match wait_tag(TAG_H_CLI, WAIT_MS) {
        Some(m) => {
            expect_true(b"H/client created and mapped the region",
                m & (H_CLI_CREATED | H_CLI_MAPPED) == H_CLI_CREATED | H_CLI_MAPPED, m as isize);
            expect_true(b"H/client's moving call was answered", m & H_CLI_ANSWERED != 0, m as isize);
            expect_true(b"H/client reads the server's write", m & H_CLI_SAW_SERVER != 0, m as isize);
            expect_true(b"H/the moved handle is stale in the mover", m & H_CLI_HANDLE_STALE != 0, m as isize);
        }
        None => expect_true(b"H/client reported at all", false, -1),
    }
}

// ── Phase R: a robust notify word whose holder dies (wave 11, LEASE2) ──────
//
// The robust-futex analogue. A server forks a client; the client creates a
// region, takes the word at its start as a lock (its TID in the low 30 bits),
// registers it robust (`SYS_NOTIFY_WAIT` op 1) and MOVES the `Cap<Shm>` to the
// server with its call (phase H's mechanism). The server maps it, sets
// `WAITERS` and sleeps on the word with a 10 s deadline. The client waits on
// the clock until it sees `WAITERS`, then 300 ms more, then dies holding the
// word (a store to the null guard). The kernel's exit sweep must mark the word
// `OWNER_DIED` and wake the sleeper with `2`, and the server must then take
// the lock over and be told the owner died.
//
// Canary (by hand): `--features qemu,robust-sweep-canary` skips the sweep;
// the wait ends `1` (timed out) after 10 s with the dead client's TID still in
// the word, and `R/server woken with OWNER_DIED` fails on rc=1.

const R_REQ_TAG: u64 = 0x0052_0000;
/// Server verdict bits.
const R_ACCEPTED: u32 = 1;
const R_MAPPED: u32 = 2;
const R_SAW_HOLDER: u32 = 4;
const R_WOKE_DIED: u32 = 8;
const R_WORD_DIED: u32 = 16;
const R_TOOK_OVER: u32 = 32;
const R_HOLDER_KILLED: u32 = 64;
const R_UNLOCKED: u32 = 128;
/// The wait's own return code rides in bits 16.. (biased by 16, so -EAGAIN
/// and friends stay positive): printed on failure.
const R_RC_SHIFT: u32 = 16;
/// How long the server sleeps on the word: the canary's failure bound.
const R_WAIT_NS: u64 = 10_000_000_000;

fn ms_deadline(ms: u32) -> isize {
    sys::uptime() + ms as isize * ticks_per_ms()
}

fn phase_r_server() -> ! {
    use core::sync::atomic::{AtomicU32, Ordering};
    let me = sys::getpid() as u32;
    let ep = sys::endpoint_create_typed();
    note_own_endpoint(ep);
    if ep < 0 {
        post(TAG_R, 0);
        sys::exit(0);
    }
    let cp = spawn(ROLE_R_CLIENT, me);
    if cp < 0 {
        post(TAG_R, 0);
        sys::exit(0);
    }
    let mut mask = 0u32;
    let mut rc: isize = -100;
    if let Some(req) = sys::fast_ipc_accept_req() {
        mask |= R_ACCEPTED;
        let va = if req.delivered && req.words[0] == R_REQ_TAG && req.moved_cap != sys::NO_CAP_TO_MOVE {
            sys::shm_map_typed(req.moved_cap)
        } else {
            -1
        };
        // Answer first: the client waits on the clock for WAITERS, not on us.
        sys::fast_ipc_reply(req.handle, [R_REQ_TAG + 1, 0, 0, 0]);
        if va > 0 {
            mask |= R_MAPPED;
            let addr = va as usize;
            // SAFETY: `va` is this task's mapping of a one-page RW region.
            let w = unsafe { &*(addr as *const AtomicU32) };
            let v = w.load(Ordering::Acquire);
            if v == cp as u32 {
                mask |= R_SAW_HOLDER;
                let want = v | sys::ROBUST_WAITERS;
                if w.compare_exchange(v, want, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    rc = sys::notify_wait(addr, want, R_WAIT_NS);
                    if rc == sys::NOTIFY_WAIT_OWNER_DIED as isize {
                        mask |= R_WOKE_DIED;
                    }
                }
            }
            let after = w.load(Ordering::Acquire);
            if after & sys::ROBUST_OWNER_DIED != 0 && after & sys::ROBUST_TID_MASK == 0 {
                mask |= R_WORD_DIED;
            }
            if sys::robust_lock(addr, me, 1_000_000_000) == sys::RobustLock::OwnerDied {
                mask |= R_TOOK_OVER;
                sys::robust_unlock(addr);
                if w.load(Ordering::Acquire) == 0 {
                    mask |= R_UNLOCKED;
                }
            }
        }
    }
    // The holder died by the fault, not by an exit of its own.
    let deadline = ms_deadline(WAIT_MS);
    let mut status: i32 = -1;
    while sys::uptime() < deadline {
        if sys::waitpid(cp as u32, &mut status as *mut i32) == cp {
            break;
        }
        sys::sleep(5);
    }
    if status == 139 {
        mask |= R_HOLDER_KILLED;
    }
    let mut l = Line::new();
    l.s(b"[IPCTEST] R: server mask=").i(mask as isize).s(b" wait rc=").i(rc)
        .s(b" holder status=").i(status as isize);
    l.flush();
    post(TAG_R, mask | (((rc + 16) as u32 & 0xFF) << R_RC_SHIFT));
    sys::exit(0);
}

fn phase_r_client() -> ! {
    use core::sync::atomic::{AtomicU32, Ordering};
    let me = sys::getpid() as u32;
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    if cap <= 0 {
        sys::exit(3);
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        sys::exit(3);
    }
    let addr = va as usize;
    if sys::robust_lock(addr, me, 0) != sys::RobustLock::Acquired || sys::notify_robust_add(addr) != 0 {
        // The server sees a word that is not ours and reports it.
        // SAFETY: this task's own mapping of a one-page RW region.
        unsafe { (*(addr as *const AtomicU32)).store(0, Ordering::Release) };
    }
    let _ = sys::fast_ipc_call_ep_moving(inherited_endpoint_handle(), [R_REQ_TAG, 0, 0, 0], cap as u32);
    // SAFETY: the mapping outlives the move (it is this task's).
    let w = unsafe { &*(addr as *const AtomicU32) };
    let deadline = ms_deadline(WAIT_MS);
    while w.load(Ordering::Acquire) & sys::ROBUST_WAITERS == 0 && sys::uptime() < deadline {
        sys::sleep(2);
    }
    // On the clock, not a yield count: long enough for the server to be
    // asleep in the kernel, short against its 10 s deadline.
    sys::sleep(300);
    // Die holding the word: a store to the null guard kills this task.
    // SAFETY: deliberately faulting; the kernel kills the task.
    unsafe { core::ptr::write_volatile(core::hint::black_box(8usize) as *mut u32, 1) };
    sys::exit(4);
}

fn phase_r() {
    sys::println(b"[IPCTEST] R: robust notify word, holder killed while a waiter sleeps");
    // The ABI, in this task.
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    let va = sys::shm_map_typed(cap as u32);
    expect_pos(b"R/shm map for the ABI checks", va);
    if va > 0 {
        let a = va as usize;
        expect_eq(b"R/robust add (misaligned) [EINVAL]", sys::notify_robust_add(a + 1), -22);
        expect_eq(b"R/robust add (unmapped) [EFAULT]", sys::notify_robust_add(0x1000), -14);
        expect_eq(b"R/robust add", sys::notify_robust_add(a), 0);
        expect_eq(b"R/robust add again is the same registration", sys::notify_robust_add(a), 0);
        expect_eq(b"R/robust del", sys::notify_robust_del(a), 0);
        expect_eq(b"R/robust del again [ENOENT]", sys::notify_robust_del(a), -2);
    }
    let ro = sys::shm_create_typed(1, 0);
    let rva = sys::shm_map_typed(ro as u32);
    if rva > 0 {
        expect_eq(b"R/robust add on a read-only region [EACCES]",
            sys::notify_robust_add(rva as usize), -13);
    } else {
        expect_pos(b"R/read-only shm map", rva);
    }
    let _ = sys::shm_release_typed(cap as u32);
    let _ = sys::shm_release_typed(ro as u32);

    if spawn(ROLE_R_SERVER, 0) < 0 {
        expect_true(b"R/fork the server", false, -1);
        return;
    }
    // The server's own wait is up to 10 s; its verdict comes after.
    match wait_tag(TAG_R, WAIT_MS + 15_000) {
        Some(v) => {
            let m = v & 0xFFFF;
            let rc = ((v >> R_RC_SHIFT) & 0xFF) as isize - 16;
            expect_true(b"R/server got the moved Cap<Shm> and mapped it",
                m & (R_ACCEPTED | R_MAPPED) == R_ACCEPTED | R_MAPPED, m as isize);
            expect_true(b"R/the word held the client's TID", m & R_SAW_HOLDER != 0, m as isize);
            expect_true(b"R/server woken with OWNER_DIED", m & R_WOKE_DIED != 0, rc);
            expect_true(b"R/word left OWNER_DIED with no owner", m & R_WORD_DIED != 0, m as isize);
            expect_true(b"R/next owner took it over and was told", m & R_TOOK_OVER != 0, m as isize);
            expect_true(b"R/the takeover released cleanly", m & R_UNLOCKED != 0, m as isize);
            expect_true(b"R/the holder was killed (status 139)", m & R_HOLDER_KILLED != 0, m as isize);
            if m & (R_WOKE_DIED | R_WORD_DIED | R_TOOK_OVER) == R_WOKE_DIED | R_WORD_DIED | R_TOOK_OVER {
                sys::println(b"[IPCTEST] R: PASS owner-died woke the sleeper and handed the word over");
            }
        }
        None => expect_true(b"R/server reported at all", false, -1),
    }
}

// ── Phase W: a lease's end takes the lessee's mapping (wave 11, LEASE2) ────
//
// RFC-0049 P4, the memfd-seal analogue on the lessee side. This task is the
// lessor. W1: a forked lessee accepts WITH the map flag, writes the buffer,
// returns the lease, then writes again — that write must fault, be attributed
// to the revoked lease (`SYS_EXIT_STATS` selector 3) and kill it (139), and
// must not land in the region. W2: a second lessee spins writing a counter
// into its lease mapping (on another hart under `-smp 4`, typically) until
// this task FREES the lease: the remote unmap and its shootdown must stop it
// with the same fault.
//
// Canary (by hand): `--features qemu,lease-revoke-canary` registers no PTE
// removal. W1's second write lands and the lessee exits 0; W2's spinner never
// stops. Both `W1/...` and `W2/...` status checks fail.

const W_FIRST: u32 = 0x5731_0001;
const W_SECOND: u32 = 0x5731_0002;

fn phase_w_lessee(lessor: u32) -> ! {
    match sys::lease_accept_map(lessor) {
        Ok((id, va)) => {
            let p = va as *mut u32;
            // SAFETY: the lease's mapping of a one-page RW region.
            unsafe { core::ptr::write_volatile(p, W_FIRST) };
            if sys::lease_return(id) != 0 {
                sys::exit(5);
            }
            // After the return: this store must fault.
            unsafe { core::ptr::write_volatile(p.add(1), W_SECOND) };
            sys::exit(0);
        }
        Err(_) => sys::exit(3),
    }
}

fn phase_w_spinner(lessor: u32) -> ! {
    match sys::lease_accept_map(lessor) {
        Ok((_id, va)) => {
            let p = (va as *mut u32).wrapping_add(2);
            let mut n = 1u32;
            loop {
                // SAFETY: the lease's mapping, until the lessor frees it.
                unsafe { core::ptr::write_volatile(p, n) };
                n = n.wrapping_add(1);
            }
        }
        Err(_) => sys::exit(3),
    }
}

/// Reap `cp`, polling on the clock; its exit status, or `None` past `ms`.
fn reap_within(cp: u32, ms: u32) -> Option<i32> {
    let deadline = ms_deadline(ms);
    let mut status: i32 = -1;
    while sys::uptime() < deadline {
        if sys::waitpid(cp, &mut status as *mut i32) == cp as isize {
            return Some(status);
        }
        sys::sleep(5);
    }
    None
}

/// Rounds of [`phase_w_cost`].
const W_COST_ROUNDS: usize = 64;

/// The price of a revoke, printed, never asserted: a self-lease returned
/// `W_COST_ROUNDS` times with a mapping and as many times without, each
/// return bracketed by two `uptime()` reads. The difference per return is
/// what the revoke adds (PTE clear, shootdown, window record, reference
/// release). Run under `-icount shift=0` the timebase counts instructions
/// (riscv64: 1 tick = 100 instructions at 10 MHz; aarch64: 1 tick = 1 at
/// 1 GHz), so the figure is an instruction count; without `-icount` it is
/// host time and only indicative. One hart holds the address space here, so
/// the shootdown is the local flush; a lessee on another hart adds one remote
/// fence round (SBI on riscv64; aarch64's `TLBI ..IS` is broadcast anyway).
fn phase_w_cost(cap: u32, me: u32) {
    let mut mapped = 0isize;
    let mut plain = 0isize;
    let mut done = 0usize;
    for _ in 0..W_COST_ROUNDS {
        let id = sys::lease_grant(cap, me, 0);
        if id < 0 {
            break;
        }
        let ok = matches!(sys::lease_accept_map(me), Ok((got, _)) if got as isize == id);
        let t0 = sys::uptime();
        let r = sys::lease_return(id as u64);
        let t1 = sys::uptime();
        let _ = sys::lease_free(id as u64);
        if !ok || r != 0 {
            break;
        }
        mapped += t1 - t0;
        let id = sys::lease_grant(cap, me, 0);
        if id < 0 || sys::lease_accept(me) != id {
            break;
        }
        let t0 = sys::uptime();
        let r = sys::lease_return(id as u64);
        let t1 = sys::uptime();
        let _ = sys::lease_free(id as u64);
        if r != 0 {
            break;
        }
        plain += t1 - t0;
        done += 1;
    }
    let mut l = Line::new();
    l.s(b"[IPCTEST] W: revoke cost over ").i(done as isize)
        .s(b" self-lease returns: with mapping=").i(mapped)
        .s(b" ticks, plain=").i(plain)
        .s(b" ticks, timebase hz=").i(sys::vdso_timebase_hz() as isize);
    l.flush();
    expect_eq(b"W/cost rounds all ran", done as isize, W_COST_ROUNDS as isize);
}

fn phase_w() {
    sys::println(b"[IPCTEST] W: a lease's end unmaps the lessee (write after revoke faults)");
    let me = sys::getpid() as u32;
    let faults0 = sys::exit_stats(sys::EXIT_STAT_LEASE_REVOKED_FAULTS);
    expect_true(b"W/revoked-fault counter readable", faults0 >= 0, faults0);
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    let va = sys::shm_map_typed(cap as u32);
    expect_pos(b"W/lessor maps its region", va);
    if va <= 0 {
        return;
    }
    let base = va as usize as *mut u32;

    // W1: return, then write.
    let cp = spawn(ROLE_W_LESSEE, me);
    let id = sys::lease_grant(cap as u32, cp as u32, 0);
    expect_true(b"W1/lease granted to the lessee", cp > 0 && id >= 0, id);
    if cp > 0 && id >= 0 {
        let lc = sys::cap_lookup(sys::CapKind::Lease as u8, id as u32);
        if lc > 0 {
            expect_eq(b"W1/lease_wait -> returned", sys::lease_wait(lc as u32), 0);
        }
        let st = reap_within(cp as u32, WAIT_MS);
        expect_eq(b"W1/lessee killed by its write after return (status 139)",
            st.map(|s| s as isize).unwrap_or(-1), 139);
        // SAFETY: this task's own mapping of the region.
        let (w0, w1) = unsafe { (core::ptr::read_volatile(base), core::ptr::read_volatile(base.add(1))) };
        expect_true(b"W1/the write while leased landed", w0 == W_FIRST, w0 as isize);
        expect_true(b"W1/the write after return did not land", w1 != W_SECOND, w1 as isize);
        expect_eq(b"W1/lease_free", sys::lease_free(id as u64), 0);
    }
    let faults1 = sys::exit_stats(sys::EXIT_STAT_LEASE_REVOKED_FAULTS);
    expect_eq(b"W1/the fault was attributed to the revoked lease", faults1 - faults0, 1);

    // W2: the lessor revokes a lessee that is running.
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(base.add(2), 0) };
    let cp = spawn(ROLE_W_SPINNER, me);
    let id = sys::lease_grant(cap as u32, cp as u32, 0);
    expect_true(b"W2/lease granted to the spinner", cp > 0 && id >= 0, id);
    if cp > 0 && id >= 0 {
        let deadline = ms_deadline(WAIT_MS);
        // SAFETY: as above.
        while unsafe { core::ptr::read_volatile(base.add(2)) } == 0 && sys::uptime() < deadline {
            sys::sleep(2);
        }
        let running = unsafe { core::ptr::read_volatile(base.add(2)) };
        expect_true(b"W2/the spinner writes through its lease mapping", running != 0, running as isize);
        expect_eq(b"W2/lessor frees the lease under the running lessee", sys::lease_free(id as u64), 0);
        let st = reap_within(cp as u32, WAIT_MS);
        expect_eq(b"W2/spinner stopped by the revoke (status 139)",
            st.map(|s| s as isize).unwrap_or(-1), 139);
        let a = unsafe { core::ptr::read_volatile(base.add(2)) };
        sys::sleep(20);
        let b = unsafe { core::ptr::read_volatile(base.add(2)) };
        expect_true(b"W2/no write lands after the revoke", a == b, (b.wrapping_sub(a)) as isize);
    }
    let faults2 = sys::exit_stats(sys::EXIT_STAT_LEASE_REVOKED_FAULTS);
    expect_eq(b"W2/the fault was attributed to the revoked lease", faults2 - faults1, 1);
    phase_w_cost(cap as u32, me);
    expect_eq(b"W/shm_release_typed", sys::shm_release_typed(cap as u32), 0);
    if faults2 - faults0 == 2 {
        sys::println(b"[IPCTEST] W: PASS lease end revoked the lessee's write (return and lessor free)");
    }
}

// ── Phase S: the producer-side seal (wave 11, LEASE3) ───────────────────────
//
// A grant with `LEASE_GRANT_SEAL` makes the lessor's own mapping of the region
// read-only until the lease ends. Each case runs in a forked child, because
// the lessor is the task that dies: S1 grants a sealed self-lease, accepts it
// (plain) and writes its own mapping — the write must fault, be attributed to
// the seal (`SYS_EXIT_STATS` selector 4) and kill it (139). S2 does the same
// but returns the lease first: its write must land (exit 0). S3 maps the
// region only AFTER its sealed grant: that mapping is read-only, so its write
// kills it too (unattributed: the mapping is not the seal's).
//
// Canary: `--features qemu,lease-seal-canary` takes nothing away at grant. S1
// writes and exits 0 (`S1/sealed lessor killed by its write (status 139)`
// fails, and so does the attribution); S2 and S3 pass.

const S_SEALED: u32 = 1;
const S_RESTORED: u32 = 2;
const S_LATE_MAP: u32 = 3;
const S_MARK: u32 = 0x5331_0001;

fn phase_s_child(case: u32) -> ! {
    let me = sys::getpid() as u32;
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    if cap < 0 {
        sys::exit(2);
    }
    let mut va = 0isize;
    if case != S_LATE_MAP {
        va = sys::shm_map_typed(cap as u32);
        if va <= 0 {
            sys::exit(3);
        }
        // SAFETY: this task's own RW mapping, before any seal.
        unsafe { core::ptr::write_volatile(va as usize as *mut u32, 1) };
    }
    let id = sys::lease_grant_flags(cap as u32, me, sys::LEASE_GRANT_SEAL, 0);
    if id < 0 || sys::lease_accept(me) != id {
        sys::exit(4);
    }
    if case == S_RESTORED && sys::lease_return(id as u64) != 0 {
        sys::exit(5);
    }
    if case == S_LATE_MAP {
        va = sys::shm_map_typed(cap as u32);
        if va <= 0 {
            sys::exit(3);
        }
    }
    // S1, S3: this store must fault. S2: the lease is over, it must land.
    // SAFETY: this task's own mapping of a one-page region.
    unsafe { core::ptr::write_volatile(va as usize as *mut u32, S_MARK) };
    let back = unsafe { core::ptr::read_volatile(va as usize as *const u32) };
    sys::exit(if back == S_MARK { 0 } else { 6 });
}

fn phase_s() {
    sys::println(b"[IPCTEST] S: a sealed grant takes the lessor's write until the lease ends");
    let me = sys::getpid() as u32;
    // The flag word: any bit but the seal is refused before anything is granted.
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    expect_pos(b"S/shm for the flag check", cap);
    if cap > 0 {
        expect_eq(b"S/an unknown grant flag [EINVAL]",
            sys::lease_grant_flags(cap as u32, me, 1u64 << 33, 0), -22);
        let _ = sys::shm_release_typed(cap as u32);
    }
    let f0 = sys::exit_stats(sys::EXIT_STAT_LEASE_SEAL_FAULTS);
    expect_true(b"S/seal-fault counter readable", f0 >= 0, f0);

    let cp = spawn(ROLE_S_SEALED, 0);
    let st = if cp > 0 { reap_within(cp as u32, WAIT_MS) } else { None };
    expect_eq(b"S1/sealed lessor killed by its write (status 139)",
        st.map(|s| s as isize).unwrap_or(-1), 139);
    let f1 = sys::exit_stats(sys::EXIT_STAT_LEASE_SEAL_FAULTS);
    expect_eq(b"S1/the fault was attributed to the seal", f1 - f0, 1);

    let cp = spawn(ROLE_S_RESTORED, 0);
    let st = if cp > 0 { reap_within(cp as u32, WAIT_MS) } else { None };
    expect_eq(b"S2/the write after return lands (status 0)",
        st.map(|s| s as isize).unwrap_or(-1), 0);

    let cp = spawn(ROLE_S_LATE_MAP, 0);
    let st = if cp > 0 { reap_within(cp as u32, WAIT_MS) } else { None };
    expect_eq(b"S3/a mapping made under the seal is read-only (status 139)",
        st.map(|s| s as isize).unwrap_or(-1), 139);
    let f2 = sys::exit_stats(sys::EXIT_STAT_LEASE_SEAL_FAULTS);
    expect_eq(b"S2+S3/no other fault was attributed to a seal", f2 - f1, 0);
    if f1 - f0 == 1 {
        sys::println(b"[IPCTEST] S: PASS the seal took the lessor's write and the return gave it back");
    }
}

// ── Phase X: an expired lease is revoked with its lessor idle (LEASE3) ─────
//
// The timer interrupt only marks a lease expired; the kernel's lease worker
// removes what it still holds. X1: this task grants a lease that expires
// 300 ms ahead to a forked lessee and then does nothing lease-related (no
// wait, no free — it reaps the child on the clock). The lessee accepts with
// a mapping, writes, sleeps past the deadline, and writes again: that write
// must fault, be attributed to the revoked lease (selector 3) and kill it
// (139). X2: a forked lessor grants a SEALED self-lease expiring 200 ms ahead,
// accepts it, sleeps past the deadline without waiting or freeing, and
// writes its own mapping: the worker gave the write back, so it lands (0).
//
// Canary: `--features qemu,lease-expiry-worker-canary` leaves the worker's
// reap out: X1's lessee writes and exits 0, X2's lessor dies (139).

const X_EXPIRE_MS: u32 = 300;
const X_SEALED_EXPIRE_MS: u32 = 200;
/// How long past its deadline a party sleeps before it writes: ten ticks of
/// the slowest timer this test runs under, so the expiry and the worker's
/// reap have both run.
const X_SLACK_MS: u32 = 500;
const X_FIRST: u32 = 0x5831_0001;
const X_SECOND: u32 = 0x5831_0002;

fn phase_x_lessee(lessor: u32) -> ! {
    match sys::lease_accept_map(lessor) {
        Ok((_id, va)) => {
            let p = va as *mut u32;
            // SAFETY: the lease's mapping of a one-page RW region.
            unsafe { core::ptr::write_volatile(p, X_FIRST) };
            sys::sleep((X_EXPIRE_MS + X_SLACK_MS) as u64);
            // Past the deadline: this store must fault.
            unsafe { core::ptr::write_volatile(p.add(1), X_SECOND) };
            sys::exit(0);
        }
        Err(_) => sys::exit(3),
    }
}

fn phase_x_sealed() -> ! {
    let me = sys::getpid() as u32;
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    let va = if cap > 0 { sys::shm_map_typed(cap as u32) } else { -1 };
    if va <= 0 {
        sys::exit(3);
    }
    let deadline = ms_deadline(X_SEALED_EXPIRE_MS) as u64;
    let id = sys::lease_grant_flags(cap as u32, me, sys::LEASE_GRANT_SEAL, deadline);
    if id < 0 || sys::lease_accept(me) != id {
        sys::exit(4);
    }
    sys::sleep((X_SEALED_EXPIRE_MS + X_SLACK_MS) as u64);
    // The worker gave the write back at the expiry: this store must land.
    // SAFETY: this task's own mapping of a one-page RW region.
    unsafe { core::ptr::write_volatile(va as usize as *mut u32, X_SECOND) };
    sys::exit(0);
}

fn phase_x() {
    sys::println(b"[IPCTEST] X: an expired lease is revoked with its lessor idle");
    let me = sys::getpid() as u32;
    let faults0 = sys::exit_stats(sys::EXIT_STAT_LEASE_REVOKED_FAULTS);
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    let va = sys::shm_map_typed(cap as u32);
    expect_pos(b"X/lessor maps its region", va);
    if va <= 0 {
        return;
    }
    let base = va as usize as *mut u32;
    let cp = spawn(ROLE_X_LESSEE, me);
    let id = sys::lease_grant(cap as u32, cp as u32, ms_deadline(X_EXPIRE_MS) as u64);
    expect_true(b"X1/lease with a deadline granted to the lessee", cp > 0 && id >= 0, id);
    if cp > 0 && id >= 0 {
        // Idle as a lessor: no lease wait, no free, until the child is reaped.
        let st = reap_within(cp as u32, WAIT_MS);
        expect_eq(b"X1/lessee killed by its write after the expiry (status 139)",
            st.map(|s| s as isize).unwrap_or(-1), 139);
        // SAFETY: this task's own mapping of the region.
        let (w0, w1) = unsafe { (core::ptr::read_volatile(base), core::ptr::read_volatile(base.add(1))) };
        expect_true(b"X1/the write before the expiry landed", w0 == X_FIRST, w0 as isize);
        expect_true(b"X1/the write after the expiry did not land", w1 != X_SECOND, w1 as isize);
        let lc = sys::cap_lookup(sys::CapKind::Lease as u8, id as u32);
        if lc > 0 {
            expect_eq(b"X1/lease_wait afterwards -> expired", sys::lease_wait(lc as u32), 1);
        }
        expect_eq(b"X1/lease_free", sys::lease_free(id as u64), 0);
    }
    let faults1 = sys::exit_stats(sys::EXIT_STAT_LEASE_REVOKED_FAULTS);
    expect_eq(b"X1/the fault was attributed to the revoked lease", faults1 - faults0, 1);
    expect_eq(b"X/shm_release_typed", sys::shm_release_typed(cap as u32), 0);

    let cp = spawn(ROLE_X_SEALED, 0);
    let st = if cp > 0 { reap_within(cp as u32, WAIT_MS) } else { None };
    expect_eq(b"X2/sealed lessor writes after the expiry (status 0)",
        st.map(|s| s as isize).unwrap_or(-1), 0);
    if faults1 - faults0 == 1 && st == Some(0) {
        sys::println(b"[IPCTEST] X: PASS the lease worker revoked the expired lease");
    }
}

// ── Phase P: one port, several sources, one wait with a deadline ────────────
//
// Wave 11 (PORTWAIT): `SYS_PORT_WAIT_UNTIL_TYPED` (604) and the channel,
// io_ring and timer sources of `SYS_PORT_BIND_TYPED` (575). Phase H's shape,
// because a channel can reach a second task only by a capability MOVE (there
// is no duplicate): the server forks the client, so the client inherits a
// capability to the server's endpoint. The client (the waiter) creates a port
// and a channel, binds the channel and a far timer to the port, and moves the
// `Cap<Channel>` to the server with its call; the server answers, sleeps
// 30 ms and sends one message on the channel. The waiter, asleep in 604 by
// then, must wake with the channel's key. Then the timer: re-armed 100 ms
// ahead, it must be the next event, not before its deadline. Then a wait with
// nothing armed must answer 0 at its deadline, and an io_ring completion must
// be an event. The binding outlives the moved capability: the waiter keeps
// its port's source after the move (the kernel's documented semantics).
//
// Canary (`--features portwait-timer-canary`, kernel): a timer bind answers 0
// and arms nothing, and the timer check reads `FAIL  P/the timer source fired`
// after the 5 s outer deadline.

const TAG_P_SRV_TID: u8 = 28;
const TAG_P_SRV_SAW: u8 = 29;
const TAG_P_CLI: u8 = 30;

const P_REQ_TAG: u64 = 0x0050_0000;
const P_KEY_CHAN: u64 = 0xC4A1_0001;
const P_KEY_TIMER: u64 = 0x71AE_0002;
const P_KEY_RING: u64 = 0x2146_0003;
/// The outer deadline of the kernel-only waits in this phase (the timer's):
/// a source that never fires ends the wait here, with a FAIL line, never a
/// hang.
const P_OUTER_NS: u64 = 5_000_000_000;
/// The outer deadline of the channel wait, which needs the server task to be
/// scheduled: 15 s, below `WAIT_MS` so a starved run still reports the
/// specific verdict rather than `P/client reported at all`.
const P_CHAN_OUTER_NS: u64 = 15_000_000_000;

const P_SRV_ACCEPTED: u32 = 1;
const P_SRV_CAP_ARRIVED: u32 = 2;
const P_SRV_SENT: u32 = 4;

const P_CLI_SETUP: u32 = 1;
const P_CLI_CHANNEL: u32 = 2;
const P_CLI_TIMER: u32 = 4;
const P_CLI_TIMEOUT: u32 = 8;
const P_CLI_RING: u32 = 16;
const P_CLI_UNBIND: u32 = 32;

/// The event's `(key, source type)`.
fn p_event(ev: &[u8; sys::PORT_EVENT_BYTES]) -> (u64, u8) {
    let mut k = [0u8; 8];
    k.copy_from_slice(&ev[..8]);
    (u64::from_le_bytes(k), ev[8])
}

fn phase_p_server() -> ! {
    let me = sys::getpid();
    let ep = sys::endpoint_create_typed();
    note_own_endpoint(ep);
    if ep < 0 {
        post(TAG_P_SRV_TID, me as u32);
        post(TAG_P_SRV_SAW, 0);
        sys::exit(0);
    }
    let cp = spawn(ROLE_P_CLIENT, me as u32);
    post(TAG_P_SRV_TID, me as u32);
    if cp < 0 {
        post(TAG_P_SRV_SAW, 0);
        sys::exit(0);
    }
    let mut mask = 0u32;
    if let Some(req) = sys::fast_ipc_accept_req() {
        mask |= P_SRV_ACCEPTED;
        let chan = req.moved_cap;
        let arrived = req.delivered && req.words[0] == P_REQ_TAG && chan != sys::NO_CAP_TO_MOVE;
        sys::fast_ipc_reply(req.handle, [P_REQ_TAG + 1, 0, 0, 0]);
        if arrived {
            mask |= P_SRV_CAP_ARRIVED;
            // The client is asleep in 604 by now: the send must wake it.
            sys::sleep(30);
            if sys::chan_write_typed(chan, b"request") == 0 {
                mask |= P_SRV_SENT;
            }
        }
    }
    post(TAG_P_SRV_SAW, mask);
    // The client's verdict, posted after its waits.
    relay_one();
    sys::exit(0);
}

fn phase_p_client(immediate_parent: u32) -> ! {
    let mut mask = 0u32;
    let mut ev = [0u8; sys::PORT_EVENT_BYTES];
    let port = sys::port_create_typed();
    let chan = sys::chan_create_typed();
    let now = sys::vdso_now_ns();
    if port > 0 && chan > 0 && now > 0 {
        let (port, chan) = (port as u32, chan as u32);
        let b_chan = sys::port_bind_typed(port, sys::PORT_SRC_CHANNEL, chan, P_KEY_CHAN);
        let b_timer = sys::port_bind_timer(port, now.saturating_add(60_000_000_000), P_KEY_TIMER);
        let got = if b_chan == 0 && b_timer == 0 {
            sys::fast_ipc_call_ep_moving(inherited_endpoint_handle(), [P_REQ_TAG, 0, 0, 0], chan)
        } else {
            None
        };
        let mut l = Line::new();
        l.s(b"[IPCTEST] P: bind channel rc=").i(b_chan).s(b" bind timer rc=").i(b_timer);
        l.flush();
        if got.map(|w| w[0]) == Some(P_REQ_TAG + 1) {
            mask |= P_CLI_SETUP;

            // 1. Two sources bound (the channel, a timer 60 s out): the server's
            //    send wakes this task.
            let t0 = sys::vdso_now_ns();
            let rc = sys::port_wait_until_typed(port, &mut ev, t0.saturating_add(P_CHAN_OUTER_NS));
            let t1 = sys::vdso_now_ns();
            let (key, ty) = p_event(&ev);
            let mut l = Line::new();
            l.s(b"[IPCTEST] P: channel wait rc=").i(rc).s(b" type=").i(ty as isize)
                .s(b" key_ok=").i((key == P_KEY_CHAN) as isize)
                .s(b" waited_us=").i((t1.saturating_sub(t0) / 1_000) as isize);
            l.flush();
            if rc == sys::PORT_EVENT_BYTES as isize && key == P_KEY_CHAN && ty == sys::PORT_EVENT_CHANNEL {
                mask |= P_CLI_CHANNEL;
            }

            // 2. The timer, re-armed 100 ms ahead by its key: the next event,
            //    never before its deadline.
            let deadline = sys::vdso_now_ns().saturating_add(100_000_000);
            let b = sys::port_bind_timer(port, deadline, P_KEY_TIMER);
            let rc = sys::port_wait_until_typed(port, &mut ev, deadline.saturating_add(P_OUTER_NS));
            let t2 = sys::vdso_now_ns();
            let (key, ty) = p_event(&ev);
            let mut l = Line::new();
            l.s(b"[IPCTEST] P: timer wait bind=").i(b).s(b" rc=").i(rc).s(b" type=").i(ty as isize)
                .s(b" key_ok=").i((key == P_KEY_TIMER) as isize)
                .s(b" late_us=").i((t2 as i64 - deadline as i64) as isize / 1_000);
            l.flush();
            if b == 0 && rc == sys::PORT_EVENT_BYTES as isize && key == P_KEY_TIMER
                && ty == sys::PORT_EVENT_TIMER && t2 >= deadline
            {
                mask |= P_CLI_TIMER;
            }

            // 3. Nothing armed and nothing sent: 0 at the deadline.
            let deadline = sys::vdso_now_ns().saturating_add(50_000_000);
            let rc = sys::port_wait_until_typed(port, &mut ev, deadline);
            let t3 = sys::vdso_now_ns();
            let mut l = Line::new();
            l.s(b"[IPCTEST] P: timeout wait rc=").i(rc)
                .s(b" late_us=").i((t3 as i64 - deadline as i64) as isize / 1_000);
            l.flush();
            if rc == 0 && t3 >= deadline {
                mask |= P_CLI_TIMEOUT;
            }

            // 4. An io_ring completion, polled (a passed deadline).
            let mut va = [0u8; 8];
            let ring = sys::ioring_create_typed(&mut va);
            let va = u64::from_le_bytes(va) as usize;
            if ring > 0 && va != 0 {
                let ring = ring as u32;
                let b = sys::port_bind_typed(port, sys::PORT_SRC_RING, ring, P_KEY_RING);
                unsafe {
                    ring_put_sqe(va, 0, RING_OP_NOP, 0, 0, 0, 0x9);
                    core::ptr::write_volatile((va + RING_SQ_TAIL) as *mut u32, 1);
                }
                let sub = sys::ioring_submit_typed(ring);
                let rc = sys::port_wait_until_typed(port, &mut ev, 0);
                let (key, ty) = p_event(&ev);
                let mut l = Line::new();
                l.s(b"[IPCTEST] P: ring bind=").i(b).s(b" submit=").i(sub).s(b" poll rc=").i(rc)
                    .s(b" type=").i(ty as isize).s(b" key_ok=").i((key == P_KEY_RING) as isize);
                l.flush();
                if b == 0 && sub == 1 && rc == sys::PORT_EVENT_BYTES as isize
                    && key == P_KEY_RING && ty == sys::PORT_EVENT_RING
                {
                    mask |= P_CLI_RING;
                }
                let _ = sys::ioring_destroy_typed(ring);
            }

            // 5. Remove the channel by its key; a second remove finds nothing.
            if sys::port_unbind_typed(port, sys::PORT_SRC_CHANNEL, P_KEY_CHAN) == 0
                && sys::port_unbind_typed(port, sys::PORT_SRC_CHANNEL, P_KEY_CHAN) == E_ENOENT
            {
                mask |= P_CLI_UNBIND;
            }
        }
        let _ = sys::port_destroy_typed(port);
    }
    post_to(immediate_parent, TAG_P_CLI, mask);
    sys::exit(0);
}

fn phase_p() {
    sys::println(b"[IPCTEST] P: multi-source port wait (channel, timer, io_ring, deadline)");
    let sp = spawn(ROLE_P_SERVER, 0);
    if sp < 0 {
        expect_err(b"P/fork-server (unexpected failure)", sp);
        return;
    }
    if wait_tag(TAG_P_SRV_TID, WAIT_MS).is_none() {
        expect_true(b"P/server announced its TID", false, -1);
        return;
    }
    match wait_tag(TAG_P_SRV_SAW, WAIT_MS) {
        Some(m) => {
            expect_true(b"P/server accepted the call", m & P_SRV_ACCEPTED != 0, m as isize);
            expect_true(b"P/the Cap<Channel> arrived with the call", m & P_SRV_CAP_ARRIVED != 0, m as isize);
            expect_true(b"P/server sent on the moved channel", m & P_SRV_SENT != 0, m as isize);
        }
        None => expect_true(b"P/server reported at all", false, -1),
    }
    match wait_tag(TAG_P_CLI, WAIT_MS) {
        Some(m) => {
            expect_true(b"P/client bound a channel and a timer and moved the channel", m & P_CLI_SETUP != 0, m as isize);
            expect_true(b"P/the channel source woke the waiter", m & P_CLI_CHANNEL != 0, m as isize);
            expect_true(b"P/the timer source fired", m & P_CLI_TIMER != 0, m as isize);
            expect_true(b"P/an empty wait answered 0 at its deadline", m & P_CLI_TIMEOUT != 0, m as isize);
            expect_true(b"P/an io_ring completion is an event", m & P_CLI_RING != 0, m as isize);
            expect_true(b"P/a source is removed by its key", m & P_CLI_UNBIND != 0, m as isize);
        }
        None => expect_true(b"P/client reported at all", false, -1),
    }
}

// ── Phase F: a typed channel, from one task ─────────────────────────────────
//
// `Cap<Channel>` (573/528/529/566) is a fork-hostile capability — the child's
// table holds no runtime object of its parent's — so unlike the mailbox it cannot go child-to-parent. This
// exercises it in the parent alone: create, write a record, read it straight
// back, then close and confirm the handle is stale.

fn phase_f_channel() {
    sys::println(b"[IPCTEST] F: typed channel round trip");

    let cap = sys::chan_create_typed();
    expect_pos(b"F/chan_create_typed", cap);
    if cap <= 0 {
        return;
    }
    let cap = cap as u32;

    const MSG: &[u8] = b"IPCTEST-chan";
    // 528 answers `0` on success, not a byte count (`syscall_nr.rs`,
    // `sys_chan_write_typed`); the read below is what proves the bytes landed.
    expect_eq(b"F/chan_write_typed", sys::chan_write_typed(cap, MSG), 0);

    let mut buf = [0u8; 32];
    let n = sys::chan_read_typed(cap, &mut buf);
    expect_true(
        b"F/chan_read_typed returns the bytes written",
        n == MSG.len() as isize && &buf[..MSG.len()] == MSG,
        n,
    );

    // An empty channel reads back nothing; a closed one is stale.
    expect_eq(b"F/close_typed(channel)", sys::close_typed(cap), 0);
    expect_eq(b"F/chan_read_typed after close [stale]", sys::chan_read_typed(cap, &mut buf), E_ECAPSTALE);
}

// ── Phase L: lease IPC by capability (wave 9) ────────────────────────────────

const E_ECAPKIND: isize = -200;

/// The ABI of `SYS_IPC_LEASE_WAIT` (602) and `SYS_IPC_LEASE_GRANT_TYPED`
/// (603): a self-lease walked through its whole life. GRANT takes the
/// `Cap<Shm>` the region was created with (ring 3 is never told a raw region
/// id) and mints the `Cap<Lease>`, WAIT on a returned lease answers 0 at once,
/// a capability of another kind is `-ECAPKIND` to either call, FREE revokes the
/// `Cap<Lease>` (`-ECAPSTALE` after), and a grant on a released region's
/// capability is `-ECAPSTALE`.
fn phase_l_lease_abi() {
    sys::println(b"[IPCTEST] L: lease wait by Cap<Lease> (SYS_IPC_LEASE_WAIT)");
    let me = unsafe { PARENT_TID };
    let shm = sys::shm_create_typed(1, 1);
    expect_pos(b"L/shm_create_typed", shm);
    if shm <= 0 {
        return;
    }
    let id = sys::lease_grant(shm as u32, me, 0);
    expect_true(b"L/lease_grant(Cap<Shm>, to self)", id >= 0, id);
    if id < 0 {
        let _ = sys::shm_release_typed(shm as u32);
        return;
    }
    let cap = sys::cap_lookup(sys::CapKind::Lease as u8, id as u32);
    expect_pos(b"L/cap_lookup(Lease, lease id) [minted by the grant]", cap);
    expect_eq(b"L/lease_accept(self)", sys::lease_accept(me), id);
    expect_eq(b"L/lease_return", sys::lease_return(id as u64), 0);
    if cap > 0 {
        expect_eq(b"L/lease_wait(returned lease) -> 0", sys::lease_wait(cap as u32), 0);
    }
    expect_eq(b"L/lease_wait(Cap<Shm>) [kind]", sys::lease_wait(shm as u32), E_ECAPKIND);
    if cap > 0 {
        expect_eq(b"L/lease_grant(Cap<Lease>) [kind]", sys::lease_grant(cap as u32, me, 0), E_ECAPKIND);
    }
    expect_eq(b"L/lease_free", sys::lease_free(id as u64), 0);
    if cap > 0 {
        expect_eq(b"L/lease_wait after free [stale]", sys::lease_wait(cap as u32), E_ECAPSTALE);
    }
    expect_eq(b"L/shm_release_typed", sys::shm_release_typed(shm as u32), 0);
    expect_eq(b"L/lease_grant(released Cap<Shm>) [stale]", sys::lease_grant(shm as u32, me, 0), E_ECAPSTALE);
}

/// Phase L2: this task is the ring-3 LESSOR of `lease-pi3-smoke` (a kernel
/// feature; without it the kernel lessee's name is absent and the phase says
/// so and runs nothing). The kernel lessee runs at 24 behind a prio-20 hog on
/// its hart; only this task's `lease_wait` lending it 16 lets it accept and
/// return. The verdict is the kernel's `[LEASEPI3]` line; here the wait must
/// end with the lease returned (0).
fn phase_l2_lease_pi() {
    // The kernel lessee registers its name from a task of its own at boot;
    // give it a few seconds before concluding the feature is off.
    let mut lessee = -1;
    for _ in 0..30 {
        lessee = sys::service_discover(b"leasepi\0");
        if lessee > 0 {
            break;
        }
        sys::sleep(100);
    }
    if lessee <= 0 {
        sys::println(b"[IPCTEST] L2: no kernel lessee registered (lease-pi3-smoke off), skipped");
        return;
    }
    sys::println(b"[IPCTEST] L2: ring-3 lessor of the kernel lessee (lease priority inheritance)");
    let me = unsafe { PARENT_TID };
    expect_eq(b"L2/service_register(leasepi.lessor)",
              sys::service_register(b"leasepi.lessor\0", me as u64, 0), 0);
    let shm = sys::shm_create_typed(1, 1);
    expect_pos(b"L2/shm_create_typed", shm);
    if shm <= 0 {
        return;
    }
    let id = sys::lease_grant(shm as u32, lessee as u32, 0);
    expect_true(b"L2/lease_grant(to the kernel lessee)", id >= 0, id);
    if id >= 0 {
        let cap = sys::cap_lookup(sys::CapKind::Lease as u8, id as u32);
        expect_pos(b"L2/cap_lookup(Lease)", cap);
        if cap > 0 {
            expect_eq(b"L2/lease_wait -> returned", sys::lease_wait(cap as u32), 0);
        }
        expect_eq(b"L2/lease_free", sys::lease_free(id as u64), 0);
    }
    expect_eq(b"L2/shm_release_typed", sys::shm_release_typed(shm as u32), 0);
}

// ── Entry ───────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[IPCTEST] Starting - ring-3 IPC probe");

    // The parent's TID is the mailbox address every child posts to, and it
    // must be set before the first `fork()` so a child that starts before the
    // parent's next instruction still has it.
    let me = sys::getpid();
    if me <= 0 {
        let mut l = Line::new();
        l.s(b"[IPCTEST]  FAIL  getpid rc=").i(me);
        l.flush();
        sys::println(b"[IPCTEST] FAILED: 1 check(s)");
        sys::exit(1);
    }
    unsafe { PARENT_TID = me as u32 };
    unsafe { ROW_EP_COUNT = count_endpoints() };


    // First child: the heartbeat that bounds every blocking accept below.
    let hb = spawn(ROLE_HEARTBEAT, 0);
    expect_pos(b"0/heartbeat child forked", hb);

    // Phase A runs LAST, deliberately. It is expected to hang today (see the
    // header), and a hang ends the run: anything scheduled after it would
    // produce no verdict at all. Ordering the cheap, terminating phases first
    // means a wedged fast-IPC path costs one phase of coverage, not five.
    phase_l_lease_abi();
    phase_l2_lease_pi();
    fork_reg_canary();
    phase_b();
    phase_g_stale_reply_accept();
    phase_c_cycle();
    phase_c_window_reuse();
    phase_c_gates();
    phase_f_channel();
    phase_d();
    phase_e();
    phase_h();
    phase_r();
    phase_w();
    phase_s();
    phase_x();
    phase_p();
    phase_k_killed_waits();
    phase_a_race();

    let failed = unsafe { FAILURES };
    let total = unsafe { CHECKS };
    let mut l = Line::new();
    l.s(b"[IPCTEST] ").i(total as isize).s(b" check(s) run");
    l.flush();
    if failed == 0 {
        sys::println(b"[IPCTEST] ALL PASSED");
        sys::exit(0);
    } else {
        let mut l = Line::new();
        l.s(b"[IPCTEST] FAILED: ").i(failed as isize).s(b" check(s)");
        l.flush();
        sys::exit(1);
    }
}

// ── Phase K: a forced kill ends a task blocked anywhere (plan item 7) ──────
//
// Every per-client release (leases, ports, shared memory, fast-IPC slots,
// sockets, descriptors) runs from the exit hook, so a forced kill that leaves
// its target blocked releases nothing. The kill used to wake only `Timer`
// waits, and the notify, port, fast-IPC accept and sleep waits went back to
// sleep. Each child below blocks where nothing will ever wake it and must be
// reaped with `128 + K_SIGNO` within `K_REAP_MS`.
//
// One line for the gate rows: `[IPCTEST] killed waits: notify=137 ...`, -1
// for a child the kill never ended.
//
// Canaries (the unfixed kernel read -1 for all four):
// `kill-wake-timer-only-canary` -> port=-1 accept=-1 lease=-1;
// `kill-reblock-canary` -> all five -1. The lease wait (a lease that never
// expires, granted to a task that never accepts it) re-blocked after the
// kill's wake until `lease_wait_return_as` checked for the stop.

/// The signal phase K's kills carry: the reaped status is `128 + K_SIGNO`.
const K_SIGNO: u64 = 9;
/// How long a killed child may take to be reaped.
const K_REAP_MS: u32 = 3_000;
/// How long the parent lets a child reach its wait before the kill.
const K_SETTLE_MS: u64 = 50;
/// A child's exit code when its wait returned before the kill: it never
/// blocked, so its line proves nothing.
const K_NOT_BLOCKED: i32 = 0x33;

/// Fork a child that runs `block`, force-kill it, and return the status it
/// is reaped with (-1: still blocked; -2: no fork; -3: the kill refused).
fn k_kill_blocked(block: fn()) -> isize {
    let pid = sys::fork();
    if pid == 0 {
        block();
        sys::exit(K_NOT_BLOCKED);
    }
    if pid <= 0 {
        return -2;
    }
    sys::sleep(K_SETTLE_MS);
    if sys::task_kill(pid as u32, sys::KILL_FORCE, K_SIGNO, 0) < 0 {
        return -3;
    }
    match reap_within(pid as u32, K_REAP_MS) {
        Some(st) => st as isize,
        None => -1,
    }
}

fn k_block_notify() {
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    let va = if cap >= 0 { sys::shm_map_typed(cap as u32) } else { -1 };
    if va > 0 {
        let _ = sys::notify_wait(va as usize, 0, sys::NOTIFY_FOREVER);
    }
}

fn k_block_port() {
    let p = sys::port_create_typed();
    if p >= 0 {
        let mut ev = [0u8; sys::PORT_EVENT_BYTES];
        let _ = sys::port_wait_typed(p as u32, &mut ev);
    }
}

fn k_block_accept() {
    let _ = sys::fast_ipc_accept_req();
}

fn k_block_sleep() {
    sys::sleep(30_000);
}

/// The TID phase K's lease child grants its lease to (the ipctest task,
/// which never accepts it): set before the fork, read by the child.
static K_LESSEE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Grant a lease that never expires to a task that never accepts it and wait
/// for its return (`SYS_IPC_LEASE_WAIT`): nothing ends this wait but the kill.
fn k_block_lease() {
    let shm = sys::shm_create_typed(1, sys::SHM_RW);
    if shm < 0 || sys::shm_map_typed(shm as u32) <= 0 {
        return;
    }
    let id = sys::lease_grant(shm as u32, K_LESSEE.load(core::sync::atomic::Ordering::Relaxed), 0);
    let lc = if id >= 0 { sys::cap_lookup(sys::CapKind::Lease as u8, id as u32) } else { -1 };
    if lc > 0 {
        let _ = sys::lease_wait(lc as u32);
    }
}

fn phase_k_killed_waits() {
    let want = 128 + K_SIGNO as isize;
    let notify = k_kill_blocked(k_block_notify);
    let port = k_kill_blocked(k_block_port);
    let accept = k_kill_blocked(k_block_accept);
    let sleep = k_kill_blocked(k_block_sleep);
    K_LESSEE.store(sys::getpid() as u32, core::sync::atomic::Ordering::Relaxed);
    let lease = k_kill_blocked(k_block_lease);
    let mut l = Line::new();
    l.s(b"[IPCTEST] killed waits: notify=").i(notify).s(b" port=").i(port)
        .s(b" accept=").i(accept).s(b" sleep=").i(sleep).s(b" lease=").i(lease);
    l.flush();
    expect_eq(b"K/a forced kill ends a notify_wait with no deadline", notify, want);
    expect_eq(b"K/a forced kill ends a port wait with no deadline", port, want);
    expect_eq(b"K/a forced kill ends an idle fast-IPC accept", accept, want);
    expect_eq(b"K/a forced kill ends a sleep", sleep, want);
    expect_eq(b"K/a forced kill ends a lease wait nobody answers", lease, want);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::println(b"[IPCTEST] FAIL panic");
    sys::exit(101);
}
