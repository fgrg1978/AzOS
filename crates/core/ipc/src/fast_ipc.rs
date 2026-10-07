// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Fast-path IPC — seL4-style register-passing (M02).
///
/// Transfers up to 32 bytes (4 × u64) between two tasks without touching
/// user-space memory or allocating any kernel buffer.  Data lives in a
/// slot drawn from one global pool of `FAST_IPC_MAX_SLOTS` entries (NOT one
/// slot per task — the pool is shared board-wide, which is why
/// `fast_ipc_release_all` matters), written by the sender and read by the
/// receiver after a minimal scheduler wakeup.
///
/// ## Protocol (as actually implemented by `syscall::dispatch`)
///
/// Caller (client):
///   SYS_IPC_FAST_CALL(server_tid, d0, d1, d2, d3)
///     → places {d0..d3} in a slot targeting `server_tid`
///     → donates its priority to the server for the span of the call when it
///       is more urgent than the server's base priority (see
///       [`fast_ipc_call_donating`]; the reply, the client's withdrawal or the
///       exit sweep returns it, exactly once)
///     → blocks self (WaitReason::FastIpcClient(slot_idx))
///     → wakes when the server calls FAST_REPLY
///     → returns: word 0 of the reply, or -1 (no slot / dead server /
///       bad target) meaning "fall back to channel IPC"
///
/// Server:
///   SYS_IPC_FAST_ACCEPT()
///     → blocks until a client calls FAST_CALL targeting this task
///     → **returns a `handle`**, not the caller TID and no longer a bare slot
///       index: the handle is `slot_index | generation << 6` — see
///       [`fast_ipc_make_handle`]. The request words come back in a1..a5.
///
///   SYS_IPC_FAST_REPLY(handle, d0, d1, d2, d3)
///     → `a0` is the **handle** from FAST_ACCEPT, not a TID and not a raw index
///     → the replier's TID and privilege come from the current task, not from
///       user registers — see [`fast_ipc_reply`]
///     → places {d0..d3} in the slot, wakes the caller
///     → returns 0, or a negative code if the reply was rejected (non-blocking
///       either way) — see [`FastIpcReply`]
///
/// ## Guarantees
/// - No heap allocation, no copy_from_user, no ring buffer.
/// - Maximum 32 bytes per message.
/// - Single-writer: only the designated sender fills a slot. This was an
///   aspiration until IPC-1; [`fast_ipc_reply`] now enforces it.
/// - The slot is NOT thread-safe for concurrent senders to the same server;
///   callers must coordinate at a higher level (or use channels instead).

#[cfg(target_os = "none")]
use azos_sync::SpinLock;
#[cfg(not(target_os = "none"))]
use self::host_seam::SpinLock;

/// Is this hart inside an interrupt handler? — through the same seam as
/// `SpinLock`, and for the same reason: `azos_sync` and `azos_arch`
/// are RV64-only, and this file is `#[path]`-pulled into `crates/ipc-fast-
/// tests` to run its embedded tests on the host.
///
/// Adding the probe without routing it through here broke that crate's build
/// — the third time this session a new dependency inside a `#[path]`-pulled
/// file did. **Anything new referenced from this file needs a seam entry.**
///
/// The host answers `false`: `cargo test` has no interrupts, so there is no
/// hazard to detect, and a stand-in that reported otherwise would make the
/// counter's tests test the stand-in.
#[cfg(target_os = "none")]
#[inline(always)]
fn in_isr_now() -> bool {
    azos_sync::isr_depth::in_isr(azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
fn in_isr_now() -> bool { false }

// ---------------------------------------------------------------------------
// Scheduler seam
// ---------------------------------------------------------------------------
//
// The kernel build uses `sched_seam` below, whose two functions are
// `#[inline(always)]` one-liners over `azos_sched`: after inlining the
// seam is not in the binary at all, so it costs nothing on the fast path.
//
// **WHY it exists.** `azos_sync` and `azos_sched` are RV64-only —
// `azos_sync::SpinLock` alone fails to build for the host with
// `unresolved import azos_arch::csr`. The house pattern for testing an
// `ipc` module (see `tests/host/cap-tests`) is to pull the file in with `#[path]`
// and run its embedded `#[cfg(test)] mod tests`, which is impossible while the
// module names those crates unconditionally.
//
// The switch is `target_os = "none"`, **not** `cfg(test)`: `cargo test` builds
// the crate twice — once plain, once with `cfg(test)` — and the plain build
// would still have to resolve `azos_sync`. Every kernel target this tree
// builds (`riscv64imac-unknown-none-elf`, the VF2 and K1 variants) is
// `target_os = "none"`, so the host substitutes below are unreachable from any
// build that can run on a board.

// Wave 15 (TRACE): the ipc class's tracepoints, behind the same switch: the
// host build of this file has no tracer (and no `.config` to read one from).
#[cfg(target_os = "none")]
use azos_trace as trace_seam;
#[cfg(not(target_os = "none"))]
mod trace_seam {
    pub fn ipc_on() -> bool { false }
    pub fn ipc_call(_caller: u32, _server: u32, _label: u32) {}
    pub mod raw {
        pub fn ipc_reply(_server: u32, _caller: u32, _status: u32) {}
    }
}

#[cfg(target_os = "none")]
mod sched_seam {
    /// Whether `tid` names a live task, and its task slot — so the fast-IPC
    /// donation reuses this lookup instead of making its own (wave 11
    /// PIFAST; it was a `bool` `tid_exists` before). See
    /// [`super::fast_ipc_call`] for the cost and the race this accepts.
    #[inline(always)]
    pub fn tid_idx(tid: u32) -> Option<usize> {
        azos_sched::idx_for_tid(tid)
    }
    /// Wave 11 PIFAST: lend the current task's priority to task slot `idx`
    /// (TID `tid`) for a fast call; `true` = one return is owed.
    #[inline(always)]
    pub fn donate_for_call(idx: usize, tid: u32) -> bool {
        azos_sched::scheduler::donate_priority_for_call_at(idx, tid)
    }
    /// U04-2 route (b): `tid_exists` alone passes while the server's exit hook
    /// has already run but the slot has not yet been freed. `TASK_EXITING` is
    /// published before that hook runs, so this closes the window a fresh
    /// call could otherwise fall into.
    #[inline(always)]
    pub fn tid_is_exiting(tid: u32) -> bool {
        azos_sched::tid_is_exiting(tid)
    }
    #[inline(always)]
    pub fn wake_client(handle: u64) {
        azos_sched::wake_fast_ipc_client(handle);
    }
    /// Parent of the task on THIS hart right now — for
    /// [`super::fast_ipc_tid_dest_for`], the CALL-direction authority check
    /// `SYS_IPC_FAST_CALL` (108) never had (RFC-0040 gap 2). `fast_ipc_call`
    /// only ever runs synchronously inside the caller's own syscall, so "the
    /// task on this hart right now" IS the caller — same fact
    /// `current_task_tid` relies on. O(1): `current_task_parent_tid` reads
    /// the same per-CPU `current_idx` cache, no `idx_for_tid` scan.
    #[inline(always)]
    pub fn current_parent_tid() -> u32 {
        azos_sched::current_task_parent_tid()
    }
    /// Destroy a capability that was moved with a message which will now never
    /// be delivered. See [`super::fast_ipc_release_all`] for when, and why it
    /// is a revoke rather than a return.
    #[inline(always)]
    pub fn revoke_moved(server_tid: u32, handle: u32) {
        crate::cap_store::revoke_moved(
            server_tid,
            azos_abi::cap::CapHandle(handle),
        );
    }
    /// Return one fast-IPC priority donation (wave 11 PIFAST) — the exit
    /// sweep's half; the reply and the client's withdrawal return theirs in
    /// `syscall::dispatch`.
    #[inline(always)]
    pub fn return_donation(target: u32) {
        azos_sched::return_donation(target);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent fast IPC slots (one per potential caller).
pub const FAST_IPC_MAX_SLOTS: usize = 64;

/// "No donation rides on this exchange" in a slot's `donee` field and in
/// [`FastIpcReply::Woke`]. `u32::MAX` is never a TID (`NEXT_TID` skips it, and
/// it is already the free-slot sentinel above).
pub const NO_DONEE: u32 = u32::MAX;

/// Maximum number of 64-bit words in a fast IPC message.
pub const FAST_IPC_MAX_WORDS: usize = 4;

/// `moved_cap` for an exchange that carries no capability.
///
/// RFC-0040 gap 2 stage 4. Named rather than written as a bare `0` at every
/// call site, because a fourth positional zero next to a TID and a word array
/// reads as another id, not as "no capability rode along".
pub const NO_CAP: u32 = 0;

/// Sentinel TID value meaning "slot is free".
const FAST_IPC_SLOT_FREE: u32 = u32::MAX;

// ── Server handle encoding (slot ABA) ──────────────────────────────────────
//
// **WHY a handle and not the bare slot index.** The index alone identifies a
// *slot*, never the *exchange* that was occupying it when the server accepted.
// Concretely: server S accepts client A's slot 5; A dies;
// `fast_ipc_release_all` frees slot 5; client B calls S and lands on slot 5; S
// accepts it. If S now replies with the index it was still holding for A, that
// reply passes both surviving checks — the slot is `Accepted` and S really is
// its `server_tid` — and **B collects the answer that was meant for A**. The
// ownership check from IPC-1 confines the damage to that server's own clients;
// it does not remove it.
//
// The handle names the tenancy, not the seat: index in the low bits, a
// per-slot generation counter above it, and the generation is bumped every
// time the slot is freed (`FastIpcState::free_slot`). A handle issued for
// tenancy N therefore stops matching the moment tenancy N ends, whether the
// slot is re-let or left empty.
//
// **The split, and what it costs.** `a0` carries the handle to ring 3 as an
// `i64` whose negative half is already spoken for by the error codes, so 63
// bits are usable. 6 of them index the 64 slots exactly; the remaining 57 are
// generation. Encode and decode are a shift, a mask and an or — no lookup, no
// second lock, nothing added to the critical section that was already being
// taken. That matters: the measured syscall floor here is 1879 ns/op and this
// is the path the kernel exists to make fast.
//
// **When the ABA comes back.** At 2^57 = 144_115_188_075_855_872 reuses *of
// one slot* the generation wraps and an ancient handle can match again. One
// reuse per nanosecond — faster than an instruction retires on this class of
// core — still needs about 4.5 years of doing nothing else. It is documented,
// tested (`generation_wrap_reopens_aba_the_documented_residual`) and accepted,
// not overlooked.

/// Bits of the handle that carry the slot index. 64 slots need exactly 6.
pub const FAST_IPC_SLOT_BITS: u32 = 6;

/// Mask for the slot-index field of a handle.
pub const FAST_IPC_SLOT_MASK: u64 = (1u64 << FAST_IPC_SLOT_BITS) - 1;

/// Mask for the generation field of a handle, **after** shifting it down.
///
/// 57 bits: 63 usable (bit 63 stays clear so every handle is a non-negative
/// `i64`) minus the 6 spent on the index.
pub const FAST_IPC_GEN_MASK: u64 = (1u64 << (63 - FAST_IPC_SLOT_BITS)) - 1;

// If `FAST_IPC_MAX_SLOTS` ever grows past what `FAST_IPC_SLOT_BITS` can
// address, indices would alias into the generation field and two different
// slots would share handles — silently. Fail the build instead.
const _: () = assert!(FAST_IPC_MAX_SLOTS <= (1usize << FAST_IPC_SLOT_BITS));

/// Build the ring-3 handle for `(slot_idx, generation)`.
///
/// Total by construction: both fields are masked, so no input panics and no
/// input can set bit 63. Exposed because `libsys` has to be able to state the
/// same layout, and one shared definition is cheaper than two that drift.
#[inline(always)]
pub const fn fast_ipc_make_handle(slot_idx: usize, generation: u64) -> u64 {
    ((generation & FAST_IPC_GEN_MASK) << FAST_IPC_SLOT_BITS)
        | ((slot_idx as u64) & FAST_IPC_SLOT_MASK)
}

/// Slot index carried by `handle`, or `None` if it does not name a real slot.
///
/// Pure arithmetic over a value ring 3 chose: it reads no table and reveals
/// nothing. It is here so that a caller which wants to *log* or *label* an
/// exchange (`libsys`'s `FastRequest.slot`, the census printers) does not have
/// to re-derive the layout and get it subtly different from this file.
///
/// **Bit 63 must be clear.** Every handle this file issues is a non-negative
/// `i64`, because that is the half of `a0` that is not already spoken for by
/// the error codes. Ignoring the bit instead of rejecting it would make
/// `h` and `h | 1<<63` the same handle, so a server that stored a negative
/// return value and later handed *that* back could land on a live slot
/// (`1<<63` alone decodes to index 0, generation 0). One compare turns that
/// whole class into a refusal.
#[inline(always)]
pub const fn fast_ipc_handle_slot(handle: u64) -> Option<usize> {
    if handle > i64::MAX as u64 {
        return None;
    }
    let idx = (handle & FAST_IPC_SLOT_MASK) as usize;
    if idx < FAST_IPC_MAX_SLOTS { Some(idx) } else { None }
}

/// Generation carried by `handle`. Same reasoning as [`fast_ipc_handle_slot`].
#[inline(always)]
const fn handle_generation(handle: u64) -> u64 {
    (handle >> FAST_IPC_SLOT_BITS) & FAST_IPC_GEN_MASK
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// State of a fast IPC slot.
///
/// **WHY `Accepted` is its own state (IPC-2).** `fast_ipc_accept` used to set
/// `Replied` with the comment "temporarily reuse state to mark accepted",
/// while `words` still held the *request*. `find_reply_for_caller` matches
/// exactly on `Replied`, so any wakeup of the client between accept and reply
/// — a server that accepts and then dies, or any spurious wake — made the
/// client collect its own request and treat it as the server's answer. No
/// attacker required. The three states must stay distinct: `Pending` is
/// "unclaimed work" (only `find_pending_for_server` matches it, so a second
/// accept cannot steal a claimed slot), `Accepted` is "claimed, no answer
/// yet" (matched by nothing), `Replied` is "answer present" (only
/// `find_reply_for_caller` matches it). Collapse any two and the confusion
/// above comes back.
#[derive(Clone, Copy, PartialEq)]
// `Debug` only off-board: it exists so host tests can name the state in an
// assertion failure, and there is no reason to hand the kernel binary a
// formatting impl for it.
#[cfg_attr(not(target_os = "none"), derive(Debug))]
enum SlotState {
    /// Slot is unused.
    Free,
    /// Caller has deposited data; waiting for server to accept.
    Pending,
    /// Server has claimed the call; `words` still holds the *request* and no
    /// reply exists yet. Deliberately matched by neither lookup helper.
    Accepted,
    /// Server has deposited reply; waiting for caller to collect.
    Replied,
}

/// One pending fast IPC exchange.
#[derive(Clone, Copy)]
struct FastIpcSlot {
    /// TID of the caller (client).
    caller_tid: u32,
    /// TID of the server this call is targeting.
    server_tid: u32,
    /// Message data (up to 4 × u64 = 32 bytes).
    words: [u64; FAST_IPC_MAX_WORDS],
    /// Slot lifecycle state.
    state: SlotState,
    /// Handle the capability moved with this message took in the SERVER's
    /// table, or `0` for an exchange that moved none.
    ///
    /// RFC-0040 gap 2 stage 4. **It is a record, not a pending action.** The
    /// move already happened, in the caller's own trap, before this slot became
    /// `Pending` — see `crates/core/syscall/src/dispatch.rs`. Putting it here means
    /// the accept can report the handle without doing any capability work, so
    /// an accept can never fail because of a capability.
    ///
    /// Held as an opaque `u32` on purpose: this file must not name
    /// `cap_store`. A handle is generation-tagged and never zero, so `0`
    /// reads as "none" with no separate flag.
    moved_cap: u32,
    /// Tenancy counter, bumped by [`FastIpcState::free_slot`] and by nothing
    /// else. It is the only field that must **survive** the wipe a free does:
    /// zero it and every handle the previous tenant handed out becomes valid
    /// again, which is exactly the ABA this field exists to close. Held masked
    /// to `FAST_IPC_GEN_MASK` so encoding is lossless.
    generation: u64,
    /// The task the caller's priority was donated to for this exchange
    /// (wave 11 PIFAST), or [`NO_DONEE`]. Written once by `alloc_slot`, in the
    /// same publish as the request, and TAKEN (reset to `NO_DONEE`) by
    /// whichever retires the exchange first: the reply (`reply_locked`; a
    /// reply that hands off puts it back for the client, see
    /// `fast_ipc_reply_then_accept`), the client's collect
    /// (`fast_ipc_collect_donated`), the client giving up
    /// (`fast_ipc_withdraw_donation`) or the exit sweep
    /// (`fast_ipc_release_all`). All run under `FAST_IPC`, so exactly one of
    /// them returns the donation; `free_slot` clears it with the rest.
    donee: u32,
}

impl FastIpcSlot {
    const fn empty() -> Self {
        FastIpcSlot {
            caller_tid: FAST_IPC_SLOT_FREE,
            server_tid: FAST_IPC_SLOT_FREE,
            words: [0u64; FAST_IPC_MAX_WORDS],
            state: SlotState::Free,
            moved_cap: 0,
            generation: 0,
            donee: NO_DONEE,
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

struct FastIpcState {
    slots: [FastIpcSlot; FAST_IPC_MAX_SLOTS],
    /// Number of slots currently in use (for quick-reject).
    used: u32,
    /// How many slots are `Pending` right now: the requests no server has taken.
    ///
    /// Exists so an `accept` with nothing to take answers in one comparison. It
    /// used to scan all `FAST_IPC_MAX_SLOTS` (64, ~384 instructions) to learn
    /// that, and a server that has just replied is exactly in that position: its
    /// own exchange still sits in the table as `Replied`, so `used != 0` and the
    /// cheap `used == 0` exit never applied. Measured 2026-09-18 with the
    /// per-block plugin profile: `fast_ipc_accept` was the largest single term of
    /// an IPC round trip (631 of ~3,700 instructions, run twice per exchange).
    ///
    /// **It is a cache of a count the slots already hold, so it must equal that
    /// count at every point the lock is released.** The only three things that
    /// change a slot's `Pending`-ness are `alloc_slot` (+1), `mark_accepted`
    /// (-1) and `free_slot` of a `Pending` slot (-1), and each is the only writer
    /// on its path. `pending_matches_the_slots` states the invariant in a test.
    pending: u32,
}

impl FastIpcState {
    const fn new() -> Self {
        FastIpcState {
            slots: [FastIpcSlot::empty(); FAST_IPC_MAX_SLOTS],
            used: 0,
            pending: 0,
        }
    }

    fn alloc_slot(
        &mut self,
        caller: u32,
        server: u32,
        words: [u64; FAST_IPC_MAX_WORDS],
        moved_cap: u32,
        donee: u32,
    ) -> Option<usize> {
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.state == SlotState::Free {
                // Carry the generation across the overwrite. This whole-struct
                // assignment is the easier of the two places to forget it —
                // `free_slot` at least looks like it is doing something to the
                // counter, this one looks like plain initialisation. Dropping
                // it here would reset every freshly allocated slot to
                // generation 0 and reopen the ABA on the very next reuse.
                let generation = s.generation;
                *s = FastIpcSlot {
                    caller_tid: caller,
                    server_tid: server,
                    words,
                    state: SlotState::Pending,
                    moved_cap,
                    generation,
                    donee,
                };
                self.used += 1;
                self.pending += 1;
                return Some(i);
            }
        }
        None
    }

    /// `Pending` -> `Accepted`: the server has taken the request and owes a reply.
    /// The only place a `Pending` slot stops being one except `free_slot`.
    fn mark_accepted(&mut self, idx: usize) {
        if let Some(s) = self.slots.get_mut(idx) {
            if s.state == SlotState::Pending {
                self.pending = self.pending.saturating_sub(1);
            }
            s.state = SlotState::Accepted;
        }
    }

    fn find_pending_for_server(&self, server_tid: u32) -> Option<usize> {
        // Early-exit when nothing is pending. `used` was the test before, and a
        // server that had just replied (its own exchange still `Replied` in the
        // table) never took it, so every such accept scanned all 64 slots to
        // find nothing. `pending` is maintained on the three transitions that
        // change it; see its field doc.
        if self.pending == 0 { return None; }
        self.slots.iter().position(|s| s.state == SlotState::Pending && s.server_tid == server_tid)
    }

    /// Identify the slot `handle` names, but only if it is still `caller_tid`'s
    /// and it is sitting `Replied` — i.e. this exact exchange has an answer
    /// waiting. See the fix note above [`fast_ipc_collect`] for why this is
    /// keyed on the handle and not a caller-wide scan.
    fn find_reply_for_caller(&self, handle: u64, caller_tid: u32) -> Option<usize> {
        if self.used == 0 { return None; }
        let slot_idx = fast_ipc_handle_slot(handle)?;
        let slot = self.slots.get(slot_idx)?;
        if slot.state == SlotState::Replied
            && slot.caller_tid == caller_tid
            && slot.generation == handle_generation(handle)
        {
            Some(slot_idx)
        } else {
            None
        }
    }

    /// Body of [`fast_ipc_accept`], under a lock the caller holds.
    #[inline(always)]
    fn accept_locked(
        &mut self,
        server_tid: u32,
    ) -> Option<(u64, u32, [u64; FAST_IPC_MAX_WORDS], u32)> {
        let idx = self.find_pending_for_server(server_tid)?;
        let slot = self.slots.get(idx)?;
        let caller = slot.caller_tid;
        let words = slot.words;
        let moved_cap = slot.moved_cap;
        let handle = fast_ipc_make_handle(idx, slot.generation);
        // Keep the slot alive — the server still owes a reply on it. `Accepted`,
        // not `Replied`: `words` still holds the request at this point, and
        // `Replied` is the state `find_reply_for_caller` hands to the client.
        // See `SlotState` for the confusion this separation prevents.
        self.mark_accepted(idx);
        Some((handle, caller, words, moved_cap))
    }

    /// Body of [`fast_ipc_reply`], under a lock the caller holds, and the
    /// ipc class's reply record (wave 15; no instruction when compiled out):
    /// `[replier, caller (0 unless delivered), status 0 delivered / 1 stale
    /// / 2 refused]`.
    #[inline(always)]
    fn reply_locked(
        &mut self,
        handle: u64,
        replier_tid: u32,
        privileged: bool,
        words: [u64; FAST_IPC_MAX_WORDS],
    ) -> FastIpcReply {
        let r = self.reply_locked_body(handle, replier_tid, privileged, words);
        if trace_seam::ipc_on() {
            let (caller, status) = match r {
                FastIpcReply::Woke { caller_tid, .. } => (caller_tid, 0),
                FastIpcReply::Stale => (0, 1),
                FastIpcReply::Refused => (0, 2),
            };
            trace_seam::raw::ipc_reply(replier_tid, caller, status);
        }
        r
    }

    /// The checks and the deposit of [`Self::reply_locked`]. The check order
    /// (state, ownership, generation last) is `FastIpcReply`'s.
    #[inline(always)]
    fn reply_locked_body(
        &mut self,
        handle: u64,
        replier_tid: u32,
        privileged: bool,
        words: [u64; FAST_IPC_MAX_WORDS],
    ) -> FastIpcReply {
        let slot_idx = match fast_ipc_handle_slot(handle) {
            Some(i) => i,
            None => return FastIpcReply::Refused,
        };
        // `get_mut` and not `[slot_idx]`: the decode above already bounds the
        // index, but the no-panic property stays local to the access rather than
        // depending on a check made somewhere else that someone may later move.
        let slot = match self.slots.get_mut(slot_idx) {
            Some(s) => s,
            None => return FastIpcReply::Refused,
        };
        if slot.state != SlotState::Accepted {
            return FastIpcReply::Refused;
        }
        if !privileged && slot.server_tid != replier_tid {
            return FastIpcReply::Refused;
        }
        // Last, and that ordering is part of the design — see `FastIpcReply`.
        if slot.generation != handle_generation(handle) {
            return FastIpcReply::Stale;
        }
        let caller = slot.caller_tid;
        slot.words = words;
        slot.state = SlotState::Replied;
        // The answer ends the call, so the donation ends here: taken now, by
        // the replier, not when the client next runs — a server answering
        // with plain REPLY keeps running and must not keep the client's
        // priority while it does.
        let donee = core::mem::replace(&mut slot.donee, NO_DONEE);
        FastIpcReply::Woke { caller_tid: caller, slot_idx, donee }
    }

    fn free_slot(&mut self, idx: usize) {
        // `get_mut` rather than `[idx]`: with `panic = "abort"` an out-of-range
        // index is a board reset, i.e. a physical-safety event on a robot. Keep
        // the no-panic property local to the access instead of depending on a
        // bounds check made by whichever caller happens to be in fashion.
        if let Some(s) = self.slots.get_mut(idx) {
            // Ending the tenancy is what retires every handle issued for it.
            // Bump *here*, not in `alloc_slot`, so a handle dies the instant
            // its exchange does — even if the slot is never re-let.
            //
            // `wrapping_add` and not `+`: `overflow-checks = true` in this
            // tree, so the plain add would be a panic at the wrap, and
            // `panic = "abort"` makes a panic a board reset. Wrapping is also
            // the *correct* arithmetic — this is a tag, not a count, and the
            // mask keeps it inside the 57 bits the handle can carry.
            let next = s.generation.wrapping_add(1) & FAST_IPC_GEN_MASK;
            if s.state == SlotState::Pending {
                self.pending = self.pending.saturating_sub(1);
            }
            *s = FastIpcSlot::empty();
            s.generation = next;
            self.used = self.used.saturating_sub(1);
        }
    }
}

static FAST_IPC: SpinLock<FastIpcState> = SpinLock::new(FastIpcState::new());

/// Times `FAST_IPC` was taken with local interrupts already masked.
///
/// **Must stay zero**, and the gate asserts it. Owner decision 2026-09-20
/// (scan unit 4): detect the violation rather than mask against it.
///
/// # The hazard this watches
///
/// `FAST_IPC` is taken with a plain `.lock()` at every one of its sites, while
/// its peer `PORTS` in this same crate uses `lock_irqsave()` at all of its —
/// and `PORTS` says why: an ISR that takes a lock a task already holds on the
/// same hart deadlocks that hart, forever. `task_exit_with_code` calls the
/// exit hook, which reaches `fast_ipc_release_all`, with `sstatus.SIE` still
/// **enabled**, so the window is genuinely open.
///
/// It is safe today — verified, not assumed: the only callers are syscall
/// dispatch, `sched/wait.rs`, the exit hook and a diagnostic *task*. No
/// interrupt handler reaches `fast_ipc_*`. What was missing is anything that
/// would notice the day one did.
///
/// **What this does and does not buy.** It does not close the deadlock: a
/// violating ISR still wedges the hart. It makes the violation *visible in the
/// gate* before it reaches a board, which is the whole of what was asked for
/// — masking would have cost interrupt latency on the hottest path in the
/// system, including a 64-slot scan in `find_pending_for_server`.
///
/// # The probe, and the one that did not work
///
/// `isr_depth` is set by the trap handler's interrupt arm, because only that
/// arm knows it is an interrupt.
///
/// The obvious probe — `sstatus.SIE == 0` — was written first and was wrong:
/// RISC-V hardware clears `SIE` on **every** trap entry, exception as well as
/// interrupt, so it is the normal state of every syscall handler here. It
/// reported 149, 16 and 162 violations on a clean boot, one per IPC call and
/// not an interrupt among them. Measuring the instrument, not the hazard.
static FAST_IPC_IRQ_CTX: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// See [`FAST_IPC_IRQ_CTX`].
#[must_use]
pub fn fast_ipc_irq_ctx_violations() -> u32 {
    FAST_IPC_IRQ_CTX.load(core::sync::atomic::Ordering::Relaxed)
}

/// The ONE place `FAST_IPC` is taken, so the check cannot be forgotten at a
/// fourteenth site. Every `lock_fast_ipc()` in this file goes through here.
#[inline]
fn lock_fast_ipc() -> impl core::ops::DerefMut<Target = FastIpcState> {
    if in_isr_now() {
        FAST_IPC_IRQ_CTX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    FAST_IPC.lock()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// `raw_tid` back, if it names the CALLING task's own parent — the authority
/// check `SYS_IPC_FAST_CALL` (108) never had (RFC-0040 gap 2, the CALL
/// direction). `None` otherwise.
///
/// **Why parent, and not a capability.** `SYS_IPC_FAST_CALL_EP` (582) already
/// has a full authority check: [`crate::endpoint::endpoint_dest_for`] resolves
/// a `Cap<Endpoint>` the caller holds, with `WRITE`, naming a live served
/// endpoint. 108 takes a raw TID in `a0` with nothing behind it — no
/// capability exists to check, because the ABI never gave it one. The
/// narrowest fix available without minting one is the relation `fork` already
/// grants for free: every surviving 108 caller in `userspace/tests/ipctest`
/// (`post`, `heartbeat_main`, `phase_a_client`, and now `phase_b_client` /
/// `phase_e_client` relayed through their own parent — see those two for why)
/// addresses its own parent. Widening this past parent (e.g. to any
/// ancestor) is an authority-model decision this function does not make.
///
/// **O(1), no scan, no lock.** [`sched_seam::current_parent_tid`] reads the
/// same per-CPU `current_idx` cache `current_task_tid` does — not
/// `idx_for_tid`, which is what `fast_ipc_call` below still pays for
/// `server_tid` (a check this function makes unnecessary for 108's caller,
/// since a parent TID is always a real, live task by construction, but
/// `fast_ipc_call` cannot tell which path called it and still needs that
/// check for 582's capability-resolved TID).
///
/// **One refusal, same convention `endpoint_dest_for` established.** "Not my
/// parent" and "no parent recorded" (root, or a child whose link `note_exit`
/// already cleared) collapse into the same `None` — which of the two would
/// report on a relationship the caller does not hold authority over.
pub fn fast_ipc_tid_dest_for(raw_tid: u32) -> Option<u32> {
    let parent = sched_seam::current_parent_tid();
    if parent != 0 && raw_tid == parent {
        Some(raw_tid)
    } else {
        None
    }
}

/// Called when a client issues SYS_IPC_FAST_CALL.
///
/// Deposits the message into a slot targeting `server_tid`.
/// Returns Some(slot_idx) if the slot was allocated (caller should then block).
/// Returns None if no free slots (caller should fall back to channel IPC).
///
/// **WHY the target is validated (IPC-5).** `server_tid` arrives raw in `a0`.
/// A call aimed at a TID that does not exist used to succeed: it burned a slot,
/// woke nobody, and blocked the caller forever. Ring 3 could therefore exhaust
/// all 64 slots with 64 syscalls, after which every `fast_ipc_call` returns
/// `None` for the life of the board and the fast path is dead — silently, since
/// dispatch's documented answer to `None` is "-1, fall back to channel IPC".
///
/// **Cost of the check, stated plainly.** `idx_for_tid` is an O(`MAX_TASKS`)
/// = O(64) linear scan of the `TASKS`/`TASK_VALID` statics with *no*
/// synchronisation, so it can run against another hart creating or destroying
/// a task and its answer is advisory, not authoritative. That is accepted on
/// purpose: the TOCTOU cannot be closed here, because holding `FAST_IPC` does
/// not freeze task creation either, and the only damage a lost race can do is
/// leak one slot — which `fast_ipc_release_all` reclaims when the task dies.
/// The scan runs *before* the lock is taken so the hot critical section stays
/// as short as it was and no lock-ordering question arises at all.
pub fn fast_ipc_call(
    caller_tid: u32,
    server_tid: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    moved_cap: u32,
) -> Option<u64> {
    fast_ipc_call_donating(caller_tid, server_tid, words, moved_cap, false)
}

/// [`fast_ipc_call`], lending the caller's priority to the server for the
/// span of the call when `donate` is set (wave 11 PIFAST, RFC-0052 §4.7).
///
/// The donation (`azos_sched::scheduler::donate_priority_for_call_at`,
/// through the seam) is made after the target checks, on the task slot the
/// existence check already found — one TID lookup for both — and BEFORE the
/// slot is published, and the target is recorded in the slot in the same hold
/// of `FAST_IPC`, for the reason `moved_cap` is: a server woken on the slot
/// can accept and reply on another hart before this one runs its next
/// instruction, so a mark written after the publish could be missed by the
/// reply meant to return it. The boost itself runs outside `FAST_IPC` (it
/// takes the target's donation lock and a run-queue lock). On `None` nothing
/// is owed: a donation made for a call that found no free slot is returned
/// here.
pub fn fast_ipc_call_donating(
    caller_tid: u32,
    server_tid: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    moved_cap: u32,
    donate: bool,
) -> Option<u64> {
    // Wave 15 (TRACE): the ipc class's call record, `[caller, server, word 0]`.
    trace_seam::ipc_call(caller_tid, server_tid, words[0] as u32);
    // Self-call is an immediate self-deadlock: the caller blocks waiting for a
    // reply only it could send, and the slot is leaked until it is killed.
    // O(1) to reject, so reject.
    if caller_tid == server_tid {
        return None;
    }
    // Also rejects the `FAST_IPC_SLOT_FREE` sentinel, which is not a live TID.
    let server_idx = match sched_seam::tid_idx(server_tid) {
        Some(i) => i,
        None => return None,
    };
    // U04-2 route (b): `tid_exists` passes for a server whose exit hook has
    // already run but whose task-pool slot is not freed yet — `TASK_EXITING`
    // is published before that hook runs, so this catches the window
    // `tid_exists` alone cannot. Refusing here means the client never
    // allocates a slot nobody will ever answer.
    if sched_seam::tid_is_exiting(server_tid) {
        return None;
    }
    let donee = if donate && sched_seam::donate_for_call(server_idx, server_tid) {
        server_tid
    } else {
        NO_DONEE
    };
    let handle = {
        let mut state = lock_fast_ipc();
        state.alloc_slot(caller_tid, server_tid, words, moved_cap, donee).and_then(|idx| {
            // The CLIENT's handle for this exchange — same encoding, and
            // (because the generation only advances on free) the same VALUE
            // the server's accept will mint. The client blocks on
            // `WaitReason::FastIpcClient(handle)`, so a wake for exchange N
            // can never be confused with exchange N+1 in the same seat: this
            // is the client-side half of the slot-ABA closure (the
            // server-side half is `fast_ipc_reply`'s generation check).
            state.slots.get(idx).map(|s| fast_ipc_make_handle(idx, s.generation))
        })
    };
    if handle.is_none() && donee != NO_DONEE {
        sched_seam::return_donation(donee);
    }
    handle
}

/// Called when a server issues SYS_IPC_FAST_ACCEPT.
///
/// Returns `Some((handle, caller_tid, words))` if a pending call exists for
/// this server; `None` if no call is pending (server should block).
///
/// **`handle`, not `slot_idx`.** It names *this* exchange, not the seat the
/// exchange happens to be sitting in — see the handle-encoding note above for
/// the ABA that a bare index cannot survive. The server hands it straight back
/// to [`fast_ipc_reply`]; it is opaque, and the only supported thing to do
/// with it besides replying is [`fast_ipc_handle_slot`] for logging.
pub fn fast_ipc_accept(
    server_tid: u32,
) -> Option<(u64, u32, [u64; FAST_IPC_MAX_WORDS], u32)> {
    lock_fast_ipc().accept_locked(server_tid)
}

/// Outcome of [`fast_ipc_reply`].
///
/// **`Stale` and `Refused` are NOT a partition of "rejected".** Read them as:
/// `Stale` is *sufficient* proof that the exchange the handle named is over
/// and will never be answerable — the server can drop its bookkeeping for it
/// with certainty. `Refused` proves nothing beyond "not now": a handle whose
/// slot has already been re-let to a *different* server, or re-let and not yet
/// accepted, fails an earlier check and reports `Refused` even though it is
/// just as dead. Anyone who inverts this — treating `Refused` as "handle still
/// good, retry later" — is reading a guarantee that was never made.
///
/// **Why the check order is load-bearing.** `Stale` is only reachable *after*
/// the state and ownership checks have passed, i.e. only by the slot's current
/// legitimate server (or a privileged task). Reordered so that generation is
/// tested first, this variant would become a generation oracle: any ring-3
/// task could sweep 64 indices, binary-search the generation of each, and read
/// off how often every slot on the board has turned over — activity it has no
/// part in. That is the same hole `fast_ipc_wait_state` documents and refuses
/// to open, and the reasoning there applies verbatim here.
#[derive(Clone, Copy, PartialEq, Eq)]
// `Debug` only off-board, same reasoning as `SlotState`.
#[cfg_attr(not(target_os = "none"), derive(Debug))]
pub enum FastIpcReply {
    /// Reply deposited. Wake `caller_tid`, which is blocked on
    /// `WaitReason::FastIpcClient(slot_idx)`.
    ///
    /// `slot_idx` is returned rather than left for the caller to decode out of
    /// the handle on purpose: the client-side wait reason is keyed on the raw
    /// index, and dispatch re-deriving it would be a second implementation of
    /// this file's encoding, free to drift from it.
    ///
    /// `donee` is the task the caller's priority was donated to for this
    /// exchange, or [`NO_DONEE`]: the replier owes exactly one
    /// `return_donation(donee)`, after `FAST_IPC` is dropped. It is the TID
    /// recorded at the call, not the replier — a privileged replier may
    /// answer a slot whose server is another task.
    Woke { caller_tid: u32, slot_idx: usize, donee: u32 },
    /// The handle is well-formed and its slot is currently this server's, but
    /// the generation is from an earlier tenancy: the exchange it named ended
    /// (the client died, or it was already completed and collected) and the
    /// slot has since been re-let. **Nothing was written.** This is the ABA the
    /// generation tag exists to catch; before it, this reply would have been
    /// delivered to whoever is in the slot now.
    Stale,
    /// Rejected for any other reason: the handle is not one this file could
    /// have issued (sign bit set, or an index outside the table), the slot is
    /// free, the slot is not `Accepted` (never accepted, or already answered),
    /// or the replier is not the slot's server.
    Refused,
}

/// Called when a server issues SYS_IPC_FAST_REPLY.
///
/// Deposits the reply into the slot and transitions state so the caller can
/// collect it. See [`FastIpcReply`] for the three outcomes and for why
/// `Refused` must not be read as "try again".
///
/// `handle` is the value [`fast_ipc_accept`] returned, taken raw from `a0`.
/// Every one of the 2^64 bit patterns is a legal *input*: decode is a compare
/// and two masks, and anything that does not name a live tenancy is `Refused`
/// or `Stale`, never a panic. With `panic = "abort"` a reachable panic here is
/// a board reset, i.e. a physical-safety event on a robot.
///
/// `replier_tid` is the TID of the task actually making the syscall and
/// `privileged` is true for kernel tasks (`current_user_pt() == 0`), which
/// skip the ownership check — the house convention, same as `cap_store`'s
/// typed callers.
///
/// **WHY the ownership check exists (IPC-1).** The handle arrives raw in `a0`
/// and its index field is only 0..63, so walking it is 64 syscalls. Before this
/// check `server_tid` was written by `alloc_slot` and never read for
/// authorisation: any ring-3 task could reply on a slot it never accepted,
/// impersonating an arbitrary IPC server and waking that server's client with
/// data of the attacker's choosing — the client has no way to tell. The check
/// runs *inside* the lock that was already being taken, so there is no TOCTOU
/// window against a concurrent `accept`/`release` and it costs no extra lock.
///
/// The `Accepted` requirement is the second half of the same fix: replying to
/// a call you never accepted is meaningless, and it also blocks a "reply
/// twice" that would overwrite a reply already deposited but not yet
/// collected.
///
/// **WHY the generation check exists (slot ABA).** `server_tid` proves *who*
/// may answer; it cannot prove *what* is being answered. Server S accepts
/// client A's slot, A dies, `fast_ipc_release_all` frees the slot, client B
/// calls S and lands on the same index, S accepts. A reply from S carrying the
/// index it still held for A passed both checks above — the slot is `Accepted`
/// and S is its server — and B collected the answer meant for A. One extra
/// comparison against a counter S never sees closes it.
///
/// **`privileged` skips the ownership check and NEVER the generation check.**
/// The two are different questions. Ownership is authorisation, and the house
/// convention is that kernel tasks are trusted with it. The generation is not
/// authorisation at all, it is the identity of the exchange: a kernel server
/// holding a handle to an exchange that ended is just as wrong about reality
/// as a user one, and letting it write would corrupt whichever client is in
/// the slot now. "Privileged bypasses the checks" is precisely the sentence a
/// later reader will over-apply — it bypasses one named check, not the concept.
pub fn fast_ipc_reply(
    handle: u64,
    replier_tid: u32,
    privileged: bool,
    words: [u64; FAST_IPC_MAX_WORDS],
) -> FastIpcReply {
    lock_fast_ipc().reply_locked(handle, replier_tid, privileged, words)
}

/// [`fast_ipc_reply`] and, only when that delivered, [`fast_ipc_accept`] for
/// `server_tid` — in ONE hold of `FAST_IPC` instead of two.
///
/// `SYS_IPC_FAST_REPLY_ACCEPT` is the only caller. Nothing is woken here: the
/// reply's client wake is the caller's, after this returns and the lock is
/// dropped (never wake or block holding `FAST_IPC` — the switched-to task may
/// take it first thing). The accept half runs only after `Woke`, exactly as
/// the arm always ran it only after a delivered reply; its answer is `None`
/// for every other outcome.
pub fn fast_ipc_reply_then_accept(
    handle: u64,
    replier_tid: u32,
    privileged: bool,
    words: [u64; FAST_IPC_MAX_WORDS],
    server_tid: u32,
) -> (FastIpcReply, Option<(u64, u32, [u64; FAST_IPC_MAX_WORDS], u32)>) {
    let mut state = lock_fast_ipc();
    let mut r = state.reply_locked(handle, replier_tid, privileged, words);
    let next = match r {
        FastIpcReply::Woke { .. } => state.accept_locked(server_tid),
        FastIpcReply::Stale | FastIpcReply::Refused => None,
    };
    // Wave 11 PIFAST: with no next request the server is about to hand the
    // hart to its client and block (`fast_ipc_reply_handoff`), so the
    // donation goes back into the replied slot and the CLIENT returns it when
    // it collects — first thing after the switch, with the server already
    // asleep. Had the server returned it here, it would drop to its own
    // priority while the client is still blocked, and a tick in the few
    // instructions before the hand-off hands the hart to whatever sits between
    // them, with the reply deposited and nobody awake to read it (measured:
    // one 1.36 s call in 1000 on riscv64, the boot's bench sweep). With a next
    // request already taken there is no hand-off: the server wakes the client
    // and then returns the donation itself (`syscall::dispatch`).
    if let FastIpcReply::Woke { slot_idx, donee, .. } = &mut r {
        if next.is_none() && *donee != NO_DONEE {
            if let Some(s) = state.slots.get_mut(*slot_idx) {
                s.donee = core::mem::replace(donee, NO_DONEE);
            }
        }
    }
    (r, next)
}

/// Called after the caller wakes from blocking.
///
/// Returns the reply words and frees the slot.
///
/// **WHY this is keyed on `handle`, not just `caller_tid` (exchange-identity
/// fix, 2026-09-03).** This used to scan the whole table for *any* `Replied`
/// slot owned by `caller_tid` and return the first one `position()` found —
/// correct only under the assumption that a client has at most one
/// outstanding fast call. That assumption does not hold: `syscall::dispatch`'s
/// SYS_IPC_FAST_CALL retry loop bounds itself at `MAX_SPURIOUS_WAKES` turns
/// and returns -1 to ring 3 without freeing the slot if the server has not
/// replied by then — the slot sits `Replied` later, owned by a caller that has
/// moved on. Nothing stops that task from issuing a second fast call; when its
/// server also replies, the table holds two `Replied` slots for the same
/// `caller_tid` and the old scan handed back whichever sorted first — silently
/// delivering a stale exchange's payload as if it were the answer to a live
/// one, over an IPC path that carries motor commands. See
/// `a_stale_reply_is_never_handed_to_a_newer_exchange` for the reproduction.
///
/// The fix is the same identity `fast_ipc_reply` and `fast_ipc_wait_state`
/// already use: the handle names the exchange (slot index + generation), so
/// decoding it and checking that one slot is O(1) and exact — no scan, and no
/// way to land on a different exchange's reply even if one is sitting right
/// next to it in the table.
pub fn fast_ipc_collect(handle: u64, caller_tid: u32) -> Option<[u64; FAST_IPC_MAX_WORDS]> {
    fast_ipc_collect_donated(handle, caller_tid).map(|(w, _)| w)
}

/// [`fast_ipc_collect`], also handing back the donation the reply left in
/// the slot for the client to return ([`fast_ipc_reply_then_accept`] with no
/// next request), or [`NO_DONEE`]. The kernel's call arm uses this one; the
/// plain form drops that second value and is for callers that never donate.
pub fn fast_ipc_collect_donated(
    handle: u64,
    caller_tid: u32,
) -> Option<([u64; FAST_IPC_MAX_WORDS], u32)> {
    let mut state = lock_fast_ipc();
    let idx = state.find_reply_for_caller(handle, caller_tid)?;
    let slot = state.slots.get(idx)?;
    let (words, donee) = (slot.words, slot.donee);
    state.free_slot(idx);
    Some((words, donee))
}

/// Answer to "should I block again, or give up?" — see [`fast_ipc_wait_state`].
#[derive(Clone, Copy, PartialEq, Eq)]
// `Debug` only off-board, same reasoning as `SlotState`.
#[cfg_attr(not(target_os = "none"), derive(Debug))]
pub enum FastIpcWait {
    /// The slot is not this caller's any more: free, or re-allocated to a
    /// different client. Blocking again would sleep forever — give up and
    /// return the "-1, fall back to channel IPC" answer.
    Gone,
    /// The slot is still this caller's and the server has not replied yet
    /// (`Pending` or `Accepted`). A wake seen in this state is spurious;
    /// blocking again is correct and will not be lost.
    Waiting,
    /// The reply is deposited. `fast_ipc_collect` will succeed.
    Ready,
}

/// Classify a blocked client's slot: O(1), one lock acquisition, no scan.
///
/// **WHY this exists.** The scheduler's `wake_pending` seal closes the lost
/// wakeup at the cost of admitting spurious ones, so a client can return from
/// `task_block` with no reply waiting. `fast_ipc_collect` alone cannot tell the
/// two survivable outcomes apart — it returns `None` both when the wake was
/// spurious (slot alive, must block again) and when the server died and
/// `fast_ipc_release_all` reclaimed the slot (blocking again sleeps forever).
/// Guessing either way is worse than the false `-1` the retry loop is meant to
/// remove: guess `Waiting` on a dead slot and ring 3 hangs permanently; guess
/// `Gone` on a live one and a perfectly good exchange is thrown away.
///
/// **WHY it takes `caller_tid` and not just the index (IPC-1, again).** An
/// index-only probe would be a state oracle over the whole 64-slot table:
/// walking 0..63 would leak which servers have work in flight and when a reply
/// lands, for slots the prober has no part in. A slot that is alive but owned
/// by somebody else reads as `Gone` — indistinguishable, from the prober's
/// side, from a slot that does not exist. That is the same shape of check
/// `fast_ipc_reply` makes, and it must not be relaxed to "index is in range":
/// doing so reopens IPC-1 through the back door.
///
/// **Interaction with the ABA hazard.** The *server* side of it is closed: the
/// handle `fast_ipc_accept` issues carries a generation and `fast_ipc_reply`
/// rejects a stale one. The **client** side is tagged too since 2026-08-23:
/// `fast_ipc_call` returns the generation-tagged handle, the client blocks on
/// `WaitReason::FastIpcClient(handle)` (now a `u64` in `sched`), and this
/// accessor takes the handle and verifies the generation — so a seat re-let
/// since the client's exchange answers `Gone` even in the one case the old
/// containment could not see through (a slot re-allocated to a *recycled*
/// TID equal to the caller's). The `caller_tid` check stays as the cheaper
/// first filter and as defence in depth.
///
/// `fast_ipc_collect` takes the same `(handle, caller_tid)` pair and applies
/// the identical ownership-then-generation check — the assumption that used
/// to justify treating them asymmetrically ("a client has at most one
/// outstanding fast call") does not hold once the SYS_IPC_FAST_CALL retry loop
/// can bail out with a slot still live; see the fix note on
/// `fast_ipc_collect` for the reachable case this closes.
pub fn fast_ipc_wait_state(handle: u64, caller_tid: u32) -> FastIpcWait {
    // Decode rejects bit 63 and out-of-range indices — `Gone`, never a panic
    // (`panic = "abort"` makes a bad value from ring 3 a board reset).
    let slot_idx = match fast_ipc_handle_slot(handle) {
        Some(i) => i,
        None => return FastIpcWait::Gone,
    };
    let state = lock_fast_ipc();
    let slot = match state.slots.get(slot_idx) {
        Some(s) => s,
        None => return FastIpcWait::Gone,
    };
    // Ownership before state: a slot belonging to anyone else must be
    // indistinguishable from an empty one. `Free` slots carry
    // `FAST_IPC_SLOT_FREE` in `caller_tid`, so the state test is what stops a
    // caller whose TID somehow equals the sentinel from reading free slots.
    if slot.state == SlotState::Free || slot.caller_tid != caller_tid {
        return FastIpcWait::Gone;
    }
    // Generation LAST, after ownership — same ordering rule as
    // `fast_ipc_reply`, and here it is not even observable (wrong generation
    // and wrong owner both answer `Gone`), so no oracle either way. A stale
    // generation means the seat was re-let since this client's exchange: the
    // slot in front of us is someone else's, and `Gone` is the answer that
    // sends the retry loop to its clean -1 exit instead of back to sleep on
    // another exchange's future.
    if slot.generation != handle_generation(handle) {
        return FastIpcWait::Gone;
    }
    match slot.state {
        SlotState::Replied => FastIpcWait::Ready,
        // Pending and Accepted are both "server still owes an answer". Free is
        // unreachable here, and mapping it to Gone is the conservative answer.
        SlotState::Pending | SlotState::Accepted => FastIpcWait::Waiting,
        SlotState::Free => FastIpcWait::Gone,
    }
}

/// Take back the donation riding on the caller's own exchange `handle`, if it
/// is still there: the client is leaving the call without a reply (the retry
/// loop exhausted its turns, or found the slot gone). Returns the task the
/// caller owes one `return_donation` to, or [`NO_DONEE`].
///
/// Same identity check as [`fast_ipc_wait_state`] — ownership, then
/// generation. Any live state: `Pending`/`Accepted` (the server may still
/// answer; that reply then finds `NO_DONEE` and returns nothing), or
/// `Replied` with the donation left for the client
/// ([`fast_ipc_reply_then_accept`]) when the retry loop ran out on the very
/// turn the reply landed. A slot that is free or someone else's has nothing
/// of this caller's.
pub fn fast_ipc_withdraw_donation(handle: u64, caller_tid: u32) -> u32 {
    let slot_idx = match fast_ipc_handle_slot(handle) {
        Some(i) => i,
        None => return NO_DONEE,
    };
    let mut state = lock_fast_ipc();
    let slot = match state.slots.get_mut(slot_idx) {
        Some(s) => s,
        None => return NO_DONEE,
    };
    if slot.state == SlotState::Free
        || slot.caller_tid != caller_tid
        || slot.generation != handle_generation(handle)
    {
        return NO_DONEE;
    }
    core::mem::replace(&mut slot.donee, NO_DONEE)
}

/// Release every fast IPC slot in which `tid` is either endpoint — called from
/// the task-exit hook.
///
/// **WHY the exit hook must do this (IPC-3).** Nothing used to reclaim these
/// slots. There are 64 of them and they are global, not per-task, so any task
/// that dies mid-exchange burns one permanently. Once all 64 are gone
/// `fast_ipc_call` returns `None` forever, dispatch answers `-1`, and `-1`'s
/// documented meaning is "fall back to channel IPC" — so the fast path this
/// kernel exists to optimise dies silently, everything still *works*, and no
/// test anywhere goes red. That silence is the defect, more than the leak.
///
/// **Dying client.** Just free the slot. A `Pending` slot removed before the
/// server accepted it merely withdraws work; a server woken for a call that is
/// no longer there gets `None` from `fast_ipc_accept` and returns `-1`.
///
/// **Dying server that already replied** (`Replied`): the slot is left alone.
/// It belongs to the client at that point — see the inline note below for the
/// completed-exchange regression that skipping it prevents.
///
/// **Dying server with a client still blocked** (`Pending` or `Accepted`) is
/// the case that needs a decision: the client is asleep on
/// `WaitReason::FastIpcClient(idx)` waiting for a reply that can never come, so
/// freeing the slot and walking away leaves it asleep for the life of the
/// board. We free the slot and then wake the client by slot index.
///
/// Free-then-wake, with no synthetic error payload, is deliberate. The client
/// resumes inside the `SYS_IPC_FAST_CALL` arm, calls `fast_ipc_collect`, finds
/// no `Replied` slot for its TID, and dispatch returns `-1` — exactly the
/// "no fast path available, use a channel" answer the ABI already documents.
/// Manufacturing a `Replied` slot with an error sentinel would instead invent
/// a second convention *and* hand the client a word pattern it could mistake
/// for data. There is nothing to mistake here.
///
/// The waking is done **after** the lock is dropped. Not for deadlock reasons
/// — `try_wake_task` takes run-queue locks and never `FAST_IPC`, so there is no
/// cycle — but because holding the hottest lock in the IPC path across a
/// run-queue lock would put scheduler contention on every fast IPC operation.
///
/// The old residual here — the wake landing on a *different* client that
/// re-allocated the index between the free and the wake — is CLOSED by the
/// client-side handle (2026-08-23): the orphan wake below carries the
/// pre-free generation, the sleeping client is blocked on exactly that
/// handle, and a new tenant of the seat is blocked on a different one, so
/// the wake matches the dead exchange's owner or nobody. No spurious -1 for
/// bystanders anymore.
///
/// What *has* changed: the free below bumps the slot's generation, so any
/// handle the dying server was still holding for this slot is retired here and
/// `fast_ipc_reply` will answer `FastIpcReply::Stale` for it rather than
/// writing into whatever exchange takes the slot next.
///
/// Returns the number of slots freed (diagnostic; callers may ignore it).
pub fn fast_ipc_release_all(tid: u32) -> usize {
    // Handles (generation-tagged) whose blocked client must be woken.
    // Fixed-size, on the stack, bounded by the table itself — no heap in
    // this kernel.
    let mut orphaned = [0u64; FAST_IPC_MAX_SLOTS];
    let mut orphan_n = 0usize;
    let mut freed = 0usize;
    // RFC-0040 gap 2 stage 4: `(server_tid, handle)` of capabilities moved
    // with a request that is about to be thrown away. Same shape as
    // `orphaned` and for the same reason — collected under the lock, acted on
    // after it is dropped.
    let mut stranded = [(0u32, 0u32); FAST_IPC_MAX_SLOTS];
    let mut stranded_n = 0usize;
    // Wave 11 PIFAST: donations riding on exchanges this exit throws away.
    // A dying CLIENT's donation goes back to its server here (nobody else is
    // left to return it, and the server would otherwise keep the dead
    // client's priority for good). A dying SERVER's own boost is not
    // returned: the target is the task being torn down, and its pool slot
    // zeroes `donation_count` when it is reused.
    let mut undonate = [0u32; FAST_IPC_MAX_SLOTS];
    let mut undonate_n = 0usize;

    {
        let mut state = lock_fast_ipc();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            let (is_caller, is_server, live) = match state.slots.get(idx) {
                Some(s) => (
                    s.caller_tid == tid,
                    s.server_tid == tid,
                    s.state != SlotState::Free,
                ),
                None => continue,
            };
            if !live || !(is_caller || is_server) {
                continue;
            }
            if is_server && !is_caller {
                // A slot already in `Replied` is the *client's* property: the
                // answer is deposited, the client has been woken, and the
                // dying server owes nothing more. Reclaiming it here would
                // turn a completed exchange into a spurious -1 every time a
                // server replies and then exits — the ordinary one-shot
                // service pattern, and deterministic on a single hart because
                // the woken client cannot run until the server yields. The
                // client's own `fast_ipc_collect` frees it; if the client dies
                // first, `fast_ipc_release_all(caller)` does.
                if state.slots.get(idx).map(|s| s.state) == Some(SlotState::Replied) {
                    continue;
                }
                // Otherwise the client is blocked on an answer that will never
                // come, so it must be woken after the slot is freed. Capture
                // the handle with the PRE-free generation — `free_slot` bumps
                // it, and the sleeping client is blocked on the handle of the
                // exchange that just died, not on whatever the seat becomes
                // next.
                if let Some(o) = orphaned.get_mut(orphan_n) {
                    let gen = state.slots.get(idx).map(|s| s.generation).unwrap_or(0);
                    *o = fast_ipc_make_handle(idx, gen);
                    orphan_n += 1;
                }
            }
            // A capability moved with this request is in the SERVER's table
            // already — the move happened in the caller's trap, before the
            // slot was `Pending`. Freeing a `Pending` slot means the request
            // will never be delivered, so that authority now belongs to
            // nothing.
            //
            // **Revoked, not returned.** The sender is the reason this slot is
            // being freed: either it died, or the server did and its whole
            // table goes with it. There is nobody to move it back to, and
            // leaving a server holding authority for a message it was never
            // told about is the failure this arm exists to prevent. `Accepted`
            // and `Replied` slots are untouched — there the server HAS seen
            // the request, and the capability is legitimately its own.
            if let Some(sl) = state.slots.get(idx) {
                if sl.state == SlotState::Pending && sl.moved_cap != 0 {
                    if let Some(e) = stranded.get_mut(stranded_n) {
                        *e = (sl.server_tid, sl.moved_cap);
                        stranded_n += 1;
                    }
                }
            }
            if let Some(sl) = state.slots.get(idx) {
                if sl.donee != NO_DONEE && sl.donee != tid {
                    if let Some(e) = undonate.get_mut(undonate_n) {
                        *e = sl.donee;
                        undonate_n += 1;
                    }
                }
            }
            state.free_slot(idx);
            freed += 1;
        }
    } // lock dropped before touching the scheduler — see doc above.

    for i in 0..undonate_n {
        if let Some(&t) = undonate.get(i) {
            sched_seam::return_donation(t);
        }
    }

    // Outside the lock, as the wakes below are: `revoke_moved` takes a cap
    // table lock, and taking one inside `FAST_IPC` would put it in the
    // critical section of the hottest lock in the kernel.
    for i in 0..stranded_n {
        if let Some(&(server_tid, handle)) = stranded.get(i) {
            sched_seam::revoke_moved(server_tid, handle);
        }
    }

    for i in 0..orphan_n {
        if let Some(&handle) = orphaned.get(i) {
            sched_seam::wake_client(handle);
        }
    }

    freed
}

/// Census of the slot table by state, for diagnosing a wedged exchange.
///
/// Returns `(pending, accepted, replied)`.
///
/// **WHY this exists.** When a fast-IPC exchange wedges, the client is blocked
/// on `FastIpcClient(slot)` and the server on `FastIpcServer(tid)` — and those
/// two states look identical in a log whether the slot is `Pending` (the server
/// lost the wake) or `Accepted` (the server took the call and never answered).
/// They are different bugs with different fixes, and nothing else in the tree
/// tells them apart. `ipc-trace` cannot: it is six UART writes per exchange, so
/// it perturbs the timing enough to hide the race entirely — measured, the
/// traced build passes 8/8 where the untraced one wedges.
///
/// Three counters read under one lock, called at most every few seconds from a
/// diagnostic task, is cheap enough not to move the race.
pub fn fast_ipc_census() -> (u32, u32, u32, u32) {
    let state = lock_fast_ipc();
    let mut pending = 0u32;
    let mut accepted = 0u32;
    let mut replied = 0u32;
    for s in state.slots.iter() {
        match s.state {
            SlotState::Pending  => pending  += 1,
            SlotState::Accepted => accepted += 1,
            SlotState::Replied  => replied  += 1,
            SlotState::Free     => {}
        }
    }
    // `used` is reported alongside the real counts on purpose. Both lookup
    // helpers early-exit on `used == 0`, so a `used` that has drifted below the
    // true occupancy makes live slots **invisible**: `fast_ipc_collect` would
    // answer `None` for a reply that is sitting right there, and the client
    // would go back to sleep on it. `used != pending + accepted + replied` is
    // therefore not a cosmetic discrepancy, it is that exact bug.
    (pending, accepted, replied, state.used)
}

/// Identify every non-free slot: `(idx, state_code, caller_tid, server_tid)`,
/// written into `out`, returning how many were filled.
///
/// State codes: 1 = Pending, 2 = Accepted, 3 = Replied.
///
/// **WHY identities and not just counts.** A census that says "one reply is
/// waiting and one client is asleep" is consistent with two opposite stories:
/// the sleeping client is the one the reply belongs to (a lost wake), or it is
/// a *different* client and the reply belongs to someone who already moved on.
/// Only the identities separate them, and every counter so far has said the
/// wake path is clean — so the premise that they match is the one left to test.
pub fn fast_ipc_slot_ids(out: &mut [(u8, u8, u32, u32)]) -> usize {
    let state = lock_fast_ipc();
    let mut n = 0usize;
    for (i, s) in state.slots.iter().enumerate() {
        if n >= out.len() { break; }
        let code = match s.state {
            SlotState::Free     => continue,
            SlotState::Pending  => 1u8,
            SlotState::Accepted => 2u8,
            SlotState::Replied  => 3u8,
        };
        out[n] = (i as u8, code, s.caller_tid, s.server_tid);
        n += 1;
    }
    n
}

/// Count currently active fast IPC slots (diagnostic).
pub fn fast_ipc_active() -> u32 {
    lock_fast_ipc().used
}

// ===========================================================================
// Host-test scaffolding — off-board only, never in the kernel binary.
// ===========================================================================

/// Host substitutes for the RV64-only crates this module names.
///
/// Compiled **only** off-board (`not(target_os = "none")`), so nothing here can
/// reach a board. See the seam note near the top of the file for why the
/// substitution is needed at all.
///
/// `allow(dead_code)`: the inspection helpers are used by `mod tests`, which is
/// `cfg(test)`, so the plain host lib build sees them unused. This allow must
/// stay scoped to this module — the kernel build has no `allow` anywhere near
/// it and warnings are failures there.
#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
mod host_seam {
    use core::cell::UnsafeCell;
    use core::ops::{Deref, DerefMut};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Stand-in for `azos_sync::SpinLock` with the same surface used here
    /// (`new`, `lock`, deref). A real spin lock rather than a no-op: `cargo
    /// test` runs test functions on parallel threads against the same
    /// `static FAST_IPC`, so the lock has to actually work.
    pub struct SpinLock<T> {
        locked: AtomicBool,
        data: UnsafeCell<T>,
    }
    unsafe impl<T: Send> Sync for SpinLock<T> {}
    unsafe impl<T: Send> Send for SpinLock<T> {}

    impl<T> SpinLock<T> {
        pub const fn new(v: T) -> Self {
            SpinLock { locked: AtomicBool::new(false), data: UnsafeCell::new(v) }
        }
        pub fn lock(&self) -> SpinGuard<'_, T> {
            while self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            SpinGuard { lock: self }
        }
    }

    pub struct SpinGuard<'a, T> {
        lock: &'a SpinLock<T>,
    }
    impl<T> Deref for SpinGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { &*self.lock.data.get() }
        }
    }
    impl<T> DerefMut for SpinGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { &mut *self.lock.data.get() }
        }
    }
    impl<T> Drop for SpinGuard<'_, T> {
        fn drop(&mut self) {
            self.lock.locked.store(false, Ordering::Release);
        }
    }

    // ── Fake task table + wake log ─────────────────────────────────────────
    //
    // `LIVE_TIDS` is a bitmap of "TIDs that exist" so IPC-5 can be exercised
    // both ways. `WAKE_LOG` is a bitmap of slot indices `wake_client` was
    // called on — that is what lets a test assert the *actuation* (the client
    // was really woken) and not just the decision (the slot was freed).
    pub const HOST_MAX_TID: u32 = 128;
    static LIVE_TIDS: [AtomicBool; HOST_MAX_TID as usize] =
        [const { AtomicBool::new(false) }; HOST_MAX_TID as usize];
    /// Mirrors the kernel's `TASK_EXITING`, for U04-2 route (b)'s tests: a TID
    /// can be `live` (so `tid_exists` passes) and separately marked exiting
    /// (so `tid_is_exiting` catches it), the exact combination the real hook
    /// ordering produces in the window between the exit hook running and the
    /// task-pool slot freeing.
    static EXITING_TIDS: [AtomicBool; HOST_MAX_TID as usize] =
        [const { AtomicBool::new(false) }; HOST_MAX_TID as usize];
    static WAKE_LOG: [AtomicBool; super::FAST_IPC_MAX_SLOTS] =
        [const { AtomicBool::new(false) }; super::FAST_IPC_MAX_SLOTS];
    static WAKE_HANDLES: [core::sync::atomic::AtomicU64; super::FAST_IPC_MAX_SLOTS] =
        [const { core::sync::atomic::AtomicU64::new(0) }; super::FAST_IPC_MAX_SLOTS];
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);

    pub fn set_tid_live(tid: u32, live: bool) {
        if let Some(c) = LIVE_TIDS.get(tid as usize) {
            c.store(live, Ordering::SeqCst);
        }
    }
    /// Parent of the "currently running" caller, for
    /// [`super::fast_ipc_tid_dest_for`]'s tests. The kernel side reads this
    /// from `PER_CPU[cpu].current_idx` — there is no such notion on the host,
    /// so a test sets this directly to whatever it wants "the caller's
    /// parent" to be before calling `fast_ipc_tid_dest_for`. Defaults to 0
    /// (no parent), same as a task `set_parent` never touched.
    static CURRENT_PARENT: AtomicU32 = AtomicU32::new(0);
    pub fn set_current_parent(tid: u32) {
        CURRENT_PARENT.store(tid, Ordering::SeqCst);
    }
    pub fn current_parent() -> u32 {
        CURRENT_PARENT.load(Ordering::SeqCst)
    }
    /// Backs `sched_seam::tid_exists` under `cfg(test)`.
    pub fn live(tid: u32) -> bool {
        LIVE_TIDS.get(tid as usize).map(|c| c.load(Ordering::SeqCst)).unwrap_or(false)
    }
    pub fn set_tid_exiting(tid: u32, exiting: bool) {
        if let Some(c) = EXITING_TIDS.get(tid as usize) {
            c.store(exiting, Ordering::SeqCst);
        }
    }
    /// Backs `sched_seam::tid_is_exiting` under `cfg(test)`.
    pub fn exiting(tid: u32) -> bool {
        EXITING_TIDS.get(tid as usize).map(|c| c.load(Ordering::SeqCst)).unwrap_or(false)
    }
    /// Backs `sched_seam::wake_client` under `cfg(test)`. Takes the
    /// generation-tagged handle the kernel-side seam now carries; the log
    /// stays indexed by slot so existing assertions keep reading naturally,
    /// and the full handle is kept alongside so a test can assert the orphan
    /// wake was minted with the PRE-free generation.
    pub fn record_wake(handle: u64) {
        let slot_idx = (handle & super::FAST_IPC_SLOT_MASK) as usize;
        if let Some(c) = WAKE_LOG.get(slot_idx) {
            c.store(true, Ordering::SeqCst);
        }
        if let Some(h) = WAKE_HANDLES.get(slot_idx) {
            h.store(handle, Ordering::SeqCst);
        }
        WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    /// Capabilities `revoke_moved` was asked to destroy: `(server_tid,
    /// handle)` pairs, newest last.
    ///
    /// **It records rather than doing nothing.** A silent stub would make the
    /// test for the stranded-capability path test the stub: the assertion that
    /// matters is that the revoke was ASKED FOR, and on the host there is no
    /// cap table to observe it in.
    static REVOKED: [core::sync::atomic::AtomicU64; super::FAST_IPC_MAX_SLOTS] =
        [const { core::sync::atomic::AtomicU64::new(0) }; super::FAST_IPC_MAX_SLOTS];
    static REVOKED_N: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    pub fn revoke_moved(server_tid: u32, handle: u32) {
        let n = REVOKED_N.fetch_add(1, Ordering::SeqCst);
        if let Some(slot) = REVOKED.get(n) {
            slot.store(((server_tid as u64) << 32) | handle as u64, Ordering::SeqCst);
        }
    }
    /// `(server_tid, handle)` of the n-th revoke asked for.
    pub fn revoked(n: usize) -> Option<(u32, u32)> {
        if n >= REVOKED_N.load(Ordering::SeqCst) { return None; }
        REVOKED.get(n).map(|v| {
            let raw = v.load(Ordering::SeqCst);
            ((raw >> 32) as u32, raw as u32)
        })
    }
    pub fn revoked_count() -> usize { REVOKED_N.load(Ordering::SeqCst) }
    pub fn clear_revoked() { REVOKED_N.store(0, Ordering::SeqCst); }

    // Donations the exit sweep returned (wave 11 PIFAST), in order, so a test
    // can assert WHICH task got one back and that it got exactly one.
    static UNDONATED: [AtomicU32; super::FAST_IPC_MAX_SLOTS] =
        [const { AtomicU32::new(0) }; super::FAST_IPC_MAX_SLOTS];
    static UNDONATED_N: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    pub fn record_undonate(target: u32) {
        let n = UNDONATED_N.fetch_add(1, Ordering::SeqCst);
        if let Some(c) = UNDONATED.get(n) {
            c.store(target, Ordering::SeqCst);
        }
    }
    pub fn undonated(n: usize) -> Option<u32> {
        if n >= UNDONATED_N.load(Ordering::SeqCst) { return None; }
        UNDONATED.get(n).map(|c| c.load(Ordering::SeqCst))
    }
    pub fn undonated_count() -> usize { UNDONATED_N.load(Ordering::SeqCst) }
    pub fn clear_undonated() { UNDONATED_N.store(0, Ordering::SeqCst); }
    static DONATES: AtomicBool = AtomicBool::new(true);
    pub fn set_donate(on: bool) { DONATES.store(on, Ordering::SeqCst); }
    pub fn donates() -> bool { DONATES.load(Ordering::SeqCst) }

    /// Last handle `wake_client` was called with for a given slot.
    pub fn woken_handle(slot_idx: usize) -> Option<u64> {
        WAKE_HANDLES.get(slot_idx).map(|h| h.load(Ordering::SeqCst))
    }
    pub fn clear_all_tids() {
        for c in LIVE_TIDS.iter() {
            c.store(false, Ordering::SeqCst);
        }
        for c in EXITING_TIDS.iter() {
            c.store(false, Ordering::SeqCst);
        }
    }
    pub fn clear_wake_log() {
        for c in WAKE_LOG.iter() {
            c.store(false, Ordering::SeqCst);
        }
        WAKE_COUNT.store(0, Ordering::SeqCst);
    }
    pub fn was_woken(slot_idx: usize) -> bool {
        WAKE_LOG.get(slot_idx).map(|c| c.load(Ordering::SeqCst)).unwrap_or(false)
    }
    pub fn wake_count() -> u32 {
        WAKE_COUNT.load(Ordering::SeqCst)
    }
}

#[cfg(not(target_os = "none"))]
mod sched_seam {
    pub fn tid_exists(tid: u32) -> bool {
        if tid >= super::host_seam::HOST_MAX_TID {
            return false;
        }
        // Mirrors the real `idx_for_tid`: unknown TID ⇒ false.
        super::host_seam::live(tid)
    }
    /// Backed by `host_seam::exiting` (default `false`, so the host suite's
    /// existing `tid_exists`-only paths are unaffected unless a test opts in
    /// with `host_seam::set_tid_exiting`).
    pub fn tid_is_exiting(tid: u32) -> bool {
        super::host_seam::exiting(tid)
    }
    pub fn wake_client(handle: u64) {
        super::host_seam::record_wake(handle);
    }
    /// Records rather than doing nothing — see `host_seam::revoke_moved`.
    pub fn revoke_moved(server_tid: u32, handle: u32) {
        super::host_seam::revoke_moved(server_tid, handle);
    }
    /// See `host_seam::current_parent`.
    pub fn current_parent_tid() -> u32 {
        super::host_seam::current_parent()
    }
    /// Records rather than doing nothing — see `host_seam::record_undonate`.
    pub fn return_donation(target: u32) {
        super::host_seam::record_undonate(target);
    }
    pub fn tid_idx(tid: u32) -> Option<usize> {
        if tid_exists(tid) { Some(tid as usize) } else { None }
    }
    /// The host donates whenever asked (the rule is `sched`'s, tested in
    /// `sched-wake-tests`); `host_seam::set_donate` turns that off.
    pub fn donate_for_call(_idx: usize, _tid: u32) -> bool {
        super::host_seam::donates()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    const SERVER: u32 = 7;
    const OTHER_SERVER: u32 = 8;
    const CLIENT: u32 = 21;
    const IMPOSTOR: u32 = 99;
    const REQ: [u64; FAST_IPC_MAX_WORDS] = [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD];
    const RSP: [u64; FAST_IPC_MAX_WORDS] = [0x1111, 0x2222, 0x3333, 0x4444];

    /// `FAST_IPC` is one global table and `cargo test` runs tests on parallel
    /// threads, so every test must own it exclusively and start from a known
    /// state. Holding this guard for the body of the test is what makes the
    /// slot-exhaustion test (IPC-3) meaningful at all.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Env {
        _g: MutexGuard<'static, ()>,
    }

    fn env() -> Env {
        // `into_inner` on poisoning: one failing test must not cascade into
        // every other test reporting a poisoned lock instead of its own result.
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut st = lock_fast_ipc();
            for s in st.slots.iter_mut() {
                *s = FastIpcSlot::empty();
            }
            st.used = 0;
            st.pending = 0;
        }
        host_seam::clear_all_tids();
        host_seam::clear_wake_log();
        host_seam::clear_revoked();
        host_seam::clear_undonated();
        host_seam::set_donate(true);
        // No parent by default — matches a task `set_parent` never touched.
        host_seam::set_current_parent(0);
        // Default population for the common case.
        host_seam::set_tid_live(SERVER, true);
        host_seam::set_tid_live(OTHER_SERVER, true);
        host_seam::set_tid_live(CLIENT, true);
        host_seam::set_tid_live(IMPOSTOR, true);
        Env { _g: g }
    }

    fn slot_state(idx: usize) -> Option<SlotState> {
        lock_fast_ipc().slots.get(idx).map(|s| s.state)
    }

    fn slot_generation(idx: usize) -> u64 {
        lock_fast_ipc().slots.get(idx).map(|s| s.generation).unwrap_or(0)
    }

    /// Force a slot's generation. Only a test can do this: reaching the wrap
    /// honestly needs 2^57 reuses, so the alternative to poking the counter is
    /// leaving the wrap untested and taking its behaviour on faith.
    fn set_slot_generation(idx: usize, generation: u64) {
        if let Some(s) = lock_fast_ipc().slots.get_mut(idx) {
            s.generation = generation & FAST_IPC_GEN_MASK;
        }
    }

    /// The handle ACCEPT would return for `idx` right now. Also the handle
    /// the CLIENT of a live exchange on `idx` holds — the two are the same
    /// value while the exchange lives (the generation only advances on free).
    fn handle_of(idx: usize) -> u64 {
        fast_ipc_make_handle(idx, slot_generation(idx))
    }

    /// [`fast_ipc_call`] reduced to its pre-handle shape — the SEAT index —
    /// because most of these tests reason about slots (`slot_state`,
    /// `reply_now`). Tests that care about the client handle itself call
    /// `fast_ipc_call` directly or reconstruct it with [`handle_of`].
    fn call_idx(
        caller: u32,
        server: u32,
        w: [u64; FAST_IPC_MAX_WORDS],
    ) -> Option<usize> {
        fast_ipc_call(caller, server, w, NO_CAP).and_then(fast_ipc_handle_slot)
    }

    /// [`fast_ipc_reply`] reduced to its pre-generation shape — handle in,
    /// `Option<caller_tid>` out — so the tests that predate handles keep
    /// asserting exactly what they always asserted. New tests that care which
    /// *kind* of rejection happened call `fast_ipc_reply` directly.
    fn reply_h(
        handle: u64,
        tid: u32,
        privileged: bool,
        w: [u64; FAST_IPC_MAX_WORDS],
    ) -> Option<u32> {
        match fast_ipc_reply(handle, tid, privileged, w) {
            FastIpcReply::Woke { caller_tid, .. } => Some(caller_tid),
            FastIpcReply::Stale | FastIpcReply::Refused => None,
        }
    }

    /// Same, addressed by slot index at that slot's current generation.
    fn reply_now(
        idx: usize,
        tid: u32,
        privileged: bool,
        w: [u64; FAST_IPC_MAX_WORDS],
    ) -> Option<u32> {
        reply_h(handle_of(idx), tid, privileged, w)
    }

    // ── reply + accept in one lock hold (`fast_ipc_reply_then_accept`) ─────

    /// `fast_ipc_reply_then_accept` must equal `fast_ipc_reply` followed, only
    /// on `Woke`, by `fast_ipc_accept` — same outcome, same slot states.
    #[test]
    fn reply_then_accept_delivers_and_takes_the_next_request() {
        let _e = env();
        let a = call_idx(CLIENT, SERVER, REQ).unwrap();
        let (h, _, _, _) = fast_ipc_accept(SERVER).unwrap();
        let b = call_idx(IMPOSTOR, SERVER, RSP).unwrap();
        let (r, next) = fast_ipc_reply_then_accept(h, SERVER, false, RSP, SERVER);
        assert_eq!(r, FastIpcReply::Woke { caller_tid: CLIENT, slot_idx: a, donee: NO_DONEE });
        let (h2, caller2, w2, _) = next.expect("the pending call is taken in the same hold");
        assert_eq!((fast_ipc_handle_slot(h2), caller2, w2), (Some(b), IMPOSTOR, RSP));
        assert_eq!(slot_state(a), Some(SlotState::Replied));
        assert_eq!(slot_state(b), Some(SlotState::Accepted));
        assert_eq!(fast_ipc_collect(h, CLIENT), Some(RSP));
    }

    #[test]
    fn reply_then_accept_with_nothing_pending_answers_none() {
        let _e = env();
        let a = call_idx(CLIENT, SERVER, REQ).unwrap();
        let (h, _, _, _) = fast_ipc_accept(SERVER).unwrap();
        let (r, next) = fast_ipc_reply_then_accept(h, SERVER, false, RSP, SERVER);
        assert_eq!(r, FastIpcReply::Woke { caller_tid: CLIENT, slot_idx: a, donee: NO_DONEE });
        assert_eq!(next, None);
    }

    /// A refused or stale reply must not accept anything: the arm answers
    /// -3/-2 and the pending request stays `Pending` for the next accept.
    #[test]
    fn reply_then_accept_refused_or_stale_accepts_nothing() {
        let _e = env();
        let _a = call_idx(CLIENT, SERVER, REQ).unwrap();
        let (h, _, _, _) = fast_ipc_accept(SERVER).unwrap();
        let b = call_idx(IMPOSTOR, SERVER, RSP).unwrap();
        let (r, next) = fast_ipc_reply_then_accept(h, OTHER_SERVER, false, RSP, OTHER_SERVER);
        assert_eq!((r, next), (FastIpcReply::Refused, None));
        let stale = fast_ipc_make_handle(fast_ipc_handle_slot(h).unwrap(), slot_generation(fast_ipc_handle_slot(h).unwrap()).wrapping_add(1) & FAST_IPC_GEN_MASK);
        let (r, next) = fast_ipc_reply_then_accept(stale, SERVER, false, RSP, SERVER);
        assert_eq!((r, next), (FastIpcReply::Stale, None));
        assert_eq!(slot_state(b), Some(SlotState::Pending));
    }

    // ── RFC-0040 gap 2, CALL direction: `fast_ipc_tid_dest_for` ────────────

    #[test]
    fn raw_tid_call_to_parent_is_allowed() {
        let _e = env();
        host_seam::set_current_parent(SERVER);
        assert_eq!(fast_ipc_tid_dest_for(SERVER), Some(SERVER));
    }

    #[test]
    fn raw_tid_call_to_non_parent_is_refused() {
        let _e = env();
        host_seam::set_current_parent(SERVER);
        // OTHER_SERVER is a live task — the refusal is the parent check, not
        // IPC-5's "TID does not exist" gate.
        assert_eq!(fast_ipc_tid_dest_for(OTHER_SERVER), None);
    }

    #[test]
    fn raw_tid_call_with_no_recorded_parent_is_refused() {
        let _e = env();
        // `set_current_parent` was never called — env() leaves it at 0, the
        // same state as root or a reaped child. `raw_tid = 0` must not slip
        // through by matching it.
        assert_eq!(fast_ipc_tid_dest_for(0), None);
    }

    // ── IPC-5: target validation ───────────────────────────────────────────

    #[test]
    fn call_to_live_server_is_accepted() {
        let _e = env();
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_some());
        assert_eq!(fast_ipc_active(), 1);
    }

    #[test]
    fn call_to_nonexistent_tid_is_rejected_and_leaks_no_slot() {
        let _e = env();
        host_seam::set_tid_live(55, false);
        assert!(fast_ipc_call(CLIENT, 55, REQ, NO_CAP).is_none());
        // The whole point of IPC-5: the failed call must not burn a slot.
        assert_eq!(fast_ipc_active(), 0);
    }

    /// U04-2 route (b): a server whose exit hook already ran but whose
    /// task-pool slot is not freed yet still passes `tid_exists` — the fixed
    /// window is closed by `tid_is_exiting`, checked right after it. Without
    /// this, the call would allocate a slot the dying server's
    /// `fast_ipc_release_all` will never run again to reclaim, and the
    /// client would block on a handle nobody can ever wake.
    #[test]
    fn a_call_to_an_exiting_server_is_rejected_and_leaks_no_slot() {
        let _e = env();
        // Live (so `tid_exists` alone would pass) AND exiting — the exact
        // combination the real `TASK_EXITING`-before-hook ordering produces.
        host_seam::set_tid_exiting(SERVER, true);
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_none());
        assert_eq!(fast_ipc_active(), 0, "the call must not burn a slot nobody will free");
    }

    #[test]
    fn call_to_free_sentinel_tid_is_rejected() {
        let _e = env();
        assert!(fast_ipc_call(CLIENT, FAST_IPC_SLOT_FREE, REQ, NO_CAP).is_none());
        assert_eq!(fast_ipc_active(), 0);
    }

    #[test]
    fn self_call_is_rejected() {
        let _e = env();
        assert!(fast_ipc_call(SERVER, SERVER, REQ, NO_CAP).is_none());
        assert_eq!(fast_ipc_active(), 0);
    }

    #[test]
    fn sixty_four_calls_to_a_dead_tid_do_not_exhaust_the_table() {
        // The exact ring-3 denial-of-service IPC-5 closes.
        let _e = env();
        host_seam::set_tid_live(55, false);
        for _ in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_call(CLIENT, 55, REQ, NO_CAP).is_none());
        }
        assert_eq!(fast_ipc_active(), 0);
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_some());
    }

    // ── Happy path ─────────────────────────────────────────────────────────

    #[test]
    fn full_exchange_delivers_reply_and_frees_slot() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let (handle, caller, words, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_handle_slot(handle), Some(idx));
        assert_eq!(caller, CLIENT);
        assert_eq!(words, REQ);
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP));
        assert_eq!(fast_ipc_active(), 0);
        assert_eq!(slot_state(idx), Some(SlotState::Free));
    }

    #[test]
    fn accept_with_nothing_pending_returns_none() {
        let _e = env();
        assert!(fast_ipc_accept(SERVER).is_none());
        // And a call aimed elsewhere must not be visible to this server.
        let _ = call_idx(CLIENT, OTHER_SERVER, REQ).expect("slot");
        assert!(fast_ipc_accept(SERVER).is_none());
    }

    // ── IPC-2: Accepted is not Replied ─────────────────────────────────────

    #[test]
    fn collect_between_accept_and_reply_returns_none_not_the_request() {
        // The heart of IPC-2. Before the fix this returned Some(REQ) and the
        // client took its own request for the server's answer.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), None);
    }

    #[test]
    fn accept_moves_slot_to_accepted_not_replied() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert_eq!(slot_state(idx), Some(SlotState::Pending));
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(slot_state(idx), Some(SlotState::Accepted));
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(slot_state(idx), Some(SlotState::Replied));
    }

    #[test]
    fn collect_before_accept_returns_none() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), None);
    }

    #[test]
    fn second_accept_cannot_steal_an_accepted_slot() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert!(fast_ipc_accept(SERVER).is_some());
        assert!(fast_ipc_accept(SERVER).is_none());
        assert_eq!(slot_state(idx), Some(SlotState::Accepted));
    }

    // ── IPC-1: only the real server may reply ──────────────────────────────

    /// Fill every slot with a call to `SERVER` and accept them all, so the
    /// impostor test below sweeps the whole 0..63 handle space rather than
    /// proving one lucky index.
    fn fill_and_accept_all() {
        for i in 0..FAST_IPC_MAX_SLOTS {
            let caller = 1000 + i as u32;
            assert!(fast_ipc_call(caller, SERVER, REQ, NO_CAP).is_some(), "alloc {i}");
        }
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_accept(SERVER).is_some(), "accept {i}");
        }
    }

    #[test]
    fn impostor_is_rejected_on_every_slot_index() {
        let _e = env();
        fill_and_accept_all();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(
                reply_now(idx, IMPOSTOR, false, RSP),
                None,
                "impostor accepted on slot {idx}"
            );
            // Rejection must not have mutated the slot.
            assert_eq!(slot_state(idx), Some(SlotState::Accepted), "slot {idx} mutated");
        }
        // And no client can collect anything the impostor tried to plant.
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(fast_ipc_collect(handle_of(i), 1000 + i as u32), None);
        }
    }

    #[test]
    fn real_server_is_accepted_on_every_slot_index() {
        // The other half of the gate: the check must not reject the legitimate
        // server anywhere in the handle space.
        let _e = env();
        fill_and_accept_all();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            let caller = 1000 + idx as u32;
            assert_eq!(
                reply_now(idx, SERVER, false, RSP),
                Some(caller),
                "real server rejected on slot {idx}"
            );
            assert_eq!(fast_ipc_collect(handle_of(idx), caller), Some(RSP));
        }
        assert_eq!(fast_ipc_active(), 0);
    }

    #[test]
    fn privileged_replier_bypasses_the_ownership_check() {
        // House convention: kernel tasks (current_user_pt() == 0) skip
        // authorisation, same as cap_store's typed callers.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, IMPOSTOR, true, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP));
    }

    #[test]
    fn reply_to_a_slot_that_was_never_accepted_is_rejected() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        // Pending, not Accepted — even the real server may not reply yet.
        assert_eq!(reply_now(idx, SERVER, false, RSP), None);
        assert_eq!(reply_now(idx, SERVER, true, RSP), None);
        assert_eq!(slot_state(idx), Some(SlotState::Pending));
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), None);
    }

    #[test]
    fn reply_to_a_free_slot_is_rejected() {
        let _e = env();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(reply_now(idx, SERVER, false, RSP), None);
            assert_eq!(reply_now(idx, SERVER, true, RSP), None);
        }
        assert_eq!(fast_ipc_active(), 0);
    }

    #[test]
    fn replying_twice_cannot_overwrite_an_uncollected_reply() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        let second = [0xDEADu64, 0, 0, 0];
        assert_eq!(reply_now(idx, SERVER, false, second), None);
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP));
    }

    // ── Exchange identity: `collect` must not confuse two exchanges ────────

    #[test]
    fn a_stale_reply_is_never_handed_to_a_newer_exchange() {
        // Reachable, not hypothetical: `syscall::dispatch`'s SYS_IPC_FAST_CALL
        // retry loop bounds itself at `MAX_SPURIOUS_WAKES` turns (dispatch.rs
        // ~704-736) and returns -1 to ring 3 the moment it runs out, *without*
        // freeing the slot if the server has not replied yet. The comment at
        // dispatch.rs:794 names the result plainly: "the -1 path itself
        // manufactures orphans: the client gives up, the server replies
        // anyway, and the slot sits Replied ... owned by a caller that is no
        // longer waiting for it." Nothing in the ABI stops that same task from
        // issuing a second SYS_IPC_FAST_CALL afterwards — the documented
        // fallback is channel IPC, but nothing enforces it, and this is
        // ordinary ring-3 code, not a protocol violation. This test builds
        // exactly that shape: one abandoned exchange whose reply lands late,
        // plus a second, current exchange the task is actually blocked on.
        let _e = env();

        // Exchange 1: called, accepted, replied — but never collected. This
        // stands in for the retry loop's bailout: the client gave up, the
        // slot is still `Replied` and still says `caller_tid == CLIENT`.
        let idx1 = call_idx(CLIENT, SERVER, REQ).expect("slot 1");
        let _ = fast_ipc_accept(SERVER).expect("accept 1");
        let rsp1 = [0x1111u64, 0, 0, 0];
        assert_eq!(reply_now(idx1, SERVER, false, rsp1), Some(CLIENT));
        assert_eq!(slot_state(idx1), Some(SlotState::Replied));

        // Exchange 2: the same task starts a fresh fast call — to a different
        // server here, but the target is not what makes the two exchanges
        // distinct; the handle is. This is the handle the task actually
        // blocks on and the one it collects against.
        let handle2 = fast_ipc_call(CLIENT, OTHER_SERVER, REQ, NO_CAP).expect("call 2");
        let idx2 = fast_ipc_handle_slot(handle2).expect("slot 2");
        assert_ne!(idx1, idx2, "the two exchanges must occupy different slots");
        let _ = fast_ipc_accept(OTHER_SERVER).expect("accept 2");
        let rsp2 = [0x2222u64, 0, 0, 0];
        assert_eq!(reply_now(idx2, OTHER_SERVER, false, rsp2), Some(CLIENT));
        assert_eq!(slot_state(idx2), Some(SlotState::Replied));

        // Both slots are now `Replied` and both are owned by CLIENT. The task
        // is blocked on exchange 2 (handle2) and must collect exchange 2's
        // reply — never exchange 1's stale one, regardless of which slot
        // sorts first in the table.
        assert_eq!(
            fast_ipc_collect(handle2, CLIENT),
            Some(rsp2),
            "collect handed the caller a reply for the wrong exchange"
        );
        // And the stale exchange must still be sitting there afterwards —
        // collect must not have silently freed or answered it either.
        assert_eq!(slot_state(idx1), Some(SlotState::Replied));
    }

    #[test]
    fn collect_rejects_a_stale_generation_even_when_tid_and_state_both_match() {
        // The companion of `a_stale_reply_is_never_handed_to_a_newer_exchange`:
        // that test proves identity across two DIFFERENT slots. This one
        // proves it within the SAME slot, across two tenancies of the same
        // `caller_tid` — the "same-tid recycle" shape `wait_state_reports_
        // gone_when_the_slot_is_reassigned` already exercises for
        // `fast_ipc_wait_state`. Matching only on `(state, caller_tid)`, as
        // the pre-fix code effectively did once decoded to a slot, would
        // accept an old handle here purely because the seat's new tenant
        // happens to be the same TID — the ownership check cannot see this,
        // because ownership *is* the TID. Only the generation can.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let old_handle = handle_of(idx);

        // CLIENT dies before collecting; the seat comes back with its
        // generation bumped.
        assert_eq!(fast_ipc_release_all(CLIENT), 1);

        // A TID is just a number the scheduler recycles — nothing here
        // depends on CLIENT still being the same task, only on it being the
        // same numeric caller_tid. It calls again, lands on the same index
        // (forced by construction), and gets a real, current answer.
        let reused = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert_eq!(reused, idx, "test needs the same index to be reused");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));

        // The old handle names a dead tenancy: same slot, same caller_tid,
        // wrong generation. It must not collect the new tenant's answer.
        assert_ne!(old_handle, handle_of(idx), "test needs the generation to differ");
        assert_eq!(fast_ipc_collect(old_handle, CLIENT), None);
        // The real, current handle still works.
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP));
    }

    // ── Slot ABA: the generation tag on the server handle ──────────────────

    #[test]
    fn handle_encoding_round_trips_over_the_whole_table() {
        // The layout is arithmetic on a value ring 3 supplies, so the two
        // fields must be recoverable for every index and at both ends of the
        // generation range — an aliasing bug here would silently make two
        // different exchanges share a handle.
        let _e = env();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            for g in [0u64, 1, 2, 0x5555_5555, FAST_IPC_GEN_MASK - 1, FAST_IPC_GEN_MASK] {
                let h = fast_ipc_make_handle(idx, g);
                assert_eq!(fast_ipc_handle_slot(h), Some(idx), "idx {idx} gen {g}");
                assert_eq!(handle_generation(h), g, "idx {idx} gen {g}");
                // Bit 63 must stay clear: the handle travels in `a0` as an
                // `i64` whose negative half means "error".
                assert!((h as i64) >= 0, "idx {idx} gen {g} handle is negative");
            }
        }
    }

    #[test]
    fn accept_hands_back_the_slots_current_generation() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let (h, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(h, fast_ipc_make_handle(idx, slot_generation(idx)));
        // And that handle is the one that works.
        assert_eq!(reply_h(h, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_collect(h, CLIENT), Some(RSP));
    }

    #[test]
    fn freeing_a_slot_advances_its_generation_by_exactly_one() {
        let _e = env();
        for round in 0..5u64 {
            let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
            assert_eq!(idx, 0, "test needs the same slot every round");
            assert_eq!(slot_generation(0), round, "round {round}");
            assert_eq!(fast_ipc_release_all(CLIENT), 1);
            assert_eq!(slot_generation(0), round + 1, "round {round}");
        }
    }

    #[test]
    fn a_stale_handle_is_refused_on_a_reassigned_slot() {
        // **This is the defect, turned into a guard.** Server accepts A's
        // slot; A dies and the slot is reclaimed; B calls the same server and
        // lands on the same index; the server accepts. A reply carrying the
        // handle the server was still holding for A used to pass both checks
        // — Accepted, and the server really is the slot's server — and B
        // collected A's answer.
        let _e = env();
        const A: u32 = 30;
        const B: u32 = 31;
        host_seam::set_tid_live(A, true);
        host_seam::set_tid_live(B, true);

        let idx = call_idx(A, SERVER, REQ).expect("slot");
        let (stale, caller, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(caller, A);

        // A dies mid-exchange; the slot comes back to the pool.
        assert_eq!(fast_ipc_release_all(A), 1);
        // B calls and must land on the very index the stale handle names,
        // otherwise the test is not exercising the hazard at all.
        let reused = call_idx(B, SERVER, REQ).expect("slot");
        assert_eq!(reused, idx, "test needs the same index to be reused");
        let (fresh, caller2, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(caller2, B);
        assert_ne!(fresh, stale, "handle did not change across the reuse");

        // The stale handle must be rejected, and rejected *as stale*.
        assert_eq!(fast_ipc_reply(stale, SERVER, false, RSP), FastIpcReply::Stale);
        // Nothing was written: B is still waiting, not holding A's answer.
        assert_eq!(slot_state(idx), Some(SlotState::Accepted));
        assert_eq!(fast_ipc_collect(fresh, B), None);
        assert_eq!(fast_ipc_wait_state(handle_of(idx), B), FastIpcWait::Waiting);

        // The fresh handle still works — the gate must not cost the live half.
        assert_eq!(
            fast_ipc_reply(fresh, SERVER, false, RSP),
            FastIpcReply::Woke { caller_tid: B, slot_idx: idx, donee: NO_DONEE }
        );
        assert_eq!(fast_ipc_collect(fresh, B), Some(RSP));
    }

    #[test]
    fn a_stale_handle_is_refused_over_the_whole_table() {
        // One index proves one index. Sweep all 64 so an encoding bug that
        // only bites at some offsets cannot hide.
        let _e = env();
        let mut stale = [0u64; FAST_IPC_MAX_SLOTS];
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_call(1000 + i as u32, SERVER, REQ, NO_CAP).is_some());
        }
        for i in 0..FAST_IPC_MAX_SLOTS {
            let (h, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
            stale[i] = h;
        }
        // Every client dies; every slot turns over.
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(fast_ipc_release_all(1000 + i as u32), 1);
        }
        let mut fresh = [0u64; FAST_IPC_MAX_SLOTS];
        for i in 0..FAST_IPC_MAX_SLOTS {
            fresh[i] = fast_ipc_call(2000 + i as u32, SERVER, REQ, NO_CAP).expect("call");
        }
        for _ in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_accept(SERVER).is_some());
        }
        for (i, &h) in stale.iter().enumerate() {
            assert_eq!(
                fast_ipc_reply(h, SERVER, false, RSP),
                FastIpcReply::Stale,
                "stale handle {i} was honoured"
            );
        }
        // No new tenant collected anything. Addressed by each client's own
        // handle: none of these are `Replied` yet (only accepted above), so
        // this also proves the fix does not make a live-but-unanswered
        // exchange collectible.
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(fast_ipc_collect(fresh[i], 2000 + i as u32), None, "client {i}");
        }
    }

    #[test]
    fn a_handle_from_a_future_generation_is_refused() {
        // The mirror of the stale case. It is not reachable by an honest
        // server, but `a0` is ring 3's to choose, so the comparison must be
        // equality and not "at least".
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        let g = slot_generation(idx);
        for ahead in [1u64, 2, 1000, FAST_IPC_GEN_MASK] {
            let h = fast_ipc_make_handle(idx, g.wrapping_add(ahead) & FAST_IPC_GEN_MASK);
            if handle_generation(h) == g { continue; }
            assert_eq!(fast_ipc_reply(h, SERVER, false, RSP), FastIpcReply::Stale, "+{ahead}");
        }
        assert_eq!(slot_state(idx), Some(SlotState::Accepted));
    }

    #[test]
    fn a_privileged_replier_is_still_bound_by_the_generation() {
        // `privileged` waives *ownership*, which is authorisation. It does not
        // waive the generation, which is the identity of the exchange: a
        // kernel server holding a dead handle is as wrong about reality as a
        // user one, and letting it write would corrupt the slot's new tenant.
        let _e = env();
        const A: u32 = 30;
        const B: u32 = 31;
        host_seam::set_tid_live(A, true);
        host_seam::set_tid_live(B, true);
        let idx = call_idx(A, SERVER, REQ).expect("slot");
        let (stale, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_release_all(A), 1);
        assert_eq!(call_idx(B, SERVER, REQ), Some(idx));
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_reply(stale, IMPOSTOR, true, RSP), FastIpcReply::Stale);
        assert_eq!(fast_ipc_collect(handle_of(idx), B), None);
    }

    #[test]
    fn stale_never_leaks_the_generation_to_a_non_owner() {
        // `Stale` is only reachable after the state and ownership checks have
        // passed. Reordered, it would be a generation oracle: a ring-3 task
        // could sweep 64 indices and read off how often each slot has turned
        // over. A non-owner must get the same `Refused` whatever it guesses.
        let _e = env();
        fill_and_accept_all();
        // Turn slot 0 over a few times so its generation is genuinely
        // distinguishable from its neighbours'.
        for _ in 0..3 {
            assert_eq!(fast_ipc_release_all(1000), 1);
            assert!(fast_ipc_call(1000, SERVER, REQ, NO_CAP).is_some());
            assert!(fast_ipc_accept(SERVER).is_some());
        }
        for g in 0..8u64 {
            let h = fast_ipc_make_handle(0, g);
            assert_eq!(
                fast_ipc_reply(h, IMPOSTOR, false, RSP),
                FastIpcReply::Refused,
                "impostor learned something at gen {g}"
            );
        }
    }

    #[test]
    fn a_stale_handle_on_a_free_slot_reads_as_refused_not_stale() {
        // `Stale` and `Refused` are not a partition of "rejected", and the
        // doc on `FastIpcReply` says so. A dead handle whose slot happens to
        // be free fails the state check first. `Stale` is *sufficient* proof
        // the exchange is over; `Refused` proves nothing either way.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let (h, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(slot_state(idx), Some(SlotState::Free));
        assert_eq!(fast_ipc_reply(h, SERVER, false, RSP), FastIpcReply::Refused);
    }

    #[test]
    fn a_stale_handle_on_a_slot_now_owned_by_another_server_is_refused() {
        // Same non-partition, the other way: the slot is live but belongs to
        // somebody else, so ownership rejects before generation is consulted.
        // That is what stops `Stale` being an oracle.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let (h, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(call_idx(CLIENT, OTHER_SERVER, REQ), Some(idx));
        assert!(fast_ipc_accept(OTHER_SERVER).is_some());
        assert_eq!(fast_ipc_reply(h, SERVER, false, RSP), FastIpcReply::Refused);
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), None);
    }

    #[test]
    fn a_collected_exchange_retires_its_own_handle() {
        // The ABA does not need a death to set it up: a completed exchange
        // frees the slot too, so a server that replies twice with the same
        // handle across two different clients must be stopped the same way.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let (h1, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_h(h1, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_collect(h1, CLIENT), Some(RSP));
        // New client, same index.
        assert_eq!(call_idx(IMPOSTOR, SERVER, REQ), Some(idx));
        assert!(fast_ipc_accept(SERVER).is_some());
        let poison = [0xDEADu64, 0, 0, 0];
        assert_eq!(fast_ipc_reply(h1, SERVER, false, poison), FastIpcReply::Stale);
        assert_eq!(fast_ipc_collect(handle_of(idx), IMPOSTOR), None);
    }

    #[test]
    fn the_generation_wraps_without_panicking() {
        // `overflow-checks = true` + `panic = "abort"`: a plain `+ 1` at the
        // ceiling would reset the board. The counter is a tag, not a count, so
        // wrapping is also the correct arithmetic.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        set_slot_generation(idx, FAST_IPC_GEN_MASK);
        assert_eq!(slot_generation(idx), FAST_IPC_GEN_MASK);
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(slot_generation(idx), 0, "generation did not wrap to 0");
        // And the wrapped value still encodes and decodes cleanly.
        assert_eq!(call_idx(CLIENT, SERVER, REQ), Some(idx));
        let (h, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(handle_generation(h), 0);
        assert_eq!(reply_h(h, SERVER, false, RSP), Some(CLIENT));
    }

    #[test]
    fn generation_wrap_reopens_aba_the_documented_residual() {
        // The honest statement of what this fix does NOT cover. At the wrap a
        // handle from an ancient tenancy matches again — that is inherent to a
        // finite tag, and 2^57 = 144_115_188_075_855_872 reuses of one slot is
        // the price. One reuse per nanosecond, faster than an instruction
        // retires, still needs ~4.5 years of doing nothing else.
        //
        // Reached here by poking the counter, because reaching it honestly is
        // the point. If this test ever fails, the encoding changed and the
        // wraparound claim in the report needs recomputing.
        let _e = env();
        const A: u32 = 30;
        const B: u32 = 31;
        host_seam::set_tid_live(A, true);
        host_seam::set_tid_live(B, true);

        let idx = call_idx(A, SERVER, REQ).expect("slot");
        set_slot_generation(idx, 0);
        let (ancient, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(handle_generation(ancient), 0);
        assert_eq!(fast_ipc_release_all(A), 1);
        assert_eq!(slot_generation(idx), 1);

        // Simulate 2^57 - 1 further turnovers of this slot.
        set_slot_generation(idx, 0);
        assert_eq!(call_idx(B, SERVER, REQ), Some(idx));
        assert!(fast_ipc_accept(SERVER).is_some());

        // The ancient handle matches again, and B collects A's answer. This is
        // the ABA, back — documented, bounded, accepted.
        assert_eq!(
            fast_ipc_reply(ancient, SERVER, false, RSP),
            FastIpcReply::Woke { caller_tid: B, slot_idx: idx, donee: NO_DONEE }
        );
        // The residual ABA is exactly this: `ancient` is honoured because it
        // happens to equal B's own current handle after the forced wrap, not
        // because `collect` failed to check identity.
        assert_eq!(fast_ipc_collect(ancient, B), Some(RSP));
    }

    // ── Bounds: no reachable panic (panic = "abort" resets the board) ───────

    #[test]
    fn arbitrary_handle_bit_patterns_never_panic() {
        // Every 64-bit value is a legal `a0`. With `FAST_IPC_MAX_SLOTS` = 64
        // the index field is saturated, so no handle decodes out of range —
        // but the table must still be swept for a panic, and every one of
        // these must be refused rather than land on a live exchange.
        let _e = env();
        fill_and_accept_all();
        // Every live slot is at generation 0, so a handle is honourable here
        // only if bit 63 is clear *and* its generation field is 0 — i.e. only
        // the plain indices 0..63. None of these qualify: the first two groups
        // have bit 63 set, the rest carry a non-zero generation.
        for h in [
            u64::MAX,
            1u64 << 63,
            (1u64 << 63) | 5,
            (1u64 << 63) | (FAST_IPC_GEN_MASK << FAST_IPC_SLOT_BITS),
            u64::MAX / 2,
            i64::MAX as u64,
            FAST_IPC_GEN_MASK << FAST_IPC_SLOT_BITS,
            0x7EAD_BEEF_DEAD_BEEF,
            1u64 << FAST_IPC_SLOT_BITS,
        ] {
            assert!(
                h > i64::MAX as u64 || handle_generation(h) != 0,
                "test datum {h:#x} is honourable, not a rejection case"
            );
            for (tid, privileged) in
                [(SERVER, false), (SERVER, true), (IMPOSTOR, false), (IMPOSTOR, true)]
            {
                assert_eq!(reply_h(h, tid, privileged, RSP), None, "handle {h:#x}");
            }
        }
        // A handle is invalidated by its sign bit, not repaired by masking it.
        let good = handle_of(0);
        assert!(reply_h(good | (1u64 << 63), SERVER, false, RSP).is_none());
        assert_eq!(fast_ipc_handle_slot(good | (1u64 << 63)), None);
        // Nothing above wrote anywhere in the table.
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(slot_state(idx), Some(SlotState::Accepted), "slot {idx} mutated");
        }
    }

    #[test]
    fn out_of_range_slot_index_never_panics() {
        // Kept as a direct index sweep: `fast_ipc_handle_slot` is the only
        // bounds check between ring 3 and `slots[..]`, and an off-by-one there
        // is a board reset under `panic = "abort"`.
        let _e = env();
        for idx in [
            FAST_IPC_MAX_SLOTS,      // 64 — first invalid
            FAST_IPC_MAX_SLOTS + 1,
            1024,
            usize::MAX / 2,
            usize::MAX - 1,
            usize::MAX,
        ] {
            let expect = if idx as u64 > i64::MAX as u64 {
                None // sign bit set: never a handle this file issued
            } else {
                Some(idx & (FAST_IPC_SLOT_MASK as usize))
            };
            assert_eq!(fast_ipc_handle_slot(idx as u64), expect, "idx {idx}");
            // ...and with every slot free, no handle at all may be honoured.
            assert_eq!(reply_h(idx as u64, SERVER, false, RSP), None, "idx {idx}");
            assert_eq!(reply_h(idx as u64, SERVER, true, RSP), None, "idx {idx}");
        }
    }

    #[test]
    fn last_valid_slot_index_works() {
        // 63 must be usable — an off-by-one in the bounds check would make the
        // last slot permanently unrepliable and leak it on every wrap.
        let _e = env();
        fill_and_accept_all();
        let last = FAST_IPC_MAX_SLOTS - 1;
        assert_eq!(reply_now(last, SERVER, false, RSP), Some(1000 + last as u32));
        assert_eq!(fast_ipc_collect(handle_of(last), 1000 + last as u32), Some(RSP));
    }

    // ── wait-state accessor: the retry loop's oracle ───────────────────────

    #[test]
    fn wait_state_is_waiting_for_the_owner_before_the_reply() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        // Pending — server has not even accepted yet.
        assert_eq!(fast_ipc_wait_state(handle_of(idx), CLIENT), FastIpcWait::Waiting);
        let _ = fast_ipc_accept(SERVER).expect("accept");
        // Accepted — server owes an answer. Still "block again".
        assert_eq!(fast_ipc_wait_state(handle_of(idx), CLIENT), FastIpcWait::Waiting);
    }

    #[test]
    fn wait_state_is_ready_once_the_reply_is_deposited() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        // The client's handle for the exchange, captured while it lives —
        // collect frees the slot and bumps the generation, so the post-collect
        // probe below must use the handle the client actually held.
        let h = handle_of(idx);
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_wait_state(h, CLIENT), FastIpcWait::Ready);
        // ...and Ready must actually mean collect succeeds.
        assert_eq!(fast_ipc_collect(h, CLIENT), Some(RSP));
        // After collecting, the exchange is over: the client's own handle is
        // dead (state check catches it; the bumped generation would too).
        assert_eq!(fast_ipc_wait_state(h, CLIENT), FastIpcWait::Gone);
    }

    #[test]
    fn wait_state_is_gone_after_the_server_dies() {
        // The case the retry loop must not get wrong: blocking again here is
        // sleeping forever.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let h = handle_of(idx); // the client's view, captured before the free
        assert_eq!(fast_ipc_release_all(SERVER), 1);
        assert_eq!(fast_ipc_wait_state(h, CLIENT), FastIpcWait::Gone);
    }

    #[test]
    fn wait_state_is_gone_on_a_free_slot() {
        let _e = env();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(
                fast_ipc_wait_state(handle_of(idx), CLIENT),
                FastIpcWait::Gone,
                "idx {idx}"
            );
        }
    }

    #[test]
    fn wait_state_hides_live_slots_owned_by_somebody_else() {
        // IPC-1 through the back door: an index-only probe would be a state
        // oracle over the whole table. A live slot owned by another client
        // must be indistinguishable from an empty one.
        let _e = env();
        fill_and_accept_all();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            let owner = 1000 + idx as u32;
            let h = handle_of(idx);
            assert_eq!(fast_ipc_wait_state(h, owner), FastIpcWait::Waiting, "owner {owner}");
            assert_eq!(
                fast_ipc_wait_state(h, IMPOSTOR),
                FastIpcWait::Gone,
                "third party read slot {idx}"
            );
        }
        // Even after a reply lands, the third party learns nothing.
        assert_eq!(reply_now(0, SERVER, false, RSP), Some(1000));
        assert_eq!(fast_ipc_wait_state(handle_of(0), IMPOSTOR), FastIpcWait::Gone);
        assert_eq!(fast_ipc_wait_state(handle_of(0), 1000), FastIpcWait::Ready);
    }

    #[test]
    fn wait_state_hides_slots_from_the_free_sentinel_tid() {
        // Free slots carry FAST_IPC_SLOT_FREE in caller_tid; a probe using it
        // must not match them.
        let _e = env();
        let _ = call_idx(CLIENT, SERVER, REQ).expect("slot");
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert_eq!(
                fast_ipc_wait_state(handle_of(idx), FAST_IPC_SLOT_FREE),
                FastIpcWait::Gone,
                "idx {idx}"
            );
        }
    }

    #[test]
    fn wait_state_hostile_handles_never_panic_and_read_as_gone() {
        // `a0` is ring 3's to choose. Bit 63 set, out-of-range garbage in the
        // generation field, plausible-but-wrong values — everything must be
        // `Gone`, never a panic (`panic = "abort"` = board reset) and never
        // a peek at someone's slot.
        let _e = env();
        let _ = call_idx(CLIENT, SERVER, REQ).expect("slot");
        for h in [
            1u64 << 63,                 // negative-half handle: decode refuses
            u64::MAX,                   // ditto
            u64::MAX >> 1,              // bit 63 clear, absurd generation: mismatch
            FAST_IPC_MAX_SLOTS as u64,  // decodes as idx 0, generation 1: stale
            fast_ipc_make_handle(1, 7), // free seat, wrong gen: state check
        ] {
            assert_eq!(fast_ipc_wait_state(h, CLIENT), FastIpcWait::Gone, "h {h:#x}");
        }
    }

    #[test]
    fn wait_state_reports_gone_when_the_slot_is_reassigned() {
        // The ABA shape, from the *waiting client's* side — now closed by the
        // generation in the client handle, not merely contained by the TID
        // check. The second half is the case the TID check could never see:
        // the seat re-let to the SAME tid.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let stale = handle_of(idx); // the doomed exchange's handle
        assert_eq!(fast_ipc_wait_state(stale, CLIENT), FastIpcWait::Waiting);
        // CLIENT dies; the slot is recycled by a different client.
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        let reused = call_idx(IMPOSTOR, SERVER, REQ).expect("slot");
        assert_eq!(reused, idx, "test needs the same index to be reused");
        assert_eq!(fast_ipc_wait_state(stale, CLIENT), FastIpcWait::Gone);
        assert_eq!(fast_ipc_wait_state(handle_of(idx), IMPOSTOR), FastIpcWait::Waiting);

        // Same-tid recycle: IMPOSTOR's first exchange dies, IMPOSTOR calls
        // again and lands on the same seat. Its OLD handle must read Gone —
        // with a bare index this was indistinguishable from the live one.
        let old = handle_of(idx);
        assert_eq!(fast_ipc_release_all(IMPOSTOR), 1);
        let again = call_idx(IMPOSTOR, SERVER, REQ).expect("slot");
        assert_eq!(again, idx, "test needs the same index to be reused");
        assert_eq!(fast_ipc_wait_state(old, IMPOSTOR), FastIpcWait::Gone,
                   "stale-generation handle matched the re-let seat");
        assert_eq!(fast_ipc_wait_state(handle_of(idx), IMPOSTOR), FastIpcWait::Waiting);
    }

    #[test]
    fn wait_state_never_reports_ready_without_a_collectable_reply() {
        // The contract the retry loop leans on, swept over the whole table and
        // every lifecycle stage: Ready ⇒ collect succeeds.
        let _e = env();
        fill_and_accept_all();
        for idx in 0..FAST_IPC_MAX_SLOTS {
            let owner = 1000 + idx as u32;
            assert_ne!(fast_ipc_wait_state(handle_of(idx), owner), FastIpcWait::Ready);
            assert_eq!(fast_ipc_collect(handle_of(idx), owner), None);
        }
        for idx in 0..FAST_IPC_MAX_SLOTS {
            let owner = 1000 + idx as u32;
            assert_eq!(reply_now(idx, SERVER, false, RSP), Some(owner));
            assert_eq!(fast_ipc_wait_state(handle_of(idx), owner), FastIpcWait::Ready);
            assert_eq!(fast_ipc_collect(handle_of(idx), owner), Some(RSP));
        }
    }

    #[test]
    fn wait_state_stays_ready_when_the_server_dies_after_replying() {
        // Pairs with release_by_server_tid_preserves_an_already_deposited_reply:
        // the retry loop must still see Ready and hand the reply over.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_release_all(SERVER), 0);
        assert_eq!(fast_ipc_wait_state(handle_of(idx), CLIENT), FastIpcWait::Ready);
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP));
    }

    // ── IPC-3: reclamation on task death ───────────────────────────────────

    #[test]
    fn exhausting_the_table_kills_the_fast_path_until_release() {
        // This is the test whose absence let the leak kill the fast path in
        // silence: everything still "works", it just stops being fast.
        let _e = env();
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_call(1000 + i as u32, SERVER, REQ, NO_CAP).is_some(), "alloc {i}");
        }
        assert_eq!(fast_ipc_active(), FAST_IPC_MAX_SLOTS as u32);
        // Table full — dispatch would answer -1 ("fall back to channel IPC").
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_none());

        // The server dies: every slot it owns comes back.
        assert_eq!(fast_ipc_release_all(SERVER), FAST_IPC_MAX_SLOTS);
        assert_eq!(fast_ipc_active(), 0);

        // ...and the fast path is alive again.
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_some());
    }

    // ── RFC-0040 gap 2 stage 4: the stranded capability ───────────────

    #[test]
    fn a_pending_slot_freed_by_the_clients_death_revokes_the_moved_capability() {
        // The move happened in the client's trap, so the capability is
        // already in the SERVER's table. Freeing a `Pending` slot means the
        // request it travelled with will never be delivered, and the client
        // that sent it is gone — so there is nobody to move it back to and
        // the fail-closed answer is to destroy it.
        let _e = env();
        const MOVED: u32 = 0xBEEF;
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, MOVED).is_some());
        assert_eq!(fast_ipc_release_all(CLIENT), 1);

        assert_eq!(host_seam::revoked_count(), 1, "the capability was not revoked");
        assert_eq!(
            host_seam::revoked(0),
            Some((SERVER, MOVED)),
            "revoked the wrong capability, or from the wrong task",
        );
    }

    #[test]
    fn an_exchange_that_moved_nothing_revokes_nothing() {
        // The negative half: without it, a path that revoked on EVERY freed
        // slot would pass the test above and destroy capabilities it was
        // never given.
        let _e = env();
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).is_some());
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(host_seam::revoked_count(), 0);
    }

    #[test]
    fn an_accepted_slot_does_not_revoke_the_moved_capability() {
        // The server HAS seen the request here, so the capability is
        // legitimately its own and destroying it would take back authority
        // that was properly delivered. Only `Pending` strands one.
        let _e = env();
        const MOVED: u32 = 0xC0DE;
        assert!(fast_ipc_call(CLIENT, SERVER, REQ, MOVED).is_some());
        let (_, _, _, got) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(got, MOVED, "the accept did not report the moved capability");

        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(
            host_seam::revoked_count(), 0,
            "a delivered capability was revoked out of the server's table",
        );
    }

    #[test]
    fn release_by_client_tid_frees_the_slot_and_wakes_nobody() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(fast_ipc_active(), 0);
        assert_eq!(slot_state(idx), Some(SlotState::Free));
        // Nobody to wake: the dead task *is* the client.
        assert_eq!(host_seam::wake_count(), 0);
        // The server now finds nothing to accept, i.e. -1 at the syscall.
        assert!(fast_ipc_accept(SERVER).is_none());
    }

    #[test]
    fn release_by_server_tid_frees_the_slot_and_wakes_the_blocked_client() {
        // Decision under test: free + wake, no synthetic reply. The client
        // wakes, collects nothing, and dispatch answers -1.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        // The handle the sleeping client is blocked on — the orphan wake must
        // be minted with THIS (pre-free) generation, or it can never match
        // the sleeper (and could only match the seat's next tenant).
        let clients_handle = handle_of(idx);
        assert_eq!(fast_ipc_release_all(SERVER), 1);
        assert_eq!(fast_ipc_active(), 0);
        assert!(host_seam::was_woken(idx), "blocked client was not woken");
        assert_eq!(host_seam::wake_count(), 1);
        assert_eq!(
            host_seam::woken_handle(idx),
            Some(clients_handle),
            "orphan wake was minted with the wrong generation"
        );
        assert_eq!(fast_ipc_collect(clients_handle, CLIENT), None);
    }

    #[test]
    fn release_by_server_tid_wakes_client_of_an_accepted_slot_too() {
        // Server accepted and then died — the client is just as stuck as in
        // the Pending case, so it must be woken just the same.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        let clients_handle = handle_of(idx); // pre-free, same reasoning as above
        assert_eq!(fast_ipc_release_all(SERVER), 1);
        assert!(host_seam::was_woken(idx));
        assert_eq!(fast_ipc_collect(clients_handle, CLIENT), None);
    }

    #[test]
    fn release_wakes_every_orphaned_client_not_just_the_first() {
        let _e = env();
        for i in 0..FAST_IPC_MAX_SLOTS {
            assert!(fast_ipc_call(1000 + i as u32, SERVER, REQ, NO_CAP).is_some());
        }
        assert_eq!(fast_ipc_release_all(SERVER), FAST_IPC_MAX_SLOTS);
        assert_eq!(host_seam::wake_count(), FAST_IPC_MAX_SLOTS as u32);
        for idx in 0..FAST_IPC_MAX_SLOTS {
            assert!(host_seam::was_woken(idx), "slot {idx} not woken");
        }
    }

    #[test]
    fn release_touches_only_the_dead_tids_slots() {
        let _e = env();
        let a = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let b = call_idx(CLIENT, OTHER_SERVER, REQ).expect("slot");
        assert_eq!(fast_ipc_release_all(SERVER), 1);
        assert_eq!(slot_state(a), Some(SlotState::Free));
        assert_eq!(slot_state(b), Some(SlotState::Pending));
        assert_eq!(fast_ipc_active(), 1);
    }

    #[test]
    fn release_of_an_unrelated_or_sentinel_tid_is_a_noop() {
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        assert_eq!(fast_ipc_release_all(IMPOSTOR), 0);
        // u32::MAX is the "slot is free" sentinel: free slots carry it in both
        // TID fields, so a release keyed on it must not scavenge the table.
        assert_eq!(fast_ipc_release_all(FAST_IPC_SLOT_FREE), 0);
        assert_eq!(fast_ipc_active(), 1);
        assert_eq!(slot_state(idx), Some(SlotState::Pending));
        assert_eq!(host_seam::wake_count(), 0);
    }

    #[test]
    fn release_on_an_empty_table_is_a_noop() {
        let _e = env();
        assert_eq!(fast_ipc_release_all(SERVER), 0);
        assert_eq!(fast_ipc_active(), 0);
        assert_eq!(host_seam::wake_count(), 0);
    }

    #[test]
    fn release_by_server_tid_preserves_an_already_deposited_reply() {
        // The one-shot service: reply, then exit. On a single hart the exit
        // hook always runs before the woken client is scheduled, so reclaiming
        // a `Replied` slot here would deterministically turn every completed
        // exchange of that shape into a spurious -1.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_release_all(SERVER), 0, "reply was reclaimed");
        assert_eq!(fast_ipc_collect(handle_of(idx), CLIENT), Some(RSP), "reply was lost");
        assert_eq!(fast_ipc_active(), 0);
    }

    #[test]
    fn release_of_a_replied_but_uncollected_slot_frees_it() {
        // Client died after the server replied but before it woke: nothing to
        // wake (the dead task is the client), slot must still come back.
        let _e = env();
        let idx = call_idx(CLIENT, SERVER, REQ).expect("slot");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_now(idx, SERVER, false, RSP), Some(CLIENT));
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(fast_ipc_active(), 0);
        assert_eq!(host_seam::wake_count(), 0);
    }

    #[test]
    fn used_counter_never_desyncs_from_the_table() {
        // `used == 0` is the O(1) early-exit in both lookup helpers: if the
        // counter drifts above the real occupancy the helpers still work, but
        // if it drifts below zero-occupancy they go blind. Exercise a full
        // alloc/free cycle through every public entry point.
        let _e = env();
        for round in 0..3 {
            for i in 0..FAST_IPC_MAX_SLOTS {
                assert!(fast_ipc_call(1000 + i as u32, SERVER, REQ, NO_CAP).is_some());
            }
            assert_eq!(fast_ipc_active(), FAST_IPC_MAX_SLOTS as u32, "round {round}");
            if round % 2 == 0 {
                for i in 0..FAST_IPC_MAX_SLOTS {
                    let (handle, caller, _, _) = fast_ipc_accept(SERVER).expect("accept");
                    assert_eq!(reply_h(handle, SERVER, false, RSP), Some(caller));
                    assert_eq!(fast_ipc_collect(handle, caller), Some(RSP));
                    let _ = i;
                }
            } else {
                assert_eq!(fast_ipc_release_all(SERVER), FAST_IPC_MAX_SLOTS);
            }
            assert_eq!(fast_ipc_active(), 0, "round {round}");
            assert!(fast_ipc_accept(SERVER).is_none());
        }
    }

    /// **`pending` is a cache, so the test is the boring one: it must equal the
    /// count it caches after every transition.** It lets an `accept` with
    /// nothing to take answer in one comparison instead of scanning 64 slots, so
    /// a count that drifted UP would only cost time, but one that drifted DOWN
    /// (a `Pending` slot the counter forgot) would make `accept` answer "nothing
    /// pending" while a caller waits: a lost request, the caller blocked for
    /// good. Random alloc / accept / reply / free of a slot in any state, with
    /// the fast answer compared to the naive scan at every step.
    #[test]
    fn pending_matches_the_slots_through_any_sequence_of_transitions() {
        let mut st = FastIpcState::new();
        // xorshift: deterministic, so a failure names its step.
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        for step in 0..8000u64 {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            let server = 100 + ((s >> 8) as u32 % 3);
            let i = (s >> 12) as usize % FAST_IPC_MAX_SLOTS;
            match (s >> 33) % 4 {
                0 => { let _ = st.alloc_slot(1 + (s as u32 % 7), server, [step, 0, 0, 0], NO_CAP, NO_DONEE); }
                1 => { if let Some(at) = st.find_pending_for_server(server) { st.mark_accepted(at); } }
                2 => { if st.slots[i].state == SlotState::Accepted { st.slots[i].state = SlotState::Replied; } }
                // Any occupied slot, Pending included: a caller that dies with its
                // request untaken frees a `Pending` slot, the easy one to forget.
                _ => { if st.slots[i].state != SlotState::Free { st.free_slot(i); } }
            }
            let want = st.slots.iter().filter(|x| x.state == SlotState::Pending).count() as u32;
            assert_eq!(st.pending, want, "`pending` drifted from the slots at step {step}");
            for srv in 100..103u32 {
                let naive = st.slots.iter().position(|x| x.state == SlotState::Pending && x.server_tid == srv);
                assert_eq!(st.find_pending_for_server(srv), naive, "server {srv} at step {step}");
            }
        }
    }


    // ── Wave 11 PIFAST: the donation riding on an exchange ────────────────
    //
    // The caller donates before the call and publishes the target with the
    // request; whoever retires the exchange first takes it back. These tests
    // count the returns each path hands out: a missing one leaves the server
    // at the client's priority for good, a second one drops it under a donor
    // still waiting (the counted return saturates, so it would not even show).

    fn donee_of(idx: usize) -> u32 {
        lock_fast_ipc().slots.get(idx).map(|s| s.donee).unwrap_or(0)
    }

    fn reply_donee(handle: u64, tid: u32, privileged: bool) -> Option<u32> {
        match fast_ipc_reply(handle, tid, privileged, RSP) {
            FastIpcReply::Woke { donee, .. } => Some(donee),
            FastIpcReply::Stale | FastIpcReply::Refused => None,
        }
    }

    #[test]
    fn a_donation_is_published_with_the_request_and_the_reply_takes_it() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let idx = fast_ipc_handle_slot(h).expect("idx");
        assert_eq!(donee_of(idx), SERVER, "published with the request");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_donee(ah, SERVER, false), Some(SERVER), "the reply returns it");
        assert_eq!(donee_of(idx), NO_DONEE);
        // Nobody else can return it again: the client's withdrawal and the
        // exit sweep both find nothing.
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), NO_DONEE);
        fast_ipc_release_all(CLIENT);
        assert_eq!(host_seam::undonated_count(), 0);
    }

    #[test]
    fn a_call_without_a_donation_hands_none_back() {
        let _e = env();
        let h = fast_ipc_call(CLIENT, SERVER, REQ, NO_CAP).expect("call");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_donee(ah, SERVER, false), Some(NO_DONEE));
        assert_eq!(fast_ipc_collect(h, CLIENT), Some(RSP));
        assert_eq!(fast_ipc_release_all(SERVER), 0);
        assert_eq!(host_seam::undonated_count(), 0);
    }

    /// A donating call that finds no free slot publishes nothing and owes
    /// nothing: the donation it made is returned before it answers `None`.
    #[test]
    fn a_donation_for_a_call_with_no_free_slot_is_returned_at_once() {
        let _e = env();
        for i in 0..FAST_IPC_MAX_SLOTS {
            host_seam::set_tid_live(40 + i as u32, true);
            assert!(fast_ipc_call(40 + i as u32, SERVER, REQ, NO_CAP).is_some());
        }
        assert!(fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).is_none());
        assert_eq!(host_seam::undonated_count(), 1);
        assert_eq!(host_seam::undonated(0), Some(SERVER));
        // And a call that did not donate returns nothing.
        host_seam::set_donate(false);
        assert!(fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).is_none());
        assert_eq!(host_seam::undonated_count(), 1);
    }

    /// A privileged replier answering another server's slot hands back the
    /// TID recorded at the call, not its own.
    #[test]
    fn the_reply_returns_the_recorded_target_not_the_replier() {
        let _e = env();
        let _h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_donee(ah, IMPOSTOR, true), Some(SERVER));
    }

    /// Reply + accept with nothing pending: the server hands off and blocks,
    /// so it owes nothing and the client's collect hands the donation back.
    #[test]
    fn reply_then_accept_that_will_block_leaves_the_donation_to_the_client() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        let (r, next) = fast_ipc_reply_then_accept(ah, SERVER, false, RSP, SERVER);
        assert_eq!(r, FastIpcReply::Woke { caller_tid: CLIENT, slot_idx: fast_ipc_handle_slot(ah).unwrap(), donee: NO_DONEE });
        assert!(next.is_none());
        assert_eq!(fast_ipc_collect_donated(h, CLIENT), Some((RSP, SERVER)));
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), NO_DONEE);
    }

    /// Reply + accept with the next request already pending: no hand-off,
    /// the server keeps running, so it returns the donation itself.
    #[test]
    fn reply_then_accept_with_work_pending_returns_the_donation_at_the_server() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let _ = fast_ipc_call(IMPOSTOR, SERVER, REQ, NO_CAP).expect("second call");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        let (r, next) = fast_ipc_reply_then_accept(ah, SERVER, false, RSP, SERVER);
        assert_eq!(r, FastIpcReply::Woke { caller_tid: CLIENT, slot_idx: fast_ipc_handle_slot(ah).unwrap(), donee: SERVER });
        assert!(next.is_some());
        assert_eq!(fast_ipc_collect_donated(h, CLIENT), Some((RSP, NO_DONEE)));
    }

    /// The retry loop can run out on the turn the reply landed: the client
    /// leaves with the slot `Replied` and the donation left for it.
    #[test]
    fn a_replied_slot_holding_the_donation_can_be_withdrawn() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        let _ = fast_ipc_reply_then_accept(ah, SERVER, false, RSP, SERVER);
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), SERVER);
        assert_eq!(fast_ipc_collect_donated(h, CLIENT), Some((RSP, NO_DONEE)));
    }

    /// The client giving up (retry loop exhausted) takes the donation back
    /// once; the server's late reply then returns nothing.
    #[test]
    fn a_client_that_gives_up_withdraws_the_donation_exactly_once() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), SERVER, "Pending: withdrawn");
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), NO_DONEE, "only once");
        let (ah, _, _, _) = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(reply_donee(ah, SERVER, false), Some(NO_DONEE), "late reply returns nothing");
    }

    #[test]
    fn an_accepted_exchange_can_be_withdrawn_but_not_by_anyone_else() {
        let _e = env();
        let h = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_withdraw_donation(h, IMPOSTOR), NO_DONEE, "not its exchange");
        // A forged generation names a different exchange in the same seat.
        let forged = fast_ipc_make_handle(fast_ipc_handle_slot(h).unwrap(), handle_generation(h) + 1);
        assert_eq!(fast_ipc_withdraw_donation(forged, CLIENT), NO_DONEE, "stale generation");
        assert_eq!(fast_ipc_withdraw_donation(u64::MAX, CLIENT), NO_DONEE, "malformed handle");
        assert_eq!(fast_ipc_withdraw_donation(h, CLIENT), SERVER, "the owner's own");
    }

    /// A client that dies mid-call: nobody else is left to return its
    /// donation, so the exit sweep does — once, to the server.
    #[test]
    fn a_dying_client_returns_its_donation_through_the_exit_sweep() {
        let _e = env();
        let _ = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("pending");
        let _ = fast_ipc_call_donating(IMPOSTOR, SERVER, REQ, NO_CAP, true).expect("other");
        let _ = fast_ipc_accept(SERVER).expect("accept CLIENT's");
        assert_eq!(fast_ipc_release_all(CLIENT), 1);
        assert_eq!(host_seam::undonated_count(), 1);
        assert_eq!(host_seam::undonated(0), Some(SERVER));
    }

    /// A server that dies with clients waiting: its own boost is not
    /// returned (the target is the task being torn down).
    #[test]
    fn a_dying_server_returns_nothing_to_itself() {
        let _e = env();
        let _ = fast_ipc_call_donating(CLIENT, SERVER, REQ, NO_CAP, true).expect("call");
        let _ = fast_ipc_call_donating(IMPOSTOR, SERVER, REQ, NO_CAP, true).expect("call");
        let _ = fast_ipc_accept(SERVER).expect("accept");
        assert_eq!(fast_ipc_release_all(SERVER), 2);
        assert_eq!(host_seam::undonated_count(), 0);
    }

    /// The leak test: random donating and plain calls, accepts, replies,
    /// withdrawals, collects and deaths, with a ledger of donations owed. No
    /// step may return more than was donated, and once every task has gone
    /// the ledger is zero and no slot still carries a target.
    #[test]
    fn every_donation_comes_back_exactly_once_through_any_sequence() {
        let _e = env();
        const CLIENTS: [u32; 4] = [30, 31, 32, 33];
        for c in CLIENTS { host_seam::set_tid_live(c, true); }
        let mut owed: i64 = 0;
        let mut handles: [Option<u64>; 4] = [None; 4];
        let mut accepted: [Option<u64>; 4] = [None; 4];
        let mut seen_undonated = 0usize;
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..20_000u64 {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            let k = (s >> 20) as usize % CLIENTS.len();
            let c = CLIENTS[k];
            match (s >> 40) % 7 {
                0 => {
                    if handles[k].is_none() {
                        let donate = (s >> 3) & 1 == 1;
                        if let Some(h) = fast_ipc_call_donating(c, SERVER, REQ, NO_CAP, donate) {
                            handles[k] = Some(h);
                            if donate { owed += 1; }
                        }
                    }
                }
                1 => {
                    if let Some((ah, caller, _, _)) = fast_ipc_accept(SERVER) {
                        let j = CLIENTS.iter().position(|&x| x == caller).expect("known caller");
                        accepted[j] = Some(ah);
                    }
                }
                2 => {
                    if let Some(ah) = accepted[k].take() {
                        // Plain reply or reply + accept, at random.
                        let d = if (s >> 5) & 1 == 1 {
                            reply_donee(ah, SERVER, false)
                        } else {
                            let (r, next) = fast_ipc_reply_then_accept(ah, SERVER, false, RSP, SERVER);
                            if let Some((nh, caller, _, _)) = next {
                                let j = CLIENTS.iter().position(|&x| x == caller).expect("known caller");
                                accepted[j] = Some(nh);
                            }
                            match r { FastIpcReply::Woke { donee, .. } => Some(donee), _ => None }
                        };
                        match d {
                            Some(d) if d != NO_DONEE => { assert_eq!(d, SERVER); owed -= 1; }
                            _ => {}
                        }
                    }
                }
                3 => {
                    if let Some(h) = handles[k] {
                        let d = fast_ipc_withdraw_donation(h, c);
                        if d != NO_DONEE { assert_eq!(d, SERVER); owed -= 1; }
                    }
                }
                4 => {
                    if let Some(h) = handles[k] {
                        if let Some((_, d)) = fast_ipc_collect_donated(h, c) {
                            if d != NO_DONEE { assert_eq!(d, SERVER); owed -= 1; }
                            handles[k] = None;
                            accepted[k] = None;
                        }
                    }
                }
                5 => {
                    // The client dies (and is replaced by a fresh one with the same TID
                    // for the test's purposes — the slots it held are gone).
                    fast_ipc_release_all(c);
                    handles[k] = None;
                    accepted[k] = None;
                }
                _ => {
                    // The client gives up on its call (the retry loop exhausted):
                    // it withdraws, as `fast_ipc_call_arm` does, and moves on. The
                    // exchange stays for the server to answer into the void.
                    if (s >> 50) % 8 == 0 {
                        if let Some(h) = handles[k].take() {
                            let d = fast_ipc_withdraw_donation(h, c);
                            if d != NO_DONEE { assert_eq!(d, SERVER); owed -= 1; }
                        }
                    }
                }
            }
            while let Some(t) = host_seam::undonated(seen_undonated) {
                assert_eq!(t, SERVER);
                owed -= 1;
                seen_undonated += 1;
            }
            // The host log holds 64 entries: drain it every step.
            host_seam::clear_undonated();
            seen_undonated = 0;
            assert!(owed >= 0, "more returned than donated at step {step}");
        }
        for c in CLIENTS { fast_ipc_release_all(c); }
        while let Some(t) = host_seam::undonated(seen_undonated) {
            assert_eq!(t, SERVER);
            owed -= 1;
            seen_undonated += 1;
        }
        assert_eq!(owed, 0, "donations never returned");
        let st = lock_fast_ipc();
        assert!(st.slots.iter().all(|x| x.donee == NO_DONEE), "a slot still carries a target");
    }
}
