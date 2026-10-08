// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A native fork child's capabilities and descriptors (wave 13, NATFORK;
//! RFC-0040 gap 3 for descriptors).
//!
//! Owner decision, round 49: a native `fork` child inherits its parent's
//! descriptors as duplicates sharing the open description (POSIX), and its
//! capabilities are seeded from its OWN topology row, never copied from the
//! parent's table. That is the model a Linux child already has
//! (`linux::fork_child_setup`). A fork child runs the parent's image, so its
//! row is the parent's row, which [`record_row`] remembers per task.
//!
//! # Handles are the names, so the child answers to the parent's
//!
//! A native program names a file or a pipe by its raw handle and keeps those
//! names in its own memory (libsys's small-fd table), which the child gets a
//! copy-on-write copy of. So [`native_child_setup`] builds the child's table
//! slot for slot against the parent's:
//!
//! 1. Every parent entry is walked in chunks. A file (not a directory-tree
//!    authority) or a pipe end is duplicated: another descriptor on the same
//!    open file description (`ops.dup`, owner moved to the child), or another
//!    reference to the same pipe end, installed at the parent's exact handle.
//!    Any other entry is installed as a placeholder at its handle, so the row
//!    seeding below cannot land on a slot the parent uses.
//! 2. The row is seeded. A minted capability that is exactly one the parent
//!    holds (kind, permissions, resource) keeps that placeholder, which is
//!    then the same capability, and the fresh copy goes: a handle the parent
//!    looked up before the fork names the same capability in the child. One
//!    the parent no longer holds keeps the slot it was minted in.
//! 3. Every placeholder left is removed, keeping its generation: each parent
//!    handle naming something the child does not hold is stale in the child,
//!    and a later grant in that slot gets a newer generation.
//!
//! Sockets, untyped (`SYS_OPEN`) descriptors and every runtime object the
//! parent created (ports, shared memory, rings, channels) are not inherited.
//! The parent-owned endpoint bootstrap (`endpoint_inherit_at_fork`) runs
//! after this, into free slots.
//!
//! # `dup` stays aliasing
//!
//! libsys `dup`/`dup2` alias small fds onto one handle, and the Linux
//! personality's `dup3` does the same in its kernel-side table (one handle
//! per open description per process, per-fd close-on-exec kept beside it).
//! Both reach one `OpenDesc`, so offsets are already shared as POSIX
//! requires, and a fork duplicates each distinct handle once. A kernel `dup`
//! per alias would spend a capability slot and a descriptor for no change in
//! semantics, and would make the two personalities differ.
//!
//! # Lock order
//!
//! Never two at once: the parent's table lock (a chunk is copied out), then,
//! with it released, the descriptor table (`KERNEL_FD_TABLE`, inside
//! `ops.dup`/`set_owner`) or the pipe pool, then the child's table lock.
//! Runs in the parent's context before the child can run (the `before_release`
//! hook of `sys_fork_impl_hooked`).
//!
//! Thread groups (wave 13 THREADS) share one table among siblings; a sibling
//! closing a descriptor between two chunks of step 1 makes that descriptor
//! absent in the child, which is the answer a fork racing a close may give.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_ipc::cap::MAX_CAPS_PER_TASK;
use azos_sched::task::MAX_TASKS;

// ── The row a task was seeded from ──────────────────────────────────────────

/// Per pool slot: `tid << 32 | (row index + 1)`, 0 for none. Tagged with the
/// TID so a reused slot never answers for its previous occupant.
static ROW: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

/// Remember that `tid` was seeded from topology row `row` (an index into
/// `Topology::tasks`).
pub fn record_row(tid: u32, row: usize) {
    if let Some(idx) = azos_sched::idx_for_tid(tid) {
        ROW[idx].store((tid as u64) << 32 | (row as u64 + 1), Ordering::Release);
    }
}

/// [`record_row`] by the row's name, for the autorun loader.
pub fn record_row_named(tid: u32, key: &[u8]) {
    if let Some(row) = row_index(key) {
        record_row(tid, row);
    }
}

/// Wave 15 (plan 4a): the seed row recorded for the process on slot `from`
/// (its leader's) moves to slot `to`, which now holds the process's TID
/// `tid` (an exec from a thread that was not the leader).
pub fn hand_over(from: usize, to: usize, tid: u32) {
    if from >= MAX_TASKS || to >= MAX_TASKS {
        return;
    }
    let v = ROW[from].swap(0, Ordering::AcqRel);
    if v >> 32 == tid as u64 {
        ROW[to].store(v, Ordering::Release);
    }
}

/// The row `tid` was seeded from, if it was.
pub fn row_of(tid: u32) -> Option<usize> {
    let idx = azos_sched::idx_for_tid(tid)?;
    let v = ROW[idx].load(Ordering::Acquire);
    (v >> 32 == tid as u64 && v as u32 != 0).then(|| (v as u32 - 1) as usize)
}

/// The index of the installed topology's row named `key`.
pub fn row_index(key: &[u8]) -> Option<usize> {
    let topo = azos_topology::get()?;
    let name = azos_topology::MaybeStr::from_bytes(key);
    topo.tasks().iter().position(|t| t.name == name)
}

// ── The child's table ───────────────────────────────────────────────────────

/// Entries copied out of the parent's table per lock hold.
const CHUNK: usize = 16;
/// Parent entries remembered as candidates for a row capability to take
/// over; past this many, a row capability simply keeps the slot it was
/// minted in.
const CANDIDATES: usize = 64;
const WORDS: usize = MAX_CAPS_PER_TASK.div_ceil(64);

/// Build `child`'s capability table from `parent`'s descriptors and their
/// shared row (see the module doc). `false` if a descriptor could not be
/// duplicated; the fork then fails and the child never runs.
pub(crate) fn native_child_setup(parent: u32, child: u32) -> bool {
    let row = row_of(parent);
    let row_kinds = row.map_or(0u64, row_kind_mask);
    let mut placeholder = [0u64; WORDS];
    let mut cand = [(CapHandle::from_raw(0), 0u32); CANDIDATES];
    let mut ncand = 0usize;

    let t_ph = azos_sched::prof::t();
    // 1. Descriptors at the parent's handles, placeholders for the rest.
    let mut from = 0usize;
    loop {
        let mut chunk = [(CapHandle::from_raw(0), 0u32); CHUNK];
        let Some((n, next)) =
            azos_ipc::cap_store::with_table(parent, |t| t.scan(from, &mut chunk, |_| true))
        else {
            return false;
        };
        // Descriptors one by one (each duplicate is made with no table lock
        // held), then this chunk's placeholders under one hold of the child's.
        let mut keep = [false; CHUNK];
        for (k, &(h, res)) in chunk[..n].iter().enumerate() {
            let kind = CapKind::from_raw(h.kind()).unwrap_or(CapKind::Null);
            if inherits(kind, res) {
                if !inherit_one(parent, child, h, kind, res) {
                    return false;
                }
            } else {
                keep[k] = true;
            }
        }
        let placed = azos_ipc::cap_store::with_table(child, |t| {
            chunk[..n].iter().zip(keep).all(|(&(h, res), k)| !k || t.install_at(h, res))
        });
        if placed != Some(true) {
            return false;
        }
        for (&(h, res), k) in chunk[..n].iter().zip(keep) {
            if !k {
                continue;
            }
            let s = h.slot() as usize;
            placeholder[s / 64] |= 1 << (s % 64);
            if row_kinds & (1u64 << (h.kind() & 63)) != 0 && ncand < CANDIDATES {
                cand[ncand] = (h, res);
                ncand += 1;
            }
        }
        if next >= MAX_CAPS_PER_TASK {
            break;
        }
        from = next;
    }

    azos_sched::prof::add(8, t_ph);
    let t_ph = azos_sched::prof::t();
    // 2. The row, each capability on the parent's handle for it if it has one.
    if let Some(row) = row {
        record_row(child, row);
        let filter = azos_sched::scheduler::current_syscall_filter();
        seed_child_row(child, row, &filter, &mut placeholder, &mut cand[..ncand]);
    }

    azos_sched::prof::add(9, t_ph);
    let t_ph = azos_sched::prof::t();
    // 3. Whatever the child does not hold goes stale at the parent's handle.
    #[cfg(not(feature = "native-fork-copy-canary"))]
    {
        let _ = azos_ipc::cap_store::with_table(child, |t| {
            for (w, bits) in placeholder.iter().enumerate() {
                let mut b = *bits;
                while b != 0 {
                    let s = w * 64 + b.trailing_zeros() as usize;
                    b &= b - 1;
                    t.clear_slot(s);
                }
            }
        });
    }
    azos_sched::prof::add(10, t_ph);
    true
}

/// Is `(kind, res)` a descriptor a fork child inherits?
fn inherits(kind: CapKind, res: u32) -> bool {
    if cfg!(feature = "native-fork-no-inherit-canary") {
        return false;
    }
    match kind {
        CapKind::Pipe => true,
        CapKind::File => !azos_ipc::file_cap::is_tree_resource(res),
        _ => false,
    }
}

/// Give `child` its own reference to what `parent`'s `h` names, at `h`.
fn inherit_one(parent: u32, child: u32, h: CapHandle, kind: CapKind, res: u32) -> bool {
    match kind {
        CapKind::Pipe => {
            let w = h.perms().contains(CapPerms::WRITE);
            if !azos_ipc::pipe::pipe_typed_add_end(res, w) {
                return false;
            }
            if azos_ipc::cap_store::with_table(child, |t| t.install_at(h, res)) == Some(true) {
                true
            } else {
                let _ = azos_ipc::pipe::pipe_typed_drop_end(res, w);
                false
            }
        }
        _ => {
            let Some(ops) = crate::file_ops::file_ops() else { return false };
            let nfd = ops.dup(res as i32);
            if nfd < 0 {
                return false;
            }
            if ops.set_owner(nfd as i32, parent, child) != 0 {
                let _ = ops.close(nfd as i32);
                return false;
            }
            // Owned by the child from here: its exit closes it if the
            // install fails.
            azos_ipc::cap_store::with_table(child, |t| t.install_at(h, nfd as u32)) == Some(true)
        }
    }
}

/// The candidate holding exactly `(kind, perms, res)`, searched from
/// `cursor` round: rows mint in a fixed order, so the parent's copies are
/// usually met in the same order and each search is one step.
fn find_candidate(
    cand: &[(CapHandle, u32)],
    cursor: &mut usize,
    kind: CapKind,
    perms: CapPerms,
    res: u32,
) -> Option<usize> {
    let n = cand.len();
    for k in 0..n {
        let i = (*cursor + k) % n;
        let (h, r) = cand[i];
        if r == res && h.kind() == kind as u8 && h.perms() == perms {
            *cursor = i + 1;
            return Some(i);
        }
    }
    None
}

// ── The row's seed, minted once (per-row template) ──────────────────────────
//
// Re-running every minter on every fork cost about 1.1k instructions per row
// capability (wave 13 measurement: 27 caps, +30k per fork+exit+wait). A
// minter of a kind that names no live object (`!objref::is_packed_kind`: a
// pin, a channel number of the board, a sensor type, an interned path or
// image name, a singleton) answers the same for the same row on every call:
// its result is a pure function of the row and the board. So the first fork
// of a row records what each declared capability minted into a template, and
// later forks of that row install those exact `(kind, perms, resource)`
// entries. Kinds that name a live object (endpoints, channels: index and
// object generation) are minted again every time, as are entries the
// template has no answer for (withheld under the first fork's filter).
//
// Authority stays the row's: the template holds only what the row's own
// minters produced, never anything read from a parent's table. It is sealed
// (a checksum over the row, the topology and every entry); an entry changed
// after it was recorded fails the seal, and the template is then dropped and
// rebuilt from the minters, never served (canaries
// `natfork-template-tamper-canary`, `natfork-template-noseal-canary`).

/// Row capabilities a template can hold; a longer row is minted every time.
const TMAX: usize = 64;
/// Rows with a template at once (replaced round-robin).
const TSLOTS: usize = 4;
const T_UNKNOWN: u8 = 0;
const T_MINTED: u8 = 1;
const T_NONE: u8 = 2;

#[derive(Clone, Copy)]
struct TEnt {
    state: u8,
    kind: u8,
    perms: u8,
    res: u32,
}
const TENT_NONE: TEnt = TEnt { state: T_UNKNOWN, kind: 0, perms: 0, res: 0 };

#[derive(Clone, Copy)]
struct Template {
    /// Row index + 1; 0 = free.
    row: u32,
    n: u32,
    seal: u64,
    ents: [TEnt; TMAX],
}
const TEMPLATE_NONE: Template = Template { row: 0, n: 0, seal: 0, ents: [TENT_NONE; TMAX] };

struct Templates {
    t: [Template; TSLOTS],
    next: usize,
}
static TEMPLATES: azos_sync::spinlock::SpinLock<Templates> =
    azos_sync::spinlock::SpinLock::new(Templates { t: [TEMPLATE_NONE; TSLOTS], next: 0 });
/// Templates refused by their seal since boot (each was rebuilt).
static TEMPLATE_SEAL_FAILS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A seal over the row, the topology's address and every entry: a 64-bit
/// multiply-xor mix per word (wave 13: the byte-wise FNV-1a it replaced cost
/// ~880 instructions per fork). Not a MAC: it catches an entry changed in
/// memory after it was recorded, which is what the template guards against.
fn seal_of(row: u32, n: u32, ents: &[TEnt]) -> u64 {
    let topo = azos_topology::get().map_or(0usize, |t| t as *const _ as usize) as u64;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (row as u64) << 32 ^ n as u64;
    let mut mix = |v: u64| {
        h = (h ^ v).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        h ^= h >> 29;
    };
    mix(topo);
    for e in ents {
        mix((e.state as u64) | (e.kind as u64) << 8 | (e.perms as u64) << 16 | (e.res as u64) << 32);
    }
    h
}

/// The sealed template of `row`, copied out; `None` without one. A template
/// whose seal fails is dropped (and the drop counted and said once).
fn template_get(row: usize) -> Option<Template> {
    let key = row as u32 + 1;
    let mut g = TEMPLATES.lock();
    let i = g.t.iter().position(|t| t.row == key)?;
    let t = g.t[i];
    if !cfg!(feature = "natfork-template-noseal-canary")
        && seal_of(t.row, t.n, &t.ents[..t.n as usize]) != t.seal
    {
        g.t[i] = TEMPLATE_NONE;
        drop(g);
        if TEMPLATE_SEAL_FAILS.fetch_add(1, Ordering::Relaxed) == 0 {
            azos_drv_sys::kwarn!(
                "[FORK] row {} capability template failed its seal: dropped, minted again", row);
        }
        return None;
    }
    Some(t)
}

fn template_put(row: usize, n: usize, ents: &[TEnt; TMAX]) {
    let mut t = Template { row: row as u32 + 1, n: n as u32, seal: 0, ents: *ents };
    t.seal = seal_of(t.row, t.n, &t.ents[..n]);
    #[cfg(feature = "natfork-template-tamper-canary")]
    {
        // Gate canary: the first entropy entry gains WRITE after the seal.
        if let Some(e) = t.ents[..n].iter_mut().find(|e| {
            e.state == T_MINTED && e.kind == CapKind::Entropy as u8
        }) {
            e.perms |= CapPerms::WRITE.bits();
        }
    }
    let mut g = TEMPLATES.lock();
    let i = match g.t.iter().position(|x| x.row == t.row || x.row == 0) {
        Some(i) => i,
        None => {
            let i = g.next % TSLOTS;
            g.next = g.next.wrapping_add(1);
            i
        }
    };
    g.t[i] = t;
}

/// Seed `child` from row `row` under `filter` (the parent's, inherited):
/// from the row's template where it has an answer, through the minters
/// otherwise, recording a template on the first fork of the row. Each
/// capability that is exactly one of the parent's placeholders keeps that
/// slot (see the module doc).
fn seed_child_row(
    child: u32,
    row: usize,
    filter: &azos_sched::filter::SyscallFilter,
    placeholder: &mut [u64; WORDS],
    cand: &mut [(CapHandle, u32)],
) {
    let Some(topo) = azos_topology::get() else { return };
    let Some(task) = topo.tasks().get(row) else { return };
    let specs = topo.caps_of(task);
    let n = specs.len();
    let tpl = if n <= TMAX { template_get(row) } else { None };
    let mut al = Aligner { cand, cursor: 0, placeholder };
    let mut remint = [false; TMAX];
    if let Some(tpl) = tpl {
        // One hold of the child's table for every entry the template answers.
        let _ = azos_ipc::cap_store::with_table(child, |t| {
            for (i, cap) in specs.iter().enumerate() {
                if crate::spawn::withheld(cap.kind, filter) {
                    continue;
                }
                let e = tpl.ents[i];
                match e.state {
                    T_MINTED => {
                        let kind = CapKind::from_raw(e.kind).unwrap_or(CapKind::Null);
                        let perms = CapPerms::from_bits_truncate(e.perms);
                        if !al.take(kind, perms, e.res) {
                            let _ = t.grant_raw(kind, perms, e.res);
                        }
                    }
                    T_NONE => {}
                    _ => remint[i] = true,
                }
            }
        });
        for (i, cap) in specs.iter().enumerate() {
            if remint[i] {
                let _ = mint_one(child, cap, &mut al);
            }
        }
        return;
    }
    // No template: every minter, recording what each pure kind produced.
    let mut ents = [TENT_NONE; TMAX];
    for (i, cap) in specs.iter().enumerate() {
        if crate::spawn::withheld(cap.kind, filter) {
            continue;
        }
        let got = mint_one(child, cap, &mut al);
        if i < TMAX && !azos_ipc::cap::objref::is_packed_kind(cap.kind) {
            ents[i] = match got {
                Some((kind, perms, res)) => {
                    TEnt { state: T_MINTED, kind: kind as u8, perms: perms.bits(), res }
                }
                None => TEnt { state: T_NONE, ..TENT_NONE },
            };
        }
    }
    if n <= TMAX {
        template_put(row, n, &ents);
    }
}

/// Matches a row capability with the parent's placeholder holding exactly
/// it (see [`find_candidate`]).
struct Aligner<'a> {
    cand: &'a mut [(CapHandle, u32)],
    cursor: usize,
    placeholder: &'a mut [u64; WORDS],
}

impl Aligner<'_> {
    /// `true` if a parent placeholder holds exactly `(kind, perms, res)`: it
    /// stays, as the row's capability, and is no longer a placeholder.
    fn take(&mut self, kind: CapKind, perms: CapPerms, res: u32) -> bool {
        let Some(i) = find_candidate(self.cand, &mut self.cursor, kind, perms, res) else {
            return false;
        };
        let s = self.cand[i].0.slot() as usize;
        self.cand[i].0 = CapHandle::from_raw(0); // taken: kind Null matches nothing
        self.placeholder[s / 64] &= !(1 << (s % 64));
        true
    }
}

/// Mint one row capability into `child` through its minter; if the parent's
/// placeholder already is that capability, the fresh mint goes. What it
/// minted.
fn mint_one(
    child: u32,
    cap: &azos_topology::CapSpec<'_>,
    al: &mut Aligner<'_>,
) -> Option<(CapKind, CapPerms, u32)> {
    let perms = if cap.transfer { cap.perms.union(CapPerms::DUP) } else { cap.perms };
    let azos_ipc::cap_seed::SeedOutcome::Minted(m) =
        azos_ipc::cap_seed::seed_one_cap_outcome(child, cap.kind, perms, cap.target.as_str())
    else {
        return None;
    };
    azos_ipc::cap_store::with_table(child, |t| {
        let (kind, perms, res) = t.peek_raw(m)?;
        if al.take(kind, perms, res) {
            t.revoke_raw(m);
        }
        Some((kind, perms, res))
    })
    .flatten()
}

/// Bit `k` set iff row `row` declares a capability of kind `k`.
fn row_kind_mask(row: usize) -> u64 {
    let Some(topo) = azos_topology::get() else { return 0 };
    let Some(task) = topo.tasks().get(row) else { return 0 };
    topo.caps_of(task).iter().fold(0u64, |m, c| m | 1u64 << ((c.kind as u8) & 63))
}
