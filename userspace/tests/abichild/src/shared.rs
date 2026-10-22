// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What `abitest` and `abichild` both need to watch a process tree: a wait
//! bounded by the guest's clock, the task list of the kernel's introspection
//! tree (the admin region, which their row is granted against the task view),
//! and reaping a child by its TID. `abitest` includes this file with `#[path]`.

use azos_inspect_lib::{str_in, u64_in, Inspector, Source, Value};
use azos_libsys as sys;

/// A poll bounded by the guest's clock, not by a number of passes.
///
/// Every wait in these programs used to be `for _ in 0..N { poll; yield }`. A
/// yield count measures scheduling luck: a pass costs whatever the other harts
/// and the host leave to this vCPU, so under host load 400,000 yields expired
/// before a loopback datagram crossed the stack (gate 193, `mem quota lets real
/// work through`: timer-ISR jitter 12 ms in the same window). QEMU's clock
/// follows the host's, so a deadline in milliseconds holds under load.
///
/// `vdso_uptime_ms()` reads 0 when no vDSO page is published; the wait then
/// falls back to a pass ceiling instead of never ending.
///
/// The clock that follows the host's also jumps with it. A host that stops
/// QEMU's threads (gs2: the row ran 3-15x its usual time) lets a deadline
/// pass while this loop ran nothing, and the wait failed with its event done
/// or about to be: a 25 s SIGSTOP in the thread storm failed the join of a
/// thread whose word already read 0, and the reap of a child that had exited.
/// So a gap between two passes longer than any pass can take (`STALL_MS`;
/// the longest body blocks 100 ms) is time the loop was not running, and it
/// moves the deadline by as much: the wait gets its whole budget of running
/// time. A wait still expires when the guest runs and the event does not come.
pub struct Deadline {
    end_ms: u64,
    last_ms: u64,
    passes: u32,
}

impl Deadline {
    /// Passes allowed when there is no clock to read.
    const NO_CLOCK_PASSES: u32 = 200_000;
    /// A gap between two passes longer than this is a stall, not a pass.
    const STALL_MS: u64 = 1_000;

    pub fn in_ms(ms: u64) -> Self {
        let now = sys::vdso_uptime_ms();
        Deadline { end_ms: if now == 0 { 0 } else { now + ms }, last_ms: now, passes: 0 }
    }

    /// Counts one pass; true once the deadline has gone by in running time.
    pub fn expired(&mut self) -> bool {
        self.passes += 1;
        if self.end_ms == 0 {
            return self.passes > Self::NO_CLOCK_PASSES;
        }
        let now = sys::vdso_uptime_ms();
        let gap = now.saturating_sub(self.last_ms);
        if gap > Self::STALL_MS {
            self.end_ms += gap;
        }
        self.last_ms = now;
        now >= self.end_ms
    }
}

/// The introspection tree, mapped once: the public region and the admin one.
static TREE: TreeCell = TreeCell(core::cell::UnsafeCell::new(None));

struct TreeCell(core::cell::UnsafeCell<Option<Option<Inspector<'static>>>>);
// SAFETY: these programs read the tree from their main thread only.
unsafe impl Sync for TreeCell {}

/// The tree, mapped at the first call (a region maps once per task).
pub fn tree() -> Option<&'static mut Inspector<'static>> {
    // SAFETY: the main thread's alone (see `TreeCell`).
    let t = unsafe { &mut *TREE.0.get() };
    if t.is_none() {
        let public = sys::inspect_map(azos_abi::cap::SHM_INSPECT_PUBLIC).ok();
        let admin = sys::inspect_map(azos_abi::cap::SHM_INSPECT_ADMIN).ok();
        // SAFETY: the mappings live as long as the task, read-only, and the
        // kernel writes them only with aligned 64-bit stores.
        *t = Some(public.and_then(|p| unsafe { Inspector::from_mapped(p, admin) }.ok()).filter(|v| v.has_admin()));
    }
    t.as_mut().and_then(|v| v.as_mut())
}

/// The admin task list (`sched/tasks/<row>/{tid, parent, state}`) as (TID,
/// parent TID, state) rows, read now: the kernel writes a row where the task
/// changes, so a task made, exited or reaped before the call is shown as it
/// is (no wait). How many; `None` if it cannot be read.
pub fn task_rows(rows: &mut [(u32, u32, u8); 64]) -> Option<usize> {
    let t = tree()?;
    t.with(Source::Admin, |r| {
        let mut count = 0;
        let Some(dir) = r.lookup("sched/tasks")? else { return Ok(0) };
        r.children(dir, &mut |info, v| {
            if !matches!(v, Value::Dir) {
                return;
            }
            // A free row shows TID 0.
            let tid = u64_in(r, info.id, "tid").ok().flatten().unwrap_or(0) as u32;
            if tid == 0 {
                return;
            }
            let parent = u64_in(r, info.id, "parent").ok().flatten().unwrap_or(0) as u32;
            let state = str_in(r, info.id, "state").ok().flatten().and_then(|s| s.as_bytes().first().copied()).unwrap_or(b'?');
            if count < rows.len() {
                rows[count] = (tid, parent, state);
            }
            count += 1;
        })?;
        Ok(count)
    })
    .ok()
}

/// Has `tid` exited? A task that has exited is no longer a row of the task
/// list (its slot is reaped at once; what the parent has not yet collected is
/// the exit NOTICE, which holds a place in the notice table, not a task
/// slot), or is there for an instant in state `Z` while the scheduler tears
/// it down. The list is the full view, so "no row" is "gone".
pub fn task_exited(tid: u32) -> bool {
    let mut rows = [(0u32, 0u32, 0u8); 64];
    let Some(n) = task_rows(&mut rows) else { return false }; // unreadable: not an answer
    rows[..n.min(rows.len())].iter().find(|r| r.0 == tid).is_none_or(|r| r.2 == b'Z')
}

/// The parent the task list shows for `tid` (0 when it has no row).
pub fn parent_of(tid: u32) -> u32 {
    let mut rows = [(0u32, 0u32, 0u8); 64];
    let n = task_rows(&mut rows).unwrap_or(0).min(rows.len());
    rows[..n].iter().find(|r| r.0 == tid).map(|r| r.1).unwrap_or(0)
}

/// The live tasks the task list shows with parent `parent`: how many, and
/// the last one listed. Polls (clock deadline) until there is exactly one,
/// so an adoption still in flight is waited for.
pub fn children_of(parent: u32) -> (usize, u32) {
    let mut rows = [(0u32, 0u32, 0u8); 64];
    let mut deadline = Deadline::in_ms(5_000);
    let mut last = (0, 0);
    while !deadline.expired() {
        let n = task_rows(&mut rows).unwrap_or(0).min(rows.len());
        last = (0, 0);
        for r in &rows[..n] {
            if r.1 == parent && r.0 != parent {
                last = (last.0 + 1, r.0);
            }
        }
        if last.0 == 1 {
            break;
        }
        sys::sleep(5);
    }
    last
}

/// The only child the task list shows for `parent`; 0 for none or several.
pub fn only_child_of(parent: u32) -> u32 {
    match children_of(parent) {
        (1, t) => t,
        _ => 0,
    }
}

/// Reap `pid` by TID within 20 s of clock: `(reaped, exit status)`.
pub fn reap_by_tid(pid: isize) -> (isize, i32) {
    let mut st: i32 = -12345;
    let mut got = -1isize;
    let mut deadline = Deadline::in_ms(20_000);
    while !deadline.expired() {
        got = sys::waitpid(pid as u32, &mut st as *mut i32);
        if got > 0 { break; }
        sys::sleep(1);
    }
    (got, st)
}

/// The image every process of the tree runs, NUL-terminated for `spawn_ex`.
pub const CHILD_IMAGE: &[u8] = b"/fat/ABICHILD.ELF\0";

/// Start `ABICHILD.ELF` with `args` as its argv after its own name: the first
/// names what the child does, the rest are its parameters (decimal text, a
/// name). Returns the child's TID, or the kernel's negative code.
pub fn spawn_child(args: &[&[u8]]) -> isize {
    let mut argv = [0u8; 256];
    let mut len = 0usize;
    let mut put = |s: &[u8]| -> bool {
        if len + s.len() + 1 > argv.len() { return false; }
        argv[len..len + s.len()].copy_from_slice(s);
        argv[len + s.len()] = 0;
        len += s.len() + 1;
        true
    };
    if !put(b"abichild") { return sys::E_INVAL; }
    for a in args {
        if !put(a) { return sys::E_INVAL; }
    }
    let req = sys::SpawnReq {
        version: sys::SPAWN_REQ_VERSION,
        argv_ptr: argv.as_ptr() as u64,
        argv_bytes: len as u32,
        argc: (args.len() + 1) as u32,
        ..sys::SpawnReq::default()
    };
    sys::spawn_ex(CHILD_IMAGE, Some(&req))
}

/// `n` as decimal text in `buf`; the digits.
pub fn dec(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// The decimal text `s` as a number (`None` for anything else, or an overflow).
pub fn parse_dec(s: &[u8]) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}
