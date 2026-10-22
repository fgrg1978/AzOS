// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The component manager's supervision tree: which components start, in which
//! order, and what happens to them and to the ones that depend on them when
//! one ends.
//!
//! Pure given a [`Host`] (spawn, stop, clock, record, failure contracts): no
//! syscall, no allocation, fixed tables. `tests/host/compmgr-tests` pulls this
//! file in with `#[path]`, so the code under test is the code `COMPMGR.ELF`
//! is built from.
//!
//! # Input: the view
//!
//! The kernel renders the signed topology rows the manager starts as
//! `/proc/components` (readable only by the component manager's own row), one
//! line per component, in the order to start them (the console program last):
//!
//! ```text
//! <image> <always|on-failure|no> <serves,...|-> <needs,...|-> [dir]
//! ...
//! end
//! ```
//!
//! `dir` is the directory of the image when it is not `/fat` (an image an
//! applied package brought is in `/pkg/APPS`); the manager spawns `dir/image`.
//!
//! The closing `end` line is what says the view is whole: a procfs file is
//! cut where its buffer ends ([`VIEW_MAX`]), and a row cut mid-line could
//! parse as a row with a shorter `needs` list, which is a lost dependency. A
//! view without it is [`EventKind::ViewRejected`] as a whole, its last (cut)
//! line is dropped, and the rows before it are used.
//!
//! `serves` are the endpoints the row holds the serving half of, `needs` the
//! endpoints it holds the calling half of or may import. There is no
//! `depends_on` key in the topology: **a dependency is a consequence of
//! authority.** A component depends on every listed component that serves an
//! endpoint it needs; a need nobody listed serves (the kernel serves it, or
//! the server is not started) is no dependency. The start order is the view's
//! order, moved only as far as the dependencies require (a stable
//! topological sort); components on a cycle cannot be ordered and are
//! [`EventKind::Blocked`], not started.
//!
//! # The tree
//!
//! One supervisor (the manager) over the components, like Erlang/OTP's
//! `one_for_one` and `rest_for_one` strategies, with two deliberate
//! differences: the restart intensity is counted **per component** (as the
//! kernel's supervisor it replaces counted it, and as systemd's
//! `StartLimitBurst` does), so one flapping service cannot spend the budget
//! of the others; and a restart is paced, each one after the first in a window
//! waiting `cooldown` after the previous one.
//!
//! * **Strategy, from the failure contract.** The contract is the strongest
//!   `#[on_failure(..)]` among the ops of the interfaces the component serves
//!   ([`Host::contract`]). A server that declares nothing promises nothing
//!   about its callers surviving it, so its dependents are restarted behind it
//!   ([`Strategy::RestForOne`]: stopped, and started again after it, in
//!   order). A declared `restart`, `degrade` or `safe_state` is that promise
//!   (callers ask again, are refused, or find the effect safe): only the
//!   component itself is restarted ([`Strategy::OneForOne`]).
//! * **`escalate` is not restarted here.** The failure is handed up; the
//!   manager is the root, so it records it ([`EventKind::Escalate`]), stops
//!   the component's dependents and leaves the component down. A
//!   `safe_state` failure is recorded ([`EventKind::SafeState`]) before the
//!   restart; driving the effect to its safe state is the device path's.
//! * **Whether a restart happens at all** is the row's `restart` key, as
//!   systemd's `Restart=`: `on-failure` restarts a failure (non-zero exit,
//!   a fault, a stop request, a spawn that was refused), not a clean exit;
//!   `always` restarts a clean exit too; `no` restarts nothing.
//! * **Intensity.** At most `burst` restarts within `interval` per component;
//!   the failure after that is final ([`EventKind::GiveUp`]): the component
//!   stays down, and so do the ones that depend on it ([`EventKind::Blocked`]).
//!   A restart older than the interval no longer counts.
//!
//! Every start, restart, clean end, give-up, escalation and refusal is one
//! [`Event`] given to [`Host::record`].

use azos_idl::OnFailure;

/// Components at once. At most 32: the dependency sets are one `u32` each.
pub const MAX_COMPONENTS: usize = 24;
/// Longest image name kept (an 8.3 name is 12).
pub const NAME_MAX: usize = 16;
/// Longest image directory kept (`/pkg/APPS` is 9).
pub const DIR_MAX: usize = 16;
/// Bytes of the view read: the procfs file bound
/// (`azos_fs::procfs::PROCFS_MAX_FILE`; `tests/host/compmgr-tests` fails when
/// the two differ).
pub const VIEW_MAX: usize = 2048;
/// The closing line of a whole view.
pub const VIEW_END: &[u8] = b"end\n";
/// Largest `burst` an [`Intensity`] may name.
pub const BURST_MAX: usize = 16;

const _: () = assert!(MAX_COMPONENTS <= 32);

/// What ends of a component are restarted: the row's `restart` key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Restart {
    /// A failure is restarted, a clean exit is final.
    OnFailure,
    /// Every end is restarted, a clean exit included.
    Always,
    /// No end is restarted.
    No,
}

impl Restart {
    fn parse(w: &[u8]) -> Option<Restart> {
        match w {
            b"on-failure" => Some(Restart::OnFailure),
            b"always" => Some(Restart::Always),
            b"no" => Some(Restart::No),
            _ => None,
        }
    }
}

/// What a failure takes with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strategy {
    /// The failed component alone is restarted.
    OneForOne,
    /// The failed component is restarted and so is everything that depends
    /// on it, after it.
    RestForOne,
}

/// The restart limit, in nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Intensity {
    /// Restarts allowed within `interval`, 1..=[`BURST_MAX`] (clamped).
    pub burst: u8,
    /// The window restarts are counted in.
    pub interval_ns: u64,
    /// The pause between two restarts in one window.
    pub cooldown_ns: u64,
}

/// Where a component is in its life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Should run; not running yet (waiting for its dependencies or for the
    /// cooldown of a restart).
    Wanted,
    /// Its task is alive.
    Running,
    /// Stopped on purpose so it can start again behind a restarted
    /// dependency; becomes `Wanted` when its exit is seen. Not a failure.
    Stopping,
    /// Ended on purpose (clean exit under `on-failure`, any end under `no`).
    /// Final.
    Exited,
    /// Its budget is spent, or it escalated. Final.
    Down,
    /// Cannot run: it is on a dependency cycle, or a component it depends on
    /// is down. Final.
    Blocked,
}

/// What the tree did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// First start: `tid` is the task.
    Start,
    /// A successor was started: `attempt` of the burst, `code` the failure it
    /// replaces.
    Restart,
    /// It ended on purpose and is not restarted: `code` its exit code.
    Exit,
    /// Its budget is spent: `attempt` restarts were granted, `code` the
    /// failure that was not restarted.
    GiveUp,
    /// Its failure contract is `escalate`: `code` the failure, handed up.
    Escalate,
    /// Its failure contract is `safe_state`: `code` the failure.
    SafeState,
    /// A running dependent was stopped (`tid`): its dependency is restarting
    /// (`rest_for_one`) or down.
    Stopped,
    /// It cannot run (see [`State::Blocked`]).
    Blocked,
    /// The spawn of its image failed with `code`; counted as a failure.
    SpawnRefused,
    /// A line of the view was not a component and was skipped; or the view had
    /// no closing line (it was cut) and its last line was dropped.
    ViewRejected,
}

/// One record.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    pub kind: EventKind,
    /// The component's image name (the view line's, for `ViewRejected`).
    pub name: &'a [u8],
    pub tid: u32,
    pub code: i32,
    pub attempt: u8,
}

/// What the tree needs from its surroundings.
pub trait Host {
    /// Start the image named `image`, found in `dir` (empty: `/fat`)
    /// (`SYS_SPAWN_EX`); its TID, or a negative errno. The row of the image
    /// grants everything the child holds: the manager passes no handle.
    fn spawn(&mut self, dir: &[u8], image: &[u8]) -> Result<u32, i32>;
    /// Ask the task `tid` to stop (`SYS_ALERT`, forced).
    fn stop(&mut self, tid: u32);
    /// The monotonic clock, nanoseconds.
    fn now_ns(&mut self) -> u64;
    /// Write one record.
    fn record(&mut self, e: &Event<'_>);
    /// The failure contract of the interface served on `endpoint`: the
    /// strongest `#[on_failure(..)]` among its ops, `None` when it declares
    /// none or the endpoint is not one with an interface.
    fn contract(&mut self, endpoint: &[u8]) -> Option<OnFailure>;
}

#[derive(Clone, Copy)]
struct Comp {
    name: [u8; NAME_MAX],
    name_len: u8,
    dir: [u8; DIR_MAX],
    dir_len: u8,
    restart: Restart,
    strategy: Strategy,
    contract: Option<OnFailure>,
    /// Components this one waits for: bit `i` is component `i`.
    deps: u32,
    state: State,
    /// The task standing for it, 0 for none. Kept while `Blocked` or `Down`
    /// until its exit is seen.
    tid: u32,
    /// When each restart still inside the interval was granted, oldest first.
    window: [u64; BURST_MAX],
    window_n: u8,
    /// The earliest the next start may happen.
    not_before: u64,
    /// The failure that put it in `Wanted`, for the `Restart` record; and
    /// whether the next start is a restart.
    last_code: i32,
    restarting: bool,
}

impl Comp {
    const fn empty() -> Comp {
        Comp {
            name: [0; NAME_MAX],
            name_len: 0,
            dir: [0; DIR_MAX],
            dir_len: 0,
            restart: Restart::OnFailure,
            strategy: Strategy::OneForOne,
            contract: None,
            deps: 0,
            state: State::Wanted,
            tid: 0,
            window: [0; BURST_MAX],
            window_n: 0,
            not_before: 0,
            last_code: 0,
            restarting: false,
        }
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Which failure handling is more demanding: the one order, for merging the
/// contracts of the endpoints one component serves and of the ops of one
/// interface (`contracts::strongest`).
pub fn severity(f: OnFailure) -> u8 {
    match f {
        OnFailure::Degrade => 1,
        OnFailure::Restart => 2,
        OnFailure::SafeState => 3,
        OnFailure::Escalate => 4,
    }
}

fn split_list(w: &[u8]) -> impl Iterator<Item = &[u8]> {
    w.split(|&c| c == b',').filter(|e| !e.is_empty() && *e != b"-")
}

/// One parsed line of the view.
struct Line<'a> {
    name: &'a [u8],
    restart: Restart,
    serves: &'a [u8],
    needs: &'a [u8],
    /// Empty for `/fat`.
    dir: &'a [u8],
}

fn parse_line(l: &[u8]) -> Option<Line<'_>> {
    let mut w = l.split(|&c| c == b' ').filter(|w| !w.is_empty());
    let name = w.next()?;
    let restart = Restart::parse(w.next()?)?;
    let serves = w.next()?;
    let needs = w.next()?;
    let dir = w.next().unwrap_or(b"");
    if w.next().is_some() || name.len() > NAME_MAX || dir.len() > DIR_MAX || (!dir.is_empty() && dir[0] != b'/') {
        return None;
    }
    Some(Line { name, restart, serves, needs, dir })
}

fn lines(view: &[u8]) -> impl Iterator<Item = &[u8]> {
    view.split(|&c| c == b'\n').filter(|l| !l.iter().all(|&c| c == b' '))
}

/// The rows of `view`, and whether it was whole. A whole view ends in
/// [`VIEW_END`]; any other is cut, and what follows its last newline is a
/// partial line, which is not a row.
fn rows_of(view: &[u8]) -> (&[u8], bool) {
    if let Some(body) = view.strip_suffix(VIEW_END) {
        if body.is_empty() || body.ends_with(b"\n") {
            return (body, true);
        }
    }
    let whole = view.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);
    (&view[..whole], false)
}

/// Read the view into `buf` with `read`, which fills a prefix of the slice it
/// is given and returns its length, 0 at the end of the file, or a negative
/// errno (the VFS hands a file out in pieces of at most one page). The length
/// read, or the errno of the read that failed. A view that failed to read is
/// no view, not a cut one ([`Tree::load`] supervises the rows of a cut view;
/// rows from a failed read would be supervised as if they were all of them).
pub fn read_view(buf: &mut [u8], mut read: impl FnMut(&mut [u8]) -> isize) -> Result<usize, isize> {
    let mut got = 0;
    while got < buf.len() {
        let n = read(&mut buf[got..]);
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            break;
        }
        got += n as usize;
    }
    Ok(got)
}

/// The tree.
pub struct Tree {
    comps: [Comp; MAX_COMPONENTS],
    n: usize,
    /// Start order: indexes into `comps`, dependencies first.
    order: [u8; MAX_COMPONENTS],
    order_n: usize,
    intensity: Intensity,
}

impl Tree {
    /// An empty tree with the restart limit `intensity` (const: the manager
    /// keeps its tree in a static, not on a small stack).
    pub const fn new(intensity: Intensity) -> Tree {
        let burst = if intensity.burst < 1 {
            1
        } else if intensity.burst as usize > BURST_MAX {
            BURST_MAX as u8
        } else {
            intensity.burst
        };
        Tree {
            comps: [Comp::empty(); MAX_COMPONENTS],
            n: 0,
            order: [0; MAX_COMPONENTS],
            order_n: 0,
            intensity: Intensity { burst, ..intensity },
        }
    }

    /// Fill the tree from the kernel's view. Lines that are not components,
    /// or past [`MAX_COMPONENTS`], are recorded and skipped; components on a
    /// dependency cycle are recorded and [`State::Blocked`]. Call once, on a
    /// tree from [`Self::new`].
    pub fn load(&mut self, view: &[u8], host: &mut impl Host) {
        let (view, whole) = rows_of(view);
        if !whole {
            host.record(&Event {
                kind: EventKind::ViewRejected, name: b"(view cut: no end line)", tid: 0, code: 0, attempt: 0,
            });
        }
        // Components, with their contracts.
        for l in lines(view) {
            let parsed = parse_line(l).filter(|_| self.n < MAX_COMPONENTS);
            let Some(p) = parsed else {
                let shown = &l[..l.len().min(NAME_MAX)];
                host.record(&Event { kind: EventKind::ViewRejected, name: shown, tid: 0, code: 0, attempt: 0 });
                continue;
            };
            let mut c = Comp::empty();
            c.name[..p.name.len()].copy_from_slice(p.name);
            c.name_len = p.name.len() as u8;
            c.dir[..p.dir.len()].copy_from_slice(p.dir);
            c.dir_len = p.dir.len() as u8;
            c.restart = p.restart;
            for ep in split_list(p.serves) {
                if let Some(f) = host.contract(ep) {
                    if c.contract.map_or(true, |g| severity(f) > severity(g)) {
                        c.contract = Some(f);
                    }
                }
            }
            c.strategy = if c.contract.is_some() { Strategy::OneForOne } else { Strategy::RestForOne };
            self.comps[self.n] = c;
            self.n += 1;
        }
        // Dependencies: a component waits for the listed servers of what it
        // needs.
        let mut i = 0;
        for l in lines(view) {
            let Some(p) = parse_line(l).filter(|_| i < self.n) else { continue };
            for need in split_list(p.needs) {
                let mut k = 0;
                for l2 in lines(view) {
                    let Some(q) = parse_line(l2).filter(|_| k < self.n) else { continue };
                    if k != i && split_list(q.serves).any(|s| s == need) {
                        self.comps[i].deps |= 1 << k;
                    }
                    k += 1;
                }
            }
            i += 1;
        }
        // Stable topological order: the first component, in view order,
        // whose dependencies are all placed.
        let mut placed = 0u32;
        loop {
            let next = (0..self.n).find(|&j| placed & (1 << j) == 0 && self.comps[j].deps & !placed == 0);
            let Some(j) = next else { break };
            self.order[self.order_n] = j as u8;
            self.order_n += 1;
            placed |= 1 << j;
        }
        for j in 0..self.n {
            if placed & (1 << j) == 0 {
                self.comps[j].state = State::Blocked;
                let c = self.comps[j];
                host.record(&Event { kind: EventKind::Blocked, name: c.name(), tid: 0, code: 0, attempt: 0 });
            }
        }
    }

    /// Start every component that can start now, in order.
    pub fn start_all(&mut self, host: &mut impl Host) {
        self.reconcile(host);
    }

    /// The earliest time a component that is waiting only for its cooldown
    /// may start; `None` when none is.
    pub fn wake_at(&self) -> Option<u64> {
        let satisfied = |c: &Comp| self.deps_satisfied(c);
        self.comps[..self.n]
            .iter()
            .filter(|c| c.state == State::Wanted && satisfied(c))
            .map(|c| c.not_before)
            .min()
    }

    /// Start whatever is due. Call after the [`Self::on_exit`]s of one reap
    /// and when the clock reaches [`Self::wake_at`].
    pub fn tick(&mut self, host: &mut impl Host) {
        self.reconcile(host);
    }

    fn deps_satisfied(&self, c: &Comp) -> bool {
        (0..self.n).all(|d| {
            c.deps & (1 << d) == 0 || matches!(self.comps[d].state, State::Running | State::Exited)
        })
    }

    /// The components that depend on `i`, directly or not.
    fn dependents_of(&self, i: usize) -> u32 {
        let mut set = 1u32 << i;
        loop {
            let mut more = set;
            for j in 0..self.n {
                if self.comps[j].deps & set != 0 {
                    more |= 1 << j;
                }
            }
            if more == set {
                return set & !(1 << i);
            }
            set = more;
        }
    }

    fn reconcile(&mut self, host: &mut impl Host) {
        let now = host.now_ns();
        for oi in 0..self.order_n {
            let i = self.order[oi] as usize;
            let c = self.comps[i];
            if c.state != State::Wanted || !self.deps_satisfied(&c) || now < c.not_before {
                continue;
            }
            self.launch(i, host);
        }
    }

    fn launch(&mut self, i: usize, host: &mut impl Host) {
        let (name, dir) = (self.comps[i].name, self.comps[i].dir);
        let name = &name[..self.comps[i].name_len as usize];
        match host.spawn(&dir[..self.comps[i].dir_len as usize], name) {
            Ok(tid) => {
                let c = &mut self.comps[i];
                c.tid = tid;
                c.state = State::Running;
                let kind = if c.restarting { EventKind::Restart } else { EventKind::Start };
                let ev = Event { kind, name, tid, code: c.last_code, attempt: c.window_n };
                c.restarting = false;
                host.record(&ev);
            }
            Err(rc) => {
                host.record(&Event { kind: EventKind::SpawnRefused, name, tid: 0, code: rc, attempt: self.comps[i].window_n });
                self.fail(i, rc, false, host);
            }
        }
    }

    /// A child of the manager ended with `code`. `false` when no component
    /// has that task.
    ///
    /// **Nothing is started here.** Call it for every child that has ended,
    /// then [`Self::tick`] once: a session's tasks end together (the shell
    /// hangs up and the terminal server ends with it), and a component started
    /// between their two reaps would be started behind a server that is
    /// already gone, only to be stopped, or to fail on its own and spend the
    /// restart budget of a crash that was not its own.
    pub fn on_exit(&mut self, tid: u32, code: i32, host: &mut impl Host) -> bool {
        if tid == 0 {
            return false;
        }
        let Some(i) = self.comps[..self.n].iter().position(|c| c.tid == tid) else { return false };
        let now = host.now_ns();
        let c = &mut self.comps[i];
        c.tid = 0;
        match c.state {
            // Stopped for a sibling's restart: comes back, no charge.
            State::Stopping => {
                c.state = State::Wanted;
                c.not_before = now;
            }
            State::Running => {
                let clean = code == 0;
                if c.restart == Restart::No || (clean && c.restart == Restart::OnFailure) {
                    c.state = State::Exited;
                    let name = c.name;
                    let name = &name[..c.name_len as usize];
                    host.record(&Event { kind: EventKind::Exit, name, tid, code, attempt: c.window_n });
                } else {
                    self.fail(i, code, clean, host);
                }
            }
            // Its end was already decided.
            _ => {}
        }
        true
    }

    /// Decide what the end of component `i` means. `clean`: a clean exit of
    /// an `always` component, which no failure contract applies to.
    fn fail(&mut self, i: usize, code: i32, clean: bool, host: &mut impl Host) {
        let now = host.now_ns();
        let name = self.comps[i].name;
        let name = &name[..self.comps[i].name_len as usize];
        if !clean {
            match self.comps[i].contract {
                Some(OnFailure::Escalate) => {
                    host.record(&Event { kind: EventKind::Escalate, name, tid: 0, code, attempt: self.comps[i].window_n });
                    self.comps[i].state = State::Down;
                    self.block_dependents(i, host);
                    return;
                }
                Some(OnFailure::SafeState) => {
                    host.record(&Event { kind: EventKind::SafeState, name, tid: 0, code, attempt: self.comps[i].window_n });
                }
                _ => {}
            }
        }
        let Intensity { burst, interval_ns, cooldown_ns } = self.intensity;
        let c = &mut self.comps[i];
        // Drop the restarts that left the window.
        let mut kept = 0;
        for k in 0..c.window_n as usize {
            if now.wrapping_sub(c.window[k]) < interval_ns {
                c.window[kept] = c.window[k];
                kept += 1;
            }
        }
        c.window_n = kept as u8;
        if kept >= burst as usize {
            c.state = State::Down;
            host.record(&Event { kind: EventKind::GiveUp, name, tid: 0, code, attempt: c.window_n });
            self.block_dependents(i, host);
            return;
        }
        // Immediate when none came before in the window, else paced.
        c.not_before = if kept == 0 { now } else { now.max(c.window[kept - 1].saturating_add(cooldown_ns)) };
        c.window[kept] = now;
        c.window_n += 1;
        c.last_code = code;
        c.restarting = true;
        c.state = State::Wanted;
        if c.strategy == Strategy::RestForOne {
            self.stop_dependents(i, host);
        }
    }

    /// `rest_for_one`: stop the running dependents of `i`; they start again
    /// behind it.
    fn stop_dependents(&mut self, i: usize, host: &mut impl Host) {
        let set = self.dependents_of(i);
        for j in 0..self.n {
            if set & (1 << j) == 0 {
                continue;
            }
            let c = &mut self.comps[j];
            if c.state == State::Running {
                c.state = State::Stopping;
                c.restarting = true;
                c.last_code = 0;
                let name = c.name;
                let ev = Event { kind: EventKind::Stopped, name: &name[..c.name_len as usize], tid: c.tid, code: 0, attempt: 0 };
                host.stop(c.tid);
                host.record(&ev);
            }
        }
    }

    /// `i` is down for good: its dependents can never run.
    fn block_dependents(&mut self, i: usize, host: &mut impl Host) {
        let set = self.dependents_of(i);
        for j in 0..self.n {
            if set & (1 << j) == 0 {
                continue;
            }
            let c = &mut self.comps[j];
            if matches!(c.state, State::Down | State::Blocked | State::Exited) {
                continue;
            }
            let was_running = c.state == State::Running || c.state == State::Stopping;
            let name = c.name;
            let name = &name[..c.name_len as usize];
            let tid = c.tid;
            c.state = State::Blocked;
            if was_running {
                host.stop(tid);
                host.record(&Event { kind: EventKind::Stopped, name, tid, code: 0, attempt: 0 });
            }
            host.record(&Event { kind: EventKind::Blocked, name, tid: 0, code: 0, attempt: 0 });
        }
    }
}

/// What the host tests look at; the manager itself never needs it.
#[cfg(test)]
impl Tree {
    /// Components in the tree (including blocked ones).
    pub fn len(&self) -> usize {
        self.n
    }

    /// The state of the component named `name`.
    pub fn state_of(&self, name: &[u8]) -> Option<State> {
        self.comps[..self.n].iter().find(|c| c.name() == name).map(|c| c.state)
    }

    /// The strategy of the component named `name`.
    pub fn strategy_of(&self, name: &[u8]) -> Option<Strategy> {
        self.comps[..self.n].iter().find(|c| c.name() == name).map(|c| c.strategy)
    }

    /// The start order, as image names.
    pub fn order(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.order[..self.order_n].iter().map(move |&i| self.comps[i as usize].name())
    }
}
