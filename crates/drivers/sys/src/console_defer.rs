// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Console ownership: ring 3 owns the UART with interrupts on, kernel lines
//! written meanwhile wait in a bounded buffer the owner drains (wave 9).
//!
//! # Why
//!
//! A ring-3 `write(1|2, ..)` used to go out in 16-byte pieces, one UART
//! spinlock hold (interrupts masked) each, and a `kprintln!` from any hart or
//! any interrupt handler could land between two pieces: gate 192b read
//! `[IPCTEST] ALL PA[SCHED-DBG]   ASKS-SCHED ...`, a timer-ISR line inside a
//! ring-3 marker. Holding the spinlock for a whole line closes that, but masks
//! interrupts for a line of wire time (≈ 10 ms per 128 B at 115200 baud). The
//! owner chose this shape instead (2026-09-28), the one Linux's printk uses:
//! the writer that owns the console puts its line on the wire with
//! interrupts ON, and everybody else hands their output to it.
//!
//! # The protocol
//!
//! Every field below is touched only under the caller's lock — in the kernel
//! the UART spinlock (`uart::acquire`/`try_acquire`, interrupts masked), in
//! the host tests a `Mutex`. That single lock is what makes each step atomic:
//!
//! * **Kernel output** ([`ConsoleDefer::kernel_write`], called with the lock
//!   already held for the whole line): if nobody owns the console and
//!   nothing is deferred it goes to the wire directly, exactly as before. If
//!   the console is owned, or a residual is waiting (below), the bytes are
//!   appended to the buffer, so order is kept, and the call returns. It waits for the owner only as long as one of
//!   the owner's lock holds (a copy of at most [`DRAIN_CHUNK`] bytes), never
//!   for its wire time, so an interrupt handler on the owner's own hart
//!   cannot deadlock against it (the owner never holds the lock with
//!   interrupts on).
//! * **The owner** ([`owner_write`]): take ownership under the lock, drop the
//!   lock, write its line with interrupts on, then drain what the kernel
//!   deferred meanwhile, chunk by chunk, each chunk copied out under the lock
//!   and written with it released. It gives the console back only when the
//!   buffer is empty, checked and released in ONE lock hold — so no kernel
//!   byte can be appended after the check and stranded behind a released
//!   console.
//! * **Bounded release.** A kernel printer faster than the wire would keep
//!   that buffer from ever being empty, and the owner would never return from
//!   `write`. So each drain has a byte budget ([`DRAIN_BUDGET`]); when it runs
//!   out, the owner releases with bytes still deferred (a residual), and the
//!   next kernel line (or the next owner) drains them first. Nothing is lost
//!   or reordered by this.
//! * **A kernel writer that finds a residual** ([`kernel_print`]) never
//!   flushes it inside its own lock hold (that was up to one buffer of wire
//!   time with interrupts masked: ≈ 30 ms under QEMU, ≈ 0.7 s at 115200
//!   baud). In task context (interrupts on at entry, no spinlock held:
//!   [`may_own`]) it takes the SAME
//!   ownership ring 3 takes — the caller's line lock, then `owned` — drains
//!   with interrupts on exactly as the ring-3 owner does, writes its own
//!   line, and releases in the lock hold that sees the buffer empty. In an
//!   interrupt handler, with interrupts already masked, or under a spinlock,
//!   it may not own
//!   the console: it puts at most one [`DRAIN_CHUNK`] of the residual on
//!   the wire and defers its own line behind the rest. Either way the
//!   interrupts-masked window of a kernel line is one chunk or its own
//!   direct line, never the residual. A residual nobody is left to drain
//!   (a quiet system) is drained from the idle loop ([`idle_drain`]).
//!
//! # The wire may be a queue (wave 11)
//!
//! In the kernel the "wire" is a TX ring the UART's interrupt drains, and a
//! writer holding the lock may not wait for room in it. So a direct kernel
//! write puts what fits ([`Wire::put`]) and defers the rest in this buffer,
//! as if the console were owned; everything after it defers behind it, and
//! the usual drains carry it on. A line starts on the ring only if the ring
//! has [`LINE_RESERVE`] bytes of room, else all of it defers: otherwise its
//! head could reach the wire while a full buffer drops its tail. A line
//! longer than that, and only one, can still be cut that way when ring and
//! buffer are both full (which already prints `[CONSOLE] dropped`).
//!
//! # Overflow: drop whole lines, with a count
//!
//! The buffer is [`crate::uart::DEFER_BYTES`] long in the kernel. When an
//! append does not fit, the partial line at its tail is cut back to the last
//! newline and everything is dropped up to and including the next newline,
//! so the wire never carries half a kernel line. The count of dropped bytes
//! and lines is put on the wire as one line ([`drop_marker`]) the next time
//! the buffer empties. An interrupt handler never waits on the owner's wire
//! time: dropping is its only failure mode.
//!
//! This file is ISA-neutral and dependency-free on purpose:
//! `tests/host/drivers-tests` pulls it in with `#[path]` and runs the whole
//! protocol with threads standing in for harts.

/// Largest number of bytes one drain step copies out under the lock. The
/// interrupt-masked window of a step is this memcpy, not wire time.
pub const DRAIN_CHUNK: usize = 128;

/// Bytes an owner drains in one [`owner_drain`] before it stops (see the
/// module doc, "Bounded release"). This, not the buffer size, bounds how long
/// a ring-3 `write` can spend putting kernel output on the wire: ≈ 30 ms
/// under QEMU, ≈ 0.7 s at 115200 baud — the price of printing other
/// contexts' lines in the owner's time, the same one Linux's
/// `console_unlock()` charges its caller.
pub const DRAIN_BUDGET: usize = 8192;

/// Room [`drop_marker`] needs.
pub const DROP_MARKER_MAX: usize = 112;

/// Where output goes. Two ways in, because the two kinds of caller differ in
/// what they may do while the wire is busy (wave 11, the TX ring):
///
/// * [`put`](Wire::put) is called with the caller's lock HELD (in the kernel:
///   the UART spinlock, interrupts masked). It must never wait. It takes the
///   longest prefix of `b` that fits and says how much that was; whatever is
///   left over is deferred by the caller ([`ConsoleDefer::kernel_write`],
///   [`ConsoleDefer::help`]), so order is kept.
/// * [`put_all`](Wire::put_all) is called by an owner with the lock RELEASED.
///   It puts all of `b` out and may wait for room to do it.
///
/// Every `FnMut(&[u8])` is a `Wire` that always takes everything: the host
/// tests' wires, and the kernel's synchronous halt/panic/reboot path.
///
/// [`fits`](Wire::fits) (lock held) says whether `put` would take all of `b`
/// now; the drop report goes out whole or waits. [`room`](Wire::room) (lock
/// held) is how many wire bytes `put` would take now.
pub trait Wire {
    fn put(&mut self, b: &[u8]) -> usize;
    fn put_all(&mut self, b: &[u8]);
    fn fits(&self, b: &[u8]) -> bool;
    fn room(&self) -> usize;
}

/// A kernel line starts on the wire only if the wire has this much room;
/// otherwise the whole line is deferred ([`ConsoleDefer::kernel_line`]).
/// That keeps a line's head from going to the wire while its tail is
/// deferred — the one way a full buffer could cut a line on the wire —
/// for every line up to this long.
pub const LINE_RESERVE: usize = 256;

impl<F: FnMut(&[u8]) + ?Sized> Wire for F {
    #[inline]
    fn fits(&self, _b: &[u8]) -> bool {
        true
    }
    #[inline]
    fn room(&self) -> usize {
        usize::MAX
    }
    #[inline]
    fn put(&mut self, b: &[u8]) -> usize {
        self(b);
        b.len()
    }
    #[inline]
    fn put_all(&mut self, b: &[u8]) {
        self(b)
    }
}

/// The deferred-output state. Only ever touched under the caller's lock.
pub struct ConsoleDefer<const N: usize> {
    buf: [u8; N],
    /// Index of the oldest deferred byte.
    head: usize,
    len: usize,
    owned: bool,
    /// Dropping the rest of the current line (see "Overflow").
    dropping: bool,
    /// Not yet reported on the wire.
    dropped_bytes: u32,
    dropped_lines: u32,
    /// Largest `len` ever reached.
    high_water: usize,
    /// Lifetime totals, for diagnostics.
    total_dropped_lines: u32,
    total_deferred: u64,
}

/// One owner drain step.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// This many deferred bytes were copied out; put them on the wire.
    Bytes(usize),
    /// The buffer is empty and this much was dropped since the last report;
    /// put [`drop_marker`] on the wire.
    Dropped { bytes: u32, lines: u32 },
    /// Nothing deferred and nothing to report.
    Empty,
}

impl<const N: usize> ConsoleDefer<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            len: 0,
            owned: false,
            dropping: false,
            dropped_bytes: 0,
            dropped_lines: 0,
            high_water: 0,
            total_dropped_lines: 0,
            total_deferred: 0,
        }
    }

    pub fn is_owned(&self) -> bool { self.owned }
    pub fn len(&self) -> usize { self.len }
    pub fn high_water(&self) -> usize { self.high_water }
    pub fn total_dropped_lines(&self) -> u32 { self.total_dropped_lines }
    pub fn total_deferred(&self) -> u64 { self.total_deferred }

    /// Something is waiting for the wire: bytes, or a drop report.
    pub fn has_residual(&self) -> bool { self.len > 0 || self.dropped_bytes > 0 }

    /// A residual nobody is draining: unowned with something deferred. The
    /// kernel publishes this to a flag the idle loop reads without the lock
    /// (see [`idle_drain`]).
    pub fn stranded(&self) -> bool { !self.owned && self.has_residual() }

    #[inline]
    fn at(&self, i: usize) -> u8 { self.buf[(self.head + i) % N] }

    /// Kernel output, with the caller's lock held across the whole line.
    /// `direct` puts bytes on the wire; it is called only while nobody owns
    /// the console and nothing is deferred, so the caller's lock hold
    /// excludes every other writer and order is kept. Otherwise the bytes
    /// are appended: behind the owner's line, or behind a residual that
    /// [`kernel_print`] drains (it never flushes one inside this hold).
    pub fn kernel_write<F: Wire + ?Sized>(&mut self, bytes: &[u8], direct: &mut F) {
        if self.owned || self.has_residual() {
            self.append(bytes);
            return;
        }
        // The tail of a line that was being dropped when ownership ended is
        // dropped too: the wire gets whole kernel lines or none.
        let rest = self.skip_dropped_tail(bytes);
        // Nothing was deferred, so this is at most the report of the tail
        // just skipped: one short line, ahead of the rest.
        // If the wire has no room for it, the report stays owed (a residual):
        // `rest` is deferred behind it and the next drain puts both out.
        if self.dropped_bytes > 0 {
            let mut m = [0u8; DROP_MARKER_MAX];
            let k = drop_marker(self.dropped_bytes, self.dropped_lines, &mut m);
            if direct.fits(&m[..k]) {
                self.dropped_bytes = 0;
                self.dropped_lines = 0;
                direct.put(&m[..k]);
            }
        }
        if !rest.is_empty() {
            self.put_or_defer(rest, direct);
        }
    }

    /// Unowned: whatever is deferred goes first. Otherwise put what the wire
    /// takes now and defer the rest behind it (wave 11: the wire is a TX ring
    /// that may be full, and the caller holds the lock, so it may not wait).
    fn put_or_defer<F: Wire + ?Sized>(&mut self, bytes: &[u8], direct: &mut F) {
        let n = if self.has_residual() { 0 } else { direct.put(bytes) };
        if n < bytes.len() {
            self.append(&bytes[n..]);
        }
    }

    /// Unowned with a residual: put at most one [`DRAIN_CHUNK`] of it (or,
    /// once the bytes are gone, the drop report) on the wire in the caller's
    /// lock hold. The bounded share of the flush a writer that may not own
    /// the console contributes, once per line (see [`kernel_print`]).
    /// With a wire that takes only part of the chunk (a full TX ring), the
    /// rest stays deferred, in place.
    pub fn help<F: Wire + ?Sized>(&mut self, direct: &mut F) {
        if self.owned {
            return;
        }
        if self.len > 0 {
            let start = self.head;
            let n = self.len.min(N - start).min(DRAIN_CHUNK);
            let took = direct.put(&self.buf[start..start + n]);
            self.consume(took.min(n));
        } else if self.dropped_bytes > 0 {
            let mut m = [0u8; DROP_MARKER_MAX];
            let k = drop_marker(self.dropped_bytes, self.dropped_lines, &mut m);
            if direct.fits(&m[..k]) {
                self.dropped_bytes = 0;
                self.dropped_lines = 0;
                direct.put(&m[..k]);
            }
        }
    }

    /// One kernel line in the caller's lock hold: [`help`](Self::help) once,
    /// then every piece `emit` produces through
    /// [`kernel_write`](Self::kernel_write).
    pub fn kernel_line<F: Wire + ?Sized, E: FnMut(&mut dyn FnMut(&[u8])) + ?Sized>(
        &mut self,
        direct: &mut F,
        emit: &mut E,
    ) {
        self.help(direct);
        if !self.owned && !self.has_residual() && direct.room() < LINE_RESERVE {
            // Too little room to start the line on the wire: all of it waits,
            // as if the console were owned (see `LINE_RESERVE`).
            emit(&mut |b: &[u8]| self.append(b));
        } else {
            emit(&mut |b: &[u8]| self.kernel_write(b, direct));
        }
    }

    /// A kernel writer takes ownership to drain a residual (see
    /// [`kernel_print`]): only if nobody owns the console and something is
    /// still deferred. Returns whether it took it.
    pub fn take_residual(&mut self) -> bool {
        if self.owned || !self.has_residual() {
            return false;
        }
        self.owned = true;
        true
    }

    /// Put everything deferred on the wire, then the drop report if any.
    /// Used by the kernel's halt, panic and reboot flushes, where the masked
    /// window no longer matters; the caller holds the lock, so `direct` must
    /// be a synchronous wire whose [`put_all`](Wire::put_all) never takes it.
    pub fn flush_residual<F: Wire + ?Sized>(&mut self, direct: &mut F) {
        while self.len > 0 {
            let start = self.head;
            let n = self.len.min(N - start);
            direct.put_all(&self.buf[start..start + n]);
            self.consume(n);
        }
        if self.dropped_bytes > 0 {
            let mut m = [0u8; DROP_MARKER_MAX];
            let k = drop_marker(self.dropped_bytes, self.dropped_lines, &mut m);
            self.dropped_bytes = 0;
            self.dropped_lines = 0;
            direct.put_all(&m[..k]);
        }
    }

    /// Take ownership. Ring-3 writers are serialised by their own lock
    /// before they get here, and a kernel writer owns the console only while
    /// holding that same lock ([`kernel_print`]), so the console is never
    /// already owned.
    /// Returns whether something is left over to drain first.
    pub fn take(&mut self) -> bool {
        // A kernel writer that owns the console holds the same line lock.
        debug_assert!(!self.owned, "console taken twice");
        self.owned = true;
        self.has_residual()
    }

    /// Owner: the next thing for the wire. Copies up to `out.len()` bytes.
    pub fn owner_step(&mut self, out: &mut [u8]) -> Step {
        if self.len > 0 {
            let mut n = 0;
            while n < out.len() && n < self.len {
                out[n] = self.at(n);
                n += 1;
            }
            self.consume(n);
            return Step::Bytes(n);
        }
        if self.dropped_bytes > 0 {
            let s = Step::Dropped { bytes: self.dropped_bytes, lines: self.dropped_lines };
            self.dropped_bytes = 0;
            self.dropped_lines = 0;
            return s;
        }
        Step::Empty
    }

    /// Give the console back. Checked and done in the same lock hold as the
    /// caller's last [`owner_step`](Self::owner_step) when it returned
    /// `Empty`; after a spent budget, with residual bytes the next kernel
    /// write flushes first.
    pub fn release(&mut self) {
        self.owned = false;
    }

    fn consume(&mut self, n: usize) {
        self.head = (self.head + n) % N;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.total_deferred = self.total_deferred.wrapping_add(bytes.len() as u64);
        for &b in bytes {
            if !self.dropping && self.len == N {
                // Full: cut the partial line at the tail back to the last
                // newline and drop through the end of the line being written.
                self.truncate_partial_line();
                self.dropping = true;
            }
            if self.dropping {
                self.count_dropped(b);
                continue;
            }
            let tail = (self.head + self.len) % N;
            self.buf[tail] = b;
            self.len += 1;
            if self.len > self.high_water {
                self.high_water = self.len;
            }
        }
    }

    fn truncate_partial_line(&mut self) {
        let mut k = self.len;
        while k > 0 && self.at(k - 1) != b'\n' {
            k -= 1;
        }
        self.dropped_bytes = self.dropped_bytes.saturating_add((self.len - k) as u32);
        self.len = k;
        if self.len == 0 {
            self.head = 0;
        }
    }

    fn count_dropped(&mut self, b: u8) {
        self.dropped_bytes = self.dropped_bytes.saturating_add(1);
        if b == b'\n' {
            self.dropping = false;
            self.dropped_lines = self.dropped_lines.saturating_add(1);
            self.total_dropped_lines = self.total_dropped_lines.saturating_add(1);
        }
    }

    fn skip_dropped_tail<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        let mut i = 0;
        while self.dropping && i < bytes.len() {
            self.count_dropped(bytes[i]);
            i += 1;
        }
        &bytes[i..]
    }
}

/// `[CONSOLE] dropped B kernel bytes (L lines) while ring 3 held the console\n`
/// into `out`; returns its length. Gate rows treat this line as a failure.
pub fn drop_marker(bytes: u32, lines: u32, out: &mut [u8; DROP_MARKER_MAX]) -> usize {
    let mut n = 0;
    let mut put = |s: &[u8], n: &mut usize| {
        for &b in s {
            if *n < DROP_MARKER_MAX {
                out[*n] = b;
                *n += 1;
            }
        }
    };
    let mut digits = [0u8; 10];
    put(b"[CONSOLE] dropped ", &mut n);
    put(fmt_u32(bytes, &mut digits), &mut n);
    put(b" kernel bytes (", &mut n);
    put(fmt_u32(lines, &mut digits), &mut n);
    put(b" lines) while ring 3 held the console\n", &mut n);
    n
}

fn fmt_u32(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// The lock that guards a [`ConsoleDefer`]: the UART spinlock in the kernel,
/// a `Mutex` in the host tests.
pub trait DeferLock<const N: usize> {
    fn with<R>(&self, f: impl FnOnce(&mut ConsoleDefer<N>) -> R) -> R;
}

/// Owner: drain what the kernel deferred, up to [`DRAIN_BUDGET`] bytes (then
/// to the end of the kernel line in progress), each
/// chunk copied out under the lock and put on the wire (`kernel_wire`) with
/// it released. With `release`, give the console back in the same lock hold
/// that saw the buffer empty — or, budget spent, with the residual left for
/// the next kernel write. Returns whether the budget ran out (the diagnostic
/// that a kernel printer outran the wire).
pub fn owner_drain<const N: usize, L: DeferLock<N>, K: FnMut(&[u8])>(
    lock: &L,
    kernel_wire: &mut K,
    release: bool,
) -> bool {
    drain(lock, kernel_wire, release, &mut 0)
}

/// [`owner_drain`] against a budget shared across calls: `drained` is what
/// this owner already drained.
fn drain<const N: usize, L: DeferLock<N>, K: Wire + ?Sized>(
    lock: &L,
    kernel_wire: &mut K,
    release: bool,
    drained: &mut usize,
) -> bool {
    let mut chunk = [0u8; DRAIN_CHUNK];
    // The budget may only end a drain between two kernel lines: stopping
    // inside one would let the owner's next ring-3 line splice into it.
    let mut mid_line = false;
    loop {
        let spent = *drained >= DRAIN_BUDGET && !mid_line;
        let step = lock.with(|st| {
            let step = if spent { Step::Empty } else { st.owner_step(&mut chunk) };
            if step == Step::Empty && release {
                st.release();
            }
            step
        });
        match step {
            Step::Bytes(n) => {
                kernel_wire.put_all(&chunk[..n]);
                *drained += n;
                mid_line = chunk[n - 1] != b'\n';
            }
            Step::Dropped { bytes, lines } => {
                let mut m = [0u8; DROP_MARKER_MAX];
                let k = drop_marker(bytes, lines, &mut m);
                kernel_wire.put_all(&m[..k]);
            }
            Step::Empty => return spent,
        }
    }
}

/// The whole ring-3 write: take the console, put `bytes` on the wire line by
/// line through `ring3_wire` with no lock held, drain the kernel's deferred
/// lines after each line, give the console back. Returns whether the final
/// release stopped on the drain budget, leaving a residual.
pub fn owner_write<const N: usize, L: DeferLock<N>, R: FnMut(&[u8]), K: FnMut(&[u8])>(
    lock: &L,
    bytes: &[u8],
    ring3_wire: &mut R,
    kernel_wire: &mut K,
) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // Older kernel output first.
    if lock.with(|st| st.take()) {
        owner_drain(lock, kernel_wire, false);
    }
    let mut start = 0;
    while start < bytes.len() {
        let end = match bytes[start..].iter().position(|&b| b == b'\n') {
            Some(i) => start + i + 1,
            None => bytes.len(),
        };
        ring3_wire(&bytes[start..end]);
        start = end;
        if start < bytes.len() {
            owner_drain(lock, kernel_wire, false);
        }
    }
    owner_drain(lock, kernel_wire, true)
}

/// A kernel line: one `kprint!`/`kprintln!`, `puts_locked`, a shell write.
/// `emit` produces its bytes, in as many pieces as it likes, into the sink it
/// is given; it is called exactly once. `wire` puts bytes on the UART.
///
/// * The common case is one lock hold: nobody owns the console and nothing
///   is deferred, so the line goes to the wire directly — or the console is
///   owned and the line is appended.
/// * **A residual** (bytes a budget-limited release left behind) is never
///   flushed inside this hold. `may_own` ([`may_own`]: interrupts were on
///   when the caller entered and it holds no spinlock) and `try_line` (the lock every ring-3 owner
///   holds across its write, TRIED, never waited for) decide who drains it:
///   - both yes: this writer becomes the owner, drains the residual with the
///     lock released between [`DRAIN_CHUNK`]s, writes its own line with no
///     lock held, drains what was deferred meanwhile, and releases in the
///     lock hold that sees the buffer empty. One [`DRAIN_BUDGET`] for the
///     whole call; if it runs out before its own line, that line is
///     appended behind the residual (order is kept) and the console is
///     released with it.
///   - otherwise (an interrupt handler, interrupts already masked, a
///     spinlock held, or the line lock busy): [`ConsoleDefer::help`] with one chunk and defer the
///     line behind the rest.
///
/// `try_line` is called without `lock` held: in the kernel it takes a
/// spinlock of its own, and nothing may be nested inside the UART lock.
pub fn kernel_print<const N: usize, L, G, T, K, E>(
    lock: &L,
    may_own: bool,
    try_line: T,
    wire: &mut K,
    emit: &mut E,
) where
    L: DeferLock<N>,
    T: FnOnce() -> Option<G>,
    K: Wire + ?Sized,
    E: FnMut(&mut dyn FnMut(&[u8])) + ?Sized,
{
    let takeover = lock.with(|st| {
        if may_own && !st.is_owned() && st.has_residual() {
            return true;
        }
        st.kernel_line(wire, emit);
        false
    });
    if !takeover {
        return;
    }
    let Some(line) = try_line() else {
        lock.with(|st| st.kernel_line(wire, emit));
        return;
    };
    // Re-check: a helper may have emptied the residual meanwhile. Nobody
    // else can own the console: ring-3 owners hold `line`.
    let took = lock.with(|st| {
        if st.take_residual() {
            return true;
        }
        st.kernel_line(wire, emit);
        false
    });
    if took {
        let mut drained = 0usize;
        if drain(lock, wire, false, &mut drained) {
            // Budget spent with bytes still deferred: this line goes
            // behind them, and the next writer carries on.
            lock.with(|st| {
                emit(&mut |b: &[u8]| st.kernel_write(b, &mut |_: &[u8]| {}));
                st.release();
            });
        } else {
            emit(&mut |b: &[u8]| wire.put_all(b));
            drain(lock, wire, true, &mut drained);
        }
    }
    drop(line);
}

/// May a kernel writer become the console's owner and drain with interrupts
/// on? Only in task context (`irqs_on` when it entered) AND holding no
/// spinlock (`preempt_depth` 0: every `azos_sync::SpinLock` guard holds a
/// preemption guard). A writer under a spinlock would otherwise keep that
/// lock across a drain that can be preempted; it helps with one chunk and
/// defers instead.
pub fn may_own(irqs_on: bool, preempt_depth: u32) -> bool {
    irqs_on && preempt_depth == 0
}

/// The idle loop's drain of a stranded residual (one a budget-limited
/// release left, with no later writer to carry it). `stranded` is the
/// caller's lock-free read of [`ConsoleDefer::stranded`]; the common case
/// costs that one load and nothing else. Otherwise it is an empty kernel
/// line from task context: [`kernel_print`] takes the console over and
/// drains it, or helps with one chunk if the line lock is busy.
pub fn idle_drain<const N: usize, L, G, T, K>(lock: &L, stranded: bool, try_line: T, wire: &mut K)
where
    L: DeferLock<N>,
    T: FnOnce() -> Option<G>,
    K: Wire + ?Sized,
{
    if !stranded {
        return;
    }
    kernel_print(lock, true, try_line, wire, &mut |_: &mut dyn FnMut(&[u8])| {});
}
