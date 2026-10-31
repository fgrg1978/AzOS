// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Drives the kernel's reclaim task with real memory pressure (gate rows
//! `reclaim:`, `tools/gate/reclaim_row.py`, which judges the lines this prints
//! and the kernel's `[DECISION]` lines of the same boot).
//!
//! The Domain's frame budget (`MM_PRESSURE_TEST_PAGES`) is under the machine's
//! RAM, and the charge comes back as pages leave for the pool, so the pages
//! touched here go past all the free frames there were at the start only if
//! reclaim really takes them.
//!
//! The pacing is the pressure events' own: this program holds back from
//! `warning` until `normal`, as a client of `PORT_SRC_PRESSURE` should. A
//! refused mmap is an answer too. Nothing here assumes the reclaim poll.

#![no_std]
#![no_main]

use azos_abi::syscall_nr::{SHM_ATTR_VOLATILE, SHM_CREATE_ATTR_SHIFT};
use azos_idl::Cap;
use azos_libsys as sys;
use sys::dev::{MemCtlCall, MemCtlClient};

const PAGE: usize = sys::PAGE_SIZE;
const WORDS: usize = PAGE / 8;
const RW: u64 = sys::PROT_READ | sys::PROT_WRITE;

/// How long a step waits on the kernel before it says the kernel did not act.
const PATIENCE_MS: u64 = 20_000;
const TICK_MS: u64 = 20;
/// The largest memory object the kernel makes (`MAX_MEMOBJ_PAGES`).
const OBJECT_PAGES: usize = 64;

fn say(s: &[u8], nums: &[(&[u8], u64)]) {
    let mut buf = [0u8; 160];
    let mut n = 0;
    let mut put = |b: &[u8]| {
        for &c in b {
            if n < buf.len() {
                buf[n] = c;
                n += 1;
            }
        }
    };
    put(b"[MEMPRESS] ");
    put(s);
    for (k, v) in nums {
        put(b" ");
        put(k);
        put(b"=");
        let mut d = [0u8; 20];
        let mut i = d.len();
        let mut x = *v;
        loop {
            i -= 1;
            d[i] = b'0' + (x % 10) as u8;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        put(&d[i..]);
    }
    sys::println(&buf[..n]);
}

fn fail(s: &[u8], nums: &[(&[u8], u64)]) -> ! {
    say(s, nums);
    sys::exit(1);
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x
}

/// A page WKdm stores at a tenth of its size or less: one word in sixty-four is
/// unique and the others are zero, so it is never a same-filled page (those
/// cost no bytes and reach no medium), and the medium the fill needs stays
/// within a gate volume.
fn compressible(page: u64, i: usize) -> u64 {
    if i % 64 == 0 {
        mix(page << 16 | i as u64) | 1
    } else {
        0
    }
}

fn incompressible(page: u64, i: usize) -> u64 {
    mix(page << 16 | i as u64) ^ mix(i as u64 + 1)
}

/// # Safety
/// `base` is a writable mapping of one page.
unsafe fn write_page(base: usize, page: u64, f: fn(u64, usize) -> u64) {
    let p = base as *mut u64;
    for i in 0..WORDS {
        // SAFETY: the caller's mapping; volatile, as the store is the fault.
        unsafe { p.add(i).write_volatile(f(page, i)) };
    }
}

/// The first word of the page that is not what [`write_page`] wrote.
///
/// # Safety
/// `base` is a readable mapping of one page.
unsafe fn check_page(base: usize, page: u64, f: fn(u64, usize) -> u64) -> Option<usize> {
    let p = base as *const u64;
    // SAFETY: the caller's mapping.
    (0..WORDS).find(|&i| unsafe { p.add(i).read_volatile() } != f(page, i))
}

/// The Domain's pressure, as its Port tells it.
struct Pressure {
    port: u32,
    level: u8,
    told: u64,
}

impl Pressure {
    fn bind() -> Self {
        let port = sys::port_create_typed();
        if port <= 0 || sys::port_bind_pressure(port as u32, 0) != 0 {
            fail(b"FAIL no pressure port", &[(b"rc", port.unsigned_abs() as u64)]);
        }
        Pressure { port: port as u32, level: 0, told: 0 }
    }

    fn drain(&mut self) {
        let mut ev = [0u8; sys::PORT_EVENT_BYTES];
        while sys::port_poll_typed(self.port, &mut ev) == sys::PORT_EVENT_BYTES as isize {
            if let Some(l) = sys::pressure_level(&ev) {
                self.level = l;
                self.told += 1;
                say(b"event", &[(b"level", l as u64), (b"told", self.told)]);
            }
        }
    }

    /// Hold back until the Domain is told `normal` again, or the patience runs
    /// out (a storm that may not take this Domain's pages never answers). The
    /// answer: it was told.
    fn wait_normal(&mut self) -> bool {
        let mut waited = 0;
        self.drain();
        while self.level != 0 && waited < PATIENCE_MS {
            sys::sleep(TICK_MS);
            waited += TICK_MS;
            self.drain();
        }
        self.level == 0
    }

    fn wait_level(&mut self, level: u8) -> bool {
        let mut waited = 0;
        self.drain();
        while self.level != level && waited < PATIENCE_MS {
            sys::sleep(TICK_MS);
            waited += TICK_MS;
            self.drain();
        }
        self.level == level
    }
}

fn map(pages: usize) -> Option<usize> {
    let r = sys::mmap(0, (pages * PAGE) as u64, RW, 0, sys::MAP_ANON_FD, 0);
    (r > 0).then_some(r as usize)
}

/// One mapped run of pages and the number of its first page.
#[derive(Clone, Copy)]
struct Run {
    base: usize,
    first: u64,
}

const MAX_RUNS: usize = 512;
static mut RUNS: [Run; MAX_RUNS] = [Run { base: 0, first: 0 }; MAX_RUNS];

fn runs() -> &'static mut [Run; MAX_RUNS] {
    // SAFETY: one thread, and the reference is not kept across calls.
    unsafe { &mut *(&raw mut RUNS) }
}

/// Map and write `target` pages of `chunk`, paced by the pressure events. The
/// runs it made and the pages they hold, which is less than `target` when the
/// kernel stopped giving room.
fn fill(p: &mut Pressure, target: usize, chunk: usize) -> (usize, usize) {
    let (mut n, mut pages, mut refused, mut untold) = (0usize, 0usize, 0u64, 0u64);
    let mut waited = 0;
    while pages < target && n < MAX_RUNS {
        if !p.wait_normal() {
            untold += 1;
            if untold == 2 {
                break;
            }
        }
        let Some(base) = map(chunk) else {
            refused += 1;
            if waited >= PATIENCE_MS {
                break;
            }
            sys::sleep(TICK_MS);
            waited += TICK_MS;
            continue;
        };
        waited = 0;
        for i in 0..chunk {
            // SAFETY: the page is in the mapping just made.
            unsafe { write_page(base + i * PAGE, (pages + i) as u64, compressible) };
        }
        runs()[n] = Run { base, first: pages as u64 };
        n += 1;
        pages += chunk;
        sys::sleep(TICK_MS);
    }
    say(b"filled", &[(b"pages", pages as u64), (b"target", target as u64), (b"refused", refused), (b"untold", untold)]);
    (n, pages)
}

/// Read every page back: the runs in the order given by `rev`.
fn verify(n: usize, chunk: usize, rev: bool) {
    for k in 0..n {
        if k % 16 == 0 {
            say(b"verifying", &[(b"run", k as u64), (b"ms", sys::vdso_uptime_ms())]);
        }
        let r = runs()[if rev { n - 1 - k } else { k }];
        for i in 0..chunk {
            // SAFETY: the run's mapping is alive until `release`.
            if let Some(w) = unsafe { check_page(r.base + i * PAGE, r.first + i as u64, compressible) } {
                fail(b"contents FAIL", &[(b"page", r.first + i as u64), (b"word", w as u64)]);
            }
        }
    }
}

fn release(n: usize, chunk: usize) {
    for r in &runs()[..n] {
        sys::munmap(r.base as u64, (chunk * PAGE) as u64);
    }
}

fn volatile_object(pages: usize) -> (u32, usize) {
    let cap = sys::shm_create_typed(pages as u64, sys::SHM_RW | (SHM_ATTR_VOLATILE << SHM_CREATE_ATTR_SHIFT));
    if cap < 0 {
        fail(b"purge FAIL create", &[(b"pages", pages as u64)]);
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        fail(b"purge FAIL map", &[]);
    }
    for i in 0..pages {
        // SAFETY: the page is in the object's mapping.
        unsafe { write_page(va as usize + i * PAGE, i as u64, compressible) };
    }
    (cap as u32, va as usize)
}

struct MemCtl {
    ep: u32,
}

impl MemCtl {
    /// `true`: the object has been purged.
    fn say(&self, cap: u32, volatile: bool) -> bool {
        let mem = Cap::<sys::dev::memctl::VolatileMem>::from_raw(cap);
        let mut c = MemCtlClient::new(sys::dev::Ep(self.ep));
        match sys::dev::value(if volatile { c.set_volatile(mem) } else { c.set_nonvolatile(mem) }) {
            Ok(purged) => purged,
            Err(code) => fail(b"purge FAIL memctl", &[(b"code", code as u64)]),
        }
    }
}

/// Reclaim does not touch an object nobody marked, and one marked and unmarked
/// with no pressure keeps its bytes: the half of the round trip a purge that
/// fires on anything would fail.
fn purge_control(ctl: &MemCtl) {
    let (cap, va) = volatile_object(8);
    if ctl.say(cap, true) || ctl.say(cap, false) {
        fail(b"purge FAIL purged with no pressure", &[]);
    }
    for i in 0..8 {
        // SAFETY: the object is held and mapped.
        if unsafe { check_page(va + i * PAGE, i as u64, compressible) }.is_some() {
            fail(b"purge FAIL contents of a held object", &[(b"page", i as u64)]);
        }
    }
    sys::shm_release_typed(cap);
    say(b"purge control PASS", &[]);
}

/// Hold pages that do not compress until the budget refuses more: the charge
/// stays at the limit, and that is what takes the system past its own
/// watermark. Every mapping keeps `SPARE` pages of the budget free until it is
/// written, as a page table its first touch needs is charged then. The runs it
/// made.
fn hold_incompressible(p: &mut Pressure, chunk: usize) -> usize {
    const SPARE: usize = 8;
    let (mut n, mut held, mut refused) = (0usize, 0u64, 0);
    while refused < 8 && n < MAX_RUNS {
        let Some(base) = map(chunk + SPARE) else {
            refused += 1;
            sys::sleep(TICK_MS);
            continue;
        };
        sys::munmap((base + chunk * PAGE) as u64, (SPARE * PAGE) as u64);
        for i in 0..chunk {
            // SAFETY: the page is in the mapping just made.
            unsafe { write_page(base + i * PAGE, held + i as u64, incompressible) };
        }
        runs()[n] = Run { base, first: held };
        n += 1;
        held += chunk as u64;
        p.drain();
    }
    say(b"incompressible held", &[(b"pages", held)]);
    n
}

fn purge_round_trip(ctl: &MemCtl, p: &mut Pressure, cap: u32, chunk: usize) {
    let held = hold_incompressible(p, chunk);
    let mut waited = 0;
    while !ctl.say(cap, true) {
        if waited >= PATIENCE_MS {
            fail(b"purge FAIL never purged", &[(b"level", p.level as u64)]);
        }
        sys::sleep(TICK_MS);
        waited += TICK_MS;
    }
    if !ctl.say(cap, false) {
        fail(b"purge FAIL set_nonvolatile says kept", &[]);
    }
    let again = sys::shm_map_typed(cap);
    if again >= 0 {
        fail(b"purge FAIL a purged object mapped", &[]);
    }
    sys::shm_release_typed(cap);
    // The budget is all held: a rebuild is what a program gives room for.
    release(held, chunk);
    let (fresh, va) = volatile_object(8);
    for i in 0..8 {
        // SAFETY: the new object is held and mapped.
        if unsafe { check_page(va + i * PAGE, i as u64, compressible) }.is_some() {
            fail(b"purge FAIL rebuilt object", &[(b"page", i as u64)]);
        }
    }
    sys::shm_release_typed(fresh);
    say(b"purge PASS", &[(b"rc", again.unsigned_abs() as u64), (b"waited_ms", waited)]);
}

/// Take the charge to the limit with a range nothing has touched yet and wait
/// to be told. The budget has answered by refusing the mappings; a range it
/// charged is the program's, and touching it must work: the charge was taken
/// when it was mapped.
fn run_into_the_limit(p: &mut Pressure, chunk: usize) {
    let Some(far) = map(chunk) else {
        fail(b"limit FAIL the range was refused", &[]);
    };
    let mut refused = 0u64;
    while map(chunk).is_some() {}
    while map(1).is_some() {}
    while map(1).is_none() && refused < 4 {
        refused += 1;
    }
    if !p.wait_level(2) {
        fail(b"pressure FAIL never told critical", &[(b"level", p.level as u64)]);
    }
    say(b"pressure told at the limit", &[(b"told", p.told)]);
    for i in 0..chunk {
        // SAFETY: the page is in the range mapped above.
        unsafe { write_page(far + i * PAGE, i as u64, compressible) };
    }
    for i in 0..chunk {
        // SAFETY: as above.
        if unsafe { check_page(far + i * PAGE, i as u64, compressible) }.is_some() {
            fail(b"limit FAIL contents", &[(b"page", i as u64)]);
        }
    }
    say(b"limit PASS", &[(b"refused", refused)]);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let free = sys::meminfo().max(0) as usize;
    let target = 2 * free;
    let chunk = (free / 64).max(16);
    say(b"start", &[(b"free", free as u64), (b"target", target as u64), (b"chunk", chunk as u64), (b"page", PAGE as u64)]);
    let mut p = Pressure::bind();
    let Some(ep) = sys::dev::lookup(sys::dev::key::MEMCTL, 0) else {
        fail(b"FAIL no memctl endpoint", &[]);
    };
    let ctl = MemCtl { ep };
    purge_control(&ctl);
    let (victim, _) = volatile_object(OBJECT_PAGES);
    if ctl.say(victim, true) {
        fail(b"purge FAIL marked after a purge nobody asked for", &[]);
    }

    let (n, pages) = fill(&mut p, target, chunk);
    if pages < target {
        // Rows that stop reclaim on purpose end here, with what they got back.
        verify(n, chunk, false);
        say(b"contents of the partial fill PASS", &[(b"pages", pages as u64)]);
        sys::exit(0);
    }
    say(b"past RAM PASS", &[(b"pages", pages as u64), (b"free_at_start", free as u64)]);
    verify(n, chunk, false);
    verify(n, chunk, true);
    say(b"contents PASS", &[(b"pages", pages as u64), (b"free_now", sys::meminfo().max(0) as u64)]);
    release(n, chunk);

    purge_round_trip(&ctl, &mut p, victim, chunk);
    run_into_the_limit(&mut p, chunk);
    sys::exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(1);
}
