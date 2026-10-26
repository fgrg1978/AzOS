// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `sdktest`: the std port, tested from inside.
//!
//! Every test is `#[azos::test]` (the user-code harness, `azos_libsys::utest`);
//! `main` runs them in name order and exits with the number that failed. The
//! output is TAP on the console, `# 0 failed` on a pass.
//!
//! No shipped image row starts it yet (`mk/userspace.mk`). The row that does must
//! grant the `entropy` capability (the allocator and `HashMap` draw from the
//! kernel pool) and, for `net_edges_and_udp_timeouts`, the socket ops: a row
//! naming one op of the `net` invoke class (`DOMAIN_SOCKET`, `NODE_SEND`, ...)
//! grants the class, and without it the first `socket` is refused by the
//! seccomp filter. It tests what the port provides: no
//! file system (`fs_is_not_provided` holds that edge); sockets over the native
//! ops, up to what the kernel offers (`net_edges_and_udp_timeouts`).

use azos_libsys as azos;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> std::process::ExitCode {
    println!("[sdktest] std on AzOS");
    std::process::ExitCode::from(azos::utest::run())
}

/// Blocks from one byte to past the allocator's size classes, each filled and
/// read back: nothing overlaps.
#[azos::test]
fn alloc_sizes() -> Result<(), &'static str> {
    let mut held: Vec<Vec<u8>> = Vec::new();
    for (i, n) in [1usize, 2, 7, 8, 15, 16, 17, 100, 511, 512, 1000, 4095, 4096, 5000, 20_000, 70_000].iter().enumerate() {
        held.push(vec![i as u8 + 1; *n]);
    }
    for (i, v) in held.iter().enumerate() {
        if v.iter().any(|&b| b != i as u8 + 1) {
            return Err("a block changed under another allocation");
        }
    }
    Ok(())
}

#[repr(align(64))]
struct Line64([u8; 64]);

#[repr(align(4096))]
struct Page([u8; 8]);

#[azos::test]
fn alloc_alignment() -> Result<(), &'static str> {
    let a = Box::new(Line64([1; 64]));
    let b = Box::new(Page([2; 8]));
    if a.0[0] != 1 || b.0[0] != 2 {
        return Err("the boxes' contents");
    }
    if (&*a as *const Line64 as usize) % 64 != 0 {
        return Err("64-byte alignment");
    }
    if (&*b as *const Page as usize) % 4096 != 0 {
        return Err("page alignment");
    }
    Ok(())
}

#[azos::test]
fn realloc_keeps_the_contents() -> Result<(), &'static str> {
    let mut v: Vec<u32> = Vec::new();
    for i in 0..50_000u32 {
        v.push(i.wrapping_mul(2_654_435_761));
    }
    for (i, x) in v.iter().enumerate() {
        if *x != (i as u32).wrapping_mul(2_654_435_761) {
            return Err("a grown vector lost an element");
        }
    }
    Ok(())
}

#[azos::test]
fn threads_join_with_their_results() -> Result<(), &'static str> {
    let count = Arc::new(AtomicUsize::new(0));
    let hs: Vec<_> = (0..4usize)
        .map(|k| {
            let count = count.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    count.fetch_add(1, Ordering::Relaxed);
                }
                k * 10
            })
        })
        .collect();
    let mut sum = 0;
    for h in hs {
        sum += h.join().map_err(|_| "a thread panicked")?;
    }
    if count.load(Ordering::Relaxed) != 4000 || sum != 60 {
        return Err("lost increments or results");
    }
    Ok(())
}

#[azos::test]
fn scoped_threads_borrow_the_stack() -> Result<(), &'static str> {
    let mut data = [0u32; 8];
    thread::scope(|s| {
        for (i, chunk) in data.chunks_mut(2).enumerate() {
            s.spawn(move || {
                for x in chunk {
                    *x = i as u32 + 1;
                }
            });
        }
    });
    if data != [1, 1, 2, 2, 3, 3, 4, 4] {
        return Err("a scoped thread's writes did not arrive");
    }
    Ok(())
}

static DROPS: AtomicUsize = AtomicUsize::new(0);

struct Counted;

impl Drop for Counted {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

thread_local! {
    static TL: Counted = const { Counted };
    static TL_VALUE: std::cell::Cell<u32> = const { std::cell::Cell::new(7) };
}

#[azos::test]
fn thread_locals_are_per_thread_and_dropped_at_exit() -> Result<(), &'static str> {
    TL_VALUE.set(1);
    let before = DROPS.load(Ordering::SeqCst);
    let seen = thread::spawn(|| {
        TL.with(|_| ());
        TL_VALUE.with(|v| {
            let first = v.get();
            v.set(99);
            first
        })
    })
    .join()
    .map_err(|_| "the thread panicked")?;
    if seen != 7 {
        return Err("a new thread saw another thread's thread-local");
    }
    if TL_VALUE.get() != 1 {
        return Err("a thread's write reached the main thread's thread-local");
    }
    if DROPS.load(Ordering::SeqCst) != before + 1 {
        return Err("the thread-local was not dropped at the thread's exit");
    }
    Ok(())
}

#[azos::test]
fn mutex_and_condvar_hand_over() -> Result<(), &'static str> {
    // Two threads take turns on one counter: this one on even values, the
    // peer on odd ones.
    let pair = Arc::new((Mutex::new(0u32), Condvar::new()));
    let p2 = pair.clone();
    let h = thread::spawn(move || {
        let (m, cv) = &*p2;
        for _ in 0..100 {
            let mut g = m.lock().unwrap();
            while *g % 2 != 1 {
                g = cv.wait(g).unwrap();
            }
            *g += 1;
            cv.notify_all();
        }
    });
    let (m, cv) = &*pair;
    for _ in 0..100 {
        let mut g = m.lock().unwrap();
        while *g % 2 != 0 {
            g = cv.wait(g).unwrap();
        }
        *g += 1;
        cv.notify_all();
    }
    h.join().map_err(|_| "the peer panicked")?;
    if *m.lock().unwrap() != 200 {
        return Err("a turn was lost");
    }
    Ok(())
}

static CELL: OnceLock<u32> = OnceLock::new();

#[azos::test]
fn once_and_rwlock() -> Result<(), &'static str> {
    let hs: Vec<_> = (1..=4u32).map(|k| thread::spawn(move || *CELL.get_or_init(|| k))).collect();
    let vals: Vec<u32> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    if vals.iter().any(|v| *v != vals[0]) {
        return Err("a OnceLock ran two initialisers");
    }
    let l = Arc::new(RwLock::new(0u32));
    let w = {
        let l = l.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                *l.write().unwrap() += 1;
            }
        })
    };
    for _ in 0..100 {
        let _ = *l.read().unwrap();
    }
    w.join().map_err(|_| "the writer panicked")?;
    if *l.read().unwrap() != 100 {
        return Err("a write was lost");
    }
    Ok(())
}

#[azos::test]
fn a_channel_carries_a_stream() -> Result<(), &'static str> {
    let (tx, rx) = mpsc::channel::<u32>();
    let h = thread::spawn(move || {
        for i in 0..1000u32 {
            tx.send(i).unwrap();
        }
    });
    let sum: u32 = rx.iter().sum();
    h.join().map_err(|_| "the sender panicked")?;
    if sum != 999 * 1000 / 2 {
        return Err("the sum of the stream");
    }
    Ok(())
}

#[azos::test]
fn the_clock_is_monotonic_and_sleep_waits() -> Result<(), &'static str> {
    let a = Instant::now();
    let b = Instant::now();
    if b < a {
        return Err("the clock went backwards");
    }
    thread::sleep(Duration::from_millis(20));
    let waited = a.elapsed();
    if waited < Duration::from_millis(20) {
        return Err("sleep returned early");
    }
    if waited > Duration::from_secs(2) {
        return Err("sleep took a hundred times as long");
    }
    Ok(())
}

#[azos::test]
fn a_hash_map_works() -> Result<(), &'static str> {
    // `RandomState` draws its keys from the kernel pool.
    let mut m = HashMap::new();
    for i in 0..1000u32 {
        m.insert(i, i * 3);
    }
    if (0..1000u32).any(|i| m.get(&i) != Some(&(i * 3))) || m.len() != 1000 {
        return Err("a map lost an entry");
    }
    Ok(())
}

#[azos::test]
fn the_environment_is_this_process_s_own() -> Result<(), &'static str> {
    std::env::set_var("SDKTEST_VAR", "one");
    if std::env::var("SDKTEST_VAR").as_deref() != Ok("one") {
        return Err("set_var");
    }
    std::env::remove_var("SDKTEST_VAR");
    if std::env::var_os("SDKTEST_VAR").is_some() {
        return Err("remove_var");
    }
    if std::env::current_dir().is_err() {
        return Err("current_dir");
    }
    Ok(())
}

#[azos::test]
fn standard_streams_write() -> Result<(), &'static str> {
    use std::io::Write;
    println!("[sdktest] stdout line");
    eprintln!("[sdktest] stderr line");
    std::io::stdout().flush().map_err(|_| "flush")?;
    if std::process::id() == 0 {
        return Err("no process id");
    }
    Ok(())
}

/// The edge of the port, held so that growing past it is a decision: the file
/// system answers `Unsupported` until the FS interface has a client here.
#[azos::test]
fn fs_is_not_provided() -> Result<(), &'static str> {
    match std::fs::File::open("/fat/SDKTEST.ELF") {
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
        _ => return Err("std::fs is provided now: test it, and drop this row"),
    }
    Ok(())
}

/// `std::net` as far as the kernel's socket ops go, with no peer needed: a
/// bound UDP socket takes a port from the ephemeral range, a receive that finds
/// nothing is `WouldBlock` (nonblocking at once, with a timeout after it ran
/// out), a zero timeout is refused, a TCP listener takes an ephemeral port,
/// answers a nonblocking `accept` with nobody waiting `WouldBlock` and holds
/// its port against a second listener, and what the ops lack answers
/// `Unsupported` (a name, IPv6 datagrams, an IPv6 listener). Held like
/// `fs_is_not_provided`: the day the resolver interface exists, these
/// assertions fail and are replaced by tests of the real thing. The row that
/// boots this needs the `net` class (see the file header).
#[azos::test]
fn net_edges_and_udp_timeouts() -> Result<(), &'static str> {
    use std::io::ErrorKind::{AddrInUse, InvalidInput, Unsupported, WouldBlock};
    use std::net::{TcpListener, UdpSocket};

    let u = UdpSocket::bind("0.0.0.0:0").map_err(|_| "udp bind")?;
    if u.local_addr().map_err(|_| "local_addr")?.port() < 49152 {
        return Err("bind to port 0 gave a port outside the ephemeral range");
    }
    let mut buf = [0u8; 16];
    u.set_nonblocking(true).map_err(|_| "nonblocking")?;
    if u.recv_from(&mut buf).err().map(|e| e.kind()) != Some(WouldBlock) {
        return Err("a nonblocking receive with nothing queued is not WouldBlock");
    }
    u.set_nonblocking(false).map_err(|_| "blocking")?;
    if u.set_read_timeout(Some(Duration::ZERO)).err().map(|e| e.kind()) != Some(InvalidInput) {
        return Err("a zero read timeout is not refused");
    }
    u.set_read_timeout(Some(Duration::from_millis(30))).map_err(|_| "set_read_timeout")?;
    if u.read_timeout().ok().flatten() != Some(Duration::from_millis(30)) {
        return Err("the read timeout does not read back");
    }
    let t0 = Instant::now();
    if u.recv_from(&mut buf).err().map(|e| e.kind()) != Some(WouldBlock) {
        return Err("a receive that timed out is not WouldBlock");
    }
    let waited = t0.elapsed();
    if waited < Duration::from_millis(30) || waited > Duration::from_millis(500) {
        return Err("the read timeout waited the wrong time");
    }
    if UdpSocket::bind("[::]:0").err().map(|e| e.kind()) != Some(Unsupported) {
        return Err("UDP over IPv6 is offered now: test it");
    }
    let l = TcpListener::bind("0.0.0.0:0").map_err(|_| "tcp listen")?;
    let port = l.local_addr().map_err(|_| "listener local_addr")?.port();
    if port < 49152 {
        return Err("listen on port 0 gave a port outside the ephemeral range");
    }
    l.set_nonblocking(true).map_err(|_| "listener nonblocking")?;
    if l.accept().err().map(|e| e.kind()) != Some(WouldBlock) {
        return Err("a nonblocking accept with nobody waiting is not WouldBlock");
    }
    if TcpListener::bind(("0.0.0.0", port)).err().map(|e| e.kind()) != Some(AddrInUse) {
        return Err("a second listener on a taken port is not AddrInUse");
    }
    if TcpListener::bind("[::]:0").err().map(|e| e.kind()) != Some(Unsupported) {
        return Err("a TCP listener over IPv6 is offered now: test it");
    }
    if std::net::ToSocketAddrs::to_socket_addrs(&("no-such-host.invalid", 80)).err().map(|e| e.kind()) != Some(Unsupported) {
        return Err("name lookup is offered now: test it");
    }
    Ok(())
}
