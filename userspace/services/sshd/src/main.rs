// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SSHD.ELF`: the AzOS SSH server.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `entropy` (the ephemeral keys, the allocator), `READ` and `WRITE` on `keys`
//! masked to open a key, read its public part and sign (the host key), the
//! `/fat` tree read-write (it writes `/fat/SSHAUTH.LOG`, the log of its
//! decisions), the right to start the
//! images a session may run, the read-only root directory, the kernel's view
//! of the signed topology's logins (`MemObj inspect.logins`) and the network (its
//! seccomp profile). The files are root names of the volume, and the tree is
//! the whole volume, because the file layer opens no file inside a directory
//! yet (`SSHD_CAPS` in the topology builder says why). Present when Kconfig
//! `SSHD` is `y` (every preset but the MCU kernel and a certifiable build),
//! listening on `SSHD_PORT`.
//!
//! The protocol is `server.rs` and what it uses (`wire.rs`, `packet.rs`,
//! `kex.rs`, `auth.rs`), a state machine with no I/O, and the session
//! behind the channel is `session.rs` over a [`Runner`]; all of it is tested
//! on the host (`tests/host/sshd-tests`). This file is the loop around them:
//! sockets, pipes, the volume.
//!
//! * **Login** is a signature by a key the signed topology lists, under the
//!   user name it lists it for (`[login.NAME]` rows, shown by the kernel in
//!   the `inspect.logins` view and read at every connection). There is nothing on the volume to edit, no
//!   password and no keyboard-interactive method. With no `[login.NAME]` row
//!   nobody can log in; the listening port is open all the same, so the
//!   refusal is a record and not a timeout.
//! * **The host key** is a key of the kernel's keystore (`keys`, the
//!   `azos_devif::keys` interface), named `sshd.host`, bound to this image and
//!   derived from the board's seed: the same image on the same board has the same
//!   host key at every boot, and nothing is stored, on the volume or anywhere
//!   (`azos_syscall::keys`). The secret never reaches this program: it asks for
//!   the public key once and has the kernel sign the exchange hash of each key
//!   exchange. An updated image has another measurement and so another host
//!   key (the clients are asked once more: the known cost of binding a secret to
//!   an image). On a board with no key sector, or for an image the loader did
//!   not measure, the keystore derives nothing; the host key is then a random
//!   key of this boot only (the keystore draws it from the entropy pool). Its
//!   fingerprint is printed on the console at every start.
//! * **Sessions** are the principal `User` (`principal = "user"` on the row of
//!   `SSHD.ELF`, inherited by the images it starts), so what a login does is
//!   held to the envelope of a human's session and not a system service's.
//! * **Decisions**: every refused key exchange, login or session (and every
//!   login) is a line on the console and in `/fat/SSHAUTH.LOG`. The kernel's
//!   decision journal cannot be written from ring 3.
//! * **One connection at a time.** A second one is accepted and closed at
//!   once, so a busy server answers "refused" instead of letting the client
//!   wait; the refusals are counted and recorded once per
//!   [`REFUSAL_WINDOW_MS`] (a flood of them must not write the flash or push
//!   the login records out of the log). A connection that has not logged in
//!   within [`LOGIN_GRACE_MS`] is closed, which bounds how long a client that
//!   connects and idles holds the only slot.
//! * **The log** is cut at [`LOG_MAX`] by rotation: the full file becomes
//!   `/fat/SSHAUTH.OLD` (the one before it is replaced) and a new one starts.
//!
//! One thread. Everything is polled (the socket and the pipes do not block)
//! with a short sleep when nothing moved.

#![no_std]
#![no_main]

extern crate alloc;

mod auth;
#[allow(dead_code)]
#[path = "../../termd/src/disc.rs"]
mod disc;
#[allow(dead_code)]
#[path = "../../termd/src/edit.rs"]
mod edit;
mod kex;
mod packet;
mod policy;
#[allow(dead_code)]
#[path = "../../sh/src/path.rs"]
mod path;
#[allow(dead_code)]
#[path = "../../sh/src/req.rs"]
mod req;
mod server;
mod session;
mod wire;

use alloc::format;
use alloc::vec::Vec;
use auth::AuthKey;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_inspect_lib::{str_in, Inspector, Source};
use azos_libsys as sys;
use azos_ualloc::UserAlloc;
use req::{Fd, ReqBuilder};
use server::{Config, Decision, Env, Event, Server};
use session::{Read, Runner, Session};

#[global_allocator]
static ALLOC: UserAlloc = UserAlloc::new();

// ── Memory pressure ─────────────────────────────────────────────────────────

/// The port the kernel reports this Domain's memory pressure on (0: none), and
/// the level it last reported.
static PRESSURE_PORT: AtomicU32 = AtomicU32::new(0);
static PRESSURE: policy::Pressure = policy::Pressure::new();

/// The level of the next pressure event on the port, or `None` when it is
/// drained. No allocation: the allocator calls this with its lock held.
fn next_pressure_level() -> Option<u8> {
    let port = PRESSURE_PORT.load(Ordering::Relaxed);
    let mut event = [0u8; sys::PORT_EVENT_BYTES];
    while sys::port_poll_typed(port, &mut event) == sys::PORT_EVENT_BYTES as isize {
        if let Some(level) = sys::pressure_level(&event) {
            return Some(level);
        }
    }
    None
}

fn memory_short() -> bool {
    PRESSURE.short(next_pressure_level)
}

/// Have the kernel report this Domain's memory pressure, and let the allocator
/// give the quarantine of freed chunks back to its free lists, instead of
/// mapping another block, where the Domain is at its warning level. The
/// quarantine (`USER_ALLOC_QUARANTINE_KB`) is memory held back for hardening
/// and the connection that just ended is what filled it: the next one asks
/// for blocks of the same classes. A build without reclaim has no pressure to
/// report and refuses the bind: the server runs without the signal and the
/// allocator keeps its quarantine.
fn watch_memory() {
    let port = sys::port_create_typed();
    if port <= 0 {
        return;
    }
    if sys::port_bind_pressure(port as u32, 0) != 0 {
        let _ = sys::close_typed(port as u32);
        return;
    }
    PRESSURE_PORT.store(port as u32, Ordering::Relaxed);
    ALLOC.watch_pressure(memory_short);
}

/// The tree this program may change, and the files in it.
/// The host key's name in the keystore (at most 16 bytes).
const HOST_KEY_NAME: &[u8] = b"sshd.host";
const _: () = assert!(HOST_KEY_NAME.len() <= 16);
const AUTH_LOG: &[u8] = b"/fat/SSHAUTH.LOG\0";
/// The log of before the last rotation.
const AUTH_LOG_OLD: &[u8] = b"/fat/SSHAUTH.OLD\0";
/// The log is rotated when it reaches this size.
const LOG_MAX: usize = 32 * 1024;
/// A connection that has not logged in by then is closed, ms. It is the time
/// an idle client holds the only slot, so it is short: a login takes far less.
const LOGIN_GRACE_MS: u64 = 10_000;
/// Connections refused because one is served are recorded once per window, ms.
const REFUSAL_WINDOW_MS: u64 = 10_000;
/// How long a closing connection is given to send what it still has, ms.
const FLUSH_MS: u64 = 2_000;
/// How long a client has to close the channel after its command ended, ms.
const CLOSE_WAIT_MS: u64 = 10_000;
/// Sleeps of the loop, ms: while a connection moves bytes, and while it is idle.
const BUSY_MS: u64 = 1;
const IDLE_MS: u64 = 5;
/// The wait between looks at the listening socket when nobody is connected.
const LISTEN_MS: u64 = 20;
/// The directory a command starts in.
const CWD: &[u8] = b"/fat";

const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
/// `SIGINT`, the signal a stop request carries.
const SIGINT: u64 = 2;

fn put(line: &str) {
    let _ = sys::console_write(sys::STDOUT, line.as_bytes());
}

// ── The volume ──────────────────────────────────────────────────────────────

/// A file, whole, up to `buf.len()` bytes. `Err` is the open's refusal.
fn read_file(path: &[u8], buf: &mut [u8]) -> Result<usize, isize> {
    let h = sys::open_root(path, 0);
    if h < 0 {
        return Err(h);
    }
    let h = h as u32;
    let mut got = 0;
    while got < buf.len() {
        let n = sys::file_read_typed(h, &mut buf[got..]);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    let _ = sys::close_typed(h);
    Ok(got)
}

/// The size of a file, counted up to `cap` bytes.
fn file_len(path: &[u8], cap: usize) -> usize {
    let h = sys::open_root(path, 0);
    if h < 0 {
        return 0;
    }
    let mut buf = [0u8; 512];
    let mut len = 0usize;
    while len < cap {
        let n = sys::file_read_typed(h as u32, &mut buf);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    let _ = sys::close_typed(h as u32);
    len
}

/// Write `data` to `path` with `flags`. `Err` is the refusal.
fn write_file(path: &[u8], flags: u64, data: &[u8]) -> Result<(), isize> {
    let h = sys::open_root(path, flags);
    if h < 0 {
        return Err(h);
    }
    let h = h as u32;
    let mut at = 0;
    while at < data.len() {
        let n = sys::file_write_typed(h, &data[at..]);
        if n <= 0 {
            let _ = sys::close_typed(h);
            return Err(if n < 0 { n } else { -5 });
        }
        at += n as usize;
    }
    let _ = sys::close_typed(h);
    Ok(())
}

// ── The host: entropy and the log ───────────────────────────────────────────

struct Host {
    entropy: u32,
    /// The kernel's `keys` endpoint and the handle of the host key on it.
    keys: u32,
    host_key: u32,
    /// Bytes in the log file (0 once it was rotated or if it cannot be written).
    log_len: usize,
    log_ok: bool,
    refusals: policy::Refusals,
}

impl Host {
    fn fill(&self, out: &mut [u8]) {
        if sys::dev::entropy_read(self.entropy, out).is_err() {
            // Never go on with a key that is not random.
            put("[sshd] the entropy pool stopped answering: exiting\n");
            sys::exit(2);
        }
    }

    fn log(&mut self, line: &[u8]) {
        let mut rec = line.to_vec();
        rec.push(b'\n');
        let _ = sys::console_write(sys::STDOUT, b"[sshd] ");
        let _ = sys::console_write(sys::STDOUT, &rec);
        if !self.log_ok {
            return;
        }
        if self.log_len + rec.len() > LOG_MAX && !self.rotate() {
            // The records of the file are not kept anywhere else: never cut
            // it without having saved it.
            self.log_ok = false;
            return;
        }
        if write_file(AUTH_LOG, O_WRONLY | O_CREAT | O_APPEND, &rec).is_ok() {
            self.log_len += rec.len();
        } else {
            self.log_ok = false;
        }
    }
}

impl Host {
    /// The full log becomes the `.OLD` file, and a new log starts. False if it
    /// could not be saved (the log is then left as it is).
    fn rotate(&mut self) -> bool {
        // On the heap: a ring-3 stack is 16 KiB.
        let mut old = alloc::vec![0u8; LOG_MAX + 1024];
        let n = match read_file(AUTH_LOG, &mut old) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if write_file(AUTH_LOG_OLD, O_WRONLY | O_CREAT | O_TRUNC, &old[..n]).is_err() {
            return false;
        }
        if write_file(AUTH_LOG, O_WRONLY | O_CREAT | O_TRUNC, b"").is_err() {
            return false;
        }
        self.log_len = 0;
        true
    }

    /// A refused connection: one record per window, the rest counted.
    fn connection_refused(&mut self, now: u64) {
        if let Some(n) = self.refusals.refused(now) {
            self.refusals_record(n);
        }
    }

    /// The refusals held back, recorded (when the connection ends).
    fn refusals_flush(&mut self, now: u64) {
        if let Some(n) = self.refusals.take_pending(now) {
            self.refusals_record(n);
        }
    }

    fn refusals_record(&mut self, n: u32) {
        self.decision(Decision {
            rule: server::Rule::Session,
            verdict: server::Verdict::Refuse,
            subject: format!("{n} connection(s)").into_bytes(),
            key: None,
            why: "one connection at a time",
        });
    }
}

impl Env for Host {
    fn random(&mut self, out: &mut [u8]) {
        self.fill(out);
    }

    fn sign_host(&mut self, msg: &[u8]) -> Option<[u8; 64]> {
        sys::dev::keys_sign(self.keys, self.host_key, msg).ok()
    }

    fn decision(&mut self, d: Decision) {
        self.log(&d.line());
    }
}

// ── The host key and the logins ─────────────────────────────────────────────

/// The name of the host key in the keystore: sixteen bytes, as words.
fn host_key_name() -> [u64; sys::dev::keys::NAME_WORDS] {
    let mut b = [0u8; 16];
    b[..HOST_KEY_NAME.len()].copy_from_slice(HOST_KEY_NAME);
    [u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
     u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])]
}

/// The host key in the keystore: its handle and its public key.
///
/// First the key the board derives for this image (`sshd.host`: the same at
/// every boot); where the keystore derives none (no board key sector, an image
/// the loader did not measure) a random key of this boot, owner-wide because an
/// unmeasured image has no image to be bound to. `None`: the keystore gives no
/// key at all (no right on the endpoint, an unseeded pool).
fn open_host_key(ep: u32) -> Option<(u32, [u8; 32])> {
    use sys::dev::KeysCall;
    // Spelled out and not imported: the syscall scanner of the seccomp tests
    // reads `use sys::dev::keys` as a libsys function named `keys`.
    type Policy = sys::dev::keys::Policy;
    let mut c = sys::dev::KeysClient::new(sys::dev::Ep(ep));
    let derived = Policy {
        purpose: sys::dev::keys::purpose::SIGN,
        envelope: sys::dev::keys::envelope::IMAGE,
        backend: sys::dev::keys::backend::BOOT,
        ..Policy::default()
    };
    let key = match sys::dev::value(c.generate(host_key_name(), derived)) {
        Ok(k) => {
            put("[sshd] host key from the keystore (derived for this image on this board)\n");
            k
        }
        Err(sys::dev::outcome::NOT_READY) => {
            let ephemeral = Policy {
                purpose: sys::dev::keys::purpose::SIGN,
                envelope: sys::dev::keys::envelope::OWNER,
                backend: sys::dev::keys::backend::VOLATILE,
                ..Policy::default()
            };
            let k = sys::dev::value(c.generate([0; 2], ephemeral)).ok()?;
            put("[sshd] the keystore derives this image no key (no board key sector, or this image was not measured): using a host key of this boot only\n");
            k
        }
        Err(rc) => {
            put(&format!("[sshd] the keystore refused the host key (outcome {rc})\n"));
            return None;
        }
    };
    let words = sys::dev::value(c.public(key)).ok()?;
    let mut pk = [0u8; 32];
    for (c, w) in pk.chunks_exact_mut(8).zip(words.iter()) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    Some((key, pk))
}

/// The logins view, mapped at the first connection: a region maps once per
/// task, and the view is read again at every connection.
struct ViewCell(core::cell::UnsafeCell<Option<Inspector<'static>>>);
// SAFETY: only the main thread reads the logins.
unsafe impl Sync for ViewCell {}
static LOGINS_VIEW: ViewCell = ViewCell(core::cell::UnsafeCell::new(None));

/// The logins of the signed topology, from the kernel's view of them (`MemObj
/// inspect.logins`, `logins/<n>/{user, key}`), read at every connection.
fn load_keys() -> auth::Parsed {
    let mut out = auth::Parsed::default();
    // SAFETY: the main thread's alone (see `ViewCell`).
    let cell = unsafe { &mut *LOGINS_VIEW.0.get() };
    if cell.is_none() {
        let tree = sys::inspect_map(azos_abi::cap::SHM_INSPECT_LOGINS)
            // SAFETY: the mapping lives as long as the task, read-only, and
            // the kernel writes it only with aligned 64-bit stores.
            .and_then(|m| unsafe { Inspector::from_mapped(m, None) }.map_err(|_| -1));
        match tree {
            Ok(t) => *cell = Some(t),
            Err(rc) => {
                put(&format!("[sshd] cannot read the logins view (rc {rc}): no key can log in\n"));
                return out;
            }
        }
    }
    let Some(tree) = cell.as_mut() else { return out };
    let _ = tree.with(Source::Public, |r| {
        out = auth::Parsed::default();
        let Some(dir) = r.lookup("logins")? else { return Ok(()) };
        r.children(dir, &mut |info, _| match (str_in(r, info.id, "user"), str_in(r, info.id, "key")) {
            (Ok(Some(u)), Ok(Some(k))) => out.add(u.as_bytes(), k.as_bytes()),
            _ => out.skipped += 1,
        })
    });
    out
}

// ── Commands: the Runner over SYS_SPAWN_EX and two pipes ────────────────────

struct Spawner {
    tid: u32,
    /// The pipe ends this task keeps: the command's stdin (write) and
    /// stdout/stderr (read).
    stdin: Option<u32>,
    stdout: Option<u32>,
    /// The command's own ends, kept open here until it is over. Given up at
    /// the spawn, the command's pipe has no reader (or no writer) until it
    /// first runs: the data written to it before then is refused as a write to
    /// a pipe nobody reads, and the stream reads as ended.
    held: [Option<u32>; 2],
    status: Option<i32>,
}

impl Spawner {
    const fn new() -> Self {
        Self { tid: 0, stdin: None, stdout: None, held: [None; 2], status: None }
    }

    /// Give up the ends the command is done with. Its output end stays: what
    /// it wrote before it exited is still to be read.
    fn release_input(&mut self) {
        for t in self.held.iter_mut().chain([&mut self.stdin]) {
            if let Some(t) = t.take() {
                let _ = sys::pipe::close(t);
            }
        }
    }

    /// Give every end up: the next command starts, or the session is over.
    fn release(&mut self) {
        self.release_input();
        if let Some(t) = self.stdout.take() {
            let _ = sys::pipe::close(t);
        }
    }

    /// The image `name` runs as, and whether the volume has it.
    fn image(name: &[u8], out: &mut [u8; path::PATH_MAX + 1]) -> Result<usize, &'static str> {
        if path::is_applet(name) {
            out[..path::TOOLBOX.len()].copy_from_slice(path::TOOLBOX);
            out[path::TOOLBOX.len()] = 0;
            return Ok(path::TOOLBOX.len());
        }
        if name.contains(&b'/') {
            return Err("name an image, not a path");
        }
        let mut file = [0u8; 12];
        let n = path::elf_name(name, &mut file).map_err(|e| core::str::from_utf8(e.message()).unwrap_or("bad name"))?;
        let dir = b"/fat/";
        out[..dir.len()].copy_from_slice(dir);
        out[dir.len()..dir.len() + n].copy_from_slice(&file[..n]);
        let len = dir.len() + n;
        out[len] = 0;
        let h = sys::open_root(&out[..len + 1], 0);
        if h < 0 {
            return Err("command not found");
        }
        let _ = sys::close_typed(h as u32);
        Ok(len)
    }
}

impl Runner for Spawner {
    fn spawn(&mut self, argv: &[Vec<u8>]) -> Result<(), &'static str> {
        let mut image = [0u8; path::PATH_MAX + 1];
        let il = Self::image(&argv[0], &mut image)?;
        let mut rb = ReqBuilder::new();
        for a in argv {
            if !rb.arg(a) {
                return Err("arguments too long");
            }
        }
        let _ = rb.env(b"PATH=/fat");
        rb.cwd(CWD);
        let stdin = sys::pipe::create().map_err(|_| "no pipe available")?;
        let stdout = match sys::pipe::create() {
            Ok(p) => p,
            Err(_) => {
                let _ = sys::pipe::close(stdin[0]);
                let _ = sys::pipe::close(stdin[1]);
                return Err("no pipe available");
            }
        };
        let close_all = || {
            for t in [stdin[0], stdin[1], stdout[0], stdout[1]] {
                let _ = sys::pipe::close(t);
            }
        };
        let (Ok((cap_in, _)), Ok((cap_out, _))) = (sys::pipe::region_of(stdin[0]), sys::pipe::region_of(stdout[1])) else {
            close_all();
            return Err("cannot share the pipes with the command");
        };
        rb.fd(0, Fd::Handle(cap_in));
        rb.fd(1, Fd::Handle(cap_out));
        rb.fd(2, Fd::Handle(cap_out));
        let r = rb.finish(sys::SPAWN_F_DIE_WITH_PARENT);
        let tid = sys::spawn_ex(&image[..il + 1], Some(&r));
        if tid <= 0 {
            close_all();
            return Err(match tid {
                -13 => "not permitted (no launch grant for this image)",
                _ => "could not start",
            });
        }
        let _ = sys::pipe::set_nonblock(stdin[1], true);
        let _ = sys::pipe::set_nonblock(stdout[0], true);
        self.release();
        self.tid = tid as u32;
        self.stdin = Some(stdin[1]);
        self.stdout = Some(stdout[0]);
        self.held = [Some(stdin[0]), Some(stdout[1])];
        self.status = None;
        Ok(())
    }

    fn write_stdin(&mut self, data: &[u8]) -> usize {
        let Some(t) = self.stdin else { return data.len() };
        match sys::pipe::write(t, data) {
            n if n > 0 => n as usize,
            // A full pipe: try again. Anything else (the command has gone, or
            // closed its input): the bytes have nowhere to go.
            -11 => 0,
            _ => data.len(),
        }
    }

    fn close_stdin(&mut self) {
        if let Some(t) = self.stdin.take() {
            let _ = sys::pipe::close(t);
        }
    }

    fn read_output(&mut self, buf: &mut [u8]) -> Read {
        let Some(t) = self.stdout else { return Read::Eof };
        match sys::pipe::read(t, buf) {
            n if n > 0 => Read::Data(n as usize),
            0 => Read::Eof,
            -11 => Read::Empty,
            _ => Read::Eof,
        }
    }

    fn exit_status(&mut self) -> Option<i32> {
        if self.status.is_none() && self.tid != 0 {
            let mut st: i32 = 0;
            let r = sys::waitpid(self.tid, &mut st as *mut i32);
            if r > 0 {
                self.status = Some(st);
            } else if r == -10 {
                // Reaped elsewhere: gone.
                self.status = Some(127);
            }
        }
        if self.status.is_some() {
            self.release_input();
        }
        self.status
    }

    fn stop(&mut self, force: bool) {
        if self.tid != 0 && self.status.is_none() {
            let how = if force { sys::KILL_FORCE } else { sys::KILL_REQUEST };
            let _ = sys::task_kill(self.tid, how, SIGINT, sys::KILL_SUBTREE);
        }
    }
}

impl Drop for Spawner {
    fn drop(&mut self) {
        self.release();
    }
}

// ── Sockets ─────────────────────────────────────────────────────────────────

fn listen(port: u16) -> Option<u32> {
    let cap = sys::socket_typed(2, 1, 0);
    if cap < 0 {
        return None;
    }
    let cap = cap as u32;
    if sys::bind_typed(cap, &sys::sockaddr_in([0, 0, 0, 0], port)) < 0 || sys::listen_typed(cap) < 0 {
        let _ = sys::close_typed(cap);
        return None;
    }
    Some(cap)
}

/// Send what the server queued; true if any went.
fn flush(sock: u32, srv: &mut Server) -> bool {
    let mut moved = false;
    loop {
        let p = srv.pending();
        if p.is_empty() {
            return moved;
        }
        let n = sys::send_typed(sock, &p[..p.len().min(sys::SOCK_SEND_MAX)]);
        if n <= 0 {
            return moved;
        }
        srv.advance(n as usize);
        moved = true;
    }
}

const E_EOF: isize = azos_abi::error::Errno::EEOF.to_syscall_ret() as isize;

/// Serve one connection until it ends.
fn serve(host: &mut Host, listener: u32, sock: u32, cfg: &Config) {
    let mut srv = Server::new(cfg, host);
    let mut sess: Option<Session<Spawner>> = None;
    let started = sys::vdso_uptime_ms();
    let mut closing_since: Option<u64> = None;
    let mut finishing = false;
    let mut finished_at: Option<u64> = None;
    let mut buf = alloc::vec![0u8; 2048];
    let mut idle = 0u32;
    loop {
        let now = sys::vdso_uptime_ms();
        let mut moved = false;

        // Bytes from the peer.
        if closing_since.is_none() {
            let n = sys::recv_typed(sock, &mut buf);
            if n > 0 {
                srv.feed(host, &buf[..n as usize]);
                moved = true;
            } else if n == E_EOF || n < 0 {
                // The peer is gone.
                if let Some(s) = &mut sess {
                    s.on_close();
                }
                break;
            }
        }

        // What the server saw.
        while let Some(ev) = srv.pop_event() {
            moved = true;
            match ev {
                // The login is already a decision record (the server wrote it).
                Event::Authenticated { .. } => sess = Some(Session::new(Spawner::new())),
                Event::Pty { cols, rows, .. } => {
                    if let Some(s) = &mut sess {
                        s.on_pty(cols, rows);
                    }
                }
                Event::Resize { cols, rows } => {
                    if let Some(s) = &mut sess {
                        s.on_resize(cols, rows);
                    }
                }
                Event::Shell => {
                    if let Some(s) = &mut sess {
                        s.on_shell();
                    }
                }
                Event::Exec(cmd) => {
                    if let Some(s) = &mut sess {
                        s.on_exec(&cmd, now);
                    }
                }
                Event::Data(d) => {
                    if let Some(s) = &mut sess {
                        s.on_data(&d, now);
                    }
                }
                Event::Eof => {
                    if let Some(s) = &mut sess {
                        s.on_eof(now);
                    }
                }
                Event::Closed => {
                    if let Some(s) = &mut sess {
                        s.on_close();
                    }
                    finishing = true;
                }
            }
        }

        // The session: run it, and send its output on the channel.
        if let Some(s) = &mut sess {
            if s.pump(now) {
                moved = true;
            }
            while !s.output().is_empty() && srv.pending().len() < 16 * 1024 {
                let n = srv.write(s.output());
                if n == 0 {
                    break;
                }
                s.consumed(n);
                moved = true;
            }
            if let Some(status) = s.finished() {
                if !finishing {
                    srv.finish(status);
                    finishing = true;
                    finished_at = Some(now);
                    moved = true;
                }
            }
        }

        if flush(sock, &mut srv) {
            moved = true;
        }

        // A client that has not logged in, or a connection that is over.
        if !srv.is_authenticated() && !srv.is_closed() && now.saturating_sub(started) > LOGIN_GRACE_MS {
            host.log(b"login refuse why=no login within the grace time");
            srv.disconnect(wire::DISCONNECT_BY_APPLICATION, "login grace time exceeded");
        }
        // The command is over and told: the client closes the channel in
        // answer. One that does not is let go.
        if finished_at.is_some_and(|t| now.saturating_sub(t) > CLOSE_WAIT_MS) && !srv.is_closed() {
            srv.disconnect(wire::DISCONNECT_BY_APPLICATION, "session over");
        }
        if srv.is_closed() {
            if closing_since.is_none() {
                closing_since = Some(now);
                if let Some(s) = &mut sess {
                    s.on_close();
                }
            }
            if srv.pending().is_empty() || now.saturating_sub(closing_since.unwrap_or(now)) > FLUSH_MS {
                break;
            }
        }

        // Another client while this one is served: refused at the door.
        let extra = sys::accept_typed(listener);
        if extra >= 0 {
            host.connection_refused(now);
            let _ = sys::close_typed(extra as u32);
            moved = true;
        }

        if moved {
            idle = 0;
            sys::sleep(BUSY_MS);
        } else {
            idle = idle.saturating_add(1);
            sys::sleep(if idle > 50 { IDLE_MS } else { BUSY_MS });
        }
    }
    // Everything the session started goes with the connection.
    if let Some(s) = &mut sess {
        s.on_close();
    }
    // The refusals held back are written once the connection is over.
    host.refusals_flush(sys::vdso_uptime_ms());
}

fn lossy(b: &[u8]) -> alloc::string::String {
    b.iter().take(96).map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '?' }).collect()
}

/// A panic ends the process with 70 (the supervisor restarts it) after saying
/// where, on the console: a daemon that dies without a word is not debuggable.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct Line {
        b: [u8; 256],
        n: usize,
    }
    impl Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let k = s.len().min(self.b.len() - self.n);
            self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
            self.n += k;
            Ok(())
        }
    }
    let mut l = Line { b: [0; 256], n: 0 };
    let _ = write!(l, "[sshd] panic");
    if let Some(loc) = info.location() {
        let _ = write!(l, " at {}:{}", loc.file(), loc.line());
    }
    let _ = write!(l, "\n");
    let _ = sys::console_write(sys::STDOUT, &l.b[..l.n]);
    sys::exit(70)
}

#[sys::main]
fn main() -> ! {
    put("[sshd] AzOS SSH server\n");
    watch_memory();
    let Some(ep) = sys::dev::lookup(sys::dev::key::ENTROPY, 0) else {
        put("[sshd] no entropy endpoint in the row: no host key, refusing to run\n");
        sys::exit(2);
    };
    let Some(keys_ep) = sys::dev::lookup(sys::dev::key::KEYS, 0) else {
        put("[sshd] no keys endpoint in the row: no host key, refusing to run\n");
        sys::exit(2);
    };
    let Some((host_key, host_public)) = open_host_key(keys_ep) else {
        put("[sshd] no host key from the keystore: refusing to run\n");
        sys::exit(2);
    };
    let mut host = Host {
        entropy: ep, keys: keys_ep, host_key, log_len: 0, log_ok: true, refusals: policy::Refusals::new(REFUSAL_WINDOW_MS),
    };
    // The log, as it stands: it is cut when it grows past its limit.
    host.log_len = file_len(AUTH_LOG, LOG_MAX);
    let keys = load_keys();
    if keys.skipped != 0 {
        put(&format!("[sshd] {} login(s) of the view skipped (not a user and a 32-byte key)\n", keys.skipped));
    }
    let mut cfg = Config::new(host_public, keys.keys);
    put(&format!(
        "[sshd] host key {}\n",
        lossy(&kex::fingerprint(&cfg.host_public))
    ));
    let port = azos_limits::SSHD_PORT as u16;
    let Some(listener) = listen(port) else {
        // No stack, or the port is taken: nothing to serve, and nothing to
        // restart for (the supervisor restarts a failure, not an exit 0).
        put(&format!("[sshd] cannot listen on port {port}: exiting\n"));
        sys::exit(0);
    };
    put(&format!("[sshd] listening on port {port}, {} authorized key(s)\n", cfg.authorized.len()));
    if cfg.authorized.is_empty() {
        put("[sshd] no key can log in: the signed topology has no [login.NAME] row\n");
    }
    loop {
        let c = sys::accept_typed(listener);
        if c < 0 {
            sys::sleep(LISTEN_MS);
            continue;
        }
        // Keys are read afresh for every connection.
        let keys: Vec<AuthKey> = load_keys().keys;
        cfg.authorized = keys;
        serve(&mut host, listener, c as u32, &cfg);
        let _ = sys::close_typed(c as u32);
    }
}
