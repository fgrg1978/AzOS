// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The real client: OpenSSH (`ssh`, `ssh-keygen`) against the server over TCP
//! on the loopback, when the host has them (the tests say so and pass when it
//! does not).
//!
//! The server side of the loop is the one `main.rs` runs, over `std` sockets;
//! the commands behind the session are a small `Runner` here.

use crate::auth::{key_of_blob, AuthKey};
use crate::server::{Config, Decision, Event, Server};
use crate::session::{Read, Runner, Session};
use crate::harness::{base64_decode, host_seed, pubkey, TestEnv};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── Commands ────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Cmds {
    out: Vec<u8>,
    at: usize,
    exit: Option<i32>,
    cat: bool,
    input_closed: bool,
    started: bool,
}

impl Runner for Cmds {
    fn spawn(&mut self, argv: &[Vec<u8>]) -> Result<(), &'static str> {
        *self = Cmds { started: true, ..Cmds::default() };
        match &argv[0][..] {
            b"echo" => {
                self.out = argv[1..].join(&b' ');
                self.out.push(b'\n');
                self.exit = Some(0);
            }
            b"false" => self.exit = Some(1),
            b"cat" => self.cat = true,
            b"big" => {
                self.out = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
                self.exit = Some(0);
            }
            _ => return Err("command not found"),
        }
        Ok(())
    }

    fn write_stdin(&mut self, data: &[u8]) -> usize {
        if self.cat {
            self.out.extend_from_slice(data);
        }
        data.len()
    }

    fn close_stdin(&mut self) {
        self.input_closed = true;
        if self.cat {
            self.exit = Some(0);
        }
    }

    fn read_output(&mut self, buf: &mut [u8]) -> Read {
        if self.at < self.out.len() {
            let n = buf.len().min(self.out.len() - self.at);
            buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
            self.at += n;
            return Read::Data(n);
        }
        if self.exit.is_some() { Read::Eof } else { Read::Empty }
    }

    fn exit_status(&mut self) -> Option<i32> {
        if self.started { self.exit } else { None }
    }

    fn stop(&mut self, _force: bool) {
        self.exit = Some(130);
    }
}

// ── The server loop ─────────────────────────────────────────────────────────

fn serve_one(listener: &TcpListener, authorized: Vec<AuthKey>) -> Vec<Decision> {
    let (mut sock, _) = listener.accept().unwrap();
    sock.set_nonblocking(true).unwrap();
    sock.set_nodelay(true).unwrap();
    let cfg = Config::new(pubkey(&host_seed()), authorized);
    let mut env = TestEnv::default();
    let mut srv = Server::new(&cfg, &mut env);
    let mut sess: Option<Session<Cmds>> = None;
    let mut buf = [0u8; 4096];
    let t0 = Instant::now();
    let mut finishing = false;
    loop {
        let now = t0.elapsed().as_millis() as u64;
        assert!(now < 60_000, "the server loop ran for a minute");
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => srv.feed(&mut env, &buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        while let Some(ev) = srv.pop_event() {
            match ev {
                Event::Authenticated { .. } => sess = Some(Session::new(Cmds::default())),
                Event::Pty { cols, rows, .. } => sess.as_mut().unwrap().on_pty(cols, rows),
                Event::Resize { cols, rows } => sess.as_mut().unwrap().on_resize(cols, rows),
                Event::Shell => sess.as_mut().unwrap().on_shell(),
                Event::Exec(c) => sess.as_mut().unwrap().on_exec(&c, now),
                Event::Data(d) => sess.as_mut().unwrap().on_data(&d, now),
                Event::Eof => sess.as_mut().unwrap().on_eof(now),
                Event::Closed => finishing = true,
            }
        }
        if let Some(s) = &mut sess {
            s.pump(now);
            while !s.output().is_empty() {
                let n = srv.write(s.output());
                if n == 0 {
                    break;
                }
                s.consumed(n);
            }
            if let Some(st) = s.finished() {
                if !finishing {
                    srv.finish(st);
                    finishing = true;
                }
            }
        }
        while !srv.pending().is_empty() {
            match sock.write(srv.pending()) {
                Ok(n) if n > 0 => srv.advance(n),
                _ => break,
            }
        }
        if srv.is_closed() && srv.pending().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_micros(300));
    }
    env.decisions
}

// ── The client ──────────────────────────────────────────────────────────────

fn have(tool: &str) -> bool {
    Command::new(tool).arg("-V").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("azos-sshd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }

    fn key(&self, name: &str) -> (PathBuf, Vec<AuthKey>) {
        let k = self.0.join(name);
        let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"]).arg(&k).status().unwrap();
        assert!(st.success());
        let pubtext = std::fs::read(format!("{}.pub", k.display())).unwrap();
        // `ssh-ed25519 <base64 blob> <comment>`: the key logs in as `tester`.
        let blob = pubtext.split(|&c| c == b' ').nth(1).and_then(base64_decode).unwrap();
        let key = key_of_blob(&blob).unwrap();
        (k, vec![AuthKey { user: b"tester".to_vec(), key }])
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Run {
    status: i32,
    stdout: Vec<u8>,
    stderr: String,
    decisions: Vec<Decision>,
}

fn run_ssh(key: &Path, authorized: Vec<AuthKey>, extra: &[&str], remote: &[&str], stdin: Option<&[u8]>) -> Run {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || serve_one(&listener, authorized));
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-F", "/dev/null", "-p", &port.to_string(), "-i",
    ])
    .arg(key)
    .args([
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
        "-o", "PreferredAuthentications=publickey", "-o", "IdentityAgent=none",
    ])
    .args(extra)
    .arg("tester@127.0.0.1")
    .args(remote)
    .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(d) = stdin {
        let mut i = child.stdin.take().unwrap();
        i.write_all(d).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let decisions = server.join().unwrap();
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        decisions,
    }
}

macro_rules! need_openssh {
    () => {
        if !have("ssh") || !have("ssh-keygen") {
            eprintln!("skipped: no OpenSSH client on this host");
            return;
        }
    };
}

#[test]
fn openssh_runs_a_command_and_gets_its_output_and_status() {
    need_openssh!();
    let d = Dir::new("exec");
    let (key, keys) = d.key("id");
    let r = run_ssh(&key, keys.clone(), &[], &["echo", "hello", "world"], None);
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(r.stdout, b"hello world\n");
    assert!(r.decisions.iter().any(|d| d.why == "authorized key, signature verifies"), "{:?}", r.decisions);
    let r = run_ssh(&key, keys.clone(), &[], &["false"], None);
    assert_eq!(r.status, 1, "stderr: {}", r.stderr);
    let r = run_ssh(&key, keys, &[], &["nonesuch"], None);
    assert_eq!(r.status, 127);
    assert!(r.stdout.starts_with(b"command not found"), "{:?}", String::from_utf8_lossy(&r.stdout));
}

#[test]
fn openssh_stdin_reaches_the_command_and_eof_ends_it() {
    need_openssh!();
    let d = Dir::new("stdin");
    let (key, keys) = d.key("id");
    let r = run_ssh(&key, keys, &[], &["cat"], Some(b"line one\nline two\n"));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(r.stdout, b"line one\nline two\n");
}

#[test]
fn openssh_gets_a_large_output_through_the_window() {
    need_openssh!();
    let d = Dir::new("big");
    let (key, keys) = d.key("id");
    let r = run_ssh(&key, keys, &[], &["big"], None);
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    let want: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    assert_eq!(r.stdout.len(), want.len());
    assert!(r.stdout == want);
}

#[test]
fn openssh_survives_a_rekey_in_the_middle_of_a_large_output() {
    need_openssh!();
    let d = Dir::new("rekey");
    let (key, keys) = d.key("id");
    // The client re-exchanges keys after 4 KiB: several times over the output.
    let r = run_ssh(&key, keys, &["-o", "RekeyLimit=4K"], &["big"], None);
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.len(), 300_000);
}

#[test]
fn openssh_with_an_unlisted_key_is_refused_and_the_refusal_recorded() {
    need_openssh!();
    let d = Dir::new("deny");
    let (_k1, listed) = d.key("listed");
    let (k2, _) = d.key("stranger");
    let r = run_ssh(&k2, listed, &[], &["echo", "no"], None);
    assert_eq!(r.status, 255, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("Permission denied"), "{}", r.stderr);
    assert!(r.stdout.is_empty());
    let refused: Vec<_> = r.decisions.iter().filter(|d| d.why == "key is not authorized").collect();
    assert!(!refused.is_empty(), "{:?}", r.decisions);
    assert_eq!(refused[0].subject, b"tester");
}

#[test]
fn openssh_interactive_session_with_a_pty() {
    need_openssh!();
    let d = Dir::new("shell");
    let (key, keys) = d.key("id");
    // -tt: a pty even though our stdin is a pipe. The script is the keystrokes.
    let r = run_ssh(&key, keys, &["-tt"], &[], Some(b"echo from the prompt\nfalse\nexit 5\n"));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(out.contains("AzOS console over ssh"), "{out:?}");
    assert!(out.contains("azos-ssh$ "), "{out:?}");
    assert!(out.contains("from the prompt"), "{out:?}");
    assert_eq!(r.status, 5, "stderr: {}\nstdout: {out:?}", r.stderr);
}

#[test]
fn openssh_port_forwarding_is_refused_and_recorded() {
    need_openssh!();
    let d = Dir::new("fwd");
    let (key, keys) = d.key("id");
    // -L opens a local listener; the first connection to it asks for a
    // direct-tcpip channel. Connect to it from here while the session runs.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || serve_one(&listener, keys));
    let local = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut child = Command::new("ssh")
        .args(["-F", "/dev/null", "-p", &port.to_string(), "-i"])
        .arg(&key)
        .args([
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o", "IdentityAgent=none",
            "-o", "ExitOnForwardFailure=yes", "-L", &format!("{local}:127.0.0.1:9"),
            "tester@127.0.0.1", "cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait for the forward to listen, use it, then end the session.
    let t0 = Instant::now();
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", local)) {
            let _ = s.write_all(b"x");
            let mut b = [0u8; 8];
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = s.read(&mut b);
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "the forward never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(child.stdin.take());
    let _ = child.wait_with_output().unwrap();
    let decisions = server.join().unwrap();
    assert!(
        decisions.iter().any(|d| d.subject == b"direct-tcpip" && d.why.starts_with("channel type not offered")),
        "{decisions:?}"
    );
}
