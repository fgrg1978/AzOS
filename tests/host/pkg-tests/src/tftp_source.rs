// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer's development package source: `pkg fetch` over TFTP.
//!
//! `userspace/services/pkgd/src/tftp.rs` is included unchanged, the same file
//! the ring-3 installer runs, over a real UDP socket on loopback, with a TFTP
//! server in a thread of the test. The installer behind it is the real one
//! (`userspace/lib/packages`) over an in-memory volume, so a package that
//! arrives is judged against the signers of the device's signed topology and
//! staged and journalled as one a client handed over.
//!
//! What the tests pin: the transport decides nothing. A package signed by the
//! device's author is installed; the same package with one bit of its
//! signature changed is refused and journalled (**canary**
//! `pkg-verify-skip-canary`: the signature check off, and the forgery is
//! installed). A lost block is asked for again, and a production build does
//! not take a TFTP source at all.

#[path = "../../../../userspace/services/pkgd/src/tftp.rs"]
mod tftp;

use super::*;
use crate::service::{Fake, MemVol, Rig};
use azos_decision::{Rule, Verdict};
use azos_packages::{status, step, step_name, step_of, FetchErr, Packages, Remote};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread::JoinHandle;
use std::time::Duration;
use tftp::{is_tftp, RowError, Source, Sources, TftpRemote};

const BLOCK: usize = 512;
const FILE: &str = "acme.pkg";

/// A TFTP server that serves one file to the one request it waits for.
struct Server {
    addr: SocketAddrV4,
    thread: JoinHandle<()>,
}

impl Server {
    /// Serve `data` as `name`. `lose` is the block whose first transmission is
    /// lost on the way: it is sent again only when the client asks, by sending
    /// its last ACK again (the server never retransmits it on its own).
    fn serve(name: &'static str, data: Vec<u8>, lose: Option<u16>) -> Server {
        assert_ne!(data.len() % BLOCK, 0, "the last block is the short one that ends the transfer");
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let SocketAddr::V4(addr) = listener.local_addr().unwrap() else { unreachable!() };
        let thread = std::thread::spawn(move || {
            let mut rrq = [0u8; 600];
            let Ok((n, client)) = listener.recv_from(&mut rrq) else { return };
            // RFC 1350 §5: opcode 1, the file name, a NUL, the mode, a NUL.
            assert_eq!(u16::from_be_bytes([rrq[0], rrq[1]]), 1, "the first datagram is a read request");
            let asked = rrq[2..n].split(|&b| b == 0).next().unwrap();
            // The reply comes from a port of its own (the TID), as a real server's does.
            let tid = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            tid.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            if asked != name.as_bytes() {
                tid.send_to(&[0, 5, 0, 1, b'n', b'o', b'n', b'e', 0], client).unwrap();
                return;
            }
            let (mut block, mut lost, mut lose) = (1u16, false, lose);
            loop {
                let from = (block as usize - 1) * BLOCK;
                let chunk = &data[from..data.len().min(from + BLOCK)];
                let mut pkt = vec![0, 3];
                pkt.extend_from_slice(&block.to_be_bytes());
                pkt.extend_from_slice(chunk);
                if lose == Some(block) {
                    lose = None;
                    lost = true;
                } else {
                    tid.send_to(&pkt, client).unwrap();
                }
                let mut tries = 0;
                loop {
                    let mut ack = [0u8; 16];
                    match tid.recv_from(&mut ack) {
                        // The client ended the transfer (RFC 1350 §7): nothing more is owed.
                        Ok((n, _)) if n >= 2 && ack[..2] == [0, 5] => return,
                        Ok((4, _)) if ack[..2] == [0, 4] => {
                            let acked = u16::from_be_bytes([ack[2], ack[3]]);
                            if acked == block {
                                break;
                            }
                            // The ACK before it, sent again: the block it asks for was lost.
                            if lost && acked == block.wrapping_sub(1) {
                                lost = false;
                                tid.send_to(&pkt, client).unwrap();
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            tries += 1;
                            // A block lost on the way is not sent again by the
                            // server on its own: only the client's ACK can bring it.
                            if lost || tries > 5 {
                                return;
                            }
                            tid.send_to(&pkt, client).unwrap();
                        }
                    }
                }
                if chunk.len() < BLOCK {
                    return;
                }
                block += 1;
            }
        });
        Server { addr, thread }
    }

    fn rows(&self, file: &str) -> Vec<u8> {
        format!("tftp={}\nfile={file}\n", self.addr).into_bytes()
    }
}

fn dev() -> Device0 {
    Device0::with_signers(&signer_text("acme", &author(), CEILING))
}

fn rig_with(rows: &[u8]) -> Rig {
    let r = Rig::new(MemVol::device(&dev(), &owner()));
    r.vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), rows.to_vec());
    r
}

/// A signed package of several blocks: the image is the bulk of it.
fn package(key: &SigningKey) -> Vec<u8> {
    let mut s = Spec::acme();
    s.images = vec![("ACME.ELF".into(), (0..3000u32).map(|i| (i * 7) as u8).collect())];
    build(&s, key)
}

#[test]
fn rows_describe_a_tftp_source() {
    let s = Source::parse(b"# the development host\ntftp=10.0.2.2   # QEMU's gateway\nfile=acme.pkg\n").unwrap();
    assert_eq!((s.server, s.file.as_str()), (SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 2), 69), "acme.pkg"), "no port is the well-known one");
    let s = Source::parse(b"file=a.pkg\ntftp=192.168.1.5:6969\n").unwrap();
    assert_eq!(s.server, SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 6969));
    assert!(is_tftp(b"tftp=10.0.2.2\n"));
    assert!(is_tftp(b"# c\n  tftp = 10.0.2.2\n"));
    assert!(!is_tftp(b"host=packages.example.org\naddr=203.0.113.7:443\npath=/a.pkg\npin_1=00\n"));
    assert!(!is_tftp(b"path=/tftp=x\n"), "the key decides, not a word in a value");
    assert!(!is_tftp(&[0xFF, 0xFE]));
}

#[test]
fn rows_that_are_not_a_source_are_refused() {
    let bad = |rows: &[u8]| Source::parse(rows).unwrap_err();
    assert_eq!(bad(&[0xFF]), RowError::Encoding);
    assert_eq!(bad(b"tftp=10.0.2.2\n"), RowError::Missing("file"));
    assert_eq!(bad(b"file=a.pkg\n"), RowError::Missing("tftp"));
    assert_eq!(bad(b"tftp=10.0.2.2\ntftp=10.0.2.3\nfile=a\n"), RowError::Duplicate(2));
    assert_eq!(bad(b"tftp=10.0.2.2\nfile=a\npin_1=00\n"), RowError::Line(3), "an HTTPS row is not a TFTP one");
    assert_eq!(bad(b"tftp=10.0.2.2\nfile\n"), RowError::Line(2));
    assert_eq!(bad(b"tftp=nowhere\nfile=a\n"), RowError::Value("tftp"));
    assert_eq!(bad(b"tftp=[::1]:69\nfile=a\n"), RowError::Value("tftp"), "the stack has no UDP over IPv6");
    assert_eq!(bad(b"tftp=10.0.2.2\nfile=a b\n"), RowError::Value("file"));
    assert_eq!(bad(b"tftp=10.0.2.2\nfile=\n"), RowError::Value("file"));
    let long = format!("tftp=10.0.2.2\nfile={}\n", "a".repeat(azos_tftp::TFTP_MAX_FILENAME_BYTES + 1));
    assert_eq!(bad(long.as_bytes()), RowError::Value("file"));
}

/// The honest flow: fetched over TFTP, verified against the device's signers,
/// admitted, staged and journalled -- as a package a client handed over.
#[test]
fn a_package_fetched_over_tftp_is_installed() {
    let bytes = package(&author());
    assert!(bytes.len() > 4 * BLOCK, "several blocks, so the lock-step is exercised");
    let server = Server::serve(FILE, bytes.clone(), None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch();
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!(reply[2], 1, "one row");
    server.thread.join().unwrap();
    let staged = r.vol.borrow().staged();
    assert_eq!(staged.len(), 1);
    assert_eq!(r.vol.borrow().files[staged[0].as_bytes()], bytes, "every byte of the signed package is what is staged");
    let j = r.vol.borrow().journal();
    assert_eq!(j.len(), 1);
    assert_eq!((j[0].rule, j[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
}

/// **The gate is the signature, not the wire.** One bit of the signature
/// changed on the server: the package arrives whole and is refused, journalled,
/// staged nowhere. **Canary** `pkg-verify-skip-canary`: with the signature
/// check off the forgery is installed, and this test goes red.
#[test]
fn a_forged_package_fetched_over_tftp_is_refused() {
    let mut bytes = package(&author());
    // One bit of the signature (it follows the 32-byte key).
    bytes[azos_pkg::container::HEADER_LEN + 32 + 5] ^= 0x01;
    let server = Server::serve(FILE, bytes, None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch();
    server.thread.join().unwrap();
    assert_ne!(reply[0], 0, "a forged package must not install");
    assert_ne!(step_of(reply[0]), step::FETCH as usize, "it arrived whole; the installer refused it");
    assert!(r.vol.borrow().staged().is_empty(), "nothing is staged");
    let j = r.vol.borrow().journal();
    assert_eq!(j.len(), 1, "a refusal is journalled");
    assert_eq!(j[0].verdict, Verdict::Refuse as u8);
}

/// A package signed by a key the device does not admit is refused the same way.
#[test]
fn a_package_signed_by_a_stranger_is_refused_over_tftp() {
    let server = Server::serve(FILE, package(&stranger()), None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch();
    server.thread.join().unwrap();
    assert_ne!(reply[0], 0);
    assert!(r.vol.borrow().staged().is_empty());
    assert_eq!(r.vol.borrow().journal()[0].verdict, Verdict::Refuse as u8);
}

/// UDP drops datagrams. A DATA block lost on the way is asked for again (the
/// client sends its last ACK once more after a second of silence), and the
/// package that arrives is whole.
#[test]
fn a_lost_block_is_asked_for_again() {
    let bytes = package(&author());
    let server = Server::serve(FILE, bytes.clone(), Some(3));
    let mut r = rig_with(&server.rows(FILE));
    let t = std::time::Instant::now();
    let reply = r.service_with(TftpRemote::new()).fetch();
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert!(t.elapsed() >= Duration::from_secs(1), "it waited for the silence before asking");
    server.thread.join().unwrap();
    let staged = r.vol.borrow().staged();
    assert_eq!(r.vol.borrow().files[staged[0].as_bytes()], bytes);
}

/// A server that has not got the file says so; that is a status and records
/// nothing, like any fetch that brings no package.
#[test]
fn a_missing_file_is_a_fetch_status() {
    let server = Server::serve(FILE, vec![1; 100], None);
    let mut r = rig_with(&server.rows("other.pkg"));
    let reply = r.service_with(TftpRemote::new()).fetch();
    server.thread.join().unwrap();
    assert_eq!(reply, [status(step::FETCH, FetchErr::Status.code()), 0, 0, 0]);
    assert!(r.vol.borrow().journal().is_empty());
    assert!(r.vol.borrow().staged().is_empty());
}

/// A server that never answers ends the fetch (the deadline), as a status.
#[test]
fn a_silent_server_is_a_fetch_status() {
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let SocketAddr::V4(addr) = silent.local_addr().unwrap() else { unreachable!() };
    let mut r = rig_with(format!("tftp={addr}\nfile={FILE}\n").as_bytes());
    let t = std::time::Instant::now();
    let reply = r.service_with(TftpRemote { total: Duration::from_millis(600) }).fetch();
    assert_eq!(reply, [status(step::FETCH, FetchErr::Connect.code()), 0, 0, 0]);
    assert!(t.elapsed() < Duration::from_secs(10), "bounded by the deadline");
    assert!(r.vol.borrow().journal().is_empty());
}

/// A file larger than the installer's package buffer is the refusal a client's
/// too-large package gets, not a truncated install.
#[test]
fn a_file_larger_than_the_buffer_is_too_large() {
    let server = Server::serve(FILE, vec![7; 3 * BLOCK + 1], None);
    let mut small = [0u8; 2 * BLOCK];
    let got = TftpRemote::new().get(&server.rows(FILE), &mut small);
    assert_eq!(got, Err(FetchErr::TooLarge));
    // The client told the server it was ending the transfer; the server's
    // thread ends on that or on its own timeout.
    server.thread.join().unwrap();
}

/// The development source exists only where the build says so. With it off (a
/// release build) a `tftp=` row goes to the HTTPS source, which does not know
/// it, and no datagram leaves; with it on, TFTP takes it and HTTPS is not asked.
#[test]
fn only_a_development_build_takes_a_tftp_source() {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    probe.set_nonblocking(true).unwrap();
    let SocketAddr::V4(addr) = probe.local_addr().unwrap() else { unreachable!() };
    let rows = format!("tftp={addr}\nfile={FILE}\n").into_bytes();
    let mut buf = [0u8; 1024];

    let mut release = Sources::<_, false>::new(Fake::new(Err(FetchErr::Rows)));
    assert_eq!(release.get(&rows, &mut buf), Err(FetchErr::Rows));
    assert_eq!(release.https.calls, 1, "the HTTPS source was handed the rows, and refused them");
    assert!(probe.recv_from(&mut buf).is_err(), "no request left the installer");

    let mut dev = Sources::<_, true>::new(Fake::new(Err(FetchErr::Io)));
    dev.tftp = TftpRemote { total: Duration::from_millis(300) };
    assert_eq!(dev.get(&rows, &mut buf), Err(FetchErr::Connect));
    assert_eq!(dev.https.calls, 0, "TFTP took it");
    assert!(probe.recv_from(&mut buf).is_ok(), "the request reached the server");
    // HTTPS rows are still HTTPS in a development build.
    let https = b"host=h\naddr=203.0.113.7:443\npath=/a\npin_1=00\n";
    assert_eq!(dev.get(https, &mut buf), Err(FetchErr::Io));
    assert_eq!(dev.https.calls, 1);
}

// ── A whole-system update bundle over TFTP ──────────────────────────────────
//
// `pkg fetch-update`: the same sources, the same installer, a bundle instead of
// a package. The bundle is staged into the inactive slot as `pkg update FILE`
// stages one a client hands over, and what decides is the signed manifest and
// the hash of every part, never the wire.

/// A signed bundle whose length is not a multiple of a block (the transfer's
/// last block is the short one).
fn bundle_file(epoch: u32) -> Vec<u8> {
    (epoch..epoch + 8).map(super::update::good).find(|b| b.len() % BLOCK != 0).expect("a bundle with a short last block")
}

const MARKER_B: &[u8] = b"/fat/PKG/SYS_B/UPDATE.MAN";

/// The honest flow: fetched over TFTP, the manifest verified against the
/// trusted key, every part hashed as it is copied, staged into the inactive
/// slot and journalled -- what `update` does for a client's bundle.
#[test]
fn a_bundle_fetched_over_tftp_is_staged() {
    let bytes = bundle_file(5);
    assert!(bytes.len() > 8 * BLOCK, "several blocks, so the lock-step is exercised");
    let server = Server::serve(FILE, bytes, None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch_update();
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    server.thread.join().unwrap();
    assert_eq!(reply[3], 1, "into slot B (the device runs from A)");
    let v = r.vol.borrow();
    let epoch = reply[2] as u32;
    for (_, name, part) in &super::update::parts(epoch, 3, &owner()) {
        assert_eq!(v.files.get(format!("/fat/PKG/SYS_B/{name}").as_bytes()), Some(part), "{name}");
    }
    assert!(v.files.contains_key(MARKER_B), "the set is complete: its marker is written last");
    assert!(!v.files.keys().any(|k| k.starts_with(b"/fat/PKG/SYS_A")), "the running slot's set is not touched");
    let j = v.journal();
    assert_eq!(j.len(), 1);
    assert_eq!((j[0].rule, j[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
    assert_eq!(j[0].image_hash_prefix, reply[1], "the record names the manifest");
}

/// **The gate is the manifest's signature, not the wire.** One bit of the
/// signature changed on the server: the bundle arrives whole and is refused,
/// journalled, and nothing is written to the slot. **Canary**
/// `update-canary-sig`: with the signature check off the forgery is staged.
#[test]
fn a_forged_bundle_fetched_over_tftp_is_refused() {
    let mut bytes = bundle_file(5);
    let sig_at = 24 + 7 * 52;
    bytes[sig_at + 3] ^= 0x01;
    let server = Server::serve(FILE, bytes, None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch_update();
    server.thread.join().unwrap();
    assert_ne!(reply[0], 0, "a forged bundle must not stage");
    assert_eq!(step_name(reply[0]), "update signature");
    let v = r.vol.borrow();
    assert!(!v.files.keys().any(|k| k.starts_with(b"/fat/PKG/SYS_")), "nothing is written before the manifest verifies");
    let j = v.journal();
    assert_eq!(j.len(), 1, "a refusal is journalled");
    assert_eq!(j[0].verdict, Verdict::Refuse as u8);
}

/// A part changed after the manifest was signed (the manifest is genuine, the
/// kernel is not): refused at that part, and the slot holds no set -- the
/// marker, which makes a directory of files a set, is never written.
/// **Canary** `update-canary-hash`: with the hash check off the tampered
/// kernel is staged.
#[test]
fn a_bundle_with_a_tampered_part_fetched_over_tftp_is_refused() {
    let mut bytes = bundle_file(5);
    // Past the manifest (24 + 7 parts of 52 + the 64-byte signature): the
    // kernel's bytes.
    let kernel_at = 24 + 7 * 52 + 64;
    bytes[kernel_at + 100] ^= 0x80;
    let server = Server::serve(FILE, bytes, None);
    let mut r = rig_with(&server.rows(FILE));
    let reply = r.service_with(TftpRemote::new()).fetch_update();
    server.thread.join().unwrap();
    assert_ne!(reply[0], 0, "a bundle with a tampered kernel must not stage");
    assert_eq!(step_name(reply[0]), "update part hash");
    let v = r.vol.borrow();
    assert!(!v.files.contains_key(MARKER_B), "no marker: the slot holds no set");
    let j = v.journal();
    assert_eq!(j.len(), 1);
    assert_eq!(j[0].verdict, Verdict::Refuse as u8);
}

/// A bundle that does not arrive is a status and records nothing; one larger
/// than the package buffer is the refusal a client's too-long bundle gets.
#[test]
fn a_bundle_that_does_not_arrive_is_a_fetch_status_and_a_large_one_is_a_length_refusal() {
    // No source rows.
    let mut r = Rig::new(MemVol::device(&dev(), &owner()));
    let reply = r.service_with(Fake::new(Ok(Vec::new()))).fetch_update();
    assert_eq!(reply, [status(step::FETCH, FetchErr::NoSource.code()), 0, 0, 0]);
    assert!(r.vol.borrow().journal().is_empty());

    // The source breaks.
    let mut r = rig_with(b"tftp=10.0.2.2\nfile=x\n");
    let reply = r.service_with(Fake::new(Err(FetchErr::Connect))).fetch_update();
    assert_eq!(reply, [status(step::FETCH, FetchErr::Connect.code()), 0, 0, 0]);
    assert!(r.vol.borrow().journal().is_empty());

    // Larger than the buffer.
    let mut r = rig_with(b"tftp=10.0.2.2\nfile=x\n");
    let reply = r.service_with(Fake::new(Err(FetchErr::TooLarge))).fetch_update();
    assert_eq!(step_name(reply[0]), "update length");
    let j = r.vol.borrow().journal();
    assert_eq!((j.len(), j[0].verdict), (1, Verdict::Refuse as u8));
    assert!(!r.vol.borrow().files.keys().any(|k| k.starts_with(b"/fat/PKG/SYS_")));
}

/// `pkg fetch-update` through the generated stubs and the installer: prints
/// where the bundle was staged, and a refusal as `update` prints it.
#[test]
fn pkg_fetch_update_says_where_it_staged() {
    use azos_idl::{MsgDesc, Transport};
    use azos_packages::{cli, PackagesClient, PackagesIdl, Service, Work};
    use azos_topology::Topology;
    use std::cell::RefCell;

    struct Loop<'a, 'w>(&'a RefCell<Service<'w, crate::service::Shared<'a>, Fake>>);
    impl Transport for Loop<'_, '_> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let req = *msg;
            let mut rep = MsgDesc::default();
            PackagesIdl::dispatch(&mut *self.0.borrow_mut(), &req, &mut rep)?;
            *msg = rep;
            Ok(())
        }
    }
    struct NoFiles;
    impl cli::Opener for NoFiles {
        fn open(&mut self, _: &[u8]) -> Option<(azos_idl::Cap<azos_packages::PkgMem>, u32)> {
            None
        }
    }

    assert_eq!(cli::parse(&[b"fetch-update".as_slice()]), Ok(cli::Cmd::FetchUpdate));
    assert!(cli::parse(&[b"fetch-update".as_slice(), b"x"]).is_err());

    let vol = RefCell::new(MemVol::device(&dev(), &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), b"tftp=10.0.2.2\nfile=sys.azu\n".to_vec());
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let ok = Fake::new(Ok(super::update::good(9)));
    let svc = RefCell::new(Service::new(crate::service::Shared(&vol), ok, &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut out = String::new();
    assert_eq!(cli::run(&cli::Cmd::FetchUpdate, &mut c, &mut NoFiles, &mut out), Ok(0), "{out}");
    assert!(out.starts_with("staged: update ") && out.contains("epoch 9, into slot B"), "{out}");

    let mut forged = super::update::good(9);
    forged[24 + 7 * 52 + 3] ^= 1;
    let vol = RefCell::new(MemVol::device(&dev(), &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), b"tftp=10.0.2.2\nfile=sys.azu\n".to_vec());
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let svc = RefCell::new(Service::new(crate::service::Shared(&vol), Fake::new(Ok(forged)), &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut out = String::new();
    assert_eq!(cli::run(&cli::Cmd::FetchUpdate, &mut c, &mut NoFiles, &mut out), Ok(1), "{out}");
    assert!(out.starts_with("refused: update signature"), "{out}");
}
