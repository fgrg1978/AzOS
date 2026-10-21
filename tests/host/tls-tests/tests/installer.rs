// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer's `fetch` (`Packages::fetch`, what `pkg fetch` asks of `pkgd`)
//! over the HTTPS source (`azos_tls::remote::HttpsRemote`) against a pinned
//! server on loopback: the code path `pkgd` runs, with a volume that keeps its
//! files in memory. A package that arrives through the connection is judged by
//! the installer exactly as one a client hands over (here the volume holds no
//! signed topology, so the installer refuses it with its own step); a
//! connection that fails is a `step::FETCH` status and records nothing.

mod common;

use std::collections::BTreeMap;

use azos_packages::update::{IoErr, Source, Store, NAME_BUF};
use azos_packages::{status, step, step_name, step_of, Cap, FetchErr, Packages, PkgMem, Read, Service, VolErr, Volume, Work};
use azos_pkg::{Device, HwClass};
use azos_topology::Topology;
use azos_tls::remote::HttpsRemote;
use common::*;

/// The files of the volume the installer reads its source rows from and
/// writes its journal to; everything a fetch does not touch is out of reach.
#[derive(Default)]
struct Mem {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Store for Mem {
    fn open_read(&mut self, _: &[u8]) -> Result<u32, IoErr> {
        unreachable!("a fetch reads no stream")
    }
    fn read(&mut self, _: u32, _: &mut [u8]) -> Result<usize, IoErr> {
        unreachable!()
    }
    fn open_write(&mut self, _: &[u8]) -> Result<u32, IoErr> {
        unreachable!()
    }
    fn write(&mut self, _: u32, _: &[u8]) -> Result<(), IoErr> {
        unreachable!()
    }
    fn close(&mut self, _: u32) -> Result<(), IoErr> {
        unreachable!()
    }
    fn remove(&mut self, _: &[u8]) -> Result<(), IoErr> {
        unreachable!()
    }
    fn ensure_dir(&mut self, _: &[u8]) -> Result<(), IoErr> {
        unreachable!()
    }
    fn entry(&mut self, _: &[u8], _: usize, _: &mut [u8; NAME_BUF]) -> Option<usize> {
        unreachable!()
    }
}

struct NoBundle;

impl Source for NoBundle {
    fn len(&self) -> u64 {
        0
    }
    fn read(&mut self, _: u64, _: &mut [u8]) -> Result<usize, IoErr> {
        Err(IoErr::Io)
    }
}

impl Volume for Mem {
    type Bundle = NoBundle;
    type Reader = Mem;
    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr> {
        let f = self.files.get(path).ok_or(VolErr::Missing)?;
        let n = f.len().min(buf.len());
        buf[..n].copy_from_slice(&f[..n]);
        Ok(Read { n, more: f.len() > buf.len() })
    }
    fn read_package(&mut self, _: Cap<PkgMem>, _: usize, _: &mut [u8]) -> Result<usize, VolErr> {
        unreachable!("a fetch has no client object")
    }
    fn open_bundle(&mut self, _: Cap<PkgMem>, _: usize) -> Result<NoBundle, VolErr> {
        unreachable!()
    }
    fn reader(&mut self) -> Mem {
        Mem::default()
    }
    fn boot_slots(&mut self) -> Option<(u8, u8)> {
        None
    }
    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        self.files.insert(path.to_vec(), data.to_vec());
        Ok(())
    }
    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        self.files.entry(path.to_vec()).or_default().extend_from_slice(data);
        Ok(())
    }
    fn dir_exists(&mut self, _: &[u8]) -> bool {
        true
    }
    fn now_ns(&mut self) -> u64 {
        1_000
    }
}

/// The installer over `vol`, fetching through TLS with the clock at `NOW`; its
/// reply and the volume it left. The signers' key is a stand-in: no package
/// here gets as far as being checked against it.
fn fetch(vol: Mem) -> ([u64; 4], Mem) {
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let dev = Device { hwclass: HwClass::Sbc, abi: azos_abi::ABI_VERSION, epoch_floor: 0, api: &[] };
    let mut svc = Service::new(vol, HttpsRemote::new(at(NOW)), &mut work, &mut topo, [7; 32], dev);
    let reply = svc.fetch();
    (reply, svc.vol)
}

fn volume_with(rows: &str) -> Mem {
    let mut vol = Mem::default();
    vol.files.insert(azos_packages::service::SOURCE.to_vec(), rows.as_bytes().to_vec());
    vol
}

/// The bytes come through the pinned connection into the installer's own
/// pipeline: what is refused is the package, not the fetch.
#[test]
fn a_fetched_package_is_judged_by_the_installer() {
    let (addr, server) = serve(GOOD, GOOD_KEY, at(NOW), Reply::Ok(body(2000)));
    let (reply, _) = fetch(volume_with(&rows(addr, NAME, &[GOOD_PIN])));
    assert!(server.join().unwrap().unwrap().starts_with("GET /azos/acme.pkg HTTP/1.0\r\n"), "the server was asked for the path of the rows");
    assert_ne!(reply[0], 0);
    assert_ne!(step_of(reply[0]), step::FETCH as usize, "the package arrived: {}", step_name(reply[0]));
    // The volume holds no signed topology to admit against: the installer's own refusal, after the transport.
    assert_eq!(step_of(reply[0]), step::NO_TOPOLOGY as usize, "{}", step_name(reply[0]));
}

/// A server whose key is not pinned gives the installer nothing, and nothing
/// is recorded: not a package, not a journal line.
#[test]
fn a_server_that_is_not_pinned_is_a_fetch_status() {
    let (addr, server) = serve(OTHER, OTHER_KEY, at(NOW), Reply::Ok(body(2000)));
    let (reply, vol) = fetch(volume_with(&rows(addr, NAME, &[GOOD_PIN])));
    let _ = server.join().unwrap();
    assert_eq!(reply, [status(step::FETCH, FetchErr::Tls.code()), 0, 0, 0]);
    assert!(!vol.files.contains_key(azos_packages::service::JOURNAL));
}

/// Without rows there is no source and the network is not touched.
#[test]
fn without_source_rows_nothing_is_dialled() {
    let (reply, vol) = fetch(Mem::default());
    assert_eq!(reply, [status(step::FETCH, FetchErr::NoSource.code()), 0, 0, 0]);
    assert!(vol.files.is_empty());
}
