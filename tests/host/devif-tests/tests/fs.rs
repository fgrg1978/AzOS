// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The file protocol (`azos_devif::fs`) through its generated client and
//! dispatcher: the read contract a client holds a server to, and the one
//! mapping between its codes and the kernel's errnos.

use azos_abi::error::Errno;
use azos_devif::fs::{
    read_checked, Extent, Node, NodeClient, NodeIdl, ReadDone, ERRNO_CODES, READ_MAX, SHORT_READ, code_of, errno_of,
};
use azos_devif::{outcome, Out};
use azos_idl::{MsgDesc, Result as IdlResult, Transport};
use std::cell::RefCell;
use std::collections::BTreeSet;

/// What a server answers for a read.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// As the contract says.
    Honest,
    /// Half of what it moved, as success, without the end of the file.
    Short,
    /// One byte more than asked.
    Long,
}

/// A file of `size` bytes served from ring 3 (the bytes themselves would be
/// in the shared region; the contract is about the counts).
struct File {
    size: u32,
    pos: u32,
    answer: Answer,
}

impl Node for File {
    fn read(&mut self, buf: Extent) -> Out<ReadDone> {
        let n = buf.len.min(READ_MAX).min(self.size - self.pos);
        self.pos += n;
        let end = self.pos == self.size;
        match self.answer {
            Answer::Honest => Out::ok(ReadDone { count: n, end }),
            Answer::Short => Out::ok(ReadDone { count: n / 2, end: false }),
            Answer::Long => Out::ok(ReadDone { count: buf.len + 1, end }),
        }
    }
    fn write(&mut self, _buf: Extent) -> Out<u32> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn fsync(&mut self) -> Out<()> {
        Out::ok(())
    }
    fn seek(&mut self, _offset: i64, _whence: u32) -> Out<u64> {
        Out::err(outcome::UNSUPPORTED)
    }
}

/// The endpoint, as a loopback: the request goes through the generated
/// dispatcher of the server above.
struct Loop<'a>(&'a RefCell<File>);

impl Transport for Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        let _ = NodeIdl::dispatch(&mut *self.0.borrow_mut(), &req, msg);
        Ok(())
    }
}

fn client(file: &RefCell<File>) -> NodeClient<Loop<'_>> {
    NodeClient::new(Loop(file))
}

const BUF: Extent = Extent { off: 0, len: READ_MAX };

/// **A file read through the protocol in full**: whole reads, then the
/// short one that says the file ended, then nothing.
#[test]
fn an_honest_server_is_read_to_the_end() {
    let f = RefCell::new(File { size: 2 * READ_MAX + 100, pos: 0, answer: Answer::Honest });
    let mut c = client(&f);
    assert_eq!(read_checked(&mut c, BUF), Ok(READ_MAX));
    assert_eq!(read_checked(&mut c, BUF), Ok(READ_MAX));
    assert_eq!(read_checked(&mut c, BUF), Ok(100));
    assert_eq!(read_checked(&mut c, BUF), Ok(0));
    assert_eq!(read_checked(&mut c, Extent { off: 0, len: 10 }), Ok(0));
}

/// **A server that answers a short read as success is caught by the
/// client**: fewer bytes than asked without the end of the file is
/// `SHORT_READ`, not a count; so is more than asked.
///
/// **Canary.** Drop the `!d.end` term in `read_checked`: the short answer
/// is taken as a count (2048), and the client reads a truncated file as the
/// whole one.
#[test]
fn a_short_read_answered_as_success_is_refused() {
    let f = RefCell::new(File { size: 3 * READ_MAX, pos: 0, answer: Answer::Short });
    assert_eq!(read_checked(&mut client(&f), BUF), Err(SHORT_READ));
    let f = RefCell::new(File { size: 3 * READ_MAX, pos: 0, answer: Answer::Long });
    assert_eq!(read_checked(&mut client(&f), Extent { off: 0, len: 10 }), Err(SHORT_READ));
}

/// **The protocol's codes and the kernel's errnos are one mapping**: each
/// code and each errno once, and each way back to where it started.
#[test]
fn the_codes_and_the_errnos_map_one_to_one() {
    let codes: BTreeSet<u32> = ERRNO_CODES.iter().map(|r| r.0).collect();
    let errnos: BTreeSet<i64> = ERRNO_CODES.iter().map(|r| r.1.to_syscall_ret()).collect();
    assert_eq!(codes.len(), ERRNO_CODES.len());
    assert_eq!(errnos.len(), ERRNO_CODES.len());
    for (c, e) in ERRNO_CODES {
        assert_ne!(c, outcome::OK);
        assert_eq!(code_of(e), c);
        assert_eq!(errno_of(c), Some(e));
    }
    assert!(!codes.contains(&SHORT_READ) && !codes.contains(&outcome::NO_SERVER), "client-only codes never travel");
    assert_eq!(code_of(Errno::ECAPKIND), outcome::FAULT);
    assert_eq!(errno_of(SHORT_READ), None);
}
