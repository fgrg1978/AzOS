// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The standard streams: fds 0..2 of the startup block, which are the console
//! or handles the spawner passed. A closed stream reads as the end of input and
//! swallows output, as an unconnected one does elsewhere.

use crate::io;
use crate::sys::map_native_error;
use azos_stdrt::console::{self, E_BADF};

pub const STDIN_BUF_SIZE: usize = crate::sys::io::DEFAULT_BUF_SIZE;

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

impl Stdin {
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl Stdout {
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl Stderr {
    pub const fn new() -> Stderr {
        Stderr
    }
}

fn write_fd(fd: u64, buf: &[u8]) -> io::Result<usize> {
    match console::write(fd, buf) {
        n if n >= 0 => Ok(n as usize),
        E_BADF => Ok(buf.len()),
        e => Err(map_native_error(e)),
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match console::read(0, buf) {
            n if n >= 0 => Ok(n as usize),
            E_BADF => Ok(0),
            e => Err(map_native_error(e)),
        }
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_fd(1, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_fd(2, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn is_ebadf(_err: &io::Error) -> bool {
    false
}

pub fn panic_output() -> Option<impl io::Write> {
    Some(Stderr::new())
}
