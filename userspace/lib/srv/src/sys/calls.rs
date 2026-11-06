// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A server with no source but its calls ([`crate::Server::calls_only`]): no
//! port, the accept is the wait.

use super::{accept_blocking, accept_poll, reply};
use azos_libsys as sys;
use crate::{Event, Kernel, MsgDesc};

/// The calls of the endpoints this task serves, and nothing else.
#[derive(Clone, Copy, Default)]
pub struct Calls;

impl Kernel for Calls {
    /// No port: a calls-only server never waits on one.
    fn wait(&mut self, _deadline_ns: u64) -> Result<Option<Event>, isize> {
        Ok(None)
    }

    fn accept(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        accept_poll(req)
    }

    fn accept_blocking(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        accept_blocking(req)
    }

    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize {
        reply(handle, rep)
    }

    /// The accept came back with nothing (its wakes ran out): let the
    /// others run, then sleep in it again.
    fn pause(&mut self) {
        sys::yield_now();
    }
}
