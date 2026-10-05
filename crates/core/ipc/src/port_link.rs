// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The link a source object keeps to the event port it is bound to.
//!
//! A channel or an io_ring bound to a port (`SYS_PORT_BIND_TYPED`, source
//! types 0 and 1) stores one [`PortLink`] in its own pool entry, read in the
//! hold its producer path already takes. After that hold is released the
//! producer hands the link to `port::port_signal`, which compares all three
//! fields inside the `PORTS` hold that marks the source pending: a link to a
//! destroyed port, to another incarnation of its index, or to a slot that no
//! longer holds this object signals nothing.
//!
//! A leaf module with no dependencies, so the host suites that pull
//! `channel.rs` without `port.rs` (`tests/host/ipc-chan-tests`,
//! `tests/host/topology-tests`) need only a stand-in for `port_signal`.

/// Where a source object's events go: a port's packed `(index, generation)`
/// reference, the epoch of that port's slot (`port::Port::epoch`) and the
/// source-table slot the object occupies in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortLink {
    /// The port's packed reference; 0 (generation 0 names no port) for none.
    pub port: u32,
    /// The port slot's wrap epoch at bind time.
    pub epoch: u32,
    /// The index in the port's source table.
    pub slot: u8,
}

impl PortLink {
    /// No port: the object signals nothing.
    pub const NONE: PortLink = PortLink { port: 0, epoch: 0, slot: 0 };

    /// Is this the empty link?
    #[inline(always)]
    pub const fn is_none(&self) -> bool {
        self.port == 0
    }
}

/// What a source object answered to a request to store a link.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkSet {
    /// Stored. `ready`: the object already had something to report (a
    /// message queued, a completion unread) when the link was stored, under
    /// the same hold, so the binder signals once itself.
    Stored { ready: bool },
    /// The object is linked to another port, through this link. The binder
    /// asks the port whether it is still live (`port::port_link_valid`) and
    /// retries with it as `replace` if it is not.
    Busy(PortLink),
}
