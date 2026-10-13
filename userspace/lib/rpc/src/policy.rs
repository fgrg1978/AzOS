// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the signed topology lets this node do over a link: the server's view of
//! `/proc/rpc` (kernel/src/boot/procfs.rs), and the catalog of interfaces the
//! server knows how to carry.
//!
//! ```text
//! peer <class> <node>
//! export <name> <endpoint pool index> <class>
//! ```
//!
//! **Nothing leaves the node except through an `export` line**, and only to the
//! nodes of its class: the engine answers a request for an interface with no
//! line for the requester's class with `Refused`, whatever the peer asked.

use azos_idl::OpInfo;

use crate::NodeId;

/// The longest class or endpoint name (`ENDPOINT_NAME_MAX`).
pub const NAME_MAX: usize = 24;
/// Nodes the view may list.
pub const PEERS_MAX: usize = 16;
/// Exports the view may list.
pub const EXPORTS_MAX: usize = 16;

/// A short name, copied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Name {
    len: u8,
    b: [u8; NAME_MAX],
}

impl Name {
    /// The empty name.
    pub const EMPTY: Name = Name { len: 0, b: [0; NAME_MAX] };

    /// `s` as a name; `None` if empty or over [`NAME_MAX`].
    pub fn new(s: &[u8]) -> Option<Name> {
        if s.is_empty() || s.len() > NAME_MAX {
            return None;
        }
        let mut b = [0; NAME_MAX];
        b[..s.len()].copy_from_slice(s);
        Some(Name { len: s.len() as u8, b })
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.len as usize]
    }
}

/// One `export` line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Export {
    /// The endpoint's name.
    pub name: Name,
    /// Its pool index, what `SYS_CAP_INFO(Endpoint, index)` turns into the
    /// handle this task holds.
    pub index: u32,
    /// The class that may ask for it.
    pub class: Name,
}

/// The view, parsed.
#[derive(Clone, Copy)]
pub struct Policy {
    peers: [(Name, NodeId); PEERS_MAX],
    n_peers: usize,
    exports: [Export; EXPORTS_MAX],
    n_exports: usize,
}

const NO_EXPORT: Export = Export { name: Name::EMPTY, index: 0, class: Name::EMPTY };

fn num(t: &[u8]) -> Option<u32> {
    if t.is_empty() || t.len() > 10 {
        return None;
    }
    t.iter().try_fold(0u32, |a, &c| {
        if c.is_ascii_digit() { a.checked_mul(10)?.checked_add((c - b'0') as u32) } else { None }
    })
}

impl Policy {
    /// Nothing is allowed: no peer, no export.
    pub const NONE: Policy = Policy {
        peers: [(Name::EMPTY, 0); PEERS_MAX],
        n_peers: 0,
        exports: [NO_EXPORT; EXPORTS_MAX],
        n_exports: 0,
    };

    /// Parse the view. A line that is not one (a blank line, a malformed line,
    /// one past the tables) is skipped: a policy only ever has less in it than
    /// the text said, never more.
    pub fn parse(view: &[u8]) -> Policy {
        let mut p = Policy::NONE;
        for line in view.split(|&c| c == b'\n') {
            let mut t = line.split(|&c| c == b' ').filter(|s| !s.is_empty());
            match t.next() {
                Some(b"peer") => {
                    let (Some(c), Some(n), None) = (t.next(), t.next(), t.next()) else { continue };
                    let (Some(c), Some(n)) = (Name::new(c), num(n)) else { continue };
                    if n != 0 && p.n_peers < PEERS_MAX {
                        p.peers[p.n_peers] = (c, n);
                        p.n_peers += 1;
                    }
                }
                Some(b"export") => {
                    let (Some(name), Some(i), Some(c), None) = (t.next(), t.next(), t.next(), t.next()) else { continue };
                    let (Some(name), Some(index), Some(class)) = (Name::new(name), num(i), Name::new(c)) else { continue };
                    if p.n_exports < EXPORTS_MAX {
                        p.exports[p.n_exports] = Export { name, index, class };
                        p.n_exports += 1;
                    }
                }
                _ => {}
            }
        }
        p
    }

    /// The class `node` belongs to; `None` for a node the topology does not
    /// know.
    pub fn class_of(&self, node: NodeId) -> Option<Name> {
        self.peers[..self.n_peers].iter().find(|(_, n)| *n == node).map(|(c, _)| *c)
    }

    /// Every node of every class, in the order of the view.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.peers[..self.n_peers].iter().map(|(_, n)| *n)
    }

    /// The export of `name` to `class`.
    pub fn export(&self, name: &[u8], class: &Name) -> Option<&Export> {
        self.exports[..self.n_exports].iter().find(|e| e.name.as_bytes() == name && e.class == *class)
    }
}

/// An interface the server can carry: the endpoint it is served on, its id and
/// its op table (`<Name>Idl::OPS`, where each op declares how it is delivered).
#[derive(Clone, Copy)]
pub struct Service {
    /// The endpoint's name (`endpoint.<name>`).
    pub name: &'static [u8],
    /// The interface id (`<Name>Idl::ID`).
    pub id: u32,
    /// The op table.
    pub ops: &'static [OpInfo],
}

impl Service {
    /// The op `op`; `None` for one the interface does not have.
    pub fn op(&self, op: u16) -> Option<&'static OpInfo> {
        self.ops.iter().find(|o| o.op == op)
    }
}

/// The interfaces a server carries, by id.
pub fn find(catalog: &'static [Service], id: u32) -> Option<&'static Service> {
    catalog.iter().find(|s| s.id == id)
}
