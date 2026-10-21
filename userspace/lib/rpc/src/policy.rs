// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the signed topology lets this node do over a link: the server's view of
//! it (the view region `inspect.rpc`, `peers/` and `exports/`,
//! `kernel/src/boot/inspect_views.rs`), and the catalog of
//! interfaces the server knows how to carry.
//!
//! A peer is a node of a `[peer.NAME]` class with the static Noise key the
//! topology pins for it (`noise_pk`): it is how the node is told from anyone
//! else. A node whose class pins no key is no peer, and has no session.
//!
//! **Nothing leaves the node except through an export**, and only to the
//! nodes of its class: the engine answers a request for an interface with no
//! export for the requester's class with `Refused`, whatever the peer asked.

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

/// One export: an endpoint this task holds, lent to a class.
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

/// The view, as read.
#[derive(Clone, Copy)]
pub struct Policy {
    peers: [(Name, NodeId, [u8; 32]); PEERS_MAX],
    n_peers: usize,
    exports: [Export; EXPORTS_MAX],
    n_exports: usize,
}

const NO_EXPORT: Export = Export { name: Name::EMPTY, index: 0, class: Name::EMPTY };

impl Policy {
    /// Nothing is allowed: no peer, no export.
    pub const NONE: Policy = Policy {
        peers: [(Name::EMPTY, 0, [0; 32]); PEERS_MAX],
        n_peers: 0,
        exports: [NO_EXPORT; EXPORTS_MAX],
        n_exports: 0,
    };

    /// Add `node`, of class `class`, pinned to `pk`. Refused (`false`, nothing
    /// added) for a class that is no name, node 0 (this node), an all-zero
    /// key, or a full table: a policy only ever has less in it than the
    /// topology said, never more.
    pub fn add_peer(&mut self, class: &[u8], node: NodeId, pk: &[u8; 32]) -> bool {
        let Some(c) = Name::new(class) else { return false };
        if node == 0 || *pk == [0; 32] || self.n_peers == PEERS_MAX {
            return false;
        }
        self.peers[self.n_peers] = (c, node, *pk);
        self.n_peers += 1;
        true
    }

    /// Add the export of the endpoint `name`, at pool index `index`, to
    /// `class`. Refused as [`Policy::add_peer`] is.
    pub fn add_export(&mut self, name: &[u8], index: u32, class: &[u8]) -> bool {
        let (Some(name), Some(class)) = (Name::new(name), Name::new(class)) else { return false };
        if self.n_exports == EXPORTS_MAX {
            return false;
        }
        self.exports[self.n_exports] = Export { name, index, class };
        self.n_exports += 1;
        true
    }

    /// The class `node` belongs to; `None` for a node the topology does not
    /// know.
    pub fn class_of(&self, node: NodeId) -> Option<Name> {
        self.peers[..self.n_peers].iter().find(|(_, n, _)| *n == node).map(|(c, _, _)| *c)
    }

    /// The static key the topology pins for `node`.
    pub fn noise_pk(&self, node: NodeId) -> Option<&[u8; 32]> {
        self.peers[..self.n_peers].iter().find(|(_, n, _)| *n == node).map(|(_, _, k)| k)
    }

    /// Every node of every class, in the order of the view.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.peers[..self.n_peers].iter().map(|(_, n, _)| *n)
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
