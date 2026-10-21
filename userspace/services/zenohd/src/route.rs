// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the gateway serves: the interfaces it knows how to call, the exports
//! its configuration (Kconfig `ZENOH_DECISIONS_KEY`) names, and the rule that
//! turns a query's key expression into one op of one export.
//!
//! # From a key to an op
//!
//! An export maps an interface to a key expression, normally a prefix pattern
//! (`azos/dec/**`). A query names one op by its **last chunk**:
//! `azos/dec/get` is `Decisions::get` of the export whose key includes it. The
//! query key must be a concrete key (no `*`, `**`, `$*`): a wildcard query names
//! no op and is not served. Two exports whose keys both include a query key are
//! tried in the order of the list; the first with an op of that name serves it.
//! Nothing outside an export is reachable, whatever the query says.

use alloc::string::String;
use azos_idl::OpInfo;

/// An interface the gateway can call: its id and level (the request header
/// word) and its op table.
#[derive(Clone, Copy, Debug)]
pub struct Iface {
    pub id: u32,
    pub level: u16,
    pub ops: &'static [OpInfo],
}

impl Iface {
    /// The op called `name`.
    pub fn op(&self, name: &str) -> Option<&'static OpInfo> {
        self.ops.iter().find(|o| o.name == name)
    }
}

/// One export the gateway fronts.
#[derive(Clone, Debug)]
pub struct Export {
    pub iface: &'static Iface,
    /// The endpoint's pool index, what the host turns into a handle.
    pub endpoint: u32,
    /// The Zenoh key expression the export is served under.
    pub key: String,
}

/// The export of `iface` on the endpoint `endpoint` under `key`, or `None`
/// when `key` is not a key expression (an empty chunk, a wildcard misplaced).
pub fn export(iface: &'static Iface, endpoint: u32, key: &str) -> Option<Export> {
    azos_zenoh::keyexpr::is_valid(key).then(|| Export { iface, endpoint, key: String::from(key) })
}

/// Why a query names no op the gateway serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoRoute {
    /// The key has a wildcard, or is not a key expression.
    NotConcrete,
    /// No export's key includes it, or none of those has an op of that name.
    NoOp,
}

/// The export and the op a concrete query key names.
pub fn route<'a>(exports: &'a [Export], key: &str) -> Result<(&'a Export, &'static OpInfo), NoRoute> {
    if !azos_zenoh::keyexpr::is_valid(key) || key.bytes().any(|c| c == b'*' || c == b'$') {
        return Err(NoRoute::NotConcrete);
    }
    let op = key.rsplit('/').next().unwrap_or(key);
    exports
        .iter()
        .filter(|e| azos_zenoh::keyexpr::includes(&e.key, key))
        .find_map(|e| e.iface.op(op).map(|o| (e, o)))
        .ok_or(NoRoute::NoOp)
}

/// The one endpoint a row lends from. `held` is every endpoint the row holds as
/// (pool index, rights bits); `lend` the rights the gateway needs on the source
/// of its per-query warrants (the call right and the lend right). `Ok(index)`
/// when exactly one holds them all; `Err(n)` with the count otherwise: none
/// means no receipts, more than one means the gateway cannot tell the decisions
/// from an effect and refuses to guess.
pub fn sole_lendable(held: impl Iterator<Item = (u32, u16)>, lend: u16) -> Result<u32, usize> {
    let (mut found, mut n) = (0, 0);
    for (i, rights) in held {
        if rights & lend == lend {
            (found, n) = (i, n + 1);
        }
    }
    if n == 1 { Ok(found) } else { Err(n) }
}
