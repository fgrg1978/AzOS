// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Consumer lookup by phandle, once for every framework.
//!
//! A consumer names its resources in properties of its own node. Two shapes:
//!
//! - **phandle with arguments** (`clocks`, `resets`, `power-domains`): a list
//!   of `<&provider arg...>` entries; the number of argument cells is the
//!   *provider's* `#clock-cells` / `#reset-cells` / `#power-domain-cells`, so
//!   the list can only be split by reading each provider. A parallel `*-names`
//!   property gives each entry a name.
//! - **a single phandle** (`vdd-supply`) or **a list of phandles**
//!   (`pinctrl-0`).
//!
//! The functions here return the provider NODE and the argument bytes; the
//! managers map the node to the provider they registered.

use crate::fdt::{cell, strings, Fdt, NodeId};
use crate::{Error, Result};

/// How a consumer picks one entry of a list.
#[derive(Clone, Copy, Debug)]
pub enum Sel<'n> {
    Index(usize),
    Name(&'n str),
}

/// One resolved entry of a phandle-with-arguments list.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    pub provider: NodeId,
    /// The provider's argument cells, big-endian as stored.
    pub spec: &'a [u8],
}

impl Entry<'_> {
    /// The one number an id-style specifier carries: no argument cell is 0,
    /// one is that cell, more is a provider this crate has no decoding for.
    pub fn id(&self) -> Result<u32> {
        match self.spec.len() {
            0 => Ok(0),
            4 => cell(self.spec, 0).ok_or(Error::BadSpec),
            _ => Err(Error::BadSpec),
        }
    }
}

/// Entry `index` of the list `prop` of `node`, its argument cells counted by
/// each provider's `cells_prop`. A `<0>` placeholder (a legal "no resource
/// here" entry that keeps its index) is `Ok(None)`; an index past the end of
/// the list is `NotFound`, like a phandle that is not in the tree; a provider
/// that has no `cells_prop` is `BadSpec`.
pub fn slot<'a>(fdt: &Fdt<'a>, node: NodeId, prop: &str, cells_prop: &str, index: usize) -> Result<Option<Entry<'a>>> {
    let list = fdt.prop(node, prop).ok_or(Error::NotFound)?;
    let mut at = 0usize; // in cells
    let mut i = 0usize;
    loop {
        let ph = cell(list, at).ok_or(Error::NotFound)?;
        if ph == 0 {
            // A placeholder is one cell and keeps its index.
            if i == index {
                return Ok(None);
            }
            at += 1;
            i += 1;
            continue;
        }
        let provider = fdt.by_phandle(ph).ok_or(Error::NotFound)?;
        let n = fdt.u32_prop(provider, cells_prop).ok_or(Error::BadSpec)? as usize;
        if i == index {
            let bytes = list.get((at + 1) * 4..(at + 1 + n) * 4).ok_or(Error::BadSpec)?;
            return Ok(Some(Entry { provider, spec: bytes }));
        }
        at += 1 + n;
        i += 1;
    }
}

/// [`slot`] for a caller that needs the resource: a placeholder is `NotFound`.
pub fn entry<'a>(fdt: &Fdt<'a>, node: NodeId, prop: &str, cells_prop: &str, index: usize) -> Result<Entry<'a>> {
    slot(fdt, node, prop, cells_prop, index)?.ok_or(Error::NotFound)
}

/// How many entries the list `prop` of `node` has, placeholders included; a
/// node without the property has none.
pub fn count(fdt: &Fdt<'_>, node: NodeId, prop: &str, cells_prop: &str) -> Result<usize> {
    let Some(list) = fdt.prop(node, prop) else { return Ok(0) };
    let (mut at, mut n) = (0usize, 0usize);
    while let Some(ph) = cell(list, at) {
        at += 1;
        if ph != 0 {
            let provider = fdt.by_phandle(ph).ok_or(Error::NotFound)?;
            at += fdt.u32_prop(provider, cells_prop).ok_or(Error::BadSpec)? as usize;
            if at * 4 > list.len() {
                return Err(Error::BadSpec);
            }
        }
        n += 1;
    }
    Ok(n)
}

/// The index of `name` in the `names_prop` list of `node`.
pub fn index_of(fdt: &Fdt<'_>, node: NodeId, names_prop: &str, name: &str) -> Result<usize> {
    let v = fdt.prop(node, names_prop).ok_or(Error::NotFound)?;
    strings(v).position(|s| s == name).ok_or(Error::NotFound)
}

/// [`entry`] selected by index or by name.
pub fn lookup<'a>(
    fdt: &Fdt<'a>,
    node: NodeId,
    prop: &str,
    names_prop: &str,
    cells_prop: &str,
    sel: Sel<'_>,
) -> Result<Entry<'a>> {
    let index = match sel {
        Sel::Index(i) => i,
        Sel::Name(n) => index_of(fdt, node, names_prop, n)?,
    };
    entry(fdt, node, prop, cells_prop, index)
}

/// The node a single-phandle property names (`vdd-supply`).
pub fn phandle(fdt: &Fdt<'_>, node: NodeId, prop: &str) -> Result<NodeId> {
    let v = fdt.prop(node, prop).ok_or(Error::NotFound)?;
    if v.len() != 4 {
        return Err(Error::BadSpec);
    }
    fdt.by_phandle(cell(v, 0).ok_or(Error::BadSpec)?).ok_or(Error::NotFound)
}

/// The nodes a phandle-list property names (`pinctrl-0`); an entry whose
/// phandle is not in the tree ends the walk with `NotFound`.
pub fn phandles<'a>(fdt: &'a Fdt<'a>, node: NodeId, prop: &str) -> impl Iterator<Item = Result<NodeId>> + 'a {
    let v = fdt.prop(node, prop).unwrap_or(&[]);
    (0..v.len() / 4).map(move |i| {
        let ph = cell(v, i).ok_or(Error::BadSpec)?;
        fdt.by_phandle(ph).ok_or(Error::NotFound)
    })
}
