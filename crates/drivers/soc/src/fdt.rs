// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A safe, read-only view of a flattened device tree, as far as the SoC
//! frameworks need it: nodes by phandle and path, properties, children,
//! parents, the first `reg` window. Every offset is bounds-checked; a damaged
//! blob answers `None`, it never panics.
//!
//! This is a lookup structure for boot-time probing (each call scans the
//! structure block), not a walker for hot paths. `azos_dtb` keeps the
//! pointer-based walkers the boot path uses.

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;

/// Deepest node nesting the parent and `reg` lookups follow.
pub const MAX_DEPTH: usize = 16;

/// Deepest node nesting [`Fdt::walk`] visits.
pub const WALK_DEPTH: usize = 8;

/// A node: the offset of its `FDT_BEGIN_NODE` token in the structure block.
/// `azos_hwbus::Device::dt_node` carries the same number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeId(pub u32);

/// The ancestors of a node, root first (the node itself is not in it).
#[derive(Clone, Copy, Debug)]
pub struct Ancestors {
    ids: [NodeId; MAX_DEPTH],
    len: usize,
}

impl Ancestors {
    pub fn as_slice(&self) -> &[NodeId] {
        &self.ids[..self.len]
    }
    /// The parent, `None` for the root.
    pub fn parent(&self) -> Option<NodeId> {
        self.as_slice().last().copied()
    }
}

#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    st: &'a [u8],
    strs: &'a [u8],
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|v| v & !3)
}

/// The NUL-terminated string at `off` of `b` and the offset past its NUL.
fn cstr(b: &[u8], off: usize) -> Option<(&str, usize)> {
    let rest = b.get(off..)?;
    let n = rest.iter().position(|&c| c == 0)?;
    Some((core::str::from_utf8(&rest[..n]).ok()?, off + n + 1))
}

impl<'a> Fdt<'a> {
    /// The tree in `blob`; `None` for a bad magic, a version below 16 or
    /// blocks that do not fit in the blob.
    pub fn parse(blob: &'a [u8]) -> Option<Fdt<'a>> {
        if be32(blob, 0)? != FDT_MAGIC {
            return None;
        }
        let total = be32(blob, 4)? as usize;
        let blob = blob.get(..total)?;
        if be32(blob, 20)? < 16 {
            return None;
        }
        let so = be32(blob, 8)? as usize;
        let sto = be32(blob, 12)? as usize;
        let ssz = be32(blob, 36)? as usize;
        let tsz = be32(blob, 32)? as usize;
        let st = blob.get(so..so.checked_add(ssz)?)?;
        let strs = blob.get(sto..sto.checked_add(tsz)?)?;
        Some(Fdt { st, strs })
    }

    /// The node name of the `FDT_BEGIN_NODE` at `n` and the offset of its
    /// first property or child.
    fn begin(&self, n: NodeId) -> Option<(&'a str, usize)> {
        let off = n.0 as usize;
        if be32(self.st, off)? != FDT_BEGIN_NODE {
            return None;
        }
        let (name, next) = cstr(self.st, off + 4)?;
        Some((name, align4(next)?))
    }

    /// The node's name with its unit address (`uart@10000000`); the root's is
    /// empty.
    pub fn name(&self, n: NodeId) -> Option<&'a str> {
        self.begin(n).map(|(name, _)| name)
    }

    /// The property at `off` (a `FDT_PROP` token): name, value, next offset.
    fn prop_at(&self, off: usize) -> Option<(&'a str, &'a [u8], usize)> {
        let len = be32(self.st, off + 4)? as usize;
        let name_off = be32(self.st, off + 8)? as usize;
        let vstart = off.checked_add(12)?;
        let val = self.st.get(vstart..vstart.checked_add(len)?)?;
        let (name, _) = cstr(self.strs, name_off)?;
        Some((name, val, align4(vstart + len)?))
    }

    /// Every property of `n`, in tree order.
    pub fn props(&self, n: NodeId) -> Props<'a> {
        Props { fdt: *self, off: self.begin(n).map(|(_, o)| o) }
    }

    /// The value of property `name` of `n`.
    pub fn prop(&self, n: NodeId, name: &str) -> Option<&'a [u8]> {
        self.props(n).find(|(p, _)| *p == name).map(|(_, v)| v)
    }

    pub fn has_prop(&self, n: NodeId, name: &str) -> bool {
        self.prop(n, name).is_some()
    }

    /// A one-cell property.
    pub fn u32_prop(&self, n: NodeId, name: &str) -> Option<u32> {
        let v = self.prop(n, name)?;
        if v.len() == 4 { cell(v, 0) } else { None }
    }

    /// Is `compat` one of the strings of `n`'s `compatible`?
    pub fn is_compatible(&self, n: NodeId, compat: &str) -> bool {
        self.prop(n, "compatible").is_some_and(|v| strings(v).any(|s| s == compat))
    }

    /// `status` absent or `okay`: a node a driver may bind.
    pub fn is_available(&self, n: NodeId) -> bool {
        match self.prop(n, "status") {
            None => true,
            Some(v) => strings(v).next().is_some_and(|s| s == "okay" || s == "ok"),
        }
    }

    /// The offset after the node whose `FDT_BEGIN_NODE` is at `off`.
    fn skip_node(&self, mut off: usize) -> Option<usize> {
        let mut depth = 0usize;
        loop {
            match be32(self.st, off)? {
                FDT_BEGIN_NODE => {
                    depth += 1;
                    let (_, next) = cstr(self.st, off + 4)?;
                    off = align4(next)?;
                }
                FDT_END_NODE => {
                    depth -= 1;
                    off += 4;
                    if depth == 0 {
                        return Some(off);
                    }
                }
                FDT_PROP => off = self.prop_at(off)?.2,
                FDT_NOP => off += 4,
                _ => return None,
            }
        }
    }

    /// The direct children of `n`.
    pub fn children(&self, n: NodeId) -> Children<'a> {
        Children { fdt: *self, off: self.begin(n).map(|(_, o)| o) }
    }

    /// Every node of the tree, parents before children, to the depth the SoC
    /// nodes sit at (`/soc/clock-controller@...` is 2). A node deeper than
    /// [`WALK_DEPTH`] and its subtree are not visited.
    pub fn walk(&self, mut f: impl FnMut(NodeId)) {
        let mut stack: [Option<Children<'_>>; WALK_DEPTH] = [const { None }; WALK_DEPTH];
        f(NodeId(0));
        stack[0] = Some(self.children(NodeId(0)));
        let mut depth = 1;
        while depth > 0 {
            match stack[depth - 1].as_mut().and_then(|c| c.next()) {
                Some(n) => {
                    f(n);
                    if depth < WALK_DEPTH {
                        stack[depth] = Some(self.children(n));
                        depth += 1;
                    }
                }
                None => {
                    stack[depth - 1] = None;
                    depth -= 1;
                }
            }
        }
    }

    /// The first available node (document order) whose `compatible` has
    /// `compat`.
    pub fn find_compatible(&self, compat: &str) -> Option<NodeId> {
        let mut found = None;
        self.walk(|n| {
            if found.is_none() && self.is_available(n) && self.is_compatible(n, compat) {
                found = Some(n);
            }
        });
        found
    }

    /// The node whose `phandle` (or `linux,phandle`) is `ph`.
    pub fn by_phandle(&self, ph: u32) -> Option<NodeId> {
        if ph == 0 {
            return None;
        }
        let mut off = 0usize;
        let mut cur = None;
        loop {
            match be32(self.st, off)? {
                FDT_BEGIN_NODE => {
                    cur = Some(NodeId(off as u32));
                    let (_, next) = cstr(self.st, off + 4)?;
                    off = align4(next)?;
                }
                FDT_END_NODE | FDT_NOP => off += 4,
                FDT_PROP => {
                    let (name, val, next) = self.prop_at(off)?;
                    if (name == "phandle" || name == "linux,phandle") && val.len() == 4 && cell(val, 0) == Some(ph) {
                        return cur;
                    }
                    off = next;
                }
                _ => return None,
            }
        }
    }

    /// Every ancestor of `target`, root first; `None` when `target` is not a
    /// node or sits deeper than [`MAX_DEPTH`].
    pub fn ancestors(&self, target: NodeId) -> Option<Ancestors> {
        let mut ids = [NodeId(0); MAX_DEPTH];
        let mut depth = 0usize;
        let mut off = 0usize;
        loop {
            match be32(self.st, off)? {
                FDT_BEGIN_NODE => {
                    if off as u32 == target.0 {
                        return Some(Ancestors { ids, len: depth });
                    }
                    if depth >= MAX_DEPTH {
                        return None;
                    }
                    ids[depth] = NodeId(off as u32);
                    depth += 1;
                    let (_, next) = cstr(self.st, off + 4)?;
                    off = align4(next)?;
                }
                FDT_END_NODE => {
                    depth = depth.checked_sub(1)?;
                    off += 4;
                }
                FDT_PROP => off = self.prop_at(off)?.2,
                FDT_NOP => off += 4,
                _ => return None,
            }
        }
    }

    /// The first `reg` window of `n`, read with its parent's `#address-cells`
    /// and `#size-cells` (defaults 2 and 1). The address is the bus address:
    /// an ancestor with a non-empty `ranges` would translate it, and this
    /// view does not, so the lookup answers `None` there rather than a wrong
    /// CPU address (an empty `ranges` is the identity).
    pub fn reg(&self, n: NodeId) -> Option<(u64, u64)> {
        let anc = self.ancestors(n)?;
        for &a in anc.as_slice() {
            if self.prop(a, "ranges").is_some_and(|r| !r.is_empty()) {
                return None;
            }
        }
        let p = anc.parent()?;
        let ac = self.u32_prop(p, "#address-cells").unwrap_or(2) as usize;
        let sc = self.u32_prop(p, "#size-cells").unwrap_or(1) as usize;
        let reg = self.prop(n, "reg")?;
        Some((cells(reg, 0, ac)?, if sc == 0 { 0 } else { cells(reg, ac, sc)? }))
    }
}

/// Properties of one node (see [`Fdt::props`]).
pub struct Props<'a> {
    fdt: Fdt<'a>,
    off: Option<usize>,
}

impl<'a> Iterator for Props<'a> {
    type Item = (&'a str, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let off = self.off?;
            match be32(self.fdt.st, off) {
                Some(FDT_NOP) => self.off = Some(off + 4),
                Some(FDT_PROP) => {
                    let (name, val, next) = match self.fdt.prop_at(off) {
                        Some(p) => p,
                        None => {
                            self.off = None;
                            return None;
                        }
                    };
                    self.off = Some(next);
                    return Some((name, val));
                }
                _ => {
                    self.off = None;
                    return None;
                }
            }
        }
    }
}

/// Children of one node (see [`Fdt::children`]).
pub struct Children<'a> {
    fdt: Fdt<'a>,
    off: Option<usize>,
}

impl<'a> Iterator for Children<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        loop {
            let off = self.off?;
            match be32(self.fdt.st, off) {
                Some(FDT_NOP) => self.off = Some(off + 4),
                Some(FDT_PROP) => match self.fdt.prop_at(off) {
                    Some((_, _, next)) => self.off = Some(next),
                    None => self.off = None,
                },
                Some(FDT_BEGIN_NODE) => {
                    self.off = self.fdt.skip_node(off);
                    return Some(NodeId(off as u32));
                }
                _ => {
                    self.off = None;
                    return None;
                }
            }
        }
    }
}

/// Cell `i` of a property value.
pub fn cell(v: &[u8], i: usize) -> Option<u32> {
    be32(v, i.checked_mul(4)?)
}

/// `count` cells (1 or 2) starting at cell `first`, as one number.
pub fn cells(v: &[u8], first: usize, count: usize) -> Option<u64> {
    match count {
        1 => cell(v, first).map(u64::from),
        2 => Some(u64::from(cell(v, first)?) << 32 | u64::from(cell(v, first + 1)?)),
        _ => None,
    }
}

/// The strings of a NUL-separated list property, in order. An empty string
/// inside the list is kept (it holds its index in a `*-names` list).
pub fn strings(v: &[u8]) -> impl Iterator<Item = &str> {
    let body = v.strip_suffix(&[0]).unwrap_or(v);
    body.split(|&b| b == 0)
        .take(if v.is_empty() { 0 } else { usize::MAX })
        .filter_map(|s| core::str::from_utf8(s).ok())
}
