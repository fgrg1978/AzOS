// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Exported-symbol table and the registry of unimplemented symbols.
//!
//! The `.ko` loader (later stage) resolves every undefined symbol of a
//! module against a table sorted by name. Sorting is checked at compile time
//! with [`is_sorted_unique`] in a `const` assertion, so a mis-ordered or
//! duplicated entry is a build error rather than a lookup that silently
//! misses.
//!
//! Symbols a driver references but the layer does not implement are bound
//! to "dummies" that report themselves. [`Dummies::hit`] counts every call
//! and logs `unimplemented <name>` once per name (the console tag adds
//! `[LX] `), so the log shows each gap once and a gate row can assert that
//! the total is zero.

use crate::printk::Printk;

/// One exported symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Linker name.
    pub name: &'static str,
    /// Address the loader patches in.
    pub addr: usize,
    /// `EXPORT_SYMBOL_GPL`: only modules with a GPL-compatible license may
    /// bind to it.
    pub gpl_only: bool,
}

/// Why a symbol did not resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// Not in the table.
    Unknown,
    /// GPL-only symbol requested by a non-GPL module.
    GplOnly,
}

/// Byte-wise ordering of two names, usable in `const` context.
pub const fn cmp_names(a: &str, b: &str) -> core::cmp::Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] < b[i] {
            return core::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return core::cmp::Ordering::Greater;
        }
        i += 1;
    }
    if a.len() < b.len() {
        core::cmp::Ordering::Less
    } else if a.len() > b.len() {
        core::cmp::Ordering::Greater
    } else {
        core::cmp::Ordering::Equal
    }
}

/// True if `syms` is strictly ascending by name (sorted, no duplicates).
/// Intended for `const _: () = assert!(is_sorted_unique(TABLE));`.
pub const fn is_sorted_unique(syms: &[Symbol]) -> bool {
    let mut i = 1;
    while i < syms.len() {
        if !matches!(cmp_names(syms[i - 1].name, syms[i].name), core::cmp::Ordering::Less) {
            return false;
        }
        i += 1;
    }
    true
}

/// A sorted symbol table.
#[derive(Clone, Copy, Debug)]
pub struct SymbolTable {
    syms: &'static [Symbol],
}

impl SymbolTable {
    /// Wrap a table; `None` if it is not sorted and unique (the run-time
    /// twin of the compile-time check, for tables built elsewhere).
    pub const fn new(syms: &'static [Symbol]) -> Option<Self> {
        if is_sorted_unique(syms) {
            Some(SymbolTable { syms })
        } else {
            None
        }
    }

    /// Number of symbols.
    pub fn len(&self) -> usize {
        self.syms.len()
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }

    /// Binary search by name.
    pub fn lookup(&self, name: &str) -> Option<&'static Symbol> {
        let syms = self.syms;
        syms.binary_search_by(|s| cmp_names(s.name, name)).ok().map(|i| &syms[i])
    }

    /// Resolve for a module, enforcing `EXPORT_SYMBOL_GPL`.
    pub fn resolve(&self, name: &str, module_is_gpl: bool) -> Result<usize, ResolveError> {
        match self.lookup(name) {
            None => Err(ResolveError::Unknown),
            Some(s) if s.gpl_only && !module_is_gpl => Err(ResolveError::GplOnly),
            Some(s) => Ok(s.addr),
        }
    }
}

/// Registry of calls to unimplemented symbols, remembering up to `N`
/// distinct names.
#[derive(Debug)]
pub struct Dummies<const N: usize> {
    names: [Option<&'static str>; N],
    counts: [u64; N],
    total: u64,
    overflow: u64,
}

impl<const N: usize> Default for Dummies<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Dummies<N> {
    /// Empty registry.
    pub const fn new() -> Self {
        Dummies { names: [None; N], counts: [0; N], total: 0, overflow: 0 }
    }

    /// Record a call to the unimplemented symbol `name`, logging it at
    /// `KERN_WARNING` the first time. When the registry is full a name can
    /// no longer be deduplicated; it is then logged on every hit and
    /// counted in [`Dummies::overflow`], erring towards visibility.
    pub fn hit<const R: usize>(&mut self, name: &'static str, log: &mut Printk<R>) {
        self.total += 1;
        let mut free = None;
        for i in 0..N {
            match self.names[i] {
                Some(n) if n == name => {
                    self.counts[i] += 1;
                    return;
                }
                None if free.is_none() => free = Some(i),
                _ => {}
            }
        }
        match free {
            Some(i) => {
                self.names[i] = Some(name);
                self.counts[i] = 1;
            }
            None => self.overflow += 1,
        }
        log_unimplemented(name, log);
    }

    /// Total calls to unimplemented symbols (a gate asserts 0).
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Calls for one name.
    pub fn count(&self, name: &str) -> u64 {
        (0..N).find(|&i| self.names[i] == Some(name)).map_or(0, |i| self.counts[i])
    }

    /// Distinct names recorded.
    pub fn distinct(&self) -> usize {
        self.names.iter().filter(|n| n.is_some()).count()
    }

    /// Hits on names that did not fit the registry.
    pub fn overflow(&self) -> u64 {
        self.overflow
    }
}

fn log_unimplemented<const R: usize>(name: &str, log: &mut Printk<R>) {
    const HEAD: &[u8] = b"unimplemented ";
    let mut buf = [0u8; crate::printk::LINE_MAX];
    let n = name.len().min(buf.len() - HEAD.len() - 1);
    buf[..HEAD.len()].copy_from_slice(HEAD);
    buf[HEAD.len()..HEAD.len() + n].copy_from_slice(&name.as_bytes()[..n]);
    buf[HEAD.len() + n] = b'\n';
    log.pr_warn(&buf[..HEAD.len() + n + 1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::printk::Printk;

    static TABLE: &[Symbol] = &[
        Symbol { name: "__kmalloc", addr: 0x10, gpl_only: false },
        Symbol { name: "kfree", addr: 0x20, gpl_only: false },
        Symbol { name: "mod_timer", addr: 0x30, gpl_only: false },
        Symbol { name: "queue_work_on", addr: 0x40, gpl_only: true },
        Symbol { name: "queue_work_onx", addr: 0x50, gpl_only: false },
    ];
    // The compile-time check this module exists for.
    const _: () = assert!(is_sorted_unique(TABLE));

    #[test]
    fn lookup_by_binary_search() {
        let t = SymbolTable::new(TABLE).unwrap();
        assert_eq!(t.len(), 5);
        for s in TABLE {
            assert_eq!(t.lookup(s.name), Some(s));
        }
        assert_eq!(t.lookup("kfre"), None);
        assert_eq!(t.lookup("kfreee"), None);
        assert_eq!(t.lookup(""), None);
        assert_eq!(t.lookup("zzz"), None);
    }

    #[test]
    fn gpl_only_symbols_need_a_gpl_module() {
        let t = SymbolTable::new(TABLE).unwrap();
        assert_eq!(t.resolve("queue_work_on", true), Ok(0x40));
        assert_eq!(t.resolve("queue_work_on", false), Err(ResolveError::GplOnly));
        assert_eq!(t.resolve("kfree", false), Ok(0x20));
        assert_eq!(t.resolve("nope", true), Err(ResolveError::Unknown));
    }

    #[test]
    fn unsorted_or_duplicate_tables_are_rejected() {
        static BAD: &[Symbol] = &[
            Symbol { name: "b", addr: 0, gpl_only: false },
            Symbol { name: "a", addr: 0, gpl_only: false },
        ];
        static DUP: &[Symbol] = &[
            Symbol { name: "a", addr: 0, gpl_only: false },
            Symbol { name: "a", addr: 1, gpl_only: false },
        ];
        assert!(!is_sorted_unique(BAD));
        assert!(!is_sorted_unique(DUP));
        assert!(SymbolTable::new(BAD).is_none());
        assert!(is_sorted_unique(&[]));
    }

    #[test]
    fn byte_order_matches_str_order() {
        let names = ["", "a", "ab", "b", "_x", "A", "a_b", "a0"];
        for x in names {
            for y in names {
                assert_eq!(cmp_names(x, y), x.cmp(y), "{} vs {}", x, y);
            }
        }
    }

    #[test]
    fn dummies_count_every_hit_and_log_once_per_name() {
        let mut log: Printk<8> = Printk::new();
        let mut d: Dummies<4> = Dummies::new();
        d.hit("of_clk_get", &mut log);
        d.hit("of_clk_get", &mut log);
        d.hit("pm_runtime_enable", &mut log);
        assert_eq!(d.total(), 3);
        assert_eq!(d.count("of_clk_get"), 2);
        assert_eq!(d.distinct(), 2);
        let texts: Vec<&[u8]> = log.records().map(|r| r.text()).collect();
        assert_eq!(texts, vec![&b"unimplemented of_clk_get\n"[..], &b"unimplemented pm_runtime_enable\n"[..]]);
    }

    #[test]
    fn full_registry_still_counts_and_logs() {
        let mut log: Printk<8> = Printk::new();
        let mut d: Dummies<1> = Dummies::new();
        d.hit("a", &mut log);
        d.hit("b", &mut log);
        d.hit("b", &mut log);
        assert_eq!(d.total(), 3);
        assert_eq!(d.overflow(), 2);
        assert_eq!(log.len(), 3);
    }
}
