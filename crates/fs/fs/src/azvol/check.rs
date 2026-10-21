// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The tree walk: the set of blocks every tree names (used to rebuild a
//! free-space map that does not match) and the consistency check built on
//! it (`Volume::check`, what `fsck` for this format will call).
//!
//! "Every tree" is the live one plus the tree of each retained snapshot
//! ([`super::snap`]) plus the two auxiliary files. Trees share blocks on
//! purpose, so a block named twice is a fault only inside one tree; the
//! union of the trees is what the free-space map must equal.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::engine::Inode;
use super::dev::BlockDev;
use super::dir;
use super::freemap::FreeMap;
use super::layout::{Extent, Kind, BLOCK_SIZE, BS, INODES_PER_BLOCK, INODE_SIZE, ROOT_INO};
use super::volume::Volume;
use super::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Problem {
    pub ino: u64,
    pub what: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct CheckReport {
    pub inodes: u64,
    pub blocks_used: u64,
    pub blocks_scrubbed: u64,
    pub problems: Vec<Problem>,
}

impl CheckReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

fn mark(map: &mut FreeMap, conflicts: &mut u64, exts: &[Extent], nodes: &[(u64, u64)]) {
    for e in exts {
        for b in e.disk_blk..e.disk_blk + e.nblocks as u64 {
            if !map.set(b) {
                *conflicts += 1;
            }
        }
    }
    for (b, _) in nodes {
        if !map.set(*b) {
            *conflicts += 1;
        }
    }
}

/// Blocks named by the trees of a volume, kept apart so `check` can tell
/// which tree names what.
pub(super) struct Used {
    /// Static regions, the live tree and the auxiliary files.
    pub live: FreeMap,
    /// The union of the retained snapshots' trees.
    pub snap: FreeMap,
    /// Everything: `live` and `snap`.
    pub all: FreeMap,
    /// Blocks named twice inside one tree.
    pub conflicts: u64,
}

impl<D: BlockDev> Volume<D> {
    /// Mark every block of the tree whose inode table has these extents
    /// (the table's own blocks and each inode's tree) into `map`; returns
    /// the number of blocks that tree names twice.
    fn mark_tree(&mut self, itable: &[Extent], inodes_nodes: &[(u64, u64)], slots: u64, map: &mut FreeMap) -> Result<u64, Error> {
        let mut conflicts = 0u64;
        mark(map, &mut conflicts, itable, inodes_nodes);
        let mut fb = 0;
        let mut blk = vec![0u8; BLOCK_SIZE];
        while fb * INODES_PER_BLOCK < slots {
            self.core.read_range(itable, fb * BS, &mut blk)?;
            for k in 0..INODES_PER_BLOCK {
                let ino = fb * INODES_PER_BLOCK + k;
                if ino == 0 || ino >= slots {
                    continue;
                }
                let o = k as usize * INODE_SIZE;
                let d = super::layout::InodeDisk::decode(&blk[o..o + INODE_SIZE])?;
                if d.kind == Kind::Table || d.ino != ino {
                    return Err(Error::Corrupt("inode record"));
                }
                if d.kind != Kind::Free {
                    let (e, n) = self.core.load_tree(&d, ino)?;
                    mark(map, &mut conflicts, &e, &n);
                }
            }
            fb += 1;
        }
        Ok(conflicts)
    }

    /// The blocks the committed trees name, plus the static regions.
    pub(super) fn collect_used(&mut self) -> Result<Used, Error> {
        let geo = self.core.geo;
        let mut live = FreeMap::new(&geo);
        live.set_static(&geo);
        let itable = self.itable.extents.clone();
        let nodes = self.itable.nodes.clone();
        let mut conflicts = self.mark_tree(&itable, &nodes, self.sb.inode_slots, &mut live)?;
        for f in [&self.snaptab, &self.deadf] {
            mark(&mut live, &mut conflicts, &f.extents, &f.nodes);
        }
        let mut snap = FreeMap::new(&geo);
        let recs = self.core.snaps.clone();
        for r in recs {
            let (e, n) = self.core.load_tree(&r.itable, 0)?;
            let mut one = FreeMap::new(&geo);
            conflicts += self.mark_tree(&e, &n, r.inode_slots, &mut one)?;
            snap.union_with(&one);
        }
        let mut all = FreeMap::new(&geo);
        all.union_with(&live);
        all.union_with(&snap);
        Ok(Used { live, snap, all, conflicts })
    }

    /// Commit, then verify the volume: block ownership against the stored
    /// free-space map, the free-inode list, directory structure and link
    /// counts (every inode but the root named exactly once). With `scrub`,
    /// also read every data block against its checksum.
    pub fn check(&mut self, scrub: bool) -> Result<CheckReport, Error> {
        self.commit()?;
        let mut rep = CheckReport::default();
        let used = self.collect_used()?;
        let (map, conflicts) = (&used.all, used.conflicts);
        if conflicts > 0 {
            rep.problems.push(Problem { ino: 0, what: "block named by more than one owner" });
        }
        let (named_not_marked, marked_not_named) = map.diff(&self.core.bitmap);
        if named_not_marked > 0 {
            rep.problems.push(Problem { ino: 0, what: "block in use but marked free" });
        }
        if marked_not_named > 0 {
            rep.problems.push(Problem { ino: 0, what: "block marked used but named by nothing" });
        }
        rep.blocks_used = map.count();
        // the dead list: runs a snapshot names and the live tree does not,
        // each once
        let mut seen = FreeMap::new(&self.core.geo);
        for e in &self.core.dead {
            for b in e.disk_blk..e.disk_blk + e.nblocks as u64 {
                if !seen.set(b) {
                    rep.problems.push(Problem { ino: 0, what: "dead list names a block twice" });
                    break;
                }
            }
            if (e.disk_blk..e.disk_blk + e.nblocks as u64).any(|b| used.live.is_set(b)) {
                rep.problems.push(Problem { ino: 0, what: "dead block named by the live tree" });
            }
            if (e.disk_blk..e.disk_blk + e.nblocks as u64).any(|b| !used.snap.is_set(b)) {
                rep.problems.push(Problem { ino: 0, what: "dead block named by no snapshot" });
            }
        }
        if self.core.used != rep.blocks_used {
            rep.problems.push(Problem { ino: 0, what: "used-block count wrong" });
        }
        let slots = self.sb.inode_slots;
        let mut free_slots = 0u64;
        let mut live: BTreeMap<u64, Kind> = BTreeMap::new();
        for ino in 1..slots {
            let d = self.read_slot(ino)?;
            if d.kind == Kind::Free {
                free_slots += 1;
            } else {
                live.insert(ino, d.kind);
            }
        }
        rep.inodes = live.len() as u64;
        // free-inode list: acyclic, only free slots, all of them
        let (mut at, mut seen) = (self.sb.free_head, 0u64);
        while at != 0 && seen <= slots {
            let d = self.read_slot(at)?;
            if d.kind != Kind::Free {
                rep.problems.push(Problem { ino: at, what: "free list names an inode in use" });
                break;
            }
            seen += 1;
            at = d.link;
            if at >= slots {
                rep.problems.push(Problem { ino: 0, what: "free list leaves the table" });
                break;
            }
        }
        if seen != free_slots {
            rep.problems.push(Problem { ino: 0, what: "free list does not cover the free slots" });
        }
        // directories
        let mut refs: BTreeMap<u64, u32> = BTreeMap::new();
        match live.get(&ROOT_INO) {
            Some(Kind::Dir) => {}
            _ => rep.problems.push(Problem { ino: ROOT_INO, what: "root is not a directory" }),
        }
        let dirs: Vec<u64> = live.iter().filter(|(_, k)| **k == Kind::Dir).map(|(i, _)| *i).collect();
        for d in dirs {
            self.load(d)?;
            let mut raw = Vec::new();
            self.dir_scan(d, |_, blk| {
                dir::list(blk, &mut raw)?;
                Ok(false)
            })?;
            for (name, target, kind) in raw {
                if !dir::name_ok(&name) {
                    rep.problems.push(Problem { ino: d, what: "invalid name in directory" });
                }
                match live.get(&target) {
                    Some(k) if *k as u8 == kind => {
                        *refs.entry(target).or_insert(0) += 1;
                        if *k == Kind::Dir {
                            self.load(target)?;
                            if self.inodes[&target].link != d {
                                rep.problems.push(Problem { ino: target, what: "directory parent link wrong" });
                            }
                        }
                    }
                    _ => rep.problems.push(Problem { ino: d, what: "entry names a missing or mistyped inode" }),
                }
            }
            if self.inodes.len() > 4096 {
                self.inodes.retain(|_, i| i.dirty);
            }
        }
        for ino in live.keys() {
            let n = refs.get(ino).copied().unwrap_or(0);
            let want = if *ino == ROOT_INO { 0 } else { 1 };
            if n != want {
                rep.problems.push(Problem { ino: *ino, what: "inode not named exactly once" });
            }
        }
        if scrub {
            let inos: Vec<u64> = live.keys().copied().collect();
            for ino in inos {
                self.load(ino)?;
                let exts: Vec<Extent> = self.inodes[&ino].extents.clone();
                let mut buf = Vec::new();
                for e in exts {
                    let mut done = 0u64;
                    while done < e.nblocks as u64 {
                        let c = (e.nblocks as u64 - done).min(64);
                        buf.resize(c as usize * BLOCK_SIZE, 0);
                        match self.core.read_run(e.disk_blk + done, &mut buf) {
                            Ok(()) => rep.blocks_scrubbed += c,
                            Err(Error::Checksum(_) | Error::Auth(_)) => rep.problems.push(Problem { ino, what: "data block fails its checksum" }),
                            Err(e) => return Err(e),
                        }
                        done += c;
                    }
                }
                if self.inodes.len() > 4096 {
                    self.inodes.retain(|_, i: &mut Inode| i.dirty);
                }
            }
        }
        if scrub {
            let dead = self.core.dead.clone();
            let mut buf = Vec::new();
            for e in dead {
                let mut done = 0u64;
                while done < e.nblocks as u64 {
                    let c = (e.nblocks as u64 - done).min(64);
                    buf.resize(c as usize * BLOCK_SIZE, 0);
                    match self.core.read_run(e.disk_blk + done, &mut buf) {
                        Ok(()) => rep.blocks_scrubbed += c,
                        Err(Error::Checksum(_) | Error::Auth(_)) => rep.problems.push(Problem { ino: 0, what: "retained block fails its checksum" }),
                        Err(x) => return Err(x),
                    }
                    done += c;
                }
            }
        }
        Ok(rep)
    }
}
