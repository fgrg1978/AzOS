// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Shared block cache (RFC-0048 prerequisite P1).
//!
//! One cache type for every filesystem in this crate, replacing the private
//! 8 x 512 B sector cache `fat32.rs` carried. It is a plain value: the owner
//! puts it behind its own lock and passes the device in, so the cache itself
//! never takes a lock and never names a driver. That is also what lets
//! `tests/host/fs-tests` drive it against a recording device on the host.
//!
//! # Geometry
//!
//! `BYTES` of line storage and at most `LINES` tags, fixed at compile time.
//! The block size is chosen at [`BlockCache::configure`] time: a power of two
//! from 512 B (FAT32's sector) to 4 KiB (ext4's usual block), so the same
//! storage holds 8 x 512 B, 4 x 1 KiB or 1 x 4 KiB lines. Block `b` is the
//! `sectors_per_block` 512-byte sectors starting at LBA
//! `base_lba + b * sectors_per_block`; `base_lba` is where a partition starts.
//!
//! Lines are grouped in sets of [`MAX_WAYS`] (wave 14): block `b` can only
//! live in set `b & set_mask`, so a lookup, an install and a single-block
//! invalidation probe at most `MAX_WAYS` tags whatever the cache size, and
//! LRU is per set. A cache of `MAX_WAYS` lines or fewer is one set, i.e.
//! fully associative, exactly the cache this file had before. Since wave 15
//! (WRITEBACK) a [`Mode::WriteBack`] cache is set-associative too: the epoch
//! rule no longer depends on which line is evicted, because evicting a dirty
//! line first writes back every OLDER epoch (see [`BlockCache::write`]), and
//! the split path ([`write_dirty`](BlockCache::write_dirty)) never evicts a
//! dirty line at all. The set count is a power of two; lines past the last
//! whole set are left unused.
//!
//! Validity is a generation stamp: a tag is live only while its `gen`
//! equals the cache's, so [`invalidate_all`](BlockCache::invalidate_all) is
//! O(1) for a write-through cache however many lines it has.
//!
//! [`BlockCache::unconfigured`] is an all-zero value (zero lines, passes
//! every read and write through), so a large cache in a `static` lands in
//! `.bss` and costs no image bytes; the owner calls `configure` before use.
//!
//! # Two ways to use it
//!
//! * **Split, lock released across the device** — [`lookup`], then the
//!   caller reads the device itself, then [`install`] with the token
//!   `lookup_miss_token` returned. FAT32 uses this, because its reads have
//!   always dropped the cache lock during the device read. The token closes
//!   the one race that leaves: a write or invalidation of the block while
//!   the read was in flight makes `install` drop the (now stale) data instead
//!   of caching it.
//! * **Whole operations** — [`read`], [`write`], [`sync`] take the device and
//!   do the I/O themselves. Used when the owner can hold its lock across I/O.
//!
//! # Write policy and ordering
//!
//! [`Mode::WriteThrough`]: every write reaches the device before the call
//! returns; a line is updated if the block is present and never installed on
//! a write miss. No line is ever dirty. This is FAT32's mode, bit for bit the
//! behaviour of the cache it replaces.
//!
//! [`Mode::WriteBack`]: a write only dirties a line, stamped with the current
//! **epoch**. [`barrier`] closes the epoch. The ordering rule, the one a
//! journal needs, is: *no block of epoch `e` reaches the device before every
//! block of every epoch `< e` that is already on its way there has been made
//! durable by a device flush*. It is enforced at the single place a dirty
//! line is written ([`BlockCache::write_line`]), so it holds for writes done
//! by [`sync`] and for writes forced by eviction alike. Eviction prefers a
//! clean line; a dirty victim is the oldest-epoch one.
//!
//! [`sync`] writes every dirty line, epoch by epoch, then flushes the device.
//! A write that fails leaves its line dirty; the error is returned and nothing
//! of a later epoch is written after it.
//!
//! # Write-back with the owner's lock released across the device
//!
//! The whole-operation calls above do their I/O with the cache borrowed, i.e.
//! under the owner's lock. An owner whose lock is a spinlock (FAT32) must
//! never wait on the device under it (owner rule F1), so wave 15 adds a
//! split write-back path that does no I/O inside the cache:
//!
//! * [`write_dirty`](BlockCache::write_dirty) dirties a line or answers
//!   [`Dirty::NeedWriteback`]: the block's line holds an older epoch's
//!   unwritten contents, or its set has no clean line to give. The owner then
//!   writes back through that epoch (below, lock released) and retries.
//! * [`checkout_run`](BlockCache::checkout_run) copies the next run out: the
//!   oldest dirty epoch's lowest block and every following block that is
//!   dirty in the SAME epoch, up to a length the owner chooses. It says
//!   whether a device flush must come first (an older epoch was written
//!   since the last flush: the epoch rule). The owner writes the run as one
//!   multi-sector request with its lock released, then
//!   [`checkin`](BlockCache::checkin)s it: a line is clean again only if it
//!   was not dirtied after the checkout (a per-line dirtying stamp, `dseq`),
//!   so a write racing the device request is never lost.
//!
//! One owner at a time may hold a checked-out run (the owner serialises its
//! flushers): two concurrent write-backs could put an epoch-`e` block on the
//! wire while an older one was still in flight, which no flush orders.
//!
//! [`lookup`]: BlockCache::lookup
//! [`install`]: BlockCache::install
//! [`read`]: BlockCache::read
//! [`write`]: BlockCache::write
//! [`sync`]: BlockCache::sync
//! [`barrier`]: BlockCache::barrier

/// Bytes per device sector. Every block device in the tree speaks 512 B.
pub const SECTOR_BYTES: usize = 512;

/// Smallest and largest block size a cache accepts.
pub const MIN_BLOCK: usize = 512;
pub const MAX_BLOCK: usize = 4096;

/// Lines per set of a write-through cache larger than this many lines.
pub const MAX_WAYS: usize = 8;

/// The device underneath a cache.
///
/// `lba` and `count` are in 512 B sectors; `buf` is exactly
/// `count * SECTOR_BYTES` bytes.
pub trait BlockIo {
    /// What a failed flush says; the cache hands it back unchanged.
    type FlushErr;
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()>;
    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()>;
    fn flush(&mut self) -> Result<(), Self::FlushErr>;
}

/// Write policy. See the module doc.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    WriteThrough,
    WriteBack,
}

/// Why [`BlockCache::configure`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigError {
    /// Not a power of two in `MIN_BLOCK..=MAX_BLOCK`, or it does not tile
    /// the storage into between 1 and `LINES` lines.
    BadBlockSize,
    /// Dirty lines would be dropped; `sync` first.
    Dirty,
}

/// Why an I/O operation of the cache failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoError<F> {
    /// A device read or write failed.
    Io,
    /// The device flush failed, with the device's reason.
    Flush(F),
    /// The block number does not map to an LBA (overflow), or the buffer is
    /// not exactly one block.
    Range,
}

/// Counters. Never reset except by [`BlockCache::reset_stats`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CacheStats {
    pub hits: u32,
    pub misses: u32,
    /// Dirty lines written to the device (by `sync` or by eviction).
    pub writebacks: u32,
    /// Device flushes the cache issued to keep epochs ordered (not counting
    /// the final flush of `sync`).
    pub ordering_flushes: u32,
}

#[derive(Clone, Copy)]
struct Tag {
    block: u64,
    epoch: u64,
    last_use: u64,
    /// The line holds data for `block` while this equals the cache's `gen`.
    /// A stamp rather than a sentinel block number, so every u64 stays an
    /// ordinary block (see the history in `fat32.rs`: `u32::MAX` used to
    /// alias "empty"). 0 is never a live generation.
    gen: u32,
    dirty: bool,
    /// The cache's `dseq` when this line was last dirtied; see `checkin`.
    dseq: u64,
    /// An older epoch's unwritten contents of `block`, kept for write-back
    /// only: a newer line of the same block answers reads. Always dirty;
    /// freed (not cleaned) once written. See `write_dirty`.
    shadow: bool,
    /// A shadow parked outside its block's set (its own set had no line to
    /// give): found by scans only. Counted in `BlockCache::naway`.
    away: bool,
}

const EMPTY_TAG: Tag = Tag { block: 0, epoch: 0, last_use: 0, gen: 0, dirty: false, dseq: 0, shadow: false, away: false };

/// What [`BlockCache::write_dirty`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dirty {
    /// The line holds the new contents, dirty in the current epoch.
    /// `first` is true when the cache had no dirty line before this write.
    Done { first: bool },
    /// Nothing changed: write back every dirty line of epochs up to and
    /// including this one (then flush as `checkout_run` says), and retry.
    NeedWriteback(u64),
    /// Nothing changed and nothing ever will: a zero-line (unconfigured)
    /// cache or a buffer that is not one block. Write the device directly.
    Uncached,
}

/// A run of consecutive dirty blocks of one epoch, copied out by
/// [`BlockCache::checkout_run`] for the owner to write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Run {
    /// First block, its first LBA, and the block count.
    pub block: u64,
    pub lba: u64,
    pub blocks: u32,
    /// Sectors to write (`blocks * sectors per block`).
    pub sectors: u32,
    pub epoch: u64,
    /// Flush the device BEFORE writing the run (and then `note_flushed`):
    /// a block of an older epoch was written since the last flush.
    pub flush_first: bool,
    /// The cache's `dseq` at checkout; a line dirtied after it stays dirty.
    seq: u64,
    /// The first block's line (it may be a shadow parked in another set).
    idx0: usize,
}

/// A block cache with `BYTES` of storage and up to `LINES` lines.
pub struct BlockCache<const BYTES: usize, const LINES: usize> {
    tags: [Tag; LINES],
    data: [u8; BYTES],
    block: usize,
    lines: usize,
    /// Lines per set; `lines` is a multiple of it.
    ways: usize,
    /// Sets - 1 (the set count is a power of two).
    set_mask: u64,
    /// The live generation; see `Tag::gen`. 0 only while `lines == 0`.
    gen: u32,
    base_lba: u64,
    mode: Mode,
    clock: u64,
    epoch: u64,
    /// The highest epoch a [`write_dirty_ahead`](Self::write_dirty_ahead)
    /// put a line in (`epoch + 1` at most); [`barrier`](Self::barrier)
    /// closes it together with `epoch`.
    ahead: u64,
    /// Bumped by every write and invalidation; see `lookup_miss_token`.
    wseq: u64,
    /// Lowest epoch among lines written to the device since the last flush,
    /// or `None` when nothing is waiting for a flush.
    pending_lo: Option<u64>,
    /// Dirty live lines, kept exact by every transition (O(1) watermark).
    ndirty: usize,
    /// Bumped by every dirtying write; stamped into `Tag::dseq`.
    dseq: u64,
    /// Shadows parked outside their block's set (`Tag::away`).
    naway: usize,
    stats: CacheStats,
}

impl<const BYTES: usize, const LINES: usize> BlockCache<BYTES, LINES> {
    /// A cache of `block`-byte lines in `mode`, based at LBA 0.
    ///
    /// `const` so it can initialise a `static`. An invalid `block` yields a
    /// cache with zero lines, which caches nothing and still passes every
    /// read and write through; `configure` reports the error instead.
    pub const fn new(block: usize, mode: Mode) -> Self {
        let (lines, ways, set_mask) = Self::geometry(block, mode);
        Self {
            tags: [EMPTY_TAG; LINES],
            data: [0u8; BYTES],
            block: if lines == 0 { MIN_BLOCK } else { block },
            lines,
            ways,
            set_mask,
            gen: 1,
            base_lba: 0,
            mode,
            clock: 1,
            epoch: 0,
            ahead: 0,
            wseq: 0,
            pending_lo: None,
            ndirty: 0,
            dseq: 0,
            naway: 0,
            stats: CacheStats { hits: 0, misses: 0, writebacks: 0, ordering_flushes: 0 },
        }
    }

    /// Every field zero: no lines and no block size, so on the split path
    /// every `lookup` misses and `install`/`update_if_present` keep nothing,
    /// while the whole-block calls (`read`, `write`) answer `Range` until
    /// [`configure`](Self::configure) gives it a geometry. For a `static`:
    /// an all-zero initialiser lands in `.bss`, not in the image.
    pub const fn unconfigured() -> Self {
        Self {
            tags: [EMPTY_TAG; LINES],
            data: [0u8; BYTES],
            block: 0,
            lines: 0,
            ways: 0,
            set_mask: 0,
            gen: 0,
            base_lba: 0,
            mode: Mode::WriteThrough,
            clock: 0,
            epoch: 0,
            ahead: 0,
            wseq: 0,
            pending_lo: None,
            ndirty: 0,
            dseq: 0,
            naway: 0,
            stats: CacheStats { hits: 0, misses: 0, writebacks: 0, ordering_flushes: 0 },
        }
    }

    /// `(lines, ways, set_mask)` for `block`-byte lines in `mode`. See the
    /// module doc's "Geometry".
    const fn geometry(block: usize, mode: Mode) -> (usize, usize, u64) {
        let n = Self::lines_for(block);
        if n == 0 {
            return (0, 0, 0);
        }
        let _ = mode;
        if n <= MAX_WAYS {
            return (n, n, 0);
        }
        let sets_max = n / MAX_WAYS;
        let sets = 1usize << (usize::BITS - 1 - sets_max.leading_zeros());
        (sets * MAX_WAYS, MAX_WAYS, (sets - 1) as u64)
    }

    const fn lines_for(block: usize) -> usize {
        if block < MIN_BLOCK || block > MAX_BLOCK || !block.is_power_of_two() {
            return 0;
        }
        if BYTES % block != 0 {
            return 0;
        }
        let n = BYTES / block;
        if n == 0 || n > LINES { 0 } else { n }
    }

    /// Change block size, mode and base. Drops every line; refuses while any
    /// line is dirty.
    pub fn configure(&mut self, block: usize, mode: Mode, base_lba: u64) -> Result<(), ConfigError> {
        if self.dirty_count() != 0 {
            return Err(ConfigError::Dirty);
        }
        let (lines, ways, set_mask) = Self::geometry(block, mode);
        if lines == 0 {
            return Err(ConfigError::BadBlockSize);
        }
        // Every tag is dropped below, so the old geometry's stamps cannot
        // alias a block under the new one.
        self.block = block;
        self.lines = lines;
        self.ways = ways;
        self.set_mask = set_mask;
        self.mode = mode;
        self.base_lba = base_lba;
        self.clear_tags();
        self.wseq = self.wseq.wrapping_add(1);
        Ok(())
    }

    pub fn block_size(&self) -> usize { self.block }
    pub fn line_count(&self) -> usize { self.lines }
    pub fn ways(&self) -> usize { self.ways }
    pub fn mode(&self) -> Mode { self.mode }
    pub fn stats(&self) -> CacheStats { self.stats }
    pub fn reset_stats(&mut self) { self.stats = CacheStats::default(); }
    pub fn epoch(&self) -> u64 { self.epoch }
    /// The highest epoch a dirty line may be in now: the current one, or
    /// the one after it when a line was written ahead into it.
    pub fn top_epoch(&self) -> u64 { self.epoch.max(self.ahead) }

    /// Dirty lines. O(1): a counter every transition keeps exact.
    pub fn dirty_count(&self) -> usize {
        self.ndirty
    }

    /// Host tests: the dirty count by a scan, to check the counter against.
    #[cfg(test)]
    pub fn dirty_scan(&self) -> usize {
        let g = self.gen;
        self.tags[..self.lines].iter().filter(|t| t.gen == g && t.dirty).count()
    }

    /// The oldest epoch any dirty line belongs to, `None` when none is dirty.
    /// O(lines).
    pub fn oldest_dirty_epoch(&self) -> Option<u64> {
        if self.ndirty == 0 {
            return None;
        }
        let g = self.gen;
        self.tags[..self.lines].iter().filter(|t| t.gen == g && t.dirty).map(|t| t.epoch).min()
    }

    /// Distinct epochs among the dirty lines (diagnostics and host tests:
    /// how many ordered groups a write-back of everything would write).
    /// O(lines^2) at worst; never on a hot path.
    pub fn dirty_epochs(&self) -> usize {
        let g = self.gen;
        let live = || self.tags[..self.lines].iter().filter(move |t| t.gen == g && t.dirty);
        live().enumerate()
            .filter(|&(i, t)| !live().take(i).any(|u| u.epoch == t.epoch))
            .count()
    }

    fn sectors(&self) -> u32 { (self.block / SECTOR_BYTES) as u32 }

    /// The first LBA of `block`, or `None` on overflow.
    pub fn lba_of(&self, block: u64) -> Option<u64> {
        block.checked_mul(self.sectors() as u64)?.checked_add(self.base_lba)
    }

    fn line(&self, i: usize) -> &[u8] {
        &self.data[i * self.block..(i + 1) * self.block]
    }

    fn line_mut(&mut self, i: usize) -> &mut [u8] {
        let b = self.block;
        &mut self.data[i * b..(i + 1) * b]
    }

    /// First tag of `block`'s set.
    #[inline]
    fn set_of(&self, block: u64) -> usize {
        (block & self.set_mask) as usize * self.ways
    }

    #[inline]
    fn find(&self, block: u64) -> Option<usize> {
        let s = self.set_of(block);
        let g = self.gen;
        self.tags[s..s + self.ways].iter().position(|t| t.gen == g && t.block == block && !t.shadow).map(|i| s + i)
    }

    /// The line (live or shadow) holding `block`'s dirty contents of `epoch`.
    #[inline]
    fn find_dirty_epoch(&self, block: u64, epoch: u64) -> Option<usize> {
        let s = self.set_of(block);
        let g = self.gen;
        self.tags[s..s + self.ways].iter()
            .position(|t| t.gen == g && t.block == block && t.dirty && t.epoch == epoch)
            .map(|i| s + i)
    }

    fn touch(&mut self, i: usize) {
        self.clock = self.clock.saturating_add(1);
        self.tags[i].last_use = self.clock;
    }

    /// Copy `block` into `dst` if it is cached. Counts a hit; a miss is
    /// counted by [`install`](Self::install), after the device answered.
    pub fn lookup(&mut self, block: u64, dst: &mut [u8]) -> bool {
        if dst.len() != self.block {
            return false;
        }
        match self.find(block) {
            Some(i) => {
                dst.copy_from_slice(self.line(i));
                self.touch(i);
                self.stats.hits = self.stats.hits.saturating_add(1);
                true
            }
            None => false,
        }
    }

    /// Copy `dst.len()` bytes at `offset` of `block`'s line, if it is cached:
    /// a FAT entry is 4 bytes, and copying its whole 512-byte sector out to
    /// read them was most of what a cached cluster-chain step cost. Counts a
    /// hit; `false` (nothing copied) on a miss or a range past the line.
    pub fn lookup_bytes(&mut self, block: u64, offset: usize, dst: &mut [u8]) -> bool {
        let end = match offset.checked_add(dst.len()) {
            Some(e) if e <= self.block => e,
            _ => return false,
        };
        match self.find(block) {
            Some(i) => {
                dst.copy_from_slice(&self.line(i)[offset..end]);
                self.touch(i);
                self.stats.hits = self.stats.hits.saturating_add(1);
                true
            }
            None => false,
        }
    }

    /// Copy `block` into `dst` if it is cached, counting nothing and not
    /// touching LRU: for a reader that overlays the cache on what it read
    /// from the device, or scans without wanting to disturb the hot set.
    pub fn peek(&self, block: u64, dst: &mut [u8]) -> bool {
        if dst.len() != self.block {
            return false;
        }
        match self.find(block) {
            Some(i) => {
                dst.copy_from_slice(self.line(i));
                true
            }
            None => false,
        }
    }

    /// Whether any of `count` blocks from `first` is dirty: `MAX_WAYS`
    /// probes per block up to a set's worth, one O(lines) scan beyond.
    pub fn any_dirty_in(&self, first: u64, count: u64) -> bool {
        if self.ndirty == 0 {
            return false;
        }
        if count <= MAX_WAYS as u64 && self.naway == 0 {
            let g = self.gen;
            return (0..count).any(|k| {
                let b = first.wrapping_add(k);
                let s = self.set_of(b);
                self.tags[s..s + self.ways].iter().any(|t| t.gen == g && t.block == b && t.dirty)
            });
        }
        let end = first.saturating_add(count);
        let g = self.gen;
        self.tags[..self.lines].iter().any(|t| t.gen == g && t.dirty && t.block >= first && t.block < end)
    }

    /// The token to pass to [`install`](Self::install) after a miss.
    pub fn lookup_miss_token(&self) -> u64 { self.wseq }

    /// Install `src`, just read from the device, as `block`. Counts a miss.
    ///
    /// Skipped (returns `false`) when `token` is stale: some write or
    /// invalidation happened since the lookup that produced it, and `src`
    /// may predate it. Also skipped when the only victim is dirty — the
    /// split path does no I/O, so it never evicts a dirty line.
    pub fn install(&mut self, block: u64, src: &[u8], token: u64) -> bool {
        self.stats.misses = self.stats.misses.saturating_add(1);
        if src.len() != self.block || token != self.wseq || self.lines == 0 {
            return false;
        }
        if let Some(i) = self.find(block) {
            // Already present (another reader won); a dirty line is newer
            // than the device, so keep it.
            if !self.tags[i].dirty {
                self.line_mut(i).copy_from_slice(src);
            }
            self.touch(i);
            return true;
        }
        let v = self.pick_victim(block);
        if self.live(v) && self.tags[v].dirty {
            return false;
        }
        self.fill(v, block, src, false);
        true
    }

    /// Update `block`'s line if present (after the caller wrote the device
    /// itself). Never installs. Bumps the write sequence either way.
    pub fn update_if_present(&mut self, block: u64, src: &[u8]) {
        self.wseq = self.wseq.wrapping_add(1);
        if src.len() != self.block {
            return;
        }
        if let Some(i) = self.find(block) {
            self.line_mut(i).copy_from_slice(src);
            if self.tags[i].dirty {
                self.tags[i].dirty = false;
                self.ndirty -= 1;
            }
        }
    }

    /// Forget `block`. A dirty line is dropped with it; returns whether one
    /// was.
    pub fn invalidate(&mut self, block: u64) -> bool {
        self.wseq = self.wseq.wrapping_add(1);
        let s = self.set_of(block);
        let g = self.gen;
        let mut was_dirty = false;
        let (lo, hi) = if self.naway != 0 { (0, self.lines) } else { (s, s + self.ways) };
        for i in lo..hi {
            let t = self.tags[i];
            if t.gen == g && t.block == block {
                if t.dirty { self.ndirty -= 1; was_dirty = true; }
                if t.away { self.naway -= 1; }
                self.tags[i] = EMPTY_TAG;
            }
        }
        was_dirty
    }

    /// Forget `count` blocks from `first` (a write the cache did not see).
    /// More than one set's worth is a whole-cache drop, which is O(1) in
    /// write-through, so the time this holds the owner's lock is bounded by
    /// `MAX_WAYS` single-block probes, never by `count`. Returns how many
    /// dirty lines were dropped.
    ///
    /// Write-back with dirty lines: a range past one set's worth must not
    /// drop the dirty lines OUTSIDE it (pending writes of other blocks), so
    /// it is one O(lines) scan that drops exactly the lines inside.
    pub fn invalidate_range(&mut self, first: u64, count: u64) -> usize {
        if count > MAX_WAYS as u64 && self.ndirty != 0 && !cfg!(feature = "wb-observer-drop-canary") {
            self.wseq = self.wseq.wrapping_add(1);
            let end = first.saturating_add(count);
            let g = self.gen;
            let mut dropped = 0;
            let mut away = 0;
            for t in self.tags[..self.lines].iter_mut() {
                if t.gen == g && t.block >= first && t.block < end {
                    if t.dirty { dropped += 1; }
                    if t.away { away += 1; }
                    *t = EMPTY_TAG;
                }
            }
            self.ndirty -= dropped;
            self.naway -= away;
            return dropped;
        }
        if count > MAX_WAYS as u64 {
            return self.invalidate_all();
        }
        let mut dropped = 0;
        for k in 0..count {
            if self.invalidate(first.wrapping_add(k)) { dropped += 1; }
        }
        self.wseq = self.wseq.wrapping_add(1);
        dropped
    }

    /// Forget every line (medium changed). Returns how many dirty lines were
    /// dropped.
    ///
    /// Write-through: a generation bump, O(1). Write-back counts the dirty
    /// lines first (O(lines)); its owner is about to lose data anyway.
    pub fn invalidate_all(&mut self) -> usize {
        self.wseq = self.wseq.wrapping_add(1);
        let dropped = self.ndirty;
        self.ndirty = 0;
        self.naway = 0;
        self.gen = self.gen.wrapping_add(1);
        if self.gen == 0 {
            // 2^32 drops: wipe the stamps so no old tag aliases the new
            // generation.
            self.clear_tags();
        }
        dropped
    }

    /// Every tag empty, generation 1. O(LINES).
    fn clear_tags(&mut self) {
        for t in self.tags.iter_mut() {
            *t = EMPTY_TAG;
        }
        self.ndirty = 0;
        self.naway = 0;
        self.gen = 1;
    }

    /// Host tests: jump the generation to `g`, leaving every tag's stamp as
    /// it is, to reach the wrap in a few steps instead of 2^32.
    #[cfg(test)]
    pub fn force_generation(&mut self, g: u32) {
        self.gen = g;
    }

    #[inline]
    fn live(&self, i: usize) -> bool {
        self.tags[i].gen == self.gen
    }

    /// An empty or clean line outside `block`'s set, scanning the following
    /// sets in turn; `None` when every other line is dirty. O(lines) worst.
    fn free_line_elsewhere(&self, block: u64) -> Option<usize> {
        let sets = self.lines / self.ways.max(1);
        if sets <= 1 {
            return None;
        }
        let own = (block & self.set_mask) as usize;
        let g = self.gen;
        for k in 1..sets {
            let s = ((own + k) % sets) * self.ways;
            if let Some(j) = self.tags[s..s + self.ways].iter().position(|t| t.gen != g || !t.dirty) {
                return Some(s + j);
            }
        }
        None
    }

    /// In `block`'s set: first empty line, else the least recently used clean
    /// line, else the dirty line with the oldest (epoch, last use). FAT32's
    /// cache picked "first empty, else least recently used"; with no dirty
    /// lines (write-through) this is the same choice. A write-back cache is
    /// one set, so its dirty choice is global.
    fn pick_victim(&self, block: u64) -> usize {
        let mut best_clean: Option<(u64, usize)> = None;
        let mut best_dirty: Option<((u64, u64), usize)> = None;
        let s = self.set_of(block);
        let g = self.gen;
        for (k, t) in self.tags[s..s + self.ways].iter().enumerate() {
            let i = s + k;
            if t.gen != g {
                return i;
            }
            if t.dirty {
                let k = (t.epoch, t.last_use);
                if best_dirty.map_or(true, |(b, _)| k < b) { best_dirty = Some((k, i)); }
            } else if best_clean.map_or(true, |(b, _)| t.last_use < b) {
                best_clean = Some((t.last_use, i));
            }
        }
        match (best_clean, best_dirty) {
            (Some((_, i)), _) => i,
            (None, Some((_, i))) => i,
            (None, None) => s,
        }
    }

    /// Callers never pass a live dirty victim (it is written back, or
    /// refused, first).
    fn fill(&mut self, i: usize, block: u64, src: &[u8], dirty: bool) {
        self.fill_at(i, block, src, dirty, self.epoch);
    }

    /// [`fill`](Self::fill) into `epoch` (the current one, or the one after
    /// it for an ahead write).
    fn fill_at(&mut self, i: usize, block: u64, src: &[u8], dirty: bool, epoch: u64) {
        self.line_mut(i).copy_from_slice(src);
        let dseq = if dirty { self.next_dseq() } else { 0 };
        self.tags[i] = Tag { block, epoch, last_use: 0, gen: self.gen, dirty, dseq, shadow: false, away: false };
        if dirty { self.ndirty += 1; }
        self.touch(i);
    }

    fn next_dseq(&mut self) -> u64 {
        self.dseq = self.dseq.wrapping_add(1);
        self.dseq
    }

    /// Write dirty line `i` to the device, keeping the epoch rule: if a
    /// line of an older epoch was written since the last flush, flush first.
    fn write_line<D: BlockIo>(&mut self, dev: &mut D, i: usize) -> Result<(), IoError<D::FlushErr>> {
        let t = self.tags[i];
        let lba = self.lba_of(t.block).ok_or(IoError::Range)?;
        if let Some(lo) = self.pending_lo {
            if lo < t.epoch {
                dev.flush().map_err(IoError::Flush)?;
                self.pending_lo = None;
                self.stats.ordering_flushes = self.stats.ordering_flushes.saturating_add(1);
            }
        }
        let n = self.sectors();
        let b = self.block;
        dev.write(lba, n, &self.data[i * b..(i + 1) * b]).map_err(|()| IoError::Io)?;
        self.tags[i].dirty = false;
        self.ndirty -= 1;
        if self.tags[i].shadow {
            if self.tags[i].away { self.naway -= 1; }
            self.tags[i] = EMPTY_TAG;
        }
        self.pending_lo = Some(self.pending_lo.map_or(t.epoch, |lo| lo.min(t.epoch)));
        self.stats.writebacks = self.stats.writebacks.saturating_add(1);
        Ok(())
    }

    /// Make room for `block` and return the line to use, writing a dirty
    /// victim back first.
    fn make_room<D: BlockIo>(&mut self, dev: &mut D, block: u64) -> Result<usize, IoError<D::FlushErr>> {
        let v = self.pick_victim(block);
        if self.live(v) && self.tags[v].dirty {
            // The set's oldest-epoch dirty line. Other sets may hold older
            // epochs: those go out first, so the epoch rule holds whichever
            // set the victim is in.
            self.write_back_before(dev, self.tags[v].epoch)?;
            self.write_line(dev, v)?;
        }
        Ok(v)
    }

    /// Read `block` into `dst` (exactly one block), from the cache or the
    /// device.
    pub fn read<D: BlockIo>(&mut self, dev: &mut D, block: u64, dst: &mut [u8]) -> Result<(), IoError<D::FlushErr>> {
        if dst.len() != self.block {
            return Err(IoError::Range);
        }
        if self.lookup(block, dst) {
            return Ok(());
        }
        let lba = self.lba_of(block).ok_or(IoError::Range)?;
        dev.read(lba, self.sectors(), dst).map_err(|()| IoError::Io)?;
        self.stats.misses = self.stats.misses.saturating_add(1);
        if self.lines == 0 {
            return Ok(());
        }
        let v = self.make_room(dev, block)?;
        self.fill(v, block, dst, false);
        Ok(())
    }

    /// Write `src` (exactly one block) as `block`, by the cache's mode.
    pub fn write<D: BlockIo>(&mut self, dev: &mut D, block: u64, src: &[u8]) -> Result<(), IoError<D::FlushErr>> {
        if src.len() != self.block {
            return Err(IoError::Range);
        }
        let lba = self.lba_of(block).ok_or(IoError::Range)?;
        self.wseq = self.wseq.wrapping_add(1);
        if self.mode == Mode::WriteThrough || self.lines == 0 {
            dev.write(lba, self.sectors(), src).map_err(|()| IoError::Io)?;
            if let Some(i) = self.find(block) {
                self.line_mut(i).copy_from_slice(src);
            }
            return Ok(());
        }
        if let Some(i) = self.find(block) {
            // A line written ahead (`write_dirty_ahead`): this write joins
            // its epoch, which closes the current one first.
            if self.tags[i].dirty && self.tags[i].epoch > self.epoch {
                self.epoch = self.tags[i].epoch;
            }
            // Re-dirtying a line that belongs to an older, still-unwritten
            // epoch: write the old contents first, so the older epoch is
            // complete on the device before this block moves forward.
            if self.tags[i].dirty && self.tags[i].epoch < self.epoch {
                self.write_back_before(dev, self.tags[i].epoch)?;
                self.write_line(dev, i)?;
            }
            self.line_mut(i).copy_from_slice(src);
            if !self.tags[i].dirty { self.ndirty += 1; }
            self.tags[i].dirty = true;
            self.tags[i].epoch = self.epoch;
            self.tags[i].dseq = self.next_dseq();
            self.touch(i);
            return Ok(());
        }
        let v = self.make_room(dev, block)?;
        self.fill(v, block, src, true);
        Ok(())
    }

    /// Write-back, split path: dirty `block`'s line with `src` (one block)
    /// WITHOUT any device I/O. See the module doc's "Write-back with the
    /// owner's lock released across the device".
    ///
    /// [`Dirty::NeedWriteback`]`(e)` when the line holds unwritten contents
    /// of an older epoch `e` (overwriting them would let the newer contents
    /// reach the device in the older epoch's place), or when the block's set
    /// has no clean or empty line (the set's oldest dirty epoch is `e`).
    /// Nothing changed; the owner writes back through `e` and calls again.
    ///
    /// A write-through cache answers like [`update_if_present`]: it never
    /// keeps a dirty line, so the owner writes the device itself.
    ///
    /// [`update_if_present`]: Self::update_if_present
    pub fn write_dirty(&mut self, block: u64, src: &[u8]) -> Dirty {
        self.write_dirty_in(block, src, false)
    }

    /// [`write_dirty`](Self::write_dirty) into the epoch AFTER the current
    /// one, without closing the current one (wave 15, FW): the block reaches
    /// the device after every block of the current epoch, including those
    /// written after this call, until the next [`barrier`](Self::barrier),
    /// which closes both. FAT32 puts a file's directory entry here: the
    /// writes of one open file then share one epoch for their data and
    /// chain, and the entry naming them is one line, rewritten in place and
    /// written once.
    ///
    /// The epoch rule still holds when a write-back takes this line before
    /// the current epoch is closed (`NeedWriteback` of it, another reader of
    /// the medium): the current epoch's lines written so far go first, a
    /// flush follows (`pending_lo`), and a current-epoch line dirtied later
    /// is written in a later pass; the entry depends only on lines dirtied
    /// before it. A plain write of a line held ahead joins that epoch.
    pub fn write_dirty_ahead(&mut self, block: u64, src: &[u8]) -> Dirty {
        self.write_dirty_in(block, src, true)
    }

    fn write_dirty_in(&mut self, block: u64, src: &[u8], ahead: bool) -> Dirty {
        if src.len() != self.block || self.lines == 0 || self.mode == Mode::WriteThrough {
            return Dirty::Uncached;
        }
        let first = self.ndirty == 0;
        let mut te = if ahead { self.epoch.saturating_add(1) } else { self.epoch };
        if let Some(i) = self.find(block) {
            let t = self.tags[i];
            if t.dirty && t.epoch > te {
                // Held ahead: a plain write joins its epoch (the current one
                // closes); an ahead write already targets it.
                te = t.epoch;
                if !ahead { self.epoch = te; }
            }
            if ahead { self.ahead = self.ahead.max(te); }
            if t.dirty && t.epoch < te && !cfg!(feature = "wb-epoch-merge-canary") {
                // Keep the older epoch's contents as a shadow for write-back
                // and put the new contents in another line of the set — no
                // I/O. Without a clean or empty line to take, write back.
                if cfg!(feature = "wb-no-shadow-canary") {
                    return Dirty::NeedWriteback(t.epoch);
                }
                let v = self.pick_victim(block);
                if v != i && !(self.live(v) && self.tags[v].dirty) {
                    self.wseq = self.wseq.wrapping_add(1);
                    self.tags[i].shadow = true;
                    self.fill_at(v, block, src, true, te);
                    return Dirty::Done { first };
                }
                // The set is all dirty (often: versions of this very block,
                // the journal sector's). Park the old contents in a free line
                // of another set and update this line in place.
                let Some(w) = self.free_line_elsewhere(block) else {
                    return Dirty::NeedWriteback(t.epoch);
                };
                self.wseq = self.wseq.wrapping_add(1);
                let b = self.block;
                self.data.copy_within(i * b..(i + 1) * b, w * b);
                self.tags[w] = Tag { shadow: true, away: true, ..t };
                self.naway += 1;
                self.ndirty += 1;
                self.line_mut(i).copy_from_slice(src);
                self.tags[i].epoch = te;
                self.tags[i].dseq = self.next_dseq();
                self.touch(i);
                return Dirty::Done { first };
            }
            self.wseq = self.wseq.wrapping_add(1);
            self.line_mut(i).copy_from_slice(src);
            if !t.dirty { self.ndirty += 1; }
            self.tags[i].dirty = true;
            self.tags[i].epoch = te;
            self.tags[i].dseq = self.next_dseq();
            self.touch(i);
            return Dirty::Done { first };
        }
        let v = self.pick_victim(block);
        if self.live(v) && self.tags[v].dirty {
            return Dirty::NeedWriteback(self.tags[v].epoch);
        }
        if ahead { self.ahead = self.ahead.max(te); }
        self.wseq = self.wseq.wrapping_add(1);
        self.fill_at(v, block, src, true, te);
        Dirty::Done { first }
    }

    /// Copy the next run to write back into `buf` and describe it, or `None`
    /// when no dirty line of an epoch `<= upto` is left.
    ///
    /// The run starts at the lowest dirty block of the oldest dirty epoch and
    /// takes every following consecutive block dirty in that SAME epoch, up
    /// to `max_blocks` and to what `buf` holds. A later epoch's block ends
    /// the run: it may only reach the device after this epoch is flushed.
    /// O(lines) for the start, O(ways) per further block. Lines stay dirty
    /// until [`checkin`](Self::checkin).
    pub fn checkout_run(&mut self, upto: u64, max_blocks: usize, buf: &mut [u8]) -> Option<Run> {
        if self.ndirty == 0 || self.lines == 0 {
            return None;
        }
        let g = self.gen;
        let mut start: Option<((u64, u64), usize)> = None;
        for (i, t) in self.tags[..self.lines].iter().enumerate() {
            if t.gen == g && t.dirty {
                let k = (t.epoch, t.block);
                if start.map_or(true, |(b, _)| k < b) { start = Some((k, i)); }
            }
        }
        let ((epoch, block), idx0) = start?;
        if epoch > upto {
            return None;
        }
        let lba = self.lba_of(block)?;
        let b = self.block;
        let cap = max_blocks.min(buf.len() / b).max(1);
        if buf.len() < b {
            return None;
        }
        let mut n = 0usize;
        while n < cap {
            let blk = match block.checked_add(n as u64) { Some(x) => x, None => break };
            let i = if n == 0 {
                idx0
            } else {
                match self.find_dirty_epoch(blk, epoch) {
                    Some(i) => i,
                    None => break,
                }
            };
            if n > 0 && cfg!(feature = "wb-no-coalesce-canary") { break; }
            buf[n * b..(n + 1) * b].copy_from_slice(&self.data[i * b..(i + 1) * b]);
            n += 1;
        }
        let flush_first = !cfg!(feature = "wb-no-ordering-flush-canary")
            && self.pending_lo.map_or(false, |lo| lo < epoch);
        Some(Run {
            block,
            lba,
            blocks: n as u32,
            sectors: n as u32 * self.sectors(),
            epoch,
            flush_first,
            seq: self.dseq,
            idx0,
        })
    }

    /// The owner wrote `run` (`ok`) or failed to. On success each of its
    /// lines that was not dirtied again after the checkout is clean, and the
    /// run's epoch is pending a flush; on failure nothing changes (the lines
    /// stay dirty, and the owner reports the error).
    pub fn checkin(&mut self, run: &Run, ok: bool) {
        if !ok {
            return;
        }
        let g = self.gen;
        for k in 0..run.blocks as u64 {
            let blk = run.block + k;
            let i = if k == 0 {
                let t = self.tags[run.idx0];
                if t.gen == g && t.block == blk && t.dirty && t.epoch == run.epoch {
                    Some(run.idx0)
                } else {
                    self.find_dirty_epoch(blk, run.epoch)
                }
            } else {
                self.find_dirty_epoch(blk, run.epoch)
            };
            if let Some(i) = i {
                let t = self.tags[i];
                if t.dseq <= run.seq {
                    self.ndirty -= 1;
                    self.stats.writebacks = self.stats.writebacks.saturating_add(1);
                    if t.shadow {
                        if t.away { self.naway -= 1; }
                        self.tags[i] = EMPTY_TAG;
                    } else {
                        self.tags[i].dirty = false;
                    }
                }
            }
        }
        self.pending_lo = Some(self.pending_lo.map_or(run.epoch, |lo| lo.min(run.epoch)));
    }

    /// The owner flushed the device to keep the epoch rule (`flush_first`).
    pub fn note_ordering_flush(&mut self) {
        self.pending_lo = None;
        self.stats.ordering_flushes = self.stats.ordering_flushes.saturating_add(1);
    }

    /// Close the current epoch, and the one after it if a line was written
    /// ahead into it: every write after this is ordered after every write
    /// before it. Returns the highest epoch closed (what a write-back must
    /// reach to make everything before the barrier durable).
    pub fn barrier(&mut self) -> u64 {
        let top = self.epoch.max(self.ahead);
        self.epoch = top.saturating_add(1);
        top
    }

    /// Write every dirty line, oldest epoch first, without the final flush.
    /// A no-op (no I/O at all) when nothing is dirty — always the case in
    /// write-through mode.
    pub fn write_back_all<D: BlockIo>(&mut self, dev: &mut D) -> Result<(), IoError<D::FlushErr>> {
        self.write_back_before(dev, u64::MAX)
    }

    /// Write every dirty line of an epoch older than `epoch`, oldest first
    /// (`u64::MAX`: every dirty line).
    fn write_back_before<D: BlockIo>(&mut self, dev: &mut D, epoch: u64) -> Result<(), IoError<D::FlushErr>> {
        if self.ndirty == 0 {
            return Ok(());
        }
        loop {
            // Oldest epoch, then lowest block: a deterministic order.
            let mut next: Option<((u64, u64), usize)> = None;
            let g = self.gen;
            for (i, t) in self.tags[..self.lines].iter().enumerate() {
                if t.gen == g && t.dirty && (epoch == u64::MAX || t.epoch < epoch) {
                    let k = (t.epoch, t.block);
                    if next.map_or(true, |(b, _)| k < b) { next = Some((k, i)); }
                }
            }
            match next {
                Some((_, i)) => self.write_line(dev, i)?,
                None => return Ok(()),
            }
        }
    }

    /// Write every dirty line, then flush the device.
    pub fn sync<D: BlockIo>(&mut self, dev: &mut D) -> Result<(), IoError<D::FlushErr>> {
        self.write_back_all(dev)?;
        dev.flush().map_err(IoError::Flush)?;
        self.pending_lo = None;
        Ok(())
    }

    /// Record that the owner flushed the device itself (the split path):
    /// nothing written before this point is pending any more.
    pub fn note_flushed(&mut self) {
        self.pending_lo = None;
    }
}
