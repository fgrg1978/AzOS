// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The verified-image digest cache (wave 14, SPAWNCACHE).
//!
//! Every spawn and exec by path hashes the whole image (SHA-256) to pick its
//! seccomp profile and topology row: about 750k instructions for a 20 KiB
//! image on rv64, most of a `spawn+wait`. This table remembers the digest of
//! bytes it has hashed, keyed by what the file system promises identifies
//! those bytes ([`ContentStamp`]: the backend, its write epoch, the file's
//! start cluster and size). FAT32's epoch moves on every write of the volume
//! (its own, an observed external one: USB mass storage, OTA, the reserved
//! tail, `SYS_DISK_WRITE`), every mount and every unmount, and never repeats,
//! so an equal stamp means no byte of the volume changed since the digest
//! was taken. A path alone is never a key; a backend without stamps (the
//! ramfs, tmpfs) is never cached.
//!
//! [`read_verified`] is the one reader. On a miss it hashes each run of the
//! image as it lands in the buffer (no second pass) and remembers the digest
//! only when the stamp before the read equals the stamp after it. On a hit it
//! reads without hashing and takes the cached digest only when the stamp
//! after the read is still the stamp it looked up; otherwise it hashes what
//! it read. Either way the digest describes the bytes in the buffer, which
//! are the bytes loaded.
//!
//! Stale entries go when a lookup on the same backend carries a later epoch.
//!
//! **Kept frames** (Kconfig `EXEC_IMAGE_CACHE_KB`, 0 = off). A spawn that
//! loaded verified bytes under a stamp that held keeps the image's frames
//! (`azos_mm::image_frames`: executable pages by reference, the rest as
//! templates) under the same stamp; a later spawn of the same stamp maps
//! them and reads nothing. A lookup pins the entry while the caller builds
//! from it ([`Pinned`]); an entry evicted or found stale while pinned is
//! released by its last unpin. A frame a running task maps outlives the
//! entry (its own reference), which is safe: it was verified.

use azos_sync::SpinLock;
use crate::file_ops::{ContentStamp, FileOps};

/// Digests remembered, least recently used replaced first.
pub const DIGEST_SLOTS: usize = 16;

#[derive(Clone, Copy)]
struct Slot {
    stamp: ContentStamp,
    digest: [u8; 32],
    tick: u32,
    live: bool,
}

const EMPTY: Slot = Slot {
    stamp: ContentStamp { fs: 0, epoch: 0, id: 0, size: 0 },
    digest: [0u8; 32],
    tick: 0,
    live: false,
};

struct Table {
    slots: [Slot; DIGEST_SLOTS],
    tick: u32,
}

static TABLE: SpinLock<Table> = SpinLock::new(Table { slots: [EMPTY; DIGEST_SLOTS], tick: 0 });

/// Two stamps name the same bytes. Gate canary `digest-cache-stale-canary`:
/// the epoch is ignored, so a file rewritten in place (same cluster, same
/// size) keeps the old digest.
#[inline]
fn same_bytes(a: &ContentStamp, b: &ContentStamp) -> bool {
    if cfg!(feature = "digest-cache-stale-canary") {
        return a.fs == b.fs && a.id == b.id && a.size == b.size;
    }
    a == b
}

/// The digest remembered for exactly the bytes `stamp` names. Drops every
/// entry of the same backend from an earlier epoch on the way.
pub fn digest_for(stamp: &ContentStamp) -> Option<[u8; 32]> {
    let mut t = TABLE.lock();
    t.tick = t.tick.wrapping_add(1);
    let tick = t.tick;
    let mut hit = None;
    for s in t.slots.iter_mut() {
        if !s.live { continue; }
        if same_bytes(&s.stamp, stamp) {
            s.tick = tick;
            hit = Some(s.digest);
        } else if s.stamp.fs == stamp.fs && s.stamp.epoch < stamp.epoch {
            s.live = false;
        }
    }
    hit
}

/// Remember `digest` for the bytes `stamp` names (replacing the least
/// recently used entry when the table is full).
pub fn remember(stamp: &ContentStamp, digest: &[u8; 32]) {
    let mut t = TABLE.lock();
    t.tick = t.tick.wrapping_add(1);
    let tick = t.tick;
    // The same bytes' entry, else a free slot, else the least recently used.
    let pick = t.slots.iter().position(|s| s.live && s.stamp == *stamp)
        .or_else(|| t.slots.iter().position(|s| !s.live))
        .unwrap_or_else(|| {
            let mut lru = 0usize;
            for (i, s) in t.slots.iter().enumerate() {
                if tick.wrapping_sub(s.tick) > tick.wrapping_sub(t.slots[lru].tick) { lru = i; }
            }
            lru
        });
    t.slots[pick] = Slot { stamp: *stamp, digest: *digest, tick, live: true };
}

/// Forget everything (host tests; a medium swap is an epoch move already).
pub fn clear() {
    let mut t = TABLE.lock();
    for s in t.slots.iter_mut() { s.live = false; }
}

/// Live entries (host tests and diagnostics).
pub fn live_entries() -> usize {
    TABLE.lock().slots.iter().filter(|s| s.live).count()
}

/// What [`read_verified`] read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Bytes of the image now at the start of the buffer.
    pub total: usize,
    /// Their SHA-256.
    pub digest: [u8; 32],
    /// The digest came from the cache (no hash pass).
    pub hit: bool,
    /// The stamp the bytes were read under, when it held across the read.
    pub stamp: Option<ContentStamp>,
}

/// Read the whole image at `path` into `buf` (it must fit, as
/// [`FileOps::read_whole`] requires) and answer its digest: from the cache
/// when the bytes are the ones it was taken from, else hashed in the same
/// pass as the read. `Err(-1)` when nothing was read.
pub fn read_verified(ops: &dyn FileOps, path: &[u8], buf: &mut [u8]) -> Result<Verified, i64> {
    let before = ops.content_stamp(path);
    let known = before.as_ref().and_then(digest_for);
    let mut h = azos_sched::seccomp::ImageHasher::new();
    let total = if known.is_some() {
        ops.read_whole(path, buf)
    } else {
        ops.read_whole_with(path, buf, &mut |run| h.update(run))
    };
    if total == 0 { return Err(-1); }
    // The stamp must hold across the read: the bytes in `buf` are then the
    // bytes `before` names. Gate canary `digest-recheck-canary`: not asked.
    let held = match before {
        Some(b) if b.size == total as u64 => {
            cfg!(feature = "digest-recheck-canary") || ops.content_stamp(path) == Some(b)
        }
        _ => false,
    };
    let stamp = if held { before } else { None };
    match known {
        Some(digest) if held => Ok(Verified { total, digest, hit: true, stamp }),
        // The file changed while it was read: hash what was read.
        Some(_) => Ok(Verified {
            total, digest: azos_sched::seccomp::image_digest(&buf[..total]), hit: false, stamp,
        }),
        None => {
            let digest = h.finalize();
            if let Some(s) = stamp.as_ref() { remember(s, &digest); }
            Ok(Verified { total, digest, hit: false, stamp })
        }
    }
}

// ── Kept frames ──────────────────────────────────────────────────────────────

use azos_mm::image_frames::{ImagePages, KeptImage};

/// Kconfig `EXEC_IMAGE_CACHE_KB`, in frames: every frame the kept images
/// hold together (their records, templates and shared frames).
pub const FRAME_BUDGET: u32 =
    (azos_limits::EXEC_IMAGE_CACHE_KB as u64 * 1024 / azos_arch_api::PAGE_SIZE as u64) as u32;

/// Images kept at once.
pub const FRAME_SLOTS: usize = 8;

#[derive(Clone, Copy)]
struct KeptSlot {
    stamp: ContentStamp,
    digest: [u8; 32],
    pages: ImagePages,
    kept: KeptImage,
    tick: u32,
    pins: u32,
    /// Evicted or stale: no new pin; released by the last unpin.
    dead: bool,
}

struct Frames {
    slots: [Option<KeptSlot>; FRAME_SLOTS],
    held: u32,
    tick: u32,
}

static FRAMES: SpinLock<Frames> =
    SpinLock::new(Frames { slots: [None; FRAME_SLOTS], held: 0, tick: 0 });

impl Frames {
    /// Mark slot `i` dead; release it now if nobody holds a pin.
    fn kill(&mut self, i: usize) {
        if let Some(k) = self.slots[i].as_mut() {
            k.dead = true;
            if k.pins == 0 {
                let pages = k.pages;
                self.held = self.held.saturating_sub(pages.frames_held());
                self.slots[i] = None;
                azos_mm::image_frames::release(pages);
            }
        }
    }
}

/// A kept image, pinned: its frames stay while this lives.
pub struct Pinned {
    slot: usize,
    pub digest: [u8; 32],
    pub pages: ImagePages,
    pub kept: KeptImage,
}

impl Drop for Pinned {
    fn drop(&mut self) {
        let mut f = FRAMES.lock();
        let i = self.slot;
        let release = match f.slots[i].as_mut() {
            Some(k) => {
                k.pins = k.pins.saturating_sub(1);
                k.dead && k.pins == 0
            }
            None => false,
        };
        if release { f.kill(i); }
    }
}

/// The kept image of exactly the bytes `stamp` names, pinned. Kept images
/// of the same backend from an earlier epoch are dropped on the way.
pub fn frames_for(stamp: &ContentStamp) -> Option<Pinned> {
    if FRAME_BUDGET == 0 { return None; }
    let mut f = FRAMES.lock();
    f.tick = f.tick.wrapping_add(1);
    let tick = f.tick;
    let mut hit = None;
    for i in 0..FRAME_SLOTS {
        let Some(k) = f.slots[i].as_mut() else { continue };
        if k.dead { continue; }
        if hit.is_none() && same_bytes(&k.stamp, stamp) {
            k.tick = tick;
            k.pins += 1;
            hit = Some(Pinned { slot: i, digest: k.digest, pages: k.pages, kept: k.kept });
        } else if k.stamp.fs == stamp.fs && k.stamp.epoch < stamp.epoch {
            f.kill(i);
        }
    }
    hit
}

/// Keep `pages` for the bytes `stamp` names (verified as `digest`), within
/// [`FRAME_BUDGET`], evicting the least recently used unpinned images. The
/// pages are released instead when they do not fit or the bytes are kept
/// already.
pub fn keep_frames(stamp: &ContentStamp, digest: &[u8; 32], pages: ImagePages, kept: KeptImage) {
    let mut f = FRAMES.lock();
    let need = pages.frames_held();
    let dup = f.slots.iter().flatten().any(|k| !k.dead && k.stamp == *stamp);
    if dup || need > FRAME_BUDGET {
        drop(f);
        azos_mm::image_frames::release(pages);
        return;
    }
    loop {
        let free = f.slots.iter().position(|k| k.is_none());
        if f.held + need <= FRAME_BUDGET {
            if let Some(i) = free {
                f.tick = f.tick.wrapping_add(1);
                let tick = f.tick;
                f.slots[i] = Some(KeptSlot {
                    stamp: *stamp, digest: *digest, pages, kept, tick, pins: 0, dead: false,
                });
                f.held += need;
                return;
            }
        }
        // Evict the least recently used live, unpinned image.
        let tick = f.tick;
        let victim = (0..FRAME_SLOTS)
            .filter(|&i| f.slots[i].is_some_and(|k| !k.dead && k.pins == 0))
            .max_by_key(|&i| tick.wrapping_sub(f.slots[i].map_or(0, |k| k.tick)));
        match victim {
            Some(i) => f.kill(i),
            None => {
                drop(f);
                azos_mm::image_frames::release(pages);
                return;
            }
        }
    }
}

/// Frames the kept images hold, and how many are kept (host tests and
/// diagnostics).
pub fn frames_held() -> (u32, usize) {
    let f = FRAMES.lock();
    (f.held, f.slots.iter().flatten().count())
}

/// Forget every kept image WITHOUT releasing its frames. **Host test
/// harnesses only**: their page allocator is re-initialised between tests,
/// so frames recorded by an earlier test belong to nobody any more.
#[cfg(not(target_os = "none"))]
pub fn shim_forget_frames() {
    let mut f = FRAMES.lock();
    f.slots = [None; FRAME_SLOTS];
    f.held = 0;
}

/// Release every unpinned kept image (host tests).
pub fn drop_frames() {
    let mut f = FRAMES.lock();
    for i in 0..FRAME_SLOTS { f.kill(i); }
}
