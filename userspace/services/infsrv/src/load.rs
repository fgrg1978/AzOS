// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Loading a signed `.MBL` bundle (`azos_ml::bundle`) into the service.
//!
//! The file is read once, front to back, through a small bounce buffer: a
//! file system with no seek and a board with a few kilobytes to spare both
//! cost nothing here. What is kept:
//!
//! * the **manifest**, once the signature over its exact bytes verifies
//!   (`Manifest::open` reads nothing but the length before that), reduced to
//!   a [`Model`]: the identity of the model, the tensor sizes and the variants
//!   in the publisher's fallback order with their signed cost rows;
//! * the **blob** of each variant whose backend this machine has and that
//!   fits what is left of the arena. A variant for another backend is not
//!   copied: its bytes go through the bounce buffer and are dropped.
//!
//! A blob that is short, whose SHA-256 is not the manifest's, or that is not a
//! model of the manifest's sizes leaves its variant **unavailable** (no
//! arena span): the broker passes it over as if its backend were absent, and
//! the console says which and why. The bundle as a whole is refused only when
//! the manifest is.

use azos_ml::bundle::{self, backend_bit, Manifest, Variant, BACKEND_GGUF, HEADER_BYTES, MAX_VARIANTS, SIG_BYTES};

/// The backends this service runs in process: the CPU's GGUF kernels.
pub const BACKENDS: u32 = 1 << BACKEND_GGUF;

/// Bytes of the bounce buffer a bundle streams through.
pub const CHUNK: usize = 512;

/// Alignment of a blob in the arena (GGUF tensor data is read as words).
const ARENA_ALIGN: usize = 8;

/// A place in the arena: `off .. off + len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub off: u32,
    pub len: u32,
}

/// The arena the blobs of every loaded bundle live in. Nothing is freed
/// piecemeal: a bundle replaced at run time is a restart of the service, and
/// when the storage itself is given up ([`Arena::reset`]) every span goes with
/// it.
pub struct Arena<'a> {
    buf: &'a mut [u8],
    used: usize,
}

impl<'a> Arena<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Arena { buf, used: 0 }
    }

    /// Point the arena at other storage, empty: every [`Span`] handed out so
    /// far is void (the models that hold them are the caller's to forget).
    /// `&mut []` is the arena of a service that has no storage now.
    pub fn reset(&mut self, buf: &'a mut [u8]) {
        self.buf = buf;
        self.used = 0;
    }

    /// Bytes not yet reserved (before alignment).
    pub fn free(&self) -> usize {
        self.buf.len() - self.used
    }

    fn alloc(&mut self, len: usize) -> Option<Span> {
        let off = self.used.checked_add(ARENA_ALIGN - 1)? / ARENA_ALIGN * ARENA_ALIGN;
        let end = off.checked_add(len)?;
        if end > self.buf.len() || u32::try_from(end).is_err() {
            return None;
        }
        self.used = end;
        Some(Span { off: off as u32, len: len as u32 })
    }

    /// The bytes of `s`.
    pub fn bytes(&self, s: Span) -> &[u8] {
        &self.buf[s.off as usize..(s.off + s.len) as usize]
    }

    fn bytes_mut(&mut self, s: Span) -> &mut [u8] {
        &mut self.buf[s.off as usize..(s.off + s.len) as usize]
    }
}

/// One variant of a [`Model`], in fallback order.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    /// The signed cost row and where the blob lay in the file.
    pub v: Variant,
    /// Where the blob is in the arena; `None`: unavailable (the reason is in
    /// the [`Report`]).
    pub span: Option<Span>,
}

/// A loaded, verified bundle.
#[derive(Clone, Copy, Debug)]
pub struct Model {
    /// `azos_devif::infer::model_ref` of the manifest's digest: the name a
    /// client calls the model by.
    pub model_ref: u64,
    pub name: [u8; bundle::NAME_BYTES],
    pub in_bytes: u32,
    pub out_bytes: u32,
    pub n: usize,
    /// The variants in the publisher's order of preference.
    pub slots: [Slot; MAX_VARIANTS],
}

impl Model {
    /// The model's name.
    pub fn name(&self) -> &str {
        let used = self.name.iter().position(|&c| c == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..used]).unwrap_or("")
    }

    /// The variants in fallback order.
    pub fn variants(&self) -> &[Slot] {
        &self.slots[..self.n]
    }
}

/// Why a bundle was not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The manifest or its signature is not a bundle's, or does not verify.
    Bundle(bundle::Error),
    /// The file ended inside the manifest.
    Truncated,
}

/// What became of one variant's blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    /// In the arena, digest verified, a model of the manifest's sizes.
    Loaded,
    /// For a backend this machine does not have: skipped.
    OtherBackend,
    /// The arena had no room.
    NoRoom,
    /// The file ended before the blob did.
    Short,
    /// The blob's SHA-256 is not the manifest's.
    BadDigest,
    /// The blob is not a model of the manifest's tensor sizes.
    BadModel,
}

/// The outcome of a load: the model and the fate of each variant, in the
/// order of the manifest's table (`Variant::id` names them).
pub struct Report {
    pub model: Model,
    pub fates: [(u32, Fate); MAX_VARIANTS],
}

/// Fill `dst` from `read` (which returns 0 at the end of the file); how many
/// bytes arrived.
fn fill(read: &mut dyn FnMut(&mut [u8]) -> usize, dst: &mut [u8]) -> usize {
    let mut got = 0;
    while got < dst.len() {
        let n = read(&mut dst[got..]);
        if n == 0 {
            break;
        }
        got += n;
    }
    got
}

/// Load the bundle `read` streams. `verify(manifest, signature)` is the
/// Ed25519 check against the trusted key and `sha256` the digest, both the
/// caller's (the bundle crate has no dependencies). `fits(blob, in, out)` says
/// whether a blob is a model of the sizes the manifest declares.
pub fn load(
    read: &mut dyn FnMut(&mut [u8]) -> usize,
    arena: &mut Arena<'_>,
    verify: impl FnOnce(&[u8], &[u8; SIG_BYTES]) -> bool,
    sha256: fn(&[u8]) -> [u8; 32],
    fits: fn(&[u8], u32, u32) -> bool,
) -> Result<Report, LoadError> {
    // The manifest: its length from the first bytes, then all of it and the
    // signature.
    let mut mf = [0u8; bundle::manifest_len(MAX_VARIANTS) + SIG_BYTES];
    if fill(read, &mut mf[..HEADER_BYTES]) < HEADER_BYTES {
        return Err(LoadError::Truncated);
    }
    let total = bundle::signed_len(&mf[..HEADER_BYTES]).map_err(LoadError::Bundle)?;
    if fill(read, &mut mf[HEADER_BYTES..total]) < total - HEADER_BYTES {
        return Err(LoadError::Truncated);
    }
    let m = Manifest::open(&mf[..total], verify).map_err(LoadError::Bundle)?;

    let mut model = Model {
        model_ref: azos_devif::infer::model_ref(&m.digest(sha256)),
        name: [0; bundle::NAME_BYTES],
        in_bytes: m.in_bytes(),
        out_bytes: m.out_bytes(),
        n: m.n_variants(),
        slots: [Slot { v: m.variant(0), span: None }; MAX_VARIANTS],
    };
    model.name[..m.name().len()].copy_from_slice(m.name().as_bytes());
    for (i, v) in m.fallback().enumerate() {
        model.slots[i].v = v;
    }

    // Reserve the arena for every variant the machine can run, in fallback
    // order (the publisher's first choice gets the room first).
    let mut fates = [(0u32, Fate::OtherBackend); MAX_VARIANTS];
    for (i, f) in fates.iter_mut().enumerate().take(model.n) {
        let v = model.slots[i].v;
        f.0 = v.id;
        if BACKENDS & backend_bit(v.backend) == 0 {
            continue;
        }
        match usize::try_from(v.blob_len).ok().and_then(|len| arena.alloc(len)) {
            Some(s) => {
                model.slots[i].span = Some(s);
                f.1 = Fate::Loaded;
            }
            None => f.1 = Fate::NoRoom,
        }
    }

    // Stream the rest of the file once. Position `pos` is a file offset; a
    // chunk is copied into every reserved span it overlaps. Stop at the end of
    // the last blob wanted.
    let want_end = model.slots[..model.n]
        .iter()
        .filter(|s| s.span.is_some())
        .map(|s| s.v.blob_off + s.v.blob_len)
        .max()
        .unwrap_or(0);
    let mut copied = [0u64; MAX_VARIANTS];
    let mut pos = total as u64;
    let mut chunk = [0u8; CHUNK];
    while pos < want_end {
        let want = (want_end - pos).min(CHUNK as u64) as usize;
        let n = read(&mut chunk[..want]);
        if n == 0 {
            break;
        }
        for (i, s) in model.slots[..model.n].iter().enumerate() {
            let Some(span) = s.span else { continue };
            let (lo, hi) = (s.v.blob_off, s.v.blob_off + s.v.blob_len);
            let (from, to) = (pos.max(lo), (pos + n as u64).min(hi));
            if from < to {
                let dst = &mut arena.bytes_mut(span)[(from - lo) as usize..(to - lo) as usize];
                dst.copy_from_slice(&chunk[(from - pos) as usize..(to - pos) as usize]);
                copied[i] += to - from;
            }
        }
        pos += n as u64;
    }

    // What arrived is checked against the manifest before it is believed.
    for i in 0..model.n {
        let Some(span) = model.slots[i].span else { continue };
        let v = model.slots[i].v;
        let fate = if copied[i] != v.blob_len {
            Fate::Short
        } else if v.check_blob(arena.bytes(span), sha256).is_err() {
            Fate::BadDigest
        } else if !fits(arena.bytes(span), model.in_bytes, model.out_bytes) {
            Fate::BadModel
        } else {
            Fate::Loaded
        };
        if fate != Fate::Loaded {
            model.slots[i].span = None;
        }
        fates[i].1 = fate;
    }
    Ok(Report { model, fates })
}
