// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The signed model bundle, `.MBL`: one model, every way the machine may run
//! it, and what each way costs.
//!
//! A bundle is a **manifest**, its **signature** and the **variant blobs**:
//!
//! ```text
//! 0                          manifest (HEADER_BYTES + n * VARIANT_BYTES)   <- signed
//! manifest_len               signature: a `DSIG` container (SIG_BYTES) over the manifest
//! 8-aligned, in any order    variant blobs (a GGUF file, a SPIR-V module, a vendor blob)
//! ```
//!
//! The manifest names the model, the sizes of its input and output tensors, and
//! for each variant: the backend it runs on ([`BACKEND_GGUF`] on the CPU through
//! this crate's engine, [`BACKEND_SPIRV`] on a GPU, [`BACKEND_VENDOR`] on an NPU),
//! where its blob lies, the blob's SHA-256, and the **cost table** row of the
//! variant: worst-case time (`wcet_us`), energy per run (`energy_uj`) and
//! working memory (`mem_bytes`). It ends with the **fallback list**, the
//! publisher's order of preference over all the variants. Everything a
//! scheduling decision reads is under the one signature, so a bundle cannot
//! claim a time or an energy its publisher did not sign, and the blobs are
//! authenticated by their digests in it: a service on a small board reads the
//! manifest (a few hundred bytes), verifies it, picks a variant and reads only
//! that variant's blob, hashing it as it goes.
//!
//! The signature covers the manifest's exact bytes, whose first four are the
//! magic: no `CAPS.TOML`, `CONFIG.INI` or GGUF file starts with it, so a
//! signature made for one of them is not a signature of a bundle. The bytes are
//! parsed **after** the signature verifies (`Manifest::open` takes the verifier
//! and does not hand out a manifest without calling it); the only field read
//! before is the manifest's length, bounds-checked against the one shape the
//! magic allows.
//!
//! The crate has no dependencies, so the verifier and the hash are the
//! caller's: the service passes `azos_topology::verify_signature` (which takes
//! the `DSIG` as it is) over the trusted key and `azos_crypto::sha256`. All integers are little-endian.
//!
//! The writer is `tools/image/make_mbl.py`; the one reader is the inference service
//! (`azos_devif::infer`).

/// The magic: the first four bytes of the manifest.
pub const MAGIC: [u8; 4] = *b"AZMB";
/// The only layout version.
pub const VERSION: u16 = 1;
/// Variants a bundle holds at most.
pub const MAX_VARIANTS: usize = 8;
/// Bytes of the manifest header, the fallback list included.
pub const HEADER_BYTES: usize = 56;
/// Bytes of one variant record.
pub const VARIANT_BYTES: usize = 72;
/// Bytes of the signature after the manifest: the `DSIG` container
/// (`azos_crypto::sig::DSIG_FILE_MAX`: 8 bytes of magic, algorithm id and
/// length, then the 64-byte Ed25519 signature; a test holds the two equal).
pub const SIG_BYTES: usize = 72;
/// Alignment of a blob's offset in the file.
pub const BLOB_ALIGN: u64 = 8;
/// Bytes of the model's name (ASCII, NUL-padded).
pub const NAME_BYTES: usize = 24;

/// Backend: a GGUF file the CPU runs with `azos_ml::ggml_nano`.
pub const BACKEND_GGUF: u32 = 1;
/// Backend: a SPIR-V compute module for a GPU.
pub const BACKEND_SPIRV: u32 = 2;
/// Backend: a vendor blob for an NPU.
pub const BACKEND_VENDOR: u32 = 3;

/// The bit of `backend` in [`Select::backends`].
pub const fn backend_bit(backend: u32) -> u32 {
    1 << backend
}

// Offsets in the header.
const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_NVAR: usize = 6;
const H_RESERVED: usize = 8;
const H_IN: usize = 12;
const H_OUT: usize = 16;
const H_LEN: usize = 20;
const H_NAME: usize = 24;
const H_FALLBACK: usize = 48;
// Offsets in a variant record.
const V_KIND: usize = 0;
const V_ID: usize = 4;
const V_OFF: usize = 8;
const V_LEN: usize = 16;
const V_WCET: usize = 24;
const V_ENERGY: usize = 28;
const V_MEM: usize = 32;
const V_RESERVED: usize = 36;
const V_SHA: usize = 40;

/// Why a bundle was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the manifest and its signature need.
    Short,
    /// The magic is not [`MAGIC`].
    Magic,
    /// The version is not [`VERSION`].
    Version,
    /// The signature does not verify. Nothing of the manifest was read past
    /// its length.
    Signature,
    /// The manifest is signed but is not a layout this reader accepts: a count
    /// out of range, a length that does not match the counts, a reserved field
    /// that is not zero, a fallback list that is not a permutation of the
    /// variants, a blob out of place or overlapping another, a name that is not
    /// ASCII, a zero size or worst-case time.
    Layout,
    /// A blob is not the length or the digest its variant says.
    Blob,
}

/// One variant: a way to run the model and what it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variant {
    /// `BACKEND_*`.
    pub backend: u32,
    /// The variant's name in the replies and the cost accounting; unique in
    /// the bundle.
    pub id: u32,
    /// Where the blob starts in the file.
    pub blob_off: u64,
    pub blob_len: u64,
    /// Signed worst-case run time, microseconds.
    pub wcet_us: u32,
    /// Signed energy of one run, microjoules.
    pub energy_uj: u32,
    /// Working memory the variant needs while it runs, bytes.
    pub mem_bytes: u32,
    /// SHA-256 of the blob.
    pub sha256: [u8; 32],
}

impl Variant {
    /// The blob, once its length and digest are the variant's. `blob` is
    /// exactly the bytes at `blob_off .. blob_off + blob_len` of the file.
    pub fn check_blob<'b>(&self, blob: &'b [u8], sha256: fn(&[u8]) -> [u8; 32]) -> Result<&'b [u8], Error> {
        if blob.len() as u64 != self.blob_len || sha256(blob) != self.sha256 {
            return Err(Error::Blob);
        }
        Ok(blob)
    }
}

/// What the service has to offer when it chooses a variant.
#[derive(Clone, Copy, Debug)]
pub struct Select {
    /// The backends present, [`backend_bit`] each.
    pub backends: u32,
    /// Working memory free now, bytes.
    pub mem_free: u32,
    /// Microseconds left to the caller's deadline; `None`: no deadline.
    pub budget_us: Option<u32>,
    /// Among the variants that fit, take the one of lowest signed energy
    /// (a tie goes to the earlier in the fallback list) instead of the first.
    pub low_energy: bool,
}

/// Why no variant fits. The reason is that of the variant that got furthest:
/// the checks run backend, then memory, then time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No variant runs on a backend that is present.
    NoBackend,
    /// A variant has its backend, but none has the memory free.
    NoMemory,
    /// A variant has backend and memory, but its signed worst case does not
    /// fit the time left.
    TooSlow,
}

/// A verified, validated manifest: the bytes are the signed ones and every
/// accessor reads inside them.
#[derive(Clone, Copy, Debug)]
pub struct Manifest<'a> {
    bytes: &'a [u8],
}

fn le16(b: &[u8], o: usize) -> u16 {
    let mut w = [0u8; 2];
    w.copy_from_slice(&b[o..o + 2]);
    u16::from_le_bytes(w)
}
fn le32(b: &[u8], o: usize) -> u32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(w)
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(w)
}

/// Bytes of the manifest of `n` variants.
pub const fn manifest_len(n: usize) -> usize {
    HEADER_BYTES + VARIANT_BYTES * n
}

/// The bytes the manifest and its signature take, read from the first bytes of
/// the file: magic and length only, nothing else is believed yet. A reader on
/// a small board calls it with the first [`HEADER_BYTES`], reads that many
/// bytes and opens the manifest with them.
pub fn signed_len(prefix: &[u8]) -> Result<usize, Error> {
    if prefix.len() < H_LEN + 4 {
        return Err(Error::Short);
    }
    if prefix[H_MAGIC..H_MAGIC + 4] != MAGIC {
        return Err(Error::Magic);
    }
    let len = le32(prefix, H_LEN) as usize;
    // The one shape the magic allows: a whole number of 1..=MAX_VARIANTS records.
    if len < manifest_len(1) || len > manifest_len(MAX_VARIANTS) || (len - HEADER_BYTES) % VARIANT_BYTES != 0 {
        return Err(Error::Layout);
    }
    Ok(len + SIG_BYTES)
}

impl<'a> Manifest<'a> {
    /// Verify and validate the manifest at the start of `file` (the whole
    /// bundle, or its first [`signed_len`] bytes). `verify(manifest, signature)`
    /// is the caller's check of the `DSIG` against its trusted key; it is called
    /// before any field but the length is read.
    pub fn open(file: &'a [u8], verify: impl FnOnce(&[u8], &[u8; SIG_BYTES]) -> bool) -> Result<Manifest<'a>, Error> {
        let total = signed_len(file)?;
        if file.len() < total {
            return Err(Error::Short);
        }
        let (bytes, rest) = file[..total].split_at(total - SIG_BYTES);
        let mut sig = [0u8; SIG_BYTES];
        sig.copy_from_slice(rest);
        if !verify(bytes, &sig) {
            return Err(Error::Signature);
        }
        let m = Manifest { bytes };
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<(), Error> {
        let b = self.bytes;
        let n = (b.len() - HEADER_BYTES) / VARIANT_BYTES;
        if le16(b, H_VERSION) != VERSION {
            return Err(Error::Version);
        }
        if usize::from(le16(b, H_NVAR)) != n || le32(b, H_RESERVED) != 0 || le32(b, H_IN) == 0 || le32(b, H_OUT) == 0 {
            return Err(Error::Layout);
        }
        // A name: printable ASCII, then NULs, not empty.
        let name = &b[H_NAME..H_NAME + NAME_BYTES];
        let used = name.iter().position(|&c| c == 0).unwrap_or(NAME_BYTES);
        if used == 0 || !name[..used].iter().all(|c| (0x21..=0x7E).contains(c)) || name[used..].iter().any(|&c| c != 0) {
            return Err(Error::Layout);
        }
        // The fallback list: a permutation of the variants, then 0xFF.
        let fb = &b[H_FALLBACK..H_FALLBACK + MAX_VARIANTS];
        let mut seen = 0u32;
        for (i, &f) in fb.iter().enumerate() {
            if i < n {
                if usize::from(f) >= n || seen & (1 << f) != 0 {
                    return Err(Error::Layout);
                }
                seen |= 1 << f;
            } else if f != 0xFF {
                return Err(Error::Layout);
            }
        }
        // The variants.
        let blobs_from = (b.len() + SIG_BYTES) as u64;
        for i in 0..n {
            let v = self.variant(i);
            let r = &b[HEADER_BYTES + i * VARIANT_BYTES..][..VARIANT_BYTES];
            if !(BACKEND_GGUF..=BACKEND_VENDOR).contains(&v.backend)
                || le32(r, V_RESERVED) != 0
                || v.wcet_us == 0
                || v.blob_len == 0
                || v.blob_off % BLOB_ALIGN != 0
                || v.blob_off < blobs_from
            {
                return Err(Error::Layout);
            }
            let end = v.blob_off.checked_add(v.blob_len).ok_or(Error::Layout)?;
            for j in 0..i {
                let w = self.variant(j);
                // Ids unique; ranges disjoint (`w`'s end cannot overflow: it was checked).
                if w.id == v.id || (v.blob_off < w.blob_off + w.blob_len && w.blob_off < end) {
                    return Err(Error::Layout);
                }
            }
        }
        Ok(())
    }

    /// The model's name.
    pub fn name(&self) -> &'a str {
        let name = &self.bytes[H_NAME..H_NAME + NAME_BYTES];
        let used = name.iter().position(|&c| c == 0).unwrap_or(NAME_BYTES);
        // ASCII was checked at `open`; the fallback keeps this total.
        core::str::from_utf8(&name[..used]).unwrap_or("")
    }

    /// Bytes of the input tensor.
    pub fn in_bytes(&self) -> u32 {
        le32(self.bytes, H_IN)
    }

    /// Bytes of the output tensor.
    pub fn out_bytes(&self) -> u32 {
        le32(self.bytes, H_OUT)
    }

    /// How many variants.
    pub fn n_variants(&self) -> usize {
        usize::from(le16(self.bytes, H_NVAR))
    }

    /// Variant `i` in the table's order (`i < n_variants()`).
    pub fn variant(&self, i: usize) -> Variant {
        let r = &self.bytes[HEADER_BYTES + i * VARIANT_BYTES..][..VARIANT_BYTES];
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&r[V_SHA..V_SHA + 32]);
        Variant {
            backend: le32(r, V_KIND),
            id: le32(r, V_ID),
            blob_off: le64(r, V_OFF),
            blob_len: le64(r, V_LEN),
            wcet_us: le32(r, V_WCET),
            energy_uj: le32(r, V_ENERGY),
            mem_bytes: le32(r, V_MEM),
            sha256,
        }
    }

    /// The variants in the publisher's order of preference.
    pub fn fallback(&self) -> impl Iterator<Item = Variant> + '_ {
        let fb = &self.bytes[H_FALLBACK..H_FALLBACK + self.n_variants()];
        fb.iter().map(move |&i| self.variant(usize::from(i)))
    }

    /// The manifest's SHA-256: the identity of this model and cost table.
    /// `azos_devif::infer::model_ref` is the reference a client names it by.
    pub fn digest(&self, sha256: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        sha256(self.bytes)
    }

    /// The variant to run: the first of the fallback list that has its backend
    /// present, memory free and a signed worst case inside the time left, or,
    /// with [`Select::low_energy`], the one of those with the lowest signed
    /// energy. `Err` says why nothing fits ([`Refusal`]).
    pub fn select(&self, s: &Select) -> Result<Variant, Refusal> {
        let mut best: Option<Variant> = None;
        let mut reason = Refusal::NoBackend;
        for v in self.fallback() {
            if s.backends & backend_bit(v.backend) == 0 {
                continue;
            }
            if reason == Refusal::NoBackend {
                reason = Refusal::NoMemory;
            }
            if v.mem_bytes > s.mem_free {
                continue;
            }
            reason = Refusal::TooSlow;
            if s.budget_us.is_some_and(|left| v.wcet_us > left) {
                continue;
            }
            match best {
                None => best = Some(v),
                Some(b) if s.low_energy && v.energy_uj < b.energy_uj => best = Some(v),
                Some(_) => {}
            }
            if !s.low_energy {
                break;
            }
        }
        best.ok_or(reason)
    }
}
