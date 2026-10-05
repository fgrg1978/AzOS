// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal GGUF v1–v3 parser — `no_std`, zero allocation.
//!
//! Parses the header and tensor-info sections of a GGUF file from a byte
//! slice (e.g. a file read from FAT32 into a static buffer).
//! KV metadata is skipped (length-counted) so the parser stays small.
//!
//! # Limits (static sizing, no heap)
//!
//! - `MAX_TENSORS` = 32 tensors per file.
//! - `MAX_KLEN`    = 64 bytes per tensor name.
//!
//! # GGUF file layout (v3)
//!
//! ```text
//! [4]  magic      : "GGUF"
//! [4]  version    : u32le  (1, 2 or 3)
//! [8]  n_tensors  : u64le
//! [8]  n_kv       : u64le
//! KV metadata × n_kv  (variable, skipped)
//! Tensor info  × n_tensors (name, n_dims, dims[], type, offset)
//! Padding to 32-byte alignment
//! ── Tensor data section ─────────────────────────────────────────────────────
//! ```

#![allow(dead_code)]

/// Maximum tensors tracked per GGUF file.
pub const MAX_TENSORS: usize = 32;
/// Maximum tensor-name length in bytes.
pub const MAX_KLEN: usize = 64;

// ── GGML quantisation types ───────────────────────────────────────────────────

/// GGML tensor element type.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GgmlType {
    F32    = 0,
    F16    = 1,
    Q4_0   = 2,
    Q4_1   = 3,
    Q8_0   = 8,
    Unknown = 255,
}

impl GgmlType {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::F32,
            1 => Self::F16,
            2 => Self::Q4_0,
            3 => Self::Q4_1,
            8 => Self::Q8_0,
            _ => Self::Unknown,
        }
    }

    /// `(block_size, bytes_per_block)` for this type.
    pub fn block_params(self) -> (usize, usize) {
        match self {
            Self::F32    => (1,  4),
            Self::F16    => (1,  2),
            Self::Q4_0   => (32, 18),  // 2-byte f16 scale + 16 bytes nibbles
            Self::Q4_1   => (32, 20),  // scale + min + nibbles
            Self::Q8_0   => (32, 34),  // 2-byte f16 scale + 32 i8 values
            Self::Unknown => (1,  1),
        }
    }

    /// Total byte size for `n` elements of this type.
    pub fn byte_size(self, n: usize) -> usize {
        let (blk, bpb) = self.block_params();
        (n.saturating_add(blk - 1) / blk).saturating_mul(bpb)
    }
}

// ── TensorInfo ────────────────────────────────────────────────────────────────

/// Parsed metadata for one tensor inside a GGUF file.
#[derive(Clone, Copy)]
pub struct TensorInfo {
    pub name:      [u8; MAX_KLEN],
    pub name_len:  usize,
    pub n_dims:    u32,
    /// Dimensions in ggml order: dims[0] = innermost (columns), dims[1] = rows, …
    pub dims:      [u64; 4],
    pub ggml_type: GgmlType,
    /// Byte offset from the start of the tensor-data section.
    pub offset:    u64,
}

impl TensorInfo {
    const fn empty() -> Self {
        TensorInfo {
            name: [0u8; MAX_KLEN], name_len: 0,
            n_dims: 0, dims: [0; 4],
            ggml_type: GgmlType::F32, offset: 0,
        }
    }

    pub fn name_bytes(&self) -> &[u8] { &self.name[..self.name_len] }

    /// Total number of elements (product of all dims).
    pub fn n_elements(&self) -> usize {
        let mut n = 1usize;
        for i in 0..self.n_dims as usize { n = n.saturating_mul(self.dims[i] as usize); }
        n
    }
}

// ── GgufFile ──────────────────────────────────────────────────────────────────

/// A parsed GGUF file (borrows the underlying byte slice).
pub struct GgufFile<'a> {
    data:        &'a [u8],
    /// Byte offset of the first tensor data byte (past header + padding).
    data_offset: usize,
    tensors:     [TensorInfo; MAX_TENSORS],
    pub n_tensors: usize,
}

impl<'a> GgufFile<'a> {
    /// Parse a GGUF file from a byte slice.  Returns `None` on any error.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 24 { return None; }
        if &data[0..4] != b"GGUF" { return None; }

        let version   = u32_le(&data[4..]);
        let n_tensors = u64_le(&data[8..])  as usize;
        let n_kv      = u64_le(&data[16..]) as usize;

        if !(1..=3).contains(&version) { return None; }
        if n_tensors > MAX_TENSORS     { return None; }

        let mut pos = 24usize;

        // Skip all KV metadata (we only need tensor data for inference).
        for _ in 0..n_kv {
            pos = skip_kv(data, pos)?;
        }

        // Parse tensor info entries.
        let mut tensors = [TensorInfo::empty(); MAX_TENSORS];
        for i in 0..n_tensors {
            let (info, next) = parse_tensor_info(data, pos)?;
            tensors[i] = info;
            pos = next;
        }

        // Tensor data starts at the next 32-byte boundary (v3) or 64-byte (v1/v2).
        let align = if version >= 3 { 32usize } else { 64usize };
        let data_offset = (pos + align - 1) / align * align;

        Some(GgufFile { data, data_offset, tensors, n_tensors })
    }

    /// Return the raw bytes, element type, and element count for a named tensor.
    ///
    /// Returns `None` if the tensor is not found or its data extends past EOF.
    pub fn tensor_data(&self, name: &[u8]) -> Option<(&'a [u8], GgmlType, usize)> {
        for i in 0..self.n_tensors {
            let t = &self.tensors[i];
            if t.name_bytes() != name { continue; }
            let n     = t.n_elements();
            let bytes = t.ggml_type.byte_size(n);
            // Checked: `offset`/`bytes` come from the file and could overflow.
            let start = self.data_offset.checked_add(t.offset as usize)?;
            let end   = start.checked_add(bytes)?;
            if end > self.data.len() { return None; }
            return Some((&self.data[start..end], t.ggml_type, n));
        }
        None
    }

    /// Return metadata for a named tensor.
    pub fn tensor_info(&self, name: &[u8]) -> Option<&TensorInfo> {
        (0..self.n_tensors).find(|&i| self.tensors[i].name_bytes() == name)
                           .map(|i| &self.tensors[i])
    }
}

// ── GGUF KV type constants ────────────────────────────────────────────────────

const GGUF_TYPE_UINT8:   u32 = 0;
const GGUF_TYPE_INT8:    u32 = 1;
const GGUF_TYPE_UINT16:  u32 = 2;
const GGUF_TYPE_INT16:   u32 = 3;
const GGUF_TYPE_UINT32:  u32 = 4;
const GGUF_TYPE_INT32:   u32 = 5;
const GGUF_TYPE_FLOAT32: u32 = 6;
const GGUF_TYPE_BOOL:    u32 = 7;
const GGUF_TYPE_STRING:  u32 = 8;
const GGUF_TYPE_ARRAY:   u32 = 9;
const GGUF_TYPE_UINT64:  u32 = 10;
const GGUF_TYPE_INT64:   u32 = 11;
const GGUF_TYPE_FLOAT64: u32 = 12;

fn kv_scalar_size(typ: u32) -> Option<usize> {
    Some(match typ {
        GGUF_TYPE_UINT8  | GGUF_TYPE_INT8  | GGUF_TYPE_BOOL    => 1,
        GGUF_TYPE_UINT16 | GGUF_TYPE_INT16                     => 2,
        GGUF_TYPE_UINT32 | GGUF_TYPE_INT32 | GGUF_TYPE_FLOAT32 => 4,
        GGUF_TYPE_UINT64 | GGUF_TYPE_INT64 | GGUF_TYPE_FLOAT64 => 8,
        _ => return None,
    })
}

/// Skip a GGUF length-prefixed string (u64 len + bytes).
fn skip_string(data: &[u8], pos: usize) -> Option<usize> {
    if pos + 8 > data.len() { return None; }
    let len = u64_le(&data[pos..]) as usize;
    let end = pos.checked_add(8)?.checked_add(len)?;
    if end > data.len() { return None; }
    Some(end)
}

/// Skip one complete KV pair.
fn skip_kv(data: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_string(data, pos)?;          // key
    if pos + 4 > data.len() { return None; }
    let vtype = u32_le(&data[pos..]);
    let pos = pos + 4;                          // past type tag

    match vtype {
        GGUF_TYPE_STRING => skip_string(data, pos),
        GGUF_TYPE_ARRAY => {
            if pos + 12 > data.len() { return None; }
            let elem_type = u32_le(&data[pos..]);
            let count     = u64_le(&data[pos + 4..]) as usize;
            let pos = pos + 12;
            if elem_type == GGUF_TYPE_STRING {
                let mut p = pos;
                for _ in 0..count { p = skip_string(data, p)?; }
                Some(p)
            } else {
                let esz = kv_scalar_size(elem_type)?;
                // The multiply was checked and the ADD was not. `count` is a
                // raw `u64` from the file: with `count = u64::MAX` and a
                // one-byte element type, `checked_mul` answers
                // `Some(usize::MAX)` and `pos + that` overflows. The release
                // profile sets `overflow-checks = true` beside
                // `panic = "abort"`, so that is a board reset, from a file the
                // kernel reads at every boot.
                let end = pos.checked_add(count.checked_mul(esz)?)?;
                if end > data.len() { return None; }
                Some(end)
            }
        }
        _ => {
            let sz = kv_scalar_size(vtype)?;
            // Checked for the same reason as the array arm above, though this
            // one cannot overflow today (`pos <= data.len()`, `sz <= 8`): the
            // next reader re-validates, so an unchecked add here is safe by a
            // property held somewhere else. Making it local costs nothing and
            // removes the question.
            pos.checked_add(sz)
        }
    }
}

/// Parse one tensor-info entry; returns (info, next_pos).
fn parse_tensor_info(data: &[u8], pos: usize) -> Option<(TensorInfo, usize)> {
    // name: string
    if pos + 8 > data.len() { return None; }
    let name_len = u64_le(&data[pos..]) as usize;
    let pos = pos + 8;
    if name_len > MAX_KLEN || pos + name_len > data.len() { return None; }

    let mut info = TensorInfo::empty();
    info.name[..name_len].copy_from_slice(&data[pos..pos + name_len]);
    info.name_len = name_len;
    let pos = pos + name_len;

    // n_dims: u32
    if pos + 4 > data.len() { return None; }
    let n_dims = u32_le(&data[pos..]);
    if n_dims as usize > info.dims.len() { return None; } // dims is [u64; 4]
    info.n_dims = n_dims;
    let pos = pos + 4;

    // dims: [u64; n_dims]
    let nd = n_dims as usize;
    if pos + 8 * nd > data.len() { return None; }
    for i in 0..nd.min(4) { info.dims[i] = u64_le(&data[pos + i * 8..]); }
    let pos = pos + 8 * nd;

    // ggml_type: u32
    if pos + 4 > data.len() { return None; }
    info.ggml_type = GgmlType::from_u32(u32_le(&data[pos..]));
    let pos = pos + 4;

    // offset: u64
    if pos + 8 > data.len() { return None; }
    info.offset = u64_le(&data[pos..]);
    let pos = pos + 8;

    Some((info, pos))
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

#[inline(always)]
pub(crate) fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline(always)]
pub(crate) fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
