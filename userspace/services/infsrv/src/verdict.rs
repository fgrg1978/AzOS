// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The latest verdict of a context, for readers that must not call.
//!
//! A real-time consumer of inference (a control loop that falls back when its
//! model was refused) cannot afford a call to ask "did my last run happen, and
//! on what?", and syscalls are for changing authority and for sleeping. So the
//! answer is published, not asked for: a `Log<Verdict, 1>` (a latest-value
//! cell, `azos_rings::Log`) in a memory object the service makes and lends
//! read-only ([`crate::service::InferLog`]). **Each context has an object of
//! its own**: the capability a client is lent maps its own verdicts and no
//! other context's, so holding the lease is not a view of anybody else's
//! refusals or energy. The service is each cell's only writer; a reader maps
//! the object and calls [`LogReader::latest`], which never blocks the writer
//! and retries while it is mid-store.
//!
//! An object starts with a [`Header`] a reader checks before it trusts the
//! cell: the magic, the version, and the size and alignment of a cell as this
//! build laid it out, so a reader built against another layout of `Log`
//! refuses the object instead of reading garbage.

use crate::config::CONTEXTS;
use azos_rings::{Log, Writer};
use core::mem::{align_of, size_of};

/// "IFVL".
pub const MAGIC: u32 = u32::from_le_bytes(*b"IFVL");
/// The only layout.
pub const VERSION: u32 = 1;

/// How the latest call of a context ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Verdict {
    /// The model the call named.
    pub model_ref: u64,
    /// The id of the decision record of a refusal (or of an admission that
    /// changed the variant); 0 when the call recorded none. Read it back with
    /// the `Decisions` object of the same endpoint.
    pub receipt: u64,
    /// The variant that ran, or the candidate a refusal is about.
    pub variant_id: u32,
    /// Its backend (`azos_ml::bundle::BACKEND_*`).
    pub backend: u32,
    /// The outcome the call was answered with (`azos_devif::outcome`).
    pub code: u32,
    /// Why ([`crate::broker::reason`]).
    pub reason: u32,
    /// Wall time of the run, microseconds; 0 for a refusal.
    pub latency_us: u32,
    /// Energy charged, microjoules (the overrun's included); 0 for a refusal.
    pub energy_uj: u32,
    /// How far the run went past its signed worst case, microseconds.
    pub overrun_us: u32,
    pub _pad: u32,
    /// When it was decided, nanoseconds on MONO.
    pub at_ns: u64,
}

/// One slot of the object.
type Cell = Log<Verdict, 1>;

/// The object's first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Header {
    pub magic: u32,
    pub version: u32,
    pub cell_bytes: u32,
    pub cell_align: u32,
    /// Where the cell is, bytes from the start.
    pub cells_off: u32,
    pub verdict_bytes: u32,
    pub _pad: u32,
}

const HEADER_BYTES: usize = size_of::<Header>();

const fn cells_off() -> usize {
    HEADER_BYTES.div_ceil(align_of::<Cell>()) * align_of::<Cell>()
}

/// Bytes of one context's object.
pub const fn region_bytes() -> usize {
    cells_off() + size_of::<Cell>()
}

/// Alignment the object's start must have.
pub const fn region_align() -> usize {
    align_of::<Cell>()
}

fn header() -> Header {
    Header {
        magic: MAGIC,
        version: VERSION,
        cell_bytes: size_of::<Cell>() as u32,
        cell_align: align_of::<Cell>() as u32,
        cells_off: cells_off() as u32,
        verdict_bytes: size_of::<Verdict>() as u32,
        _pad: 0,
    }
}

/// The service's side: the writer of each context's cell.
pub struct Publisher {
    writers: [Option<Writer<'static, Verdict, 1>>; CONTEXTS],
}

impl Publisher {
    /// A publisher with no object yet: every [`Publisher::publish`] says `None`
    /// until [`Publisher::add`] gives its slot one.
    pub const fn new() -> Publisher {
        Publisher { writers: [const { None }; CONTEXTS] }
    }

    /// Make the object of context `slot` at `base`. `false`: the slot is past
    /// the table, has an object already, or the region does not fit.
    ///
    /// # Safety
    ///
    /// `base .. base + len` is memory this program may write, aligned to
    /// [`region_align`], that stays mapped for the life of the program and that
    /// nothing else in it refers to.
    pub unsafe fn add(&mut self, slot: usize, base: *mut u8, len: usize) -> bool {
        if slot >= CONTEXTS || self.writers[slot].is_some() || len < region_bytes() || base as usize % region_align() != 0 {
            return false;
        }
        // SAFETY: the caller's contract; every write is inside `region_bytes()`.
        unsafe {
            core::ptr::write(base as *mut Header, header());
            let cell = base.add(cells_off()) as *mut Cell;
            core::ptr::write(cell, Cell::new(Verdict::default()));
            self.writers[slot] = (*cell).writer();
        }
        self.writers[slot].is_some()
    }

    /// Publish `v` as the latest verdict of context `slot`; its sequence
    /// number. `None` for a slot past the table or with no object.
    pub fn publish(&mut self, slot: usize, v: Verdict) -> Option<u64> {
        self.writers.get_mut(slot)?.as_mut().map(|w| w.publish(v))
    }
}

/// A reader's side: the cell of an object a service lent.
pub struct LogReader {
    cell: *const Cell,
}

impl LogReader {
    /// Open the object at `base`, `None` unless it is one this build can read.
    ///
    /// # Safety
    ///
    /// `base .. base + len` is memory this program may read, aligned to
    /// [`region_align`], that stays mapped while the reader is used.
    pub unsafe fn open(base: *const u8, len: usize) -> Option<LogReader> {
        if len < HEADER_BYTES || base as usize % region_align() != 0 {
            return None;
        }
        // SAFETY: the caller's contract; the header is inside `len`.
        let h = unsafe { core::ptr::read(base as *const Header) };
        let own = header();
        if h.magic != own.magic
            || h.version != own.version
            || h.cell_bytes != own.cell_bytes
            || h.cell_align != own.cell_align
            || h.cells_off != own.cells_off
            || h.verdict_bytes != own.verdict_bytes
            || len < cells_off() + size_of::<Cell>()
        {
            return None;
        }
        // SAFETY: inside `len`, as checked.
        Some(LogReader { cell: unsafe { base.add(cells_off()) as *const Cell } })
    }

    /// The newest verdict of the context and its sequence number (0: none yet,
    /// a default verdict).
    pub fn latest(&self) -> (u64, Verdict) {
        // SAFETY: `open` checked the cell is inside the object; `latest` only
        // loads (a read-only mapping is enough).
        unsafe { (*self.cell).latest() }
    }
}
