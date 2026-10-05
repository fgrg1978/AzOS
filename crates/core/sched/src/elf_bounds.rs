// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure bounds checks for the `PT_LOAD` headers of a ring-3 ELF image.
//!
//! Split out of `process.rs` for one reason: `process.rs` cannot be built for
//! the host (PTE flags, the physical allocator, inline assembly), so **not one
//! of these bounds was ever unit-tested**. Every rejection below fires only on
//! a malformed or hostile image — exactly the class that a QEMU boot of a
//! well-formed binary never exercises, so "it boots" was never evidence that
//! any of them worked. This module has no dependencies at all, which is what
//! lets `tests/host/sched-wake-tests` compile it verbatim (`#[path]`) and probe
//! the edges directly.
//!
//! `process.rs` **calls** this; it does not keep a copy. The three limits
//! arrive in [`SegLimits`] from their real single-source definitions
//! (`vmm::USER_GUARD_LIMIT`, `process::USER_LOW_MAX`, `mmu::PAGE_SIZE`) rather
//! than being redeclared here, so this file can never drift away from them.
//!
//! Under this build profile (`panic = "abort"`, `overflow-checks = true`) an
//! arithmetic overflow reboots the board, and `exec` is reachable from ring 3
//! with a fully attacker-chosen 64-bit `p_vaddr`/`p_memsz`/`p_offset`. So
//! every addition here is `checked_`/`saturating_`: a rejected image must
//! return `Reject`, never reset the robot.

/// The three address limits the loader enforces, passed in so that this module
/// owns no constant of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegLimits {
    /// `vmm::USER_GUARD_LIMIT` — lowest VA any legitimate user image uses.
    pub guard_limit: usize,
    /// `process::USER_LOW_MAX` — ceiling for the image and the `brk` heap.
    pub low_max: usize,
    /// `mmu::PAGE_SIZE`. Must be a power of two.
    pub page_size: usize,
}

/// Page range a accepted segment occupies, plus its unaligned end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegRange {
    /// First page to map (`p_vaddr` rounded down).
    pub va_start: usize,
    /// One past the last page to map (`p_vaddr + p_memsz` rounded up).
    pub va_end: usize,
    /// `p_vaddr + p_memsz`, unaligned — the ordering bound for the next
    /// segment.
    pub seg_end: usize,
}

/// Why a `PT_LOAD` header was refused. Distinct variants exist so the tests
/// can assert *which* bound caught a given header, not merely that something
/// did — a header rejected for the wrong reason means the bound under test is
/// dead code hiding behind an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegReject {
    /// `p_vaddr` below `guard_limit`: the image wants the null-guard region.
    NullGuard,
    /// `p_vaddr` at or above `low_max`: kernel MMIO / stack / vDSO territory.
    StartAboveLowMax,
    /// `p_vaddr + p_memsz` overflows `usize`, or lands above `low_max`.
    EndOutOfRange,
    /// `p_filesz > p_memsz` — unspecified by the ELF spec.
    FileSizeOverMemSize,
    /// `p_offset + p_filesz` overflows, or reads past the end of the blob.
    FileRangeOutOfBlob,
    /// This segment starts below the end of the previous one.
    Descending,
}

/// Verdict for one `PT_LOAD` program header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegCheck {
    /// `p_memsz == 0`: nothing to map, and not an error.
    Empty,
    /// Accepted; map `va_start..va_end`.
    Load(SegRange),
    /// Refuse the whole image.
    Reject(SegReject),
}

/// Round `a` up to the next multiple of `page_size`, saturating.
///
/// `a + page_size - 1` wraps for any `a` within one page of `usize::MAX`, and
/// a wrap here is a panic (`overflow-checks`), i.e. a board reset driven by an
/// ELF field. Saturating yields `usize::MAX & !(page_size-1)`, which every
/// caller's range check then rejects.
#[inline]
pub fn page_up(a: usize, page_size: usize) -> usize {
    debug_assert!(page_size.is_power_of_two());
    a.saturating_add(page_size - 1) & !(page_size - 1)
}

/// Validate one `PT_LOAD` header against `lim` and the previous segment's end.
///
/// `prev_seg_end` is the `seg_end` of the last segment this loader accepted
/// (0 for the first). Requiring `p_vaddr >= prev_seg_end` enforces the
/// ascending, non-overlapping segment order that the page-reuse branch in
/// `load_elf_into` *documents but never checked*: an out-of-order image could
/// otherwise have a later segment's file bytes rewrite an earlier segment's
/// already-mapped page. Verified against every ELF in `build/` (12 images):
/// all of them are strictly ascending with no byte-level overlap, several
/// with a segment starting exactly at the previous one's end — hence `>=`,
/// not `>`.
pub fn check_pt_load(
    p_offset: usize,
    p_vaddr: usize,
    p_filesz: usize,
    p_memsz: usize,
    elf_len: usize,
    prev_seg_end: usize,
    lim: SegLimits,
) -> SegCheck {
    if p_memsz == 0 {
        return SegCheck::Empty;
    }

    // Lower bound. The rest of the kernel already refuses to *resolve* a fault
    // below `guard_limit` (`handle_demand_fault` / `handle_cow_fault`), so a
    // task that jumps through a null pointer dies. That guarantee is only
    // worth anything if nothing can map the page for real up front: a
    // `PT_LOAD` at `p_vaddr = 0` is a legal ELF, and without this line the
    // loader honoured it, handing the process a live, pre-populated page zero
    // and turning every null dereference in it back into silent success.
    // Nothing legitimate is lost: all 12 images in `build/` report
    // `min PT_LOAD p_vaddr = 0x10000`, and all nine `userspace/*/user.ld`
    // start at exactly `0x10000` — the comparison must stay `<`, since
    // `0x10000` is both the guard limit and the lowest real segment.
    if p_vaddr < lim.guard_limit {
        return SegCheck::Reject(SegReject::NullGuard);
    }
    if p_vaddr >= lim.low_max {
        return SegCheck::Reject(SegReject::StartAboveLowMax);
    }
    if p_vaddr < prev_seg_end {
        return SegCheck::Reject(SegReject::Descending);
    }
    if p_filesz > p_memsz {
        return SegCheck::Reject(SegReject::FileSizeOverMemSize);
    }

    let seg_end = match p_vaddr.checked_add(p_memsz) {
        Some(v) if v <= lim.low_max => v,
        _ => return SegCheck::Reject(SegReject::EndOutOfRange),
    };
    match p_offset.checked_add(p_filesz) {
        Some(src_end) if src_end <= elf_len => {}
        _ => return SegCheck::Reject(SegReject::FileRangeOutOfBlob),
    }

    SegCheck::Load(SegRange {
        va_start: p_vaddr & !(lim.page_size - 1),
        va_end: page_up(seg_end, lim.page_size),
        seg_end,
    })
}
