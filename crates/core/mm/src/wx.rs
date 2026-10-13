// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The W^X boundary rule, in one place.
//!
//! `enforce_wx` used to own this arithmetic privately and nothing checked its
//! work: it returns `()`, `split_mega_range` skips a megapage in silence when
//! `alloc_page` fails, and the gate had no test that read a single PTE back.
//! The boot log said `W^X enforced` because the line was printed
//! unconditionally after the call, not because anything had been verified.
//!
//! So the ranges are computed here, by [`plan`], and BOTH the code that
//! applies them (`vmm::enforce_wx`) and the code that checks them
//! (`vmm::verify_wx`) consume the same output. A verifier that re-derived the
//! boundaries would be a second implementation of this rule, free to drift
//! from the first — and it would drift exactly at the shared boundary pages,
//! which are the only interesting part.
//!
//! Nothing here touches a page table or dereferences anything, so the whole
//! rule is reachable from `mm-tests` on the host.
//!
//! **ISA-neutral since the page-table abstraction (B2).** This module used
//! to type against `azos_arch::mmu::PteFlags` — RISC-V's raw Sv39 PTE
//! bits — which is exactly the kind of ISA-specific surface `crates/core/mm` is
//! meant to stop depending on. It now types against
//! [`azos_arch_api::PagePerms`], the cross-ISA permission model:
//! `vmm::enforce_wx`/`verify_wx` decode a live PTE word to `PagePerms`
//! (via `Mmu::pte_perms`) before calling into this module, so nothing here
//! touches a raw word at all, on any ISA.
//!
//! One narrowing from the old full-bitset comparison, stated rather than
//! left to be discovered by a failing test: `PagePerms` carries
//! `read/write/exec/user/cache/accessed/dirty` but not the software COW /
//! DEMAND markers `PteFlags` also held. `judge`'s equality therefore no
//! longer distinguishes a COW- or DEMAND-marked leaf from a plain one.
//! This is inert in practice — `enforce_wx`/`verify_wx` only ever walk the
//! kernel's own page table, and the kernel image is never COW-shared or
//! demand-mapped — but it is a real change in what the check can see, and
//! future code that reused `judge` for a user mapping should know it will
//! not catch a COW/DEMAND mismatch.

use azos_arch_api::{PagePerms, PAGE_SIZE};

/// One contiguous span of the kernel image and the permissions it must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WxRange {
    pub start: usize,
    pub end:   usize,
    pub flags: PagePerms,
    /// For diagnostics: which section this came from.
    pub name:  &'static str,
}

impl WxRange {
    #[inline]
    pub fn is_empty(&self) -> bool { self.start >= self.end }

    /// Number of 4 KiB pages the range covers.
    #[inline]
    pub fn pages(&self) -> usize {
        if self.is_empty() { 0 } else { (self.end - self.start).div_ceil(PAGE_SIZE) }
    }
}

/// The three ranges `enforce_wx` applies, in the order it applies them.
///
/// Boundary rule, unchanged from the original inline version:
///
///   * `.text` rounds its END **up** — a page shared with `.rodata` stays RX,
///     because removing X from it would fault the code living in its first
///     half.
///   * `.rodata` starts at whichever is higher, its own page-aligned start or
///     the end of `.text` — same reason, text wins the shared page.
///   * `.data`/`.bss` likewise start after `.rodata`'s last page.
///
/// The order matters and is why this returns an array rather than a set: a
/// later range overwriting an earlier one on a shared page is not a bug here,
/// it is the tie-break above. `verify_wx` walks the same array in the same
/// order for that reason.
pub fn plan(
    text_start: usize, text_end: usize,
    rodata_start: usize, rodata_end: usize,
    data_start: usize, kernel_end: usize,
) -> [WxRange; 3] {
    let text_page_end     = (text_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let rodata_page_start = rodata_start & !(PAGE_SIZE - 1);
    let rodata_page_end   = (rodata_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let data_page_start   = data_start & !(PAGE_SIZE - 1);

    let ro_start = if rodata_page_start < text_page_end {
        text_page_end // boundary page stays RX (text wins)
    } else {
        rodata_page_start
    };

    let data_start_safe = if data_page_start < rodata_page_end {
        rodata_page_end
    } else {
        data_page_start
    };

    [
        WxRange { start: text_start & !(PAGE_SIZE - 1), end: text_page_end,
                  flags: PagePerms::KERNEL_RX, name: ".text" },
        // Identical bits to the literal `VALID | READ | ACCESSED` this
        // replaced; named so a reader can see it is read-only, not just
        // "not writable".
        WxRange { start: ro_start, end: rodata_page_end,
                  flags: PagePerms::KERNEL_RO, name: ".rodata" },
        WxRange { start: data_start_safe, end: kernel_end,
                  flags: PagePerms::KERNEL_RW, name: ".data/.bss" },
    ]
}

/// Does this mapping permit writing AND executing the same bytes?
///
/// The one property W^X exists to deny, stated once so a test can hold it
/// against a flag set without a page table.
#[inline]
pub fn is_write_exec(flags: PagePerms) -> bool {
    flags.write && flags.exec
}

/// What one page turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageVerdict {
    /// Flags are exactly what `plan` asked for.
    Ok,
    /// Writable and executable at once — the violation W^X denies.
    WriteExec,
    /// Not writable+executable, but not what was asked either. Worth
    /// reporting separately: it means the enforcer and the page table
    /// disagree, which is a bug even when it happens to be safe.
    WrongFlags,
    /// No valid leaf maps this address. `remap_range` skips these, so it is
    /// not a W^X failure — but inside the kernel image it is a surprise.
    Unmapped,
    /// A 2 MiB leaf still covers this address: `split_mega_range` did not
    /// split it (its `alloc_page` failure path skips in silence). Writing
    /// 4 KiB flags into that entry would retag the whole 2 MiB, so this is
    /// reported rather than counted as one page.
    UnsplitMegapage,
}

/// Judge one page against the range it belongs to.
#[inline]
pub fn judge(want: PagePerms, got: PagePerms) -> PageVerdict {
    if is_write_exec(got) {
        PageVerdict::WriteExec
    } else if got == want {
        PageVerdict::Ok
    } else {
        PageVerdict::WrongFlags
    }
}

/// Outcome of a whole `verify_wx` sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WxReport {
    pub checked:          usize,
    pub write_exec:       usize,
    pub wrong_flags:      usize,
    pub unmapped:         usize,
    pub unsplit_megapage: usize,
    /// First address that was not `Ok`, for a log line worth reading.
    pub first_bad:        usize,
}

impl WxReport {
    /// Did every page of the kernel image carry exactly the flags planned?
    ///
    /// Deliberately stricter than "no page is writable and executable": an
    /// `.rodata` page that came out RW is not a W^X violation and is still
    /// the enforcer having failed to do what it said.
    #[inline]
    pub fn is_clean(&self) -> bool {
        self.write_exec == 0
            && self.wrong_flags == 0
            && self.unmapped == 0
            && self.unsplit_megapage == 0
    }

    /// The subset that is a security failure rather than a surprise.
    #[inline]
    pub fn has_wx_violation(&self) -> bool {
        self.write_exec > 0 || self.unsplit_megapage > 0
    }

    pub fn record(&mut self, vaddr: usize, verdict: PageVerdict) {
        self.checked += 1;
        let bad = match verdict {
            PageVerdict::Ok              => false,
            PageVerdict::WriteExec       => { self.write_exec += 1; true }
            PageVerdict::WrongFlags      => { self.wrong_flags += 1; true }
            PageVerdict::Unmapped        => { self.unmapped += 1; true }
            PageVerdict::UnsplitMegapage => { self.unsplit_megapage += 1; true }
        };
        if bad && self.first_bad == 0 {
            self.first_bad = vaddr;
        }
    }
}


// ---------------------------------------------------------------------------
// The RAM outside the kernel image.
// ---------------------------------------------------------------------------

/// Does this mapping permit execution?
///
/// Separate from [`is_write_exec`] because outside the kernel image the
/// question is not "is this W AND X" but simply "is anything here executable
/// that has no business being". Every page out there is data: the heap, the
/// frames `pmm` hands out, task stacks, the vDSO page (which holds atomics,
/// not code — the user side maps it through its own table).
#[inline]
pub fn is_exec(flags: PagePerms) -> bool {
    flags.exec
}

/// The same mapping with EXEC removed, everything else untouched.
///
/// Returns `None` when there is nothing to do, so a caller can count only the
/// mappings it actually changed instead of rewriting every PTE in RAM and
/// reporting a number that means "pages visited".
#[inline]
pub fn without_exec(flags: PagePerms) -> Option<PagePerms> {
    if is_exec(flags) { Some(PagePerms { exec: false, ..flags }) } else { None }
}

/// What a sweep over the non-image RAM found or did.
///
/// `megapages` and `pages` are counted apart because they are not the same
/// unit and summing them would produce a number with no meaning: one megapage
/// entry covers 512 times the address space of one 4 KiB entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RamExecReport {
    /// Level-1 leaves (2 MiB at a 4 KiB page) that were (or still are) executable.
    pub megapages: usize,
    /// Page leaves (4 KiB unless an aarch64 granule says otherwise) that were (or still are) executable.
    pub pages: usize,
    /// First executable address seen.
    pub first: usize,
}

impl RamExecReport {
    /// Bytes of RAM the report covers. This is the figure worth printing —
    /// "121 MiB executable" says something; "62 entries" does not.
    #[inline]
    pub fn bytes(&self) -> usize {
        // A megapage spans one table of pages: 2 MiB at a 4 KiB page.
        self.megapages * (PAGE_SIZE / 8) * PAGE_SIZE + self.pages * PAGE_SIZE
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.megapages == 0 && self.pages == 0
    }

    pub fn record_mega(&mut self, vaddr: usize) {
        self.megapages += 1;
        if self.first == 0 { self.first = vaddr; }
    }

    pub fn record_page(&mut self, vaddr: usize) {
        self.pages += 1;
        if self.first == 0 { self.first = vaddr; }
    }
}
