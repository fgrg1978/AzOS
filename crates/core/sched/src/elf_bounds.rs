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
    /// This segment starts on the page the previous one ends on, and the two
    /// are mapped with different permissions ([`seg_perms`]): one page table
    /// entry cannot hold both, and their union would make read-only data
    /// executable or writable.
    SharedPageMixedPerms,
    /// An executable segment's file range holds a byte of the ELF header or
    /// the program header table ([`check_exec_headers`]).
    ExecMapsHeaders,
}

/// `PF_X` and `PF_W` of a program header's `p_flags` (ELF spec).
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;

/// The permissions the loader maps a `PT_LOAD` segment with, from its
/// `p_flags`. Three classes, W^X in both directions: writable is never
/// executable (an `RWX` header maps read-write), and a read-only segment is
/// never executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegPerms {
    ReadOnly,
    ReadExec,
    ReadWrite,
}

/// [`SegPerms`] of a header's `p_flags`.
pub fn seg_perms(p_flags: u32) -> SegPerms {
    if p_flags & PF_W != 0 {
        SegPerms::ReadWrite
    } else if p_flags & PF_X != 0 {
        SegPerms::ReadExec
    } else {
        SegPerms::ReadOnly
    }
}

/// May a segment mapped `perms`, starting at `p_vaddr`, follow one mapped
/// `prev` that ended (unaligned) at `prev_seg_end`?
///
/// A page gets exactly the permissions of the one segment it belongs to. A
/// page both segments touch would need two permission sets in one page table
/// entry; mapping it with their union (what the loader did) made the
/// `.rodata` sharing the last `.text` page executable. So a shared page is
/// accepted only when both segments are mapped alike; otherwise the image is
/// refused, whatever its header says. Linkers place a segment with other
/// permissions on a page of its own (lld, which links every native image
/// with no script, and GNU ld), so no well-formed image is lost. Segments arrive
/// in ascending order ([`check_pt_load`]), so the previous segment is the
/// only one that can share this one's first page.
///
/// `prev` is `None` for the first loaded segment.
pub fn check_page_sharing(
    prev_seg_end: usize,
    prev: Option<SegPerms>,
    p_vaddr: usize,
    perms: SegPerms,
    page_size: usize,
) -> Result<(), SegReject> {
    let Some(prev) = prev else { return Ok(()) };
    if cfg!(feature = "elf-mixed-page-canary") || prev == perms || prev_seg_end == 0 {
        return Ok(());
    }
    let mask = !(page_size - 1);
    if (prev_seg_end - 1) & mask == p_vaddr & mask {
        return Err(SegReject::SharedPageMixedPerms);
    }
    Ok(())
}

/// May a segment with `p_flags`, file range `p_offset..p_offset+p_filesz`,
/// be mapped when the ELF header and the program header table end at
/// `headers_end` in the file?
///
/// A segment the loader maps executable ([`seg_perms`] `ReadExec`) whose
/// file range covers the headers is refused. The headers are never code: a
/// text segment that maps them is one a linker built by folding everything
/// read-only into the RX segment, `.rodata` included (lld `--no-rosegment`,
/// GNU ld without `-z separate-code`), so the image would run with its
/// read-only data executable. The program headers are all the loader has
/// (a streamed exec never sees the section headers), and this is the
/// signature they carry; a `.rodata` placed inside the text segment by a
/// script that keeps the headers out is named at build time instead
/// (tools/lint/elf_page_perms.py). lld's default layout (every native image's)
/// and GNU ld with `-z separate-code` keep the headers in a read-only
/// segment or in none. Kconfig ELF_REFUSE_EXEC_HEADERS decides whether the loader
/// asks.
pub fn check_exec_headers(
    p_flags: u32,
    p_offset: usize,
    p_filesz: usize,
    headers_end: usize,
) -> Result<(), SegReject> {
    if seg_perms(p_flags) == SegPerms::ReadExec && p_filesz != 0 && p_offset < headers_end {
        return Err(SegReject::ExecMapsHeaders);
    }
    Ok(())
}

/// `p_type` of a note segment.
pub const PT_NOTE: u32 = 4;

/// `p_type` of the stack header (`PT_GNU_STACK`). Its `p_memsz` is the stack
/// the image asks for: lld writes `-z stack-size` there (a native image's
/// `build.rs`, e.g. `userspace/services/toolbox/build.rs`); an image with no
/// such header, or with `p_memsz == 0`, takes the default. A Linux image may
/// carry a toolchain's request (zig links 16 MiB into every binary): see
/// [`foreign_stack_bytes`].
/// It sits in the program header table, so a streamed image's first
/// `STREAM_HDR_BYTES` carry it, which a note in the middle of the file would not.
pub const PT_GNU_STACK: u32 = 0x6474_e551;

/// Why an image's stack request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackReject {
    /// The request, rounded up to whole pages, is over the build's ceiling
    /// (Kconfig `USER_STACK_MAX_KB`); the bytes are the rounded request.
    OverMax(usize),
}

/// The user stack, in bytes, of an image whose `PT_GNU_STACK` asks for
/// `memsz`: `default` when it asks for nothing (`0`), else the request rounded
/// up to whole pages, refused above `max`. `memsz` is the image's, so the
/// rounding saturates ([`page_up`]) and cannot wrap into an acceptable size.
pub fn stack_bytes(memsz: usize, page_size: usize, default: usize, max: usize) -> Result<usize, StackReject> {
    if memsz == 0 {
        return Ok(default);
    }
    let bytes = page_up(memsz, page_size);
    if bytes > max {
        return Err(StackReject::OverMax(bytes));
    }
    Ok(bytes)
}

/// The user stack of a foreign image (no AZOS ABI note: a Linux program). Linux
/// sizes the main thread's stack from `RLIMIT_STACK` and never refuses an exec
/// over `PT_GNU_STACK`'s size, and toolchains write a default there (zig: 16
/// MiB in every binary), so the request is clamped to `max`, never refused.
/// A native image is built for this build, and an over-ceiling request is its
/// bug: [`stack_bytes`] refuses it.
pub fn foreign_stack_bytes(memsz: usize, page_size: usize, default: usize, max: usize) -> usize {
    stack_bytes(memsz.min(max), page_size, default, max).unwrap_or(max)
}

/// The ABI version the `PT_NOTE` program header at byte `ph` of `elf` names, if
/// its notes include the AZOS ABI note (name `AZOS`, type `note_type`, a 4-byte
/// descriptor); `None` for a segment with no such note or one that does not
/// parse. Every offset is checked: the header is attacker-chosen.
pub fn abi_note_version(elf: &[u8], ph: usize, note_type: u32) -> Option<u32> {
    let rd64 = |at: usize| -> Option<u64> {
        let b = elf.get(at..at.checked_add(8)?)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_le_bytes(a))
    };
    let off = usize::try_from(rd64(ph.checked_add(8)?)?).ok()?;
    let len = usize::try_from(rd64(ph.checked_add(32)?)?).ok()?;
    let seg = elf.get(off..off.checked_add(len)?)?;
    let mut at = 0usize;
    while at.checked_add(12)? <= seg.len() {
        let w = |i: usize| u32::from_le_bytes([seg[at + i], seg[at + i + 1], seg[at + i + 2], seg[at + i + 3]]);
        let (namesz, descsz, ty) = (w(0) as usize, w(4) as usize, w(8));
        let name_at = at + 12;
        let desc_at = name_at.checked_add(namesz.checked_add(3)? & !3)?;
        let next = desc_at.checked_add(descsz.checked_add(3)? & !3)?;
        if next > seg.len() {
            return None;
        }
        if ty == note_type && descsz == 4 && seg.get(name_at..name_at + namesz) == Some(b"AZOS\0".as_slice()) {
            return Some(u32::from_le_bytes([seg[desc_at], seg[desc_at + 1], seg[desc_at + 2], seg[desc_at + 3]]));
        }
        at = next;
    }
    None
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
/// already-mapped page. Verified against every ELF in `$AZOS_OUT/build/` (12 images):
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
    // Nothing legitimate is lost: a native image starts at its target spec's
    // image base (`--image-base`, sdk/targets: 0x200000) and a static Linux
    // image at lld's or the toolchain's, 0x10000 at the lowest — the
    // comparison must stay `<`, since `0x10000` is both the guard limit and
    // the lowest such segment.
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

// ── The header walk ──────────────────────────────────────────────────────────
//
// The loader (`process::load_elf_into`) and the fuzz target (`tests/fuzz/elf-fuzz`)
// read an image's headers through the code below, and nothing else: it takes
// every fact it needs from [`ImageParams`], so it names no kernel crate, no
// Kconfig value and no `cfg(target_arch)`, and one host build runs it for all
// three ISAs' machine types.

/// `e_machine` of the three ISAs a native image is built for.
pub const EM_RISCV: u16 = 0xf3;
pub const EM_AARCH64: u16 = 0xb7;
pub const EM_X86_64: u16 = 0x3e;

/// `p_type` of a loadable segment.
pub const PT_LOAD: u32 = 1;

/// The alignment an entry point must have for `machine`: RISC-V fetches on
/// 2-byte boundaries (compressed instructions), aarch64 keeps the same check
/// (its instructions are 4-byte, so 4 would be the tighter value), x86_64
/// instructions start on any byte (its `_start` is wherever the linker put it,
/// odd as often as not), so there it constrains nothing.
pub const fn entry_align(machine: u16) -> u64 {
    if machine == EM_X86_64 && !cfg!(feature = "elf-entry-align-canary") { 1 } else { 2 }
}

/// What the walk is told, none of which it may name itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageParams {
    /// The `e_machine` this kernel build runs.
    pub machine: u16,
    pub limits: SegLimits,
    /// Kconfig `ELF_REFUSE_EXEC_HEADERS` ([`check_exec_headers`]).
    pub refuse_exec_headers: bool,
    /// The ABI note's type and the version this build speaks ([`abi_note_version`]).
    pub abi_note_type: u32,
    pub abi_version: u32,
}

/// The fields of the ELF header the loader reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfHeader {
    pub entry: u64,
    pub phoff: usize,
    pub phentsize: usize,
    pub phnum: usize,
}

fn rd16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn rd32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn rd64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3], d[o + 4], d[o + 5], d[o + 6], d[o + 7]])
}

/// The ELF header of `elf` (its first bytes at least), or `None` when it is not
/// a little-endian 64-bit image for `machine` with a program header table
/// whose entries hold the 56 bytes the walk reads.
///
/// The machine is matched against the ISA this kernel binary is built for, not
/// "either machine on both": a RISC-V kernel is never handed an aarch64 image
/// whatever the file it arrived in was called.
pub fn parse_header(elf: &[u8], machine: u16) -> Option<ElfHeader> {
    if elf.len() < 64 || elf[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    if elf[4] != 2 || elf[5] != 1 {
        return None; // ELFCLASS64, ELFDATA2LSB
    }
    if rd16(elf, 18) != machine && !cfg!(feature = "elf-machine-canary") {
        return None;
    }
    let hdr = ElfHeader {
        entry: rd64(elf, 24),
        phoff: rd64(elf, 32) as usize,
        phentsize: rd16(elf, 54) as usize,
        phnum: rd16(elf, 56) as usize,
    };
    if hdr.phentsize < 56 || hdr.phnum == 0 {
        return None;
    }
    Some(hdr)
}

/// One accepted `PT_LOAD` segment: its header fields and the pages it maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flags: u32,
    pub offset: usize,
    pub vaddr: usize,
    pub filesz: usize,
    pub range: SegRange,
}

/// Why the walk refused an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkReject {
    /// A program header lies (partly) outside the blob, or `e_phoff + i *
    /// e_phentsize` overflows. The walk refuses the image instead of loading
    /// the segments that happened to fit: a half-built address space is a far
    /// worse outcome than a failed exec.
    ProgramTable,
    /// The ABI note names a version other than this build's.
    AbiVersion,
    Segment(SegReject),
}

/// What the headers say once every one has been walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalkEnd {
    /// The entry point lies in the file-backed part of a segment the loader
    /// maps executable, and has the ISA's instruction alignment. Only a
    /// segment that passed [`check_pt_load`] sets it, so it is also confined to
    /// the guard limit..`low_max` window: the one ELF address not checked
    /// directly, and it goes straight to the return-to-user as the PC.
    pub entry_ok: bool,
    /// `p_memsz` of the `PT_GNU_STACK` header: 0 for none or no request.
    pub stack_req: usize,
    /// The image carries the ABI note: built for this native ABI, so its stack
    /// request is held to the ceiling instead of clamped.
    pub native: bool,
}

/// An iterator over the accepted `PT_LOAD` segments of an image, in the order
/// the loader maps them; the first refusal ends it with an `Err`. Read the
/// rest of what the headers say with [`finish`](Self::finish) after the last
/// segment.
///
/// `elf` is the whole image, or its header bytes only when `file_len` is the
/// length of the file they belong to: every segment's file range is bounded by
/// `file_len`, every program header by `elf.len()`.
pub struct SegWalk<'a> {
    elf: &'a [u8],
    file_len: usize,
    hdr: ElfHeader,
    p: ImageParams,
    next: usize,
    done: bool,
    prev_seg_end: usize,
    prev_perms: Option<SegPerms>,
    headers_end: usize,
    entry_ok: bool,
    stack_req: usize,
    native: bool,
}

impl<'a> SegWalk<'a> {
    pub fn new(elf: &'a [u8], file_len: usize, hdr: ElfHeader, p: ImageParams) -> Self {
        SegWalk {
            elf,
            file_len,
            hdr,
            p,
            next: 0,
            done: false,
            // `p_vaddr >= prev_seg_end` is the ascending order the page-reuse
            // branch of the mapper relies on ([`check_pt_load`]).
            prev_seg_end: 0,
            prev_perms: None,
            // End of the ELF header and the program header table in the file
            // ([`check_exec_headers`]). Saturating: a bogus `e_phoff` only
            // widens the range no executable segment may cover.
            headers_end: hdr
                .phoff
                .saturating_add(hdr.phentsize.saturating_mul(hdr.phnum))
                .max(64),
            entry_ok: false,
            stack_req: 0,
            native: false,
        }
    }

    /// What the headers said, after the iterator ran out.
    pub fn finish(&self) -> WalkEnd {
        WalkEnd {
            entry_ok: self.entry_ok && self.hdr.entry % entry_align(self.p.machine) == 0,
            stack_req: self.stack_req,
            native: self.native,
        }
    }

    fn advance(&mut self) -> Result<Option<Segment>, WalkReject> {
        let elf = self.elf;
        while self.next < self.hdr.phnum {
            let i = self.next;
            self.next += 1;
            // Only 56 bytes are read of each entry, whatever `e_phentsize` says.
            let ph = i
                .checked_mul(self.hdr.phentsize)
                .and_then(|x| self.hdr.phoff.checked_add(x))
                .ok_or(WalkReject::ProgramTable)?;
            if ph.checked_add(56).map_or(true, |end| end > elf.len()) {
                return Err(WalkReject::ProgramTable);
            }
            let p_type = rd32(elf, ph);
            // The ABI note: an image built for another version of the native
            // ABI is refused (a mismatch would mean other calls). No note is
            // no refusal: a Linux program or a hand-assembled test has none.
            if p_type == PT_NOTE {
                if let Some(v) = abi_note_version(elf, ph, self.p.abi_note_type) {
                    if v != self.p.abi_version {
                        return Err(WalkReject::AbiVersion);
                    }
                    self.native = true;
                }
                continue;
            }
            if p_type == PT_GNU_STACK {
                self.stack_req = rd64(elf, ph + 40) as usize;
                continue;
            }
            if p_type != PT_LOAD {
                continue;
            }
            let flags = rd32(elf, ph + 4);
            let offset = rd64(elf, ph + 8) as usize;
            let vaddr = rd64(elf, ph + 16) as usize;
            let filesz = rd64(elf, ph + 32) as usize;
            let memsz = rd64(elf, ph + 40) as usize;
            let range = match check_pt_load(offset, vaddr, filesz, memsz, self.file_len, self.prev_seg_end, self.p.limits) {
                SegCheck::Empty => continue,
                SegCheck::Reject(r) => return Err(WalkReject::Segment(r)),
                SegCheck::Load(r) => r,
            };
            let perms = seg_perms(flags);
            check_page_sharing(self.prev_seg_end, self.prev_perms, vaddr, perms, self.p.limits.page_size)
                .map_err(WalkReject::Segment)?;
            if self.p.refuse_exec_headers {
                check_exec_headers(flags, offset, filesz, self.headers_end).map_err(WalkReject::Segment)?;
            }
            self.prev_seg_end = range.seg_end;
            self.prev_perms = Some(perms);
            // The entry must sit in the *file-backed* part of a segment the
            // loader maps executable. `p_memsz` would be too loose (its tail is
            // zero-filled BSS: an entry there executes zeros), and `PF_X` alone
            // too (a writable segment is mapped without the execute bit, so an
            // `RWX` one advertises X in the header and faults on fetch): the
            // check agrees with the mapper, not with the header.
            if flags & PF_X != 0 && flags & PF_W == 0 {
                let e = self.hdr.entry as usize;
                if e >= vaddr && e < vaddr.saturating_add(filesz) {
                    self.entry_ok = true;
                }
            }
            return Ok(Some(Segment { flags, offset, vaddr, filesz, range }));
        }
        Ok(None)
    }
}

impl Iterator for SegWalk<'_> {
    type Item = Result<Segment, WalkReject>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.advance() {
            Ok(Some(s)) => Some(Ok(s)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// What the copy loop of the mapper does with the page at `va` of a segment
/// (`vaddr`, `offset`, `filesz`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageCopy {
    /// The page holds no file byte of the segment.
    Nothing,
    /// `n` bytes from `src` (an offset into the blob) to `dest` (an offset in
    /// the page).
    Copy { dest: usize, src: usize, n: usize },
    /// The segment has file bytes here but the copy would leave the blob or the
    /// page (or overflow): the mapper skips it. A segment [`check_pt_load`]
    /// accepted never gets here.
    Skipped,
}

/// The copy of segment bytes into the page `[va, va + page_size)`, bounded by
/// the blob of `blob_len` bytes the bytes are read from.
///
/// When a segment starts mid-page (`vaddr > va`, a `.rodata` sharing the
/// `.text` page), its bytes land at `vaddr - va` in the page, not at offset 0,
/// which would clobber the preceding segment's code.
pub fn page_copy(va: usize, vaddr: usize, offset: usize, filesz: usize, page_size: usize, blob_len: usize) -> PageCopy {
    let page_end = va.saturating_add(page_size);
    let seg_file_end = vaddr.saturating_add(filesz);
    let copy_start = va.max(vaddr);
    let copy_end = page_end.min(seg_file_end);
    if copy_start >= copy_end {
        return PageCopy::Nothing;
    }
    let dest = if cfg!(feature = "elf-page-copy-canary") { 0 } else { copy_start - va };
    let src = offset.saturating_add(copy_start - vaddr);
    let n = copy_end - copy_start;
    match (src.checked_add(n), dest.checked_add(n)) {
        (Some(src_end), Some(dst_end)) if src_end <= blob_len && dst_end <= page_size => PageCopy::Copy { dest, src, n },
        _ => PageCopy::Skipped,
    }
}
