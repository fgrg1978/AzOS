// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Flattened Device Tree (FDT) parser for bare-metal RISC-V.
//!
//! No alloc, no heap, no external dependencies.  Parses the DTB blob
//! that firmware (OpenSBI / U-Boot) passes in `a1` at kernel entry and
//! returns a [`DtbInfo`] with the fields the kernel needs to
//! self-configure at boot.
//!
//! All multi-byte integers in FDT are **big-endian**.

// `cfg_attr` rather than a bare `#![no_std]` because this file is pulled whole
// into `tests/host/regression-tests` with `#[path]`, to exercise the real parser
// rather than a copy. An inner attribute is only legal at a crate root, so as a
// module it warned on every host build -- and warnings in host suites were not
// gated, so it warned for as long as it has existed.
//
// The guarantee is not weakened: this crate is only ever built for
// `target_os = "none"`, where the attribute applies, and there it would fail to
// compile at all if anything reached for `std`.
#![cfg_attr(target_os = "none", no_std)]

// ---------------------------------------------------------------
// FDT structure-block token constants
// ---------------------------------------------------------------
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Size of the FDT header in bytes (Devicetree Specification v0.4 §5.2).
/// Any blob claiming a `totalsize` below this cannot even contain its own
/// header, so it is rejected outright.
const FDT_HEADER_SIZE: usize = 40;

/// Hard upper bound on the blob size we are willing to walk.
///
/// WHY THIS EXISTS — do not remove as "redundant":
/// `totalsize` is an attacker/firmware-controlled u32 read from the very
/// first bytes of the blob, and it is the *only* bound `walk()` has. With
/// it unclamped, a blob claiming `totalsize = 0xFFFF_FFFF` licenses the
/// walker to march ~4 GiB past the end of physical RAM. That happens at
/// `kernel/src/main.rs` before the trap handler is useful, and with
/// `panic = "abort"` a load access fault there is a full board reset with
/// no diagnostics.
///
/// 4 MiB is deliberately generous: real DTBs are ~10-100 KiB (QEMU virt
/// with 8 harts is under 8 KiB), and even the largest server-class device
/// trees stay well under 1 MiB. Anything above this is malformed, not big.
///
/// Consequence of tripping this bound: `dtb_parse` returns `None` and the
/// kernel falls back to its hardcoded memory map / CPU count. That is a
/// degraded boot, never a fatal one — which is exactly why the bound is
/// safe to enforce strictly.
const MAX_DTB_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------
// Public types
// ---------------------------------------------------------------

/// Information extracted from a parsed FDT blob.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DtbInfo {
    /// Physical base address of main memory (from /memory reg).
    pub mem_base: usize,
    /// Size of main memory in bytes.
    pub mem_size: usize,
    /// Timer frequency in Hz (timebase-frequency).
    pub timer_freq: u64,
    /// Base address of the first UART / serial device.
    pub uart_base: usize,
    /// Base address of the PLIC: the `reg` of the first interrupt-controller
    /// node whose `compatible` names `riscv,plic0` or `sifive,plic-1.0.0`.
    /// 0 when there is none — as on `-machine virt,aia=aplic-imsic`, whose
    /// interrupt controllers are an APLIC pair and IMSIC groups (see
    /// [`Self::aplic_base`]).
    pub plic_base: usize,
    /// Number of cpu@N children under /cpus.
    pub num_cpus: usize,
    /// Compatible string from the root node (NUL-terminated, truncated).
    pub compatible: [u8; 64],
    /// `/cpus/cpu@0` declares the Sstc extension: its `riscv,isa` string has
    /// an `_sstc` segment, or its `riscv,isa-extensions` list has the entry
    /// `sstc`. Exact tokens only — `_sstcx` and `_ssstc` do not count.
    ///
    /// This says the hart implements `stimecmp`, not that the firmware let
    /// S-mode reach it (`menvcfg.STCE`); see `clint::timer_select`.
    pub isa_sstc: bool,
    /// `/cpus/cpu@0` declares the Zicboz extension (`cbo.zero`): same exact-
    /// token match as [`Self::isa_sstc`], against the `zicboz` token.
    ///
    /// This says the hart *implements* `cbo.zero`, not that it is safe to
    /// execute yet — RFC-0045 Tier 0 item 3 requires a trap-safe execution
    /// probe on top of this (`azos_arch::cbo::zicboz_select`), the same
    /// two-step discipline `isa_sstc` already uses for `stimecmp`.
    pub isa_zicboz: bool,
    /// `riscv,cboz-block-size` from `/cpus/cpu@0`: the block size in bytes
    /// `cbo.zero` operates on. `0` means the property was absent or
    /// malformed (wrong cell count) — Zicboz block size is implementation-
    /// defined and must never be assumed (64 is the common case, not a
    /// guarantee); see the Linux `riscv,cboz-block-size` device-tree binding
    /// and QEMU's `hw/riscv/virt.c`, which both source it the same way.
    pub cboz_block_size: u32,
    /// `/cpus/cpu@0` declares Zbb / Zbc / Zknh (exact tokens, as
    /// [`Self::isa_sstc`]) and V (a letter of the base segment of
    /// `riscv,isa`, or the entry `v` of `riscv,isa-extensions`): the inputs
    /// of the vDSO `hwcap` word (wave 13).
    pub isa_zbb: bool,
    pub isa_zbc: bool,
    pub isa_zknh: bool,
    pub isa_v: bool,
    /// Base address of the S-domain APLIC (RFC-0046 stage 1a), or 0 if
    /// none was found. `-machine virt,aia=aplic-imsic` has two
    /// `riscv,aplic` nodes: the M-domain root (has `riscv,children`,
    /// delegates to the child; firmware owns it) and the S-domain leaf
    /// (does not). This is the leaf. Telling them apart by that property
    /// needs no phandle table, which this parser does not keep.
    pub aplic_base: usize,
    /// `riscv,num-sources` from that same S-domain APLIC node.
    pub aplic_num_sources: u32,
    /// Base address of the S-level IMSIC group, or 0 if none was found.
    /// The same machine has two `riscv,imsics` nodes (M-level and
    /// S-level); this is the one whose own `interrupts-extended` names
    /// RISC-V cause 9 (Supervisor External) — the M-level one names 11.
    /// A single-node check, again with no phandle resolution.
    pub imsic_base: usize,
    /// `riscv,num-ids` from that same S-level IMSIC node.
    pub imsic_num_ids: u32,
    /// `riscv,guest-index-bits` from that node, 0 if absent (QEMU `virt`
    /// without guest interrupt files). It sets the per-hart file stride:
    /// `1 << (12 + guest_index_bits)`.
    pub imsic_guest_index_bits: u32,
}

impl DtbInfo {
    const fn zeroed() -> Self {
        Self {
            mem_base: 0,
            mem_size: 0,
            timer_freq: 0,
            uart_base: 0,
            plic_base: 0,
            num_cpus: 0,
            compatible: [0u8; 64],
            isa_sstc: false,
            isa_zicboz: false,
            cboz_block_size: 0,
            isa_zbb: false,
            isa_zbc: false,
            isa_zknh: false,
            isa_v: false,
            aplic_base: 0,
            aplic_num_sources: 0,
            imsic_base: 0,
            imsic_num_ids: 0,
            imsic_guest_index_bits: 0,
        }
    }
}

/// Does `prop` — the bytes of an ISA property — name `token` as a whole
/// extension segment/entry?
///
/// `riscv,isa` (`isa_extensions == false`) is one string: a base such as
/// `rv64imafdc` followed by `_`-separated multi-letter extensions, so
/// `token` must be a whole segment after the first. `riscv,isa-extensions`
/// is a list of NUL-separated strings, one extension each, and `token` must
/// be a whole entry. A NUL ends a segment in both. Matching a prefix instead
/// would take `sstcx` for `sstc`, and a substring would take `ssstc`.
fn isa_prop_has_token(prop: &[u8], isa_extensions: bool, token: &[u8]) -> bool {
    let mut start = 0usize;
    let mut index = 0usize;
    for i in 0..=prop.len() {
        let at_end = i == prop.len();
        let sep = at_end || prop[i] == 0 || (!isa_extensions && prop[i] == b'_');
        if !sep {
            continue;
        }
        let segment = &prop[start..i];
        // In `riscv,isa` the first segment is the base ISA, never an extension.
        if (isa_extensions || index > 0) && segment == token {
            return true;
        }
        // A NUL ends the `riscv,isa` string: what follows is padding.
        if !at_end && prop[i] == 0 && !isa_extensions {
            return false;
        }
        start = i + 1;
        index += 1;
    }
    false
}

/// Does `prop` — the bytes of an ISA property — name the Sstc extension?
/// See [`isa_prop_has_token`] for the exact-token-match rules.
pub fn isa_prop_has_sstc(prop: &[u8], isa_extensions: bool) -> bool {
    isa_prop_has_token(prop, isa_extensions, b"sstc")
}

/// Does `prop` — the bytes of an ISA property — name the Zicboz extension?
/// See [`isa_prop_has_token`] for the exact-token-match rules.
pub fn isa_prop_has_zicboz(prop: &[u8], isa_extensions: bool) -> bool {
    isa_prop_has_token(prop, isa_extensions, b"zicboz")
}

/// Does `prop` name the single-letter extension `letter` (lower case)? In
/// `riscv,isa` single letters live in the base segment after `rv32`/`rv64`
/// (`rv64imafdcvh`: `v` yes, `h` yes); in `riscv,isa-extensions` the letter
/// is an entry of its own.
pub fn isa_prop_has_letter(prop: &[u8], isa_extensions: bool, letter: u8) -> bool {
    if isa_extensions {
        return isa_prop_has_token(prop, true, &[letter]);
    }
    let end = prop.iter().position(|&c| c == b'_' || c == 0).unwrap_or(prop.len());
    let base = &prop[..end];
    if base.len() < 4 || !(base.starts_with(b"rv32") || base.starts_with(b"rv64")) {
        return false;
    }
    base[4..].contains(&letter)
}

/// Does `prop` name the multi-letter extension `token`? Public face of
/// [`isa_prop_has_token`] for the hwcap extensions.
pub fn isa_prop_has_ext(prop: &[u8], isa_extensions: bool, token: &[u8]) -> bool {
    isa_prop_has_token(prop, isa_extensions, token)
}

/// Does a `compatible` property's byte value name `token` as one of its
/// (possibly several) NUL-separated strings? A `compatible` list is
/// exactly the same shape `isa_prop_has_token` already parses for
/// `riscv,isa-extensions` (`isa_extensions = true`: every segment is
/// eligible, not just segments after the first) — reused rather than
/// re-implemented, per this crate's own discipline of one tokenizer for
/// one shape (see `isa_prop_has_sstc`/`isa_prop_has_zicboz` above).
fn compatible_has(prop: &[u8], token: &[u8]) -> bool {
    isa_prop_has_token(prop, true, token)
}

// ---------------------------------------------------------------
// FDT header (40 bytes)
// ---------------------------------------------------------------

struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    _off_mem_rsvmap: u32,
    version: u32,
    _last_comp_version: u32,
    _boot_cpuid_phys: u32,
    size_dt_strings: u32,
    _size_dt_struct: u32,
}

// ---------------------------------------------------------------
// Safe byte-level readers (no alignment requirements)
// ---------------------------------------------------------------

/// Read a big-endian u32 from `base + offset`.
///
/// # Safety
/// `base` must point to a valid DTB blob and `offset + 4` must be
/// within `totalsize`.
#[inline]
unsafe fn read_be32(base: *const u8, offset: usize) -> u32 {
    let p = base.add(offset);
    let b = [
        core::ptr::read(p),
        core::ptr::read(p.add(1)),
        core::ptr::read(p.add(2)),
        core::ptr::read(p.add(3)),
    ];
    u32::from_be_bytes(b)
}

/// Read a big-endian u64 from `base + offset`.
#[inline]
unsafe fn read_be64(base: *const u8, offset: usize) -> u64 {
    let hi = read_be32(base, offset) as u64;
    let lo = read_be32(base, offset + 4) as u64;
    (hi << 32) | lo
}

// ---------------------------------------------------------------
// Bounded C-string helpers
//
// EVERY one of these takes an exclusive `end` offset and refuses to read
// at or past it. WHY — do not "simplify" the bound away:
// FDT strings (node names in the structure block, property names in the
// strings block) are length-prefixed by *nothing*; they are terminated by
// a NUL that a malformed or truncated blob is under no obligation to
// provide. The blob comes from firmware via the raw `a1` register, so an
// unbounded scan walks off the end of the DTB and, moments later, off the
// end of physical RAM — a load access fault before the trap handler is
// usable, i.e. an unrecoverable board reset under `panic = "abort"`.
//
// The offsets are all derived from untrusted u32 header fields, so the
// address arithmetic uses checked adds too: `overflow-checks = true` turns
// a wrapping `offset + len` into a panic, which is the same board reset by
// a different route.
// ---------------------------------------------------------------

/// Read a NUL-terminated C string starting at `base + offset`, scanning no
/// further than `end` (exclusive, relative to `base`).
///
/// Returns the byte length **excluding** the terminator, or `None` if no
/// NUL was found before `end` — i.e. the blob is truncated/malformed and
/// the caller must abandon the walk rather than guess.
#[inline]
unsafe fn strlen_bounded(base: *const u8, offset: usize, end: usize) -> Option<usize> {
    let mut len: usize = 0;
    loop {
        let at = offset.checked_add(len)?;
        if at >= end {
            // Ran to the end of the blob without a terminator.
            return None;
        }
        if core::ptr::read(base.add(at)) == 0 {
            return Some(len);
        }
        len += 1;
    }
}

/// Compare a NUL-terminated C string at `base + offset` with `needle`,
/// reading nothing at or past `end` (exclusive, relative to `base`).
/// Returns `true` if they are equal up to the NUL.
///
/// Note the `+ 1`: this reads `needle.len()` bytes *plus* the terminator,
/// so the whole `needle.len() + 1` window must be inside the blob before a
/// single byte is touched. Checking only the first byte (as the caller
/// used to) leaves a name near the end of the blob reading past it.
#[inline]
unsafe fn streq(base: *const u8, offset: usize, end: usize, needle: &[u8]) -> bool {
    match offset.checked_add(needle.len()).and_then(|v| v.checked_add(1)) {
        Some(window_end) if window_end <= end => {}
        // Not enough blob left to hold `needle` + NUL: it cannot match, and
        // reading to find out would go out of bounds.
        _ => return false,
    }
    for (i, &ch) in needle.iter().enumerate() {
        if core::ptr::read(base.add(offset + i)) != ch {
            return false;
        }
    }
    core::ptr::read(base.add(offset + needle.len())) == 0
}

/// Check whether the C string at `base + offset` starts with `prefix`,
/// reading nothing at or past `end` (exclusive, relative to `base`).
///
/// Deliberately does **not** require a NUL after the prefix — callers use
/// it for genuine prefix matches like `"memory@"` against `"memory@80000000"`.
/// Only `prefix.len()` bytes need to be in bounds.
#[inline]
unsafe fn starts_with(base: *const u8, offset: usize, end: usize, prefix: &[u8]) -> bool {
    match offset.checked_add(prefix.len()) {
        Some(window_end) if window_end <= end => {}
        _ => return false,
    }
    for (i, &ch) in prefix.iter().enumerate() {
        if core::ptr::read(base.add(offset + i)) != ch {
            return false;
        }
    }
    true
}

/// Align `v` up to a 4-byte boundary, or `None` on overflow.
///
/// The input is an untrusted `prop_len`/name length straight out of the
/// blob; `(v + 3)` on a near-`usize::MAX` value panics under
/// `overflow-checks = true`, so the add is checked and the caller aborts
/// the walk instead.
#[inline]
fn align4_checked(v: usize) -> Option<usize> {
    v.checked_add(3).map(|x| x & !3)
}

// ---------------------------------------------------------------
// Header parser
// ---------------------------------------------------------------

unsafe fn parse_header(base: *const u8) -> Option<FdtHeader> {
    let magic = read_be32(base, 0);
    if magic != FDT_MAGIC {
        return None;
    }
    Some(FdtHeader {
        magic,
        totalsize: read_be32(base, 4),
        off_dt_struct: read_be32(base, 8),
        off_dt_strings: read_be32(base, 12),
        _off_mem_rsvmap: read_be32(base, 16),
        version: read_be32(base, 20),
        _last_comp_version: read_be32(base, 24),
        _boot_cpuid_phys: read_be32(base, 28),
        size_dt_strings: read_be32(base, 32),
        _size_dt_struct: read_be32(base, 36),
    })
}

// ---------------------------------------------------------------
// Structure-block walker
// ---------------------------------------------------------------

/// Internal state kept while walking the structure block.
struct Walker {
    /// Pointer to the beginning of the DTB blob.
    base: *const u8,
    /// Offset of the structure block relative to `base`.
    struct_off: usize,
    /// Offset of the strings block relative to `base`.
    strings_off: usize,
    /// Upper bound for the strings block.
    strings_end: usize,
    /// Total size of the DTB blob (safety bound).
    totalsize: usize,
    /// Current byte offset inside the structure block (relative to
    /// `struct_off`).
    cursor: usize,
    /// Nesting depth.
    depth: usize,
    /// Result being accumulated.
    info: DtbInfo,

    // -- contextual flags while walking ---
    /// True when we are inside a /memory node at depth 1.
    in_memory: bool,
    /// True when we are inside /cpus at depth 1.
    in_cpus: bool,
    /// True when we are inside /cpus/cpu@* at depth 2.
    in_cpu_child: bool,
    /// True when that child is `cpu@0`, whose ISA properties set `isa_sstc`.
    in_cpu0: bool,
    /// True when we are inside a node whose name starts with
    /// "serial" or "uart" at any depth.
    in_uart: bool,
    /// True when we are inside an interrupt-controller node.
    in_intc: bool,

    // -- AIA (APLIC/IMSIC) per-node scratch, RFC-0046 stage 1a --
    //
    // Buffered and committed at `handle_end_node`, NOT at property-read
    // time like `uart_base`/`plic_base` above: in QEMU's AIA DTB
    // (`qemu-system-riscv64 -machine virt,aia=aplic-imsic,dumpdtb=x.dtb`)
    // every `interrupt-controller@…` node's `reg` comes BEFORE its
    // `compatible`, so the kind of node is unknown when `reg` is read.
    // One scratch set suffices because APLIC/IMSIC nodes never nest (they
    // are siblings under /soc), so only one is ever "open" at a time.
    /// 0 = not yet classified, 1 = `riscv,aplic`, 2 = `riscv,imsics`.
    aia_kind: u8,
    /// This node's `reg` (address portion only, via `read_addr` — same as
    /// `uart_base`/`plic_base`).
    aia_reg: usize,
    /// `riscv,num-sources` (APLIC) or `riscv,num-ids` (IMSIC).
    aia_num_field: u32,
    /// `riscv,children` present — marks the AIA M-domain ROOT (delegates
    /// down), never the S-domain leaf this kernel wants.
    aia_has_children: bool,
    /// This IMSIC node's `interrupts-extended` contains RISC-V cause 9
    /// (Supervisor External) for at least one hart — marks the S-LEVEL
    /// group, never the M-level one.
    aia_s_ext: bool,
    /// `riscv,guest-index-bits`, 0 if the property was absent.
    aia_guest_bits: u32,
    /// This interrupt controller's `compatible` names a PLIC
    /// (`riscv,plic0` / `sifive,plic-1.0.0`). Committed to `plic_base` at
    /// `handle_end_node`, like the AIA kinds above.
    intc_is_plic: bool,

    /// #address-cells in the current context (default 2 at root).
    /// Stack is indexed by `depth`; index 0 is the implicit pre-root default.
    /// `/cpus` typically declares `#address-cells=1, #size-cells=0`, which
    /// must NOT bleed into a sibling `/memory` reg parse — hence per-scope
    /// tracking.
    address_cells: u32,
    /// #size-cells in the current context (default 1 at root).
    size_cells: u32,
    /// Saved (address_cells, size_cells) per nesting depth, restored on
    /// FDT_END_NODE. Up to 8 levels deep is plenty for any realistic FDT.
    cells_stack: [(u32, u32); 8],

    /// Depth at which the current "interesting" node was entered,
    /// so we know when we leave it.
    uart_depth: usize,
    intc_depth: usize,

    /// Raw `reg` cell(s) of every `/cpus/cpu@N` node, in document order —
    /// aarch64's MPIDR affinity bits (Aff2:Aff1:Aff0, and Aff3 when
    /// `#address-cells` is 2) or RISC-V's hart id, same property, ISA-
    /// specific meaning. Populated here (not exposed on [`DtbInfo`]) so
    /// [`dtb_cpu_regs`] can reuse this walker's exact depth/cells tracking
    /// instead of a second, easily-divergent implementation. Sized to
    /// `MAX_CPU_REG`, matching the largest `MAX_HARTS` any board in this
    /// tree configures; a node past that count is still counted toward
    /// [`DtbInfo::num_cpus`] but its `reg` is not recorded.
    cpu_reg: [u64; MAX_CPU_REG],
    /// Number of entries written into `cpu_reg` so far.
    cpu_reg_count: usize,

    /// [`dtb_pci_host`]'s per-node scratch and result.
    pci: PciScratch,
    pci_host: Option<PciHost>,

    /// [`dtb_pl011_irq`]'s per-node scratch and result. Compiled out on
    /// riscv64, which has no PL011 and never calls that function, so the
    /// riscv64 walker is the same code it was.
    #[cfg(not(target_arch = "riscv64"))]
    con: ConsoleScratch,
    #[cfg(not(target_arch = "riscv64"))]
    pl011: Option<Pl011Irq>,
}

/// Bound on [`Walker::cpu_reg`] — matches `kernel::MAX_HARTS` (8), the
/// largest per-hart table any board build in this tree sizes. A DTB
/// reporting more `cpu@` nodes than this still parses; the extra ones are
/// counted in [`DtbInfo::num_cpus`] but their `reg` is not recorded, the
/// same truncate-not-fail shape [`dtb_parse`]'s `compatible` copy uses.
pub const MAX_CPU_REG: usize = azos_limits::NR_CPUS;

impl Walker {
    /// Read the next big-endian u32 token from the structure block and
    /// advance the cursor by 4.
    ///
    /// # Caller obligation — this method performs NO bounds check
    /// The caller must already have proved, with checked arithmetic, that
    /// `struct_off + cursor + 4 <= totalsize`. `walk()` does this before
    /// reading each token and `handle_prop()` does it for the 8 bytes of
    /// property header it consumes.
    ///
    /// Both the read and the raw `+` below depend on that: an unproved
    /// call reads outside the blob, and a wrapping `struct_off + cursor`
    /// panics under `overflow-checks = true` — either way a board reset,
    /// since this runs before the trap handler is useful. If you add a new
    /// token handler, you owe it that check.
    #[inline]
    unsafe fn next_u32(&mut self) -> u32 {
        let off = self.struct_off + self.cursor;
        self.cursor += 4;
        read_be32(self.base, off)
    }

    /// Resolve a property name from the strings block.
    ///
    /// `nameoff` is an untrusted u32 from the blob, so the add is checked;
    /// `strings_end` was clamped to `totalsize` in `dtb_parse`, and `streq`
    /// re-checks the full `needle.len() + 1` window against it. The old
    /// code guarded only the *first* byte, which let a property name sitting
    /// at the tail of the strings block read past the end of the blob.
    #[inline]
    unsafe fn prop_name_eq(&self, nameoff: u32, needle: &[u8]) -> bool {
        let off = match self.strings_off.checked_add(nameoff as usize) {
            Some(v) => v,
            None => return false,
        };
        if off >= self.strings_end {
            return false;
        }
        streq(self.base, off, self.strings_end, needle)
    }

    /// Walk the entire structure block, populating `self.info`.
    ///
    /// Handlers return `false` to abort the walk when the blob turns out to
    /// be truncated or malformed. Returning a value (rather than setting a
    /// flag) means the compiler forces every call site to deal with it — a
    /// missed abort here is an out-of-bounds read, not a wrong answer.
    unsafe fn walk(&mut self) {
        loop {
            // Safety bound — the 4-byte token itself must lie entirely
            // inside the blob. Checked adds because `struct_off` and
            // `cursor` both derive from untrusted blob contents and a wrap
            // would panic (= board reset) under `overflow-checks = true`.
            let token_end = match self
                .struct_off
                .checked_add(self.cursor)
                .and_then(|v| v.checked_add(4))
            {
                Some(v) => v,
                None => break,
            };
            if token_end > self.totalsize {
                break;
            }

            let token = self.next_u32();

            let keep_walking = match token {
                FDT_BEGIN_NODE => self.handle_begin_node(),
                // Asymmetry is deliberate: handle_end_node only pops
                // bookkeeping state and reads no blob memory, so it has no
                // failure mode to report.
                FDT_END_NODE => {
                    self.handle_end_node();
                    true
                }
                FDT_PROP => self.handle_prop(),
                FDT_NOP => true, /* skip */
                FDT_END => false,
                _ => false, // malformed
            };
            if !keep_walking {
                break;
            }
        }
    }

    /// Returns `false` if the node name is unterminated inside the blob, in
    /// which case the walk must stop.
    unsafe fn handle_begin_node(&mut self) -> bool {
        let name_off = match self.struct_off.checked_add(self.cursor) {
            Some(v) => v,
            None => return false,
        };
        // walk() only proved the 4-byte *token* is inside the blob; nothing
        // says a NUL follows the name. A blob whose last token is
        // FDT_BEGIN_NODE with an unterminated name would otherwise scan RAM
        // until it happened to hit a zero byte. Bound the scan at
        // `totalsize` — node names live in the structure block, so the blob
        // bound applies here, NOT `strings_end`.
        let name_len = match strlen_bounded(self.base, name_off, self.totalsize) {
            Some(l) => l,
            None => return false, // truncated blob — abandon the walk.
        };
        // Advance past name + NUL, then align to 4.
        let step = match name_len.checked_add(1).and_then(align4_checked) {
            Some(s) => s,
            None => return false,
        };
        self.cursor = match self.cursor.checked_add(step) {
            Some(c) => c,
            None => return false,
        };
        self.depth += 1;

        // Push the parent's (address_cells, size_cells) so any override
        // in this child node can be popped on FDT_END_NODE without leaking
        // into siblings (e.g. /cpus declares 1/0, /memory must still see 2/2).
        if self.depth < self.cells_stack.len() {
            self.cells_stack[self.depth] = (self.address_cells, self.size_cells);
        }
        #[cfg(not(target_arch = "riscv64"))]
        self.con_begin();
        self.pci_begin();

        // Detect which node we entered.
        // NOTE: walk() starts at depth=0; entering the FDT_BEGIN_NODE for the
        // (anonymous) root takes depth → 1. Root's direct children are
        // therefore at depth 2 (not 1, as an earlier version assumed —
        // that mistake silently zeroed `mem_base`, `num_cpus`, `timer_freq`
        // because /memory and /cpus were never recognised).
        // All of the name comparisons below are bounded by `totalsize`: the
        // name lives in the structure block and `strlen_bounded` above has
        // already proved its NUL sits inside the blob, so a needle longer
        // than the name simply mismatches instead of reading past the end.
        let end = self.totalsize;

        if self.depth == 2 {
            // Root-level children.
            if streq(self.base, name_off, end, b"memory")
                || starts_with(self.base, name_off, end, b"memory@")
            {
                self.in_memory = true;
            } else if streq(self.base, name_off, end, b"cpus") {
                self.in_cpus = true;
            }
        }

        if self.depth == 3 && self.in_cpus {
            if starts_with(self.base, name_off, end, b"cpu@") {
                self.in_cpu_child = true;
                self.in_cpu0 = streq(self.base, name_off, end, b"cpu@0");
                self.info.num_cpus += 1;
            }
        }

        // UART / serial can appear at any depth.
        if !self.in_uart {
            if starts_with(self.base, name_off, end, b"serial")
                || starts_with(self.base, name_off, end, b"uart")
            {
                self.in_uart = true;
                self.uart_depth = self.depth;
            }
        }

        // Interrupt controller.
        if !self.in_intc {
            if starts_with(self.base, name_off, end, b"interrupt-controller")
                || starts_with(self.base, name_off, end, b"plic")
            {
                self.in_intc = true;
                self.intc_depth = self.depth;
                // Fresh scratch for THIS node — see the struct field docs
                // on why AIA classification is buffered and committed at
                // `handle_end_node`, not here.
                self.aia_kind = 0;
                self.aia_reg = 0;
                self.aia_num_field = 0;
                self.aia_has_children = false;
                self.aia_s_ext = false;
                self.aia_guest_bits = 0;
                self.intc_is_plic = false;
            }
        }

        true
    }

    unsafe fn handle_end_node(&mut self) {
        #[cfg(not(target_arch = "riscv64"))]
        self.con_end();
        self.pci_end();
        // Mirrors the depth correction in handle_begin_node: root children
        // live at depth 2, /cpus/cpu@N at depth 3.
        if self.depth == 2 {
            self.in_memory = false;
            self.in_cpus = false;
        }
        if self.depth == 3 {
            self.in_cpu_child = false;
            self.in_cpu0 = false;
        }
        if self.in_uart && self.depth == self.uart_depth {
            self.in_uart = false;
        }
        if self.in_intc && self.depth == self.intc_depth {
            // Commit this node's buffered AIA scratch now that its own
            // `compatible` (read somewhere in the middle of its property
            // list — order is not guaranteed) is known. `== 0` guards
            // (not `unconditional overwrite`) mean the FIRST matching
            // node wins if a future machine ever had more than the two
            // this task's dumped DTBs show, same "first one wins" rule
            // `uart_base`/`plic_base` already use.
            match self.aia_kind {
                1 if !self.aia_has_children && self.info.aplic_base == 0 => {
                    self.info.aplic_base = self.aia_reg;
                    self.info.aplic_num_sources = self.aia_num_field;
                }
                2 if self.aia_s_ext && self.info.imsic_base == 0 => {
                    self.info.imsic_base = self.aia_reg;
                    self.info.imsic_num_ids = self.aia_num_field;
                    self.info.imsic_guest_index_bits = self.aia_guest_bits;
                }
                _ => {}
            }
            // Same end-of-node commit for the PLIC: its `compatible` may
            // follow its `reg`. First PLIC wins.
            if self.intc_is_plic && self.info.plic_base == 0 {
                self.info.plic_base = self.aia_reg;
            }
            self.in_intc = false;
        }
        // Restore parent's (address_cells, size_cells) — critical so a
        // /cpus override of 1/0 doesn't leak into the sibling /memory parse.
        if self.depth > 0 && self.depth < self.cells_stack.len() {
            let (ac, sc) = self.cells_stack[self.depth];
            self.address_cells = ac;
            self.size_cells    = sc;
        }
        if self.depth > 0 {
            self.depth -= 1;
        }
    }

    /// Returns `false` if the property header or payload runs past the end
    /// of the blob, in which case the walk must stop.
    unsafe fn handle_prop(&mut self) -> bool {
        // walk() validated only the 4-byte FDT_PROP token. The property
        // header is two MORE big-endian u32 (len, nameoff) — 8 bytes that
        // used to be read with no bound at all, so a blob whose final token
        // was FDT_PROP read 8 bytes past the end regardless of how well the
        // header offsets checked out.
        let hdr_off = match self.struct_off.checked_add(self.cursor) {
            Some(v) => v,
            None => return false,
        };
        match hdr_off.checked_add(8) {
            Some(e) if e <= self.totalsize => {}
            _ => return false,
        }

        let prop_len = self.next_u32() as usize;
        let nameoff = self.next_u32();
        let data_off = hdr_off + 8; // == struct_off + cursor, already bounded

        // `prop_len` is an untrusted u32: bound the whole payload ONCE here
        // so every reader below (the `compatible` copy, the cells reads,
        // parse_mem_reg, read_addr) is operating inside the blob by
        // construction. Without this, `#address-cells` alone would read 4
        // bytes at an entirely unchecked `data_off`.
        let data_end = match data_off.checked_add(prop_len) {
            Some(v) => v,
            None => return false,
        };
        if data_end > self.totalsize {
            return false;
        }

        // Advance past data, aligned to 4.
        let step = match align4_checked(prop_len) {
            Some(s) => s,
            None => return false,
        };
        self.cursor = match self.cursor.checked_add(step) {
            Some(c) => c,
            None => return false,
        };

        #[cfg(not(target_arch = "riscv64"))]
        self.con_prop(nameoff, data_off, prop_len);
        self.pci_prop(nameoff, data_off, prop_len);

        // --- root compatible ---
        if self.depth == 1
            && !self.in_memory
            && !self.in_cpus
            && self.prop_name_eq(nameoff, b"compatible")
        {
            let copy_len = if prop_len < 64 { prop_len } else { 63 };
            for i in 0..copy_len {
                self.info.compatible[i] = core::ptr::read(self.base.add(data_off + i));
            }
            // Ensure NUL termination.
            self.info.compatible[copy_len] = 0;
            return true;
        }

        // --- #address-cells / #size-cells (used for reg parsing) ---
        if self.prop_name_eq(nameoff, b"#address-cells") && prop_len == 4 {
            self.address_cells = read_be32(self.base, data_off);
        }
        if self.prop_name_eq(nameoff, b"#size-cells") && prop_len == 4 {
            self.size_cells = read_be32(self.base, data_off);
        }

        // --- memory reg ---
        //
        // `depth == 2` (not just `in_memory`, which is not itself
        // depth-scoped — it only turns off again on FDT_END_NODE at depth
        // 2) restricts this to /memory's OWN `reg`, not a `reg` belonging to
        // some nested child a hostile blob placed underneath it. Without
        // this, a `/memory/evil { reg = ...; }` subnode's `reg` — read with
        // whatever `#address-cells`/`#size-cells` happen to be in scope at
        // that deeper level — would silently overwrite `mem_base`/
        // `mem_size` as if it were /memory's own property. Real DTBs never
        // nest a `reg`-bearing child under `/memory`, so this is no change
        // for a real blob.
        if self.in_memory && self.depth == 2 && self.prop_name_eq(nameoff, b"reg") {
            self.parse_mem_reg(data_off, prop_len);
            return true;
        }

        // --- timebase-frequency (in /cpus or /cpus/cpu@N) ---
        // `in_cpus` at depth 2 is /cpus itself; `in_cpu_child` at depth 3 is
        // a direct `cpu@N` child. Depth-check both for the same reason as
        // the memory `reg` above — neither flag alone proves we are still
        // at that exact level, only that we have not yet popped back out of
        // it.
        if ((self.depth == 2 && self.in_cpus) || (self.depth == 3 && self.in_cpu_child))
            && self.prop_name_eq(nameoff, b"timebase-frequency")
        {
            if prop_len == 4 {
                self.info.timer_freq = read_be32(self.base, data_off) as u64;
            } else if prop_len == 8 {
                self.info.timer_freq = read_be64(self.base, data_off);
            }
            return true;
        }

        // --- ISA extensions of cpu@0 (Sstc, Zicboz) ---
        // The node's own properties only (depth 3), not those of a child such
        // as its `interrupt-controller`.
        if self.depth == 3 && self.in_cpu_child && self.in_cpu0 {
            let isa = self.prop_name_eq(nameoff, b"riscv,isa");
            let list = !isa && self.prop_name_eq(nameoff, b"riscv,isa-extensions");
            if isa || list {
                // In the blob by construction: `data_end <= totalsize` above.
                let prop = core::slice::from_raw_parts(self.base.add(data_off), prop_len);
                if isa_prop_has_sstc(prop, list) {
                    self.info.isa_sstc = true;
                }
                if isa_prop_has_zicboz(prop, list) {
                    self.info.isa_zicboz = true;
                }
                self.info.isa_zbb |= isa_prop_has_token(prop, list, b"zbb");
                self.info.isa_zbc |= isa_prop_has_token(prop, list, b"zbc");
                self.info.isa_zknh |= isa_prop_has_token(prop, list, b"zknh");
                self.info.isa_v |= isa_prop_has_letter(prop, list, b'v');
                return true;
            }

            // `riscv,cboz-block-size`: one u32 cell, the block size in bytes
            // `cbo.zero` operates on (Linux device-tree binding, mirrored by
            // QEMU's `hw/riscv/virt.c` when `-cpu ...,zicboz=true`). A
            // `prop_len != 4` is a malformed property, not a value to guess
            // from — left at its zeroed default, which the runtime probe
            // (`azos_arch::cbo::zicboz_select`) treats as "block size
            // unknown, fast path stays off" regardless of `isa_zicboz`.
            if self.prop_name_eq(nameoff, b"riscv,cboz-block-size") && prop_len == 4 {
                self.info.cboz_block_size = read_be32(self.base, data_off);
                return true;
            }
        }

        // --- cpu reg (MPIDR affinity on aarch64, hart id on RISC-V) ---
        //
        // Assumes each `cpu@` node carries exactly one `reg` property —
        // true for every real and QEMU-generated DTB (the ARM and RISC-V
        // cpu bindings both require it) — so this stays in document order
        // with `DtbInfo::num_cpus`'s own per-node increment in
        // `handle_begin_node` without needing a separate index.
        if self.depth == 3
            && self.in_cpu_child
            && self.cpu_reg_count < self.cpu_reg.len()
            && self.prop_name_eq(nameoff, b"reg")
        {
            // Only 1 or 2 address cells are read — `.max(1)` used to coerce
            // an untrusted `#address-cells` of 0 into "1 cell" instead of
            // refusing it; every real `/cpus` node declares 1 (RISC-V hart
            // id) or 2 (aarch64 cluster'd MPIDR), so requiring exactly that
            // is no change for a real blob. The bounds check
            // (`prop_len >= cells * 4`) already made this read safe even
            // with the old coercion — no OOB here, unlike `parse_mem_reg` —
            // this is a correctness/consistency fix, not a bounds fix.
            let ac = self.address_cells;
            if matches!(ac, 1 | 2) {
                let cells = ac as usize;
                if prop_len >= cells * 4 {
                    let val = if cells >= 2 {
                        read_be64(self.base, data_off)
                    } else {
                        read_be32(self.base, data_off) as u64
                    };
                    self.cpu_reg[self.cpu_reg_count] = val;
                    self.cpu_reg_count += 1;
                }
            }
            return true;
        }

        // --- UART reg (take only the first one found) ---
        // `depth == uart_depth`, not just `in_uart` (which stays true for
        // every descendant until we pop back out): a child node nested
        // under the UART node could otherwise overwrite `uart_base` with
        // its own unrelated `reg`. `uart_base`/`plic_base` are only ever
        // logged today (`kernel/src/main.rs` maps MMIO from its own
        // hardcoded constants, not these fields), so this is a correctness
        // fix, not a bounds one — kept consistent with the memory/timer
        // scoping above rather than left as the odd one out.
        if self.in_uart
            && self.depth == self.uart_depth
            && self.info.uart_base == 0
            && self.prop_name_eq(nameoff, b"reg")
        {
            self.info.uart_base = self.read_addr(data_off, prop_len);
            return true;
        }

        // --- Interrupt-controller reg (PLIC, APLIC, IMSIC) ---
        if self.in_intc
            && self.depth == self.intc_depth
            && self.prop_name_eq(nameoff, b"reg")
        {
            // Buffered, committed at `handle_end_node` once the node's
            // `compatible` is known — see the struct field docs. The PLIC
            // used to take the first interrupt controller's `reg` here,
            // whatever it was: on `virt,aia=aplic-imsic` that labelled the
            // APLIC as the PLIC in the `[DTB]` boot line and in `hwbus`.
            self.aia_reg = self.read_addr(data_off, prop_len);
            return true;
        }

        // --- AIA (APLIC/IMSIC) node classification + fields ---
        if self.in_intc && self.depth == self.intc_depth {
            if self.prop_name_eq(nameoff, b"compatible") {
                let prop = core::slice::from_raw_parts(self.base.add(data_off), prop_len);
                if compatible_has(prop, b"riscv,aplic") {
                    self.aia_kind = 1;
                } else if compatible_has(prop, b"riscv,imsics") {
                    self.aia_kind = 2;
                }
                self.intc_is_plic = compatible_has(prop, b"riscv,plic0")
                    || compatible_has(prop, b"sifive,plic-1.0.0");
                return true;
            }
            if self.prop_name_eq(nameoff, b"riscv,children") {
                self.aia_has_children = true;
                return true;
            }
            if (self.prop_name_eq(nameoff, b"riscv,num-sources")
                || self.prop_name_eq(nameoff, b"riscv,num-ids"))
                && prop_len == 4
            {
                self.aia_num_field = read_be32(self.base, data_off);
                return true;
            }
            if self.prop_name_eq(nameoff, b"riscv,guest-index-bits") && prop_len == 4 {
                self.aia_guest_bits = read_be32(self.base, data_off);
                return true;
            }
            if self.prop_name_eq(nameoff, b"interrupts-extended") {
                // Pairs of (phandle, cause) cells, 8 bytes each — every
                // `riscv,cpu-intc` node this crate has ever seen declares
                // `#interrupt-cells = <1>`, so each entry is exactly one
                // phandle cell + one cause cell. Cause 9 is RISC-V's
                // Supervisor External code (privileged spec) — the S-level
                // IMSIC group raises it, the M-level one raises 11. This
                // reads every pair rather than only the first: nothing
                // requires every hart's entry to name the same cause.
                let mut off = 0usize;
                while off + 8 <= prop_len {
                    let cause = read_be32(self.base, data_off + off + 4);
                    if cause == 9 {
                        self.aia_s_ext = true;
                        break;
                    }
                    off += 8;
                }
                return true;
            }
        }

        true
    }

    /// Parse a "reg" property for /memory.  Handles #address-cells = 1 or 2,
    /// #size-cells = 1 or 2 — the only two encodings the reads below
    /// actually implement.
    ///
    /// WHY the explicit `ac`/`sc` match — do not "simplify" back to the old
    /// `if ac == 2 { .. } else { .. 1 cell .. }` / `if sc == 2 { .. } else
    /// { .. 1 cell .. }` shape:
    ///
    /// `#address-cells`/`#size-cells` are untrusted u32 read straight from
    /// the blob with no range check on the value itself (see the property
    /// handler above — any u32 is accepted). The old code's `else` branches
    /// silently treated *every* value other than 2 — including 0 and
    /// anything >= 3 — as "1 cell", while `entry_bytes = (ac + sc) * 4` used
    /// the *actual* (unclamped) `ac`/`sc` to size the bounds check. For
    /// `#size-cells = 0` specifically (spec-legal — some nodes declare it —
    /// and reachable simply by placing a `#size-cells` property directly on
    /// /memory itself, or on any node still flagged `in_memory` at the time
    /// the `reg` property is seen, `in_memory` not being depth-scoped),
    /// `entry_bytes` accounted for `ac` cells only, `prop_len == ac * 4`
    /// passed the check with nothing to spare, and the code then *still*
    /// unconditionally read a 4-byte size field at `data_off + ac * 4`
    /// (`sc == 2` is false, so the `else` branch fired) — 4 bytes that were
    /// never validated to be inside `prop_len`, `data_end` or `totalsize`.
    /// Put the malformed `reg` property at (or within 4 bytes of) the end of
    /// the blob and this reads past the whole allocation: a load fault
    /// before the trap handler is useful (an unconditional board reset
    /// under `panic = "abort"`) on hardware, or on a host `Vec`-backed blob
    /// in tests, memory the allocator does not own. `entry_bytes` itself
    /// also multiplied two untrusted u32-derived values with a raw (not
    /// checked) `+`/`*`, inconsistent with every other untrusted-length
    /// computation in this file — moot now that `ac`/`sc` are bounded to
    /// {1, 2} below, `(2 + 2) * 4` cannot overflow any `usize`.
    ///
    /// Refusing anything else (leaving `mem_base`/`mem_size` at their zeroed
    /// default, exactly like a missing `/memory` node) matches every real
    /// DTB this parser has ever seen — QEMU and both supported boards always
    /// declare 1 or 2 cells for `/memory` — so this changes nothing for a
    /// blob this tree actually boots.
    unsafe fn parse_mem_reg(&mut self, data_off: usize, prop_len: usize) {
        let ac = self.address_cells;
        let sc = self.size_cells;
        if !matches!(ac, 1 | 2) || !matches!(sc, 1 | 2) {
            return;
        }
        let entry_bytes = (ac as usize + sc as usize) * 4;
        if prop_len < entry_bytes {
            return;
        }
        let base = if ac == 2 {
            read_be64(self.base, data_off) as usize
        } else {
            read_be32(self.base, data_off) as usize
        };
        let size_off = data_off + ac as usize * 4;
        let size = if sc == 2 {
            read_be64(self.base, size_off) as usize
        } else {
            read_be32(self.base, size_off) as usize
        };
        self.info.mem_base = base;
        self.info.mem_size = size;
    }

    /// Read the first address from a "reg" property, respecting
    /// #address-cells. Only `#address-cells` of 1 or 2 are read. `0` was
    /// already refused before this change (`min == 0` below); what is new
    /// is refusing >= 3, which the old `if ac >= 2 { 8 bytes } else { 4
    /// bytes }` shape silently mis-decoded as 2 cells instead — mirroring
    /// [`Self::parse_mem_reg`]'s policy. UART/PLIC nodes in every real DTB
    /// this parser sees declare 1 or 2, so this is no change in accepted
    /// behaviour for a real blob.
    unsafe fn read_addr(&self, data_off: usize, prop_len: usize) -> usize {
        let ac = self.address_cells;
        if !matches!(ac, 1 | 2) {
            return 0;
        }
        let min = ac as usize * 4;
        if prop_len < min {
            return 0;
        }
        if ac == 2 {
            read_be64(self.base, data_off) as usize
        } else {
            read_be32(self.base, data_off) as usize
        }
    }

    // -- PCI host bridge ([`dtb_pci_host`]) --
    //
    // Same buffering as the PL011 scratch below: a node's properties all
    // precede its first child, so the node is complete at its first child's
    // FDT_BEGIN_NODE or at its own FDT_END_NODE. `reg` is decoded with the
    // PARENT's cells (captured when the node opens, before the node's own
    // `#address-cells = <3>` can change `self.address_cells`); `ranges`
    // with the node's own `#address-cells`/`#size-cells` for the child side
    // and the parent's `#address-cells` for the CPU side.

    /// Called right after `depth` was incremented for a new node.
    fn pci_begin(&mut self) {
        self.pci_commit();
        self.pci = PciScratch {
            depth: self.depth,
            parent_ac: self.address_cells,
            parent_sc: self.size_cells,
            ..PciScratch::NEW
        };
    }

    /// Called at FDT_END_NODE, before `depth` is decremented.
    fn pci_end(&mut self) {
        if self.pci.depth == self.depth {
            self.pci_commit();
        }
    }

    fn pci_commit(&mut self) {
        let c = self.pci;
        self.pci = PciScratch::NEW;
        if c.depth == 0 || !c.is_ecam || self.pci_host.is_some() {
            return;
        }
        // SAFETY (both slices): `handle_prop` bounded every property payload
        // to the blob before `pci_prop` recorded its offset and length.
        let reg = unsafe { core::slice::from_raw_parts(self.base.add(c.reg_off), c.reg_len) };
        let Some((ecam_base, ecam_size)) = decode_reg_first(reg, c.parent_ac, c.parent_sc) else {
            return;
        };
        let ranges = unsafe { core::slice::from_raw_parts(self.base.add(c.ranges_off), c.ranges_len) };
        let r = decode_pci_ranges(ranges, c.own_ac, c.parent_ac, c.own_sc);
        self.pci_host = Some(PciHost { ecam_base, ecam_size, io: r.io, mem32: r.mem32, mem64: r.mem64 });
    }

    /// Record this property if [`dtb_pci_host`] needs it. Never consumes it.
    unsafe fn pci_prop(&mut self, nameoff: u32, data_off: usize, prop_len: usize) {
        if self.pci.depth != self.depth {
            return;
        }
        if self.prop_name_eq(nameoff, b"compatible") {
            let prop = core::slice::from_raw_parts(self.base.add(data_off), prop_len);
            self.pci.is_ecam = compatible_has(prop, b"pci-host-ecam-generic");
        } else if self.prop_name_eq(nameoff, b"reg") {
            self.pci.reg_off = data_off;
            self.pci.reg_len = prop_len;
        } else if self.prop_name_eq(nameoff, b"ranges") {
            self.pci.ranges_off = data_off;
            self.pci.ranges_len = prop_len;
        } else if self.prop_name_eq(nameoff, b"#address-cells") && prop_len == 4 {
            self.pci.own_ac = read_be32(self.base, data_off);
        } else if self.prop_name_eq(nameoff, b"#size-cells") && prop_len == 4 {
            self.pci.own_sc = read_be32(self.base, data_off);
        }
    }

    // -- PL011 console interrupt ([`dtb_pl011_irq`]) --
    //
    // A node's properties all come before its first child node (FDT
    // structure block rule), so the node whose properties were being
    // buffered is complete at the next FDT_BEGIN_NODE (its first child) or
    // at its own FDT_END_NODE, whichever comes first. Both commit.

    /// Called right after `depth` was incremented for a new node.
    #[cfg(not(target_arch = "riscv64"))]
    fn con_begin(&mut self) {
        self.con_commit();
        self.con = ConsoleScratch { depth: self.depth, ..ConsoleScratch::NEW };
    }

    /// Called at FDT_END_NODE, before `depth` is decremented.
    #[cfg(not(target_arch = "riscv64"))]
    fn con_end(&mut self) {
        if self.con.depth == self.depth {
            self.con_commit();
        }
    }

    #[cfg(not(target_arch = "riscv64"))]
    fn con_commit(&mut self) {
        let c = self.con;
        self.con = ConsoleScratch::NEW;
        if c.depth == 0 || !c.is_pl011 || c.base == 0 || self.pl011.is_some() {
            return;
        }
        if let Some(irq) = decode_gic_spi(c.cells) {
            self.pl011 = Some(Pl011Irq { base: c.base, intid: irq.0, edge: irq.1 });
        }
    }

    /// Record this property if it is one [`dtb_pl011_irq`] needs. Never
    /// consumes it: the other extractors still see every property.
    #[cfg(not(target_arch = "riscv64"))]
    unsafe fn con_prop(&mut self, nameoff: u32, data_off: usize, prop_len: usize) {
        if self.con.depth != self.depth {
            return;
        }
        if self.prop_name_eq(nameoff, b"compatible") {
            let prop = core::slice::from_raw_parts(self.base.add(data_off), prop_len);
            self.con.is_pl011 = compatible_has(prop, b"arm,pl011");
        } else if self.prop_name_eq(nameoff, b"reg") {
            self.con.base = self.read_addr(data_off, prop_len);
        } else if self.prop_name_eq(nameoff, b"interrupts") {
            // Exactly one 3-cell GIC specifier. Any other length is either
            // a different interrupt parent (#interrupt-cells != 3) or more
            // than one line; neither is something to guess at.
            self.con.cells = if prop_len == 12 {
                Some([
                    read_be32(self.base, data_off),
                    read_be32(self.base, data_off + 4),
                    read_be32(self.base, data_off + 8),
                ])
            } else {
                None
            };
        }
    }
}

/// Per-node scratch for [`dtb_pl011_irq`]. `depth == 0` means "no node".
#[cfg(not(target_arch = "riscv64"))]
#[derive(Clone, Copy)]
struct ConsoleScratch {
    depth: usize,
    is_pl011: bool,
    base: usize,
    cells: Option<[u32; 3]>,
}

#[cfg(not(target_arch = "riscv64"))]
impl ConsoleScratch {
    const NEW: Self = Self { depth: 0, is_pl011: false, base: 0, cells: None };
}

/// Per-node scratch for [`dtb_pci_host`]. `depth == 0` means "no node".
#[derive(Clone, Copy)]
struct PciScratch {
    depth: usize,
    is_ecam: bool,
    /// The parent's `#address-cells`/`#size-cells`, for `reg` and the CPU
    /// side of `ranges`.
    parent_ac: u32,
    parent_sc: u32,
    /// The node's own `#address-cells`/`#size-cells` (PCI bus side).
    own_ac: u32,
    own_sc: u32,
    reg_off: usize,
    reg_len: usize,
    ranges_off: usize,
    ranges_len: usize,
}

impl PciScratch {
    const NEW: Self = Self {
        depth: 0, is_ecam: false, parent_ac: 2, parent_sc: 1, own_ac: 0, own_sc: 0,
        reg_off: 0, reg_len: 0, ranges_off: 0, ranges_len: 0,
    };
}

/// One `ranges` translation of a PCI host bridge: PCI bus addresses
/// `[bus_base, bus_base + size)` appear to the CPU at `cpu_base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciWindow {
    pub cpu_base: u64,
    pub bus_base: u64,
    pub size: u64,
    /// `p` bit (bit 30) of the entry's `phys.hi` cell.
    pub prefetchable: bool,
}

/// The windows of one `ranges` property, first entry of each space wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciRanges {
    /// Space code `01`: I/O space.
    pub io: Option<PciWindow>,
    /// Space code `10`: 32-bit memory space.
    pub mem32: Option<PciWindow>,
    /// Space code `11`: 64-bit memory space.
    pub mem64: Option<PciWindow>,
}

/// A `pci-host-ecam-generic` host bridge as its DTB node describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciHost {
    /// ECAM window (`reg`, first entry, parent's cells).
    pub ecam_base: u64,
    pub ecam_size: u64,
    pub io: Option<PciWindow>,
    pub mem32: Option<PciWindow>,
    pub mem64: Option<PciWindow>,
}

/// Read `cells` (1 or 2) big-endian cells at `off` of `b` as one number.
fn cells_at(b: &[u8], off: usize, cells: u32) -> Option<u64> {
    let n = cells as usize * 4;
    let bytes = b.get(off..off.checked_add(n)?)?;
    match cells {
        1 => Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        2 => Some(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => None,
    }
}

/// First `(address, size)` pair of a `reg` value, or `None` if the cell
/// counts are not 1 or 2 or the value is shorter than one pair.
pub fn decode_reg_first(reg: &[u8], ac: u32, sc: u32) -> Option<(u64, u64)> {
    if !matches!(ac, 1 | 2) || !matches!(sc, 1 | 2) {
        return None;
    }
    let base = cells_at(reg, 0, ac)?;
    let size = cells_at(reg, ac as usize * 4, sc)?;
    Some((base, size))
}

/// Decode a PCI host bridge's `ranges` (PCI bus binding, IEEE 1275):
/// each entry is `phys.hi phys.mid phys.lo` (the node's `#address-cells`,
/// which must be 3), the CPU address (`parent_ac` cells, 1 or 2) and the
/// size (`child_sc` cells, 1 or 2). `phys.hi` bits 25:24 are the space code
/// (`00` configuration, `01` I/O, `10` 32-bit memory, `11` 64-bit memory),
/// bit 30 the prefetchable flag; `phys.mid:phys.lo` is the bus address.
///
/// Configuration-space entries and a trailing partial entry are ignored;
/// cell counts outside the binding decode as no windows at all.
pub fn decode_pci_ranges(ranges: &[u8], child_ac: u32, parent_ac: u32, child_sc: u32) -> PciRanges {
    let mut out = PciRanges::default();
    if child_ac != 3 || !matches!(parent_ac, 1 | 2) || !matches!(child_sc, 1 | 2) {
        return out;
    }
    let entry = (3 + parent_ac + child_sc) as usize * 4;
    let mut off = 0usize;
    while off + entry <= ranges.len() {
        let e = &ranges[off..off + entry];
        off += entry;
        let hi = u32::from_be_bytes([e[0], e[1], e[2], e[3]]);
        let (Some(bus_base), Some(cpu_base), Some(size)) = (
            cells_at(e, 4, 2),
            cells_at(e, 12, parent_ac),
            cells_at(e, 12 + parent_ac as usize * 4, child_sc),
        ) else {
            continue;
        };
        let w = PciWindow { cpu_base, bus_base, size, prefetchable: hi & (1 << 30) != 0 };
        let slot = match (hi >> 24) & 3 {
            1 => &mut out.io,
            2 => &mut out.mem32,
            3 => &mut out.mem64,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(w);
        }
    }
    out
}

/// The first node whose `compatible` names `pci-host-ecam-generic` and whose
/// `reg` decodes, or `None` (invalid header, no such node). QEMU `virt`
/// carries one on both ISAs: `pci@30000000` under `/soc` on riscv64,
/// `pcie@10000000` at the root on aarch64 (whose ECAM `reg` sits above
/// 4 GiB with `highmem-ecam`).
///
/// A new function, not a [`DtbInfo`] field, for the reason [`dtb_cpu_regs`]
/// gives.
///
/// # Safety
/// Same precondition as [`dtb_parse`].
pub unsafe fn dtb_pci_host(ptr: *const u8) -> Option<PciHost> {
    if ptr.is_null() {
        return None;
    }
    let hdr = unsafe { parse_header(ptr) }?;
    if hdr.magic != FDT_MAGIC || hdr.version < 16 {
        return None;
    }
    let totalsize = hdr.totalsize as usize;
    if totalsize < FDT_HEADER_SIZE || totalsize > MAX_DTB_SIZE {
        return None;
    }
    let struct_off = hdr.off_dt_struct as usize;
    if struct_off >= totalsize {
        return None;
    }
    let strings_off = hdr.off_dt_strings as usize;
    let strings_end = strings_off.checked_add(hdr.size_dt_strings as usize)?;
    if strings_end > totalsize {
        return None;
    }

    let mut walker = Walker {
        base: ptr,
        struct_off,
        strings_off,
        strings_end,
        totalsize,
        cursor: 0,
        depth: 0,
        info: DtbInfo::zeroed(),
        in_memory: false,
        in_cpus: false,
        in_cpu_child: false,
        in_cpu0: false,
        in_uart: false,
        in_intc: false,
        aia_kind: 0,
        aia_reg: 0,
        aia_num_field: 0,
        aia_has_children: false,
        aia_s_ext: false,
        aia_guest_bits: 0,
        intc_is_plic: false,
        address_cells: 2,
        size_cells: 1,
        cells_stack: [(2, 1); 8],
        uart_depth: 0,
        intc_depth: 0,
        cpu_reg: [0u64; MAX_CPU_REG],
        cpu_reg_count: 0,
        pci: PciScratch::NEW,
        pci_host: None,
        #[cfg(not(target_arch = "riscv64"))]
        con: ConsoleScratch::NEW,
        #[cfg(not(target_arch = "riscv64"))]
        pl011: None,
    };
    walker.walk();
    // As `dtb_pl011_irq`: a walk that stopped inside the node still commits
    // what it read in full.
    walker.pci_commit();
    walker.pci_host
}

/// A PL011's interrupt as its DTB node describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pl011Irq {
    /// The node's `reg` address (first cell group).
    pub base: usize,
    /// GIC INTID: `32 + n` for the specifier `<GIC_SPI n flags>`.
    pub intid: u32,
    /// Edge-triggered (`flags & 0xf` is 1 or 2); level otherwise (4 or 8).
    pub edge: bool,
}

/// Decode one 3-cell GICv3 interrupt specifier (`arm,gic-v3` binding:
/// `<type number flags>`) into `(INTID, edge)`. Only SPIs (type 0) are
/// accepted: a PPI (type 1) is per-PE and routed through the redistributor,
/// which is not what a console line is. SPI numbers run 0..=987 (INTIDs
/// 32..=1019); 1020..=1023 are special INTIDs. The trigger nibble must be
/// one of the four values the binding defines.
pub fn decode_gic_spi(cells: Option<[u32; 3]>) -> Option<(u32, bool)> {
    let [ty, num, flags] = cells?;
    if ty != 0 || num > 987 {
        return None;
    }
    let edge = match flags & 0xf {
        1 | 2 => true,
        4 | 8 => false,
        _ => return None,
    };
    Some((32 + num, edge))
}

// ---------------------------------------------------------------
// Interrupt trigger types (wave 9 IRQ4 item 3)
// ---------------------------------------------------------------

/// The interrupt controller whose lines [`dtb_irq_triggers`] decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqController {
    /// The `arm,gic-v3` distributor: 3-cell specifiers `<type number flags>`;
    /// only SPIs (type 0, line = 32 + number) are recorded.
    GicV3,
    /// The S-domain `riscv,aplic` (the one without `riscv,children`):
    /// 2-cell specifiers `<source flags>`.
    AplicS,
}

/// Lines a DTB describes on one interrupt controller and their trigger, one
/// bit per line 0..1023. A line no `interrupts` property names is not
/// `described`, and its trigger is unknown ([`IrqTriggers::edge`] = `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqTriggers {
    /// Bit set: some node's `interrupts` names this line.
    pub described: [u32; 32],
    /// Bit set: that specifier's trigger nibble is edge (1 rising, 2
    /// falling); clear: level (4 high, 8 low).
    pub edge_bits: [u32; 32],
}

impl IrqTriggers {
    /// Nothing described.
    pub const EMPTY: Self = Self { described: [0; 32], edge_bits: [0; 32] };

    /// `Some(true)` edge, `Some(false)` level, `None` for a line the DTB does
    /// not describe on this controller (or outside 0..1023).
    pub const fn edge(&self, line: u32) -> Option<bool> {
        if line >= 1024 {
            return None;
        }
        let (w, b) = ((line / 32) as usize, 1u32 << (line % 32));
        if self.described[w] & b == 0 {
            None
        } else {
            Some(self.edge_bits[w] & b != 0)
        }
    }

    /// How many lines are described, and how many of those are edge.
    pub fn counts(&self) -> (u32, u32) {
        let d = self.described.iter().map(|w| w.count_ones()).sum();
        let e = self.edge_bits.iter().map(|w| w.count_ones()).sum();
        (d, e)
    }

    fn record(&mut self, line: u32, edge: bool) {
        if line >= 1024 {
            return;
        }
        let (w, b) = ((line / 32) as usize, 1u32 << (line % 32));
        self.described[w] |= b;
        if edge {
            self.edge_bits[w] |= b;
        } else {
            self.edge_bits[w] &= !b;
        }
    }
}

/// Decode a trigger nibble: `Some(edge)` for the four values the GIC and
/// APLIC bindings define (1/2 edge, 4/8 level), `None` otherwise.
pub const fn decode_trigger_flags(flags: u32) -> Option<bool> {
    match flags & 0xf {
        1 | 2 => Some(true),
        4 | 8 => Some(false),
        _ => None,
    }
}

/// Deepest node nesting [`dtb_irq_triggers`] follows; a deeper node ends the
/// scan with what was decoded so far.
const IRQ_SCAN_DEPTH: usize = 16;

/// One structure-block token, bounds-checked against the blob.
enum Tok {
    Begin,
    End,
    /// `(name offset into the strings block, payload offset, payload length)`.
    Prop(u32, usize, usize),
    Nop,
}

/// A bounded cursor over the structure block: every read is proved inside
/// `totalsize` with checked arithmetic first (the same discipline as
/// `Walker::walk`), and anything malformed ends the scan (`None`).
struct TokCursor {
    base: *const u8,
    struct_off: usize,
    strings_off: usize,
    strings_end: usize,
    totalsize: usize,
    cursor: usize,
}

impl TokCursor {
    unsafe fn new(ptr: *const u8) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        let hdr = unsafe { parse_header(ptr) }?;
        if hdr.version < 16 {
            return None;
        }
        let totalsize = hdr.totalsize as usize;
        if totalsize < FDT_HEADER_SIZE || totalsize > MAX_DTB_SIZE {
            return None;
        }
        let struct_off = hdr.off_dt_struct as usize;
        if struct_off >= totalsize {
            return None;
        }
        let strings_off = hdr.off_dt_strings as usize;
        let strings_end = strings_off.checked_add(hdr.size_dt_strings as usize)?;
        if strings_end > totalsize {
            return None;
        }
        Some(Self { base: ptr, struct_off, strings_off, strings_end, totalsize, cursor: 0 })
    }

    fn rewind(&mut self) {
        self.cursor = 0;
    }

    /// The u32 at `cursor`, advancing past it; `None` if it is not inside the blob.
    unsafe fn u32_at_cursor(&mut self) -> Option<u32> {
        let off = self.struct_off.checked_add(self.cursor)?;
        if off.checked_add(4)? > self.totalsize {
            return None;
        }
        self.cursor += 4;
        Some(unsafe { read_be32(self.base, off) })
    }

    unsafe fn next(&mut self) -> Option<Tok> {
        match unsafe { self.u32_at_cursor() }? {
            FDT_BEGIN_NODE => {
                let name_off = self.struct_off.checked_add(self.cursor)?;
                let len = unsafe { strlen_bounded(self.base, name_off, self.totalsize) }?;
                let step = align4_checked(len.checked_add(1)?)?;
                self.cursor = self.cursor.checked_add(step)?;
                Some(Tok::Begin)
            }
            FDT_END_NODE => Some(Tok::End),
            FDT_PROP => {
                let len = unsafe { self.u32_at_cursor() }? as usize;
                let nameoff = unsafe { self.u32_at_cursor() }?;
                let data_off = self.struct_off.checked_add(self.cursor)?;
                if data_off.checked_add(len)? > self.totalsize {
                    return None;
                }
                self.cursor = self.cursor.checked_add(align4_checked(len)?)?;
                Some(Tok::Prop(nameoff, data_off, len))
            }
            FDT_NOP => Some(Tok::Nop),
            _ => None, // FDT_END or malformed
        }
    }

    unsafe fn name_is(&self, nameoff: u32, needle: &[u8]) -> bool {
        match self.strings_off.checked_add(nameoff as usize) {
            Some(off) if off < self.strings_end => unsafe {
                streq(self.base, off, self.strings_end, needle)
            },
            _ => false,
        }
    }

    unsafe fn be32(&self, data_off: usize, index: usize) -> u32 {
        unsafe { read_be32(self.base, data_off + 4 * index) }
    }

    unsafe fn bytes(&self, data_off: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base.add(data_off), len) }
    }
}

/// The trigger type of every line `ctrl` receives, from the `interrupts`
/// properties of the nodes whose effective `interrupt-parent` (their own, or
/// the nearest ancestor's) is that controller. `None` for a blob this cannot
/// read or one without that controller.
///
/// Two passes over the structure block. The first finds the controller: a
/// node with `interrupt-controller` whose `compatible` names it (for
/// [`IrqController::AplicS`], the `riscv,aplic` node without
/// `riscv,children`), its `phandle` and `#interrupt-cells` (3 for the GIC, 2
/// for the APLIC; anything else is refused). The second decodes. A node's
/// properties precede its subnodes in an FDT, so a child inherits its
/// parent's final `interrupt-parent`; within one node `interrupt-parent` may
/// follow `interrupts` (QEMU's riscv64 `virt` writes it after), so each
/// node's `interrupts` is decoded at its end. `interrupts-extended` is not
/// read. A specifier with an undefined trigger nibble is skipped.
///
/// A PLIC has no trigger configuration and its binding carries none
/// (`#interrupt-cells = 1`), so there is no PLIC variant.
///
/// # Safety
/// Same precondition as [`dtb_parse`].
pub unsafe fn dtb_irq_triggers(ptr: *const u8, ctrl: IrqController) -> Option<IrqTriggers> {
    let mut c = unsafe { TokCursor::new(ptr) }?;

    // Pass 1: the controller's phandle and #interrupt-cells.
    let (want, not_if): (&[u8], &[u8]) = match ctrl {
        IrqController::GicV3 => (b"arm,gic-v3", b""),
        IrqController::AplicS => (b"riscv,aplic", b"riscv,children"),
    };
    let (mut phandle, mut cells) = (0u32, 0u32);
    {
        // Per open node: (is controller, compatible matches, excluded, phandle, cells).
        let mut st = [(false, false, false, 0u32, 0u32); IRQ_SCAN_DEPTH];
        let mut depth = 0usize;
        loop {
            match unsafe { c.next() } {
                Some(Tok::Begin) => {
                    depth += 1;
                    if depth >= IRQ_SCAN_DEPTH {
                        break;
                    }
                    st[depth] = (false, false, false, 0, 0);
                }
                Some(Tok::End) => {
                    if depth == 0 {
                        break;
                    }
                    if depth < IRQ_SCAN_DEPTH {
                        let (ic, compat, excluded, ph, ce) = st[depth];
                        if ic && compat && !excluded && ph != 0 && phandle == 0 {
                            phandle = ph;
                            cells = ce;
                        }
                    }
                    depth -= 1;
                }
                Some(Tok::Prop(name, off, len)) => {
                    if depth == 0 || depth >= IRQ_SCAN_DEPTH {
                        continue;
                    }
                    let n = &mut st[depth];
                    unsafe {
                        if c.name_is(name, b"interrupt-controller") {
                            n.0 = true;
                        } else if c.name_is(name, b"compatible") {
                            n.1 = compatible_has(c.bytes(off, len), want);
                        } else if !not_if.is_empty() && c.name_is(name, not_if) {
                            n.2 = true;
                        } else if len == 4 && (c.name_is(name, b"phandle") || c.name_is(name, b"linux,phandle")) {
                            n.3 = c.be32(off, 0);
                        } else if len == 4 && c.name_is(name, b"#interrupt-cells") {
                            n.4 = c.be32(off, 0);
                        }
                    }
                }
                Some(Tok::Nop) => {}
                None => break,
            }
        }
    }
    let expect_cells = match ctrl {
        IrqController::GicV3 => 3,
        IrqController::AplicS => 2,
    };
    if phandle == 0 || cells != expect_cells {
        return None;
    }

    // Pass 2: decode every node whose effective interrupt-parent is it.
    c.rewind();
    let mut out = IrqTriggers::EMPTY;
    // Per open node: effective interrupt-parent, and its own `interrupts`.
    let mut parent = [0u32; IRQ_SCAN_DEPTH];
    let mut irqs = [(0usize, 0usize); IRQ_SCAN_DEPTH];
    let mut depth = 0usize;
    loop {
        match unsafe { c.next() } {
            Some(Tok::Begin) => {
                depth += 1;
                if depth >= IRQ_SCAN_DEPTH {
                    break;
                }
                parent[depth] = parent[depth - 1];
                irqs[depth] = (0, 0);
            }
            Some(Tok::End) => {
                if depth == 0 {
                    break;
                }
                let (off, len) = irqs[depth];
                let stride = 4 * cells as usize;
                if len != 0 && parent[depth] == phandle && len % stride == 0 {
                    for i in 0..len / stride {
                        let cell = |k: usize| unsafe { c.be32(off, i * cells as usize + k) };
                        let decoded = match ctrl {
                            IrqController::GicV3 => match (cell(0), cell(1)) {
                                (0, num) if num <= 987 => {
                                    decode_trigger_flags(cell(2)).map(|e| (32 + num, e))
                                }
                                _ => None,
                            },
                            IrqController::AplicS => {
                                decode_trigger_flags(cell(1)).map(|e| (cell(0), e))
                            }
                        };
                        if let Some((line, edge)) = decoded {
                            out.record(line, edge);
                        }
                    }
                }
                depth -= 1;
            }
            Some(Tok::Prop(name, off, len)) => {
                if depth == 0 || depth >= IRQ_SCAN_DEPTH {
                    continue;
                }
                unsafe {
                    if len == 4 && c.name_is(name, b"interrupt-parent") {
                        parent[depth] = c.be32(off, 0);
                    } else if c.name_is(name, b"interrupts") {
                        irqs[depth] = (off, len);
                    }
                }
            }
            Some(Tok::Nop) => {}
            None => break,
        }
    }
    Some(out)
}

// ---------------------------------------------------------------
// Public API
// ---------------------------------------------------------------

/// Parse the Flattened Device Tree blob at `ptr` and return a [`DtbInfo`]
/// with the extracted hardware description.
///
/// Returns `None` if the magic number does not match or the header is
/// obviously invalid.
///
/// # Safety
/// `ptr` must point to a valid, complete FDT blob that remains readable
/// for its entire `totalsize`.  The pointer does **not** need to be
/// aligned.
///
/// **At least [`FDT_HEADER_SIZE`] bytes at `ptr` must be readable.** This
/// is the caller's guarantee and the one precondition this function cannot
/// check: `totalsize` — the bound every other read is validated against —
/// lives *inside* the header, so the header must be read before anything
/// is known about the blob's extent. Everything after that point is
/// defensive against a hostile or truncated blob; this first 40 bytes is
/// not, and cannot be.
pub unsafe fn dtb_parse(ptr: *const u8) -> Option<DtbInfo> {
    if ptr.is_null() {
        return None;
    }

    let hdr = parse_header(ptr)?;
    if hdr.magic != FDT_MAGIC {
        return None;
    }
    // Minimal sanity: version >= 16 (the oldest version we support).
    if hdr.version < 16 {
        return None;
    }

    // ---- Blob-extent validation -------------------------------------
    // Everything below is the *only* thing standing between a firmware-
    // supplied u32 and a walker that dereferences it. These are not
    // redundant with the per-read bounds inside the walker: the walker's
    // bounds are all expressed relative to `totalsize`, `strings_off` and
    // `strings_end`, so if those three are nonsense the per-read checks
    // faithfully permit nonsense.
    //
    // Concretely, the bug this closes: with off_dt_strings = 0xFFFF_F000
    // and size_dt_strings = 0x1000, `strings_end` became 0x1_0000_0000,
    // `prop_name_eq`'s "off < strings_end" guard passed, and the first
    // FDT_PROP token resolved its name ~4 GiB past the blob — outside
    // physical RAM on every target board, so a load access fault during
    // early boot with no working trap handler.

    let totalsize = hdr.totalsize as usize;
    // A blob smaller than its own header cannot be coherent.
    if totalsize < FDT_HEADER_SIZE {
        return None;
    }
    // See MAX_DTB_SIZE: clamps how far walk() may ever march.
    if totalsize > MAX_DTB_SIZE {
        return None;
    }

    // The structure block must start inside the blob; walk() bounds the
    // cursor relative to it, so an out-of-blob `struct_off` would make
    // every subsequent bound meaningless.
    let struct_off = hdr.off_dt_struct as usize;
    if struct_off >= totalsize {
        return None;
    }

    // The strings block must lie wholly inside the blob. `<=` (not `<`) is
    // correct and deliberate: a blob whose strings block runs exactly to
    // the last byte — the normal layout emitted by dtc — has
    // off_dt_strings + size_dt_strings == totalsize.
    let strings_off = hdr.off_dt_strings as usize;
    let strings_end = match strings_off.checked_add(hdr.size_dt_strings as usize) {
        Some(v) => v,
        // Two u32 cannot overflow a 64-bit usize, but this crate also
        // builds for 32-bit RISC-V targets where they trivially can — and
        // `overflow-checks = true` turns that into a panic, i.e. a board
        // reset. Check it rather than rely on the pointer width.
        None => return None,
    };
    if strings_end > totalsize {
        return None;
    }

    let mut walker = Walker {
        base: ptr,
        struct_off,
        strings_off,
        strings_end,
        totalsize,
        cursor: 0,
        depth: 0,
        info: DtbInfo::zeroed(),
        in_memory: false,
        in_cpus: false,
        in_cpu_child: false,
        in_cpu0: false,
        in_uart: false,
        in_intc: false,
        aia_kind: 0,
        aia_reg: 0,
        aia_num_field: 0,
        aia_has_children: false,
        aia_s_ext: false,
        aia_guest_bits: 0,
        intc_is_plic: false,
        address_cells: 2,
        size_cells: 1,
        cells_stack: [(2, 1); 8],
        uart_depth: 0,
        intc_depth: 0,
        cpu_reg: [0u64; MAX_CPU_REG],
        cpu_reg_count: 0,
        pci: PciScratch::NEW,
        pci_host: None,
        #[cfg(not(target_arch = "riscv64"))]
        con: ConsoleScratch::NEW,
        #[cfg(not(target_arch = "riscv64"))]
        pl011: None,
    };

    walker.walk();
    Some(walker.info)
}

/// Raw `reg` cell(s) of every `/cpus/cpu@N` node, in document order, into
/// `out` — capped at `out.len()`. Returns the total number of `cpu@` nodes
/// found (which may exceed `out.len()`, mirroring [`DtbInfo::num_cpus`]'s own
/// truncate-not-fail shape), or `None` if the blob's header is invalid.
///
/// A new function rather than a new [`DtbInfo`] field — see [`dtb_probe`]'s
/// own comment for why: the RISC-V boot path, which never calls this, gets
/// zero codegen delta, and this crate is `#[path]`-pulled whole into
/// `tests/host/regression-tests`, where a new struct field would need a matching
/// `use` at that pull site (`feedback-a-path-pulled-file-needs-a-seam-
/// entry.md`) — a new function needs none.
///
/// On aarch64, `reg` is the MPIDR affinity bits (`Aff2:Aff1:Aff0` in one
/// cell, or with `Aff3` folded in when `#address-cells` is 2) — unpack with
/// [`crate`]-external `azos_arch_aarch64::mpidr::mpidr_affinity_key`, not
/// here (this crate has no ISA dependency). On RISC-V it is the hart id
/// directly.
///
/// # Safety
/// Same precondition as [`dtb_parse`]: at least [`FDT_HEADER_SIZE`] bytes at
/// `ptr` must be readable, extending to the blob's own `totalsize` once that
/// is known.
pub unsafe fn dtb_cpu_regs(ptr: *const u8, out: &mut [u64]) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }

    let hdr = unsafe { parse_header(ptr) }?;
    if hdr.magic != FDT_MAGIC || hdr.version < 16 {
        return None;
    }

    let totalsize = hdr.totalsize as usize;
    if totalsize < FDT_HEADER_SIZE || totalsize > MAX_DTB_SIZE {
        return None;
    }

    let struct_off = hdr.off_dt_struct as usize;
    if struct_off >= totalsize {
        return None;
    }

    let strings_off = hdr.off_dt_strings as usize;
    let strings_end = match strings_off.checked_add(hdr.size_dt_strings as usize) {
        Some(v) => v,
        None => return None,
    };
    if strings_end > totalsize {
        return None;
    }

    let mut walker = Walker {
        base: ptr,
        struct_off,
        strings_off,
        strings_end,
        totalsize,
        cursor: 0,
        depth: 0,
        info: DtbInfo::zeroed(),
        in_memory: false,
        in_cpus: false,
        in_cpu_child: false,
        in_cpu0: false,
        in_uart: false,
        in_intc: false,
        aia_kind: 0,
        aia_reg: 0,
        aia_num_field: 0,
        aia_has_children: false,
        aia_s_ext: false,
        aia_guest_bits: 0,
        intc_is_plic: false,
        address_cells: 2,
        size_cells: 1,
        cells_stack: [(2, 1); 8],
        uart_depth: 0,
        intc_depth: 0,
        cpu_reg: [0u64; MAX_CPU_REG],
        cpu_reg_count: 0,
        pci: PciScratch::NEW,
        pci_host: None,
        #[cfg(not(target_arch = "riscv64"))]
        con: ConsoleScratch::NEW,
        #[cfg(not(target_arch = "riscv64"))]
        pl011: None,
    };

    walker.walk();
    let n = walker.cpu_reg_count.min(out.len());
    out[..n].copy_from_slice(&walker.cpu_reg[..n]);
    Some(walker.cpu_reg_count)
}

/// The first node whose `compatible` names `arm,pl011` and that carries a
/// `reg` and exactly one 3-cell GIC SPI specifier in `interrupts`, or `None`
/// (invalid header, no such node, or a specifier [`decode_gic_spi`]
/// refuses).
///
/// Matched by `compatible`, not by node name: QEMU `virt` names the node
/// `pl011@9000000`, which the `serial`/`uart` name match behind
/// [`DtbInfo::uart_base`] never sees. The caller is expected to compare
/// [`Pl011Irq::base`] with the UART it actually drives before wiring the
/// line.
///
/// A new function, not a [`DtbInfo`] field, for the reason [`dtb_cpu_regs`]
/// gives; not built for riscv64, which has no PL011.
///
/// # Safety
/// Same precondition as [`dtb_parse`].
#[cfg(not(target_arch = "riscv64"))]
pub unsafe fn dtb_pl011_irq(ptr: *const u8) -> Option<Pl011Irq> {
    if ptr.is_null() {
        return None;
    }
    let hdr = unsafe { parse_header(ptr) }?;
    if hdr.magic != FDT_MAGIC || hdr.version < 16 {
        return None;
    }
    let totalsize = hdr.totalsize as usize;
    if totalsize < FDT_HEADER_SIZE || totalsize > MAX_DTB_SIZE {
        return None;
    }
    let struct_off = hdr.off_dt_struct as usize;
    if struct_off >= totalsize {
        return None;
    }
    let strings_off = hdr.off_dt_strings as usize;
    let strings_end = strings_off.checked_add(hdr.size_dt_strings as usize)?;
    if strings_end > totalsize {
        return None;
    }

    let mut walker = Walker {
        base: ptr,
        struct_off,
        strings_off,
        strings_end,
        totalsize,
        cursor: 0,
        depth: 0,
        info: DtbInfo::zeroed(),
        in_memory: false,
        in_cpus: false,
        in_cpu_child: false,
        in_cpu0: false,
        in_uart: false,
        in_intc: false,
        aia_kind: 0,
        aia_reg: 0,
        aia_num_field: 0,
        aia_has_children: false,
        aia_s_ext: false,
        aia_guest_bits: 0,
        intc_is_plic: false,
        address_cells: 2,
        size_cells: 1,
        cells_stack: [(2, 1); 8],
        uart_depth: 0,
        intc_depth: 0,
        cpu_reg: [0u64; MAX_CPU_REG],
        cpu_reg_count: 0,
        pci: PciScratch::NEW,
        pci_host: None,
        con: ConsoleScratch::NEW,
        pl011: None,
    };
    walker.walk();
    // A blob whose structure block ends without closing the node leaves
    // the last one uncommitted; `walk` stopping early is not a reason to
    // ignore what was fully read.
    walker.con_commit();
    walker.pl011
}

/// Read just the FDT header's `magic` and `totalsize`, with none of
/// [`dtb_parse`]'s structure-block walk.
///
/// For a boot path that wants to prove "x0 is a real FDT" as its own
/// checkpoint, independent of whether the full walk below it later
/// succeeds — aarch64's Image-format boot passes the DTB address in x0
/// only when QEMU/U-Boot recognise the kernel as an Image, unlike a bare
/// ELF `-kernel` load (x0 == 0 there); this is the direct way to assert
/// that handoff happened, without conflating it with `dtb_parse`'s
/// (unrelated) memory/CPU/ISA extraction succeeding or not.
///
/// Added as a new function rather than a new [`DtbInfo`] field so the
/// RISC-V boot path — which never calls this — has zero code-generation
/// delta from its addition (see this crate's `riscv64-unknown-elf-objdump`
/// discipline in the workspace's `tools/ci_check.sh` header comments).
///
/// Returns `None` if `ptr` is null or the magic does not match; the same
/// one precondition [`dtb_parse`] documents applies here (`ptr` must have
/// at least [`FDT_HEADER_SIZE`] readable bytes).
///
/// # Safety
/// Same as [`dtb_parse`]: `ptr` must point to at least `FDT_HEADER_SIZE`
/// readable bytes.
pub unsafe fn dtb_probe(ptr: *const u8) -> Option<(u32, u32)> {
    if ptr.is_null() {
        return None;
    }
    let hdr = unsafe { parse_header(ptr) }?;
    Some((hdr.magic, hdr.totalsize))
}

/// Return the compatible string from a [`DtbInfo`] as a byte slice
/// (up to the first NUL or end of buffer).
pub fn dtb_compatible_str(info: &DtbInfo) -> &[u8] {
    let mut len = 0usize;
    while len < info.compatible.len() && info.compatible[len] != 0 {
        len += 1;
    }
    &info.compatible[..len]
}

// ---------------------------------------------------------------
// Energy model tables (RFC-0051 E2): operating-points-v2, idle-states
// ---------------------------------------------------------------

/// CPUs [`dtb_energy`] records, in document order (the same bound as
/// [`MAX_CPU_REG`]).
pub const DT_ENERGY_CPUS: usize = MAX_CPU_REG;
/// OPP tables it records.
pub const DT_ENERGY_TABLES: usize = 4;
/// OPPs per table it records.
pub const DT_ENERGY_OPPS: usize = 16;
/// Idle-state nodes it records.
pub const DT_ENERGY_IDLE: usize = 8;
/// `cpu-idle-states` entries per CPU it records.
pub const DT_ENERGY_CPU_IDLE: usize = 4;
/// Bytes of an `idle-state-name` it keeps.
pub const DT_ENERGY_NAME: usize = 16;

/// One `device_type = "cpu"` node, as far as the energy model cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtCpuEnergy {
    /// Phandle its `operating-points-v2` names, 0 if it has none.
    pub opp_table: u32,
    /// `capacity-dmips-mhz`, 0 if absent.
    pub capacity_dmips_mhz: u32,
    /// Phandles of its `cpu-idle-states`, shallowest first.
    pub idle_states: [u32; DT_ENERGY_CPU_IDLE],
    /// Entries used in `idle_states`.
    pub n_idle: u8,
}

/// One OPP node of an `operating-points-v2` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtOpp {
    /// `opp-hz` (its first value), Hz.
    pub hz: u64,
    /// `opp-microwatt`, summed over its cells (one per supply); 0 if absent.
    pub microwatt: u64,
}

/// One node whose `compatible` names `operating-points-v2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtOppTable {
    /// Its phandle.
    pub phandle: u32,
    /// `opp-shared`: every CPU naming the table shares its clock.
    pub shared: bool,
    /// Its OPP children not marked `status = "disabled"`, document order.
    pub opps: [DtOpp; DT_ENERGY_OPPS],
    /// Entries used in `opps`.
    pub n_opps: u8,
    /// More OPPs than [`DT_ENERGY_OPPS`] were present.
    pub truncated: bool,
}

/// One node whose `compatible` names `arm,idle-state` or `riscv,idle-state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtIdleState {
    /// Its phandle.
    pub phandle: u32,
    /// `idle-state-name`, truncated; empty if absent.
    pub name: [u8; DT_ENERGY_NAME],
    /// Bytes used in `name`.
    pub name_len: u8,
    /// `entry-latency-us`.
    pub entry_latency_us: u32,
    /// `exit-latency-us`.
    pub exit_latency_us: u32,
    /// `min-residency-us`.
    pub min_residency_us: u32,
}

/// Everything [`dtb_energy`] read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtEnergy {
    /// CPU nodes, document order.
    pub cpus: [DtCpuEnergy; DT_ENERGY_CPUS],
    /// Entries used in `cpus`.
    pub n_cpus: u8,
    /// OPP tables, document order.
    pub tables: [DtOppTable; DT_ENERGY_TABLES],
    /// Entries used in `tables`.
    pub n_tables: u8,
    /// Idle-state nodes, document order.
    pub idle: [DtIdleState; DT_ENERGY_IDLE],
    /// Entries used in `idle`.
    pub n_idle: u8,
    /// Some CPU, table or idle state did not fit and was dropped.
    pub truncated: bool,
}

impl DtEnergy {
    const EMPTY_CPU: DtCpuEnergy =
        DtCpuEnergy { opp_table: 0, capacity_dmips_mhz: 0, idle_states: [0; DT_ENERGY_CPU_IDLE], n_idle: 0 };
    const EMPTY_TABLE: DtOppTable = DtOppTable {
        phandle: 0,
        shared: false,
        opps: [DtOpp { hz: 0, microwatt: 0 }; DT_ENERGY_OPPS],
        n_opps: 0,
        truncated: false,
    };
    const EMPTY_IDLE: DtIdleState = DtIdleState {
        phandle: 0,
        name: [0; DT_ENERGY_NAME],
        name_len: 0,
        entry_latency_us: 0,
        exit_latency_us: 0,
        min_residency_us: 0,
    };
    /// Nothing read.
    pub const EMPTY: Self = Self {
        cpus: [Self::EMPTY_CPU; DT_ENERGY_CPUS],
        n_cpus: 0,
        tables: [Self::EMPTY_TABLE; DT_ENERGY_TABLES],
        n_tables: 0,
        idle: [Self::EMPTY_IDLE; DT_ENERGY_IDLE],
        n_idle: 0,
        truncated: false,
    };

    /// The CPUs read.
    pub fn cpus(&self) -> &[DtCpuEnergy] {
        &self.cpus[..self.n_cpus as usize]
    }
    /// The tables read.
    pub fn tables(&self) -> &[DtOppTable] {
        &self.tables[..self.n_tables as usize]
    }
    /// The idle states read.
    pub fn idle_states(&self) -> &[DtIdleState] {
        &self.idle[..self.n_idle as usize]
    }
}

/// Deepest node nesting [`dtb_energy`] follows; a deeper node ends the scan
/// with what was read so far.
const ENERGY_SCAN_DEPTH: usize = 16;

/// What one open node has said so far. An FDT puts every property of a node
/// before its first subnode, so a node's kind is settled by the time a child
/// opens (which is how an OPP is told apart: a child of a table).
#[derive(Clone, Copy)]
struct EnergyNode {
    is_cpu: bool,
    is_table: bool,
    is_idle: bool,
    is_opp: bool,
    disabled: bool,
    shared: bool,
    phandle: u32,
    opp_table: u32,
    cap: u32,
    idle: [u32; DT_ENERGY_CPU_IDLE],
    n_idle: u8,
    hz: u64,
    uw: u64,
    entry: u32,
    exit: u32,
    resid: u32,
    name: [u8; DT_ENERGY_NAME],
    name_len: u8,
}

impl EnergyNode {
    const EMPTY: Self = Self {
        is_cpu: false,
        is_table: false,
        is_idle: false,
        is_opp: false,
        disabled: false,
        shared: false,
        phandle: 0,
        opp_table: 0,
        cap: 0,
        idle: [0; DT_ENERGY_CPU_IDLE],
        n_idle: 0,
        hz: 0,
        uw: 0,
        entry: 0,
        exit: 0,
        resid: 0,
        name: [0; DT_ENERGY_NAME],
        name_len: 0,
    };
}

/// Read the tables an energy model is built from: every CPU node's
/// `operating-points-v2`, `capacity-dmips-mhz` and `cpu-idle-states`; every
/// `operating-points-v2` table (its `phandle`, `opp-shared`, and per enabled
/// OPP child `opp-hz` and `opp-microwatt`); every `arm,idle-state` /
/// `riscv,idle-state` node (`phandle`, `idle-state-name`,
/// `entry-latency-us`, `exit-latency-us`, `min-residency-us`). Phandles are
/// left unresolved; `azos_energy::dt` resolves them.
///
/// Nodes are recognised by their properties (`device_type = "cpu"`,
/// `compatible`), not their names, through the same bounded [`TokCursor`]
/// [`dtb_irq_triggers`] uses. Not read: `opp-supported-hw` filtering,
/// `opp-microvolt`, `dynamic-power-coefficient` (no power is derived from
/// it), `domain-idle-states`. `None` only for a blob this cannot read; a DTB
/// with none of these nodes gives an empty [`DtEnergy`].
///
/// Not called by any default build: only the kernel's `energy` feature
/// reaches it, so the default image's code is unchanged by its existence.
///
/// # Safety
/// Same precondition as [`dtb_parse`].
pub unsafe fn dtb_energy(ptr: *const u8) -> Option<DtEnergy> {
    let mut c = unsafe { TokCursor::new(ptr) }?;
    let mut out = DtEnergy::EMPTY;
    let mut st = [EnergyNode::EMPTY; ENERGY_SCAN_DEPTH];
    // OPPs read for the table node at `pending_depth`, committed at its end.
    let mut pending = DtEnergy::EMPTY_TABLE;
    let mut pending_depth = usize::MAX;
    let mut depth = 0usize;
    loop {
        match unsafe { c.next() } {
            Some(Tok::Begin) => {
                depth += 1;
                if depth >= ENERGY_SCAN_DEPTH {
                    break;
                }
                st[depth] = EnergyNode::EMPTY;
                st[depth].is_opp = st[depth - 1].is_table;
            }
            Some(Tok::End) => {
                if depth == 0 {
                    break;
                }
                let n = st[depth];
                if n.is_opp && !n.disabled {
                    if pending_depth != depth - 1 {
                        pending = DtEnergy::EMPTY_TABLE;
                        pending_depth = depth - 1;
                    }
                    if (pending.n_opps as usize) < DT_ENERGY_OPPS {
                        pending.opps[pending.n_opps as usize] = DtOpp { hz: n.hz, microwatt: n.uw };
                        pending.n_opps += 1;
                    } else {
                        pending.truncated = true;
                    }
                } else if n.is_table {
                    let mut t = if pending_depth == depth { pending } else { DtEnergy::EMPTY_TABLE };
                    t.phandle = n.phandle;
                    t.shared = n.shared;
                    if (out.n_tables as usize) < DT_ENERGY_TABLES {
                        out.tables[out.n_tables as usize] = t;
                        out.n_tables += 1;
                    } else {
                        out.truncated = true;
                    }
                    pending_depth = usize::MAX;
                } else if n.is_cpu {
                    if (out.n_cpus as usize) < DT_ENERGY_CPUS {
                        out.cpus[out.n_cpus as usize] = DtCpuEnergy {
                            opp_table: n.opp_table,
                            capacity_dmips_mhz: n.cap,
                            idle_states: n.idle,
                            n_idle: n.n_idle,
                        };
                        out.n_cpus += 1;
                    } else {
                        out.truncated = true;
                    }
                } else if n.is_idle {
                    if (out.n_idle as usize) < DT_ENERGY_IDLE {
                        out.idle[out.n_idle as usize] = DtIdleState {
                            phandle: n.phandle,
                            name: n.name,
                            name_len: n.name_len,
                            entry_latency_us: n.entry,
                            exit_latency_us: n.exit,
                            min_residency_us: n.resid,
                        };
                        out.n_idle += 1;
                    } else {
                        out.truncated = true;
                    }
                }
                depth -= 1;
            }
            Some(Tok::Prop(name, off, len)) => {
                if depth == 0 || depth >= ENERGY_SCAN_DEPTH {
                    continue;
                }
                let n = &mut st[depth];
                unsafe {
                    if c.name_is(name, b"device_type") {
                        n.is_cpu = c.bytes(off, len).split(|&b| b == 0).next() == Some(&b"cpu"[..]);
                    } else if c.name_is(name, b"compatible") {
                        let v = c.bytes(off, len);
                        n.is_table = compatible_has(v, b"operating-points-v2");
                        n.is_idle = compatible_has(v, b"arm,idle-state") || compatible_has(v, b"riscv,idle-state");
                    } else if c.name_is(name, b"status") {
                        n.disabled = c.bytes(off, len).split(|&b| b == 0).next() == Some(&b"disabled"[..]);
                    } else if len == 4 && (c.name_is(name, b"phandle") || c.name_is(name, b"linux,phandle")) {
                        n.phandle = c.be32(off, 0);
                    } else if c.name_is(name, b"opp-shared") {
                        n.shared = true;
                    } else if len == 4 && c.name_is(name, b"operating-points-v2") {
                        n.opp_table = c.be32(off, 0);
                    } else if len == 4 && c.name_is(name, b"capacity-dmips-mhz") {
                        n.cap = c.be32(off, 0);
                    } else if c.name_is(name, b"cpu-idle-states") {
                        let k = (len / 4).min(DT_ENERGY_CPU_IDLE);
                        for i in 0..k {
                            n.idle[i] = c.be32(off, i);
                        }
                        n.n_idle = k as u8;
                    } else if c.name_is(name, b"opp-hz") {
                        n.hz = if len >= 8 {
                            ((c.be32(off, 0) as u64) << 32) | c.be32(off, 1) as u64
                        } else if len >= 4 {
                            c.be32(off, 0) as u64
                        } else {
                            0
                        };
                    } else if c.name_is(name, b"opp-microwatt") {
                        let mut s = 0u64;
                        for i in 0..len / 4 {
                            s = s.saturating_add(c.be32(off, i) as u64);
                        }
                        n.uw = s;
                    } else if len == 4 && c.name_is(name, b"entry-latency-us") {
                        n.entry = c.be32(off, 0);
                    } else if len == 4 && c.name_is(name, b"exit-latency-us") {
                        n.exit = c.be32(off, 0);
                    } else if len == 4 && c.name_is(name, b"min-residency-us") {
                        n.resid = c.be32(off, 0);
                    } else if c.name_is(name, b"idle-state-name") {
                        let v = c.bytes(off, len);
                        let s = v.split(|&b| b == 0).next().unwrap_or(&[]);
                        let k = s.len().min(DT_ENERGY_NAME);
                        n.name[..k].copy_from_slice(&s[..k]);
                        n.name_len = k as u8;
                    }
                }
            }
            Some(Tok::Nop) => {}
            None => break,
        }
    }
    Some(out)
}
