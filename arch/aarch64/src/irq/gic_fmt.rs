// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The GICv3 redistributor's LPI tables and the ITS: register offsets, command
//! and table-pointer encodings, the LPI configuration byte. Numbers only, no
//! dependency: the interrupt drivers (`gic.rs`, `its.rs`) and the resident
//! monitor, which programs the ITS on a split image, include the same file.

pub const LPI_INTID_BASE: u32 = 8192;

/// `GICR_PROPBASER.IDbits` this driver programs — see the module-section
/// doc above for why 13 is a floor, not a policy knob.
pub const LPI_ID_BITS: u8 = 13;

/// Byte size of the LPI configuration table `LPI_ID_BITS` implies:
/// `2^(id_bits+1)` one-byte entries. 16 KiB for `LPI_ID_BITS == 13`.
pub const fn lpi_prop_table_size(id_bits: u8) -> usize {
    1usize << (id_bits as u32 + 1)
}

pub const GICR_CTLR_ENABLE_LPIS: u32 = 1 << 0;
/// GICR_CTLR.RWP (bit 3) — Register Write Pending. Same role as the
/// distributor's own RWP ([`GICD_CTLR_RWP`]): a caller that pokes
/// PROPBASER/PENDBASER and does not wait for this to clear has no
/// guarantee the redistributor has latched either pointer yet.
pub const GICR_CTLR_RWP: u32 = 1 << 3;

pub const GICR_PROPBASER_OFF: usize = 0x0070;
pub const GICR_PENDBASER_OFF: usize = 0x0078;

/// `GIC_BASER_CACHE_RaWaWb` (architecture spec naming) — Normal,
/// Read-allocate, Write-allocate, Write-Back. Shared by every BASER-shaped
/// register this driver programs (GITS_CBASER/BASERn in `its.rs`,
/// GICR_PROPBASER/PENDBASER here) — see the module-section doc for why.
pub const BASER_CACHE_RAWAWB: u64 = 0b111;
/// `GIC_BASER_InnerShareable`.
pub const BASER_SHAREABILITY_INNER: u64 = 0b01;

/// Encode `GICR_PROPBASER`: the LPI configuration table pointer, shared
/// across every redistributor that enables LPIs (one physical table, one
/// value, written identically everywhere — unlike PENDBASER below). Low
/// 12 bits of `phys_base` are masked off (4 KiB alignment, architectural
/// `[51:12]` address field); `id_bits` should be [`LPI_ID_BITS`].
pub const fn propbaser_value(phys_base: u64, id_bits: u8) -> u64 {
    (phys_base & 0x000f_ffff_ffff_f000)
        | (BASER_CACHE_RAWAWB << 7)
        | (BASER_SHAREABILITY_INNER << 10)
        | (id_bits as u64 & 0x1f)
}

/// Encode `GICR_PENDBASER`: the LPI pending-state bitmap, ONE PER
/// REDISTRIBUTOR (never shared — two redistributors sharing a pending
/// table would each think the other's LPI delivery is its own). Low 16
/// bits of `phys_base` are masked off: the architectural address field is
/// `[51:16]`, i.e. **64 KiB alignment**, stricter than PROPBASER's 4 KiB —
/// verified against `GICR_PENDBASER_ADDRESS`'s own mask
/// (`GENMASK_ULL(51,16)` vs PROPBASER's `GENMASK_ULL(51,12)`) rather than
/// assumed uniform with PROPBASER, which is exactly the kind of
/// off-by-a-field-width mistake this project's own canary discipline
/// exists to catch. `ptz`: true if the caller already zeroed the table
/// (lets the redistributor skip its own zeroing pass) — this driver's
/// caller always zeroes its `static` before calling, so always passes
/// `true`.
pub const fn pendbaser_value(phys_base: u64, ptz: bool) -> u64 {
    const PTZ_BIT: u64 = 1 << 62;
    (phys_base & 0x000f_ffff_ffff_0000)
        | (BASER_CACHE_RAWAWB << 7)
        | (BASER_SHAREABILITY_INNER << 10)
        | if ptz { PTZ_BIT } else { 0 }
}


/// `GENMASK_ULL(hi, lo)` — inclusive bit range, same semantics as the
/// Linux macro this module's encoders are checked against. `hi == 63` is
/// handled separately because `1u64 << 64` is a shift-overflow panic in
/// debug builds, not merely UB, and every 64-bit-wide field this module
/// touches (`Valid`, `PTZ`) needs exactly that case.
pub const fn genmask(hi: u32, lo: u32) -> u64 {
    debug_assert!(hi < 64 && lo <= hi);
    if hi == 63 {
        !0u64 << lo
    } else {
        ((1u64 << (hi + 1)) - 1) & !((1u64 << lo) - 1)
    }
}


// ---- GITS_TYPER decode --------------------------------------------------

pub const fn typer_plpis(typer: u64) -> bool {
    typer & 1 != 0
}
/// `GITS_TYPER.PTA` (bit 19) — 0: a collection's `target` field is a
/// linear Processor Number (redistributor's own `GICR_TYPER` bits
/// [23:8]); 1: `target` is the redistributor's physical base address.
/// [`ItsDriver::init`] reads this once and picks the matching
/// `collection_target_*` helper below — never assumed either way.
pub const fn typer_pta(typer: u64) -> bool {
    typer & (1 << 19) != 0
}
/// `GITS_TYPER.HCC` (bits [31:24]) — Hardware Collection Count, the
/// number of collections usable WITHOUT a memory-backed Collections
/// table. See this module's header doc for why stage 1a relies on this
/// being `>= 1` instead of building that table.
pub const fn typer_hcc(typer: u64) -> u8 {
    ((typer >> 24) & 0xff) as u8
}

// ---- ITS command opcodes (GITS_CMD_*) -----------------------------------

pub const GITS_CMD_MOVI: u8 = 0x01;
pub const GITS_CMD_INT: u8 = 0x03;
pub const GITS_CMD_CLEAR: u8 = 0x04;
pub const GITS_CMD_SYNC: u8 = 0x05;
pub const GITS_CMD_MAPD: u8 = 0x08;
pub const GITS_CMD_MAPC: u8 = 0x09;
pub const GITS_CMD_MAPTI: u8 = 0x0a;
pub const GITS_CMD_MAPI: u8 = 0x0b;
pub const GITS_CMD_INV: u8 = 0x0c;
pub const GITS_CMD_INVALL: u8 = 0x0d;
pub const GITS_CMD_MOVALL: u8 = 0x0e;
pub const GITS_CMD_DISCARD: u8 = 0x0f;

/// Every ITS command is 32 bytes: four 64-bit doublewords.
pub type ItsCommand = [u64; 4];

/// `MAPD` — bind `device_id` to an Interrupt Translation Table at
/// `itt_addr` (must be 256-byte aligned — the architectural ITT address
/// field is `[51:8]`, so any nonzero low byte is silently dropped by the
/// hardware, not rejected). `id_bits_minus1` is the number of EventID
/// bits this device's ITT covers, minus one (i.e. `log2(event_capacity)
/// - 1`) — the same "Size" field Linux's `its_build_mapd_cmd` derives
/// from `ilog2(nr_ites)`.
pub const fn cmd_mapd(dev: u32, id_bits_minus1: u8, itt_addr: u64, valid: bool) -> ItsCommand {
    let dw0 = (GITS_CMD_MAPD as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = (id_bits_minus1 as u64) & genmask(4, 0);
    let dw2 = (itt_addr & genmask(51, 8)) | if valid { genmask(63, 63) } else { 0 };
    [dw0, dw1, dw2, 0]
}

/// `MAPC` — bind collection `col` to `target` (pre-shifted by
/// [`collection_target_cpu_number`] or [`collection_target_rdbase`] —
/// its low 16 bits MUST already be zero, which both of those guarantee;
/// see their docs for why masking here alone is not equivalent to
/// Linux's `its_encode_target`'s explicit `>> 16` unless that holds).
pub const fn cmd_mapc(col: u16, target: u64, valid: bool) -> ItsCommand {
    let dw0 = GITS_CMD_MAPC as u64 & genmask(7, 0);
    let dw2 = ((col as u64) & genmask(15, 0))
        | (target & genmask(51, 16))
        | if valid { genmask(63, 63) } else { 0 };
    [dw0, 0, dw2, 0]
}

/// `MAPTI` — map `dev`'s `event_id` to physical INTID `phys_id`
/// (>= [`crate::irq::gic::LPI_INTID_BASE`]) in collection `col`.
pub const fn cmd_mapti(dev: u32, event_id: u32, phys_id: u32, col: u16) -> ItsCommand {
    let dw0 = (GITS_CMD_MAPTI as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = ((event_id as u64) & genmask(31, 0)) | (((phys_id as u64) << 32) & genmask(63, 32));
    let dw2 = (col as u64) & genmask(15, 0);
    [dw0, dw1, dw2, 0]
}

/// `INVALL` — invalidate cached config for every LPI in collection `col`.
pub const fn cmd_invall(col: u16) -> ItsCommand {
    let dw0 = GITS_CMD_INVALL as u64 & genmask(7, 0);
    let dw2 = (col as u64) & genmask(15, 0);
    [dw0, 0, dw2, 0]
}

/// One shape shared by `INV`/`CLEAR`/`DISCARD`/`INT` — all four take just
/// `(device_id, event_id)`, differing only in opcode.
const fn cmd_dev_event(opcode: u8, dev: u32, event_id: u32) -> ItsCommand {
    let dw0 = (opcode as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = (event_id as u64) & genmask(31, 0);
    [dw0, dw1, 0, 0]
}
pub const fn cmd_inv(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_INV, dev, event_id)
}
pub const fn cmd_clear(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_CLEAR, dev, event_id)
}
pub const fn cmd_discard(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_DISCARD, dev, event_id)
}

/// `SYNC` — drain the ITS's internal pipeline for `target`'s redistributor
/// before any command queued after this one is guaranteed visible there.
/// [`ItsDriver`] issues one after every mapping command and polls
/// `GITS_CREADR` past it — the only completion signal this driver uses.
pub const fn cmd_sync(target: u64) -> ItsCommand {
    let dw0 = GITS_CMD_SYNC as u64 & genmask(7, 0);
    let dw2 = target & genmask(51, 16);
    [dw0, 0, dw2, 0]
}

/// A collection `target` when `GITS_TYPER.PTA == 0`: the redistributor's
/// own linear Processor Number ([`crate::irq::gic::typer_cpu_number`]),
/// pre-shifted into the position [`cmd_mapc`]/[`cmd_sync`] expect (bits
/// [51:16] of the raw command — Linux's `its_encode_target` gets there by
/// right-shifting `target_addr` by 16 first; shifting `cpu_number` LEFT by
/// 16 up front and masking `[51:16]` directly is the same result exactly
/// because the low 16 bits are zero either way — see the module doc's
/// verified-not-recalled note for where this equivalence was checked).
pub const fn collection_target_cpu_number(cpu_number: u16) -> u64 {
    (cpu_number as u64) << 16
}

/// A collection `target` when `GITS_TYPER.PTA == 1`: the redistributor's
/// physical `RD_base` directly (already 64 KiB aligned, so its own low 16
/// bits are zero — same masking argument as
/// [`collection_target_cpu_number`]).
pub const fn collection_target_rdbase(rd_phys_base: u64) -> u64 {
    rd_phys_base
}

// ---- GITS_CBASER / GITS_BASERn ------------------------------------------

/// `GIC_BASER_CACHE_RaWaWb` (architecture spec naming, value `0b111`) —
/// Normal Read-allocate/Write-allocate Write-Back. Same choice as
/// `gic.rs`'s `BASER_CACHE_RAWAWB` and the same reasoning (this module's
/// doc's memory-attribute note); duplicated here as its own named
/// constant because `GITS_CBASER`/`GITS_BASERn`'s cacheability field sits
/// at a DIFFERENT bit shift (59) than `GICR_PROPBASER`/`PENDBASER`'s (7),
/// so the two crates' constants are not interchangeable even though the
/// 3-bit code is.


/// One LPI Configuration table entry (GICv3 §5.1.1): priority in bits
/// [7:2], bit 1 RES1-as-0 here, bit 0 = Enable. The table is indexed from
/// LPI 8192 (`byte[intid - LPI_INTID_BASE]`). An entry left at 0 (the
/// static table's initial value) is a DISABLED LPI: the ITS still
/// translates the device's write, and the redistributor drops it — which is
/// how the first wave-4 boot read `tx used=1` with zero LPIs delivered.
/// Priority 0xA0 matches the SPIs `init_distributor` programs; the CPU
/// interface's PMR is 0xFF, so it is never masked.
pub const LPI_DEFAULT_PRIORITY: u8 = 0xA0;
pub const fn lpi_config_byte(priority: u8, enabled: bool) -> u8 {
    (priority & 0xFC) | if enabled { 1 } else { 0 }
}

pub const BASER_TYPE_DEVICE: u8 = 1;
pub const BASER_TYPE_COLLECTION: u8 = 4;

/// `GITS_BASERn.Type` (bits [58:56]) — which table this slot describes.
/// Software must probe all 8 `GITS_BASERn` registers and read each one's
/// reset value to find out (the slot→type binding is hardware-fixed, NOT
/// index 0 == Devices — a driver that assumed that would work on some
/// implementations and silently misprogram others).
pub const fn baser_type(reg: u64) -> u8 {
    ((reg >> 56) & 0x7) as u8
}
/// `GITS_BASERn.EntrySize` (bits [52:48], value+1) — bytes per table
/// entry, hardware-defined and read-only; software sizes the table from
/// this, never assumes a fixed entry width.
pub const fn baser_entry_size(reg: u64) -> u32 {
    (((reg >> 48) & 0x1f) as u32) + 1
}

/// Rebuild a `GITS_BASERn` value from its own reset value `existing`
/// (which supplies the hardware-fixed `Type`/`EntrySize`/`Indirect` bits
/// this function must NOT clobber), pointing it at `phys_base`
/// (4 KiB-aligned, `n_pages_minus1` 4 KiB pages) and setting `Valid`.
pub const fn baser_value(existing: u64, phys_base: u64, n_pages_minus1: u8, valid: bool) -> u64 {
    let preserved = existing & (genmask(62, 62) | genmask(58, 48)); // Indirect, Type, EntrySize
    preserved
        | (BASER_CACHE_RAWAWB << 59)
        | (BASER_SHAREABILITY_INNER << 10)
        | (phys_base & genmask(47, 12))
        | (n_pages_minus1 as u64 & genmask(7, 0))
        | if valid { genmask(63, 63) } else { 0 }
}

/// `GITS_CBASER` — the command queue's own base/size/valid.
pub const fn cbaser_value(phys_base: u64, n_pages_minus1: u8, valid: bool) -> u64 {
    (BASER_CACHE_RAWAWB << 59)
        | (BASER_SHAREABILITY_INNER << 10)
        | (phys_base & genmask(51, 12))
        | (n_pages_minus1 as u64 & genmask(7, 0))
        | if valid { genmask(63, 63) } else { 0 }
}

/// Absolute address of `GITS_TRANSLATER` — the ONE register a PCI
/// function's MSI-X address points at. Frame layout (verified against
/// Linux's `GITS_TRANSLATER == 0x10040` relative to the ITS control
/// frame's own base): control frame `[GITS_BASE, +0x10000)`, translation
/// frame `[GITS_BASE+0x10000, +0x20000)`, register at `+0x40` within
/// that second frame.
pub const fn translater_address(its_base: usize) -> usize {
    its_base + 0x1_0000 + 0x0040
}

/// The MSI address/data pair for `event_id` on the ITS at `its_base` —
/// exactly what a PCI MSI-X table entry needs (address = where to write,
/// data = what to write). This is the "arch hook" `A2-pci.diff` wires
/// `crates/drivers/virtio/src/virtio/pci.rs`'s `msix_vector` doc up to, in place
/// of the `VIRTIO_PCI_NO_VECTOR` it programs today.
pub const fn msi_target(its_base: usize, event_id: u32) -> (u64, u32) {
    (translater_address(its_base) as u64, event_id)
}


pub mod regs {
    pub const GITS_CTLR: usize = 0x0000;
    pub const GITS_TYPER: usize = 0x0008;
    pub const GITS_CBASER: usize = 0x0080;
    pub const GITS_CWRITER: usize = 0x0088;
    pub const GITS_CREADR: usize = 0x0090;
    pub const GITS_BASER0: usize = 0x0100;
    pub const GITS_CTLR_ENABLE: u32 = 1 << 0;
    pub const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
}
