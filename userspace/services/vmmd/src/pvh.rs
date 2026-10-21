// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot information of an x86_64 guest: the PVH `hvm_start_info`
//! (xen/include/public/arch-x86/hvm/start_info.h, version 1), its memory map
//! and its command line, built as one blob for a fixed place in RAM.
//!
//! A PVH kernel starts in 32-bit protected mode with paging off, `ebx` the
//! guest-physical address of the start_info (the entry is the kernel's
//! `XEN_ELFNOTE_PHYS32_ENTRY` note, `loader`). There is no firmware, so the
//! blob carries everything the kernel is told:
//!
//! * the memory map: RAM below the legacy hole, the hole reserved, RAM above
//!   1 MiB to the end of the guest's memory (a PC's shape, which is what a
//!   kernel written for the PVH machine expects);
//! * the command line: the monitor's `virtio_mmio.device=<size>@<base>:<irq>`
//!   entry for each device of the row (no machine model fixes their place on
//!   x86, so the line is the guest's only way to find them), then the owner's
//!   arguments.
//!
//! No modules, no RSDP: a guest has no ACPI tables (`rsdp_paddr` 0).

use core::fmt::Write;

/// Where the blob goes: the page layout of a PC's low memory, clear of the
/// real-mode vectors and of the kernel at 1 MiB.
pub const BASE: u64 = 0x6000;
/// The most the blob takes (it is placed whole in the page(s) at [`BASE`]).
pub const MAX_BYTES: usize = 4096;

/// `hvm_start_info`'s magic.
pub const MAGIC: u32 = 0x336e_c578;
const VERSION: u32 = 1;
const START_INFO_BYTES: usize = 56;
const MEMMAP_ENTRY_BYTES: usize = 24;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
/// The legacy hole below 1 MiB (video memory, option ROMs, BIOS).
const HOLE_START: u64 = 0xA_0000;
const HOLE_END: u64 = 0x10_0000;

/// What the blob is built from.
pub struct Info<'a> {
    /// Bytes of guest RAM from address 0.
    pub ram_bytes: u64,
    /// Where each device of the row sits: `(window base, window length, irq line)`.
    pub devices: &'a [(u64, u64, u32)],
    /// The owner's arguments, appended to the monitor's.
    pub args: &'a [u8],
}

/// Why no blob was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PvhError {
    /// The guest's RAM does not reach past the legacy hole.
    RamTooSmall,
    /// The blob does not fit [`MAX_BYTES`] (or the caller's buffer).
    Full,
}

/// A `fmt::Write` into a byte slice that fails when it is full.
struct Cursor<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.at.checked_add(s.len()).filter(|&e| e <= self.buf.len()).ok_or(core::fmt::Error)?;
        self.buf[self.at..end].copy_from_slice(s.as_bytes());
        self.at = end;
        Ok(())
    }
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Build the blob into `out` (which is placed at [`BASE`]): the number of bytes.
pub fn build(info: &Info, out: &mut [u8]) -> Result<usize, PvhError> {
    if info.ram_bytes <= HOLE_END {
        return Err(PvhError::RamTooSmall);
    }
    let out = out.get_mut(..MAX_BYTES).ok_or(PvhError::Full)?;
    out.fill(0);
    let map: [(u64, u64, u32); 3] = [
        (0, HOLE_START, E820_RAM),
        (HOLE_START, HOLE_END - HOLE_START, E820_RESERVED),
        (HOLE_END, info.ram_bytes - HOLE_END, E820_RAM),
    ];
    let map_at = START_INFO_BYTES;
    for (i, &(addr, size, kind)) in map.iter().enumerate() {
        let e = map_at + i * MEMMAP_ENTRY_BYTES;
        put64(out, e, addr);
        put64(out, e + 8, size);
        put32(out, e + 16, kind);
    }
    let cmd_at = map_at + map.len() * MEMMAP_ENTRY_BYTES;
    let mut c = Cursor { buf: &mut out[cmd_at..], at: 0 };
    for &(base, len, irq) in info.devices {
        write!(c, "virtio_mmio.device={len:#x}@{base:#x}:{irq} ").map_err(|_| PvhError::Full)?;
    }
    if c.at + info.args.len() + 1 > c.buf.len() {
        return Err(PvhError::Full);
    }
    c.buf[c.at..c.at + info.args.len()].copy_from_slice(info.args);
    // A trailing space of the device entries stays when there are no
    // arguments: harmless to every command-line parser.
    let cmd_end = cmd_at + c.at + info.args.len() + 1; // the NUL is already there

    put32(out, 0, MAGIC);
    put32(out, 4, VERSION);
    // flags 0: not a dom0, no console of the hypervisor's.
    // nr_modules 0, modlist 0, rsdp 0 (the zero fill).
    // magic 0, version 4, flags 8, nr_modules 12, modlist_paddr 16,
    // cmdline_paddr 24, rsdp_paddr 32, memmap_paddr 40, memmap_entries 48.
    put64(out, 24, BASE + cmd_at as u64);
    put64(out, 40, BASE + map_at as u64);
    put32(out, 48, map.len() as u32);
    Ok(cmd_end)
}
