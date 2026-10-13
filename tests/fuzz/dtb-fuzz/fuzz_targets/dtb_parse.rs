// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: every `unsafe fn dtb_*(ptr)` entry point of
//! `azos_dtb`, plus the pure cell decoders, on an arbitrary blob.
//!
//! The one precondition the parser documents and cannot check itself is
//! "`ptr` is readable for the blob's own `totalsize`" (the header field that
//! bounds every later read). The harness honours it the way firmware does:
//! the blob handed to the parser is exactly as long as the input, and the
//! header's `totalsize` is clamped to that length. Without the clamp a
//! 55-byte input claiming 2 MiB is a harness bug, not a parser bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use azos_dtb::{
    decode_gic_spi, decode_pci_ranges, decode_reg_first, dtb_compatible_str, dtb_cpu_regs,
    dtb_irq_triggers, dtb_parse, dtb_pci_host, dtb_pl011_irq, dtb_probe, IrqController,
};

/// `FDT_HEADER_SIZE`: the bytes the parser reads before it knows anything.
const HDR: usize = 40;

fuzz_target!(|data: &[u8]| {
    // Pure decoders first: they take slices, so any input is a valid call.
    if data.len() >= 3 {
        let (ac, sc) = (u32::from(data[0] & 7), u32::from(data[1] & 7));
        let _ = decode_reg_first(&data[2..], ac, sc);
        let _ = decode_pci_ranges(&data[2..], ac, u32::from(data[1] >> 4), sc);
        let cells = [u32::from(data[0]), u32::from(data[1]), u32::from(data[2])];
        let _ = decode_gic_spi(Some(cells));
    }
    if data.len() < HDR {
        return;
    }
    // A heap copy of exactly `len` bytes: ASan flags any read past it.
    let mut blob = data.to_vec();
    let claimed = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    let size = claimed.min(blob.len()) as u32;
    blob[4..8].copy_from_slice(&size.to_be_bytes());
    let p = blob.as_ptr();
    unsafe {
        let _ = dtb_probe(p);
        if let Some(info) = dtb_parse(p) {
            let _ = dtb_compatible_str(&info);
        }
        let mut regs = [0u64; 8];
        let _ = dtb_cpu_regs(p, &mut regs);
        let _ = dtb_pci_host(p);
        let _ = dtb_irq_triggers(p, IrqController::GicV3);
        let _ = dtb_irq_triggers(p, IrqController::AplicS);
        let _ = dtb_pl011_irq(p);
    }
});
