// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CRC-32C (Castagnoli, reflected, polynomial 0x82F63B78), the checksum of
//! every azvol block. Not the IEEE CRC-32 that `pstore.rs` and the partition
//! parser carry: Castagnoli is the one with hardware support on all three
//! ISAs (SSE4.2 `crc32`, ARMv8 `crc32c*`, Zbc on RISC-V), so the kernel mount
//! can swap the table loop for the instruction without a format change.
//!
//! Table-driven (1 KiB in `.rodata`, built at compile time): the checksum is
//! on the path of every block read, unlike the boot-time bitwise IEEE copies.

const fn make_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = make_table();

/// Continue a checksum: pass `0` to start, feed the result back to go on.
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// CRC-32C of `data`. `crc32c(b"123456789") == 0xE3069283`.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0, data)
}
