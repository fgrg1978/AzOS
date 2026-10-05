// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! OTA wire-format microbenchmarks (pure layer — no FS, no drivers).
//!
//! CRC-32 dominates OTA image verification; the header parse runs once per
//! transfer.  Both are pure compute, good signal under TCG.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_ota::pure;

/// CRC-32 over a 256-byte chunk (one `PKT_OTA_CHUNK` payload).  Per-chunk
/// integrity cost; the full-image CRC is this × (image_size / 256).
pub fn bench_crc32_256B(iters: u64) -> BenchResult {
    let data = [0x42u8; 256];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(pure::crc32(&data));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `ota_parse_header` — magic + version check + 4× u32 parse over the
/// 24-byte header.  Pre-encode a valid header outside the timed loop.
pub fn bench_ota_parse_header(iters: u64) -> BenchResult {
    let h = pure::OtaHeader {
        header_version: pure::OTA_HEADER_VERSION,
        image_size:     1024,
        image_crc32:    0xDEAD_BEEF,
        fw_version:     1,
        platform_id:    pure::OTA_PLATFORM_QEMU,
        flags:          0,
    };
    let mut buf = [0u8; pure::OTA_HEADER_SIZE];
    pure::ota_encode_header(&h, &mut buf);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(pure::ota_parse_header(&buf));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("ota.crc32_256B",      &best_of(|| bench_crc32_256B(iters)));      n += 1;
    report("ota.parse_header",    &best_of(|| bench_ota_parse_header(iters))); n += 1;
    n
}
