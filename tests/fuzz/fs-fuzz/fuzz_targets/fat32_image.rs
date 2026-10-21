// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: an arbitrary FAT32 medium through the real driver —
//! mount (BPB validation, journal recovery), directory listing, chain reads,
//! open/read by path, and a create/rename/unlink cycle that must leave the
//! free-cluster count where it found it. See
//! `tests/host/fs-tests/src/lib.rs::fuzz_entry`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    azos_fs_tests::fuzz_entry::fat32_image(data);
});
