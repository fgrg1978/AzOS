// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! OT01 — host-side unit tests for the pure OTA logic.
//!
//! Pulls in `crates/core/ota/src/pure.rs` directly via `#[path]` so we test the
//! exact same source the kernel uses, without dragging in the FAT32 +
//! drivers crates (which can't be built for the host).

#[path = "../../../../crates/core/ota/src/pure.rs"]
pub mod pure;

// DEV02 — recovery-mode entry trigger logic. Same #[path] pattern.
#[path = "../../../../crates/core/ota/src/recovery.rs"]
pub mod recovery;

#[cfg(test)]
mod tests {
    use super::pure::*;

    // ── Test fixtures ──────────────────────────────────────────────────

    /// Acceptance ceiling used by these tests.
    ///
    /// The real ceiling is `azos_ota::OTA_MAX_IMAGE_SIZE`, which comes
    /// from Kconfig (`OTA_MAX_IMAGE_SIZE_MB`). It deliberately does NOT live
    /// in `pure`, because this crate `#[path]`-includes `pure.rs` directly and
    /// that file must stay dependency-free — so `ota_validate_header` takes
    /// the ceiling as a parameter. These tests exercise the boundary logic
    /// with a fixed value of their own; they are testing the comparison, not
    /// the configured number.
    const TEST_MAX_IMAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Build a header that should validate against the QEMU platform.
    fn good_header() -> OtaHeader {
        OtaHeader {
            header_version: OTA_HEADER_VERSION,
            image_size:     1024,
            image_crc32:    0xDEADBEEF,
            fw_version:     0x00_01_02_03,
            platform_id:    OTA_PLATFORM_QEMU,
            flags:          0,
        }
    }

    fn encode(h: &OtaHeader) -> [u8; OTA_HEADER_SIZE] {
        let mut buf = [0u8; OTA_HEADER_SIZE];
        ota_encode_header(h, &mut buf);
        buf
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.A — Header roundtrip + brain-side encode/kernel-side decode sync
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn header_roundtrip_preserves_all_fields() {
        let h = good_header();
        let buf = encode(&h);
        let decoded = ota_parse_header(&buf).expect("valid header must parse");
        assert_eq!(h, decoded);
    }

    #[test]
    fn header_decode_rejects_buffer_smaller_than_header_size() {
        let buf = [0u8; OTA_HEADER_SIZE - 1];
        assert!(ota_parse_header(&buf).is_none());
    }

    #[test]
    fn header_magic_is_rota_ascii() {
        assert_eq!(&OTA_MAGIC, b"ROTA");
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.B — CRC32 vectors (IEEE 802.3, polynomial 0xEDB88320)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn crc32_known_vectors() {
        // Standard test vectors for CRC-32/ISO-HDLC (== IEEE 802.3).
        // Source: https://reveng.sourceforge.io/crc-catalogue/all.htm
        assert_eq!(crc32(b""),               0x0000_0000);
        assert_eq!(crc32(b"a"),              0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"),      0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"),
                   0x414F_A339);
    }

    #[test]
    fn crc32_streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = crc32(data);

        // Feed in 4 chunks
        let mut state = Crc32State::new();
        state.update(&data[0..10]);
        state.update(&data[10..20]);
        state.update(&data[20..30]);
        state.update(&data[30..]);
        assert_eq!(state.finalize(), oneshot);
    }

    #[test]
    fn crc32_state_empty_matches_oneshot_empty() {
        let state = Crc32State::new();
        assert_eq!(state.finalize(), crc32(b""));
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.C — Header magic / version invalid → parse returns None
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn header_with_wrong_magic_is_rejected() {
        let mut buf = encode(&good_header());
        buf[0] = b'X'; // corrupt magic
        assert!(ota_parse_header(&buf).is_none());
    }

    #[test]
    fn header_with_wrong_version_is_rejected() {
        let h = OtaHeader { header_version: 99, ..good_header() };
        let buf = encode(&h);
        // Note: encode writes 99 into the version field; parse will reject
        // because OTA_HEADER_VERSION is 1.
        assert!(ota_parse_header(&buf).is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.D — Platform ID mismatch is rejected by validate
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_platform_mismatch() {
        let h = OtaHeader { platform_id: OTA_PLATFORM_VF2, ..good_header() };
        // Running on QEMU, image targets VF2 → reject.
        assert!(!ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
        // Running on VF2 with VF2 image → accept.
        assert!(ota_validate_header(&h, OTA_PLATFORM_VF2, TEST_MAX_IMAGE_SIZE));
    }

    #[test]
    fn validate_accepts_matching_platform() {
        let h = good_header();
        assert!(ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.E — Image size > the acceptance ceiling is rejected
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_oversize_image() {
        let h = OtaHeader {
            image_size: (TEST_MAX_IMAGE_SIZE + 1) as u32,
            ..good_header()
        };
        assert!(!ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
    }

    #[test]
    fn validate_accepts_image_at_exact_max_size() {
        let h = OtaHeader {
            image_size: TEST_MAX_IMAGE_SIZE as u32,
            ..good_header()
        };
        assert!(ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
    }

    #[test]
    fn validate_rejects_zero_size_image() {
        let h = OtaHeader {
            image_size: 0,
            ..good_header()
        };
        assert!(!ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
    }

    #[test]
    fn validate_rejects_compressed_flag_until_supported() {
        let h = OtaHeader { flags: OTA_FLAG_COMPRESSED, ..good_header() };
        assert!(!ota_validate_header(&h, OTA_PLATFORM_QEMU, TEST_MAX_IMAGE_SIZE));
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.F — Boot-loop simulation: panic 4× → automatic rollback
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn boot_count_increments_on_each_boot() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 0,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::Normal);
        assert_eq!(meta.boot_count, 1);
        assert_eq!(meta.active_slot, SLOT_B); // not yet rolled back
    }

    /// Regression: `boot_count` at `u32::MAX` must saturate, not overflow.
    ///
    /// `parse_u32_simple` saturates rather than rejecting, so
    /// `boot_count=4294967295` in BOOTMETA survives parsing intact and
    /// arrives here as a real value. The kernel builds with
    /// `overflow-checks = true` and `panic = "abort"`, so the old
    /// `meta.boot_count += 1` was a board reset on every boot — and
    /// `ota_boot_validate()` runs unconditionally at boot, making it an
    /// unrecoverable reset loop. BOOTMETA is writable over USB mass storage,
    /// so this is reachable, not theoretical.
    ///
    /// NOTE: this test would abort the test process rather than fail if the
    /// fix regressed, because the `+=` panics. `cargo test` reports that as a
    /// failed test binary, which is the signal we want either way.
    #[test]
    fn boot_count_at_u32_max_saturates_instead_of_overflowing() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: u32::MAX,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        // u32::MAX > max_attempts, so the correct response is the rollback
        // branch: return to last_good and restart the count at this attempt.
        assert_eq!(outcome, BootValidateOutcome::RolledBack);
        assert_eq!(meta.active_slot, SLOT_A);
        assert_eq!(meta.boot_count, 1);
    }

    /// The saturation must hold for a value one below the ceiling too — that
    /// is the case where a plain `+= 1` still fits and the *next* one does
    /// not, i.e. the boot before the brick.
    #[test]
    fn boot_count_near_u32_max_rolls_back_without_wrapping() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: u32::MAX - 1,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::RolledBack);
        assert_eq!(meta.boot_count, 1);
    }

    /// A BOOTMETA carrying an out-of-range `boot_count` must round-trip
    /// through the parser as `u32::MAX` (saturated) rather than wrapping —
    /// this is the input half of the pair above, and the reason the value
    /// can reach `ota_boot_validate_pure` at all.
    #[test]
    fn parser_saturates_absurd_boot_count_rather_than_wrapping() {
        let text = b"active_slot=b\nboot_count=99999999999999999999\nlast_good=a\n";
        let meta = parse_boot_meta(text);
        assert_eq!(meta.boot_count, u32::MAX);
    }

    #[test]
    fn boot_count_at_max_does_not_yet_rollback() {
        // boot_count starts at max-1 (2), increments to max (3), still OK.
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 2,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::Normal);
        assert_eq!(meta.boot_count, 3);
        assert_eq!(meta.active_slot, SLOT_B);
    }

    #[test]
    fn boot_count_exceeding_max_triggers_rollback() {
        // boot_count is already at max (3), this would be the 4th attempt.
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 3,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::RolledBack);
        // Active slot must have been swapped to last_good
        assert_eq!(meta.active_slot, SLOT_A);
        // Boot count resets to 1 (counts THIS boot attempt)
        assert_eq!(meta.boot_count, 1);
    }

    /// Owner decision 2026-09-28. Already on last_good with the attempts
    /// spent: there is nothing to roll back to. This used to "roll back" onto
    /// the same slot and reset the count to 1 — a crash loop with no end. The
    /// count is now kept (and keeps climbing) and the outcome is `Exhausted`,
    /// which the kernel answers with safe mode.
    ///
    /// **Canary**: remove the `last_good == active_slot` arm in
    /// `ota_boot_validate_pure`: RolledBack, count 1.
    #[test]
    fn exhausted_when_already_on_last_good_keeps_the_count() {
        let mut meta = BootMeta {
            active_slot: SLOT_A, last_good: SLOT_A, boot_count: 5,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::Exhausted);
        assert_eq!(meta.active_slot, SLOT_A);
        assert_eq!(meta.boot_count, 6);
        assert!(ota_boot_exhausted(&meta, 3));
    }

    /// Full "boot-loop" simulation: 4 consecutive failed boots into slot B.
    #[test]
    fn boot_loop_simulation_4_panics_rolls_back() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 0,
            ..BootMeta::default()
        };
        // Boot 1, 2, 3 — all Normal.
        for expected_count in 1u32..=3 {
            let o = ota_boot_validate_pure(&mut meta, 3);
            assert_eq!(o, BootValidateOutcome::Normal);
            assert_eq!(meta.boot_count, expected_count);
            assert_eq!(meta.active_slot, SLOT_B);
        }
        // Boot 4 — boot_count was 3, increments to 4, which exceeds max=3.
        let o = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(o, BootValidateOutcome::RolledBack);
        assert_eq!(meta.active_slot, SLOT_A);
        assert_eq!(meta.boot_count, 1);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.G — mark_boot_good resets boot_count and updates last_good
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn mark_boot_good_resets_count_to_zero() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 2,
            ..BootMeta::default()
        };
        ota_mark_boot_good_pure(&mut meta);
        assert_eq!(meta.boot_count, 0);
        // last_good now tracks the (successful) active_slot
        assert_eq!(meta.last_good, SLOT_B);
        // active_slot itself unchanged
        assert_eq!(meta.active_slot, SLOT_B);
    }

    #[test]
    fn mark_boot_good_then_validate_starts_fresh_at_one() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 2,
            ..BootMeta::default()
        };
        ota_mark_boot_good_pure(&mut meta);
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::Normal);
        assert_eq!(meta.boot_count, 1);
        assert_eq!(meta.last_good, SLOT_B);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.H — BOOTMETA serialize/parse roundtrip
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn bootmeta_serialize_parse_roundtrip() {
        let original = BootMeta {
            active_slot:  SLOT_B,
            boot_count:   42,
            last_good:    SLOT_A,
            fw_version_a: 0x0100_0001,
            fw_version_b: 0x0100_0002,
            fw_version_r: 0x0100_0000,
            image_size_a: 524288,
            image_size_b: 524300,
            image_size_r: 524288,
            image_crc_a:  0xCAFE_BABE,
            image_crc_b:  0xDEAD_F00D,
            image_crc_r:  0x1234_5678,
            min_fw_version: 0x0100_0001,
            authenticated_fw_version_a: 0x0100_0001,
            authenticated_fw_version_b: 0,
            bad_slots:    1 << SLOT_R,
        };

        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&original, &mut buf);
        assert!(n > 0 && n <= buf.len());

        let parsed = parse_boot_meta(&buf[..n]);
        assert_eq!(original, parsed);
    }

    #[test]
    fn bootmeta_parse_handles_unknown_keys_and_comments() {
        let text = b"# this is a comment\n\
                     active_slot=b\n\
                     unknown_key=hello\n\
                     boot_count=5\n\
                     last_good=a\n\
                     fw_version_a=1\n\
                     fw_version_b=2\n\
                     image_size_a=100\n\
                     image_size_b=200\n\
                     image_crc_a=300\n\
                     image_crc_b=400\n";
        let meta = parse_boot_meta(text);
        assert_eq!(meta.active_slot,  SLOT_B);
        assert_eq!(meta.boot_count,   5);
        assert_eq!(meta.last_good,    SLOT_A);
        assert_eq!(meta.fw_version_a, 1);
        assert_eq!(meta.fw_version_b, 2);
        assert_eq!(meta.image_size_a, 100);
        assert_eq!(meta.image_size_b, 200);
        assert_eq!(meta.image_crc_a,  300);
        assert_eq!(meta.image_crc_b,  400);
        // OT04 — this text predates the `_r` fields entirely (as every
        // BOOTMETA on disk today does). Absent keys must read back as 0,
        // not panic or pick up garbage.
        assert_eq!(meta.fw_version_r, 0);
        assert_eq!(meta.image_size_r, 0);
        assert_eq!(meta.image_crc_r,  0);
    }

    #[test]
    fn bootmeta_parse_empty_returns_default() {
        let meta = parse_boot_meta(b"");
        assert_eq!(meta, BootMeta::default());
    }

    #[test]
    fn bootmeta_parse_garbage_does_not_panic() {
        let garbage = b"\x00\xFF\xAB\x12==\nlolwut\n";
        let _ = parse_boot_meta(garbage); // must not panic
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT01.I — Slot inversion logic
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn inactive_slot_is_b_when_active_is_a() {
        assert_eq!(ota_inactive_slot_pure(SLOT_A), SLOT_B);
    }

    #[test]
    fn inactive_slot_is_a_when_active_is_b() {
        assert_eq!(ota_inactive_slot_pure(SLOT_B), SLOT_A);
    }

    #[test]
    fn slot_helpers_on_bootmeta_pick_correct_field() {
        let meta = BootMeta {
            fw_version_a: 1, fw_version_b: 2, fw_version_r: 3,
            image_size_a: 10, image_size_b: 20, image_size_r: 30,
            image_crc_a: 100, image_crc_b: 200, image_crc_r: 300,
            ..BootMeta::default()
        };
        assert_eq!(meta.slot_version(SLOT_A), 1);
        assert_eq!(meta.slot_version(SLOT_B), 2);
        assert_eq!(meta.slot_version(SLOT_R), 3);
        assert_eq!(meta.slot_size(SLOT_A),    10);
        assert_eq!(meta.slot_size(SLOT_B),    20);
        assert_eq!(meta.slot_size(SLOT_R),    30);
        assert_eq!(meta.slot_crc(SLOT_A),     100);
        assert_eq!(meta.slot_crc(SLOT_B),     200);
        assert_eq!(meta.slot_crc(SLOT_R),     300);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT02.B — BOOTMETA record with seq + CRC (dual-file power-loss safety)
    // ──────────────────────────────────────────────────────────────────────

    fn record(seq: u32, active: u8, last_good: u8, count: u32) -> BootMetaRecord {
        BootMetaRecord {
            meta: BootMeta {
                active_slot: active,
                last_good,
                boot_count: count,
                ..BootMeta::default()
            },
            seq,
        }
    }

    /// Serialize into a stack-allocated buffer, returning `(buf, len)`.
    fn serialize(rec: &BootMetaRecord) -> ([u8; 512], usize) {
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta_record(rec, &mut buf);
        (buf, n)
    }

    #[test]
    fn record_roundtrip_preserves_meta_and_seq() {
        let rec = BootMetaRecord {
            meta: BootMeta {
                active_slot: SLOT_B,
                boot_count: 5,
                last_good: SLOT_A,
                fw_version_a: 1, fw_version_b: 2, fw_version_r: 3,
                image_size_a: 100, image_size_b: 200, image_size_r: 300,
                image_crc_a: 0xCAFE_BABE,
                image_crc_b: 0xDEAD_F00D,
                image_crc_r: 0xABCD_1234,
                min_fw_version: 1,
                authenticated_fw_version_a: 1,
                authenticated_fw_version_b: 0,
                bad_slots: 1 << SLOT_B,
            },
            seq: 42,
        };

        let (buf, n) = serialize(&rec);
        let bytes = &buf[..n];
        let parsed = parse_boot_meta_record(bytes).expect("valid record must parse");
        assert_eq!(parsed, rec);
    }

    #[test]
    fn record_with_corrupted_payload_is_rejected() {
        let rec = record(7, SLOT_A, SLOT_A, 0);
        let (mut buf, n) = serialize(&rec);
        // Flip a byte inside the body — CRC must no longer match.
        buf[10] ^= 0x01;
        assert!(parse_boot_meta_record(&buf[..n]).is_none());
    }

    #[test]
    fn record_with_wrong_crc_line_is_rejected() {
        let rec = record(7, SLOT_A, SLOT_A, 0);
        let (buf, n) = serialize(&rec);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        // Build the corrupted version into a fresh stack buffer.
        let mut bad = [0u8; 1024];
        let mut len = 0usize;
        for &b in text.as_bytes() {
            bad[len] = b;
            len += 1;
        }
        // Find the "crc=0x" prefix and rewrite the 8 hex digits to FFs.
        let needle = b"crc=0x";
        let mut i = 0;
        while i + needle.len() <= len && &bad[i..i + needle.len()] != needle {
            i += 1;
        }
        if i + needle.len() <= len {
            for j in 0..8 {
                bad[i + needle.len() + j] = b'F';
            }
        }
        assert!(parse_boot_meta_record(&bad[..len]).is_none());
    }

    #[test]
    fn record_missing_crc_line_is_rejected() {
        // Plain serialize_boot_meta output (no `crc=` line) must NOT parse
        // as a record.
        let m = BootMeta { active_slot: SLOT_B, ..BootMeta::default() };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&m, &mut buf);
        assert!(parse_boot_meta_record(&buf[..n]).is_none());
    }

    #[test]
    fn record_truncated_is_rejected() {
        let rec = record(3, SLOT_A, SLOT_A, 0);
        let (buf, n) = serialize(&rec);
        let truncated_len = n / 2;
        assert!(parse_boot_meta_record(&buf[..truncated_len]).is_none());
    }

    #[test]
    fn record_seq_zero_default_is_valid() {
        let rec = BootMetaRecord::default();
        assert_eq!(rec.seq, 0);
        assert_eq!(rec.meta, BootMeta::default());
        let (buf, n) = serialize(&rec);
        let parsed = parse_boot_meta_record(&buf[..n]).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn record_high_seq_roundtrips() {
        let rec = record(u32::MAX, SLOT_B, SLOT_B, 1);
        let (buf, n) = serialize(&rec);
        let parsed = parse_boot_meta_record(&buf[..n]).unwrap();
        assert_eq!(parsed.seq, u32::MAX);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT02.B — record-picker (read side)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn picker_returns_higher_seq_when_both_valid() {
        let r1 = record(10, SLOT_A, SLOT_A, 0);
        let r2 = record(11, SLOT_B, SLOT_A, 0);
        let picked = ota_pick_boot_meta_record(Some(r1), Some(r2)).unwrap();
        assert_eq!(picked.seq, 11);
        assert_eq!(picked.meta.active_slot, SLOT_B);
    }

    #[test]
    fn picker_returns_a_on_seq_tie() {
        let r1 = record(5, SLOT_A, SLOT_A, 0);
        let r2 = record(5, SLOT_B, SLOT_A, 0);
        let picked = ota_pick_boot_meta_record(Some(r1), Some(r2)).unwrap();
        assert_eq!(picked.meta.active_slot, SLOT_A);
    }

    #[test]
    fn picker_returns_only_valid_when_other_is_corrupt() {
        let r = record(7, SLOT_B, SLOT_A, 0);
        assert_eq!(ota_pick_boot_meta_record(Some(r), None).unwrap().seq, 7);
        assert_eq!(ota_pick_boot_meta_record(None, Some(r)).unwrap().seq, 7);
    }

    #[test]
    fn picker_returns_none_when_both_invalid() {
        assert!(ota_pick_boot_meta_record(None, None).is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT02.B — write-slot picker (write side: target the older/invalid file)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn write_slot_targets_a_when_a_missing() {
        let r = record(5, SLOT_B, SLOT_A, 0);
        assert_eq!(ota_pick_meta_write_slot(None, Some(r)), SLOT_A);
    }

    #[test]
    fn write_slot_targets_b_when_b_missing() {
        let r = record(5, SLOT_A, SLOT_A, 0);
        assert_eq!(ota_pick_meta_write_slot(Some(r), None), SLOT_B);
    }

    #[test]
    fn write_slot_targets_a_when_both_empty() {
        // First-ever write goes to A.
        assert_eq!(ota_pick_meta_write_slot(None, None), SLOT_A);
    }

    #[test]
    fn write_slot_targets_lower_seq_when_both_valid() {
        let r_a = record(11, SLOT_A, SLOT_A, 0);
        let r_b = record(10, SLOT_B, SLOT_A, 0);
        // B has lower seq → write should overwrite B.
        assert_eq!(ota_pick_meta_write_slot(Some(r_a), Some(r_b)), SLOT_B);
    }

    #[test]
    fn write_slot_targets_a_on_tie() {
        let r_a = record(5, SLOT_A, SLOT_A, 0);
        let r_b = record(5, SLOT_B, SLOT_A, 0);
        // On tie, the deterministic choice is A (it'll just bump seq+1
        // and B becomes the older one next round).
        assert_eq!(ota_pick_meta_write_slot(Some(r_a), Some(r_b)), SLOT_A);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT02.B — sequence helpers
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn next_seq_starts_at_one_when_no_record() {
        assert_eq!(ota_next_seq(None), 1);
    }

    #[test]
    fn next_seq_increments_existing() {
        let r = record(42, SLOT_A, SLOT_A, 0);
        assert_eq!(ota_next_seq(Some(r)), 43);
    }

    #[test]
    fn next_seq_saturates_at_u32_max() {
        let r = record(u32::MAX, SLOT_A, SLOT_A, 0);
        assert_eq!(ota_next_seq(Some(r)), u32::MAX);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT02.B — power-loss simulation: torn write produces invalid CRC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn power_loss_during_write_simulated_as_truncation() {
        // Simulate writing a record but losing power at every byte boundary.
        // For each truncation length where the CRC value is not yet fully
        // on disk, the partial buffer MUST NOT parse as a valid record.
        // (This is the property OT02.B relies on.)
        //
        // Edge case: dropping only the very last byte (the trailing '\n'
        // after the crc value) is *not* a real torn write — the value was
        // fully written. The parser is allowed to accept that. We exclude
        // it from the loop.
        let rec = record(99, SLOT_B, SLOT_A, 1);
        let (buf, n) = serialize(&rec);
        let upper = n.saturating_sub(1);

        for truncated_len in 0..upper {
            let result = parse_boot_meta_record(&buf[..truncated_len]);
            assert!(
                result.is_none(),
                "truncated record at len={truncated_len} unexpectedly parsed; partial torn write must be detectable"
            );
        }
        // And the full buffer parses cleanly.
        assert_eq!(parse_boot_meta_record(&buf[..n]), Some(rec));
    }

    #[test]
    fn power_loss_keeps_other_file_valid() {
        // Scenario: file A has seq=10 (valid), file B is being written
        // with seq=11 when power is lost mid-write (B becomes corrupt).
        // Read picker must return A's record, not crash, not return B.
        let a = record(10, SLOT_A, SLOT_A, 0);
        let b_corrupt: Option<BootMetaRecord> = None; // CRC mismatch on read returns None

        let picked = ota_pick_boot_meta_record(Some(a), b_corrupt).unwrap();
        assert_eq!(picked.seq, 10);
        assert_eq!(picked.meta.active_slot, SLOT_A);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT03 — Anti-rollback floor (min_fw_version)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn rollback_check_accepts_newer_version() {
        assert!(ota_check_rollback_pure(10, 5));
        assert!(ota_check_rollback_pure(0xFFFF_FFFF, 0));
    }

    #[test]
    fn rollback_check_accepts_equal_version() {
        // Same version is allowed — recovery / re-install is a valid op.
        assert!(ota_check_rollback_pure(7, 7));
    }

    #[test]
    fn rollback_check_rejects_older_version() {
        assert!(!ota_check_rollback_pure(4, 5));
        assert!(!ota_check_rollback_pure(0, 1));
    }

    /// U09-4/U11-4/security finding #10: the floor must advance from the
    /// AUTHENTICATED version, never the sender-reported `fw_version_a/b`
    /// (unsigned wire-header value on an unenforced install). This test
    /// pins both halves of that: `fw_version_b` being large does nothing,
    /// and `authenticated_fw_version_b` being the real driver.
    ///
    /// RED before the fix: this test previously read
    /// `ota_mark_boot_good_pure` advancing the floor from `fw_version_b`
    /// (7) directly — restore that (`meta.slot_version` instead of
    /// `meta.slot_auth_version` in `ota_mark_boot_good_pure`) and the
    /// first assertion below fails (floor stays 1, since
    /// `authenticated_fw_version_b` is 0), while a version of this test
    /// using only `fw_version_b: 0xFFFF_FFFF` and no authenticated field
    /// would have wrongly passed either way — which is exactly the u32::MAX
    /// floor-pinning bug from an unauthenticated wire claim.
    #[test]
    fn mark_boot_good_advances_min_fw_version_from_the_authenticated_field() {
        let mut meta = BootMeta {
            active_slot: SLOT_B,
            fw_version_a: 1,
            fw_version_b: 0xFFFF_FFFF, // attacker-claimed, unsigned, must NOT be used
            authenticated_fw_version_a: 1,
            authenticated_fw_version_b: 7, // the value a verified .SIG actually bound
            min_fw_version: 1,
            ..BootMeta::default()
        };
        ota_mark_boot_good_pure(&mut meta);
        assert_eq!(meta.min_fw_version, 7,
            "the floor must advance to the AUTHENTICATED version (7), not the \
             unsigned wire claim (0xFFFFFFFF) — that claim pinning the floor \
             is exactly U11-4");
    }

    /// An install that was never signature-verified (`authenticated_fw_version_*`
    /// stays 0, e.g. a dev/unenforced build) must NOT be able to advance the
    /// floor at all, no matter what it claims on the wire.
    #[test]
    fn mark_boot_good_does_not_advance_floor_for_an_unauthenticated_install() {
        let mut meta = BootMeta {
            active_slot: SLOT_A,
            fw_version_a: 0xFFFF_FFFF, // unsigned claim
            authenticated_fw_version_a: 0, // never verified
            min_fw_version: 3,
            ..BootMeta::default()
        };
        ota_mark_boot_good_pure(&mut meta);
        assert_eq!(meta.min_fw_version, 3, "an unverified install must not move the floor");
    }

    #[test]
    fn mark_boot_good_does_not_lower_floor() {
        // active slot has authenticated version older than the floor
        // (shouldn't happen in practice, but the floor must remain
        // monotonic).
        let mut meta = BootMeta {
            active_slot: SLOT_A,
            authenticated_fw_version_a: 3,
            min_fw_version: 9,
            ..BootMeta::default()
        };
        ota_mark_boot_good_pure(&mut meta);
        assert_eq!(meta.min_fw_version, 9);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT04 — Recovery slot SLOT_R = 2 (read-only, never written by OTA)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn slot_r_constant_is_distinct_from_a_and_b() {
        assert_ne!(SLOT_R, SLOT_A);
        assert_ne!(SLOT_R, SLOT_B);
        assert_eq!(SLOT_R, 2);
    }

    #[test]
    fn ota_inactive_slot_never_returns_r_when_active_is_a_or_b() {
        // OTA writes always target the inactive A/B slot — never R.
        assert_eq!(ota_inactive_slot_pure(SLOT_A), SLOT_B);
        assert_eq!(ota_inactive_slot_pure(SLOT_B), SLOT_A);
    }

    #[test]
    fn ota_inactive_slot_when_unexpectedly_r_falls_back_to_a_or_b() {
        // Defensive: SLOT_R should never be the active slot, but if BOOTMETA
        // is somehow corrupted to claim it is, the inactive slot should be
        // a writable A/B slot (not R itself).
        let inactive = ota_inactive_slot_pure(SLOT_R);
        assert!(inactive == SLOT_A || inactive == SLOT_B);
    }

    // ──────────────────────────────────────────────────────────────────────
    // OT04.B — BOOTMETA can now represent `active_slot`/`last_good` = R
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn active_slot_r_serializes_as_lowercase_r() {
        let meta = BootMeta { active_slot: SLOT_R, ..BootMeta::default() };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&meta, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.contains("active_slot=r\n"),
            "expected 'active_slot=r' line, got: {text}");
    }

    #[test]
    fn last_good_r_serializes_as_lowercase_r() {
        let meta = BootMeta { last_good: SLOT_R, ..BootMeta::default() };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&meta, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.contains("last_good=r\n"),
            "expected 'last_good=r' line, got: {text}");
    }

    // ── bad_slots: a rollback must not select an unsigned slot ───────────
    //
    // Owner decision 2026-09-19. `ota_boot_validate_pure` rolled back to
    // `last_good` UNCONDITIONALLY, so an attacker who writes the inactive
    // slot and then induces `max_attempts` failed boots got their image
    // selected. The boot gate now verifies every slot it is not running and
    // records the failures here; this is the branch that consults them.
    //
    // These tests do NOT cover F1 (the confused deputy), which is not
    // closable kernel-side at all.

    #[test]
    fn rollback_selects_last_good_when_it_is_not_marked_bad() {
        // The control. Without this, a `RollbackRefused` that fired always
        // would look identical to a working refusal.
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 3,
            ..BootMeta::default()
        };
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::RolledBack);
        assert_eq!(meta.active_slot, SLOT_A);
    }

    #[test]
    fn rollback_refuses_a_last_good_that_failed_secure_boot() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 3,
            ..BootMeta::default()
        };
        meta.mark_slot_bad(SLOT_A);
        let outcome = ota_boot_validate_pure(&mut meta, 3);
        assert_eq!(outcome, BootValidateOutcome::RollbackRefused);
        // The active slot must be LEFT ALONE — selecting the bad slot is the
        // whole attack, and "rolled back to itself" would read as success.
        assert_eq!(meta.active_slot, SLOT_B);
        // And the condition must stay visible rather than being reset to 1 the
        // way a taken rollback resets it.
        assert_eq!(meta.boot_count, 4);
    }

    #[test]
    fn a_bad_slot_survives_a_bootmeta_round_trip() {
        // The verdict is only worth anything if it is still there on the next
        // boot — it is written by one boot and read by another.
        let mut original = BootMeta { active_slot: SLOT_A, ..BootMeta::default() };
        original.mark_slot_bad(SLOT_B);
        original.mark_slot_bad(SLOT_R);
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&original, &mut buf);
        let parsed = parse_boot_meta(&buf[..n]);
        assert_eq!(parsed, original);
        assert!(parsed.slot_is_bad(SLOT_B));
        assert!(parsed.slot_is_bad(SLOT_R));
        assert!(!parsed.slot_is_bad(SLOT_A));
    }

    #[test]
    fn a_bootmeta_without_the_field_reads_as_no_bad_slots() {
        // Backward compatibility with every BOOTMETA already in the field:
        // an absent `bad_slots=` line must mean "nothing condemned", not
        // garbage. A wrong default here would brick a fleet on upgrade.
        let meta = parse_boot_meta(b"active_slot=a\nboot_count=0\nlast_good=a\n");
        assert_eq!(meta.bad_slots, 0);
        assert!(!meta.slot_is_bad(SLOT_A));
        assert!(!meta.slot_is_bad(SLOT_B));
        assert!(!meta.slot_is_bad(SLOT_R));
    }

    #[test]
    fn a_hand_edited_bad_slots_cannot_set_undefined_bits() {
        // The file is attacker-writable. Bits outside the three defined slots
        // could never be produced by `mark_slot_bad` and could never be
        // cleared by `clear_slot_bad` either, so they must not survive the
        // parse at all.
        let meta = parse_boot_meta(b"bad_slots=255\n");
        assert_eq!(meta.bad_slots, 0b111);
    }

    #[test]
    fn an_install_clears_the_slots_previous_verdict() {
        // The verdict was about bytes an install has just overwritten. Left
        // set, a one-time failure would make the slot permanently
        // unselectable.
        let mut meta = BootMeta::default();
        meta.mark_slot_bad(SLOT_B);
        assert!(meta.slot_is_bad(SLOT_B));
        meta.clear_slot_bad(SLOT_B);
        assert!(!meta.slot_is_bad(SLOT_B));
        // Clearing one slot must not clear the others.
        meta.mark_slot_bad(SLOT_A);
        meta.mark_slot_bad(SLOT_B);
        meta.clear_slot_bad(SLOT_A);
        assert!(!meta.slot_is_bad(SLOT_A));
        assert!(meta.slot_is_bad(SLOT_B));
    }

    // ── Slot labelling (owner decision 99 made SLOT_R reachable) ─────────
    //
    // Until decision 99, every log site in the tree spelled the slot label as
    // `if slot == SLOT_A { 'A' } else { 'B' }`, which was harmless only while
    // nothing could actually be running R. `secure_boot_steer_to_recovery`
    // makes `active_slot == SLOT_R` a real boot state, and the next boot's
    // console line then named the WRONG slot — observed, not hypothesised: a
    // canary that restored the ternary printed "Slot B signature: verified"
    // for a boot verifying KERN_R.BIN.

    #[test]
    fn slot_char_names_all_three_slots() {
        assert_eq!(ota_slot_char(SLOT_A), 'A');
        assert_eq!(ota_slot_char(SLOT_B), 'B');
        assert_eq!(ota_slot_char(SLOT_R), 'R');
    }

    #[test]
    fn slot_char_refuses_to_guess_an_unknown_code() {
        // The whole failure mode being fixed is a label that confidently
        // names a slot the board is not running. An unrecognised code must
        // therefore NOT fall back to a real slot letter.
        for code in [3u8, 4, 127, 255] {
            let c = ota_slot_char(code);
            assert_eq!(c, '?', "slot code {code} must not be labelled as a real slot");
            assert!(c != 'A' && c != 'B' && c != 'R');
        }
    }

    #[test]
    fn slot_char_labels_what_bootmeta_actually_round_trips() {
        // Ties the label to the on-disk representation rather than to the
        // constant: this is the exact path the recovery boot takes — the
        // steer writes `active_slot=r`, the next boot parses it back, and the
        // console line is rendered from what was parsed.
        let steered = BootMeta { active_slot: SLOT_R, ..BootMeta::default() };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&steered, &mut buf);
        let parsed = parse_boot_meta(&buf[..n]);
        assert_eq!(ota_slot_char(parsed.active_slot), 'R');
    }

    #[test]
    fn parse_accepts_lowercase_and_uppercase_r() {
        let lower = parse_boot_meta(b"active_slot=r\n");
        let upper = parse_boot_meta(b"active_slot=R\n");
        assert_eq!(lower.active_slot, SLOT_R);
        assert_eq!(upper.active_slot, SLOT_R);
    }

    #[test]
    fn parse_accepts_r_for_last_good_too() {
        let meta = parse_boot_meta(b"last_good=r\n");
        assert_eq!(meta.last_good, SLOT_R);
    }

    #[test]
    fn bootmeta_r_serialize_parse_roundtrip() {
        // Full roundtrip with active_slot=R AND populated `_r` fields —
        // the state a hypothetical future factory-flashing tool would
        // produce.
        let original = BootMeta {
            active_slot: SLOT_R,
            last_good:   SLOT_R,
            boot_count:  0,
            fw_version_r: 0x0200_0000,
            image_size_r: 1_048_576,
            image_crc_r:  0x0BAD_F00D,
            ..BootMeta::default()
        };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&original, &mut buf);
        let parsed = parse_boot_meta(&buf[..n]);
        assert_eq!(original, parsed);
        assert_eq!(parsed.slot_version(SLOT_R), 0x0200_0000);
        assert_eq!(parsed.slot_size(SLOT_R),    1_048_576);
        assert_eq!(parsed.slot_crc(SLOT_R),     0x0BAD_F00D);
    }

    #[test]
    fn old_bootmeta_text_without_r_fields_parses_as_zero_and_stays_unselectable() {
        // OT04 backward compatibility: a BOOTMETA written by pre-OT04 code
        // (or any BOOTMETA where nothing has ever populated R, which is
        // every BOOTMETA on disk today) has no `_r` keys at all. The
        // parser must not choke on their absence, and the resulting
        // `image_size_r == 0` is exactly the state that keeps
        // `ota_verify_slot(SLOT_R)` (guarded by `expected_size == 0` in
        // `crates/core/ota/src/lib.rs`) from ever treating R as verified.
        let legacy_text = b"active_slot=b\n\
                             boot_count=1\n\
                             last_good=a\n\
                             fw_version_a=1\n\
                             fw_version_b=2\n\
                             image_size_a=100\n\
                             image_size_b=200\n\
                             image_crc_a=10\n\
                             image_crc_b=20\n";
        let meta = parse_boot_meta(legacy_text);
        assert_eq!(meta.fw_version_r, 0);
        assert_eq!(meta.image_size_r, 0);
        assert_eq!(meta.image_crc_r,  0);
        assert_eq!(meta.slot_size(SLOT_R), 0);
    }

    #[test]
    fn active_slot_r_read_by_pre_ot04_style_parser_would_be_a() {
        // Documents the forward-compat / downgrade risk (not something
        // this parser can fix): a NEW BOOTMETA with `active_slot=r`,
        // read by an OLD parser that only recognizes "b" (else assumes
        // "a"), would silently resolve to SLOT_A. We can't test the old
        // parser here (it no longer exists in this tree), but we can
        // pin the exact byte the new serializer emits, since that byte
        // is the input the old parser's `val == b"b"` check would see.
        let meta = BootMeta { active_slot: SLOT_R, ..BootMeta::default() };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&meta, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        let line = text.lines().find(|l| l.starts_with("active_slot=")).unwrap();
        assert_eq!(line, "active_slot=r");
        // An old `if val == b"b" {SLOT_B} else {SLOT_A}` parser reading
        // "r" takes the `else` branch: SLOT_A. That's the downgrade risk.
    }

    #[test]
    fn min_fw_version_persists_through_serialize() {
        let original = BootMeta {
            min_fw_version: 0xCAFEBABE,
            ..BootMeta::default()
        };
        let mut buf = [0u8; 512];
        let n = serialize_boot_meta(&original, &mut buf);
        let parsed = parse_boot_meta(&buf[..n]);
        assert_eq!(parsed.min_fw_version, 0xCAFEBABE);
    }

    // ── Owner decisions 2026-09-28: safe mode and the orderly void ─────────

    /// The recovery input the kernel computes (`boot_count_loaded`): the
    /// running slot's unconfirmed boots before this one, after validation.
    fn recovery_armed(meta: &BootMeta) -> bool {
        use super::recovery::{recovery_mode_should_enter, RecoveryInputs};
        recovery_mode_should_enter(RecoveryInputs {
            crash_count: meta.boot_count.saturating_sub(1),
            recovery_button_held: None,
            bootmeta_user_flag: None,
        })
        .should_enter()
    }

    /// The whole sequence of `pure.rs`'s table, boot by boot, with a crash on
    /// every boot: B (new) crashes 3 times, boot 4 rolls back to A and does NOT
    /// arm, A crashes twice more, boot 7 is exhausted and arms, and every boot
    /// after it stays exhausted and armed (the count keeps climbing).
    ///
    /// **Canary**: the kernel's old input (`crash_count` = count as READ, i.e.
    /// `prior_unconfirmed`) arms on boot 4, the rollback boot; asserted below
    /// as the difference that matters.
    #[test]
    fn the_boot_sequence_rolls_back_once_then_safe_mode_and_stays() {
        let mut meta = BootMeta {
            active_slot: SLOT_B, last_good: SLOT_A, boot_count: 0,
            ..BootMeta::default()
        };
        let expect = [
            // (outcome, active after, count after, armed)
            (BootValidateOutcome::Normal, SLOT_B, 1, false),
            (BootValidateOutcome::Normal, SLOT_B, 2, false),
            (BootValidateOutcome::Normal, SLOT_B, 3, false),
            (BootValidateOutcome::RolledBack, SLOT_A, 1, false),
            (BootValidateOutcome::Normal, SLOT_A, 2, false),
            (BootValidateOutcome::Normal, SLOT_A, 3, false),
            (BootValidateOutcome::Exhausted, SLOT_A, 4, true),
            (BootValidateOutcome::Exhausted, SLOT_A, 5, true),
            (BootValidateOutcome::Exhausted, SLOT_A, 6, true),
        ];
        for (boot, (o, slot, count, armed)) in expect.iter().enumerate() {
            let prior = meta.boot_count;
            let got = ota_boot_validate_pure(&mut meta, OTA_DEFAULT_MAX_BOOT_ATTEMPTS);
            assert_eq!((got, meta.active_slot, meta.boot_count), (*o, *slot, *count),
                       "boot {}", boot + 1);
            assert_eq!(recovery_armed(&meta), *armed, "boot {} armed", boot + 1);
            assert_eq!(ota_boot_exhausted(&meta, OTA_DEFAULT_MAX_BOOT_ATTEMPTS), *armed,
                       "boot {}: FSM and recovery disagree", boot + 1);
            if boot == 3 {
                // The rollback boot read 3: the old input armed it.
                assert_eq!(prior, 3);
                assert!(prior >= super::recovery::RECOVERY_BOOT_LOOP_THRESHOLD);
            }
        }
    }

    /// One slot only (a fresh device, `last_good == active`): three crashes,
    /// and the fourth boot is safe mode — not a reset onto itself.
    #[test]
    fn a_single_image_device_reaches_safe_mode_on_the_fourth_boot() {
        let mut meta = BootMeta::default();
        for n in 1..=3u32 {
            assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Normal);
            assert_eq!(meta.boot_count, n);
            assert!(!recovery_armed(&meta));
        }
        assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Exhausted);
        assert_eq!((meta.active_slot, meta.boot_count), (SLOT_A, 4));
        assert!(recovery_armed(&meta));
    }

    /// For every starting count and slot arrangement, "recovery armed" (the
    /// kernel's safe-mode decision) and "attempts exhausted" (the FSM's
    /// verdict) are the same fact: they share one threshold.
    #[test]
    fn recovery_arms_exactly_when_the_fsm_is_exhausted() {
        assert_eq!(super::recovery::RECOVERY_BOOT_LOOP_THRESHOLD, OTA_DEFAULT_MAX_BOOT_ATTEMPTS);
        for start in [0u32, 1, 2, 3, 4, 5, 40, u32::MAX - 1, u32::MAX] {
            for (active, last_good, bad) in [
                (SLOT_B, SLOT_A, false), (SLOT_A, SLOT_A, false), (SLOT_B, SLOT_A, true),
            ] {
                let mut meta = BootMeta { active_slot: active, last_good, boot_count: start,
                                          ..BootMeta::default() };
                if bad { meta.mark_slot_bad(last_good); }
                let o = ota_boot_validate_pure(&mut meta, OTA_DEFAULT_MAX_BOOT_ATTEMPTS);
                let spent = matches!(o, BootValidateOutcome::Exhausted
                                      | BootValidateOutcome::RollbackRefused);
                assert_eq!(recovery_armed(&meta), spent, "start {start} {o:?}");
                assert_eq!(ota_boot_exhausted(&meta, OTA_DEFAULT_MAX_BOOT_ATTEMPTS), spent);
            }
        }
    }

    /// An orderly shutdown takes back exactly this boot's +1, and only when
    /// the record still says what this boot wrote.
    ///
    /// **Canary**: void without the compare (always decrement): the OTA-install
    /// case below writes `boot_count` 0 -> ... and the assertion on it fails.
    #[test]
    fn an_orderly_shutdown_voids_only_its_own_mark() {
        // Boot 2 of slot A wrote 2; an orderly reboot takes it back to 1.
        let mut meta = BootMeta { active_slot: SLOT_A, last_good: SLOT_A, boot_count: 2,
                                  ..BootMeta::default() };
        assert!(ota_void_boot_pure(&mut meta, SLOT_A, 2));
        assert_eq!(meta.boot_count, 1);
        // The next boot then counts 2 again, not 3: the shutdown did not count.
        assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Normal);
        assert_eq!(meta.boot_count, 2);

        // An OTA install during the boot switched the slot and reset the count.
        let mut meta = BootMeta { active_slot: SLOT_B, last_good: SLOT_A, boot_count: 0,
                                  ..BootMeta::default() };
        assert!(!ota_void_boot_pure(&mut meta, SLOT_A, 4));
        assert_eq!((meta.active_slot, meta.boot_count), (SLOT_B, 0));
        // Marked good in the meantime (count 0 on the same slot).
        let mut meta = BootMeta { active_slot: SLOT_A, boot_count: 0, ..BootMeta::default() };
        assert!(!ota_void_boot_pure(&mut meta, SLOT_A, 3));
        assert_eq!(meta.boot_count, 0);
        // Nothing recorded this boot.
        let mut meta = BootMeta { active_slot: SLOT_A, boot_count: 0, ..BootMeta::default() };
        assert!(!ota_void_boot_pure(&mut meta, SLOT_A, 0));
    }

    /// In safe mode an orderly reboot voids its own mark too, and the next
    /// boot is safe mode again: 4 -> void -> 3 -> validate -> 4, exhausted.
    #[test]
    fn an_orderly_reboot_out_of_safe_mode_lands_in_safe_mode() {
        let mut meta = BootMeta { active_slot: SLOT_A, last_good: SLOT_A, boot_count: 3,
                                  ..BootMeta::default() };
        assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Exhausted);
        assert!(ota_void_boot_pure(&mut meta, SLOT_A, 4));
        assert_eq!(ota_boot_validate_pure(&mut meta, 3), BootValidateOutcome::Exhausted);
        assert!(recovery_armed(&meta));
    }
}
