// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_tftp` (DEV01).
//!
//! Covers builders + parser + state-machine corners: every branch
//! of the protocol logic gets at least one test. QEMU-level E2E
//! (Python TFTP server fed via `-netdev user,tftp=...`) is a
//! separate follow-up.

/// Byte-level conformance against the RFC 1350 §5 packet figures.
#[cfg(test)]
mod conformance;

#[cfg(test)]
mod build_rrq_tests {
    use azos_tftp::{
        build_rrq, TftpEncodeError, RRQ_FIXED_OVERHEAD_BYTES,
        TFTP_MAX_FILENAME_BYTES, TFTP_RRQ_MAX_BYTES,
    };

    #[test]
    fn rrq_layout_matches_rfc_1350_octet_mode() {
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES];
        let n = build_rrq("KERN.BIN", &mut out).unwrap();
        // [00 01]                       ── opcode RRQ
        // [4B 45 52 4E 2E 42 49 4E 00]  ── "KERN.BIN\0"
        // [6F 63 74 65 74 00]           ── "octet\0"
        let expected: &[u8] = &[
            0x00, 0x01,
            b'K', b'E', b'R', b'N', b'.', b'B', b'I', b'N', 0x00,
            b'o', b'c', b't', b'e', b't', 0x00,
        ];
        assert_eq!(&out[..n], expected);
    }

    #[test]
    fn rrq_size_is_filename_plus_fixed_overhead() {
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES];
        let name = "a";
        let n = build_rrq(name, &mut out).unwrap();
        assert_eq!(n, name.len() + RRQ_FIXED_OVERHEAD_BYTES);
    }

    #[test]
    fn rrq_max_length_filename_fits() {
        let name: String = "a".repeat(TFTP_MAX_FILENAME_BYTES);
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES];
        let n = build_rrq(&name, &mut out).unwrap();
        assert_eq!(
            n,
            TFTP_MAX_FILENAME_BYTES + RRQ_FIXED_OVERHEAD_BYTES
        );
    }

    #[test]
    fn rrq_rejects_oversize_filename() {
        let name: String = "a".repeat(TFTP_MAX_FILENAME_BYTES + 1);
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES + 16];
        let err = build_rrq(&name, &mut out).unwrap_err();
        assert_eq!(err, TftpEncodeError::FilenameTooLong);
    }

    #[test]
    fn rrq_rejects_empty_filename() {
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES];
        let err = build_rrq("", &mut out).unwrap_err();
        assert_eq!(err, TftpEncodeError::EmptyFilename);
    }

    #[test]
    fn rrq_rejects_filename_with_nul() {
        let mut out = [0u8; TFTP_RRQ_MAX_BYTES];
        let err = build_rrq("KERN\0X.BIN", &mut out).unwrap_err();
        assert_eq!(err, TftpEncodeError::FilenameHasNul);
    }

    #[test]
    fn rrq_rejects_too_small_buffer() {
        let mut out = [0u8; 4]; // way too small
        let err = build_rrq("KERN.BIN", &mut out).unwrap_err();
        assert_eq!(err, TftpEncodeError::BufferTooSmall);
    }
}

#[cfg(test)]
mod build_ack_tests {
    use azos_tftp::{build_ack, TFTP_ACK_BYTES};

    #[test]
    fn ack_layout_is_opcode_then_block_be() {
        let mut out = [0u8; TFTP_ACK_BYTES];
        build_ack(0x1234, &mut out);
        assert_eq!(out, [0x00, 0x04, 0x12, 0x34]);
    }

    #[test]
    fn ack_block_zero_is_well_formed() {
        // RFC 1350: an ACK with block=0 is what the server sends in
        // response to a WRQ; clients may produce one on receiving
        // an OACK we don't negotiate. Tested for completeness.
        let mut out = [0u8; TFTP_ACK_BYTES];
        build_ack(0, &mut out);
        assert_eq!(out, [0x00, 0x04, 0x00, 0x00]);
    }

    #[test]
    fn ack_block_u16_max_round_trips() {
        let mut out = [0u8; TFTP_ACK_BYTES];
        build_ack(u16::MAX, &mut out);
        assert_eq!(out, [0x00, 0x04, 0xFF, 0xFF]);
    }
}

#[cfg(test)]
mod parse_packet_tests {
    use azos_tftp::{parse_packet, RxOutcome, TFTP_BLOCK_SIZE};

    fn data_pkt(block: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + payload.len());
        v.extend_from_slice(&3u16.to_be_bytes()); // OP_DATA
        v.extend_from_slice(&block.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn data_full_block_is_not_last() {
        let pkt = data_pkt(1, &[0xAB; TFTP_BLOCK_SIZE]);
        match parse_packet(&pkt) {
            RxOutcome::Data { block, payload, is_last } => {
                assert_eq!(block, 1);
                assert_eq!(payload.len(), TFTP_BLOCK_SIZE);
                assert!(!is_last);
            }
            other => panic!("expected Data, got {:?}", other),
        }
    }

    #[test]
    fn data_short_block_is_last() {
        // RFC 1350 §1: a DATA whose data field is < 512 bytes
        // signals end-of-file.
        let pkt = data_pkt(42, &[0xCD; 100]);
        match parse_packet(&pkt) {
            RxOutcome::Data { block, payload, is_last } => {
                assert_eq!(block, 42);
                assert_eq!(payload.len(), 100);
                assert!(is_last);
            }
            other => panic!("expected last Data, got {:?}", other),
        }
    }

    #[test]
    fn data_empty_payload_is_last_block_of_exact_multiple() {
        // A file whose size is an exact multiple of 512 ends with
        // a DATA carrying zero bytes — RFC 1350 §1 last paragraph.
        let pkt = data_pkt(7, &[]);
        match parse_packet(&pkt) {
            RxOutcome::Data { block, payload, is_last } => {
                assert_eq!(block, 7);
                assert!(payload.is_empty());
                assert!(is_last);
            }
            other => panic!("expected empty-last Data, got {:?}", other),
        }
    }

    #[test]
    fn data_oversize_payload_is_malformed() {
        // We don't negotiate RFC 2348 block-size options, so any
        // payload > 512 bytes is a protocol violation.
        let pkt = data_pkt(1, &[0xEE; TFTP_BLOCK_SIZE + 1]);
        assert_eq!(parse_packet(&pkt), RxOutcome::Malformed);
    }

    #[test]
    fn data_truncated_header_is_malformed() {
        // Need at least 4 bytes (opcode + block).
        let pkt = [0x00, 0x03, 0x00]; // missing low byte of block
        assert_eq!(parse_packet(&pkt), RxOutcome::Malformed);
    }

    #[test]
    fn error_packet_returns_code() {
        // [00 05][00 01]["msg"][00] — code 1 = FileNotFound
        let pkt = [0x00, 0x05, 0x00, 0x01, b'm', b's', b'g', 0x00];
        assert_eq!(parse_packet(&pkt), RxOutcome::Error(1));
    }

    #[test]
    fn error_minimum_packet_just_terminator() {
        // [00 05][00 02][00] — code 2 = AccessViolation, empty msg
        let pkt = [0x00, 0x05, 0x00, 0x02, 0x00];
        assert_eq!(parse_packet(&pkt), RxOutcome::Error(2));
    }

    #[test]
    fn error_truncated_is_malformed() {
        let pkt = [0x00, 0x05, 0x00, 0x01]; // missing terminator
        assert_eq!(parse_packet(&pkt), RxOutcome::Malformed);
    }

    #[test]
    fn unknown_opcode_is_malformed() {
        let pkt = [0x00, 0xFF, 0x00, 0x00];
        assert_eq!(parse_packet(&pkt), RxOutcome::Malformed);
    }

    #[test]
    fn empty_packet_is_malformed() {
        let pkt = [];
        assert_eq!(parse_packet(&pkt), RxOutcome::Malformed);
    }
}

#[cfg(test)]
mod client_state_tests {
    use azos_tftp::{ClientAction, TftpClient};

    #[test]
    fn fresh_client_expects_block_one() {
        let c = TftpClient::new();
        assert_eq!(c.expected_block(), 1);
        assert!(!c.is_complete());
    }

    #[test]
    fn first_data_block_one_consumes_and_advances() {
        let mut c = TftpClient::new();
        assert_eq!(c.on_data(1, false), ClientAction::AckAndConsume);
        assert_eq!(c.expected_block(), 2);
        assert!(!c.is_complete());
    }

    #[test]
    fn duplicate_block_one_is_acked_without_re_consume() {
        let mut c = TftpClient::new();
        let _ = c.on_data(1, false);
        assert_eq!(c.on_data(1, false), ClientAction::AckIgnore);
        // Expected stays at 2 — no state change on duplicate.
        assert_eq!(c.expected_block(), 2);
    }

    #[test]
    fn out_of_order_block_is_reported() {
        let mut c = TftpClient::new();
        let _ = c.on_data(1, false);
        match c.on_data(3, false) {
            ClientAction::OutOfOrder { expected, received } => {
                assert_eq!(expected, 2);
                assert_eq!(received, 3);
            }
            other => panic!("expected OutOfOrder, got {:?}", other),
        }
        // State unchanged.
        assert_eq!(c.expected_block(), 2);
    }

    #[test]
    fn last_block_marks_complete() {
        let mut c = TftpClient::new();
        let _ = c.on_data(1, false);
        let _ = c.on_data(2, false);
        assert_eq!(c.on_data(3, true), ClientAction::Complete);
        assert!(c.is_complete());
    }

    #[test]
    fn data_after_complete_is_ignored_with_re_ack() {
        let mut c = TftpClient::new();
        let _ = c.on_data(1, true);
        assert!(c.is_complete());
        // Server retransmitted the final block — caller re-ACKs it.
        assert_eq!(c.on_data(1, true), ClientAction::AckIgnore);
    }

    #[test]
    fn block_number_wraps_after_u16_max() {
        // Build a client up to expected=u16::MAX, then consume that
        // and verify wrap → 0 (matches common server behaviour for
        // files > 32 MiB without RFC 7440 block-size negotiation).
        // Fast-forward via direct construction is not exposed; consume one
        // block instead and assert the wrap math through the public API.
        let mut c = TftpClient::new();
        // Send a block with our actual expected → ack
        let _ = c.on_data(1, false);
        assert_eq!(c.expected_block(), 2);

        // Replace client and walk it to wrap. We simulate by
        // consuming `u16::MAX - 1` blocks; that's 65534 calls
        // which is fast in a unit test.
        c = TftpClient::new();
        for blk in 1..=u16::MAX {
            let _ = c.on_data(blk, false);
        }
        // Now expected_block has wrapped: 65535.wrapping_add(1) == 0.
        assert_eq!(c.expected_block(), 0);
    }

    #[test]
    fn single_block_file_completes_immediately() {
        // A file smaller than 512 bytes: server sends one DATA
        // with block=1 and is_last=true, transfer done.
        let mut c = TftpClient::new();
        assert_eq!(c.on_data(1, true), ClientAction::Complete);
        assert!(c.is_complete());
        // After complete, the wrap-advance still happened.
        assert_eq!(c.expected_block(), 2);
    }
}
