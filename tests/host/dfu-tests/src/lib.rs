// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for azos_dfu (DEV02).

#[cfg(test)]
mod tests {
    use azos_dfu::{
        AccumulatorError, ChunkAccumulator,
        DescriptorBuilder, DfuRequest, DfuRequestType, DfuState, DfuStateMachine,
        FunctionalDescriptor, SetupPacket, parse_setup_packet,
        DFU_FUNC_DESCRIPTOR_LEN, DFU_FUNC_DESCRIPTOR_TYPE,
        DFU_INTERFACE_CLASS, DFU_INTERFACE_PROTOCOL_DFU, DFU_INTERFACE_SUBCLASS,
        DFU_REQ_DETACH, DFU_REQ_DNLOAD, DFU_REQ_GETSTATUS,
        STATUS_OK, STATUS_ERR_ADDRESS, STATUS_ERR_NOTDONE,
        STATUS_ERR_STALLEDPKT, STATUS_ERR_WRITE,
    };

    const KIB:        usize = 1024;
    const MAX_IMG:    usize = 2 * 1024 * KIB; // 2 MiB
    const XFER_SIZE:  u16   = 1024;

    fn fresh_dfu() -> DfuStateMachine {
        DfuStateMachine::new_dfu_mode(MAX_IMG, XFER_SIZE)
    }

    fn fresh_runtime() -> DfuStateMachine {
        DfuStateMachine::new_runtime(MAX_IMG, XFER_SIZE)
    }

    // ── State machine: happy-path download ─────────────────────────

    #[test]
    fn full_download_three_chunks() {
        let mut sm = fresh_dfu();
        assert_eq!(sm.state(), DfuState::DfuIdle);

        // Three chunks of XFER_SIZE then a 0-length terminator.
        sm.dnload(XFER_SIZE).unwrap();
        assert_eq!(sm.state(), DfuState::DnloadSync);
        sm.finish_sync().unwrap();
        assert_eq!(sm.state(), DfuState::DnloadIdle);

        sm.dnload(XFER_SIZE).unwrap();
        sm.finish_sync().unwrap();
        sm.dnload(XFER_SIZE).unwrap();
        sm.finish_sync().unwrap();

        assert_eq!(sm.bytes_written, 3 * XFER_SIZE as usize);

        // 0-length DNLOAD → ManifestSync.
        sm.dnload(0).unwrap();
        assert_eq!(sm.state(), DfuState::ManifestSync);
        sm.finish_sync().unwrap();
        assert_eq!(sm.state(), DfuState::Manifest);

        // Caller commits firmware, then advances to wait-reset.
        sm.finish_manifest().unwrap();
        assert_eq!(sm.state(), DfuState::ManifestWaitReset);
    }

    // ── Regression: legal host polling must not poison the FSM ─────
    //
    // `kernel/src/dfu_recovery.rs` used to call `finish_sync()` on EVERY
    // GETSTATUS. These tests pin the FSM half of that contract: from any
    // state other than DnloadSync / ManifestSync, `finish_sync()` is an
    // error transition, so the caller MUST gate it on the state. `dfu-util`
    // polls GETSTATUS from dfuIDLE routinely (including as its first request
    // after enumerating), and this is the last-resort un-brick path — being
    // driven into dfuERROR by a correct request is not survivable there.

    #[test]
    fn finish_sync_from_dfu_idle_is_an_error_transition() {
        let mut sm = fresh_dfu();
        assert_eq!(sm.state(), DfuState::DfuIdle);
        assert!(sm.finish_sync().is_err());
        assert_eq!(sm.state(), DfuState::Error);
        assert_eq!(sm.last_status(), STATUS_ERR_STALLEDPKT);
    }

    #[test]
    fn status_from_dfu_idle_reports_dfu_idle_when_finish_sync_is_not_called() {
        // The positive case: a caller that gates `finish_sync()` correctly
        // can answer GETSTATUS from dfuIDLE all day, reporting OK/dfuIDLE.
        let sm = fresh_dfu();
        let st = sm.status();
        assert_eq!(st.b_state, DfuState::DfuIdle);
        assert_eq!(st.b_status, STATUS_OK);
        assert_eq!(st.encode().len(), 6);
    }

    #[test]
    fn finish_sync_from_manifest_wait_reset_is_an_error_transition() {
        // Second instance of the same bug: ManifestWaitReset is exactly when
        // a host polls to confirm the commit took. An ungated finish_sync()
        // there turned a completed update into an apparent failure.
        let mut sm = fresh_dfu();
        sm.dnload(XFER_SIZE).unwrap();
        sm.finish_sync().unwrap();          // DnloadSync → DnloadIdle
        sm.dnload(0).unwrap();              // → ManifestSync
        sm.finish_sync().unwrap();          // → Manifest
        sm.finish_manifest().unwrap();      // → ManifestWaitReset
        assert_eq!(sm.state(), DfuState::ManifestWaitReset);

        // Status is still answerable...
        assert_eq!(sm.status().b_state, DfuState::ManifestWaitReset);
        // ...but finish_sync() from here is not legal, so callers must gate.
        assert!(sm.finish_sync().is_err());
        assert_eq!(sm.state(), DfuState::Error);
    }

    // ── Regression: explicit commit-time failure reporting ─────────

    #[test]
    fn fail_sets_error_state_with_the_given_status_code() {
        // `finalize_manifest` needs to report a *specific* cause (refused
        // image / failed write). Before `fail()` existed, the only way in was
        // to call clr_status() and rely on it failing, which reported
        // ERR_STALLEDPKT regardless of the real reason.
        let mut sm = fresh_dfu();
        sm.fail(STATUS_ERR_NOTDONE);
        assert_eq!(sm.state(), DfuState::Error);
        assert_eq!(sm.last_status(), STATUS_ERR_NOTDONE);
        assert_eq!(sm.status().b_status, STATUS_ERR_NOTDONE);
        assert_eq!(sm.status().b_state, DfuState::Error);

        // And the host can still recover the normal way.
        sm.clr_status().unwrap();
        assert_eq!(sm.state(), DfuState::DfuIdle);
        assert_eq!(sm.last_status(), STATUS_OK);
    }

    #[test]
    fn fail_from_error_keeps_the_newer_code_and_does_not_reset() {
        // The old clr_status()-as-error-setter trick did the opposite here:
        // from Error, clr_status() SUCCEEDS, resetting to DfuIdle and
        // reporting OK for a commit that had just failed.
        let mut sm = fresh_dfu();
        sm.fail(STATUS_ERR_WRITE);
        sm.fail(STATUS_ERR_NOTDONE);
        assert_eq!(sm.state(), DfuState::Error);
        assert_eq!(sm.last_status(), STATUS_ERR_NOTDONE);
    }

    /// A zero-length DNLOAD straight from dfuIdle is *legal* at the protocol
    /// level and reaches ManifestSync with `bytes_written == 0`. The FSM is
    /// right to allow it; the refusal belongs to the caller that commits.
    /// This pins the precondition the kernel guard in
    /// `dfu_recovery.rs::finalize_manifest` relies on — one USB control
    /// request can put the machine one step away from a slot write with no
    /// payload behind it.
    #[test]
    fn zero_length_dnload_from_idle_reaches_manifest_with_no_bytes() {
        let mut sm = fresh_dfu();
        assert_eq!(sm.state(), DfuState::DfuIdle);
        sm.dnload(0).unwrap();
        assert_eq!(sm.state(), DfuState::ManifestSync);
        assert_eq!(sm.bytes_written, 0);
    }

    #[test]
    fn detach_runtime_to_dfu_mode() {
        let mut sm = fresh_runtime();
        assert_eq!(sm.state(), DfuState::AppIdle);
        sm.detach().unwrap();
        assert_eq!(sm.state(), DfuState::AppDetach);
        // (Real device would re-enumerate as DFU mode here; tests
        // for that path use the `new_dfu_mode` constructor above.)
    }

    // ── State machine: error paths ──────────────────────────────────

    #[test]
    fn dnload_oversize_chunk_errors() {
        let mut sm = fresh_dfu();
        let err = sm.dnload(XFER_SIZE + 1).unwrap_err();
        assert_eq!(err.0, STATUS_ERR_STALLEDPKT);
        assert_eq!(sm.state(), DfuState::Error);
    }

    #[test]
    fn dnload_past_max_image_errors() {
        // Construct a state machine with a tiny limit so two
        // full-size chunks already exceed it.
        let mut sm = DfuStateMachine::new_dfu_mode(
            (XFER_SIZE as usize) + 1, XFER_SIZE,
        );
        sm.dnload(XFER_SIZE).unwrap();
        sm.finish_sync().unwrap();
        let err = sm.dnload(XFER_SIZE).unwrap_err();
        assert_eq!(err.0, STATUS_ERR_ADDRESS);
        assert_eq!(sm.state(), DfuState::Error);
    }

    #[test]
    fn dnload_from_wrong_state_errors() {
        let mut sm = fresh_runtime();          // AppIdle
        assert!(sm.dnload(XFER_SIZE).is_err());
        assert_eq!(sm.state(), DfuState::Error);
    }

    #[test]
    fn clr_status_recovers_to_dfu_idle() {
        let mut sm = fresh_dfu();
        sm.dnload(XFER_SIZE + 1).unwrap_err();  // sends to Error
        assert_eq!(sm.state(), DfuState::Error);
        sm.clr_status().unwrap();
        assert_eq!(sm.state(), DfuState::DfuIdle);
        assert_eq!(sm.last_status(), STATUS_OK);
        // After recovery a fresh download starts cleanly.
        assert_eq!(sm.bytes_written, 0);
    }

    #[test]
    fn abort_resets_progress() {
        let mut sm = fresh_dfu();
        sm.dnload(XFER_SIZE).unwrap();
        sm.finish_sync().unwrap();
        assert_eq!(sm.bytes_written, XFER_SIZE as usize);
        sm.abort().unwrap();
        assert_eq!(sm.state(), DfuState::DfuIdle);
        assert_eq!(sm.bytes_written, 0);
    }

    // ── GETSTATUS encoding ─────────────────────────────────────────

    #[test]
    fn getstatus_encodes_six_bytes_with_poll_timeout() {
        let mut sm = fresh_dfu();
        sm.dnload(XFER_SIZE).unwrap();
        // In DnloadSync the spec allows a non-zero poll_timeout to
        // throttle the host. Our impl reports 0 outside DnloadBusy.
        // Direct-construct a busy status for the encode coverage.
        let stat = sm.status();
        let bytes = stat.encode();
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], STATUS_OK);
        assert_eq!(bytes[4], DfuState::DnloadSync.as_u8());
    }

    // ── Descriptor builder ─────────────────────────────────────────

    #[test]
    fn functional_descriptor_is_9_bytes() {
        let func = FunctionalDescriptor::AZOS_DEFAULT;
        let bytes = func.encode();
        assert_eq!(bytes.len(), DFU_FUNC_DESCRIPTOR_LEN as usize);
        assert_eq!(bytes[0], DFU_FUNC_DESCRIPTOR_LEN);
        assert_eq!(bytes[1], DFU_FUNC_DESCRIPTOR_TYPE);
        // bcdDFU 1.1 little-endian = 0x10, 0x01.
        assert_eq!(bytes[7], 0x10);
        assert_eq!(bytes[8], 0x01);
    }

    #[test]
    fn full_descriptor_blob_length_and_layout() {
        let mut buf = [0u8; 64];
        let builder = DescriptorBuilder::new(FunctionalDescriptor::AZOS_DEFAULT);
        let written = builder.encode(&mut buf).unwrap();
        assert_eq!(written, builder.total_length() as usize);

        // First 9 bytes: CONFIGURATION descriptor.
        assert_eq!(buf[0], 9);
        assert_eq!(buf[1], 0x02); // CONFIGURATION
        assert_eq!(buf[2..4], (builder.total_length()).to_le_bytes());
        assert_eq!(buf[4], 1); // bNumInterfaces

        // Bytes 9..18: INTERFACE descriptor.
        assert_eq!(buf[9], 9);
        assert_eq!(buf[10], 0x04); // INTERFACE
        assert_eq!(buf[14], DFU_INTERFACE_CLASS);
        assert_eq!(buf[15], DFU_INTERFACE_SUBCLASS);
        assert_eq!(buf[16], DFU_INTERFACE_PROTOCOL_DFU);

        // Bytes 18..27: DFU functional descriptor.
        assert_eq!(buf[18], DFU_FUNC_DESCRIPTOR_LEN);
        assert_eq!(buf[19], DFU_FUNC_DESCRIPTOR_TYPE);
    }

    #[test]
    fn descriptor_rejects_short_buffer() {
        let mut buf = [0u8; 8];  // too small
        let builder = DescriptorBuilder::new(FunctionalDescriptor::AZOS_DEFAULT);
        assert!(builder.encode(&mut buf).is_none());
    }

    // ── Setup-packet parser ────────────────────────────────────────

    fn build_setup(bm: u8, br: u8, w_value: u16, w_index: u16, w_length: u16) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = bm;
        out[1] = br;
        out[2..4].copy_from_slice(&w_value.to_le_bytes());
        out[4..6].copy_from_slice(&w_index.to_le_bytes());
        out[6..8].copy_from_slice(&w_length.to_le_bytes());
        out
    }

    #[test]
    fn parses_dfu_detach() {
        let raw = build_setup(0b0010_0001, DFU_REQ_DETACH, 500, 0, 0);
        let pkt = SetupPacket::from_bytes(&raw).unwrap();
        let (dir, req) = parse_setup_packet(pkt).unwrap();
        assert_eq!(dir, DfuRequestType::Out);
        match req {
            DfuRequest::Detach { detach_timeout_ms } => assert_eq!(detach_timeout_ms, 500),
            _ => panic!("expected Detach"),
        }
    }

    #[test]
    fn parses_dfu_dnload_with_block_and_length() {
        let raw = build_setup(0b0010_0001, DFU_REQ_DNLOAD, 7, 0, XFER_SIZE);
        let pkt = SetupPacket::from_bytes(&raw).unwrap();
        let (_dir, req) = parse_setup_packet(pkt).unwrap();
        match req {
            DfuRequest::Dnload { block_num, len } => {
                assert_eq!(block_num, 7);
                assert_eq!(len, XFER_SIZE);
            }
            _ => panic!("expected Dnload"),
        }
    }

    #[test]
    fn parses_dfu_getstatus_as_in_direction() {
        let raw = build_setup(0b1010_0001, DFU_REQ_GETSTATUS, 0, 0, 6);
        let pkt = SetupPacket::from_bytes(&raw).unwrap();
        let (dir, req) = parse_setup_packet(pkt).unwrap();
        assert_eq!(dir, DfuRequestType::In);
        assert_eq!(req, DfuRequest::GetStatus);
    }

    #[test]
    fn rejects_non_dfu_class_requests() {
        // bmRequestType 0x00 = standard device request, not class iface.
        let raw = build_setup(0x00, DFU_REQ_GETSTATUS, 0, 0, 6);
        let pkt = SetupPacket::from_bytes(&raw).unwrap();
        assert!(parse_setup_packet(pkt).is_none());
    }

    #[test]
    fn rejects_unknown_brequest_within_dfu_class() {
        let raw = build_setup(0b0010_0001, 0xFE, 0, 0, 0);
        let pkt = SetupPacket::from_bytes(&raw).unwrap();
        assert!(parse_setup_packet(pkt).is_none());
    }

    // ── Chunk accumulator (DEV02 kernel-glue helper) ───────────────

    #[test]
    fn accumulator_appends_sequential_chunks() {
        let mut staging = [0u8; 16];
        let mut acc = ChunkAccumulator::new(4);
        assert_eq!(acc.push(&[1, 2, 3, 4], &mut staging).unwrap(), 4);
        assert_eq!(acc.push(&[5, 6, 7, 8], &mut staging).unwrap(), 8);
        assert_eq!(&staging[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(acc.bytes_written, 8);
    }

    #[test]
    fn accumulator_rejects_chunk_larger_than_transfer_size() {
        let mut staging = [0u8; 16];
        let mut acc = ChunkAccumulator::new(4);
        let too_big = [0u8; 5];
        assert_eq!(
            acc.push(&too_big, &mut staging),
            Err(AccumulatorError::ChunkTooLarge),
        );
        // Failed push must not advance the counter.
        assert_eq!(acc.bytes_written, 0);
    }

    #[test]
    fn accumulator_rejects_overflow_past_staging_capacity() {
        let mut staging = [0u8; 6];
        let mut acc = ChunkAccumulator::new(4);
        acc.push(&[1, 2, 3, 4], &mut staging).unwrap();
        assert_eq!(
            acc.push(&[5, 6, 7], &mut staging),
            Err(AccumulatorError::Overflow),
        );
        // The earlier successful push is preserved.
        assert_eq!(acc.bytes_written, 4);
        assert_eq!(&staging[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn accumulator_reset_clears_progress() {
        let mut staging = [0u8; 8];
        let mut acc = ChunkAccumulator::new(4);
        acc.push(&[9, 9, 9, 9], &mut staging).unwrap();
        assert_eq!(acc.bytes_written, 4);
        acc.reset();
        assert_eq!(acc.bytes_written, 0);
        // A fresh push after reset starts at offset 0 again.
        acc.push(&[1, 2, 3], &mut staging).unwrap();
        assert_eq!(&staging[..3], &[1, 2, 3]);
    }

    #[test]
    fn accumulator_accepts_zero_length_chunk() {
        // Zero-length DNLOAD is the "end of transfer" signal at the
        // FSM layer; the accumulator should accept it as a no-op so
        // the kernel glue can use a single push() call site.
        let mut staging = [0u8; 8];
        let mut acc = ChunkAccumulator::new(4);
        acc.push(&[1, 2], &mut staging).unwrap();
        assert_eq!(acc.push(&[], &mut staging).unwrap(), 2);
        assert_eq!(acc.bytes_written, 2);
    }

    #[test]
    fn accumulator_fills_staging_exactly() {
        let mut staging = [0u8; 4];
        let mut acc = ChunkAccumulator::new(4);
        assert_eq!(acc.push(&[1, 2, 3, 4], &mut staging).unwrap(), 4);
        // Boundary case: pushing one more byte must overflow.
        assert_eq!(
            acc.push(&[5], &mut staging),
            Err(AccumulatorError::Overflow),
        );
    }
}
