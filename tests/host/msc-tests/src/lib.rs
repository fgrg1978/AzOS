// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for azos_msc (DEV03).

#[cfg(test)]
mod tests {
    use azos_msc::{
        BlockDevice, Cbw, Csw, CBW_DIR_IN, CBW_DIR_OUT, CBW_SIGNATURE,
        CSW_SIGNATURE, CSW_STATUS_OK, MscDescriptorBuilder,
        MSC_BULK_EP_MAX_PACKET, MSC_INTERFACE_CLASS,
        MSC_INTERFACE_PROTOCOL_BBB, MSC_INTERFACE_SUBCLASS_SCSI,
        MscPhase, MscStateMachine, ScsiCommand, ScsiResponse,
        SCSI_OP_INQUIRY, SCSI_OP_READ_10, SCSI_OP_READ_CAPACITY_10,
        SCSI_OP_TEST_UNIT_READY, SCSI_OP_WRITE_10,
        execute_scsi, parse_scsi_command, Sense,
    };

    const BLOCK_SIZE: usize = 512;

    // ── Mock block device ──────────────────────────────────────────

    struct MockDisk {
        blocks: Vec<[u8; BLOCK_SIZE]>,
        /// What `sync_cache` answers, and how often it was asked.
        sync_ok: bool,
        syncs: std::cell::Cell<u32>,
    }

    impl MockDisk {
        fn new(n_blocks: u32) -> Self {
            Self { blocks: vec![[0u8; BLOCK_SIZE]; n_blocks as usize],
                   sync_ok: true, syncs: std::cell::Cell::new(0) }
        }
    }

    impl BlockDevice for MockDisk {
        fn block_count(&self) -> u32 {
            self.blocks.len() as u32
        }
        fn read_block(&self, lba: u32, out: &mut [u8]) -> Result<(), ()> {
            let blk = self.blocks.get(lba as usize).ok_or(())?;
            out[..BLOCK_SIZE].copy_from_slice(blk);
            Ok(())
        }
        fn write_block(&mut self, lba: u32, data: &[u8]) -> Result<(), ()> {
            let blk = self.blocks.get_mut(lba as usize).ok_or(())?;
            blk.copy_from_slice(&data[..BLOCK_SIZE]);
            Ok(())
        }
        fn sync_cache(&self) -> Result<(), ()> {
            self.syncs.set(self.syncs.get() + 1);
            if self.sync_ok { Ok(()) } else { Err(()) }
        }
    }

    // ── CBW / CSW wire format ──────────────────────────────────────

    fn build_cbw_raw(tag: u32, xfer_len: u32, flags: u8, cdb: &[u8]) -> [u8; 31] {
        let mut out = [0u8; 31];
        out[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&tag.to_le_bytes());
        out[8..12].copy_from_slice(&xfer_len.to_le_bytes());
        out[12] = flags;
        out[13] = 0;                 // LUN 0
        out[14] = cdb.len() as u8;
        out[15..15 + cdb.len()].copy_from_slice(cdb);
        out
    }

    #[test]
    fn cbw_parse_round_trip() {
        let raw = build_cbw_raw(0xDEAD_BEEF, 512, CBW_DIR_IN,
                                &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        let cbw = Cbw::parse(&raw).expect("valid CBW");
        assert_eq!(cbw.tag, 0xDEAD_BEEF);
        assert_eq!(cbw.data_transfer_len, 512);
        assert!(cbw.direction_is_in());
        assert_eq!(cbw.cdb_len, 6);
        assert_eq!(cbw.cdb[0], SCSI_OP_INQUIRY);
    }

    #[test]
    fn cbw_rejects_bad_signature() {
        let mut raw = build_cbw_raw(0, 0, 0, &[SCSI_OP_INQUIRY]);
        raw[0] = b'X';
        assert!(Cbw::parse(&raw).is_none());
    }

    #[test]
    fn cbw_rejects_zero_cdb_len() {
        let mut raw = build_cbw_raw(0, 0, 0, &[SCSI_OP_INQUIRY]);
        raw[14] = 0;
        assert!(Cbw::parse(&raw).is_none());
    }

    #[test]
    fn cbw_rejects_short_buffer() {
        let raw = [0u8; 10];
        assert!(Cbw::parse(&raw).is_none());
    }

    #[test]
    fn csw_encodes_13_bytes_with_signature_and_status() {
        let csw = Csw::new(0xABCD_1234, 16, CSW_STATUS_OK);
        let bytes = csw.encode();
        assert_eq!(bytes.len(), 13);
        let sig = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(sig, CSW_SIGNATURE);
        let tag = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(tag, 0xABCD_1234);
        let res = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(res, 16);
        assert_eq!(bytes[12], CSW_STATUS_OK);
    }

    // ── SCSI command parser ────────────────────────────────────────

    #[test]
    fn parses_test_unit_ready() {
        assert_eq!(parse_scsi_command(&[SCSI_OP_TEST_UNIT_READY, 0, 0, 0, 0, 0]),
                   Some(ScsiCommand::TestUnitReady));
    }

    #[test]
    fn parses_inquiry_with_allocation_length() {
        assert_eq!(parse_scsi_command(&[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]),
                   Some(ScsiCommand::Inquiry { allocation_length: 36 }));
    }

    #[test]
    fn parses_read10_with_big_endian_lba() {
        // LBA 0x1234, blocks 2.
        let cdb = [SCSI_OP_READ_10, 0, 0, 0, 0x12, 0x34, 0, 0, 2, 0];
        assert_eq!(parse_scsi_command(&cdb),
                   Some(ScsiCommand::Read10 { lba: 0x1234, blocks: 2 }));
    }

    #[test]
    fn parses_write10_with_big_endian_lba() {
        let cdb = [SCSI_OP_WRITE_10, 0, 0x00, 0x00, 0x00, 0x05, 0, 0, 4, 0];
        assert_eq!(parse_scsi_command(&cdb),
                   Some(ScsiCommand::Write10 { lba: 5, blocks: 4 }));
    }

    #[test]
    fn rejects_unknown_opcode() {
        assert!(parse_scsi_command(&[0xEF, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn rejects_empty_cdb() {
        assert!(parse_scsi_command(&[]).is_none());
    }

    // ── SCSI execution ─────────────────────────────────────────────

    #[test]
    fn inquiry_returns_vendor_product_revision() {
        let blk = MockDisk::new(1);
        let mut buf = [0u8; 64];
        let resp = execute_scsi(ScsiCommand::Inquiry { allocation_length: 36 },
                                &blk, &mut buf, &mut Sense::default());
        match resp {
            ScsiResponse::Done { data_in_len } => {
                assert_eq!(data_in_len, 36);
                // Vendor at [8..16]
                assert_eq!(&buf[8..16], b"AZOS    ");
                // Product at [16..32]
                assert_eq!(&buf[16..32], b"AzOS Recovery   ");
                // Revision at [32..36]
                assert_eq!(&buf[32..36], b"0001");
            }
            _ => panic!("expected Done"),
        }
    }

    #[test]
    fn read_capacity_reports_last_lba_and_block_size() {
        let blk = MockDisk::new(100);
        let mut buf = [0u8; 8];
        let resp = execute_scsi(ScsiCommand::ReadCapacity10, &blk, &mut buf, &mut Sense::default());
        match resp {
            ScsiResponse::Done { data_in_len } => {
                assert_eq!(data_in_len, 8);
                let last_lba = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                assert_eq!(last_lba, 99);
                let blk_size = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                assert_eq!(blk_size, 512);
            }
            _ => panic!("expected Done"),
        }
    }

    #[test]
    fn test_unit_ready_returns_immediately() {
        let blk = MockDisk::new(1);
        let mut buf = [0u8; 1];
        let resp = execute_scsi(ScsiCommand::TestUnitReady, &blk, &mut buf, &mut Sense::default());
        assert_eq!(resp, ScsiResponse::Done { data_in_len: 0 });
    }

    #[test]
    fn read10_signals_expected_data_in_bytes() {
        let blk = MockDisk::new(1024);
        let mut buf = [0u8; 1];
        let resp = execute_scsi(ScsiCommand::Read10 { lba: 0, blocks: 4 },
                                &blk, &mut buf, &mut Sense::default());
        assert_eq!(resp, ScsiResponse::ReadData { expected_data_in: 4 * 512 });
    }

    #[test]
    fn write10_signals_expected_data_out_bytes() {
        let blk = MockDisk::new(1024);
        let mut buf = [0u8; 1];
        let resp = execute_scsi(ScsiCommand::Write10 { lba: 10, blocks: 3 },
                                &blk, &mut buf, &mut Sense::default());
        assert_eq!(resp, ScsiResponse::WriteData { expected_data_out: 3 * 512 });
    }

    #[test]
    fn request_sense_returns_no_sense_18_bytes() {
        let blk = MockDisk::new(1);
        let mut buf = [0u8; 32];
        let resp = execute_scsi(ScsiCommand::RequestSense { allocation_length: 18 },
                                &blk, &mut buf, &mut Sense::default());
        match resp {
            ScsiResponse::Done { data_in_len } => {
                assert_eq!(data_in_len, 18);
                assert_eq!(buf[0], 0x70); // response code
                assert_eq!(buf[2], 0x00); // NO SENSE
                assert_eq!(buf[7], 10);   // additional length = 18-8
            }
            _ => panic!("expected Done"),
        }
    }

    // ── Descriptor builder ─────────────────────────────────────────

    #[test]
    fn descriptor_blob_layout() {
        let mut buf = [0u8; 64];
        let b = MscDescriptorBuilder::new(0x81, 0x02);
        let n = b.encode(&mut buf).unwrap();
        assert_eq!(n, b.total_length() as usize);

        // CONFIGURATION (9 bytes)
        assert_eq!(buf[1], 0x02);
        assert_eq!(buf[4], 1); // bNumInterfaces

        // INTERFACE descriptor (offset 9..18). Layout per USB spec:
        //  9 bLength, 10 bDescriptorType, 11 bInterfaceNumber,
        // 12 bAlternateSetting, 13 bNumEndpoints,
        // 14 bInterfaceClass, 15 bInterfaceSubClass,
        // 16 bInterfaceProtocol, 17 iInterface.
        assert_eq!(buf[10], 0x04);                       // INTERFACE
        assert_eq!(buf[13], 2);                          // bNumEndpoints
        assert_eq!(buf[14], MSC_INTERFACE_CLASS);
        assert_eq!(buf[15], MSC_INTERFACE_SUBCLASS_SCSI);
        assert_eq!(buf[16], MSC_INTERFACE_PROTOCOL_BBB);

        // Bulk-IN endpoint descriptor (offset 18..25). Layout:
        // 18 bLength, 19 bDescriptorType, 20 bEndpointAddress,
        // 21 bmAttributes, 22..24 wMaxPacketSize, 24 bInterval.
        assert_eq!(buf[19], 0x05);                       // ENDPOINT
        assert_eq!(buf[20], 0x81);                       // bulk-IN addr
        assert_eq!(buf[21], 0x02);                       // bulk transfer type
        let mps_in = u16::from_le_bytes(buf[22..24].try_into().unwrap());
        assert_eq!(mps_in, MSC_BULK_EP_MAX_PACKET);

        // Bulk-OUT endpoint descriptor (offset 25..32). Same layout.
        assert_eq!(buf[27], 0x02);                       // bulk-OUT addr
    }

    #[test]
    fn descriptor_rejects_short_buffer() {
        let mut tiny = [0u8; 8];
        let b = MscDescriptorBuilder::new(0x81, 0x02);
        assert!(b.encode(&mut tiny).is_none());
    }

    // ── State machine ──────────────────────────────────────────────

    #[test]
    fn state_machine_transitions() {
        let mut sm = MscStateMachine::new();
        assert_eq!(sm.phase(), MscPhase::Idle);
        sm.set_phase(MscPhase::DataIn { remaining: 36 });
        assert!(matches!(sm.phase(), MscPhase::DataIn { .. }));
        sm.set_phase(MscPhase::Status);
        assert_eq!(sm.phase(), MscPhase::Status);
        sm.set_phase(MscPhase::Reset);
        sm.reset();
        assert_eq!(sm.phase(), MscPhase::Idle);
    }

    // ── Round-trip: CBW → execute → CSW ────────────────────────────

    #[test]
    fn full_inquiry_round_trip() {
        let raw_cbw = build_cbw_raw(
            0xCAFE_F00D, 36, CBW_DIR_IN,
            &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0],
        );
        let cbw = Cbw::parse(&raw_cbw).unwrap();
        let cmd = parse_scsi_command(&cbw.cdb[..cbw.cdb_len as usize]).unwrap();
        let blk = MockDisk::new(1024);
        let mut data_in = [0u8; 36];
        let resp = execute_scsi(cmd, &blk, &mut data_in, &mut Sense::default());
        let len = match resp {
            ScsiResponse::Done { data_in_len } => data_in_len,
            _ => panic!("expected Done"),
        };
        let csw = Csw::new(cbw.tag,
                           cbw.data_transfer_len - len as u32,
                           CSW_STATUS_OK);
        let bytes = csw.encode();
        assert_eq!(&bytes[4..8], &0xCAFE_F00D_u32.to_le_bytes());
        // Residue = 36 - 36 = 0.
        assert_eq!(&bytes[8..12], &0u32.to_le_bytes());
    }

    // ── DEV03 kernel-glue dispatcher (crates/drivers/msc::dispatch) ────────

    use azos_msc::{
        block_bytes, dispatch_cbw, lba_range_in_bounds, Action,
        CSW_STATUS_FAIL, CSW_TOTAL_LEN, DISPATCH_IN_BUF_LEN,
        MSC_MAX_LUN, SCSI_OP_MODE_SENSE_6,
    };

    /// 13-byte CSW header layout: signature(4) tag(4) residue(4) status(1).
    fn csw_status(csw: &[u8; CSW_TOTAL_LEN]) -> u8 { csw[12] }
    fn csw_tag(csw: &[u8; CSW_TOTAL_LEN]) -> u32 {
        u32::from_le_bytes(csw[4..8].try_into().unwrap())
    }
    fn csw_residue(csw: &[u8; CSW_TOTAL_LEN]) -> u32 {
        u32::from_le_bytes(csw[8..12].try_into().unwrap())
    }

    const MOCK_DISK_BLOCKS: u32 = 1024;

    #[test]
    fn dispatch_inquiry_inline_done_with_correct_csw() {
        let raw = build_cbw_raw(0x1111_2222, 36, CBW_DIR_IN,
                                &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 36);
                assert_eq!(csw_tag(&csw), 0x1111_2222);
                assert_eq!(csw_residue(&csw), 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(&scratch[8..16], b"AZOS    ");
            }
            other => panic!("expected InlineDone, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_read10_emits_read_blocks_action() {
        let raw = build_cbw_raw(
            0xAAAA_BBBB, block_bytes(4) as u32, CBW_DIR_IN,
            &[SCSI_OP_READ_10, 0, 0, 0, 0, 0x10, 0, 0, 4, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::ReadBlocks { start_lba, blocks, csw } => {
                assert_eq!(start_lba, 0x10);
                assert_eq!(blocks, 4);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(csw_residue(&csw), 0); // host requested exactly 4×512
            }
            other => panic!("expected ReadBlocks, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_write10_emits_write_blocks_action() {
        let raw = build_cbw_raw(
            7, block_bytes(2) as u32, CBW_DIR_OUT,
            &[SCSI_OP_WRITE_10, 0, 0, 0, 0, 0x20, 0, 0, 2, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::WriteBlocks { start_lba, blocks, csw } => {
                assert_eq!(start_lba, 0x20);
                assert_eq!(blocks, 2);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(csw_residue(&csw), 0);
            }
            other => panic!("expected WriteBlocks, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_out_of_range_read_fails_with_csw_fail() {
        // Request LBA beyond the device — expect inline FAIL CSW,
        // not ReadBlocks (so we don't stream garbage on bulk-IN).
        let raw = build_cbw_raw(
            42, block_bytes(2) as u32, CBW_DIR_IN,
            // LBA = 2048 + 0 (way past MOCK_DISK_BLOCKS = 1024).
            &[SCSI_OP_READ_10, 0, 0, 0, 0x08, 0x00, 0, 0, 2, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_FAIL);
                assert_eq!(csw_tag(&csw), 42);
            }
            other => panic!("expected InlineDone(FAIL), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_out_of_range_write_fails_with_csw_fail() {
        let raw = build_cbw_raw(
            43, block_bytes(1) as u32, CBW_DIR_OUT,
            &[SCSI_OP_WRITE_10, 0, 0, 0, 0x08, 0x00, 0, 0, 1, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { csw, .. } => {
                assert_eq!(csw_status(&csw), CSW_STATUS_FAIL);
            }
            other => panic!("expected InlineDone(FAIL), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_bad_cbw_signature_reports_phase_error() {
        let mut raw = build_cbw_raw(0, 0, 0, &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        raw[0] = b'Z';                       // wreck the signature
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(
            dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()),
            Action::PhaseError,
        );
    }

    #[test]
    fn dispatch_short_buffer_reports_phase_error() {
        let short = [0u8; 10];
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(
            dispatch_cbw(&short, &blk, &mut scratch, &mut Sense::default()),
            Action::PhaseError,
        );
    }

    #[test]
    fn dispatch_unknown_opcode_emits_fail_csw_not_phase_error() {
        // Unknown opcode → host expects a normal CSW(FAIL), then
        // REQUEST_SENSE — NOT a stall. The dispatcher must not
        // collapse this case into PhaseError.
        let raw = build_cbw_raw(99, 0, CBW_DIR_IN,
                                &[0xEF, 0, 0, 0, 0, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_FAIL);
                assert_eq!(csw_tag(&csw), 99);
            }
            other => panic!("expected InlineDone(FAIL), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_mode_sense6_inline_response() {
        let raw = build_cbw_raw(1, 4, CBW_DIR_IN,
                                &[SCSI_OP_MODE_SENSE_6, 0, 0, 0, 4, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 4);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(scratch[0], 3); // mode parameter header length
            }
            other => panic!("expected InlineDone, got {other:?}"),
        }
    }

    // ── BBB §6.7 host/device transfer reconciliation (Table 6.1) ───
    //
    // Before these, `data_transfer_len` was used only to compute the CSW
    // residue and `direction_is_in()` was never called at all — no case in
    // the table produced PhaseError, so a desynchronised endpoint was never
    // reported and the host was never told to run reset recovery.

    #[test]
    fn dispatch_read10_shorter_than_cdb_is_phase_error() {
        // Case 7 (Hi < Di): host allots 512 bytes, CDB asks for 8 blocks
        // (4096). Streaming 4096 into a 512-byte expectation desynchronises
        // the bulk-IN endpoint.
        let raw = build_cbw_raw(
            0x51, 512, CBW_DIR_IN,
            &[SCSI_OP_READ_10, 0, 0, 0, 0, 0x10, 0, 0, 8, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_read10_flagged_data_out_is_phase_error() {
        // Case 10 (Ho <> Di): a READ_10 whose CBW claims host→device. The
        // device would push data onto an endpoint the host drives the other
        // way.
        let raw = build_cbw_raw(
            0x52, block_bytes(2) as u32, CBW_DIR_OUT,
            &[SCSI_OP_READ_10, 0, 0, 0, 0, 0x10, 0, 0, 2, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_write10_flagged_data_in_is_phase_error() {
        // Case 8 (Hi <> Do).
        let raw = build_cbw_raw(
            0x53, block_bytes(2) as u32, CBW_DIR_IN,
            &[SCSI_OP_WRITE_10, 0, 0, 0, 0, 0x20, 0, 0, 2, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_write10_shorter_than_cdb_is_phase_error() {
        // Case 13 (Ho < Do).
        let raw = build_cbw_raw(
            0x54, 512, CBW_DIR_OUT,
            &[SCSI_OP_WRITE_10, 0, 0, 0, 0, 0x20, 0, 0, 4, 0],
        );
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_data_command_with_zero_host_length_is_phase_error() {
        // Case 2 (Hn < Di): the host announced no data phase at all, but the
        // command produces 36 bytes.
        let raw = build_cbw_raw(0x55, 0, CBW_DIR_IN,
                                &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_host_longer_than_device_is_ok_with_residue() {
        // Case 5 (Hi > Di): perfectly legal — the device just under-runs and
        // reports the difference as residue. Must NOT be a phase error.
        let raw = build_cbw_raw(0x56, 64, CBW_DIR_IN,
                                &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 36);
                assert_eq!(csw_residue(&csw), 64 - 36);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
            }
            other => panic!("expected InlineDone, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_no_data_command_ignores_direction_bit() {
        // Case 1 (Hn = Dn): TEST_UNIT_READY transfers nothing, so the
        // direction bit is don't-care and any host length is satisfied by
        // residue. This is the arm that must stay permissive.
        for flags in [CBW_DIR_IN, CBW_DIR_OUT] {
            let raw = build_cbw_raw(0x57, 0, flags,
                                    &[SCSI_OP_TEST_UNIT_READY, 0, 0, 0, 0, 0]);
            let blk = MockDisk::new(MOCK_DISK_BLOCKS);
            let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
            match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
                Action::InlineDone { in_len, csw } => {
                    assert_eq!(in_len, 0);
                    assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                }
                other => panic!("expected InlineDone, got {other:?}"),
            }
        }
    }

    #[test]
    fn dispatch_zero_allocation_length_is_treated_as_no_data() {
        // Case 4 (Hi > Dn) via the allocation-length route: INQUIRY with
        // allocation_length = 0 moves no data, so it must normalise to the
        // Dn arm rather than being compared as a zero-length IN.
        let raw = build_cbw_raw(0x58, 0, CBW_DIR_IN,
                                &[SCSI_OP_INQUIRY, 0, 0, 0, 0, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
            }
            other => panic!("expected InlineDone, got {other:?}"),
        }
    }

    // ── BBB §6.2.2 — LUN validation ───────────────────────────────

    #[test]
    fn dispatch_unsupported_lun_is_phase_error() {
        // We export exactly one LUN. A CBW addressed to LUN 3 used to be
        // executed against LUN 0 anyway — the host believes it talked to a
        // device that does not exist, while the command landed on the volume
        // holding the kernel images.
        let mut raw = build_cbw_raw(0x59, 36, CBW_DIR_IN,
                                    &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        raw[13] = 3;
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert_eq!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()), Action::PhaseError);
    }

    #[test]
    fn dispatch_lun_zero_still_accepted() {
        assert_eq!(MSC_MAX_LUN, 0);
        let mut raw = build_cbw_raw(0x5A, 36, CBW_DIR_IN,
                                    &[SCSI_OP_INQUIRY, 0, 0, 0, 36, 0]);
        raw[13] = 0;
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        assert!(matches!(dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()),
                         Action::InlineDone { .. }));
    }

    // ── Finding 8 — Inquiry bounds ────────────────────────────────

    #[test]
    fn inquiry_with_zero_allocation_length_does_not_touch_the_buffer() {
        // `need = 0`, so the `data_in_buf.len() < need` guard passes for ANY
        // buffer — including an empty one. The five unconditional field
        // stores that followed were an out-of-bounds index, and with
        // `panic = "abort"` that is a board reset, not a bad response.
        let blk = MockDisk::new(8);
        let mut empty: [u8; 0] = [];
        let resp = execute_scsi(ScsiCommand::Inquiry { allocation_length: 0 },
                                &blk, &mut empty, &mut Sense::default());
        assert_eq!(resp, ScsiResponse::Done { data_in_len: 0 });
    }

    #[test]
    fn inquiry_with_short_allocation_length_fills_only_what_fits() {
        let blk = MockDisk::new(8);
        for alloc in 1u8..=5 {
            let mut buf = vec![0xAAu8; alloc as usize];
            let resp = execute_scsi(ScsiCommand::Inquiry { allocation_length: alloc },
                                    &blk, &mut buf, &mut Sense::default());
            assert_eq!(resp, ScsiResponse::Done { data_in_len: alloc as usize });
            // Every byte it was allowed to write must have been written
            // (zeroed then set), so none of the 0xAA fill survives.
            assert!(!buf.contains(&0xAA), "alloc={alloc} buf={buf:?}");
        }
    }

    #[test]
    fn inquiry_partial_prefix_matches_the_full_response() {
        // A truncated INQUIRY must be a byte-exact prefix of the full one —
        // that is what makes the per-field guards correct rather than merely
        // panic-free.
        let blk = MockDisk::new(8);
        let mut full = [0u8; 36];
        execute_scsi(ScsiCommand::Inquiry { allocation_length: 36 }, &blk, &mut full, &mut Sense::default());
        for alloc in 0u8..=5 {
            let mut buf = vec![0u8; alloc as usize];
            execute_scsi(ScsiCommand::Inquiry { allocation_length: alloc }, &blk, &mut buf, &mut Sense::default());
            assert_eq!(&buf[..], &full[..alloc as usize], "alloc={alloc}");
        }
    }

    #[test]
    fn lba_range_bounds_check_corner_cases() {
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        assert!(lba_range_in_bounds(&blk, 0, 1));
        assert!(lba_range_in_bounds(&blk, MOCK_DISK_BLOCKS - 1, 1));
        assert!(lba_range_in_bounds(&blk, 0, 0));
        assert!(!lba_range_in_bounds(&blk, MOCK_DISK_BLOCKS, 1));
        assert!(!lba_range_in_bounds(&blk, MOCK_DISK_BLOCKS - 1, 2));
        // u32 wrap-around path must not falsely pass.
        assert!(!lba_range_in_bounds(&blk, u32::MAX, 1));
    }

    #[test]
    fn block_bytes_is_512_aligned() {
        assert_eq!(block_bytes(0), 0);
        assert_eq!(block_bytes(1), 512);
        assert_eq!(block_bytes(8), 4096);
    }

    #[test]
    fn full_read_capacity_round_trip() {
        let raw_cbw = build_cbw_raw(
            1, 8, CBW_DIR_IN,
            &[SCSI_OP_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let cbw = Cbw::parse(&raw_cbw).unwrap();
        let cmd = parse_scsi_command(&cbw.cdb[..cbw.cdb_len as usize]).unwrap();
        assert_eq!(cmd, ScsiCommand::ReadCapacity10);
        let blk = MockDisk::new(1024);
        let mut buf = [0u8; 8];
        let resp = execute_scsi(cmd, &blk, &mut buf, &mut Sense::default());
        assert_eq!(resp, ScsiResponse::Done { data_in_len: 8 });
        let last_lba = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(last_lba, 1023);
    }
    // ── SYNCHRONIZE CACHE(10) (wave 7, STOR) ───────────────────────

    use azos_msc::SCSI_OP_SYNCHRONIZE_CACHE_10;

    fn sync_cache_cbw(tag: u32) -> [u8; 31] {
        build_cbw_raw(tag, 0, CBW_DIR_OUT,
                      &[SCSI_OP_SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    fn request_sense(blk: &MockDisk, sense: &mut Sense) -> [u8; 18] {
        let raw = build_cbw_raw(7, 18, CBW_DIR_IN, &[0x03, 0, 0, 0, 18, 0]);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, blk, &mut scratch, sense) {
            Action::InlineDone { in_len: 18, csw } => {
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                scratch[..18].try_into().unwrap()
            }
            other => panic!("REQUEST SENSE: {other:?}"),
        }
    }

    #[test]
    fn parses_synchronize_cache_10() {
        assert_eq!(parse_scsi_command(&[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                   Some(ScsiCommand::SynchronizeCache10));
        // A 6-byte CDB cannot be SYNCHRONIZE CACHE(10).
        assert_eq!(parse_scsi_command(&[0x35, 0, 0, 0, 0, 0]), None);
        // The 16-byte form is not implemented (see SCSI_OP_SYNCHRONIZE_CACHE_10).
        assert_eq!(parse_scsi_command(&[0x91; 16]), None);
    }

    /// The flush is reached, and a confirmed flush is GOOD with no sense.
    #[test]
    fn synchronize_cache_flushes_and_reports_good() {
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut sense = Sense::default();
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&sync_cache_cbw(0x35), &blk, &mut scratch, &mut sense) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(csw_tag(&csw), 0x35);
            }
            other => panic!("expected InlineDone(OK), got {other:?}"),
        }
        assert_eq!(blk.syncs.get(), 1, "SYNCHRONIZE CACHE must reach sync_cache exactly once");
        assert_eq!(request_sense(&blk, &mut sense)[2], 0x00, "a good flush leaves NO SENSE");
    }

    /// A flush that fails is CHECK CONDITION (CSW FAIL) and the next
    /// REQUEST SENSE says MEDIUM ERROR / WRITE ERROR — once.
    #[test]
    fn a_failed_synchronize_cache_is_check_condition_with_medium_error() {
        let mut blk = MockDisk::new(MOCK_DISK_BLOCKS);
        blk.sync_ok = false;
        let mut sense = Sense::default();
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&sync_cache_cbw(9), &blk, &mut scratch, &mut sense) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(in_len, 0);
                assert_eq!(csw_status(&csw), CSW_STATUS_FAIL,
                           "a flush the device could not confirm must not report GOOD");
            }
            other => panic!("expected InlineDone(FAIL), got {other:?}"),
        }
        let s = request_sense(&blk, &mut sense);
        assert_eq!((s[0], s[2], s[12], s[13]), (0x70, 0x03, 0x0C, 0x00),
                   "sense must be MEDIUM ERROR / WRITE ERROR");
        assert_eq!(request_sense(&blk, &mut sense)[2], 0x00,
                   "sense is reported once, then cleared");
    }

    /// SYNCHRONIZE CACHE moves no data: the host may announce any length
    /// and either direction (BBB §6.7 cases 1/4/9).
    #[test]
    fn synchronize_cache_with_a_host_length_is_ok_with_full_residue() {
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let raw = build_cbw_raw(3, 512, CBW_DIR_IN,
                                &[SCSI_OP_SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len: 0, csw } => {
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(csw_residue(&csw), 512);
            }
            other => panic!("expected InlineDone, got {other:?}"),
        }
    }

    /// An unknown opcode's CSW(FAIL) is now explained by the sense data.
    #[test]
    fn an_unknown_opcode_leaves_illegal_request_sense() {
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut sense = Sense::default();
        let raw = build_cbw_raw(5, 0, CBW_DIR_IN, &[0xEF, 0, 0, 0, 0, 0]);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        let _ = dispatch_cbw(&raw, &blk, &mut scratch, &mut sense);
        let s = request_sense(&blk, &mut sense);
        assert_eq!((s[2], s[12]), (0x05, 0x20));
    }
    // ── MODE SENSE(6) Caching page (wave 7 follow-up) ──────────────

    use azos_msc::{CACHING_WCE, MODE_PAGE_ALL, MODE_PAGE_CACHING};

    /// MODE SENSE(6) for `page` (PC = `pc`) with Linux usb-storage's
    /// 192-byte allocation; returns the bytes the device sent.
    fn mode_sense(page: u8, pc: u8) -> Vec<u8> {
        let raw = build_cbw_raw(0x5E, 192, CBW_DIR_IN,
                                &[SCSI_OP_MODE_SENSE_6, 0, (pc << 6) | page, 0, 192, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len, csw } => {
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(csw_residue(&csw), 192 - in_len as u32);
                scratch[..in_len].to_vec()
            }
            other => panic!("MODE SENSE page {page:#x}: {other:?}"),
        }
    }

    /// What Linux `sd_read_cache_type` walks: header, then pages; the
    /// Caching page (08h) byte 2 carries WCE (bit 2) and RCD (bit 0).
    fn caching_byte2(resp: &[u8]) -> Option<u8> {
        assert_eq!(resp[0] as usize + 1, resp.len(), "mode data length");
        let mut off = 4 + resp[3] as usize;
        while off + 2 < resp.len() {
            if resp[off] & 0x3F == 0x08 { return Some(resp[off + 2]); }
            off += 2 + resp[off + 1] as usize;
        }
        None
    }

    /// Hosts must see a volatile write cache, or they never send
    /// SYNCHRONIZE CACHE (Linux: "Assuming drive cache: write through").
    #[test]
    fn mode_sense_reports_the_caching_page_with_wce_set() {
        for page in [MODE_PAGE_CACHING, MODE_PAGE_ALL] {
            let resp = mode_sense(page, 0);
            assert_eq!(resp.len(), 24, "page {page:#x}");
            let b2 = caching_byte2(&resp).expect("Caching page present");
            assert_eq!(b2 & CACHING_WCE, CACHING_WCE, "WCE=1 for page {page:#x}");
            assert_eq!(b2 & 0x01, 0, "RCD=0 for page {page:#x}");
            assert_eq!(resp[2] & 0x80, 0, "not write-protected");
        }
    }

    /// Nothing is changeable (there is no MODE SELECT): PC=01 returns the
    /// page with WCE clear, so a host does not think it can turn it off.
    #[test]
    fn mode_sense_changeable_values_show_nothing_changeable() {
        let resp = mode_sense(MODE_PAGE_CACHING, 1);
        assert_eq!(caching_byte2(&resp), Some(0));
    }

    /// Other pages keep the old header-only answer, and a short
    /// allocation truncates without changing the reported length.
    #[test]
    fn mode_sense_other_pages_and_short_allocations() {
        let resp = mode_sense(0x1C, 0);
        assert_eq!(resp, vec![3, 0, 0, 0]);
        let raw = build_cbw_raw(1, 4, CBW_DIR_IN, &[SCSI_OP_MODE_SENSE_6, 0, 0x3F, 0, 4, 0]);
        let blk = MockDisk::new(MOCK_DISK_BLOCKS);
        let mut scratch = [0u8; DISPATCH_IN_BUF_LEN];
        match dispatch_cbw(&raw, &blk, &mut scratch, &mut Sense::default()) {
            Action::InlineDone { in_len: 4, csw } => {
                assert_eq!(csw_status(&csw), CSW_STATUS_OK);
                assert_eq!(scratch[0], 23, "mode data length is the full response, not the truncated one");
            }
            other => panic!("{other:?}"),
        }
    }
}


