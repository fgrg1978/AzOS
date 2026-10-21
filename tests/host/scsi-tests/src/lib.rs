// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for azos_scsi.
//!
//! The initiator builds what the target decodes; each test drives one end
//! against the other, so a field moved on one side goes red here.

#[cfg(test)]
mod tests {
    use azos_scsi::bbb::{Cbw, Csw, CBW_DIR_IN, CBW_DIR_OUT, CBW_TOTAL_LEN, CSW_STATUS_FAIL, CSW_TOTAL_LEN};
    use azos_scsi::initiator::{
        parse_inquiry, parse_read_capacity_10, parse_sense, CapacityError, Cdb, INQUIRY_LEN, READ_CAPACITY_10_LEN,
        SENSE_LEN,
    };
    use azos_scsi::target::{
        execute_scsi, parse_scsi_command, BlockDevice, ScsiCommand, ScsiResponse, Sense, BLOCK_SIZE,
        INQUIRY_PRODUCT_ID, INQUIRY_REVISION, INQUIRY_VENDOR_ID,
    };

    struct Disk {
        blocks: u32,
        sync_ok: bool,
    }

    impl BlockDevice for Disk {
        fn block_count(&self) -> u32 {
            self.blocks
        }
        fn read_block(&self, _: u32, _: &mut [u8]) -> Result<(), ()> {
            Ok(())
        }
        fn write_block(&mut self, _: u32, _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        fn sync_cache(&self) -> Result<(), ()> {
            if self.sync_ok { Ok(()) } else { Err(()) }
        }
    }

    /// Run `cdb` on the target and return the bytes it answers.
    fn answer(cdb: &Cdb, disk: &Disk, sense: &mut Sense) -> Vec<u8> {
        let cmd = parse_scsi_command(&cdb.bytes[..cdb.len as usize]).expect("the target decodes every CDB built");
        let mut buf = [0u8; 64];
        match execute_scsi(cmd, disk, &mut buf, sense) {
            ScsiResponse::Done { data_in_len } => buf[..data_in_len].to_vec(),
            other => panic!("{other:?}"),
        }
    }

    // ---- CDBs ----

    #[test]
    fn every_cdb_is_decoded_by_the_target_as_built() {
        assert_eq!(parse_scsi_command(&Cdb::test_unit_ready().bytes[..6]), Some(ScsiCommand::TestUnitReady));
        assert_eq!(
            parse_scsi_command(&Cdb::request_sense(18).bytes[..6]),
            Some(ScsiCommand::RequestSense { allocation_length: 18 })
        );
        assert_eq!(
            parse_scsi_command(&Cdb::inquiry(36).bytes[..6]),
            Some(ScsiCommand::Inquiry { allocation_length: 36 })
        );
        assert_eq!(parse_scsi_command(&Cdb::read_capacity_10().bytes[..10]), Some(ScsiCommand::ReadCapacity10));
        // Distinct values in every byte of the address and of the count, so a
        // swapped or truncated field cannot decode to the same command.
        assert_eq!(
            parse_scsi_command(&Cdb::read_10(0x0102_0304, 0x0506).bytes[..10]),
            Some(ScsiCommand::Read10 { lba: 0x0102_0304, blocks: 0x0506 })
        );
        assert_eq!(
            parse_scsi_command(&Cdb::write_10(0xA0B0_C0D0, 0x0708).bytes[..10]),
            Some(ScsiCommand::Write10 { lba: 0xA0B0_C0D0, blocks: 0x0708 })
        );
        assert_eq!(
            parse_scsi_command(&Cdb::synchronize_cache_10().bytes[..10]),
            Some(ScsiCommand::SynchronizeCache10)
        );
    }

    #[test]
    fn cdb_lengths_are_the_standards() {
        assert_eq!(Cdb::test_unit_ready().len, 6);
        assert_eq!(Cdb::request_sense(18).len, 6);
        assert_eq!(Cdb::inquiry(36).len, 6);
        assert_eq!(Cdb::read_capacity_10().len, 10);
        assert_eq!(Cdb::read_10(0, 1).len, 10);
        assert_eq!(Cdb::write_10(0, 1).len, 10);
        assert_eq!(Cdb::synchronize_cache_10().len, 10);
    }

    // ---- CBW / CSW ----

    #[test]
    fn a_cbw_the_host_encodes_is_the_one_the_gadget_parses() {
        let cdb = Cdb::read_10(77, 8);
        let cbw = cdb.cbw(0xDEAD_BEEF, 8 * BLOCK_SIZE as u32, true);
        let wire = cbw.encode();
        assert_eq!(wire.len(), CBW_TOTAL_LEN);
        assert_eq!(&wire[0..4], b"USBC");
        let back = Cbw::parse(&wire).expect("parses");
        assert_eq!(back, cbw);
        assert_eq!(back.flags, CBW_DIR_IN);
        assert_eq!(back.tag, 0xDEAD_BEEF);
        assert_eq!(back.data_transfer_len, 4096);
        assert_eq!(back.cdb_len, 10);
        assert_eq!(&back.cdb[..10], &cdb.bytes[..10]);
    }

    #[test]
    fn a_cbw_without_data_is_data_out_with_length_zero() {
        // BBB §6.7: with no data stage the direction bit is "not meaningful"; 0
        // is the form every device accepts.
        let cbw = Cdb::test_unit_ready().cbw(1, 0, true);
        assert_eq!((cbw.flags, cbw.data_transfer_len), (CBW_DIR_OUT, 0));
        let cbw = Cdb::write_10(0, 1).cbw(1, 512, false);
        assert_eq!((cbw.flags, cbw.data_transfer_len), (CBW_DIR_OUT, 512));
    }

    #[test]
    fn a_csw_the_gadget_encodes_is_the_one_the_host_parses() {
        let wire = Csw::new(0x1122_3344, 0x55, CSW_STATUS_FAIL).encode();
        assert_eq!(wire.len(), CSW_TOTAL_LEN);
        let csw = Csw::parse(&wire).expect("parses");
        assert_eq!((csw.tag, csw.data_residue, csw.status), (0x1122_3344, 0x55, CSW_STATUS_FAIL));
    }

    #[test]
    fn an_invalid_csw_is_refused() {
        let good = Csw::new(1, 0, 0).encode();
        assert!(Csw::parse(&good).is_some());
        // Wrong length, either way.
        assert!(Csw::parse(&good[..12]).is_none());
        let mut long = good.to_vec();
        long.push(0);
        assert!(Csw::parse(&long).is_none());
        // Wrong signature, one byte off.
        for i in 0..4 {
            let mut bad = good;
            bad[i] ^= 1;
            assert!(Csw::parse(&bad).is_none(), "signature byte {i}");
        }
    }

    // ---- INQUIRY ----

    #[test]
    fn inquiry_data_from_the_gadget_parses() {
        let d = Disk { blocks: 8, sync_ok: true };
        let data = answer(&Cdb::inquiry(INQUIRY_LEN as u8), &d, &mut Sense::default());
        let i = parse_inquiry(&data).expect("36 bytes");
        assert_eq!(&i.vendor, INQUIRY_VENDOR_ID);
        assert_eq!(&i.product, INQUIRY_PRODUCT_ID);
        assert_eq!(&i.revision, INQUIRY_REVISION);
        assert!(i.removable);
        assert!(i.is_block_device());
    }

    #[test]
    fn inquiry_classifies_the_device_type() {
        let mut data = [0u8; INQUIRY_LEN];
        let mut kind = |first: u8| {
            data[0] = first;
            parse_inquiry(&data).unwrap().is_block_device()
        };
        assert!(kind(0x00), "direct access");
        assert!(kind(0x0E), "RBC");
        assert!(!kind(0x05), "CD-ROM");
        assert!(!kind(0x01), "tape");
        // Peripheral qualifier 1 (device not connected) and 3 (no logical
        // unit): a type of 0 on a unit that is not there.
        assert!(!kind(0x20), "qualifier 1");
        assert!(!kind(0x60), "qualifier 3");
        assert!(parse_inquiry(&data[..35]).is_none());
    }

    // ---- READ CAPACITY(10) ----

    #[test]
    fn capacity_from_the_gadget_is_blocks_not_last_lba() {
        let d = Disk { blocks: 1000, sync_ok: true };
        let data = answer(&Cdb::read_capacity_10(), &d, &mut Sense::default());
        assert_eq!(data.len(), READ_CAPACITY_10_LEN);
        // The wire carries the LAST lba (999); the parser says 1000 sectors.
        assert_eq!(parse_read_capacity_10(&data).unwrap().sectors, 1000);
    }

    #[test]
    fn capacity_the_block_layer_cannot_use_is_refused() {
        let mut d = [0u8; 8];
        d[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        d[4..8].copy_from_slice(&512u32.to_be_bytes());
        assert_eq!(parse_read_capacity_10(&d), Err(CapacityError::TooLarge));
        d[0..4].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
        d[4..8].copy_from_slice(&4096u32.to_be_bytes());
        assert_eq!(parse_read_capacity_10(&d), Err(CapacityError::BlockLen(4096)));
        assert_eq!(parse_read_capacity_10(&d[..7]), Err(CapacityError::Short));
        // The largest medium a 10-byte CDB reports: last LBA 0xFFFFFFFE.
        d[0..4].copy_from_slice(&(u32::MAX - 1).to_be_bytes());
        d[4..8].copy_from_slice(&512u32.to_be_bytes());
        assert_eq!(parse_read_capacity_10(&d).unwrap().sectors, u32::MAX as u64);
    }

    // ---- Sense ----

    #[test]
    fn a_sense_the_gadget_reports_is_the_one_the_host_reads() {
        let d = Disk { blocks: 8, sync_ok: false };
        let mut sense = Sense::WRITE_ERROR;
        let data = answer(&Cdb::request_sense(SENSE_LEN as u8), &d, &mut sense);
        assert_eq!(data.len(), SENSE_LEN);
        assert_eq!(parse_sense(&data), Some(Sense::WRITE_ERROR));
        // Reported and cleared.
        assert_eq!(sense, Sense::NONE);
        let mut sense = Sense::INVALID_OPCODE;
        let data = answer(&Cdb::request_sense(SENSE_LEN as u8), &d, &mut sense);
        let got = parse_sense(&data).unwrap();
        assert!(got.is_invalid_opcode());
        assert!(!got.is_not_ready() && !got.is_unit_attention());
    }

    #[test]
    fn sense_in_descriptor_format_is_read_too() {
        // Response code 0x72: key in byte 1, ASC / ASCQ in bytes 2 and 3.
        let d = [0x72, 0x02, 0x3A, 0x00, 0, 0, 0, 0];
        let s = parse_sense(&d).unwrap();
        assert!(s.is_not_ready());
        assert_eq!((s.asc, s.ascq), (0x3A, 0));
        // Unit attention, fixed format.
        let mut f = [0u8; 18];
        f[0] = 0xF0; // valid bit + 0x70
        f[2] = 0x06;
        f[7] = 10;
        f[12] = 0x29;
        assert!(parse_sense(&f).unwrap().is_unit_attention());
        assert_eq!(parse_sense(&f[..13]), None, "too short for the qualifier");
        assert_eq!(parse_sense(&[0x00; 18]), None, "not a sense response code");
        assert_eq!(parse_sense(&[]), None);
    }
}
