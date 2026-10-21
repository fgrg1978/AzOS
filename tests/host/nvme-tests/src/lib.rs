// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_nvme`. Expected values are written out from the NVMe
//! 1.4 base specification's field layouts (section numbers in the comments),
//! not computed with the code under test.

#![cfg(test)]

use azos_nvme::*;

// ── Registers, doorbells ────────────────────────────────────────────────

#[test]
fn cap_decode_fields() {
    // MQES=0x3ff, CQR=1, TO=20, DSTRD=3, CSS bit 0, MPSMIN=0, MPSMAX=4.
    let raw: u64 = 0x3ff | 1 << 16 | 20 << 24 | 3 << 32 | 1 << 37 | 4 << 52;
    let c = decode_cap(raw);
    assert_eq!(c.max_queue_entries, 0x400);
    assert!(c.contiguous_required);
    assert_eq!(c.ready_timeout_ms, 10_000);
    assert_eq!(c.dstrd, 3);
    assert!(c.nvm_command_set);
    assert_eq!((c.mps_min_shift, c.mps_max_shift), (12, 16));
}

#[test]
fn cap_decode_zero_is_a_one_entry_queue() {
    let c = decode_cap(0);
    assert_eq!(c.max_queue_entries, 1);
    assert!(!c.nvm_command_set);
    assert_eq!(c.ready_timeout_ms, 0);
}

#[test]
fn cc_and_aqa_values() {
    // EN | IOSQES=6 << 16 | IOCQES=4 << 20 (3.1.5)
    assert_eq!(cc_enable(), 0x0046_0001);
    // ASQS = 31, ACQS = 15 (3.1.8)
    assert_eq!(aqa(32, 16), 0x000f_001f);
    assert_eq!(aqa(2, 2), 0x0001_0001);
}

#[test]
fn doorbell_offsets_default_stride() {
    // 3.1.10 with DSTRD 0: 4 bytes apart, SQ then CQ per queue.
    assert_eq!(doorbell_offset(0, false, 0), 0x1000);
    assert_eq!(doorbell_offset(0, true, 0), 0x1004);
    assert_eq!(doorbell_offset(1, false, 0), 0x1008);
    assert_eq!(doorbell_offset(1, true, 0), 0x100c);
    assert_eq!(doorbell_offset(5, true, 0), 0x1000 + 11 * 4);
}

#[test]
fn doorbell_offsets_wide_stride() {
    // DSTRD 2: 16 bytes apart.
    assert_eq!(doorbell_offset(1, false, 2), 0x1000 + 2 * 16);
    assert_eq!(doorbell_offset(1, true, 2), 0x1000 + 3 * 16);
    assert_eq!(doorbell_offset(0, true, 5), 0x1000 + 128);
}

// ── Ring arithmetic ─────────────────────────────────────────────────────

#[test]
fn ring_next_wraps() {
    assert_eq!(ring_next(0, 4), 1);
    assert_eq!(ring_next(2, 4), 3);
    assert_eq!(ring_next(3, 4), 0);
    assert_eq!(ring_next(0, 1), 0);
}

#[test]
fn sq_full_leaves_one_slot() {
    assert!(!sq_full(0, 0, 4), "empty is not full");
    assert!(!sq_full(0, 2, 4));
    assert!(sq_full(0, 3, 4), "3 queued of 4 slots is full");
    assert!(sq_full(2, 1, 4), "wrapped: tail 1 behind head 2");
    assert!(!sq_full(2, 0, 4));
}

#[test]
fn sq_used_counts_across_the_wrap() {
    assert_eq!(sq_used(0, 0, 8), 0);
    assert_eq!(sq_used(2, 5, 8), 3);
    assert_eq!(sq_used(6, 1, 8), 3);
}

// ── Completion phase, against a fake controller ─────────────────────────

/// A completion queue the way a controller fills it: entries are written
/// with the lap's phase tag; the memory starts zeroed.
struct FakeCq {
    entries: Vec<Cqe>,
    post_at: u16,
    post_phase: bool,
}

impl FakeCq {
    fn new(depth: u16) -> Self {
        FakeCq { entries: vec![Cqe::default(); depth as usize], post_at: 0, post_phase: true }
    }
    fn post(&mut self, cid: u16, sq_head: u16) {
        let depth = self.entries.len() as u16;
        self.entries[self.post_at as usize] = Cqe {
            dw0: 0,
            dw1: 0,
            dw2: sq_head as u32 | 1 << 16,
            dw3: cid as u32 | (self.post_phase as u32) << 16,
        };
        self.post_at += 1;
        if self.post_at == depth {
            self.post_at = 0;
            self.post_phase = !self.post_phase;
        }
    }
}

fn reap(cq: &FakeCq, cur: &mut CqCursor, out: &mut Vec<u16>) {
    let depth = cq.entries.len() as u16;
    // At most one lap per call: a cursor that mistakes stale entries for new
    // ones must fail the test, not spin.
    for _ in 0..depth {
        if !cqe_is_new(&cq.entries[cur.head as usize], cur.phase) {
            break;
        }
        out.push(cq.entries[cur.head as usize].cid());
        cur.advance(depth);
    }
}

#[test]
fn zeroed_queue_has_no_new_entry() {
    let cq = FakeCq::new(4);
    let cur = CqCursor::new();
    assert!(!cqe_is_new(&cq.entries[0], cur.phase));
}

#[test]
fn cursor_tracks_phase_over_three_laps() {
    let depth = 4u16;
    let mut cq = FakeCq::new(depth);
    let mut cur = CqCursor::new();
    let mut seen = Vec::new();
    // 3 laps + 2: post 3 entries, reap them, repeat; stale entries from the
    // previous lap must not be read again.
    let mut cid = 100u16;
    for _ in 0..14 {
        cq.post(cid, 0);
        cid += 1;
        let mut got = Vec::new();
        reap(&cq, &mut cur, &mut got);
        assert_eq!(got.len(), 1, "exactly the one new entry at cid {cid}");
        seen.extend(got);
    }
    assert_eq!(seen, (100..114).collect::<Vec<u16>>());
    assert_eq!(cur.head, 14 % 4);
}

#[test]
fn cursor_reaps_a_burst_across_the_wrap() {
    let mut cq = FakeCq::new(4);
    let mut cur = CqCursor::new();
    let mut out = Vec::new();
    for c in 0..3 { cq.post(c, 0); }
    reap(&cq, &mut cur, &mut out);
    assert_eq!(out, vec![0, 1, 2]);
    for c in 3..6 { cq.post(c, 0); }
    reap(&cq, &mut cur, &mut out);
    assert_eq!(out, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(cur, CqCursor { head: 2, phase: false });
}

// ── Completion entries ──────────────────────────────────────────────────

#[test]
fn cqe_fields() {
    // SC=0x02, SCT=1 -> status 0x102; DNR set; CID 0x1234; P=1 (4.6.1).
    let dw3 = 0x1234 | 1 << 16 | (0x102u32) << 17 | 1 << 31;
    let c = Cqe { dw0: 7, dw1: 0, dw2: 5 | 3 << 16, dw3 };
    assert_eq!(c.cid(), 0x1234);
    assert!(c.phase());
    assert_eq!(c.status(), 0x102);
    assert_eq!(status_type(c.status()), 1);
    assert_eq!(status_code(c.status()), 2);
    assert!(!c.is_success());
    assert!(c.do_not_retry());
    assert_eq!(c.sq_head(), 5);
    assert_eq!(c.sq_id(), 3);
}

#[test]
fn cqe_success() {
    let c = Cqe { dw3: 9 | 1 << 16, ..Cqe::default() };
    assert!(c.is_success());
    assert!(!c.do_not_retry());
}

// ── Submission entries ──────────────────────────────────────────────────

#[test]
fn read_encoding() {
    let s = read_write(0x0102, 1, false, 0x1_2345_6789, 8, 0xaaaa_bbbb_cccc_d000, 0x1_0000_2000);
    let d = s.0;
    assert_eq!(d[0], 0x0102_0002, "opcode 2 (read), CID in 31:16, FUSE/PSDT 0");
    assert_eq!(d[1], 1);
    assert_eq!((d[6], d[7]), (0xcccc_d000, 0xaaaa_bbbb));
    assert_eq!((d[8], d[9]), (0x0000_2000, 1));
    assert_eq!((d[10], d[11]), (0x2345_6789, 1));
    assert_eq!(d[12], 7, "NLB is 0-based: 8 sectors -> 7");
    assert_eq!(s.opcode(), OP_NVM_READ);
    assert_eq!(s.cid(), 0x0102);
    assert_eq!(s.prp1(), 0xaaaa_bbbb_cccc_d000);
    assert_eq!(s.prp2(), 0x1_0000_2000);
    assert_eq!(s.slba(), 0x1_2345_6789);
    assert_eq!(s.nlb_field(), 7);
}

#[test]
fn write_encoding_and_max_count() {
    let s = read_write(3, 1, true, 0, 65536, 0x1000, 0);
    assert_eq!(s.opcode(), OP_NVM_WRITE);
    assert_eq!(s.0[12], 0xffff, "65536 sectors -> NLB 0xffff");
    let one = read_write(3, 1, true, 0, 1, 0x1000, 0);
    assert_eq!(one.0[12], 0, "one sector -> NLB 0");
}

#[test]
fn flush_encoding() {
    let s = flush(9, 1);
    assert_eq!(s.0[0], 9 << 16, "flush is opcode 0");
    assert_eq!(s.0[1], 1);
    assert!(s.0[2..].iter().all(|&d| d == 0));
}

/// FUA is CDW12 bit 30 and nothing else moves (the block count is below it).
#[test]
fn fua_sets_cdw12_bit_30_only() {
    let w = read_write(3, 1, true, 0x1_0000_0002, 8, 0x1000, 0);
    let f = with_fua(w);
    assert_eq!(f.0[12], w.0[12] | 1 << 30);
    assert_eq!(f.0[12] & 0xffff, 7, "NLB intact");
    for i in (0..16).filter(|&i| i != 12) {
        assert_eq!(f.0[i], w.0[i], "dword {i}");
    }
}

#[test]
fn dataset_management_deallocate_encoding() {
    let s = dataset_management_deallocate(5, 1, 3, 0x8000_3000);
    assert_eq!(s.opcode(), OP_NVM_DSM);
    assert_eq!((s.cid(), s.nsid()), (5, 1));
    assert_eq!(s.prp1(), 0x8000_3000);
    assert_eq!(s.prp2(), 0);
    assert_eq!(s.0[10], 2, "NR is 0-based");
    assert_eq!(s.0[11], 4, "AD only");
    let r = dsm_range(0x1_0000_0010, 0x400);
    assert_eq!(&r[0..4], &[0, 0, 0, 0], "no context attributes");
    assert_eq!(u32::from_le_bytes([r[4], r[5], r[6], r[7]]), 0x400);
    assert_eq!(u64::from_le_bytes(r[8..16].try_into().unwrap()), 0x1_0000_0010);
}

#[test]
fn identify_encoding() {
    let s = identify(1, 0, CNS_CONTROLLER, 0x8000_1000);
    assert_eq!(s.0[0], 1 << 16 | 0x06);
    assert_eq!(s.0[10], 1);
    assert_eq!(s.prp1(), 0x8000_1000);
    let n = identify(2, 1, CNS_NAMESPACE, 0x8000_2000);
    assert_eq!((n.0[1], n.0[10]), (1, 0));
}

#[test]
fn queue_creation_encoding() {
    // 5.4: CDW10 = QSIZE (0-based) << 16 | QID; CDW11 CQ: IV << 16 | IEN << 1 | PC.
    let cq = create_io_cq(4, 1, 32, 0x9000, 1, true);
    assert_eq!(cq.0[0], 4 << 16 | 0x05);
    assert_eq!(cq.0[10], 31 << 16 | 1);
    assert_eq!(cq.0[11], 1 << 16 | 1 << 1 | 1);
    assert_eq!(cq.prp1(), 0x9000);
    let polled = create_io_cq(4, 1, 32, 0x9000, 0, false);
    assert_eq!(polled.0[11], 1, "polled: PC only");
    // 5.5: CDW11 SQ: CQID << 16 | QPRIO << 1 | PC.
    let sq = create_io_sq(5, 1, 32, 0xa000, 1);
    assert_eq!(sq.0[0], 5 << 16 | 0x01);
    assert_eq!(sq.0[10], 31 << 16 | 1);
    assert_eq!(sq.0[11], 1 << 16 | 1);
    assert_eq!(sq.prp1(), 0xa000);
}

#[test]
fn delete_and_features_encoding() {
    assert_eq!(delete_io_sq(1, 1).0[0], 1 << 16);
    assert_eq!(delete_io_sq(1, 1).0[10], 1);
    assert_eq!(delete_io_cq(1, 1).0[0], 1 << 16 | 0x04);
    // 5.21.1.7: NCQR << 16 | NSQR, both 0-based.
    let f = set_number_of_queues(2, 4, 2);
    assert_eq!(f.0[0], 2 << 16 | 0x09);
    assert_eq!(f.0[10], 0x07);
    assert_eq!(f.0[11], 1 << 16 | 3);
}

#[test]
fn sqe_bytes_are_little_endian_dwords() {
    let s = read_write(0x0102, 1, false, 0x1122_3344_5566_7788, 1, 0xdead_beef_0000_1000, 0);
    let b = s.to_bytes();
    assert_eq!(&b[0..4], &[0x02, 0x00, 0x02, 0x01]);
    assert_eq!(&b[24..32], &0xdead_beef_0000_1000u64.to_le_bytes(), "PRP1 at bytes 24..32");
    assert_eq!(&b[40..48], &0x1122_3344_5566_7788u64.to_le_bytes(), "SLBA at bytes 40..48");
    assert_eq!(b.len(), SQE_BYTES);
}

// ── PRPs ────────────────────────────────────────────────────────────────

fn pages(n: usize) -> Vec<u64> {
    // Deliberately scattered: PRP pages need not be contiguous.
    (0..n).map(|i| 0x8000_0000 + ((n - i) as u64) * 0x3000).collect()
}

#[test]
fn pages_spanned_cases() {
    assert_eq!(pages_spanned(0, 0), 0);
    assert_eq!(pages_spanned(0, 1), 1);
    assert_eq!(pages_spanned(0, 4096), 1);
    assert_eq!(pages_spanned(0, 4097), 2);
    assert_eq!(pages_spanned(0xe00, 0x400), 2);
    assert_eq!(pages_spanned(0xe00, 0x200), 1);
    assert_eq!(pages_spanned(0, 32 * 1024), 8);
}

#[test]
fn prp_one_page_has_no_prp2() {
    let p = pages(1);
    let mut list = [0u64; 8];
    assert_eq!(build_prps(&p, 0x200, 512, 0xdead000, &mut list), Ok((p[0] + 0x200, 0)));
    assert_eq!(list, [0; 8], "no list written");
}

#[test]
fn prp_two_pages_put_the_second_in_prp2() {
    let p = pages(2);
    let mut list = [0u64; 8];
    assert_eq!(build_prps(&p, 0xe00, 0x400, 0xdead000, &mut list), Ok((p[0] + 0xe00, p[1])));
    assert_eq!(list, [0; 8], "two pages need no list");
}

#[test]
fn prp_many_pages_use_a_list() {
    let p = pages(8);
    let mut list = [0u64; 16];
    let (prp1, prp2) = build_prps(&p, 0, 32 * 1024, 0xdead000, &mut list).unwrap();
    assert_eq!(prp1, p[0]);
    assert_eq!(prp2, 0xdead000, "PRP2 names the list, not a data page");
    assert_eq!(&list[..7], &p[1..8], "the list holds pages 1..8 in order");
    assert_eq!(list[7], 0);
}

#[test]
fn prp_partial_last_page_still_counts() {
    let p = pages(3);
    let mut list = [0u64; 4];
    let (_, prp2) = build_prps(&p, 0, 2 * 4096 + 1, 0xbeef000, &mut list).unwrap();
    assert_eq!(prp2, 0xbeef000);
    assert_eq!(&list[..2], &p[1..3]);
}

#[test]
fn prp_rejects_bad_shapes() {
    let p = pages(4);
    let mut list = [0u64; 2];
    assert_eq!(build_prps(&p, 0, 0, 0, &mut list), Err(PrpError::BadShape));
    assert_eq!(build_prps(&p, 4096, 16, 0, &mut list), Err(PrpError::BadShape));
    assert_eq!(build_prps(&p[..1], 0, 8192, 0, &mut list), Err(PrpError::BadShape));
    assert_eq!(build_prps(&p, 0, 4 * 4096, 0, &mut list), Err(PrpError::ListTooSmall));
    let mut bad = pages(3);
    bad[2] += 8;
    assert_eq!(build_prps(&bad, 0, 3 * 4096, 0, &mut [0u64; 4]), Err(PrpError::Unaligned));
    assert_eq!(prp_list_entries(1), 0);
    assert_eq!(prp_list_entries(2), 0);
    assert_eq!(prp_list_entries(8), 7);
}

// ── Identify ────────────────────────────────────────────────────────────

#[test]
fn controller_decode() {
    let mut id = [0u8; 4096];
    id[516..520].copy_from_slice(&3u32.to_le_bytes());
    id[77] = 5;
    id[525] = 1;
    let c = decode_controller(&id);
    assert_eq!(c, Controller { namespaces: 3, mdts: 5, volatile_write_cache: true, dataset_management: false });
    id[520] = 1 << 2;
    assert!(decode_controller(&id).dataset_management, "ONCS bit 2");
    id[520] = !(1 << 2);
    assert!(!decode_controller(&id).dataset_management, "any other ONCS bit is not DSM");
    assert_eq!(mdts_max_sectors(5), 256, "8 sectors << 5 = 128 KiB");
    assert_eq!(mdts_max_sectors(0), u32::MAX);
    id[525] = 0;
    assert!(!decode_controller(&id).volatile_write_cache);
}

#[test]
fn namespace_decode_follows_the_formatted_lba_format() {
    let mut id = [0u8; 4096];
    id[0..8].copy_from_slice(&0x2_0000u64.to_le_bytes());
    // Format 0: 512 B (LBADS 9); format 1: 4096 B + 8 B metadata. FLBAS selects 1.
    id[128..132].copy_from_slice(&(9u32 << 16).to_le_bytes());
    id[132..136].copy_from_slice(&(12u32 << 16 | 8).to_le_bytes());
    id[26] = 1;
    let n = decode_namespace(&id);
    assert_eq!(n, Namespace { blocks: 0x2_0000, lba_shift: 12, metadata_bytes: 8 });
    id[26] = 0;
    assert_eq!(decode_namespace(&id).lba_shift, 9);
}

#[test]
fn granted_queues_are_zero_based_in_the_completion() {
    assert_eq!(granted_queues(0x0001_0003), (4, 2));
    assert_eq!(granted_queues(0), (1, 1));
}
