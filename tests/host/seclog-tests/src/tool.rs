// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The forensic tool's own tests: files laid out as `logd` writes them (the
//! opening `file N` line, kernel log lines around the `@security` ones, the
//! seam), handed over out of order, with and without what a reader off the
//! device brings.

use super::{seam, tpm_boot, Boot};
use azos_seclog::{kind, Backend, Class, Seal};
use seclog_verify::{parse_witness, render, verify, Options, Verdict};

#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;

fn put(out: &mut Vec<u8>, seq: u64, module: &str, msg: &[u8]) {
    let mut b = [0u8; wire::LINE_MAX];
    let n = wire::line_of(seq, 1000, 1_000_000, 0, wire::LEVEL_INFO, false, module.as_bytes(), msg, &mut b);
    out.extend_from_slice(&b[..n]);
}

/// A file of serial `serial` holding the security lines `msgs` (a seam is a
/// `logd` line), each after a kernel log line.
fn file(serial: u64, msgs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut head = [0u8; 24];
    let n = wire::file_head(serial, &mut head);
    put(&mut out, 0, "logd", &head[..n]);
    for (i, m) in msgs.iter().enumerate() {
        put(&mut out, i as u64, "kernel", b"some kernel line");
        let seq = match azos_seclog::text::parse(m) {
            Some(azos_seclog::text::Parsed::Record { env, .. }) => env.seq,
            _ => 0,
        };
        let module = if m == &seam() { "logd" } else { "@security" };
        put(&mut out, seq, module, m);
    }
    out
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// The console lines the kernel prints for a boot's seals.
fn console(b: &Boot) -> String {
    b.recs
        .iter()
        .filter(|r| r.env.kind == kind::SEAL)
        .map(|r| {
            let s = Seal::decode(&r.payload).unwrap();
            format!(
                "seclog: seal {} through {} counter {} nonce {:016x} head {} anchor {} tpm-nv\n",
                s.count,
                s.through,
                s.counter,
                s.nonce,
                hex(&s.head),
                hex(&s.anchor)
            )
        })
        .collect()
}

fn export() -> (Boot, Vec<Vec<u8>>) {
    let b1 = tpm_boot([0; 32], 2);
    let b2 = tpm_boot(b1.tpm, 2);
    let mut second = vec![seam()];
    second.extend(b2.lines());
    // Handed over newest first: the order is the files' serials.
    (b2, vec![file(2, &second), file(1, &b1.lines())])
}

#[test]
fn tool_a_whole_export_matching_the_live_tpm_is_intact() {
    let (b2, files) = export();
    let r = verify(&files, &Options { tpm_anchor: Some(b2.tpm), tpm_counter: Some(b2.counter), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Intact, "{}", render(&r));
    assert_eq!((r.summary.boots, r.summary.seals, r.summary.seals_verified), (2, 4, 4));
}

#[test]
fn tool_without_an_off_device_check_says_it_is_not_anchored() {
    let (_, files) = export();
    let r = verify(&files, &Options::default());
    assert_eq!(r.verdict, Verdict::Incomplete);
    assert!(render(&r).contains("not anchored"));
}

#[test]
fn tool_a_forgery_consistent_with_itself_is_refuted_by_the_live_tpm() {
    let real = tpm_boot([0; 32], 2);
    let mut forged = Boot::new(Backend::TpmNv, [0; 32]);
    forged.event(Class::Camera, 7);
    forged.seal();
    let files = vec![file(1, &forged.lines())];
    assert_eq!(verify(&files, &Options::default()).summary.evidence, 0, "offline it holds together");
    let r = verify(&files, &Options { tpm_anchor: Some(real.tpm), tpm_counter: Some(real.counter), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Evidence);
    assert!(r.external[0].starts_with("tpm:"), "{:?}", r.external);
}

#[test]
fn tool_a_seal_the_console_showed_and_the_export_lacks_is_evidence() {
    let b = tpm_boot([0; 32], 3);
    let witness = parse_witness(&console(&b));
    assert_eq!(witness.len(), 3);
    let whole = vec![file(1, &b.lines())];
    assert_eq!(verify(&whole, &Options { tpm_anchor: None, tpm_counter: None, witness: witness.clone() }).verdict, Verdict::Intact);
    // The tail cut after the second seal (record 10): the third is gone.
    let cut = vec![file(1, &b.lines()[..11])];
    let r = verify(&cut, &Options { tpm_anchor: None, tpm_counter: None, witness });
    assert_eq!(r.verdict, Verdict::Evidence, "{}", render(&r));
    assert!(r.external[0].starts_with("witness:"));
}

#[test]
fn tool_finds_the_tampering_inside_files() {
    let (b2, mut files) = export();
    let mut lines: Vec<&[u8]> = files[1].split(|&b| b == b'\n').collect();
    lines.remove(6);
    files[1] = lines.join(&b'\n');
    let r = verify(&files, &Options { tpm_anchor: Some(b2.tpm), tpm_counter: Some(b2.counter), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Evidence);
    assert!(render(&r).contains("EVIDENCE: boot 1: 1 records from"), "{}", render(&r));
}

#[test]
fn tool_reads_only_witness_lines_of_the_kernels_form() {
    let h = "ab".repeat(32);
    let text = format!(
        "seclog: seal 1 through 4 counter 3 nonce 00000000000000ff head {h} anchor {h} tpm-nv\n\
         x seclog: seal 1 through 4 counter 3 nonce 00000000000000ff head {h} anchor {h} tpm-nv\n\
         seclog: seal 2 through 9 counter 4 nonce 00000000000000ff head zz anchor {h}\nnoise\n"
    );
    let w = parse_witness(&text);
    assert_eq!(w.len(), 1);
    assert_eq!((w[0].count, w[0].nonce), (1, 0xff));
}

/// A file removed between two the export has: the serials say so.
#[test]
fn tool_a_file_missing_between_two_is_evidence() {
    let (b2, mut files) = export();
    let b3 = tpm_boot(b2.tpm, 1);
    let mut third = vec![seam()];
    third.extend(b3.lines());
    files.push(file(4, &third));
    let r = verify(&files, &Options { tpm_anchor: Some(b3.tpm), tpm_counter: Some(b3.counter), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Evidence, "{}", render(&r));
    assert!(r.external.iter().any(|e| e.starts_with("files: serial 3 to 3")), "{:?}", r.external);
}

/// The live counter is past the export's last seal: seals were cut, even
/// when the anchor index was reset and replayed to the export's last value.
#[test]
fn tool_a_replayed_anchor_is_refuted_by_the_live_counter() {
    let (b2, files) = export();
    let r = verify(&files, &Options { tpm_anchor: Some(b2.tpm), tpm_counter: Some(b2.counter + 2), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Evidence, "{}", render(&r));
}

/// The TPM took a seal and the boot ended before logd wrote its record: the
/// live values are that seal's, which the export's last records give.
#[test]
fn tool_a_seal_a_crash_lost_matches_the_live_tpm() {
    let mut b = tpm_boot([0; 32], 2);
    b.event(Class::Usb, 9);
    let before = b.recs.len();
    b.seal();
    let file1 = file(1, &b.lines()[..before]);
    let r = verify(&[file1], &Options { tpm_anchor: Some(b.tpm), tpm_counter: Some(b.counter), witness: vec![] });
    assert_eq!(r.verdict, Verdict::Incomplete, "{}", render(&r));
    assert!(r.notes.iter().any(|n| n.contains("a crash lost")), "{:?}", r.notes);
}
