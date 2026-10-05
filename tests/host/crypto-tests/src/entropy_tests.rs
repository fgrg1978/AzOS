// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel entropy pool (`crates/core/crypto/src/entropy.rs`).
//!
//! What must hold for the consumers' fallback to be honest: the pool writes
//! nothing until credited bytes seed it, its output moves on every fill, and
//! a reseed changes what comes next. The DRBG itself is pinned against an
//! independent implementation, so a transposed HMAC argument cannot pass as
//! "output looks random".

use azos_crypto::entropy::{
    self, hmac_sha256, Pool, MAX_REQUEST_BYTES, RESEED_BYTES, SEED_BYTES,
    seed_file_encode, seed_file_decode, SEED_FILE_BYTES, SEED_FILE_SEED_BYTES,
    SeedLoad, SeedTail, seed_tail_check,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn key32(k: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..k.len()].copy_from_slice(k);
    out
}

fn seeded_pool(seed_byte: u8) -> Pool {
    let mut p = Pool::new();
    p.mix(&[seed_byte; SEED_BYTES], true);
    assert!(p.seeded());
    p
}

/// RFC 4231 §4.2 and §4.3 (test cases 1 and 2). Keys shorter than 32 bytes
/// zero-padded to 32 give the same MAC (RFC 2104 pads to the block anyway).
#[test]
fn hmac_matches_rfc4231() {
    assert_eq!(
        hmac_sha256(&key32(&[0x0b; 20]), &[b"Hi There"]).to_vec(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    assert_eq!(
        hmac_sha256(&key32(b"Jefe"), &[b"what do ya ", b"want for nothing?"]).to_vec(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

/// HMAC_DRBG SHA-256, no reseed, no personalization, no additional input:
/// instantiate with entropy || nonce, generate 1024 bits twice, keep the
/// second. The expected bytes were reproduced by an independent
/// implementation of SP 800-90A §10.1.2 over Python's `hmac`/`hashlib`.
#[test]
fn drbg_matches_an_independent_implementation() {
    let mut seed = hex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
    seed.extend(hex("659ba96c601dc69fc902940805ec0ca8"));
    assert_eq!(seed.len(), SEED_BYTES);
    let mut p = Pool::new();
    p.mix(&seed, true);
    let mut out = [0u8; 128];
    assert!(p.fill(&mut out));
    assert!(p.fill(&mut out));
    assert_eq!(out.to_vec(), hex(
        "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89\
         d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1\
         07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668\
         961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8"));
}

/// **Unseeded writes nothing.** Uncredited input — however much — and one
/// credited byte short of the seed must both leave `fill` refusing with the
/// buffer untouched: the consumers' fallback depends on that `false`.
#[test]
fn the_pool_is_unseeded_until_credited_bytes_are_mixed() {
    let mut p = Pool::new();
    let mut out = [0xAAu8; 32];
    assert!(!p.seeded());
    assert!(!p.fill(&mut out));
    p.mix(&[0x55; 4096], false);
    assert!(!p.fill(&mut out), "uncredited input must not seed the pool");
    p.mix(&[0x11; SEED_BYTES - 1], true);
    assert!(!p.fill(&mut out), "one credited byte short must not seed the pool");
    assert_eq!(out, [0xAAu8; 32], "an unseeded fill wrote into the buffer");
    p.mix(&[0x22], true);
    assert!(p.fill(&mut out), "{SEED_BYTES} credited bytes, in two calls, must seed");
    assert_ne!(out, [0xAAu8; 32]);
}

/// The same property on the kernel's global instance — the one the consumers
/// reach. The only test in this binary that touches it.
#[test]
fn the_global_pool_is_unseeded_until_mixed() {
    let mut out = [0u8; 16];
    assert!(!entropy::seeded());
    assert!(!entropy::fill(&mut out));
    assert_eq!(out, [0u8; 16]);
    entropy::mix(&[0x42; SEED_BYTES], true);
    assert!(entropy::seeded());
    assert!(entropy::fill(&mut out));
    assert_ne!(out, [0u8; 16]);
}

/// **Consecutive fills differ**, and so do pools seeded differently. A
/// generator that did not advance its state would hand every consumer the
/// same "random" bytes: the same DHCP xid, the same ephemeral key.
#[test]
fn fills_differ() {
    let mut p = seeded_pool(1);
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    assert!(p.fill(&mut a));
    assert!(p.fill(&mut b));
    assert_ne!(a, b, "two fills from one pool returned the same bytes");
    let mut q = seeded_pool(2);
    let mut c = [0u8; 32];
    assert!(q.fill(&mut c));
    let mut r = seeded_pool(1);
    let mut d = [0u8; 32];
    assert!(r.fill(&mut d));
    assert_ne!(a, c, "different seeds gave the same output");
    assert_eq!(a, d, "the same seed must give the same output (determinism)");
}

/// **A reseed changes what comes next.** Two pools in the same state produce
/// the same bytes; credited input into one of them must split the streams.
/// An uncredited mix must split them too — it is still input to the state.
#[test]
fn reseed_changes_output() {
    let (mut p, mut q) = (seeded_pool(7), seeded_pool(7));
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    assert!(p.fill(&mut a) && q.fill(&mut b));
    assert_eq!(a, b);
    q.mix(&[0x99; RESEED_BYTES], true);
    assert!(p.fill(&mut a) && q.fill(&mut b));
    assert_ne!(a, b, "a credited reseed did not change the output");
    assert!(q.seeded());

    let (mut p, mut q) = (seeded_pool(8), seeded_pool(8));
    q.mix(b"mac 52:54:00:12:34:56", false);
    assert!(p.fill(&mut a) && q.fill(&mut b));
    assert_ne!(a, b, "an uncredited mix did not change the output");
}

/// A request longer than `MAX_REQUEST_BYTES` is split into generate calls:
/// it must equal two consecutive requests from an identical pool, so the
/// tail runs on the updated state and is output, not leftover zeros.
#[test]
fn a_long_fill_is_split_into_requests() {
    let (mut p, mut q) = (seeded_pool(3), seeded_pool(3));
    let mut long = vec![0u8; MAX_REQUEST_BYTES + 100];
    let mut one = vec![0u8; MAX_REQUEST_BYTES];
    let mut next = [0u8; 100];
    assert!(p.fill(&mut long));
    assert!(q.fill(&mut one) && q.fill(&mut next));
    assert_eq!(&long[..MAX_REQUEST_BYTES], &one[..]);
    assert_eq!(&long[MAX_REQUEST_BYTES..], &next[..],
               "a long fill must be exactly consecutive generate requests");
    assert_ne!(&next[..], &one[..100], "the second request restarted the stream");
}

// ── U09-8 persisted seed file (owner decision 2026-09-26 V1.2) ────────────

#[test]
fn seed_file_roundtrips() {
    let seed = [0x7Au8; SEED_FILE_SEED_BYTES];
    let mut buf = [0u8; SEED_FILE_BYTES];
    let n = seed_file_encode(&seed, &mut buf);
    assert_eq!(n, SEED_FILE_BYTES);
    assert_eq!(seed_file_decode(&buf), Some(seed));
}

#[test]
fn seed_file_survives_trailing_padding() {
    // On-disk it lives in a 512-byte sector; only the first SEED_FILE_BYTES
    // are meaningful. A decoder that requires an exact-length buffer would
    // reject every real on-disk read.
    let seed = [0x11u8; SEED_FILE_SEED_BYTES];
    let mut sector = [0xFFu8; 512]; // pretend the rest of the sector is old data
    let n = seed_file_encode(&seed, &mut sector);
    assert_eq!(n, SEED_FILE_BYTES);
    assert_eq!(seed_file_decode(&sector), Some(seed));
}

/// **A torn or absent write must read back as "no seed", never as zero
/// bytes credited as if they were real entropy.**
///
/// RED without the tag check: decode the first `SEED_FILE_BYTES` of an
/// all-zero (freshly erased / never-written) sector unconditionally and
/// this test's first assertion fails — an erased sector would silently
/// "decode" as a valid zero seed.
#[test]
fn an_unwritten_or_corrupt_sector_decodes_as_no_seed() {
    let erased = [0u8; 512];
    assert_eq!(seed_file_decode(&erased), None,
        "an erased sector must not decode as a valid (zero) seed");

    let seed = [0x22u8; SEED_FILE_SEED_BYTES];
    let mut buf = [0u8; SEED_FILE_BYTES];
    seed_file_encode(&seed, &mut buf);

    // Torn write: only the first half landed (power loss mid-sector-write).
    let mut torn = buf;
    torn[SEED_FILE_BYTES / 2..].fill(0);
    assert_eq!(seed_file_decode(&torn), None, "a torn write must not decode");

    // One flipped bit in the seed itself must also be caught (the tag
    // covers the seed, not just magic/version).
    let mut flipped = buf;
    flipped[10] ^= 1;
    assert_eq!(seed_file_decode(&flipped), None,
        "the integrity tag must cover the seed bytes, not just the header");
}

#[test]
fn wrong_magic_or_version_is_rejected() {
    let seed = [0x33u8; SEED_FILE_SEED_BYTES];
    let mut buf = [0u8; SEED_FILE_BYTES];
    seed_file_encode(&seed, &mut buf);

    let mut bad_magic = buf;
    bad_magic[0] = b'X';
    assert_eq!(seed_file_decode(&bad_magic), None);

    let mut bad_version = buf;
    bad_version[4] = 2;
    assert_eq!(seed_file_decode(&bad_version), None);
}

// ── Persisted seed: load, rotate, and where it may be written (ENTSEED) ───

fn record_with(seed_byte: u8) -> [u8; SEED_FILE_BYTES] {
    let mut rec = [0u8; SEED_FILE_BYTES];
    seed_file_encode(&[seed_byte; SEED_FILE_SEED_BYTES], &mut rec);
    rec
}

/// A seed is wide enough to seed a pool on its own — the whole point of
/// crediting it when it is the only source.
#[test]
fn a_persisted_seed_alone_seeds_an_unseeded_pool() {
    assert!(SEED_FILE_SEED_BYTES >= SEED_BYTES);
    let mut p = Pool::new();
    let mut sector = [0u8; 512];
    sector[..SEED_FILE_BYTES].copy_from_slice(&record_with(0x5A));
    let r = p.apply_persisted_seed(&sector);
    assert_eq!(r.load, SeedLoad::Credited);
    assert!(p.seeded(), "the only source must be credited, or the pool never seeds");
    assert!(r.fresh.is_some());
}

/// Default taken: with another source already seeding the pool the file only
/// stirs (it is not credited). The credit has no other externally visible
/// effect than the verdict and the seeded flag, so this pins the verdict:
/// RED if the load credited unconditionally (`Credited` is reported).
#[test]
fn a_seeded_pool_only_stirs_the_persisted_seed() {
    let mut p = seeded_pool(1);
    let mut sector = [0u8; 512];
    sector[..SEED_FILE_BYTES].copy_from_slice(&record_with(0x5A));
    let r = p.apply_persisted_seed(&sector);
    assert_eq!(r.load, SeedLoad::Stirred);
    assert!(p.seeded());
}

#[test]
fn an_absent_or_corrupt_record_mixes_nothing_and_an_unseeded_pool_writes_nothing() {
    for sector in [[0u8; 512], [0xFFu8; 512]] {
        let mut p = Pool::new();
        let r = p.apply_persisted_seed(&sector);
        assert_eq!(r.load, SeedLoad::Absent);
        assert!(!p.seeded(), "an erased sector must not seed the pool");
        assert!(r.fresh.is_none(), "an unseeded pool has nothing honest to write");
    }
    // A seeded pool with no file still produces a record: this is how the
    // first boot on a volume provisions it.
    let mut p = seeded_pool(2);
    let r = p.apply_persisted_seed(&[0u8; 512]);
    assert_eq!(r.load, SeedLoad::Absent);
    assert!(r.fresh.is_some());
}

/// The mix is real: two pools identical except for the seed in the sector
/// then yield different pool output AND different replacement records.
/// RED if the seed were decoded but not mixed (same pool state, same record).
#[test]
fn the_persisted_seed_changes_the_pool_and_the_replacement() {
    let run = |b: u8| {
        let mut p = Pool::new();
        let mut sector = [0u8; 512];
        sector[..SEED_FILE_BYTES].copy_from_slice(&record_with(b));
        let r = p.apply_persisted_seed(&sector);
        let mut out = [0u8; 32];
        assert!(p.fill(&mut out));
        (r.fresh.unwrap(), out)
    };
    let (rec_a, out_a) = run(0x01);
    let (rec_b, out_b) = run(0x02);
    assert_ne!(rec_a, rec_b);
    assert_ne!(out_a, out_b);
    let (rec_a2, out_a2) = run(0x01);
    assert_eq!((rec_a, out_a), (rec_a2, out_a2), "the same seed is deterministic");
}

/// A seed is never used twice: the record that replaces it differs from it,
/// and feeding the replacement back (the next boot) differs again.
/// RED if the rotate step handed back the record it had just read.
#[test]
fn the_replacement_is_not_the_record_just_read_and_chains_forward() {
    let mut p = Pool::new();
    let first = record_with(0x77);
    let mut sector = [0u8; 512];
    sector[..SEED_FILE_BYTES].copy_from_slice(&first);
    let r1 = p.apply_persisted_seed(&sector).fresh.unwrap();
    assert_ne!(r1, first);
    assert!(seed_file_decode(&r1).is_some(), "the replacement must be a valid record");

    let mut p2 = Pool::new();
    sector[..SEED_FILE_BYTES].copy_from_slice(&r1);
    let r2 = p2.apply_persisted_seed(&sector).fresh.unwrap();
    assert_ne!(r2, r1);
    assert_ne!(r2, first);
}

/// What the consumers draw after the load is not the record on disk.
#[test]
fn consumers_draw_something_other_than_the_stored_seed() {
    let mut p = Pool::new();
    let mut sector = [0u8; 512];
    sector[..SEED_FILE_BYTES].copy_from_slice(&record_with(0x31));
    let rec = p.apply_persisted_seed(&sector).fresh.unwrap();
    let mut draw = [0u8; SEED_FILE_SEED_BYTES];
    assert!(p.fill(&mut draw));
    assert_ne!(&rec[5..5 + SEED_FILE_SEED_BYTES], &draw[..]);
}

fn fat32_sector0(tot32: u32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[11..13].copy_from_slice(&512u16.to_le_bytes());
    s[32..36].copy_from_slice(&tot32.to_le_bytes());
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

#[test]
fn the_tail_is_written_only_when_no_filesystem_reaches_it() {
    // The Makefile image: 65536-sector FAT32 volume + 8-sector tail.
    assert_eq!(seed_tail_check(65544, 8, &[], &fat32_sector0(65536)), SeedTail::Clear);
    // An image built without the headroom: the volume IS the whole medium.
    assert_eq!(seed_tail_check(65536, 8, &[], &fat32_sector0(65536)),
               SeedTail::FilesystemReaches);
    // One sector of overlap is still overlap.
    assert_eq!(seed_tail_check(65544, 8, &[], &fat32_sector0(65537)),
               SeedTail::FilesystemReaches);
    // Not a FAT32 boot sector and no table: no extent known.
    assert_eq!(seed_tail_check(65544, 8, &[], &[0u8; 512]), SeedTail::UnknownLayout);
    let mut fat16ish = fat32_sector0(65536);
    fat16ish[19..21].copy_from_slice(&100u16.to_le_bytes());
    assert_eq!(seed_tail_check(65544, 8, &[], &fat16ish), SeedTail::UnknownLayout);
    // Partitioned medium: every partition must end before the tail.
    assert_eq!(seed_tail_check(100_000, 8, &[(2048, 90_000)], &[]), SeedTail::Clear);
    assert_eq!(seed_tail_check(100_000, 8, &[(2048, 97_952)], &[]),
               SeedTail::FilesystemReaches);
    assert_eq!(seed_tail_check(100_000, 8, &[(2048, 1000), (50_000, 49_999)], &[]),
               SeedTail::FilesystemReaches);
    assert_eq!(seed_tail_check(8, 8, &[], &fat32_sector0(1)), SeedTail::TooSmall);
}
