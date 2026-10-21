// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! WKdm on synthetic pages of every supported size: round trip, ratio per
//! data shape, the zero-page fast path, buffer limits and corrupted streams.

mod common;
use azos_crypto::wkdm::*;
use common::Rng;

const SIZES: [usize; 3] = [4096, 16384, 65536];

fn words(page: &mut [u8], f: impl FnMut(usize) -> u32) {
    let mut f = f;
    for (i, c) in page.chunks_exact_mut(4).enumerate() {
        c.copy_from_slice(&f(i).to_le_bytes());
    }
}

/// Round trip; returns the compressed length (0 = zero page, usize::MAX =
/// incompressible).
fn round_trip(page: &[u8]) -> usize {
    let mut out = vec![0xCDu8; page.len()];
    match compress(page, &mut out) {
        Ok(n) => {
            assert!(n < page.len());
            let mut back = vec![0x5Au8; page.len()];
            decompress(&out[..n], &mut back).unwrap();
            assert!(back == page, "round trip mismatch (size {})", page.len());
            // Exact-fit buffer works, one byte less does not.
            if n > 0 {
                let mut exact = vec![0u8; n];
                assert_eq!(compress(page, &mut exact), Ok(n));
                assert_eq!(&exact[..], &out[..n], "output independent of spare capacity");
                let mut short = vec![0u8; n - 1];
                assert_eq!(compress(page, &mut short), Err(Error::Incompressible));
            }
            n
        }
        Err(Error::Incompressible) => usize::MAX,
        Err(e) => panic!("{e:?}"),
    }
}

#[test]
fn zero_page_costs_nothing() {
    for sz in SIZES {
        let page = vec![0u8; sz];
        assert_eq!(compress(&page, &mut []), Ok(0));
        let mut back = vec![0xFFu8; sz];
        decompress(&[], &mut back).unwrap();
        assert!(back.iter().all(|&b| b == 0));
    }
}

#[test]
fn single_nonzero_byte_is_not_mistaken_for_zero() {
    for sz in SIZES {
        for pos in [0, 1, sz / 2, sz - 1] {
            let mut page = vec![0u8; sz];
            page[pos] = 1;
            let n = round_trip(&page);
            assert!(n != 0 && n != usize::MAX);
            assert!(n < 16 + sz / 16 + 8 + 16, "one word: header + tags + 1 miss");
        }
    }
}

#[test]
fn small_integers_compress_hard() {
    for sz in SIZES {
        let mut page = vec![0u8; sz];
        let mut rng = Rng(7);
        words(&mut page, |_| (rng.next() % 1000) as u32);
        let n = round_trip(&page);
        assert!(n < sz * 6 / 10, "size {sz}: {n} bytes");
    }
}

#[test]
fn pointer_like_words_compress() {
    for sz in SIZES {
        let mut page = vec![0u8; sz];
        let mut rng = Rng(11);
        // 64-bit pointers into one 4 MiB region: constant high word, a low
        // word that shares its upper bits with recent ones.
        words(&mut page, |i| {
            if i % 2 == 1 {
                0x0000_7fff
            } else {
                0xdead_0000 | ((rng.next() % 64) as u32 * 16)
            }
        });
        let n = round_trip(&page);
        assert!(n < sz / 2, "size {sz}: {n} bytes");
    }
}

#[test]
fn repeated_and_mostly_zero_pages() {
    for sz in SIZES {
        let mut page = vec![0u8; sz];
        words(&mut page, |i| if i % 8 == 0 { 0xcafe_f00d } else { 0 });
        let n = round_trip(&page);
        assert!(n < sz / 8, "size {sz}: {n} bytes");

        words(&mut page, |_| 0x1234_5678);
        let n = round_trip(&page);
        assert!(n < sz / 5, "size {sz}: {n} bytes");

        // A sparse page: every 64th word non-zero and unique.
        words(&mut page, |i| if i % 64 == 0 { 0x8000_0000 | (i as u32) << 6 } else { 0 });
        assert!(round_trip(&page) < sz / 10);
    }
}

#[test]
fn random_pages_are_reported_incompressible() {
    for sz in SIZES {
        let mut page = vec![0u8; sz];
        let mut rng = Rng(99);
        for b in page.iter_mut() {
            *b = rng.next() as u8;
        }
        assert_eq!(round_trip(&page), usize::MAX);
        // Even with a generous buffer: contract is "smaller than the page".
        let mut out = vec![0u8; sz * 2];
        assert_eq!(compress(&page, &mut out), Err(Error::Incompressible));
    }
}

#[test]
fn dictionary_conflicts_and_partial_matches_round_trip() {
    // Words crafted to share slots: same upper 22 bits (partial hits), same
    // slot different upper bits (replacement), and alternation between them.
    for sz in SIZES {
        let mut page = vec![0u8; sz];
        let mut rng = Rng(5);
        words(&mut page, |i| match i % 5 {
            0 => 0xabcd_e000 | (rng.next() as u32 & 0x3ff),
            1 => 0xabcd_e000,
            2 => (rng.next() as u32) | 1,
            3 => 0xabcd_e000 | (rng.next() as u32 & 0x3ff),
            _ => 0xffff_ffff,
        });
        round_trip(&page);
    }
}

#[test]
fn every_word_pattern_boundary_round_trips() {
    // 0, 1, 0x3ff (all low bits), 0x400 (first high bit), 0xffffffff.
    let vals = [0u32, 1, 0x3ff, 0x400, 0x401, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];
    let mut rng = Rng(3);
    for sz in SIZES {
        for _ in 0..8 {
            let mut page = vec![0u8; sz];
            words(&mut page, |_| vals[(rng.next() % 8) as usize]);
            round_trip(&page);
        }
    }
}

#[test]
fn compress_is_deterministic() {
    let mut page = vec![0u8; 4096];
    let mut rng = Rng(1);
    words(&mut page, |_| (rng.next() % 50) as u32);
    let (mut a, mut b) = (vec![0u8; 4096], vec![0xFFu8; 4096]);
    let n = compress(&page, &mut a).unwrap();
    assert_eq!(compress(&page, &mut b), Ok(n));
    assert_eq!(a[..n], b[..n]);
}

#[test]
fn bad_sizes_are_refused() {
    for sz in [0usize, 1, 64, 4095, 4097, 8192, 32768, 131072] {
        let page = vec![1u8; sz];
        assert_eq!(compress(&page, &mut [0u8; 8192]), Err(Error::BadPageSize), "{sz}");
        assert_eq!(decompress(&[], &mut vec![0u8; sz]), Err(Error::BadPageSize), "{sz}");
    }
    assert!(is_page_size(4096) && is_page_size(16384) && is_page_size(65536));
}

#[test]
fn truncated_and_inconsistent_streams_are_malformed() {
    let mut page = vec![0u8; 4096];
    let mut rng = Rng(2);
    words(&mut page, |i| if i % 3 == 0 { (rng.next() % 40) as u32 } else { 0x0001_0000 | (rng.next() as u32 & 0x3ff) });
    let mut out = vec![0u8; 4096];
    let n = compress(&page, &mut out).unwrap();
    assert!(n > 0);
    let stream = out[..n].to_vec();
    let mut back = vec![0u8; 4096];
    // Every proper prefix is rejected (the end word no longer matches).
    for cut in 1..n {
        assert_eq!(decompress(&stream[..cut], &mut back), Err(Error::Malformed), "cut {cut}");
    }
    // Trailing garbage is rejected too.
    let mut longer = stream.clone();
    longer.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(decompress(&longer, &mut back), Err(Error::Malformed));
    // Decoding into a page of another size is rejected via the word count.
    assert_eq!(decompress(&stream, &mut vec![0u8; 16384]), Err(Error::Malformed));
}

#[test]
fn corrupted_streams_never_panic_or_overrun() {
    let mut page = vec![0u8; 4096];
    let mut rng = Rng(8);
    words(&mut page, |i| if i % 4 == 0 { (rng.next() % 200) as u32 } else { 0x00ab_0000 | (rng.next() as u32 & 0x3ff) });
    let mut out = vec![0u8; 4096];
    let n = compress(&page, &mut out).unwrap();
    let stream = out[..n].to_vec();
    let mut back = vec![0u8; 4096];
    let mut seen_err = 0;
    for _ in 0..4000 {
        let mut s = stream.clone();
        for _ in 0..1 + rng.next() % 3 {
            let at = (rng.next() as usize) % s.len();
            s[at] ^= 1 << (rng.next() % 8);
        }
        // Any outcome but a panic is acceptable; most flips are caught.
        if decompress(&s, &mut back).is_err() {
            seen_err += 1;
        }
    }
    assert!(seen_err > 500, "header/tag corruption must be detected often: {seen_err}");
}
