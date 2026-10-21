// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_fb::edid`: the parser over EDID blobs, and over
//! blobs that are wrong.
//!
//! **About the blobs.** No display was attached to the machine these were
//! written on and nothing may be downloaded, so the five blobs below are not
//! captures of a particular monitor. They are laid out byte for byte as
//! EDID 1.3/1.4 and CTA-861 say, with the detailed-timing descriptors that
//! real displays carry for the modes they name (the CTA-861 1080p60, 720p60,
//! 480p60 and 4K timings, the VESA 1280x1024 and reduced-blanking 1920x1200
//! ones), a fictional vendor id (`AZT`) and invented product codes, checksums
//! sealed. The expectations are written from the specification, not from the
//! parser's output. A capture of a real display belongs next to these as a
//! sixth `const` (the harness takes any hex); until one is at hand, the claim
//! is "parses spec-conforming blobs", not "parses every monitor".

use azos_fb::edid::{parse, Edid, EdidError, Timing, BLOCK, MAX_MODES};

mod common;
use common::{hex, seal, FHD_1_3, SXGA_1_3, TV_1_3_CTA, UHD_1_4_CTA, WUXGA_RB_1_3};

fn t(width: u16, height: u16, hz: u32) -> Timing {
    Timing { width, height, refresh_mhz: hz * 1000 }
}

fn modes(e: &Edid) -> Vec<(u16, u16, u32)> {
    e.modes().iter().map(|m| (m.width, m.height, m.refresh_mhz)).collect()
}

fn list(v: &[Timing]) -> Vec<(u16, u16, u32)> {
    v.iter().map(|m| (m.width, m.height, m.refresh_mhz)).collect()
}

/// A 23-inch 1080p desktop panel, EDID 1.3, no extension. Preferred mode from
/// the first descriptor with the 509x286 mm image size in millimetres; the
/// name descriptor; then the standard timings in order, then the established
/// timings by bit; the serial-number descriptor is not exposed.
///
/// **Canary:** read the descriptors from byte 55 or the size in centimetres:
/// the preferred mode or the size is wrong.
#[test]
fn a_1080p_desktop_panel() {
    let e = parse(&hex(FHD_1_3)).unwrap();
    assert_eq!(&e.vendor, b"AZT");
    assert_eq!((e.product, e.week, e.year, e.version, e.revision), (0x1234, 12, 2021, 1, 3));
    assert!(e.digital);
    assert_eq!((e.width_mm, e.height_mm), (509, 286), "the descriptor's millimetres beat the 51x29 cm of byte 21");
    assert_eq!(e.name(), b"AZ FHD23");
    assert_eq!(e.extensions, 0);
    assert_eq!(e.preferred(), Some(t(1920, 1080, 60)));
    assert_eq!(
        list(e.modes()),
        list(&[
            t(1920, 1080, 60),
            // standard timings, in the order the blob lists them
            t(1280, 1024, 60), // 5:4
            t(1280, 960, 60),  // 4:3
            t(1440, 900, 60),  // 16:10
            t(1600, 900, 60),  // 16:9
            t(1680, 1050, 60),
            t(1280, 800, 60),
            // established timings, byte 35 bit 0 and 5, byte 36 bit 3
            t(800, 600, 60),
            t(640, 480, 60),
            t(1024, 768, 60),
        ])
    );
}

/// A 17-inch 5:4 panel: the preferred mode's refresh is the pixel clock over
/// the frame (108 MHz / 1688x1066 = 60.020 Hz), and the standard timing for
/// the same mode at "60 Hz" is the same mode, not a second one. Every
/// established-timing bit, interlaced 1024x768 excepted, lists once.
///
/// **Canary:** compare modes by exact millihertz: 1280x1024 is listed twice
/// and the list below has one more entry.
#[test]
fn a_5_4_panel_dedups_by_whole_hertz_and_reads_every_established_timing() {
    let e = parse(&hex(SXGA_1_3)).unwrap();
    assert_eq!(e.name(), b"AZ S17");
    assert_eq!((e.width_mm, e.height_mm), (338, 270));
    assert_eq!(e.preferred(), Some(Timing { width: 1280, height: 1024, refresh_mhz: 60_020 }));
    assert_eq!(
        list(e.modes()),
        list(&[
            Timing { width: 1280, height: 1024, refresh_mhz: 60_020 },
            t(1280, 1024, 75),
            t(1152, 864, 75),
            // byte 35 = 0x2A: bits 1, 3, 5
            t(800, 600, 56),
            t(640, 480, 72),
            t(640, 480, 60),
            // byte 36 = 0xFF: 1280x1024@75 is a repeat; the interlaced 1024x768 is not listed
            t(1024, 768, 75),
            t(1024, 768, 70),
            t(1024, 768, 60),
            t(832, 624, 75),
            t(800, 600, 75),
            t(800, 600, 72),
            // byte 37 bit 7
            t(1152, 870, 75),
        ])
    );
}

/// A television: one CTA-861 extension. The short video descriptors add the
/// 1080p50/24/30 and 720p50 and 480p modes; 1080i (VIC 5) and a code the
/// table does not name (VIC 20) add nothing; VIC 16 carries the native flag
/// and is the preferred mode again. The extension's own detailed timings
/// (720p60 and the 29.97-style 480p at 59.94 Hz) are modes the SVDs gave.
///
/// **Canary:** skip the data-block walk: 720p50 and 1080p50/24/30 are missing.
#[test]
fn a_television_with_a_cta_extension() {
    let e = parse(&hex(TV_1_3_CTA)).unwrap();
    assert_eq!(e.name(), b"AZ TV");
    assert_eq!(e.extensions, 1);
    assert_eq!((e.width_mm, e.height_mm), (509, 286), "byte 21/22 are zero; the descriptor says");
    assert_eq!(e.preferred(), Some(t(1920, 1080, 60)));
    assert_eq!(
        list(e.modes()),
        list(&[
            t(1920, 1080, 60),
            t(1280, 720, 60),
            t(1920, 1080, 50),
            t(1920, 1080, 24),
            t(1920, 1080, 30),
            t(1280, 720, 50),
            t(720, 480, 60),
        ])
    );
}

/// A 27-inch 4K panel, EDID 1.4: the preferred mode is a 594 MHz timing
/// (the pixel clock field holds 59400), the extension lists the 4K and
/// high-refresh 1080p codes and ends with two detailed timings that repeat
/// modes already listed.
///
/// **Canary:** treat the pixel clock as a signed 16-bit value: 4K60 reads as
/// a negative clock and the preferred mode is lost.
#[test]
fn a_4k_panel_with_high_clock_and_vics() {
    let e = parse(&hex(UHD_1_4_CTA)).unwrap();
    assert_eq!((e.version, e.revision), (1, 4));
    assert_eq!(e.name(), b"AZ UHD27");
    assert_eq!((e.width_mm, e.height_mm), (597, 336));
    assert_eq!(e.preferred(), Some(t(3840, 2160, 60)));
    assert_eq!(
        list(e.modes()),
        list(&[
            t(3840, 2160, 60),
            t(1920, 1080, 60), // standard timing, 16:9
            t(1280, 720, 60),
            t(3840, 2160, 30),
            t(3840, 2160, 25),
            t(3840, 2160, 50),
            t(1920, 1080, 120),
            t(1920, 1080, 100),
            t(1920, 1080, 50),
            t(1920, 1080, 24),
            t(1920, 1080, 30),
        ])
    );
}

/// Reduced blanking: 154 MHz over 2080x1235 is 59.950 Hz, and the standard
/// timing 1920x1200 "at 60" is that mode.
#[test]
fn a_reduced_blanking_timing_keeps_its_exact_refresh() {
    let e = parse(&hex(WUXGA_RB_1_3)).unwrap();
    assert_eq!(e.preferred(), Some(Timing { width: 1920, height: 1200, refresh_mhz: 59_950 }));
    assert_eq!(
        list(e.modes()),
        list(&[
            Timing { width: 1920, height: 1200, refresh_mhz: 59_950 },
            t(1680, 1050, 60),
            t(1440, 900, 60),
            t(1280, 800, 60),
            t(800, 600, 60),
            t(640, 480, 60),
            t(1024, 768, 60),
        ])
    );
}

/// A blob that is not an EDID is a refusal naming why, in the order the
/// checks run: size, header, checksum, version.
///
/// **Canary:** skip the checksum: the flipped-byte blob parses.
#[test]
fn blobs_that_are_not_edids_are_refused() {
    let good = hex(FHD_1_3);
    assert_eq!(parse(&[]), Err(EdidError::TooShort));
    assert_eq!(parse(&good[..BLOCK - 1]), Err(EdidError::TooShort));
    let mut b = good.clone();
    b[3] = 0;
    seal(&mut b, 0);
    assert_eq!(parse(&b), Err(EdidError::BadHeader), "a sealed block with a wrong header");
    let mut b = good.clone();
    b[40] ^= 0x10;
    assert_eq!(parse(&b), Err(EdidError::BadChecksum));
    for (ver, rev) in [(0u8, 3u8), (2, 0), (1, 5), (255, 255)] {
        let mut b = good.clone();
        b[18] = ver;
        b[19] = rev;
        seal(&mut b, 0);
        assert_eq!(parse(&b), Err(EdidError::BadVersion), "{ver}.{rev}");
    }
    assert!(parse(&vec![0xFF; 128]).is_err() && parse(&vec![0; 128]).is_err());
}

/// An extension block that fails its checksum is skipped; the base block's
/// modes stay. A blob cut off after the base block (the extension count says
/// one) gives the base block's modes. A block with another tag (DisplayID,
/// 0x70) is not read.
///
/// **Canary:** read the extension without its checksum: the corrupted blob
/// lists 720x480.
#[test]
fn a_bad_or_missing_extension_costs_only_its_modes() {
    let tv = hex(TV_1_3_CTA);
    let base_only = parse(&tv[..BLOCK]).unwrap();
    assert_eq!(modes(&base_only), vec![(1920, 1080, 60_000)]);
    assert_eq!(base_only.extensions, 1, "the count is what the base block says");

    let mut b = tv.clone();
    b[BLOCK + 40] ^= 0x01;
    assert_eq!(modes(&parse(&b).unwrap()), vec![(1920, 1080, 60_000)], "a corrupt extension");

    let mut b = tv.clone();
    b[BLOCK] = 0x70;
    seal(&mut b, 1);
    assert_eq!(modes(&parse(&b).unwrap()), vec![(1920, 1080, 60_000)], "a DisplayID block is not read");

    let mut b = tv.clone();
    b[BLOCK + 1] = 2; // CTA revision 2 has no data blocks
    seal(&mut b, 1);
    assert_eq!(modes(&parse(&b).unwrap()), vec![(1920, 1080, 60_000)]);
}

/// An interlaced first descriptor is not a preferred progressive mode: the
/// list has no preferred, and the rest of the blob still counts.
#[test]
fn an_interlaced_first_timing_is_not_listed_or_preferred() {
    let mut b = hex(FHD_1_3);
    b[54 + 17] |= 0x80;
    seal(&mut b, 0);
    let e = parse(&b).unwrap();
    assert_eq!(e.preferred(), None);
    assert_eq!(e.modes()[0], t(1280, 1024, 60));
    assert!(!e.modes().contains(&t(1920, 1080, 60)));
    // The image size still comes from the base block's centimetres.
    assert_eq!((e.width_mm, e.height_mm), (510, 290));
}

/// Data blocks that lie about their length stop the walk at the lie; a
/// timing area that starts inside the header or past the block is not read;
/// a zero pixel clock ends the extension's timing list.
#[test]
fn damaged_extension_layouts_are_read_as_far_as_they_are_sound() {
    let tv = hex(TV_1_3_CTA);
    // The SVD block claims 31 bytes: it runs past `d`.
    let mut b = tv.clone();
    b[BLOCK + 4] = (2 << 5) | 31;
    seal(&mut b, 1);
    assert_eq!(modes(&parse(&b).unwrap()).len(), 3, "base mode plus the two extension DTDs (720p60, 480p)");
    for d in [0u8, 1, 3, 127, 200, 255] {
        let mut b = tv.clone();
        b[BLOCK + 2] = d;
        seal(&mut b, 1);
        let e = parse(&b).unwrap();
        assert!(!e.modes().is_empty() && e.modes().len() <= MAX_MODES, "d = {d}");
    }
}

/// Standard timing identifiers: `01 01` and `20 20` are "unused", the first
/// byte 0 is reserved, and before EDID 1.3 aspect code 0 is 1:1.
#[test]
fn standard_timings_skip_unused_slots_and_read_the_aspect_by_revision() {
    let mut b = hex(FHD_1_3);
    b[38..54].fill(0);
    b[38..40].copy_from_slice(&[0x20, 0x20]);
    b[40..42].copy_from_slice(&[0x01, 0x01]);
    b[42..44].copy_from_slice(&[0x00, 0x40]);
    b[44..46].copy_from_slice(&[0xA9, 0xC0]); // 1600 wide, 16:9, 60 Hz
    b[46..48].copy_from_slice(&[0x81, 0x00]); // 1280 wide, aspect 0, 60 Hz
    seal(&mut b, 0);
    let e = parse(&b).unwrap();
    assert_eq!(&modes(&e)[1..3], &[(1600, 900, 60_000), (1280, 800, 60_000)], "16:10 from 1.3");
    let mut b = b.clone();
    b[19] = 2;
    seal(&mut b, 0);
    let e = parse(&b).unwrap();
    assert_eq!(&modes(&e)[1..3], &[(1600, 900, 60_000), (1280, 1280, 60_000)], "1:1 before 1.3");
}

/// The text of a name descriptor: trailing spaces and the line feed are
/// dropped, bytes outside printable ASCII show as `?`, a name that fills the
/// descriptor has no terminator.
#[test]
fn the_monitor_name_is_printable_ascii() {
    let mut b = hex(FHD_1_3);
    // descriptor 2 (bytes 72..90) is the name
    b[72 + 5..72 + 18].copy_from_slice(b"AB\xFFD\x01 EFGH\n  ");
    seal(&mut b, 0);
    assert_eq!(parse(&b).unwrap().name(), b"AB?D? EFGH");
    b[72 + 5..72 + 18].copy_from_slice(b"ABCDEFGHIJKLM");
    seal(&mut b, 0);
    assert_eq!(parse(&b).unwrap().name(), b"ABCDEFGHIJKLM");
    b[72 + 5..72 + 18].copy_from_slice(b"\n            ");
    seal(&mut b, 0);
    assert_eq!(parse(&b).unwrap().name(), b"");
}

/// A manufacturer id with a letter outside A-Z is shown with `?`; the unset
/// year and week read as "not given".
#[test]
fn the_manufacturer_id_and_the_date_say_when_they_do_not_know() {
    let mut b = hex(FHD_1_3);
    b[8] = 0;
    b[9] = 0x1F; // letters 0, 0, 31
    b[16] = 0xFF; // model year follows
    b[17] = 0;
    seal(&mut b, 0);
    let e = parse(&b).unwrap();
    assert_eq!(&e.vendor, b"???");
    assert_eq!((e.week, e.year), (0, 0));
}

/// Hostile input: 40,000 blobs of pseudo-random bytes behind a valid header,
/// version and checksums, one to three blocks each, none panics, every mode
/// is non-empty, none repeats, and the list never outgrows its capacity.
///
/// **Canary:** index the CTA block by its `d` byte without the clamp, or the
/// descriptors by a length the blob gives: a debug build panics here.
#[test]
fn random_blobs_behind_a_valid_header_never_panic_or_overflow() {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for round in 0..40_000 {
        let blocks = 1 + (round % 3);
        let mut b: Vec<u8> = (0..blocks * BLOCK).map(|_| rnd() as u8).collect();
        b[..8].copy_from_slice(&[0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0]);
        b[18] = 1;
        b[19] = (rnd() % 5) as u8;
        b[126] = (blocks - 1) as u8 + (round % 2) as u8; // sometimes more than the blob holds
        for k in 1..blocks {
            b[k * BLOCK] = 0x02;
            b[k * BLOCK + 1] = 3;
            if round % 3 != 0 {
                b[k * BLOCK + 2] = 4 + (rnd() % 124) as u8;
            }
        }
        for k in 0..blocks {
            seal(&mut b, k);
        }
        let e = parse(&b).unwrap();
        let m = e.modes();
        assert!(m.len() <= MAX_MODES);
        for (i, a) in m.iter().enumerate() {
            assert!(a.width > 0 && a.height > 0 && a.refresh_mhz > 0);
            assert!(m[..i].iter().all(|o| (o.width, o.height) != (a.width, a.height) || (o.refresh_mhz + 500) / 1000 != (a.refresh_mhz + 500) / 1000));
        }
        let _ = (e.name(), e.preferred());
    }
}
