// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure half of the driver, on bytes: the class-specific descriptor walk,
//! the choice of format, frame and interval, the PROBE block and the payload
//! header.

use azos_usb::class::uvc::{
    block_len, parse_block, parse_header, pick_mode, request_block, survey, Choice, Header, Mode, Negotiated, Pixels, Want,
};

use crate::fixtures::*;

fn want(w: u16, h: u16, fps: u16) -> Want {
    Want { width: w, height: h, fps, max_frame: 64 * 1024, max_jpeg: usize::MAX }
}

fn walk(config: &[u8], vs: u8, w: &Want) -> azos_usb::class::uvc::Survey {
    survey(config.len(), &mut |off, out| out.copy_from_slice(&config[off..off + out.len()]), vs, w)
}

#[test]
fn the_walk_finds_the_header_the_endpoint_the_frames_and_the_settings() {
    let cam = Cam::new();
    let s = walk(&cam.config(), 1, &want(160, 120, 10));
    assert_eq!(s.bcd_uvc, 0x0110);
    assert_eq!(s.endpoint, 0x81);
    assert!(s.streaming);
    // Setting 0 has no endpoint; 1 to 3 have one each.
    let alts: Vec<_> = s.alts().iter().map(|a| (a.alt, a.address, a.bytes_per_interval())).collect();
    assert_eq!(alts, [(0, 0, 0), (1, 0x81, 192), (2, 0x81, 512), (3, 0x81, 1024)]);
}

#[test]
fn motion_jpeg_is_preferred_to_raw_pixels_of_the_exact_size() {
    // A YUY2 frame of exactly 160x120 and an MJPEG one of 320x240: JPEG wins.
    let s = walk(&Cam::new().config(), 1, &want(160, 120, 10));
    let c = s.best.unwrap();
    assert_eq!((c.pixels, c.format_index, c.frame_index, c.width, c.height), (Pixels::Mjpeg, 1, 2, 160, 120));
}

#[test]
fn the_frame_closest_in_area_wins_and_a_tie_goes_to_the_smaller() {
    let cam = Cam::new();
    let c = walk(&cam.config(), 1, &want(300, 220, 10)).best.unwrap();
    assert_eq!((c.width, c.height), (320, 240));
    let c = walk(&cam.config(), 1, &want(200, 150, 10)).best.unwrap();
    // 200x150 = 30000: 160x120 = 19200 is 10800 away, 320x240 = 76800 is 46800.
    assert_eq!((c.width, c.height), (160, 120));
    let c = walk(&cam.config(), 1, &want(1, 1, 10)).best.unwrap();
    assert_eq!((c.width, c.height), (160, 120), "nothing is smaller");
}

#[test]
fn a_motion_jpeg_frame_larger_than_the_one_wanted_needs_the_cameras_word_that_it_fits() {
    let mut w = want(160, 120, 10);
    w.max_jpeg = 8000;
    // 320x240 and 160x120, each bounded by w * h * 2 bytes: neither bound
    // fits the link, so only the frame no larger than the wanted one stands.
    let cam = Cam::new();
    let mut big = want(300, 220, 10);
    big.max_jpeg = 8000;
    let c = walk(&cam.config(), 1, &big).best.unwrap();
    assert_eq!((c.width, c.height), (160, 120), "320x240 is nearer 300x220, but is not offered");
    // The smaller one is offered whatever its bound says.
    let c = walk(&cam.config(), 1, &w).best.unwrap();
    assert_eq!((c.pixels, c.width, c.height), (Pixels::Mjpeg, 160, 120));
    // A camera that bounds a 640x480 frame at 6000 bytes proves it fits.
    let mut cam = Cam::new();
    cam.formats = vec![Format { kind: Kind::Mjpeg, frames: vec![Frame::new(640, 480, 6000, &[1_000_000])] }];
    let c = walk(&cam.config(), 1, &w).best.unwrap();
    assert_eq!((c.width, c.height), (640, 480));
    // One byte over the link's limit does not.
    cam.formats[0].frames[0].max_size = 8001;
    assert!(walk(&cam.config(), 1, &w).best.is_none());
    // And a bound of 0 says nothing.
    cam.formats[0].frames[0].max_size = 0;
    assert!(walk(&cam.config(), 1, &w).best.is_none());
}

#[test]
fn a_large_motion_jpeg_frame_does_not_hide_the_raw_one_that_fits() {
    let mut cam = Cam::new();
    cam.formats = vec![
        Format { kind: Kind::Mjpeg, frames: vec![Frame::new(640, 480, 640 * 480 * 2, &[1_000_000])] },
        Format { kind: Kind::Yuy2, frames: vec![Frame::new(160, 120, 160 * 120 * 2, &[1_000_000])] },
    ];
    let mut w = want(160, 120, 10);
    w.max_jpeg = 8000;
    let c = walk(&cam.config(), 1, &w).best.unwrap();
    assert_eq!((c.pixels, c.width, c.height), (Pixels::Yuyv, 160, 120));
}

#[test]
fn raw_pixels_are_offered_only_when_a_frame_fits_the_slot() {
    let mut cam = Cam::new();
    cam.formats.remove(0); // YUY2 only
    let mut w = want(160, 120, 10);
    w.max_frame = 160 * 120 * 2 - 1;
    assert!(walk(&cam.config(), 1, &w).best.is_none(), "one byte short of a frame");
    w.max_frame = 160 * 120 * 2;
    let c = walk(&cam.config(), 1, &w).best.unwrap();
    assert_eq!((c.pixels, c.format_index, c.frame_index), (Pixels::Yuyv, 1, 1));
}

#[test]
fn the_interval_closest_to_the_frame_rate_is_chosen() {
    let cam = Cam::new();
    // 15, 10 and 5 fps are offered.
    for (fps, interval) in [(15u16, 666_666u32), (11, 1_000_000), (8, 1_000_000), (7, 1_000_000), (6, 2_000_000), (1, 2_000_000), (60, 666_666)] {
        let c = walk(&cam.config(), 1, &want(160, 120, fps)).best.unwrap();
        assert_eq!(c.interval, interval, "{fps} fps");
    }
}

#[test]
fn a_continuous_interval_range_is_clamped_and_rounded_to_its_step() {
    let mut cam = Cam::new();
    for f in cam.formats.iter_mut().flat_map(|f| f.frames.iter_mut()) {
        // 100 ms to 400 ms in steps of 50 ms (10 to 2.5 fps).
        f.intervals = vec![1_000_000, 4_000_000];
        f.step = Some(500_000);
        f.default_interval = 1_000_000;
    }
    let iv = |fps| walk(&cam.config(), 1, &want(160, 120, fps)).best.unwrap().interval;
    assert_eq!(iv(10), 1_000_000);
    assert_eq!(iv(30), 1_000_000, "clamped to the minimum");
    assert_eq!(iv(4), 2_500_000);
    assert_eq!(iv(1), 4_000_000, "clamped to the maximum");
    assert_eq!(iv(3), 3_500_000, "1/3 s rounds to the nearest 50 ms step: 350 ms");
}

#[test]
fn formats_the_driver_does_not_know_are_skipped() {
    // NV12 (uncompressed, another GUID) and H.264 (frame-based) come first,
    // each with a 64x48 frame that would be the exact match.
    let mut cam = Cam::new();
    let exact = Frame::new(64, 48, 64 * 48, &[1_000_000]);
    cam.formats.insert(0, Format { kind: Kind::Nv12, frames: vec![exact.clone()] });
    cam.formats.insert(1, Format { kind: Kind::H264, frames: vec![exact] });
    let s = walk(&cam.config(), 1, &want(64, 48, 10));
    let c = s.best.unwrap();
    assert_eq!((c.pixels, c.format_index, c.frame_index, c.width), (Pixels::Mjpeg, 3, 2, 160));
    assert_eq!((c.height, c.interval), (120, 1_000_000), "the MJPEG format keeps its own index");
}

#[test]
fn a_camera_with_no_streaming_interface_has_nothing_to_choose() {
    let s = walk(&Cam::new().config(), 5, &want(160, 120, 10));
    assert!(!s.streaming);
    assert!(s.best.is_none());
    assert_eq!(s.alts().len(), 0);
}

#[test]
fn a_truncated_configuration_gives_what_was_read_before_the_cut() {
    let cam = Cam::new();
    let cfg = cam.config();
    // Cut in the middle of the second MJPEG frame descriptor: the first
    // frame (320x240) was complete.
    let cut = cfg.windows(2).rposition(|w| w == [0x24, 7]).unwrap();
    let s = walk(&cfg[..cut + 10], 1, &want(160, 120, 10));
    let c = s.best.unwrap();
    assert_eq!((c.width, c.height), (320, 240));
    // No setting was reached: the cut is before them.
    assert_eq!(s.alts().len(), 1);
}

#[test]
fn a_bulk_camera_is_one_setting_with_its_endpoint() {
    let cam = Cam::bulk();
    let s = walk(&cam.config(), 1, &want(160, 120, 10));
    assert_eq!(s.endpoint, 0x82);
    assert_eq!(s.alts().len(), 1);
    assert_eq!((s.alts()[0].alt, s.alts()[0].address, s.alts()[0].attrs), (0, 0x82, 2));
    assert_eq!(pick_mode(&s, 12_345), Some(Mode::Bulk { endpoint: 0x82, mps: 512 }));
}

#[test]
fn the_smallest_setting_that_carries_the_payload_is_selected() {
    let s = walk(&Cam::new().config(), 1, &want(160, 120, 10));
    let isoch = |alt, bytes| Some(Mode::Isoch { alt, endpoint: 0x81, bytes });
    assert_eq!(pick_mode(&s, 100), isoch(1, 192));
    assert_eq!(pick_mode(&s, 192), isoch(1, 192), "exactly enough");
    assert_eq!(pick_mode(&s, 193), isoch(2, 512));
    assert_eq!(pick_mode(&s, 1024), isoch(3, 1024));
    assert_eq!(pick_mode(&s, 1025), None, "no setting is big enough");
}

#[test]
fn a_high_bandwidth_or_superspeed_setting_counts_all_its_transactions() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![
        Alt { mps_word: 1024 | 1 << 11, interval: 1, companion: None },
        Alt { mps_word: 1024, interval: 1, companion: Some((3, 1, 8192)) },
    ]);
    let s = walk(&cam.config(), 1, &want(160, 120, 10));
    let bytes: Vec<_> = s.alts().iter().map(|a| a.bytes_per_interval()).collect();
    assert_eq!(bytes, [0, 2048, 8192]);
    assert_eq!(s.alts()[2].companion, Some((3, 1, 8192)));
}

#[test]
fn the_probe_block_is_26_bytes_before_uvc_1_1_and_34_from_it() {
    assert_eq!(block_len(0x0100), 26);
    assert_eq!(block_len(0x0000), 26);
    assert_eq!(block_len(0x0110), 34);
    assert_eq!(block_len(0x0150), 34);
}

#[test]
fn the_request_names_the_frame_and_the_interval_and_nothing_else() {
    let c = Choice { pixels: Pixels::Mjpeg, format_index: 2, frame_index: 3, width: 160, height: 120, interval: 666_666 };
    let b = request_block(&c);
    assert_eq!(&b[..8], &[1, 0, 2, 3, 0x2a, 0x2c, 0x0a, 0x00]);
    assert!(b[8..].iter().all(|x| *x == 0));
}

#[test]
fn the_camera_answer_is_read_by_field() {
    let b = probe_block(34, 1, 1, 2, 1_000_000, 38_400, 400);
    assert_eq!(
        parse_block(&b),
        Some(Negotiated { format_index: 1, frame_index: 2, interval: 1_000_000, max_payload: 400 })
    );
    assert_eq!(parse_block(&b[..26]).map(|n| n.max_payload), Some(400), "a 1.0 block is enough");
    assert_eq!(parse_block(&b[..25]), None);
}

#[test]
fn a_payload_header_is_decoded_and_checked_against_the_payload() {
    let p = payload(true, false, false, None, b"abc");
    assert_eq!(parse_header(&p), Some(Header { len: 2, fid: true, eof: false, err: false, still: false }));
    let p = payload(false, true, true, Some(7), b"");
    assert_eq!(parse_header(&p), Some(Header { len: 6, fid: false, eof: true, err: true, still: false }));
    // bmHeaderInfo bit 5: a still image payload.
    assert!(parse_header(&[2, 0x80 | 1 << 5]).unwrap().still);
    assert_eq!(parse_header(&[]), None);
    assert_eq!(parse_header(&[2]), None, "shorter than two bytes");
    assert_eq!(parse_header(&[1, 0x80]), None, "a header length under 2");
    assert_eq!(parse_header(&[12, 0x80, 1, 2, 3]), None, "a header longer than the payload");
}
