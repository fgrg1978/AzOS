// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the raw-pixel helpers of `azos_cam_ring`.

#[test]
fn the_luma_of_a_yuyv_frame_is_every_other_byte() {
    use azos_cam_ring::yuyv_luma;
    // 4x2 pixels: Y values 10..18 interleaved with chroma 200+.
    let yuyv: Vec<u8> = (0..8u8).flat_map(|i| [10 + i, 200 + i]).collect();
    let mut dst = [0u8; 8];
    assert_eq!(yuyv_luma(&yuyv, 4, 2, &mut dst, 8, 8), Some((4, 2)));
    assert_eq!(dst, [10, 11, 12, 13, 14, 15, 16, 17]);
}

#[test]
fn a_big_yuyv_frame_is_decimated_to_fit() {
    use azos_cam_ring::yuyv_luma;
    // 8x4 pixels into 4x4: every second pixel of every second row (step 2).
    let yuyv: Vec<u8> = (0..32u8).flat_map(|i| [i, 0xee]).collect();
    let mut dst = [0u8; 16];
    assert_eq!(yuyv_luma(&yuyv, 8, 4, &mut dst, 4, 4), Some((4, 2)));
    assert_eq!(&dst[..8], &[0, 2, 4, 6, 16, 18, 20, 22]);
    // Height decides the step as well as width.
    assert_eq!(yuyv_luma(&yuyv, 8, 4, &mut dst, 8, 1), Some((2, 1)));
    assert_eq!(&dst[..2], &[0, 4]);
}

#[test]
fn a_yuyv_frame_that_does_not_add_up_gives_nothing() {
    use azos_cam_ring::yuyv_luma;
    let mut dst = [0u8; 16];
    assert_eq!(yuyv_luma(&[0; 15], 2, 4, &mut dst, 8, 8), None, "a byte short of 2 * w * h");
    assert_eq!(yuyv_luma(&[0; 16], 0, 4, &mut dst, 8, 8), None);
    assert_eq!(yuyv_luma(&[0; 16], 2, 4, &mut dst[..7], 8, 8), None, "dst too small");
    assert_eq!(yuyv_luma(&[0; 16], 2, 4, &mut dst, 0, 8), None);
}

// ---- JPEG size ----

/// SOI, an APP0 and a DQT segment, then SOF0 for `w` x `h`.
fn jpeg_head(w: u16, h: u16) -> Vec<u8> {
    let mut j = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x06, 1, 2, 3, 4, 0xff, 0xdb, 0x00, 0x04, 9, 9];
    j.extend([0xff, 0xc0, 0x00, 0x0b, 8]);
    j.extend(h.to_be_bytes());
    j.extend(w.to_be_bytes());
    j.extend([1, 1, 0x11, 0]);
    j
}

#[test]
fn a_jpeg_says_its_size_in_the_start_of_frame() {
    use azos_cam_ring::jpeg_size;
    assert_eq!(jpeg_size(&jpeg_head(160, 120)), Some((160, 120)));
    assert_eq!(jpeg_size(&jpeg_head(640, 480)), Some((640, 480)));
    // Fill bytes before a marker, and a progressive frame (SOF2).
    let mut j = jpeg_head(320, 240);
    j.splice(2..2, [0xff, 0xff]);
    assert_eq!(jpeg_size(&j), Some((320, 240)));
    let mut j = jpeg_head(320, 240);
    let sof = j.iter().position(|b| *b == 0xc0).unwrap();
    j[sof] = 0xc2;
    assert_eq!(jpeg_size(&j), Some((320, 240)));
}

#[test]
fn bytes_that_are_not_a_jpeg_with_a_frame_header_have_no_size() {
    use azos_cam_ring::jpeg_size;
    let j = jpeg_head(160, 120);
    assert_eq!(jpeg_size(&[]), None);
    assert_eq!(jpeg_size(&[0xff, 0xd8]), None, "SOI alone");
    assert_eq!(jpeg_size(&[0, 1, 2, 3, 4, 5]), None, "no SOI");
    assert_eq!(jpeg_size(&j[..j.len() - 6]), None, "ends inside the SOF");
    // The scan starts before any frame header.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xda, 0, 2, 0, 0]), None);
    // A segment whose length runs past the end.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xe0, 0xff, 0xff, 0, 0]), None);
    // A zero size is no size.
    assert_eq!(jpeg_size(&jpeg_head(0, 120)), None);
    // A DHT (c4) is not a frame header.
    assert_eq!(jpeg_size(&[0xff, 0xd8, 0xff, 0xc4, 0, 4, 0, 0, 0xff, 0xd9]), None);
}
