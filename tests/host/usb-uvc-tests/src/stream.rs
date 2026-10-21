// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The driver over the xHCI mock: a camera is plugged in, negotiated, started
//! by a reader of the ring and made to send frames, payload by payload, the
//! way a UVC firmware does.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use azos_cam_ring::{FanoutRing, FrameInfo, Policy};
use azos_devif::Out;
use azos_usb::class::uvc::{Fail, Mode, Pixels, State, Uvc, Want, IDLE_STOP_US};
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::Clock;
use azos_usb::xhci::trb::cc;
use azos_usb::PIPE_DEPTH;
use azos_usb_tests::devices::DevRef;
use azos_usb_tests::harness::Rig;
use azos_usb_tests::mock::{MockClock, MockMem};

use crate::fixtures::*;

type Ring<const SZ: usize> = FanoutRing<4, SZ, 1>;
type Driver<const SZ: usize> = Uvc<'static, MockMem, MockClock, Ring<SZ>>;

static STAMP: AtomicU64 = AtomicU64::new(1000);

fn stamp() -> u64 {
    STAMP.fetch_add(1, Ordering::Relaxed)
}

pub struct Handle<'a, const SZ: usize>(&'a RefCell<Driver<SZ>>);

impl<const SZ: usize> UsbClass for Handle<'_, SZ> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        UsbClass::attach(&mut *self.0.borrow_mut(), claim, vid_pid, triple, speed_port)
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        UsbClass::detach(&mut *self.0.borrow_mut(), claim)
    }
}

/// The payload data a frame carries: derived from its number, so a frame that
/// comes out wrong can be told from one that comes out right.
pub fn jpeg(n: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0xff, 0xd8];
    v.extend((0..len - 4).map(|i| (i as u8).wrapping_mul(7).wrapping_add(n)));
    v.extend([0xff, 0xd9]);
    v
}

pub struct Bench<const SZ: usize> {
    pub rig: Rig,
    pub ring: &'static Ring<SZ>,
    pub uvc: RefCell<Driver<SZ>>,
    pub dev: DevRef,
    pub cam: Cam,
    /// FID of the next frame sent.
    fid: bool,
}

pub const CONSUMER: usize = 0;

impl<const SZ: usize> Bench<SZ> {
    /// A camera whose probe answer is the block for `payload` bytes per
    /// interval, of the first MJPEG frame of 160x120.
    pub fn answered(cam: Cam, psiv: u32, payload: u32) -> Bench<SZ> {
        Bench::answered_for(cam, psiv, 1, 2, payload)
    }

    /// As [`Bench::answered`] for frame `frame` of format `format`.
    pub fn answered_for(cam: Cam, psiv: u32, format: u8, frame: u8, payload: u32) -> Bench<SZ> {
        let dev = cam.device(psiv);
        let len = if cam.bcd_uvc >= 0x0110 { 34 } else { 26 };
        dev.borrow_mut().canned.push((0xa1, 0x81, probe_block(len, 1, format, frame, 1_000_000, 38_400, payload)));
        Bench::with(cam, dev, Want { width: 160, height: 120, fps: 10, max_frame: SZ, max_jpeg: SZ })
    }

    pub fn with(cam: Cam, dev: DevRef, want: Want) -> Bench<SZ> {
        let rig = Rig::new();
        let ring: &'static Ring<SZ> = Box::leak(Box::new(Ring::<SZ>::new(Policy::OverwriteOldest)));
        let uvc = RefCell::new(Uvc::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..], ring, want, stamp));
        rig.hw.attach_root(1, dev.clone());
        Bench { rig, ring, uvc, dev, cam, fid: false }
    }

    pub fn state(&self) -> State {
        self.uvc.borrow().state()
    }

    /// One turn of the `usb` task: the core, then the driver with its session.
    pub fn turn(&mut self) {
        let mut h = UsbClassDirect(Handle(&self.uvc));
        let mut reg = Registry::new();
        reg.register(0, azos_usb::listing::Lister::rule(), &mut self.rig.lister).unwrap();
        reg.register(1, Driver::<SZ>::rule(), &mut h).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        let claim = self.uvc.borrow().claim();
        match claim {
            Some(c) => {
                let mut s = self.rig.usb.session(c);
                self.uvc.borrow_mut().service(Some(&mut s));
            }
            None => self.uvc.borrow_mut().service(None),
        }
        self.rig.hw.clock().delay_us(1_000);
    }

    pub fn run(&mut self, turns: u32) {
        for _ in 0..turns {
            self.turn();
        }
    }

    pub fn until(&mut self, mut done: impl FnMut(&mut Bench<SZ>) -> bool, max: u32) -> bool {
        for _ in 0..max {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    /// Plugged in and negotiated.
    pub fn negotiate(&mut self) {
        assert!(self.until(|b| matches!(b.state(), State::Ready | State::Failed(_)), 3000), "never negotiated: {:?}", self.state());
    }

    /// A reader attaches to the ring and the stream starts.
    pub fn start(&mut self) {
        self.ring.attach(CONSUMER);
        assert!(self.until(|b| matches!(b.state(), State::Streaming | State::Failed(_)), 200), "never started: {:?}", self.state());
        assert_eq!(self.state(), State::Streaming);
    }

    pub fn requests(&self) -> Vec<([u8; 8], Vec<u8>)> {
        self.dev.borrow().requests.clone()
    }

    /// The control requests the camera saw with this bRequest.
    pub fn requests_of(&self, request: u8) -> Vec<([u8; 8], Vec<u8>)> {
        self.requests().into_iter().filter(|(s, _)| s[1] == request).collect()
    }

    /// Queue payloads on the camera's streaming endpoint.
    pub fn send(&mut self, payloads: &[Vec<u8>]) {
        let ep = (self.cam.endpoint & 0x0f) as usize;
        for p in payloads {
            self.rig.hw.inject_in(&self.dev, ep, p);
            // The driver resubmits a buffer a turn after it completes.
            self.turn();
        }
        self.run(PIPE_DEPTH as u32 + 2);
    }

    /// One frame as payloads of `chunk` data bytes: FID toggled per frame,
    /// EOF on the last unless `eof` is false.
    pub fn frame_payloads(&mut self, data: &[u8], chunk: usize, eof: bool) -> Vec<Vec<u8>> {
        let fid = self.fid;
        self.fid = !self.fid;
        let n = data.len().div_ceil(chunk);
        data.chunks(chunk)
            .enumerate()
            .map(|(i, c)| payload(fid, eof && i + 1 == n, false, if i == 0 { Some(i as u32) } else { None }, c))
            .collect()
    }

    /// The FID the next frame starts with.
    pub fn fid_next(&mut self, fid: bool) {
        self.fid = fid;
    }

    pub fn send_frame(&mut self, data: &[u8], chunk: usize) {
        let p = self.frame_payloads(data, chunk, true);
        self.send(&p);
    }

    /// The newest frame the reader has not taken: (bytes, info, stamp).
    pub fn take(&self) -> Option<(Vec<u8>, FrameInfo, u64)> {
        let f = self.ring.acquire_latest(CONSUMER)?;
        Some((f.bytes().to_vec(), f.info(), f.stamp()))
    }
}

/// A HS camera whose probe answer asks for 400 bytes per interval: setting 2.
fn bench() -> Bench<8192> {
    Bench::answered(Cam::new(), 3, 400)
}

#[test]
fn a_camera_is_negotiated_and_left_idle_until_somebody_reads() {
    let mut b = bench();
    b.negotiate();
    assert_eq!(b.state(), State::Ready);
    let c = b.uvc.borrow().stream_choice().unwrap();
    assert_eq!((c.pixels, c.width, c.height, c.fps()), (Pixels::Mjpeg, 160, 120, 10));
    assert_eq!(b.uvc.borrow().mode(), Some(Mode::Isoch { alt: 2, endpoint: 0x81, bytes: 512 }));
    // PROBE was set (34 bytes: UVC 1.1) and read; nothing was committed, no
    // setting selected.
    let set = b.requests_of(0x01);
    let probe = set.iter().find(|(s, _)| s[3] == 1 && s[0] == 0x21).expect("SET_CUR(PROBE)");
    assert_eq!(probe.0[4], 1, "to the streaming interface");
    assert_eq!(probe.0[6], 34, "wLength");
    assert_eq!(probe.1, request_bytes(34, 1, 2, 1_000_000));
    assert!(set.iter().all(|(s, _)| s[3] != 2), "no COMMIT yet");
    assert!(b.requests_of(11).is_empty(), "no SET_INTERFACE yet");
    assert_eq!(b.requests_of(0x81).len(), 1, "GET_CUR(PROBE)");
}

/// What the driver asks PROBE for: hint, format, frame, interval.
fn request_bytes(len: usize, format: u8, frame: u8, interval: u32) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[0] = 1;
    v[2] = format;
    v[3] = frame;
    v[4..8].copy_from_slice(&interval.to_le_bytes());
    v
}

#[test]
fn a_reader_starts_the_stream_with_commit_and_the_smallest_setting_that_carries_it() {
    let mut b = bench();
    b.negotiate();
    b.start();
    // COMMIT carries the block the camera answered PROBE with.
    let commit = b.requests_of(0x01).into_iter().find(|(s, _)| s[3] == 2).expect("SET_CUR(COMMIT)");
    assert_eq!(commit.1, probe_block(34, 1, 1, 2, 1_000_000, 38_400, 400));
    // 400 bytes per interval: setting 1 carries 192, setting 2 512.
    let alt = b.requests_of(11);
    assert_eq!(alt.len(), 1);
    assert_eq!((alt[0].0[0], alt[0].0[2], alt[0].0[4]), (0x01, 2, 1), "SET_INTERFACE(interface 1, setting 2)");
    // The endpoint is configured with setting 2's packet size.
    let slot = b.rig.slot_of(&b.dev) as usize;
    let c = b.rig.hw.ep_ctx(slot, 3);
    assert_eq!((c[1] >> 3) & 7, 5);
    assert_eq!(c[1] >> 16, 512);
}

/// A stream running with the first frame (the partial one the stream starts
/// in) already behind it, so the next frame sent is whole for the driver.
fn streaming() -> Bench<8192> {
    let mut b = bench();
    b.negotiate();
    b.start();
    let first = jpeg(0, 300);
    b.send_frame(&first, 100);
    assert_eq!(b.uvc.borrow().stats().frames, 0, "the frame the stream started in is not delivered");
    b
}

#[test]
fn frames_are_assembled_from_payloads_and_committed_whole() {
    let mut b = streaming();
    for n in 1..=4u8 {
        let f = jpeg(n, 250 + 40 * n as usize);
        // Payloads of 100 data bytes: a frame is 3 to 5 of them.
        b.send_frame(&f, 100);
        let (got, info, _) = b.take().unwrap_or_else(|| panic!("frame {n} not delivered"));
        assert_eq!(got, f, "frame {n}");
        assert_eq!(info, FrameInfo::JPEG);
    }
    let s = b.uvc.borrow().stats();
    assert_eq!((s.frames, s.dropped, s.lost, s.bad_headers), (4, 1, 0, 0));
    assert_eq!(b.ring.produced(), 4);
}

#[test]
fn the_acquisition_stamp_is_read_when_the_frame_is_committed() {
    let mut b = streaming();
    let before = STAMP.load(Ordering::Relaxed);
    b.send_frame(&jpeg(1, 200), 100);
    let (_, _, stamp) = b.take().unwrap();
    assert!(stamp >= before && stamp < STAMP.load(Ordering::Relaxed), "stamp {stamp} from the stamp clock");
}

#[test]
fn a_payload_flagged_with_the_error_bit_drops_its_frame_and_the_next_one_is_fine() {
    let mut b = streaming();
    let f = jpeg(1, 300);
    let mut p = b.frame_payloads(&f, 100, true);
    p[1] = payload(p[1][1] & 1 != 0, false, true, None, &f[100..200]);
    b.send(&p);
    assert!(b.take().is_none(), "a flagged frame must not reach the ring");
    let g = jpeg(2, 300);
    b.send_frame(&g, 100);
    assert_eq!(b.take().map(|t| t.0), Some(g));
    let s = b.uvc.borrow().stats();
    assert_eq!((s.frames, s.dropped), (1, 2));
}

#[test]
fn a_lost_interval_drops_the_frame_it_was_part_of() {
    let mut b = streaming();
    let slot = b.rig.slot_of(&b.dev) as usize;
    let f = jpeg(1, 400);
    let p = b.frame_payloads(&f, 100, true);
    b.send(&p[..1]);
    // The bus loses the interval the second payload was in.
    b.rig.hw.inject_error(slot, 3, cc::MISSED_SERVICE);
    b.send(&p[1..]);
    assert!(b.take().is_none(), "a frame with a hole must not reach the ring");
    let s = b.uvc.borrow().stats();
    assert_eq!(s.lost, 1);
    // The stream goes on: the next frame is whole.
    let g = jpeg(2, 300);
    b.send_frame(&g, 100);
    assert_eq!(b.take().map(|t| t.0), Some(g));
}

#[test]
fn a_stream_that_starts_mid_frame_delivers_nothing_of_that_frame() {
    let mut b = bench();
    b.negotiate();
    b.start();
    // The camera was in the middle of a frame: payloads 3 and 4 of it, FID
    // 0, then whole frames. Its tail happens to start like a JPEG would.
    let mut f = jpeg(9, 400);
    f[200..202].copy_from_slice(&[0xff, 0xd8]);
    let p = b.frame_payloads(&f, 100, true);
    b.send(&p[2..]);
    assert!(b.take().is_none());
    b.send_frame(&jpeg(1, 200), 100);
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(1, 200)));
}

#[test]
fn a_stream_that_starts_on_a_flipped_fid_mid_frame_still_waits_for_a_real_start() {
    // The first payload seen has FID 1 (the camera was in a frame with FID
    // 1): it is not a toggle, and the frame is not taken for a whole one.
    let mut b = bench();
    b.negotiate();
    b.start();
    b.fid_next(true);
    let f = jpeg(9, 400);
    let p = b.frame_payloads(&f, 100, true);
    b.send(&p[1..]);
    assert!(b.take().is_none());
}

#[test]
fn a_frame_longer_than_the_slot_is_dropped_and_counted() {
    let mut b = streaming();
    let big = jpeg(1, 9000); // slots are 8192
    b.send_frame(&big, 400);
    assert!(b.take().is_none());
    let s = b.uvc.borrow().stats();
    assert_eq!(s.oversize, 1);
    let g = jpeg(2, 500);
    b.send_frame(&g, 100);
    assert_eq!(b.take().map(|t| t.0), Some(g));
}

#[test]
fn a_jpeg_the_consumer_cannot_carry_is_dropped_and_counted_though_the_slot_holds_it() {
    // Slots are 8192, the consumer carries 1000.
    let cam = Cam::new();
    let dev = cam.device(3);
    dev.borrow_mut().canned.push((0xa1, 0x81, probe_block(34, 1, 1, 2, 1_000_000, 38_400, 400)));
    let want = Want { width: 160, height: 120, fps: 10, max_frame: 8192, max_jpeg: 1000 };
    let mut b: Bench<8192> = Bench::with(cam, dev, want);
    b.negotiate();
    b.start();
    b.send_frame(&jpeg(0, 300), 100);
    let big = jpeg(1, 2000);
    b.send_frame(&big, 400);
    assert!(b.take().is_none(), "nothing reaches the ring");
    assert_eq!(b.uvc.borrow().stats().oversize, 1);
    let ok = jpeg(2, 1000);
    b.send_frame(&ok, 200);
    assert_eq!(b.take().map(|t| t.0), Some(ok), "exactly the limit is carried");
    let over = jpeg(3, 1001);
    b.send_frame(&over, 200);
    assert!(b.take().is_none());
    assert_eq!(b.uvc.borrow().stats().oversize, 2);
}

#[test]
fn a_camera_with_only_big_motion_jpeg_frames_is_failed_not_streamed_into_nothing() {
    let mut cam = Cam::new();
    cam.formats = vec![Format { kind: Kind::Mjpeg, frames: vec![Frame::new(640, 480, 640 * 480 * 2, &[1_000_000])] }];
    let mut b: Bench<8192> = Bench::answered_for(cam, 3, 1, 1, 400);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::NoFormat));
}

#[test]
fn a_motion_jpeg_frame_that_does_not_start_with_the_soi_marker_is_dropped() {
    let mut b = streaming();
    let mut f = jpeg(1, 300);
    f[0] = 0x00;
    b.send_frame(&f, 100);
    assert!(b.take().is_none());
    assert_eq!(b.uvc.borrow().stats().dropped, 2);
}

#[test]
fn payloads_of_a_still_image_are_not_part_of_the_stream() {
    let mut b = streaming();
    let f = jpeg(1, 300);
    let mut p = b.frame_payloads(&f, 100, true);
    // Between its payloads, a still image's.
    let still = vec![2, 0x80 | 1 << 5 | 1 << 1 | (p[1][1] & 1), 0xaa, 0xbb];
    p.insert(2, still);
    b.send(&p);
    assert_eq!(b.take().map(|t| t.0), Some(f));
}

#[test]
fn empty_intervals_and_a_garbled_header_are_not_frames() {
    let mut b = streaming();
    let f = jpeg(1, 300);
    let mut p = b.frame_payloads(&f, 100, true);
    p.insert(1, vec![]);
    b.send(&p);
    assert_eq!(b.take().map(|t| t.0), Some(f), "an empty interval is nothing");
    // A header that says it is longer than the payload loses the frame.
    let g = jpeg(2, 300);
    let mut p = b.frame_payloads(&g, 100, true);
    p[1] = vec![9, 0x80, 1, 2];
    b.send(&p);
    assert!(b.take().is_none());
    assert_eq!(b.uvc.borrow().stats().bad_headers, 1);
}

#[test]
fn a_camera_that_never_sets_eof_ends_its_frames_at_the_toggle() {
    let mut b = bench();
    b.negotiate();
    b.start();
    // No EOF anywhere: frame n is complete when frame n+1 starts. Frame 0 is
    // the one the stream started in.
    let f: Vec<Vec<u8>> = (0..4).map(|n| jpeg(n, 300)).collect();
    for fr in &f {
        let p = b.frame_payloads(fr, 100, false);
        b.send(&p);
    }
    // Frame 1 ended at the first payload of frame 2, frame 2 at the first of
    // frame 3; frame 3 is still open.
    assert_eq!(b.ring.produced(), 2);
    assert_eq!(b.take().map(|t| t.0), Some(f[2].clone()));
}

#[test]
fn a_camera_that_sets_eof_loses_a_frame_whose_last_payload_never_came() {
    let mut b = streaming();
    let (f1, f2, f3) = (jpeg(1, 300), jpeg(2, 300), jpeg(3, 300));
    b.send_frame(&f1, 100);
    assert_eq!(b.take().map(|t| t.0), Some(f1), "this camera sets EOF");
    // f2 loses its last payload (and with it the EOF).
    let mut p = b.frame_payloads(&f2, 100, true);
    p.pop();
    b.send(&p);
    b.send_frame(&f3, 100);
    assert_eq!(b.take().map(|t| t.0), Some(f3));
    assert_eq!(b.ring.produced(), 2, "f2 was cut short and is not delivered");
}

#[test]
fn a_ring_that_refuses_a_slot_costs_that_frame_only() {
    let mut b = streaming();
    // Another producer holds the ring for a while.
    let held = b.ring.claim().expect("the capture task's claim");
    held[0] = 1;
    b.send_frame(&jpeg(1, 300), 100);
    assert!(b.take().is_none());
    assert_eq!(b.uvc.borrow().stats().refused, 1);
    b.ring.abort();
    let g = jpeg(2, 300);
    b.send_frame(&g, 100);
    assert_eq!(b.take().map(|t| t.0), Some(g));
}

#[test]
fn the_stream_stops_when_nobody_has_read_for_a_while_and_restarts_when_somebody_does() {
    let mut b = streaming();
    let slot = b.rig.slot_of(&b.dev) as usize;
    b.ring.detach(CONSUMER);
    // Not at once: a reader that comes and goes does not cost a restart.
    b.run(100);
    assert_eq!(b.state(), State::Streaming);
    b.run((IDLE_STOP_US / 1000) as u32 + 50);
    assert_eq!(b.state(), State::Ready);
    // Setting 0 again, the endpoint gone.
    let alts = b.requests_of(11);
    assert_eq!((alts.len(), alts[1].0[2]), (2, 0), "SET_INTERFACE(0) after the stream");
    assert_eq!(b.rig.hw.ep_info(slot, 3).3, 0, "endpoint disabled");
    // A reader again: committed again, streaming again.
    b.ring.attach(CONSUMER);
    assert!(b.until(|b| b.state() == State::Streaming, 200));
    assert_eq!(b.requests_of(0x01).iter().filter(|(s, _)| s[3] == 2).count(), 2, "COMMIT at each start");
    assert_eq!(b.rig.hw.ep_info(slot, 3).3, 1);
    b.send_frame(&jpeg(1, 200), 100);
    b.send_frame(&jpeg(2, 200), 100);
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(2, 200)));
}

#[test]
fn a_reader_that_returns_in_time_keeps_the_stream() {
    let mut b = streaming();
    b.ring.detach(CONSUMER);
    b.run(200);
    b.ring.attach(CONSUMER);
    b.run((IDLE_STOP_US / 1000) as u32 + 100);
    assert_eq!(b.state(), State::Streaming);
    assert_eq!(b.requests_of(11).len(), 1);
}

#[test]
fn unplugging_a_streaming_camera_frees_the_driver_for_the_next() {
    let mut b = streaming();
    b.ring.detach(CONSUMER);
    b.rig.hw.detach_root(1);
    assert!(b.until(|b| b.state() == State::Idle, 400), "{:?}", b.state());
    assert!(b.uvc.borrow().claim().is_none());
    // The same driver takes the next camera.
    let dev = b.cam.device(3);
    dev.borrow_mut().canned.push((0xa1, 0x81, probe_block(34, 1, 1, 2, 1_000_000, 38_400, 400)));
    b.dev = dev.clone();
    b.rig.hw.attach_root(1, dev);
    b.negotiate();
    b.start();
    b.send_frame(&jpeg(0, 200), 100);
    b.send_frame(&jpeg(1, 200), 100);
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(1, 200)));
}

#[test]
fn a_second_camera_is_declined_while_one_is_driven() {
    let mut b = bench();
    b.negotiate();
    let other = Cam::new().device(3);
    b.rig.hw.attach_root(2, other.clone());
    b.run(2500);
    assert_eq!(b.uvc.borrow().stats().declined, 1);
    assert_eq!(b.state(), State::Ready, "the first camera is not disturbed");
}

// ---- Other cameras: bulk, raw pixels, UVC 1.0, super speed ----

/// A frame of YUY2 pixels for frame number `n`: every byte tells which.
fn yuyv(n: u8, w: usize, h: usize) -> Vec<u8> {
    (0..w * h * 2).map(|i| (i as u8).wrapping_mul(3).wrapping_add(n)).collect()
}

#[test]
fn a_bulk_camera_streams_over_the_bulk_endpoint_with_no_setting_to_select() {
    let mut b: Bench<8192> = Bench::answered(Cam::bulk(), 3, 3000);
    b.negotiate();
    assert_eq!(b.uvc.borrow().mode(), Some(Mode::Bulk { endpoint: 0x82, mps: 512 }));
    b.start();
    assert!(b.requests_of(11).is_empty(), "a bulk camera has one setting");
    // Transfers of the payload size rounded up to the packet size, as Normal
    // TRBs.
    b.send_frame(&jpeg(0, 300), 100);
    let slot = b.rig.slot_of(&b.dev) as usize;
    let first = b.rig.hw.first_trbs(slot, 5);
    assert!(!first.is_empty());
    assert!(first.iter().all(|t| (t[3] >> 10) & 0x3f == 1 && t[2] & 0x1_ffff == 3072), "{first:08x?}");
    for n in 1..=3 {
        b.send_frame(&jpeg(n, 200 + n as usize), 100);
        assert_eq!(b.take().map(|t| t.0), Some(jpeg(n, 200 + n as usize)));
    }
}

#[test]
fn a_stalled_bulk_stream_is_cleared_on_the_device_and_goes_on() {
    let mut b: Bench<8192> = Bench::answered(Cam::bulk(), 3, 3000);
    b.negotiate();
    b.start();
    b.send_frame(&jpeg(0, 300), 100);
    let slot = b.rig.slot_of(&b.dev) as usize;
    b.rig.hw.inject_error(slot, 5, 6);
    b.send_frame(&jpeg(1, 300), 100);
    // CLEAR_FEATURE(ENDPOINT_HALT) on endpoint 0x82 reached the camera.
    let clears: Vec<_> = b.requests_of(1).into_iter().filter(|(s, _)| s[0] == 0x02).collect();
    assert_eq!(clears.len(), 1);
    assert_eq!(clears[0].0[4], 0x82);
    // Whatever frame the stall cost, the next ones arrive.
    for n in 2..=3 {
        b.send_frame(&jpeg(n, 300), 100);
    }
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(3, 300)));
    assert_eq!(b.state(), State::Streaming);
}

#[test]
fn raw_pixels_are_delivered_as_a_yuyv_frame_with_its_size() {
    let mut cam = Cam::new();
    cam.formats.remove(0);
    let mut b: Bench<40960> = Bench::answered_for(cam, 3, 1, 1, 1000);
    b.negotiate();
    let c = b.uvc.borrow().stream_choice().unwrap();
    assert_eq!((c.pixels, c.width, c.height), (Pixels::Yuyv, 160, 120));
    b.start();
    b.send_frame(&yuyv(0, 160, 120), 900);
    for n in 1..=2 {
        let f = yuyv(n, 160, 120);
        b.send_frame(&f, 900);
        let (got, info, _) = b.take().unwrap();
        assert_eq!(info, FrameInfo::yuyv(160, 120));
        assert!(got == f, "frame {n}");
    }
}

#[test]
fn a_raw_frame_of_the_wrong_size_is_dropped() {
    let mut cam = Cam::new();
    cam.formats.remove(0);
    let mut b: Bench<40960> = Bench::answered_for(cam, 3, 1, 1, 1000);
    b.negotiate();
    b.start();
    b.send_frame(&yuyv(0, 160, 120), 900);
    let mut short = yuyv(1, 160, 120);
    short.truncate(38_000);
    b.send_frame(&short, 900);
    assert!(b.take().is_none());
    b.send_frame(&yuyv(2, 160, 120), 900);
    assert!(b.take().is_some());
}

#[test]
fn a_uvc_1_0_camera_is_sent_the_26_byte_block() {
    let mut cam = Cam::new();
    cam.bcd_uvc = 0x0100;
    let mut b: Bench<8192> = Bench::answered(cam, 3, 400);
    b.negotiate();
    b.start();
    let sets: Vec<_> = b.requests_of(0x01).into_iter().filter(|(s, _)| s[0] == 0x21).collect();
    assert_eq!(sets.len(), 2, "PROBE and COMMIT");
    for (s, data) in &sets {
        assert_eq!((s[6], data.len()), (26, 26));
    }
    assert_eq!(b.requests_of(0x81).iter().map(|(s, _)| s[6]).collect::<Vec<_>>(), [26]);
}

#[test]
fn a_super_speed_camera_streams_big_intervals_without_a_buffer_crossing_64k() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![
        Alt { mps_word: 1024, interval: 1, companion: Some((7, 1, 16384)) },
        Alt { mps_word: 1024, interval: 1, companion: Some((15, 2, 49152)) },
    ]);
    // 40000 bytes per interval: the second setting, 48 KiB transfers.
    let mut b: Bench<131072> = Bench::answered(cam, 4, 40000);
    b.negotiate();
    assert_eq!(b.uvc.borrow().mode(), Some(Mode::Isoch { alt: 2, endpoint: 0x81, bytes: 49152 }));
    b.start();
    let slot = b.rig.slot_of(&b.dev) as usize;
    let frames: Vec<Vec<u8>> = (0..3).map(|n| jpeg(n, 100_000)).collect();
    for f in &frames {
        b.send_frame(f, 40_000);
    }
    assert_eq!(b.take().map(|t| t.0.len()), Some(100_000));
    for t in b.rig.hw.first_trbs(slot, 3) {
        let (buf, len) = (t[0] as u64 | (t[1] as u64) << 32, (t[2] & 0x1_ffff) as u64);
        assert_eq!(len, 49152);
        assert!((buf & 0xffff) + len <= 0x1_0000, "a TRB across a 64 KiB boundary: {buf:#x} + {len}");
        assert_eq!(t[3] & 1 << 4, 0, "one TRB per interval");
        assert_eq!(((t[3] >> 7) & 3, (t[3] >> 16) & 0xf), (2, 15), "TBC, TLBPC of 48 packets in bursts of 16");
    }
}

#[test]
fn a_full_speed_camera_streams_on_a_millisecond_interval() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![
        Alt { mps_word: 128, interval: 1, companion: None },
        Alt { mps_word: 256, interval: 1, companion: None },
        Alt { mps_word: 1023, interval: 1, companion: None },
    ]);
    let mut b: Bench<8192> = Bench::answered(cam, 1, 200);
    b.negotiate();
    assert_eq!(b.uvc.borrow().mode(), Some(Mode::Isoch { alt: 2, endpoint: 0x81, bytes: 256 }));
    b.start();
    b.send_frame(&jpeg(0, 300), 100);
    b.send_frame(&jpeg(1, 300), 100);
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(1, 300)));
}

// ---- A camera that cannot be driven ----

#[test]
fn a_camera_that_answers_probe_with_another_frame_is_failed() {
    let cam = Cam::new();
    let dev = cam.device(3);
    // The first frame (320x240) instead of the 160x120 asked for.
    dev.borrow_mut().canned.push((0xa1, 0x81, probe_block(34, 1, 1, 1, 1_000_000, 153_600, 400)));
    let mut b: Bench<8192> = Bench::with(cam, dev, Want { width: 160, height: 120, fps: 10, max_frame: 8192, max_jpeg: 8192 });
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::Negotiation));
}

#[test]
fn a_camera_that_stalls_probe_or_asks_for_no_payload_is_failed() {
    let cam = Cam::new();
    let dev = cam.device(3);
    dev.borrow_mut().stall_requests.push(0x01);
    let mut b: Bench<8192> = Bench::with(cam.clone(), dev, Want { width: 160, height: 120, fps: 10, max_frame: 8192, max_jpeg: 8192 });
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::Negotiation));
    // dwMaxPayloadTransferSize 0: no bandwidth to select a setting by.
    let mut b: Bench<8192> = Bench::answered(cam, 3, 0);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::Negotiation));
}

#[test]
fn a_camera_that_needs_more_than_any_setting_carries_is_failed_for_want_of_bandwidth() {
    let mut b: Bench<8192> = Bench::answered(Cam::new(), 3, 1025);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::Bandwidth));
}

#[test]
fn a_camera_with_no_format_that_fits_is_failed() {
    let mut cam = Cam::new();
    cam.formats.remove(0);
    // 160x120 YUY2 is 38400 bytes: the slot is 8192.
    let mut b: Bench<8192> = Bench::answered(cam, 3, 400);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::NoFormat));
}

#[test]
fn a_camera_whose_streaming_interface_has_no_endpoint_is_failed() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![]);
    let mut b: Bench<8192> = Bench::answered(cam, 3, 400);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::NoEndpoint));
}

#[test]
fn a_failed_camera_is_forgotten_when_it_is_unplugged() {
    let mut b: Bench<8192> = Bench::answered(Cam::new(), 3, 1025);
    b.negotiate();
    assert_eq!(b.state(), State::Failed(Fail::Bandwidth));
    b.rig.hw.detach_root(1);
    assert!(b.until(|b| b.state() == State::Idle, 500), "{:?}", b.state());
}

#[test]
fn a_stream_that_delivers_nothing_is_restarted_and_then_given_up() {
    let mut b = bench();
    b.negotiate();
    b.start();
    // Nothing arrives. After the stall limit: stop, setting 0, commit,
    // setting 2 again.
    assert!(b.until(|b| b.uvc.borrow().stats().restarts == 1 && b.state() == State::Streaming, 8000));
    assert_eq!(b.requests_of(11).iter().map(|(s, _)| s[2]).collect::<Vec<_>>(), [2, 0, 2]);
    // And again, until the camera is given up on.
    assert!(b.until(|b| matches!(b.state(), State::Failed(_)), 40_000));
    assert_eq!(b.state(), State::Failed(Fail::NoFrames));
    assert_eq!(b.uvc.borrow().stats().restarts, 5);
}

#[test]
fn a_frame_between_restarts_resets_the_count() {
    let mut b = streaming();
    // Four silent periods, then a frame, then four more: never given up.
    for _ in 0..2 {
        for r in 1..=4u32 {
            let want = b.uvc.borrow().stats().restarts + 1;
            assert!(b.until(|b| b.uvc.borrow().stats().restarts == want && b.state() == State::Streaming, 8000), "restart {r}");
        }
        b.send_frame(&jpeg(1, 200), 100);
        b.send_frame(&jpeg(2, 200), 100);
        assert_eq!(b.state(), State::Streaming);
    }
}

#[test]
fn a_lost_interval_between_two_frames_spoils_the_next_frame() {
    let mut b = streaming();
    let slot = b.rig.slot_of(&b.dev) as usize;
    b.send_frame(&jpeg(1, 300), 100);
    assert!(b.take().is_some());
    // The interval that held the first payload of the next frame is lost.
    b.rig.hw.inject_error(slot, 3, cc::MISSED_SERVICE);
    b.send_frame(&jpeg(2, 300), 100);
    assert!(b.take().is_none(), "a frame that may be missing its head must not be delivered");
    b.send_frame(&jpeg(3, 300), 100);
    assert_eq!(b.take().map(|t| t.0), Some(jpeg(3, 300)));
}

#[test]
fn a_camera_that_fails_while_starting_gives_its_pipe_back() {
    let cam = Cam::new();
    let dev = cam.device(3);
    dev.borrow_mut().canned.push((0xa1, 0x81, probe_block(34, 1, 1, 2, 1_000_000, 38_400, 400)));
    let mut b: Bench<8192> = Bench::with(cam, dev.clone(), Want { width: 160, height: 120, fps: 10, max_frame: 8192, max_jpeg: 8192 });
    b.negotiate();
    assert_eq!(b.state(), State::Ready);
    // SET_INTERFACE stalls: the pipe was opened before it.
    dev.borrow_mut().stall_requests.push(11);
    b.ring.attach(CONSUMER);
    assert!(b.until(|b| matches!(b.state(), State::Failed(_)), 400));
    assert_eq!(b.state(), State::Failed(Fail::Transport));
    b.run(5);
    let slot = b.rig.slot_of(&dev) as usize;
    assert_eq!(b.rig.hw.ep_info(slot, 3).3, 0, "the endpoint is dropped, the bandwidth is free");
}
