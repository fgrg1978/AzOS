// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the audio server (`userspace/services/audiod`).
//!
//! `mixer.rs` and `server.rs` are pulled in with `#[path]`, so the code under
//! test is the code `AUDIOD.ELF` is built from. The server asks the world for
//! everything through its `Env` trait; here the world is a heap (the clients'
//! queues and arenas, the device's) and a fake device that plays what is
//! posted to it and returns the periods, so a test is a client, the server and
//! the device in one thread, one `tick` at a time.
//!
//! Every test names the canary that turns it red.

#[allow(dead_code)]
#[path = "../../../../userspace/services/audiod/src/mixer.rs"]
pub mod mixer;

#[allow(dead_code)]
#[path = "../../../../userspace/services/audiod/src/server.rs"]
pub mod server;

#[cfg(test)]
mod mix {
    use crate::mixer::{self, accumulate, finish, headroom_gain, mix, Source, GAIN_UNITY};

    fn pcm(v: &[i16]) -> Vec<u8> {
        v.iter().flat_map(|s| s.to_le_bytes()).collect()
    }

    fn samples(b: &[u8]) -> Vec<i16> {
        b.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect()
    }

    /// Two loud streams are a flat top, not a wrap to the other sign.
    ///
    /// **Canary.** Replace the clamp in `finish` with `as i16` (a wrap): the
    /// positive pair reads -1536 and the negative pair 1536.
    #[test]
    fn a_mix_saturates_it_never_wraps() {
        let a = pcm(&[30_000, -30_000, 100, i16::MAX, i16::MIN]);
        let b = pcm(&[30_000, -30_000, 100, i16::MAX, i16::MIN]);
        let mut out = vec![0u8; a.len()];
        mix(&mut out, &[Source { pcm: &a, gain: GAIN_UNITY }, Source { pcm: &b, gain: GAIN_UNITY }]);
        assert_eq!(samples(&out), [i16::MAX, i16::MIN, 200, i16::MAX, i16::MIN]);
    }

    /// Many streams add in 32 bits: thirty-two full-scale streams do not wrap
    /// the accumulator on the way to the clamp.
    ///
    /// **Canary.** Make `acc` in `mix` an `i16` array: the sum wraps before it
    /// is clamped and the sign flips.
    #[test]
    fn thirty_two_streams_add_without_wrapping() {
        let one = pcm(&[i16::MAX; 8]);
        let sources: Vec<Source> = (0..32).map(|_| Source { pcm: &one, gain: GAIN_UNITY }).collect();
        let mut out = vec![0u8; one.len()];
        mix(&mut out, &sources);
        assert!(samples(&out).iter().all(|&s| s == i16::MAX));
    }

    /// Two streams of the same wave sum at the gain `headroom_gain(2)` gives
    /// each: the sum is the one wave at 4/3, exactly, in integer arithmetic.
    ///
    /// **Canary.** Let `headroom_gain(2)` return the unity: the sum is 2.0 and
    /// the expected 11998 is 18000.
    #[test]
    fn two_streams_mix_at_their_headroom_gain() {
        let w = pcm(&[9_000, -9_000, 3_000]);
        let g = headroom_gain(2);
        assert_eq!(g, 2 * GAIN_UNITY / 3);
        let mut out = vec![0u8; w.len()];
        mix(&mut out, &[Source { pcm: &w, gain: g }, Source { pcm: &w, gain: g }]);
        // 9000 * 21845 >> 15 is 5999 (and -9000's is -6000: the shift floors),
        // 3000's is 1999; each twice.
        assert_eq!(samples(&out), [11_998, -12_000, 3_998]);
    }

    /// The headroom never lets n equal streams sum past twice one stream's
    /// level, however many there are, and is unity for one.
    ///
    /// **Canary.** Return `GAIN_UNITY / 2` for every n: n = 1 is no longer
    /// unity and the first assert fails.
    #[test]
    fn headroom_bounds_the_sum_by_two() {
        assert_eq!(headroom_gain(0), GAIN_UNITY);
        assert_eq!(headroom_gain(1), GAIN_UNITY);
        for n in 2..=32usize {
            let sum = n as u64 * headroom_gain(n) as u64;
            assert!(sum < 2 * GAIN_UNITY as u64, "n = {n}: {sum}");
            assert!(headroom_gain(n) < headroom_gain(n - 1), "more streams, less each");
        }
    }

    /// A source that ends early contributes silence for the rest of the pass
    /// and nothing else changes: the other stream's samples are exactly what
    /// they would have been alone.
    ///
    /// **Canary.** Make `accumulate` repeat the last sample of a short source
    /// instead of stopping: the tail of the pass is no longer the long
    /// stream's alone.
    #[test]
    fn the_underrun_of_one_source_is_silence_from_it_only() {
        let long = pcm(&[1_000; 8]);
        let short = pcm(&[500; 3]);
        let mut both = vec![0u8; long.len()];
        mix(&mut both, &[Source { pcm: &long, gain: GAIN_UNITY }, Source { pcm: &short, gain: GAIN_UNITY }]);
        assert_eq!(samples(&both), [1_500, 1_500, 1_500, 1_000, 1_000, 1_000, 1_000, 1_000]);
        let mut alone = vec![0u8; long.len()];
        mix(&mut alone, &[Source { pcm: &long, gain: GAIN_UNITY }]);
        assert_eq!(samples(&alone)[3..], samples(&both)[3..]);
    }

    /// A stream is never louder than it was written: a gain past unity is
    /// unity.
    ///
    /// **Canary.** Drop the `min(GAIN_UNITY)`: the sample doubles.
    #[test]
    fn a_gain_past_unity_is_unity() {
        let mut acc = [0i32; 2];
        accumulate(&mut acc, &pcm(&[1_000, -1_000]), GAIN_UNITY * 2);
        assert_eq!(acc, [1_000, -1_000]);
        let mut out = [0u8; 4];
        finish(&acc, &mut out);
        assert_eq!(samples(&out), [1_000, -1_000]);
    }

    /// The accumulator size is the one `server.rs` budgets passes by.
    #[test]
    fn the_pass_holds_a_period_of_eight_thousand_samples() {
        assert_eq!(mixer::ACC_MAX, 8192);
    }
}

#[cfg(test)]
mod world;

#[cfg(test)]
mod streams {
    use crate::server::{IDLE_NS, RETRY_NS, STALL_NS};
    use crate::world::{call, params, pump, server, server_with, limits, Client, device_info};
    use azos_devif::outcome;
    use azos_devif::sound::{
        Params, Period, Sound, DIR_PLAYBACK, FMT_S16, NO_PERIOD, PERIOD_CANCELLED, PERIOD_END, PERIOD_XRUN, SLOT_WORDS, STATE_DRAINING,
        STATE_OPEN, STATE_RUNNING,
    };

    /// Whole 1024-frame periods: one device period each.
    fn big() -> Params {
        Params { period_frames: 1024, ..params() }
    }

    fn ok<T: Default>(o: azos_devif::Out<T>) -> T {
        assert_eq!(o.code, outcome::OK, "the call was refused");
        o.value
    }

    /// A queue the client made read-only is refused, not mapped and used: the
    /// server writes both queues (the consumer moves the tail), so it would
    /// fault on the first period. A read-only arena is fine: it is only read.
    ///
    /// **Canary.** Drop the `!r.rw || !d.rw` check in `open_inner`: the open is
    /// accepted.
    #[test]
    fn a_read_only_queue_is_refused_and_a_read_only_arena_is_not() {
        let (mut srv, w) = server();
        for ro in [1u32, 2] {
            let c = Client::new(&w, 7, [1, 2, 3], &params());
            w.borrow_mut().read_only = vec![ro];
            assert_eq!(c.open(&mut srv, params()).code, outcome::BAD_ARGUMENT, "cap {ro} read-only");
            assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        }
        let c = Client::new(&w, 7, [1, 2, 3], &params());
        w.borrow_mut().read_only = vec![3];
        assert_eq!(c.open(&mut srv, params()).code, outcome::OK);
    }

    /// What `open` takes and refuses. A refused open gives back the three
    /// objects it was moved (the server has no use for them), and an open that
    /// is accepted keeps them.
    ///
    /// **Canary.** Delete the `release_all` in `Sound::open`'s refusal arm:
    /// `released` stays empty for every refusal.
    #[test]
    fn open_checks_the_stream_and_gives_back_what_it_refuses() {
        let (mut srv, w) = server();
        // Unidentified: no badge.
        let c = Client::new(&w, 0, [1, 2, 3], &params());
        assert_eq!(c.open(&mut srv, params()).code, outcome::DENIED);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        // Not the device's rate, channels or format.
        for bad in [
            Params { rate_hz: 44_100, ..params() },
            Params { channels: 1, ..params() },
            Params { format: azos_devif::sound::FMT_F32, ..params() },
            Params { period_frames: 32, ..params() },
        ] {
            let c = Client::new(&w, 7, [1, 2, 3], &bad.check().map(|_| bad).unwrap_or(params()));
            assert_eq!(c.open(&mut srv, bad).code, outcome::UNSUPPORTED, "{bad:?}");
            assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        }
        // Outside the interface's bounds, and over this build's.
        let c = Client::new(&w, 7, [1, 2, 3], &params());
        assert_eq!(c.open(&mut srv, Params { periods: 1, ..params() }).code, outcome::BAD_ARGUMENT);
        assert_eq!(c.open(&mut srv, Params { periods: 32, ..params() }).code, outcome::BAD_ARGUMENT, "over max_periods");
        w.borrow_mut().released.clear();
        // Objects too small: an arena short of its periods, a queue with no room.
        let short = Client::new(&w, 7, [1, 2, 3], &Params { periods: 2, ..params() });
        assert_eq!(short.open(&mut srv, params()).code, outcome::BAD_ARGUMENT, "arena of two periods for four");
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        w.borrow_mut().add(2, 300);
        assert_eq!(short.open(&mut srv, params()).code, outcome::BAD_ARGUMENT, "a queue with no slot");
        w.borrow_mut().released.clear();
        // An open that is right.
        let c = Client::new(&w, 7, [1, 2, 3], &params());
        let o = ok(c.open(&mut srv, params()));
        assert_eq!(o.period_bytes, 1024);
        assert!(w.borrow().released.is_empty(), "an accepted stream keeps its objects");
        // One stream per badge.
        let again = Client::new(&w, 7, [4, 5, 6], &params());
        assert_eq!(again.open(&mut srv, params()).code, outcome::BUSY);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [4, 5, 6], "only the refused objects go back");
        // And a table of four.
        for b in 8..11 {
            let n = b * 10;
            let c = Client::new(&w, b, [n, n + 1, n + 2], &params());
            ok(c.open(&mut srv, params()));
        }
        let c = Client::new(&w, 11, [200, 201, 202], &params());
        assert_eq!(c.open(&mut srv, params()).code, outcome::BUSY, "AUDIO_MAX_STREAMS");
        assert_eq!(srv.open_streams(), 4);
    }

    /// A stream's life: open, prime, start, the device opens and plays what was
    /// posted in order, every period comes back, a drain ends with the end
    /// marker, the device is drained and closed when nothing runs, and close
    /// lets go of the three objects.
    ///
    /// **Canary.** In `tick`, skip `drain_device` when `live == 0`: the device
    /// is never closed and `dev_closes` stays 0. Skip `give_end` in the drain
    /// finish: no end marker.
    #[test]
    fn a_stream_plays_through_the_device_and_ends_with_the_marker() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &big());
        ok(c.open(&mut srv, big()));
        assert!(c.post(0, 1024, 1000) && c.post(1, 1024, 2000));
        assert_eq!(w.borrow().dev_opens, 0, "the device is not opened for a stream that is not running");
        ok(call(&mut srv, 7, |s| s.start()));
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).state, STATE_RUNNING);
        pump(&mut srv, &w, 1, 5);
        assert_eq!(w.borrow().dev_opens, 1);
        let played = w.borrow_mut().take_played();
        assert_eq!(played.len(), 2 * 2048, "two device periods were primed");
        assert!(played[..2048].iter().all(|&s| s == 1000), "period 0 first");
        assert!(played[2048..].iter().all(|&s| s == 2000), "then period 1");
        let back = c.returned();
        assert_eq!(back.iter().map(|p| (p.index, p.frames, p.flags)).collect::<Vec<_>>(), [(0, 1024, 0), (1, 1024, 0)]);

        ok(call(&mut srv, 7, |s| s.drain()));
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).state, STATE_DRAINING);
        pump(&mut srv, &w, 3, 5);
        let back = c.returned();
        let end = back.last().expect("the end marker came");
        assert_eq!((end.index, end.flags), (NO_PERIOD, PERIOD_END));
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).state, STATE_OPEN);
        pump(&mut srv, &w, 4, 5);
        assert_eq!((w.borrow().dev_closes, srv.device_open()), (1, false), "nothing runs: the device was drained and closed");

        ok(call(&mut srv, 7, |s| s.close()));
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        assert_eq!(srv.open_streams(), 0);
        // Closing again, and calling with no stream, are served.
        ok(call(&mut srv, 7, |s| s.close()));
        assert_eq!(call(&mut srv, 7, |s| s.start()).code, outcome::NOT_READY);
        assert_eq!(call(&mut srv, 7, |s| s.drain()).code, outcome::NOT_READY);
    }

    /// Two streams at once are one stream on the device: the periods are
    /// summed at the headroom gain, each client gets its periods back, and the
    /// device was opened once.
    ///
    /// **Canary.** Mix each stream at unity: the 9998 is 15000. Leave `peak`
    /// at 0: the summary line says one stream at most.
    #[test]
    fn two_streams_are_mixed_into_the_one_device_stream() {
        let (mut srv, w) = server();
        let a = Client::new(&w, 7, [1, 2, 3], &big());
        let b = Client::new(&w, 8, [11, 12, 13], &big());
        ok(a.open(&mut srv, big()));
        ok(b.open(&mut srv, big()));
        assert!(a.post(0, 1024, 6000) && b.post(0, 1024, 9000));
        ok(call(&mut srv, 7, |s| s.start()));
        ok(call(&mut srv, 8, |s| s.start()));
        assert_eq!(srv.live_streams(), 2);
        pump(&mut srv, &w, 1, 5);
        let played = w.borrow_mut().take_played();
        // 6000 * 2/3 >> 15 and 9000 * 2/3 >> 15 are 3999 and 5999.
        assert!(played[..2048].iter().all(|&s| s == 9_998), "{:?}", &played[..4]);
        assert_eq!(w.borrow().dev_opens, 1);
        assert_eq!(a.returned().len(), 1);
        assert_eq!(b.returned().len(), 1);
        // The second pass had neither stream's data: silence, not a repeat.
        assert!(played[2048..].iter().all(|&s| s == 0));
        // When they have ended the device is closed and the console says what
        // it carried: the line the gate's two-beeps row looks for.
        ok(call(&mut srv, 7, |s| s.drain()));
        ok(call(&mut srv, 8, |s| s.drain()));
        pump(&mut srv, &w, 8, 5);
        assert_eq!(w.borrow().dev_closes, 1);
        let line = w.borrow().logs.iter().find(|l| l.contains("playback ended")).cloned().expect("the stream's summary");
        assert!(line.ends_with(", most streams at once 2\n") && line.starts_with("[audiod] playback ended: periods "), "{line:?}");
    }

    /// A stream that runs dry underruns alone: its next returned period is
    /// flagged, the other stream's periods are not, and the device goes on.
    ///
    /// **Canary.** Set `xrun_owed` on every running stream when one underruns:
    /// A's period carries the flag too.
    #[test]
    fn the_underrun_of_one_stream_does_not_touch_the_other() {
        let (mut srv, w) = server();
        let a = Client::new(&w, 7, [1, 2, 3], &big());
        let b = Client::new(&w, 8, [11, 12, 13], &big());
        ok(a.open(&mut srv, big()));
        ok(b.open(&mut srv, big()));
        assert!(a.post(0, 1024, 6000) && a.post(1, 1024, 6000) && b.post(0, 1024, 9000));
        ok(call(&mut srv, 7, |s| s.start()));
        ok(call(&mut srv, 8, |s| s.start()));
        pump(&mut srv, &w, 1, 5);
        // Pass one: both. Pass two: A alone, B dry.
        let played = w.borrow_mut().take_played();
        assert!(played[..2048].iter().all(|&s| s == 9_998));
        assert!(played[2048..].iter().all(|&s| s == 3_999), "A alone, B contributed silence");
        assert_eq!(ok(call(&mut srv, 8, |s| s.status())).xruns, 1);
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).xruns, 0);
        assert!(a.returned().iter().all(|p| p.flags == 0));
        assert_eq!(b.returned().iter().map(|p| p.flags).collect::<Vec<_>>(), [0]);
        // B posts again: the period it gets back says where the gap was.
        assert!(b.post(1, 1024, 1000));
        pump(&mut srv, &w, 1, 5);
        let b_back = b.returned();
        assert_eq!(b_back.len(), 1);
        assert_eq!((b_back[0].index, b_back[0].flags), (1, PERIOD_XRUN));
        assert_eq!(w.borrow().dev_closes, 0, "the device did not stop");
        assert!(w.borrow().dev_periods >= 4);
    }

    /// `stop` hands back everything the server holds, cancelled: the periods
    /// posted and not yet taken, and the end marker too when it cuts a drain.
    ///
    /// **Canary.** Make `stop` only set the state: the posted periods are not
    /// returned.
    #[test]
    fn stop_cancels_what_the_server_holds() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &big());
        ok(c.open(&mut srv, big()));
        assert!(c.post(0, 1024, 1) && c.post(1, 1024, 1) && c.post(2, 1024, 1));
        ok(call(&mut srv, 7, |s| s.start()));
        ok(call(&mut srv, 7, |s| s.drain()));
        ok(call(&mut srv, 7, |s| s.stop()));
        let back = c.returned();
        let cancelled: Vec<_> = back.iter().filter(|p| p.flags == PERIOD_CANCELLED).map(|p| p.index).collect();
        assert_eq!(cancelled, [0, 1, 2]);
        assert!(back.iter().any(|p| p.flags == PERIOD_END), "a stop that cuts a drain ends it");
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).state, STATE_OPEN);
        // The periods are the client's again: posting one is accepted.
        assert!(c.post(0, 1024, 1));
    }

    /// A client's slots are not trusted: an index outside the arena, an empty
    /// or oversize period, flags set, a field wider than its type and a time
    /// stamp are consumed and ignored, and nothing outside the arena is read.
    /// The valid periods around them are played, in order.
    ///
    /// **Canary.** Remove the `p.check` in `next_posted`: index 99 is read
    /// from beyond the arena (a different sample, or a fault) and the period
    /// count differs.
    #[test]
    fn hostile_slots_are_ignored() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &big());
        ok(c.open(&mut srv, big()));
        let junk: [[u64; SLOT_WORDS]; 6] = [
            [99, 1024, 0, 0],
            [0, 0, 0, 0],
            [0, 1025, 0, 0],
            [0, 1024, 1, 0],
            [u64::MAX, 1024, 0, 0],
            [0, 1024, 0, 77],
        ];
        for j in junk {
            assert!(c.post_raw(j));
        }
        assert!(c.post(0, 1024, 1000));
        assert!(c.post(1, 1024, 2000));
        ok(call(&mut srv, 7, |s| s.start()));
        pump(&mut srv, &w, 1, 5);
        let played = w.borrow_mut().take_played();
        assert!(played[..2048].iter().all(|&s| s == 1000) && played[2048..4096].iter().all(|&s| s == 2000), "{:?}", &played[..3]);
        let idx: Vec<u32> = c.returned().iter().map(|p| p.index).collect();
        assert_eq!(idx, [0, 1], "the junk was consumed and never returned as a period");
    }

    /// A client period longer than the device's is consumed across device
    /// periods, and one shorter is carried into the next: the frames are all
    /// played, in order, exactly once.
    ///
    /// **Canary.** Reset `pos` to 0 at each pass: the second half of the
    /// period is never reached.
    #[test]
    fn client_periods_are_cut_to_the_device_period() {
        let (mut srv, w) = server();
        let p = Params { period_frames: 2048, periods: 2, ..params() };
        let c = Client::new(&w, 7, [1, 2, 3], &p);
        ok(c.open(&mut srv, p));
        // Two frames' worth of ramp so a skipped or repeated half shows.
        let ch = 2usize;
        let arena = unsafe { std::slice::from_raw_parts_mut(c.arena as *mut u8, 2 * 2048 * 4) };
        for (i, s) in arena.chunks_exact_mut(2).enumerate() {
            s.copy_from_slice(&((i / ch) as i16).to_le_bytes());
        }
        assert!(c.post_raw(Period { index: 0, frames: 2048, flags: 0, time_ns: 0 }.to_slot()));
        ok(call(&mut srv, 7, |s| s.start()));
        pump(&mut srv, &w, 1, 5);
        let played = w.borrow_mut().take_played();
        let frames: Vec<i16> = played.chunks_exact(2).map(|f| f[0]).collect();
        assert_eq!(frames.len(), 2048);
        assert!(frames.iter().enumerate().all(|(i, &f)| f == i as i16), "in order, once");
        let back = c.returned();
        assert_eq!(back.len(), 1, "returned once, whole, when its last frame was mixed");
        assert_eq!(back[0].frames, 2048);
    }

    /// A running stream that gives the mixer nothing for `STALL_NS` is a
    /// client that stopped: it is closed, its objects given back, and the
    /// device is drained and closed. One that keeps posting is not.
    ///
    /// **Canary.** Delete the `reap_stale` call in `tick`: the stalled stream
    /// is still open at the end.
    #[test]
    fn a_stalled_stream_is_closed_and_a_fed_one_is_not() {
        let (mut srv, w) = server();
        let fed = Client::new(&w, 7, [1, 2, 3], &big());
        let dead = Client::new(&w, 8, [11, 12, 13], &big());
        ok(fed.open(&mut srv, big()));
        ok(dead.open(&mut srv, big()));
        for i in 0..4 {
            assert!(fed.post(i, 1024, 100));
        }
        ok(call(&mut srv, 7, |s| s.start()));
        ok(call(&mut srv, 8, |s| s.start()));
        let steps = (STALL_NS / 21_000_000) as usize + 40;
        for _ in 0..steps {
            pump(&mut srv, &w, 1, 21);
            for p in fed.returned() {
                if p.index != NO_PERIOD {
                    assert!(fed.post(p.index, 1024, 100));
                }
            }
        }
        assert_eq!(srv.open_streams(), 1, "only the dead client's stream was closed");
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [11, 12, 13]);
        assert!(w.borrow().logs.iter().any(|l| l.contains("client stopped")));
        assert_eq!(ok(call(&mut srv, 7, |s| s.status())).state, STATE_RUNNING);
    }

    /// A stream that is open and not running, and that nobody has called for a
    /// minute, is a client that died between `open` and `start`.
    ///
    /// **Canary.** Never touch `active_ns` on `start`: the started stream is
    /// closed by the idle rule too.
    #[test]
    fn an_idle_stream_is_closed_after_a_minute() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &big());
        ok(c.open(&mut srv, big()));
        w.borrow_mut().now += IDLE_NS - 1;
        srv.tick();
        assert_eq!(srv.open_streams(), 1);
        w.borrow_mut().now += 2;
        srv.tick();
        assert_eq!(srv.open_streams(), 0);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
    }

    /// A device that refuses its stream is tried again later, not every pass,
    /// and not never; the clients' stream stays open meanwhile.
    ///
    /// **Canary.** Drop the `retry_at` check: the device is opened (asked)
    /// every pass.
    #[test]
    fn a_device_that_refuses_is_retried_after_a_second() {
        let (mut srv, w) = server();
        w.borrow_mut().device_fails_open = true;
        let c = Client::new(&w, 7, [1, 2, 3], &big());
        ok(c.open(&mut srv, big()));
        assert!(c.post(0, 1024, 100));
        ok(call(&mut srv, 7, |s| s.start()));
        let calls = |w: &std::rc::Rc<std::cell::RefCell<crate::world::World>>| w.borrow().logs.iter().filter(|l| l.contains("refused the playback")).count();
        pump(&mut srv, &w, 3, 10);
        assert_eq!((calls(&w), w.borrow().dev_opens), (1, 0), "asked once, not every pass");
        w.borrow_mut().device_fails_open = false;
        pump(&mut srv, &w, 1, (RETRY_NS / 1_000_000) as u64 + 10);
        assert_eq!(w.borrow().dev_opens, 1);
        assert_eq!(srv.open_streams(), 1);
    }

    /// `info` is the device's with what this server does: signed 16-bit only,
    /// and capture only when the build has it.
    ///
    /// **Canary.** Report the device's `formats` unchanged: an F32 device
    /// would be offered a format the mixer cannot sum.
    #[test]
    fn info_is_the_device_with_what_the_mixer_does() {
        let (mut srv, _w) = server();
        assert_eq!(srv.info().code, outcome::NOT_READY, "before the device has been asked");
        srv.prepare();
        let i = ok(srv.info());
        let d = device_info();
        assert_eq!((i.rate_hz, i.channels), (d.rate_hz, d.channels));
        assert_eq!(i.formats, azos_devif::sound::format_bit(FMT_S16), "the device also takes F32; the mixer sums S16");
        assert_eq!(i.dirs, DIR_PLAYBACK | azos_devif::sound::DIR_CAPTURE);
        let (mut nocap, _w) = server_with(crate::server::Limits { capture: false, ..limits() });
        nocap.prepare();
        assert_eq!(ok(nocap.info()).dirs, DIR_PLAYBACK);
    }
}

#[cfg(test)]
mod capture {
    use crate::server::{Limits, LEASE_POLL_NS};
    use crate::world::{call, client_tid, limits, params, server, server_with, Client, SERVER_TID};
    use azos_devif::outcome;
    use azos_devif::sound::{self as snd, Params, Sound, Status, DIR_CAPTURE, STATE_RUNNING};

    fn rec() -> Params {
        Params { dir: DIR_CAPTURE, ..params() }
    }

    /// A server whose mixer was refused its deadline reservation serves no
    /// playback stream (`UNSUPPORTED`, the objects given back at once): mixing
    /// without a budget is the real-time work the reservation exists to bound.
    /// Capture, which the kernel moves, is served as before.
    ///
    /// **Canary.** Drop the `!self.playback` check in `open_inner`: the
    /// playback open is accepted.
    #[test]
    fn without_the_mixers_reservation_playback_is_refused_and_capture_is_not() {
        let (mut srv, w) = server();
        srv.set_playback(false);
        let c = Client::new(&w, 7, [1, 2, 3], &params());
        assert_eq!(c.open(&mut srv, params()).code, outcome::UNSUPPORTED);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        let k = Client::new(&w, 8, [4, 5, 6], &rec());
        assert_eq!(k.open(&mut srv, rec()).code, outcome::OK, "capture does not need the mixer");
    }

    /// Capture without the microphone effect is refused, and the refusal is
    /// the kernel's: the server asks it for every attempt (the kernel writes
    /// the `audio-capture` decision record; ring 3 cannot), passes `REFUSED`
    /// through, takes no lease, and gives the client's three objects back.
    ///
    /// **Canary.** Give the client the effect (`withheld` empty): the same
    /// open is admitted, a lease is taken and the objects are kept (the second
    /// half of this test says so). Make the server answer `REFUSED` itself
    /// without asking: `lease_open_calls` stays 0 and the first assert fails.
    /// Drop the `log_capture_attempt` call: the badge lines are missing.
    #[test]
    fn capture_without_the_effect_is_refused_by_the_kernel_gate_and_leaves_no_lease() {
        let (mut srv, w) = server();
        w.borrow_mut().withheld.push(client_tid(7));
        for n in 1..=2u32 {
            let c = Client::new(&w, 7, [1, 2, 3], &rec());
            assert_eq!(c.open(&mut srv, rec()).code, outcome::REFUSED);
            assert_eq!(w.borrow().lease_open_calls, n, "every attempt reaches the gate that records it");
            assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        }
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (0, false));
        assert!(!srv.busy());
        assert_eq!(
            w.borrow().logs.iter().filter(|l| l.contains("capture open by badge 7: refused by the gate")).count(),
            2,
            "each attempt names the badge, and the kernel's record the client behind it"
        );
        // The gate admits: the same call is a lease, and nothing is released.
        w.borrow_mut().withheld.clear();
        let c = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::OK);
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (1, true));
        assert!(w.borrow().released.is_empty());
        assert!(w.borrow().logs.iter().any(|l| l.contains("capture open by badge 7: admitted")));
    }

    /// **The microphone is the client's, not the server's.** Two clients of one
    /// server whose own class holds the effect: the one whose class has it
    /// listens, the one whose class does not is refused, and in both the
    /// decision record names the client, never the server.
    ///
    /// **Canaries.** Have the server open on its own account (`on_behalf` 0,
    /// or the fake gate deciding on `SERVER_TID`, which holds the effect): the
    /// client without the effect is admitted and the first assert is red.
    #[test]
    fn two_clients_one_with_the_mic_right_and_one_without_through_one_server() {
        let (mut srv, w) = server();
        let (with, without) = (client_tid(7), client_tid(8));
        w.borrow_mut().withheld.push(without);

        let b = Client::new(&w, 8, [11, 12, 13], &rec());
        assert_eq!(b.open(&mut srv, rec()).code, outcome::REFUSED, "its class has no mic effect; the server's has");
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (0, false));
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [11, 12, 13]);
        assert_eq!(w.borrow().gate, [(without, false, snd::MIC_NO_GRANT)], "the record names the client that asked");

        let a = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(a.open(&mut srv, rec()).code, outcome::OK, "its class has the effect");
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (1, true));
        assert_eq!(w.borrow().gate, [(without, false, snd::MIC_NO_GRANT), (with, true, snd::MIC_ADMITTED)]);

        // While the one listens the other is still refused for its own reason
        // first: a task without the effect learns nothing of the device.
        let b = Client::new(&w, 8, [21, 22, 23], &rec());
        assert_eq!(b.open(&mut srv, rec()).code, outcome::REFUSED);
        assert_eq!(w.borrow().gate.last(), Some(&(without, false, snd::MIC_NO_GRANT)));
        // A client with the effect is held off by the open stream, and named.
        let c = Client::new(&w, 9, [31, 32, 33], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::REFUSED);
        assert_eq!(w.borrow().gate.last(), Some(&(client_tid(9), false, snd::MIC_HELD)));
        assert!(w.borrow().gate.iter().all(|&(subject, ..)| subject != SERVER_TID), "the server is never the subject");
        assert_eq!(w.borrow().lease_open_calls, 4);
    }

    /// A client has no call of its own to name: a nonzero `on_behalf` from a
    /// client is a bad argument, refused before the kernel is asked, and its
    /// objects go back. Without a call being served the server asks for nobody.
    ///
    /// **Canaries.** Forward the client's word: the kernel is asked
    /// (`lease_open_calls` 1) and a made-up warrant names nobody (`REFUSED`).
    /// Drop the `call == 0` test in `open_capture`: the second half reaches the
    /// gate.
    #[test]
    fn a_client_names_no_call_and_a_server_without_one_asks_for_nobody() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(c.open_naming(&mut srv, rec(), 0xCA11_0000 + 8).code, outcome::BAD_ARGUMENT);
        assert_eq!((w.borrow().lease_open_calls, srv.open_streams()), (0, 0));
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        // Playback too: the word is for the capture open alone, but a client
        // never has one to give.
        assert_eq!(c.open_naming(&mut srv, params(), 5).code, outcome::BAD_ARGUMENT);
        // The server serving no call (the loop sets `call` before each dispatch).
        use azos_devif::Sound;
        srv.caller = 7;
        srv.call = 0;
        use crate::world::lend;
        let r = srv.open(rec(), lend(1), lend(2), lend(3), 0);
        srv.caller = 0;
        assert_eq!(r.code, outcome::DENIED);
        assert_eq!(w.borrow().lease_open_calls, 0, "nothing to ask the kernel on");
    }

    /// An unidentified caller is refused before the kernel is asked, and a
    /// build without capture never asks at all.
    ///
    /// **Canary.** Drop the `capture` check in `open_capture`: the second
    /// half reaches the gate.
    #[test]
    fn capture_is_refused_for_the_unbadged_and_unsupported_when_compiled_out() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 0, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::DENIED);
        assert_eq!(w.borrow().lease_open_calls, 0);
        let (mut off, w2) = server_with(Limits { capture: false, ..limits() });
        let c = Client::new(&w2, 7, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut off, rec()).code, outcome::UNSUPPORTED);
        assert_eq!(w2.borrow().lease_open_calls, 0, "nothing to decide, nothing asked");
        assert_eq!(std::mem::take(&mut w2.borrow_mut().released), [1, 2, 3]);
    }

    /// A lent stream is the kernel's: start, stop, drain and close are
    /// forwarded in order, its count is the kernel's, the objects are kept
    /// until close and given back after it, and a second client is refused
    /// without losing the first's.
    ///
    /// **Canary.** Treat a capture stream as a playback one in `start`: the
    /// forwarded list is empty.
    #[test]
    fn a_lent_capture_stream_is_forwarded_and_released_at_close() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::OK);
        w.borrow_mut().lease_status = Status { state: STATE_RUNNING, xruns: 2, frames: 99 };
        call(&mut srv, 7, |s| s.start());
        call(&mut srv, 7, |s| s.stop());
        call(&mut srv, 7, |s| s.drain());
        let st = call(&mut srv, 7, |s| s.status());
        assert_eq!((st.value.state, st.value.xruns, st.value.frames), (STATE_RUNNING, 2, 99));
        let other = Client::new(&w, 8, [11, 12, 13], &rec());
        assert_eq!(other.open(&mut srv, rec()).code, outcome::REFUSED, "one capture stream: the gate says held");
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [11, 12, 13]);
        call(&mut srv, 7, |s| s.close());
        assert_eq!(w.borrow().lease_calls, ["open", "start", "stop", "drain", "close"]);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        assert_eq!(srv.open_streams(), 0);
        // Only the holder's calls are forwarded.
        assert_eq!(call(&mut srv, 9, |s| s.start()).code, outcome::NOT_READY);
        assert_eq!(w.borrow().lease_calls.len(), 5);
    }

    /// One badge is one stream of either kind. A badge that has a playback
    /// stream is refused a capture one (BUSY, before the kernel is asked), and
    /// a badge that holds the capture lease is refused a playback one; in both
    /// the stream it had stays controllable and closes cleanly, and only the
    /// refused open's objects go back.
    ///
    /// **Canaries.** Drop the `slot_of` test in `open_capture`: the capture open
    /// reaches the gate (`lease_open_calls` 1) and the badge's calls go to the
    /// lease. Drop the `lease_of_caller` test in `open_inner`: the playback open
    /// is admitted under the lease's badge, `open_streams` is 2, and the
    /// playback stream can never be closed (the lease takes the call).
    #[test]
    fn a_badge_cannot_hold_a_playback_and_a_capture_stream_at_once() {
        // Playback first, then capture.
        let (mut srv, w) = server();
        let p = Client::new(&w, 7, [1, 2, 3], &params());
        assert_eq!(p.open(&mut srv, params()).code, outcome::OK);
        let c = Client::new(&w, 7, [11, 12, 13], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::BUSY);
        assert_eq!(w.borrow().lease_open_calls, 0, "refused before the gate: nothing was attempted at the device");
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [11, 12, 13], "only the refused objects go back");
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (1, false));
        call(&mut srv, 7, |s| s.close());
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3], "the playback stream closes under its own badge");
        assert_eq!(srv.open_streams(), 0);
        assert!(w.borrow().lease_calls.is_empty(), "no call went to the lease");

        // Capture first, then playback.
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::OK);
        let p = Client::new(&w, 7, [11, 12, 13], &params());
        assert_eq!(p.open(&mut srv, params()).code, outcome::BUSY);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [11, 12, 13]);
        assert_eq!((srv.open_streams(), w.borrow().lease_active), (1, true));
        call(&mut srv, 7, |s| s.close());
        assert_eq!(w.borrow().lease_calls, ["open", "close"], "the lease closes under its own badge");
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        assert_eq!(srv.open_streams(), 0);
        // Another badge is unaffected by either.
        let p = Client::new(&w, 8, [21, 22, 23], &params());
        assert_eq!(p.open(&mut srv, params()).code, outcome::OK);
    }

    /// A lease whose client stopped posting room (the device's xruns climb) is
    /// closed at the next call, so a dead client does not leave the
    /// microphone live; one that keeps up is not.
    ///
    /// **Canary.** Raise `LEASE_STALL_XRUNS` past the growth: the stalled
    /// lease is still open.
    #[test]
    fn a_lease_whose_client_stopped_is_closed() {
        let (mut srv, w) = server();
        let c = Client::new(&w, 7, [1, 2, 3], &rec());
        assert_eq!(c.open(&mut srv, rec()).code, outcome::OK);
        // A client that keeps up: a few xruns between two looks.
        for round in 1..=3u32 {
            w.borrow_mut().now += LEASE_POLL_NS + 1;
            w.borrow_mut().lease_status = Status { state: STATE_RUNNING, xruns: round * 3, frames: 0 };
            call(&mut srv, 99, |_| ());
            assert!(w.borrow().lease_active, "round {round}");
        }
        // The client died: the device lost a period for every one it did not post.
        w.borrow_mut().now += LEASE_POLL_NS + 1;
        w.borrow_mut().lease_status = Status { state: STATE_RUNNING, xruns: 9 + 300, frames: 0 };
        call(&mut srv, 99, |_| ());
        assert!(!w.borrow().lease_active);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [1, 2, 3]);
        assert!(w.borrow().logs.iter().any(|l| l.contains("stopped posting room")));
        assert_eq!(srv.open_streams(), 0);
    }
}

#[cfg(test)]
mod wire {
    use crate::server::Server;
    use crate::world::{params, server, Fake};
    use azos_devif::sound::{SoundCall, SoundClient, SoundIdl};
    use azos_devif::outcome;
    use crate::world::lend;
    use azos_idl::{MsgDesc, Result as IdlResult, Transport, CAP_MODE_DUP};
    use std::cell::RefCell;

    /// The client stub over the server, as a call arrives: the badge of the
    /// capability it went through is set before the dispatch, as `main.rs`
    /// does from `MsgDesc::badge`.
    struct Loop<'a> {
        srv: &'a RefCell<Server<Fake>>,
        badge: u32,
        last: RefCell<MsgDesc>,
    }

    impl Transport for &Loop<'_> {
        fn call(&self, msg: &mut MsgDesc) -> IdlResult {
            let req = *msg;
            *self.last.borrow_mut() = req;
            let mut s = self.srv.borrow_mut();
            s.caller = self.badge;
            // The kernel hands the server the call's warrant at accept and
            // knows who made the call.
            s.call = crate::world::Client::call_of(self.badge);
            s.env.0.borrow_mut().served.insert(s.call, crate::world::client_tid(self.badge));
            s.prepare();
            let _ = SoundIdl::dispatch(&mut *s, &req, msg);
            s.env.0.borrow_mut().served.remove(&s.call);
            s.caller = 0;
            s.call = 0;
            Ok(())
        }
    }

    /// The generated stub and the generated dispatcher agree with the server
    /// on every op: info, open with three capabilities (the server receives
    /// the handles the client wrote), start, status, close, and a capture open
    /// the kernel's gate decides on the client.
    ///
    /// **Canary.** Answer `info` before `prepare`: the first op reads
    /// `NOT_READY`.
    #[test]
    fn the_sound_interface_round_trips_through_the_server() {
        let (srv, w) = server();
        let srv = RefCell::new(srv);
        let c = crate::world::Client::new(&w, 5, [21, 22, 23], &params());
        let lp = Loop { srv: &srv, badge: 5, last: RefCell::new(MsgDesc::default()) };
        let mut client = SoundClient::new(&lp);
        let info = client.info().unwrap();
        assert_eq!((info.code, info.value.rate_hz, info.value.channels), (outcome::OK, 48_000, 2));
        let opened = client
            .open(params(), lend(21), lend(22), lend(23), 0)
            .unwrap();
        assert_eq!((opened.code, opened.value.period_bytes), (outcome::OK, 1024));
        assert_eq!(lp.last.borrow().n_caps, 3);
        assert!(lp.last.borrow().caps[..3].iter().all(|e| e.mode == CAP_MODE_DUP), "lent, never moved");
        assert_eq!(client.start().unwrap().code, outcome::OK);
        assert_eq!(client.status().unwrap().value.state, azos_devif::sound::STATE_RUNNING);
        assert_eq!(client.close().unwrap().code, outcome::OK);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [21, 22, 23]);
        // A capture open through the generated stub: the gate decides on the
        // task that made the call, which only the kernel can tell the server.
        let rec = azos_devif::sound::Params { dir: azos_devif::sound::DIR_CAPTURE, ..params() };
        w.borrow_mut().withheld.push(crate::world::client_tid(5));
        let r = client.open(rec, lend(21), lend(22), lend(23), 0).unwrap();
        assert_eq!(r.code, outcome::REFUSED);
        assert_eq!(w.borrow().gate, [(crate::world::client_tid(5), false, azos_devif::sound::MIC_NO_GRANT)]);
        w.borrow_mut().withheld.clear();
        let r = client.open(rec, lend(21), lend(22), lend(23), 0).unwrap();
        assert_eq!(r.code, outcome::OK);
        assert_eq!(client.close().unwrap().code, outcome::OK);
        std::mem::take(&mut w.borrow_mut().released);
        drop(c);
        // The same badge on a closed stream opens again.
        let again = client.open(params(), lend(21), lend(22), lend(23), 0).unwrap();
        assert_eq!(again.code, outcome::OK);
    }

    /// An open with an object the client did not lend is refused, and the
    /// copies it did lend are let go of at once: the server has no stream to
    /// keep them for. (The dispatcher refuses a request with fewer entries
    /// than `open` declares; a crafted one can still mark an entry absent.)
    ///
    /// **Canary.** Release only on a full set of three in `Sound::open`:
    /// `released` is empty.
    #[test]
    fn an_object_not_lent_is_refused_and_the_rest_given_back() {
        use azos_devif::Sound;
        let (mut srv, w) = server();
        let _c = crate::world::Client::new(&w, 5, [21, 22, 23], &params());
        srv.caller = 5;
        let r = srv.open(params(), lend(21), lend(0), lend(23), 0);
        srv.caller = 0;
        assert_eq!(r.code, outcome::BAD_ARGUMENT);
        assert_eq!(std::mem::take(&mut w.borrow_mut().released), [21, 23]);
        assert_eq!(srv.live_streams(), 0);
    }
}

#[cfg(test)]
mod row {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::builder::{AUDIOD_ROW, TASK_AUDIOD_IMAGE};
    use azos_topology::default_minimal;

    /// **The row is the whole of the server's authority**: it serves
    /// `endpoint.audio` (`READ`, which claims the service), holds the kernel's
    /// `sound.0` (`RW`, the one device stream) and the `time` warrant (`WRITE`,
    /// which the mixer presents for its own deadline reservation), lends
    /// nothing (`transfer` false) and holds nothing else. It is a best-effort
    /// service row with no profile: the task it spawns is the thread that
    /// accepts calls, which needs no budget; the real-time work is the
    /// mixer's, which asks for its reservation itself. Started at boot, and the
    /// topology admits it. The row exists exactly when Kconfig `AUDIOD` does.
    ///
    /// **Canary.** Give the row `WRITE` on `sound.0` only (drop `READ` on the
    /// endpoint): the first cap assertion goes red; give it back the 1 ms /
    /// 10 ms `hard_rt` profile: the no-profile assertion goes red.
    #[test]
    fn the_row_serves_the_endpoint_holds_the_device_and_the_time_warrant() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()), "the topology, with the row, is admitted");
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == TASK_AUDIOD_IMAGE);
        assert_eq!(row.is_some(), AUDIOD_ROW, "a row exactly when Kconfig AUDIOD");
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 3);
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].transfer), (CapKind::Endpoint, CapPerms::READ, false));
        assert_eq!(caps[0].target.as_bytes(), b"endpoint.audio");
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].transfer), (CapKind::Endpoint, CapPerms::RW, false));
        assert_eq!(caps[1].target.as_bytes(), b"sound.0");
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].transfer), (CapKind::Endpoint, CapPerms::WRITE, false));
        assert_eq!(caps[2].target.as_bytes(), b"time", "the warrant SYS_SCHEDCTL asks of the mixer");
        assert!(row.start, "the kernel starts it with the row");
        assert_eq!(row.class_name.as_bytes(), b"best_effort");
        assert!(!row.profile.is_declared(), "no reservation for the thread that accepts calls");
        // The mixer's own reservation, as Kconfig spells it: a budget no longer
        // than its period, at a band level (below the ring-3 floor of 12).
        assert!(azos_limits::AUDIOD_PUMP_RUNTIME_US <= azos_limits::AUDIOD_PUMP_PERIOD_US);
        assert!(azos_limits::AUDIOD_PUMP_LEVEL < 12);
    }

    /// `beep` goes through the server when the toolbox row holds its endpoint,
    /// else straight to `sound.0`: with the server the row holds the call right
    /// on `endpoint.audio` (lent, `transfer = true`, for the `DUP` that derives
    /// its stream badge; never
    /// `READ`, which would claim the service) and no `sound.0`; without it, the
    /// kernel's `sound.0` as before and no audio endpoint. Exactly one of the
    /// two, never both (the device has one holder).
    ///
    /// **Canary.** Leave `TOOLBOX_SOUND_CAP` in the row with `AUDIOD_ROW`: the
    /// toolbox holds both and the exactly-one assertion goes red.
    #[test]
    fn the_toolbox_plays_through_the_server_or_the_device_never_both() {
        let t = default_minimal();
        let tb = t.tasks().iter().find(|r| r.name.as_bytes() == b"TOOLBOX.ELF").expect("the toolbox row");
        let caps = t.caps_of(tb);
        let audio: Vec<_> = caps.iter().filter(|c| c.target.as_bytes() == b"endpoint.audio").collect();
        let sound: Vec<_> = caps.iter().filter(|c| c.target.as_bytes() == b"sound.0").collect();
        if AUDIOD_ROW {
            assert_eq!((audio.len(), sound.len()), (1, 0));
            assert_eq!(audio[0].perms, CapPerms::WRITE);
            assert!(!audio[0].perms.contains(CapPerms::READ), "READ would claim the service");
            assert!(audio[0].transfer, "the DUP that derives the badge comes with `transfer = true`");
        } else {
            assert_eq!(audio.len(), 0);
            assert_eq!(sound.len() as u32, azos_limits::DRV_VIRTIO_SND as u32);
        }
    }

    /// The interface names the endpoint the row grants: a typo in the builder's
    /// spelling would make the row refuse to seed, not fail a build.
    #[test]
    fn the_endpoint_and_the_device_the_row_names_are_the_interfaces() {
        assert_eq!(azos_devif::sound::ENDPOINT, "endpoint.audio");
        let (iface, badge) = azos_devif::parse_target("sound.0").expect("sound.0 names an interface");
        assert_eq!((iface.id, badge), (azos_devif::SOUND_ID, azos_devif::sound::device_badge(0)));
    }
}
