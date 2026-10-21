// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-sound wire format (virtio 1.2, section 5.14; `linux/virtio_snd.h`):
//! the control requests the driver sends, the answers it reads, the PCM
//! transfer header and status, and the code tables that map a sample rate or
//! format to the device's bit numbers.
//!
//! Pure (`core` only), so `tests/host/drivers-tests` runs it against fixed
//! bytes. Every request is built as a fixed-size array (all fields little
//! endian, whatever the CPU): the driver copies it into a request slot, so no
//! encoder has a length to get wrong and none can panic. Everything read from
//! the device is parsed with a length check: a short answer is `None`, never
//! a read past the buffer.

/// PCI: vendor 0x1af4, device 0x1040 + the virtio device id (25).
pub const PCI_DEVICE: u16 = 0x1059;

// ── Queues (5.14.2) ──────────────────────────────────────────────────────

pub const VQ_CONTROL: u32 = 0;
pub const VQ_EVENT: u32 = 1;
pub const VQ_TX: u32 = 2;
pub const VQ_RX: u32 = 3;

// ── Config space (5.14.4): jacks, streams, chmaps, little-endian u32 each ─

/// Bytes of `struct virtio_snd_config` the driver reads (`controls`, present
/// only with `VIRTIO_SND_F_CTLS`, is not used).
pub const CONFIG_LEN: usize = 12;

/// The counts the device reports in its config space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
}

impl Config {
    pub fn parse(b: &[u8]) -> Option<Config> {
        Some(Config { jacks: get32(b, 0)?, streams: get32(b, 4)?, chmaps: get32(b, 8)? })
    }
}

// ── Request and status codes (5.14.6) ────────────────────────────────────

pub const R_JACK_INFO: u32 = 0x0001;
pub const R_PCM_INFO: u32 = 0x0100;
pub const R_PCM_SET_PARAMS: u32 = 0x0101;
pub const R_PCM_PREPARE: u32 = 0x0102;
pub const R_PCM_RELEASE: u32 = 0x0103;
pub const R_PCM_START: u32 = 0x0104;
pub const R_PCM_STOP: u32 = 0x0105;
pub const R_CHMAP_INFO: u32 = 0x0200;

pub const S_OK: u32 = 0x8000;
pub const S_BAD_MSG: u32 = 0x8001;
pub const S_NOT_SUPP: u32 = 0x8002;
pub const S_IO_ERR: u32 = 0x8003;

/// `VIRTIO_SND_D_OUTPUT` / `_INPUT`: the stream's direction.
pub const D_OUTPUT: u8 = 0;
pub const D_INPUT: u8 = 1;

/// Bytes of the answer to a request with no data: `struct virtio_snd_hdr`
/// (the status code).
pub const RESP_HDR_LEN: usize = 4;
/// Bytes of one `struct virtio_snd_jack_info`, `virtio_snd_pcm_info`,
/// `virtio_snd_chmap_info` (all three items are fixed-size).
pub const JACK_INFO_LEN: usize = 24;
pub const PCM_INFO_LEN: usize = 32;
pub const CHMAP_INFO_LEN: usize = 24;
/// The most items one info query asks for; the answer buffer is
/// `RESP_HDR_LEN + INFO_MAX * item_size`.
pub const INFO_MAX: usize = 4;
/// Bytes of the largest info answer.
pub const INFO_RESP_MAX: usize = RESP_HDR_LEN + INFO_MAX * PCM_INFO_LEN;

/// `struct virtio_snd_query_info`: code, start id, count, item size.
pub const LEN_QUERY_INFO: usize = 16;
/// `struct virtio_snd_pcm_hdr`: code, stream id.
pub const LEN_PCM_HDR: usize = 8;
/// `struct virtio_snd_pcm_set_params`.
pub const LEN_SET_PARAMS: usize = 24;
/// `struct virtio_snd_pcm_xfer`: the stream id, in front of every period.
pub const LEN_XFER: usize = 4;
/// `struct virtio_snd_pcm_status`: status, latency bytes; behind every period.
pub const LEN_PCM_STATUS: usize = 8;
/// The largest request the driver builds.
pub const REQ_MAX: usize = LEN_SET_PARAMS;

// ── PCM formats and rates (5.14.6.6.2): bit numbers ──────────────────────

pub const FMT_S16: u8 = 5;
/// 24 bits in a 32-bit word (the low three bytes), `azos_devif::sound::FMT_S24`.
pub const FMT_S24: u8 = 15;
pub const FMT_S32: u8 = 17;
pub const FMT_FLOAT: u8 = 19;

pub const RATE_5512: u8 = 0;
pub const RATE_8000: u8 = 1;
pub const RATE_11025: u8 = 2;
pub const RATE_16000: u8 = 3;
pub const RATE_22050: u8 = 4;
pub const RATE_32000: u8 = 5;
pub const RATE_44100: u8 = 6;
pub const RATE_48000: u8 = 7;
pub const RATE_64000: u8 = 8;
pub const RATE_88200: u8 = 9;
pub const RATE_96000: u8 = 10;
pub const RATE_176400: u8 = 11;
pub const RATE_192000: u8 = 12;
pub const RATE_384000: u8 = 13;

/// The rates of the table, by bit number.
pub const RATES_HZ: [u32; 14] =
    [5_512, 8_000, 11_025, 16_000, 22_050, 32_000, 44_100, 48_000, 64_000, 88_200, 96_000, 176_400, 192_000, 384_000];

/// The bit number of `hz`, `None` for a rate the specification has no bit for.
pub fn rate_bit(hz: u32) -> Option<u8> {
    RATES_HZ.iter().position(|&r| r == hz).map(|i| i as u8)
}

/// The rate to run a device at when the topology does not say: 48 kHz if the
/// device has it, else the highest it has up to 48 kHz, else the lowest above.
/// `None` for a device that reports no rate at all.
pub fn preferred_rate(rates: u64) -> Option<u32> {
    let has = |hz: u32| rate_bit(hz).is_some_and(|b| rates >> b & 1 != 0);
    if has(48_000) {
        return Some(48_000);
    }
    let below = RATES_HZ.iter().rev().copied().filter(|&r| r < 48_000).find(|&r| has(r));
    below.or_else(|| RATES_HZ.iter().copied().filter(|&r| r > 48_000).find(|&r| has(r)))
}

// ── Encoders ─────────────────────────────────────────────────────────────

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn get64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// `struct virtio_snd_query_info`: ask for `count` items starting at
/// `start_id`, each `size` bytes (`R_JACK_INFO`, `R_PCM_INFO`, `R_CHMAP_INFO`).
pub fn query_info(code: u32, start_id: u32, count: u32, size: u32) -> [u8; LEN_QUERY_INFO] {
    let mut b = [0u8; LEN_QUERY_INFO];
    put32(&mut b, 0, code);
    put32(&mut b, 4, start_id);
    put32(&mut b, 8, count);
    put32(&mut b, 12, size);
    b
}

/// `struct virtio_snd_pcm_hdr`: `R_PCM_PREPARE`, `R_PCM_RELEASE`,
/// `R_PCM_START` and `R_PCM_STOP` carry nothing else.
pub fn pcm_hdr(code: u32, stream_id: u32) -> [u8; LEN_PCM_HDR] {
    let mut b = [0u8; LEN_PCM_HDR];
    put32(&mut b, 0, code);
    put32(&mut b, 4, stream_id);
    b
}

/// What `R_PCM_SET_PARAMS` carries beyond the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetParams {
    pub stream_id: u32,
    /// The hardware buffer: every period of the arena.
    pub buffer_bytes: u32,
    pub period_bytes: u32,
    pub channels: u8,
    /// A `FMT_*` bit number.
    pub format: u8,
    /// A `RATE_*` bit number.
    pub rate: u8,
}

/// `struct virtio_snd_pcm_set_params`: no optional feature (`features` 0, so
/// the samples travel in the I/O queues and not in shared memory).
pub fn set_params(p: &SetParams) -> [u8; LEN_SET_PARAMS] {
    let mut b = [0u8; LEN_SET_PARAMS];
    put32(&mut b, 0, R_PCM_SET_PARAMS);
    put32(&mut b, 4, p.stream_id);
    put32(&mut b, 8, p.buffer_bytes);
    put32(&mut b, 12, p.period_bytes);
    put32(&mut b, 16, 0);
    b[20] = p.channels;
    b[21] = p.format;
    b[22] = p.rate;
    b
}

/// `struct virtio_snd_pcm_xfer`: in front of every period on the tx and rx
/// queues.
pub fn xfer(stream_id: u32) -> [u8; LEN_XFER] {
    stream_id.to_le_bytes()
}

// ── Decoders ─────────────────────────────────────────────────────────────

/// The status code of an answer (`struct virtio_snd_hdr`).
pub fn resp_status(b: &[u8]) -> Option<u32> {
    get32(b, 0)
}

/// `struct virtio_snd_pcm_status`: the answer behind every period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmStatus {
    pub status: u32,
    pub latency_bytes: u32,
}

pub fn pcm_status(b: &[u8]) -> Option<PcmStatus> {
    Some(PcmStatus { status: get32(b, 0)?, latency_bytes: get32(b, 4)? })
}

/// `struct virtio_snd_pcm_info`, as far as the driver uses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PcmInfo {
    /// Bit `n`: the format with bit number `n` is supported.
    pub formats: u64,
    /// Bit `n`: the rate with bit number `n` is supported.
    pub rates: u64,
    /// `D_OUTPUT` or `D_INPUT`.
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
}

impl PcmInfo {
    /// The item at byte `off` of an info answer's data (`b` is the whole
    /// answer minus the status word).
    pub fn parse(b: &[u8]) -> Option<PcmInfo> {
        if b.len() < PCM_INFO_LEN {
            return None;
        }
        Some(PcmInfo {
            // 0: hda_fn_nid, 4: features
            formats: get64(b, 8)?,
            rates: get64(b, 16)?,
            direction: b[24],
            channels_min: b[25],
            channels_max: b[26],
        })
    }

    pub fn has_format(&self, bit: u8) -> bool {
        bit < 64 && self.formats >> bit & 1 != 0
    }

    pub fn has_rate(&self, bit: u8) -> bool {
        bit < 64 && self.rates >> bit & 1 != 0
    }

    pub fn has_channels(&self, n: u32) -> bool {
        n >= self.channels_min as u32 && n <= self.channels_max as u32 && n != 0
    }
}

/// `struct virtio_snd_jack_info`, as far as the driver uses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JackInfo {
    /// Pin configuration default register (HDA 7.3.3.31).
    pub hda_reg_defconf: u32,
    /// Whether something is plugged in now.
    pub connected: bool,
}

impl JackInfo {
    pub fn parse(b: &[u8]) -> Option<JackInfo> {
        if b.len() < JACK_INFO_LEN {
            return None;
        }
        // 0: hda_fn_nid, 4: features, 8: hda_reg_defconf, 12: hda_reg_caps
        Some(JackInfo { hda_reg_defconf: get32(b, 8)?, connected: b[16] != 0 })
    }
}

/// Most channel positions one channel map carries (`VIRTIO_SND_CHMAP_MAX_SIZE`).
pub const CHMAP_POSITIONS: usize = 18;

/// `struct virtio_snd_chmap_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChmapInfo {
    /// `D_OUTPUT` or `D_INPUT`.
    pub direction: u8,
    /// How many of `positions` are valid.
    pub channels: u8,
    pub positions: [u8; CHMAP_POSITIONS],
}

impl ChmapInfo {
    /// `None` for a short item or a channel count past the position table.
    pub fn parse(b: &[u8]) -> Option<ChmapInfo> {
        if b.len() < CHMAP_INFO_LEN || b[5] as usize > CHMAP_POSITIONS {
            return None;
        }
        let mut positions = [0u8; CHMAP_POSITIONS];
        positions.copy_from_slice(&b[6..6 + CHMAP_POSITIONS]);
        Some(ChmapInfo { direction: b[4], channels: b[5], positions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    /// **Canary.** Swap `start_id` and `count` in `query_info`: the layout test fails.
    #[test]
    fn a_query_is_the_spec_struct() {
        let q = query_info(R_PCM_INFO, 1, 2, PCM_INFO_LEN as u32);
        assert_eq!(q.len(), 16);
        assert_eq!([le32(&q, 0), le32(&q, 4), le32(&q, 8), le32(&q, 12)], [0x100, 1, 2, 32]);
    }

    #[test]
    fn the_codes_are_the_specifications() {
        // 5.14.6: each constant against the value in linux/virtio_snd.h.
        assert_eq!(
            [R_JACK_INFO, R_PCM_INFO, R_PCM_SET_PARAMS, R_PCM_PREPARE, R_PCM_RELEASE, R_PCM_START, R_PCM_STOP, R_CHMAP_INFO],
            [1, 0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x200]
        );
        assert_eq!([S_OK, S_BAD_MSG, S_NOT_SUPP, S_IO_ERR], [0x8000, 0x8001, 0x8002, 0x8003]);
        assert_eq!([VQ_CONTROL, VQ_EVENT, VQ_TX, VQ_RX], [0, 1, 2, 3]);
        assert_eq!(PCI_DEVICE, 0x1040 + 25);
        assert_eq!([FMT_S16, FMT_S24, FMT_S32, FMT_FLOAT], [5, 15, 17, 19]);
        assert_eq!([RATE_8000, RATE_44100, RATE_48000, RATE_384000], [1, 6, 7, 13]);
    }

    /// **Canary.** Put `rate` before `format` in `set_params`: byte 21/22 differ.
    #[test]
    fn set_params_lays_out_the_struct() {
        let b = set_params(&SetParams { stream_id: 3, buffer_bytes: 0x1_0000, period_bytes: 0x2000, channels: 2, format: FMT_S16, rate: RATE_48000 });
        assert_eq!(b.len(), 24, "struct virtio_snd_pcm_set_params");
        assert_eq!(le32(&b, 0), R_PCM_SET_PARAMS);
        assert_eq!(le32(&b, 4), 3, "hdr.stream_id");
        assert_eq!(le32(&b, 8), 0x1_0000, "buffer_bytes");
        assert_eq!(le32(&b, 12), 0x2000, "period_bytes");
        assert_eq!(le32(&b, 16), 0, "features: none");
        assert_eq!(&b[20..24], &[2, FMT_S16, RATE_48000, 0], "channels, format, rate, padding");
    }

    #[test]
    fn pcm_requests_carry_the_stream() {
        let b = pcm_hdr(R_PCM_START, 1);
        assert_eq!((le32(&b, 0), le32(&b, 4)), (0x104, 1));
        assert_eq!(xfer(7), [7, 0, 0, 0]);
    }

    #[test]
    fn the_config_and_status_parse_and_a_short_one_does_not() {
        let mut c = [0u8; 12];
        c[0] = 1;
        c[4] = 2;
        c[8] = 3;
        assert_eq!(Config::parse(&c), Some(Config { jacks: 1, streams: 2, chmaps: 3 }));
        assert_eq!(Config::parse(&c[..11]), None);
        let s = [0x00, 0x80, 0, 0, 0x10, 0, 0, 0];
        assert_eq!(pcm_status(&s), Some(PcmStatus { status: S_OK, latency_bytes: 16 }));
        assert_eq!(pcm_status(&s[..7]), None);
        assert_eq!(resp_status(&s), Some(S_OK));
        assert_eq!(resp_status(&s[..3]), None);
    }

    #[test]
    fn pcm_info_reads_the_bitmaps_and_the_channel_range() {
        let mut b = [0u8; PCM_INFO_LEN];
        b[8..16].copy_from_slice(&((1u64 << FMT_S16) | (1 << FMT_FLOAT)).to_le_bytes());
        b[16..24].copy_from_slice(&((1u64 << RATE_44100) | (1 << RATE_48000)).to_le_bytes());
        b[24] = D_INPUT;
        b[25] = 1;
        b[26] = 2;
        let i = PcmInfo::parse(&b).unwrap();
        assert_eq!(i.direction, D_INPUT);
        assert!(i.has_format(FMT_S16) && i.has_format(FMT_FLOAT) && !i.has_format(FMT_S32));
        assert!(i.has_rate(RATE_48000) && !i.has_rate(RATE_8000));
        assert!(i.has_channels(1) && i.has_channels(2) && !i.has_channels(3) && !i.has_channels(0));
        assert!(!i.has_format(64) && !i.has_rate(200), "a bit number past the map is not supported");
        assert_eq!(PcmInfo::parse(&b[..31]), None);
    }

    #[test]
    fn jack_and_chmap_items_parse_and_refuse_a_bad_count() {
        let mut j = [0u8; JACK_INFO_LEN];
        j[8..12].copy_from_slice(&0x0121_4010u32.to_le_bytes());
        j[16] = 1;
        assert_eq!(JackInfo::parse(&j), Some(JackInfo { hda_reg_defconf: 0x0121_4010, connected: true }));
        assert_eq!(JackInfo::parse(&j[..23]), None);
        let mut c = [0u8; CHMAP_INFO_LEN];
        c[4] = D_INPUT;
        c[5] = 2;
        c[6] = 3; // FL
        c[7] = 4; // FR
        let m = ChmapInfo::parse(&c).unwrap();
        assert_eq!((m.direction, m.channels, &m.positions[..2]), (D_INPUT, 2, &[3u8, 4][..]));
        c[5] = 19;
        assert_eq!(ChmapInfo::parse(&c), None, "more channels than the table holds");
        assert_eq!(ChmapInfo::parse(&c[..23]), None);
    }

    #[test]
    fn the_preferred_rate_is_48k_then_the_best_below_then_the_lowest_above() {
        let m = |bits: &[u8]| bits.iter().fold(0u64, |a, &b| a | 1 << b);
        assert_eq!(preferred_rate(m(&[RATE_8000, RATE_44100, RATE_48000])), Some(48_000));
        assert_eq!(preferred_rate(m(&[RATE_8000, RATE_44100])), Some(44_100));
        assert_eq!(preferred_rate(m(&[RATE_96000, RATE_192000])), Some(96_000));
        assert_eq!(preferred_rate(0), None);
        assert_eq!(rate_bit(44_100), Some(RATE_44100));
        assert_eq!(rate_bit(44_101), None);
        for (i, &hz) in RATES_HZ.iter().enumerate() {
            assert_eq!(rate_bit(hz), Some(i as u8));
        }
    }
}
