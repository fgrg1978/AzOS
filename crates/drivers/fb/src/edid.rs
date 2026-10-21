// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! EDID: what a display says about itself, read from the blob a source hands
//! over (a virtio-gpu `GET_EDID` answer, the Limine loader's EDID, a DDC read).
//!
//! [`parse`] takes the bytes as they came and answers an [`Edid`]: who made
//! the display, how big it is, its name, and the list of video modes it
//! accepts with its preferred one first. Pure `core`, no allocation, never
//! indexes past what it was given: a truncated or hostile blob is an
//! [`EdidError`] or a shorter list, not a fault.
//!
//! # What is read
//!
//! * **Base block (EDID 1.x)**: the header and checksum, the vendor and
//!   product, the manufacture date, the input type, the physical size, the
//!   established timings, the eight standard timings and the four 18-byte
//!   descriptors (detailed timings, the monitor name, the additional
//!   standard timings of tag `0xFA`).
//! * **CTA-861 extension blocks (tag `0x02`, revision 3)**: the video data
//!   block's short video descriptors (a table of the [`VICS`] a display
//!   offers progressive) and the detailed timings that follow the data
//!   blocks.
//!
//! Not read: DisplayID extensions, the HDMI vendor block's 4K modes, colour
//! characteristics, range limits, audio and HDR blocks. A mode that only one
//! of those would have named is not in the list, which is why the list is a
//! lower bound: the preferred mode, the first, is always what the first
//! detailed timing of the base block says.
//!
//! # Refusals
//!
//! A block whose bytes do not sum to zero modulo 256 is refused (the base
//! block: the whole blob; an extension: that extension, the rest still
//! count). Linux accepts a bad checksum with a warning; a display that lies
//! about its checksum is not trusted for a mode here, and the connector then
//! reports the one mode the scanout runs.
//!
//! Interlaced timings are not listed: the display server scans out whole
//! frames.

/// Bytes of one EDID block.
pub const BLOCK: usize = 128;
/// Modes [`Edid`] keeps. Extra ones are dropped, the preferred first kept.
pub const MAX_MODES: usize = 32;
/// Bytes of the monitor name descriptor's text.
pub const NAME_MAX: usize = 13;

/// A video mode: pixels and refresh rate. Refresh is in millihertz so that
/// 59.94 Hz and 60 Hz are two numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    pub width: u16,
    pub height: u16,
    pub refresh_mhz: u32,
}

impl Timing {
    /// Refresh rate in whole hertz, rounded: the key two sources of the same
    /// mode are compared by (a detailed timing says 59.94, a short video
    /// descriptor 60).
    fn hz(&self) -> u32 {
        (self.refresh_mhz + 500) / 1000
    }

    fn same_mode(&self, o: &Timing) -> bool {
        self.width == o.width && self.height == o.height && self.hz() == o.hz()
    }
}

/// Why a blob is not an EDID this parser trusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Fewer than [`BLOCK`] bytes.
    TooShort,
    /// The 8-byte header is not `00 FF FF FF FF FF FF 00`.
    BadHeader,
    /// The base block's bytes do not sum to 0 modulo 256.
    BadChecksum,
    /// Not EDID 1.x (1.0 to 1.4).
    BadVersion,
}

/// What a display's EDID said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edid {
    /// The manufacturer's three-letter PNP id (`'?'` for a letter outside
    /// A-Z).
    pub vendor: [u8; 3],
    /// The manufacturer's product code.
    pub product: u16,
    /// Week of manufacture (1..=54), 0 when the display does not say.
    pub week: u8,
    /// Year of manufacture, 0 when the display does not say.
    pub year: u16,
    /// EDID version and revision (`1`, `0..=4`).
    pub version: u8,
    pub revision: u8,
    /// A digital input (DVI, HDMI, DisplayPort), not an analogue one.
    pub digital: bool,
    /// The picture's physical size in millimetres, 0 when unknown. The
    /// preferred detailed timing's image size when it has one (millimetre
    /// resolution), else the base block's centimetres.
    pub width_mm: u32,
    pub height_mm: u32,
    /// Extension blocks the base block announces (they may not all be in the
    /// blob).
    pub extensions: u8,
    name: [u8; NAME_MAX],
    name_len: u8,
    /// The first mode is the first detailed timing of the base block: the
    /// display's preferred (and, from EDID 1.3 on, native) mode.
    has_preferred: bool,
    modes: [Timing; MAX_MODES],
    n_modes: u8,
}

impl Edid {
    /// The modes, preferred first when there is one ([`Edid::preferred`]),
    /// then the rest in the order the blob listed them, each mode once.
    pub fn modes(&self) -> &[Timing] {
        &self.modes[..self.n_modes as usize]
    }

    /// The display's preferred mode: the first detailed timing of the base
    /// block, when it describes a progressive mode.
    pub fn preferred(&self) -> Option<Timing> {
        self.has_preferred.then(|| self.modes[0])
    }

    /// The monitor name descriptor's text, printable ASCII only (anything
    /// else shows as `?`), empty when the blob has none.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    fn push(&mut self, t: Timing) {
        if t.width == 0 || t.height == 0 || t.refresh_mhz == 0 {
            return;
        }
        let n = self.n_modes as usize;
        if n >= MAX_MODES || self.modes[..n].iter().any(|m| m.same_mode(&t)) {
            return;
        }
        self.modes[n] = t;
        self.n_modes += 1;
    }
}

fn sums_to_zero(block: &[u8]) -> bool {
    block.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

/// One detailed timing descriptor (EDID 1.4 3.10.2), 18 bytes. `None` for a
/// descriptor that is not a timing (a zero pixel clock), one with no pixels,
/// and an interlaced one.
struct Dtd {
    timing: Timing,
    width_mm: u32,
    height_mm: u32,
}

fn dtd(d: &[u8]) -> Option<Dtd> {
    let d = d.get(..18)?;
    let clock_10khz = u16::from_le_bytes([d[0], d[1]]) as u64;
    if clock_10khz == 0 {
        return None;
    }
    let hactive = d[2] as u32 | (d[4] as u32 & 0xF0) << 4;
    let hblank = d[3] as u32 | (d[4] as u32 & 0x0F) << 8;
    let vactive = d[5] as u32 | (d[7] as u32 & 0xF0) << 4;
    let vblank = d[6] as u32 | (d[7] as u32 & 0x0F) << 8;
    let interlaced = d[17] & 0x80 != 0;
    if hactive == 0 || vactive == 0 || interlaced {
        return None;
    }
    let frame = (hactive + hblank) as u64 * (vactive + vblank) as u64;
    // Pixel clock over the frame, in millihertz, rounded to nearest. A clock
    // of at most 655.35 MHz and a frame of at least one pixel keep this in a
    // u64; the result is clamped so a nonsense clock cannot overflow a u32.
    let mhz = ((clock_10khz * 10_000 * 1000 + frame / 2) / frame).min(u32::MAX as u64) as u32;
    Some(Dtd {
        timing: Timing { width: hactive as u16, height: vactive as u16, refresh_mhz: mhz },
        width_mm: d[12] as u32 | (d[14] as u32 & 0xF0) << 4,
        height_mm: d[13] as u32 | (d[14] as u32 & 0x0F) << 8,
    })
}

/// The established timings I and II (bytes 35 and 36) and the manufacturer
/// timing bit of byte 37: the modes a display of 1990s vintage lists. The
/// interlaced 1024x768 at 87 Hz is left out.
fn established(e: &mut Edid, b35: u8, b36: u8, b37: u8) {
    const T35: [(u16, u16, u32); 8] = [
        (800, 600, 60),
        (800, 600, 56),
        (640, 480, 75),
        (640, 480, 72),
        (640, 480, 67),
        (640, 480, 60),
        (720, 400, 88),
        (720, 400, 70),
    ];
    const T36: [(u16, u16, u32); 8] = [
        (1280, 1024, 75),
        (1024, 768, 75),
        (1024, 768, 70),
        (1024, 768, 60),
        (0, 0, 0), // 1024x768 at 87 Hz, interlaced
        (832, 624, 75),
        (800, 600, 75),
        (800, 600, 72),
    ];
    for (bits, table) in [(b35, T35), (b36, T36)] {
        // The tables are indexed by bit number.
        for (bit, &(w, h, hz)) in table.iter().enumerate() {
            if bits >> bit & 1 != 0 {
                e.push(Timing { width: w, height: h, refresh_mhz: hz * 1000 });
            }
        }
    }
    if b37 & 0x80 != 0 {
        e.push(Timing { width: 1152, height: 870, refresh_mhz: 75_000 });
    }
}

/// One standard timing identifier (2 bytes). `None` for the unused value
/// `01 01` (and its all-zero cousin) and for an aspect/size that gives no
/// mode.
fn standard(revision: u8, a: u8, b: u8) -> Option<Timing> {
    if (a == 0x01 && b == 0x01) || a == 0x00 || (a == 0x20 && b == 0x20) {
        return None;
    }
    let width = (a as u32 + 31) * 8;
    // Before EDID 1.3 the aspect code 00 was 1:1.
    let height = match b >> 6 {
        0 if revision < 3 => width,
        0 => width * 10 / 16,
        1 => width * 3 / 4,
        2 => width * 4 / 5,
        _ => width * 9 / 16,
    };
    let hz = (b & 0x3F) as u32 + 60;
    Some(Timing { width: width as u16, height: height as u16, refresh_mhz: hz * 1000 })
}

/// The CTA-861 video identification codes this parser knows, progressive
/// modes only: `(vic, width, height, refresh in Hz)`. A VIC not listed is a
/// mode the display offers that this table does not name; it is skipped.
const VICS: &[(u8, u16, u16, u16)] = &[
    (1, 640, 480, 60),
    (2, 720, 480, 60),
    (3, 720, 480, 60),
    (4, 1280, 720, 60),
    (16, 1920, 1080, 60),
    (17, 720, 576, 50),
    (18, 720, 576, 50),
    (19, 1280, 720, 50),
    (31, 1920, 1080, 50),
    (32, 1920, 1080, 24),
    (33, 1920, 1080, 25),
    (34, 1920, 1080, 30),
    (60, 1280, 720, 24),
    (61, 1280, 720, 25),
    (62, 1280, 720, 30),
    (63, 1920, 1080, 120),
    (64, 1920, 1080, 100),
    (93, 3840, 2160, 24),
    (94, 3840, 2160, 25),
    (95, 3840, 2160, 30),
    (96, 3840, 2160, 50),
    (97, 3840, 2160, 60),
    (98, 4096, 2160, 24),
    (99, 4096, 2160, 25),
    (100, 4096, 2160, 30),
    (101, 4096, 2160, 50),
    (102, 4096, 2160, 60),
];

/// The video identification code a short video descriptor byte names: codes
/// 1..=64 carry a "native" flag in bit 7, the rest are the byte itself.
fn svd_vic(b: u8) -> u8 {
    if (129..=192).contains(&b) { b & 0x7F } else { b }
}

fn vic_timing(vic: u8) -> Option<Timing> {
    VICS.iter()
        .find(|v| v.0 == vic)
        .map(|&(_, w, h, hz)| Timing { width: w, height: h, refresh_mhz: hz as u32 * 1000 })
}

/// Read one CTA-861 extension block (128 bytes, tag `0x02`, checksum already
/// verified): the video data blocks, then the detailed timings after them.
fn cta(e: &mut Edid, b: &[u8]) {
    if b.get(1).copied().unwrap_or(0) < 3 {
        return; // revisions 1 and 2 have no data blocks to read
    }
    // `d` is where the detailed timings begin; 0 says there are none and no
    // data blocks either, 4 that there are none after an empty data area.
    let d = (b[2] as usize).min(BLOCK - 1);
    if d < 4 {
        return;
    }
    let mut at = 4;
    while at < d {
        let head = b[at];
        let (tag, len) = (head >> 5, (head & 0x1F) as usize);
        let end = at + 1 + len;
        if end > d {
            break; // a data block that runs into the timings: the rest is junk
        }
        if tag == 2 {
            for &svd in &b[at + 1..end] {
                if let Some(t) = vic_timing(svd_vic(svd)) {
                    e.push(t);
                }
            }
        }
        at = end;
    }
    let mut at = d;
    while at + 18 <= BLOCK - 1 {
        match dtd(&b[at..at + 18]) {
            Some(t) => e.push(t.timing),
            // A zero clock ends the list (the rest is padding); a timing
            // that is skipped (interlaced, empty) does not.
            None if b[at] == 0 && b[at + 1] == 0 => break,
            None => {}
        }
        at += 18;
    }
}

/// Parse an EDID blob: the base block, then each CTA-861 extension block the
/// blob holds. See the module documentation for what is read and refused.
pub fn parse(bytes: &[u8]) -> Result<Edid, EdidError> {
    let base = bytes.get(..BLOCK).ok_or(EdidError::TooShort)?;
    if base[..8] != [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0] {
        return Err(EdidError::BadHeader);
    }
    if !sums_to_zero(base) {
        return Err(EdidError::BadChecksum);
    }
    let (version, revision) = (base[18], base[19]);
    if version != 1 || revision > 4 {
        return Err(EdidError::BadVersion);
    }
    let id = u16::from_be_bytes([base[8], base[9]]);
    let letter = |v: u16| if (1..=26).contains(&v) { b'A' + (v - 1) as u8 } else { b'?' };
    let year = base[17] as u16 + 1990;
    let mut e = Edid {
        vendor: [letter(id >> 10 & 0x1F), letter(id >> 5 & 0x1F), letter(id & 0x1F)],
        product: u16::from_le_bytes([base[10], base[11]]),
        // A week outside 1..=54 (0xFF marks a model year) and a zero year
        // byte mean the display does not say.
        week: if (1..=54).contains(&base[16]) { base[16] } else { 0 },
        year: if base[17] == 0 { 0 } else { year },
        version,
        revision,
        digital: base[20] & 0x80 != 0,
        // Byte 21 or 22 zero means the size is not given (or, in 1.4, an
        // aspect ratio instead): no centimetres to report.
        width_mm: if base[21] != 0 && base[22] != 0 { base[21] as u32 * 10 } else { 0 },
        height_mm: if base[21] != 0 && base[22] != 0 { base[22] as u32 * 10 } else { 0 },
        extensions: base[126],
        name: [0; NAME_MAX],
        name_len: 0,
        has_preferred: false,
        modes: [Timing { width: 0, height: 0, refresh_mhz: 0 }; MAX_MODES],
        n_modes: 0,
    };

    // The four descriptors. The first detailed timing, when it is one, is the
    // preferred mode and goes in the list before everything else.
    let descriptors = [&base[54..72], &base[72..90], &base[90..108], &base[108..126]];
    if let Some(first) = dtd(descriptors[0]) {
        e.push(first.timing);
        e.has_preferred = e.n_modes == 1;
        if first.width_mm != 0 && first.height_mm != 0 {
            e.width_mm = first.width_mm;
            e.height_mm = first.height_mm;
        }
    }
    for (i, d) in descriptors.iter().enumerate() {
        if d[0] != 0 || d[1] != 0 {
            if i > 0 {
                if let Some(t) = dtd(d) {
                    e.push(t.timing);
                }
            }
            continue;
        }
        // A display descriptor: bytes 0..=2 zero, the tag at byte 3.
        match d[3] {
            0xFC => {
                let text = &d[5..18];
                let n = text.iter().position(|&c| c == 0x0A).unwrap_or(NAME_MAX);
                let n = text[..n].iter().rposition(|&c| c != b' ').map_or(0, |p| p + 1);
                for (o, &c) in e.name.iter_mut().zip(&text[..n]) {
                    *o = if (0x20..0x7F).contains(&c) { c } else { b'?' };
                }
                e.name_len = n as u8;
            }
            0xFA => {
                for s in d[5..17].chunks_exact(2) {
                    if let Some(t) = standard(revision, s[0], s[1]) {
                        e.push(t);
                    }
                }
            }
            _ => {}
        }
    }
    for s in base[38..54].chunks_exact(2) {
        if let Some(t) = standard(revision, s[0], s[1]) {
            e.push(t);
        }
    }
    established(&mut e, base[35], base[36], base[37]);

    // The extension blocks the blob really holds, as many as the base block
    // announces.
    for k in 1..=base[126] as usize {
        let Some(block) = bytes.get(k * BLOCK..(k + 1) * BLOCK) else { break };
        if block[0] == 0x02 && sums_to_zero(block) {
            cta(&mut e, block);
        }
    }
    Ok(e)
}
