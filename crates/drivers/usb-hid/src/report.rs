// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The HID report descriptor parser (HID 1.11, section 6.2.2).
//!
//! A report descriptor is a stream of short items: a prefix byte (size, type,
//! tag) and up to four data bytes. Global items (usage page, logical range,
//! report size/count/ID) set state that holds until changed; local items
//! (usages) belong to the next main item and are cleared after it; an Input
//! main item turns the state into a field of the report. [`Layout::parse`]
//! runs that machine once and keeps only what a keyboard or a mouse driver
//! reads: for each field of an Input item it either knows an evdev meaning
//! (a key, a button, a relative or an absolute axis) or it only advances the
//! bit position. The result is a [`Layout`], a flat table of [`Control`]s a
//! [`crate::decode::Decoder`] walks for every report.
//!
//! What a control means depends on the application collection it sits in: the
//! keyboard page's usages only under a Keyboard or Keypad collection; buttons,
//! the X, Y and wheel axes and AC Pan only under a Mouse or Pointer one. A
//! gamepad's X and Y are not a pointer's, and a vendor collection is nobody's.
//!
//! No allocation: the table has [`MAX_CONTROLS`] entries and [`MAX_IDS`]
//! report IDs; a descriptor that needs more is refused, not truncated.

use azos_input_wire::event::{REL_HWHEEL, REL_WHEEL, REL_X, REL_Y, ABS_X, ABS_Y};

use crate::usage::{
    button_code, key_code, CONSUMER_AC_PAN, GD_KEYBOARD, GD_KEYPAD, GD_MOUSE, GD_POINTER, GD_WHEEL, GD_X, GD_Y,
    PAGE_BUTTON, PAGE_CONSUMER, PAGE_GENERIC_DESKTOP, PAGE_KEYBOARD,
};

/// Controls a layout holds.
pub const MAX_CONTROLS: usize = 32;
/// Distinct report IDs a layout holds (one when the descriptor has none).
pub const MAX_IDS: usize = 8;
/// Explicit usages one main item may name (a range counts as two).
const MAX_USAGES: usize = 16;
/// Push/Pop depth.
const MAX_STACK: usize = 4;
/// Collection nesting.
const MAX_DEPTH: usize = 16;
/// Largest report, in bits, a field may reach into.
const MAX_REPORT_BITS: u32 = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A run of `count` variable fields of `size` bits, each a key or a button
    /// that is down while its value is not zero. Element `i` is usage
    /// `base + i` of `page` (keyboard or button).
    Bits,
    /// An array of `count` fields of `size` bits, each naming a keyboard-page
    /// usage: the value `v` is usage `base + (v - lmin)`; a value outside
    /// `lmin..=lmax` names nothing.
    Array,
    /// A relative axis: the value is a movement.
    Rel,
    /// An absolute axis: the value is a position in `lmin..=lmax`.
    Abs,
}

/// One field (or run of fields) of an Input report with an evdev meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub kind: Kind,
    /// Index into [`Layout::ids`] of the report the control is in.
    pub id: u8,
    /// Bit offset of the first element from the start of the report's payload
    /// (after the ID byte, when there are IDs).
    pub off: u16,
    /// Bits per element (1..=32).
    pub size: u8,
    pub count: u16,
    /// [`Kind::Bits`]: the usage page of the run.
    pub page: u16,
    /// [`Kind::Bits`]: usage of element 0. [`Kind::Array`]: usage of the value
    /// `lmin`.
    pub base: u16,
    pub lmin: i32,
    pub lmax: i32,
    /// [`Kind::Rel`] and [`Kind::Abs`]: the evdev axis code.
    pub code: u16,
}

impl Control {
    const NONE: Control =
        Control { kind: Kind::Bits, id: 0, off: 0, size: 0, count: 0, page: 0, base: 0, lmin: 0, lmax: 0, code: 0 };
}

/// What the parser refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An item runs past the end of the descriptor.
    Truncated,
    /// More controls than [`MAX_CONTROLS`].
    TooManyControls,
    /// More report IDs than [`MAX_IDS`].
    TooManyIds,
    /// Collections or Push/Pop nested deeper than the parser holds, or an End
    /// Collection / Pop with nothing to end.
    Unbalanced,
    /// A report larger than the parser reads.
    TooBig,
}

/// The fields of a descriptor's Input reports a driver here reads.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    controls: [Control; MAX_CONTROLS],
    n: u8,
    /// The report IDs, in order of first appearance; `ids[0]` is 0 when the
    /// descriptor has no Report ID item.
    pub ids: [u8; MAX_IDS],
    pub n_ids: u8,
    /// Input bits of each report (the payload, without the ID byte).
    pub bits: [u16; MAX_IDS],
    /// The descriptor uses report IDs: byte 0 of every report is the ID.
    pub has_ids: bool,
    /// The layout has a key (a keyboard collection with keys).
    pub keys: bool,
    /// The layout has a button or an axis (a pointer).
    pub pointer: bool,
}

impl Layout {
    pub const EMPTY: Layout = Layout {
        controls: [Control::NONE; MAX_CONTROLS],
        n: 0,
        ids: [0; MAX_IDS],
        n_ids: 0,
        bits: [0; MAX_IDS],
        has_ids: false,
        keys: false,
        pointer: false,
    };

    pub fn controls(&self) -> &[Control] {
        &self.controls[..self.n as usize]
    }

    /// Does the descriptor give the driver anything to report?
    pub fn is_useful(&self) -> bool {
        self.n > 0
    }

    /// The index of report ID `id`, if the layout has it.
    pub fn index_of(&self, id: u8) -> Option<usize> {
        self.ids[..self.n_ids as usize].iter().position(|&i| i == id)
    }

    /// The bytes of the largest report, ID byte included.
    pub fn max_report_bytes(&self) -> usize {
        let payload = self.bits[..self.n_ids as usize].iter().map(|&b| (b as usize).div_ceil(8)).max().unwrap_or(0);
        payload + self.has_ids as usize
    }

    /// Parse a report descriptor.
    pub fn parse(desc: &[u8]) -> Result<Layout, ParseError> {
        let mut p = Parser::new();
        p.run(desc)?;
        Ok(p.finish())
    }
}

// ---- The parser ----

#[derive(Clone, Copy)]
struct Global {
    page: u16,
    lmin: i32,
    /// Logical Maximum as the descriptor wrote it, and the bytes it took:
    /// whether it is signed depends on the minimum, known only at the main item.
    lmax_raw: u32,
    lmax_size: u8,
    size: u32,
    count: u32,
    id: u8,
}

impl Global {
    const INIT: Global = Global { page: 0, lmin: 0, lmax_raw: 0, lmax_size: 0, size: 0, count: 0, id: 0 };

    fn lmax(&self) -> i32 {
        if self.lmin < 0 { sign_extend(self.lmax_raw, self.lmax_size) } else { self.lmax_raw as i32 }
    }
}

#[derive(Clone, Copy)]
struct Local {
    usages: [u32; MAX_USAGES],
    n: usize,
    min: Option<u32>,
    max: Option<u32>,
}

impl Local {
    const INIT: Local = Local { usages: [0; MAX_USAGES], n: 0, min: None, max: None };
}

/// Which usages a collection's controls are read as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum App {
    Other,
    Keyboard,
    Pointer,
}

struct Parser {
    layout: Layout,
    g: Global,
    stack: [Global; MAX_STACK],
    sp: usize,
    l: Local,
    /// Open collections, and the application collection the outermost is.
    depth: usize,
    app: App,
    /// Input bits consumed so far in each report.
    off: [u32; MAX_IDS],
}

fn sign_extend(v: u32, size: u8) -> i32 {
    match size {
        1 => v as u8 as i8 as i32,
        2 => v as u16 as i16 as i32,
        _ => v as i32,
    }
}

impl Parser {
    fn new() -> Parser {
        Parser {
            layout: Layout::EMPTY,
            g: Global::INIT,
            stack: [Global::INIT; MAX_STACK],
            sp: 0,
            l: Local::INIT,
            depth: 0,
            app: App::Other,
            off: [0; MAX_IDS],
        }
    }

    fn run(&mut self, d: &[u8]) -> Result<(), ParseError> {
        let mut i = 0;
        while i < d.len() {
            let prefix = d[i];
            if prefix == 0xfe {
                // A long item: bDataSize, bLongItemTag, data. Nothing defined uses it.
                let size = *d.get(i + 1).ok_or(ParseError::Truncated)? as usize;
                i += 3 + size;
                if i > d.len() {
                    return Err(ParseError::Truncated);
                }
                continue;
            }
            let size = match prefix & 3 {
                3 => 4,
                s => s as usize,
            };
            let ty = (prefix >> 2) & 3;
            let tag = prefix >> 4;
            let data = d.get(i + 1..i + 1 + size).ok_or(ParseError::Truncated)?;
            i += 1 + size;
            let mut v = 0u32;
            for (k, b) in data.iter().enumerate() {
                v |= (*b as u32) << (8 * k);
            }
            match ty {
                0 => self.main(tag, v)?,
                1 => self.global(tag, v, size as u8)?,
                2 => self.local(tag, v, size as u8),
                _ => {}
            }
        }
        Ok(())
    }

    fn global(&mut self, tag: u8, v: u32, size: u8) -> Result<(), ParseError> {
        match tag {
            0 => self.g.page = v as u16,
            1 => self.g.lmin = sign_extend(v, size),
            2 => {
                self.g.lmax_raw = v;
                self.g.lmax_size = size;
            }
            7 => self.g.size = v,
            8 => {
                self.g.id = v as u8;
                self.layout.has_ids = true;
            }
            9 => self.g.count = v,
            0xa => {
                if self.sp == MAX_STACK {
                    return Err(ParseError::Unbalanced);
                }
                self.stack[self.sp] = self.g;
                self.sp += 1;
            }
            0xb => {
                if self.sp == 0 {
                    return Err(ParseError::Unbalanced);
                }
                self.sp -= 1;
                self.g = self.stack[self.sp];
            }
            _ => {}
        }
        Ok(())
    }

    fn local(&mut self, tag: u8, v: u32, size: u8) {
        // A usage of four bytes carries its own page.
        let full = |g: &Global| if size == 4 { v } else { (g.page as u32) << 16 | (v & 0xffff) };
        match tag {
            0 => {
                if self.l.n < MAX_USAGES {
                    self.l.usages[self.l.n] = full(&self.g);
                    self.l.n += 1;
                }
            }
            1 => self.l.min = Some(full(&self.g)),
            2 => self.l.max = Some(full(&self.g)),
            _ => {}
        }
    }

    fn main(&mut self, tag: u8, v: u32) -> Result<(), ParseError> {
        match tag {
            // Input.
            8 => self.input(v)?,
            // Output and Feature take no bits of an Input report.
            9 | 0xb => {}
            // Collection.
            0xa => {
                if self.depth == 0 {
                    // The application collection: its first usage says what it is.
                    let first = self.l.usages[..self.l.n].first().copied().or(self.l.min).unwrap_or(0);
                    self.app = match (first >> 16, first as u16) {
                        (0x01, GD_KEYBOARD | GD_KEYPAD) => App::Keyboard,
                        (0x01, GD_MOUSE | GD_POINTER) => App::Pointer,
                        _ => App::Other,
                    };
                }
                if self.depth == MAX_DEPTH {
                    return Err(ParseError::Unbalanced);
                }
                self.depth += 1;
            }
            // End Collection.
            0xc => {
                if self.depth == 0 {
                    return Err(ParseError::Unbalanced);
                }
                self.depth -= 1;
                if self.depth == 0 {
                    self.app = App::Other;
                }
            }
            _ => {}
        }
        self.l = Local::INIT;
        Ok(())
    }

    /// The report slot of the current ID.
    fn slot(&mut self) -> Result<usize, ParseError> {
        let n = self.layout.n_ids as usize;
        if let Some(i) = self.layout.ids[..n].iter().position(|&i| i == self.g.id) {
            return Ok(i);
        }
        if n == MAX_IDS {
            return Err(ParseError::TooManyIds);
        }
        self.layout.ids[n] = self.g.id;
        self.layout.n_ids += 1;
        Ok(n)
    }

    fn push(&mut self, c: Control) -> Result<(), ParseError> {
        let n = self.layout.n as usize;
        if n == MAX_CONTROLS {
            return Err(ParseError::TooManyControls);
        }
        self.layout.controls[n] = c;
        self.layout.n += 1;
        Ok(())
    }

    /// The usage of element `i` of the current main item: an explicit list
    /// (the last usage serves the rest), or a range, or none (padding).
    fn usage_of(&self, i: u32) -> Option<u32> {
        if self.l.n > 0 {
            return Some(self.l.usages[(i as usize).min(self.l.n - 1)]);
        }
        match (self.l.min, self.l.max) {
            (Some(min), Some(max)) => Some(min.saturating_add(i).min(max)),
            _ => None,
        }
    }

    fn input(&mut self, flags: u32) -> Result<(), ParseError> {
        let (size, count) = (self.g.size, self.g.count);
        let bits = size.checked_mul(count).filter(|&b| b <= MAX_REPORT_BITS).ok_or(ParseError::TooBig)?;
        let slot = self.slot()?;
        let off = self.off[slot];
        if off + bits > MAX_REPORT_BITS {
            return Err(ParseError::TooBig);
        }
        self.off[slot] = off + bits;
        self.layout.bits[slot] = (off + bits) as u16;
        let constant = flags & 1 != 0;
        let variable = flags & 2 != 0;
        let relative = flags & 4 != 0;
        if constant || count == 0 || self.app == App::Other {
            return Ok(());
        }
        if size == 0 || size > 32 {
            // Wider than a value here is read as: not a key, a button or an axis.
            return Ok(());
        }
        let lmin = self.g.lmin;
        let lmax = self.g.lmax();
        if !variable {
            // An array of keyboard usages.
            if self.app == App::Keyboard && count <= u16::MAX as u32 {
                if let Some(first) = self.l.min.or_else(|| self.l.usages[..self.l.n].first().copied()) {
                    if first >> 16 == PAGE_KEYBOARD as u32 {
                        self.layout.keys = true;
                        return self.push(Control {
                            kind: Kind::Array,
                            id: slot as u8,
                            off: off as u16,
                            size: size as u8,
                            count: count as u16,
                            page: PAGE_KEYBOARD,
                            base: first as u16,
                            lmin,
                            lmax,
                            code: 0,
                        });
                    }
                }
            }
            return Ok(());
        }
        // Variable fields: a run of consecutive keyboard or button usages is one
        // control; every other usage is judged on its own.
        let Some(first) = self.usage_of(0) else { return Ok(()) };
        let (page, usage) = ((first >> 16) as u16, first as u16);
        let in_range = self.l.n == 0;
        let keyboard_run = in_range && page == PAGE_KEYBOARD && self.app == App::Keyboard;
        let button_run = in_range && page == PAGE_BUTTON && self.app == App::Pointer;
        if (keyboard_run || button_run) && count <= u16::MAX as u32 {
            if keyboard_run {
                self.layout.keys = true;
            } else {
                self.layout.pointer = true;
            }
            return self.push(Control {
                kind: Kind::Bits,
                id: slot as u8,
                off: off as u16,
                size: size as u8,
                count: count as u16,
                page,
                base: usage,
                lmin: 0,
                lmax: 0,
                code: 0,
            });
        }
        for i in 0..count {
            let Some(u) = self.usage_of(i) else { continue };
            let (page, usage) = ((u >> 16) as u16, u as u16);
            let at = (off + i * size) as u16;
            let mut c = Control { id: slot as u8, off: at, size: size as u8, count: 1, page, base: usage, lmin, lmax, ..Control::NONE };
            match (self.app, page, usage) {
                (App::Keyboard, PAGE_KEYBOARD, _) if key_code(usage) != 0 => {
                    self.layout.keys = true;
                    c.kind = Kind::Bits;
                }
                (App::Pointer, PAGE_BUTTON, _) if button_code(usage) != 0 => {
                    self.layout.pointer = true;
                    c.kind = Kind::Bits;
                }
                (App::Pointer, PAGE_GENERIC_DESKTOP, GD_X | GD_Y | GD_WHEEL) | (App::Pointer, PAGE_CONSUMER, CONSUMER_AC_PAN) => {
                    self.layout.pointer = true;
                    c.kind = if relative { Kind::Rel } else { Kind::Abs };
                    c.code = match (page, usage) {
                        (_, GD_X) => if relative { REL_X } else { ABS_X },
                        (_, GD_Y) => if relative { REL_Y } else { ABS_Y },
                        (PAGE_GENERIC_DESKTOP, _) => REL_WHEEL,
                        _ => REL_HWHEEL,
                    };
                    // The wheels have no absolute form here.
                    if c.kind == Kind::Abs && c.code != ABS_X && c.code != ABS_Y {
                        continue;
                    }
                }
                _ => continue,
            }
            self.push(c)?;
        }
        Ok(())
    }

    fn finish(self) -> Layout {
        self.layout
    }
}
