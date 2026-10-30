// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Raspberry Pi VideoCore mailbox, property-tag channel.
//!
//! On every Pi the ARM cores do not own the SoC temperature sensor or the
//! ARM clock: the VideoCore firmware does, and it answers requests posted
//! through the mailbox (channel 8, "property tags, ARM to VC"). Nor do they
//! own the power of the SoC's blocks: the USB host is off until the firmware
//! is asked to power it. This module is the whole of that interface the
//! thermal framework and the board's power domains need:
//!
//! * [`MsgBuf`] builds and parses a message: a header, tags (`id`, value
//!   buffer size, request or response code, value words) and an end tag. The
//!   encoding is pure, so the host suite checks it word for word.
//! * The typed requests: [`MsgBuf::get_temperature`], [`MsgBuf::get_max_temperature`],
//!   [`MsgBuf::get_clock_rate`], [`MsgBuf::get_min_clock_rate`],
//!   [`MsgBuf::get_max_clock_rate`], [`MsgBuf::set_clock_rate`],
//!   [`MsgBuf::set_power_state`], each with its decoder.
//! * [`Mailbox`] posts a message through a [`MailboxPort`] (the register
//!   file, the cache maintenance and the bus address of the buffer, supplied
//!   by the board) and waits, bounded, for the VideoCore's answer.
//!   [`MmioPort`] is the memory-mapped port, with the bus window
//!   ([`BusWindow`]) the board's SoC is known to use and the platform's
//!   address translation and cache maintenance ([`DmaHooks`]). The message
//!   buffer is a field of the [`Mailbox`], never the caller's stack: see "Who
//!   owns the buffer".
//!
//! The mailbox registers (BCM2835 ARM peripherals, "mailbox 0" read side and
//! "mailbox 1" write side): `READ` at 0x00, `STATUS` (read side) at 0x18 with
//! `EMPTY` in bit 30, `WRITE` at 0x20, `STATUS` (write side) at 0x38 with
//! `FULL` in bit 31. A word carries a 16-byte-aligned bus address in its high
//! 28 bits and the channel in the low 4. The base address is the `reg` of
//! the `brcm,bcm2835-mbox` node, so no board constant lives here.
//!
//! A call spins on the registers for at most [`SPIN_LIMIT`] polls and never
//! blocks: a thermal tick that finds the firmware silent records a sensor
//! failure (which the framework counts) instead of hanging the tick.
//!
//! # Who owns the buffer
//!
//! Once the address is posted the VideoCore owns the buffer until it posts the
//! answer word back, and a call that gave up (a timeout, a word for our
//! channel that is not ours) does not take it back: a late answer still
//! writes into it. The buffer is therefore a field of the [`Mailbox`] (which a
//! board keeps in a `static`), and after such a call the mailbox is *pending*:
//! the next call first looks, without waiting, for the answer it is owed
//! ([`MailboxError::Pending`] if it has not come), and only a drained mailbox
//! posts again. A [`Mailbox`] that is moved while pending can no longer
//! vouch for the old address, so it stays pending for good
//! ([`MailboxError::Moved`]); a mailbox that never gave up may be moved freely.

#![cfg_attr(target_os = "none", no_std)]
#![deny(missing_docs)]

/// The property-tags channel, ARM to VideoCore.
pub const CHANNEL_PROPERTY: u32 = 8;

/// Offset of the read side's data register.
pub const REG_READ: usize = 0x00;
/// Offset of the read side's status register.
pub const REG_READ_STATUS: usize = 0x18;
/// Offset of the write side's data register.
pub const REG_WRITE: usize = 0x20;
/// Offset of the write side's status register.
pub const REG_WRITE_STATUS: usize = 0x38;
/// Read status: nothing to read.
pub const STATUS_EMPTY: u32 = 1 << 30;
/// Write status: no room to write.
pub const STATUS_FULL: u32 = 1 << 31;

/// Polls of a status register before a call gives up.
pub const SPIN_LIMIT: u32 = 1_000_000;
/// Words a pending mailbox reads, at most, looking for its overdue answer.
const MAX_DRAIN: u32 = 16;

/// Message code: a request.
pub const CODE_REQUEST: u32 = 0;
/// Message code: the firmware processed the request.
pub const CODE_RESPONSE_OK: u32 = 0x8000_0000;
/// Message code: the firmware could not parse the request.
pub const CODE_RESPONSE_ERROR: u32 = 0x8000_0001;
/// Tag code bit: the firmware answered this tag (the low 31 bits are the
/// length of the value it wrote, in bytes).
pub const TAG_RESPONSE: u32 = 1 << 31;

/// Tag: get a clock's current rate (`clock id` -> `clock id, Hz`).
pub const TAG_GET_CLOCK_RATE: u32 = 0x0003_0002;
/// Tag: get a clock's maximum rate.
pub const TAG_GET_MAX_CLOCK_RATE: u32 = 0x0003_0004;
/// Tag: get a clock's minimum rate.
pub const TAG_GET_MIN_CLOCK_RATE: u32 = 0x0003_0007;
/// Tag: get a sensor's temperature (`sensor id` -> `sensor id, m°C`).
pub const TAG_GET_TEMPERATURE: u32 = 0x0003_0006;
/// Tag: get the temperature at which the firmware throttles or shuts down.
pub const TAG_GET_MAX_TEMPERATURE: u32 = 0x0003_000A;
/// Tag: set a clock's rate (`clock id, Hz, skip turbo` -> `clock id, Hz`).
pub const TAG_SET_CLOCK_RATE: u32 = 0x0003_8002;

/// Clock id of the ARM cores.
pub const CLOCK_ARM: u32 = 3;
/// Set the power state of a device: `device id`, `state` (bit 0 on, bit 1
/// wait for the change). The answer is the id and the state reached: bit 0
/// on, bit 1 "no such device". Linux `RPI_FIRMWARE_SET_POWER_STATE`, U-Boot
/// `BCM2835_MBOX_TAG_SET_POWER_STATE`.
pub const TAG_SET_POWER_STATE: u32 = 0x0002_8001;
/// [`TAG_SET_POWER_STATE`]'s state bits: on.
pub const POWER_ON: u32 = 1 << 0;
/// In a request, wait until the device is in the state asked.
pub const POWER_WAIT: u32 = 1 << 1;
/// In an answer, the firmware has no such device.
pub const POWER_NO_DEVICE: u32 = 1 << 1;
/// The USB host controller's device id in the power tags (U-Boot
/// `BCM2835_MBOX_POWER_DEVID_USB_HCD`, Linux `RPI_OLD_POWER_DOMAIN_USB`).
pub const POWER_DEVICE_USB_HCD: u32 = 3;

/// The power tags' device id of the domain a device tree names with
/// `power-domains = <&power N>` (the `raspberrypi,bcm2835-power` provider;
/// `N` from `dt-bindings/power/raspberrypi-power.h`, where
/// `RPI_POWER_DOMAIN_USB` is 6), for the domains that have one. Only the
/// domains a driver here powers are listed: USB.
pub const fn power_device_for_domain(domain: u32) -> Option<u32> {
    /// `RPI_POWER_DOMAIN_USB`.
    const DOMAIN_USB: u32 = 6;
    match domain {
        DOMAIN_USB => Some(POWER_DEVICE_USB_HCD),
        _ => None,
    }
}
/// Temperature id of the SoC.
pub const TEMP_SOC: u32 = 0;

/// Words that hold any of the typed requests: header (2), the widest tag
/// (3 + 3) and the end tag, rounded up to a 16-byte multiple.
pub const MSG_WORDS: usize = 12;

/// Header words: size and code.
const HEADER: usize = 2;
/// Words of a tag's header: id, value size, code.
const TAG_HEADER: usize = 3;

/// Why a message could not be built, posted or understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxError {
    /// The buffer is too small for the tag.
    NoRoom,
    /// The firmware did not answer within [`SPIN_LIMIT`] polls.
    Timeout,
    /// The buffer has no address the VideoCore can reach (outside the bus
    /// window of the board): nothing was posted, because the firmware would
    /// write its answer somewhere else.
    BadAddress,
    /// The firmware refused the message ([`CODE_RESPONSE_ERROR`]) or answered
    /// with an unknown code.
    Refused,
    /// The answer has no response for the tag asked, or its value is shorter
    /// than the request expects.
    NoResponse,
    /// The firmware's answer to a request is for another message than the
    /// one posted.
    Mismatch,
    /// An earlier call gave up and the firmware has not yet answered it; the
    /// buffer is still the firmware's, so nothing was posted.
    Pending,
    /// The firmware has no device with the id a power request named
    /// ([`POWER_NO_DEVICE`]), or did not reach the state asked.
    NoDevice,
    /// The mailbox moved while an answer was owed: the firmware may still
    /// write to the old address, so this mailbox never posts again.
    Moved,
}

/// A message buffer of `N` words. The mailbox takes the address in its high
/// 28 bits, so the buffer is aligned to 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct MsgBuf<const N: usize> {
    words: [u32; N],
    /// Words in use, header and end tag included once [`MsgBuf::finish`] ran.
    len: usize,
}

impl<const N: usize> MsgBuf<N> {
    /// An empty request: header only.
    pub const fn new() -> Self {
        Self { words: [0; N], len: HEADER }
    }

    /// Start over.
    pub fn clear(&mut self) {
        self.words = [0; N];
        self.len = HEADER;
    }

    /// The words, as the firmware sees them.
    pub fn words(&self) -> &[u32; N] {
        &self.words
    }

    /// Append a tag. `value` is the request payload; `value_words` the size
    /// of the value buffer (at least `value.len()`: the firmware writes its
    /// answer into it, and it may be longer than the request). Returns the
    /// word index of the value buffer.
    pub fn tag(&mut self, id: u32, value: &[u32], value_words: usize) -> Result<usize, MailboxError> {
        let vw = value_words.max(value.len());
        // Header + tag + value + the end tag.
        if self.len + TAG_HEADER + vw + 1 > N {
            return Err(MailboxError::NoRoom);
        }
        let at = self.len;
        self.words[at] = id;
        self.words[at + 1] = (vw * 4) as u32;
        self.words[at + 2] = CODE_REQUEST;
        self.words[at + TAG_HEADER..at + TAG_HEADER + value.len()].copy_from_slice(value);
        for w in &mut self.words[at + TAG_HEADER + value.len()..at + TAG_HEADER + vw] {
            *w = 0;
        }
        self.len = at + TAG_HEADER + vw;
        Ok(at + TAG_HEADER)
    }

    /// Close the message: the end tag and the total size in bytes. A message
    /// is sent only after this.
    pub fn finish(&mut self) {
        self.words[self.len] = 0;
        self.words[0] = ((self.len + 1) * 4) as u32;
        self.words[1] = CODE_REQUEST;
    }

    /// The value words the firmware wrote for tag `id`, after a call.
    pub fn response(&self, id: u32) -> Result<&[u32], MailboxError> {
        match self.words[1] {
            CODE_RESPONSE_OK => {}
            _ => return Err(MailboxError::Refused),
        }
        let end = (self.words[0] as usize / 4).min(N);
        let mut at = HEADER;
        while at + TAG_HEADER <= end && self.words[at] != 0 {
            let size = self.words[at + 1] as usize / 4;
            let code = self.words[at + 2];
            let value = at + TAG_HEADER;
            if value + size > end {
                return Err(MailboxError::NoResponse);
            }
            if self.words[at] == id {
                if code & TAG_RESPONSE == 0 {
                    return Err(MailboxError::NoResponse);
                }
                let written = ((code & !TAG_RESPONSE) as usize).div_ceil(4).min(size);
                return Ok(&self.words[value..value + written]);
            }
            at = value + size;
        }
        Err(MailboxError::NoResponse)
    }

    /// Request: the temperature of sensor `id`.
    pub fn get_temperature(id: u32) -> Self {
        Self::single(TAG_GET_TEMPERATURE, &[id], 2)
    }
    /// Request: the temperature at which sensor `id` is a danger.
    pub fn get_max_temperature(id: u32) -> Self {
        Self::single(TAG_GET_MAX_TEMPERATURE, &[id], 2)
    }
    /// Request: the current rate of clock `id`.
    pub fn get_clock_rate(id: u32) -> Self {
        Self::single(TAG_GET_CLOCK_RATE, &[id], 2)
    }
    /// Request: the minimum rate of clock `id`.
    pub fn get_min_clock_rate(id: u32) -> Self {
        Self::single(TAG_GET_MIN_CLOCK_RATE, &[id], 2)
    }
    /// Request: the maximum rate of clock `id`.
    pub fn get_max_clock_rate(id: u32) -> Self {
        Self::single(TAG_GET_MAX_CLOCK_RATE, &[id], 2)
    }
    /// Request: set clock `id` to `hz`. `skip_turbo` = 1 keeps the firmware
    /// from changing the turbo setting as a side effect; 0 lets it.
    pub fn set_clock_rate(id: u32, hz: u32, skip_turbo: u32) -> Self {
        Self::single(TAG_SET_CLOCK_RATE, &[id, hz, skip_turbo], 3)
    }

    /// Request: power device `id` on (or off), waiting for the change.
    pub fn set_power_state(id: u32, on: bool) -> Self {
        Self::single(TAG_SET_POWER_STATE, &[id, if on { POWER_ON } else { 0 } | POWER_WAIT], 2)
    }

    /// Decode a [`MsgBuf::set_power_state`] answer for device `id`: whether it
    /// is now on. [`MailboxError::NoDevice`] when the firmware has none, or
    /// answered for another device.
    pub fn power_state(&self, id: u32) -> Result<bool, MailboxError> {
        let v = self.response(TAG_SET_POWER_STATE)?;
        let (&dev, &state) = (v.first().ok_or(MailboxError::NoResponse)?, v.get(1).ok_or(MailboxError::NoResponse)?);
        if dev != id || state & POWER_NO_DEVICE != 0 {
            return Err(MailboxError::NoDevice);
        }
        Ok(state & POWER_ON != 0)
    }

    /// A message of one tag. `N` must hold it; the typed requests need [`MSG_WORDS`].
    fn single(id: u32, value: &[u32], value_words: usize) -> Self {
        let mut b = Self::new();
        // A buffer too small for one tag is a build error of the caller's
        // const, and the message that comes out says so: it has no tag and
        // `response` finds none.
        let _ = b.tag(id, value, value_words);
        b.finish();
        b
    }

    /// Decode a [`MsgBuf::get_temperature`] / [`MsgBuf::get_max_temperature`]
    /// answer: milli-degrees Celsius.
    pub fn temperature(&self, tag: u32) -> Result<i32, MailboxError> {
        let v = self.response(tag)?;
        v.get(1).map(|&m| m as i32).ok_or(MailboxError::NoResponse)
    }

    /// Decode a clock answer (`get`, `min`, `max` or `set`): Hz.
    pub fn clock_rate(&self, tag: u32) -> Result<u32, MailboxError> {
        let v = self.response(tag)?;
        v.get(1).copied().ok_or(MailboxError::NoResponse)
    }
}

impl<const N: usize> Default for MsgBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the board supplies to reach the mailbox.
pub trait MailboxPort {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
    /// The VideoCore's bus address of the `len` bytes at `buf` (the CPU
    /// physical address with the board's bus alias applied; 16-byte
    /// aligned), or `None` when the VideoCore cannot reach all of them: the
    /// message is then not posted.
    fn bus_addr(&self, buf: *const u8, len: usize) -> Option<u32>;
    /// Make the CPU's writes to `buf` visible to the VideoCore (clean the
    /// data cache over it). A port whose buffer is uncached does nothing.
    fn clean(&mut self, buf: *mut u8, len: usize) {
        let _ = (buf, len);
    }
    /// Discard the CPU's cached copy of `buf`, so the next read sees what the
    /// VideoCore wrote. A port whose buffer is uncached does nothing.
    fn invalidate(&mut self, buf: *mut u8, len: usize) {
        let _ = (buf, len);
    }
}

/// A mailbox reached through a port. It owns the message buffer the
/// firmware writes its answers into (see the module documentation), so keep
/// it in a `static` or otherwise at a fixed address.
pub struct Mailbox<P> {
    port: P,
    buf: MsgBuf<MSG_WORDS>,
    /// The word whose answer is owed, and where the buffer was when it was
    /// posted; set from the post until the answer is read.
    owed: Option<Owed>,
}

/// An answer the firmware still owes.
#[derive(Clone, Copy)]
struct Owed {
    word: u32,
    buf_at: usize,
}

impl<P: MailboxPort> Mailbox<P> {
    /// Wrap `port`.
    pub const fn new(port: P) -> Self {
        Self { port, buf: MsgBuf::new(), owed: None }
    }

    /// The port.
    pub fn port(&mut self) -> &mut P {
        &mut self.port
    }

    /// Is an answer owed (an earlier call gave up)?
    pub fn pending(&self) -> bool {
        self.owed.is_some()
    }

    fn buf_ptr(&mut self) -> *mut u8 {
        self.buf.words.as_mut_ptr() as *mut u8
    }

    /// Look, without waiting, for the answer an earlier call gave up on. On
    /// success the buffer is ours again.
    fn reclaim(&mut self) -> Result<(), MailboxError> {
        let Some(owed) = self.owed else { return Ok(()) };
        if owed.buf_at != self.buf_ptr() as usize {
            return Err(MailboxError::Moved);
        }
        // Whatever is waiting, up to a bound: foreign words are skipped.
        let mut seen = 0;
        while self.port.read32(REG_READ_STATUS) & STATUS_EMPTY == 0 {
            if self.port.read32(REG_READ) == owed.word {
                self.owed = None;
                return Ok(());
            }
            seen += 1;
            if seen > MAX_DRAIN {
                break;
            }
        }
        Err(MailboxError::Pending)
    }

    /// Post `req` and wait for the answer, which the firmware writes into
    /// the mailbox's own buffer; the buffer is returned for decoding.
    fn transact(&mut self, req: MsgBuf<MSG_WORDS>) -> Result<&MsgBuf<MSG_WORDS>, MailboxError> {
        self.reclaim()?;
        self.buf = req;
        let ptr = self.buf_ptr();
        let bytes = self.buf.words[0] as usize;
        let Some(bus) = self.port.bus_addr(ptr as *const u8, bytes) else {
            // Nothing was posted: the buffer is still ours.
            return Err(MailboxError::BadAddress);
        };
        let word = (bus & !0xF) | CHANNEL_PROPERTY;
        self.port.clean(ptr, bytes);

        let mut spins = 0;
        while self.port.read32(REG_WRITE_STATUS) & STATUS_FULL != 0 {
            spins += 1;
            if spins > SPIN_LIMIT {
                // Nothing was posted: the buffer is still ours.
                return Err(MailboxError::Timeout);
            }
        }
        self.port.write32(REG_WRITE, word);
        // From here the buffer is the firmware's until it answers.
        self.owed = Some(Owed { word, buf_at: ptr as usize });

        // Messages for other channels may arrive first; only ours ends the call.
        // The wait is bounded as a whole, so a flood of foreign words cannot
        // hold the caller either.
        let mut foreign = 0;
        loop {
            let mut spins = 0;
            while self.port.read32(REG_READ_STATUS) & STATUS_EMPTY != 0 {
                spins += 1;
                if spins > SPIN_LIMIT {
                    return Err(MailboxError::Timeout);
                }
            }
            let got = self.port.read32(REG_READ);
            if got == word {
                break;
            }
            if got & 0xF == CHANNEL_PROPERTY {
                // Our channel, another buffer: not an answer to this call,
                // and ours is still owed.
                return Err(MailboxError::Mismatch);
            }
            foreign += 1;
            if foreign > SPIN_LIMIT {
                return Err(MailboxError::Timeout);
            }
        }
        self.owed = None;
        self.port.invalidate(ptr, bytes);
        match self.buf.words[1] {
            CODE_RESPONSE_OK => Ok(&self.buf),
            _ => Err(MailboxError::Refused),
        }
    }

    /// The SoC temperature, milli-degrees Celsius.
    pub fn soc_temperature(&mut self) -> Result<i32, MailboxError> {
        self.transact(MsgBuf::get_temperature(TEMP_SOC))?.temperature(TAG_GET_TEMPERATURE)
    }

    /// The ARM clock's current rate, Hz.
    pub fn arm_clock_rate(&mut self) -> Result<u32, MailboxError> {
        self.transact(MsgBuf::get_clock_rate(CLOCK_ARM))?.clock_rate(TAG_GET_CLOCK_RATE)
    }

    /// The ARM clock's minimum rate, Hz.
    pub fn arm_min_clock_rate(&mut self) -> Result<u32, MailboxError> {
        self.transact(MsgBuf::get_min_clock_rate(CLOCK_ARM))?.clock_rate(TAG_GET_MIN_CLOCK_RATE)
    }

    /// The ARM clock's maximum rate, Hz.
    pub fn arm_max_clock_rate(&mut self) -> Result<u32, MailboxError> {
        self.transact(MsgBuf::get_max_clock_rate(CLOCK_ARM))?.clock_rate(TAG_GET_MAX_CLOCK_RATE)
    }

    /// Power device `id` on and wait until it is: [`MailboxError::NoDevice`]
    /// when the firmware has no such device or it stayed off.
    pub fn power_on(&mut self, id: u32) -> Result<(), MailboxError> {
        match self.transact(MsgBuf::set_power_state(id, true))?.power_state(id)? {
            true => Ok(()),
            false => Err(MailboxError::NoDevice),
        }
    }

    /// Set the ARM clock to `hz` and return the rate the firmware settled
    /// on (it rounds to what the PLL can make). The turbo setting is left
    /// alone.
    pub fn set_arm_clock_rate(&mut self, hz: u32) -> Result<u32, MailboxError> {
        self.transact(MsgBuf::set_clock_rate(CLOCK_ARM, hz, 1))?.clock_rate(TAG_SET_CLOCK_RATE)
    }
}

/// The part of the VideoCore's view of RAM that a board is known to map: the
/// ARM's RAM appears at `alias` (OR-ed into the physical address), and only
/// the physical addresses below what the alias leaves free reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusWindow {
    alias: u32,
}

/// The bus alias of the 32-bit-bus Pis (BCM2835/6/7 and BCM2711 legacy
/// master view): the uncached alias at 0xC000_0000, which reaches the first
/// GiB of RAM.
pub const ALIAS_UNCACHED: u32 = 0xC000_0000;

/// The `compatible` strings of the SoCs whose bus map is known, with the
/// window each has. A SoC nobody has measured is not given the firmware's
/// DMA.
///
/// The BCM2712 (Pi 5) is the identity map: the `soc` node that holds
/// `mailbox@7c013880` and the root that holds the `/firmware` node carry no
/// `dma-ranges` (`bcm2712.dtsi`, Linux v7.2), so the bus address the Linux
/// firmware driver posts for its `dma_alloc_coherent` buffer is the CPU
/// physical address, and the 32-bit mailbox word limits it to 4 GiB. That is
/// a declaration of the tree, not yet a boot on the board.
const KNOWN_SOCS: [(&[u8], BusWindow); 5] = [
    (b"brcm,bcm2835", BusWindow::UNCACHED),
    (b"brcm,bcm2836", BusWindow::UNCACHED),
    (b"brcm,bcm2837", BusWindow::UNCACHED),
    (b"brcm,bcm2711", BusWindow::UNCACHED),
    (b"brcm,bcm2712", BusWindow::IDENTITY),
];

impl BusWindow {
    /// The window of the 32-bit-bus Pis: [`ALIAS_UNCACHED`], first GiB of RAM.
    pub const UNCACHED: Self = Self { alias: ALIAS_UNCACHED };

    /// The window of the BCM2712 (Pi 5): the bus address is the physical
    /// address, as far as the 32 bits of a mailbox word reach (4 GiB).
    pub const IDENTITY: Self = Self { alias: 0 };

    /// The window of the SoC whose root `compatible` property is `root` (its
    /// NUL-separated strings, as the device tree stores them), if it is one
    /// whose bus map is known. The first string of the property that names a
    /// known SoC decides.
    pub fn for_root_compatible(root: &[u8]) -> Option<Self> {
        root.split(|&b| b == 0).find_map(|s| KNOWN_SOCS.iter().find(|(c, _)| *c == s).map(|&(_, w)| w))
    }

    /// The bus address of the `len` bytes at physical address `phys`, or
    /// `None` when any of them is outside what the alias maps (so that the
    /// OR cannot change them, and the result fits 32 bits). The identity
    /// window maps the first 4 GiB.
    pub fn bus_addr(&self, phys: u64, len: usize) -> Option<u32> {
        let reach = u64::from(!self.alias) + 1;
        let end = phys.checked_add(len as u64)?;
        if end > reach {
            return None;
        }
        Some(phys as u32 | self.alias)
    }
}

/// What the platform supplies to the memory-mapped port: the translation of
/// a kernel address to a physical one, and the cache maintenance of the
/// message buffer. (The register access and the bus window are the port's.)
pub trait DmaHooks {
    /// The physical address of `buf`.
    fn phys(&self, buf: *const u8) -> u64;
    /// Make the CPU's writes to `buf` visible to the VideoCore.
    fn clean(&mut self, buf: *mut u8, len: usize);
    /// Discard the CPU's cached copy of `buf`, so the next read sees what
    /// the VideoCore wrote.
    fn invalidate(&mut self, buf: *mut u8, len: usize);
}

/// The memory-mapped port: the registers at `base` (the `reg` of the
/// `brcm,bcm2835-mbox` node, translated to a CPU address), the board's bus
/// window, and the platform's hooks.
pub struct MmioPort<H> {
    base: usize,
    window: BusWindow,
    hooks: H,
}

impl<H: DmaHooks> MmioPort<H> {
    /// A port at `base`.
    ///
    /// # Safety
    /// `base` must be the mailbox register block, mapped as device memory,
    /// and the [`Mailbox`] over this port (whose buffer the firmware reads
    /// and writes) must live in memory the VideoCore can reach through
    /// `window` (the port checks the address, not that `window` is the
    /// board's).
    pub const unsafe fn new(base: usize, window: BusWindow, hooks: H) -> Self {
        Self { base, window, hooks }
    }
}

impl<H: DmaHooks> MailboxPort for MmioPort<H> {
    fn read32(&mut self, off: usize) -> u32 {
        // SAFETY: `new`'s contract: `base` is the mapped register block.
        unsafe { azos_arch_api::mmio::read32(self.base + off) }
    }
    fn write32(&mut self, off: usize, v: u32) {
        // SAFETY: as above.
        unsafe { azos_arch_api::mmio::write32(self.base + off, v) }
    }
    fn bus_addr(&self, buf: *const u8, len: usize) -> Option<u32> {
        self.window.bus_addr(self.hooks.phys(buf), len)
    }
    fn clean(&mut self, buf: *mut u8, len: usize) {
        self.hooks.clean(buf, len);
    }
    fn invalidate(&mut self, buf: *mut u8, len: usize) {
        self.hooks.invalidate(buf, len);
    }
}
