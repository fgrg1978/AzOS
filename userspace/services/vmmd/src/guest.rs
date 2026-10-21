// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Guest-physical memory as the device models see it.
//!
//! The guest is untrusted code: every address a descriptor, a ring index or a
//! register carries is the guest's to forge. The models therefore reach guest
//! RAM only through [`GuestMem`], whose contract is that **an access outside
//! the RAM range fails and touches nothing**: the real implementation is a
//! window onto memory that vmmd maps, and what lies beyond it is vmmd's own.
//! Callers (the virtqueue code) check the range as well, so a model never
//! asks for an access its memory would have to refuse.

/// An access that is not wholly inside guest RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfRam;

/// Guest RAM, addressed by guest-physical address.
pub trait GuestMem {
    /// `(base, len)`: the guest-physical range RAM occupies.
    fn range(&self) -> (u64, u64);
    /// Copy `out.len()` bytes from `gpa`.
    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), OutOfRam>;
    /// Copy `data` to `gpa`.
    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), OutOfRam>;

    /// Is `[gpa, gpa + len)` wholly inside RAM? Overflow is outside.
    fn contains(&self, gpa: u64, len: u64) -> bool {
        let (base, size) = self.range();
        match (gpa.checked_add(len), base.checked_add(size)) {
            (Some(end), Some(ram_end)) => gpa >= base && end <= ram_end,
            _ => false,
        }
    }
}

pub fn read_u16(m: &dyn GuestMem, gpa: u64) -> Result<u16, OutOfRam> {
    let mut b = [0u8; 2];
    m.read(gpa, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

pub fn read_u32(m: &dyn GuestMem, gpa: u64) -> Result<u32, OutOfRam> {
    let mut b = [0u8; 4];
    m.read(gpa, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

pub fn read_u64(m: &dyn GuestMem, gpa: u64) -> Result<u64, OutOfRam> {
    let mut b = [0u8; 8];
    m.read(gpa, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

pub fn write_u16(m: &mut dyn GuestMem, gpa: u64, v: u16) -> Result<(), OutOfRam> {
    m.write(gpa, &v.to_le_bytes())
}

pub fn write_u32(m: &mut dyn GuestMem, gpa: u64, v: u32) -> Result<(), OutOfRam> {
    m.write(gpa, &v.to_le_bytes())
}

/// Most memory objects a guest's RAM is made of: a task holds that many
/// capabilities for them (the table is 256 slots, and vmmd's other handles
/// come out of it).
pub const MAX_SEGS: usize = 200;

/// A range of guest RAM as this task maps it.
#[derive(Clone, Copy)]
struct Seg {
    gpa: u64,
    len: u64,
    base: *mut u8,
}

/// Why a range was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegError {
    /// Not the next range: RAM is attached in ascending order from its base,
    /// each range where the last ended.
    NotNext,
    /// Past the end of the RAM window, or empty.
    OutOfWindow,
    /// [`MAX_SEGS`] ranges are attached.
    Full,
}

/// The guest's RAM, as the memory objects that make it (each mapped into this
/// task and attached to the VM at its guest-physical address).
///
/// It answers [`GuestMem::range`] only when the whole window is attached: a
/// guest with part of its memory missing has no queue a model could trust.
/// Within the window an access is split across the ranges it spans, and it is
/// all or nothing.
pub struct SegRam {
    window_base: u64,
    window_bytes: u64,
    segs: [Seg; MAX_SEGS],
    n: usize,
    attached: u64,
}

impl SegRam {
    /// No RAM: every access is refused.
    pub const fn new() -> SegRam {
        SegRam {
            window_base: 0,
            window_bytes: 0,
            segs: [Seg { gpa: 0, len: 0, base: core::ptr::null_mut() }; MAX_SEGS],
            n: 0,
            attached: 0,
        }
    }

    /// The window the VM's RAM occupies (`Vm::config`'s `mem_mib` and
    /// `ram_base`).
    pub fn set_window(&mut self, base: u64, bytes: u64) {
        self.window_base = base;
        self.window_bytes = bytes;
    }

    /// Bytes attached so far.
    #[cfg(test)]
    pub fn attached(&self) -> u64 {
        self.attached
    }

    /// Is the whole window attached?
    pub fn complete(&self) -> bool {
        self.window_bytes != 0 && self.attached == self.window_bytes
    }

    /// Add the range of `len` bytes at guest-physical `gpa`, mapped at `base`.
    ///
    /// # Safety
    /// `base` is valid for reads and writes of `len` bytes for as long as the
    /// `SegRam` lives, and nothing else in this program uses those bytes.
    pub unsafe fn attach(&mut self, gpa: u64, len: u64, base: *mut u8) -> Result<(), SegError> {
        if self.n == MAX_SEGS {
            return Err(SegError::Full);
        }
        if gpa != self.window_base + self.attached {
            return Err(SegError::NotNext);
        }
        if len == 0 || self.attached + len > self.window_bytes {
            return Err(SegError::OutOfWindow);
        }
        self.segs[self.n] = Seg { gpa, len, base };
        self.n += 1;
        self.attached += len;
        Ok(())
    }

    /// The range holding `gpa`: its index.
    fn seg_of(&self, gpa: u64) -> usize {
        // The ranges are contiguous from the base, so the one holding `gpa`
        // is the last that starts at or before it.
        self.segs[..self.n].partition_point(|s| s.gpa <= gpa) - 1
    }

    /// Visit the pieces of `[gpa, gpa + len)`, one per range it touches, as
    /// `(pointer, bytes, offset into the access)`. The caller has checked the
    /// access is inside the window, which is complete.
    fn pieces(&self, gpa: u64, len: usize, mut f: impl FnMut(*mut u8, usize, usize)) {
        let (mut at, mut done) = (gpa, 0usize);
        let mut i = self.seg_of(gpa);
        while done < len {
            let s = self.segs[i];
            let off = at - s.gpa;
            let take = (len - done).min((s.len - off) as usize);
            // SAFETY: `off < s.len`, so the pointer stays inside the range.
            f(unsafe { s.base.add(off as usize) }, take, done);
            at += take as u64;
            done += take;
            i += 1;
        }
    }
}

impl GuestMem for SegRam {
    fn range(&self) -> (u64, u64) {
        if self.complete() { (self.window_base, self.window_bytes) } else { (0, 0) }
    }

    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, out.len() as u64) {
            return Err(OutOfRam);
        }
        if out.is_empty() {
            return Ok(());
        }
        let dst = out.as_mut_ptr();
        // SAFETY: each piece is inside a range `attach` was promised valid;
        // `out` has `len` bytes and the pieces' offsets and sizes tile it.
        self.pieces(gpa, out.len(), |p, n, off| unsafe { core::ptr::copy_nonoverlapping(p, dst.add(off), n) });
        Ok(())
    }

    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, data.len() as u64) {
            return Err(OutOfRam);
        }
        if data.is_empty() {
            return Ok(());
        }
        let src = data.as_ptr();
        // SAFETY: as `read`, the other way.
        self.pieces(gpa, data.len(), |p, n, off| unsafe { core::ptr::copy_nonoverlapping(src.add(off), p, n) });
        Ok(())
    }
}

/// Why [`attach_all`] stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachStop {
    /// `make` could not provide an object for the range at this guest-physical
    /// address (a quota, a refusal by the VM).
    Make { at: u64 },
    /// The `SegRam` would not take what `make` gave.
    Seg(SegError),
}

/// Fill the window of `ram` with objects of at most `chunk` bytes, in order.
/// `make(gpa, len)` makes one object, maps it here and attaches it to the VM at
/// `gpa`, and answers where it is mapped. Stops at the first failure; what was
/// attached before stays, and the RAM is then not complete.
///
/// # Safety
/// What `make` answers is valid for reads and writes of `len` bytes for as
/// long as `ram` lives, and nothing else uses those bytes.
pub unsafe fn attach_all(
    ram: &mut SegRam,
    base: u64,
    bytes: u64,
    chunk: u64,
    mut make: impl FnMut(u64, u64) -> Option<*mut u8>,
) -> Result<(), AttachStop> {
    ram.set_window(base, bytes);
    let mut done = 0u64;
    while done < bytes {
        let len = chunk.min(bytes - done);
        let at = base + done;
        let ptr = make(at, len).ok_or(AttachStop::Make { at })?;
        // SAFETY: the caller's promise about `make`.
        unsafe { ram.attach(at, len, ptr) }.map_err(AttachStop::Seg)?;
        done += len;
    }
    Ok(())
}
