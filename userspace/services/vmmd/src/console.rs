// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-console backend (device id 3): one port, `receiveq` (queue 0,
//! host to guest) and `transmitq` (queue 1, guest to host), no features
//! beyond `VERSION_1` (no multiport, no size, no emergency write).
//!
//! The bytes the guest writes go to a [`Term`], and the bytes the term has
//! for the guest are delivered into the buffers it offers. The term is the
//! console's owner side: it has no authority a guest can widen, only the
//! write and the read it is given.
//!
//! # Why the guest's console is not a termd session
//!
//! `termd` serves one client, the shell, over the one `endpoint.term` the
//! topology grants the shell's row; a second session would need an endpoint
//! per guest in the topology and a session table in the server, neither of
//! which exists. Until they do, the guest's output reaches the operator's
//! console through [`Guarded`], which gives it none of the console's
//! powers: only printable ASCII and newlines pass (an escape sequence cannot
//! move the cursor, retitle or clear the screen, or fake the kernel's own
//! lines), every line is marked with the guest's name, and the volume is a
//! token bucket, so a guest that prints in a loop loses bytes, counted and
//! reported, instead of flooding the console the operator and the kernel log
//! share. There is no input: the console's input belongs to its owner (the
//! shell and termd), and nothing lends it to a guest.

use crate::guest::GuestMem;
use crate::mmio::{Device, F_VERSION_1, MAX_QUEUES};
use crate::virtq::{Virtq, VqError};

/// Bytes of a guest's write handed to the term at a time.
const CHUNK: usize = 256;

/// The console the guest's port is attached to.
pub trait Term {
    /// The guest wrote these bytes.
    fn write(&mut self, bytes: &[u8]);
    /// Take input for the guest, without waiting; the count (0: none).
    fn read(&mut self, buf: &mut [u8]) -> usize;
    /// The loop's clock, called once a pass: what a term that limits volume
    /// refills from.
    fn tick(&mut self, _now_ns: u64) {}
}

/// Bytes of output a guest may print per second.
pub const RATE_BPS: u64 = 4096;
/// Bytes it may print at once after being quiet.
pub const BURST: u64 = 2048;
/// The marker at the start of each line the guest prints.
pub const TAG: &[u8] = b"[vm0] ";
/// Bytes handed to the inner term in one write.
const OUT: usize = 512;

/// A guest's output made safe for a console it shares: see the module comment.
pub struct Guarded<T: Term> {
    pub inner: T,
    /// Bytes the guest may still print now.
    budget: u64,
    last_ns: u64,
    /// Is the next byte the first of a line?
    bol: bool,
    /// Bytes dropped since the last report.
    lost: u64,
    /// Bytes replaced with `?` (not printable).
    pub replaced: u64,
    /// Bytes dropped for want of budget, ever.
    pub dropped: u64,
}

impl<T: Term> Guarded<T> {
    pub fn new(inner: T) -> Self {
        Guarded { inner, budget: BURST, last_ns: 0, bol: true, lost: 0, replaced: 0, dropped: 0 }
    }

    /// Pay `cost` output bytes; `false` when the budget does not cover them.
    fn take(&mut self, cost: u64) -> bool {
        #[cfg(feature = "canary-term-unlimited")]
        {
            let _ = cost;
            return true;
        }
        #[cfg(not(feature = "canary-term-unlimited"))]
        if self.budget >= cost {
            self.budget -= cost;
            true
        } else {
            false
        }
    }
}

impl<T: Term> Term for Guarded<T> {
    fn write(&mut self, bytes: &[u8]) {
        let mut out = [0u8; OUT];
        let mut n = 0;
        for &b in bytes {
            let ch = match b {
                b'\n' => b'\n',
                b'\t' => b' ',
                0x20..=0x7E => b,
                #[cfg(feature = "canary-term-unfiltered")]
                _ => b,
                #[cfg(not(feature = "canary-term-unfiltered"))]
                _ => b'?',
            };
            // The marker is paid for with the first byte of a line; a blank
            // line costs its newline alone.
            let tag = self.bol && ch != b'\n';
            let cost = 1 + if tag { TAG.len() as u64 } else { 0 };
            if !self.take(cost) {
                self.lost += 1;
                self.dropped += 1;
                continue;
            }
            if ch != b && ch != b'\n' {
                self.replaced += 1;
            }
            if out.len() - n < TAG.len() + 1 {
                self.inner.write(&out[..n]);
                n = 0;
            }
            if tag {
                out[n..n + TAG.len()].copy_from_slice(TAG);
                n += TAG.len();
            }
            out[n] = ch;
            n += 1;
            self.bol = ch == b'\n';
        }
        if n > 0 {
            self.inner.write(&out[..n]);
        }
    }

    /// The guest has no input.
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }

    /// Refill the budget for the time that passed, and say once what was lost
    /// while it was empty.
    fn tick(&mut self, now_ns: u64) {
        let elapsed = now_ns.saturating_sub(self.last_ns);
        if self.last_ns == 0 || elapsed >= 1_000_000_000 {
            // The first pass, or a long quiet: a full bucket.
            self.budget = BURST;
            self.last_ns = now_ns;
        } else {
            let earned = elapsed * RATE_BPS / 1_000_000_000;
            if earned > 0 {
                self.budget = (self.budget + earned).min(BURST);
                // Keep the fraction of a byte the time bought for next time.
                self.last_ns += earned * 1_000_000_000 / RATE_BPS;
            }
        }
        // The notice is vmmd's, not the guest's: it is not charged, and it
        // waits for a line boundary and some room so it is read whole.
        if self.lost > 0 && self.budget >= BURST / 2 {
            let mut msg = [0u8; 48];
            let mut n = 0;
            if !self.bol {
                msg[0] = b'\n';
                n = 1;
            }
            msg[n..n + TAG.len()].copy_from_slice(TAG);
            n += TAG.len();
            let mut digits = [0u8; 20];
            let (mut d, mut v) = (digits.len(), self.lost);
            while v > 0 {
                d -= 1;
                digits[d] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            let num = &digits[d..];
            msg[n..n + num.len()].copy_from_slice(num);
            n += num.len();
            let tail = b" bytes dropped\n";
            msg[n..n + tail.len()].copy_from_slice(tail);
            n += tail.len();
            self.inner.write(&msg[..n]);
            self.lost = 0;
            self.bol = true;
        }
    }
}

/// The device.
pub struct Console<T: Term> {
    pub term: T,
    pend: [u8; CHUNK],
    pend_len: usize,
    pend_off: usize,
    /// Bytes the guest wrote.
    pub out_bytes: u64,
    /// Bytes delivered to the guest.
    pub in_bytes: u64,
}

impl<T: Term> Console<T> {
    pub fn new(term: T) -> Self {
        Console { term, pend: [0; CHUNK], pend_len: 0, pend_off: 0, out_bytes: 0, in_bytes: 0 }
    }

    fn transmit(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        let mut any = false;
        let mut buf = [0u8; CHUNK];
        while let Some(chain) = vqs[1].pop(mem)? {
            let total = chain.readable();
            let mut off = 0u64;
            while off < total {
                let n = (total - off).min(CHUNK as u64) as usize;
                chain.read_at(mem, off, &mut buf[..n])?;
                self.term.write(&buf[..n]);
                self.out_bytes += n as u64;
                off += n as u64;
            }
            vqs[1].push_used(mem, &chain, 0)?;
            any = true;
        }
        Ok(any)
    }

    fn receive(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        let mut any = false;
        loop {
            if self.pend_len == 0 {
                self.pend_len = self.term.read(&mut self.pend).min(CHUNK);
                if self.pend_len == 0 {
                    break;
                }
            }
            let Some(chain) = vqs[0].pop(mem)? else { break };
            // A buffer smaller than the chunk takes what fits; the rest waits
            // for the next one.
            let n = (chain.writable() as usize).min(self.pend_len - self.pend_off);
            chain.write_at(mem, 0, &self.pend[self.pend_off..self.pend_off + n])?;
            self.pend_off += n;
            self.in_bytes += n as u64;
            if self.pend_off == self.pend_len {
                self.pend_off = 0;
                self.pend_len = 0;
            }
            vqs[0].push_used(mem, &chain, n as u32)?;
            any = true;
        }
        Ok(any)
    }
}

impl<T: Term> Device for Console<T> {
    fn id(&self) -> u32 {
        3
    }

    fn features(&self) -> u64 {
        F_VERSION_1
    }

    fn queues(&self) -> usize {
        2
    }

    fn read_config(&self, _off: usize, out: &mut [u8]) {
        out.fill(0);
    }

    fn notify(&mut self, q: usize, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        if q == 1 { self.transmit(vqs, mem) } else { self.receive(vqs, mem) }
    }

    fn poll(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        self.receive(vqs, mem)
    }
}
