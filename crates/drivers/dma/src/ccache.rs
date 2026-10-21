// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SiFive composable cache controller (`sifive,ccache0`, the JH7110's
//! `starfive,jh7110-ccache`): cache maintenance by physical line, for cores
//! that have no Zicbom (the U74 of the VisionFive 2).
//!
//! The controller owns the shared L2. Its `Flush64` register takes the
//! physical address of one cache line and writes the line back and drops it
//! (write-back plus invalidate, Linux `sifive_ccache_flush_range`). There is
//! no clean-only operation, so the arch layer installs the same walk for both
//! halves of [`crate::cache`]'s pair: a flush where a clean would do costs a
//! refill, never data.
//!
//! This module is the walk: which lines a byte range covers and in which
//! order the register is written. The register write itself, its fences and
//! the virtual-to-physical translation are the kernel's (`kernel/src/boot/
//! dma.rs`, `azos_arch::cache`), so the walk host-tests against a recorder.
//! The register offset and the 64-byte line are from the DT binding and
//! `sifive_ccache.c`, whose source is not in the pinned Linux checkout:
//! `[verify]` against the TRM on the board.

/// Offset of `Flush64` in the controller's register window.
pub const FLUSH64: usize = 0x200;

/// Bytes one `Flush64` write covers (DT `cache-block-size`).
pub const LINE: u64 = 64;

/// Where a line flush goes: a register write the kernel makes, fenced on both
/// sides (the line's data reaches the controller before the write, and the
/// write completes before the next one).
pub trait Flush64 {
    /// Write back and drop the cache line at physical address `pa`
    /// (line-aligned).
    fn flush_line(&self, pa: u64);
}

/// Flush every line of `[pa, pa + len)`, first to last. The edge lines are
/// included whole: a buffer that does not start or end on a line shares it
/// with a neighbour, and the flush writes the neighbour's dirty bytes back
/// before dropping them. A zero length writes nothing; a range that runs past
/// the end of the address space stops there. Returns the number of lines
/// flushed.
pub fn flush_range(w: &dyn Flush64, pa: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let first = pa & !(LINE - 1);
    let last = pa.saturating_add(len - 1) & !(LINE - 1);
    let mut line = first;
    let mut n = 0;
    loop {
        w.flush_line(line);
        n += 1;
        if line >= last {
            return n;
        }
        line += LINE;
    }
}
