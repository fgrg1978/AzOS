// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `irq-order-probe` (wave 15, DAIF): a function the gate disassembles to see
//! that the interrupt-mask primitives are compiler barriers on this ISA.
//!
//! It stores 1, masks interrupts through `ARCH.disable_all()`, stores 2 and
//! restores. With the mask asm a barrier, the first store is live (the asm
//! may read memory) and must be emitted BEFORE the mask instruction (`csrw
//! sstatus` / `msr DAIF`), and the second after it. With `nomem` on that asm
//! (`irq-nomem-canary`) the first store is dead and LLVM drops it, or moves
//! the stores across the mask: the `irq order` rows read the order of the
//! stores against the mask in `llvm-objdump` output.

use azos_arch::ARCH;
use azos_arch_api::Interrupts;

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn azos_irq_order_probe(p: *mut u64) {
    unsafe {
        p.write(1);
        let t = ARCH.disable_all();
        p.write(2);
        ARCH.restore(t);
    }
}

/// Keeps the probe in the image without a caller.
#[used]
static KEEP: extern "C" fn(*mut u64) = azos_irq_order_probe;
