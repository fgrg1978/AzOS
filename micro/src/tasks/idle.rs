// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `IDLE.ELF`: the task the idle class runs when nothing else can. U-mode
//! cannot rely on `wfi` (a hart with S-mode traps it), so it spins; the
//! timer tick still preempts it.

pub extern "C" fn main(_region: usize, _info: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
