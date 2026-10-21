// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel entropy pool through the `Entropy` interface, written out by
//! hand because the generated client (`azos_devif`) needs the IDL proc-macro,
//! which cannot be part of the std build graph. The ids and the wire form are
//! pinned to the generated ones by `tests/host/stdrt-tests`, which runs this
//! function against the generated dispatcher.
//!
//! Request: the header word (`id << 32 | level << 16 | op`) and the number of
//! words wanted. Reply: the status word (0 = served), the outcome code (0 =
//! served) and [`DRAW_WORDS`] words of the pool.

use azos_abi::ipc_msg::{MsgDesc, MSG_VERSION};

/// The interface id (ASCII "ENTR"), `azos_devif::ENTROPY_ID`.
pub const ENTROPY_ID: u32 = 0x454E_5452;
/// The host key of the kernel-hosted `entropy` endpoint, `azos_devif::key::ENTROPY`.
pub const ENTROPY_KEY: u16 = 1;
/// Words one draw returns at most, `azos_devif::entropy::DRAW_WORDS`.
pub const DRAW_WORDS: usize = 6;
const LEVEL: u64 = 1;
const OP_DRAW: u64 = 1;

/// Fill `out` from the pool by calling `call` (the endpoint call: request in
/// `*msg`, reply written over it, 0 when answered). `false` when the pool is
/// not ready, the capability lacks `READ`, or the call did not reach the
/// interface; `out` is then partly or not written.
pub fn fill(call: &mut dyn FnMut(&mut MsgDesc) -> isize, out: &mut [u8]) -> bool {
    let mut done = 0;
    while done < out.len() {
        let want = (out.len() - done).min(DRAW_WORDS * 8);
        let words = want.div_ceil(8);
        let mut m = MsgDesc { version: MSG_VERSION, n_words: 2, ..MsgDesc::default() };
        m.words[0] = (ENTROPY_ID as u64) << 32 | LEVEL << 16 | OP_DRAW;
        m.words[1] = words as u64;
        if call(&mut m) != 0 || m.words[0] != 0 || m.words[1] != 0 {
            return false;
        }
        for (i, b) in out[done..done + want].iter_mut().enumerate() {
            *b = m.words[2 + i / 8].to_le_bytes()[i % 8];
        }
        // The words were key material in this frame: not left behind.
        // SAFETY: a valid, aligned reference; volatile so it is not elided.
        unsafe { core::ptr::write_volatile(&mut m.words, [0; azos_abi::ipc_msg::MSG_WORDS_MAX]) };
        done += want;
    }
    true
}
