// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Random bytes are the kernel pool, through the `Entropy` interface the
//! program's topology row grants (`HashMap`'s keys come from here).

pub fn fill_bytes(bytes: &mut [u8]) {
    if !azos_stdrt::alloc::fill_entropy(bytes) {
        panic!("no kernel entropy: the program's row needs the entropy capability and a seeded pool");
    }
}
