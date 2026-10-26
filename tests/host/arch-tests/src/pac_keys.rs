// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-process pointer-authentication keys (Kconfig `A64_PAUTH_PROC_KEYS`):
//! the pure half of `arch/aarch64/src/cpu/cfi.rs`.
//!
//! The kernel's production caller is `azos_sched::pac`, which composes these
//! calls on the events below; [`Kernel`] repeats that composition so the
//! lifecycle is pinned here (the register writes and the swap at the EL0
//! boundary are `msr` and cannot run on the host):
//!
//! * `spawn` and `exec` draw fresh keys;
//! * a `fork` child and a thread copy their creator's keys;
//! * a slot that is created again has no keys;
//! * no process's key is the kernel's, and no key is the zero a missing
//!   draw would read.
//!
//! Canary: `--features pac-canary` makes the exec model keep the old keys and
//! the fork model draw fresh ones: `an_exec_changes_every_key` and
//! `a_fork_child_and_a_thread_have_their_creators_keys` must fail.

use crate::a64_cfi::{
    derive_user_keys, enable_mask, fresh_user_keys, keys_from_bytes, keys_usable, KeyTable, UserKeys, KEY_BYTES, KEY_DA,
    KEY_DB, KEY_GA, KEY_IA, KEY_IB, KEY_WORDS, SCTLR_ENDA, SCTLR_ENDB, SCTLR_ENIB,
};
use crate::sysregs::SCTLR_EL1_ENIA;

const KERNEL: (u64, u64) = (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
const SLOTS: usize = 16;

/// Pool bytes that differ in every word, from a seed.
fn pool(seed: u64) -> [u8; KEY_BYTES] {
    let mut b = [0u8; KEY_BYTES];
    for (i, c) in b.chunks_exact_mut(8).enumerate() {
        let w = (seed.wrapping_add(i as u64 + 1)).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        c.copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// The sequence `azos_sched::pac` runs, over the table.
struct Kernel {
    table: KeyTable<SLOTS>,
    counter: u64,
}

impl Kernel {
    fn new() -> Self {
        Self { table: KeyTable::new(), counter: 1000 }
    }

    /// A new image in `slot` (`spawn_prepare`, `set_current_user_info`).
    fn draw(&mut self, slot: usize, pool_seed: Option<u64>) {
        self.counter += 7;
        let bytes = pool_seed.map(pool);
        let k = fresh_user_keys(bytes.as_ref(), KERNEL, self.counter, slot as u64);
        assert!(self.table.draw(slot, &k));
    }

    /// `exec` in `slot`. Canary: the old keys stay.
    fn exec(&mut self, slot: usize, pool_seed: u64) {
        if cfg!(feature = "pac-canary") {
            return;
        }
        self.draw(slot, Some(pool_seed));
    }

    /// `fork` / thread creation: `child` from `parent`. Canary (fork): fresh.
    fn inherit(&mut self, child: usize, parent: usize) {
        if cfg!(feature = "pac-canary") {
            self.draw(child, Some(0xF0F0 + child as u64));
            return;
        }
        assert!(self.table.inherit(child, parent));
    }

    fn keys(&self, slot: usize) -> UserKeys {
        self.table.get(slot).expect("the slot has keys")
    }
}

fn pairs(k: &UserKeys) -> [(u64, u64); 5] {
    [
        (k[KEY_IA], k[KEY_IA + 1]),
        (k[KEY_IB], k[KEY_IB + 1]),
        (k[KEY_DA], k[KEY_DA + 1]),
        (k[KEY_DB], k[KEY_DB + 1]),
        (k[KEY_GA], k[KEY_GA + 1]),
    ]
}

#[test]
fn the_key_layout_is_five_pairs_in_register_order() {
    assert_eq!(KEY_WORDS, 10);
    assert_eq!(KEY_BYTES, 80);
    assert_eq!([KEY_IA, KEY_IB, KEY_DA, KEY_DB, KEY_GA], [0, 2, 4, 6, 8]);
    let mut b = [0u8; KEY_BYTES];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8;
    }
    let k = keys_from_bytes(&b);
    assert_eq!(k[0], 0x0706_0504_0302_0100, "little endian, lo word first");
    assert_eq!(k[9], 0x4F4E_4D4C_4B4A_4948);
}

#[test]
fn every_process_gets_keys_of_its_own() {
    let mut os = Kernel::new();
    for slot in 1..6 {
        os.draw(slot, Some(slot as u64 * 31));
    }
    for a in 1..6 {
        for b in (a + 1)..6 {
            let (ka, kb) = (os.keys(a), os.keys(b));
            for (pa, pb) in pairs(&ka).iter().zip(pairs(&kb).iter()) {
                assert_ne!(pa, pb, "slots {a} and {b} share a key");
            }
        }
    }
}

#[test]
fn the_five_keys_of_one_process_are_five_different_keys() {
    let k = fresh_user_keys(Some(&pool(5)), KERNEL, 1, 3);
    let p = pairs(&k);
    for i in 0..5 {
        for j in (i + 1)..5 {
            assert_ne!(p[i], p[j], "key {i} and key {j} of one process are equal");
        }
    }
}

#[test]
fn no_process_key_is_the_kernels_or_zero() {
    // The pool gave the kernel's key as the process's APIA.
    let mut bad = pool(9);
    bad[..8].copy_from_slice(&KERNEL.0.to_le_bytes());
    bad[8..16].copy_from_slice(&KERNEL.1.to_le_bytes());
    assert!(!keys_usable(&keys_from_bytes(&bad), KERNEL));
    let k = fresh_user_keys(Some(&bad), KERNEL, 5, 2);
    assert_ne!((k[KEY_IA], k[KEY_IA + 1]), KERNEL, "a process got the kernel's APIA");
    assert!(keys_usable(&k, KERNEL));

    // The pool gave zeros (a draw that did not happen reads the same).
    let z = [0u8; KEY_BYTES];
    assert!(!keys_usable(&keys_from_bytes(&z), KERNEL));
    let k = fresh_user_keys(Some(&z), KERNEL, 5, 2);
    assert!(keys_usable(&k, KERNEL));
    for p in pairs(&k) {
        assert_ne!(p, (0, 0));
    }

    // One zero key among good ones is refused too.
    let mut one = pool(11);
    one[KEY_GA * 8..KEY_GA * 8 + 16].fill(0);
    assert!(!keys_usable(&keys_from_bytes(&one), KERNEL));
}

#[test]
fn the_unseeded_fallback_moves_every_word_with_each_source() {
    let base = derive_user_keys(KERNEL, 100, 4);
    let moved = [
        ("boot key lo", derive_user_keys((KERNEL.0 ^ 1, KERNEL.1), 100, 4)),
        ("boot key hi", derive_user_keys((KERNEL.0, KERNEL.1 ^ 1), 100, 4)),
        ("counter", derive_user_keys(KERNEL, 101, 4)),
        ("slot", derive_user_keys(KERNEL, 100, 5)),
    ];
    for (what, k) in moved {
        for i in 0..KEY_WORDS {
            assert_ne!(k[i], base[i], "{what} leaves word {i} alone");
        }
    }
    // And `fresh_user_keys` takes it when the pool gave nothing.
    assert_eq!(fresh_user_keys(None, KERNEL, 100, 4), base);
}

#[test]
fn a_spawn_draws_and_the_slot_reads_back_what_was_drawn() {
    let mut os = Kernel::new();
    assert!(os.table.get(3).is_none(), "a slot nobody drew for has no keys");
    os.draw(3, Some(77));
    assert_eq!(os.keys(3), fresh_user_keys(Some(&pool(77)), KERNEL, 1007, 3));
}

#[test]
fn an_exec_changes_every_key() {
    let mut os = Kernel::new();
    os.draw(2, Some(1));
    let before = os.keys(2);
    os.exec(2, 2);
    let after = os.keys(2);
    for (b, a) in pairs(&before).iter().zip(pairs(&after).iter()) {
        assert_ne!(b, a, "an exec kept a key of the old image");
    }
}

#[test]
fn a_fork_child_and_a_thread_have_their_creators_keys() {
    let mut os = Kernel::new();
    os.draw(2, Some(1));
    os.inherit(5, 2); // fork
    os.inherit(6, 5); // a thread of the fork child
    assert_eq!(os.keys(5), os.keys(2), "a fork child returns through frames its parent signed");
    assert_eq!(os.keys(6), os.keys(5), "a thread shares its process's keys");
    // And the creator's are not disturbed.
    assert_eq!(os.keys(2), fresh_user_keys(Some(&pool(1)), KERNEL, 1007, 2));
}

#[test]
fn an_exec_in_the_child_leaves_the_parent_alone() {
    let mut os = Kernel::new();
    os.draw(2, Some(1));
    os.inherit(5, 2);
    let parent = os.keys(2);
    os.draw(5, Some(9)); // the child execs
    assert_eq!(os.keys(2), parent);
    assert_ne!(os.keys(5), parent);
}

#[test]
fn a_task_slot_that_is_created_again_has_no_keys() {
    let mut os = Kernel::new();
    os.draw(4, Some(1));
    os.table.clear(4);
    assert!(os.table.get(4).is_none(), "the next task in the slot must not inherit the dead one's keys");
    // A creator without keys gives none.
    os.draw(7, Some(2));
    os.table.clear(7);
    assert!(os.table.inherit(8, 7));
    assert!(os.table.get(8).is_none());
}

#[test]
fn a_slot_out_of_range_is_refused_not_wrapped() {
    let t: KeyTable<4> = KeyTable::new();
    let k = fresh_user_keys(Some(&pool(1)), KERNEL, 1, 1);
    assert!(!t.draw(4, &k));
    assert!(!t.inherit(0, 4));
    assert!(!t.inherit(4, 0));
    assert!(t.get(4).is_none());
    t.clear(4); // no panic
}

#[test]
fn the_enable_bits_are_the_architectures() {
    assert_eq!(SCTLR_EL1_ENIA, 1 << 31);
    assert_eq!(SCTLR_ENIB, 1 << 30);
    assert_eq!(SCTLR_ENDA, 1 << 27);
    assert_eq!(SCTLR_ENDB, 1 << 13);
    // Without per-process keys only the shared key A is on: B and the data
    // keys would be keys nobody set.
    assert_eq!(enable_mask(false), SCTLR_EL1_ENIA);
    assert_eq!(enable_mask(true), SCTLR_EL1_ENIA | SCTLR_ENIB | SCTLR_ENDA | SCTLR_ENDB);
}
