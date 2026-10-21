// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: CONFIG.INI as the kernel reads it at boot
//! (`cfg_load_verified`, both trust outcomes), every accessor, and the
//! serialise -> reload round trip the kernel relies on when it writes the
//! factory defaults back to the card on first boot.
//!
//! The parser's state is a set of statics; every iteration starts with a load,
//! which replaces all of it, so iterations do not leak into each other.
#![no_main]

use libfuzzer_sys::fuzz_target;
use azos_config::{
    cfg_count, cfg_dropped_count, cfg_get, cfg_get_i32, cfg_get_u32, cfg_iter, cfg_load,
    cfg_load_verified, cfg_serialize, cfg_set, cfg_truncated_count, MAX_ENTRIES, MAX_KEY,
    MAX_VAL,
};

fn snapshot() -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..cfg_count()).filter_map(cfg_iter).map(|(k, v)| (k.to_vec(), v.to_vec())).collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, ini)) = data.split_first() else { return };

    // The boot path, with and without a verified signature.
    let _ = cfg_load_verified(ini, flags & 1 != 0);

    // The parser alone, then everything a reader of the table can do.
    // A refused file (e.g. a repeated key) is a valid outcome, not a finding.
    let _ = cfg_load(ini);
    assert!(cfg_count() <= MAX_ENTRIES);
    let before = snapshot();
    for (k, v) in &before {
        assert!(!k.is_empty() && k.len() <= MAX_KEY && v.len() <= MAX_VAL);
        assert!(cfg_get(k).is_some());
        let _ = cfg_get_u32(k, 7);
        let _ = cfg_get_i32(k, -7);
    }

    // Round trip: what `cfg_serialize` writes must load back to the same
    // table. Skipped when the load cut something (a cut can end in
    // whitespace that the reload trims; counted and reported at boot).
    let cut = cfg_truncated_count() != 0
        || cfg_dropped_count() != 0
        || before.iter().any(|(k, _)| k.len() == MAX_KEY);
    let mut buf = vec![0u8; MAX_ENTRIES * (MAX_KEY + MAX_VAL + 2)];
    let n = cfg_serialize(&mut buf);
    if !cut {
        assert!(cfg_load(&buf[..n]).is_ok(), "a serialised table (unique keys) must reload");
        assert_eq!(snapshot(), before, "serialised table reloads differently");
    }

    // `cfg_set` with a key/value taken from the input itself.
    if let Some(pos) = ini.iter().position(|&b| b == b'=') {
        let (k, v) = (&ini[..pos], &ini[pos + 1..]);
        let k = &k[..k.len().min(MAX_KEY + 1)];
        let v = &v[..v.len().min(MAX_VAL + 1)];
        if cfg_set(k, v) {
            assert_eq!(cfg_get(k).map(|x| x.len()), Some(v.len()));
        }
    }
});
