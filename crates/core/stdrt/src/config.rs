// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The knobs of this layer. Kconfig is their only source: `make sdk` exports
//! them as `AZOS_<SYMBOL>` through `tools/build/kconfig_to_cargo.py --sdk-env`, and
//! there is no default here, so a build outside `make sdk` does not compile.

const fn num(s: &str) -> usize {
    let b = s.as_bytes();
    assert!(!b.is_empty(), "empty number");
    let mut v = 0usize;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i] >= b'0' && b[i] <= b'9', "not a decimal number");
        v = v * 10 + (b[i] - b'0') as usize;
        i += 1;
    }
    v
}

const fn flag(s: &str) -> bool {
    let b = s.as_bytes();
    assert!(b.len() == 1 && (b[0] == b'0' || b[0] == b'1'), "not a 0/1 flag");
    b[0] == b'1'
}

/// `PAGE_SIZE` of the image (`AZOS_PAGE_SIZE`, the aarch64 granule builds; 4096 otherwise).
pub const PAGE_SIZE: usize = match option_env!("AZOS_PAGE_SIZE") {
    None => 4096,
    Some(s) => {
        let v = num(s);
        assert!(v == 4096 || v == 16384 || v == 65536, "AZOS_PAGE_SIZE must be 4096, 16384 or 65536");
        v
    }
};

pub const USER_ALLOC_QUARANTINE_KB: usize = num(env!("AZOS_USER_ALLOC_QUARANTINE_KB"));
pub const USER_ALLOC_QUARANTINE_SLOTS: usize = num(env!("AZOS_USER_ALLOC_QUARANTINE_SLOTS"));
pub const USER_ALLOC_BLOCK_KB: usize = num(env!("AZOS_USER_ALLOC_BLOCK_KB"));
pub const USER_ALLOC_MAX_MAPS: usize = num(env!("AZOS_USER_ALLOC_MAX_MAPS"));
pub const USER_ALLOC_RANDOMIZE: bool = flag(env!("AZOS_USER_ALLOC_RANDOMIZE"));
pub const USER_ALLOC_SEED_REQUIRED: bool = flag(env!("AZOS_USER_ALLOC_SEED_REQUIRED"));
pub const USER_ALLOC_POISON_FREED: bool = flag(env!("AZOS_USER_ALLOC_POISON_FREED"));
pub const USER_ALLOC_GUARD_PAGES: bool = flag(env!("AZOS_USER_ALLOC_GUARD_PAGES"));
/// Default stack of a thread `std` starts without `stack_size`, in KiB.
pub const SDK_THREAD_STACK_KB: usize = num(env!("AZOS_SDK_THREAD_STACK_KB"));
