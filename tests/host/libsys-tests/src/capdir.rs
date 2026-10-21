// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Storage L12 on the libsys side: the only open the native API has is
//! `open_at(dir, rel, flags)` on a `Cap<Dir>`; there is no open by path in the
//! global namespace.
//!
//! `lib.rs` cannot be pulled into a host test (it is `ecall`), so the rows
//! that concern the wrappers read its source: what is checked is what ships.

use super::libsys::below_root;

const LIB: &str = include_str!("../../../../crates/core/libsys/src/lib.rs");
const ABI: &str = include_str!("../../../../crates/core/abi/src/invoke.rs");
const SECCOMP: &str = include_str!("../../../../crates/core/sched/src/seccomp.rs");

/// Code lines of `src` (comments and doc lines dropped), for the greps below.
fn code(src: &str) -> Vec<&str> {
    src.lines().filter(|l| !l.trim_start().starts_with("//")).collect()
}

/// **An absolute path becomes a name below the root; nothing else changes.**
/// Only the leading slashes go. `..` stays for the kernel to refuse, an empty
/// name stays empty (the kernel refuses it), and a NUL terminator stays.
///
/// **Canary.** Make `below_root` strip one slash only: `//x` keeps a slash and
/// the kernel then refuses it as absolute.
#[test]
fn below_root_takes_off_the_leading_slashes_only() {
    assert_eq!(below_root(b"/fat/CONFIG.INI\0"), b"fat/CONFIG.INI\0");
    assert_eq!(below_root(b"//fat//x"), b"fat//x");
    assert_eq!(below_root(b"fat/x"), b"fat/x", "a relative name is already one");
    assert_eq!(below_root(b"/"), b"");
    assert_eq!(below_root(b""), b"");
    assert_eq!(below_root(b"/../etc"), b"../etc", "the kernel refuses the climb, not this");
}

/// **No ambient path open is left in the native API.** `DOMAIN_OPEN`, `open`
/// and `file_open_typed` are gone from the library and the op list; the open is
/// `NODE_OPENAT` on a directory handle.
///
/// **Canary.** Re-add `pub fn open(path: &[u8], flags: u64)` to lib.rs: the
/// first assert finds it.
#[test]
fn the_native_api_has_no_open_by_path() {
    let lib = code(LIB);
    for banned in ["pub fn open(", "pub fn file_open_typed(", "DOMAIN_OPEN"] {
        assert!(!lib.iter().any(|l| l.contains(banned)), "libsys still has `{banned}`");
    }
    assert!(!code(ABI).iter().any(|l| l.contains("DOMAIN_OPEN")), "the op list still has DOMAIN_OPEN");
    assert!(!code(SECCOMP).iter().any(|l| l.contains("DOMAIN_OPEN")), "a profile still lists DOMAIN_OPEN");
    assert!(lib.iter().any(|l| l.contains("pub fn open_at(dir: u32, rel: &[u8], flags: u64)")));
    assert!(lib.iter().any(|l| l.contains("invoke_abi::NODE_OPENAT")));
    // The handle the open goes through is the caller's directory, never the
    // domain's self handle.
    let at = LIB.find("pub fn open_at(").expect("open_at");
    let body = &LIB[at..at + LIB[at..].find("\n}\n").unwrap()];
    assert!(!body.contains("DOMAIN_SELF"), "open_at invokes the domain, not a directory");
}

/// **The root directory is looked up by the kernel's constant, not guessed.**
/// `root_dir` asks `SYS_CAP_INFO` for the `FILE` capability whose resource is
/// `ROOT_DIR_RESOURCE`, the tree on `/` that the kernel interns first.
#[test]
fn the_root_directory_is_looked_up_by_the_constant_resource() {
    let at = LIB.find("pub fn root_dir()").expect("root_dir");
    let body = &LIB[at..at + LIB[at..].find("\n}\n").unwrap()];
    assert!(body.contains("cap_lookup(ty::FILE.raw(), invoke_abi::ROOT_DIR_RESOURCE)"), "{body}");
    assert!(ABI.contains("pub const ROOT_DIR_RESOURCE: u32 = 0x4000_0000;"));
}
