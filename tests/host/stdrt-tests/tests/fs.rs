// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arithmetic half of `std::fs` on the native ABI (`azos_stdrt::fspure`):
//! paths made absolute, the open flags of `OpenOptions`, the stat record.
//! The calls are covered from ring 3 by the boot rows of the ported programs.

use azos_abi::syscall_nr::{STAT_BYTES, STAT_OFF_MODE, STAT_OFF_MTIME, STAT_OFF_SIZE, STAT_S_IFDIR, STAT_S_IFREG};
use azos_stdrt::fspure::{normalize, open_flags, parent_of, OpenError, PathError, Stat, O_APPEND, O_CREAT, O_RDWR, O_TRUNC, O_WRONLY, PATH_MAX};

fn norm(base: &str, path: &str) -> Result<String, PathError> {
    normalize(base.as_bytes(), path.as_bytes()).map(|p| String::from_utf8(p.bytes().to_vec()).unwrap())
}

/// A relative path hangs off the working directory; an absolute one ignores it.
/// **Canary:** an `normalize` that always joined the base gives `/work/etc/x`.
#[test]
fn relative_paths_follow_the_base_and_absolute_ones_do_not() {
    assert_eq!(norm("/work", "a/b").unwrap(), "/work/a/b");
    assert_eq!(norm("/work", "/etc/x").unwrap(), "/etc/x");
}

/// `.`, doubled slashes and trailing slashes vanish.
#[test]
fn dots_and_slashes_are_dropped() {
    assert_eq!(norm("/", "./a//b/./c/").unwrap(), "/a/b/c");
}

/// `..` removes a component and can never climb above the root: a path cannot
/// name anything outside the directory it is opened beneath.
/// **Canary:** `..` that did not stop at the root would produce a leading `..`.
#[test]
fn dotdot_stops_at_the_root() {
    assert_eq!(norm("/a/b", "../../../../x").unwrap(), "/x");
    assert_eq!(norm("/a/b", "..").unwrap(), "/a");
    assert_eq!(norm("/", "..").unwrap(), "/");
    assert_eq!(norm("/a", "b/../../c").unwrap(), "/c");
}

/// The root normalises to `/` and a NUL follows every result.
#[test]
fn the_root_is_a_single_slash_and_results_are_nul_terminated() {
    let p = normalize(b"/x", b"/").unwrap();
    assert_eq!(p.bytes(), b"/");
    assert_eq!(p.with_nul(), b"/\0");
}

/// Empty, NUL-carrying and over-long paths are refused, not cut.
/// **Canary:** a limit of `PATH_MAX + 1` lets the 256-byte name through.
#[test]
fn bad_paths_are_refused() {
    assert_eq!(norm("/", ""), Err(PathError::Empty));
    assert_eq!(norm("/", "a\0b"), Err(PathError::Nul));
    let long = format!("/{}", "a".repeat(PATH_MAX - 2));
    assert_eq!(norm("/", &long).unwrap().len(), PATH_MAX - 1);
    let too_long = format!("/{}", "a".repeat(PATH_MAX - 1));
    assert_eq!(norm("/", &too_long), Err(PathError::TooLong));
}

/// The flags `File::open`, `File::create` and `OpenOptions` map to.
/// **Canary:** swapping `O_WRONLY` and `O_RDWR` fails the second and third.
#[test]
fn open_options_become_native_flags() {
    assert_eq!(open_flags(true, false, false, false, false, false), Ok(0));
    assert_eq!(open_flags(false, true, false, true, true, false), Ok(O_WRONLY | O_CREAT | O_TRUNC));
    assert_eq!(open_flags(true, true, false, false, false, false), Ok(O_RDWR));
    assert_eq!(open_flags(false, false, true, false, true, false), Ok(O_WRONLY | O_APPEND | O_CREAT));
}

/// What `std` refuses on every platform is refused; `create_new` is refused
/// because the native open cannot fail on an existing file.
/// **Canary:** answering `create_new` with `O_CREAT` would make it a silent `create`.
#[test]
fn impossible_combinations_are_refused() {
    assert_eq!(open_flags(false, false, false, false, false, false), Err(OpenError::Invalid));
    assert_eq!(open_flags(true, false, false, true, false, false), Err(OpenError::Invalid));
    assert_eq!(open_flags(true, false, false, false, true, false), Err(OpenError::Invalid));
    assert_eq!(open_flags(false, false, true, true, false, false), Err(OpenError::Invalid));
    assert_eq!(open_flags(false, true, false, false, false, true), Err(OpenError::CreateNew));
}

fn record(size: u64, mode: u32, mtime: u64) -> [u8; STAT_BYTES] {
    let mut b = [0u8; STAT_BYTES];
    b[STAT_OFF_SIZE..STAT_OFF_SIZE + 8].copy_from_slice(&size.to_le_bytes());
    b[STAT_OFF_MODE..STAT_OFF_MODE + 4].copy_from_slice(&mode.to_le_bytes());
    b[STAT_OFF_MTIME..STAT_OFF_MTIME + 8].copy_from_slice(&mtime.to_le_bytes());
    b
}

/// The stat record decodes at the offsets the ABI documents.
/// **Canary:** reading the size from the mode offset gives 0o100644, not 4096.
#[test]
fn the_stat_record_decodes() {
    let s = Stat::decode(&record(4096, STAT_S_IFREG | 0o644, 1_700_000_000));
    assert_eq!((s.size, s.mtime), (4096, 1_700_000_000));
    assert!(!s.is_dir());
    assert!(!s.readonly());
    let d = Stat::decode(&record(0, STAT_S_IFDIR | 0o755, 0));
    assert!(d.is_dir());
}

/// Read-only is the absence of every write bit.
#[test]
fn readonly_means_no_write_bit() {
    assert!(Stat::decode(&record(1, STAT_S_IFREG | 0o444, 0)).readonly());
    assert!(!Stat::decode(&record(1, STAT_S_IFREG | 0o464, 0)).readonly());
}

/// The parent of a created name is the directory a missing-parent refusal is told apart in.
/// **Canary:** a `parent_of` that kept the last component answers `/a/b` for `/a/b`.
#[test]
fn the_parent_drops_the_last_component() {
    let p = |s: &str| String::from_utf8(parent_of(&normalize(b"/", s.as_bytes()).unwrap()).bytes().to_vec()).unwrap();
    assert_eq!(p("/a/b"), "/a");
    assert_eq!(p("/a/b/c"), "/a/b");
    assert_eq!(p("/a"), "/");
    assert_eq!(p("/"), "/");
}

/// A path as long as the kernel reads (`PATH_MAX_BYTES`, NUL included) passes, one more byte does not.
#[test]
fn the_limit_is_the_kernels() {
    assert_eq!(PATH_MAX, azos_abi::syscall_nr::PATH_MAX_BYTES);
}
