// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `why crash` and where a dump lands: the real sources pulled with `#[path]`,
//! the tool's own command logic (`userspace/services/why/src/crash.rs`) over
//! the kernel's layout and report (`crates/core/recovery/src/crashdump.rs`),
//! and the one join the dump's file name goes through
//! (`crates/core/common/src/path.rs`). The write itself, against the real VFS
//! and FAT32, is `tests/host/fs-tests` (`crash_dump_beneath_a_directory`).

#[allow(dead_code)]
#[path = "../../../../crates/core/recovery/src/crashdump.rs"]
mod cd;
// `why`'s `crash.rs` reaches the layout as `crate::crashdump`: this module.
pub use cd::*;

#[allow(dead_code)]
#[path = "../../../../crates/core/common/src/path.rs"]
mod path;

#[path = "../../../../userspace/services/why/src/crash.rs"]
mod why_crash;

use why_crash::{parse, run, Dumps};

struct Files(Vec<Vec<u8>>);

impl Dumps for Files {
    fn files(&self) -> Vec<Vec<u8>> {
        self.0.clone()
    }
}

fn names() -> Names {
    Names { rule: |_| "some-rule", verdict: |_| "deny" }
}

/// One encoded dump of task `tid`, stamped with `serial`.
fn file(tid: u32, serial: u32, pc: u64) -> Vec<u8> {
    let regs = [0x11u64; 32];
    let d = Dump {
        isa: Isa::Riscv64, tid, status: 139, cause: 13, cpu: 0, ticks: 5, pc, sp: 0x7000, fault_addr: 0,
        image: [0; 32], name: b"SVC.ELF", regs: &regs, maps: &[], maps_total: 0, decisions: &[], stack_base: 0x7000, stack: &[1, 2, 3],
    };
    let mut out = vec![0u8; MAX_BYTES];
    let n = encode(&d, &mut out).unwrap();
    out.truncate(n);
    set_serial(&mut out, serial);
    out
}

fn out_of(tid: Option<u32>, files: Vec<Vec<u8>>) -> (i32, String) {
    let mut out = String::new();
    let code = run(tid, &Files(files), &names(), &mut out).unwrap();
    (code, out)
}

/// **`why crash TID` prints the NEWEST dump of that task**, by serial, not the
/// first file it finds and not another task's.
///
/// **Canary.** Take `find` over `found.iter()` instead of `.rev()`: the oldest
/// dump of task 5 prints.
#[test]
fn why_crash_prints_the_newest_dump_of_the_task() {
    let files = vec![file(5, 3, 0x30), file(7, 2, 0x20), file(5, 1, 0x10)];
    let (code, out) = out_of(Some(5), files);
    assert_eq!(code, 0);
    assert!(out.starts_with("crash dump 3 (riscv64"), "{out}");
    assert!(out.contains("pc      0x30\n"), "{out}");
    assert!(!out.contains("pc      0x10\n"), "{out}");
}

/// **The ring's order survives the 32-bit wrap**: serial 0 is newer than
/// `u32::MAX`.
#[test]
fn the_newest_survives_the_serial_wrap() {
    let (code, out) = out_of(Some(5), vec![file(5, u32::MAX, 0x10), file(5, 0, 0x20)]);
    assert_eq!(code, 0);
    assert!(out.contains("pc      0x20\n"), "{out}");
}

/// **A task with no dump is exit 1 with the count of what is held**, and a cut
/// or foreign file is counted as unreadable, never printed as a dump.
#[test]
fn a_task_without_a_dump_is_exit_one() {
    let mut torn = file(9, 4, 0x10);
    *torn.last_mut().unwrap() ^= 0xFF;
    let (code, out) = out_of(Some(9), vec![file(5, 1, 0x10), torn, b"not a dump".to_vec()]);
    assert_eq!(code, 1);
    assert_eq!(out, "why: no crash dump of task 9 (1 dumps held, 2 unreadable)\n");
    let (code, out) = out_of(Some(9), vec![]);
    assert_eq!((code, out.as_str()), (1, "why: no crash dump of task 9 (0 dumps held)\n"));
}

/// **With no task, one line per dump, oldest first**, and the totals.
#[test]
fn why_crash_lists_every_dump_oldest_first() {
    let (code, out) = out_of(None, vec![file(7, 9, 0x3), file(5, 2, 0x1), file(6, 4, 0x2), vec![0; 8]]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert!(lines[0].starts_with("dump 2 tid 5 SVC.ELF SIGSEGV pc 0x1"), "{out}");
    assert!(lines[1].starts_with("dump 4 tid 6"), "{out}");
    assert!(lines[2].starts_with("dump 9 tid 7"), "{out}");
    assert_eq!(lines[3], "# 3 dumps, 1 unreadable");
}

/// **The command line**: `crash`, `crash TID`, and nothing else is a crash
/// command (the decision commands keep their own parser).
#[test]
fn the_crash_command_line() {
    assert_eq!(parse(&[b"crash"]), Some(Ok(None)));
    assert_eq!(parse(&[b"crash", b"12"]), Some(Ok(Some(12))));
    assert!(matches!(parse(&[b"crash", b"x"]), Some(Err(_))));
    assert!(matches!(parse(&[b"crash", b"-1"]), Some(Err(_))));
    assert!(matches!(parse(&[b"crash", b"1", b"2"]), Some(Err(_))));
    assert_eq!(parse(&[]), None);
    assert_eq!(parse(&[b"list"]), None);
    assert_eq!(parse(&[b"12"]), None);
}

fn join(root: &[u8], rel: &[u8]) -> Option<Vec<u8>> {
    let mut out = [0u8; path::MAX_PATH];
    path::join_beneath(root, rel, &mut out).ok().map(|n| out[..n].to_vec())
}

/// **Every dump file name joins beneath the Domain's directory and nowhere
/// else**, whatever the tree: the file the kernel writes is
/// `<tree>/CRASHn.DMP`, and a tree's root is never a place the name can
/// leave.
///
/// **Canary.** Make `slot_rel` start with `/`: every join is refused.
#[test]
fn a_dump_lands_beneath_the_domains_directory() {
    for root in [&b"/fat"[..], b"/fat/svc/net", b"/fat/svc/net/", b"/tmp", b"/"] {
        let tree = String::from_utf8(root.to_vec()).unwrap();
        let tree = tree.trim_end_matches('/');
        for slot in 0..MAX_SLOTS {
            let mut rel = [0u8; REL_MAX];
            let n = slot_rel(slot, &mut rel);
            let joined = join(root, &rel[..n]).expect("a slot name joins beneath any tree");
            let want = format!("{tree}/CRASH{:x}.DMP", slot);
            assert_eq!(String::from_utf8(joined).unwrap(), want);
        }
    }
}

/// **The reader's name for a dump, opened beneath the root directory, is the
/// file the kernel wrote beneath the write tree**: for every directory a write
/// tree can be and every slot, `slot_path` joined onto `/` is the join of
/// `slot_rel` onto that tree, NUL-terminated inside `PATH_MAX`.
///
/// **Canary.** Make `slot_path` drop the `/` between directory and name:
/// `fatCRASH0.DMP` is not the writer's file.
#[test]
fn the_readers_path_is_the_writers_file() {
    for dir in DUMP_DIRS {
        for slot in 0..MAX_SLOTS {
            let mut p = [0u8; PATH_MAX];
            let n = slot_path(dir, slot, &mut p);
            assert_eq!(p[n], 0, "NUL-terminated");
            let mut rel = [0u8; REL_MAX];
            let k = slot_rel(slot, &mut rel);
            let written = join(format!("/{dir}").as_bytes(), &rel[..k]).unwrap();
            assert_eq!(join(b"/", &p[..n]).unwrap(), written, "{dir} slot {slot}");
        }
    }
}
