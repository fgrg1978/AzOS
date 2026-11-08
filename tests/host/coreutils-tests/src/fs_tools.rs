// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::{run, run_with, Mem};

fn base() -> Mem {
    let mut m = Mem::new();
    m.cwd = b"/w".to_vec();
    m.dir("/w");
    m
}

#[test]
fn cp_copies_a_file_through_short_reads_and_writes() {
    let mut m = base();
    let text = "0123456789abcdefghij".repeat(40);
    m.file("/w/a", &text);
    assert_eq!(run(&mut m, "cp", &["a", "b"]), 0);
    assert_eq!(m.read("/w/b").unwrap(), text);
    assert_eq!(m.read("/w/a").unwrap(), text);
}

#[test]
fn cp_replaces_a_longer_file() {
    let mut m = base();
    m.file("/w/a", "short").file("/w/b", "a much longer old content");
    assert_eq!(run(&mut m, "cp", &["a", "b"]), 0);
    assert_eq!(m.read("/w/b").unwrap(), "short");
}

#[test]
fn cp_into_a_directory_and_many_sources() {
    let mut m = base();
    m.file("/w/a", "1").file("/w/b", "2").dir("/w/d");
    assert_eq!(run(&mut m, "cp", &["a", "b", "d"]), 0);
    assert_eq!(m.read("/w/d/a").unwrap(), "1");
    assert_eq!(m.read("/w/d/b").unwrap(), "2");
    assert_ne!(run(&mut m, "cp", &["a", "b", "a"]), 0, "several sources need a directory");
}

#[test]
fn cp_directory_needs_r_and_copies_the_tree_with_it() {
    let mut m = base();
    m.file("/w/src/x", "X").file("/w/src/sub/y", "Y").dir("/w/src/empty");
    assert_eq!(run(&mut m, "cp", &["src", "dst"]), 1);
    assert!(m.err().contains("is a directory (use -r)"), "{}", m.err());
    assert!(!m.exists("/w/dst"));
    assert_eq!(run(&mut m, "cp", &["-r", "src", "dst"]), 0);
    assert_eq!(m.read("/w/dst/x").unwrap(), "X");
    assert_eq!(m.read("/w/dst/sub/y").unwrap(), "Y");
    assert!(m.is_dir("/w/dst/empty"));
    // Into an existing directory it lands inside.
    assert_eq!(run(&mut m, "cp", &["-r", "src", "dst"]), 0);
    assert_eq!(m.read("/w/dst/src/sub/y").unwrap(), "Y");
}

#[test]
fn cp_refuses_a_directory_into_itself_and_a_file_onto_itself() {
    let mut m = base();
    m.file("/w/d/f", "1").file("/w/a", "x");
    assert_eq!(run(&mut m, "cp", &["-r", "d", "d/in"]), 1);
    assert!(!m.exists("/w/d/in/f"));
    assert_eq!(run(&mut m, "cp", &["a", "a"]), 1);
    assert_eq!(m.read("/w/a").unwrap(), "x");
}

#[test]
fn cp_n_keeps_an_existing_target() {
    let mut m = base();
    m.file("/w/a", "new").file("/w/b", "old");
    assert_eq!(run(&mut m, "cp", &["-n", "a", "b"]), 0);
    assert_eq!(m.read("/w/b").unwrap(), "old");
}

#[test]
fn cp_says_what_failed() {
    let mut m = base();
    m.file("/w/a", "1");
    assert_eq!(run(&mut m, "cp", &["nope", "b"]), 1);
    assert!(m.err().starts_with("cp: nope: no such file or directory"));
    m.read_only = Some(b"/w/ro".to_vec());
    m.dir("/w/ro");
    m.stderr.clear();
    assert_eq!(run(&mut m, "cp", &["a", "ro/a"]), 1);
    assert!(m.err().contains("denied"), "{}", m.err());
    assert_eq!(run(&mut m, "cp", &["a"]), 2);
    assert_eq!(run(&mut m, "cp", &["-z", "a", "b"]), 2);
}

#[test]
fn mv_renames_and_moves_into_a_directory() {
    let mut m = base();
    m.file("/w/a", "1").file("/w/b", "2").dir("/w/d");
    assert_eq!(run(&mut m, "mv", &["a", "c"]), 0);
    assert!(!m.exists("/w/a") && m.read("/w/c").unwrap() == "1");
    assert_eq!(run(&mut m, "mv", &["c", "b", "d"]), 0);
    assert_eq!(m.read("/w/d/c").unwrap(), "1");
    assert_eq!(m.read("/w/d/b").unwrap(), "2");
}

#[test]
fn mv_replaces_an_existing_file_and_moves_a_tree() {
    let mut m = base();
    m.file("/w/a", "new").file("/w/b", "old").file("/w/t/x", "X");
    assert_eq!(run(&mut m, "mv", &["a", "b"]), 0);
    assert_eq!(m.read("/w/b").unwrap(), "new");
    assert_eq!(run(&mut m, "mv", &["t", "u"]), 0);
    assert_eq!(m.read("/w/u/x").unwrap(), "X");
    assert!(!m.exists("/w/t"));
}

#[test]
fn mv_across_volumes_copies_then_removes() {
    let mut m = base();
    m.other_volume = Some(b"/tmp".to_vec());
    m.dir("/tmp").file("/w/t/x", "X").file("/w/t/s/y", "Y");
    assert_eq!(run(&mut m, "mv", &["t", "/tmp/t"]), 0);
    assert_eq!(m.read("/tmp/t/x").unwrap(), "X");
    assert_eq!(m.read("/tmp/t/s/y").unwrap(), "Y");
    assert!(!m.exists("/w/t"), "{:?}", m.paths());
}

#[test]
fn mv_refuses_a_directory_into_itself() {
    let mut m = base();
    m.file("/w/d/f", "1");
    assert_eq!(run(&mut m, "mv", &["d", "d/e"]), 1);
    assert!(m.exists("/w/d/f"));
}

#[test]
fn rm_removes_files_and_says_what_is_missing() {
    let mut m = base();
    m.file("/w/a", "1").file("/w/b", "2");
    assert_eq!(run(&mut m, "rm", &["a", "b"]), 0);
    assert!(!m.exists("/w/a") && !m.exists("/w/b"));
    assert_eq!(run(&mut m, "rm", &["a"]), 1);
    assert!(m.err().contains("rm: a: no such file"));
    assert_eq!(run(&mut m, "rm", &["-f", "a"]), 0);
    assert_eq!(run(&mut m, "rm", &["-f"]), 0);
    assert_eq!(run(&mut m, "rm", &[]), 2);
}

#[test]
fn rm_refuses_a_directory_without_r() {
    let mut m = base();
    m.file("/w/d/f", "1");
    assert_eq!(run(&mut m, "rm", &["d"]), 1);
    assert!(m.err().contains("is a directory"));
    assert!(m.exists("/w/d/f"));
}

#[test]
fn rm_r_removes_a_tree_bottom_up() {
    let mut m = base();
    for i in 0..9 {
        m.file(&format!("/w/t/f{i}"), "x");
        m.file(&format!("/w/t/d{i}/g"), "y");
    }
    m.dir("/w/t/e");
    m.file("/w/keep", "k");
    assert_eq!(run(&mut m, "rm", &["-r", "t"]), 0);
    assert_eq!(m.paths(), vec!["/w", "/w/keep"]);
    assert_eq!(run(&mut m, "rm", &["-rf", "t", "keep"]), 0);
    assert_eq!(m.paths(), vec!["/w"]);
}

#[test]
fn rm_r_keeps_going_past_a_denied_entry_and_reports_it() {
    let mut m = base();
    m.file("/w/t/a", "1").file("/w/t/b", "2").file("/w/t/c", "3");
    m.read_only = Some(b"/w/t/b".to_vec());
    assert_eq!(run(&mut m, "rm", &["-r", "t"]), 1);
    assert_eq!(m.paths(), vec!["/w", "/w/t", "/w/t/b"]);
    assert!(m.err().contains("/w/t/b: denied"), "{}", m.err());
    assert!(!m.err().contains("not empty"), "{}", m.err());
}

#[test]
fn rm_r_will_not_remove_the_root() {
    let mut m = base();
    assert_eq!(run(&mut m, "rm", &["-r", "/"]), 1);
    assert!(m.err().contains("root"));
    assert!(m.exists("/w"));
}

#[test]
fn mkdir_makes_one_and_refuses_a_missing_parent() {
    let mut m = base();
    assert_eq!(run(&mut m, "mkdir", &["a"]), 0);
    assert!(m.is_dir("/w/a"));
    assert_eq!(run(&mut m, "mkdir", &["a"]), 1);
    assert!(m.err().contains("already exists"));
    assert_eq!(run(&mut m, "mkdir", &["x/y"]), 1);
    assert!(!m.exists("/w/x"));
    assert_eq!(run(&mut m, "mkdir", &[]), 2);
}

#[test]
fn mkdir_p_makes_the_parents() {
    let mut m = base();
    assert_eq!(run(&mut m, "mkdir", &["-p", "a/b/c"]), 0);
    assert!(m.is_dir("/w/a/b/c"));
    assert_eq!(run(&mut m, "mkdir", &["-p", "a/b"]), 0, "an existing directory is fine");
    m.file("/w/f", "x");
    assert_eq!(run(&mut m, "mkdir", &["-p", "f"]), 1, "an existing file is not");
}

#[test]
fn rmdir_removes_only_empty_directories() {
    let mut m = base();
    m.dir("/w/e").file("/w/d/f", "1");
    assert_eq!(run(&mut m, "rmdir", &["e"]), 0);
    assert!(!m.exists("/w/e"));
    assert_eq!(run(&mut m, "rmdir", &["d"]), 1);
    assert!(m.err().contains("directory not empty"));
    assert_eq!(run(&mut m, "rmdir", &["d/f"]), 1);
    assert_eq!(run(&mut m, "rmdir", &[]), 2);
}

#[test]
fn touch_creates_and_leaves_an_existing_file_alone() {
    let mut m = base();
    m.file("/w/a", "keep");
    assert_eq!(run(&mut m, "touch", &["a", "b"]), 0);
    assert_eq!(m.read("/w/a").unwrap(), "keep");
    assert_eq!(m.read("/w/b").unwrap(), "");
    assert_eq!(run(&mut m, "touch", &["x/y"]), 1);
}

#[test]
fn stat_prints_kind_size_and_time() {
    let mut m = base();
    m.file_mtime("/w/a", "hello", 1_700_000_000).dir("/w/d");
    assert_eq!(run(&mut m, "stat", &["a", "d"]), 0);
    assert_eq!(
        m.out(),
        "  File: a\n  Type: file\n  Size: 5 bytes\nModify: 2023-11-14 22:13:20 UTC\n\
         \x20 File: d\n  Type: directory\n  Size: 0 bytes\n"
    );
    assert_eq!(run(&mut m, "stat", &["zz"]), 1);
}

#[test]
fn du_rounds_files_to_the_block() {
    let mut m = base();
    m.block = 4096;
    m.file("/w/t/a", "x").file("/w/t/s/b", &"y".repeat(5000));
    // 1 byte -> one 4 KiB block; 5000 bytes -> two blocks: 12 KiB in all.
    assert_eq!(run(&mut m, "du", &["-s", "t"]), 0);
    assert_eq!(m.out(), "12\tt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "du", &["t"]), 0);
    assert_eq!(m.out(), "8\tt/s\n12\tt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "du", &["-sb", "t"]), 0);
    assert_eq!(m.out(), "5001\tt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "du", &["-sh", "t"]), 0);
    assert_eq!(m.out(), "12K\tt\n");
}

#[test]
fn du_of_a_file_and_of_the_working_directory() {
    let mut m = base();
    m.block = 1024;
    m.file("/w/a", &"x".repeat(1500));
    assert_eq!(run(&mut m, "du", &["a"]), 0);
    assert_eq!(m.out(), "2\ta\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "du", &[]), 0);
    assert_eq!(m.out(), "2\t.\n");
}

#[test]
fn df_reports_the_filesystem() {
    let mut m = base();
    m.block = 1024;
    assert_eq!(run(&mut m, "df", &[]), 0);
    assert_eq!(m.out(), "TYPE\tSIZE\tUSED\tAVAIL\tUSE%\tPATH\ntmpfs\t1000\t600\t400\t60%\t.\n");
    m.stdout.clear();
    m.fold = true;
    assert_eq!(run(&mut m, "df", &["-h", "/w"]), 0);
    assert!(m.out().contains("fat32\t1000K\t600K\t400K\t60%\t/w"), "{}", m.out());
}

fn tree() -> Mem {
    let mut m = base();
    m.file("/w/t/a.txt", "1").file("/w/t/b.log", "2").file("/w/t/s/c.txt", "3").file("/w/t/s/u/d.txt", "4");
    m
}

#[test]
fn find_lists_the_tree_as_the_path_was_given() {
    let mut m = tree();
    assert_eq!(run(&mut m, "find", &["t"]), 0);
    assert_eq!(m.out(), "t\nt/a.txt\nt/b.log\nt/s\nt/s/c.txt\nt/s/u\nt/s/u/d.txt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &["t/", "-name", "*.log"]), 0);
    assert_eq!(m.out(), "t/b.log\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &[]), 0);
    assert!(m.out().starts_with(".\n./t\n"), "{}", m.out());
}

#[test]
fn find_type_f_lists_only_files() {
    let mut m = tree();
    assert_eq!(run(&mut m, "find", &["t", "-type", "f"]), 0);
    assert_eq!(m.out(), "t/a.txt\nt/b.log\nt/s/c.txt\nt/s/u/d.txt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &["t", "-type", "d"]), 0);
    assert_eq!(m.out(), "t\nt/s\nt/s/u\n");
}

#[test]
fn find_depth_limits() {
    let mut m = tree();
    assert_eq!(run(&mut m, "find", &["t", "-maxdepth", "1"]), 0);
    assert_eq!(m.out(), "t\nt/a.txt\nt/b.log\nt/s\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &["t", "-mindepth", "2", "-type", "f"]), 0);
    assert_eq!(m.out(), "t/s/c.txt\nt/s/u/d.txt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &["t", "-maxdepth", "0"]), 0);
    assert_eq!(m.out(), "t\n");
}

#[test]
fn find_name_folds_case_only_where_the_filesystem_does() {
    let mut m = base();
    m.file("/w/A.TXT", "1");
    assert_eq!(run(&mut m, "find", &[".", "-name", "*.txt"]), 0);
    assert_eq!(m.out(), "");
    m.fold = true;
    assert_eq!(run(&mut m, "find", &[".", "-name", "*.txt"]), 0);
    assert_eq!(m.out(), "./A.TXT\n");
    m.fold = false;
    m.stdout.clear();
    assert_eq!(run(&mut m, "find", &[".", "-iname", "*.txt"]), 0);
    assert_eq!(m.out(), "./A.TXT\n");
}

#[test]
fn find_says_what_it_does_not_take() {
    let mut m = tree();
    assert_eq!(run(&mut m, "find", &["t", "-exec", "rm"]), 2);
    assert_eq!(run(&mut m, "find", &["t", "-type", "x"]), 2);
    assert_eq!(run(&mut m, "find", &["nope"]), 1);
}

#[test]
fn a_tree_deeper_than_the_walk_is_an_error_not_a_loop() {
    let mut m = base();
    let deep = (0..12).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/");
    m.file(&format!("/w/{deep}/f"), "x");
    assert_eq!(run(&mut m, "find", &["."]), 1);
    assert!(m.err().contains("too long"), "{}", m.err());
    assert_eq!(run_with(&mut m, "rm", &["-r", "d0"], 4096), 1);
}

#[test]
fn walks_skip_the_dot_entries_a_fat_directory_lists() {
    let mut m = tree();
    m.dots = true;
    assert_eq!(run(&mut m, "find", &["t"]), 0);
    assert_eq!(m.out(), "t\nt/a.txt\nt/b.log\nt/s\nt/s/c.txt\nt/s/u\nt/s/u/d.txt\n");
    assert_eq!(run(&mut m, "cp", &["-r", "t", "u"]), 0);
    assert_eq!(m.read("/w/u/s/u/d.txt").unwrap(), "4");
    assert_eq!(run(&mut m, "grep", &["-rc", "3", "u"]), 0);
    assert!(m.out().contains("u/s/c.txt:1"), "{}", m.out());
    assert_eq!(run(&mut m, "rm", &["-r", "t", "u"]), 0);
    assert_eq!(m.paths(), vec!["/w"]);
}
