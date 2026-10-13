// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `pure.rs` of the relibc `azos` platform module.
//!
//! The file under test is pulled in with `#[path]`, so it is the code that ships
//! in `libc.a`. What these tests cannot reach is every call into the kernel
//! (`fs.rs`, `proc.rs`, `mem.rs` ...): those need a boot and are listed with the
//! front's open items.
//!
//! Each property is checked by a function that takes the implementation, and a
//! canary: a deliberately wrong implementation of the same function that the
//! check must reject, so a check that passes everything does not pass.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../../../userspace/lib/relibc-azos/overlay/src/platform/azos/pure.rs"]
mod pure;

#[cfg(test)]
mod tests {
    use super::pure::*;
    use alloc::vec::Vec;

    type Norm = fn(&[u8], &[u8], usize) -> Result<Vec<u8>, PathError>;

    /// What `normalize` must answer, from a plain stack of components.
    fn reference(base: &str, path: &str) -> String {
        let mut stack: Vec<&str> = Vec::new();
        let start = if path.starts_with('/') { "" } else { base };
        for part in start.split('/').chain(path.split('/')) {
            match part {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                p => stack.push(p),
            }
        }
        if stack.is_empty() { "/".into() } else { alloc::format!("/{}", stack.join("/")) }
    }

    const CASES: &[(&str, &str)] = &[
        ("/", "a"),
        ("/x/y", "a/b"),
        ("/x/y", "../a"),
        ("/x/y", "../../../a"),
        ("/x", "a/../.."),
        ("/x", "/abs/./path//with///slashes/"),
        ("/x", "/a/../../.."),
        ("/x", "."),
        ("/x", ".."),
        ("/x/y", "./."),
        ("/", "/"),
        ("/x", "a/b/../../../../../c"),
        ("/dir with space", "f g"),
    ];

    fn check_normalize(f: Norm) -> Result<(), alloc::string::String> {
        for (base, path) in CASES {
            let got = f(base.as_bytes(), path.as_bytes(), 256).map_err(|e| alloc::format!("{base} + {path}: {e:?}"))?;
            let want = reference(base, path);
            let mut want_b = want.clone().into_bytes();
            want_b.push(0);
            if got != want_b {
                return Err(alloc::format!("{base} + {path}: got {:?}, want {want}", core::str::from_utf8(&got)));
            }
        }
        Ok(())
    }

    #[test]
    fn normalize_matches_a_component_stack() {
        check_normalize(normalize).unwrap();
    }

    #[test]
    fn normalize_canary_a_dotdot_that_climbs_is_caught() {
        // A mutant that leaves `..` in the path (never pops) must be rejected.
        fn never_pops(base: &[u8], path: &[u8], max: usize) -> Result<Vec<u8>, PathError> {
            let mut out = Vec::new();
            for chunk in [if path.first() == Some(&b'/') { &b""[..] } else { base }, path] {
                for c in chunk.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".") {
                    out.push(b'/');
                    out.extend_from_slice(c);
                }
            }
            if out.is_empty() {
                out.push(b'/');
            }
            out.push(0);
            let _ = max;
            Ok(out)
        }
        assert!(check_normalize(never_pops).is_err());
    }

    #[test]
    fn dotdot_never_leaves_the_root() {
        for p in ["..", "../..", "/..", "/a/../..", "a/../../../.."] {
            assert_eq!(normalize(b"/x", p.as_bytes(), 256).unwrap(), b"/\0", "{p}");
        }
    }

    #[test]
    fn normalize_refuses_the_empty_path_and_the_long_one() {
        assert_eq!(normalize(b"/", b"", 256), Err(PathError::Empty));
        // `max` counts the NUL: a path of max-1 bytes fits, max bytes does not.
        let fits = alloc::format!("/{}", "a".repeat(254));
        let long = alloc::format!("/{}", "a".repeat(255));
        assert_eq!(fits.len(), 255);
        assert!(normalize(b"/", fits.as_bytes(), 256).is_ok());
        assert_eq!(normalize(b"/", long.as_bytes(), 256), Err(PathError::TooLong));
        // The base counts too.
        assert_eq!(normalize(long[..250].as_bytes(), b"bbbbbbbb", 256), Err(PathError::TooLong));
    }

    // POSIX's own definitions, over a wait status.
    fn wifexited(s: i32) -> bool {
        s & 0x7f == 0
    }
    fn wexitstatus(s: i32) -> i32 {
        (s >> 8) & 0xff
    }
    fn wifsignaled(s: i32) -> bool {
        ((s & 0x7f) + 1) as i8 >> 1 > 0
    }
    fn wtermsig(s: i32) -> i32 {
        s & 0x7f
    }

    #[test]
    fn wait_status_reports_exits_and_kernel_kills_as_posix_does() {
        for code in [0, 1, 3, 42, 127, 255] {
            let s = wait_status(code);
            assert!(wifexited(s) && !wifsignaled(s), "exit {code}");
            assert_eq!(wexitstatus(s), code);
        }
        // The kernel's kills: 128 + the signal a shell shows.
        for (code, sig) in [(139, 11), (132, 4), (135, 7), (133, 5), (137, 9)] {
            let s = wait_status(code);
            assert!(wifsignaled(s) && !wifexited(s), "kill {code}");
            assert_eq!(wtermsig(s), sig);
        }
        // Only the codes the kernel assigns are kills; an exit(130) is an exit.
        assert!(wifexited(wait_status(130)));
        // The status is 8 bits wide.
        assert_eq!(wexitstatus(wait_status(256 + 7)), 7);
    }

    #[test]
    fn dirent_records_round_trip_and_pack() {
        let names: [&[u8]; 4] = [b"A", b"HELLO.TXT", b"a-name-of-twenty-chars", b"x"];
        let mut buf = alloc::vec![0xAAu8; 512];
        let mut at = 0;
        for (i, n) in names.iter().enumerate() {
            let rl = dirent_reclen(n.len());
            assert_eq!(rl % 8, 0);
            assert!(rl >= D_NAME + n.len() + 1);
            write_dirent(&mut buf[at..at + rl], i as u64, i == 1, n);
            at += rl;
        }
        let mut at = 0;
        for (i, n) in names.iter().enumerate() {
            let (rl, off) = read_dirent(&buf[at..]).unwrap();
            assert_eq!(rl as usize, dirent_reclen(n.len()));
            assert_eq!(off, i as u64 + 1, "d_off is the index of the next entry");
            let rec = &buf[at..at + rl as usize];
            assert_eq!(rec[D_TYPE], if i == 1 { DT_DIR } else { DT_REG });
            assert_eq!(&rec[D_NAME..D_NAME + n.len()], *n);
            assert!(rec[D_NAME + n.len()..].iter().all(|&b| b == 0), "name is NUL-padded");
            at += rl as usize;
        }
        assert_eq!(read_dirent(&buf[..D_RECLEN + 1]), None, "a short buffer is not a record");
    }

    type Pack = fn(&[DirEntry], u64, &mut [u8]) -> Result<usize, BufferTooSmall>;

    fn snapshot() -> Vec<DirEntry> {
        [(&b"A"[..], false), (b"SUB", true), (b"HELLO.TXT", false)]
            .iter()
            .map(|&(n, d)| DirEntry { name: n.into(), is_dir: d })
            .collect()
    }

    /// What reading a directory from its snapshot must do: resume at `first`,
    /// stop at the end, stop at the last whole record that fits, refuse a buffer
    /// that holds not even one.
    fn check_pack(f: Pack) -> Result<(), alloc::string::String> {
        let e = snapshot();
        let mut buf = alloc::vec![0u8; 512];
        let all = f(&e, 0, &mut buf).map_err(|_| "full buffer refused")?;
        let (rl0, off0) = read_dirent(&buf).ok_or("no first record")?;
        if off0 != 1 || rl0 as usize != dirent_reclen(1) {
            return Err(alloc::format!("first record: reclen {rl0}, d_off {off0}"));
        }
        let want = dirent_reclen(1) + dirent_reclen(3) + dirent_reclen(9);
        if all != want {
            return Err(alloc::format!("all entries: {all} bytes, want {want}"));
        }
        let rest = f(&e, 1, &mut buf).map_err(|_| "resume refused")?;
        let (_, off) = read_dirent(&buf).ok_or("no record after resume")?;
        if rest != want - dirent_reclen(1) || off != 2 || buf[D_NAME..D_NAME + 3] != *b"SUB" {
            return Err(alloc::format!("resume at 1: {rest} bytes, d_off {off}"));
        }
        if f(&e, 3, &mut buf) != Ok(0) || f(&e, u64::MAX, &mut buf) != Ok(0) {
            return Err("past the end is not 0".into());
        }
        let two = dirent_reclen(1) + dirent_reclen(3);
        if f(&e, 0, &mut buf[..two + 4]) != Ok(two) {
            return Err("a partial buffer must end on a whole record".into());
        }
        if f(&e, 0, &mut buf[..dirent_reclen(1) - 1]) != Err(BufferTooSmall) {
            return Err("a buffer under one record must be refused".into());
        }
        Ok(())
    }

    #[test]
    fn pack_dirents_serves_the_snapshot_by_index() {
        check_pack(pack_dirents).unwrap();
    }

    #[test]
    fn pack_dirents_canary_ignoring_the_resume_index_is_caught() {
        fn from_zero(e: &[DirEntry], _first: u64, buf: &mut [u8]) -> Result<usize, BufferTooSmall> {
            pack_dirents(e, 0, buf)
        }
        assert!(check_pack(from_zero).is_err(), "a pack that always restarts must fail the check");
    }

    #[test]
    fn cstr_blob_counts_and_bounds() {
        let (b, n) = cstr_blob([&b"ls"[..], b"-l", b""].into_iter(), 16, 1024).unwrap();
        assert_eq!((b.as_slice(), n), (&b"ls\0-l\0\0"[..], 3));
        assert_eq!(cstr_blob(core::iter::empty(), 16, 1024).unwrap(), (Vec::new(), 0));
        let many = alloc::vec![&b"a"[..]; 17];
        assert_eq!(cstr_blob(many.iter().copied(), 16, 1024), Err(TooBig));
        assert!(cstr_blob(many[..16].iter().copied(), 16, 1024).is_ok());
        // 1024 bytes with their NULs fit, 1025 do not.
        let s = alloc::vec![b'x'; 511];
        assert!(cstr_blob([&s[..], &s[..]].into_iter(), 16, 1024).is_ok());
        let t = alloc::vec![b'x'; 512];
        assert_eq!(cstr_blob([&t[..], &s[..]].into_iter(), 16, 1024), Err(TooBig));
    }

    #[test]
    fn futex_timeout_is_relative_and_never_zero() {
        assert_eq!(futex_timeout(1_500, 1_000), Some(500));
        // A deadline that has passed, or is now: a timeout, because 0 means "no limit".
        assert_eq!(futex_timeout(1_000, 1_000), None);
        assert_eq!(futex_timeout(999, 1_000), None);
        assert_eq!(futex_timeout(0, u64::MAX), None);
        assert_eq!(futex_timeout(u64::MAX, 0), Some(u64::MAX));
    }
}
