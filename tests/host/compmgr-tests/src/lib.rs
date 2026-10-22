// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the component manager (`userspace/services/compmgr`).
//!
//! The supervision tree (`tree.rs`) and the table of IDL failure contracts
//! (`contracts.rs`) are pulled in with `#[path]`, so the code under test is
//! the code `COMPMGR.ELF` is built from. The tree is driven over a [`World`]:
//! a clock, the tasks it started, the stops it asked for and the records it
//! wrote. What the kernel does with a spawn or a stop (the row's capabilities,
//! the seccomp profile, the exit notice) is tested where the kernel is.

#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/tree.rs"]
pub mod tree;

#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/contracts.rs"]
pub mod contracts;

#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/request.rs"]
pub mod request;

#[cfg(test)]
mod tests {
    use crate::contracts;
    use crate::tree::*;
    use azos_idl::OnFailure;
    use std::collections::HashMap;

    const SEC: u64 = 1_000_000_000;

    /// The world the tree sees.
    struct World {
        now: u64,
        next_tid: u32,
        /// Images whose spawn is refused, with the errno.
        refuse: HashMap<&'static str, i32>,
        /// Images spawned, in order, with the TID given.
        spawned: Vec<(String, u32)>,
        /// The directory each spawn was given, in order ("" for /fat).
        dirs: Vec<String>,
        stopped: Vec<u32>,
        /// Every record, as (kind, name, tid, code, attempt).
        log: Vec<(EventKind, String, u32, i32, u8)>,
        /// Failure contracts by endpoint (instead of the IDL's).
        contracts: HashMap<&'static str, OnFailure>,
        /// Use the IDL's contracts (`contracts::contract_of`).
        idl: bool,
    }

    impl World {
        fn new() -> World {
            World {
                now: 10 * SEC,
                next_tid: 100,
                refuse: HashMap::new(),
                spawned: Vec::new(),
                dirs: Vec::new(),
                stopped: Vec::new(),
                log: Vec::new(),
                contracts: HashMap::new(),
                idl: false,
            }
        }

        fn tid_of(&self, image: &str) -> u32 {
            self.spawned.iter().rev().find(|(n, _)| n == image).map(|(_, t)| *t).expect("never spawned")
        }

        fn spawned_names(&self) -> Vec<&str> {
            self.spawned.iter().map(|(n, _)| n.as_str()).collect()
        }

        fn kinds(&self, k: EventKind) -> Vec<&(EventKind, String, u32, i32, u8)> {
            self.log.iter().filter(|e| e.0 == k).collect()
        }

        fn count(&self, k: EventKind, name: &str) -> usize {
            self.log.iter().filter(|e| e.0 == k && e.1 == name).count()
        }
    }

    impl Host for World {
        fn spawn(&mut self, dir: &[u8], image: &[u8]) -> Result<u32, i32> {
            self.dirs.push(String::from_utf8(dir.to_vec()).unwrap());
            let name = String::from_utf8(image.to_vec()).unwrap();
            if let Some(rc) = self.refuse.get(name.as_str()) {
                return Err(*rc);
            }
            self.next_tid += 1;
            self.spawned.push((name, self.next_tid));
            Ok(self.next_tid)
        }
        fn stop(&mut self, tid: u32) {
            self.stopped.push(tid);
        }
        fn now_ns(&mut self) -> u64 {
            self.now
        }
        fn record(&mut self, e: &Event<'_>) {
            self.log.push((e.kind, String::from_utf8_lossy(e.name).into_owned(), e.tid, e.code, e.attempt));
        }
        fn contract(&mut self, endpoint: &[u8]) -> Option<OnFailure> {
            if self.idl {
                return contracts::contract_of(endpoint);
            }
            self.contracts.get(std::str::from_utf8(endpoint).unwrap()).copied()
        }
    }

    /// A reap of one child as the manager's loop does it: the tree is told of
    /// the end, then starts what is due. Several ends in one reap are
    /// `on_exit` for each and one `tick` (the tests of the session).
    trait Reap {
        fn exit(&mut self, tid: u32, code: i32, w: &mut World) -> bool;
    }

    impl Reap for Tree {
        fn exit(&mut self, tid: u32, code: i32, w: &mut World) -> bool {
            let known = self.on_exit(tid, code, w);
            self.tick(w);
            known
        }
    }

    fn intensity(burst: u8) -> Intensity {
        Intensity { burst, interval_ns: 300 * SEC, cooldown_ns: SEC }
    }

    /// A whole view, as the kernel renders it: the rows and the closing line.
    fn load(view: &str, burst: u8, w: &mut World) -> Tree {
        load_raw(&format!("{view}end\n"), burst, w)
    }

    /// A view exactly as given.
    fn load_raw(view: &str, burst: u8, w: &mut World) -> Tree {
        let mut t = Tree::new(intensity(burst));
        t.load(view.as_bytes(), w);
        t
    }

    fn order(t: &Tree) -> Vec<String> {
        t.order().map(|n| String::from_utf8(n.to_vec()).unwrap()).collect()
    }

    /// The native shell session as the kernel lists it: the name server, then
    /// the console program (the terminal server), then the shell.
    const SESSION: &str = "NAMESD.ELF on-failure endpoint.names -\n\
                           TERMD.ELF on-failure endpoint.term -\n\
                           SH.ELF on-failure - endpoint.names,endpoint.term\n";

    // ---- reading the view ------------------------------------------------------

    /// A read that fails is an error the manager sees, not the end of the
    /// file: the rows read before it would be supervised as the whole view.
    /// Canary: the loop that stopped on `n <= 0` returned `Ok(10)` here.
    #[test]
    fn a_failed_read_of_the_view_is_an_error_not_its_end() {
        let mut buf = [0u8; 64];
        let mut calls = 0;
        let r = read_view(&mut buf, |b| {
            calls += 1;
            if calls == 1 {
                b[..10].copy_from_slice(b"A.ELF no -");
                10
            } else {
                -5
            }
        });
        assert_eq!(r, Err(-5));
    }

    /// The pieces the VFS hands out are joined, up to the end of the file or
    /// of the buffer.
    #[test]
    fn the_view_is_read_in_pieces_to_its_end() {
        const FILE: &[u8] = b"A.ELF no - -\nend\n";
        fn pieces(at: &mut usize) -> impl FnMut(&mut [u8]) -> isize + '_ {
            move |b| {
                let n = (FILE.len() - *at).min(5).min(b.len());
                b[..n].copy_from_slice(&FILE[*at..*at + n]);
                *at += n;
                n as isize
            }
        }
        let mut buf = [0u8; 64];
        assert_eq!(read_view(&mut buf, pieces(&mut 0)), Ok(FILE.len()));
        assert_eq!(&buf[..FILE.len()], FILE);
        let mut small = [0u8; 8];
        assert_eq!(read_view(&mut small, pieces(&mut 0)), Ok(8), "a full buffer ends the read");
    }

    // ---- start order -------------------------------------------------------

    #[test]
    fn starts_follow_the_dependencies_the_endpoints_imply() {
        let mut w = World::new();
        // The view lists the shell FIRST; it needs both servers.
        let mut t = load(
            "SH.ELF on-failure - endpoint.names,endpoint.term\n\
             TERMD.ELF on-failure endpoint.term -\n\
             NAMESD.ELF on-failure endpoint.names -\n",
            3,
            &mut w,
        );
        assert_eq!(order(&t), ["TERMD.ELF", "NAMESD.ELF", "SH.ELF"]);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["TERMD.ELF", "NAMESD.ELF", "SH.ELF"]);
        assert_eq!(w.kinds(EventKind::Start).len(), 3);
        assert_eq!(t.state_of(b"SH.ELF"), Some(State::Running));
    }

    #[test]
    fn independent_components_keep_the_kernels_order() {
        let mut w = World::new();
        let mut t = load("B.ELF on-failure - -\nA.ELF on-failure - -\nC.ELF no - -\n", 3, &mut w);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["B.ELF", "A.ELF", "C.ELF"]);
    }

    /// A row a package brought is in `/pkg/APPS`, not on `/fat`: the view says
    /// so in a fifth field and the manager hands the directory to the host.
    #[test]
    fn a_package_row_is_spawned_from_its_directory() {
        let mut w = World::new();
        let mut t = load("SH.ELF on-failure - -\nVISION.ELF on-failure - - /pkg/APPS\n", 3, &mut w);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["SH.ELF", "VISION.ELF"]);
        assert_eq!(w.dirs, ["", "/pkg/APPS"], "only the package's row leaves /fat");
    }

    /// A directory that is not absolute, or is past the longest kept, is a bad
    /// line, not a path the manager joins to an image.
    #[test]
    fn a_relative_or_overlong_image_directory_is_a_bad_line() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - - pkg\nB.ELF on-failure - - /aaaaaaaaaaaaaaaaaaaa\nC.ELF on-failure - -\n", 3, &mut w);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 2);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["C.ELF"]);
    }

    #[test]
    fn a_need_nobody_listed_serves_is_no_dependency() {
        let mut w = World::new();
        // `entropy` is served by the kernel; `endpoint.packages` by a row
        // that is not started: neither holds the shell back.
        let mut t = load("SH.ELF on-failure - entropy,endpoint.packages\n", 3, &mut w);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["SH.ELF"]);
    }

    #[test]
    fn a_dependency_cycle_blocks_its_members_and_nothing_else() {
        let mut w = World::new();
        let mut t = load(
            "A.ELF on-failure ea eb\nB.ELF on-failure eb ea\nC.ELF on-failure - -\nD.ELF on-failure - ea\n",
            3,
            &mut w,
        );
        assert_eq!(w.count(EventKind::Blocked, "A.ELF"), 1);
        assert_eq!(w.count(EventKind::Blocked, "B.ELF"), 1);
        assert_eq!(w.count(EventKind::Blocked, "D.ELF"), 1, "what waits for a cycle waits for ever");
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["C.ELF"]);
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Blocked));
    }

    #[test]
    fn a_bad_line_is_recorded_and_skipped() {
        let mut w = World::new();
        let mut t = load("A.ELF sometimes - -\nB.ELF on-failure - -\nnonsense\n\n", 3, &mut w);
        assert_eq!(t.len(), 1);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 2);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["B.ELF"]);
    }

    /// A view without its closing line was cut (the procfs buffer ended, or
    /// the read did): it is recorded, and a row cut mid-line is NOT a row. The
    /// cut row below would parse as `CLI.ELF` with the need `ea` only, a lost
    /// dependency on `eb`.
    ///
    /// Canary: take a view with no `end` line as whole (`rows_of` returns
    /// `true` for it) and the cut `CLI.ELF` row is started without `eb`'s server.
    #[test]
    fn a_view_cut_mid_row_is_recorded_and_its_partial_row_dropped() {
        let mut w = World::new();
        let mut t = load_raw("SRVB.ELF on-failure eb -\nCLI.ELF on-failure - ea", 3, &mut w);
        assert_eq!(t.len(), 1, "the cut CLI.ELF row is not a component");
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 1);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["SRVB.ELF"]);
    }

    /// The rows before the cut are kept (a cut after a whole line loses no
    /// row but is still recorded); an empty read is recorded too.
    #[test]
    fn a_view_without_its_end_line_is_recorded() {
        let mut w = World::new();
        let mut t = load_raw("A.ELF on-failure - -\nB.ELF on-failure - -\n", 3, &mut w);
        assert_eq!(t.len(), 2);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 1);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["A.ELF", "B.ELF"]);
        let mut w = World::new();
        let t = load_raw("", 3, &mut w);
        assert_eq!(t.len(), 0);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 1);
        // A whole view with no rows is not an error.
        let mut w = World::new();
        let t = load_raw("end\n", 3, &mut w);
        assert_eq!(t.len(), 0);
        assert!(w.kinds(EventKind::ViewRejected).is_empty());
    }

    /// `end` closes a view only as a line of its own: the tail of a row's
    /// name is not the closing line.
    #[test]
    fn end_is_a_line_of_its_own() {
        let mut w = World::new();
        let t = load_raw("A.ELF on-failure - -\nrow-without-newline-end\n", 3, &mut w);
        assert_eq!(t.len(), 1);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 2);
    }

    /// `VIEW_MAX` is the procfs file bound the kernel renders `/proc/components`
    /// into: one number in two places, and this is where they are held equal.
    #[test]
    fn the_view_buffer_is_the_procfs_file_bound() {
        let src = include_str!("../../../../crates/fs/fs/src/procfs.rs");
        let line = src
            .lines()
            .find(|l| l.starts_with("pub const PROCFS_MAX_FILE: usize = "))
            .expect("PROCFS_MAX_FILE is declared");
        let n: usize = line
            .trim_start_matches("pub const PROCFS_MAX_FILE: usize = ")
            .trim_end_matches(';')
            .parse()
            .unwrap();
        assert_eq!(VIEW_MAX, n);
    }

    #[test]
    fn components_past_the_table_are_recorded_and_skipped() {
        let mut w = World::new();
        let mut view = String::new();
        for i in 0..MAX_COMPONENTS + 2 {
            view.push_str(&format!("C{i}.ELF on-failure - -\n"));
        }
        let mut t = load(&view, 3, &mut w);
        assert_eq!(t.len(), MAX_COMPONENTS);
        assert_eq!(w.kinds(EventKind::ViewRejected).len(), 2);
        t.start_all(&mut w);
        assert_eq!(w.spawned.len(), MAX_COMPONENTS);
    }

    // ---- restart strategies ------------------------------------------------

    #[test]
    fn a_server_with_no_contract_restarts_its_dependents_behind_it() {
        let mut w = World::new();
        let mut t = load(SESSION, 3, &mut w);
        assert_eq!(t.strategy_of(b"TERMD.ELF"), Some(Strategy::RestForOne));
        t.start_all(&mut w);
        let (termd, names, sh) = (w.tid_of("TERMD.ELF"), w.tid_of("NAMESD.ELF"), w.tid_of("SH.ELF"));
        w.spawned.clear();
        // The terminal server fails.
        assert!(t.exit(termd, 7, &mut w));
        // The shell (it needs `endpoint.term`) was stopped; the name server
        // (it only serves) was not.
        assert_eq!(w.stopped, [sh]);
        assert_eq!(t.state_of(b"SH.ELF"), Some(State::Stopping));
        assert_eq!(t.state_of(b"NAMESD.ELF"), Some(State::Running));
        // The terminal server is started again at once; the shell waits for
        // its own exit to be seen.
        assert_eq!(w.spawned_names(), ["TERMD.ELF"]);
        assert!(t.exit(sh, 9, &mut w));
        assert_eq!(w.spawned_names(), ["TERMD.ELF", "SH.ELF"], "behind it, in order");
        assert_eq!(w.count(EventKind::Restart, "TERMD.ELF"), 1);
        assert_eq!(w.count(EventKind::Restart, "SH.ELF"), 1);
        assert_eq!(w.count(EventKind::Stopped, "SH.ELF"), 1);
        // A stop is not a failure: the shell's restart spent none of its budget.
        let shell_restart = w.log.iter().find(|e| e.0 == EventKind::Restart && e.1 == "SH.ELF").unwrap();
        assert_eq!(shell_restart.4, 0);
        // The name server was never touched.
        assert_eq!(w.count(EventKind::Restart, "NAMESD.ELF"), 0);
        assert_eq!(w.spawned.iter().filter(|(n, _)| n == "NAMESD.ELF").count(), 0);
        let _ = names;
    }

    // ---- the shell session ends together ------------------------------------
    //
    // `exit 1` in the shell hangs up the terminal server with the status, and
    // both end with it (`userspace/services/termd`): the manager reaps two
    // ends in one pass. (`/proc/components` spells the shell's imports as the
    // endpoints they stand for: `tests/host/topology-tests`, `compmgr_view`.)

    /// Both ends are in one reap, the shell's first: the shell is not started
    /// while its terminal server is still `Running` in the tree's eyes (it
    /// would ask the name server for a terminal nobody serves, exit 1 on its
    /// own, and spend a restart of its budget on a crash that was not its
    /// own). The terminal server comes back first, the shell behind it.
    ///
    /// **Canary.** Start what is due inside `on_exit` again (call
    /// `self.reconcile(host)` before its `true`): the shell is started at once,
    /// ahead of the terminal server, and is stopped when the terminal
    /// server's end is seen; the spawn order and the stop list below fail.
    #[test]
    fn a_session_that_ends_together_restarts_the_terminal_server_first() {
        let mut w = World::new();
        let mut t = load(SESSION, 3, &mut w);
        t.start_all(&mut w);
        let (sh, termd) = (w.tid_of("SH.ELF"), w.tid_of("TERMD.ELF"));
        w.spawned.clear();
        assert!(t.on_exit(sh, 1, &mut w));
        assert!(w.spawned.is_empty(), "nothing starts until the whole reap is known");
        assert!(t.on_exit(termd, 1, &mut w));
        assert!(w.spawned.is_empty());
        t.tick(&mut w);
        assert_eq!(w.spawned_names(), ["TERMD.ELF", "SH.ELF"], "the server first, the shell behind it");
        assert!(w.stopped.is_empty(), "the shell had already ended: nothing to stop");
        // One crash, one restart each; the name server was not touched.
        for n in ["SH.ELF", "TERMD.ELF"] {
            let r = w.log.iter().find(|e| e.0 == EventKind::Restart && e.1 == n).unwrap();
            assert_eq!((r.3, r.4), (1, 1), "{n}: the failure it replaces, the first attempt");
        }
        assert_eq!(w.count(EventKind::Restart, "NAMESD.ELF"), 0);
    }

    /// The shell's end is seen first and in a reap of its own, so it is
    /// started again while the terminal server is still `Running`; then the
    /// terminal server's end is seen. The new shell depends on it, so it is
    /// stopped and started again behind it, and the stop is no failure.
    ///
    /// **Canary.** Drop the edge (`/proc/components` spelling the shell's
    /// import as `term`, which no row serves): the shell is never stopped and
    /// keeps running against a server that has gone.
    #[test]
    fn a_shell_started_ahead_of_its_dead_terminal_server_is_stopped_not_charged() {
        let mut w = World::new();
        let mut t = load(SESSION, 3, &mut w);
        t.start_all(&mut w);
        let (sh, termd) = (w.tid_of("SH.ELF"), w.tid_of("TERMD.ELF"));
        w.spawned.clear();
        t.exit(sh, 1, &mut w);
        let early = w.tid_of("SH.ELF");
        assert_ne!(early, sh);
        t.exit(termd, 1, &mut w);
        assert_eq!(w.stopped, [early], "the early shell is stopped behind its server");
        // The stop ends it (137 is what a forced stop is): no charge.
        t.exit(early, 137, &mut w);
        assert_eq!(w.spawned_names(), ["SH.ELF", "TERMD.ELF", "SH.ELF"]);
        let restarts: Vec<_> = w.log.iter().filter(|e| e.0 == EventKind::Restart && e.1 == "SH.ELF").collect();
        assert_eq!(restarts.len(), 2);
        assert_eq!(restarts[1].4, 1, "the stop spent nothing: still the first attempt of the burst");
        assert_eq!(t.state_of(b"SH.ELF"), Some(State::Running));
    }

    /// `exit 1` four times: each time the shell and the terminal server end
    /// together and come back together, and the fourth time both budgets are
    /// spent in the same reap: the terminal server stays down, so console
    /// input is released for good (`kernel/src/console_mode.rs` hands it to
    /// the recovery console), and so does the shell. Nothing is started
    /// afterwards, and the name server was never a casualty.
    ///
    /// **Canary.** Start what is due inside `on_exit` again: the shell is
    /// started ahead of the terminal server in the first round, which fails.
    #[test]
    fn exit_one_four_times_gives_up_the_session_together() {
        let mut w = World::new();
        let mut t = load(SESSION, 3, &mut w);
        t.start_all(&mut w);
        for round in 1..=3u8 {
            let (sh, termd) = (w.tid_of("SH.ELF"), w.tid_of("TERMD.ELF"));
            t.on_exit(sh, 1, &mut w);
            t.on_exit(termd, 1, &mut w);
            w.now += 2 * SEC;
            t.tick(&mut w);
            assert_eq!(t.state_of(b"SH.ELF"), Some(State::Running), "round {round}");
            assert_eq!(t.state_of(b"TERMD.ELF"), Some(State::Running), "round {round}");
            assert_eq!(w.count(EventKind::Restart, "SH.ELF"), round as usize);
            assert_eq!(w.count(EventKind::Restart, "TERMD.ELF"), round as usize);
        }
        let spawned = w.spawned.len();
        let (sh, termd) = (w.tid_of("SH.ELF"), w.tid_of("TERMD.ELF"));
        t.on_exit(sh, 1, &mut w);
        t.on_exit(termd, 1, &mut w);
        t.tick(&mut w);
        assert_eq!(t.state_of(b"TERMD.ELF"), Some(State::Down), "console input is released for good");
        assert_eq!(t.state_of(b"SH.ELF"), Some(State::Down));
        assert_eq!(w.count(EventKind::GiveUp, "TERMD.ELF"), 1);
        assert_eq!(w.count(EventKind::GiveUp, "SH.ELF"), 1);
        assert!(w.stopped.is_empty());
        w.now += 1000 * SEC;
        t.tick(&mut w);
        assert_eq!(w.spawned.len(), spawned, "nothing starts again");
        assert_eq!(t.state_of(b"NAMESD.ELF"), Some(State::Running));
        assert_eq!(w.count(EventKind::Restart, "NAMESD.ELF"), 0);
    }

    #[test]
    fn the_restart_follows_the_chain_not_just_the_direct_dependents() {
        let mut w = World::new();
        let mut t = load("C.ELF on-failure - eb\nB.ELF on-failure eb ea\nA.ELF on-failure ea -\n", 3, &mut w);
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["A.ELF", "B.ELF", "C.ELF"]);
        let (a, b, c) = (w.tid_of("A.ELF"), w.tid_of("B.ELF"), w.tid_of("C.ELF"));
        w.spawned.clear();
        t.exit(a, 1, &mut w);
        let mut stopped = w.stopped.clone();
        stopped.sort();
        assert_eq!(stopped, [b, c]);
        t.exit(c, 0, &mut w);
        assert_eq!(w.spawned_names(), ["A.ELF"], "B is not out yet: C waits for it");
        t.exit(b, 0, &mut w);
        assert_eq!(w.spawned_names(), ["A.ELF", "B.ELF", "C.ELF"]);
    }

    #[test]
    fn a_declared_contract_restarts_the_component_alone() {
        let mut w = World::new();
        w.idl = true; // the IDL: the Packages interface declares degrade
        let mut t = load(
            "PKGD.ELF on-failure endpoint.packages -\nPKG.ELF on-failure - endpoint.packages\n",
            3,
            &mut w,
        );
        assert_eq!(t.strategy_of(b"PKGD.ELF"), Some(Strategy::OneForOne));
        t.start_all(&mut w);
        let pkgd = w.tid_of("PKGD.ELF");
        w.spawned.clear();
        t.exit(pkgd, 1, &mut w);
        assert!(w.stopped.is_empty(), "its callers are refused meanwhile, not restarted");
        assert_eq!(w.spawned_names(), ["PKGD.ELF"]);
        assert_eq!(t.state_of(b"PKG.ELF"), Some(State::Running));
    }

    #[test]
    fn the_strongest_contract_among_the_served_endpoints_wins() {
        let mut w = World::new();
        w.contracts.insert("e1", OnFailure::Degrade);
        w.contracts.insert("e2", OnFailure::Escalate);
        w.contracts.insert("e3", OnFailure::Restart);
        // A escalates, B restarts: observed through what a failure does.
        let mut t = load("A.ELF on-failure e1,e2,e3 -\nB.ELF on-failure e3,e1 -\n", 3, &mut w);
        t.start_all(&mut w);
        let (a, b) = (w.tid_of("A.ELF"), w.tid_of("B.ELF"));
        t.exit(a, 1, &mut w);
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Down));
        assert_eq!(w.count(EventKind::Escalate, "A.ELF"), 1);
        t.exit(b, 1, &mut w);
        assert_eq!(t.state_of(b"B.ELF"), Some(State::Running), "B restarted");
        assert_eq!(w.count(EventKind::Escalate, "B.ELF"), 0);
    }

    #[test]
    fn escalate_is_handed_up_not_restarted_and_takes_the_dependents_down() {
        let mut w = World::new();
        w.contracts.insert("motor", OnFailure::Escalate);
        let mut t = load("MOTOR.ELF on-failure motor -\nCTL.ELF on-failure - motor\nLOG.ELF on-failure - -\n", 3, &mut w);
        t.start_all(&mut w);
        let (motor, ctl) = (w.tid_of("MOTOR.ELF"), w.tid_of("CTL.ELF"));
        w.spawned.clear();
        t.exit(motor, 139, &mut w);
        assert_eq!(w.count(EventKind::Escalate, "MOTOR.ELF"), 1);
        assert_eq!(w.log.iter().find(|e| e.0 == EventKind::Escalate).unwrap().3, 139);
        assert!(w.spawned.is_empty(), "nothing is restarted");
        assert_eq!(w.stopped, [ctl]);
        assert_eq!(t.state_of(b"MOTOR.ELF"), Some(State::Down));
        assert_eq!(t.state_of(b"CTL.ELF"), Some(State::Blocked));
        assert_eq!(t.state_of(b"LOG.ELF"), Some(State::Running), "what does not depend on it is untouched");
        // The dependent's own exit, which the stop caused, changes nothing.
        t.exit(ctl, 143, &mut w);
        assert!(w.spawned.is_empty());
    }

    #[test]
    fn safe_state_is_recorded_and_the_component_restarted() {
        let mut w = World::new();
        w.contracts.insert("pwm", OnFailure::SafeState);
        let mut t = load("PWM.ELF on-failure pwm -\n", 3, &mut w);
        t.start_all(&mut w);
        let tid = w.tid_of("PWM.ELF");
        t.exit(tid, 11, &mut w);
        assert_eq!(w.count(EventKind::SafeState, "PWM.ELF"), 1);
        assert_eq!(w.count(EventKind::Restart, "PWM.ELF"), 1);
    }

    // ---- restart policy ----------------------------------------------------

    #[test]
    fn on_failure_leaves_a_clean_exit_alone() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\n", 3, &mut w);
        t.start_all(&mut w);
        t.exit(w.tid_of("A.ELF"), 0, &mut w);
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Exited));
        assert_eq!(w.count(EventKind::Exit, "A.ELF"), 1);
        assert_eq!(w.spawned.len(), 1);
    }

    #[test]
    fn always_restarts_a_clean_exit_against_the_same_window() {
        let mut w = World::new();
        let mut t = load("A.ELF always - -\n", 2, &mut w);
        t.start_all(&mut w);
        for round in 0..3u32 {
            let tid = w.tid_of("A.ELF");
            t.exit(tid, 0, &mut w);
            w.now += 2 * SEC; // past the cooldown
            t.tick(&mut w);
            assert_eq!(w.spawned.len() as u32, 2 + round.min(1), "round {round}");
        }
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Down));
        assert_eq!(w.count(EventKind::GiveUp, "A.ELF"), 1);
    }

    #[test]
    fn no_restarts_nothing_whatever_the_code() {
        let mut w = World::new();
        let mut t = load("A.ELF no - -\n", 3, &mut w);
        t.start_all(&mut w);
        t.exit(w.tid_of("A.ELF"), 139, &mut w);
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Exited));
        let e = w.kinds(EventKind::Exit);
        assert_eq!((e.len(), e[0].3), (1, 139));
        assert_eq!(w.spawned.len(), 1);
    }

    #[test]
    fn a_child_the_tree_does_not_know_is_ignored() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\n", 3, &mut w);
        t.start_all(&mut w);
        let n = w.log.len();
        assert!(!t.exit(4242, 1, &mut w));
        assert!(!t.exit(0, 1, &mut w));
        assert_eq!(w.log.len(), n);
    }

    // ---- the buzzer's ring-3 host ---------------------------------------------

    /// The row of the buzzer's ring-3 host as the kernel renders it
    /// (`/proc/components`): it serves `endpoint.buzzer`; its PWM channel is a
    /// kernel-hosted interface, so it is no `needs`. The kernel's placement
    /// controller does not start or end this task, so the manager's restart
    /// policy is the only one there is.
    fn buzzer_view(restart: &str) -> String {
        format!("BUZZDRV.ELF {restart} endpoint.buzzer -\n")
    }

    /// The manager restarts the buzzer's ring-3 host after a death it did not
    /// ask for, as it does any row: a fresh task, the failure on the record,
    /// no charge on anything else.
    ///
    /// **Canary.** Make `on_exit` ignore a failure of a `Running` component
    /// (return before `fail`): no restart is recorded and the spawn count
    /// stays 1, so every assertion below goes red.
    #[test]
    fn the_buzzer_host_is_restarted_by_the_manager_after_an_injected_death() {
        let mut w = World::new();
        w.idl = true;
        let mut t = load(&buzzer_view("on-failure"), 3, &mut w);
        // It declares no failure contract and nothing depends on it.
        assert_eq!(t.strategy_of(b"BUZZDRV.ELF"), Some(Strategy::RestForOne));
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["BUZZDRV.ELF"]);
        let first = w.tid_of("BUZZDRV.ELF");

        // The injected death: a forced stop (137), as `task_kill` ends it.
        assert!(t.exit(first, 137, &mut w));
        assert_eq!(t.state_of(b"BUZZDRV.ELF"), Some(State::Running));
        assert_eq!(w.spawned_names(), ["BUZZDRV.ELF", "BUZZDRV.ELF"]);
        let second = w.tid_of("BUZZDRV.ELF");
        assert_ne!(first, second, "the successor is a new task");
        // The death notice: one restart record that carries the failure.
        let r = w.kinds(EventKind::Restart);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].1.as_str(), r[0].2, r[0].3, r[0].4), ("BUZZDRV.ELF", second, 137, 1));
        assert!(w.stopped.is_empty(), "nothing else was stopped for it");
        assert_eq!(w.count(EventKind::GiveUp, "BUZZDRV.ELF"), 0);
    }

    /// The row's `restart` key is the buzzer host's policy: the same death
    /// under `restart = no` is final (the topology gate row `restart-smoke`
    /// states it on a boot), and a clean exit under `on-failure` is too.
    ///
    /// This is the test above's canary seen from the other side: a manager
    /// that restarted whatever the key says would pass that one and fail
    /// this one.
    #[test]
    fn the_buzzer_host_follows_its_rows_restart_key() {
        let mut w = World::new();
        w.idl = true;
        let mut t = load(&buzzer_view("no"), 3, &mut w);
        t.start_all(&mut w);
        t.exit(w.tid_of("BUZZDRV.ELF"), 137, &mut w);
        assert_eq!(t.state_of(b"BUZZDRV.ELF"), Some(State::Exited));
        assert_eq!((w.count(EventKind::Exit, "BUZZDRV.ELF"), w.count(EventKind::Restart, "BUZZDRV.ELF")), (1, 0));
        w.now += 5 * SEC;
        t.tick(&mut w);
        assert_eq!(w.spawned.len(), 1, "nothing starts it again");

        let mut w = World::new();
        let mut t = load(&buzzer_view("on-failure"), 3, &mut w);
        t.start_all(&mut w);
        t.exit(w.tid_of("BUZZDRV.ELF"), 0, &mut w);
        assert_eq!(t.state_of(b"BUZZDRV.ELF"), Some(State::Exited));
        assert_eq!(w.spawned.len(), 1);
    }

    /// A buzzer host that keeps dying is given up on after the burst, once,
    /// and stays down; the kernel's calls then find no server on
    /// `endpoint.buzzer` (the placement controller waits for one and does not
    /// start another).
    #[test]
    fn a_buzzer_host_that_keeps_dying_is_given_up_on() {
        let mut w = World::new();
        let mut t = load(&buzzer_view("on-failure"), 2, &mut w);
        t.start_all(&mut w);
        for _ in 0..3 {
            fail_and_wait(&mut t, &mut w, "BUZZDRV.ELF", 137);
        }
        assert_eq!(t.state_of(b"BUZZDRV.ELF"), Some(State::Down));
        assert_eq!(w.spawned.len(), 3, "the first start and two restarts");
        assert_eq!(w.count(EventKind::GiveUp, "BUZZDRV.ELF"), 1);
    }

    // ---- intensity ---------------------------------------------------------

    /// Fail the running `name` and let the cooldown pass.
    fn fail_and_wait(t: &mut Tree, w: &mut World, name: &str, code: i32) {
        let tid = w.tid_of(name);
        t.exit(tid, code, w);
        w.now += 2 * SEC;
        t.tick(w);
    }

    #[test]
    fn the_intensity_limit_gives_up_with_exactly_one_record() {
        let mut w = World::new();
        let mut t = load("SRV.ELF on-failure es -\nCLI.ELF on-failure - es\n", 3, &mut w);
        t.start_all(&mut w);
        for _ in 0..3 {
            fail_and_wait(&mut t, &mut w, "SRV.ELF", 1);
        }
        assert_eq!(w.count(EventKind::Restart, "SRV.ELF"), 3);
        assert_eq!(t.state_of(b"SRV.ELF"), Some(State::Running));
        // The fourth failure within the window is final.
        let spawned = w.spawned.len();
        let tid = w.tid_of("SRV.ELF");
        t.exit(tid, 1, &mut w);
        assert_eq!(t.state_of(b"SRV.ELF"), Some(State::Down));
        let g = w.kinds(EventKind::GiveUp);
        assert_eq!(g.len(), 1, "one record");
        assert_eq!((g[0].1.as_str(), g[0].3, g[0].4), ("SRV.ELF", 1, 3));
        // No more spawns, however long we wait; the dependent is blocked.
        w.now += 1000 * SEC;
        t.tick(&mut w);
        assert_eq!(w.spawned.len(), spawned);
        assert_eq!(t.state_of(b"CLI.ELF"), Some(State::Blocked));
        assert_eq!(w.count(EventKind::GiveUp, "SRV.ELF"), 1);
        assert_eq!(t.wake_at(), None);
    }

    #[test]
    fn restarts_older_than_the_interval_do_not_count() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\n", 2, &mut w);
        t.start_all(&mut w);
        // Ten failures, each further apart than the interval: never given up.
        for _ in 0..10 {
            w.now += 301 * SEC;
            let tid = w.tid_of("A.ELF");
            t.exit(tid, 1, &mut w);
        }
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Running));
        assert_eq!(w.count(EventKind::GiveUp, "A.ELF"), 0);
        assert_eq!(w.count(EventKind::Restart, "A.ELF"), 10);
    }

    #[test]
    fn a_second_restart_waits_out_the_cooldown() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\n", 3, &mut w);
        t.start_all(&mut w);
        let t0 = w.now;
        // The first restart in a window is immediate.
        t.exit(w.tid_of("A.ELF"), 1, &mut w);
        assert_eq!(w.spawned.len(), 2);
        // The second waits `cooldown` after the first.
        w.now = t0 + 100;
        t.exit(w.tid_of("A.ELF"), 1, &mut w);
        assert_eq!(w.spawned.len(), 2, "not yet");
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Wanted));
        assert_eq!(t.wake_at(), Some(t0 + SEC));
        w.now = t0 + SEC - 1;
        t.tick(&mut w);
        assert_eq!(w.spawned.len(), 2);
        w.now = t0 + SEC;
        t.tick(&mut w);
        assert_eq!(w.spawned.len(), 3);
        assert_eq!(t.wake_at(), None);
    }

    #[test]
    fn the_budget_is_per_component() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\nB.ELF on-failure - -\n", 2, &mut w);
        t.start_all(&mut w);
        for _ in 0..3 {
            fail_and_wait(&mut t, &mut w, "A.ELF", 1);
        }
        assert_eq!(t.state_of(b"A.ELF"), Some(State::Down));
        // B has spent nothing.
        fail_and_wait(&mut t, &mut w, "B.ELF", 1);
        assert_eq!(t.state_of(b"B.ELF"), Some(State::Running));
    }

    #[test]
    fn a_refused_spawn_counts_like_a_failure_and_ends_in_a_give_up() {
        let mut w = World::new();
        w.refuse.insert("GONE.ELF", -13);
        let mut t = load("GONE.ELF on-failure - -\nOK.ELF on-failure - -\n", 3, &mut w);
        t.start_all(&mut w);
        for _ in 0..5 {
            w.now += 2 * SEC;
            t.tick(&mut w);
        }
        // The first try and three restarts are refused; the fourth failure
        // is final. Nothing loops.
        assert_eq!(w.count(EventKind::SpawnRefused, "GONE.ELF"), 4);
        assert_eq!(w.count(EventKind::GiveUp, "GONE.ELF"), 1);
        assert_eq!(t.state_of(b"GONE.ELF"), Some(State::Down));
        assert_eq!(w.kinds(EventKind::SpawnRefused)[0].3, -13);
        assert_eq!(t.state_of(b"OK.ELF"), Some(State::Running), "its neighbour is unaffected");
    }

    #[test]
    fn a_dependency_that_is_down_keeps_its_dependents_from_ever_starting() {
        let mut w = World::new();
        w.refuse.insert("SRV.ELF", -2);
        let mut t = load("CLI.ELF on-failure - es\nSRV.ELF on-failure es -\n", 1, &mut w);
        t.start_all(&mut w);
        for _ in 0..3 {
            w.now += 2 * SEC;
            t.tick(&mut w);
        }
        assert_eq!(t.state_of(b"SRV.ELF"), Some(State::Down));
        assert_eq!(t.state_of(b"CLI.ELF"), Some(State::Blocked));
        assert!(w.spawned.is_empty());
        assert_eq!(w.count(EventKind::Blocked, "CLI.ELF"), 1);
    }

    #[test]
    fn the_wake_up_is_the_earliest_cooldown_among_the_startable() {
        let mut w = World::new();
        let mut t = load("A.ELF on-failure - -\nB.ELF on-failure - ea\nC.ELF on-failure ea -\n", 3, &mut w);
        t.start_all(&mut w);
        assert_eq!(t.wake_at(), None);
        let c = w.tid_of("C.ELF");
        t.exit(c, 1, &mut w);
        t.exit(w.tid_of("C.ELF"), 1, &mut w);
        // C waits out a cooldown. B, which needs it, was stopped behind it
        // and is not waiting for the clock.
        assert_eq!(t.wake_at(), Some(w.now + SEC));
    }

    // ---- the IDL's contracts -----------------------------------------------

    #[test]
    fn the_idl_declares_what_the_manager_acts_on() {
        // The Packages interface declares `degrade` on its ops; the others
        // served on a topology endpoint declare nothing today.
        assert_eq!(contracts::contract_of(b"endpoint.packages"), Some(OnFailure::Degrade));
        assert_eq!(contracts::contract_of(b"endpoint.names"), None);
        assert_eq!(contracts::contract_of(b"endpoint.term"), None);
        assert_eq!(contracts::contract_of(b"endpoint.decisions"), None);
        // The buzzer's ring-3 host is a row of the manager like the others:
        // its interface is classified, and declares no contract.
        assert!(contracts::SERVED.iter().any(|(e, _)| *e == b"endpoint.buzzer"));
        assert_eq!(contracts::contract_of(b"endpoint.buzzer"), None);
        assert_eq!(contracts::contract_of(b"endpoint.unheard-of"), None);
        // It is the generated table, not a copy: the strongest of the ops.
        assert_eq!(
            contracts::strongest(&azos_packages::PackagesIdl::OPS),
            Some(OnFailure::Degrade),
        );
        assert_eq!(contracts::strongest(&azos_names::NamesIdl::OPS), None);
    }

    /// One order for failure handling: `tree::severity` merges the contracts
    /// of the endpoints a row serves and `contracts::strongest` merges those
    /// of an interface's ops (it calls `severity`; there is no second ranking
    /// to drift).
    #[test]
    fn failure_handling_has_one_order() {
        let order = [OnFailure::Degrade, OnFailure::Restart, OnFailure::SafeState, OnFailure::Escalate];
        for w in order.windows(2) {
            assert!(severity(w[0]) < severity(w[1]));
        }
    }

    #[test]
    fn the_shell_session_over_the_real_contracts() {
        let mut w = World::new();
        w.idl = true;
        let mut t = load(SESSION, 3, &mut w);
        // The three declare nothing: a failure takes the dependents along.
        for n in [&b"NAMESD.ELF"[..], b"TERMD.ELF", b"SH.ELF"] {
            assert_eq!(t.strategy_of(n), Some(Strategy::RestForOne));
        }
        t.start_all(&mut w);
        assert_eq!(w.spawned_names(), ["NAMESD.ELF", "TERMD.ELF", "SH.ELF"]);
        let (names, sh) = (w.tid_of("NAMESD.ELF"), w.tid_of("SH.ELF"));
        t.exit(names, 1, &mut w);
        // The shell needs `endpoint.names`: stopped, started again behind it.
        assert_eq!(w.stopped, [sh]);
    }

    /// **A child gets the console on stdout and stderr.** The kernel closes
    /// every startup fd the request does not name, and a `std` child (the
    /// package installer) prints through that fd table: the request the
    /// manager sent with no descriptor left its banner and every diagnostic
    /// nowhere, and a gate row waiting for the banner failed on a healthy
    /// boot. The request is well formed, lends no handle, and does not open
    /// stdin (console input is the terminal server's).
    ///
    /// **Canary.** A request with `nmoves = 0` (what the manager sent):
    /// fds 1 and 2 are absent from the lend list.
    #[test]
    fn a_child_is_started_with_the_console_on_stdout_and_stderr() {
        use crate::request;
        use azos_abi::ushell::{FD_CONSOLE, FD_CLOSED, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT, StartupFd, STARTUP_FDS};
        let req = request::child_request();
        assert_eq!(req.check_shape(), Ok(()));
        assert_eq!(req.flags, SPAWN_F_DIE_WITH_PARENT);
        assert_eq!((req.argv_ptr, req.env_ptr, req.cwd_ptr), (0, 0, 0));
        // The fd table the kernel lays out from the move list
        // (`sys_spawn_ex`: a MOVE_CONSOLE entry is a console fd).
        let mut fds = [StartupFd::default(); STARTUP_FDS];
        for m in &req.moves[..req.nmoves as usize] {
            assert_eq!(m.handle, MOVE_CONSOLE, "no handle is lent");
            fds[m.child_fd as usize] = StartupFd { kind: FD_CONSOLE, handle: 0 };
        }
        assert_eq!(fds[0].kind, FD_CLOSED, "stdin stays closed");
        assert_eq!(fds[1].kind, FD_CONSOLE, "stdout");
        assert_eq!(fds[2].kind, FD_CONSOLE, "stderr");
        assert!(fds[3..].iter().all(|f| f.kind == FD_CLOSED));
    }
}
