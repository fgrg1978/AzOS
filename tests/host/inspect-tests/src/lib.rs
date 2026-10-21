// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the introspection tree (crates/core/inspect) and its
//! ring-3 reader (userspace/lib/inspect).
//!
//! The regions are `Vec<AtomicU64>`: the same aligned atomic words the kernel
//! allocates as a MemObj, shared between threads the way the kernel and a
//! reader share a mapping. Tests that poke a word by hand use the layout
//! documented in `crates/core/inspect/src/format.rs`, which a test below pins.

#[cfg(test)]
mod metrics;

#[cfg(test)]
mod tests {
    use azos_inspect::*;
    use azos_inspect_lib::{Inspector, RenderError, Source};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::*};
    use std::sync::Arc;

    const HEADER_WORDS: usize = 8;
    const NODE_WORDS: usize = 8;

    fn words(n: usize) -> Vec<AtomicU64> {
        (0..n).map(|_| AtomicU64::new(0)).collect()
    }

    fn bytes_of(v: &[AtomicU64]) -> Vec<u8> {
        v.iter().flat_map(|w| w.load(Relaxed).to_le_bytes()).collect()
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    /// The word index of field `f` of node `n`.
    fn node_word(n: usize, f: usize) -> usize {
        HEADER_WORDS + n * NODE_WORDS + f
    }

    struct Ids {
        ready: NodeId,
        delta: NodeId,
        name: NodeId,
        lat: NodeId,
    }

    /// `sched/{ready, delta, name, lat}` plus an empty `mem/` directory.
    fn build_sample(w: &Writer) -> Ids {
        let mut ids = None;
        w.rebuild(|b| {
            let sched = b.dir(NodeId::ROOT, "sched")?;
            b.dir(NodeId::ROOT, "mem")?;
            ids = Some(Ids {
                ready: b.u64(sched, "ready", 7)?,
                delta: b.i64(sched, "delta", -3)?,
                name: b.string(sched, "name", 16, "legacy")?,
                lat: b.hist(sched, "lat", 4)?,
            });
            Ok(())
        })
        .unwrap();
        ids.unwrap()
    }

    // ── the format ──────────────────────────────────────────────────────────

    #[test]
    fn the_header_layout_is_pinned() {
        let v = words(512);
        Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        assert_eq!(&bytes_of(&v)[..8], b"AZINSPCT");
        assert_eq!(v[1].load(Relaxed), FORMAT_VERSION as u64);
        assert_eq!(v[2].load(Relaxed), 0, "the epoch starts even");
        assert_eq!(v[3].load(Relaxed) as u32 as usize, 512 * 8, "region bytes");
        assert_eq!(v[4].load(Relaxed) as u32, 1, "the root is the only node");
        let a = words(512);
        Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
        assert_eq!(a[1].load(Relaxed), FORMAT_VERSION as u64 | 1 << 32, "the class is the high half");
    }

    #[test]
    fn a_region_too_small_for_a_tree_is_refused() {
        let v = words(HEADER_WORDS + 8);
        assert_eq!(Writer::init(Region::from_atomics(&v), Class::Public).err(), Some(Error::BadRegion));
        assert_eq!(Reader::open(Region::from_atomics(&v[..4]), Class::Public).err(), Some(Error::BadRegion));
    }

    #[test]
    fn publish_and_read_back_every_kind() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        assert!(matches!(r.read(ids.ready).unwrap(), Value::U64(7)));
        assert!(matches!(r.read(ids.delta).unwrap(), Value::I64(-3)));
        match r.read(ids.name).unwrap() {
            Value::Str(s) => assert_eq!(s.as_str(), "legacy"),
            _ => panic!("kind"),
        }
        match r.read(ids.lat).unwrap() {
            Value::Hist(h) => assert_eq!(h.buckets(), &[0, 0, 0, 0]),
            _ => panic!("kind"),
        }
        w.set_u64(ids.ready, u64::MAX).unwrap();
        w.set_i64(ids.delta, i64::MIN).unwrap();
        w.set_str(ids.name, "classes").unwrap();
        w.set_hist(ids.lat, &[1, 2]).unwrap();
        assert!(matches!(r.read(ids.ready).unwrap(), Value::U64(u64::MAX)));
        assert!(matches!(r.read(ids.delta).unwrap(), Value::I64(i64::MIN)));
        match (r.read(ids.name).unwrap(), r.read(ids.lat).unwrap()) {
            (Value::Str(s), Value::Hist(h)) => {
                assert_eq!(s.as_str(), "classes");
                assert_eq!(h.buckets(), &[1, 2, 0, 0], "buckets past the slice are zeroed");
            }
            _ => panic!("kind"),
        }
        w.stamp(41);
        assert_eq!(r.stamp(), 41);
    }

    #[test]
    fn lookup_and_walk_follow_the_tree() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        assert_eq!(r.lookup("sched/ready").unwrap(), Some(ids.ready));
        assert_eq!(r.lookup("/sched//ready/").unwrap(), Some(ids.ready), "empty segments are ignored");
        assert_eq!(r.lookup("").unwrap(), Some(NodeId::ROOT));
        assert_eq!(r.lookup("sched/nope").unwrap(), None);
        assert_eq!(r.lookup("sched/ready/deeper").unwrap(), None, "a leaf has no children");
        let mut seen = Vec::new();
        r.walk(&mut |i, _| seen.push((i.depth, i.name.as_str().to_string()))).unwrap();
        let want: Vec<(u32, String)> = [(0, ""), (1, "sched"), (2, "ready"), (2, "delta"), (2, "name"), (2, "lat"), (1, "mem")]
            .iter()
            .map(|(d, n)| (*d, n.to_string()))
            .collect();
        assert_eq!(seen, want, "depth first, siblings in the order they were added");
        let info = r.info(ids.delta).unwrap();
        assert_eq!((info.kind, info.depth, info.parent), (Kind::I64, 2, r.lookup("sched").unwrap().unwrap()));
    }

    #[test]
    fn builder_refuses_what_the_format_cannot_hold() {
        let v = words(256);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        w.rebuild(|b| {
            let d = b.dir(NodeId::ROOT, "d")?;
            b.u64(d, "x", 0)?;
            assert_eq!(b.u64(d, "x", 1).err(), Some(Error::Duplicate));
            assert_eq!(b.u64(d, "", 1).err(), Some(Error::BadName));
            assert_eq!(b.u64(d, "a/b", 1).err(), Some(Error::BadName));
            assert_eq!(b.u64(d, &"n".repeat(NAME_MAX + 1), 1).err(), Some(Error::BadName));
            assert!(b.u64(d, &"n".repeat(NAME_MAX), 1).is_ok(), "the longest name fits");
            let leaf = b.u64(d, "leaf", 0)?;
            assert_eq!(b.dir(leaf, "under").err(), Some(Error::WrongKind), "only a directory has children");
            assert_eq!(b.dir(NodeId(999), "x").err(), Some(Error::BadNode));
            assert_eq!(b.string(d, "s", 0, "").err(), Some(Error::BadSize));
            assert_eq!(b.string(d, "s", STR_MAX + 1, "").err(), Some(Error::BadSize));
            assert_eq!(b.hist(d, "h", 0).err(), Some(Error::BadSize));
            assert_eq!(b.hist(d, "h", HIST_MAX + 1).err(), Some(Error::BadSize));
            let mut cur = d;
            let mut deepest = 1;
            while let Ok(n) = b.dir(cur, "d") {
                cur = n;
                deepest += 1;
            }
            assert_eq!(deepest, 8, "eight levels below the root");
            assert_eq!(b.dir(cur, "d").err(), Some(Error::TooDeep));
            Ok(())
        })
        .unwrap();
        // Fill the node table: the next add says so, and the nodes before it stay whole.
        let r = w.rebuild(|b| {
            for i in 0..1000 {
                b.u64(NodeId::ROOT, &format!("n{i}"), i)?;
            }
            Ok(())
        });
        assert_eq!(r.err(), Some(Error::NoSpace));
        let rd = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        let mut n = 0;
        rd.walk(&mut |_, _| n += 1).unwrap();
        assert!(n > 4, "a failed rebuild commits what it built ({n} nodes)");
        assert!(matches!(rd.read(rd.lookup("n3").unwrap().unwrap()).unwrap(), Value::U64(3)));
    }

    #[test]
    fn setters_check_the_kind_and_cut_strings_at_a_character() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        assert_eq!(w.set_i64(ids.ready, 1).err(), Some(Error::WrongKind));
        assert_eq!(w.set_u64(ids.name, 1).err(), Some(Error::WrongKind));
        assert_eq!(w.set_hist(ids.lat, &[0; 5]).err(), Some(Error::BadSize));
        assert_eq!(w.set_u64(NodeId(500), 1).err(), Some(Error::BadNode));
        // 16 bytes of capacity: seven two-byte characters and then one that would straddle it.
        w.set_str(ids.name, "ééééééééé").unwrap();
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        match r.read(ids.name).unwrap() {
            Value::Str(s) => assert_eq!(s.as_str(), "éééééééé", "cut at 16 bytes, on a boundary"),
            _ => panic!("kind"),
        }
        w.set_str(ids.name, "ab").unwrap();
        match r.read(ids.name).unwrap() {
            Value::Str(s) => assert_eq!(s.as_str(), "ab", "a shorter string leaves nothing of the longer one"),
            _ => panic!("kind"),
        }
    }

    /// A bytes node keeps bytes that are not text (a decision record in its
    /// wire form), cut to its capacity, and is a kind of its own: the string
    /// setter refuses it, and a reader gets `Value::Bytes`.
    ///
    /// **Canary.** Read `Kind::Bytes` back as `Value::Str` in `read_raw`: the
    /// first `match` fails.
    #[test]
    fn a_bytes_node_holds_bytes_that_are_not_text() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let mut id = None;
        w.rebuild(|b| {
            id = Some(b.bytes(NodeId::ROOT, "rec", 8, &[0xff, 0x00, 0xfe])?);
            assert_eq!(b.bytes(NodeId::ROOT, "big", STR_MAX + 1, &[]).err(), Some(Error::BadSize));
            Ok(())
        })
        .unwrap();
        let id = id.unwrap();
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        match r.read(id).unwrap() {
            Value::Bytes(b) => assert_eq!(b.as_bytes(), &[0xff, 0x00, 0xfe]),
            _ => panic!("kind"),
        }
        assert_eq!(w.set_str(id, "x").err(), Some(Error::WrongKind));
        w.set_bytes(id, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        match r.read(id).unwrap() {
            Value::Bytes(b) => assert_eq!(b.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8], "cut at its capacity"),
            _ => panic!("kind"),
        }
    }

    /// A directory's children are visited in the order they were added, each
    /// once, and a path below a node is looked up from it.
    #[test]
    fn children_and_lookup_below_a_node() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        w.rebuild(|b| {
            let d = b.dir(NodeId::ROOT, "eps")?;
            for name in ["names", "term", "log"] {
                let e = b.dir(d, name)?;
                b.u64(e, "index", name.len() as u64)?;
            }
            Ok(())
        })
        .unwrap();
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        let d = r.lookup("eps").unwrap().unwrap();
        let mut seen = Vec::new();
        r.children(d, &mut |info, _| seen.push(String::from(info.name.as_str()))).unwrap();
        assert_eq!(seen, ["names", "term", "log"]);
        let t = r.lookup_in(d, "term/index").unwrap().unwrap();
        assert!(matches!(r.read(t).unwrap(), Value::U64(4)));
        assert_eq!(r.lookup_in(d, "nope/index").unwrap(), None);
        assert_eq!(azos_inspect_lib::u64_in(&r, d, "log/index").unwrap(), Some(3));
    }

    // ── versions and classes ────────────────────────────────────────────────

    #[test]
    fn a_region_of_another_layout_version_is_refused() {
        let v = words(512);
        Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        assert!(Reader::open(Region::from_atomics(&v), Class::Public).is_ok());
        for bad in [0u32, FORMAT_VERSION + 1, u32::MAX] {
            v[1].store(bad as u64, Relaxed);
            assert_eq!(
                Reader::open(Region::from_atomics(&v), Class::Public).err(),
                Some(Error::VersionMismatch { found: bad }),
                "version {bad}"
            );
        }
        v[1].store(FORMAT_VERSION as u64, Relaxed);
        v[0].store(0x1234, Relaxed);
        assert_eq!(Reader::open(Region::from_atomics(&v), Class::Public).err(), Some(Error::BadMagic));
    }

    #[test]
    fn a_header_that_contradicts_itself_is_corrupt_not_trusted() {
        let v = words(512);
        Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let good = v[3].load(Relaxed);
        v[3].store(good & !0xffff_ffff | 1 << 30, Relaxed); // claims 1 GiB in a 4 KiB region
        assert_eq!(Reader::open(Region::from_atomics(&v), Class::Public).err(), Some(Error::Corrupt));
        v[3].store(good, Relaxed);
        v[1].store(FORMAT_VERSION as u64 | 7 << 32, Relaxed); // no such class
        assert_eq!(Reader::open(Region::from_atomics(&v), Class::Public).err(), Some(Error::Corrupt));
    }

    #[test]
    fn the_admin_region_is_not_readable_as_a_public_one() {
        let (p, a) = (words(1024), words(1024));
        let pw = Writer::init(Region::from_atomics(&p), Class::Public).unwrap();
        let aw = Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
        pw.rebuild(|b| {
            let s = b.dir(NodeId::ROOT, "sched")?;
            b.u64(s, "ready", 5)?;
            Ok(())
        })
        .unwrap();
        aw.rebuild(|b| {
            let t = b.dir(NodeId::ROOT, "tasks")?;
            let one = b.dir(t, "17")?;
            b.string(one, "name", 16, "payroll-daemon")?;
            Ok(())
        })
        .unwrap();

        // The marker is in the admin region and nowhere in the public one: the scan can fail.
        assert!(contains(&bytes_of(&a), "payroll-daemon") && contains(&bytes_of(&a), "tasks"));
        assert!(!contains(&bytes_of(&p), "payroll-daemon"), "no admin byte in the public region");
        assert!(!contains(&bytes_of(&p), "tasks"));

        // Each region opens as its own class only.
        assert_eq!(
            Reader::open(Region::from_atomics(&a), Class::Public).err(),
            Some(Error::WrongClass { found: 1 })
        );
        assert_eq!(
            Reader::open(Region::from_atomics(&p), Class::Admin).err(),
            Some(Error::WrongClass { found: 0 })
        );
        assert!(Inspector::new(Region::from_atomics(&a), None).is_err(), "the admin region as the public one");
        assert!(
            Inspector::new(Region::from_atomics(&p), Some(Region::from_atomics(&p))).is_err(),
            "the public region as the admin one"
        );

        // A task with only the public MemObj cannot reach the admin paths.
        let mut public_only = Inspector::new(Region::from_atomics(&p), None).unwrap();
        assert!(!public_only.has_admin());
        assert!(public_only.read("tasks/17/name").unwrap().is_none());
        assert_eq!(public_only.read_u64("sched/ready").unwrap(), Some(5));
        let mut text = String::new();
        public_only.render(&mut text).unwrap();
        assert!(!text.contains("payroll") && !text.contains("admin"));

        // The warrant holder sees both as one namespace.
        let mut both = Inspector::new(Region::from_atomics(&p), Some(Region::from_atomics(&a))).unwrap();
        match both.read("tasks/17/name").unwrap() {
            Some((Source::Admin, Value::Str(s))) => assert_eq!(s.as_str(), "payroll-daemon"),
            _ => panic!("the admin node"),
        }
        assert!(matches!(both.read("sched/ready").unwrap(), Some((Source::Public, Value::U64(5)))));
    }

    // ── the seqlocks ────────────────────────────────────────────────────────

    #[test]
    fn a_node_mid_write_is_never_returned() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        w.set_hist(ids.lat, &[9, 9, 9, 9]).unwrap();
        let lat = ids.lat.0 as usize;
        let val_off = (v[node_word(lat, 1)].load(Relaxed) >> 32) as usize;
        let data = HEADER_WORDS + (v[3].load(Relaxed) >> 32) as usize * NODE_WORDS + val_off;
        // A writer, stopped half way: the seq is odd and two of four buckets are new.
        let seq = &v[node_word(lat, 0)];
        let s = seq.load(Relaxed);
        seq.store(s + 1, Relaxed);
        v[data].store(1, Relaxed);
        v[data + 1].store(1, Relaxed);
        // Canary: the words themselves are torn, so only the seq stands between the reader and them.
        let raw: Vec<u64> = (0..4).map(|i| v[data + i].load(Relaxed)).collect();
        assert_eq!(raw, [1, 1, 9, 9], "the state a reader without the seq would have seen");
        assert_eq!(r.read(ids.lat).err(), Some(Error::Contended));
        // The writer finishes.
        v[data + 2].store(1, Relaxed);
        v[data + 3].store(1, Relaxed);
        seq.store(s + 2, Release);
        match r.read(ids.lat).unwrap() {
            Value::Hist(h) => assert_eq!(h.buckets(), &[1, 1, 1, 1]),
            _ => panic!("kind"),
        }
    }

    #[test]
    fn readers_never_see_a_torn_value_under_a_concurrent_writer() {
        let v: Arc<Vec<AtomicU64>> = Arc::new(words(2048));
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        // A full-width histogram and a string: the widest values, the widest tear window.
        let (lat, name) = {
            let mut ids = None;
            w.rebuild(|b| {
                ids = Some((b.hist(NodeId::ROOT, "lat", HIST_MAX)?, b.string(NodeId::ROOT, "name", STR_MAX, "a")?));
                Ok(())
            })
            .unwrap();
            ids.unwrap()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let (v, stop) = (v.clone(), stop.clone());
                std::thread::spawn(move || {
                    let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
                    let (mut ok, mut distinct, mut last) = (0u64, 0u64, u64::MAX);
                    while !stop.load(Relaxed) {
                        match r.read(lat) {
                            Ok(Value::Hist(h)) => {
                                let b = h.buckets();
                                assert_eq!(b.len(), HIST_MAX);
                                assert!(b.iter().all(|x| *x == b[0]), "torn histogram {b:?}");
                                ok += 1;
                                if b[0] != last {
                                    distinct += 1;
                                    last = b[0];
                                }
                            }
                            Ok(_) => panic!("kind"),
                            Err(Error::Contended) => {}
                            Err(e) => panic!("{e:?}"),
                        }
                        match r.read(name) {
                            Ok(Value::Str(s)) => {
                                let t = s.as_str();
                                assert!(t.bytes().all(|c| c == t.as_bytes()[0]), "torn string {t:?}");
                            }
                            Ok(_) => panic!("kind"),
                            Err(Error::Contended) => {}
                            Err(e) => panic!("{e:?}"),
                        }
                    }
                    (ok, distinct)
                })
            })
            .collect();
        for i in 1..=300_000u64 {
            w.set_hist(lat, &[i; HIST_MAX]).unwrap();
            w.set_str(name, &((b'a' + (i % 26) as u8) as char).to_string().repeat(1 + (i % 120) as usize)).unwrap();
        }
        stop.store(true, Relaxed);
        for h in readers {
            let (ok, distinct) = h.join().unwrap();
            assert!(ok > 0, "a reader that never read proves nothing");
            assert!(distinct > 1, "the reader saw the writer's progress");
        }
    }

    #[test]
    fn two_writers_of_one_node_do_not_interleave() {
        let v = words(2048);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let reader = s.spawn(|| {
                let mut ok = 0u64;
                // Keep reading once the writers rest until one read has been checked: two
                // writers can hold the node mid-write for the whole of a loaded run.
                while !stop.load(Relaxed) || ok == 0 {
                    if let Ok(Value::Hist(h)) = r.read(ids.lat) {
                        assert!(h.buckets().iter().all(|x| *x == h.buckets()[0]), "interleaved {:?}", h.buckets());
                        ok += 1;
                    }
                }
                ok
            });
            let other = s.spawn(|| {
                for i in 0..100_000u64 {
                    let _ = w.set_hist(ids.lat, &[i | 1 << 63; 4]);
                }
            });
            for i in 0..100_000u64 {
                let _ = w.set_hist(ids.lat, &[i; 4]);
            }
            other.join().unwrap();
            stop.store(true, Relaxed);
            assert!(reader.join().unwrap() > 0);
        });
    }

    #[test]
    fn a_rebuild_invalidates_ids_and_the_reader_refreshes() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        let ids = build_sample(&w);
        let mut r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        let e0 = r.epoch();
        assert!(r.read(ids.ready).is_ok());
        w.rebuild(|b| {
            b.u64(NodeId::ROOT, "only", 1)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(r.read(ids.ready).err(), Some(Error::Restructured));
        assert_eq!(r.lookup("sched").err(), Some(Error::Restructured));
        r.refresh().unwrap();
        assert_eq!(r.epoch(), e0 + 2);
        assert_eq!(r.lookup("sched").unwrap(), None, "the old shape is gone");
        let only = r.lookup("only").unwrap().unwrap();
        assert!(matches!(r.read(only).unwrap(), Value::U64(1)));
    }

    #[test]
    fn a_rebuild_in_progress_is_contended_and_does_not_nest() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        build_sample(&w);
        let r = Reader::open(Region::from_atomics(&v), Class::Public).unwrap();
        let mut nested = None;
        w.rebuild(|_| {
            nested = Some(w.rebuild(|_| Ok(())).err());
            assert_eq!(Reader::open(Region::from_atomics(&v), Class::Public).err(), Some(Error::Contended));
            assert_eq!(r.lookup("sched").err(), Some(Error::Restructured));
            Ok(())
        })
        .unwrap();
        assert_eq!(nested, Some(Some(Error::Contended)));
        assert!(Reader::open(Region::from_atomics(&v), Class::Public).is_ok(), "stable again");
    }

    #[test]
    fn a_walk_that_succeeds_is_one_shape_under_concurrent_rebuilds() {
        let v: Arc<Vec<AtomicU64>> = Arc::new(words(2048));
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        // Generation g has ten leaves "g{g}_0".."g{g}_9", all holding g.
        let build = |g: u64| {
            w.rebuild(|b| {
                for i in 0..10 {
                    b.u64(NodeId::ROOT, &format!("g{g}_{i}"), g)?;
                }
                Ok(())
            })
            .unwrap()
        };
        build(0);
        let stop = Arc::new(AtomicBool::new(false));
        let walked = Arc::new(AtomicU64::new(0));
        let met = Arc::new(AtomicU64::new(0));
        let reader = {
            let (v, stop, walked, met) = (v.clone(), stop.clone(), walked.clone(), met.clone());
            std::thread::spawn(move || {
                // The first open can land in a rebuild: that is Contended, try again.
                let mut r = loop {
                    match Reader::open(Region::from_atomics(&v), Class::Public) {
                        Err(Error::Contended) => continue,
                        other => break other.unwrap(),
                    }
                };
                let (mut ok, mut moved) = (0u64, 0u64);
                while !stop.load(Relaxed) {
                    let mut vals = Vec::new();
                    match r.walk(&mut |i, val| {
                        if let Value::U64(x) = val {
                            vals.push((i.name.as_str().to_string(), *x));
                        }
                    }) {
                        Ok(()) => {
                            assert_eq!(vals.len(), 10, "{vals:?}");
                            let g = vals[0].1;
                            for (i, (n, x)) in vals.iter().enumerate() {
                                assert_eq!((n.as_str(), *x), (format!("g{g}_{i}").as_str(), g), "mixed shapes: {vals:?}");
                            }
                            ok += 1;
                            walked.fetch_add(1, Relaxed);
                        }
                        Err(Error::Restructured) | Err(Error::Contended) => {
                            moved += 1;
                            met.fetch_add(1, Relaxed);
                            let _ = r.refresh();
                        }
                        Err(e) => panic!("{e:?}"),
                    }
                }
                (ok, moved)
            })
        };
        // Rebuild until the reader has completed 200 walks (a writer that never
        // let the epoch rest would starve it) and has met a rebuild at least once
        // (a loaded machine can run the reader only between bursts).
        let mut g = 0u64;
        while (walked.load(Relaxed) < 200 || met.load(Relaxed) == 0) && g < 200_000 {
            g += 1;
            // Bursts of back-to-back rebuilds, which overlap a walk, and a rest after each.
            if g % 20 == 0 {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
            build(g);
        }
        stop.store(true, Relaxed);
        let (ok, moved) = reader.join().unwrap();
        assert!(ok >= 200, "the reader walked {ok} times");
        assert!(moved > 0, "and met a rebuild {moved} times: otherwise the epoch check was never exercised");
    }

    // ── the library ─────────────────────────────────────────────────────────

    #[test]
    fn render_prints_the_tree_and_the_admin_part_after_a_marker() {
        let (p, a) = (words(1024), words(1024));
        let pw = Writer::init(Region::from_atomics(&p), Class::Public).unwrap();
        let aw = Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
        build_sample(&pw);
        aw.rebuild(|b| {
            let t = b.dir(NodeId::ROOT, "tasks")?;
            b.u64(t, "count", 3)?;
            Ok(())
        })
        .unwrap();
        let mut ins = Inspector::new(Region::from_atomics(&p), Some(Region::from_atomics(&a))).unwrap();
        let mut out = String::new();
        ins.render(&mut out).unwrap();
        assert_eq!(
            out,
            "sched/\n  ready = 7\n  delta = -3\n  name = \"legacy\"\n  lat = [0, 0, 0, 0]\nmem/\n# admin\ntasks/\n  count = 3\n"
        );
        struct Full;
        impl std::fmt::Write for Full {
            fn write_str(&mut self, _: &str) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }
        assert_eq!(ins.render(&mut Full).err(), Some(RenderError::Write));
    }

    #[test]
    fn the_library_reads_through_a_rebuild() {
        let v = words(1024);
        let w = Writer::init(Region::from_atomics(&v), Class::Public).unwrap();
        build_sample(&w);
        let mut ins = Inspector::new(Region::from_atomics(&v), None).unwrap();
        assert_eq!(ins.read_u64("sched/ready").unwrap(), Some(7));
        w.rebuild(|b| {
            let s = b.dir(NodeId::ROOT, "sched")?;
            b.u64(s, "pad", 0)?;
            b.u64(s, "ready", 8)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(ins.read_u64("sched/ready").unwrap(), Some(8), "the stale view is refreshed and the read repeated");
        assert_eq!(ins.read_u64("sched/name").unwrap(), None);
    }
}
