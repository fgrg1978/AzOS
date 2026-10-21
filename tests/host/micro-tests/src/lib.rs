// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the micro kernel (`micro/`).
//!
//! The kernel's decisions are pure over [`Hw`](azos_micro::kernel::Hw), so
//! the suite runs the real [`Kernel`](azos_micro::kernel::Kernel) over a fake
//! machine: the topology the QEMU image ships is parsed and admitted, tasks
//! are booted, and syscalls are issued as the running task would issue them
//! (registers in its frame, then `syscall()`). What the host cannot see is
//! the CSRs and the trap assembly; those are the QEMU gate's (open_issues).
//!
//! The host is 64-bit and the micro kernel's words are 32 bits, so a test
//! never stands in for a width: layouts are checked by the `const`
//! assertions the rv32 build evaluates (`sc.rs`, `captable.rs`,
//! `kernel.rs`), and here by summing field widths (`abi-tests` does the
//! same for the wire structs).

#![allow(clippy::all)]

#[cfg(test)]
mod pmp {
    use azos_micro::pmp_core::*;

    const BASE: usize = 0x8000_0000;

    #[test]
    fn a_power_of_two_block_on_its_alignment_is_one_napot_entry() {
        let c = region(BASE, 4096, R | W, 2).unwrap();
        assert_eq!(c.count(), 1);
        // pmpaddr = base >> 2 with the low bits set to (size / 8 - 1):
        // the spec's "yyyy...y0111" form for 4 KiB is 9 trailing ones.
        assert_eq!(c.entries()[0], PmpEntry { cfg: 0x18 | R | W, addr: (BASE >> 2) | 0x1ff });
    }

    #[test]
    fn the_smallest_napot_block_is_eight_bytes_and_four_is_na4() {
        let c = region(BASE, 8, R, 2).unwrap();
        assert_eq!(c.entries()[0], PmpEntry { cfg: 0x18 | R, addr: BASE >> 2 });
        let c = region(BASE, 4, R | X, 2).unwrap();
        assert_eq!(c.entries()[0], PmpEntry { cfg: 0x10 | R | X, addr: BASE >> 2 });
        // A coarser PMP has no NA4: four bytes cannot be expressed at all.
        assert!(region(BASE, 4, R, 3).is_none());
    }

    #[test]
    fn any_other_range_is_a_tor_pair_base_first() {
        let c = region(BASE + 0x100, 0x300, R | W | X, 2).unwrap();
        assert_eq!(c.count(), 2);
        assert_eq!(c.entries()[0], PmpEntry { cfg: 0, addr: (BASE + 0x100) >> 2 });
        assert_eq!(c.entries()[1], PmpEntry { cfg: 0x08 | R | W | X, addr: (BASE + 0x400) >> 2 });
        // A power of two NOT on its alignment is a pair too.
        let c = region(BASE + 0x1000, 0x2000, R, 2).unwrap();
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn what_the_hart_cannot_express_exactly_is_refused() {
        assert!(region(BASE, 0, R, 2).is_none(), "empty");
        assert!(region(BASE + 1, 8, R, 2).is_none(), "unaligned base");
        assert!(region(BASE, 6, R, 2).is_none(), "size not a multiple of the grain");
        assert!(region(usize::MAX - 3, 8, R, 2).is_none(), "wraps the address space");
        // Granularity 8 (log2 3): a 12-byte range is not a multiple.
        assert!(region(BASE, 12, R, 3).is_none());
        assert!(region(BASE, 16, R, 3).is_some());
    }

    #[test]
    fn no_entry_sets_the_lock_bit() {
        for (base, size) in [(BASE, 4096), (BASE + 4, 12), (BASE, 4)] {
            for e in region(base, size, R | W | X, 2).unwrap().entries() {
                assert_eq!(e.cfg & 0x80, 0, "an unlocked entry does not constrain M-mode");
            }
        }
    }

    #[test]
    fn cfg_bytes_pack_by_the_width_of_the_csr() {
        let cfgs: Vec<u8> = (1..=16).collect();
        // rv32: four entries a CSR, pmpcfg0 = entries 0..3, little-endian.
        assert_eq!(pack_cfg(&cfgs, 0, 4), 0x0403_0201);
        assert_eq!(pack_cfg(&cfgs, 3, 4), 0x100f_0e0d);
        // rv64: eight a CSR.
        assert_eq!(pack_cfg(&cfgs, 0, 8) as u64, 0x0807_0605_0403_0201);
        assert_eq!(pack_cfg(&cfgs, 1, 8) as u64, 0x100f_0e0d_0c0b_0a09);
        assert_eq!(cfg_words(16, 4), 4);
        assert_eq!(cfg_words(64, 4), 16);
        assert_eq!(cfg_words(16, 8), 2);
        // Past the end the bytes are zero (entries switched off).
        assert_eq!(pack_cfg(&cfgs[..5], 1, 4), 0x0000_0005);
    }
}

#[cfg(test)]
mod domains {
    use azos_micro::domain::*;
    use azos_micro::pmp_core::{PmpEntry, R, W, X};

    fn anon(base: usize, size: usize) -> Region {
        Region { base, size, perm: R | W, kind: Kind::Anon }
    }

    #[test]
    fn a_range_is_admitted_only_inside_one_region_with_the_rights() {
        let mut d = Domain::new(8, 2);
        d.add(anon(0x1000, 0x1000)).unwrap();
        d.add(Region { base: 0x4000, size: 0x100, perm: R, kind: Kind::Phys }).unwrap();
        assert!(d.admits(0x1000, 0x1000, R | W));
        assert!(d.admits(0x1ffc, 4, W));
        assert!(!d.admits(0x1ffd, 4, W), "one byte past the end");
        assert!(!d.admits(0xfff, 2, R), "one byte before the start");
        assert!(d.admits(0x4000, 0x100, R));
        assert!(!d.admits(0x4000, 4, W), "the window is read-only");
        assert!(!d.admits(0x2000, 1, R), "between regions");
        assert!(!d.admits(usize::MAX, 2, R), "a wrapping range");
        assert!(!d.admits(0x1000, usize::MAX, R), "a length that wraps");
    }

    #[test]
    fn two_adjacent_regions_are_not_one_for_a_copy_across_the_seam() {
        let mut d = Domain::new(8, 2);
        d.add(anon(0x1000, 0x1000)).unwrap();
        d.add(anon(0x2000, 0x1000)).unwrap();
        assert!(d.admits(0x1ff0, 0x10, R));
        assert!(!d.admits(0x1ff0, 0x20, R), "neither region covers the whole range");
    }

    #[test]
    fn the_pmp_budget_is_checked_when_a_region_is_added_and_a_refusal_changes_nothing() {
        let mut d = Domain::new(3, 2);
        d.add(anon(0x1000, 0x300)).unwrap(); // TOR pair: 2 entries
        assert_eq!(d.entries_used(), 2);
        d.add(anon(0x8000_0000, 4096)).unwrap(); // NAPOT: 1
        assert_eq!(d.entries_used(), 3);
        assert_eq!(d.add(anon(0x9000_0000, 4096)), Err(DomainError::NoEntries));
        assert_eq!(d.entries_used(), 3);
        assert_eq!(d.regions().count(), 2);
        assert_eq!(Domain::new(8, 2).add(anon(0x1001, 8)), Err(DomainError::Unencodable));
    }

    #[test]
    fn encode_lists_the_entries_of_every_region_in_order() {
        let mut d = Domain::new(8, 2);
        d.add(anon(0x1000, 0x300)).unwrap();
        d.add(Region { base: 0x8000_0000, size: 4096, perm: R | X, kind: Kind::Contig }).unwrap();
        let mut out = [PmpEntry::OFF; 8];
        assert_eq!(d.encode(&mut out), 3);
        assert_eq!(out[0].addr, 0x1000 >> 2);
        assert_eq!(out[1].addr, 0x1300 >> 2);
        assert_eq!(out[2].cfg & 0x18, 0x18, "NAPOT");
    }

    #[test]
    fn the_pool_aligns_and_runs_out_without_consuming() {
        let mut p = Pool::new(0x1004, 0x3000);
        assert_eq!(p.alloc(0x100, 0x1000), Some(0x2000));
        assert_eq!(p.alloc(0x10, 4), Some(0x2100));
        assert_eq!(p.left(), 0x3000 - 0x2110);
        assert_eq!(p.alloc(0x2000, 4), None);
        assert_eq!(p.left(), 0x3000 - 0x2110, "a refusal consumes nothing");
        assert_eq!(p.alloc(usize::MAX, 4), None);
    }

    #[test]
    fn a_contiguous_block_is_a_power_of_two() {
        assert_eq!(contig_size(4, 2), 4096);
        assert_eq!(contig_size(5, 2), 8192);
        assert_eq!(contig_size(0, 2), 4);
        assert_eq!(round_up(5, 2), 8);
        assert_eq!(round_up(8, 2), 8);
        assert_eq!(round_up(1, 4), 16);
    }
}

#[cfg(test)]
mod grants {
    use azos_micro::grant::Grants;

    #[test]
    fn the_region_is_split_and_grants_come_from_the_top() {
        let mut g = Grants::split(0x1000, 0x1000, 0x100, 0x200, 2).unwrap();
        assert_eq!(g.app(), (0x1000, 0xf00));
        assert_eq!(g.kernel(), (0x1f00, 0x100));
        assert_eq!(g.alloc(0x40, 8), Some(0x1fc0));
        assert_eq!(g.alloc(0x10, 16), Some(0x1fb0));
        assert_eq!(g.left(), 0x1fb0 - 0x1f00);
    }

    #[test]
    fn a_grant_never_reaches_the_tasks_part() {
        let mut g = Grants::split(0x1000, 0x1000, 0x40, 0x200, 2).unwrap();
        assert_eq!(g.alloc(0x41, 1), None, "one byte more than the kernel's part");
        assert_eq!(g.left(), 0x40, "a refusal consumes nothing");
        assert!(g.alloc(0x40, 1).is_some());
        assert_eq!(g.alloc(1, 1), None);
        // An alignment that rounds the address below the boundary is refused too.
        let mut g = Grants::split(0x1000, 0x1000, 0x40, 0x200, 2).unwrap();
        assert_eq!(g.alloc(0x30, 0x40), Some(0x1fc0));
        assert_eq!(g.alloc(0x10, 0x100), None);
    }

    #[test]
    fn the_split_leaves_the_task_its_stack() {
        assert!(Grants::split(0x1000, 0x1000, 0xf00, 0x200, 2).is_none());
        assert!(Grants::split(0x1000, 0x1000, 0x1001, 0, 2).is_none());
        assert!(Grants::split(0x1000, 0x1000, 0xe00, 0x200, 2).is_some());
        // The reserve is rounded up to the granularity so the task's part
        // ends where a PMP entry can end.
        let g = Grants::split(0x1000, 0x1000, 0x41, 0, 4).unwrap();
        assert_eq!(g.kernel().1, 0x50);
    }

    #[test]
    fn need_counts_every_alignment_pad() {
        let sizes = [(256, 8), (6, 4)];
        let need = Grants::need(&sizes);
        assert_eq!(need, 256 + 7 + 6 + 3);
        let mut g = Grants::split(0x1001 & !3, 0x1000, need, 0, 2).unwrap();
        for (s, a) in sizes {
            assert!(g.alloc(s, a).is_some());
        }
    }
}

#[cfg(test)]
mod captable {
    use azos_abi::cap::{ty, CapHandle, CapPerms};
    use azos_micro::captable::*;

    fn table(n: usize) -> Vec<CapSlot> {
        vec![CapSlot::EMPTY; n]
    }

    #[test]
    fn install_resolve_and_the_order_of_the_checks() {
        let mut s = table(4);
        let mut t = CapTable::new(&mut s);
        let h = t.install(ty::ENDPOINT, CapPerms::RW, 7).unwrap();
        assert_eq!(t.resolve(h, ty::ENDPOINT, CapPerms::WRITE), Ok(7));
        assert_eq!(t.resolve(h, ty::ENDPOINT, CapPerms::RW), Ok(7));
        assert_eq!(t.resolve(h, ty::SHM, CapPerms::READ), Err(CapError::WrongKind));
        assert_eq!(t.resolve(h, ty::ENDPOINT, CapPerms::RW_DELEGATE), Err(CapError::MissingPerms));
        // Stale beats everything: a wrong generation says nothing about kind.
        let forged = CapHandle::pack(ty::SHM, CapPerms::ALL, 99, h.slot());
        assert_eq!(t.resolve(forged, ty::ENDPOINT, CapPerms::NONE), Err(CapError::Stale));
        assert_eq!(t.resolve(CapHandle::from_raw(0), ty::ENDPOINT, CapPerms::NONE), Err(CapError::Stale));
        let far = CapHandle::pack(ty::ENDPOINT, CapPerms::RW, 1, 300);
        assert_eq!(t.resolve(far, ty::ENDPOINT, CapPerms::NONE), Err(CapError::Stale), "slot past the table");
    }

    #[test]
    fn a_closed_handle_goes_stale_and_a_regrant_does_not_revive_it() {
        let mut s = table(2);
        let mut t = CapTable::new(&mut s);
        let h1 = t.install(ty::IRQ, CapPerms::RW, 3).unwrap();
        assert_eq!(t.close(h1), Ok((ty::IRQ, CapPerms::RW, 3)));
        assert_eq!(t.close(h1), Err(CapError::Stale), "closing twice");
        let h2 = t.install(ty::IRQ, CapPerms::RW, 3).unwrap();
        assert_eq!(h2.slot(), h1.slot(), "the freed slot is reused");
        assert_eq!(h2.generation(), h1.generation() + 1);
        assert_eq!(t.resolve(h1, ty::IRQ, CapPerms::NONE), Err(CapError::Stale));
        assert_eq!(t.resolve(h2, ty::IRQ, CapPerms::NONE), Ok(3));
    }

    #[test]
    fn a_slot_whose_generation_ran_out_is_retired_never_reissued() {
        let mut s = table(1);
        let mut t = CapTable::new(&mut s);
        let mut last = None;
        for _ in 0..CapHandle::MAX_GENERATION {
            let h = t.install(ty::MMIO, CapPerms::READ, 0).unwrap();
            assert!(last.map_or(true, |l: CapHandle| h.generation() == l.generation() + 1));
            t.close(h).unwrap();
            last = Some(h);
        }
        assert_eq!(last.unwrap().generation(), CapHandle::MAX_GENERATION);
        assert!(t.install(ty::MMIO, CapPerms::READ, 0).is_none(), "retired, not wrapped");
    }

    #[test]
    fn lookup_finds_what_the_table_holds_and_only_that() {
        let mut s = table(4);
        let mut t = CapTable::new(&mut s);
        let a = t.install(ty::ENDPOINT, CapPerms::READ, 1).unwrap();
        let b = t.install(ty::ENDPOINT, CapPerms::WRITE, 2).unwrap();
        assert_eq!(t.lookup(ty::ENDPOINT, 1), Some(a));
        assert_eq!(t.lookup(ty::ENDPOINT, 2), Some(b));
        assert_eq!(t.lookup(ty::ENDPOINT, 3), None);
        assert_eq!(t.lookup(ty::SHM, 1), None);
        t.close(a).unwrap();
        assert_eq!(t.lookup(ty::ENDPOINT, 1), None);
        assert_eq!(t.live(), 1);
    }

    #[test]
    fn a_full_table_refuses_and_clear_all_keeps_generations() {
        let mut s = table(2);
        let mut t = CapTable::new(&mut s);
        let h0 = t.install(ty::MMIO, CapPerms::READ, 0).unwrap();
        t.install(ty::MMIO, CapPerms::READ, 1).unwrap();
        assert!(t.install(ty::MMIO, CapPerms::READ, 2).is_none());
        t.clear_all();
        assert_eq!(t.live(), 0);
        assert_eq!(t.resolve(h0, ty::MMIO, CapPerms::NONE), Err(CapError::Stale));
        let again = t.install(ty::MMIO, CapPerms::READ, 0).unwrap();
        assert_eq!(again.generation(), h0.generation() + 1);
    }

    #[test]
    fn the_slot_is_128_bits_with_the_main_kernels_hot_word() {
        assert_eq!(core::mem::size_of::<CapSlot>(), 16);
        let mut s = table(1);
        let mut t = CapTable::new(&mut s);
        t.install(ty::ENDPOINT, CapPerms::RW, 0x1234).unwrap();
        assert_eq!(s[0].hot, azos_abi::cap::slot_word::encode(ty::ENDPOINT, CapPerms::RW, 1, 0x1234));
        assert_eq!(s[0].ext, 0);
    }
}

#[cfg(test)]
mod ceilings {
    use azos_micro::ceiling::*;
    use azos_micro::pi_attr::PiAttr;
    use azos_micro::sc::Class;

    fn rt(p: u8) -> PiAttr {
        base_attr(Class::Rt, p)
    }

    #[test]
    fn the_ceiling_is_the_most_urgent_of_server_and_clients() {
        assert_eq!(endpoint_ceiling(rt(20), [rt(12), rt(15)]), rt(12));
        assert_eq!(endpoint_ceiling(rt(8), [rt(12)]), rt(8), "a server already above its clients");
        assert_eq!(endpoint_ceiling(rt(20), []), rt(20));
        assert_eq!(endpoint_ceiling(base_attr(Class::Idle, 31), [rt(30)]), rt(30));
    }

    #[test]
    fn a_deadline_client_raises_the_ceiling_to_the_top_real_time_level() {
        let dl = base_attr(Class::Dl, 0);
        assert_eq!(endpoint_ceiling(rt(20), [dl, rt(12)]), rt(0));
        assert_eq!(endpoint_ceiling(base_attr(Class::Idle, 31), [dl]), rt(0));
    }

    #[test]
    fn effective_takes_the_ceiling_only_while_serving_and_never_for_a_reservation() {
        assert_eq!(effective(rt(20), None), rt(20));
        assert_eq!(effective(rt(20), Some(rt(12))), rt(12));
        assert_eq!(effective(rt(8), Some(rt(12))), rt(8), "a ceiling below the base changes nothing");
        let dl = base_attr(Class::Dl, 0);
        assert_eq!(effective(dl, Some(rt(0))), dl);
    }
}

#[cfg(test)]
mod dispatch {
    use azos_micro::rt_core::Cbs;
    use azos_micro::sc::Class;
    use azos_micro::sched::*;

    fn ent(class: Class, prio: u32) -> Entity {
        let mut e = Entity::unborn();
        e.sc.set_class(class, prio);
        e.runnable = true;
        e
    }

    #[test]
    fn deadline_beats_real_time_beats_idle() {
        let mut v = vec![ent(Class::Idle, 31), ent(Class::Rt, 3), ent(Class::Dl, 0)];
        v[2].cbs = Cbs::new(100, 1000, 1000, true, 0, 0);
        assert_eq!(pick(&mut v, None, 0), Some(2));
        v[2].runnable = false;
        assert_eq!(pick(&mut v, None, 0), Some(1));
        v[1].runnable = false;
        assert_eq!(pick(&mut v, None, 0), Some(0));
        v[0].runnable = false;
        assert_eq!(pick(&mut v, None, 0), None);
    }

    #[test]
    fn real_time_is_fixed_priority_lower_number_first() {
        let mut v = vec![ent(Class::Rt, 12), ent(Class::Rt, 8), ent(Class::Rt, 20)];
        assert_eq!(pick(&mut v, None, 0), Some(1));
    }

    #[test]
    fn peers_of_one_level_take_turns_and_the_running_one_keeps_its_slice() {
        let mut v = vec![ent(Class::Rt, 10), ent(Class::Rt, 10)];
        v[0].dispatched(1, 3);
        v[1].dispatched(2, 0);
        // 0 ran longest ago and is the pick with no one running.
        assert_eq!(pick(&mut v, None, 0), Some(0));
        // 1 is running with slice left and 0 is a peer that ran longer ago:
        // 1 keeps the processor.
        v[1].slice_left = 2;
        assert_eq!(pick(&mut v, Some(1), 0), Some(1));
        // Its slice runs out: stamped newest, 0 goes.
        slice_tick(&mut v[1], 10);
        slice_tick(&mut v[1], 11);
        assert_eq!(v[1].slice_left, 0);
        assert_eq!(pick(&mut v, Some(1), 0), Some(0));
    }

    #[test]
    fn a_ceiling_lifts_a_server_over_the_task_that_would_have_preempted_it() {
        use azos_micro::ceiling::base_attr;
        let mut v = vec![ent(Class::Rt, 20), ent(Class::Rt, 15)];
        assert_eq!(pick(&mut v, None, 0), Some(1), "without a boost the level-15 task runs first");
        v[0].ceiling = Some(base_attr(Class::Rt, 12));
        assert_eq!(pick(&mut v, None, 0), Some(0), "serving under a level-12 ceiling");
        v[0].ceiling = None;
        assert_eq!(pick(&mut v, None, 0), Some(1));
    }

    #[test]
    fn the_earliest_deadline_runs_and_a_hard_server_that_ran_out_waits_for_its_period() {
        let mut v = vec![ent(Class::Dl, 0), ent(Class::Dl, 0), ent(Class::Rt, 5)];
        v[0].cbs = Cbs::new(100, 1000, 1000, true, 0, 0);
        v[1].cbs = Cbs::new(100, 500, 500, true, 0, 0);
        assert_eq!(pick(&mut v, None, 0), Some(1), "released at 0: deadlines 1000 and 500");
        assert!(v[1].cbs.charge(100));
        v[1].cbs.exhaust(50);
        assert_eq!(pick(&mut v, None, 50), Some(0), "the throttled one is not eligible");
        v[0].cbs.charge(100);
        v[0].cbs.exhaust(60);
        assert_eq!(pick(&mut v, None, 60), Some(2), "both throttled: real time runs");
        // 500: the second server's deadline came, its budget is back.
        assert_eq!(pick(&mut v, None, 500), Some(1));
        assert_eq!(v[1].cbs.budget, 100);
    }

    #[test]
    fn waking_applies_the_cbs_release_rule_at_the_next_pick() {
        let mut v = vec![ent(Class::Dl, 0)];
        v[0].cbs = Cbs::new(100, 1000, 1000, true, 0, 0);
        assert_eq!(pick(&mut v, None, 0), Some(0));
        let d = v[0].cbs.deadline;
        v[0].runnable = false;
        v[0].wake();
        // Long after the deadline: a new server period, not the old one.
        assert_eq!(pick(&mut v, None, d + 5000), Some(0));
        assert_eq!(v[0].cbs.deadline, d + 5000 + 1000);
    }
}

#[cfg(test)]
mod kernel;

/// The riscv32 side of libsys (`crates/core/libsys/src/rv32.rs`), which the
/// tasks of the image call. It runs only on the target (the `ecall`s), so the
/// host holds the two properties a task cannot do without: the file keeps no
/// state, because U-mode reaches only the task's own region and a `static`
/// in it is a fault at the first access; and the crate that holds it takes
/// nothing but `azos_abi` on riscv32, because the rings and the 64-bit-word
/// API do not build for it.
#[cfg(test)]
mod libsys_rv32 {
    const SRC: &str = include_str!("../../../../crates/core/libsys/src/rv32.rs");
    const MANIFEST: &str = include_str!("../../../../crates/core/libsys/Cargo.toml");

    /// The code of `SRC`, comments and doc lines dropped.
    fn code() -> impl Iterator<Item = &'static str> {
        SRC.lines().map(str::trim_start).filter(|l| !l.starts_with("//"))
    }

    #[test]
    fn the_task_side_keeps_no_static_state() {
        for l in code() {
            assert!(
                !l.starts_with("static ") && !l.starts_with("pub static ") && !l.contains("thread_local"),
                "a task has no data window: {l}"
            );
            assert!(!l.contains("VDSO"), "this kernel maps no vDSO page: {l}");
        }
    }

    #[test]
    fn riscv32_takes_only_the_abi_crate() {
        // Everything before the target table is a dependency of every ISA.
        let every_isa = MANIFEST.split("[target.").next().unwrap();
        let deps = every_isa.split("[dependencies]").nth(1).unwrap();
        let names: Vec<&str> = deps.lines().filter_map(|l| l.split('=').next()).map(str::trim).filter(|n| !n.is_empty() && !n.starts_with('#')).collect();
        assert_eq!(names, ["azos_abi"], "the rest is behind cfg(not(target_arch = \"riscv32\"))");
    }
}
