// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_percpu` (wave 15, NRCPUS): the CPU masks, the
//! DTB-count clamp, `nr_cpu_ids`, and the per-CPU area allocator with its
//! out-of-range refusal. `NR_CPUS` is the `.config`'s (the qemu default, 64,
//! when this suite is run from a configured tree).

#[cfg(test)]
mod tests {
    use azos_percpu::*;
    use std::alloc::{alloc_zeroed, Layout};
    use std::sync::Mutex;

    /// The crate keeps its possible/online masks in statics: tests touching
    /// them run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn mask_ops_stop_at_the_ceiling() {
        let mut m = CpuMask::EMPTY;
        assert_eq!(m.weight(), 0);
        assert_eq!(m.first(), None);
        assert!(m.set(0));
        assert!(m.set(NR_CPUS - 1));
        assert!(!m.set(NR_CPUS), "a CPU at the ceiling cannot be named");
        assert!(m.test(0) && m.test(NR_CPUS - 1) && !m.test(NR_CPUS));
        assert_eq!(m.weight(), if NR_CPUS == 1 { 1 } else { 2 });
        assert_eq!(m.first(), Some(0));
        assert_eq!(m.last(), Some(NR_CPUS - 1));
        m.clear(0);
        assert!(!m.test(0));
        m.clear(NR_CPUS + 5); // no-op, no panic
        assert_eq!(m.iter().collect::<Vec<_>>(), vec![NR_CPUS - 1]);
    }

    #[test]
    fn first_n_is_a_prefix_cut_to_the_ceiling() {
        for n in [0, 1, 3, 63.min(NR_CPUS), NR_CPUS, NR_CPUS + 10] {
            let m = CpuMask::first_n(n);
            let want = n.min(NR_CPUS);
            assert_eq!(m.weight(), want, "first_n({n})");
            assert_eq!(m.iter().collect::<Vec<_>>(), (0..want).collect::<Vec<_>>());
        }
    }

    /// The logical CPU a built map gives hardware id `hw` (the installed map's
    /// `cpu_of_hw` is the production reader).
    fn cpu_of(m: &CpuMap, hw: usize) -> Option<usize> {
        (0..m.len()).find(|&c| m.hw_id(c) == Some(hw))
    }

    /// A VF2-like board: the boot hart is 4 and the DTB lists the U74s 1..4
    /// (the S7 monitor core is disabled and not listed). Logical CPU 0 is the
    /// boot hart, the others follow in DTB order. Canary: build an identity
    /// map (`hw_id(c) == c`) and every assertion below fails.
    #[test]
    fn the_boot_hart_is_cpu_0_and_the_rest_follow_the_firmware_order() {
        let m = CpuMap::build(4, &[1, 2, 3, 4]);
        assert_eq!(m.len(), 4.min(NR_CPUS));
        assert_eq!(m.hw_id(0), Some(4), "boot hart = logical CPU 0");
        if NR_CPUS >= 4 {
            assert_eq!((m.hw_id(1), m.hw_id(2), m.hw_id(3)), (Some(1), Some(2), Some(3)));
            assert_eq!(cpu_of(&m, 4), Some(0));
            assert_eq!(cpu_of(&m, 1), Some(1));
        }
        assert_eq!(cpu_of(&m, 0), None, "the S7 is no CPU of this kernel");
        assert_eq!(m.hw_id(m.len()), None);
        assert!(m.boot_listed());
    }

    /// A K1-like board numbers its harts from 0 and boots on 0: identity.
    #[test]
    fn a_dense_board_booting_on_hart_0_is_the_identity() {
        let ids: Vec<usize> = (0..8.min(NR_CPUS)).collect();
        let m = CpuMap::build(0, &ids);
        for c in 0..ids.len() {
            assert_eq!((m.hw_id(c), cpu_of(&m, c)), (Some(c), Some(c)));
        }
    }

    /// Sparse and out of order: hart ids 0, 8, 16, 24 with the boot on 16.
    #[test]
    fn a_sparse_board_gets_dense_logical_ids() {
        let m = CpuMap::build(16, &[0, 8, 16, 24]);
        assert_eq!(m.len(), 4.min(NR_CPUS));
        assert_eq!(m.hw_id(0), Some(16));
        if NR_CPUS >= 4 {
            assert_eq!((m.hw_id(1), m.hw_id(2), m.hw_id(3)), (Some(0), Some(8), Some(24)));
            assert_eq!(cpu_of(&m, 24), Some(3));
        }
        assert_eq!(cpu_of(&m, 1), None, "a hole in the hart ids is no CPU");
    }

    /// A firmware table that forgot the boot CPU (or was cut before it): the
    /// boot CPU is still logical 0 and is not counted twice when listed.
    #[test]
    fn the_boot_cpu_is_cpu_0_even_when_the_table_leaves_it_out() {
        let m = CpuMap::build(7, &[1, 2]);
        assert!(!m.boot_listed());
        assert_eq!(m.hw_id(0), Some(7));
        assert_eq!(m.len(), 3.min(NR_CPUS));
        assert_eq!(cpu_of(&m, 7), Some(0));
        let none = CpuMap::build(5, &[]);
        assert_eq!((none.len(), none.hw_id(0)), (1, Some(5)), "no table: the boot CPU alone");
        let twice = CpuMap::build(0, &[0, 1, 1, 0, 2]);
        assert_eq!(twice.len(), 3.min(NR_CPUS), "a CPU named twice is one CPU");
    }

    /// More firmware CPUs than the ceiling: the map stops at it; the boot CPU
    /// keeps its place whatever the order.
    #[test]
    fn a_table_past_the_ceiling_is_cut() {
        let ids: Vec<usize> = (0..NR_CPUS + 3).map(|i| 100 + i).collect();
        let m = CpuMap::build(100 + NR_CPUS + 2, &ids);
        assert_eq!(m.len(), NR_CPUS);
        assert!(cpu_of(&m, 100 + NR_CPUS + 1).is_none(), "the CPU past the ceiling has no id");
        assert_eq!(m.hw_id(0), Some(100 + NR_CPUS + 2), "the boot CPU is never the one cut");
        assert!(m.boot_listed());
    }

    /// The installed map (what the SBI, PLIC and IPI paths read) answers like
    /// the one built, and an empty one answers nothing.
    #[test]
    fn the_installed_map_translates_both_ways() {
        let _g = SERIAL.lock().unwrap();
        install_map(&CpuMap::EMPTY);
        assert_eq!((hw_id(0), cpu_of_hw(0)), (None, None));
        install_map(&CpuMap::build(4, &[1, 2, 3, 4]));
        assert_eq!(hw_id(0), Some(4));
        assert_eq!(cpu_of_hw(4), Some(0));
        assert_eq!(cpu_of_hw(0), None);
        if NR_CPUS >= 4 {
            assert_eq!(hw_id(3), Some(3));
            assert_eq!(cpu_of_hw(2), Some(2));
        }
        assert_eq!(hw_id(NR_CPUS), None);
        install_map(&CpuMap::EMPTY);
    }

    fn groups(hw: &[usize]) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        hw_groups(hw, |m, b| v.push((m, b)));
        v.sort_by_key(|g| g.1);
        v
    }

    /// SBI masks: bit `i` is hart `base + i`. Harts inside a word share one
    /// call; harts further apart than a word need another, and none is lost.
    /// Canary: send the logical mask unchanged (`(0b111, 0)` for the CPUs
    /// that sit on harts 4, 1, 2) and the second assertion fails.
    #[test]
    fn hart_masks_follow_the_hardware_ids_and_split_past_a_word() {
        assert_eq!(groups(&[]), vec![]);
        assert_eq!(groups(&[4, 1, 2]), vec![(0b1011, 1)], "lowest id is the base: harts 1, 2, 4");
        assert_eq!(groups(&[5]), vec![(1, 5)]);
        let w = usize::BITS as usize;
        assert_eq!(groups(&[2, 2 + w - 1, 2 + w]), vec![(1 | 1 << (w - 1), 2), (1, 2 + w)]);
        assert_eq!(groups(&[1000, 3]), vec![(1, 3), (1, 1000)]);
        let all: Vec<usize> = (0..w).collect();
        assert_eq!(groups(&all), vec![(usize::MAX, 0)]);
    }

    /// Logical CPU bits through the installed map: the VF2-like map sends
    /// CPUs {0, 2} to harts {4, 2}, a CPU the map lacks to nothing.
    #[test]
    fn logical_cpu_bits_become_hart_masks_through_the_map() {
        let _g = SERIAL.lock().unwrap();
        install_map(&CpuMap::build(4, &[1, 2, 3, 4]));
        let mut got = Vec::new();
        for_each_hw_group(0b101, |m, b| got.push((m, b)));
        if NR_CPUS >= 4 {
            assert_eq!(got, vec![(0b101, 2)], "harts 4 and 2, base 2");
            got.clear();
            for_each_hw_group(1 << 40, |m, b| got.push((m, b)));
            assert!(got.is_empty(), "CPU 40 is not in the map");
        }
        install_map(&CpuMap::EMPTY);
    }

    #[test]
    fn nr_cpu_ids_follows_the_possible_mask_and_online_is_a_subset() {
        let _g = SERIAL.lock().unwrap();
        set_possible(&CpuMask::first_n(3.min(NR_CPUS)));
        assert_eq!(nr_cpu_ids(), 3.min(NR_CPUS));
        assert!(set_cpu_online(0, true));
        assert!(cpu_online(0));
        assert!(!set_cpu_online(NR_CPUS - 1, true) || NR_CPUS <= 3,
            "a CPU that is not possible cannot come online");
        assert!(set_cpu_online(0, false));
        assert!(!cpu_online(0) && cpu_possible(0), "offline keeps it possible (hotplug-ready)");
        set_possible(&CpuMask::EMPTY);
        assert_eq!(nr_cpu_ids(), 1, "the boot CPU always exists");
    }

    static A: PerCpuRemote<u64> = unsafe { PerCpuRemote::zeroed() };
    unsafe fn b_init(p: *mut [u32; 25]) {
        unsafe { p.write([7; 25]) };
    }
    static B: PerCpuRemote<[u32; 25]> = PerCpuRemote::with_init(b_init);
    #[repr(align(64))]
    #[allow(dead_code)]
    struct Line([u8; 64]);
    static C: PerCpuRemote<Line> = unsafe { PerCpuRemote::zeroed() };

    /// The allocator: each variable at its own alignment inside the area, the
    /// initialiser run, every CPU its own instance, and a CPU without an area
    /// refused — `POISON` from the raw accessor, `None` (counted) from the
    /// checked one. Canary: attach CPU 1 too and the refusal assertions fail.
    #[test]
    fn areas_hold_every_variable_and_refuse_a_cpu_without_one() {
        let _g = SERIAL.lock().unwrap();
        let vars: [&dyn PerCpuVar; 3] = [&A, &B, &C];
        let bytes = area_bytes(&vars);
        assert_eq!(bytes % AREA_ALIGN, 0);
        assert!(bytes >= 8 + 100 + 64);
        let layout = Layout::from_size_align(bytes, AREA_ALIGN).unwrap();
        let cpus: Vec<usize> = [0usize, 2].into_iter().filter(|&c| c < NR_CPUS).collect();
        for &cpu in &cpus {
            let base = unsafe { alloc_zeroed(layout) };
            unsafe { attach_area(&vars, cpu, base) };
            assert_eq!(area_base(cpu), base as usize);
            for (p, a) in [(A.ptr(cpu) as usize, 8), (B.ptr(cpu) as usize, 4), (C.ptr(cpu) as usize, 64)] {
                assert!(p >= base as usize && p < base as usize + bytes, "inside the area");
                assert_eq!(p % a, 0, "aligned");
            }
            assert_eq!(unsafe { *B.ptr(cpu) }, [7; 25], "initialiser ran");
            unsafe { *A.ptr(cpu) = cpu as u64 + 100 };
        }
        for &cpu in &cpus {
            assert_eq!(unsafe { *A.ptr(cpu) }, cpu as u64 + 100, "one instance per CPU");
        }
        if NR_CPUS > 1 {
            let before = oor_count();
            assert!(!A.attached(1));
            assert_eq!(A.ptr(1) as usize, POISON, "a CPU without an area holds POISON");
            assert!(A.get(1).is_none());
            assert!(A.get(NR_CPUS).is_none(), "past the ceiling: refused, no panic");
            assert!(checked_area(1).is_none());
            assert_eq!(oor_count(), before + 3, "every refusal is counted");
        }
    }

    /// POISON must fault on both ISAs: non-canonical on Sv39 (bits 63..39 not
    /// a sign extension of bit 38) and on a 48-bit aarch64 VA (bits 63..48 not
    /// all equal), for any offset a per-CPU variable can add.
    #[test]
    fn poison_is_non_canonical_on_both_isas() {
        for off in [0usize, 4096, (1 << 32) - 1] {
            let a = POISON + off;
            let sv39_canonical = (a >> 38) == 0 || (a >> 38) == (usize::MAX >> 38);
            let va48_canonical = (a >> 47) == 0 || (a >> 47) == (usize::MAX >> 47);
            assert!(!sv39_canonical && !va48_canonical, "{a:#x}");
        }
    }

    // ── Placement classes (azos_percpu::place, Kconfig TASK_*_PLACE) ──────

    use azos_percpu::place::{pin, resolve, Place};

    #[test]
    fn every_class_spelling_parses_and_nothing_else_does() {
        assert_eq!(Place::parse("any"), Some(Place::Any));
        assert_eq!(Place::parse("boot"), Some(Place::Boot));
        assert_eq!(Place::parse("general"), Some(Place::General));
        assert_eq!(Place::parse("last"), Some(Place::Last));
        assert_eq!(Place::parse("rt.0"), Some(Place::Rt(0)));
        assert_eq!(Place::parse("rt.1"), Some(Place::Rt(1)));
        assert_eq!(Place::parse("rt.63"), Some(Place::Rt(63)));
        // A CPU number is not a class: that is what the classes replace.
        for bad in ["", "3", "hart3", "cpu2", "rt", "rt.", "rt.x", "rt.123", "LAST", "last ", "rt-0"] {
            assert_eq!(Place::parse(bad), None, "{bad:?}");
        }
    }

    /// The values the build was configured with (config/kernel/Kconfig.tasks) are
    /// classes; the kernel evaluates the same at compile time.
    #[test]
    fn the_configured_classes_parse() {
        for v in [
            azos_limits::TASK_NET_POLL_PLACE, azos_limits::TASK_AUTORUN_PLACE,
            azos_limits::TASK_SYS_WDT_PLACE, azos_limits::TASK_OTA_RECV_PLACE,
            azos_limits::TASK_CONTROL_PLACE, azos_limits::TASK_SENSING_PLACE,
            azos_limits::TASK_BEHAVIOR_PLACE,
        ] {
            assert!(Place::parse(v).is_some(), "{v:?}");
        }
    }

    /// The defaults on 4 CPUs are the layout the literal pins gave (control
    /// 0, sensing 1, behavior and sys-wdt 2, net-poll and autorun 3).
    #[test]
    fn four_cpus_keep_the_old_layout() {
        let r = |p| resolve(p, 4, 2);
        assert_eq!(r(Place::Rt(0)), Some(0));
        assert_eq!(r(Place::Rt(1)), Some(1));
        assert_eq!(r(Place::General), Some(2));
        assert_eq!(r(Place::Last), Some(3));
        assert_eq!(r(Place::Boot), Some(0));
        assert_eq!(r(Place::Any), None);
    }

    /// Canary for the literal hart: riscv64 pinned net-poll to 3 on every
    /// board. On 2 CPUs that CPU does not exist; on a K1's 8 it left the last
    /// four idle of kernel work.
    #[test]
    fn the_last_cpu_follows_the_board_not_a_literal() {
        assert_eq!(resolve(Place::Last, 1, 2), Some(0));
        assert_eq!(resolve(Place::Last, 2, 2), Some(1));
        assert_eq!(resolve(Place::Last, 8, 2), Some(7));
        assert_eq!(resolve(Place::General, 2, 2), Some(1), "no CPU after the cluster: the last");
        assert_eq!(resolve(Place::General, 8, 2), Some(2));
        assert_eq!(resolve(Place::Rt(1), 1, 2), Some(0), "a 1-CPU cluster folds rt.1 onto rt.0");
        assert_eq!(resolve(Place::Rt(3), 8, 0), Some(0), "no cluster: the boot CPU");
        assert_eq!(resolve(Place::General, 4, 0), Some(0), "no cluster: general starts at CPU 0");
    }

    /// Whatever the board and the cluster size, a class names a CPU the boot
    /// has: `task_create_affinity` never has to re-pin it.
    #[test]
    fn a_class_always_names_a_cpu_the_boot_has() {
        let classes = [Place::Boot, Place::General, Place::Last, Place::Rt(0), Place::Rt(1), Place::Rt(9)];
        for n in 0..=NR_CPUS {
            for rt in 0..=NR_CPUS + 2 {
                for p in classes {
                    let cpu = resolve(p, n, rt).unwrap();
                    assert!(cpu < n.max(1), "{p:?} n={n} rt={rt} -> {cpu}");
                }
            }
        }
    }

    /// `pin` resolves against `nr_cpu_ids`, which the firmware's CPU map sets.
    #[test]
    fn pin_reads_nr_cpu_ids() {
        // Read under the lock, asserted after it: a failure here must not
        // poison the lock for the other tests of the masks.
        let (last, one) = {
            let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            let before = possible();
            set_possible(&CpuMask::first_n(2.min(NR_CPUS)));
            let last = pin(Place::Last);
            set_possible(&CpuMask::first_n(1));
            let one = pin(Place::Last);
            set_possible(&before);
            (last, one)
        };
        assert_eq!(last, (2.min(NR_CPUS) - 1) as i8);
        assert_eq!(one, 0);
        assert_eq!(pin(Place::Any), -1);
    }
}
