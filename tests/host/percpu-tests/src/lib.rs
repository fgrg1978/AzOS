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

    /// The DTB clamp: nothing past the ceiling, never zero, flagged when cut.
    /// Canary: make `clamp_discovered` return the count unchanged and the
    /// third assertion fails.
    #[test]
    fn a_dtb_count_past_the_ceiling_is_clamped_and_flagged() {
        assert_eq!(clamp_discovered(0), (1, false));
        assert_eq!(clamp_discovered(1), (1, false));
        assert_eq!(clamp_discovered(NR_CPUS + 1), (NR_CPUS, true));
        assert_eq!(clamp_discovered(NR_CPUS), (NR_CPUS, false));
        assert_eq!(clamp_discovered(usize::MAX), (NR_CPUS, true));
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
}
