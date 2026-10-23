// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where the kernel's own tasks run: a placement *class* per task (Kconfig
//! `TASK_*_PLACE`, config/kernel/Kconfig.tasks), resolved against the CPUs this boot
//! has (`nr_cpu_ids`, from the firmware's CPU map). No CPU number is written
//! at a call site: a pin that names a CPU the board does not have used to be
//! re-pinned by the scheduler with a warning (riscv64 net-poll on CPU 3 under
//! `-smp 2`), and one the board has twice over left CPUs idle (CPU 3 of a
//! K1's eight).
//!
//! The classes, for a boot of `n` CPUs whose first `rt` CPUs are the
//! real-time cluster (Kconfig `TASK_RT_CLUSTER_CPUS`):
//!
//! | class     | CPU                                                        |
//! |-----------|------------------------------------------------------------|
//! | `any`     | none: the scheduler places the task                        |
//! | `boot`    | the boot CPU, logical CPU 0 on every ISA                    |
//! | `rt.K`    | the K-th CPU of the cluster, the cluster's last when it has fewer than K + 1 (and CPU 0 with no cluster) |
//! | `general` | the first CPU after the cluster, the last CPU when there is none |
//! | `last`    | the last CPU, `n - 1`                                      |

/// A kernel task's placement class (see the module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Any,
    Boot,
    Rt(u8),
    General,
    Last,
}

const fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl Place {
    /// The class a Kconfig `TASK_*_PLACE` string names, or `None` for any
    /// other spelling. `rt.K` takes one or two decimal digits.
    pub const fn parse(s: &str) -> Option<Place> {
        let b = s.as_bytes();
        if eq(b, b"any") {
            return Some(Place::Any);
        }
        if eq(b, b"boot") {
            return Some(Place::Boot);
        }
        if eq(b, b"general") {
            return Some(Place::General);
        }
        if eq(b, b"last") {
            return Some(Place::Last);
        }
        if b.len() < 4 || b.len() > 5 || b[0] != b'r' || b[1] != b't' || b[2] != b'.' {
            return None;
        }
        let mut k: u8 = 0;
        let mut i = 3;
        while i < b.len() {
            if !b[i].is_ascii_digit() {
                return None;
            }
            k = k * 10 + (b[i] - b'0');
            i += 1;
        }
        Some(Place::Rt(k))
    }

    /// [`Place::parse`] for a Kconfig constant: a spelling no class has stops
    /// the build (the constant is evaluated at compile time).
    pub const fn of_kconfig(s: &str) -> Place {
        match Place::parse(s) {
            Some(p) => p,
            None => panic!("a TASK_*_PLACE value is not a placement class: \
                            any, boot, rt.K, general or last (config/kernel/Kconfig.tasks)"),
        }
    }
}

/// The CPU a task of class `p` is pinned to on a boot of `ncpu` CPUs whose
/// first `rt` CPUs are the real-time cluster; `None` for [`Place::Any`].
/// Always below `ncpu` (a boot has at least the boot CPU).
pub const fn resolve(p: Place, ncpu: usize, rt: usize) -> Option<usize> {
    let n = if ncpu == 0 { 1 } else { ncpu };
    let cluster = if rt > n { n } else { rt };
    match p {
        Place::Any => None,
        Place::Boot => Some(0),
        Place::Rt(k) => {
            let k = k as usize;
            let top = if cluster == 0 { 0 } else { cluster - 1 };
            Some(if k < top { k } else { top })
        }
        Place::General => Some(if cluster < n { cluster } else { n - 1 }),
        Place::Last => Some(n - 1),
    }
}

/// [`resolve`] against this boot: `nr_cpu_ids` (fixed from the firmware's CPU
/// map before any task exists) and Kconfig `TASK_RT_CLUSTER_CPUS`, as the
/// affinity argument of `task_create_affinity` (`-1`: no pin).
pub fn pin(p: Place) -> i8 {
    match resolve(p, crate::nr_cpu_ids(), azos_limits::TASK_RT_CLUSTER_CPUS as usize) {
        // `NR_CPUS` is at most 64 (config/limits/Kconfig.limits), so the id fits.
        Some(cpu) => cpu as i8,
        None => -1,
    }
}
