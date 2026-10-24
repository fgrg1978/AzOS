// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kernel_main`'s Phase 5 up to the scheduler's own init: the devices left
//! undecided settled, the topology installed and what it declares (guests,
//! firewall, volumes, the swap file, the keystore roots, the device rows),
//! the build type, the command line, the framebuffer and the log and terminal
//! regions, the energy model and the CPU topology, then `azos_sched::init`.

use crate::*;

/// Phase 5 to `azos_sched::init`, in order (see the module doc). Inlined, as
/// every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn init_scheduler(num_cpus: usize, dtb_ptr: usize) {
    // ---- Phase 5: SMP + Scheduler ----

    kprintln!("========================================");
    kprintln!(" Phase 5: SMP Scheduler ({} CPUs)", num_cpus);
    kprintln!("========================================");
    kprintln!();

    // Every device the stages so far did not name is decided now, under the
    // built-in topology's device rows; the input devices wait for their
    // interrupt wiring below.
    #[cfg(feature = "virtio-input")]
    boot::hwbus::settle(&["virtio-input"]);
    #[cfg(not(feature = "virtio-input"))]
    boot::hwbus::settle(&[]);

    // AZOS Phase 1 W3 — install the static topology before the
    // scheduler so that future task spawns can pull their cap_table +
    // class assignment from the topology's declarations. Shared with aarch64's
    // kernel_main — see `install_topology`'s own doc.
    install_topology(num_cpus);
    // Kconfig VIRT: admit the topology's `[guest.NAME]` rows (the monitor's VMs).
    #[cfg(feature = "hv")]
    install_hv(num_cpus);
    #[cfg(feature = "net")]
    install_firewall();
    // The native volumes the topology declares (`[volume.NAME]`), mounted at
    // their rows' paths now that the rows and the partition table exist.
    install_azvol();
    // Kconfig MM_SWAP_BACKEND_FILE: the swap file, on whichever volume
    // holds its path (FAT32 was mounted above, azvol just now), before the
    // first task. A no-op for the other backends.
    boot::swap::install_swap_file();
    // The roots the keystore derives persistent keys from (the TPM's secret,
    // the volume's), now that the mounts and the entropy pool exist.
    boot::keys::install_keystore_roots();
    // The topology's rows (a signed file's, when there is one) replace the
    // built-in ones: bring every device to what they say.
    boot::hwbus::reconcile();
    // Kconfig BUILD_TYPE (dev: test machinery and the TEST key allowed).
    kprintln!("[BOOT] build type: {}", if azos_limits::BUILD_TYPE_CERTIFIABLE {
        "certifiable"
    } else if azos_limits::BUILD_TYPE_RELEASE {
        "release"
    } else {
        "dev"
    });
    // The kernel command line: `init=` (secure boot off) names this boot's
    // console program. Read before anything ring 3 starts.
    crate::console_mode::read_cmdline(dtb_ptr);
    // The framebuffer (Kconfig FB_GENERIC): the console mirrors the lines
    // printed from here on.
    #[cfg(feature = "fb-generic")]
    boot::fb::init(dtb_ptr);
    // The structured kernel log's ring (Kconfig KLOG): the lines printed so
    // far move from the early ring into the region ring 3 maps.
    boot::klog_region::install();
    // The terminal server's regions: the input event ring (before any input
    // line is enabled) and the console screen (the grid is up now).
    #[cfg(any(feature = "virtio-input", feature = "ps2", feature = "usb-hid", feature = "fb-console"))]
    boot::term_regions::install();
    // The energy model, from the topology just installed, else
    // the DTB, else none.
    #[cfg(feature = "energy")]
    install_energy(num_cpus, dtb_ptr);
    // Kconfig ENERGY (and THERMAL): the board's clock runtime over that model,
    // with the DTB's `thermal-zones` under THERMAL; its task is created below.
    #[cfg(feature = "energy")]
    boot::thermal::install(dtb_ptr);
    // Which CPUs share a core, a cluster, a cache, a node and a package, and
    // their capacities: from the DT, the ACPI PPTT or CPUID, for the balancer.
    boot::smp::install_topology(num_cpus, dtb_ptr);

    azos_sched::init();

    // (`install_sched_hooks()` now called much earlier — right after the
    // "Phase 6" banner, before `install_entropy()`; see that call site's
    // comment, ordering-decision #1.)
    //
    // Marker cluster for the four callbacks wired by `install_sched_hooks`
    // — see `sched_hooks_smoke`'s own doc. Off by default
    // (`sched-hooks-smoke` feature); compiles to nothing otherwise. Still
    // spawned here (well after the hooks are installed — installing them
    // earlier only widens that margin, function-pointer stores are
    // idempotent). riscv64 only: aarch64 spawns it from its own later site
    // below (the early one reads `counter at wake = 0` there), and the
    // cluster shares its statics, so spawning it from both sites printed
    // every `[SCHEDHOOKS]` line twice and doubled the waitqueue counter.
    #[cfg(all(feature = "sched-hooks-smoke", not(target_arch = "aarch64"), not(feature = "ktest")))]
    sched_hooks_smoke::spawn();
}
