// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kernel_main`'s Phase 6: the scheduler hooks, the hardware bus and the
//! board's safety hardware, the DMA domains and the entropy seed, the PCI
//! bring-up, the block device, the swap partition, the CPU clock, the ring-3
//! seams, the page cache and the FAT32 mount.

use crate::*;

/// Phase 6, in order (see the module doc). Inlined, as every boot phase (see
/// `boot`'s module doc).
#[inline(always)]
#[cfg_attr(not(feature = "pci"), allow(unused_variables))]
pub(crate) fn bring_up_devices(early: &EarlyBoot, dtb_ptr: usize, num_cpus: usize) {
    // ---- Phase 6: VirtIO Block + VFS + Network ----

    kprintln!("========================================");
    kprintln!(" Phase 6: Storage + Network");
    kprintln!("========================================");
    kprintln!();

    // Wire Mutex/preempt/exit/WaitQueue callbacks through the scheduler.
    // Shared with aarch64's kernel_main — see `install_sched_hooks`'s own
    // doc for what each callback does and what silently degrades without
    // it. MOVED here (kernel-main-merge task, ordering-decision #1) from
    // this function's old, much later position (right before the task-spawn
    // block, after `install_topology`/`azos_sched::init()`) to match
    // aarch64's early position: `install_sched_hooks()` only stores function
    // pointers into `azos_sync`/`azos_sched` statics — verified, no
    // dependency on `azos_sched::init()` or any task-pool state — so
    // calling it this early is safe on both ISAs, and it must run before
    // anything can be woken/blocked/boosted/exit, which this position still
    // satisfies (well before the first `task_create*` below).
    install_sched_hooks();

    // ── Entropy: virtio-rng seeds the kernel pool ────────────────────────────
    // Shared with aarch64's kernel_main — see `install_entropy`'s own doc
    // for the full reasoning and the ordering constraint.
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    boot::hwbus::note_firmware_virtio(dtb_ptr);
    ARCH_ENTRY.map_late_mmio();
    // The hardware bus: the device tree's nodes and the populated virtio-mmio
    // windows become device objects, and the kernel's own hardware among them
    // (console, interrupt controller) is recorded as bound. The drivers below
    // are bound to the devices the bus found, in stages; none scans for its
    // hardware. See kernel/src/boot/hwbus.rs.
    boot::hwbus::enumerate_firmware(dtb_ptr);
    // The clock, reset, regulator and power-domain managers (Kconfig
    // SOC_FRAMEWORKS), from the same tree.
    #[cfg(feature = "soc")]
    boot::soc::install(dtb_ptr);
    // The real-time clock seeds the wall clock, before the network and so
    // before every record of the boot that wants a date (Kconfig DRV_RTC).
    #[cfg(feature = "rtc")]
    boot::rtc::install();
    // The board's safety-read hardware binds first: the GPIO that carries the
    // e-stop line and the watchdog (kernel/src/boot/hwbus.rs, "Board
    // controllers"). Their clocks and resets are on (the frameworks above),
    // no task exists yet, and the watchdog is armed much later
    // (`watchdog::hw_init`). The panic-time pin drive is a no-op before this
    // line: nothing had set the pins up either.
    boot::hwbus::bind_safety();
    // The DMA domains every driver maps its buffers through, before the first
    // virtio device (the entropy seed's) is probed.
    boot::dma_init(early.ram);
    boot::hwbus::bind(&["virtio-rng"]);
    install_entropy(dtb_ptr);

    // The PCI bring-up runs BEFORE the block device is brought up: with
    // Kconfig DRV_NVME an NVMe controller on the bus is attached here and
    // becomes the block device `blkdev::init` then finds (the FAT32 mount
    // below reads from it). It used to sit after the filesystem mounts; the
    // virtio-pci NIC it also brings up does not depend on anything between.
    // ── Native PCI bus-0 enumeration (QEMU only) ────
    //
    // Prints one line per PCI function found on ECAM bus 0 — vendor:device,
    // BAR(s) with kind/address/size, MSI/MSI-X capability presence — via
    // `azos_pci::format_function_line`. Enumeration reads BARs as found
    // (nothing runs a firmware PCI init step ahead of this kernel, so an
    // unassigned BAR reads address 0 with its real size). The users below —
    // the MSI-X self-test, the virtio-net-pci NIC, the MMC smoke — assign
    // the BARs they need from the host bridge's memory windows.
    #[cfg(feature = "pci")]
    boot::pci::bring_up(early, num_cpus);

    // The virtio disk, when the bus admits one and no NVMe controller took
    // the role above; the VisionFive 2's microSD controller (`dw-mshc`).
    boot::hwbus::bind(&["virtio-blk", "dw-mshc"]);
    match azos_drv_block::blkdev::init() {
        Ok(()) => {
            kprintln!("[FS] Block device OK ({} sectors)",
                azos_drv_block::blkdev::capacity_sectors());
            publish_partitions();
        }
        Err(()) => kprintln!("[FS] Block device not found (no disk)"),
    }
    // Persisted entropy seed: mixed and replaced here, before anything but the
    // virtio-rng seed has drawn from the pool, then the canary (which needs the
    // pool as seeded as it will get).
    install_entropy_seed();
    install_stack_canary();
    // Swap on a partition: after the seed (its key comes from the pool, and
    // the seed's tail check must still see the swap partition) and before any
    // task. A swap file waits for the mounts (`install_swap_file`, below).
    boot::swap::install_swap();

    // Measure the CPU clock against the CLINT timebase, before anything reads a
    // WCET or jitter figure. `rdcycle` runs at the core clock and the tree has
    // no constant for it on any board; the conversion used to divide by
    // `TIMER_FREQ` instead, which on the VF2 made every microsecond figure
    // roughly 375x too large. Measuring needs no datasheet and is right on a
    // board nobody has characterised.
    azos_drv_sys::wcet::calibrate_cpu_freq();
    kprintln!("[WCET] CPU clock measured: {} cycles/us",
              azos_drv_sys::wcet::cycles_per_us());

    // Ramfs root, the `FileOps` seam behind `SYS_OPEN`/`SYS_SPAWN_EX`, the
    // actuation gate and io_ring — see `install_ring3_seams`'s own doc.
    install_ring3_seams();

    // F20: TmpFS — bounded in-RAM temporary filesystem.
    kprintln!("[FS] tmpfs ready — max {} files, {} KiB cap",
        azos_fs::TMPFS_MAX_FILES,
        azos_fs::TMPFS_MAX_BYTES / 1024);

    // Storage L11 part B: the file data of FAT32 and tmpfs goes through the
    // page cache from the first mount on (the object table and the allocator
    // are up; the `fs-wb` task it wakes comes later and is a no-op until then).
    boot::pagecache::install_page_cache();

    if azos_drv_block::blkdev::capacity_sectors() > 0 {
        match azos_fs::fat32_mount() {
            Ok(()) => {
                // What the mount found on an unclean volume or a pending
                // journal record, and what it gave back.
                let r = azos_fs::fat32_mount_report();
                fat32_check_report(&r);
                match azos_fs::vfs_mount(b"/fat", azos_fs::FS_TYPE_FAT32) {
                    Ok(())  => {
                        kprintln!("[FS] FAT32 mounted at /fat");
                        // The files of the system that is running (a signed
                        // set's, after a whole-system update) before any of
                        // them is read.
                        install_boot_set();
                        // A panic record the previous boot left in RAM goes
                        // into /fat/CRASH.LOG now.
                        pstore::recover();
                        #[cfg(feature = "pstore-smoke")]
                        pstore::smoke();
                    }
                    Err(()) => azos_drv_sys::kerr!("[FS] FAT32 vfs_mount failed"),
                }
                #[cfg(feature = "fat-barrier-smoke")]
                fat_barrier_smoke();
                #[cfg(feature = "blk-discard-smoke")]
                blk_discard_smoke();
                // Shared with aarch64's kernel_main — see `install_flight_recorder`'s
                // own doc for the full reasoning and the ordering constraint (must run
                // before `robot_init()`).
                install_flight_recorder();
            }
            // A refusal by the check has its own line and record.
            Err(()) if azos_fs::fat32_mount_report().refused => fat32_check_report(&azos_fs::fat32_mount_report()),
            Err(()) => azos_drv_sys::kerr!("[FS] FAT32 mount failed (disk not FAT32?)"),
        }
    }
    kprintln!();

    // ---- Optional: HDMI framebuffer (VF2 only, --features hdmi) ─────────────
    // Never validated against real hardware — QEMU has no model for this
    // peripheral. See crates/drivers/display. PHY calibration is unconfirmed placeholder
    // data (crates/drivers/display/src/hdmi.rs) — expect no signal on a real
    // monitor even with this call wired correctly.
    #[cfg(feature = "hdmi")]
    azos_display::display_init();
}
