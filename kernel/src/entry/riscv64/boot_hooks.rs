// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 boot hooks: the ISA-specific steps of the generic early boot
//! (`boot::early_main`, kernel/src/boot/early.rs), which calls them through
//! this ISA's `ArchEntry` (`arch_entry.rs`), plus the SBI HSM secondary-hart
//! wake and the hand-off to the scheduler.
//!
//! What is riscv64's own here: `stvec` and the interrupt stacks, the
//! PLIC/AIA choice and its init, Sstc vs SBI `set_timer`, Zicboz, the QEMU
//! and board MMIO windows, the PMP audit log, the `sie` enables. The common
//! steps (console, memory map, page tables, W^X/NX, guards, heap) are in
//! `early_main` (`tools/boot_seq_lint.py` keeps them there).

use azos_drv_sys::kprintln;
use azos_arch::csr;
use azos_arch::Interrupts;
use azos_arch::FirmwareMemory;
use azos_arch_api::isa::riscv64 as policy;
use core::sync::atomic::{AtomicU32, Ordering};

/// What cpu@0's device tree declares, for the `[ISA]` line `firmware_done`
/// prints (no DTB: nothing declared). One bit per [`Dt`] entry.
static DT_ISA: AtomicU32 = AtomicU32::new(0);

/// The `DT_ISA` bits.
#[derive(Clone, Copy)]
#[repr(u32)]
enum Dt { Zicboz = 1, Sstc = 2, Svpbmt = 4, Zba = 8, Zbb = 16, Zbs = 32, V = 64, Aia = 128, F = 256, D = 512,
         Zawrs = 1024, Zacas = 2048, Zihintpause = 4096 }

/// Kconfig RV_V, except that a build given `--features rvv` by hand (`make
/// build-rvv`, `qemu-rvv`, the `k1` feature's edge) on a config whose RV_V
/// is n means probe: the feature compiled the vector code in to be used.
const V_POLICY: azos_arch_api::isa::ExtPolicy =
    if cfg!(feature = "rvv") && !policy::V.allowed() {
        azos_arch_api::isa::ExtPolicy::Probe
    } else {
        policy::V
    };

fn dt_has(bit: Dt) -> bool {
    DT_ISA.load(Ordering::Relaxed) & bit as u32 != 0
}

/// The parsed device tree (`None`: no pointer, or one that did not parse),
/// and the hart it was parsed on.
pub struct Firmware {
    info: Option<azos_dtb::DtbInfo>,
    hart_id: usize,
}

/// Nothing to read before the console on riscv64.
#[inline(always)]
pub fn pre_console() {}

/// The trap vector, installed before any code that could fault: until
/// `stvec` is set, an exception jumps to address 0. `trap_init` needs only
/// the UART (for `kprintln`) and CSRs: no heap, no MMU. The interrupt stacks
/// are armed FIRST: from the instant `stvec` is live a trap can arrive, and
/// the exit path reads the magic word of the slot it ran on. Secondaries
/// share these slots by hart id, so arming them here covers every hart.
#[inline(always)]
pub fn trap_init() {
    crate::irq_stacks_arm();
    crate::trap_init();
}

/// The banner, then a boot hart at or past `NR_CPUS` halts.
#[inline(always)]
pub fn boot_banner(hart_id: usize, dtb_ptr: usize) {
    kprintln!();
    kprintln!("========================================");
    kprintln!("  AzOS Rust kernel booted!");
    kprintln!("========================================");
    kprintln!();
    kprintln!("[BOOT] Hart ID:  {}", hart_id);
    kprintln!("[BOOT] DTB addr: {:#x}", dtb_ptr);

    // The boot hart is whoever won `boot_lock`: boot.S range-checks only
    // SECONDARY harts. A CPU id is the hart id here (`tp`), and every per-CPU
    // table is indexed by it, so a boot hart at or past `NR_CPUS` has no slot
    // anywhere: halt loudly with the id rather than index out of bounds on
    // the first scheduler touch. (VF2: S7 is hart 0 and the U74s 1..4, so
    // its default is 5.)
    if hart_id >= crate::MAX_HARTS {
        azos_drv_sys::kerr!("[BOOT] FATAL: boot hart id {} >= NR_CPUS {} — it has no per-CPU \
                   slot. Halting. (Raise NR_CPUS in make config.)", hart_id, crate::MAX_HARTS);
        loop { azos_arch::cpu::wfi(); }
    }
}

/// `/chosen/bootargs` of the device tree at `dtb_ptr` (`ArchEntry::kernel_cmdline`).
pub fn kernel_cmdline(dtb_ptr: usize, out: &mut [u8]) -> Option<usize> {
    if dtb_ptr == 0 {
        return None;
    }
    // SAFETY: the firmware's device-tree pointer, as `dtb_parse` reads it.
    unsafe { azos_dtb::dtb_bootargs(dtb_ptr as *const u8, out) }
}

/// Print what the DTB says (`dt`: `early_main`'s parse of it).
#[inline(always)]
pub fn firmware_table(hart_id: usize, dtb_ptr: usize, dt: Option<azos_dtb::DtbInfo>) -> Firmware {
    match &dt {
        Some(info) => {
            let compat = azos_dtb::dtb_compatible_str(info);
            kprintln!("[DTB] Parsed FDT — {} CPUs, mem={:#x}+{:#x}, timer={}",
                info.num_cpus, info.mem_base, info.mem_size, info.timer_freq);
            if info.plic_base != 0 {
                kprintln!("[DTB] UART={:#x}, PLIC={:#x}", info.uart_base, info.plic_base);
            } else {
                kprintln!("[DTB] UART={:#x}, PLIC=none", info.uart_base);
            }
            kprintln!("[DTB] Compatible: {}", core::str::from_utf8(compat).unwrap_or("?"));
        }
        None if dtb_ptr != 0 => azos_drv_sys::kerr!("[DTB] Parse failed (invalid or unsupported FDT)"),
        None => {}
    }
    Firmware { info: dt, hart_id }
}

/// RFC-0046 stage 1a: an S-domain APLIC plus an S-level IMSIC group in the
/// DTB (`virt,aia=aplic-imsic`) selects the AIA path of `irqchip`; plain
/// `virt` keeps the PLIC. Must run before the MMIO mapping and the IRQ init,
/// which both consult the selection. Then the drivers front: QEMU virt's
/// bus/device/driver table, bound from the DTB (VF2/K1 have compile-time
/// device tables instead).
#[inline(always)]
pub fn irqchip_probe(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    // Kconfig RV_AIA = n: the PLIC, even when the DTB has an APLIC.
    if policy::AIA.allowed() && info.aplic_base != 0 && info.imsic_base != 0 {
        let layout = azos_drv_irqchip::imsic::GroupLayout {
            base: info.imsic_base,
            num_ids: info.imsic_num_ids,
            hart_stride: azos_drv_irqchip::imsic::GroupLayout::stride_for_guest_bits(
                info.imsic_guest_index_bits),
        };
        azos_drv_irqchip::irqchip::select_aia(info.aplic_base, info.aplic_num_sources, layout);
        kprintln!("[DTB] AIA: APLIC={:#x} sources={} IMSIC={:#x} ids={} stride={:#x}",
            info.aplic_base, info.aplic_num_sources, info.imsic_base,
            info.imsic_num_ids, layout.hart_stride);
    }
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    azos_drv_bus::hwbus::probe_qemu_virt_riscv64(
        info.uart_base, info.plic_base, azos_drv_irqchip::irqchip::is_aia());
}

/// RFC-0041 §B: `stimecmp` when cpu@0 declares Sstc and S-mode can read the
/// CSR (`clint::timer_select` probes it); SBI otherwise. Then the DTB's
/// timebase against the kernel's fixed `TIMER_FREQ`: if they disagree, every
/// µs/ms calculation (WCET, sleeps, timeouts) is off, so say so loudly.
#[inline(always)]
pub fn timer_probe(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    // Kconfig RV_SSTC = n: SBI, even when cpu@0 declares Sstc.
    azos_drv_irqchip::clint::timer_select(
        cfg!(not(feature = "timer-sbi-only")) && policy::SSTC.gate(info.isa_sstc),
    );
    let kernel_timer_hz = azos_drv_base::platform::hw::TIMER_FREQ;
    if info.timer_freq != 0 && info.timer_freq != kernel_timer_hz {
        azos_drv_sys::kwarn!("[DTB] WARNING: timer_freq mismatch — DTB={}Hz kernel={}Hz, \
            timing calculations will drift", info.timer_freq, kernel_timer_hz);
    }
}

/// RFC-0045 Tier 0 item 3: `cbo.zero` for the page allocator's zero-fill
/// when cpu@0 declares Zicboz and a trap-safe probe confirms it executes and
/// zeroes correctly on this hart (`cbo::zicboz_select`; the same "the DTB
/// claims it, then verify on the real hart" shape as Sstc). Before
/// `pmm::init`: `alloc_page`'s zero-fill consults it on its first call.
/// Gate canary `zicboz-skip-canary`: the DTB's Zicboz is ignored. Then the
/// vDSO `hwcap` inputs (wave 13, published by `install_vdso`).
#[inline(always)]
pub fn cpu_features(fw: &Firmware) {
    let Some(info) = &fw.info else { return };
    let mut dt = 0u32;
    for (on, bit) in [(info.isa_zicboz, Dt::Zicboz), (info.isa_sstc, Dt::Sstc),
                      (info.isa_svpbmt, Dt::Svpbmt), (info.isa_zba, Dt::Zba),
                      (info.isa_zbb, Dt::Zbb), (info.isa_zbs, Dt::Zbs), (info.isa_v, Dt::V),
                      (info.aplic_base != 0 && info.imsic_base != 0, Dt::Aia),
                      (info.isa_f, Dt::F), (info.isa_d, Dt::D),
                      (info.isa_zawrs, Dt::Zawrs), (info.isa_zacas, Dt::Zacas),
                      (info.isa_zihintpause, Dt::Zihintpause)] {
        if on {
            dt |= bit as u32;
        }
    }
    DT_ISA.store(dt, Ordering::Relaxed);
    // Kconfig RV_ZICBOZ = n: the DTB's Zicboz is ignored (as the canary does).
    #[cfg(not(feature = "zicboz-skip-canary"))]
    azos_arch::cbo::zicboz_select(policy::ZICBOZ.gate(info.isa_zicboz), info.cboz_block_size);
    // Kconfig n hides Zbb / V from the kernel's own users and from the vDSO hwcap.
    crate::boot::note_dtb_isa(policy::ZBB.gate(info.isa_zbb), info.isa_zbc, info.isa_zknh,
                              V_POLICY.gate(info.isa_v));
    #[cfg(feature = "rvv")]
    azos_arch::rvv::set_usable(V_POLICY.gate(info.isa_v));
    spin_select(info.isa_zacas, info.isa_zawrs, info.isa_zihintpause);
}

/// `SpinWait`'s extensions (wave 15, N2): cpu@0's claim, masked by Kconfig
/// RV_ZACAS / RV_ZAWRS / RV_ZIHINTPAUSE, then Zacas and Zawrs executed once
/// under a private trap vector (`azos_arch::spin::select`). The `probe`
/// sites take the verdict at `boot_patch` (`boot/spin_patch.rs`). Canary
/// `spin-ext-claim`: claim Zacas and Zawrs whatever the device tree says;
/// the execution probe must refute a false claim and the locks stay on
/// LR/SC.
fn spin_select(dt_zacas: bool, dt_zawrs: bool, dt_pause: bool) {
    let claim = canary!("spin-ext-claim");
    let v = azos_arch::spin::select(policy::ZACAS.gate(dt_zacas || claim),
                                    policy::ZAWRS.gate(dt_zawrs || claim),
                                    policy::ZIHINTPAUSE.gate(dt_pause));
    kprintln!("[SPIN] cas: {}{}; wait: {}{}",
        if azos_arch::spin::zacas_on() { "amocas (Zacas)" } else { "lr/sc" },
        if v.zacas_refuted { " (zacas claimed, refuted by the execution probe)" } else { "" },
        if azos_arch::spin::zawrs_on() { "lr+wrs.nto (Zawrs)" }
            else if azos_arch::spin::pause_on() { "pause" } else { "poll" },
        if v.zawrs_refuted { " (zawrs claimed, refuted by the execution probe)" } else { "" });
}

/// RAM from the DTB's `/memory` node, or the platform fallback. The boot
/// CPU's logical id is its hart id on this ISA.
#[inline(always)]
pub fn firmware_memory(fw: &Firmware) -> FirmwareMemory {
    use azos_drv_base::platform::hw;
    let (mem_start, mem_size, from_firmware) = match &fw.info {
        Some(i) if i.mem_base != 0 && i.mem_size != 0 => (i.mem_base, i.mem_size, true),
        _ => (hw::RAM_BASE, crate::FALLBACK_MEM_SIZE, false),
    };
    let (cpu_count, cpu_source) = match &fw.info {
        Some(i) => (i.num_cpus, "DTB"),
        None => (0, "none"),
    };
    FirmwareMemory { mem_start, mem_size, from_firmware, cpu_count, boot_cpu: fw.hart_id, cpu_source }
}

/// Ring-3 trigger types come only from an APLIC (`sourcecfg`); a PLIC has
/// no trigger configuration and its binding (`#interrupt-cells = 1`) carries
/// none, so plain `virt` reads nothing.
#[inline(always)]
pub fn irq_trigger_controller() -> Option<azos_dtb::IrqController> {
    azos_drv_irqchip::irqchip::is_aia().then_some(azos_dtb::IrqController::AplicS)
}

/// The APLIC's trigger types, noted for `user_irq` (wave 9 IRQ4).
#[inline(always)]
pub fn irq_triggers(found: Option<azos_dtb::IrqTriggers>) {
    match found {
        Some(t) => {
            for line in 1..azos_drv_irqchip::plic::MAX_IRQS {
                if let Some(edge) = t.edge(line) {
                    azos_drv_irqchip::user_irq::note_dtb_trigger(line, edge);
                }
            }
            let (n, e) = t.counts();
            kprintln!("[IRQ] DTB triggers (APLIC-S): {} sources, {} edge", n, e);
        }
        None => kprintln!("[IRQ] DTB triggers: no S-domain APLIC with 2-cell specifiers"),
    }
}

/// The final timer and Zicboz choices, each finalized here when the DTB
/// made none, and the CPU count.
#[inline(always)]
pub fn firmware_done(_dtb_ptr: usize, num_cpus: usize) {
    // Selects SBI when nothing above did (no DTB, or one that did not parse);
    // otherwise returns the choice already made.
    let sstc_on = match azos_drv_irqchip::clint::timer_select(false) {
        azos_drv_irqchip::clint::TimerMode::Sstc => { kprintln!("[TIMER] stimecmp (Sstc)"); true }
        azos_drv_irqchip::clint::TimerMode::Sbi => { kprintln!("[TIMER] SBI set_timer"); false }
    };
    // The probe's own trap path, taken on purpose: under `-cpu rv64,sstc=off`
    // the read traps, and the boot must carry on past this line.
    #[cfg(feature = "qemu")]
    kprintln!("[TIMER] stimecmp probe: {}",
        if azos_drv_irqchip::clint::stimecmp_probe() { "readable" } else { "trapped" });
    // Selects "absent" when nothing above did; same "finalize the decision"
    // role as `timer_select(false)` just above.
    let zicboz_on = azos_arch::cbo::zicboz_select(false, 0);
    kprintln!("[MM] Zicboz cbo.zero fast path: {}",
        if zicboz_on { "enabled" } else { "scalar fallback" });
    isa_report(zicboz_on, sstc_on);
    kprintln!("[BOOT] Online CPUs: {} (NR_CPUS: {})", num_cpus, crate::MAX_HARTS);
    kprintln!();
}

/// The baseline check and the `[ISA]` line (config/Kconfig.arch): Zicboz
/// and Sstc as the probes resolved them (DTB plus a trap-safe execution
/// probe), the rest as cpu@0's device tree declares them. A level above
/// the hart, or a `require`d extension it lacks, refuses the boot.
fn isa_report(zicboz_on: bool, sstc_on: bool) {
    use azos_arch_api::isa::Ext;
    if policy::LEVEL_NEEDS_FD && !(dt_has(Dt::F) && dt_has(Dt::D)) {
        crate::boot::isa::refuse_level(policy::LEVEL, "F and D (cpu@0 riscv,isa)");
    }
    if policy::LEVEL_NEEDS_V && !dt_has(Dt::V) {
        crate::boot::isa::refuse_level(policy::LEVEL, "V (cpu@0 riscv,isa)");
    }
    let e = |name, symbol, policy, present| Ext { name, symbol, policy, present };
    crate::boot::isa::report(policy::LEVEL, &[
        e("zicboz", "RV_ZICBOZ", policy::ZICBOZ, zicboz_on),
        e("sstc", "RV_SSTC", policy::SSTC, sstc_on),
        e("svpbmt", "RV_SVPBMT", policy::SVPBMT, dt_has(Dt::Svpbmt)),
        e("zba", "RV_ZBA", policy::ZBA, dt_has(Dt::Zba)),
        e("zbb", "RV_ZBB", policy::ZBB, dt_has(Dt::Zbb)),
        e("zbs", "RV_ZBS", policy::ZBS, dt_has(Dt::Zbs)),
        e("v", "RV_V", V_POLICY, dt_has(Dt::V)),
        e("aia", "RV_AIA", policy::AIA, azos_drv_irqchip::irqchip::is_aia()),
        e("zawrs", "RV_ZAWRS", policy::ZAWRS, azos_arch::spin::verdict().1),
        e("zacas", "RV_ZACAS", policy::ZACAS, azos_arch::spin::verdict().0),
        e("zihintpause", "RV_ZIHINTPAUSE", policy::ZIHINTPAUSE, azos_arch::spin::verdict().2),
    ]);
}

/// Nothing to reserve: the blob is read in full before `pmm::init`
/// (`firmware_done`), and `pstore::reserve` already rules out an overlap.
#[inline(always)]
pub fn reserve_firmware_table(_dtb_ptr: usize) {}

/// `satp` now holds the kernel table.
#[inline(always)]
pub fn mmu_enabled() {
    kprintln!("[MM] Sv39 paging ENABLED");
}

/// Nothing to restrict: user tables copy only the kernel's own half on
/// riscv64, and RAM is not mapped in the user range.
#[inline(always)]
pub fn restrict_low_half() {}

/// The guards' "active" lines are the riscv64 report; its fault probes are
/// the generic ones (`early_main`).
#[inline(always)]
pub fn verify_guards() {}

/// The Zicboz zero-fill self-check and bench (QEMU), and the PMP audit log.
#[inline(always)]
pub fn post_heap(heap_start: usize, kernel_end_aligned: usize) {
    crate::entry::riscv64::zicboz::selfcheck();
    kprintln!();

    // F04: PMP policy audit log. The kernel runs in S-mode and cannot write
    // PMP CSRs (M-mode only); every boot path runs under OpenSBI, which sets
    // a permissive PMP, and W^X is enforced by the page tables. (B2-02: the
    // no-OpenSBI M-mode stub that once called pmp_early_init() was deleted.)
    // Log the intended stricter policy for operator audit.
    {
        use azos_arch::pmp::{pmp_regions, N_PMP_REGIONS};
        use azos_drv_base::platform::hw::KERNEL_LOAD;
        let pmp = pmp_regions(KERNEL_LOAD, kernel_end_aligned, heap_start, crate::HEAP_SIZE);
        kprintln!("[PMP] Intended policy ({} regions + deny catch-all):", N_PMP_REGIONS);
        for (i, r) in pmp.iter().enumerate() {
            kprintln!("[PMP]  {}: {:20}  {:010x}-{:010x}  {}{}{}",
                i, r.name,
                r.base, r.base + r.size,
                if r.perm.r { 'R' } else { '-' },
                if r.perm.w { 'W' } else { '-' },
                if r.perm.x { 'X' } else { '-' },
            );
        }
        kprintln!("[PMP] Running under OpenSBI — W^X enforced by VMM page tables");
        kprintln!();
    }

}

/// `irqchip` dispatches to `plic::init` on plain `virt`, or to this hart's
/// IMSIC file plus the APLIC domain (MSI mode) on AIA.
#[inline(always)]
pub fn irqchip_init(hart_id: usize, _dtb_ptr: usize) {
    if azos_drv_irqchip::irqchip::is_aia() {
        kprintln!("[IRQ] Initializing AIA (APLIC MSI mode + IMSIC)...");
    } else {
        kprintln!("[IRQ] Initializing PLIC...");
    }
    azos_drv_irqchip::irqchip::init(hart_id as u32);
    azos_drv_irqchip::irqchip::init_aia_domain();
}

/// EXTERNAL + SOFTWARE interrupts (PLIC, IPI). The timer (STIE) waits until
/// just before `scheduler::start()`: otherwise the timer ISR preempts
/// `kernel_main` with already-created RT tasks and the boot CPU never
/// reaches `wake_harts()`, starving every secondary.
#[inline(always)]
pub fn irq_enable_early() {
    let sie = csr::read_sie();
    csr::write_sie(sie | csr::SIE_SEIE | csr::SIE_SSIE);
    azos_arch::ARCH.enable_all();
}

/// The interrupt line of virtio-mmio transport `slot` (Kconfig
/// `NET_RX_IRQ`): QEMU `virt` wires slot `n` to PLIC source
/// `VIRTIO_IRQ_BASE + n`. VF2/K1 have no virtio-mmio window.
#[inline(always)]
pub fn net_mmio_line(slot: usize, _base: usize) -> Option<u32> {
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    { Some(azos_drv_base::platform::hw::VIRTIO_IRQ_BASE + slot as u32) }
    #[cfg(any(feature = "vf2", feature = "k1"))]
    { let _ = slot; None }
}

/// Route (AIA: APLIC source -> this hart's IMSIC) and enable `line` for
/// `hart`, as [`console_irq`] does for the UART.
#[inline(always)]
pub fn net_mmio_unmask(hart: usize, line: u32) {
    if let Some(cfg) = azos_drv_irqchip::irqchip::wire_aia_source(line, hart as u32) {
        kprintln!("[IRQ] APLIC source {} -> hart {} sourcecfg={:#x}", line, hart, cfg);
    }
    azos_drv_irqchip::irqchip::enable_irq(hart as u32, line);
}

/// UART RX interrupt (IRQ 10): characters go to the ring buffer. On AIA the
/// APLIC source is first routed to this hart, identity 10.
#[inline(always)]
pub fn console_irq(hart_id: usize, _dtb_ptr: usize) {
    if let Some(cfg) = azos_drv_irqchip::irqchip::wire_aia_source(
        azos_drv_sys::uart::UART_IRQ, hart_id as u32)
    {
        kprintln!("[IRQ] APLIC source {} -> hart {} sourcecfg={:#x}",
            azos_drv_sys::uart::UART_IRQ, hart_id, cfg);
    }
    azos_drv_irqchip::irqchip::enable_irq(hart_id as u32, azos_drv_sys::uart::UART_IRQ);
    azos_drv_sys::uart::enable_irq();
    // RFC-0055 S1: the PLIC arm (`trap::interrupt`) wakes a reader parked on
    // console input, as aarch64's PL011 arm does.
    azos_drv_sys::uart::set_rx_wake_wired();
    kprintln!("[IRQ] UART IRQ enabled (ring buffer RX)");
    // The same line now feeds the UART from the console's TX ring.
    azos_drv_sys::uart::enable_tx_irq();
}

/// The fixed `TIMER_FREQ`. `rdtime` from U-mode is enabled
/// (`scounteren.TM`), so libsys may read the counter instead of trapping for
/// SYS_UPTIME (RFC-0041 §A); `vdso-force-syscall` keeps the trap.
#[inline(always)]
pub fn timebase_hz() -> u64 {
    azos_drv_sys::timebase::TIMER_FREQ
}

/// The PLIC/APLIC line, masked and handed back.
#[inline(always)]
pub fn line_release() -> fn(u32) {
    azos_drv_irqchip::user_irq::release
}

/// The boot hart: the kernel's own lines are routed here, and it is the
/// first hart a ring-3 line may be routed to; each secondary joins in
/// `secondary_main` (`user_irq::hart_ready`).
#[inline(always)]
pub fn irq_routing_init(hart_id: usize) {
    azos_drv_irqchip::user_irq::set_boot_hart(hart_id as u32);
    kprintln!("[IRQ] Traps + interrupts active");
    kprintln!();
}

/// SBI HSM needs no probe: `hart_start` is the interface on every board.
#[inline(always)]
pub fn smp_probe(_dtb_ptr: usize) {}

/// The tick is armed in `arch_enter_scheduler` (see `irq_enable_early`).
#[inline(always)]
pub fn timer_init() {}

/// riscv64's boot self-checks run where their subject comes up
/// (`[MM] Zicboz`, `[TIMER] stimecmp probe`).
#[inline(always)]
pub fn boot_selftests() {}

/// No-op on riscv64: nothing this ISA maps late. See
/// `entry::aarch64::boot_hooks::arch_map_late_mmio` for why aarch64 needs
/// one (VirtIO-MMIO is not live before this point on that ISA).
pub fn arch_map_late_mmio() {}

/// Final hand-off to the scheduler: boot-stack usage report, the SIE-armed-
/// too-early canary, the shared "[SCHED] Starting scheduler..." line, arm
/// the timer, re-establish `tp = hart_id` (Rust calls up to this point may
/// have clobbered it as a caller-saved scratch register), then
/// `azos_sched::start()` — never returns. Verbatim cut from the former
/// riscv64 `kernel_main`'s own tail.
pub fn arch_enter_scheduler(hart_id: usize) -> ! {
    crate::boot_stack_report();

    // Only now may a tick switch the boot hart to a task. kernel_main is no
    // task, so `do_schedule` saves nothing when it switches away from it:
    // with the timer enabled any earlier, the first switching tick discards
    // the rest of this function, hw_init above included. SIE stays clear
    // until the first task's entry wrapper sets it, so no tick lands before
    // sched::start() either. The "Starting scheduler" line is the gate's proof
    // that this point was reached. Losing the tail is a race (it takes a tick
    // that finds a ready task on this hart), so a timer enabled too early can
    // also get here by luck; the check below turns that case red as well.
    if csr::read_sie() & csr::SIE_STIE != 0 {
        azos_drv_sys::kerr!("[SCHED] Boot hart FAILED: timer interrupt enabled before the end of kernel_main");
    }
    kprintln!("[SCHED] Starting scheduler on boot CPU — tasks will now preempt...");
    kprintln!();
    let _ = azos_arch::ARCH.disable_all();

    // U01-4: open the SCHED_LIVE gate before anything re-enables interrupts
    // below — same ordering as `entry::aarch64::boot_hooks::arch_enter_
    // scheduler`. `trap_resched()` (kernel/src/trap/interrupt.rs) now checks this
    // first and returns early while it is false, so SIE_SEIE/SIE_SSIE
    // having been live since Phase 3 (arch_hardware_init) can no longer
    // walk a cross-hart IPI into `schedule()` on a hart that has not
    // called `sched::start()` yet.
    crate::entry::riscv64::SCHED_LIVE.store(true, core::sync::atomic::Ordering::Release);

    azos_drv_sys::timebase::set_next_tick(hart_id as u32);
    csr::write_sie(csr::read_sie() | csr::SIE_STIE);

    // Re-establish tp = hart_id immediately before entering the scheduler.
    // Rust functions called during kernel_main (including kprintln) may have used
    // tp as a caller-saved scratch register, corrupting current_cpu_id().
    // After this point no Rust functions are called before context_switch.S saves/restores tp.
    unsafe { core::arch::asm!("mv tp, {}", in(reg) hart_id, options(nostack, nomem)); }

    // Start the scheduler on the boot CPU (never returns).
    azos_sched::start()
}
