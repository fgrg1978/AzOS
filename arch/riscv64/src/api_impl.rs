// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Adapter — implements the cross-ISA [`azos_arch_api`]
//! traits in terms of the existing RISC-V modules in this crate.
//!
//! Pure additive: the legacy `cpu::*`, `mmu::*`, `firmware::*`
//! free-function APIs stay in place for in-crate callers (the
//! kernel still calls `cpu::read_satp()` directly today). This
//! adapter is the entry point for cross-ISA code that needs to
//! call arch through the trait surface — and for the upcoming
//! aarch64 / x86_64 ports, which will implement the same traits
//! over their own backends.
//!
//! See B0.2 commit message for the rationale.

use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    MemType, PagePerms, ArchId, Vector,
};

// ──────────────────────────────────────────────────────────────────────────
// Singleton marker type
// ──────────────────────────────────────────────────────────────────────────

/// ZST marker satisfying every arch-api trait family for RISC-V 64.
/// Held as a static so callers can pass `&RISCV64` wherever a
/// `&dyn Cpu` / `&dyn Mmu` / etc. is expected.
pub struct Riscv64;

/// Singleton instance. Use `&arch_impl::RISCV64` to drive the
/// cross-ISA API from in-tree code while the kernel continues to
/// call the legacy free-function modules directly.
pub static RISCV64: Riscv64 = Riscv64;

/// Architectural identifier surfaced through arch-api.
pub const ARCH_ID: ArchId = ArchId::Riscv64;

// ──────────────────────────────────────────────────────────────────────────
// Deep idle
// ──────────────────────────────────────────────────────────────────────────

use crate::firmware::{IdleLadder, SuspendState};
use core::sync::atomic::{AtomicU8, Ordering};

/// Per hart (indexed by the per-CPU base, the kernel's CPU id): the idle
/// states `cpu_idle(depth)` can enter. Empty until `install_idle_states`.
static IDLE_LADDERS: [IdleLadder; azos_limits::NR_CPUS] = [const { IdleLadder::EMPTY }; azos_limits::NR_CPUS];

/// Whether the firmware has `hart_suspend`: 0 not asked, 1 no, 2 yes.
static HART_SUSPEND: AtomicU8 = AtomicU8::new(0);

impl Riscv64 {
    /// Tell `cpu_idle` what the device tree's `cpu-idle-states` of CPU `cpu`
    /// are (depth 1 is `states[0]`). Returns the mask of depths that will be
    /// entered as themselves, bit `d - 1` for depth `d`; a depth outside it
    /// is entered as the deepest retentive state below it, or `wfi`. 0 when
    /// the firmware has no `hart_suspend` or `cpu` has no slot. Boot time,
    /// before the idle governor runs.
    pub fn install_idle_states(&self, cpu: usize, states: &[SuspendState]) -> u8 {
        let Some(ladder) = IDLE_LADDERS.get(cpu) else { return 0 };
        if HART_SUSPEND.load(Ordering::Relaxed) == 0 {
            let has = crate::firmware::hart_suspend_available();
            HART_SUSPEND.store(if has { 2 } else { 1 }, Ordering::Relaxed);
        }
        if HART_SUSPEND.load(Ordering::Relaxed) != 2 {
            return 0;
        }
        ladder.install(states)
    }

    /// The depths of CPU `cpu` that lose the hart's context (a non-retentive
    /// `hart_suspend`), bit `d - 1` for depth `d`; 0 until
    /// `install_idle_states`. The boot hands it to the energy model.
    pub fn idle_powerdown_depths(&self, cpu: usize) -> u8 {
        IDLE_LADDERS.get(cpu).map_or(0, IdleLadder::powerdown_mask)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Cpu
// ──────────────────────────────────────────────────────────────────────────

impl Cpu for Riscv64 {
    #[inline]
    fn hart_id(&self) -> usize {
        crate::cpu::hart_id()
    }

    #[inline]
    fn wait_for_interrupt(&self) {
        crate::cpu::wfi();
    }

    #[inline]
    fn cpu_idle(&self, depth: u8) -> u64 {
        // Depth 0, a depth with no enterable state, and a `hart_suspend` that
        // returns without sleeping are all `wfi`.
        let t0 = self.now_ticks();
        let slept = depth != 0
            && IDLE_LADDERS
                .get(self.percpu_base())
                .is_some_and(|l| l.enter(depth, crate::firmware::hart_suspend_retentive));
        if !slept {
            crate::cpu::wfi();
        }
        azos_arch_api::ticks_to_us(self.now_ticks().wrapping_sub(t0), azos_limits::TIMER_FREQ as u64)
    }

    #[inline]
    fn halt(&self) -> ! {
        loop {
            crate::cpu::wfi();
        }
    }

    #[inline]
    fn now_ticks(&self) -> u64 {
        // `rdtime`, the unprivileged read of the `time` CSR. Same instruction
        // `azos_drv_sys::timebase::now` issues — that module's name is
        // historical, it does not touch the CLINT's MMIO for this.
        //
        // Deliberately NOT a call into `azos_drv_*`: `arch` sits below
        // the driver crates, and an `arch -> drivers` edge to reach one
        // instruction would invert the dependency for nothing.
        let t: u64;
        unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
        t
    }

    #[inline(always)]
    fn percpu_base(&self) -> usize {
        let b: usize;
        unsafe { core::arch::asm!("mv {}, tp", out(reg) b, options(nomem, nostack, preserves_flags)) };
        b
    }

    #[inline(always)]
    fn set_percpu_base(&self, base: usize) {
        unsafe { core::arch::asm!("mv tp, {}", in(reg) base, options(nomem, nostack, preserves_flags)) };
    }

    #[inline(always)]
    fn qos_max_partition(&self) -> u16 {
        // Kconfig RV_SSQOSID = n: a constant 0, so the switch hook is not compiled.
        if !azos_arch_api::isa::riscv64::SSQOSID.allowed() {
            return 0;
        }
        crate::ext::ssqosid::max_partition()
    }

    #[inline]
    fn set_qos_tag(&self, partition: u16) -> bool {
        crate::ext::ssqosid::set_tag(partition)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Interrupts
// ──────────────────────────────────────────────────────────────────────────

impl Interrupts for Riscv64 {
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn disable_all(&self) -> InterruptState {
        let prev = crate::cpu::read_sstatus();
        crate::cpu::write_sstatus(prev & !crate::cpu::SSTATUS_SIE);
        #[cfg(feature = "lat-trace")]
        if prev & crate::cpu::SSTATUS_SIE != 0 {
            crate::lat_hook::irq_off(core::panic::Location::caller());
        }
        InterruptState(prev as u64)
    }

    /// Read-modify-write of `SIE` alone.
    ///
    /// **This wrote the whole saved `sstatus` back until 2026-09-21.** On
    /// aarch64 that shape is right — `DAIF` is a pure mask register. On
    /// RISC-V `sstatus` is shared: `SPIE`, `SPP`, `FS`, `SUM`, `MXR` and
    /// `SD` live in the same word, so a blanket write-back reverts anything
    /// that legitimately changed while interrupts were off.
    ///
    /// Unobservable in this tree today, and said plainly rather than
    /// dressed up as a fix with a rate: `arch/riscv64/src/cpu.rs`
    /// declares only `SSTATUS_SIE`, `SSTATUS_SPIE` and `SSTATUS_SPP`, and
    /// nothing writes the latter two inside a critical section. What makes
    /// it worth correcting now is that this function had **no production
    /// caller at all** until the `csr` call sites migrated onto it — so the
    /// over-broad version was about to acquire ~55 of them.
    ///
    /// The hand-written idiom in `sched::scheduler` and
    /// `sync::IrqSaveGuard::drop` was already the careful one; this brings
    /// the trait in line with the code it replaces, not the other way round.
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn restore(&self, prev: InterruptState) {
        let current = crate::cpu::read_sstatus();
        let sie = crate::cpu::SSTATUS_SIE;
        #[cfg(feature = "lat-trace")]
        if current & sie == 0 && (prev.0 as usize) & sie != 0 {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        crate::cpu::write_sstatus((current & !sie) | ((prev.0 as usize) & sie));
    }

    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn enable_all(&self) {
        #[cfg(feature = "lat-trace")]
        if crate::cpu::read_sstatus() & crate::cpu::SSTATUS_SIE == 0 {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        // One `csrsi` instead of `csrr`/`or`/`csrw`: the same bit set, and
        // atomic, so no other `sstatus` bit is written back (SYSFLOOR: this
        // runs on every syscall).
        unsafe {
            core::arch::asm!("csrsi sstatus, {0}", const crate::cpu::SSTATUS_SIE, options(nostack));
        }
    }

    #[inline]
    fn interrupts_enabled(&self) -> bool {
        crate::cpu::read_sstatus() & crate::cpu::SSTATUS_SIE != 0
    }

    #[inline]
    fn set_timer_deadline(&self, deadline_ticks: u64) {
        // The `stimecmp` CSR when the boot selected Sstc, else SBI `set_timer`
        // (`irq::clint::timer_select`); the hart argument is unused, both are per hart.
        crate::irq::clint::set_timer(0, deadline_ticks);
    }

    #[inline]
    fn send_ipi(&self, target_hart: usize) {
        // `target_hart` is a logical CPU id; the SBI IPI takes the hart's
        // hardware id, which `firmware::send_ipi` looks up.
        let _ = crate::firmware::send_ipi(target_hart);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Mmu
// ──────────────────────────────────────────────────────────────────────────

// RISC-V allows an ISA impl to ignore `level` for leaf/table
// classification (Sv39: R|W|X on the word decides leaf-ness at any
// level), so most methods below take it only to satisfy the trait
// shape aarch64 genuinely needs it for. `#[inline]` on every one: this
// workspace builds with `lto = false` (see `arch/facade/src/lib.rs`),
// so an un-inlined trait call here would be a real cross-crate call on
// every page-table write.
impl Mmu for Riscv64 {
    const PAGE_SIZE: usize = crate::mmu::PAGE_SIZE;

    #[inline]
    fn levels(&self) -> usize { 3 }

    #[inline]
    fn entries_per_table(&self) -> usize { crate::mmu::PT_ENTRIES }

    #[inline]
    fn vpn(&self, va: usize, level: usize) -> usize {
        match level {
            0 => crate::mmu::vpn0(va),
            1 => crate::mmu::vpn1(va),
            _ => crate::mmu::vpn2(va),
        }
    }

    /// No break-before-make: RISC-V defines no TLB conflict abort, and a
    /// table-to-block change of the same map is allowed with an
    /// `sfence.vma` after it (the shootdown `promote_finish` does).
    #[inline]
    fn block_change_needs_bbm(&self) -> bool { false }

    /// Svnapot's 64 KiB run, when the probe found the extension and the
    /// Kconfig policy allows it (`ext::napot::select`).
    #[inline]
    fn contig_run_pages(&self) -> usize {
        if crate::ext::napot::on() { crate::ext::napot::NAPOT_PAGES } else { 0 }
    }

    /// Every member of a NAPOT run is the same word (`index` is unused).
    #[inline]
    fn pte_make_contig_leaf(&self, run_pa: usize, _index: usize, perms: PagePerms) -> Result<u64, MmuError> {
        if !crate::ext::napot::on() {
            return Err(MmuError::UnrepresentablePerms);
        }
        if run_pa & (crate::ext::napot::NAPOT_SIZE - 1) != 0 {
            return Err(MmuError::NotAligned);
        }
        Ok(crate::ext::napot::make_64k(run_pa, riscv_leaf_flags(perms)))
    }

    #[inline]
    fn pte_is_contig(&self, word: u64) -> bool { crate::ext::napot::is_napot(word) }

    #[inline]
    fn pte_contig_member(&self, word: u64, index: usize) -> u64 { crate::ext::napot::member(word, index) }

    /// A NAPOT word's PPN names the run, so the offset is taken modulo 64 KiB.
    #[inline]
    fn pte_leaf0_span(&self, word: u64) -> usize {
        if crate::ext::napot::is_napot(word) { crate::ext::napot::NAPOT_SIZE } else { crate::mmu::PAGE_SIZE }
    }

    #[inline]
    fn pte_empty(&self) -> u64 {
        crate::mmu::Pte::empty().0
    }

    #[inline]
    fn pte_is_valid(&self, word: u64) -> bool {
        crate::mmu::Pte(word).is_valid()
    }

    #[inline]
    fn pte_is_table(&self, word: u64, _level: usize) -> bool {
        let p = crate::mmu::Pte(word);
        p.is_valid() && !p.is_leaf()
    }

    #[inline]
    fn pte_is_leaf(&self, word: u64, _level: usize) -> bool {
        crate::mmu::Pte(word).is_leaf()
    }

    #[inline]
    fn pte_phys(&self, word: u64) -> usize {
        crate::mmu::Pte(word).phys_addr()
    }

    #[inline]
    fn pte_make_table(&self, pa: usize) -> u64 {
        crate::mmu::Pte::new(pa, crate::mmu::PteFlags::VALID).0
    }

    #[inline]
    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, _level: usize) -> Result<u64, MmuError> {
        if pa & (Self::PAGE_SIZE - 1) != 0 {
            return Err(MmuError::NotAligned);
        }
        Ok(crate::mmu::Pte::new(pa, riscv_leaf_flags(perms)).0)
    }

    #[inline]
    fn pte_global_bit(&self) -> u64 {
        crate::mmu::PteFlags::GLOBAL.bits()
    }

    #[inline]
    fn pte_perms(&self, word: u64) -> PagePerms {
        let f = crate::mmu::Pte(word).flags();
        PagePerms {
            read:  f.contains(crate::mmu::PteFlags::READ),
            write: f.contains(crate::mmu::PteFlags::WRITE),
            exec:  f.contains(crate::mmu::PteFlags::EXEC),
            user:  f.contains(crate::mmu::PteFlags::USER),
            mem: mem_of(f),
            accessed: f.contains(crate::mmu::PteFlags::ACCESSED),
            dirty:    f.contains(crate::mmu::PteFlags::DIRTY),
        }
    }

    #[inline]
    fn pte_is_cow(&self, word: u64) -> bool {
        crate::mmu::is_cow(word)
    }

    #[inline]
    fn pte_share_cow(&self, word: u64) -> u64 {
        let p = crate::mmu::Pte(word);
        let flags = (p.flags() - crate::mmu::PteFlags::WRITE) | crate::mmu::PteFlags::COW;
        crate::mmu::Pte::new(p.phys_addr(), flags).0
    }

    #[inline]
    fn pte_break_cow(&self, word: u64) -> u64 {
        let p = crate::mmu::Pte(word);
        let flags = (p.flags() - crate::mmu::PteFlags::COW)
            | crate::mmu::PteFlags::WRITE
            | crate::mmu::PteFlags::DIRTY;
        crate::mmu::Pte::new(p.phys_addr(), flags).0
    }

    #[inline]
    fn pte_make_demand(&self, perms: PagePerms) -> u64 {
        // VALID = 0 (never set below), DEMAND set, desired flags stored
        // in-line for `pte_demand_perms` to recover at fault time.
        crate::mmu::PteFlags::DEMAND.bits() | riscv_leaf_flags_no_valid(perms)
    }

    #[inline]
    fn pte_make_marker(&self, kind: azos_arch_api::PageMarker, payload: u32) -> u64 {
        crate::mmu::make_marker(kind.code(), payload)
    }

    #[inline]
    fn pte_marker(&self, word: u64) -> Option<(azos_arch_api::PageMarker, u32)> {
        let (code, payload) = crate::mmu::marker_of(word)?;
        Some((azos_arch_api::PageMarker::from_code(code)?, payload))
    }

    #[inline]
    fn pte_is_demand(&self, word: u64) -> bool {
        word & crate::mmu::PteFlags::DEMAND.bits() != 0
    }

    #[inline]
    fn pte_demand_perms(&self, word: u64) -> PagePerms {
        let f = crate::mmu::PteFlags::from_bits_truncate(
            word & !crate::mmu::PteFlags::DEMAND.bits(),
        );
        PagePerms {
            read:  f.contains(crate::mmu::PteFlags::READ),
            write: f.contains(crate::mmu::PteFlags::WRITE),
            exec:  f.contains(crate::mmu::PteFlags::EXEC),
            user:  f.contains(crate::mmu::PteFlags::USER),
            mem: mem_of(f),
            accessed: f.contains(crate::mmu::PteFlags::ACCESSED),
            dirty:    f.contains(crate::mmu::PteFlags::DIRTY),
        }
    }

    #[inline]
    fn switch_pt(&self, root_phys: usize, asid: u16) {
        // `write_satp` already emits `sfence.vma zero, zero` (see
        // `cpu::write_satp`) — no second fence here. That used to be a
        // second full TLB flush on every address-space switch.
        let satp = crate::mmu::make_satp(root_phys, asid);
        crate::cpu::write_satp(satp);
    }

    /// riscv64 has ONE translation register: the kernel's table and a task's
    /// table are both `satp`, so this is `switch_pt` with ASID 0. Kept as a
    /// distinct method only so `crates/core/mm` can say which of the two it means.
    #[inline]
    fn switch_kernel_pt(&self, root_phys: usize) {
        self.switch_pt(root_phys, 0);
    }

    #[inline]
    fn flush_tlb_all(&self) {
        // The flush and the hart left out of the stale marks are one window:
        // marking every hart but the one that did NOT flush would leave a
        // stale hart unmarked.
        let irq = self.disable_all();
        crate::cpu::sfence_vma();
        // Local only: harts that ran an address space earlier keep its
        // entries under retained ASIDs (Kconfig `TLB_RETAIN`).
        azos_arch_api::tlb_gen::mark_all_stale(crate::cpu::hart_id());
        self.restore(irq);
    }

    #[inline]
    fn flush_tlb_asid(&self, _asid: u16) {
        // RISC-V SFENCE.VMA with rs2 != 0 selects by ASID, but the
        // existing `cpu::sfence_vma()` flushes all. A per-ASID
        // variant is a follow-up; flushing all preserves
        // correctness at the cost of TLB pressure.
        crate::cpu::sfence_vma();
    }

    /// The privileged spec's ASIDLEN probe: satp.ASID (bits 59:44) is WARL,
    /// so all-ones written reads back as the bits the hart implements. The
    /// root and mode are kept, the old word is restored, and the TLB is
    /// flushed (`satp` is not republished: the root never changes here).
    fn asid_bits(&self) -> u32 {
        let old = crate::cpu::read_satp();
        if old >> 60 == 0 {
            return 0; // Bare: no translation, nothing to probe
        }
        let back: usize;
        // SAFETY: same root and mode as the live word; only the ASID tag
        // changes, and the full flush drops any entry tagged with the probe.
        unsafe {
            core::arch::asm!(
                "csrw satp, {probe}",
                "csrr {back}, satp",
                "csrw satp, {old}",
                "sfence.vma zero, zero",
                probe = in(reg) old | (0xFFFF << 44),
                back = out(reg) back,
                old = in(reg) old,
                options(nostack),
            );
        }
        ((back >> 44) & 0xFFFF).count_ones()
    }

    #[inline]
    fn flush_tlb_page(&self, va: usize) {
        // One window, as `flush_tlb_all`.
        let irq = self.disable_all();
        crate::cpu::sfence_vma_addr(va);
        // `sfence.vma va, zero` covers every ASID, but only here: a hart
        // that ran this address space and left keeps the entry under its
        // retained ASID, so it flushes at its next switch (`TLB_RETAIN`).
        azos_arch_api::tlb_gen::mark_all_stale(crate::cpu::hart_id());
        self.restore(irq);
    }

    #[inline]
    fn tlb_shootdown(&self, root_phys: usize, va: usize, len: usize) -> usize {
        crate::tlb::shootdown(root_phys, va, len)
    }

    #[inline]
    fn root_holders(&self, root_phys: usize) -> usize {
        crate::tlb::holders(root_phys)
    }

    #[inline]
    fn pte_accessed_bit(&self) -> u64 { crate::mmu::PteFlags::ACCESSED.bits() }

    #[inline]
    fn accessed_in_hardware(&self) -> bool { crate::mmu::svadu_on() }
}

/// The memory type a leaf's Svpbmt field names. `WC` and `NC` share one
/// encoding, so a leaf mapped `WC` reads back `NC`.
#[inline]
fn mem_of(f: crate::mmu::PteFlags) -> MemType {
    if f.contains(crate::mmu::PteFlags::PBMT_IO) { MemType::Device }
    else if f.contains(crate::mmu::PteFlags::PBMT_NC) { MemType::NC }
    else { MemType::WB }
}

/// Shared flag-building body for [`Riscv64::pte_make_leaf`] and
/// [`Riscv64::pte_make_demand`] (which stores the same bits minus
/// `VALID`). The memory type becomes the Svpbmt field when the extension
/// is on; Sv39 has no other cacheability bit (PMAs govern it).
#[inline]
fn riscv_leaf_flags_no_valid(perms: PagePerms) -> u64 {
    let mut flags = crate::mmu::PteFlags::empty();
    if perms.read  { flags |= crate::mmu::PteFlags::READ; }
    if perms.write { flags |= crate::mmu::PteFlags::WRITE; }
    if perms.exec  { flags |= crate::mmu::PteFlags::EXEC; }
    if perms.user  { flags |= crate::mmu::PteFlags::USER; }
    if perms.accessed { flags |= crate::mmu::PteFlags::ACCESSED; }
    if perms.dirty     { flags |= crate::mmu::PteFlags::DIRTY; }
    flags.bits()
        | crate::mmu::pbmt_bits(
            matches!(perms.mem, MemType::WC | MemType::NC),
            matches!(perms.mem, MemType::Device),
        )
}

#[inline]
fn riscv_leaf_flags(perms: PagePerms) -> crate::mmu::PteFlags {
    crate::mmu::PteFlags::VALID
        | crate::mmu::PteFlags::from_bits_truncate(riscv_leaf_flags_no_valid(perms))
}

// ──────────────────────────────────────────────────────────────────────────
// Boot
// ──────────────────────────────────────────────────────────────────────────

impl Boot for Riscv64 {
    #[inline]
    fn shutdown(&self) -> ! {
        crate::firmware::shutdown()
    }

    #[inline]
    fn reboot(&self) -> ! {
        crate::firmware::reboot()
    }

    #[inline]
    fn hart_start(
        &self,
        hart_id: usize,
        start_pc: usize,
        opaque: usize,
    ) -> Result<(), HartStartError> {
        // `hart_id` is the logical CPU id (`firmware::hart_start` maps it to the
        // hardware hart). SBI HSM hart_start returns 0 on success; negative on
        // error. RISC-V SBI doesn't surface a clean
        // AlreadyOn/InvalidHartId split, so we collapse all errors
        // into `Other(rc as i32)` so the caller can log the raw
        // SBI return code.
        let rc = crate::firmware::hart_start(hart_id, start_pc, opaque);
        if rc == 0 {
            Ok(())
        } else {
            Err(HartStartError::Other(rc as i32))
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Vector (B0.3)
// ──────────────────────────────────────────────────────────────────────────
//
// The Vector trait is a **build-time** dispatch on RISC-V: the
// `rvv` Cargo feature is set per platform (k1 enables it via the
// SpacemiT K1's RVV 1.0; QEMU rv64,v=true enables it via `rvv`).
// When the feature is off (QEMU default / VF2), we delegate to
// the scalar fallback that already exists in `crate::fp`.
//
// A *runtime* probe (read `misa` CSR, check bit 'V') would let
// one binary run on both V-capable and V-less harts; that's a
// follow-up. The build-time form is correct today because every
// `--features qemu/vf2/k1/no-ml` config is for a single
// known target hart family.

impl Vector for Riscv64 {
    #[inline]
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
        #[cfg(feature = "rvv")]
        if crate::fp::usable() {
            return crate::fp::dot_f32_rvv(a, b);
        }
        crate::fp::dot_f32_scalar(a, b)
    }
}
// ── Ring-3 port I/O ─────────────────────────────────────────────────────────
//
// No port space: devices are memory-mapped, and ring 3 reaches them through
// `DOMAIN_MMIO_MAP`. The defaults load nothing, and the op that opens ports
// answers -ENODEV before it looks at a handle (`azos_arch_api::ioport`).
impl azos_arch_api::IoPorts for Riscv64 {}
