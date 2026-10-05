// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch`, used only by `tests/host/syscall-tests`.
//!
//! `mmu` re-exports the real Sv39 module rather than stubbing it, same
//! reasoning and same file `tests/host/mm-tests` already relies on: it is pure
//! arithmetic, and the mmap/munmap handlers in `handlers.rs` compute page
//! numbers with the kernel's own `PAGE_SIZE`/`PteFlags`, not a copy that can
//! drift. `sbi` is real CSR/SBI calls with no host meaning, so it is
//! `todo!()` — nothing in this crate's three test targets reaches it.

#[path = "../../../../../../crates/core/arch-riscv64/src/mmu.rs"]
pub mod mmu;

/// Host stand-in for `azos_arch::cbo` (RFC-0045 Tier 0 item 3), needed
/// because `tests/host/syscall-tests/shims/mm` pulls the **real** `demand.rs`
/// and `vdso.rs`, and both zero a fresh page through this module.
///
/// Unlike the `csr` stand-ins below this is not `todo!()`: the demand-fault
/// path under test really does zero the page it hands to the caller, and
/// that zeroing is load-bearing (a demand page must never carry stale
/// bytes). Faking it cannot make a wrong answer look right either — the
/// real module's own behavior on a target with no Zicboz to probe is
/// exactly this `write_bytes`, so the host takes the same branch a board
/// without the extension takes.
pub mod cbo {
    /// See the module doc: the real dispatcher's scalar fallback branch.
    ///
    /// # Safety
    /// Same contract as `core::ptr::write_bytes(addr, 0, len)`.
    pub unsafe fn zero_memory(addr: usize, len: usize) {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
    }
}

/// Host stand-in for the S-mode CSR accessors, needed because
/// `tests/host/syscall-tests/shims/mm` pulls the **real** `vmm.rs`/`cow.rs`/
/// `demand.rs`, and those call `sfence.vma` and touch `satp`.
///
/// **These are the only faked things on the mmap/munmap path, and faking
/// them cannot make a wrong answer look right.** `sfence.vma` invalidates
/// TLB entries; nothing on a host reads memory *through* a translation, and
/// every walker in `vmm.rs` reads the PTE array directly with
/// `read_volatile`, so a skipped shootdown is unobservable here. `satp` is
/// recorded rather than dropped so `vmm::switch_pagetable` remains
/// inspectable, and `read_satp` returns what was last written instead of a
/// constant — a stub returning 0 would make `kernel_pagetable()` claim the
/// kernel root is page 0.
///
/// Everything else in the real `csr.rs` (stvec/sie/sstatus/sscratch/…) is
/// trap-delivery state that no `handlers.rs` path under test reaches; those
/// are `todo!()` rather than no-ops so a future test that does reach one
/// fails loudly instead of silently observing a fabricated CSR.
pub mod csr {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SATP: AtomicUsize = AtomicUsize::new(0);

    pub fn read_satp() -> usize {
        SATP.load(Ordering::SeqCst)
    }
    pub fn write_satp(val: usize) {
        SATP.store(val, Ordering::SeqCst);
    }
    /// No-op: see the module doc for why a skipped TLB flush is unobservable
    /// on a host.
    pub fn sfence_vma() {}
    /// No-op: see the module doc.
    pub fn sfence_vma_addr(_vaddr: usize) {}

    pub fn read_sstatus() -> usize {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn write_sstatus(_val: usize) {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn read_stvec() -> usize {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn write_stvec(_val: usize) {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn read_sie() -> usize {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn write_sie(_val: usize) {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn write_sscratch(_val: usize) {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn write_scounteren(_val: usize) {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
    pub fn clear_sip_ssip() {
        todo!("CSR stand-in: not reached by any test in this crate")
    }
}

pub mod sbi {
    pub fn reboot() -> ! {
        todo!("SBI stand-in: not reached by any test in this crate")
    }
    pub fn shutdown() -> ! {
        todo!("SBI stand-in: not reached by any test in this crate")
    }
}

// ── `Mmu` singleton ──────────────────────────────────────────────────────
//
// `vmm.rs`/`cow.rs`/`demand.rs` (pulled by path into `shims/mm`) reach the
// active ISA through `azos_arch::ARCH` + `azos_arch_api::Mmu`, not
// through the free-function `mmu`/`csr` modules above directly any more —
// see `crates/core/mm/src/vmm.rs`'s module doc (page-table abstraction, B2).
// This is the same body as `arch-riscv64/src/api_impl.rs`'s `impl Mmu for
// Riscv64`, over this shim's own `mmu`/`csr` modules (both real,
// path-pulled above) instead of `crate::mmu`/`crate::csr` in that crate —
// intentionally duplicated rather than path-pulled, because `api_impl.rs`
// also implements `Cpu`/`Interrupts`/`Boot`/`Vector` over `crate::cpu`/
// `crate::sbi`/`crate::rvv`, none of which this shim has or needs (no test
// here reaches them). If `arch-riscv64::api_impl`'s `Mmu` body changes,
// this one must change with it — same obligation the module doc above
// already states for `mmu`/`csr`.
use azos_arch_api::{Mmu, MmuError, PagePerms};

pub struct Arch;
pub static ARCH: Arch = Arch;

/// The page-table root whose shootdowns [`SHOOTDOWNS_ON_WATCHED_ROOT`] counts
/// (0: none). Per root, so a test running beside others counts only its own.
pub static SHOOTDOWN_WATCH_ROOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// `tlb_shootdown` calls made against [`SHOOTDOWN_WATCH_ROOT`].
pub static SHOOTDOWNS_ON_WATCHED_ROOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// A root the shim reports as still live on "hart 2" (0: none), so a test can
/// drive the page-table free into its refusal.
pub static LIVE_ROOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

impl Mmu for Arch {
    const PAGE_SIZE: usize = mmu::PAGE_SIZE;

    fn levels(&self) -> usize { 3 }
    fn entries_per_table(&self) -> usize { mmu::PT_ENTRIES }

    fn vpn(&self, va: usize, level: usize) -> usize {
        match level {
            0 => mmu::vpn0(va),
            1 => mmu::vpn1(va),
            _ => mmu::vpn2(va),
        }
    }

    fn pte_empty(&self) -> u64 { mmu::Pte::empty().0 }
    fn pte_is_valid(&self, word: u64) -> bool { mmu::Pte(word).is_valid() }
    fn pte_is_table(&self, word: u64, _level: usize) -> bool {
        let p = mmu::Pte(word);
        p.is_valid() && !p.is_leaf()
    }
    fn pte_is_leaf(&self, word: u64, _level: usize) -> bool { mmu::Pte(word).is_leaf() }
    fn pte_phys(&self, word: u64) -> usize { mmu::Pte(word).phys_addr() }
    fn pte_make_table(&self, pa: usize) -> u64 {
        mmu::Pte::new(pa, mmu::PteFlags::VALID).0
    }

    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, _level: usize) -> Result<u64, MmuError> {
        if pa & (Self::PAGE_SIZE - 1) != 0 { return Err(MmuError::NotAligned); }
        Ok(mmu::Pte::new(pa, leaf_flags(perms)).0)
    }

    fn pte_perms(&self, word: u64) -> PagePerms {
        let f = mmu::Pte(word).flags();
        PagePerms {
            read: f.contains(mmu::PteFlags::READ),
            write: f.contains(mmu::PteFlags::WRITE),
            exec: f.contains(mmu::PteFlags::EXEC),
            user: f.contains(mmu::PteFlags::USER),
            cache: true,
            accessed: f.contains(mmu::PteFlags::ACCESSED),
            dirty: f.contains(mmu::PteFlags::DIRTY),
        }
    }

    fn pte_is_cow(&self, word: u64) -> bool {
        mmu::Pte(word).flags().contains(mmu::PteFlags::COW)
    }
    fn pte_share_cow(&self, word: u64) -> u64 {
        let p = mmu::Pte(word);
        let flags = (p.flags() - mmu::PteFlags::WRITE) | mmu::PteFlags::COW;
        mmu::Pte::new(p.phys_addr(), flags).0
    }
    fn pte_break_cow(&self, word: u64) -> u64 {
        let p = mmu::Pte(word);
        let flags = (p.flags() - mmu::PteFlags::COW) | mmu::PteFlags::WRITE | mmu::PteFlags::DIRTY;
        mmu::Pte::new(p.phys_addr(), flags).0
    }

    fn pte_make_demand(&self, perms: PagePerms) -> u64 {
        mmu::PteFlags::DEMAND.bits() | leaf_flags_no_valid(perms)
    }
    fn pte_is_demand(&self, word: u64) -> bool {
        word & mmu::PteFlags::DEMAND.bits() != 0
    }
    fn pte_demand_perms(&self, word: u64) -> PagePerms {
        let f = mmu::PteFlags::from_bits_truncate(word & !mmu::PteFlags::DEMAND.bits());
        PagePerms {
            read: f.contains(mmu::PteFlags::READ),
            write: f.contains(mmu::PteFlags::WRITE),
            exec: f.contains(mmu::PteFlags::EXEC),
            user: f.contains(mmu::PteFlags::USER),
            cache: true,
            accessed: f.contains(mmu::PteFlags::ACCESSED),
            dirty: f.contains(mmu::PteFlags::DIRTY),
        }
    }

    fn switch_pt(&self, root_phys: usize, asid: u16) {
        csr::write_satp(mmu::make_satp(root_phys, asid));
    }
    /// Mirrors the riscv64 implementation: one register for both halves.
    fn switch_kernel_pt(&self, root_phys: usize) {
        self.switch_pt(root_phys, 0);
    }

    fn flush_tlb_all(&self) { csr::sfence_vma(); }
    fn flush_tlb_asid(&self, _asid: u16) { csr::sfence_vma(); }
    fn flush_tlb_page(&self, va: usize) { csr::sfence_vma_addr(va); }
    /// No remote harts on the host: the local part is the no-op above. Counts
    /// the calls against [`SHOOTDOWN_WATCH_ROOT`] so a test can pin how many
    /// shootdowns an operation costs.
    fn tlb_shootdown(&self, root_phys: usize, _va: usize, _len: usize) -> usize {
        use core::sync::atomic::Ordering;
        if root_phys != 0 && SHOOTDOWN_WATCH_ROOT.load(Ordering::SeqCst) == root_phys {
            SHOOTDOWNS_ON_WATCHED_ROOT.fetch_add(1, Ordering::SeqCst);
        }
        0
    }
    fn root_holders(&self, root_phys: usize) -> usize {
        use core::sync::atomic::Ordering;
        if root_phys != 0 && LIVE_ROOT.load(Ordering::SeqCst) == root_phys { 1 << 2 } else { 0 }
    }
}

fn leaf_flags_no_valid(perms: PagePerms) -> u64 {
    let mut flags = mmu::PteFlags::empty();
    if perms.read  { flags |= mmu::PteFlags::READ; }
    if perms.write { flags |= mmu::PteFlags::WRITE; }
    if perms.exec  { flags |= mmu::PteFlags::EXEC; }
    if perms.user  { flags |= mmu::PteFlags::USER; }
    if perms.accessed { flags |= mmu::PteFlags::ACCESSED; }
    if perms.dirty     { flags |= mmu::PteFlags::DIRTY; }
    flags.bits()
}

fn leaf_flags(perms: PagePerms) -> mmu::PteFlags {
    mmu::PteFlags::VALID | mmu::PteFlags::from_bits_truncate(leaf_flags_no_valid(perms))
}

// `Interrupts`: the real `vdso.rs` (pulled by path into `shims/mm`) masks
// interrupts around its seqlock write since wave 13 (RT7). The host has no
// interrupts, so the enable bit is a per-thread flag: `disable_all` clears it
// and returns the previous value, `restore` puts that value back. Modelled
// rather than no-op'd so a test could still see an unbalanced pair.
pub use azos_arch_api::{InterruptState, Interrupts};

std::thread_local! {
    static IRQ_ON: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
}

impl Interrupts for Arch {
    fn disable_all(&self) -> InterruptState {
        InterruptState(IRQ_ON.with(|on| on.replace(false)) as u64)
    }
    fn restore(&self, prev: InterruptState) {
        IRQ_ON.with(|on| on.set(prev.0 != 0));
    }
    fn enable_all(&self) {
        IRQ_ON.with(|on| on.set(true));
    }
    fn interrupts_enabled(&self) -> bool {
        IRQ_ON.with(|on| on.get())
    }
    fn set_timer_deadline(&self, _deadline_ticks: u64) {
        todo!("timer stand-in: not reached by any test in this crate")
    }
    fn send_ipi(&self, _target_hart: usize) {
        todo!("IPI stand-in: not reached by any test in this crate")
    }
}
