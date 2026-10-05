// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_arch_api` — the cross-ISA trait
//! surface every per-ISA impl crate satisfies.
//!
//! The traits themselves are abstract — the value-adds we can pin
//! from the host are:
//!
//! - `PagePerms` named constants represent the layouts the kernel
//!   actually requests, so changing one would silently break MMU
//!   programming on every ISA.
//! - `arch_name(ArchId)` is the string the kernel prints in procfs
//!   and the OTA manifest — a typo here breaks operational tools.
//! - `ArchId::Stub` exists specifically for host tests of code
//!   that depends on the trait shape; we exercise it here so the
//!   variant doesn't get accidentally removed.
//! - A `Stub` impl that satisfies all five traits proves the trait
//!   surface is dyn-compatible and self-consistent (no
//!   unintentionally-required `Self: Sized` or duplicated methods).
//!
//! `aarch64_mmu` below pulls in the REAL VMSAv8-64 encoding module,
//! `crates/core/arch-aarch64/src/mmu.rs` — it is pure arithmetic (no asm, no
//! `#[cfg(target_arch = ...)]` gate), so unlike `api_impl.rs` it is safe
//! to link on the host and exercises the actual bit-level encoding the
//! aarch64 port builds page tables with, not a copy that can drift.
//!
//! `aarch64_vector` below pulls in the REAL NEON kernel,
//! `crates/core/arch-aarch64/src/vector.rs`, the same way — this one works for a
//! different reason than `mmu.rs`: it DOES carry `#[cfg(target_arch =
//! "aarch64")]` on the NEON-specific items, but this host toolchain runs on
//! `aarch64-apple-darwin`, so that cfg is true here too and the real
//! `core::arch::aarch64` intrinsics compile and execute natively — no
//! emulation, no shim. Confirmed empirically (2026-09-22): a throwaway probe
//! that reads `ID_AA64PFR0_EL1` via `mrs` from this host process takes
//! SIGILL (exit 132) — EL0 on macOS does not emulate ID-register reads the
//! way Linux does. That is why the tests below call `dot_f32_neon` and
//! `dot_f32_scalar` directly and never `has_sve`/`dot_f32_best`/
//! `active_backend`, which read that register — calling those from a host
//! test would crash the test binary, not fail an assertion.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/mmu.rs"]
mod aarch64_mmu;

// Phase 4 PREP (SMP building blocks) — three more arch-aarch64 files pulled
// the same way `aarch64_mmu` is above: none of the three has any
// `use crate::...` cross-reference (checked — each is self-contained), so
// pulling them standalone under these renamed modules is safe the same way
// `aarch64_mmu` already is. What's new here is that ALL THREE also contain
// `#[cfg(target_arch = "aarch64")]`-gated `core::arch::asm!` bodies (MMIO
// reads, `hvc`/`smc`, `mrs`/`msr` on EL1-only system registers) alongside
// the pure decode/encode functions the tests below actually exercise —
// and this crate's own `.cargo/config.toml` pins `aarch64-apple-darwin` as
// its build target, so on an Apple Silicon dev machine `target_arch =
// "aarch64"` is TRUE and those gated bodies DO get compiled here (LLVM
// assembles them fine — they're valid AArch64 encodings regardless of
// OS). That's fine to COMPILE; it would not be fine to CALL, since EL1
// sysreg reads are illegal instructions at EL0 under macOS (see
// `arch-aarch64::features`'s header comment for this project's own prior
// case of exactly that crash). Every test below calls ONLY the pure,
// `target_arch`-ungated functions (`typer_affinity_key`, `sgi1r_encode`,
// `mpidr_affinity_key`, `decode_cpu_on`, ...) and never `read_mpidr`,
// `find_redistributor`, `send_sgi`, `cpu_on`, or anything else that
// touches real hardware.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/mpidr.rs"]
mod aarch64_mpidr;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/gic.rs"]
mod aarch64_gic;

// `its.rs` below is a REAL cross-reference (`use crate::gic;`), unlike
// `aarch64_mpidr`/`aarch64_gic`/`aarch64_psci`/`aarch64_vector` above,
// which the comment on this file's first `#[path]` pull confirms are
// each self-contained. Aliasing `crate::gic` to the `aarch64_gic` pull
// above (rather than editing `its.rs`'s import to something
// test-crate-specific) is what lets the exact same file compile in both
// places — the real crate's `lib.rs` has `pub mod gic;` at the same
// crate-root position this alias recreates here.
#[allow(dead_code)]
use crate::aarch64_gic as gic;
// Same reason, second edge: `its.rs::kva_to_pa` reads
// `crate::mmu::KERNEL_VA_OFFSET` (the kernel runs in the TTBR1 upper half).
#[allow(dead_code)]
use crate::aarch64_mmu as mmu;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/its.rs"]
mod aarch64_its;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/psci.rs"]
mod aarch64_psci;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/vector.rs"]
mod aarch64_vector;

#[cfg(test)]
mod tests {
    use azos_arch_api::{
        arch_name, ArchId, Boot, Cpu, HartStartError, InterruptState,
        Interrupts, Mmu, MmuError, PagePerms, Vector,
    };

    // ── PagePerms named constants ──────────────────────────────

    #[test]
    fn page_perms_kernel_rw_is_no_exec_no_user() {
        let p = PagePerms::KERNEL_RW;
        assert!(p.read);
        assert!(p.write);
        assert!(!p.exec, "KERNEL_RW must not be executable (W^X)");
        assert!(!p.user, "KERNEL_RW must not be userspace-accessible");
        assert!(p.cache, "KERNEL_RW is normal cacheable memory");
    }

    #[test]
    fn page_perms_kernel_rx_is_no_write() {
        let p = PagePerms::KERNEL_RX;
        assert!(p.read);
        assert!(!p.write, "KERNEL_RX must not be writable (W^X)");
        assert!(p.exec);
        assert!(!p.user);
        assert!(p.cache);
    }

    #[test]
    fn page_perms_user_rw_is_no_exec_with_user() {
        let p = PagePerms::USER_RW;
        assert!(p.read);
        assert!(p.write);
        assert!(!p.exec, "USER_RW must not be executable (W^X)");
        assert!(p.user, "USER_RW must allow userspace access");
        assert!(p.cache);
    }

    #[test]
    fn page_perms_user_rx_is_no_write_with_user() {
        let p = PagePerms::USER_RX;
        assert!(p.read);
        assert!(!p.write, "USER_RX must not be writable (W^X)");
        assert!(p.exec);
        assert!(p.user);
        assert!(p.cache);
    }

    /// A user driver's device window must encode as DEVICE memory on
    /// aarch64, through the real VMSAv8 encoder — the bug was a cacheable
    /// `USER_RW` handed to `mmio_map_user`, which that encoder turns into
    /// MAIR Normal write-back.
    #[test]
    fn user_mmio_windows_encode_as_device_memory() {
        for (p, w) in [(PagePerms::USER_MMIO_RW, true), (PagePerms::USER_MMIO_RO, false)] {
            assert!(p.user && p.read && !p.exec);
            assert_eq!(p.write, w);
            assert!(!p.cache, "a user MMIO window must be uncached");
            let word = crate::mmu::make_leaf(0x0900_0000, p, 0).expect("encodable");
            let back = crate::mmu::perms_of(word);
            assert!(!back.cache, "aarch64 leaf for a user MMIO window is Normal memory");
            assert!(back.user && !back.exec);
        }
        // The pre-fix permission, through the same encoder, IS cacheable —
        // the test would have caught it.
        let old = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
        assert!(crate::mmu::perms_of(crate::mmu::make_leaf(0x0900_0000, old, 0).unwrap()).cache);
    }

    #[test]
    fn page_perms_mmio_is_uncached() {
        let p = PagePerms::MMIO;
        assert!(p.read);
        assert!(p.write);
        assert!(!p.exec, "MMIO must not be executable");
        assert!(!p.user, "MMIO must be kernel-only");
        assert!(!p.cache, "MMIO must be uncached (device memory)");
    }

    #[test]
    fn page_perms_kernel_ro_is_no_write_no_exec() {
        let p = PagePerms::KERNEL_RO;
        assert!(p.read);
        assert!(!p.write);
        assert!(!p.exec);
        assert!(!p.user);
        assert!(p.accessed, "KERNEL_RO presets Accessed (software-managed A/D)");
        assert!(!p.dirty, "a read-only page is never dirty");
    }

    #[test]
    fn page_perms_kernel_rwx_is_the_coarse_identity_map_permission() {
        let p = PagePerms::KERNEL_RWX;
        assert!(p.read && p.write && p.exec);
        assert!(!p.user);
        assert!(p.accessed && p.dirty);
    }

    #[test]
    fn page_perms_user_ro_is_no_write_no_exec_with_user() {
        let p = PagePerms::USER_RO;
        assert!(p.read);
        assert!(!p.write);
        assert!(!p.exec);
        assert!(p.user);
    }

    /// `accessed`/`dirty` on `KERNEL_RW` are a per-mapping REQUEST (both
    /// ISAs support software-managed A/D), not free-standing hardware
    /// facts — see the `Mmu` trait doc. Pinned here because the base
    /// `USER_*` constants deliberately leave them `false` (real call
    /// sites request A/D explicitly via struct-update syntax), so a
    /// reader comparing the two should not conclude the field is unused.
    #[test]
    fn page_perms_kernel_rw_presets_accessed_and_dirty() {
        let p = PagePerms::KERNEL_RW;
        assert!(p.accessed && p.dirty);
    }

    #[test]
    fn page_perms_user_rw_leaves_accessed_dirty_for_the_caller() {
        let p = PagePerms::USER_RW;
        assert!(!p.accessed && !p.dirty);
        // The struct-update idiom every user-leaf call site uses.
        let with_ad = PagePerms { accessed: true, dirty: true, ..p };
        assert!(with_ad.accessed && with_ad.dirty);
        assert_eq!(with_ad.read, p.read);
        assert_eq!(with_ad.write, p.write);
    }

    #[test]
    fn page_perms_constants_are_distinct() {
        // Quickly catch a copy-paste accident: a constant ending
        // up structurally identical to another.
        let all = [
            PagePerms::KERNEL_RW,
            PagePerms::KERNEL_RX,
            PagePerms::KERNEL_RO,
            PagePerms::KERNEL_RWX,
            PagePerms::USER_RW,
            PagePerms::USER_RX,
            PagePerms::USER_RO,
            PagePerms::MMIO,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j],
                    "PagePerms constants {} and {} are equal", i, j);
            }
        }
    }

    // ── ArchId + arch_name ─────────────────────────────────────

    #[test]
    fn arch_name_matches_uname_style_strings() {
        // These strings show up in procfs / OTA manifests / logs.
        // Changing them is operational-tool-breaking.
        assert_eq!(arch_name(ArchId::Riscv64), "riscv64");
        assert_eq!(arch_name(ArchId::Aarch64), "aarch64");
        assert_eq!(arch_name(ArchId::X86_64),  "x86_64");
        assert_eq!(arch_name(ArchId::Stub),    "stub");
    }

    #[test]
    fn arch_id_variants_are_distinct() {
        // PartialEq derive means we can compare; this proves the
        // enum hasn't degenerated to a single variant.
        let all = [
            ArchId::Riscv64, ArchId::Aarch64, ArchId::X86_64, ArchId::Stub,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    // ── Error enums round-trip via derive ──────────────────────

    #[test]
    fn mmu_error_variants_distinct() {
        assert_ne!(MmuError::NotAligned, MmuError::UnrepresentablePerms);
        assert_ne!(MmuError::NotAligned, MmuError::BadPhys);
        assert_ne!(MmuError::UnrepresentablePerms, MmuError::BadPhys);
    }

    #[test]
    fn hart_start_error_other_inner_round_trip() {
        let e = HartStartError::Other(-7);
        assert_eq!(e, HartStartError::Other(-7));
        assert_ne!(e, HartStartError::Other(-8));
        assert_ne!(e, HartStartError::AlreadyOn);
    }

    // ── InterruptState transparency ────────────────────────────

    #[test]
    fn interrupt_state_is_a_thin_u64_wrapper() {
        // The doc says callers treat it as opaque; we pin that
        // it's a single u64 newtype so per-ISA impls don't grow
        // it into something heavier.
        let s = InterruptState(0xDEAD_BEEF);
        assert_eq!(s.0, 0xDEAD_BEEF);
        assert_eq!(core::mem::size_of::<InterruptState>(), 8);
    }

    // ── Stub impl: trait shape is satisfiable ──────────────────

    /// Stub satisfying all five traits.  If any of them grew a
    /// method we forgot to add here, this test would fail to compile
    /// — which is the point.
    struct Stub;

    impl Cpu for Stub {
        fn hart_id(&self) -> usize { 0 }
        fn wfi(&self) {}
        fn halt(&self) -> ! { loop {} }
        // Monotonic by construction: each read is one higher than the last.
        // A stub returning a constant would let a "time moves forward" test
        // pass against an implementation that never reads the counter.
        fn now_ticks(&self) -> u64 {
            use core::sync::atomic::{AtomicU64, Ordering};
            static T: AtomicU64 = AtomicU64::new(0);
            T.fetch_add(1, Ordering::Relaxed)
        }
    }

    /// The stub's simulated interrupt-enable bit.
    ///
    /// It used to be absent: `disable_all` returned `InterruptState(0)` and
    /// `restore` did nothing, so the round-trip test below could only assert
    /// that the calls compiled. Modelling one bit costs nothing and lets the
    /// same tests assert the CONTRACT — that the token carries the previous
    /// state and that restoring puts back exactly that.
    static STUB_IRQ_ON: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(true);

    impl Interrupts for Stub {
        fn disable_all(&self) -> InterruptState {
            use core::sync::atomic::Ordering;
            InterruptState(STUB_IRQ_ON.swap(false, Ordering::Relaxed) as u64)
        }
        fn restore(&self, prev: InterruptState) {
            use core::sync::atomic::Ordering;
            STUB_IRQ_ON.store(prev.0 != 0, Ordering::Relaxed);
        }
        fn enable_all(&self) {
            use core::sync::atomic::Ordering;
            STUB_IRQ_ON.store(true, Ordering::Relaxed);
        }
        fn interrupts_enabled(&self) -> bool {
            use core::sync::atomic::Ordering;
            STUB_IRQ_ON.load(Ordering::Relaxed)
        }
        fn set_timer_deadline(&self, _deadline_ticks: u64) {}
        fn send_ipi(&self, _target_hart: usize) {}
    }

    /// Stub PTE-word layout, entirely made up (bit 0 = valid, bit 1 = leaf,
    /// bit 2 = COW, bit 3 = DEMAND, [15:12] = perms nibble, [63:16] = PPN).
    /// Real per-ISA layouts live in `arch-riscv64`/`arch-aarch64`; this
    /// only has to be internally consistent so the trait shape compiles
    /// and round-trips.
    impl Mmu for Stub {
        const PAGE_SIZE: usize = 4096;

        fn levels(&self) -> usize { 3 }
        fn entries_per_table(&self) -> usize { 512 }

        fn vpn(&self, va: usize, level: usize) -> usize {
            (va >> (12 + 9 * level)) & 0x1FF
        }

        fn pte_empty(&self) -> u64 { 0 }
        fn pte_is_valid(&self, word: u64) -> bool { word & 1 != 0 }
        fn pte_is_table(&self, word: u64, _level: usize) -> bool {
            word & 1 != 0 && word & 0b10 == 0
        }
        fn pte_is_leaf(&self, word: u64, _level: usize) -> bool {
            word & 1 != 0 && word & 0b10 != 0
        }
        fn pte_phys(&self, word: u64) -> usize {
            ((word >> 16) << 12) as usize
        }
        fn pte_make_table(&self, pa: usize) -> u64 {
            ((pa as u64) << 4) | 1
        }
        fn pte_make_leaf(&self, phys: usize, perms: PagePerms, _level: usize) -> Result<u64, MmuError> {
            if phys % Self::PAGE_SIZE != 0 { return Err(MmuError::NotAligned); }
            Ok(((phys as u64) << 4) | stub_perm_bits(perms) | 0b11)
        }
        fn pte_perms(&self, word: u64) -> PagePerms {
            stub_perms_from_bits(word)
        }
        fn pte_is_cow(&self, word: u64) -> bool { word & 0b100 != 0 }
        fn pte_share_cow(&self, word: u64) -> u64 {
            (word & !(1u64 << 13 /* write bit, see stub_perm_bits */)) | 0b100
        }
        fn pte_break_cow(&self, word: u64) -> u64 {
            (word & !0b100) | (1u64 << 13) | (1u64 << 15)
        }
        fn pte_make_demand(&self, perms: PagePerms) -> u64 {
            // Invalid (bit 0 clear) but DEMAND-marked (bit 3) with perms stored.
            stub_perm_bits(perms) | 0b1000
        }
        fn pte_is_demand(&self, word: u64) -> bool {
            word & 1 == 0 && word & 0b1000 != 0
        }
        fn pte_demand_perms(&self, word: u64) -> PagePerms {
            stub_perms_from_bits(word)
        }

        fn switch_pt(&self, _root_phys: usize, _asid: u16) {}
        fn switch_kernel_pt(&self, _root_phys: usize) {}
        fn flush_tlb_all(&self) {}
        fn flush_tlb_asid(&self, _asid: u16) {}
        fn flush_tlb_page(&self, _va: usize) {}
        fn tlb_shootdown(&self, _root_phys: usize, _va: usize, _len: usize) -> usize { 0 }
        fn root_holders(&self, _root_phys: usize) -> usize { 0 }
    }


    /// Perm nibble: bit12=read bit13=write bit14=exec bit15=user.
    /// `accessed`/`dirty`/`cache` are not modeled — the stub only has to
    /// prove the trait shape compiles and the bits it does model round-trip.
    fn stub_perm_bits(perms: PagePerms) -> u64 {
        (perms.read as u64) << 12
            | (perms.write as u64) << 13
            | (perms.exec as u64) << 14
            | (perms.user as u64) << 15
    }
    fn stub_perms_from_bits(word: u64) -> PagePerms {
        PagePerms {
            read:  word & (1 << 12) != 0,
            write: word & (1 << 13) != 0,
            exec:  word & (1 << 14) != 0,
            user:  word & (1 << 15) != 0,
            cache: true,
            accessed: false,
            dirty: false,
        }
    }

    impl Boot for Stub {
        fn shutdown(&self) -> ! { loop {} }
        fn reboot(&self) -> ! { loop {} }
        fn hart_start(&self, _hart_id: usize, _start_pc: usize, _opaque: usize)
            -> Result<(), HartStartError>
        {
            Ok(())
        }
    }

    impl Vector for Stub {
        fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
            a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
        }
        fn is_accelerated(&self) -> bool { false }
    }

    /// `now_ticks` must be MONOTONIC, and the trait must be usable through a
    /// `dyn Cpu` — which is how the kernel will reach it once the 129
    /// `clint::get_time()` call sites migrate.
    ///
    /// **What this does and does not prove.** It pins the contract and the
    /// object-safety, against the stub. It cannot prove `rdtime` or
    /// `CNTVCT_EL0` were read: the real implementations are ISA instructions
    /// that no host test can execute. Those are covered by the aarch64 smoke
    /// booting on both CPU models in the gate, and by the RISC-V kernel using
    /// the same instruction it always has.
    ///
    /// **Canary.** Make the stub return a constant: `strictly increases` fails
    /// on the second reading. A stub returning a constant is the exact shape
    /// that would let an implementation which never reads the counter pass.
    #[test]
    fn now_ticks_is_monotonic_through_a_trait_object() {
        let s = Stub;
        let dynamic: &dyn Cpu = &s;
        let a = dynamic.now_ticks();
        let b = dynamic.now_ticks();
        let c = dynamic.now_ticks();
        assert!(b > a, "now_ticks must not go backwards or stand still: {a} then {b}");
        assert!(c > b, "strictly increases across three readings: {b} then {c}");
    }

    #[test]
    fn stub_cpu_hart_id() {
        let s = Stub;
        assert_eq!(s.hart_id(), 0);
        s.wfi(); // no-op; just confirm it's callable
    }

    #[test]
    fn stub_interrupts_disable_restore_round_trip() {
        let s = Stub;
        s.enable_all();
        assert!(s.interrupts_enabled(), "enable_all must leave them on");

        let prev = s.disable_all();
        assert!(!s.interrupts_enabled(), "disable_all must leave them off");

        s.restore(prev);
        assert!(s.interrupts_enabled(), "restore must put back what was there");
    }

    /// **Nesting is the shape every caller uses**, so the contract has to
    /// survive it: an inner `disable_all`/`restore` pair inside an outer one
    /// must leave interrupts OFF, not on. A `restore` that unconditionally
    /// enabled would pass the round-trip test above and open a window here.
    #[test]
    fn a_nested_disable_restore_does_not_re_enable_early() {
        let s = Stub;
        s.enable_all();

        let outer = s.disable_all();
        let inner = s.disable_all();
        s.restore(inner);
        assert!(
            !s.interrupts_enabled(),
            "the inner restore must honour the outer critical section",
        );
        s.restore(outer);
        assert!(s.interrupts_enabled(), "the outer restore reopens them");
    }

    /// The token describes the state BEFORE the disable, so it cannot answer
    /// "are they on now" — that is what `interrupts_enabled` is for. Pinned
    /// because the two are easy to conflate and because the aarch64 impl
    /// reads them with OPPOSITE polarity: `DAIF.I` SET means masked, while
    /// RISC-V's `SSTATUS_SIE` set means enabled.
    #[test]
    fn the_saved_token_is_not_the_live_state() {
        let s = Stub;
        s.enable_all();
        let prev = s.disable_all();
        assert_ne!(
            prev.0 != 0,
            s.interrupts_enabled(),
            "the token says 'was on', the live query says 'now off'",
        );
        s.restore(prev);
    }

    #[test]
    fn stub_mmu_make_leaf_rejects_unaligned() {
        let s = Stub;
        let err = s.pte_make_leaf(0x1001, PagePerms::KERNEL_RW, 0).unwrap_err();
        assert_eq!(err, MmuError::NotAligned);
    }

    #[test]
    fn stub_mmu_make_leaf_round_trips_perms() {
        let s = Stub;
        let word = s.pte_make_leaf(0x2000, PagePerms::USER_RW, 0).unwrap();
        assert!(s.pte_is_valid(word));
        assert!(s.pte_is_leaf(word, 0));
        assert_eq!(s.pte_phys(word), 0x2000);
        let perms = s.pte_perms(word);
        assert!(perms.read && perms.write && !perms.exec && perms.user);
    }

    /// Canary for [`Mmu::pte_share_cow`] / [`Mmu::pte_break_cow`]: share
    /// clears WRITE and sets the COW marker; break does the reverse and
    /// leaves the physical address untouched. Mutate either body to a
    /// no-op and this fails.
    #[test]
    fn stub_mmu_cow_share_then_break_round_trips() {
        let s = Stub;
        let leaf = s.pte_make_leaf(0x3000, PagePerms::USER_RW, 0).unwrap();
        assert!(!s.pte_is_cow(leaf));

        let shared = s.pte_share_cow(leaf);
        assert!(s.pte_is_cow(shared), "share must set the COW marker");
        assert!(!s.pte_perms(shared).write, "share must clear WRITE");
        assert_eq!(s.pte_phys(shared), 0x3000, "share must not move the frame");

        let broken = s.pte_break_cow(shared);
        assert!(!s.pte_is_cow(broken), "break must clear the COW marker");
        assert!(s.pte_perms(broken).write, "break must restore WRITE");
    }

    /// Canary for [`Mmu::pte_make_demand`] / [`Mmu::pte_is_demand`]: a
    /// demand marker must read as INVALID (traps on access) yet still be
    /// recognisable as a demand marker, with its perms recoverable.
    #[test]
    fn stub_mmu_demand_marker_is_invalid_but_recoverable() {
        let s = Stub;
        let marker = s.pte_make_demand(PagePerms::USER_RW);
        assert!(!s.pte_is_valid(marker), "a demand marker must trap on access");
        assert!(s.pte_is_demand(marker));
        let perms = s.pte_demand_perms(marker);
        assert!(perms.read && perms.write && perms.user);
    }

    #[test]
    fn stub_vector_dot_f32_matches_scalar_oracle() {
        let s = Stub;
        let a = [1.0f32, 2.0, 3.0, 4.0];
        let b = [4.0f32, 3.0, 2.0, 1.0];
        // 1·4 + 2·3 + 3·2 + 4·1 = 20
        assert_eq!(s.dot_f32(&a, &b), 20.0);
        assert!(!s.is_accelerated(), "stub is the scalar fallback");
    }

    // ── Trait object dispatch ──────────────────────────────────
    //
    // Pin which traits are dyn-compatible. Cpu/Interrupts/Boot/
    // Vector ARE; Mmu is NOT because of its associated
    // `const PAGE_SIZE: usize` — associated consts make a trait
    // not dyn-compatible (Rust limitation).  Documented as task
    // #218: callers must use generics `<M: Mmu>` for the Mmu
    // surface, not `&dyn Mmu`.

    #[test]
    fn non_mmu_traits_are_dyn_compatible() {
        let s = Stub;
        let _cpu:        &dyn Cpu        = &s;
        let _interrupts: &dyn Interrupts = &s;
        let _boot:       &dyn Boot       = &s;
        let _vector:     &dyn Vector     = &s;
        // `let _mmu: &dyn Mmu = &s;` — intentionally NOT compiled.
        // See task #218; Mmu has an associated const, so dyn-dispatch
        // is forbidden by the language. Use `fn foo<M: Mmu>(m: &M)`
        // at call sites instead.
    }
}

/// Host tests for the real VMSAv8-64 encoding in `crate::aarch64_mmu`
/// (pulled from `crates/core/arch-aarch64/src/mmu.rs` — see the module doc at
/// the top of this file). These exercise the actual bit patterns the
/// aarch64 port writes into a page table: the level-dependent table/leaf
/// distinction, the AP/PXN/UXN permission encoding, and the software
/// COW/DEMAND markers.
#[cfg(test)]
mod aarch64_encoding_tests {
    use crate::aarch64_mmu as m;
    use azos_arch_api::PagePerms;

    const PA: usize = 0x4020_3000;

    // ── Memory attributes: the leaf's index must select the right MAIR byte ──

    /// The attribute byte `MAIR_EL1` holds at the index a leaf carries.
    fn mair_byte_selected_by(word: u64) -> u64 {
        let idx = (word >> 2) & 0b111; // AttrIndx, bits [4:2]
        (m::MAIR_VALUE >> (8 * idx)) & 0xFF
    }

    /// **A cacheable leaf must select Normal Write-Back memory, and an
    /// uncached one Device-nGnRE — read through `MAIR_VALUE` at the leaf's
    /// own index, which is how the hardware reads it.**
    ///
    /// Review 2026-09-21: `mmu.rs` had its two indices swapped relative to
    /// the `MAIR_EL1` value `mmu_setup.rs` programs, so every RAM leaf would
    /// have been Device memory (uncached, and alignment-faulting) and every
    /// MMIO leaf cacheable Normal memory (writes merged and reordered). It
    /// was fixed in the same wave — and then **reintroducing the swap passed
    /// all 41 tests in this crate**, because nothing tied the index to the
    /// byte. The round-trip tests below are symmetric: they encode and decode
    /// with the same constants, so they agree with themselves whichever way
    /// round the constants are. This one asserts the ARCHITECTURAL meaning.
    ///
    /// **Canary.** Replace `ATTRIDX_NORMAL`'s derivation in `mmu.rs` with the
    /// old literal `0 << ATTRIDX_SHIFT` (and `ATTRIDX_DEVICE` with `1 <<`):
    /// both assertions fail.
    #[test]
    fn a_leaf_selects_the_mair_attribute_its_cacheability_asks_for() {
        for (name, perms) in [
            ("KERNEL_RW", PagePerms::KERNEL_RW),
            ("KERNEL_RX", PagePerms::KERNEL_RX),
            ("USER_RW", PagePerms::USER_RW),
            ("USER_RX", PagePerms::USER_RX),
        ] {
            let w = m::make_leaf(PA, perms, 0).expect("representable");
            assert_eq!(mair_byte_selected_by(w), 0xFF,
                "{name} is cacheable RAM and must select Normal WB (0xFF)");
        }
        let mmio = m::make_leaf(PA, PagePerms::MMIO, 0).expect("representable");
        assert_eq!(mair_byte_selected_by(mmio), 0x04,
            "MMIO must select Device-nGnRE (0x04), never cacheable memory");
    }

    // ── Table vs. leaf, per level ───────────────────────────────────────

    /// A table descriptor (bit[1]=1) is a TABLE at L1/L2 (trait level 1,
    /// 2) and a PAGE (leaf) at L3 (trait level 0) — the exact asymmetry
    /// that makes a level-blind `is_leaf` dishonest on this ISA.
    ///
    /// **Canary.** Delete the `level == 0` branch in `is_leaf` (always
    /// treat bit[1]=1 as non-leaf, RISC-V-style): `bit11_set_is_a_leaf_at_l3`
    /// fails.
    #[test]
    fn bit11_is_a_table_at_l1_l2_and_a_leaf_at_l3() {
        let table_word = m::make_table(PA);
        // At L2 (trait level 1) and L1 (trait level 2): a table pointer.
        assert!(m::is_table(table_word, 1));
        assert!(m::is_table(table_word, 2));
        assert!(!m::is_leaf(table_word, 1));
        assert!(!m::is_leaf(table_word, 2));

        let page_word = m::make_leaf(PA, PagePerms::KERNEL_RW, 0).expect("aligned");
        // At L3 (trait level 0): the SAME low bits mean a leaf, not a table.
        assert!(m::is_leaf(page_word, 0));
        assert!(!m::is_table(page_word, 0));
    }

    /// A block descriptor (bit[1]=0, the RISC-V-style "megapage"/"gigapage"
    /// case) is a leaf at L1/L2 and would be reserved/invalid at L3 — this
    /// crate never builds an L3 block, but `is_leaf`/`is_table` must still
    /// agree that bit[1]=0 at a non-leaf level is a leaf, not a table.
    ///
    /// **Canary.** Swap `word & TYPE_TABLE_OR_PAGE == 0` for `!= 0` in the
    /// `level > 0` arm of `is_leaf`: this fails.
    #[test]
    fn a_block_descriptor_is_a_leaf_at_l1_and_l2() {
        // level=1 (L2 block, i.e. a "megapage"-equivalent 2 MiB mapping).
        let block = m::make_leaf(PA & !(0x1F_FFFF), PagePerms::KERNEL_RW, 1).expect("aligned");
        assert!(m::is_leaf(block, 1));
        assert!(!m::is_table(block, 1));
    }

    /// `is_valid` is level-independent: an all-zero word (unmapped) is
    /// invalid regardless of what level it is read at, and a freshly built
    /// table/leaf is valid regardless of level.
    #[test]
    fn empty_is_invalid_everywhere() {
        let e = m::empty();
        assert!(!m::is_valid(e));
        for level in 0..3 {
            assert!(!m::is_table(e, level));
            assert!(!m::is_leaf(e, level));
        }
    }

    // ── Physical address round trip ─────────────────────────────────────

    #[test]
    fn phys_addr_round_trips_through_table_and_leaf() {
        assert_eq!(m::phys_addr(m::make_table(PA)), PA);
        let leaf = m::make_leaf(PA, PagePerms::KERNEL_RW, 0).unwrap();
        assert_eq!(m::phys_addr(leaf), PA);
    }

    #[test]
    fn make_leaf_rejects_an_unaligned_physical_address() {
        let err = m::make_leaf(PA + 1, PagePerms::KERNEL_RW, 0).unwrap_err();
        assert_eq!(err, azos_arch_api::MmuError::NotAligned);
    }

    // ── PagePerms → AP/UXN/PXN → PagePerms round trip ───────────────────

    /// Every named `PagePerms` constant this tree actually uses for a
    /// fresh leaf must survive an encode/decode round trip on read/write/
    /// exec/user — the fields that map onto AP\[2:1\] and PXN/UXN.
    ///
    /// **Canary.** Flip the `AP_EL0`/`AP_RO` assignment in `attr_bits`
    /// (e.g. swap which bit gates read-only vs. user-reach): this fails
    /// for at least one constant, because `USER_RO`/`KERNEL_RW` stop
    /// being distinguishable from their neighbors.
    #[test]
    fn page_perms_round_trip_through_ap_and_xn_bits() {
        for (name, perms) in [
            ("KERNEL_RW", PagePerms::KERNEL_RW),
            ("KERNEL_RX", PagePerms::KERNEL_RX),
            ("KERNEL_RO", PagePerms::KERNEL_RO),
            ("USER_RW",   PagePerms::USER_RW),
            ("USER_RX",   PagePerms::USER_RX),
            ("USER_RO",   PagePerms::USER_RO),
        ] {
            let word = m::make_leaf(PA, perms, 0).expect(name);
            let back = m::perms_of(word);
            assert_eq!(back.read,  perms.read,  "{name}: read");
            assert_eq!(back.write, perms.write, "{name}: write");
            assert_eq!(back.exec,  perms.exec,  "{name}: exec");
            assert_eq!(back.user,  perms.user,  "{name}: user");
        }
    }

    /// AF is set unconditionally (this crate's documented convention —
    /// see `attr_bits`'s doc), so `accessed` decodes `true` even for a
    /// `PagePerms` value that left it `false`.
    #[test]
    fn accessed_is_always_set_on_a_fresh_leaf() {
        let perms = PagePerms { accessed: false, ..PagePerms::USER_RW };
        let word = m::make_leaf(PA, perms, 0).unwrap();
        assert!(m::perms_of(word).accessed, "AF is unconditional on this ISA");
    }

    /// `dirty` has no VMSAv8 hardware meaning here (no DBM wired up) — it
    /// is mm's own software bit, and must round-trip faithfully rather
    /// than being silently dropped or forced.
    ///
    /// **Canary.** Remove the `SW_DIRTY` read/write from `attr_bits`/
    /// `perms_from_attr_bits`: the `true` case fails (comes back `false`).
    #[test]
    fn dirty_round_trips_as_a_software_bit() {
        let clean = m::make_leaf(PA, PagePerms { dirty: false, ..PagePerms::USER_RW }, 0).unwrap();
        let dirty = m::make_leaf(PA, PagePerms { dirty: true,  ..PagePerms::USER_RW }, 0).unwrap();
        assert!(!m::perms_of(clean).dirty);
        assert!(m::perms_of(dirty).dirty);
    }

    // ── W^X-relevant combinations ────────────────────────────────────────

    /// `KERNEL_RX`/`USER_RX` must decode `write == false` — the read side
    /// of W^X: an executable leaf this ISA builds is never also writable.
    #[test]
    fn executable_leaves_are_never_writable() {
        for perms in [PagePerms::KERNEL_RX, PagePerms::USER_RX] {
            let word = m::make_leaf(PA, perms, 0).unwrap();
            let back = m::perms_of(word);
            assert!(back.exec, "expected executable");
            assert!(!back.write, "W^X: an executable leaf must not be writable");
        }
    }

    /// `KERNEL_RW`/`USER_RW` must decode `exec == false` — the write side
    /// of the same rule, checked from the PXN bit rather than assumed.
    ///
    /// **Canary.** Drop the `if !perms.exec { attrs |= PXN; ... }` guard
    /// in `attr_bits` (always leave PXN clear): this fails, because a
    /// freshly built `KERNEL_RW`/`USER_RW` leaf would decode as executable.
    #[test]
    fn writable_leaves_are_never_executable() {
        for perms in [PagePerms::KERNEL_RW, PagePerms::USER_RW] {
            let word = m::make_leaf(PA, perms, 0).unwrap();
            let back = m::perms_of(word);
            assert!(back.write, "expected writable");
            assert!(!back.exec, "W^X: a writable leaf must not be executable");
        }
    }

    /// Every kernel (non-user) leaf carries UXN, executable or not. This
    /// test used to assert the OPPOSITE ("UXN is redundant, EL0 has no
    /// AP-granted access") — false on VMSAv8-64: AP = 00 with UXN = 0 is the
    /// EL0 execute-only encoding, so kernel text without UXN is executable
    /// from EL0 (wave 4 found it happening). A kernel non-exec leaf also
    /// keeps PXN.
    ///
    /// **Canary.** Drop the `if !perms.user { attrs |= UXN; }` in
    /// `attr_bits`: both assertions on UXN fail.
    #[test]
    fn kernel_leaves_always_get_uxn() {
        let rw = m::make_leaf(PA, PagePerms::KERNEL_RW, 0).unwrap();
        assert_eq!(rw & (1 << 53), 1 << 53, "PXN must be set on a kernel data leaf");
        assert_eq!(rw & (1 << 54), 1 << 54, "UXN must be set on a kernel data leaf");
        let rx = m::make_leaf(PA, PagePerms::KERNEL_RX, 0).unwrap();
        assert_eq!(rx & (1 << 54), 1 << 54, "UXN must be set on kernel TEXT: EL0 must never execute it");
        assert_eq!(rx & (1 << 53), 0, "kernel text stays executable at EL1 (no PXN)");
        assert!(m::perms_of(rx).exec, "decode still reports the kernel text as executable");
    }

    /// A user non-exec leaf gets BOTH PXN and UXN: EL1 must not execute a
    /// user data page it might be asked to read, and EL0 must not execute
    /// it either.
    #[test]
    fn user_non_exec_gets_both_pxn_and_uxn() {
        let word = m::make_leaf(PA, PagePerms::USER_RW, 0).unwrap();
        assert_eq!(word & (1 << 53), 1 << 53, "PXN must be set");
        assert_eq!(word & (1 << 54), 1 << 54, "UXN must be set");
    }

    // ── COW / DEMAND software markers ───────────────────────────────────

    /// `share_cow` clears the write permission and sets the COW marker
    /// without moving the frame; `break_cow` reverses exactly that and
    /// marks the page dirty (it was just copied into).
    ///
    /// **Canary.** Make `break_cow` a no-op: `pte_perms(broken).write`
    /// stays `false` and this fails.
    #[test]
    fn cow_share_then_break_round_trips() {
        let leaf = m::make_leaf(PA, PagePerms::USER_RW, 0).unwrap();
        assert!(!m::is_cow(leaf));

        let shared = m::share_cow(leaf);
        assert!(m::is_cow(shared));
        assert!(!m::perms_of(shared).write, "share must clear WRITE");
        assert_eq!(m::phys_addr(shared), PA, "share must not move the frame");

        let broken = m::break_cow(shared);
        assert!(!m::is_cow(broken));
        assert!(m::perms_of(broken).write, "break must restore WRITE");
        assert!(m::perms_of(broken).dirty, "break must mark the page dirty");
    }

    /// A DEMAND marker is invalid (traps on access) yet distinguishable
    /// from a plain unmapped slot, with its perms recoverable — the same
    /// contract RISC-V's RSW-bit marker gives mm's demand-paging path.
    ///
    /// **Canary.** Make `is_demand` ignore the `is_valid` check: a real
    /// (valid) leaf would then also read as a demand marker, which
    /// `demand_marker_is_invalid_and_distinct_from_unmapped` catches via
    /// its `!m::is_valid(marker)` assertion combined with reusing the
    /// same word shape as a leaf.
    #[test]
    fn demand_marker_is_invalid_and_distinct_from_unmapped() {
        let marker = m::make_demand(PagePerms::USER_RW).unwrap();
        assert!(!m::is_valid(marker), "a demand marker must trap on access");
        assert!(m::is_demand(marker));
        assert!(!m::is_demand(m::empty()), "plain unmapped must not read as demand-reserved");

        let perms = m::demand_perms(marker);
        assert!(perms.read && perms.write && perms.user);
    }
}

/// Host tests for the real NEON kernel in `crate::aarch64_vector` (pulled
/// from `crates/core/arch-aarch64/src/vector.rs` — see the module doc at the top
/// of this file for why that link works on this host).
///
/// The scalar path (`dot_f32_scalar`) is the oracle, per project convention
/// (a sequential, unambiguous sum). NEON is checked against it, not the
/// other way round.
///
/// **Integer kernels: none exist.** `crates/core/ml/src/int8.rs` (the INT8
/// inference path) is pure scalar in this tree — it has never had an RVV
/// path (verified: `grep -n "rvv\|Vector\|dot_f32" crates/core/ml/src/int8.rs`
/// returns nothing), so there is no bit-exact integer comparison to add
/// here. `dot_f32` is the only vector-shaped kernel on any path the aarch64
/// kernel runs.
///
/// **ULP bound: 4.0 (a `f64`-space ratio, not a literal bit-distance
/// count).** `dot_f32_neon` sums in 4 independent SIMD lanes across the
/// `chunks` loop, folds the 4 lanes with `vaddvq_f32` (a 2-level pairwise
/// tree: (0+1)+(2+3)), then adds the scalar tail sequentially.
/// `dot_f32_scalar` sums strictly left-to-right. Both are O(n) sums of the
/// same n products; only the ASSOCIATION differs, and it differs by a fixed
/// number of reassociations (bounded by the lane count and one pairwise
/// fold), not by a term that grows with n — so the two results are expected
/// to agree to within a handful of ULPs regardless of test-vector length.
/// `approx_ulp` below approximates one ULP at a value's own magnitude as
/// `magnitude * f32::EPSILON`, which is the standard first-order estimate
/// away from the subnormal range (this test's generator never produces
/// subnormals). The bound was set empirically: the observed maximum over
/// every case below (lengths 0..=11, four alignment offsets each) is
/// asserted and printed on failure; 4.0 passed with margin against the
/// observed worst case at the time this was written.
#[cfg(test)]
mod aarch64_vector_tests {
    use crate::aarch64_vector as v;

    /// Deterministic pseudo-random f32 generator (no `rand` dependency).
    /// Range roughly [-4.0, 4.0), no subnormals, no NaN/Inf — this probes
    /// summation-order disagreement, not IEEE special-case handling.
    fn gen(seed: u32, n: usize) -> Vec<f32> {
        let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            let unit = ((x >> 8) as i32 as f32) / (i32::MAX as f32); // ~[-1, 1)
            out.push(unit * 4.0);
        }
        out
    }

    /// `diff / (one ULP at this magnitude)` — see the module doc for why
    /// this first-order estimate is good enough for this test's inputs.
    fn approx_ulp(a: f32, b: f32) -> f64 {
        let diff = (a as f64 - b as f64).abs();
        if diff == 0.0 { return 0.0; }
        let scale = (a.abs() as f64).max(b.abs() as f64).max(f32::MIN_POSITIVE as f64);
        diff / (scale * f32::EPSILON as f64)
    }

    const ULP_BOUND: f64 = 4.0;

    /// Tail lengths 0..(lanes*2 + 3) = 0..=11 (lanes=4), covering: empty,
    /// sub-one-lane tail-only, exactly one lane, one lane + tail, exactly
    /// two lanes, two lanes + tail, and past two lanes — the boundary
    /// cases `dot_f32_neon`'s `chunks = n/4, tail = n - chunks*4` split
    /// can produce.
    #[test]
    fn neon_matches_scalar_oracle_across_tail_lengths() {
        let mut worst: f64 = 0.0;
        for n in 0..=11usize {
            let a = gen(0xA5A5_0000u32.wrapping_add(n as u32), n);
            let b = gen(0x5A5A_0000u32.wrapping_add(n as u32), n);
            let scalar = v::dot_f32_scalar(&a, &b);
            let neon = unsafe { v::dot_f32_neon(&a, &b) };
            let ulp = approx_ulp(neon, scalar);
            worst = worst.max(ulp);
            assert!(
                ulp <= ULP_BOUND,
                "n={n}: neon={neon} scalar={scalar} ulp={ulp} exceeds bound {ULP_BOUND}"
            );
        }
        // Not a hard assertion — a println so a future tightening of
        // ULP_BOUND has a real number to start from instead of a guess.
        eprintln!("neon_matches_scalar_oracle_across_tail_lengths: worst observed ulp = {worst}");
    }

    /// Same comparison, but with both operands read from misaligned
    /// offsets (1..=3 elements into a backing `Vec`, so the pointer is not
    /// 16-byte aligned) in every combination. AArch64 `vld1q_f32` does not
    /// require alignment — this proves that holds for THIS kernel's use of
    /// it, rather than assuming the ISA guarantee transfers.
    #[test]
    fn neon_matches_scalar_oracle_on_unaligned_slices() {
        for n in [0usize, 1, 3, 4, 5, 8, 9, 11] {
            for a_off in 0..4usize {
                for b_off in 0..4usize {
                    let a_buf = gen(0x1111_0000u32.wrapping_add(n as u32), n + a_off);
                    let b_buf = gen(0x2222_0000u32.wrapping_add(n as u32), n + b_off);
                    let a = &a_buf[a_off..];
                    let b = &b_buf[b_off..];
                    let scalar = v::dot_f32_scalar(a, b);
                    let neon = unsafe { v::dot_f32_neon(a, b) };
                    let ulp = approx_ulp(neon, scalar);
                    assert!(
                        ulp <= ULP_BOUND,
                        "n={n} a_off={a_off} b_off={b_off}: neon={neon} scalar={scalar} ulp={ulp}"
                    );
                }
            }
        }
    }

    /// `dot_f32_scalar` accepts unequal-length inputs and truncates to
    /// `min(a.len(), b.len())` (it has no `debug_assert`); `dot_f32_neon`
    /// carries a `debug_assert_eq!` that FIRES in a debug/test build (found
    /// empirically: an earlier version of this test passed unequal slices
    /// straight to `dot_f32_neon` and the whole test binary aborted, not
    /// just this one assertion — `debug_assert!` panics, it does not return
    /// an `Err`). So the equal-length contract is the one every production
    /// call site (`ml`, `camera`, `conv.rs`) already honours; this test
    /// checks the two functions agree on the SAME already-truncated slices,
    /// which is the only comparison the contract allows.
    #[test]
    fn neon_matches_scalar_oracle_on_unequal_length_inputs_pre_truncated() {
        let a = gen(7, 11);
        let b = gen(9, 5);
        let n = a.len().min(b.len());
        let (a, b) = (&a[..n], &b[..n]);
        let scalar = v::dot_f32_scalar(a, b);
        let neon = unsafe { v::dot_f32_neon(a, b) };
        let ulp = approx_ulp(neon, scalar);
        assert!(ulp <= ULP_BOUND, "neon={neon} scalar={scalar} ulp={ulp}");
    }

    /// Canary target for the tail loop specifically: an input whose length
    /// is not a multiple of 4 (so `tail > 0`) with the tail elements set to
    /// values that dominate the sum. If the tail loop's bound (`tail =
    /// n - chunks*4`) or its indexing (`ap.add(i)`/`bp.add(i)` after the
    /// SIMD loop already advanced `ap`/`bp` by `chunks*4`) were wrong, this
    /// is the case that would catch it: a chunks-only sum would be wildly
    /// off from the scalar oracle, not off by a few ULPs.
    #[test]
    fn tail_elements_are_not_dropped_or_double_counted() {
        // 9 elements = 2 full lanes (8) + 1 tail element, tail set huge
        // relative to the lane elements so a dropped/doubled tail is
        // obviously outside any ULP bound, not just numerically close.
        let mut a = vec![0.001f32; 9];
        let mut b = vec![0.001f32; 9];
        a[8] = 1000.0;
        b[8] = 1000.0;
        let scalar = v::dot_f32_scalar(&a, &b);
        let neon = unsafe { v::dot_f32_neon(&a, &b) };
        let ulp = approx_ulp(neon, scalar);
        assert!(ulp <= ULP_BOUND, "neon={neon} scalar={scalar} ulp={ulp} (tail={})", a[8]);
    }

    #[test]
    fn empty_slices_give_zero() {
        let empty: [f32; 0] = [];
        assert_eq!(v::dot_f32_scalar(&empty, &empty), 0.0);
        assert_eq!(unsafe { v::dot_f32_neon(&empty, &empty) }, 0.0);
    }
}

/// Host tests for `mpidr::affinity_key`/`mpidr_affinity_key` — pure MPIDR
/// affinity-byte packing (`crates/core/arch-aarch64/src/mpidr.rs`, pulled above
/// as `aarch64_mpidr`). Never calls `read_mpidr` (real `MPIDR_EL1` read —
/// see this file's header comment on why that would crash here).
#[cfg(test)]
mod aarch64_mpidr_tests {
    use crate::aarch64_mpidr::{affinity_key, mpidr_affinity_key, Mpidr};

    /// Four DISTINCT nonzero bytes, one per field — a copy-paste shift
    /// error (e.g. Aff1 and Aff2 swapped) cannot pass by coincidence the
    /// way it could with a repeated or zero byte.
    #[test]
    fn affinity_key_packs_each_field_into_its_own_byte() {
        assert_eq!(affinity_key(0x05, 0x01, 0x02, 0x03), 0x0302_0105);
    }

    /// **Canary target.** Real `MPIDR_EL1` always has bit 31 (RES1) set,
    /// often bit 30 (U) or 24 (MT) too — none of those are part of any
    /// Aff field, and they sit BETWEEN Aff2 (`[23:16]`) and Aff3
    /// (`[39:32]`). A wrong slice (e.g. `(raw >> 24) & 0xFF`, which is a
    /// natural-looking but wrong guess at Aff3's position) would read MT
    /// plus half of Aff3's neighbours instead. This test sets bit 31 to
    /// catch exactly that class of mistake.
    #[test]
    fn mpidr_affinity_key_reads_aff3_from_bit32_not_bit24() {
        let raw: u64 = (1u64 << 31) | (0x03u64 << 32) | (0x02 << 16) | (0x01 << 8) | 0x05;
        assert_eq!(mpidr_affinity_key(raw), 0x0302_0105);
    }

    /// MT (bit 24) and U (bit 30) are real MPIDR bits that sit inside the
    /// Aff2..Aff3 gap; setting both must not perturb the decoded key.
    #[test]
    fn mpidr_affinity_key_ignores_mt_and_u_bits() {
        let raw: u64 =
            (1u64 << 31) | (1 << 30) | (1 << 24) | (0x03u64 << 32) | (0x02 << 16) | (0x01 << 8) | 0x05;
        assert_eq!(mpidr_affinity_key(raw), 0x0302_0105);
    }

    /// `Mpidr::affinity_key` (the decoded-struct method) must agree with
    /// the free function it delegates to — both packers are exercised by
    /// different call sites in production code, so this pins that they
    /// can never silently drift apart.
    #[test]
    fn mpidr_struct_affinity_key_matches_the_free_function() {
        let m = Mpidr {
            raw: 0,
            aff0: 0x05,
            aff1: 0x01,
            aff2: 0x02,
            aff3: 0x03,
            multi_thread: false,
            uniprocessor: false,
        };
        assert_eq!(m.affinity_key(), affinity_key(0x05, 0x01, 0x02, 0x03));
    }
}

/// Host tests for the pure parts of `gic.rs` (pulled above as
/// `aarch64_gic`): `GICR_TYPER` decode and `ICC_SGI1R_EL1` encode. Never
/// calls `find_redistributor`/`send_sgi`/any `mmio_*` helper — those touch
/// real MMIO and would fault immediately on this host.
#[cfg(test)]
mod aarch64_gic_tests {
    use crate::aarch64_gic::{
        sgi1r_encode, typer_affinity_key, typer_frame_stride, typer_is_last, GICR_STRIDE,
    };

    /// GICR_TYPER's affinity nibble positions are Aff0=[39:32], Aff1=[47:40],
    /// Aff2=[55:48], Aff3=[63:56] — a DIFFERENT layout than MPIDR's own
    /// (Aff1/Aff2 swapped relative to MPIDR, and everything shifted up by
    /// 32). `typer_affinity_key` must still land on the SAME canonical
    /// `Aff3<<24|Aff2<<16|Aff1<<8|Aff0` shape `mpidr_affinity_key` uses, so
    /// the two can be compared with `==` — this is the property the
    /// redistributor walk depends on.
    #[test]
    fn typer_affinity_key_matches_the_mpidr_affinity_key_shape() {
        let typer: u64 = (0x03u64 << 56) | (0x02u64 << 48) | (0x01u64 << 40) | (0x05u64 << 32);
        assert_eq!(typer_affinity_key(typer), 0x0302_0105);
        // Cross-check against the OTHER pulled module's packer directly —
        // proves the two independently-written functions agree, not just
        // that each matches a hand-computed literal.
        assert_eq!(
            typer_affinity_key(typer),
            crate::aarch64_mpidr::affinity_key(0x05, 0x01, 0x02, 0x03)
        );
    }

    #[test]
    fn typer_affinity_key_ignores_the_non_affinity_low_bits() {
        // PLPIS/VLPIS/Dirty/DirectLPI/Last/DPGS (bits 0..5) and
        // Processor_Number (bits 8..23) must not leak into the key.
        let noise: u64 = 0x00FF_FFFF;
        let typer = noise | (0x03u64 << 56) | (0x02u64 << 48) | (0x01u64 << 40) | (0x05u64 << 32);
        assert_eq!(typer_affinity_key(typer), 0x0302_0105);
    }

    #[test]
    fn typer_is_last_reads_bit4_only() {
        assert!(typer_is_last(1 << 4));
        assert!(!typer_is_last(0));
        assert!(!typer_is_last(!(1u64 << 4)), "every OTHER bit set, bit 4 clear, must read false");
    }

    #[test]
    fn typer_frame_stride_doubles_on_vlpis() {
        assert_eq!(typer_frame_stride(0), GICR_STRIDE);
        assert_eq!(typer_frame_stride(1 << 1), GICR_STRIDE * 2);
    }

    /// **Canary target: the `RS` field.** Aff0 = 0x15 (21, >= 16) forces
    /// `RS = 1` and a `TargetList` bit at position `0x15 & 0xF = 5` — NOT
    /// bit 21 (doesn't exist in a 16-bit field) and NOT bit 0. Dropping
    /// the `RS` term from `sgi1r_encode` would still pass every OTHER
    /// assertion here (they don't depend on RS) but this one would still
    /// read `RS=0`, exposing the exact omission `Mpidr::sgi_to_self_aff0`
    /// has and this function exists to fix for Aff0 >= 16.
    #[test]
    fn sgi1r_encode_places_every_field_and_carries_rs_for_aff0_above_15() {
        let target: u32 = 0x15 | (0x01 << 8) | (0x02 << 16) | (0x03 << 24);
        let v = sgi1r_encode(target, 7);
        assert_eq!(v & 0xFFFF, 1 << 5, "TargetList must be Aff0's LOW nibble");
        assert_eq!((v >> 16) & 0xFF, 0x01, "Aff1 at [23:16]");
        assert_eq!((v >> 24) & 0xF, 7, "INTID at [27:24]");
        assert_eq!((v >> 32) & 0xFF, 0x02, "Aff2 at [39:32]");
        assert_eq!((v >> 40) & 1, 0, "IRM must be 0 (targeted, not all-but-self)");
        assert_eq!((v >> 44) & 0xF, 1, "RS at [47:44] must be Aff0's HIGH nibble (0x15>>4=1)");
        assert_eq!((v >> 48) & 0xFF, 0x03, "Aff3 at [55:48]");
    }

    #[test]
    fn sgi1r_encode_intid_is_masked_to_four_bits() {
        let target: u32 = 0x00; // Aff0=0, TargetList bit 0
        let v = sgi1r_encode(target, 0xFF);
        assert_eq!((v >> 24) & 0xF, 0xF, "INTID must be masked, never overflow into RS");
        assert_eq!((v >> 44) & 0xF, 0, "masking INTID must not touch RS");
    }

    /// For Aff0 < 16 (every real call site in this tree today — QEMU
    /// virt's `-smp 2..4`), the general encoder must agree byte-for-byte
    /// with the existing self-targeted one it's meant to supersede for
    /// non-self targets.
    #[test]
    fn sgi1r_encode_matches_sgi_to_self_aff0_when_aff0_is_below_16() {
        let m = crate::aarch64_mpidr::Mpidr {
            raw: 0,
            aff0: 0x01,
            aff1: 0x00,
            aff2: 0x00,
            aff3: 0x00,
            multi_thread: false,
            uniprocessor: false,
        };
        let via_self = m.sgi_to_self_aff0(0);
        let via_general = sgi1r_encode(m.affinity_key(), 0);
        assert_eq!(via_self, via_general);
    }
}

/// Host tests for `psci::decode_cpu_on` (pulled above as `aarch64_psci`).
/// Never calls `cpu_on`/`cpu_on_checked`/`psci_call` — those execute
/// `hvc`/`smc`, undefined instructions at EL0 under macOS.
#[cfg(test)]
mod aarch64_psci_tests {
    use crate::aarch64_psci::{decode_cpu_on, CpuOnOutcome};

    #[test]
    fn decode_cpu_on_maps_ok_and_the_standard_errors() {
        assert_eq!(decode_cpu_on(0), CpuOnOutcome::Success);
        assert_eq!(decode_cpu_on(-1), CpuOnOutcome::NotSupported);
        assert_eq!(decode_cpu_on(-2), CpuOnOutcome::InvalidParams);
        assert_eq!(decode_cpu_on(-3), CpuOnOutcome::Denied);
        assert_eq!(decode_cpu_on(-4), CpuOnOutcome::AlreadyOn);
        assert_eq!(decode_cpu_on(-5), CpuOnOutcome::OnPending);
        assert_eq!(decode_cpu_on(-6), CpuOnOutcome::InternalFailure);
        assert_eq!(decode_cpu_on(-7), CpuOnOutcome::NotPresent);
        assert_eq!(decode_cpu_on(-8), CpuOnOutcome::Disabled);
        assert_eq!(decode_cpu_on(-9), CpuOnOutcome::InvalidAddress);
    }

    /// **Canary target: the truncation.** Firmware that writes only W0 and
    /// leaves X0's upper 32 bits zero (instead of sign-extending, as the
    /// calling convention requires but not every implementation honours)
    /// must decode IDENTICALLY to firmware that sign-extended properly.
    /// Dropping the `as i32` truncation (comparing `raw_x0` against the
    /// `PSCI_*` `i32` constants directly, which doesn't even compile, or
    /// widening the constants to `i64` instead) breaks the zero-extended
    /// case specifically.
    #[test]
    fn decode_cpu_on_truncates_a_zero_extended_negative_return_the_same_as_sign_extended() {
        let sign_extended: i64 = -4;
        let zero_extended: i64 = 0x0000_0000_FFFF_FFFCu64 as i64;
        assert_eq!(decode_cpu_on(sign_extended), CpuOnOutcome::AlreadyOn);
        assert_eq!(decode_cpu_on(zero_extended), CpuOnOutcome::AlreadyOn);
        assert_eq!(decode_cpu_on(sign_extended), decode_cpu_on(zero_extended));
    }

    #[test]
    fn decode_cpu_on_unknown_code_round_trips_its_value() {
        assert_eq!(decode_cpu_on(-99), CpuOnOutcome::Unknown(-99));
        assert_eq!(decode_cpu_on(42), CpuOnOutcome::Unknown(42));
    }

    #[test]
    fn cpu_on_outcome_variants_are_distinct() {
        let all = [
            CpuOnOutcome::Success,
            CpuOnOutcome::AlreadyOn,
            CpuOnOutcome::OnPending,
            CpuOnOutcome::InvalidParams,
            CpuOnOutcome::InvalidAddress,
            CpuOnOutcome::Denied,
            CpuOnOutcome::InternalFailure,
            CpuOnOutcome::NotSupported,
            CpuOnOutcome::Disabled,
            CpuOnOutcome::NotPresent,
            CpuOnOutcome::Unknown(0),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }
}

/// Host tests for `psci::select_conduit_from_fdt` — the second, independent
/// FDT walker the 2026-09-22 DTB audit spot-checked (bounds-checked
/// arithmetic, a depth cap, a size cap) but did not audit. Safe to call
/// directly on the host, unlike `cpu_on`/`psci_call`/`system_off`: it
/// executes no `hvc`/`smc`/`mrs` — only `[u8]::get`, arithmetic, and (on a
/// match) `set_conduit`'s plain atomic store — so nothing here can SIGILL
/// under macOS EL0 the way the sibling module's header comment warns about.
///
/// Every test builds its own minimal, spec-shaped FDT byte-for-byte (no
/// borrowed golden blob) so the exact adversarial knob each test turns is
/// visible in the test itself.
#[cfg(test)]
mod aarch64_psci_fdt_tests {
    use crate::aarch64_psci::{conduit, select_conduit_from_fdt, set_conduit, Conduit};

    /// `CONDUIT` is one process-wide atomic; `cargo test` runs tests on
    /// multiple threads by default and every test here reads or writes it.
    /// Serialized the same way `tests/host/mm-tests` serializes its PMM
    /// singleton.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    const FDT_MAGIC: u32 = 0xd00d_feed;
    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;
    const HEADER_LEN: u32 = 40;

    /// Minimal FDT builder. Produces a spec-shaped blob (header + struct
    /// block + strings block) so tests exercise the exact layout
    /// `select_conduit_from_fdt` expects, rather than a hand-typed byte
    /// dump nobody could audit by eye.
    struct Fdt {
        struct_block: Vec<u8>,
        strings: Vec<u8>,
        open_nodes: u32,
    }

    impl Fdt {
        fn new() -> Self {
            Fdt { struct_block: Vec::new(), strings: Vec::new(), open_nodes: 0 }
        }

        fn push_padded_name(buf: &mut Vec<u8>, name: &[u8]) {
            buf.extend_from_slice(name);
            buf.push(0);
            while buf.len() % 4 != 0 { buf.push(0); }
        }

        fn begin_node(&mut self, name: &[u8]) -> &mut Self {
            self.struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            Self::push_padded_name(&mut self.struct_block, name);
            self.open_nodes += 1;
            self
        }

        fn end_node(&mut self) -> &mut Self {
            self.struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
            // `wrapping_sub`, not `-=`: the unmatched-`END_NODE` test below
            // deliberately calls this with `open_nodes == 0` to build a
            // malformed fixture, and that bookkeeping is not what's under
            // test — the parser's own underflow guard is. A plain `-=`
            // would panic in the TEST HARNESS itself (this crate's dev/test
            // profile checks overflow too) before the fixture ever reaches
            // `select_conduit_from_fdt`.
            self.open_nodes = self.open_nodes.wrapping_sub(1);
            self
        }

        /// A property whose NAME lives at the natural next offset in the
        /// strings table. Returns that offset, in case a test wants it.
        fn prop(&mut self, name: &[u8], value: &[u8]) -> u32 {
            let nameoff = self.strings.len() as u32;
            self.strings.extend_from_slice(name);
            self.strings.push(0);
            self.prop_raw(nameoff, value);
            nameoff
        }

        /// A property with a HAND-PICKED `nameoff`, bypassing the strings
        /// table entirely — the adversarial knob the canary test below
        /// turns.
        fn prop_raw(&mut self, nameoff: u32, value: &[u8]) {
            self.struct_block.extend_from_slice(&FDT_PROP.to_be_bytes());
            self.struct_block.extend_from_slice(&(value.len() as u32).to_be_bytes());
            self.struct_block.extend_from_slice(&nameoff.to_be_bytes());
            self.struct_block.extend_from_slice(value);
            while self.struct_block.len() % 4 != 0 { self.struct_block.push(0); }
        }

        /// Assemble the full blob. `size_dt_strings_override` /
        /// `size_dt_struct_override`, when `Some`, replace the header's
        /// true block lengths — how the strings/struct-bound tests below
        /// declare a block SHORTER than what actually follows it.
        /// `trailer` is appended after the (real, full-length) strings
        /// block, standing in for whatever bytes a real DTB might place
        /// there next (more struct-block padding, another header field's
        /// target, ...) — content a correctly-bounded parser must never
        /// read as part of either block.
        fn finish(
            self,
            size_dt_strings_override: Option<u32>,
            size_dt_struct_override: Option<u32>,
            trailer: &[u8],
        ) -> Vec<u8> {
            let off_dt_struct = HEADER_LEN;
            let true_size_dt_struct = self.struct_block.len() as u32;
            let off_dt_strings = off_dt_struct + true_size_dt_struct;
            let size_dt_strings = size_dt_strings_override.unwrap_or(self.strings.len() as u32);
            let size_dt_struct = size_dt_struct_override.unwrap_or(true_size_dt_struct);

            let mut blob = Vec::new();
            blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
            blob.extend_from_slice(&0u32.to_be_bytes()); // totalsize, patched below
            blob.extend_from_slice(&off_dt_struct.to_be_bytes());
            blob.extend_from_slice(&off_dt_strings.to_be_bytes());
            blob.extend_from_slice(&0u32.to_be_bytes()); // off_mem_rsvmap, unused by this parser
            blob.extend_from_slice(&17u32.to_be_bytes()); // version, unused
            blob.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version, unused
            blob.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys, unused
            blob.extend_from_slice(&size_dt_strings.to_be_bytes());
            blob.extend_from_slice(&size_dt_struct.to_be_bytes());
            assert_eq!(blob.len(), HEADER_LEN as usize, "header layout drifted");

            blob.extend_from_slice(&self.struct_block);
            blob.extend_from_slice(&self.strings);
            blob.extend_from_slice(trailer);

            let total = blob.len() as u32;
            blob[4..8].copy_from_slice(&total.to_be_bytes());
            blob
        }

        /// A complete, well-formed `root -> psci@0 { method = <value> }`
        /// blob, declared sizes matching what was actually built (the
        /// baseline every canary test below diverges from by exactly one
        /// knob).
        fn well_formed_psci(method: &[u8]) -> Vec<u8> {
            let mut f = Fdt::new();
            f.begin_node(b"");
            f.begin_node(b"psci@0");
            f.prop(b"method", method);
            f.end_node();
            f.end_node();
            f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
            assert_eq!(f.open_nodes, 0);
            f.finish(None, None, &[])
        }
    }

    /// Baseline: a legitimate `method = "hvc"` under `/psci@0` is found and
    /// applied. Establishes that the builder above (and the parser) agree
    /// on the wire format before any test bends it.
    #[test]
    fn detects_hvc_under_a_well_formed_psci_node() {
        let _g = serial();
        set_conduit(Conduit::Smc); // start from the opposite value
        let blob = Fdt::well_formed_psci(b"hvc\0");
        assert_eq!(blob.as_ptr() as usize % 4, 0, "test blob must be 4-byte aligned");
        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(ok, "a well-formed /psci@0 {{ method = \"hvc\" }} must be found");
        assert_eq!(conduit(), Conduit::Hvc);
    }

    #[test]
    fn detects_smc_under_a_well_formed_psci_node() {
        let _g = serial();
        set_conduit(Conduit::Hvc); // start from the opposite value
        let blob = Fdt::well_formed_psci(b"smc\0");
        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(ok, "a well-formed /psci@0 {{ method = \"smc\" }} must be found");
        assert_eq!(conduit(), Conduit::Smc);
    }

    /// **The audit's fix, as a canary.** A `method` property whose `nameoff`
    /// points exactly ONE byte past the strings table this FDT actually
    /// declares (`size_dt_strings: Some(0)`, an honestly-empty strings
    /// table) — with the literal bytes `"method\0"` sitting right there in
    /// the blob anyway, as `trailer`, because that's what a real DTB's next
    /// section might look like. A parser that trusts `off_dt_strings..` all
    /// the way to `totalsize` (the pre-fix behaviour) finds that trailer,
    /// decides this property IS named "method", and applies whatever
    /// `prop_raw`'s value said — a false positive. A parser bounded to the
    /// header's own `size_dt_strings` must instead fail closed.
    #[test]
    fn refuses_a_method_name_that_lives_outside_the_declared_strings_block() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let mut f = Fdt::new();
        f.begin_node(b"");
        f.begin_node(b"psci@0");
        // nameoff == 0, but the declared strings table is zero bytes long —
        // so this offset resolves OUTSIDE it, into `trailer` below, in any
        // parser that does not enforce `size_dt_strings`.
        f.prop_raw(0, b"smc\0");
        f.end_node();
        f.end_node();
        f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
        let blob = f.finish(Some(0), None, b"method\0");

        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(
            !ok,
            "a nameoff outside the declared strings block must not resolve to \"method\" \
             just because bytes spelling it happen to sit further along the blob",
        );
        assert_eq!(
            conduit(), Conduit::Hvc,
            "a refused parse must not have called set_conduit at all",
        );
    }

    /// The struct-block counterpart of the test above: `size_dt_struct`
    /// declared shorter than the struct content actually written, with a
    /// legitimate `psci@0 { method = "smc" }` node sitting just past the
    /// declared end. A parser that only checks reads against `totalsize`
    /// would still walk into it; one bounded to `size_dt_struct` must stop
    /// at the declared edge and never see it.
    #[test]
    fn refuses_a_psci_node_that_lives_outside_the_declared_struct_block() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let mut f = Fdt::new();
        f.begin_node(b""); // root only — this is the part "inside bounds"
        let truncated_at = f.struct_block.len() as u32;
        // Everything below is REAL, well-formed FDT content — it would be
        // found by an unbounded walk — but it is declared to live past
        // `size_dt_struct`.
        f.begin_node(b"psci@0");
        f.prop(b"method", b"smc\0");
        f.end_node();
        f.end_node(); // close root
        f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
        let blob = f.finish(None, Some(truncated_at), &[]);

        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok, "a psci node past the declared size_dt_struct must not be found");
        assert_eq!(conduit(), Conduit::Hvc);
    }

    /// Bad magic must refuse without touching `CONDUIT` at all — not even
    /// a partial parse.
    #[test]
    fn a_bad_magic_is_refused_without_side_effects() {
        let _g = serial();
        set_conduit(Conduit::Smc);
        let mut blob = Fdt::well_formed_psci(b"hvc\0");
        blob[0] = 0; // corrupt the magic
        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok);
        assert_eq!(conduit(), Conduit::Smc, "conduit must be untouched by a rejected blob");
    }

    /// `fdt_ptr == 0` and a misaligned pointer are both refused before any
    /// memory is read — no `Fdt` builder involved, since neither of these
    /// inputs is a blob at all.
    #[test]
    fn a_null_or_misaligned_pointer_is_refused() {
        let _g = serial();
        assert!(!unsafe { select_conduit_from_fdt(0) });
        let blob = Fdt::well_formed_psci(b"hvc\0");
        let misaligned = blob.as_ptr() as u64 | 1;
        assert!(!unsafe { select_conduit_from_fdt(misaligned) });
    }

    /// **Depth cap, exercised for real.** 30 nested `BEGIN_NODE`s — past
    /// `MAX_DEPTH` (24) — with the deepest named `psci@0` and holding a
    /// `method` property. A walker without the cap either indexes
    /// `psci_depth` out of bounds (a panic on the real kernel: no unwinding,
    /// `panic = "abort"`) or, if it tracked depth in something unbounded,
    /// still finds and applies the buried property. This one must return
    /// `false`, not panic and not apply anything.
    #[test]
    fn a_node_nested_past_the_depth_cap_is_refused_not_panicked_on() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let mut f = Fdt::new();
        for i in 0..30 {
            let name: &[u8] = if i == 29 { b"psci@0" } else { b"wrapper" };
            f.begin_node(name);
        }
        f.prop(b"method", b"smc\0");
        for _ in 0..30 { f.end_node(); }
        f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
        let blob = f.finish(None, None, &[]);

        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok, "30 levels of nesting exceeds MAX_DEPTH (24) and must be refused");
        assert_eq!(conduit(), Conduit::Hvc);
    }

    /// An `END_NODE` with no matching `BEGIN_NODE` (`depth` would underflow)
    /// must refuse, not panic — `find_method`'s `depth.checked_sub(1)?` is
    /// exactly this guard.
    #[test]
    fn an_unmatched_end_node_is_refused_not_panicked_on() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let mut f = Fdt::new();
        f.end_node(); // no matching begin_node — open_nodes underflows to
                       // u32::MAX in the builder too, which is fine: this
                       // test never calls a method that reads `open_nodes`
                       // again before `finish` overwrites the struct block
                       // wholesale below.
        f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
        let blob = f.finish(None, None, &[]);

        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok, "an END_NODE with no matching BEGIN_NODE must be refused");
        assert_eq!(conduit(), Conduit::Hvc);
    }

    /// A property `len` that claims more bytes than the blob has left must
    /// refuse, not read past the end. Built by hand rather than through
    /// `prop()`, which always writes a consistent `len`.
    #[test]
    fn a_property_length_running_past_the_end_is_refused_not_read() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let mut f = Fdt::new();
        f.begin_node(b"");
        f.begin_node(b"psci@0");
        let nameoff = f.strings.len() as u32;
        f.strings.extend_from_slice(b"method\0");
        // FDT_PROP, len = 0xFFFF_FFF0 (absurd), nameoff, then NO value
        // bytes at all — the declared length runs far past the blob.
        f.struct_block.extend_from_slice(&FDT_PROP.to_be_bytes());
        f.struct_block.extend_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        f.struct_block.extend_from_slice(&nameoff.to_be_bytes());
        f.end_node();
        f.end_node();
        f.struct_block.extend_from_slice(&FDT_END.to_be_bytes());
        let blob = f.finish(None, None, &[]);

        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok, "a property length past the end of the blob must be refused");
        assert_eq!(conduit(), Conduit::Hvc);
    }

    /// A `method` value naming a conduit this parser doesn't recognise must
    /// refuse (fall through to the entry-EL heuristic) rather than guess.
    #[test]
    fn an_unrecognised_method_value_is_refused() {
        let _g = serial();
        set_conduit(Conduit::Hvc);
        let blob = Fdt::well_formed_psci(b"psci-jtag-fake\0");
        let ok = unsafe { select_conduit_from_fdt(blob.as_ptr() as u64) };
        assert!(!ok);
        assert_eq!(conduit(), Conduit::Hvc);
    }
}

/// Wave 7 CON: the two pure encoders behind `gic::route_spi` (the PL011
/// console SPI). Never calls `route_spi` itself — it touches real MMIO.
#[cfg(test)]
mod aarch64_gic_spi_route_tests {
    use crate::aarch64_gic::{icfgr_with_trigger, irouter_for_mpidr};

    /// MPIDR carries MT (bit 24), U (bit 30) and RES1 (bit 31) next to the
    /// affinity fields; none of them may reach GICD_IROUTER, where bit 31 is
    /// Interrupt_Routing_Mode ("any PE") and would silently undo "this PE".
    #[test]
    fn irouter_keeps_affinity_and_drops_mt_u_res1() {
        // QEMU virt, -smp N: MPIDR_EL1 of cpu0 reads 0x8000_0000 (RES1 only).
        assert_eq!(irouter_for_mpidr(0x8000_0000), 0);
        let mpidr = (0x7u64 << 32) | (1 << 31) | (1 << 30) | (1 << 24) | 0x03_02_01;
        assert_eq!(irouter_for_mpidr(mpidr), (0x7u64 << 32) | 0x03_02_01);
    }

    /// INTID 33 is field 1 of GICD_ICFGR2 (bits [3:2]); edge is bit 3.
    #[test]
    fn icfgr_rewrites_only_this_intids_trigger_bit() {
        assert_eq!(icfgr_with_trigger(0, 33, true), 1 << 3);
        assert_eq!(icfgr_with_trigger(0xFFFF_FFFF, 33, false), !(1u32 << 3));
        // INTID 47 is the last field of the same register.
        assert_eq!(icfgr_with_trigger(0, 47, true), 1 << 31);
        assert_eq!(icfgr_with_trigger(0x5555_5555, 32, true), 0x5555_5557);
    }
}

/// Wave 8 IRQ3: which INTIDs ring 3 may bind, and the ownership bitmap
/// `handle_irq` reads. Pure: `user_spi_mark` never touches the GIC.
#[cfg(test)]
mod aarch64_gic_user_spi_tests {
    use crate::aarch64_gic::{
        user_spi_bindable, user_spi_in_range, user_spi_mark, user_spi_owned, user_spi_unmark,
    };

    #[test]
    fn only_spis_are_bindable() {
        assert!(!user_spi_in_range(0), "SGI 0 is the kernel's IPI");
        assert!(!user_spi_in_range(30), "PPI 30 is the EL1 physical timer");
        assert!(!user_spi_in_range(27), "PPI 27 is the kernel's tick: the EL1 virtual timer");
        assert_eq!(crate::aarch64_gic::PPI_VIRT_TIMER, 27, "the kernel's tick line");
        assert_eq!(crate::aarch64_gic::PPI_EL1_PHYS_TIMER, 30);
        assert!(!user_spi_in_range(crate::aarch64_gic::PPI_VIRT_TIMER));
        assert!(!user_spi_in_range(31));
        assert!(user_spi_in_range(32));
        assert!(user_spi_in_range(1019));
        assert!(!user_spi_in_range(1020), "1020..1023 are special INTIDs");
        assert!(!user_spi_in_range(8192), "an LPI has no distributor enable");
        assert!(!user_spi_mark(30));
        assert!(!user_spi_owned(30));
    }

    /// A marked line reads back owned; its neighbours in the same word and
    /// the same bit of the next word do not. Canary: `intid % 32` → `intid
    /// / 32` in `spi_set` fails the neighbour asserts.
    #[test]
    fn marking_owns_exactly_that_line() {
        assert!(user_spi_bindable(34));
        assert!(!user_spi_owned(34));
        assert!(user_spi_mark(34));
        assert!(user_spi_owned(34));
        assert!(!user_spi_owned(33));
        assert!(!user_spi_owned(35));
        assert!(!user_spi_owned(66));
    }

    /// Wave 9 IRQ4 item 4: the release clears exactly that line's ownership
    /// and nothing else, and releasing a line nobody owns is refused.
    /// Canary: `fetch_and(!bit)` → `fetch_and(bit)` in `spi_clear` clears the
    /// neighbour 37 too.
    #[test]
    fn unmarking_forgets_exactly_that_line() {
        assert!(user_spi_mark(36));
        assert!(user_spi_mark(37));
        assert!(user_spi_unmark(36));
        assert!(!user_spi_owned(36));
        assert!(user_spi_owned(37), "the neighbour lost its ownership");
        assert!(!user_spi_unmark(36), "a line nobody owns was released");
        assert!(user_spi_bindable(36), "a released line can be bound again");
    }
}

/// Wave 9 IRQ4 item 3: the device tree's SPI trigger, as `user_spi_bind`
/// reads it. Pure bitmaps.
#[cfg(test)]
mod aarch64_gic_dtb_trigger_tests {
    use crate::aarch64_gic::{dtb_trigger, note_dtb_trigger};

    /// Canary: `spi_set(&DTB_EDGE, ..)` for a level note too — INTID 34
    /// reads edge.
    #[test]
    fn spi_triggers_read_back_and_non_spis_are_ignored() {
        note_dtb_trigger(34, false);
        note_dtb_trigger(48, true);
        assert_eq!(dtb_trigger(34), Some(false));
        assert_eq!(dtb_trigger(48), Some(true));
        assert_eq!(dtb_trigger(35), None);
        note_dtb_trigger(30, true);
        assert_eq!(dtb_trigger(30), None, "a PPI was recorded");
        note_dtb_trigger(1020, true);
        assert_eq!(dtb_trigger(1020), None, "a special INTID was recorded");
    }
}

/// The masked-window tracer's bookkeeping (`azos_arch_api::lat`,
/// feature `lat-trace`). Its state is one global table, so every test here
/// holds `LAT_LOCK` and starts from `reset()`.
#[cfg(test)]
mod lat_tests {
    use azos_arch_api::lat::{self, Kind, SiteRecord};
    use std::sync::Mutex;

    static LAT_LOCK: Mutex<()> = Mutex::new(());

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = LAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        lat::reset();
        for h in 0..lat::HARTS {
            for k in [Kind::Irq, Kind::Preempt] {
                lat::close(k, h, 0, 0); // leave no window open
            }
        }
        lat::reset();
        g
    }

    /// Canary: `close` taking `max` from the first window only (`if
    /// t.windows == 0`) keeps 100 instead of 300.
    #[test]
    fn longest_window_and_its_sites_are_kept() {
        let _g = fresh();
        lat::open(Kind::Irq, 1, 1_000, 11);
        lat::close(Kind::Irq, 1, 1_100, 12);
        lat::open(Kind::Irq, 1, 2_000, 21);
        lat::close(Kind::Irq, 1, 2_300, 22);
        lat::open(Kind::Irq, 1, 3_000, 31);
        lat::close(Kind::Irq, 1, 3_050, 32);
        let s = lat::summary(Kind::Irq, 1);
        assert_eq!((s.max, s.max_start, s.max_end, s.windows, s.unpaired), (300, 21, 22, 3, 0));
        // The other track and the other harts saw nothing.
        assert_eq!(lat::summary(Kind::Preempt, 1).windows, 0);
        assert_eq!(lat::summary(Kind::Irq, 0).windows, 0);
    }

    /// A window whose end was never seen is discarded, not extended: the
    /// second `open` restarts the clock. Canary: dropping the restart (keep
    /// `t0` when already open) reports 150 here.
    #[test]
    fn a_missed_close_is_counted_and_never_lengthens_a_window() {
        let _g = fresh();
        lat::open(Kind::Preempt, 2, 0, 1);
        lat::open(Kind::Preempt, 2, 100, 2);
        lat::close(Kind::Preempt, 2, 150, 3);
        let s = lat::summary(Kind::Preempt, 2);
        assert_eq!((s.max, s.max_start, s.unpaired, s.windows), (50, 2, 1, 1));
        // A close with no window open is a no-op.
        lat::close(Kind::Preempt, 2, 10_000, 4);
        assert_eq!(lat::summary(Kind::Preempt, 2).max, 50);
        assert!(!lat::is_open(Kind::Preempt, 2));
    }

    #[test]
    fn top_sites_merge_harts_and_sort_longest_first() {
        let _g = fresh();
        // site 7 on two harts (40 and 90), site 8 once (60), site 9 twice (10, 5).
        for (h, t0, len, site) in [(0, 0, 40, 7), (3, 0, 90, 7), (0, 500, 60, 8),
                                   (1, 0, 10, 9), (1, 100, 5, 9)] {
            lat::open(Kind::Irq, h, t0, site);
            lat::close(Kind::Irq, h, t0 + len, site + 100);
        }
        let mut out = [SiteRecord::default(); 4];
        let n = lat::top_sites(Kind::Irq, &mut out);
        assert_eq!(n, 3);
        assert_eq!((out[0].site, out[0].max, out[0].count, out[0].end), (7, 90, 2, 107));
        assert_eq!((out[1].site, out[1].max, out[1].count), (8, 60, 1));
        assert_eq!((out[2].site, out[2].max, out[2].count), (9, 10, 2));
        // A short output keeps the longest ones.
        let mut two = [SiteRecord::default(); 2];
        assert_eq!(lat::top_sites(Kind::Irq, &mut two), 2);
        assert_eq!((two[0].site, two[1].site), (7, 8));
    }

    #[test]
    fn a_full_site_table_is_counted_and_out_of_range_harts_ignored() {
        let _g = fresh();
        for i in 0..(lat::SITES + 3) {
            lat::open(Kind::Irq, 4, 0, 1_000 + i);
            lat::close(Kind::Irq, 4, 1, 0);
        }
        let s = lat::summary(Kind::Irq, 4);
        assert_eq!((s.windows, s.sites_full), ((lat::SITES + 3) as u64, 3));
        // A full table still takes a LONGER window from a new site: it evicts
        // the shortest entry. Canary: no eviction leaves site 9_999 out.
        lat::open(Kind::Irq, 4, 0, 9_999);
        lat::close(Kind::Irq, 4, 50, 0);
        let mut top = [SiteRecord::default(); 1];
        assert_eq!(lat::top_sites(Kind::Irq, &mut top), 1);
        assert_eq!((top[0].site, top[0].max), (9_999, 50));
        lat::open(Kind::Irq, lat::HARTS, 0, 1);
        lat::close(Kind::Irq, lat::HARTS, 5, 1);
        assert_eq!(lat::summary(Kind::Irq, lat::HARTS), lat::Summary::default());
        lat::reset();
        assert_eq!(lat::summary(Kind::Irq, 4), lat::Summary::default());
        let mut out = [SiteRecord::default(); 2];
        assert_eq!(lat::top_sites(Kind::Irq, &mut out), 0);
    }
}
