// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CPU microcode at boot (Kconfig `X86_UCODE_LOAD`): the half that finds the
//! image, verifies it, writes the patch and says what happened. The image
//! format and the choice of the patch are `azos_arch::cpu::ucode` (pure,
//! host-tested).
//!
//! # Order, as Linux has it
//!
//! [`boot_cpu`] runs first in `cpu_features`, before the baseline check,
//! `features::detect` and the mitigation probe: a patch changes what they
//! read (`MD_CLEAR`, `RFDS_CLEAR`, `GDS_CTRL`, the Zen fixes). Linux loads in
//! `load_ucode_bsp`, before `early_cpu_init`, and selects the mitigations
//! much later in `arch_cpu_finalize_init`. Each secondary runs [`this_cpu`]
//! first in `x86_64_secondary_entry`, before it writes its mitigation MSRs
//! (`load_ucode_ap`, early in `start_secondary`). `irqchip_probe` and
//! `timer_probe` read CPUID before the load; microcode changes neither
//! the APIC nor the TSC leaves.
//!
//! # One image, one patch kept
//!
//! The image is the first boot module that is an `RSIG` followed by the
//! payload magic. It is verified like every signed image of the system: the
//! signer's id against the update key (`SECURE_BOOT_PUBKEY`), the signed
//! size against the payload's, the signature over the payload's SHA-256.
//! With no key installed nothing verifies, and nothing is loaded (as the OTA
//! and the livepatch refuse). The boot CPU reads the module through boot.S's
//! 0..4 GiB identity map, before the page allocator exists; after it, only
//! the patch it loaded is kept: its frames are reserved
//! ([`kept_frames`], `reserve_firmware_table`) and stay in the direct map,
//! where each secondary reads it. The rest of the module is free RAM (a
//! Limine module is reserved memory of the loader's, and stays so).
//!
//! # The record
//!
//! Every outcome is a `Rule::BootChain` record, subject [`STAGE`] (CPU
//! microcode): `version` the revision after, `floor` the revision before,
//! `reason` an [`Outcome`] in bits 0..8 and the logical CPU above. The boot
//! CPU records once; a secondary records what it wrote.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use azos_arch::cpu::ucode::{self, Choice};
use azos_arch::platform_impl::platform;
use azos_decision::{Rule, Verdict};
use azos_drv_sys::kprintln;
use azos_sync::SpinLock;

/// Is the loader built in?
const ON: bool = azos_limits::X86_UCODE_LOAD;

/// The boot-chain stage a microcode record names.
pub(crate) const STAGE: u32 = 6;

/// What a record says happened (its `reason`, bits 0..8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub(crate) enum Outcome {
    /// Written, and the revision read back is the patch's.
    Applied = 0,
    /// The image's signature does not verify (or no update key is installed).
    BadSignature = 1,
    /// No patch in the image names this CPU.
    NoPatch = 4,
    /// Written, and the CPU kept its old revision (it refused the patch, or
    /// an emulator ignored the write).
    NotTaken = 5,
    /// The image verified and its containers do not parse.
    Malformed = 6,
    /// A hypervisor owns the microcode: nothing written.
    Hypervisor = 7,
    /// The CPU already runs the image's newest patch, or a newer one.
    Current = 8,
    /// A secondary whose signature or platform flags differ from the boot
    /// CPU's: the kept patch is not for it.
    OtherCpu = 9,
}

/// The patch the boot CPU loaded, for the secondaries: its physical address
/// and length (0 = none), the revision it brings, and the boot CPU's
/// signature and platform flags, which a secondary must share.
static KEPT_PA: AtomicU64 = AtomicU64::new(0);
static KEPT_LEN: AtomicU64 = AtomicU64::new(0);
static KEPT_REV: AtomicU32 = AtomicU32::new(0);
static KEPT_SIG: AtomicU32 = AtomicU32::new(0);
static KEPT_PF: AtomicU32 = AtomicU32::new(0);

/// One secondary loads at a time: the threads of a core share its
/// microcode, and the second one reads the revision the first loaded.
static AP_LOAD: SpinLock<()> = SpinLock::new(());

fn record(verdict: Verdict, cpu: usize, outcome: Outcome, before: u32, after: u32) {
    azos_decision::record(Rule::BootChain, verdict, STAGE,
                          [after as u64, before as u64, outcome as u64 | (cpu as u64) << 8]);
}

/// The boot identity map's reach (boot.S: 0..4 GiB).
const IDENTITY_LIMIT: u64 = 1 << 32;

/// The microcode image among the boot modules: `(physical address, the
/// module's bytes)`, the first that is an `RSIG` and then the payload magic.
fn find_image() -> Option<(u64, &'static [u8])> {
    platform().modules().iter().find_map(|&(pa, len)| {
        if pa.checked_add(len).is_none_or(|e| e > IDENTITY_LIMIT) {
            azos_drv_sys::kwarn!("[UCODE] module at {:#x} ({} bytes) is above 4 GiB: not read", pa, len);
            return None;
        }
        // SAFETY: a module the loader reported, in RAM below 4 GiB, which
        // boot.S maps 1:1 and nothing has written since (the page allocator
        // does not exist yet); read-only.
        let b = unsafe { core::slice::from_raw_parts(pa as usize as *const u8, len as usize) };
        let sig = azos_crypto::sig::Rsig::parse(b)?;
        b[sig.wire_len()..].starts_with(&ucode::MAGIC).then_some((pa, b))
    })
}

/// The payload of `image`, if its `RSIG` verifies against the update key.
fn verified(image: &[u8]) -> Option<&[u8]> {
    let sig = azos_crypto::sig::Rsig::parse(image)?;
    let payload = &image[sig.wire_len()..];
    let key = &azos_ota::SECURE_BOOT_PUBKEY;
    let ok = key.iter().any(|&b| b != 0)
        && sig.payload_size as usize == payload.len()
        && sig.verify(key, &azos_crypto::sha256::sha256(payload));
    ok.then_some(payload)
}

/// The boot CPU: load the patch for it, keep it for the secondaries, print
/// and record the outcome. First in `cpu_features`, identity map live, no
/// page allocator yet, no other CPU running.
pub(crate) fn boot_cpu() {
    if !ON {
        return;
    }
    let mods = platform().modules().len();
    let Some((pa, image)) = find_image() else {
        if mods == 0 {
            kprintln!("[UCODE] no boot module: the CPU runs the firmware's microcode");
        } else {
            kprintln!("[UCODE] {} boot module(s), none a microcode image: the CPU runs the firmware's microcode", mods);
        }
        return;
    };
    let Some(payload) = verified(image) else {
        azos_drv_sys::kwarn!("[UCODE] REFUSED: the image at {:#x} ({} bytes) does not verify against the update key{}",
            pa, image.len(),
            if azos_ota::SECURE_BOOT_PUBKEY.iter().all(|&b| b == 0) { " (none is installed)" } else { "" });
        record(Verdict::Refuse, 0, Outcome::BadSignature, 0, 0);
        return;
    };
    let base = payload.as_ptr() as u64;
    if ucode::hypervisor() {
        kprintln!("[UCODE] image verified ({} bytes); under a hypervisor, which owns the microcode: nothing written",
                  payload.len());
        record(Verdict::Refuse, 0, Outcome::Hypervisor, 0, 0);
        return;
    }
    let cpu = ucode::this_cpu();
    kprintln!("[UCODE] image verified ({} bytes); cpu {} signature {:#x} platform flags {:#x} revision {:#x}",
              payload.len(), cpu.vendor.name(), cpu.sig, cpu.pf, cpu.rev);
    match ucode::select(payload, &cpu) {
        Err(e) => {
            azos_drv_sys::kwarn!("[UCODE] REFUSED: {}", e.label());
            record(Verdict::Refuse, 0, Outcome::Malformed, cpu.rev, cpu.rev);
        }
        Ok(Choice::None) => {
            kprintln!("[UCODE] no matching patch for this CPU: revision {:#x} stays", cpu.rev);
            record(Verdict::Refuse, 0, Outcome::NoPatch, cpu.rev, cpu.rev);
        }
        Ok(Choice::Current { newest }) => {
            kprintln!("[UCODE] up to date: revision {:#x}, the image's newest for this CPU {:#x}", cpu.rev, newest);
            record(Verdict::Admit, 0, Outcome::Current, cpu.rev, cpu.rev);
        }
        Ok(Choice::Load(p)) => {
            // Identity-mapped: the address is the physical one.
            let pa = base + p.off as u64;
            // SAFETY: the patch `select` found inside the verified payload,
            // identity-mapped; the boot CPU, interrupts masked, alone.
            let after = unsafe { ucode::write(cpu.vendor, pa as usize, p.len) };
            if after == p.rev {
                kprintln!("[UCODE] applied: revision {:#x} -> {:#x}", cpu.rev, after);
                record(Verdict::Admit, 0, Outcome::Applied, cpu.rev, after);
                KEPT_PA.store(pa, Ordering::Relaxed);
                KEPT_LEN.store(p.len as u64, Ordering::Relaxed);
                KEPT_REV.store(p.rev, Ordering::Relaxed);
                KEPT_SIG.store(cpu.sig, Ordering::Relaxed);
                KEPT_PF.store(cpu.pf, Ordering::Relaxed);
            } else {
                azos_drv_sys::kwarn!("[UCODE] patch revision {:#x} written, not taken: revision {:#x} -> {:#x}",
                                     p.rev, cpu.rev, after);
                record(Verdict::Refuse, 0, Outcome::NotTaken, cpu.rev, after);
            }
        }
    }
}

/// The frames `(start, len)`, page-aligned, of the patch the boot CPU
/// loaded, which the secondaries read: what `reserve_firmware_table` keeps
/// out of the page allocator and the direct map keeps mapped. `None` when
/// nothing was loaded.
pub(crate) fn kept_frames() -> Option<(u64, u64)> {
    let len = KEPT_LEN.load(Ordering::Relaxed);
    let pa = KEPT_PA.load(Ordering::Relaxed);
    (len != 0).then(|| (pa & !0xFFF, ((pa + len + 0xFFF) & !0xFFF) - (pa & !0xFFF)))
}

/// A secondary CPU, first thing: the boot CPU's patch, unless this CPU
/// already runs it (a sibling thread of the same core loaded it, or the
/// firmware did). Interrupts are off; the kernel's tables are live.
pub(crate) fn this_cpu(cpu: usize) {
    let (pa, len) = (KEPT_PA.load(Ordering::Relaxed), KEPT_LEN.load(Ordering::Relaxed));
    if !ON || len == 0 {
        return;
    }
    let want = KEPT_REV.load(Ordering::Relaxed);
    let _one = AP_LOAD.lock();
    let me = ucode::this_cpu();
    if me.rev >= want {
        return;
    }
    if me.sig != KEPT_SIG.load(Ordering::Relaxed) || me.pf != KEPT_PF.load(Ordering::Relaxed) {
        azos_drv_sys::kwarn!("[UCODE] CPU {}: signature {:#x} flags {:#x} differ from the boot CPU's: revision {:#x} stays",
                             cpu, me.sig, me.pf, me.rev);
        record(Verdict::Refuse, cpu, Outcome::OtherCpu, me.rev, me.rev);
        return;
    }
    let va = azos_mm::addr::phys_to_virt(pa as usize);
    // SAFETY: the kept patch: reserved frames the direct map covers
    // (`kept_frames`); this CPU, interrupts off, its siblings serialized by
    // `AP_LOAD`.
    let after = unsafe { ucode::write(me.vendor, va, len as usize) };
    if after == want {
        record(Verdict::Admit, cpu, Outcome::Applied, me.rev, after);
    } else {
        azos_drv_sys::kwarn!("[UCODE] CPU {}: patch revision {:#x} written, not taken: revision {:#x}", cpu, want, after);
        record(Verdict::Refuse, cpu, Outcome::NotTaken, me.rev, after);
    }
}
