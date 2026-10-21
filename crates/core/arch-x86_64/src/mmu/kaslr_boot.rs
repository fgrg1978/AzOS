// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot half of x86_64 virtual KASLR (Kconfig `KASLR`): gather the seed,
//! choose the base, apply the relocations, hang the image page directory.
//!
//! **When it runs.** Once, on the boot CPU, from `boot.S` (`long_entry`): the
//! 32-bit stage has built the boot tables and entered long mode, the PC is
//! still the image's *physical* address (the 1:1 half of the boot map),
//! interrupts are off, and every pointer-bearing word of the image still holds
//! zero: the relocations are what this applies. So everything reachable from
//! [`x86_64_early_kaslr`] must not read such a word. That constrains the code,
//! not the data:
//!
//!  * addresses reach this function as arguments from `boot.S` (`lea`, RIP-
//!    relative, so they are the physical addresses the PC runs at), never
//!    through an `extern` static (a GOT slot the relocations have not filled)
//!    or a function pointer loaded from memory;
//!  * no `panic!`, no formatting: the panic path loads a `Location` through a
//!    pointer the relocations have not fixed yet. The shared arithmetic in
//!    `azos_arch_api::kaslr` has the same rule.
//!
//! The code is position-independent (`-C relocation-model=pie`: RIP-relative
//! addressing, `kaslr_rustflags` in tools/kconfig_to_cargo.py), so it runs at
//! the low address it was linked for.

use azos_arch_api::kaslr::{self as shared, Failure, SEED_HW};

use super::kaslr::{fill_image_pd, first_block, recorded_slide, set_boot_result, LAYOUT};
use super::{set_image_slide, KERNEL_VA_OFFSET};

const P: u64 = 1;
const RW: u64 = 1 << 1;

/// CPUID.1:ECX[30] RDRAND.
fn has_rdrand() -> bool {
    // CPUID leaf 1 exists on every CPU that reaches long mode.
    core::arch::x86_64::__cpuid_count(1, 0).ecx & (1 << 30) != 0
}

/// CPUID.(7,0):EBX[18] RDSEED.
fn has_rdseed() -> bool {
    // The leaf-count check comes first; CPUID itself is always legal.
    core::arch::x86_64::__cpuid_count(0, 0).eax >= 7 && core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0
}

/// Up to `RETRIES + 1` tries of one entropy instruction (CF=0 is "no data").
macro_rules! try_draw {
    ($insn:literal) => {{
        let mut tries = 0u32;
        let mut got = None;
        loop {
            let (v, ok): (u64, u8);
            // SAFETY: only expanded after CPUID reported the instruction.
            unsafe {
                core::arch::asm!(
                    concat!($insn, " {v}"),
                    "setc {ok}",
                    v = out(reg) v, ok = out(reg_byte) ok,
                    options(nostack, nomem),
                );
            }
            if ok != 0 {
                got = Some(v);
                break;
            }
            if tries >= azos_arch_api::entropy::RETRIES {
                break;
            }
            tries += 1;
            core::hint::spin_loop();
        }
        got
    }};
}

/// One 64-bit seed word from RDSEED and/or RDRAND (each unless Kconfig
/// `X86_RDSEED` / `X86_RDRAND` is `n`, and only if CPUID has it); both are
/// folded together when both answer. `None` when neither did.
fn hw_word() -> Option<u64> {
    let seed = if azos_arch_api::isa::x86_64::RDSEED.allowed() && has_rdseed() { try_draw!("rdseed") } else { None };
    let rand = if azos_arch_api::isa::x86_64::RDRAND.allowed() && has_rdrand() { try_draw!("rdrand") } else { None };
    shared::mix(seed, rand)
}

/// Choose the image base, apply the relocations, hang the image page
/// directory and record the result.
///
/// `img`/`img_end` are the physical addresses of `_text_start` and
/// `_kernel_end`, `rela`/`rela_end` those of the relocation table inside the
/// image, `pdpt_hi` the page directory pointer table of the top 2 GiB and
/// `pd_img` an empty page directory for the slid image (all physical).
///
/// # Safety
/// Boot CPU, long mode on the boot map, PC at the physical address, before any
/// relocation has been applied; `pdpt_hi` and `pd_img` are the boot stage's
/// own writable tables.
pub unsafe fn boot(
    img: u64,
    img_end: u64,
    rela: u64,
    rela_end: u64,
    pdpt_hi: *mut u64,
    pd_img: *mut u64,
) -> Result<(), Failure> {
    let entropy = hw_word();
    let sources = if entropy.is_some() { SEED_HW } else { 0 };
    let bytes = img_end.wrapping_sub(img);
    // The link-time VA of the image's first byte: the loader put the image
    // where the script says (PVH), and the link offset is `KERNEL_VA_OFFSET`.
    let link_va = KERNEL_VA_OFFSET.wrapping_add(img);
    let plan = shared::plan(&LAYOUT, link_va, img, bytes, entropy);
    // Even with delta 0 the walk runs: the linker leaves a RELA target zero,
    // and the word must hold its link-time value. It runs before a `require`
    // refusal is reported too, so the message's own pointers are valid when it
    // is printed. Every target, and the table itself, is checked against
    // `[img, img_end)` first.
    let delta = match &plan { Ok(p) => p.delta, Err(_) => 0 };
    // SAFETY: `rela..rela_end` lies inside the image (checked), which the boot
    // map maps writable at its physical address; nothing else runs.
    let applied =
        unsafe { shared::relocate_image(img, img_end, rela, rela_end, link_va, delta, shared::R_X86_64_RELATIVE) };
    if let Err(e) = applied {
        return Err(Failure::Relocation(e));
    }
    let plan = match plan {
        Ok(p) => p,
        Err(c) => return Err(Failure::Refused(c)),
    };
    if plan.bits == 0 {
        // `probe` with no seed: the image stays at its link address.
        set_boot_result(0, sources);
        return Ok(());
    }

    // The slid image's page directory: 2 MiB blocks onto the image's frames,
    // in the first GiB of the top 2 GiB (PDPT slot of the window's start). The
    // second GiB's entry is dropped: nothing runs from it.
    let (first, pa_block) = first_block(plan.image_va, img);
    let (_, _, blocks) = shared::image_blocks(&LAYOUT, plan.image_va, img, bytes);
    // SAFETY: the caller's contract.
    unsafe {
        fill_image_pd(&mut *(pd_img as *mut [u64; 512]), first, pa_block, blocks);
        let slot = ((KERNEL_VA_OFFSET >> 30) & 511) as usize;
        pdpt_hi.add(slot).write_volatile((pd_img as u64) | P | RW);
        pdpt_hi.add(slot + 1).write_volatile(0);
        // CR3 again: drops every translation of the old top 2 GiB. The PC runs
        // on the 1:1 half, which none of this touched.
        core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack));
    }
    set_image_slide(recorded_slide(plan.image_va.wrapping_sub(link_va)));
    set_boot_result(plan.bits, sources);
    Ok(())
}

/// `boot.S` calls this when the policy is not `n`: a failure prints on COM1
/// and stops, since no console of the kernel's exists yet.
///
/// # Safety
/// As [`boot`]; the C ABI is `boot.S`'s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_early_kaslr(
    img: u64,
    img_end: u64,
    rela: u64,
    rela_end: u64,
    pdpt_hi: *mut u64,
    pd_img: *mut u64,
) {
    // SAFETY: this function's contract.
    if let Err(f) = unsafe { boot(img, img_end, rela, rela_end, pdpt_hi, pd_img) } {
        early_say(f.text());
        loop {
            // SAFETY: stops this CPU; interrupts are off.
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }
}

fn outb(port: u16, v: u8) {
    // SAFETY: a byte to a legacy I/O port at CPL0.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}

fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: as above.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Write `msg` on COM1 (8N1, 115200), setting the port up as boot.S's
/// baseline refusal does: this runs before the console exists.
fn early_say(msg: &[u8]) {
    const COM1: u16 = 0x3F8;
    outb(COM1 + 3, 0x80);
    outb(COM1, 1);
    outb(COM1 + 1, 0);
    outb(COM1 + 3, 0x03);
    let mut i = 0usize;
    while i < msg.len() {
        // SAFETY: i < len.
        let c = unsafe { *msg.as_ptr().add(i) };
        let mut spins = 0u32;
        while inb(COM1 + 5) & 0x20 == 0 && spins < 1_000_000 {
            spins += 1;
        }
        outb(COM1, c);
        i += 1;
    }
}
