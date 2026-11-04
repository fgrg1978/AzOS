// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot half of riscv64 virtual KASLR (Kconfig `KASLR`): gather the seed,
//! choose the base, apply the relocations, build the boot root.
//!
//! **When it runs.** Once, on the boot hart, from `boot.S` (`_start`), after
//! the BSS is cleared and before anything else reaches a pointer: `satp` is 0
//! (bare), the PC is the image's physical address (the link address is the
//! physical one, as it always was on riscv64), and every pointer-bearing word
//! of the image still holds its link-time value: the relocations are what this
//! applies. So everything reachable from [`riscv64_early_kaslr`] must not read
//! such a word. That constrains the code, not the data:
//!
//!  * addresses reach these functions as arguments from `boot.S` (`lla`,
//!    PC-relative, so they are the physical addresses the PC runs at), or as
//!    the address of a `static` taken here with `&raw` (also PC-relative),
//!    never through a vtable or a function pointer loaded from memory;
//!  * no `panic!`, no indexing with a variable that could be out of range, no
//!    formatting: the panic path loads a `Location` through a pointer the
//!    relocations have not fixed yet. The shared arithmetic in
//!    `azos_arch_api::kaslr` has the same rule.
//!
//! The code is PC-relative (`auipc`), so it runs at the low address it was
//! linked for. A slide is then taken on the boot root: `boot.S` writes `satp`
//! and jumps to the slid address (the bias this records).

use azos_arch_api::kaslr::{self as shared, Failure, SEED_DT, SEED_HW};

use super::kaslr::{boot_satp, fill_boot_root, set_image_bias, LAYOUT};

/// A page table: 512 eight-byte entries, page-aligned.
#[repr(C, align(4096))]
struct Table([u64; 512]);

/// The boot root: the low half 1:1 with gigapages, one entry for the image.
static mut BOOT_ROOT: Table = Table([0; 512]);
/// The level-1 table of the slid image (megapages), under one root entry.
static mut BOOT_L1: Table = Table([0; 512]);

/// The device tree is read in place; a flattened tree is at most this big
/// (Linux caps it at 2 MiB). The cap also bounds the in-place erase.
const DT_CAP: usize = 2 << 20;

/// One trap-safe Zkr `seed` word (four ES16 reads), or `None` when Kconfig
/// `RV_ZKR` is `n`, firmware does not let S-mode read the CSR (the trap is
/// absorbed), or the source stays empty for the configured number of tries.
/// The device tree's claim of `zkr` is not consulted: it is not parsed yet, and
/// the read under a private `stvec` is what settles it.
fn zkr_word() -> Option<u64> {
    if !azos_arch_api::isa::riscv64::ZKR.allowed() {
        return None;
    }
    let mut acc = 0u64;
    let mut words = 0u32;
    let mut tries = 0u32;
    while words < 4 {
        match crate::seed::read() {
            azos_arch_api::entropy::Draw::Bytes { word, len } if len >= 2 => {
                acc = acc << 16 | (word & 0xFFFF);
                words += 1;
                tries = 0;
            }
            azos_arch_api::entropy::Draw::Dead => return None,
            _ => {
                if tries >= azos_arch_api::entropy::RETRIES {
                    return None;
                }
                tries += 1;
            }
        }
    }
    Some(acc)
}

/// The seed and which sources gave it. A device tree whose own size (its
/// header's `totalsize`) overlaps the image `[img, img_end)` is not read (the
/// walk writes there and the seed properties are erased in place).
///
/// # Safety
/// `dtb` must be readable and writable for [`DT_CAP`] bytes when it is not 0
/// (RAM, with satp = 0).
unsafe fn seed(dtb: u64, img: u64, img_end: u64) -> (Option<u64>, u64) {
    let hw = zkr_word();
    // The tree's own size, not the cap (the firmware may put the tree right
    // behind the image, inside the cap).
    // SAFETY: the caller's contract.
    let dt_len = if dtb != 0 { unsafe { shared::fdt_size(dtb as *const u8, DT_CAP) } } else { None };
    let dt = match dt_len {
        Some(n) if !shared::overlaps(dtb, n as u64, img, img_end.wrapping_sub(img)) => {
            // SAFETY: the caller's contract; the tree is `n` bytes.
            unsafe { shared::take_dt_seed(dtb as *mut u8, n) }
        }
        _ => None,
    };
    // A zero seed is the erased property of an earlier boot stage (or a
    // loader that left it blank): not a source.
    let dt = match dt { Some(0) => None, other => other };
    let sources = (hw.is_some() as u64) * SEED_HW | (dt.is_some() as u64) * SEED_DT;
    (shared::mix(hw, dt), sources)
}

/// Choose the image base, apply the relocations, build the boot root and
/// record the result. Nothing is mapped yet: `boot.S` installs the root.
///
/// `img`/`img_end` are the physical addresses of `_start` and `_kernel_end`,
/// `rela`/`rela_end` those of the relocation table inside the image, `dtb` the
/// device tree the firmware passed (0 = none).
///
/// # Safety
/// Boot hart, `satp` = 0, before any relocation has been applied.
pub unsafe fn boot(dtb: u64, img: u64, img_end: u64, rela: u64, rela_end: u64) -> Result<(), Failure> {
    // SAFETY: the caller's contract.
    let (entropy, sources) = unsafe { seed(dtb, img, img_end) };
    let bytes = img_end.wrapping_sub(img);
    // The image is linked at the address it is loaded at: the identity.
    let plan = shared::plan(&LAYOUT, img, img, bytes, entropy);
    // Even with delta 0 the walk runs: the linker leaves a RELA target zero,
    // and the word must hold its link-time value. It runs before a `require`
    // refusal is reported too, so the message's own pointers are valid when it
    // is printed. Every target, and the table itself, is checked against
    // `[img, img_end)` first.
    let delta = match &plan { Ok(p) => p.delta, Err(_) => 0 };
    // SAFETY: `rela..rela_end` lies inside the image (checked), which is RAM
    // the caller owns, mapped by nothing yet; nothing else runs.
    let applied =
        unsafe { shared::relocate_image(img, img_end, rela, rela_end, img, delta, shared::R_RISCV_RELATIVE) };
    if let Err(e) = applied {
        return Err(Failure::Relocation(e));
    }
    let plan = match plan {
        Ok(p) => p,
        Err(c) => return Err(Failure::Refused(c)),
    };
    if plan.bits == 0 {
        // `probe` with no seed: the image stays where it is, `satp` stays 0.
        set_image_bias(0, 0, 0, sources);
        return Ok(());
    }

    // The boot root. Static tables in .bss, written before `satp` is.
    let root = &raw mut BOOT_ROOT;
    let l1 = &raw mut BOOT_L1;
    let (va_block, pa_block, blocks) = shared::image_blocks(&LAYOUT, plan.image_va, img, bytes);
    // SAFETY: boot hart, nothing maps these yet; they are statics of the
    // image, so their addresses (PC-relative) are physical. `no_cross` keeps
    // the image inside one root entry, so one level-1 table maps all of it.
    unsafe { fill_boot_root(&mut (*root).0, &mut (*l1).0, l1 as u64, va_block, pa_block, blocks) };
    let satp = boot_satp(root as u64);
    set_image_bias(plan.image_va.wrapping_sub(img), satp, plan.bits, sources);
    Ok(())
}

/// `boot.S` calls this on the boot hart when the policy is not `n`: a failure
/// prints on SBI's console (the legacy putchar, then the debug-console call)
/// and parks the hart, since no console of the kernel's exists yet.
///
/// # Safety
/// As [`boot`]; the C ABI is `boot.S`'s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_early_kaslr(dtb: u64, img: u64, img_end: u64, rela: u64, rela_end: u64) {
    // SAFETY: this function's contract.
    if let Err(f) = unsafe { boot(dtb, img, img_end, rela, rela_end) } {
        early_say(f.text());
        loop {
            // SAFETY: `wfi` has no side effect on memory.
            unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
        }
    }
}

/// Write `msg` with SBI's legacy console putchar (extension 0x01).
fn early_say(msg: &[u8]) {
    let mut i = 0usize;
    while i < msg.len() {
        // SAFETY: i < len.
        let c = unsafe { *msg.as_ptr().add(i) } as usize;
        let _ = crate::firmware::sbi_call(0x01, 0, [c, 0, 0, 0, 0, 0]);
        i += 1;
    }
}
