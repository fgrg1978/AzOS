// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the image loader needs about a static ELF image, for every image the
//! kernel starts, native or Linux: where its program headers land
//! ([`image_aux`]) and the initial stack its `_start` reads (argc, argv, envp,
//! the auxiliary vector: [`layout_initial_stack`]). Pure, so a kernel with no
//! personality keeps it and `tests/host/linux-abi-tests` checks it on the host.
#![no_std]
#![forbid(unsafe_code)]

/// Auxiliary-vector keys the initial stack carries.
pub mod at {
    pub const NULL: u64 = 0;
    pub const PHDR: u64 = 3;
    pub const PHENT: u64 = 4;
    pub const PHNUM: u64 = 5;
    pub const PAGESZ: u64 = 6;
    pub const BASE: u64 = 7;
    pub const FLAGS: u64 = 8;
    pub const ENTRY: u64 = 9;
    pub const UID: u64 = 11;
    pub const EUID: u64 = 12;
    pub const GID: u64 = 13;
    pub const EGID: u64 = 14;
    pub const HWCAP: u64 = 16;
    pub const CLKTCK: u64 = 17;
    pub const SECURE: u64 = 23;
    pub const RANDOM: u64 = 25;
    pub const EXECFN: u64 = 31;
}

/// What the image loader learned that the auxiliary vector reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageAux {
    /// User address of the program headers, or 0 when no `PT_LOAD` maps them
    /// (then `AT_PHDR` is left out rather than pointing at unmapped memory).
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub entry: u64,
    pub pagesz: u64,
}

/// Find where the program headers of `elf` land in the image: the address
/// inside the first `PT_LOAD` whose file range holds them, or 0 if none does. Also returns `e_phentsize`, `e_phnum` and
/// `e_entry`. `None` for a malformed header.
pub fn image_aux(elf: &[u8], pagesz: u64) -> Option<ImageAux> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return None;
    }
    let r16 = |at: usize| u16::from_le_bytes([elf[at], elf[at + 1]]) as u64;
    let r32 = |at: usize| u32::from_le_bytes([elf[at], elf[at + 1], elf[at + 2], elf[at + 3]]) as u64;
    let r64 = |at: usize| r32(at) | (r32(at + 4) << 32);
    let entry = r64(24);
    let phoff = r64(32);
    let phent = r16(54);
    let phnum = r16(56);
    if phent < 56 || phnum == 0 {
        return None;
    }
    let table_end = phoff.checked_add(phent.checked_mul(phnum)?)?;
    if table_end > elf.len() as u64 {
        return None;
    }
    let mut from_load = 0u64;
    for i in 0..phnum {
        let at = (phoff + i * phent) as usize;
        let p_type = r32(at);
        let p_offset = r64(at + 8);
        let p_vaddr = r64(at + 16);
        let p_filesz = r64(at + 32);
        const PT_LOAD: u64 = 1;
        if p_type == PT_LOAD
            && from_load == 0
            && p_offset <= phoff
            && table_end <= p_offset.saturating_add(p_filesz)
        {
            from_load = p_vaddr + (phoff - p_offset);
        }
    }
    // Taken from the covering `PT_LOAD`, not from `PT_PHDR`: a `PT_PHDR` no
    // `PT_LOAD` covers would name unmapped memory, and when one does cover
    // it the two addresses are the same.
    Some(ImageAux { phdr: from_load, phent, phnum, entry, pagesz })
}

/// Most argv and environment strings the initial stack carries (the
/// `SYS_SPAWN_EX` limits).
pub const STACK_STRINGS_MAX: usize = 32;

/// Lay out the initial stack a static binary's `_start` reads (the System V
/// layout native and Linux images share), in
/// `out`, which is mapped at user addresses `[base, base + out.len())`; the
/// stack grows down from `base + out.len()`.
///
/// From the top: the argv strings, the environment strings, 16 random bytes
/// (`AT_RANDOM`), then, 16-byte aligned, `argc`, the argv pointers and a
/// NULL, the envp pointers and a NULL, and the auxiliary vector ending in
/// `AT_NULL`. Returns the stack pointer (the address of `argc`), or `None`
/// if it does not fit, a blob is not `argc`/`envc` NUL-terminated strings,
/// or `base` is not 16-byte aligned.
#[allow(clippy::too_many_arguments)]
pub fn layout_initial_stack(
    out: &mut [u8],
    base: u64,
    argv: &[u8],
    argc: usize,
    env: &[u8],
    envc: usize,
    random: &[u8; 16],
    aux: &ImageAux,
) -> Option<u64> {
    if base % 16 != 0 || argc > STACK_STRINGS_MAX || envc > STACK_STRINGS_MAX {
        return None;
    }
    let count = |blob: &[u8]| -> Option<usize> {
        if blob.is_empty() {
            return Some(0);
        }
        if *blob.last()? != 0 {
            return None;
        }
        Some(blob.iter().filter(|&&b| b == 0).count())
    };
    if count(argv)? != argc || count(env)? != envc {
        return None;
    }
    let top = out.len();
    // Strings, then the random bytes, at the top.
    let argv_at = top.checked_sub(argv.len() + env.len())?;
    let env_at = argv_at + argv.len();
    let random_at = (argv_at.checked_sub(16)?) & !15;
    // The pointer block: argc, argv[], NULL, envp[], NULL, auxv pairs.
    let mut auxv: [(u64, u64); 18] = [(0, 0); 18];
    let mut na = 0usize;
    let mut push = |k: u64, v: u64| {
        auxv[na] = (k, v);
        na += 1;
    };
    if aux.phdr != 0 {
        push(at::PHDR, aux.phdr);
    }
    push(at::PHENT, aux.phent);
    push(at::PHNUM, aux.phnum);
    push(at::PAGESZ, aux.pagesz);
    push(at::BASE, 0);
    push(at::FLAGS, 0);
    push(at::ENTRY, aux.entry);
    push(at::UID, 0);
    push(at::EUID, 0);
    push(at::GID, 0);
    push(at::EGID, 0);
    push(at::HWCAP, 0);
    push(at::CLKTCK, 100);
    push(at::SECURE, 0);
    push(at::RANDOM, base + random_at as u64);
    if argc > 0 {
        push(at::EXECFN, base + argv_at as u64);
    }
    push(at::NULL, 0);
    let words = 1 + argc + 1 + envc + 1 + 2 * na;
    let block = words * 8;
    let sp_at = (random_at.checked_sub(block)?) & !15;

    out.fill(0);
    out[argv_at..argv_at + argv.len()].copy_from_slice(argv);
    out[env_at..env_at + env.len()].copy_from_slice(env);
    out[random_at..random_at + 16].copy_from_slice(random);
    let mut w = sp_at;
    let mut put = |out: &mut [u8], v: u64| {
        out[w..w + 8].copy_from_slice(&v.to_le_bytes());
        w += 8;
    };
    put(out, argc as u64);
    let mut s = argv_at;
    for _ in 0..argc {
        put(out, base + s as u64);
        s += out[s..].iter().position(|&b| b == 0)? + 1;
    }
    put(out, 0);
    let mut s = env_at;
    for _ in 0..envc {
        put(out, base + s as u64);
        s += out[s..].iter().position(|&b| b == 0)? + 1;
    }
    put(out, 0);
    for &(k, v) in &auxv[..na] {
        put(out, k);
        put(out, v);
    }
    Some(base + sp_at as u64)
}
