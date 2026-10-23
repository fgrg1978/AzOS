// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CPU's own entropy instruction as a seed source for the kernel pool
//! (`ArchPlatform::cpu_seed`), the same model on every ISA:
//!
//! | ISA     | Instruction                          | Kconfig choice          | Probe |
//! |---------|--------------------------------------|-------------------------|-------|
//! | riscv64 | Zkr `seed` CSR (0x015), ES16 only    | RV_ZKR                  | cpu@0 `riscv,isa` + a trap-safe `csrrw` (M-mode must set `mseccfg.SSEED`) |
//! | aarch64 | FEAT_RNG `RNDRRS` (reseeded)         | A64_RNG                 | ID_AA64ISAR0_EL1.RNDR \[63:60\] |
//! | x86_64  | `RDSEED`, else `RDRAND`              | X86_RDSEED, X86_RDRAND  | CPUID |
//!
//! Whether the bytes are credited is Kconfig `ENTROPY_CPU_SOURCE`
//! ([`CpuCredit`]): `credit`, `mix-only`, or `off` (never read). Under
//! `credit` each instruction is credited at its own rate ([`Source::credit`],
//! owner decision 2026-10-23), not 1:1 across the board as Linux's
//! `RANDOM_TRUST_CPU` does:
//!
//! | Source   | Credit | Why |
//! |----------|--------|-----|
//! | `RDSEED` | 1:1    | conditioned entropy straight from the source (SP 800-90B/C) |
//! | `RNDRRS` | 1:1    | FEAT_RNG: reseeded from the true source before every read |
//! | Zkr ES16 | 1:2    | the spec asks a 2:1 conditioning of its output (see [`Source::ZkrSeed`]) |
//! | `RDRAND` | 0      | DRBG output: mixed, never counted toward a seed |
//!
//! The ISA crates read the instruction; the word loop, the retry bound, the
//! credit rates and the riscv64 status decode are here, pure, so the host
//! tests drive them with a scripted source.

/// The CPU instruction a [`CpuSeed`] came from, and what it is worth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// No source selected on this boot.
    None,
    /// x86_64 `RDSEED`.
    RdSeed,
    /// x86_64 `RDRAND`: the output of the CPU's DRBG, which the hardware
    /// reseeds on its own schedule. One RDRAND value carries no more entropy
    /// than the DRBG's last reseed spread over every value since, so it is
    /// mixed and credited 0.
    RdRand,
    /// aarch64 FEAT_RNG `RNDRRS`.
    Rndrrs,
    /// riscv64 Zkr `seed`, ES16 samples. RISC-V Cryptography Extensions
    /// Volume I (Scalar) v1.0.1, chapter "Entropy Source", section "Entropy
    /// Source Requirements" (§4.2 [verify the number; the heading is
    /// checked]): the requirement is that "2-to-1 cryptographic
    /// post-processing in 256-bit input blocks will yield 128-bit" full
    /// entropy, and the NIST SP 800-90B subsection recommends at least 512
    /// entropy bits to initialise a DRBG of 256-bit security. Credited at
    /// that ratio: two ES16 bytes count as one, so the pool's 48-byte seed
    /// takes 96 bytes (768 bits) of samples.
    ZkrSeed,
}

impl Source {
    /// The name the boot log prints.
    pub const fn name(self) -> &'static str {
        match self {
            Source::None => "none",
            Source::RdSeed => "rdseed",
            Source::RdRand => "rdrand",
            Source::Rndrrs => "rndrrs",
            Source::ZkrSeed => "zkr-seed",
        }
    }

    /// Bytes of entropy `bytes` bytes of this source's output are credited
    /// with (rounded down).
    pub const fn credit(self, bytes: usize) -> usize {
        match self {
            Source::RdSeed | Source::Rndrrs => bytes,
            Source::ZkrSeed => bytes / 2,
            Source::RdRand | Source::None => 0,
        }
    }
}

/// Output bytes per credited byte of the lowest credited rate ([`Source::ZkrSeed`]):
/// the kernel draws `seed bytes * DRAW_PER_CREDIT` so that any credited source
/// seeds the pool in one draw.
pub const DRAW_PER_CREDIT: usize = 2;

/// The result of one [`ArchPlatform::cpu_seed`](crate::ArchPlatform::cpu_seed)
/// draw (the kernel asks for `azos_crypto::entropy::SEED_BYTES` times
/// [`DRAW_PER_CREDIT`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuSeed {
    /// Bytes of `out` actually filled with instruction output (a prefix).
    pub bytes: usize,
    /// The instruction they came from, [`Source::None`] when no source was
    /// selected.
    pub source: Source,
}

impl CpuSeed {
    /// No source selected on this boot: nothing read.
    pub const NONE: Self = CpuSeed { bytes: 0, source: Source::None };

    /// The bytes of entropy the draw is credited with ([`Source::credit`]).
    pub const fn credit(&self) -> usize {
        self.source.credit(self.bytes)
    }
}

/// One attempt to read the instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Draw {
    /// `len` (1..=8) valid bytes in the low end of `word`, little-endian.
    Bytes { word: u64, len: u8 },
    /// The source had nothing this time (x86 CF=0, aarch64 NZCV.Z=1,
    /// riscv64 BIST/WAIT): try again, up to the bound.
    Retry,
    /// The source says it will never deliver (riscv64 DEAD): stop.
    Dead,
}

/// Fill `out` from `draw`, one word at a time, retrying each word at most
/// `retries` times after its first attempt. Returns the bytes filled (a
/// prefix of `out`); stops early at [`Draw::Dead`] or when one word's
/// retries run out, so a source that stops delivering costs at most
/// `retries + 1` attempts more, never a hang. `relax` runs between retries
/// (the ISA's pause hint).
pub fn fill(out: &mut [u8], retries: u32, mut draw: impl FnMut() -> Draw,
            mut relax: impl FnMut()) -> usize {
    let mut filled = 0usize;
    while filled < out.len() {
        let mut tries = 0u32;
        let (word, len) = loop {
            match draw() {
                Draw::Bytes { word, len } if len >= 1 => break (word, (len as usize).min(8)),
                Draw::Dead => return filled,
                // `Bytes` with len 0 is a source bug; it counts as a retry.
                _ => {
                    if tries >= retries {
                        return filled;
                    }
                    tries += 1;
                    relax();
                }
            }
        };
        let take = len.min(out.len() - filled);
        out[filled..filled + take].copy_from_slice(&word.to_le_bytes()[..take]);
        filled += take;
    }
    filled
}

/// The riscv64 Zkr `seed` CSR value (RISC-V Scalar Cryptography spec,
/// "Entropy Source"): OPST in bits 31:30 — `00` BIST and `01` WAIT are
/// transient, `10` ES16 carries 16 bits of entropy in bits 15:0, `11` DEAD
/// is a fatal source error.
pub const fn rv_seed_decode(csr: u64) -> Draw {
    match (csr >> 30) & 0b11 {
        0b10 => Draw::Bytes { word: csr & 0xFFFF, len: 2 },
        0b11 => Draw::Dead,
        _ => Draw::Retry,
    }
}

/// Kconfig `ENTROPY_CPU_SOURCE`: what the boot does with the CPU's bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CpuCredit {
    /// Mixed into the pool and credited at the instruction's own rate
    /// ([`Source::credit`]): RDSEED, RNDRRS or Zkr alone can seed it,
    /// RDRAND cannot.
    Credit,
    /// Mixed, never credited: the pool still needs another source.
    MixOnly,
    /// Never read.
    Off,
}

impl CpuCredit {
    /// The `make config` choice.
    pub const CONFIG: CpuCredit = if azos_limits::ENTROPY_CPU_SOURCE_OFF {
        CpuCredit::Off
    } else if azos_limits::ENTROPY_CPU_SOURCE_MIX {
        CpuCredit::MixOnly
    } else {
        CpuCredit::Credit
    };
}

/// Kconfig `ENTROPY_CPU_RETRIES`: retries per word before the source is
/// given up for this boot.
pub const RETRIES: u32 = azos_limits::ENTROPY_CPU_RETRIES as u32;
