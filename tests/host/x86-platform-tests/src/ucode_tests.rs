// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The microcode loader's choice (`arch/x86_64/src/cpu/ucode.rs`)
//! on synthetic containers built byte by byte to Intel's and AMD's layouts:
//! the checksums, the signature and platform-flag match, the extended
//! signature table, AMD's equivalence table, the image's sections. Canary:
//! `--features x86-ucode-canary` (the Intel checksum is not computed), under
//! which `a_corrupted_update_is_refused` fails.

use super::cpu::features::Vendor;
use super::ucode::{self, intel, Choice, CpuSig, Error, Patch};

// ── builders ────────────────────────────────────────────────────────────────

fn put(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn dword_sum(b: &[u8]) -> u32 {
    b.chunks_exact(4).fold(0u32, |a, w| a.wrapping_add(u32::from_le_bytes(w.try_into().unwrap())))
}

/// An Intel update: header, `data` bytes of data, and an extended signature
/// table when `ext` names rows, every checksum right.
fn intel_update(sig: u32, pf: u32, rev: u32, data: usize, ext: &[(u32, u32)]) -> Vec<u8> {
    let ext_len = if ext.is_empty() { 0 } else { 20 + 12 * ext.len() };
    let total = 48 + data + ext_len;
    let mut u = vec![0u8; total];
    put(&mut u, 0, 1); // header version
    put(&mut u, 4, rev);
    put(&mut u, 8, 0x1023_2026); // date
    put(&mut u, 12, sig);
    put(&mut u, 20, 1); // loader version
    put(&mut u, 24, pf);
    put(&mut u, 28, data as u32);
    put(&mut u, 32, total as u32);
    for (i, b) in u[48..48 + data].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let ck = 0u32.wrapping_sub(dword_sum(&u[..48 + data]));
    put(&mut u, 16, ck);
    if !ext.is_empty() {
        let t = 48 + data;
        put(&mut u, t, ext.len() as u32);
        let own = sig.wrapping_add(pf).wrapping_add(ck);
        for (i, &(s, p)) in ext.iter().enumerate() {
            let r = t + 20 + 12 * i;
            put(&mut u, r, s);
            put(&mut u, r + 4, p);
            put(&mut u, r + 8, own.wrapping_sub(s).wrapping_sub(p));
        }
        let ek = 0u32.wrapping_sub(dword_sum(&u[t..]));
        put(&mut u, t + 4, ek);
    }
    u
}

/// One AMD container: the equivalence table (`(installed CPU, id)` rows and
/// the terminating zero row), then a patch section per `(patch_id,
/// processor_rev_id, size)`.
fn amd_container(equiv: &[(u32, u16)], patches: &[(u32, u16, usize)]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&ucode::amd::MAGIC.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&(16 * (equiv.len() as u32 + 1)).to_le_bytes());
    for &(cpu, id) in equiv.iter().chain([(0, 0)].iter()) {
        c.extend_from_slice(&cpu.to_le_bytes());
        c.extend_from_slice(&[0; 8]);
        c.extend_from_slice(&id.to_le_bytes());
        c.extend_from_slice(&[0; 2]);
    }
    for &(id, rev_id, size) in patches {
        c.extend_from_slice(&1u32.to_le_bytes());
        c.extend_from_slice(&(size as u32).to_le_bytes());
        let mut p = vec![0u8; size];
        put(&mut p, 0, 0x2026_1023); // data_code
        put(&mut p, 4, id);
        p[24..26].copy_from_slice(&rev_id.to_le_bytes());
        c.extend_from_slice(&p);
    }
    c
}

/// The image's payload: header and one section per `(tag, body)`.
fn payload(sections: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ucode::MAGIC);
    v.extend_from_slice(&ucode::VERSION.to_le_bytes());
    v.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    for (tag, body) in sections {
        v.extend_from_slice(*tag);
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(body);
        v.resize(v.len().next_multiple_of(16), 0);
    }
    v
}

// Skylake-S (family 6 model 0x5e stepping 3) and Rome (family 0x17 model
// 0x31 stepping 0), the gate's QEMU models.
const SKL: u32 = 0x0005_06e3;
const ROME: u32 = 0x0083_0f10;
const ROME_ID: u16 = 0x8310;

fn intel_cpu(sig: u32, pf: u32, rev: u32) -> CpuSig {
    CpuSig { vendor: Vendor::Intel, sig, pf, rev }
}

fn amd_cpu(sig: u32, rev: u32) -> CpuSig {
    CpuSig { vendor: Vendor::Amd, sig, pf: 0, rev }
}

fn rev_of(c: Choice) -> Option<u32> {
    match c {
        Choice::Load(p) => Some(p.rev),
        _ => None,
    }
}

// ── Intel ───────────────────────────────────────────────────────────────────

#[test]
fn an_intel_update_is_chosen_by_signature_and_platform_flag() {
    let u = intel_update(SKL, 0x36, 0xf0, 1024 - 48, &[]);
    let p = payload(&[(&ucode::TAG_INTEL, &u)]);
    // The flags intersect (0x02 is in 0x36): chosen, at the section's body.
    let c = ucode::select(&p, &intel_cpu(SKL, 0x02, 0xc2)).unwrap();
    assert_eq!(c, Choice::Load(Patch { off: 32, len: 1024, rev: 0xf0 }));
    // Same signature, a flag the update does not list: not for this CPU.
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x01, 0xc2)).unwrap(), Choice::None);
    // Another stepping: not for this CPU.
    assert_eq!(ucode::select(&p, &intel_cpu(SKL + 1, 0x02, 0xc2)).unwrap(), Choice::None);
}

#[test]
fn processor_flags_match_when_both_are_zero() {
    let u = intel_update(0x0000_0f29, 0, 0x2e, 2000, &[]);
    let p = payload(&[(&ucode::TAG_INTEL, &u)]);
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(0x0f29, 0, 0x10)).unwrap()), Some(0x2e));
    // A CPU with a flag and an update with none: no intersection.
    assert_eq!(ucode::select(&p, &intel_cpu(0x0f29, 0x04, 0x10)).unwrap(), Choice::None);
}

#[test]
fn the_platform_flag_comes_from_msr_bits_52_to_50() {
    // Family 6 model 0x5e: bits 52:50 = 0b101 -> bit 5.
    assert_eq!(ucode::intel_platform_flag(SKL, 5 << 50), 1 << 5);
    // Family 6 model 3 (Klamath) has no platform id: flag 0.
    assert_eq!(ucode::intel_platform_flag(0x0000_0633, 5 << 50), 0);
    // Family 0xF (NetBurst), model 2: it has one.
    assert_eq!(ucode::intel_platform_flag(0x0000_0f29, 1 << 50), 1 << 1);
    assert_eq!((ucode::family(SKL), ucode::model(SKL)), (6, 0x5e));
    assert_eq!((ucode::family(ROME), ucode::model(ROME)), (0x17, 0x31));
}

#[test]
fn a_corrupted_update_is_refused() {
    let mut u = intel_update(SKL, 0x02, 0xf0, 2048 - 48, &[]);
    u[600] ^= 0x40;
    let p = payload(&[(&ucode::TAG_INTEL, &u)]);
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xc2)), Err(Error::IntelChecksum));
    // A corrupted header word too (the checksum covers the header).
    let mut u = intel_update(SKL, 0x02, 0xf0, 2048 - 48, &[]);
    put(&mut u, 8, 0x1024_2026);
    let p = payload(&[(&ucode::TAG_INTEL, &u)]);
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xc2)), Err(Error::IntelChecksum));
}

#[test]
fn a_corrupted_update_for_another_cpu_is_not_looked_at() {
    // Linux checks the sums of a matching update only; the walk still needs
    // its header to step over it.
    let mut other = intel_update(SKL + 1, 0x02, 0xf0, 1024 - 48, &[]);
    other[100] ^= 1;
    let mine = intel_update(SKL, 0x02, 0xf4, 1024 - 48, &[]);
    let body = [other, mine].concat();
    let p = payload(&[(&ucode::TAG_INTEL, &body)]);
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xc2)).unwrap()), Some(0xf4));
}

#[test]
fn the_extended_table_names_more_cpus() {
    // Header for stepping 3, the table adds stepping 4 with flag 0x80.
    let u = intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[(SKL + 1, 0x80), (SKL + 2, 0x01)]);
    assert_eq!(u.len(), 1024 + 44);
    let p = payload(&[(&ucode::TAG_INTEL, &u)]);
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(SKL + 1, 0x80, 0)).unwrap()), Some(0xf0));
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(SKL + 2, 0x01, 0)).unwrap()), Some(0xf0));
    assert_eq!(ucode::select(&p, &intel_cpu(SKL + 1, 0x02, 0)).unwrap(), Choice::None);
    let h = intel::header(&u).unwrap();
    assert!(intel::check(&u, &h).is_ok());
}

#[test]
fn a_broken_extended_table_is_refused() {
    let good = intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[(SKL + 1, 0x80)]);
    let t = 1024;
    let cpu = intel_cpu(SKL + 1, 0x80, 0);
    // A row that does not balance against the header (the table's own sum
    // fixed up, so only the row is wrong).
    let mut u = good.clone();
    let w = get(&u, t + 20 + 8).wrapping_add(1);
    put(&mut u, t + 20 + 8, w);
    let w = get(&u, t + 4).wrapping_sub(1);
    put(&mut u, t + 4, w);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_INTEL, &u)]), &cpu), Err(Error::IntelExtTable));
    // The table's sum.
    let mut u = good.clone();
    let w = get(&u, t + 4).wrapping_add(1);
    put(&mut u, t + 4, w);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_INTEL, &u)]), &cpu), Err(Error::IntelExtTable));
    // A count that does not fill the table.
    let mut u = good.clone();
    put(&mut u, t, 2);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_INTEL, &u)]), &cpu), Err(Error::IntelExtTable));
    // The header's own CPU is checked against the table as well.
    let mut u = good;
    let w = get(&u, t + 4).wrapping_add(1);
    put(&mut u, t + 4, w);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_INTEL, &u)]), &intel_cpu(SKL, 0x02, 0)),
               Err(Error::IntelExtTable));
}

#[test]
fn an_intel_header_must_be_version_one_with_sizes_that_fit() {
    let cpu = intel_cpu(SKL, 0x02, 0);
    let good = intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[]);
    for (off, v) in [(0, 2u32), (20, 0), (28, 1024), (32, 4096), (28, 1022)] {
        let mut u = good.clone();
        put(&mut u, off, v);
        assert_eq!(ucode::select(&payload(&[(&ucode::TAG_INTEL, &u)]), &cpu), Err(Error::IntelHeader), "word {off} = {v}");
    }
    // A data size of 0 is the old format: 2000 bytes of data, 2048 in all.
    let mut u = intel_update(SKL, 0x02, 0xf0, 2000, &[]);
    put(&mut u, 28, 0);
    put(&mut u, 32, 0);
    let h = intel::header(&u).unwrap();
    assert_eq!((h.data_size, h.total_size), (2000, 2048));
}

#[test]
fn the_newest_update_wins_and_nothing_is_downgraded() {
    let body = [
        intel_update(SKL, 0x02, 0xc6, 1024 - 48, &[]),
        intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[]),
        intel_update(SKL, 0x02, 0xd6, 1024 - 48, &[]),
    ]
    .concat();
    let p = payload(&[(&ucode::TAG_INTEL, &body)]);
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xc2)).unwrap(),
               Choice::Load(Patch { off: 32 + 1024, len: 1024, rev: 0xf0 }));
    // The firmware already loaded the newest: nothing to do.
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xf0)).unwrap(), Choice::Current { newest: 0xf0 });
    assert_eq!(ucode::select(&p, &intel_cpu(SKL, 0x02, 0xf8)).unwrap(), Choice::Current { newest: 0xf0 });
}

// ── AMD ─────────────────────────────────────────────────────────────────────

#[test]
fn an_amd_patch_is_chosen_by_equivalence_id() {
    let c = amd_container(&[(0x0080_0f12, 0x8012), (ROME, ROME_ID)],
                          &[(0x0800_126e, 0x8012, 3200), (0x0830_107c, ROME_ID, 3200)]);
    let p = payload(&[(&ucode::TAG_AMD, &c)]);
    // Rome: the second patch, right after its 8-byte section header.
    let first = 12 + 48 + 8 + 3200;
    assert_eq!(ucode::select(&p, &amd_cpu(ROME, 0x0830_1000)).unwrap(),
               Choice::Load(Patch { off: 32 + first + 8, len: 3200, rev: 0x0830_107c }));
    // A CPU the table does not list.
    assert_eq!(ucode::select(&p, &amd_cpu(0x00a2_0f10, 0)).unwrap(), Choice::None);
    // Up to date already.
    assert_eq!(ucode::select(&p, &amd_cpu(ROME, 0x0830_107c)).unwrap(), Choice::Current { newest: 0x0830_107c });
}

#[test]
fn an_amd_patch_for_another_equivalence_id_or_family_is_not_chosen() {
    // Rome's row names id 0x8310; the only patch is for 0x8301.
    let c = amd_container(&[(ROME, ROME_ID)], &[(0x0830_107c, 0x8301, 3200)]);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_AMD, &c)]), &amd_cpu(ROME, 0)).unwrap(), Choice::None);
    // The id matches but the patch's family (0xF + 0xA) is not the CPU's 0x17.
    let c = amd_container(&[(ROME, 0xA310)], &[(0x0830_107c, 0xA310, 3200)]);
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_AMD, &c)]), &amd_cpu(ROME, 0)).unwrap(), Choice::None);
}

#[test]
fn amd_containers_back_to_back_are_each_read() {
    // microcode_amd.bin's shape: one container per family, concatenated.
    let fam15 = amd_container(&[(0x0060_0f12, 0x6012)], &[(0x0600_063e, 0x6012, 2592)]);
    let fam17 = amd_container(&[(ROME, ROME_ID)], &[(0x0830_107c, ROME_ID, 3200)]);
    let body = [fam15.clone(), fam17].concat();
    let p = payload(&[(&ucode::TAG_AMD, &body)]);
    assert_eq!(rev_of(ucode::select(&p, &amd_cpu(ROME, 0)).unwrap()), Some(0x0830_107c));
    assert_eq!(rev_of(ucode::select(&p, &amd_cpu(0x0060_0f12, 0)).unwrap()), Some(0x0600_063e));
    // Junk where the next container should start.
    let body = [fam15, vec![0x55; 16]].concat();
    assert_eq!(ucode::select(&payload(&[(&ucode::TAG_AMD, &body)]), &amd_cpu(ROME, 0)), Err(Error::AmdContainer));
}

#[test]
fn a_malformed_amd_container_is_refused() {
    let good = amd_container(&[(ROME, ROME_ID)], &[(0x0830_107c, ROME_ID, 3200)]);
    let cpu = amd_cpu(ROME, 0);
    let sel = |c: &[u8]| ucode::select(&payload(&[(&ucode::TAG_AMD, c)]), &cpu);
    let mut c = good.clone();
    c[0] ^= 1; // magic
    assert_eq!(sel(&c), Err(Error::AmdContainer));
    let mut c = good.clone();
    put(&mut c, 8, 8); // an equivalence table shorter than a row
    assert_eq!(sel(&c), Err(Error::AmdContainer));
    let mut c = good.clone();
    put(&mut c, 8, 1 << 20); // past the end
    assert_eq!(sel(&c), Err(Error::AmdContainer));
    let mut c = good.clone();
    put(&mut c, 12 + 32 + 4, 32); // a patch shorter than its header
    assert_eq!(sel(&c), Err(Error::AmdPatch));
    let mut c = good;
    put(&mut c, 12 + 32 + 4, 4000); // a patch past the end
    assert_eq!(sel(&c), Err(Error::AmdPatch));
}

// ── the image ───────────────────────────────────────────────────────────────

#[test]
fn each_vendor_reads_its_own_section() {
    let i = intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[]);
    let a = amd_container(&[(ROME, ROME_ID)], &[(0x0830_107c, ROME_ID, 3200)]);
    let p = payload(&[(&ucode::TAG_INTEL, &i), (&ucode::TAG_AMD, &a)]);
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(SKL, 0x02, 0)).unwrap()), Some(0xf0));
    assert_eq!(rev_of(ucode::select(&p, &amd_cpu(ROME, 0)).unwrap()), Some(0x0830_107c));
    // The AMD body starts 16-aligned after the Intel one.
    match ucode::select(&p, &amd_cpu(ROME, 0)).unwrap() {
        Choice::Load(pt) => assert_eq!(pt.off, 32 + 1024 + 16 + 12 + 32 + 8),
        c => panic!("{c:?}"),
    }
    // An Intel CPU does not parse the AMD section: a broken one is not its
    // concern (the image as a whole is signed).
    let mut bad = a.clone();
    bad[0] ^= 1;
    let p = payload(&[(&ucode::TAG_INTEL, &i), (&ucode::TAG_AMD, &bad)]);
    assert_eq!(rev_of(ucode::select(&p, &intel_cpu(SKL, 0x02, 0)).unwrap()), Some(0xf0));
    assert_eq!(ucode::select(&p, &amd_cpu(ROME, 0)), Err(Error::AmdContainer));
}

#[test]
fn a_malformed_image_is_refused_before_any_section_is_read() {
    let i = intel_update(SKL, 0x02, 0xf0, 1024 - 48, &[]);
    let good = payload(&[(&ucode::TAG_INTEL, &i)]);
    let cpu = intel_cpu(SKL, 0x02, 0);
    assert!(ucode::select(&good, &cpu).is_ok());
    let cases: [(&str, Box<dyn Fn(&mut Vec<u8>)>); 7] = [
        ("magic", Box::new(|p| p[0] ^= 1)),
        ("version", Box::new(|p| put(p, 8, 2))),
        ("one more section than there is", Box::new(|p| put(p, 12, 2))),
        ("unknown tag", Box::new(|p| p[16] = b'X')),
        ("reserved word", Box::new(|p| p[16 + 9] = 1)),
        ("body past the end", Box::new(|p| put(p, 20, 4096))),
        ("trailing bytes", Box::new(|p| p.extend_from_slice(&[0; 16]))),
    ];
    for (what, f) in cases {
        let mut p = good.clone();
        f(&mut p);
        assert_eq!(ucode::select(&p, &cpu), Err(Error::Section), "{what}");
    }
    // A truncated image: refused even for a CPU whose patch sits before the cut.
    let i2 = intel_update(SKL + 1, 0x02, 0xf0, 1024 - 48, &[]);
    let p = payload(&[(&ucode::TAG_INTEL, &i), (&ucode::TAG_AMD, &i2)]);
    assert_eq!(ucode::select(&p[..p.len() - 16], &cpu), Err(Error::Section));
    // An unknown vendor reads no section, but the structure still holds.
    let unknown = CpuSig { vendor: Vendor::Unknown, sig: 0, pf: 0, rev: 0 };
    assert_eq!(ucode::select(&good, &unknown).unwrap(), Choice::None);
}

// ── the published files, when the downloads are on this host ────────────────

/// `$AZOS_DL` (default `~/azos-dl`), where mk/firmware.mk reads the vendors'
/// files from; the test says so and passes when they are not there.
fn dl() -> Option<std::path::PathBuf> {
    let d = std::env::var_os("AZOS_DL").map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join("azos-dl")))?;
    d.is_dir().then_some(d)
}

#[test]
fn every_published_intel_update_parses_and_is_chosen_for_its_own_cpu() {
    let Some(dir) = dl().map(|d| d.join("intel-ucode/intel-ucode")).filter(|d| d.is_dir()) else {
        eprintln!("intel-ucode not downloaded: skipped");
        return;
    };
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let f = std::fs::read(e.unwrap().path()).unwrap();
        let p = payload(&[(&ucode::TAG_INTEL, &f)]);
        let mut off = 0;
        while off < f.len() {
            let h = intel::header(&f[off..]).unwrap();
            let c = ucode::select(&p, &intel_cpu(h.sig, h.pf & h.pf.wrapping_neg(), 0)).unwrap();
            assert!(matches!(c, Choice::Load(pt) if pt.rev >= h.rev), "{:#x}", h.sig);
            off += h.total_size;
            n += 1;
        }
    }
    assert!(n > 100, "{n} updates");
}

#[test]
fn every_published_amd_container_parses() {
    let Some(dir) = dl().map(|d| d.join("amd-fw/amd-ucode")).filter(|d| d.is_dir()) else {
        eprintln!("amd-ucode not downloaded: skipped");
        return;
    };
    let mut found = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        if path.extension().is_some_and(|x| x == "bin") {
            let f = std::fs::read(&path).unwrap();
            let p = payload(&[(&ucode::TAG_AMD, &f)]);
            // Every installed CPU of every table; most have a patch.
            let mut off = 0;
            while off < f.len() {
                let eq = get(&f, off + 8) as usize;
                for row in f[off + 12..off + 12 + eq].chunks_exact(16) {
                    let cpu = get(row, 0);
                    if cpu != 0 && rev_of(ucode::select(&p, &amd_cpu(cpu, 0)).unwrap()).is_some() {
                        found += 1;
                    }
                }
                // The next container: past the patch sections.
                let mut q = off + 12 + eq;
                while q < f.len() && get(&f, q) == 1 {
                    q += 8 + get(&f, q + 4) as usize;
                }
                off = q;
            }
        }
    }
    // Rome B0 is in fam17h's table, with a patch.
    assert!(found > 20, "{found} CPUs with a patch");
}
