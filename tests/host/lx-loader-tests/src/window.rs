// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The module window: the planner's addresses (`azos_lx_loader::Window`),
//! and the filesystem set relocated where the planner puts it, against a
//! server image at the lowest user address.

use super::{fnv, host_abi, FS_ORDER};
use azos_lx_loader::{Error, Isa, Layout, Module, Placement, Window, WindowError};
use std::collections::BTreeMap;

const PAGE: u64 = 4096;
/// The lowest address a server image is linked at (`sdk/ld/user_*.ld`:
/// 0x10000 on aarch64 and x86_64; riscv64 links higher, which is nearer).
const IMAGE: u64 = 0x1_0000;

fn kconfig_window() -> Window {
    Window::new(azos_limits::LX_MODULE_WINDOW_BASE as u64, azos_limits::LX_MODULE_WINDOW_SIZE as u64, PAGE).unwrap()
}

fn layout(text: u64, data: u64) -> Layout {
    Layout { text_size: text, text_align: 8, data_size: data, data_align: 8 }
}

fn pages(base: u64, len: u64) -> std::ops::Range<u64> {
    base / PAGE..(base + len).div_ceil(PAGE)
}

#[test]
fn text_and_data_never_share_a_page_and_a_guard_page_follows() {
    let mut w = Window::new(0x400_0000, 0x10_0000, PAGE).unwrap();
    let a = w.place(&layout(5000, 100)).unwrap();
    assert_eq!(a, Placement { text_base: 0x400_0000, text_len: 2 * PAGE, data_base: 0x400_2000, data_len: PAGE });
    let b = w.place(&layout(1, 0)).unwrap();
    assert_eq!(b.text_base, 0x400_4000, "one unmapped page after a's data");
    assert_eq!(b.data_len, PAGE, "a data region is at least one page");
    for p in [a, b] {
        let (t, d) = (pages(p.text_base, p.text_len), pages(p.data_base, p.data_len));
        assert!(t.end <= d.start, "text and data share a page: {p:?}");
    }
}

#[test]
fn a_large_alignment_is_honoured_and_a_module_without_text_takes_none() {
    let mut w = Window::new(0x400_0000, 0x10_0000, PAGE).unwrap();
    w.place(&layout(10, 10)).unwrap();
    let a = w.place(&Layout { text_size: 64, text_align: 0x1_0000, data_size: 8, data_align: 0x4000 }).unwrap();
    assert_eq!((a.text_base % 0x1_0000, a.data_base % 0x4000), (0, 0));
    let n = w.place(&layout(0, 8)).unwrap();
    assert_eq!(n.text_len, 0);
}

#[test]
fn a_module_that_does_not_fit_is_refused_and_takes_nothing() {
    let mut w = Window::new(0x400_0000, 4 * PAGE, PAGE).unwrap();
    assert_eq!(w.place(&layout(3 * PAGE, 2 * PAGE)), Err(WindowError::Full));
    assert_eq!(w.cursor(), 0x400_0000, "a refusal moved the cursor");
    assert!(w.place(&layout(2 * PAGE, PAGE)).is_ok(), "text and data exactly fill it");
    assert_eq!(w.place(&layout(0, 1)), Err(WindowError::Full), "the guard page is the last one");
}

#[test]
fn a_misaligned_or_empty_window_is_refused() {
    assert_eq!(Window::new(0x400_0001, 0x1000, PAGE).err(), Some(WindowError::Misaligned));
    assert_eq!(Window::new(0x400_0000, 0x1001, PAGE).err(), Some(WindowError::Misaligned));
    assert_eq!(Window::new(0x400_0000, 0, PAGE).err(), Some(WindowError::Misaligned));
    assert_eq!(Window::new(u64::MAX - 0xfff, 0x2000, PAGE).err(), Some(WindowError::Misaligned));
}

/// Loads the filesystem set at the addresses `w` gives each module, with the
/// host ABI and every import no module of the set provides at the server
/// image, `IMAGE` upward. `Err` is the first module the loader refused, and
/// why.
fn fs_in(isa: Isa, mut w: Window) -> Option<Result<(), String>> {
    let isa_dir = if isa == Isa::Riscv64 { "riscv64" } else { "aarch64" };
    let mut exports: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    for n in FS_ORDER {
        let path = format!("{}/build/lx/kbuild/{isa_dir}/{n}", env!("AZOS_OUT"));
        let Ok(obj) = std::fs::read(&path) else {
            assert!(std::env::var_os("LX_REQUIRE_FS").is_none(), "{path} not built, but LX_REQUIRE_FS is set");
            eprintln!("SKIP: {path} not built (make lx-kbuild)");
            return None;
        };
        let m = Module::parse(&obj, Some(isa)).unwrap();
        let l = m.layout().unwrap();
        let p = w.place(&l).unwrap_or_else(|e| panic!("{isa:?} {n}: {e:?}"));
        let mut text = vec![0u8; p.text_len as usize];
        let mut data = vec![0u8; p.data_len as usize];
        let mut resolve = |s: &[u8]| -> Option<u64> {
            Some(match (host_abi(s), exports.get(s)) {
                (Some(a), _) => a - 0x1000_2000 + IMAGE,
                (None, Some(&a)) => a,
                (None, None) => IMAGE + 0x1000 + (fnv(s) % 0x1_0000) * 16,
            })
        };
        let loaded = match m.load(&mut text, p.text_base, &mut data, p.data_base, &mut resolve) {
            Ok(l) => l,
            Err(Error::Overflow(t, off)) => return Some(Err(format!("{n}: relocation type {t} at {off:#x} does not reach"))),
            Err(e) => return Some(Err(format!("{n}: {e:?}"))),
        };
        loaded.for_each_export(&data, |s, a| {
            exports.insert(s.to_vec(), a);
        }).unwrap();
    }
    Some(Ok(()))
}

/// The set relocates in the Kconfig window on each ISA, every branch to the
/// server image and between modules within reach.
#[test]
fn the_fs_set_relocates_in_the_kconfig_window() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        if let Some(r) = fs_in(isa, kconfig_window()) {
            assert_eq!(r, Ok(()), "{isa:?}");
        }
    }
}

/// Why the window must end within 128 MiB of the image: one placed past an
/// aarch64 direct branch refuses the set on aarch64, while riscv64's
/// PC-relative pairs (2 GiB) still reach.
#[test]
fn a_window_past_an_aarch64_branch_of_the_image_refuses_the_aarch64_set() {
    let far = || Window::new(0x1000_0000, 0x200_0000, PAGE).unwrap();
    let Some(a64) = fs_in(Isa::Aarch64, far()) else { return };
    let e = a64.expect_err("aarch64 loaded the set 256 MiB from the image");
    assert!(e.contains("type 283") || e.contains("type 282"), "not a CALL26/JUMP26 refusal: {e}");
    if let Some(rv) = fs_in(Isa::Riscv64, far()) {
        assert_eq!(rv, Ok(()), "riscv64 reaches 2 GiB");
    }
}
