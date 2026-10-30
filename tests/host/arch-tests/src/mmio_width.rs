// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_arch_api::mmio` on this host's memory: each accessor touches exactly
//! its width at exactly its address, the contract a register depends on. On an
//! aarch64 host this runs the `asm!` bodies the kernel runs.

use azos_arch_api::mmio;

#[repr(align(16))]
struct Window([u8; 32]);

const AT: usize = 8;

fn window() -> Window {
    Window([0x5a; 32])
}

fn only_changed(w: &Window, width: usize) {
    for (i, b) in w.0.iter().enumerate() {
        if !(AT..AT + width).contains(&i) {
            assert_eq!(*b, 0x5a, "byte {i} changed by a {width}-byte write");
        }
    }
}

#[test]
fn a_write_touches_its_width_and_nothing_else() {
    let mut w = window();
    let a = w.0.as_mut_ptr() as usize + AT;
    unsafe { mmio::write8(a, 0x11) };
    assert_eq!(w.0[AT], 0x11);
    only_changed(&w, 1);

    let mut w = window();
    let a = w.0.as_mut_ptr() as usize + AT;
    unsafe { mmio::write16(a, 0x2211) };
    assert_eq!(w.0[AT..AT + 2], 0x2211u16.to_ne_bytes());
    only_changed(&w, 2);

    let mut w = window();
    let a = w.0.as_mut_ptr() as usize + AT;
    unsafe { mmio::write32(a, 0x4433_2211) };
    assert_eq!(w.0[AT..AT + 4], 0x4433_2211u32.to_ne_bytes());
    only_changed(&w, 4);

    let mut w = window();
    let a = w.0.as_mut_ptr() as usize + AT;
    unsafe { mmio::write64(a, 0x8877_6655_4433_2211) };
    assert_eq!(w.0[AT..AT + 8], 0x8877_6655_4433_2211u64.to_ne_bytes());
    only_changed(&w, 8);
}

#[test]
fn a_read_returns_its_width_zero_extended() {
    let mut w = window();
    w.0[AT..AT + 8].copy_from_slice(&0x8877_6655_4433_2211u64.to_ne_bytes());
    let a = w.0.as_ptr() as usize + AT;
    let v64 = u64::from_ne_bytes(w.0[AT..AT + 8].try_into().unwrap());
    unsafe {
        assert_eq!(mmio::read8(a) as u64, v64 & 0xff);
        assert_eq!(mmio::read16(a) as u64, v64 & 0xffff);
        assert_eq!(mmio::read32(a) as u64, v64 & 0xffff_ffff);
        assert_eq!(mmio::read64(a), v64);
    }
}
