// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two kernel-owned regions the ring-3 terminal server (`TERMD.ELF`)
//! turns into keys and a mouse, as gpm does on a Linux console:
//!
//! * **`input.events`** (a keyboard or mouse driver configured: Kconfig
//!   `DRV_VIRTIO_INPUT`, `DRV_PS2`): the ring of events no driver turned into
//!   a console byte (`azos_drv_input::events`). The drivers write it through
//!   the direct map, the server maps it and moves the tail.
//! * **`console.screen`** (Kconfig `FB_CONSOLE`): the framebuffer console's
//!   screen region (`azos_input_wire::screen`): what is on the screen, the
//!   lines scrolled off it (`FB_CONSOLE_SCROLLBACK`), the mouse modes
//!   programs set, and the overlay the server asks the renderer to draw.
//!
//! Both are contiguous memory objects the kernel creates here, once, and
//! publishes to the minter (`azos_ipc::kregion`); a topology row grants one
//! with `MemObj input.events` / `MemObj console.screen`, `READ|WRITE|MAP`
//! (`TERMD.ELF`'s row is the only one). No task has them otherwise: they are
//! not reachable by name, address or ambient access.
//!
//! Called from `kernel_main` after the framebuffer is up (so the grid is
//! there to publish) and before any input line is enabled (so the ring is
//! there to publish into) and before any task is seeded.

use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec};

/// A kernel-owned read-write region of at least `bytes` bytes: its packed
/// reference, the base in the direct map, its size.
fn region(bytes: usize) -> Option<(u32, *mut u8, usize)> {
    let pages = bytes.div_ceil(azos_arch::PAGE_SIZE);
    let (obj, phys) = memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadWrite, false))?;
    Some((obj, azos_mm::addr::phys_to_virt(phys) as *mut u8, pages * azos_arch::PAGE_SIZE))
}

/// Create and publish the regions this build has.
pub(crate) fn install() {
    // The one minter of every kernel-owned region (also the introspection
    // ones): installed here and by `install_inspect`, the same function.
    azos_ipc::cap_seed::set_shm_inspect_minter(azos_ipc::kregion::seed_mint_any);
    #[cfg(any(feature = "virtio-input", feature = "ps2"))]
    install_input_ring();
    #[cfg(feature = "fb-console")]
    install_screen();
}

#[cfg(any(feature = "virtio-input", feature = "ps2"))]
fn install_input_ring() {
    let Some((obj, base, _)) = region(azos_drv_input::events::RING_BYTES) else {
        azos_drv_sys::kwarn!("[INPUT] no memory for the event ring: keys with no byte and the mouse are not delivered");
        return;
    };
    // SAFETY: a fresh, zeroed, page-aligned kernel-owned region that is never
    // freed; the consumer's mapping of it is shared memory by design.
    if unsafe { azos_drv_input::events::install(base as usize) } {
        azos_ipc::kregion::publish(azos_ipc::kregion::Region::InputEvents, obj);
        azos_drv_sys::kprintln!("[INPUT] event ring {} slots, granted as MemObj input.events", azos_input_wire::event::RING_CAP);
    }
}

#[cfg(feature = "fb-console")]
fn install_screen() {
    use azos_input_wire::screen::{Layout, Publisher};
    let l = Layout {
        cols_max: azos_limits::FB_CONSOLE_COLS_MAX as u32,
        rows_max: azos_limits::FB_CONSOLE_ROWS_MAX as u32,
        sb_cap: azos_limits::FB_CONSOLE_SCROLLBACK as u32,
    };
    let Some((obj, base, len)) = region(l.bytes()) else {
        azos_drv_sys::kwarn!("[FB] no memory for the screen region: no selection or scrollback");
        return;
    };
    // SAFETY: a fresh, zeroed, kernel-owned region that is never freed; every
    // other access to it goes through `azos_input_wire::screen`.
    let Some(p) = (unsafe { Publisher::format(base, len, l) }) else { return };
    azos_ipc::kregion::publish(azos_ipc::kregion::Region::ConsoleScreen, obj);
    // Without a framebuffer there is no grid to publish: the region stays
    // formatted at 0x0, which the server reads as "no screen".
    let live = azos_fb::console::attach_screen(p);
    azos_drv_sys::kprintln!(
        "[FB] screen region {} KiB ({} lines of scrollback), granted as MemObj console.screen{}",
        len / 1024,
        l.sb_cap,
        if live { "" } else { " (no console to publish)" }
    );
}
