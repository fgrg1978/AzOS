// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The autorun loader's staging buffer: no static buffer, one run of frames of
//! exactly the image's size, refused (with a receipt) past the budget of the
//! row that bounds it. The run is charged to no Domain: the loading kernel
//! task's Domain has no limit to refuse with until the exec commits, and a
//! charge would feed the census peak the budget rows are sized from.
//! `kernel/src/tasks/loader_admit.rs` is compiled unchanged; the loader
//! (`kernel/src/tasks/loader.rs`) cannot be built for the host, so its order of
//! operations is pinned on its source.
//!
//! Three buckets. DISCRIMINATING (red when the check is dropped, off by one
//! frame, or when the loader keeps the buffer past the exec's commit): the
//! exact-fit and one-byte-over rows, the rounding row, the source-order pins.
//! The rest check shape.
//!
//! Wired into the suite by `mod loader_admit;` in `src/lib.rs`.

#[allow(dead_code)]
#[path = "../../../../kernel/src/tasks/loader_admit.rs"]
mod admit_src;
use admit_src::{admit, Refusal};

const FRAME: u64 = 4096;
const RUN: u32 = 1 << 14;

#[test]
fn an_image_that_fills_its_budget_exactly_is_staged() {
    assert_eq!(admit(64 * FRAME, FRAME, 64, RUN), Ok(64));
}

#[test]
fn one_byte_over_the_budget_is_refused_with_the_frames_it_needed() {
    // DISCRIMINATES: the compare against the limit (a `>=`, or none, goes red).
    let r = admit(64 * FRAME + 1, FRAME, 64, RUN);
    assert_eq!(r, Err(Refusal::OverBudget { frames: 65, limit: 64 }));
    assert_eq!(r.unwrap_err().frames(), 65, "the receipt carries the frames");
}

#[test]
fn the_buffer_is_whole_frames_rounded_up_and_no_more() {
    // DISCRIMINATES: rounding (truncating or adding a spare frame goes red).
    assert_eq!(admit(1, FRAME, 0, RUN), Ok(1));
    assert_eq!(admit(FRAME, FRAME, 0, RUN), Ok(1));
    assert_eq!(admit(FRAME + 1, FRAME, 0, RUN), Ok(2));
    // A 64 KiB granule: the same bytes, fewer and larger frames.
    assert_eq!(admit(FRAME * 17, 64 * 1024, 0, RUN), Ok(2));
}

#[test]
fn an_empty_file_is_not_an_image() {
    assert_eq!(admit(0, FRAME, 64, RUN), Err(Refusal::Empty));
}

#[test]
fn no_budget_means_no_budget_but_the_allocator_still_bounds_the_run() {
    assert_eq!(admit(RUN as u64 * FRAME, FRAME, 0, RUN), Ok(RUN));
    assert_eq!(
        admit(RUN as u64 * FRAME + 1, FRAME, 0, RUN),
        Err(Refusal::TooLarge { frames: RUN + 1, max_run: RUN }),
    );
    // Past 32 bits of frames is refused as well, not wrapped into a small one.
    assert_eq!(
        admit(u64::MAX, FRAME, 0, RUN),
        Err(Refusal::TooLarge { frames: u32::MAX, max_run: RUN }),
    );
}

#[test]
fn the_longest_run_is_checked_before_the_budget() {
    // A budget larger than the allocator can form must not admit the image.
    assert_eq!(
        admit((RUN as u64 + 1) * FRAME, FRAME, RUN + 100, RUN),
        Err(Refusal::TooLarge { frames: RUN + 1, max_run: RUN }),
    );
}

/// The real users: the std images with TLS (about 0.85 to 1.0 MiB at 4 KiB
/// pages, measured, `PKGD.ELF`/`RPCQUIC.ELF`) fit their rows' budgets and the
/// generic autorun row's on a board that has them; twice that does not fit
/// the installer's row. This is what replaced the 2 MiB `.bss` buffer.
#[test]
fn a_std_image_is_staged_within_its_row_and_twice_that_is_not() {
    if !azos_topology::builder::PKGD_ROW {
        return;
    }
    let image = 1024 * 1024 + 64 * 1024; // measured peak 0.99 MiB, with slack
    let row = azos_topology::builder::PKGD_MEM_PAGES;
    let frames = admit(image, FRAME, row, RUN).expect("the installer's image fits its own row");
    assert_eq!(frames as u64, image / FRAME);
    assert!(admit(image, FRAME, azos_limits::AUTORUN_MEM_PAGES as u32, RUN).is_ok(), "and the generic autorun row's");
    assert!(matches!(
        admit(2 * row as u64 * FRAME, FRAME, row, RUN),
        Err(Refusal::OverBudget { .. })
    ));
}

const LOADER: &str = include_str!("../../../../kernel/src/tasks/loader.rs");

#[test]
fn the_loader_has_no_static_buffer_and_no_fixed_size() {
    // DISCRIMINATES: bringing back a fixed buffer (or its Kconfig size).
    assert!(!LOADER.contains("static mut AUTORUN_BUF"));
    assert!(!LOADER.contains("AUTORUN_ELF_MAX"));
    assert!(!LOADER.contains("LOADER_BUSY"), "nothing is shared, so nothing is locked");
    let kconfig = include_str!("../../../../config/limits/Kconfig.limits");
    assert!(!kconfig.contains("AUTORUN_ELF_MAX_KB"));
}

#[test]
fn the_loader_sizes_before_it_reads_and_frees_before_the_switch() {
    // DISCRIMINATES: the order. The size is checked before a frame is taken;
    // the staging frames are given back after the image is copied into its own
    // address space and BEFORE the commit switches to it, so the program never
    // runs beside a second copy of itself.
    let at = |needle: &str| LOADER.find(needle).unwrap_or_else(|| panic!("{needle} not in the loader"));
    assert!(at("vfs_stat(") < at("admit(size"));
    assert!(at("admit(size") < at("Staging::take(frames)"));
    assert!(at("Staging::take(frames)") < at("vfs_read("));
    assert!(at("vfs_read(") < at("image_digest("));
    assert!(at("image_digest(") < at("exec_prepare_mem("));
    assert!(at("exec_prepare_mem(") < at("drop(staging)"));
    assert!(at("drop(staging)") < at("exec_commit("));
    assert_eq!(LOADER.matches("exec_commit(").count(), 1);
}

#[test]
fn a_refusal_is_recorded_durably() {
    // The receipt: the record the autorun refusals use, with its own action.
    let at = LOADER.find("fn refuse_image_room").expect("the refusal path");
    let body = &LOADER[at..];
    assert!(body.contains("log_safety_violation_durable"));
    assert!(body.contains("REFUSED_ACTION_IMAGE_ROOM"));
}

#[test]
fn the_staging_run_is_charged_to_no_domain() {
    // DISCRIMINATES: putting the charge back. The loading kernel task's Domain
    // has no limit until `exec_commit`, so the charge never refused, and it
    // raised the Domain's high-water mark and `mm_peak_global` with frames that
    // are gone before the program runs: a peak measured on the installer's row
    // would include the loader's own copy of its image.
    assert!(!LOADER.contains("mm_charge"));
    assert!(!LOADER.contains("mm_discharge"));
    // The one bound is the row's: `staging_limit` feeds `admit`, and the
    // allocator's own refusal is the other way to be turned down.
    assert!(LOADER.contains("staging_limit(path_slice)"));
    assert!(LOADER.contains("row_mem(name"));
    assert!(LOADER.contains("Refusal::NoFrames"));
    assert!(!LOADER.contains("current_user_pages().1"), "the receipt's limit is the one admit() used");
}
