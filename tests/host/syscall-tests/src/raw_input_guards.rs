// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for handlers whose reject paths run entirely inside real,
// pulled-in code (`copy_from_user`, size/length ceilings) before reaching a
// hardware call this crate cannot exercise. Each group below states exactly
// how far into the handler a test can go before the next call is a
// `todo!()` stub in one of `shims/*` — see the crate report for the full
// per-handler trace. None of the "not reachable beyond here" claims below
// are inferred: each was confirmed by grepping the relevant shim for
// `todo!()` and reading the call order in `handlers.rs`.

use super::harness::serial;
use crate::ipc_handlers::*;

use azos_abi::error::Errno;

// ── SYS_RING_SETUP ──────────────────────────────────────────────────
//
// **Not reachable beyond its null-pointer guard, for a reason worth
// recording explicitly.** `sys_ioring_create_typed` (`crates/core/syscall/src/ipc_handlers.rs`)
// calls `azos_ipc::io_ring::io_ring_create_cap`, whose first action
// (`crates/core/ipc/src/io_ring.rs`'s `io_ring_create`, pulled in real) is an
// UNCONDITIONAL `azos_sched::current_user_pt()` call. From inside
// `shims/ipc`, that name resolves to `shims/ipc_sched`'s OWN
// `current_user_pt`, which is `todo!()` there (its module doc: reachable
// only from a `#[cfg(not(test))]` arm of `channel.rs` that never runs under
// `cargo test` -- but `io_ring.rs`'s call is NOT behind any such cfg, so
// this path panics unconditionally). This is a real gap in the shim, not in
// `handlers.rs`, and is flagged separately rather than silently worked
// around with a fake page-table setup that would not exist on the real
// path either.
#[test]
fn ioring_create_refuses_a_null_pointer() {
    let _g = serial();
    assert_eq!(sys_ioring_create_typed(0), Errno::EINVAL.to_syscall_ret());
}

/// Defects the 2026-09-19 user-pointer audit found, each pinned so it cannot
/// come back. These are source-text assertions where the behaviour needs two
/// harts (which this host harness cannot make) and value assertions where it
/// does not.
#[cfg(test)]
mod audit_2026_09_19 {
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");

    /// Comments stripped: a comment that quotes a pattern is not code.
    fn code(src: &str) -> String {
        src.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n")
    }

    /// **A disk call's bounce buffer must stay its own.**
    ///
    /// They were `static mut` taken by `addr_of_mut!`, with a SAFETY comment
    /// claiming syscalls run with preemption disabled — nothing does that — and
    /// `blk::read` releases `BLK_LOCK` before the handler copies out. Two harts
    /// raced: one filled the buffer, the other overwrote it, the first copied
    /// the other's sectors to its caller. On the write side the wrong bytes
    /// reached the sector, and the sectors under the partition table are the
    /// flight recorder and the boot image.
    ///
    /// Two harts are what it takes to observe, and this harness has one, so the
    /// assertion is on the shape: no shared buffer in the syscall surface at
    /// all, unsynchronised or behind a lock held across the device wait (owner
    /// rule F1: that lock was held across the device call, and the exclusion only existed
    /// because the buffer was shared). Each block entry takes its own
    /// (`bounce`). That is the class, not the instance.
    #[test]
    fn no_syscall_handler_keeps_an_unsynchronised_static_mut_buffer() {
        let c = code(HANDLERS);
        let offenders: Vec<&str> = c
            .lines()
            .filter(|l| l.contains("static mut ") && (l.contains("[u8;") || l.contains("BUF") || l.contains("BOUNCE")))
            .collect();
        assert!(
            offenders.is_empty(),
            "a shared mutable buffer with no lock is back in the syscall surface; \
             a block entry takes its own (`bounce`), `CAM_BUF` is behind a lock: {offenders:?}"
        );
        let shared: Vec<&str> = c
            .lines()
            .filter(|l| l.contains("static DISK_") && l.contains("BUF"))
            .collect();
        assert!(
            shared.is_empty(),
            "a shared disk bounce buffer is back (held across the device wait, rule F1): {shared:?}"
        );
        // The block entry is the one path that moves sectors now: it takes its
        // own bounce buffer.
        let blk = code(include_str!("../../../../crates/core/syscall/src/block_host.rs"));
        let at = blk.find("pub fn block_io(").expect("block_io is gone");
        let body = &blk[at..];
        let end = body.find("\n}\n").unwrap_or(body.len());
        assert!(
            body[..end].contains("bounce(len)"),
            "block_io does not take its own bounce buffer"
        );
    }

    /// **Clamp in the wide type, then narrow.** `(x as u16).min(LIMIT)` cannot
    /// clamp what the cast already wrapped: `0x1_0000` arrived as 0 and was
    /// reported as success — a 0-byte reply capacity.
    #[test]
    fn register_arguments_are_clamped_before_they_are_narrowed() {
        let c = code(HANDLERS);
        for pat in ["(out_cap as u16)"] {
            assert!(
                !c.contains(pat),
                "{pat} narrows before clamping: a value past u16 wraps to a small \
                 one and the .min() below can no longer see it"
            );
        }
        // The `out_cap` clamp lived in `sys_driver_request`, retired with 526
        // in wave 11 (OVSwrap review F3); the negative check above still keeps
        // the narrow-first shape out.
    }
}
