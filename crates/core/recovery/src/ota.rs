// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console's `ota` command and the `ota-recv` task (Kconfig `BOOT_SLOTS`):
//! the A/B slots' status, verification, rollback and the image receive.

use super::*;

/// OTA firmware update — A/B slot management over TCP.
///
/// Subcommands:
///   ota recv <port>    — receive firmware image over TCP, write to inactive slot
///   ota status         — show current slot, boot count, versions
///   ota verify         — CRC-32 check both firmware slots
///   ota rollback       — switch active slot to last known good
pub(super) fn cmd_ota(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: ota <recv|status|verify|rollback>");
        azos_drv_sys::kconsoleln!("  recv <port>  — receive firmware over TCP");
        azos_drv_sys::kconsoleln!("  status       — show OTA slot info");
        azos_drv_sys::kconsoleln!("  verify       — CRC-32 check firmware slots");
        azos_drv_sys::kconsoleln!("  rollback     — revert to last good slot");
        return;
    }

    if args[1] == b"status" {
        cmd_ota_status();
    } else if args[1] == b"verify" {
        cmd_ota_verify();
    } else if args[1] == b"rollback" {
        cmd_ota_rollback();
    } else if args[1] == b"recv" {
        if argc < 3 {
            azos_drv_sys::kconsoleln!("Usage: ota recv <port>");
            return;
        }
        let port = parse_u16(args[2]);
        if port == 0 {
            azos_drv_sys::kconsoleln!("[OTA] Invalid port");
            return;
        }
        cmd_ota_recv(port);
    } else {
        azos_drv_sys::kconsoleln!("[OTA] Unknown subcommand. Use: recv, status, verify, rollback");
    }
}

fn cmd_ota_status() {
    let meta = azos_ota::ota_read_boot_meta();
    let slot_char = azos_ota::ota_slot_char;
    azos_drv_sys::kconsoleln!("[OTA] Active slot:  {}", slot_char(meta.active_slot));
    azos_drv_sys::kconsoleln!("[OTA] Boot count:   {}/{}", meta.boot_count,
        azos_ota::CFG_OTA_MAX_BOOT_ATTEMPTS.load(core::sync::atomic::Ordering::Relaxed));
    azos_drv_sys::kconsoleln!("[OTA] Last good:    {}", slot_char(meta.last_good));
    azos_drv_sys::kconsoleln!("[OTA] Slot A: fw={} size={} crc={:#010x}",
        meta.fw_version_a, meta.image_size_a, meta.image_crc_a);
    azos_drv_sys::kconsoleln!("[OTA] Slot B: fw={} size={} crc={:#010x}",
        meta.fw_version_b, meta.image_size_b, meta.image_crc_b);
    azos_drv_sys::kconsoleln!("[OTA] Platform:     {}", match azos_ota::ota_current_platform() {
        azos_ota::OTA_PLATFORM_QEMU => "QEMU",
        azos_ota::OTA_PLATFORM_VF2  => "VisionFive 2",
        azos_ota::OTA_PLATFORM_K1   => "SpacemiT K1",
        _ => "unknown",
    });
}

fn cmd_ota_verify() {
    for (label, slot) in [
        ("A", azos_ota::SLOT_A),
        ("B", azos_ota::SLOT_B),
    ] {
        let (ver, size, crc) = azos_ota::ota_slot_info(slot);
        if size == 0 {
            azos_drv_sys::kconsoleln!("[OTA] Slot {} — empty (no firmware)", label);
            continue;
        }
        if azos_ota::ota_verify_slot(slot) {
            azos_drv_sys::kconsoleln!(
                "[OTA] Slot {} — OK  (fw={}, size={}, crc={:#010x})",
                label, ver, size, crc);
        } else {
            azos_drv_sys::kconsoleln!(
                "[OTA] Slot {} — CRC FAIL or missing file (expected size={}, crc={:#010x})",
                label, size, crc);
        }
    }
}

fn cmd_ota_rollback() {
    if !authority::check_power_row(authority_policy::CMD_OTA_ROLLBACK) {
        return;
    }
    match families::ota_rollback() {
        families::Rollback::Already(slot) => {
            azos_drv_sys::kconsoleln!("[OTA] Already on last good slot ({})",
                azos_ota::ota_slot_char(slot));
        }
        families::Rollback::BadSlot(slot, bad) => {
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: slot {} failed secure-boot verification \
                 (bad_slots={:#04x}). Install a signed image instead.",
                azos_ota::ota_slot_char(slot), bad);
        }
        families::Rollback::Done(old, new) => {
            azos_drv_sys::kconsoleln!("[OTA] Rolled back: {} → {} (reboot to apply)",
                azos_ota::ota_slot_char(old), azos_ota::ota_slot_char(new));
        }
    }
}

/// Receive firmware over TCP, write to inactive slot, validate CRC-32.
/// OT02.A — promote a staged `KERN_X.TMP` into the live `KERN_X.BIN`.
///
/// FAT32 has no atomic rename primitive in our driver, so we emulate it
/// by streaming the TMP contents into a freshly-opened BIN and then
/// unlinking the TMP. If a power-loss happens during the stream, the
/// next boot finds:
///   - TMP still present (will be overwritten by the next OTA attempt)
///   - BIN truncated or absent
///   - BOOTMETA NOT updated yet → kernel still boots from the other slot
/// So a torn promotion is recoverable without operator action.
///
/// U11-3 (partially closed): a FAILED promotion here — the
/// return-`false` paths below — no longer causes the CALLER
/// (`cmd_ota_recv`) to also delete `tmp_path`. Before this, a copy failure
/// (typically the volume too full to hold the live BIN, the staged TMP,
/// AND this copy simultaneously) emptied the rollback slot (`bin_path`,
/// via the `O_TRUNC` open below) AND destroyed the only
/// verified copy of the image in the same operation. The verified bytes in
/// `tmp_path` now survive a failed promotion for a retry. What this
/// function still cannot do without a real FAT32 rename primitive: avoid
/// `bin_path` going through a truncate-then-write window at all — that
/// window, and the fix for it, belong to `crates/fs/src/fat32.rs`.
fn ota_promote_tmp_to_bin(tmp_path: &[u8], bin_path: &[u8]) -> bool {
    // Buffer reused for read+write copy. The slot binary is bounded by
    // OTA_MAX_IMAGE_SIZE so we know the loop terminates.
    static mut PROMOTE_BUF: [u8; 4096] = [0u8; 4096];
    let buf = unsafe { &mut *(&raw mut PROMOTE_BUF) };

    // Open source (TMP) for read.
    let mut src_fdt = azos_fs::ScratchFds::new();
    let src_fd = azos_fs::vfs_open(&mut src_fdt, tmp_path, azos_fs::O_RDONLY);
    if src_fd < 0 {
        return false;
    }

    // Drop any pre-existing BIN, then create fresh.
    let _ = azos_fs::fat32_unlink_path(bin_path);
    let mut dst_fdt = azos_fs::ScratchFds::new();
    let dst_fd = azos_fs::vfs_open(&mut dst_fdt, bin_path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
    if dst_fd < 0 {
        azos_fs::vfs_close(&mut src_fdt, src_fd);
        return false;
    }

    // Copy in chunks until EOF.
    loop {
        let got = azos_fs::vfs_read(&mut src_fdt, src_fd,
                                          buf.as_mut_ptr(), buf.len());
        if got <= 0 { break; }
        let wrote = azos_fs::vfs_write(&mut dst_fdt, dst_fd,
                                            buf.as_ptr(), got as usize);
        if wrote != got {
            azos_fs::vfs_close(&mut src_fdt, src_fd);
            azos_fs::vfs_close(&mut dst_fdt, dst_fd);
            return false;
        }
    }
    azos_fs::vfs_close(&mut src_fdt, src_fd);
    azos_fs::vfs_close(&mut dst_fdt, dst_fd);

    // Flush dirty FAT32 cache so .BIN is durable before we drop .TMP.
    let _ = azos_fs::fat32_sync();

    // Best-effort unlink of the staging file. If it fails the next OTA
    // attempt will TRUNC it, so it's not a hard error.
    let _ = azos_fs::fat32_unlink_path(tmp_path);

    true
}

/// U11-2 — payload phase idle timeout. A peer whose TCP connection is
/// live but whose application sends nothing (valid header, then silence)
/// must not pin this listener indefinitely: the stack's own keepalive only
/// reaps a genuinely DEAD peer (`crates/net/stack/src/tcp.rs`, 30 s x 3 probes),
/// and nothing else bounds an application-silent one.
/// TIMER_FREQ-derived, never a raw tick literal
/// a hard-coded 10 MHz assumption is wrong on VF2 (4 MHz), K1 (24 MHz) and
/// aarch64 (1 GHz).
const OTA_PAYLOAD_IDLE_TIMEOUT_S: u64 = 30;

fn cmd_ota_recv(port: u16) {
    let platform = azos_ota::ota_current_platform();

    // Create TCP listener
    let listen_fd = azos_net::socket_create(
        azos_net::AF_INET, azos_net::SOCK_STREAM, 0);
    if listen_fd < 0 {
        azos_drv_sys::kconsoleln!("[OTA] socket_create failed");
        return;
    }

    let mut addr = azos_net::SockAddr::new();
    addr.family = azos_net::AF_INET as u16;
    addr.port   = port;

    if azos_net::socket_bind(listen_fd, &addr) < 0 ||
       azos_net::socket_listen_bound(listen_fd) < 0 {
        azos_drv_sys::kconsoleln!("[OTA] bind/listen failed");
        azos_net::socket_close(listen_fd);
        return;
    }

    // Print AFTER bind+listen so the test script's pattern only fires once
    // the socket is genuinely ready to accept connections.
    azos_drv_sys::kconsoleln!("[OTA] Listening on port {}", port);

    static mut OTA_HDR_BUF: [u8; 24] = [0u8; 24];
    let hdr_buf = unsafe { &mut *(&raw mut OTA_HDR_BUF) };

    // U11-2 — outer session loop. Before this, EVERY payload-phase failure
    // (incomplete transfer, CRC mismatch, signature refusal, promote
    // failure) `return`ed from this function — ending the task for good,
    // since `ota_recv_task_entry` calls `cmd_ota_recv` exactly once. One
    // stalled or rejected transfer meant no later OTA could be received
    // without a reboot. Every failure path below now falls through to
    // `continue 'session`, which goes back to `socket_accept` on the SAME
    // listener instead. Only listener setup failures above (already
    // returned) are fatal — nothing can proceed without them.
    'session: loop {
    let target_slot = azos_ota::ota_inactive_slot();
    let final_path  = azos_ota::ota_slot_path(target_slot);
    // OT02.A — write to a staging .TMP file first; promote to .BIN only
    // after the full payload validates against the CRC32 in the header.
    let target_path = if target_slot == azos_ota::SLOT_A {
        azos_ota::OTA_SLOT_A_TMP_PATH
    } else {
        azos_ota::OTA_SLOT_B_TMP_PATH
    };
    azos_drv_sys::kconsoleln!("[OTA] Awaiting connection — target slot {}",
        if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' });

    // Accept + header loop: retry on probe connections that close before sending
    // a valid header (e.g. health-check probes, accidental connections).
    let (client_fd, header) = 'accept_loop: loop {
        // Wait for next TCP connection. K-C27: sleep between accept polls —
        // this task runs at NET_POLL_PRIORITY (12) pinned to hart 2, and the
        // old bare `task_yield()` made an idle listener starve everything
        // below priority 12 on that hart for as long as no client connected.
        // +10 ms of accept latency is invisible to an OTA push; the transfer
        // loop below keeps its tight polling, which is bounded by the
        // connection's lifetime.
        let cfd = loop {
            azos_net::net_poll();
            let r = azos_net::socket_accept(listen_fd);
            if r >= 0 { break r; }
            listen_poll_sleep();
        };
        azos_drv_sys::kconsoleln!("[OTA] Client connected — receiving header...");

        // Receive the fixed-size OTA header.
        let mut hdr_got = 0usize;
        hdr_buf.fill(0);
        let header_ok = 'recv_hdr: loop {
            azos_net::net_poll();
            let n = azos_net::socket_recv(cfd, &mut hdr_buf[hdr_got..
                azos_ota::OTA_HEADER_SIZE]);
            if n > 0 {
                hdr_got += n as usize;
                if hdr_got >= azos_ota::OTA_HEADER_SIZE { break 'recv_hdr true; }
            } else if n < 0 {
                azos_drv_sys::kconsoleln!("[OTA] Connection lost during header — retry");
                azos_net::socket_close(cfd);
                break 'recv_hdr false;
            }
            // K-C27: a client that connects and stalls before sending the
            // 24-byte header must not pin this hart; 10 ms polls are
            // invisible against the sender's own pacing.
            listen_poll_sleep();
        };
        if !header_ok { continue 'accept_loop; }

        // Parse header.
        let hdr = match azos_ota::ota_parse_header(hdr_buf) {
            Some(h) => h,
            None => {
                azos_drv_sys::kconsoleln!("[OTA] Invalid header (bad magic or version)");
                azos_net::socket_close(cfd);
                continue 'accept_loop;
            }
        };

        // Validate header (platform, size bounds).
        if !azos_ota::ota_validate_header(&hdr, platform,
                                              azos_ota::OTA_MAX_IMAGE_SIZE) {
            azos_drv_sys::kconsoleln!("[OTA] Header validation failed (platform={}, size={})",
                hdr.platform_id, hdr.image_size);
            azos_net::socket_close(cfd);
            continue 'accept_loop;
        }

        // OT03 anti-rollback — ADVISORY ONLY. Read the comment before
        // trusting this gate to do what its name says.
        //
        // Both of its inputs are attacker-controlled:
        //
        //  * `hdr.fw_version` is byte 16 of the 24-byte wire header. That
        //    header is NOT signed and NOT covered by any signature we hold —
        //    `FirmwareSignature` (crates/core/crypto/src/ed25519.rs) is magic /
        //    algorithm / pubkey / signature / payload_size, with no version
        //    field, and the signature itself is computed over the raw image
        //    bytes only. So the sender picks this number freely: replaying a
        //    genuinely-signed OLD image with `fw_version = 0xFFFFFFFF`
        //    sails through here.
        //  * `min_fw_version` comes from BOOTMETA, which lives on the FAT
        //    volume of a removable card. An attacker with a card reader
        //    rewrites the floor to 0; if both
        //    dual-file records are destroyed, `ota_read_boot_meta()`'s
        //    unauthenticated legacy fallback hands back 0 anyway.
        //
        // It is kept because it costs nothing and rejects the honest-mistake
        // case (an operator pushing a stale build) at the cheapest possible
        // point — before a multi-MiB transfer. It is NOT the security gate.
        // The gate that actually decides whether this image goes live is the
        // Ed25519 verification of the staged payload further down; a version
        // floor cannot be enforced against a signature that does not cover a
        // version. See the report / OWNER DECISION note on binding the
        // version into a signed manifest.
        let current_meta = azos_ota::ota_read_boot_meta();
        if !azos_ota::ota_check_rollback_pure(hdr.fw_version, current_meta.min_fw_version) {
            azos_drv_sys::kconsoleln!(
                "[OTA] Anti-rollback (advisory): incoming fw={} < floor={} — rejected",
                hdr.fw_version, current_meta.min_fw_version);
            azos_net::socket_close(cfd);
            continue 'accept_loop;
        }

        break 'accept_loop (cfd, hdr);
    };

    // Do NOT close listen_fd here — some TCP stacks tear down accepted
    // connections when the listening socket closes. Keep it alive until after
    // the full payload transfer completes.
    azos_drv_sys::kconsoleln!("[OTA] Header OK — fw={} size={} crc={:#010x}",
        header.fw_version, header.image_size, header.image_crc32);

    // Open target file
    let mut fd_table = azos_fs::ScratchFds::new();
    let file_fd = azos_fs::vfs_open(&mut fd_table, target_path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
    if file_fd < 0 {
        azos_drv_sys::kconsoleln!("[OTA] Cannot create target file");
        azos_net::socket_close(client_fd);
        continue 'session;
    }

    // Stream payload from TCP to FAT32 as raw binary (no header on disk).
    // The .BIN file is directly bootable by U-Boot.
    static mut OTA_CHUNK: [u8; 4096] = [0u8; 4096];
    let chunk = unsafe { &mut *(&raw mut OTA_CHUNK) };
    let mut crc_state = azos_ota::Crc32State::new();
    let mut remaining = header.image_size as usize;
    let mut total_written = 0usize;

    azos_drv_sys::kconsoleln!("[OTA] Receiving {} bytes...", header.image_size);

    let mut idle_iters: u32 = 0;
    // U11-2 — idle deadline, reset on every byte received. See
    // `OTA_PAYLOAD_IDLE_TIMEOUT_S`. `now()`/`TIMER_FREQ`, never a raw tick
    // literal (TIMER_FREQ is per-board).
    let mut idle_deadline = azos_drv_sys::timebase::now()
        + azos_drv_sys::timebase::TIMER_FREQ * OTA_PAYLOAD_IDLE_TIMEOUT_S;
    while remaining > 0 {
        azos_net::net_poll();
        let max_recv = remaining.min(chunk.len());
        let n = azos_net::socket_recv(client_fd, &mut chunk[..max_recv]);
        if n > 0 {
            // Clamped to what we ASKED for, not trusted from the return value.
            //
            // `socket_recv` was handed `chunk[..max_recv]` and cannot honestly
            // exceed it, so this is an internal invariant rather than an
            // attacker-controlled one. It is enforced anyway because the
            // failure mode is not a wrong byte count: `remaining -= got` on an
            // over-report underflows, and `overflow-checks = true` with
            // `panic = "abort"` makes that a **board reset** mid-OTA. Clamping
            // instead lets the CRC at the end reject the transfer, which is a
            // detected error rather than a robot that stops.
            let got = (n as usize).min(max_recv);
            crc_state.update(&chunk[..got]);
            azos_fs::vfs_write(&mut fd_table, file_fd, chunk.as_ptr(), got);
            remaining -= got;
            total_written += got;
            idle_iters = 0;
            idle_deadline = azos_drv_sys::timebase::now()
                + azos_drv_sys::timebase::TIMER_FREQ * OTA_PAYLOAD_IDLE_TIMEOUT_S;
            // Don't yield while we have data to drain — every yield gives
            // the scheduler an opportunity to switch us out and lets the
            // peer's window fill again before we resume.
            continue;
        } else if n < 0 {
            azos_drv_sys::kconsoleln!("[OTA] Connection lost ({}/{} bytes received)",
                total_written, header.image_size);
            break;
        }
        // U11-2 — a TCP-live, application-silent peer (valid header, then
        // nothing) must not pin this listener forever: the stack's
        // keepalive only reaps a genuinely dead one. Checked in the idle
        // branch only — a peer that is actually sending data never reaches
        // this check, so it costs nothing on the common path.
        if azos_drv_sys::timebase::now() >= idle_deadline {
            azos_drv_sys::kconsoleln!(
                "[OTA] Payload idle for {}s ({}/{} bytes received) — closing",
                OTA_PAYLOAD_IDLE_TIMEOUT_S, total_written, header.image_size);
            break;
        }
        // No data: poll a few more times before yielding, so a packet that
        // arrives just-after-our-recv doesn't sit one full task quantum.
        idle_iters = idle_iters.saturating_add(1);
        if idle_iters >= 8 {
            idle_iters = 0;
            azos_sched::task_yield();
        }
    }

    azos_fs::vfs_close(&mut fd_table, file_fd);
    azos_net::socket_close(client_fd);
    // listen_fd stays open — U11-2, this task keeps accepting connections
    // for the life of the 'session loop, not just one transfer.

    if remaining > 0 {
        azos_drv_sys::kconsoleln!("[OTA] INCOMPLETE — deleting partial .TMP");
        let _ = azos_fs::fat32_unlink_path(target_path);
        continue 'session;
    }

    // Verify CRC-32 BEFORE promoting .TMP → .BIN
    let computed_crc = crc_state.finalize();
    if computed_crc != header.image_crc32 {
        azos_drv_sys::kconsoleln!("[OTA] CRC MISMATCH: computed={:#010x} expected={:#010x}",
            computed_crc, header.image_crc32);
        azos_drv_sys::kconsoleln!("[OTA] Deleting corrupt .TMP");
        let _ = azos_fs::fat32_unlink_path(target_path);
        continue 'session;
    }

    // ── F18 — authenticate the image BEFORE it is allowed anywhere near a
    //          live slot. This is the gate; CRC-32 above is not one.
    //
    // Everything checked up to this point (magic, version, platform, size,
    // flags, the version floor, and the CRC just above) is computed by the
    // *sender*. CRC-32 is an integrity check against a noisy link, not an
    // authenticator: anyone who can open a TCP connection to this port can
    // produce a payload whose CRC matches, because they choose both. Without
    // the check below, reaching this line meant "an arbitrary remote peer's
    // kernel image is now the one this board boots" — unauthenticated remote
    // code execution on a robot.
    //
    // Two properties matter about WHERE this check sits:
    //
    //  1. BEFORE `ota_promote_tmp_to_bin`. Verifying after promotion would
    //     be far too late: promotion is what destroys the rollback target.
    //     `target_slot` is the inactive slot, which is normally `last_good`
    //     — the exact image `ota_boot_validate_pure()`'s boot-loop rollback
    //     and `ota rollback` fall back to. If a refused update had already
    //     overwritten it, merely *reaching* this port would destroy the
    //     device's fallback without ever touching `active_slot`, turning the
    //     next failure of the active slot into an unrecoverable brick. By
    //     verifying `KERN_{A,B}.TMP`, a refused image leaves
    //     `KERN_{A,B}.BIN` byte-identical to what it was.
    //  2. BEFORE `meta.active_slot = target_slot`. On a
    //     `secure-boot-enforced` build the boot gate in `kernel/src/boot/ota.rs`
    //     halts at `loop { wfi() }` for anything that is not
    //     `BootTrust::Verified`. Flipping the boot slot to an image that
    //     gate will refuse is not a security failure, it is a brick — and it
    //     would have happened on a perfectly legitimate update, because
    //     nothing in this tree writes the `.SIG` sidecar yet. Refusing here
    //     converts that brick into a recoverable "update rejected".
    //
    // Policy deliberately mirrors the boot gate's, and for the same reason
    // it uses `secure_boot_enforced_at_compile_time()` rather than the
    // runtime-relaxable `secure_boot_require_signature()`: the decision to
    // *install* must agree with the decision to *boot*, or an enforced build
    // can be talked into staging an image it will then refuse to run. Kconfig
    // OTA_SIG_MANDATORY may make the install stricter than the boot, never
    // looser: refusing to stage an image is never a brick.
    // Flush before verifying. The payload was written through `vfs_*` on the
    // `/fat` mount point; the verifier reads the same file through
    // `fat32_open()` on the volume root (`/KERN_X.TMP` — see
    // `SECURE_BOOT_TMP_PATH_*` for why the prefixes differ). Both go through
    // the one FAT32 driver, so this is belt-and-braces rather than strictly
    // required — but "the bytes I verify are the bytes on disk" is not a
    // property worth inferring from cache-layer reasoning on the path that
    // decides whether unauthenticated code gets to run.
    let _ = azos_fs::fat32_sync();

    // The `.SIG` now signs a MANIFEST
    // `{fw_version, payload_size, sha256(image)}` (see
    // `crates/core/crypto/src/ed25519.rs` module docs), so `secure_boot_*`
    // returns the AUTHENTICATED `fw_version` alongside the trust verdict
    // (0 when not `Verified`). `header.fw_version` from here on is
    // DISPLAY ONLY — the anti-rollback decision uses `auth_fw_version`.
    let (trust, trust_reason, auth_fw_version) =
        azos_ota::secure_boot_verify_staged_detailed(target_slot);
    let enforced = azos_ota::secure_boot_enforced_at_compile_time();
    // Kconfig OTA_SIG_MANDATORY: an unsigned image is refused here even where
    // the boot gate would run it (the build validation keeps it on whenever
    // `secure-boot-enforced` is).
    let required = enforced || azos_limits::OTA_SIG_MANDATORY;

    if trust != azos_ota::BootTrust::Verified {
        // `Failed` means a `.SIG` IS present and does not verify (wrong key,
        // wrong contents, or a size/hash mismatch). Refuse that in BOTH
        // build flavours: a signature that is present and wrong is
        // evidence, not an absence, and promoting over the rollback target
        // on that evidence is never the right trade. Note this cannot fire
        // on a dev build — with the all-zero `SECURE_BOOT_PUBKEY` the
        // verifier short-circuits to `Unverified`/`NoTrustedKey` before
        // ever reading a `.SIG`.
        if azos_ota::ota_install_refused_pure(false, trust == azos_ota::BootTrust::Failed, required) {
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: staged image for slot {} is {} ({}) — \
                 {}; live slot left untouched, deleting .TMP",
                if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' },
                trust.as_str(), trust_reason.as_str(),
                if enforced {
                    "secure-boot-enforced is compiled in, refusing to install"
                } else if required {
                    "Kconfig OTA_SIG_MANDATORY refuses an image without a valid signature"
                } else {
                    "a present-but-invalid or unverifiable signature is never installed"
                });
            // Name the sidecar by slot letter rather than printing the path
            // slice: `secure_boot_sig_path` returns `&[u8]`, which `{:?}`
            // renders as a list of decimal byte values — useless in a log.
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: sign the image with tools/sign/sign_ota.py --fw-version <N> \
                 and place the sidecar at /KERN_{}.SIG (FAT32 volume root) before retrying",
                if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' });
            let _ = azos_fs::fat32_unlink_path(target_path);
            continue 'session;
        }

        // Not required, and no usable signature was found at all. Install —
        // this is the dev/QEMU path and the pre-key-rollout path — but say so
        // unmistakably. "CRC OK" must never be mistaken for "authenticated".
        azos_drv_sys::kconsoleln!(
            "[OTA] ##### WARNING: INSTALLING AN UNAUTHENTICATED IMAGE #####");
        azos_drv_sys::kconsoleln!(
            "[OTA] ##### trust={} reason={}",
            trust.as_str(), trust_reason.as_str());
        azos_drv_sys::kconsoleln!(
            "[OTA] ##### This image's origin is UNPROVEN — CRC-32 is computed \
             by the sender and authenticates nothing. Anyone who can reach \
             this TCP port can install code that runs as this robot's kernel.");
        azos_drv_sys::kconsoleln!(
            "[OTA] ##### Do NOT ship a build in this state: install a prod key \
             (tools/sign/gen_prod_key.py) and build --features secure-boot-enforced.");
    } else {
        // The AUTHORITATIVE anti-rollback check. The one in the
        // accept loop above is advisory (it reads the unsigned wire
        // header); this is the real gate, run against the version that was
        // actually bound into the verified signature. A validly-signed OLD
        // image cannot pass this by claiming a higher `fw_version` on the
        // wire — that claim was never part of what got checked here.
        let current_meta = azos_ota::ota_read_boot_meta();
        if !azos_ota::ota_check_rollback_pure(auth_fw_version, current_meta.min_fw_version) {
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: staged image for slot {} carries a VALID signature for \
                 fw={}, below the anti-rollback floor of {} — live slot left untouched, \
                 deleting .TMP",
                if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' },
                auth_fw_version, current_meta.min_fw_version);
            let _ = azos_fs::fat32_unlink_path(target_path);
            continue 'session;
        }
        azos_drv_sys::kconsoleln!(
            "[OTA] Signature VERIFIED for staged slot {} image (fw={})",
            if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' }, auth_fw_version);
    }

    // OT02.A — promote .TMP to .BIN. FAT32 has no atomic rename primitive
    // (a driver gap — `crates/fs/src/fat32.rs`, not owned here), so this
    // still emulates it with unlink-then-copy. U11-3, PARTIALLY closed from
    // this side: on a copy FAILURE we no longer also delete `.TMP` (below) —
    // the already-verified staged bytes survive for a retry. What remains
    // open, and needs the fs owner: `fat32_open(..., O_TRUNC)` itself frees
    // the target's cluster chain before the first byte of the copy is
    // written, so `.BIN` can still end up empty if the copy fails
    // partway — closing that needs a real rename (or write-then-swap)
    // primitive in the FAT32 driver, not something achievable from the
    // shell side of this seam.
    let promote_ok = ota_promote_tmp_to_bin(target_path, final_path);
    if !promote_ok {
        azos_drv_sys::kconsoleln!(
            "[OTA] Promote {:?} → final failed — leaving .TMP in place for a retry \
             (was: deleted here too, destroying the only verified copy — U11-3)",
            target_path);
        continue 'session;
    }

    azos_drv_sys::kconsoleln!("[OTA] CRC OK — {} bytes written to slot {}",
        total_written, if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' });

    // Update boot metadata: switch to new slot, record CRC + size for verify.
    //
    // Reaching this line means the image either verified AND passed the
    // authoritative rollback check above, or is an `Unverified` install on
    // a build that has explicitly not opted into enforcement (and screamed
    // about it above). Only now is `active_slot` allowed to move.
    let mut meta = azos_ota::ota_read_boot_meta();
    // This install puts a kernel into the slot and no set: a signed set the slot
    // held belongs to the kernel it replaces, so its marker is withdrawn BEFORE
    // the record moves (a cut in between leaves a slot nobody boots), and the
    // record zeroes the slot's epoch (`ota_kernel_install_pure`) so neither the
    // boot nor the confirmation takes the old set for this kernel's.
    if azos_ota::ota_unstage_slot(target_slot).is_err() {
        azos_drv_sys::kconsoleln!("[OTA] WARNING: the previous system set of slot {} could not be withdrawn; \
            its epoch is cleared and the boot ignores it",
            if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' });
    }
    // `fw_version` is DISPLAY ONLY (sender-reported); the authenticated version
    // is what `ota_mark_boot_good_pure` reads to advance the anti-rollback
    // floor. Only a `Verified` install sets it; an
    // `Unverified`/dev install leaves the slot's as whatever it last verified
    // to (0 if never), so it can NEVER pin the floor no matter what
    // `header.fw_version` claims.
    azos_ota::ota_kernel_install_pure(
        &mut meta, target_slot, header.fw_version,
        (trust == azos_ota::BootTrust::Verified).then_some(auth_fw_version),
        header.image_size, header.image_crc32);
    azos_ota::ota_write_boot_meta(&meta);
    azos_ota::ota_apply_meta(&meta);

    azos_drv_sys::kconsoleln!("[OTA] Active slot → {} (fw={}). Reboot to apply.",
        if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' },
        header.fw_version);

    // U11-2 — go back to accepting the NEXT connection on the same
    // listener, rather than ending this task. A successful install still
    // needs a reboot to actually boot the new slot, but nothing stops the
    // operator from pushing to the OTHER slot (now the inactive one) or
    // retrying before that reboot happens.
    } // 'session: loop
}

// ── OTA auto-recv task entry ──────────────────────────────────────────────────

/// Kernel task entry for CONFIG.INI `ota_auto_recv_port`.
/// Spawned by main.rs when the config key is non-zero; `port_arg` is the port.
pub fn ota_recv_task_entry(port_arg: usize) {
    azos_drv_sys::kconsoleln!("[OTA] Auto-recv task running on port {}", port_arg);
    cmd_ota_recv(port_arg as u16);
}
