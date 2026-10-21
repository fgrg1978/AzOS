// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The recovery console: a small kernel-task console on the UART
//! for the case where ring 3 cannot start (no `SH.ELF`, a corrupt volume, a
//! supervisor that gave up). The user shell is the one shell
//! (`userspace/services/sh`); this is not a second one, so it carries only
//! what diagnosing and repairing a machine without ring 3 needs:
//!
//! * `help`, `mem`, `uptime`, `drvls`, `security`, `estop`: status;
//! * `ls`, `cat` (`cat /proc/decisions` is the decision dump), `crash [log|clear]`,
//!   `why [<id>]` (the chain behind a refusal or denial, from the decision
//!   query: rule, verdict, subject, numbers, provenance, clock): diagnosis;
//! * `ota [status|verify|rollback|recv <port>]`, `config [list|get|set|save|defaults]`,
//!   `ifconfig`, `dhcp` (the network `ota recv` needs): repair;
//! * `swap <image>`: the live update of a supervised server (handover Level 1);
//! * `reboot`, `shutdown`: the two exits, both checked against WRITE on the `power` endpoint.
//!
//! Marked **(c), not recovery**: `wcet` and `bench`, kept only because
//! `tools/bench_e2e.sh` drives them over this console.
//!
//! Besides the console loop the crate holds two things ring 3 and the boot
//! also use: the family bodies behind the typed syscalls (`families`) and the
//! `ota-recv` kernel task entry.

mod authority;
/// Wave 12: the flight/behavior/config/OTA bodies, shared with ring 3.
pub mod families;
/// The minidump of a ring-3 task a fault killed: layout, file ring, report
/// (`kernel/src/trap/crash.rs` writes it, `why crash` reads it).
pub mod crashdump;
// The table is shared with the ring-3 typed calls.
use azos_ipc::authority_policy;

const MAX_LINE:  usize = 256;
const MAX_ARGS:  usize = 8;
const PROMPT:    &str  = "robot> ";

/// K-C27: park a listening/receiving loop for ~10 ms instead of yielding.
/// A bare `task_yield()` in a wait-for-something loop returns immediately
/// whenever nothing outranks the caller, turning the loop into a spinner
/// that starves every lower-priority task on its hart. 100 Hz polling is
/// far above human and protocol patience for the paths that use this
/// (accept, header wait, interactive echo); loops that drain an active
/// bulk transfer deliberately do NOT use it.
fn listen_poll_sleep() {
    let dl = azos_drv_sys::timebase::now()
        + azos_drv_sys::timebase::TIMER_FREQ / 100;
    azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
}


// ── Line reader ───────────────────────────────────────────────────────────────

/// Read one line from UART into `buf`.  Returns byte count (without newline).
/// Supports backspace editing.
fn readline(buf: &mut [u8; MAX_LINE]) -> usize {
    /// UART poll period while the line is idle: 50 Hz. Worst-case 20 ms of
    /// added latency on the first byte of a burst; once `can_read()` is
    /// true the inner loop drains the FIFO without sleeping.
    const UART_POLL_INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 50;
    let mut pos = 0usize;
    loop {
        // Poll until a character is available. K-C27: sleep between polls —
        // the old bare `task_yield()` made an idle shell a priority-13
        // spinner that, wherever placement put it, starved everything below
        // priority 13 on that hart once the RT daemons stopped masking it.
        loop {
            if azos_drv_sys::uart::can_read() { break; }
            // aarch64 with the PL011 RX interrupt wired: park until the IRQ
            // arm wakes this task by TID (`entry::aarch64::handle_irq`), not
            // for 20 ms at a time. Still a `Timer` wait, with a 1 s ceiling:
            // the wake is delivered as a TID wake of a `Timer` sleeper (the
            // `net_msi_wake` shape), and the ceiling bounds any wake that is
            // ever missed. Arm, THEN re-test: a byte that landed between the
            // test above and the arm is caught by the re-test; one that lands
            // after it finds the TID armed. If the wake reaches this task
            // before it has committed to `Blocked`, `block_current` consumes
            // the stamp and returns at once — the loop re-tests either way.
            // Both ISAs since wave 11: riscv64's PLIC arm wakes
            // the waiter too.
            if azos_drv_sys::uart::rx_wake_wired() {
                azos_drv_sys::uart::rx_waiter_arm(azos_sched::current_task_tid());
                if azos_drv_sys::uart::can_read() {
                    azos_drv_sys::uart::rx_waiter_disarm();
                    break;
                }
                let dl = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ;
                azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
                azos_drv_sys::uart::rx_waiter_disarm();
                continue;
            }
            let dl = azos_drv_sys::timebase::now() + UART_POLL_INTERVAL;
            azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        }
        let c = azos_drv_sys::uart::getc();
        match c {
            b'\r' | b'\n' => {
                azos_drv_sys::uart::putc_locked(b'\n');
                break;
            }
            // Backspace / DEL
            0x08 | 0x7F => {
                if pos > 0 {
                    pos -= 1;
                    azos_drv_sys::uart::puts_locked("\x08 \x08");
                }
            }
            // Printable ASCII
            0x20..=0x7E => {
                if pos < MAX_LINE - 1 {
                    buf[pos] = c;
                    pos += 1;
                    azos_drv_sys::uart::putc_locked(c);
                }
            }
            _ => {}
        }
    }
    pos
}

// ── Argument parser ───────────────────────────────────────────────────────────

fn parse_args<'a>(line: &'a [u8], args: &mut [&'a [u8]; MAX_ARGS]) -> usize {
    let mut argc = 0;
    let mut start = 0;
    let mut in_word = false;

    for i in 0..line.len() {
        let b = line[i];
        if b == b' ' || b == b'\t' {
            if in_word {
                if argc < MAX_ARGS { args[argc] = &line[start..i]; argc += 1; }
                in_word = false;
            }
        } else {
            if !in_word { start = i; in_word = true; }
        }
    }
    if in_word && argc < MAX_ARGS {
        args[argc] = &line[start..line.len()];
        argc += 1;
    }
    argc
}

// ── Status ────────────────────────────────────────────────────────────────────

fn cmd_help() {
    azos_drv_sys::kconsoleln!("Available commands (recovery console):");
    azos_drv_sys::kconsoleln!("  help              - this message");
    azos_drv_sys::kconsoleln!("  mem               - memory info");
    azos_drv_sys::kconsoleln!("  uptime            - system uptime ticks");
    azos_drv_sys::kconsoleln!("  drvls             - list registered drivers (runtime registry)");
    azos_drv_sys::kconsoleln!("  swap <image>      - live update of a supervised server (successor from its row, endpoints handed over)");
    azos_drv_sys::kconsoleln!("  security          - security overview");
    azos_drv_sys::kconsoleln!("  estop             - e-stop latch / safe mode");
    azos_drv_sys::kconsoleln!("  ls [path]         - list directory");
    azos_drv_sys::kconsoleln!("  cat <path>        - print file (cat /proc/decisions: decision dump)");
    azos_drv_sys::kconsoleln!("  crash [log|clear] - crash log");
    azos_drv_sys::kconsoleln!("  why [id]          - explain a decision: its rule, numbers and provenance (no id: the latest)");
    azos_drv_sys::kconsoleln!("  ota [status|verify|rollback|recv <port>] - firmware slots");
    azos_drv_sys::kconsoleln!("  config [list|get|set|save|defaults] - persistent config");
    azos_drv_sys::kconsoleln!("  ifconfig          - network interface info");
    azos_drv_sys::kconsoleln!("  dhcp              - DHCP client (acquire IP)");
    azos_drv_sys::kconsoleln!("  wcet [reset|jitter|check] - WCET report (bench tooling)");
    azos_drv_sys::kconsoleln!("  bench [subsystem|all] [iters] - microbenches (bench tooling)");
    azos_drv_sys::kconsoleln!("  shutdown          - shutdown system");
    azos_drv_sys::kconsoleln!("  reboot            - reboot system");
}

/// `swap <image path>`: a live update of the supervised server started from
/// that image (`/fat/EPSRV.ELF`). The supervisor creates a successor from the
/// same signed row, lets the old server finish its calls, hands the
/// endpoints over without draining them, and stops the old one. A driver-
/// server task is refused (it needs Level 2). The result is on the console
/// (`[SUP] swap ...`).
fn cmd_swap(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("[SWAP] usage: swap <image path>");
        return;
    }
    let Some((slot, _)) = azos_sched::supervisor::sup_find_image(args[1]) else {
        azos_drv_sys::kconsoleln!("[SWAP] no supervised image of that path");
        return;
    };
    if azos_sched::supervisor::sup_request_swap(slot) {
        azos_drv_sys::kconsoleln!("[SWAP] requested for supervisor entry {}", slot);
    } else {
        azos_drv_sys::kconsoleln!("[SWAP] refused: not a serving spawned image, or a swap is under way");
    }
}

fn cmd_mem() {
    let free  = azos_mm::pmm::free_pages();
    let total = azos_mm::pmm::total_pages();
    let used  = azos_mm::pmm::used_pages();
    azos_drv_sys::kconsoleln!("[MEM] Total: {} pages ({} KiB)", total, total * 4);
    azos_drv_sys::kconsoleln!("[MEM] Used:  {} pages ({} KiB)", used,  used  * 4);
    azos_drv_sys::kconsoleln!("[MEM] Free:  {} pages ({} KiB)", free,  free  * 4);
}


fn cmd_uptime() {
    let ticks = azos_drv_sys::timebase::now();
    azos_drv_sys::kconsoleln!("[UPTIME] {} ticks (~{} ms)", ticks,
        ticks / (azos_drv_sys::timebase::TIMER_FREQ / 1000));
}

/// List registered drivers from the runtime registry: the view
/// `cat /sys/drivers` gives, without the FS (for an unhealthy volume).
fn cmd_drvls() {
    use azos_drv_api::DriverIsolation;
    use azos_drv_base::runtime::registry::REGISTRY;
    let reg = REGISTRY.lock();
    let mut shown = 0u32;
    for kind in 0u32..0x100 {
        if let Some(d) = reg.find_by_kind(kind) {
            let m = d.manifest();
            let iso = match m.isolation {
                DriverIsolation::InKernel       => "inkernel",
                DriverIsolation::UserProcess { .. } => "userproc",
                DriverIsolation::Hypervisor     => "hypervisor",
            };
            azos_drv_sys::kconsoleln!(
                "[DRV] 0x{:04x}  {:<16}  {}  perms=0x{:02x}",
                m.kind, m.name, iso, m.required_perms.bits(),
            );
            shown += 1;
        }
    }
    azos_drv_sys::kconsoleln!("[DRV] {} drivers registered", shown);
}

/// `estop`: is the actuators' e-stop latch (or safe mode, which holds the
/// same chokepoints) active? The release is ring 3's `estop` authority, not
/// this console's.
fn cmd_estop() {
    let active = azos_actuation::estop::estop_is_active();
    azos_drv_sys::kconsoleln!("[ESTOP] {}",
        if active { "ACTIVE (e-stop latched or safe mode)" } else { "clear" });
}


fn cmd_ls(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let path: &[u8] = if argc >= 2 { args[1] } else { b"/" };

    // FAT32 paths: /fat or /fat/...
    let is_fat = path == b"/fat" || path.starts_with(b"/fat/");
    if is_fat {
        azos_drv_sys::kconsole!("[FS] ls ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!(" (FAT32):");
        azos_fs::fat32_ls_root(|name, size, is_dir| {
            if is_dir {
                azos_drv_sys::kconsole!("  [DIR]  ");
                azos_drv_sys::uart::write_locked(name);
                azos_drv_sys::kconsoleln!();
            } else {
                azos_drv_sys::kconsole!("  [FILE] ");
                azos_drv_sys::uart::write_locked(name);
                azos_drv_sys::kconsoleln!("  ({} B)", size);
            }
        });
        return;
    }

    // ramfs path
    let idx = azos_fs::path_lookup(path);
    if idx == azos_fs::NO_IDX {
        azos_drv_sys::kconsole!("[FS] Not found: ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!();
        return;
    }
    azos_drv_sys::kconsole!("[FS] ls ");
    azos_drv_sys::uart::write_locked(path);
    azos_drv_sys::kconsoleln!(":");
    azos_fs::dir_list(idx, |name, itype| {
        let kind = match itype {
            azos_fs::INODE_DIR    => "[DIR] ",
            azos_fs::INODE_DEVICE => "[DEV] ",
            _                         => "[FILE]",
        };
        azos_drv_sys::kconsole!("  {} ", kind);
        azos_drv_sys::uart::write_locked(name);
        azos_drv_sys::kconsoleln!();
    });
}

fn cmd_cat(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: cat <path>");
        return;
    }
    let path = args[1];
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path, azos_fs::O_RDONLY);
    if fd < 0 {
        azos_drv_sys::kconsole!("[FS] Cannot open: ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!();
        return;
    }
    let mut buf = [0u8; 256];
    loop {
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), 256);
        if n <= 0 { break; }
        azos_drv_sys::uart::write_locked(&buf[..n as usize]);
    }
    azos_fs::vfs_close(&mut fd_table, fd);
    azos_drv_sys::uart::putc_locked(b'\n');
}

/// OTA firmware update — A/B slot management over TCP.
///
/// Subcommands:
///   ota recv <port>    — receive firmware image over TCP, write to inactive slot
///   ota status         — show current slot, boot count, versions
///   ota verify         — CRC-32 check both firmware slots
///   ota rollback       — switch active slot to last known good
fn cmd_ota(args: &[&[u8]; MAX_ARGS], argc: usize) {
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
/// U11-3 (partially closed, 2026-09-26): a FAILED promotion here — the
/// return-`false` paths below — no longer causes the CALLER
/// (`cmd_ota_recv`) to also delete `tmp_path`. Before this, a copy failure
/// (typically the volume too full to hold the live BIN, the staged TMP,
/// AND this copy simultaneously) emptied the rollback slot (`bin_path`,
/// via the `O_TRUNC` open below — see U09-13) AND destroyed the only
/// verified copy of the image in the same operation. The verified bytes in
/// `tmp_path` now survive a failed promotion for a retry. What this
/// function still cannot do without a real FAT32 rename primitive: avoid
/// `bin_path` going through a truncate-then-write window at all — that
/// window, and the fix for it, belong to `crates/fs/fs/src/fat32.rs`.
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
/// reaps a genuinely DEAD peer (`crates/net/net/src/tcp.rs`, 30 s x 3 probes),
/// and until 2026-09-26 nothing else bounded an application-silent one.
/// TIMER_FREQ-derived, never a raw tick literal — see U06-13/U11-6 for why
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
        //    volume `msc_gadget.rs` exports over USB mass storage. An
        //    attacker with the USB port rewrites the floor to 0; if both
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
    // literal (U06-13/U11-6: TIMER_FREQ is per-board).
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
    // can be talked into staging an image it will then refuse to run.
    // Flush before verifying. The payload was written through `vfs_*` on the
    // `/fat` mount point; the verifier reads the same file through
    // `fat32_open()` on the volume root (`/KERN_X.TMP` — see
    // `SECURE_BOOT_TMP_PATH_*` for why the prefixes differ). Both go through
    // the one FAT32 driver, so this is belt-and-braces rather than strictly
    // required — but "the bytes I verify are the bytes on disk" is not a
    // property worth inferring from cache-layer reasoning on the path that
    // decides whether unauthenticated code gets to run.
    let _ = azos_fs::fat32_sync();

    // U09-4/U11-4/security finding #10 — the `.SIG` now signs a MANIFEST
    // `{fw_version, payload_size, sha256(image)}` (see
    // `crates/core/crypto/src/ed25519.rs` module docs), so `secure_boot_*`
    // returns the AUTHENTICATED `fw_version` alongside the trust verdict
    // (0 when not `Verified`). `header.fw_version` from here on is
    // DISPLAY ONLY — the anti-rollback decision uses `auth_fw_version`.
    let (trust, trust_reason, auth_fw_version) =
        azos_ota::secure_boot_verify_staged_detailed(target_slot);
    let enforced = azos_ota::secure_boot_enforced_at_compile_time();

    if trust != azos_ota::BootTrust::Verified {
        // `Failed` means a `.SIG` IS present and does not verify (wrong key,
        // wrong contents, or a size/hash mismatch). Refuse that in BOTH
        // build flavours: a signature that is present and wrong is
        // evidence, not an absence, and promoting over the rollback target
        // on that evidence is never the right trade. Note this cannot fire
        // on a dev build — with the all-zero `SECURE_BOOT_PUBKEY` the
        // verifier short-circuits to `Unverified`/`NoTrustedKey` before
        // ever reading a `.SIG`.
        if enforced || trust == azos_ota::BootTrust::Failed {
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: staged image for slot {} is {} ({}) — \
                 {}; live slot left untouched, deleting .TMP",
                if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' },
                trust.as_str(), trust_reason.as_str(),
                if enforced {
                    "secure-boot-enforced is compiled in, refusing to install"
                } else {
                    "a present-but-invalid or unverifiable signature is never installed"
                });
            // Name the sidecar by slot letter rather than printing the path
            // slice: `secure_boot_sig_path` returns `&[u8]`, which `{:?}`
            // renders as a list of decimal byte values — useless in a log.
            azos_drv_sys::kconsoleln!(
                "[OTA] REFUSED: sign the image with tools/sign_ota.py --fw-version <N> \
                 and place the sidecar at /KERN_{}.SIG (FAT32 volume root) before retrying",
                if target_slot == azos_ota::SLOT_A { 'A' } else { 'B' });
            let _ = azos_fs::fat32_unlink_path(target_path);
            continue 'session;
        }

        // Not enforced, and no usable signature was found at all. Install —
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
             (tools/gen_prod_key.py) and build --features secure-boot-enforced.");
    } else {
        // U09-4 — the AUTHORITATIVE anti-rollback check. The one in the
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
    // (a driver gap — `crates/fs/fs/src/fat32.rs`, not owned here), so this
    // still emulates it with unlink-then-copy. U11-3, PARTIALLY closed from
    // this side: on a copy FAILURE we no longer also delete `.TMP` (below) —
    // the already-verified staged bytes survive for a retry. What remains
    // open, and needs the fs owner: `fat32_open(..., O_TRUNC)` itself frees
    // the target's cluster chain before the first byte of the copy is
    // written (U09-13), so `.BIN` can still end up empty if the copy fails
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
    // floor (U09-4/U11-4). Only a `Verified` install sets it; an
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

/// Phase 16: print a summary of all active security layers.
fn cmd_security() {
    azos_drv_sys::kconsoleln!("[SEC] ========================================");
    azos_drv_sys::kconsoleln!("[SEC]  Phase 16: Security overview");
    azos_drv_sys::kconsoleln!("[SEC] ========================================");

    // Sv39 paging (RISC-V). aarch64 has no `satp` CSR to read here — see
    // `crates/core/sched/src/process.rs`'s `make_satp` doc for the same gap on
    // the scheduler side; this command just reports that honestly instead
    // of printing a RISC-V register that doesn't exist on this ISA.
    #[cfg(target_arch = "riscv64")]
    {
        let satp = azos_arch::cpu::read_satp();
        if satp != 0 {
            azos_drv_sys::kconsoleln!("[SEC]  Sv39 paging:     ACTIVE  (satp={:#x})", satp);
        } else {
            azos_drv_sys::kconsoleln!("[SEC]  Sv39 paging:     DISABLED");
        }
    }
    #[cfg(not(target_arch = "riscv64"))]
    azos_drv_sys::kconsoleln!("[SEC]  VMSAv8-64 paging: (TTBR0_EL1 read not wired up yet)");

    // Stack canaries
    let (ok, total) = azos_sched::stack_canary_check();
    azos_drv_sys::kconsoleln!(
        "[SEC]  Stack canaries:  {}/{} intact  (magic=0xDEADBEEFCAFE1234)", ok, total);

    // RT motor watchdog
    #[cfg(feature = "use-robot")]
    let wdt_fired = azos_robot::motor_watchdog_fired();
    #[cfg(feature = "use-robot")]
    if wdt_fired {
        azos_drv_sys::kconsoleln!("[SEC]  RT watchdog:     FIRED   (motors stopped)");
    } else {
        let t = azos_robot::watchdog_timeout_ticks() / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
        azos_drv_sys::kconsoleln!("[SEC]  RT watchdog:     OK      (timeout={} ms)", t);
    }

    // System watchdog task
    azos_drv_sys::kconsoleln!("[SEC]  System watchdog: RUNNING (sys-wdt task, ~500 ms)");

    azos_drv_sys::kconsoleln!("[SEC] ========================================");
}

/// Crash log management: `crash log` / `crash clear`.
fn cmd_crash(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"log" };

    if sub == b"log" {
        let mut fd_table = azos_fs::ScratchFds::new();
        let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/CRASH.LOG",
                                        azos_fs::O_RDONLY);
        if fd < 0 {
            azos_drv_sys::kconsoleln!("[CRASH] No crash log found");
            return;
        }
        static mut CRASH_READ_BUF: [u8; 2048] = [0u8; 2048];
        let buf = unsafe { &mut *(&raw mut CRASH_READ_BUF) };
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
        azos_fs::vfs_close(&mut fd_table, fd);
        if n <= 0 {
            azos_drv_sys::kconsoleln!("[CRASH] Crash log empty");
            return;
        }
        azos_drv_sys::kconsoleln!("[CRASH] === /fat/CRASH.LOG ({} bytes) ===", n);
        azos_drv_sys::uart::write_locked(&buf[..n as usize]);
        azos_drv_sys::kconsoleln!("[CRASH] === end ===");
    } else if sub == b"clear" {
        let _ = azos_fs::fat32_unlink_path(b"/fat/CRASH.LOG");
        azos_drv_sys::kconsoleln!("[CRASH] Crash log cleared");
    } else {
        azos_drv_sys::kconsoleln!("Usage: crash [log|clear]");
    }
}

/// A fixed buffer the chain is formatted into and written to the console in
/// one piece (the lines of one record do not interleave with another task's).
struct ChainBuf {
    b: [u8; 1024],
    n: usize,
}

impl core::fmt::Write for ChainBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let s = s.as_bytes();
        let room = self.b.len() - self.n;
        let k = s.len().min(room);
        self.b[self.n..self.n + k].copy_from_slice(&s[..k]);
        self.n += k;
        if k < s.len() { Err(core::fmt::Error) } else { Ok(()) }
    }
}

/// Decimal `u64`, nothing else (`None` for empty, a sign, a non-digit or an
/// overflow).
fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

/// How many decisions `why` with no id lists.
const WHY_LIST: usize = 12;

/// `why [<id>]`: the decision query (`azos_decision::query` / `lookup`, the
/// same functions the `Decisions` interface serves in ring 3). With an id,
/// the chain behind that decision; without one, the latest few, one line
/// each, so there is an id to ask about.
///
/// What it can name is what is held: the journal of durable decisions
/// (refusals, rate-limited capability denials; Kconfig
/// `DECISION_REFUSALS_DURABLE`) and, when built, the ring
/// (`DECISION_RECORDS_DEV`). Ids restart at a reset.
fn cmd_why(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if !(azos_decision::DURABLE || azos_decision::ON) {
        azos_drv_sys::kconsoleln!("[WHY] decision records are not built in (DECISION_REFUSALS_DURABLE=n, DECISION_RECORDS_DEV=n)");
        return;
    }
    let mut out = ChainBuf { b: [0; 1024], n: 0 };
    if argc < 2 {
        let total = azos_decision::total();
        let f = azos_decision::Filter { after: total.saturating_sub(WHY_LIST as u64), ..azos_decision::Filter::ANY };
        let mut ids = [0u64; WHY_LIST];
        let n = azos_decision::query(&f, &mut ids);
        if n == 0 {
            azos_drv_sys::kconsoleln!("[WHY] no decision held ({} since boot)", total);
            return;
        }
        azos_drv_sys::kconsoleln!("[WHY] latest {} of {} decisions since boot (why <id> for the chain):", n, total);
        for &id in &ids[..n] {
            out.n = 0;
            if let Some(p) = azos_decision::lookup(id) {
                let _ = p.write_line(&mut out);
                azos_drv_sys::uart::write_locked(&out.b[..out.n]);
            }
        }
        return;
    }
    let Some(id) = parse_u64(args[1]) else {
        azos_drv_sys::kconsoleln!("Usage: why [id]");
        return;
    };
    match azos_decision::lookup(id) {
        None => azos_drv_sys::kconsoleln!(
            "[WHY] decision {} is not held ({} since boot; the journal keeps {})",
            id,
            azos_decision::total(),
            azos_decision::JOURNAL_ENTRIES
        ),
        Some(p) => {
            let _ = p.write_chain(&mut out);
            azos_drv_sys::uart::write_locked(&out.b[..out.n]);
        }
    }
}

/// `shutdown` — orderly power-off. Needs the console's WRITE on the `power` endpoint on
/// every build (`authority_policy::CMD_SHUTDOWN`), as ring 3's `power
/// shutdown` does; refused, it records the denial and returns to the prompt.
fn cmd_shutdown() {
    if !authority::check_power_row(authority_policy::CMD_SHUTDOWN) {
        return;
    }
    azos_drv_sys::kconsoleln!("[RECOVERY] System shutdown...");
    // Orderly: void this boot's unconfirmed mark rather than count a crash.
    let _ = azos_ota::ota_void_unconfirmed_boot();
    // The line above may be deferred (ring 3 owns the console): out first.
    azos_drv_sys::uart::console_flush_for_reboot();
    // Same 1:1 wrapper as `crates/core/syscall`'s `sys_shutdown` fix — see its
    // comment for why this is not a behavior change on RISC-V.
    use azos_arch::Boot;
    azos_arch::ARCH.shutdown()
}

/// `reboot` — orderly reboot. Same authority as [`cmd_shutdown`]
/// (`authority_policy::CMD_REBOOT`).
fn cmd_reboot() {
    if !authority::check_power_row(authority_policy::CMD_REBOOT) {
        return;
    }
    azos_drv_sys::kconsoleln!("[RECOVERY] System reboot...");
    let _ = azos_ota::ota_void_unconfirmed_boot();
    azos_drv_sys::uart::console_flush_for_reboot();
    use azos_arch::Boot;
    azos_arch::ARCH.reboot()
}

// ── Parsing utilities ─────────────────────────────────────────────────────────

/// Decimal digits to a `u32`, **saturating**, stopping at the first non-digit.
///
/// Saturating is not a style choice here. The release profile sets
/// `overflow-checks = true` with `panic = "abort"` (`Cargo.toml:326-327`), so
/// an unguarded `v = v * 10 + d` on operator-typed input is not a wrong
/// number — it is a kernel abort, i.e. a board reset, from someone typing a
/// long number at the console.
///
/// Three copies of this loop carried exactly that bug until 2026-09-18:
/// `parse_u8` and `parse_u16` accumulated in `u32` (overflow at 10 digits)
/// and `parse_u32` in `u64` (20 digits), each clamping only AFTER the loop,
/// by which point the multiply had already aborted. A fourth copy,
/// `parse_u32_shell`, had the saturating form all along — the drift was
/// invisible because every copy *looked* clamped. All four are now this one
/// function; the clamp is what differs, and it happens on a value that
/// already exists.
fn parse_u32_sat(s: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in s {
        if b < b'0' || b > b'9' { break; }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    v
}

fn parse_u16(s: &[u8]) -> u16 { parse_u32_sat(s).min(65535) as u16 }

// ── Phase 18 + G2: Persistent configuration ──────────────────────────────────

/// Push config atomics to every subsystem (net, sched, behavior, encoder, wdt).
/// Called after `cfg_apply()` from `config set` or `config defaults` (and the ring-3 `config set`).
pub(crate) fn apply_config_to_subsystems() {
    use core::sync::atomic::Ordering;

    // Network
    let ip   = azos_config::unpack_ip(
        azos_config::CFG_NET_IP.load(Ordering::Relaxed));
    let mask = azos_config::unpack_ip(
        azos_config::CFG_NET_MASK.load(Ordering::Relaxed));
    let gw   = azos_config::unpack_ip(
        azos_config::CFG_NET_GATEWAY.load(Ordering::Relaxed));
    azos_net::net_set_ip(ip, mask, gw);

    // Scheduler Hz
    let hz = azos_config::cfg_get_u32(b"sched_hz", 100);
    if hz >= 10 {
        azos_drv_sys::timebase::sched_hz_set(hz as u64);
    }

    // Behavior layers
    #[cfg(feature = "use-robot")]
    azos_behavior::layer_set_enabled(1,
        azos_config::BEHAVIOR_L1_ENABLED.load(Ordering::Relaxed));
    #[cfg(feature = "use-robot")]
    azos_behavior::layer_set_enabled(2,
        azos_config::BEHAVIOR_L2_ENABLED.load(Ordering::Relaxed));
    #[cfg(feature = "use-robot")]
    azos_behavior::layer_set_enabled(3,
        azos_config::BEHAVIOR_L3_ENABLED.load(Ordering::Relaxed));

    // Behavior VLA server
    #[cfg(feature = "use-robot")]
    let bport = azos_config::BEHAVIOR_SERVER_PORT.load(Ordering::Relaxed);
    #[cfg(feature = "use-robot")]
    if bport > 0 {
        let bip = azos_config::behavior_server_ip_bytes();
        azos_behavior::remote_configure(bip, bport as u16);
    }

    // Encoder physical params
    #[cfg(feature = "use-robot")]
    azos_robot::set_ticks_per_m(
        azos_config::CFG_TICKS_PER_M.load(Ordering::Relaxed));
    #[cfg(feature = "use-robot")]
    azos_robot::set_wheel_base_mm(
        azos_config::CFG_WHEEL_BASE_MM.load(Ordering::Relaxed));

    // Watchdog (note: wdt_init re-programs the hardware timer)
    azos_drv_sys::wdt::wdt_init(
        azos_config::CFG_WATCHDOG_MS.load(Ordering::Relaxed));
}

/// `config [list | get <key> | set <key> <val> | save | defaults]`
///
/// Recovery from a bad configuration: reset to the factory defaults and
/// persist them (`/fat/CONFIG.INI`), or fix one key. The same bodies as the
/// ring-3 `config` tool (`families`).
fn cmd_config(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"list" };

    if sub == b"list" {
        let count = azos_config::cfg_count();
        azos_drv_sys::kconsoleln!("[CFG] {} entries:", count);
        for i in 0..count {
            if let Some((k, v)) = azos_config::cfg_iter(i) {
                azos_drv_sys::uart::write_locked(k);
                azos_drv_sys::uart::putc_locked(b'=');
                azos_drv_sys::uart::write_locked(v);
                azos_drv_sys::kconsoleln!();
            }
        }
        azos_drv_sys::kconsoleln!("[CFG] ml_enabled (runtime)={}",
            azos_config::ML_ENABLED.load(core::sync::atomic::Ordering::Relaxed) as u8);
        return;
    }

    if sub == b"get" {
        if argc < 3 {
            azos_drv_sys::kconsoleln!("Usage: config get <key>");
            return;
        }
        let key = args[2];
        match azos_config::cfg_get(key) {
            None => {
                azos_drv_sys::kconsole!("[CFG] not found: ");
                azos_drv_sys::uart::write_locked(key);
                azos_drv_sys::kconsoleln!();
            }
            Some(v) => {
                azos_drv_sys::uart::write_locked(key);
                azos_drv_sys::uart::putc_locked(b'=');
                azos_drv_sys::uart::write_locked(v);
                azos_drv_sys::kconsoleln!();
            }
        }
        return;
    }

    if sub == b"set" {
        if argc < 4 {
            azos_drv_sys::kconsoleln!("Usage: config set <key> <val>");
            return;
        }
        let key = args[2];
        let val = args[3];
        if key == b"watchdog_ms"
            && !authority::check_power_row(authority_policy::CMD_CONFIG_SET_WATCHDOG)
        {
            return;
        }
        if families::config_set(key, val) == 0 {
            azos_drv_sys::kconsoleln!("[CFG] set OK");
        } else {
            azos_drv_sys::kconsoleln!(
                "[CFG] FAILED: key>{} or val>{} bytes, or table full ({})",
                azos_config::MAX_KEY, azos_config::MAX_VAL,
                azos_config::MAX_ENTRIES);
        }
        return;
    }

    if sub == b"save" {
        static mut SAVE_BUF: [u8; 1024] = [0u8; 1024];
        let buf = unsafe { &mut *(&raw mut SAVE_BUF) };
        let n = azos_config::cfg_serialize(buf);
        if n == 0 {
            azos_drv_sys::kconsoleln!("[CFG] nothing to save");
            return;
        }
        let mut fd_table = azos_fs::ScratchFds::new();
        let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/CONFIG.INI",
            azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
        if fd < 0 {
            azos_drv_sys::kconsoleln!("[CFG] cannot open /fat/CONFIG.INI for write");
            return;
        }
        let written = azos_fs::vfs_write(&mut fd_table, fd, buf.as_ptr(), n);
        azos_fs::vfs_close(&mut fd_table, fd);
        // A close queues under FAT32's write-back cache; "saved" means on
        // the medium.
        let _ = azos_fs::fat32_sync();
        azos_drv_sys::kconsoleln!("[CFG] saved {} bytes to /fat/CONFIG.INI", written);
        return;
    }

    // Reset to factory defaults (in-memory only, use `config save` to persist).
    if sub == b"defaults" {
        azos_config::cfg_defaults();
        azos_config::cfg_apply();
        apply_config_to_subsystems();
        azos_drv_sys::kconsoleln!("[CFG] factory defaults applied ({} entries)",
            azos_config::cfg_count());
        return;
    }

    azos_drv_sys::kconsoleln!(
        "Usage: config [list|get <key>|set <k> <v>|save|defaults]");
}

// ── Network (what `ota recv` needs) ───────────────────────────────────────────

fn cmd_ifconfig() {
    azos_net::net_info();
}

fn cmd_dhcp() {
    azos_drv_sys::kconsoleln!("[DHCP] Starting DHCP discovery...");
    let ok = azos_net::dhcp::dhcp_start(azos_sched::task_yield);
    if ok {
        azos_drv_sys::kconsoleln!("[DHCP] Bound successfully");
    } else {
        azos_drv_sys::kconsoleln!("[DHCP] Failed to obtain IP");
    }
}

// ── (c) Not recovery: bench tooling ───────────────────────────────────────────
//
// `tools/bench_e2e.sh` types `wcet`, `wcet jitter` and `bench all 1000` here.
// No gate row drives them; they stay until the bench harness has a ring-3 home.

fn cmd_wcet(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 && args[1] == b"reset" {
        azos_drv_sys::wcet::wcet_reset_all();
        azos_drv_sys::kconsoleln!("[WCET] Statistics reset.");
        return;
    }
    if argc >= 2 && args[1] == b"jitter" {
        azos_drv_sys::wcet::jitter_report();
        return;
    }
    if argc >= 2 && args[1] == b"check" {
        let viols = azos_drv_sys::wcet::wcet_check_bounds();
        if viols == 0 {
            azos_drv_sys::kconsoleln!("[WCET] All bounds satisfied.");
        }
        return;
    }
    azos_drv_sys::wcet::wcet_report();
}


/// `bench [subsystem|all] [iters]` — run synthetic kernel microbenches.
///
/// Each subsystem emits one `[BENCH-RES] <subsystem>.<name> iters=N
/// min_cycles=… max_cycles=… avg_cycles=… total_cycles=…` line per
/// microbench.  The bench harness parses these into the bench JSON.
///
/// Defaults: `bench all` with `iters=1000`.  Override iters with the
/// second arg, e.g. `bench ipc 100` or `bench all 5000`.
#[cfg(feature = "use-robot")]
fn cmd_bench(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let subsystem: &[u8] = if argc >= 2 { args[1] } else { b"all" };
    let iters: u64 = if argc >= 3 {
        // Quick decimal parse; fallback to default on garbage.
        let mut n = 0u64;
        for &b in args[2] {
            if !b.is_ascii_digit() { n = 0; break; }
            n = n.saturating_mul(10).saturating_add((b - b'0') as u64);
        }
        if n == 0 { azos_bench::DEFAULT_ITERS } else { n }
    } else {
        azos_bench::DEFAULT_ITERS
    };

    let emitted = match subsystem {
        b"all"    => azos_bench::run_all(iters),
        b"ipc"    => azos_bench::ipc::run(iters),
        b"mm"     => azos_bench::mm::run(iters),
        b"sched"  => azos_bench::sched::run(iters),
        b"net"    => azos_bench::net::run(iters),
        b"fs"     => azos_bench::fs::run(iters),
        b"crypto" => azos_bench::crypto::run(iters),
        _         => {
            azos_drv_sys::kconsoleln!(
                "[BENCH] unknown subsystem; valid: all ipc mm sched net fs crypto",
            );
            0
        }
    };
    let _ = emitted;
}

/// Without the Robot domain there is no bench crate.
#[cfg(not(feature = "use-robot"))]
fn cmd_bench(_args: &[&[u8]; MAX_ARGS], _argc: usize) {
    azos_drv_sys::kconsoleln!(
        "[RECOVERY] 'bench' needs the Robot domain (USE_ROBOT); this image was built without it");
}

// ── OTA auto-recv task entry ──────────────────────────────────────────────────

/// Kernel task entry for CONFIG.INI `ota_auto_recv_port`.
/// Spawned by main.rs when the config key is non-zero; `port_arg` is the port.
pub fn ota_recv_task_entry(port_arg: usize) {
    azos_drv_sys::kconsoleln!("[OTA] Auto-recv task running on port {}", port_arg);
    cmd_ota_recv(port_arg as u16);
}


// ── Main loop ─────────────────────────────────────────────────────────────────

/// The recovery console's entry. Runs forever, reading and executing
/// commands. Called from a kernel task (`kernel/src/tasks/system.rs`).
pub fn recovery_run() -> ! {
    azos_drv_sys::kconsoleln!();
    azos_drv_sys::kconsoleln!("AzOS shell — type 'help' for commands");
    azos_drv_sys::kconsoleln!();

    // U11-5: seed the console's own endpoints before the first command can
    // possibly run. See `authority.rs` module doc — commenting this call out
    // is the RED canary for `reboot`/`shutdown`'s authority gate.
    authority::seed_console_authority();

    let mut line_buf = [0u8; MAX_LINE];

    loop {
        azos_drv_sys::uart::puts_locked(PROMPT);

        let len = readline(&mut line_buf);
        azos_net::net_poll();

        if len > 0 {
            let mut args: [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
            let argc = parse_args(&line_buf[..len], &mut args);

            if argc > 0 {
                let cmd = args[0];
                if      cmd == b"help"     { cmd_help(); }
                else if cmd == b"mem"      { cmd_mem(); }
                else if cmd == b"uptime"   { cmd_uptime(); }
                else if cmd == b"drvls"    { cmd_drvls(); }
                else if cmd == b"swap"     { cmd_swap(&args, argc); }
                else if cmd == b"security" { cmd_security(); }
                else if cmd == b"estop"    { cmd_estop(); }
                else if cmd == b"ls"       { cmd_ls(&args, argc); }
                else if cmd == b"cat"      { cmd_cat(&args, argc); }
                else if cmd == b"crash"    { cmd_crash(&args, argc); }
                else if cmd == b"why"      { cmd_why(&args, argc); }
                else if cmd == b"ota"      { cmd_ota(&args, argc); }
                else if cmd == b"config"   { cmd_config(&args, argc); }
                else if cmd == b"ifconfig" { cmd_ifconfig(); }
                else if cmd == b"dhcp"     { cmd_dhcp(); }
                else if cmd == b"wcet"     { cmd_wcet(&args, argc); }
                else if cmd == b"bench"    { cmd_bench(&args, argc); }
                else if cmd == b"shutdown" { cmd_shutdown(); }
                else if cmd == b"reboot"   { cmd_reboot(); }
                else {
                    azos_drv_sys::kconsole!("[RECOVERY] Unknown: ");
                    azos_drv_sys::uart::write_locked(cmd);
                    azos_drv_sys::kconsoleln!(" (type 'help')");
                }
            }
        }

        for b in line_buf.iter_mut() { *b = 0; }
    }
}
