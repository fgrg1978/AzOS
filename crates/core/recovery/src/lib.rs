// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The recovery console: a small kernel-task console on the UART
//! for the case where ring 3 cannot start (no `SH.ELF`, a corrupt volume, a
//! supervisor that gave up). The user shell is the one shell
//! (`userspace/services/sh`); this is not a second one, so it carries only
//! what diagnosing and repairing a machine without ring 3 needs:
//!
//! * `help`, `mem`, `uptime`, `security`, `estop`: status;
//! * `ls`, `cat`, `crash [log|clear]`,
//!   `why [<id>]` (the chain behind a refusal or denial, from the decision
//!   query: rule, verdict, subject, numbers, provenance, clock): diagnosis;
//! * `ota [status|verify|rollback|recv <port>]`, `config [list|get|set|save|defaults]`,
//!   `ifconfig`, `dhcp` (the network `ota recv` needs): repair;
//! * `swap <image>`: the live update of a supervised server (handover Level 1);
//! * `reboot`, `shutdown`: the two exits, both checked against WRITE on the `power` endpoint.
//!
//! Marked **(c), not recovery**: `wcet` and `bench`, typed by hand on this
//! console and left out of `help`.
//!
//! Besides the console loop the crate holds two things ring 3 and the boot
//! also use: the family bodies behind the typed syscalls (`families`) and the
//! `ota-recv` kernel task entry.

mod authority;
#[cfg(feature = "boot-slots")]
mod ota;
#[cfg(feature = "boot-slots")]
pub use ota::ota_recv_task_entry;
#[cfg(feature = "boot-slots")]
use ota::cmd_ota;
/// The flight/behavior/config/OTA bodies, shared with ring 3.
pub mod families;
/// The minidump of a ring-3 task a fault killed: layout, file ring, report
/// (`kernel/src/trap/crash.rs` writes it, `why crash` reads it).
pub mod crashdump;
pub mod coredump;
// The table is shared with the ring-3 typed calls.
use azos_ipc::authority_policy;

const MAX_LINE:  usize = 256;
const MAX_ARGS:  usize = 8;

/// park a listening/receiving loop for ~10 ms instead of yielding.
/// A bare `task_yield()` in a wait-for-something loop returns immediately
/// whenever nothing outranks the caller, turning the loop into a spinner
/// that starves every lower-priority task on its hart. 100 Hz polling is
/// far above human and protocol patience for the paths that use this
/// (accept, header wait, interactive echo); loops that drain an active
/// bulk transfer deliberately do NOT use it.
#[cfg(feature = "boot-slots")]
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
        // Poll until a character is available. sleep between polls —
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
            // Both ISAs: riscv64's PLIC arm wakes
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
    azos_drv_sys::kconsoleln!("  swap <image>      - live update of a supervised server (successor from its row, endpoints handed over)");
    azos_drv_sys::kconsoleln!("  security          - security overview");
    azos_drv_sys::kconsoleln!("  estop             - e-stop latch / safe mode");
    azos_drv_sys::kconsoleln!("  ls [path]         - list directory");
    azos_drv_sys::kconsoleln!("  cat <path>        - print file");
    azos_drv_sys::kconsoleln!("  crash [log|clear] - crash log");
    azos_drv_sys::kconsoleln!("  why [id]          - explain a decision: its rule, numbers and provenance (no id: the latest)");
    #[cfg(feature = "boot-slots")]
    azos_drv_sys::kconsoleln!("  ota [status|verify|rollback|recv <port>] - firmware slots");
    azos_drv_sys::kconsoleln!("  config [list|get|set|save|defaults] - persistent config");
    azos_drv_sys::kconsoleln!("  ifconfig          - network interface info");
    azos_drv_sys::kconsoleln!("  dhcp              - DHCP client (acquire IP)");
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

    let mut ent = azos_fs::DirEnt::new();
    if azos_fs::vfs_readdir(path, 0, &mut ent).is_err() {
        azos_drv_sys::kconsole!("[FS] Not found: ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!();
        return;
    }
    azos_drv_sys::kconsole!("[FS] ls ");
    azos_drv_sys::uart::write_locked(path);
    azos_drv_sys::kconsoleln!(":");
    let mut cookie = 0u64;
    while let Ok(Some(next)) = azos_fs::vfs_readdir(path, cookie, &mut ent) {
        azos_drv_sys::kconsole!("  {} ", if ent.is_dir { "[DIR] " } else { "[FILE]" });
        azos_drv_sys::uart::write_locked(ent.name());
        azos_drv_sys::kconsoleln!();
        cookie = next;
    }
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
    #[cfg(feature = "boot-slots")]
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
    #[cfg(feature = "boot-slots")]
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
/// Three copies of this loop carried exactly that bug:
/// `parse_u8` and `parse_u16` accumulated in `u32` (overflow at 10 digits)
/// and `parse_u32` in `u64` (20 digits), each clamping only AFTER the loop,
/// by which point the multiply had already aborted. A fourth copy,
/// `parse_u32_shell`, had the saturating form all along — the drift was
/// invisible because every copy *looked* clamped. All four are now this one
/// function; the clamp is what differs, and it happens on a value that
/// already exists.
#[cfg(feature = "boot-slots")]
fn parse_u32_sat(s: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in s {
        if b < b'0' || b > b'9' { break; }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    v
}

#[cfg(feature = "boot-slots")]
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
// `wcet`, `wcet jitter` and `bench all 1000`, typed by hand. No gate row and no
// script drives them; they stay until the bench harness has a ring-3 home.

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
        b"all"    => azos_robot_bench::run_all(iters),
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


// ── Main loop ─────────────────────────────────────────────────────────────────

/// The recovery console's entry. Runs forever, reading and executing
/// commands. Called from a kernel task (`kernel/src/tasks/system.rs`).
pub fn recovery_run() -> ! {
    azos_drv_sys::kconsoleln!();
    azos_drv_sys::kconsoleln!("AzOS shell — type 'help' for commands");
    azos_drv_sys::kconsoleln!();

    // seed the console's own endpoints before the first command can
    // possibly run. See `authority.rs` module doc — commenting this call out
    // is the RED canary for `reboot`/`shutdown`'s authority gate.
    authority::seed_console_authority();

    let mut line_buf = [0u8; MAX_LINE];

    loop {
        azos_drv_sys::uart::puts_locked(azos_limits::PRESET_PROMPT);

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
                else if cmd == b"swap"     { cmd_swap(&args, argc); }
                else if cmd == b"security" { cmd_security(); }
                else if cmd == b"estop"    { cmd_estop(); }
                else if cmd == b"ls"       { cmd_ls(&args, argc); }
                else if cmd == b"cat"      { cmd_cat(&args, argc); }
                else if cmd == b"crash"    { cmd_crash(&args, argc); }
                else if cmd == b"why"      { cmd_why(&args, argc); }
                else if cmd == b"ota" {
                    #[cfg(feature = "boot-slots")]
                    cmd_ota(&args, argc);
                    #[cfg(not(feature = "boot-slots"))]
                    azos_drv_sys::kconsoleln!(
                        "[RECOVERY] 'ota' needs the A/B boot slots (BOOT_SLOTS); this image was built without them");
                }
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
