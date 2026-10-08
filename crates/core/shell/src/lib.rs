// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Kernel shell — port of kernel/core/shell.c
//! Interactive UART command shell.  Runs as a kernel task.

mod authority;
/// Wave 12: the flight/behavior/config/OTA bodies, shared with ring 3.
pub mod families;
// RFC-0055 S5: the table is shared with the ring-3 typed calls.
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
            // Both ISAs since wave 11 (RFC-0055 S1): riscv64's PLIC arm wakes
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

// ── Individual commands ───────────────────────────────────────────────────────

fn cmd_help() {
    azos_drv_sys::kconsoleln!("Available commands:");
    azos_drv_sys::kconsoleln!("  help              - this message");
    #[cfg(not(feature = "no-mmu"))]
    azos_drv_sys::kconsoleln!("  exec <path>       - load and run ELF from FAT32 (consumes the console)");
    azos_drv_sys::kconsoleln!("  spawn <path>      - like exec, but on a new task (console stays free)");
    azos_drv_sys::kconsoleln!("  ps                - list current task");
    azos_drv_sys::kconsoleln!("  mem               - memory info");
    azos_drv_sys::kconsoleln!("  uptime            - system uptime ticks");
    azos_drv_sys::kconsoleln!("  drvls             - list registered drivers (RFC-0002 registry)");
    azos_drv_sys::kconsoleln!("  ls [path]         - list directory");
    azos_drv_sys::kconsoleln!("  cat <path>        - print file");
    azos_drv_sys::kconsoleln!("  write <path> <t>  - write text to FAT32 file");
    azos_drv_sys::kconsoleln!("  rm <path>         - remove FAT32 file");
    azos_drv_sys::kconsoleln!("  mkdir <path>      - create directory");
    azos_drv_sys::kconsoleln!("  echo <text>       - echo arguments");
    azos_drv_sys::kconsoleln!("  disk              - disk capacity");
    azos_drv_sys::kconsoleln!("  ifconfig          - network interface info");
    azos_drv_sys::kconsoleln!("  ping <ip>         - send ICMP ping");
    azos_drv_sys::kconsoleln!("  arp               - ARP cache");
    azos_drv_sys::kconsoleln!("  tcpecho <port>    - TCP echo server");
    azos_drv_sys::kconsoleln!("  gpio info         - GPIO state");
    azos_drv_sys::kconsoleln!("  pwm info          - PWM state");
    azos_drv_sys::kconsoleln!("  i2c scan [bus]    - I2C bus scan");
    azos_drv_sys::kconsoleln!("  motor info        - motor state");
    azos_drv_sys::kconsoleln!("  rvv               - RVV 1.0 f32 benchmark (qemu-rvv only)");
    azos_drv_sys::kconsoleln!("  pipeline          - motor command pipeline status");
    azos_drv_sys::kconsoleln!("  security          - Phase 16: security overview");
    azos_drv_sys::kconsoleln!("  odom              - Phase 17: odometry (dist, heading)");
    azos_drv_sys::kconsoleln!("  traj [status|dump [N]|flush|reset]  - trajectory ring");
    azos_drv_sys::kconsoleln!("  ota recv <port>   - receive a firmware image over TCP into the inactive slot");
    azos_drv_sys::kconsoleln!("  config [list|get|set|save|load|defaults|export] - Phase G2: persistent config");
    azos_drv_sys::kconsoleln!("  behavior [status|enable|disable|remote|goal]  - Phase G1: subsumption + VLA");
    azos_drv_sys::kconsoleln!("  pmp               - Phase D: PMP memory-protection policy");
    azos_drv_sys::kconsoleln!("  wdt               - Phase D: hardware watchdog status");
    azos_drv_sys::kconsoleln!("  fuzz              - Phase D: basic memory fuzz test");
    azos_drv_sys::kconsoleln!("  sched_hz [<hz>]   - Phase E1: show/set scheduler rate");
    azos_drv_sys::kconsoleln!("  imu [info|read]   - Phase E2: MPU-6050 IMU sensor");
    azos_drv_sys::kconsoleln!("  baro [info|read]  - Phase G1: BMP280 barometer");
    azos_drv_sys::kconsoleln!("  attitude          - Phase I1: AHRS attitude (roll/pitch/yaw/alt)");
    azos_drv_sys::kconsoleln!("  gps [info|read]   - Phase I2: GPS position (lat/lon/alt)");
    azos_drv_sys::kconsoleln!("  flight [status|arm|disarm|mode <m>] - Phase J: flight controller");
    azos_drv_sys::kconsoleln!("  authority         - U11-5: per-command CapKind authority table");
    azos_drv_sys::kconsoleln!("  rc [info]         - Phase K: RC receiver channels");
    azos_drv_sys::kconsoleln!("  esc [info]        - Phase J: ESC motor outputs");
    azos_drv_sys::kconsoleln!("  telem [status|start <port>|stop] - Phase L: telemetry");
    azos_drv_sys::kconsoleln!("  range             - Phase M: rangefinder sensors (US+ToF)");
    azos_drv_sys::kconsoleln!("  nav [info]        - Phase N: navigation + waypoints");
    azos_drv_sys::kconsoleln!("  csi               - Phase M2: CSI camera info");
    azos_drv_sys::kconsoleln!("  wifi [info|connect|disconnect] - Phase O: WiFi (API stub)");
    azos_drv_sys::kconsoleln!("  spi info          - SPI bus info");
    azos_drv_sys::kconsoleln!("  can [info|send|recv] - CAN bus");
    azos_drv_sys::kconsoleln!("  dma info          - DMA controller info");
    azos_drv_sys::kconsoleln!("  usb info          - USB host info");
    azos_drv_sys::kconsoleln!("  pm [info|idle|suspend|resume] - power management");
    azos_drv_sys::kconsoleln!("  eth info          - Ethernet MAC info");
    azos_drv_sys::kconsoleln!("  dhcp              - DHCP client (acquire IP)");
    #[cfg(not(feature = "no-mmu"))]
    azos_drv_sys::kconsoleln!("  fork              - fork current process (test)");
    azos_drv_sys::kconsoleln!("  shutdown          - shutdown system");
    azos_drv_sys::kconsoleln!("  reboot            - reboot system");
}

fn cmd_ps() {
    azos_drv_sys::kconsoleln!("[SCHED] TID: {}", azos_sched::current_task_tid());
    azos_drv_sys::kconsoleln!("[SCHED] Task: {}", azos_sched::current_task_name());
}

fn cmd_mem() {
    let free  = azos_mm::pmm::free_pages();
    let total = azos_mm::pmm::total_pages();
    let used  = azos_mm::pmm::used_pages();
    azos_drv_sys::kconsoleln!("[MEM] Total: {} pages ({} KiB)", total, total * 4);
    azos_drv_sys::kconsoleln!("[MEM] Used:  {} pages ({} KiB)", used,  used  * 4);
    azos_drv_sys::kconsoleln!("[MEM] Free:  {} pages ({} KiB)", free,  free  * 4);
}

/// Ticks → milliseconds, using the board's own `TIMER_FREQ` (U11-6).
///
/// The two sites this file used to hard-code `/ 10000` (`cmd_uptime`,
/// `cmd_pipeline`) assumed the QEMU riscv64 CLINT frequency (10 MHz).
/// `TIMER_FREQ` is 10 MHz on QEMU riscv64, 4 MHz on VF2, 24 MHz on K1 and
/// 1 GHz on aarch64 (`crates/drivers/base/src/platform.rs`), so the hard-coded
/// constant read 2.5x low on VF2, 2.4x low on K1 and 100x high on aarch64 —
/// the pipeline's "command age" is the operator's only signal that a motor
/// command is stale, so the error was not cosmetic. This is the same
/// division `cmd_pipeline`'s watchdog-timeout line and the "System watchdog"
/// status line already used correctly (`watchdog_timeout_ticks() /
/// (TIMER_FREQ / 1000)`); this function just gives the other two sites the
/// same divisor instead of inventing a second one.
fn ticks_to_ms(ticks: u64) -> u64 {
    ticks / (azos_drv_sys::timebase::TIMER_FREQ / 1000)
}

fn cmd_uptime() {
    let ticks = azos_drv_sys::timebase::now();
    azos_drv_sys::kconsoleln!("[UPTIME] {} ticks (~{} ms)", ticks, ticks_to_ms(ticks));
}

/// A4.next.2 — list registered drivers from the runtime registry
/// (RFC-0002). Walks every kind ID 0..256 and prints the manifest
/// of any driver currently registered.
///
/// Equivalent to `cat /sys/drivers` (which A4.next wired up via
/// procfs); this gives the same view interactively without needing
/// `cat` + an FS lookup, useful early in boot before procfs is
/// mounted or when the FS is unhealthy.
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

fn cmd_mkdir(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: mkdir <path>");
        return;
    }
    let path = args[1];
    let (parent_idx, name) = azos_fs::path_parent(path);
    if parent_idx == azos_fs::NO_IDX || name.is_empty() {
        azos_drv_sys::kconsoleln!("[FS] Invalid path");
        return;
    }
    let dir_idx = azos_fs::inode_alloc(
        azos_fs::INODE_DIR,
        azos_fs::PERM_READ | azos_fs::PERM_WRITE | azos_fs::PERM_EXEC,
    );
    if dir_idx == azos_fs::NO_IDX {
        azos_drv_sys::kconsoleln!("[FS] No free inodes");
        return;
    }
    match azos_fs::dir_add_entry(parent_idx, name, dir_idx) {
        Ok(())  => azos_drv_sys::kconsoleln!("[FS] mkdir ok"),
        Err(()) => {
            azos_fs::inode_free(dir_idx);
            azos_drv_sys::kconsoleln!("[FS] mkdir failed");
        }
    }
}

fn cmd_echo(args: &[&[u8]; MAX_ARGS], argc: usize) {
    for i in 1..argc {
        if i > 1 { azos_drv_sys::uart::putc_locked(b' '); }
        azos_drv_sys::uart::write_locked(args[i]);
    }
    azos_drv_sys::uart::putc_locked(b'\n');
}

fn cmd_disk() {
    let secs = azos_drv_virtio::virtio::blk::capacity_sectors();
    azos_drv_sys::kconsoleln!("[DISK] Capacity: {} sectors ({} MiB)", secs, secs / 2048);
}

fn cmd_ifconfig() {
    azos_net::net_info();
}

fn cmd_ping(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: ping <ip>");
        return;
    }
    match parse_ip(args[1]) {
        Some(addr) => {
            azos_drv_sys::kconsoleln!("PING {}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
            for seq in 1u32..=4 {
                let r = azos_net::net_ping(addr);
                if r == 0 {
                    azos_drv_sys::kconsoleln!("  seq={}: sent", seq);
                } else {
                    azos_drv_sys::kconsoleln!("  seq={}: no route (ARP miss)", seq);
                }
                for _ in 0..50000 { core::hint::spin_loop(); }
                azos_net::net_poll();
            }
        }
        None => azos_drv_sys::kconsoleln!("Invalid IP address"),
    }
}

fn cmd_arp() {
    azos_net::arp::dump();
}

fn cmd_gpio(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 && args[1] == b"info" {
        azos_drv_gpio::gpio::gpio_info();
    } else {
        azos_drv_sys::kconsoleln!("Usage: gpio info");
    }
}

fn cmd_pwm(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 && args[1] == b"info" {
        azos_drv_actuator::pwm::pwm_info();
    } else {
        azos_drv_sys::kconsoleln!("Usage: pwm info");
    }
}

fn cmd_i2c(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 && args[1] == b"scan" {
        let bus = if argc >= 3 { parse_u8(args[2]) } else { 0 };
        azos_drv_bus::i2c::i2c_scan(bus);
    } else if argc >= 2 && args[1] == b"info" {
        azos_drv_bus::i2c::i2c_info();
    } else {
        azos_drv_sys::kconsoleln!("Usage: i2c scan [bus] | i2c info");
    }
}

fn cmd_motor(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 && args[1] == b"info" {
        #[cfg(feature = "domain-robot")]
        azos_robot::motor_info();
        #[cfg(not(feature = "domain-robot"))]
        azos_drv_sys::kconsoleln!("[MOTOR] no motors (image built without the Robot domain)");
    } else {
        azos_drv_sys::kconsoleln!("Usage: motor info");
    }
}

/// Write text arguments (joined by spaces + newline) to a FAT32 file.
fn cmd_write(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 3 {
        azos_drv_sys::kconsoleln!("Usage: write <path> <text...>");
        return;
    }
    let path = args[1];
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(
        &mut fd_table, path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC,
    );
    if fd < 0 {
        azos_drv_sys::kconsole!("[FS] Cannot create: ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!();
        return;
    }
    for i in 2..argc {
        if i > 2 {
            azos_fs::vfs_write(&mut fd_table, fd, b" ".as_ptr(), 1);
        }
        azos_fs::vfs_write(&mut fd_table, fd, args[i].as_ptr(), args[i].len());
    }
    azos_fs::vfs_write(&mut fd_table, fd, b"\n".as_ptr(), 1);
    azos_fs::vfs_close(&mut fd_table, fd);
    azos_drv_sys::kconsoleln!("[FS] Written");
}

/// Remove a file from the FAT32 root directory.
fn cmd_rm(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: rm <path>");
        return;
    }
    let path = args[1];
    if !path.starts_with(b"/fat/") {
        azos_drv_sys::kconsoleln!("[FS] rm only supports /fat/<file> paths");
        return;
    }
    let name = &path[5..]; // strip "/fat/"
    if name.is_empty() || name.contains(&b'/') {
        azos_drv_sys::kconsoleln!("[FS] Only root-level FAT32 files supported");
        return;
    }
    match azos_fs::fat32_unlink_path(name) {
        Ok(())  => azos_drv_sys::kconsoleln!("[FS] Removed"),
        Err(()) => azos_drv_sys::kconsoleln!("[FS] Not found or cannot remove"),
    }
}

#[cfg(not(feature = "no-mmu"))]
fn cmd_exec(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: exec <path>");
        return;
    }
    let path = args[1];

    // Read the ELF from FAT32 using VFS.
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path, azos_fs::O_RDONLY);
    if fd < 0 {
        azos_drv_sys::kconsole!("[EXEC] Cannot open: ");
        azos_drv_sys::uart::write_locked(path);
        azos_drv_sys::kconsoleln!();
        return;
    }

    // Read into a static buffer (max 256 KiB — enough for small test ELFs).
    static mut ELF_BUF: [u8; 256 * 1024] = [0u8; 256 * 1024];
    let mut total = 0usize;
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(ELF_BUF) };

    loop {
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf[total..].as_mut_ptr(), 512);
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    azos_fs::vfs_close(&mut fd_table, fd);

    if total == 0 {
        azos_drv_sys::kconsoleln!("[EXEC] Empty file");
        return;
    }

    // Bind the program to its seccomp profile by the BYTES read, not by the
    // path: the SHA-256 of `buf[..total]` against the digests the build
    // generated from the exact ELFs it copies onto the image
    // (`azos_sched::seccomp::image_for_digest`). The slice hashed is the
    // slice `exec_user` loads below, from this function's own static buffer,
    // so what was checked is what runs. An image no profile is bound to is not
    // exec'd, whatever name it was opened under.
    let elf = &buf[..total];
    let digest = azos_sched::seccomp::image_digest(elf);
    let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let Some(profile) = azos_sched::seccomp::image_for_digest(&digest) else {
        azos_drv_sys::kconsoleln!(
            "[EXEC] REFUSED: {} ({} bytes, sha256 {:08x}{:08x}...) matches no seccomp image profile",
            core::str::from_utf8(path).unwrap_or("?"), total, head,
            u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]])
        );
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_EXEC_REFUSED, 1, head);
        return;
    };

    azos_drv_sys::kconsoleln!("[EXEC] Loading {} bytes...", total);
    let r = azos_sched::exec_user(elf);
    if r != 0 {
        azos_drv_sys::kconsoleln!("[EXEC] exec_user failed (bad ELF?)");
        return;
    }
    // Confine the program before its first instruction, with the profile its
    // bytes are bound to. After a successful `exec_user`, so a failed one
    // leaves nothing behind on this task; before the SRET below. The filter is
    // on this task's slot, which `exec_user` keeps, and every child the
    // program forks copies it. A filter already in force is kept, never
    // replaced (see `install_image_profile`).
    match azos_sched::seccomp::install_image_profile(profile) {
        0 => azos_drv_sys::kconsoleln!(
            "[EXEC] seccomp: {} profile installed{}",
            profile.image, if profile.audit { " (audit mode)" } else { "" }
        ),
        other => azos_drv_sys::kconsoleln!(
            "[EXEC] seccomp: a filter was already in force (rc={}); kept", other
        ),
    }
    // The shell is a kernel task — it cannot rely on the ecall/SRET mechanism.
    // Instead, we take the prepared hand-off and SRET to U-mode directly
    // (K-C21: it lives on THIS task's own slot, and the taker has already
    // installed the new satp — sret_to_user just re-writes the same value).
    if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
        azos_drv_sys::kconsoleln!("[EXEC] SRET to user-space entry={:#x}", ctx.entry);
        unsafe {
            azos_sched::sret_to_user(
                ctx.entry   as usize,
                ctx.user_sp as usize,
                ctx.satp    as usize,
            );
        }
        // sret_to_user() is -> ! — unreachable
    }
}

/// Path handoff from `cmd_spawn` to `spawn_task_entry`, guarded so a second
/// `spawn` cannot overwrite the path while the previous one is still
/// copying it onto its own task's stack. Held only across that copy — a
/// few bytes, bounded — never across the file read or `exec_user` below.
#[cfg(not(feature = "no-mmu"))]
static SPAWN_PATH: azos_sync::pi_mutex::PiMutex<[u8; MAX_LINE]> =
    azos_sync::pi_mutex::PiMutex::new([0u8; MAX_LINE]);
#[cfg(not(feature = "no-mmu"))]
static SPAWN_PATH_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// `SPAWN_ELF_BUF`'s mutex — held from "start reading the file" through
/// "`exec_user` has copied what it needs out of the slice", i.e. for the
/// whole body of `spawn_task_entry` below the path handoff. A second
/// `spawn` started while one is already loading blocks here rather than
/// racing `ELF_BUF`-style unguarded statics like `cmd_exec`'s (safe there
/// only because `exec` consumes its own task and nothing else touches that
/// buffer).
#[cfg(not(feature = "no-mmu"))]
static SPAWN_ELF_LOCK: azos_sync::pi_mutex::PiMutex<()> =
    azos_sync::pi_mutex::PiMutex::new(());
#[cfg(not(feature = "no-mmu"))]
static mut SPAWN_ELF_BUF: [u8; 256 * 1024] = [0u8; 256 * 1024];

/// `spawn <path>` — like `exec`, but on a NEW kernel task, so the console
/// stays live for the next command instead of becoming the program (U11 §3
/// (2): "`exec` stops consuming the console").
///
/// Mechanism: copies `path` into `SPAWN_PATH` and calls
/// `azos_sched::task_create`, which starts an independent task running
/// [`spawn_task_entry`] — the exact open/read/seccomp-bind/`exec_user`/
/// `sret_to_user` sequence [`cmd_exec`] runs on ITS OWN task, just run on
/// the NEW one instead. `cmd_spawn` returns as soon as the task is created;
/// it does not wait for the program to load, let alone run.
#[cfg(not(feature = "no-mmu"))]
fn cmd_spawn(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: spawn <path>");
        return;
    }
    let path = args[1];
    if path.len() >= MAX_LINE {
        azos_drv_sys::kconsoleln!("[SPAWN] path too long");
        return;
    }
    {
        let mut guard = SPAWN_PATH.lock();
        guard[..path.len()].copy_from_slice(path);
        SPAWN_PATH_LEN.store(path.len(), core::sync::atomic::Ordering::Release);
    }
    let tid = azos_sched::task_create(
        "spawn", spawn_task_entry, 0, azos_sched::DEFAULT_PRIORITY);
    azos_drv_sys::kconsoleln!("[SPAWN] tid={} loading {}",
        tid, core::str::from_utf8(path).unwrap_or("?"));
}

/// Entry point for the task `cmd_spawn` creates. Runs to completion on ITS
/// OWN task/stack/slot — never on the shell's — so `sret_to_user` at the end
/// replaces only this task, exactly as it replaces the shell task at the end
/// of `cmd_exec`.
#[cfg(not(feature = "no-mmu"))]
fn spawn_task_entry(_arg: usize) {
    let mut path_buf = [0u8; MAX_LINE];
    let path_len = {
        let guard = SPAWN_PATH.lock();
        let len = SPAWN_PATH_LEN.load(core::sync::atomic::Ordering::Acquire);
        path_buf[..len].copy_from_slice(&guard[..len]);
        len
    };
    let path = &path_buf[..path_len];

    let _elf_guard = SPAWN_ELF_LOCK.lock();
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path, azos_fs::O_RDONLY);
    if fd < 0 {
        azos_drv_sys::kconsoleln!("[SPAWN] cannot open {}", core::str::from_utf8(path).unwrap_or("?"));
        return;
    }
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SPAWN_ELF_BUF) };
    let mut total = 0usize;
    loop {
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf[total..].as_mut_ptr(), 512);
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    azos_fs::vfs_close(&mut fd_table, fd);
    if total == 0 {
        azos_drv_sys::kconsoleln!("[SPAWN] empty file");
        return;
    }

    let elf = &buf[..total];
    let digest = azos_sched::seccomp::image_digest(elf);
    let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let Some(profile) = azos_sched::seccomp::image_for_digest(&digest) else {
        azos_drv_sys::kconsoleln!(
            "[SPAWN] REFUSED: ({} bytes, sha256 {:08x}...) matches no seccomp image profile",
            total, head);
        // `action_code` 3: site numbering for `SAFETY_EXEC_REFUSED` is
        // 0 = autorun (`kernel/src/tasks/loader.rs`), 1 = shell `exec` (`cmd_exec`
        // above), 2 = ring-3 `SYS_EXEC`/`SYS_EXECPATH`
        // (`crates/core/syscall/src/handlers.rs::EXEC_REFUSED_ACTION_RING3`) — 3
        // is free and this is a new site, not a collision.
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_EXEC_REFUSED, 3, head);
        return;
    };

    azos_drv_sys::kconsoleln!("[SPAWN] loading {} bytes...", total);
    let r = azos_sched::exec_user(elf);
    if r != 0 {
        azos_drv_sys::kconsoleln!("[SPAWN] exec_user failed (bad ELF?)");
        return;
    }
    match azos_sched::seccomp::install_image_profile(profile) {
        0 => azos_drv_sys::kconsoleln!("[SPAWN] seccomp: {} profile installed", profile.image),
        other => azos_drv_sys::kconsoleln!("[SPAWN] seccomp: kept existing filter (rc={})", other),
    }
    if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
        azos_drv_sys::kconsoleln!("[SPAWN] SRET to user-space entry={:#x}", ctx.entry);
        unsafe {
            azos_sched::sret_to_user(ctx.entry as usize, ctx.user_sp as usize, ctx.satp as usize);
        }
        // sret_to_user() is -> ! — unreachable
    }
}

/// RVV 1.0 interactive benchmark — runs scalar vs RVV dot product + matmul.
///
/// When built without `--features rvv`, prints a hint and returns immediately.
/// Timer interrupt is disabled during RVV operations (vector context save is
/// a Phase 12 TODO; preemption mid-RVV would corrupt vector registers).
fn cmd_rvv() {
    #[cfg(not(feature = "rvv"))]
    {
        azos_drv_sys::kconsoleln!("[RVV] not available — build with: make qemu-rvv");
        return;
    }

    #[cfg(feature = "rvv")]
    {
        use azos_arch::{csr, rvv};

        if !rvv::usable() {
            azos_drv_sys::kconsoleln!("[RVV] not available — this hart has no V (RV_V = probe)");
            return;
        }
        azos_drv_sys::kconsoleln!("[RVV] RISC-V Vector Extension 1.0 benchmark");
        azos_drv_sys::kconsoleln!("[RVV] VLEN=128, LMUL=m4, f32 precision");
        azos_drv_sys::kconsoleln!();

        // Disable timer IRQ — prevent vector register corruption during bench.
        let saved_sie = csr::read_sie();
        csr::write_sie(saved_sie & !csr::SIE_STIE);

        // ── Dot product: 256 f32 ────────────────────────────────────────────
        const N: usize = 256;
        let mut a = [0.0f32; N];
        let mut b = [0.0f32; N];
        for i in 0..N {
            a[i] = (i as f32) * 0.001;
            b[i] = 1.0_f32;
        }

        let (sc, vc, _, _) = rvv::bench_dot(&a, &b);
        let sp = if vc > 0 { sc * 100 / vc } else { 0 };
        azos_drv_sys::kconsoleln!("[RVV] dot({} f32):", N);
        azos_drv_sys::kconsoleln!("[RVV]   scalar : {} cycles", sc);
        azos_drv_sys::kconsoleln!("[RVV]   rvv    : {} cycles", vc);
        azos_drv_sys::kconsoleln!("[RVV]   speedup: {}.{}x", sp / 100, sp % 100);
        azos_drv_sys::kconsoleln!();

        // ── Matmul: 8×8×8 f32 ──────────────────────────────────────────────
        const MM: usize = 8;
        const KK: usize = 8;
        const NN: usize = 8;
        let mut ma   = [0.0f32; MM * KK];
        let mut mb   = [0.0f32; KK * NN];
        let mut mc_s = [0.0f32; MM * NN];
        let mut mc_v = [0.0f32; MM * NN];
        for i in 0..MM * KK { ma[i] = (i as f32) * 0.001; }
        for i in 0..KK * NN { mb[i] = (i as f32) * 0.001; }

        let (ms, mv) = rvv::bench_matmul(&mut mc_s, &mut mc_v, &ma, &mb, MM, KK, NN);
        let msp = if mv > 0 { ms * 100 / mv } else { 0 };
        azos_drv_sys::kconsoleln!("[RVV] matmul({}x{}x{} f32):", MM, KK, NN);
        azos_drv_sys::kconsoleln!("[RVV]   scalar : {} cycles", ms);
        azos_drv_sys::kconsoleln!("[RVV]   rvv    : {} cycles", mv);
        azos_drv_sys::kconsoleln!("[RVV]   speedup: {}.{}x", msp / 100, msp % 100);

        csr::write_sie(saved_sie);
        azos_drv_sys::kconsoleln!();
        azos_drv_sys::kconsoleln!("[RVV] done");
    }
}

/// Phase 13: print the motor command pipeline's status (last command, its
/// age, the RT watchdog).
#[cfg(feature = "domain-robot")]
fn cmd_pipeline() {
    let cmd   = azos_robot::motor_cmd_read();
    let age   = azos_robot::motor_cmd_age_ticks();
    let fired = azos_robot::motor_watchdog_fired();

    azos_drv_sys::kconsoleln!("[PIPELINE] ========================================");
    azos_drv_sys::kconsoleln!("[PIPELINE]  Phase 13: Robot pipeline status");
    azos_drv_sys::kconsoleln!("[PIPELINE] ========================================");

    if !azos_robot::CH_MOTOR_CMD.is_valid() {
        azos_drv_sys::kconsoleln!("[PIPELINE] No command published yet");
    } else {
        azos_drv_sys::kconsoleln!("[PIPELINE] Last cmd: L={} R={}", cmd.speed_l, cmd.speed_r);
        // U11-6: board-correct conversion (see `ticks_to_ms`), not a QEMU-only constant.
        let age_ms = ticks_to_ms(age);
        azos_drv_sys::kconsoleln!("[PIPELINE] Command age: {} ticks (~{} ms)", age, age_ms);
    }

    if fired {
        azos_drv_sys::kconsoleln!("[PIPELINE] Watchdog: FIRED (safe stop active)");
    } else {
        let timeout_ms = azos_robot::watchdog_timeout_ticks() / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
        azos_drv_sys::kconsoleln!("[PIPELINE] Watchdog: OK (timeout={} ms)", timeout_ms);
    }

    azos_drv_sys::kconsoleln!("[PIPELINE] ---- Motor state ----");
    azos_robot::motor_info();
    azos_drv_sys::kconsoleln!("[PIPELINE] ========================================");
}

// ── Integer formatting helpers (for CSV trajectory flush) ────────────────────

/// Write decimal digits of `v` into `buf[pos..]`. Returns new position.
#[cfg(feature = "domain-robot")]
fn write_u64(buf: &mut [u8], pos: usize, v: u64) -> usize {
    if pos >= buf.len() { return pos; }
    if v == 0 {
        buf[pos] = b'0';
        return pos + 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = v;
    let mut len = 0usize;
    while n > 0 && len < 20 {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    tmp[..len].reverse();
    let end = (pos + len).min(buf.len());
    buf[pos..end].copy_from_slice(&tmp[..end - pos]);
    end
}

#[cfg(feature = "domain-robot")]
fn write_i64(buf: &mut [u8], mut pos: usize, v: i64) -> usize {
    if pos >= buf.len() { return pos; }
    if v < 0 {
        buf[pos] = b'-';
        pos += 1;
        // Avoid i64::MIN negation overflow: use wrapping_neg cast to u64.
        write_u64(buf, pos, (v as u64).wrapping_neg())
    } else {
        write_u64(buf, pos, v as u64)
    }
}

#[cfg(feature = "domain-robot")]
fn write_i32(buf: &mut [u8], pos: usize, v: i32) -> usize {
    write_i64(buf, pos, v as i64)
}

// ── Phase 17 commands ─────────────────────────────────────────────────────────

/// Phase 17: print dead-reckoning odometry state.
#[cfg(feature = "domain-robot")]
fn cmd_odom() {
    let (tl, tr)             = azos_robot::encoder_read();
    let (dist_mm, hdg_cdeg)  = azos_robot::odom_get();

    // Convert heading_cdeg to deg + centideg remainder for display.
    let neg = hdg_cdeg < 0;
    let abs_cdeg = if neg { hdg_cdeg.wrapping_neg() } else { hdg_cdeg };
    let deg  = abs_cdeg / 100;
    let frac = abs_cdeg % 100;

    azos_drv_sys::kconsoleln!("[ODOM] ========================================");
    azos_drv_sys::kconsoleln!("[ODOM]  Phase 17: Dead-reckoning odometry");
    azos_drv_sys::kconsoleln!("[ODOM] ========================================");
    azos_drv_sys::kconsoleln!("[ODOM]  Encoder ticks : L={}  R={}", tl, tr);
    azos_drv_sys::kconsoleln!("[ODOM]  Total distance: {} mm", dist_mm);
    if neg {
        azos_drv_sys::kconsoleln!("[ODOM]  Heading change: -{}.{:02} deg", deg, frac);
    } else {
        azos_drv_sys::kconsoleln!("[ODOM]  Heading change: +{}.{:02} deg", deg, frac);
    }
    azos_drv_sys::kconsoleln!("[ODOM] ========================================");
}

/// Phase 17: trajectory ring buffer command.
///
/// Subcommands:
///   traj status    — show buffer fill level.
///   traj dump [N]  — print last N points to UART (default: all).
///   traj flush     — write all points as CSV to /fat/TRAJ.CSV.
///   traj reset     — clear the ring buffer.
#[cfg(feature = "domain-robot")]
fn cmd_traj(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub = if argc >= 2 { args[1] } else { b"status" };

    if sub == b"status" {
        let n = azos_robot::traj_len();
        azos_drv_sys::kconsoleln!("[TRAJ] Ring buffer: {}/{} points recorded",
            n, azos_robot::TRAJ_CAP);
        return;
    }

    if sub == b"reset" {
        azos_robot::traj_reset();
        azos_drv_sys::kconsoleln!("[TRAJ] Ring buffer cleared");
        return;
    }

    if sub == b"dump" {
        let total = azos_robot::traj_len();
        let want  = if argc >= 3 { parse_u8(args[2]) as usize } else { total };
        let start = if want < total { total - want } else { 0 };
        azos_drv_sys::kconsoleln!("[TRAJ] ts_ms | spd_L | spd_R | class | dist_mm | hdg_cdeg");
        for i in start..total {
            if let Some(p) = azos_robot::traj_get(i) {
                azos_drv_sys::kconsoleln!("[TRAJ] {} {} {} {} {} {}",
                    p.timestamp_ms, p.speed_l, p.speed_r,
                    p.ml_class as u32, p.dist_mm, p.heading_cdeg);
            }
        }
        return;
    }

    if sub == b"flush" {
        cmd_traj_flush();
        return;
    }

    azos_drv_sys::kconsoleln!("Usage: traj status | dump [N] | flush | reset");
}

/// Write trajectory ring buffer to /fat/TRAJ.CSV.
#[cfg(feature = "domain-robot")]
fn cmd_traj_flush() {
    static mut TRAJ_CSV: [u8; 8192] = [0u8; 8192];
    let buf = unsafe { &mut *(&raw mut TRAJ_CSV) };

    let n = azos_robot::traj_len();
    if n == 0 {
        azos_drv_sys::kconsoleln!("[TRAJ] No points to flush");
        return;
    }

    // Build CSV content.
    let header = b"timestamp_ms,speed_l,speed_r,ml_class,dist_mm,heading_cdeg\n";
    let mut pos = 0usize;
    if pos + header.len() <= buf.len() {
        buf[pos..pos + header.len()].copy_from_slice(header);
        pos += header.len();
    }

    let mut written = 0usize;
    for i in 0..n {
        if let Some(p) = azos_robot::traj_get(i) {
            if pos + 100 > buf.len() { break; } // buffer safety margin
            pos = write_u64(buf, pos, p.timestamp_ms); buf[pos] = b','; pos += 1;
            pos = write_i32(buf, pos, p.speed_l);      buf[pos] = b','; pos += 1;
            pos = write_i32(buf, pos, p.speed_r);      buf[pos] = b','; pos += 1;
            buf[pos] = b'0' + (p.ml_class % 10);      buf[pos + 1] = b','; pos += 2;
            pos = write_i64(buf, pos, p.dist_mm);      buf[pos] = b','; pos += 1;
            pos = write_i64(buf, pos, p.heading_cdeg); buf[pos] = b'\n'; pos += 1;
            written += 1;
        }
    }

    // Write to FAT32.
    let path = b"/fat/TRAJ.CSV";
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
    if fd < 0 {
        azos_drv_sys::kconsoleln!("[TRAJ] Cannot create /fat/TRAJ.CSV (mount FAT32 first)");
        return;
    }
    azos_fs::vfs_write(&mut fd_table, fd, buf.as_ptr(), pos);
    azos_fs::vfs_close(&mut fd_table, fd);
    azos_drv_sys::kconsoleln!("[TRAJ] Flushed {} points ({} bytes) → /fat/TRAJ.CSV",
        written, pos);
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
    meta.active_slot = target_slot;
    meta.boot_count = 0;
    // The slot's previous occupant may have been recorded in `bad_slots` by
    // the boot gate. That verdict was about THOSE bytes, which no longer
    // exist: this install has just written a different image over them, and on
    // an enforced build it got here only by verifying. Leaving the bit set
    // would make the slot permanently unselectable by any rollback — a
    // one-time failure turning into a dead slot nobody can revive.
    meta.clear_slot_bad(target_slot);
    // `fw_version_a/b` (DISPLAY ONLY, sender-reported) vs
    // `authenticated_fw_version_a/b` (what `ota_mark_boot_good_pure` reads
    // to advance the anti-rollback floor — U09-4/U11-4). Only a `Verified`
    // install ever sets the authenticated field; an `Unverified`/dev
    // install leaves it as whatever the slot last verified to (0 if never),
    // so it can NEVER pin the floor no matter what `header.fw_version` claims.
    if target_slot == azos_ota::SLOT_A {
        meta.fw_version_a = header.fw_version;
        if trust == azos_ota::BootTrust::Verified {
            meta.authenticated_fw_version_a = auth_fw_version;
        }
        meta.image_size_a = header.image_size;
        meta.image_crc_a  = header.image_crc32;
    } else {
        meta.fw_version_b = header.fw_version;
        if trust == azos_ota::BootTrust::Verified {
            meta.authenticated_fw_version_b = auth_fw_version;
        }
        meta.image_size_b = header.image_size;
        meta.image_crc_b  = header.image_crc32;
    }
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
        let satp = azos_arch::csr::read_satp();
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
    #[cfg(feature = "domain-robot")]
    let wdt_fired = azos_robot::motor_watchdog_fired();
    #[cfg(feature = "domain-robot")]
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

/// `shutdown` — orderly power-off. Needs the console's `Cap<Power>` WRITE on
/// every build (`authority_policy::CMD_SHUTDOWN`), as ring 3's `power
/// shutdown` does; refused, it records the denial and returns to the prompt.
fn cmd_shutdown() {
    if !authority::check_power_row(authority_policy::CMD_SHUTDOWN) {
        return;
    }
    azos_drv_sys::kconsoleln!("[SHELL] System shutdown...");
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
    azos_drv_sys::kconsoleln!("[SHELL] System reboot...");
    let _ = azos_ota::ota_void_unconfirmed_boot();
    azos_drv_sys::uart::console_flush_for_reboot();
    use azos_arch::Boot;
    azos_arch::ARCH.reboot()
}

// ── Parsing utilities ─────────────────────────────────────────────────────────

fn parse_ip(s: &[u8]) -> Option<[u8; 4]> {
    let mut result = [0u8; 4];
    let mut octet  = 0u32;
    let mut idx    = 0usize;
    let mut digits = 0usize;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            octet  = octet * 10 + (b - b'0') as u32;
            digits += 1;
            if octet > 255 { return None; }
        } else if b == b'.' {
            if digits == 0 || idx >= 3 { return None; }
            result[idx] = octet as u8;
            idx   += 1;
            octet  = 0;
            digits = 0;
        } else {
            return None;
        }
    }
    if idx == 3 && digits > 0 {
        result[3] = octet as u8;
        Some(result)
    } else {
        None
    }
}

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

fn parse_u8(s: &[u8]) -> u8 { parse_u32_sat(s).min(255) as u8 }

fn parse_u16(s: &[u8]) -> u16 { parse_u32_sat(s).min(65535) as u16 }

fn parse_u32(s: &[u8]) -> u32 { parse_u32_sat(s) }

/// TCP echo server: listen on given port, echo back received data.
/// Usage: tcpecho <port>
fn cmd_tcpecho(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc < 2 {
        azos_drv_sys::kconsoleln!("Usage: tcpecho <port>");
        return;
    }
    let port = parse_u16(args[1]);
    if port == 0 {
        azos_drv_sys::kconsoleln!("[NET] Invalid port");
        return;
    }

    azos_drv_sys::kconsoleln!("[NET] TCP echo server on port {} (Ctrl+C to stop)", port);

    // Create and bind listener socket
    let listen_fd = azos_net::socket_create(
        azos_net::AF_INET, azos_net::SOCK_STREAM, 0,
    );
    if listen_fd < 0 {
        azos_drv_sys::kconsoleln!("[NET] socket_create failed");
        return;
    }

    let mut addr = azos_net::SockAddr::new();
    addr.family = azos_net::AF_INET as u16;
    addr.port   = port;

    if azos_net::socket_bind(listen_fd, &addr) < 0 {
        azos_drv_sys::kconsoleln!("[NET] bind failed");
        azos_net::socket_close(listen_fd);
        return;
    }
    if azos_net::socket_listen_bound(listen_fd) < 0 {
        azos_drv_sys::kconsoleln!("[NET] listen failed");
        azos_net::socket_close(listen_fd);
        return;
    }

    azos_drv_sys::kconsoleln!("[NET] Waiting for connection...");

    // Poll until a client connects. K-C27: sleep between accept polls (see
    // the OTA listener) — an idle listener must not spin at shell priority.
    let client_fd = loop {
        azos_net::net_poll();
        let r = azos_net::socket_accept(listen_fd);
        if r >= 0 { break r; }
        listen_poll_sleep();
    };

    azos_drv_sys::kconsoleln!("[NET] Client connected (fd={})", client_fd);

    // Echo loop: receive data and send it back
    let mut buf = [0u8; 256];
    loop {
        azos_net::net_poll();
        let n = azos_net::socket_recv(client_fd, &mut buf);
        if n > 0 {
            let sent = azos_net::socket_send(client_fd, &buf[..n as usize]);
            azos_drv_sys::kconsoleln!("[NET] echoed {} bytes (sent={})", n, sent);
        } else if n < 0 {
            azos_drv_sys::kconsoleln!("[NET] Connection closed");
            break;
        }
        // K-C27: interactive echo — 10 ms poll granularity is fine, and an
        // idle connection must not spin at shell priority.
        listen_poll_sleep();
    }

    azos_net::socket_close(client_fd);
    azos_net::socket_close(listen_fd);
    azos_drv_sys::kconsoleln!("[NET] Echo server done");
}

// ── Phase 18 + G2: Persistent configuration ──────────────────────────────────

/// Push config atomics to every subsystem (net, sched, behavior, encoder, wdt).
/// Called after `cfg_apply()` from `config set`, `config load`, or `config defaults`.
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
    #[cfg(feature = "domain-robot")]
    azos_behavior::layer_set_enabled(1,
        azos_config::BEHAVIOR_L1_ENABLED.load(Ordering::Relaxed));
    #[cfg(feature = "domain-robot")]
    azos_behavior::layer_set_enabled(2,
        azos_config::BEHAVIOR_L2_ENABLED.load(Ordering::Relaxed));
    #[cfg(feature = "domain-robot")]
    azos_behavior::layer_set_enabled(3,
        azos_config::BEHAVIOR_L3_ENABLED.load(Ordering::Relaxed));

    // Behavior VLA server
    #[cfg(feature = "domain-robot")]
    let bport = azos_config::BEHAVIOR_SERVER_PORT.load(Ordering::Relaxed);
    #[cfg(feature = "domain-robot")]
    if bport > 0 {
        let bip = azos_config::behavior_server_ip_bytes();
        azos_behavior::remote_configure(bip, bport as u16);
    }

    // Encoder physical params
    #[cfg(feature = "domain-robot")]
    azos_robot::set_ticks_per_m(
        azos_config::CFG_TICKS_PER_M.load(Ordering::Relaxed));
    #[cfg(feature = "domain-robot")]
    azos_robot::set_wheel_base_mm(
        azos_config::CFG_WHEEL_BASE_MM.load(Ordering::Relaxed));

    // Watchdog (note: wdt_init re-programs the hardware timer)
    azos_drv_sys::wdt::wdt_init(
        azos_config::CFG_WATCHDOG_MS.load(Ordering::Relaxed));
}

/// `config [list | get <key> | set <key> <val> | save | load | defaults | export]`
///
/// Manages the in-memory key-value config store and persists it to
/// `/fat/CONFIG.INI` on the FAT32 volume.
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
        azos_drv_sys::kconsoleln!("[CFG] saved {} bytes to /fat/CONFIG.INI", written);
        return;
    }

    if sub == b"load" {
        static mut LOAD_BUF: [u8; 1024] = [0u8; 1024];
        let buf = unsafe { &mut *(&raw mut LOAD_BUF) };
        let mut fd_table = azos_fs::ScratchFds::new();
        let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/CONFIG.INI",
                                        azos_fs::O_RDONLY);
        if fd < 0 {
            azos_drv_sys::kconsoleln!("[CFG] /fat/CONFIG.INI not found (mount FAT32 first)");
            return;
        }
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
        azos_fs::vfs_close(&mut fd_table, fd);
        if n > 0 {
            match azos_config::cfg_load(&buf[..n as usize]) {
                Ok(()) => {
                    azos_config::cfg_apply();
                    apply_config_to_subsystems();
                    azos_drv_sys::kconsoleln!("[CFG] loaded {} entries",
                        azos_config::cfg_count());
                }
                Err(e) => {
                    azos_drv_sys::kconsoleln!("[CFG] /fat/CONFIG.INI repeats the key '{}' — \
                        refused, running configuration unchanged",
                        core::str::from_utf8(e.key()).unwrap_or("?"));
                }
            }
        } else {
            azos_drv_sys::kconsoleln!("[CFG] empty or read error");
        }
        return;
    }

    // Phase G2: reset to factory defaults (in-memory only, use `config save` to persist).
    if sub == b"defaults" {
        azos_config::cfg_defaults();
        azos_config::cfg_apply();
        apply_config_to_subsystems();
        azos_drv_sys::kconsoleln!("[CFG] factory defaults applied ({} entries)",
            azos_config::cfg_count());
        return;
    }

    // Phase G2: export all config as KEY=VALUE over UART (copy/paste backup).
    if sub == b"export" {
        static mut EXPORT_BUF: [u8; 1024] = [0u8; 1024];
        let buf = unsafe { &mut *(&raw mut EXPORT_BUF) };
        let n = azos_config::cfg_serialize(buf);
        azos_drv_sys::kconsoleln!("# AzOS CONFIG.INI ({} bytes)", n);
        azos_drv_sys::uart::write_locked(&buf[..n]);
        return;
    }

    azos_drv_sys::kconsoleln!(
        "Usage: config [list|get <key>|set <k> <v>|save|load|defaults|export]");
}

// ── Phase G1: Behavior Engine + VLA Protocol ─────────────────────────────────

#[cfg(feature = "domain-robot")]
fn cmd_behavior(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"status" };

    if sub == b"status" {
        azos_drv_sys::kconsoleln!("[BEHAVIOR] Subsumption layers:");
        let statuses = azos_behavior::layer_statuses();
        for ls in &statuses {
            let mark = if ls.winning { " <-- WINNING" } else { "" };
            azos_drv_sys::kconsoleln!("  L{}: {:16} enabled={} {}",
                ls.layer, ls.name,
                ls.enabled as u8, mark);
        }

        // Remote info
        let ri = azos_behavior::remote_info();
        if ri.enabled {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Remote VLA: {}.{}.{}.{}:{} connected={} tx={} rx={}",
                ri.server_ip[0], ri.server_ip[1], ri.server_ip[2], ri.server_ip[3],
                ri.server_port, ri.connected as u8,
                ri.packets_sent, ri.packets_recv);
        } else {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Remote VLA: disabled");
        }

        // Current goal
        let goal = azos_behavior::current_goal();
        if goal.valid {
            azos_drv_sys::kconsole!("[BEHAVIOR] Goal #{}: ", goal.goal_id);
            azos_drv_sys::uart::write_locked(&goal.text[..goal.text_len as usize]);
            azos_drv_sys::kconsoleln!();
        } else {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Goal: (none)");
        }
        return;
    }

    if sub == b"enable" {
        if argc < 3 {
            azos_drv_sys::kconsoleln!("Usage: behavior enable <layer>");
            return;
        }
        let layer = parse_u32(args[2]) as usize;
        if layer == 0 {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Layer 0 cannot be disabled");
            return;
        }
        if layer >= azos_behavior::NUM_LAYERS {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Invalid layer (0-3)");
            return;
        }
        families::behavior(azos_abi::families::BEHAVIOR_OP_ENABLE, layer as u64);
        azos_drv_sys::kconsoleln!("[BEHAVIOR] L{} enabled", layer);
        return;
    }

    if sub == b"disable" {
        if argc < 3 {
            azos_drv_sys::kconsoleln!("Usage: behavior disable <layer>");
            return;
        }
        let layer = parse_u32(args[2]) as usize;
        if layer == 0 {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Layer 0 cannot be disabled");
            return;
        }
        if layer >= azos_behavior::NUM_LAYERS {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Invalid layer (0-3)");
            return;
        }
        if !authority::check_power_row(authority_policy::CMD_BEHAVIOR_DISABLE) {
            return;
        }
        families::behavior(azos_abi::families::BEHAVIOR_OP_DISABLE, layer as u64);
        azos_drv_sys::kconsoleln!("[BEHAVIOR] L{} disabled", layer);
        return;
    }

    if sub == b"remote" {
        if argc < 4 {
            azos_drv_sys::kconsoleln!("Usage: behavior remote <ip> <port>");
            return;
        }
        if let Some(ip) = parse_ip(args[2]) {
            let port = parse_u32(args[3]) as u16;
            azos_behavior::remote_configure(ip, port);
            azos_drv_sys::kconsoleln!("[BEHAVIOR] VLA server: {}.{}.{}.{}:{}",
                ip[0], ip[1], ip[2], ip[3], port);
        } else {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] Invalid IP format (a.b.c.d)");
        }
        return;
    }

    if sub == b"goal" {
        let goal = azos_behavior::current_goal();
        if goal.valid {
            azos_drv_sys::kconsole!("[BEHAVIOR] Goal #{}: ", goal.goal_id);
            azos_drv_sys::uart::write_locked(&goal.text[..goal.text_len as usize]);
            azos_drv_sys::kconsoleln!();
        } else {
            azos_drv_sys::kconsoleln!("[BEHAVIOR] No active goal from VLA server");
        }
        return;
    }

    azos_drv_sys::kconsoleln!("Usage: behavior [status|enable <n>|disable <n>|remote <ip> <port>|goal]");
}

// ── Phase D: PMP + WDT + fuzz commands ────────────────────────────────────────

/// Show the AzOS PMP memory-protection policy (informational; M-mode only to enforce).
#[cfg(target_arch = "riscv64")]
fn cmd_pmp() {
    use azos_arch::pmp;
    // Use platform kernel-load address as firmware_end; PMM watermark as proxy for heap.
    let fw_end    = azos_drv_base::platform::hw::KERNEL_LOAD;
    let heap_mark = azos_mm::pmm::next_free_addr();
    let regions   = pmp::pmp_regions(fw_end, heap_mark, heap_mark, 4 * 1024 * 1024);
    azos_drv_sys::kconsoleln!("[PMP] Memory-protection policy ({} TOR regions):", pmp::N_PMP_REGIONS);
    azos_drv_sys::kconsoleln!("[PMP]   Note: CSRs are M-mode only; enforce from boot stub.");
    for r in &regions {
        azos_drv_sys::kconsoleln!("[PMP]   {:20}  base={:#010x}  size={:#010x}  {}{}{}",
            r.name,
            r.base, r.size,
            if r.perm.r { "R" } else { "-" },
            if r.perm.w { "W" } else { "-" },
            if r.perm.x { "X" } else { "-" });
    }
}

/// aarch64: PMP (Physical Memory Protection) is a RISC-V M-mode concept
/// with no ARMv8 equivalent — reported honestly rather than printing a
/// RISC-V-shaped region table that names no real hardware on this ISA.
#[cfg(not(target_arch = "riscv64"))]
fn cmd_pmp() {
    azos_drv_sys::kconsoleln!(
        "[PMP] Not applicable on this ISA — PMP is RISC-V-only (ARMv8 memory \
         protection is MMU/EL-based, not modeled by this command)."
    );
}

/// Show hardware watchdog status.
fn cmd_wdt() {
    use azos_drv_sys::wdt;
    if wdt::wdt_has_hardware() {
        azos_drv_sys::kconsoleln!("[WDT] Hardware WDT present (DesignWare)");
        azos_drv_sys::kconsoleln!("[WDT] Counter = {}", wdt::wdt_counter());
        // U11 §4 contradiction: this used to say "~1 ms" unconditionally.
        // `feed_from_timer_tick` runs at the SCHEDULER tick, not a fixed
        // 1 kHz clock; `SCHED_HZ` defaults to 100 (`crates/drivers/irqchip/src/
        // clint.rs`) which is 10 ms/tick, and CONFIG.INI can change it
        // (`sched_hz set`). Computed from the live config, not restated.
        let hz = azos_config::cfg_get_u32(b"sched_hz", 100).max(1);
        azos_drv_sys::kconsoleln!(
            "[WDT] Kick is called every timer tick (~{} ms, sched_hz={})",
            1000 / hz, hz);
    } else {
        azos_drv_sys::kconsoleln!("[WDT] No hardware WDT (QEMU) — software watchdog only");
        azos_drv_sys::kconsoleln!("[WDT] Software WDT: sys-wdt task checks canaries + timer");
    }
}

/// WCET report and jitter statistics (F16).
/// `bench [subsystem|all] [iters]` — run synthetic kernel microbenches.
///
/// Each subsystem emits one `[BENCH-RES] <subsystem>.<name> iters=N
/// min_cycles=… max_cycles=… avg_cycles=… total_cycles=…` line per
/// microbench.  The bench harness parses these into the bench JSON.
///
/// Defaults: `bench all` with `iters=1000`.  Override iters with the
/// second arg, e.g. `bench ipc 100` or `bench all 5000`.
#[cfg(feature = "domain-robot")]
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
        b"auth"   => azos_bench::auth::run(iters),
        _         => {
            azos_drv_sys::kconsoleln!(
                "[BENCH] unknown subsystem; valid: all ipc mm sched net fs crypto auth",
            );
            0
        }
    };
    let _ = emitted;
}

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

/// Basic memory write+read fuzz test over a stack buffer.
fn cmd_fuzz() {
    const N: usize = 256;
    let mut buf = [0u32; N];
    let magic: u32 = 0xCAFE_BEEF;
    for (i, v) in buf.iter_mut().enumerate() {
        *v = magic ^ (i as u32);
    }
    let mut ok = 0usize;
    for (i, v) in buf.iter().enumerate() {
        if *v == magic ^ (i as u32) { ok += 1; }
    }
    azos_drv_sys::kconsoleln!("[FUZZ] Stack memory test: {}/{} cells correct", ok, N);
    if ok == N {
        azos_drv_sys::kconsoleln!("[FUZZ] PASS");
    } else {
        azos_drv_sys::kconsoleln!("[FUZZ] FAIL ({} errors)", N - ok);
    }
}

// ── Phase E1: Scheduler Hz ────────────────────────────────────────────────────

/// `sched_hz [<hz>]` — show or set the scheduler tick rate.
fn cmd_sched_hz(args: &[&[u8]; MAX_ARGS], argc: usize) {
    if argc >= 2 {
        let hz = parse_u32(args[1]) as u64;
        if hz >= 10 && hz <= 10_000 {
            if !authority::check_power_row(authority_policy::CMD_SCHED_HZ_SET) {
                return;
            }
            azos_drv_sys::timebase::sched_hz_set(hz);
            azos_drv_sys::kconsoleln!("[SCHED] Scheduler rate set to {} Hz", hz);
        } else {
            azos_drv_sys::kconsoleln!("[SCHED] Invalid Hz (range 10..10000)");
        }
    } else {
        let hz = azos_drv_sys::timebase::sched_hz_get();
        azos_drv_sys::kconsoleln!("[SCHED] Scheduler: {} Hz (TIMER_FREQ={})",
            hz, azos_drv_sys::timebase::TIMER_FREQ);
    }
}

// ── Phase E2: IMU ─────────────────────────────────────────────────────────────

/// `imu [info|read]` — MPU-6050 IMU sensor.
#[cfg(feature = "domain-robot")]
fn cmd_imu(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"read" };

    if sub == b"info" {
        azos_imu::imu_info();
    } else if sub == b"read" {
        match azos_imu::imu_read_scaled() {
            Some(d) => {
                azos_drv_sys::kconsoleln!(
                    "[IMU] Accel: X={} Y={} Z={} mg",
                    d.accel_mg[0], d.accel_mg[1], d.accel_mg[2]);
                azos_drv_sys::kconsoleln!(
                    "[IMU] Gyro:  X={} Y={} Z={} mdps",
                    d.gyro_mdps[0], d.gyro_mdps[1], d.gyro_mdps[2]);
                let deg = d.temp_cdeg / 100;
                let frac = (d.temp_cdeg % 100).unsigned_abs();
                azos_drv_sys::kconsoleln!("[IMU] Temp:  {}.{:02} C", deg, frac);
            }
            None => {
                azos_drv_sys::kconsoleln!("[IMU] Read failed (not initialized?)");
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("Usage: imu [info|read]");
    }
}

#[cfg(feature = "domain-robot")]
fn cmd_baro(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"read" };

    if sub == b"info" {
        azos_baro::baro_info();
    } else if sub == b"read" {
        match azos_baro::baro_read() {
            Some(d) => {
                let hpa = d.pressure_pa / 100;
                let hpa_frac = d.pressure_pa % 100;
                let deg = d.temp_cdeg / 100;
                let frac = (d.temp_cdeg % 100).unsigned_abs();
                azos_drv_sys::kconsoleln!("[BARO] Pressure: {}.{:02} hPa ({} Pa)",
                    hpa, hpa_frac, d.pressure_pa);
                azos_drv_sys::kconsoleln!("[BARO] Temp:     {}.{:02} C", deg, frac);
            }
            None => {
                azos_drv_sys::kconsoleln!("[BARO] Read failed (not initialized?)");
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("Usage: baro [info|read]");
    }
}

// ── Phase I1: AHRS attitude ──────────────────────────────────────────────────

#[cfg(feature = "domain-robot")]
fn cmd_attitude() {
    azos_ahrs::attitude_info();
}

// ── Phase I2: GPS ────────────────────────────────────────────────────────────

#[cfg(feature = "domain-robot")]
fn cmd_gps(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"info" };

    if sub == b"info" {
        azos_gps::gps_info();
        // Also show channel age.
        let snap = azos_gps::CH_GPS.read();
        if snap.seq > 0 {
            azos_drv_sys::kconsoleln!("[GPS] ch seq={} age={} ticks",
                snap.seq,
                azos_gps::CH_GPS.age(azos_drv_sys::timebase::now()));
        }
    } else if sub == b"read" {
        match azos_gps::gps_read() {
            Some(pos) => {
                azos_drv_sys::kconsoleln!("[GPS] fix={} sats={} hdop={}.{:02}",
                    pos.fix, pos.sats, pos.hdop / 100, pos.hdop % 100);
                let (lat_sign, lat_abs) = if pos.lat_deg7 < 0 { ("-", (-pos.lat_deg7) as u32) } else { ("", pos.lat_deg7 as u32) };
                let (lon_sign, lon_abs) = if pos.lon_deg7 < 0 { ("-", (-pos.lon_deg7) as u32) } else { ("", pos.lon_deg7 as u32) };
                azos_drv_sys::kconsoleln!("[GPS] lat={}{}.{:07} lon={}{}.{:07}",
                    lat_sign, lat_abs / 10_000_000, lat_abs % 10_000_000,
                    lon_sign, lon_abs / 10_000_000, lon_abs % 10_000_000);
                let alt_sign = if pos.alt_mm < 0 { "-" } else { "" };
                let alt_abs = pos.alt_mm.unsigned_abs();
                azos_drv_sys::kconsoleln!("[GPS] alt={}{}.{:03}m speed={}.{:02}m/s course={}.{:02}deg",
                    alt_sign, alt_abs / 1000, alt_abs % 1000,
                    pos.speed_cms / 100, pos.speed_cms % 100,
                    pos.course_cdeg / 100, pos.course_cdeg % 100);
            }
            None => {
                azos_drv_sys::kconsoleln!("[GPS] Not initialized");
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("Usage: gps [info|read]");
    }
}

// ── Phase J: flight controller ───────────────────────────────────────────────

#[cfg(feature = "domain-robot")]
fn cmd_flight(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"status" };

    if sub == b"status" {
        azos_flight::flight_info();
    } else if sub == b"arm" {
        // U11-5: the one command this front wires to a real capability
        // check. See `authority.rs`.
        if authority::check_flight_arm() {
            let _ = families::flight(azos_abi::families::FLIGHT_OP_ARM);
        }
    } else if sub == b"disarm" {
        let _ = families::flight(azos_abi::families::FLIGHT_OP_DISARM);
    } else if sub == b"mode" {
        if argc < 3 {
            azos_drv_sys::kconsoleln!("[FLIGHT] Current mode: {}",
                azos_flight::flight_mode().name());
            azos_drv_sys::kconsoleln!("Usage: flight mode <disarmed|manual|stabilize|althold|poshold|auto|rtl|land>");
            return;
        }
        match azos_flight::FlightMode::from_str(args[2]) {
            Some(mode) => {
                azos_flight::set_flight_mode(mode);
                azos_drv_sys::kconsoleln!("[FLIGHT] Mode set: {}", mode.name());
            }
            None => {
                azos_drv_sys::kconsoleln!("[FLIGHT] Unknown mode");
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("Usage: flight [status|arm|disarm|mode <mode>]");
    }
}

/// `authority` — print U11-5's per-command authority table: which
/// `CapKind` each consequential command needs, and whether that need is
/// enforced on this build (see `authority.rs` module doc: four rows always,
/// four more under `CONFIG_CONSOLE_LOCKDOWN`).
fn cmd_authority() {
    azos_drv_sys::kconsoleln!(
        "[AUTHORITY] command                     kind             write  enforced  console holds");
    for row in authority::AUTHORITY_TABLE {
        let holds = match row.kind {
            azos_abi::cap::CapKind::Motor => authority::console_holds_drivetrain_write(),
            azos_abi::cap::CapKind::Power => authority::console_holds_power_write(),
            _ => false,
        };
        azos_drv_sys::kconsoleln!(
            "[AUTHORITY] {:<28} {:<16?} {:<6} {:<9} {}",
            row.cmd, row.kind, row.need_write, authority::row_enforced(row), holds,
        );
    }
}

// The RC receiver and the ESCs are robot-only drivers (`azos_robot_drivers`);
// without the Robot domain these answer from `robot_cmds_absent`.
#[cfg(feature = "domain-robot")]
fn cmd_rc() {
    azos_robot_drivers::rc::rc_info();
}

#[cfg(feature = "domain-robot")]
fn cmd_esc() {
    azos_robot_drivers::esc::esc_info();
}

// ── Phase L: telemetry ──────────────────────────────────────────────────────

#[cfg(feature = "domain-robot")]
fn cmd_telem(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"status" };

    if sub == b"status" {
        azos_telemetry::telem_info();
    } else if sub == b"start" {
        let port: u16 = if argc >= 3 {
            parse_u32(args[2]) as u16
        } else {
            5000
        };
        azos_telemetry::telem_start(port);
    } else if sub == b"stop" {
        azos_telemetry::telem_stop();
    } else {
        azos_drv_sys::kconsoleln!("Usage: telem [status|start <port>|stop]");
    }
}

// ── Phase M+N: perception + navigation ────────────────────────────────────────

fn cmd_range() {
    azos_drv_sensor::rangefinder::range_info();
}

#[cfg(feature = "domain-robot")]
fn cmd_nav(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"info" };

    if sub == b"info" {
        azos_nav::nav_info();
    } else {
        azos_drv_sys::kconsoleln!("Usage: nav [info]");
    }
}

fn cmd_csi() {
    azos_drv_sensor::csi::csi_info();
}

fn cmd_wifi(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"info" };

    if sub == b"info" {
        azos_drv_net::wifi::wifi_info();
    } else if sub == b"connect" {
        let ssid: &[u8] = if argc >= 3 { args[2] } else { b"RobotAP" };
        let pass: &[u8] = if argc >= 4 { args[3] } else { b"" };
        azos_drv_net::wifi::wifi_connect(ssid, pass);
    } else if sub == b"disconnect" {
        azos_drv_net::wifi::wifi_disconnect();
    } else {
        azos_drv_sys::kconsoleln!("Usage: wifi [info|connect <ssid> [pass]|disconnect]");
    }
}

// ── Phase H: new driver + subsystem commands ─────────────────────────────────

fn cmd_spi() {
    azos_drv_bus::spi::spi_info();
}

fn cmd_can(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"info" };

    if sub == b"info" {
        azos_drv_bus::can::can_info();
    } else if sub == b"send" {
        let frame = azos_drv_bus::can::CanFrame::standard(
            0x123, &[0xDE, 0xAD, 0xBE, 0xEF],
        );
        let rc = azos_drv_bus::can::can_send(&frame);
        azos_drv_sys::kconsoleln!("[CAN] send(id=0x123, 4B) = {}", rc);
    } else if sub == b"recv" {
        match azos_drv_bus::can::can_recv() {
            Some(f) => azos_drv_sys::kconsoleln!("[CAN] recv: id=0x{:03x} dlc={} data={:02x?}",
                f.id, f.dlc, &f.data[..f.dlc as usize]),
            None => azos_drv_sys::kconsoleln!("[CAN] No frames in buffer"),
        }
    } else {
        azos_drv_sys::kconsoleln!("Usage: can [info|send|recv]");
    }
}

fn cmd_dma() {
    azos_drv_dmac::dma::dma_info();
}

fn cmd_usb() {
    azos_drv_bus::usb::usb_info();
}

fn cmd_pm(args: &[&[u8]; MAX_ARGS], argc: usize) {
    let sub: &[u8] = if argc >= 2 { args[1] } else { b"info" };

    if sub == b"info" {
        azos_drv_power::pm::pm_info();
    } else if sub == b"idle" {
        azos_drv_sys::kconsoleln!("[PM] Entering idle...");
        azos_drv_power::pm::pm_idle();
        azos_drv_sys::kconsoleln!("[PM] Resumed from idle");
    } else if sub == b"suspend" {
        if !authority::check_pm_suspend() {
            return;
        }
        azos_drv_sys::kconsoleln!("[PM] Entering suspend...");
        azos_drv_power::pm::pm_suspend();
        azos_drv_sys::kconsoleln!("[PM] Resumed from suspend");
    } else if sub == b"resume" {
        azos_drv_power::pm::pm_resume();
        azos_drv_sys::kconsoleln!("[PM] Forced resume");
    } else {
        azos_drv_sys::kconsoleln!("Usage: pm [info|idle|suspend|resume]");
    }
}

fn cmd_eth() {
    azos_drv_net::eth::eth_info();
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

#[cfg(not(feature = "no-mmu"))]
fn cmd_fork() {
    azos_drv_sys::kconsoleln!("[FORK] Calling sys_fork_impl()...");
    // Debug shell command, not a real ecall trap — there is no genuine
    // sepc/user_sp to thread through. The forked child's sret target is
    // meaningless here; this exercises fork's kernel-side bookkeeping only.
    // K-C11: likewise no genuine register file — a zeroed one is consistent
    // with the zeroed sepc/user_sp above.
    let rc = azos_sched::process::sys_fork_impl(0, 0, &azos_sched::UserRegs::default());
    azos_drv_sys::kconsoleln!("[FORK] Result: {}", rc);
}

// ── OTA auto-recv task entry ──────────────────────────────────────────────────

/// Kernel task entry for CONFIG.INI `ota_auto_recv_port`.
/// Spawned by main.rs when the config key is non-zero; `port_arg` is the port.
pub fn ota_recv_task_entry(port_arg: usize) {
    azos_drv_sys::kconsoleln!("[OTA] Auto-recv task running on port {}", port_arg);
    cmd_ota_recv(port_arg as u16);
}

// ── Main shell loop ───────────────────────────────────────────────────────────

/// Main shell entry point.  Runs forever, reading and executing commands.
/// Should be called from a kernel task.
pub fn shell_run() -> ! {
    azos_drv_sys::kconsoleln!();
    azos_drv_sys::kconsoleln!("AzOS shell — type 'help' for commands");
    azos_drv_sys::kconsoleln!();

    // U11-5: seed the console's own Cap<Motor> pair before the first command
    // can possibly run. See `authority.rs` module doc — commenting this call
    // out is this front's RED canary for `flight arm`'s authority gate.
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
                else if cmd == b"exec"     {
                    #[cfg(not(feature = "no-mmu"))]
                    cmd_exec(&args, argc);
                    #[cfg(feature = "no-mmu")]
                    azos_drv_sys::kconsoleln!("[SHELL] exec disabled (compiled with --features no-mmu)");
                }
                else if cmd == b"spawn"    {
                    #[cfg(not(feature = "no-mmu"))]
                    cmd_spawn(&args, argc);
                    #[cfg(feature = "no-mmu")]
                    azos_drv_sys::kconsoleln!("[SHELL] spawn disabled (compiled with --features no-mmu)");
                }
                else if cmd == b"ps"       { cmd_ps(); }
                else if cmd == b"mem"      { cmd_mem(); }
                else if cmd == b"uptime"   { cmd_uptime(); }
                else if cmd == b"drvls"    { cmd_drvls(); }
                else if cmd == b"ls"       { cmd_ls(&args, argc); }
                else if cmd == b"cat"      { cmd_cat(&args, argc); }
                else if cmd == b"write"    { cmd_write(&args, argc); }
                else if cmd == b"rm"       { cmd_rm(&args, argc); }
                else if cmd == b"mkdir"    { cmd_mkdir(&args, argc); }
                else if cmd == b"echo"     { cmd_echo(&args, argc); }
                else if cmd == b"disk"     { cmd_disk(); }
                else if cmd == b"ifconfig" { cmd_ifconfig(); }
                else if cmd == b"ping"     { cmd_ping(&args, argc); }
                else if cmd == b"arp"      { cmd_arp(); }
                else if cmd == b"tcpecho"  { cmd_tcpecho(&args, argc); }
                else if cmd == b"gpio"     { cmd_gpio(&args, argc); }
                else if cmd == b"pwm"      { cmd_pwm(&args, argc); }
                else if cmd == b"i2c"      { cmd_i2c(&args, argc); }
                else if cmd == b"motor"    { cmd_motor(&args, argc); }
                else if cmd == b"rvv"      { cmd_rvv(); }
                else if cmd == b"pipeline" { cmd_pipeline(); }
                else if cmd == b"ota" { cmd_ota(&args, argc); }
                else if cmd == b"security" { cmd_security(); }
                else if cmd == b"odom"     { cmd_odom(); }
                else if cmd == b"traj"     { cmd_traj(&args, argc); }
                else if cmd == b"config"   { cmd_config(&args, argc); }
                else if cmd == b"behavior" { cmd_behavior(&args, argc); }
                else if cmd == b"pmp"      { cmd_pmp(); }
                else if cmd == b"wdt"      { cmd_wdt(); }
                else if cmd == b"fuzz"     { cmd_fuzz(); }
                else if cmd == b"sched_hz" { cmd_sched_hz(&args, argc); }
                else if cmd == b"imu"      { cmd_imu(&args, argc); }
                else if cmd == b"baro"     { cmd_baro(&args, argc); }
                else if cmd == b"attitude" { cmd_attitude(); }
                else if cmd == b"gps"      { cmd_gps(&args, argc); }
                else if cmd == b"flight"   { cmd_flight(&args, argc); }
                else if cmd == b"authority" { cmd_authority(); }
                else if cmd == b"rc"       { cmd_rc(); }
                else if cmd == b"esc"      { cmd_esc(); }
                else if cmd == b"telem"    { cmd_telem(&args, argc); }
                else if cmd == b"range"    { cmd_range(); }
                else if cmd == b"nav"      { cmd_nav(&args, argc); }
                else if cmd == b"csi"      { cmd_csi(); }
                else if cmd == b"wifi"     { cmd_wifi(&args, argc); }
                else if cmd == b"spi"      { cmd_spi(); }
                else if cmd == b"can"      { cmd_can(&args, argc); }
                else if cmd == b"dma"      { cmd_dma(); }
                else if cmd == b"usb"      { cmd_usb(); }
                else if cmd == b"pm"       { cmd_pm(&args, argc); }
                else if cmd == b"eth"      { cmd_eth(); }
                else if cmd == b"dhcp"     { cmd_dhcp(); }
                else if cmd == b"fork"     {
                    #[cfg(not(feature = "no-mmu"))]
                    cmd_fork();
                    #[cfg(feature = "no-mmu")]
                    azos_drv_sys::kconsoleln!("[SHELL] fork disabled (compiled with --features no-mmu)");
                }
                else if cmd == b"crash"    { cmd_crash(&args, argc); }
                else if cmd == b"wcet"     { cmd_wcet(&args, argc); }
                else if cmd == b"bench"    { cmd_bench(&args, argc); }
                else if cmd == b"shutdown" { cmd_shutdown(); }
                else if cmd == b"reboot"   { cmd_reboot(); }
                else {
                    azos_drv_sys::kconsole!("[SHELL] Unknown: ");
                    azos_drv_sys::uart::write_locked(cmd);
                    azos_drv_sys::kconsoleln!(" (type 'help')");
                }
            }
        }

        for b in line_buf.iter_mut() { *b = 0; }
    }
}

// ── Without the Robot domain ─────────────────────────────────────────────────
//
// The robot commands above are compiled only with `domain-robot` (wave 11).
// Without it the dispatch chain in `shell_run` is unchanged and each of them
// says why it is absent instead of disappearing from `help` silently.
#[cfg(not(feature = "domain-robot"))]
mod robot_cmds_absent {
    use super::MAX_ARGS;

    fn absent(cmd: &str) {
        azos_drv_sys::kconsoleln!(
            "[SHELL] '{}' needs the Robot domain (DOMAIN_ROBOT); this image was built without it", cmd);
    }

    pub(super) fn cmd_pipeline() { absent("pipeline"); }
    pub(super) fn cmd_odom() { absent("odom"); }
    pub(super) fn cmd_traj(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("traj"); }
    pub(super) fn cmd_behavior(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("behavior"); }
    pub(super) fn cmd_bench(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("bench"); }
    pub(super) fn cmd_imu(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("imu"); }
    pub(super) fn cmd_baro(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("baro"); }
    pub(super) fn cmd_attitude() { absent("attitude"); }
    pub(super) fn cmd_gps(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("gps"); }
    pub(super) fn cmd_flight(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("flight"); }
    pub(super) fn cmd_telem(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("telem"); }
    pub(super) fn cmd_nav(_args: &[&[u8]; MAX_ARGS], _argc: usize) { absent("nav"); }
    pub(super) fn cmd_rc() { absent("rc"); }
    pub(super) fn cmd_esc() { absent("esc"); }
}
#[cfg(not(feature = "domain-robot"))]
use robot_cmds_absent::*;
