// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! build.rs for `azos_limits` (RFC-0026 Phase C2)
//!
//! Reads the workspace `.config` file, emits `generated.rs` into OUT_DIR,
//! and runs a set of compile-time validation invariants that reject nonsense
//! configuration combinations before any code is compiled.
//!
//! **Validation failures are hard errors** — the build aborts with a clear
//! message naming the option pair that violated the invariant.
//!
//! To change a value: `make menuconfig` or `make defconfig-<profile>`.

use azos_config::{parse_config, ConfigMap};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // -----------------------------------------------------------------------
    // Locate .config relative to the workspace root.
    //
    // CARGO_MANIFEST_DIR is `crates/core/limits/`, so go up three levels.
    // A Makefile wrapper can override with KCONFIG_CONFIG env var.
    // -----------------------------------------------------------------------
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()  // crates/core/
        .and_then(|p| p.parent())  // crates/
        .and_then(|p| p.parent())  // workspace root
        .expect("could not determine workspace root from CARGO_MANIFEST_DIR");

    let config_path_env = env::var("KCONFIG_CONFIG")
        .unwrap_or_else(|_| workspace_root.join(".config").to_string_lossy().to_string());

    let config_path = PathBuf::from(&config_path_env);

    // Emit rerun directive regardless of whether .config exists so changes
    // to the file trigger a rebuild.
    println!("cargo:rerun-if-changed={}", config_path.display());
    println!("cargo:rerun-if-env-changed=KCONFIG_CONFIG");

    // -----------------------------------------------------------------------
    // If .config is missing, skip generation (do not block `cargo check`).
    // The Makefile rule `$(KCONFIG_CONFIG):` creates it automatically.
    // -----------------------------------------------------------------------
    if !config_path.exists() {
        eprintln!(
            "cargo:warning=azos_limits: .config not found at {} — \
             run `make defconfig-edge` to generate it.  \
             Emitting empty generated.rs.",
            config_path.display()
        );
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let dest = out_dir.join("generated.rs");
        fs::write(
            &dest,
            "// GENERATED — .config was absent at build time.  Run `make defconfig-edge`.\n",
        )
        .expect("could not write empty generated.rs");
        return;
    }

    // -----------------------------------------------------------------------
    // Compute SHA-256 of .config for the header comment.
    // -----------------------------------------------------------------------
    let config_bytes = fs::read(&config_path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", config_path.display()));
    let digest = Sha256::digest(&config_bytes);
    let sha_hex = format!("{digest:x}");
    let sha12 = &sha_hex[..12];

    // -----------------------------------------------------------------------
    // Parse .config.
    // -----------------------------------------------------------------------
    let mut cfg = parse_config(config_path.to_str().unwrap())
        .unwrap_or_else(|e| panic!("azos-config: parse error in {}: {e}", config_path.display()));

    // -----------------------------------------------------------------------
    // Bools a valid .config leaves out (wave 11). kconfiglib writes nothing
    // for a bool that is n and hidden: a `visible if` menu (the Robot menu
    // outside DOMAIN_ROBOT), an `if` block, a `depends on`. The value is n
    // all the same, and code that is compiled into every image still reads
    // some of them (`MULTISTREAM_SCHED_PRIORITY` in kernel/src/tasks/brain_link.rs), so
    // each one the Kconfig tree declares as hideable is filled in as n.
    // A bool that is always written is not filled: a .config without one
    // predates the Kconfig tree, and its consumer fails to compile instead
    // of reading a silent `false` (regenerate with `make olddefconfig`).
    // -----------------------------------------------------------------------
    let (kconfig_syms, kconfig_files) =
        azos_config::read_kconfig_tree(workspace_root, "Kconfig")
            .unwrap_or_else(|e| panic!("azos-config: cannot read the Kconfig tree under {}: {e}",
                                       workspace_root.display()));
    for f in &kconfig_files {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    for name in azos_config::hidden_bools(&kconfig_syms) {
        cfg.entry(name).or_insert_with(|| "n".to_string());
    }

    // -----------------------------------------------------------------------
    // Run validation invariants BEFORE emitting Rust source.
    // A failed invariant panics the build with a clear error message.
    // -----------------------------------------------------------------------
    run_validations(&cfg);

    // -----------------------------------------------------------------------
    // Emit generated.rs into OUT_DIR.
    // -----------------------------------------------------------------------
    let mut out = String::new();
    azos_config::emit_rust(&cfg, &mut out, sha12);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("generated.rs");
    fs::write(&dest, &out)
        .unwrap_or_else(|e| panic!("could not write {}: {e}", dest.display()));

    // (informational — only shown with `cargo build -vv`)
    let const_count = out.lines().filter(|l| l.starts_with("pub const ")).count();
    eprintln!("azos_limits: emitted {const_count} consts from .config [{sha12}]");
}

// ---------------------------------------------------------------------------
// Helper: read a u64 value from ConfigMap (decimal or hex string).
// Panics if the key is absent or the value cannot be parsed.
// ---------------------------------------------------------------------------
fn get_u64(cfg: &ConfigMap, key: &str) -> Option<u64> {
    let val = cfg.get(key)?;
    if val == "y" || val == "n" {
        return None; // bool, not integer
    }
    if val.starts_with("0x") || val.starts_with("0X") {
        return u64::from_str_radix(&val[2..], 16).ok();
    }
    val.parse::<u64>().ok()
}

fn get_u64_required(cfg: &ConfigMap, key: &str) -> u64 {
    get_u64(cfg, key)
        .unwrap_or_else(|| panic!("validation: required integer key {key} is missing or non-numeric in .config"))
}

fn get_bool(cfg: &ConfigMap, key: &str) -> bool {
    cfg.get(key).map(|v| v == "y").unwrap_or(false)
}

fn get_str<'a>(cfg: &'a ConfigMap, key: &str) -> &'a str {
    cfg.get(key).map(|s| s.as_str()).unwrap_or("")
}

// ---------------------------------------------------------------------------
// Validation invariants (RFC-0026 §Validation & invariants).
// Every check panics with a descriptive message on failure.
// ---------------------------------------------------------------------------
fn run_validations(cfg: &ConfigMap) {
    // -----------------------------------------------------------------------
    // Options for code that does not exist yet (wave 11). The Linux
    // compatibility menu (config/Kconfig.linux, RFC-0053) is laid out before
    // its code; none of its symbols may be silently inert, so a .config that
    // enables one does not build. A stage that lands removes its symbols
    // from this list in the same change that wires them.
    // -----------------------------------------------------------------------
    const NOT_IMPLEMENTED: &[(&str, &str)] = &[
        ("LX_FS_EXT2",               "RFC-0053 stages L1 (read-only) and L2 (read-write)"),
        ("LX_FS_EXT4_RO",            "RFC-0053 stage L3"),
        ("LX_FS_EXT4_RW",            "RFC-0053 stage L4"),
        ("LX_USB_XHCI",              "RFC-0053 stages L5 (DMA/BAR/MSI prerequisites) and L6"),
        ("LX_USB_DWC3",              "RFC-0053 stage L8"),
        ("LX_USB_HID",               "RFC-0053 stage L6"),
        ("LX_USB_STORAGE",           "RFC-0053 stage L7"),
        ("LX_USB_CDC",               "RFC-0053 stage L7"),
        ("LX_USB_UVC",               "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_SND_ASOC",              "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_DRM_PANEL",             "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_IIO",                   "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_WIFI",                  "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_BLUETOOTH",             "RFC-0053 stage L9+ (needs an amendment)"),
        ("LX_ACCEPT_UNCONFINED_DMA", "RFC-0053 stages L5/L8"),
    ];
    let set: Vec<String> = NOT_IMPLEMENTED
        .iter()
        .filter(|(k, _)| get_bool(cfg, k))
        .map(|(k, stage)| format!("CONFIG_{k}=y: not implemented ({stage})"))
        .collect();
    // RFC-0053 L0/L0b landed the module loader and the empty server only.
    // `LINUX_DRIVERS` alone would be a menu with nothing behind it, so it
    // builds only together with the dev option that says what it builds: the
    // server skeleton (`LX_SERVER_SKELETON`, no Linux object). Every module
    // option above still refuses until its stage lands (L1 needs the
    // owner's sign-off, RFC-0053 10.3).
    let mut set = set;
    if get_bool(cfg, "LINUX_DRIVERS") && !get_bool(cfg, "LX_SERVER_SKELETON") {
        set.push("CONFIG_LINUX_DRIVERS=y without CONFIG_LX_SERVER_SKELETON=y: only the empty \
                  server skeleton exists (RFC-0053 L0); the first Linux module is stage L1".to_string());
    }
    if !set.is_empty() {
        panic!(
            "validation FAIL: .config enables options whose code does not exist yet:\n  {}\n\
             Fix: turn them off (`make menuconfig`, \"Linux compatibility\"). An image with a \
             Linux module will also ship as GPL-2.0-only.",
            set.join("\n  ")
        );
    }

    // -----------------------------------------------------------------------
    // Network socket capacity
    //
    // RFC-0026 body says +16; config/Kconfig.limits help text says +4.
    // We use +4 to match the Kconfig documentation and to allow the only
    // existing defconfig (edge: MAX_SOCKETS=16, TCP_MAX_CONNS=8) to pass.
    // (The RFC body states "+16" but the authored Kconfig says "+4 reserved
    //  UDP slots"; Kconfig is the normative per-file specification for C2.)
    // -----------------------------------------------------------------------
    const MIN_UDP_RESERVE: u64 = 4;
    let max_sockets     = get_u64_required(cfg, "MAX_SOCKETS");
    let tcp_max_conns   = get_u64_required(cfg, "TCP_MAX_CONNS");
    if max_sockets < tcp_max_conns + MIN_UDP_RESERVE {
        panic!(
            "validation FAIL: MAX_SOCKETS ({max_sockets}) < TCP_MAX_CONNS ({tcp_max_conns}) + \
             {MIN_UDP_RESERVE} (UDP reserve). \
             Fix: increase MAX_SOCKETS or decrease TCP_MAX_CONNS in .config."
        );
    }

    // -----------------------------------------------------------------------
    // File descriptor capacity
    // MAX_FDS_TOTAL >= MAX_TASKS / 4 * MAX_FDS_PER_PROC
    // (rough: if every 4th task uses its max FD budget, we can serve them all)
    // -----------------------------------------------------------------------
    let max_fds_total   = get_u64_required(cfg, "MAX_FDS_TOTAL");
    let max_tasks       = get_u64_required(cfg, "MAX_TASKS");
    let max_fds_per_proc = get_u64_required(cfg, "MAX_FDS_PER_PROC");
    // Average-case sizing: assume each task uses ~4 FDs on average
    // (stdin/stdout/stderr + one TCP socket).  MAX_FDS_PER_PROC is the
    // per-task CEILING — well-behaved tasks rarely use more than 4.  The
    // previous formula `(MAX_TASKS/4) × MAX_FDS_PER_PROC` was a
    // worst-case-on-25%-of-tasks heuristic that scaled super-linearly with
    // the per-proc cap and rejected reasonable fleet configs.
    const AVG_FDS_PER_TASK: u64 = 4;
    let fds_required = max_tasks * AVG_FDS_PER_TASK;
    if max_fds_total < fds_required {
        panic!(
            "validation FAIL: MAX_FDS_TOTAL ({max_fds_total}) < \
             MAX_TASKS * {AVG_FDS_PER_TASK} = {fds_required} (average FDs/task budget). \
             Fix: increase MAX_FDS_TOTAL in .config, or reduce MAX_TASKS."
        );
    }
    // Also reject the (unusual) case where per-proc cap exceeds the global
    // pool — a single task could starve everyone else.
    if max_fds_per_proc > max_fds_total {
        panic!(
            "validation FAIL: MAX_FDS_PER_PROC ({max_fds_per_proc}) > MAX_FDS_TOTAL ({max_fds_total}). \
             One task could exhaust the entire FD pool."
        );
    }

    // -----------------------------------------------------------------------
    // Capability pool capacity
    // MAX_CAPS_TOTAL >= MAX_TASKS * 8
    // -----------------------------------------------------------------------
    let max_caps_total  = get_u64_required(cfg, "MAX_CAPS_TOTAL");
    let caps_required   = max_tasks * 8;
    if max_caps_total < caps_required {
        panic!(
            "validation FAIL: MAX_CAPS_TOTAL ({max_caps_total}) < MAX_TASKS*8 = {caps_required}. \
             Fix: increase MAX_CAPS_TOTAL in .config."
        );
    }

    // -----------------------------------------------------------------------
    // Kernel heap size
    // Must cover the static-table footprints.  Note that kernel stacks live
    // in a DEDICATED arena (sized via KERNEL_STACK_SIZE_KB × MAX_TASKS but
    // allocated from the linker's `.bss`, not the runtime heap), so we do
    // NOT include them in the heap floor.
    //
    // Formula (bytes), sized from the largest few in-heap structures:
    //   MAX_TASKS    * 384   — TCB metadata (state, ptr, accounting)
    //   MAX_CHANNELS * 256   — channel message queues
    //   MAX_PIPES    * 4096  — pipe ring buffers (PIPE_BUF_SIZE)
    //   MAX_TOPICS   * 512   — topic descriptor + sub list slot
    //   MAX_CAPS_TOTAL * 64  — capability table entries
    //   + 64 KiB             — slop / IPC / FS overhead
    //
    // The previous formula included a 1 MiB hard floor that rejected the
    // embedded profile (512 KiB heap), and double-counted kernel stacks
    // that don't actually live on the heap.
    // -----------------------------------------------------------------------
    let heap_size_kib = get_u64_required(cfg, "KERNEL_HEAP_SIZE");
    let heap_size_bytes = heap_size_kib * 1024;
    let max_channels    = get_u64_required(cfg, "MAX_CHANNELS");
    let max_pipes       = get_u64(cfg, "MAX_PIPES").unwrap_or(0);
    let max_topics      = get_u64(cfg, "MAX_TOPICS").unwrap_or(0);

    const TCB_BYTES:    u64 = 384;
    const CHAN_BYTES:   u64 = 256;
    const PIPE_BYTES:   u64 = 4096;
    const TOPIC_BYTES:  u64 = 512;
    const CAP_BYTES:    u64 = 64;
    const SLOP_BYTES:   u64 = 64 * 1024;

    let min_heap = max_tasks       * TCB_BYTES
        + max_channels    * CHAN_BYTES
        + max_pipes       * PIPE_BYTES
        + max_topics      * TOPIC_BYTES
        + max_caps_total  * CAP_BYTES
        + SLOP_BYTES;

    if heap_size_bytes < min_heap {
        panic!(
            "validation FAIL: KERNEL_HEAP_SIZE ({heap_size_kib} KiB = {heap_size_bytes} bytes) < \
             estimated minimum {min_heap} bytes \
             (MAX_TASKS*{TCB_BYTES} + MAX_CHANNELS*{CHAN_BYTES} + MAX_PIPES*{PIPE_BYTES} + \
              MAX_TOPICS*{TOPIC_BYTES} + MAX_CAPS_TOTAL*{CAP_BYTES} + {SLOP_BYTES}). \
             Fix: increase KERNEL_HEAP_SIZE in .config, or reduce MAX_PIPES / MAX_CHANNELS / MAX_TASKS."
        );
    }

    // -----------------------------------------------------------------------
    // Kernel heap against RAM_SIZE
    //
    // The heap is taken from the page allocator after the image
    // (kernel/src/entry/{riscv64,aarch64}/boot_hooks.rs, "[MM] Heap"), and the allocator manages at most
    // RAM_SIZE MiB (crates/core/mm/src/pmm.rs MAX_PAGES). A heap that is not
    // smaller than RAM_SIZE can never fit, and the boot stops at
    // "[MM] Heap FAILED:". The image size is not known here, so this refuses
    // only the impossible case; the boot check covers the rest.
    // -----------------------------------------------------------------------
    if let Some(ram_mib) = get_u64(cfg, "RAM_SIZE") {
        let ram_bytes = ram_mib * 1024 * 1024;
        if heap_size_bytes >= ram_bytes {
            panic!(
                "validation FAIL: KERNEL_HEAP_SIZE ({heap_size_kib} KiB) >= RAM_SIZE ({ram_mib} MiB). \
                 The heap is taken from the page allocator after the kernel image and cannot fit. \
                 Fix: increase RAM_SIZE or decrease KERNEL_HEAP_SIZE in .config."
            );
        }
    }

    // -----------------------------------------------------------------------
    // Board → arch consistency
    // -----------------------------------------------------------------------
    let board_vf2      = get_bool(cfg, "BOARD_VF2");
    let board_k1       = get_bool(cfg, "BOARD_K1");
    let arch_riscv64   = get_bool(cfg, "ARCH_RISCV64");
    let arch_aarch64   = get_bool(cfg, "ARCH_AARCH64");

    if board_vf2 && !arch_riscv64 {
        panic!(
            "validation FAIL: BOARD_VF2=y requires ARCH_RISCV64=y (JH7110 is a RISC-V SoC). \
             Fix: set ARCH_RISCV64=y in .config."
        );
    }
    if board_k1 && !arch_riscv64 {
        panic!(
            "validation FAIL: BOARD_K1=y requires ARCH_RISCV64=y (SpacemiT K1 is a RISC-V SoC). \
             Fix: set ARCH_RISCV64=y in .config."
        );
    }

    // -----------------------------------------------------------------------
    // FP extension consistency
    // FP_NEON requires ARCH_AARCH64; FP_RVV requires HAS_RVV
    // -----------------------------------------------------------------------
    let fp_neon = get_bool(cfg, "FP_NEON");
    let fp_rvv  = get_bool(cfg, "FP_RVV");
    let has_rvv = get_bool(cfg, "HAS_RVV");

    if fp_neon && !arch_aarch64 {
        panic!(
            "validation FAIL: FP_NEON=y requires ARCH_AARCH64=y (NEON is an Aarch64 feature). \
             Fix: select ARCH_AARCH64 or choose a different FP context."
        );
    }
    if fp_rvv && !has_rvv {
        panic!(
            "validation FAIL: FP_RVV=y but HAS_RVV=n — the target SoC does not have RVV hardware. \
             Fix: enable HAS_RVV or choose FP_HARDFLOAT_D as the FP context."
        );
    }

    // -----------------------------------------------------------------------
    // AEAD link encryption requires a PSK path
    // -----------------------------------------------------------------------
    let link_aead_default_on = get_bool(cfg, "LINK_AEAD_DEFAULT_ON");
    let link_psk_path        = get_str(cfg, "LINK_PSK_PATH");
    if link_aead_default_on && link_psk_path.is_empty() {
        panic!(
            "validation FAIL: LINK_AEAD_DEFAULT_ON=y but LINK_PSK_PATH is empty. \
             Fix: set LINK_PSK_PATH to the FAT path of the pre-shared key file \
             (e.g. /fat/LINK.KEY)."
        );
    }

    // -----------------------------------------------------------------------
    // Secure boot → OTA signature mandatory
    // -----------------------------------------------------------------------
    let secure_boot = get_bool(cfg, "SECURE_BOOT_ENFORCED");
    let ota_sig_man = get_bool(cfg, "OTA_SIG_MANDATORY");
    if secure_boot && !ota_sig_man {
        panic!(
            "validation FAIL: SECURE_BOOT_ENFORCED=y but OTA_SIG_MANDATORY=n. \
             Secure boot requires all OTA images to be signed to prevent \
             downgrade attacks. Fix: set OTA_SIG_MANDATORY=y in .config."
        );
    }

    // -----------------------------------------------------------------------
    // PMP regions reserved ≤ 12
    // (hardware cap is 16; we need at least 4 slots for user-process isolation)
    // -----------------------------------------------------------------------
    const PMP_MAX_RESERVED: u64 = 12;
    let pmp_reserved = get_u64_required(cfg, "PMP_REGIONS_RESERVED");
    if pmp_reserved > PMP_MAX_RESERVED {
        panic!(
            "validation FAIL: PMP_REGIONS_RESERVED={pmp_reserved} exceeds maximum {PMP_MAX_RESERVED}. \
             RISC-V M-mode hardware has 16 PMP regions; reserving more than {PMP_MAX_RESERVED} \
             leaves fewer than 4 slots for user-process isolation. \
             Fix: reduce PMP_REGIONS_RESERVED in .config."
        );
    }

    // -----------------------------------------------------------------------
    // Per-task capability ceiling vs global pool
    // MAX_CAPS_PER_TASK <= MAX_CAPS_TOTAL — a single task cannot be allowed
    // to request more capability slots than the entire pool holds.  Mirrors
    // the MAX_FDS_PER_PROC <= MAX_FDS_TOTAL invariant above; the FD check
    // existed but the cap-table parallel was missing.
    // -----------------------------------------------------------------------
    let max_caps_per_task = get_u64_required(cfg, "MAX_CAPS_PER_TASK");
    if max_caps_per_task > max_caps_total {
        panic!(
            "validation FAIL: MAX_CAPS_PER_TASK ({max_caps_per_task}) > MAX_CAPS_TOTAL ({max_caps_total}). \
             One task could exhaust the entire capability pool. \
             Fix: reduce MAX_CAPS_PER_TASK or increase MAX_CAPS_TOTAL in .config."
        );
    }

    // -----------------------------------------------------------------------
    // WCET measurement point capacity
    // WCET_MAX_POINTS must accommodate the 9 hardcoded fixed kernel points
    // (IDs 0-8: pid_loop, sensor_read, ctx_switch, timer_isr, actuator_write,
    // net_send, cnn_infer, lidar_scan, path_plan) before any
    // `#[wcet(...)]`-generated point is added.  Setting it below 9 would
    // index out of the static WCET table on the first timer ISR.
    //
    // This is a structural invariant — independent of Kconfig range, which
    // already enforces >= 16, but the panic message documents the constraint
    // for anyone editing config/Kconfig.limits later.
    // -----------------------------------------------------------------------
    const WCET_FIXED_POINTS: u64 = 9;
    let wcet_max_points = get_u64_required(cfg, "WCET_MAX_POINTS");
    if wcet_max_points < WCET_FIXED_POINTS {
        panic!(
            "validation FAIL: WCET_MAX_POINTS ({wcet_max_points}) < {WCET_FIXED_POINTS} \
             (the kernel's hardcoded fixed WCET points pid_loop..path_plan, IDs 0-8). \
             Fix: set WCET_MAX_POINTS >= {WCET_FIXED_POINTS} in .config; the embedded \
             profile default of 32 is a safe minimum."
        );
    }

    // -----------------------------------------------------------------------
    // Topic subscriber slot vs schedulable tasks
    // MAX_SUBS_PER_TOPIC <= MAX_TASKS — a topic cannot have more
    // subscribers than there are tasks in the system.  Allocating more slots
    // than tasks just wastes BSS for entries that can never be filled, and
    // hints at a misconfig (likely intended a higher MAX_TASKS).
    // -----------------------------------------------------------------------
    let max_subs_per_topic = get_u64_required(cfg, "MAX_SUBS_PER_TOPIC");
    if max_subs_per_topic > max_tasks {
        panic!(
            "validation FAIL: MAX_SUBS_PER_TOPIC ({max_subs_per_topic}) > MAX_TASKS ({max_tasks}). \
             A topic can't have more subscribers than there are tasks; the slack just wastes BSS. \
             Fix: reduce MAX_SUBS_PER_TOPIC or increase MAX_TASKS in .config."
        );
    }

    // -----------------------------------------------------------------------
    // PAGE_SHIFT (config/Kconfig.arch): the base page. riscv64 has exactly
    // one (Sv39, 4 KiB); aarch64 takes 12, 14 or 16 from the AARCH64_PAGE_*
    // choice. The kernel additionally asserts that azos_arch_api's
    // feature-selected PAGE_SIZE equals 1 << this, so `.config` and the
    // cargo features cannot silently disagree.
    // -----------------------------------------------------------------------
    let page_shift = get_u64_required(cfg, "PAGE_SHIFT");
    if get_bool(cfg, "ARCH_RISCV64") && page_shift != 12 {
        panic!(
            "validation FAIL: PAGE_SHIFT ({page_shift}) on ARCH_RISCV64 — Sv39's only \
             base page is 4 KiB (PAGE_SHIFT = 12). Large mappings on riscv64 are \
             LOCKED_HUGE_LEAVES, not a different base page."
        );
    }
    if !matches!(page_shift, 12 | 14 | 16) {
        panic!(
            "validation FAIL: PAGE_SHIFT ({page_shift}) is not a VMSAv8-64 granule \
             (12 / 14 / 16). Fix: pick AARCH64_PAGE_4K / _16K / _64K."
        );
    }
    let page_bytes: u64 = 1 << page_shift;

    // -----------------------------------------------------------------------
    // KERNEL_STACK_SIZE_KB must leave a positive usable stack after the guard
    // page (crates/core/sched sets one up — see setup_stack_guard_pages()),
    // and be a whole number of pages, or the guard of stack i+1 would unmap
    // the top of stack i. The Kconfig `range 4 256` alone permits 4, which
    // leaves exactly 0 usable bytes.
    // -----------------------------------------------------------------------
    let stack_guard_page_bytes: u64 = page_bytes;
    let kernel_stack_kb = get_u64_required(cfg, "KERNEL_STACK_SIZE_KB");
    let kernel_stack_bytes = kernel_stack_kb * 1024;
    if kernel_stack_bytes <= stack_guard_page_bytes {
        panic!(
            "validation FAIL: KERNEL_STACK_SIZE_KB ({kernel_stack_kb} KiB = \
             {kernel_stack_bytes} bytes) leaves no usable stack after the \
             {stack_guard_page_bytes}-byte guard page. Fix: increase \
             KERNEL_STACK_SIZE_KB in .config (minimum useful value is well \
             above one page)."
        );
    }
    if kernel_stack_bytes % page_bytes != 0 {
        panic!(
            "validation FAIL: KERNEL_STACK_SIZE_KB ({kernel_stack_kb}) is not a whole \
             number of {page_bytes}-byte pages. Fix: a multiple of {} KiB.",
            page_bytes / 1024
        );
    }
    let user_stack_kb = get_u64_required(cfg, "USER_STACK_SIZE_KB");
    if (user_stack_kb * 1024) % page_bytes != 0 {
        panic!(
            "validation FAIL: USER_STACK_SIZE_KB ({user_stack_kb}) is not a whole \
             number of {page_bytes}-byte pages (the stack is mapped page by page). \
             Fix: a multiple of {} KiB.",
            page_bytes / 1024
        );
    }

    // -----------------------------------------------------------------------
    // TCP_BUF_SIZE is used as a ring-buffer bitmask (TCP_BUF_SIZE - 1) in
    // crates/net/net/src/tcp.rs — it must be a power of two or the mask silently
    // produces wrong wrap-around behavior. The Kconfig `range 4096 1048576`
    // doesn't enforce this on its own.
    // -----------------------------------------------------------------------
    let tcp_buf_size = get_u64_required(cfg, "TCP_BUF_SIZE");
    if tcp_buf_size == 0 || (tcp_buf_size & (tcp_buf_size - 1)) != 0 {
        panic!(
            "validation FAIL: TCP_BUF_SIZE ({tcp_buf_size}) is not a power of \
             two. It's used as a ring-buffer mask (TCP_BUF_SIZE - 1) in \
             crates/net/net/src/tcp.rs and must stay a power of two. \
             Fix: pick a power-of-two value in .config (e.g. 65536, 131072, \
             262144)."
        );
    }

    // -----------------------------------------------------------------------
    // TCP_BUF_SIZE lower bound: the send ring (the same size) must hold
    // DUP_ACK_THRESHOLD + 1 full-size segments, or no loss can be repaired by
    // fast retransmit or SACK recovery and every one waits for the
    // retransmission timer. crates/net/net/src/tcp.rs asserts the same at compile
    // time from its own constants; TCP_MSS (1460) and DUP_ACK_THRESHOLD (3)
    // are hard-coded there and not read from .config, so they are restated
    // here. The Kconfig `range` enforces this only through kconfiglib, not
    // on a hand-edited .config.
    // -----------------------------------------------------------------------
    const TCP_MSS_BYTES: u64 = 1460;
    const DUP_ACK_THRESHOLD: u64 = 3;
    let tcp_buf_min = (DUP_ACK_THRESHOLD + 1) * TCP_MSS_BYTES;
    if tcp_buf_size < tcp_buf_min {
        panic!(
            "validation FAIL: TCP_BUF_SIZE ({tcp_buf_size}) < {tcp_buf_min} \
             ((DUP_ACK_THRESHOLD {DUP_ACK_THRESHOLD} + 1) x TCP_MSS {TCP_MSS_BYTES}). \
             The send ring could not hold the flight that duplicate ACKs come \
             from, so every loss would wait for the retransmission timer. \
             Fix: set TCP_BUF_SIZE to 8192 or more in .config."
        );
    }

    // -----------------------------------------------------------------------
    // SCHED_HZ_FLOOR must not exceed SCHED_HZ (Q4.2, owner decision
    // 2026-09-25). SCHED_HZ_FLOOR is the floor CONFIG.INI is allowed to
    // request at boot (crates/core/config's `resolve_sched_hz`); SCHED_HZ is the
    // compile-time ceiling for this board/profile. Kconfig cannot express
    // "SCHED_HZ_FLOOR <= SCHED_HZ" as a `range` (a symbol's range can only
    // reference literals), so SCHED_HZ_FLOOR is a second literal (10) that
    // has to independently track SCHED_HZ's own `range 10 1000` lower
    // bound. This is that check, made a hard build error instead of a
    // comment someone has to remember to re-read.
    //
    // SCHED_HZ_FLOOR is a brand-new key (added the same day as this check):
    // an existing `.config` on disk was generated before config/Kconfig.timing knew
    // about it and will not contain it until the next `make
    // defconfig-<profile>` / `olddefconfig` regenerates it. Unlike the
    // required keys above (which have always been in every `.config` this
    // crate has ever read), this one uses the optional accessor and no-ops
    // when absent, so a plain `cargo build` against a not-yet-regenerated
    // `.config` still succeeds — the check activates automatically the next
    // time the `.config` is regenerated, same as every other new option.
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Wave 11 tunables whose constraint a Kconfig `range` cannot state, or
    // that a hand-edited .config could break (kconfiglib enforces `range`
    // only when it writes the file).
    //   UDP_RX_SLOTS: the receive ring index is a mask (crates/net/net/src/
    //     udp.rs asserts the same at compile time).
    //   SUP_RESTART_BURST: crates/core/sched/src/supervisor.rs keeps at most
    //     SUP_BURST_MAX = 16 restart times and clamps a larger burst silently.
    //   CONSOLE_TX_RING_BYTES: console_defer.rs defers every kernel line that
    //     finds less than LINE_RESERVE (256) bytes of room.
    //   MAX_IO_RINGS: a Cap<IoRing> packs the ring index in 8 bits.
    // Absent keys (a .config from before wave 11) are not checked.
    // -----------------------------------------------------------------------
    if let Some(slots) = get_u64(cfg, "UDP_RX_SLOTS") {
        if !slots.is_power_of_two() {
            panic!("validation FAIL: UDP_RX_SLOTS ({slots}) is not a power of two. \
                    Fix: set it to 2, 4, 8, 16, 32 or 64.");
        }
    }
    if let Some(burst) = get_u64(cfg, "SUP_RESTART_BURST") {
        if !(1..=16).contains(&burst) {
            panic!("validation FAIL: SUP_RESTART_BURST ({burst}) outside 1..=16 \
                    (SUP_BURST_MAX in crates/core/sched/src/supervisor.rs).");
        }
    }
    if let Some(ring) = get_u64(cfg, "CONSOLE_TX_RING_BYTES") {
        if ring < 1024 {
            panic!("validation FAIL: CONSOLE_TX_RING_BYTES ({ring}) < 1024: every kernel \
                    console line would be deferred (LINE_RESERVE is 256).");
        }
    }
    //   ROBOT_TYPE_ID: safety.rs narrows it to u8 before its own assert.
    if let Some(id) = get_u64(cfg, "ROBOT_TYPE_ID") {
        if id > 3 {
            panic!("validation FAIL: ROBOT_TYPE_ID ({id}) names no robot type \
                    (0 wheeled, 1 drone, 2 humanoid, 3 ackermann).");
        }
    }
    if let Some(rings) = get_u64(cfg, "MAX_IO_RINGS") {
        if !(2..=256).contains(&rings) {
            panic!("validation FAIL: MAX_IO_RINGS ({rings}) outside 2..=256 \
                    (one task may hold half; the index is packed in 8 bits).");
        }
    }

    // -----------------------------------------------------------------------
    // LOG_LEVEL (config/Kconfig.development): the kernel's log macros
    // (crates/drivers/sys/src/uart.rs) compare it against Linux's numbers,
    // so any other value would silently compile a level in or out. It must
    // also be the one the LOG_LEVEL_* choice selected: a hand-edited
    // CONFIG_LOG_LEVEL that disagrees with the choice is refused rather
    // than letting the number win.
    // -----------------------------------------------------------------------
    let log_level = get_u64_required(cfg, "LOG_LEVEL");
    let chosen: Vec<(&str, u64)> = [("LOG_LEVEL_ERR", 3), ("LOG_LEVEL_WARN", 4),
                                    ("LOG_LEVEL_INFO", 6), ("LOG_LEVEL_DEBUG", 7)]
        .into_iter()
        .filter(|(k, _)| get_bool(cfg, k))
        .collect();
    if ![3, 4, 6, 7].contains(&log_level) {
        panic!("validation FAIL: LOG_LEVEL ({log_level}) is not a kernel log level: \
                3 (err), 4 (warn), 6 (info) or 7 (debug). Fix: pick one of the \
                LOG_LEVEL_* choices (`make menuconfig`, \"Development & Debug\").");
    }
    if chosen.len() != 1 || chosen[0].1 != log_level {
        panic!("validation FAIL: LOG_LEVEL ({log_level}) does not match the LOG_LEVEL_* \
                choice ({chosen:?}). Fix: set exactly one LOG_LEVEL_* and run \
                `python3 -m olddefconfig`.");
    }

    if let (Some(sched_hz), Some(sched_hz_floor)) =
        (get_u64(cfg, "SCHED_HZ"), get_u64(cfg, "SCHED_HZ_FLOOR"))
    {
        if sched_hz_floor > sched_hz {
            panic!(
                "validation FAIL: SCHED_HZ_FLOOR ({sched_hz_floor}) > SCHED_HZ ({sched_hz}). \
                 CONFIG.INI's sched_hz floor cannot exceed this board/profile's compile-time \
                 ceiling, or every CONFIG.INI request would be rejected as garbage. \
                 Fix: lower SCHED_HZ_FLOOR in config/Kconfig.timing or raise SCHED_HZ in .config."
            );
        }
    }

    // -----------------------------------------------------------------------
    // FAT32 block cache geometry (wave 14): 512 B lines in sets of 8, the set
    // count a power of two. A size that is not 0 or a power of two from 4 KiB
    // would leave lines past the last whole power-of-two set count unused, so
    // it is refused rather than silently rounded down.
    // -----------------------------------------------------------------------
    if let Some(kb) = get_u64(cfg, "FS_BLOCK_CACHE_KB") {
        if kb != 0 && (kb < 4 || !kb.is_power_of_two()) {
            panic!(
                "validation FAIL: FS_BLOCK_CACHE_KB ({kb}) must be 0 or a power of two \
                 from 4 (crates/fs/fs/src/bcache.rs: 8-way sets, a power-of-two set count). \
                 Fix: set FS_BLOCK_CACHE_KB to 0, 4, 8, 16, ... in .config."
            );
        }
    }
}
