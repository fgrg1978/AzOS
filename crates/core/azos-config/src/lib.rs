// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos-config` — build-time Kconfig reader and Rust const emitter
//!
//! RFC-0026 Phase C2 implementation.
//!
//! # Usage (Phase C2 onwards)
//!
//! In `crates/core/limits/build.rs`:
//!
//! ```ignore
//! use azos_config::{parse_config, emit_rust};
//! use std::collections::HashMap;
//!
//! fn main() {
//!     let cfg = parse_config(".config").expect("no .config — run `make defconfig-edge`");
//!     let mut out = String::new();
//!     emit_rust(&cfg, &mut out, "abcdef012345");  // 12-char SHA-256 prefix
//!     std::fs::write(&format!("{}/generated.rs", std::env::var("OUT_DIR").unwrap()), out).unwrap();
//! }
//! ```

use std::collections::HashMap;

/// Key→value map of all `CONFIG_*` entries from a `.config` file.
///
/// Keys are stored **without** the `CONFIG_` prefix (stripped on parse).
/// Values are unquoted strings (e.g. `"y"`, `"512"`, `"edge"`, `"10.0.2.2"`).
pub type ConfigMap = HashMap<String, String>;

/// Error type for configuration parsing failures.
#[derive(Debug)]
pub enum ConfigError {
    /// The `.config` file could not be opened or read.
    Io(std::io::Error),
    /// A line in the file does not conform to `CONFIG_KEY=value` format.
    ParseError { line: usize, text: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error reading .config: {e}"),
            ConfigError::ParseError { line, text } => {
                write!(f, ".config parse error at line {line}: {text:?}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

/// Parse a kconfiglib-generated `.config` file into a [`ConfigMap`].
///
/// Each non-comment, non-blank line must be either:
/// - `CONFIG_FOO=value`  — a set option.
/// - `# CONFIG_FOO is not set` — an unset bool option (stored as `"n"`).
///
/// Keys are stored **without** the `CONFIG_` prefix.
/// String values have surrounding double-quotes stripped.
/// Bool `y` options store `"y"`; unset bools store `"n"`.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] if the file cannot be read, or
/// [`ConfigError::ParseError`] if an unexpected line format is found.
pub fn parse_config(path: &str) -> Result<ConfigMap, ConfigError> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut cfg = ConfigMap::new();

    for (idx, line_result) in reader.lines().enumerate() {
        let line_num = idx + 1;
        let line = line_result?;
        let trimmed = line.trim();

        // Skip blank lines
        if trimmed.is_empty() {
            continue;
        }

        // Handle "# CONFIG_FOO is not set" — unset bool, store as "n"
        if let Some(rest) = trimmed.strip_prefix("# CONFIG_") {
            if let Some(key) = rest.strip_suffix(" is not set") {
                cfg.insert(key.to_string(), "n".to_string());
            }
            // Other comment lines (section headers, etc.) are silently skipped.
            continue;
        }

        // Skip other comment lines (e.g. `# Deployment Profile`)
        if trimmed.starts_with('#') {
            continue;
        }

        // Parse CONFIG_KEY=value
        if !trimmed.starts_with("CONFIG_") {
            return Err(ConfigError::ParseError {
                line: line_num,
                text: line.clone(),
            });
        }

        let body = &trimmed["CONFIG_".len()..];
        let eq_pos = body.find('=').ok_or_else(|| ConfigError::ParseError {
            line: line_num,
            text: line.clone(),
        })?;

        let key = &body[..eq_pos];
        let raw_val = &body[eq_pos + 1..];

        // Strip outer double-quotes from string values (kconfiglib format).
        let value = if raw_val.starts_with('"') && raw_val.ends_with('"') && raw_val.len() >= 2 {
            raw_val[1..raw_val.len() - 1].to_string()
        } else {
            raw_val.to_string()
        };

        cfg.insert(key.to_string(), value);
    }

    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Type inference for Rust const emission
// ---------------------------------------------------------------------------

/// Determine the Rust integer type for a config key based on its name suffix.
///
/// Mapping (longest-suffix-first to avoid false matches):
/// - `_HZ`         → `u32`    (scheduler/timer frequencies)
/// - `_MS`         → `u64`    (millisecond durations)
/// - `_US`         → `u64`    (microsecond durations)
/// - `_TICKS`      → `u64`    (hardware timer ticks; can exceed u32)
/// - `_BYTES`      → `usize`  (buffer sizes)
/// - `_KB`         → `usize`  (sizes in KiB, before ×1024 expansion)
/// - `_MB`         → `usize`  (sizes in MiB, before ×1024×1024 expansion)
/// - `_SIZE`       → `usize`  (generic size)
/// - `_COUNT`      → `usize`  (table / slot counts)
/// - `_ATTEMPTS`   → `u32`    (retry counters)
/// - `_PROBES`     → `u32`    (keepalive probe count)
/// - `_MULT`       → `u32`    (multipliers)
/// - `_MM`         → `u32`    (millimetre measurements)
/// - `_FREQ`       → `u32`    (hardware frequencies)
/// - `_CPUS`       → `u32`    (CPU counts)
/// - default       → `usize`
fn infer_int_type(key: &str) -> &'static str {
    // Array lengths named like counts: `NR_CPUS` sizes every per-CPU table
    // and must not take the `_CPUS` suffix's u32 below.
    if key == "NR_CPUS" {
        return "usize";
    }
    // Longest-suffix-first to avoid partial matches.
    let suffixes: &[(&str, &str)] = &[
        ("_ATTEMPTS", "u32"),
        ("_PROBES", "u32"),
        ("_MULT", "u32"),
        ("_TICKS", "u64"),
        ("_BYTES", "usize"),
        ("_SIZE", "usize"),
        ("_COUNT", "usize"),
        ("_FREQ", "u32"),
        ("_CPUS", "u32"),
        ("_HZ", "u32"),
        ("_MS", "u64"),
        ("_US", "u64"),
        ("_KB", "usize"),
        ("_MB", "usize"),
        ("_MM", "u32"),
    ];
    for (suffix, ty) in suffixes {
        if key.ends_with(suffix) {
            return ty;
        }
    }
    "usize"
}

/// Options whose values must be multiplied before emission.
///
/// Returns `(rust_name, scale_factor)`.  The scale is applied to the raw
/// integer value before writing the const literal.
///
/// Handles the config/Kconfig.limits pattern where `KERNEL_HEAP_SIZE` is stored
/// in KiB but consumers want bytes.
fn byte_expanded_key(key: &str) -> Option<(&'static str, u64)> {
    match key {
        // KERNEL_HEAP_SIZE is declared in KiB in config/Kconfig.limits
        "KERNEL_HEAP_SIZE"    => Some(("KERNEL_HEAP_SIZE_BYTES",    1024)),
        // Explicit KB suffixed stack sizes
        "USER_STACK_SIZE_KB"        => Some(("USER_STACK_SIZE_BYTES",        1024)),
        "KERNEL_STACK_SIZE_KB"      => Some(("KERNEL_STACK_SIZE_BYTES",      1024)),
        "INTERRUPT_STACK_SIZE_KB"   => Some(("INTERRUPT_STACK_SIZE_BYTES",   1024)),
        "SECONDARY_STACK_SIZE_KB"   => Some(("SECONDARY_STACK_SIZE_BYTES",   1024)),
        // OTA image size
        "OTA_MAX_IMAGE_SIZE_MB"     => Some(("OTA_MAX_IMAGE_SIZE_BYTES", 1024 * 1024)),
        _ => None,
    }
}

/// Emit a Rust source file containing `pub const` declarations for every
/// option in `cfg`.
///
/// - Int options → `pub const FOO: <type> = <value>;`
/// - Bool options → `pub const FOO: bool = true/false;`
/// - Hex options (0x…) → `pub const FOO: usize = 0x…;`
/// - String options → `pub const FOO: &str = "<value>";`
/// - Byte-expanded keys (KERNEL_HEAP_SIZE, stack sizes, OTA size) emit
///   an *additional* `_BYTES` constant with the expanded value, alongside
///   the raw constant.
///
/// The `config_sha12` parameter is the first 12 hex characters of the
/// SHA-256 of the `.config` file, embedded in the header comment so
/// audit logs can match a binary to a config snapshot.
pub fn emit_rust(cfg: &ConfigMap, out: &mut String, config_sha12: &str) {
    out.push_str("// GENERATED by crates/core/azos-config from .config — DO NOT EDIT.\n");
    out.push_str(&format!(
        "// Config SHA-256 prefix: {config_sha12} — use `sha256sum .config` to verify.\n"
    ));
    out.push_str("//\n");
    out.push_str("// Each Kconfig integer/bool/string option becomes a `pub const`.\n");
    out.push_str("// Change values via `make menuconfig` or `make defconfig-<profile>`.\n");
    out.push('\n');
    // Note: inner attributes (#![...]) are not valid inside include!().
    // Consumers suppress dead_code at the use site or in lib.rs.


    // Collect and sort keys for deterministic output.
    let mut keys: Vec<&String> = cfg.keys().collect();
    keys.sort();

    for key in keys {
        let val = &cfg[key];
        emit_single_const(key, val, out);
    }
}

/// Emit a single `pub const` (or a pair for byte-expanded keys).
fn emit_single_const(key: &str, val: &str, out: &mut String) {
    // Hex values (0x… prefix)
    if val.starts_with("0x") || val.starts_with("0X") {
        // Parse as u64 to avoid overflow; emit as usize (addresses/bases).
        match u64::from_str_radix(&val[2..], 16) {
            Ok(_n) => {
                // Emit raw hex literal for readability
                out.push_str(&format!("pub const {key}: usize = {val};\n"));
            }
            Err(_) => {
                out.push_str(&format!("// WARN: could not parse hex value for {key}: {val}\n"));
            }
        }
        return;
    }

    // Bool values: "y" → true, "n" → false
    if val == "y" || val == "n" {
        let bool_val = val == "y";
        out.push_str(&format!("pub const {key}: bool = {bool_val};\n"));
        return;
    }

    // Integer values (pure decimal)
    if let Ok(n) = val.parse::<u64>() {
        let rust_type = infer_int_type(key);
        out.push_str(&format!("pub const {key}: {rust_type} = {n};\n"));

        // Emit additional byte-expanded const if this key needs it.
        if let Some((expanded_name, scale)) = byte_expanded_key(key) {
            let expanded_val = n.saturating_mul(scale);
            out.push_str(&format!("pub const {expanded_name}: usize = {expanded_val};\n"));
        }
        return;
    }

    // String values (everything else)
    // Escape any remaining double-quotes or backslashes in the value.
    let escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
    out.push_str(&format!("pub const {key}: &str = \"{escaped}\";\n"));
}

// ---------------------------------------------------------------------------
// Kconfig declarations: the bools a .config may legitimately leave out
// ---------------------------------------------------------------------------

/// One `config` entry of the Kconfig tree, as far as [`hidden_bools`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KconfigSymbol {
    pub name: String,
    /// `bool` (or `def_bool`).
    pub is_bool: bool,
    /// The entry has a prompt and nothing can hide it: no enclosing `if`,
    /// no `menu ... visible if/depends on`, no `choice ... depends on`, no
    /// `depends on` of its own and no `if` on its prompt. kconfiglib writes
    /// such a symbol to every `.config` (a bool as `=y` or `is not set`).
    pub always_written: bool,
}

/// Read the Kconfig tree rooted at `root_dir/kconfig`, following `source`
/// lines (paths relative to `root_dir`, as kconfiglib resolves them from the
/// directory it runs in). A line-level reader for the subset this tree uses;
/// it is not a Kconfig parser.
pub fn read_kconfig_tree(root_dir: &std::path::Path, kconfig: &str)
    -> std::io::Result<(Vec<KconfigSymbol>, Vec<std::path::PathBuf>)>
{
    let mut syms = Vec::new();
    let mut files = Vec::new();
    // Block stack: true = the block can hide what it contains.
    let mut stack: Vec<bool> = Vec::new();
    read_one(root_dir, kconfig, &mut stack, &mut syms, &mut files)?;
    Ok((syms, files))
}

fn read_one(
    root_dir: &std::path::Path,
    rel: &str,
    stack: &mut Vec<bool>,
    syms: &mut Vec<KconfigSymbol>,
    files: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    let path = root_dir.join(rel);
    let text = std::fs::read_to_string(&path)?;
    files.push(path);
    // The entry being read, and whether the block header just opened may
    // still take a `visible if` / `depends on` line.
    let mut cur: Option<KconfigSymbol> = None;
    let mut cur_cond = false;
    let mut cur_prompt = false;
    let mut header_open = false;
    let flush = |cur: &mut Option<KconfigSymbol>, cond: bool, prompt: bool,
                 syms: &mut Vec<KconfigSymbol>| {
        if let Some(mut s) = cur.take() {
            s.always_written = !cond && prompt;
            syms.push(s);
        }
    };
    // Help text runs while lines are indented deeper than its `help` line.
    let mut help_indent: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim();
        let indent = raw.len() - raw.trim_start().len();
        if let Some(h) = help_indent {
            if line.is_empty() || indent > h {
                continue;
            }
            help_indent = None;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let word = line.split_whitespace().next().unwrap_or("");
        if word == "help" || word == "---help---" {
            help_indent = Some(indent);
            continue;
        }
        let rest = line[word.len()..].trim();
        match word {
            "source" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                header_open = false;
                let inner = rest.trim_matches('"');
                read_one(root_dir, inner, stack, syms, files)?;
            }
            "config" | "menuconfig" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                header_open = false;
                cur = Some(KconfigSymbol {
                    name: rest.to_string(),
                    is_bool: false,
                    always_written: false,
                });
                cur_cond = stack.iter().any(|c| *c);
                cur_prompt = false;
            }
            "menu" | "choice" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                stack.push(false);
                header_open = true;
            }
            "if" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                stack.push(true);
                header_open = false;
            }
            "endmenu" | "endchoice" | "endif" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                stack.pop();
                header_open = false;
            }
            "comment" | "mainmenu" => {
                flush(&mut cur, cur_cond, cur_prompt, syms);
                header_open = false;
            }
            "visible" | "depends" => {
                if let Some(_) = cur {
                    cur_cond = true;
                } else if header_open {
                    if let Some(top) = stack.last_mut() {
                        *top = true;
                    }
                }
            }
            "bool" | "def_bool" | "int" | "hex" | "string" | "tristate" | "prompt" => {
                if let Some(s) = cur.as_mut() {
                    if word == "bool" || word == "def_bool" {
                        s.is_bool = true;
                    }
                    // A quoted prompt on the type line, or a `prompt` line.
                    if (word == "prompt" || rest.starts_with('"')) && word != "def_bool" {
                        cur_prompt = true;
                        // `bool "text" if COND`: everything after the closing quote.
                        let after = rest.rsplit('"').next().unwrap_or("");
                        if after.trim_start().starts_with("if ") {
                            cur_cond = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, cur_cond, cur_prompt, syms);
    Ok(())
}

/// Every declared `bool` that a valid `.config` may leave out: kconfiglib
/// writes nothing for a bool that is n and hidden (an enclosing `if`, a
/// `visible if` menu, a `depends on`). Its value is n all the same, and a
/// crate that reads the const must still compile, so `crates/core/limits`
/// emits these as `false` when `.config` omits them. A bool that is always
/// written is NOT listed: if a `.config` lacks one, it predates the Kconfig
/// tree, and a consumer of that const should fail to compile rather than
/// read a silent `false`.
pub fn hidden_bools(syms: &[KconfigSymbol]) -> Vec<String> {
    let mut out: Vec<String> = syms
        .iter()
        .filter(|s| s.is_bool && !s.always_written)
        .map(|s| s.name.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_str(content: &str) -> ConfigMap {
        use std::time::{SystemTime, UNIX_EPOCH};
        let dir = std::env::temp_dir();
        // Use a unique file name per call to avoid races between parallel tests.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // Include thread ID for uniqueness when multiple tests run simultaneously.
        let tid = std::thread::current().id();
        let path = dir.join(format!("azos_config_test_{ts}_{tid:?}.config"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        drop(f);
        let result = parse_config(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn test_parse_simple_int() {
        let cfg = parse_str("CONFIG_MAX_TASKS=64\n");
        assert_eq!(cfg["MAX_TASKS"], "64");
    }

    #[test]
    fn test_parse_bool_y() {
        let cfg = parse_str("CONFIG_ARCH_RISCV64=y\n");
        assert_eq!(cfg["ARCH_RISCV64"], "y");
    }

    #[test]
    fn test_parse_bool_not_set() {
        let cfg = parse_str("# CONFIG_ARCH_AARCH64 is not set\n");
        assert_eq!(cfg["ARCH_AARCH64"], "n");
    }

    #[test]
    fn test_parse_string_unquoted() {
        let cfg = parse_str("CONFIG_BRAIN_SERVER_IP_DEFAULT=\"10.0.2.2\"\n");
        // Quotes must be stripped
        assert_eq!(cfg["BRAIN_SERVER_IP_DEFAULT"], "10.0.2.2");
    }

    #[test]
    fn test_parse_blank_and_comment_lines() {
        let content = "\n# Architecture\nCONFIG_ARCH_RISCV64=y\n\n# end of Architecture\n";
        let cfg = parse_str(content);
        assert_eq!(cfg["ARCH_RISCV64"], "y");
        // Comment header lines should not appear as keys
        assert!(!cfg.contains_key("Architecture"));
    }

    #[test]
    fn test_emit_int() {
        let mut cfg = ConfigMap::new();
        cfg.insert("MAX_TASKS".to_string(), "64".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const MAX_TASKS: usize = 64;"));
    }

    #[test]
    fn test_emit_bool_true() {
        let mut cfg = ConfigMap::new();
        cfg.insert("ARCH_RISCV64".to_string(), "y".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const ARCH_RISCV64: bool = true;"));
    }

    #[test]
    fn test_emit_bool_false() {
        let mut cfg = ConfigMap::new();
        cfg.insert("ARCH_AARCH64".to_string(), "n".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const ARCH_AARCH64: bool = false;"));
    }

    #[test]
    fn test_emit_string() {
        let mut cfg = ConfigMap::new();
        cfg.insert("BRAIN_SERVER_IP_DEFAULT".to_string(), "10.0.2.2".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains(r#"pub const BRAIN_SERVER_IP_DEFAULT: &str = "10.0.2.2";"#));
    }

    #[test]
    fn test_emit_hex() {
        let mut cfg = ConfigMap::new();
        cfg.insert("UART_BASE".to_string(), "0x10000000".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const UART_BASE: usize = 0x10000000;"));
    }

    #[test]
    fn test_emit_kernel_heap_size_expanded() {
        let mut cfg = ConfigMap::new();
        cfg.insert("KERNEL_HEAP_SIZE".to_string(), "32768".to_string()); // 32 MiB in KiB
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const KERNEL_HEAP_SIZE: usize = 32768;"));
        assert!(out.contains(&format!(
            "pub const KERNEL_HEAP_SIZE_BYTES: usize = {};",
            32768_u64 * 1024
        )));
    }

    #[test]
    fn test_emit_user_stack_size_expanded() {
        let mut cfg = ConfigMap::new();
        cfg.insert("USER_STACK_SIZE_KB".to_string(), "16".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains("pub const USER_STACK_SIZE_BYTES: usize = 16384;"));
    }

    #[test]
    fn test_emit_ota_max_image_size_expanded() {
        let mut cfg = ConfigMap::new();
        cfg.insert("OTA_MAX_IMAGE_SIZE_MB".to_string(), "8".to_string());
        let mut out = String::new();
        emit_rust(&cfg, &mut out, "000000000000");
        assert!(out.contains(&format!(
            "pub const OTA_MAX_IMAGE_SIZE_BYTES: usize = {};",
            8_u64 * 1024 * 1024
        )));
    }

    #[test]
    fn test_infer_int_type() {
        assert_eq!(infer_int_type("SCHED_HZ"), "u32");
        assert_eq!(infer_int_type("RTO_INITIAL_MS"), "u64");
        assert_eq!(infer_int_type("WCET_BOUND_PID_US"), "u64");
        assert_eq!(infer_int_type("KEEPALIVE_INTERVAL_TICKS"), "u64");
        assert_eq!(infer_int_type("TCP_BUF_SIZE"), "usize");
        assert_eq!(infer_int_type("KERNEL_HEAP_SIZE"), "usize");
        assert_eq!(infer_int_type("OTA_SLOT_COUNT"), "usize");
        assert_eq!(infer_int_type("MAX_TASKS"), "usize");
    }

    fn tree(files: &[(&str, &str)]) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("azos_kc_{}_{ts}", std::process::id()));
        std::fs::create_dir_all(dir.join("config")).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn test_hidden_bools_follow_visibility() {
        let dir = tree(&[
            ("Kconfig", "mainmenu \"t\"\nsource \"config/Kconfig.a\"\nconfig TOP\n    bool \"top\"\n    default y\n"),
            ("config/Kconfig.a", concat!(
                "menu \"Hidden\"\n    visible if TOP\nconfig IN_VISIBLE_IF\n    bool \"x\"\nconfig INT_IN_VISIBLE_IF\n    int \"n\"\n    default 3\nendmenu\n",
                "menu \"Plain\"\nconfig PLAIN\n    bool \"p\"\n    help\n      if this line were read, PLAIN would look hidden\n      source \"nowhere\"\n\n      menu text\nconfig DEP\n    bool \"d\"\n    depends on TOP\nconfig PROMPT_IF\n    bool \"q\" if TOP\nconfig NOPROMPT\n    bool\n    default y if TOP\nendmenu\n",
                "choice\n    prompt \"c\"\nconfig CH_A\n    bool \"a\"\nconfig CH_B\n    bool \"b\"\nendchoice\n",
                "if TOP\nconfig IN_IF\n    bool \"i\"\nendif\n",
            )),
        ]);
        let (syms, files) = read_kconfig_tree(&dir, "Kconfig").unwrap();
        assert_eq!(files.len(), 2);
        let hidden = hidden_bools(&syms);
        assert_eq!(hidden, vec!["DEP", "IN_IF", "IN_VISIBLE_IF", "NOPROMPT", "PROMPT_IF"]);
        // always written: TOP, PLAIN and the members of an unconditional choice
        for name in ["TOP", "PLAIN", "CH_A", "CH_B"] {
            assert!(syms.iter().any(|s| s.name == name && s.always_written), "{name}");
        }
        // an int is never in the bool list, wherever it is
        assert!(!hidden.iter().any(|n| n == "INT_IN_VISIBLE_IF"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hidden_bools_on_the_real_tree() {
        // CARGO_MANIFEST_DIR = crates/core/azos-config
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let (syms, _) = read_kconfig_tree(&root, "Kconfig").expect("read the Kconfig tree");
        let hidden = hidden_bools(&syms);
        // The Robot menu is `visible if DOMAIN_ROBOT`; the brain link is in it.
        assert!(hidden.iter().any(|n| n == "MULTISTREAM_SCHED_PRIORITY"));
        assert!(hidden.iter().any(|n| n == "ROBOT_DRONE"));
        // A top-level switch is always written: never filled in.
        assert!(!hidden.iter().any(|n| n == "CONTROL_TXN_TICKS"));
        assert!(!hidden.iter().any(|n| n == "DOMAIN_GENERIC"));
        // Wave 11 (DOMAIN): the brain-link enforcement switches exist only in
        // the Robot domain, so a Generic .config leaves them out and limits
        // must fill them as n; the domain choice itself is always written
        // (kernel/src/main.rs reads DOMAIN_ROBOT in its build guard), and so
        // is the camera switch IoT-HMI implies.
        assert!(hidden.iter().any(|n| n == "LINK_AUTH_ENFORCED"));
        assert!(hidden.iter().any(|n| n == "LINK_ENCRYPT_ENFORCED"));
        assert!(!hidden.iter().any(|n| n == "DOMAIN_ROBOT"));
        assert!(!hidden.iter().any(|n| n == "DRV_CAMERA"));
    }

    #[test]
    fn test_emit_domain_robot_both_ways() {
        // The kernel's build guard reads `azos_limits::DOMAIN_ROBOT`: it
        // must be emitted as a bool whichever way the .config sets it.
        for (line, want) in [("CONFIG_DOMAIN_ROBOT=y", "pub const DOMAIN_ROBOT: bool = true;"),
                             ("# CONFIG_DOMAIN_ROBOT is not set", "pub const DOMAIN_ROBOT: bool = false;")] {
            let cfg = parse_str(line);
            let mut out = String::new();
            emit_rust(&cfg, &mut out, "test");
            assert!(out.contains(want), "{line}: {out}");
        }
    }

}
