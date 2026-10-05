// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! build.rs for `azos_drv_sys` (RFC-0027 Phase I1.2)
//!
//! Walks every `.rs` file under `crates/*/src/` looking for `#[wcet(...)]`
//! attribute annotations in source (NOT for `__WCET_DECL_` markers which
//! live in the compiled IR, not the source text).
//!
//! For each annotation found it:
//! 1. Derives a module-qualified name from the file path and the function name
//!    on the next `pub fn` / `fn` line after the attribute.
//!    (`behavior/src/auth_envelope.rs` + fn `wrap` → `auth_envelope_wrap`).
//! 2. Sorts all discovered entries by module-qualified name (deterministic IDs
//!    across rebuilds — `bench/baselines.json` references these IDs).
//! 3. Assigns IDs starting at `FIRST_GENERATED_POINT_ID` (= 9, the first slot
//!    after the 9 currently hard-coded fixed points in wcet.rs).
//! 4. Emits `wcet_points_generated.rs` into `OUT_DIR`; `src/wcet.rs` includes
//!    it from there, so nothing is generated into the source tree.
//! 5. Writes `crates/drivers/sys/wcet_points.json` (committed) only when its
//!    content changes, through a temp file in the same directory and a rename.
//!    AzOSRobotBrain's `tools/bench_e2e_collect.py` reads it by this path, so
//!    the file must not move or be renamed.
//!
//! **Stable IDs**: sorting by module-qualified name before assignment means
//! IDs don't shift when new annotations are added to other modules — only
//! newly inserted names between two existing sorted names would renumber, and
//! that is a conscious trade-off documented in RFC-0027 §Detailed design.
//!
//! ## Why scan source (not markers)?
//!
//! The `__WCET_DECL_` side-channel constants are emitted by the proc-macro
//! into the compiled binary — they are NOT present as text in the `.rs`
//! source files.  The build script (host-side) has access only to source
//! text, not to compiled artefacts from other crates.  Scanning for
//! `#[wcet(` in source is reliable, fast, and dependency-free.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    // ── Locate workspace root ────────────────────────────────────────────────
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // CARGO_MANIFEST_DIR = <workspace>/crates/drivers/sys
    let workspace_root = manifest_dir
        .parent()      // crates/drivers/
        .and_then(|p| p.parent())  // crates/
        .and_then(|p| p.parent())  // workspace root
        .expect("could not determine workspace root from CARGO_MANIFEST_DIR");

    // ── Rerun directives ─────────────────────────────────────────────────────
    // Rerun if ANY Rust source under crates/ changes so new annotations are
    // picked up automatically.  We emit per-file directives below once we
    // know which files exist.
    println!("cargo:rerun-if-changed=build.rs");

    // ── Scan for #[wcet(...)] annotations ─────────────────────────────────────
    // Collect BTreeMap<module_qualified_name, (bare_fn_name, budget_us)>.
    // BTreeMap gives sorted iteration for stable ID assignment.
    let mut entries: BTreeMap<String, (String, u32)> = BTreeMap::new();

    // Every directory that used to live under crates/ is still scanned, or the WCET point
    // IDs (assigned in sorted order) would silently shift: domains/robot/* (behavior...) and
    // tests/host/*, tests/qemu/* were crates/* before the restructure.
    for scan_root in ["crates", "domains", "tests/host", "tests/qemu"] {
        let crates_dir = workspace_root.join(scan_root);
        if crates_dir.exists() {
            scan_dir(&crates_dir, workspace_root, &mut entries);
        }
    }

    // ── Fixed point metadata (IDs 0-8) ───────────────────────────────────────
    // These IDs are hard-coded in wcet.rs and must not be disturbed.
    let fixed_points = [
        "pid_loop",
        "sensor_read",
        "ctx_switch",
        "timer_isr",
        "actuator_write",
        "net_send",
        "cnn_infer",
        "lidar_scan",
        "path_plan",
    ];
    // First generated ID = one past the last fixed point.
    const FIRST_GENERATED_POINT_ID: u8 = 9;

    // ── Assign IDs ────────────────────────────────────────────────────────────
    // `entries` maps module_qualified_name → (fn_bare_name, budget_us).
    // IDs are assigned sorted by module_qualified_name for stability.
    let generated: Vec<(u8, String, String, u32)> = entries
        .into_iter()
        .enumerate()
        .map(|(i, (qualified_name, (fn_name, budget)))| {
            let id = FIRST_GENERATED_POINT_ID + i as u8;
            (id, qualified_name, fn_name, budget)
        })
        .collect();

    // ── Emit wcet_points_generated.rs into OUT_DIR ───────────────────────────
    //
    // POINT_* const name is derived from the BARE FUNCTION NAME (upper-snake),
    // matching what the proc-macro emits in the function body:
    //   `fn wrap` → `POINT_WRAP`
    //   `fn motor_pid_step` → `POINT_MOTOR_PID_STEP`
    //
    // The module-qualified name is stored in WCET_FN_NAMES for the JSON
    // index and for human-readable bench output.
    //
    // Into OUT_DIR, as `crates/core/limits` does, never into `src/`. Written into the
    // source tree it raced between two builds of one checkout, and because the
    // walk above lists every `.rs` under `crates/` as a rerun trigger, each run
    // re-armed this script's own rerun.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let generated_rs_path = out_dir.join("wcet_points_generated.rs");
    let mut rs_out = String::new();
    rs_out.push_str("// GENERATED by crates/drivers/sys/build.rs — do not edit.\n");
    rs_out.push_str("// Source of truth: #[wcet(...)] annotations in crates/*/src/.\n");
    rs_out.push_str("// Committed index: crates/drivers/sys/wcet_points.json\n");
    rs_out.push('\n');

    for (id, qualified, fn_name, budget) in &generated {
        // POINT_WRAP, POINT_MOTOR_PID_STEP, etc. — derived from bare fn name.
        let const_name = format!("POINT_{}", fn_name.to_uppercase().replace('-', "_"));
        rs_out.push_str(&format!(
            "/// WCET point: `{qualified}` (id={id}, budget={budget}µs). Generated by build.rs.\n"
        ));
        rs_out.push_str(&format!("pub const {const_name}: u8 = {id};\n"));
    }

    rs_out.push('\n');
    rs_out.push_str(
        "/// All generated WCET measurement points: (id, qualified_name, budget_us).\n",
    );
    rs_out.push_str("/// `qualified_name` is `<module>_<fn>` for human-readable bench output.\n");
    rs_out.push_str(
        "pub const WCET_FN_NAMES: &[(u8, &str, u32)] = &[\n",
    );
    for (id, qualified, _fn_name, budget) in &generated {
        rs_out.push_str(&format!("    ({id}, \"{qualified}\", {budget}),\n"));
    }
    rs_out.push_str("];\n");

    // Unchanged content is not rewritten and keeps its mtime.
    write_if_changed(&generated_rs_path, &rs_out);

    // ── Emit wcet_points.json (committed) ────────────────────────────────────
    //
    // Tracked, so it is written only when its content changes: an unchanged
    // file keeps its mtime and never shows in `git status`. The write goes
    // through a temp file and a rename, so a second build of the same checkout
    // reads the old file or the new one, never a truncated one.
    let json_path = manifest_dir.join("wcet_points.json");
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"schema_version\": 1,\n");

    // Fixed points array
    json.push_str("  \"fixed_points\": [");
    for (i, name) in fixed_points.iter().enumerate() {
        if i > 0 { json.push_str(", "); }
        json.push_str(&format!("\"{}\"", name));
    }
    json.push_str("],\n");

    // Generated points array — use module-qualified name in JSON for readability.
    json.push_str("  \"generated_points\": [\n");
    for (idx, (id, qualified, _fn_name, budget)) in generated.iter().enumerate() {
        let comma = if idx + 1 < generated.len() { "," } else { "" };
        json.push_str(&format!(
            "    {{\"id\": {id}, \"name\": \"{qualified}\", \"budget_us\": {budget}}}{comma}\n"
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");

    write_if_changed(&json_path, &json);
}

/// Write `content` to `path` unless the file already holds exactly that.
///
/// The new content goes to `<name>.tmp.<pid>` in the same directory and is
/// renamed over `path`. A rename within one directory replaces the file in one
/// step, so no reader sees it half-written; the pid keeps two concurrent
/// builds off each other's temp file. The temp file is removed when the write
/// or the rename fails.
fn write_if_changed(path: &Path, content: &str) {
    if fs::read(path).map_or(false, |old| old == content.as_bytes()) {
        return;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| panic!("drivers/build.rs: no file name in {}", path.display()));
    let tmp = path.with_file_name(format!("{name}.tmp.{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, content) {
        let _ = fs::remove_file(&tmp);
        panic!("drivers/build.rs: could not write {}: {e}", tmp.display());
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        panic!("drivers/build.rs: could not rename {} to {}: {e}", tmp.display(), path.display());
    }
}

// ── File walker ───────────────────────────────────────────────────────────────

/// Recursively walk `dir`, scanning every `.rs` file for `#[wcet(...)]` annotations.
/// Emits `cargo:rerun-if-changed=<path>` for each file found.
fn scan_dir(dir: &Path, workspace_root: &Path, entries: &mut BTreeMap<String, (String, u32)>) {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Build output is not source: skip every `target` directory and
            // the "target 2" copies iCloud makes of them. Several are symlinks
            // into a shared build tree (`is_dir` follows them) holding
            // generated `.rs` files such as `azos_limits`' `generated.rs`,
            // and listing those as rerun triggers re-ran this script after any
            // host test build that rewrote one.
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dir_name == "target" || dir_name.starts_with("target ") {
                continue;
            }
            scan_dir(&path, workspace_root, entries);
        } else if path.extension().map_or(false, |e| e == "rs") {
            // A file whose stem is not a Rust identifier ("uart 2.rs", the
            // copies iCloud leaves beside a file it failed to sync) can never
            // be a module, so its annotations are not code. Scanning one
            // defined every WCET point in it twice (E0428, gate 194).
            let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
            if !stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            scan_file(&path, workspace_root, entries);
        }
    }
}

/// Scan a single `.rs` file for `#[wcet(N_us)]` attribute annotations.
///
/// Derives a module-qualified name from the file path + function name:
///   - `domains/robot/behavior/src/auth_envelope.rs` + fn `wrap` → `auth_envelope_wrap`
///
/// Budget normalisation mirrors the proc-macro:
///   - no suffix / `us`  → identity
///   - `ns`              → `(n + 999) / 1000`  (round up)
///   - `cycles`          → `(n + 9) / 10`       (10 MHz QEMU virt)
fn scan_file(path: &Path, _workspace_root: &Path, entries: &mut BTreeMap<String, (String, u32)>) {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,  // binary or non-UTF8 file — skip
    };

    // Derive the module name from the file stem (e.g. "auth_envelope").
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // For "mod.rs" / "lib.rs" use the parent directory name instead.
    let module_name = if file_stem == "mod" || file_stem == "lib" {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or(file_stem)
            .to_string()
    } else {
        file_stem.to_string()
    };

    // Scan line-by-line; no regex dependency.
    // We look for `#[wcet(` and then peek at the next non-blank, non-attribute
    // line to find the function name.
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i].trim();

        if !line.starts_with("#[wcet(") {
            i += 1;
            continue;
        }

        // Extract the argument inside `#[wcet(...)]`.
        // Handles single-line only; multi-line attributes are not supported
        // by this scanner (the proc-macro supports them, but annotation
        // style guidelines recommend single-line for #[wcet(...)]).
        let arg_str = if let Some(inner) = line.strip_prefix("#[wcet(") {
            inner.trim_end_matches(']').trim_end_matches(')')
        } else {
            i += 1;
            continue;
        };

        let budget_us = parse_budget_arg(arg_str);

        // Find the function name on a following line.
        // Skip blank lines and other attribute lines (#[...]).
        let fn_name = find_next_fn_name(&lines, i + 1);

        if let Some(fn_name) = fn_name {
            // Module-qualified name: "<module>_<fn_name>" for sorting & JSON.
            // If fn_name already starts with module_name, don't double it.
            let qualified = if fn_name.starts_with(&module_name) {
                fn_name.clone()
            } else {
                format!("{module_name}_{fn_name}")
            };
            // Store (bare_fn_name, budget_us); qualified name is the map key.
            entries.insert(qualified, (fn_name, budget_us));
        }

        i += 1;
    }
}

/// Parse `#[wcet(...)]` argument string (e.g. "100_us", "50", "200ns") and
/// return the budget normalised to microseconds.
fn parse_budget_arg(s: &str) -> u32 {
    // Strip underscores used as digit separators in the numeric part.
    // E.g. "100_000_us" → "100000_us"
    // Strategy: split on the first alphabetic character.
    let s = s.trim();

    // Find where the numeric part ends (digits + leading underscores).
    let (num_part, suffix) = split_num_suffix(s);

    // Remove internal underscores (digit separators: 1_000 → 1000).
    let num_clean: String = num_part.chars().filter(|c| *c != '_').collect();
    let raw: u32 = num_clean.parse().unwrap_or(0);

    match suffix {
        "us" | "" => raw,
        "ns" => raw.saturating_add(999) / 1000,
        "cycles" => raw.saturating_add(9) / 10,
        _ => raw, // unknown suffix — treat as µs (conservative)
    }
}

/// Split "100_us" → ("100_", "us"), "50" → ("50", ""), "200ns" → ("200", "ns").
fn split_num_suffix(s: &str) -> (&str, &str) {
    // Find the index of the first alphabetic character that is NOT preceded
    // by an underscore used as a digit separator.
    // Heuristic: underscore separating digits from suffix is the last underscore
    // before an alphabetic run.
    // Examples:
    //   "100_us"    → split at index 3 (after "100") → num="100_", suffix="us"
    //   "100us"     → split at index 3                → num="100",  suffix="us"
    //   "1_000_000" → all digits + underscores        → num="1_000_000", suffix=""
    //   "50cycles"  → split at index 2                → num="50", suffix="cycles"

    let bytes = s.as_bytes();
    let mut i = 0usize;

    // Skip leading digits and underscores (digit group separators).
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() || c == '_' {
            i += 1;
        } else {
            break;
        }
    }

    // i is now at the start of the suffix (or end-of-string).
    // Trim a trailing underscore from the numeric part (the separator `_` in `100_us`).
    let num_end = if i > 0 && bytes[i - 1] == b'_' { i - 1 } else { i };
    (&s[..num_end], &s[i..])
}

/// Find the function name from `lines[start..]`, skipping blank lines and
/// attribute lines (`#[...]`).  Returns `None` if no `fn` declaration found
/// within the next 10 lines.
fn find_next_fn_name(lines: &[&str], start: usize) -> Option<String> {
    let limit = (start + 10).min(lines.len());
    for j in start..limit {
        let line = lines[j].trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // Look for a line containing `fn ` keyword.
        if let Some(fn_pos) = line.find("fn ") {
            let after_fn = &line[fn_pos + 3..];
            // Extract identifier up to `(` or `<` or whitespace.
            let name: String = after_fn
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
        // Bail if we hit something that's clearly not an attribute or fn decl.
        if line.starts_with("pub") || line.starts_with("unsafe") ||
           line.starts_with("async") || line.starts_with("fn") ||
           line.starts_with("extern")
        {
            // Already handled above or not a fn — stop looking.
            break;
        }
    }
    None
}
