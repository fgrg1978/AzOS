// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Prints the board's ELF service list, one FAT32 name per line, sorted.
//!
//! Owner decision 2026-09-24: an ELF ships on a board's FAT32 volume iff the
//! topology declares a service it provides. This binary IS that query — it
//! is not a second list to keep in sync, it just reads
//! `crates/core/topology/src/builder.rs::default_minimal()` and prints every
//! `TaskSpec` name that ends in `.ELF`.
//!
//! Run with NO Cargo feature on (`cargo run -q --bin board_elfs`, the
//! default in this crate) to get the BOARD list: no board build turns on
//! `cap-refusal-canary` / `ipc-endpoint-canary` / `profile-actuation` (see
//! `crates/core/topology/Cargo.toml`, each feature's own doc comment says which
//! kernel build wires it and that none of them is `vf2`/`k1`), so a board
//! build is exactly this crate's own default feature set. Running WITH
//! `ipc-endpoint-canary` additionally prints `EPSRV.ELF`/`VSSRV.ELF` — the
//! two IPC canary rows — which is correct for a QEMU gate topology and
//! wrong for a board one; the Makefile never passes that feature here.
//!
//! `Makefile`'s `build/board_elfs.list` target runs this and treats a
//! non-zero exit (a `cargo` failure: this crate did not build) as fatal,
//! same as any other build step — no silent empty list.
//!
//! `tools/gen_board_manifest.py` consumes this binary's stdout.

fn main() {
    let topo = azos_topology::default_minimal();
    let mut names: Vec<&str> = topo
        .tasks()
        .iter()
        .map(|task| task.name.as_str())
        .filter(|n| n.ends_with(".ELF"))
        .collect();
    names.sort_unstable();
    names.dedup();
    for n in names {
        println!("{n}");
    }
}
