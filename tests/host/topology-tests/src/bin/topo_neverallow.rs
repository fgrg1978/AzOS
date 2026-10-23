// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Runs the `neverallow` rules (`azos_topology::neverallow`) over the built-in
//! topology of one configuration.
//!
//! ```text
//!   topo_neverallow                       # the built-in topology
//!   topo_neverallow <CAPS.TOM> <SCHED.TOM> # a topology file pair
//! ```
//!
//! The pair is parsed as the loader parses it (signature and binding are not
//! looked at: `topo_emit` and the gate cover those). The micro kernel's
//! topology (`tools/micro_topology.py`) is checked this way.
//!
//! Like `topo_emit`, the built-in topology is
//! `azos_topology::fill_default_minimal`, so the build must match the kernel's: the same `KCONFIG_CONFIG` (the image's
//! domain, `USE_DESKTOP`, and the limits come from it), the topology features
//! the kernel's features turn on, and `emit-target-riscv64`,
//! `emit-target-aarch64` or `emit-target-x86_64` for the rows only a kernel of
//! that ISA declares.
//! `tools/check_neverallow.py` (`make check-neverallow`) does that for every
//! preset. The rules run whatever Kconfig `TOPOLOGY_NEVERALLOW` says: the
//! option is the kernel's switch, not the checker's.
//!
//! Exits 0 and prints `neverallow: ok` when no rule is broken; exits 1 and
//! prints the rule, the row and the grant when one is.

use std::process::exit;

use azos_topology::neverallow::{self, Env};
use azos_topology::Topology;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut topo = Box::new(Topology::empty());
    match args.as_slice() {
        [] => azos_topology::fill_default_minimal(&mut topo),
        [caps, sched] => {
            let read = |path: &String| std::fs::read(path).unwrap_or_else(|e| {
                eprintln!("topo_neverallow: {path}: {e}");
                exit(2);
            });
            // The buffers live as long as the topology borrows them: the
            // process.
            let (caps, sched): (&'static [u8], &'static [u8]) =
                (Vec::leak(read(caps)), Vec::leak(read(sched)));
            if let Err(e) = azos_topology::parse_sched(sched, &mut topo) {
                eprintln!("topo_neverallow: SCHED.TOM does not parse: {e:?}");
                exit(2);
            }
            if let Err(e) = azos_topology::parse_caps(caps, &mut topo) {
                eprintln!("topo_neverallow: CAPS.TOM does not parse: {e:?}");
                exit(2);
            }
        }
        _ => {
            eprintln!("usage: topo_neverallow [<CAPS.TOM> <SCHED.TOM>]");
            exit(2);
        }
    }
    let env = Env::BUILD;
    match neverallow::check(&topo, &env) {
        Ok(()) => println!(
            "neverallow: ok ({} rules, {} rows, {} grants, desktop={})",
            neverallow::RULES.len(), topo.tasks_len(), topo.caps_pool_len(), env.desktop,
        ),
        Err(r) => {
            let row = &topo.tasks()[r.row as usize];
            println!(
                "neverallow: REFUSED rule {} ({}): row {} ({}), grant {} of kind code {}: {}",
                r.rule, r.rule().id, r.row, row.name.as_str(), r.grant, r.kind, r.rule().text,
            );
            exit(1);
        }
    }
}
