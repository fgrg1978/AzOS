// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_sim`: the host dry boot of a topology (`make sim`).
//!
//! ```text
//!   azos_sim [--cpus <N>] [--check-log <boot log>] builtin
//!   azos_sim [--cpus <N>] [--check-log <boot log>] <dir holding CAPS.TOM and SCHED.TOM>
//! ```
//!
//! `builtin` is `azos_topology::fill_default_minimal`, the topology a kernel
//! built with the same `KCONFIG_CONFIG` and topology features carries; a
//! directory is a pair `make topology-files` writes (its signature is not
//! checked). `--cpus` is the board's CPU count, or QEMU's `-smp`; without it
//! Kconfig `NR_CPUS`, which is a ceiling, is used. Prints the records the boot
//! would write and what it would refuse (`azos_sim::write_report`); exits 0
//! when the boot goes past admission, 1 when it would not, 2 on a usage error.
//!
//! `--check-log` holds the dry boot to a real boot of the same kernel on
//! `--cpus` harts instead (the gate row "topology: dry boot matches the
//! boot"): exits 0 when the boot's console shows the same install verdict,
//! records and refusal (`azos_sim::check_boot_log`), 1 when it does not.

use std::process::exit;

use azos_topology::Topology;

fn usage(why: &str) -> ! {
    eprintln!("azos_sim: {why}");
    eprintln!("usage: azos_sim [--cpus <N>] [--check-log <boot log>] <builtin | dir with CAPS.TOM and SCHED.TOM>");
    exit(2);
}

fn main() {
    let mut cpus = None;
    let mut topology = None;
    let mut check_log = None;
    let mut a = std::env::args().skip(1);
    while let Some(arg) = a.next() {
        match arg.as_str() {
            "--cpus" => {
                let v = a.next().unwrap_or_else(|| usage("--cpus needs a value"));
                match v.parse::<usize>() {
                    Ok(n) if (1..=azos_topology::deadline::MAX_ADMISSION_CPUS).contains(&n) => cpus = Some(n),
                    _ => usage("--cpus takes 1..=32"),
                }
            }
            "--check-log" => check_log = Some(a.next().unwrap_or_else(|| usage("--check-log needs a file"))),
            _ if topology.is_none() => topology = Some(arg),
            _ => usage(&format!("unexpected argument {arg}")),
        }
    }
    let topology = topology.unwrap_or_else(|| usage("missing the topology"));
    let files = (topology != "builtin").then(|| {
        let read = |f: &str| std::fs::read(format!("{topology}/{f}")).unwrap_or_else(|e| usage(&format!("{topology}/{f}: {e}")));
        (read("CAPS.TOM"), read("SCHED.TOM"))
    });
    let boot = check_log.map(|f| {
        let log = std::fs::read(&f).unwrap_or_else(|e| usage(&format!("{f}: {e}")));
        let cpus = cpus.unwrap_or_else(|| usage("--check-log needs --cpus, the harts the boot ran on"));
        azos_sim::read_boot_log(&String::from_utf8_lossy(&log), cpus).unwrap_or_else(|why| {
            println!("check-log: {f}: {why}");
            exit(1)
        })
    });
    let (cpus, cpus_from) = match cpus {
        Some(n) => (n, "--cpus"),
        None => ((azos_limits::NR_CPUS as usize).min(azos_topology::deadline::MAX_ADMISSION_CPUS), "Kconfig NR_CPUS, a ceiling: pass --cpus"),
    };
    // A `Topology` is sized by the limits (megabytes on the fleet profile):
    // it does not fit the default main-thread stack.
    let worker = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || {
            let d = match &files {
                Some((caps, sched)) => azos_sim::dry_boot_files(caps, sched, cpus),
                None => {
                    let mut t = Box::new(Topology::empty());
                    azos_topology::fill_default_minimal(&mut t);
                    azos_sim::dry_boot(&t, cpus)
                }
            };
            let mut out = String::new();
            azos_sim::write_report(&d, &mut out).expect("format the report");
            let ok = match &boot {
                Some(b) => match azos_sim::check_boot_log(&d, b) {
                    Ok(()) => {
                        out += &format!("check-log: the boot matches: {} record(s)\n", d.receipts.len());
                        true
                    }
                    Err(why) => {
                        out += &format!("check-log: MISMATCH: {why}\n");
                        false
                    }
                },
                None => d.boots(),
            };
            (ok, out)
        })
        .expect("spawn the dry-boot thread");
    let Ok((ok, out)) = worker.join() else { exit(1) };
    println!("azos sim: {topology} topology on {cpus} CPU(s) ({cpus_from})");
    print!("{out}");
    exit(if ok { 0 } else { 1 });
}
