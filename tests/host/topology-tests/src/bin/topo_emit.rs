// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Writes the built-in topology as `CAPS.TOM` and `SCHED.TOM`, the two files
//! a kernel loads, verifies and installs instead of it (Kconfig
//! `TOPOLOGY_SOURCE`).
//!
//! ```text
//!   topo_emit <CAPS.TOM out> <SCHED.TOM out> [--device <32 hex>] [--counter <N>]
//! ```
//!
//! The topology is `azos_topology::fill_default_minimal`, the one a kernel
//! builds into its image, so the build must match the kernel's: the same
//! `KCONFIG_CONFIG` (row budgets and limits come from it) and the topology
//! features the kernel's own features turn on, plus `emit-target-riscv64` or
//! `emit-target-aarch64` for the rows only a kernel of that ISA declares.
//! `make topology-files` / `make topo-volume` pass all three.
//!
//! CAPS.TOM is format 4 and always names `sched_sha256`, the SHA-256 of the
//! SCHED.TOM written next to it (the one signature, CAPS.SIG, covers both).
//! `--device` and `--counter` add the other two binding keys
//! (`azos_topology::Binding`); `make` passes the image's device id and
//! `TOPO_COUNTER`.
//!
//! The text is read back before the program exits 0: the binding is parsed
//! and compared, the files are parsed (`parse_sched`, then `parse_caps`, as
//! the kernel does), admitted, and compared field by field with the built-in
//! topology (`azos_topology::emit::first_difference`). A difference exits 1
//! and names the field, so no file is shipped that the kernel would install as
//! a different topology.

use std::process::exit;

use azos_topology::{emit, Binding, Topology};

struct Args {
    caps_out: String,
    sched_out: String,
    device: Option<[u8; 16]>,
    counter: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = std::env::args().skip(1);
    let caps_out = a.next().ok_or("missing <CAPS.TOM out>")?;
    let sched_out = a.next().ok_or("missing <SCHED.TOM out>")?;
    let (mut device, mut counter) = (None, None);
    while let Some(flag) = a.next() {
        let v = a.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--device" => {
                if v.len() != 32 {
                    return Err("--device takes 32 hex digits".into());
                }
                let mut id = [0u8; 16];
                for (i, b) in id.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).map_err(|_| "--device: bad hex")?;
                }
                device = Some(id);
            }
            "--counter" => {
                let n: u64 = v.parse().map_err(|_| "--counter takes a number")?;
                if n == 0 {
                    return Err("--counter must be at least 1".into());
                }
                counter = Some(n);
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    Ok(Args { caps_out, sched_out, device, counter })
}

fn run(args: Args) -> Result<(), String> {
    let mut built = Box::new(Topology::empty());
    azos_topology::fill_default_minimal(&mut built);
    let mut sched = String::new();
    emit::emit_sched(&built, &mut sched).map_err(|e| format!("SCHED.TOM: {e:?}"))?;
    let binding = Binding {
        format: emit::EMIT_FORMAT,
        device: args.device,
        counter: args.counter,
        sched_sha256: Some(azos_crypto::sha256::sha256(sched.as_bytes())),
    };
    let mut caps = String::new();
    emit::emit_caps(&built, &binding, &mut caps).map_err(|e| format!("CAPS.TOM: {e:?}"))?;

    let read = azos_topology::parse_binding(caps.as_bytes())
        .map_err(|e| format!("the binding does not parse back: {e:?}"))?;
    if read != binding {
        return Err(format!("the binding reads back as {read:?}, not {binding:?}"));
    }
    let mut parsed = Box::new(Topology::empty());
    azos_topology::parse_sched(sched.as_bytes(), &mut parsed)
        .map_err(|e| format!("SCHED.TOM does not parse back: {e:?}"))?;
    azos_topology::parse_caps(caps.as_bytes(), &mut parsed)
        .map_err(|e| format!("CAPS.TOM does not parse back: {e:?}"))?;
    parsed.admission_check().map_err(|e| format!("the parsed topology is not admitted: {e:?}"))?;
    if let Some(field) = emit::first_difference(&built, &parsed) {
        return Err(format!("the parsed topology differs from the built-in one: {field}"));
    }
    std::fs::write(&args.caps_out, caps.as_bytes()).map_err(|e| format!("{}: {e}", args.caps_out))?;
    std::fs::write(&args.sched_out, sched.as_bytes()).map_err(|e| format!("{}: {e}", args.sched_out))?;
    println!(
        "topo_emit: {} classes, {} tasks, {} grants, counter {} -> {} ({} B), {} ({} B)",
        built.classes_len(), built.tasks_len(), built.caps_pool_len(),
        args.counter.map_or("none".to_string(), |c| c.to_string()),
        args.caps_out, caps.len(), args.sched_out, sched.len(),
    );
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("topo_emit: {why}");
            eprintln!("usage: topo_emit <CAPS.TOM out> <SCHED.TOM out> [--device <32 hex>] [--counter <N>]");
            exit(2);
        }
    };
    // A `Topology` is sized by the limits (megabytes on the fleet profile);
    // two of them do not fit the default main-thread stack.
    let worker = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || run(args))
        .expect("spawn the emitter thread");
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(why)) => {
            eprintln!("topo_emit: {why}");
            exit(1);
        }
        Err(_) => exit(1),
    }
}
