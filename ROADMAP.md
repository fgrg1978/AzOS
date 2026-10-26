# Roadmap

The direction of the work, by area. It states intent: there is no schedule, and
it is not a list of what exists. What the tree does today is described in
[`ARCHITECTURE.md`](ARCHITECTURE.md) and in [`Documentation/README.md`](Documentation/README.md);
the `help` text of each option in `config/Kconfig.*` says what that option
covers and leaves out.

## Direction

| Area | Direction | Where it lives |
|---|---|---|
| One feature set on every ISA | Every feature lands on riscv64, aarch64 and x86_64 together, under the same hardware-support model: a compile-time baseline per ISA, and each extension above it probed at boot with a fallback. | `crates/core/arch-api/src/isa.rs`, `config/arch/Kconfig.isa` |
| Memory | Reclaim and memory-pressure policy, file-backed paging through the page cache, and larger pages. | `crates/core/mm`, `config/limits/Kconfig.limits` |
| Real time | Admission and budgets for every kind of time a task consumes, including interrupt handlers and time spent in servers on a client's behalf. | `crates/core/sched`, `config/kernel/Kconfig.sched` |
| Driver placement | Drivers that run in ring 3 or move between ring 3 and the kernel, and Linux driver modules running in ring-3 servers under DMA and capability limits. | `crates/core/topology/src/placement.rs`, `lx/`, `config/axes/Kconfig.personality` |
| File authority | A task reaches files through the directory handles it was granted, not through global paths. | `crates/core/abi/src/invoke.rs`, `crates/fs` |
| Storage | A crash-consistent, checksummed volume for logs, crash reports, the device record and update state, beside FAT32 as the boot medium. | `crates/fs/src/azvol` |
| Less `unsafe` | A per-crate ratchet on `unsafe`, then `forbid(unsafe_code)` in the crates that can take it. | `crates/` |
| Native interfaces | More of the device and service surface as IDL interfaces on endpoints, with the SDK and the relibc port built on them. | `crates/core/idl`, `crates/core/devif`, `sdk/` |

## How the order is chosen

Dependencies come first, then measured value. A step is finished when it has:

- a test that fails when the property is broken, or a benchmark path compared
  against Linux on the same harness (`tools/bench/vsbench_compare.sh`),
- a canary that shows the check can fail,
- a pass of the full check, `make ci`.
