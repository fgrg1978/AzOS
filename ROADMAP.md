# Roadmap

This is where AzOS is going: the direction and the order of the work. It
describes intent, not progress. There are no dates. What exists today is
described in [`ARCHITECTURE.md`](ARCHITECTURE.md), and only there.

## Next

**Memory foundation.**
- One descriptor per physical frame, in place of today's separate bitmap and
  refcount tables. It carries the owner, pin state and offset of the frame.
- Fault-around for anonymous memory, then transparent 2 MiB pages.
- A pager for file-backed `mmap`, with the reclaim and memory-pressure policy
  designed in from the start.

**One hardware-support model on every ISA.**
- Each architecture has one compile-time baseline, the only thing generated
  code may assume.
- Every extension above the baseline is probed at boot and has a fallback.
- A board declares what it has in `make config`.

riscv64 already works this way. aarch64 and x86_64 follow the same rules,
and a CPU that lacks the baseline refuses to boot with a clear message.

**x86_64.** The port continues from its skeleton:
- memory and paging;
- ACPI and the local and I/O APICs;
- traps and the timer;
- user mode;
- SMP;
- virtio devices.

The first target is QEMU `microvm`.

## Then

**Linux drivers in ring 3.**
- Capability delegation across tasks, with attenuation and revocation.
- DMA capabilities backed by a per-driver IOMMU domain.
- The client protocol of the Linux-driver server, with out-of-line memory and
  no-senders notifications.
- A first useful Linux driver running there, outside the kernel.

**Real-time and scheduling.**
- Scheduling-context donation on the fast IPC call, so that a server runs on
  its client's time and priority.
- Load balancing at run time: idle CPUs take ready work that is neither
  pinned nor in a real-time band.

## Later

- **File authority by directory handle:** a task reaches files through the
  directories it was granted, not through global paths.
- **A crash-consistent, checksummed volume** for logs, crash reports, the
  device record and update state. FAT32 stays the boot medium.
- **Less `unsafe`:** a per-crate ratchet, then `forbid(unsafe_code)` in the
  system-call, IPC, file-system, network and topology crates.

## Hardware

- Bring-up on StarFive VisionFive 2 and SpacemiT K1.
- Address-space identifiers.
- Energy-aware task placement, timer slack and power hints.
- Cache maintenance and timing measured on silicon, not only under QEMU.

## How the order is chosen

Dependencies come first, then measured value. Each step closes with
evidence:
- a benchmark path compared against Linux on the same harness, or a test
  that fails when the property is broken;
- a canary that proves the check discriminates;
- the full check script.
