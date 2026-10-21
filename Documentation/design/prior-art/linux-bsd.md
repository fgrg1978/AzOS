# Prior art: Linux and BSD kernel mechanisms

This page records a small set of mechanisms in the Linux and BSD kernels that
are relevant to the design of this kernel. Every item was checked against the
upstream project's own documentation; the URL is given per section. The page
describes other projects as their documentation states them. It is not a
comparison and makes no claim about this tree.

## sched_ext: scheduling policy loaded as BPF

sched_ext is a Linux scheduler class whose behaviour is defined by a BPF
program implementing `struct sched_ext_ops`. The program can be loaded and
unloaded at runtime. If the BPF scheduler misbehaves (an error or a stall),
the kernel reverts the affected tasks to the default fair scheduling class.
Example schedulers live in the `sched_ext` directory under `tools` in the Linux tree, and the
feature is selected with `CONFIG_SCHED_CLASS_EXT`. The release notes for
Linux 6.12 list the first pieces of sched_ext as part of that release.

Source: https://docs.kernel.org/scheduler/sched-ext.html and
https://kernelnewbies.org/Linux_6.12

## PREEMPT_RT in mainline

The Linux 6.12 release notes record the real-time preemption patchset as
merged into mainline, so a stock kernel can be configured for real-time
preemption.

Source: https://kernelnewbies.org/Linux_6.12

## Kexec HandOver and the Live Update Orchestrator

Kexec HandOver (KHO) preserves selected memory regions across a kexec reboot.
The old kernel describes the preserved state to the new kernel with a
flattened device tree, and reserves scratch memory so the new kernel has
contiguous space to boot into without overwriting preserved pages.

The Live Update Orchestrator (LUO) builds on KHO to update a running kernel
while keeping chosen userspace state and devices alive:

- user space groups file descriptors into named sessions through
  `/dev/liveupdate`;
- file types that carry state (memfd, vfio, iommufd are named in the
  documentation) register handlers that save and restore it, and files can be
  restored in any order;
- objects shared between files, such as core IOMMU state, are saved once when
  the first dependent file is preserved and restored once;
- all LUO state sits under one KHO entry, and the feature is enabled with the
  `liveupdate=on` boot parameter;
- the serialized format is versioned by compatibility strings, and only
  kernels using the same ABI version are guaranteed to interoperate.

Source: https://docs.kernel.org/core-api/kho/index.html and
https://docs.kernel.org/core-api/liveupdate.html

## Landlock: unprivileged sandboxing, versioned by ABI number

Landlock lets an unprivileged process restrict its own access. The user-space
documentation lists the capabilities added by each ABI version:

| ABI | Addition |
|---|---|
| 1 | filesystem access control (first introduced in Linux 5.13) |
| 2 | `LANDLOCK_ACCESS_FS_REFER`, linking or renaming across directories |
| 3 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | TCP bind and connect rules |
| 5 | `LANDLOCK_ACCESS_FS_IOCTL_DEV`, ioctl on character and block devices |
| 6 | scoping of abstract UNIX sockets and signals |
| 7 | control over audit logging of denials |
| 8 | `LANDLOCK_RESTRICT_SELF_TSYNC`, enforcing a ruleset on all threads of a process |
| 9 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, pathname UNIX socket connections |
| 10 | UDP bind and connect/send rules, and a per-object quiet flag for audit |
| 11 | `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS`, no_new_privs set only if enforcement succeeds |

The document gives a kernel version only for ABI 1.

Source: https://docs.kernel.org/userspace-api/landlock.html

## Rust in the Linux kernel

The kernel documentation lists the architectures where Rust support is
maintained, with the constraints that apply: arm (ARMv7 little-endian),
arm64 (little-endian), loongarch, riscv (riscv64 with LLVM/Clang), s390
(`CONFIG_EXPOLINE` disabled), um, and x86 (x86_64 only). Support depends on
`rustc`'s LLVM-based code generation, on LLVM/Clang kernel builds, and on
`bindgen`. The Linux 6.18 release notes list the Rust Binder driver
(`rust_binder`) under the Rust changes.

Source: https://docs.kernel.org/rust/arch-support.html and
https://kernelnewbies.org/Linux_6.18

## OpenBSD: `hw.blockcpu`

OpenBSD's `sysctl(2)` manual documents `hw.blockcpu`, a string that a
privileged process can change. Each letter names a CPU type the scheduler
should avoid placing tasks on: S for SMT threads, P for performance cores,
E for efficiency cores, and L for low-power efficiency cores. The manual
states that it replaces the deprecated `hw.smt` variable.

Source: https://man.openbsd.org/sysctl.2
