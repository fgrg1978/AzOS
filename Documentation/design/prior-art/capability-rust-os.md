# Prior art: capability, microkernel and Rust operating systems

This page records design points of several open capability-oriented,
microkernel and Rust operating-system projects, limited to what each project
states in its own public pages or papers. The URL is given per section. The
page describes other projects as they describe themselves. It is not a
comparison and makes no claim about this tree.

## seL4: verification roadmap and system frameworks

The seL4 roadmap page lists three verification efforts:

- verification of the mixed-criticality scheduling (MCS) kernel: the page
  reports the C-level proofs as complete for RISC-V and listed for AArch64 as
  upcoming work;
- automated verification of platform ports, aimed at letting ports be verified
  without proof experts; the page reports support for all Arm platforms;
- verification of the multikernel configuration (one kernel per core), listed
  as a later target.

On the systems side, the page lists Microkit, an OS framework for building
seL4-based systems, and LionsOS, an OS built on Microkit with an initial
release and a non-trivial example system.

Source: https://sel4.systems/roadmap.html

## Genode: roadmap themes

The Genode roadmap page groups its planned work under a "Building bridges"
theme for interoperability with other projects, languages and user groups.
Items it lists include client-budgeted DMA buffer allocation, power and
thermal management in the `base-hw` kernel, a dynamically reconfigurable
virtual file system with GUI access as a virtual file system, pre-boot
platform discovery, IPv6 for native components, and USB access control at
interface granularity. The page presents these as roadmap items and does not state their delivery
status.

Source: https://genode.org/about/road-map

## Redox: capabilities in the namespace and working directory

A Redox project post describes two changes toward capability-based access:

- the kernel no longer holds scheme names or the namespace; a userspace
  daemon (`nsmgr`) resolves scheme names, and a process's namespace is a file
  descriptor rather than an integer identifier held by the kernel;
- the current working directory is kept as a file descriptor next to its path
  string, so relative paths resolve through the descriptor. The post says this
  enables `O_RESOLVE_BENEATH` and restricting absolute-path access through the
  namespace.

Source: https://redox-os.org/news/nlnet-cap-nsmgr-cwd

## Asterinas: the framekernel

Asterinas is a Rust kernel built on a "framekernel" design. The whole kernel
runs in one address space, split into a privileged framework, OSTD (the
`ostd` crate), which may use `unsafe`, and unprivileged services, which must
be safe Rust. The project states that all `unsafe` code is confined to OSTD
and that the rest, device drivers included, is safe Rust, so the kernel's memory safety
rests on the framework. It aims to run Linux applications
unmodified.

The USENIX ATC paper describes the framekernel and its Linux-compatible
system-call layer; the paper's own pages are the reference for details.

Source: https://asterinas.github.io/ and
https://www.usenix.org/conference/atc25/presentation/peng-yuke

## Tock: stable Rust and application credentials

The Tock 2.2 release notes state that nightly-only features were removed from
the core kernel crates so the kernel can build on the stable Rust toolchain
(one board was switched over first and others still built on nightly at that
release). The same release added application identifiers, credentials and
storage permissions, which let a Tock kernel identify, verify and restrict
applications, including a process checker that verifies signatures.

Source: https://github.com/tock/tock/releases
