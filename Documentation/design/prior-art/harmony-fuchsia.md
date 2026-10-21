# Prior art: HongMeng and Fuchsia

This page records design points of two other systems, the HongMeng
microkernel (as described in its OSDI paper) and the Fuchsia platform (as
described in its public documentation and RFCs). Every item was checked
against the primary source named in its section. The page is not a
comparison and makes no claim about this tree.

## HongMeng: a general-purpose multi-server microkernel

Architecture, as the paper states it:

- the core kernel keeps the thread scheduler, serial and timer drivers, and
  access control; the other OS components are isolated services outside it;
- Linux API/ABI compatibility comes from a shim that identifies Linux system
  calls and redirects them to IPC;
- unmodified Linux drivers are reused through a driver container that
  provides a Linux runtime, with "twin drivers" that separate the control
  plane from the data plane to avoid critical-path performance degradation.

Problems the authors report when going from domain-specific to general
workloads:

- IPC frequency rises sharply once all services are isolated in user space.
- State is double-bookkept across servers, which costs time and memory
  compared with a monolithic design.
- Hiding frequently updated kernel objects behind capabilities makes
  anonymous page-fault handling slower.
- A big kernel lock did not scale on phones, which the paper attributes to a
  high system-call rate and to long-running operations such as `poll` and
  energy-aware scheduling decisions.
- The number of drivers grows with the range of device classes supported,
  and rewriting them for the new kernel is impractical, which motivates reuse.

Techniques the paper describes in response:

- **Isolation classes.** IC0 is for verified, performance-critical services
  with no isolation from the kernel (the ABI shim is the only IC0 service
  mentioned). IC1 places validated services in kernel space and enforces
  separation with hardware domain mechanisms (ARM watchpoints, Intel PKS) plus
  binary scanning and control-flow integrity. IC2 uses ordinary address-space
  isolation and is for non-critical or third-party code such as Linux
  drivers. The paper notes IC1 widens the attack surface and is limited by
  the number of hardware domains (16 with PKS, 4 with ARM watchpoints).
- **RPC-like IPC fast path.** Services register a handler and a stack pool;
  on a call the kernel switches directly to the handler (no scheduling pass),
  switching only the stack and instruction pointers and the protection
  domain, and pops an invocation stack on return.
- **Address tokens.** An OS-internal mechanism that supplements capabilities
  for co-managing kernel objects such as page tables. The paper states that
  tokens cannot restrict fine-grained operations and do not support chain
  revocation, and that they are not exposed as an application-level
  abstraction.

Source: https://www.usenix.org/system/files/osdi24-chen-haibo.pdf
(the observations, design and lessons sections).

## Fuchsia: component framework capability routing

In Component Framework v2 a capability must have a valid route from its
provider to its consumer. Three declarations form the route: `offer` passes a
capability from a parent down to a child, `expose` makes a capability
available from a component or its child to the parent, and `use` declares a
capability that a running component needs in its namespace. The
documentation states that offers between components must not form a cycle,
checked between parent and child and between siblings. Its suggested remedies
are to mark one link `dependency: "weak"` (weak links are excluded from cycle
detection and shutdown ordering), to split a component, or to invert a
dependency.

Source: https://fuchsia.dev/fuchsia-src/concepts/components/v2/capabilities

## Fuchsia: devfs retirement for driver connections (Fuchsia RFC 263)

The accepted RFC moves non-driver clients from devfs paths to aggregated
services mediated by the component manager. Reasons it gives include that
devfs connections are unknown to the component manager and so cannot be used
for dependency tracking, that devfs allows only one protocol per device
instance with the type not explicitly defined, and that services let a client
request a specific service instead of reaching any driver by topological
path. The RFC states that devfs's internal implementation can be removed
once drivers and clients have migrated.

Source: Fuchsia RFC 263, "Migrate driver communication to services", in the
governance section of fuchsia.dev.

## Fuchsia: running Linux programs (Starnix, Fuchsia RFC 82 and 261)

RFC 82 proposes Starnix, a userspace program that implements the Linux
system interface so unmodified Linux binaries run on Fuchsia, translating
Linux calls into calls on Fuchsia services. The RFC compares alternatives:
a Linux kernel in a virtual machine (not chosen as the primary design, though
a VM path is still planned in parallel), an in-process library, and an
in-kernel implementation (avoided to keep the kernel simpler). It notes that
the initial syscall mechanism, based on Zircon exceptions, is expected to be
slow and is to be replaced, that running in user space adds a context switch,
and that WSL1's file-system performance is a cautionary comparison.

RFC 261 adds "restricted mode", a third execution mode in which guest code
runs while a supervisor in normal mode receives its system calls and faults,
without hypervisor hardware. The RFC states the aim is a faster Starnix
runner and acknowledges added kernel complexity, a mode-switch cost above a
native one, changed relationships between kernel objects, and a need to
update debugging and memory tools.

Source: Fuchsia RFC 82, "Starnix", and RFC 261, "Fast and efficient user
space kernel emulation", in the governance section of fuchsia.dev.
