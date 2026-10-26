# Security

This document describes the security mechanisms present in the source tree and
where each one lives. It describes mechanisms, not guarantees.

Related documents: [update.md](update.md) for the update chain that the signed
artefacts below feed, [network.md](network.md) for the socket capabilities and
packet filter, [observability.md](observability.md) for the decision records
every refusal here produces.

| Area | Main source |
|------|-------------|
| Capabilities and the syscall boundary | `crates/core/abi/src/cap.rs`, `crates/core/ipc/src/cap.rs`, `crates/core/syscall/src/invoke.rs` |
| Per-image syscall filters | `crates/core/sched/src/seccomp.rs`, `crates/core/sched/src/filter.rs` |
| Control-flow integrity | `arch/aarch64/src/cpu/cfi.rs`, `arch/x86_64/src/cpu/cfi.rs`, `config/subsys/Kconfig.topology` |
| Speculation mitigations | `arch/x86_64/src/ext/mitigations.rs`, `arch/aarch64/src/ext/mitigations.rs`, `crates/core/limits/src/nospec.rs`, `config/axes/Kconfig.security` |
| Secure boot, signed artefacts | `crates/core/ota/src/secure_boot.rs`, `crates/core/ota/src/update.rs`, `crates/core/topology/src/verify.rs`, `crates/core/topology/src/signed.rs`, `crates/core/pkg/src` |
| Crypto primitives | `crates/core/crypto/src` |
| Entropy, TPM | `crates/core/crypto/src/entropy.rs`, `kernel/src/boot/entropy.rs`, `crates/drivers/tpm/src`, `kernel/src/boot/tpm.rs` |
| Node identity, link keys | `crates/core/crypto/src/dice.rs`, `crates/core/syscall/src/link_key.rs`, `crates/core/crypto/src/secure_channel.rs`, `userspace/lib/rpc/src/chan.rs` |
| Memory protection, DMA | `crates/core/mm/src/wx.rs`, `kernel/src/boot/early.rs`, `crates/core/sched/src/elf_bounds.rs`, `kernel/src/boot/dma.rs` |

Several of the checks below are build options, and the defaults differ by
build type. `BUILD_TYPE` is `DEV` on `BOARD_QEMU` and `RELEASE` on every other
board (`config/axes/Kconfig.build`):

| Kconfig symbol | Default | Turns on |
|----------------|---------|----------|
| `SECURE_BOOT_ENFORCED` | `y` unless `BUILD_TYPE_DEV`; forced on `BUILD_TYPE_CERTIFIABLE` | Refusing an unverified kernel image at boot and at OTA install |
| `LINK_PROVISIONING_ENFORCED` | `n`; the `vf2` and `k1` board features build it in | No boot without a link key, no handshake on an unseeded pool, no UART bridge |
| `CONSOLE_LOCKDOWN` | `n` | No recovery console; every authority-table row checked |
| `TOPOLOGY_SOURCE` | signed required unless `BOARD_QEMU`, where a missing set boots the built-in topology | Where task grants come from |
| `TOPOLOGY_NEVERALLOW`, `TOPOLOGY_BIND_DEVICE`, `TOPOLOGY_COUNTER_FLOOR` | `y` | The topology admission checks named below |
| `KASLR` | `probe`; `require` on `SECURITY_HARDENED` and certifiable builds | Kernel image randomization |

`THREAT_PHYSICAL_ACCESS` (the default threat model of the separation-static
and confidential postures) implies the first three `y`. The gate's canary
builds (cargo features named `*-canary`, and on a development build with
Kconfig `CANARY_RUNTIME` a `canary=` kernel argument) switch single checks off
on purpose, `topo-verify-skip-canary` the topology signature among them; no
build script refuses a canary feature in a release build.

## Isolation model

This section states what a compromised program can and cannot reach, and where
that boundary depends on the kernel. The sections after it describe each
mechanism.

**A ring-3 program holds only what its topology row grants.**
- **Grants at spawn:** the kernel looks up the topology row bound to the SHA-256 of the program's ELF. The row lists the capabilities the program receives (files, endpoints, devices, sockets) and the system-call filter it runs under. Both come from the signed topology.
- **Nothing implicit is inherited:** a child gets its own row's grants, plus at most the file handles its creator moves to it explicitly (`SYS_SPAWN_EX`, a move list of up to 8).
- **No ambient authority:** a path, a device number or a socket address grants nothing; only a held handle does. A handle carries a generation, so a revoked handle cannot be replayed.
- **No privileged identity to escalate to:** the native ABI has no uid, no root and no setuid. A program that takes over another program gains that program's grants, not more. The Linux personality answers `getuid` and similar calls itself; the kernel keeps no Linux identity.
- **Narrow system-call surface:** a call the program's filter does not list is refused before its handler runs, and the refusal is recorded.
- **Ring-3 drivers and services are programs too:** each runs under its own row, so taking over one does not reach another's devices or data.

**What this does and does not cover.** The kernel enforces the boundary between programs, so a defect in ring 3 stays inside the grants of the program that has it. A defect in ring 0 code is outside this boundary, as on any kernel. What reduces that risk:
- The kernel is written in Rust. `unsafe` blocks are counted per crate, and the gate refuses a count that grows without a baseline change (`tools/lint/unsafe_budget.py`).
- The placement rule puts parsers of untrusted input in ring 3. Some still run in the kernel (see the limits below).
- The hardware protections below are set on every CPU at boot, not left to firmware: SMEP/SMAP on x86_64, PAN on aarch64, W^X for kernel and user mappings, per-process pointer-authentication keys on aarch64, and the user-visible system registers.

**Compared with a typical Linux system.**

| Aspect | Linux system | AzOS |
|--------|--------------|------|
| Starting authority of a program | Everything its uid can reach, unless a sandbox (namespaces, seccomp, LSM) is set up for it | Only the grants of its signed row |
| Privilege escalation target | uid 0, setuid binaries, privileged daemons | None in the native ABI |
| System-call filter | Optional, chosen by the program or its launcher | Always on, bound to the image digest |
| Inheritance across fork/exec | File descriptors, environment and credentials by default | Row grants plus an explicit move list |
| Drivers and most services | In the kernel, or root-owned daemons | Many drivers and services in ring 3 under their own rows |

**Known limits of the current tree.**
- **Large subsystems still run in ring 0:** the network stack, the FAT32 file system, the in-kernel Linux personality, the robot brain link and behaviour tasks, and many drivers. A defect there is a kernel defect.
- **DMA without an IOMMU:** a ring-3 driver for a DMA-capable device is only as contained as the platform's DMA isolation. On boards without an IOMMU (VF2, K1), such a driver can reach physical memory through its device ([DMA](#dma)).
- **Partial CFI:** control-flow integrity coverage is incomplete; see [Control-flow integrity](#control-flow-integrity).
- **Advisory Linux-level seccomp:** a filter a Linux program installs inside the hosted runtime is not enforced. Only the native per-image filter is.
- **No external review yet:** the tree has had no external security audit, and fuzzing covers only parts of the ABI and the parsers.

## Authority model

Source: `crates/core/abi/src/cap.rs`, `crates/core/ipc/src/cap.rs`,
`crates/core/ipc/src/cap_store.rs`, `crates/core/syscall/src/invoke.rs`,
`crates/core/topology/src/neverallow.rs`, `crates/core/ipc/src/authority_policy.rs`.

Authority over a resource is a capability held in a table. There is no ambient
authority to name a device, a file or a socket by number.

**The handle.** Across the syscall boundary a capability is a `u32`
(`CapHandle`); `0` is `CAP_NULL`.

| Bits | Field |
|------|-------|
| 31..26 | Type tag: kind (4 bits) and class (2 bits) |
| 25..20 | Permissions (`CapPerms`, 6 bits) |
| 19..9 | Generation (11 bits) |
| 8..0 | Slot index in the task's capability table (9 bits) |

**Kinds and classes** (`CapKind`, `CapType`, module `cap::ty`):

| Kind | Classes |
|------|---------|
| `Endpoint` | A right to call a service: a task-hosted endpoint or an interface the kernel hosts (`azos_devif`). The endpoint's badge names the resource and its rights are the op classes of the interface. |
| `MemObj` | `SHM`: a memory object two tasks can map |
| `Queue` | `IORING`: an io_ring |
| `Port` | An event port |
| `Domain` | `TASK`: the right to see every task (not authority over one) |
| `Node` | `FILE` (a file or directory tree), `LAUNCH` (start one image), `SOCKET` |
| `Device` | `IRQ`, `MMIO`, `DRIVER_REGISTRY` (a driver slot for one driver kind), `IOPORT` (a range of x86_64 I/O ports) |
| `Log` | `TRACE` (the kernel tracer), `CONSOLE` |

A pin, a wheel, a sensor or a partition is not a kind of its own: it is the
badge of an `Endpoint` capability, and devices have no syscall number.

**Permissions:** `READ`, `WRITE`, `EXEC`, `DUP` (derive an attenuated copy),
`TRANSFER` (hand the capability to another domain), `MAP` (map a memory object
into an address space). `DELEGATE` is `DUP | TRANSFER`.

**Dereference.** Every typed call resolves the handle in the caller's own
table (`Cap<T>`, a compile-time-typed wrapper in `crates/core/ipc/src/cap.rs`),
and fails with a distinct errno if the slot index is out of range or empty or
the generation does not match (`ECAPSTALE`), the kind tag does not match
(`ECAPKIND`) or the slot's permissions do not contain the right the operation
needs (`ECAPPERMS`). A slot's generation never wraps: a slot that reaches the maximum
generation is retired, so a revoked handle cannot validate again against a
later grant of the same slot.

**Tables.** Each domain (a process and its threads) has one capability table,
indexed by domain slot, not by task id (`cap_store`). A recycled domain slot is
wiped lazily if the table's recorded owner differs from the domain asking, so a
new domain cannot inherit an old one's capabilities. Kernel tasks hold no
capabilities; the capability and socket-owner checks apply to ring 3 and let
kernel callers through.

**Warrants.** A capability can be derived into an attenuated copy, and revoked
together with every descendant. A slot can be weak (transitively read-only:
resolves with `READ` and `MAP` only) and can carry a deadline. Derivation and
revocation are written as `Rule::CapDerive` and `Rule::CapRevoke` decision
records.

**Invocation.** Most operations go through one syscall, `SYS_INVOKE`
(`crates/core/syscall/src/invoke.rs`): the handle's type selects the kind, the
op must belong to that kind, the calling image's profile must list the op's
class (see the next section), and then the family that owns the type runs the
op and checks the rights it needs.

**Where grants come from.** A task's capabilities are the `[task.NAME]` rows of
the topology: the signed `CAPS.TOM` (see "Secure boot and signed artefacts"),
or the built-in one the image carries where Kconfig `TOPOLOGY_SOURCE` lets the
boot fall back to it. Each grant has a kind, a target, permissions and a
`transfer` flag. At admission the topology is checked for deadline
schedulability, memory, one writer per motor, and (Kconfig
`TOPOLOGY_NEVERALLOW`, default `y`) against `neverallow` rules
(`crates/core/topology/src/neverallow.rs`), assertions about all grants rather
than allow rules:

| Rule id | Forbids |
|---------|---------|
| `actuation-outside-actuation-row` | A ring-3 row holding a motor, PWM or GPIO write, or the buzzer, unless it is a listed actuation row |
| `desktop-grants-no-motor` | Any row holding a motor in a desktop image |
| `names-import-and-service-export` | A row that imports names and also serves an endpoint or registers a driver |
| `actuation-grant-not-transferable` | An actuator grant that carries `TRANSFER` |
| `proxy-endpoint-not-realtime` | A real-time row holding a grant on a proxy endpoint (`endpoint.rpc-*`) |
| `proxy-endpoint-served-by-rpcsrv-only` | A row other than `RPCSRV.ELF` serving a proxy endpoint |

An exception is a row name plus the exact grants it may hold and a reason, in
the table in the kernel image; a topology file cannot add one. A refusal is
`Rule::Neverallow`.

**Consequential commands.** `AUTHORITY_TABLE` in
`crates/core/ipc/src/authority_policy.rs` maps commands such as reboot,
shutdown, `ota rollback` and `config set` to `WRITE` on the `power`, `ota` or
`config` endpoint. Ring-3 tools are checked per op against the calling image's
own capability. The recovery console is seeded with `WRITE` on the `power`,
`config` and `ota` endpoints; its `reboot` and `shutdown` are checked against
that on every build, while `ota rollback` and `config set watchdog_ms` are
checked only under Kconfig `CONSOLE_LOCKDOWN` (default `n`), which also leaves
the recovery console out entirely.

**Refusals leave records.** A refused typed call is recorded as
`Rule::CapDenial` (verdict `deny`). It also reaches the durable flight recorder,
through a token bucket per subject task (`DECISION_DENY_DURABLE_PER_SEC`,
`DECISION_DENY_DURABLE_BURST`), so a ring-3 loop cannot turn denials into a
flood of writes.

## Image-bound syscall filters

Source: `crates/core/sched/src/seccomp.rs`, `crates/core/sched/src/filter.rs`,
`crates/core/syscall/src/dispatch.rs`, `crates/core/syscall/src/handlers.rs`,
`userspace/image_hashes.py`.

Every ring-3 program the disk image ships runs under a filter of its own,
installed by the kernel at exec, and a program that matches no filter is not
run.

- **A row per image** (`ImageProfile` in `IMAGE_PROFILES`): `syscalls` (the
  syscall numbers it may issue), `ifaces` (the kernel-hosted interfaces it may
  call, by `azos_devif::key`), `ops` (the `SYS_INVOKE` ops it may issue, listed
  by kind and class) and `audit`. The numbers are written as `SYS_*` names from
  `azos_abi::syscall_nr`, not literals, so a renumbering cannot silently
  whitelist a different call.
- **Bound to the bytes, not the name.** Each row is bound to the SHA-256 of one
  ELF. The build generates the digest table (`userspace/image_hashes.py`, a file
  `include!`d as `IMAGE_SHA256`); `image_for_digest` finds the row from the
  bytes the exec site hashed. A binary copied over another name keeps its own
  row; a binary that differs by one byte has none.
- **No row, no exec.** The autorun loader and the shell's exec hash the bytes
  they read into their own buffer and hand the same slice to `exec_user`, so
  the bytes checked are the bytes loaded. An image that matches no row is
  refused and `SAFETY_EXEC_REFUSED` is written durably. `SYS_SPAWN_EX` and the
  Linux `execve` refuse such an image too (`EACCES`).
- **One-way.** `install_image_profile` sets the filter on the task slot after
  `exec_user` succeeds and before the first user instruction; a task with a
  filter already in force gets `SECCOMP_E_ALREADY`. The filter lives on the
  task slot, is copied to children by fork, and a Linux `execve` installs the
  executed image's own row, which must be a Linux row; a row other than the
  caller's needs a `LAUNCH` grant (`EXEC`) for that image, and may be wider
  than the caller's (`crates/core/syscall/src/linux.rs`, `sys_execve`).
- **A call outside the row kills the task** (`seccomp_deny_kill`,
  `seccomp_deny_op_kill`, exit code 159). In `audit` mode the call goes through
  and is recorded as `SAFETY_SECCOMP_AUDIT`, bounded per task; two test images
  that probe the kernel use it.
- **How the check is made.** The dispatcher tests one bit of a bitmap
  (`SyscallFilter::bits`, built alongside the list by `allow`), read in place
  on the task slot. `SYS_INVOKE` ops are checked per kind and class.
- **Third-party images** (`THIRDPARTY_PROFILES`) have a digest table of their
  own, empty unless the program was built.
- **Package images.** The boot-time apply of a package (see "Packages")
  registers the digest of each image it admitted (`register_package_images`).
  Every package image runs under one profile (`package_profile`): the calls of
  an ordinary native service, none that start, signal or schedule other tasks
  or belong to the Linux personality, and as `ifaces` the kernel-hosted
  interfaces its own row grants. A shipped digest is looked up first, so a
  package cannot take a shipped image's row.
- **Role profiles** are a separate id space that a task can ask for itself with
  `DOMAIN_SET_FILTER`: `PROFILE_UNRESTRICTED` (a no-op that does not burn the
  one-way gate) and `PROFILE_MINIMAL` (exit, getpid, yield, sleep, console
  write). An unknown id returns `SECCOMP_E_BADPROFILE` and installs nothing. The
  per-image profiles are deliberately not reachable by number from ring 3.
- An image whose row lists `SYS_FOREIGN_FORK`, or is in audit mode, can fork;
  an image under a `mem = "locked"` topology row must not (`locked_compatible`).

## Control-flow integrity

Source: `arch/aarch64/src/cpu/cfi.rs`,
`arch/x86_64/src/cpu/cfi.rs`, `tools/build/kconfig_to_cargo.py`
(`cfi_rustflags`), `config/subsys/Kconfig.topology` (section "Hardware control-flow
integrity"), `config/arch/Kconfig.isa`.

The model is the same on every ISA: forward edges (an indirect call or jump may
only land on a landing pad) and backward edges (a return address is signed or
kept on a shadow stack). Each extension is a per-ISA `make config` choice of
`n` / `probe` / `require` (`ExtPolicy` in `arch/api/src/isa.rs`).
Any policy but `n` makes the kernel and the user images compile with the pads,
which are no-ops on a CPU without the extension; the boot then uses the
extension when the CPU has it (`probe`) or refuses the CPU (`require`).

| ISA | Forward edge | Backward edge |
|-----|--------------|---------------|
| aarch64 | `A64_BTI`: `bti` pads are emitted (`-Z branch-protection=bti,pac-ret`). Not enforced: the page-table guarded-page bit is never set and `SCTLR_EL1.BT0/BT1` stay clear. | `A64_PAUTH`: `paciasp` / `autiasp` in non-leaf functions, kernel and user images. One key (A) for the kernel, loaded on every CPU; checking is switched on by `_azos_cfi_enable` (sets `SCTLR_EL1.EnIA`, and with `A64_PAUTH_PROC_KEYS` also `EnIB`, `EnDA`, `EnDB`) right before Rust is entered. With `A64_PAUTH_PROC_KEYS` (default) every process has its own `APIA`, `APIB`, `APDA`, `APDB` and `APGA` keys from the DRBG (`spawn` and `exec` draw, `fork` and threads copy), and the kernel's key is back in `APIAKey_EL1` on every entry from EL0 (`trap_entry.S`), so ring 3 cannot sign under the kernel's key or another process's; with it off, ring 3 shares the key and this is corruption detection inside an image, not a privilege boundary. The kernel key comes from `RNDRRS` when available, mixed with counter values; without FEAT_RNG it is the counter values alone, guessable by whoever knows the boot time closely. Both choices default to `n` on `BOARD_RPI5` (the Cortex-A76 has neither). |
| x86_64 | `X86_CET_IBT`: `endbr64` at every function entry (`-Z cf-protection=branch`) and at every hand-written entry point. Enforced in ring 0 by `IA32_S_CET.ENDBR_EN` with `CR4.CET`, on each CPU after `CR0.WP` is set; an indirect branch to a non-`endbr64` target raises #CP. `NO_TRACK_EN` is set so jump tables (in read-only memory) work. Ring 3 gets nothing from this. | `X86_CET_SHSTK`: the policy and the CPUID row exist; the kernel does not enable the shadow stack. |
| riscv64 | None: no landing-pad or shadow-stack code is generated or enabled (Zicfilp and Zicfiss are not used). | None |

Also not implemented, per the Kconfig notes: aarch64 GCS, and kCFI (the
compiler does not support it for riscv64).

## Speculation mitigations

Source: `config/axes/Kconfig.security`,
`arch/x86_64/src/ext/mitigations.rs`,
`arch/aarch64/src/ext/mitigations.rs`,
`arch/x86_64/src/ext/retpoline.rs`,
`crates/core/limits/src/nospec.rs`.

Every mitigation is a switch in `make config`; none is forced. The threat model
is the security posture (`SECURITY_*`, `config/axes/Kconfig.security`): the
physical-access postures (`SECURITY_SEPARATION_STATIC`, `SECURITY_CONFIDENTIAL`)
set defaults with `imply`, never `select`, so a switch set by hand wins.

**Probe, not vendor name.** A verdict is a pure function of what the CPU
reports (host-testable): architectural capability bits first (x86:
`IA32_ARCH_CAPABILITIES` and CPUID leaves; aarch64: the ID registers), and a
model table (the rows Linux's own tables carry) only for a bug the architecture
publishes no bit for. aarch64 decides per core, on every CPU including
secondaries, from that core's own MIDR and ID registers. Each x86_64 and
aarch64 mitigation has the same three-way choice:

| Choice | Meaning |
|--------|---------|
| `n` | Do not look, do nothing |
| `probe` | Mitigate when the CPU is affected and the tree has the mechanism; otherwise print `vulnerable` and why |
| `require` | Refuse to boot on a CPU left `vulnerable` (on an aarch64 secondary, power it off) |

**All ISAs: Spectre v1** (`MITIGATION_SPECTRE_V1_INDEX`, on by default). The
index into the syscall table, and into per-task tables a syscall indexes with a
user value, is masked with a branch-free mask after the bounds check
(`azos_limits::nospec`): `sltu`+`neg` on riscv64, `cmp`+`sbc`+`csdb` on aarch64,
the portable shift formula elsewhere. Under a mispredicted check the load reads
entry 0.

**x86_64**

| Bug | Mechanism in the tree | Otherwise |
|-----|----------------------|-----------|
| Meltdown | Reported only | An affected CPU is `vulnerable` (no page-table isolation) |
| L1 terminal fault | PTE inversion by construction: a not-present entry the kernel writes names no frame, and frame 0 is never allocated | |
| MDS, TAA, RFDS | `verw` on every return to ring 3 (guarded by one byte), effective when the microcode provides buffer clearing | `vulnerable` without it |
| Gather data sampling | Microcode mitigation kept enabled (`IA32_MCU_OPT_CTRL`) | `vulnerable` if missing or locked off |
| Spectre v2 | eIBRS (`IA32_SPEC_CTRL.IBRS`), else AutoIBRS (`EFER.AIBRS`), else retpoline: the kernel is built with the external indirect-branch thunk and the boot patches it once to a plain `jmp` when hardware protects indirect branches. Under `require` the kernel is built without the thunk. | |
| Branch history injection | `BHI_DIS_S`; retpoline covers a CPU with no eIBRS | An eIBRS CPU with neither `BHI_NO` nor `BHI_DIS_S` is `vulnerable` |
| Retbleed | Covered by eIBRS where present | Other affected CPUs `vulnerable` |
| Speculative return stack overflow (AMD) | Reported only | `vulnerable` unless the CPU is not affected |
| Zenbleed | `DE_CFG` chicken bit unless the microcode is the fixed one | |

**aarch64**

| Bug | Decision | Mechanism |
|-----|----------|-----------|
| Spectre v2 | `ID_AA64PFR0_EL1.CSV2`, in-order core list, or firmware `SMCCC_ARCH_WORKAROUND_1` "not affected" | Otherwise `vulnerable`: the per-entry firmware call is not implemented |
| Spectre v4 | In-order core, `FEAT_SSBS`, or firmware `SMCCC_ARCH_WORKAROUND_2` | `PSTATE.SSBS` cleared on each CPU and `SCTLR_EL1.DSSBS` cleared (exception entry starts with `SSBS` 0); or the firmware call once per CPU at boot |
| Spectre-BHB | `FEAT_ECBHB` (hardware), `FEAT_CLRBHB`, the MIDR loop table, or firmware `SMCCC_ARCH_WORKAROUND_3` | Entry-time mitigations are not implemented, so an affected core is `vulnerable`. A core on no list reads as not affected unless the firmware says it needs `WORKAROUND_3` (the MIDR lists are Linux's, not checked against Arm's) |

**riscv64:** only the Spectre v1 masking above.

The following are listed in the Kconfig as not implemented: a predictor or
buffer flush on address-space switch, kernel page-table isolation, a
speculation barrier on syscall entry.

## Kernel image randomization (KASLR)

Source: `arch/api/src/kaslr.rs`,
`arch/{aarch64,riscv64,x86_64}/src/mmu/kaslr.rs` and
`kaslr_boot.rs`, `kernel/linker-*.ld`, `kernel/build.rs` (the `-pie` link),
`config/kernel/Kconfig.hardening` (the `KASLR` choice), `tools/image/kaslr_image.sh`,
`tools/gate/kaslr_boot_row.sh`.

Kconfig `KASLR` is `n` / `probe` / `require` (default `probe` on every build
type, development included, so a layout bug shows where it is written; `require`
on `SECURITY_HARDENED` and on certifiable builds, and it refuses to boot without
a seed; a debugger or a trace that needs fixed addresses sets `n` by hand). Any
policy but `n` links the kernel as a static position-independent
executable: `kernel/build.rs` adds the link flags from the same configuration
the policy is compiled from, so no build command line can drop them, and a
boot that finds an empty relocation table refuses to slide. The boot picks a random base for the image in a window of the
kernel's address range, applies the image's `R_*_RELATIVE` relocations before
any pointer is followed (every target and the table itself are checked against
the image), and maps the image there. The shared arithmetic (slide choice,
policy, the relocation walk, the device-tree seeds `kaslr-seed` and `rng-seed`,
erased after they are read) is `azos_arch_api::kaslr`, host-tested in
`tests/host/kaslr-tests`.

| ISA | Window | Seed |
|-----|--------|------|
| aarch64 | upper half of the TTBR1 range, 2 MiB steps at a 4 KiB granule (about 16 bits) | `RNDRRS`, device tree |
| riscv64 | Sv39 upper half, 256 GiB, 2 MiB steps (about 16 bits); the kernel stays identity-mapped for RAM, and every hart installs the boot root and jumps the same way | Zkr `seed` CSR, device tree |
| x86_64 | first GiB of the top 2 GiB `-mcmodel=kernel` allows, 2 MiB steps (about 9 bits, 8 whole); the 32-bit boot stage names its symbols through linker-defined `<sym>_pa` | RDSEED, RDRAND |

The map of RAM keeps its address (aarch64's linear map, x86_64's direct map,
riscv64's identity), so a slid image is a second mapping of its own frames:
`virt_to_phys` of an image address goes through the recorded bias, and the RAM
map's alias of the text and read-only data is made read-only and not
executable. The direct-map base is not randomized: it would turn every
`phys_to_virt` into a load. Not slid: riscv64 on a small board (no MMU) and the
x86_64 Limine image. A development image prints the base on the `[KASLR]` line;
other builds print only the entropy bits. Gate rows: `kaslr: slid` and
`kaslr: plain` per ISA, with a canary; the `plain` rows set `n` by hand
(`tools/image/kaslr_image.sh`), as no defconfig does. `kaslr: gate ktest kernel
(rv|arm)` takes the kernel the ktest rows boot, as the gate builds it: its ELF
must carry the relative relocations, and two boots must slide it and reach the
test plan. `make check-fast` wants the `[KASLR] image slid` line on every boot
of a KASLR build.

## Memory protection

Source: `crates/core/mm/src/wx.rs`, `crates/core/mm/src/vmm.rs`,
`crates/core/mm/src/text_poke.rs`, `kernel/src/boot/early.rs`,
`crates/core/sched/src/elf_bounds.rs`, `crates/core/syscall/src/handlers.rs`,
`crates/core/mm/src/slab.rs`, `crates/core/mm/src/buddy.rs`,
`config/arch/Kconfig.isa`, `config/subsys/Kconfig.topology`.

- **Kernel W^X.** On every build with an MMU the boot remaps the image by
  section (text read-execute, read-only data read-only, data read-write;
  `.data.ro_after_init` is made read-only once the boot hooks are installed),
  takes execute off all RAM outside the image, and makes the RAM map's alias of
  the image (x86_64's direct map, aarch64's linear map once KASLR slid it)
  read-only and not executable. Each step is read back from the page table
  (`vmm::verify_wx`, `verify_no_exec_outside_image`); a failed readback prints a
  `FAILED` line and the boot goes on. Kernel text is written only through
  `text_poke` (static keys, livepatch): a one-word write through a read-write,
  non-executable alias that is unmapped again after it.
- **Ring-3 W^X.** The ELF loader maps a segment with `PF_W` read-write and
  never executable (an `RWX` header maps read-write, `seg_perms`), and with
  Kconfig `ELF_REFUSE_EXEC_HEADERS` (default `y`) it refuses an executable
  segment that maps the ELF headers. The map calls refuse `PROT_EXEC`. The one
  path that makes anonymous memory executable is `DOMAIN_MODULE_MAP_X` (only
  with the `lx-loader` feature, `crates/core/syscall/src/module_ops.rs`): it
  flips a Linux driver server's relocated module text from read-write to
  read-execute after `DOMAIN_MODULE_VERIFY` matched the module file's SHA-256
  against the table built into the kernel; the digest covers the file, not the
  relocated text.
- **Kernel access to user memory.** Outside an explicit `UserAccess` window the
  kernel faults on a dereference of a user address (the copy routines of
  `crates/core/sched/src/process.rs` translate the address and reach the frame
  through the kernel's RAM map, which these bits do not cover):

| ISA | Mechanism | Kconfig (default) |
|-----|-----------|-------------------|
| x86_64 | `CR4.SMEP`, `CR4.SMAP` (window: `stac` / `clac`), and `CR4.UMIP` against ring-3 `SGDT`/`SIDT`/`SLDT`/`SMSW`/`STR`, set on each CPU | `X86_SMEP`, `X86_SMAP`, `X86_UMIP` (`probe`) |
| aarch64 | `PSTATE.PAN`, set on every exception entry (`SCTLR_EL1.SPAN` clear) | `A64_PAN` (`require` at Armv8.1 and above, `probe` at 8.0, where a core without FEAT_PAN runs unprotected) |
| riscv64 | `sstatus.SUM` clear (the boot value; only `UserAccess` sets it) | none |

- **Heap hardening.** `SLAB_HARDENED` (default `y`, every build): obfuscated
  slab free-list links with a check on every pop and free, and safe unlink on
  the slab and buddy lists; a failure panics. `ALLOC_RANDOM` randomizes slab
  carve order and buddy list order (default `y`, `n` on certifiable and
  separation-static builds). The ring-3 allocator's quarantine, free-chunk
  poison and randomized placement (`USER_ALLOC_QUARANTINE_KB`,
  `USER_ALLOC_POISON_FREED`, `USER_ALLOC_RANDOMIZE`) are on for every
  `SECURITY` posture but `general` (the fallback default when no preset picks
  another); its guard pages
  (`USER_ALLOC_GUARD_PAGES`) are on in every posture.

## DMA

Source: `kernel/src/boot/dma.rs`, `crates/drivers/iommu/src`,
`config/subsys/Kconfig.drivers` (`IOMMU_*`), `config/axes/Kconfig.personality`.

A bus-mastering device is not confined by the capability model. The IOMMU
drivers (`IOMMU_RISCV`, `IOMMU_SMMUV3`, `IOMMU_VTD`, `IOMMU_AMDVI`) are on by
default where the ISA has PCI and the firmware describes a unit
(`IOMMU_BYPASS` opts out). The boot gives each function whose driver maps all
its DMA through its domain (virtio-net/gpu/snd over PCI, e1000e, igc, xHCI) a
translating domain of its own, with its own cache tag; NVMe and AHCI hand their
devices physical addresses and stay in pass-through, said per function; a
function no kernel driver binds is blocked (`iommu_init`). The AMD-Vi `Block`
mode is an entry with `V` and `TV` set and no permission (`encode_dte`): an
all-zero entry would pass DMA through, so a fresh table starts blocked.
A Linux driver server that drives a bus master on a
board without an IOMMU needs `LX_ACCEPT_UNCONFINED_DMA`, which fails the build.

## Secure boot and signed artefacts

Source: `crates/core/ota/src/secure_boot.rs`, `crates/core/ota/build.rs`,
`crates/core/ota/src/update.rs`, `crates/core/topology/build.rs`,
`crates/core/topology/src/verify.rs`, `crates/core/topology/src/signed.rs`,
`kernel/src/boot/ota.rs`, `kernel/src/boot/config_auth.rs`,
`crates/core/pkg/src`, `crates/core/crypto/src/sig.rs`, `tools/sign/sign_ota.py`,
`tools/sign/sigalg.py`.

Every artefact below carries a signature, verified before its bytes are
interpreted, with three build-time exceptions: the kernel image is verified by
the kernel it already is, and refused only with `SECURE_BOOT_ENFORCED`; the OTA
receiver installs an image with no usable signature unless
`secure-boot-enforced` is compiled in; and `INFER_MODEL_SIG_REQUIRED=n` lets the
inference policy file through unverified. The signature algorithm is Ed25519.
Every signed format names its algorithm by a 16-bit id (1 Ed25519; 2 and 3 are
reserved for ML-DSA-65 and SLH-DSA-SHA2-128s, which no build verifies) and
carries a signature of that algorithm's length; a device accepts only its own
algorithm, and refuses a file naming another before its signature is looked at.
The embedded keys and every signature slot (read buffers, the update manifest)
are sized for it (`azos_crypto::sig::KEY_LEN`, `SIG_LEN`), so a post-quantum
scheme is a new `SigAlg` with its verifier, not a new format. There are two trust anchors, deliberately separate
keys:

- the **firmware key**, embedded by `crates/core/ota/build.rs` from
  `prod_pub.bin` in the `keys` directory of `tools`, a file that is not kept in the repository (override
  the path with `PROD_PUBKEY_PATH`) into the section
  `.secure_boot_pubkey` as `SECURE_BOOT_PUBKEY`. If no key file exists the array
  is all zeros, which the kernel treats as "no trusted key";
- the **topology key**, embedded by `crates/core/topology/build.rs`
  (`TRUSTED_PUBKEY`). It comes from `TOPOLOGY_PUBKEY_PATH`, or from the
  `dev-key` feature (a test key; the kernel's `qemu` feature enables it). The
  build fails if neither is given, and a bare-metal build whose
  `KCONFIG_CONFIG` selects `BUILD_TYPE_RELEASE` or `BUILD_TYPE_CERTIFIABLE`
  fails if the key it would embed is the test key (ring-3 programs built with
  `dev-key` and no `KCONFIG_CONFIG` keep it). An all-zero key makes every
  signature check fail closed.

| Artefact | Format | Verified by | Key |
|----------|--------|-------------|-----|
| Kernel image of a slot | `RSIG` sidecar file (`KERN_A.SIG`, `KERN_B.SIG`, `KERN_R.SIG`): magic, algorithm id, signature length, id of the signing key, payload size, firmware version (48 bytes), then the signature (64 bytes for Ed25519, 112 bytes in all) | `secure_boot_verify_slot_detailed` at boot | Firmware key |
| Whole-system update | Manifest `AZUM` with per-part SHA-256; the head names the algorithm and the signature's length ([update.md](update.md)) | `update::verify_set` at stage and again at switch | Firmware key |
| Livepatch blob (Kconfig `LIVEPATCH`, default `n`) | `RSIG` + `APCH` payload ([update.md](update.md)) | `kernel/src/boot/livepatch.rs` | Firmware key |
| Topology | `CAPS.TOM` + `CAPS.SIG` (a `DSIG`: magic, algorithm id, signature length, the signature over the file bytes); `CAPS.TOM` binds `SCHED.TOM` by SHA-256, plus this device's id and a counter | `azos_topology::signed` | Topology key |
| Configuration | `CONFIG.INI` + `CONFIG.SIG` (version 2: names the algorithm, a device id and a counter) | `kernel/src/boot/config_auth.rs` | Topology key |
| Inference policy file | `POLICY.SIG` sidecar (`DSIG`); the `.MBL` model bundles carry their own signature and are always verified | `userspace/services/infsrv`, Kconfig `INFER_MODEL_SIG_REQUIRED` | Topology key |
| Application package | `.azpkg` container `AZPK`, signed message with domain tag `azos-pkg-v1` | `azos_pkg` in `pkgd` and in the kernel's boot-time apply | The signer table of the signed topology |

**Kernel image.** The signature does not cover the raw image. It covers a
54-byte manifest, the domain tag `azos-rsig-v2`, the algorithm id, then
`fw_version || payload_size || sha256(image)`, so the version
is inside the signature (the anti-rollback floor trusts it) and the image is
hashed in a stream and never needs to be resident. The sidecar's signer id
(`sha256(algorithm || public key)`) must equal the embedded key's; a mismatch
is rejected whether or not the signature is mathematically valid. The result is `BootTrust::Verified`,
`Unverified` (no sidecar, or no trusted key) or `Failed`, with a
`BootTrustReason`. The comparison uses constant-time equality.

With the compile-time feature `secure-boot-enforced` (Kconfig
`SECURE_BOOT_ENFORCED`; no runtime flag can relax it), `kernel_main` verifies
the running slot before SMP bring-up and refuses to continue unless the result
is `Verified`. Before halting it tries to steer the next boot to the recovery
slot, and only when that slot's own signature verifies and the steer read back
off the volume, so this cannot become a reset loop. It also verifies the slots
it is not running and records a failing one as unfit, so a later rollback will
not select it. Without the feature, verification still runs and the state is
printed, and boot continues. The OTA receiver
(`crates/core/recovery/src/lib.rs`) refuses a staged image whose signature is
present and does not verify on every build, and one with no usable signature
(no sidecar, or no trusted key) only when `secure-boot-enforced` is compiled
in; otherwise it installs it with a warning. Kconfig `OTA_SIG_MANDATORY` is not
read by the kernel: the build refuses `SECURE_BOOT_ENFORCED=y` with it `n`
(`crates/core/limits/build.rs`), and it is exported to the brain.

**Topology.** `CAPS.SIG` is verified before any byte of `CAPS.TOM` is
interpreted. One signature covers both topology files: the verified
`CAPS.TOM` names the SHA-256 of the `SCHED.TOM` it was signed with, this
device's id and a counter. Only after the hash, the device (Kconfig
`TOPOLOGY_BIND_DEVICE`) and the counter floor (`TOPOLOGY_COUNTER_FLOOR`, sector
`TOPOLOGY_FLOOR_SECTOR` of the reserved tail; both default `y`) pass is
`SCHED.TOM` parsed, then the rows. The result is then admission-checked
(deadlines, real-time band, memory, `neverallow`); a topology refused at any
step is never published. Policy for a missing or invalid topology is Kconfig
`TOPOLOGY_SOURCE` and `TOPOLOGY_INVALID`: on `BOARD_QEMU` (signed if present)
a deleted set, and by `TOPOLOGY_INVALID`'s default a refused one, boots the
built-in topology, which may grant more than the signed one; every other board
requires the signed set. A partial set (some of
the three files present) is a refusal, not an absent set.

**Configuration.** `CONFIG.INI` decides, among other things, whether the kill
switch is armed and whether the OTA listener starts, and it lives on a volume
that is also exported over USB mass storage. It is loaded only if `CONFIG.SIG`
v2 verifies for this device's id with a counter no lower than the floor in the
device record (reserved tail sector 2). If a signed configuration was accepted
here before and its authority is now gone (file or sidecar deleted or changed,
an older counter, another device's sidecar), the kernel falls back to factory
defaults and latches the e-stop with a durable record, so deleting the sidecar
does not leave a provisioned machine unconfigured.

**Packages.** A package is images plus a manifest of what they ask for, signed
by their author. The signer table is the `[signer.NAME]` sections of the signed
topology, so a package cannot add a signer for itself, and a device with no
signer admits no package. A signer's ceiling (`warrants`, `rt`,
`mem_pages_max`) bounds what its packages may ask for. No metadata or row is
interpreted before the signature verifies; the package rows are judged by the
same admission as a signed `CAPS.TOM` (`neverallow` included); a package cannot
hold `[operator]`, `[pipeline]`, `[class]` or `[signer]` sections, replace an
existing row, or name a file other than a `.ELF` in the volume root. The
signature algorithm is a field of the container (`azos_crypto::sig::SigAlg`);
an id other than the device's is refused; a package also carries the security epoch it was
signed against and is refused below the device's epoch floor. The installer
(`userspace/services/pkgd`) verifies, admits and stages on the native volume;
its verdict is not a trust anchor, since the volume it stages on is writable by
others. The kernel applies what is staged at boot, before anything starts
(`kernel/src/boot/pkg_apply.rs`): it verifies and admits every staged package
again against the signed topology, merges the rows into the candidate topology
before the kernel's own boot admission, and writes the programs to `APPS/` on
the staging volume after a snapshot. The boot is a trial: confirmed by the next
boots, or rolled back to the snapshot with the packages removed and a refusal on
record, by the same attempt count as an A/B slot. Every apply and every refusal
is a `PackageInstall` decision record.

## Crypto primitives

Source: `crates/core/crypto/src`.

The crate is `no_std` and has no allocation. Symmetric primitives and hashes
are implemented in the crate; the two asymmetric ones call the vetted
`curve25519-dalek` and `ed25519-dalek` crates (`default-features = false`).

| Module | Provides |
|--------|----------|
| `sha256` | SHA-256 (FIPS 180-4), streaming. The block function is chosen at boot: generic, riscv64 `zbb` or `zknh` variants, or a hook other code can install (`select_riscv`, `select_hook`); the `no-bitmanip` feature compiles the generic one only. |
| `aes` | AES-128 (FIPS 197), ECB block and CTR mode |
| `chachapoly` | ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439); constant-time by construction; `open` verifies the tag before decrypting and leaves the buffer untouched on mismatch |
| `hkdf` | HMAC-SHA256 with arbitrary key, HKDF-SHA256 (RFC 5869) |
| `x25519` | X25519 (RFC 7748) via `curve25519-dalek`, with a checked variant that rejects low-order points |
| `ed25519` | Ed25519 (RFC 8032) via `ed25519-dalek`: strict verification, and signing from a seed (the keystore's `SIGN` keys) |
| `sig` | The signature algorithms by id and their key and signature sizes, the configured one (`SigAlg::CONFIGURED`), and the signed containers: `RSIG` (image signatures, with the 54-byte manifest message) and `DSIG` (detached signatures) |
| `noise` | Noise Protocol Framework handshakes `Noise_IK_25519_ChaChaPoly_SHA256` and `Noise_XX_25519_ChaChaPoly_SHA256`; no RNG inside (the caller supplies the ephemeral key); every DH result goes through the checked X25519; an error poisons the handshake state |
| `secure_channel` | The brain link: the Noise handshake driver (initiator role, `IK` or `XX`), static keys derived from the link key, and the framed Noise transport with rekey |
| `entropy` | HMAC_DRBG over SHA-256 (NIST SP 800-90A), see "Entropy" |
| `dice` | The node static key, see "Node identity" |
| `keystore` | The kernel-held keys and their policies, see "Keystore" |
| `ct` | Constant-time comparison (`ct_eq`, hardened with `black_box`) and `secure_zero` |
| `wkdm` | WKdm page compression (not a security primitive; it lives in this crate) |

Secret-dependent comparisons (peer static keys, the boot public key) use
`ct_eq`. The hand-written SHA-256 and AES are not constant-time against cache
attacks; the crate does not claim it.

Ring 3 TLS and QUIC use rustls from `third_party/vendor` with the
`rustls-rustcrypto` provider (a patched copy in
`third_party/patches/rustls-rustcrypto`) ([network.md](network.md)).

## Entropy

Source: `crates/core/crypto/src/entropy.rs`, `kernel/src/boot/entropy.rs`,
`kernel/src/boot/entropy_pool.rs`, `crates/core/syscall/src/entropy.rs`.

The kernel pool is an HMAC_DRBG (SHA-256). Its rules:

- `mix(bytes, credited)` stirs bytes in. Only credited bytes count toward
  seeding; uncredited ones (MAC addresses, boot timing) never make the pool
  seeded on their own.
- The pool is **seeded** after 48 credited bytes (256 bits of entropy input
  plus the 128-bit nonce SP 800-90A asks for), **reseeded** every further 32
  credited bytes, and **unseeded again** after 2^48 generate requests without a
  reseed.
- `fill` writes output only when the pool is seeded and returns `false`
  otherwise, leaving the buffer untouched. `fill` has no fallback path of its
  own (the crate depends on no kernel crate, only `azos_common`). Each consumer
  keeps the
  counter-based fallback it had; the fallbacks are labelled in code as
  unpredictable-in-practice, not random.

Sources, mixed at boot by `install_entropy`:

| Source | Policy | Notes |
|--------|--------|-------|
| virtio-rng | Credited | Where the device exists |
| CPU instruction | `ENTROPY_CPU_SOURCE`: `credit` (default), `mix-only`, `off` | riscv64 Zkr `seed`, aarch64 `RNDRRS` (FEAT_RNG), x86_64 `RDSEED` then `RDRAND`; each used only where its extension choice allows and the probe finds it; bounded retries (`ENTROPY_CPU_RETRIES`). Under `credit` each at its own rate (`azos_arch_api::entropy::Source::credit`): RDSEED and RNDRRS 1:1, Zkr ES16 1:2 (the spec's 2:1 conditioning), RDRAND 0 (DRBG output, mixed only) |
| TPM 2.0 | `ENTROPY_TPM_SOURCE`: `credit`, `mix-only`, `off` | 48 bytes from `GetRandom`; see "TPM" |
| Persisted seed | Credited only if no other source seeded the pool | One reserved tail sector (sector 1) of the boot medium, outside the FAT volume and not reachable over USB mass storage; read at boot and immediately replaced by a fresh record drawn from the pool so a seed is never used twice; replaced again at an orderly power-off. Only touched when no partition or filesystem reaches the tail. |

Consumers: the TCP initial-sequence-number secret, DHCP/DNS/SNTP ids and DNS
source ports, the firewall and NAT hash keys (from the pool when it is seeded), the link keys and nonces, and the
kernel stack canary (drawn once before the first task exists). Ring 3 reads the
pool through the kernel-hosted `entropy` endpoint (`READ` on an `Endpoint`
capability that the topology row grants, `endpoint = "entropy"`). That endpoint
has no fallback: an unseeded pool answers `NOT_READY` on every build, and the
first refusal of a boot is recorded durably.

**Where the records live.** The link key (sector 0), the persisted seed
(sector 1), the device record (sector 2) and the topology counter floor are
one sector each of the kernel's record store (`kernel/src/reserved_tail.rs`).
On an MBR or bare FAT32 medium that store is the reserved tail: the last 8
sectors, used only when no partition and no filesystem reaches them. A GPT
medium laid out to its end has its backup table there instead, so on GPT the
store is the AzOS records partition, GPT type GUID
`653ED7AA-51CA-43D8-9AF7-54775962C612` (generated once for AzOS;
`GPT_RECORDS_GUID` in `crates/drivers/block/src/partition.rs`,
`tools/image/azos_records.py`), of at least 8 sectors. The partition table publishes
it but never hands it out: no capability is minted for it, no disk syscall
names it and no filesystem scan mounts it. A table with two such partitions is
refused whole. The records are read or written only after the backup GPT
header on the last sector, and its entry array, are found equal to the
primary ones; a mismatch leaves the board without them for the boot (no seed,
unprovisioned, no floor), as a missing tail does. `tools/image/make_parted_disk.py
--gpt` builds such an image, and the provisioning tools find the partition on
their own.

## TPM

Source: `crates/drivers/tpm/src`, `kernel/src/boot/tpm.rs`, Kconfig `TPM`.

A TPM 2.0 is found, never assumed. On x86_64 the kernel reads the ACPI `TPM2`
table: TIS over MMIO (start method 6) or the Command Response Buffer (7, and 2
and 8, whose ACPI `_DSM` start is not run: there is no AML interpreter). On
riscv64 and aarch64 it looks for a device-tree node compatible with
`tcg,tpm_tis-spi` and talks to it through the `Spi` device interface. With no
TPM, or one that does not answer, the boot is as it would be without the
feature. A command the TPM answers `TPM_RC_RETRY` or `TPM_RC_TESTING` is sent
again, a bounded number of times (about 2.5 s). The driver is polling, has no `unsafe` and no allocation,
and its wire parser checks every size against what is left.

The kernel uses the TPM for three things:

1. Random bytes for the entropy pool (above).
2. **Measured boot.** Three SHA-256 PCRs, starting at `TPM_PCR_BASE`: the kernel
   image (its build-id), the accepted configuration, the accepted topology. Each
   extend writes a `Rule::MeasuredBoot` decision record. The boot asks the TPM
   which PCR banks it allocated first: without a SHA-256 bank holding those
   PCRs nothing is extended (the TPM would drop each extend), and other banks
   keep their reset value there, so a verifier quotes SHA-256.
3. The OTA anti-rollback floor in an NV index, see [update.md](update.md). The
   index is an ordinary one whose password the kernel derives from public inputs
   (`azos_ota::floor::nv_auth`): it keeps out software that does not know the
   scheme, not an attacker who has read the source. A policy bound to PCRs is not
   used.

## Node identity

Source: `crates/core/crypto/src/dice.rs`, `crates/core/syscall/src/link_key.rs`,
`userspace/lib/rpc/src/keys.rs`, `kernel/src/tasks/loader.rs`.

A node's static key is a function of the device's secret and of the image that
asks for it, in the style of DICE:

```text
node_static_key = HKDF-SHA256(salt = measurement, ikm = device seed,
                              info = "azos-dice node static key v1")
```

- The **measurement** is the SHA-256 of the image a domain started from. The
  loader records it with `azos_sched::domain::set_measurement`.
- The **device seed** is the secret in reserved tail sector 0, which only the
  kernel reads.
- The kernel-hosted `linkkey` endpoint's `node_key` op derives the key of the
  *caller's own domain* (a `READ` capability on the endpoint is required) and
  returns it. The raw seed is the endpoint's `read` op, which only `brain_client`
  can call among the shipped images (only `BRAINCLI.ELF`, `RPCSRV.ELF` and
  `MCPD.ELF` list `linkkey` in their image profile, and a grant of an
  interface the profile does not list is withheld): the tasks that face a
  network and take an identity (`RPCSRV.ELF`, `MCPD.ELF`) hold `READ` with an
  op mask (an `OP_MASK` caveat, one
  bit per IDL op) that lists `node_key` and nothing else. The kernel holds every
  call through the capability to the mask before the interface runs, so those
  tasks never reach the seed, and containment does not block them (`node_key`
  observes). A domain with no measurement (not started by the measuring loader)
  has no identity and is answered `NOT_READY`.
- The topology pins the public half in a `[peer.NAME]` row (`noise_pk`, with
  an optional `measurement` the operator derives it from). A node running a
  different image derives a different key, and the Noise IK handshake refuses
  it.
- The ring-3 side (`userspace/lib/rpc/src/keys.rs`) refuses an all-zero
  answer, hands the key out once and wipes every copy it made.

## Keystore

Source: `crates/core/crypto/src/keystore.rs`, `crates/core/devif/src/keys.rs`,
`crates/core/syscall/src/keys.rs`, `crates/drivers/tpm/src/tpm.rs`,
`kernel/src/boot/keys.rs`, `config/subsys/Kconfig.topology`.

A task that signs, seals or derives does not hold the key: it holds a handle on a
key the kernel keeps, and asks the kernel to use it (the kernel-hosted `keys`
interface, an endpoint like `entropy`; no capability kind and no syscall number of
its own). The secret never reaches ring 3 (a key leaves only wrapped, and only if it
was made `wrappable`).

- **Policy.** Every key has one **purpose** (`SIGN`, an Ed25519 key; `SEAL`, a key
  that seals and opens 32-byte blocks; `DERIVE`; `WRAP`), an **envelope** (any task
  of the owner, or only the owner's tasks that run the image that made it), a
  **time to live** and a number of **uses**. A use outside the policy is answered
  `DENIED` and is a `key-use` decision record (`Rule::KeyUse`): subject the calling
  task, then the handle, the op (1 sign, 2 seal or unseal, 3 derive, 4 wrap or unwrap,
  5 public key or destroy) and the reason (1 the key does not allow the op, 2 not the
  key's owner or image, 3 the uses are used up, 4 expired). A refusal is a durable
  receipt, at most 8 a second; past that it is a ring record.
- **Per owner.** The table is shared and the keys are not: a handle belongs to the
  `owner_root` of the Domain that made it (0 is the system), another owner that
  presents it is refused with reason 2, and an owner holds at most
  `KEYSTORE_KEYS_PER_OWNER` of the `KEYSTORE_KEYS` slots.
- **Backends.** A volatile key is drawn from the entropy pool and lives in RAM. A
  named key is derived, with the owner, the purpose, the envelope, the image (for an
  image-bound key) and the name, from the root of its backend, so it is the same at
  every boot and nothing is stored: `boot` from the board seed of BOOTMETA's reserved
  sector; `tpm_nv` from a 32-byte secret in an NV index of the TPM (`KEYSTORE_TPM_NV`;
  the password of the index is a function of its number, like the OTA floor's, so it is
  as safe as the TPM bus); `volume` from a 32-byte file on a volume
  (`KEYSTORE_VOLUME_ROOT_PATH`, best under an `aead = true` `[volume.NAME]` row, where
  it is ciphertext on the medium and a volume cloned to another board does not open). A
  backend without a root answers `NOT_READY`.
- **Op classes.** `READ` uses a key and reads its public part (live while the system is
  contained: a signature is not an actuation); `WRITE` makes a key (refused while
  contained: no new secret is minted then; opening a *named* key is served, since
  the board determines it); `EXEC` wraps. A holder narrows itself with
  the capability's `OP_MASK`: `SSHD.ELF` is granted `generate`, `public` and `sign`.
- **Where the bytes go.** A request has seven words and a reply six. A name, a 32-byte
  secret or block and a sealed block (the 32 bytes and a 16-byte tag, an
  HMAC-SHA256-keyed synthetic IV with ChaCha20) travel inline; a signature and a
  message of up to 256 bytes do not, so `sign` works in a one-page memory object the
  caller shares for the call (`azos_libsys::dev::keys_sign`).
- **The console login** is the `login` op (the eleventh; `EXEC`, the one op of the
  login service's mask). It is not a use of a handle: it checks a credential
  against the signed topology and arms a grant. See "Console login" below.
- **The first user** is the SSH server: its host key is the named key `sshd.host`,
  bound to its image and derived from the board seed. The file `/fat/SSHHOST.KEY` and
  the sealing in ring 3 are gone; a compromised server can sign key exchanges (as it
  could) but cannot read the key, import another or wrap it out.

## Console login

Source: `crates/core/syscall/src/keys.rs` (`login_in`), `crates/core/crypto/src/keystore.rs`
(`login_public`), `crates/core/sched/src/domain.rs` (the grant, `set_owner_root`),
`crates/core/syscall/src/ushell.rs` (`SPAWN_F_USER`), `userspace/services/logind`,
`userspace/services/termd/src/{secure,service}.rs`, `userspace/lib/login`,
`config/subsys/Kconfig.console` (`CONSOLE_LOGIN`), `config/subsys/Kconfig.topology` (`LOGIN_*`).

With Kconfig `CONSOLE_LOGIN` and at least one `[login.NAME]` row in the signed topology the
console is **gated**: the native shell is a session of a user, started by the login service,
not by the component manager. With no such row, or the option off, the shell starts as it
always did and nothing asks for a credential. The gate is decided once, by the topology
(`azos_topology::builder::console_gated`): the kernel's launch plan leaves the shell out of
the manager's view, and only a gated console seeds the terminal server with its call right on
`endpoint.login`. A terminal server without that right never asks; with it, a login service
that does not answer keeps the console locked (fail closed: the server ends and the manager
restarts it).

- **Secure-attention key.** Ctrl+Alt+Del (input event ring) or the byte
  `LOGIN_SAK_SERIAL_BYTE` on a serial line. The terminal server owns console input, so it
  alone sees it. The user's session ends first, then the server asks for the name and the
  passphrase itself; the shell never reads them and the passphrase is not echoed. The server
  does not own the console's output: a system service may still print over the prompt.
- **Credential and record.** The server makes 32 bytes of the line (PBKDF2-HMAC-SHA256,
  4096 rounds, salted by the name). Nothing derived from the passphrase is stored: the
  `[login.NAME]` row lists the public half of an Ed25519 key made from the board's root, the
  user's root and name and the credential (`login_public`), so a verifier cannot be attacked
  without the board. `login_enroll` (`tests/host/logind-tests`) computes it.
- **The op.** `keys.login(user, credential)` (`EXEC`; the login service's mask lists this op
  and no other) compares in constant time with every key of the row; an unknown name does the
  same work. `LOGIN_MAX_FAILURES` refusals in a row lock the account `LOGIN_LOCKOUT_S`
  seconds. A user's `owner_root` is the row's place plus one, never 0.
- **The grant.** A verified credential arms a one-shot grant on the caller's Domain
  (`LOGIN_GRANT_TTL_S`), spent by the next `SPAWN_F_USER` spawn: that Domain, and every Domain
  beneath it, is owned by the user's root (its keystore scope). Spent at the start of the
  spawn; without a live grant the spawn is `-EACCES`.
- **Records.** Every call is a `login` decision record (`Rule::Login`, method 4): `Admit`
  with the user's root, or `Refuse` with the failures in a row and a reason (1 wrong secret or
  unknown user, 2 locked out, 4 no board root, 5 no signed topology). Every verdict of the
  rule is a durable receipt, so the SSH server's admit records are kept too. With nobody
  enrolled one `Admit` of the system's session is recorded. `why list -r login` shows them.
- **A session that will not end.** The prompt is drawn only once `Login::end` reports no
  session left; a shell that survives the forced stop keeps the session, every login is
  `NOT_NOW`, and a service that cannot be asked counts as a session that may still run.
- **Limits.** The lock counters are in RAM. A board with no key sector cannot enrol a console
  user. A shell that dies while the terminal server is outside one of its calls leaves the
  server in its accept until the login service restarts it.

## Link keys

Source: `crates/core/syscall/src/link_key.rs`,
`crates/core/crypto/src/secure_channel.rs`,
`domains/robot/behavior/src/encrypt_link.rs`, `userspace/lib/rpc/src/chan.rs`,
`config/subsys/Kconfig.topology`.

There are two kinds of authenticated link.

**Brain link** (robot domain). A 32-byte pre-shared key is provisioned into
reserved tail sector 0 of the boot medium, as a record with a magic, a version
and an integrity tag (`tools/sign/link_key_provision.py`). That sector is outside
the FAT volume and the USB mass-storage export never reports it, so a USB host
cannot address it. The kernel reads it only when no partition and no FAT32
volume reaches the tail, and refuses a sector that holds no valid record (a raw
key, a torn write, filesystem data): the link then stays down. There is no
write path from a running task. Ring 3 reads the key
through the kernel-hosted `linkkey` endpoint, which is refused unless the
caller holds an `Endpoint` capability with `READ` that the signed topology
granted (the `read` op returns the raw key; `RPCSRV.ELF` and `MCPD.ELF`
hold the same right masked to the `node_key` op, their own node
identity). The link is
always a Noise session: there is no plaintext mode, no MAC-only mode and no
runtime switch (a `CONFIG.INI` key would live on the FAT volume of a
removable card, so it would be an attacker-writable downgrade). Without the key the
link does not run. Over a TCP connection:

1. The handshake is Noise (`noise.rs`) in `ChaChaPoly_SHA256`, and the robot is
   the Noise *initiator* (it dials the brain and speaks first). The static keys
   derive from the provisioned key (HKDF-SHA256, one label per side), never the
   key itself as a curve scalar. When the signed topology's `[peer.brain]` row
   pins the brain's static public key (`noise_pk`; the `linkkey` endpoint's
   `brain_pk` op hands it to the ring-3 link client) the pattern is `IK`: the
   brain proves it holds the private half, and a leaked link key alone cannot
   impersonate it.
   Otherwise it is `XX` with the derived statics, and the robot compares the
   brain's static with the derived one before it sends its own, so `XX` is
   authenticated by the link key and is not trust-on-first-use. One pattern
   byte precedes the first message and is part of the prologue. A failed
   handshake ends the connection; there is no `REJECT` frame. The handshake
   hash gives a session id, kept in a replay cache.
2. The transport: Noise transport messages, framed with a 2-byte big-endian
   length (also the associated data), ChaCha20-Poly1305, the nonce being the
   cipher state's counter, which the wire does not carry. A dropped, repeated
   or reordered frame fails the AEAD and ends the session, which also closes
   in-session replay. A bare 16-byte tag (an empty message) is the rekey
   signal: both sides replace that direction's key with Noise `REKEY`. The
   sender rekeys at 2^20 messages, 1 GiB, a wall-clock interval of at most an
   hour, or on request; the receiver enforces the same limits.
3. The kernel seals one brain-protocol packet per transport message (it reads
   a run of packets out of one). There is no second MAC
   or replay floor inside it: replay is refused by the transport's message
   counter within a session, and a frame recorded in an earlier session fails
   the AEAD under the new keys.

An ephemeral key is a SHA-256 over a label, the link key, the clock, the cycle
counter, a salt and, when the entropy pool is seeded, 32 bytes from the pool
(`derive_ephemeral_priv`). With an unseeded pool the session is not
forward-secret; a build that enforces the link (below) refuses the handshake
instead, any other build proceeds.

Policy symbol:

| Kconfig symbol | Effect |
|----------------|--------|
| `LINK_PROVISIONING_ENFORCED` | Compile-time (cargo feature `link-provisioning-enforced`, which only Kconfig sets), no runtime override; on by default outside `BUILD_TYPE_DEV` (forced on in `BUILD_TYPE_CERTIFIABLE`). Boot halts rather than go on with no valid link key, the handshake is refused while the entropy pool is unseeded, and the UART bridge (brain-protocol frames, motion commands included, with no authentication, outside any session) is down in both directions. The link itself is the same Noise session in every build. |

**Node-to-node RPC links** (`userspace/lib/rpc`). Every session is
authenticated. A node dials with `Noise_IK_25519_ChaChaPoly_SHA256`: the dialer
knows the answerer's static key (its `noise_pk` in the topology's `[peer.NAME]`
row), sends its own encrypted in the first message, and the answerer accepts
only if that key is the one its topology pins for the node id the hello states.
Both static keys are the signed topology's. The node ids, the dialer's boot
epoch and a nonce are mixed into the Noise prologue, so an edited header makes
the handshake fail. The transport uses the Noise cipher states with an explicit
counter from the packet header, and a receiver refuses a counter it has seen, or
one that fell out of a 64-packet window, before decrypting anything. The
transport underneath (plain datagrams or QUIC, [network.md](network.md)) does not
change this: QUIC's own TLS layer authenticates nobody.
