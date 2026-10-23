# Variable page size

AzOS has one base page per build and three ways to map more than one base page
with a single translation. This note describes the base page on each ISA, the
three larger-translation mechanisms (boot-reserved 2 MiB leaves, 2 MiB
reservations that are promoted, and contiguous runs of small leaves), and the
break-before-make rule that changes between them have to follow on some CPUs.

## Contents

1. The base page
2. Why the base page is not a runtime choice
3. Boot-reserved 2 MiB leaves for locked rows
4. Superpage reservations
5. Contiguous runs of small leaves
6. The break-before-make gate
7. Limits
8. References

## 1. The base page

| ISA | Base page | How it is chosen |
|---|---|---|
| riscv64 | 4 KiB | Fixed: Sv39 has no other base page. A `page-16k` or `page-64k` feature reaching a riscv64 build fails a compile-time assertion in `arch-riscv64`. |
| x86_64 | 4 KiB | Fixed: the Kconfig choice exists only for aarch64. |
| aarch64 | 4, 16 or 64 KiB | Kconfig `AARCH64_PAGE_4K` (default), `AARCH64_PAGE_16K`, `AARCH64_PAGE_64K`, at compile time. |

On aarch64 the whole system, kernel and every user image, uses the one granule.
The choice reaches the build twice and the kernel refuses to compile if the
two disagree:
- as the cargo feature `page-16k` or `page-64k` (emitted by
  `tools/kconfig_to_cargo.py`), which sets `azos_arch_api::PAGE_SHIFT` and
  `PAGE_SIZE`;
- as `azos_limits::PAGE_SHIFT`, derived from `.config`, which `kernel/src/main.rs`
  asserts equal to the first.

`arch-aarch64`'s `Granule` (`crates/core/arch-aarch64/src/mmu/mod.rs`) carries
the consequences: the `TG0`/`TG1` encodings, `T0SZ`/`T1SZ`, the root size and the
boot tables. The 4 KiB and 16 KiB granules walk three levels over a 39-bit
input range, with the same virtual layout; at 16 KiB the root has 8 live
entries. The 64 KiB granule needs a 48-bit range to walk three levels, so the
kernel's upper half moves to `0xFFFF_0000_0000_0000`. A level-1 block is 2 MiB,
32 MiB and 512 MiB at the three granules.

A CPU that does not implement the granule the kernel was built for never
translates once the MMU is on, so the boot checks `ID_AA64MMFR0_EL1.TGran`
before enabling it and halts with an `[AARCH64-GRANULE] FATAL` message on the
console.

User images are linked for the same granule (`make AARCH64_PAGE_SIZE=16384` or
`65536`), and `libsys` exports `PAGE_SIZE`, taken from `AZOS_PAGE_SIZE` at
compile time.

**The topology unit does not move.** `mem_pages` in the signed topology is
counted in 4 KiB units (`TOPOLOGY_PAGE`) on every build and is converted to
frames at the allocator, so a topology means the same number of bytes on every
ISA and granule.

Source: `config/arch/Kconfig.isa` (`AARCH64_PAGE_*`, `PAGE_SHIFT`),
`crates/core/arch-api/src/lib.rs`, `crates/core/arch-riscv64/src/lib.rs`,
`crates/core/arch-aarch64/src/mmu/mod.rs`, `kernel/src/main.rs`,
`kernel/src/entry/aarch64/mod.rs`, `crates/core/libsys/src/lib.rs`,
`crates/core/topology/src/memory.rs`.

## 2. Why the base page is not a runtime choice

A larger base page holds more per TLB entry and needs fewer page-table levels
for a dense region. It also rounds up every per-task allocation: the stack, each
ELF segment, each page table, the vDSO page. AzOS's workloads are the case where
that rounding hurts.

- Address spaces are sparse: text, stack, the vDSO and device windows sit in
  different slots, so each region pays for at least a table frame, and a table
  frame is a whole page at any granule.
- Stacks are populated eagerly, so a larger page is a larger stack unless the
  default is changed (the 16 KiB and 64 KiB builds change the default kernel and
  user stack sizes).
- Frame budgets are page-counted, so a larger page also makes enforcement
  coarser: a task can no longer be held to a few pages.
- Copy-on-write copies a whole page on the first write, and a forked pair
  shares more.
- A small-memory profile pays the rounding on every task.

Two of those costs are specific to this tree. First, riscv64 cannot follow:
the same source would run on a 4 KiB base page on one ISA and a different
granule on another. Second, the signed topology and the shared-memory sizes
would become ISA-dependent, which is why the topology unit is fixed above.

The way to get most of the TLB benefit without the rounding is to keep the base
page small and map the few big, long-lived regions with larger translations.
That is what the next three sections do.

Source: `config/arch/Kconfig.isa`, `crates/core/topology/src/memory.rs`.

## 3. Boot-reserved 2 MiB leaves for locked rows

Kconfig `LOCKED_HUGE_LEAVES` (default off) lets a `mem = "locked"` ring-3
topology row declare `mem_huge_mib = N` (N even, at most `MAX_HUGE_MIB`). The
region is for a model, a tensor arena or a pipeline buffer: big, long-lived,
fully populated, never forked.

- **Reservation at boot.** `azos_mm::huge::reserve` takes N MiB of physically
  contiguous RAM, aligned to the level-1 leaf size, from the allocator once, at
  boot, right after memory admission counted it. A 2 MiB-aligned run is exactly
  what fragmentation makes impossible later, so it is not allocated at run time.
  The region is keyed by the row and never given back; the row's next instance
  gets the same frames, zeroed again.
- **Admission.** The region counts as locked pages, N x 256 topology pages
  (`crates/core/pkg/src/admit.rs`, `crates/core/topology/src/memory.rs`). A row
  that declares it without `mem = "locked"`, or with more than one instance, is
  refused. With the option off, a topology that declares `mem_huge_mib` is
  refused at boot rather than run without the region.
- **Mapping.** `exec` maps the region (`install_locked_arena` in
  `crates/core/sched/src/process.rs`) at `LOCKED_ARENA_VA`, the first level-1
  leaf boundary at or above the shm/MMIO window's base, with level-1 leaves
  (`vmm::map_user_mega_range`): read-write, never executable, with accessed and
  dirty preset because a locked task must take no fault. Only `exec` installs it;
  spawning such a row is refused.
- **Lifetime.** Never forked (a locked row cannot fork), never demand-paged,
  never copy-on-write. `munmap` of any part of it is refused. Teardown skips the
  level-1 user leaf (`vmm::destroy_user_pagetable_skip_range`) and never frees
  the frames.
- **Cost of the shape.** Memory is pinned and unreclaimable. Internal
  fragmentation is explicit: the topology author sizes the region.

Source: `config/arch/Kconfig.isa-riscv64` (`LOCKED_HUGE_LEAVES`), `crates/core/mm/src/huge.rs`,
`crates/core/mm/src/vmm.rs`, `crates/core/sched/src/process.rs`,
`crates/core/pkg/src/admit.rs`, `crates/core/topology/src/memory.rs`,
`crates/core/topology/src/types.rs`.

## 4. Superpage reservations

Kconfig `MM_THP_RESV` (default on for the desktop and server profiles, off
elsewhere; needs demand paging and a 4 KiB base page) uses the reservation
scheme of FreeBSD for anonymous memory in ordinary tasks.

- **Reserve.** The first fault in a 2 MiB-aligned part of an anonymous `mmap`
  region that lies wholly inside one region record, with nothing mapped in it
  yet, takes a physically contiguous, 2 MiB-aligned run from the page
  allocator. That fault and the following ones fill 4 KiB pages from the run,
  each zeroed when it is handed out. The bookkeeping (which block of which
  address space holds which run, which frames were handed out and installed) is
  plain data in `crates/core/mm/src/resv.rs`.
- **Promote.** When every frame of the run is installed with the same
  permissions and no copy-on-write mark, `promote_user_block` replaces the
  level-0 table with one level-1 leaf: one TLB entry for 2 MiB and a walk one
  level shorter. The old table is freed in `promote_finish`, outside the locks.
- **Break.** Whatever cuts the block first breaks the reservation, and the
  frames not yet handed out go back to the allocator: an `munmap` or `mprotect`
  of part of it, a fork, the task's exit, an allocator that runs dry. A promoted
  leaf is split back into 512 4 KiB leaves (`split_user_mega`) before part of it
  is unmapped or re-protected, or the space is forked.
- **Who never reserves.** A `mem = "locked"` task and a real-time-class task
  commit at map time and never fault, so they never reserve; `MAP_POPULATE` and
  `MAP_LOCKED` mappings likewise.
- **Why it is off by default.** A reservation holds up to 2 MiB of frames that
  no page uses yet, inside a region the task's quota has been charged for whole,
  and the fault that fills the last page pays for the promotion, a latency
  spike a control loop does not want. A 16 KiB or 64 KiB granule has 32 MiB or
  512 MiB blocks, too coarse to reserve, so this is available only with a 4 KiB
  base page.

This is the opposite model from the previous section: reservation is
opportunistic and reversible, the locked-row region is declared, static and
permanent.

Source: `config/kernel/Kconfig.mm` (`MM_THP_RESV`), `crates/core/mm/src/resv.rs`,
`crates/core/mm/src/pager.rs`, `crates/core/mm/src/vmm.rs`.

## 5. Contiguous runs of small leaves

Both aarch64 and riscv64 let a run of adjacent small leaves be cached as one TLB
entry, as a hint the hardware may ignore.

| ISA | Mechanism | Run | Kconfig |
|---|---|---|---|
| aarch64 | The contiguous bit (descriptor bit 52) on identically attributed level-3 leaves | 16 pages at 4 KiB (64 KiB), 128 at 16 KiB and 32 at 64 KiB (2 MiB in both) | `A64_CONTIG_HINT` (default on) |
| riscv64 | Svnapot: the N bit (PTE bit 63) with `PPN[3:0] = 0b1000` | 16 pages (64 KiB) | `RV_SVNAPOT_NEVER`, `_PROBE` (default), `_REQUIRE` |
| x86_64 | None below a 2 MiB leaf | 0 | n/a |

- **Planning is ISA-neutral.** `crates/core/arch-api/src/contig.rs` holds the
  arithmetic: a run is `contig_run_pages` leaves, the first at a virtual and a
  physical address both aligned to the run's size, the frames consecutive, every
  word one set of attributes. The ISA supplies `pte_make_contig_leaf`,
  `pte_is_contig` and `pte_contig_member` through the `Mmu` trait.
- **Where runs are written.** The user mapper of a memory object
  (`vmm::map_contig_range`, reached from `shm_map_user`) writes a run for every
  aligned stretch of consecutive frames and a plain leaf for everything else.
  The frames come from the page allocator in whatever order its lists gave
  them, so a run is the stretch that happens to be aligned and consecutive. A
  run is written whole or not at all.
- **Runs are a unit.** If one member changed alone, the TLB might still
  translate the old state through the others. Every mutator that can reach a
  run therefore breaks it into plain leaves first (`break_contig_run`): unmap,
  mprotect, and the memory-object unmap and revoke paths. Readers that turn a
  leaf into a physical address ask `Mmu::pte_leaf0_span`, because a NAPOT word
  names the whole run.
- **riscv64 detection.** Svnapot has no enable bit; `cpu@0`'s `riscv,isa` token
  is the whole probe (`ext::napot::select`). Setting N on a hart without the
  extension is a reserved-bit fault, so the decision is made once at boot.

Source: `config/arch/Kconfig.isa-aarch64` (`A64_CONTIG_HINT`, `RV_SVNAPOT_*`),
`crates/core/arch-api/src/contig.rs`, `crates/core/arch-riscv64/src/ext/napot.rs`,
`crates/core/arch-aarch64/src/api_impl.rs`, `crates/core/mm/src/vmm.rs`.

## 6. The break-before-make gate

Changing a translation from a table to a block, or a block to a table, or
breaking a contiguous run, is a change of the size a TLB entry covers. On some
aarch64 CPUs that is only allowed after the old entry is invalid and flushed;
done in place, the TLB may hold both the block and entries of the old table, and
the CPU may raise a TLB conflict abort.

- **The question.** `Mmu::block_change_needs_bbm` (`azos_arch_api`) says whether
  the change must be made break-before-make. riscv64 and x86_64 define no such
  abort for the same-map change the kernel makes and answer `false`. aarch64
  answers `true` unless every CPU reports FEAT_BBM level 2
  (`ID_AA64MMFR2_EL1.BBM >= 2`), for which the change is allowed in place.
- **The weakest CPU counts.** `BbmSurvey` in
  `crates/core/arch-aarch64/src/cpu/features.rs` collects each CPU's answer as
  it comes up. A system that mixes CPUs would otherwise let a block made while
  only a level-2 CPU was looked at meet a CPU that aborts. Until the boot's
  expected number of CPUs have all noted themselves (`expect_cpus_bbm`), the
  answer is break-before-make, which is correct on every CPU.
- **The sequence** (`l1_replace` in `crates/core/mm/src/vmm.rs`). Without the
  need: one compare-and-swap of the level-1 word, and the caller shoots the
  range down afterwards. With it:
  1. interrupts off on this CPU;
  2. break: the slot becomes `PTE_BBM_PARK`, an invalid marker, by compare-and-swap
     from the old word, so a racing writer of the slot loses cleanly;
  3. shoot the range down. On aarch64 this is a hardware broadcast, so there is
     no inter-processor interrupt to wait for with interrupts off;
  4. make: store the new word and publish it.
  The window is the shootdown's length and cannot be stretched by a preemption.
  The same shape, over the sixteen or more members of a run, is
  `break_contig_run`.
- **A thread that touches the range meanwhile** does not see it as unmapped. A
  software walk waits in `l1_load` or `l0_read` while the word is
  `PTE_BBM_PARK`. A hardware fault on a parked word waits in
  `wait_out_parked_fault` and the access is retried. A fault handler of the
  space takes the table lock first, and `promote_user_block` holds it across
  the window, so the handler runs after the make.
- **Verification.** QEMU does not model the conflict abort, so the order and the
  wait are pinned by host tests and the abort itself is a hardware question.

Source: `crates/core/arch-api/src/lib.rs`, `crates/core/arch-aarch64/src/cpu/features.rs`,
`crates/core/arch-aarch64/src/api_impl.rs`, `crates/core/arch-riscv64/src/api_impl.rs`,
`crates/core/arch-x86_64/src/lib.rs`, `crates/core/mm/src/vmm.rs`,
`kernel/src/entry/aarch64/smp.rs`.

## 7. Limits

- A TLB hint (a contiguous run) may be ignored by the hardware; a gain is not
  guaranteed, and a block or a run is not a lockdown of the translation.
- A 2 MiB leaf is data only: never executable, and not for small tasks.
- The benefit of a block depends on how many large-page entries the hardware
  can keep live. On a core whose second-level TLB holds only 4 KiB entries, a
  block evicted from the first level goes straight back to the walker, so many
  small tasks each holding blocks can thrash rather than help.
- Superpage reservations trade memory and a latency spike at promotion for TLB
  reach, which is why a real-time task never reserves.
- QEMU shows the mappings (page-table walks, counts of frames and levels); it
  does not model the TLB, so the effect of any of this on translation misses is
  a question for hardware counters.
- Not built: a runtime choice of base page; promotion of executable or
  copy-on-write memory; a contiguous-run counterpart on x86_64.

Source: `config/kernel/Kconfig.mm` (`MM_THP_RESV`), `config/arch/Kconfig.isa`,
`crates/core/mm/src/vmm.rs`.

## 8. References

Source: external; these are the documents the design follows.

- Arm Architecture Reference Manual, FEAT_BBM and the contiguous bit; Linux,
  "HugeTLBpage on ARM64": https://docs.kernel.org/arch/arm64/hugetlbpage.html
- The RISC-V Instruction Set Manual, Volume II, Privileged Architecture, the
  Svnapot chapter.
- Linux, "Transparent Hugepage Support":
  https://docs.kernel.org/admin-guide/mm/transhuge.html
- Navarro, Iyer, Druschel, Cox, "Practical, transparent operating system
  support for superpages", OSDI 2002 (the reservation scheme FreeBSD took).
