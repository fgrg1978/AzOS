# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# config/kernel/Kconfig.mm — Memory management: TLB, kernel heap, reclaim, swap, page zones

config TLB_RETAIN
    bool "Keep TLB entries across user address-space switches (ASID/PCID tags)"
    default y
    help
      A switch between user address spaces installs the incoming root with
      its ASID (riscv64 satp.ASID, aarch64 TTBR0_EL1.ASID with nG user
      leaves, x86_64 PCID with the CR3 no-flush bit) and does NOT flush the
      TLB, so a task coming back finds its translations still cached.
      ASIDs carry a generation (crates/core/sched/src/asid.rs): when the
      ASID space runs out the generation advances and each hart flushes
      once before running a new-generation ASID; a space whose ASID was
      taken re-tags at its next switch-in, to the ASID the first of its
      threads to be switched in took: one ASID per address space per
      generation (the record lives in the TLB_SPACE_SLOTS_BITS table).
      A shootdown that cannot reach a
      hart that ran the space marks that hart stale, and its next switch
      flushes (crates/core/arch-api/src/tlb_gen.rs).

      Boards whose MMU has no ASID bits (the boot probe reads 0) keep
      flush-on-switch whatever this says.

      Cost: 16 bytes of RAM per ASID (2^ASID_BITS slots); per switch a
      few loads and one atomic swap, against a full TLB refill. Say n to
      get the old flush on every address-space switch (for comparison, or
      to rule the TLB out when chasing a stale-translation bug).

config ASID_BITS
    int "Address-space ID width the allocator uses (bits)"
    range 1 16
    default 8 if TLB_RETAIN && HWCLASS_EMBEDDED
    default 12 if TLB_RETAIN
    default 16
    help
      Width of the ASID space user address spaces draw from
      (crates/core/sched/src/asid.rs): ASIDs 1 to 2^ASID_BITS - 1, 0
      being the kernel's.  The cap on what the hardware offers: the boot
      probes what the MMU implements (riscv64: satp.ASID written all-ones
      and read back, the spec's ASIDLEN; aarch64: ID_AA64MMFR0_EL1.ASIDBits;
      x86_64: 12 with CR4.PCIDE) and uses the smaller of the two; a hart
      with no ASID bits gets 0 for every address space and flushes on
      every switch.  When the space runs out the generation advances (a
      rollover): every hart flushes once.

      With TLB_RETAIN the allocator keeps one 16-byte slot per ASID, so
      this sets RAM (8 bits: 4 KiB; 12: 64 KiB) against how often a
      rollover forces flushes (once per 2^ASID_BITS - 1 forks/execs).
      Without TLB_RETAIN every switch flushes and the width costs nothing.

      Change it only to test: 1 (one ASID) makes every new address space
      a rollover, which is what the stale-translation ktest runs under;
      2 (three ASIDs) is what the ASID gate row runs under.

config TLB_SPACE_MASK
    bool "Per-address-space hart mask: a shootdown marks stale only the harts that ran the space"
    depends on TLB_RETAIN
    default y
    help
      With TLB_RETAIN a hart that ran an address space and switched away
      keeps its entries under the space's ASID/PCID. The riscv64 and x86_64
      shootdowns reach only the harts running the space now, so without
      this every other hart is marked stale and flushes its whole TLB at
      its next user switch. With it, each switch-in records the hart in a
      table keyed by the space's root frame (crates/core/arch-api/src/
      tlb_gen.rs, Linux's mm_cpumask), and a shootdown marks stale only
      the harts recorded for that space in the current ASID generation,
      plus any hart whose TLB is of an older generation. The table resets
      at each ASID rollover. aarch64 invalidates with broadcast TLBI and
      records nothing.

      Cost: 2^TLB_SPACE_SLOTS_BITS x 20 bytes of RAM; per user switch one
      hash, a few probes and one atomic OR; per shootdown the same lookup
      instead of nothing. Saves a full TLB flush on every hart that never
      ran the space. Say n to go back to marking every hart (to rule the
      table out when chasing a stale translation).

config TLB_ASID_SCOPED
    bool "ASID-scoped shootdowns: invalidate only the target address space's ASID"
    depends on TLB_RETAIN
    default y
    help
      With TLB_RETAIN each address space holds exactly one ASID per
      generation (crates/core/sched/src/asid.rs, the per-space record in
      crates/core/arch-api/src/tlb_gen.rs). A shootdown of one space can
      then invalidate that ASID only, and leave every other space's
      retained entries in place.

      riscv64: `sfence.vma va, asid` / `sfence.vma zero, asid` locally and
      SBI REMOTE_SFENCE_VMA_ASID remotely, for every hart whose live ASID
      for the space is the recorded one; a hart still running the space
      under an older generation's ASID (it has not been switched since a
      rollover) gets the all-ASID form.

      aarch64: `TLBI ASIDE1IS` / `TLBI VAE1IS` on the recorded ASID instead
      of `VMALLE1IS` / `VAAE1IS`. The broadcast reaches every PE, including
      one still on an older generation that may hold the space under an
      older ASID, so it is scoped only when every PE's TLB generation is the
      record's (or the PE has not run a user space since boot);
      otherwise all-ASID. Extra cost: one load per
      NR_CPUS per shootdown. Global (kernel) entries in the low half, such as
      device mappings, are not reached by ASIDE1IS; user shootdowns never
      target them.

      x86_64: the IPIs already reach only the CPUs on the root, so the
      gain is the shooter's: with PCIDE and INVPCID (X86_INVPCID probe or
      require) it invalidates the space's PCID directly (INVPCID type 0 per
      page, type 1 past TLB_FLUSH_CEILING_PAGES) when its own TLB is of the
      record's generation, instead of `invlpg` on the live PCID plus a mark
      that flushes its whole TLB at its next user switch. Without INVPCID
      the symbol has no effect there.

      Cost: per shootdown one record lookup (a few loads; up to one per
      slot of the TLB_SPACE_SLOTS_BITS table when it is nearly full, so
      keep it at about half load) and at most one more SBI call than
      without; saves every other ASID's entries on
      every hart a shootdown reaches. Say n to go back to all-ASID
      invalidation (to rule it out when chasing a stale translation).

config TLB_SPACE_SLOTS_BITS
    int "Per-address-space hart mask: table size (log2 slots)"
    range 1 16
    default 9 if HWCLASS_EMBEDDED
    default 13
    help
      Slots in the TLB_SPACE_MASK table (2^n, 20 bytes each: 9 is 10 KiB,
      12 is 80 KiB, 13 is 160 KiB). The non-embedded default is 13, one bit
      above the default ASID_BITS (12), so the table stays at or below half
      load when every ASID is live: a lookup then ends within a few probes
      and a burst of new spaces runs the ASIDs out (a rollover) before it
      fills the table. At 12/12 a near-full table costs up to
      TLB_SPACE_PROBE loads per switch and shootdown and can force a
      rollover early; 13 costs 80 KiB more RAM than 12. Embedded keeps 9
      (10 KiB) over ASID_BITS 8. Each address space switched into during one ASID
      generation takes one slot, so a size of about twice the live address
      spaces keeps probes short. When a space finds no free slot within
      TLB_SPACE_PROBE probes the table is marked overflowed and every
      shootdown of an unrecorded space marks every hart stale (the
      behaviour without the table) until the next rollover. Raise it for
      systems with thousands of processes.

      The same table holds each address space's ASID for the current
      generation (one ASID per space), whenever TLB_RETAIN is on, mask or
      not. A space that finds the table full forces an ASID rollover, so
      keep 2^n above 2^ASID_BITS (one more bit keeps the load at or below
      half); at n = ASID_BITS a burst of new spaces can roll the
      generation over before the ASIDs run out. The ASID costs 4 more
      bytes per slot.

config TLB_SPACE_PROBE
    int "Per-address-space hart mask: probes before the table counts as full"
    range 1 64
    default 8 if HWCLASS_EMBEDDED
    default 16
    help
      Linear-probe bound of the TLB_SPACE_MASK table, on every user switch
      and every shootdown. Each probe is one or two loads. A larger bound
      tolerates a fuller table before it overflows (see
      TLB_SPACE_SLOTS_BITS), at more instructions in the worst case.

config TLB_FLUSH_CEILING_PAGES
    int "Pages above which a ranged TLB flush drops the whole address space"
    range 1 4096
    default 33
    help
      A shootdown or local flush of more than this many pages flushes the
      whole address space (x86_64: the PCID's non-global entries; the
      kernel's own range: everything) instead of one invalidation per
      page. Linux's tlb_single_page_flush_ceiling, also 33. Read by
      x86_64 (crates/core/arch-x86_64/src/tlb.rs) and by riscv64's local
      part (crates/core/arch-riscv64/src/tlb.rs, which runs masked);
      aarch64 broadcasts and still invalidates page by page. This is the plan's
      TLB_FLUSH_THRESHOLD_PAGES (N12).

      Cost: below the ceiling one invlpg (~100-200 cycles) per page, on
      every CPU signalled; above it one full flush plus the re-walks it
      causes. Raise it for workloads that unmap mid-sized ranges of a
      big, hot working set; lower it on CPUs with a slow invlpg.

config MM_DEMAND_PAGING
    bool "Demand-paged anonymous mmap"
    default n if USE_INDUSTRIAL || USE_AUTOMOTIVE
    default y
    help
      Wave 14 (DEMANDPAGE): an anonymous mmap (native SYS_MO_MAP and the
      Linux personality's) reserves its range and commits each page on
      the first touch, from the region's pager (zero-filled anonymous
      memory; crates/core/mm/src/pager.rs).  The reservation is charged
      to the task's page budget when it is made, so a
      fault never refuses on quota.  A kernel copy into a reserved page
      (read() into fresh mmap memory) commits it as the fault would.

      Pre-committed regardless: a mapping with MAP_POPULATE (0x8000) or
      MAP_LOCKED (0x2000), every mapping of a mem = "locked" task (which
      must take no page fault), and with MM_PRECOMMIT_RT every mapping
      of a real-time-class task.

      With this off every mmap commits every page at map time, the
      pre-wave-14 behaviour; the industrial and automotive domains start
      with it off (static memory, a fault never lands in a control loop).  Cost: no static RAM beyond
      MM_REGIONS_PER_SPACE's table.

config MM_PRECOMMIT_RT
    bool "Pre-commit mmap for real-time-class tasks"
    depends on MM_DEMAND_PAGING
    default y
    help
      A task of class SafetyCritical, HardRT or SoftRT gets every mmap
      page committed at map time, as if it had passed MAP_POPULATE: a
      control loop never takes a demand fault, whose cost (a page zeroed
      in the fault path) would land inside its period.  Off: such tasks
      demand-fault like any other unless they ask for MAP_POPULATE.

config KHEAP_SLAB
    bool "Per-CPU size-class cache in front of the kernel heap"
    default y
    help
      Wave 15 (SLAB). Small kernel heap requests (up to KHEAP_SLAB_MAX_CLASS
      bytes) are served from per-CPU magazines of fixed size classes, a
      per-class depot of full and empty magazines, and slabs carved from the
      heap (crates/core/mm/src/slab.rs). Alloc and free of a small object
      are then O(1) with no lock and no heap walk while the CPU's magazines
      hold or have room for it; a miss costs at most one magazine of slab
      work with interrupts masked, never a heap walk. Larger requests, and
      every request with this off, go to the first-fit heap exactly as
      before (off is today's allocator, kept for comparison).

      Measured (riscv64, -icount, wave 15): the kernel heap is not on any
      vsbench hot path (spawn, thread, fork, IPC, file, UDP make no heap
      allocation); procfs text on open was its main user then (the kernel
      keeps no /proc since 2026-10-21). So this moves no
      lane; it bounds what an allocation costs. A heap refusal first gives
      back what this layer caches (this CPU's magazines, the depot, empty
      slabs) and retries once; a refusal is still a refusal.

      Cost: 3,712 B of .data (riscv64, measured: 8 CPUs x 2 x 16 magazine
      pointers and 17 class locks) and about 0.5 KiB of tables, plus, in the
      heap, what the options below let it cache (edge defaults: at most
      27 KiB per CPU, 54 KiB of depot, one 4-32 KiB slab per class in use).
      Instructions (riscv64, -icount): a small alloc or free that its
      magazine serves is about 40 (an alloc+free pair 81) against 310-360
      for the first-fit heap on a nearly empty heap and 1,700+ with 256
      small holes in front of the request; a request above the largest class
      pays about 7 more than before (the interrupt-context owner check in
      crates/core/mm/src/kheap.rs).
      Same on both ISAs: nothing here depends on the page granule.
      The KHEAP_SLAB_* options below are read only with this on.

config KHEAP_SLAB_DEBUG
    bool "Poison freed objects and check red zones"
    default y if LOG_LEVEL_DEBUG && BUILD_TYPE_DEV
    help
      A freed small object is filled with 0x6b and checked on its next
      allocation (a write after free panics with the object's address); the
      bytes between the requested size and the class size are filled with
      0xbb and checked on free (an overrun panics). On by default only in
      a development build (BUILD_TYPE) at the debug log level, the QEMU
      development configurations, never in a release build by default.
      Cost: a fill and a scan of the object on every alloc and free (about
      size/8 to size instructions each), nothing in RAM.

config MM_THP_RESV
    bool "Superpage reservations: a 2 MiB run per aligned anonymous region, promoted when full"
    depends on MM_DEMAND_PAGING
    depends on !AARCH64_PAGE_16K && !AARCH64_PAGE_64K
    default y if USE_DESKTOP || USE_SERVER
    default n
    help
      FreeBSD-style reservations (crates/core/mm/src/resv.rs, pager.rs).
      The first fault in a 2 MiB-aligned part of an anonymous mmap region
      (one that lies wholly inside one region record, with nothing mapped
      in it yet) takes a physically contiguous, 2 MiB-aligned run from the
      page allocator; that fault and the following ones fill 4 KiB pages
      from the run, each zeroed when it is handed out. When all of the run
      is filled, with the same permissions and no copy-on-write mark, the
      level-0 table is replaced by one level-1 leaf: one TLB entry for
      2 MiB and a walk one level shorter. Whatever cuts the block first
      (munmap or mprotect of a part, a fork, the task's exit, an allocator
      that runs dry) breaks the reservation, and the frames not yet handed
      out go back to the allocator; a promoted leaf is split back into
      4 KiB pages before a part of it is unmapped or re-protected, or the
      space is forked (crates/core/mm/src/vmm.rs).

      Not affected: a mem = "locked" task and a real-time-class task
      (MM_PRECOMMIT_RT) commit at map time and never fault, so they never
      reserve; MAP_POPULATE and MAP_LOCKED mappings likewise. Only a 4 KiB
      base page offers it (the level-1 leaf of a 16 KiB or 64 KiB granule is
      32 MiB or 512 MiB, too coarse to hold a run for).

      aarch64: a CPU without FEAT_BBM level 2 (Cortex-A53, A72, A76: the
      Raspberry Pi 3 and 5) may answer a table-to-block change with a TLB
      conflict abort, so the promotion (and the split back) is done
      break-before-make there: the level-1 slot is made invalid, the block's
      translations are flushed on every CPU, then the leaf is stored, with
      interrupts off on the one CPU that does it (about 512 TLB
      invalidations, the length of the window). A thread of the space that
      touches the block meanwhile faults or waits, and continues on the
      leaf. The level is read from every CPU as it comes up and the weakest
      one counts. QEMU does not model the abort, so the sequence is checked
      on the host and by a boot of the real board, not by a QEMU run.

      Off by default outside the desktop and server presets: a reservation
      holds up to 2 MiB of frames no page uses yet (inside a region the
      task's quota has been charged for whole), and the fault that fills the
      last page pays for the promotion, a latency spike a control loop does
      not want.

      Cost: 160 B of .bss per reservation slot, min(MAX_TASKS, 64) slots
      (10 KiB at 64 tasks or more), both ISAs; off: +0 B. On the fault path
      one lookup under a short IRQ-safe lock per fault inside a reserved
      block, and the first fault of a block allocates its run (no zeroing).

choice
    prompt "Memory reclaim (what the kernel does with anonymous pages under pressure)"
    default MM_RECLAIM_COMPRESS if USE_WEARABLE || USE_IOT_HMI || USE_GATEWAY || USE_DESKTOP || USE_SERVER
    default MM_RECLAIM_OFF
    help
      The macOS/XNU model (owner 11-10): compressor first. An explicit choice
      per profile, never an implicit default: robot, industrial, automotive, firmware and the generic image
      stay off (determinism, admission instead of overcommit, SD/eMMC wear);
      wearable, iot-hmi, gateway, desktop and server compress.

      Only the stages that have code are offered. Plain `reclaim` (page-cache
      drop, MGLRU, the scanner) is a later stage: it gains a member
      here when it gains an implementation. Segment swap is not a member of
      this choice: it is MM_SWAP_BACKEND, on top of the compressor.

    config MM_RECLAIM_OFF
        bool "off: no reclaim; admission instead of overcommit"
        help
          Nothing compresses; the compressed-page pool
          (crates/core/mm/src/zpool.rs) is compiled to zero-sized tables and
          the page-fault path's tests on it are constants that fold away.
          Cost: about 0.1 KiB of .bss, the pool's lock, counters and key slot.

    config MM_RECLAIM_COMPRESS
        bool "reclaim+compress: anonymous pages are compressed before anything else"
        help
          A page the reclaimer picks is compressed (MM_COMPRESS_ALGO) into a
          segment of the compressed-page pool, encrypted under an ephemeral
          boot key, charged to the owning Domain's pool quota (H5), and its
          frame freed. The next touch decompresses it into a fresh frame
          (crates/core/mm/src/pager.rs). A zero or same-filled page is kept as
          one index entry and no bytes; a page that does not compress below
          MM_ZPOOL_MAX_RATIO_PCT is not stored and stays resident. Real-time
          and pinned memory is never offered to the pool (L7 admission).

          The page stays reachable through a marker the reclaimer leaves in
          its page-table slot (the slot is not present, the pager reads what
          it says: in transit, compressed, on swap), so a fault that races
          the store waits for it and a page nobody stored is zero-filled
          without a look at the pool.

          Cost: see MM_ZPOOL_ENTRIES, MM_ZPOOL_SEGMENTS and
          MM_ZPOOL_SEGMENT_PAGES for the tables and the segments; one pool
          lookup on the fault of a page that was stored, none on any other
          fault.
endchoice

choice
    prompt "Compression algorithm of the compressed-page pool"
    default MM_COMPRESS_ALGO_WKDM
    help
      Read only with MM_RECLAIM_COMPRESS. WKdm (Wilson-Kaplan-Smaragdakis,
      crates/core/crypto/src/wkdm.rs) is a word-based coder built for memory
      pages: one pass, no allocation, any of the three page sizes. LZ4 is the
      intended second option; it joins this choice when its coder exists in the
      tree.

    config MM_COMPRESS_ALGO_WKDM
        bool "wkdm"
endchoice

config MM_ZPOOL_MAX_RATIO_PCT
    int "Largest compressed size worth storing (% of a page)"
    range 10 95
    default 75
    help
      Read only with MM_RECLAIM_COMPRESS. A page whose compressed form is
      larger than this share of the page is not stored: it stays resident
      for the reclaimer to drop or (later) swap. Storing a 90% page saves a
      tenth of a frame and still costs a compression, a decryption on the
      way back and a slot of the index. Recorded threshold (plan: "the
      thresholds are recorded"); the host row measures the pool's saving at
      it.

config MM_RECLAIM_HIGH_PCT
    int "Domain reclaim high watermark (% of its frame limit)"
    range 2 99
    default 85
    help
      Read only with MM_RECLAIM_COMPRESS. A Domain whose frame budget
      (mem_pages) has this share of its limit charged is under pressure
      (level "warning") and starts a reclaim storm: its swappable, unlocked
      anonymous pages are compressed into the pool until the charge is back
      at MM_RECLAIM_LOW_PCT. The level is "critical" at the limit itself, and
      "normal" again once the charge is back at the low watermark. A Domain
      that binds a Port to its pressure (PORT_BIND with PORT_SRC_PRESSURE) is
      told each change of level with a PORT_EVENT_PRESSURE event, and its
      storm waits one poll after a first "warning" so the program can give
      memory back first (azos_ualloc drops its quarantine). A Domain without a
      frame limit has no watermark and never reclaims. A Domain on a "locked"
      memory row is never reclaimed, whatever its charge.

      Cost: two u32 words in each Domain's frame budget (watermarks derived
      when the limit is declared), one atomic load per charge; a byte for the
      last level told and a lock-guarded Port reference per Domain slot.

config MM_RECLAIM_LOW_PCT
    int "Domain reclaim low watermark (% of its frame limit)"
    range 1 98
    default 65
    help
      Read only with MM_RECLAIM_COMPRESS. Where a reclaim storm stops: the
      Domain's charge is back at this share of its limit. Must be below
      MM_RECLAIM_HIGH_PCT (the build refuses otherwise). The gap is the
      hysteresis: a Domain that just left a storm has room to grow before
      the next one starts.

config MM_RECLAIM_POLL_MS
    int "Reclaim task poll interval (ms)"
    range 10 60000
    default 100
    help
      Read only with MM_RECLAIM_COMPRESS. The reclaim task looks at the free
      frame count at this interval: the page allocator cannot wake a task (it
      runs under its callers' locks), and nothing is added to its hot path.
      The longest memory can sit below the low watermark before a pass starts.

      Cost: one wake per interval while the system is otherwise idle.

config MM_AGING_INTERVAL_MS
    int "Page-age pass interval per Domain (ms)"
    range 100 600000
    default 1000
    help
      Read only with MM_RECLAIM_COMPRESS. A Domain with a frame limit and a
      charge above its low watermark has its pages aged at most this often:
      the pass clears the Accessed bit of each resident anonymous page and
      collects the bits set since the last pass, so one generation is one
      interval of not being used. A Domain below its low watermark is not aged
      (it cannot be asked to give memory back soon); one that crosses it is
      aged at the next reclaim poll. Recorded threshold: a page is oldest after
      three intervals idle (3 s at the default); shorter intervals separate hot
      from cold pages sooner and pay the pass more often.

      Cost: a walk of the Domain's resident pages per interval, on the reclaim
      task's CPU, with a short IRQ-off section per 64 pages. Where the CPU does
      not set the Accessed bit itself (Svade without Svadu on riscv64, aarch64
      without FEAT_HAFDBS) every page cleared costs one fault on its next use;
      the interval bounds that to one fault per page per interval.

choice
    prompt "Swap: where full compressed segments are written"
    depends on MM_RECLAIM_COMPRESS
    default MM_SWAP_BACKEND_PARTITION if USE_SERVER
    default MM_SWAP_BACKEND_FILE if USE_DESKTOP || USE_IOT_HMI
    default MM_SWAP_BACKEND_OFF
    help
      The last stage of the reclaim order (owner 16-10): when the compressed
      pool is full, whole segments of it (never single pages) are written to
      the medium and their frames freed. A fault on a page of a swapped
      segment reads the segment back, verifies it and carries on as for any
      compressed page.

      Encrypted always (MM_SWAP_ENCRYPT); the swap space is a quota on the
      Domain (MM_SWAP_DOMAIN_KIB); the I/O goes through the block layer's
      queue and is never made from a real-time hart; a Domain on a locked
      memory row never has a page in a swapped segment. One Rule::SwapOut
      decision record per eviction storm.

      Off on robot, industrial, automotive, firmware, wearable and gateway:
      determinism, admission instead of overcommit, SD/eMMC wear. Without
      swap every table below is zero-sized and the fault path has no swap
      test.

    config MM_SWAP_BACKEND_OFF
        bool "off: no swap"

    config MM_SWAP_BACKEND_PARTITION
        bool "partition: a swap partition (server)"
        help
          The medium's swap partition (MBR type 0x82, or the GPT Linux swap
          type GUID). It is the kernel's alone: once claimed at boot, no
          capability names it. Its size is fixed; a smaller partition than
          MM_SWAP_SEGMENTS segments holds fewer. Cost: see MM_SWAP_SEGMENTS.

    config MM_SWAP_BACKEND_FILE
        bool "file: a swap file on FAT32 or azvol (desktop, iot-hmi)"
        help
          A file at MM_SWAP_FILE_PATH, on a FAT32 volume (below 4 GiB, never
          sparse) or an azvol one, for a machine that has no partition to
          spare. The file starts empty at every boot and grows by
          MM_SWAP_FILE_GROW_SEGMENTS whole segments when a storm finds no free
          slot, up to MM_SWAP_SEGMENTS; the reclaim task gives the free tail
          back after MM_SWAP_FILE_SHRINK_POLLS passes without swap traffic.
          The VFS pins it (nothing opens, truncates, renames or removes it) and
          the swap layer writes its blocks directly, cut along the sector runs
          the filesystem reports (MM_SWAP_FILE_RUNS), so a segment never goes
          through the filesystem; a file the filesystem scatters over more runs
          than that is not grown. The contents are ciphertext under a key that
          lives in RAM, so reading the file or the medium gives nothing, and
          swap does not survive a reboot.

          Cost: MM_SWAP_FILE_RUNS x 16 B of .bss, one growth step of zeros
          written through the filesystem, and the flash wear of those writes
          and of the segments themselves (the reason a small card keeps swap
          off).
endchoice

config MM_SWAP_BACKEND
    def_bool !MM_SWAP_BACKEND_OFF && MM_RECLAIM_COMPRESS
    help
      Swap exists (either backend). The tables below are sized only then.

config MM_SWAP_ENCRYPT
    def_bool MM_SWAP_BACKEND
    help
      Not a knob. A segment leaves the kernel's RAM only as AES-128-CTR
      ciphertext under a fresh nonce and key made at boot, with an
      HMAC-SHA256 tag over (slot, nonce, ciphertext) that stays in RAM, so a
      block that was changed, swapped between slots or replayed from an
      earlier write is refused when it is read back. The key never leaves
      RAM: swap does not survive a reboot, by design.

config MM_SWAP_FULL_PCT
    int "Live share of a segment before it is written out (%)"
    range 50 100
    default 87
    help
      Read only with MM_SWAP_BACKEND. Only full segments are written: after
      the holes are slid out, the live blobs must fill at least this share of
      the segment. A sparser one is left for the compactor, which empties it
      into the others' tails for nothing instead of a write.

config MM_SWAP_FILE_PATH
    string "Swap file path (MM_SWAP_BACKEND_FILE)"
    default "/fat/SWAP.AZS"
    help
      Read only with MM_SWAP_BACKEND_FILE. The file, with its mount point
      ("/fat/SWAP.AZS": the FAT32 volume's root directory, an 8.3 name; an
      azvol volume's mount point from its topology row, any path below it).
      It is created, or emptied, at every boot: its old contents were
      ciphertext under a key that is gone.

      Cost: none.

config MM_SWAP_FILE_SHRINK_POLLS
    int "Idle reclaim passes before the swap file shrinks"
    range 1 100000
    default 100
    help
      Read only with MM_SWAP_BACKEND_FILE. The reclaim task looks at the swap
      file once per MM_RECLAIM_POLL_MS when memory is not low; after this many
      looks in a row with no segment written or read, the free tail of the
      file (in whole growth steps, never below the highest segment in use) is
      given back to the volume. 100 looks are 10 s at the default poll.

      Cost: none.

config PMM_TYPE_ZONES
    bool "Type-isolated physical frames (page tables and io_ring pages)"
    default y if !SECURITY_GENERAL
    help
      Phase 5 item 5, the kalloc_type lesson (Apple XNU). A frame that held a
      page table or an io_ring page is never handed out as anything else
      after it is freed: it goes on a free list of its own zone
      (crates/core/mm/src/zone.rs) instead of the per-hart cache and the
      buddy lists, and only a zoned allocation of the same zone takes it
      back. A use-after-free of a freed page-table frame then cannot see
      that frame as a ring-3 data page, whose bytes the attacker controls.

      Zones: page-table pages (every level, `vmm::alloc_table`,
      `create_pagetable`, the megapage splits, the kernel-half copy) and
      io_ring pages (`io_ring::create_core`). The security-sensitive
      objects the plan names (task, capability table, endpoint, MemObj
      header) are fixed static tables, type-isolated by construction, so
      there is no kernel-heap zone: no object of those types is ever in
      the heap. Only order-0 frames are zoned; contiguous runs are not.

      On by default for every SECURITY posture but general. A kernel built
      with the `ktest` cargo feature runs the zones whatever this says (as
      LOCKDEP_KTEST does for lockdep): `mm_zone_no_cross_type_reuse` needs
      them. Off, the zoned allocation is `pmm::alloc_page` and a free costs
      what it did.

      Cost: no growth in RAM per frame (the tag is the sixth word of the
      32-byte descriptor, which was padded to 32), 80 B of .data for the two
      lists and their locks (riscv64, measured), one load and compare in
      `pmm::free` (nothing with this off). A zoned allocation takes its
      zone's lock on a hit and on a miss: there is no per-hart cache for
      zones, so page-table allocation under a fork storm serializes on one
      lock (a general allocation is untouched). Memory: a zone keeps its
      high-water mark. Frames freed to a zone are counted by
      `pmm::free_pages()` (they are not leaked, as with a frame in another
      hart's cache) but a general allocation cannot take them; read how many
      with `pmm::zone_pages()`.
