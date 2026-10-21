# Memory management

This page describes how the kernel manages physical memory, how that memory is
named and shared as objects, how it is mapped into address spaces, how it is
charged to Domains, and how it is taken back under pressure. Storage-side use
of the same machinery (the file page cache) is covered again from the
filesystem side in [storage.md](storage.md).

Most of the code lives in the `azos_mm` crate (`crates/core/mm`). The object
table lives in `azos_ipc` (`crates/core/ipc/src/memobj.rs`) because it is also
a capability type. Page-table words are built by the per-ISA crates behind the
`Mmu` trait (`crates/core/arch-api/src/lib.rs`).

Contents:

1. [Physical allocator and frame descriptors](#physical-allocator-and-frame-descriptors)
2. [MemObj kinds](#memobj-kinds)
3. [Object rmap](#object-rmap)
4. [Page cache as a Paged MemObj](#page-cache-as-a-paged-memobj)
5. [File-backed mmap](#file-backed-mmap)
6. [2 MiB reservations and contiguous leaves](#2-mib-reservations-and-contiguous-leaves)
7. [Kernel memory charged to the Domain](#kernel-memory-charged-to-the-domain)
8. [Reclaim order](#reclaim-order)
9. [Marker PTEs](#marker-ptes)
10. [TLB invalidation per ISA](#tlb-invalidation-per-isa)

## Physical allocator and frame descriptors

Every frame of RAM that firmware reported has one 32-byte descriptor,
`FrameDesc`, indexed by frame number (`Pfn`, absolute from physical address 0).
`pmm::init` places the descriptor array in RAM just above the kernel image and
marks it reserved. Colour and memory node are not stored: colour is
`pfn & (colours - 1)` and the node is a function of the address.

| `FrameDesc` field | Meaning |
|-------------------|---------|
| `refcount` | Copy-on-write share count. `0` means untracked (a single holder). An atomic updated only by compare-and-swap. |
| `flags` | The state bits below. |
| `order` | On the head frame of a free block, the block's order; `NOT_HEAD` otherwise. |
| `next`, `prev` | Free-list (and per-hart cache) links, as table indexes. |
| `zone` | The type zone the frame belongs to (`0` = none). |
| `owner`, `owner_idx` | Reverse map: the object that holds the frame and the frame's page index in it. Opaque to `frame.rs`. |

| State bit | Meaning |
|-----------|---------|
| `F_FREE` | In the buddy lists, owned by nobody. |
| `F_ALLOCATED` | Handed out by the allocator. |
| `F_RESERVED` | Never allocatable: kernel image, the descriptor array, memory-map holes. `free` accepts a reserved frame that was taken with `reserve_range` and is being given back. |
| `F_PINNED` | Modifier: not to be freed or moved while set. `free` refuses a pinned frame. |
| `F_COMPRESSED`, `F_SWAPPED` | Modifiers: the contents are held compressed, or have been written to swap. |
| `F_CACHED` | Free, but held in a hart's page cache: counted free, not in a buddy list. |

Allocation is a buddy allocator (`buddy.rs`). A free block of order `k` is
`2^k` frames starting at a frame number divisible by `2^k`; only its first
frame is linked into a list, but every frame of it has `F_FREE`. Orders run
`0..=PMM_MAX_ORDER` (Kconfig, `config/Kconfig.limits`). Because frame numbers
are absolute, a buddy block of the right order is also aligned in physical
address space, which is what a 2 MiB leaf needs.

The API in `pmm.rs` has three groups of calls:

| Layer | Functions |
|-------|-----------|
| Blocks by frame number, contents unspecified | `pmm::alloc(order, colour_mask, node)`, `pmm::free(pfn, order)`. `colour_mask` and `node` are accepted and ignored. |
| Physical addresses, zeroed | `alloc_page`, `alloc_contiguous`, `alloc_contiguous_aligned`, `free_page`, `reserve_range`, `reserve_dma_pool`. |
| Caller promises to overwrite | `alloc_page_uninit`, `alloc_contiguous_aligned_uninit` (both `unsafe`), `zero_frame`. |

`free` may give a block back one frame at a time; the frames merge as they
arrive. A run from `alloc_contiguous` is a buddy block of the order that holds
the request, with the tail pages returned straight away, so it is aligned to a
power of two and at most `2^PMM_MAX_ORDER` pages.

**Per-hart caches.** Once `pmm::enable_cpu_caches` has run (late boot), a
single-frame allocation or free touches only the calling hart's cache, with
interrupts masked. A hart takes `PMM_PCP_BATCH` frames
from the buddy lists when its cache is empty and returns that many when it
holds `PMM_PCP_HIGH`; that is the only time the buddy lock is taken. Free
counts include cached frames, so an exhausted allocator can refuse while up to
`NR_CPUS * PMM_PCP_HIGH` frames are counted free in other harts' caches.

**Type zones** (Kconfig `PMM_TYPE_ZONES`, `zone.rs`). A frame allocated for a
zone is tagged in `FrameDesc::zone` and never leaves its type: `pmm::free` of a
tagged frame puts it on that zone's own free list instead of the cache or the
buddy lists, and only a zoned allocation of the same zone takes it back.

| `Zone` | Holds |
|--------|-------|
| `Zone::PageTable` | Page-table pages of every level. |
| `Zone::Ring` | io_ring pages. |

Only order-0 frames are zoned. `PMM_ZONE_MAX_PAGES` bounds each zone.
`alloc_page_zone` is the zoned allocator; with the option off it is
`alloc_page`.

Source: `crates/core/mm/src/frame.rs`, `crates/core/mm/src/buddy.rs`,
`crates/core/mm/src/pmm.rs`, `crates/core/mm/src/zone.rs`,
`config/Kconfig.limits`.

## MemObj kinds

A MemObj is the kernel object for memory that is named, charged, transferred or
shared. It is named by a `Cap<Shm>`. The object table is a fixed array of
`MAX_MEMOBJS` slots, each with up to `MAX_MEMOBJ_PAGES` (64) pages and a
holder table of at most `MAX_MEMOBJ_HOLDERS` (8) tasks.

| `MemKind` | Frames | Charged to a Domain | Frames freed with the object | Created by |
|-----------|--------|---------------------|------------------------------|------------|
| `Anon` (0) | One frame per page, zeroed at create. | Yes | Yes | `memobj_create_spec` (ring 3 creates this kind and `Contig`) |
| `Contig` (2) | One physically contiguous, zeroed run. | Yes | Yes | `memobj_create_spec` (ring 3 asks for it with `SHM_KIND_CONTIG`: a stream's or a surface's memory a device reads or writes; no swappable, volatile or clone) and `memobj_create_kernel` |
| `Paged` (3) | File pages, filled on demand, droppable. | No (kernel-owned) | Yes, once clean or flushed | `memobj_create_paged` (kernel only) |

Attributes in `MemSpec::attrs`:

| Attribute | Meaning |
|-----------|---------|
| `ATTR_SWAPPABLE` | The object's opt-in for a reclaimer of MemObj frames. None exists yet (a frame taken out of an shm window has no fault path to restore it), so only a guest's memory check reads it. |
| `ATTR_NO_KERNEL_MAP` | The kernel never reads the object through the direct map; `memobj_with_word_ref` refuses it, and a reclaimer of MemObj frames would have to leave it alone. |
| `ATTR_VOLATILE` | Purgeable (Anon only). The owner marks the object droppable with `MemCtl::set_volatile` (kernel-hosted endpoint `memctl`, `WRITE`) and in use again with `set_nonvolatile`, which answers whether the object was purged. While volatile, the first stage of the reclaim pass (`memobj_purge_volatile`) may take its frames whole: every holder's mapping is unmapped, the frames and the charge go back, nothing is written, one `Rule::Purge` record is made. Purged is final: `SYS_MO_MAP` and a clone answer `-EPURGED`, and the holder creates a new object. Stage 0 runs only with `MM_RECLAIM_COMPRESS`: on a `MM_RECLAIM_OFF` image a volatile object is never purged (`set_nonvolatile` always answers `false`). `infsrv` (the inference service) keeps its blob arena in one: droppable between calls, held during a call, rebuilt from the signed bundles when it finds the object purged. Never purged: an object in use, one the kernel holds a reference to (a guest's RAM), one a clone shares frames with, one with a pinned holder, one charged to a `mem = "locked"` Domain. |

An anonymous mapping used by one task does not need a table slot at all:
`anon_map_private` is that case, on the marker-PTE path described below (no
frame until the first touch, no object lock on the fault).

Operations on an object, all in `memobj.rs`:

| Operation | Functions |
|-----------|-----------|
| Map/unmap | The mapping a task made is recorded on its holder record (`MemHolder::map_va`, `map_root`, `map_pages`, `map_write`). `memobj_resolve_map` bounds a map by the capability's rights; `memobj_protect_ref` changes access within what the map was allowed. |
| Revoke | A share is taken back with the warrant it derived from: the sweep of `SYS_CAP_REVOKE` hands each swept `Cap<Shm>` to `memobj_warrant_swept` (the `SweptHook` of `cap_store.rs`, registered at boot), which unmaps the Domain's holders on every hart and gives back their references. The sweep first drops the objects the Domain still names by another `Cap<Shm>` slot (`SweptSet::retain_unheld`, asked under the table's lock), and other Domains' holders are untouched. There is no resize operation: an object's page count is fixed at creation, and reclaim takes frames only from a volatile object (`ATTR_VOLATILE`). |
| Clone | `memobj_clone`: frames are shared through `FrameDesc::refcount` until a write mapping or `memobj_cow_break` gives the clone its own. |
| Move | `memobj_move` hands a task's references, its charge (when it holds the owning reference) and its ownership to another task. |
| Share | The IPC transfer's duplicate entry derives an attenuated capability; the receiver's map is bounded by the rights it received. |

Source: `crates/core/ipc/src/memobj.rs`.

## Object rmap

A revoke, a page drop, or a future reclaimer needs every mapping of a frame without
scanning page tables. Two pieces make that possible:

* **Frame to object.** `FrameDesc::owner` and `owner_idx` name the holder
  object (its packed `(index, generation)` reference, which goes stale on its
  own when the slot is reused) and the frame's page index in it.
  `pmm::set_frame_owner`, `pmm::frame_owner` and `pmm::clear_frame_owner_if`
  are the accessors. The writer holds the object's lock; the field is cleared
  before the frame goes back to the allocator, so a free frame never names an
  object.
* **Object to mappings.** The object's holder table doubles as its mapping
  list: each `MemHolder` records at most one mapping (page-table root, virtual
  address, page count, writable or not). `MAX_MEMOBJ_HOLDERS` bounds the list.

`memobj_warrant_swept` and `memobj_paged_drop_clean` are the readers of the
second piece: they walk the object's holder list, and remove the one PTE (a
page drop) or the whole recorded mapping (a revoke) each mapping has. The
mapping records of a page drop stay; a later touch of the hole is the pager's
to resolve. A revoke clears the record and leaves the window to its task to
give back. A `pinned` holder (a failed map may have left a PTE no record
names) keeps its pinned reference through a revoke and refuses a page drop.

The frame-to-object half has no reader yet: it is the entry a later reclaimer
of shared frames (an accessed-bit scan) would use to find a frame's mappings
from the frame.

The same `refcount` field is the copy-on-write share count used by
`cow::fork_cow`, `page_addref` and `page_decref` (`crates/core/mm/src/cow.rs`,
`crates/core/mm/src/cow_table.rs`): a first `addref` takes an untracked page to
2, a `decref` from 1 or 0 means "free it", and counts saturate rather than wrap
(a saturated page leaks and is never freed).

Source: `crates/core/mm/src/frame.rs`, `crates/core/mm/src/pmm.rs`,
`crates/core/mm/src/cow.rs`, `crates/core/mm/src/cow_table.rs`,
`crates/core/ipc/src/memobj.rs`.

## Page cache as a Paged MemObj

A `MemKind::Paged` object is a window of up to 64 pages of one file, and it
**is** that file's page cache: a cached page is one of its frames
(`phys_pages[i] != 0`), the same frame a mapper maps and the kernel reads and
writes. There is no second cache to keep coherent.

* **Creation.** `memobj_create_paged(backing, key, first_page, pages,
  file_size, perms)`. Kernel-owned, charged to no Domain, no frame yet. Pages
  are filled on first use, outside every lock, through a `PageBacking`
  (`crates/core/mm/src/page_backing.rs`): `read_page`/`write_page` over a
  `PageKey`. `azos_fs::FsPageBacking` implements it over a filesystem's
  positional `read_at`/`write_at` (`crates/fs/fs/src/pagecache.rs`).
* **Reading and writing from the kernel.** `memobj_paged_frame_ref`,
  `memobj_paged_read_ref`, `memobj_paged_write_ref`.
* **Dirty state.** A page is dirty after a kernel write, after a `write`
  request of `memobj_paged_frame_ref`, and for as long as a writable mapping
  reaches it (no PTE dirty bit is read, so a writable mapping is taken to be
  writing). `PagedInfo` exposes `resident`, `dirty` and `flushing` bitmaps.
* **Write-back.** `memobj_paged_writeback_ref` clears the dirty bit before the
  write, so a store that lands during it keeps the page dirty; a failed write
  makes the page dirty again. A page being written back is pinned by its
  `flushing` bit, which every path that frees or rewrites a frame honours.
* **Dropping.** `memobj_paged_drop_clean(max_pages)` unmaps a clean page from
  every address space through the object's mapping list, frees the frame, and
  leaves the next use to read it again. A dirty page, a page being written
  back, and any page of an object with a pinned holder are never dropped.
* **Pressure entry.** `memobj_paged_reclaim(max_pages)` writes back every Paged
  object's dirty pages and then drops up to `max_pages` clean ones, so a page
  that was dirty a moment ago can go in the same pass.
* **Length.** An object never changes the file's length: reads and write-backs
  clamp to the size it was attached at. `memobj_paged_set_size_ref` re-attaches
  it; `memobj_paged_forget_ref` forgets pages at or after an offset.
* **End of life.** `memobj_paged_close_ref` is the one way a dirty object ends:
  flush, then the kernel's reference goes and the frames with it.

A Paged object is never compressed or swapped: the compressed pool takes only
Anon objects, because the file already holds a copy. The kernel installs the
file layer's use of this cache at boot (`kernel/src/boot/pagecache.rs`); see
[storage.md](storage.md#the-page-cache-path) for that side.

Source: `crates/core/ipc/src/memobj.rs`,
`crates/core/mm/src/page_backing.rs`, `crates/fs/fs/src/pagecache.rs`,
`kernel/src/boot/pagecache.rs`.

## File-backed mmap

`mmap` of a file does not commit frames. It records a `Region` of
`PagerKind::File` in the address space's `RegionSet`
(`crates/core/mm/src/region.rs`), and the first touch of each page faults into
the pager (`crates/core/mm/src/pager.rs`), which supplies the page and installs
it with the region's exact permissions.

* **One object per window.** A file is cached in aligned 64-page windows, one
  Paged MemObj each, and a mapping is cut into one piece (one `Region`) per
  window it touches, at most `MAX_PIECES` (8) per call. The registry in
  `crates/core/syscall/src/file_map.rs` names the object of each (file,
  window); the file is identified by the filesystem's own key under that
  filesystem's backing, so every mapper of the same file reaches the same
  object and the same frames.
* **`MAP_SHARED`** maps the cache's own frame into the task's shm/MMIO window:
  every mapper sees every store. The task records the mapping in the object
  (`memobj_note_mapping_ref`), so the cache can drop a page out of this address
  space, and a writable mapping makes the page dirty. Pages go back to the file
  at `munmap`, at the file's sync, at task exit (`exit_writeback`), or at the
  flusher's pass.
* **`MAP_PRIVATE`** is a region of the task's own, placed and charged like an
  anonymous mapping. Each page is a copy of the cache page taken at the first
  touch, so stores never reach the cache or the file.
* **Pager seam.** The page cache lives above `azos_mm`, so the pager reaches it
  through the `FileFrames` trait (`frame`, `resident`, `read`, `addref`,
  `unref`), installed once with `pager::set_file_frames`. `addref`/`unref` are
  called as regions are made, copied by a fork and removed; a cache entry
  nobody uses stays until a call needs room and reaps it.
* **Entry point.** `file_map::sys_file_mmap(cap, len, off, prot, flags)`;
  `MAP_SHARED = 1` and `MAP_PRIVATE = 2`.

Regions are never executable (`PROT_EXEC` is refused before a region is made)
and a `PROT_NONE` range is not a region. A cut of a file region may only take
whole regions, because the cache counts regions.

An anonymous region is supplied by `AnonPager`: a slot whose marker names a
compressed copy is restored from the pool, any other page is zero-filled. A
pager that cannot answer at once could return `Supply::Pending`; no in-kernel
pager does, and a `Pending` answer is treated as unresolved.

Source: `crates/core/syscall/src/file_map.rs`,
`crates/core/mm/src/pager.rs`, `crates/core/mm/src/region.rs`,
`crates/core/mm/src/demand.rs`.

## 2 MiB reservations and contiguous leaves

Two mechanisms reduce TLB reach cost for anonymous and shared memory; a third
maps boot-reserved regions with 2 MiB leaves directly.

### Reservations (Kconfig `MM_THP_RESV`)

Requires `MM_DEMAND_PAGING` and a 4 KiB base page. The first fault in a
block-aligned part (`resv::BLOCK_SIZE` = one level-0 table's span, 2 MiB at
4 KiB pages) of an anonymous region that one region record covers whole, with
nothing mapped in it yet, takes a physically contiguous, aligned run
(`alloc_contiguous_aligned_uninit`). That fault and the following ones fill 4
KiB pages from the run, each zeroed when handed out. The fault that fills the
last page replaces the level-0 table with one level-1 leaf
(`vmm::promote_user_block`). A cut of the region (`munmap`, `mprotect`), a fork,
task exit, or an allocator that ran dry breaks the reservation, and frames not
yet handed out go back. A promoted leaf is split back to 4 KiB leaves
(`vmm::split_user_mega`) before part of it is unmapped or re-protected.

`resv.rs` is the bookkeeping only. Each frame of a run is owned by exactly one
of: the reservation (never handed out), a faulting thread (handed out, not yet
installed), or the page table (installed, and from then on an ordinary frame).
Promotion happens only if the table holds exactly the run: every entry a valid
user leaf onto frame `i`, same permissions, not executable, not copy-on-write.

### The break-before-make gate

Changing a table entry into a block (or back) at one level needs
break-before-make on some CPUs. `Mmu::block_change_needs_bbm` is the gate:

| ISA | Answer |
|-----|--------|
| aarch64 | `true` unless every CPU reports `ID_AA64MMFR2_EL1.BBM >= 2` (FEAT_BBM level 2). Each CPU notes its level as it comes up (`features::BbmSurvey`) and the weakest CPU's answer counts. |
| riscv64 | `false`. |
| x86_64 | `false`. |

`vmm::l1_replace` implements the change. Without the gate, one compare-and-swap
of the level-1 word, and the caller shoots the range down afterwards. With it,
with interrupts off on the one CPU doing the change:

1. **Break:** compare-and-swap the slot from the old word to
   `azos_arch_api::PTE_BBM_PARK` (bit 62: invalid on every ISA, not the empty
   word, not a demand marker).
2. **Shoot down** the block's range (`Mmu::tlb_shootdown`).
3. **Make:** store the new word and publish it.

A software page-table walk that meets `PTE_BBM_PARK` waits for the make
(`vmm::l1_load`) instead of reading the slot as empty. A hardware fault on a
parked word waits in `wait_out_parked_fault` and the access retries.

### Contiguous runs of level-0 leaves

A run is `Mmu::contig_run_pages()` adjacent 4 KiB leaves that the hardware may
cache as one TLB entry; the first is aligned in both virtual and physical
address to the run size, the frames are consecutive, and every word carries one
set of attributes (`arch-api/src/contig.rs`: `is_run`, `step_pages`).

| ISA | Mechanism | Run size |
|-----|-----------|----------|
| aarch64 | Contiguous hint, descriptor bit 52 (Kconfig `A64_CONTIG_HINT`). Each member names its own frame. | 16 pages at a 4 KiB granule (64 KiB); 128 at 16 KiB; 32 at 64 KiB |
| riscv64 | Svnapot, every member the same NAPOT word (Kconfig `RV_SVNAPOT`, probed). | 16 pages (64 KiB) |
| x86_64 | None below the 2 MiB leaf; `contig_run_pages()` is 0. | n/a |

`vmm::map_contig_range` is the writer: it maps consecutive pages of a user
table and writes a run wherever `contig::is_run` holds, a plain leaf elsewhere.
A run is written whole or not at all. Because a run is one TLB unit, every
per-page mutator breaks it first: `vmm::break_contig_run` rewrites each member
as a plain leaf (`Mmu::pte_contig_member`), through the same
break-before-make gate when it is required, and is called from the unmap,
protect and teardown paths. Readers that turn a leaf into a physical address
use `Mmu::pte_leaf0_span`, because a NAPOT word names the whole run.

### Boot-reserved 2 MiB regions (Kconfig `LOCKED_HUGE_LEAVES`)

A topology row with `mem = "locked"` may declare `mem_huge_mib`. `huge::reserve`
takes that much physically contiguous, 2 MiB-aligned RAM from the allocator
once, at boot, keyed by the row; it is never given back, except that `huge::release_all` undoes every reservation when boot admission refuses the topology they were reserved for. `vmm::map_user_mega_range`
maps it with level-1 leaves; it refuses unaligned or empty ranges, a slot whose
table is borrowed from the kernel, and any slot already mapped, before writing
anything. Teardown skips these leaves.

Source: `crates/core/mm/src/resv.rs`, `crates/core/mm/src/huge.rs`,
`crates/core/mm/src/vmm.rs`, `crates/core/mm/src/pager.rs`,
`crates/core/arch-api/src/lib.rs`, `crates/core/arch-api/src/contig.rs`,
`crates/core/arch-aarch64/src/cpu/features.rs`,
`crates/core/arch-aarch64/src/mmu/mod.rs`,
`crates/core/arch-riscv64/src/ext/napot.rs`,
`config/Kconfig.limits`, `config/Kconfig.arch`.

## User stacks

A user stack is mapped whole at exec and never grown. The size is the image's
own: the loader reads the `p_memsz` of its `PT_GNU_STACK` header, rounds it up to
a page and maps that many pages below `USER_STACK_TOP`; an image that asks for
nothing (`p_memsz == 0`, every Linux image) gets Kconfig `USER_STACK_SIZE_KB`
(16 KiB). A request over `USER_STACK_MAX_KB` (256 KiB) refuses the exec or the
spawn (`[LOAD] REFUSED: the image asks for a N KiB stack`). The pages are
charged to the task's row like the image's, so a row that runs a larger stack
budgets for it (`MLSRV.ELF`: 88 pages). The cached image of a spawn keeps the
size with its entry and break.

Below the stack lies nothing mapped up to `USER_MMIO_LIMIT`, which is
`USER_STACK_TOP - USER_STACK_MAX_KB`: the window that shm and device mappings
are placed in stops there, so a stack that outgrows its request faults instead
of running into a mapping. The fault report says so (`stack: below the stack
this image asked for`). There is no demand growth on purpose: a `mem = "locked"`
row must take no fault at run time, and a stack sized from the program is
deterministic where a grown one is not.

How an image asks: riscv64 and aarch64 link scripts give the `PT_GNU_STACK`
header a `NOLOAD` section (`.azos_stack`, e.g. `userspace/services/toolbox/user.ld`);
x86_64 images, and the images linked with the linker's own layout, pass
`-z stack-size` (`.cargo/config.toml`, or a `build.rs` for `LOGD.ELF`). The
size is read off the program, not guessed: `tools/user_stacks.py` takes the
deepest static call chain of each image (`tools/stack_chain.py`), adds 25% for
what a static chain does not see (indirect calls), and the gate row
`ring-3 stacks` fails an image whose request is smaller. The header sits in the
program header table, inside the first `STREAM_HDR_BYTES` of a streamed image,
which an ELF note in the middle of the file would not.

Source: `crates/core/sched/src/process.rs`, `crates/core/sched/src/elf_bounds.rs`,
`tools/user_stacks.py`, `config/Kconfig.limits`.

## Kernel memory charged to the Domain

A Domain is the unit that owns a capability table, a memory charge and a
security boundary (`crates/core/sched/src/domain.rs`). Three ledgers hang off it.

| Ledger | Unit | What it counts | Limit |
|--------|------|----------------|-------|
| `PageBudget` | Frames | Resident frames charged by `brk`, `mmap`, page tables, shm and fork, whichever thread of the Domain runs the call. | Frame limit from the topology row (`mem_pages`; `domain::set_limit`). `0` = unlimited. |
| Compressed pool ledger | Bytes | Compressed blobs stored for the Domain's pages (`zpool.rs`), and bytes of its segments on swap. | `MM_ZPOOL_DOMAIN_KIB`, `MM_SWAP_DOMAIN_KIB` |
| `KmemBudget` | Bytes | What the kernel keeps *for* the Domain, by class. | `kmem_kib` of the row. `0` = none. |

Rules shared by `PageBudget` and `KmemBudget` (`crates/core/mm/src/budget.rs`):
charges are atomic compare-and-swap loops, all-or-nothing (a charge that would
pass the limit charges nothing), and discharges saturate at zero. A MemObj move
charges the receiving Domain first and then gives the sender's back. The frame
charge counts *resident* frames: a page the reclaimer compresses is discharged,
and the fault that restores it charges it again with
`PageBudget::charge_restore`, which cannot be refused (the access cannot be
undone).

Kernel-memory classes (`KmemClass`):

| Class | Charged | Charged to |
|-------|---------|------------|
| `CapTable` | The Domain's capability table, once, when the Domain first claims it. | The Domain |
| `EpQueue` | One endpoint's slot and call queue. | The Domain that creates (or first claims) the endpoint |
| `MemObjMeta` | One MemObj region's metadata (frame array, holder records). | The Domain that holds the object's charge |
| `PageTable` | A page-table frame grown by the Domain's own mappings after its address space was installed. Also counted in the frame budget: two ledgers, two limits. | The task whose own root the table is under |

`domain::kmem_charge` records a `Rule::KmemCharge` decision on refusal.
`kmem_charge_atomic` is for contexts that may hold a spinlock or have
interrupts off (the page-table hook of the mapping paths) and records the
refusal in the lock-free ring only. A key that names no live Domain (the
kernel's own objects) has nothing to bill: the charge succeeds and the matching
discharge is a no-op.

Anon and Contig MemObjs are charged to the Domain of the task holding the
owning reference (`MemObj::charge_key`); `charge_region` takes the frames and
the `MemObjMeta` bytes together and gives the frames back if the second charge
is refused. Paged objects are kernel-owned and charged to no Domain.

Source: `crates/core/mm/src/budget.rs`, `crates/core/sched/src/domain.rs`,
`crates/core/sched/src/scheduler/budget.rs`,
`crates/core/ipc/src/memobj.rs`, `crates/core/ipc/src/cap_store.rs`,
`kernel/src/boot/sched.rs`.

## Reclaim order

When memory is low a reclaim task runs four stages in a fixed order, cheapest
first (`zpool::reclaim_pass` over the `Stages` trait). It exists only with
Kconfig `MM_RECLAIM_COMPRESS`; stage 0 included, so with `MM_RECLAIM_OFF` volatile
objects stay resident.

| Stage | Action | Function |
|-------|--------|----------|
| 0. Volatile objects | Objects created with `ATTR_VOLATILE` and marked droppable by their owner (`MemCtl::set_volatile`) give their frames up whole: every mapping is unmapped, the frames and the charge go back, nothing is written. Enough to get from now to `MM_RECLAIM_LOW_PCT` percent in use; runs only when the system as a whole is above `MM_RECLAIM_HIGH_PCT`. A Domain on a `mem = "locked"` row keeps its objects. One `Rule::Purge` record per object (`what` 2); the page cache's clean drop writes the same record (`what` 1). | `memobj_purge_volatile` |
| 1. Page cache | Write back dirty Paged pages and drop clean ones, enough to get from now to `MM_RECLAIM_LOW_PCT` percent in use. Runs only when the system as a whole is above `MM_RECLAIM_HIGH_PCT`. | `memobj_paged_reclaim` |
| 2. Compression | Every Domain over its high watermark gets one storm: its resident anonymous pages leave their address spaces for the compressed pool, until its charge is back at the low watermark. | `zpool::run_storm` over `pager::AnonReclaim` |
| 3. Swap | When a storm ended because the pool had no room, one full pool segment is written to the swap area, and compression is asked again. | `pager::swap_segment` |

`reclaim_pass` runs stages 0 and 1, then rounds of stage 2; if a round ended with the
pool full it runs stage 3 and goes round again, and it stops when a round
stores nothing or memory is no longer low, after at most `max_rounds` rounds.

**When it runs.** `kernel/src/tasks/reclaim.rs` polls every `MM_RECLAIM_POLL_MS`.
A pass runs when frames in use reach `MM_RECLAIM_HIGH_PCT` percent, or a Domain
with a frame limit has crossed its own high watermark. The task is placed on
the lowest CPU outside `RCU_NOCBS_CPUS` and the topology's `isolcpus`, at
`MM_RECLAIM_PRIORITY`, and a pass is refused if the CPU it finds itself on is
in that set. A Domain on a `mem = "locked"` row is never reclaimed
(`PageBudget::storm_begin`), and real-time tasks' frames are committed at map
time and have no region to take a page from.

### Stage 2: the compressed pool

The page is compressed with WKdm (`crates/core/crypto/src/wkdm.rs`) and packed
into a *segment*, `MM_ZPOOL_SEGMENT_PAGES` of contiguous frames. A page is one
of three things in the pool: *same-filled* (one 64-bit word repeated; one index
entry, no bytes), a *blob*, or nothing: a page that does not compress below
`MM_ZPOOL_MAX_RATIO_PCT` is skipped and stays resident (`Packed::Skip`).

* Each blob has an 8-byte header, so a segment can be walked front to back.
  Freeing a blob leaves a hole; `Pool::compact` slides segments down over their
  holes and empties the sparsest segment into the others' tails. A store that
  finds no room tries to grow, then compacts, then grows again, then refuses
  (`Error::Full`).
* **Encryption.** Every blob is AES-128-CTR under a key made once per boot from
  the entropy pool and kept in RAM only. The nonce is a 64-bit counter drawn
  once per blob and moves with the blob under compaction. CTR is not
  authenticated; this protects confidentiality of frames that are reused or
  dumped, not integrity of the pool in kernel RAM.
* **Quota.** A store that would take a Domain past `MM_ZPOOL_DOMAIN_KIB` is
  refused (`Error::Quota`) and the page stays resident.
* **Fork.** `Pool::dup_obj` gives the child index entries that point at the
  parent's immutable blob (a reference count), charged to the same Domain.
* **Concurrency.** The pool is plain data behind one lock, taken for index
  operations and copies in and out of a segment. Compression, encryption and
  their inverses run outside the lock on the caller's buffers. Restoring leaves
  the entry in place until the restored frame is installed, so a thread that
  loses the install race leaves it for its retry.

A storm picks victims from the source it is given, unmaps each from its address
space with a shootdown, stores it, frees the frame, and gives the charge back.
`pager::AnonReclaim` offers resident anonymous region pages that are owned by
their space alone and are plain 4 KiB leaves, coldest generation first (see
*Page generations* below). It never offers file-region pages,
pages shared copy-on-write, pages of a promoted block or contiguous run, or
any page of a space with a fork walking it. A storm stops at the first refusal
that is not "this page does not compress", and is recorded as one
`Rule::Compress` decision however many pages it took. Shared frames take other paths: the page cache's
clean frames go through `memobj_paged_drop_clean`, and a shared Anon MemObj is not reclaimed (no fault
path restores a frame taken from an shm window).

#### Page generations (`crates/core/mm/src/aging.rs`)

Four generations per page, 2 bits each, fed by the page table's Accessed bit
(`Mmu::harvest_accessed`, 64 pages per call). Every `MM_AGING_INTERVAL_MS` a
Domain with a frame limit and a charge above its low watermark is aged
(`pager::age_space`, driven by `kernel/src/tasks/reclaim.rs`): a resident
anonymous page moves one generation older, or back to the youngest when its
Accessed bit was set; a page first seen starts at generation 2 if idle and 0 if
used. A storm takes generation 3 first (address order inside a generation), so
the page compressed is the one idle longest. A page the coder gave up on
(`Packed::Skip`) is flagged and not offered again until a pass sees it used, so
the coder runs on it once, not on every storm. A zero or same-filled page needs
no such flag: `Codec::pack` tests for one repeated word before it compresses
anything and stores an index entry. The table (`MM_AGING_CHUNKS` records of 64
pages, 48 B each) is shared by all Domains and bounds how much memory reclaim
can reach; the reclaim task logs once per Domain slot when a pass leaves chunks
out. Where the CPU does not set the Accessed bit itself (Svade without Svadu,
aarch64 without FEAT_HAFDBS) a cleared page costs one fault on its next use.

### Stage 3: segment swap (Kconfig `MM_SWAP_BACKEND`)

The unit written out is a full pool segment, never a single page. The
backend is a Kconfig choice: off, a partition (server), or a file (desktop,
iot-hmi). With a partition, the boot step (`kernel/src/boot/swap.rs`) claims
the swap partition for the kernel (`partition::claim_swap`; from then on no
capability names it), draws a boot secret from the entropy pool, and attaches
the area. If there is no swap partition, or the entropy pool is not yet seeded,
swap stays off for the boot. With a file, the same step runs after the mounts
and makes `MM_SWAP_FILE_PATH` the swap file (below).

A segment leaves in three steps, none holding the pool lock across I/O:
`Pool::swap_pick` chooses a full segment, slides its holes out and marks it leaving (appends, compaction and release skip a leaving segment);
`Pool::swap_stage` copies its bytes out; `Pool::swap_commit` frees the frames
once the copy is on the medium. The Domain's bytes move from the pool ledger to
the swap ledger at the commit. A segment holding a page of a Domain on a
`mem = "locked"` row is never picked.

Each staged segment is encrypted with AES-128-CTR and tagged with
`HMAC-SHA256(mac_key, slot || nonce || ciphertext)` cut to 16 bytes, under keys
made once per boot from the entropy pool and kept in RAM only (so swap does not survive a reboot). The
tag and the nonce stay in RAM in the slot's record, not on the medium; a block
that was changed, moved to another slot, or replaced by an earlier write of the
same slot fails its tag on read and nothing of it is attached
(`SwapError::Tamper`). The tag is checked in constant time before decryption.
`MM_SWAP_ENCRYPT` is not a knob: the build asserts that it is on whenever swap
is.

**The swap file** (`MM_SWAP_BACKEND_FILE`) is an area that changes size. The
VFS makes the file (FAT32, below 4 GiB, or azvol), empties it at every boot and
pins it: nothing opens, truncates, renames, replaces or removes it, nor
renames a directory above it (azvol copies a tree to rename it). The
filesystem reports the sector runs under it (`FileSystem::swap_runs`: a FAT32
cluster chain, an azvol extent list; azvol's copy on write never moves blocks
nobody writes through the engine) and the kernel's `SwapDev` cuts each request
along them, so a segment never goes through the filesystem. It starts at
`MM_SWAP_FILE_GROW_SEGMENTS` segments. When a storm finds no free slot,
`swap_grow` has the filesystem append that many segments of zeros
(`FileSystem::swap_resize`, durable on return, fewer when the volume lacks the
room) and only then raises the pool's slot count; a restore that meets the
ceiling never grows it (it may hold the filesystem's locks), so a storm that
fills the last slot grows the file once more before it ends. When memory is not low the reclaim
task calls `pager::swap_trim` once per poll; after `MM_SWAP_FILE_SHRINK_POLLS`
polls without a segment moving, the free tail (whole growth steps, never below
the highest slot in use or one step) is given back: the slot count goes down
first, then the file, and never while a segment is leaving or a discard is
still on a tail slot. A file the filesystem scatters over more than
`MM_SWAP_FILE_RUNS` runs is not grown. The blocks are written directly and
azvol's checksum table does not know them, which is why the file is emptied
at the next boot and why a scrub of a volume with a live swap file reports it.

The device is the block layer's queue (`SwapDev`, implemented over
`blkdev::{write,read}_quiet`). An eviction storm on a real-time hart is
refused before anything is touched. One `Rule::SwapOut` decision is written per
storm: `[segments, live bytes, bytes written]`, `Refuse` when nothing went out.

Source: `crates/core/mm/src/zpool.rs`, `crates/core/mm/src/swap.rs`,
`crates/core/mm/src/pager.rs`, `crates/core/mm/src/budget.rs`,
`crates/core/crypto/src/wkdm.rs`, `crates/core/ipc/src/memobj.rs`,
`kernel/src/tasks/reclaim.rs`, `kernel/src/boot/swap.rs`,
`config/Kconfig.limits`.

## Marker PTEs

A page-table word with the valid bit clear is ignored whole by the hardware
walker, so the kernel stores its own state in it. Two kinds exist, built by
the `Mmu` trait.

**Demand marker** (`pte_make_demand`, `pte_is_demand`, `pte_demand_perms`). The
page is reserved but has no frame. The final permissions are stored inline so
the fault handler can recover them. The first touch allocates a zeroed frame
and rewrites the word (`demand::map_demand`, `vmm::handle_demand_fault`).

**Page marker** (`pte_make_marker`, `pte_marker`). The reclaimer leaves one in
a user page's slot while the page is outside the address space. A fault decides
from the word it reads, never from a look at the pool: an empty slot is a zero
page, `InTransit` is waited for, and a compressed or swapped marker is
restored. A 32-bit payload is stored inline.

| `PageMarker` | Code | Meaning | Payload |
|--------------|------|---------|---------|
| `Compressed` | 1 | The page is in the compressed pool. | Generation of the pool entry, so a marker never restores an earlier or later store of the same page. |
| `Swapped` | 2 | As `Compressed`, and the entry's segment is on the swap area; a fault brings it back first. | Same |
| `InTransit` | 3 | The reclaimer is storing the page now: out of the table, not yet in the pool. A fault waits. | Unused |

Encoding per ISA (software bits of an invalid word; the marker flag, the DEMAND
bit and, on riscv64, the COW bit occupy distinct positions):

| ISA | Marker flag | Demand flag | Kind code (2 bits) | 32-bit payload |
|-----|-------------|-------------|--------------------|----------------|
| riscv64 | RSW bit 8 (the position COW uses on a valid leaf) | bit 9 | bits 11:10 | bits 63:32 |
| aarch64 | software bit 57 | software bit 58 | bits 56:55 | bits 47:16 |
| x86_64 | available bit 11 | bit 10 | bits 4:3 | bits 43:12, stored inverted, with bits 51:44 always set |

On riscv64 the kind bits sit clear of the R/W/X bits so `Pte::is_leaf`, which
does not look at the valid bit, still reports "not a leaf". On x86_64 the
payload is inverted and the high address bits are set so the address field of
a non-present entry never names real memory, because a speculative load through
the field of a non-present entry on some CPUs reads whatever line is cached at
that address. A marker is never read as a demand marker or as a COW leaf:
`pte_is_cow` is true only for a valid word.

Marker lifecycle rules (`pager.rs`): the pool entry stays until the restored
frame is installed, then is dropped by generation; whatever ends the address
range (`munmap`, `mprotect(PROT_NONE)`, the space's end) clears the markers and
drops the entries; a fork gives the child a marker and a pool entry sharing the
parent's blob for each page the parent has out, after waiting for stores in
flight.

Source: `crates/core/arch-api/src/lib.rs`,
`crates/core/arch-riscv64/src/mmu.rs`,
`crates/core/arch-aarch64/src/mmu/mod.rs`,
`crates/core/arch-x86_64/src/mmu.rs`, `crates/core/mm/src/demand.rs`,
`crates/core/mm/src/pager.rs`.

## TLB invalidation per ISA

The cross-ISA contract is in `Mmu` (`crates/core/arch-api/src/lib.rs`):

| Function | Contract |
|----------|----------|
| `flush_tlb_page(va)` | Invalidate the entry translating `va`. For changes where a stale entry elsewhere only faults and re-walks: demand materialize, permission widening, the kernel's own table at boot. |
| `tlb_shootdown(root, va, len)` | After the caller removed, downgraded or repointed user PTEs of the table at `root`, invalidate `[va, va + len)` (`TLB_ALL`: everything) on every hart that may hold a translation, this one included, and return only when none can use one. Frames the old PTEs named may be freed after it returns, not before. Returns the mask of remote harts interrupted. |
| `flush_tlb_all`, `flush_tlb_asid` | Whole-TLB and per-address-space-tag forms. |
| `root_holders(root)` | Harts that still translate through `root`; a page table may be freed only while this is 0. |
| `asid_bits` | ASID/PCID bits this hart implements (0: none). |

| | riscv64 | aarch64 | x86_64 |
|---|---------|---------|--------|
| `flush_tlb_page` | `sfence.vma va`, local | `TLBI VAAE1IS` (broadcast) | `invlpg` of the current PCID only |
| `tlb_shootdown` | SBI `remote_sfence_vma` (and the `_asid` form) to the harts running the space; a local `sfence.vma` first, scoped to the space's ASID when this hart runs it under that ASID | `TLBI ...IS` broadcast then `DSB ISH`; no IPI, return value 0 | IPI to the CPUs holding the root, each running `invlpg`; or, with INVLPGB, a hardware broadcast followed by `TLBSYNC`, no IPI |
| Who is signalled | Harts whose published `satp` (`AZOS_HART_SATP`) names the root | Everyone (hardware broadcast) | CPUs whose published CR3 (`AZOS_HART_CR3`) names the root |
| Ranged form | `sfence.w.inval; sinval.vma; sfence.inval.ir` for ranges of `SVINVAL_MIN_PAGES` or more when Svinval is present (Kconfig `RV_SVINVAL`, execution-probed) | `TLBI RVAE1IS`/`RVAAE1IS` (FEAT_TLBIRANGE, Kconfig `A64_TLBIRANGE`) for ranges of `A64_TLBIRANGE_MIN_PAGES` or more, at most five operations for any length | Above `TLB_FLUSH_CEILING_PAGES` pages, the whole PCID is dropped instead of one `invlpg` each |
| `flush_tlb_all` | `sfence.vma`, local | `TLBI VMALLE1IS` | `invpcid` type 2, else a CR4.PGE toggle; local |
| `flush_tlb_asid` | Falls back to a full local `sfence.vma` | `TLBI ASIDE1IS` | `invpcid` single-context, else a CR3 reload of the live PCID |
| `root_holders` | Exact, from the published `satp` of every hart | This PE's own `TTBR0_EL1` only | From the published CR3 of every CPU |

Each shootdown guarantees that when it returns, no CPU can use a translation
cached before the caller's PTE change. Where there is no broadcast
(riscv64, and x86_64 without INVLPGB) the guarantee rests on a
store-buffering argument fenced on both sides: the shooter stores the PTE,
fences, then loads each hart's published root; the switcher stores its root,
fences, writes the root register and walks. Either the shooter sees the
publication and signals the hart, or the switcher's first walk sees the new
PTE.

**Retained translations** (Kconfig `TLB_RETAIN`). A user address-space switch
installs the incoming root with its ASID or PCID and does not flush, so a task
coming back finds its translations cached. ASIDs carry a generation
(`crates/core/sched/src/asid.rs`); when the space runs out the generation
advances and each hart flushes once before running a new-generation ASID.
Shootdowns that cannot reach a hart that ran the space mark that hart stale
(`azos_arch_api::tlb_gen`), and its next switch flushes. `TLB_SPACE_MASK`
narrows the marking to the harts recorded for that space. `TLB_ASID_SCOPED`
lets a shootdown invalidate only the target space's ASID instead of every
space's. An MMU whose ASID width probes as 0 flushes on every switch whatever
`TLB_RETAIN` says.

Source: `crates/core/arch-api/src/lib.rs`,
`crates/core/arch-api/src/tlb_gen.rs`,
`crates/core/arch-riscv64/src/api_impl.rs`,
`crates/core/arch-riscv64/src/tlb.rs`,
`crates/core/arch-aarch64/src/api_impl.rs`,
`crates/core/arch-x86_64/src/lib.rs`,
`crates/core/arch-x86_64/src/tlb.rs`, `config/Kconfig.arch`.
