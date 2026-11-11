# Memory management

This page describes how the kernel manages physical memory, how that memory is
named and shared as objects, how it is mapped into address spaces, how it is
charged to Domains, and how it is taken back under pressure. Storage-side use
of the same machinery (the file page cache) is covered again from the
filesystem side in [storage.md](storage.md).

Most of the code lives in the `azos_mm` crate (`crates/core/mm`). The object
table lives in `azos_ipc` (`crates/core/mm/src/memobj.rs`) because it is also
a capability type. Page-table words are built by the per-ISA crates behind the
`Mmu` trait (`arch/api/src/lib.rs`).

Contents:

1. [Physical allocator and frame descriptors](#physical-allocator-and-frame-descriptors)
2. [MemObj kinds](#memobj-kinds)
3. [Object rmap](#object-rmap)
4. [Page cache as a Paged MemObj](#page-cache-as-a-paged-memobj)
5. [File-backed mmap](#file-backed-mmap)
6. [Anonymous objects and slots](#anonymous-objects-and-slots)
7. [2 MiB reservations and contiguous leaves](#2-mib-reservations-and-contiguous-leaves)
8. [User stacks](#user-stacks)
9. [Kept image frames](#kept-image-frames)
10. [Kernel heap](#kernel-heap)
11. [Kernel image permissions (W^X)](#kernel-image-permissions-wx)
12. [Kernel memory charged to the Domain](#kernel-memory-charged-to-the-domain)
13. [Reclaim order](#reclaim-order)
14. [Page markers](#page-markers)
15. [TLB invalidation per ISA](#tlb-invalidation-per-isa)

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
`0..=PMM_MAX_ORDER` (Kconfig, `config/limits/Kconfig.limits`). Because frame numbers
are absolute, a buddy block of the right order is also aligned in physical
address space, which is what a 2 MiB leaf needs.

With Kconfig `SLAB_HARDENED` (default y) a block leaves its free list only if
both neighbours link back to it and its descriptor still names the list's
order; a damaged list panics with the addresses. With `ALLOC_RANDOM` (default
y, n on certifiable and static-separation builds) a freed block may go to the
tail of its list instead of the head, by placement bits drawn from a seed the
entropy pool stirs in (`buddy::stir`); before the first seed every list is
plain LIFO.

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
`config/limits/Kconfig.limits`.

## MemObj kinds

A MemObj is the kernel object for memory that is named, charged, transferred or
shared. It is named by a `Cap<Shm>`. The object table is a fixed array of
`MAX_MEMOBJS` slots, each with up to `MAX_MEMOBJ_PAGES` (64) pages and a
holder table of at most `MAX_MEMOBJ_HOLDERS` (Kconfig, 8) tasks.

| `MemKind` | Frames | Charged to a Domain | Frames freed with the object | Created by |
|-----------|--------|---------------------|------------------------------|------------|
| `Anon` (0) | One frame per page, zeroed at create. | Yes | Yes | `memobj_create_spec` (ring 3 creates this kind and `Contig`) |
| `Contig` (2) | One physically contiguous, zeroed run. | Yes | Yes | `memobj_create_spec` (ring 3 asks for it with `SHM_KIND_CONTIG`: a stream's or a surface's memory a device reads or writes; no swappable, volatile or clone) and `memobj_create_kernel` |
| `Paged` (3) | File pages, filled on demand, droppable. | No (kernel-owned) | Yes, once clean or flushed | `memobj_create_paged` (kernel only) |

Attributes in `MemSpec::attrs`:

| Attribute | Meaning |
|-----------|---------|
| `ATTR_SWAPPABLE` | The object's opt-in for the Domain storm (*Swappable objects* below): its pages may be compressed, swapped and restored by the fault of any mapper. Anon only, never with `ATTR_VOLATILE`. The kernel does not address its frames (its word, span and frame calls answer as for `ATTR_NO_KERNEL_MAP`; a futex word of a mapped page still works; a kernel ring over it is refused, below), and a guest's RAM, a display and a sound buffer refuse it. |
| `ATTR_NO_KERNEL_MAP` | The kernel never reads the object through the direct map; `memobj_with_word_ref` refuses it, and a reclaimer of MemObj frames would have to leave it alone. |
| `ATTR_VOLATILE` | Purgeable (Anon only). The owner marks the object droppable with `MemCtl::set_volatile` (kernel-hosted endpoint `memctl`, `WRITE`) and in use again with `set_nonvolatile`, which answers whether the object was purged. While volatile, the first stage of the reclaim pass (`memobj_purge_volatile`) may take its frames whole: every holder's mapping is unmapped, the frames and the charge go back, nothing is written, one `Rule::Purge` record is made. Purged is final: `SYS_MO_MAP` and a clone answer `-EPURGED`, and the holder creates a new object. Stage 0 runs only with `MM_RECLAIM_COMPRESS`: on a `MM_RECLAIM_OFF` image a volatile object is never purged (`set_nonvolatile` always answers `false`). `infsrv` (the inference service) keeps its blob arena in one: droppable between calls, held during a call, rebuilt from the signed bundles when it finds the object purged. Never purged: an object in use, one the kernel holds a reference to (a guest's RAM), one a clone shares frames with, one with a pinned holder, one charged to a `mem = "locked"` Domain. |

An anonymous mapping used by one task does not need a table slot at all: a
private `mmap` is a mapping of an *unnamed* anonymous object of the address
space (see *Anonymous objects and slots* below): no capability, no table slot,
no frame until the first touch, and no lock on the fault but the address
space's own. That is Kconfig `MM_DEMAND_PAGING`
(default y; n on industrial and automotive): the reservation is charged to
the page budget when it is made, so a fault never refuses on quota. A mapping
with `MAP_POPULATE` or `MAP_LOCKED`, every mapping of a `mem = "locked"` row,
and with `MM_PRECOMMIT_RT` every mapping of a real-time-class task are
committed at map time; with the option off, every mapping is. A shared Anon
object has its frames at create, because every mapper needs the same frames.

Operations on an object, all in `memobj.rs`:

| Operation | Functions |
|-----------|-----------|
| Map/unmap | The mapping a task made is recorded on its holder record (`MemHolder::map_va`, `map_space`, `map_pages`, `map_write`). `memobj_resolve_map` bounds a map by the capability's rights; `memobj_protect_ref` changes access within what the map was allowed. |
| Revoke | A share is taken back with the warrant it derived from: the sweep of `SYS_CAP_REVOKE` hands each swept `Cap<Shm>` to `memobj_warrant_swept` (the `SweptHook` of `cap_store.rs`, registered at boot), which unmaps the Domain's holders on every hart and gives back their references. The sweep first drops the objects the Domain still names by another `Cap<Shm>` slot (`SweptSet::retain_unheld`, asked under the table's lock), and other Domains' holders are untouched. There is no resize operation: an object's page count is fixed at creation, and reclaim takes frames only from a volatile object (`ATTR_VOLATILE`). |
| Clone | `memobj_clone`: frames are shared through `FrameDesc::refcount` until a write mapping or `memobj_cow_break` gives the clone its own. |
| Move | `memobj_move` hands a task's references, its charge (when it holds the owning reference) and its ownership to another task. |
| Share | The IPC transfer's duplicate entry derives an attenuated capability; the receiver's map is bounded by the rights it received. |

### MemObj and budget limits (contract)

Limits on the objects themselves (`memobj.rs`, Kconfig in
`config/limits/Kconfig.limits`):

| Limit | Value | Refused as |
|-------|-------|------------|
| Objects in the machine | `MAX_MEMOBJS` (Kconfig, 4 to 256; 8 embedded, 32 SBC and desktop, 64 server) | `NoMem` at create and clone |
| Objects one task owns | `MAX_MEMOBJS_PER_TASK` = `MAX_MEMOBJS / 2`; the kernel owner has none. Counted at create, clone and on the receiving side of a MOVE | `NoMem`; a MOVE is not carried out (`transferred == false`) |
| Pages per object | `MAX_MEMOBJ_PAGES` = 64, fixed at creation (no resize) | `BadArg` |
| Holders per object | `MAX_MEMOBJ_HOLDERS` (Kconfig, 2 to 255, default 8): one row per task holding a reference, each with at most one mapping record | a clone, acquire or MOVE that needs a new row is refused |

Charge rules for the Domain that pays (`PageBudget`, and `KmemBudget` class
`MemObjMeta`; `charge_region`, `memobj_move`, the release path):

- **Create and clone** charge the frames to the owner's Domain (`charge_key`)
  and `size_of::<MemObj>()` bytes to the same Domain's `MemObjMeta` (`meta_key`),
  all or nothing: if the second charge is refused the first goes back and the
  call answers `NoMem`. A kernel owner (key 0) and a Paged object are charged
  nothing.
- **MOVE of the owning reference** charges the receiver's Domain the whole
  object first; a refusal, or a receiver with no Domain, leaves the object with
  the sender. Only then is the sender's charge given back and `charge_key`
  changed. `meta_key` does not move: the metadata stays charged to the creator's
  Domain for the object's life. An object with a page out (swapped or in
  flight) is not moved while its owner holds it (`Busy`): the Domain that
  stored a page restores it.
- **The last release** gives the frames back to `charge_key` and the metadata to
  `meta_key`, from whichever task drops the last reference; pages that are out
  were given back when they left and are not given back twice. A **purge** of a
  volatile object gives the frames back at once and clears `charge_key`; the
  metadata stays until the object goes.
- **A restore** of a compressed or swapped page charges the page again to
  `charge_key` with `charge_restore`, which is never refused and may take the
  count past the limit; the next plain charge is refused until the overshoot is
  given back.
- **Not charged:** the copy a copy-on-write break makes (it cannot be refused;
  admission counts the copies), a Paged object's pages, and anything of a kernel
  owner. Mappings (`mmap`, `brk`, a module-window placement, a fork child's
  inherited reservation) charge the whole request before anything is made and
  `munmap` gives back what the range held, reserved or touched; a shrink of the
  break is not supported, so its charge stays until the address space is
  discarded. A ring's buffer page is charged to its creator's Domain and given
  back to it on teardown.
- **Exec** forgets the old address space's charge and keeps the frames the
  Domain's objects hold: the MemObj frames (`memobj_charged_pages`, the pages a
  release would give back) and the io_ring pages stay in the count, because
  their references outlive the image and their release lands later
  (`domain::RETAINED_HOOK`, registered by `azos_ipc`). Resetting to zero would let a
  later release discharge from the new image's count.
- **Arithmetic:** every charge is a compare-and-swap loop that saturates, a
  refusal changes no counter, a discharge floors at zero, and a Domain's death
  returns the growth it took from the growth pool. The host rows are in
  `tests/host/mm-tests/src/budget_stress.rs` (the ledgers) and
  `tests/host/syscall-tests/src/budget_sites.rs` (charge sites against their
  discharges).

Source: `crates/core/mm/src/memobj.rs`.

## Object rmap

A revoke, a page drop, or a purge needs every mapping of an object's frame without
scanning page tables. The object's holder table doubles as its mapping list:
each `MemHolder` records at most one mapping (page-table root, virtual address,
page count, writable or not). `MAX_MEMOBJ_HOLDERS` bounds the list.

`memobj_warrant_swept`, `memobj_paged_drop_clean` and `memobj_purge_volatile`
are its readers: they walk the object's holder list, and remove the one PTE (a page drop) or the whole
recorded mapping (a revoke, a purge) each mapping has. The mapping records of a page
drop stay; a later touch of the hole is the pager's to resolve. A revoke clears
the record and leaves the window to its task to give back. A `pinned` holder (a
failed map may have left a PTE no record names) keeps its pinned reference
through a revoke and refuses a page drop.

There is no frame-to-object half: no reader needs to go from a frame to the
object that holds it (the anonymous reclaimer walks page tables, the page
cache's walks its objects).

The same `refcount` field is the copy-on-write share count used by
`pager::fork_clone`, `cow::fork_cow`, `page_addref` and `page_decref` (`crates/core/mm/src/cow.rs`,
`crates/core/mm/src/cow_table.rs`): a first `addref` takes an untracked page to
2, a `decref` from 1 or 0 means "free it", and counts saturate rather than wrap
(a saturated page leaks and is never freed).

Source: `crates/core/mm/src/frame.rs`, `crates/core/mm/src/pmm.rs`,
`crates/core/mm/src/cow.rs`, `crates/core/mm/src/cow_table.rs`,
`crates/core/mm/src/memobj.rs`.

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
  positional `read_at`/`write_at` (`crates/fs/src/pagecache.rs`).
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

Source: `crates/core/mm/src/memobj.rs`,
`crates/core/mm/src/page_backing.rs`, `crates/fs/src/pagecache.rs`,
`kernel/src/boot/pagecache.rs`.

## File-backed mmap

`mmap` of a file does not commit frames. It records a `Mapping` with
`Backing::File` in the address space's `MapSet`
(`crates/core/mm/src/mapping.rs`), and the first touch of each page faults into
the pager (`crates/core/mm/src/pager.rs`), which supplies the page and installs
it with the mapping's exact permissions.

* **One object per window.** A file is cached in aligned 64-page windows, one
  Paged MemObj each, and a mapping is cut into one piece (one `Region`) per
  window it touches, at most `MAX_PIECES` (8) per call (a `Region` of
  `file_map.rs`, one mapping record each). The registry in
  `crates/core/syscall/src/file_map.rs` names the object of each (file,
  window); the file is identified by the filesystem's own key under that
  filesystem's backing, so every mapper of the same file reaches the same
  object and the same frames.
* **`MAP_SHARED`** maps the cache's own frame, in a mapping placed in the mmap
  area: every mapper sees every store. The task books the mapping in
  the object (`memobj_note_mapping_at_ref`, which names the cache page the
  mapping starts at), so the cache can drop a page out of this address space,
  and a writable mapping makes the page dirty. The pager clears the mapping's
  leaves when it ends, so the sweep that frees a space's own frames never meets
  one of the cache's (`pager::unmap_shared`). Pages go back to the file
  at `munmap`, at the file's sync, at task exit (`exit_writeback`), or at the
  flusher's pass.
* **`MAP_PRIVATE`** is a region of the task's own, placed and charged like an
  anonymous mapping. Each page is a copy of the cache page taken at the first
  touch, so stores never reach the cache or the file.
* **Pager seam.** The page cache is `azos_mm::memobj`'s Paged objects, which the
  pager calls directly. A file object counts its users (`memobj_paged_users_*`),
  raised as regions are made or copied by a fork and dropped as they are removed;
  a cache entry nobody uses stays until a call needs room and reaps it.
* **Entry point.** `file_map::sys_file_mmap(cap, len, off, prot, flags)`;
  `MAP_SHARED = 1` and `MAP_PRIVATE = 2`.

Regions are never executable (`PROT_EXEC` is refused before a region is made)
and a `PROT_NONE` range is not a region. A cut of a file region may only take
whole regions, because the cache counts regions.

A pager that cannot answer at once could return `Supply::Pending`; no
in-kernel pager does, and a `Pending` answer is treated as unresolved.

Source: `crates/core/syscall/src/file_map.rs`,
`crates/core/mm/src/pager.rs`, `crates/core/mm/src/mapping.rs`.

## Physical ranges

A range of physical memory the allocator does not hand out is lent to a task as
a `Backing::Phys` mapping (`crates/core/mm/src/mapping.rs`): a device's
register window (`DOMAIN_MMIO_MAP`), a ring page (`SYS_RING_SETUP`), the
per-task vDSO page (`DOMAIN_VDSO_MAP`), the vDSO data page every space maps, a
locked row's region. It has no pages to supply, count or reclaim, so its object
is the record itself: `off` is the first frame number, the memory type (`WB`,
`WC`, `NC` or `Device`, in the leaf as PAT on x86_64, MAIR on aarch64 and
Svpbmt on riscv64) and whether a fork gives it to the child.

* **Placement and order.** `syscall::phys_map` places the range in the mmap area
  like a shared object, records it (`pager::reserve_phys`) and then maps its
  leaves (`vmm::map_phys`): a refusal after the record releases it, which takes
  the leaves done with it. Charged to nobody: the range is its owner's.
* **Never executable, never taken back by the task.** The record carries no
  execute bit and the exec flip (`vmm::set_user_range_exec`) refuses it; `munmap`
  and `mprotect` refuse it whole. Its owner ends it (`phys_map::unmap_user`, a
  ring's destroy) or the space does.
* **Torn down by its record.** `release_range` and the space's end clear its
  leaves (`vmm::unmap_user_range_keep`, level-1 leaves included) with the
  shootdown and free no frame; the sweep never meets one.
* **Fork.** The walk passes it; the child gets it only when the record says
  `inherit` (the vDSO data page), as a record and the same leaf with no
  reference counted. A device window, a ring page and the notify page are not
  inherited.

A ring keeps its address across an `exec` and its destroy releases a record
only when it is that ring's page; a pool slot's vDSO page leaves the group's
space when the thread that mapped it ends (`vdso_notify::release_task_page`),
before the slot is reissued. A forked child's runtime still holds the addresses
of the ranges it was not given; they lie above the cursor it copied, so nothing
it maps lands there.

The vDSO data page and a locked row's region are recorded by exec and spawn
(`process::map_vdso`, `install_locked_arena`) once the address space exists; the region's bytes are zeroed at the exec's commit, not at admission. The
riscv64 sigreturn trampoline stays a plain loader mapping: it is executable, which
a physical range never is.

Source: `crates/core/mm/src/mapping.rs`, `crates/core/mm/src/pager.rs`,
`crates/core/mm/src/vmm.rs`, `crates/core/syscall/src/phys_map.rs`,
`crates/core/sched/src/process.rs`.

## Anonymous objects and slots

A private anonymous `mmap` is a mapping of an anonymous object the address
space owns (`crates/core/mm/src/anon_obj.rs`). The object holds one 64-bit
**slot word** per page (`crates/core/mm/src/slot.rs`, the same encoding on every
ISA):

| Slot | Word | Meaning |
|------|------|---------|
| `Empty` | `0` | Never touched: a zero page. |
| `Frame(pa)` | `pa \| 1` | Resident in the frame at `pa`. |
| `Marker(kind, payload)` | `payload << 32 \| code << 1` | In transit, compressed or swapped (see *Page markers*). |

**The slot is the page's state; the leaf is a cache of it.** A fault reads the
slot, never the leaf (`slot::resolve`): `Empty` is supplied zero-filled (a leaf
over an empty slot is a stale cache word and is replaced), `Frame` whose leaf is
missing is installed again, `InTransit` is waited for, `Compressed`/`Swapped`
is restored. The install compares the slot and the leaf words it decided on and
writes both under the address space's lock, which is also the object's (the
object has one mapper). A leaf is written when a slot becomes `Frame` and
cleared when it stops being one; a copy-on-write break moves the leaf and the
slot together (`pager::cow_swap`). The leaf sweep of `munmap` and of the space's
end frees the frames, which a `Frame` slot and its leaf name alike.

**Pages are numbered by address**, as Linux numbers an anonymous VMA's: the page
an object maps at `va` is `va >> PAGE_SHIFT`. A new mapping next to one of the
object's (below or above it, same permission) is more pages of that object and
folds into its record, so a heap that grows up or down holds one record of
`MM_REGIONS_PER_SPACE`.

**The program break is such a heap** (`sys_brk`, the Linux personality's): a
growth reserves `[page_up(brk), page_up(addr))`, which folds into the mapping
below it, and is charged once for the whole growth before anything is made. A
growth that cannot be had in full (the budget, a range that is not vacant, no
memory) leaves the break where it was, as Linux's does. A task whose pages are
committed at map time (`mem = "locked"`, a real-time task with
`MM_PRECOMMIT_RT`, `MM_DEMAND_PAGING` off) gets the frames at once, as its
`mmap` does.

**Slot storage.** `MM_SLOTS_INLINE` (default 16) pages from the object's first
have their words inside the object. The others sit in 4 KiB chunks of 512 words:
the first four chunks from the object's first through pointers in the object,
the rest of a window of 512 chunks (1 GiB of address space, half below, half
above) through one directory page. Chunks and the directory are allocated on the
first touch of a page they hold, charged to the task within its limit, and a
`munmap` that leaves none of a chunk's pages mapped frees it. A touch past the
limit that needs a chunk is refused, the one exception to "a fault never
refuses on quota": a ring-3 touch kills the task with exit status 137
(`KILLED_KILL`, SIGKILL's, as an out-of-memory kill; not 139, a bad pointer's)
and writes a durable `SAFETY_MM_QUOTA_FAULT` record with the address, and a
kernel copy into the page answers `EFAULT`; a mapping that would leave the window gets an object of its own. The lookup is a
binary search over the space's mapping records and one or two loads into the
object.

**Fork** clones the objects (flat copy-on-write, no shadow chains):
`pager::fork_clone` gives each parent object one child object and copies its
slot words in one pass. A `Frame` slot takes one more reference on its frame
(`FrameDesc::refcount`), taken before either leaf names it as shared; the
parent's leaf is made read-only (copy-on-write in a writable mapping) by
compare-and-swap, the child's leaf is the same word, and one shootdown of the
parent follows. A `Compressed` or `Swapped` slot is its marker word over a
share of the pool's entry (`Pool::dup_obj`): nothing is restored. The child's
slot and leaf come from one read of the parent's slot, so a page a sibling
thread commits during the fork is either shared (read after the commit) or a
zero page of the child's own (read before). A store by either side then breaks
the share through the slot (`cow::handle_cow_fault`, `pager::cow_swap`): a copy
while another holder is left, the frame itself once the count is down to one.
The copy-on-write walk of `cow.rs` passes every leaf table an anonymous mapping
holds whole and every page one holds; it shares only the pages no anonymous
mapping holds (the image, the stack, the vDSO and trampoline, eager commits,
private file pages). The fork holds the parent (`pager::ForkHold`) from before
its walk until the clone is done: the reclaimer takes no page of it and its
faults restore none meanwhile, so no marker changes under the clone and none is
in transit. The child is charged its uncommitted reservation and the leaf tables
and slot chunks the clone built for it as one request, which may grow its limit
from the row's base: a parent that grew past its base can still fork. A clone
refused because the parent's records disagree (a resident page with no leaf)
is counted as `clone-invariant` and warned, not taken for memory pressure. A fork of a fully touched 64 MiB heap
copies no frame: it takes 69 pages (host suite), the child's root, its 32 leaf
tables and upper tables, and its 33 pages of slot words.

Source: `crates/core/mm/src/anon_obj.rs`, `crates/core/mm/src/slot.rs`,
`crates/core/mm/src/mapping.rs`, `crates/core/mm/src/pager.rs`.

## 2 MiB reservations and contiguous leaves

Two mechanisms reduce TLB reach cost for anonymous and shared memory; a third
maps boot-reserved regions with 2 MiB leaves directly.

### Reservations (Kconfig `MM_THP_RESV`)

Requires `MM_DEMAND_PAGING` and a 4 KiB base page; default y on desktop and
server, n otherwise. A task that commits at map time never reserves. The first fault in a
block-aligned part (`resv::BLOCK_SIZE` = one level-0 table's span, 2 MiB at
4 KiB pages) of an anonymous mapping that one mapping record covers whole, with
nothing mapped in it yet, takes a physically contiguous, aligned run
(`alloc_contiguous_aligned_uninit`). That fault and the following ones fill 4
KiB pages from the run, each zeroed when handed out. The fault that fills the
last page replaces the level-0 table with one level-1 leaf
(`vmm::promote_user_block`). A cut of the mapping (`munmap`, `mprotect`), a fork,
task exit, or an allocator that ran dry breaks the reservation, and frames not
yet handed out go back. A promoted leaf is split back to 4 KiB leaves
(`vmm::split_user_mega`) before part of it is unmapped or re-protected, and
every promoted leaf of a space before it is forked
(`vmm::demote_all_user_megas`).

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
   word).
2. **Shoot down** the block's range (`Mmu::tlb_shootdown`).
3. **Make:** store the new word and publish it.

A software page-table walk that meets `PTE_BBM_PARK` waits for the make
(`vmm::l1_load`) instead of reading the slot as empty. A hardware fault on a
parked word waits in `wait_out_parked_fault` and the access retries.

### Contiguous runs of level-0 leaves

A run is `Mmu::contig_run_pages()` adjacent 4 KiB leaves that the hardware may
cache as one TLB entry; the first is aligned in both virtual and physical
address to the run size, the frames are consecutive, and every word carries one
set of attributes (`arch/api/src/contig.rs`: `is_run`, `step_pages`).

| ISA | Mechanism | Run size |
|-----|-----------|----------|
| aarch64 | Contiguous hint, descriptor bit 52 (Kconfig `A64_CONTIG_HINT`). Each member names its own frame. | 16 pages at a 4 KiB granule (64 KiB); 128 at 16 KiB; 32 at 64 KiB |
| riscv64 | Svnapot, every member the same NAPOT word (Kconfig choice, default `RV_SVNAPOT_PROBE`: used when cpu@0's `riscv,isa` names it). | 16 pages (64 KiB) |
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

A topology row with `mem = "locked"` may declare `mem_huge_mib`.
`scheduler::row_arena_reserve` takes that much physically contiguous, 2 MiB-aligned RAM from the allocator
once, at boot, keyed by the row, and pins its frames (`F_PINNED`: the allocator refuses to free them); it is never given back, except that `scheduler::row_arena_release_all` undoes every reservation when boot admission refuses the topology they were reserved for. Exec records the region as a physical range of the new
address space and `vmm::map_user_mega_range`
maps it with level-1 leaves; it refuses unaligned or empty ranges, a slot whose
table is borrowed from the kernel, and any slot already mapped, before writing
anything. The record clears these leaves at the space's end.

Source: `crates/core/mm/src/resv.rs`, `crates/core/sched/src/scheduler/budget.rs`,
`crates/core/mm/src/vmm.rs`, `crates/core/mm/src/pager.rs`,
`arch/api/src/lib.rs`, `arch/api/src/contig.rs`,
`arch/aarch64/src/cpu/features.rs`,
`arch/aarch64/src/mmu/mod.rs`,
`arch/riscv/src/ext/napot.rs`,
`config/limits/Kconfig.limits`, `config/arch/Kconfig.isa`.

## User stacks

A user stack is mapped whole at exec and never grown. The size is the image's
own: the loader reads the `p_memsz` of its `PT_GNU_STACK` header, rounds it up to
a page and maps that many pages below `USER_STACK_TOP`; an image that asks for
nothing (`p_memsz == 0`, every Linux image) gets Kconfig `USER_STACK_SIZE_KB`
(16 KiB; 64 KiB with an aarch64 64 KiB granule). A request over
`USER_STACK_MAX_KB` (256 KiB) refuses the exec or the spawn
(`[LOAD] REFUSED: the image asks for a N KiB stack`). The pages are charged to
the task's row like the image's, so a row that runs a larger stack budgets for
it (`MLSRV.ELF`, whose image asks for 64 KiB: a small row's 64 pages plus 16,
`MLSRV_MEM_PAGES` in `crates/core/topology/src/builder.rs`). The cached image of a spawn keeps the
size with its entry and break.

Below the stack lies nothing mapped up to `USER_STACK_FLOOR`, which is
`USER_STACK_TOP - USER_STACK_MAX_KB`: the locked rows' regions end there, so a stack that outgrows its request faults instead
of running into a mapping. The fault report says so (`stack: below the stack
this image asked for`). There is no demand growth on purpose: a `mem = "locked"`
row must take no fault at run time, and a stack sized from the program is
deterministic where a grown one is not.

How an image asks: its crate's `build.rs` passes the linker `-z stack-size`
(e.g. `userspace/services/toolbox/build.rs`), which lld writes as the
`PT_GNU_STACK` header's `p_memsz`, on every ISA. The
size is read off the program, not guessed: `tools/lint/user_stacks.py` takes the
deepest static call chain of each image (`tools/lint/stack_chain.py`), adds 25% for
what a static chain does not see (indirect calls), and the gate rows
`ring-3 stacks` (riscv64 and aarch64 images) fail an image whose request is
smaller. The header sits in the
program header table, inside the first `STREAM_HDR_BYTES` of a streamed image,
which an ELF note in the middle of the file would not.

Source: `crates/core/sched/src/process.rs`, `crates/core/sched/src/elf_bounds.rs`,
`tools/lint/user_stacks.py`, `config/limits/Kconfig.limits`.

## Kept image frames

A spawn or exec by path hashes the whole image (SHA-256) to pick its profile
and topology row. The digest cache (`crates/core/syscall/src/image_cache.rs`,
16 entries, always on) remembers the digest of bytes it hashed, keyed by a
content stamp (the backend, its write epoch, the file's start cluster and
size). FAT32's epoch moves on every write of the volume, mount and unmount, so
an equal stamp means no byte changed; a backend without stamps (tmpfs)
is never cached.

With Kconfig `EXEC_IMAGE_CACHE_KB` nonzero (64 KiB embedded, 512 KiB edge,
4 MiB fleet; `0` = off) a spawn also keeps the image's frames under the same
stamp (`image_frames::capture`, run before the new task's first
instruction). An executable page, never writable, is kept by reference
(`cow_table`); every other page is copied into a kernel-owned template frame.
The next spawn of the same stamp (`image_frames::map_into`) maps the
executable frames again read-execute, with one more reference each, and gives
every other page a fresh frame filled from its template, so it neither reads
nor hashes the file. Nothing it maps is both shared and writable: nothing adds
WRITE to an executable leaf, and the copy-on-write fault refuses an
executable entry. Every page is present when the task starts, so a
`mem = "locked"` row stays committed. The least recently used images go
first; a frame a running task still maps outlives the eviction until that
task's teardown. One record frame holds `image_frames::MAX_PAGES` pages
(`PAGE_SIZE / 16`) per image.

Source: `crates/core/syscall/src/image_cache.rs`,
`crates/core/mm/src/image_frames.rs`, `config/limits/Kconfig.limits`.

## Kernel heap

The kernel's `GlobalAlloc` (`kheap.rs`) takes its pages from the page
allocator on demand and gives them back when freed. `KERNEL_HEAP_SIZE` KiB
(512 KiB embedded, 32 MiB edge, 256 MiB fleet) is a ceiling on the pages it
holds, not a region reserved at boot. The tables the Kconfig limits size are
static, not in the heap. Exhaustion, of the ceiling or of RAM, is a refusal
(a null pointer), never a panic.

A request that a size class covers (`KHEAP_SLAB_CLASSES`, default
`16 32 64 128 256 512 1024 2048`, up to `KHEAP_SLAB_MAX_CLASS`, alignment
permitting) goes to a magazine cache (`slab.rs`, after Bonwick's magazines
and Linux SLUB):

| Layer | What it is |
|-------|------------|
| Per-CPU magazines | Per CPU and class, a `loaded` and a `prev` stack of free objects (`KHEAP_SLAB_MAG_DEPTH`). Alloc pops, free pushes, with the CPU's interrupts masked and no lock. |
| Depot | Per class, under the class lock: full and empty magazines exchanged with a CPU (`KHEAP_SLAB_DEPOT_MAGS` full ones at most; past that a full magazine is flushed back to its slabs). |
| Slabs | Power-of-two blocks of the page allocator (`KHEAP_SLAB_BYTES`, at least a page), aligned to their size, with the header in the last bytes, so `ptr & !(slab_bytes - 1)` finds an object's slab. A slab whose last object comes back returns to the page allocator once its class keeps `KHEAP_SLAB_KEEP_EMPTY` empty ones. |

Larger requests are an exact run of pages (the tail past the last page goes
straight back), up to the largest block the page allocator forms
(`PMM_MAX_ORDER`). A refused request first has the cache give back what it
holds, then is retried once. A slab is taken with the caller's interrupt state
restored, so this layer never calls the page allocator masked, and the page
allocator masks interrupts itself, so an interrupt handler may allocate.

Hardening: with `SLAB_HARDENED` (default y) a free object's link is stored as
`next ^ key ^ byteswap(address)` with a key per slab page, a pop checks the
decoded link names an object of the same slab, a free checks the pointer is
an object and not the one freed last, and the slab list unlinks only a slab
whose neighbours link back to it; a failure panics with the addresses. With
`ALLOC_RANDOM` a new slab hands out its objects from a random start in a
random step coprime with the object count. The key and the draw come from the
entropy pool, or from the timer tick mixed with the page address before the
pool is seeded or when interrupts are masked. `KHEAP_SLAB_DEBUG` poisons freed
objects (`0x6b`) and red-zones the class slack (`0xbb`), and panics on a
write after free or an overrun.

Source: `crates/core/mm/src/kheap.rs`, `crates/core/mm/src/slab.rs`,
`config/limits/Kconfig.limits`, `config/subsys/Kconfig.topology`.

## Kernel image permissions (W^X)

At boot, after paging is on, the megapages covering the kernel image are split
into 4 KiB leaves (`vmm::split_mega_range`) and each section is remapped:
`.text` read-execute, `.rodata` read-only, `.data`/`.bss` read-write and never
executable (`vmm::enforce_wx`). A page that `.text` shares with `.rodata`
stays read-execute, and `.rodata` and `.data` start after the previous
section's last page. The ranges are computed once (`wx::plan_with_ro`) and the
same output is applied and then read back from the page table
(`vmm::verify_wx`): the boot prints `[MM] W^X ok: N pages checked` only when
the readback is clean, and `[MM] W^X FAILED` with the count of W+X, wrongly
flagged, unmapped and unsplit pages otherwise.

`.data.ro_after_init` holds every function-pointer hook (`ro_hook!`) and, on
x86_64, the IDT. It is mapped read-write with the rest of `.data` while the
boot installs them; once every installer has run, before any other CPU or user
task, `kernel/src/boot/seal.rs` seals the hooks (a later set panics) and
remaps the section read-only, in the direct-map alias of the image too where
there is one (x86_64).

User mappings follow the same rule: a region is never executable, and nothing
adds WRITE to an executable user leaf.

Source: `crates/core/mm/src/wx.rs`, `crates/core/mm/src/vmm.rs`,
`kernel/src/boot/early.rs`, `kernel/src/boot/seal.rs`.

## Kernel memory charged to the Domain

A Domain is the unit that owns a capability table, a memory charge and a
security boundary (`crates/core/sched/src/domain.rs`). Three ledgers hang off it.

| Ledger | Unit | What it counts | Limit |
|--------|------|----------------|-------|
| `PageBudget` | Frames | Resident frames charged by `brk`, `mmap`, page tables, shm and fork, whichever thread of the Domain runs the call. | Frame limit from the topology row (`mem_pages`; `domain::set_limit`). `0` = unlimited. |
| Compressed pool ledger | Bytes | Compressed blobs stored for the Domain's pages (`zpool.rs`), and bytes of its segments on swap. | `MM_ZPOOL_DOMAIN_KIB`, `MM_SWAP_DOMAIN_KIB` |
| `KmemBudget` | Bytes | What the kernel keeps *for* the Domain, by class. | `kmem_kib` of the row. `0` = no ceiling. |

A request (`mmap`, a `brk` growth) is charged whole by
`PageBudget::charge_request`. Past the limit, a Domain that may grow (not
`mem = "locked"`, not real time) has its limit grown by exactly the request, up
to its ceiling, the row's `mem_pages_max` (CAPS.TOML format 8, in 4 KiB pages,
set with the limit at exec and spawn). Admitted bases are guaranteed: admission
counts the bases (with their copy-on-write copies and the kernel reserve), and
what that leaves of the free pages is the **growth pool**
(`budget::set_growth_pool`). Every growth takes its pages from the pool
atomically and is refused when the pool cannot hold it, so no Domain's growth
can take a frame another Domain's base (a real-time row's precommitted maps
included) was promised; a new declaration of the limit (exec) or the Domain's death (its last
member leaving) gives the growth back. Admission refuses rows whose growth, `(ceiling -
base) × instances` over every row, does not fit the pool; a ceiling below the
base; and a ceiling on a locked, real-time or kernel row, where it would change
nothing. A package row's ceiling is bounded by its signer's `mem_pages_max`.

An exec that keeps its budget and a fork child start from the row's **base**
(`PageBudget::base`), not the grown limit, with the same ceiling: a growth is
the Domain's own and is never handed on as base. What a fork child holds past
its base (the reservation it inherits) is a growth of its own, from the pool.

Each growth, and each refusal at the ceiling or for want of pool, leaves a
`budget-grow` decision record (pages asked for, limit after, ceiling), paced per
Domain like other caller-raised refusals; the growths are counted
(`memory/budget_growths` in the introspection tree, `grew=` beside `mem quota
refused=` in the census). Other charges stay within the limit as it is. A row
with no `mem_pages_max` never grows.

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
| `MemObjMeta` | One MemObj region's metadata (frame array, holder records). | The Domain of the object's creator, for its whole life (a MOVE changes the frame charge, not this one) |
| `PageTable` | A page-table frame grown by the Domain's own mappings after its address space was installed. Also counted in the frame budget: two ledgers, two limits. | The task whose own root the table is under. The table a first touch of a reserved page builds is promised: its frame and these bytes are charged past the limit (`KmemBudget::charge_unrefused`), never refused. The overshoot is bounded by the tables of the Domain's reserved pages: at most one per distinct 2 MiB touched, so about `mem_pages` x 4 KiB in the sparse worst case (a table per page) and `mem_pages / 128` KiB when the pages are dense. It goes back with the unmap or the exit; a plain table charge is refused until it has |
| `IoRing` | One io_ring's table entry (`IoRingState`), while the ring lives; the ring's page is a frame of the budget. Both are charged to the calling process's Domain at create and given back by destroy, a release and the owner's exit. | The Domain of the creating process |
| `Port` | One event port's record (`Port`: sources, queue, waiters), until the port is destroyed or its owner exits. | The Domain of the creating task |
| `Bounce` | A block call's bounce buffer: `len` bytes (at most the ring's data window, `RING_DATA_BUF_SIZE`, 2048) of kernel heap, for as long as the call, or the queued request, holds it. Refused: the call answers `ENOMEM`. | The Domain of the submitting task |

A row that declares no `kmem_kib` gets the preset's default: Kconfig
`KMEM_DEFAULT_KIB` (32 on embedded, 96 on SBC and desktop, 384 on server) plus
`mem_pages / KMEM_DEFAULT_PAGES_DIV` (64) KiB for its page tables, set where the
row's limits are installed (`domain::set_kmem_limit_kib`); `KMEM_DEFAULT_KIB = 0`
turns it off, and a row may declare more. The base is about the sum of the
per-task quotas of the class's own limits at their defaults.

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
`crates/core/mm/src/memobj.rs`, `crates/core/ipc/src/cap_store.rs`,
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
| 2. Compression | Every Domain over its high watermark gets one storm: its resident anonymous pages leave their address spaces for the compressed pool, until its charge is back at the low watermark. | `zpool::run_storm` over `pager::DomainReclaim` |
| 3. Swap | When a storm ended because the pool had no room, one full pool segment is written to the swap area, and compression is asked again. | `pager::swap_segment` |

`reclaim_pass` runs stages 0 and 1, then rounds of stage 2; if a round ended with the
pool full it runs stage 3 and goes round again. It stops when a round
stores nothing, memory is no longer low, or stage 3 could move no segment,
after at most `max_rounds` rounds (the reclaim task passes the swap area's
segment count plus one).

**Pressure comes first.** Before a pass, each poll compares every Domain's
frame-budget level (`PageBudget::pressure_change`: normal, warning from the
high watermark, critical at the limit) with the one it last reported, records
a `mem-pressure` decision for a change, and queues one `PORT_EVENT_PRESSURE`
on the Port the Domain bound with `PORT_SRC_PRESSURE`. A Domain told it
crossed into warning, with a Port bound, gets this pass to give memory back:
its storm waits for the next poll. A Domain that jumped to critical, or has
no Port bound, is not delayed.

**When it runs.** `kernel/src/tasks/reclaim.rs` polls every `MM_RECLAIM_POLL_MS`.
A pass runs when frames in use reach `MM_RECLAIM_HIGH_PCT` percent, or a Domain
with a frame limit has crossed its own high watermark. The task is placed on
the lowest CPU outside `RCU_NOCBS_CPUS` and the topology's `isolcpus`, at
`MM_RECLAIM_PRIORITY`, and a pass is refused if the CPU it finds itself on is
in that set. A Domain on a `mem = "locked"` row is never reclaimed
(`PageBudget::storm_begin`), and real-time tasks' frames are committed at map
time and have no region to take a page from.

### Stage 2: the compressed pool

The page is compressed with WKdm (`crates/core/crypto/src/wkdm.rs`, Kconfig
`MM_COMPRESS_ALGO_WKDM`, the one member of the algorithm choice) and packed
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
`pager::DomainReclaim` offers resident anonymous mapping pages that are owned by
their space alone and are plain 4 KiB leaves whose slot names their frame,
coldest generation first (see *Page generations* below). Taking one out turns
its slot into the `InTransit` marker and clears its leaf. It never offers
file-mapping pages,
pages shared copy-on-write, pages of a promoted block or contiguous run, or
any page of a space with a fork walking it. A storm stops at the first refusal
that is not "this page does not compress", and is recorded as one
`Rule::Compress` decision however many pages it took: `Refuse` when candidates reached the pool and
none was stored, `Admit` otherwise, with no pages when there was no candidate. Shared frames take other paths: the page cache's
clean frames go through `memobj_paged_drop_clean`, and the pages of a named Anon
MemObj that carries `ATTR_SWAPPABLE` are offered by the same source, as below.

#### Swappable objects

A storm of the Domain that is charged for a `SHM_ATTR_SWAPPABLE` object takes its
pages through the object, not through any one address space. A page has four
states under the object table's lock: resident (`phys_pages[i]`), storing (the
frame is the reclaimer's, the `transit` bit is set), out (the `out` bit: the
pool or swap holds the bytes) and restoring (`out` and `transit`: one fault owns
the way back). The pool names a page of an object by `memobj::pool_container`
and its number in the object, so one entry serves every mapper.

* **Take.** `memobj_swap_take` clears the page's leaf in every recorded mapping
  of the object (the holder table is the object's reverse map) and shoots it
  down on every hart, then the frame leaves the object, in one hold of the
  table. It refuses while a holder is pinned by a failed map, leaves are being
  built or removed, a fault holds the frame (`installing`), the kernel holds
  the object, a clone shares its frames, or any holder is a process whose
  Domain is `mem = "locked"` or which is real-time (`Host::pins_memory`),
  whichever Domain the object is charged to.
* **Fault.** A fault in a mapping of the object asks it (`memobj_fault_look`): a
  resident page is installed (`install_leaf`, shared with the file fault, which
  checks that the mapping still reaches the page after the leaf is written), a
  page in transit is waited for (`MARKER_WAIT`, rung by every end of a store or
  restore), and a page that is out is restored with no lock held across the
  decompression or the swap device, then installed by the next attempt. A page
  with neither frame nor copy is not the pager's and the fault fails.
* **Kernel-attached rings.** The kernel's end of a ring (a device or sound queue,
  a NIC queue, a buffer shared for one call: a key or frame buffer) addresses its region's pages directly, and a page
  that can be out cannot be addressed. A swappable object handed as such a region
  is refused by name (`ring_region`: `UNSUPPORTED` for a queue and a call buffer,
  `EINVAL` for a NIC queue) and the refusal is a `swappable-ring` decision record
  with the attach site. An application that wants swappable memory and a kernel
  ring uses two objects.
* **Who pins.** A mapper pins the object when any thread of its process group has a
  Domain on a `mem = "locked"` row, a real-time class or a base priority in the
  real-time band (`group::any_member`, `thread_pins_memory`; a priority inheritance
  boost does not count). A storm that leaves an object alone for that reason writes one
  `reclaim-skip` record for the object (the pages of it are offered one by one,
  so a storm remembers the last sixteen objects it recorded).
* **Pinning starts with nothing out.** A process is admitted to pinning by a
  `SYS_SCHEDCTL` change to a real-time class or priority (the class lands first,
  then the pages of every object it holds come back; the change is undone and
  recorded, `pin-restore` site 3, when one cannot), or by an exec into a
  `mem = "locked"` row (the Domain is locked first, then every page out of an object
  any of its processes holds comes back; the exec is refused and the Domain unlocked,
  site 4, when one cannot: such an exec may wait on the swap device). A map after
  the admission, of an object another Domain's storm took pages from, is the one
  case left:
  - a process with no real-time thread (a locked Domain alone) is not on a
    real-time path, and its map waits for the pages (refused, site 1, when one
    cannot come back);
  - a process with a real-time thread is refused, `-EBUSY` with a `pin-restore`
    record of site 1, and never waits on the pool or the swap device on its
    real-time path. Its contract: map such objects before it becomes real-time,
    or call `MEMOBJ_RESTORE` on the object in its setup phase (its reference then
    keeps every storm off the object) and map after it, never in the loop. The
    op needs `READ` and `MAP`, and refuses (`-EINVAL`, nothing done) a process
    that does not pin memory: for it the next storm takes the pages again, and
    the restores would be charged to the object's owner.
* **Opt-in.** Private anonymous memory is always reclaimable; a shared object needs
  `SHM_ATTR_SWAPPABLE`, because its other mappers did not choose to share a
  Domain's pressure (the asymmetry is intended).
* **Map and fork.** A map of an object with a page out leaves that page without
  a leaf; a fork child inherits the mapping the same way (`ForkLeaves::sparse`).
* **Charge and life.** A page that is out has given its charge back and its
  restore charges it again (`PageBudget::charge_restore`); the last release
  gives back what is resident and drops the object's pool entries. MOVE of the
  owning reference and clone answer `-EBUSY` while a page is out or moving.
* **Aging.** `pager::age_objects` feeds the same generation table as
  `pager::age_slots` does for private pages: the object's slots say what is
  resident, and the Accessed bit is harvested through each recorded mapping.

#### Page generations (`crates/core/mm/src/aging.rs`)

Four generations per page, 2 bits each, fed by the page table's Accessed bit
(`Mmu::harvest_accessed`, 64 pages per call). Every `MM_AGING_INTERVAL_MS` a
Domain with a frame limit and a charge above its low watermark is aged
(`pager::age_slots` over the slots of its private anonymous mappings and
`pager::age_objects` over its swappable objects, driven by
`kernel/src/tasks/reclaim.rs`; residency comes from the slots, the Accessed
bit from the leaves the slots' mappings reach): a resident
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
backend is a Kconfig choice: `MM_SWAP_BACKEND_OFF`, `MM_SWAP_BACKEND_PARTITION`
(server) or `MM_SWAP_BACKEND_FILE` (desktop, iot-hmi); `MM_SWAP_BACKEND` is
true when either backend is on and `MM_RECLAIM_COMPRESS` is too. The area
holds at most `MM_SWAP_SEGMENTS` segments. With a partition, the boot step (`kernel/src/boot/swap.rs`) claims
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
`crates/core/crypto/src/wkdm.rs`, `crates/core/mm/src/memobj.rs`,
`kernel/src/tasks/reclaim.rs`, `kernel/src/boot/swap.rs`,
`config/limits/Kconfig.limits`.

## Page markers

A page of a mapping that is not resident has an empty page-table word: its
state is its object's slot (*Anonymous objects and slots*), and a not-present
user entry carries nothing. There is no demand marker: a page reserved and not
touched yet is an `Empty` slot of its mapping's object, `brk` included.

The reclaimer leaves a marker in an anonymous page's slot (`slot::marker`,
`slot::PageMarker`) while the page is outside the address space, its leaf
cleared. A fault decides from the slot, never from a look at the pool: an empty
slot is a zero page, `InTransit` is waited for, and a compressed or swapped
marker is restored. The encoding is the slot word's, the same on every ISA:
the payload in bits 63:32, the code in bits 2:1, bit 0 clear (a set bit 0 is
a `Frame`).

| `PageMarker` | Code | Meaning | Payload |
|--------------|------|---------|---------|
| `Compressed` | 1 | The page is in the compressed pool. | Generation of the pool entry, so a marker never restores an earlier or later store of the same page. |
| `Swapped` | 2 | As `Compressed`, and the entry's segment is on the swap area; a fault brings it back first. | Same |
| `InTransit` | 3 | The reclaimer is storing the page now: out of the table, not yet in the pool. A fault waits. | Unused |

Marker lifecycle rules (`pager.rs`): the pool entry stays until the restored
frame is installed, then is dropped by generation; whatever ends the address
range (`munmap`, `mprotect(PROT_NONE)`, the space's end) clears the markers and
drops the entries; a fork gives the child a marker and a pool entry sharing the
parent's blob for each page the parent has out, after waiting for stores in
flight.

The pool is keyed by the address space and the page's address, not by the
object: a private object has its space as its one mapper and numbers its pages
by address, so the two keys name the same page. Keying by object needs an
object handle that outlives reuse (a generation, as an address space's key
has) and per-object duplicate, discard and retag, which shared objects with
several mappers bring.

Source: `crates/core/mm/src/slot.rs`, `crates/core/mm/src/zpool.rs`,
`crates/core/mm/src/pager.rs`.

## TLB invalidation per ISA

The cross-ISA contract is in `Mmu` (`arch/api/src/lib.rs`):

| Function | Contract |
|----------|----------|
| `flush_tlb_page(va)` | Invalidate the entry translating `va`. For changes where a stale entry elsewhere only faults and re-walks: a first-touch install, permission widening, the kernel's own table at boot. |
| `tlb_shootdown(root, va, len)` | After the caller removed, downgraded or repointed user PTEs of the table at `root`, invalidate `[va, va + len)` (`TLB_ALL`: everything) on every hart that may hold a translation, this one included, and return only when none can use one. Frames the old PTEs named may be freed after it returns, not before. Returns the mask of remote harts interrupted. |
| `flush_tlb_all` | Whole-TLB form. |
| `root_holders(root)` | Harts that still translate through `root`; a page table may be freed only while this is 0. |
| `asid_bits` | ASID/PCID bits this hart implements (0: none). |

| | riscv64 | aarch64 | x86_64 |
|---|---------|---------|--------|
| `flush_tlb_page` | `sfence.vma va`, local | `TLBI VAAE1IS` (broadcast) | `invlpg` of the current PCID only |
| `tlb_shootdown` | SBI `remote_sfence_vma` (and the `_asid` form) to the harts running the space; a local `sfence.vma` first, scoped to the space's ASID when this hart runs it under that ASID | `TLBI ...IS` broadcast then `DSB ISH` (with `TLB_ASID_SCOPED`, `ASIDE1IS`/`VAE1IS` on the space's ASID); no IPI, return value 0 | IPI to the CPUs holding the root, each running `invlpg`; or, with INVLPGB (Kconfig choice, default `X86_INVLPGB_PROBE`), a hardware broadcast followed by `TLBSYNC`, no IPI |
| Who is signalled | Harts whose published `satp` (`AZOS_HART_SATP`) names the root | Everyone (hardware broadcast) | CPUs whose published CR3 (`AZOS_HART_CR3`) names the root |
| Ranged form | Local part: `sfence.w.inval; sinval.vma; sfence.inval.ir` for ranges of `SVINVAL_MIN_PAGES` (2) or more when Svinval is present (Kconfig choice, default `RV_SVINVAL_PROBE`, execution-probed); above `TLB_FLUSH_CEILING_PAGES` pages one full flush, ASID-scoped where it can be | `TLBI RVAE1IS`/`RVAAE1IS` (FEAT_TLBIRANGE, Kconfig choice, default `A64_TLBIRANGE_PROBE`) for ranges of `A64_TLBIRANGE_MIN_PAGES` (4) or more, at most five operations for any length; per page otherwise | Above `TLB_FLUSH_CEILING_PAGES` (33) pages, the whole PCID is dropped instead of one `invlpg` each |
| `flush_tlb_all` | `sfence.vma`, local | `TLBI VMALLE1IS` | `invpcid` type 2, else a CR4.PGE toggle; local |
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

Source: `arch/api/src/lib.rs`,
`arch/api/src/tlb_gen.rs`,
`arch/riscv/src/api_impl.rs`,
`arch/riscv/src/tlb.rs`,
`arch/aarch64/src/api_impl.rs`,
`arch/x86_64/src/lib.rs`,
`arch/x86_64/src/tlb.rs`, `config/arch/Kconfig.isa`.
