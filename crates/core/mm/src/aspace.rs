// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The address space object: a user page-table root and the mappings made in
//! it ([`crate::pager`]'s state for the space), with the anonymous objects
//! they name.
//!
//! One per thread group. It is made when a root is handed to a task (exec,
//! spawn, fork) and ends with [`destroy`]: its records first, then its tables.
//! The group's tasks hold a [`SpaceRef`]; the leader's is the owning one, the
//! other threads copy it and drop it when they leave the root (`azos_sched`).
//!
//! **Stale references.** A task other than the group's reaches a space only
//! through a reference read from a task slot (the reclaimer) or a pool entry
//! (the swap retag), which the space may have outlived. Objects come from a
//! retained cache, so that memory is an `AddressSpace` for good. Each end of a
//! space advances the object's generation, which a reference carries: both
//! the object and the page-table frame come back last-in first-out, so the next
//! space is often the same object over the same root, and only the generation
//! tells it from the dead one. [`SpaceRef::lock`] answers `None` once the
//! object no longer holds the reference's root and generation. A made-again
//! object keeps the lock a stale reader may be holding: [`create`] writes the
//! whole object only the first time, and [`destroy`] is what empties the
//! records, so an object goes back to the cache clean.

use core::num::NonZeroUsize;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_sync::{IrqSaveGuard, SpinLock};

use crate::addr::KERNEL_PHYS_TO_VIRT_OFFSET;
use crate::cache::Cache;
use crate::anon_obj::{self, AnonObj};
use crate::mapping::{MapSet, Mapping};
use crate::pager::MAPPINGS_PER_SPACE;

/// The pager's records of one space, under the space's lock.
pub(crate) struct Space {
    /// The space has records: a mapping was made and the set has not been
    /// emptied since (`open`, `close`). The counters below mean nothing while
    /// it is not.
    pub(crate) recorded: bool,
    /// Mapped pages whose frame is installed (an anonymous page's `Frame`
    /// slot, a file page's leaf the pager made and `munmap` has not taken back).
    pub(crate) committed: usize,
    /// Fork walks running on this space (`fork_begin` .. `fork_end`; threads
    /// of one space may fork at once, so a count, not a flag): while it is
    /// not zero no block of the space may be promoted, or a walk would pass
    /// the leaf and the child get a hole, and the reclaimer takes no page out
    /// of it, or the child would miss a page that is in neither table.
    pub(crate) forking: u32,
    /// Stores of this space in flight (the reclaimer has a page out of the
    /// table and not yet in the pool). A fork waits for them to end, and the
    /// reclaimer starts none while a fork walks.
    pub(crate) reclaiming: u32,
    pub(crate) set: MapSet<MAPPINGS_PER_SPACE>,
}

impl Space {
    const fn new() -> Self {
        Space { recorded: false, committed: 0, forking: 0, reclaiming: 0, set: MapSet::new() }
    }

    /// The space gets records, starting from none if it had none.
    pub(crate) fn open(&mut self) {
        if !self.recorded {
            self.recorded = true;
            self.committed = 0;
            self.forking = 0;
            self.reclaiming = 0;
            self.set.clear();
        }
    }

    /// The space's records go.
    pub(crate) fn close(&mut self) {
        self.recorded = false;
        self.set.clear();
    }

    /// The anonymous mapping holding `va` and its object. The object lives
    /// while a mapping of the set names it, and the set is read under the
    /// space's lock, which `self` is.
    #[inline]
    pub(crate) fn anon_at(&self, va: usize) -> Option<(&Mapping, &AnonObj)> {
        let m = self.set.find(va)?;
        // SAFETY: a mapping of this set names a live object (above).
        Some((m, unsafe { anon_obj::get(m.anon_obj()?) }))
    }
}

#[repr(C)]
pub struct AddressSpace {
    /// The first word of a free object is the cache's link: nothing here
    /// reads it.
    _link: usize,
    /// The object was written whole once: its lock is a live one from then on.
    born: AtomicBool,
    /// Advanced by each [`destroy`], under the lock.
    gen: AtomicU32,
    /// The stale-mapping epoch this space last looked at (`pager::reap_stale`).
    stale_seen: AtomicU64,
    /// The page-table root, 0 while the object is no space.
    root: AtomicUsize,
    st: SpinLock<Space>,
}

static SPACES: Cache<AddressSpace> = Cache::retained();

/// A reference's tag: the object's physical address in the low bits, the low
/// bits of its generation above them. Objects lie in the RAM map, below 2^48
/// on every machine the kernel runs on; [`create`] refuses one above.
const TAG_ADDR_BITS: u32 = 48;
const TAG_ADDR_MASK: usize = (1 << TAG_ADDR_BITS) - 1;

#[inline(always)]
fn tag_of(obj: usize, gen: u32) -> usize {
    obj.wrapping_sub(KERNEL_PHYS_TO_VIRT_OFFSET) | ((gen as usize & 0xffff) << TAG_ADDR_BITS)
}

#[inline(always)]
fn tag_gen(tag: usize) -> u32 {
    (tag >> TAG_ADDR_BITS) as u32
}

#[inline(always)]
fn tag_obj(tag: usize) -> &'static AddressSpace {
    // SAFETY: a tag names an object of the retained cache (`SpaceRef` doc).
    unsafe { &*((tag & TAG_ADDR_MASK).wrapping_add(KERNEL_PHYS_TO_VIRT_OFFSET) as *const AddressSpace) }
}

/// Does the object hold the space `root` of generation `gen` (the tag's)?
/// Canary `as-stale-ref-canary`: nothing is compared; `as-gen-unchecked-canary`:
/// the generation is not.
#[inline(always)]
fn holds(a: &AddressSpace, root: usize, gen: u32) -> bool {
    cfg!(feature = "as-stale-ref-canary")
        || (a.root.load(Ordering::Relaxed) == root
            && (cfg!(feature = "as-gen-unchecked-canary") || a.gen.load(Ordering::Relaxed) & 0xffff == gen))
}

/// Runtime canary `as-stale-root` (`kernel/src/canary_rt.rs`): [`destroy`] leaves
/// the records in the object (ktest `aspace_made_again_starts_with_no_records`).
pub static CANARY_STALE_ROOT: AtomicBool = AtomicBool::new(false);

azos_common::ro_hook! {
    /// `fn() -> Option<SpaceRef>`: the running task's address space. Installed
    /// by the scheduler, which this crate cannot see; unset, there is none.
    static CURRENT_HOOK: fn() -> Option<SpaceRef>;
}

/// Install the running task's address space lookup. See [`CURRENT_HOOK`].
pub fn set_current_hook(f: fn() -> Option<SpaceRef>) {
    CURRENT_HOOK.set(f);
}

azos_common::ro_hook! {
    /// `fn(root) -> Option<SpaceRef>`: the address space of any task whose
    /// root is `root`. Installed by the scheduler; unset, there is none.
    static ROOT_HOOK: fn(usize) -> Option<SpaceRef>;
}

/// Install the lookup of an address space by its root. See [`ROOT_HOOK`].
pub fn set_root_hook(f: fn(usize) -> Option<SpaceRef>) {
    ROOT_HOOK.set(f);
}

/// The address space whose root is `root`, the running task's or another's:
/// what a kernel write into a task's memory changes (a copy-on-write break,
/// `pager::cow_swap`). The running task's is found at once, another's by the
/// scheduler's lookup.
pub fn with_root(root: usize) -> Option<SpaceRef> {
    current_with_root(root).or_else(|| ROOT_HOOK.get().and_then(|f| f(root)))
}

/// The running task's address space when its root is `root`: what a user
/// access through `root` (`vmm::translate_user`, the fault-in of a kernel copy)
/// is made on behalf of. `None` for any other root, which has no records the
/// access could commit.
pub fn current_with_root(root: usize) -> Option<SpaceRef> {
    CURRENT_HOOK.get().and_then(|f| f()).filter(|r| r.root() == root)
}

/// A reference to an address space: its root, and a tag naming the object and
/// its generation. `Copy`; the root is the space's for as long as it lives, so
/// the reference carries it and reading it costs what reading a bare root did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceRef {
    root: NonZeroUsize,
    tag: usize,
}

impl SpaceRef {
    /// The space's page-table root.
    #[inline(always)]
    pub fn root(self) -> usize {
        self.root.get()
    }

    /// The space's name where a root is not enough (the compressed pool:
    /// [`Self::of_key`]): its object and generation, so a space made again from
    /// the object has another. Canary `as-key-no-gen-canary`: the object alone.
    #[inline(always)]
    pub fn key(self) -> usize {
        if cfg!(feature = "as-key-no-gen-canary") { self.tag & TAG_ADDR_MASK } else { self.tag }
    }

    /// The stale-mapping epoch the space last looked at. Read and written only
    /// under the group's layout lock, so a stale reference reads a counter
    /// that is a lower bound at worst.
    #[inline(always)]
    pub(crate) fn stale_seen(self) -> &'static AtomicU64 {
        &tag_obj(self.tag).stale_seen
    }

    /// The space's records, or `None` when the object is no longer this space.
    #[inline]
    pub(crate) fn lock(self) -> Option<IrqSaveGuard<'static, Space>> {
        let a = tag_obj(self.tag);
        if !a.born.load(Ordering::Acquire) {
            return None;
        }
        let g = a.st.lock_irqsave();
        holds(a, self.root.get(), tag_gen(self.tag)).then_some(g)
    }

    /// The space a pool key names, with its records, if it is still that space.
    ///
    /// # Safety
    /// `key` is a [`Self::key`] of some reference.
    pub(crate) unsafe fn of_key(key: usize) -> Option<(SpaceRef, IrqSaveGuard<'static, Space>)> {
        let a = tag_obj(key);
        if !a.born.load(Ordering::Acquire) {
            return None;
        }
        let g = a.st.lock_irqsave();
        let root = NonZeroUsize::new(a.root.load(Ordering::Relaxed))?;
        let gen = a.gen.load(Ordering::Relaxed);
        if !cfg!(feature = "as-key-no-gen-canary") && !holds(a, root.get(), tag_gen(key)) {
            return None;
        }
        Some((SpaceRef { root, tag: tag_of(a as *const AddressSpace as usize, gen) }, g))
    }
}

/// Where a task keeps its [`SpaceRef`], or none: zero words are none (a task
/// starts zeroed), and the layout is plain words for the task struct the
/// switch assembly is handed. Atomic words: another hart may read a task's
/// slot while it is written.
#[repr(C)]
pub struct SpaceSlot {
    root: AtomicUsize,
    tag: AtomicUsize,
}

impl SpaceSlot {
    /// The reference the slot holds. Another task's slot may be read while it
    /// is written (the reclaimer reads them): a torn pair with either word zero
    /// reads as none, and a pair of an old and a new word is a reference that
    /// [`SpaceRef::lock`] refuses (the object is type-stable, its root and
    /// generation compared).
    #[inline]
    pub fn get(&self) -> Option<SpaceRef> {
        let tag = self.tag.load(Ordering::Relaxed);
        let root = NonZeroUsize::new(self.root.load(Ordering::Relaxed))?;
        (tag != 0).then_some(SpaceRef { root, tag })
    }

    /// [`Self::get`] of the running task's own slot, which nothing writes while
    /// the task runs: no torn pair to refuse.
    #[inline(always)]
    pub fn get_own(&self) -> Option<SpaceRef> {
        let root = NonZeroUsize::new(self.root.load(Ordering::Relaxed))?;
        Some(SpaceRef { root, tag: self.tag.load(Ordering::Relaxed) })
    }

    /// The space's root, 0 when the slot holds none.
    #[inline(always)]
    pub fn root(&self) -> usize {
        self.root.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn is_some(&self) -> bool {
        self.root() != 0
    }

    #[inline(always)]
    pub fn is_none(&self) -> bool {
        self.root() == 0
    }

    pub fn set(&self, r: Option<SpaceRef>) {
        let (root, tag) = r.map_or((0, 0), |r| (r.root.get(), r.tag));
        self.root.store(root, Ordering::Relaxed);
        self.tag.store(tag, Ordering::Relaxed);
    }

    pub fn take(&self) -> Option<SpaceRef> {
        let r = self.get();
        self.set(None);
        r
    }
}

/// A new address space over the user root `root`, with no records. `None`
/// when the cache has no memory for it, or `root` is 0.
pub fn create(root: usize) -> Option<SpaceRef> {
    let root = NonZeroUsize::new(root)?;
    let p = SPACES.alloc();
    if p.is_null() {
        return None;
    }
    if (p as usize).wrapping_sub(KERNEL_PHYS_TO_VIRT_OFFSET) & !TAG_ADDR_MASK != 0 {
        // SAFETY: just taken from this cache, unused.
        unsafe { SPACES.free(p) };
        return None;
    }
    // SAFETY: `p` is a whole object of the cache, ours until `destroy`. Its
    // bytes are a block's zeros or what `destroy` left; only `born` is read
    // before it is written.
    let gen = unsafe {
        if !(*p).born.load(Ordering::Acquire) {
            addr_of_mut!((*p).gen).write(AtomicU32::new(0));
            addr_of_mut!((*p).root).write(AtomicUsize::new(0));
            addr_of_mut!((*p).stale_seen).write(AtomicU64::new(0));
            addr_of_mut!((*p).st).write(SpinLock::new(Space::new()));
            (*p).born.store(true, Ordering::Release);
        }
        // Under the lock: a stale reader that holds it reads the old answer
        // (0) or this one.
        let _g = (*p).st.lock_irqsave();
        (*p).root.store(root.get(), Ordering::Relaxed);
        (*p).gen.load(Ordering::Relaxed)
    };
    Some(SpaceRef { root, tag: tag_of(p as usize, gen) })
}

/// End the space `r`: its records go (`pager::forget`: mappings and their
/// anonymous objects, reservations, pool pages, the page cache's counts, the
/// leaves of every mapping of frames another owner holds), then the object, then
/// its page tables ([`crate::vmm::destroy_user_pagetable`]). Returns that call's
/// answer: the mask of harts still on the root, the tables then leaked.
///
/// Canary `as-stale-root-canary` (host suites), runtime canary `as-stale-root`
/// ([`CANARY_STALE_ROOT`]): the records are not dropped, so the next space made
/// from the object starts with them.
///
/// The caller holds the only live reference: no task runs on the space.
pub fn destroy(r: SpaceRef) -> usize {
    if !cfg!(feature = "as-stale-root-canary") && !CANARY_STALE_ROOT.load(Ordering::Relaxed) {
        crate::pager::forget(r);
    }
    let a = tag_obj(r.tag);
    {
        let _g = a.st.lock_irqsave();
        a.root.store(0, Ordering::Relaxed);
        a.gen.store(a.gen.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }
    // SAFETY: the object came from this cache and is no space any more.
    unsafe { SPACES.free(a as *const AddressSpace as *mut AddressSpace) };
    crate::vmm::destroy_user_pagetable(r.root())
}
