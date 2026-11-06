// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The address space object: a user page-table root and the region records
//! made in it ([`crate::pager`]'s state for the space).
//!
//! One per thread group. It is made when a root is handed to a task (exec,
//! spawn, fork) and ends with [`destroy`]: its records first, then its tables.
//! The group's tasks hold a [`SpaceRef`]; the leader's is the owning one, the
//! other threads copy it and drop it when they leave the root (`azos_sched`).
//!
//! **Stale references.** A task other than the group's reaches a space only
//! through a reference read from a task slot (the reclaimer) or a pool entry
//! (the swap retag), which the space may have outlived. Objects come from a
//! retained cache, so that memory is an `AddressSpace` for good, and
//! [`SpaceRef::lock`] answers `None` once the object no longer holds the
//! reference's root (destroyed, or made again for another root). A made-again
//! object keeps the lock a stale reader may be holding: [`create`] writes the
//! whole object only the first time, and [`destroy`] is what empties the
//! records, so an object goes back to the cache clean.

use core::num::NonZeroUsize;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use azos_sync::{IrqSaveGuard, SpinLock};

use crate::cache::Cache;
use crate::pager::REGIONS_PER_SPACE;
use crate::region::RegionSet;

/// The pager's records of one space, under the space's lock.
pub(crate) struct Space {
    /// The space has records: a region was reserved and the set has not been
    /// emptied since (`open`, `close`). The counters below mean nothing while
    /// it is not.
    pub(crate) recorded: bool,
    /// Region pages whose frame is installed (page table entries the pager
    /// made valid and that `munmap` has not taken back).
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
    pub(crate) set: RegionSet<REGIONS_PER_SPACE>,
}

impl Space {
    const fn new() -> Self {
        Space { recorded: false, committed: 0, forking: 0, reclaiming: 0, set: RegionSet::new() }
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
}

#[repr(C)]
pub struct AddressSpace {
    /// The first word of a free object is the cache's link: nothing here
    /// reads it.
    _link: usize,
    /// The object was written whole once: its lock is a live one from then on.
    born: AtomicBool,
    /// The page-table root, 0 while the object is no space.
    root: AtomicUsize,
    st: SpinLock<Space>,
}

static SPACES: Cache<AddressSpace> = Cache::retained();

azos_common::ro_hook! {
    /// `fn() -> Option<SpaceRef>`: the running task's address space. Installed
    /// by the scheduler, which this crate cannot see; unset, there is none.
    static CURRENT_HOOK: fn() -> Option<SpaceRef>;
}

/// Install the running task's address space lookup. See [`CURRENT_HOOK`].
pub fn set_current_hook(f: fn() -> Option<SpaceRef>) {
    CURRENT_HOOK.set(f);
}

/// The running task's address space when its root is `root`: what a user
/// access through `root` (`vmm::translate_user`, the fault-in of a kernel copy)
/// is made on behalf of. `None` for any other root, which has no records the
/// access could commit.
pub fn current_with_root(root: usize) -> Option<SpaceRef> {
    CURRENT_HOOK.get().and_then(|f| f()).filter(|r| r.root() == root)
}

/// A reference to an address space: its root, with the object. `Copy`; the
/// root is the object's for as long as the space lives, so the reference
/// carries it and reading it costs what reading a bare root did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceRef {
    root: NonZeroUsize,
    obj: *const AddressSpace,
}

// SAFETY: `obj` names an object of a retained cache, valid memory for the
// life of the kernel; what it holds is reached under its lock.
unsafe impl Send for SpaceRef {}
// SAFETY: as above.
unsafe impl Sync for SpaceRef {}

impl SpaceRef {
    /// The space's page-table root.
    #[inline(always)]
    pub fn root(self) -> usize {
        self.root.get()
    }

    /// The space's name where a root is not enough (the compressed pool:
    /// [`Self::of_key`]): its object's address.
    #[inline(always)]
    pub fn key(self) -> usize {
        self.obj as usize
    }

    #[inline(always)]
    fn obj(self) -> &'static AddressSpace {
        // SAFETY: a retained cache's object (type doc).
        unsafe { &*self.obj }
    }

    /// The space's records, or `None` when the object is no longer this space.
    /// Canary `as-stale-ref-canary`: the root is not compared, so a stale
    /// reference reaches the records of the next space made from the object.
    #[inline]
    pub(crate) fn lock(self) -> Option<IrqSaveGuard<'static, Space>> {
        let a = self.obj();
        let g = a.st.lock_irqsave();
        (cfg!(feature = "as-stale-ref-canary") || a.root.load(Ordering::Relaxed) == self.root.get()).then_some(g)
    }

    /// The space a pool key names, with its records, if it is still a space.
    ///
    /// # Safety
    /// `key` is a [`Self::key`] of some reference.
    pub(crate) unsafe fn of_key(key: usize) -> Option<(SpaceRef, IrqSaveGuard<'static, Space>)> {
        // SAFETY: per the contract, an object of the retained cache.
        let a: &'static AddressSpace = unsafe { &*(key as *const AddressSpace) };
        let g = a.st.lock_irqsave();
        let root = NonZeroUsize::new(a.root.load(Ordering::Relaxed))?;
        Some((SpaceRef { root, obj: a }, g))
    }
}

/// Where a task keeps its [`SpaceRef`], or none: zero bytes are none (a task
/// starts zeroed), and the layout is plain words for the task struct the
/// switch assembly is handed.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceSlot {
    root: usize,
    obj: usize,
}

impl SpaceSlot {
    pub fn new(r: Option<SpaceRef>) -> Self {
        match r {
            Some(r) => SpaceSlot { root: r.root.get(), obj: r.obj as usize },
            None => SpaceSlot { root: 0, obj: 0 },
        }
    }

    #[inline(always)]
    pub fn get(self) -> Option<SpaceRef> {
        NonZeroUsize::new(self.root).map(|root| SpaceRef { root, obj: self.obj as *const AddressSpace })
    }

    /// The space's root, 0 when the slot holds none.
    #[inline(always)]
    pub fn root(self) -> usize {
        self.root
    }

    #[inline(always)]
    pub fn is_some(self) -> bool {
        self.root != 0
    }

    #[inline(always)]
    pub fn is_none(self) -> bool {
        self.root == 0
    }

    pub fn set(&mut self, r: Option<SpaceRef>) {
        *self = SpaceSlot::new(r);
    }

    pub fn take(&mut self) -> Option<SpaceRef> {
        let r = self.get();
        *self = SpaceSlot::new(None);
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
    // SAFETY: `p` is a whole object of the cache, ours until `destroy`. Its
    // bytes are a block's zeros or what `destroy` left; only `born` is read
    // before it is written.
    unsafe {
        if !(*p).born.load(Ordering::Acquire) {
            addr_of_mut!((*p).root).write(AtomicUsize::new(0));
            addr_of_mut!((*p).st).write(SpinLock::new(Space::new()));
            (*p).born.store(true, Ordering::Release);
        }
        // Under the lock: a stale reader that holds it reads the old answer
        // (0) or this one.
        let _g = (*p).st.lock_irqsave();
        (*p).root.store(root.get(), Ordering::Relaxed);
    }
    Some(SpaceRef { root, obj: p })
}

/// End the space `r`: its records go (`pager::forget`: regions, reservations,
/// pool pages, the page cache's region counts), then the object, then its
/// page tables, sparing the leaf frames in `[skip_lo, skip_hi)`
/// ([`crate::vmm::destroy_user_pagetable_skip_range`]). Returns that call's
/// answer: the mask of harts still on the root, the tables then leaked.
///
/// Canary `as-stale-root-canary`: the records are not dropped, so the next
/// space made from the object starts with them.
///
/// The caller holds the only live reference: no task runs on the space.
pub fn destroy(r: SpaceRef, skip_lo: usize, skip_hi: usize) -> usize {
    if !cfg!(feature = "as-stale-root-canary") {
        crate::pager::forget(r);
    }
    let a = r.obj();
    {
        let _g = a.st.lock_irqsave();
        a.root.store(0, Ordering::Relaxed);
    }
    // SAFETY: the object came from this cache and is no space any more.
    unsafe { SPACES.free(r.obj as *mut AddressSpace) };
    crate::vmm::destroy_user_pagetable_skip_range(r.root(), skip_lo, skip_hi)
}
