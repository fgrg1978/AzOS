// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Test doubles: host memory standing in for physical memory (the "physical
//! address" is the host address), and a register file the unit models mutate.

use azos_iommu::{Mmio, TableMem};
use std::alloc::{alloc_zeroed, Layout};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Pages from the host allocator; `limit` caps how many `alloc_page` may
/// hand out (to test running out). `pages` lists them in allocation order.
pub struct TestMem {
    pub pages: Mutex<Vec<u64>>,
    pub limit: Mutex<usize>,
    /// Every `invalidate` call: (pa, len).
    pub invalidated: Mutex<Vec<(u64, usize)>>,
    /// Every `clean` call: (pa, len).
    pub cleaned: Mutex<Vec<(u64, usize)>>,
    /// The first 64-bit word at `pa` when each `clean` call made it visible:
    /// what a unit could have read at that moment.
    pub cleaned_first: Mutex<Vec<(u64, u64)>>,
}

impl TestMem {
    pub fn leak() -> &'static TestMem {
        Box::leak(Box::new(TestMem {
            pages: Mutex::new(Vec::new()),
            limit: Mutex::new(usize::MAX),
            invalidated: Mutex::new(Vec::new()),
            cleaned: Mutex::new(Vec::new()),
            cleaned_first: Mutex::new(Vec::new()),
        }))
    }
    pub fn page(&self, i: usize) -> u64 {
        self.pages.lock().unwrap()[i]
    }
    pub fn count(&self) -> usize {
        self.pages.lock().unwrap().len()
    }
    pub fn set_limit(&self, n: usize) {
        *self.limit.lock().unwrap() = n;
    }
    /// Was `invalidate` called on a range inside `[pa, pa + len)`?
    pub fn invalidated_in(&self, pa: u64, len: u64) -> bool {
        self.invalidated.lock().unwrap().iter().any(|&(p, _)| p >= pa && p < pa + len)
    }
    /// The first word at `pa` each time a `clean` started there.
    pub fn cleaned_values(&self, pa: u64) -> Vec<u64> {
        self.cleaned_first.lock().unwrap().iter().filter(|&&(p, _)| p == pa).map(|&(_, v)| v).collect()
    }
    /// Was `clean` called on a range that covers all of `[pa, pa + len)`?
    pub fn cleaned_all(&self, pa: u64, len: u64) -> bool {
        self.cleaned.lock().unwrap().iter().any(|&(p, l)| p <= pa && p + l as u64 >= pa + len)
    }
}

impl TableMem for TestMem {
    fn alloc_page(&self) -> Option<u64> {
        if self.pages.lock().unwrap().len() >= *self.limit.lock().unwrap() {
            return None;
        }
        self.alloc_aligned(4096, 4096)
    }
    fn alloc_aligned(&self, bytes: usize, align: usize) -> Option<u64> {
        let layout = Layout::from_size_align(bytes, align).unwrap();
        // SAFETY: non-zero size.
        let p = unsafe { alloc_zeroed(layout) } as u64;
        self.pages.lock().unwrap().push(p);
        Some(p)
    }
    fn ptr(&self, pa: u64) -> *mut u8 {
        pa as *mut u8
    }
    fn clean(&self, pa: u64, len: usize) {
        self.cleaned.lock().unwrap().push((pa, len));
        self.cleaned_first.lock().unwrap().push((pa, read64(pa, 0)));
    }
    fn invalidate(&self, pa: u64, len: usize) {
        self.invalidated.lock().unwrap().push((pa, len));
    }
}

pub fn read64(pa: u64, idx: usize) -> u64 {
    // SAFETY: a test page this file allocated.
    unsafe { *((pa as *const u64).add(idx)) }
}

pub fn write64(pa: u64, idx: usize, v: u64) {
    // SAFETY: a test page this file allocated.
    unsafe { *((pa as *mut u64).add(idx)) = v }
}

/// A register file: reads return what was last written unless the model
/// installed a hook for the offset.
#[derive(Default)]
pub struct Regs {
    pub r: HashMap<usize, u64>,
    /// Every write in order: (offset, value).
    pub log: Vec<(usize, u64)>,
}

pub type Hook = Box<dyn FnMut(&mut Regs, usize, u64) + Send>;

#[derive(Clone)]
pub struct FakeMmio {
    pub regs: Arc<Mutex<Regs>>,
    hook: Arc<Mutex<Hook>>,
}

impl FakeMmio {
    pub fn new(init: &[(usize, u64)], hook: Hook) -> Self {
        let mut regs = Regs::default();
        for (o, v) in init {
            regs.r.insert(*o, *v);
        }
        FakeMmio { regs: Arc::new(Mutex::new(regs)), hook: Arc::new(Mutex::new(hook)) }
    }
    pub fn get(&self, off: usize) -> u64 {
        self.regs.lock().unwrap().r.get(&off).copied().unwrap_or(0)
    }
    pub fn set(&self, off: usize, v: u64) {
        self.regs.lock().unwrap().r.insert(off, v);
    }
    pub fn writes_to(&self, off: usize) -> Vec<u64> {
        self.regs.lock().unwrap().log.iter().filter(|(o, _)| *o == off).map(|(_, v)| *v).collect()
    }
    fn put(&self, off: usize, v: u64) {
        let mut regs = self.regs.lock().unwrap();
        regs.log.push((off, v));
        regs.r.insert(off, v);
        let mut hook = self.hook.lock().unwrap();
        (hook)(&mut regs, off, v);
    }
}

impl Mmio for FakeMmio {
    fn read32(&self, off: usize) -> u32 {
        self.get(off) as u32
    }
    fn write32(&self, off: usize, val: u32) {
        self.put(off, val as u64)
    }
    fn read64(&self, off: usize) -> u64 {
        self.get(off)
    }
    fn write64(&self, off: usize, val: u64) {
        self.put(off, val)
    }
}
