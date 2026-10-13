// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The model of the kernel side: `map` hands out page-aligned zeroed memory
//! with the guard pages as bookkeeping, `fault` is a catchable panic.

use azos_ualloc::engine::{Config, Fault, Heap, Sys};
use std::alloc::{alloc_zeroed, Layout};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const PAGE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub struct Faulted(pub Fault, pub usize);

pub struct Model {
    /// Entropy handed out, `None` = the pool refuses.
    pub entropy: Option<u64>,
    pub notes: Vec<String>,
    /// Every body mapped: (base, len, guards).
    pub mapped: Vec<(usize, usize, bool)>,
    /// Every guard page handed out.
    pub guard_pages: Vec<usize>,
    pub unmapped: Vec<(usize, usize, bool)>,
    /// Refuse a map after this many (to test the failure paths).
    pub map_budget: usize,
    /// Really free on unmap (the benchmark); tests keep stale memory readable.
    pub release: bool,
}

impl Model {
    pub fn new(seed: Option<u64>) -> Model {
        Model { entropy: seed, notes: vec![], mapped: vec![], guard_pages: vec![], unmapped: vec![], map_budget: usize::MAX, release: false }
    }
}

impl Sys for Model {
    const PAGE: usize = PAGE;

    fn map(&mut self, len: usize, guards: bool) -> Option<usize> {
        if self.map_budget == 0 {
            return None;
        }
        self.map_budget -= 1;
        assert_eq!(len % PAGE, 0, "map length is a page multiple");
        let total = len + if guards { 2 * PAGE } else { 0 };
        // SAFETY: non-zero size, valid power-of-two alignment.
        let p = unsafe { alloc_zeroed(Layout::from_size_align(total, PAGE).unwrap()) } as usize;
        assert_ne!(p, 0);
        let body = if guards { p + PAGE } else { p };
        if guards {
            self.guard_pages.push(p);
            self.guard_pages.push(body + len);
        }
        self.mapped.push((body, len, guards));
        Some(body)
    }

    fn unmap(&mut self, base: usize, len: usize, guards: bool) {
        assert!(self.mapped.contains(&(base, len, guards)), "unmap of something that was mapped, same shape");
        self.unmapped.push((base, len, guards));
        // Tests leak on purpose: a stale pointer must read the model, not
        // crash the harness.
        if self.release {
            let (p, total) = if guards { (base - PAGE, len + 2 * PAGE) } else { (base, len) };
            // SAFETY: the pointer and layout `map` allocated.
            unsafe { std::alloc::dealloc(p as *mut u8, Layout::from_size_align(total, PAGE).unwrap()) };
        }
    }

    fn entropy(&mut self, out: &mut [u8]) -> bool {
        let Some(mut s) = self.entropy else { return false };
        for b in out.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (s >> 33) as u8;
        }
        true
    }

    fn note(&mut self, msg: &[u8]) {
        self.notes.push(String::from_utf8_lossy(msg).into_owned());
    }

    fn fault(&mut self, kind: Fault, addr: usize) -> ! {
        std::panic::panic_any(Faulted(kind, addr))
    }
}

pub type H = Heap<Model, 64, 16>;
pub type Big = Heap<Model, 4096, 256>;

pub fn plain() -> Config {
    Config { quarantine_bytes: 0, block_bytes: 16 * 1024, randomize: false, poison: false, guard: true, seed_required: false }
}

pub fn hardened() -> Config {
    Config { quarantine_bytes: 4096, block_bytes: 16 * 1024, randomize: true, poison: true, guard: true, seed_required: false }
}

pub fn heap(cfg: Config, seed: Option<u64>) -> H {
    Heap::new(Model::new(seed), cfg)
}

/// Run `f`; `Some(fault)` if the engine raised one.
pub fn fault_of<R>(f: impl FnOnce() -> R) -> Option<Faulted> {
    // The default hook prints every panic: the engine's own are expected.
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<Faulted>().is_none() {
                prev(info);
            }
        }));
    });
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => None,
        Err(e) => match e.downcast::<Faulted>() {
            Ok(f) => Some(*f),
            Err(e) => std::panic::resume_unwind(e),
        },
    }
}
