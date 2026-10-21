// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Table memory, a MemObj's frames and an ISA with no tables, for the tests.

use azos_arch_api::{
    Exit, HvKind, HvStatus, Hypervisor, RawExit, Stage2Root, StageError, StagePerms, StageTableMem,
};
use azos_hv::stage2::FrameSource;
use std::collections::HashMap;
use std::sync::Mutex;

/// Table memory in a hash map: frames from 0x10_0000 up, optionally capped,
/// every live allocation remembered so a leak or a double free shows.
#[derive(Default)]
pub struct Mem {
    words: HashMap<u64, u64>,
    next: u64,
    /// Frames (pages) allocatable in total; `None`: no cap.
    pub cap_pages: Option<usize>,
    live: HashMap<u64, usize>,
}

impl Mem {
    pub fn new() -> Mem {
        Mem { next: 0x10_0000, ..Mem::default() }
    }

    pub fn capped(pages: usize) -> Mem {
        Mem { cap_pages: Some(pages), ..Mem::new() }
    }

    /// Pages allocated and not freed.
    pub fn live_pages(&self) -> usize {
        self.live.values().sum()
    }

    pub fn leaked(&self) -> bool {
        !self.live.is_empty()
    }
}

impl StageTableMem for Mem {
    fn alloc(&mut self, pages: usize) -> Option<u64> {
        if let Some(c) = self.cap_pages {
            if self.live_pages() + pages > c {
                return None;
            }
        }
        let align = pages as u64 * 4096;
        let pa = self.next.div_ceil(align) * align;
        self.next = pa + align;
        assert!(self.live.insert(pa, pages).is_none());
        Some(pa)
    }

    fn free(&mut self, pa: u64, pages: usize) {
        assert_eq!(self.live.remove(&pa), Some(pages), "free of {pa:#x} x{pages} that is not a live allocation");
        for i in 0..(pages as u64 * 512) {
            self.words.remove(&(pa + i * 8));
        }
    }

    fn read(&self, pa: u64) -> u64 {
        self.words.get(&pa).copied().unwrap_or(0)
    }

    fn write(&mut self, pa: u64, word: u64) {
        self.words.insert(pa, word);
    }
}

/// The frames of a MemObj: `n` frames of `bytes` each, scattered (2 MiB
/// apart, from `base`), so a mapping that assumed contiguity would be wrong.
pub struct Frames {
    pub n: usize,
    pub bytes: u64,
    pub base: u64,
}

impl Frames {
    pub fn new(n: usize, bytes: u64) -> Frames {
        Frames { n, bytes, base: 0x4000_0000 }
    }
}

impl FrameSource for Frames {
    fn frames(&self) -> usize {
        self.n
    }
    fn frame(&self, idx: usize) -> Option<u64> {
        (idx < self.n).then(|| self.base + idx as u64 * 0x20_0000)
    }
    fn frame_bytes(&self) -> u64 {
        self.bytes
    }
}

/// An ISA with no tables: a map of pages, and a count of maps after which it
/// runs out of memory.
#[derive(Default)]
pub struct FakeHv {
    pages: Mutex<HashMap<u64, (u64, StagePerms)>>,
    /// Maps that succeed before `NoMemory` (None: unlimited).
    pub fail_after: Mutex<Option<usize>>,
}

impl Hypervisor for FakeHv {
    fn kind(&self) -> HvKind {
        HvKind::RiscvH
    }
    fn status(&self) -> HvStatus {
        HvStatus::Usable(HvKind::RiscvH)
    }
    fn gpa_bits(&self) -> u8 {
        40
    }
    fn stage2_create(&self, _mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        Ok(Stage2Root { root: 0, aux: 0 })
    }
    fn stage2_map(
        &self,
        _s2: &Stage2Root,
        _mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError> {
        if let Some(n) = self.fail_after.lock().unwrap().as_mut() {
            if *n == 0 {
                return Err(StageError::NoMemory);
            }
            *n -= 1;
        }
        let mut p = self.pages.lock().unwrap();
        if p.contains_key(&gpa) {
            return Err(StageError::Overlap);
        }
        p.insert(gpa, (hpa, perms));
        Ok(())
    }
    fn stage2_unmap(&self, _s2: &Stage2Root, _mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        self.pages.lock().unwrap().remove(&gpa).map(|p| p.0).ok_or(StageError::NotMapped)
    }
    fn stage2_translate(&self, _s2: &Stage2Root, _mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        self.pages.lock().unwrap().get(&(gpa & !0xFFF)).map(|&(h, p)| (h | (gpa & 0xFFF), p))
    }
    fn stage2_flush(&self, _vmid: u16) {}
    fn stage2_destroy(&self, _s2: Stage2Root, _mem: &mut dyn StageTableMem) {
        self.pages.lock().unwrap().clear();
    }
    fn decode_exit(&self, raw: &RawExit) -> Exit {
        Exit::Other(raw.code)
    }
}

// ── a guest that follows a script ───────────────────────────────────────

use azos_arch_api::{GuestCtx, MmioDone};
use std::collections::VecDeque;

/// What the ISA saw at one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub irqs: u64,
    pub completed: Option<MmioDone>,
    pub started: bool,
    /// The held time the ISA was told to take off the guest's clock.
    pub time_skip: u64,
}

/// An ISA whose guest does what a script says: each entry answers the next
/// exit (and, for a decoded store, the value the guest register held). It can
/// enter or not, as asked.
pub struct ScriptHv {
    inner: FakeHv,
    can: bool,
    script: Mutex<VecDeque<(Exit, u64)>>,
    pub seen: Mutex<Vec<Entry>>,
    /// For each fence carried out: how many entries had happened.
    pub fenced: Mutex<Vec<usize>>,
}

impl ScriptHv {
    pub fn new(script: Vec<(Exit, u64)>) -> ScriptHv {
        ScriptHv { inner: FakeHv::default(), can: true, script: Mutex::new(script.into()), seen: Mutex::new(Vec::new()), fenced: Mutex::new(Vec::new()) }
    }
}

impl Hypervisor for ScriptHv {
    fn kind(&self) -> HvKind {
        self.inner.kind()
    }
    fn status(&self) -> HvStatus {
        self.inner.status()
    }
    fn gpa_bits(&self) -> u8 {
        self.inner.gpa_bits()
    }
    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        self.inner.stage2_create(mem)
    }
    fn stage2_map(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64, hpa: u64, p: StagePerms) -> Result<(), StageError> {
        self.inner.stage2_map(s2, mem, gpa, hpa, p)
    }
    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        self.inner.stage2_unmap(s2, mem, gpa)
    }
    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        self.inner.stage2_translate(s2, mem, gpa)
    }
    fn stage2_flush(&self, vmid: u16) {
        self.inner.stage2_flush(vmid)
    }
    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem) {
        self.inner.stage2_destroy(s2, mem)
    }
    fn decode_exit(&self, raw: &RawExit) -> Exit {
        self.inner.decode_exit(raw)
    }
    fn can_enter(&self) -> bool {
        self.can
    }
    fn enter(&self, ctx: &mut GuestCtx) -> Exit {
        self.seen.lock().unwrap().push(Entry {
            irqs: ctx.irqs,
            completed: ctx.completed,
            started: ctx.started,
            time_skip: ctx.time_skip,
        });
        let (exit, store_value) = self.script.lock().unwrap().pop_front().expect("the script ran out: the loop entered again");
        ctx.completed = None;
        ctx.mmio_value = store_value;
        exit
    }
    fn remote_fence(&self, _ctx: &GuestCtx, _fence: &azos_arch_api::RemoteFence) {
        let entries = self.seen.lock().unwrap().len();
        self.fenced.lock().unwrap().push(entries);
    }
}

// ── the shared page, as the far end writes it ───────────────────────────

use azos_hv::trapwire::{Completion, Trap, CPL_AT, CPL_BYTES, CPL_HEAD, CPL_TAIL, TRAPS, TRAP_AT, TRAP_BYTES, TRAP_HEAD, TRAP_TAIL};

/// A 4-aligned page of zeroes.
pub struct Page(pub Box<[u32; 1024]>);

impl Page {
    pub fn new() -> Page {
        Page(Box::new([0; 1024]))
    }

    pub fn ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr() as *mut u8
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: a `[u32; 1024]` is 4096 initialised bytes.
        unsafe { core::slice::from_raw_parts(self.0.as_ptr() as *const u8, 4096) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`.
        unsafe { core::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut u8, 4096) }
    }

    pub fn word(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.bytes()[off..off + 4].try_into().unwrap())
    }

    pub fn set_word(&mut self, off: usize, v: u32) {
        self.bytes_mut()[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// The device model's side, written out from the layout and not by the
    /// monitor's code: take the oldest trap.
    pub fn model_pop_trap(&mut self) -> Option<Trap> {
        let (head, tail) = (self.word(TRAP_HEAD), self.word(TRAP_TAIL));
        if head == tail {
            return None;
        }
        let at = TRAP_AT + (head % TRAPS) as usize * TRAP_BYTES;
        let b: [u8; TRAP_BYTES] = self.bytes()[at..at + TRAP_BYTES].try_into().unwrap();
        self.set_word(TRAP_HEAD, head.wrapping_add(1));
        Some(Trap::decode(&b))
    }

    /// The device model's side: answer.
    pub fn model_push_completion(&mut self, c: &Completion) {
        let (head, tail) = (self.word(CPL_HEAD), self.word(CPL_TAIL));
        assert!(tail.wrapping_sub(head) < TRAPS, "the model filled the completion ring");
        let at = CPL_AT + (tail % TRAPS) as usize * CPL_BYTES;
        self.bytes_mut()[at..at + CPL_BYTES].copy_from_slice(&c.encode());
        self.set_word(CPL_TAIL, tail.wrapping_add(1));
    }
}
