// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver Manager (AQ2) — a registry of driver entries with heartbeat and
//! crash bookkeeping.
//!
//! It restarts nothing, and no entry is bound to a task today (nothing calls
//! `driver_start`). See the note at the end of this file. The RFC-0049 M4
//! cold-restart supervisor is `supervisor.rs`: a table of its own, which no
//! syscall reaches, that shares this file's cooldown (its restart limit is
//! Kconfig's `SUP_RESTART_BURST` within `SUP_RESTART_INTERVAL_S`).

use azos_sync::SpinLock;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum registered drivers.
const MAX_DRIVERS: usize = 16;

/// Maximum MMIO regions per driver.
const MAX_MMIO_PER_DRIVER: usize = 4;

/// Maximum IRQ bindings per driver.
const MAX_IRQS_PER_DRIVER: usize = 4;

/// Timeout before considering a driver unresponsive (ms).
const DRIVER_TIMEOUT_MS: u64 = 5000;

/// Maximum auto-restart attempts before giving up (the AQ2 table). The M4
/// supervisor (`supervisor.rs`) has its own limit since wave 10: Kconfig
/// `SUP_RESTART_BURST` restarts within `SUP_RESTART_INTERVAL_S` (default 3
/// within 300 s), on failure only.
pub const DRIVER_MAX_RESTARTS: u8 = 3;

/// Restart cooldown period (ms). The M4 supervisor spaces its second and
/// later restarts by this much; its first is immediate.
pub const DRIVER_RESTART_COOLDOWN_MS: u64 = 1000;

/// Maximum length of a driver name.
const DRIVER_NAME_LEN: usize = 32;

// ── Types ────────────────────────────────────────────────────────────────────

/// Driver lifecycle state.
#[derive(Clone, Copy, PartialEq)]
pub enum DriverState {
    /// Slot is unused.
    Empty,
    /// Registered but not yet started.
    Registered,
    /// Running normally.
    Running,
    /// Stopped gracefully.
    Stopped,
    /// Crashed — awaiting restart or marked as failed.
    Crashed,
}

/// A memory-mapped I/O region assigned to a driver.
#[derive(Clone, Copy)]
pub struct MmioRegion {
    pub base: usize,
    pub size: usize,
}

impl MmioRegion {
    const fn empty() -> Self {
        MmioRegion { base: 0, size: 0 }
    }
}

/// Registry entry for a single driver.
#[derive(Clone, Copy)]
pub struct DriverEntry {
    pub name: [u8; DRIVER_NAME_LEN],
    pub state: DriverState,
    /// TID of the task running this driver, NOT its scheduler pool slot.
    ///
    /// WHY the TID: this field is the key `driver_on_crash` matches a dying
    /// task against. Pool slots (`TASKS[]` / `TASK_VALID[]`) are recycled —
    /// `alloc_slot` hands back the first free index and `do_schedule` frees
    /// it on exit — so keying on the slot attributes a crash to whichever
    /// driver *last occupied that slot*, quietly marking a healthy driver
    /// as Crashed and burning its restart budget while the one that
    /// actually died is never noticed.
    ///
    /// 0 means "no task" and is used as the empty-slot sentinel: `NEXT_TID`
    /// starts at 1 and its wrap-around explicitly skips 0 (see
    /// `scheduler.rs`, `if NEXT_TID == 0 { NEXT_TID = 1 }`), so 0 is never
    /// handed to a live task. If that allocator ever changes, this sentinel
    /// breaks silently — every empty entry would match TID 0.
    ///
    /// Honest about the limit: `NEXT_TID` is a `wrapping_add(u32)`, so TIDs
    /// are monotone-within-any-realistic-uptime, not unique. After 2^32
    /// task creations a stale entry could alias a new task. That is a far
    /// weaker collision than slot reuse (which recurs within milliseconds),
    /// but it is not "impossible".
    pub task_tid: u32,
    pub mmio: [MmioRegion; MAX_MMIO_PER_DRIVER],
    pub mmio_count: u8,
    pub irqs: [u32; MAX_IRQS_PER_DRIVER],
    pub irq_count: u8,
    pub restart_count: u8,
    pub last_heartbeat: u64,
    pub last_crash: u64,
}

impl DriverEntry {
    const fn empty() -> Self {
        DriverEntry {
            name: [0; DRIVER_NAME_LEN],
            state: DriverState::Empty,
            task_tid: 0, // 0 = no task; never a live TID (see field doc)
            mmio: [MmioRegion::empty(); MAX_MMIO_PER_DRIVER],
            mmio_count: 0,
            irqs: [0; MAX_IRQS_PER_DRIVER],
            irq_count: 0,
            restart_count: 0,
            last_heartbeat: 0,
            last_crash: 0,
        }
    }
}

// ── Global state ─────────────────────────────────────────────────────────────

struct DriverTable {
    entries: [DriverEntry; MAX_DRIVERS],
    count: usize,
}

impl DriverTable {
    const fn new() -> Self {
        DriverTable {
            entries: [DriverEntry::empty(); MAX_DRIVERS],
            count: 0,
        }
    }
}

static DRIVERS: SpinLock<DriverTable> = SpinLock::new(DriverTable::new());

// ── Public API ───────────────────────────────────────────────────────────────

/// Register a new driver by name. Returns the driver slot index, or `None`
/// if the registry is full or the name is empty.
pub fn driver_register(name: &[u8]) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    let mut table = DRIVERS.lock();
    if table.count >= MAX_DRIVERS {
        return None;
    }

    // Find first empty slot.
    for (i, entry) in table.entries.iter_mut().enumerate() {
        if entry.state == DriverState::Empty {
            *entry = DriverEntry::empty();
            let copy_len = name.len().min(DRIVER_NAME_LEN);
            entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
            entry.state = DriverState::Registered;
            table.count += 1;
            return Some(i);
        }
    }
    None
}

/// Assign an MMIO region to a registered driver. Returns `true` on success.
pub fn driver_set_mmio(id: usize, base: usize, size: usize) -> bool {
    let mut table = DRIVERS.lock();
    if id >= MAX_DRIVERS {
        return false;
    }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let id = azos_limits::nospec::array_index_nospec(id, MAX_DRIVERS);
    let entry = &mut table.entries[id];
    if entry.state == DriverState::Empty {
        return false;
    }
    let idx = entry.mmio_count as usize;
    if idx >= MAX_MMIO_PER_DRIVER {
        return false;
    }
    entry.mmio[idx] = MmioRegion { base, size };
    entry.mmio_count += 1;
    true
}

/// Bind an IRQ number to a registered driver. Returns `true` on success.
pub fn driver_set_irq(id: usize, irq: u32) -> bool {
    let mut table = DRIVERS.lock();
    if id >= MAX_DRIVERS {
        return false;
    }
    let id = azos_limits::nospec::array_index_nospec(id, MAX_DRIVERS);
    let entry = &mut table.entries[id];
    if entry.state == DriverState::Empty {
        return false;
    }
    let idx = entry.irq_count as usize;
    if idx >= MAX_IRQS_PER_DRIVER {
        return false;
    }
    entry.irqs[idx] = irq;
    entry.irq_count += 1;
    true
}

/// Mark a driver as running, bound to the task with TID `task_tid`.
///
/// Returns `false` (and changes nothing) if the id is out of range, the
/// slot is empty, `task_tid` is 0, or the driver has burned through its
/// restart budget.
///
/// WHY it takes a TID and not a pool index: see [`DriverEntry::task_tid`].
///
/// WHY the restart-budget refusal: this function used to move a driver to
/// `Running` from *any* state, and it deliberately does NOT reset
/// `restart_count` — resetting would hand every crash-looping driver an
/// unlimited budget, which on a robot means a wedged peripheral respawning
/// forever instead of staying down where an operator can see it. But that
/// leaves the mirror-image hazard: a caller that keeps force-starting an
/// exhausted driver drives `restart_count` up on every crash. The counter
/// is `u8` and this kernel builds with `overflow-checks = true` and
/// `panic = "abort"`, so the 256th increment is a board reset — a
/// physical-safety event. The increments themselves are now
/// `saturating_add`, so the panic is gone regardless; this check is the
/// second layer, refusing the pointless restart in the first place.
///
/// No caller reaches this today: nothing in the tree calls `driver_start` at
/// all (see the note at the end of this file). The guard is defence against
/// the *next* caller, written for when a supervisor (RFC-0049 M4) exists.
pub fn driver_start(id: usize, task_tid: u32) -> bool {
    let mut table = DRIVERS.lock();
    if id >= MAX_DRIVERS {
        return false;
    }
    let id = azos_limits::nospec::array_index_nospec(id, MAX_DRIVERS);
    // 0 is the "no task" sentinel — accepting it would make every empty
    // entry a crash-match target for a task that never existed.
    if task_tid == 0 {
        return false;
    }
    let entry = &mut table.entries[id];
    if entry.state == DriverState::Empty {
        return false;
    }
    if entry.restart_count > DRIVER_MAX_RESTARTS {
        return false; // permanently failed — needs explicit operator action
    }
    entry.task_tid = task_tid;
    entry.state = DriverState::Running;
    entry.last_heartbeat = 0;
    true
}

// NOTE: a `driver_heartbeat(id)` with no timestamp argument used to live
// here. It stored `u64::MAX` as a "recently alive" sentinel, which
// `driver_check_health` then fed to `now_ms.saturating_sub(last_heartbeat)`
// — always 0, always under DRIVER_TIMEOUT_MS. One call to it made a driver
// permanently immune to timeout detection: a watchdog switched off by the
// very thing it watches. It had no callers (the wired path is
// `SYS_DRV_HEARTBEAT` → `driver_heartbeat_with_time`), and this crate has
// no clock to read a real timestamp from, so it was removed rather than
// repaired — a no-op stub would be another mechanism reporting success
// while doing nothing. Heartbeat with a timestamp or not at all.

/// Update heartbeat with an explicit timestamp (ms).
pub fn driver_heartbeat_with_time(id: usize, now_ms: u64) {
    let mut table = DRIVERS.lock();
    if id >= MAX_DRIVERS {
        return;
    }
    let id = azos_limits::nospec::array_index_nospec(id, MAX_DRIVERS);
    let entry = &mut table.entries[id];
    if entry.state == DriverState::Running {
        entry.last_heartbeat = now_ms;
    }
}

/// Called when a task exits. Finds the driver bound to TID `task_tid` and
/// marks it as crashed.
///
/// `task_tid` is a TID, not a scheduler pool index — see
/// [`DriverEntry::task_tid`] for why that distinction is the whole point of
/// this function being correct.
///
/// Known gap (not fixable in this crate): this variant leaves `last_crash`
/// at whatever it was, normally 0. `driver_check_health` then evaluates
/// `now_ms.saturating_sub(0) >= DRIVER_RESTART_COOLDOWN_MS`, which is true
/// immediately, so the restart cooldown is skipped on the crash path (it is
/// honoured on the heartbeat-timeout path, which does stamp `last_crash`).
/// `crates/core/sched` has no millisecond clock to read — the callers that have
/// one should prefer [`driver_on_crash_with_time`].
pub fn driver_on_crash(task_tid: u32) {
    let mut table = DRIVERS.lock();
    if task_tid == 0 {
        return; // sentinel, never a live task
    }
    for entry in table.entries.iter_mut() {
        if entry.state == DriverState::Running && entry.task_tid == task_tid {
            entry.state = DriverState::Crashed;
            // saturating, NOT `+= 1`: `restart_count` is u8 and this kernel
            // builds `overflow-checks = true` + `panic = "abort"`, so an
            // overflow here is a full board reset. Saturating at 255 keeps
            // the entry permanently above DRIVER_MAX_RESTARTS, i.e. it
            // stays down — the fail-safe direction.
            entry.restart_count = entry.restart_count.saturating_add(1);
            return;
        }
    }
}

/// Called when a task exits, with an explicit crash timestamp (ms).
///
/// Preferred over [`driver_on_crash`]: stamping `last_crash` is what makes
/// `DRIVER_RESTART_COOLDOWN_MS` actually apply to this crash.
pub fn driver_on_crash_with_time(task_tid: u32, now_ms: u64) {
    let mut table = DRIVERS.lock();
    if task_tid == 0 {
        return; // sentinel, never a live task
    }
    for entry in table.entries.iter_mut() {
        if entry.state == DriverState::Running && entry.task_tid == task_tid {
            entry.state = DriverState::Crashed;
            // See driver_on_crash for why this is saturating.
            entry.restart_count = entry.restart_count.saturating_add(1);
            entry.last_crash = now_ms;
            return;
        }
    }
}

/// Check all running drivers for heartbeat timeouts.
///
/// Drivers that have not sent a heartbeat within `DRIVER_TIMEOUT_MS` are
/// marked as crashed. Crashed drivers that have not exceeded
/// `DRIVER_MAX_RESTARTS` and whose cooldown has elapsed are marked as
/// `Registered`. No supervisor consumes that state yet (RFC-0049 M4), and
/// no entry reaches `Running` today (nothing calls `driver_start`).
///
/// Returns the number of drivers that need restarting (state == Registered
/// after having been Crashed).
pub fn driver_check_health(now_ms: u64) -> usize {
    let mut table = DRIVERS.lock();
    let mut needs_restart = 0usize;

    for entry in table.entries.iter_mut() {
        match entry.state {
            DriverState::Running => {
                // Check heartbeat timeout (skip if heartbeat was never set, i.e. == 0).
                if entry.last_heartbeat > 0
                    && now_ms.saturating_sub(entry.last_heartbeat) > DRIVER_TIMEOUT_MS
                {
                    entry.state = DriverState::Crashed;
                    // See driver_on_crash: u8 + overflow-checks + panic=abort
                    // means `+= 1` past 255 resets the board.
                    entry.restart_count = entry.restart_count.saturating_add(1);
                    entry.last_crash = now_ms;
                }
            }
            DriverState::Crashed => {
                // Check if we can auto-restart.
                if entry.restart_count <= DRIVER_MAX_RESTARTS
                    && now_ms.saturating_sub(entry.last_crash) >= DRIVER_RESTART_COOLDOWN_MS
                {
                    entry.state = DriverState::Registered;
                    needs_restart += 1;
                }
            }
            _ => {}
        }
    }

    needs_restart
}

/// Get a snapshot of a driver entry. Returns `None` if the slot is empty
/// or the id is out of range.
pub fn driver_info(id: usize) -> Option<DriverEntry> {
    let table = DRIVERS.lock();
    if id >= MAX_DRIVERS {
        return None;
    }
    let id = azos_limits::nospec::array_index_nospec(id, MAX_DRIVERS);
    let entry = &table.entries[id];
    if entry.state == DriverState::Empty {
        return None;
    }
    Some(*entry)
}

/// Return the number of registered (non-empty) drivers.
pub fn driver_count() -> usize {
    DRIVERS.lock().count
}

// ---------------------------------------------------------------------------
// Driver spawn orchestration (F06)
// ---------------------------------------------------------------------------

/// ELF path for a driver (stored alongside the registry entry).
pub const DRIVER_PATH_MAX_LEN: usize = 64;

/// Descriptor for spawning a userspace driver.
#[derive(Clone, Copy)]
pub struct DriverDescriptor {
    /// Human-readable name.
    pub name: [u8; DRIVER_NAME_LEN],
    pub name_len: u8,
    /// FAT32 path to the driver ELF.
    pub elf_path: [u8; DRIVER_PATH_MAX_LEN],
    pub elf_path_len: u8,
    /// MMIO regions to grant.
    pub mmio: [MmioRegion; MAX_MMIO_PER_DRIVER],
    pub mmio_count: u8,
    /// IRQ numbers to grant.
    pub irqs: [u32; MAX_IRQS_PER_DRIVER],
    pub irq_count: u8,
}

impl DriverDescriptor {
    pub const fn empty() -> Self {
        Self {
            name: [0; DRIVER_NAME_LEN],
            name_len: 0,
            elf_path: [0; DRIVER_PATH_MAX_LEN],
            elf_path_len: 0,
            mmio: [MmioRegion::empty(); MAX_MMIO_PER_DRIVER],
            mmio_count: 0,
            irqs: [0; MAX_IRQS_PER_DRIVER],
            irq_count: 0,
        }
    }
}

/// Maximum number of drivers that can be auto-spawned at boot.
pub const MAX_SPAWN_DESCRIPTORS: usize = 8;

/// Boot-time driver descriptors. Nothing populates or reads them: the M4
/// supervisor (`supervisor.rs`) records the image path the autorun loader
/// actually opened instead, at load time.
static mut SPAWN_DESCRIPTORS: [DriverDescriptor; MAX_SPAWN_DESCRIPTORS] = {
    const EMPTY: DriverDescriptor = DriverDescriptor::empty();
    [EMPTY; MAX_SPAWN_DESCRIPTORS]
};
static mut SPAWN_COUNT: usize = 0;

/// Register a driver descriptor for boot-time spawning.
/// Called from kernel init to declare which drivers should be auto-spawned.
pub fn driver_add_spawn_descriptor(desc: DriverDescriptor) -> bool {
    unsafe {
        if SPAWN_COUNT >= MAX_SPAWN_DESCRIPTORS {
            return false;
        }
        SPAWN_DESCRIPTORS[SPAWN_COUNT] = desc;
        SPAWN_COUNT += 1;
        true
    }
}

/// Get the number of registered spawn descriptors.
pub fn driver_spawn_count() -> usize {
    unsafe { SPAWN_COUNT }
}

/// Get a spawn descriptor by index.
pub fn driver_spawn_descriptor(idx: usize) -> Option<DriverDescriptor> {
    unsafe {
        if idx >= SPAWN_COUNT { return None; }
        Some(SPAWN_DESCRIPTORS[idx])
    }
}

/// Spawn a driver from its descriptor.
///
/// This function:
/// 1. Registers the driver in the driver table
/// 2. Configures MMIO regions and IRQ bindings
/// 3. Grants capability handles to the new task
///
/// The actual ELF loading and task creation is done by the caller
/// (kernel main or supervisor task) since it requires `exec_user`
/// which is in a different crate.
///
/// Returns the driver registry ID, or None on failure.
pub fn driver_spawn_register(desc: &DriverDescriptor) -> Option<usize> {
    let name = &desc.name[..desc.name_len as usize];

    // 1. Register in driver table
    let drv_id = driver_register(name)?;

    // 2. Configure MMIO regions
    for i in 0..desc.mmio_count as usize {
        driver_set_mmio(drv_id, desc.mmio[i].base, desc.mmio[i].size);
    }

    // 3. Configure IRQ bindings
    for i in 0..desc.irq_count as usize {
        driver_set_irq(drv_id, desc.irqs[i]);
    }

    Some(drv_id)
}

// NOTE: `driver_get_restart_list` used to live here, returning the entries
// `driver_check_health` had moved from `Crashed` back to `Registered`. It had
// no caller, and could not have had a useful one: nothing calls
// `driver_start`, so no entry ever reaches `Running`, `driver_on_crash` never
// matches a dying task, and `restart_count` never leaves 0 (the list filtered
// on `restart_count > 0`, so it was always empty). The table also records no
// ELF path to reload from (`SPAWN_DESCRIPTORS` carries one, and nothing
// populates it). Restarting a driver needs a supervisor that binds a task to
// an entry and re-executes its image; that is RFC-0049 stage M4, not a list
// accessor. Removed rather than kept as a function that answers "nothing to
// restart" forever. M4 is `supervisor.rs` (its own table, keyed by the image
// path the loader opened) and `kernel/src/drv_supervisor.rs`.
