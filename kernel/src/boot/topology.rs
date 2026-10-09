// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Topology install and memory admission against the DTB/fallback RAM window.

use azos_arch::Cpu as _;
use crate::*;

/// Install the static topology before any task that mints a capability
/// from it can run.
///
/// Shared between both `kernel_main`s (riscv64 called this in place until
/// 2026-09-22; aarch64 never called it at all, which is why `captest` and
/// `abitest`'s topology-seeded checks — `cap_lookup(Endpoint, ...)` for
/// `endpoint.demo` among them — failed there: `azos_topology::get()`
/// returned `None`, and the autorun cap-seed bridge logs "topology not
/// installed — nothing minted" instead of granting anything).
///
/// Wave 15 (TOPOSIGN): the topology comes from the volume when Kconfig
/// `TOPOLOGY_SOURCE` says so — `/fat/CAPS.TOM` + `CAPS.SIG` and
/// `/fat/SCHED.TOM`: one signature over CAPS.TOM, whose top-level binding
/// names SCHED.TOM's SHA-256, this device's id and a counter no lower than
/// the floor in reserved tail sector `TOPOLOGY_FLOOR_SECTOR`; nothing is
/// parsed before the signature and the hash match; then admitted (the checks
/// below, run on the candidate BEFORE it is published) — and from
/// `fill_default_minimal` (builder.rs) otherwise. FAT32 is mounted in Phase 6, long before this
/// point, so nothing moved. Which one, and what a missing or refused set
/// does, is `azos_topology::signed::decide`'s table; this function reads
/// the files, prints, records (`SAFETY_TOPO_SOURCE`) and halts.
///
/// Built in place in the topology's static slot: the table is sized by the
/// limits and is megabytes on the fleet profile. Built on the boot stack
/// and passed by value, it ran past the stack into `.bss` and the fleet
/// image faulted in the driver registry it had overwritten.
///
/// `num_cpus` gates deadline admission: the install-time check can only
/// assume every CPU a mask names, so a profile pinned to a CPU this board
/// does not have is refused here, once the board's real hart count is
/// known, before anything is spawned. Halts the board on either failure —
/// callers do not return past this on an error path.
pub(crate) fn install_topology(num_cpus: usize) {
    use azos_topology::signed::{SourceAction, SourcePolicy};
    let t0 = azos_drv_sys::timebase::now();
    let policy = SourcePolicy::KCONFIG;
    let action = if policy == SourcePolicy::Builtin {
        SourceAction::Builtin
    } else {
        signed_source(policy, num_cpus)
    };
    match action {
        SourceAction::Signed => {}
        SourceAction::Builtin
        | SourceAction::FallbackMissing
        | SourceAction::FallbackInvalid(_) => install_builtin(),
        SourceAction::HaltMissing | SourceAction::HaltInvalid(_) => halt_without_topology(),
    }
    // The cost of the whole choice, file reads and verification included:
    // under `-icount shift=0` a nanosecond is one instruction.
    let ticks = azos_drv_sys::timebase::now().wrapping_sub(t0);
    kprintln!(
        "[TOPO] Topology installed: {} classes, {} tasks, from the {} in {} ticks ({} ns)",
        azos_topology::get().map(|t| t.classes_len()).unwrap_or(0),
        azos_topology::get().map(|t| t.tasks_len()).unwrap_or(0),
        if action == SourceAction::Signed { "signed files" } else { "built-in topology" },
        ticks, ticks_to_ns(ticks),
    );
    // A signed topology was admitted, with its memory reserved, before it
    // was published (`signed_candidate`). The built-in one is admitted here,
    // the same way, and halts the board if it does not fit.
    if action != SourceAction::Signed {
        if let Some(topo) = azos_topology::get() {
            let _ = admit(topo, num_cpus, Mode::Final);
        }
    }
}

fn install_builtin() {
    if let Err(e) = azos_topology::init_with(azos_topology::fill_default_minimal) {
        azos_drv_sys::kerr!("[TOPO] Topology install FAILED: {:?} — halting", e);
        loop { azos_arch::ARCH.wfi(); }
    }
}

/// Halt the boot hart with no topology installed: nothing the topology admits
/// (no ring-3 row, no kernel task it places) has been created, and nothing is
/// ever created. The `SAFETY_TOPO_SOURCE` record was written before this.
fn halt_without_topology() -> ! {
    azos_drv_sys::kerr!("[TOPO] HALTED: no capability topology installed — the boot stops here");
    loop { azos_arch::ARCH.wfi(); }
}

// ── The signed topology on the volume (Kconfig TOPOLOGY_SOURCE) ─────────────

/// Bytes of the CAPS.TOM buffer (Kconfig `TOPOLOGY_CAPS_MAX_KB`).
const CAPS_MAX: usize = azos_limits::TOPOLOGY_CAPS_MAX_KB * 1024;
/// Bytes of the SCHED.TOM buffer (Kconfig `TOPOLOGY_SCHED_MAX_KB`).
const SCHED_MAX: usize = azos_limits::TOPOLOGY_SCHED_MAX_KB * 1024;
/// A sidecar is 64 bytes; one more so a longer file reads as the wrong length
/// (`VerifyError::BadSignatureLen`), never as a truncated signature.
const SIG_READ: usize = azos_crypto::ed25519::ED25519_SIGNATURE_SIZE + 1;

/// The file texts. They live as long as the kernel: every name and grant
/// target of an installed signed topology borrows from them.
static mut CAPS_BUF: [u8; CAPS_MAX] = [0; CAPS_MAX];
static mut SCHED_BUF: [u8; SCHED_MAX] = [0; SCHED_MAX];
static mut CAPS_SIG_BUF: [u8; SIG_READ] = [0; SIG_READ];

/// One file off the volume.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FileRead {
    /// Not on the volume (or no volume).
    Absent,
    /// This many bytes, all of the file.
    Read(usize),
    /// The file does not fit the buffer.
    TooLarge,
}

/// Read all of `path` into `buf`. Loops, since one read need not return the
/// whole file, and asks for one byte past a full buffer to tell "exactly
/// full" from "larger".
fn read_whole(path: &[u8], buf: &mut [u8]) -> FileRead {
    let mut fds = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fds, path, azos_fs::O_RDONLY);
    if fd < 0 {
        return FileRead::Absent;
    }
    let mut n = 0usize;
    let result = loop {
        if n == buf.len() {
            let mut probe = [0u8; 1];
            let r = azos_fs::vfs_read(&mut fds, fd, probe.as_mut_ptr(), 1);
            break if r > 0 { FileRead::TooLarge } else { FileRead::Read(n) };
        }
        let r = azos_fs::vfs_read(&mut fds, fd, buf[n..].as_mut_ptr(), buf.len() - n);
        if r <= 0 {
            break FileRead::Read(n);
        }
        n += r as usize;
    };
    azos_fs::vfs_close(&mut fds, fd);
    result
}

/// Read, verify, parse and admit the signed set, install it if it passes,
/// and return what the policy does. Prints the outcome with its cost, and
/// writes the `SAFETY_TOPO_SOURCE` record for every outcome but `Signed`.
fn signed_source(
    policy: azos_topology::signed::SourcePolicy,
    num_cpus: usize,
) -> azos_topology::signed::SourceAction {
    use azos_topology::signed::{decide, SourceAction};
    let t0 = azos_drv_sys::timebase::now();
    let device = super::config_auth::read_device_record();
    let floor = read_topo_floor();
    let ctx = azos_topology::signed::DeviceContext::kconfig(device.map(|r| r.device_id), floor);
    let (candidate, caps_len, sched_len, counter) = signed_candidate(num_cpus, &ctx);
    let ticks = azos_drv_sys::timebase::now().wrapping_sub(t0);
    let ns = ticks_to_ns(ticks);
    let action = decide(policy, candidate);
    match action {
        SourceAction::Signed => {
            kprintln!(
                "[TOPO] source: signed /fat/CAPS.TOM ({} B) + /fat/SCHED.TOM ({} B), verified, bound \
                 (counter {}, floor {}), parsed and admitted in {} ticks ({} ns)",
                caps_len, sched_len, counter.unwrap_or(0), floor, ticks, ns,
            );
            if let Some(c) = counter {
                if azos_limits::TOPOLOGY_COUNTER_FLOOR && c > floor {
                    raise_topo_floor(floor, c);
                }
            }
        }
        SourceAction::Builtin => {}
        SourceAction::FallbackMissing => {
            azos_drv_sys::kwarn!("[TOPO] WARNING: no signed topology on the volume (CAPS.TOM/SCHED.TOM and \
                       their .SIG) — the built-in topology is installed ({} ticks, {} ns)", ticks, ns);
            record(azos_actuation::logger::TOPO_ACTION_FALLBACK_MISSING, 0);
        }
        SourceAction::FallbackInvalid(r) => {
            azos_drv_sys::kerr!("[TOPO] REFUSED: the signed topology on the volume: {:?} — the built-in \
                       topology is installed ({} ticks, {} ns)", r, ticks, ns);
            record(azos_actuation::logger::TOPO_ACTION_FALLBACK_INVALID, r.code());
        }
        SourceAction::HaltMissing => {
            azos_drv_sys::kerr!("[TOPO] REFUSED: no signed topology on the volume and \
                       TOPOLOGY_SOURCE_SIGNED_REQUIRED ({} ticks)", ticks);
            record(azos_actuation::logger::TOPO_ACTION_HALT_MISSING, 0);
        }
        SourceAction::HaltInvalid(r) => {
            azos_drv_sys::kerr!("[TOPO] REFUSED: the signed topology on the volume: {:?} — the policy \
                       halts ({} ticks)", r, ticks);
            record(azos_actuation::logger::TOPO_ACTION_HALT_INVALID, r.code());
        }
    }
    action
}

/// Timebase ticks to nanoseconds (`TIMER_FREQ` is per board).
fn ticks_to_ns(ticks: u64) -> u64 {
    (ticks as u128 * 1_000_000_000 / (azos_drv_sys::timebase::TIMER_FREQ as u128).max(1)) as u64
}

/// The durable `SAFETY_TOPO_SOURCE` record. The flight recorder is armed in
/// Phase 6 (`install_flight_recorder`), right after the FAT32 mount.
fn record(action: u8, detail: u32) {
    match azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_TOPO_SOURCE, action, detail,
    ) {
        Ok(n) => kprintln!("[TOPO] SAFETY_TOPO_SOURCE action {} detail {:#010x} recorded ({} record(s) flushed)",
            action, detail, n),
        // No recorder at all (a boot without a FAT volume, where every file
        // is "missing" by construction): a warning, not an error, so a
        // diskless boot does not print an error line on every boot.
        Err(_) if !azos_actuation::logger::logger_active() => azos_drv_sys::kwarn!(
            "[TOPO] SAFETY_TOPO_SOURCE action {} not recorded: no flight recorder (no volume)", action),
        Err(_) => azos_drv_sys::kerr!("[TOPO] SAFETY_TOPO_SOURCE action {} NOT recorded: the flight recorder \
                             is unavailable — this line is the only record", action),
    }
}

/// The topology counter floor (Kconfig `TOPOLOGY_FLOOR_SECTOR`): 0 when the
/// tail is not usable or holds no valid record, as CONFIG.SIG v2 reads an
/// absent device floor.
fn read_topo_floor() -> u64 {
    if !azos_limits::TOPOLOGY_COUNTER_FLOOR || !super::config_auth::tail_writable() {
        return 0;
    }
    let mut sector = [0u8; 512];
    if crate::msc_gadget::reserved_region_read(azos_limits::TOPOLOGY_FLOOR_SECTOR as u32, &mut sector).is_err() {
        return 0;
    }
    azos_topology::device_record::topo_floor_decode(&sector).unwrap_or(0)
}

/// Raise the floor to the counter of the topology just installed, and flush.
/// A failed write leaves the old floor: an older signed topology stays
/// acceptable until a later boot raises it (CONFIG.SIG v2's rule).
fn raise_topo_floor(old: u64, new: u64) {
    let rec = azos_topology::device_record::topo_floor_encode(new);
    let ok = super::config_auth::tail_writable()
        && crate::msc_gadget::reserved_region_write(azos_limits::TOPOLOGY_FLOOR_SECTOR as u32, &rec).is_ok()
        && !matches!(azos_drv_block::blkdev::flush(),
                     Err(e) if e != azos_drv_api::block::FlushError::Unsupported);
    if ok {
        kprintln!("[TOPO] topology counter floor raised {} -> {}", old, new);
    } else {
        azos_drv_sys::kwarn!("[TOPO] WARNING: topology counter floor NOT raised ({} -> {}): the reserved \
                   tail write failed; an older signed topology stays acceptable", old, new);
    }
}

/// What the volume holds, installed into the topology slot if it passes:
/// `(candidate, CAPS.TOM bytes, SCHED.TOM bytes, its counter)`. A SCHED.SIG
/// left on the volume is not read (retired: CAPS.TOM's `sched_sha256` binds
/// SCHED.TOM under CAPS.SIG).
fn signed_candidate(
    num_cpus: usize,
    ctx: &azos_topology::signed::DeviceContext,
) -> (azos_topology::signed::Candidate, usize, usize, Option<u64>) {
    use azos_topology::signed::{Candidate, SignedFile, SignedFiles, SignedRefusal};
    use azos_topology::TryInitError;
    // SAFETY: the boot hart runs this once, before any other task exists;
    // nothing else names these buffers. After this block they are only read.
    let (caps, caps_sig, sched) = unsafe {
        (
            read_whole(azos_topology::CAPS_TOML_PATH, &mut *(&raw mut CAPS_BUF)),
            read_whole(azos_topology::CAPS_SIG_PATH, &mut *(&raw mut CAPS_SIG_BUF)),
            read_whole(azos_topology::SCHED_TOML_PATH, &mut *(&raw mut SCHED_BUF)),
        )
    };
    let reads = [caps, caps_sig, sched];
    let present = reads.iter().enumerate()
        .fold(0u8, |m, (i, r)| if *r == FileRead::Absent { m } else { m | 1 << i });
    let len = |r: FileRead| if let FileRead::Read(n) = r { n } else { 0 };
    let (caps_len, sched_len) = (len(caps), len(sched));
    if present == 0 {
        return (Candidate::Absent, 0, 0, None);
    }
    if present != 0b111 {
        return (Candidate::Refused(SignedRefusal::Incomplete { present }), caps_len, sched_len, None);
    }
    if caps == FileRead::TooLarge {
        return (Candidate::Refused(SignedRefusal::TooLarge(SignedFile::Caps)), 0, sched_len, None);
    }
    if sched == FileRead::TooLarge {
        return (Candidate::Refused(SignedRefusal::TooLarge(SignedFile::Sched)), caps_len, 0, None);
    }
    // A sidecar longer than SIG_READ was read as SIG_READ bytes and fails
    // the 64-byte length check in `verify_signature`.
    let sig_len = |r: FileRead| if let FileRead::Read(n) = r { n } else { SIG_READ };
    // SAFETY: as above; the reads are done and these are never written again.
    let files: SignedFiles<'static> = unsafe {
        SignedFiles {
            caps: &(&*(&raw const CAPS_BUF))[..caps_len],
            caps_sig: &(&*(&raw const CAPS_SIG_BUF))[..sig_len(caps_sig)],
            sched: &(&*(&raw const SCHED_BUF))[..sched_len],
        }
    };
    let mut counter = None;
    let outcome = azos_topology::try_init_with(
        |t| {
            counter = azos_topology::signed::fill_signed(t, &files, &azos_topology::TRUSTED_PUBKEY, ctx)?;
            Ok(())
        },
        |t| admit(t, num_cpus, Mode::Candidate),
    );
    let candidate = match outcome {
        Ok(()) => Candidate::Valid,
        Err(TryInitError::Fill(r)) | Err(TryInitError::Check(r)) => Candidate::Refused(r),
        Err(TryInitError::Admission(e)) => Candidate::Refused(SignedRefusal::Admission(e)),
        Err(TryInitError::AlreadyInit) => {
            azos_drv_sys::kerr!("[TOPO] Topology install FAILED: the slot was already taken — halting");
            loop { azos_arch::ARCH.wfi(); }
        }
    };
    (candidate, caps_len, sched_len, counter)
}

/// Who [`admit`] answers to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A signed candidate: a refusal is returned, and the built-in topology
    /// is still there to fall back to.
    Candidate,
    /// The topology that will run: a refusal halts the board.
    Final,
}

/// The boot admission of one topology, the signed candidate's or the
/// built-in one's, in one place:
/// 1. deadlines on this board's CPUs, and the real-time band cap;
/// 2. huge-leaf rows against Kconfig `LOCKED_HUGE_LEAVES`;
/// 3. the DMA pool reserved, then every ring-3 row's frame budget checked
///    against the RAM left (`Topology::memory_admission`);
/// 4. each 2 MiB-leaf region reserved, which admission has just counted.
///
/// The memory is reserved, not estimated, so what is admitted is what the
/// allocator really gave: a pool or a region that has the frames but no
/// contiguous (or aligned) run for them is refused here, before a signed
/// topology is published, instead of halting the board after it. On a
/// refusal everything this call reserved is released, so the fallback
/// starts from the same RAM. Booting a topology whose budgets cannot all be
/// honoured would turn a declared guarantee into a race for the last frames.
fn admit(
    topo: &azos_topology::Topology<'static>,
    num_cpus: usize,
    mode: Mode,
) -> Result<(), azos_topology::signed::SignedRefusal> {
    use azos_topology::signed::SignedRefusal;
    use azos_topology::{AdmissionError, MemoryRefusal};

    // 1. Deadlines and the band.
    use azos_decision::{record, Rule, Verdict};
    let rows = topo.tasks().len() as u64;
    let r = match topo.deadline_admission(num_cpus) {
        Ok(r) => r,
        Err(e) => {
            record(Rule::DeadlineAdmission, Verdict::Refuse, num_cpus as u32, [0, rows, 0]);
            if mode == Mode::Final {
                halt_refused(format_args!("[TOPO] Deadline admission REFUSED on {} CPU(s): {:?}", num_cpus, e));
            }
            return Err(SignedRefusal::Admission(e));
        }
    };
    record(Rule::DeadlineAdmission, Verdict::Admit, num_cpus as u32, [r.placed as u64, rows, 0]);
    if r.placed > 0 {
        kprintln!("[TOPO] Deadline admission: {} real-time task(s) placed on {} CPU(s)", r.placed, num_cpus);
        let band = band_check(topo, &r);
        let v = if band.is_ok() { Verdict::Admit } else { Verdict::Refuse };
        record(Rule::RtBandCap, v, num_cpus as u32, [r.placed as u64, azos_limits::RT_BAND_CAP_PCT as u64, 0]);
        if let Err(e) = band {
            if mode == Mode::Final {
                halt_refused(format_args!("[TOPO] Deadline admission REFUSED: {:?} — the band's rows on that CPU exceed \
                     RT_BAND_CAP_PCT={} %", e, azos_limits::RT_BAND_CAP_PCT));
            }
            return Err(SignedRefusal::Admission(AdmissionError::Deadline(e)));
        }
    }

    // 2. A row that asks for a 2 MiB-leaf region on a kernel built without
    // the option is refused, not run without the region it was written for.
    if !azos_limits::LOCKED_HUGE_LEAVES {
        if let Some((i, t)) = topo.tasks().iter().enumerate().find(|(_, t)| t.mem_huge_mib != 0) {
            if mode == Mode::Final {
                halt_refused(format_args!("[TOPO] Memory admission REFUSED: row {} ({}) declares mem_huge_mib = {} but this \
                     kernel was built without LOCKED_HUGE_LEAVES", i, t.name.as_str(), t.mem_huge_mib));
            }
            return Err(SignedRefusal::HugeLeaves);
        }
    }

    // 3. The DMA pool, then the rows' budgets against what is left. Below,
    // sizes are topology pages (4 KiB, `TOPOLOGY_PAGE`); the allocator counts
    // frames of PAGE_SIZE. The conversions keep a signed topology meaning the
    // same bytes under an aarch64 16/64 KiB granule.
    let page = azos_arch_api::PAGE_SIZE as u64;
    let floor = dma_floor_pages();
    let pool = topo.dma_pool_pages(floor);
    // Held to the end of this call: the frames go back when it returns.
    #[cfg(feature = "dma-contig-canary")]
    let _frag = dma_contig_canary::fragment(azos_topology::frames_for(pool, page) as usize);
    let free_before = azos_topology::units_for(azos_mm::pmm::free_pages() as u64, page);
    match azos_mm::pmm::reserve_dma_pool(azos_topology::frames_for(pool, page) as usize) {
        Ok(base) => kprintln!(
            "[MM] DMA pool: {} KiB reserved at {:#x} (floor {} KiB, {} pipeline(s) declare {} KiB)",
            pool * 4, base.as_usize(), floor * 4, topo.pipelines().len(),
            topo.pipelines().iter().map(|p| p.dma_pages as u64 * 4).sum::<u64>(),
        ),
        Err(_) => {
            let e = MemoryRefusal::DmaPool { need: pool, free: free_before };
            record(Rule::MemoryAdmission, Verdict::Refuse, rows as u32, [pool, free_before, 0]);
            if mode == Mode::Final {
                halt_refused(format_args!("[TOPO] Memory admission REFUSED: {:?}", e));
            }
            return Err(SignedRefusal::Admission(AdmissionError::Memory(e)));
        }
    }
    let reserve = kernel_reserve_pages();
    let free = azos_topology::units_for(azos_mm::pmm::free_pages() as u64, page);
    match topo.memory_admission(free, reserve, azos_topology::RING3_DEFAULT_PAGES, &may_fork) {
        Ok(m) => {
            record(Rule::MemoryAdmission, Verdict::Admit, m.rows as u32, [m.need as u64, m.free as u64, m.reserve_pages as u64]);
            kprintln!(
                "[TOPO] Memory admission: {} ring-3 row(s) ({} locked, {} forking), {} instance(s): {} locked + {} ceiling + {} COW copy + {} kernel reserve = {} of {} free pages",
                m.rows, m.locked_rows, m.fork_rows, m.instances, m.locked_pages, m.ceiling_pages, m.cow_pages, m.reserve_pages, m.need, m.free,
            )
        }
        Err(e) => {
            let need = match e {
                AdmissionError::Memory(MemoryRefusal::Overcommit { need, .. }) => need,
                _ => 0,
            };
            record(Rule::MemoryAdmission, Verdict::Refuse, rows as u32, [need, free, reserve as u64]);
            if mode == Mode::Final {
                halt_refused(format_args!("[TOPO] Memory admission REFUSED: {:?}", e));
            }
            azos_mm::pmm::release_dma_pool();
            return Err(SignedRefusal::Admission(e));
        }
    }

    // 4. The 2 MiB-leaf regions, each one physically contiguous and 2 MiB
    // aligned (`azos_mm::huge`); exec maps them with 2 MiB leaves.
    if azos_limits::LOCKED_HUGE_LEAVES {
        for (i, t) in topo.tasks().iter().enumerate() {
            if t.mem_huge_mib == 0 {
                continue;
            }
            let bytes = t.mem_huge_mib as usize * 1024 * 1024;
            match azos_mm::huge::reserve((i + 1) as u16, bytes) {
                Ok(pa) => kprintln!(
                    "[MM] huge region: row {} ({}) {} MiB reserved at pa {:#x}, mapped with 2 MiB leaves at exec",
                    i, t.name.as_str(), t.mem_huge_mib, pa,
                ),
                Err(err) => {
                    if mode == Mode::Final {
                        halt_refused(format_args!("[TOPO] Memory admission REFUSED: row {} ({}) huge region of {} MiB: {:?}",
                            i, t.name.as_str(), t.mem_huge_mib, err));
                    }
                    azos_mm::huge::release_all();
                    azos_mm::pmm::release_dma_pool();
                    return Err(SignedRefusal::Admission(AdmissionError::Memory(
                        MemoryRefusal::HugeRegion { task: i as u16, mib: t.mem_huge_mib })));
                }
            }
        }
    }
    Ok(())
}

/// Kernel feature `dma-contig-canary` (gate rows "topology: DMA pool needs a
/// run"): the boot's first [`admit`] reserves its DMA pool with one free frame
/// in every `pool` taken, so no free run is as long as the pool while the
/// free total still covers the pool and every row's budget; the frames go
/// back when that admission returns. An admission that reserves the pool
/// refuses it (`DmaPool`); one that compared the pool with the free total
/// would admit it.
#[cfg(feature = "dma-contig-canary")]
mod dma_contig_canary {
    use crate::kprintln;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const WORDS: usize = azos_limits::RAM_SIZE * 1024 * 1024 / azos_arch_api::PAGE_SIZE / 64 + 1;
    /// The frames taken, by `pmm::frame_index`.
    static TAKEN: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
    static DONE: AtomicBool = AtomicBool::new(false);

    /// Frames taken until dropped; `base` is the physical address of frame 0.
    pub(super) struct Fragmented {
        base: usize,
    }

    /// Take one free frame in every `pool` (at least every other one), on
    /// the first call of the boot only.
    pub(super) fn fragment(pool: usize) -> Option<Fragmented> {
        if DONE.swap(true, Ordering::AcqRel) {
            return None;
        }
        let page = azos_arch_api::PAGE_SIZE;
        let before = azos_mm::pmm::free_pages();
        let mut pa = azos_mm::pmm::next_free_addr();
        let first = azos_mm::pmm::frame_index(pa)?;
        let base = pa - first * page;
        let stride = pool.max(2);
        let mut taken = 0usize;
        while let Some(i) = azos_mm::pmm::frame_index(pa) {
            if i % stride == stride - 1 && azos_mm::pmm::range_is_free(pa, page) {
                azos_mm::pmm::reserve_range(pa, page);
                TAKEN[i / 64].fetch_or(1 << (i % 64), Ordering::Relaxed);
                taken += 1;
            }
            pa += page;
        }
        kprintln!(
            "[CANARY] dma-contig: {} of {} free frames taken, one in every {}: {} free, no free run of {}",
            taken, before, stride, azos_mm::pmm::free_pages(), stride,
        );
        Some(Fragmented { base })
    }

    impl Drop for Fragmented {
        fn drop(&mut self) {
            let page = azos_arch_api::PAGE_SIZE;
            let mut back = 0usize;
            for (w, word) in TAKEN.iter().enumerate() {
                let mut bits = word.swap(0, Ordering::Relaxed);
                while bits != 0 {
                    let i = w * 64 + bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(self.base + i * page));
                    back += 1;
                }
            }
            kprintln!("[CANARY] dma-contig: {} frames given back, {} free", back, azos_mm::pmm::free_pages());
        }
    }
}

/// A refusal of the topology that will run: the board stops here.
fn halt_refused(what: core::fmt::Arguments<'_>) -> ! {
    azos_drv_sys::kerr!("{} — halting", what);
    loop { azos_arch::ARCH.wfi(); }
}

/// The band condition of [`admit`].
fn band_check(
    topo: &azos_topology::Topology<'static>,
    r: &azos_topology::deadline::Report,
) -> Result<(), azos_topology::DeadlineRefusal> {
    let tasks = topo.tasks();
    let in_band = |ti: u16| {
        let Some(t) = tasks.get(ti as usize) else { return false };
        let Some(c) = topo.find_class(&t.class_name) else { return false };
        let (lo, hi) = c.priority_range;
        (t.priority.clamp(lo, hi.max(lo)) as u32) < azos_sched::RT_PRIORITY_THRESHOLD
    };
    let density = |ti: u16| tasks.get(ti as usize)
        .and_then(|t| azos_topology::deadline::profile_density(&t.profile))
        .unwrap_or(u32::MAX);
    let limit = (azos_limits::RT_BAND_CAP_PCT as u32).saturating_mul(10_000);
    r.band_check(in_band, density, limit)
}

/// `DMA_POOL_FLOOR_KB` in topology pages.
fn dma_floor_pages() -> u64 {
    (azos_limits::DMA_POOL_FLOOR_KB as u64).div_ceil(4)
}

/// The kernel reserve of memory admission, in topology pages: Kconfig
/// `MEM_KERNEL_RESERVE_KB` plus one vDSO page per task slot.
fn kernel_reserve_pages() -> u64 {
    (azos_limits::MEM_KERNEL_RESERVE_KB as u64).div_ceil(4)
        + azos_topology::units_for(azos_limits::MAX_TASKS as u64, azos_arch_api::PAGE_SIZE as u64)
}

/// Wave 9: only a row whose image can fork pays for a COW copy. The image's
/// seccomp profile decides (`seccomp::profile_can_fork`); the generic
/// `autorun` row and a row naming no shipped image are assumed to fork, since
/// any image may run under them.
fn may_fork(t: &azos_topology::TaskSpec<'_>) -> bool {
    let name = t.name.as_bytes();
    if name == azos_topology::AUTORUN_ROW {
        return true;
    }
    azos_sched::seccomp::profile_named(name)
        .map_or(true, azos_sched::seccomp::profile_can_fork)
}

/// `mem_start + mem_size` for display and for the W^X "outside the image"
/// sweep range — both ISAs' `kernel_main` compute this from `mem_size`
/// straight off a DTB `/memory` node, several times each (the "RAM
/// detected"/"RAM fallback" `kprintln!` arms, then again once each for the
/// two `strip_exec_outside_image`/`verify_no_exec_outside_image` calls).
/// A hostile `mem_size` (e.g. `usize::MAX`) can carry that raw addition
/// past `usize::MAX`; under this kernel's release profile
/// (`overflow-checks = true`, `panic = "abort"`) an unchecked `+` there is
/// an immediate, undiagnosed board reset — the same failure class DTB
/// audit closed on the parser side and `pmm::init` now refuses on the
/// `mem_start > kernel_end` side. Saturating instead of refusing here:
/// unlike `pmm::init`'s range, this one only feeds a log line and the W^X
/// sweep's upper bound, and `azos_mm::pmm::init` (called first, on
/// every path to this) is what already refuses to boot on a `mem_start`
/// it cannot trust — this helper just keeps the arithmetic that runs
/// after that decision from resetting the board on its own account.
#[inline]
pub(crate) fn mem_range_end(mem_start: usize, mem_size: usize) -> usize {
    mem_start.saturating_add(mem_size)
}
