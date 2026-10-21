// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Autorun and the ELF loader: `autorun_task` and `load_and_exec_image`.

use super::loader_admit::{admit, Refusal};
use crate::*;

/// Phase U4: autorun task — loads and exec's an ELF from the filesystem.
///
/// The ELF path is stored in the static `AUTORUN_PATH` buffer (set during boot).
/// `arg` contains the path length.
///
/// **Shared with aarch64 (Phase 6), not a second copy.** Every call this
/// body makes — `azos_fs::vfs_*`, `azos_sched::seccomp::*`,
/// `azos_sched::exec_user`/`take_current_task_exec_ctx`,
/// `azos_sched::sret_to_user` — is already ISA-portable (the loader in
/// `crates/core/sched::process` and the vmm it calls take no RISC-V-only path;
/// `sret_to_user` itself is `#[cfg]`'d per ISA inside that crate). This
/// function used to be `#[cfg(target_arch = "riscv64")]`; removing that
/// gate is the whole change needed to make aarch64's `kernel_main` able to
/// call it too.
pub(crate) fn autorun_task(arg: usize) {
    let path_len = arg;
    let path = unsafe { &*(&raw const AUTORUN_PATH) };
    load_and_exec_image(&path[..path_len]);
}

/// The autorun loader's priority, and its hart at boot. Every successor the M4
/// supervisor creates (`drv_supervisor`) loads at this priority, on the hart
/// the driver it replaces was pinned to.
pub(crate) const AUTORUN_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
pub(crate) const AUTORUN_HART: i8 = 3;

/// `SAFETY_EXEC_REFUSED`'s `action_code` for an image the loader could not stage:
/// it needs more frames than the budget of the row that bounds it, than the allocator
/// forms in one run, or than are free. `detail` is the frames it needed.
const REFUSED_ACTION_IMAGE_ROOM: u8 = 7;

/// The staging buffer of one image: a run of frames of exactly the file's
/// size, given back on drop. There is no buffer of the loader's own: each load
/// takes what its image needs, so two loads at once (the boot's autorun task
/// and a supervisor successor) never wait for one another.
///
/// The run is NOT charged to a Domain. The loading task is a kernel task whose
/// Domain carries no limit until `exec_commit` installs the program's (so a
/// charge here could never refuse), and a charge would raise the Domain's high-water
/// mark and the census peak (`mm_peak_global`) the budget rows are sized from
/// with frames that are gone before the program runs. The bound is
/// [`admit`] against the row's budget ([`staging_limit`]), checked before a
/// frame is taken; the frames themselves are taken from the free pool for the time
/// between the read and the copy, and a pool that lacks them refuses the load
/// ([`Refusal::NoFrames`]).
struct Staging {
    /// Physical address of the first frame.
    base: usize,
    frames: usize,
}

impl Staging {
    /// `None` when no physically contiguous run of that length is free.
    fn take(frames: u32) -> Option<Staging> {
        azos_mm::pmm::alloc_contiguous(frames as usize)
            .ok()
            .map(|pa| Staging { base: pa.as_usize(), frames: frames as usize })
    }

    /// The first `len` bytes of the run (`len` is at most the run's length).
    fn bytes(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= self.frames << PAGE_SHIFT);
        // SAFETY: the frames are this value's alone (`alloc_contiguous` handed
        // them out zeroed and nothing else names them), reached through the
        // kernel's linear map, and `len` bytes lie inside the run.
        unsafe { core::slice::from_raw_parts_mut(azos_mm::addr::phys_to_virt(self.base) as *mut u8, len) }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        for i in 0..self.frames {
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(self.base + (i << PAGE_SHIFT)));
        }
    }
}

const PAGE_SHIFT: usize = azos_limits::PAGE_SHIFT as usize;

/// The frame budget that bounds the staging of `path`: the row
/// named after the file, else the generic `autorun` row (the order the image's
/// own row is looked up in once it is identified by its digest, which needs
/// the bytes). A renamed file is bounded by its name's row, not its own; the
/// exec that follows checks the image against the row its digest names. 0 =
/// none (no topology installed yet).
fn staging_limit(path: &[u8]) -> u32 {
    let Some(topo) = azos_topology::get() else { return 0 };
    let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
    let units = topo
        .row_mem(name, Some(azos_topology::AUTORUN_ROW), azos_topology::RING3_DEFAULT_PAGES)
        .map_or(azos_topology::RING3_DEFAULT_PAGES, |m| m.limit);
    azos_topology::frames_for(units as u64, 1 << PAGE_SHIFT).min(u32::MAX as u64) as u32
}

/// Say, and record durably, that an image was not staged: a robot whose
/// program did not start is likely to be power-cycled next, so the receipt
/// is written at once (`SAFETY_EXEC_REFUSED`, action [`REFUSED_ACTION_IMAGE_ROOM`],
/// the frames it needed). An empty file is an error to read, not a refusal.
fn refuse_image_room(path: &str, size: u64, why: Refusal) {
    match why {
        Refusal::Empty => {
            azos_drv_sys::kerr!("[AUTORUN] {} is empty or not a regular file", path);
            return;
        }
        Refusal::OverBudget { frames, limit } => azos_drv_sys::kwarn!(
            "[AUTORUN] REFUSED: {} ({} bytes) needs {} frames, its row's budget is {}",
            path, size, frames, limit),
        Refusal::TooLarge { frames, max_run } => azos_drv_sys::kwarn!(
            "[AUTORUN] REFUSED: {} ({} bytes) needs {} frames, the allocator forms runs of {} at most",
            path, size, frames, max_run),
        Refusal::NoFrames { frames } => azos_drv_sys::kwarn!(
            "[AUTORUN] REFUSED: {} ({} bytes): no run of {} free frames", path, size, frames),
    }
    let _ = azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_EXEC_REFUSED, REFUSED_ACTION_IMAGE_ROOM, why.frames());
}

/// Load the ELF at `path_slice` from the filesystem, bind it to its seccomp
/// profile by digest, grant its topology capabilities, exec it on THIS task
/// and enter ring 3. Returns only if the program could not be started; the
/// task then exits.
///
/// The body of the autorun task, and of every successor the
/// supervisor creates for a supervised driver: a restart re-reads and
/// re-hashes the image and applies exactly the policy the first start did.
pub(crate) fn load_and_exec_image(path_slice: &[u8]) {
    // Q1.4 (owner decision, 2026-09-25): defense-in-depth beside gate_speed's
    // own fail-closed default -- no ring-3 program starts until the actuation
    // gate is installed, so an ordering bug stops motors instead of moving them.
    if !azos_actuation::gate::gate_installed() {
        azos_drv_sys::kwarn!("[AUTORUN] REFUSED: actuation gate is not installed -- \
                   refusing to start any ring-3 program");
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_ACTUATION_GATE_ABSENT, 0, 0);
        return;
    }
    // Safe mode (owner decision 2026-09-28): no ring-3 program runs.
    if azos_actuation::estop::safe_mode_active() {
        azos_drv_sys::kwarn!("[AUTORUN] REFUSED: safe mode -- {} not started",
            core::str::from_utf8(path_slice).unwrap_or("?"));
        return;
    }

    kprintln!("[AUTORUN] Loading ELF: {}",
        core::str::from_utf8(path_slice).unwrap_or("?"));

    // Size the image first and stage it in a buffer of exactly that size
    // (`Staging`); refused, with a receipt, when it does not fit the budget of
    // the row that bounds it (`staging_limit`). The size is only a plan: the read below must return
    // exactly that many bytes and then end.
    let shown = core::str::from_utf8(path_slice).unwrap_or("?");
    let Some(st) = azos_fs::vfs_stat(path_slice) else {
        kprintln!("[AUTORUN] File not found: {}", shown);
        return;
    };
    let size = if st.is_dir { 0 } else { st.size };
    let max_run = 1u32 << azos_limits::PMM_MAX_ORDER.min(31);
    let frames = match admit(size, 1 << PAGE_SHIFT, staging_limit(path_slice), max_run) {
        Ok(frames) => frames,
        Err(why) => return refuse_image_room(shown, size, why),
    };
    let Some(mut staging) = Staging::take(frames) else {
        return refuse_image_room(shown, size, Refusal::NoFrames { frames });
    };
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path_slice, azos_fs::O_RDONLY);
    if fd < 0 {
        kprintln!("[AUTORUN] File not found: {}", shown);
        return;
    }
    let want = size as usize;
    let buf = staging.bytes(want);
    let mut n = 0usize;
    while n < want {
        let r = azos_fs::vfs_read(&mut fd_table, fd, buf[n..].as_mut_ptr(), want - n);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    // One byte past the planned size: a file that grew since the stat is not
    // the image that was sized (and a prefix of it must not be hashed).
    let mut probe = 0u8;
    let grew = azos_fs::vfs_read(&mut fd_table, fd, &mut probe, 1) > 0;
    azos_fs::vfs_close(&mut fd_table, fd);
    if n != want || grew {
        azos_drv_sys::kwarn!("[AUTORUN] REFUSED: {} changed while it was read ({} of {} bytes planned{})",
            shown, n, want, if grew { ", and more follows" } else { "" });
        return;
    }
    let buf = &*buf;

    // Bind the program to its seccomp profile by the BYTES read, before it is
    // granted anything. `image_for_digest` compares the SHA-256 of `buf[..n]`
    // with the digests the build generated from the exact ELFs it copies onto
    // the image (`azos_sched::seccomp`, `$AZOS_OUT/build/image_hashes.rs`). The slice
    // hashed is the slice `exec_user` loads below, from this load's own staging
    // buffer, so what was checked is what runs. An image no profile is bound
    // to (replaced, rebuilt after the kernel, never profiled) is not exec'd and
    // is granted no capability, whatever name it was opened under.
    let digest = azos_sched::seccomp::image_digest(&buf[..n]);
    let Some(profile) = azos_sched::seccomp::image_for_digest(&digest) else {
        let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        azos_drv_sys::kwarn!("[AUTORUN] REFUSED: {} ({} bytes, sha256 {:08x}{:08x}...) matches no seccomp image profile",
            core::str::from_utf8(path_slice).unwrap_or("?"), n, head,
            u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]));
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_EXEC_REFUSED, 0, head);
        #[cfg(feature = "cap-deny-smoke")]
        exec_refusal_readback(head);
        return;
    };
    kprintln!("[AUTORUN] {} ({} bytes) is {} by its SHA-256",
        core::str::from_utf8(path_slice).unwrap_or("?"), n, profile.image);
    // DICE-ID: the digest just matched is the measurement of this Domain's
    // image; the `linkkey` endpoint derives the node's identity from it.
    if let Some(idx) = azos_sched::idx_for_tid(azos_sched::current_task_tid()) {
        azos_sched::domain::set_measurement(azos_sched::task_domain(idx), digest);
    }

    // Note which image this task is, so that if it registers a
    // driver-server kind the supervisor can re-create it from the same path.
    // A successor the supervisor created is already on its entry.
    // Its topology row's `restart` key (wave 11) applies from here on.
    if let Some(slot) = azos_sched::supervisor::sup_note_spawn(
        azos_sched::current_task_tid(), path_slice)
    {
        let _ = azos_sched::supervisor::sup_set_restart(
            slot, drv_supervisor::row_restart(path_slice));
    }

    // Provision the capabilities the process will need BEFORE it runs: the
    // topology's declarative "autorun" task (`azos_topology::default_minimal`)
    // minted into this task's capability table.
    //
    // Every hardware syscall checks the caller's capability table: the typed
    // calls resolve a handle, the untyped ones ask `cap_check`. Before ring 3
    // was granted anything, every `sensor_read`/`motor_speed` from ring 3
    // returned E_PERM, and reflex and brain_client could be started and still
    // do nothing: reflex treats a failed range read as "no obstacle"
    // (`range_front > 0` guards the comparison), so a blind daemon and a daemon
    // on a clear road produce byte-identical output.
    //
    // This is the only seed. A second one, into the global handle table, stood
    // here once: ten sensor types READ, motors 0 and 1
    // READ|WRITE and the GPIO driver registry READ|WRITE. The topology declares
    // each of those with the same permissions (`crates/core/topology/src/builder.rs`),
    // and no capability decision reads the handle table any more.
    //
    // The TID does not change across `exec_user` — the autorun kernel task
    // becomes the user process — so granting here is granting to the process
    // that is about to run. See `crates/core/ipc/src/cap_seed.rs` for the bridge and
    // its ordering contract (this call happens from inside the already-running
    // autorun task, i.e. strictly after its own pool slot was claimed, which is
    // exactly the property that contract requires).
    {
        let tid = azos_sched::current_task_tid();
        let mut minted = 0u32;
        let mut skipped = 0u32;
        // Wave 13 (NATFORK): a fork child of this task is seeded from the same row.
        azos_syscall::natfork::record_row_named(tid, b"autorun");
        match azos_topology::get() {
            Some(topo) => match topo.find_task(&azos_topology::MaybeStr::from_bytes(b"autorun")) {
                Some(task) => {
                    // The frame budget is no longer read here: the exec
                    // takes it from the IMAGE's row first, like the class
                    // and priority, and installs it with the exec below
                    // (`azos_sched::exec_user_mem`).
                    //
                    // The same row decides whether this task may start an
                    // io_ring SQ poller (off unless it declares an idle time).
                    if task.sqpoll_idle_ms != 0 {
                        let ok = azos_ipc::io_ring::io_ring_permit_sqpoll(tid, task.sqpoll_idle_ms);
                        kprintln!("[AUTORUN][SQPOLL] tid={} may start io_ring SQ pollers, idle {} ms{}",
                            tid, task.sqpoll_idle_ms, if ok { "" } else { " (REFUSED: permit table full)" });
                    }
                    for cap in topo.caps_of(task) {
                        let target = cap.target.as_str();
                        // A kernel-hosted endpoint (the brain-link PSK, the
                        // entropy pool, ...) goes only to an image whose seccomp
                        // row LISTS its interface. The topology names the
                        // `autorun` ROW, not an image, so without this the key
                        // would go to whichever blessed image CONFIG.INI names
                        // -- and the audit-mode rows (CAPTEST.ELF, ABITEST.ELF)
                        // let an unlisted call through, so for them holding the
                        // capability would be enough.
                        if azos_syscall::spawn::withheld_by_profile(cap, profile) {
                            skipped += 1;
                            azos_drv_sys::kwarn!(
                                "[AUTORUN][CAP-SEED] WITHHELD kind={:?} target={} tid={} \
                                 — {}'s seccomp row does not list its interface",
                                cap.kind, target, tid, profile.image,
                            );
                            continue;
                        }
                        use azos_ipc::cap_seed::SeedOutcome;
                        match azos_ipc::cap_seed::seed_one_cap_ops(
                            tid, cap.kind,
    // O3.4 (2026-09-26): topology grants carry `transfer = true` to be giftable.
    cap.grant_perms(),
    target,
    cap.ops,
                        ) {
                            SeedOutcome::Minted(handle) => {
                                minted += 1;
                                kprintln!(
                                    "[AUTORUN][CAP-SEED] minted kind={:?} target={} perms={:?} \
                                     tid={} handle={:#010x}",
                                    cap.kind, target, cap.perms, tid, handle.as_raw(),
                                );
                            }
                            // The kind HAS a minter and it refused: the program is
                            // about to run WITHOUT a capability the signed topology
                            // says it has. Recorded, not just printed — a console
                            // line is gone by the time anyone asks why an actuation
                            // was denied, and this used to be reported under the
                            // "no typed minter" wording, which was false.
                            SeedOutcome::Refused => {
                                skipped += 1;
                                let _ = azos_actuation::logger::log_safety_violation_durable(
                                    azos_actuation::logger::SAFETY_CAP_SEED_REFUSED,
                                    // action_code names the SITE, as
                                    // `SAFETY_EXEC_REFUSED` does: 0 = autorun.
                                    0,
                                    cap.kind as u32,
                                );
                                azos_drv_sys::kwarn!(
                                    "[AUTORUN][CAP-SEED] REFUSED kind={:?} target={} perms={:?} \
                                     tid={} — runs without a capability its topology declares",
                                    cap.kind, target, cap.perms, tid,
                                );
                            }
                            SeedOutcome::NoMinter => {
                                skipped += 1;
                                kprintln!(
                                    "[AUTORUN][CAP-SEED] skipped kind={:?} target={} \
                                     (no typed minter yet)",
                                    cap.kind, target,
                                );
                            }
                        }
                    }
                }
                None => kprintln!("[AUTORUN][CAP-SEED] no 'autorun' task in topology — nothing minted"),
            },
            None => kprintln!("[AUTORUN][CAP-SEED] topology not installed — nothing minted"),
        }
        // The console every task is admitted with.
        match azos_ipc::cap_seed::seed_console(tid) {
            Some(_) => minted += 1,
            None => {
                skipped += 1;
                azos_drv_sys::kwarn!("[AUTORUN][CAP-SEED] REFUSED the console for tid {}", tid);
            }
        }
        kprintln!(
            "[AUTORUN] Typed caps minted via topology bridge: {} (skipped {}) for tid {}",
            minted, skipped, tid,
        );
    }

    // cap-deny-smoke: read the audit record back off the flight recorder when
    // this image runs in audit mode. Spawned here, while this is still a
    // kernel task; the probe waits for the program to issue its unlisted call.
    #[cfg(feature = "cap-deny-smoke")]
    {
        // The one call each audit-mode image issues outside its row
        // (`tests/host/seccomp-tests`, `AUDITED_PROBES`): the probe counts only a
        // record carrying that number.
        let expected: usize = match profile.image {
            "CAPTEST.ELF" => 116,
            "ABITEST.ELF" => 999,
            _ => 0,
        };
        if profile.audit {
            azos_sched::task_create(
                "seccomp-audit-smoke", seccomp_audit_smoke_task, expected,
                azos_sched::DEFAULT_PRIORITY,
            );
        }
    }

    // The program's frame budget, from the row named after its
    // IMAGE, else the generic `autorun` row (the order the class and priority
    // use). It covers everything the task holds: the image, stack and page
    // tables `exec_user_mem` charges below, and every heap, anonymous, demand,
    // shm and io_ring page after. A `mem = "locked"` row is a reservation and
    // takes fork and demand paging away; an image whose profile could do
    // either is refused under one (P2).
    let (mem, mem_row) = azos_syscall::topo_sched::resolve_mem(profile.image, Some("autorun"));
    if !azos_syscall::topo_sched::mem_row_admissible(mem, profile) {
        azos_drv_sys::kwarn!("[AUTORUN][MEM] REFUSED: {} runs under the locked row {} but its seccomp \
                   profile can fork or demand-page -- not exec'd",
            profile.image, mem_row);
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_EXEC_REFUSED, 0, 0);
        return;
    }
    kprintln!("[AUTORUN][MEM] tid={} {} row={} budget={} pages ({} KiB){}",
        azos_sched::current_task_tid(), profile.image, mem_row, mem.limit, mem.limit * 4,
        if mem.locked { " LOCKED" } else { "" });

    kprintln!("[AUTORUN] Read {} bytes, exec'ing...", n);
    let Some(prepared) = azos_sched::process::exec_prepare_mem(&buf[..n], Some(mem)) else {
        azos_drv_sys::kerr!("[AUTORUN] exec_user failed");
        return;
    };
    // The image is copied into its own address space: the staging frames go
    // back before the switch, so the program never runs beside a second copy
    // of itself.
    drop(staging);
    azos_sched::process::exec_commit(prepared);
    // Wave 13 (orphans): the autorun image is init, the reaper of last resort
    // for a user task's orphaned children. Both ISAs pass here (aarch64
    // consumes the exec hand-off in its trap path, not below). A supervised
    // successor runs this body too and takes the role over.
    azos_sched::scheduler::set_init_tid(azos_sched::current_task_tid());
    kprintln!("[AUTORUN] tid={} is init (reaper of last resort)", azos_sched::current_task_tid());
    {
        // What the new address space already costs its budget
        // (image + stack + page tables), before the program runs a single
        // instruction.
        let (used, limit) = azos_sched::current_user_pages();
        kprintln!("[AUTORUN][MEM] exec charged {} pages (image+stack+tables) of {}", used, limit);
    }
    // Confine the program before its first instruction, with the profile its
    // bytes are bound to (checked above, before the grants). After a successful
    // `exec_user`, so a failed one leaves nothing behind; before the SRET
    // below. The filter is on this task's slot, which `exec_user` keeps, and
    // every child the program forks copies it.
    // An audit-mode profile enforces nothing, and a filter already in force
    // is not this image's: both are warnings. tools/vsbench_compare.sh reads
    // their absence on a warn-level kernel as "ran under its own profile".
    match azos_sched::seccomp::install_image_profile(profile) {
        0 if profile.audit => azos_drv_sys::kwarn!("[AUTORUN] seccomp: {} runs under the {} profile (audit mode)",
            core::str::from_utf8(path_slice).unwrap_or("?"), profile.image),
        0 => kprintln!("[AUTORUN] seccomp: {} runs under the {} profile",
            core::str::from_utf8(path_slice).unwrap_or("?"), profile.image),
        other => azos_drv_sys::kwarn!("[AUTORUN] seccomp: a filter was already in force (rc={}); kept",
            other),
    }
    // Wave 7 — the program's scheduling class and priority, from the signed
    // topology: the row named after its IMAGE (the key `SYS_SPAWN_EX` uses), else
    // the generic `autorun` row. Until wave 7 nothing read either: every
    // autorun program ran at `AUTORUN_PRIORITY` whatever its row declared.
    // After `exec_user` like the filter, so a failed exec changes nothing; the
    // loader itself ran at `AUTORUN_PRIORITY` up to here.
    {
        use azos_syscall::topo_sched::{self, TopoSched};
        let tid = azos_sched::current_task_tid();
        match topo_sched::resolve_image(profile.image, Some("autorun")) {
            (TopoSched::Apply { priority, class, declared, floored, rt }, row) => {
                // A band row with a reservation but demand-paged memory never
                // enters the band (wave 11): `resolve` already floored it.
                if topo_sched::row_band_entry(row.as_bytes())
                    == Some(azos_topology::BandEntry::NotLocked)
                {
                    azos_drv_sys::kwarn!("[AUTORUN][SCHED-RT] REFUSED tid={} row={}: a real-time band row \
                               must be mem = \"locked\" -- runs at the ring-3 floor", tid, row);
                    let _ = azos_actuation::logger::log_safety_violation_durable(
                        azos_actuation::logger::SAFETY_TOPO_CLASS_REFUSED,
                        topo_sched::SITE_AUTORUN_RT, tid);
                }
                // Wave 11 SCHED-RT: a profiled row's reservation first, the
                // band only with it; refused, the floor and a record.
                let priority = match rt {
                    Some(r) => {
                        let me = azos_sched::idx_for_tid(tid).unwrap_or(usize::MAX);
                        match azos_sched::rt::reserve(me, r) {
                            Ok(_) => priority,
                            Err(_) => {
                                let _ = azos_actuation::logger::log_safety_violation_durable(
                                    azos_actuation::logger::SAFETY_TOPO_CLASS_REFUSED,
                                    topo_sched::SITE_AUTORUN_RT, tid);
                                topo_sched::band_refused_priority(priority)
                            }
                        }
                    }
                    None => priority,
                };
                topo_sched::apply_timer_slack(tid, row);
                topo_sched::apply_principal(tid, row, None);
                let was = azos_sched::set_current_sched_params(priority, class as u8);
                kprintln!("[AUTORUN][PRIO] tid={} {} row={} class={} declared={} applied={} (was {}){}",
                    tid, profile.image, row, class.name(), declared, priority, was,
                    if floored { " RAISED to the ring-3 floor" } else { "" });
                if floored {
                    let _ = azos_actuation::logger::log_safety_violation_durable(
                        azos_actuation::logger::SAFETY_TOPO_CLASS_REFUSED,
                        topo_sched::SITE_AUTORUN_FLOOR, tid);
                }
            }
            (TopoSched::Refused, row) => {
                let _ = azos_actuation::logger::log_safety_violation_durable(
                    azos_actuation::logger::SAFETY_TOPO_CLASS_REFUSED,
                    topo_sched::SITE_AUTORUN, tid);
                azos_drv_sys::kwarn!("[AUTORUN][PRIO] REFUSED tid={} {} row={} names a class this build \
                           does not schedule — runs at priority {}",
                    tid, profile.image, row,
                    azos_sched::task_priority(tid).unwrap_or(0));
            }
            (TopoSched::NoRow, _) => kprintln!(
                "[AUTORUN][PRIO] tid={} {} has no topology row — runs at priority {}",
                tid, profile.image, azos_sched::task_priority(tid).unwrap_or(0)),
        }
    }
    // autorun is a kernel task — it cannot rely on the ecall/SRET return path
    // a user process uses. Like the shell's `exec` command, take the prepared
    // hand-off (K-C21: published on THIS task's own slot, and the taker has
    // already installed the new satp — sret_to_user's own write of the same
    // value is a harmless re-write) and SRET to U-mode directly. Previously
    // this task simply returned here, hitting task_exit() before the pending
    // exec was ever applied — so the user process never started.
    if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
        kprintln!("[AUTORUN] SRET to user-space entry={:#x}", ctx.entry);
        unsafe {
            azos_sched::sret_to_user(
                ctx.entry   as usize,
                ctx.user_sp as usize,
                ctx.satp    as usize,
            );
        }
        // sret_to_user() is -> ! — unreachable
    }
}

/// Maximum autorun ELF path length (including NUL terminator).
///
/// This is the SECOND place the autorun path is cut. The first is
/// `MAX_VAL` in `azos_config`, which counts what it truncates and makes
/// boot say so; this one is silent, because it can never fire — and it can
/// never fire only while it is strictly larger than `MAX_VAL`.
///
/// That margin is what the assert below holds. Raising `MAX_VAL` past 63
/// would otherwise bring back the 2026-08-20 bug (`/fat/BRAINCLI.ELF` cut to
/// `/fat/BRAINCLI.EL`, surfacing as "[AUTORUN] File not found") at a cut
/// point with no counter behind it. The build fails instead.
// Shared by every ISA — `autorun_task` itself lost its riscv64-only gate for
// the same reason (see that function's own doc): this buffer and its length
// constant are pure data, read/written identically by every `kernel_main`.
pub(crate) const AUTORUN_PATH_MAX: usize = 64;
const _: () = assert!(
    AUTORUN_PATH_MAX > azos_config::MAX_VAL,
    "AUTORUN_PATH_MAX must leave room for the longest value CONFIG.INI can \
     hold plus its NUL, or the autorun path is cut a second time in silence",
);

/// Static buffer for autorun ELF path (set during boot, read by autorun_task).
pub(crate) static mut AUTORUN_PATH: [u8; AUTORUN_PATH_MAX] = [0u8; AUTORUN_PATH_MAX];
