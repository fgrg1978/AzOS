// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! An ext4 volume served from ring 3 (Kconfig `FS_EXT4_RING3`).
//!
//! A `[volume.NAME]` row with `format = "ext4"` names a partition and a mount
//! point. The image is parsed by `EXT4D.ELF` (`userspace/services/ext4d`),
//! never here: its row holds `READ` on that partition and serves
//! `endpoint.ext4`. The kernel mounts `azos_fs::endpoint::EndpointFs` at the
//! row's path and gives it its [`Link`]:
//!
//! * the region the two share (`MemObj fs.share`, created here once and
//!   granted to the server's row alone), read and written through the direct
//!   map, and only between a call and its answer;
//! * the calls, made by a kernel task of their own ([`call_task`]) with
//!   capabilities in its own table: the one on `endpoint.ext4`
//!   (`kcall::endpoint_handle`) and the open files' the server lends. A
//!   client that reads the mount blocks in its own system call until the
//!   call task has the answer, for at most `FS_EXT4_RING3_REPLY_MS`; it never
//!   holds a capability on the server, so it cannot call it directly.
//!
//! One call is in flight at a time (the mount serialises its operations and
//! the region holds one request). A call the client stopped waiting for still
//! runs to its end, and the next waits for it rather than share the region
//! with it. One ext4 row is served per boot: there is one region and one
//! endpoint.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_devif::{IdlError, IdlResult, MsgDesc, Transport};
use azos_drv_sys::{kprintln, kwarn};
use azos_fs::endpoint::{EndpointFs, Link, REGION_BYTES};
use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec};
use azos_sched::{BlockOutcome, WaitReason};
use azos_sync::SpinLock;
use azos_syscall::kcall::{self, KernelEndpoint};
use azos_topology::VolumeFormat;

/// The endpoint the server serves.
const ENDPOINT: &[u8] = b"ext4";
/// How long a client waits for the server: Kconfig `FS_EXT4_RING3_REPLY_MS`.
const REPLY_MS: u64 = azos_limits::FS_EXT4_RING3_REPLY_MS as u64;
/// The call task parks on this; a client wakes it with the same value.
const PARK: u64 = u64::MAX;

static FS: EndpointFs = EndpointFs::new(azos_fs::vfs::FS_TYPE_EXT4);
static LINK: KernelLink = KernelLink;
static REGION: AtomicUsize = AtomicUsize::new(0);
static CALL_TASK: AtomicBool = AtomicBool::new(false);
static CALL_TASK_TID: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    /// Posted by a client, not yet taken.
    Posted,
    /// The call task is making the call.
    Taken,
    /// Answered; the client has not read it yet.
    Done,
    /// The client stopped waiting: the answer is dropped when it comes.
    Abandoned,
}

/// Lent capabilities the mount gave back, which the call task closes (they
/// are in its table): at most one per open file the mount keeps.
const CLOSES: usize = 8;

struct Job {
    phase: Phase,
    node: Option<u32>,
    msg: Option<MsgDesc>,
    res: IdlResult,
    waiter: u32,
    deadline: u64,
    closes: [u32; CLOSES],
    n_closes: usize,
}

static JOB: SpinLock<Job> = SpinLock::new(Job {
    phase: Phase::Idle,
    node: None,
    msg: None,
    res: Ok(()),
    waiter: 0,
    deadline: 0,
    closes: [0; CLOSES],
    n_closes: 0,
});

fn wake(tid: u32, deadline: u64) {
    if tid != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(d) if *d == deadline));
    }
}

/// The handle of a capability the server lent in `msg`'s answer (its first
/// entry), if it carries one.
fn lent(msg: &MsgDesc) -> Option<u32> {
    (msg.n_caps > 0).then(|| msg.caps[0].handle)
}

/// The call task: takes the posted call, makes it through its own
/// capabilities, hands the answer back (or drops it, and gives back what it
/// lent, when nobody waits), and parks until the next.
fn call_task(_: usize) {
    CALL_TASK_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    loop {
        let (job, closes, n) = {
            let mut j = JOB.lock();
            let n = core::mem::take(&mut j.n_closes);
            let job = match (j.phase, j.msg) {
                (Phase::Posted, Some(m)) => {
                    j.phase = Phase::Taken;
                    Some((j.node, m))
                }
                _ => None,
            };
            (job, j.closes, n)
        };
        for &h in &closes[..n] {
            close(h);
        }
        let Some((node, mut msg)) = job else {
            if n != 0 {
                continue;
            }
            let _ = azos_sched::task_block_outcome(WaitReason::Timer(PARK));
            continue;
        };
        let res = match node.or_else(|| kcall::endpoint_handle(ENDPOINT)) {
            Some(h) => KernelEndpoint(h).call(&mut msg),
            None => Err(IdlError::Transport(-1)),
        };
        let (waiter, deadline) = {
            let mut j = JOB.lock();
            if j.phase == Phase::Abandoned {
                j.phase = Phase::Idle;
                (0, 0)
            } else {
                j.phase = Phase::Done;
                j.msg = Some(msg);
                j.res = res;
                (j.waiter, j.deadline)
            }
        };
        if waiter == 0 {
            if let Some(h) = lent(&msg).filter(|_| res.is_ok()) {
                close(h);
            }
        } else {
            wake(waiter, deadline);
        }
    }
}

/// Give back a capability of the call task's table.
fn close(h: u32) {
    let _ = azos_syscall::handlers::sys_close_typed(h as u64);
}

struct KernelLink;

impl KernelLink {
    fn region(&self) -> Option<&'static mut [u8]> {
        let base = REGION.load(Ordering::Acquire);
        // SAFETY: a kernel-owned region of `REGION_BYTES` bytes, created once
        // and never freed. The server writes it only while it serves a call,
        // and the mount touches it only around one (its claim): what is read
        // is copied out before anything checks it.
        (base != 0).then(|| unsafe { core::slice::from_raw_parts_mut(base as *mut u8, REGION_BYTES) })
    }
}

impl Link for KernelLink {
    fn call(&self, node: Option<u32>, msg: &mut MsgDesc) -> IdlResult {
        const BUSY: IdlError = IdlError::Transport(-16);
        kcall::admit_blocking().map_err(|e| IdlError::Transport(e as isize))?;
        if !CALL_TASK.load(Ordering::Acquire) {
            return Err(IdlError::Transport(-1));
        }
        let me = azos_sched::current_task_tid();
        let freq = azos_drv_sys::timebase::freq();
        let deadline = azos_drv_sys::timebase::now().saturating_add(freq.saturating_mul(REPLY_MS) / 1000);
        {
            let mut j = JOB.lock();
            if j.phase != Phase::Idle {
                return Err(BUSY);
            }
            j.phase = Phase::Posted;
            j.node = node;
            j.msg = Some(*msg);
            j.res = Ok(());
            j.waiter = me;
            j.deadline = deadline;
        }
        wake(CALL_TASK_TID.load(Ordering::Acquire), PARK);
        loop {
            {
                let mut j = JOB.lock();
                if j.phase == Phase::Done {
                    j.phase = Phase::Idle;
                    if let Some(m) = j.msg.take() {
                        *msg = m;
                    }
                    return j.res;
                }
                if azos_drv_sys::timebase::now() >= deadline {
                    // Not yet taken: withdrawn. Taken: it runs to its end and
                    // its answer is dropped.
                    j.phase = if j.phase == Phase::Posted { Phase::Idle } else { Phase::Abandoned };
                    return Err(IdlError::DeadlineExpired);
                }
            }
            if azos_sched::task_block_killable(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
                let mut j = JOB.lock();
                j.phase = if j.phase == Phase::Posted { Phase::Idle } else { Phase::Abandoned };
                return Err(BUSY);
            }
        }
    }

    fn close(&self, node: u32) {
        // In the call task's table: it closes it before its next call.
        let queued = {
            let mut j = JOB.lock();
            let n = j.n_closes;
            if n < CLOSES {
                j.closes[n] = node;
                j.n_closes = n + 1;
            }
            n < CLOSES
        };
        if queued {
            wake(CALL_TASK_TID.load(Ordering::Acquire), PARK);
        }
    }

    fn put(&self, off: usize, bytes: &[u8]) -> bool {
        let Some(r) = self.region() else { return false };
        match off.checked_add(bytes.len()).and_then(|end| r.get_mut(off..end)) {
            Some(d) => {
                d.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    fn get(&self, off: usize, out: &mut [u8]) -> bool {
        let Some(r) = self.region() else { return false };
        match off.checked_add(out.len()).and_then(|end| r.get(off..end)) {
            Some(s) => {
                out.copy_from_slice(s);
                true
            }
            None => false,
        }
    }
}

/// Create the shared region and publish it to the minter, before any task is
/// seeded (the server's row is granted it at spawn).
pub(crate) fn install_region() {
    if !azos_topology::get().is_some_and(|t| t.volumes().iter().any(|v| v.format == VolumeFormat::Ext4)) {
        return;
    }
    let pages = REGION_BYTES.div_ceil(azos_arch::PAGE_SIZE);
    let Some((obj, phys)) = memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadWrite, false)) else {
        kwarn!("[EXT4] no memory for the shared region: the ext4 volume is not served");
        return;
    };
    azos_ipc::cap_seed::set_shm_inspect_minter(azos_ipc::kregion::seed_mint_any);
    REGION.store(azos_mm::addr::phys_to_virt(phys) as usize, Ordering::Release);
    azos_ipc::kregion::publish(azos_ipc::kregion::Region::FsShare, obj);
}

/// Mount the topology's ext4 row (the first; one is served per boot) at its
/// path. The server answers once its row has started; until then every
/// operation on the mount fails as an unreachable volume does.
pub(crate) fn install_mounts() {
    let Some(topo) = azos_topology::get() else { return };
    let mut rows = topo.volumes().iter().filter(|v| v.format == VolumeFormat::Ext4);
    let Some(row) = rows.next() else { return };
    for extra in rows {
        kwarn!("[EXT4] volume {}: one ext4 volume is served per boot, not mounted", extra.name.as_str());
    }
    let at = row.mount.as_str();
    if REGION.load(Ordering::Acquire) == 0 {
        kwarn!("[EXT4] volume {}: no shared region, not mounted at {}", row.name.as_str(), at);
        return;
    }
    if azos_drv_block::partition::partition(u32::from(row.partition) - 1).is_none() {
        kprintln!("[EXT4] volume {}: partition {} is not on this medium, not mounted", row.name.as_str(), row.partition);
        return;
    }
    FS.attach(&LINK);
    match azos_fs::vfs::vfs_mount_fs(row.mount.as_bytes(), &FS) {
        Ok(()) => kprintln!(
            "[EXT4] volume {} (partition {}) mounted read-only at {}, served by EXT4D.ELF on endpoint.ext4",
            row.name.as_str(),
            row.partition,
            at
        ),
        Err(()) => kwarn!("[EXT4] volume {}: the mount table is full, not mounted at {}", row.name.as_str(), at),
    }
}

/// Start the call task, once, from a kernel context (`tasks::create`).
pub(crate) fn start_call_task() {
    if REGION.load(Ordering::Acquire) != 0 && !CALL_TASK.swap(true, Ordering::AcqRel) {
        azos_sched::task_create_affinity("ext4-call", call_task, 0, azos_sched::DEFAULT_PRIORITY, -1);
    }
}
