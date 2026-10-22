// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a ring-3 service needs from the kernel's state, as introspection
//! trees: the system's identity and counters in the public region, and the
//! signed topology's wiring in **view regions**, one per service, each a
//! read-only MemObj only the rows that declare it are granted.
//!
//! The kernel keeps no text files. A service maps its view (`MemObj
//! inspect.<view>` in its row; `SYS_CAP_INFO(Shm, SHM_INSPECT_<VIEW>)`) and
//! reads it with loads. What it may do with what it reads is still its own
//! capabilities': a view lists the named endpoints the declaring rows hold,
//! with their pool index, and the reader checks its own table
//! (`SYS_CAP_INFO`) for the handle and the rights.
//!
//! Public tree (beside the scheduler's and memory's, `inspect.rs`): nothing
//! here names a task, a key or what the topology wires together.
//!
//! ```text
//! system/{version, platform}
//! fs/tmpfs/{files, used_bytes, max_bytes}
//! drivers/<slot>/{kind, name, isolation, perms}       name "" = free slot
//! chaos/{seed, <point>/{rate, checked, fired}}         Kconfig CHAOS
//! ```
//!
//! View regions (the same layout, class public; each also carries
//! `inspect/refresh_ms` and the refresh count as its stamp):
//!
//! ```text
//! inspect.names       NAMESD.ELF  endpoints/<name>/{index, server}, imports/<badge> = "name,..."
//! inspect.rpc         RPCSRV.ELF  endpoints/<name>/{index, server}, peers/<n>/{class, node, noise_pk},
//!                                 exports/<n>/{endpoint, class} (of the endpoints listed)
//! inspect.mcp         MCPD.ELF    endpoints/<name>/{index, server}
//! inspect.components  COMPMGR.ELF components/<n>/{image, restart, serves, needs, dir, start}, components/rows
//! inspect.logins      SSHD.ELF, LOGIND.ELF   logins/<n>/{user, key}
//! inspect.clock       PTPD.ELF    clock/ptp_domain
//! ```
//!
//! A view's `endpoints/` lists what the rows declaring it hold, as the old
//! per-reader files did: every named endpoint of those rows for the names
//! view (but the name server's own), the exported ones for the RPC view, the
//! ones held with the call and the lend right (`WRITE`, `transfer`) for the
//! MCP view. `index` is `u64::MAX` until the endpoint exists; `server` is the
//! image serving it, empty while none does. A view no row declares is not
//! created.
//!
//! Admin tree: `decisions/records/<n>`, the newest stored decisions as
//! `ProvenanceRecord::to_bytes` records, oldest first (Kconfig
//! DECISION_RECORDS_DEV or DECISION_REFUSALS_DURABLE): a record's subject may
//! be a task.
//!
//! Shapes are built once, at `install_inspect`, from the topology installed by
//! then; the values (an endpoint's index and server, a component's `start`,
//! the registry, the counters) are rewritten at every refresh.
//! `components/rows` is written last and only when every component fit.

use azos_inspect::{Builder, Class, Error, NodeId, Region, Writer};
use azos_ipc::inspect_region::ViewKind;
use azos_ipc::memobj::{self, MemPerms, MemSpec};
use azos_sync::SpinLock;

use super::inspect_metrics::Num;

/// A named endpoint's `index` before the endpoint exists.
const NO_INDEX: u64 = u64::MAX;
/// Named endpoints a view lists, at most.
const ENDPOINTS: usize = 64;
/// Components the view lists, at most (`compmgr`'s `MAX_COMPONENTS`).
const COMPONENTS: usize = 24;
/// Pages a view region may take, at most.
const VIEW_PAGES_MAX: usize = 16;
/// Decision records the admin view holds (`decisd`'s table).
#[cfg(any(feature = "decisions", feature = "decisions-durable"))]
const DECISION_ROWS: usize = 24;

type EpName = [u8; azos_ipc::endpoint::ENDPOINT_NAME_MAX];

#[derive(Clone, Copy)]
struct Endpoint {
    name: EpName,
    len: usize,
    index: NodeId,
    server: NodeId,
}

struct Driver {
    kind: NodeId,
    name: NodeId,
    isolation: NodeId,
    perms: NodeId,
}

/// The public nodes the refresh writes.
struct Ids {
    tmpfs: [NodeId; 3],
    drivers: [Option<Driver>; azos_drv_api::REGISTRY_MAX_DRIVERS],
    #[cfg(feature = "chaos")]
    chaos: [(NodeId, NodeId, NodeId); azos_chaos::POINTS.len()],
}

static IDS: SpinLock<Option<Ids>> = SpinLock::new(None);

/// A view's nodes the refresh writes.
#[derive(Clone, Copy)]
struct ViewIds {
    endpoints: [Option<Endpoint>; ENDPOINTS],
    /// Each component's `start` and its topology row number.
    starts: [Option<(NodeId, usize)>; COMPONENTS],
}

const NO_VIEW_IDS: ViewIds = ViewIds { endpoints: [None; ENDPOINTS], starts: [None; COMPONENTS] };

static VIEWS: SpinLock<[Option<(Writer<'static>, ViewIds)>; ViewKind::ALL.len()]> =
    SpinLock::new([const { None }; ViewKind::ALL.len()]);

/// A string node sized to `s` (at least one byte).
fn text(b: &mut Builder<'_, '_>, parent: NodeId, name: &str, s: &str) -> Result<NodeId, Error> {
    b.string(parent, name, s.len().max(1), s)
}

/// A NUL-padded name as text.
fn padded(n: &[u8]) -> &str {
    let l = n.iter().position(|&c| c == 0).unwrap_or(n.len());
    core::str::from_utf8(&n[..l]).unwrap_or("?")
}

// ── The public subtrees ──────────────────────────────────────────────────────

/// Build the public subtrees under `root`.
pub(crate) fn build(b: &mut Builder<'_, '_>, root: NodeId) -> Result<(), Error> {
    let sys = b.dir(root, "system")?;
    text(b, sys, "version", env!("CARGO_PKG_VERSION"))?;
    text(b, sys, "platform", azos_drv_base::platform::hw::PLATFORM_NAME)?;

    let fs = b.dir(root, "fs")?;
    let t = b.dir(fs, "tmpfs")?;
    let tmpfs = [b.u64(t, "files", 0)?, b.u64(t, "used_bytes", 0)?, b.u64(t, "max_bytes", 0)?];
    let mut ids = Ids {
        tmpfs,
        drivers: [const { None }; azos_drv_api::REGISTRY_MAX_DRIVERS],
        #[cfg(feature = "chaos")]
        chaos: [(NodeId::ROOT, NodeId::ROOT, NodeId::ROOT); azos_chaos::POINTS.len()],
    };
    let r = build_rest(b, root, &mut ids);
    // What was built is refreshed even when a later subtree did not fit.
    *IDS.lock_irqsave() = Some(ids);
    r
}

fn build_rest(b: &mut Builder<'_, '_>, root: NodeId, ids: &mut Ids) -> Result<(), Error> {
    let drv = b.dir(root, "drivers")?;
    for (i, slot) in ids.drivers.iter_mut().enumerate() {
        let d = b.dir(drv, &Num::name("", i as u64))?;
        *slot = Some(Driver {
            kind: b.u64(d, "kind", 0)?,
            name: b.string(d, "name", 24, "")?,
            isolation: b.string(d, "isolation", 10, "")?,
            perms: b.u64(d, "perms", 0)?,
        });
    }
    #[cfg(feature = "chaos")]
    {
        let c = b.dir(root, "chaos")?;
        b.u64(c, "seed", azos_chaos::seed())?;
        for (slot, p) in ids.chaos.iter_mut().zip(azos_chaos::POINTS) {
            let d = b.dir(c, p.name())?;
            *slot = (b.u64(d, "rate", 0)?, b.u64(d, "checked", 0)?, b.u64(d, "fired", 0)?);
        }
    }
    Ok(())
}

/// Rewrite the public values and every view's, and stamp the views with
/// `stamp` (the refresh count); the number not published.
pub(crate) fn refresh(w: &Writer<'_>, stamp: u64) -> u32 {
    let mut bad = 0u32;
    {
        let g = IDS.lock_irqsave();
        if let Some(ids) = g.as_ref() {
            let mut ok = |r: Result<(), Error>| bad += r.is_err() as u32;
            let (files, used, max) = azos_fs::tmpfs_stats();
            for (id, v) in ids.tmpfs.iter().zip([files, used, max]) {
                ok(w.set_u64(*id, v as u64));
            }
            #[cfg(feature = "chaos")]
            for ((rate, checked, fired), p) in ids.chaos.iter().zip(azos_chaos::POINTS) {
                let (r, c, f) = azos_chaos::stats(p);
                ok(w.set_u64(*rate, r as u64));
                ok(w.set_u64(*checked, c));
                ok(w.set_u64(*fired, f));
            }
        }
    }
    bad += refresh_drivers(w);
    bad + refresh_views(stamp)
}

fn refresh_drivers(w: &Writer<'_>) -> u32 {
    use azos_drv_api::DriverIsolation;
    let mut rows = [(0u32, [0u8; 24], 0usize, "", 0u64); azos_drv_api::REGISTRY_MAX_DRIVERS];
    let mut n = 0;
    {
        // One pass over the table under its lock; the order is made after.
        let reg = azos_drv_base::runtime::registry::REGISTRY.lock();
        for d in reg.iter() {
            if n == rows.len() {
                break;
            }
            let m = d.manifest();
            let iso = match m.isolation {
                DriverIsolation::InKernel => "inkernel",
                DriverIsolation::UserProcess { .. } => "userproc",
                DriverIsolation::Hypervisor => "hypervisor",
            };
            let name = m.name.as_bytes();
            let l = name.len().min(24);
            rows[n].0 = m.kind;
            rows[n].1[..l].copy_from_slice(&name[..l]);
            rows[n].2 = l;
            rows[n].3 = iso;
            rows[n].4 = m.required_perms.bits() as u64;
            n += 1;
        }
    }
    // By kind, as the registry is looked up.
    rows[..n].sort_unstable_by_key(|r| r.0);
    let g = IDS.lock_irqsave();
    let Some(ids) = g.as_ref() else { return 0 };
    let mut bad = 0;
    for (i, d) in ids.drivers.iter().enumerate() {
        let Some(d) = d else { continue };
        let (kind, name, len, iso, perms) = if i < n { rows[i] } else { (0, [0; 24], 0, "", 0) };
        bad += w.set_u64(d.kind, kind as u64).is_err() as u32;
        bad += w.set_str(d.name, core::str::from_utf8(&name[..len]).unwrap_or("?")).is_err() as u32;
        bad += w.set_str(d.isolation, iso).is_err() as u32;
        bad += w.set_u64(d.perms, perms).is_err() as u32;
    }
    bad
}

// ── The view regions ─────────────────────────────────────────────────────────

/// Does any row of `topo` declare the view `v` (`MemObj inspect.<view>`)?
fn declared(topo: &azos_topology::Topology<'_>, v: ViewKind) -> bool {
    topo.tasks().iter().any(|r| declares(topo, r, v))
}

fn declares(topo: &azos_topology::Topology<'_>, row: &azos_topology::TaskSpec<'_>, v: ViewKind) -> bool {
    topo.caps_of(row)
        .iter()
        .any(|c| c.kind == azos_abi::cap::CapKind::MemObj && c.target.as_bytes() == v.target().as_bytes())
}

/// The named endpoints the rows declaring `v` hold that the view lists, each
/// once, into `out`; how many.
fn view_endpoints(topo: &azos_topology::Topology<'_>, v: ViewKind, out: &mut [(EpName, usize); ENDPOINTS]) -> usize {
    let mut n = 0;
    let mut add = |name: &[u8]| {
        if name.is_empty() || name.len() > azos_ipc::endpoint::ENDPOINT_NAME_MAX || n == ENDPOINTS {
            return;
        }
        if out[..n].iter().any(|(e, l)| &e[..*l] == name) {
            return;
        }
        out[n].0 = [0; azos_ipc::endpoint::ENDPOINT_NAME_MAX];
        out[n].0[..name.len()].copy_from_slice(name);
        out[n].1 = name.len();
        n += 1;
    };
    for row in topo.tasks().iter().filter(|r| declares(topo, r, v)) {
        for c in topo.caps_of(row) {
            if c.kind != azos_abi::cap::CapKind::Endpoint {
                continue;
            }
            let Some(name) = azos_topology::types::endpoint_target(c) else { continue };
            let listed = match v {
                ViewKind::Names => name != azos_ipc::cap_seed::NAMES_ENDPOINT,
                ViewKind::Rpc => topo
                    .tasks()
                    .iter()
                    .any(|t| topo.exports_of(t).iter().any(|e| e.endpoint.as_bytes() == name)),
                ViewKind::Mcp => c.perms.contains(azos_abi::cap::CapPerms::WRITE) && c.transfer,
                _ => false,
            };
            if listed {
                add(name);
            }
        }
    }
    n
}

/// Build the view `v` of `topo` under the root of `b`.
fn build_view(
    b: &mut Builder<'_, '_>,
    topo: &azos_topology::Topology<'_>,
    v: ViewKind,
    ids: &mut ViewIds,
) -> Result<(), Error> {
    *ids = NO_VIEW_IDS;
    let root = NodeId::ROOT;
    // How often the values move, as in the public region: what a reader that
    // waits for a refresh paces itself by.
    let meta = b.dir(root, "inspect")?;
    b.u64(meta, "refresh_ms", azos_limits::INSPECT_REFRESH_MS as u64)?;
    if matches!(v, ViewKind::Names | ViewKind::Rpc | ViewKind::Mcp) {
        let mut eps = [([0u8; azos_ipc::endpoint::ENDPOINT_NAME_MAX], 0usize); ENDPOINTS];
        let n = view_endpoints(topo, v, &mut eps);
        let dir = b.dir(root, "endpoints")?;
        for (slot, (name, len)) in ids.endpoints.iter_mut().zip(&eps[..n]) {
            let d = b.dir(dir, core::str::from_utf8(&name[..*len]).map_err(|_| Error::BadName)?)?;
            *slot = Some(Endpoint {
                name: *name,
                len: *len,
                index: b.u64(d, "index", NO_INDEX)?,
                server: b.string(d, "server", 16, "")?,
            });
        }
    }
    match v {
        ViewKind::Names => build_imports(b, root, topo),
        ViewKind::Rpc => build_peers(b, root, topo, ids),
        ViewKind::Mcp => Ok(()),
        ViewKind::Components => build_components(b, root, topo, ids),
        ViewKind::Logins => {
            let l = b.dir(root, "logins")?;
            let mut n = 0u64;
            for login in topo.logins() {
                for key in login.keys() {
                    let d = b.dir(l, &Num::name("", n))?;
                    text(b, d, "user", login.name.as_str())?;
                    b.bytes(d, "key", 32, key)?;
                    n += 1;
                }
            }
            Ok(())
        }
        ViewKind::Clock => {
            let c = b.dir(root, "clock")?;
            if let Some(domain) = topo.clock().ptp_domain {
                b.u64(c, "ptp_domain", domain as u64)?;
            }
            Ok(())
        }
    }
}

/// One node per importing row, by its badge
/// (`azos_syscall::spawn::names_badge`): the names it imports, comma
/// separated. A name holds no comma (`azos_topology::types::import_name_ok`).
fn build_imports(b: &mut Builder<'_, '_>, top: NodeId, topo: &azos_topology::Topology<'_>) -> Result<(), Error> {
    let dir = b.dir(top, "imports")?;
    for (ti, task) in topo.tasks().iter().enumerate() {
        let names = topo.imports_of(task);
        if names.is_empty() {
            continue;
        }
        let mut list = Line::new();
        for (i, name) in names.iter().enumerate() {
            if i > 0 {
                list.put(",")?;
            }
            list.put(name.as_str())?;
        }
        text(b, dir, &Num::name("", azos_syscall::spawn::names_badge(ti) as u64), list.as_str())?;
    }
    Ok(())
}

/// One node per peer node whose `[peer.NAME]` row pins a Noise key, and one per
/// `export = ["NAME@CLASS"]` entry whose endpoint the view lists (one the
/// rows declaring it hold).
fn build_peers(
    b: &mut Builder<'_, '_>,
    top: NodeId,
    topo: &azos_topology::Topology<'_>,
    ids: &ViewIds,
) -> Result<(), Error> {
    let dir = b.dir(top, "peers")?;
    let mut n = 0u64;
    for p in topo.peers() {
        for node in p.nodes() {
            let Some(pk) = p.noise_pk_of(*node) else { continue };
            let d = b.dir(dir, &Num::name("", n))?;
            text(b, d, "class", p.name.as_str())?;
            b.u64(d, "node", *node as u64)?;
            b.bytes(d, "noise_pk", 32, pk)?;
            n += 1;
        }
    }
    let dir = b.dir(top, "exports")?;
    let mut n = 0u64;
    for task in topo.tasks() {
        for e in topo.exports_of(task) {
            let held = ids.endpoints.iter().flatten().any(|x| &x.name[..x.len] == e.endpoint.as_bytes());
            if !held {
                continue;
            }
            let d = b.dir(dir, &Num::name("", n))?;
            text(b, d, "endpoint", e.endpoint.as_str())?;
            text(b, d, "class", e.peer.as_str())?;
            n += 1;
        }
    }
    Ok(())
}

/// The rows the component manager starts (`for_each_launch_row`: the rows with
/// `start = true`, not the manager's own row, in the order to start them),
/// each with the endpoints it serves and needs
/// (`azos_topology::builder::manager_view_endpoints`), its directory when a
/// package brought it, and `start`: 0 for a row whose image the boot launcher
/// found missing from the volume.
fn build_components(
    b: &mut Builder<'_, '_>,
    top: NodeId,
    topo: &azos_topology::Topology<'_>,
    ids: &mut ViewIds,
) -> Result<(), Error> {
    let dir = b.dir(top, "components")?;
    let mut n = 0usize;
    let mut r = Ok(());
    super::for_each_launch_row(topo, &mut |i, row| {
        if r.is_err() || !azos_topology::builder::manager_starts(row) {
            return;
        }
        if n == COMPONENTS {
            r = Err(Error::NoSpace);
            return;
        }
        r = (|| {
            let d = b.dir(dir, &Num::name("", n as u64))?;
            text(b, d, "image", row.name.as_str())?;
            text(b, d, "restart", view_restart(row))?;
            let mut eps = Line::new();
            azos_topology::builder::manager_view_endpoints(topo, row, &mut eps).map_err(|_| Error::BadSize)?;
            let (serves, needs) = eps.as_str().split_once(' ').ok_or(Error::Corrupt)?;
            text(b, d, "serves", serves)?;
            text(b, d, "needs", needs)?;
            let mut dbuf = [0u8; 16];
            let dir_s = crate::boot::pkg_boot::image_dir(row.name.as_bytes(), &mut dbuf)
                .and_then(|d| core::str::from_utf8(d).ok())
                .unwrap_or("");
            text(b, d, "dir", dir_s)?;
            ids.starts[n] = Some((b.u64(d, "start", super::row_startable(i) as u64)?, i));
            n += 1;
            Ok(())
        })();
    });
    r?;
    b.u64(dir, "rows", n as u64)?;
    Ok(())
}

/// The `restart` word of `row` in the view. **Gate canaries only:**
/// `restart-canary` (every row restarts on failure only, as before the key
/// existed) and `supall-canary` (no row is restarted) make the manager act on
/// a policy the signed topology does not state, so the `restart` and `supall`
/// rows must fail on the buzzer they restart, or do not.
fn view_restart(row: &azos_topology::TaskSpec<'_>) -> &'static str {
    if cfg!(feature = "supall-canary") {
        "no"
    } else if cfg!(feature = "restart-canary") {
        "on-failure"
    } else {
        row.restart.as_str()
    }
}

/// Build `v` into `pages` pages of scratch memory: whether it fits.
fn fits(topo: &azos_topology::Topology<'_>, v: ViewKind, pages: usize) -> bool {
    let words: alloc::vec::Vec<core::sync::atomic::AtomicU64> =
        (0..pages * azos_arch::PAGE_SIZE / 8).map(|_| core::sync::atomic::AtomicU64::new(0)).collect();
    let Ok(w) = Writer::init(Region::from_atomics(&words), Class::Public) else { return false };
    let mut ids = NO_VIEW_IDS;
    w.rebuild(|b| build_view(b, topo, v, &mut ids)).is_ok()
}

/// Create, build and publish every view a row declares. Boot, before any task
/// is seeded; after the public region (the reader check is the same).
pub(crate) fn install_views() {
    let Some(topo) = azos_topology::get() else { return };
    for v in ViewKind::ALL {
        if !declared(topo, v) {
            continue;
        }
        let Some(pages) = (0..=VIEW_PAGES_MAX.trailing_zeros()).map(|s| 1usize << s).find(|&p| fits(topo, v, p)) else {
            azos_drv_sys::kwarn!("[INSPECT] the {} view does not fit {} pages: not published", v.target(), VIEW_PAGES_MAX);
            continue;
        };
        let Some((obj, phys)) = memobj::memobj_create_kernel(pages, &MemSpec::contig(MemPerms::ReadOnly, false)) else {
            azos_drv_sys::kwarn!("[INSPECT] no memory object for the {} view: not published", v.target());
            continue;
        };
        let base = azos_mm::addr::phys_to_virt(phys) as *const u8;
        // SAFETY: the object's frames are the kernel's for good (it is never
        // freed) and mapped in the direct map; every access to them is an
        // atomic word (this writer, and the readers' loads).
        let Ok(region) = (unsafe { Region::from_raw(base, pages * azos_arch::PAGE_SIZE) }) else { continue };
        let Ok(w) = Writer::init(region, Class::Public) else { continue };
        let mut ids = NO_VIEW_IDS;
        if w.rebuild(|b| build_view(b, topo, v, &mut ids)).is_err()
            || azos_inspect::Reader::open(region, Class::Public).is_err()
        {
            azos_drv_sys::kwarn!("[INSPECT] the {} view does not build: not published", v.target());
            continue;
        }
        VIEWS.lock_irqsave()[v as usize] = Some((w, ids));
        azos_ipc::inspect_region::publish_view(v, obj);
        let (nodes, _, words, _) = w.usage();
        azos_drv_sys::kprintln!("[INSPECT] view {} published: {} KiB, {} nodes, {} value words",
            v.target(), pages * azos_arch::PAGE_SIZE / 1024, nodes, words);
    }
}

/// The named, live endpoints of the pool: name, pool index, serving image.
struct Live {
    name: EpName,
    len: usize,
    index: u32,
    server: [u8; 16],
}

/// Rewrite every view's endpoints and components; the values not published.
fn refresh_views(stamp: u64) -> u32 {
    // The pool first, with no view lock held (each read takes the pool's).
    let mut live = [const { None::<Live> }; ENDPOINTS];
    let mut n = 0;
    for i in 0..azos_ipc::endpoint::MAX_ENDPOINTS {
        let Some((name, len, owner)) = azos_ipc::endpoint::endpoint_name_owner(i) else { continue };
        if n == ENDPOINTS {
            break;
        }
        let served = owner != 0 && owner != azos_ipc::endpoint::UNCLAIMED;
        let mut server = [0u8; 16];
        if let Some(r) = served.then(|| azos_sched::task_row(owner)).flatten() {
            server = r.name;
        }
        live[n] = Some(Live { name, len, index: i as u32, server });
        n += 1;
    }
    // Atomic stores only under the lock: no other lock is taken in it.
    let views = VIEWS.lock_irqsave();
    let mut bad = 0u32;
    for (w, ids) in views.iter().flatten() {
        for e in ids.endpoints.iter().flatten() {
            let found = live[..n].iter().flatten().find(|l| l.name[..l.len] == e.name[..e.len]);
            bad += w.set_u64(e.index, found.map_or(NO_INDEX, |l| l.index as u64)).is_err() as u32;
            bad += w.set_str(e.server, found.map_or("", |l| padded(&l.server))).is_err() as u32;
        }
        for (id, row) in ids.starts.iter().flatten() {
            bad += w.set_u64(*id, super::row_startable(*row) as u64).is_err() as u32;
        }
        w.stamp(stamp);
    }
    bad
}

// ── The admin region ─────────────────────────────────────────────────────────

/// The admin region's decision records, newest that fit [`DECISION_ROWS`],
/// oldest first, as `azos_decision::query` lists them. Rebuilt with the admin
/// tree at every refresh.
#[cfg(any(feature = "decisions", feature = "decisions-durable"))]
pub(crate) fn build_admin(b: &mut Builder<'_, '_>) -> Result<(), Error> {
    const SIZE: usize = azos_decision::PROVENANCE_SIZE;
    let dec = b.dir(NodeId::ROOT, "decisions")?;
    let dir = b.dir(dec, "records")?;
    let mut ids = [0u64; DECISION_ROWS];
    let after = azos_decision::total().saturating_sub(DECISION_ROWS as u64);
    let n = azos_decision::query(&azos_decision::Filter { after, ..azos_decision::Filter::ANY }, &mut ids);
    let mut k = 0u64;
    for &id in &ids[..n] {
        if let Some(p) = azos_decision::lookup(id) {
            b.bytes(dir, &Num::name("", k), SIZE, &p.to_bytes())?;
            k += 1;
        }
    }
    Ok(())
}

/// A short line built in place: a list of names, the two endpoint columns.
struct Line {
    b: [u8; azos_inspect::STR_MAX * 2],
    n: usize,
}

impl Line {
    fn new() -> Line {
        Line { b: [0; azos_inspect::STR_MAX * 2], n: 0 }
    }

    fn put(&mut self, s: &str) -> Result<(), Error> {
        let s = s.as_bytes();
        if self.n + s.len() > self.b.len() {
            return Err(Error::BadSize);
        }
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
        Ok(())
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.b[..self.n]).unwrap_or("")
    }
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.put(s).map_err(|_| core::fmt::Error)
    }
}
