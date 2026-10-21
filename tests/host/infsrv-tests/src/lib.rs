// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fixtures of the inference service's host suite: real signed bundles (the
//! writer is `tools/make_mbl.py`, the key a throwaway one), a GGUF model
//! with a known answer, and a [`Platform`] made of host memory with a clock
//! the tests move. The tests are `tests/*.rs`.

use azos_abi::ipc_msg::MSG_BADGED;
use azos_crypto::sig::{dsig_signature, SigAlg};
use azos_crypto::sha256::sha256;
use azos_idl::{IdlError, MsgDesc, Transport};
use infsrv::broker::{Broker, Limits};
use infsrv::exec::Exec;
use infsrv::load::{self, Arena, LoadError, Report};
use infsrv::service::{Blobs, LogObject, Platform, Service, TensorError};
use infsrv::verdict::Publisher;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

pub const TOOL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tools/make_mbl.py");

// ── a model ──────────────────────────────────────────────────────────────

fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
    buf.extend_from_slice(s);
}

fn push_info(buf: &mut Vec<u8>, name: &[u8], dims: &[u64], off: u64) {
    push_string(buf, name);
    buf.extend_from_slice(&(dims.len() as u32).to_le_bytes());
    for d in dims {
        buf.extend_from_slice(&d.to_le_bytes());
    }
    buf.extend_from_slice(&0u32.to_le_bytes()); // F32
    buf.extend_from_slice(&off.to_le_bytes());
}

/// A two-layer MLP as a GGUF v3 file: `w1` is `hid x n_in` (row `j` the weights
/// of hidden neuron `j`), `w2` is `n_out x hid`, all F32.
pub fn mlp_gguf(n_in: usize, w1: &[f32], b1: &[f32], w2: &[f32], b2: &[f32]) -> Vec<u8> {
    let (hid, n_out) = (b1.len(), b2.len());
    assert_eq!((w1.len(), w2.len()), (hid * n_in, n_out * hid));
    let mut buf = Vec::new();
    buf.extend_from_slice(b"GGUF");
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(&4u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    let mut off = 0u64;
    for (name, dims, n) in [
        (&b"w1"[..], vec![n_in as u64, hid as u64], w1.len()),
        (b"b1", vec![hid as u64], b1.len()),
        (b"w2", vec![hid as u64, n_out as u64], w2.len()),
        (b"b2", vec![n_out as u64], b2.len()),
    ] {
        push_info(&mut buf, name, &dims, off);
        off += 4 * n as u64;
    }
    while buf.len() % 32 != 0 {
        buf.push(0);
    }
    for v in [w1, b1, w2, b2] {
        for x in v {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    buf
}

/// The model every test runs: 4 inputs, 2 hidden, 2 outputs.
///   y0 = relu(x0) + relu(x1)
///   y1 = relu(x0) - relu(x1) + 0.5
pub fn model() -> Vec<u8> {
    mlp_gguf(
        4,
        &[1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        &[0.0, 0.0],
        &[1.0, 1.0, 1.0, -1.0],
        &[0.0, 0.5],
    )
}

/// What [`model`] answers, computed here and not by the code under test.
pub fn model_answer(x: [f32; 4]) -> [f32; 2] {
    let (h0, h1) = (x[0].max(0.0), x[1].max(0.0));
    [h0 + h1, h0 - h1 + 0.5]
}

pub const IN_BYTES: u32 = 16;
pub const OUT_BYTES: u32 = 8;

pub fn tensor(x: &[f32]) -> Vec<u8> {
    x.iter().flat_map(|v| v.to_le_bytes()).collect()
}

pub fn floats(b: &[u8], n: usize) -> Vec<f32> {
    b[..4 * n].chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

// ── a signed bundle ──────────────────────────────────────────────────────

pub struct Tmp(pub PathBuf);
impl Tmp {
    pub fn new(tag: &str) -> Tmp {
        // Tests run in parallel: a directory per call, not per tag.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("azos-infsrv-{}-{n}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn python(args: &[&str]) -> String {
    let out = Command::new("python3").args(args).output().expect("python3 is required (tools/make_mbl.py)");
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn key(dir: &Path) -> (PathBuf, [u8; 32]) {
    let (priv_p, pub_p) = (dir.join("k.priv"), dir.join("k.pub"));
    std::fs::write(&priv_p, [7u8; 32]).unwrap();
    python(&[
        "-c",
        "import sys\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K\n\
         from cryptography.hazmat.primitives import serialization as s\n\
         k = K.from_private_bytes(open(sys.argv[1], 'rb').read())\n\
         open(sys.argv[2], 'wb').write(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))",
        priv_p.to_str().unwrap(),
        pub_p.to_str().unwrap(),
    ]);
    (priv_p, std::fs::read(pub_p).unwrap().try_into().unwrap())
}

/// One variant to write: the backend name `make_mbl.py` takes (`gguf`,
/// `spirv`, `vendor`), its id, its blob and its signed cost row.
pub struct Var {
    pub backend: &'static str,
    pub id: u32,
    pub blob: Vec<u8>,
    pub wcet_us: u32,
    pub energy_uj: u32,
    pub mem_bytes: u32,
}

/// A GGUF variant of [`model`].
pub fn gguf(id: u32, wcet_us: u32, energy_uj: u32, mem_bytes: u32) -> Var {
    Var { backend: "gguf", id, blob: model(), wcet_us, energy_uj, mem_bytes }
}

/// A bundle file and the public key it verifies under.
pub fn bundle(tag: &str, vars: &[Var], fallback: Option<&str>) -> (Vec<u8>, [u8; 32]) {
    bundle_as(tag, "policy-v1", (IN_BYTES, OUT_BYTES), vars, fallback)
}

/// [`bundle`] under another name and with other tensor sizes (`in`, `out` bytes).
pub fn bundle_as(tag: &str, name: &str, (in_bytes, out_bytes): (u32, u32), vars: &[Var], fallback: Option<&str>) -> (Vec<u8>, [u8; 32]) {
    let d = Tmp::new(tag);
    let (priv_p, pub_k) = key(&d.0);
    let mut args: Vec<String> = vec![
        TOOL.into(), "--name".into(), name.into(),
        "--in-bytes".into(), in_bytes.to_string(), "--out-bytes".into(), out_bytes.to_string(),
    ];
    for (n, v) in vars.iter().enumerate() {
        let file = d.0.join(format!("blob{n}"));
        std::fs::write(&file, &v.blob).unwrap();
        args.push("--variant".into());
        args.push(format!("{}:{}:{}:{}:{}:{}", v.backend, v.id, file.display(), v.wcet_us, v.energy_uj, v.mem_bytes));
    }
    if let Some(fb) = fallback {
        args.push("--fallback".into());
        args.push(fb.into());
    }
    let out = d.0.join("M.MBL");
    args.extend(["--priv".into(), priv_p.display().to_string(), "--out".into(), out.display().to_string()]);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    python(&a);
    (std::fs::read(out).unwrap(), pub_k)
}

/// The three-variant bundle most tests use, in the publisher's order: the most
/// accurate variant is the slowest and hungriest.
///   id 1  wcet 2000 us  energy 400 uJ  mem 8192
///   id 2  wcet  800 us  energy 120 uJ  mem 4096
///   id 3  wcet  300 us  energy  40 uJ  mem 1024
pub fn three() -> (Vec<u8>, [u8; 32]) {
    bundle("three", &[gguf(1, 2000, 400, 8192), gguf(2, 800, 120, 4096), gguf(3, 300, 40, 1024)], Some("1,2,3"))
}

/// Load `file` streamed `chunk` bytes at a time (a file system hands back what
/// it likes), verified under `pub_k`.
pub fn load_with(file: &[u8], pub_k: [u8; 32], arena: &mut Arena<'_>, chunk: usize) -> Result<Report, LoadError> {
    let mut at = 0usize;
    let mut read = |buf: &mut [u8]| {
        let n = buf.len().min(chunk).min(file.len() - at);
        buf[..n].copy_from_slice(&file[at..at + n]);
        at += n;
        n
    };
    load::load(&mut read, arena, move |m, s| dsig_signature(s).is_some_and(|sig| SigAlg::CONFIGURED.verify(&pub_k, m, sig)), sha256, infsrv::exec::fits)
}

// ── a platform ───────────────────────────────────────────────────────────

pub const PAGE: usize = 4096;

pub struct Region {
    pub bytes: Vec<u8>,
    pub writable: bool,
}

/// The blob arena as the host platform plays it: what the service did to it,
/// whether the next `blobs_resume` finds it taken back, and what a rebuild
/// finds to load and how much storage it is given.
#[derive(Default)]
pub struct BlobHost {
    /// `"resume"`, `"park"`, `"give-back"` and `"rebuild"`, in the order the
    /// service made them.
    pub log: Vec<&'static str>,
    /// The next `blobs_resume` answers `Lost` (once).
    pub purged: bool,
    /// The next `pressure_rose` answers true (once): the Domain's level rose.
    pub pressure_rose: bool,
    /// The bundles a rebuild loads, with the key each verifies under.
    pub bundles: Vec<(Vec<u8>, [u8; 32])>,
    /// Bytes of storage a rebuild gets; 0: none could be made.
    pub storage: usize,
    /// How long a rebuild takes, nanoseconds on the host clock.
    pub rebuild_ns: u64,
}

/// Host memory, a clock the tests move, and a record of what was given back.
#[derive(Clone)]
pub struct Host {
    pub blobs: Rc<RefCell<BlobHost>>,
    pub mem: Rc<RefCell<HashMap<u32, Region>>>,
    pub now: Rc<Cell<u64>>,
    /// How long the next run takes, nanoseconds.
    pub run_ns: Rc<Cell<u64>>,
    /// Capabilities released, in order.
    pub released: Rc<RefCell<Vec<u32>>>,
    /// The first capability of the context logs: context `n`'s object is
    /// `base + n`, `PAGE` bytes. `None`: the service made no logs.
    pub log: Rc<Cell<Option<u32>>>,
    /// With no `log`: the region each context's object would be (from
    /// `lazy_regions`), made on its first ask and handed over then; context
    /// `n`'s capability is `LAZY_CAP + n`.
    pub lazy: Rc<RefCell<Vec<(*mut u8, usize)>>>,
    /// The contexts whose object was made, in the order they asked.
    pub made: Rc<RefCell<Vec<usize>>>,
}

/// The first capability of the objects made on demand (`Host::lazy`).
pub const LAZY_CAP: u32 = 70;

impl Host {
    pub fn new() -> Host {
        Host {
            blobs: Default::default(),
            mem: Default::default(),
            now: Rc::new(Cell::new(1_000_000_000)),
            run_ns: Rc::new(Cell::new(100_000)),
            released: Default::default(),
            log: Rc::new(Cell::new(None)),
            lazy: Default::default(),
            made: Default::default(),
        }
    }

    /// A tensor pair as a client would move it: capability numbers and the
    /// input filled.
    pub fn tensors(&self, base: u32, x: &[f32]) -> (u32, u32) {
        let (i, o) = (base, base + 1);
        let mut input = tensor(x);
        input.resize(PAGE, 0);
        let mut m = self.mem.borrow_mut();
        m.insert(i, Region { bytes: input, writable: false });
        m.insert(o, Region { bytes: vec![0xEE; PAGE], writable: true });
        (i, o)
    }

    pub fn output(&self, cap: u32, n: usize) -> Vec<f32> {
        floats(&self.mem.borrow()[&cap].bytes, n)
    }
}

impl Platform for Host {
    fn now_ns(&self) -> u64 {
        self.now.get()
    }

    fn with_tensors(
        &mut self,
        input: u32,
        output: u32,
        f: &mut dyn FnMut(&[u8], &mut [u8], &dyn Fn() -> u64),
    ) -> Result<(), TensorError> {
        let r = {
            let mut m = self.mem.borrow_mut();
            let ok = match (m.get(&input), m.get(&output)) {
                (Some(_), Some(o)) if o.writable => Ok(()),
                (Some(_), Some(_)) => Err(TensorError::ReadOnly),
                _ => Err(TensorError::Unmappable),
            };
            if ok.is_ok() {
                let i = m.remove(&input).unwrap();
                let mut o = m.remove(&output).unwrap();
                let reads = Cell::new(0u32);
                let (now, run) = (self.now.get(), self.run_ns.get());
                let clock = || {
                    let n = reads.get();
                    reads.set(n + 1);
                    now + if n >= 1 { run } else { 0 }
                };
                f(&i.bytes, &mut o.bytes, &clock);
                m.insert(input, i);
                m.insert(output, o);
            }
            ok
        };
        self.released.borrow_mut().extend([input, output]);
        r
    }

    fn drop_cap(&mut self, cap: u32) {
        self.released.borrow_mut().push(cap);
    }

    fn log_region(&mut self, slot: usize) -> Option<LogObject> {
        // The regions are the test's (`shared_regions`), already given to the
        // publisher: nothing fresh to hand over.
        if let Some(base) = self.log.get() {
            return Some(LogObject { cap: base + slot as u32, bytes: PAGE as u32, fresh: None });
        }
        let (base, len) = *self.lazy.borrow().get(slot)?;
        let cap = LAZY_CAP + slot as u32;
        let mut made = self.made.borrow_mut();
        if made.contains(&slot) {
            return Some(LogObject { cap, bytes: len as u32, fresh: None });
        }
        made.push(slot);
        Some(LogObject { cap, bytes: len as u32, fresh: Some(base) })
    }

    fn blobs_resume(&mut self) -> Blobs {
        let mut b = self.blobs.borrow_mut();
        b.log.push("resume");
        if std::mem::take(&mut b.purged) {
            Blobs::Lost
        } else {
            Blobs::Kept
        }
    }

    fn pressure_rose(&mut self) -> bool {
        std::mem::take(&mut self.blobs.borrow_mut().pressure_rose)
    }

    fn blobs_park(&mut self, give_back: bool) {
        let mut b = self.blobs.borrow_mut();
        b.log.push(if give_back { "give-back" } else { "park" });
        // The object is let go: there is nothing to find next time.
        b.purged |= give_back;
    }

    fn blobs_rebuild(&mut self, broker: &mut Broker, arena: &mut Arena<'_>) {
        let (bundles, storage, ns) = {
            let mut b = self.blobs.borrow_mut();
            b.log.push("rebuild");
            (b.bundles.clone(), b.storage, b.rebuild_ns)
        };
        self.now.set(self.now.get() + ns);
        if storage == 0 {
            return;
        }
        // Leaked on purpose: it stands for a mapping that lives until the
        // object is let go.
        arena.reset(Box::leak(vec![0u8; storage].into_boxed_slice()));
        for (file, k) in &bundles {
            let rep = load_with(file, *k, arena, 512).expect("the bundle loads again");
            broker.add(rep.model).expect("the broker forgot its models first");
        }
    }
}

/// A service over [`Host`], with `models` loaded from `file` and `lim` as its
/// limits. `arena` is the caller's storage.
pub fn service<'a>(
    arena: &'a mut Vec<u8>,
    host: &Host,
    lim: Limits,
    bundles: &[(Vec<u8>, [u8; 32])],
    publisher: Option<Publisher>,
) -> Service<'a, Host> {
    let mut broker = Broker::new(lim);
    let mut ar = Arena::new(arena);
    for (file, k) in bundles {
        let rep = load_with(file, *k, &mut ar, 512).expect("the bundle loads");
        broker.add(rep.model).expect("a free model slot");
    }
    Service::new(broker, ar, Exec::scalar(), host.clone(), publisher)
}

pub fn limits() -> Limits {
    Limits { work_bytes: 16 * 1024, quota_uj: 0, window_ns: 1_000_000_000 }
}

/// The calls of a client, delivered to a service in this process with the
/// badge the kernel would stamp.
pub struct Loopback<'s, 'a> {
    pub svc: &'s RefCell<Service<'a, Host>>,
    pub badge: Option<u32>,
    /// `MsgDesc::clock_id` the request is delivered with.
    pub clock: u32,
}

impl Transport for Loopback<'_, '_> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        let mut req = *msg;
        req.clock_id = self.clock;
        if let Some(b) = self.badge {
            req.flags |= MSG_BADGED;
            req.badge = b as u64;
        }
        let mut rep = MsgDesc::default();
        self.svc.borrow_mut().handle(&req, &mut rep);
        *msg = rep;
        Ok(())
    }
}

/// The verdict logs of the service: one region of host memory per context,
/// with the alignment of the verdict log, standing in for the memory object the
/// service and a reader of that context both map, and the publisher that owns
/// their cells.
pub fn shared_regions() -> (Publisher, Vec<(*mut u8, usize)>) {
    let len = infsrv::verdict::region_bytes();
    let layout = std::alloc::Layout::from_size_align(len, infsrv::verdict::region_align()).unwrap();
    let mut publisher = Publisher::new();
    let mut regions = Vec::new();
    for slot in 0..infsrv::config::CONTEXTS {
        // Leaked on purpose: it stands for a mapping that lives as long as the
        // program.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!base.is_null());
        // SAFETY: the region is ours alone, aligned, and never freed.
        assert!(unsafe { publisher.add(slot, base, len) });
        regions.push((base, len));
    }
    (publisher, regions)
}

/// One zeroed region per context, aligned like a verdict log and given to no
/// publisher: what `Host::lazy` hands the service when a context first asks.
pub fn lazy_regions() -> Vec<(*mut u8, usize)> {
    let len = infsrv::verdict::region_bytes();
    let layout = std::alloc::Layout::from_size_align(len, infsrv::verdict::region_align()).unwrap();
    (0..infsrv::config::CONTEXTS)
        .map(|_| {
            // Leaked on purpose, like `shared_regions`.
            let base = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!base.is_null());
            (base, len)
        })
        .collect()
}

/// A request header for interface `id`, op `op` (the dispatcher's wire form),
/// delivered with `badge`.
pub fn raw_request(id: u32, op: u16, badge: Option<u32>) -> MsgDesc {
    let mut m = MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    m.words[0] = azos_idl::header(id, 1, op);
    if let Some(b) = badge {
        m.flags |= MSG_BADGED;
        m.badge = b as u64;
    }
    m
}
