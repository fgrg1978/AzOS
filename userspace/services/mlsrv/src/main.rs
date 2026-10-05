// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 ML inference service (`DRV_KIND_ML`).
//!
//! The behavior loop's MLP used to run inside `behavior_task`, in the kernel,
//! and on aarch64 the kernel is soft-float. It runs here now, in a ring-3
//! image built hard-float on aarch64 (riscv64imac has no F/D, so on that ISA
//! it is the same soft-float code, one privilege level down). The kernel
//! reaches it the way it reaches a ring-3 driver: the behavior loop queues a
//! request on the driver-server queue for `DRV_KIND_ML` and blocks, with a
//! deadline, for the reply.
//!
//! # What it does, in order
//!
//! 1. Loads `/fat/MLP.RML` into its own copy of the weights, as the kernel's
//!    Phase 15 does for the in-kernel MLP (the file carries the same weights
//!    as the compiled-in ones), once its Ed25519 signature `/fat/MLP.SIG`
//!    verifies (see [`check_signature`]).
//! 2. Runs the GGUF policy self-test on `/fat/POLICY.GGF` (signed the same
//!    way, `/fat/POLICY.SIG`) — the three
//!    classifications Phase C used to run in the kernel at boot, printed with
//!    the same `[GGUF] n/3 tests passed` verdict the gate reads.
//! 3. Registers as `DRV_KIND_ML` through its `Cap<DriverRegistry>` and serves
//!    requests with `SYS_DRIVER_REPLY_WAIT`, blocked while none is queued.
//!
//! The op space is `azos_abi::ml_srv`.

#![no_std]
#![no_main]

use azos_abi::drv_kind::DRV_KIND_ML;
use azos_abi::ml_srv;
use azos_libsys as sys;

// ── Wire structs — MUST byte-match azos_driver_server (see gpio_drv) ────
const REQ_PAYLOAD_BYTES: usize = 64;
const REPLY_PAYLOAD_BYTES: usize = 64;

/// The kernel proxy's `client_tid` (`PROXY_CALLER_TID_KERNEL`).
const CLIENT_KERNEL: u32 = u32::MAX;
/// Reply status: success.
const STATUS_OK: i32 = 0;
/// Reply status: unknown op or malformed request.
const STATUS_BAD: i32 = -1;

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverRequest {
    token: u64,
    client_tid: u32,
    op: u32,
    in_len: u16,
    out_cap: u16,
    input: [u8; REQ_PAYLOAD_BYTES],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DriverReply {
    token: u64,
    status: i32,
    out_len: u16,
    _pad: u16,
    output: [u8; REPLY_PAYLOAD_BYTES],
}

impl DriverRequest {
    const fn zeroed() -> Self {
        DriverRequest { token: 0, client_tid: 0, op: 0, in_len: 0, out_cap: 0, input: [0; REQ_PAYLOAD_BYTES] }
    }
}

impl DriverReply {
    const fn zeroed() -> Self {
        DriverReply { token: 0, status: 0, out_len: 0, _pad: 0, output: [0; REPLY_PAYLOAD_BYTES] }
    }
}

// ── Console lines with numbers (libsys prints bytes only) ───────────────────

struct Line {
    buf: [u8; 160],
    len: usize,
}

impl Line {
    fn new(s: &[u8]) -> Self {
        let mut l = Line { buf: [0; 160], len: 0 };
        l.push(s);
        l
    }
    fn push(&mut self, s: &[u8]) -> &mut Self {
        for &b in s {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        self
    }
    fn num(&mut self, mut v: u64) -> &mut Self {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 { break; }
        }
        self.push(&d[i..])
    }
    fn hex(&mut self, v: u32) -> &mut Self {
        let mut d = [0u8; 10];
        d[0] = b'0';
        d[1] = b'x';
        for k in 0..8 {
            let nib = ((v >> (28 - 4 * k)) & 0xF) as u8;
            d[2 + k] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        }
        self.push(&d)
    }
    fn print(&self) {
        sys::println(&self.buf[..self.len]);
    }
}

// ── Files ───────────────────────────────────────────────────────────────────

/// Read a whole (small) file into `buf`. `None` when it cannot be opened or
/// read; otherwise the bytes read, up to `buf.len()`.
fn read_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let h = sys::file_open_typed(path, 0);
    if h < 0 {
        return None;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let r = sys::file_read_typed(h as u32, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    let _ = sys::close_typed(h as u32);
    if n == 0 { None } else { Some(n) }
}

// ── Startup: the model files ────────────────────────────────────────────────

/// What [`check_signature`] found for one data file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signature {
    /// The sidecar verified against the trusted key.
    Verified,
    /// `CONFIG_ML_DATA_SIG_REQUIRED=n`: nothing was checked.
    NotRequired,
    /// No sidecar on the volume.
    Absent,
    /// A sidecar that is not 64 bytes, or that does not verify.
    Bad,
}

/// Check `data` against the bare 64-byte Ed25519 signature in `sig_path` —
/// the `CAPS.SIG`/`CONFIG.SIG` format and key
/// (`azos_topology::verify_signature`, `TRUSTED_PUBKEY`). The bytes
/// checked are the bytes the caller then uses: a file longer than the
/// caller's buffer was read truncated and fails here.
fn check_signature(data: &[u8], sig_path: &[u8]) -> Signature {
    if !azos_limits::ML_DATA_SIG_REQUIRED {
        return Signature::NotRequired;
    }
    // One byte more than a signature, so a longer sidecar is seen as such.
    let mut sig = [0u8; 65];
    match read_file(sig_path, &mut sig) {
        None => Signature::Absent,
        Some(64) => {
            match azos_topology::verify_signature(
                data, &sig[..64], &azos_topology::TRUSTED_PUBKEY)
            {
                Ok(()) => Signature::Verified,
                Err(_) => Signature::Bad,
            }
        }
        Some(_) => Signature::Bad,
    }
}

/// Load `/fat/MLP.RML` if its signature verifies. Refused, absent or
/// malformed, the service keeps the weights compiled into this image, which
/// the kernel admitted by its digest: a file nobody signed never reaches the
/// MLP, and the loop still gets verdicts (owner rule 2026-09-28: L1 must never
/// pass for lack of one).
fn load_rmlp() {
    static mut BUF: [u8; 512] = [0; 512];
    // SAFETY: single-threaded program; the only reference to BUF.
    let buf = unsafe { &mut *(&raw mut BUF) };
    let Some(n) = read_file(ml_srv::WEIGHTS_PATH, buf) else {
        sys::println(b"[mlsrv] /fat/MLP.RML not found -- using the compiled-in weights");
        return;
    };
    let sig = check_signature(&buf[..n], ml_srv::WEIGHTS_SIG_PATH);
    match sig {
        Signature::Absent => {
            sys::println(b"[mlsrv] /fat/MLP.RML REFUSED: no /fat/MLP.SIG -- using the compiled-in weights");
            return;
        }
        Signature::Bad => {
            sys::println(b"[mlsrv] /fat/MLP.RML REFUSED: bad signature in /fat/MLP.SIG -- using the compiled-in weights");
            return;
        }
        Signature::Verified | Signature::NotRequired => {}
    }
    if azos_ml::model_load_bytes(&buf[..n]) {
        Line::new(b"[mlsrv] weights loaded from /fat/MLP.RML (").num(n as u64)
            .push(if sig == Signature::Verified { b" bytes, signature verified)" as &[u8] }
                  else { b" bytes, NOT verified: ML_DATA_SIG_REQUIRED=n)" })
            .print();
    } else {
        sys::println(b"[mlsrv] /fat/MLP.RML invalid -- using the compiled-in weights");
    }
}

/// Phase C's boot self-test, moved out of the kernel with the inference.
fn gguf_self_test() {
    static mut BUF: [u8; 4096] = [0; 4096];
    // SAFETY: single-threaded program; the only reference to BUF.
    let buf = unsafe { &mut *(&raw mut BUF) };
    let Some(n) = read_file(ml_srv::POLICY_PATH, buf) else {
        sys::println(b"[GGUF] /fat/POLICY.GGF not found");
        return;
    };
    // Verified before the parser sees a byte (`verify.rs`'s ordering rule).
    match check_signature(&buf[..n], ml_srv::POLICY_SIG_PATH) {
        Signature::Absent => {
            sys::println(b"[GGUF] /fat/POLICY.GGF REFUSED: no /fat/POLICY.SIG -- self-test skipped");
            return;
        }
        Signature::Bad => {
            sys::println(b"[GGUF] /fat/POLICY.GGF REFUSED: bad signature in /fat/POLICY.SIG -- self-test skipped");
            return;
        }
        Signature::Verified | Signature::NotRequired => {}
    }
    let Some(gguf) = azos_ml::gguf::GgufFile::parse(&buf[..n]) else {
        sys::println(b"[GGUF] Parse error: invalid GGUF file");
        return;
    };
    Line::new(b"[GGUF] Parsed POLICY.GGF: ").num(gguf.n_tensors as u64)
        .push(b" tensors, ").num(n as u64).push(b" bytes (in mlsrv)").print();
    let tests: [([f32; 4], usize); 3] = [
        ([0.8, 0.3, 0.5, 0.9], 0),
        ([0.6, 0.1, 0.5, 0.9], 1),
        ([0.1, 0.5, 0.5, 0.9], 2),
    ];
    let mut pass = 0u64;
    for (inp, expected) in &tests {
        let mut logits = [0.0f32; 3];
        if azos_ml::ggml_nano::gguf_mlp_infer(&gguf, inp, &mut logits) {
            let idx = azos_ml::ggml_nano::argmax(&logits);
            let ok = idx == *expected;
            if ok { pass += 1; }
            Line::new(if ok { b"  [OK] " } else { b"  [MISMATCH] " })
                .push(azos_ml::CLASS_NAMES[idx].as_bytes())
                .push(b" logits ").hex(logits[0].to_bits()).push(b" ")
                .hex(logits[1].to_bits()).push(b" ").hex(logits[2].to_bits()).print();
        } else {
            sys::println(b"  [MISMATCH] gguf_mlp_infer returned false");
        }
    }
    Line::new(b"[GGUF] ").num(pass).push(b"/3 tests passed").print();
}

// ── Serving ─────────────────────────────────────────────────────────────────

/// `OP_INFER`: the MLP on `[front / 1000, right / 1000, 0.5, 0.9]`.
fn infer(req: &DriverRequest, reply: &mut DriverReply) {
    if (req.in_len as usize) < ml_srv::INFER_REQ_LEN {
        reply.status = STATUS_BAD;
        return;
    }
    let front = u16::from_le_bytes([req.input[0], req.input[1]]);
    let right = u16::from_le_bytes([req.input[2], req.input[3]]);
    let input: [f32; 4] = [front as f32 / 1000.0, right as f32 / 1000.0, 0.5, 0.9];
    let logits = azos_ml::mlp_infer(&input);
    let class = azos_ml::argmax3(&logits) as u8;
    reply.output[0] = class;
    for (k, l) in logits.iter().enumerate() {
        reply.output[4 + 4 * k..8 + 4 * k].copy_from_slice(&l.to_bits().to_le_bytes());
    }
    reply.out_len = ml_srv::INFER_REPLY_LEN as u16;
    reply.status = STATUS_OK;
}

/// `OP_FAULT`: a store to address 0. The kernel kills the task on the page
/// fault, and its exit releases the `DRV_KIND_ML` slot. Kernel clients only.
fn fault() -> ! {
    sys::println(b"[mlsrv] OP_FAULT from the kernel: faulting on purpose");
    // SAFETY: deliberately not safe — this is the fault being injected.
    unsafe { core::ptr::write_volatile(core::ptr::null_mut::<u32>(), 0xDEAD) };
    sys::exit(3);
}

/// `OP_STALL`: sleep for the payload's milliseconds, then answer as
/// `OP_INFER` on a zero vector. Kernel clients only.
fn stall(req: &DriverRequest, reply: &mut DriverReply) {
    let ms = if req.in_len >= 2 { u16::from_le_bytes([req.input[0], req.input[1]]) } else { 0 };
    Line::new(b"[mlsrv] OP_STALL from the kernel: sleeping ").num(ms as u64).push(b" ms").print();
    sys::sleep(ms as u64);
    let mut zero = *req;
    zero.input[..ml_srv::INFER_REQ_LEN].fill(0);
    zero.in_len = ml_srv::INFER_REQ_LEN as u16;
    infer(&zero, reply);
}

fn handle(req: &DriverRequest) -> DriverReply {
    let mut reply = DriverReply::zeroed();
    reply.token = req.token;
    match req.op {
        ml_srv::OP_INFER => infer(req, &mut reply),
        ml_srv::OP_STALL if req.client_tid == CLIENT_KERNEL => stall(req, &mut reply),
        ml_srv::OP_FAULT if req.client_tid == CLIENT_KERNEL => fault(),
        _ => reply.status = STATUS_BAD,
    }
    reply
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[mlsrv] starting");
    load_rmlp();
    gguf_self_test();

    // Typed registration, as gpio_drv: the kind comes out of the capability
    // the topology row grants (`drv.18`), and there is no untyped fallback.
    let cap = sys::cap_lookup(sys::CapKind::DriverRegistry as u8, DRV_KIND_ML);
    if cap < 0 {
        sys::println(b"[mlsrv] no DriverRegistry capability for DRV_KIND_ML FAILED");
        sys::exit(1);
    }
    if sys::drv_srv_register_typed(cap as u32, 0, 0, 0) != 0 {
        sys::println(b"[mlsrv] typed register FAILED");
        sys::exit(1);
    }
    sys::println(b"[mlsrv] registered DRV_KIND_ML via Cap<DriverRegistry>, serving");

    let mut req = DriverRequest::zeroed();
    let mut reply = DriverReply::zeroed();
    let mut owed = false;
    loop {
        let reply_ptr = if owed { &reply as *const DriverReply as *const u8 } else { core::ptr::null() };
        // Blocks while the queue is empty; the proxy's submit wakes it.
        let rc = sys::drv_srv_reply_wait(DRV_KIND_ML, reply_ptr, &mut req as *mut DriverRequest as *mut u8, 0);
        match rc {
            0 => {
                reply = handle(&req);
                owed = true;
            }
            // The reply went out; the park ended with no request.
            -1 => owed = false,
            // Refused with nothing done: the reply is still owed. Yield
            // rather than spin on a refusal that will repeat.
            _ => sys::yield_now(),
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}
