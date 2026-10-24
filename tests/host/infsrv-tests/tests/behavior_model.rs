// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior loop's model, end to end through the service: the bundle the
//! build ships as `BEHAVIOR.MBL` (`mk/images.mk`: `tools/image/make_gguf.py`'s policy
//! wrapped by `tools/image/make_mbl.py` with the same name, tensor sizes and cost row),
//! loaded by the real loader, called through the real dispatcher with the input
//! the kernel's client builds, and answered with the class the policy gives.
//!
//! What this pins that no other test sees: the model reference the kernel names
//! the model by (`BEHAVIOR_MODEL_REF` in `kernel/src/behavior_ml.rs`) is the
//! bundle's, the signed worst case of the cost row fits the 10 ms deadline the
//! loop gives a call, and the three reference scenarios classify as the gate's
//! `[GGUF] 3/3` self-test says they do.

use azos_devif::infer::{Done, InferCall, InferClient, Tensor};
use azos_devif::outcome::{self, Out};
use azos_idl::Cap;
use azos_infsrv_tests::*;
use std::cell::RefCell;
use std::process::Command;

const BADGE: u32 = 1;
const DEADLINE_NS: u64 = 10_000_000;

/// The policy file as the build writes it.
fn policy_gguf() -> Vec<u8> {
    let d = Tmp::new("policy");
    let tool = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tools/image/make_gguf.py");
    let out = Command::new("python3").arg(tool).env("AZOS_OUT", &d.0).output().expect("python3");
    assert!(out.status.success(), "make_gguf.py: {}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(d.0.join("build").join("policy.gguf")).unwrap()
}

/// The bundle as `mk/images.mk` builds it.
fn behavior_bundle() -> (Vec<u8>, [u8; 32]) {
    let var = Var { backend: "gguf", id: 1, blob: policy_gguf(), wcet_us: 1000, energy_uj: 20, mem_bytes: 4096 };
    bundle_as("behavior", "behavior-mlp", (16, 12), &[var], None)
}

/// `const BEHAVIOR_MODEL_REF: u64 = 0x...;` of the kernel's client.
fn pinned_ref() -> u64 {
    let src = include_str!("../../../../kernel/src/behavior_ml.rs");
    let at = src.find("pub const BEHAVIOR_MODEL_REF: u64 = 0x").expect("the kernel pins the model reference");
    let hex: String = src[at..].split("0x").nth(1).unwrap().chars().take_while(|c| c.is_ascii_hexdigit() || *c == '_').collect();
    u64::from_str_radix(&hex.replace('_', ""), 16).unwrap()
}

#[test]
fn the_kernels_model_reference_is_the_bundles() {
    let (file, _) = behavior_bundle();
    let d = azos_crypto::sha256::sha256(&file[..azos_ml::bundle::manifest_len(1)]);
    assert_eq!(
        azos_devif::infer::model_ref(&d),
        pinned_ref(),
        "kernel/src/behavior_ml.rs BEHAVIOR_MODEL_REF is not the model_ref of the bundle the build ships \
         (the build says the right value: tools/image/make_mbl.py --expect-ref-from)"
    );
}

/// The three scenarios of `tools/image/make_gguf.py` and of the start-up self-test,
/// through the service, inside the loop's deadline: the class, the model that
/// ran and a cost the broker admitted.
#[test]
fn the_behavior_loop_gets_its_classes_inside_its_deadline() {
    let mut arena = vec![0u8; 64 * 1024];
    let host = Host::new();
    let b = behavior_bundle();
    let svc = RefCell::new(service(&mut arena, &host, limits(), &[b], None));
    let now = host.now.get();
    for (n, (x, class)) in [([0.8f32, 0.3, 0.5, 0.9], 0usize), ([0.6, 0.1, 0.5, 0.9], 1), ([0.1, 0.5, 0.5, 0.9], 2)]
        .into_iter()
        .enumerate()
    {
        let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + DEADLINE_NS);
        let caps = host.tensors(10 + 2 * n as u32, &x);
        let out: Out<Done> = c
            .infer(pinned_ref(), Cap::<Tensor>::from_raw(caps.0), Cap::<Tensor>::from_raw(caps.1), 0)
            .expect("the call reached the service");
        assert_eq!(out.code, outcome::OK, "scenario {n}");
        assert_eq!((out.value.model_hash, out.value.variant_id, out.value.backend), (pinned_ref(), 1, 1));
        let y = host.output(caps.1, 3);
        let best = (0..3).fold(0, |b, i| if y[i] > y[b] { i } else { b });
        assert_eq!(best, class, "scenario {n}: logits {y:?}");
    }
}

/// A call whose deadline is nearer than the signed worst case is refused now:
/// the loop's fallback, not a late answer.
#[test]
fn a_deadline_inside_the_signed_worst_case_is_refused() {
    let mut arena = vec![0u8; 64 * 1024];
    let host = Host::new();
    let b = behavior_bundle();
    let svc = RefCell::new(service(&mut arena, &host, limits(), &[b], None));
    let now = host.now.get();
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 }).with_deadline(now + 500_000);
    let caps = host.tensors(10, &[0.8, 0.3, 0.5, 0.9]);
    let out = c
        .infer(pinned_ref(), Cap::<Tensor>::from_raw(caps.0), Cap::<Tensor>::from_raw(caps.1), 0)
        .expect("the call reached the service");
    assert_eq!(out.code, outcome::REFUSED);
}

/// A model reference the service does not hold is `NO_RESOURCE`, which the
/// loop turns into a missing verdict (`Unavailable`).
#[test]
fn another_model_reference_is_no_resource() {
    let mut arena = vec![0u8; 64 * 1024];
    let host = Host::new();
    let b = behavior_bundle();
    let svc = RefCell::new(service(&mut arena, &host, limits(), &[b], None));
    let mut c = InferClient::new(Loopback { svc: &svc, badge: Some(BADGE), clock: 0 });
    let caps = host.tensors(10, &[0.8, 0.3, 0.5, 0.9]);
    let out = c
        .infer(pinned_ref() ^ 1, Cap::<Tensor>::from_raw(caps.0), Cap::<Tensor>::from_raw(caps.1), 0)
        .expect("the call reached the service");
    assert_eq!(out.code, outcome::NO_RESOURCE);
}

/// The string literal of `const NAME: &[u8] = b"...";` in `src`.
fn byte_const<'a>(src: &'a str, name: &str) -> &'a str {
    let at = src.find(&format!("const {name}: &[u8] = b\"")).unwrap_or_else(|| panic!("no const {name}"));
    let rest = &src[at..];
    let start = rest.find("b\"").unwrap() + 2;
    &rest[start..start + rest[start..].find('"').unwrap()]
}

/// The kernel calls the endpoint the service serves. The topology names it by a
/// target (`endpoint.infer`: the kind, a dot, the name) and the kernel by the
/// name alone; a name with the prefix on it would be another endpoint, never
/// claimed, and every call would find nobody.
///
/// **Canary.** Write `b"endpoint.infer"` in `kernel/src/behavior_ml.rs`: red.
#[test]
fn the_kernel_calls_the_endpoint_the_row_serves() {
    let row = include_str!("../../../../crates/core/topology/src/builder.rs");
    let kernel = include_str!("../../../../kernel/src/behavior_ml.rs");
    let target = byte_const(row, "RESOURCE_ENDPOINT_INFER");
    assert_eq!(target.strip_prefix("endpoint."), Some(byte_const(kernel, "INFER_ENDPOINT")));
}
