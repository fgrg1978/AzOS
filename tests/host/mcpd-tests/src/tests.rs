// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Each test says what turns it red.

use crate::bridge::{LINE_MAX, PROPOSALS_MAX};
use crate::catalog::{self, parse_view, CONFIRM_OP, CONTROL_ID};
use crate::warrant::{self, Ledger, Refusal, Scope};
use crate::world::*;
use azos_mcp::json::Value;
use azos_rpc::wire::{cav, Caveat, Token};

/// The clock the model starts at.
const T0: u64 = 1_000_000_000;
/// Ten seconds on.
const T10: u64 = T0 + 10_000_000_000;
const AGENT: u32 = 101;
const HUMAN: u32 = 900;

fn names(list: &Value) -> Vec<String> {
    result(list)
        .get("tools")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap().to_string())
        .collect()
}

fn tool<'a>(list: &'a Value, name: &str) -> &'a Value {
    result(list).get("tools").and_then(Value::as_array).unwrap().iter().find(|t| t.get("name").and_then(Value::as_str) == Some(name)).unwrap()
}

/// Propose `lamp.set(level)` as `AGENT`; the proposal id and digest.
fn propose(s: &mut Session, level: u32) -> (u32, String) {
    let w = agent(AGENT, LAMP.id, &[SET, GET], T10);
    let a = s.call("lamp.set", &format!(r#"{{"args":[{level}]}}"#), Some(&w));
    assert_eq!(status(&a), "proposed", "{a:?}");
    (field_i64(&a, "proposal") as u32, structured(&a).get("digest").and_then(Value::as_str).unwrap().to_string())
}

fn confirm(s: &mut Session, id: u32, digest: &str, w: &Token) -> Value {
    s.call("azos.confirm", &format!(r#"{{"proposal":{id},"digest":"{digest}"}}"#), Some(w))
}

fn commit(s: &mut Session, id: u32, w: &Token) -> Value {
    s.call("azos.commit", &format!(r#"{{"proposal":{id}}}"#), Some(w))
}

// ── the handshake ────────────────────────────────────────────────────────────

/// The result of `initialize` names the epoch and the clock a warrant is signed
/// for, and the server's one capability, tools. **Red when** `_meta` is dropped
/// from the result, or the epoch it names is not the one the bridge checks.
#[test]
fn initialize_reports_the_epoch_and_the_clock() {
    let mut s = bare(config(), keys(), exports());
    let init = s.request(
        "initialize",
        r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scripted","version":"1"}}"#,
    );
    let r = result(&init);
    assert_eq!(r.get("protocolVersion").and_then(Value::as_str), Some("2025-06-18"));
    assert!(r.get("capabilities").and_then(|c| c.get("tools")).is_some());
    let meta = r.get("_meta").unwrap();
    assert_eq!(meta.get("azos/epoch").and_then(Value::as_i64), Some(EPOCH as i64));
    assert_eq!(meta.get("azos/mono_ns").and_then(Value::as_i64), Some(T0 as i64));
}

/// Before `notifications/initialized` only `ping` is served; a second
/// `initialize` is refused. **Red when** the phase check is dropped.
#[test]
fn nothing_but_ping_before_the_handshake_is_over() {
    let mut s = bare(config(), keys(), exports());
    let a = s.request("tools/list", "{}");
    assert_eq!(a.get("error").and_then(|e| e.get("code")).and_then(Value::as_i64), Some(-32600), "{a:?}");
    assert!(s.request("ping", "{}").get("result").is_some());
    let init = r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}"#;
    assert!(s.request("initialize", init).get("result").is_some());
    let a = s.request("tools/list", "{}");
    assert!(a.get("error").is_some(), "initialize alone is not the handshake: {a:?}");
    s.notify("notifications/initialized");
    assert!(s.request("tools/list", "{}").get("result").is_some());
    let again = s.request("initialize", init);
    assert!(again.get("error").is_some(), "{again:?}");
}

// ── tools/list ───────────────────────────────────────────────────────────────

/// The tools are the ops of the exported interfaces' tables that say how they
/// are delivered and take no capability; an op that declares nothing is not
/// one. The arguments' schema is the op's word count. The control tools appear
/// because an exported op is irreversible. **Red when** `exposed` lets an
/// undeclared op through (`odd.plain` appears), or a schema takes its size from
/// anything but `req_words`.
#[test]
fn tools_list_comes_from_the_op_tables() {
    let mut s = session();
    let list = s.request("tools/list", "{}");
    let mut got = names(&list);
    got.sort();
    let mut want: Vec<String> = [
        "azos.commit", "azos.confirm", "azos.grant_agent", "azos.grant_confirm", "decisions.get", "decisions.query", "lamp.get",
        "lamp.set", "lamp.wide", "odd.ok",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    want.sort();
    assert_eq!(got, want);
    assert!(!got.contains(&"odd.plain".to_string()), "an op that declares no delivery is not carried");

    // lamp.set: one request word after the header; irreversible.
    let set = tool(&list, "lamp.set");
    let args = set.get("inputSchema").and_then(|i| i.get("properties")).and_then(|p| p.get("args")).unwrap();
    assert_eq!(args.get("minItems").and_then(Value::as_i64), Some(1));
    assert_eq!(args.get("maxItems").and_then(Value::as_i64), Some(1));
    let ann = set.get("annotations").unwrap();
    assert_eq!(ann.get("destructiveHint").and_then(Value::as_bool), Some(true));
    assert_eq!(ann.get("idempotentHint").and_then(Value::as_bool), Some(false));
    let d = set.get("description").and_then(Value::as_str).unwrap();
    assert!(d.contains("once_only") && d.contains("IRREVERSIBLE") && d.contains("50000000 ns") && d.contains("safe_state"), "{d}");

    // lamp.get: no word after the header, so no `args`.
    let get = tool(&list, "lamp.get");
    assert!(get.get("inputSchema").and_then(|i| i.get("properties")).and_then(|p| p.get("args")).is_none());
    assert_eq!(get.get("annotations").and_then(|a| a.get("idempotentHint")).and_then(Value::as_bool), Some(true));
    // decisions.query: two request words (the filter).
    let q = tool(&list, "decisions.query");
    let n = q.get("inputSchema").and_then(|i| i.get("properties")).and_then(|p| p.get("args")).and_then(|a| a.get("minItems"));
    assert_eq!(n.and_then(Value::as_i64), Some(2));
}

/// With no irreversible op exported there is no propose, confirm or commit (and
/// no grant of a confirmation): those control tools are neither listed nor
/// callable; the grant of an agent's warrant stays. **Red when**
/// `has_irreversible` is true for an interface without a `once_only` op.
#[test]
fn the_control_tools_exist_only_with_an_irreversible_op() {
    let ex = vec![crate::catalog::Export { iface: &DECISIONS, endpoint: EP_DECISIONS }];
    let mut s = session_with(config(), keys(), ex);
    let list = s.request("tools/list", "{}");
    let mut got = names(&list);
    got.sort();
    assert_eq!(got, ["azos.grant_agent", "decisions.get", "decisions.query"]);
    for tool in ["azos.commit", "azos.confirm", "azos.grant_confirm"] {
        let a = s.call(tool, r#"{"proposal":1}"#, None);
        assert_eq!(a.get("error").and_then(|e| e.get("code")).and_then(Value::as_i64), Some(-32602), "{tool}: {a:?}");
    }
}

/// `/proc/mcp` is parsed against the catalog: a name the catalog does not know,
/// or a line that is not one, adds nothing. **Red when** an unknown name is
/// turned into an export.
#[test]
fn the_view_lists_only_what_the_catalog_knows() {
    static CAT: [catalog::Iface; 2] = [
        catalog::Iface { name: "lamp", id: 1, level: 1, ops: &[] },
        catalog::Iface { name: "decisions", id: 2, level: 1, ops: &[] },
    ];
    let v = parse_view(b"endpoint lamp 3\nendpoint toaster 4\nendpoint decisions 1\nendpoint lamp x\nnoise\nendpoint lamp 5 extra\n", &CAT);
    assert_eq!(v.decisions, Some(1));
    let got: Vec<(&str, u32)> = v.exports.iter().map(|e| (e.iface.name, e.endpoint)).collect();
    assert_eq!(got, vec![("lamp", 3), ("decisions", 1)]);
    assert_eq!(v.skipped, 3, "toaster, lamp x, lamp 5 extra");
    assert!(parse_view(&[0xff, 0xfe], &CAT).exports.is_empty());
}

// ── a call needs a warrant ───────────────────────────────────────────────────

/// A call with no warrant never reaches the kernel: an error result, a reason,
/// receipt 0. **Red when** the bridge calls without a token, or reports an
/// error as a JSON-RPC error (the result must be a result with `isError`).
#[test]
fn a_call_without_a_warrant_is_refused_before_the_kernel() {
    let mut s = session();
    let a = s.call("lamp.get", "{}", None);
    assert!(is_error(&a), "{a:?}");
    assert_eq!(status(&a), "refused");
    assert_eq!(reason(&a), "no-warrant");
    assert_eq!(receipt(&a), 0);
    assert_eq!(s.k.invokes, 0);
    assert!(s.k.log.iter().any(|l| l.contains("lamp.get") && l.contains("no-warrant")), "{:?}", s.k.log);
}

/// Warrants that are not warrants: not hex, not a token, a token with a byte
/// changed, for another interface, for another epoch, another principal's chain
/// claimed by a different issuer. **Red when** `verify` is skipped, or the
/// session (the epoch) is left out of the chain.
#[test]
fn a_warrant_that_does_not_verify_is_refused() {
    let mut s = session();
    let good = agent(AGENT, LAMP.id, &[GET], T10);
    let one = |s: &mut Session, hexed: &str| {
        let a = s.request(
            "tools/call",
            &format!(r#"{{"name":"lamp.get","arguments":{{}},"_meta":{{"azos/warrant":"{hexed}"}}}}"#),
        );
        reason(&a).to_string()
    };
    assert_eq!(one(&mut s, "zz"), "malformed-warrant");
    assert_eq!(one(&mut s, "abc"), "malformed-warrant");
    assert_eq!(one(&mut s, ""), "malformed-warrant");
    let h = hex(&good);
    assert_eq!(one(&mut s, &format!("{h}00")), "malformed-warrant", "bytes after the token");
    // One byte of the signature changed.
    let mut b = warrant::from_hex(&h).unwrap();
    let last = b.len() - 1;
    b[last] ^= 1;
    assert_eq!(one(&mut s, &warrant::to_hex(&b)), "bad-chain");
    // A caveat edited: the mask widened to every op.
    let mut b = warrant::from_hex(&h).unwrap();
    let at = 10 + 9 + 1;
    b[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(one(&mut s, &warrant::to_hex(&b)), "bad-chain");
    // Another interface's token.
    assert_eq!(one(&mut s, &hex(&agent(AGENT, ODD.id, &[GET], T10))), "wrong-interface");
    // Another boot's epoch.
    let old = agent_token(AGENT, EPOCH ^ 1, LAMP.id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET]))]);
    assert_eq!(one(&mut s, &hex(&old)), "bad-chain");
    // A human's key does not sign an agent's warrant, nor the reverse.
    let mut forged = Token::mint(&keys().human(AGENT), EPOCH, AGENT, LAMP.id);
    forged.attenuate(Caveat::new(cav::EXPIRY, T10)).unwrap();
    forged.attenuate(Caveat::new(cav::OP_MASK, mask(&[GET]))).unwrap();
    assert_eq!(one(&mut s, &hex(&forged)), "bad-chain");
    // Principal 0 is nobody.
    assert_eq!(one(&mut s, &hex(&agent(0, LAMP.id, &[GET], T10))), "no-principal");
    assert_eq!(s.k.invokes, 0, "none of them reached the kernel");
}

/// The caveats a warrant must carry, and the ones the bridge does not
/// evaluate: no expiry, a lapsed one, no mask, a kind it cannot honour, two
/// quotas. **Red when** a warrant without an `EXPIRY` or an `OP_MASK` passes,
/// or an unknown kind is ignored.
#[test]
fn a_warrant_must_expire_and_name_its_ops() {
    let mut s = session();
    let mut reasons = Vec::new();
    for caveats in [
        vec![(cav::OP_MASK, mask(&[GET]))],
        vec![(cav::EXPIRY, T10)],
        vec![(cav::EXPIRY, T0), (cav::OP_MASK, mask(&[GET]))],
        vec![(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::NODE, 1)],
        vec![(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::RECEIPT, 1)],
        vec![(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 3), (cav::QUOTA, 3)],
        vec![(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 0)],
    ] {
        let t = agent_token(AGENT, EPOCH, LAMP.id, &caveats);
        let a = s.call("lamp.get", "{}", Some(&t));
        assert_eq!(status(&a), "refused", "{caveats:?}");
        reasons.push(reason(&a).to_string());
    }
    assert_eq!(reasons, ["no-expiry", "no-op-mask", "lapsed", "unsupported-caveat", "unsupported-caveat", "unsupported-caveat", "spent"]);
    assert_eq!(s.k.invokes, 0);
}

/// The op mask names IDL ops, by number: an op outside it is refused whatever
/// else the warrant says, and a narrowing appended by the holder narrows. Two
/// masks intersect. **Red when** the mask is not tested, is tested against the
/// wrong bit (`1 << (op - 1)`), or a second mask replaces the first.
#[test]
fn an_op_mask_that_does_not_name_the_op_refuses_it() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[GET], T10);
    let a = s.call("lamp.set", r#"{"args":[5]}"#, Some(&w));
    assert_eq!((status(&a), reason(&a)), ("refused", "op-denied"));
    assert_eq!(s.k.invokes, 0);
    assert_eq!(s.k.lamp.sets, 0);
    // The same warrant calls the op it names.
    let a = s.call("lamp.get", "{}", Some(&w));
    assert_eq!(status(&a), "served", "{a:?}");
    // Mask {get, wide}; the holder appends {wide}: get is gone, wide stays.
    let mut w = agent(AGENT, LAMP.id, &[GET, 3], T10);
    w.attenuate(Caveat::new(cav::OP_MASK, mask(&[3]))).unwrap();
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&w))), "op-denied");
    assert_eq!(status(&s.call("lamp.wide", "{}", Some(&w))), "served");
    // A mask of nothing names nothing.
    let none = agent_token(AGENT, EPOCH, LAMP.id, &[(cav::EXPIRY, T10), (cav::OP_MASK, 0)]);
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&none))), "op-denied");
}

/// A warrant lapses with the clock. **Red when** `EXPIRY` is compared with `<`
/// instead of `<=`, or not at all.
#[test]
fn a_warrant_lapses_with_the_clock() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[GET], T0 + 5_000);
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
    s.k.now = T0 + 5_000;
    let a = s.call("lamp.get", "{}", Some(&w));
    assert_eq!((status(&a), reason(&a)), ("refused", "lapsed"));
}

/// A `QUOTA` counts uses and a refused call does not spend one; appending a
/// caveat does not make a fresh count. **Red when** the charge comes before the
/// other checks, or the count is keyed by the whole token.
#[test]
fn a_quota_counts_uses_not_tokens() {
    let mut s = session();
    let w = agent_token(AGENT, EPOCH, LAMP.id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 2)]);
    // A refused call (an op outside the mask) takes nothing.
    assert_eq!(reason(&s.call("lamp.set", r#"{"args":[1]}"#, Some(&w))), "op-denied");
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
    // The holder narrows the token and presents the result: the same count.
    let mut narrowed = w;
    narrowed.attenuate(Caveat::new(cav::EXPIRY, T10 - 1)).unwrap();
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&narrowed))), "served");
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&w))), "spent");
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&narrowed))), "spent");
    assert_eq!(s.k.invokes, 2);
}

/// A holder cannot reset a quota by narrowing the expiry: the count lives as long as
/// the issuer's own `EXPIRY`, not as long as the narrowed copy. **Red when** the entry's
/// lifetime is the minimum over every caveat, so the original token gets a fresh count
/// once the narrowed copy lapses.
#[test]
fn a_narrowed_expiry_does_not_reset_a_quota() {
    let mut s = session();
    let w = agent_token(AGENT, EPOCH, LAMP.id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 1)]);
    let mut narrowed = w;
    narrowed.attenuate(Caveat::new(cav::EXPIRY, T0 + 5_000)).unwrap();
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&narrowed))), "served");
    // The narrowed copy lapses; the original is still inside its own expiry and still spent.
    s.k.now = T0 + 5_000;
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&narrowed))), "lapsed");
    assert_eq!(reason(&s.call("lamp.get", "{}", Some(&w))), "spent");
    assert_eq!(s.k.invokes, 1);
}

/// The ledger forgets a token when it lapses and is bounded; a full ledger
/// refuses a new quota token rather than forgetting a live one. **Red when**
/// entries are never pruned, or the bound evicts.
#[test]
fn the_ledger_is_bounded_and_prunes_by_expiry() {
    let k = keys();
    let mut l = Ledger::default();
    let mk = |expiry: u64| {
        agent_token(AGENT, EPOCH, LAMP.id, &[(cav::EXPIRY, expiry), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 1)])
    };
    for i in 0..warrant::LEDGER_MAX as u64 {
        let g = warrant::check(&k, Scope::Agent { epoch: EPOCH }, &mk(T10 + i), LAMP.id, GET, T0).unwrap();
        l.charge(&g, T0).unwrap();
    }
    assert_eq!(l.len(), warrant::LEDGER_MAX);
    let extra = warrant::check(&k, Scope::Agent { epoch: EPOCH }, &mk(T10 + 999), LAMP.id, GET, T0).unwrap();
    assert_eq!(l.charge(&extra, T0), Err(Refusal::LedgerFull));
    // The oldest lapse: their entries go and there is room again.
    l.charge(&extra, T10 + 1).unwrap();
    assert!(l.len() < warrant::LEDGER_MAX);
}

// ── a reversible call: warrant, op, receipt ──────────────────────────────────

/// An admitted call returns the op's reply words and the receipt: the id of the
/// kernel's derive record of the warrant the bridge asked for. The warrant the
/// kernel is asked for is badged with the principal, lasts as long as the client's
/// warrant (and no longer than the cap), and carries the op's declared deadline.
/// **Red when** the receipt is 0 or another task's record, the badge is not the
/// principal, or the life is not bounded by the client's warrant.
#[test]
fn a_call_is_one_warrant_and_returns_its_receipt() {
    let mut s = session();
    s.k.lamp.level = 9;
    s.k.record_n(azos_decision::Rule::CapDenial, azos_decision::Verdict::Deny, ME + 1, [0, 0, 0]);
    let w = agent(AGENT, LAMP.id, &[GET], T0 + 500_000_000);
    let a = s.call("lamp.get", "{}", Some(&w));
    assert!(!is_error(&a), "{a:?}");
    assert_eq!(status(&a), "served");
    assert_eq!(structured(&a).get("words").and_then(Value::as_array).unwrap(), &[Value::Int(9)]);
    assert_eq!(field_i64(&a, "principal"), AGENT as i64);
    // The receipt is the derive record the kernel wrote for this warrant.
    let id = receipt(&a);
    let rec = s.k.journal.iter().find(|p| p.seq as i64 == id).unwrap();
    assert_eq!((rec.rule, rec.verdict), (azos_decision::Rule::CapDerive as u8, azos_decision::Verdict::Admit as u8));
    assert_eq!(rec.n[2], T0 + 500_000_000, "the expiry the bridge asked for tells the record");
    assert_eq!(structured(&a).get("rule").and_then(Value::as_str), Some("cap-derive"));
    assert_eq!(structured(&a).get("verdict").and_then(Value::as_str), Some("admit"));
    let text = result(&a).get("content").and_then(Value::as_array).unwrap()[0].get("text").and_then(Value::as_str).unwrap();
    assert!(text.contains(&format!("Receipt {id}")), "{text}");
    // The one warrant.
    assert_eq!(s.k.warrants.len(), 1);
    let w = s.k.warrants[0];
    assert_eq!(w.badge, AGENT);
    assert_eq!(w.life_ns, 500_000_000, "the client's warrant bounds the kernel's");
    assert_eq!(w.deadline_ns, 500_000_000);
}

/// Another task's derive written while the call is made is not the receipt:
/// the warrant's own expiry tells the record. **Red when** `derive_of` takes the
/// first admission after the mark.
#[test]
fn the_receipt_is_this_calls_derive_not_a_neighbours() {
    let mut s = session();
    s.k.foreign_derive_first = true;
    let w = agent(AGENT, LAMP.id, &[GET], T0 + 500_000_000);
    let a = s.call("lamp.get", "{}", Some(&w));
    let rec = s.k.journal.iter().find(|p| p.seq as i64 == receipt(&a)).unwrap();
    assert_eq!((rec.subject, rec.n[2]), (DOMAIN, T0 + 500_000_000));
}

/// A kernel warrant never outlives the cap, and the call's deadline is the
/// op's own when it declares one. **Red when** `warrant_max_ns` is ignored.
#[test]
fn the_kernel_warrant_is_capped() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[GET], T0 + 3_600_000_000_000);
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
    assert_eq!(s.k.warrants[0].life_ns, config().warrant_max_ns);
}

/// A call the kernel refuses is an error result with the receipt of the
/// refusal: a record under the bridge's task id. **Red when** the receipt of a
/// refusal is 0, or a record of another task is taken for it.
#[test]
fn a_refusal_by_the_kernel_returns_the_refusal_as_the_receipt() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[GET], T10);
    s.k.grant = false;
    s.k.record_n(azos_decision::Rule::CapDenial, azos_decision::Verdict::Deny, ME + 1, [0, 0, 0]);
    let a = s.call("lamp.get", "{}", Some(&w));
    assert!(is_error(&a));
    assert_eq!((status(&a), reason(&a)), ("refused", "kernel-refused"));
    let rec = s.k.journal.iter().find(|p| p.seq as i64 == receipt(&a)).unwrap();
    assert_eq!((rec.subject, rec.rule), (ME, azos_decision::Rule::CapDenial as u8));
    assert_eq!(structured(&a).get("rule").and_then(Value::as_str), Some("cap-denial"));
    // A refused call through an admitted warrant: the newer record is the receipt.
    s.k.grant = true;
    s.k.refuse_call = true;
    let a = s.call("lamp.get", "{}", Some(&w));
    assert_eq!(status(&a), "refused");
    let rec = s.k.journal.iter().find(|p| p.seq as i64 == receipt(&a)).unwrap();
    assert_eq!((rec.subject, rec.rule), (ME, azos_decision::Rule::CapDenial as u8));
    // Without admissions kept, an admitted call has no receipt, and says 0.
    s.k.refuse_call = false;
    s.k.keep_admits = false;
    let a = s.call("lamp.get", "{}", Some(&w));
    assert_eq!((status(&a), receipt(&a)), ("served", 0));
}

/// A server that dies holding the call leaves the outcome unknown, which is
/// said, not called a refusal. **Red when** `EPEERDIED` is reported as refused.
#[test]
fn a_lost_answer_is_unknown_not_refused() {
    let mut s = session();
    s.k.peer_dies = true;
    let w = agent(AGENT, LAMP.id, &[GET], T10);
    let a = s.call("lamp.get", "{}", Some(&w));
    assert!(is_error(&a));
    assert_eq!(status(&a), "unknown");
}

/// Words outside a JSON integer go out as hex text; negative or missing
/// arguments are refused as results, not as protocol errors. **Red when** a
/// word above `i64::MAX` is truncated into an integer.
#[test]
fn words_and_arguments_keep_their_shape() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[GET, 3], T10);
    let a = s.call("lamp.wide", "{}", Some(&w));
    assert_eq!(structured(&a).get("words").and_then(Value::as_array).unwrap(), &[Value::str("0xfffffffffffffffe")]);
    // The decisions interface takes two words: the wrong count is refused.
    let dw = agent(AGENT, DECISIONS.id, &[1, 2], T10);
    for args in [r#"{}"#, r#"{"args":[1]}"#, r#"{"args":[1,-2]}"#, r#"{"args":[1,"2"]}"#, r#"{"args":[1,2],"x":1}"#, r#"{"args":5}"#] {
        let a = s.call("decisions.query", args, Some(&dw));
        assert_eq!((status(&a), reason(&a)), ("invalid", "bad-arguments"), "{args}");
        assert!(is_error(&a));
    }
    assert_eq!(s.k.invokes, 1, "only the first call reached the kernel");
}

/// A tool that does not exist is a protocol error, not a failed tool.
/// **Red when** it is answered as an `isError` result.
#[test]
fn an_unknown_tool_is_a_protocol_error() {
    let mut s = session();
    for name in ["lamp.nothing", "toaster.get", "lamp", "odd.plain", ""] {
        let a = s.call(name, "{}", None);
        assert_eq!(a.get("error").and_then(|e| e.get("code")).and_then(Value::as_i64), Some(-32602), "{name}: {a:?}");
    }
}

// ── an irreversible op: propose, confirm, commit ─────────────────────────────

/// Calling an irreversible op's tool proposes it and runs nothing: no kernel
/// call, the level unchanged, a proposal id, a digest and the clock to sign the
/// confirmation for. **Red when** the tool runs the op.
#[test]
fn an_irreversible_op_is_proposed_not_run() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[SET], T10);
    let a = s.call("lamp.set", r#"{"args":[5]}"#, Some(&w));
    assert!(!is_error(&a), "{a:?}");
    assert_eq!(status(&a), "proposed");
    assert_eq!(s.k.invokes, 0);
    assert_eq!((s.k.lamp.sets, s.k.lamp.level), (0, 0));
    assert!(field_i64(&a, "proposal") > 0);
    assert_eq!(structured(&a).get("digest").and_then(Value::as_str).unwrap().len(), 16);
    assert_eq!(field_i64(&a, "now_ns"), T0 as i64);
    assert_eq!(field_i64(&a, "control_interface"), CONTROL_ID as i64);
    assert_eq!(receipt(&a), 0, "a proposal touches no kernel object");
    let text = result(&a).get("content").and_then(Value::as_array).unwrap()[0].get("text").and_then(Value::as_str).unwrap();
    assert!(text.contains("NOT run"), "{text}");
    // The proposal needs the warrant to name the op, as a call does.
    let w = agent(AGENT, LAMP.id, &[GET], T10);
    assert_eq!(reason(&s.call("lamp.set", r#"{"args":[5]}"#, Some(&w))), "op-denied");
}

/// Commit before the human confirmed refuses and runs nothing. **Red when**
/// `commit` does not look at the proposal's state.
#[test]
fn commit_without_confirmation_is_refused() {
    let mut s = session();
    let (id, _) = propose(&mut s, 5);
    let w = agent(AGENT, LAMP.id, &[SET], T10);
    let a = commit(&mut s, id, &w);
    assert_eq!((status(&a), reason(&a)), ("refused", "not-confirmed"));
    assert_eq!((s.k.invokes, s.k.lamp.sets), (0, 0));
    // An unknown proposal.
    assert_eq!(reason(&commit(&mut s, id + 1, &w)), "unknown-proposal");
}

/// The whole path: propose, a human confirms with a one-shot warrant bound to
/// that proposal, the agent commits. The op runs once, with the deadline the op
/// declares; the answer carries the receipt; a second commit and a replayed
/// confirmation run nothing. **Red when** commit does not mark the proposal
/// spent, or runs it with no deadline, or the receipt is missing.
#[test]
fn propose_confirm_commit_runs_the_op_once() {
    let mut s = session();
    s.k.lamp.level = 3;
    let (id, digest) = propose(&mut s, 5);
    let h = human(HUMAN, id, T10);
    let c = confirm(&mut s, id, &digest, &h);
    assert_eq!(status(&c), "confirmed", "{c:?}");
    assert_eq!(field_i64(&c, "confirmed_by"), HUMAN as i64);
    assert_eq!(s.k.invokes, 0, "a confirmation runs nothing");

    let w = agent(AGENT, LAMP.id, &[SET], T10);
    let a = commit(&mut s, id, &w);
    assert!(!is_error(&a), "{a:?}");
    assert_eq!(status(&a), "served");
    assert_eq!(structured(&a).get("words").and_then(Value::as_array).unwrap(), &[Value::Int(3)], "the level before");
    assert_eq!((s.k.lamp.sets, s.k.lamp.level), (1, 5));
    assert!(receipt(&a) > 0);
    assert_eq!(field_i64(&a, "proposal"), id as i64);
    // B2: the call carries the op's declared deadline (50 ms), under the warrant's life.
    assert_eq!(s.k.warrants.len(), 1);
    assert_eq!(s.k.warrants[0].badge, AGENT);
    assert_eq!(s.k.warrants[0].deadline_ns, 50_000_000);
    assert!(s.k.warrants[0].life_ns <= config().warrant_max_ns);

    // Never twice.
    let again = commit(&mut s, id, &w);
    assert_eq!((status(&again), reason(&again)), ("refused", "already-committed"));
    let replay = confirm(&mut s, id, &digest, &h);
    assert_eq!(status(&replay), "refused");
    assert_eq!((s.k.invokes, s.k.lamp.sets), (1, 1));
}

/// The commit is spent before the call: whatever the kernel does with it, the
/// proposal is not run again. **Red when** the state is set after the call, or
/// only on success.
#[test]
fn a_failed_commit_is_not_retried() {
    let mut s = session();
    let (id, digest) = propose(&mut s, 5);
    assert_eq!(status(&confirm(&mut s, id, &digest, &human(HUMAN, id, T10))), "confirmed");
    let w = agent(AGENT, LAMP.id, &[SET], T10);
    s.k.peer_dies = true;
    let a = commit(&mut s, id, &w);
    assert_eq!(status(&a), "unknown");
    s.k.peer_dies = false;
    let b = commit(&mut s, id, &w);
    assert_eq!(reason(&b), "already-committed");
    assert_eq!((s.k.invokes, s.k.lamp.sets), (1, 0));
}

/// The human's warrant is one-shot and bound: signed with the human key, for
/// the control interface, for this proposal (a token for another proposal does
/// not verify), with a `QUOTA` of exactly 1 and an op mask naming confirm, by
/// someone other than the proposer, with the digest the human saw. **Red when**
/// any of these is not held: confirm with an agent's token, a token of another
/// proposal, a quota of 2 or none, a mask without confirm, the proposer's own
/// id, a wrong digest.
#[test]
fn only_a_one_shot_human_warrant_bound_to_the_proposal_confirms() {
    let mut s = session();
    let (id, digest) = propose(&mut s, 5);
    let (other, other_digest) = propose(&mut s, 6);
    assert_ne!(id, other);
    let expect = |s: &mut Session, w: &Token, why: &str| {
        let a = confirm(s, id, &digest, w);
        assert!(is_error(&a), "{why}: {a:?}");
        assert_eq!(reason(&a), why, "{a:?}");
    };
    // The agent's own warrant (signed with the agent key) is not a human's.
    let as_agent = agent_token(
        AGENT, EPOCH, CONTROL_ID,
        &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[CONFIRM_OP])), (cav::QUOTA, 1)],
    );
    expect(&mut s, &as_agent, "bad-chain");
    // A human's warrant for another proposal does not open this one.
    expect(&mut s, &human(HUMAN, other, T10), "bad-chain");
    // Not one-shot: no quota, a quota of 2.
    let no_quota = human_token(HUMAN, id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[CONFIRM_OP]))]);
    expect(&mut s, &no_quota, "not-one-shot");
    let two = human_token(HUMAN, id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[CONFIRM_OP])), (cav::QUOTA, 2)]);
    expect(&mut s, &two, "not-one-shot");
    // Does not name confirm; does not expire.
    let wrong_op = human_token(HUMAN, id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[5])), (cav::QUOTA, 1)]);
    expect(&mut s, &wrong_op, "op-denied");
    let no_expiry = human_token(HUMAN, id, &[(cav::OP_MASK, mask(&[CONFIRM_OP])), (cav::QUOTA, 1)]);
    expect(&mut s, &no_expiry, "no-expiry");
    // The proposer does not confirm its own proposal.
    expect(&mut s, &human(AGENT, id, T10), "same-principal");
    // The digest must be what the human saw.
    let a = confirm(&mut s, id, &other_digest, &human(HUMAN, id, T10));
    assert_eq!(reason(&a), "digest-mismatch");
    // Nothing above spent the proposal or the human's use: the good one works.
    let good = human(HUMAN, id, T10);
    assert_eq!(status(&confirm(&mut s, id, &digest, &good)), "confirmed");
    // The same warrant again: the proposal is no longer waiting.
    assert_eq!(reason(&confirm(&mut s, id, &digest, &good)), "not-pending");
    assert_eq!(s.k.invokes, 0);
}

/// Another principal's commit is refused: a proposal is its proposer's. And a
/// commit under a warrant whose mask has lost the op is refused. **Red when**
/// the principal is not compared, or the commit does not test the mask.
#[test]
fn only_the_proposer_with_the_op_in_its_mask_commits() {
    let mut s = session();
    let (id, digest) = propose(&mut s, 5);
    assert_eq!(status(&confirm(&mut s, id, &digest, &human(HUMAN, id, T10))), "confirmed");
    let other = agent(AGENT + 1, LAMP.id, &[SET], T10);
    assert_eq!(reason(&commit(&mut s, id, &other)), "other-principal");
    let narrowed = agent(AGENT, LAMP.id, &[GET], T10);
    assert_eq!(reason(&commit(&mut s, id, &narrowed)), "op-denied");
    assert_eq!(reason(&commit(&mut s, id, &agent(AGENT, ODD.id, &[SET], T10))), "wrong-interface");
    assert_eq!(s.k.invokes, 0);
    // The proposer's own does.
    assert_eq!(status(&commit(&mut s, id, &agent(AGENT, LAMP.id, &[SET], T10))), "served");
}

/// A proposal lapses: with its time-to-live, or with the agent's warrant,
/// whichever is first; a lapsed one can be neither confirmed nor committed.
/// **Red when** the lapse is not tested, or the warrant's expiry does not bound
/// the proposal.
#[test]
fn a_proposal_lapses() {
    let mut s = session();
    let (id, digest) = propose(&mut s, 5);
    let h = human(HUMAN, id, T10 * 100);
    assert_eq!(status(&confirm(&mut s, id, &digest, &h)), "confirmed");
    s.k.now = T0 + config().proposal_ttl_ns;
    let w = agent(AGENT, LAMP.id, &[SET], T0 + 3 * config().proposal_ttl_ns);
    let a = commit(&mut s, id, &w);
    assert_eq!((status(&a), reason(&a)), ("refused", "unknown-proposal"));
    assert_eq!(s.k.invokes, 0);
    // The agent's warrant ends first: the proposal ends with it.
    s.k.now = T0;
    let short = agent(AGENT, LAMP.id, &[SET], T0 + 1_000);
    let a = s.call("lamp.set", r#"{"args":[1]}"#, Some(&short));
    let id = field_i64(&a, "proposal") as u32;
    assert_eq!(field_i64(&a, "expires_ns"), (T0 + 1_000) as i64);
    s.k.now = T0 + 1_000;
    let h = human(HUMAN, id, T10 * 100);
    let dig = structured(&a).get("digest").and_then(Value::as_str).unwrap().to_string();
    assert_eq!(reason(&confirm(&mut s, id, &dig, &h)), "unknown-proposal");
}

/// The table of proposals is bounded and frees what lapsed. **Red when** the
/// bound is not held.
#[test]
fn proposals_are_bounded() {
    let mut s = session();
    let w = agent(AGENT, LAMP.id, &[SET], T10);
    for i in 0..PROPOSALS_MAX {
        let a = s.call("lamp.set", &format!(r#"{{"args":[{i}]}}"#), Some(&w));
        assert_eq!(status(&a), "proposed");
    }
    let a = s.call("lamp.set", r#"{"args":[99]}"#, Some(&w));
    assert_eq!((status(&a), reason(&a)), ("busy", "too-many-proposals"));
    s.k.now = T0 + config().proposal_ttl_ns;
    let w = agent(AGENT, LAMP.id, &[SET], T10 * 100);
    assert_eq!(status(&s.call("lamp.set", r#"{"args":[99]}"#, Some(&w))), "proposed");
}

/// An agent's quota is taken by the commit, not by the proposal: a warrant of
/// one use can propose twice, and runs the first commit only. **Red when** the
/// proposal spends a use, or the commit does not.
#[test]
fn the_commit_takes_the_agents_use() {
    let mut s = session();
    let w = agent_token(AGENT, EPOCH, LAMP.id, &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[SET])), (cav::QUOTA, 1)]);
    let mut ids = Vec::new();
    for level in [5, 6] {
        let a = s.call("lamp.set", &format!(r#"{{"args":[{level}]}}"#), Some(&w));
        assert_eq!(status(&a), "proposed", "{a:?}");
        let id = field_i64(&a, "proposal") as u32;
        let digest = structured(&a).get("digest").and_then(Value::as_str).unwrap().to_string();
        assert_eq!(status(&confirm(&mut s, id, &digest, &human(HUMAN, id, T10))), "confirmed");
        ids.push(id);
    }
    assert_eq!(status(&commit(&mut s, ids[0], &w)), "served");
    let a = commit(&mut s, ids[1], &w);
    assert_eq!((status(&a), reason(&a)), ("refused", "spent"));
    assert_eq!((s.k.lamp.sets, s.k.lamp.level), (1, 5));
}

// ── the rate, the lines, the batches ─────────────────────────────────────────

/// Calls over the rate are answered busy without reaching the kernel. **Red
/// when** the rate is not applied before the check of the warrant.
#[test]
fn calls_over_the_rate_are_busy() {
    let mut cfg = config();
    cfg.call_rate = 2;
    let mut s = session_with(cfg, keys(), exports());
    let w = agent(AGENT, LAMP.id, &[GET], T10);
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
    let a = s.call("lamp.get", "{}", Some(&w));
    assert_eq!((status(&a), reason(&a)), ("busy", "busy"));
    assert_eq!(s.k.invokes, 2);
    s.k.now += 1_000_000_000;
    assert_eq!(status(&s.call("lamp.get", "{}", Some(&w))), "served");
}

/// Messages are lines: two in one write, one in two writes, a blank line, and
/// a line too long that is answered and dropped to its newline. **Red when**
/// the framing keeps a partial line, or an overlong line is parsed.
#[test]
fn messages_are_newline_delimited_lines() {
    let mut s = session();
    s.raw(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n");
    let out = s.take();
    assert_eq!(out.len(), 2);
    s.raw(b"{\"jsonrpc\":\"2.0\",\"id\":3,");
    assert!(s.take().is_empty(), "no answer to half a line");
    s.raw(b"\"method\":\"ping\"}\r\n");
    assert_eq!(s.take().len(), 1);
    // Not JSON, not UTF-8.
    s.line("{nope");
    let e = s.take();
    assert_eq!(e[0].get("error").and_then(|e| e.get("code")).and_then(Value::as_i64), Some(-32700));
    s.raw(&[0xff, 0xfe, b'\n']);
    assert_eq!(s.take().len(), 1);
    // A line over the limit arrives in pieces: one error, then the next line is read.
    s.raw(&vec![b'x'; LINE_MAX]);
    s.raw(&vec![b'x'; 10]);
    let e = s.take();
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].get("error").and_then(|e| e.get("code")).and_then(Value::as_i64), Some(-32700));
    s.raw(b"more of the same line\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n");
    let after = s.take();
    assert_eq!(after.len(), 1, "{after:?}");
    assert_eq!(after[0].get("id").and_then(Value::as_i64), Some(9));
    // A whole line over the limit in one write.
    let mut big = vec![b'y'; LINE_MAX + 5];
    big.push(b'\n');
    s.raw(&big);
    assert_eq!(s.take().len(), 1);
}

/// A batch is answered as a batch, a notification in it is not answered.
/// **Red when** the batch is dropped or answered line by line.
#[test]
fn a_batch_is_answered_as_a_batch() {
    let mut s = session();
    s.line(
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/cancelled"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]"#,
    );
    let out = s.take();
    assert_eq!(out.len(), 1);
    let items = out[0].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[1].get("result").and_then(|r| r.get("tools")).is_some());
}

/// A reconnect forgets the handshake but not the proposals or the quota. **Red
/// when** `reset` clears the ledger or the proposals.
#[test]
fn a_new_link_keeps_proposals_and_spent_quotas() {
    let mut s = session();
    let (id, digest) = propose(&mut s, 5);
    s.bridge.reset();
    let a = s.request("tools/list", "{}");
    assert!(a.get("error").is_some(), "the handshake is to be done again");
    s.request("initialize", r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"s","version":"1"}}"#);
    s.notify("notifications/initialized");
    assert_eq!(status(&confirm(&mut s, id, &digest, &human(HUMAN, id, T10))), "confirmed");
}

// ── the operator's grants ────────────────────────────────────────────────────

const OPERATOR: u32 = 1;

fn warrant_of(a: &Value) -> String {
    structured(a).get("warrant").and_then(Value::as_str).unwrap_or_else(|| panic!("a warrant: {a:?}")).to_string()
}

/// The operator issues an agent's warrant by name, and what comes back is the
/// warrant the agent presents: the principal as issuer, the interface, the
/// expiry, the mask of the named ops, the count. **Red when** the mask is built
/// from anything but the op numbers of the table, the expiry ignores the
/// clock, or the count is dropped.
#[test]
fn the_operator_issues_an_agents_warrant_that_works() {
    let mut s = session();
    let op = admin(OPERATOR, T10);
    let a = s.call(
        "azos.grant_agent",
        r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":5000,"uses":2}"#,
        Some(&op),
    );
    assert_eq!((status(&a), is_error(&a)), ("granted", false), "{a:?}");
    assert_eq!(field_i64(&a, "expires_ns"), (T0 + 5_000_000_000) as i64);
    let h = warrant_of(&a);
    let tok = warrant::parse(&h).unwrap();
    assert_eq!((tok.issuer, tok.iface), (AGENT, LAMP.id));
    let got: Vec<(u8, u64)> = tok.caveats().iter().map(|c| (c.kind, c.arg)).collect();
    assert_eq!(got, [(cav::EXPIRY, T0 + 5_000_000_000), (cav::OP_MASK, mask(&[GET])), (cav::QUOTA, 2)]);
    // It is the agent's warrant: two uses of the op it names, none of another.
    assert_eq!(status(&s.call_hex("lamp.get", "{}", Some(&h))), "served");
    assert_eq!(reason(&s.call_hex("lamp.set", r#"{"args":[1]}"#, Some(&h))), "op-denied");
    assert_eq!(status(&s.call_hex("lamp.get", "{}", Some(&h))), "served");
    assert_eq!(reason(&s.call_hex("lamp.get", "{}", Some(&h))), "spent");
    // And it runs out with the clock.
    let b = s.call("azos.grant_agent", r#"{"principal":101,"interface":"lamp","ops":["get","wide"],"ttl_ms":5000}"#, Some(&op));
    let h = warrant_of(&b);
    assert_eq!(status(&s.call_hex("lamp.wide", "{}", Some(&h))), "served");
    s.k.now = T0 + 5_000_000_000;
    assert_eq!(reason(&s.call_hex("lamp.get", "{}", Some(&h))), "lapsed");
}

/// Only the operator's warrant issues one: not none, not an agent's, not a
/// human's, not one of another boot, not one that does not name the grant, not
/// a lapsed one. **Red when** the grant skips the check of the operator's
/// warrant or checks it under the agent's key.
#[test]
fn only_the_operators_warrant_grants() {
    let mut s = session();
    let args = r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":5000}"#;
    let try_with = |s: &mut Session, w: Option<&Token>| {
        let a = s.call("azos.grant_agent", args, w);
        assert!(is_error(&a), "{a:?}");
        reason(&a).to_string()
    };
    assert_eq!(try_with(&mut s, None), "no-warrant");
    // An agent's warrant, for the control interface, under the agent's key.
    let as_agent = agent_token(
        OPERATOR, EPOCH, CONTROL_ID,
        &[(cav::EXPIRY, T10), (cav::OP_MASK, mask(&[crate::catalog::GRANT_OP]))],
    );
    assert_eq!(try_with(&mut s, Some(&as_agent)), "bad-chain");
    assert_eq!(try_with(&mut s, Some(&agent(AGENT, LAMP.id, &[GET], T10))), "wrong-interface");
    // A human's confirmation warrant.
    assert_eq!(try_with(&mut s, Some(&human(HUMAN, 5, T10))), "bad-chain");
    // The operator's, in another boot, not naming the grant, lapsed.
    let mut other_boot = Token::mint(&keys().admin(OPERATOR), EPOCH ^ 1, OPERATOR, CONTROL_ID);
    other_boot.attenuate(Caveat::new(cav::EXPIRY, T10)).unwrap();
    other_boot.attenuate(Caveat::new(cav::OP_MASK, mask(&[crate::catalog::GRANT_OP]))).unwrap();
    assert_eq!(try_with(&mut s, Some(&other_boot)), "bad-chain");
    let mut wrong_op = Token::mint(&keys().admin(OPERATOR), EPOCH, OPERATOR, CONTROL_ID);
    wrong_op.attenuate(Caveat::new(cav::EXPIRY, T10)).unwrap();
    wrong_op.attenuate(Caveat::new(cav::OP_MASK, mask(&[CONFIRM_OP]))).unwrap();
    assert_eq!(try_with(&mut s, Some(&wrong_op)), "op-denied");
    assert_eq!(try_with(&mut s, Some(&admin(OPERATOR, T0))), "lapsed");
    // The operator's own works.
    assert_eq!(status(&s.call("azos.grant_agent", args, Some(&admin(OPERATOR, T10)))), "granted");
}

/// A grant names what it grants and is capped: unknown interfaces and ops, a
/// life over the cap or over the operator's own warrant, arguments out of
/// shape. **Red when** an op that is not a tool can be granted, or the life is
/// not bounded by the operator's warrant and the cap.
#[test]
fn a_grant_names_its_ops_and_is_capped() {
    let mut s = session();
    let op = admin(OPERATOR, T10);
    let g = |s: &mut Session, args: &str| s.call("azos.grant_agent", args, Some(&op));
    let a = g(&mut s, r#"{"principal":101,"interface":"toaster","ops":["get"],"ttl_ms":5000}"#);
    assert_eq!(reason(&a), "unknown-interface");
    let a = g(&mut s, r#"{"principal":101,"interface":"odd","ops":["plain"],"ttl_ms":5000}"#);
    assert_eq!(reason(&a), "unknown-op", "an op that declares no delivery is not a tool, so it is not grantable");
    let a = g(&mut s, r#"{"principal":101,"interface":"lamp","ops":["get","nothing"],"ttl_ms":5000}"#);
    assert_eq!(reason(&a), "unknown-op");
    // A year is more than the operator's warrant has left: it ends with it.
    let a = g(&mut s, r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":31536000000}"#);
    assert_eq!(field_i64(&a, "expires_ns"), T10 as i64);
    // And the cap holds for a longer-lived operator.
    let long = admin(OPERATOR, T0 * 100_000);
    let a = s.call("azos.grant_agent", r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":31536000000}"#, Some(&long));
    assert_eq!(field_i64(&a, "expires_ns"), (T0 + config().grant_max_ns) as i64);
    for bad in [
        r#"{"principal":0,"interface":"lamp","ops":["get"],"ttl_ms":5000}"#,
        r#"{"principal":101,"interface":"lamp","ops":[],"ttl_ms":5000}"#,
        r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":0}"#,
        r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":5000,"uses":0}"#,
        r#"{"principal":101,"interface":"lamp","ops":[1],"ttl_ms":5000}"#,
        r#"{"principal":101,"interface":"lamp","ops":["get"],"ttl_ms":5000,"admin":true}"#,
        r#"{"principal":101,"interface":"lamp","ops":["get"]}"#,
    ] {
        let a = g(&mut s, bad);
        assert_eq!((status(&a), reason(&a)), ("invalid", "bad-arguments"), "{bad}");
    }
}

/// The whole path with nothing but the bridge's own warrants: the operator
/// grants the agent its op, the agent proposes, the operator issues a human's
/// one-shot warrant for that proposal, the human confirms, the agent commits.
/// The grant of a confirmation names a waiting proposal and another principal
/// than the proposer; the warrant it returns opens that proposal once.
/// **Red when** the confirmation can be granted for a proposal that is not
/// waiting or to the proposer, or outlives the proposal.
#[test]
fn the_bridge_issues_every_warrant_of_the_irreversible_path() {
    let mut s = session();
    s.k.lamp.level = 3;
    let op = admin(OPERATOR, T0 + 3_600_000_000_000);
    let a = s.call("azos.grant_agent", r#"{"principal":101,"interface":"lamp","ops":["set"],"ttl_ms":60000}"#, Some(&op));
    let agent_w = warrant_of(&a);
    let p = s.call_hex("lamp.set", r#"{"args":[8]}"#, Some(&agent_w));
    assert_eq!(status(&p), "proposed", "{p:?}");
    let id = field_i64(&p, "proposal");
    let digest = structured(&p).get("digest").and_then(Value::as_str).unwrap().to_string();
    let grant = |s: &mut Session, id: i64, who: u32| {
        s.call("azos.grant_confirm", &format!(r#"{{"proposal":{id},"principal":{who},"ttl_ms":600000}}"#), Some(&op))
    };
    // Not for the proposer, not for a proposal that does not exist.
    assert_eq!(reason(&grant(&mut s, id, AGENT)), "same-principal");
    assert_eq!(reason(&grant(&mut s, id + 1, HUMAN)), "unknown-proposal");
    let g = grant(&mut s, id, HUMAN);
    assert_eq!(status(&g), "granted", "{g:?}");
    assert_eq!(structured(&g).get("digest").and_then(Value::as_str), Some(digest.as_str()));
    // It lapses with the proposal (60 s), not with its own ten minutes.
    assert_eq!(field_i64(&g, "expires_ns"), (T0 + 60_000_000_000) as i64);
    let human_w = warrant_of(&g);
    let tok = warrant::parse(&human_w).unwrap();
    assert_eq!((tok.issuer, tok.iface), (HUMAN, CONTROL_ID));
    let c = s.call_hex("azos.confirm", &format!(r#"{{"proposal":{id},"digest":"{digest}"}}"#), Some(&human_w));
    assert_eq!(status(&c), "confirmed", "{c:?}");
    // A confirmed proposal is not waiting: no second confirmation warrant, no replay.
    assert_eq!(reason(&grant(&mut s, id, HUMAN + 1)), "not-pending");
    let again = s.call_hex("azos.confirm", &format!(r#"{{"proposal":{id},"digest":"{digest}"}}"#), Some(&human_w));
    assert_eq!(status(&again), "refused");
    let done = s.call_hex("azos.commit", &format!(r#"{{"proposal":{id}}}"#), Some(&agent_w));
    assert_eq!(status(&done), "served", "{done:?}");
    assert_eq!((s.k.lamp.sets, s.k.lamp.level), (1, 8));
    assert!(receipt(&done) > 0);
}
