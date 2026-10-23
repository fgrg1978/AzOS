// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The bridge engine: one MCP server session over a stream link, the tools the
//! IDL interfaces make ([`crate::catalog`]), and the rule that decides who may
//! call which.
//!
//! Pure: no socket, no clock, no capability of its own. The kernel host
//! (`main.rs`) and the host tests (`tests/host/mcpd-tests`, a scripted client)
//! implement [`Host`] (time, the two kinds of call) and [`Link`] (bytes out);
//! the engine is fed the bytes that come in.
//!
//! # The transport
//!
//! MCP over a byte stream, as its stdio transport frames it: one JSON-RPC
//! message (or batch) per line, `\n`-terminated, no newline inside. The
//! codec is `userspace/lib/mcp`. The daemon dials out (`MCP_PEER_ADDR`: a
//! relay or the agent's host listens) and serves the MCP server role over
//! that one stream; one client speaks on it at a time. A longer line
//! than [`LINE_MAX`] is answered with a parse error and dropped to its newline.
//!
//! # A call is a warrant, an op and a receipt
//!
//! `tools/call` of `<interface>.<op>`: the arguments are the op's request words
//! ([`crate::catalog`]), the client's authority is the token in
//! `params._meta["azos/warrant"]` ([`crate::warrant`]: an `OP_MASK` that names
//! the op, an `EXPIRY`, a principal). **The bridge holds the authority of its
//! row and no more, and lends none:** for each call it asks the kernel for a
//! warrant (`Host::invoke`: an attenuated copy of the interface's endpoint, call
//! right only, badged with the principal's Domain id, one use, lapsing with the
//! client's warrant), calls the op through it and drops it. The kernel admits
//! or refuses the derive and the call, and the answer carries the decision
//! record that is the receipt (`structuredContent.receipt`, [`crate::receipt`]).
//!
//! A call the bridge itself refuses (no warrant, a mask that does not name the
//! op, a lapsed token) never reaches the kernel: `isError: true`, a `reason`, and
//! receipt 0. **A tool that fails is a normal result; a JSON-RPC error is for
//! the protocol only** (an unknown tool, malformed params).
//!
//! # Irreversible ops: propose, confirm, commit
//!
//! An op declared `#[once_only]` is never run by its own tool. Calling it
//! (`<interface>.<op>`, with the agent's warrant) **proposes** it: the bridge
//! keeps `{principal, op, arguments}` as a proposal that lapses after
//! `MCP_PROPOSAL_TTL_MS` (or with the agent's warrant, whichever is first), runs
//! nothing, and answers with the proposal id, a digest of what is proposed and
//! the clock. A human then **confirms** it (`azos.confirm`, with the proposal
//! id and the digest, under a one-shot human warrant bound to that proposal:
//! another human than the proposing principal, a `QUOTA` of 1). The agent then
//! **commits** it (`azos.commit`, under its own warrant): the bridge marks the
//! proposal spent *before* the call, so a second commit finds nothing to run,
//! and calls the op once, with the op's declared deadline (and never later than
//! the warrant or the proposal) as the call's deadline, so the kernel refuses a
//! call whose time has gone before it queues anything. The answer to a commit
//! is never asked for again: if it is lost (`unknown`), the outcome is
//! unknown, which the status says, and a new proposal is a new decision.
//!
//! # Who issues the warrants
//!
//! The bridge, to an operator. Its root key is the image's own DICE key, which
//! never leaves it ([`crate::warrant`]), so there is no one else to sign. At
//! boot the host prints an **operator's warrant** on the board's console
//! (`main.rs`, lapsing after `MCP_ENROL_TTL_MS`): whoever reads it holds the
//! console, which is the human the system already trusts. With it
//! `azos.grant_agent` issues an agent's warrant for named ops of an interface
//! (intent-scoped: the ops, the time, optionally the count), and
//! `azos.grant_confirm` a human's one-shot warrant for one waiting proposal.
//! Both are capped by `MCP_GRANT_MAX_MS` and by the operator's own warrant.
//!
//! # What is not done
//!
//! Only tools: no resources, prompts, sampling, cancellation or progress.
//! Batches are answered as a batch. The client is told nothing it did not ask:
//! the server sends no notification.

use crate::catalog::{
    self, Export, CONFIRM_OP, CONTROL_ID, GRANT_OP, TOOL_COMMIT, TOOL_CONFIRM, TOOL_GRANT_AGENT, TOOL_GRANT_CONFIRM,
};
use crate::receipt;
use crate::warrant::{self, Grant, Keys, Ledger, Refusal, Scope};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use azos_abi::error::Errno;
use azos_crypto::sha256::sha256;
use azos_decisions::{ProvenanceRecord, RULES, VERDICTS};
use azos_idl::{header, MsgDesc, MSG_VERSION, MSG_WORDS_MAX, STATUS_OK};
use azos_mcp::json::Value;
use azos_mcp::jsonrpc::{self, Incoming, Message, Request, RpcError};
use azos_mcp::mcp::{
    is_initialized, Content, Implementation, InitializeResult, McpRequest, ToolCallParams, ToolCallResult,
};

/// The key of the warrant in a request's `_meta`.
pub const META_WARRANT: &str = "azos/warrant";
/// The longest line the bridge reads, bytes.
pub const LINE_MAX: usize = 16 * 1024;
/// Proposals held at once.
pub const PROPOSALS_MAX: usize = 8;
/// A pending proposal's digest: the first bytes of a SHA-256, shown in hex.
pub const DIGEST_BYTES: usize = 8;

/// The settings, from Kconfig and the entropy pool.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// This boot's epoch: the session of an agent's warrants, and the base of
    /// the proposal ids. Random, so a token of an earlier boot verifies nowhere.
    pub epoch: u32,
    /// Calls served per second, at most.
    pub call_rate: u32,
    /// The longest a kernel warrant lives, ns.
    pub warrant_max_ns: u64,
    /// How long a proposal waits for its confirmation and commit, ns.
    pub proposal_ttl_ns: u64,
    /// The longest a warrant the bridge issues lives, ns.
    pub grant_max_ns: u64,
    /// The subject the kernel writes this task's refusals under: its task id.
    pub me: u32,
}

/// The authority of one call, relative to the moment the host mints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Warrant {
    /// The principal's Domain id (never 0): the server sees it as the badge of
    /// the call. The principal was authenticated by its token's chain.
    pub badge: u32,
    /// The warrant lapses this long after it is minted. It carries one use.
    pub life_ns: u64,
    /// The call's deadline, from the call.
    pub deadline_ns: u64,
}

/// What the engine needs from its surroundings.
pub trait Host {
    fn now_ns(&mut self) -> u64;
    fn log(&mut self, line: &str);
    /// Call `req` on the export endpoint `endpoint` through a warrant minted for
    /// the call and dropped after it; the reply replaces `req`.
    fn invoke(&mut self, endpoint: u32, req: &mut MsgDesc, w: &Warrant) -> Invoked;
    /// One call on the `Decisions` endpoint.
    fn decisions(&mut self, req: &mut MsgDesc) -> Result<(), i64>;
}

/// What [`Host::invoke`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invoked {
    /// `Err` is the kernel's negative code: the warrant or the call was refused.
    pub result: Result<(), i64>,
    /// The expiry the warrant was minted with, absolute nanoseconds; 0 when
    /// none was minted.
    pub expiry_ns: u64,
}

/// Where bytes go.
pub trait Link {
    fn send(&mut self, bytes: &[u8]) -> bool;
}

/// What the engine counted: the tests read it, the host logs it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub calls: u32,
    pub served: u32,
    pub refused: u32,
    pub failed: u32,
    pub busy: u32,
    pub proposed: u32,
    pub confirmed: u32,
    pub committed: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// `initialize` not seen.
    Fresh,
    /// `initialize` answered; `notifications/initialized` not yet.
    Initialized,
    Ready,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Proposed,
    Confirmed { by: u32 },
    Spent,
}

struct Proposal {
    id: u32,
    principal: u32,
    export: Export,
    op: &'static azos_idl::OpInfo,
    args: Vec<u64>,
    digest: [u8; DIGEST_BYTES],
    deadline_ns: u64,
    state: State,
}

/// The session.
pub struct Bridge {
    cfg: Config,
    keys: Keys,
    exports: Vec<Export>,
    phase: Phase,
    rx: Vec<u8>,
    discarding: bool,
    ledger: Ledger,
    proposals: Vec<Proposal>,
    next_proposal: u32,
    window_start: u64,
    window_count: u32,
    pub stats: Stats,
}

fn word_value(w: u64) -> Value {
    if w <= i64::MAX as u64 {
        Value::Int(w as i64)
    } else {
        Value::Str(format!("{w:#x}"))
    }
}

/// A tool's answer under construction.
struct Answer {
    status: &'static str,
    error: bool,
    text: String,
    fields: Vec<(String, Value)>,
}

impl Answer {
    fn new(status: &'static str, error: bool, text: String) -> Answer {
        Answer { status, error, text, fields: Vec::new() }
    }

    fn with(mut self, key: &str, v: Value) -> Answer {
        self.fields.push((String::from(key), v));
        self
    }

    /// The result, with the receipt: its id (0 when the kernel wrote none for
    /// the call), and the rule and verdict it names.
    fn finish(self, receipt: Option<&ProvenanceRecord>) -> ToolCallResult {
        let mut m = alloc::vec![(String::from("status"), Value::str(self.status))];
        m.extend(self.fields);
        m.push((String::from("receipt"), Value::Int(receipt.map_or(0, |p| p.seq) as i64)));
        let mut text = self.text;
        if let Some(p) = receipt {
            let rule = RULES.get(p.rule as usize).map_or("unknown", |r| r.name);
            let verdict = VERDICTS.get(p.verdict as usize).copied().unwrap_or("unknown");
            m.push((String::from("rule"), Value::str(rule)));
            m.push((String::from("verdict"), Value::str(verdict)));
            text.push_str(&format!(" Receipt {} ({rule}/{verdict}): why {}.", p.seq, p.seq));
        }
        ToolCallResult {
            content: alloc::vec![Content::Text(text)],
            structured_content: Some(Value::Object(m)),
            is_error: self.error,
        }
    }
}

fn refusal_answer(tool: &str, why: Refusal) -> Answer {
    Answer::new("refused", true, format!("{tool}: refused before any call ({}).", why.name())).with("reason", Value::str(why.name()))
}

fn bad_args(tool: &str, why: &str) -> Answer {
    Answer::new("invalid", true, format!("{tool}: {why}.")).with("reason", Value::str("bad-arguments"))
}

fn hex8(d: &[u8; DIGEST_BYTES]) -> String {
    warrant::to_hex(d)
}

/// The digest of what a proposal asks: the interface, the op, the arguments.
fn digest_of(iface: u32, op: u16, args: &[u64]) -> [u8; DIGEST_BYTES] {
    let mut b = Vec::with_capacity(6 + args.len() * 8);
    b.extend_from_slice(&iface.to_le_bytes());
    b.extend_from_slice(&op.to_le_bytes());
    for a in args {
        b.extend_from_slice(&a.to_le_bytes());
    }
    let d = sha256(&b);
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(&d[..DIGEST_BYTES]);
    out
}

/// A tool's `arguments`: `args`, an array of exactly `want` non-negative
/// integers (the key may be absent when `want` is 0), and nothing else.
fn words_arg(arguments: &Option<Value>, want: usize) -> Result<Vec<u64>, &'static str> {
    let empty = Value::Object(Vec::new());
    let obj = arguments.as_ref().unwrap_or(&empty);
    let Value::Object(m) = obj else { return Err("arguments must be an object") };
    if m.iter().any(|(k, _)| k != "args") {
        return Err("arguments takes only `args`");
    }
    let Some(a) = obj.get("args") else {
        return if want == 0 { Ok(Vec::new()) } else { Err("`args` is required") };
    };
    let Some(a) = a.as_array() else { return Err("`args` must be an array") };
    if a.len() != want {
        return Err("`args` has the wrong number of words for this op");
    }
    a.iter()
        .map(|v| v.as_i64().filter(|&i| i >= 0).map(|i| i as u64))
        .collect::<Option<Vec<u64>>>()
        .ok_or("every word of `args` must be a non-negative integer")
}

/// A control tool's arguments: `proposal` (a positive integer), and for
/// confirm a `digest` string; nothing else.
fn proposal_arg(arguments: &Option<Value>, digest: bool) -> Result<(u32, Option<&str>), &'static str> {
    let Some(obj @ Value::Object(m)) = arguments.as_ref() else { return Err("arguments must be an object") };
    if m.iter().any(|(k, _)| k != "proposal" && !(digest && k == "digest")) {
        return Err("unknown argument");
    }
    let id = obj.get("proposal").and_then(Value::as_i64).filter(|&i| i > 0 && i <= u32::MAX as i64);
    let Some(id) = id else { return Err("`proposal` must be a positive integer") };
    if !digest {
        return Ok((id as u32, None));
    }
    match obj.get("digest").and_then(Value::as_str) {
        Some(d) => Ok((id as u32, Some(d))),
        None => Err("`digest` must be a string"),
    }
}

/// The arguments of `azos.grant_agent`.
struct GrantArgs {
    principal: u32,
    interface: String,
    ops: Vec<String>,
    ttl_ms: i64,
    uses: u64,
}

fn int_in(obj: &Value, key: &str, lo: i64, hi: i64) -> Option<i64> {
    obj.get(key).and_then(Value::as_i64).filter(|&i| (lo..=hi).contains(&i))
}

fn only_keys(arguments: &Option<Value>, allowed: &[&str]) -> Result<(), &'static str> {
    let Some(Value::Object(m)) = arguments.as_ref() else { return Err("arguments must be an object") };
    if m.iter().any(|(k, _)| !allowed.contains(&k.as_str())) {
        return Err("unknown argument");
    }
    Ok(())
}

fn grant_args(arguments: &Option<Value>) -> Result<GrantArgs, &'static str> {
    only_keys(arguments, &["principal", "interface", "ops", "ttl_ms", "uses"])?;
    let obj = arguments.as_ref().ok_or("arguments must be an object")?;
    let principal = int_in(obj, "principal", 1, u32::MAX as i64).ok_or("`principal` must be a positive 32-bit integer")?;
    let interface = obj.get("interface").and_then(Value::as_str).ok_or("`interface` must be a string")?;
    let ops = obj.get("ops").and_then(Value::as_array).filter(|a| !a.is_empty() && a.len() <= 64).ok_or("`ops` must be a non-empty array")?;
    let ops = ops.iter().map(|o| o.as_str().map(String::from)).collect::<Option<Vec<_>>>().ok_or("every op must be a string")?;
    let ttl_ms = int_in(obj, "ttl_ms", 1, i64::MAX).ok_or("`ttl_ms` must be a positive integer")?;
    let uses = match obj.get("uses") {
        None => 0,
        Some(_) => int_in(obj, "uses", 1, i64::MAX).ok_or("`uses` must be a positive integer")? as u64,
    };
    Ok(GrantArgs { principal: principal as u32, interface: String::from(interface), ops, ttl_ms, uses })
}

fn confirm_grant_args(arguments: &Option<Value>) -> Result<(u32, u32, i64), &'static str> {
    only_keys(arguments, &["proposal", "principal", "ttl_ms"])?;
    let obj = arguments.as_ref().ok_or("arguments must be an object")?;
    let proposal = int_in(obj, "proposal", 1, u32::MAX as i64).ok_or("`proposal` must be a positive 32-bit integer")?;
    let principal = int_in(obj, "principal", 1, u32::MAX as i64).ok_or("`principal` must be a positive 32-bit integer")?;
    let ttl_ms = int_in(obj, "ttl_ms", 1, i64::MAX).ok_or("`ttl_ms` must be a positive integer")?;
    Ok((proposal as u32, principal as u32, ttl_ms))
}

impl Bridge {
    pub fn new(cfg: Config, keys: Keys, exports: Vec<Export>) -> Bridge {
        Bridge {
            cfg,
            keys,
            exports,
            phase: Phase::Fresh,
            rx: Vec::new(),
            discarding: false,
            ledger: Ledger::default(),
            proposals: Vec::new(),
            next_proposal: 1,
            window_start: 0,
            window_count: 0,
            stats: Stats::default(),
        }
    }

    /// Forget the session (a new link): the exports, the keys, the ledger, the
    /// proposals and the counters stay. A proposal outlives the connection it
    /// came on, and a warrant's quota is spent for good.
    pub fn reset(&mut self) {
        self.phase = Phase::Fresh;
        self.rx.clear();
        self.discarding = false;
    }

    // ── the link ────────────────────────────────────────────────────────────

    fn send<L: Link>(&mut self, link: &mut L, text: &str) -> bool {
        let mut out = Vec::with_capacity(text.len() + 1);
        out.extend_from_slice(text.as_bytes());
        out.push(b'\n');
        link.send(&out)
    }

    /// Bytes read from the link. Returns `false` once the link is no longer
    /// writable: the host redials.
    pub fn on_bytes<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, bytes: &[u8]) -> bool {
        self.rx.extend_from_slice(bytes);
        loop {
            let nl = self.rx.iter().position(|&b| b == b'\n');
            if self.discarding {
                match nl {
                    Some(i) => {
                        self.rx.drain(..=i);
                        self.discarding = false;
                        continue;
                    }
                    None => {
                        self.rx.clear();
                        return true;
                    }
                }
            }
            let Some(i) = nl else {
                if self.rx.len() > LINE_MAX {
                    self.rx.clear();
                    self.discarding = true;
                    let e = Message::error(None, RpcError::new(jsonrpc::PARSE_ERROR, "Parse error: message too long"));
                    return self.send(link, &e.to_json());
                }
                return true;
            };
            if i > LINE_MAX {
                self.rx.drain(..=i);
                let e = Message::error(None, RpcError::new(jsonrpc::PARSE_ERROR, "Parse error: message too long"));
                if !self.send(link, &e.to_json()) {
                    return false;
                }
                continue;
            }
            let line: Vec<u8> = self.rx.drain(..=i).take(i).collect();
            if !self.on_line(host, link, &line) {
                return false;
            }
        }
    }

    fn on_line<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, line: &[u8]) -> bool {
        let Ok(text) = core::str::from_utf8(line) else {
            let e = Message::error(None, RpcError::new(jsonrpc::PARSE_ERROR, "Parse error: not UTF-8"));
            return self.send(link, &e.to_json());
        };
        let text = text.trim();
        if text.is_empty() {
            return true;
        }
        let out = match jsonrpc::decode(text) {
            Err(e) => Some(Message::Error(e).to_json()),
            Ok(Incoming::Single(item)) => self.on_item(host, item).map(|m| m.to_json()),
            Ok(Incoming::Batch(items)) => {
                let replies: Vec<Message> = items.into_iter().filter_map(|i| self.on_item(host, i)).collect();
                (!replies.is_empty()).then(|| jsonrpc::encode_batch(&replies))
            }
        };
        match out {
            Some(t) => self.send(link, &t),
            None => true,
        }
    }

    fn on_item<H: Host>(&mut self, host: &mut H, item: jsonrpc::Item) -> Option<Message> {
        match item {
            Err(e) => Some(Message::Error(e)),
            Ok(Message::Request(r)) => Some(self.on_request(host, &r)),
            Ok(Message::Notification(n)) => {
                if is_initialized(&n) && self.phase == Phase::Initialized {
                    self.phase = Phase::Ready;
                }
                None
            }
            // The server asks the client nothing: a response is not for it.
            Ok(Message::Response(_) | Message::Error(_)) => None,
        }
    }

    // ── requests ────────────────────────────────────────────────────────────

    fn on_request<H: Host>(&mut self, host: &mut H, r: &Request) -> Message {
        let id = r.id.clone();
        let req = match McpRequest::from_rpc(r) {
            Ok(q) => q,
            Err(e) => return Message::error(Some(id), e),
        };
        match req {
            McpRequest::Ping => Message::response(id, Value::Object(Vec::new())),
            McpRequest::Initialize(_) => {
                if self.phase != Phase::Fresh {
                    return Message::error(Some(id), RpcError::new(jsonrpc::INVALID_REQUEST, "already initialized"));
                }
                self.phase = Phase::Initialized;
                let now = host.now_ns();
                let info = Implementation { name: String::from("mcpd"), version: String::from(env!("CARGO_PKG_VERSION")) };
                let mut v = InitializeResult::new(info, Some(INSTRUCTIONS)).to_value();
                if let Value::Object(m) = &mut v {
                    m.push((
                        String::from("_meta"),
                        Value::object([
                            ("azos/epoch", Value::Int(self.cfg.epoch as i64)),
                            ("azos/mono_ns", Value::Int(now.min(i64::MAX as u64) as i64)),
                        ]),
                    ));
                }
                Message::response(id, v)
            }
            _ if self.phase != Phase::Ready => {
                Message::error(Some(id), RpcError::new(jsonrpc::INVALID_REQUEST, "send notifications/initialized first"))
            }
            McpRequest::ToolsList(p) => {
                if p.cursor.is_some() {
                    return Message::error(Some(id), RpcError::invalid_params("unknown cursor"));
                }
                Message::response(id, self.tools_list())
            }
            McpRequest::ToolsCall(p) => {
                let warrant = r.params.as_ref().and_then(|v| v.get("_meta")).and_then(|m| m.get(META_WARRANT));
                let warrant = warrant.and_then(Value::as_str);
                match self.tools_call(host, &p, warrant) {
                    Some(res) => Message::response(id, res.to_value()),
                    None => Message::error(Some(id), RpcError::invalid_params("unknown tool")),
                }
            }
        }
    }

    /// The `tools/list` result, one page: `{ "tools": [...] }`, each tool as
    /// JSON because it carries `annotations`, which the codec's `Tool` does not.
    /// Built from the op tables on every ask: the exports are few and the list
    /// is not hot.
    fn tools_list(&self) -> Value {
        let mut tools = Vec::new();
        for e in &self.exports {
            for op in e.iface.ops.iter().filter(|o| catalog::exposed(o)) {
                tools.push(catalog::mcp_tool(e.iface, op));
            }
        }
        tools.extend(catalog::control_tools(catalog::has_irreversible(&self.exports)));
        Value::object([("tools", Value::Array(tools))])
    }

    // ── calls ───────────────────────────────────────────────────────────────

    /// May another call be served in this second?
    fn admit_rate(&mut self, now: u64) -> bool {
        if now.wrapping_sub(self.window_start) >= 1_000_000_000 {
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count += 1;
        self.window_count <= self.cfg.call_rate
    }

    fn token(&self, hex: Option<&str>) -> Result<azos_rpc::wire::Token, Refusal> {
        warrant::parse(hex.ok_or(Refusal::NoWarrant)?)
    }

    /// `None`: the tool is unknown (a protocol error).
    fn tools_call<H: Host>(&mut self, host: &mut H, p: &ToolCallParams, warrant: Option<&str>) -> Option<ToolCallResult> {
        let irreversible = catalog::has_irreversible(&self.exports);
        let control = match p.name.as_str() {
            TOOL_GRANT_AGENT => true,
            TOOL_GRANT_CONFIRM | TOOL_CONFIRM | TOOL_COMMIT => irreversible,
            _ => false,
        };
        let found = if control { None } else { Some(catalog::find(&self.exports, &p.name).map(|(e, op)| (*e, op))?) };
        let now = host.now_ns();
        self.stats.calls += 1;
        if !self.admit_rate(now) {
            self.stats.busy += 1;
            let a = Answer::new("busy", true, format!("{}: over the call rate; ask again later.", p.name));
            return Some(a.with("reason", Value::str("busy")).finish(None));
        }
        let (answer, receipt) = match found {
            Some((e, op)) => self.op_call(host, &p.name, e, op, &p.arguments, warrant, now),
            None if p.name == TOOL_GRANT_AGENT => (self.grant_agent(host, &p.arguments, warrant, now), None),
            None if p.name == TOOL_GRANT_CONFIRM => (self.grant_confirm(host, &p.arguments, warrant, now), None),
            None if p.name == TOOL_CONFIRM => (self.confirm(&p.arguments, warrant, now), None),
            None => self.commit(host, &p.arguments, warrant, now),
        };
        match answer.status {
            "served" | "proposed" | "confirmed" | "granted" => self.stats.served += 1,
            "failed" | "unknown" => self.stats.failed += 1,
            "busy" => self.stats.busy += 1,
            _ => self.stats.refused += 1,
        }
        if answer.error {
            host.log(&format!("[mcpd] {}: {}\n", p.name, answer.text));
        }
        Some(answer.finish(receipt.as_ref()))
    }

    /// `<interface>.<op>`: run it, or for an irreversible op propose it.
    #[allow(clippy::too_many_arguments)]
    fn op_call<H: Host>(
        &mut self,
        host: &mut H,
        tool: &str,
        e: Export,
        op: &'static azos_idl::OpInfo,
        arguments: &Option<Value>,
        warrant: Option<&str>,
        now: u64,
    ) -> (Answer, Option<ProvenanceRecord>) {
        let args = match words_arg(arguments, op.req_words as usize - 1) {
            Ok(a) => a,
            Err(why) => return (bad_args(tool, why), None),
        };
        let grant = match self
            .token(warrant)
            .and_then(|t| warrant::check(&self.keys, Scope::Agent { epoch: self.cfg.epoch }, &t, e.iface.id, op.op, now))
        {
            Ok(g) => g,
            Err(why) => return (refusal_answer(tool, why), None),
        };
        if op.once_only() {
            return (self.propose(tool, e, op, args, &grant, now), None);
        }
        if let Err(why) = self.ledger.charge(&grant, now) {
            return (refusal_answer(tool, why), None);
        }
        self.run(host, tool, e, op, &args, &grant, grant.expiry_ns - now)
    }

    fn propose(&mut self, tool: &str, e: Export, op: &'static azos_idl::OpInfo, args: Vec<u64>, grant: &Grant, now: u64) -> Answer {
        self.proposals.retain(|p| p.deadline_ns > now);
        if self.proposals.len() >= PROPOSALS_MAX {
            return Answer::new("busy", true, format!("{tool}: too many proposals are waiting."))
                .with("reason", Value::str("too-many-proposals"));
        }
        let mut id = self.cfg.epoch.wrapping_add(self.next_proposal);
        self.next_proposal = self.next_proposal.wrapping_add(1);
        if id == 0 {
            id = self.cfg.epoch.wrapping_add(self.next_proposal);
            self.next_proposal = self.next_proposal.wrapping_add(1);
        }
        let deadline_ns = now.saturating_add(self.cfg.proposal_ttl_ns).min(grant.expiry_ns);
        let digest = digest_of(e.iface.id, op.op, &args);
        self.proposals.push(Proposal {
            id,
            principal: grant.principal,
            export: e,
            op,
            args,
            digest,
            deadline_ns,
            state: State::Proposed,
        });
        self.stats.proposed += 1;
        Answer::new(
            "proposed",
            false,
            format!(
                "{tool} is irreversible and was NOT run. Proposal {id} (digest {}) waits for a human: azos.confirm with a \
                 one-shot warrant of the control interface ({CONTROL_ID:#x}, op {CONFIRM_OP}, session {id}), then azos.commit.",
                hex8(&digest)
            ),
        )
        .with("proposal", Value::Int(id as i64))
        .with("digest", Value::Str(hex8(&digest)))
        .with("principal", Value::Int(grant.principal as i64))
        .with("now_ns", word_value(now))
        .with("expires_ns", word_value(deadline_ns))
        .with("control_interface", Value::Int(CONTROL_ID as i64))
    }

    /// The operator's warrant for a grant, or why not.
    fn admin(&mut self, tool: &str, warrant: Option<&str>, now: u64) -> Result<Grant, Answer> {
        let tok = self.token(warrant).map_err(|why| refusal_answer(tool, why))?;
        let grant = warrant::check(&self.keys, Scope::Admin { epoch: self.cfg.epoch }, &tok, CONTROL_ID, GRANT_OP, now)
            .map_err(|why| refusal_answer(tool, why))?;
        self.ledger.charge(&grant, now).map_err(|why| refusal_answer(tool, why))?;
        Ok(grant)
    }

    /// The `ttl_ms` of a grant as an absolute expiry, within the cap.
    fn expiry_in(&self, ttl_ms: i64, now: u64) -> u64 {
        let ttl_ns = (ttl_ms as u64).saturating_mul(1_000_000).min(self.cfg.grant_max_ns);
        now.saturating_add(ttl_ns)
    }

    /// `azos.grant_agent`: the operator issues an agent's warrant.
    fn grant_agent<H: Host>(&mut self, host: &mut H, arguments: &Option<Value>, warrant: Option<&str>, now: u64) -> Answer {
        let tool = TOOL_GRANT_AGENT;
        let a = match grant_args(arguments) {
            Ok(a) => a,
            Err(why) => return bad_args(tool, why),
        };
        let operator = match self.admin(tool, warrant, now) {
            Ok(g) => g,
            Err(a) => return a,
        };
        let Some(e) = self.exports.iter().find(|e| e.iface.name == a.interface).copied() else {
            return Answer::new("refused", true, format!("{tool}: no interface called {}.", a.interface))
                .with("reason", Value::str("unknown-interface"));
        };
        let mut mask = 0u64;
        for name in &a.ops {
            let Some(op) = e.iface.op(name).filter(|o| catalog::exposed(o)) else {
                return Answer::new("refused", true, format!("{tool}: {} has no tool op called {name}.", a.interface))
                    .with("reason", Value::str("unknown-op"));
            };
            mask |= 1 << op.op;
        }
        let expiry = self.expiry_in(a.ttl_ms, now).min(operator.expiry_ns);
        let tok = warrant::mint_agent(&self.keys, self.cfg.epoch, a.principal, e.iface.id, mask, expiry, a.uses);
        host.log(&format!(
            "[mcpd] operator {} granted principal {} {} ops {:#x} until {} ns\n",
            operator.principal, a.principal, a.interface, mask, expiry
        ));
        let hex = warrant::token_hex(&tok);
        Answer::new(
            "granted",
            false,
            format!("Warrant for principal {} on {} until {} ns: {hex}", a.principal, a.interface, expiry),
        )
        .with("warrant", Value::Str(hex))
        .with("principal", Value::Int(a.principal as i64))
        .with("interface", Value::Str(a.interface))
        .with("op_mask", word_value(mask))
        .with("expires_ns", word_value(expiry))
        .with("uses", Value::Int(a.uses as i64))
    }

    /// `azos.grant_confirm`: the operator issues a human's one-shot warrant to
    /// confirm one waiting proposal.
    fn grant_confirm<H: Host>(&mut self, host: &mut H, arguments: &Option<Value>, warrant: Option<&str>, now: u64) -> Answer {
        let tool = TOOL_GRANT_CONFIRM;
        let (proposal, principal, ttl_ms) = match confirm_grant_args(arguments) {
            Ok(a) => a,
            Err(why) => return bad_args(tool, why),
        };
        let operator = match self.admin(tool, warrant, now) {
            Ok(g) => g,
            Err(a) => return a,
        };
        self.proposals.retain(|p| p.deadline_ns > now);
        let Some(p) = self.proposals.iter().find(|p| p.id == proposal) else {
            return Answer::new("refused", true, format!("{tool}: no such proposal (never made, lapsed or spent)."))
                .with("reason", Value::str("unknown-proposal"));
        };
        if p.state != State::Proposed {
            return Answer::new("refused", true, format!("{tool}: proposal {proposal} is not waiting for a confirmation."))
                .with("reason", Value::str("not-pending"));
        }
        if p.principal == principal {
            return Answer::new("refused", true, format!("{tool}: a principal does not confirm its own proposal."))
                .with("reason", Value::str("same-principal"));
        }
        // It never outlives the proposal or the operator's own warrant.
        let expiry = self.expiry_in(ttl_ms, now).min(p.deadline_ns).min(operator.expiry_ns);
        let tok = warrant::mint_human(&self.keys, principal, proposal, expiry);
        host.log(&format!("[mcpd] operator {} granted human {} proposal {} until {} ns\n", operator.principal, principal, proposal, expiry));
        let hex = warrant::token_hex(&tok);
        Answer::new(
            "granted",
            false,
            format!("One-shot warrant for principal {principal} to confirm proposal {proposal} until {expiry} ns: {hex}"),
        )
        .with("warrant", Value::Str(hex))
        .with("principal", Value::Int(principal as i64))
        .with("proposal", Value::Int(proposal as i64))
        .with("digest", Value::Str(hex8(&p.digest)))
        .with("expires_ns", word_value(expiry))
    }

    /// `azos.confirm`: a human's one-shot warrant opens one proposal.
    fn confirm(&mut self, arguments: &Option<Value>, warrant: Option<&str>, now: u64) -> Answer {
        let tool = TOOL_CONFIRM;
        let (id, digest) = match proposal_arg(arguments, true) {
            Ok((id, d)) => (id, d.unwrap_or("")),
            Err(why) => return bad_args(tool, why),
        };
        self.proposals.retain(|p| p.deadline_ns > now);
        let tok = match self.token(warrant) {
            Ok(t) => t,
            Err(why) => return refusal_answer(tool, why),
        };
        // The human's warrant is bound to this proposal id (its session): what
        // follows can only be about the proposal it names.
        let grant = match warrant::check(&self.keys, Scope::Human { proposal: id }, &tok, CONTROL_ID, CONFIRM_OP, now) {
            Ok(g) => g,
            Err(why) => return refusal_answer(tool, why),
        };
        let Some(p) = self.proposals.iter_mut().find(|p| p.id == id) else {
            return Answer::new("refused", true, format!("{tool}: no such proposal (never made, lapsed or spent)."))
                .with("reason", Value::str("unknown-proposal"));
        };
        if p.state != State::Proposed {
            return Answer::new("refused", true, format!("{tool}: proposal {id} is not waiting for a confirmation."))
                .with("reason", Value::str("not-pending"));
        }
        if hex8(&p.digest) != digest {
            return Answer::new("refused", true, format!("{tool}: the digest is not the one of proposal {id}."))
                .with("reason", Value::str("digest-mismatch"));
        }
        if grant.principal == p.principal {
            return Answer::new("refused", true, format!("{tool}: a principal does not confirm its own proposal."))
                .with("reason", Value::str("same-principal"));
        }
        if let Err(why) = self.ledger.charge(&grant, now) {
            return refusal_answer(tool, why);
        }
        p.state = State::Confirmed { by: grant.principal };
        self.stats.confirmed += 1;
        Answer::new("confirmed", false, format!("Proposal {id} is confirmed by principal {}; azos.commit runs it.", grant.principal))
            .with("proposal", Value::Int(id as i64))
            .with("confirmed_by", Value::Int(grant.principal as i64))
    }

    /// `azos.commit`: run a confirmed proposal, once.
    fn commit<H: Host>(
        &mut self,
        host: &mut H,
        arguments: &Option<Value>,
        warrant: Option<&str>,
        now: u64,
    ) -> (Answer, Option<ProvenanceRecord>) {
        let tool = TOOL_COMMIT;
        let id = match proposal_arg(arguments, false) {
            Ok((id, _)) => id,
            Err(why) => return (bad_args(tool, why), None),
        };
        self.proposals.retain(|p| p.deadline_ns > now);
        let tok = match self.token(warrant) {
            Ok(t) => t,
            Err(why) => return (refusal_answer(tool, why), None),
        };
        let Some(i) = self.proposals.iter().position(|p| p.id == id) else {
            let a = Answer::new("refused", true, format!("{tool}: no such proposal (never made, lapsed or spent)."));
            return (a.with("reason", Value::str("unknown-proposal")), None);
        };
        let (export, op, principal, state, deadline_ns) = {
            let p = &self.proposals[i];
            (p.export, p.op, p.principal, p.state, p.deadline_ns)
        };
        // The agent's own warrant for the proposed op, not any warrant.
        let grant = match warrant::check(&self.keys, Scope::Agent { epoch: self.cfg.epoch }, &tok, export.iface.id, op.op, now) {
            Ok(g) => g,
            Err(why) => return (refusal_answer(tool, why), None),
        };
        if grant.principal != principal {
            let a = Answer::new("refused", true, format!("{tool}: proposal {id} is another principal's."));
            return (a.with("reason", Value::str("other-principal")), None);
        }
        match state {
            State::Confirmed { .. } => {}
            State::Proposed => {
                let a = Answer::new("refused", true, format!("{tool}: proposal {id} has no human confirmation."));
                return (a.with("reason", Value::str("not-confirmed")), None);
            }
            State::Spent => {
                let a = Answer::new("refused", true, format!("{tool}: proposal {id} was committed; it is never run twice."));
                return (a.with("reason", Value::str("already-committed")), None);
            }
        }
        // The proposal lapses with `deadline_ns`; the retain above dropped a
        // lapsed one, so this is the remaining life.
        if let Err(why) = self.ledger.charge(&grant, now) {
            return (refusal_answer(tool, why), None);
        }
        // Spent BEFORE the call: whatever the call does, it is not asked again.
        let args = {
            let p = &mut self.proposals[i];
            p.state = State::Spent;
            core::mem::take(&mut p.args)
        };
        self.stats.committed += 1;
        let life = (grant.expiry_ns - now).min(deadline_ns - now);
        let (a, r) = self.run(host, tool, export, op, &args, &grant, life);
        (a.with("proposal", Value::Int(id as i64)), r)
    }

    /// One op through a warrant of the kernel's, and its receipt.
    #[allow(clippy::too_many_arguments)]
    fn run<H: Host>(
        &mut self,
        host: &mut H,
        tool: &str,
        e: Export,
        op: &'static azos_idl::OpInfo,
        args: &[u64],
        grant: &Grant,
        life: u64,
    ) -> (Answer, Option<ProvenanceRecord>) {
        let life_ns = life.min(self.cfg.warrant_max_ns);
        let mut msg = MsgDesc { version: MSG_VERSION, n_words: op.req_words, ..MsgDesc::default() };
        msg.words[0] = header(e.iface.id, e.iface.level, op.op);
        msg.words[1..=args.len()].copy_from_slice(args);
        let w = Warrant {
            badge: grant.principal,
            life_ns,
            // B2: the call carries the time it may take; the kernel refuses one
            // whose deadline has passed before it queues anything.
            deadline_ns: if op.deadline_ns != 0 { op.deadline_ns.min(life_ns) } else { life_ns },
        };
        let mark = receipt::mark(host);
        let inv = host.invoke(e.endpoint, &mut msg, &w);
        let rec = receipt::find(host, self.cfg.me, mark, inv.expiry_ns);
        let a = match inv.result {
            Err(rc) if rc == Errno::EPEERDIED.to_syscall_ret() || rc == Errno::EREVOKED.to_syscall_ret() => Answer::new(
                "unknown",
                true,
                format!("{tool}: the server died while it held the call; whether the op ran is unknown."),
            )
            .with("code", Value::Int(rc)),
            Err(rc) => Answer::new("refused", true, format!("{tool}: the kernel refused the warrant or the call ({rc})."))
                .with("reason", Value::str("kernel-refused"))
                .with("code", Value::Int(rc)),
            Ok(()) if msg.words[0] != STATUS_OK => {
                Answer::new("failed", true, format!("{tool}: the server answered with status {}.", msg.words[0]))
                    .with("code", word_value(msg.words[0]))
            }
            Ok(()) => {
                let n = (msg.n_words as usize).clamp(1, MSG_WORDS_MAX);
                let words: Vec<Value> = msg.words[1..n].iter().map(|&x| word_value(x)).collect();
                let shown: Vec<String> = msg.words[1..n].iter().map(|x| format!("{x}")).collect();
                Answer::new("served", false, format!("{tool}: served, reply words [{}].", shown.join(", ")))
                    .with("words", Value::Array(words))
            }
        };
        (a.with("principal", Value::Int(grant.principal as i64)), rec)
    }
}

const INSTRUCTIONS: &str = "AzOS MCP bridge. Every tools/call needs a warrant in params._meta[\"azos/warrant\"]: a hex token \
whose op mask names the op and which expires. The operator issues them with azos.grant_agent (and azos.grant_confirm for a human's \
one-shot confirmation), under the operator's own warrant, which the board's console shows at boot; the epoch and clock they are \
signed for are in this result's _meta. An op that cannot be undone is only proposed by its own tool; a human confirms it with \
azos.confirm and azos.commit runs it once. Every answer carries structuredContent.receipt, the decision record the kernel wrote \
for the call (0: none).";
