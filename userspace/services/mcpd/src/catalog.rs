// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the bridge serves: the interfaces it knows (the catalog), the
//! endpoints its row lets it call, and the MCP tools that follow from the two.
//!
//! The endpoints are those of the bridge's view of the topology (`MemObj
//! inspect.mcp`, `endpoints/<name>/index`) that this task holds the call right
//! **and** the lend right on (`WRITE` + `DUP` + `TRANSFER`, the topology's
//! `transfer = true`), checked against its own table: the authority the
//! bridge's row grants is what opens them, not the name of the image. A name
//! the catalog does not know is skipped, so the result only ever has less in
//! it than the row holds.
//!
//! # From an interface to tools
//!
//! The IDL is self-describing: an interface carries its id, its level and an
//! op table ([`OpInfo`]) that says how many words each request and reply has and
//! how the op is delivered. The bridge adds no schema of its own. Every op of an
//! exported interface that
//!
//! * declares how it is delivered (`#[idempotent]`, `#[at_most_once]` or
//!   `#[once_only]`; an op that declares nothing is not carried by a transport
//!   that can lose a message, and this is one),
//! * takes no capability (a capability cannot cross a JSON string), and
//! * has a number the warrant's op mask can name ([`OP_MASK_BITS`])
//!
//! is the tool `<interface>.<op>`. Its arguments are one non-negative integer
//! per request word after the header, the interface's own wire form. An op that
//! is `#[once_only]` is irreversible: its tool does not run it, it proposes it
//! ([`crate::bridge`]).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use azos_idl::{OpInfo, MSG_WORDS_MAX};
use azos_mcp::json::Value;
use azos_mcp::mcp::Tool;

/// An interface the bridge can front: the endpoint name a row uses for it, its
/// id and level (the request header word) and its op table.
#[derive(Clone, Copy, Debug)]
pub struct Iface {
    pub name: &'static str,
    pub id: u32,
    pub level: u16,
    pub ops: &'static [OpInfo],
}

impl Iface {
    /// The op called `name`.
    pub fn op(&self, name: &str) -> Option<&'static OpInfo> {
        self.ops.iter().find(|o| o.name == name)
    }
}

/// One interface the bridge's row can call.
#[derive(Clone, Copy, Debug)]
pub struct Export {
    pub iface: &'static Iface,
    /// The endpoint's pool index, what the host turns into a handle.
    pub endpoint: u32,
}

/// The endpoints the bridge may call, matched to the catalog.
#[derive(Debug, Default)]
pub struct View {
    /// The pool index of the call and lend capability on `endpoint.decisions`
    /// (the receipts come from it), whether or not the catalog fronts it.
    pub decisions: Option<u32>,
    pub exports: Vec<Export>,
    /// Endpoints skipped: an interface the catalog does not know, or past
    /// [`EXPORTS_MAX`].
    pub skipped: u32,
}

/// Exports one view may list (the topology's endpoint pool is smaller).
pub const EXPORTS_MAX: usize = 16;

/// The op numbers a warrant's `OP_MASK` can name: bit `n` of the 64-bit mask is
/// op number `n` (the ops of an interface count from 1).
pub const OP_MASK_BITS: u16 = 63;

/// Match the endpoints the bridge holds (name, pool index) to `catalog`.
pub fn view_of<'n>(held: impl IntoIterator<Item = (&'n str, u32)>, catalog: &'static [Iface]) -> View {
    let mut v = View::default();
    for (name, index) in held {
        if name == "decisions" {
            v.decisions = Some(index);
        }
        match catalog.iter().find(|i| i.name == name) {
            Some(iface) if v.exports.len() < EXPORTS_MAX => v.exports.push(Export { iface, endpoint: index }),
            Some(_) => v.skipped += 1,
            // An endpoint of an interface the bridge cannot describe: its
            // row grant is not an invitation.
            None => {
                if name != "decisions" {
                    v.skipped += 1;
                }
            }
        }
    }
    v
}

/// Is `op` one the bridge turns into a tool?
pub fn exposed(op: &OpInfo) -> bool {
    op.delivery().is_some()
        && op.req_caps == 0
        && op.op != 0
        && op.op <= OP_MASK_BITS
        && (1..=MSG_WORDS_MAX).contains(&(op.req_words as usize))
}

/// The tool name of an op: `<interface>.<op>`.
pub fn tool_name(iface: &Iface, op: &OpInfo) -> String {
    format!("{}.{}", iface.name, op.name)
}

/// The export and op a tool name names.
pub fn find<'a>(exports: &'a [Export], name: &str) -> Option<(&'a Export, &'static OpInfo)> {
    let (iface, op) = name.split_once('.')?;
    let e = exports.iter().find(|e| e.iface.name == iface)?;
    let op = e.iface.op(op).filter(|o| exposed(o))?;
    Some((e, op))
}

/// Does any exported op need the propose, confirm and commit steps?
pub fn has_irreversible(exports: &[Export]) -> bool {
    exports.iter().any(|e| e.iface.ops.iter().any(|o| exposed(o) && o.once_only()))
}

fn delivery_word(op: &OpInfo) -> &'static str {
    if op.once_only() {
        "once_only"
    } else if op.at_most_once() {
        "at_most_once"
    } else {
        "idempotent"
    }
}

fn on_failure_word(op: &OpInfo) -> Option<&'static str> {
    use azos_idl::OnFailure::*;
    Some(match op.on_failure? {
        Degrade => "degrade",
        SafeState => "safe_state",
        Restart => "restart",
        Escalate => "escalate",
    })
}

/// The MCP tool of one op, built from its row of the op table and nothing else.
pub fn mcp_tool(iface: &Iface, op: &OpInfo) -> Value {
    let n = op.req_words as usize - 1;
    let mut text = format!(
        "Op {} of the {} interface (id {:#x}, level {}): {} request word(s) after the header, {} reply word(s) after the status. Delivery: {}.",
        op.op,
        iface.name,
        iface.id,
        iface.level,
        n,
        (op.rep_words as usize).saturating_sub(1),
        delivery_word(op),
    );
    if op.deadline_ns != 0 {
        text.push_str(&format!(" It declares a deadline of {} ns.", op.deadline_ns));
    }
    if let Some(f) = on_failure_word(op) {
        text.push_str(&format!(" When its service fails: {f}."));
    }
    if op.once_only() {
        text.push_str(
            " IRREVERSIBLE: calling this tool only proposes the op and runs nothing; a human confirms the proposal \
             with azos.confirm and azos.commit then runs it, once.",
        );
    }
    text.push_str(" Needs a warrant (_meta[\"azos/warrant\"]) whose op mask names this op.");
    let mut props = alloc::vec![];
    if n != 0 {
        props.push((
            "args",
            Value::object([
                ("type", Value::str("array")),
                ("items", Value::object([("type", Value::str("integer")), ("minimum", Value::Int(0))])),
                ("minItems", Value::Int(n as i64)),
                ("maxItems", Value::Int(n as i64)),
                (
                    "description",
                    Value::str("One non-negative integer (below 2^63) per request word after the header, in the interface's wire order."),
                ),
            ]),
        ));
    }
    let schema = object_schema(props, if n != 0 { &["args"] } else { &[] });
    let tool = Tool {
        name: tool_name(iface, op),
        title: None,
        description: Some(text),
        input_schema: schema,
        output_schema: None,
    };
    let mut v = tool.to_value();
    let mut hints = alloc::vec![];
    if op.idempotent() {
        hints.push((String::from("idempotentHint"), Value::Bool(true)));
    }
    if op.once_only() {
        hints.push((String::from("destructiveHint"), Value::Bool(true)));
        hints.push((String::from("idempotentHint"), Value::Bool(false)));
    }
    if let Value::Object(m) = &mut v {
        m.push((String::from("annotations"), Value::Object(hints)));
    }
    v
}

/// The id of the control interface the human's warrant is for: ASCII "MCPC".
/// It is not an endpoint; it names the confirm step in a token.
pub const CONTROL_ID: u32 = 0x4D43_5043;
/// The op of the control interface a human warrant must name: confirm a proposal.
pub const CONFIRM_OP: u16 = 1;
/// The op of the control interface an operator's warrant must name: grant warrants.
pub const GRANT_OP: u16 = 2;
/// The tool a human confirms a proposal with.
pub const TOOL_CONFIRM: &str = "azos.confirm";
/// The tool that runs a confirmed proposal.
pub const TOOL_COMMIT: &str = "azos.commit";
/// The tool an operator issues an agent's warrant with.
pub const TOOL_GRANT_AGENT: &str = "azos.grant_agent";
/// The tool an operator issues a human's one-shot confirmation warrant with.
pub const TOOL_GRANT_CONFIRM: &str = "azos.grant_confirm";

/// A JSON Schema of type `object` with these properties and required names.
fn object_schema(props: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut m = alloc::vec![
        (String::from("type"), Value::str("object")),
        (String::from("properties"), Value::Object(props.into_iter().map(|(k, v)| (String::from(k), v)).collect())),
        (String::from("additionalProperties"), Value::Bool(false)),
    ];
    if !required.is_empty() {
        m.push((String::from("required"), Value::Array(required.iter().map(|r| Value::str(r)).collect())));
    }
    Value::Object(m)
}

fn control_tool(name: &str, text: &str, schema: Value, destructive: bool) -> Value {
    let t = Tool { name: String::from(name), title: None, description: Some(String::from(text)), input_schema: schema, output_schema: None };
    let mut v = t.to_value();
    if let Value::Object(m) = &mut v {
        m.push((
            String::from("annotations"),
            Value::object([("destructiveHint", Value::Bool(destructive)), ("idempotentHint", Value::Bool(false))]),
        ));
    }
    v
}

fn integer(what: &str, min: i64) -> Value {
    Value::object([("type", Value::str("integer")), ("minimum", Value::Int(min)), ("description", Value::str(what))])
}

/// The tools of the control interface: the grants, and with an irreversible op
/// exported the two steps after a proposal.
pub fn control_tools(irreversible: bool) -> Vec<Value> {
    let proposal = || integer("The proposal id the propose step returned.", 1);
    let digest = Value::object([
        ("type", Value::str("string")),
        ("description", Value::str("The digest the propose step returned: what the human saw.")),
    ]);
    let mut v = alloc::vec![control_tool(
        TOOL_GRANT_AGENT,
        "Issue an agent's warrant: a principal (a Domain id) may call the named ops of one interface until it \
         expires, optionally a number of times. Needs the operator's warrant (_meta[\"azos/warrant\"]).",
        object_schema(
            alloc::vec![
                ("principal", integer("The agent's Domain id.", 1)),
                ("interface", Value::object([("type", Value::str("string")), ("description", Value::str("An interface name, as in the tool names."))])),
                (
                    "ops",
                    Value::object([
                        ("type", Value::str("array")),
                        ("items", Value::object([("type", Value::str("string"))])),
                        ("minItems", Value::Int(1)),
                        ("description", Value::str("Op names of the interface, as in the tool names.")),
                    ]),
                ),
                ("ttl_ms", integer("How long the warrant lives, milliseconds.", 1)),
                ("uses", integer("How many calls it allows; absent: no count.", 1)),
            ],
            &["principal", "interface", "ops", "ttl_ms"],
        ),
        false,
    )];
    if irreversible {
        v.push(control_tool(
            TOOL_GRANT_CONFIRM,
            "Issue a human's one-shot warrant to confirm one proposal that is waiting. Needs the operator's warrant.",
            object_schema(
                alloc::vec![
                    ("proposal", proposal()),
                    ("principal", integer("The confirming human's Domain id (not the proposer's).", 1)),
                    ("ttl_ms", integer("How long the warrant lives, milliseconds; it never outlives the proposal.", 1)),
                ],
                &["proposal", "principal", "ttl_ms"],
            ),
            false,
        ));
        v.push(control_tool(
            TOOL_CONFIRM,
            "Confirm a proposed irreversible op. Called by a human, with a one-shot warrant (_meta[\"azos/warrant\"]) \
             of the control interface bound to this proposal. It runs nothing.",
            object_schema(alloc::vec![("proposal", proposal()), ("digest", digest)], &["proposal", "digest"]),
            false,
        ));
        v.push(control_tool(
            TOOL_COMMIT,
            "Run a confirmed proposal, once, with the agent's own warrant for the proposed op. The answer is never \
             asked for again, whatever it is.",
            object_schema(alloc::vec![("proposal", proposal())], &["proposal"]),
            true,
        ));
    }
    v
}
