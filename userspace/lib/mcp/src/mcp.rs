// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Model Context Protocol (revision 2025-06-18) over JSON-RPC: the shapes
//! a tools server needs.
//!
//! * `initialize` / `notifications/initialized`: the handshake. The server
//!   answers with the protocol version it speaks and the one capability it has,
//!   `tools`.
//! * `ping`.
//! * `tools/list`: [`Tool`]s with a JSON-Schema `inputSchema`, paged by cursor.
//! * `tools/call`: a tool name and its `arguments`; the answer is a list of
//!   [`Content`] blocks and an `isError` flag. **A tool that fails is a normal
//!   result with `isError: true`**; a JSON-RPC error is for the protocol only
//!   (unknown method, unknown tool, malformed params).
//!
//! [`McpRequest::from_rpc`] reads a request into one of these shapes (an
//! unknown method is the Method-not-found error to send back); each result type
//! has `to_value`, the `result` of the response.

use crate::json::Value;
use crate::jsonrpc::{Notification, Request, RpcError};
use alloc::string::String;
use alloc::vec::Vec;

/// The protocol revision this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub const METHOD_INITIALIZE: &str = "initialize";
pub const METHOD_PING: &str = "ping";
pub const METHOD_TOOLS_LIST: &str = "tools/list";
pub const METHOD_TOOLS_CALL: &str = "tools/call";
pub const NOTIFY_INITIALIZED: &str = "notifications/initialized";

/// Name and version of a client or server (`clientInfo`, `serverInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Implementation {
    pub name: String,
    pub version: String,
}

impl Implementation {
    fn to_value(&self) -> Value {
        Value::object([("name", Value::str(&self.name)), ("version", Value::str(&self.version))])
    }
}

/// `initialize` params. The client's capabilities are kept as they came: a
/// tools server reads none of them.
#[derive(Clone, Debug, PartialEq)]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: Value,
    pub client_info: Implementation,
}

/// The `initialize` result: a tools server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub server_info: Implementation,
    pub instructions: Option<String>,
    /// `capabilities.tools.listChanged`: the server sends
    /// `notifications/tools/list_changed`.
    pub tools_list_changed: bool,
}

impl InitializeResult {
    /// The answer to any `initialize`: the revision we speak (the client
    /// continues if it can speak it too, and disconnects if it cannot).
    pub fn new(server_info: Implementation, instructions: Option<&str>) -> InitializeResult {
        InitializeResult {
            protocol_version: String::from(PROTOCOL_VERSION),
            server_info,
            instructions: instructions.map(String::from),
            tools_list_changed: false,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut m = alloc::vec![
            (String::from("protocolVersion"), Value::str(&self.protocol_version)),
            (
                String::from("capabilities"),
                Value::object([(
                    "tools",
                    Value::object([("listChanged", Value::Bool(self.tools_list_changed))]),
                )]),
            ),
            (String::from("serverInfo"), self.server_info.to_value()),
        ];
        if let Some(i) = &self.instructions {
            m.push((String::from("instructions"), Value::str(i)));
        }
        Value::Object(m)
    }
}

/// A tool the server offers.
#[derive(Clone, Debug, PartialEq)]
pub struct Tool {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// A JSON Schema of type `object`: the `arguments` the tool takes.
    pub input_schema: Value,
    /// A JSON Schema of the `structuredContent` the tool returns, if it does.
    pub output_schema: Option<Value>,
}

impl Tool {
    pub fn to_value(&self) -> Value {
        let mut m = alloc::vec![(String::from("name"), Value::str(&self.name))];
        if let Some(t) = &self.title {
            m.push((String::from("title"), Value::str(t)));
        }
        if let Some(d) = &self.description {
            m.push((String::from("description"), Value::str(d)));
        }
        m.push((String::from("inputSchema"), self.input_schema.clone()));
        if let Some(o) = &self.output_schema {
            m.push((String::from("outputSchema"), o.clone()));
        }
        Value::Object(m)
    }
}

/// `tools/list` params: the cursor of the page wanted (absent: the first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolsListParams {
    pub cursor: Option<String>,
}

/// The `tools/list` result: one page of tools, and where the next starts.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
    pub next_cursor: Option<String>,
}

impl ToolsListResult {
    pub fn to_value(&self) -> Value {
        let mut m = alloc::vec![(
            String::from("tools"),
            Value::Array(self.tools.iter().map(Tool::to_value).collect())
        )];
        if let Some(c) = &self.next_cursor {
            m.push((String::from("nextCursor"), Value::str(c)));
        }
        Value::Object(m)
    }
}

/// `tools/call` params.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCallParams {
    pub name: String,
    /// An object, when the call has arguments.
    pub arguments: Option<Value>,
}

/// One block of a tool's output.
#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    Text(String),
    /// `data` is base64, as it goes on the wire.
    Image { data: String, mime_type: String },
}

impl Content {
    pub fn text(s: &str) -> Content {
        Content::Text(String::from(s))
    }

    pub fn to_value(&self) -> Value {
        match self {
            Content::Text(t) => Value::object([("type", Value::str("text")), ("text", Value::str(t))]),
            Content::Image { data, mime_type } => Value::object([
                ("type", Value::str("image")),
                ("data", Value::str(data)),
                ("mimeType", Value::str(mime_type)),
            ]),
        }
    }
}

/// The `tools/call` result.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCallResult {
    pub content: Vec<Content>,
    /// A JSON object that matches the tool's `outputSchema`.
    pub structured_content: Option<Value>,
    /// The tool ran and failed: the content says why.
    pub is_error: bool,
}

impl ToolCallResult {
    pub fn text(s: &str) -> ToolCallResult {
        ToolCallResult { content: alloc::vec![Content::text(s)], structured_content: None, is_error: false }
    }

    /// A failed tool: the text is for the model to read.
    pub fn error(s: &str) -> ToolCallResult {
        ToolCallResult { content: alloc::vec![Content::text(s)], structured_content: None, is_error: true }
    }

    pub fn to_value(&self) -> Value {
        let mut m = alloc::vec![(
            String::from("content"),
            Value::Array(self.content.iter().map(Content::to_value).collect())
        )];
        if let Some(s) = &self.structured_content {
            m.push((String::from("structuredContent"), s.clone()));
        }
        m.push((String::from("isError"), Value::Bool(self.is_error)));
        Value::Object(m)
    }
}

/// A request a tools server answers.
#[derive(Clone, Debug, PartialEq)]
pub enum McpRequest {
    Initialize(InitializeParams),
    Ping,
    ToolsList(ToolsListParams),
    ToolsCall(ToolCallParams),
}

fn need_str(p: &Value, key: &str) -> Result<String, RpcError> {
    match p.get(key) {
        Some(Value::Str(s)) => Ok(s.clone()),
        _ => Err(RpcError::invalid_params(&alloc::format!("{key} must be a string"))),
    }
}

impl McpRequest {
    /// Read a request. An unknown method is `Err` with Method-not-found, a
    /// malformed `params` is `Err` with Invalid-params: send it as the response.
    pub fn from_rpc(r: &Request) -> Result<McpRequest, RpcError> {
        let empty = Value::Object(Vec::new());
        // params may be absent, or an array (never valid for these methods).
        let params = match &r.params {
            None => &empty,
            Some(p @ Value::Object(_)) => p,
            Some(_) => return Err(RpcError::invalid_params("params must be an object")),
        };
        match r.method.as_str() {
            METHOD_INITIALIZE => {
                let info = params
                    .get("clientInfo")
                    .ok_or_else(|| RpcError::invalid_params("clientInfo is required"))?;
                Ok(McpRequest::Initialize(InitializeParams {
                    protocol_version: need_str(params, "protocolVersion")?,
                    capabilities: params
                        .get("capabilities")
                        .cloned()
                        .ok_or_else(|| RpcError::invalid_params("capabilities is required"))?,
                    client_info: Implementation {
                        name: need_str(info, "name")?,
                        version: need_str(info, "version")?,
                    },
                }))
            }
            METHOD_PING => Ok(McpRequest::Ping),
            METHOD_TOOLS_LIST => {
                let cursor = match params.get("cursor") {
                    None => None,
                    Some(Value::Str(c)) => Some(c.clone()),
                    Some(_) => return Err(RpcError::invalid_params("cursor must be a string")),
                };
                Ok(McpRequest::ToolsList(ToolsListParams { cursor }))
            }
            METHOD_TOOLS_CALL => {
                let arguments = match params.get("arguments") {
                    None => None,
                    Some(a @ Value::Object(_)) => Some(a.clone()),
                    Some(_) => return Err(RpcError::invalid_params("arguments must be an object")),
                };
                Ok(McpRequest::ToolsCall(ToolCallParams { name: need_str(params, "name")?, arguments }))
            }
            other => Err(RpcError::method_not_found(other)),
        }
    }
}

/// Is this the client's `notifications/initialized`: the handshake is over and
/// requests other than `ping` may follow?
pub fn is_initialized(n: &Notification) -> bool {
    n.method == NOTIFY_INITIALIZED
}
