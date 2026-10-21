// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! JSON-RPC 2.0, as MCP uses it.
//!
//! [`decode`] turns the text of one transport message into [`Incoming`]: one
//! [`Message`] or a batch. Whatever is wrong with the input comes back as an
//! [`ErrorResponse`] that is already the reply to send (Parse error for text
//! that is not JSON, Invalid Request for JSON that is not a request), so the
//! caller never builds an error by hand for malformed input.
//!
//! * `id` is an integer or a string. `null` is refused in a request (MCP
//!   forbids it) and a fraction is not an id.
//! * `params`, when present, is an array or an object.
//! * A batch is answered by a batch of the replies to its requests, in any
//!   order, with no reply for notifications; if every member was a
//!   notification there is no reply at all. An empty batch is Invalid Request.
//!   Each member that is not a valid message gets its own error in the batch.

use crate::json::{ParseError, Value};
use alloc::string::String;
use alloc::vec::Vec;

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// The `id` of a request and of its response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Id {
    Num(i64),
    Str(String),
}

impl Id {
    fn to_value(&self) -> Value {
        match self {
            Id::Num(n) => Value::Int(*n),
            Id::Str(s) => Value::Str(s.clone()),
        }
    }

    fn from_value(v: &Value) -> Option<Id> {
        match v {
            Value::Int(n) => Some(Id::Num(*n)),
            Value::Str(s) => Some(Id::Str(s.clone())),
            _ => None,
        }
    }
}

/// The `error` object of a failed response.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: &str) -> RpcError {
        RpcError { code, message: String::from(message), data: None }
    }

    pub fn method_not_found(method: &str) -> RpcError {
        let mut e = RpcError::new(METHOD_NOT_FOUND, "Method not found");
        e.data = Some(Value::object([("method", Value::str(method))]));
        e
    }

    pub fn invalid_params(why: &str) -> RpcError {
        RpcError::new(INVALID_PARAMS, why)
    }

    fn to_value(&self) -> Value {
        let mut m = alloc::vec![
            (String::from("code"), Value::Int(self.code)),
            (String::from("message"), Value::Str(self.message.clone())),
        ];
        if let Some(d) = &self.data {
            m.push((String::from("data"), d.clone()));
        }
        Value::Object(m)
    }
}

/// A call that expects a response.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: Id,
    pub method: String,
    pub params: Option<Value>,
}

/// A call that expects none.
#[derive(Clone, Debug, PartialEq)]
pub struct Notification {
    pub method: String,
    pub params: Option<Value>,
}

/// A successful response.
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub id: Id,
    pub result: Value,
}

/// A failed response. `id` is `None` (`null` on the wire) when the request's
/// id could not be read.
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorResponse {
    pub id: Option<Id>,
    pub error: RpcError,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Request(Request),
    Notification(Notification),
    Response(Response),
    Error(ErrorResponse),
}

impl Message {
    pub fn request(id: Id, method: &str, params: Option<Value>) -> Message {
        Message::Request(Request { id, method: String::from(method), params })
    }

    pub fn notification(method: &str, params: Option<Value>) -> Message {
        Message::Notification(Notification { method: String::from(method), params })
    }

    pub fn response(id: Id, result: Value) -> Message {
        Message::Response(Response { id, result })
    }

    pub fn error(id: Option<Id>, error: RpcError) -> Message {
        Message::Error(ErrorResponse { id, error })
    }

    /// The message as a JSON value.
    pub fn to_value(&self) -> Value {
        let ver = || (String::from("jsonrpc"), Value::str("2.0"));
        let mut m = alloc::vec![ver()];
        match self {
            Message::Request(r) => {
                m.push((String::from("id"), r.id.to_value()));
                m.push((String::from("method"), Value::Str(r.method.clone())));
                if let Some(p) = &r.params {
                    m.push((String::from("params"), p.clone()));
                }
            }
            Message::Notification(n) => {
                m.push((String::from("method"), Value::Str(n.method.clone())));
                if let Some(p) = &n.params {
                    m.push((String::from("params"), p.clone()));
                }
            }
            Message::Response(r) => {
                m.push((String::from("id"), r.id.to_value()));
                m.push((String::from("result"), r.result.clone()));
            }
            Message::Error(e) => {
                m.push((String::from("id"), e.id.as_ref().map_or(Value::Null, Id::to_value)));
                m.push((String::from("error"), e.error.to_value()));
            }
        }
        Value::Object(m)
    }

    pub fn to_json(&self) -> String {
        self.to_value().to_json()
    }
}

/// The text of a batch of messages (the replies to a batch).
pub fn encode_batch(msgs: &[Message]) -> String {
    Value::Array(msgs.iter().map(Message::to_value).collect()).to_json()
}

/// A message, or the reply to send because it is not one.
pub type Item = Result<Message, ErrorResponse>;

/// What one transport message holds.
#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    Single(Item),
    Batch(Vec<Item>),
}

fn invalid(id: Option<Id>, why: &str) -> ErrorResponse {
    ErrorResponse { id, error: RpcError::new(INVALID_REQUEST, why) }
}

/// Decode the text of one transport message. `Err` is the reply to send.
pub fn decode(text: &str) -> Result<Incoming, ErrorResponse> {
    let v = Value::parse(text).map_err(|e| ErrorResponse {
        id: None,
        error: RpcError {
            code: PARSE_ERROR,
            message: String::from("Parse error"),
            data: Some(Value::str(match e {
                ParseError::Eof => "unexpected end of input",
                ParseError::Unexpected(_) => "unexpected character",
                ParseError::BadNumber(_) => "bad number",
                ParseError::BadString(_) => "bad string",
                ParseError::DuplicateKey(_) => "duplicate key",
                ParseError::TooDeep => "nesting too deep",
                ParseError::TooLong => "message too long",
                ParseError::TooManyMembers => "too many object members",
                ParseError::Trailing(_) => "trailing characters",
            })),
        },
    })?;
    match v {
        Value::Array(items) => {
            if items.is_empty() {
                return Err(invalid(None, "empty batch"));
            }
            Ok(Incoming::Batch(items.iter().map(message_from_value).collect()))
        }
        v => Ok(Incoming::Single(message_from_value(&v))),
    }
}

/// Read one message out of a JSON value.
pub fn message_from_value(v: &Value) -> Item {
    let Value::Object(_) = v else {
        return Err(invalid(None, "a message is an object"));
    };
    // The id is recovered first so that an error about the rest can name it.
    let id_value = v.get("id");
    let id = id_value.and_then(Id::from_value);
    if v.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid(id, "jsonrpc must be \"2.0\""));
    }
    let params = match v.get("params") {
        None => None,
        Some(p @ (Value::Array(_) | Value::Object(_))) => Some(p.clone()),
        Some(_) => return Err(invalid(id, "params must be an array or an object")),
    };
    if let Some(m) = v.get("method") {
        let Some(method) = m.as_str() else {
            return Err(invalid(id, "method must be a string"));
        };
        if v.get("result").is_some() || v.get("error").is_some() {
            return Err(invalid(id, "a call has no result or error"));
        }
        let method = String::from(method);
        return match (id_value, id) {
            (None, _) => Ok(Message::Notification(Notification { method, params })),
            (Some(_), Some(id)) => Ok(Message::Request(Request { id, method, params })),
            (Some(_), None) => Err(invalid(None, "id must be an integer or a string")),
        };
    }
    if v.get("params").is_some() {
        return Err(invalid(id, "params without a method"));
    }
    match (v.get("result"), v.get("error")) {
        (Some(result), None) => match id {
            Some(id) => Ok(Message::Response(Response { id, result: result.clone() })),
            None => Err(invalid(None, "a response needs the id of its request")),
        },
        (None, Some(e)) => {
            // `null` is an id here: the request's id could not be read.
            if !matches!(id_value, Some(Value::Null)) && id.is_none() {
                return Err(invalid(None, "an error response needs an id or null"));
            }
            let code = e.get("code").and_then(Value::as_i64);
            let message = e.get("message").and_then(Value::as_str);
            match (code, message) {
                (Some(code), Some(message)) => Ok(Message::Error(ErrorResponse {
                    id,
                    error: RpcError { code, message: String::from(message), data: e.get("data").cloned() },
                })),
                _ => Err(invalid(id, "error needs an integer code and a string message")),
            }
        }
        (Some(_), Some(_)) => Err(invalid(id, "a response has a result or an error, not both")),
        (None, None) => Err(invalid(id, "neither method, result nor error")),
    }
}
