// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the MCP codec (`userspace/lib/mcp`): JSON, JSON-RPC 2.0 and the
//! MCP shapes. The JSON-RPC cases are the examples of the JSON-RPC 2.0
//! specification (section 7), the MCP ones those of the 2025-06-18 revision
//! (lifecycle and tools pages), written out here as text.
#![cfg(test)]

mod json;
mod jsonrpc;
mod mcp;

use azos_mcp::json::Value;

/// Parse, panicking with the text if it is not JSON.
pub fn j(text: &str) -> Value {
    Value::parse(text).unwrap_or_else(|e| panic!("{e:?}: {text}"))
}

/// Equality of JSON that ignores the order of members in objects.
pub fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| y.iter().any(|(k2, v2)| k == k2 && same(v, v2)))
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        _ => a == b,
    }
}

pub fn assert_json(got: &str, want: &str) {
    let (g, w) = (j(got), j(want));
    assert!(same(&g, &w), "\n got: {got}\nwant: {want}");
}
