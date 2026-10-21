// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::{assert_json, j};
use azos_mcp::json::Value;
use azos_mcp::jsonrpc::{decode, Id, Incoming, Message, Request, METHOD_NOT_FOUND, INVALID_PARAMS};
use azos_mcp::mcp::*;

fn req(text: &str) -> Request {
    match decode(text) {
        Ok(Incoming::Single(Ok(Message::Request(r)))) => r,
        other => panic!("{other:?}"),
    }
}

#[test]
fn initialize() {
    // The request of the lifecycle page.
    let r = req(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{"elicitation":{}},
            "clientInfo":{"name":"example-client","title":"Example Client Display Name","version":"1.0.0"}}}"#,
    );
    let McpRequest::Initialize(p) = McpRequest::from_rpc(&r).unwrap() else { panic!() };
    assert_eq!(p.protocol_version, "2025-06-18");
    assert_eq!(p.client_info, Implementation { name: "example-client".into(), version: "1.0.0".into() });
    assert_eq!(p.capabilities, j(r#"{"elicitation":{}}"#));

    let res = InitializeResult::new(
        Implementation { name: "mcpd".into(), version: "0.1.0".into() },
        Some("AzOS tools"),
    );
    assert_json(
        &Message::response(Id::Num(1), res.to_value()).to_json(),
        r#"{"jsonrpc":"2.0","id":1,"result":{
            "protocolVersion":"2025-06-18",
            "capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"mcpd","version":"0.1.0"},
            "instructions":"AzOS tools"}}"#,
    );
    // Without instructions the member is absent.
    let res = InitializeResult::new(Implementation { name: "n".into(), version: "v".into() }, None);
    assert!(res.to_value().get("instructions").is_none());

    // Missing pieces.
    for bad in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"x","capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"capabilities":{},"clientInfo":{"name":"a","version":"b"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"x","clientInfo":{"name":"a","version":"b"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}"#,
    ] {
        assert_eq!(McpRequest::from_rpc(&req(bad)).unwrap_err().code, INVALID_PARAMS, "{bad}");
    }
}

#[test]
fn initialized_notification_and_ping() {
    let Ok(Incoming::Single(Ok(Message::Notification(n)))) =
        decode(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
    else {
        panic!()
    };
    assert!(is_initialized(&n));
    let Ok(Incoming::Single(Ok(Message::Notification(n)))) =
        decode(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#)
    else {
        panic!()
    };
    assert!(!is_initialized(&n));
    assert_eq!(
        McpRequest::from_rpc(&req(r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#)),
        Ok(McpRequest::Ping)
    );
    // The result of a ping is an empty object.
    assert_json(
        &Message::response(Id::Str("p".into()), Value::Object(vec![])).to_json(),
        r#"{"jsonrpc":"2.0","id":"p","result":{}}"#,
    );
}

#[test]
fn tools_list() {
    let r = req(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"optional-cursor-value"}}"#);
    assert_eq!(
        McpRequest::from_rpc(&r),
        Ok(McpRequest::ToolsList(ToolsListParams { cursor: Some("optional-cursor-value".into()) }))
    );
    // No params at all: the first page.
    let r = req(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(McpRequest::from_rpc(&r), Ok(McpRequest::ToolsList(ToolsListParams { cursor: None })));
    let r = req(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":5}}"#);
    assert_eq!(McpRequest::from_rpc(&r).unwrap_err().code, INVALID_PARAMS);

    // The response of the tools page.
    let res = ToolsListResult {
        tools: vec![Tool {
            name: "get_weather".into(),
            title: Some("Weather Information Provider".into()),
            description: Some("Get current weather information for a location".into()),
            input_schema: j(r#"{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]}"#),
            output_schema: None,
        }],
        next_cursor: Some("next-page-cursor".into()),
    };
    assert_json(
        &Message::response(Id::Num(1), res.to_value()).to_json(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{
            "name":"get_weather","title":"Weather Information Provider",
            "description":"Get current weather information for a location",
            "inputSchema":{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]}}],
            "nextCursor":"next-page-cursor"}}"#,
    );
    // The last page has no cursor; a tool with the bare minimum.
    let res = ToolsListResult {
        tools: vec![Tool {
            name: "t".into(),
            title: None,
            description: None,
            input_schema: j(r#"{"type":"object"}"#),
            output_schema: Some(j(r#"{"type":"object"}"#)),
        }],
        next_cursor: None,
    };
    assert_json(
        &res.to_value().to_json(),
        r#"{"tools":[{"name":"t","inputSchema":{"type":"object"},"outputSchema":{"type":"object"}}]}"#,
    );
}

#[test]
fn tools_call() {
    let r = req(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"New York"}}}"#,
    );
    let McpRequest::ToolsCall(c) = McpRequest::from_rpc(&r).unwrap() else { panic!() };
    assert_eq!(c.name, "get_weather");
    assert_eq!(c.arguments.unwrap().get("location").and_then(Value::as_str), Some("New York"));
    // No arguments.
    let r = req(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"now"}}"#);
    assert_eq!(
        McpRequest::from_rpc(&r),
        Ok(McpRequest::ToolsCall(ToolCallParams { name: "now".into(), arguments: None }))
    );
    for bad in [
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":3}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":[1]}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":["x"]}"#,
    ] {
        assert_eq!(McpRequest::from_rpc(&req(bad)).unwrap_err().code, INVALID_PARAMS, "{bad}");
    }

    // The result of the tools page.
    let res = ToolCallResult::text("Current weather in New York:\nTemperature: 72°F\nConditions: Partly cloudy");
    assert_json(
        &Message::response(Id::Num(2), res.to_value()).to_json(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text",
            "text":"Current weather in New York:\nTemperature: 72°F\nConditions: Partly cloudy"}],"isError":false}}"#,
    );
    // A tool that failed is a result, not a protocol error.
    let res = ToolCallResult::error("Failed to fetch weather data: API rate limit exceeded");
    assert_json(
        &res.to_value().to_json(),
        r#"{"content":[{"type":"text","text":"Failed to fetch weather data: API rate limit exceeded"}],"isError":true}"#,
    );
    // Structured content and an image block.
    let res = ToolCallResult {
        content: vec![
            Content::text("{\"temperature\":22.5}"),
            Content::Image { data: "AAEC".into(), mime_type: "image/png".into() },
        ],
        structured_content: Some(j(r#"{"temperature":22.5}"#)),
        is_error: false,
    };
    assert_json(
        &res.to_value().to_json(),
        r#"{"content":[{"type":"text","text":"{\"temperature\":22.5}"},
            {"type":"image","data":"AAEC","mimeType":"image/png"}],
            "structuredContent":{"temperature":22.5},"isError":false}"#,
    );
}

#[test]
fn unknown_methods_are_method_not_found() {
    for m in ["resources/list", "prompts/list", "tools/nope", ""] {
        let r = req(&format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}"}}"#));
        let e = McpRequest::from_rpc(&r).unwrap_err();
        assert_eq!(e.code, METHOD_NOT_FOUND);
        assert_eq!(e.data.unwrap().get("method").and_then(Value::as_str), Some(m));
    }
}

#[test]
fn a_whole_session_in_text() {
    // initialize -> initialized -> tools/list -> tools/call, each message
    // decoded and its reply written, as the daemon will.
    let lines = [
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
    ];
    let mut replies = Vec::new();
    for l in lines {
        match decode(l).unwrap() {
            Incoming::Single(Ok(Message::Request(r))) => {
                let result = match McpRequest::from_rpc(&r).unwrap() {
                    McpRequest::Initialize(_) => InitializeResult::new(
                        Implementation { name: "s".into(), version: "1".into() },
                        None,
                    )
                    .to_value(),
                    McpRequest::ToolsList(_) => ToolsListResult { tools: vec![], next_cursor: None }.to_value(),
                    McpRequest::ToolsCall(c) => {
                        let t = c.arguments.unwrap().get("text").and_then(Value::as_str).unwrap().to_string();
                        ToolCallResult::text(&t).to_value()
                    }
                    McpRequest::Ping => Value::Object(vec![]),
                };
                replies.push(Message::response(r.id, result).to_json());
            }
            Incoming::Single(Ok(Message::Notification(n))) => assert!(is_initialized(&n)),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(replies.len(), 3);
    assert_json(&replies[2], r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hi"}],"isError":false}}"#);
}
