// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::{assert_json, j};
use azos_mcp::json::Value;
use azos_mcp::jsonrpc::*;

fn single(text: &str) -> Item {
    match decode(text) {
        Ok(Incoming::Single(i)) => i,
        other => panic!("{other:?}"),
    }
}

fn batch(text: &str) -> Vec<Item> {
    match decode(text) {
        Ok(Incoming::Batch(v)) => v,
        other => panic!("{other:?}"),
    }
}

fn err_code(i: &Item) -> (Option<Id>, i64) {
    let e = i.as_ref().unwrap_err();
    (e.id.clone(), e.error.code)
}

// ---- the examples of section 7 of the JSON-RPC 2.0 specification -------------

#[test]
fn rpc_call_with_positional_parameters() {
    let m = single(r#"{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}"#).unwrap();
    assert_eq!(
        m,
        Message::request(
            Id::Num(1),
            "subtract",
            Some(Value::Array(vec![Value::Int(42), Value::Int(23)]))
        )
    );
    // The response of the specification.
    assert_json(
        &Message::response(Id::Num(1), Value::Int(19)).to_json(),
        r#"{"jsonrpc": "2.0", "result": 19, "id": 1}"#,
    );
}

#[test]
fn rpc_call_with_named_parameters() {
    let m = single(
        r#"{"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}"#,
    )
    .unwrap();
    let Message::Request(r) = m else { panic!() };
    assert_eq!(r.id, Id::Num(3));
    assert_eq!(r.params.unwrap().get("minuend").and_then(Value::as_i64), Some(42));
}

#[test]
fn a_notification() {
    let m = single(r#"{"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}"#).unwrap();
    assert!(matches!(m, Message::Notification(ref n) if n.method == "update"));
    assert_eq!(
        m.to_json(),
        r#"{"jsonrpc":"2.0","method":"update","params":[1,2,3,4,5]}"#
    );
    let m = single(r#"{"jsonrpc": "2.0", "method": "foobar"}"#).unwrap();
    assert_eq!(m, Message::notification("foobar", None));
}

#[test]
fn method_not_found_response() {
    let e = RpcError::new(METHOD_NOT_FOUND, "Method not found");
    assert_json(
        &Message::error(Some(Id::Str("1".into())), e).to_json(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}"#,
    );
}

#[test]
fn parse_error_for_invalid_json() {
    let e = decode(r#"{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]"#).unwrap_err();
    assert_eq!((e.id.clone(), e.error.code), (None, PARSE_ERROR));
    assert_eq!(e.error.message, "Parse error");
    assert_json(
        &Message::Error(e).to_json(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error", "data": "unexpected character"}, "id": null}"#,
    );
}

#[test]
fn invalid_request_object() {
    // method is not a string (and params is not structured).
    assert_eq!(err_code(&single(r#"{"jsonrpc": "2.0", "method": 1, "params": "bar"}"#)), (None, INVALID_REQUEST));
    // Method not a string, id readable: the error names the id.
    assert_eq!(
        err_code(&single(r#"{"jsonrpc": "2.0", "method": 1, "id": 7}"#)),
        (Some(Id::Num(7)), INVALID_REQUEST)
    );
}

#[test]
fn batch_with_invalid_json() {
    let e = decode(
        r#"[ {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"}, {"jsonrpc": "2.0", "method" ]"#,
    )
    .unwrap_err();
    assert_eq!(e.error.code, PARSE_ERROR);
}

#[test]
fn empty_batch_and_batch_of_non_requests() {
    let e = decode("[]").unwrap_err();
    assert_eq!((e.id, e.error.code), (None, INVALID_REQUEST));
    // [1]: one reply, an error.
    let b = batch("[1]");
    assert_eq!(b.len(), 1);
    assert_eq!(err_code(&b[0]), (None, INVALID_REQUEST));
    // [1,2,3]: three.
    let b = batch("[1,2,3]");
    assert_eq!(b.len(), 3);
    assert!(b.iter().all(|i| err_code(i) == (None, INVALID_REQUEST)));
}

#[test]
fn batch_of_mixed_calls() {
    let b = batch(
        r#"[
        {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
        {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]},
        {"jsonrpc": "2.0", "method": "subtract", "params": [42,23], "id": "2"},
        {"foo": "boo"},
        {"jsonrpc": "2.0", "method": "foo.get", "params": {"name": "myself"}, "id": "5"},
        {"jsonrpc": "2.0", "method": "get_data", "id": "9"}
    ]"#,
    );
    assert_eq!(b.len(), 6);
    assert!(matches!(&b[0], Ok(Message::Request(r)) if r.id == Id::Str("1".into())));
    assert!(matches!(&b[1], Ok(Message::Notification(_))));
    assert!(matches!(&b[2], Ok(Message::Request(_))));
    assert_eq!(err_code(&b[3]), (None, INVALID_REQUEST));
    assert!(matches!(&b[4], Ok(Message::Request(r)) if r.method == "foo.get"));
    assert!(matches!(&b[5], Ok(Message::Request(r)) if r.params.is_none()));
    // The reply batch of the specification's example.
    let reply = encode_batch(&[
        Message::response(Id::Str("1".into()), Value::Int(7)),
        Message::error(None, RpcError::new(INVALID_REQUEST, "Invalid Request")),
    ]);
    assert_json(
        &reply,
        r#"[{"jsonrpc":"2.0","result":7,"id":"1"},{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}]"#,
    );
    // A batch of notifications: all Ok, none expects a reply.
    let b = batch(r#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","method":"b","params":{}}]"#);
    assert!(b.iter().all(|i| matches!(i, Ok(Message::Notification(_)))));
}

// ---- the rest of the grammar ------------------------------------------------

#[test]
fn ids() {
    assert!(matches!(single(r#"{"jsonrpc":"2.0","method":"m","id":"abc"}"#), Ok(Message::Request(r)) if r.id == Id::Str("abc".into())));
    assert!(matches!(single(r#"{"jsonrpc":"2.0","method":"m","id":-5}"#), Ok(Message::Request(r)) if r.id == Id::Num(-5)));
    // MCP: null is not an id; a fraction is not an id; a structure is not an id.
    for bad in ["null", "1.5", "[1]", "{}", "true"] {
        let t = format!(r#"{{"jsonrpc":"2.0","method":"m","id":{bad}}}"#);
        assert_eq!(err_code(&single(&t)), (None, INVALID_REQUEST), "{bad}");
    }
}

#[test]
fn version_and_params_are_checked() {
    for t in [
        r#"{"method":"m"}"#,
        r#"{"jsonrpc":"1.0","method":"m"}"#,
        r#"{"jsonrpc":2,"method":"m"}"#,
        r#"{"jsonrpc":"2.0","method":"m","params":3}"#,
        r#"{"jsonrpc":"2.0","method":"m","params":null}"#,
        r#"{"jsonrpc":"2.0","method":"m","result":1}"#,
        r#"{"jsonrpc":"2.0","method":"m","error":{"code":1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"params":[]}"#,
    ] {
        assert_eq!(err_code(&single(t)).1, INVALID_REQUEST, "{t}");
    }
    // The id survives into the error.
    assert_eq!(
        err_code(&single(r#"{"jsonrpc":"1.0","method":"m","id":4}"#)),
        (Some(Id::Num(4)), INVALID_REQUEST)
    );
}

#[test]
fn responses_are_read_too() {
    let m = single(r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#).unwrap();
    assert_eq!(m, Message::response(Id::Num(2), j(r#"{"ok":true}"#)));
    // A result may be null.
    assert!(matches!(single(r#"{"jsonrpc":"2.0","id":2,"result":null}"#), Ok(Message::Response(_))));
    let m = single(r#"{"jsonrpc":"2.0","id":"x","error":{"code":-32602,"message":"bad","data":[1]}}"#).unwrap();
    let Message::Error(e) = m else { panic!() };
    assert_eq!(e.id, Some(Id::Str("x".into())));
    assert_eq!((e.error.code, e.error.message.as_str()), (-32602, "bad"));
    assert_eq!(e.error.data, Some(j("[1]")));
    // id null is how an error answers an unreadable request.
    assert!(matches!(single(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"p"}}"#), Ok(Message::Error(ErrorResponse { id: None, .. }))));
    for bad in [
        r#"{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","result":1}"#,
        r#"{"jsonrpc":"2.0","id":null,"result":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"1","message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":"x"}"#,
        r#"{"jsonrpc":"2.0","error":{"code":1,"message":"x"}}"#,
    ] {
        assert!(single(bad).is_err(), "{bad}");
    }
}

#[test]
fn every_message_survives_a_round_trip() {
    let msgs = [
        Message::request(Id::Num(i64::MIN), "tools/call", Some(j(r#"{"name":"x","arguments":{}}"#))),
        Message::request(Id::Str("a\"b".into()), "ping", None),
        Message::notification("notifications/initialized", None),
        Message::response(Id::Num(0), j(r#"[1,{"a":null}]"#)),
        Message::error(None, RpcError::new(PARSE_ERROR, "Parse error")),
        Message::error(Some(Id::Num(1)), RpcError { code: 5, message: "m".into(), data: Some(j("{}")) }),
    ];
    for m in msgs {
        assert_eq!(single(&m.to_json()), Ok(m.clone()), "{}", m.to_json());
    }
}

#[test]
fn duplicate_keys_in_a_message_are_a_parse_error() {
    let e = decode(r#"{"jsonrpc":"2.0","method":"a","method":"b","id":1}"#).unwrap_err();
    assert_eq!(e.error.code, PARSE_ERROR);
}

#[test]
fn error_helpers() {
    let e = RpcError::method_not_found("tools/nope");
    assert_eq!(e.code, METHOD_NOT_FOUND);
    assert_json(
        &Message::error(Some(Id::Num(1)), e).to_json(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found","data":{"method":"tools/nope"}}}"#,
    );
    assert_eq!(RpcError::invalid_params("x").code, INVALID_PARAMS);
    assert_eq!(INTERNAL_ERROR, -32603);
}
