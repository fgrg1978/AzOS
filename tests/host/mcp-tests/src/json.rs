// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_mcp::json::{ParseError, Value, MAX_DEPTH};

fn p(t: &str) -> Result<Value, ParseError> {
    Value::parse(t)
}

#[test]
fn scalars_and_structures() {
    assert_eq!(p("null"), Ok(Value::Null));
    assert_eq!(p(" true "), Ok(Value::Bool(true)));
    assert_eq!(p("false"), Ok(Value::Bool(false)));
    assert_eq!(p("0"), Ok(Value::Int(0)));
    assert_eq!(p("-0"), Ok(Value::Int(0)));
    assert_eq!(p("-12"), Ok(Value::Int(-12)));
    assert_eq!(p("9223372036854775807"), Ok(Value::Int(i64::MAX)));
    assert_eq!(p("-9223372036854775808"), Ok(Value::Int(i64::MIN)));
    // Past i64: a float, not a wrong integer.
    assert_eq!(p("9223372036854775808"), Ok(Value::Float(9223372036854775808.0)));
    assert_eq!(p("1.5"), Ok(Value::Float(1.5)));
    assert_eq!(p("1e2"), Ok(Value::Float(100.0)));
    assert_eq!(p("-2.5E-1"), Ok(Value::Float(-0.25)));
    assert_eq!(p("[]"), Ok(Value::Array(vec![])));
    assert_eq!(p("{}"), Ok(Value::Object(vec![])));
    assert_eq!(
        p(r#" { "a" : [ 1 , "x" , null ] , "b" : { "c" : false } } "#).unwrap(),
        Value::object([
            ("a", Value::Array(vec![Value::Int(1), Value::str("x"), Value::Null])),
            ("b", Value::object([("c", Value::Bool(false))])),
        ])
    );
}

#[test]
fn strings() {
    assert_eq!(p(r#""a\"b\\c\/d\b\f\n\r\t""#), Ok(Value::str("a\"b\\c/d\u{8}\u{c}\n\r\t")));
    assert_eq!(p(r#""Aé""#), Ok(Value::str("Aé")));
    // A surrogate pair is one character.
    assert_eq!(p(r#""😀""#), Ok(Value::str("😀")));
    // Raw UTF-8 passes through.
    assert_eq!(p("\"é€😀\""), Ok(Value::str("é€😀")));
    assert_eq!(p(r#""\u0000""#), Ok(Value::str("\0")));
    // Lone surrogates, either half.
    assert!(matches!(p(r#""\ud83d""#), Err(ParseError::BadString(_))));
    assert!(matches!(p(r#""\ud83dx""#), Err(ParseError::BadString(_))));
    assert!(matches!(p(r#""\ude00""#), Err(ParseError::BadString(_))));
    assert!(matches!(p(r#""\ud83dA""#), Err(ParseError::BadString(_))));
    // Bad escapes, short \u, raw control characters.
    assert!(matches!(p(r#""\x""#), Err(ParseError::BadString(_))));
    assert!(matches!(p(r#""\u12g4""#), Err(ParseError::BadString(_))));
    assert_eq!(p(r#""\u12"#), Err(ParseError::Eof));
    assert!(matches!(p("\"a\nb\""), Err(ParseError::BadString(_))));
    assert!(matches!(p("\"a\tb\""), Err(ParseError::BadString(_))));
    assert_eq!(p("\"abc"), Err(ParseError::Eof));
}

#[test]
fn not_json() {
    for t in [
        "01", "1.", ".5", "-", "+1", "1e", "1e+", "--1", "0x10", "NaN", "Infinity", "[1,]", "[,1]",
        "{\"a\":1,}", "{'a':1}", "{a:1}", "[1 2]", "{\"a\" 1}", "{\"a\":}", "nul", "tru e", "[", "{",
        "", "  ", "1 2", "[] x", "// c\n1", "\u{feff}1",
    ] {
        assert!(p(t).is_err(), "{t:?} must be refused");
    }
    assert_eq!(p(""), Err(ParseError::Eof));
    assert_eq!(p("[] x"), Err(ParseError::Trailing(3)));
    // Not finite.
    assert!(matches!(p("1e999"), Err(ParseError::BadNumber(_))));
}

#[test]
fn repeated_keys_are_refused() {
    assert!(matches!(p(r#"{"a":1,"a":2}"#), Err(ParseError::DuplicateKey(_))));
    assert!(matches!(p(r#"{"a":1,"b":{"x":1,"x":1}}"#), Err(ParseError::DuplicateKey(_))));
    // The same key in different objects is fine.
    assert!(p(r#"[{"a":1},{"a":2}]"#).is_ok());
}

#[test]
fn depth_is_bounded() {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(p(&deep(MAX_DEPTH)).is_ok());
    assert_eq!(p(&deep(MAX_DEPTH + 1)), Err(ParseError::TooDeep));
    // A hostile megabyte of brackets is refused without recursing it.
    assert_eq!(p(&"[".repeat(1 << 20)), Err(ParseError::TooDeep));
    let deep_obj = format!("{}1{}", "{\"a\":".repeat(MAX_DEPTH + 1), "}".repeat(MAX_DEPTH + 1));
    assert_eq!(p(&deep_obj), Err(ParseError::TooDeep));
}

#[test]
fn size_and_member_count_are_bounded() {
    use azos_mcp::json::{MAX_LEN, MAX_MEMBERS};
    // A hostile object of ~100 K tiny distinct keys is refused at the member
    // limit, after MAX_MEMBERS^2/2 comparisons, not 5 G.
    let many: String =
        (0..100_000).map(|i| format!("\"{i}\":0")).collect::<Vec<_>>().join(",");
    assert_eq!(p(&format!("{{{many}}}")), Err(ParseError::TooManyMembers));
    // The bound is exact.
    let obj = |n: usize| {
        let m: Vec<String> = (0..n).map(|i| format!("\"{i}\":0")).collect();
        format!("{{{}}}", m.join(","))
    };
    match p(&obj(MAX_MEMBERS)) {
        Ok(Value::Object(m)) => assert_eq!(m.len(), MAX_MEMBERS),
        other => panic!("{other:?}"),
    }
    assert_eq!(p(&obj(MAX_MEMBERS + 1)), Err(ParseError::TooManyMembers));
    // Inside the limit a repeated key is still a duplicate.
    assert!(matches!(p(r#"{"a":1,"a":2}"#), Err(ParseError::DuplicateKey(_))));
    // The text itself is bounded.
    let big = format!("[{}0]", "0,".repeat(MAX_LEN / 2));
    assert!(big.len() > MAX_LEN);
    assert_eq!(p(&big), Err(ParseError::TooLong));
    let fits = format!("\"{}\"", "a".repeat(MAX_LEN - 2));
    assert_eq!(fits.len(), MAX_LEN);
    assert!(p(&fits).is_ok());
    assert_eq!(p(&format!("{fits} ")), Err(ParseError::TooLong));
    // Through JSON-RPC the oversize is a parse error reply.
    assert!(azos_mcp::jsonrpc::decode(&big).is_err());
}

#[test]
fn writer() {
    assert_eq!(Value::Null.to_json(), "null");
    assert_eq!(Value::Int(-5).to_json(), "-5");
    assert_eq!(Value::Float(1.5).to_json(), "1.5");
    assert_eq!(Value::Float(f64::NAN).to_json(), "null");
    assert_eq!(Value::Float(f64::INFINITY).to_json(), "null");
    assert_eq!(Value::str("a\"b\\c\n\u{1}é/").to_json(), r#""a\"b\\c\n\u0001é/""#);
    assert_eq!(
        Value::object([
            ("k", Value::Array(vec![Value::Bool(true), Value::Null])),
            ("z", Value::object([])),
        ])
        .to_json(),
        r#"{"k":[true,null],"z":{}}"#
    );
}

#[test]
fn text_round_trips() {
    for t in [
        r#"{"a":[1,2.5,"x\n\u0001",null,true,{"b":{}}],"é":"😀"}"#,
        "[]",
        r#""\"""#,
        "-9223372036854775808",
    ] {
        let v = p(t).unwrap();
        assert_eq!(v.to_json(), t);
        assert_eq!(p(&v.to_json()), Ok(v));
    }
}

#[test]
fn accessors() {
    let v = p(r#"{"s":"x","i":3,"b":true,"a":[1],"o":{}}"#).unwrap();
    assert_eq!(v.get("s").and_then(Value::as_str), Some("x"));
    assert_eq!(v.get("i").and_then(Value::as_i64), Some(3));
    assert_eq!(v.get("b").and_then(Value::as_bool), Some(true));
    assert_eq!(v.get("a").and_then(Value::as_array).map(|a| a.len()), Some(1));
    assert!(v.get("o").unwrap().is_object());
    assert_eq!(v.get("missing"), None);
    assert_eq!(Value::Int(1).get("x"), None);
    assert_eq!(v.get("s").and_then(Value::as_i64), None);
}
