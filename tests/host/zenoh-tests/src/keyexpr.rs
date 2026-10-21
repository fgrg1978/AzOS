// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_zenoh::keyexpr::{includes, intersects, is_valid, MAX_KEY_LEN};

#[test]
fn well_formed() {
    for k in [
        "a", "a/b", "a/*", "a/**", "**", "*", "*/**", "**/a", "a/**/c", "a$*", "$*a", "a$*b$*c",
        "@/router/a", "a/b.c-d_e~f", "a/b%20c", "é/ü",
    ] {
        assert!(is_valid(k), "{k}");
    }
    for k in [
        "", "/", "a/", "/a", "a//b", "**/**", "a/**/**", "**/*", "$*", "a/$*/b", "a*", "a*b",
        "a$", "a$b", "a$*$*b", "a#b", "a?b", "@a$*", "a/**/*",
    ] {
        assert!(!is_valid(k), "{k}");
    }
}

#[test]
fn intersection() {
    let yes = [
        ("a/b", "a/b"),
        ("a/*", "a/b"),
        ("a/**", "a"),
        ("a/**", "a/b/c"),
        ("**", "a/b"),
        ("**", "**"),
        ("**/c", "a/b/c"),
        ("a/**/c", "a/c"),
        ("a/**/c", "a/b/d/c"),
        ("**/a", "a/**"),
        ("*/a", "a/*"),
        ("*/**", "a"),
        ("a$*", "abc"),
        ("a$*", "a"),
        ("$*a$*", "xaz"),
        ("a$*b", "$*b"),
        ("*", "a$*"),
        ("a$*", "$*b"),
        ("@/x", "@/x"),
        ("@", "@"),
        ("**/x", "x"),
    ];
    let no = [
        ("a/b", "a/c"),
        ("a/*", "a"),
        ("a/*", "a/b/c"),
        ("*", "a/b"),
        ("**/c", "a/b/d"),
        ("a/*/c", "a/b/d/c"),
        ("a/**/b", "a/**/c"),
        ("a$*c", "abd"),
        ("a$*", "b$*"),
        ("$*a$*", "xyz"),
        ("a$*b", "$*c"),
        ("**", "@/x"),
        ("**/x", "@/x"),
        ("*/x", "@/x"),
        ("*", "@"),
        ("$*", "@"),
        ("@/x", "@/y"),
        ("a", ""),
        ("a//b", "a/b"),
    ];
    for (a, b) in yes {
        assert!(intersects(a, b), "{a} ∩ {b}");
        assert!(intersects(b, a), "{b} ∩ {a}");
    }
    for (a, b) in no {
        assert!(!intersects(a, b), "{a} ∩ {b}");
        assert!(!intersects(b, a), "{b} ∩ {a}");
    }
}

#[test]
fn inclusion() {
    let yes = [
        ("a/b", "a/b"),
        ("a/**", "a/b"),
        ("a/**", "a"),
        ("a/*", "a/b"),
        ("**", "a/*"),
        ("**", "**"),
        ("a/*/c", "a/b/c"),
        ("**/c", "a/**/c"),
        ("a$*", "ab$*"),
        ("*", "a$*"),
        ("$*a$*", "xay"),
        ("*/**", "a/**"),
        ("a/b/**", "a/b"),
        ("a/**/b", "a/b"),
        ("@/a", "@/a"),
        ("a/**", "a/**/b"),
    ];
    let no = [
        ("a/*", "a/**"),
        ("a/b", "a/*"),
        ("a/**/c", "**/c"),
        ("ab$*", "a$*"),
        ("a$*", "*"),
        ("a/**", "*/**"),
        ("**", "@/a"),
        ("*", "@"),
        ("a/*", "a"),
        ("a/b", "a/b/c"),
        ("a/b/c", "a/b"),
        ("a$*b", "a$*"),
    ];
    for (a, b) in yes {
        assert!(includes(a, b), "{a} ⊇ {b}");
        assert!(intersects(a, b), "inclusion implies intersection: {a} {b}");
    }
    for (a, b) in no {
        assert!(!includes(a, b), "{a} ⊉ {b}");
    }
    // Malformed arguments are neither.
    assert!(!includes("a//b", "a/b") && !includes("a/b", "") && !includes("**/**", "a"));
}

#[test]
fn a_subscription_receives_a_concrete_key() {
    // The router's question: a PUSH on a concrete key, subscribers with patterns.
    let key = "demo/example/temp";
    assert!(includes("demo/**", key));
    assert!(includes("demo/*/temp", key));
    assert!(includes("**/temp", key));
    assert!(!includes("demo/*", key));
    assert!(!includes("demo/example/hum", key));
    assert!(includes("demo/ex$*/temp", key));
    assert!(!includes("demo/@ex$*", key));
}

#[test]
fn long_keys_do_not_blow_up() {
    // Patterns of 200 chunks with many `**`: the tables are quadratic, not exponential.
    let chunk = |i: usize| if i % 2 == 0 { format!("c{i}") } else { "**".to_string() };
    let x: String = (0..199).map(chunk).collect::<Vec<_>>().join("/");
    let y = format!("{x}/**/zzz");
    assert!(!intersects(&x, &y));
    assert!(intersects(&x, &x) && includes(&x, &x));
    // Shifted by one chunk they do share keys: c0/c2/../c198/c200.
    let a: String = (0..200).map(chunk).collect::<Vec<_>>().join("/");
    let b: String = (1..201).map(chunk).collect::<Vec<_>>().join("/");
    assert!(intersects(&a, &b));
    assert!(!includes(&a, &b));
}

#[test]
fn oversized_keys_are_refused_before_any_table_is_built() {
    // Remote peers choose the key: a 64 KiB run of `$*` pairs would ask the
    // glob matcher for a 4 G cell table, 32 K one-byte chunks for 1 G cells.
    let stars = "a$*".repeat(1 << 15);
    let chunks = vec!["a"; 1 << 15].join("/");
    for k in [stars.as_str(), chunks.as_str()] {
        assert!(!is_valid(k));
        assert!(!intersects(k, k) && !includes(k, k));
        assert!(!intersects("**", k) && !includes("**", k) && !includes(k, "a"));
    }
    // The bound is exact: MAX_KEY_LEN bytes pass, one more does not.
    let at = "a".repeat(MAX_KEY_LEN);
    assert!(is_valid(&at) && includes(&at, &at));
    let over = "a".repeat(MAX_KEY_LEN + 1);
    assert!(!is_valid(&over) && !intersects(&over, &over));
    // Two worst-case in-bound text chunks still answer.
    let g = "a$*".repeat(MAX_KEY_LEN / 3);
    assert!(is_valid(&g) && intersects(&g, &g) && includes(&g, &g));
}
