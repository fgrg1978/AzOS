// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The std side's trap wrappers are a copy of libsys's (libsys cannot be in
//! the std build graph). The register discipline is what the `sysabi` gate
//! rows hold, so the copy must not drift: the bodies are compared as text,
//! comments and whitespace aside.

const LIBSYS: &str = include_str!("../../../../crates/core/libsys/src/lib.rs");
const STDRT: &str = include_str!("../../../../crates/core/stdrt/src/sys.rs");

/// The body of `fn name`, from its opening brace to the matching one,
/// without comments and with all whitespace dropped.
fn body(src: &str, name: &str) -> String {
    let at = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let rest = &src[at..];
    let open = rest.find('{').unwrap();
    // `{` inside the signature's generics does not occur in these two.
    let mut depth = 0usize;
    let mut end = None;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let text = &rest[open..end.expect("unbalanced braces")];
    let mut out = String::new();
    for line in text.lines() {
        let code = line.split("//").next().unwrap();
        out.extend(code.chars().filter(|c| !c.is_whitespace()));
    }
    out
}

#[test]
fn syscall6_is_libsys_syscall6() {
    assert_eq!(body(STDRT, "syscall6"), body(LIBSYS, "syscall6"));
}

#[test]
fn invoke_is_libsys_invoke() {
    assert_eq!(body(STDRT, "invoke"), body(LIBSYS, "invoke"));
}

/// **Canary.** The comparison discriminates: a one-register change in the
/// copy is a different body.
#[test]
fn a_changed_register_list_is_noticed() {
    let drifted = STDRT.replacen("lateout(\"t6\") _", "lateout(\"t5\") _", 1);
    assert_ne!(body(&drifted, "syscall6"), body(LIBSYS, "syscall6"));
}
