// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A `node` row that is no directory tree is a launch grant: `EXEC` on one
//! image (`TOOLBOX.ELF`) or on every image of one signed package (`pkg.` and
//! the 64 lower-case hex digits of its id). The parser refuses any other
//! spelling, so a grant that would be seeded to nothing is an error at parse.

use azos_abi::cap::{launch_name, CapKind, CapPerms};
use azos_topology::builder::default_minimal;
use azos_topology::{parse_caps, ParseError, Topology};

const ID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn row(target: &str, perm: &str) -> String {
    format!("[task.SH.ELF]\ncaps = [ {{ kind = \"node\", target = \"{target}\", perm = \"{perm}\" }} ]\n")
}

fn parsed(target: &str, perm: &str) -> Result<Vec<(String, CapPerms)>, ParseError> {
    let text = row(target, perm);
    let mut topo = Topology::empty();
    parse_caps(text.as_bytes(), &mut topo)?;
    Ok(topo.caps_of(&topo.tasks()[0]).iter().map(|c| (c.target.as_str().to_string(), c.perms)).collect())
}

/// **An image grant and a package grant parse, whole.**
///
/// **Canary.** Make `launch_name::parse` return `None` for a package id: the
/// package row is refused.
#[test]
fn an_image_and_a_package_parse() {
    assert_eq!(parsed("TOOLBOX.ELF", "x").unwrap(), vec![("TOOLBOX.ELF".to_string(), CapPerms::EXEC)]);
    let pkg = format!("pkg.{ID}");
    assert_eq!(parsed(&pkg, "x").unwrap(), vec![(pkg.clone(), CapPerms::EXEC)]);
}

/// **A directory tree keeps its own rules.**
#[test]
fn a_tree_is_not_a_launch_grant() {
    assert!(parsed("/fat", "rw").is_ok());
    assert!(parsed("/", "r").is_ok());
}

/// **Only `EXEC`, and only a spelling the kernel can intern.** Every
/// refusal is `BadValue`, at parse, before any boot.
///
/// **Canary.** Drop the check in `cap_spec_from_inline`: each refusal below
/// parses.
#[test]
fn any_other_launch_grant_is_refused() {
    let short = format!("pkg.{}", &ID[..62]);
    let long = format!("pkg.{ID}00");
    let upper = format!("pkg.{}", ID.to_uppercase());
    let nonhex = format!("pkg.{}g", &ID[..63]);
    let bare = format!("{ID}");
    for (target, perm) in [
        ("TOOLBOX.ELF", "r"),
        ("TOOLBOX.ELF", "rx"),
        ("TOOLBOX.ELF", "xd"),
        ("toolbox.elf", "x"),
        ("TOOLBOX", "x"),
        ("TOOLBOX.BIN", "x"),
        ("TOOLBOXES.ELF", "x"),
        ("a/b.ELF", "x"),
        ("", "x"),
        (short.as_str(), "x"),
        (long.as_str(), "x"),
        (upper.as_str(), "x"),
        (nonhex.as_str(), "x"),
        (bare.as_str(), "x"),
    ] {
        assert_eq!(parsed(target, perm), Err(ParseError::BadValue), "{target:?} {perm:?}");
    }
    let pkg = format!("pkg.{ID}");
    for perm in ["r", "rw", "xt", "xd"] {
        assert_eq!(parsed(&pkg, perm), Err(ParseError::BadValue), "package {perm:?}");
    }
}

/// **The id is the 32 bytes the hex spells**, in order.
#[test]
fn a_package_id_is_read_in_order() {
    let Some(launch_name::Target::Package(id)) = launch_name::parse(format!("pkg.{ID}").as_bytes()) else {
        panic!("a package id did not parse");
    };
    assert_eq!(id[0], 0x00);
    assert_eq!(id[1], 0x11);
    assert_eq!(id[15], 0xff);
    assert_eq!(id[16], 0x00);
    assert_eq!(id[31], 0xff);
    assert_eq!(launch_name::parse(b"TOOLBOX.ELF"), Some(launch_name::Target::Image(b"TOOLBOX.ELF")));
}

/// **The built-in topology's launch grants are all well formed**: what the
/// parser would refuse in a signed file, the built-in rows do not hold.
#[test]
fn the_built_in_launch_grants_parse() {
    let topo = default_minimal();
    let mut seen = 0;
    for r in topo.tasks() {
        for c in topo.caps_of(r).iter().filter(|c| c.kind == CapKind::Node && !c.target.as_bytes().starts_with(b"/")) {
            seen += 1;
            assert_eq!(c.perms, CapPerms::EXEC, "{} grants {}", r.name.as_str(), c.target.as_str());
            assert!(launch_name::parse(c.target.as_bytes()).is_some(), "{}", c.target.as_str());
        }
    }
    assert!(seen > 0, "the built-in topology holds no launch grant");
}
