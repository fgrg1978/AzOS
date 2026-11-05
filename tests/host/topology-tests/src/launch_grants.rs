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

/// **A package grant mints EXEC on the package's own resource.** The
/// resource carries `PACKAGE_RESOURCE`, so no image name collides with it; the
/// same id is the same resource however many rows name it; the table holds
/// `MAX_LAUNCH_PACKAGES` and refuses the next, whose grant is not minted.
///
/// **Canary.** Make `launch_grant_cap` intern a package id as an image name's
/// slot (drop `PACKAGE_RESOURCE`): the bit assertion goes red.
#[test]
fn a_package_grant_mints_on_the_packages_own_resource() {
    use crate::cap::targets;
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::launch_cap::{launch_resource_of, package_resource_of, MAX_LAUNCH_PACKAGES, PACKAGE_RESOURCE};
    use azos_abi::cap::CapKind;

    let tid = crate::cap_seed_bridge_tests::fresh_tid();
    let id_of = |n: u8| {
        let mut id = [0u8; 32];
        id[0] = 0xAC;
        id[1] = n;
        id
    };
    let target = |n: u8| format!("pkg.{}", id_of(n).iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(package_resource_of(&id_of(0)), None, "a package no row names has no resource");

    let mint = |n: u8| match seed_one_cap_outcome(tid, CapKind::Node, CapPerms::EXEC, &target(n)) {
        SeedOutcome::Minted(h) => Some(crate::cap::Cap::<targets::Launch>::from_raw(h)),
        SeedOutcome::Refused => None,
        o => panic!("{o:?}"),
    };
    let first = mint(0).expect("a package grant is minted");
    let r = crate::cap_store::get(tid, first, CapPerms::EXEC).expect("it resolves with EXEC");
    assert_ne!(r & PACKAGE_RESOURCE, 0, "a package resource is told from an image's");
    assert_eq!(package_resource_of(&id_of(0)), Some(r));
    assert_eq!(launch_resource_of(target(0).as_bytes()), None, "and it is no image name");

    let again = mint(0).expect("the same id again");
    assert_eq!(crate::cap_store::get(tid, again, CapPerms::EXEC), Ok(r), "one id, one resource");

    for n in 1..MAX_LAUNCH_PACKAGES as u8 {
        assert!(mint(n).is_some(), "package {n} fits the table");
    }
    assert!(mint(MAX_LAUNCH_PACKAGES as u8).is_none(), "past the table the grant is not minted");
    assert_eq!(package_resource_of(&id_of(MAX_LAUNCH_PACKAGES as u8)), None);
}
