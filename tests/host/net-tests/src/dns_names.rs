// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Whose answer is it (`crates/net/stack/src/dns.rs`, `parse_answer`).
//!
//! A response is trusted for the name that was asked, and for the names it is
//! an alias of, and for nothing else: the owner of an address record must be
//! the question's name (case-insensitively) or the target of a CNAME chain of
//! at most `DNS_MAX_CNAME_HOPS` links that starts at it. These tests build the
//! responses by hand, with every name spelled out unless a test is about
//! compression.

use crate::dns;

const ID: u16 = 0x4242;
const OK: u16 = 0x8180;
const ADDR: [u8; 4] = [93, 184, 216, 34];
const EVIL: [u8; 4] = [6, 6, 6, 6];

/// `a.b.c` as labels ending in the root.
fn name(dotted: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in dotted.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

/// One record: `owner` (wire form), type, class IN, TTL 60, rdata.
fn rec(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = owner.to_vec();
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&60u32.to_be_bytes());
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

fn a(owner: &str, ip: [u8; 4]) -> Vec<u8> {
    rec(&name(owner), 1, &ip)
}

fn cname(owner: &str, target: &str) -> Vec<u8> {
    rec(&name(owner), 5, &name(target))
}

/// A response to the question `qname` of type `qtype` carrying `records`.
fn response(qname: &str, qtype: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&ID.to_be_bytes());
    d.extend_from_slice(&OK.to_be_bytes());
    d.extend_from_slice(&[0, 1]);
    d.extend_from_slice(&(records.len() as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(&name(qname));
    d.extend_from_slice(&qtype.to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes());
    for r in records {
        d.extend_from_slice(r);
    }
    d
}

fn parse(m: &[u8]) -> Option<[u8; 4]> {
    dns::parse_response(m, ID)
}

/// **Canary.** Drop the owner comparison in `scan_answers`: the "evil" lines
/// fail.
#[test]
fn an_address_is_taken_only_from_a_record_owned_by_the_name_asked() {
    assert_eq!(parse(&response("host.example", 1, &[a("host.example", ADDR)])), Some(ADDR), "control");
    // The server answers another name: a forged or confused answer.
    assert_eq!(parse(&response("host.example", 1, &[a("evil.example", EVIL)])), None, "other owner");
    assert_eq!(parse(&response("host.example", 1, &[a("sub.host.example", EVIL)])), None, "a subdomain");
    assert_eq!(parse(&response("host.example", 1, &[a("example", EVIL)])), None, "the parent");
    // A record for another name does not hide the right one, and is not taken.
    let both = [a("evil.example", EVIL), a("host.example", ADDR)];
    assert_eq!(parse(&response("host.example", 1, &both)), Some(ADDR), "evil first");
    let both = [a("host.example", ADDR), a("evil.example", EVIL)];
    assert_eq!(parse(&response("host.example", 1, &both)), Some(ADDR), "evil last");
}

#[test]
fn names_compare_without_regard_to_ascii_case() {
    assert_eq!(parse(&response("Host.Example", 1, &[a("hOST.eXAMPLE", ADDR)])), Some(ADDR));
    // Only ASCII letters fold: a label of other octets is compared as it is.
    assert_eq!(parse(&response("h\u{e9}.example", 1, &[a("H\u{c9}.example", EVIL)])), None);
}

#[test]
fn a_compressed_owner_is_compared_by_the_name_it_points_to() {
    // The owner is a label followed by a pointer to the question's second
    // label: `host` + `.example` is the question's name.
    let q = name("host.example");
    let mut owner = vec![4, b'h', b'o', b's', b't'];
    owner.extend_from_slice(&[0xC0, 12 + 5]); // `example` in the question
    assert_eq!(q[5], 7);
    let m = response("host.example", 1, &[rec(&owner, 1, &ADDR)]);
    assert_eq!(parse(&m), Some(ADDR), "same name, written in two parts");
    // The same shape naming another host is another name.
    let mut other = vec![4, b'e', b'v', b'i', b'l'];
    other.extend_from_slice(&[0xC0, 12 + 5]);
    let m = response("host.example", 1, &[rec(&other, 1, &EVIL)]);
    assert_eq!(parse(&m), None);
}

#[test]
fn a_cname_leads_to_the_name_that_holds_the_address() {
    let m = response("www.example", 1, &[cname("www.example", "edge.cdn.test"), a("edge.cdn.test", ADDR)]);
    assert_eq!(parse(&m), Some(ADDR), "alias then address");
    // The records of a chain need not come in order.
    let m = response("www.example", 1, &[a("edge.cdn.test", ADDR), cname("www.example", "edge.cdn.test")]);
    assert_eq!(parse(&m), Some(ADDR), "address then alias");
    // An address for the alias's owner does not stand in for its target.
    let m = response("www.example", 1, &[cname("www.example", "edge.cdn.test"), a("www.example", EVIL)]);
    assert_eq!(parse(&m), Some(EVIL), "an address owned by the question's name is still an address for it");
    // An address for some third name is not on the chain.
    let m = response("www.example", 1, &[cname("www.example", "edge.cdn.test"), a("other.cdn.test", EVIL)]);
    assert_eq!(parse(&m), None, "off the chain");
    // An alias with no address at its end is not an answer.
    let m = response("www.example", 1, &[cname("www.example", "edge.cdn.test")]);
    assert_eq!(parse(&m), None, "dangling alias");
    // An alias for another name is not followed.
    let m = response("www.example", 1, &[cname("evil.example", "edge.cdn.test"), a("edge.cdn.test", EVIL)]);
    assert_eq!(parse(&m), None, "the alias is not the question's");
}

/// The chain `n0 -> n1 -> ... -> n<links>` and an address at its end.
fn chain(links: usize) -> Vec<u8> {
    let n = |i: usize| format!("n{i}.chain.test");
    let mut recs: Vec<Vec<u8>> = (0..links).map(|i| cname(&n(i), &n(i + 1))).collect();
    recs.push(a(&n(links), ADDR));
    response(&n(0), 1, &recs)
}

/// **Canary.** Raise `DNS_MAX_CNAME_HOPS` by one: the nine-link line fails.
#[test]
fn a_chain_is_followed_for_eight_links_and_no_further() {
    assert_eq!(dns::DNS_MAX_CNAME_HOPS, 8);
    for links in 0..=8 {
        assert_eq!(parse(&chain(links)), Some(ADDR), "{links} links");
    }
    assert_eq!(parse(&chain(9)), None, "9 links");
    assert_eq!(parse(&chain(30)), None, "30 links");
}

#[test]
fn a_chain_in_reverse_order_still_ends_at_the_hop_limit() {
    let n = |i: usize| format!("n{i}.chain.test");
    for links in [8usize, 9] {
        let mut recs = vec![a(&n(links), ADDR)];
        recs.extend((0..links).rev().map(|i| cname(&n(i), &n(i + 1))));
        let want = (links <= 8).then_some(ADDR);
        assert_eq!(parse(&response(&n(0), 1, &recs)), want, "{links} links, last first");
    }
}

#[test]
fn a_loop_of_aliases_is_refused() {
    let m = response("a.loop.test", 1, &[cname("a.loop.test", "b.loop.test"), cname("b.loop.test", "a.loop.test")]);
    assert_eq!(parse(&m), None, "two names");
    let m = response("a.loop.test", 1, &[cname("a.loop.test", "a.loop.test")]);
    assert_eq!(parse(&m), None, "a name that is its own alias");
    // The loop does not hide an address that is genuinely on the chain.
    let m = response(
        "a.loop.test",
        1,
        &[cname("a.loop.test", "b.loop.test"), cname("b.loop.test", "a.loop.test"), a("a.loop.test", ADDR)],
    );
    assert_eq!(parse(&m), Some(ADDR), "an address for a name on the loop");
}

#[test]
fn an_alias_target_must_lie_inside_the_record() {
    // RDLENGTH covers three octets of the target name: it runs out of its
    // rdata.
    let mut bad = name("www.example");
    bad.extend_from_slice(&5u16.to_be_bytes());
    bad.extend_from_slice(&1u16.to_be_bytes());
    bad.extend_from_slice(&60u32.to_be_bytes());
    bad.extend_from_slice(&3u16.to_be_bytes());
    bad.extend_from_slice(&name("edge.cdn.test")[..3]);
    let m = response("www.example", 1, &[bad, a("edge.cdn.test", EVIL)]);
    assert_eq!(parse(&m), None, "target cut by RDLENGTH");
}

#[test]
fn an_aaaa_query_follows_aliases_the_same_way() {
    let g6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let m = response(
        "www.example",
        28,
        &[cname("www.example", "edge.cdn.test"), rec(&name("edge.cdn.test"), 28, &g6)],
    );
    assert_eq!(dns::parse_response_aaaa(&m, ID), Some(g6));
    let m = response("www.example", 28, &[rec(&name("evil.example"), 28, &g6)]);
    assert_eq!(dns::parse_response_aaaa(&m, ID), None, "other owner");
}

/// Pointers that lead back into labels already read make a cycle that a
/// "pointers go backwards" rule alone does not break; the 255-octet bound on
/// a name does.
#[test]
fn a_cycle_through_labels_and_pointers_is_refused() {
    // Offset 12: question `x`, then at 12+3+4 = 19 the records start.
    // Owner at 19: label `a`, then a pointer to 19 itself would be a
    // self-pointer; use a label at 19, a label at 21, and a pointer at 23
    // back to 19: 19 'a' 21 'b' 23 ptr->19.
    let mut m = Vec::new();
    m.extend_from_slice(&ID.to_be_bytes());
    m.extend_from_slice(&OK.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    m.extend_from_slice(&[1, b'x', 0, 0, 1, 0, 1]); // question x, A, IN: 12..19
    m.extend_from_slice(&[1, b'a', 1, b'b', 0xC0, 19]); // 19..25
    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    m.extend_from_slice(&EVIL);
    assert_eq!(parse(&m), None);
}

#[test]
fn nothing_panics_on_any_prefix_of_a_chained_answer() {
    let full = chain(3);
    for n in 0..full.len() {
        assert_eq!(parse(&full[..n]), None, "{n}-octet prefix");
    }
}
