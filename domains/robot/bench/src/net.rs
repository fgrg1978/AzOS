// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Network subsystem microbenchmarks.
//!
//! Today: ARP cache lookup + insert.  Skips IP send (allocates ethernet
//! frame + writes virtio descriptor, not pure CPU) and TCP loopback
//! (needs a server task already listening — depends on workload).

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_net::{arp, ip, ethernet};

// RFC 5737 TEST-NET-1, which exists precisely so documentation and tests can
// name an address that is guaranteed not to be anybody's. `bench_arp_lookup_miss`
// below already used it and said why; the other two used `10.0.2.x`, which under
// SLIRP is the LIVE subnet — `10.0.2.2` is the gateway and the brain server.
const TEST_IP: [u8; 4] = [192, 0, 2, 99];
const TEST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

// ── These benchmarks own their cache, 2026-09-08 ──────────────────────────
//
// They used to call `arp::insert` and `arp::lookup`, which operate on the
// machine's LIVE table: `bench_arp_insert` performed 100 iterations x 5
// repeats of `insert([10, 0, 2, i], ...)` into a 16-entry LRU cache on every
// boot. That wiped every real entry many times over and, at `i == 2`, gave the
// SLIRP gateway a fabricated MAC — while `net-poll` was running on another
// hart.
//
// It surfaced three layers away and read as a transport bug: ring 3's
// `brain_client` connected, its first data segment hit an `arp::lookup` miss,
// `ip::send` returned -1, and `tcp::send_data` turns that into a fatal error
// rather than the "retry later" 0 it uses for its other transients — so a
// healthy `Established` connection was torn down. (That second half is a
// separate defect and is NOT fixed here.)
//
// `arp::ArpCache` is public for this: same structure, same code, on the
// bench's own stack. A benchmark must not mutate the machine it measures.

/// `ArpCache::get` hit path — IP pre-inserted.  Measures the table scan +
/// hit return.
pub fn bench_arp_lookup_hit(iters: u64) -> BenchResult {
    let mut cache = arp::ArpCache::new();
    cache.insert(TEST_IP, TEST_MAC);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = cache.get(&TEST_IP);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `arp::lookup` miss path — IP NOT in cache.  Measures full scan +
/// negative return.
pub fn bench_arp_lookup_miss(iters: u64) -> BenchResult {
    // IP guaranteed-absent: TEST_NET (192.0.2/24) per RFC 5737.
    let absent: [u8; 4] = [192, 0, 2, 1];
    // On an OWN cache, like its siblings. `lookup` on the global only reads,
    // so this one was never the corrupting call — but measuring the live table
    // means measuring however many entries the machine happens to hold, which
    // is a number that moves between boots. An empty cache is a stated
    // precondition instead of an inherited one.
    let cache = arp::ArpCache::new();

    let start = read_cycles();
    for _ in 0..iters {
        let _ = cache.get(&absent);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `arp::insert` — table update + LRU bookkeeping.
pub fn bench_arp_insert(iters: u64) -> BenchResult {
    let mut cache = arp::ArpCache::new();
    let start = read_cycles();
    for i in 0..iters {
        // Vary IP so we exercise LRU evict over time. TEST-NET-1, and on the
        // bench's own cache: this loop is the one that used to overwrite the
        // live gateway entry.
        let ip: [u8; 4] = [192, 0, 2, ((i & 0xFF) as u8)];
        cache.insert(ip, TEST_MAC);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Internet checksum (RFC 1071) over a 20-byte IP header.  Per-packet TX
/// cost on the header; the sum-fold loop is the hot part.
pub fn bench_ip_checksum_20B(iters: u64) -> BenchResult {
    let data = [0x42u8; 20];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(ip::checksum(&data));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Internet checksum over a full 1500-byte MTU payload — worst-case
/// per-packet checksum cost.  Scales linearly with payload length.
pub fn bench_ip_checksum_1500B(iters: u64) -> BenchResult {
    let data = [0x42u8; ip::ETH_MTU];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(ip::checksum(&data));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `ip::build_header` — fill the 20-byte IPv4 header incl. checksum.  The
/// per-packet header-assembly cost (one checksum + scalar writes).
pub fn bench_ip_build_header(iters: u64) -> BenchResult {
    let mut buf = [0u8; 20];
    let src = [10, 0, 2, 15];
    let dst = [10, 0, 2, 2];

    let start = read_cycles();
    for _ in 0..iters {
        ip::build_header(&mut buf, ip::IP_PROTO_UDP, &src, &dst, 64);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `ip::pseudo_checksum` — TCP/UDP pseudo-header partial sum.  Fixed
/// constant-cost accumulation; computed once per L4 segment.
pub fn bench_ip_pseudo_checksum(iters: u64) -> BenchResult {
    let src = [10, 0, 2, 15];
    let dst = [10, 0, 2, 2];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(
            ip::pseudo_checksum(&src, &dst, ip::IP_PROTO_TCP, 64),
        );
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `ethernet::build` — 14-byte header + 64-byte payload memcpy.  The
/// per-frame framing cost at L2.
pub fn bench_ethernet_build_64B(iters: u64) -> BenchResult {
    let payload = [0x42u8; 64];
    let mut out = [0u8; ethernet::EthHdr::SIZE + 64];
    let dst = [0xAAu8; 6];
    let src = [0xBBu8; 6];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = ethernet::build(&mut out, &dst, &src, ethernet::ETH_TYPE_IP, &payload);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `ethernet::parse` — header cast + bounds check on a 78-byte frame.  The
/// per-frame RX demux fast path.
pub fn bench_ethernet_parse(iters: u64) -> BenchResult {
    let payload = [0x42u8; 64];
    let mut frame = [0u8; ethernet::EthHdr::SIZE + 64];
    let _ = ethernet::build(&mut frame, &[0xAAu8; 6], &[0xBBu8; 6],
                            ethernet::ETH_TYPE_IP, &payload);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(ethernet::parse(&frame));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("net.arp_lookup_hit",   &best_of(|| bench_arp_lookup_hit(iters)));   n += 1;
    report("net.arp_lookup_miss",  &best_of(|| bench_arp_lookup_miss(iters)));  n += 1;
    report("net.arp_insert",       &best_of(|| bench_arp_insert(iters)));       n += 1;
    report("net.ip_checksum_20B",  &best_of(|| bench_ip_checksum_20B(iters)));  n += 1;
    report("net.ip_checksum_1500B", &best_of(|| bench_ip_checksum_1500B(iters))); n += 1;
    report("net.ip_build_header",  &best_of(|| bench_ip_build_header(iters)));  n += 1;
    report("net.ip_pseudo_checksum", &best_of(|| bench_ip_pseudo_checksum(iters))); n += 1;
    report("net.ethernet_build_64B", &best_of(|| bench_ethernet_build_64B(iters))); n += 1;
    report("net.ethernet_parse",   &best_of(|| bench_ethernet_parse(iters)));   n += 1;
    n
}
