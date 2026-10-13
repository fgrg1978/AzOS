// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-level wire conformance for `azos_tftp` against RFC 1350 §5.
//!
//! The builder and parser tests in `lib.rs` already pin an RRQ and the ACK
//! layout. This module derives each packet field by field from the RFC 1350
//! §5 figures, pins the packet LENGTH as well as its contents, and feeds the
//! parser the server-side shapes a real server sends — including the ones
//! this client never negotiates (an RFC 2347 OACK) and the ones that are
//! malformed.
//!
//! RFC 1350 also has the client SEND an ERROR: to the source of a packet from
//! a wrong transfer ID (§4), and to the server when the client ends a transfer
//! early (§7). The encoder is pinned byte for byte below, and the fetch loop
//! is driven against a scripted wire to pin which ERROR goes where, and when
//! none may be sent at all.

use azos_tftp::client::{tftp_fetch, TftpFetchError, UdpTransport};
use azos_tftp::{
    build_ack, build_error, build_rrq, parse_packet, RxOutcome, TftpEncodeError,
    TFTP_ACK_BYTES, TFTP_ERR_DISK_FULL, TFTP_ERR_NOT_DEFINED, TFTP_ERR_UNKNOWN_TID,
    TFTP_RRQ_MAX_BYTES,
};
use std::cell::RefCell;
use std::collections::VecDeque;

/// Filler for output buffers, so an octet written past the packet shows up.
const UNTOUCHED: u8 = 0xAA;

/// RRQ for `fw/robot-v2.img` in octet mode (RFC 1350 §5, Figure 5-1).
///
/// ```text
/// off 0   Opcode    00 01   RRQ
/// off 2   Filename  66 77 2F 72 6F 62 6F 74 2D 76 32 2E 69 6D 67
///                   f  w  /  r  o  b  o  t  -  v  2  .  i  m  g   (15 octets, netascii)
/// off 17  0         00      terminates Filename
/// off 18  Mode      6F 63 74 65 74
///                   o  c  t  e  t
/// off 23  0         00      terminates Mode, and the packet
/// length 24
/// ```
const RRQ_FW_IMG: [u8; 24] = [
    0x00, 0x01,
    0x66, 0x77, 0x2F, 0x72, 0x6F, 0x62, 0x6F, 0x74, 0x2D, 0x76, 0x32, 0x2E, 0x69, 0x6D, 0x67,
    0x00,
    0x6F, 0x63, 0x74, 0x65, 0x74,
    0x00,
];

/// **Encode: RRQ.** Byte-exact, and nothing is written past octet 24.
#[test]
fn an_rrq_is_byte_exact_and_ends_at_the_mode_terminator() {
    let mut out = [UNTOUCHED; TFTP_RRQ_MAX_BYTES];
    let n = build_rrq("fw/robot-v2.img", &mut out).expect("a legal filename");
    assert_eq!(n, RRQ_FW_IMG.len(), "the packet ends at the Mode terminator");
    assert_eq!(&out[..n], &RRQ_FW_IMG[..]);
    assert!(
        out[n..].iter().all(|&b| b == UNTOUCHED),
        "no octet may be written past the packet",
    );
}

/// ACK for block 258 (RFC 1350 §5, Figure 5-3).
///
/// ```text
/// off 0  Opcode   00 04   ACK
/// off 2  Block #  01 02   258, network byte order: high octet first
/// length 4
/// ```
///
/// 258 rather than a symmetric value: `0x0102` read little-endian is 513,
/// so a byte-order slip cannot pass.
const ACK_258: [u8; 4] = [0x00, 0x04, 0x01, 0x02];

/// **Encode: ACK.** Byte-exact, four octets and no more.
#[test]
fn an_ack_is_byte_exact_in_network_byte_order() {
    let mut out = [UNTOUCHED; TFTP_ACK_BYTES + 4];
    build_ack(258, &mut out);
    assert_eq!(&out[..TFTP_ACK_BYTES], &ACK_258[..]);
    assert_eq!(&out[TFTP_ACK_BYTES..], &[UNTOUCHED; 4], "an ACK is exactly 4 octets");
}

/// **Decode: DATA** (RFC 1350 §5, Figure 5-2), a full block and the short one
/// that ends the transfer (§6: a data field under 512 octets is the last).
///
/// ```text
/// full:  00 03 | 01 02 | 512 x 5A        opcode DATA, block 258, 512 octets
/// last:  00 03 | 01 03 | 74 61 69 6C     opcode DATA, block 259, "tail"
/// ```
#[test]
fn hand_built_data_packets_decode_to_block_payload_and_eof() {
    let mut full = vec![0x00, 0x03, 0x01, 0x02];
    full.extend_from_slice(&[0x5A; 512]);
    match parse_packet(&full) {
        RxOutcome::Data { block, payload, is_last } => {
            assert_eq!(block, 258, "block # is big-endian at offset 2");
            assert_eq!(payload, &[0x5A; 512][..], "data starts at offset 4");
            assert!(!is_last, "512 octets is not the last block");
        }
        other => panic!("expected Data, got {other:?}"),
    }

    let last = [0x00, 0x03, 0x01, 0x03, 0x74, 0x61, 0x69, 0x6C];
    match parse_packet(&last) {
        RxOutcome::Data { block, payload, is_last } => {
            assert_eq!(block, 259);
            assert_eq!(payload, b"tail");
            assert!(is_last, "fewer than 512 octets ends the transfer");
        }
        other => panic!("expected Data, got {other:?}"),
    }
}

/// **Decode: ERROR** (RFC 1350 §5, Figure 5-4).
///
/// ```text
/// 00 05 | 00 01 | 46 69 6C 65 20 6E 6F 74 20 66 6F 75 6E 64 | 00
/// ERROR | code 1| "File not found"                           | terminator
///
/// 00 05 | 00 05 | 55 6E 6B 6E 6F 77 6E 20 74 72 61 6E 73 66 65 72 20 49 44 | 00
/// ERROR | code 5| "Unknown transfer ID"                                     | terminator
/// ```
#[test]
fn hand_built_error_packets_decode_to_their_code() {
    let not_found = [
        0x00, 0x05, 0x00, 0x01,
        0x46, 0x69, 0x6C, 0x65, 0x20, 0x6E, 0x6F, 0x74, 0x20, 0x66, 0x6F, 0x75, 0x6E, 0x64,
        0x00,
    ];
    assert_eq!(parse_packet(&not_found), RxOutcome::Error(1));

    assert_eq!(parse_packet(&ERROR_UNKNOWN_TID), RxOutcome::Error(5));
}

/// ERROR code 5, "Unknown transfer ID" (RFC 1350 §5, Figure 5-4).
///
/// ```text
/// off 0   Opcode   00 05   ERROR
/// off 2   ErrCode  00 05   Unknown transfer ID
/// off 4   ErrMsg   55 6E 6B 6E 6F 77 6E 20 74 72 61 6E 73 66 65 72 20 49 44
///                  U  n  k  n  o  w  n     t  r  a  n  s  f  e  r     I  D   (19 octets)
/// off 23  0        00      terminates ErrMsg, and the packet
/// length 24
/// ```
const ERROR_UNKNOWN_TID: [u8; 24] = [
    0x00, 0x05, 0x00, 0x05,
    0x55, 0x6E, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x66,
    0x65, 0x72, 0x20, 0x49, 0x44,
    0x00,
];

/// ERROR code 3, "Disk full or allocation exceeded".
///
/// ```text
/// off 0   Opcode   00 05
/// off 2   ErrCode  00 03   Disk full or allocation exceeded
/// off 4   ErrMsg   44 69 73 6B 20 66 75 6C 6C 20 6F 72 20
///                  D  i  s  k     f  u  l  l     o  r
///                  61 6C 6C 6F 63 61 74 69 6F 6E 20 65 78 63 65 65 64 65 64
///                  a  l  l  o  c  a  t  i  o  n     e  x  c  e  e  d  e  d   (32 octets)
/// off 36  0        00
/// length 37
/// ```
const ERROR_DISK_FULL: [u8; 37] = [
    0x00, 0x05, 0x00, 0x03,
    0x44, 0x69, 0x73, 0x6B, 0x20, 0x66, 0x75, 0x6C, 0x6C, 0x20, 0x6F, 0x72, 0x20,
    0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x65, 0x78, 0x63, 0x65,
    0x65, 0x64, 0x65, 0x64,
    0x00,
];

/// ERROR code 0 (not defined, see message), "Block out of order".
///
/// ```text
/// off 0   Opcode   00 05
/// off 2   ErrCode  00 00
/// off 4   ErrMsg   42 6C 6F 63 6B 20 6F 75 74 20 6F 66 20 6F 72 64 65 72
///                  B  l  o  c  k     o  u  t     o  f     o  r  d  e  r   (18 octets)
/// off 22  0        00
/// length 23
/// ```
const ERROR_OUT_OF_ORDER: [u8; 23] = [
    0x00, 0x05, 0x00, 0x00,
    0x42, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6F, 0x75, 0x74, 0x20, 0x6F, 0x66, 0x20, 0x6F, 0x72,
    0x64, 0x65, 0x72,
    0x00,
];

/// ERROR code 0, "Timed out".
///
/// ```text
/// off 0   Opcode   00 05
/// off 2   ErrCode  00 00
/// off 4   ErrMsg   54 69 6D 65 64 20 6F 75 74
///                  T  i  m  e  d     o  u  t   (9 octets)
/// off 13  0        00
/// length 14
/// ```
const ERROR_TIMED_OUT: [u8; 14] = [
    0x00, 0x05, 0x00, 0x00,
    0x54, 0x69, 0x6D, 0x65, 0x64, 0x20, 0x6F, 0x75, 0x74,
    0x00,
];

/// **Encode: ERROR.** Byte-exact, terminator included, nothing written past
/// it. The empty message is the shortest ERROR: `00 05 | 00 00 | 00`.
#[test]
fn an_error_is_byte_exact_and_ends_at_its_terminator() {
    for (code, msg, expected) in [
        (TFTP_ERR_UNKNOWN_TID, "Unknown transfer ID", &ERROR_UNKNOWN_TID[..]),
        (TFTP_ERR_DISK_FULL, "Disk full or allocation exceeded", &ERROR_DISK_FULL[..]),
        (TFTP_ERR_NOT_DEFINED, "", &[0x00, 0x05, 0x00, 0x00, 0x00][..]),
    ] {
        let mut out = [UNTOUCHED; 64];
        let n = build_error(code, msg, &mut out).expect("fits in 64 octets");
        assert_eq!(n, expected.len(), "code {code}: length is 4 + message + 1");
        assert_eq!(&out[..n], expected, "code {code}");
        assert!(
            out[n..].iter().all(|&b| b == UNTOUCHED),
            "code {code}: no octet may be written past the terminator",
        );
    }
}

/// **Encode: a message that does not fit is refused, not truncated.** The
/// 24-octet "Unknown transfer ID" packet fits a 24-octet buffer exactly and
/// is refused by a 23-octet one, which is the terminator's octet. A message
/// with a NUL inside is refused too: the receiver would stop reading there.
/// On refusal the buffer is left as it was.
#[test]
fn an_error_message_that_does_not_fit_is_refused_not_truncated() {
    let mut exact = [UNTOUCHED; 24];
    assert_eq!(build_error(TFTP_ERR_UNKNOWN_TID, "Unknown transfer ID", &mut exact), Ok(24));
    assert_eq!(exact, ERROR_UNKNOWN_TID);

    for len in [23usize, 22, 5, 4, 0] {
        let mut short = vec![UNTOUCHED; len];
        assert_eq!(
            build_error(TFTP_ERR_UNKNOWN_TID, "Unknown transfer ID", &mut short),
            Err(TftpEncodeError::BufferTooSmall),
            "{len} octets cannot hold 24",
        );
        assert!(short.iter().all(|&b| b == UNTOUCHED), "{len} octets: nothing written on refusal");
    }

    let mut none = [UNTOUCHED; 4];
    assert_eq!(
        build_error(TFTP_ERR_NOT_DEFINED, "", &mut none),
        Err(TftpEncodeError::BufferTooSmall),
        "even an empty message needs its terminator: 5 octets",
    );

    let mut out = [UNTOUCHED; 64];
    assert_eq!(
        build_error(TFTP_ERR_NOT_DEFINED, "Unknown\0ID", &mut out),
        Err(TftpEncodeError::MessageHasNul),
    );
    assert!(out.iter().all(|&b| b == UNTOUCHED), "nothing written on refusal");
}

// ── The fetch loop against a scripted wire ─────────────────────────────────

/// One UDP datagram: the far endpoint (source on receive, destination on
/// send) and the TFTP packet.
#[derive(Clone, Debug, PartialEq)]
struct Datagram {
    ip: [u8; 4],
    port: u16,
    bytes: Vec<u8>,
}

/// The far end: hands the scripted datagrams to `recvfrom` one per call, in
/// order, and records every `sendto`. Every send succeeds, so no ARP retry
/// loop runs and every send is visible exactly once.
struct FakeWire {
    inbound: RefCell<VecDeque<Datagram>>,
    sent: RefCell<Vec<Datagram>>,
}

impl FakeWire {
    fn new(script: Vec<Datagram>) -> Self {
        FakeWire { inbound: RefCell::new(script.into()), sent: RefCell::new(Vec::new()) }
    }

    /// Every sent datagram carrying the ERROR opcode.
    fn errors(&self) -> Vec<Datagram> {
        self.sent.borrow().iter().filter(|d| d.bytes.starts_with(&[0x00, 0x05])).cloned().collect()
    }
}

impl UdpTransport for FakeWire {
    fn bind(&self, _port: u16) -> i32 { 0 }
    fn unbind(&self, _sock: usize) {}
    fn sendto(&self, _sock: i32, dst_ip: &[u8; 4], dst_port: u16, data: &[u8]) -> i32 {
        self.sent.borrow_mut().push(Datagram { ip: *dst_ip, port: dst_port, bytes: data.to_vec() });
        0
    }
    fn recvfrom(&self, _sock: i32, buf: &mut [u8], src_ip: &mut [u8; 4], src_port: &mut u16) -> i32 {
        match self.inbound.borrow_mut().pop_front() {
            Some(d) => {
                buf[..d.bytes.len()].copy_from_slice(&d.bytes);
                *src_ip = d.ip;
                *src_port = d.port;
                d.bytes.len() as i32
            }
            None => 0,
        }
    }
    fn poll(&self) {}
}

const SERVER_IP: [u8; 4] = [10, 0, 0, 69];
const STRANGER_IP: [u8; 4] = [10, 0, 0, 66];
const SERVER_TID: u16 = 40069;
const ROGUE_TID: u16 = 40070;

/// DATA (Figure 5-2): `00 03 | block | len x fill`.
fn data(block: u16, fill: u8, len: usize) -> Vec<u8> {
    let mut d = vec![0x00, 0x03];
    d.extend_from_slice(&block.to_be_bytes());
    d.extend(std::iter::repeat(fill).take(len));
    d
}

fn from(ip: [u8; 4], port: u16, bytes: Vec<u8>) -> Datagram {
    Datagram { ip, port, bytes }
}

/// **§4: a packet from a wrong TID.** After block 1 locks the server's TID
/// to 40069, a DATA from the same host's port 40070 draws exactly one ERROR
/// code 5, addressed to 10.0.0.69:40070 (the stray's source), not to the
/// server's TID. The transfer is not disturbed: the file lands whole, and
/// every ACK still goes to 40069.
#[test]
fn a_wrong_tid_draws_one_error_5_to_its_source_and_the_transfer_completes() {
    let wire = FakeWire::new(vec![
        from(SERVER_IP, SERVER_TID, data(1, b'A', 512)),
        from(SERVER_IP, ROGUE_TID, data(2, b'X', 512)),
        from(SERVER_IP, SERVER_TID, data(2, b'B', 512)),
        from(SERVER_IP, SERVER_TID, data(3, b'C', 10)),
    ]);
    let mut dst = [0u8; 2048];
    assert_eq!(tftp_fetch(&wire, SERVER_IP, "boot.bin", &mut dst), Ok(512 + 512 + 10));
    assert_eq!(&dst[512..1024], &[b'B'; 512][..], "block 2 is the server's, not the stray's");
    assert!(!dst.contains(&b'X'));

    assert_eq!(
        wire.errors(),
        vec![from(SERVER_IP, ROGUE_TID, ERROR_UNKNOWN_TID.to_vec())],
        "exactly one ERROR 5, to the source of the stray",
    );
    let acks: Vec<(u16, Vec<u8>)> = wire.sent.borrow().iter()
        .filter(|d| d.bytes.starts_with(&[0x00, 0x04]))
        .map(|d| (d.port, d.bytes.clone()))
        .collect();
    assert_eq!(acks, vec![
        (SERVER_TID, vec![0x00, 0x04, 0x00, 0x01]),
        (SERVER_TID, vec![0x00, 0x04, 0x00, 0x02]),
        (SERVER_TID, vec![0x00, 0x04, 0x00, 0x03]),
    ]);
}

/// **§4, another host.** A packet from 10.0.0.66 is not from this transfer,
/// before the TID is locked as after. Its ERROR 5 goes to 10.0.0.66 at the
/// port it came from, which here equals the server's TID, so only the
/// address tells the two destinations apart.
#[test]
fn a_packet_from_another_host_draws_error_5_to_that_host() {
    let wire = FakeWire::new(vec![
        from(STRANGER_IP, SERVER_TID, data(1, b'X', 512)),
        from(SERVER_IP, SERVER_TID, data(1, b'A', 512)),
        from(STRANGER_IP, SERVER_TID, data(2, b'X', 512)),
        from(SERVER_IP, SERVER_TID, data(2, b'C', 10)),
    ]);
    let mut dst = [0u8; 2048];
    assert_eq!(tftp_fetch(&wire, SERVER_IP, "boot.bin", &mut dst), Ok(512 + 10));
    assert!(!dst.contains(&b'X'));
    assert_eq!(
        wire.errors(),
        vec![
            from(STRANGER_IP, SERVER_TID, ERROR_UNKNOWN_TID.to_vec()),
            from(STRANGER_IP, SERVER_TID, ERROR_UNKNOWN_TID.to_vec()),
        ],
        "one ERROR 5 per stray, both to the stranger",
    );
}

/// **§7: an overflow abort.** The destination holds 1024 octets. Two cases,
/// one per place the client can overflow: a third full block, and a short
/// final block. Each time the fetch reports `BufferOverflow` and sends
/// exactly one ERROR code 3 to the server's TID.
#[test]
fn an_overflow_abort_sends_error_3_to_the_server_tid() {
    for (dst_len, last_len) in [(1024usize, 512usize), (1024 + 50, 100)] {
        let wire = FakeWire::new(vec![
            from(SERVER_IP, SERVER_TID, data(1, b'A', 512)),
            from(SERVER_IP, SERVER_TID, data(2, b'B', 512)),
            from(SERVER_IP, SERVER_TID, data(3, b'C', last_len)),
        ]);
        let mut dst = vec![0u8; dst_len];
        assert_eq!(
            tftp_fetch(&wire, SERVER_IP, "big.bin", &mut dst),
            Err(TftpFetchError::BufferOverflow),
            "dst {dst_len}, last block {last_len}",
        );
        assert_eq!(
            wire.errors(),
            vec![from(SERVER_IP, SERVER_TID, ERROR_DISK_FULL.to_vec())],
            "dst {dst_len}, last block {last_len}: one ERROR 3, to the server's TID",
        );
    }
}

/// **§7: an out-of-order abort.** Block 3 after block 1 ends the transfer
/// with one ERROR code 0 and its message, to the server's TID.
#[test]
fn an_out_of_order_abort_sends_error_0_to_the_server_tid() {
    let wire = FakeWire::new(vec![
        from(SERVER_IP, SERVER_TID, data(1, b'A', 512)),
        from(SERVER_IP, SERVER_TID, data(3, b'C', 512)),
    ]);
    let mut dst = [0u8; 2048];
    assert_eq!(
        tftp_fetch(&wire, SERVER_IP, "boot.bin", &mut dst),
        Err(TftpFetchError::OutOfOrderBlock { expected: 2, received: 3 }),
    );
    assert_eq!(wire.errors(), vec![from(SERVER_IP, SERVER_TID, ERROR_OUT_OF_ORDER.to_vec())]);
}

/// **§7: giving up.** A server that goes silent after block 1 exhausts the
/// poll budget; the client ends the transfer with one ERROR code 0 to the
/// server's TID. A server that never answered has no TID and no transfer, so
/// nothing is sent but the RRQ, and in particular nothing to port 69.
#[test]
fn giving_up_on_a_locked_transfer_sends_error_0_and_on_no_reply_sends_nothing() {
    let wire = FakeWire::new(vec![from(SERVER_IP, SERVER_TID, data(1, b'A', 512))]);
    let mut dst = [0u8; 2048];
    assert_eq!(
        tftp_fetch(&wire, SERVER_IP, "boot.bin", &mut dst),
        Err(TftpFetchError::PollBudgetExhausted),
    );
    assert_eq!(wire.errors(), vec![from(SERVER_IP, SERVER_TID, ERROR_TIMED_OUT.to_vec())]);

    let silent = FakeWire::new(vec![]);
    assert_eq!(tftp_fetch(&silent, SERVER_IP, "boot.bin", &mut dst), Err(TftpFetchError::NoReply));
    let sent = silent.sent.borrow();
    assert_eq!(sent.len(), 1, "the RRQ and nothing else");
    assert!(sent[0].bytes.starts_with(&[0x00, 0x01]), "that one datagram is the RRQ");
}

/// **§7: an ERROR is never answered with an ERROR.** A stray ERROR from a
/// wrong TID draws no ERROR 5, and the server's own ERROR ends the fetch
/// without one. Otherwise two endpoints that each answer ERRORs loop.
#[test]
fn an_error_is_never_answered_with_an_error() {
    let wire = FakeWire::new(vec![
        from(SERVER_IP, SERVER_TID, data(1, b'A', 512)),
        from(SERVER_IP, ROGUE_TID, ERROR_UNKNOWN_TID.to_vec()),
        // An unterminated ERROR is still an ERROR: no answer either.
        from(SERVER_IP, ROGUE_TID, vec![0x00, 0x05, 0x00, 0x05, 0x55]),
        from(SERVER_IP, SERVER_TID, ERROR_DISK_FULL.to_vec()),
    ]);
    let mut dst = [0u8; 2048];
    assert_eq!(
        tftp_fetch(&wire, SERVER_IP, "boot.bin", &mut dst),
        Err(TftpFetchError::ServerError(3)),
    );
    assert_eq!(wire.errors(), vec![], "no ERROR in answer to any of them");
}

/// **Malformed: an ERROR whose ErrMsg is not terminated.**
///
/// RFC 1350 §5 closes the packet with a zero octet after ErrMsg. Without it
/// the packet is cut short somewhere inside the message — the length alone
/// cannot tell a truncated ERROR from a complete one.
///
/// ```text
/// 00 05 | 00 01 | 46 69 6C 65      "File" and no 00
/// ```
#[test]
fn an_error_without_its_terminating_zero_is_refused() {
    let unterminated = [0x00, 0x05, 0x00, 0x01, 0x46, 0x69, 0x6C, 0x65];
    assert_eq!(parse_packet(&unterminated), RxOutcome::Malformed);
}

/// **Malformed: truncated headers, an oversized block, and every shape a
/// server must not send to a reading client.**
#[test]
fn truncated_oversized_and_client_side_shapes_are_refused() {
    for n in 0..4 {
        assert_eq!(
            parse_packet(&[0x00, 0x03, 0x01, 0x02][..n]), RxOutcome::Malformed,
            "a {n}-octet DATA has no complete block number",
        );
    }
    for n in 0..5 {
        assert_eq!(
            parse_packet(&[0x00, 0x05, 0x00, 0x01, 0x00][..n]), RxOutcome::Malformed,
            "a {n}-octet ERROR is short of opcode, code and terminator",
        );
    }

    let mut oversized = vec![0x00, 0x03, 0x00, 0x01];
    oversized.extend_from_slice(&[0x00; 513]);
    assert_eq!(parse_packet(&oversized), RxOutcome::Malformed, "513 octets exceeds the block size");

    // RRQ, WRQ and ACK are what a client sends; none is a server's answer.
    for op in [0x01u8, 0x02, 0x04] {
        assert_eq!(parse_packet(&[0x00, op, 0x00, 0x01]), RxOutcome::Malformed, "opcode {op}");
    }

    // RFC 2347 OACK: opcode 6, then option/value strings.
    //   00 06 | 62 6C 6B 73 69 7A 65 00 | 31 34 36 38 00
    //   OACK  | "blksize" 0             | "1468" 0
    // This client requests no options, so an OACK answers nothing it asked.
    let oack = [
        0x00, 0x06, 0x62, 0x6C, 0x6B, 0x73, 0x69, 0x7A, 0x65, 0x00, 0x31, 0x34, 0x36, 0x38, 0x00,
    ];
    assert_eq!(parse_packet(&oack), RxOutcome::Malformed);
}
