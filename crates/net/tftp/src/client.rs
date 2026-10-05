// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-side TFTP fetch — wires the pure `azos_tftp` state
//! machine to the kernel's UDP socket layer.
//!
//! Intended for **boot-time use** (before the scheduler starts):
//! the function is busy-polling and synchronous. It picks an
//! ephemeral local UDP port, sends a Read Request to
//! `server_ip:69`, then drives the state machine through DATA /
//! ACK exchanges until the transfer completes or a bounded poll
//! budget is exhausted.
//!
//! # Phase 1 limitations
//!
//! - Blocking poll loop. Not safe to call after `sched::start()`
//!   from a non-driver task — the calling CPU stalls.
//! - No RFC 1350 §4 retransmit-on-timeout. If the server drops a
//!   packet the fetch fails fast.
//! - No congestion / windowing — just request / data / ack.
//! - Server's `tid` (the ephemeral port it picks for replies) is
//!   captured on the first DATA and used for all subsequent ACKs.

use core::sync::atomic::{AtomicU16, Ordering};

use azos_tftp::{
    build_ack, build_error, build_rrq, parse_packet, ClientAction, RxOutcome, TftpClient,
    TftpEncodeError, TFTP_ACK_BYTES, TFTP_BLOCK_SIZE, TFTP_DATA_HEADER_BYTES,
    TFTP_ERR_DISK_FULL, TFTP_ERR_NOT_DEFINED, TFTP_ERR_UNKNOWN_TID, TFTP_OPCODE_ERROR,
    TFTP_PORT, TFTP_RRQ_MAX_BYTES,
};

/// The five UDP operations the fetch loop needs, and the reason this crate has
/// no network dependency.
///
/// `tftp_client.rs` used to live in `crates/net/net`, which made a core crate
/// depend on a scaffolding one: TFTP is boot-time netboot convenience, not
/// part of the transport. Moving the file was not enough on its own -- making
/// `crates/net/tftp` depend on `crates/net/net` instead just inverted the edge and
/// dragged the whole kernel stack into every host crate that wanted the
/// protocol constants, breaking two suites.
///
/// So the dependency is passed in. `crates/net/tftp` is dependency-free again, the
/// kernel supplies the real sockets, and `tests/host/net-tests` supplies its own
/// shims -- which is what lets that suite exercise this loop against a fake
/// wire at all. Same shape as `waitqueue` and `pi_mutex`, which take their
/// scheduler operations as callbacks for the same reason.
pub trait UdpTransport {
    fn bind(&self, port: u16) -> i32;
    fn unbind(&self, sock: usize);
    fn sendto(&self, sock: i32, dst_ip: &[u8; 4], dst_port: u16, data: &[u8]) -> i32;
    fn recvfrom(&self, sock: i32, buf: &mut [u8],
                src_ip: &mut [u8; 4], src_port: &mut u16) -> i32;
    /// Pump the stack so a reply can arrive. Called between retries.
    fn poll(&self);
}

// ──────────────────────────────────────────────────────────────────────────
// Tunables — every "magic number" lives here.
// ──────────────────────────────────────────────────────────────────────────

/// Receive buffer for one UDP datagram (header + payload). One
/// TFTP DATA carries at most `TFTP_DATA_HEADER_BYTES +
/// TFTP_BLOCK_SIZE` payload bytes.
const TFTP_RX_BUF_BYTES: usize = TFTP_DATA_HEADER_BYTES + TFTP_BLOCK_SIZE;

/// Transmit buffer for one ERROR: opcode, code, message, terminator. The
/// longest message below is 32 octets, so 37 are used; `build_error` refuses
/// rather than truncates if a message ever outgrows it.
const TFTP_ERROR_TX_BYTES: usize = 64;

/// ERROR messages this client sends (RFC 1350 §5: netascii, zero-terminated
/// by `build_error`). Codes 3 and 5 carry the RFC's own wording for them.
const MSG_UNKNOWN_TID: &str = "Unknown transfer ID";
const MSG_DISK_FULL: &str = "Disk full or allocation exceeded";
const MSG_OUT_OF_ORDER: &str = "Block out of order";
const MSG_GAVE_UP: &str = "Timed out";

/// Maximum total iterations of the boot-time poll loop, summed
/// across all blocks. At ~1 poll per cycle this bounds the fetch
/// runtime regardless of server behaviour — a hung server can
/// still fail the boot in finite time rather than spin forever.
pub const TFTP_FETCH_MAX_POLLS: u32 = 5_000_000;

/// Polls to spend re-trying a send that returned nonzero.
///
/// U06 §4 comment audit (2026-09-26): this used to say the IP layer returns
/// -1 on an ARP cache miss and "expects the caller to retry once a reply
/// lands". `ip::send` no longer does that — an unresolved destination is
/// QUEUED (rc 0), not refused, and the frame is released once
/// `arp::arp_resolved` runs. So the retry loop below is not exercised by a
/// cold ARP cache any more; it stays as the budget for whatever OTHER
/// nonzero `sendto` this transport can still return. Each iteration pumps
/// `net_poll()` to drain incoming packets.
pub const TFTP_SEND_RETRY_POLLS: u32 = 200_000;

/// Ephemeral local source port allocator. We start from this base
/// and bump per fetch so two back-to-back fetches don't collide
/// inside a session. Range chosen above the IANA ephemeral floor
/// (49152) so we don't tread on well-known assignments.
const TFTP_EPHEMERAL_PORT_BASE: u16 = 49152;
static TFTP_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(TFTP_EPHEMERAL_PORT_BASE);

fn next_ephemeral_port() -> u16 {
    // Wrap back to the IANA floor at u16::MAX.
    let next = TFTP_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
    if next < TFTP_EPHEMERAL_PORT_BASE {
        TFTP_EPHEMERAL_PORT_BASE
    } else {
        next
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────

/// Failure modes of [`tftp_fetch`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TftpFetchError {
    /// Filename rejected by [`build_rrq`].
    Encode(TftpEncodeError),
    /// `dst` is too small for the transferred file.
    BufferOverflow,
    /// Could not allocate a UDP socket (table full).
    SocketBindFailed,
    /// `sendto` of the RRQ or an ACK returned a hardware error.
    SendFailed,
    /// Server's first reply did not arrive within
    /// [`TFTP_FETCH_MAX_POLLS`].
    NoReply,
    /// Block jumped past the expected number — RFC 1350 §4 retry
    /// would be needed; not implemented in Phase 1.
    OutOfOrderBlock { expected: u16, received: u16 },
    /// Server returned an ERROR packet; the contained `code` is
    /// the RFC 1350 error code.
    ServerError(u16),
    /// Poll loop hit [`TFTP_FETCH_MAX_POLLS`] without finishing
    /// the transfer.
    PollBudgetExhausted,
}

impl From<TftpEncodeError> for TftpFetchError {
    fn from(e: TftpEncodeError) -> Self {
        Self::Encode(e)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Public entry point
// ──────────────────────────────────────────────────────────────────────────

/// Fetch `filename` from `server_ip:69` into `dst`. Returns the
/// number of bytes written.
///
/// **Boot-time only**: busy-polls; not safe from a runnable task.
pub fn tftp_fetch(
    net: &dyn UdpTransport,
    server_ip: [u8; 4],
    filename: &str,
    dst: &mut [u8],
) -> Result<usize, TftpFetchError> {
    // ── Set up the local UDP socket. ────────────────────────────────
    let local_port = next_ephemeral_port();
    let sock = net.bind(local_port);
    if sock < 0 {
        return Err(TftpFetchError::SocketBindFailed);
    }

    let mut server_tid: Option<u16> = None;
    let result = fetch_inner(net, server_ip, filename, dst, sock, &mut server_tid);

    // RFC 1350 §7: a transfer this client ends early is ended with an ERROR,
    // so the server stops retransmitting instead of timing out. Sent here,
    // once, rather than at each `return Err` in `fetch_inner`: every early
    // end passes this point, including any added later. Only once the server's
    // TID is known -- before the first DATA there is no transfer on the server
    // side to end, and port 69 is its listener, not a TID.
    if let (Err(e), Some(tid)) = (result, server_tid) {
        if let Some((code, msg)) = abort_error(e) {
            send_error(net, sock, &server_ip, tid, code, msg);
        }
    }

    // Always release the socket — match-and-return would skip this.
    net.unbind(sock as usize);
    result
}

/// The ERROR code and message that end a transfer on `e`, or `None` when no
/// ERROR is owed. RFC 1350's table (Appendix, "Error Codes"):
/// 0 not defined (see message), 1 file not found, 2 access violation,
/// 3 disk full or allocation exceeded, 4 illegal TFTP operation,
/// 5 unknown transfer ID, 6 file already exists, 7 no such user.
///
/// No wildcard arm: a new failure mode has to be decided here.
fn abort_error(e: TftpFetchError) -> Option<(u16, &'static str)> {
    match e {
        // The destination cannot hold the file: the table's code 3, verbatim.
        TftpFetchError::BufferOverflow => Some((TFTP_ERR_DISK_FULL, MSG_DISK_FULL)),
        // Code 0 with a message, not 4. `TftpClient::on_data` reports
        // OutOfOrder for any block that is neither the next nor the previous
        // one. A block ahead is a server fault, but one further behind is a
        // late duplicate, which RFC 1350 §2 counts among packets "explained by
        // a delay or duplication in the network", not as an illegal operation.
        // What ends the transfer is this client not reordering, and the table
        // has no entry for that.
        TftpFetchError::OutOfOrderBlock { .. } => Some((TFTP_ERR_NOT_DEFINED, MSG_OUT_OF_ORDER)),
        // The client gives up on a transfer the server may still be running:
        // an ACK that could not be sent, or the poll budget. No table entry.
        TftpFetchError::NoReply
        | TftpFetchError::SendFailed
        | TftpFetchError::PollBudgetExhausted => Some((TFTP_ERR_NOT_DEFINED, MSG_GAVE_UP)),
        // RFC 1350 §7: an ERROR is neither acknowledged nor retransmitted.
        // Answering one with another is how two peers loop.
        TftpFetchError::ServerError(_) => None,
        // No transfer exists: nothing sent, or no socket to send from.
        TftpFetchError::Encode(_) | TftpFetchError::SocketBindFailed => None,
    }
}

fn fetch_inner(
    net: &dyn UdpTransport,
    server_ip: [u8; 4],
    filename: &str,
    dst: &mut [u8],
    sock: i32,
    server_tid: &mut Option<u16>,
) -> Result<usize, TftpFetchError> {
    // ── Build + send the RRQ. ───────────────────────────────────────
    let mut rrq_buf = [0u8; TFTP_RRQ_MAX_BYTES];
    let rrq_len = build_rrq(filename, &mut rrq_buf)?;
    // U06 §4 comment audit (2026-09-26): the first send to a new destination
    // used to almost always return -1 on a cold ARP cache; `ip::send` now
    // queues that frame instead (rc 0) and releases it once
    // `arp::arp_resolved` runs, so this call typically succeeds on its
    // first try even with nothing in the cache yet. `sendto_with_arp_retry`
    // is kept as the budget for a nonzero `sendto` from some other cause.
    sendto_with_arp_retry(net, sock, &server_ip, TFTP_PORT, &rrq_buf[..rrq_len])?;

    // ── Poll for DATA, ACK, accumulate. ─────────────────────────────
    let mut client = TftpClient::new();
    let mut written: usize = 0;
    // The server picks a fresh ephemeral port (RFC 1350 calls it
    // the TID) and replies from it. We learn it from the first
    // DATA and direct subsequent ACKs there; `server_tid` stays
    // `None` until then.
    let mut rx = [0u8; TFTP_RX_BUF_BYTES];
    let mut from_ip = [0u8; 4];
    let mut from_port: u16 = 0;

    for _poll in 0..TFTP_FETCH_MAX_POLLS {
        // Pump the device once per iter so the RX ring fills.
        net.poll();

        let n = net.recvfrom(sock, &mut rx, &mut from_ip, &mut from_port);
        if n <= 0 {
            // Nothing yet — keep polling within the budget.
            continue;
        }
        let pkt = &rx[..n as usize];

        // Defensive: drop packets from unrelated peers. The first
        // accepted DATA locks the server's TID for the rest of
        // the transfer.
        let from_server = from_ip == server_ip
            && server_tid.map_or(true, |tid| from_port == tid);
        if !from_server {
            // RFC 1350 §4: "An error packet should be sent to the source of
            // the incorrect packet, while not disturbing the transfer." To
            // its source address and port, from this transfer's socket.
            // Not when the stray is itself an ERROR (§7): two endpoints that
            // each answer an ERROR with an ERROR never stop.
            if !is_error_opcode(pkt) {
                send_error(net, sock, &from_ip, from_port, TFTP_ERR_UNKNOWN_TID, MSG_UNKNOWN_TID);
            }
            continue;
        }

        match parse_packet(pkt) {
            RxOutcome::Data { block, payload, is_last } => {
                let server_tid = *server_tid.get_or_insert(from_port);
                match client.on_data(block, is_last) {
                    ClientAction::AckAndConsume => {
                        if written + payload.len() > dst.len() {
                            return Err(TftpFetchError::BufferOverflow);
                        }
                        dst[written..written + payload.len()]
                            .copy_from_slice(payload);
                        written += payload.len();
                        send_ack(net, sock, &server_ip, server_tid, block)?;
                    }
                    ClientAction::AckIgnore => {
                        // Duplicate — re-ACK the prior block.
                        send_ack(net, sock, &server_ip, server_tid, block)?;
                    }
                    ClientAction::Complete => {
                        if written + payload.len() > dst.len() {
                            return Err(TftpFetchError::BufferOverflow);
                        }
                        dst[written..written + payload.len()]
                            .copy_from_slice(payload);
                        written += payload.len();
                        send_ack(net, sock, &server_ip, server_tid, block)?;
                        return Ok(written);
                    }
                    ClientAction::OutOfOrder { expected, received } => {
                        return Err(TftpFetchError::OutOfOrderBlock {
                            expected,
                            received,
                        });
                    }
                }
            }
            RxOutcome::Error(code) => {
                return Err(TftpFetchError::ServerError(code));
            }
            RxOutcome::Malformed => {
                // Drop and keep polling — the I/O layer's job is
                // to ignore garbage, not to escalate it.
                continue;
            }
        }
    }
    if server_tid.is_none() {
        Err(TftpFetchError::NoReply)
    } else {
        Err(TftpFetchError::PollBudgetExhausted)
    }
}

/// Does `pkt` carry the ERROR opcode, well-formed or not?
fn is_error_opcode(pkt: &[u8]) -> bool {
    pkt.len() >= 2 && u16::from_be_bytes([pkt[0], pkt[1]]) == TFTP_OPCODE_ERROR
}

/// Send one ERROR, once.
///
/// Best effort on purpose, and never through `sendto_with_arp_retry`. RFC
/// 1350 §7 calls an ERROR "only a courtesy", never acknowledged. For a stray
/// packet the retry loop would be the disturbance §4 forbids: a stranger's
/// ARP miss would spend `TFTP_SEND_RETRY_POLLS` pumping the stack without
/// reading the socket, while the real server's blocks pile up behind it. For
/// an abort the fetch has already failed, and a retry budget would only delay
/// reporting that. The send's result is ignored for the same reason: it must
/// not change what the fetch returns.
fn send_error(
    net: &dyn UdpTransport,
    sock: i32,
    dst_ip: &[u8; 4],
    dst_port: u16,
    code: u16,
    msg: &str,
) {
    let mut pkt = [0u8; TFTP_ERROR_TX_BYTES];
    if let Ok(len) = build_error(code, msg, &mut pkt) {
        let _ = net.sendto(sock, dst_ip, dst_port, &pkt[..len]);
    }
}

fn send_ack(
    net: &dyn UdpTransport,
    sock: i32,
    server_ip: &[u8; 4],
    server_tid: u16,
    block: u16,
) -> Result<(), TftpFetchError> {
    let mut ack = [0u8; TFTP_ACK_BYTES];
    build_ack(block, &mut ack);
    // After the first round-trip the ARP cache is warm and sends
    // succeed in one shot — but go through the retry helper anyway
    // so a transient ARP eviction doesn't sink the transfer.
    sendto_with_arp_retry(net, sock, server_ip, server_tid, &ack)
}

/// `udp::sendto` plus ARP-warmup retries. Returns `Ok(())` as
/// soon as the underlying send returns `0`, or
/// `Err(NoReply | SendFailed)` after `TFTP_SEND_RETRY_POLLS`.
fn sendto_with_arp_retry(
    net: &dyn UdpTransport,
    sock: i32,
    dst_ip: &[u8; 4],
    dst_port: u16,
    data: &[u8],
) -> Result<(), TftpFetchError> {
    let mut last_rc = net.sendto(sock, dst_ip, dst_port, data);
    if last_rc == 0 {
        return Ok(());
    }
    for _ in 0..TFTP_SEND_RETRY_POLLS {
        net.poll();
        last_rc = net.sendto(sock, dst_ip, dst_port, data);
        if last_rc == 0 {
            return Ok(());
        }
    }
    // After the retry budget, distinguish the "no ARP reply at
    // all" case from a deeper send error. The IP layer returns
    // -1 in both cases, so we can only report the budget exhaustion.
    Err(TftpFetchError::NoReply)
}
