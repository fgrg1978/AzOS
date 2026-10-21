// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::rig::*;
use azos_ble::att::{self, Pdu as Att};
use azos_ble::h4;
use azos_ble::host::{HostError, SendError};
use azos_ble::hci::{self, status, ConnParams, ScanParams};
use azos_ble::smp::{io_cap, Role};
use azos_ble::{Host, PeerAddr, MAX_CONN};
use azos_devif::uart::{Chunk, CHUNK_OVERRUN};

/// One host and its controller.
struct Solo {
    h: Host<Rng>,
    c: Side,
    u: Rec,
    now: u64,
}

impl Solo {
    fn new(cfg: azos_ble::Config) -> Solo {
        Solo { h: Host::new(Rng(7), cfg), c: Side::new(ADDR_A), u: Rec::default(), now: 1000 }
    }

    fn settle(&mut self) {
        for _ in 0..100 {
            let moved = step_host(&mut self.h, &mut self.c, &mut self.u, self.now);
            let radio = self.c.process();
            if !moved && radio.is_empty() {
                return;
            }
        }
        panic!("never settled");
    }

    fn ready() -> Solo {
        let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
        s.settle();
        assert!(s.h.ready());
        s.u.take();
        s.c.cmds.clear();
        s
    }

    fn ops(&self) -> Vec<u16> {
        self.c.cmds.iter().map(|c| c.op).collect()
    }

    /// A connection with `handle`, in `role` (0 central, 1 peripheral).
    fn connected(role: u8) -> Solo {
        let mut s = Solo::ready();
        s.c.conn_complete(0x0041, role, PeerAddr { kind: 0, addr: ADDR_B });
        s.settle();
        s.u.take();
        s
    }

    /// The ACL fragments the controller got, reassembled into frames (cid, payload).
    fn frames(&mut self) -> Vec<(u16, Vec<u8>)> {
        let mut out = vec![];
        let mut cur: Option<(u16, usize, Vec<u8>)> = None;
        for (_, pb, d) in self.c.acl.drain(..) {
            if pb == 0 {
                let len = u16::from_le_bytes([d[0], d[1]]) as usize;
                cur = Some((u16::from_le_bytes([d[2], d[3]]), len, d[4..].to_vec()));
            } else {
                cur.as_mut().unwrap().2.extend_from_slice(&d);
            }
            if let Some((cid, len, p)) = &cur {
                if p.len() == *len {
                    out.push((*cid, p.clone()));
                    cur = None;
                }
            }
        }
        assert!(cur.is_none(), "a frame was left half sent");
        out
    }
}

#[test]
fn init_sequence_then_ready() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    assert_eq!(s.h.att_send(1, &Att::Confirmation, 0), Err(SendError::NotReady));
    assert_eq!(s.h.start_scan(ScanParams { active: true, interval: 16, window: 16, own_addr_type: 0 }), Err(SendError::NotReady));
    s.settle();
    assert_eq!(
        s.ops(),
        [hci::OP_RESET, hci::OP_SET_EVENT_MASK, hci::OP_LE_SET_EVENT_MASK, hci::OP_READ_BD_ADDR, hci::OP_LE_READ_BUFFER_SIZE]
    );
    assert_eq!(s.c.cmds[1].params, hci::EVENT_MASK.to_le_bytes());
    assert_eq!(s.c.cmds[2].params, hci::LE_EVENT_MASK.to_le_bytes());
    assert_eq!(s.u.events, vec![Ev::Ready(ADDR_A)]);
    assert!(s.h.ready());
    assert_eq!(s.h.address(), PeerAddr { kind: 0, addr: ADDR_A });
    assert_eq!(s.c.junk, 0);
}

#[test]
fn a_static_random_address_is_set_and_used() {
    let mut c = cfg(io_cap::NO_INPUT_NO_OUTPUT, false);
    c.random_address = Some([0xC0, 1, 2, 3, 4, 5]);
    let mut s = Solo::new(c);
    s.settle();
    assert_eq!(s.ops().last(), Some(&hci::OP_LE_SET_RANDOM_ADDRESS));
    assert_eq!(s.u.events, vec![Ev::Ready([0xC0, 1, 2, 3, 4, 5])]);
    assert_eq!(s.h.address(), PeerAddr { kind: 1, addr: [0xC0, 1, 2, 3, 4, 5] });
    s.c.cmds.clear();
    s.h.start_scan(ScanParams { active: false, interval: 16, window: 16, own_addr_type: 0 }).unwrap();
    s.settle();
    assert_eq!(s.c.cmds[0].params[5], 1, "own address type follows the address in use");
}

#[test]
fn a_failed_init_command_stops_the_host_and_restart_runs_it_again() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    s.c.fail.push((hci::OP_READ_BD_ADDR, status::UNKNOWN_COMMAND));
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::Init { opcode: hci::OP_READ_BD_ADDR, status: 1 })]);
    assert!(!s.h.ready());
    assert_eq!(s.h.disconnect(1, 0x13), Err(SendError::NotReady));
    s.c.fail.clear();
    s.c.cmds.clear();
    s.h.restart(&mut s.u);
    s.settle();
    assert!(s.h.ready());
    assert_eq!(s.ops()[0], hci::OP_RESET, "the controller is reset again");
}

#[test]
fn a_controller_without_le_buffers_is_refused() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    s.c.acl_num = 0;
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::NoLeBuffers)]);
}

#[test]
fn one_command_in_flight_and_the_controllers_credit_is_obeyed() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    s.c.mute = true;
    s.settle();
    assert_eq!(s.ops(), [hci::OP_RESET], "the second waits for the first");
    // The controller answers but has no room for another command.
    s.c.mute = false;
    s.c.ncmd = 0;
    s.c.cc(hci::OP_RESET, &[0]);
    s.settle();
    assert_eq!(s.ops(), [hci::OP_RESET], "credit 0: nothing may be sent");
    s.c.ncmd = 1;
    s.c.cc(0, &[]); // a NOP command complete that only returns credit
    s.settle();
    assert!(s.h.ready());
}

#[test]
fn an_unanswered_command_stops_the_host_after_the_timeout() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    s.c.mute = true;
    s.settle();
    s.now += hci_timeout() - 1;
    s.settle();
    assert!(s.u.events.is_empty());
    s.now += 1;
    s.h.tick(s.now, &mut s.u);
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::CommandTimeout { opcode: hci::OP_RESET })]);
}

fn hci_timeout() -> u64 {
    azos_ble::host::COMMAND_TIMEOUT_MS
}

#[test]
fn a_hardware_error_stops_the_host() {
    let mut s = Solo::ready();
    s.c.event(hci::EVT_HARDWARE_ERROR, &[0x42]);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::Hardware(0x42))]);
    assert!(!s.h.ready());
}

#[test]
fn garbage_on_the_line_is_counted_and_the_stream_recovers() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    s.c.rx.extend([0x00u8, 0x07, 0x99]);
    s.settle();
    assert!(s.h.ready());
    assert_eq!(s.h.framing().bad_indicator, 3);
}

fn chunk(b: &[u8], flags: u32) -> Chunk {
    Chunk::new(b, flags)
}

#[test]
fn a_stalled_half_packet_is_dropped_by_the_timer() {
    let mut s = Solo::ready();
    // Half of a hardware error event, then silence.
    s.h.rx_chunk(&chunk(&[0x04, 0x10], 0), s.now, &mut s.u);
    s.now += 300;
    s.h.tick(s.now, &mut s.u);
    assert_eq!(s.h.framing().resets, 1);
    s.h.rx_chunk(&chunk(&[0x04, 0x10, 0x01, 0x09], 0), s.now, &mut s.u);
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::Hardware(9))], "the next packet is read from its indicator");
}

#[test]
fn a_chunk_flagged_overrun_drops_the_half_packet_before_it() {
    let mut s = Solo::ready();
    s.h.rx_chunk(&chunk(&[0x04, 0x0E, 0x04, 0x01], 0), s.now, &mut s.u);
    s.h.rx_chunk(&chunk(&[0x04, 0x10, 0x01, 0x05], CHUNK_OVERRUN), s.now, &mut s.u);
    assert_eq!(s.u.events, vec![Ev::Failed(HostError::Hardware(5))]);
    assert_eq!(s.h.framing().resets, 1);
}

#[test]
fn the_transmit_ring_keeps_what_the_sink_has_no_room_for() {
    let mut s = Solo::new(cfg(io_cap::NO_INPUT_NO_OUTPUT, false));
    let mut out = vec![];
    let mut none = std::collections::VecDeque::new();
    let mut flags = std::collections::VecDeque::new();
    s.h.run(&mut Src(&mut none, &mut flags), &mut Sink { out: &mut out, room: Some(0) }, s.now, &mut s.u);
    assert!(out.is_empty(), "no room in the ring: nothing lost, nothing sent");
    s.h.run(&mut Src(&mut none, &mut flags), &mut Sink { out: &mut out, room: Some(2) }, s.now, &mut s.u);
    assert!(out.is_empty(), "a chunk is whole or not at all");
    s.h.run(&mut Src(&mut none, &mut flags), &mut Sink { out: &mut out, room: None }, s.now, &mut s.u);
    assert_eq!(out, [0x01, 0x03, 0x0C, 0x00], "the reset, once");
}

// ── Advertising, scanning, connections ─────────────────────────────────────

#[test]
fn advertising_is_four_commands_in_order() {
    let mut s = Solo::ready();
    let data = [2, 1, 6, 5, 9, b'a', b'z', b'o'];
    s.h.start_advertising(adv_params(), &data, &[3, 0xFF, 1, 2]).unwrap();
    s.settle();
    assert_eq!(s.ops(), [hci::OP_LE_SET_ADV_PARAMS, hci::OP_LE_SET_ADV_DATA, hci::OP_LE_SET_SCAN_RSP_DATA, hci::OP_LE_SET_ADV_ENABLE]);
    assert_eq!(s.c.cmds[1].params[0], 8);
    assert_eq!(&s.c.cmds[1].params[1..9], &data);
    assert_eq!(s.c.cmds[2].params[0], 4);
    assert_eq!(s.c.cmds[3].params, [1]);
    assert!(s.c.adv_enabled);
    s.h.stop_advertising().unwrap();
    s.settle();
    assert!(!s.c.adv_enabled);
}

#[test]
fn advertising_arguments_and_the_command_queue_are_checked() {
    let mut s = Solo::ready();
    assert_eq!(s.h.start_advertising(adv_params(), &[0; 32], &[]), Err(SendError::Invalid));
    assert_eq!(s.h.start_advertising(adv_params(), &[], &[0; 32]), Err(SendError::Invalid));
    s.h.start_advertising(adv_params(), &[], &[]).unwrap();
    s.h.start_advertising(adv_params(), &[], &[]).unwrap();
    assert_eq!(s.h.start_advertising(adv_params(), &[], &[]), Err(SendError::QueueFull));
    assert_eq!(s.h.stop_scan(), Err(SendError::QueueFull));
    s.settle();
    s.h.stop_scan().unwrap();
}

#[test]
fn a_command_that_fails_after_init_is_reported() {
    let mut s = Solo::ready();
    s.c.fail.push((hci::OP_LE_SET_ADV_ENABLE, 0x0D));
    s.h.start_advertising(adv_params(), &[], &[]).unwrap();
    s.settle();
    assert_eq!(s.u.events, vec![Ev::CommandFailed(hci::OP_LE_SET_ADV_ENABLE, 0x0D)]);
    assert!(s.h.ready(), "the host carries on");
}

#[test]
fn scanning_delivers_reports() {
    let mut s = Solo::ready();
    s.h.start_scan(ScanParams { active: true, interval: 0x30, window: 0x30, own_addr_type: 0 }).unwrap();
    s.settle();
    assert_eq!(s.ops(), [hci::OP_LE_SET_SCAN_PARAMS, hci::OP_LE_SET_SCAN_ENABLE]);
    assert_eq!(s.c.cmds[0].params[0], 1, "active scanning");
    assert_eq!(s.c.cmds[1].params, [1, 1]);
    let mut p = vec![1, 0, 0];
    p.extend_from_slice(&ADDR_B);
    p.extend_from_slice(&[3, 2, 1, 6, 0xC4]);
    s.c.le_event(hci::LE_ADVERTISING_REPORT, &p);
    s.settle();
    assert_eq!(
        s.u.events,
        vec![Ev::Advert { peer: PeerAddr { kind: 0, addr: ADDR_B }, kind: 0, data: vec![2, 1, 6], rssi: -60 }]
    );
}

#[test]
fn a_connection_as_central_and_as_peripheral() {
    let mut s = Solo::ready();
    let peer = PeerAddr { kind: 1, addr: ADDR_B };
    s.h.connect(peer).unwrap();
    s.settle();
    assert_eq!(s.ops(), [hci::OP_LE_CREATE_CONNECTION]);
    assert_eq!(&s.c.cmds[0].params[5..12], &[1, 0xC1, 0xCF, 0x2D, 0x70, 0x13, 0xA7]);
    s.c.conn_complete(0x0041, 0, peer);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Connected { conn: 0x41, role: Role::Initiator, peer }]);
    s.u.take();
    s.c.conn_complete(0x0042, 1, PeerAddr { kind: 0, addr: [9; 6] });
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Connected { conn: 0x42, role: Role::Responder, peer: PeerAddr { kind: 0, addr: [9; 6] } }]);
}

#[test]
fn a_failed_attempt_is_reported_and_a_full_table_turns_the_extra_link_away() {
    let mut s = Solo::ready();
    let mut p = vec![0x3E];
    p.extend_from_slice(&[0; 17]);
    s.c.le_event(hci::LE_CONNECTION_COMPLETE, &p);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::ConnectFailed(0x3E)]);
    s.u.take();
    for i in 0..MAX_CONN as u16 {
        s.c.conn_complete(0x10 + i, 1, PeerAddr { kind: 0, addr: [i as u8; 6] });
    }
    s.c.conn_complete(0x20, 1, PeerAddr { kind: 0, addr: [0x77; 6] });
    s.settle();
    assert_eq!(s.u.events.len(), MAX_CONN);
    let last = s.c.cmds.last().unwrap();
    assert_eq!((last.op, &last.params[..2]), (hci::OP_DISCONNECT, &[0x20u8, 0][..]));
}

#[test]
fn disconnect_reports_and_forgets_the_connection() {
    let mut s = Solo::connected(0);
    assert_eq!(s.h.disconnect(0x99, 0x13), Err(SendError::NoConnection));
    s.h.disconnect(0x41, status::REMOTE_USER_TERMINATED).unwrap();
    s.settle();
    assert_eq!(s.c.cmds.last().unwrap().params, [0x41, 0x00, 0x13]);
    s.c.event(hci::EVT_DISCONNECTION_COMPLETE, &[0, 0x41, 0, 0x16]);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Disconnected(0x41, 0x16)]);
    assert_eq!(s.h.att_send(0x41, &Att::Confirmation, 0), Err(SendError::NoConnection));
    // A repeated event for a handle that is gone is not reported twice.
    s.c.event(hci::EVT_DISCONNECTION_COMPLETE, &[0, 0x41, 0, 0x16]);
    s.settle();
    assert_eq!(s.u.events.len(), 1);
}

// ── ACL ────────────────────────────────────────────────────────────────────

/// Give the connection a large MTU: the peer asks for 247.
fn big_mtu(s: &mut Solo) {
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::EXCHANGE_MTU_REQ, 247, 0], 27);
    s.settle();
    s.c.acl.clear();
    s.c.complete(0x41, 1);
    s.settle();
    s.u.take();
}

#[test]
fn a_long_pdu_is_fragmented_to_the_controllers_buffer_length() {
    let mut s = Solo::connected(0);
    big_mtu(&mut s);
    assert_eq!(s.h.mtu(0x41), Some(247));
    let value: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    s.h.att_send(0x41, &Att::Notification { handle: 9, value: &value }, s.now).unwrap();
    s.c.acl_num = 8;
    s.settle();
    // The credits were read at init: acl_num was 4 then.
    let first: Vec<_> = s.c.acl.iter().map(|(_, pb, d)| (*pb, d.len())).collect();
    assert_eq!(first, [(0, 27), (1, 27), (1, 27), (1, 27)], "four buffers, the rest waits");
    let sent = s.c.acl.len();
    s.c.complete(0x41, sent as u16);
    s.settle();
    let mut all = s.frames();
    assert_eq!(all.len(), 1);
    let (cid, p) = all.pop().unwrap();
    assert_eq!(cid, att::CID_ATT);
    assert_eq!(Att::parse(&p), Ok(Att::Notification { handle: 9, value: &value }));
}

#[test]
fn a_disconnection_returns_the_buffers_it_held() {
    let mut s = Solo::connected(0);
    big_mtu(&mut s);
    let value = [7u8; 150];
    s.h.att_send(0x41, &Att::Notification { handle: 9, value: &value }, s.now).unwrap();
    s.settle();
    assert_eq!(s.c.acl.len(), 4, "all four buffers are out");
    s.c.acl.clear();
    s.c.event(hci::EVT_DISCONNECTION_COMPLETE, &[0, 0x41, 0, 0x13]);
    s.c.conn_complete(0x43, 1, PeerAddr { kind: 0, addr: [3; 6] });
    s.settle();
    s.c.acl.clear();
    s.u.take();
    s.c.frame_to_host(0x43, att::CID_ATT, &[att::op::EXCHANGE_MTU_REQ, 100, 0], 27);
    s.settle();
    s.c.acl.clear();
    s.c.complete(0x43, 1);
    s.settle();
    // The queued rest of the old notification must not leak onto the new link,
    // and the new link has its four buffers.
    s.h.att_send(0x43, &Att::Notification { handle: 9, value: &[1u8; 90] }, s.now).unwrap();
    s.settle();
    assert_eq!(s.c.acl.len(), 4);
    assert!(s.c.acl.iter().all(|(h, _, _)| *h == 0x43));
}

#[test]
fn a_pdu_in_fragments_over_uneven_chunks_is_delivered_once() {
    let mut s = Solo::connected(1);
    let mut pdu = vec![att::op::WRITE_CMD, 5, 0];
    pdu.extend((0..20u8).map(|i| 0xA0 + i));
    // 23 is the default MTU: a command of 23 bytes.
    s.c.frame_to_host(0x41, att::CID_ATT, &pdu, 7);
    // Deliver in odd pieces: the deframer sees packets straddling chunks.
    let bytes: Vec<u8> = s.c.rx.drain(..).collect();
    for part in bytes.chunks(5) {
        s.h.rx_chunk(&Chunk::new(part, 0), s.now, &mut s.u);
    }
    assert_eq!(s.u.events, vec![Ev::Att(0x41, pdu)]);
}

#[test]
fn acl_for_an_unknown_handle_and_broken_sequences_are_dropped_quietly() {
    let mut s = Solo::connected(1);
    s.c.frame_to_host(0x77, att::CID_ATT, &[att::op::WRITE_CMD, 1, 0], 27);
    s.c.acl_to_host(0x41, 1, &[1, 2, 3]); // a continuation with nothing begun
    s.settle();
    assert!(s.u.events.is_empty());
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::WRITE_CMD, 1, 0, 9], 27);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Att(0x41, vec![att::op::WRITE_CMD, 1, 0, 9])]);
}

// ── ATT bearer ─────────────────────────────────────────────────────────────

#[test]
fn an_unknown_request_gets_an_error_response_and_an_unknown_command_none() {
    let mut s = Solo::connected(1);
    s.c.frame_to_host(0x41, att::CID_ATT, &[0x0E, 1, 0, 2, 0], 27); // read multiple
    s.settle();
    let f = s.frames();
    assert_eq!(f.len(), 1);
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ErrorRsp { request: 0x0E, handle: 0, code: att::err::REQUEST_NOT_SUPPORTED }));
    assert!(s.u.events.is_empty());
    s.c.frame_to_host(0x41, att::CID_ATT, &[0x40 | 0x12, 1, 0], 27); // an unknown command (bit 6)
    s.settle();
    assert!(s.frames().is_empty());
}

#[test]
fn a_malformed_request_is_answered_invalid_pdu() {
    let mut s = Solo::connected(1);
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::READ_REQ, 1], 27);
    s.settle();
    let f = s.frames();
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ErrorRsp { request: att::op::READ_REQ, handle: 0, code: att::err::INVALID_PDU }));
}

#[test]
fn a_request_reaches_the_upper_layer_and_is_answered_through_att_send() {
    let mut s = Solo::connected(1);
    let rd = [att::op::READ_REQ, 3, 0];
    s.c.frame_to_host(0x41, att::CID_ATT, &rd, 27);
    s.settle();
    assert_eq!(s.u.take(), vec![Ev::Att(0x41, rd.to_vec())]);
    // A second request while the first is unanswered is a protocol violation: dropped.
    s.c.frame_to_host(0x41, att::CID_ATT, &rd, 27);
    s.settle();
    assert!(s.u.events.is_empty());
    s.h.att_send(0x41, &Att::ReadRsp { value: &[42] }, s.now).unwrap();
    assert_eq!(s.h.att_send(0x41, &Att::ReadRsp { value: &[42] }, s.now), Err(SendError::NotAllowed));
    s.settle();
    let f = s.frames();
    assert_eq!(f.len(), 1);
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ReadRsp { value: &[42] }));
    s.c.frame_to_host(0x41, att::CID_ATT, &rd, 27);
    s.settle();
    assert_eq!(s.u.events.len(), 1, "answered: the next request is accepted");
}

#[test]
fn the_host_answers_the_peers_mtu_request_itself() {
    let mut s = Solo::connected(1);
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::EXCHANGE_MTU_REQ, 185, 0], 27);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Mtu(0x41, 185)], "the upper layer sees the result, not the request");
    let f = s.frames();
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ExchangeMtuRsp { mtu: att::LOCAL_MTU }));
    assert_eq!(s.h.mtu(0x41), Some(185));
    s.u.take();
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::EXCHANGE_MTU_REQ, 185, 0], 27);
    s.settle();
    let f = s.frames();
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ErrorRsp { request: att::op::EXCHANGE_MTU_REQ, handle: 0, code: att::err::REQUEST_NOT_SUPPORTED }));
    assert!(s.u.events.is_empty());
}

#[test]
fn the_host_runs_the_mtu_exchange_as_the_client() {
    let mut s = Solo::connected(0);
    s.h.exchange_mtu(0x41, s.now).unwrap();
    assert_eq!(s.h.exchange_mtu(0x41, s.now), Err(SendError::Busy));
    s.settle();
    let f = s.frames();
    assert_eq!(Att::parse(&f[0].1), Ok(Att::ExchangeMtuReq { mtu: att::LOCAL_MTU }));
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::EXCHANGE_MTU_RSP, 100, 0], 27);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Mtu(0x41, 100)]);
    assert_eq!(s.h.exchange_mtu(0x41, s.now), Err(SendError::NotAllowed));
    let big = [0u8; 120];
    assert_eq!(s.h.att_send(0x41, &Att::WriteReq { handle: 1, value: &big }, s.now), Err(SendError::TooBig));
}

#[test]
fn an_exchange_the_peer_refuses_still_ends() {
    let mut s = Solo::connected(0);
    s.h.exchange_mtu(0x41, s.now).unwrap();
    s.settle();
    s.c.frame_to_host(0x41, att::CID_ATT, &[att::op::ERROR_RSP, att::op::EXCHANGE_MTU_REQ, 0, 0, att::err::REQUEST_NOT_SUPPORTED], 27);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::Mtu(0x41, att::DEFAULT_MTU)]);
}

#[test]
fn a_request_never_answered_costs_the_link() {
    let mut s = Solo::connected(0);
    s.h.att_send(0x41, &Att::ReadReq { handle: 1 }, s.now).unwrap();
    s.settle();
    s.c.cmds.clear();
    s.now += att::TRANSACTION_TIMEOUT_MS;
    s.h.tick(s.now, &mut s.u);
    s.settle();
    assert_eq!(s.ops(), [hci::OP_DISCONNECT]);
}

// ── Signalling ─────────────────────────────────────────────────────────────

fn sig_update_req(id: u8, min: u16, max: u16, lat: u16, to: u16) -> Vec<u8> {
    let mut v = vec![0x12, id, 8, 0];
    for x in [min, max, lat, to] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

#[test]
fn the_central_accepts_a_valid_parameter_update_and_applies_it() {
    let mut s = Solo::connected(0);
    s.c.frame_to_host(0x41, l2cap_sig(), &sig_update_req(5, 24, 40, 2, 600), 27);
    s.settle();
    let f = s.frames();
    assert_eq!(f, vec![(5, vec![0x13, 5, 2, 0, 0, 0])]);
    let upd = s.c.cmds.last().unwrap();
    assert_eq!(upd.op, hci::OP_LE_CONNECTION_UPDATE);
    assert_eq!(&upd.params[2..10], &[24, 0, 40, 0, 2, 0, 0x58, 0x02]);
    s.c.le_event(hci::LE_CONNECTION_UPDATE_COMPLETE, &[0, 0x41, 0, 40, 0, 2, 0, 0x58, 0x02]);
    s.settle();
    assert_eq!(s.u.events, vec![Ev::ConnectionUpdated { conn: 0x41, interval: 40 }]);
}

fn l2cap_sig() -> u16 {
    azos_ble::l2cap::CID_SIGNALLING
}

#[test]
fn the_central_rejects_an_invalid_update_without_touching_the_controller() {
    let mut s = Solo::connected(0);
    s.c.cmds.clear();
    s.c.frame_to_host(0x41, l2cap_sig(), &sig_update_req(6, 2, 40, 0, 400), 27);
    s.settle();
    assert_eq!(s.frames(), vec![(5, vec![0x13, 6, 2, 0, 1, 0])]);
    assert!(s.c.cmds.is_empty());
}

#[test]
fn a_peripheral_is_not_asked_for_parameters() {
    let mut s = Solo::connected(1);
    s.c.frame_to_host(0x41, l2cap_sig(), &sig_update_req(7, 24, 40, 0, 400), 27);
    s.settle();
    assert_eq!(s.frames(), vec![(5, vec![0x01, 7, 2, 0, 0, 0])]);
}

#[test]
fn credit_based_channels_and_unknown_requests_are_refused_responses_are_not_answered() {
    let mut s = Solo::connected(0);
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x14, 3, 10, 0, 0x80, 0, 0x41, 0, 23, 0, 23, 0, 5, 0], 27);
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x06, 4, 4, 0, 0x41, 0, 0x42, 0], 27);
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x0A, 8, 2, 0, 1, 0], 27); // information request
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x13, 9, 2, 0, 0, 0], 27); // a response
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x16, 10, 4, 0, 0x41, 0, 5, 0], 27); // credits for nothing
    s.settle();
    assert_eq!(
        s.frames(),
        vec![
            (5, vec![0x15, 3, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]),
            (5, vec![0x01, 4, 2, 0, 0, 0]),
            (5, vec![0x01, 8, 2, 0, 0, 0]),
        ]
    );
}

#[test]
fn the_peripheral_asks_the_central_and_the_central_tells_its_controller() {
    let p = ConnParams { interval_min: 24, interval_max: 40, latency: 0, timeout: 400 };
    let mut s = Solo::connected(1);
    s.h.update_connection(0x41, p).unwrap();
    s.settle();
    assert_eq!(s.frames(), vec![(5, sig_update_req(1, 24, 40, 0, 400))]);
    s.h.update_connection(0x41, p).unwrap();
    s.settle();
    assert_eq!(s.frames()[0].1[1], 2, "identifiers advance");
    assert_eq!(s.h.update_connection(0x41, ConnParams { interval_min: 1, ..p }), Err(SendError::Invalid));
    assert_eq!(s.h.update_connection(0x99, p), Err(SendError::NoConnection));

    let mut c = Solo::connected(0);
    c.h.update_connection(0x41, p).unwrap();
    c.settle();
    assert_eq!(c.c.cmds.last().unwrap().op, hci::OP_LE_CONNECTION_UPDATE);
    assert!(c.c.acl.is_empty());
}

#[test]
fn a_garbled_sdu_on_a_channel_nobody_has_is_ignored() {
    let mut s = Solo::connected(0);
    s.c.frame_to_host(0x41, 0x0040, &[1, 2, 3], 27);
    s.c.frame_to_host(0x41, l2cap_sig(), &[0x12], 27);
    s.settle();
    assert!(s.u.events.is_empty());
    assert!(s.c.acl.is_empty());
    let _ = h4::BODY_MAX;
}
