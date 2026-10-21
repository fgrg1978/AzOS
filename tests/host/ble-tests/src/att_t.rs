// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_ble::att::*;
use azos_ble::Error;

fn rt(p: Pdu) -> Vec<u8> {
    let mut b = [0u8; 300];
    let n = p.encode(&mut b).unwrap();
    assert_eq!(Pdu::parse(&b[..n]), Ok(p), "round trip of {p:?}");
    b[..n].to_vec()
}

#[test]
fn every_pdu_round_trips_and_has_the_documented_bytes() {
    assert_eq!(rt(Pdu::ErrorRsp { request: op::READ_REQ, handle: 0x0003, code: err::ATTRIBUTE_NOT_FOUND }), [1, 0x0A, 3, 0, 0x0A]);
    assert_eq!(rt(Pdu::ExchangeMtuReq { mtu: 247 }), [2, 247, 0]);
    assert_eq!(rt(Pdu::ExchangeMtuRsp { mtu: 185 }), [3, 185, 0]);
    assert_eq!(rt(Pdu::FindInfoReq { start: 1, end: 0xFFFF }), [4, 1, 0, 0xFF, 0xFF]);
    rt(Pdu::FindInfoRsp { format: 1, data: &[1, 0, 0x00, 0x28] });
    rt(Pdu::FindByTypeValueReq { start: 1, end: 9, attr_type: 0x2800, value: &[0x0F, 0x18] });
    rt(Pdu::FindByTypeValueRsp { data: &[1, 0, 5, 0] });
    assert_eq!(rt(Pdu::ReadByTypeReq { start: 1, end: 9, uuid: Uuid::U16(0x2803) }), [8, 1, 0, 9, 0, 3, 0x28]);
    let u = Uuid::U128([7; 16]);
    assert_eq!(rt(Pdu::ReadByGroupTypeReq { start: 1, end: 9, uuid: u }).len(), 1 + 4 + 16);
    rt(Pdu::ReadByTypeRsp { item_len: 7, data: &[1; 14] });
    rt(Pdu::ReadByGroupTypeRsp { item_len: 6, data: &[1; 12] });
    assert_eq!(rt(Pdu::ReadReq { handle: 0x0102 }), [0x0A, 2, 1]);
    rt(Pdu::ReadRsp { value: &[] });
    rt(Pdu::ReadBlobReq { handle: 3, offset: 22 });
    rt(Pdu::ReadBlobRsp { value: &[1, 2, 3] });
    assert_eq!(rt(Pdu::WriteReq { handle: 5, value: &[1, 2] }), [0x12, 5, 0, 1, 2]);
    assert_eq!(rt(Pdu::WriteRsp), [0x13]);
    assert_eq!(rt(Pdu::WriteCmd { handle: 5, value: &[9] }), [0x52, 5, 0, 9]);
    rt(Pdu::PrepareWriteReq { handle: 5, offset: 4, value: &[1, 2] });
    rt(Pdu::PrepareWriteRsp { handle: 5, offset: 4, value: &[1, 2] });
    assert_eq!(rt(Pdu::ExecuteWriteReq { flags: 1 }), [0x18, 1]);
    assert_eq!(rt(Pdu::ExecuteWriteRsp), [0x19]);
    assert_eq!(rt(Pdu::Notification { handle: 7, value: &[1, 2, 3] }), [0x1B, 7, 0, 1, 2, 3]);
    assert_eq!(rt(Pdu::Indication { handle: 7, value: &[] }), [0x1D, 7, 0]);
    assert_eq!(rt(Pdu::Confirmation), [0x1E]);
}

#[test]
fn malformed_pdus() {
    assert_eq!(Pdu::parse(&[]), Err(Error::Short));
    assert_eq!(Pdu::parse(&[op::READ_REQ, 1]), Err(Error::Short));
    assert_eq!(Pdu::parse(&[op::READ_REQ, 1, 0, 0]), Err(Error::Invalid));
    assert_eq!(Pdu::parse(&[op::READ_BY_TYPE_REQ, 1, 0, 9, 0, 3, 0x28, 0]), Err(Error::Invalid), "a 3-byte uuid");
    assert_eq!(Pdu::parse(&[op::READ_BY_TYPE_REQ, 1, 0, 9, 0, 3]), Err(Error::Short), "a 1-byte uuid");
    assert_eq!(Pdu::parse(&[op::FIND_INFO_RSP, 3, 0]), Err(Error::Invalid));
    assert_eq!(Pdu::parse(&[op::CONFIRMATION, 0]), Err(Error::Invalid));
    assert_eq!(Pdu::parse(&[0x0E, 1, 2]), Err(Error::Unknown), "read multiple is not decoded");
    let mut small = [0u8; 3];
    assert_eq!(Pdu::ReadReq { handle: 1 }.encode(&mut small), Ok(3));
    assert_eq!(Pdu::WriteReq { handle: 1, value: &[1, 2] }.encode(&mut small), Err(Error::NoRoom));
}

#[test]
fn classes() {
    assert_eq!(class_of(op::READ_REQ), Some(Class::Request));
    assert_eq!(class_of(op::ERROR_RSP), Some(Class::Response));
    assert_eq!(class_of(op::WRITE_CMD), Some(Class::Command));
    assert_eq!(class_of(op::NOTIFICATION), Some(Class::Notification));
    assert_eq!(class_of(op::INDICATION), Some(Class::Indication));
    assert_eq!(class_of(op::CONFIRMATION), Some(Class::Confirmation));
    assert_eq!(class_of(0x0E), None);
}

#[test]
fn the_bearer_allows_one_request_and_matches_its_response() {
    let mut b = Bearer::new();
    let rd = Pdu::ReadReq { handle: 3 };
    assert_eq!(b.mtu(), DEFAULT_MTU);
    assert_eq!(b.sending(&rd, 3, 0), Ok(()));
    assert_eq!(b.sending(&rd, 3, 0), Err(Refusal::Busy));
    // A response of another kind is not the answer.
    assert_eq!(b.received(&Pdu::WriteRsp), Ok(false));
    assert_eq!(b.sending(&rd, 3, 0), Err(Refusal::Busy));
    // An error response names its request.
    assert_eq!(b.received(&Pdu::ErrorRsp { request: op::WRITE_REQ, handle: 0, code: 1 }), Ok(false));
    assert_eq!(b.received(&Pdu::ReadRsp { value: &[1] }), Ok(true));
    assert_eq!(b.sending(&rd, 3, 0), Ok(()), "free again");
    assert_eq!(b.received(&Pdu::ErrorRsp { request: op::READ_REQ, handle: 3, code: err::INVALID_HANDLE }), Ok(true));
    // Commands and notifications are unrestricted.
    assert_eq!(b.sending(&Pdu::WriteCmd { handle: 1, value: &[] }, 3, 0), Ok(()));
    assert_eq!(b.sending(&Pdu::Notification { handle: 1, value: &[] }, 3, 0), Ok(()));
}

#[test]
fn a_pdu_past_the_mtu_is_refused() {
    let mut b = Bearer::new();
    let w = Pdu::Notification { handle: 1, value: &[0; 30] };
    assert_eq!(b.sending(&w, 33, 0), Err(Refusal::TooBig));
    assert_eq!(b.sending(&w, 23, 0), Ok(()));
}

#[test]
fn one_indication_in_flight_until_confirmed() {
    let mut b = Bearer::new();
    let ind = Pdu::Indication { handle: 1, value: &[1] };
    assert_eq!(b.sending(&ind, 4, 0), Ok(()));
    assert_eq!(b.sending(&ind, 4, 0), Err(Refusal::Busy));
    assert_eq!(b.received(&Pdu::Confirmation), Ok(true));
    assert_eq!(b.sending(&ind, 4, 0), Ok(()));
    // A confirmation nobody asked for is dropped.
    let mut c = Bearer::new();
    assert_eq!(c.received(&Pdu::Confirmation), Ok(false));
}

#[test]
fn a_response_only_after_a_request_and_only_one_request_at_a_time() {
    let mut b = Bearer::new();
    assert_eq!(b.sending(&Pdu::ReadRsp { value: &[] }, 1, 0), Err(Refusal::NotAllowed));
    assert_eq!(b.received(&Pdu::ReadReq { handle: 1 }), Ok(true));
    assert_eq!(b.received(&Pdu::ReadReq { handle: 2 }), Err(()), "a second request while one is owed");
    assert_eq!(b.sending(&Pdu::ReadRsp { value: &[1] }, 2, 0), Ok(()));
    assert_eq!(b.sending(&Pdu::ReadRsp { value: &[1] }, 2, 0), Err(Refusal::NotAllowed), "answered once");
    assert_eq!(b.received(&Pdu::ReadReq { handle: 2 }), Ok(true));
}

#[test]
fn the_mtu_exchange_as_client_is_the_smaller_of_the_two_and_happens_once() {
    let mut b = Bearer::new();
    let req = Pdu::ExchangeMtuReq { mtu: LOCAL_MTU };
    assert_eq!(b.sending(&req, 3, 0), Ok(()));
    assert_eq!(b.received(&Pdu::ExchangeMtuRsp { mtu: 100 }), Ok(true));
    assert_eq!(b.mtu(), 100);
    assert_eq!(b.sending(&req, 3, 0), Err(Refusal::NotAllowed));
    let mut c = Bearer::new();
    assert_eq!(c.sending(&req, 3, 0), Ok(()));
    assert_eq!(c.received(&Pdu::ExchangeMtuRsp { mtu: 500 }), Ok(true));
    assert_eq!(c.mtu(), LOCAL_MTU, "never above what we can reassemble");
    let mut d = Bearer::new();
    assert_eq!(d.sending(&req, 3, 0), Ok(()));
    assert_eq!(d.received(&Pdu::ExchangeMtuRsp { mtu: 5 }), Ok(true));
    assert_eq!(d.mtu(), DEFAULT_MTU, "never below the default");
}

#[test]
fn the_mtu_exchange_as_server() {
    let mut b = Bearer::new();
    assert_eq!(b.received(&Pdu::ExchangeMtuReq { mtu: 185 }), Ok(true));
    assert_eq!(b.peer_mtu(185), Some(LOCAL_MTU));
    assert_eq!(b.mtu(), 185);
    assert_eq!(b.sending(&Pdu::ExchangeMtuRsp { mtu: LOCAL_MTU }, 3, 0), Ok(()));
    assert_eq!(b.received(&Pdu::ExchangeMtuReq { mtu: 185 }), Ok(true));
    assert_eq!(b.peer_mtu(185), None, "once per connection");
}

#[test]
fn a_transaction_that_never_finishes_expires() {
    let mut b = Bearer::new();
    assert!(!b.expired(1_000_000));
    b.sending(&Pdu::ReadReq { handle: 1 }, 3, 1000).unwrap();
    assert!(!b.expired(1000 + TRANSACTION_TIMEOUT_MS - 1));
    assert!(b.expired(1000 + TRANSACTION_TIMEOUT_MS));
    let mut c = Bearer::new();
    c.sending(&Pdu::Indication { handle: 1, value: &[] }, 3, 5).unwrap();
    assert!(c.expired(5 + TRANSACTION_TIMEOUT_MS));
}
