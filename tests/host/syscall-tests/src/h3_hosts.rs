// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Spi`, `Can`, `Uart` and `Adc` interfaces the kernel
// hosts (`crates/core/syscall/src/devices.rs`, dispatched by
// `khost.rs::serve`). The adapters behind the servers are stand-ins that only
// record that they were reached (`shims/drivers/src/h3_ports.rs`; the
// adapters are tested against their drivers in `tests/host/drivers-tests`):
// what is asked here is the SERVER's contract, which op class each op
// demands (both directions), that a refusal is recorded and never reaches the
// adapter, that containment refuses the acting class only, that the badge
// names the resource, and that the real dispatch (an endpoint capability from
// `kernel_endpoint_cap`, the generated client, `khost::serve`) serves an
// authorized op once and never serves a `once_only` op twice.
//
// Included inside `mod handlers { .. }`, like `device_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::adc::{self, Record};
use azos_devif::can::{self, Frame};
use azos_devif::i2c::Bytes;
use azos_devif::spi;
use azos_devif::uart::{self, Chunk};
use azos_devif::{
    key, outcome, Adc, AdcCall, AdcClient, AdcIdl, Can, CanCall, CanClient, CanIdl, Cap, Out, Spi, SpiCall, SpiClient,
    SpiIdl, Uart, UartCall, UartClient, UartIdl,
};
use azos_drv_bus::h3_ports::{calls, can_rx_frame, on_pass, reset};
use azos_sched::{shim_refuse_spawns, shim_take_spawned, shim_wakes};
use std::rc::Rc;
use azos_idl::{IdlError, MsgDesc, OpInfo, Transport};
use azos_ipc::cap::targets::Shm;
use azos_ipc::memobj::{memobj_create_cap, memobj_page_phys_ref, memobj_release_cap, MemPerms, MemSpec};
use azos_rings::region::{RingStep, SpscSlots, RING_CONS_WAIT};
use azos_sched::futex::{shim_take_calls, Call, Key};
use crate::devices::{
    attach_client, plug_line, unplug_line, AdcServer, CanServer, PortClient, SerialLine, SpiServer, UartServer,
    LINE_PORT_BASE,
};
use crate::khost::Caller;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::Mutex;

/// Cap-store pool slots for this file (`SLOT`, and `SLOT + 1` for a second task); no other file in this crate binds 48 or 49.
const SLOT: usize = 48;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e48_0001);
/// `(kind code, reason code)` of every typed capability denial recorded.
static DENIALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn denials() -> Vec<(u8, u32)> {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The endpoint kind's recorder code and the reason a missing right records.
const ENDPOINT_CODE: u8 = azos_abi::cap::ty::ENDPOINT.denial_code();
const MISSING_PERMS: u32 = 3;

/// A caller with an empty table and nothing recorded. Dropping it releases
/// the task and the containment flag.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        // The queue regions a test made: released with their holder, or the
        // region table (shared by the whole suite) fills.
        azos_ipc::memobj::memobj_release_all(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

fn scene() -> Scene {
    reset(outcome::OK);
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let tid = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    set_cap_deny_typed_recorder(typed_recorder);
    Scene { tid }
}

fn caller(s: &Scene, badge: u32, rights: CapPerms) -> Caller {
    Caller { tid: s.tid, badge, rights }
}

fn bytes(b: &[u8]) -> Bytes {
    Bytes::from_slice(b)
}

/// One op of an interface: how to call it on a server, and the op class the
/// IDL says it needs.
type Row<'a, S> = (&'static str, CapPerms, &'a dyn Fn(&mut S) -> u32);

fn code<T>(o: Out<T>) -> u32 {
    o.code
}

/// Every op must demand exactly its class: with the class it reaches the
/// adapter (one call), without it it answers `DENIED`, records the refusal and
/// the adapter is not reached. Both directions, op by op: an op that started
/// demanding another class, or none, fails its own line.
fn rights_table<S>(rows: &[Row<'_, S>], server: impl Fn(&Scene, CapPerms) -> S, s: &Scene) {
    for &(name, need, call) in rows {
        // The class alone: served, and the adapter saw exactly this op.
        reset(outcome::OK);
        assert_eq!(call(&mut server(s, need)), outcome::OK, "{name} with {need:?}");
        assert_eq!(calls().len(), 1, "{name} reached the adapter once");
        // Every other class alone, and none: refused before the adapter.
        for other in [CapPerms::READ, CapPerms::WRITE, CapPerms::EXEC, CapPerms::NONE] {
            if other == need {
                continue;
            }
            reset(outcome::OK);
            DENIALS.lock().unwrap().clear();
            assert_eq!(call(&mut server(s, other)), outcome::DENIED, "{name} with only {other:?}");
            assert_eq!(calls(), vec![], "{name} with only {other:?} reached the adapter");
            assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS)], "{name}: the refusal is recorded once");
        }
    }
}

const SPI_BADGE: u32 = spi::badge(1, 3);

// ── Spi ───────────────────────────────────────────────────────────────────

/// **Every byte on the wire needs `WRITE`, the port's setup needs `EXEC`, and
/// there is no `READ` op**: `read` is a command byte and then a read, so it is
/// `WRITE` too (the IDL's own words).
///
/// **Canary.** Ask `READ` of `Spi::read` (or `WRITE` of `set_mode`): that op's
/// line fails.
#[test]
fn an_spi_endpoint_demands_the_op_class_the_idl_declares() {
    let _g = serial();
    let s = scene();
    let rows: [Row<'_, SpiServer>; 6] = [
        ("transfer", CapPerms::WRITE, &|x| code(x.transfer(bytes(&[1, 2])))),
        ("write", CapPerms::WRITE, &|x| code(x.write(bytes(&[1, 2])))),
        ("read", CapPerms::WRITE, &|x| code(x.read(0x9F, 3))),
        ("hold_cs", CapPerms::WRITE, &|x| code(x.hold_cs(true))),
        ("set_mode", CapPerms::EXEC, &|x| code(x.set_mode(3))),
        ("set_speed", CapPerms::EXEC, &|x| code(x.set_speed(1_000_000))),
    ];
    rights_table(&rows, |s, c| SpiServer(caller(s, SPI_BADGE, c)), &s);
}

/// The adapter is told the chip select the BADGE names and the arguments the
/// caller sent: a capability for the flash on chip select 3 reaches nothing
/// else, and the port, not the caller, picks the bus.
///
/// **Canary.** Read the bus from the argument instead of the badge: the
/// resource column changes.
#[test]
fn the_spi_adapter_gets_the_chip_select_from_the_badge() {
    let _g = serial();
    let s = scene();
    let mut x = SpiServer(caller(&s, SPI_BADGE, CapPerms::ALL));
    assert_eq!(x.transfer(bytes(&[9, 8, 7])), Out::ok(bytes(&[9, 8, 7])));
    assert_eq!(x.set_speed(2_000_000), Out::ok(()));
    assert_eq!(calls(), vec![("spi.transfer", SPI_BADGE, 3), ("spi.speed", SPI_BADGE, 2_000_000)]);
}

/// A bus that does not answer is `FAULT` and a missing device `NO_RESOURCE`:
/// the adapter's outcome travels back unchanged.
#[test]
fn an_adapter_refusal_is_the_servers_answer() {
    let _g = serial();
    let s = scene();
    let mut x = SpiServer(caller(&s, SPI_BADGE, CapPerms::ALL));
    for armed in [outcome::FAULT, outcome::NO_RESOURCE, outcome::UNSUPPORTED] {
        reset(armed);
        assert_eq!(x.transfer(bytes(&[1])), Out::err(armed));
        assert_eq!(x.set_mode(1), Out::err(armed));
    }
}

/// Containment (brain-triggered degraded mode) refuses the acting class (`WRITE`: every SPI byte),
/// leaves `EXEC` and the bus-observing ops of other interfaces alone, and
/// records nothing: a holder contained is the safety system working.
///
/// **Canary.** Ignore containment in `Caller::allows`: the contained transfer
/// reaches the adapter.
#[test]
fn containment_refuses_spi_traffic_but_not_its_setup_and_records_nothing() {
    let _g = serial();
    let s = scene();
    let mut x = SpiServer(caller(&s, SPI_BADGE, CapPerms::ALL));
    azos_ipc::cap::degraded_set(true);
    let t = x.transfer(bytes(&[1]));
    let m = x.set_mode(0);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(t, Out::err(outcome::DENIED));
    assert_eq!(m, Out::ok(()));
    assert_eq!(calls(), vec![("spi.mode", SPI_BADGE, 0)]);
    assert_eq!(denials(), vec![]);
}

// ── Can ───────────────────────────────────────────────────────────────────

fn frame() -> Frame {
    Frame::new(0x123, 0, &[1, 2, 3])
}

/// `READ` receives and observes the state, `WRITE` transmits, `EXEC` retunes
/// the bus.
///
/// **Canary.** Ask `EXEC` of `recv` (or `READ` of `send`): that line fails.
#[test]
fn a_can_endpoint_demands_the_op_class_the_idl_declares() {
    let _g = serial();
    let s = scene();
    let rows: [Row<'_, CanServer>; 7] = [
        ("send", CapPerms::WRITE, &|x| code(x.send(frame()))),
        ("recv", CapPerms::READ, &|x| code(x.recv())),
        ("state", CapPerms::READ, &|x| code(x.state())),
        ("add_filter", CapPerms::EXEC, &|x| code(x.add_filter(0x100, 0x700))),
        ("clear_filters", CapPerms::EXEC, &|x| code(x.clear_filters())),
        ("set_bitrate", CapPerms::EXEC, &|x| code(x.set_bitrate(250_000))),
        ("recover", CapPerms::EXEC, &|x| code(x.recover())),
    ];
    rights_table(&rows, |s, c| CanServer(caller(s, 0, c)), &s);
}

/// The values travel both ways, and the board has one controller: another
/// badge is `NO_RESOURCE` after the class check and before the adapter.
///
/// **Canary.** Drop the badge check: `can.1` reaches the controller.
#[test]
fn a_can_server_carries_frames_and_names_its_one_controller() {
    let _g = serial();
    let s = scene();
    let mut x = CanServer(caller(&s, 0, CapPerms::ALL));
    assert_eq!(x.send(frame()), Out::ok(()));
    assert_eq!(x.recv(), Out::ok(can_rx_frame()));
    assert_eq!(x.state(), Out::ok(can::STATE_ACTIVE));
    assert_eq!(calls(), vec![("can.send", 0, 0x123), ("can.recv", 0, 0), ("can.state", 0, 0)]);

    reset(outcome::OK);
    let mut other = CanServer(caller(&s, 1, CapPerms::ALL));
    assert_eq!(other.send(frame()), Out::err(outcome::NO_RESOURCE));
    assert_eq!(other.recv(), Out::err(outcome::NO_RESOURCE));
    assert_eq!(other.recover(), Out::err(outcome::NO_RESOURCE));
    assert_eq!(calls(), vec![]);
    let ro = CanServer(caller(&s, 1, CapPerms::NONE));
    assert_eq!(ro.state(), Out::err(outcome::DENIED), "the class is checked before the badge");
}

/// A frame on the bus is acting (`WRITE`, refused while contained); listening
/// and retuning are not.
///
/// **Canary.** Gate `send` on `EXEC`: the contained send reaches the adapter.
#[test]
fn containment_refuses_a_can_frame_but_not_listening() {
    let _g = serial();
    let s = scene();
    let mut x = CanServer(caller(&s, 0, CapPerms::ALL));
    azos_ipc::cap::degraded_set(true);
    let sent = x.send(frame());
    let got = x.recv();
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sent, Out::err(outcome::DENIED));
    assert_eq!(got, Out::ok(can_rx_frame()));
    assert_eq!(calls(), vec![("can.recv", 0, 0)]);
    assert_eq!(denials(), vec![]);
}

// ── The real dispatch ─────────────────────────────────────────────────────

/// The far end of a client: a real endpoint capability minted for the task
/// (`kernel_endpoint_cap`, what a topology row grants), the caller read back
/// from the table (`khost::caller`), the request decoded by `khost::serve`.
/// It applies the transport's retry rule from the op table, as a retrying
/// transport does: a request whose reply is LOST is sent again only when its
/// op is `retry_safe` (`idempotent`).
struct Wire {
    ops: &'static [OpInfo],
    key: u16,
    ep: u32,
    tid: u32,
    /// Replies to drop, from the front: the request is delivered and served,
    /// the answer never arrives.
    lose: Cell<u32>,
    /// Requests delivered to the server.
    delivered: Cell<u32>,
}

impl Wire {
    fn new(s: &Scene, ops: &'static [OpInfo], key: u16, rights: CapPerms, badge: u32) -> Wire {
        let cap = azos_ipc::endpoint::kernel_endpoint_cap(s.tid, rights, key, badge).expect("grant");
        Wire { ops, key, ep: cap.raw().0, tid: s.tid, lose: Cell::new(0), delivered: Cell::new(0) }
    }

    fn serve_once(&self, msg: &mut MsgDesc) {
        let who = crate::khost::caller(self.tid, self.ep).expect("the capability resolves");
        let req = *msg;
        self.delivered.set(self.delivered.get() + 1);
        crate::khost::serve(self.key, &who, &req, msg);
    }
}

impl Transport for &Wire {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        // The op number is the header word's low 16 bits, counted from 1.
        let op = (msg.words[0] & 0xFFFF) as usize;
        let retry_safe = self.ops[op - 1].retry_safe();
        let req = *msg;
        loop {
            self.serve_once(msg);
            if self.lose.get() == 0 {
                return Ok(());
            }
            self.lose.set(self.lose.get() - 1);
            if !retry_safe {
                return Err(IdlError::NoConnection);
            }
            *msg = req;
        }
    }
}

/// **An authorized op is served once, through the capability, the generated
/// client and `khost::serve`**: the badge the capability carries is the
/// resource the adapter is told, and the reply carries the value back.
///
/// **Canary.** Route `key::SPI` to the `Can` arm (or drop the arm): the status
/// word is a bad-interface error and the adapter is not reached.
#[test]
fn an_authorized_spi_and_can_op_is_served_through_the_real_dispatch() {
    let _g = serial();
    let s = scene();
    let spi_w = Wire::new(&s, &SpiIdl::OPS, key::SPI, CapPerms::WRITE, SPI_BADGE);
    let mut c = SpiClient::new(&spi_w);
    assert_eq!(c.transfer(bytes(&[5, 6])).unwrap(), Out::ok(bytes(&[5, 6])));
    let can_w = Wire::new(&s, &CanIdl::OPS, key::CAN, CapPerms::READ, 0);
    let mut c = CanClient::new(&can_w);
    assert_eq!(c.recv().unwrap(), Out::ok(can_rx_frame()));
    assert_eq!(calls(), vec![("spi.transfer", SPI_BADGE, 2), ("can.recv", 0, 0)]);
    assert_eq!((spi_w.delivered.get(), can_w.delivered.get()), (1, 1));
}

/// **A missing right is refused through the same path**: the capability
/// carries `READ` only, the client asks for `send`, the answer is `DENIED`,
/// the refusal is recorded and the controller never sees the frame.
///
/// **Canary.** Skip `gate` in `CanServer::send`: the frame reaches the adapter.
#[test]
fn a_missing_right_is_refused_through_the_real_dispatch() {
    let _g = serial();
    let s = scene();
    let w = Wire::new(&s, &CanIdl::OPS, key::CAN, CapPerms::READ, 0);
    let mut c = CanClient::new(&w);
    assert_eq!(c.send(frame()).unwrap().code, outcome::DENIED);
    assert_eq!(c.state().unwrap(), Out::ok(can::STATE_ACTIVE), "the right it holds is served");
    assert_eq!(calls(), vec![("can.state", 0, 0)]);
    assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS)]);
}

/// **A `once_only` op is not retried**: the transfer is delivered and the reply
/// is lost; the transport (which retries only what the op table calls
/// `retry_safe`) reports the loss instead of clocking the bytes into the chip
/// a second time. The idempotent op next to it, same loss, IS served again.
/// A `FAULT` answer is an answer: it is not retried either.
///
/// **Canary.** Drop `#[once_only]` from `Spi::transfer` (the table then says
/// retry-safe): the adapter sees two transfers.
#[test]
fn a_once_only_op_is_not_retried_and_an_idempotent_one_is() {
    let _g = serial();
    let s = scene();
    let w = Wire::new(&s, &SpiIdl::OPS, key::SPI, CapPerms::ALL, SPI_BADGE);
    let mut c = SpiClient::new(&w);

    w.lose.set(1);
    assert!(c.transfer(bytes(&[0xDE, 0xAD])).is_err(), "the lost reply is reported");
    assert_eq!(w.delivered.get(), 1, "delivered once, never sent again");
    assert_eq!(calls(), vec![("spi.transfer", SPI_BADGE, 2)], "the bytes were clocked out once");

    reset(outcome::OK);
    w.delivered.set(0);
    w.lose.set(1);
    assert_eq!(c.set_mode(2).unwrap(), Out::ok(()));
    assert_eq!(w.delivered.get(), 2, "an idempotent op is sent again");

    reset(outcome::FAULT);
    w.delivered.set(0);
    assert_eq!(c.write(bytes(&[1])).unwrap(), Out::err(outcome::FAULT));
    assert_eq!(w.delivered.get(), 1, "a FAULT is an answer, not a loss");
    assert_eq!(calls(), vec![("spi.write", SPI_BADGE, 1)]);

    let cw = Wire::new(&s, &CanIdl::OPS, key::CAN, CapPerms::WRITE, 0);
    reset(outcome::OK);
    cw.lose.set(1);
    assert!(CanClient::new(&cw).send(frame()).is_err());
    assert_eq!((cw.delivered.get(), calls()), (1, vec![("can.send", 0, 0x123)]), "a frame is on the bus once");
}

// ── Queues: Uart and Adc ──────────────────────────────────────────────────

/// A queue region the client made: a zero-filled, physically contiguous,
/// read-write region (a zero region is an empty ring). The handle carries
/// every right; `r` is the packed reference the capability stores.
fn make_queue(s: &Scene) -> (u32, u32) {
    let cap = memobj_create_cap(s.tid, 1, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    let r = azos_ipc::cap_store::get(s.tid, cap, CapPerms::READ).expect("the capability resolves");
    (cap.raw().0, r)
}

/// Another handle on region `r` carrying only `perms` (the attenuated copy
/// a client moves).
fn attenuated(s: &Scene, r: u32, perms: CapPerms) -> u32 {
    azos_ipc::cap::objref::grant_packed::<Shm>(s.tid, perms, r).expect("a handle").raw().0
}

/// The slots a page of `W`-word slots holds, counted here and not asked of
/// the server: the largest power of two that fits after the 256-byte header.
fn page_slots<const W: usize>() -> u32 {
    let room = (azos_arch::PAGE_SIZE - 256) / (W * 8);
    let mut n = 1usize;
    while n * 2 <= room {
        n *= 2;
    }
    n as u32
}

/// The test's view of the ring in region `r`.
fn ring<const W: usize>(r: u32) -> SpscSlots<W> {
    let phys = memobj_page_phys_ref(r, 0).expect("live").expect("a page");
    SpscSlots { base: azos_mm::addr::phys_to_virt(phys), cap: page_slots::<W>() }
}

fn pop_record(r: u32) -> Option<Record> {
    let mut w = [0u64; 2];
    match ring::<2>(r).try_pop(&mut w) {
        RingStep::Blocked => None,
        _ => {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&w[0].to_le_bytes());
            b[8..].copy_from_slice(&w[1].to_le_bytes());
            Some(Record::decode(&b))
        }
    }
}

fn pop_chunk(r: u32) -> Option<Chunk> {
    let mut w = [0u64; 5];
    match ring::<5>(r).try_pop(&mut w) {
        RingStep::Blocked => None,
        _ => {
            let mut b = [0u8; uart::CHUNK_BYTES];
            for (i, x) in w.iter().enumerate() {
                b[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
            }
            Chunk::decode(&b)
        }
    }
}

fn push_chunk(r: u32, c: &Chunk) {
    let b = c.encode();
    let w: [u64; 5] = core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    assert_ne!(ring::<5>(r).try_push(&w), RingStep::Blocked);
}

const UART_BADGE: u32 = azos_drv_bus::h3_ports::BRIDGE_PORT;
const NEVER_NS: u64 = 1_000_000;

/// The pump's pass as the kernel task runs it.
fn pump(now_ns: u64) -> Option<u64> {
    crate::devices::pump(now_ns, NEVER_NS)
}

/// The bridge and every ADC channel are statics of the kernel: leave them idle.
fn idle_devices(s: &Scene) {
    let mut u = UartServer(caller(s, UART_BADGE, CapPerms::ALL));
    let _ = u.detach();
    unplug_line(LINE_PORT_BASE);
    for ch in 0..adc::CHANNELS {
        let mut a = AdcServer(caller(s, ch, CapPerms::ALL));
        let _ = a.stop_batch();
    }
    reset(outcome::OK);
    shim_take_calls();
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn queue_scene() -> Scene {
    let s = scene();
    idle_devices(&s);
    s
}

/// **Which interfaces may carry capability entries**: the two whose ops take a
/// queue, the `Vm` interface, whose ops attach a memory object and a port, and
/// `Display`, whose ops attach a band and a vsync port, `MemCtl`, whose ops
/// name a memory object, `Keys`, whose `sign` works in one, and `Sound`, whose
/// `open` takes a stream's two queues and its arena.
/// The kernel-hosted call path refuses a request with capability entries for
/// every other interface (`ipc_v2::call_kernel_hosted` asks this).
///
/// **Canary.** Return true for `key::GPIO`: the gpio line fails.
#[test]
fn only_uart_adc_vm_display_memctl_keys_and_sound_requests_may_carry_capability_entries() {
    for iface in azos_devif::IFACES {
        let want = iface.key == key::UART
            || iface.key == key::ADC
            || iface.key == key::VM
            || iface.key == key::DISPLAY
            || iface.key == key::MEMCTL
            || iface.key == key::KEYS
            || iface.key == key::SOUND;
        assert_eq!(crate::khost::takes_caps(iface.key), want, "{}", iface.name);
    }
    assert!(!crate::khost::takes_caps(0));
}

const ADC_BADGE: u32 = 2;

/// Every Uart op demands exactly its class; the allowed `attach` reaches the
/// adapter once with queues that resolve.
///
/// **Canary.** Ask `EXEC` of `detach` (or `WRITE` of `status`): that line fails.
#[test]
fn a_uart_endpoint_demands_the_op_class_the_idl_declares() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let rows: [Row<'_, UartServer>; 4] = [
        ("configure", CapPerms::EXEC, &|x| code(x.configure(115_200, 8, uart::PARITY_NONE, 1))),
        ("status", CapPerms::READ, &|x| code(x.status())),
        ("attach", CapPerms::WRITE, &|x| code(x.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)))),
        ("detach", CapPerms::WRITE, &|x| code(x.detach())),
    ];
    // `attach` leaves the bridge attached; `detach` is the last row.
    rights_table(&rows, |s, c| UartServer(caller(s, UART_BADGE, c)), &s);
}

/// Every Adc op demands exactly its class: the conversions and the batch
/// observe (`READ`), the shared rate is `EXEC`.
///
/// **Canary.** Ask `READ` of `set_rate`: that line fails.
#[test]
fn an_adc_endpoint_demands_the_op_class_the_idl_declares() {
    let _g = serial();
    let s = queue_scene();
    let (q, _) = make_queue(&s);
    let rows: [Row<'_, AdcServer>; 5] = [
        ("read", CapPerms::READ, &|x| code(x.read())),
        ("rate", CapPerms::READ, &|x| code(x.rate())),
        ("set_rate", CapPerms::EXEC, &|x| code(x.set_rate(250))),
        ("start_batch", CapPerms::READ, &|x| code(x.start_batch(Cap::from_raw(q), 4))),
        ("stop_batch", CapPerms::READ, &|x| code(x.stop_batch())),
    ];
    rights_table(&rows, |s, c| AdcServer(caller(s, ADC_BADGE, c)), &s);
}

/// **The attach is the queue's resolution**: each handle must name a region the
/// caller holds with the right the direction needs, big enough for a ring and
/// touchable by the kernel; whatever is wrong, the adapter is never reached and
/// the bridge stays free for the next client.
///
/// **Canary.** Skip the `rights.contains(need)` test in `QueueEnd::resolve`:
/// the read-only receive handle is accepted and the DENIED line fails.
#[test]
fn a_uart_attach_resolves_its_queues_before_the_adapter_sees_them() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, rx_r) = make_queue(&s);
    let (tx_h, tx_r) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    let attach = |u: &mut UartServer, rx: u32, tx: u32| u.attach(Cap::from_raw(rx), Cap::from_raw(tx));

    assert_eq!(attach(&mut u, 0xDEAD, tx_h), Out::err(outcome::BAD_ARGUMENT), "a handle the table does not hold");
    let ep = azos_ipc::endpoint::kernel_endpoint_cap(s.tid, CapPerms::ALL, key::UART, 1).expect("an endpoint").raw().0;
    assert_eq!(attach(&mut u, rx_h, ep), Out::err(outcome::BAD_ARGUMENT), "a handle that is not a region");
    assert_eq!(attach(&mut u, rx_h, rx_h), Out::err(outcome::BAD_ARGUMENT), "one ring cannot be both directions");
    let rx_read_only = attenuated(&s, rx_r, CapPerms::READ);
    assert_eq!(attach(&mut u, rx_read_only, tx_h), Out::err(outcome::DENIED), "the kernel fills the receive queue: WRITE");
    assert_eq!(denials(), vec![(azos_abi::cap::ty::SHM.denial_code(), MISSING_PERMS)], "and the refusal is recorded");
    let tx_write_only = attenuated(&s, tx_r, CapPerms::WRITE);
    assert_eq!(attach(&mut u, rx_h, tx_write_only), Out::err(outcome::DENIED), "the kernel drains the transmit queue: READ");
    assert_eq!(calls(), vec![], "nothing above reached the adapter");

    // A region the kernel may not write (read-only) is refused even through a
    // handle that carries WRITE: the capability is not the region's mode.
    let ro = memobj_create_cap(s.tid, 1, &MemSpec::contig(MemPerms::ReadOnly, false)).expect("a region");
    let ro_r = azos_ipc::cap_store::get(s.tid, ro, CapPerms::READ).expect("resolves");
    let ro_write = attenuated(&s, ro_r, CapPerms::WRITE);
    assert_eq!(attach(&mut u, ro_write, tx_h), Out::err(outcome::UNSUPPORTED));
    assert_eq!(calls(), vec![]);

    // The good pair, the attenuated copies a client moves, is served once and
    // the bridge is then busy.
    let (rx_wo, tx_ro) = (attenuated(&s, rx_r, CapPerms::WRITE), attenuated(&s, tx_r, CapPerms::READ));
    assert_eq!(attach(&mut u, rx_wo, tx_ro), Out::ok(()));
    assert_eq!(calls(), vec![("uart.attach", UART_BADGE, rx_wo)]);
    assert_eq!(attach(&mut u, rx_h, tx_h), Out::err(outcome::BUSY));

    // Another port has nothing behind it.
    let mut other = UartServer(caller(&s, 2, CapPerms::ALL));
    assert_eq!(attach(&mut other, rx_h, tx_h), Out::err(outcome::NO_RESOURCE));
}

/// **Bytes move on the rings, not in calls**: after the attach, one pass of the
/// pump pushes what the line received onto the receive ring and pops what the
/// client queued on the transmit ring to the line. The slot is the 40-byte
/// chunk, little-endian, as `Chunk::encode` has it; the pass answers when to
/// come back, and after the detach there is nothing to come back for.
///
/// **Canary.** Make `ChunkRx::push` a no-op: the receive ring stays empty.
#[test]
fn a_pass_of_the_pump_moves_chunks_both_ways_and_a_detach_ends_it() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, rx_r) = make_queue(&s);
    let (tx_h, tx_r) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(pump(10), None, "nothing attached, nothing to come back for");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    push_chunk(tx_r, &Chunk::new(b"AT\r\n", 0));

    assert_eq!(pump(1_000), Some(1_000 + NEVER_NS), "a polled line is looked at again after the poll period");
    assert_eq!(pop_chunk(rx_r), Some(Chunk::new(&[0xB0, UART_BADGE as u8], 0)), "the received chunk is on the ring");
    assert_eq!(pop_chunk(rx_r), None);
    assert_eq!(pop_chunk(tx_r), None, "the transmit chunk was taken off its ring");
    assert_eq!(calls(), vec![("uart.attach", UART_BADGE, rx_h), ("bridge.tx", UART_BADGE, 4)]);

    assert_eq!(u.detach(), Out::ok(()));
    assert_eq!(pump(2_000), None);
    assert_eq!(pop_chunk(rx_r), None, "a detached bridge pushes nothing");
}

/// A transmit slot the client wrote wrong (a length past the chunk) is consumed
/// and skipped, not clamped: the line gets the good chunk after it and nothing
/// of the bad one.
///
/// **Canary.** Clamp the length instead of refusing it (`Chunk::decode`): the
/// line is sent 32 bytes of the bad slot.
#[test]
fn a_wrong_transmit_slot_is_skipped_not_clamped() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, tx_r) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    let mut bad = [0u64; 5];
    bad[0] = 1000; // len, a word later flags: way past CHUNK_DATA
    assert_ne!(ring::<5>(tx_r).try_push(&bad), RingStep::Blocked);
    push_chunk(tx_r, &Chunk::new(b"ok", 0));
    pump(1);
    assert_eq!(calls().iter().filter(|c| c.0 == "bridge.tx").collect::<Vec<_>>(), vec![&("bridge.tx", UART_BADGE, 2)]);
}

/// **A queue whose region goes away ends its attachment**: the client frees the
/// receive region; the next pass cannot touch it (the packed reference is
/// stale), detaches the bridge and writes nothing anywhere, and the next client
/// can attach.
///
/// **Canary.** Cache the region's address at the attach: the pass writes into a
/// freed frame, and the final attach is `BUSY`.
#[test]
fn a_freed_queue_region_ends_the_attachment_and_nothing_is_written() {
    let _g = serial();
    let s = queue_scene();
    let cap_rx = memobj_create_cap(s.tid, 1, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    let (tx_h, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(cap_rx.raw().0), Cap::from_raw(tx_h)), Out::ok(()));
    azos_ipc::cap_store::with_table(s.tid, |t| memobj_release_cap(s.tid, t, cap_rx)).expect("table").expect("freed");
    assert_eq!(pump(1), None, "the attachment ended: nothing to come back for");
    let (rx2, _) = make_queue(&s);
    assert_eq!(u.attach(Cap::from_raw(rx2), Cap::from_raw(tx_h)), Out::ok(()), "the bridge is free again");
}

/// **The reader is woken when it said it may be asleep.** The client's wait flag
/// is set; the push that fills the first slot asks for the futex wake of the
/// ring's head word, keyed by (region, offset) as the client's wait is.
///
/// **Canary.** Drop the `notify_wake_kernel` call in `QueueEnd::push`: no wake.
#[test]
fn a_push_wakes_a_reader_that_announced_it_sleeps() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, rx_r) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    shim_take_calls();
    pump(1);
    assert_eq!(shim_take_calls(), vec![], "a reader that is awake is not woken");
    // The reader found the ring empty and announced it.
    let base = ring::<5>(rx_r).base;
    unsafe { (*((base + RING_CONS_WAIT) as *const core::sync::atomic::AtomicU32)).store(1, core::sync::atomic::Ordering::SeqCst) };
    pump(2);
    assert_eq!(
        shim_take_calls(),
        vec![Call { is_wait: false, key: Key::Shared { obj: rx_r, offset: 0 }, arg: 1, deadline: None }],
        "one wake, on the head word"
    );
}

// ── Adc batches ───────────────────────────────────────────────────────────

/// The stand-in converter runs 128 Hz: one period in nanoseconds.
const PERIOD_NS: u64 = 1_000_000_000 / 128;

/// **A batch is samples on a ring, paced by the clock**: the first sample is due
/// at the first pass, the next a period after it; a pass in between pushes
/// nothing and says when to come back; the batch of two ends by itself and the
/// pump has nothing left to wait for. The record is the 16-byte slot, with the
/// channel, the reading and the time the sample was taken.
///
/// **Canary.** Pace on the pass's own time (`now + period`) instead of the
/// batch's: the second sample's time column moves.
#[test]
fn an_adc_batch_fills_its_ring_on_the_clock_and_ends_by_itself() {
    let _g = serial();
    let s = queue_scene();
    let (q_h, q_r) = make_queue(&s);
    let mut a = AdcServer(caller(&s, ADC_BADGE, CapPerms::READ));
    assert_eq!(a.start_batch(Cap::from_raw(q_h), 2), Out::ok(()));
    assert_eq!(a.start_batch(Cap::from_raw(q_h), 2), Out::err(outcome::BUSY), "one batch per channel");

    let t0 = 5_000_000;
    assert_eq!(pump(t0), Some(t0 + PERIOD_NS), "the sample is taken and the next is due a period on");
    let r1 = pop_record(q_r).expect("the first sample");
    assert_eq!((r1.channel, r1.raw, r1.mv, r1.acq_ns, r1.flags), (2, 102, 7, t0, 0));
    assert_eq!(pump(t0 + PERIOD_NS / 2), Some(t0 + PERIOD_NS), "early: nothing pushed, same answer");
    assert_eq!(pop_record(q_r), None);
    assert_eq!(pump(t0 + PERIOD_NS), None, "the count ran out: the batch ended itself");
    let r2 = pop_record(q_r).expect("the second sample");
    assert_eq!(r2.acq_ns, t0 + PERIOD_NS);
    assert_eq!(pop_record(q_r), None);
    assert_eq!(a.stop_batch(), Out::ok(2), "the samples the ring took");
    // The channel is free for the next batch.
    assert_eq!(a.start_batch(Cap::from_raw(q_h), 1), Out::ok(()));
}

/// **A full ring loses samples and says so**: nobody reads, the ring fills, the
/// next sample is lost (counted by the batch), and the first record that fits
/// after the reader catches up carries the lost flag.
///
/// **Canary.** Make `RecordRing::push` answer `true` when the ring is full: the
/// flag never appears.
#[test]
fn a_full_sample_ring_drops_and_the_next_record_says_so() {
    let _g = serial();
    let s = queue_scene();
    let (q_h, q_r) = make_queue(&s);
    let mut a = AdcServer(caller(&s, ADC_BADGE, CapPerms::READ));
    assert_eq!(a.start_batch(Cap::from_raw(q_h), 0), Out::ok(()), "until stopped");
    let slots = page_slots::<2>() as u64;
    for k in 0..slots + 1 {
        pump(k * PERIOD_NS);
    }
    // Slots 0..slots are on the ring; the last pass found it full.
    let first = pop_record(q_r).expect("a record");
    assert_eq!((first.acq_ns, first.flags), (0, 0));
    pump((slots + 1) * PERIOD_NS);
    let mut last = first;
    while let Some(r) = pop_record(q_r) {
        last = r;
    }
    assert_eq!(last.acq_ns, (slots + 1) * PERIOD_NS);
    assert_eq!(last.flags, adc::RECORD_LOST, "the record after the gap says samples were lost");
    assert_eq!(a.stop_batch().code, outcome::OK);
}

/// A batch whose region goes away is stopped by the pass that finds out; the
/// channel is free again.
#[test]
fn a_batch_into_a_freed_region_stops() {
    let _g = serial();
    let s = queue_scene();
    let cap = memobj_create_cap(s.tid, 1, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    let mut a = AdcServer(caller(&s, ADC_BADGE, CapPerms::READ));
    assert_eq!(a.start_batch(Cap::from_raw(cap.raw().0), 0), Out::ok(()));
    azos_ipc::cap_store::with_table(s.tid, |t| memobj_release_cap(s.tid, t, cap)).expect("table").expect("freed");
    assert_eq!(pump(1), None);
    let (q2, _) = make_queue(&s);
    assert_eq!(a.start_batch(Cap::from_raw(q2), 0), Out::ok(()), "not BUSY: the dead batch was stopped");
}

/// The channel is the badge: another channel has its own batch, and a channel
/// the interface cannot name is `NO_RESOURCE` before any queue is looked at.
#[test]
fn each_adc_channel_has_its_own_batch_and_the_badge_is_bounded() {
    let _g = serial();
    let s = queue_scene();
    let (q0, r0) = make_queue(&s);
    let (q1, r1) = make_queue(&s);
    let mut a0 = AdcServer(caller(&s, 0, CapPerms::READ));
    let mut a1 = AdcServer(caller(&s, 1, CapPerms::READ));
    assert_eq!(a0.start_batch(Cap::from_raw(q0), 0), Out::ok(()));
    assert_eq!(a1.start_batch(Cap::from_raw(q1), 0), Out::ok(()), "channel 1 is not busy because channel 0 is");
    pump(7);
    assert_eq!(pop_record(r0).map(|r| r.channel), Some(0));
    assert_eq!(pop_record(r1).map(|r| r.channel), Some(1));
    let mut nobody = AdcServer(caller(&s, adc::CHANNELS, CapPerms::READ));
    assert_eq!(nobody.start_batch(Cap::from_raw(0xDEAD), 0), Out::err(outcome::NO_RESOURCE));
    assert_eq!(nobody.stop_batch(), Out::err(outcome::NO_RESOURCE));
}

// ── The real dispatch of the queue ops ────────────────────────────────────

/// **A queue op is served through the capability, the generated client and
/// `khost::serve`**: the request carries the handles as capability entries, the
/// server resolves them in the caller's table, and the batch then fills the
/// ring the client made. The register form carries no entries: `attach`
/// there is a malformed request, served as an error status, and nothing is
/// attached.
///
/// **Canary.** Resolve the handle in the callee's table instead of the
/// caller's (`who.tid`): `BAD_ARGUMENT`.
#[test]
fn queue_ops_are_served_through_the_real_dispatch_with_capability_entries() {
    let _g = serial();
    let s = queue_scene();
    let (q_h, q_r) = make_queue(&s);
    let w = Wire::new(&s, &AdcIdl::OPS, key::ADC, CapPerms::READ, ADC_BADGE);
    let mut c = AdcClient::new(&w);
    assert_eq!(c.start_batch(Cap::from_raw(q_h), 1).unwrap(), Out::ok(()));
    assert_eq!(w.delivered.get(), 1);
    pump(9);
    assert_eq!(pop_record(q_r).map(|r| (r.channel, r.acq_ns)), Some((2, 9)));
    assert_eq!(c.stop_batch().unwrap(), Out::ok(1));

    // The register form has no room for an entry.
    let who = caller(&s, UART_BADGE, CapPerms::ALL);
    let req = azos_idl::header(UartIdl::ID, UartIdl::LEVEL, UartIdl::OP_ATTACH);
    let regs = crate::khost::serve_regs(key::UART, &who, [req, 0, 0, 0]);
    assert_ne!(regs[0], azos_idl::STATUS_OK, "an attach with no capability entries is malformed");
    assert_eq!(calls().iter().filter(|c| c.0 == "uart.attach").count(), 0);
}

/// **`attach` is `once_only`**: its reply is lost, the transport reports it and
/// does not attach twice (which would answer `BUSY` to a client that in fact
/// succeeded and leave it believing the line is not its own).
///
/// **Canary.** Drop `#[once_only]` from `Uart::attach`: the adapter sees two
/// attaches.
#[test]
fn a_lost_attach_reply_is_not_retried() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let w = Wire::new(&s, &UartIdl::OPS, key::UART, CapPerms::WRITE, UART_BADGE);
    let mut c = UartClient::new(&w);
    w.lose.set(1);
    assert!(c.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)).is_err(), "the loss is reported");
    assert_eq!(w.delivered.get(), 1);
    assert_eq!(calls().iter().filter(|c| c.0 == "uart.attach").count(), 1, "attached once");
    assert_eq!(UartServer(caller(&s, UART_BADGE, CapPerms::READ)).status().code, outcome::OK);
}

/// **An attachment ends with the task that made it**: the client exits while
/// another task still holds its region; the bridge is released (the next
/// client can attach), the pump has nothing to come back for, and a batch of
/// the same task is stopped too. Another task's attachment is untouched.
///
/// **Canary.** Drop the `owner == tid` test (or the call in the kernel's exit
/// hook is the half this host test cannot see): the other task's batch dies.
#[test]
fn a_task_exit_ends_the_attachments_it_made_and_only_those() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let (q0, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    let mut mine = AdcServer(caller(&s, 0, CapPerms::READ));
    assert_eq!(mine.start_batch(Cap::from_raw(q0), 0), Out::ok(()));
    // A batch another task started on channel 1.
    let other_tid = s.tid + 0x1000;
    ipc_task_pool::shim_bind(other_tid, SLOT + 1);
    azos_ipc::cap_store::reset(other_tid);
    let cap = memobj_create_cap(other_tid, 1, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    let mut theirs = AdcServer(Caller { tid: other_tid, badge: 1, rights: CapPerms::READ });
    assert_eq!(theirs.start_batch(Cap::from_raw(cap.raw().0), 0), Out::ok(()));

    crate::devices::release_all(s.tid);
    assert_eq!(mine.start_batch(Cap::from_raw(q0), 0), Out::ok(()), "channel 0 is free again");
    assert_eq!(theirs.start_batch(Cap::from_raw(cap.raw().0), 0), Out::err(outcome::BUSY), "channel 1 is still the other task's");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "the bridge was released: not BUSY");

    crate::devices::release_all(s.tid);
    crate::devices::release_all(other_tid);
    assert_eq!(pump(2), None, "nothing is attached any more");
    azos_ipc::memobj::memobj_release_all(other_tid);
    ipc_task_pool::shim_kill(other_tid);
}

// ── The pump holds no lock while an adapter works ─────────────────────────

/// A hook that runs `f` once, the first time the adapter pass reaches it.
fn once(f: impl FnOnce() + 'static) -> Option<Box<dyn FnMut()>> {
    let mut f = Some(f);
    Some(Box::new(move || {
        if let Some(f) = f.take() {
            f();
        }
    }))
}

/// The adapters wait while they work (the bridge busy-waits on the
/// transmitter, the converter sleeps in the I2C queue), so a pass runs with
/// the host's lock RELEASED: another task's detach lands in the middle of it.
/// That the call returns at all is the first half (with the lock held across
/// the pass the detach spins forever); the second is that it STANDS: the pass
/// worked on a copy of the adapter, and putting the copy back would undo it.
///
/// **Canary.** Hold the `BRIDGE` lock across `port.pump` in `devices::pump`:
/// the test never returns. Publish the copy without the `gen` test: the
/// attach after it answers `BUSY`.
#[test]
fn a_detach_that_lands_during_a_bridge_pass_stands() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    let seen = Rc::new(Cell::new(u32::MAX));
    let (tid, seen2) = (s.tid, seen.clone());
    on_pass(once(move || {
        seen2.set(UartServer(Caller { tid, badge: UART_BADGE, rights: CapPerms::ALL }).detach().code);
    }));
    let next = pump(1);
    on_pass(None);
    assert_eq!(seen.get(), outcome::OK, "the detach was served while the pass ran");
    assert_eq!(next, None, "nothing is attached after it");
    assert_eq!(pump(2), None);
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "the pass did not put the attachment back");
}

/// The same for a converter's batch: a stop and a start on another channel
/// are served while channel 0's sample is being taken, and the stop stands.
///
/// **Canary.** As above, for `ADC` and `port.pump`; or publish the copy
/// without the `gen` test: channel 0's next `start_batch` answers `BUSY`.
#[test]
fn a_stop_that_lands_during_an_adc_pass_stands() {
    let _g = serial();
    let s = queue_scene();
    let (q0, _) = make_queue(&s);
    let (q1, _) = make_queue(&s);
    let mut ch0 = AdcServer(caller(&s, 0, CapPerms::READ));
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()));
    let seen = Rc::new(Cell::new((u32::MAX, u32::MAX)));
    let (tid, seen2) = (s.tid, seen.clone());
    on_pass(once(move || {
        let stop = AdcServer(Caller { tid, badge: 0, rights: CapPerms::READ }).stop_batch().code;
        let other = AdcServer(Caller { tid, badge: 1, rights: CapPerms::READ }).start_batch(Cap::from_raw(q1), 0).code;
        seen2.set((stop, other));
    }));
    let next = pump(1);
    on_pass(None);
    assert_eq!(seen.get(), (outcome::OK, outcome::OK), "both were served while the pass ran");
    assert_eq!(next, Some(1 + PERIOD_NS), "channel 1's batch is the one left to look at");
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()), "the stop stood: channel 0 is free, not BUSY");
}

/// A task that exits while a pass runs ends its attachments too, and the pass
/// does not put them back (the bridge's rings and the converter's batch would
/// stay held by a task that is gone).
///
/// **Canary.** Drop the `gen` bump from `end_bridge` or `end_batch`: the next
/// attach answers `BUSY`.
#[test]
fn a_task_exit_during_a_pass_ends_the_attachments() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let (q0, _) = make_queue(&s);
    let exit = {
        let tid = s.tid;
        move || crate::devices::release_all(tid)
    };
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    on_pass(once(exit.clone()));
    pump(1);
    on_pass(None);
    assert_eq!(pump(2), None, "nothing is attached after the exit");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "the bridge is free, not BUSY");

    idle_devices(&s);
    let mut ch0 = AdcServer(caller(&s, 0, CapPerms::READ));
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()));
    on_pass(once(exit));
    pump(3);
    on_pass(None);
    assert_eq!(pump(4), None, "nothing is attached after the exit");
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()), "the channel is free, not BUSY");
    idle_devices(&s);
}

// ── The pump task ─────────────────────────────────────────────────────────

/// Makes the scheduler refuse task creation for the test's length.
struct NoTasks;

impl NoTasks {
    fn new() -> NoTasks {
        shim_refuse_spawns(true);
        NoTasks
    }
}

impl Drop for NoTasks {
    fn drop(&mut self) {
        shim_refuse_spawns(false);
    }
}

/// The pump task is created by the first attach (nothing pays for it on a
/// machine that never attaches) and woken by the later ones, never created
/// twice.
///
/// **Canary.** Create the task in `kick_pump` on every call: the second
/// attach creates a second one; never wake it: the second attach wakes nobody.
#[test]
fn the_first_attach_creates_the_pump_task_and_later_ones_wake_it() {
    let _g = serial();
    let s = queue_scene();
    crate::devices::forget_pump_task();
    shim_take_spawned();
    shim_wakes();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let (q0, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    assert_eq!(shim_take_spawned(), vec!["dev-pump".to_string()], "the first attach created the task");
    assert_eq!(shim_wakes(), Vec::<u32>::new(), "a task just created needs no wake");
    let mut ch0 = AdcServer(caller(&s, 0, CapPerms::READ));
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()));
    assert_eq!(shim_take_spawned(), Vec::<String>::new(), "the second attach created nothing");
    assert!(!shim_wakes().is_empty(), "it woke the task instead");
    idle_devices(&s);
}

/// With no task to move the data an attach would never run: it is undone and
/// answers `NO_RESOURCE`, and a later attach (the pool has room again)
/// succeeds and creates the task.
///
/// **Canary.** Ignore the `false` from `kick_pump`: the attach answers OK and
/// the second attach below answers `BUSY`.
#[test]
fn an_attach_that_cannot_get_a_pump_task_is_undone() {
    let _g = serial();
    let s = queue_scene();
    crate::devices::forget_pump_task();
    shim_take_spawned();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let (q0, _) = make_queue(&s);
    let mut u = UartServer(caller(&s, UART_BADGE, CapPerms::ALL));
    let mut ch0 = AdcServer(caller(&s, 0, CapPerms::READ));
    {
        let _full = NoTasks::new();
        assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::NO_RESOURCE));
        assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::err(outcome::NO_RESOURCE));
    }
    assert_eq!(pump(1), None, "neither attachment survived");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "not BUSY");
    assert_eq!(ch0.start_batch(Cap::from_raw(q0), 0), Out::ok(()), "not BUSY");
    assert_eq!(shim_take_spawned(), vec!["dev-pump".to_string()]);
    idle_devices(&s);
}

// ── Plugged serial lines (the USB CDC-ACM port) ───────────────────────────

/// A stand-in for a hot-plugged line: it records what reached it, holds the
/// chunks it "received", and says who holds it. It is as strict as the real
/// one about being held twice (`BUSY`).
#[derive(Default)]
struct FakeLine {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    /// `Some(true)`: the kernel holds it; `Some(false)`: a client with queues.
    held: Option<bool>,
    received: VecDeque<Chunk>,
    sent: Vec<Vec<u8>>,
    configured: Vec<u32>,
    detaches: u32,
    /// Runs in the middle of a pass, with no table lock held.
    mid_pass: Option<Box<dyn FnMut() + Send>>,
    /// Runs inside an attach that is about to answer yes, with the line already
    /// held and no lock of the line or of the table held.
    mid_attach: Option<Box<dyn FnMut() + Send>>,
}

impl FakeLine {
    fn leak() -> &'static FakeLine {
        Box::leak(Box::default())
    }

    fn st(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SerialLine for FakeLine {
    fn configure(&self, baud: u32, _data_bits: u32, _parity: u32, _stop_bits: u32) -> Out<()> {
        self.st().configured.push(baud);
        Out::ok(())
    }

    fn attach(&self, _rx: Cap<uart::RxQueue>, _tx: Cap<uart::TxQueue>) -> Out<()> {
        let mut st = self.st();
        if st.held.is_some() {
            return Out::err(outcome::BUSY);
        }
        st.held = Some(false);
        let mid = st.mid_attach.take();
        drop(st);
        if let Some(mut f) = mid {
            f();
        }
        Out::ok(())
    }

    fn attach_kernel(&self) -> Out<()> {
        let mut st = self.st();
        if st.held.is_some() {
            return Out::err(outcome::BUSY);
        }
        st.held = Some(true);
        Out::ok(())
    }

    fn detach(&self) -> Out<()> {
        let mut st = self.st();
        st.held = None;
        st.detaches += 1;
        Out::ok(())
    }

    fn status(&self) -> Out<uart::Status> {
        Out::ok(uart::Status { rx_lost: 5, tx_lost: 7 })
    }

    fn pump(&self, rx: &mut dyn uart::ChunkSink, tx: &mut dyn uart::ChunkSource) -> usize {
        let mid = self.st().mid_pass.take();
        if let Some(mut f) = mid {
            f();
        }
        let mut st = self.st();
        if st.held.is_none() {
            return 0;
        }
        let mut moved = 0;
        while let Some(c) = st.received.pop_front() {
            if !rx.push(&c) {
                break;
            }
            moved += 1;
        }
        while let Some(c) = tx.pop() {
            st.sent.push(c.bytes().to_vec());
            moved += 1;
        }
        moved
    }
}

/// A kernel-side client of a port: what it is sent and what it has to send.
#[derive(Default)]
struct FakeClient {
    st: Mutex<(Vec<Vec<u8>>, VecDeque<Chunk>)>,
}

impl FakeClient {
    fn leak() -> &'static FakeClient {
        Box::leak(Box::default())
    }
}

impl PortClient for FakeClient {
    fn rx(&self, chunk: &Chunk) -> bool {
        self.st.lock().unwrap().0.push(chunk.bytes().to_vec());
        true
    }

    fn tx(&self) -> Option<Chunk> {
        self.st.lock().unwrap().1.pop_front()
    }

    fn lost(&self) -> u32 {
        3
    }
}

/// **A plugged line is a port of the table**: it gets the first plug port,
/// the one slot is taken once, the ops reach the line, the pump moves chunks
/// between the client's rings and the line both ways, and a detach ends it.
///
/// **Canary.** Serve a plug port from the bridge's slot (`slot_of` answers 0
/// for it): the configure and the attach reach the bridge's adapter, and
/// the line sees nothing.
#[test]
fn a_plugged_line_is_a_port_the_pump_moves_chunks_through() {
    let _g = serial();
    let s = queue_scene();
    let line = FakeLine::leak();
    let port = plug_line(line).expect("a free slot");
    assert_eq!(port, LINE_PORT_BASE);
    assert_eq!(plug_line(FakeLine::leak()), None, "the one plug slot is taken");
    let (rx_h, rx_r) = make_queue(&s);
    let (tx_h, tx_r) = make_queue(&s);
    let mut u = UartServer(caller(&s, port, CapPerms::ALL));

    assert_eq!(u.configure(115_200, 8, uart::PARITY_NONE, 1), Out::ok(()));
    assert_eq!(line.st().configured, vec![115_200]);
    assert_eq!(u.status(), Out::ok(uart::Status { rx_lost: 5, tx_lost: 7 }));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::BUSY));
    assert_eq!(calls(), vec![], "nothing reached the bridge's adapter");

    line.st().received.push_back(Chunk::new(b"hello", 0));
    push_chunk(tx_r, &Chunk::new(b"AT\r", 0));
    assert_eq!(pump(1_000), Some(1_000 + NEVER_NS), "a polled line is looked at again");
    assert_eq!(pop_chunk(rx_r), Some(Chunk::new(b"hello", 0)));
    assert_eq!(line.st().sent, vec![b"AT\r".to_vec()]);

    assert_eq!(u.detach(), Out::ok(()));
    assert_eq!(line.st().detaches, 1, "the line was told");
    assert_eq!(pump(2_000), None);
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "free again");
    idle_devices(&s);
}

/// **An unplug takes the line and its attachment with it**: the port answers
/// `NO_RESOURCE` like a port the board does not have, the pump has nothing to
/// come back for, and a device plugged in later is attached afresh (not
/// `BUSY` from the old client). An unplug that lands in the middle of a pass
/// stands: the pass does not put the attachment back.
///
/// **Canary.** Publish a pass's copy without the `gen` test, or keep the
/// slot's ends in `unplug_line`: the attach after the replug answers `BUSY`.
#[test]
fn an_unplug_ends_the_attachment_even_in_the_middle_of_a_pass() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let line = FakeLine::leak();
    let port = plug_line(line).unwrap();
    let mut u = UartServer(caller(&s, port, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));

    line.st().mid_pass = Some(Box::new(move || unplug_line(port)));
    assert_eq!(pump(1), None, "nothing is attached after the unplug");
    assert_eq!(u.status().code, outcome::NO_RESOURCE);
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::NO_RESOURCE));
    assert_eq!(u.configure(9600, 8, uart::PARITY_NONE, 1).code, outcome::NO_RESOURCE);

    let again = FakeLine::leak();
    assert_eq!(plug_line(again), Some(port), "the slot is free again");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "not BUSY");
    idle_devices(&s);
}

/// **An attach that loses to an unplug and a replug of the same line lets go of
/// it**: the line said yes, then the device went and came back (the class
/// driver reuses its object) before the attach could publish. The attach
/// answers `NO_RESOURCE` and the line is told to detach, so the new session
/// is not held by an attachment nobody owns (every later attach, the console's
/// among them, would answer `BUSY`). When what came back is a different line,
/// the old one is gone with its attachment and the new one is left alone.
///
/// **Canary.** Drop the `detach` on the stale path of `attach_slot`: the
/// line stays held, the detach count stays 0 and the next attach is `BUSY`.
#[test]
fn an_attach_that_loses_to_an_unplug_and_replug_of_the_same_line_lets_go() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let line = FakeLine::leak();
    let port = plug_line(line).unwrap();
    let mut u = UartServer(caller(&s, port, CapPerms::ALL));

    line.st().mid_attach = Some(Box::new(move || {
        unplug_line(port);
        assert_eq!(plug_line(line), Some(port));
    }));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::NO_RESOURCE));
    assert_eq!(line.st().held, None, "the line was told to let go");
    assert_eq!(line.st().detaches, 1);
    assert_eq!(pump(1), None, "nothing is attached");
    assert_eq!(attach_client(port, FakeClient::leak()), Out::ok(()), "the new session is not BUSY");
    assert_eq!(line.st().held, Some(true));
    unplug_line(port);

    // A different line in the slot afterwards: the old one is gone, the new
    // one is not ours to detach.
    let old = FakeLine::leak();
    let port = plug_line(old).unwrap();
    let new = FakeLine::leak();
    old.st().mid_attach = Some(Box::new(move || {
        unplug_line(port);
        assert_eq!(plug_line(new), Some(port));
    }));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::NO_RESOURCE));
    assert_eq!(new.st().detaches, 0, "the other line is left alone");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    assert_eq!(new.st().held, Some(false));
    unplug_line(port);
    idle_devices(&s);
}

/// **The kernel can hold a plugged port with a client of its own** (the USB
/// serial console): the chunks the line received go to the client and what the
/// client has goes to the line, a task cannot take the port meanwhile (`BUSY`)
/// nor end the kernel's hold (`REFUSED`), a task's exit leaves it alone, the
/// client's losses show in the port's status, and when the device goes the hold
/// goes with it. A port with no line plugged in, and the bridge's,
/// take no kernel client.
///
/// **Canary.** Let `UartServer::detach` end an attachment whatever its owner:
/// the `REFUSED` line fails.
#[test]
fn the_kernel_can_hold_a_plugged_port_and_a_task_cannot_end_that() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let client = FakeClient::leak();
    assert_eq!(attach_client(LINE_PORT_BASE, client), Out::err(outcome::NO_RESOURCE), "nothing plugged in");
    let line = FakeLine::leak();
    let port = plug_line(line).unwrap();
    assert_eq!(attach_client(UART_BADGE, client), Out::err(outcome::NO_RESOURCE), "the bridge has no kernel client");
    assert_eq!(attach_client(port, client), Out::ok(()));
    assert_eq!(line.st().held, Some(true));
    assert_eq!(attach_client(port, client), Out::err(outcome::BUSY));

    let mut u = UartServer(caller(&s, port, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::err(outcome::BUSY));
    assert_eq!(u.detach(), Out::err(outcome::REFUSED));
    crate::devices::release_all(s.tid);
    assert_eq!(line.st().held, Some(true), "a task's exit does not end the kernel's hold");

    line.st().received.push_back(Chunk::new(b"ls\r", 0));
    client.st.lock().unwrap().1.push_back(Chunk::new(b"# ", 0));
    assert_eq!(pump(1), Some(1 + NEVER_NS));
    assert_eq!(client.st.lock().unwrap().0, vec![b"ls\r".to_vec()]);
    assert_eq!(line.st().sent, vec![b"# ".to_vec()]);
    assert_eq!(u.status(), Out::ok(uart::Status { rx_lost: 5, tx_lost: 7 + 3 }), "the client's losses are the port's");

    // The device goes: the kernel's hold goes with it, and the next device's
    // port is a task's to take.
    unplug_line(port);
    assert_eq!(pump(2), None);
    let next = FakeLine::leak();
    assert_eq!(plug_line(next), Some(port));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()), "the port is a task's again");
    assert_eq!(next.st().held, Some(false));
    idle_devices(&s);
}

/// A task that exits ends its hold on a plugged port: the line is told and the
/// next client can attach.
///
/// **Canary.** Walk only the bridge's slot in `release_all`: the second attach
/// answers `BUSY`.
#[test]
fn a_task_exit_ends_its_hold_on_a_plugged_port() {
    let _g = serial();
    let s = queue_scene();
    let (rx_h, _) = make_queue(&s);
    let (tx_h, _) = make_queue(&s);
    let line = FakeLine::leak();
    let port = plug_line(line).unwrap();
    let mut u = UartServer(caller(&s, port, CapPerms::ALL));
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    crate::devices::release_all(s.tid);
    assert_eq!(line.st().held, None, "the line was told");
    assert_eq!(u.attach(Cap::from_raw(rx_h), Cap::from_raw(tx_h)), Out::ok(()));
    idle_devices(&s);
}
