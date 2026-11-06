// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The NIC queue pair (`azos_drv_api::net::NetQueue`) and the one doorbell
//! rule the table applies to every backend (`azos_drv_net::net_queue`).
//!
//! **What is real here.** The table (`net_queue.rs`, its USB slot used to
//! number a test NIC), the doorbell rule (`TxDoorbell`) and the Kconfig
//! bounds. **What is not.** The NIC: [`Wire`] is a queue pair that moves what
//! was posted to its receive side when, and only when, its doorbell rings.
//! A frame the rule forgets to announce is therefore a frame that never
//! arrives, which is what the loss row counts.

use crate::net_queue::{batch_begin, batch_end, flush, reap_rx, register_usb, submit, unregister_usb};
use azos_drv_api::net::{NetError, NetQueue, TxDoorbell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// One test at a time may hold the table's USB slot.
static TABLE: Mutex<()> = Mutex::new(());

/// The table's USB slot is given back when the test ends, red or not.
struct Registered;

impl Drop for Registered {
    fn drop(&mut self) {
        unregister_usb();
    }
}

/// A queue pair with a submission ring of `depth` frames: `post` fills it,
/// `ring` moves it to the receive side, `reap_rx` hands it up.
struct Wire {
    depth: usize,
    sq: Mutex<Vec<Vec<u8>>>,
    rx: Mutex<VecDeque<Vec<u8>>>,
    rings: AtomicUsize,
    delivered: AtomicUsize,
    /// Receive buffers handed back by `reap_rx` that no doorbell announced.
    rx_unannounced: AtomicUsize,
}

impl Wire {
    fn new(depth: usize) -> Wire {
        Wire { depth, sq: Mutex::new(Vec::new()), rx: Mutex::new(VecDeque::new()), rings: AtomicUsize::new(0), delivered: AtomicUsize::new(0), rx_unannounced: AtomicUsize::new(0) }
    }
}

impl NetQueue for Wire {
    fn is_ready(&self) -> bool {
        true
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 9]
    }
    fn post(&self, frame: &[u8]) -> Result<usize, NetError> {
        let mut sq = self.sq.lock().unwrap();
        if sq.len() >= self.depth {
            return Err(NetError::QueueFull);
        }
        sq.push(frame.to_vec());
        Ok(frame.len())
    }
    fn ring(&self) {
        self.rx_unannounced.store(0, Ordering::SeqCst);
        let mut sq = self.sq.lock().unwrap();
        if sq.is_empty() {
            return;
        }
        self.rings.fetch_add(1, Ordering::SeqCst);
        for f in sq.drain(..) {
            let n = self.delivered.fetch_add(1, Ordering::SeqCst) + 1;
            // Canary: the NIC loses every 100th frame it is given.
            if cfg!(feature = "net-queue-drop-canary") && n % 100 == 0 {
                continue;
            }
            self.rx.lock().unwrap().push_back(f);
        }
    }
    fn reap_rx(&self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
        let mut n = 0;
        while n < max {
            let Some(frame) = self.rx.lock().unwrap().pop_front() else { break };
            f(&frame);
            n += 1;
        }
        self.rx_unannounced.fetch_add(n, Ordering::SeqCst);
        n
    }
}

fn tagged(i: usize) -> [u8; 60] {
    let mut f = [0u8; 60];
    f[..8].copy_from_slice(&(i as u64).to_le_bytes());
    f
}

fn drain(nic: usize) -> Vec<u64> {
    let mut seen = Vec::new();
    while reap_rx(nic, 16, &mut |f| seen.push(u64::from_le_bytes(f[..8].try_into().unwrap()))) != 0 {}
    seen
}

/// **Discriminates (the loss row).** A thousand frames posted through the
/// table in bursts, each burst a batch, all arrive, in order, and a burst
/// costs a few doorbells, not one a frame; a frame that has to be re-posted
/// because the ring was full is not lost either. Canary: build with
/// `net-queue-drop-canary` (the NIC loses every 100th frame) and the count
/// falls to 990. Hand canary: drop the `ring` of `batch_end` and the tail of
/// every burst never arrives.
#[test]
fn every_frame_posted_through_the_table_arrives_in_order_with_few_doorbells() {
    static WIRE: std::sync::OnceLock<Wire> = std::sync::OnceLock::new();
    let _g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let wire = WIRE.get_or_init(|| Wire::new(azos_limits::NET_TX_BATCH_MAX as usize + 3));
    let nic = register_usb(wire).expect("a free number");
    let _slot = Registered;
    let mut seen = Vec::new();
    for burst in 0..10 {
        batch_begin(nic);
        for i in 0..100 {
            let f = tagged(burst * 100 + i);
            loop {
                match submit(nic, &f) {
                    Ok(_) => break,
                    Err(NetError::QueueFull) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
        }
        batch_end(nic);
        seen.extend(drain(nic));
    }
    assert_eq!(seen.len(), 1000, "the NIC lost {} of 1000 frames", 1000 - seen.len());
    assert!(seen.iter().copied().eq(0..1000), "every frame, once, in order");
    let rings = wire.rings.load(Ordering::SeqCst);
    let bound = azos_limits::NET_TX_BATCH_MAX as usize;
    assert!(rings <= 10 * (100usize.div_ceil(bound) + 1), "a doorbell per batch bound, not per frame: {rings}");
    assert!(rings < 1000 / 2, "{rings} doorbells for 1000 frames");
}

/// **Discriminates.** A frame posted outside a batch is announced at once (it
/// has no flush point coming); inside a batch it waits for the end; and
/// `flush` announces it without closing the batch. Canary: drop the
/// `depth == 0` arm of `TxDoorbell::posted` and the first assertion fails.
#[test]
fn a_lone_frame_rings_at_once_a_batched_one_at_the_end_and_flush_does_not_wait() {
    static WIRE: std::sync::OnceLock<Wire> = std::sync::OnceLock::new();
    let _g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let wire = WIRE.get_or_init(|| Wire::new(64));
    let nic = register_usb(wire).expect("a free number");
    let _slot = Registered;
    submit(nic, &tagged(1)).unwrap();
    assert_eq!(drain(nic), vec![1], "outside a batch the frame is on its way at once");
    assert_eq!(wire.rx_unannounced.load(Ordering::SeqCst), 0, "outside a batch the buffers a reap handed back are announced");
    batch_begin(nic);
    submit(nic, &tagged(2)).unwrap();
    assert!(drain(nic).is_empty(), "inside a batch it waits");
    flush(nic);
    assert_eq!(drain(nic), vec![2], "a flush point does not wait for the batch");
    assert_ne!(wire.rx_unannounced.load(Ordering::SeqCst), 0, "inside a batch the buffers wait for its end");
    submit(nic, &tagged(3)).unwrap();
    batch_end(nic);
    assert_eq!(wire.rx_unannounced.load(Ordering::SeqCst), 0, "the end of the batch announces them");
    assert_eq!(drain(nic), vec![3]);
}

/// **Discriminates.** A full submission ring is announced so the device can
/// free it, and the refused frame is `QueueFull`, not lost: after the ring
/// the same frame is accepted. Canary: drop the `QueueFull` arm of `submit`
/// and the ring stays full for good.
#[test]
fn a_full_ring_is_announced_and_the_refused_frame_goes_in_afterwards() {
    static WIRE: std::sync::OnceLock<Wire> = std::sync::OnceLock::new();
    let _g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let wire = WIRE.get_or_init(|| Wire::new(2));
    let nic = register_usb(wire).expect("a free number");
    let _slot = Registered;
    batch_begin(nic);
    submit(nic, &tagged(1)).unwrap();
    submit(nic, &tagged(2)).unwrap();
    assert_eq!(submit(nic, &tagged(3)), Err(NetError::QueueFull));
    assert_eq!(drain(nic), vec![1, 2], "the full ring was announced");
    assert_eq!(submit(nic, &tagged(3)), Ok(60));
    batch_end(nic);
    assert_eq!(drain(nic), vec![3]);
}

/// **Discriminates.** A registered USB NIC takes the first free number,
/// every call addressed to that number reaches it, a second registration is
/// refused, and once it is unregistered the number names nothing. Drop the
/// `BACKEND_USB` arm of `on_nic!`, or leave the table entry behind in
/// `unregister_usb`, and this fails.
#[test]
fn a_registered_usb_nic_is_reached_by_its_number_until_it_is_gone() {
    static WIRE: std::sync::OnceLock<Wire> = std::sync::OnceLock::new();
    let _g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let wire = WIRE.get_or_init(|| Wire::new(8));
    let before = crate::net_queue::count();
    let nic = register_usb(wire).expect("a free number");
    assert_eq!(nic, before, "the first free number: nothing already numbered moves");
    assert!(register_usb(wire).is_none(), "one USB NIC at a time");
    assert_eq!(crate::net_queue::count(), before + 1);
    assert_eq!(crate::net_queue::mac(nic), [2, 0, 0, 0, 0, 9]);
    assert!(!crate::net_queue::irq_driven(), "a polled NIC makes the poller run on its timer");
    unregister_usb();
    assert_eq!(crate::net_queue::count(), before);
    assert_eq!(submit(nic, &tagged(0)), Err(NetError::NotReady));
    assert_eq!(reap_rx(nic, 4, &mut |_| {}), 0);
    assert_eq!(crate::net_queue::mac(nic), [0u8; 6]);
    assert_eq!(register_usb(wire), Some(nic), "and it can come back");
    unregister_usb();
}

/// **Discriminates.** The rule itself. Outside a batch every frame rings;
/// inside one only the frame that reaches the bound does; `end` leaves nothing
/// pending; the canary mode rings every frame. Canary: drop the `depth == 0`
/// arm or the `pending >= bound` arm of `TxDoorbell::posted`.
#[test]
fn the_doorbell_rule_rings_outside_a_batch_and_at_the_bound_inside_one() {
    let db = TxDoorbell::new();
    assert!(db.posted(16), "no batch open: ring now");
    db.begin();
    assert!(db.batching());
    assert!(!db.posted(16), "batch open, 1 of 16: wait");
    for _ in 0..14 {
        assert!(!db.posted(16));
    }
    assert!(db.posted(16), "the 16th rings");
    assert!(!db.posted(16), "and the count starts again");
    db.begin();
    db.end();
    assert!(db.batching(), "batches nest");
    db.end();
    assert!(!db.batching());
    db.begin();
    db.set_every_frame(true);
    assert!(db.posted(16), "net-kick-per-frame: ring");
    assert!(!db.batching());
    db.set_every_frame(false);
    db.end();
}

/// **Pins the Kconfig relation build.rs enforces:** a batch fits in the
/// frames the TX ring holds (two descriptors per frame).
#[test]
fn the_batch_bound_fits_in_the_tx_ring() {
    assert!(azos_limits::NET_TX_BATCH_MAX >= 1);
    assert!(azos_limits::NET_TX_BATCH_MAX <= azos_limits::NET_VIRTIO_TXQ_SIZE / 2);
}
