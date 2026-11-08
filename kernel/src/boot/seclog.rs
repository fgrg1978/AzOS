// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealer of the sealed security log (Kconfig `SEC_LOG`): the `seclog`
//! task folds every record of the record substrate's security ring into the
//! chain (`azos_seclog::chain::Sealer`) and seals it.
//!
//! The task runs at the log flusher's priority, outside the real-time band:
//! a seal on a TPM is two commands of milliseconds. Each pass reads the ring
//! from where the last one stopped. What it declares, in records that are
//! themselves in the chain: a record the ring overwrote before the pass read
//! it, or one a producer never finished (still pending three passes later),
//! with the classes the producers copied and the pass never saw (`loss`);
//! records the producers' rate cap held back, by class (`held`); and records
//! `logd` says on its page it never wrote, with the classes this pass folded
//! (`sink-loss`). It seals at its first pass, every `SEC_LOG_SEAL_S`,
//! `SEC_LOG_SEAL_URGENT_S` after a record of a high-value class, and at an
//! orderly power-off (after which it waits for `logd` to have the seal on
//! the volume); the console gets one `seclog: seal` line per seal.
//!
//! The backend is what [`install_hw`] installed at boot (the TPM's indexes,
//! Kconfig `SEC_LOG_SEAL_TPM_NV`), never what Kconfig asked for: with none,
//! the seals are forward-only and the anchor record says why. A seal on the
//! TPM increments the counter, extends the anchor with the seal's data and
//! reads the anchor back. An increment or an extend the TPM refuses ends the
//! hardware seals for the boot: that seal and the later ones are advisory.
//! A value read back that the extend does not give is the seal's anchor,
//! flagged diverged: something else extended the index.

use azos_drv_sys::{kerr, kprintln, timebase};
use azos_seclog::ack::Page;
use azos_seclog::chain::Sealer;
use azos_seclog::{kind, Anchor, Backend, Event, Hash, Held, Loss, Reason, CLASSES, FLAG_HARDWARE, FLAG_UNDELETABLE};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The hardware a boot seals to.
pub(crate) struct Hw {
    /// Increment the counter: its value after, `None` when not taken.
    pub increment: fn() -> Option<u64>,
    /// Extend the anchor with a seal's data; false when not taken.
    pub extend: fn(&Hash) -> bool,
    /// The anchor's value now; `None` when it cannot be read.
    pub read: fn() -> Option<Hash>,
}

azos_common::ro_hook! {
    static HW: &'static Hw;
}
azos_common::ro_hook! {
    static SINK: &'static Page;
}
/// The value and counter the hardware held at boot, and whether its anchor
/// index is undeletable, set with [`HW`].
static BOOT: azos_sync::SpinLock<(Hash, u64, bool)> = azos_sync::SpinLock::new(([0; 32], 0, false));
/// Why the boot seals forward-only, when it does.
static REASON: AtomicU8 =
    AtomicU8::new(if azos_limits::SEC_LOG_SEAL_FORWARD { Reason::Configured as u8 } else { Reason::NoTpm as u8 });
/// The hardware refused a commit this boot.
static HW_FAILED: AtomicBool = AtomicBool::new(false);

/// Passes a record may stay pending before the sealer declares it lost.
const PENDING_PASSES: u32 = 3;
/// Records whose class the sealer remembers, by sequence number: what a
/// `sink-loss` can name.
const CLASS_LOG: usize = 2 * azos_limits::SEC_LOG_ENTRIES as usize;

/// Install `hw`, which holds `anchor` and `counter` now (the caller read
/// them). Boot, once.
#[cfg(feature = "tpm")]
pub(crate) fn install_hw(hw: &'static Hw, anchor: Hash, counter: u64, undeletable: bool) {
    *BOOT.lock() = (anchor, counter, undeletable);
    REASON.store(Reason::Hardware as u8, Ordering::Relaxed);
    HW.set(hw);
}

/// The TPM was found and its indexes could not be used: why.
#[cfg(feature = "tpm")]
pub(crate) fn forward_because(r: Reason) {
    REASON.store(r as u8, Ordering::Relaxed);
}

/// Install the sink's page (`MemObj klog.ack`). Boot, once, before the task.
pub(crate) fn install_sink(page: &'static Page) {
    SINK.set(page);
}

struct HexHash<'a>(&'a Hash);

impl core::fmt::Display for HexHash<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

fn publish(k: u16, payload: &[u8]) {
    let Some(w) = azos_records::writer(azos_records::SOURCE_SECURITY) else { return };
    let h = azos_records::Head {
        ts: timebase::now(),
        clock: azos_records::CLOCK_TIMEBASE,
        kind: k,
        len: payload.len() as u16,
        cpu: 0,
        flags: 0,
    };
    w.publish(&h, |p| p.bytes(0, payload));
}

/// The sealer's state across passes.
struct State {
    s: Sealer,
    cursor: u64,
    pending: u32,
    /// Events folded, and declared lost, by class.
    folded: [u32; CLASSES],
    declared: [u32; CLASSES],
    held_seen: [u32; CLASSES],
    /// The class of each record folded, by sequence number.
    classes: [u8; CLASS_LOG],
    /// A loss the pass found, declared once the pass has read what there is.
    loss: Option<(u64, u64)>,
    sink_seen: u64,
    last_seal: u64,
    /// When a high-value record came that no seal covers yet.
    urgent_since: Option<u64>,
    sealed: bool,
    flags: u8,
}

static STATE: azos_sync::kmutex::Mutex<Option<State>> = azos_sync::kmutex::Mutex::new(None);

/// Create the task (with the security ring only).
pub(crate) fn create_task() {
    if !azos_records::SECURITY {
        return;
    }
    azos_sched::task_create("seclog", seclog_task, 0, azos_limits::LOG_FLUSHER_PRIORITY as u32);
}

fn nonce() -> u64 {
    let mut b = [0u8; 8];
    // An unseeded pool leaves the nonce to the clock: unique, not secret,
    // which is all a boot's identity needs.
    if !azos_crypto::entropy::fill(&mut b) {
        b = (timebase::now() ^ 0x9e37_79b9_7f4a_7c15).to_le_bytes();
    }
    u64::from_le_bytes(b)
}

/// The security ring (the shared region's once the task runs).
fn ring() -> Option<azos_records::record::Ring> {
    azos_records::reader(azos_records::SOURCE_SECURITY)
}

fn seclog_task(_: usize) {
    if ring().is_none() {
        return;
    }
    let hw = HW.get();
    let (anchor, counter, undeletable) = *BOOT.lock();
    let (backend, anchor, counter) = match hw {
        Some(_) => (Backend::TpmNv, anchor, counter),
        None => (Backend::Forward, [0; 32], 0),
    };
    let reason = Reason::from_u8(REASON.load(Ordering::Relaxed)).unwrap_or(Reason::NoTpm);
    let mut flags = if hw.is_some() { FLAG_HARDWARE } else { 0 };
    if hw.is_some() && undeletable {
        flags |= FLAG_UNDELETABLE;
    }
    let nonce = nonce();
    publish(kind::ANCHOR, &Anchor { backend, flags, reason, nonce, counter, value: anchor }.encode());
    kprintln!(
        "[SECLOG] sealing to {}{} every {} s, boot {:016x}, anchor {}, counter {}",
        backend.name(),
        if hw.is_some() { "" } else { " (advisory: no hardware holds the seals, the console carries them)" },
        azos_limits::SEC_LOG_SEAL_S,
        nonce,
        HexHash(&anchor),
        counter
    );
    if hw.is_none() {
        kprintln!("[SECLOG] forward-only because: {}", reason.name());
    }
    *STATE.lock() = Some(State {
        s: Sealer::new(backend, anchor, nonce),
        cursor: 0,
        pending: 0,
        folded: [0; CLASSES],
        declared: [0; CLASSES],
        held_seen: [0; CLASSES],
        classes: [0; CLASS_LOG],
        loss: None,
        sink_seen: 0,
        last_seal: timebase::now(),
        urgent_since: None,
        sealed: false,
        flags: flags & FLAG_UNDELETABLE,
    });
    loop {
        if let Some(st) = STATE.lock().as_mut() {
            st.pass(false);
        }
        let end = timebase::now() + timebase::TIMER_FREQ;
        while timebase::now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

impl State {
    /// Fold what the ring holds, declare what was lost or held, and seal if
    /// one is due (or `force`d). The seal's sequence number when one was
    /// taken.
    fn pass(&mut self, force: bool) -> Option<u64> {
        self.drain();
        self.declare();
        let now = timebase::now();
        let urgent =
            self.urgent_since.is_some_and(|t| now.wrapping_sub(t) >= azos_limits::SEC_LOG_SEAL_URGENT_S as u64 * timebase::TIMER_FREQ);
        let period = now.wrapping_sub(self.last_seal) >= azos_limits::SEC_LOG_SEAL_S as u64 * timebase::TIMER_FREQ;
        if self.s.unsealed() > 0 && (force || !self.sealed || urgent || period) {
            return Some(self.seal(now));
        }
        None
    }

    fn drain(&mut self) {
        let Some(ring) = ring() else { return };
        let (mut env, mut p) = (azos_records::record::Envelope::default(), [0u8; azos_seclog::PAYLOAD]);
        loop {
            match ring.read(&mut self.cursor, &mut env, &mut p) {
                azos_records::record::Read::Record => {
                    self.pending = 0;
                    let skipped = self.s.skip_to(env.seq);
                    self.note_loss(skipped);
                    if self.s.fold(&env, &p) {
                        let class = (env.kind == kind::EVENT).then(|| Event::decode(&p[..Event::LEN]).map(|e| e.class)).flatten();
                        self.classes[(env.seq % CLASS_LOG as u64) as usize] = class.map_or(0, |c| c as u8);
                        if let Some(c) = class {
                            self.folded[c as usize] += 1;
                            if c.high_value() && self.urgent_since.is_none() {
                                self.urgent_since = Some(timebase::now());
                            }
                        }
                    }
                }
                azos_records::record::Read::Pending if self.pending < PENDING_PASSES => {
                    self.pending += 1;
                    break;
                }
                azos_records::record::Read::Pending => {
                    self.pending = 0;
                    ring.skip(&mut self.cursor);
                    let skipped = self.s.skip_to(self.cursor);
                    self.note_loss(skipped);
                }
                azos_records::record::Read::Lost(_) | azos_records::record::Read::Stale => {
                    let skipped = self.s.skip_to(self.cursor);
                    self.note_loss(skipped);
                }
                azos_records::record::Read::Empty => break,
            }
        }
    }

    fn note_loss(&mut self, l: Option<(u64, u64)>) {
        if let Some((first, count)) = l {
            self.loss = Some(match self.loss {
                Some((f, c)) if f + c == first => (f, c + count),
                Some(prev) => {
                    self.publish_loss(prev);
                    (first, count)
                }
                None => (first, count),
            });
        }
    }

    /// The loss, with the classes the producers copied and no pass folded
    /// (an upper bound: a record copied while the pass ran counts here too).
    fn publish_loss(&mut self, (first, count): (u64, u64)) {
        let (copied, _) = azos_decision::security_tally();
        let mut by_class = [0u32; CLASSES];
        for c in 0..CLASSES {
            by_class[c] = copied[c].saturating_sub(self.folded[c]).saturating_sub(self.declared[c]);
            self.declared[c] += by_class[c];
        }
        publish(kind::LOSS, &Loss { first, count, by_class }.encode());
    }

    fn declare(&mut self) {
        if let Some(l) = self.loss.take() {
            self.publish_loss(l);
        }
        let (_, held) = azos_decision::security_tally();
        let mut delta = [0u32; CLASSES];
        for c in 0..CLASSES {
            delta[c] = held[c].wrapping_sub(self.held_seen[c]);
        }
        if delta.iter().any(|&d| d != 0) {
            self.held_seen = held;
            publish(kind::HELD, &Held { by_class: delta }.encode());
        }
        if let Some(page) = SINK.get() {
            let (oldest, next) = (ring().map_or(0, |r| r.oldest()), self.s.next());
            let mut claims = [None; azos_seclog::ack::CLAIMS];
            let mut n = 0;
            let mut lapped = false;
            self.sink_seen = page.read_claims(self.sink_seen, |c| match c {
                Some(r) if n < claims.len() => {
                    claims[n] = Some(r);
                    n += 1;
                }
                _ => lapped = true,
            });
            if lapped {
                kerr!("[SECLOG] logd's page lapped the sealer: a sink-loss claim was not read");
            }
            for c in &claims[..n] {
                match *c {
                    // Only what the ring has dropped and the pass has read.
                    Some((first, count)) => {
                        let end = first.saturating_add(count).min(oldest).min(next);
                        if end > first {
                            self.publish_sink_loss(first, end - first);
                        }
                    }
                    None => {}
                }
            }
        }
    }

    fn publish_sink_loss(&mut self, first: u64, count: u64) {
        let next = self.s.next();
        let mut by_class = [0u32; CLASSES];
        for seq in first..first + count {
            // Index 0: a record that is not an event, or one the log forgot.
            let known = seq + (CLASS_LOG as u64) >= next && seq < next;
            let c = if known { self.classes[(seq % CLASS_LOG as u64) as usize] } else { 0 };
            by_class[c as usize] += 1;
        }
        publish(kind::SINK_LOSS, &Loss { first, count, by_class }.encode());
    }

    fn seal(&mut self, now: u64) -> u64 {
        let hw = HW.get().filter(|_| !HW_FAILED.load(Ordering::Relaxed));
        let (hardware, counter, held) = match hw {
            Some(h) => match (h.increment)() {
                Some(c) => {
                    let ok = (h.extend)(&self.s.data(c));
                    if !ok {
                        HW_FAILED.store(true, Ordering::Relaxed);
                    }
                    (ok, c, if ok { (h.read)() } else { None })
                }
                None => {
                    HW_FAILED.store(true, Ordering::Relaxed);
                    (false, 0, None)
                }
            },
            None => (false, 0, None),
        };
        if hw.is_some() && !hardware {
            kerr!("[SECLOG] the TPM refused a seal: the seals of this boot are advisory from here");
        }
        let seal = self.s.seal(hardware, counter, held, self.flags);
        if seal.flags & azos_seclog::FLAG_DIVERGED != 0 {
            kerr!("[SECLOG] the TPM's anchor is not the one this seal extended: something else extended the index");
        }
        let seq = ring().map_or(0, |r| r.head());
        publish(kind::SEAL, &seal.encode());
        kprintln!(
            "seclog: seal {} through {} counter {} nonce {:016x} head {} anchor {} {}",
            seal.count,
            seal.through,
            seal.counter,
            seal.nonce,
            HexHash(&seal.head),
            HexHash(&seal.anchor),
            if hardware { self.s.backend().name() } else { "advisory" }
        );
        (self.last_seal, self.urgent_since, self.sealed) = (now, None, true);
        seq
    }
}

/// The orderly power-off: seal what the ring holds and give `logd` up to two
/// of its periods to have the seal on the volume (its page's `next` past it),
/// so the boot ends sealed and its last seal is in the export. Called while
/// the tasks still run, before the filesystems go down.
pub(crate) fn seal_at_power_off() {
    if !azos_records::SECURITY {
        return;
    }
    let seq = match STATE.lock().as_mut() {
        Some(st) => st.pass(true),
        None => return,
    };
    let (Some(seq), Some(page)) = (seq, SINK.get()) else { return };
    let end = timebase::now() + 2 * azos_limits::LOGD_POLL_MS as u64 * timebase::TIMER_FREQ / 1000;
    while page.next.load(Ordering::Acquire) <= seq && timebase::now() < end {
        let at = (timebase::now() + timebase::TIMER_FREQ / 100).min(end);
        azos_sched::task_block(azos_sched::WaitReason::Timer(at));
    }
    if page.next.load(Ordering::Acquire) <= seq {
        kerr!("[SECLOG] logd did not write the last seal before the power-off: the console line carries it");
    }
}
