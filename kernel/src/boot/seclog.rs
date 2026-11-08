// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealer of the sealed security log (Kconfig `SEC_LOG`): the `seclog`
//! task runs the pass (`azos_seclog::pass`) over the record substrate's
//! security ring every second, at the log flusher's priority, outside the
//! real-time band (a seal on a TPM is three commands of milliseconds).
//!
//! The backend is what [`install_hw`] installed at boot (the TPM's indexes,
//! Kconfig `SEC_LOG_SEAL_TPM_NV`), never what Kconfig asked for: with none,
//! the seals are forward-only and the anchor record says why. This file is
//! the kernel's side of the pass: the TPM, the clock, the ring, the
//! producers' tallies, the console, and the orderly power-off's last seal.

use azos_drv_sys::{kerr, kprintln, timebase};
use azos_seclog::ack::Page;
use azos_seclog::chain::Sealer;
use azos_seclog::pass::{Config, Note, Pass};
use azos_seclog::{kind, Anchor, Backend, Hash, Reason, CLASSES, FLAG_HARDWARE, FLAG_UNDELETABLE};
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

fn publish(k: u16, payload: &[u8]) -> u64 {
    let Some(w) = azos_records::writer(azos_records::SOURCE_SECURITY) else { return 0 };
    let h = azos_records::Head {
        ts: timebase::now(),
        clock: azos_records::CLOCK_TIMEBASE,
        kind: k,
        len: payload.len() as u16,
        cpu: 0,
        flags: 0,
    };
    w.publish(&h, |p| p.bytes(0, payload))
}

struct KHw(&'static Hw);

impl azos_seclog::pass::Hw for KHw {
    fn increment(&mut self) -> Option<u64> {
        (self.0.increment)()
    }
    fn extend(&mut self, data: &Hash) -> bool {
        (self.0.extend)(data)
    }
    fn read(&mut self) -> Option<Hash> {
        (self.0.read)()
    }
}

struct KHost;

impl azos_seclog::pass::Host for KHost {
    fn now(&self) -> u64 {
        timebase::now()
    }
    fn tally(&self) -> ([u32; CLASSES], [u32; CLASSES], [(u32, u32); azos_seclog::Held::SUBJECTS]) {
        azos_decision::security_tally()
    }
    fn publish(&mut self, k: u16, payload: &[u8]) -> u64 {
        publish(k, payload)
    }
    fn sealed(&mut self, seal: &azos_seclog::Seal, hardware: bool) {
        kprintln!(
            "seclog: seal {} through {} counter {} nonce {:016x} head {} anchor {} {}",
            seal.count,
            seal.through,
            seal.counter,
            seal.nonce,
            HexHash(&seal.head),
            HexHash(&seal.anchor),
            if hardware { seal.backend.name() } else { "advisory" }
        );
    }
    fn note(&mut self, n: Note) {
        match n {
            Note::Refused => kerr!("[SECLOG] the TPM refused a seal: the seals of this boot are advisory from here"),
            Note::Diverged => kerr!("[SECLOG] the TPM's anchor is not the one this seal extended: something else extended the index"),
            Note::ClaimsLapped => kerr!("[SECLOG] logd's page lapped the sealer: a sink-loss claim was not read"),
            Note::UrgentBudget => {}
        }
    }
}

const CONFIG: Config = Config {
    hz: timebase::TIMER_FREQ,
    seal_s: azos_limits::SEC_LOG_SEAL_S as u64,
    urgent_s: azos_limits::SEC_LOG_SEAL_URGENT_S as u64,
    urgent_per_day: azos_limits::SEC_LOG_URGENT_PER_DAY as u32,
};

static STATE: azos_sync::kmutex::Mutex<Option<Pass<CLASS_LOG>>> = azos_sync::kmutex::Mutex::new(None);
/// A thermal critical trip is powering off: no seal, no wait.
static CRITICAL: AtomicBool = AtomicBool::new(false);

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

/// One pass under the state's lock: the seal's sequence number if one was
/// taken.
fn run(st: &mut Pass<CLASS_LOG>, force: bool) -> Option<u64> {
    let ring = ring()?;
    let mut hw = HW.get().map(KHw);
    st.run(&ring, SINK.get(), hw.as_mut().map(|h| h as &mut dyn azos_seclog::pass::Hw), &mut KHost, &CONFIG, force)
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
    *STATE.lock() = Some(Pass::new(Sealer::new(backend, anchor, nonce), flags & FLAG_UNDELETABLE, timebase::now()));
    loop {
        if let Some(st) = STATE.lock().as_mut() {
            run(st, false);
        }
        let end = timebase::now() + timebase::TIMER_FREQ;
        while timebase::now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

/// A thermal critical trip powers off: the seal and the wait for logd are
/// skipped, the shutdown goes on at once.
#[cfg(feature = "energy")]
pub(crate) fn critical() {
    CRITICAL.store(true, Ordering::Relaxed);
}

/// The orderly power-off: seal what the ring holds and give `logd` the rest
/// of the step's budget (Kconfig `POWER_OFF_STEP_TIMEOUT_MS`, and at most two
/// of its periods) to have the seal on the volume (its page's `next` past
/// it), so the boot ends sealed and its last seal is in the export. Not on a
/// thermal critical trip; no wait when logd's heartbeat stopped. Called
/// while the tasks still run, before the filesystems go down.
pub(crate) fn seal_at_power_off() {
    if !azos_records::SECURITY || CRITICAL.load(Ordering::Relaxed) {
        return;
    }
    let ms = |n: u64| n * timebase::TIMER_FREQ / 1000;
    let start = timebase::now();
    let budget_end = start + ms(azos_limits::POWER_OFF_STEP_TIMEOUT_MS as u64);
    // A pass in progress holds the state: wait for it within the budget.
    let mut g = loop {
        if let Some(g) = STATE.try_lock() {
            break g;
        }
        if timebase::now() >= budget_end {
            kerr!("[SECLOG] the sealer was busy past the power-off step's budget: no last seal");
            return;
        }
        azos_sched::task_block(azos_sched::WaitReason::Timer(timebase::now() + ms(1)));
    };
    let Some(st) = g.as_mut() else { return };
    let seq = run(st, true);
    let alive = timebase::now().wrapping_sub(st.sink_alive_at()) <= ms(2 * azos_limits::LOGD_POLL_MS as u64);
    drop(g);
    let (Some(seq), Some(page)) = (seq, SINK.get()) else { return };
    if !alive {
        kerr!("[SECLOG] logd's heartbeat stopped: the last seal is on the console and the TPM only");
        return;
    }
    let end = budget_end.min(start + ms(2 * azos_limits::LOGD_POLL_MS as u64));
    while page.next.load(Ordering::Acquire) <= seq && timebase::now() < end {
        let at = (timebase::now() + ms(10)).min(end);
        azos_sched::task_block(azos_sched::WaitReason::Timer(at));
    }
    if page.next.load(Ordering::Acquire) <= seq {
        kerr!("[SECLOG] logd did not write the last seal before the power-off: the console line carries it");
    }
}
