// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealer of the sealed security log (Kconfig `SEC_LOG`): the `seclog`
//! task folds every record of the record substrate's security ring into the
//! chain (`azos_seclog::chain::Sealer`) and seals it.
//!
//! The task runs at the log flusher's priority, outside the real-time band:
//! a seal on a TPM is a command of milliseconds. Each pass reads the ring
//! from where the last one stopped; a record the ring overwrote before the
//! pass read it, or one a producer never finished (still pending three
//! passes later), is declared in a `loss` record, which is itself in the
//! chain. Every `SEC_LOG_SEAL_S`, if records came, it takes a seal: the head
//! goes to the backend, a `seal` record goes to the ring, and the console
//! gets one `seclog: seal` line with the head and the anchor in full.
//!
//! The backend is what [`install_hw`] installed at boot (the TPM's extend
//! index, Kconfig `SEC_LOG_SEAL_TPM_NV`), never what Kconfig asked for: with
//! none, the seals are forward-only and every record says they are advisory.
//! An extend the TPM refuses ends the hardware seals for the boot: that seal
//! and the later ones are advisory, and the next boot's anchor is the last
//! seal the TPM took, where the verifier links the two boots.

use azos_drv_sys::{kerr, kprintln, timebase};
use azos_seclog::chain::Sealer;
use azos_seclog::{kind, Anchor, Backend, Hash, Loss};
use core::sync::atomic::{AtomicBool, Ordering};

/// The hardware a boot seals to.
pub(crate) struct Hw {
    /// Commit a head; false when the hardware did not take it.
    pub extend: fn(&Hash) -> bool,
}

azos_common::ro_hook! {
    static HW: &'static Hw;
}
/// The value the hardware held at boot, set with [`HW`].
static BOOT_ANCHOR: azos_sync::SpinLock<Hash> = azos_sync::SpinLock::new([0; 32]);
/// The hardware refused a commit this boot.
static HW_FAILED: AtomicBool = AtomicBool::new(false);

/// Passes a record may stay pending before the sealer declares it lost.
const PENDING_PASSES: u32 = 3;

/// Install `hw`, which holds `anchor` now (the caller read it). Boot, once.
#[cfg(feature = "tpm")]
pub(crate) fn install_hw(hw: &'static Hw, anchor: Hash) {
    *BOOT_ANCHOR.lock() = anchor;
    HW.set(hw);
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

fn declare(loss: Option<Loss>) {
    if let Some(l) = loss {
        publish(kind::LOSS, &l.encode());
    }
}

/// Create the task (with the security ring only).
pub(crate) fn create_task() {
    if !azos_records::SECURITY {
        return;
    }
    azos_sched::task_create("seclog", seclog_task, 0, azos_limits::LOG_FLUSHER_PRIORITY as u32);
}

fn seclog_task(_: usize) {
    let Some(ring) = azos_records::reader(azos_records::SOURCE_SECURITY) else { return };
    let hw = HW.get();
    let (backend, anchor) = match hw {
        Some(_) => (Backend::TpmNv, *BOOT_ANCHOR.lock()),
        None => (Backend::Forward, [0; 32]),
    };
    publish(kind::ANCHOR, &Anchor { backend, hardware: hw.is_some(), value: anchor }.encode());
    kprintln!(
        "[SECLOG] sealing to {}{} every {} s, boot anchor {}",
        backend.name(),
        if hw.is_some() { "" } else { " (advisory: no hardware holds the seals, the console carries them)" },
        azos_limits::SEC_LOG_SEAL_S,
        HexHash(&anchor)
    );
    let mut s = Sealer::new(backend, anchor);
    let mut cursor = 0u64;
    let (mut env, mut p) = (azos_records::record::Envelope::default(), [0u8; azos_seclog::PAYLOAD]);
    let mut pending = 0u32;
    let period = azos_limits::SEC_LOG_SEAL_S as u64 * timebase::TIMER_FREQ;
    let mut last_seal = timebase::now();
    loop {
        loop {
            match ring.read(&mut cursor, &mut env, &mut p) {
                azos_records::record::Read::Record => {
                    pending = 0;
                    declare(s.skip_to(env.seq));
                    s.fold(&env, &p);
                }
                azos_records::record::Read::Pending if pending < PENDING_PASSES => {
                    pending += 1;
                    break;
                }
                azos_records::record::Read::Pending => {
                    pending = 0;
                    ring.skip(&mut cursor);
                    declare(s.skip_to(cursor));
                }
                azos_records::record::Read::Lost(_) | azos_records::record::Read::Stale => declare(s.skip_to(cursor)),
                azos_records::record::Read::Empty => break,
            }
        }
        let now = timebase::now();
        if s.unsealed() > 0 && now.wrapping_sub(last_seal) >= period {
            let head = s.head();
            let ok = match hw.filter(|_| !HW_FAILED.load(Ordering::Relaxed)) {
                Some(h) => (h.extend)(&head) || {
                    HW_FAILED.store(true, Ordering::Relaxed);
                    kerr!("[SECLOG] the {} refused a seal: the seals of this boot are advisory from here", backend.name());
                    false
                },
                None => false,
            };
            let seal = s.seal(ok);
            publish(kind::SEAL, &seal.encode());
            kprintln!(
                "seclog: seal {} through {} head {} anchor {} {}",
                seal.count,
                seal.through,
                HexHash(&seal.head),
                HexHash(&seal.anchor),
                if ok { backend.name() } else { "advisory" }
            );
            last_seal = now;
        }
        let end = timebase::now() + timebase::TIMER_FREQ;
        while timebase::now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}
