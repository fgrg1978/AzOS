// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Adc` interface the kernel hosts (`endpoint = "adc.<n>"`): the board's
//! converter (`azos_drv_sensor::ads1115`) channel by channel, one-shot reads and
//! sample batches into a client's queue. Built with the board's I/O (Kconfig
//! `BOARD_IO`); without it no `Adc` interface is served. The queues and the
//! pump task are the device table's (`crate::devices`).

use azos_abi::cap::CapPerms;
use azos_devif::adc::{self, Record, RecordSink, SampleQueue};
use azos_devif::{outcome, Cap, Out};
use azos_drv_sensor::ads1115::AdcPort;
use azos_sync::SpinLock;

use crate::devices::{kick_pump, words_of, QueueEnd};
use crate::khost::Caller;

/// Slot words of a record (the little-endian words of the bytes
/// `Record::encode` gives).
const RECORD_WORDS: usize = adc::RECORD_BYTES / 8;

/// The sample queue as the adapter's sink; `gone` once the region could not be
/// touched (the attachment is then over).
struct RecordRing {
    end: QueueEnd,
    gone: bool,
}

impl RecordSink for RecordRing {
    fn push(&mut self, record: &Record) -> bool {
        match self.end.push::<RECORD_WORDS>(&words_of(&record.encode())) {
            Ok(fit) => fit,
            Err(()) => {
                self.gone = true;
                false
            }
        }
    }
}

/// One channel's port and the queue its batch fills.
struct AdcHost {
    port: AdcPort,
    queue: Option<QueueEnd>,
    /// The task that started the batch (see [`release_all`]).
    owner: u32,
    /// As [`UartHost::gen`]: bumped by every start and stop of the batch.
    gen: u32,
}

macro_rules! adc_hosts {
    ($($n:literal)*) => { [$(AdcHost { port: AdcPort::new($n), queue: None, owner: 0, gen: 0 }),*] };
}

static ADC: SpinLock<[AdcHost; adc::CHANNELS as usize]> = SpinLock::new(adc_hosts!(0 1 2 3 4 5 6 7));

/// End the channel's batch (the lock is held); the samples the queue took.
fn end_batch(host: &mut AdcHost) -> Out<u32> {
    host.queue = None;
    host.gen = host.gen.wrapping_add(1);
    azos_devif::Adc::stop_batch(&mut host.port)
}

/// When the pump should look at the channel again, if its batch runs.
fn adc_next(host: &AdcHost, now_ns: u64, poll_ns: u64) -> Option<u64> {
    host.queue?;
    Some(match host.port.next_due_ns() {
        Some(due) if due > now_ns => due,
        _ => now_ns.saturating_add(poll_ns),
    })
}

/// A task exited: stop the batches it started.
pub(crate) fn release_all(tid: u32) {
    let mut hosts = ADC.lock();
    for host in hosts.iter_mut() {
        if host.queue.is_some() && host.owner == tid {
            let _ = end_batch(host);
        }
    }
}

/// Take the samples of every running batch that are due at `now_ns`; when the
/// next pass is due, `None` when no batch runs (`crate::devices::pump`).
pub(crate) fn pump(now_ns: u64, poll_ns: u64) -> Option<u64> {
    let mut next: Option<u64> = None;
    for ch in 0..adc::CHANNELS as usize {
        let taken = {
            let hosts = ADC.lock();
            hosts[ch].queue.map(|end| (hosts[ch].port.clone(), end, hosts[ch].gen))
        };
        let Some((mut port, end, gen)) = taken else { continue };
        let mut sink = RecordRing { end, gone: false };
        port.pump(now_ns, &mut sink);
        let mut hosts = ADC.lock();
        let host = &mut hosts[ch];
        if host.gen == gen {
            host.port = port;
            if sink.gone {
                let _ = end_batch(host);
            } else if host.port.queue().is_none() {
                // The batch ran its count.
                host.queue = None;
                host.gen = host.gen.wrapping_add(1);
            }
        }
        if let Some(t) = adc_next(host, now_ns, poll_ns) {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
    }
    next
}

// ── Adc ───────────────────────────────────────────────────────────────────

/// The `Adc` interface served for one caller: the converter channel the badge
/// names (`adc.2`). Every op observes (`READ`) except `set_rate`, which retunes
/// the converter all channels share (`EXEC`). The one-shot ops run on a fresh
/// adapter of the channel: they keep no state and take no lock. `start_batch` and `stop_batch` use the
/// channel's own adapter, which keeps the batch.
pub struct AdcServer(pub Caller);

impl AdcServer {
    /// The channel, if the interface can name it.
    fn channel(&self) -> Result<usize, u32> {
        if self.0.badge < adc::CHANNELS {
            Ok(self.0.badge as usize)
        } else {
            Err(outcome::NO_RESOURCE)
        }
    }
}

impl azos_devif::Adc for AdcServer {
    fn read(&mut self) -> Out<adc::Reading> {
        if let Err(o) = self.0.gate::<adc::Reading>(CapPerms::READ) {
            return o;
        }
        azos_devif::Adc::read(&mut AdcPort::new(self.0.badge))
    }

    fn set_rate(&mut self, hz: u32) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::EXEC) {
            return o;
        }
        azos_devif::Adc::set_rate(&mut AdcPort::new(self.0.badge), hz)
    }

    fn rate(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        azos_devif::Adc::rate(&AdcPort::new(self.0.badge))
    }

    fn start_batch(&mut self, queue: Cap<SampleQueue>, count: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::READ) {
            return o;
        }
        let ch = match self.channel() {
            Ok(c) => c,
            Err(c) => return Out::err(c),
        };
        let end = match QueueEnd::resolve::<RECORD_WORDS>(&self.0, queue.raw(), CapPerms::WRITE) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        let r = {
            let mut hosts = ADC.lock();
            let host = &mut hosts[ch];
            let r = azos_devif::Adc::start_batch(&mut host.port, queue, count);
            if r.code == outcome::OK {
                host.queue = Some(end);
                host.owner = self.0.tid;
                host.gen = host.gen.wrapping_add(1);
            }
            r
        };
        if r.code == outcome::OK && !kick_pump() {
            let _ = end_batch(&mut ADC.lock()[ch]);
            return Out::err(outcome::NO_RESOURCE);
        }
        r
    }

    fn stop_batch(&mut self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let ch = match self.channel() {
            Ok(c) => c,
            Err(c) => return Out::err(c),
        };
        end_batch(&mut ADC.lock()[ch])
    }
}
