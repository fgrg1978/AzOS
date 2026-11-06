// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log: every `kerr!`/`kwarn!`/`kinfo!`/`kdebug!`/
//! `kprintln!` line, as a `{ts, level, module, msg}` record in the kernel-log
//! ring of the record substrate (`azos_records`), which ring 3 maps and reads.
//!
//! The UART mirror is unchanged: [`uart::kernel_log`](crate::uart::kernel_log)
//! pushes the record, then prints the same bytes it always printed. The
//! record is what a durable sink reads instead of the console's bytes:
//! `userspace/services/logd` drains the substrate (this ring, the decision
//! records', the telemetry's) into a file under its own directory grant
//! (Kconfig `LOGD_*`), and the toolbox's `log` reads the file. The payload
//! and the text line: [`wire`]. The early ring and its handover at boot are
//! the substrate's (`azos_records::attach`).

pub mod wire;

/// Does this build keep the log (Kconfig `KLOG`)?
pub const ENABLED: bool = azos_limits::KLOG;

const _: () = assert!(wire::PAYLOAD_BYTES == azos_records::KLOG_PAYLOAD);

/// Record one kernel line: `msg` is the formatted line without its newline,
/// `partial` that it had none (a `kprint!` fragment), `truncated` that
/// formatting stopped at the console's pre-format buffer.
#[inline]
pub fn record(level: usize, module: &'static str, msg: &[u8], partial: bool, truncated: bool) {
    if !ENABLED {
        return;
    }
    let Some(w) = azos_records::writer(azos_records::SOURCE_KLOG) else { return };
    use azos_arch::Cpu;
    let mut flags = 0;
    if partial {
        flags |= wire::FLAG_PARTIAL;
    }
    if truncated {
        flags |= wire::FLAG_TRUNC;
    }
    let (len, flags) = wire::encoded(msg, flags);
    let h = azos_records::Head {
        ts: crate::timebase::now(),
        clock: azos_records::CLOCK_TIMEBASE,
        kind: level as u16,
        len,
        // percpu-hint: the cpu tag of a log line: display only
        cpu: azos_arch::ARCH.hart_id() as u8,
        flags,
    };
    let fill = |p: &mut azos_records::Payload| {
        wire::encode(module, msg, 0, |off, b| p.bytes(off, b));
    };
    if STALE_CANARY.load(core::sync::atomic::Ordering::Relaxed) {
        STALE_CANARY.store(false, core::sync::atomic::Ordering::Relaxed);
        w.publish_stale(&h, fill);
    } else {
        w.publish(&h, fill);
    }
}

/// Gate canary `canary=record-stale`: the first line after the boot's
/// handover to the shared region is written under a stale sequence, which
/// every reader must drop (and `logd` counts). Armed after the handover, so
/// how many lines the boot printed before it cannot push it out.
static STALE_CANARY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static STALE_ASKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Ask for the `record-stale` canary (the kernel, at boot, from the command line).
pub fn set_stale_canary() {
    STALE_ASKED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// The handover is done: arm the canary if it was asked for.
pub fn arm_stale_canary() {
    if STALE_ASKED.load(core::sync::atomic::Ordering::Relaxed) {
        STALE_CANARY.store(true, core::sync::atomic::Ordering::Relaxed);
    }
}
