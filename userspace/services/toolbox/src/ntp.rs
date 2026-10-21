// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ntp`: how the SNTP client and the clock discipline stand.
//!
//! The text only, with no system call in it, so a host test can pull it in
//! with `#[path]` (`tests/host/net-tests`). The two reads (`Net::ntp_status`,
//! `Clock::status`) are `main.rs`'s `ntp()`.

use super::host::write_v4;
use azos_devif::clock::{SOURCE_NTP, SOURCE_PTP, STATE_SYNCED};
use azos_devif::{ClockStatus, NtpStatus};
use core::fmt::{self, Write};

/// The lines of the report: the client (its server, its last exchange and the
/// counts of its syncs) and, when the discipline is known, the clock (its
/// state, the source of the last sample it took, the frequency and phase it
/// holds and the steps made and samples refused).
pub fn write_report(w: &mut dyn Write, ntp: &NtpStatus, clock: Option<&ClockStatus>) -> fmt::Result {
    w.write_str("server ")?;
    if ntp.server == 0 {
        w.write_str("none (no lease names one and NTP_SERVER is empty or did not resolve)")?;
    } else {
        write_v4(w, &ntp.server.to_be_bytes())?;
    }
    w.write_char('\n')?;
    if ntp.synced != 0 {
        writeln!(
            w,
            "client synced: last reply {} s after the Unix epoch, {} s ago; {} exchanges, {} given up",
            ntp.last_unix_sec,
            ntp.age_ms / 1000,
            ntp.exchanges,
            ntp.failures
        )?;
    } else {
        writeln!(w, "client not synced: {} exchanges, {} given up", ntp.exchanges, ntp.failures)?;
    }
    if let Some(c) = clock {
        let source = match c.source {
            SOURCE_NTP => "ntp",
            SOURCE_PTP => "ptp",
            _ => "none",
        };
        writeln!(
            w,
            "clock {}: source {}, frequency {:+} ppb, phase {:+} ns, {} steps, {} samples refused",
            if c.state == STATE_SYNCED { "synced" } else { "unset" },
            source,
            c.freq_ppb,
            c.phase_ns,
            c.steps,
            c.rejected
        )?;
    }
    Ok(())
}
