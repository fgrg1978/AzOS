// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor's call path, without a syscall in it: the order in which a call
//! is served while the chip has a power state (`tests/host/power-tests` pulls
//! this file in by path and drives it with a scripted monitor).
//!
//! The rule it holds: a call is answered from the chip's state AFTER the use,
//! never before it. A suspended chip is resumed and re-measured first; a chip
//! that could not be resumed answers nothing, never the sample taken before
//! the pause.

/// The monitor as the call path drives it.
pub trait Unit {
    /// A use is about to be served: resume the chip if it is suspended and
    /// start its idle clock. `Some(true)`: it was resumed; `Some(false)`: it
    /// was running; `None`: it could not be resumed.
    fn begin(&mut self) -> Option<bool>;
    /// The chip is running again after a pause: take a fresh sample.
    fn woke(&mut self);
    /// The call is served: the idle clock starts.
    fn done(&mut self);
}

/// Serve one call: `serve` reads the state the use leaves. `None`: the chip
/// could not be resumed and `serve` did not run.
pub fn serve_use<U: Unit, R>(unit: &mut U, serve: impl FnOnce(&mut U) -> R) -> Option<R> {
    match unit.begin() {
        Some(true) => unit.woke(),
        Some(false) => {}
        None => return None,
    }
    let out = serve(unit);
    unit.done();
    Some(out)
}
