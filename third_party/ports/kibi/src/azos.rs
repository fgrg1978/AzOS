//! # sys (AzOS)
//!
//! The terminal backend for the native SDK std target. A program reads its
//! input from the handle its spawner passed as fd 0 and writes the console
//! directly; there is no termios, no ioctl and no signal. The terminal server
//! switches a terminal between cooked and raw only for its one client (the
//! shell), so a child program cannot ask for raw input: `enable_raw_mode`
//! refuses instead of pretending, and the editor stops with that error.

use std::io;

use crate::Error;
pub use crate::xdg::*;

#[derive(Copy, Clone)]
pub struct TermMode;

/// No size query exists; the editor falls back to asking the terminal for the cursor position.
pub const fn get_window_size() -> Result<(usize, usize), Error> { Err(Error::InvalidWindowSize) }

/// There is no resize signal.
#[expect(clippy::unnecessary_wraps)] // Result required on other platforms
pub const fn register_winsize_change_signal_handler() -> io::Result<()> { Ok(()) }

pub const fn has_window_size_changed() -> bool { false }

/// The mode is never changed, so there is nothing to restore.
#[expect(clippy::unnecessary_wraps)] // Result required on other platforms
#[expect(clippy::trivially_copy_pass_by_ref)]
pub const fn set_term_mode(_term: &TermMode) -> io::Result<()> { Ok(()) }

pub fn enable_raw_mode() -> io::Result<TermMode> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "the terminal has no raw mode for this program"))
}

/// The standard input of the program, one buffer shared by every caller.
#[expect(clippy::unnecessary_wraps)] // Result required on other platforms
pub fn stdin() -> io::Result<impl io::BufRead> { Ok(io::stdin().lock()) }

pub fn path(filename: &str) -> std::path::PathBuf { std::path::PathBuf::from(filename) }
