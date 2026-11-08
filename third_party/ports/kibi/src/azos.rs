//! # sys (AzOS)
//!
//! The terminal backend for the native SDK std target. The shell lends the
//! foreground job a terminal of its own (fd 0, a call capability on the
//! terminal server, `std::os::azos::terminal`): raw mode and the size are asked
//! of it, and the input is read from it through `std::io::stdin`. There is no
//! termios, no ioctl and no signal; when the job ends the terminal server puts
//! the shell's mode back itself, so restoring it here is a courtesy.

use std::io;
use std::os::azos::terminal;

use crate::Error;
pub use crate::xdg::*;

/// The mode the editor found: raw or cooked, echo or not.
#[derive(Copy, Clone)]
pub struct TermMode {
    raw: bool,
    echo: bool,
}

/// Return the current window size as (rows, columns).
pub fn get_window_size() -> Result<(usize, usize), Error> {
    match terminal::size() {
        Ok((cols, rows)) if cols > 0 && rows > 0 => Ok((rows.into(), cols.into())),
        _ => Err(Error::InvalidWindowSize),
    }
}

/// There is no resize signal.
#[expect(clippy::unnecessary_wraps)] // Result required on other platforms
pub const fn register_winsize_change_signal_handler() -> io::Result<()> { Ok(()) }

pub const fn has_window_size_changed() -> bool { false }

/// Put back the mode the editor found (cooked and echoing, from the shell).
pub fn set_term_mode(term: &TermMode) -> io::Result<()> {
    terminal::set_raw(term.raw)?;
    terminal::set_echo(term.echo)
}

/// Raw mode without echo. Refused when the program was lent no terminal (it
/// was not started by the shell as a foreground job) or the job does not have
/// the focus.
pub fn enable_raw_mode() -> io::Result<TermMode> {
    terminal::set_raw(true)?;
    terminal::set_echo(false)?;
    Ok(TermMode { raw: false, echo: true })
}

/// The standard input of the program, one buffer shared by every caller.
#[expect(clippy::unnecessary_wraps)] // Result required on other platforms
pub fn stdin() -> io::Result<impl io::BufRead> { Ok(io::stdin().lock()) }

pub fn path(filename: &str) -> std::path::PathBuf { std::path::PathBuf::from(filename) }
