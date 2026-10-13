// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The i8042 PS/2 controller: presence, self-test and bring-up.
//!
//! Pure over [`Ports`] (the two I/O ports), so a host test drives it against a
//! scripted controller. Every wait is a bounded count of status reads
//! (`spins`, Kconfig `PS2_WAIT_SPINS`): a machine with no controller, or one
//! that stops answering, fails the step instead of hanging the boot.
//!
//! Bring-up, in the order the controller needs it:
//!
//! 1. A status byte of `0xFF` is a floating bus: no controller.
//! 2. Both ports off, output buffer drained, configuration byte read; IRQs
//!    off and **scancode translation off** (the keyboard's own set 2 is what
//!    `scancode` decodes).
//! 3. Controller self-test (`0xAA` answers `0x55`), then the configuration is
//!    written again (a self-test may reset it).
//! 4. Second (mouse) port detected by its clock-disable bit going set when it
//!    is disabled and clear when it is enabled; each port's interface test (`0xAB`, `0xA9` answer 0).
//! 5. Ports on, each device reset (`0xFF`, ack, `0xAA`), the keyboard put on
//!    set 2 and both told to stream (`0xF4`). A device that does not answer
//!    is left off.
//!
//! The IRQ bits are NOT set here: the caller routes the lines first and then
//! calls [`enable_irqs`], so an edge is never raised into a masked entry.

pub const PORT_DATA: u16 = 0x60;
pub const PORT_CMD: u16 = 0x64;

/// Status: output buffer full (a byte to read at [`PORT_DATA`]).
pub const ST_OBF: u8 = 0x01;
/// Status: input buffer full (the controller has not taken our last byte).
pub const ST_IBF: u8 = 0x02;
/// Status: the byte in the output buffer came from the mouse port.
pub const ST_AUX: u8 = 0x20;

const CMD_READ_CFG: u8 = 0x20;
const CMD_WRITE_CFG: u8 = 0x60;
const CMD_AUX_OFF: u8 = 0xA7;
const CMD_AUX_ON: u8 = 0xA8;
const CMD_AUX_TEST: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_KBD_TEST: u8 = 0xAB;
const CMD_KBD_OFF: u8 = 0xAD;
const CMD_KBD_ON: u8 = 0xAE;
const CMD_TO_AUX: u8 = 0xD4;

const CFG_KBD_IRQ: u8 = 0x01;
const CFG_AUX_IRQ: u8 = 0x02;
const CFG_KBD_CLOCK_OFF: u8 = 0x10;
const CFG_AUX_CLOCK_OFF: u8 = 0x20;
const CFG_TRANSLATE: u8 = 0x40;

const SELF_TEST_OK: u8 = 0x55;
const PORT_TEST_OK: u8 = 0x00;

const DEV_ACK: u8 = 0xFA;
const DEV_RESEND: u8 = 0xFE;
const DEV_SELF_TEST_OK: u8 = 0xAA;
const DEV_RESET: u8 = 0xFF;
const KBD_SET_SCANCODE: u8 = 0xF0;
const KBD_SET_2: u8 = 0x02;
const DEV_ENABLE_STREAM: u8 = 0xF4;

/// Times a device command is resent when it answers 0xFE.
const RESENDS: u32 = 3;
/// Output-buffer bytes dropped before giving up draining (the buffer is a
/// few bytes deep; more means the data port is not a controller's).
const DRAIN_MAX: u32 = 64;
/// A device reset takes far longer than a command: its self-test runs
/// first (a keyboard's takes up to about half a second). The wait for its
/// result is this many times `spins`; a device that is absent never gets
/// that far, it does not acknowledge the reset.
const RESET_WAIT_FACTOR: u32 = 8;

/// The controller's two I/O ports.
pub trait Ports {
    fn inb(&mut self, port: u16) -> u8;
    fn outb(&mut self, port: u16, v: u8);
}

/// Why the controller was not brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The status port reads all ones: nothing answers.
    Floating,
    /// A wait ran out.
    Timeout(&'static str),
    /// The controller self-test answered something but `0x55`.
    SelfTest(u8),
    /// No port passed its interface test (or no device answered its reset).
    NoDevice,
}

impl Fail {
    pub const fn describe(&self) -> &'static str {
        match self {
            Fail::Floating => "status port floats (no controller)",
            Fail::Timeout(w) => w,
            Fail::SelfTest(_) => "controller self-test failed",
            Fail::NoDevice => "no keyboard or mouse answered",
        }
    }
}

/// What is attached after [`init`], and the configuration byte [`enable_irqs`]
/// completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub kbd: bool,
    pub aux: bool,
    cfg: u8,
}

fn wait_write<P: Ports>(p: &mut P, spins: u32, what: &'static str) -> Result<(), Fail> {
    for _ in 0..spins {
        if p.inb(PORT_CMD) & ST_IBF == 0 {
            return Ok(());
        }
    }
    Err(Fail::Timeout(what))
}

fn wait_read<P: Ports>(p: &mut P, spins: u32, what: &'static str) -> Result<u8, Fail> {
    for _ in 0..spins {
        if p.inb(PORT_CMD) & ST_OBF != 0 {
            return Ok(p.inb(PORT_DATA));
        }
    }
    Err(Fail::Timeout(what))
}

fn send_cmd<P: Ports>(p: &mut P, spins: u32, cmd: u8) -> Result<(), Fail> {
    wait_write(p, spins, "controller did not take a command")?;
    p.outb(PORT_CMD, cmd);
    Ok(())
}

fn send_data<P: Ports>(p: &mut P, spins: u32, v: u8) -> Result<(), Fail> {
    wait_write(p, spins, "controller did not take a data byte")?;
    p.outb(PORT_DATA, v);
    Ok(())
}

/// A command with a one-byte answer.
fn query<P: Ports>(p: &mut P, spins: u32, cmd: u8, what: &'static str) -> Result<u8, Fail> {
    send_cmd(p, spins, cmd)?;
    wait_read(p, spins, what)
}

fn write_cfg<P: Ports>(p: &mut P, spins: u32, cfg: u8) -> Result<(), Fail> {
    send_cmd(p, spins, CMD_WRITE_CFG)?;
    send_data(p, spins, cfg)
}

/// Drop whatever the output buffer holds. `false`: it never emptied.
fn drain<P: Ports>(p: &mut P) -> bool {
    for _ in 0..DRAIN_MAX {
        if p.inb(PORT_CMD) & ST_OBF == 0 {
            return true;
        }
        let _ = p.inb(PORT_DATA);
    }
    false
}

/// One byte to a device (`aux`: the mouse, through `0xD4`), then its
/// acknowledge, resent on `0xFE`. `false`: no acknowledge.
fn dev_send<P: Ports>(p: &mut P, spins: u32, aux: bool, v: u8) -> bool {
    for _ in 0..=RESENDS {
        let sent = (!aux || send_cmd(p, spins, CMD_TO_AUX).is_ok()) && send_data(p, spins, v).is_ok();
        if !sent {
            return false;
        }
        match wait_read(p, spins, "device did not answer") {
            Ok(DEV_ACK) => return true,
            Ok(DEV_RESEND) => continue,
            _ => return false,
        }
    }
    false
}

/// Reset one device: ack, then the self-test result `0xAA`; a mouse then
/// sends its id byte, which is read and dropped.
fn dev_reset<P: Ports>(p: &mut P, spins: u32, aux: bool) -> bool {
    if !dev_send(p, spins, aux, DEV_RESET) {
        return false;
    }
    let long = spins.saturating_mul(RESET_WAIT_FACTOR);
    if wait_read(p, long, "device reset").ok() != Some(DEV_SELF_TEST_OK) {
        return false;
    }
    if aux {
        let _ = wait_read(p, spins, "mouse id");
    }
    true
}

/// Probe and bring up the controller. See the module doc for the sequence.
pub fn init<P: Ports>(p: &mut P, spins: u32) -> Result<Found, Fail> {
    if p.inb(PORT_CMD) == 0xFF {
        return Err(Fail::Floating);
    }
    send_cmd(p, spins, CMD_KBD_OFF)?;
    send_cmd(p, spins, CMD_AUX_OFF)?;
    if !drain(p) {
        return Err(Fail::Floating);
    }
    let cfg = query(p, spins, CMD_READ_CFG, "configuration byte")?;
    // The second port was just disabled: only a controller that has one
    // shows its clock-disable bit set.
    let aux_off_seen = cfg & CFG_AUX_CLOCK_OFF != 0;
    let cfg = cfg & !(CFG_KBD_IRQ | CFG_AUX_IRQ | CFG_TRANSLATE);
    write_cfg(p, spins, cfg)?;

    let st = query(p, spins, CMD_SELF_TEST, "controller self-test")?;
    if st != SELF_TEST_OK {
        return Err(Fail::SelfTest(st));
    }
    // A self-test may have reset the configuration.
    write_cfg(p, spins, cfg)?;

    // Second port: it exists if disabling it set its clock-disable bit and
    // enabling it clears the bit again.
    send_cmd(p, spins, CMD_AUX_ON)?;
    let dual = aux_off_seen
        && query(p, spins, CMD_READ_CFG, "configuration byte")? & CFG_AUX_CLOCK_OFF == 0;
    send_cmd(p, spins, CMD_AUX_OFF)?;

    let mut kbd = query(p, spins, CMD_KBD_TEST, "keyboard port test")? == PORT_TEST_OK;
    let mut aux = dual && query(p, spins, CMD_AUX_TEST, "mouse port test")? == PORT_TEST_OK;
    if !kbd && !aux {
        return Err(Fail::NoDevice);
    }

    let mut cfg = cfg;
    if kbd {
        send_cmd(p, spins, CMD_KBD_ON)?;
        cfg &= !CFG_KBD_CLOCK_OFF;
    }
    if aux {
        send_cmd(p, spins, CMD_AUX_ON)?;
        cfg &= !CFG_AUX_CLOCK_OFF;
    }
    let _ = drain(p);

    kbd = kbd && dev_reset(p, spins, false)
        && dev_send(p, spins, false, KBD_SET_SCANCODE) && dev_send(p, spins, false, KBD_SET_2)
        && dev_send(p, spins, false, DEV_ENABLE_STREAM);
    aux = aux && dev_reset(p, spins, true) && dev_send(p, spins, true, DEV_ENABLE_STREAM);
    if !kbd && !aux {
        return Err(Fail::NoDevice);
    }
    // A port with no working device stays off.
    if !kbd {
        send_cmd(p, spins, CMD_KBD_OFF)?;
        cfg |= CFG_KBD_CLOCK_OFF;
    }
    if !aux {
        send_cmd(p, spins, CMD_AUX_OFF)?;
        cfg |= CFG_AUX_CLOCK_OFF;
    }
    write_cfg(p, spins, cfg)?;
    let _ = drain(p);
    Ok(Found { kbd, aux, cfg })
}

/// Turn the interrupts of the ports in `found` on (the lines are routed).
/// Writes only: nothing is read back, so a byte arriving between the two
/// accesses is left for the handler.
pub fn enable_irqs<P: Ports>(p: &mut P, spins: u32, found: &Found) -> Result<(), Fail> {
    let mut cfg = found.cfg;
    if found.kbd {
        cfg |= CFG_KBD_IRQ;
    }
    if found.aux {
        cfg |= CFG_AUX_IRQ;
    }
    write_cfg(p, spins, cfg)
}
