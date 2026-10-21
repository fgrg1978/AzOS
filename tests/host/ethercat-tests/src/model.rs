// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A scripted EtherCAT slave chain: enough of an ESC to run a master against.
//!
//! Each [`Esc`] is a 8 KiB register file plus process data RAM with the
//! behaviours a master depends on: auto-increment, node and broadcast
//! addressing, the working counter rules, FMMU-resolved logical access, the AL
//! state machine (with scripted refusals and delayed transitions) and the DC
//! receive-time latch. A [`Bus`] wires several in a line with a fixed hop
//! delay and a per-slave clock skew, so a test can compare what the DC
//! arithmetic computes with the delay and skew it was built with.
//!
//! Frames go in and out as bytes through the crate's own parser, so a test that
//! uses the model also tests the codec against an independent reader of the
//! same wire format.

use azos_ethercat::al::{status_code, transition_allowed, AlState, AL_ERROR_BIT};
use azos_ethercat::frame::{self, Addressing, Cmd};
use azos_ethercat::reg::{self, Fmmu, FmmuDir};

pub const MEM: usize = 0x2000;

/// What an [`Esc`] does beyond the standard rules.
#[derive(Default, Clone)]
pub struct Script {
    /// Requests for these states are refused with the given AL status code.
    pub refuse: Vec<(AlState, u16)>,
    /// SAFE-OP is refused (code 0x001D) unless all of these sync managers are
    /// enabled with a non-zero length.
    pub require_sm: Vec<u8>,
    /// Polls of the AL status that still show the old state after a request.
    pub polls_before_change: u32,
}

pub struct Esc {
    pub mem: Vec<u8>,
    pub script: Script,
    /// Local clock = true time + skew (wrapping).
    pub skew: u64,
    pending: Option<(AlState, u32)>,
    /// True time at which the frame reaches this slave going forward / coming
    /// back, set by the bus before it runs the frame through.
    t_fwd: u64,
    t_ret: Option<u64>,
}

impl Esc {
    pub fn new(script: Script, skew: u64) -> Esc {
        let mut e = Esc { mem: vec![0; MEM], script, skew, pending: None, t_fwd: 0, t_ret: None };
        e.mem[reg::AL_STATUS as usize] = AlState::Init as u8;
        e
    }

    pub fn state(&self) -> AlState {
        AlState::from_status(self.mem[reg::AL_STATUS as usize]).unwrap()
    }

    pub fn error(&self) -> bool {
        self.mem[reg::AL_STATUS as usize] & AL_ERROR_BIT != 0
    }

    pub fn force_state(&mut self, s: AlState, error: bool) {
        self.mem[reg::AL_STATUS as usize] = s as u8 | if error { AL_ERROR_BIT } else { 0 };
    }

    pub fn station(&self) -> u16 {
        self.u16_at(reg::STATION_ADDR)
    }

    pub fn u16_at(&self, a: u16) -> u16 {
        u16::from_le_bytes([self.mem[a as usize], self.mem[a as usize + 1]])
    }

    pub fn u32_at(&self, a: u16) -> u32 {
        u32::from_le_bytes(self.mem[a as usize..a as usize + 4].try_into().unwrap())
    }

    pub fn u64_at(&self, a: u16) -> u64 {
        u64::from_le_bytes(self.mem[a as usize..a as usize + 8].try_into().unwrap())
    }

    /// System time this slave reads at true time `t`: local clock + offset.
    pub fn sys_time_at(&self, t: u64) -> u64 {
        t.wrapping_add(self.skew).wrapping_add(self.u64_at(reg::SYS_TIME_OFFSET))
    }

    fn set_error(&mut self, code: u16) {
        self.mem[reg::AL_STATUS as usize] |= AL_ERROR_BIT;
        self.mem[reg::AL_STATUS_CODE as usize..reg::AL_STATUS_CODE as usize + 2]
            .copy_from_slice(&code.to_le_bytes());
    }

    fn al_control_written(&mut self) {
        let ctrl = self.mem[reg::AL_CONTROL as usize];
        if ctrl & AL_ERROR_BIT != 0 {
            self.mem[reg::AL_STATUS as usize] &= !AL_ERROR_BIT;
            self.mem[reg::AL_STATUS_CODE as usize..reg::AL_STATUS_CODE as usize + 2].fill(0);
        }
        let Some(want) = AlState::from_status(ctrl) else {
            self.set_error(status_code::UNKNOWN_STATE);
            return;
        };
        let cur = self.state();
        if want == cur {
            return;
        }
        if !transition_allowed(cur, want) {
            self.set_error(status_code::INVALID_STATE_CHANGE);
            return;
        }
        if let Some(&(_, code)) = self.script.refuse.iter().find(|(s, _)| *s == want) {
            self.set_error(code);
            return;
        }
        if want == AlState::SafeOp {
            for &n in &self.script.require_sm {
                let b = reg::sm_addr(n) as usize;
                let len = u16::from_le_bytes([self.mem[b + 2], self.mem[b + 3]]);
                if self.mem[b + 6] & 1 == 0 || len == 0 {
                    self.set_error(status_code::INVALID_OUTPUT_CONFIG);
                    return;
                }
            }
        }
        // Going down is immediate; going up takes the scripted polls.
        let down = (want as u8) < (cur as u8) || want == AlState::Init;
        if down || self.script.polls_before_change == 0 {
            self.force_state(want, false);
        } else {
            self.pending = Some((want, self.script.polls_before_change));
        }
    }

    fn read_regs(&mut self, ado: usize, len: usize, out: &mut [u8], or: bool) {
        if ado <= reg::AL_STATUS as usize && (reg::AL_STATUS as usize) < ado + len {
            if let Some((want, left)) = self.pending {
                if left == 0 {
                    self.force_state(want, false);
                    self.pending = None;
                } else {
                    self.pending = Some((want, left - 1));
                }
            }
        }
        for (o, m) in out[..len].iter_mut().zip(&self.mem[ado..ado + len]) {
            if or {
                *o |= *m;
            } else {
                *o = *m;
            }
        }
    }

    fn write_regs(&mut self, ado: usize, data: &[u8]) {
        let end = ado + data.len();
        let touches = |a: u16, n: usize| ado < a as usize + n && (a as usize) < end;
        self.mem[ado..end].copy_from_slice(data);
        if touches(reg::AL_CONTROL, 2) {
            self.al_control_written();
        }
        if touches(reg::RX_TIME_P0, 4) {
            let p0 = self.t_fwd.wrapping_add(self.skew);
            self.mem[reg::RX_TIME_P0 as usize..][..4].copy_from_slice(&(p0 as u32).to_le_bytes());
            self.mem[reg::RX_TIME_PU as usize..][..8].copy_from_slice(&p0.to_le_bytes());
            let p1 = self.t_ret.map_or(0, |t| t.wrapping_add(self.skew) as u32);
            self.mem[reg::RX_TIME_P1 as usize..][..4].copy_from_slice(&p1.to_le_bytes());
        }
    }

    /// Logical access through this slave's FMMUs; returns the WKC contribution.
    fn logical(&mut self, cmd: Cmd, laddr: u32, data: &mut [u8]) -> u16 {
        let (mut read_hit, mut write_hit) = (false, false);
        let state = self.state();
        for n in 0..16u8 {
            let b = reg::fmmu_addr(n) as usize;
            let Some(f) = Fmmu::decode(self.mem[b..b + reg::FMMU_LEN].try_into().unwrap()) else { continue };
            if !f.enabled || !f.byte_aligned() {
                continue;
            }
            let (fs, fe) = (u64::from(f.logical_start), u64::from(f.logical_start) + u64::from(f.len));
            let (ds, de) = (u64::from(laddr), u64::from(laddr) + data.len() as u64);
            let (s, e) = (fs.max(ds), fe.min(de));
            if s >= e {
                continue;
            }
            let len = (e - s) as usize;
            let phys = usize::from(f.phys_start) + (s - fs) as usize;
            let doff = (s - ds) as usize;
            match f.dir {
                FmmuDir::Read if cmd.reads() && state as u8 >= AlState::SafeOp as u8 => {
                    data[doff..doff + len].copy_from_slice(&self.mem[phys..phys + len]);
                    read_hit = true;
                }
                FmmuDir::Write if cmd.writes() && state == AlState::Op => {
                    self.mem[phys..phys + len].copy_from_slice(&data[doff..doff + len]);
                    write_hit = true;
                }
                _ => {}
            }
        }
        let rw = cmd.reads() && cmd.writes();
        u16::from(read_hit) + if write_hit { if rw { 2 } else { 1 } } else { 0 }
    }
}

/// ESCs in a line, the master on the near end of slave 0.
pub struct Bus {
    pub slaves: Vec<Esc>,
    /// One-way wire plus forwarding time between neighbours, ns.
    pub hop_ns: u64,
    /// Frames exchanged so far.
    pub frames: usize,
}

impl Bus {
    pub fn new(slaves: Vec<Esc>, hop_ns: u64) -> Bus {
        Bus { slaves, hop_ns, frames: 0 }
    }

    /// Run `frame` (a complete frame, `len` bytes) through the chain at true
    /// time `now` and leave the reply in place.
    pub fn exchange(&mut self, frame: &mut [u8], len: usize, now: u64) {
        self.frames += 1;
        let n = self.slaves.len() as u64;
        for (i, s) in self.slaves.iter_mut().enumerate() {
            let i = i as u64;
            s.t_fwd = now + i * self.hop_ns;
            s.t_ret = (i + 1 < n).then(|| now + (2 * (n - 1) - i) * self.hop_ns);
        }
        // (cmd, offset of the data, data length), collected first so the buffer
        // can then be changed in place.
        let dgs: Vec<(Cmd, usize, usize)> = frame::parse(&frame[..len])
            .unwrap()
            .datagrams()
            .map(|d| {
                let d = d.unwrap();
                (d.cmd, d.data_offset, d.data.len())
            })
            .collect();
        for (cmd, off, dlen) in dgs {
            let hdr = off - frame::DG_HDR_LEN;
            let mut wkc = 0u16;
            for s in self.slaves.iter_mut() {
                let adp = u16::from_le_bytes([frame[hdr + 2], frame[hdr + 3]]);
                let ado = u16::from_le_bytes([frame[hdr + 4], frame[hdr + 5]]);
                let (matched, new_adp) = match cmd.addressing() {
                    Addressing::None | Addressing::Logical => (false, adp),
                    Addressing::Position => (adp == 0, adp.wrapping_add(1)),
                    Addressing::Broadcast => (true, adp.wrapping_add(1)),
                    Addressing::Node => (s.station() == adp, adp),
                };
                frame[hdr + 2..hdr + 4].copy_from_slice(&new_adp.to_le_bytes());
                if cmd.addressing() == Addressing::Logical {
                    let laddr = u32::from_le_bytes(frame[hdr + 2..hdr + 6].try_into().unwrap());
                    wkc += s.logical(cmd, laddr, &mut frame[off..off + dlen]);
                    continue;
                }
                let ado = usize::from(ado);
                if !matched || ado + dlen > MEM {
                    continue;
                }
                let reads = cmd.reads();
                let writes = cmd.writes();
                // A read-write command writes what the master sent and returns
                // what the slave held before.
                let sent = frame[off..off + dlen].to_vec();
                if reads {
                    let mut buf = sent.clone();
                    s.read_regs(ado, dlen, &mut buf, cmd == Cmd::Brd);
                    frame[off..off + dlen].copy_from_slice(&buf);
                }
                if writes {
                    s.write_regs(ado, &sent);
                }
                wkc += u16::from(reads) + if writes { if reads { 2 } else { 1 } } else { 0 };
            }
            frame[off + dlen..off + dlen + 2].copy_from_slice(&wkc.to_le_bytes());
        }
    }
}
