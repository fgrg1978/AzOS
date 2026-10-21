// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SBI a guest kernel (VS-mode) calls with `ecall`, served by the monitor.
//!
//! A guest has no firmware under it: the `ecall` traps to HS-mode
//! ([`super::fault::Exit::VsEcall`]) and the monitor *is* the SBI. Nothing is
//! forwarded to the host's own firmware: a guest must not reach the host
//! machine's timer, harts or reset through it.
//!
//! The call is `a7` = extension, `a6` = function, `a0..a5` = arguments; the
//! answer is `a0` = error, `a1` = value, and the guest resumes after the
//! `ecall` (4 bytes). Version 2.0 of the specification, these extensions:
//!
//! | extension | functions | served by |
//! |-----------|-----------|-----------|
//! | BASE `0x10` | spec version, implementation id and version, probe, `mvendorid` / `marchid` / `mimpid` (0: virtual) | here |
//! | TIME `0x54494D45` | `set_timer` | the monitor's timer ([`HypercallHost::arm_timer`]), which asserts [`LINE_TIMER`] |
//! | IPI `0x735049` | `send_ipi` | [`LINE_SOFTWARE`] raised on each target vCPU |
//! | RFENCE `0x52464E43` | `remote_fence_i`, `remote_sfence_vma`, `remote_sfence_vma_asid` | [`HypercallHost::fence`] per target; `hfence.vvma` / `fence.i` run by [`execute`] on the hart of the target |
//! | HSM `0x48534D` | `hart_start`, `hart_stop`, `hart_get_status` | [`HypercallHost::start_vcpu`], the loop ends the caller's thread |
//! | SRST `0x53525354` | `system_reset` | the loop ends the VM ([`HypercallOutcome::EndGuest`]), vmmd sees the end |
//!
//! Any other extension, and any function of these that is not listed
//! (`hart_suspend`, the legacy `0x00..=0x0F` calls, the nested-hypervisor
//! RFENCE functions), answers `SBI_ERR_NOT_SUPPORTED`. A guest finds what is
//! there with `probe_extension`.
//!
//! There is no console extension (DBCN): a guest's console is the VM's console
//! backend, a device on the trap ring like every other, so a guest names its
//! MMIO console (`stdout-path`), not `earlycon=sbi`.
//!
//! # Contracts with the monitor
//!
//! * A hart id is the vCPU's index in its VM. A VM boots with vCPU 0 running;
//!   the others are stopped until the guest starts them with `hart_start`.
//! * `hart_start(hartid, addr, opaque)` runs the vCPU at guest-physical
//!   `addr` with `a0` = hart id and `a1` = `opaque`: the monitor starts it
//!   with entry argument `opaque` ([`HypercallHost::start_vcpu`]) and the
//!   riscv64 entry puts the vCPU's index in `a0` and the entry argument in
//!   `a1` (the same protocol the boot vCPU gets, with the device tree address
//!   as `opaque`).
//! * A vCPU's virtual interrupt line `n` is `hvip` bit `n`: the lines this
//!   file raises are [`LINE_SOFTWARE`] (`VSSIP`) and [`LINE_TIMER`] (`VSTIP`).
//! * The guest's `time` is the host's plus `htimedelta` (0 from the start;
//!   every vCPU has it moved back by the time the VM was held, one value for
//!   the VM, see `GuestCtx::time_skip`: a vCPU started by `hart_start` takes
//!   all of it at its first entry); every deadline here is in the guest's
//!   ticks.
//! * A VM has no Sstc (`henvcfg.STCE` clear, the device tree omits it): every
//!   guest deadline passes through `set_timer`, and the timer is a level the
//!   monitor owns, asserted as [`LINE_TIMER`] while the deadline has passed.

use azos_arch_api::{HypercallHost, HypercallOutcome, RemoteFence, VcpuStartError};

use super::csr::{VSSIP, VSTIP};
use super::enter::GuestFrame;

// ── the numbers of the specification ────────────────────────────────────

/// Extension ids.
pub mod eid {
    pub const BASE: u64 = 0x10;
    pub const TIME: u64 = 0x5449_4D45;
    pub const IPI: u64 = 0x73_5049;
    pub const RFENCE: u64 = 0x5246_4E43;
    pub const HSM: u64 = 0x48_534D;
    pub const SRST: u64 = 0x5352_5354;
}

/// Function ids.
pub mod fid {
    pub const BASE_SPEC_VERSION: u64 = 0;
    pub const BASE_IMPL_ID: u64 = 1;
    pub const BASE_IMPL_VERSION: u64 = 2;
    pub const BASE_PROBE: u64 = 3;
    pub const BASE_MVENDORID: u64 = 4;
    pub const BASE_MARCHID: u64 = 5;
    pub const BASE_MIMPID: u64 = 6;
    pub const TIME_SET_TIMER: u64 = 0;
    pub const IPI_SEND: u64 = 0;
    pub const RFENCE_FENCE_I: u64 = 0;
    pub const RFENCE_SFENCE_VMA: u64 = 1;
    pub const RFENCE_SFENCE_VMA_ASID: u64 = 2;
    pub const HSM_START: u64 = 0;
    pub const HSM_STOP: u64 = 1;
    pub const HSM_STATUS: u64 = 2;
    pub const SRST_RESET: u64 = 0;
}

/// Error codes (`a0`), as the signed word the guest reads.
pub mod err {
    pub const SUCCESS: i64 = 0;
    pub const FAILED: i64 = -1;
    pub const NOT_SUPPORTED: i64 = -2;
    pub const INVALID_PARAM: i64 = -3;
    pub const DENIED: i64 = -4;
    pub const INVALID_ADDRESS: i64 = -5;
    pub const ALREADY_AVAILABLE: i64 = -6;
}

/// HSM hart states (`hart_get_status`).
pub mod hart_state {
    pub const STARTED: u64 = 0;
    pub const STOPPED: u64 = 1;
}

/// SRST reset types.
pub mod reset {
    pub const SHUTDOWN: u64 = 0;
    pub const COLD_REBOOT: u64 = 1;
    pub const WARM_REBOOT: u64 = 2;
}

/// The specification version this implements: 2.0 (`major << 24 | minor`).
pub const SPEC_VERSION: u64 = 2 << 24;
/// The implementation id `get_impl_id` answers: "AzOS" (the specification
/// allocates ids to named implementations; this is a private one).
pub const IMPL_ID: u64 = 0x417A_4F53;
/// The implementation version.
pub const IMPL_VERSION: u64 = 1;

/// The virtual interrupt line of the guest's software interrupt (`VSSIP`).
pub const LINE_SOFTWARE: u32 = VSSIP.trailing_zeros();
/// The virtual interrupt line of the guest's timer (`VSTIP`).
pub const LINE_TIMER: u32 = VSTIP.trailing_zeros();

/// The extensions served, as `probe_extension` reports them.
const SERVED: [u64; 6] = [eid::BASE, eid::TIME, eid::IPI, eid::RFENCE, eid::HSM, eid::SRST];

// ── the call and its answer ─────────────────────────────────────────────

/// One `ecall`, read from the guest's registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbiCall {
    pub eid: u64,
    pub fid: u64,
    /// `a0..a5`.
    pub args: [u64; 6],
}

impl SbiCall {
    pub fn from_frame(f: &GuestFrame) -> SbiCall {
        let g = &f.gpr;
        SbiCall { eid: g[17], fid: g[16], args: [g[10], g[11], g[12], g[13], g[14], g[15]] }
    }
}

/// What the guest reads back: `a0`, `a1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbiRet {
    pub error: i64,
    pub value: u64,
}

impl SbiRet {
    const fn ok(value: u64) -> SbiRet {
        SbiRet { error: err::SUCCESS, value }
    }
    const fn err(error: i64) -> SbiRet {
        SbiRet { error, value: 0 }
    }
}

/// What a call does besides answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// The caller's vCPU ends; the call does not return.
    StopVcpu,
    /// The guest ends the machine; the call does not return.
    EndGuest { kind: u32, reason: u32 },
}

/// The result of [`handle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handled {
    pub ret: SbiRet,
    pub effect: Effect,
}

const fn done(ret: SbiRet) -> Handled {
    Handled { ret, effect: Effect::None }
}

// ── hart masks ──────────────────────────────────────────────────────────

/// The vCPUs a `(hart_mask, hart_mask_base)` pair names, as a bit per vCPU.
/// `hart_mask_base == u64::MAX` names all of them (the mask is ignored);
/// otherwise bit `i` of the mask is hart `base + i`. A selected hart the VM
/// does not have makes the whole pair invalid (`None`): nothing is done for
/// the ones before it. An empty mask names nobody, whatever the base.
pub fn targets(mask: u64, base: u64, vcpus: usize) -> Option<u64> {
    let n = vcpus.min(64);
    if base == u64::MAX {
        return Some(if n == 64 { u64::MAX } else { (1u64 << n) - 1 });
    }
    let mut out = 0u64;
    for i in 0..64u64 {
        if mask >> i & 1 == 0 {
            continue;
        }
        let hart = base.checked_add(i)?;
        if hart >= n as u64 {
            return None;
        }
        out |= 1 << hart;
    }
    Some(out)
}

fn each(set: u64, mut f: impl FnMut(usize)) {
    let mut m = set;
    while m != 0 {
        f(m.trailing_zeros() as usize);
        m &= m - 1;
    }
}

// ── the handler ─────────────────────────────────────────────────────────

/// Serve `call` made by vCPU `caller`. Pure but for `host`: what it asks of
/// the vCPU loop besides the answer is returned as an [`Effect`], not done.
pub fn handle(call: &SbiCall, caller: usize, host: &mut dyn HypercallHost) -> Handled {
    let a = &call.args;
    match call.eid {
        eid::BASE => done(base(call.fid, a[0])),
        eid::TIME if call.fid == fid::TIME_SET_TIMER => set_timer(a[0], caller, host),
        eid::IPI if call.fid == fid::IPI_SEND => done(send_ipi(a[0], a[1], host)),
        eid::RFENCE => done(rfence(call, host)),
        eid::HSM => hsm(call.fid, a[0], a[1], a[2], host),
        eid::SRST if call.fid == fid::SRST_RESET => system_reset(a[0], a[1]),
        _ => done(SbiRet::err(err::NOT_SUPPORTED)),
    }
}

fn base(function: u64, arg: u64) -> SbiRet {
    match function {
        fid::BASE_SPEC_VERSION => SbiRet::ok(SPEC_VERSION),
        fid::BASE_IMPL_ID => SbiRet::ok(IMPL_ID),
        fid::BASE_IMPL_VERSION => SbiRet::ok(IMPL_VERSION),
        fid::BASE_PROBE => SbiRet::ok(SERVED.contains(&arg) as u64),
        // A virtual hart has no vendor, architecture or implementation.
        fid::BASE_MVENDORID | fid::BASE_MARCHID | fid::BASE_MIMPID => SbiRet::ok(0),
        _ => SbiRet::err(err::NOT_SUPPORTED),
    }
}

/// The deadline replaces the caller's pending one, and a later one withdraws
/// a timer interrupt that was asserted (the specification's way to clear it).
fn set_timer(deadline: u64, caller: usize, host: &mut dyn HypercallHost) -> Handled {
    host.arm_timer(caller, deadline, LINE_TIMER);
    done(SbiRet::ok(0))
}

fn send_ipi(mask: u64, base: u64, host: &mut dyn HypercallHost) -> SbiRet {
    let Some(set) = targets(mask, base, host.vcpus()) else { return SbiRet::err(err::INVALID_PARAM) };
    each(set, |v| host.raise_irq(v, LINE_SOFTWARE));
    SbiRet::ok(0)
}

fn rfence(call: &SbiCall, host: &mut dyn HypercallHost) -> SbiRet {
    let a = &call.args;
    let fence = match call.fid {
        fid::RFENCE_FENCE_I => RemoteFence::Insn,
        fid::RFENCE_SFENCE_VMA => match tlb_range(a[2], a[3]) {
            Some((start, size)) => RemoteFence::Tlb { start, size, asid: None },
            None => return validate_only(a[0], a[1], host),
        },
        fid::RFENCE_SFENCE_VMA_ASID => match tlb_range(a[2], a[3]) {
            Some((start, size)) => RemoteFence::Tlb { start, size, asid: Some(a[4]) },
            None => return validate_only(a[0], a[1], host),
        },
        _ => return SbiRet::err(err::NOT_SUPPORTED),
    };
    let Some(set) = targets(a[0], a[1], host.vcpus()) else { return SbiRet::err(err::INVALID_PARAM) };
    each(set, |v| host.fence(v, fence));
    SbiRet::ok(0)
}

/// A fence of an empty range does nothing, but the harts it names are still
/// checked.
fn validate_only(mask: u64, base: u64, host: &dyn HypercallHost) -> SbiRet {
    match targets(mask, base, host.vcpus()) {
        Some(_) => SbiRet::ok(0),
        None => SbiRet::err(err::INVALID_PARAM),
    }
}

/// The range of an `sfence.vma` call as [`RemoteFence::Tlb`] carries it:
/// `start = 0, size = 0` and `size = u64::MAX` are the whole address space
/// (`size == u64::MAX`); any other zero size is an empty range (`None`).
fn tlb_range(start: u64, size: u64) -> Option<(u64, u64)> {
    match (start, size) {
        (0, 0) => Some((0, u64::MAX)),
        (_, 0) => None,
        _ => Some((start, size)),
    }
}

fn hsm(function: u64, hartid: u64, addr: u64, opaque: u64, host: &mut dyn HypercallHost) -> Handled {
    match function {
        fid::HSM_START => done(hart_start(hartid, addr, opaque, host)),
        fid::HSM_STOP => Handled { ret: SbiRet::ok(0), effect: Effect::StopVcpu },
        fid::HSM_STATUS => {
            if hartid >= host.vcpus() as u64 {
                return done(SbiRet::err(err::INVALID_PARAM));
            }
            let st = if host.vcpu_running(hartid as usize) { hart_state::STARTED } else { hart_state::STOPPED };
            done(SbiRet::ok(st))
        }
        _ => done(SbiRet::err(err::NOT_SUPPORTED)),
    }
}

fn hart_start(hartid: u64, addr: u64, opaque: u64, host: &mut dyn HypercallHost) -> SbiRet {
    if hartid >= host.vcpus() as u64 {
        return SbiRet::err(err::INVALID_PARAM);
    }
    let v = hartid as usize;
    if host.vcpu_running(v) {
        return SbiRet::err(err::ALREADY_AVAILABLE);
    }
    match host.start_vcpu(v, addr, opaque) {
        Ok(()) => SbiRet::ok(0),
        Err(VcpuStartError::BadAddress) => SbiRet::err(err::INVALID_ADDRESS),
        Err(VcpuStartError::AlreadyRunning) => SbiRet::err(err::ALREADY_AVAILABLE),
        Err(VcpuStartError::Failed) => SbiRet::err(err::FAILED),
    }
}

fn system_reset(kind: u64, reason: u64) -> Handled {
    if kind > reset::WARM_REBOOT {
        return done(SbiRet::err(err::INVALID_PARAM));
    }
    Handled { ret: SbiRet::ok(0), effect: Effect::EndGuest { kind: kind as u32, reason: reason as u32 } }
}

// ── on the guest's register frame ───────────────────────────────────────

/// The `ecall` instruction's length: the guest resumes after it.
const ECALL_LEN: u8 = 4;

/// Serve the call in `frame` for vCPU `caller`: decode, [`handle`], write the
/// answer and step past the `ecall`. A
/// call that does not return (`hart_stop`, `system_reset`) leaves the frame
/// alone.
pub fn serve(frame: &mut GuestFrame, caller: usize, host: &mut dyn HypercallHost) -> HypercallOutcome {
    let h = handle(&SbiCall::from_frame(frame), caller, host);
    match h.effect {
        Effect::StopVcpu => return HypercallOutcome::StopVcpu,
        Effect::EndGuest { kind, reason } => return HypercallOutcome::EndGuest { kind, reason },
        Effect::None => {}
    }
    frame.gpr[10] = h.ret.error as u64;
    frame.gpr[11] = h.ret.value;
    frame.skip_insn(ECALL_LEN);
    HypercallOutcome::Served
}

// ── hfence.vvma / fence.i ───────────────────────────────────────────────

/// Pages of a ranged flush past which one flush of everything is cheaper.
pub const RANGE_PAGES_MAX: u64 = 64;
const PAGE: u64 = 4096;

/// How a [`RemoteFence::Tlb`] is carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vvma {
    /// `hfence.vvma x0, x0`.
    All,
    /// `hfence.vvma x0, asid`.
    Asid(u64),
    /// `hfence.vvma va, asid|x0` for `count` pages from `first`.
    Pages { first: u64, count: u64, asid: Option<u64> },
}

/// The flush a translation fence of the range `start .. start + size` (size
/// `u64::MAX`: everything) of `asid` becomes; `None` for an empty range. A
/// range that wraps the address space or spans more than [`RANGE_PAGES_MAX`]
/// pages is flushed whole.
pub fn vvma_plan(start: u64, size: u64, asid: Option<u64>) -> Option<Vvma> {
    if size == 0 {
        return None;
    }
    let whole = match asid {
        Some(a) => Vvma::Asid(a),
        None => Vvma::All,
    };
    if size == u64::MAX {
        return Some(whole);
    }
    let first = start & !(PAGE - 1);
    let Some(end) = start.checked_add(size) else { return Some(whole) };
    let count = (end - first).div_ceil(PAGE);
    if count > RANGE_PAGES_MAX {
        return Some(whole);
    }
    Some(Vvma::Pages { first, count, asid })
}

/// `hfence.vvma rs1, rs2` (funct7 0010001), encoded by hand like the other
/// H instructions ([`super::gstage::HFENCE_VVMA`] is the `x0, x0` form).
pub const fn hfence_vvma_word(rs1: u32, rs2: u32) -> u32 {
    super::gstage::HFENCE_VVMA | (rs2 << 20) | (rs1 << 15)
}

/// What a hart does for a fence: the three instructions, and the guest whose
/// translations `hfence.vvma` names (`hgatp.VMID`). [`Real`] is the hart this
/// runs on; the host tests pass one that records, so what [`execute_on`] asks
/// of the hart is checked without the instructions.
pub trait Hart {
    /// Load `hgatp`: the guest the next `hfence.vvma` is about.
    fn select_guest(&mut self, hgatp: u64);
    /// `fence.i`.
    fn fence_i(&mut self);
    /// `hfence.vvma va, asid` (`None`: x0, every address / every ASID).
    fn hfence_vvma(&mut self, va: Option<u64>, asid: Option<u64>);
}

/// Carry out `fence` on `hart` for the guest whose `hgatp` is `hgatp`:
/// [`azos_arch_api::Hypervisor::remote_fence`].
pub fn execute_on(hart: &mut dyn Hart, hgatp: u64, fence: &RemoteFence) {
    match *fence {
        RemoteFence::Insn => hart.fence_i(),
        RemoteFence::Tlb { start, size, asid } => {
            let Some(plan) = vvma_plan(start, size, asid) else { return };
            // `hfence.vvma` is about the guest `hgatp` names, which is not
            // necessarily the one this hart ran last.
            hart.select_guest(hgatp);
            match plan {
                Vvma::All => hart.hfence_vvma(None, None),
                Vvma::Asid(a) => hart.hfence_vvma(None, Some(a)),
                Vvma::Pages { first, count, asid } => {
                    for i in 0..count {
                        hart.hfence_vvma(Some(first + i * PAGE), asid);
                    }
                }
            }
        }
    }
}

/// [`execute_on`] on this hart.
pub fn execute(hgatp: u64, fence: &RemoteFence) {
    execute_on(&mut Real, hgatp, fence)
}

/// The hart the code runs on. Off riscv64 (the host tests) its instructions
/// are not there to run and it does nothing.
pub struct Real;

#[cfg(target_arch = "riscv64")]
const A0: u32 = 10;
#[cfg(target_arch = "riscv64")]
const A1: u32 = 11;

#[cfg(target_arch = "riscv64")]
impl Hart for Real {
    fn select_guest(&mut self, hgatp: u64) {
        // SAFETY: a CSR write; H is usable when a guest runs, and the guest's
        // own entry loads `hgatp` again.
        unsafe {
            core::arch::asm!("csrw {a}, {v}", a = const super::csr::HGATP, v = in(reg) hgatp,
                options(nomem, nostack));
        }
    }

    fn fence_i(&mut self) {
        // SAFETY: an instruction fence; no operand.
        unsafe { core::arch::asm!("fence.i", options(nostack)) };
    }

    fn hfence_vvma(&mut self, va: Option<u64>, asid: Option<u64>) {
        // SAFETY: a fence on a0 = guest virtual address, a1 = ASID; x0 is
        // "all". H is usable when a guest runs.
        unsafe {
            match (va, asid) {
                (None, None) => {
                    core::arch::asm!(".word {w}", w = const super::gstage::HFENCE_VVMA, options(nostack))
                }
                (None, Some(a)) => core::arch::asm!(".word {w}", w = const hfence_vvma_word(0, A1),
                    in("a1") a, options(nostack)),
                (Some(v), None) => core::arch::asm!(".word {w}", w = const hfence_vvma_word(A0, 0),
                    in("a0") v, options(nostack)),
                (Some(v), Some(a)) => core::arch::asm!(".word {w}", w = const hfence_vvma_word(A0, A1),
                    in("a0") v, in("a1") a, options(nostack)),
            }
        }
    }
}

#[cfg(not(target_arch = "riscv64"))]
impl Hart for Real {
    fn select_guest(&mut self, _hgatp: u64) {}
    fn fence_i(&mut self) {}
    fn hfence_vvma(&mut self, _va: Option<u64>, _asid: Option<u64>) {}
}
