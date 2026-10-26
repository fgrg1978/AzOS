// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupts into a guest: `hvip` injection, the Sstc guest timer and the
//! AIA guest interrupt files.
//!
//! The monitor makes a VS-level interrupt pending in the guest by setting its
//! bit in `hvip` (`hideleg` must delegate it, [`super::csr::HIDELEG_GUEST`]);
//! the guest sees it in `vsip` whenever its `vsie`/`vsstatus.SIE` allow.
//! `hvip` is part of the saved guest state ([`super::vscsr::VsCsrs`]).
//!
//! The guest timer needs no injection when Sstc is present: with
//! `henvcfg.STCE` the guest writes `stimecmp` (which is `vstimecmp` for it)
//! and the hart raises `hip.VSTIP` itself when the guest's `time`
//! (`time + htimedelta`) reaches it. `vstimecmp` keeps counting while the
//! vCPU is descheduled, but a deadline that passes then raises only a
//! VS-level interrupt the host never sees: the monitor must arm its own host
//! timer for the saved `vstimecmp` ([`host_deadline`]) and re-pend the vCPU.
//! Without Sstc there is no hardware guest timer: the monitor emulates the
//! SBI timer call and injects `VSTIP` here.
//!
//! # Who owns which `hvip` bit
//!
//! * `VSEIP` and `VSTIP` are **levels the monitor owns**: the guest cannot
//!   write them (`hvip` is the only way to set them, `vsip` shows them read
//!   only), so the monitor recomputes them from the line behind them with
//!   [`hvip_level`]: the virtual PLIC's context line
//!   (`azos_hv::vplic::Vplic::line`) for `External`, the SBI timer deadline
//!   for `Timer` without Sstc. Recomputing never touches the other bits.
//! * `VSSIP` is an **edge**: the monitor pends it ([`hvip_with`], an SBI IPI)
//!   and the guest clears it by writing `sip.SSIP`, so the monitor must not
//!   re-derive it from a line.
//!
//! # Sstc: the guest's timer is `vstimecmp`
//!
//! With [`Wiring::sstc`] every VM runs with `henvcfg.STCE`. The guest's
//! `stimecmp` writes land in `vstimecmp` (saved and restored with the vCPU,
//! [`super::vscsr::VsCsrs`]) and the hart raises `VSTIP` itself, so the
//! monitor's timer line is not used: a guest that still asks for the SBI
//! timer is served by writing `vstimecmp` ([`set_timer_sstc`]), the same
//! register, so one source drives `VSTIP` whichever way the guest sets it.
//! A vCPU starts with the timer never due ([`super::vscsr::VsCsrs::reset`]).
//!
//! # AIA: one interrupt file per vCPU
//!
//! A hart with the AIA and its IMSIC has, besides its own supervisor file,
//! GEILEN *guest interrupt files* (`hgeie`/`hgeip` bits 1..=GEILEN). A guest
//! whose `hstatus.VGEIN` names file `n` uses it as its IMSIC: its
//! `siselect`/`sireg`/`stopei` (VS-mode `vs*` CSRs) reach that file, a write
//! of an identity to the file's page makes it pending, and `hgeip[n]` raises
//! the guest's `VSEIP` by hardware, while the guest runs, with no exit.
//!
//! * **When a vCPU gets a file.** Lazily, so a guest on the PLIC (the virtual
//!   PLIC of `azos_hv::vplic`) costs nothing and keeps its freedom to move
//!   between harts: on its first use of the IMSIC, that is, its first CSR
//!   access to `siselect`/`sireg`/`stopei` (which `hstateen0` or the missing
//!   `VGEIN` turns into a virtual-instruction exception: [`adoptable`]), or
//!   the first message-signalled line the monitor raises for it
//!   ([`msi_bits`]). The slot comes from [`FilePool`], keyed by the VM's
//!   stage-2 root and the vCPU, and is given back with the VM's tables.
//! * **A vCPU with a file stays on its hart**: the file is the hart's
//!   hardware, its contents (identities pending, enabled, the guest's
//!   threshold) are not copied elsewhere, so an entry on another hart is
//!   refused (`InvalidState`) rather than run with an empty file. The
//!   topology pins such a guest; PLIC guests still move.
//! * **Cleared at the bind.** The file holds the last owner's identities
//!   until it is cleared; the first entry with it clears delivery, threshold,
//!   enables and pendings through `vsiselect`/`vsireg`.
//! * **The guest's identities** are the file's `1..=num-ids`: the guest
//!   programs enables, threshold and delivery itself. The monitor's virtual
//!   devices raise `GuestCtx::irqs` lines `MSI_LINE_BASE..64`, which the
//!   entry sets pending in the file as identities `1..=`[`MSI_IDS`] (line
//!   `MSI_LINE_BASE + id - 1` is identity `id`); lines `0..16` are still
//!   `hvip` bits.
//! * **How a host interrupt reaches a guest.** `Vcpu::inject_msi(id)` on the
//!   vCPU's endpoint, which needs the `WRITE` right of its capability (the
//!   authority every injection needs, checked there and nowhere else): it
//!   makes the line [`msi_line`] pending in the vCPU's record, and the next
//!   entry presents it. A monitor that gives a device to a guest keeps the
//!   device's `Cap<Irq>` bound to its own port and makes that call with the
//!   identity it told the guest when the port delivers the notification. The
//!   kernel does not connect an `Irq` capability to a vCPU by itself: which
//!   device a guest may have is the monitor's policy, in ring 3.
//! * **A vCPU that waits.** Its file is armed in `hgeie` when it exits to
//!   wait ([`FilePool`], `Hart::file_exit`); an identity arriving in it
//!   raises the supervisor guest-external interrupt (cause 12), which the
//!   kernel's trap vector hands to [`sgei_take`]: the file is disarmed and its
//!   owner's thread woken. The hart takes the interrupt once
//!   [`sgei_enable`] ran, which the entry does the first time it probes the
//!   hart's files.
//!
//! # What the boot decides
//!
//! Nothing above is on until [`wire`] is called, and the kernel's boot calls
//! it ([`Wiring::resolve`]) only on a hart where H was confirmed: Sstc from
//! the host timer's own selection (Kconfig `RV_SSTC`), Smstateen from the
//! device tree and a trap-safe `hstateen0` access, the guest-file count from
//! the IMSIC the AIA selection found (Kconfig `RV_AIA`, DTB
//! `guest-index-bits`). Each of them off leaves a guest as it ran before:
//! the SBI timer emulated, no `hstateen0` written, no vCPU holding a file.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::csr::{self, VSEIP, VSSIP, VSTIP};
use super::vscsr::{Caps, VsCsrs};

/// A VS-level interrupt the monitor can pend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VsIrq {
    /// Software (IPI from another vCPU).
    Software,
    /// Timer, without Sstc (with Sstc the hart owns this bit).
    Timer,
    /// External (a virtual device's line).
    External,
}

/// The `hvip` bit of `irq`.
pub const fn hvip_bit(irq: VsIrq) -> u64 {
    match irq {
        VsIrq::Software => VSSIP,
        VsIrq::Timer => VSTIP,
        VsIrq::External => VSEIP,
    }
}

/// `hvip` after pending `irq` / un-pending it.
pub const fn hvip_with(hvip: u64, irq: VsIrq) -> u64 {
    hvip | hvip_bit(irq)
}

pub const fn hvip_without(hvip: u64, irq: VsIrq) -> u64 {
    hvip & !hvip_bit(irq)
}

/// `hvip` with `irq` following a line: pended while `asserted`, un-pended
/// when not. For the level interrupts (`External`, `Timer`); a vCPU entry
/// applies it to the saved `hvip` after the lines changed, a running vCPU's
/// hart gets the same through [`inject`] / [`clear`].
pub const fn hvip_level(hvip: u64, irq: VsIrq, asserted: bool) -> u64 {
    if asserted { hvip_with(hvip, irq) } else { hvip_without(hvip, irq) }
}

/// `vstimecmp` value that never fires.
pub const VSTIMECMP_NEVER: u64 = u64::MAX;

/// The `vstimecmp` for a deadline given in host `time` ticks: the guest's
/// clock reads `time + htimedelta`, so the compare value is shifted by the
/// same delta. [`VSTIMECMP_NEVER`] stays never.
pub const fn guest_deadline(host_deadline: u64, htimedelta: u64) -> u64 {
    if host_deadline == VSTIMECMP_NEVER {
        VSTIMECMP_NEVER
    } else {
        host_deadline.wrapping_add(htimedelta)
    }
}

/// The inverse: the host `time` at which a saved `vstimecmp` expires.
pub const fn host_deadline(vstimecmp: u64, htimedelta: u64) -> u64 {
    if vstimecmp == VSTIMECMP_NEVER {
        VSTIMECMP_NEVER
    } else {
        vstimecmp.wrapping_sub(htimedelta)
    }
}

/// Pend `irq` in the guest running (or next to run) on this hart.
///
/// # Safety
/// H must be [`super::probe::available`]; `irq` must be delegated by
/// `hideleg`, and `Timer` must not be used when `henvcfg.STCE` is set.
#[cfg(target_arch = "riscv64")]
pub unsafe fn inject(irq: VsIrq) {
    // SAFETY: a CSR set; the caller guarantees H.
    unsafe {
        core::arch::asm!("csrs {a}, {v}", a = const super::csr::HVIP, v = in(reg) hvip_bit(irq),
            options(nomem, nostack));
    }
}

/// Un-pend `irq`.
///
/// # Safety
/// As [`inject`].
#[cfg(target_arch = "riscv64")]
pub unsafe fn clear(irq: VsIrq) {
    // SAFETY: a CSR clear; the caller guarantees H.
    unsafe {
        core::arch::asm!("csrc {a}, {v}", a = const super::csr::HVIP, v = in(reg) hvip_bit(irq),
            options(nomem, nostack));
    }
}

/// Program the running guest's timer: `vstimecmp` for a host-time deadline.
///
/// # Safety
/// H and Sstc present (`henvcfg.STCE` set for this VM).
#[cfg(target_arch = "riscv64")]
pub unsafe fn set_guest_timer(host_deadline: u64, htimedelta: u64) {
    // SAFETY: a CSR write; the caller guarantees H and Sstc.
    unsafe {
        core::arch::asm!("csrw {a}, {v}", a = const super::csr::VSTIMECMP,
            v = in(reg) guest_deadline(host_deadline, htimedelta), options(nomem, nostack));
    }
}

// ── what the boot decided ───────────────────────────────────────────────

/// What the boot knows and the guest entry needs, handed over once by
/// [`wire`]. Until then every field is off: no guest runs on Sstc, no
/// `hstateen0` is written and no vCPU gets a guest interrupt file, which is
/// how a guest ran before these paths existed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wiring {
    /// The hart has Sstc and S-mode may use it (what the host's own timer
    /// selection found): every VM runs with `henvcfg.STCE`.
    pub sstc: bool,
    /// The hart has Smstateen (cpu@0's `riscv,isa`): `hstateen0` exists and a
    /// guest may touch only what it grants.
    pub smstateen: bool,
    /// Identities the IMSIC's guest interrupt files implement
    /// (`riscv,num-ids` of the group, which is also the guests' count unless
    /// the device tree says otherwise); 0: no IMSIC, or none with guest
    /// files, and no vCPU gets one.
    pub guest_ids: u32,
}

impl Wiring {
    /// What the boot's facts make of the wiring. Without H nothing is on;
    /// the guest files need the IMSIC to have some (`imsic_guest_files`, from
    /// its `guest-index-bits`) and the AIA to be what the host runs on.
    pub const fn resolve(
        h: bool,
        host_sstc: bool,
        smstateen: bool,
        imsic_ids: u32,
        imsic_guest_files: u32,
    ) -> Wiring {
        if !h {
            return Wiring { sstc: false, smstateen: false, guest_ids: 0 };
        }
        Wiring {
            sstc: host_sstc,
            smstateen,
            guest_ids: if imsic_guest_files > 0 { imsic_ids } else { 0 },
        }
    }
}

static SSTC: AtomicBool = AtomicBool::new(false);
static SMSTATEEN: AtomicBool = AtomicBool::new(false);
static GUEST_IDS: AtomicU32 = AtomicU32::new(0);

/// Record the boot's facts (see [`Wiring`]); the harts of one machine are
/// taken to be uniform, as for [`super::probe::select`].
pub fn wire(w: Wiring) {
    SSTC.store(w.sstc, Ordering::Relaxed);
    SMSTATEEN.store(w.smstateen, Ordering::Relaxed);
    GUEST_IDS.store(w.guest_ids, Ordering::Release);
}

/// What [`wire`] recorded.
pub fn wiring() -> Wiring {
    Wiring {
        sstc: SSTC.load(Ordering::Relaxed),
        smstateen: SMSTATEEN.load(Ordering::Relaxed),
        guest_ids: GUEST_IDS.load(Ordering::Acquire),
    }
}

/// [`Caps`] of a vCPU that does (`guest_file`) or does not hold a guest file.
pub fn caps(guest_file: bool) -> Caps {
    let w = wiring();
    Caps { sstc: w.sstc, smstateen: w.smstateen, aia: w.guest_ids != 0, guest_file }
}

/// The SBI timer call on an Sstc guest: `deadline` (guest time) goes where
/// the guest's own `stimecmp` write would, and the timer interrupt the call
/// is specified to clear is withdrawn from the saved `hvip`.
pub fn set_timer_sstc(vs: &mut VsCsrs, deadline: u64) {
    vs.vstimecmp = deadline;
    vs.hvip = hvip_without(vs.hvip, VsIrq::Timer);
}

// ── message-signalled lines ─────────────────────────────────────────────

/// First `GuestCtx::irqs` line that is an IMSIC identity, not an `hvip` bit.
/// Lines below it are the three VS-level bits (`VSSIP`, `VSTIP`, `VSEIP`) and
/// room for the interrupts the AIA adds to `hvip`.
pub const MSI_LINE_BASE: u32 = 16;
/// Identities a line can carry: `1..=MSI_IDS` (identity 0 does not exist).
pub const MSI_IDS: u32 = u64::BITS - MSI_LINE_BASE;

/// The line that raises identity `id` in a guest's file (`Vcpu::inject_msi`).
pub const fn msi_line(id: u32) -> Option<u32> {
    if id >= 1 && id <= MSI_IDS { Some(id + MSI_LINE_BASE - 1) } else { None }
}

/// The identities `irqs` raises as the word `eip0` holds them (bit `id`):
/// what the entry sets pending in the vCPU's guest file.
pub const fn msi_bits(irqs: u64) -> u64 {
    (irqs >> MSI_LINE_BASE) << 1
}

// ── hstatus.VGEIN ───────────────────────────────────────────────────────

/// `hstatus` selecting guest file `gei` (0: none) and nothing else changed.
pub const fn hstatus_with_vgein(hstatus: u64, gei: u32) -> u64 {
    (hstatus & !csr::HSTATUS_VGEIN) | (((gei as u64) << csr::HSTATUS_VGEIN_SHIFT) & csr::HSTATUS_VGEIN)
}

/// The guest file `hstatus` selects (0: none).
pub const fn vgein_of(hstatus: u64) -> u32 {
    ((hstatus & csr::HSTATUS_VGEIN) >> csr::HSTATUS_VGEIN_SHIFT) as u32
}

// ── the virtual-instruction exception of a guest's first IMSIC access ───

/// `siselect`, `sireg`, `stopei`, `stopi`: the S-level AIA CSRs a guest
/// reaches its interrupt file with (the `vs*` ones when V=1).
const AIA_CSRS: [u64; 4] = [0x150, 0x151, 0x15C, 0xDB0];

/// Is `insn` (`stval` of a virtual-instruction exception) a CSR instruction
/// on one of the AIA's S-level registers?
pub const fn is_aia_csr_access(insn: u64) -> bool {
    let i = insn & 0xFFFF_FFFF;
    if i & 3 != 3 || i & 0x7F != 0x73 {
        return false;
    }
    let f3 = (i >> 12) & 7;
    // 0: ecall/ebreak/sret/..; 4: reserved.
    if f3 == 0 || f3 == 4 {
        return false;
    }
    let c = i >> 20;
    let mut k = 0;
    while k < AIA_CSRS.len() {
        if AIA_CSRS[k] == c {
            return true;
        }
        k += 1;
    }
    false
}

/// Does a virtual-instruction exception with this `stval` mean the guest
/// reached for an interrupt file it has not got? An exception that does not
/// say what trapped (`stval` 0, which the hardware may do) is given the same
/// benefit once: the entry retries and a second trap is a fault.
pub const fn adoptable(stval: u64) -> bool {
    stval == 0 || is_aia_csr_access(stval)
}

// ── the pool of guest interrupt files ───────────────────────────────────

/// Guest files `hstatus.VGEIN` (6 bits) can name; `hgeie` has a bit for each.
pub const GEI_MAX: u32 = 63;

/// Files of one hart the pool tracks: no more than there are files to name
/// and no more than there are vCPUs (`HV_MAX_VCPUS`) to hold them.
pub const POOL_FILES: usize = if (azos_limits::HV_MAX_VCPUS as usize) < GEI_MAX as usize {
    azos_limits::HV_MAX_VCPUS as usize
} else {
    GEI_MAX as usize
};

/// `hgeie` after writing all ones: the file count is the highest bit left
/// (bit 0 is read-only zero), at most [`GEI_MAX`].
pub const fn geilen_from_readback(hgeie: u64) -> u32 {
    let n = (u64::BITS - hgeie.leading_zeros()).saturating_sub(1);
    if n > GEI_MAX { GEI_MAX } else { n }
}

const USED: u64 = 1 << 63;
const ROOT_MASK: u64 = (1 << 48) - 1;

/// The key of the vCPU `vcpu` of the VM whose stage-2 root is `root`.
const fn key(root: u64, vcpu: u8) -> u64 {
    USED | (vcpu as u64) << 48 | (root & ROOT_MASK)
}

/// Who holds a guest file: the VM (by its stage-2 root, which names it for as
/// long as it exists) and the vCPU's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub root: u64,
    pub vcpu: u8,
}

impl Owner {
    /// The word that names this holder (never 0): what the pool stores and
    /// what a lock-free table of vCPUs can compare an interrupt's owner with.
    pub const fn key(self) -> u64 {
        key(self.root, self.vcpu)
    }
}

/// Why a vCPU got no guest file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    /// The hart has none (no IMSIC guest files, or its GEILEN is 0), or it
    /// has not been probed.
    NoFiles,
    /// All the hart's files are in use.
    Full,
    /// A hart id past the pool.
    BadHart,
}

/// The guest interrupt files of every hart and who holds them: one slot per
/// file, 0 free, else the holder's key. A holder is found again (a vCPU
/// restarted by `CPU_ON` after `CPU_OFF` gets the same file, cleared again at
/// its entry) and all of a VM's files are given back with its tables
/// ([`FilePool::release`]).
pub struct FilePool<const HARTS: usize, const FILES: usize> {
    slots: [[AtomicU64; FILES]; HARTS],
    /// GEILEN of each hart, [`UNPROBED`] until its first entry reads it.
    geilen: [AtomicU8; HARTS],
}

const UNPROBED: u8 = u8::MAX;

impl<const HARTS: usize, const FILES: usize> FilePool<HARTS, FILES> {
    pub const fn new() -> Self {
        FilePool {
            slots: [const { [const { AtomicU64::new(0) }; FILES] }; HARTS],
            geilen: [const { AtomicU8::new(UNPROBED) }; HARTS],
        }
    }

    /// Record hart `hart`'s file count, clamped to the files the pool tracks.
    pub fn set_geilen(&self, hart: usize, n: u32) {
        if let Some(g) = self.geilen.get(hart) {
            g.store(n.min(FILES as u32).min(GEI_MAX) as u8, Ordering::Release);
        }
    }

    /// The hart's file count; `None` until it was recorded.
    pub fn geilen(&self, hart: usize) -> Option<u32> {
        match self.geilen.get(hart)?.load(Ordering::Acquire) {
            UNPROBED => None,
            n => Some(n as u32),
        }
    }

    /// The guest file (1..) vCPU `vcpu` of the VM with stage-2 root `root`
    /// holds on `hart`: the one it already has there, else a free one. A file
    /// the same vCPU held on another hart (an earlier run of it) is freed.
    pub fn bind(&self, hart: usize, root: u64, vcpu: u8) -> Result<u32, BindError> {
        let row = self.slots.get(hart).ok_or(BindError::BadHart)?;
        let n = match self.geilen(hart) {
            Some(n) if n > 0 => n as usize,
            _ => return Err(BindError::NoFiles),
        };
        let k = key(root, vcpu);
        let mut mine = None;
        for (h, r) in self.slots.iter().enumerate() {
            for (i, s) in r.iter().enumerate() {
                if s.load(Ordering::Acquire) != k {
                    continue;
                }
                if h == hart && i < n && mine.is_none() {
                    mine = Some(i as u32 + 1);
                } else {
                    s.store(0, Ordering::Release);
                }
            }
        }
        if let Some(g) = mine {
            return Ok(g);
        }
        for (i, s) in row.iter().take(n).enumerate() {
            if s.compare_exchange(0, k, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return Ok(i as u32 + 1);
            }
        }
        Err(BindError::Full)
    }

    /// Give back every file of the VM whose stage-2 root is `root`.
    pub fn release(&self, root: u64) {
        for r in &self.slots {
            for s in r {
                let k = s.load(Ordering::Acquire);
                if k != 0 && k & ROOT_MASK == root & ROOT_MASK {
                    s.store(0, Ordering::Release);
                }
            }
        }
    }

    /// Who holds file `gei` of `hart`.
    pub fn owner(&self, hart: usize, gei: u32) -> Option<Owner> {
        let k = self.slots.get(hart)?.get((gei as usize).checked_sub(1)?)?.load(Ordering::Acquire);
        (k != 0).then_some(Owner { root: k & ROOT_MASK, vcpu: (k >> 48) as u8 })
    }

    /// The vCPUs to wake for a supervisor guest-external interrupt: the
    /// holders of the files `hgeip` shows pending and `hgeie` armed. Returns
    /// the files, so the caller can disarm them.
    pub fn wake(&self, hart: usize, hgeip: u64, hgeie: u64, mut f: impl FnMut(Owner)) -> u64 {
        let mask = hgeip & hgeie & !1;
        let mut m = mask;
        while m != 0 {
            let gei = m.trailing_zeros();
            m &= m - 1;
            if let Some(o) = self.owner(hart, gei) {
                f(o);
            }
        }
        mask
    }
}

/// The machine's pool.
pub static FILES: FilePool<{ azos_limits::NR_CPUS }, POOL_FILES> = FilePool::new();

/// The harts' GEILEN, read from the hart: write all ones to `hgeie`, read
/// back, clear.
///
/// # Safety
/// H must be [`super::probe::available`]; call with the interrupts off (the
/// SGEI handler must not see the transient bits).
#[cfg(target_arch = "riscv64")]
pub unsafe fn geilen_probe() -> u32 {
    let back: u64;
    // SAFETY: only `hgeie` is touched, and it is cleared again.
    unsafe {
        core::arch::asm!(
            "csrw {a}, {ones}",
            "csrr {b}, {a}",
            "csrw {a}, zero",
            a = const csr::HGEIE, ones = in(reg) u64::MAX, b = out(reg) back,
            options(nomem, nostack));
    }
    geilen_from_readback(back)
}

/// Arm file `gei`: while its pending identities include an enabled one the
/// hart raises the guest-external interrupt (if [`sgei_enable`]d).
///
/// # Safety
/// As [`geilen_probe`].
#[cfg(target_arch = "riscv64")]
pub unsafe fn file_arm(gei: u32) {
    // SAFETY: a CSR set; the caller guarantees H.
    unsafe {
        core::arch::asm!("csrs {a}, {v}", a = const csr::HGEIE, v = in(reg) 1u64 << gei, options(nomem, nostack));
    }
}

/// Disarm file `gei`.
///
/// # Safety
/// As [`geilen_probe`].
#[cfg(target_arch = "riscv64")]
pub unsafe fn file_disarm(gei: u32) {
    // SAFETY: a CSR clear; the caller guarantees H.
    unsafe {
        core::arch::asm!("csrc {a}, {v}", a = const csr::HGEIE, v = in(reg) 1u64 << gei, options(nomem, nostack));
    }
}

/// Let this hart take the supervisor guest-external interrupt (`hie.SGEIE`).
/// The kernel's trap vector handles cause 12 by calling [`sgei_take`]; call
/// this on each hart that has guest files (`Hart::guest_files` does, when it
/// probes the hart), never where nothing handles the interrupt: it would be
/// taken for ever.
///
/// # Safety
/// As [`geilen_probe`].
#[cfg(target_arch = "riscv64")]
pub unsafe fn sgei_enable() {
    // SAFETY: a CSR set; the caller guarantees H and the handler.
    unsafe {
        core::arch::asm!("csrs {a}, {v}", a = const csr::HIE, v = in(reg) csr::SGEIP, options(nomem, nostack));
    }
}

/// The handler of the guest-external interrupt on `hart` (the calling hart):
/// calls `wake` for the vCPU of each file with something pending, and disarms
/// those files, which stay disarmed until the vCPU waits again.
///
/// # Safety
/// As [`geilen_probe`].
#[cfg(target_arch = "riscv64")]
pub unsafe fn sgei_take(hart: usize, wake: impl FnMut(Owner)) {
    let (ip, ie): (u64, u64);
    // SAFETY: CSR reads, then a clear of the bits just read.
    unsafe {
        core::arch::asm!("csrr {i}, {p}", "csrr {e}, {q}",
            i = out(reg) ip, e = out(reg) ie, p = const csr::HGEIP, q = const csr::HGEIE,
            options(nomem, nostack));
    }
    let done = FILES.wake(hart, ip, ie, wake);
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("csrc {a}, {v}", a = const csr::HGEIE, v = in(reg) done, options(nomem, nostack));
    }
}
