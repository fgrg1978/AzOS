// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CSR state a guest owns, and the CSRs that configure one VM.
//!
//! * [`VsCsrs`]: what the guest's supervisor registers hold (`vsstatus`,
//!   `vstvec`, `vsatp`, ...) plus the injected-interrupt word `hvip`, with
//!   Sstc the guest timer `vstimecmp` and with the AIA the guest's
//!   `siselect` (`vsiselect`). Saved when a vCPU stops running on a hart,
//!   restored before it runs again. The contents of the guest's interrupt
//!   file are not here: they stay in the file (see `inject::FilePool`).
//!   `scounteren` and `senvcfg` are on the list although they have no `vs`
//!   copy: a VS-mode guest uses the hart's real ones, so without the swap a
//!   guest write would leak into the host's counter access and CBO/FIOM
//!   settings and into the next VM. `vsip` is not on the list: its writable
//!   bit is the alias of `hvip.VSSIP`, and the rest is derived.
//! * [`VmCtl`]: what the monitor decides per VM and loads before entry:
//!   the G-stage root, the delegation masks, the guest's view of `time`, the
//!   state a guest may touch (`hstateen0`).
//! * [`Caps`]: what the hart gives a guest and which of it this vCPU uses;
//!   it decides which optional slots are saved and which control words load.
//!
//! One macro lists each CSR once and generates the data table, the save
//! code and the restore code, so the three cannot disagree (the host tests
//! check the table against the struct layout and the spec's addresses).

use core::mem::{offset_of, size_of};

use super::csr;

/// One saved CSR: its name, its address, and its index in [`VsCsrs`]'s words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsrSlot {
    pub name: &'static str,
    pub addr: u16,
    pub word: usize,
    /// When the slot exists on the hart.
    pub needs: Needs,
}

/// When a [`CsrSlot`] exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    Always,
    /// Only with Sstc (`vstimecmp`).
    Sstc,
    /// Only on a hart with the AIA's guest interrupt files (`vsiselect`).
    Aia,
}

/// What the hart offers a guest, and what this vCPU uses of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// Sstc: the guest's timer is `vstimecmp` (`henvcfg.STCE`).
    pub sstc: bool,
    /// Smstateen: `hstateen0` exists and gates what a guest may touch.
    pub smstateen: bool,
    /// The hart has the AIA's guest interrupt files (`vsiselect` exists).
    pub aia: bool,
    /// This vCPU has one of them (`hstatus.VGEIN` names it).
    pub guest_file: bool,
}

impl Caps {
    /// Does a slot that needs `n` exist for this vCPU?
    pub const fn has(&self, n: Needs) -> bool {
        match n {
            Needs::Always => true,
            Needs::Sstc => self.sstc,
            Needs::Aia => self.aia,
        }
    }

    /// The `hstateen0` a guest of this vCPU gets, if the hart has Smstateen:
    /// its own `senvcfg` always, and with a guest file the AIA state it
    /// needs to use it. Everything else stays denied.
    pub const fn hstateen0(&self) -> Option<u64> {
        if !self.smstateen {
            return None;
        }
        let aia = if self.guest_file {
            csr::HSTATEEN0_IMSIC | csr::HSTATEEN0_AIA | csr::HSTATEEN0_ISEL
        } else {
            0
        };
        Some(csr::HSTATEEN0_ENVCFG | aia)
    }
}

macro_rules! vs_csrs {
    ($($field:ident = $addr:path, $needs:expr;)*) => {
        /// The guest's `vs*` registers, the S CSRs H does not bank (`scounteren`,
        /// `senvcfg`) and the interrupt-injection word.
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct VsCsrs {
            $(pub $field: u64,)*
        }

        /// Every slot of [`VsCsrs`], in field order.
        pub const VS_CSR_LIST: &[CsrSlot] = &[
            $(CsrSlot {
                name: stringify!($field),
                addr: $addr,
                word: offset_of!(VsCsrs, $field) / size_of::<u64>(),
                needs: $needs,
            },)*
        ];

        #[cfg(target_arch = "riscv64")]
        impl VsCsrs {
            /// Read the guest's CSRs off this hart. A slot `caps` says the
            /// hart (or this vCPU) lacks is not read and its field stays 0.
            ///
            /// # Safety
            /// H must be [`super::probe::available`], and the CSRs must
            /// belong to the guest being stopped (nothing else owns them).
            pub unsafe fn save(&mut self, caps: Caps) {
                $(if caps.has($needs) {
                    let v: u64;
                    // SAFETY: a CSR read; the caller guarantees H and the extension of the slot.
                    unsafe { core::arch::asm!("csrr {v}, {a}", v = out(reg) v, a = const $addr,
                        options(nomem, nostack)) };
                    self.$field = v;
                })*
            }

            /// Write the guest's CSRs onto this hart.
            ///
            /// # Safety
            /// As [`VsCsrs::save`]; the next VS-mode entry on this hart runs
            /// with these values.
            pub unsafe fn restore(&self, caps: Caps) {
                $(if caps.has($needs) {
                    // SAFETY: a CSR write; the caller guarantees H and the extension of the slot.
                    unsafe { core::arch::asm!("csrw {a}, {v}", v = in(reg) self.$field,
                        a = const $addr, options(nomem, nostack)) };
                })*
            }
        }
    };
}

vs_csrs! {
    vsstatus = csr::VSSTATUS, Needs::Always;
    vsie = csr::VSIE, Needs::Always;
    vstvec = csr::VSTVEC, Needs::Always;
    vsscratch = csr::VSSCRATCH, Needs::Always;
    vsepc = csr::VSEPC, Needs::Always;
    vscause = csr::VSCAUSE, Needs::Always;
    vstval = csr::VSTVAL, Needs::Always;
    vsatp = csr::VSATP, Needs::Always;
    scounteren = csr::SCOUNTEREN, Needs::Always;
    senvcfg = csr::SENVCFG, Needs::Always;
    hvip = csr::HVIP, Needs::Always;
    vstimecmp = csr::VSTIMECMP, Needs::Sstc;
    vsiselect = csr::VSISELECT, Needs::Aia;
}

impl VsCsrs {
    /// A vCPU that has not run: every register zero, but the timer never due
    /// (`vstimecmp` 0 would be a deadline in the past the moment Sstc is on).
    pub fn reset() -> VsCsrs {
        VsCsrs { vstimecmp: u64::MAX, ..VsCsrs::default() }
    }
}

/// The per-VM control registers, loaded as one set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmCtl {
    /// `hgatp`: [`super::gstage::GStage::hgatp`].
    pub hgatp: u64,
    pub hedeleg: u64,
    pub hideleg: u64,
    /// The guest's `time` is the host's plus this (wrapping).
    pub htimedelta: u64,
    pub hcounteren: u64,
    /// With Sstc: `STCE` makes `vstimecmp` the guest's timer.
    pub henvcfg: u64,
    /// With Smstateen: what the guest may touch ([`Caps::hstateen0`]).
    pub hstateen0: Option<u64>,
}

impl VmCtl {
    /// The usual VM: the guest OS handles its own page faults, user ecalls
    /// and VS interrupts; it reads `time`; with Sstc it programs
    /// `vstimecmp` itself.
    pub const fn new(hgatp: u64, htimedelta: u64, caps: Caps) -> VmCtl {
        VmCtl {
            hgatp,
            hedeleg: csr::HEDELEG_GUEST,
            hideleg: csr::HIDELEG_GUEST,
            htimedelta,
            hcounteren: csr::HCOUNTEREN_TM,
            henvcfg: if caps.sstc { csr::HENVCFG_STCE } else { 0 },
            hstateen0: caps.hstateen0(),
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl VmCtl {
    /// Make this VM current on this hart. Does not fence: the caller issues
    /// `hfence.gvma` when the VMID's tables changed.
    ///
    /// # Safety
    /// H must be [`super::probe::available`]; `hgatp` must name a live
    /// G-stage root, which must stay alive while the VM runs here.
    pub unsafe fn load(&self) {
        macro_rules! w {
            ($a:expr, $v:expr) => {
                // SAFETY: a CSR write; the caller guarantees H.
                unsafe { core::arch::asm!("csrw {a}, {v}", v = in(reg) $v, a = const $a,
                    options(nomem, nostack)) }
            };
        }
        w!(csr::HEDELEG, self.hedeleg);
        w!(csr::HIDELEG, self.hideleg);
        w!(csr::HTIMEDELTA, self.htimedelta);
        w!(csr::HCOUNTEREN, self.hcounteren);
        w!(csr::HENVCFG, self.henvcfg);
        if let Some(v) = self.hstateen0 {
            w!(csr::HSTATEEN0, v);
        }
        w!(csr::HGATP, self.hgatp);
    }
}
