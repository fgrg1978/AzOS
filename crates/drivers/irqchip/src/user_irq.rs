// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 ownership of riscv64 external interrupt lines — the PLIC/APLIC
//! half of mask-until-ACK (wave 9 IRQ4 item 2; aarch64's GIC half is
//! `azos_arch_aarch64::gic`'s ring-3 section).
//!
//! A line a ring-3 driver bound (`SYS_IRQ_BIND` / `SYS_PORT_BIND_TYPED`) is
//! delivered like this: the external-interrupt handler claims it, MASKS it,
//! completes it, then queues/wakes; the driver's `SYS_DRV_IRQ_ACK` unmasks
//! it. Before this, the handler claimed, dispatched and completed at once and
//! nothing masked, so a level device the driver had not quietened yet was
//! taken again on the handler's return — and the bind never enabled the
//! source at all, so on the PLIC path nothing was delivered in the first
//! place.
//!
//! **The mask.** PLIC: the source's PRIORITY goes to 0 ("never interrupt":
//! a source is delivered only when its priority exceeds the context's
//! threshold, 0 here), and the ACK writes 1 back. This is how Linux's PLIC
//! driver masks (`plic_irq_mask`), and it is chosen over the enable bits for
//! two reasons: priority is global, so any hart's ACK unmasks a line enabled
//! only for the binding hart's context; and the completion `plic::complete`
//! writes requires the source to be ENABLED for the completing context (it
//! re-reads the enable bit and skips the write otherwise, as the PLIC spec
//! lets hardware ignore it), so disabling before completing would leave the
//! source claimed forever. APLIC (AIA): the source's enable
//! (`clrienum`/`setienum`, domain-global), plus a level re-arm on the unmask.
//!
//! **Routing (wave 10 IRQ5).** A ring-3 line is enabled on ONE hart: the
//! hart its binding task is pinned to, or, for an unpinned task, the hart it
//! binds from ([`route_for`]); a hart that does not take supervisor external
//! interrupts falls back to the boot hart. Every hart that takes them says so
//! once ([`hart_ready`]: the boot hart from its interrupt bring-up, each
//! secondary from `smp_secondary_start`, which now sets `sie.SEIE` and gives
//! its PLIC context threshold 0). A later bind by a task on another hart
//! moves the line: PLIC, the old context's enable bit is cleared before the
//! new one is set (Linux `plic_set_affinity`: one effective CPU, invalidate
//! then enable); APLIC, the source's `target` is rewritten (Linux rewrites
//! the MSI message the same way), and an MSI already pending in the old
//! hart's IMSIC file is taken there once — every hart enables the wired
//! identities. The last bind wins, as aarch64's route to the binding PE
//! does. A task that migrates is not followed: a pinned task never does, and
//! Linux likewise keeps an interrupt's effective affinity until someone sets
//! a new one. Lines the kernel enabled for itself stay on the boot hart: its
//! handlers (the UART ring buffer, the virtio MSI wake) are boot-hart paths.
//!
//! Two bitmaps, one bit per source: lines the kernel enabled for itself
//! ([`mark_kernel`], from `irqchip::enable_irq`/`wire_aia_source`), which
//! ring 3 may not bind, and lines ring 3 bound. Plain atomics, no lock: the
//! handler reads the second on every external interrupt.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// The boot hart: where the kernel's own lines are routed, and where a
/// ring-3 line goes when the binder's hart takes no external interrupts.
/// Set once at boot ([`set_boot_hart`]).
static EXT_HART: AtomicU32 = AtomicU32::new(0);

/// Harts that take supervisor external interrupts, one bit per hart id
/// below 32 ([`hart_ready`]). A line is only ever routed to one of these.
static EXT_READY: AtomicU32 = AtomicU32::new(0);

/// "No hart" in [`ROUTE`] and [`TAKEN`].
const NO_HART: u8 = u8::MAX;

/// Sources tracked: the PLIC's largest `MAX_IRQS` (256 on K1).
const LINES: u32 = 256;
const WORDS: usize = (LINES / 32) as usize;

static KERNEL: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];
static USER: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];
/// The hart each ring-3 line is enabled on ([`bind`]); [`NO_HART`] for a line
/// never bound. Kept across a release: the next bind clears the old route.
static ROUTE: [AtomicU8; LINES as usize] = [const { AtomicU8::new(NO_HART) }; LINES as usize];
/// The hart whose external-interrupt handler last took each ring-3 line
/// ([`note_taken`]); [`NO_HART`] since the last bind.
static TAKEN: [AtomicU8; LINES as usize] = [const { AtomicU8::new(NO_HART) }; LINES as usize];
/// Lines whose first delivery since their last bind was already reported
/// ([`first_delivery`]).
static REPORTED: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];
/// Sources whose trigger the device tree gives, and of those the edge ones
/// ([`note_dtb_trigger`], once at boot). Only the APLIC consumes it: a PLIC
/// has no trigger configuration and its binding carries none.
static DTB_DESCRIBED: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];
static DTB_EDGE: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];

fn set(map: &[AtomicU32; WORDS], irq: u32) {
    if let Some(w) = map.get((irq / 32) as usize) {
        w.fetch_or(1 << (irq % 32), Ordering::AcqRel);
    }
}

fn clear(map: &[AtomicU32; WORDS], irq: u32) {
    if let Some(w) = map.get((irq / 32) as usize) {
        w.fetch_and(!(1 << (irq % 32)), Ordering::AcqRel);
    }
}

fn test(map: &[AtomicU32; WORDS], irq: u32) -> bool {
    match map.get((irq / 32) as usize) {
        Some(w) => w.load(Ordering::Acquire) & (1 << (irq % 32)) != 0,
        None => false,
    }
}

/// The largest source number this build's controller has, plus one.
#[cfg(target_arch = "riscv64")]
fn limit() -> u32 {
    crate::plic::MAX_IRQS
}
#[cfg(not(target_arch = "riscv64"))]
fn limit() -> u32 {
    LINES
}

/// Record the trigger the device tree gives source `irq` (boot, from
/// `azos_dtb::dtb_irq_triggers`).
pub fn note_dtb_trigger(irq: u32, edge: bool) {
    set(&DTB_DESCRIBED, irq);
    if edge {
        set(&DTB_EDGE, irq);
    } else {
        clear(&DTB_EDGE, irq);
    }
}

/// `Some(true)` edge, `Some(false)` level, `None` when the device tree did
/// not describe `irq`'s trigger.
pub fn dtb_trigger(irq: u32) -> Option<bool> {
    if test(&DTB_DESCRIBED, irq) {
        Some(test(&DTB_EDGE, irq))
    } else {
        None
    }
}

/// Record `irq` as a line the kernel drives itself. Called by the kernel's
/// own enable paths; the ring-3 bind below does not go through them.
pub fn mark_kernel(irq: u32) {
    set(&KERNEL, irq);
}

/// Whether ring 3 may bind `irq`: a real source (not 0, below the
/// controller's count) the kernel did not enable for itself.
pub fn bindable(irq: u32) -> bool {
    irq != 0 && irq < limit() && !test(&KERNEL, irq)
}

/// Whether a ring-3 driver bound `irq` (the external-interrupt handler's test).
#[inline]
pub fn owned(irq: u32) -> bool {
    test(&USER, irq)
}

/// Record `irq` as ring-3 owned without touching the controller. Host tests
/// only; the kernel goes through [`bind`].
pub fn mark(irq: u32) -> bool {
    if !bindable(irq) {
        return false;
    }
    set(&USER, irq);
    true
}

/// Forget ring-3 ownership of `irq` without touching the controller. Host
/// tests only; the kernel goes through [`release`]. `false` if not owned.
pub fn unmark(irq: u32) -> bool {
    if !owned(irq) {
        return false;
    }
    clear(&USER, irq);
    true
}

/// The hart a ring-3 line bound by a task pinned to `pin` (`< 0`: unpinned)
/// and binding from hart `current` is routed to: the pin, else `current`;
/// either only if it is in `ready` (bit per hart, [`hart_ready`]), else
/// `boot`. Pure: the host suite tests the rule.
pub fn route_for(pin: i8, current: u32, ready: u32, boot: u32) -> u32 {
    let want = if pin >= 0 { pin as u32 } else { current };
    if want < 32 && ready & (1 << want) != 0 {
        want
    } else {
        boot
    }
}

/// [`route_for`] with this boot's ready set and boot hart.
pub fn target_hart(pin: i8, current: u32) -> u32 {
    route_for(pin, current, EXT_READY.load(Ordering::Acquire), boot_hart())
}

/// Record that `hart` takes supervisor external interrupts (bit only; the
/// kernel goes through [`hart_ready`], which also prepares the controller).
pub fn note_hart_ready(hart: u32) {
    if hart < 32 {
        EXT_READY.fetch_or(1 << hart, Ordering::AcqRel);
    }
}

/// The harts [`note_hart_ready`] recorded, one bit each.
pub fn ready_mask() -> u32 {
    EXT_READY.load(Ordering::Acquire)
}

/// The hart ring-3 line `irq` is routed to, `None` if never bound.
pub fn routed_hart(irq: u32) -> Option<u32> {
    match ROUTE.get(irq as usize).map(|r| r.load(Ordering::Acquire)) {
        Some(h) if h != NO_HART => Some(h as u32),
        _ => None,
    }
}

/// Record `irq`'s route (and forget its last delivery: the next one is the
/// first of this binding). Called by [`bind`] after the controller took it.
pub fn set_route(irq: u32, hart: u32) {
    if let Some(r) = ROUTE.get(irq as usize) {
        r.store(hart.min(NO_HART as u32 - 1) as u8, Ordering::Release);
    }
    if let Some(t) = TAKEN.get(irq as usize) {
        t.store(NO_HART, Ordering::Relaxed);
    }
    clear(&REPORTED, irq);
}

/// The external-interrupt handler took ring-3 line `irq` on `hart`. One
/// relaxed store, on the owned branch only.
#[inline]
pub fn note_taken(irq: u32, hart: u32) {
    if let Some(t) = TAKEN.get(irq as usize) {
        t.store(hart.min(NO_HART as u32 - 1) as u8, Ordering::Relaxed);
    }
}

/// The hart that took `irq`'s first delivery since its last bind — once:
/// `Some` on the first call after that delivery, `None` before it and
/// after. `SYS_DRV_IRQ_ACK` reports it.
pub fn first_delivery(irq: u32) -> Option<u32> {
    let h = TAKEN.get(irq as usize)?.load(Ordering::Relaxed);
    if h == NO_HART {
        return None;
    }
    let w = REPORTED.get((irq / 32) as usize)?;
    if w.fetch_or(1 << (irq % 32), Ordering::AcqRel) & (1 << (irq % 32)) != 0 {
        return None;
    }
    Some(h as u32)
}

/// Record the boot hart (from its interrupt bring-up, running ON it) and
/// make it ready ([`hart_ready`]).
#[cfg(target_arch = "riscv64")]
pub fn set_boot_hart(hart: u32) {
    EXT_HART.store(hart, Ordering::Release);
    hart_ready(hart);
}

/// The calling hart — `hart`, after its `irqchip::init` — takes supervisor
/// external interrupts from now on: a ring-3 line may be routed here. On AIA
/// this also enables every wired APLIC source's identity in this hart's IMSIC
/// file, because an IMSIC enable is a CSR write only its own hart can make
/// and a bind runs on whichever hart the binder is on; the APLIC source
/// enable (`setienum`) and `target` remain the gate, so an identity no
/// source targets here never fires. PLIC: a hart without an S-mode context
/// (VF2's S7 monitor core) is never made ready.
#[cfg(target_arch = "riscv64")]
pub fn hart_ready(hart: u32) {
    if crate::irqchip::is_aia() {
        for id in 1..=crate::irqchip::aia_num_sources().min(LINES - 1) {
            crate::imsic::enable(id);
        }
    } else if !crate::plic::has_s_context(hart) {
        return;
    }
    note_hart_ready(hart);
}

/// The boot hart ([`set_boot_hart`]).
pub fn boot_hart() -> u32 {
    EXT_HART.load(Ordering::Acquire)
}

/// Take `irq` for ring 3 and route it to `hart` alone ([`target_hart`]; see
/// the module doc). PLIC: the source must exist (`plic::implemented`, the
/// boot probe), its enable bit on the previous route's context is cleared
/// first, then priority 1 and `hart`'s enable bit. AIA: the APLIC source
/// configured with the trigger `edge` names (`None` = the DTB did not say:
/// level, the only kind QEMU `virt` has) and targeted at `hart` (its IMSIC
/// identity was enabled by [`hart_ready`]). Enables on every call, as the
/// aarch64 bind does: a line left masked by a driver that died before its
/// ACK is live again for the next binder.
///
/// `false` when the line is not ring 3's to take ([`bindable`]) or the
/// controller cannot deliver it: a PLIC source past the implemented ones, an
/// APLIC source past `riscv,num-sources`, or one the firmware did not
/// delegate (the `sourcecfg` read-back is not the mode written). Then
/// nothing is left owned and the route is unchanged; the syscall answers
/// `-ENODEV` and drops the binding it stored.
#[cfg(target_arch = "riscv64")]
pub fn bind(irq: u32, hart: u32, edge: Option<bool>) -> bool {
    if !mark(irq) {
        return false;
    }
    let routed = if crate::irqchip::is_aia() {
        crate::irqchip::wire_aia_user_source(irq, hart, edge.unwrap_or(false)).is_some()
    } else if crate::plic::implemented(irq) && crate::plic::has_s_context(hart) {
        if let Some(old) = routed_hart(irq) {
            if old != hart {
                crate::plic::disable_irq(old, irq);
            }
        }
        crate::plic::set_priority(irq, 1);
        crate::plic::enable_irq(hart, irq);
        true
    } else {
        false
    };
    if !routed {
        let _ = unmark(irq);
        return false;
    }
    set_route(irq, hart);
    true
}

/// Mask `irq` (see the module doc). Called by the handler before it
/// completes a ring-3 line, and by [`release`].
#[cfg(target_arch = "riscv64")]
#[inline]
pub fn mask(irq: u32) {
    if crate::irqchip::is_aia() {
        crate::irqchip::aia_source_enable(irq, false);
    } else {
        crate::plic::set_priority(irq, 0);
    }
}

/// Unmask `irq`: `SYS_DRV_IRQ_ACK`. A level line the driver has not
/// quietened is delivered again at once.
#[cfg(target_arch = "riscv64")]
pub fn unmask(irq: u32) {
    if crate::irqchip::is_aia() {
        crate::irqchip::aia_source_enable(irq, true);
    } else {
        crate::plic::set_priority(irq, 1);
    }
}

/// Hand `irq` back when its last binding went (task exit, through
/// `irq_bind`'s release hook): mask, then forget the ownership — the order
/// `gic::user_spi_release` uses, for the same reason. Not owned: untouched.
#[cfg(target_arch = "riscv64")]
pub fn release(irq: u32) {
    if !owned(irq) {
        return;
    }
    mask(irq);
    let _ = unmark(irq);
}
