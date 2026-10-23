// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// GPIO driver — port of kernel/drivers/gpio.c + kernel/include/gpio.h
///
/// QEMU:  in-memory simulation (no hardware on QEMU virt).
/// VF2:   StarFive JH7110 sys_iomux GPIO controller — real MMIO.
/// K1:    SpacemiT `spacemit,k1-gpio` — real MMIO, register-level core in
///        [`crate::gpio_k1`].
///
/// Every module also takes the edges of ONE input line by interrupt, the
/// kill switch's (`azos_actuation::kill_switch`): [`gpio_edge_arm`] and
/// [`gpio_edge_rearm`] from its task, [`gpio_edge_irq`] from the interrupt
/// handler. The handler acknowledges and masks the pin, stamps the edge and
/// wakes the task ([`set_edge_waker`]); the task samples the level, debounces
/// it (`crate::debounce`) and unmasks the pin again. The simulation takes its
/// edges from [`gpio_inject`], the circuit QEMU does not model.
pub const GPIO_MAX_PINS: usize = 64;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as EdgeOrdering};

/// What the device tree says about an input pin: a `gpio-keys` child whose
/// `gpios` names this controller (the Linux binding,
/// `Documentation/devicetree/bindings/input/gpio-keys.yaml`). Recorded by the
/// kernel when it binds the controller ([`gpio_describe_key`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyLine {
    /// The specifier's `GPIO_ACTIVE_LOW` flag (`dt-bindings/gpio/gpio.h`).
    pub active_low: bool,
    /// `debounce-interval`, in ms (the binding's default, 5, when absent).
    pub debounce_ms: u32,
}

/// The specifier flag `GPIO_ACTIVE_LOW` (`include/dt-bindings/gpio/gpio.h`).
pub const GPIO_ACTIVE_LOW: u32 = 1;
/// `gpio-keys`' `debounce-interval` when the child has none.
pub const GPIO_KEYS_DEBOUNCE_MS_DEFAULT: u32 = 5;

static KEY_DESCRIBED: AtomicU64 = AtomicU64::new(0);
static KEY_ACTIVE_LOW: AtomicU64 = AtomicU64::new(0);
static KEY_DEBOUNCE_MS: [AtomicU32; GPIO_MAX_PINS] = [const { AtomicU32::new(0) }; GPIO_MAX_PINS];

/// Record the tree's description of `pin`. `false` for a pin the kernel does
/// not expose.
pub fn gpio_describe_key(pin: u32, key: KeyLine) -> bool {
    if pin as usize >= GPIO_MAX_PINS {
        return false;
    }
    let bit = 1u64 << pin;
    KEY_DEBOUNCE_MS[pin as usize].store(key.debounce_ms, EdgeOrdering::Relaxed);
    if key.active_low {
        KEY_ACTIVE_LOW.fetch_or(bit, EdgeOrdering::Relaxed);
    } else {
        KEY_ACTIVE_LOW.fetch_and(!bit, EdgeOrdering::Relaxed);
    }
    KEY_DESCRIBED.fetch_or(bit, EdgeOrdering::Release);
    true
}

/// The tree's description of `pin`, `None` when the tree has none.
pub fn gpio_key(pin: u32) -> Option<KeyLine> {
    if pin as usize >= GPIO_MAX_PINS || KEY_DESCRIBED.load(EdgeOrdering::Acquire) & (1u64 << pin) == 0 {
        return None;
    }
    Some(KeyLine {
        active_low: KEY_ACTIVE_LOW.load(EdgeOrdering::Relaxed) & (1u64 << pin) != 0,
        debounce_ms: KEY_DEBOUNCE_MS[pin as usize].load(EdgeOrdering::Relaxed),
    })
}

/// How the armed line's edges arrive ([`gpio_edge_arm`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeMode {
    /// By interrupt (on the simulation: by [`gpio_inject`]).
    Interrupt,
    /// Not at all: no controller line is routed, so the caller samples on its
    /// own period only.
    Polled,
}

azos_common::ro_hook! {
    /// Wakes the task that armed the line (interrupt context); `true` when a
    /// task was made ready. Installed once by the kernel at boot.
    static EDGE_WAKER: fn() -> bool;
}

/// Install the edge's wake (the kernel, at boot, with the kill switch's).
pub fn set_edge_waker(wake: fn() -> bool) {
    EDGE_WAKER.set(wake);
}

/// No pin armed.
const NO_PIN: u32 = u32::MAX;
/// The armed pin, [`NO_PIN`] while none is.
static EDGE_PIN: AtomicU32 = AtomicU32::new(NO_PIN);
/// When the last edge was taken (timebase ticks), and how many were.
static EDGE_STAMP: AtomicU64 = AtomicU64::new(0);
static EDGE_COUNT: AtomicU32 = AtomicU32::new(0);

/// An edge of the armed pin was taken (acknowledged and masked): stamp it and
/// wake its task. Interrupt context, or the simulation's injector.
fn edge_taken() -> bool {
    EDGE_STAMP.store(azos_drv_sys::timebase::now(), EdgeOrdering::Relaxed);
    EDGE_COUNT.fetch_add(1, EdgeOrdering::Release);
    EDGE_WAKER.get().is_some_and(|wake| wake())
}

/// The last edge taken: (`timebase::now()` when it was, edges taken so far).
pub fn gpio_edge_stamp() -> (u64, u32) {
    let n = EDGE_COUNT.load(EdgeOrdering::Acquire);
    (EDGE_STAMP.load(EdgeOrdering::Relaxed), n)
}

/// The armed pin, if any.
#[inline(always)]
fn edge_pin() -> Option<u32> {
    match EDGE_PIN.load(EdgeOrdering::Acquire) {
        NO_PIN => None,
        p => Some(p),
    }
}

/// GPIO pin direction.
#[derive(Clone, Copy, PartialEq)]
pub enum GpioDir {
    Input  = 0,
    Output = 1,
}

// ── QEMU: in-memory simulation ────────────────────────────────────────────────

#[cfg(not(any(feature = "vf2", feature = "k1")))]
mod sim {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    // One atomic per pin and per field: a write is one store, so the kernel's
    // own stop (`gpio_write_panic`, used by the panic handler and by the
    // motor layer's safe-state entry) needs no lock and cannot tear a
    // concurrent writer's update of the same pin or of its neighbours.
    static VALUE: [AtomicU8; GPIO_MAX_PINS] = [const { AtomicU8::new(0) }; GPIO_MAX_PINS];
    static OUTPUT: [AtomicBool; GPIO_MAX_PINS] = [const { AtomicBool::new(false) }; GPIO_MAX_PINS];
    static VALID: [AtomicBool; GPIO_MAX_PINS] = [const { AtomicBool::new(false) }; GPIO_MAX_PINS];

    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        OUTPUT[pin as usize].store(dir == GpioDir::Output, Ordering::Release);
        VALID[pin as usize].store(true, Ordering::Release);
        0
    }

    pub fn gpio_read(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        if !VALID[pin as usize].load(Ordering::Acquire) { return -1; }
        VALUE[pin as usize].load(Ordering::Acquire) as i32
    }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        if !OUTPUT[pin as usize].load(Ordering::Acquire) { return -1; }
        VALUE[pin as usize].store((val & 1) as u8, Ordering::Release);
        0
    }

    pub fn gpio_toggle(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        if !OUTPUT[pin as usize].load(Ordering::Acquire) { return -1; }
        VALUE[pin as usize].fetch_xor(1, Ordering::AcqRel);
        0
    }

    /// Emergency GPIO write for the panic handler and the kernel's safe-state
    /// drive: one store to the pin's own atomic, no lock, so it never waits
    /// on a writer that is stalled and never tears another pin's state.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        gpio_write(pin, val)
    }

    // The edge model: the controller's both-edge detection on the armed pin,
    // its latch and its mask, as the boards' blocks have them (an edge while
    // masked stays latched and is taken on the unmask). One lock, interrupts
    // off, for the three words together; the wake runs after it.
    static EDGE_LOCK: azos_sync::SpinLock<()> = azos_sync::SpinLock::new(());
    static EDGE_DETECT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static EDGE_LATCHED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static EDGE_UNMASKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    /// Under `EDGE_LOCK`: take `pin`'s latched edge if it is unmasked.
    fn edge_claim(bit: u64) -> bool {
        if EDGE_LATCHED.load(Ordering::Relaxed) & EDGE_UNMASKED.load(Ordering::Relaxed) & bit == 0 {
            return false;
        }
        EDGE_LATCHED.fetch_and(!bit, Ordering::Relaxed);
        EDGE_UNMASKED.fetch_and(!bit, Ordering::Relaxed);
        true
    }

    /// The outside drives input `pin` to `high`: the circuit QEMU does not
    /// model (a switch and its pull-up). An edge on the armed pin is taken as
    /// the boards' interrupt handler takes it. -1 for an output pin (this
    /// side drives it) or a pin the kernel does not expose.
    pub fn gpio_inject(pin: u32, high: bool) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || OUTPUT[pin as usize].load(Ordering::Acquire) {
            return -1;
        }
        let bit = 1u64 << pin;
        let taken = {
            let _g = EDGE_LOCK.lock_irqsave();
            let was = VALUE[pin as usize].swap(high as u8, Ordering::AcqRel) != 0;
            if was != high && EDGE_DETECT.load(Ordering::Relaxed) & bit != 0 {
                EDGE_LATCHED.fetch_or(bit, Ordering::Relaxed);
            }
            edge_claim(bit)
        };
        if taken {
            super::edge_taken();
        }
        0
    }

    /// No controller line to route: the model delivers its edges itself.
    pub fn gpio_irq_route(_enable: impl FnOnce(u32) -> bool) -> Option<u32> {
        None
    }

    /// No controller line, so never one of its interrupts.
    pub fn gpio_edge_irq(_line: u32) -> Option<bool> {
        None
    }

    /// Make `pin` the armed input: both edges detected, nothing latched,
    /// unmasked. Any previously armed pin is disarmed.
    pub fn gpio_edge_arm(pin: u32) -> Option<EdgeMode> {
        if pin as usize >= GPIO_MAX_PINS || gpio_set_direction(pin, GpioDir::Input) != 0 {
            return None;
        }
        let bit = 1u64 << pin;
        let _g = EDGE_LOCK.lock_irqsave();
        EDGE_DETECT.store(bit, Ordering::Relaxed);
        EDGE_LATCHED.store(0, Ordering::Relaxed);
        EDGE_UNMASKED.store(bit, Ordering::Relaxed);
        super::EDGE_PIN.store(pin, Ordering::Release);
        Some(EdgeMode::Interrupt)
    }

    /// Unmask the armed pin after its task sampled it; an edge latched while
    /// it was masked is taken now.
    pub fn gpio_edge_rearm(pin: u32) {
        if super::edge_pin() != Some(pin) {
            return;
        }
        let bit = 1u64 << pin;
        let taken = {
            let _g = EDGE_LOCK.lock_irqsave();
            EDGE_UNMASKED.fetch_or(bit, Ordering::Relaxed);
            edge_claim(bit)
        };
        if taken {
            super::edge_taken();
        }
    }

    /// Stop taking `pin`'s edges.
    pub fn gpio_edge_disarm(pin: u32) {
        if super::EDGE_PIN.compare_exchange(pin, super::NO_PIN, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return;
        }
        let _g = EDGE_LOCK.lock_irqsave();
        EDGE_DETECT.store(0, Ordering::Relaxed);
        EDGE_LATCHED.store(0, Ordering::Relaxed);
        EDGE_UNMASKED.store(0, Ordering::Relaxed);
    }

    /// The simulation has no device-tree specifier.
    pub fn gpio_specifier(_cells: &[u32]) -> Option<(u32, u32)> {
        None
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub use sim::*;

// ── VisionFive 2 / JH7110: real MMIO GPIO ────────────────────────────────────
//
// **U05-1 correction, 2026-09-26.** JH7110 `sysgpio: pinctrl@13040000`
// (`compatible = "starfive,jh7110-sys-pinctrl"`) is NOT a bit-per-pin GPIO
// controller — the model this module used to implement (`GPIOOUT0`/
// `GPIOOEN0`/`GPIOIN0`, one bit per pin, two 32-bit banks). It is a pin
// MULTIPLEXER: `DOUT`/`DOEN` are byte-per-pin arrays that each select which
// of the SoC's internal output/output-enable *signal sources* drives a
// given physical pin (7 and 6 significant bits respectively — far more
// signal sources than 64 pins), and reading a pin's live level is a
// SEPARATE bit-per-pin array (`GPIOIN`). Confirmed against Linux mainline
// `drivers/pinctrl/starfive/pinctrl-starfive-jh7110-sys.c` (register
// offsets: `JH7110_SYS_DOEN 0x000`, `JH7110_SYS_DOUT 0x040`, `JH7110_SYS_GPI
// 0x080`, `JH7110_SYS_GPIOIN 0x118`) and `pinctrl-starfive-jh7110.c`'s
// `jh7110_gpio_set`/`jh7110_gpio_get`/`jh7110_gpio_direction_output` (byte
// offset `4*(pin/4)`, bit-shift `8*(pin%4)` within that word for
// DOUT/DOEN; word `4*(pin/32)`, bit `pin%32` for GPIOIN). The two fixed
// "signal" values used for plain GPIO output are `GPOUT_LOW = 0` /
// `GPOUT_HIGH = 1`; the two fixed output-enable selections are
// `GPOEN_ENABLE = 0` (output) / `GPOEN_DISABLE = 1` (input) — from
// `include/dt-bindings/pinctrl/starfive,jh7110-pinctrl.h`.
//
// The previous model's `GPIO_OEN0`/`GPIO_DIN0` constants
// (`platform::hw::GPIO_OEN0 = 0x044`, `GPIO_DIN0 = 0x050`) pointed at
// neither real register: `gpio_init` wrote `0xFFFF_FFFF` into bytes 4-7 and
// 12-15 of the `DOUT` array (selecting output-signal-source 127 on four
// pins, not "set to input"), and every `gpio_write`/`gpio_read` flipped one
// mux-selection bit rather than the pin's actual output value or reading
// its actual input level. The `DOUT` offset (0x040) was, by coincidence,
// already the right register.

#[cfg(feature = "vf2")]
mod mmio {
    use super::*;
    use crate::gpio_jh7110_irq::{Jh7110Bus, Jh7110Irq};
    use azos_drv_base::window::{Taken, Window};
    use azos_sync::SpinLock;
    use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, Ordering};

    /// Register offsets in the pad controller's window (`pinctrl-starfive-
    /// jh7110-sys.c`: `JH7110_SYS_DOEN`, `JH7110_SYS_DOUT`, `JH7110_SYS_GPIOIN`).
    const DOEN:   usize = 0x000;
    const DOUT:   usize = 0x040;
    const GPIOIN: usize = 0x118;

    /// The `starfive,jh7110-sys-pinctrl` window, attached when the hardware
    /// bus binds the node (`gpio_attach`). Unbound: no GPIO, every entry point
    /// answers -1 and the panic-time drive touches nothing.
    static WINDOW: Window = Window::new();

    /// `dout_mask`/`doen_mask` fixed signal-source selections for plain
    /// GPIO use (`include/dt-bindings/pinctrl/starfive,jh7110-pinctrl.h`).
    const GPOUT_LOW:     u32 = 0;
    const GPOUT_HIGH:    u32 = 1;
    const GPOEN_ENABLE:  u32 = 0; // output
    const GPOEN_DISABLE: u32 = 1; // input (tri-state)
    /// `dout_mask = GENMASK(6,0)`.
    const DOUT_FIELD_MASK: u32 = 0x7F;
    /// `doen_mask = GENMASK(5,0)`.
    const DOEN_FIELD_MASK: u32 = 0x3F;

    // `DOUT`/`DOEN` are byte-per-pin read-modify-write words (4 pins per
    // 32-bit register): set_direction/write/toggle all read-modify-write
    // one byte of a word up to three other pins also live in. Bank 0 (pins
    // 0-31) is shared by motors, the payload actuator and the camera, so
    // two harts touching different pins in the same word can race. Mirrors
    // the lock already used by the QEMU `sim` path above.
    static GPIO_MMIO_LOCK: SpinLock<()> = SpinLock::new(());

    /// Pins a lock-free write ([`gpio_write_panic`]: the panic handler and the
    /// kernel's safe-state drive) put to `STOP_VAL` without the lock, and no
    /// locked write has superseded since. That write is a read-modify-write of
    /// a word shared with three other pins, so a locked writer that read the
    /// word before it and writes it back after would restore the old byte and
    /// lose the stop. Every locked writer therefore re-asserts the pending
    /// pins after its own write, still under the lock; a locked write of a
    /// pin is a newer command for that pin and clears its bit first.
    static STOP_PENDING: AtomicU64 = AtomicU64::new(0);
    static STOP_VAL: AtomicU64 = AtomicU64::new(0);

    /// Callers have checked [`WINDOW`] is bound (`bound()`); an unbound read
    /// is 0 and an unbound write goes nowhere, so a path that missed the
    /// check still cannot reach an address that is not the controller's.
    #[inline(always)]
    fn reg_read32(offset: usize) -> u32 {
        match WINDOW.base() {
            // SAFETY: the base the bus bound and the kernel mapped.
            Some(b) => unsafe { core::ptr::read_volatile((b + offset) as *const u32) },
            None => 0,
        }
    }

    #[inline(always)]
    fn reg_write32(offset: usize, val: u32) {
        if let Some(b) = WINDOW.base() {
            // SAFETY: as `reg_read32`.
            unsafe { core::ptr::write_volatile((b + offset) as *mut u32, val) }
        }
    }

    #[inline(always)]
    fn bound() -> bool {
        WINDOW.base().is_some()
    }

    /// Whether a controller is attached: the tree had the pad controller's
    /// node and the bus bound it. Without it there is no e-stop line to drive.
    pub fn gpio_has_hardware() -> bool {
        bound()
    }

    /// Byte-per-pin word offset and bit-shift for the `DOUT`/`DOEN` arrays.
    /// Pure, host-tested — see `dout_doen_word_and_shift` calls in
    /// `tests/host/drivers-tests` (or the scratch harness this pass used where
    /// that crate could not be edited). Confirmed against
    /// `pinctrl-starfive-jh7110.c`'s `jh7110_gpio_set`
    /// (`offset = 4 * (gpio / 4); shift = 8 * (gpio % 4);`).
    #[inline(always)]
    pub const fn dout_doen_word_and_shift(pin: u32) -> (usize, u32) {
        (4 * (pin as usize / 4), 8 * (pin % 4))
    }

    /// Word offset and bit for the bit-per-pin `GPIOIN` array. Confirmed
    /// against `jh7110_gpio_get` (`sfp->base + info->gpioin_reg_base + 4 *
    /// (gpio / 32)`, `BIT(gpio % 32)`).
    #[inline(always)]
    pub const fn gpioin_word_and_bit(pin: u32) -> (usize, u32) {
        ((pin as usize / 32) * 4, pin % 32)
    }

    /// Read-modify-write the `DOUT` byte of `pin` to the plain level `val`.
    /// The caller holds `GPIO_MMIO_LOCK`, or is `gpio_write_panic`.
    fn dout_write(pin: u32, val: u32) {
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOUT_FIELD_MASK << shift;
        let sel = if val & 1 != 0 { GPOUT_HIGH } else { GPOUT_LOW };
        let cur = reg_read32(DOUT + word);
        reg_write32(DOUT + word, (cur & !mask) | ((sel << shift) & mask));
    }

    /// Re-assert every pending stop (see [`STOP_PENDING`]). Under the lock.
    fn reassert_stops() {
        fence(Ordering::SeqCst);
        let mut pend = STOP_PENDING.load(Ordering::Acquire);
        let val = STOP_VAL.load(Ordering::Acquire);
        while pend != 0 {
            let pin = pend.trailing_zeros();
            pend &= pend - 1;
            dout_write(pin, (val >> pin) as u32);
        }
    }

    /// A locked write of `pin`: supersedes a pending stop of that pin.
    fn supersede_stop(pin: u32) {
        STOP_PENDING.fetch_and(!(1u64 << pin), Ordering::AcqRel);
    }

    /// Hand the driver the controller the hardware bus bound at `base`, and
    /// the node's interrupt `line` (0: the node names none). `Err` when a
    /// controller is already attached.
    ///
    /// **Nothing is written.** This used to set every pad's `DOEN` byte to
    /// "input", and the window is the whole pad multiplexer, not a bank of
    /// spare GPIOs: the pads the firmware routed to a peripheral (UART0's TX,
    /// the I2C and PWM pads) had their output enable taken away, so the
    /// console went silent at the GPIO bind. A pin is now an input or an
    /// output when its user says so (`gpio_set_direction`: the motors, the
    /// payload, the camera power, the kill switch's [`gpio_edge_arm`]), and
    /// every other pad keeps what the firmware gave it, as the K1 module
    /// already did.
    pub fn gpio_attach(base: usize, line: u32) -> Result<(), Taken> {
        WINDOW.attach(base)?;
        LINE.store(line, Ordering::Release);
        Ok(())
    }

    // ── The edge interrupt (`crate::gpio_jh7110_irq`) ───────────────────────

    /// The node's interrupt line, 0 while none is known.
    static LINE: AtomicU32 = AtomicU32::new(0);
    /// The kernel routed [`LINE`] to a CPU ([`gpio_irq_route`]).
    static ROUTED: AtomicBool = AtomicBool::new(false);
    /// Serialises the interrupt registers' read-modify-writes (each word is
    /// shared by 32 pins), between the kill switch's task and the interrupt
    /// handler: taken with interrupts off everywhere. Not `GPIO_MMIO_LOCK`:
    /// the words are not the level path's, and the handler must not wait on a
    /// level writer.
    static IRQ_LOCK: SpinLock<()> = SpinLock::new(());

    struct Mmio;

    impl Jh7110Bus for Mmio {
        #[inline(always)]
        fn read32(&mut self, off: usize) -> u32 {
            reg_read32(off)
        }
        #[inline(always)]
        fn write32(&mut self, off: usize, v: u32) {
            reg_write32(off, v)
        }
    }

    /// Mask every pin's interrupt and clear what the firmware left latched,
    /// then have the kernel route the controller's line (`enable`). The line
    /// when it was routed.
    pub fn gpio_irq_route(enable: impl FnOnce(u32) -> bool) -> Option<u32> {
        let line = LINE.load(Ordering::Acquire);
        if !bound() || line == 0 {
            return None;
        }
        {
            let _g = IRQ_LOCK.lock_irqsave();
            Jh7110Irq::new(Mmio).init();
        }
        if !enable(line) {
            return None;
        }
        ROUTED.store(true, Ordering::Release);
        Some(line)
    }

    /// The interrupt handler's arm for `line` (interrupt context): `None` when
    /// it is not the controller's; otherwise take the armed pin's edge
    /// (acknowledge, mask, stamp, wake its task), `Some(true)` when a task was
    /// made ready.
    pub fn gpio_edge_irq(line: u32) -> Option<bool> {
        if !ROUTED.load(Ordering::Acquire) || line != LINE.load(Ordering::Relaxed) {
            return None;
        }
        let Some(pin) = edge_pin() else { return Some(false) };
        let taken = {
            let _g = IRQ_LOCK.lock_irqsave();
            Jh7110Irq::new(Mmio).take(pin)
        };
        Some(taken && edge_taken())
    }

    /// Make `pin` the armed input: an input, both edges detected, its stale
    /// edge cleared, unmasked; any previously armed pin masked. `Polled` when
    /// the line is not routed (the caller then samples on its own period).
    pub fn gpio_edge_arm(pin: u32) -> Option<EdgeMode> {
        if pin as usize >= GPIO_MAX_PINS || gpio_set_direction(pin, GpioDir::Input) != 0 {
            return None;
        }
        if let Some(old) = edge_pin() {
            gpio_edge_disarm(old);
        }
        if !ROUTED.load(Ordering::Acquire) {
            super::EDGE_PIN.store(pin, Ordering::Release);
            return Some(EdgeMode::Polled);
        }
        let _g = IRQ_LOCK.lock_irqsave();
        let mut c = Jh7110Irq::new(Mmio);
        c.set_both_edges(pin);
        c.ack(pin);
        super::EDGE_PIN.store(pin, Ordering::Release);
        c.set_unmasked(pin, true);
        Some(EdgeMode::Interrupt)
    }

    /// Unmask the armed pin after its task sampled it; an edge latched while
    /// it was masked raises the line now.
    pub fn gpio_edge_rearm(pin: u32) {
        if edge_pin() != Some(pin) || !ROUTED.load(Ordering::Acquire) {
            return;
        }
        let _g = IRQ_LOCK.lock_irqsave();
        Jh7110Irq::new(Mmio).set_unmasked(pin, true);
    }

    /// Stop taking `pin`'s edges.
    pub fn gpio_edge_disarm(pin: u32) {
        if super::EDGE_PIN.compare_exchange(pin, super::NO_PIN, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return;
        }
        if ROUTED.load(Ordering::Acquire) {
            let _g = IRQ_LOCK.lock_irqsave();
            Jh7110Irq::new(Mmio).set_unmasked(pin, false);
        }
    }

    /// A `gpios` specifier of this controller (`#gpio-cells = <2>`: the pin,
    /// then the flags) as (pin, flags).
    pub fn gpio_specifier(cells: &[u32]) -> Option<(u32, u32)> {
        match *cells {
            [pin, flags] if (pin as usize) < GPIO_MAX_PINS => Some((pin, flags)),
            _ => None,
        }
    }

    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || !bound() { return -1; }
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOEN_FIELD_MASK << shift;
        let sel = match dir {
            GpioDir::Output => GPOEN_ENABLE,
            GpioDir::Input  => GPOEN_DISABLE,
        };
        let _guard = GPIO_MMIO_LOCK.lock();
        let cur = reg_read32(DOEN + word);
        reg_write32(DOEN + word, (cur & !mask) | ((sel << shift) & mask));
        0
    }

    pub fn gpio_read(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || !bound() { return -1; }
        let (word, bit) = gpioin_word_and_bit(pin);
        ((reg_read32(GPIOIN + word) >> bit) & 1) as i32
    }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || !bound() { return -1; }
        let _guard = GPIO_MMIO_LOCK.lock();
        supersede_stop(pin);
        dout_write(pin, val);
        reassert_stops();
        0
    }

    pub fn gpio_toggle(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || !bound() { return -1; }
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOUT_FIELD_MASK << shift;
        let _guard = GPIO_MMIO_LOCK.lock();
        supersede_stop(pin);
        let cur = reg_read32(DOUT + word);
        let now_high = (cur >> shift) & DOUT_FIELD_MASK == GPOUT_HIGH;
        let sel = if now_high { GPOUT_LOW } else { GPOUT_HIGH };
        reg_write32(DOUT + word, (cur & !mask) | ((sel << shift) & mask));
        reassert_stops();
        0
    }

    /// Emergency GPIO write for the panic handler and the kernel's safe-state
    /// drive: it does not take `GPIO_MMIO_LOCK`, because a stalled holder (or
    /// a panic on another hart) would make it spin forever.
    ///
    /// The pin is marked pending first ([`STOP_PENDING`]), then written; a
    /// locked writer that was inside its read-modify-write re-asserts it when
    /// it is done, and the write is read back and repeated (bounded) in case
    /// another lock-free writer clobbered it with a stale word. So the stop
    /// is not lost to a neighbour pin's write, whichever order they land in.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS || !bound() { return -1; }
        let bit = 1u64 << pin;
        if val & 1 != 0 { STOP_VAL.fetch_or(bit, Ordering::AcqRel); } else { STOP_VAL.fetch_and(!bit, Ordering::AcqRel); }
        STOP_PENDING.fetch_or(bit, Ordering::AcqRel);
        fence(Ordering::SeqCst);
        let (word, shift) = dout_doen_word_and_shift(pin);
        let want = if val & 1 != 0 { GPOUT_HIGH } else { GPOUT_LOW };
        for _ in 0..4 {
            dout_write(pin, val);
            if (reg_read32(DOUT + word) >> shift) & DOUT_FIELD_MASK == want { break; }
        }
        0
    }

}

#[cfg(feature = "vf2")]
pub use mmio::*;

// ── SpacemiT K1: `spacemit,k1-gpio` ──────────────────────────────────────────
//
// The registers and their offsets are `gpio_k1.rs`'s (from Linux
// `drivers/gpio/gpio-spacemit-k1.c`); this module is the part only the kernel
// can do: hold the window the hardware bus bound, give the core its bus, and
// keep the `gpio_*` entry points the VF2 module has.
//
// Differences from the VF2 module, all of them the hardware's:
//
// * a level write is ONE store to a set or a clear register (`GPSR`/`GPCR`),
//   so there is no software lock on the level path and no pending-stop
//   bookkeeping: `gpio_write_panic` IS `gpio_write`, and a neighbour pin's
//   write cannot undo it;
// * only a direction change is a read-modify-write (`GPDR`), under
//   `DIR_LOCK`;
// * attach writes nothing: the pins keep the firmware's direction and level
//   (the board's reset and power-enable lines are driven by U-Boot; the VF2
//   module's attach writes nothing either, since it stopped tri-stating the
//   pads);
// * the edge interrupt's mask is per bank and its detect enables are set and
//   clear registers, so arming takes one store per edge and only the mask is
//   a read-modify-write (under `IRQ_LOCK`);
// * the controller has 128 pins, the kernel's pin space is `GPIO_MAX_PINS`
//   (64, `azos_devif::gpio::PINS`): pins 64..127 (bank 2 and 3, among them the
//   BPI-F3's user LED, GPIO 96) are not reachable until that constant moves.

#[cfg(feature = "k1")]
mod k1 {
    use super::*;
    use crate::gpio_k1::{K1Gpio, K1GpioBus, PINS, PINS_PER_BANK};
    use azos_drv_base::window::{Taken, Window};
    use azos_sync::SpinLock;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // The kernel's pin space must fit in the controller's.
    const _: () = assert!(GPIO_MAX_PINS as u32 <= PINS, "GPIO_MAX_PINS exceeds the pins of the K1 controller");
    // The window the board map and the device tree agree on.
    const _: () = assert!(
        azos_drv_base::platform::hw::GPIO_BASE == 0xD401_9000,
        "the K1 GPIO window moved: re-check gpio_k1.rs's bank offsets against the new node"
    );

    /// The `spacemit,k1-gpio` window, attached when the hardware bus binds
    /// the node (`gpio_attach`). Unbound: no GPIO, every entry point answers
    /// -1 and the panic-time drive touches nothing.
    static WINDOW: Window = Window::new();

    /// Serialises the read-modify-write of `GPDR` (a direction change). The
    /// level path takes no lock.
    static DIR_LOCK: SpinLock<()> = SpinLock::new(());

    /// The controller's registers over the mapped window.
    struct Mmio(usize);

    impl K1GpioBus for Mmio {
        #[inline(always)]
        fn read32(&mut self, off: usize) -> u32 {
            // SAFETY: the base the bus bound and the kernel mapped; `off` is a
            // register offset of `gpio_k1` (below 0x200).
            unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
        }
        #[inline(always)]
        fn write32(&mut self, off: usize, v: u32) {
            // SAFETY: as `read32`.
            unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, v) }
        }
    }

    /// The controller, `None` while no node is bound.
    #[inline(always)]
    fn controller() -> Option<K1Gpio<Mmio>> {
        WINDOW.base().map(|b| K1Gpio::new(Mmio(b)))
    }

    /// The pin as the controller's index, if the kernel exposes it.
    #[inline(always)]
    fn exposed(pin: u32) -> bool {
        (pin as usize) < GPIO_MAX_PINS
    }

    /// Whether a controller is attached: the tree had the node and the bus
    /// bound it. Without it there is no e-stop line to drive.
    pub fn gpio_has_hardware() -> bool {
        WINDOW.base().is_some()
    }

    /// Hand the driver the controller the hardware bus bound at `base`, and
    /// the node's interrupt `line` (0: the node names none). `Err` when a
    /// controller is already attached.
    pub fn gpio_attach(base: usize, line: u32) -> Result<(), Taken> {
        WINDOW.attach(base)?;
        LINE.store(line, Ordering::Release);
        azos_drv_sys::kprintln!("[GPIO] SpacemiT K1 controller @ {:#010x} ({} of {} pins exposed)",
            base, GPIO_MAX_PINS, PINS);
        Ok(())
    }

    // ── The edge interrupt (`crate::gpio_k1`'s edge registers) ──────────────

    /// The node's interrupt line, the one all four banks share; 0 while none
    /// is known.
    static LINE: AtomicU32 = AtomicU32::new(0);
    /// The kernel routed [`LINE`] to a CPU ([`gpio_irq_route`]).
    static ROUTED: AtomicBool = AtomicBool::new(false);
    /// Serialises the `GAPMASK` read-modify-write between the kill switch's
    /// task and the interrupt handler: taken with interrupts off everywhere.
    static IRQ_LOCK: SpinLock<()> = SpinLock::new(());

    /// Mask every pin's interrupt, turn edge detection off and clear what the
    /// firmware left latched, then have the kernel route the controller's
    /// line (`enable`). The line when it was routed.
    pub fn gpio_irq_route(enable: impl FnOnce(u32) -> bool) -> Option<u32> {
        let line = LINE.load(Ordering::Acquire);
        let mut c = controller()?;
        if line == 0 {
            return None;
        }
        {
            let _g = IRQ_LOCK.lock_irqsave();
            c.edge_irq_init();
        }
        if !enable(line) {
            return None;
        }
        ROUTED.store(true, Ordering::Release);
        Some(line)
    }

    /// The interrupt handler's arm for `line` (interrupt context): `None` when
    /// it is not the controller's; otherwise take the armed pin's edge
    /// (acknowledge, mask, stamp, wake its task), `Some(true)` when a task was
    /// made ready.
    pub fn gpio_edge_irq(line: u32) -> Option<bool> {
        if !ROUTED.load(Ordering::Acquire) || line != LINE.load(Ordering::Relaxed) {
            return None;
        }
        let (Some(pin), Some(mut c)) = (edge_pin(), controller()) else { return Some(false) };
        let taken = {
            let _g = IRQ_LOCK.lock_irqsave();
            c.take(pin)
        };
        Some(taken && edge_taken())
    }

    /// Make `pin` the armed input: an input, both edges detected, its stale
    /// edge cleared, unmasked; any previously armed pin masked. `Polled` when
    /// the line is not routed (the caller then samples on its own period).
    pub fn gpio_edge_arm(pin: u32) -> Option<EdgeMode> {
        if !exposed(pin) || gpio_set_direction(pin, GpioDir::Input) != 0 {
            return None;
        }
        let mut c = controller()?;
        if let Some(old) = edge_pin() {
            gpio_edge_disarm(old);
        }
        if !ROUTED.load(Ordering::Acquire) {
            super::EDGE_PIN.store(pin, Ordering::Release);
            return Some(EdgeMode::Polled);
        }
        let _g = IRQ_LOCK.lock_irqsave();
        c.set_both_edges(pin, true);
        // An edge latched before the arm is not this arm's: the caller
        // samples the level next.
        c.ack(pin);
        super::EDGE_PIN.store(pin, Ordering::Release);
        c.set_unmasked(pin, true);
        Some(EdgeMode::Interrupt)
    }

    /// Unmask the armed pin after its task sampled it; an edge latched while
    /// it was masked raises the line now.
    pub fn gpio_edge_rearm(pin: u32) {
        if edge_pin() != Some(pin) || !ROUTED.load(Ordering::Acquire) {
            return;
        }
        if let Some(mut c) = controller() {
            let _g = IRQ_LOCK.lock_irqsave();
            c.set_unmasked(pin, true);
        }
    }

    /// Stop taking `pin`'s edges: masked, detection off.
    pub fn gpio_edge_disarm(pin: u32) {
        if super::EDGE_PIN.compare_exchange(pin, super::NO_PIN, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return;
        }
        if let (true, Some(mut c)) = (ROUTED.load(Ordering::Acquire), controller()) {
            let _g = IRQ_LOCK.lock_irqsave();
            c.set_unmasked(pin, false);
            c.set_both_edges(pin, false);
        }
    }

    /// A `gpios` specifier of this controller (`#gpio-cells = <3>`, binding
    /// `spacemit,k1-gpio.yaml`: the bank, the pin in the bank, the flags) as
    /// (pin, flags).
    pub fn gpio_specifier(cells: &[u32]) -> Option<(u32, u32)> {
        match *cells {
            [bank, off, flags] if off < PINS_PER_BANK => {
                let pin = bank.checked_mul(PINS_PER_BANK)?.checked_add(off)?;
                exposed(pin).then_some((pin, flags))
            }
            _ => None,
        }
    }

    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        if !exposed(pin) { return -1; }
        let Some(mut c) = controller() else { return -1 };
        let _guard = DIR_LOCK.lock();
        if c.set_output(pin, dir == GpioDir::Output) { 0 } else { -1 }
    }

    pub fn gpio_read(pin: u32) -> i32 {
        if !exposed(pin) { return -1; }
        match controller().and_then(|mut c| c.level(pin)) {
            Some(high) => high as i32,
            None => -1,
        }
    }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if !exposed(pin) { return -1; }
        match controller() {
            Some(mut c) => if c.set_level(pin, val & 1 != 0) { 0 } else { -1 },
            None => -1,
        }
    }

    pub fn gpio_toggle(pin: u32) -> i32 {
        if !exposed(pin) { return -1; }
        match controller() {
            Some(mut c) => if c.toggle(pin) { 0 } else { -1 },
            None => -1,
        }
    }

    /// Emergency GPIO write for the panic handler and the kernel's safe-state
    /// drive. Identical to [`gpio_write`]: that is already one store to a
    /// clear/set register, with no lock to wait on and no word shared with
    /// another pin to tear.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        gpio_write(pin, val)
    }
}

#[cfg(feature = "k1")]
pub use k1::*;
