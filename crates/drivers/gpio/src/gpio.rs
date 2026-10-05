// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// U05-4 (2026-09-26): a `k1` build used to silently fall through to the
// QEMU simulation below (`#[cfg(not(feature = "vf2"))]` includes `k1`)
// while `gpio_driver.rs`/`platform::hw` advertise real K1 GPIO MMIO ranges
// — a K1 kernel would report a real GPIO driver and drive nothing. `rc.rs`
// already refuses this class of gap at compile time
// (`RcMode::Simulated` does not exist under `k1`); this is the same rule
// applied here, per the owner's [rec] on U05 §5 Q2. Fails the `--features
// k1` build until a real `spacemit,k1-gpio` driver replaces this module's
// `k1` path — see this front's report for exactly which build row that is
// and why it is the honest state, not a regression.
//
// Placed BEFORE the module doc comment below on purpose: a `///` doc
// comment immediately followed by a macro invocation (rather than a
// doc-able item) is itself an `unused_doc_comments` warning — this project
// gates on zero warnings, so the ordering here is load-bearing, not
// cosmetic.
#[cfg(feature = "k1")]
compile_error!(
    "crates/drivers/gpio/src/gpio.rs: no real K1 GPIO driver exists yet — the \
     `not(vf2)` path below is the QEMU simulation, and a `k1` build must \
     not silently drive it while advertising real MMIO. See U05-4."
);

/// GPIO driver — port of kernel/drivers/gpio.c + kernel/include/gpio.h
///
/// QEMU:  in-memory simulation (no hardware on QEMU virt).
/// VF2:   StarFive JH7110 sys_iomux GPIO controller — real MMIO.
pub const GPIO_MAX_PINS: usize = 64;

/// GPIO pin direction.
#[derive(Clone, Copy, PartialEq)]
pub enum GpioDir {
    Input  = 0,
    Output = 1,
}

// ── QEMU: in-memory simulation ────────────────────────────────────────────────

#[cfg(not(feature = "vf2"))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    struct GpioState {
        value:     [u8; GPIO_MAX_PINS],
        direction: [GpioDir; GPIO_MAX_PINS],
        valid:     [bool; GPIO_MAX_PINS],
    }

    impl GpioState {
        const fn new() -> Self {
            GpioState {
                value:     [0u8; GPIO_MAX_PINS],
                direction: [GpioDir::Input; GPIO_MAX_PINS],
                valid:     [false; GPIO_MAX_PINS],
            }
        }
    }

    static GPIO: SpinLock<GpioState> = SpinLock::new(GpioState::new());

    pub fn gpio_init() {}

    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let mut g = GPIO.lock();
        g.direction[pin as usize] = dir;
        g.valid[pin as usize]     = true;
        0
    }

    pub fn gpio_read(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let g = GPIO.lock();
        if !g.valid[pin as usize] { return -1; }
        g.value[pin as usize] as i32
    }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let mut g = GPIO.lock();
        if g.direction[pin as usize] != GpioDir::Output { return -1; }
        g.value[pin as usize] = (val & 1) as u8;
        0
    }

    pub fn gpio_toggle(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let mut g = GPIO.lock();
        if g.direction[pin as usize] != GpioDir::Output { return -1; }
        g.value[pin as usize] ^= 1;
        0
    }

    /// Emergency GPIO write for the panic handler — bypasses the `GPIO`
    /// spinlock entirely instead of calling `.lock()`.
    ///
    /// This deliberately sacrifices mutual exclusion: if another hart is
    /// inside `gpio_write`/`gpio_set_direction`/`gpio_toggle` holding
    /// `GPIO` at the exact moment of a panic, waiting for that lock (as
    /// `gpio_write` does) would spin forever and the panic message would
    /// never reach UART. During a panic, stopping actuators and getting
    /// the crash reason printed matters more than leaving the simulated
    /// GPIO state internally consistent. This is a conscious trade-off,
    /// not an oversight — do not "fix" it by adding a lock back in.
    ///
    /// # Safety
    /// May race with a concurrent `gpio_write`/`gpio_set_direction` on
    /// another hart, producing a torn read-modify-write of `GpioState`.
    /// Only call this from the panic handler.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let g = unsafe { GPIO.get_mut_unchecked() };
        if g.direction[pin as usize] != GpioDir::Output { return -1; }
        g.value[pin as usize] = (val & 1) as u8;
        0
    }

    pub fn gpio_info() {
        azos_drv_sys::kconsoleln!("[GPIO] Simulated GPIO — {} pins", GPIO_MAX_PINS);
        let g = GPIO.lock();
        let mut configured = 0u32;
        for i in 0..GPIO_MAX_PINS {
            if g.valid[i] { configured += 1; }
        }
        azos_drv_sys::kconsoleln!("[GPIO] Configured: {} pins", configured);
        for i in 0..GPIO_MAX_PINS {
            if g.valid[i] {
                let dir = if g.direction[i] == GpioDir::Output { "OUT" } else { "IN " };
                azos_drv_sys::kconsoleln!("[GPIO]   pin {:2}: {} = {}", i, dir, g.value[i]);
            }
        }
    }
}

#[cfg(not(feature = "vf2"))]
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
// its actual input level. `GPIO_DOUT0 = 0x040` was, by coincidence, already
// the right register (`DOUT`).

#[cfg(feature = "vf2")]
mod mmio {
    use super::*;
    use azos_drv_base::platform::hw::{GPIO_BASE, GPIO_DOEN as DOEN, GPIO_DOUT0 as DOUT, GPIO_GPIOIN as GPIOIN};
    use azos_sync::SpinLock;

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

    #[inline(always)]
    fn reg_read32(offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((GPIO_BASE + offset) as *const u32) }
    }

    #[inline(always)]
    fn reg_write32(offset: usize, val: u32) {
        unsafe { core::ptr::write_volatile((GPIO_BASE + offset) as *mut u32, val) }
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

    pub fn gpio_init() {
        // Default every pin's DOEN byte to GPOEN_DISABLE (input, tri-state)
        // rather than the old model's "write 0xFFFF_FFFF" (which used to
        // select output-signal-source 127 on 4 pins per word — not "input").
        for pin in 0..GPIO_MAX_PINS as u32 {
            let (word, shift) = dout_doen_word_and_shift(pin);
            let mask = DOEN_FIELD_MASK << shift;
            let cur = reg_read32(DOEN + word);
            reg_write32(DOEN + word, (cur & !mask) | ((GPOEN_DISABLE << shift) & mask));
        }
    }

    pub fn gpio_set_direction(pin: u32, dir: GpioDir) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
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
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let (word, bit) = gpioin_word_and_bit(pin);
        ((reg_read32(GPIOIN + word) >> bit) & 1) as i32
    }

    pub fn gpio_write(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOUT_FIELD_MASK << shift;
        let sel = if val & 1 != 0 { GPOUT_HIGH } else { GPOUT_LOW };
        let _guard = GPIO_MMIO_LOCK.lock();
        let cur = reg_read32(DOUT + word);
        reg_write32(DOUT + word, (cur & !mask) | ((sel << shift) & mask));
        0
    }

    pub fn gpio_toggle(pin: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOUT_FIELD_MASK << shift;
        let _guard = GPIO_MMIO_LOCK.lock();
        let cur = reg_read32(DOUT + word);
        let now_high = (cur >> shift) & DOUT_FIELD_MASK == GPOUT_HIGH;
        let sel = if now_high { GPOUT_LOW } else { GPOUT_HIGH };
        reg_write32(DOUT + word, (cur & !mask) | ((sel << shift) & mask));
        0
    }

    /// Emergency GPIO write for the panic handler — bypasses
    /// `GPIO_MMIO_LOCK` entirely instead of calling `.lock()`.
    ///
    /// `GPIO_MMIO_LOCK` was added to serialize the GPIOOUT/GPIOOEN
    /// read-modify-write across harts (see the lock's doc comment above).
    /// That is exactly right for normal operation, but it means a panic
    /// on one hart while another hart holds this lock would spin forever
    /// in the panic handler and the crash reason would never reach UART.
    /// This function deliberately sacrifices RMW exclusion — a torn
    /// bank write that leaves some unrelated pin's output bit wrong is
    /// an acceptable price during a panic; a kernel that hangs silently
    /// instead of printing why it crashed is not. Conscious trade-off,
    /// not an oversight — do not "fix" it by adding the lock back.
    ///
    /// # Safety
    /// May race with a concurrent `gpio_write`/`gpio_set_direction`/
    /// `gpio_toggle` on another hart touching the same register bank,
    /// producing a torn read-modify-write. Only call this from the
    /// panic handler.
    pub fn gpio_write_panic(pin: u32, val: u32) -> i32 {
        if pin as usize >= GPIO_MAX_PINS { return -1; }
        let (word, shift) = dout_doen_word_and_shift(pin);
        let mask = DOUT_FIELD_MASK << shift;
        let sel = if val & 1 != 0 { GPOUT_HIGH } else { GPOUT_LOW };
        let cur = reg_read32(DOUT + word);
        reg_write32(DOUT + word, (cur & !mask) | ((sel << shift) & mask));
        0
    }

    pub fn gpio_info() {
        azos_drv_sys::kconsoleln!("[GPIO] JH7110 sys_iomux @ {:#010x} (DOEN={:#x} DOUT={:#x} GPIOIN={:#x})",
            GPIO_BASE, DOEN, DOUT, GPIOIN);
        for word in (0..8).step_by(4) {
            azos_drv_sys::kconsoleln!("[GPIO] DOEN[{:#x}]={:#010x} DOUT[{:#x}]={:#010x}",
                word, reg_read32(DOEN + word), word, reg_read32(DOUT + word));
        }
        azos_drv_sys::kconsoleln!("[GPIO] GPIOIN[0]={:#010x} GPIOIN[1]={:#010x}",
            reg_read32(GPIOIN), reg_read32(GPIOIN + 4));
    }
}

#[cfg(feature = "vf2")]
pub use mmio::*;
