// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Platform constants — compile-time hardware address selection.
///
/// Default (no feature): QEMU virt machine.
/// Feature "vf2": StarFive VisionFive 2 (JH7110 SoC, SiFive U74 × 4).
/// Feature "k1":  SpacemiT K1 (BananaPi BPI-F3, SpacemiT X60 × 8, RV64GCVB).
///
/// Key differences QEMU virt vs VF2 vs K1:
///   - Timer frequency: 10 MHz (QEMU) / 4 MHz (JH7110) / 24 MHz (K1)
///   - RAM base:        0x8000_0000 (QEMU) / 0x4000_0000 (VF2) / 0x0000_0000 (K1)
///   - UART base:       0x1000_0000 (QEMU/VF2) / 0xD401_7000 (K1)
///   - PLIC base:       0x0C00_0000 (QEMU/VF2) / 0xE000_0000 (K1)
///   - GPIO/PWM/I2C:    simulated (QEMU) vs real MMIO (VF2/K1)

// ── QEMU virt (RISC-V) ───────────────────────────────────────────────────────
//
// Deliberately NOT `target_arch = "riscv64"` alone: this is also the `hw`
// module every HOST-side shim/test crate gets when it `#[path]`-pulls this
// file (see `crates/*-tests/shims/drivers`) — none of them set `vf2`/`k1`,
// and until this port none of them checked the host's own arch either,
// because the host toolchain here is `aarch64-apple-darwin`. Excluding it
// only on a REAL aarch64 bare-metal build (`target_os = "none"`, where the
// new aarch64 block below takes over) keeps every host build — including
// this Mac — getting these QEMU-virt constants exactly as before, and
// avoids two `pub mod hw` definitions colliding on the actual
// `aarch64-unknown-none` target.
#[cfg(not(any(
    feature = "vf2",
    feature = "k1",
    all(target_arch = "aarch64", target_os = "none"),
)))]
pub mod hw {
    pub const PLATFORM_NAME: &str = "QEMU virt";

    /// NS16550A UART0 base address.
    pub const UART_BASE:   usize = 0x1000_0000;
    /// Platform-Level Interrupt Controller base.
    pub const PLIC_BASE:   usize = 0x0C00_0000;
    /// QEMU `virt`'s own UART node compatible string (`hw/riscv/virt.c` wires
    /// a `ns16550a`). Named so a DTB-provenance check (`dtb_provenance`
    /// module) has something to print beside the address — QEMU's device
    /// tree is synthetic but still worth cross-checking at boot.
    pub const UART_COMPATIBLE: &str = "ns16550a";
    pub const PLIC_COMPATIBLE: &str = "sifive,plic-1.0.0";
    /// `mtime` timer frequency reported by the hardware (Hz).
    pub const TIMER_FREQ:  u64   = azos_limits::TIMER_FREQ as u64;   // Kconfig TIMER_FREQ (V2.6): 10 MHz default under BOARD_QEMU
    /// Maximum usable CPU cores.
    pub const NUM_CPUS:    usize = 4;
    /// Physical RAM base (below OpenSBI).
    pub const RAM_BASE:    usize = 0x8000_0000;
    /// Kernel load address (above OpenSBI 2 MiB reservation).
    pub const KERNEL_LOAD: usize = 0x8020_0000;

    // GPIO/PWM/I2C are simulated in QEMU; no MMIO addresses needed.

    /// QEMU `fw_cfg` MMIO-DMA interface, RISC-V `virt` machine. Confirmed
    /// against QEMU mainline `hw/riscv/virt.c`'s `virt_memmap[VIRT_FW_CFG]`
    /// (`{ 0x10100000, 0x18 }`) — QEMU's own emulated device, not JH7110
    /// hardware; used only by the `crates/drivers/display` `ramfb` module (behind
    /// `--features qemu` there) to test the general "can this kernel drive
    /// *a* framebuffer" question in QEMU, entirely separate from the real
    /// DC8200/HDMI TX driver, which QEMU cannot simulate at all.
    pub const FW_CFG_BASE: usize = 0x1010_0000;

    /// The MMIO regions a topology can grant to ring 3: `mmio.N` names
    /// `MMIO_REGIONS[N]` (RFC-0043). Addresses from QEMU's `virt_memmap[]`
    /// (`hw/riscv/virt.c`), read out of the QEMU 11.0.0 binary the gate runs.
    /// Devices the kernel drives itself (UART0, PLIC, CLINT, the virtio-mmio
    /// slots, `fw_cfg`) have no entry.
    pub const MMIO_REGIONS: &[super::MmioRegion] = &[
        // 0: goldfish RTC, `VIRT_RTC` = { 0x101000, 0x1000 }. Read-only: a
        // ring-3 program reads the clock through it, and its writable
        // registers (alarm, interrupt enable) are nothing a program needs.
        // Reading `TIME_LOW` (0x00) latches `TIME_HIGH` (0x04).
        super::MmioRegion { base: 0x0010_1000, size: 0x1000, writable: false },
        // 1: first page of the platform bus, `VIRT_PLATFORM_BUS` =
        // { 0x4000000, 0x2000000 }, where QEMU places dynamic sysbus devices.
        // The gate's scenarios attach only virtio-mmio devices, which sit on
        // their own slots, so a write here reaches no device. Writable, and
        // granted to no task.
        super::MmioRegion { base: 0x0400_0000, size: 0x1000, writable: true },
        // 2: the goldfish RTC again, writable (wave 9 IRQ4) — aarch64's
        // index 2 for the PL031, same role. The one device on this board
        // ring 3 can make interrupt on demand: `userspace/tests/captest` writes its
        // alarm (ALARM_HIGH then ALARM_LOW with the current time fires at
        // once), clears it through CLEAR_INTERRUPT, and binds its line
        // (source 11) to prove delivery to ring 3 and mask-until-ACK. It
        // ALIASES index 0, the same page at a second authority level: the one
        // exception `no_two_regions_overlap` allows (an exact read-only /
        // writable pair). The kernel does not drive this device. Granted only
        // by the qemu topology.
        super::MmioRegion { base: 0x0010_1000, size: 0x1000, writable: true },
    ];

    // vDSO placement (RFC-0041 M01 fix, 2026-09-22): `VDSO_USER_BASE`
    // (`crates/core/abi/src/vdso.rs`) must not share a 2 MiB (VPN[1]) slot with
    // any POINT device this board's kernel identity-maps, and must sit
    // entirely below RAM (a size this crate cannot see at compile time —
    // see `vdso_is_below_ram`'s doc). Checked against every constant and
    // every literal size `kernel/src/main.rs` actually calls
    // `map_mmio_region` with for this board — CLINT and the QEMU
    // virtio-mmio window are literals there (`0x0200_0000`/`0x1000_1000`,
    // not named constants), mirrored here rather than promoted, to avoid
    // touching that file's RISC-V codegen for an unrelated fix.
    const _: () = {
        use azos_abi::vdso::{vdso_is_below_ram, vdso_shares_a_2mib_slot_with as collides};
        const CLINT_BASE: usize = 0x0200_0000; // kernel/src/main.rs literal
        const CLINT_SIZE: usize = 0x1_0000;
        const VIRTIO_MMIO_BASE: usize = 0x1000_1000; // kernel/src/main.rs literal
        const VIRTIO_MMIO_SIZE: usize = 0x8000;
        assert!(vdso_is_below_ram(RAM_BASE), "vDSO is not below QEMU riscv64 RAM");
        assert!(!collides(UART_BASE, 0x1000), "vDSO shares QEMU riscv64 UART's 2 MiB slot");
        assert!(!collides(PLIC_BASE, 0x40_0000), "vDSO shares QEMU riscv64 PLIC's 2 MiB slot");
        assert!(!collides(FW_CFG_BASE, 0x1000), "vDSO shares QEMU riscv64 fw_cfg's 2 MiB slot");
        assert!(!collides(CLINT_BASE, CLINT_SIZE), "vDSO shares QEMU riscv64 CLINT's 2 MiB slot");
        assert!(!collides(VIRTIO_MMIO_BASE, VIRTIO_MMIO_SIZE), "vDSO shares QEMU riscv64 virtio-mmio's 2 MiB slot");
    };
}

// ── StarFive VisionFive 2 (JH7110) ───────────────────────────────────────────
//
// **`vf2` is NOT a supported target — OWNER DECISION V2.3 (2026-09-26).**
// Every constant below was re-checked against mainline `jh7110.dtsi` (and,
// for the WDT/GPIO/PLIC register-level code in `wdt.rs`/`gpio.rs`/
// `plic.rs`, against the matching mainline `.c` driver) during this pass —
// but NONE of it has run on real VF2 silicon, and citation strength is not
// hardware verification. Treat every address and register sequence in this
// module as unverified regardless of how precisely it is sourced, until a
// board is on the bench. The checklist below is every constant this pass
// touched, the mainline node each was checked against, and whether the
// fix stopped at the address (register model still unverified/wrong-IP)
// or went further (a cited register-level rewrite — still untested on
// hardware, not "done"):
//
// | constant | mainline node | scope of this pass's fix |
// |---|---|---|
// | `I2C1_BASE` | `i2c1@10040000` | address only (was `uart2`'s address) |
// | `SPI0_BASE` (new) | `spi0@10060000` | address only (register model: unverified, wrong IP — see `spi.rs`) |
// | `WDT_BASE` | `watchdog@13070000` | address + register-level rewrite (`wdt.rs`, cited against `starfive-wdt.c`) |
// | `USB0_BASE` (new) | `usb0@10100000`/`usb@0` (`cdns,usb3`) | address only (register model: unverified — see `usb.rs`) |
// | `ETH0_BASE` | `gmac0@16030000` (`starfive,jh7110-dwmac`) | compatible-string correction only; address was already right; register model: unverified, wrong IP — see `eth.rs` |
// | `DMA_AXI_BASE`/`DMA_SDMA_BASE` (new) | `dma@16050000` / `sdma@16008000` | address+identity only — two distinct real controllers named, neither driven; see `dma.rs` |
// | `PMU_COMPATIBLE`/`DC8200_NOC_BASE` (relabelled) | `pwrc@17030000` | identity correction only (was mislabeled a display NOC block) |
// | `PWM_COMPATIBLE`/`PWM_BASE` | `pwm@120d0000` (`opencores,pwm-v1` fallback) | compatible-string correction only; register model: unverified, wrong IP (OpenCores PTC, not SiFive) — see `pwm.rs` |
// | `GPIO_BASE`/`GPIO_DOEN`/`GPIO_DOUT0`/`GPIO_GPIOIN` | `sysgpio: pinctrl@13040000` | address + register-level rewrite (`gpio.rs`, cited against `pinctrl-starfive-jh7110{,-sys}.c`) |
// | PLIC S-context formula (`plic.rs::s_context`) | `plic` node's `interrupts-extended` | logic rewrite (cited against the DTS's own hart/context enumeration) |
// | `pm.rs`'s thermal sensor base | `sfctemp@120e0000` (was `pwrc@17030000`) | address only; offset/formula: still unverified |
//
// `pm.rs`'s `pm_clock_gate`/`dvfs_set_freq` syscrg write and `mmc.rs`'s
// DW-MSHC-vs-SDHCI mismatch were already flagged unverified before this
// pass (U05-10, and `mmc.rs`'s own 2026-09-18 note) and are unchanged here.
#[cfg(feature = "vf2")]
pub mod hw {
    pub const PLATFORM_NAME: &str = "StarFive VisionFive 2 (JH7110)";

    /// UART0 — SAME base as QEMU virt (by design). Real IP is a Synopsys
    /// DesignWare APB UART (`snps,dw-apb-uart`), 16550-register-compatible
    /// but NOT byte-addressed like QEMU's model — `reg-shift = 2`,
    /// `reg-io-width = 4` on real silicon. See `crates/drivers/sys/src/uart.rs`
    /// module doc comment for the fix and citation (confirmed against
    /// `jh7110.dtsi` `uart0@10000000`, 2026-09-18). The base address itself
    /// (0x1000_0000) matches the real device tree, independently confirmed
    /// the same fetch.
    pub const UART_BASE:   usize = 0x1000_0000;
    pub const UART_COMPATIBLE: &str = "starfive,jh7110-uart";
    /// PLIC — SAME base as QEMU virt (by design).
    pub const PLIC_BASE:   usize = 0x0C00_0000;
    pub const PLIC_COMPATIBLE: &str = "starfive,jh7110-plic";
    /// JH7110 `mtime` timebase (from DTS: timebase-frequency = <4000000>).
    pub const TIMER_FREQ:  u64   = azos_limits::TIMER_FREQ as u64;    // Kconfig TIMER_FREQ (V2.6): 4 MHz under BOARD_VF2 ← critical difference
    /// DW-WDT "core" clock (`wdt->core_clk` in Linux mainline
    /// `drivers/watchdog/starfive-wdt.c`) — the one that actually feeds the
    /// timeout-to-ticks computation (`count = timeout * clk_get_rate(core_clk)`).
    /// NOT the same as TIMER_FREQ (RISC-V mtime clock), and NOT the WDT's
    /// "apb" clock either (that one is register-access-only, per the same
    /// driver — irrelevant to timing). Confirmed via
    /// `clk-starfive-jh7110-sys.c`'s clock tree: `wdt_core` is gated
    /// directly off `JH7110_SYSCLK_OSC` (the 24 MHz crystal oscillator),
    /// bypassing the APB_BUS/STG_AXIAHB divider chain entirely — so unlike
    /// a generic "APB clock ≈ 24 MHz" guess, this is a direct,
    /// undivided connection with no PLL/divider uncertainty in between.
    pub const WDT_CLK_HZ:  u64   = 24_000_000;
    /// 4× SiFive U74 application cores (+ 1× S7 monitor, not managed by our kernel).
    pub const NUM_CPUS:    usize = 4;
    /// JH7110 DDR physical base.
    pub const RAM_BASE:    usize = 0x4000_0000;
    /// Kernel load address on VF2 (above OpenSBI 2 MiB reservation).
    pub const KERNEL_LOAD: usize = 0x4020_0000;

    // ── GPIO / pin mux ────────────────────────────────────────────────────────
    /// `sysgpio: pinctrl@13040000`, `compatible = "starfive,jh7110-sys-
    /// pinctrl"` — confirmed base, unchanged.
    pub const GPIO_BASE:   usize = 0x1304_0000;
    pub const GPIO_COMPATIBLE: &str = "starfive,jh7110-sys-pinctrl";
    /// **Corrected 2026-09-26 (U05-1): these were bit-per-pin bank offsets
    /// (`0x040`/`0x044`/`0x050`) for a GPIO model this IP does not have.**
    /// The real registers are byte-per-pin mux-select arrays — see
    /// `crates/drivers/gpio/src/gpio.rs`'s module doc for the full citation
    /// (`pinctrl-starfive-jh7110-sys.c`'s `JH7110_SYS_DOEN/DOUT/GPIOIN`).
    /// Kept here, renamed to match, as the single source `gpio.rs` reads
    /// from rather than re-declaring locally.
    pub const GPIO_DOEN:   usize = 0x000;
    pub const GPIO_DOUT0:  usize = 0x040;
    pub const GPIO_GPIOIN: usize = 0x118;

    // ── PWM ───────────────────────────────────────────────────────────────────
    /// JH7110 PWM controller. Base address (`0x120D_0000`, was previously
    /// mis-set to the PMU's `0x1703_0000`) was already fixed against
    /// `jh7110.dtsi`'s `pwm@120d0000`. **Compatible string re-checked
    /// 2026-09-26: it is `"starfive,jh7110-pwm", "opencores,pwm-v1"` — NOT
    /// `"sifive,pwm0"`.** The real IP is an OpenCores PTC core (one
    /// independent 4-register block — `CNTR`/`HRC`/`LRC`/`CTRL` — PER
    /// CHANNEL, at `(ch&4)<<13 | (ch&3)<<4` from this base; see the
    /// out-of-tree `drivers/pwm/pwm-ocores.c` StarFive submission,
    /// lore.kernel.org/linux-pwm, not yet merged to mainline as of this
    /// fetch), not the shared-`PWMCFG`/per-channel-`PWMCMP` SiFive `pwm-
    /// sifive.c` layout `crates/drivers/actuator/src/pwm.rs`'s `mmio` module
    /// implements. `pwm.rs` is left on the SiFive layout, now marked
    /// unverified rather than silently "confirmed" (see that file's module
    /// doc) — porting to the real OpenCores model needs the PWM APB clock
    /// rate (for the ns↔register-count conversion) this pass did not chase
    /// down, and there is no *merged* mainline driver to cite register
    /// behaviour against yet, only a pending patch. What IS fixed here and
    /// now: `pwm_domain::PWM_DOMAIN_INDEPENDENT_8` states the real IP (8
    /// independent channels); the gate on a `vf2` build still uses
    /// `PWM_DOMAIN_VF2_DRIVER`, the shared shape this SiFive-layout driver
    /// actually programs, until `pwm.rs` is ported (see `pwm_domain`).
    pub const PWM_BASE:    usize = 0x120D_0000;
    pub const PWM_COMPATIBLE: &str = "starfive,jh7110-pwm";

    // ── I2C (DesignWare APB I2C) ──────────────────────────────────────────────
    /// I2C0 base (DesignWare APB I2C, 400 kHz).
    // JH7110 i2c0 @ 0x10030000 (Linux mainline jh7110.dtsi) — was aliased to UART1_BASE, fixed 2026-08.
    pub const I2C0_BASE:   usize = 0x1003_0000;
    /// I2C1 base. **Was `0x1002_0000` (fixed U05-1, this pass).** That
    /// address is `uart2@10020000` in mainline `jh7110.dtsi` — `i2c1` is at
    /// `0x1004_0000`. Every `i2c_init` write on bus 1 (`ina219.rs I2C_BUS =
    /// 1`) was landing in UART2's `DLL`/`IER` instead. Re-confirmed against
    /// the same fetch as `I2C0_BASE` (`i2c0@10030000`, `i2c1@10040000`,
    /// `i2c2@10050000`, `uart2@10020000`, all `snps,designware-i2c` /
    /// `snps,dw-apb-uart` respectively).
    pub const I2C1_BASE:   usize = 0x1004_0000;
    /// `compatible` string every I2C0/I2C1 write should be landing on —
    /// checked below, not left as a comment (the mechanism U05-1 exists to
    /// fix: an address that drifts from its citation used to be silent).
    pub const I2C_COMPATIBLE: &str = "snps,designware-i2c";

    // ── SPI (ARM PL022, PrimeCell) ───────────────────────────────────────────
    /// `spi0@10060000` — **NOT** `0x1004_0000` (that is `i2c1`, see above;
    /// `crates/drivers/bus/src/spi.rs`'s own `SPI_BASE` literal carried the same
    /// wrong address, modelled as a Cadence SPI controller). Real IP is
    /// `arm,pl022`/`arm,primecell` (SSP/PL022), confirmed against
    /// `jh7110.dtsi`'s `spi0` node, 2026-09-25. Register layout
    /// (`SSPCR0`/`SSPCR1`/`SSPDR`/`SSPSR`/`SSPCPSR`) is a separate, not-yet-
    /// ported fix — `spi.rs` is left marked unverified against this address
    /// rather than reprogrammed against a still-unconfirmed register map
    /// (see that file's module doc): a base-address fix without a register
    /// fix would still mis-program the real PL022.
    pub const SPI0_BASE: usize = 0x1006_0000;
    pub const SPI_COMPATIBLE: &str = "arm,pl022";

    // ── eMMC / SD ─────────────────────────────────────────────────────────────
    /// SDIO0 base (eMMC — JH7110 `sdio0@16010000`). Base address confirmed
    /// against `jh7110.dtsi` (see UART0 citation above, same fetch,
    /// 2026-09-18) — but the real IP behind it is `compatible =
    /// "snps,dw-mshc"` (DesignWare MSHC), NOT SDHCI. `crates/drivers/block/src/mmc.rs`
    /// currently implements an SDHCI-v3 register model against this address;
    /// that is a real driver-vs-silicon mismatch, not just a naming issue —
    /// see `mmc.rs`'s module doc for details. Header comment below kept as
    /// "eMMC / SD" (what these pins are wired to on the board), not as a
    /// claim about the controller's register interface.
    pub const MMC0_BASE:   usize = 0x1601_0000;
    /// SDIO1 base (microSD slot — JH7110 `sdio1@16020000`). Same DW-MSHC
    /// caveat as `MMC0_BASE` above.
    pub const MMC1_BASE:   usize = 0x1602_0000;

    // ── Ethernet (DesignWare QoS, StarFive glue) ────────────────────────────
    /// GMAC0 base — address confirmed against `jh7110.dtsi`'s
    /// `gmac0: ethernet@16030000`, but the IP behind it is **not** Cadence
    /// GEM/MACB: mainline names it `compatible = "starfive,jh7110-dwmac",
    /// "snps,dwmac-5.20"` — a Synopsys DesignWare EQoS/QoS MAC (`stmmac`
    /// family), a different register model entirely (`MAC_CONFIGURATION` et
    /// al., not `NCR`/`NCFGR`/`RBQP`). `crates/drivers/net/src/eth.rs` still
    /// implements the Cadence MACB model against this address — every
    /// register write from that file lands in the dwmac's configuration
    /// space at the wrong offset. Fixed here as a base+identity correction
    /// only; the MACB register writes in `eth.rs` are left as documented,
    /// verified-wrong dead code (no board maps this address today — see
    /// `boot_hooks.rs`'s `vf2` MMIO list) rather than rewritten against a
    /// register model (`stmmac`) this pass does not have primary-source
    /// time to port safely.
    pub const ETH0_BASE:   usize = 0x1603_0000;
    pub const ETH0_COMPATIBLE: &str = "starfive,jh7110-dwmac";

    // ── UART1 (for ESP32 WiFi bridge) ───────────────────────────────────────
    /// JH7110 UART1 — NS16550A, used for ESP32-C3 bridge (serial@10010000).
    pub const UART1_BASE:  usize = 0x1001_0000;

    // ── Watchdog (StarFive WDT, NOT DesignWare) ─────────────────────────────
    /// `watchdog@13070000` in `jh7110.dtsi` — **was `0x1301_0000`** (that
    /// address has no node in mainline at all: nothing there is a
    /// watchdog). `compatible = "starfive,jh7110-wdt"`, confirmed against
    /// Linux mainline `drivers/watchdog/starfive-wdt.c`'s JH7110 variant
    /// (`STARFIVE_WDT_JH7110_LOAD/VALUE/CONTROL/INTCLR/LOCK`) — see
    /// `crates/drivers/sys/src/wdt.rs` for the register map that file now
    /// implements against this address, and this fetch's citation.
    pub const WDT_BASE:    usize = 0x1307_0000;
    pub const WDT_COMPATIBLE: &str = "starfive,jh7110-wdt";

    // ── Display (Verisilicon DC8200 + Innosilicon HDMI TX) ──────────────────
    // Confirmed against Linux mainline device tree source
    // (jh7110-common.dtsi / jh7110.dtsi, starfive-tech vendor fork,
    // JH7110_VisionFive2_devel branch), 2026-08. HDMI-only path — the SoC
    // also has MIPI DSI/D-PHY outputs, not used here, not wired.
    /// DC8200 top-level/config block (chip ID, top-level IRQ ack/enable).
    pub const DC8200_TOP_BASE:   usize = 0x2940_0000;
    /// DC8200 main register block — CRTC timing, plane/framebuffer config.
    /// This is the block `DC8200_*` register offsets in `crates/drivers/display`
    /// are relative to.
    pub const DC8200_MAIN_BASE:  usize = 0x2940_0800;
    /// **Mislabeled (U05-1 pass, 2026-09-26): this is not a "DC8200
    /// NOC/clock-reset block".** `0x1703_0000` is `pwrc:
    /// power-controller@17030000`, `compatible = "starfive,jh7110-pmu"`,
    /// confirmed against mainline `jh7110.dtsi` — the SoC power controller
    /// (see `pm.rs::thermal_read_temp_mdeg`, which was reading this same
    /// address as a temperature sensor and has been corrected separately).
    /// No display-clock node exists at this address in mainline; kept as a
    /// named constant only because `pm.rs`'s clock-gate path already used
    /// it as a landmark before this fix — not used by `crates/drivers/display`
    /// itself, which never reads it.
    pub const DC8200_NOC_BASE:   usize = 0x1703_0000;
    /// PMU `compatible` string for the address above.
    pub const PMU_COMPATIBLE: &str = "starfive,jh7110-pmu";

    // ── USB (Cadence USB3, "starfive,jh7110-usb") ───────────────────────────
    /// `usb0@10100000` — **NOT** `0x1040_0000` (`crates/drivers/bus/src/usb.rs`'s
    /// `xHCI at 0x10400000` claim: no node exists there). Confirmed against
    /// `jh7110.dtsi`: `compatible = "starfive,jh7110-usb"`, with an inner
    /// `usb_cdns3: usb@0 { compatible = "cdns,usb3"; reg = <0x0 0x10000>,
    /// <0x10000 0x10000>, <0x20000 0x10000>; reg-names = "otg","xhci","dev";
    /// }` — a Cadence USB3 (`cdns3`) controller with OTG/xHCI/device register
    /// windows at +0/+0x10000/+0x20000 from this base, not a standalone xHCI
    /// at a different address. Register model is a separate, not-yet-ported
    /// fix — see `usb.rs`'s module doc.
    pub const USB0_BASE: usize = 0x1010_0000;
    pub const USB0_COMPATIBLE: &str = "starfive,jh7110-usb";

    // ── DMA (two distinct, unrelated controllers) ───────────────────────────
    /// `dma-controller@16050000`, `compatible = "starfive,jh7110-axi-dma"`
    /// (Synopsys DW AXI DMAC). `crates/drivers/dmac/src/dma.rs` claims a
    /// "SiFive PDMA" at `0x1600_8000` — that address is real hardware, but
    /// it is `sdma: dma-controller@16008000`, `compatible = "arm,pl080",
    /// "arm,primecell"` (an ARM PL080, unrelated IP, used for the crypto
    /// engine's DMA per mainline). Neither address is a SiFive PDMA; the two
    /// controllers are named here so a future real implementation picks the
    /// right one for the right job rather than continuing to guess.
    pub const DMA_AXI_BASE: usize = 0x1605_0000;
    pub const DMA_AXI_COMPATIBLE: &str = "starfive,jh7110-axi-dma";
    /// `sdma@16008000` — see `DMA_AXI_BASE`'s doc. Not driven by anything in
    /// this crate; named so `dma.rs`'s `0x1600_8000` literal is no longer
    /// the only record of what is actually at that address.
    pub const DMA_SDMA_BASE: usize = 0x1600_8000;
    pub const DMA_SDMA_COMPATIBLE: &str = "arm,pl080";
    /// Innosilicon HDMI TX — register interface is byte-addressed (8-bit
    /// registers), unlike DC8200's word-aligned layout — see
    /// `crates/drivers/display/src/hdmi.rs`.
    pub const HDMI_TX_BASE:      usize = 0x2959_0000;

    /// MMIO regions a topology can grant to ring 3 (RFC-0043). Empty: every
    /// `mmio.N` is refused at mint and every index at `SYS_MMIO_MAP`.
    pub const MMIO_REGIONS: &[super::MmioRegion] = &[];

    // vDSO placement — see the QEMU riscv64 block above for the mechanism.
    // VF2's RAM_BASE (0x4000_0000) is exactly the collision `VDSO_USER_BASE`
    // used to hit (`0x5000_0000`, same VPN[2]=1 slot) before this fix.
    const _: () = {
        use azos_abi::vdso::{vdso_is_below_ram, vdso_shares_a_2mib_slot_with as collides};
        const CLINT_BASE: usize = 0x0200_0000; // kernel/src/main.rs literal (VF2 arm)
        const CLINT_SIZE: usize = 0x1_0000;
        assert!(vdso_is_below_ram(RAM_BASE), "vDSO is not below VF2 RAM");
        assert!(!collides(UART_BASE, 0x1000), "vDSO shares VF2 UART's 2 MiB slot");
        assert!(!collides(PLIC_BASE, 0x40_0000), "vDSO shares VF2 PLIC's 2 MiB slot");
        assert!(!collides(CLINT_BASE, CLINT_SIZE), "vDSO shares VF2 CLINT's 2 MiB slot");
        assert!(!collides(GPIO_BASE, 0x1000), "vDSO shares VF2 GPIO's 2 MiB slot");
        assert!(!collides(PWM_BASE, 0x1000), "vDSO shares VF2 PWM's 2 MiB slot");
        assert!(!collides(I2C0_BASE, 0x1000), "vDSO shares VF2 I2C0's 2 MiB slot");
        assert!(!collides(I2C1_BASE, 0x1000), "vDSO shares VF2 I2C1's 2 MiB slot");
        assert!(!collides(MMC0_BASE, 0x1000), "vDSO shares VF2 MMC0's 2 MiB slot");
        assert!(!collides(MMC1_BASE, 0x1000), "vDSO shares VF2 MMC1's 2 MiB slot");
        assert!(!collides(ETH0_BASE, 0x1000), "vDSO shares VF2 ETH0's 2 MiB slot");
        assert!(!collides(UART1_BASE, 0x1000), "vDSO shares VF2 UART1's 2 MiB slot");
        assert!(!collides(WDT_BASE, 0x1000), "vDSO shares VF2 WDT's 2 MiB slot");
        assert!(!collides(DC8200_TOP_BASE, 0x1000), "vDSO shares VF2 DC8200 top's 2 MiB slot");
        assert!(!collides(DC8200_MAIN_BASE, 0x2000), "vDSO shares VF2 DC8200 main's 2 MiB slot");
        assert!(!collides(DC8200_NOC_BASE, 0x1000), "vDSO shares VF2 PMU's 2 MiB slot");
        assert!(!collides(HDMI_TX_BASE, 0x1000), "vDSO shares VF2 HDMI TX's 2 MiB slot");
        assert!(!collides(SPI0_BASE, 0x1000), "vDSO shares VF2 SPI0's 2 MiB slot");
        assert!(!collides(USB0_BASE, 0x1_0000), "vDSO shares VF2 USB0's 2 MiB slot");
        assert!(!collides(DMA_AXI_BASE, 0x1000), "vDSO shares VF2 DMA(axi)'s 2 MiB slot");
        assert!(!collides(DMA_SDMA_BASE, 0x1000), "vDSO shares VF2 DMA(sdma)'s 2 MiB slot");
    };

    /// The compatible string becomes a checked field, not a comment (U05-1's
    /// own mechanism fix — a base address that drifted from its citation
    /// used to be silent). Cheap sanity only: every corrected `compatible`
    /// above must be non-empty and carry a real Linux vendor/IP prefix, so a
    /// future edit that empties or garbles one of these strings fails the
    /// build instead of silently going back to being a comment.
    const _: () = {
        const fn has_prefix(s: &str) -> bool {
            let b = s.as_bytes();
            !b.is_empty() && (
                starts_with(b, b"starfive,") || starts_with(b, b"snps,") ||
                starts_with(b, b"arm,")
            )
        }
        const fn starts_with(s: &[u8], prefix: &[u8]) -> bool {
            if s.len() < prefix.len() { return false; }
            let mut i = 0;
            while i < prefix.len() {
                if s[i] != prefix[i] { return false; }
                i += 1;
            }
            true
        }
        assert!(has_prefix(I2C_COMPATIBLE), "I2C_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(SPI_COMPATIBLE), "SPI_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(WDT_COMPATIBLE), "WDT_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(ETH0_COMPATIBLE), "ETH0_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(USB0_COMPATIBLE), "USB0_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(DMA_AXI_COMPATIBLE), "DMA_AXI_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(DMA_SDMA_COMPATIBLE), "DMA_SDMA_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(PMU_COMPATIBLE), "PMU_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(PWM_COMPATIBLE), "PWM_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(UART_COMPATIBLE), "UART_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(PLIC_COMPATIBLE), "PLIC_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(GPIO_COMPATIBLE), "GPIO_COMPATIBLE lost its vendor prefix");
    };
}

// ── SpacemiT K1 (BananaPi BPI-F3) ─────────────────────────────────────────────
#[cfg(feature = "k1")]
pub mod hw {
    pub const PLATFORM_NAME: &str = "SpacemiT K1 (BananaPi BPI-F3)";

    /// SpacemiT K1 UART0 — "intel,xscale-uart" compatible (NS16550A register layout).
    /// Clock: 14 MHz.  U-Boot/OpenSBI configures 115200 baud before kernel hand-off.
    pub const UART_BASE:   usize = 0xD401_7000;
    /// `serial@d4017000` in mainline `k1.dtsi`: `compatible = "spacemit,k1-
    /// uart", "intel,xscale-uart"`, `reg-shift = <2>`, `reg-io-width = <4>`
    /// — a 4-byte-strided register file, NOT the byte-addressed NS16550A
    /// model `crates/drivers/sys/src/uart.rs` uses under `cfg(not(feature =
    /// "vf2"))` (which also covers `k1`; see U05-4). Not this crate's file
    /// to fix (owned by `uart.rs`'s front this wave) — recorded here so the
    /// compatible string is checked, not just commented.
    pub const UART_COMPATIBLE: &str = "spacemit,k1-uart";
    /// SpacemiT K1 PLIC (Platform-Level Interrupt Controller).
    /// 256 external interrupt sources, M-mode + S-mode per hart.
    pub const PLIC_BASE:   usize = 0xE000_0000;
    pub const PLIC_COMPATIBLE: &str = "spacemit,k1-plic";
    /// K1 `mtime` timebase (from DTS: timebase-frequency = <24000000>).
    pub const TIMER_FREQ:  u64   = azos_limits::TIMER_FREQ as u64;   // Kconfig TIMER_FREQ (V2.6): 24 MHz under BOARD_K1
    /// SpacemiT K1 is a different vendor/SoC from the JH7110 (StarFive) —
    /// the JH7110 clock-tree research that confirmed `WDT_CLK_HZ` for the
    /// vf2 block above (see its doc comment) does NOT transfer here; K1's
    /// own WDT IP and clock tree haven't been traced from primary source.
    /// This value is provisional (matches TIMER_FREQ, which is a real DTS
    /// value, but that's not evidence the WDT's own core clock is the
    /// same rate) pending real hardware/TRM access for K1 specifically.
    pub const WDT_CLK_HZ:  u64   = 24_000_000;
    /// 8× SpacemiT X60 application cores.
    pub const NUM_CPUS:    usize = 8;
    /// K1 physical DDR base (LPDDR4X starts at address 0x0).
    pub const RAM_BASE:    usize = 0x0000_0000;
    /// Kernel load address (OpenSBI reserves first 2 MiB; kernel follows).
    pub const KERNEL_LOAD: usize = 0x0020_0000;

    // ── GPIO / Pinctrl ────────────────────────────────────────────────────────
    /// **Was `0xD401_E000` — that is `pinctrl@d401e000`
    /// ("spacemit,k1-pinctrl"), not GPIO.** Mainline `k1.dtsi`'s real GPIO
    /// block is `gpio@d4019000`, `compatible = "spacemit,k1-gpio"`,
    /// confirmed 2026-09-26. Register offsets below (`GPIO_DOUT0`/
    /// `GPIO_OEN0`/`GPIO_DIN0`) are unchanged and still unverified against
    /// this IP's actual layout — this is a base-address correction only,
    /// same class as `I2C1_BASE` below. Moot until U05-4's `compile_error!`
    /// lands: `gpio.rs`'s `k1` build drives the QEMU simulation, not this
    /// address, either way.
    pub const GPIO_BASE:   usize = 0xD401_9000;
    pub const GPIO_COMPATIBLE: &str = "spacemit,k1-gpio";
    /// Output data register offset (32-bit, GPIOs 0-31).
    pub const GPIO_DOUT0:  usize = 0x000;
    /// Output enable register offset (0 = output).
    pub const GPIO_OEN0:   usize = 0x004;
    /// Input data register offset.
    pub const GPIO_DIN0:   usize = 0x010;

    // ── PWM ───────────────────────────────────────────────────────────────────
    /// SpacemiT K1 PWM0 base — confirmed against `k1.dtsi`'s
    /// `pwm0@d401a000`, `compatible = "spacemit,k1-pwm", "marvell,pxa910-
    /// pwm"` (**not** `"spacemit,k1x-pwm"` — corrected 2026-09-26).
    pub const PWM_BASE:    usize = 0xD401_A000;
    pub const PWM_COMPATIBLE: &str = "spacemit,k1-pwm";
    /// **Was `0x10` — the mainline DTS instantiates one `pwm@` node PER
    /// CHANNEL, stepping by `0x400`** (`pwm0@d401a000`, `pwm1@d401a400`,
    /// … `pwm7@d401bc00`, `pwm8@d4020000`, …): eight separate 1 KiB
    /// register windows, not eight 16-byte slots in one window. Corrected
    /// 2026-09-26; the per-window register layout itself
    /// (`marvell,pxa910-pwm`) is still unverified — same "address fixed,
    /// register model not" class as `SPI0_BASE`/`I2C1_BASE`.
    pub const PWM_STRIDE:  usize = 0x400;
    /// Channel duty cycle offset.
    pub const PWM_DUTY:    usize = 0x04;
    /// Channel period offset.
    pub const PWM_PERIOD:  usize = 0x08;
    /// Channel enable offset.
    pub const PWM_ENABLE:  usize = 0x0C;

    // ── I2C ("spacemit,k1-i2c", not DesignWare) ─────────────────────────────
    /// I2C6 base — confirmed against `k1.dtsi`'s `i2c6@d4018800`. Compatible
    /// is `"spacemit,k1-i2c"`, not the DesignWare IP this file's header
    /// implied — recorded so a real driver ports against the right IP.
    pub const I2C0_BASE:   usize = 0xD401_8800;
    pub const I2C_COMPATIBLE: &str = "spacemit,k1-i2c";
    /// **Was `0xD401_8C00` — no node exists there in mainline `k1.dtsi`**
    /// (it falls between `i2c6@d4018800` and `gpio@d4019000`, in neither's
    /// declared `reg` range). The real `i2c7` is at `0xD401_D000`.
    /// Corrected 2026-09-26.
    pub const I2C1_BASE:   usize = 0xD401_D000;

    // ── eMMC / SD (DesignWare SDHCI) ─────────────────────────────────────────
    /// SDHCI0 base — removable SD card slot on BPI-F3.
    /// Used as the boot storage device (MmcSlot::Emmc = 0 → MMC0_BASE).
    pub const MMC0_BASE:   usize = 0xD428_0000;
    /// SDHCI2 base — onboard eMMC (HS400, non-removable).
    pub const MMC1_BASE:   usize = 0xD428_1000;

    // ── Watchdog: NO NODE IN MAINLINE — see `wdt.rs::wdt_has_hardware` ──────
    /// **Not a watchdog.** `0xD401_5000` is `syscon_apbc:
    /// system-controller@d4015000`, `compatible = "spacemit,k1-syscon-
    /// apbc"` in mainline `k1.dtsi` (confirmed 2026-09-26) — and mainline
    /// has no watchdog node anywhere on this SoC (`grep -i "watchdog\|wdt"
    /// k1.dtsi` → none). Kept as a named constant only because
    /// `wdt.rs`'s `hw_wdt_init` used to write here under `feature = "k1"`;
    /// that call is now gated off by `wdt_has_hardware()` returning `false`
    /// for `k1` (U05-3) — this address is unused, not a corrected target.
    pub const WDT_BASE:    usize = 0xD401_5000;

    // ── NPU (Neural Processing Unit) ─────────────────────────────────────────
    /// SpacemiT K1 NPU MMIO base.
    /// Compatible: "spacemit,k1x-npu".  Reference: K1 BSP DTS (bpi-f3.dts).
    /// Performance: ~2 TOPS INT8; supports conv, pool, activation, eltwise.
    pub const NPU_BASE:    usize = 0xC080_0000;
    /// NPU MMIO region size (1 MiB covers all command/data registers).
    pub const NPU_SIZE:    usize = 0x0010_0000;

    /// MMIO regions a topology can grant to ring 3 (RFC-0043). Empty: every
    /// `mmio.N` is refused at mint and every index at `SYS_MMIO_MAP`.
    pub const MMIO_REGIONS: &[super::MmioRegion] = &[];

    // vDSO placement — K1 is the one board NO value of `VDSO_USER_BASE` can
    // fix, and this assert encodes *that* fact rather than silently omitting
    // a check. `RAM_BASE == 0` means the kernel's megapage identity map
    // starts at VA 0 and, on any board with enough installed RAM, owns the
    // whole VPN[2]=0 slot outright — the same slot `VDSO_USER_BASE` lives in
    // (chosen there because vpn2=0 is where every OTHER board's kernel
    // mapping is confined to a sparse cluster of 2 MiB windows, not a
    // contiguous megapage run from VA 0). This is `crates/core/sched/src/
    // process.rs`'s `USER_STACK_TOP`/K1 note and `crates/core/mm/src/vmm.rs`'s
    // `kernel_entry_collision` K1 note, restated as a build-time pin: if K1
    // ever stops setting `RAM_BASE = 0`, this assert breaks and the vDSO
    // placement for K1 needs re-deriving, not silently trusting the old
    // reasoning.
    const _: () = {
        assert!(RAM_BASE == 0, "K1's RAM_BASE changed — re-derive the vDSO/K1 exclusion note");
    };

    /// Same mechanism as the vf2 block: the compatible string is a checked
    /// field, not a comment.
    const _: () = {
        const fn has_prefix(s: &str, prefix: &str) -> bool {
            let (b, p) = (s.as_bytes(), prefix.as_bytes());
            if b.len() < p.len() { return false; }
            let mut i = 0;
            while i < p.len() {
                if b[i] != p[i] { return false; }
                i += 1;
            }
            true
        }
        assert!(has_prefix(UART_COMPATIBLE, "spacemit,"), "K1 UART_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(PLIC_COMPATIBLE, "spacemit,"), "K1 PLIC_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(GPIO_COMPATIBLE, "spacemit,"), "K1 GPIO_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(PWM_COMPATIBLE, "spacemit,"), "K1 PWM_COMPATIBLE lost its vendor prefix");
        assert!(has_prefix(I2C_COMPATIBLE, "spacemit,"), "K1 I2C_COMPATIBLE lost its vendor prefix");
    };
}

// ── QEMU virt (aarch64) ──────────────────────────────────────────────────────
//
// `target_os = "none"` in addition to the arch check, matching the guard
// `crates/core/arch`'s facade uses: the host toolchain is `aarch64-apple-darwin`,
// so `target_arch = "aarch64"` alone is also true for `cargo test`/`cargo
// build` run directly on this Mac, not just for the bare-metal target. Every
// host-side crate that reaches a driver crate goes through a `#[path]`
// shim of its own drivers module (see `crates/*-tests/shims/drivers`) rather
// than this one, so this block never needs to build for the host — but
// without the `target_os` guard it would try to, and its MMIO reads would be
// real ARM system-register asm compiled for the wrong purpose.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod hw {
    pub const PLATFORM_NAME: &str = "QEMU virt (aarch64)";

    /// PL011 UART0 base — QEMU `virt` machine (`hw/arm/virt.c`'s
    /// `VIRT_UART0` MemMapEntry, and `tests/qemu/aarch64-smoke/aarch64-virt.ld`'s
    /// own header comment, same address, independently confirmed by that
    /// crate's boot log). See `crates/drivers/sys/src/uart.rs`'s `pl011` module
    /// for the register layout.
    pub const UART_BASE:   usize = 0x0900_0000;
    pub const UART_COMPATIBLE: &str = "arm,pl011";
    // UART IRQ number lives in `azos_drv_sys::uart::UART_IRQ`, not here — matching
    // the convention the RISC-V blocks above already use (10/32 are defined
    // in `uart.rs`, per-feature, not in `platform::hw`).
    /// ARMv8 generic-timer counter frequency (`CNTFRQ_EL0`), as QEMU's
    /// `target/arm/cpu.c` sets it on CPU reset for a current (>= 9.0)
    /// machine type: `GTIMER_DEFAULT_HZ` = 1 GHz, architecturally mandated
    /// for ARMv8.6+ and QEMU's unconditional default otherwise unless the
    /// old `GTIMER_BACKCOMPAT_HZ` (62.5 MHz) compat property is set for a
    /// pre-9.0 versioned machine type — which the gate's `-M virt` (no
    /// version pin) is not. Confirmed against a fetch of QEMU
    /// `target/arm/cpu.c` (`master`, 2026-09-21). Still a **compile-time
    /// constant standing in for a runtime register** — see `WDT_CLK_HZ` on
    /// the K1 block above for the same honesty caveat: this is the value
    /// for the specific `-M virt -cpu cortex-a72` config
    /// `tests/qemu/aarch64-smoke`'s Makefile targets use, not a promise CNTFRQ_EL0
    /// cannot differ under a different CPU/machine-version combination.
    /// [`timer_freq_hw`] reads the live register so a boot path can assert
    /// the two agree, the same shape `kernel/src/main.rs` already uses to
    /// cross-check the RISC-V `TIMER_FREQ` constant against the DTB.
    pub const TIMER_FREQ:  u64   = azos_limits::TIMER_FREQ as u64;
    /// Maximum usable CPU cores. `aarch64-smoke`'s two-PE boot path is the
    /// only aarch64 SMP exercised so far; matches the RISC-V QEMU value
    /// pending a real per-board discovery path on this ISA.
    pub const NUM_CPUS:    usize = 4;
    /// Physical RAM base — `hw/arm/virt.c`'s `VIRT_MEM` MemMapEntry, and
    /// `aarch64-virt.ld`'s `MEMORY` block, same address.
    pub const RAM_BASE:    usize = 0x4000_0000;
    /// Kernel load address: `aarch64-virt.ld` starts `.text` at
    /// `ORIGIN(ram)` = this address, matching QEMU's `-kernel` mini-loader
    /// convention for `virt` (32 KiB reserved below it for the FDT/boot
    /// data QEMU places there before jumping in).
    pub const KERNEL_LOAD: usize = 0x4008_0000;

    /// Read the generic timer's counter frequency straight from
    /// `CNTFRQ_EL0`, instead of trusting [`TIMER_FREQ`]'s compile-time
    /// value — the RISC-V-side analogue of `kernel/src/main.rs`'s DTB vs
    /// `platform::hw::TIMER_FREQ` mismatch check, offered here so an
    /// aarch64 boot path can run the same cross-check.
    pub fn timer_freq_hw() -> u64 {
        azos_arch::cpu::timer_freq_hw()
    }

    /// The MMIO regions a topology can grant to ring 3 (RFC-0043), mirroring
    /// the QEMU-virt riscv64 table above: the board's RTC, read-only, plus
    /// one writable region granted to nobody in the default topology (used
    /// only to prove an UNGRANTED index is refused as a capability denial,
    /// not as an out-of-range index — see `userspace/tests/captest`'s
    /// `mmio_map(1, READ)` check). Left empty until 2026-09-22, when this
    /// board grew a real userspace exec path and the two tests that exercise
    /// this table (captest, and the `[GIC]`-adjacent MMIO refusal checks)
    /// started actually running on it.
    ///
    /// Both entries are addresses this SAME module already names —
    /// `RTC_BASE` and `VIRTIO_MMIO_BASE`, declared below — restated nowhere.
    pub const MMIO_REGIONS: &[super::MmioRegion] = &[
        // 0: PL031 RTC (`RTC_BASE`). Read-only, same role as the riscv64
        // table's goldfish RTC: `userspace/tests/captest` maps it and reads a
        // live, non-zero value back through it. PL031's register layout
        // differs from goldfish's (RTCDR at offset 0x00 is the current
        // seconds-since-epoch value directly, not a latching TIME_LOW/
        // TIME_HIGH pair), but captest's read is `low | high != 0` — RTCDR
        // alone is non-zero the moment QEMU seeds a real host clock, so the
        // same generic check holds without knowing which RTC IP answered it.
        super::MmioRegion { base: RTC_BASE, size: 0x1000, writable: false },
        // 1: the first VirtIO-MMIO transport slot (`VIRTIO_MMIO_BASE`).
        // Writable, and granted to nobody — the kernel already maps and
        // drives this window itself (`blkdev::init`'s probe), so exposing
        // its address here grants no NEW reachability; it exists only so
        // index 1 is a valid, writable table entry that nothing has been
        // handed, mirroring the riscv64 table's spare platform-bus page.
        super::MmioRegion { base: VIRTIO_MMIO_BASE, size: 0x1000, writable: true },
        // 2: the same PL031, writable. The one ring-3-triggerable interrupt
        // source on this board: `userspace/tests/captest`'s IRQ section writes the
        // match register (RTCMR = RTCDR raises the alarm at once), clears it
        // through RTCICR, and binds its line (`RTC_IRQ`, INTID 34) to prove
        // delivery to ring 3 and mask-until-ACK. It ALIASES index 0 — the
        // same page at a second authority level — which is the one exception
        // to "no two regions overlap" (that host test reads the riscv64
        // table). Granted only by the qemu topology on aarch64.
        super::MmioRegion { base: RTC_BASE, size: 0x1000, writable: true },
    ];

    // ── VirtIO-MMIO transport window ─────────────────────────────────────────
    //
    // Confirmed 2026-09-21 by decoding the device tree QEMU itself generates
    // (`qemu-system-aarch64 -M virt,gic-version=3 -cpu cortex-a72 -smp 2
    // -dumpdtb=... ` then `dtc -I dtb -O dts`, the exact `-M`/`-cpu`/`-smp`
    // this project's own `tools/ci_check.sh` `aarch64_smoke_row` boots with —
    // not a default `-M virt` invocation, which picks GICv2 and would be the
    // wrong config to read this from). The DTB lists 32
    // `virtio_mmio@a000000`..`virtio_mmio@a003e00` nodes, `reg` stepping by
    // `0x200`, each with its own `interrupts = <0 N 1>` (SPI N, N = 16..47,
    // one more than the previous node every time).
    /// First VirtIO-MMIO transport slot (`hw/arm/virt.c`'s `VIRT_MMIO`
    /// MemMapEntry). Mirrors `VIRTIO_MMIO_BASE` in `azos_drv_virtio::virtio` for the
    /// RISC-V `virt` board (0x1000_1000) — a different base, same "32 fixed
    /// MMIO slots, probe each for a device" transport `azos_drv_virtio::virtio::mod`
    /// already implements ISA-generically.
    pub const VIRTIO_MMIO_BASE:  usize = 0x0A00_0000;
    /// Bytes between one slot's `reg` and the next.
    pub const VIRTIO_MMIO_STRIDE: usize = 0x200;
    /// Number of slots QEMU wires up.
    pub const VIRTIO_MMIO_COUNT: usize = 32;
    /// GIC INTID of slot 0 (SPI 16 → INTID 32 + 16). Slot `n`'s INTID is
    /// `VIRTIO_IRQ_BASE + n` — same "SPI = 32 + n" convention `uart.rs`'s
    /// `UART_IRQ` already uses for this board (SPI 1 → INTID 33). Not
    /// consumed anywhere yet: no aarch64 driver reads it through the GIC (or
    /// takes any interrupt at all) before this crate's IRQ dispatch exists —
    /// today's transport polls (see `azos_drv_virtio::virtio::mod` module doc).
    pub const VIRTIO_IRQ_BASE: u32 = 48;

    // ── RTC (PL031) ───────────────────────────────────────────────────────────
    /// `hw/arm/virt.c`'s `VIRT_RTC` MemMapEntry — same DTB fetch as above
    /// (`pl031@9010000`). No driver reads this yet; recorded for whichever
    /// one lands first, same reasoning as `VIRTIO_IRQ_BASE`.
    pub const RTC_BASE: usize = 0x0901_0000;
    /// `pl031@9010000`'s `interrupts = <0 2 4>` → SPI 2 → INTID 34.
    pub const RTC_IRQ: u32 = 34;

    // ── GIC ───────────────────────────────────────────────────────────────────
    // Deliberately NOT re-declared here: `crates/core/arch-aarch64/src/gic.rs`
    // already defines `GICD_BASE` (0x0800_0000) and `GICR_BASE`
    // (0x080A_0000) — that crate's own DTB-confirmed constants (same
    // `gic-version=3` fetch as this module's — its GICv3 `intc@8000000`
    // node: `reg = <0x8000000 0x10000  0x80a0000 0xf60000>`, distributor
    // then the whole redistributor region). Re-stating the same two
    // addresses here would be a second copy of a number this crate does not
    // own; a future `crates/drivers/irqchip` GIC/IRQ-dispatch consumer reaches them
    // via `azos_arch_aarch64::gic::{GICD_BASE, GICR_BASE}`, not a new
    // `platform::hw` constant.

    // vDSO placement — see the QEMU riscv64 block's comment at the top of
    // this file for the mechanism. `RAM_BASE` (0x4000_0000) is exactly the
    // collision this task fixed: same VPN[2]=1 slot as VF2's, so the old
    // `VDSO_USER_BASE = 0x5000_0000` collided here too, not just on VF2.
    // GICD/GICR read through `azos_arch::gic` (re-exported from
    // `azos_arch_aarch64` under the same `target_os = "none"` cfg this
    // whole module is gated on) rather than restated, per the comment above.
    const _: () = {
        use azos_abi::vdso::{vdso_is_below_ram, vdso_shares_a_2mib_slot_with as collides};
        // Mirrors `kernel/src/main.rs`'s `const MAX_HARTS: usize = 8` — the
        // literal `map_mmio_region(gic::GICR_BASE, gic::GICR_STRIDE *
        // MAX_HARTS)` call actually maps with. Not imported: the kernel
        // crate depends on this one, not the other way around, so there is
        // no reverse path to the real constant; margin here is ~63 MiB
        // (see the module doc), so even a stale copy cannot silently pass
        // a real collision.
        const MAX_HARTS_MIRROR: usize = 8;
        assert!(vdso_is_below_ram(RAM_BASE), "vDSO is not below aarch64 QEMU virt RAM");
        assert!(!collides(UART_BASE, 0x1000), "vDSO shares aarch64 QEMU virt UART's 2 MiB slot");
        assert!(
            !collides(VIRTIO_MMIO_BASE, VIRTIO_MMIO_STRIDE * VIRTIO_MMIO_COUNT),
            "vDSO shares aarch64 QEMU virt VirtIO-MMIO's 2 MiB slot",
        );
        assert!(!collides(RTC_BASE, 0x1000), "vDSO shares aarch64 QEMU virt RTC's 2 MiB slot");
        assert!(
            !collides(azos_arch::gic::GICD_BASE, 0x1_0000),
            "vDSO shares aarch64 QEMU virt GICD's 2 MiB slot",
        );
        assert!(
            !collides(azos_arch::gic::GICR_BASE, azos_arch::gic::GICR_STRIDE * MAX_HARTS_MIRROR),
            "vDSO shares aarch64 QEMU virt GICR's 2 MiB slot",
        );
    };
}

// ── MMIO region table (RFC-0043) ──────────────────────────────────────────────

/// One entry of a board's MMIO region table (`hw::MMIO_REGIONS`).
///
/// An `MmioRegion` capability names an index into the table, and
/// `SYS_MMIO_MAP` maps exactly `base..base + size`, read-only unless
/// `writable`. Every entry is page aligned, outside RAM, overlaps no other
/// entry, fits one user MMIO mapping (1 MiB) and has a base below 4 GiB, the
/// width of the denial record (`tests/host/topology-tests`, `mmio_table_tests`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MmioRegion {
    /// Physical base address.
    pub base: usize,
    /// Size in bytes, a whole number of pages.
    pub size: usize,
    /// Whether ring 3 may be granted, and map, the region writable.
    pub writable: bool,
}

/// The region at `index` in this board's table, `None` outside it.
pub const fn mmio_region(index: u32) -> Option<MmioRegion> {
    let table = hw::MMIO_REGIONS;
    if (index as usize) < table.len() {
        Some(table[index as usize])
    } else {
        None
    }
}

/// The object a `SAFETY_CAP_DENIED` record names for an `MmioRegion`
/// capability over `index`: the region's base, as the record carried before
/// the capability named an index, and 0 for an index outside the table.
pub const fn mmio_region_record_base(index: u32) -> u32 {
    match mmio_region(index) {
        Some(r) => r.base as u32,
        None => 0,
    }
}
