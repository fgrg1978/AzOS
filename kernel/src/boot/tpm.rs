// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The TPM 2.0 at boot (Kconfig `TPM`): the kernel's three uses of the driver.
//!
//! The driver (`azos_tpm`) is pure: it speaks the TIS/FIFO protocol to a
//! register file and a clock it is handed. This file is what only the kernel
//! can do: find the TPM, hand the driver its registers and the clock, hold the
//! one device, and give the rest of the boot its three uses of it.
//!
//! * **Entropy.** [`random`] is a pool seed source next to virtio-rng and the
//!   CPU instruction (`entropy.rs`, Kconfig `ENTROPY_TPM_SOURCE`).
//! * **Measured boot.** Each boot stage whose digest the kernel knows is
//!   extended into a PCR, in the order the boot learns them: the kernel image
//!   ([`init`]), the configuration it loaded ([`measure_config`]) and the
//!   topology it installed ([`measure_topology`]). One decision record
//!   (`Rule::MeasuredBoot`) per extend, so the first records of a boot say
//!   what was measured.
//! * **The OTA rollback floor.** With Kconfig `OTA_FLOOR_TPM_NV` an NV index
//!   holds the epoch floor beside BOOTMETA's (`azos_ota::floor`).
//! * **The keystore's root.** With Kconfig `KEYSTORE_TPM_NV` a 32-byte NV
//!   index holds the secret that keys opened with the `tpm_nv` backend derive
//!   from ([`install_keystore_root`]; `azos_syscall::keys`).
//!
//! # Where the TPM is
//!
//! * x86_64: the ACPI `TPM2` table. Start method 6 is the PC-client TIS
//!   window; 7 is the Command Response Buffer (`azos_tpm::crb`) at the
//!   table's control area, its locality registers 0x40 below it, its buffers
//!   where the control area says; 2 and 8 are the CRB with an ACPI start,
//!   driven with `START` alone (the `_DSM` needs an AML interpreter). The
//!   windows are the table's and the control area's: the TPM device's `_CRS`
//!   is AML too.
//! * riscv64, aarch64: the first device-tree node compatible with
//!   `tcg,tpm_tis-spi`. Its `reg` is the chip select, `spi-max-frequency` the
//!   clock; the bus is Kconfig `TPM_SPI_BUS`. The bytes go through the `Spi`
//!   device interface (`azos_devif`), the same one a ring-3 driver would use.
//!
//! No TPM, a TPM that does not answer, or one that is not a TPM 2.0 leaves the
//! boot exactly as it was: every entry point below is then a no-op. A TPM that
//! fails later costs the stage it failed on (counted and printed), never the
//! boot. A TPM whose SHA-256 bank does not hold the boot's three PCRs (its
//! firmware allocated other banks: `GetCapability(TPM_CAP_PCRS)`, asked at
//! [`init`]) is not extended at all, and the boot says so once: the TPM
//! would accept each extend and drop it.
//!
//! # The clock
//!
//! The driver polls, bounded by the PTP timeouts. `pause_us` spins on the
//! timebase: this runs before the scheduler runs anything else, and the waits
//! are microseconds in practice. A dead TPM costs its timeouts once (a few
//! seconds) and is then dropped. The one long wait is `NV_DefineSpace`
//! (up to 30 s on a slow part), once per device, when the floor index is
//! first provisioned.

use azos_decision::{Rule, Verdict};
use azos_tpm::tis::{Clock, Tis};
use azos_tpm::tpm::{Tpm, FLOOR_INDEX};
use azos_tpm::Error;
use azos_arch_api::entropy::CpuCredit;
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::*;

/// Kconfig `ENTROPY_TPM_SOURCE`: what the boot does with the TPM's bytes.
pub(crate) const CREDIT: CpuCredit = if azos_limits::ENTROPY_TPM_SOURCE_OFF {
    CpuCredit::Off
} else if azos_limits::ENTROPY_TPM_SOURCE_MIX {
    CpuCredit::MixOnly
} else {
    CpuCredit::Credit
};

/// The boot stages, in `Rule::MeasuredBoot`'s `stage` numbering. The PCR is
/// `TPM_PCR_BASE + stage - 1`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Stage {
    Kernel = 1,
    Config = 2,
    Topology = 3,
}

impl Stage {
    fn pcr(self) -> u8 {
        azos_limits::TPM_PCR_BASE as u8 + self as u8 - 1
    }

    fn name(self) -> &'static str {
        match self {
            Stage::Kernel => "kernel",
            Stage::Config => "config",
            Stage::Topology => "topology",
        }
    }
}

// ── The kernel's side of the driver: the clock, the registers ────────────────

struct KClock;

impl KClock {
    fn us() -> u64 {
        (azos_drv_sys::timebase::now() as u128 * 1_000_000
            / (azos_drv_sys::timebase::TIMER_FREQ as u128).max(1)) as u64
    }
}

impl Clock for KClock {
    fn now_us(&mut self) -> u64 {
        Self::us()
    }

    fn pause_us(&mut self, us: u32) {
        let t0 = Self::us();
        while Self::us().wrapping_sub(t0) < u64::from(us) {
            core::hint::spin_loop();
        }
    }
}

/// Volatile accesses to the TIS window, or to the CRB's registers and
/// buffers, which [`probe`] mapped.
#[cfg(target_arch = "x86_64")]
struct Mmio;

#[cfg(target_arch = "x86_64")]
impl azos_tpm::mmio::MmioAccess for Mmio {
    fn read8(&mut self, addr: u64) -> u8 {
        // SAFETY: inside the window `probe` mapped (identity: VA = PA).
        unsafe { azos_arch_api::mmio::read8(addr as usize) }
    }
    fn read32(&mut self, addr: u64) -> u32 {
        // SAFETY: as above; the driver reads dwords only at 4-aligned registers.
        unsafe { azos_arch_api::mmio::read32(addr as usize) }
    }
    fn write8(&mut self, addr: u64, v: u8) {
        // SAFETY: as above.
        unsafe { azos_arch_api::mmio::write8(addr as usize, v) }
    }
    fn write32(&mut self, addr: u64, v: u32) {
        // SAFETY: as above; the CRB driver writes dwords only at its 4-aligned
        // control registers.
        unsafe { azos_arch_api::mmio::write32(addr as usize, v) }
    }
}

/// x86_64's two interfaces, chosen by the TPM2 table at run time.
#[cfg(target_arch = "x86_64")]
enum Iface {
    Tis(Tis<azos_tpm::mmio::MmioTis<Mmio>, KClock>),
    Crb(azos_tpm::crb::Crb<Mmio, KClock>),
}

#[cfg(target_arch = "x86_64")]
impl azos_tpm::Transport for Iface {
    fn probe(&mut self) -> Result<azos_tpm::tis::DeviceInfo, Error> {
        match self {
            Iface::Tis(t) => t.probe(),
            Iface::Crb(c) => c.probe(),
        }
    }
    fn transmit(&mut self, cmd: &[u8], rsp: &mut [u8], dur: azos_tpm::tis::Duration) -> Result<usize, Error> {
        match self {
            Iface::Tis(t) => t.transmit(cmd, rsp, dur),
            Iface::Crb(c) => c.transmit(cmd, rsp, dur),
        }
    }
    fn pause_us(&mut self, us: u32) {
        KClock.pause_us(us)
    }
}

/// The driver's SPI bus over the `Spi` device interface. The driver holds
/// chip select across a whole transaction (header, wait states, data); the
/// interface has `hold_cs` for that and carries at most `MAX_BYTES` a call,
/// so a transfer longer than that is several calls under one hold.
#[cfg(not(target_arch = "x86_64"))]
struct DevifSpi {
    port: azos_drv_bus::spi::SpiPort,
    /// `hold_cs(true)` was accepted: without it the controller would release
    /// the chip select between calls and every transaction would be torn.
    held: bool,
}

#[cfg(not(target_arch = "x86_64"))]
impl azos_tpm::spi::Spi for DevifSpi {
    fn select(&mut self, on: bool) {
        use azos_devif::Spi as _;
        let ok = self.port.hold_cs(on).is_ok();
        if on {
            self.held = ok;
        }
    }

    fn xfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), azos_tpm::BusError> {
        use azos_devif::Spi as _;
        use azos_devif::i2c::{Bytes, MAX_BYTES};
        if !self.held || tx.len() != rx.len() {
            return Err(azos_tpm::BusError);
        }
        for (t, r) in tx.chunks(MAX_BYTES).zip(rx.chunks_mut(MAX_BYTES)) {
            let out = self.port.transfer(Bytes::from_slice(t));
            if !out.is_ok() || out.value.copy_to(r) != r.len() {
                return Err(azos_tpm::BusError);
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
type Iface = Tis<azos_tpm::spi::SpiTis<DevifSpi>, KClock>;

/// The TPM, once [`init`] found and started it. A sleeping lock: a command is
/// milliseconds, and the floor's raise runs from the watchdog task at run
/// time, so nothing that must not wait ever takes it.
static TPM: Mutex<Option<Tpm<Iface>>> = Mutex::new(None);

/// The SHA-256 bank holds the boot's PCRs (or the TPM could not say): the
/// stages are extended. Cleared by [`init`] when the bank is missing.
static MEASURE: AtomicBool = AtomicBool::new(true);

fn with<T>(f: impl FnOnce(&mut Tpm<Iface>) -> T) -> Option<T> {
    TPM.lock().as_mut().map(f)
}

// ── Finding it ──────────────────────────────────────────────────────────────

/// x86_64: the TIS window or the CRB the `TPM2` table asks for, mapped;
/// `None` when there is no table, it names another interface, the CRB's
/// control area names unusable buffers, or a window cannot be mapped.
#[cfg(target_arch = "x86_64")]
fn probe(_dtb_ptr: usize) -> Option<(Iface, &'static str)> {
    use azos_tpm::acpi::{Interface, Tpm2Table};
    let p = azos_arch::platform_impl::platform();
    let &(_, pa, len) = p.acpi.tables().iter().find(|t| &t.0 == b"TPM2")?;
    // ACPI memory is not in the direct map (the PMM keeps the firmware's
    // reserved ranges out of it); the table is read through an identity alias,
    // as a device window is.
    if !super::map_mmio_region(pa as usize, len as usize) {
        return None;
    }
    // SAFETY: `pa..pa + len` is the table the ACPI walk found and verified,
    // mapped just above.
    let bytes = unsafe { core::slice::from_raw_parts(pa as usize as *const u8, len as usize) };
    let table = match Tpm2Table::parse(bytes) {
        Ok(t) => t,
        Err(e) => {
            azos_drv_sys::kwarn!("[TPM] the ACPI TPM2 table is unusable ({:?}): TPM not used", e);
            return None;
        }
    };
    match table.interface() {
        Interface::Tis { base } => {
            if !super::map_mmio_region(base as usize, 0x1000) {
                return None;
            }
            Some((Iface::Tis(Tis::new(azos_tpm::mmio::MmioTis::new(Mmio, base), KClock, 0)), "acpi TPM2, TIS"))
        }
        Interface::Crb { control_area, start } => {
            use azos_tpm::crb::{self, StartMethod, CTRL_BYTES};
            // The pages from the locality registers (0x40 below, method 7)
            // through the control area: one window, which on the PTP layout
            // holds the buffers too.
            let lo = crb::head_for(control_area, start).unwrap_or(control_area) & !0xFFF;
            let hi = (control_area + CTRL_BYTES + 0xFFF) & !0xFFF;
            if !super::map_mmio_region(lo as usize, (hi - lo) as usize) {
                return None;
            }
            let buf = match crb::read_buffers(&mut Mmio, control_area) {
                Ok(b) => b,
                Err(e) => {
                    azos_drv_sys::kwarn!("[TPM] ACPI TPM2 CRB at {:#x}: its control area names no usable buffers \
                                          ({:?}): TPM not used", control_area, e);
                    return None;
                }
            };
            for (pa, n) in [(buf.cmd, buf.cmd_span()), (buf.rsp, buf.rsp_span())] {
                if !super::map_mmio_region(pa as usize, n as usize) {
                    return None;
                }
            }
            let via = match start {
                StartMethod::Crb => "acpi TPM2, CRB",
                StartMethod::Acpi => "acpi TPM2, CRB with ACPI start (_DSM not run)",
            };
            Some((Iface::Crb(crb::Crb::new(Mmio, KClock, control_area, start, buf)), via))
        }
        Interface::Unsupported(m) => {
            kprintln!("[TPM] ACPI TPM2 start method {}: not driven, TPM not used", m);
            None
        }
    }
}

/// riscv64, aarch64: the device tree's `tcg,tpm_tis-spi` node, on
/// `TPM_SPI_BUS`, if a device answers that chip select.
#[cfg(not(target_arch = "x86_64"))]
fn probe(dtb_ptr: usize) -> Option<(Iface, &'static str)> {
    use azos_devif::Spi as _;
    if dtb_ptr == 0 {
        return None;
    }
    let blob = azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8;
    // SAFETY: the pointer is the one the firmware handed the kernel;
    // `dtb_spi_slave` bounds every read by the blob's own header.
    let node = unsafe { azos_dtb::dtb_spi_slave(blob, b"tcg,tpm_tis-spi") }?;
    let (bus, cs) = (azos_limits::TPM_SPI_BUS as u8, node.cs as u8);
    if node.cs > u32::from(u8::MAX) || !azos_drv_bus::spi::spi_detect(bus, cs) {
        kprintln!("[TPM] device tree node (cs {}) but nothing answers spi.{}.{}: TPM not used",
                  node.cs, bus, cs);
        return None;
    }
    let mut port = azos_drv_bus::spi::SpiPort { bus, cs };
    // The TPM's SPI is mode 0. A controller that cannot take the part's clock
    // keeps the one it has: slower, and the same bytes.
    if !port.set_mode(0).is_ok() {
        azos_drv_sys::kwarn!("[TPM] spi.{}.{}: the controller refused mode 0: TPM not used", bus, cs);
        return None;
    }
    if node.max_hz != 0 {
        let hz = node.max_hz.clamp(azos_devif::spi::SPEED_MIN_HZ, azos_devif::spi::SPEED_MAX_HZ);
        let _ = port.set_speed(hz);
    }
    let regs = azos_tpm::spi::SpiTis::new(DevifSpi { port, held: false });
    Some((Tis::new(regs, KClock, 0), "device tree tcg,tpm_tis-spi"))
}

// ── Bringing it up ──────────────────────────────────────────────────────────

/// A code for the decision record's `how`: the TPM's response code, or a
/// number above 32 bits that names the driver's own error.
fn error_code(e: Error) -> u64 {
    match e {
        Error::Tpm(rc) => u64::from(rc),
        Error::Bus => 1 << 32,
        Error::NoDevice => 2 << 32,
        Error::NotTpm2 => 3 << 32,
        Error::Timeout(_) => 4 << 32,
        Error::BadLocality | Error::BadCommand | Error::BadArgument => 5 << 32,
        Error::ExpectMismatch | Error::BadResponseSize | Error::Truncated
        | Error::TrailingData | Error::Malformed => 6 << 32,
        Error::NvMismatch => 7 << 32,
        Error::Fatal => 8 << 32,
    }
}

/// Is the timebase running? The driver's timeouts are read off it, so a clock
/// that stands still would make every wait endless.
fn clock_runs() -> bool {
    let t0 = azos_drv_sys::timebase::now();
    for _ in 0..1_000_000 {
        if azos_drv_sys::timebase::now() != t0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Find the TPM, start it, extend the kernel image into its PCR and bring up
/// the rollback floor's NV index. `false`, with the boot as it was, when there
/// is no TPM or it does not work. Call once, at the entropy step: after the
/// device windows are mapped, before anything draws from the pool.
pub(crate) fn init(dtb_ptr: usize) -> bool {
    let Some((iface, via)) = probe(dtb_ptr) else { return false };
    if !clock_runs() {
        azos_drv_sys::kwarn!("[TPM] the timebase does not advance: TPM not used");
        return false;
    }
    let mut tpm = Tpm::new(iface);
    let info = match tpm.probe() {
        Ok(i) => i,
        Err(e) => {
            kprintln!("[TPM] {}: no TPM 2.0 answers ({:?})", via, e);
            return false;
        }
    };
    if let Err(e) = tpm.startup(azos_tpm::tpm::StartupType::Clear) {
        azos_drv_sys::kerr!("[TPM] {}: Startup failed ({:?}): TPM not used", via, e);
        return false;
    }
    kprintln!("[TPM] TPM 2.0 vendor {:#06x} device {:#06x} rev {} via {}", info.vid, info.did, info.rid, via);
    check_banks(&mut tpm);
    *TPM.lock() = Some(tpm);
    measure_kernel();
    install_floor();
    true
}

/// Orderly power-off or reboot, the TPM's last command
/// (`azos_syscall::handlers::orderly_storage_down`, through the devices hook):
/// `TPM2_Shutdown(STATE)` (owner decision 2026-10-23), so the next boot's
/// `Startup(CLEAR)` does not count an unorderly shutdown toward the
/// dictionary-attack lockout. The TPM leaves [`TPM`] first: nothing sends it a
/// command after its Shutdown. Bounded by the driver's command timeouts; the
/// power-off goes on whatever it answered.
pub(crate) fn shutdown() {
    let Some(mut tpm) = TPM.lock().take() else { return };
    match tpm.shutdown(azos_tpm::tpm::StartupType::State) {
        Ok(()) => kprintln!("[ORDERLY] tpm: TPM2_Shutdown(STATE) ok"),
        Err(e) => azos_drv_sys::kwarn!("[ORDERLY] tpm: TPM2_Shutdown(STATE) failed ({:?}): the next Startup \
                   counts an unorderly shutdown", e),
    }
}

/// The boot's PCRs, `TPM_PCR_BASE` and the two after it.
fn boot_pcrs() -> core::ops::Range<u8> {
    Stage::Kernel.pcr()..Stage::Topology.pcr() + 1
}

/// The banks, for the boot line: ` sha1 sha256`.
struct Banks<'a>(&'a [azos_tpm::tpm::PcrBank]);

impl core::fmt::Display for Banks<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, " {}", azos_tpm::wire::alg_name(b.alg)))
    }
}

/// Ask the TPM which PCR banks it allocated: the stages go into the SHA-256
/// bank, and a TPM whose SHA-256 bank does not hold the boot's PCRs would
/// accept every extend and drop it, so then none is sent ([`MEASURE`]).
/// Another bank that holds them keeps its reset value there: said once, so a
/// verifier knows to quote SHA-256.
fn check_banks(tpm: &mut Tpm<Iface>) {
    use azos_tpm::wire::ALG_SHA256;
    let pcrs = boot_pcrs();
    let banks = match tpm.pcr_banks() {
        Ok(b) => b,
        Err(e) => {
            azos_drv_sys::kwarn!("[TPM] GetCapability(PCRS) failed ({:?}): the banks are unknown, the boot \
                                  extends SHA-256 unchecked", e);
            return;
        }
    };
    kprintln!("[TPM] PCR banks:{}", Banks(banks.banks()));
    if !banks.holds(ALG_SHA256, pcrs.clone()) {
        MEASURE.store(false, Ordering::Relaxed);
        azos_drv_sys::kwarn!("[TPM] the SHA-256 bank does not hold PCR{}..PCR{} (the firmware's allocation): \
                              the boot is not measured", pcrs.start, pcrs.end - 1);
        return;
    }
    let others = banks.banks().iter().filter(|b| b.alg != ALG_SHA256).count();
    if others != 0 {
        kprintln!("[TPM] the boot extends the sha256 bank only: the {} other bank(s) keep their reset value in \
                   PCR{}..PCR{}", others, pcrs.start, pcrs.end - 1);
    }
}

/// Fill `out` with TPM random bytes (the pool's seed source). `false` when
/// there is no TPM or it failed.
pub(crate) fn random(out: &mut [u8]) -> bool {
    match with(|t| t.get_random(out)) {
        Some(Ok(())) => true,
        Some(Err(e)) => {
            azos_drv_sys::kerr!("[TPM] GetRandom failed ({:?}): no bytes from the TPM", e);
            false
        }
        None => false,
    }
}

// ── Measured boot ───────────────────────────────────────────────────────────

/// Extend `digest` into `stage`'s PCR and write the decision record. `how` is
/// the stage's own detail (see `Rule::MeasuredBoot`). A failed extend is
/// said, recorded as a refusal, and the boot goes on without the stage.
fn extend(stage: Stage, digest: [u8; 32], how: u64) {
    if !MEASURE.load(Ordering::Relaxed) {
        return;
    }
    let pcr = stage.pcr();
    let Some(r) = with(|t| t.pcr_extend(pcr, &digest)) else { return };
    let d8 = u64::from_be_bytes([digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]]);
    match r {
        Ok(()) => {
            azos_decision::record(Rule::MeasuredBoot, Verdict::Admit, u32::from(pcr), [stage as u64, d8, how]);
            kprintln!("[TPM] PCR{} <- {} {:016x}{:016x}{:016x}{:016x}", pcr, stage.name(),
                      d8, be64(&digest[8..16]), be64(&digest[16..24]), be64(&digest[24..32]));
        }
        Err(e) => {
            azos_decision::record(Rule::MeasuredBoot, Verdict::Refuse, u32::from(pcr),
                                  [stage as u64, d8, error_code(e)]);
            azos_drv_sys::kerr!("[TPM] PCR{} extend ({}) FAILED ({:?}): the stage is not measured",
                                pcr, stage.name(), e);
        }
    }
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn sha256(b: &[u8]) -> [u8; 32] {
    azos_crypto::sha256::sha256(b)
}

/// The kernel image: its build-id (SHA-256 of the linked text, before the
/// boot-time rewrites) when Kconfig `LIVEPATCH` computed it, else SHA-256 of
/// the text as it stands now, which is the same on one CPU and one mask but
/// not across CPUs (the PAN and spin sites are rewritten per CPU).
fn measure_kernel() {
    let (digest, how) = match crate::boot::isa::build_id() {
        Some(id) => (id, 0),
        None => {
            let (s, e) = crate::boot::isa::text_range();
            // SAFETY: the kernel's own text, mapped and readable.
            (sha256(unsafe { core::slice::from_raw_parts(s as *const u8, e - s) }), 1)
        }
    };
    extend(Stage::Kernel, digest, how);
}

/// The configuration the boot loaded: `ini` is the CONFIG.INI bytes when its
/// signature verified, `None` when the factory defaults are in force.
pub(crate) fn measure_config(ini: Option<&[u8]>) {
    match ini {
        Some(b) => extend(Stage::Config, sha256(b), 0),
        None => extend(Stage::Config, sha256(b"azos:config:factory-defaults"), 1),
    }
}

/// The topology the boot installed: `caps` is CAPS.TOM when the signed set was
/// installed (it binds SCHED.TOM's hash), `None` for the built-in topology.
pub(crate) fn measure_topology(caps: Option<&[u8]>) {
    match caps {
        Some(b) => extend(Stage::Topology, sha256(b), 0),
        None => extend(Stage::Topology, sha256(b"azos:topology:builtin"), 1),
    }
}

// ── The keystore's root ─────────────────────────────────────────────────────

/// The NV password of the keystore secret's index: a function of the index, as
/// the floor's is. It is built from public constants, so it is NOT a secret
/// (audit K2-H1): what keeps the keystore root is the session lock
/// [`install_keystore_root`] issues right after its read (`secret_lock`).
fn keystore_auth() -> [u8; 32] {
    const TAG: &[u8; 24] = b"azos/keystore-tpm-nv/v1.";
    let mut m = [0u8; 28];
    m[..24].copy_from_slice(TAG);
    m[24..].copy_from_slice(&azos_tpm::tpm::SECRET_INDEX.to_be_bytes());
    sha256(&m)
}

/// Define the keystore secret's NV index (once per TPM), read the secret out
/// of it, drawing it from the entropy pool the first time, lock the index for
/// the rest of the TPM session (no read, no write until the next TPM Reset:
/// nothing that reaches the TPM after this point can read the root or plant
/// one for the next boot), and install it as the root of the `tpm_nv`
/// backend. A secret whose index could not be locked is not installed: the
/// root would be readable by whoever reaches the TPM next. Without Kconfig
/// `KEYSTORE_TPM_NV`, a TPM, or a seeded pool at the first boot, the backend
/// has no root and says `NOT_READY`. The first boot waits on
/// `NV_DefineSpace` (see the module doc).
///
/// Still open (needs policy sessions): code that runs on the TPM BEFORE this
/// boot locks it, such as another OS booted from removable media, reads the
/// index with the public password. A PCR policy over the stages this file
/// measures would close that.
pub(crate) fn install_keystore_root() -> bool {
    use azos_tpm::tpm::{SECRET_BYTES, SECRET_INDEX};
    if !azos_limits::KEYSTORE_TPM_NV || TPM.lock().is_none() {
        return false;
    }
    let auth = keystore_auth();
    let mut fresh = [0u8; SECRET_BYTES as usize];
    // The pool's own lock does not keep preemption off (see `boot/swap.rs`).
    let seeded = {
        let _cs = azos_sync::critical_section();
        azos_crypto::entropy::fill(&mut fresh)
    };
    let r = with(|t| {
        t.secret_provision(&[], SECRET_INDEX, &auth)?;
        if seeded {
            t.secret_load_or_create(SECRET_INDEX, &auth, &fresh).map(Some)
        } else {
            t.secret_read(SECRET_INDEX, &auth)
        }
    });
    azos_crypto::ct::secure_zero(&mut fresh);
    // Whatever the read gave, an index of ours left open could be read now,
    // or written for the next boot to adopt. Not one that is not ours: our
    // password would be a failed authorization there, counted against the
    // TPM's dictionary-attack lockout if that index is not `NO_DA`.
    let locked = match r {
        Some(Err(Error::NvMismatch)) | None => None,
        _ => with(|t| t.secret_lock(SECRET_INDEX, &auth)),
    };
    match r {
        Some(Ok(Some(mut secret))) => {
            if let Some(Err(e)) = locked {
                azos_crypto::ct::secure_zero(&mut secret);
                azos_drv_sys::kerr!("[KEYS] TPM NV index {:#010x} could not be locked for the session ({:?}): \
                                     its secret stays readable, so the tpm_nv backend gets no root", SECRET_INDEX, e);
                return false;
            }
            let ok = azos_syscall::keys::install_root(azos_crypto::keystore::Backend::TpmNv, &secret);
            azos_crypto::ct::secure_zero(&mut secret);
            if ok {
                kprintln!("[KEYS] TPM NV index {:#010x}: the tpm_nv backend has its root (index locked \
                           until the next TPM reset)", SECRET_INDEX);
            }
            ok
        }
        Some(Ok(None)) => {
            azos_drv_sys::kwarn!("[KEYS] TPM NV index {:#010x} holds no secret and the entropy pool is not seeded: \
                                  the tpm_nv backend has no root", SECRET_INDEX);
            false
        }
        Some(Err(Error::NvMismatch)) => {
            azos_drv_sys::kerr!("[KEYS] TPM NV index {:#010x} exists and is not ours (attributes, size or policy \
                                 differ): the tpm_nv backend has no root", SECRET_INDEX);
            false
        }
        Some(Err(Error::Tpm(azos_tpm::wire::RC_NV_LOCKED))) => {
            azos_drv_sys::kerr!("[KEYS] TPM NV index {:#010x} is locked: the TPM was not reset since a boot \
                                 read it (a warm restart that kept the TPM's session); the tpm_nv backend \
                                 has no root until a reset", SECRET_INDEX);
            false
        }
        Some(Err(e)) => {
            azos_drv_sys::kerr!("[KEYS] the TPM NV secret cannot be provisioned or read ({:?}): the tpm_nv \
                                 backend has no root", e);
            false
        }
        None => false,
    }
}

// ── The OTA rollback floor ──────────────────────────────────────────────────

fn floor_auth() -> [u8; 32] {
    azos_ota::floor::nv_auth(FLOOR_INDEX)
}

fn floor_raise(to: u32) -> Option<u32> {
    let auth = floor_auth();
    match with(|t| t.floor_raise(FLOOR_INDEX, &auth, to))? {
        Ok(now) => Some(now),
        Err(e) => {
            azos_drv_sys::kerr!("[TPM] OTA floor: raising to {} FAILED ({:?}): the volume's floor holds alone", to, e);
            None
        }
    }
}

static FLOOR: azos_ota::floor::Backend = azos_ota::floor::Backend { raise: floor_raise };

/// Define the floor's NV index (once per TPM), read it, and install it as the
/// OTA floor's second home. Any failure leaves BOOTMETA's floor holding alone,
/// and says so.
fn install_floor() {
    if !azos_limits::OTA_FLOOR_TPM_NV {
        return;
    }
    let auth = floor_auth();
    let r = with(|t| {
        t.floor_provision(&[], FLOOR_INDEX, &auth)?;
        t.floor_read(FLOOR_INDEX, &auth)
    });
    match r {
        Some(Ok(now)) => {
            azos_ota::floor::install(&FLOOR, now);
            kprintln!("[TPM] OTA rollback floor: NV index {:#010x}, holds epoch {}", FLOOR_INDEX, now);
        }
        Some(Err(Error::NvMismatch)) => azos_drv_sys::kerr!(
            "[TPM] OTA rollback floor: NV index {:#010x} exists and is not ours (attributes, size or \
             policy differ): not used, the volume's floor holds alone", FLOOR_INDEX),
        Some(Err(e)) => azos_drv_sys::kerr!(
            "[TPM] OTA rollback floor: the NV index cannot be provisioned or read ({:?}): not used, \
             the volume's floor holds alone", e),
        None => {}
    }
}
