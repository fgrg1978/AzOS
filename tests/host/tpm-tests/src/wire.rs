// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the kernel does with the TPM, as a transcript: `kernel/src/boot/tpm.rs`
//! drives this driver in a fixed order, and these tests run that order against
//! the scripted TPM over every transport. The glue itself (finding the TPM,
//! the clock, the SPI hold) is kernel code and boots, not host-tests; what is
//! checked here is everything that crosses the wire and what the kernel does
//! with the answers.
//!
//! * the boot session: Startup, the 48-byte entropy draw (32 + 16), the three
//!   stage extends into consecutive PCRs, the floor index's provisioning;
//! * the entropy credit: the bytes of that draw seed the real pool when they
//!   are credited, and a draw that fails part way seeds nothing;
//! * a failed extend costs its stage, not the rest of the session;
//! * the OTA floor through `azos_ota::floor` (the file the kernel links):
//!   raised only upward, a stale cache never lowers the TPM, a failed raise is
//!   retried;
//! * the device-tree node `tcg,tpm_tis-spi`, which the device list cannot see.

use crate::fake::*;
use crate::*;
use azos_crypto::entropy::{Pool, SEED_BYTES};
use azos_tpm::tpm::{StartupType, FLOOR_INDEX};
use azos_tpm::Error;
use std::cell::RefCell;
use std::sync::Mutex;

#[path = "../../../../crates/core/ota/src/floor.rs"]
mod floor;

const AUTH_AREA_EMPTY: &str = "00 00 00 09 40 00 00 09 00 00 01 00 00";
const SESSION_RSP_TAIL: &str = "00 00 00 00 00 00 01 00 00";
/// The first PCR of the boot measurements (Kconfig `TPM_PCR_BASE`'s default).
const PCR_BASE: u8 = 8;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

fn seed_bytes() -> Vec<u8> {
    (0..SEED_BYTES as u8).map(|i| 0xC0 ^ i.wrapping_mul(7)).collect()
}

fn get_random_cmd(n: u8) -> String {
    format!("80 01 00 00 00 0C 00 00 01 7B 00 {n:02X}")
}

fn get_random_rsp(bytes: &[u8]) -> String {
    format!("80 01 00 00 00 {:02X} 00 00 00 00 00 {:02X} {}", 12 + bytes.len(), bytes.len(), hexs(bytes))
}

fn extend_cmd(pcr: u8, digest: &[u8; 32]) -> String {
    format!("80 02 00 00 00 41 00 00 01 82 00 00 00 {pcr:02X} {AUTH_AREA_EMPTY} 00 00 00 01 00 0B {}", hexs(digest))
}

fn extend_rsp() -> String {
    format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}")
}

/// The three digests of the boot, as the kernel derives them.
fn stage_digests() -> [[u8; 32]; 3] {
    [
        azos_crypto::sha256::sha256(b"kernel image"),
        azos_crypto::sha256::sha256(b"CONFIG.INI as accepted"),
        azos_crypto::sha256::sha256(b"azos:topology:builtin"),
    ]
}

/// A password-session command on the floor index with the kernel's 32-byte
/// password, `body` the parameters after the authorization area.
fn nv_cmd(cc: &str, tail_len: usize, body: &str) -> String {
    let auth = floor::nv_auth(FLOOR_INDEX);
    // Header 10, two handles 8, area size 4 + the area (handle 4, nonce 2,
    // attributes 1, hmac 2 + 32), then the parameters.
    let size = 10 + 8 + 4 + (4 + 2 + 1 + 2 + 32) + tail_len;
    format!(
        "80 02 00 00 00 {size:02X} 00 00 01 {cc} 01 50 00 01 01 50 00 01 00 00 00 29 40 00 00 09 00 00 01 00 20 {} {body}",
        hexs(&auth)
    )
}

fn nv_read4() -> String {
    nv_cmd("4E", 4, "00 04 00 00")
}

fn nv_write4(v: u32) -> String {
    nv_cmd("37", 2 + 4 + 2, &format!("00 04 {} 00 00", hexs(&v.to_be_bytes())))
}

fn nv_read_rsp(v: u32) -> String {
    format!("80 02 00 00 00 19 00 00 00 00 00 00 00 06 00 04 {} 00 00 01 00 00", hexs(&v.to_be_bytes()))
}

fn nv_define_floor() -> String {
    let auth = floor::nv_auth(FLOOR_INDEX);
    format!(
        "80 02 00 00 00 4D 00 00 01 2A 40 00 00 01 {AUTH_AREA_EMPTY} 00 20 {} 00 0E 01 50 00 01 00 0B 02 04 00 04 00 00 00 04",
        hexs(&auth)
    )
}

#[test]
fn nv_command_builders_agree_with_the_driver() {
    // The builders above are the transcript's only hand-made bytes: pin them to
    // the driver's own encoding with the shortest case, so a typo here cannot
    // make a floor test pass for the wrong reason.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(&nv_read4(), &nv_read_rsp(0x2A));
    assert_eq!(t.floor_read(FLOOR_INDEX, &floor::nv_auth(FLOOR_INDEX)), Ok(0x2A));
    r.dev.borrow_mut().expect(&nv_write4(0x2B), &extend_rsp());
    t.nv_write(FLOOR_INDEX, &floor::nv_auth(FLOOR_INDEX), 0, &0x2Bu32.to_be_bytes()).unwrap();
    r.dev.borrow_mut().expect(&nv_define_floor(), &extend_rsp());
    t.nv_define(&[], FLOOR_INDEX, azos_tpm::tpm::FLOOR_ATTRS, 4, &floor::nv_auth(FLOOR_INDEX)).unwrap();
    r.assert_clean();
}

#[test]
fn boot_session_entropy_pcr_extends_and_floor_in_order() {
    let seed = seed_bytes();
    let digests = stage_digests();
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        {
            let mut d = r.dev.borrow_mut();
            // An already-started TPM (firmware ran Startup): success.
            d.expect("80 01 00 00 00 0C 00 00 01 44 00 00", "80 01 00 00 00 0A 00 00 01 00");
            d.expect(&get_random_cmd(32), &get_random_rsp(&seed[..32]));
            d.expect(&get_random_cmd(16), &get_random_rsp(&seed[32..]));
            for (i, dg) in digests.iter().enumerate() {
                d.expect(&extend_cmd(PCR_BASE + i as u8, dg), &extend_rsp());
            }
            d.expect(&nv_define_floor(), &extend_rsp());
            d.expect(&nv_read4(), &nv_read_rsp(0x2A));
        }
        t.startup(StartupType::Clear).unwrap();
        let mut got = [0u8; SEED_BYTES];
        t.get_random(&mut got).unwrap();
        assert_eq!(&got[..], &seed[..], "the draw is the TPM's bytes, in order");
        for (i, dg) in digests.iter().enumerate() {
            t.pcr_extend(PCR_BASE + i as u8, dg).unwrap();
        }
        let auth = floor::nv_auth(FLOOR_INDEX);
        t.floor_provision(&[], FLOOR_INDEX, &auth).unwrap();
        assert_eq!(t.floor_read(FLOOR_INDEX, &auth), Ok(0x2A));
        // Every command ran, in the scripted order, and the locality is free.
        r.assert_clean();
    }
}

#[test]
fn entropy_draw_credits_the_pool_only_when_it_completes() {
    let seed = seed_bytes();
    // Credited: the 48 bytes are a full seed.
    let (mut t, r) = rig(Kind::Mmio, 0);
    r.dev.borrow_mut().expect(&get_random_cmd(32), &get_random_rsp(&seed[..32]));
    r.dev.borrow_mut().expect(&get_random_cmd(16), &get_random_rsp(&seed[32..]));
    let mut got = [0u8; SEED_BYTES];
    t.get_random(&mut got).unwrap();
    let mut credited = Pool::new();
    credited.mix(&got, true);
    assert!(credited.seeded(), "48 credited TPM bytes seed the pool");
    // Mix-only: stirred in, never counted.
    let mut stirred = Pool::new();
    stirred.mix(&got, false);
    assert!(!stirred.seeded());
    // A draw that fails on its second command returns an error and the kernel
    // mixes nothing (it only mixes on Ok): the pool is not half-seeded.
    let (mut t, r) = rig(Kind::Mmio, 0);
    r.dev.borrow_mut().expect(&get_random_cmd(32), &get_random_rsp(&seed[..32]));
    r.dev.borrow_mut().expect(&get_random_cmd(16), "80 01 00 00 00 0A 00 00 09 22");
    let mut part = [0u8; SEED_BYTES];
    assert_eq!(t.get_random(&mut part), Err(Error::Tpm(0x922)));
    r.assert_clean();
    let mut p = Pool::new();
    if t.get_random(&mut part).is_ok() {
        p.mix(&part, true);
    }
    assert!(!p.seeded());
}

#[test]
fn a_failed_extend_costs_its_stage_and_the_session_goes_on() {
    let digests = stage_digests();
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        {
            let mut d = r.dev.borrow_mut();
            d.expect(&extend_cmd(PCR_BASE, &digests[0]), &extend_rsp());
            // The config stage's extend is refused (locality, lockout, ...).
            d.expect(&extend_cmd(PCR_BASE + 1, &digests[1]), "80 01 00 00 00 0A 00 00 09 21");
            d.expect(&extend_cmd(PCR_BASE + 2, &digests[2]), &extend_rsp());
        }
        assert_eq!(t.pcr_extend(PCR_BASE, &digests[0]), Ok(()));
        assert_eq!(t.pcr_extend(PCR_BASE + 1, &digests[1]), Err(Error::Tpm(0x921)));
        assert_eq!(t.pcr_extend(PCR_BASE + 2, &digests[2]), Ok(()));
        r.assert_clean();
    }
}

// ── The OTA floor through the kernel's backend module ───────────────────────

thread_local! {
    static RIG: RefCell<Option<(azos_tpm::tpm::Tpm<Dyn, FakeClock>, Rig)>> = const { RefCell::new(None) };
}

/// What `kernel/src/boot/tpm.rs`'s `floor_raise` does, against this thread's
/// scripted TPM.
fn raise_on_tpm(to: u32) -> Option<u32> {
    RIG.with(|c| {
        let mut g = c.borrow_mut();
        let (t, _) = g.as_mut()?;
        t.floor_raise(FLOOR_INDEX, &floor::nv_auth(FLOOR_INDEX), to).ok()
    })
}

static BACKEND: floor::Backend = floor::Backend { raise: raise_on_tpm };
/// `floor` keeps its state in statics: one test at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn script(f: impl FnOnce(&mut Dev)) {
    RIG.with(|c| f(&mut *c.borrow().as_ref().unwrap().1.dev.borrow_mut()));
}

fn clean() {
    RIG.with(|c| c.borrow().as_ref().unwrap().1.assert_clean());
}

#[test]
fn ota_floor_is_raised_only_upward_through_the_backend() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for k in ALL {
        let (t, r) = rig(k, 0);
        RIG.with(|c| *c.borrow_mut() = Some((t, r)));
        // Installed with what the boot read: 0x2A.
        floor::install(&BACKEND, 0x2A);
        let fails0 = floor::raise_failures();
        // The read side never touches the TPM; BOOTMETA's lower or higher
        // floor is lifted to the TPM's, never lowered by it.
        assert_eq!(floor::lift(0), 0x2A);
        assert_eq!(floor::lift(0x10), 0x2A);
        assert_eq!(floor::lift(0x40), 0x40);
        // At or below the known floor: nothing on the wire (the script is
        // empty, an unexpected command would be a violation).
        floor::commit(0x2A);
        floor::commit(1);
        floor::commit(0);
        clean();
        // One above: read, then write.
        script(|d| {
            d.expect(&nv_read4(), &nv_read_rsp(0x2A));
            d.expect(&nv_write4(0x2B), &extend_rsp());
        });
        floor::commit(0x2B);
        clean();
        assert_eq!(floor::lift(0), 0x2B);
        // The same again: known, so silent.
        floor::commit(0x2B);
        clean();
        // The cache is stale (something else raised the index to 0x30): the
        // driver reads first, finds the higher value, writes nothing, and the
        // cache catches up. The index is never lowered.
        script(|d| d.expect(&nv_read4(), &nv_read_rsp(0x30)));
        floor::commit(0x2C);
        clean();
        assert_eq!(floor::lift(0), 0x30);
        assert_eq!(floor::raise_failures(), fails0);
    }
}

#[test]
fn ota_floor_failed_raise_is_counted_and_retried_while_the_volume_holds() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (t, r) = rig(Kind::Spi(3), 0);
    RIG.with(|c| *c.borrow_mut() = Some((t, r)));
    floor::install(&BACKEND, 0x05);
    let fails0 = floor::raise_failures();
    // The TPM refuses the read (lockout): the raise fails, the known floor is
    // unchanged, the failure is counted.
    script(|d| d.expect(&nv_read4(), "80 01 00 00 00 0A 00 00 09 21"));
    floor::commit(0x06);
    clean();
    assert_eq!(floor::raise_failures(), fails0 + 1);
    assert_eq!(floor::lift(0), 0x05);
    // BOOTMETA's own 0x06 is what holds meanwhile (lift takes the higher).
    assert_eq!(floor::lift(0x06), 0x06);
    // The next confirmation retries and succeeds.
    script(|d| {
        d.expect(&nv_read4(), &nv_read_rsp(0x05));
        d.expect(&nv_write4(0x06), &extend_rsp());
    });
    floor::commit(0x06);
    clean();
    assert_eq!(floor::lift(0), 0x06);
    assert_eq!(floor::raise_failures(), fails0 + 1);
}

// ── The device-tree node ────────────────────────────────────────────────────

/// A flattened device tree, built the way `dtc` lays it out.
struct Fdt {
    st: Vec<u8>,
    strings: Vec<u8>,
}

impl Fdt {
    fn new() -> Fdt {
        Fdt { st: Vec::new(), strings: Vec::new() }
    }
    fn pad(&mut self) {
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
    }
    fn begin(&mut self, name: &str) -> &mut Self {
        self.st.extend(1u32.to_be_bytes());
        self.st.extend(name.as_bytes());
        self.st.push(0);
        self.pad();
        self
    }
    fn end(&mut self) -> &mut Self {
        self.st.extend(2u32.to_be_bytes());
        self
    }
    fn prop(&mut self, name: &str, val: &[u8]) -> &mut Self {
        let off = self.strings.len() as u32;
        self.strings.extend(name.as_bytes());
        self.strings.push(0);
        self.st.extend(3u32.to_be_bytes());
        self.st.extend((val.len() as u32).to_be_bytes());
        self.st.extend(off.to_be_bytes());
        self.st.extend(val);
        self.pad();
        self
    }
    fn cells(&mut self, name: &str, v: &[u32]) -> &mut Self {
        let b: Vec<u8> = v.iter().flat_map(|x| x.to_be_bytes()).collect();
        self.prop(name, &b)
    }
    fn finish(mut self) -> Vec<u8> {
        self.st.extend(9u32.to_be_bytes());
        let (off_struct, rsv) = (40u32 + 16, 40u32);
        let off_strings = off_struct + self.st.len() as u32;
        let total = off_strings + self.strings.len() as u32;
        let mut b = Vec::new();
        for w in [0xd00d_feed, total, off_struct, off_strings, rsv, 17, 16, 0, self.strings.len() as u32, self.st.len() as u32] {
            b.extend(w.to_be_bytes());
        }
        b.extend([0u8; 16]);
        b.extend(&self.st);
        b.extend(&self.strings);
        b
    }
}

fn tpm_node(f: &mut Fdt, name: &str, status: Option<&str>, cs: Option<u32>, hz: Option<u32>) {
    f.begin(name);
    f.prop("compatible", b"infineon,slb9670\0tcg,tpm_tis-spi\0");
    if let Some(c) = cs {
        f.cells("reg", &[c]);
    }
    if let Some(h) = hz {
        f.cells("spi-max-frequency", &[h]);
    }
    if let Some(s) = status {
        f.prop("status", format!("{s}\0").as_bytes());
    }
    f.end();
}

/// `/ { soc { spi@10060000 { <children> } } }`, the SPI controller's window
/// translated through the soc's `ranges`, its children addressed by chip select.
fn tree(spi_status: Option<&str>, children: impl FnOnce(&mut Fdt)) -> Vec<u8> {
    let mut f = Fdt::new();
    f.begin("");
    f.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    f.begin("soc");
    f.cells("#address-cells", &[1]).cells("#size-cells", &[1]).prop("ranges", &[]);
    f.begin("spi@10060000");
    f.cells("reg", &[0x1006_0000, 0x1000]);
    f.cells("#address-cells", &[1]).cells("#size-cells", &[0]);
    f.prop("compatible", b"arm,pl022\0");
    if let Some(s) = spi_status {
        f.prop("status", format!("{s}\0").as_bytes());
    }
    children(&mut f);
    f.end().end().end();
    f.finish()
}

fn find(blob: &[u8]) -> Option<azos_dtb::DtSpiSlave> {
    // SAFETY: `blob` is a complete tree this test built.
    unsafe { azos_dtb::dtb_spi_slave(blob.as_ptr(), b"tcg,tpm_tis-spi") }
}

#[test]
fn device_tree_tpm_node_gives_the_chip_select_and_the_clock() {
    let blob = tree(None, |f| tpm_node(f, "tpm@1", None, Some(1), Some(10_000_000)));
    assert_eq!(find(&blob), Some(azos_dtb::DtSpiSlave { cs: 1, max_hz: 10_000_000 }));
    // No clock in the node: 0, the caller keeps the controller's.
    let blob = tree(None, |f| tpm_node(f, "tpm@0", Some("okay"), Some(0), None));
    assert_eq!(find(&blob), Some(azos_dtb::DtSpiSlave { cs: 0, max_hz: 0 }));
    // The device list skips the node (a chip select is not a window), which is
    // why the kernel walks for it.
    let mut listed = 0;
    // SAFETY: as above.
    unsafe { azos_dtb::dtb_devices(blob.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
        assert!(!d.name.starts_with(b"tpm"), "a SPI slave must not be a bus device");
        listed += 1;
    }) };
    assert!(listed >= 1, "the controller itself is listed");
}

#[test]
fn device_tree_tpm_node_refusals() {
    // Disabled node; disabled controller; no chip select; another part.
    assert_eq!(find(&tree(None, |f| tpm_node(f, "tpm@1", Some("disabled"), Some(1), None))), None);
    assert_eq!(find(&tree(Some("disabled"), |f| tpm_node(f, "tpm@1", None, Some(1), None))), None);
    assert_eq!(find(&tree(None, |f| tpm_node(f, "tpm", None, None, None))), None);
    let other = tree(None, |f| {
        f.begin("flash@0");
        f.prop("compatible", b"jedec,spi-nor\0").cells("reg", &[0]);
        f.end();
    });
    assert_eq!(find(&other), None);
    // The first enabled match wins when an earlier one is disabled.
    let two = tree(None, |f| {
        tpm_node(f, "tpm@0", Some("disabled"), Some(0), None);
        tpm_node(f, "tpm@2", None, Some(2), Some(1_000_000));
    });
    assert_eq!(find(&two), Some(azos_dtb::DtSpiSlave { cs: 2, max_hz: 1_000_000 }));
    // A truncated or foreign blob is None, not a read past the end.
    let good = tree(None, |f| tpm_node(f, "tpm@1", None, Some(1), None));
    let mut cut = good.clone();
    let total = cut.len() as u32 - 8;
    cut[4..8].copy_from_slice(&total.to_be_bytes());
    cut.truncate(total as usize);
    assert_eq!(find(&cut), None);
    assert_eq!(find(&[0u8; 64]), None);
}
