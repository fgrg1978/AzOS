// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TOPO-ROWS-C (CAPS.TOML format 8): the rows and fields the later fronts
//! consume, parsed, verified, emitted and signed before any of them exists:
//! `tsn`, `fieldbus`, `audio`, `display`, `user`, `key`, `mission`,
//! `boot_chain`, `island`, `activity`, `numa`, `envelope`, `rtc`, `nic`,
//! `model` and `usb` rows, the task keys `security_boundary` and
//! `partition_id`, and the guest keys `passthrough`, `static`, `pcpus` and
//! `mem_base`. (`verity_root` is the existing `[volume.NAME]` key.)
//!
//! Each row has a valid case, the malformed cases it must refuse, the
//! format-7 refusal, a duplicate where the row has a name, and the
//! parse -> emit -> parse round trip (`first_difference`), so an emitter or
//! comparison that forgets a field turns a test red. The last test signs a
//! topology that declares one of everything, flips one byte in each row and
//! expects the loader to refuse it.

use azos_topology::emit::{emit_caps, emit_sched, first_difference, EMIT_FORMAT};
use azos_topology::signed::{load_signed, DeviceContext, SignedFile, SignedFiles, SignedRefusal};
use azos_topology::{
    parse_caps, AdmissionError, Binding, EffectKind, Envelope, FieldbusKind, KeySource, ParseError, RowKind, Topology,
    UsbAuthorize, VerifyError,
};
use ed25519_dalek::Signer;

use crate::topo_rows::{dsig, key, leak, parse_with, round_trip, DEV, SCHED};

const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn parse8(body: &str) -> (Box<Topology<'static>>, Result<(), ParseError>) {
    let caps: &'static str = leak(format!("format = 8\n{body}"));
    parse_with(SCHED, caps)
}

/// Parse a format-8 body that must be accepted and survive the round trip.
fn ok(body: &str) -> Box<Topology<'static>> {
    let (t, r) = parse8(body);
    assert_eq!(r, Ok(()), "{body}");
    assert_eq!(round_trip(&t), None, "{body}");
    t
}

fn refused(body: &str) -> ParseError {
    let (_, r) = parse8(body);
    r.expect_err(body)
}

fn bad(kind: RowKind) -> ParseError {
    ParseError::Admission(AdmissionError::BadRow(kind))
}

fn dup(kind: RowKind) -> ParseError {
    ParseError::Admission(AdmissionError::DuplicateRow(kind))
}

/// Every case in `cases` is refused with the error beside it.
fn all_refused(cases: &[(String, ParseError)]) {
    for (body, want) in cases {
        assert_eq!(&refused(body), want, "{body}");
    }
}

/// `body` in a file that says `format = 7` is refused, not read.
fn needs_8(body: &str) {
    let caps: &'static str = leak(format!("format = 7\n{body}"));
    let (_, r) = parse_with(SCHED, caps);
    assert_eq!(r, Err(ParseError::FieldNeedsFormat), "{body}");
}

const TSN: &str = "[tsn.uplink]\ndev = \"eth0\"\nwindow_us = 1000\nlink_budget = 100000\n";
const FIELDBUS: &str = "[fieldbus.ec0]\nkind = \"ethercat\"\ndev = \"eth1\"\ncycle_us = 1000\n\
[fieldbus.mb0]\nkind = \"modbus\"\ndev = \"uart1\"\n";
const AUDIO: &str = "[audio.out]\ndev = \"codec0\"\nrate_hz = 48000\nchannels = 2\ndir = \"duplex\"\n";
const DISPLAY: &str = "[display.panel]\ndev = \"fb0\"\nwidth = 1280\nheight = 720\nrotation = 90\nprimary = true\n";
const USER: &str = "[user.owner]\nroot = \"/home/owner\"\nkeystore = \"/keys/owner\"\n";
const KEY: &str = "[key.link]\npurpose = \"link\"\nsource = \"dice\"\n\
[key.vol]\npurpose = \"aead\"\nsource = \"keystore\"\nuser = \"owner\"\n";
const MISSION: &str = "[mission]\nreserve_mj = 250000\ntask = \"RETURN.ELF\"\n";
const BOOT: &str = "[boot_chain.spl]\nstage = 0\ndigest = \"1111111111111111111111111111111111111111111111111111111111111111\"\n\
[boot_chain.kernel]\nstage = 1\ndigest = \"2222222222222222222222222222222222222222222222222222222222222222\"\n";
const ISLAND: &str = "[island.lp]\nimage = \"LP.BIN\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n\
mailbox = \"lp-mbox\"\nwake = [\"button\", \"ble-rx\"]\n";
const ACTIVITY: &str = "[activity.sync]\ntask = \"SYNC.ELF\"\ntrigger = \"timer\"\nperiod_ms = 60000\n\
[activity.index]\ntask = \"INDEX.ELF\"\ntrigger = \"idle\"\n";
const NUMA: &str = "[numa.n0]\nnode = 0\ncpus = 3\n[numa.n1]\nnode = 1\ncpus = 12\n";
const ENVELOPE: &str = "[envelope.ota-slow]\nkind = \"ota\"\nclass = \"best_effort\"\nlevel = \"slow\"\n\
[envelope.egress-off]\nkind = \"egress\"\nclass = \"best_effort\"\nlevel = \"contained\"\n";
const RTC: &str = "[rtc]\ndev = \"rtc0\"\nutc = false\n";
const NIC: &str = "[nic.lan]\ndev = \"eth0\"\nmtu = 9000\nmac = \"02:00:5e:10:00:01\"\n[nic.wan]\ndev = \"eth1\"\n";
const MODEL: &str = "[model.vision]\nbundle = \"2222222222222222222222222222222222222222222222222222222222222222\"\nvariant = \"int8\"\n";
const USB: &str = "[usb.hub]\nvid = \"1d6b\"\npid = \"0002\"\nauthorize = \"allow\"\n\
[usb.storage]\nclass = 8\nauthorize = \"deny\"\n\
[usb.rest]\nauthorize = \"allow\"\n";

/// Every row kind this file adds, once, with a task row for the rows that
/// name one.
fn everything() -> String {
    format!(
        "[task.RETURN.ELF]\ncaps = []\n[task.SYNC.ELF]\ncaps = []\n[task.INDEX.ELF]\nsecurity_boundary = true\npartition_id = 7\ncaps = []\n\
{TSN}{FIELDBUS}{AUDIO}{DISPLAY}{USER}{KEY}{MISSION}{BOOT}{ISLAND}{ACTIVITY}{NUMA}{ENVELOPE}{RTC}{NIC}{MODEL}{USB}\
[guest.ais]\ncpus = 2\nmem_mib = 64\nenvelope = \"slow\"\ndevices = [\"virtio-net\"]\npassthrough = [\"uart2\", \"nvme0\"]\n\
static = true\npcpus = 12\nmem_base = 2147483648\n"
    )
}

#[test]
fn the_rows_declare_what_their_consumers_read() {
    let t = ok(&format!("{TSN}{FIELDBUS}{AUDIO}{DISPLAY}{USER}{KEY}{RTC}{NIC}{MODEL}{USB}"));
    let r = &t.tsns()[0];
    assert_eq!((r.dev.as_bytes(), r.window_us, r.link_budget), (&b"eth0"[..], 1000, 100_000));
    assert_eq!(t.tsn_for(b"eth0").map(|r| r.name.as_bytes()), Some(&b"uplink"[..]));
    assert!(t.tsn_for(b"eth1").is_none());
    assert_eq!((t.fieldbuses()[0].kind, t.fieldbuses()[0].cycle_us), (FieldbusKind::EtherCat, 1000));
    assert_eq!((t.fieldbuses()[1].kind, t.fieldbuses()[1].cycle_us), (FieldbusKind::Modbus, 0));
    let a = &t.audios()[0];
    assert_eq!((a.rate_hz, a.channels, a.dir.as_str()), (48_000, 2, "duplex"));
    let d = &t.displays()[0];
    assert_eq!((d.width, d.height, d.rotation, d.primary), (1280, 720, 90, true));
    assert_eq!(t.users()[0].root.as_bytes(), b"/home/owner");
    assert_eq!(t.users()[0].keystore.as_bytes(), b"/keys/owner");
    assert_eq!(t.keys()[1].source, KeySource::Keystore);
    assert_eq!(t.keys()[1].user.map(|u| u.as_bytes()), Some(&b"owner"[..]));
    assert_eq!(t.keys()[0].user, None);
    let rtc = t.rtc().expect("rtc");
    assert_eq!((rtc.dev.as_bytes(), rtc.utc), (&b"rtc0"[..], false));
    assert_eq!((t.nics()[0].mtu, t.nics()[0].mac), (9000, Some([2, 0, 0x5e, 0x10, 0, 1])));
    assert_eq!((t.nics()[1].mtu, t.nics()[1].mac), (1500, None));
    assert_eq!(t.models()[0].bundle, [0x22; 32]);
    assert_eq!(t.models()[0].variant.as_bytes(), b"int8");

    let t = ok(&format!("{BOOT}{ISLAND}{NUMA}"));
    assert_eq!(t.boot_chain().iter().map(|s| s.stage).collect::<Vec<_>>(), [0, 1]);
    let i = &t.islands()[0];
    assert_eq!((i.image.as_bytes(), i.mailbox.as_bytes(), i.sha256), (&b"LP.BIN"[..], &b"lp-mbox"[..], [0x11; 32]));
    assert_eq!(i.wake().iter().map(|w| w.as_bytes()).collect::<Vec<_>>(), [&b"button"[..], b"ble-rx"]);
    assert_eq!(t.numa_nodes().iter().map(|n| (n.node, n.cpus)).collect::<Vec<_>>(), [(0, 3), (1, 12)]);

    let t = ok(&format!("[task.RETURN.ELF]\ncaps = []\n[task.SYNC.ELF]\ncaps = []\n[task.INDEX.ELF]\ncaps = []\n{MISSION}{ACTIVITY}{ENVELOPE}"));
    let m = t.mission().expect("mission");
    assert_eq!((m.reserve_mj, m.task.map(|t| t.as_bytes())), (250_000, Some(&b"RETURN.ELF"[..])));
    assert_eq!(t.activity_of(b"SYNC.ELF").map(|a| a.period_ms), Some(60_000));
    assert_eq!(t.activity_of(b"INDEX.ELF").map(|a| a.period_ms), Some(0));
    assert_eq!(t.effect_ceiling(b"best_effort", EffectKind::Ota), Envelope::Slow);
    assert_eq!(t.effect_ceiling(b"best_effort", EffectKind::Egress), Envelope::Contained);
    assert_eq!(t.effect_ceiling(b"best_effort", EffectKind::Delete), Envelope::Full, "no row, no ceiling");
    assert_eq!(t.admission_check(), Ok(()));
}

#[test]
fn everything_together_is_admitted_and_round_trips() {
    let t = ok(&everything());
    assert_eq!(t.admission_check(), Ok(()));
    let ais = &t.guests()[0];
    assert!(ais.static_partition);
    assert_eq!((ais.pcpus, ais.mem_base), (12, 2 << 30));
    assert_eq!(ais.passthrough().iter().map(|d| d.as_bytes()).collect::<Vec<_>>(), [&b"uart2"[..], b"nvme0"]);
    let idx = t.tasks().iter().find(|t| t.name.as_bytes() == b"INDEX.ELF").unwrap();
    assert_eq!((idx.security_boundary, idx.partition_id), (true, 7));
    let ret = t.tasks().iter().find(|t| t.name.as_bytes() == b"RETURN.ELF").unwrap();
    assert_eq!((ret.security_boundary, ret.partition_id), (false, 0));
}

#[test]
fn the_rows_are_format_8() {
    for body in [TSN, FIELDBUS, AUDIO, DISPLAY, USER, KEY, MISSION, BOOT, ISLAND, ACTIVITY, NUMA, ENVELOPE, RTC, NIC, MODEL, USB] {
        needs_8(body);
    }
    needs_8("[task.A.ELF]\nsecurity_boundary = true\ncaps = []\n");
    needs_8("[task.A.ELF]\npartition_id = 3\ncaps = []\n");
    for key in ["passthrough = [\"a\"]", "static = true", "pcpus = 1", "mem_base = 4096"] {
        needs_8(&format!("[guest.g]\ncpus = 1\nmem_mib = 1\nenvelope = \"full\"\n{key}\n"));
    }
    // The emitter writes what the parser reads.
    assert_eq!(EMIT_FORMAT, 8);
}

#[test]
fn a_malformed_tsn_row_is_refused() {
    let edit = |a: &str, b: &str| TSN.replace(a, b);
    all_refused(&[
        (edit("dev = \"eth0\"\n", ""), ParseError::MissingField),
        (edit("window_us = 1000\n", ""), ParseError::MissingField),
        (edit("link_budget = 100000\n", ""), ParseError::MissingField),
        (edit("window_us = 1000", "window_us = 0"), bad(RowKind::Tsn)),
        (edit("window_us = 1000", "window_us = 1000001"), bad(RowKind::Tsn)),
        (edit("window_us = 1000", "window_us = 4294967296"), ParseError::BadValue),
        (edit("link_budget = 100000", "link_budget = 0"), bad(RowKind::Tsn)),
        (edit("link_budget = 100000", "link_budget = 10000001"), bad(RowKind::Tsn)),
        (edit("\"eth0\"", "\".eth0\""), bad(RowKind::Tsn)),
        (edit("\"eth0\"", "\"eth 0\""), bad(RowKind::Tsn)),
        (format!("{TSN}rate = 1\n"), ParseError::UnknownField),
        (format!("{TSN}window_us = 2000\n"), ParseError::BadValue),
        (format!("{TSN}{TSN}"), dup(RowKind::Tsn)),
        (format!("{TSN}{}", edit("uplink", "other")), dup(RowKind::Tsn)),
    ]);
}

#[test]
fn a_malformed_fieldbus_row_is_refused() {
    let ec = "[fieldbus.ec0]\nkind = \"ethercat\"\ndev = \"eth1\"\ncycle_us = 1000\n";
    let mb = "[fieldbus.mb0]\nkind = \"modbus\"\ndev = \"uart1\"\n";
    all_refused(&[
        (ec.replace("kind = \"ethercat\"\n", ""), ParseError::MissingField),
        (ec.replace("dev = \"eth1\"\n", ""), ParseError::MissingField),
        (ec.replace("ethercat", "profibus"), ParseError::UnknownEnumValue),
        // EtherCAT is cyclic: no cycle, no master. The others have none.
        (ec.replace("cycle_us = 1000\n", ""), bad(RowKind::Fieldbus)),
        (format!("{mb}cycle_us = 1000\n"), bad(RowKind::Fieldbus)),
        (format!("{ec}{}", ec.replace("ec0", "ec1")), dup(RowKind::Fieldbus)),
        (format!("{ec}{}", mb.replace("uart1", "eth1")), dup(RowKind::Fieldbus)),
    ]);
}

#[test]
fn a_malformed_audio_or_display_row_is_refused() {
    let au = |a: &str, b: &str| AUDIO.replace(a, b);
    let di = |a: &str, b: &str| DISPLAY.replace(a, b);
    all_refused(&[
        (au("rate_hz = 48000", "rate_hz = 7999"), bad(RowKind::Audio)),
        (au("rate_hz = 48000", "rate_hz = 384001"), bad(RowKind::Audio)),
        (au("channels = 2", "channels = 0"), bad(RowKind::Audio)),
        (au("channels = 2", "channels = 33"), bad(RowKind::Audio)),
        (au("channels = 2", "channels = 256"), ParseError::BadValue),
        (au("duplex", "loopback"), ParseError::UnknownEnumValue),
        (au("rate_hz = 48000\n", ""), ParseError::MissingField),
        (format!("{AUDIO}{AUDIO}"), dup(RowKind::Audio)),
        (di("width = 1280", "width = 0"), bad(RowKind::Display)),
        (di("height = 720", "height = 0"), bad(RowKind::Display)),
        (di("rotation = 90", "rotation = 45"), bad(RowKind::Display)),
        (di("rotation = 90", "rotation = 360"), bad(RowKind::Display)),
        (di("primary = true", "primary = 1"), ParseError::BadValue),
        (di("height = 720\n", ""), ParseError::MissingField),
        (format!("{DISPLAY}{}", di("panel", "second").replace("\"fb0\"", "\"fb1\"")), dup(RowKind::Display)),
        (format!("{DISPLAY}{}", di("panel", "panel2")), dup(RowKind::Display)),
    ]);
    // Rotation 0 is the default and is not written.
    let t = ok(&format!("{}{}", DISPLAY.replace("rotation = 90\n", ""), "[audio.a]\ndev = \"c\"\nrate_hz = 8000\nchannels = 1\n"));
    assert_eq!(t.displays()[0].rotation, 0);
    assert_eq!(t.audios()[0].dir.as_str(), "playback");
    // A second display is fine as long as only one is primary.
    let second = DISPLAY.replace("panel", "aux").replace("\"fb0\"", "\"fb1\"").replace("primary = true", "primary = false");
    assert_eq!(ok(&format!("{DISPLAY}{second}")).displays().len(), 2);
}

#[test]
fn a_malformed_user_or_key_row_is_refused() {
    let us = |a: &str, b: &str| USER.replace(a, b);
    all_refused(&[
        (us("root = \"/home/owner\"\n", ""), ParseError::MissingField),
        (us("keystore = \"/keys/owner\"\n", ""), ParseError::MissingField),
        (us("\"/home/owner\"", "\"home/owner\""), bad(RowKind::User)),
        (us("\"/home/owner\"", "\"/\""), bad(RowKind::User)),
        (us("\"/home/owner\"", "\"/home/../owner\""), bad(RowKind::User)),
        (us("\"/home/owner\"", "\"/fat/owner\""), bad(RowKind::User)),
        (us("\"/keys/owner\"", "\"/home/owner\""), bad(RowKind::User)),
        (us("\"/keys/owner\"", "\"/fat\""), bad(RowKind::User)),
        (format!("{USER}{USER}"), dup(RowKind::User)),
        (format!("{USER}{}", us("owner]", "other]").replace("/keys/owner", "/keys/o2")), dup(RowKind::User)),
    ]);
    // Per-user isolation: no root or keystore equals, lies inside or contains
    // another one, whichever row comes first.
    let two = |r2: &str, k2: &str| format!("{USER}[user.other]\nroot = \"{r2}\"\nkeystore = \"{k2}\"\n");
    all_refused(&[
        // A root inside another user's root, and one that contains it.
        (two("/home/owner/sub", "/keys/o2"), bad(RowKind::User)),
        (two("/home", "/keys/o2"), bad(RowKind::User)),
        // A root that contains, or sits inside, another user's keystore.
        (two("/keys", "/k/o2"), bad(RowKind::User)),
        (two("/keys/owner/x", "/k/o2"), bad(RowKind::User)),
        // A keystore inside another user's root, or inside/around/equal to its keystore.
        (two("/home/o2", "/home/owner/keys"), bad(RowKind::User)),
        (two("/home/o2", "/home"), bad(RowKind::User)),
        (two("/home/o2", "/keys/owner"), bad(RowKind::User)),
        (two("/home/o2", "/keys/owner/o2"), bad(RowKind::User)),
        (two("/home/o2", "/keys"), bad(RowKind::User)),
        // A keystore inside, or around, the user's own root.
        (USER.replace("/keys/owner", "/home/owner/keys"), bad(RowKind::User)),
        (USER.replace("/keys/owner", "/home"), bad(RowKind::User)),
    ]);
    // Component-wise: a shared string prefix is not nesting.
    let (t, r) = parse8(&two("/home/owner2", "/keys/owner2"));
    assert_eq!(r, Ok(()));
    assert_eq!(t.users().len(), 2);
    let ky = |a: &str, b: &str| KEY.replace(a, b);
    all_refused(&[
        (ky("purpose = \"link\"\n", ""), ParseError::MissingField),
        (ky("source = \"dice\"\n", ""), ParseError::MissingField),
        (ky("\"link\"", "\"pgp\""), ParseError::UnknownEnumValue),
        (ky("\"dice\"", "\"cloud\""), ParseError::UnknownEnumValue),
        // A keystore key belongs to a user; the other sources have none.
        (ky("\nuser = \"owner\"", ""), bad(RowKind::Key)),
        (ky("source = \"dice\"\n", "source = \"dice\"\nuser = \"owner\"\n"), bad(RowKind::Key)),
        (ky("\"owner\"", "\"ow ner\""), bad(RowKind::Key)),
        (format!("{KEY}{KEY}"), dup(RowKind::Key)),
    ]);
    // The user's row must exist.
    let (t, r) = parse8(&ky("\"owner\"", "\"ghost\""));
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::Key)));
    let (t, _) = parse8(&format!("{USER}{KEY}"));
    assert_eq!(t.admission_check(), Ok(()));
}

#[test]
fn a_malformed_mission_rtc_nic_or_model_row_is_refused() {
    all_refused(&[
        ("[mission]\nreserve_mj = 0\n".to_string(), bad(RowKind::Mission)),
        ("[mission]\ntask = \"A.ELF\"\n".to_string(), ParseError::MissingField),
        ("[mission]\nreserve_mj = 4294967296\n".to_string(), ParseError::BadValue),
        (format!("{MISSION}{MISSION}"), dup(RowKind::Mission)),
        ("[rtc]\nutc = true\n".to_string(), ParseError::MissingField),
        ("[rtc]\ndev = \"\"\n".to_string(), bad(RowKind::Rtc)),
        (format!("{RTC}{RTC}"), dup(RowKind::Rtc)),
        ("[rtc]\ndev = \"r\"\nutc = 1\n".to_string(), ParseError::BadValue),
    ]);
    let nc = |a: &str, b: &str| NIC.replace(a, b);
    all_refused(&[
        (nc("mtu = 9000", "mtu = 575"), bad(RowKind::Nic)),
        (nc("mtu = 9000", "mtu = 9217"), bad(RowKind::Nic)),
        (nc("mtu = 9000", "mtu = 65536"), ParseError::BadValue),
        // Multicast, all-zero, short, long, wrong separator, not hex.
        (nc("02:00:5e:10:00:01", "01:00:5e:10:00:01"), bad(RowKind::Nic)),
        (nc("02:00:5e:10:00:01", "00:00:00:00:00:00"), bad(RowKind::Nic)),
        (nc("02:00:5e:10:00:01", "02:00:5e:10:00"), ParseError::BadValue),
        (nc("02:00:5e:10:00:01", "02:00:5e:10:00:01:02"), ParseError::NameTooLong),
        (nc("02:00:5e:10:00:01", "02-00-5e-10-00-01"), ParseError::BadValue),
        (nc("02:00:5e:10:00:01", "02:00:5e:10:00:0g"), ParseError::BadValue),
        (nc("dev = \"eth1\"", "dev = \"eth0\""), dup(RowKind::Nic)),
        (format!("{NIC}{}", nc("lan", "lan2").replace("eth0", "eth2")), dup(RowKind::Nic)),
        ("[nic.a]\nmtu = 1500\n".to_string(), ParseError::MissingField),
    ]);
    let md = |a: &str, b: &str| MODEL.replace(a, b);
    all_refused(&[
        (md(H2, ZERO), bad(RowKind::Model)),
        (md(H2, &H2[1..]), ParseError::BadValue),
        (md("\"int8\"", "\"in t8\""), bad(RowKind::Model)),
        (format!("{MODEL}{}", md("vision", "again")), dup(RowKind::Model)),
        ("[model.m]\nvariant = \"x\"\n".to_string(), ParseError::MissingField),
    ]);
    // A model without a variant has none.
    let t = ok(&MODEL.replace("variant = \"int8\"\n", ""));
    assert!(t.models()[0].variant.is_empty());
    // The mission's task must exist.
    let (t, _) = parse8(MISSION);
    assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::Mission)));
    assert_eq!(ok("[mission]\nreserve_mj = 1\n").admission_check(), Ok(()));
}

#[test]
fn a_malformed_boot_chain_island_or_activity_row_is_refused() {
    let bc = |a: &str, b: &str| BOOT.replace(a, b);
    all_refused(&[
        (bc(H1, ZERO), bad(RowKind::BootChain)),
        (bc("stage = 1", "stage = 256"), ParseError::BadValue),
        (bc("stage = 1", "stage = 0"), dup(RowKind::BootChain)),
        (bc("kernel", "spl"), dup(RowKind::BootChain)),
        (bc("stage = 0\n", ""), ParseError::MissingField),
        (bc(&format!("digest = \"{H2}\""), ""), ParseError::MissingField),
    ]);
    // The stages are consecutive from 0.
    for gap in [bc("stage = 0", "stage = 3"), bc("stage = 1", "stage = 2")] {
        let (t, r) = parse8(&gap);
        assert_eq!(r, Ok(()));
        assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::BootChain)), "{gap}");
    }
    let is = |a: &str, b: &str| ISLAND.replace(a, b);
    let wake9: Vec<String> = (0..azos_topology::ISLAND_WAKE + 1).map(|i| format!("\"e{i}\"")).collect();
    all_refused(&[
        (is(H1, ZERO), bad(RowKind::Island)),
        (is("\"LP.BIN\"", "\".LP\""), bad(RowKind::Island)),
        (is("\"lp-mbox\"", "\"lp.mbox\""), bad(RowKind::Island)),
        (is("\"ble-rx\"", "\"button\""), bad(RowKind::Island)),
        (is("\"ble-rx\"", "\"ble rx\""), bad(RowKind::Island)),
        (is("image = \"LP.BIN\"\n", ""), ParseError::MissingField),
        (is("mailbox = \"lp-mbox\"\n", ""), ParseError::MissingField),
        (is("wake = [\"button\", \"ble-rx\"]", &format!("wake = [{}]", wake9.join(", "))), bad(RowKind::Island)),
        (format!("{ISLAND}{}", is("lp]", "lp2]")), dup(RowKind::Island)),
        (format!("{ISLAND}{}", is("lp]", "lp2]").replace("LP.BIN", "LP2.BIN")), dup(RowKind::Island)),
    ]);
    // No wake list: the island never wakes the kernel.
    let t = ok(&ISLAND.replace("wake = [\"button\", \"ble-rx\"]\n", ""));
    assert!(t.islands()[0].wake().is_empty());
    let ac = |a: &str, b: &str| ACTIVITY.replace(a, b);
    all_refused(&[
        (ac("period_ms = 60000\n", ""), bad(RowKind::Activity)),
        (ac("\"idle\"", "\"idle\"\nperiod_ms = 5"), bad(RowKind::Activity)),
        (ac("period_ms = 60000", "period_ms = 0"), bad(RowKind::Activity)),
        (ac("\"timer\"", "\"later\""), ParseError::UnknownEnumValue),
        (ac("task = \"SYNC.ELF\"\n", ""), ParseError::MissingField),
        (format!("{ACTIVITY}{}", ac("sync", "sync2")), dup(RowKind::Activity)),
        (format!("{ACTIVITY}{}", ac("sync]", "again]")), dup(RowKind::Activity)),
    ]);
    // The task must exist.
    let (t, r) = parse8(ACTIVITY);
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::Activity)));
}

#[test]
fn a_malformed_numa_envelope_or_usb_row_is_refused() {
    let nu = |a: &str, b: &str| NUMA.replace(a, b);
    all_refused(&[
        (nu("node = 1", "node = 64"), bad(RowKind::Numa)),
        (nu("cpus = 12", "cpus = 0"), bad(RowKind::Numa)),
        (nu("node = 1", "node = 0"), dup(RowKind::Numa)),
        // Node 1 may not claim CPU 1, which node 0 has.
        (nu("cpus = 12", "cpus = 6"), dup(RowKind::Numa)),
        (nu("n1", "n0"), dup(RowKind::Numa)),
        (nu("node = 0\n", ""), ParseError::MissingField),
        (nu("cpus = 3", "cpus = 18446744073709551616"), ParseError::BadValue),
    ]);
    let hi = ok("[numa.big]\nnode = 63\ncpus = 18446744073709551615\n");
    assert_eq!(hi.numa_nodes()[0].cpus, u64::MAX);
    let en = |a: &str, b: &str| ENVELOPE.replace(a, b);
    all_refused(&[
        (en("\"ota\"", "\"motor\""), ParseError::UnknownEnumValue),
        (en("\"slow\"", "\"off\""), ParseError::UnknownEnumValue),
        (en("level = \"slow\"\n", ""), ParseError::MissingField),
        (en("class = \"best_effort\"\n", ""), ParseError::MissingField),
        // One row per class and kind.
        (en("\"egress\"", "\"ota\""), dup(RowKind::Envelope)),
        (en("egress-off", "ota-slow"), dup(RowKind::Envelope)),
        (en("ota-slow", "ota slow"), bad(RowKind::Envelope)),
    ]);
    for k in ["config", "ota", "egress", "delete", "rt_time", "mic"] {
        let t = ok(&format!("[envelope.e]\nkind = \"{k}\"\nclass = \"best_effort\"\nlevel = \"cautious\"\n"));
        assert_eq!(t.envelopes()[0].kind.as_str(), k);
    }
    // The class must exist.
    let (t, r) = parse8(&en("best_effort", "ghosts"));
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::Envelope)));
    let us = |a: &str, b: &str| USB.replace(a, b);
    all_refused(&[
        (us("authorize = \"allow\"\n[usb.storage]", "[usb.storage]"), ParseError::MissingField),
        (us("\"1d6b\"", "\"1d6\""), ParseError::BadValue),
        (us("\"1d6b\"", "\"1d6g\""), ParseError::BadValue),
        (us("class = 8", "class = 256"), ParseError::BadValue),
        (us("\"deny\"", "\"ask\""), ParseError::UnknownEnumValue),
        (us("vid = \"1d6b\"\n", ""), bad(RowKind::Usb)),
        // A catch-all ends the list; a selector twice is unreachable.
        (format!("{USB}[usb.late]\nvid = \"0001\"\nauthorize = \"deny\"\n"), dup(RowKind::Usb)),
        (format!("{USB}[usb.rest2]\nauthorize = \"deny\"\n"), dup(RowKind::Usb)),
        (format!("{}[usb.hub2]\nvid = \"1d6b\"\npid = \"0002\"\nauthorize = \"deny\"\n", &USB[..USB.find("[usb.rest]").unwrap()]), dup(RowKind::Usb)),
        (format!("{USB}{}", us("hub", "hub")), dup(RowKind::Usb)),
    ]);
}

#[test]
fn usb_rules_are_tried_in_order_and_default_to_deny() {
    let t = ok(&USB);
    // Hub: allowed by its id. Storage class 8: denied before the catch-all.
    assert_eq!(t.usb_decision(0x1d6b, 0x0002, 9), UsbAuthorize::Allow);
    assert_eq!(t.usb_decision(0x1d6b, 0x0003, 8), UsbAuthorize::Deny);
    assert_eq!(t.usb_decision(0x0781, 0x5567, 3), UsbAuthorize::Allow);
    let t = ok("[usb.hid]\nclass = 3\nauthorize = \"allow\"\n");
    assert_eq!(t.usb_decision(0x046d, 0xc077, 3), UsbAuthorize::Allow);
    assert_eq!(t.usb_decision(0x046d, 0xc077, 8), UsbAuthorize::Deny, "no row matches: refused");
    assert_eq!(ok("").usb_decision(1, 2, 3), UsbAuthorize::Deny, "no rows: everything refused");
}

#[test]
fn a_task_row_may_be_a_security_boundary_in_a_partition() {
    let row = |keys: &str| format!("[task.A.ELF]\n{keys}caps = []\n");
    let t = ok(&row("security_boundary = true\npartition_id = 65535\n"));
    assert_eq!((t.tasks()[0].security_boundary, t.tasks()[0].partition_id), (true, 65535));
    let t = ok(&row("security_boundary = true\n"));
    assert_eq!((t.tasks()[0].security_boundary, t.tasks()[0].partition_id), (true, 0));
    // The keys come in any order.
    let t = ok(&row("partition_id = 2\nsecurity_boundary = true\n"));
    assert_eq!(t.tasks()[0].partition_id, 2);
    for (keys, want) in [
        // A partition belongs to a boundary.
        ("partition_id = 3\n", bad(RowKind::Task)),
        ("partition_id = 3\nsecurity_boundary = false\n", bad(RowKind::Task)),
        ("security_boundary = true\npartition_id = 0\n", ParseError::BadValue),
        ("security_boundary = true\npartition_id = 65536\n", ParseError::BadValue),
        ("security_boundary = \"yes\"\n", ParseError::BadValue),
    ] {
        assert_eq!(refused(&row(keys)), want, "{keys}");
    }
    // The row after a boundary row starts clean.
    let t = ok(&format!("{}[task.B.ELF]\ncaps = []\n", row("security_boundary = true\npartition_id = 4\n")));
    assert_eq!((t.tasks()[1].security_boundary, t.tasks()[1].partition_id), (false, 0));
}

/// The row's `partition_id` reaches the kernel through `row_mem` (the
/// `MemSpec` an exec or a spawn installs, `azos_sched::scheduler::set_task_partition`),
/// 0 on a row that declares none.
#[test]
fn row_mem_carries_the_rows_partition_id() {
    let t = ok("[task.A.ELF]\nsecurity_boundary = true\npartition_id = 9\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(t.row_mem(b"A.ELF", None, 1).unwrap().partition_id, 9);
    assert_eq!(t.row_mem(b"B.ELF", None, 1).unwrap().partition_id, 0, "the next row inherits nothing");
}

const G: &str = "[guest.ais]\ncpus = 2\nmem_mib = 64\nenvelope = \"slow\"\n";

#[test]
fn a_guest_may_pass_devices_through_and_be_a_static_partition() {
    let g = format!("{G}passthrough = [\"uart2\"]\nstatic = true\npcpus = 12\nmem_base = 4096\n");
    let t = ok(&g);
    assert!(t.guests()[0].static_partition);
    assert_eq!(t.guests()[0].passthrough().len(), 1);
    // Not static: no partition keys, and the defaults are not written.
    let t = ok(G);
    assert!(!t.guests()[0].static_partition && t.guests()[0].passthrough().is_empty());
    let t = ok(&format!("{G}static = false\n"));
    assert!(!t.guests()[0].static_partition);
    let st = |extra: &str| format!("{G}static = true\n{extra}");
    let pass9: Vec<String> = (0..azos_topology::GUEST_PASSTHROUGH + 1).map(|i| format!("\"p{i}\"")).collect();
    all_refused(&[
        (st("mem_base = 4096\n"), bad(RowKind::Guest)),
        (st("pcpus = 12\n"), bad(RowKind::Guest)),
        (st("pcpus = 4\nmem_base = 4096\n"), bad(RowKind::Guest)),
        (st("pcpus = 14\nmem_base = 4096\n"), bad(RowKind::Guest)),
        (st("pcpus = 12\nmem_base = 4097\n"), bad(RowKind::Guest)),
        (st("pcpus = 12\nmem_base = 0\n"), bad(RowKind::Guest)),
        (st("pcpus = 12\nmem_base = 18446744073709551615\n"), bad(RowKind::Guest)),
        (format!("{G}pcpus = 12\n"), bad(RowKind::Guest)),
        (format!("{G}mem_base = 4096\n"), bad(RowKind::Guest)),
        (format!("{G}static = 1\n"), ParseError::BadValue),
        (format!("{G}pcpus = 12\npcpus = 12\n"), ParseError::BadValue),
        (format!("{G}passthrough = [\"a\", \"a\"]\n"), bad(RowKind::Guest)),
        (format!("{G}passthrough = [\"a.b\"]\n"), bad(RowKind::Guest)),
        (format!("{G}devices = [\"a\"]\npassthrough = [\"a\"]\n"), bad(RowKind::Guest)),
        (format!("{G}passthrough = [{}]\n", pass9.join(", ")), bad(RowKind::Guest)),
    ]);
    // Static partitions own their CPUs and memory alone.
    let a = format!("{G}static = true\npcpus = 12\nmem_base = 1048576\n");
    let other = |name: &str, pcpus: u32, base: u64| {
        format!("[guest.{name}]\ncpus = 1\nmem_mib = 64\nenvelope = \"full\"\nstatic = true\npcpus = {pcpus}\nmem_base = {base}\n")
    };
    assert_eq!(refused(&format!("{a}{}", other("b", 8, 1 << 30))), dup(RowKind::Guest), "CPU 3 twice");
    assert_eq!(refused(&format!("{a}{}", other("b", 1, (1 << 20) + (63 << 20)))), dup(RowKind::Guest), "memory overlaps");
    assert_eq!(ok(&format!("{a}{}", other("b", 1, (1 << 20) + (64 << 20)))).guests().len(), 2, "adjacent is fine");
    // A guest that is not static shares freely.
    assert_eq!(ok(&format!("{a}[guest.dyn]\ncpus = 4\nmem_mib = 64\nenvelope = \"full\"\n")).guests().len(), 2);
}

#[test]
fn tables_are_bounded_by_their_kconfig_limits() {
    let rows = |n: usize, f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<String>();
    let tsn = |i: usize| format!("[tsn.t{i}]\ndev = \"d{i}\"\nwindow_us = 10\nlink_budget = 10\n");
    assert_eq!(ok(&rows(azos_topology::MAX_TSN, &tsn)).tsns().len(), azos_topology::MAX_TSN);
    assert_eq!(refused(&rows(azos_topology::MAX_TSN + 1, &tsn)), dup(RowKind::Tsn));
    let usb = |i: usize| format!("[usb.u{i}]\nvid = \"{i:04x}\"\nauthorize = \"allow\"\n");
    assert_eq!(ok(&rows(azos_topology::MAX_USB_RULES, &usb)).usb_rules().len(), azos_topology::MAX_USB_RULES);
    assert_eq!(refused(&rows(azos_topology::MAX_USB_RULES + 1, &usb)), dup(RowKind::Usb));
    let key = |i: usize| format!("[key.k{i}]\npurpose = \"sign\"\nsource = \"hardware\"\n");
    assert_eq!(refused(&rows(azos_topology::MAX_KEYS + 1, &key)), dup(RowKind::Key));
    let boot = |i: usize| format!("[boot_chain.s{i}]\nstage = {i}\ndigest = \"{H1}\"\n");
    assert_eq!(ok(&rows(azos_topology::MAX_BOOT_STAGES, &boot)).boot_chain().len(), azos_topology::MAX_BOOT_STAGES);
    assert_eq!(refused(&rows(azos_topology::MAX_BOOT_STAGES + 1, &boot)), dup(RowKind::BootChain));
}

#[test]
fn clearing_a_topology_forgets_the_rows() {
    let mut t = ok(&everything());
    assert!(!t.tsns().is_empty() && t.mission().is_some() && t.rtc().is_some());
    t.clear();
    assert!(t.tsns().is_empty() && t.usb_rules().is_empty() && t.boot_chain().is_empty() && t.keys().is_empty());
    assert!(t.mission().is_none() && t.rtc().is_none() && t.numa_nodes().is_empty());
    // The singletons can be declared again.
    let mut s = String::new();
    s.push_str("format = 8\n[mission]\nreserve_mj = 5\n[rtc]\ndev = \"r\"\n");
    let s: &'static str = leak(s);
    assert_eq!(parse_caps(s.as_bytes(), &mut t), Ok(()));
}

// ── the rows are inside the signature ──────────────────────────────────────

/// Emit the everything topology as a bound pair, sign it, and load it.
fn signed_pair(mutate: impl Fn(String) -> String) -> Result<Option<u64>, SignedRefusal> {
    let caps = leak(format!("format = 8\n{}", everything()));
    let (t, r) = parse_with(SCHED, caps);
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Ok(()));
    let mut sched_out = String::new();
    emit_sched(&t, &mut sched_out).unwrap();
    let b = Binding {
        format: EMIT_FORMAT,
        device: Some(DEV),
        counter: Some(1),
        sched_sha256: Some(azos_crypto::sha256::sha256(sched_out.as_bytes())),
    };
    let mut caps_out = String::new();
    emit_caps(&t, &b, &mut caps_out).unwrap();
    let sig = dsig(key().sign(caps_out.as_bytes()).to_bytes());
    let caps_in = mutate(caps_out.clone());
    let files = SignedFiles { caps: caps_in.as_bytes(), caps_sig: &sig, sched: sched_out.as_bytes() };
    let ctx = DeviceContext { device_id: Some(DEV), floor: 0, bind_device: true, enforce_floor: true };
    let mut loaded = Box::new(Topology::empty());
    let r = load_signed(&mut loaded, &files, key().verifying_key().as_bytes(), &ctx);
    if r.is_ok() {
        assert_eq!(first_difference(&t, &loaded), None, "what was signed is what loads");
    }
    r
}

/// **Canary.** Build with `--features azos_topology/topo-verify-skip-canary`:
/// the tampered files load and the assertions go red.
#[test]
fn the_format_8_rows_are_inside_the_signature() {
    assert_eq!(signed_pair(|c| c), Ok(Some(1)), "the pair as signed loads");
    let tampered: &[(&str, &str)] = &[
        ("window_us = 1000", "window_us = 1001"),
        ("link_budget = 100000", "link_budget = 100001"),
        ("cycle_us = 1000", "cycle_us = 1001"),
        ("\"duplex\"", "\"capture\""),
        ("rate_hz = 48000", "rate_hz = 44100"),
        ("rotation = 90", "rotation = 180"),
        ("/home/owner", "/home/ownes"),
        ("/keys/owner", "/keys/ownes"),
        ("source = \"dice\"", "source = \"hardware\""),
        ("reserve_mj = 250000", "reserve_mj = 250001"),
        (H1, H2),
        ("\"ble-rx\"", "\"ble-tx\""),
        ("period_ms = 60000", "period_ms = 60001"),
        ("cpus = 12\n\n[envelope", "cpus = 13\n\n[envelope"),
        ("level = \"slow\"", "level = \"cautious\""),
        ("utc = false", "utc = true"),
        ("mtu = 9000", "mtu = 9001"),
        ("02:00:5e:10:00:01", "02:00:5e:10:00:02"),
        ("variant = \"int8\"", "variant = \"int4\""),
        ("class = 8", "class = 9"),
        ("security_boundary = true", "security_boundary = false"),
        ("partition_id = 7", "partition_id = 8"),
        ("\"nvme0\"", "\"nvme1\""),
        ("pcpus = 12", "pcpus = 13"),
        ("mem_base = 2147483648", "mem_base = 2147487744"),
    ];
    for (from, to) in tampered {
        let r = signed_pair(|c| {
            assert!(c.contains(from), "{from}");
            c.replacen(from, to, 1)
        });
        assert_eq!(r, Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature)), "{from}");
    }
}

#[test]
fn the_kinds_have_distinct_words() {
    // `EffectKind` and `KeySource` words are the row values; a typo in one
    // would make a row unwritable.
    for k in ["config", "ota", "egress", "delete", "rt_time", "mic"] {
        assert_eq!(EffectKind::from_bytes(k.as_bytes()).map(|k| k.as_str()), Some(k));
    }
    for s in ["dice", "keystore", "hardware"] {
        assert_eq!(KeySource::from_bytes(s.as_bytes()).map(|k| k.as_str()), Some(s));
    }
    assert_eq!(EffectKind::from_bytes(b"motor"), None);
}

/// The built-in (development) topology says, in rows, what every image did
/// before the effect gate held deletes, first packets, configuration writes,
/// update steps and real-time reservations to an envelope: the classes its
/// tasks run in may do all five (`full`). The rows fit the table (15 of
/// `TOPOLOGY_MAX_ENVELOPES`, 16 by default on every profile), and a class they
/// do not name is `full` too.
#[test]
fn the_development_topology_allows_every_gated_effect_in_rows() {
    let t = azos_topology::default_minimal();
    assert_eq!(t.envelopes().len(), 15);
    assert!(t.envelopes().len() <= azos_limits::TOPOLOGY_MAX_ENVELOPES as usize);
    for class in [&b"soft_rt"[..], b"best_effort", b"session"] {
        for kind in [EffectKind::Delete, EffectKind::Egress, EffectKind::Config, EffectKind::Ota, EffectKind::RtTime] {
            let row = t.envelopes().iter().find(|r| r.kind == kind && r.class.as_bytes() == class);
            assert_eq!(row.map(|r| r.level), Some(Envelope::Full), "{} {}", String::from_utf8_lossy(class), kind.as_str());
        }
    }
    for kind in [EffectKind::Egress, EffectKind::Config, EffectKind::Ota, EffectKind::RtTime] {
        assert_eq!(t.effect_ceiling(b"safety_critical", kind), Envelope::Full);
    }
    assert_eq!(t.admission_check(), Ok(()));
}
