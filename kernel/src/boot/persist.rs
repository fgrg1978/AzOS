// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kernel_main`'s Phase G2, persistent state recovery: the signed CONFIG.INI,
//! the OTA boot validation and secure boot, the brain link key and its ring-3
//! door, the operator's e-stop release authority, the keyless-link policy
//! gate, and the configuration applied to the subsystems, all before the
//! network and the first task.

use crate::*;

/// Phase G2, in order (see the module doc). Inlined, as every boot phase (see
/// `boot`'s module doc).
#[inline(always)]
pub(crate) fn recover_persistent_state() {
    // ---- Phase G2: Persistent State Recovery ────────────────────────────────
    //
    // Load /fat/CONFIG.INI BEFORE net_init() and task creation so every
    // subsystem starts with the persisted (or factory-default) configuration.
    // First-boot: generate defaults and write CONFIG.INI to disk.

    kprintln!("========================================");
    kprintln!(" Phase G2: Persistent State Recovery");
    kprintln!("========================================");
    {
        // CONFIG.INI under its signed authority: CONFIG.SIG format v2 (device
        // id + a counter the device record's floor never lets go backwards),
        // and a provisioned device that loses that authority latches the
        // e-stop. The whole policy and its reasons: `boot/config_auth.rs`.
        load_signed_config();
        azos_config::cfg_apply();
        kprintln!("[CFG] {} entries, ml_enabled={}",
            azos_config::cfg_count(),
            ML_ENABLED.load(Ordering::Relaxed) as u8);

        // ── OTA boot validation + secure boot (SHARED with aarch64) ───
        // The whole block — A/B slot, CRC, Ed25519, decision 99's fall to
        // recovery, the `bad_slots` record — moved into
        // `boot_validate_and_verify_slots()` so aarch64's `kernel_main`
        // runs the same code instead of a copy. See that function's doc
        // for the three preconditions this call site satisfies.
        boot_validate_and_verify_slots();

        // ── Brain link key (reserved tail sector) ───────────────────────
        // The 32-byte pre-shared key the brain link's Noise static keys derive
        // from (`azos_behavior::encrypt_link`, `azos_crypto::secure_channel`).
        // The brain's matching key lives in env `AZOS_BRAIN_LINK_KEY`. The link
        // is always a Noise session: without a key it does not run at all (the
        // control and camera dials close at once, `brain_dial`), it is never
        // downgraded to anything weaker.
        //
        // U06-9/#30 (2026-09-26): this used to be an ordinary FAT32 file,
        // `/fat/LINK.KEY`, and a USB mass-storage export of the volume reaches
        // every file on it block for block. The key now lives in the reserved
        // tail (`reserved_tail::LINK_KEY`), past the filesystem, at LBAs such an
        // export never reports (`crate::reserved_tail` for the mechanism).
        //
        // The sector holds a link-key record (magic, version, key, integrity
        // tag: `azos_crypto::secure_channel::link_key_record_decode`), and it is
        // read only when no partition and no FAT32 volume reaches the tail
        // (`reserved_tail::verdict`). Anything else is refused and the link
        // stays down: a raw key, a torn write, or filesystem data on an image
        // built without the headroom, whose bytes anyone who can write a file
        // there would choose.
        //
        // Whether a boot without the key goes on is a policy decision, and
        // like secure boot it is fixed at COMPILE time by the
        // `link-provisioning-enforced` feature: with it compiled in there must be
        // no runtime flag, debug build, or code path that relaxes the
        // requirement. The load below always runs so the trust state is
        // visible on the console; only the "refuse to boot" half is gated.
        //
        // The brain link is the Robot domain's (wave 11): without it there is
        // no link to key and nothing below runs.
        //
        // The one reader of the key, for this boot's load and for the ring-3
        // door below: `Absent` also covers a tail that is not ours or a sector
        // that does not read (no disk, an image without the headroom).
        fn link_key_read(
            key: &mut [u8; azos_crypto::secure_channel::PSK_BYTES],
        ) -> Result<(), azos_crypto::secure_channel::LinkKeyFault> {
            use azos_crypto::secure_channel::{link_key_record_decode, LinkKeyFault, LINK_KEY_RECORD_BYTES};
            let mut rec = [0u8; LINK_KEY_RECORD_BYTES];
            if crate::reserved_tail::read(crate::reserved_tail::LINK_KEY, &mut rec).is_err() {
                return Err(LinkKeyFault::Absent);
            }
            let r = link_key_record_decode(&rec);
            azos_crypto::ct::secure_zero(&mut rec);
            let mut k = r?;
            key.copy_from_slice(&k);
            azos_crypto::ct::secure_zero(&mut k);
            Ok(())
        }
        #[cfg(feature = "use-robot")]
        let mut link_keyed = false;
        // No initialiser: every branch below assigns it, and a placeholder
        // value here would be dead (rustc says so, and warnings fail CI).
        #[cfg(feature = "use-robot")]
        let link_key_reason: &str;
        #[cfg(feature = "use-robot")]
        {
            let mut key_buf = [0u8; azos_behavior::encrypt_link::PSK_BYTES];
            match link_key_read(&mut key_buf) {
                Ok(()) => {
                    // SAFETY: called exactly once during boot, single-threaded,
                    // before any task that reads the key is spawned.
                    if unsafe { azos_behavior::encrypt_link::install_link_key(&key_buf) } {
                        kprintln!("[SECCHAN] link key loaded ({} bytes, reserved sector {}) — \
                                   brain link authenticated",
                            key_buf.len(), crate::reserved_tail::LINK_KEY);
                        link_keyed = true;
                        link_key_reason = "key loaded";
                    } else {
                        azos_drv_sys::kerr!("[SECCHAN] link key rejected by encrypt_link::install_link_key");
                        link_key_reason = "key rejected by encrypt_link::install_link_key";
                    }
                }
                Err(azos_crypto::secure_channel::LinkKeyFault::Malformed) => {
                    azos_drv_sys::kerr!("[SECCHAN] link key REFUSED: reserved sector {} holds no valid \
                               link-key record (magic, version or integrity tag wrong, or a zero \
                               key) — brain link down",
                        crate::reserved_tail::LINK_KEY);
                    link_key_reason = "key sector malformed (no valid link-key record)";
                }
                Err(azos_crypto::secure_channel::LinkKeyFault::Absent) => {
                    azos_drv_sys::kwarn!("[SECCHAN] link key absent (reserved sector {} unreadable, \
                               not ours, or all-zero) — brain link down",
                        crate::reserved_tail::LINK_KEY);
                    link_key_reason = "key sector absent/unprovisioned";
                }
            }
            azos_crypto::ct::secure_zero(&mut key_buf);
        }

        // U06-9 (2026-09-26): the ring-3 door onto this same reserved
        // sector (the `linkkey` endpoint, `crates/core/syscall/src/link_key.rs`).
        // Registered right after the load above so the hook re-reads the
        // exact same sector this boot just logged the state of, through the
        // same reader — a ring-3 caller holding the capability sees the same
        // bytes, not a second, possibly different, read. `crates/core/syscall`
        // cannot call `crate::reserved_tail::read` directly (that module lives
        // in `kernel/src`, above it in the dependency graph), same TCB reason
        // `ESTOP_HANDLER` is a hook and not a call.
        fn read_link_key_for_ring3(
            out: &mut [u8; azos_syscall::link_key::LINK_KEY_BYTES],
        ) -> bool {
            link_key_read(out).is_ok()
        }
        azos_syscall::link_key::set_link_key_read_hook(read_link_key_for_ring3);

        // ── Operator e-stop release authority (`/fat/OPERATOR.PUB`) ──────
        // Owner decision, 2026-09-25 — see `safety::ReleaseAuthority`'s
        // module note for the finding and the three acceptable authorities.
        // This is the ONE hook registration this change adds to `main.rs`:
        // the Ed25519 PUBLIC key of the operator who may release an armed
        // e-stop latch. The brain link never receives this file — only the
        // holder of the matching PRIVATE key can produce a signature
        // `safety::verify_operator_release` accepts. Absent, wrong-size or
        // all-zero ⇒ `operator_authority_init` is never called with a usable
        // key ⇒ every release attempt is refused: fail-closed by
        // construction, the same shape as the `/fat/LINK.KEY` load above,
        // and there is deliberately no `-enforced` boot-refusal feature
        // paired with it — an unprovisioned robot must still boot, it just
        // cannot have its e-stop released by anything this module checks.
        {
            const OPERATOR_KEY_BYTES: usize = 32;
            // W2-B5 (2026-09-26): the signed topology (`[operator]` in
            // CAPS.TOML) carries the key. G1 (2026-10-11): the loose
            // `/fat/OPERATOR.PUB` has no signature, so anyone who can write
            // the FAT could install a key and release a latched e-stop. It is
            // read only by a development build whose signed topology declares
            // no key (`estop::operator_key_source`); a release build refuses
            // every release instead. The topology's key is pinned in the
            // flight recorder on first use; a later boot offering another is
            // refused and recorded (`estop::operator_key_pin_install`).
            let topology_op_key = azos_topology::get()
                .map(|t| t.operator_pubkey())
                .filter(|k| *k != [0u8; OPERATOR_KEY_BYTES]);
            use azos_actuation::estop::{operator_key_source, OperatorKeySource};
            match operator_key_source(topology_op_key.is_some(), azos_limits::BUILD_TYPE_DEV) {
                OperatorKeySource::SignedTopology => {
                    let key = topology_op_key.unwrap_or([0u8; OPERATOR_KEY_BYTES]);
                    use azos_actuation::estop::{operator_key_pin_install, KeyPin};
                    match operator_key_pin_install(&key) {
                        KeyPin::Installed => kprintln!("[ESTOP] operator release authority \
                                   provisioned from signed topology ([operator] section)"),
                        KeyPin::Changed => azos_drv_sys::kerr!("[ESTOP] the topology's [operator] \
                                   key differs from the one this robot pinned — key refused and \
                                   recorded, every release refused"),
                        KeyPin::NotDurable => azos_drv_sys::kerr!("[ESTOP] the topology's [operator] \
                                   key could not be pinned in the flight recorder — key refused, \
                                   every release refused"),
                        KeyPin::Zero => azos_drv_sys::kwarn!("[ESTOP] topology declared an \
                                   [operator] key but it was rejected — every release refused"),
                    }
                }
                OperatorKeySource::UnsignedFatDevOnly => {
                    let mut op_key_buf = [0u8; OPERATOR_KEY_BYTES];
                    let mut fd_table = azos_fs::ScratchFds::new();
                    let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/OPERATOR.PUB",
                                                    azos_fs::O_RDONLY);
                    if fd >= 0 {
                        let n = azos_fs::vfs_read(&mut fd_table, fd,
                                                       op_key_buf.as_mut_ptr(),
                                                       op_key_buf.len());
                        azos_fs::vfs_close(&mut fd_table, fd);
                        if n == OPERATOR_KEY_BYTES as i32
                            && azos_actuation::estop::operator_authority_init(&op_key_buf)
                        {
                            azos_drv_sys::kwarn!("[ESTOP] /fat/OPERATOR.PUB loaded (UNSIGNED, \
                                       development build only) — release authority provisioned");
                        } else {
                            azos_drv_sys::kwarn!("[ESTOP] /fat/OPERATOR.PUB missing/wrong-size/all-zero — \
                                       no release authority provisioned, every release refused");
                        }
                    } else {
                        azos_drv_sys::kwarn!("[ESTOP] /fat/OPERATOR.PUB absent — no release authority \
                                   provisioned, every release refused");
                    }
                }
                OperatorKeySource::None => {
                    azos_drv_sys::kwarn!("[ESTOP] no [operator] key in the signed topology; a release \
                               build ignores /fat/OPERATOR.PUB — every release refused");
                }
            }
            // A warrant names the robot it releases: the id of the device
            // record, the identity the signed topology and CONFIG.SIG are
            // bound to, so one signed for another robot under the same key is
            // no warrant here. Without a record a release build refuses every
            // release (`ReleaseDenial::NoDeviceIdentity`).
            match boot::read_device_record() {
                Some(r) => azos_actuation::estop::release_device_init(&r.device_id),
                None => azos_drv_sys::kwarn!("[ESTOP] no device record: release warrants bind no robot \
                           ({})", if azos_limits::BUILD_TYPE_DEV { "development build: the zero id" }
                                  else { "every release refused" }),
            }
        }

        // Policy gate — deliberately NOT consulting any runtime flag, for the
        // same reason the secure-boot gate does not: a build that claims to
        // enforce must have no way to be talked out of it.
        //
        // `link-provisioning-enforced`: a keyless boot leaves the robot with a
        // link that is down forever — refusing to boot surfaces the
        // provisioning error here, on the console, instead of in the field
        // as "robot won't talk".
        //
        // A keyless link is refused in every build, so the refusal is a
        // `login` decision record in every build (`azos_decision::RULES`:
        // method 5 the brain link, attempt 0, reason 4 no key to verify
        // with); the console line names its id. It is made before the flight
        // recorder is armed (`install_robot_hw`, below), so it is in the ring
        // and the journal, not on the medium.
        #[cfg(feature = "use-robot")]
        {
            if !link_keyed {
                const LOGIN_METHOD_BRAIN_LINK: u64 = 5;
                const LOGIN_NO_KEY: u64 = 4;
                let receipt = azos_decision::record_receipt(
                    azos_decision::Rule::Login,
                    azos_decision::Verdict::Refuse,
                    0,
                    [LOGIN_METHOD_BRAIN_LINK, 0, LOGIN_NO_KEY],
                );
                if azos_behavior::encrypt_link::link_provisioning_enforced() {
                    azos_drv_sys::kerr!("[SECCHAN] FATAL: brain link has no key — {} — \
                               link-provisioning-enforced is compiled in, refusing to boot \
                               (decision {})",
                        link_key_reason, receipt);
                    loop { azos_arch::Cpu::wait_for_interrupt(&azos_arch::ARCH); }
                }
                azos_drv_sys::kwarn!("[SECCHAN] WARNING: brain link has no key — {} \
                           (link-provisioning-enforced not compiled in — booting anyway, \
                           the link stays down; decision {})",
                    link_key_reason, receipt);
            }
        }

        // ── Apply config to all subsystems ─────────────────────────────

        // Network: set IP/mask/gateway BEFORE net_init() — see
        // `install_net_config`'s own doc for the ordering reason.
        #[cfg(feature = "net")]
        install_net_config();

        // Scheduler Hz -- Q4.2 (owner decision, 2026-09-25): CONFIG.INI on
        // the removable FAT volume may only LOWER sched_hz below the
        // Kconfig compile-time default for this board/profile, never raise
        // it, and never below SCHED_HZ_FLOOR. The old check here
        // (`cfg_hz >= 10`) had no upper bound at all -- a CONFIG.INI value
        // above the compiled default was previously honoured outright.
        let sched_hz_default = azos_limits::SCHED_HZ as u32;
        let sched_hz_floor = azos_limits::SCHED_HZ_FLOOR as u32;
        let cfg_hz = azos_config::cfg_get_u32(b"sched_hz", sched_hz_default);
        let sched_hz_res = azos_config::resolve_sched_hz(
            cfg_hz, sched_hz_default, sched_hz_floor);
        azos_drv_sys::timebase::sched_hz_set(sched_hz_res.effective as u64);
        if sched_hz_res.clamped {
            azos_drv_sys::kwarn!("[CFG] sched_hz: CONFIG.INI requested {} Hz, clamped to {} Hz \
                       (compile-time default {} Hz, floor {} Hz)",
                sched_hz_res.requested, sched_hz_res.effective,
                sched_hz_default, sched_hz_floor);
        }
        kprintln!("[CFG] sched_hz={}", azos_drv_sys::timebase::sched_hz_get());

        // Behavior layers.
        #[cfg(feature = "use-robot")]
        azos_behavior::layer_set_enabled(1,
            azos_config::BEHAVIOR_L1_ENABLED.load(Ordering::Relaxed));
        #[cfg(feature = "use-robot")]
        azos_behavior::layer_set_enabled(2,
            azos_config::BEHAVIOR_L2_ENABLED.load(Ordering::Relaxed));
        #[cfg(feature = "use-robot")]
        azos_behavior::layer_set_enabled(3,
            azos_config::BEHAVIOR_L3_ENABLED.load(Ordering::Relaxed));

        // Behavior VLA server.
        #[cfg(feature = "use-robot")]
        let bport = azos_config::BEHAVIOR_SERVER_PORT.load(Ordering::Relaxed);
        #[cfg(feature = "use-robot")]
        if bport > 0 {
            let bip = azos_config::behavior_server_ip_bytes();
            azos_behavior::remote_configure(bip, bport as u16);
            kprintln!("[CFG] VLA server: {}.{}.{}.{}:{}",
                bip[0], bip[1], bip[2], bip[3], bport);
        }

        // Encoder physical params.
        #[cfg(feature = "use-robot")]
        azos_robot::set_ticks_per_m(
            azos_config::CFG_TICKS_PER_M.load(Ordering::Relaxed));
        #[cfg(feature = "use-robot")]
        azos_robot::set_wheel_base_mm(
            azos_config::CFG_WHEEL_BASE_MM.load(Ordering::Relaxed));
        #[cfg(feature = "use-robot")]
        kprintln!("[CFG] encoder: tpm={} wb={}mm",
            azos_robot::ticks_per_m(), azos_robot::wheel_base_mm());

        // IMU offsets are applied automatically in imu_read_scaled() via atomics.
    }
    azos_fs::inode_leak_probe();
    kprintln!();
}
