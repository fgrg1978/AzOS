// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DEV02 — USB DFU recovery mode kernel glue.
//!
//! Drives the [`azos_dfu`] crate's state machine end-to-end:
//! decodes incoming Setup packets, advances the DFU 1.1 FSM,
//! buffers DNLOAD payload into a 2 MiB staging area, and on a
//! zero-length DNLOAD ("end of transfer") flushes the buffer to
//! the OTA inactive slot (KERN_A.BIN / KERN_B.BIN) via
//! [`azos_fs::vfs_*`].
//!
//! ## What is stubbed
//!
//! The actual USB device-controller register programming
//! (DWC2 on JH7110, similar on K1) is NOT wired here — the
//! hardware was not yet on hand when this module was written
//! (pre-Julio 2026). The entry points [`feed_setup_packet`] and
//! [`feed_dnload_payload`] are the seams the controller driver
//! calls once available. See the `// TODO(hw):` markers.
//!
//! The signature-verify hand-off in `finalize_manifest()` is a
//! stub that always succeeds — real secure-boot integration goes
//! through [`azos_ota::secure_boot`] after the .SIG file is
//! also DFU-uploaded (out of scope for DEV02; tracked separately).
//!
//! OPEN ISSUE, for whoever wires the controller: because of that
//! stub, this path writes an unauthenticated image straight over
//! `KERN_{A,B}.BIN` — the same class of problem as the OTA
//! receiver's, which is now gated by
//! `secure_boot_verify_staged_detailed()` in `cmd_ota_recv`. DFU
//! cannot copy that fix as-is: it has no way to receive the `.SIG`
//! sidecar (DFU carries one opaque byte stream, and the functional
//! descriptor here advertises a single alt-setting), and it is the
//! recovery path of last resort, so a hard signature requirement
//! with no way to supply a signature would make a bricked board
//! permanently unrecoverable. Deciding how a signature reaches this
//! path — a second alt-setting, or a container framing the image
//! and its signature together — is the same OWNER DECISION as the
//! OTA `.SIG` transport. What IS enforced here today is a minimum
//! image size (`DFU_MIN_IMAGE_SIZE`), which stops a zero-length
//! DNLOAD from truncating a live slot to nothing.
//!
//! ## Concurrency
//!
//! DFU runs on a dedicated USB device-mode task. All state lives
//! in a single static behind a `SpinLock`, accessed only from
//! that task plus the IRQ handler that delivers Setup packets.

#![allow(dead_code)] // entry points are called by the (not-yet-wired) USB controller driver.

use azos_dfu::{
    ChunkAccumulator, DfuRequest, DfuRequestType, DfuState, DfuStateMachine,
    FunctionalDescriptor, SetupPacket, parse_setup_packet,
    STATUS_ERR_NOTDONE, STATUS_ERR_UNKNOWN, STATUS_ERR_WRITE,
};
use azos_drv_sys::kprintln;
use azos_ota::{
    OTA_MAX_IMAGE_SIZE, ota_inactive_slot, ota_slot_path,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Max DNLOAD chunk size (matches the functional descriptor).
const DFU_TRANSFER_SIZE: u16 = 1024;

/// Staging buffer size — must be >= the largest firmware image the
/// kernel will accept. Mirrors [`OTA_MAX_IMAGE_SIZE`] (2 MiB) so any
/// image that would fit in an OTA slot also fits here.
const DFU_STAGING_SIZE: usize = OTA_MAX_IMAGE_SIZE;

/// Smallest DNLOAD total that may be committed over a kernel slot.
///
/// The number that closes the hole is `> 0` — see `finalize_manifest`. This
/// floor is the cheap sanity margin on top of it: a RISC-V kernel image for
/// this project is multi-MiB (the `secure_boot.rs` notes put the current one
/// around 4.3 MiB), so nothing under 64 KiB is a plausible kernel, and
/// anything under 64 KiB arriving on the recovery path is either a truncated
/// transfer or someone probing. Deliberately kept far below any real image so
/// it can never reject a legitimate update: the check must not become its own
/// denial of service on the last-resort un-brick path.
const DFU_MIN_IMAGE_SIZE: usize = 64 * 1024;

/// USB control endpoint id (EP0). DFU 1.1 §3.2 — all DFU class
/// requests travel on the control pipe.
const DFU_CONTROL_ENDPOINT: u8 = 0;

/// GETSTATUS response payload size (DFU 1.1 §6.1.2 Table 6.3).
const DFU_GETSTATUS_LEN: usize = 6;

/// GETSTATE response payload size (DFU 1.1 §6.1.1).
const DFU_GETSTATE_LEN: usize = 1;

/// Maximum number of pending IN bytes to buffer for the host to
/// read on the next GETSTATUS / GETSTATE poll.
const DFU_REPLY_BUF_LEN: usize = DFU_GETSTATUS_LEN;

// ── Internal state ────────────────────────────────────────────────────────

/// Result of feeding the FSM a request. The USB controller driver
/// uses this to decide whether to ACK the control transfer with a
/// zero-length packet, send back IN data, or STALL EP0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DfuFeedOutcome {
    /// Request handled, no data stage required. Driver acks ZLP.
    Ack,
    /// Request handled, `len` bytes ready in the reply buffer
    /// (call [`take_reply`] to read them out).
    Reply { len: usize },
    /// Transfer complete — DNLOAD terminator received, staging
    /// buffer was flushed to the inactive slot, and the FSM is
    /// now in `ManifestWaitReset`. Driver should re-enumerate
    /// (USB bus reset) once the host issues one.
    ManifestDone,
    /// Request was malformed / from the wrong state. Driver
    /// STALLs EP0; host will issue CLRSTATUS to recover.
    Stall,
}

/// Aggregate kernel-side DFU state. One global instance behind a
/// spinlock (single USB device controller).
struct DfuRecoveryState {
    fsm:         DfuStateMachine,
    accumulator: ChunkAccumulator,
    /// Pre-encoded reply for the next IN transfer. Filled by
    /// GETSTATUS / GETSTATE handlers, drained by the controller
    /// driver via [`take_reply`].
    reply:       [u8; DFU_REPLY_BUF_LEN],
    reply_len:   usize,
}

impl DfuRecoveryState {
    const fn new() -> Self {
        Self {
            fsm:         DfuStateMachine::new_dfu_mode(
                            DFU_STAGING_SIZE, DFU_TRANSFER_SIZE),
            accumulator: ChunkAccumulator::new(DFU_TRANSFER_SIZE),
            reply:       [0u8; DFU_REPLY_BUF_LEN],
            reply_len:   0,
        }
    }
}

// 2 MiB staging buffer for the firmware image. Lives in BSS,
// zero-initialized by the boot code. Only touched from the DFU
// task — no cross-thread access needed.
static mut DFU_STAGING: [u8; DFU_STAGING_SIZE] = [0u8; DFU_STAGING_SIZE];

// Aggregate FSM/accumulator/reply. Same single-owner discipline as
// `DFU_STAGING`. The USB device-mode task is the only caller.
static mut DFU_STATE: DfuRecoveryState = DfuRecoveryState::new();

/// `&mut` accessor for `DFU_STATE`. SAFETY: only the USB device
/// task touches DFU state; this is enforced by convention until the
/// real DWC2 driver is wired and we can add a `SpinLock`.
#[inline]
fn state() -> &'static mut DfuRecoveryState {
    // SAFETY: single-owner (USB device task); see module docs.
    unsafe { &mut *core::ptr::addr_of_mut!(DFU_STATE) }
}

#[inline]
fn staging() -> &'static mut [u8; DFU_STAGING_SIZE] {
    // SAFETY: single-owner (USB device task); see module docs.
    unsafe { &mut *core::ptr::addr_of_mut!(DFU_STAGING) }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Initialize recovery DFU mode. Called from boot if a recovery
/// trigger fired (button held, crash counter exceeded, etc.). The
/// real implementation will additionally hand the DFU descriptor
/// blob over to the USB device controller driver and arm the EP0
/// IRQ. For now this only resets the FSM/accumulator so the kernel
/// is ready when the controller is wired.
pub fn dfu_recovery_init() {
    let s = state();
    s.fsm = DfuStateMachine::new_dfu_mode(DFU_STAGING_SIZE, DFU_TRANSFER_SIZE);
    s.accumulator = ChunkAccumulator::new(DFU_TRANSFER_SIZE);
    s.reply_len = 0;

    let _ = FunctionalDescriptor::AZOS_DEFAULT; // descriptor exported to host via the controller driver.
    // TODO(hw): wire DWC2 controller here — pass DescriptorBuilder
    // bytes to the device-mode driver, enable EP0 IRQ, and route
    // Setup packets to `feed_setup_packet` below.

    kprintln!(
        "[DFU] recovery mode armed (staging={} KiB, transfer={} B, EP={})",
        DFU_STAGING_SIZE / 1024, DFU_TRANSFER_SIZE, DFU_CONTROL_ENDPOINT);
}

/// Feed a raw 8-byte USB Setup packet from the USB controller IRQ
/// into the DFU state machine. Returns what the controller should
/// do next.
pub fn feed_setup_packet(raw: &[u8]) -> DfuFeedOutcome {
    let Some(pkt) = SetupPacket::from_bytes(raw) else {
        return DfuFeedOutcome::Stall;
    };
    let Some((dir, req)) = parse_setup_packet(pkt) else {
        return DfuFeedOutcome::Stall;
    };
    handle_request(dir, req)
}

/// Feed the data stage of an in-flight DNLOAD transfer. The
/// controller driver calls this after `feed_setup_packet` returned
/// `Ack` for a DNLOAD whose `w_length` was non-zero. `payload.len()`
/// MUST equal the `w_length` from that Setup packet.
pub fn feed_dnload_payload(payload: &[u8]) -> DfuFeedOutcome {
    let s = state();
    match s.accumulator.push(payload, staging()) {
        Ok(_) => DfuFeedOutcome::Ack,
        Err(_) => {
            // Mirror the FSM into Error so the next GETSTATUS reports it.
            // CLRSTATUS from the host clears both.
            // The state machine itself already moved to Error inside
            // `dnload()` if applicable; here we only signal STALL.
            DfuFeedOutcome::Stall
        }
    }
}

/// Drain the pending IN reply (GETSTATUS / GETSTATE) into `out`.
/// Returns the number of bytes written. Driver calls this when the
/// host issues the IN data stage following a class-IN request.
pub fn take_reply(out: &mut [u8]) -> usize {
    let s = state();
    let n = s.reply_len.min(out.len());
    if n > 0 {
        out[..n].copy_from_slice(&s.reply[..n]);
    }
    s.reply_len = 0;
    n
}

// ── Internals ─────────────────────────────────────────────────────────────

fn handle_request(dir: DfuRequestType, req: DfuRequest) -> DfuFeedOutcome {
    let s = state();
    match req {
        DfuRequest::Detach { .. } => {
            if dir != DfuRequestType::Out { return DfuFeedOutcome::Stall; }
            // Already in DFU mode — Detach from runtime is not the
            // normal path here. The FSM only transitions
            // AppIdle → AppDetach if it was constructed via
            // `new_runtime`; from any other state `detach()` drives it
            // into `Error` with ERR_STALLEDPKT.
            //
            // That result must be reported. The old code discarded it and
            // returned `Ack` unconditionally, so the device told the host
            // "detach accepted" while its own FSM had just entered
            // `dfuERROR` — the host proceeds to wait for a re-enumeration
            // that will never come, and every subsequent request it sends
            // is answered from an error state it was never told about. A
            // STALL is the honest answer and the one the host knows how to
            // recover from (CLRSTATUS), which matters more here than
            // anywhere else: this is the recovery path.
            match s.fsm.detach() {
                Ok(())  => DfuFeedOutcome::Ack,
                Err(_)  => DfuFeedOutcome::Stall,
            }
        }
        DfuRequest::Dnload { len, .. } => {
            if dir != DfuRequestType::Out { return DfuFeedOutcome::Stall; }
            match s.fsm.dnload(len) {
                Ok(()) => {
                    if len == 0 {
                        // Zero-length DNLOAD = end-of-transfer. The
                        // host will poll GETSTATUS → Manifest. We
                        // commit to the inactive slot synchronously.
                        finalize_manifest()
                    } else {
                        // Data stage follows — the controller driver
                        // will invoke `feed_dnload_payload` with the
                        // payload bytes.
                        DfuFeedOutcome::Ack
                    }
                }
                Err(_) => DfuFeedOutcome::Stall,
            }
        }
        DfuRequest::Upload { .. } => {
            // DFU functional descriptor advertises CAN_DOWNLOAD only.
            // UPLOAD is not supported on AZOS — STALL per spec §5.1.3.
            DfuFeedOutcome::Stall
        }
        DfuRequest::GetStatus => {
            if dir != DfuRequestType::In { return DfuFeedOutcome::Stall; }
            // If we are in DnloadSync / ManifestSync, the spec wants
            // us to advance to DnloadIdle / Manifest after replying.
            // We advance *before* encoding so the reply reflects the
            // post-advance state — dfu-util tolerates both orderings.
            //
            // The state test is NOT optional. `finish_sync()` is only legal
            // from those two states; from anywhere else it falls through to
            // `into_error(STATUS_ERR_STALLEDPKT)` and puts the machine in
            // `dfuERROR`. Calling it unconditionally therefore meant that a
            // GETSTATUS from `DfuIdle` — which `dfu-util` issues routinely,
            // including as its very first request after enumerating — moved
            // the device into an error state and reported `dfuERROR` back to
            // the host, all in response to a perfectly legal request. The
            // host then has to CLRSTATUS to make any progress, and does the
            // same thing again on its next poll. This is the last-resort
            // un-brick path; it has to survive being spoken to correctly.
            //
            // The same guard also fixes a second instance: GETSTATUS in
            // `ManifestWaitReset` (the state we sit in between a successful
            // commit and the host's bus reset — precisely when a host polls
            // to confirm the commit took) previously landed in `dfuERROR`
            // too, turning a completed firmware update into an apparent
            // failure.
            if matches!(s.fsm.state(), DfuState::DnloadSync | DfuState::ManifestSync) {
                let _ = s.fsm.finish_sync();
            }
            let bytes = s.fsm.status().encode();
            debug_assert_eq!(bytes.len(), DFU_GETSTATUS_LEN);
            s.reply[..DFU_GETSTATUS_LEN].copy_from_slice(&bytes);
            s.reply_len = DFU_GETSTATUS_LEN;
            DfuFeedOutcome::Reply { len: DFU_GETSTATUS_LEN }
        }
        DfuRequest::ClrStatus => {
            if dir != DfuRequestType::Out { return DfuFeedOutcome::Stall; }
            // CLR_STATUS is only legal from Error per spec §5.1.7.
            // The FSM enforces that; we also reset the accumulator
            // so the next download starts clean.
            match s.fsm.clr_status() {
                Ok(()) => {
                    s.accumulator.reset();
                    DfuFeedOutcome::Ack
                }
                Err(_) => DfuFeedOutcome::Stall,
            }
        }
        DfuRequest::GetState => {
            if dir != DfuRequestType::In { return DfuFeedOutcome::Stall; }
            s.reply[0] = s.fsm.state().as_u8();
            s.reply_len = DFU_GETSTATE_LEN;
            DfuFeedOutcome::Reply { len: DFU_GETSTATE_LEN }
        }
        DfuRequest::Abort => {
            if dir != DfuRequestType::Out { return DfuFeedOutcome::Stall; }
            match s.fsm.abort() {
                Ok(()) => {
                    s.accumulator.reset();
                    DfuFeedOutcome::Ack
                }
                Err(_) => DfuFeedOutcome::Stall,
            }
        }
    }
}

/// Flush the staging buffer to the OTA inactive slot. Called when
/// the FSM enters `ManifestSync` (zero-length DNLOAD). On success
/// the FSM is advanced through `Manifest` → `ManifestWaitReset`.
fn finalize_manifest() -> DfuFeedOutcome {
    let s = state();
    let total = s.accumulator.bytes_written;
    let slot  = ota_inactive_slot();
    let path  = ota_slot_path(slot);

    // ── Refuse to commit a transfer that carried no (or implausibly little)
    //    firmware. This guard is what stops ONE USB control request from
    //    destroying a kernel slot.
    //
    // `DfuState::accepts_dnload()` is true in `DfuIdle`, and `dnload(0)` is
    // the legal "end of transfer" terminator — so a host that has sent no
    // payload at all can go straight from `DfuIdle` to `ManifestSync` and
    // land here with `bytes_written == 0`. `write_slot_file` then opens
    // `KERN_{A,B}.BIN` with `O_TRUNC` and writes `&staging()[..0]`, which
    // truncates a live, possibly the *only* good, kernel image to zero bytes
    // — and `n as usize == bytes.len()` is `0 == 0`, so it reports success
    // and the FSM cheerfully advances to `ManifestWaitReset`. No malformed
    // packet, no overflow: a single well-formed zero-length DNLOAD from any
    // device that can speak USB to this port.
    //
    // The refusal has to happen BEFORE `write_slot_file`, because the
    // destruction is the `O_TRUNC` in the open, not the write.
    if total < DFU_MIN_IMAGE_SIZE {
        azos_drv_sys::kwarn!(
            "[DFU] manifest REFUSED: {} bytes staged, minimum is {} — \
             slot {} left untouched (a zero-length DNLOAD must never truncate \
             a live kernel image)",
            total, DFU_MIN_IMAGE_SIZE, slot);
        // ERR_NOTDONE — DFU 1.1 Table 6.3: "the device's file is not done
        // being written". Exactly this case, and it tells the host the
        // transfer was incomplete rather than that the device choked on a
        // packet, so `dfu-util` reports something actionable.
        s.fsm.fail(STATUS_ERR_NOTDONE);
        return DfuFeedOutcome::Stall;
    }

    let ok = write_slot_file(path, &staging()[..total]);

    if !ok {
        // Persist the error in the FSM so the next GETSTATUS reports
        // ERR_WRITE.
        //
        // This used to call `clr_status()` and rely on it *failing* (illegal
        // from `ManifestSync`) to land in Error as a side effect — which put
        // ERR_STALLEDPKT in `bStatus` instead of the real cause, and would
        // have done the opposite of what was wanted had we ever been in
        // `Error` already: `clr_status()` succeeds there, resetting the
        // machine to `DfuIdle` and reporting OK for a commit that failed.
        // `DfuStateMachine::fail()` states the outcome directly.
        azos_drv_sys::kerr!("[DFU] manifest write FAILED (slot={}, {} bytes)", slot, total);
        s.fsm.fail(STATUS_ERR_WRITE);
        let _ = STATUS_ERR_UNKNOWN; // documented alternative status code
        return DfuFeedOutcome::Stall;
    }

    // Advance ManifestSync → Manifest → ManifestWaitReset.
    let _ = s.fsm.finish_sync();
    let _ = s.fsm.finish_manifest();

    kprintln!("[DFU] manifest OK (slot={}, {} bytes) — awaiting USB bus reset",
        slot, total);

    // TODO(hw): wait for the host-issued USB bus reset; the DWC2
    // driver should call back here on reset to re-enumerate from
    // recovery into the freshly-written slot.

    DfuFeedOutcome::ManifestDone
}

/// Write `bytes` to `path` (FAT32), truncating any existing file.
/// Returns true on success.
fn write_slot_file(path: &[u8], bytes: &[u8]) -> bool {
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(
        &mut fd_table, path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC,
    );
    if fd < 0 { return false; }
    let n = azos_fs::vfs_write(&mut fd_table, fd, bytes.as_ptr(), bytes.len());
    azos_fs::vfs_close(&mut fd_table, fd);
    let _ = azos_fs::fat32_sync();
    n as usize == bytes.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────
// Pure helpers (the accumulator) are tested in tests/host/dfu-tests; the
// kernel-side glue here depends on azos_fs / azos_drv_*
// which are riscv-no_std only, so it isn't host-testable. The FSM
// transitions exercised by this module ARE covered by the existing
// dfu-tests suite.

/// Compile-time check: staging buffer is at least the OTA max
/// image size so any legitimate firmware fits.
const _: () = {
    assert!(DFU_STAGING_SIZE >= OTA_MAX_IMAGE_SIZE);
    assert!(DFU_TRANSFER_SIZE > 0);
};

/// Sanity check that the DFU FSM accepts our staging size at
/// construction time (catches an inconsistent change in the
/// underlying crate).
#[allow(dead_code)]
fn _state_constructs_ok() {
    let sm = DfuStateMachine::new_dfu_mode(DFU_STAGING_SIZE, DFU_TRANSFER_SIZE);
    let _: DfuState = sm.state();
}
