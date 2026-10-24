# Update

Four mechanisms change a running system, from the largest unit to the smallest:

| Mechanism | Unit replaced | Takes effect |
|-----------|---------------|--------------|
| Whole-system update (A/B slots) | Kernel, userspace images, topology and configuration, together | Next boot, on trial |
| Delta update | The same, sent as a patch against the running bundle | As above |
| Signed livepatch | Individual non-sleeping kernel functions | At once, until reboot |
| Service swap by endpoint handover | One ring-3 server | At once |

A fifth piece, the rollback floor, makes the first three monotonic. Signed
application packages, which add programs and topology rows without replacing
the slot, are summarised under "Application packages" below. Signature
formats and keys are in [security.md](security.md); the decision records and
console lines each step writes are in [observability.md](observability.md).

The code is the `azos_ota` crate (`crates/core/ota`), the installer service
(`userspace/services/pkgd`), the livepatch (`kernel/src/boot/livepatch.rs`,
`crates/core/mm/src/livepatch_fmt.rs`) and the endpoint handover
(`crates/core/ipc/src/endpoint.rs`, `kernel/src/drv_supervisor.rs`).

## Slots, boot record and rollback

Source: `crates/core/ota/src/lib.rs`, `crates/core/ota/src/pure.rs`,
`kernel/src/boot/ota.rs`, `crates/core/recovery/src/lib.rs`.

The boot volume holds two kernel slots and one recovery slot:

| File | Meaning |
|------|---------|
| `/fat/KERN_A.BIN`, `/fat/KERN_B.BIN` | Raw kernel binaries of slots A and B; no header |
| `KERN_A.SIG`, `KERN_B.SIG` | Their `RSIG` signature sidecars ([security.md](security.md)) |
| `KERN_R.BIN`, `KERN_R.SIG` | The recovery slot R. OTA never writes it; `ota_inactive_slot_pure` never returns it. In a `SECURE_BOOT_ENFORCED` build, boot steering selects it when the running slot fails secure-boot verification and R's own signature verifies. |
| `BOOTMETA.A`, `BOOTMETA.B` | The boot record, two files |
| `BOOTMETA` | The same record as plain INI with no sequence number or CRC, rewritten after every record write for U-Boot (`tools/image/boot.cmd`, `env import -t`), which picks the slot it loads from this file |

**The boot record** (`BootMeta`) is INI text: `active_slot` (`a`, `b` or `r`),
`boot_count`, `last_good`, per-slot firmware version, image size and CRC-32,
`min_fw_version`, the authenticated firmware version of each slot, `sec_epoch_a`,
`sec_epoch_b`, `min_sec_epoch`, and a `bad_slots` mask. Each write goes to the
older of the two files with an incremented sequence number and a CRC; a read
takes the valid file with the higher sequence number. A power loss during a write
leaves the other file intact, so a record is replaced atomically. When neither
file is valid the kernel reads the plain `BOOTMETA` (`ota_read_boot_meta`), which
is not authenticated, and warns once that its floor is not to be trusted.

**Trial and confirmation.** A newly selected slot boots on trial:

- Each boot increments `boot_count`. A boot is confirmed good
  (`ota_mark_boot_good`) after `OTA_BOOT_GOOD_DELAY_S` seconds of uptime, from the
  watchdog task. Confirmation resets `boot_count`, moves `last_good` to the active
  slot and raises the anti-rollback floors to the confirmed slot's values.
- When `boot_count` exceeds `max_attempts`, `ota_boot_validate_pure` rolls the
  active slot back to `last_good`. With nothing to roll back to, the kernel enters
  safe mode. If `last_good` is recorded in `bad_slots` the rollback is refused and
  the boot enters safe mode as well. A slot is recorded there only by a
  `SECURE_BOOT_ENFORCED` build, which verifies the slots it is not running at
  boot, and only when its signature is present and fails (`Failed`); a slot with
  no sidecar, or any slot on a build without the feature, is never recorded.
- An orderly reboot or power-off before confirmation does not count toward the
  limit (`ota_void_boot_pure`), and does not confirm the boot either.
- The console's `ota rollback`, and `OTA.ELF rollback` through the `ota`
  endpoint's `OTA_OP_ROLLBACK` (needs `WRITE`), return to `last_good` at the next
  boot; they answer `-EACCES` if that slot failed
  verification.

**Kernel-only install.** `ota recv <port>` (recovery console) listens on the
given TCP port (`tools/dev/ota_send.py` sends to `OTA_DEFAULT_PORT`, 8080, by default)
and receives a 24-byte `ROTA` header (magic, header version, size, CRC-32,
firmware version, platform id, flags) followed by the raw kernel, at most
`OTA_MAX_IMAGE_SIZE_MB`. The header is never stored and is not signed: its
version is checked against `min_fw_version` only as an early, advisory refusal.
`tools/dev/ota_send.py` is the sender (to one robot, or with
`--inventory` to a fleet in health-checked stages) and `tools/sign/sign_ota.py` makes the signature
sidecar. The image is written to `KERN_<slot>.TMP` and verified
(`secure_boot_verify_staged_detailed`) before it replaces the slot: a present
signature that fails is refused on every build, an image with no usable
signature only with `SECURE_BOOT_ENFORCED`; otherwise it is installed with a
warning. Kconfig `OTA_SIG_MANDATORY` plays no part here: only the build reads it,
to refuse `SECURE_BOOT_ENFORCED=y` with it off. A build with no trusted key (an all-zero `SECURE_BOOT_PUBKEY`, the
development default) reads no sidecar, so every image is `Unverified` there. The
floor check against the signed version runs only for a verified image. A
kernel-only install zeroes the slot's epoch and withdraws any signed set of that
slot, so the slot boots the volume's root files.

**Boot-time verification.** The signature of the active slot's file on the
volume is checked before SMP bring-up and printed on every build; only
`SECURE_BOOT_ENFORCED` refuses to go on without `Verified`. The kernel checks the
file, not the image U-Boot already loaded from the slot the plain `BOOTMETA`
named. See "Secure boot and signed artefacts" in [security.md](security.md).

## Whole-system update

Source: `crates/core/ota/src/update.rs`, `crates/core/ota/src/pure.rs`,
`crates/core/ota/src/lib.rs` (`ota_update_switch`, `ota_install_boot_set`),
`userspace/services/pkgd`, `userspace/lib/packages`, `tools/sign/sign_ota.py`,
`kernel/src/boot/ota.rs`.

A kernel does not run alone. The unit of installation is the slot: one signed
manifest covers the kernel, its signature, the topology (`CAPS.TOM`,
`CAPS.SIG`, `SCHED.TOM`), the configuration (`CONFIG.INI`, optionally
`CONFIG.SIG`) and the userspace ELF images. The pieces confirm and roll back
together because they share one slot.

```text
 stage          verify the signed manifest, copy each part into the inactive
                slot's set directory (/fat/PKG/SYS_A or SYS_B), hashing as it
                copies; write the manifest LAST as the completion marker; read
                everything back and verify again
 switch         verify the set again, promote the kernel to the slot's boot
                path, write ONE BOOTMETA record naming the slot active
 boot           the slot's set directory resolves images, topology, config
 confirm/       existing trial machinery (above)
 roll back
```

1. **Stage** (`update::stage`, driven by `pkgd` for `pkg update FILE`, or for
   `pkg fetch-update`, where the installer gets the bundle itself from the
   source `/fat/PKG/SOURCE.CFG` names: HTTPS, or TFTP in a development build;
   it arrives in the installer's package buffer, so it is at most
   `PKG_MAX_KB`). The running system is never touched. A crash, a full volume or a forged part
   leaves no marker, and "no marker" is what the switch reads as "not staged".
   The installer holds no authority over the boot record: its part in an update
   is a write tree on `/fat/PKG` and `READ` on the `ota` endpoint (to learn the
   inactive slot).
2. **Switch** (`ota_update_switch`, reached through `OTA_OP_SWITCH` on the
   kernel-hosted `ota` endpoint, needs `WRITE`; `OTA.ELF switch` is the tool). The stager's verdict is not a
   trust anchor, so `update::verify_set` runs again, with the key and floors only
   the kernel holds. The set must be in the inactive slot, the active slot must
   be the last confirmed one (`TrialPending` otherwise: switching would destroy
   the way back), and `sec_epoch` and the kernel version must not be below the
   floors (`ota_update_allowed_pure`, `SwitchRefusal`). With no update key
   installed (an all-zero `SECURE_BOOT_PUBKEY`) the switch answers `NoKey`. The
   switch refuses while this boot is unconfirmed (`BootUnconfirmed`) or another
   switch runs (`Busy`).
3. **Boot** (`ota_install_boot_set`, first thing after the volume mounts). A slot
   with a signed set makes the set's files the ones the root of the volume names,
   but only when BOOTMETA records a non-zero `sec_epoch` for the slot and the
   signed marker in the directory carries that epoch. A slot that BOOTMETA says has
   a set the volume does not hold runs, but its boot is never confirmed, so it
   counts toward rollback to a slot whose set is intact.

**What the signature covers.** The configured algorithm (Ed25519) over a domain tag
(`AZOS-SYSUPDATE-V1`) and the manifest body: the algorithm id, the signature
length, the epoch, the kernel version, the
platform and, for each part, its kind, its 8.3 name, its size and its SHA-256.
Nothing but the head is interpreted before the signature verifies, and the part
names are inside the signature, so a part cannot be staged under another name.
The directory must hold the manifest and its parts and nothing else.

**Wire form** (little endian; the bundle is the manifest followed by each part's
bytes in table order, built by `tools/sign/sign_ota.py bundle`):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `AZUM` |
| 4 | 2 | Format (1) |
| 6 | 2 | Signature algorithm id (`azos_crypto::sig::SigAlg`; only the device's is read) |
| 8 | 4 | `sec_epoch` |
| 12 | 4 | Kernel `fw_version` |
| 16 | 1 | Platform id |
| 20 | 2 | Number of parts (at most `MAX_PARTS`) |
| 22 | 2 | Signature length (the algorithm's) |
| 24 | 52 each | Part: kind (1 kernel, 2 kernel signature, 3 topology, 4 config, 5 image), size, 8.3 name, SHA-256 |
| end | signature length | Signature (64 bytes for Ed25519) |

`update.rs` is dependency-free apart from `azos_crypto` and `pure.rs`, so the
ring-3 installer and the host test suite include it by path.

## Delta updates

Source: `crates/core/ota/src/pure.rs` (section "Delta updates"),
`tools/image/ota_delta.py`, `tools/dev/ota_send.py`.

A whole-system bundle can be sent as a patch against the bundle the running slot
was staged from: the slot's set directory holds exactly that bundle's bytes (the
marker is the manifest, the part files are the parts in order).

The patch is applied by reading, not writing. `DeltaSource` presents the new
bundle as a `Source`, reading the base through `SetBase`, and the stager copies it
into the inactive slot exactly as it copies a bundle that came whole. Nothing
about the atomic update changes: the signed manifest is verified before any byte
is written, every part is hashed as it is copied and read back, the marker is
written last, and the switch is one BOOTMETA record. A delta can only produce a
bundle the manifest's signature covers, or one the stager refuses, so the delta
itself is not signed.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `AZDL` |
| 4 | 2 | Format (1) |
| 6 | 2 | Flags (0) |
| 8 | 4 | Base length |
| 12 | 32 | SHA-256 of the base |
| 44 | 4 | Result length |
| 48 | 32 | SHA-256 of the result |
| 80 | | Ops, to the end: `COPY` (`01`, source offset u32, length u32) or `INSERT` (`02`, length u32, bytes). No op is empty. |

`DeltaSource::open` refuses before the stager has written a byte (`DeltaError`):
a base of the wrong length or hash, ops that do not run exactly to the result's
length or reach outside the base, or a result whose SHA-256 differs from the
head's. That last check reads the whole patch and the base once, writing nothing,
so a damaged patch is found while the inactive slot is untouched.

`tools/image/ota_delta.py` has `make`, `apply` and `info`; `make` checks its own output
by applying it. Its matcher prefers sources at or after the previous copy, since
the device reads the base as a sequential stream. `tools/dev/ota_send.py
--delta-from` produces the patch from two bundles.

## Signed livepatch

Source: `kernel/src/boot/livepatch.rs`, `crates/core/mm/src/livepatch_fmt.rs`,
`crates/core/mm/src/text_poke.rs`, `crates/core/topology/src/types.rs`
(`LivepatchSpec`), `tools/lint/check_livepatch_layout.py`, Kconfig `LIVEPATCH`.

A livepatch replaces the body of individual kernel functions in a running
kernel. It is compiled in only with Kconfig `LIVEPATCH` (which needs
`RCU_QSBR`, a patch pool and entry slots). A topology that declares
`[livepatch.NAME]` rows in a build without it has each refused at boot with a
decision record.

**Admission.** A `[livepatch.NAME]` row of the signed topology names the blob:
`isa`, `build_id` (the kernel build it is bound to), `sec_epoch` (at least 1) and
`sha256` of the blob (never all zero; two rows never name one blob for one ISA).
A blob is applied only when every check passes, in this order, and each failure is
one `Reason`:

1. The blob parses (`Format`).
2. A topology row names the SHA-256 of the whole blob for this ISA
   (`NotAdmitted`).
3. The `RSIG` signature verifies against the firmware key (the header names it by
   key id) and the payload size matches (`Signature`). For a patch, the signed `fw_version` is the payload's
   `sec_epoch`, so the epoch cannot be changed without the signature.
4. The payload's ISA matches (`Isa`).
5. The build-id equals the row's and the running kernel's (`BuildId`). With
   `LIVEPATCH` on the build-id is the SHA-256 of the linked kernel text, taken at
   boot.
6. The epoch equals the signed one and the row's and is not below the floor
   (`Epoch`).
7. For each function: it is marked non-sleeping (`NotNosleep`), it lies in the
   kernel text and is in the image's allowlist (`NotAllowed`), and it has an entry
   slot in `.azos_patch` (`NoSite`).

**The blob** (`APCH`): an `RSIG` (48 bytes and the signature: 112 for Ed25519)
followed by the signed payload: magic, version, ISA, function count, `sec_epoch`, build-id, a table of
functions (old entry address, body offset and length, flags) and relocations,
then the bodies. A body is a complete replacement function, entered with the ABI
of the one it replaces, position-independent except at its relocations. A
relocation binds a call to a kernel function whose absolute address is checked
to lie in the kernel text; references to data are not supported. Relocation
kinds are per ISA: aarch64 `CALL26`, riscv64 `auipc`+`jalr`, x86_64 PC-relative
32-bit. The function count is bounded by `LIVEPATCH_MAX_FUNCS`.

**The allowlist** (`is_patchable`) is baked into the image and holds one entry,
the demonstration function `livepatch_probe_target`. A function belongs on it
once it is `#[inline(never)]`, non-generic and never sleeps, and is not boot,
trap entry, context switch, the text writer, the QSBR hooks or the livepatch
code itself.

**Applying.**

1. The bodies are written into `.text.patch_pool` through the one text writer
   (`text_poke`), so kernel text stays read-execute. A word is written through a
   short-lived read-write alias of the frame, mapped for one write and then
   unmapped, after the text page's own entry is checked to be execute and not
   write. Every CPU's TLB is shot down for the alias afterwards. The pool only
   grows.
2. The entry of each function is redirected to its body: one `B` on aarch64; one
   `JAL` at the 4-aligned part of the entry slot on riscv64 (the body must be
   within 1 MiB); on x86_64 the five bytes at the entry go from a `nopl` to a
   `jmp rel32` in three writes (first byte `int3`, then the other four, then the
   first byte), each followed by a serialising IPI, and a CPU that fetches the
   site in between takes the breakpoint, where `bp_resume` hands it the address to
   continue at. A failure unwinds the entries already redirected, and the entries
   of an apply are claimed in the patch table before any byte is written.
3. One bounded QSBR grace (`LIVEPATCH_GRACE_MS`): when it ends no CPU is inside an
   old body. A miss is recorded as `GraceMissed` and is not undone. No CPU is
   stopped.

**There is no revert.** Nothing persists across a reboot; the signed rows are
applied again at boot from `/fat/PATCH/`, so a cold boot with the volume removed
runs the image as built. A blob larger than `LIVEPATCH_MAX_BLOB_KIB` is refused.

Every apply and refusal is a `Rule::Livepatch` decision record: the subject is
the row (or `u32::MAX` when no row named the blob) and the numbers are the first
eight bytes of the blob's SHA-256, the entry of the first function and the
`Reason` code.

## Service update by endpoint handover

Source: `kernel/src/drv_supervisor.rs` (`swap`),
`crates/core/ipc/src/endpoint.rs` (section "Live update"),
`crates/core/sched/src/supervisor.rs`, `crates/core/recovery/src/lib.rs`
(`cmd_swap`).

A supervised ring-3 server can be replaced by a new instance of its image
without draining its endpoints. Every capability, queued call and handle stays
valid, because the endpoints change server rather than being recreated: no new
generation is issued.

The request is the recovery console's `swap <image path>`
(`sup_request_swap`), served by the kernel's supervisor task. The sequence:

1. **Open.** `endpoint_swap_open(old)` lets every *named* endpoint the old server
   serves accept a `READ` grant for a successor from the signed topology without
   making it the server.
2. **Create the successor** from the same signed row (`spawn_path_hooked`), its
   endpoint grants seeded without claiming anything, and **begin the handover**
   (`endpoint_handover_begin_all`): new calls queue and wait, nothing is
   delivered. A named endpoint must have been granted to the successor
   (`HandoverError::NotGranted` otherwise); the operation is all-or-none.
3. **Quiesce.** The old server finishes the calls it has in service
   (`endpoint_handover_in_service`). Halfway through the wait
   (`SWAP_QUIESCE_MS`) the calls still in service are handed back to the queue
   for the successor (`endpoint_handover_represent_all`).
4. **Flip.** The successor's own seeded capability table is wiped, it joins the
   old server's domain (`task_adopt_domain`), so the same table and handles
   apply, and `endpoint_rebind_all(old, new)` makes the successor the server of
   every endpoint, refusing while any call is in service. The kernel-memory
   charge of the endpoints moves to the successor's domain first; the identity
   word changes, so resolve-cache entries miss on their own and a task that
   resolved the old server and calls after the flip is refused like any call to an
   endpoint that changed server, not lost. Driver-server slots are handed over
   (`driver_adopt`), and the queued calls' wake goes to the successor.
5. **Stop** the old server, which is no longer supervised.

Any step before the flip cancels: the old server serves on, its queued calls are
delivered to it, the successor is stopped (`endpoint_swap_cancel`). The successor
runs from its release but takes no calls before the flip, since the queue
delivers to no one during a handover.

Refused up front (`sup_swap_refused`): an image that is not a serving spawned
image, a driver-server task (its kind is registered by the old task; a pure IPC
server only), a missing actuation gate, and safe mode. The state
between servers is not transferred: the successor starts from its image.

## Application packages

Source: `crates/core/pkg/src`, `userspace/services/pkgd`, `userspace/services/pkg`,
`kernel/src/boot/pkg_apply.rs`, `config/subsys/Kconfig.packages`.

A package (`.azpkg`, built by `tools/image/azpkg.py`) is images plus the topology rows
they ask for, signed by a signer the signed topology names. `pkg install FILE`
(or `pkg fetch`) has `PKGD.ELF` verify and admit it and stage it as
`XXXXXXXX.PKG` on its native volume with a journal record; nothing it decides is
trusted by the kernel. At the next boot, before the topology is published,
`pkg_apply` verifies and admits every staged package again, merges its rows into
the candidate topology and writes its programs to `APPS/` after a snapshot of the
volume. That boot is a trial judged by the same attempt count as an A/B slot:
confirmed, or rolled back to the snapshot with the packages removed and a
`package-install` refusal on record. The limits are Kconfig `PKG_MAX_KB`,
`PKG_META_MAX_KB`, `PKG_MAX_IMAGES`, `PKG_MAX_STAGED`, `PKG_MAX_API` and
`PKG_SNAPSHOTS_KEPT`; `PKG_FETCH_TFTP` (development builds only) lets `pkg fetch`
use a TFTP source. The signature and admission rules are "Packages" in
[security.md](security.md); the commands are under `pkgd` in
[services.md](services.md).

## Rollback floor and its backends

Source: `crates/core/ota/src/floor.rs`, `crates/core/ota/src/pure.rs`,
`kernel/src/boot/tpm.rs`, `crates/drivers/tpm/src/tpm.rs`, Kconfig
`OTA_FLOOR_BOOTMETA`, `OTA_FLOOR_TPM_NV`.

Two floors keep updates from going backwards: `min_fw_version` (the kernel's
authenticated version) and `min_sec_epoch` (the whole system's epoch). A
manifest or blob below the floor is refused whatever its signature. A
kernel-only image is held to `min_fw_version` by its signed version only when it
verifies; an unverified one, which only a build without `SECURE_BOOT_ENFORCED`
installs, meets the advisory header check alone. The floors only advance when a
boot is confirmed, and they advance to the confirmed slot's own signed values:
the authenticated version (0 for a slot installed unverified) and the slot's
epoch (`ota_confirmed_epoch`), which BOOTMETA records and the boot accepts only
when the signed marker in the slot's set directory carries it (otherwise the
boot is never confirmed). Because the version in the kernel signature is the one signed
into the manifest, a sender cannot claim a higher version for an old image to
pin the floor.

The epoch floor lives in BOOTMETA on the FAT volume, which anything that can
write the volume can roll back. A **backend** is a second home for the same
number that the volume cannot reach. The choice is Kconfig
`OTA_FLOOR_BOOTMETA` (the volume only) or `OTA_FLOOR_TPM_NV`:

| Backend | Where the floor is held | Behaviour |
|---------|------------------------|-----------|
| `OTA_FLOOR_BOOTMETA` | The `min_sec_epoch` field of the BOOTMETA records | Whoever can write the volume can write an older record back; the signature check is then the only gate |
| `OTA_FLOOR_TPM_NV` | BOOTMETA and a 4-byte TPM NV index | The floor in force is the higher of the two |

The policy is in `floor.rs`, all of it pure:

- **Read side.** `lift(stored)` returns the higher of BOOTMETA's value and the
  backend's. The backend's value is read once, when the backend is installed, so
  reads cost nothing at run time and never wait on the hardware. Replacing or
  deleting BOOTMETA can lower the floor only down to the backend's.
- **Write side.** The floor is raised at one point only, the boot confirmation
  (`floor::commit`). The backend is asked only for a value above the one it
  holds; a failed raise is counted (`raise_failures`) and retried at the next
  confirmation, and BOOTMETA's floor holds meanwhile.
- **Only upward**, twice: `commit` never asks for a value at or below the known
  one, and the TPM driver reads before it writes (`Tpm::floor_raise`).
- **The volume never sets the hardware value.** `commit` is given the confirmed
  slot's own epoch, not BOOTMETA's `min_sec_epoch`, so a forged floor on the
  volume cannot be ratcheted into the TPM, where nothing short of clearing it
  could undo it.
- With no TPM found, or one that fails to provision or read, the backend is not
  installed and BOOTMETA's floor holds alone; the boot says so.

The NV index is an ordinary one, defined once per TPM, with a password the kernel
derives (`floor::nv_auth`); see "TPM" in [security.md](security.md) for what that
password does and does not protect against. A replay-protected eMMC partition is
the other hardware floor the choice has room for; none is implemented.
