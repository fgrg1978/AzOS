# Forward-secret encrypted link

The link between the robot's behaviour engine (`COMPCLI.ELF`, ring 3) and
the companion (the off-board planner) is a Noise
session whose keys come from fresh ephemeral keys on every connection, and it
is the only mode the link has: no plaintext, no MAC-only mode, no runtime
switch. The engine seals each companion-protocol packet it sends as one transport
message (a message it receives may carry a run of them), and the packet layout
is unchanged. This note describes the handshake, the transport, rekeying, the
policy and the limits of the forward-secrecy claim.

## Summary

Source: `crates/core/crypto/src/secure_channel.rs`,
`crates/core/crypto/src/noise.rs`,
`kernel/src/boot/persist.rs` (the link key and the provisioning policy,
kernel side), `crates/core/syscall/src/link_key.rs` (the `linkkey` endpoint),
`userspace/services/companion_client/src/link.rs`.

Layers on the wire, outermost first:

1. **Noise transport** (`azos_crypto::secure_channel`): a Noise handshake
   (`IK` or `XX`, X25519, ChaCha20-Poly1305, SHA-256), then one transport
   message per frame.
2. **Companion packet**: unchanged.

There is one MAC: the Poly1305 tag. Replay inside a session is refused by the
transport's message counter, and a frame recorded in an earlier session fails
the AEAD under the new keys. There is no second MAC or replay floor inside
the session.

## What the session gives

Source: `crates/core/crypto/src/secure_channel.rs`.

A MAC under the long-term link key alone would give integrity and forgery
resistance, leave every payload byte readable on the wire, and tie every past
session to the long-term key: whoever later recovers the key could read all
recorded traffic. The Noise session gives:

- **Authentication** of both peers from the link key (and, under `IK`, of the
  companion from its own static key).
- **Confidentiality** of sensor streams, commands and camera frames.
- **Forward secrecy**: the transport keys depend on ephemeral X25519 keys, so
  recovering the link key later does not recover a recorded session,
  provided the ephemeral key had real entropy (see "Entropy" below).
- **Replay rejection** inside a session (the message counter) and across
  sessions (different keys).

It does not hide packet sizes or timing (no padding, no cover traffic).

## Handshake

Source: `crates/core/crypto/src/secure_channel.rs` (`Initiator`,
`SessionIdCache`), `crates/core/crypto/src/noise.rs`,
`userspace/services/companion_client/src/link.rs` (`handshake`).

The Noise roles match the TCP roles. The engine dials the companion (TCP client)
and is the Noise **initiator**; the companion is the TCP server and the
responder. A single pattern byte (`I` or `X`) precedes the first frame and is
bound into the prologue (`azos-companion-link-v2` followed by the pattern byte).
Handshake payloads are empty; every handshake frame is a 2-byte big-endian
length followed by the Noise message.

```
IK  1 robot -> companion  e, es, s, ss      2 companion -> robot  e, ee, se
XX  1 robot -> companion  e                 2 companion -> robot  e, ee, s, es
    3 robot -> companion  s, se
```

The static keys derive from the provisioned 32-byte link key with
HKDF-SHA256, one label per side (`kernel_static_key`, `companion_static_key`);
the link key is never used as a curve scalar.

- **`IK`** when the signed topology's `[peer.companion]` row pins the companion's
  static public key (`noise_pk`; the first node of the class). The companion proves in message 2 that it holds the private half, so a leaked link
  key alone cannot impersonate it. The companion checks that the robot's static
  (sent in message 1) is the one the link key derives.
- **`XX`** otherwise, with both statics the derived ones. The robot compares
  the companion's static with the derived value before it sends its own, and the
  companion makes the mirrored check after message 3, so `XX` is authenticated by
  the link key and is not trust-on-first-use.
- A failed handshake ends the connection. There is no `REJECT` frame and no
  hint about which check failed.
- The session id is derived from the handshake hash. `SessionIdCache` keeps
  recent ids in RAM and a repeat is refused. The client remembers `SESSION_IDS` (8) per run. The cache covers
  one run, not a restart.
- The handshake has a wall-clock deadline of 5 seconds for the whole
  exchange, because X25519 is slow on a small core.

## Transport

Source: `crates/core/crypto/src/secure_channel.rs` (`Link::seal_message`,
`Link::open_frame`, `frame_len`).

```
[length u16 BE][ChaCha20-Poly1305 ciphertext || 16-byte tag]
```

The length bytes are the associated data. The nonce is the cipher state's
counter, which the wire does not carry: TCP is in order, so a dropped,
repeated or reordered frame fails the AEAD and ends the session. That also
closes in-session replay.

- A message of up to 16 KiB (`MAX_MESSAGE_BYTES`) is sealed as one frame
  (preceded by a rekey frame when one is due); a message is never empty. A
  camera frame (`PKT_CAMERA`) travels this way, on the control session.
- Any violation (bad length, tag failure, overdue rekey, oversize message) is
  terminal: the link leaves `Established`, the keys are wiped and the caller
  closes the connection. The reconnect is a fresh handshake with fresh
  ephemerals.

## Rekeying

Source: `crates/core/crypto/src/secure_channel.rs` (`REKEY_MAX_RECORDS`,
`REKEY_MAX_BYTES`, `REKEY_INTERVAL_SECS`, `rekey_interval_secs`),
`userspace/services/companion_client/src/main.rs`.

A bare 16-byte tag (an empty message) is the rekey signal. After it the
sender, and the receiver on reading it, replace that direction's key with
Noise `REKEY`; the counter keeps running. Each direction rekeys independently
and without a round trip. The sender emits the signal in front of its next
message when the generation would pass any of:

| Trigger (per direction, per generation) | Value |
|---|---|
| Messages, including the closing rekey | 2^20 |
| Payload bytes | 2^30 |
| Wall clock | 3600 s |

The message and byte limits are enforced by the link on both sides; a
generation that overruns them without a rekey is a violation. The wall-clock
trigger belongs to the caller, because the module has no clock: the engine
calls `request_rekey` when its timer expires. It rekeys every `REKEY_INTERVAL_SECS`, which CONFIG.INI
`companion_client_rekey_secs` may only shorten (the gate's link rows set 5 or 10 s).
`rekey_interval_secs`, the clamp a configured request would go through
(5..3600 s, so a file on the USB-exported volume could only shorten a key's
life), has no caller outside the host tests.

## Policy and configuration

Source: `config/subsys/Kconfig.secure-boot` (`LINK_PROVISIONING_ENFORCED`),
`crates/core/topology/src/types.rs` (`Topology::companion_noise_pk`),
`crates/core/syscall/src/link_key.rs` (the link key and the pinned companion key,
read by the ring-3 client).

There is no negotiated downgrade and no runtime switch; the only choice an
operator has on each side is the handshake pattern, and both sides must agree
on it.

- **No key, no link.** With no valid link key in the reserved sector the companion
  connection is closed rather than downgraded to anything weaker, and the
  refusal is a `login` decision record (method 5, the companion link). A
  development build (`BUILD_TYPE_DEV`) goes on booting with the link down;
  every other robot build has `LINK_PROVISIONING_ENFORCED` and halts.
- **The companion's key is the topology's.** The `linkkey` endpoint's `companion_pk`
  op answers the `noise_pk` of the signed topology's `[peer.companion]` row, and
  the ring-3 link client (`companion_client`) selects `IK` with it; with no such
  row (or a row without a key) the link is `XX`. There is no Kconfig symbol
  and no file for it: a second source would be a second authority over who
  the companion is.
- **`LINK_PROVISIONING_ENFORCED`** (cargo feature `link-provisioning-enforced`, robot
  domain, fixed at compile time with no runtime override; on by default
  outside `BUILD_TYPE_DEV`, and only Kconfig turns it on): boot halts without
  a valid link key. The UART bridge carries no session and no command: on a
  robot the kernel takes only e-stop frames from it, which can only stop the
  machine.

## Entropy

Source: `userspace/services/companion_client/src/link.rs` (`handshake`),
`userspace/services/companion_client/src/main.rs` (`entropy_init`),
`crates/core/crypto/src/entropy.rs`.

`azos_crypto::secure_channel` is pure: it collects no entropy. The caller
supplies the 32-byte ephemeral private key. The ring-3 client draws it, per
connection, from the kernel entropy pool through the `entropy` endpoint.

Forward secrecy therefore depends on the platform's entropy source: a seeded
pool (for example a virtio RNG device, or a persisted seed provisioned for a
board without an entropy device). An unseeded pool answers `NOT_READY` on
every build and writes a durable safety record, so the client does not run
the link at all: there is no degraded key.

## Design choices

Source: `crates/core/crypto/src/noise.rs`,
`crates/core/crypto/src/secure_channel.rs`.

- **Noise instead of a bespoke handshake.** The handshake is a standard Noise
  pattern with a published security analysis, built from the primitives in
  `crates/core/crypto` (`x25519`, `chachapoly`, `sha256`, `hkdf`). The companion
  speaks the same patterns from its Python implementation, and the host tests
  (`tests/host/aead-link-tests`) pin the derived static keys and the `IK` and
  `XX` handshake bytes for fixed keys, the vectors the companion's test suite
  asserts too.
- **Keys derived from the link key, with an optional second factor.** The
  deployed secret stays one 32-byte key; pinning the companion's own static key in
  the signed topology adds a factor a leaked link key does not cover.
- **Security boundary in the link client.** The session sits inside the
  companion TCP connection, so it does not depend on a network-layer tunnel or on
  a transport the kernel does not provide.
- **One cipher state per direction.** Each direction has its own key, so a
  frame the peer sent cannot be reflected back at its sender.

## Limitations

Source: `crates/core/crypto/src/secure_channel.rs`,
`userspace/services/companion_client/src/link.rs`.

- No link-key rotation protocol and no provisioning protocol for the first
  key: it is written into the reserved sector by an out-of-band step.
- No traffic-analysis defence (sizes and timing are visible).
- The session-id cache lives in RAM, so duplicate detection covers one boot;
  a repeat across a reboot rests on the ephemeral key's entropy.
- X25519 is not post-quantum. The primitives live in `crates/core/crypto`, and
  a hybrid scheme would change the handshake.
- The handshake costs one extra round trip at connect time (`XX` three
  messages, `IK` two).
