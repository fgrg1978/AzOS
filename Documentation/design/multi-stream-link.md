# Multi-stream brain link

The link between the kernel and the brain (the off-board planner) is one TCP
connection. A small stream-id and length header in front of each frame lets
logically separate streams share that connection. This note records what the
framing is, how it composes with the other link layers, what uses it, and the compile-time scheduling option for bulk versus control traffic.

## Summary

Source: `crates/net/multi-stream/src/lib.rs`, `crates/core/config/src/lib.rs`
(`CFG_MULTI_STREAM`), `kernel/src/tasks/brain_link.rs` (`frame_wire`).

- The framing is the outermost wire layer of the brain link. It composes
  outside the encrypted records (see `forward-secret-link.md`), which in turn
  carry the brain packet.
- It is off by default. The CONFIG.INI key `multi_stream=1` turns it on
  (`CFG_MULTI_STREAM`); both ends must agree.
- With it on, every sealed message the kernel sends is wrapped in one frame on
  `STREAM_CONTROL`. On receive, the kernel strips the header and keeps only
  `STREAM_CONTROL` payloads for the brain-packet path; frames on any other
  stream id are ignored.

## Wire format

Source: `crates/net/multi-stream/src/lib.rs` (`wrap`, `unwrap`,
`HEADER_LEN`, `MAX_PAYLOAD_LEN`).

```
+-----------+---------------+-----------------+
| STREAM_ID | LEN           | PAYLOAD         |
| 1 byte    | 2 bytes, LE   | LEN bytes       |
+-----------+---------------+-----------------+
```

- `LEN` is an unsigned 16-bit length, so a payload is at most
  `MAX_PAYLOAD_LEN` = 65535 bytes. Overhead is `HEADER_LEN` = 3 bytes per frame.
- `wrap(stream_id, payload, out)` returns the bytes written, or
  `WrapError::PayloadTooLarge` / `WrapError::OutputTooSmall`.
- `unwrap(frame)` returns `(stream_id, payload_len, payload)`, or `None` for a
  frame shorter than the header or one whose `LEN` claims more bytes than the
  frame holds (a truncated or length-extended frame).
- `StreamDemux` is the receive side: it walks frames across socket reads
  (TCP cuts and coalesces them) and hands each payload piece to the caller
  tagged with its stream id, so a frame of an ignored stream costs no copy.
  The kernel's brain receive path (`BrainRxStream::feed_wire`) uses it.

Stream ids:

| Value | Constant | Use |
|---|---|---|
| `0x00` | `STREAM_CONTROL` | the brain protocol: sensors, actuators, status |
| `0x10..=0x1F` | `STREAM_CAMERA_BASE`..`STREAM_CAMERA_LAST` | up to 16 camera streams (`camera_stream_id(n)`, `is_camera_stream`) |
| `0x20` | `STREAM_LIDAR` | point cloud, reserved |
| `0x21` | `STREAM_AUDIO` | audio, reserved |
| other | | reserved |

## Why one multiplexed connection

Source: `crates/net/multi-stream/src/lib.rs`.

The alternatives are one TCP connection per stream, and a datagram transport
with custom reliability.

- Separate connections isolate streams completely, but multiply socket state,
  address-translation entries and reconnection coordination per robot, and give
  up the single handshake and single encrypted session of the link.
- A datagram transport with its own reliability re-implements TCP in a
  constrained kernel.
- One multiplexed stream keeps one connection and one session, and the brain
  routes by a stream-id prefix instead of by port. Its cost is head-of-line
  blocking: bytes of a large frame already handed to the socket delay any
  frame queued behind them.

A transport with independent streams would remove that cost. The brain link is
a TCP connection (`crates/net/net`), so it keeps the cost and bounds it with the
mechanisms below.

## Where the traffic goes

Source: `kernel/src/tasks/brain_link.rs` (`enqueue_framed`, `frame_wire`,
`tx_drain`), `kernel/src/tasks/behavior.rs`, `kernel/src/tasks/camera.rs`,
`kernel/src/tasks/cam_capture.rs`, `domains/robot/behavior/src/brain_tx.rs`.

The data path of a robot frame is:

```
sensor / status packet -> sealed record (encrypted session)
    -> frame_wire: one STREAM_CONTROL frame per sealed message (when on)
    -> brain-tx queue (two lanes) -> TCP socket -> brain
```

- **One sealed message, one frame.** `frame_wire` wraps each sealed message in a
  single `STREAM_CONTROL` frame, which is the unit the brain's control reader
  opens. With the framing off the bytes go out unchanged.
- **No encoder stage in the stream path.** Camera frames are captured and
  JPEG-encoded once by the capture task into a lock-free frame ring
  (`crates/drivers/cam-ring`, `FanoutRing`); with a USB camera (`USB_UVC`)
  the class driver writes the camera's frames into the same ring, and a raw
  YUY2 frame is converted to JPEG when the sender reads it. The capture task
  never waits for the sender; by default (`CAMERA_RING_OVERWRITE_OLDEST`) a slow sender loses
  only frames it would have skipped, and takes the newest frame it has not
  taken. The sender packs the JPEG into a `PKT_CAMERA` brain packet and sends
  it through the same sealing path as every other packet.
- **Camera frames travel as control-stream frames.** They either share the
  control connection (telemetry lane) or use a connection of their own when
  `behavior_camera_port` is set, with its own handshake and session
  (`camera_tx_task`). The camera stream ids are defined in the framing crate but
  the production sender does not put camera frames on them.
- **Control is protected by a transmit queue, not by chunking.** The behavior
  task seals a message into the `brain-tx` queue and returns; the `brain-tx`
  task puts it on the socket and waits for the TCP window there, not in the
  control loop. The queue has two lanes. `Control` (status, `REJECT`) may use the
  whole queue; `Telemetry` (sensor and camera frames) is admitted only while
  `BRAIN_TX_CONTROL_RESERVE_BYTES` stay free, and a refused telemetry frame is
  dropped before it is sealed and counted. This matters because a sealed record
  cannot be dropped or reordered once its counter is spent. Sizes are
  `BRAIN_TX_QUEUE_BYTES` and `BRAIN_TX_PRIORITY` in `config/domains/Kconfig.brain`.

## No scheduling policy between streams

The sender puts every frame on `STREAM_CONTROL` in the order it was sealed and
does not chunk or interleave; control is protected by the transmit-queue lanes
above. A compile-time "priority" policy (bulk cut into chunks with control
between them) was measured at a hold-off ratio of 8.4 to 8.6 times against a
target of 10, its chunked sender was never built, and its Kconfig switch was
removed.

## Limitations

Source: `crates/net/multi-stream/src/lib.rs`, `kernel/src/tasks/behavior.rs`,
`kernel/src/tasks/brain_link.rs`.

- Head-of-line blocking on one TCP connection remains for bytes already handed
  to the socket; the lanes bound what is queued, not what is in flight.
- The framing carries no version or capability negotiation. A mismatch between
  the two ends (one framing, the other not) corrupts the stream, so the setting
  must match on both.
- Camera, lidar and audio stream ids are allocated but unused by the
  production sender; only `STREAM_CONTROL` is demultiplexed on receive.
- A header is not authenticated on its own; it travels outside the encrypted
  records, so the receive path must treat an unexpected stream id or length as
  hostile input (`unwrap` returns `None` rather than reading past the frame).
