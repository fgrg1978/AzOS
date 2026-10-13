#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Perception server for AzOS -- Phase M3.

Server-side perception daemon that runs on a host machine (x86/GPU).
Receives camera frames from the robot via UDP, runs stub object detection,
and sends obstacle detections back using the telemetry CMD protocol.

Protocol:
  Robot -> Server (UDP):
    Camera frame: "CAMF" (4B) + width (u16 LE) + height (u16 LE)
                  + frame_id (u32 LE) + width*height grayscale pixels

  Server -> Robot (UDP):
    Obstacle CMD: "CMDS" (4B) + length (u16 LE) + type=0x15 (u8)
                  + seq (u8) + payload + CRC-8

    Payload: count (u8) + per obstacle: x_mm (i32 LE) + y_mm (i32 LE)
             + radius_mm (u16 LE) + confidence (u8) = 11 bytes each

Usage:
  python3 perception_server.py --listen-port 6000 --robot-ip 10.0.2.15 --robot-port 5001
  python3 perception_server.py --listen-port 6000 --robot-ip 10.0.2.15 --robot-port 5001 --verbose

In QEMU shell:
  config set perception_server_ip 10.0.2.2
  config set perception_server_port 6000
"""

import argparse
import socket
import struct
import sys
import time

# ── Constants ──────────────────────────────────────────────────────────────────

# Incoming frame header
CAM_MAGIC = b"CAMF"
CAM_HEADER_SIZE = 12  # magic(4) + width(2) + height(2) + frame_id(4)

# Outgoing command header (matches domains/robot/telemetry/src/lib.rs)
CMD_MAGIC = b"CMDS"
CMD_HEADER_SIZE = 8   # magic(4) + length(2) + type(1) + seq(1)
CMD_CRC_SIZE = 1

CMD_OBSTACLES = 0x15

# Detection grid
GRID_ROWS = 4
GRID_COLS = 4
BRIGHTNESS_THRESHOLD = 200

# Max obstacles per packet (limited by UDP MTU headroom)
MAX_OBSTACLES = 16

# Obstacle size in bytes: x_mm(4) + y_mm(4) + radius_mm(2) + confidence(1)
OBSTACLE_BYTES = 11


# ── CRC-8/MAXIM ───────────────────────────────────────────────────────────────

def crc8(data: bytes) -> int:
    """CRC-8/MAXIM (polynomial 0x31, init 0x00).

    Matches the Rust implementation in domains/robot/telemetry/src/lib.rs.
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


# ── Frame parsing ──────────────────────────────────────────────────────────────

def parse_frame(data: bytes):
    """Parse a camera frame packet.

    Returns (width, height, frame_id, pixels) or None on error.
    Pixels is a bytes object of length width*height.
    """
    if len(data) < CAM_HEADER_SIZE:
        return None

    magic = data[0:4]
    if magic != CAM_MAGIC:
        return None

    width, height, frame_id = struct.unpack_from('<HHI', data, 4)

    expected_size = CAM_HEADER_SIZE + width * height
    if len(data) < expected_size:
        return None

    pixels = data[CAM_HEADER_SIZE:CAM_HEADER_SIZE + width * height]
    return (width, height, frame_id, pixels)


# ── Stub detection ─────────────────────────────────────────────────────────────

def detect_obstacles(width, height, pixels):
    """Stub object detection via brightness grid analysis.

    Divides the frame into a 4x4 grid, computes the average brightness
    of each cell, and reports cells with average > 200 as obstacles.

    Each obstacle is positioned in millimeters relative to the robot's
    forward-facing frame center. The grid maps to a 2000mm x 2000mm
    area in front of the robot:
      - X axis: left (-1000mm) to right (+1000mm)
      - Y axis: near (0mm) to far (+2000mm)

    Returns a list of (x_mm, y_mm, radius_mm, confidence) tuples.
    """
    obstacles = []

    cell_h = height // GRID_ROWS if height >= GRID_ROWS else 1
    cell_w = width // GRID_COLS if width >= GRID_COLS else 1

    for gr in range(GRID_ROWS):
        for gc in range(GRID_COLS):
            # Compute pixel boundaries for this grid cell
            row_start = gr * cell_h
            row_end = min(row_start + cell_h, height)
            col_start = gc * cell_w
            col_end = min(col_start + cell_w, width)

            # Sum brightness
            total = 0
            count = 0
            for r in range(row_start, row_end):
                for c in range(col_start, col_end):
                    idx = r * width + c
                    if idx < len(pixels):
                        total += pixels[idx]
                        count += 1

            if count == 0:
                continue

            avg = total / count

            if avg > BRIGHTNESS_THRESHOLD:
                # Map grid position to millimeter coordinates
                # X: column center mapped to [-1000, +1000]
                center_col = (col_start + col_end) / 2.0
                x_mm = int((center_col / width - 0.5) * 2000)

                # Y: row center mapped to [+2000, 0] (top row = far)
                center_row = (row_start + row_end) / 2.0
                y_mm = int((1.0 - center_row / height) * 2000)

                # Radius proportional to cell size
                radius_mm = int(min(cell_w, cell_h) / max(width, height) * 1000)
                radius_mm = max(radius_mm, 50)  # minimum 50mm

                # Confidence proportional to brightness above threshold
                confidence = min(int((avg - BRIGHTNESS_THRESHOLD) / 55.0 * 255), 255)
                confidence = max(confidence, 1)

                obstacles.append((x_mm, y_mm, radius_mm, confidence))

    return obstacles[:MAX_OBSTACLES]


# ── Command packet builder ────────────────────────────────────────────────────

class PacketBuilder:
    """Builds CMD packets for the telemetry protocol."""

    def __init__(self):
        self._seq = 0

    def _next_seq(self) -> int:
        s = self._seq
        self._seq = (s + 1) & 0xFF
        return s

    def build_obstacle_cmd(self, obstacles):
        """Build a CMD_OBSTACLES packet.

        Args:
            obstacles: list of (x_mm, y_mm, radius_mm, confidence) tuples.

        Returns:
            bytes: complete packet with header, payload, and CRC.
        """
        count = min(len(obstacles), MAX_OBSTACLES)

        # Payload: count(1) + obstacles * 11
        payload_len = 1 + count * OBSTACLE_BYTES

        # Build header
        seq = self._next_seq()
        header = struct.pack('<4sHBB',
                             CMD_MAGIC,
                             payload_len,
                             CMD_OBSTACLES,
                             seq)

        # Build payload
        payload = struct.pack('<B', count)
        for i in range(count):
            x_mm, y_mm, radius_mm, confidence = obstacles[i]
            payload += struct.pack('<iiHB',
                                   x_mm,
                                   y_mm,
                                   radius_mm & 0xFFFF,
                                   confidence & 0xFF)

        # CRC over header + payload
        packet_body = header + payload
        crc = crc8(packet_body)

        return packet_body + struct.pack('<B', crc)


# ── Statistics tracker ─────────────────────────────────────────────────────────

class Stats:
    """Track server performance statistics."""

    def __init__(self):
        self.frames_received = 0
        self.detections_sent = 0
        self.total_obstacles = 0
        self.start_time = time.monotonic()
        self._last_print_time = self.start_time
        self._last_print_frames = 0

    def record_frame(self):
        self.frames_received += 1

    def record_detections(self, count):
        self.detections_sent += 1
        self.total_obstacles += count

    def fps(self) -> float:
        elapsed = time.monotonic() - self.start_time
        if elapsed < 0.001:
            return 0.0
        return self.frames_received / elapsed

    def recent_fps(self) -> float:
        now = time.monotonic()
        elapsed = now - self._last_print_time
        if elapsed < 0.001:
            return 0.0
        frames_delta = self.frames_received - self._last_print_frames
        fps = frames_delta / elapsed
        self._last_print_time = now
        self._last_print_frames = self.frames_received
        return fps

    def summary(self) -> str:
        elapsed = time.monotonic() - self.start_time
        return (f"frames={self.frames_received}  "
                f"det_pkts={self.detections_sent}  "
                f"obstacles={self.total_obstacles}  "
                f"avg_fps={self.fps():.1f}  "
                f"uptime={elapsed:.0f}s")


# ── Display helpers ────────────────────────────────────────────────────────────

def print_frame_info(width, height, frame_id, obstacles, stats, verbose=False):
    """Print detection results to terminal."""
    ts = time.strftime('%H:%M:%S')
    fps = stats.recent_fps()
    n = len(obstacles)

    print(f"[{ts}] frame #{frame_id:>6d}  {width}x{height}  "
          f"obstacles={n}  fps={fps:.1f}  [{stats.summary()}]")

    if n > 0:
        for i, (x, y, r, c) in enumerate(obstacles):
            print(f"  obs[{i}]: x={x:+5d}mm  y={y:+5d}mm  "
                  f"r={r:3d}mm  conf={c:3d}/255")

    if verbose and n == 0:
        print("  (no obstacles detected)")


def print_frame_ascii(width, height, pixels):
    """Print grayscale frame as ASCII art."""
    # Downsample to max 40 cols x 20 rows for readability
    step_c = max(1, width // 40)
    step_r = max(1, height // 20)

    print(f"  Frame ({width}x{height}):")
    for r in range(0, height, step_r):
        row = "  |"
        for c in range(0, width, step_c):
            idx = r * width + c
            if idx < len(pixels):
                p = pixels[idx]
                if p > 200:
                    row += "##"
                elif p > 150:
                    row += "**"
                elif p > 100:
                    row += ".."
                elif p > 50:
                    row += "  "
                else:
                    row += "  "
            else:
                row += "??"
        row += "|"
        print(row)


# ── Main server loop ──────────────────────────────────────────────────────────

def run_server(args):
    """Main perception server loop."""
    # Create UDP socket for receiving frames
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.listen_port))

    # Set a receive timeout so we can print idle status
    sock.settimeout(5.0)

    builder = PacketBuilder()
    stats = Stats()

    robot_addr = (args.robot_ip, args.robot_port)

    print(f"[PERCEPT] Perception server started")
    print(f"[PERCEPT] Listening on UDP port {args.listen_port}")
    print(f"[PERCEPT] Sending obstacle commands to {args.robot_ip}:{args.robot_port}")
    print(f"[PERCEPT] Detection: {GRID_ROWS}x{GRID_COLS} grid, "
          f"threshold={BRIGHTNESS_THRESHOLD}")
    print(f"[PERCEPT] Waiting for camera frames...")
    print()

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                if stats.frames_received > 0:
                    print(f"[PERCEPT] Idle (no frames for 5s)  [{stats.summary()}]")
                continue

            # Parse the camera frame
            result = parse_frame(data)
            if result is None:
                ts = time.strftime('%H:%M:%S')
                print(f"[{ts}] WARN: invalid frame packet "
                      f"({len(data)} bytes from {addr})")
                continue

            width, height, frame_id, pixels = result
            stats.record_frame()

            # Run stub detection
            obstacles = detect_obstacles(width, height, pixels)

            # Print results
            print_frame_info(width, height, frame_id, obstacles, stats,
                             verbose=args.verbose)

            if args.verbose and stats.frames_received <= 3:
                print_frame_ascii(width, height, pixels)

            # Build and send obstacle command packet
            packet = builder.build_obstacle_cmd(obstacles)
            sock.sendto(packet, robot_addr)
            stats.record_detections(len(obstacles))

    except KeyboardInterrupt:
        print(f"\n[PERCEPT] Shutting down")
        print(f"[PERCEPT] Final stats: {stats.summary()}")
    finally:
        sock.close()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Perception server for AzOS (Phase M3). "
                    "Receives camera frames via UDP, runs stub object detection, "
                    "and sends obstacle data back to the robot.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --listen-port 6000 --robot-ip 10.0.2.15 --robot-port 5001
  %(prog)s --listen-port 6000 --robot-ip 10.0.2.15 --robot-port 5001 --verbose

Protocol:
  Incoming: CAMF header (12B) + grayscale pixels
  Outgoing: CMDS header (8B) + obstacle payload + CRC-8
""")

    parser.add_argument('--listen-port', type=int, default=6000,
                        help='UDP port to listen for camera frames (default: 6000)')
    parser.add_argument('--robot-ip', type=str, default='10.0.2.15',
                        help='Robot IP address for sending commands (default: 10.0.2.15)')
    parser.add_argument('--robot-port', type=int, default=5001,
                        help='Robot UDP port for commands (default: 5001)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print ASCII frame visualization and extra details')

    args = parser.parse_args()

    # Validate ports
    if not (1 <= args.listen_port <= 65535):
        print(f"Error: listen-port must be 1-65535, got {args.listen_port}",
              file=sys.stderr)
        sys.exit(1)
    if not (1 <= args.robot_port <= 65535):
        print(f"Error: robot-port must be 1-65535, got {args.robot_port}",
              file=sys.stderr)
        sys.exit(1)

    run_server(args)


if __name__ == '__main__':
    main()
