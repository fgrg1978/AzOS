#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""SLAM server daemon for AzOS -- Phase N3.

Server-side SLAM (Simultaneous Localization and Mapping) that runs on
the host machine (x86/GPU), NOT on the robot. Receives telemetry from
the robot via UDP, maintains an occupancy grid, tracks position with
GPS-corrected dead reckoning, and sends corrected poses back.

Protocols:
  Robot -> Server (UDP):  TELEM packets (attitude + sensors)
  Server -> Robot (UDP):  CMD_POSE packets (corrected pose)

Telemetry packet (TELEM):
  Header 8B: magic "TLMR" (4B) + length (u16 LE) + type (u8) + seq (u8)
  Type 0x01 ATTITUDE 28B: roll/pitch/yaw/alt_cm/lat_deg7/lon_deg7 (i32 LE)
                           + mode/armed/sats/fix (u8 each)
  Type 0x02 SENSORS 28B:  accel[3]/gyro[3]/pressure (i32 LE)
  CRC-8/MAXIM trailer (1B)

Corrected pose packet (CMD):
  Header 8B: magic "CMDS" (4B) + length (u16 LE) + type (u8) + seq (u8)
  Type 0x16 CMD_POSE 17B: lat_deg7/lon_deg7/alt_mm/yaw_cdeg (i32 LE)
                           + confidence (u8)
  CRC-8/MAXIM trailer (1B)

Usage:
  python3 slam_server.py --listen-port 5000 --robot-ip 10.0.2.15 --robot-port 5001

  In QEMU shell:
    config set slam_server_ip 10.0.2.2
    config set slam_server_port 5000
"""

import socket
import struct
import argparse
import time
import sys
import math
import threading

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

TELEM_MAGIC = b"TLMR"
CMD_MAGIC   = b"CMDS"

TELEM_HEADER_SIZE = 8   # magic(4) + length(2) + type(1) + seq(1)

TYPE_ATTITUDE = 0x01
TYPE_SENSORS  = 0x02

ATTITUDE_PAYLOAD_SIZE = 28
SENSORS_PAYLOAD_SIZE  = 28

CMD_POSE_TYPE    = 0x16
CMD_POSE_PAYLOAD = 17   # lat(4) + lon(4) + alt(4) + yaw(4) + confidence(1)

# ---------------------------------------------------------------------------
# Occupancy grid parameters
# ---------------------------------------------------------------------------

GRID_SIZE     = 100     # 100x100 cells
CELL_SIZE_CM  = 10      # 10 cm per cell -> 10m x 10m local map

# Cell values: 0 = unknown, 1-127 = increasingly free, 128-254 = increasingly
# occupied, 255 = definitely occupied.
CELL_UNKNOWN  = 0
CELL_FREE     = 1
CELL_OCCUPIED = 255

# Visualization window
VIEW_SIZE = 20  # 20x20 cells centered on robot

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

MAP_DISPLAY_INTERVAL = 2.0   # seconds between ASCII map redraws
POSE_SEND_INTERVAL   = 5.0   # seconds between pose corrections to robot

# ---------------------------------------------------------------------------
# CRC-8/MAXIM (polynomial 0x31, init 0x00)
# ---------------------------------------------------------------------------

def crc8(data: bytes) -> int:
    """Compute CRC-8/MAXIM over data."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


# ---------------------------------------------------------------------------
# Telemetry parser
# ---------------------------------------------------------------------------

def parse_telem_header(data: bytes):
    """Parse TELEM header (8 bytes). Returns (length, type, seq) or None."""
    if len(data) < TELEM_HEADER_SIZE:
        return None
    magic = data[0:4]
    if magic != TELEM_MAGIC:
        return None
    length, ptype, seq = struct.unpack_from('<HBB', data, 4)
    return (length, ptype, seq)


def parse_attitude(payload: bytes):
    """Parse ATTITUDE payload (28 bytes).

    Returns dict with roll, pitch, yaw (cdeg), alt_cm, lat_deg7, lon_deg7,
    mode, armed, sats, fix.
    """
    if len(payload) < ATTITUDE_PAYLOAD_SIZE:
        return None
    vals = struct.unpack_from('<6i4B', payload, 0)
    return {
        'roll':     vals[0],   # centidegrees
        'pitch':    vals[1],
        'yaw':      vals[2],
        'alt_cm':   vals[3],
        'lat_deg7': vals[4],   # degrees * 1e7
        'lon_deg7': vals[5],
        'mode':     vals[6],
        'armed':    vals[7],
        'sats':     vals[8],
        'fix':      vals[9],
    }


def parse_sensors(payload: bytes):
    """Parse SENSORS payload (28 bytes).

    Returns dict with accel[3] (mg), gyro[3] (mdps), pressure (Pa).
    """
    if len(payload) < SENSORS_PAYLOAD_SIZE:
        return None
    vals = struct.unpack_from('<7i', payload, 0)
    return {
        'accel': (vals[0], vals[1], vals[2]),   # milli-g
        'gyro':  (vals[3], vals[4], vals[5]),   # milli-deg/s
        'pressure': vals[6],                    # Pascals
    }


# ---------------------------------------------------------------------------
# CMD builder
# ---------------------------------------------------------------------------

def build_pose_cmd(seq: int, lat_deg7: int, lon_deg7: int,
                   alt_mm: int, yaw_cdeg: int, confidence: int) -> bytes:
    """Build a CMD_POSE packet with CRC-8 trailer."""
    payload = struct.pack('<4i B',
                          lat_deg7, lon_deg7, alt_mm, yaw_cdeg,
                          min(max(confidence, 0), 255))
    length = CMD_POSE_PAYLOAD
    header = struct.pack('<4sHBB', CMD_MAGIC, length, CMD_POSE_TYPE, seq & 0xFF)
    body = header + payload
    crc = crc8(body)
    return body + struct.pack('B', crc)


# ---------------------------------------------------------------------------
# Occupancy grid
# ---------------------------------------------------------------------------

class OccupancyGrid:
    """Simple 2D occupancy grid (no numpy dependency)."""

    def __init__(self, size: int = GRID_SIZE):
        self.size = size
        self.cells = [[CELL_UNKNOWN] * size for _ in range(size)]
        self.occupied_count = 0

    def in_bounds(self, gx: int, gy: int) -> bool:
        return 0 <= gx < self.size and 0 <= gy < self.size

    def mark_free(self, gx: int, gy: int):
        """Mark cell as free (decrease occupancy evidence)."""
        if not self.in_bounds(gx, gy):
            return
        old = self.cells[gy][gx]
        if old >= 128:
            self.occupied_count -= 1
        self.cells[gy][gx] = max(CELL_FREE, old - 20)
        if self.cells[gy][gx] >= 128 and old < 128:
            self.occupied_count += 1

    def mark_occupied(self, gx: int, gy: int):
        """Mark cell as occupied (increase occupancy evidence)."""
        if not self.in_bounds(gx, gy):
            return
        old = self.cells[gy][gx]
        was_occ = old >= 128
        self.cells[gy][gx] = min(CELL_OCCUPIED, old + 40)
        if self.cells[gy][gx] >= 128 and not was_occ:
            self.occupied_count += 1

    def clear_line(self, x0: int, y0: int, x1: int, y1: int):
        """Bresenham ray: mark cells along the line as free, endpoint as occupied."""
        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        cx, cy = x0, y0

        while True:
            if cx == x1 and cy == y1:
                self.mark_occupied(cx, cy)
                break
            self.mark_free(cx, cy)
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                cx += sx
            if e2 < dx:
                err += dx
                cy += sy

    def get_view(self, center_gx: int, center_gy: int, view_size: int = VIEW_SIZE):
        """Return a view_size x view_size window of cells centered at (center_gx, center_gy).

        Returns list of lists. Out-of-bounds cells are CELL_UNKNOWN.
        """
        half = view_size // 2
        view = []
        for dy in range(view_size):
            row = []
            for dx in range(view_size):
                gx = center_gx - half + dx
                gy = center_gy - half + dy
                if self.in_bounds(gx, gy):
                    row.append(self.cells[gy][gx])
                else:
                    row.append(CELL_UNKNOWN)
            view.append(row)
        return view


# ---------------------------------------------------------------------------
# Position tracker (dead reckoning + GPS correction)
# ---------------------------------------------------------------------------

class PositionTracker:
    """Fuse GPS and IMU for position estimation.

    Uses a simple weighted-average correction (EKF-like but without full
    matrix algebra -- suitable for a reference implementation without numpy).
    """

    # Weight for GPS vs. dead-reckoning (0.0 = pure DR, 1.0 = pure GPS)
    GPS_WEIGHT = 0.7

    def __init__(self):
        # Position in deg*1e7 (same units as protocol)
        self.lat_deg7 = 0
        self.lon_deg7 = 0
        self.alt_mm   = 0      # millimeters
        self.yaw_cdeg = 0      # centidegrees

        # Dead-reckoning accumulators
        self.dr_lat_deg7 = 0
        self.dr_lon_deg7 = 0
        self.dr_yaw_cdeg = 0

        # GPS state
        self.gps_lat_deg7 = 0
        self.gps_lon_deg7 = 0
        self.gps_fix = 0
        self.gps_sats = 0

        # IMU integration
        self.last_update_s = time.monotonic()
        self.accel = (0, 0, 0)
        self.gyro  = (0, 0, 0)

        # Confidence (0-100): higher = more certain
        self.confidence = 0

        # Grid position (cell coordinates)
        self.grid_x = GRID_SIZE // 2
        self.grid_y = GRID_SIZE // 2

        # Origin in deg7 (set on first GPS fix)
        self.origin_lat_deg7 = None
        self.origin_lon_deg7 = None

    def update_attitude(self, att: dict):
        """Integrate an ATTITUDE telemetry packet."""
        self.gps_lat_deg7 = att['lat_deg7']
        self.gps_lon_deg7 = att['lon_deg7']
        self.gps_fix  = att['fix']
        self.gps_sats = att['sats']
        self.yaw_cdeg = att['yaw']
        self.alt_mm   = att['alt_cm'] * 10

        # Set origin on first valid GPS fix
        if self.origin_lat_deg7 is None and att['fix'] >= 2 and att['sats'] >= 4:
            self.origin_lat_deg7 = att['lat_deg7']
            self.origin_lon_deg7 = att['lon_deg7']

        # GPS correction: weighted merge of GPS and dead-reckoning
        if att['fix'] >= 2 and att['sats'] >= 4:
            w = self.GPS_WEIGHT
            self.lat_deg7 = int(w * att['lat_deg7'] + (1 - w) * self.dr_lat_deg7)
            self.lon_deg7 = int(w * att['lon_deg7'] + (1 - w) * self.dr_lon_deg7)
            self.confidence = min(95, 30 + att['sats'] * 5)
        else:
            # No GPS fix: rely on dead reckoning only
            self.lat_deg7 = self.dr_lat_deg7
            self.lon_deg7 = self.dr_lon_deg7
            self.confidence = max(5, self.confidence - 5)

        # Update dead-reckoning baseline to fused position
        self.dr_lat_deg7 = self.lat_deg7
        self.dr_lon_deg7 = self.lon_deg7
        self.dr_yaw_cdeg = self.yaw_cdeg

        self._update_grid_pos()

    def update_sensors(self, sens: dict):
        """Integrate a SENSORS telemetry packet (dead reckoning step)."""
        now = time.monotonic()
        dt = now - self.last_update_s
        self.last_update_s = now

        self.accel = sens['accel']
        self.gyro  = sens['gyro']

        # Integrate gyro Z for yaw (gyro[2] is in mdps = milli-degrees/s)
        gyro_z_cdeg_s = sens['gyro'][2] / 10.0   # mdps -> cdeg/s
        self.dr_yaw_cdeg += int(gyro_z_cdeg_s * dt)
        self.dr_yaw_cdeg = self.dr_yaw_cdeg % 36000

        # Integrate forward acceleration for position
        # accel[0] is forward in mg; convert to cm/s^2 (1g = 981 cm/s^2)
        accel_fwd_cm_s2 = sens['accel'][0] * 981.0 / 1000.0
        # Displacement in cm over dt (simple v*t, assuming starting from rest
        # each integration step -- crude but workable for reference)
        disp_cm = 0.5 * accel_fwd_cm_s2 * dt * dt

        # Convert displacement to deg7 offset
        # 1 degree latitude ~ 111_000m = 11_100_000cm -> 1cm ~ 0.9e-7 deg ~ 0.9 deg7
        # We use yaw to determine direction
        yaw_rad = self.dr_yaw_cdeg * math.pi / 18000.0
        dlat = disp_cm * math.cos(yaw_rad) * 0.9   # approximate deg7 per cm
        dlon = disp_cm * math.sin(yaw_rad) * 0.9

        self.dr_lat_deg7 += int(dlat)
        self.dr_lon_deg7 += int(dlon)

        # Without GPS correction, use pure DR
        if self.gps_fix < 2:
            self.lat_deg7 = self.dr_lat_deg7
            self.lon_deg7 = self.dr_lon_deg7

        self.confidence = max(1, self.confidence - 1)
        self._update_grid_pos()

    def _update_grid_pos(self):
        """Convert current lat/lon to grid cell coordinates."""
        if self.origin_lat_deg7 is None:
            self.grid_x = GRID_SIZE // 2
            self.grid_y = GRID_SIZE // 2
            return

        # Offset from origin in deg7
        dlat = self.lat_deg7 - self.origin_lat_deg7
        dlon = self.lon_deg7 - self.origin_lon_deg7

        # 1 deg7 ~ 1.11 cm latitude (111_000m / 1e7)
        # Cell size is 10cm, so 1 cell ~ 9 deg7
        cm_per_deg7 = 1.11
        offset_x_cm = dlon * cm_per_deg7
        offset_y_cm = dlat * cm_per_deg7

        self.grid_x = GRID_SIZE // 2 + int(offset_x_cm / CELL_SIZE_CM)
        self.grid_y = GRID_SIZE // 2 - int(offset_y_cm / CELL_SIZE_CM)  # y inverted

        # Clamp to grid bounds
        self.grid_x = max(0, min(GRID_SIZE - 1, self.grid_x))
        self.grid_y = max(0, min(GRID_SIZE - 1, self.grid_y))


# ---------------------------------------------------------------------------
# SLAM daemon
# ---------------------------------------------------------------------------

class SlamServer:
    """Main SLAM server: receives telemetry, maintains map, sends corrections."""

    def __init__(self, listen_port: int, robot_ip: str, robot_port: int,
                 perception_port: int, verbose: bool = False):
        self.listen_port     = listen_port
        self.robot_ip        = robot_ip
        self.robot_port      = robot_port
        self.perception_port = perception_port
        self.verbose         = verbose

        self.grid    = OccupancyGrid()
        self.tracker = PositionTracker()

        # Statistics
        self.pkts_received    = 0
        self.attitude_count   = 0
        self.sensor_count     = 0
        self.pose_corrections = 0
        self.cmd_seq          = 0

        # Timing
        self.last_map_display = 0.0
        self.last_pose_send   = 0.0
        self.start_time       = 0.0

        # UDP sockets
        self.telem_sock      = None
        self.perception_sock = None

        self._running = True

    def start(self):
        """Bind sockets and run the main loop."""
        # Telemetry socket (receives from robot)
        self.telem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.telem_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.telem_sock.bind(('0.0.0.0', self.listen_port))
        self.telem_sock.settimeout(0.5)

        # Perception socket (receives obstacle detections)
        self.perception_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.perception_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.perception_sock.bind(('0.0.0.0', self.perception_port))
        self.perception_sock.settimeout(0.1)

        self.start_time = time.monotonic()

        self._print_banner()

        # Perception listener thread
        perc_thread = threading.Thread(target=self._perception_loop, daemon=True)
        perc_thread.start()

        # Main telemetry loop
        try:
            self._main_loop()
        except KeyboardInterrupt:
            print("\n[SLAM] Shutting down")
        finally:
            self._running = False
            self.telem_sock.close()
            self.perception_sock.close()

    def _print_banner(self):
        """Print startup banner."""
        print("=" * 60)
        print("  AzOS -- SLAM Server (Phase N3)")
        print("=" * 60)
        print(f"  Telemetry listen : 0.0.0.0:{self.listen_port}")
        print(f"  Robot endpoint   : {self.robot_ip}:{self.robot_port}")
        print(f"  Perception listen: 0.0.0.0:{self.perception_port}")
        print(f"  Grid             : {GRID_SIZE}x{GRID_SIZE} @ {CELL_SIZE_CM}cm/cell")
        print(f"  Map window       : {VIEW_SIZE}x{VIEW_SIZE}")
        print(f"  Pose interval    : {POSE_SEND_INTERVAL}s")
        print("=" * 60)
        print(f"  In QEMU shell:")
        print(f"    config set slam_server_ip 10.0.2.2")
        print(f"    config set slam_server_port {self.listen_port}")
        print("=" * 60)
        print()
        print("[SLAM] Waiting for telemetry...")
        print()

    def _main_loop(self):
        """Receive telemetry and process."""
        while self._running:
            try:
                data, addr = self.telem_sock.recvfrom(512)
            except socket.timeout:
                self._periodic_tasks()
                continue

            self.pkts_received += 1
            self._process_telem(data)
            self._periodic_tasks()

    def _process_telem(self, data: bytes):
        """Parse and process a single telemetry packet."""
        # Minimum packet: header(8) + payload(1) + crc(1)
        if len(data) < TELEM_HEADER_SIZE + 1:
            if self.verbose:
                print(f"[WARN] Packet too short: {len(data)} bytes")
            return

        hdr = parse_telem_header(data)
        if hdr is None:
            if self.verbose:
                print(f"[WARN] Bad magic: {data[0:4]!r}")
            return

        length, ptype, seq = hdr
        payload = data[TELEM_HEADER_SIZE:TELEM_HEADER_SIZE + length]
        crc_byte = data[-1] if len(data) > TELEM_HEADER_SIZE + length else None

        # Verify CRC
        if crc_byte is not None:
            computed = crc8(data[:-1])
            if computed != crc_byte:
                if self.verbose:
                    print(f"[WARN] CRC mismatch: got 0x{crc_byte:02X}, "
                          f"expected 0x{computed:02X}")
                return

        if ptype == TYPE_ATTITUDE:
            att = parse_attitude(payload)
            if att is None:
                return
            self.attitude_count += 1
            self.tracker.update_attitude(att)
            self._mark_robot_vicinity_free()

            if self.verbose:
                ts = time.strftime('%H:%M:%S')
                print(f"[{ts}] ATT seq={seq} yaw={att['yaw']}cdeg "
                      f"alt={att['alt_cm']}cm lat={att['lat_deg7']} "
                      f"lon={att['lon_deg7']} sats={att['sats']} "
                      f"fix={att['fix']}")

        elif ptype == TYPE_SENSORS:
            sens = parse_sensors(payload)
            if sens is None:
                return
            self.sensor_count += 1
            self.tracker.update_sensors(sens)

            if self.verbose:
                ts = time.strftime('%H:%M:%S')
                ax, ay, az = sens['accel']
                gx, gy, gz = sens['gyro']
                print(f"[{ts}] SNS seq={seq} accel=({ax},{ay},{az})mg "
                      f"gyro=({gx},{gy},{gz})mdps "
                      f"P={sens['pressure']}Pa")
        else:
            if self.verbose:
                print(f"[WARN] Unknown telem type: 0x{ptype:02X}")

    def _mark_robot_vicinity_free(self):
        """Mark cells near the robot as free (robot is there, so no obstacle)."""
        gx = self.tracker.grid_x
        gy = self.tracker.grid_y
        for dy in range(-1, 2):
            for dx in range(-1, 2):
                self.grid.mark_free(gx + dx, gy + dy)

    def _perception_loop(self):
        """Receive obstacle detections from the perception server.

        Expected format: simple binary packets with grid-relative obstacle
        positions. Each detection is 4 bytes: gx(u16 LE) + gy(u16 LE).
        Multiple detections can be packed in one UDP datagram.
        """
        while self._running:
            try:
                data, addr = self.perception_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            # Each detection is 4 bytes
            n_detections = len(data) // 4
            for i in range(n_detections):
                gx, gy = struct.unpack_from('<HH', data, i * 4)
                if self.grid.in_bounds(gx, gy):
                    self.grid.mark_occupied(gx, gy)
                    if self.verbose:
                        print(f"[PERC] Obstacle at grid ({gx},{gy})")

    def _periodic_tasks(self):
        """Run periodic actions: map display, pose send."""
        now = time.monotonic()

        if now - self.last_map_display >= MAP_DISPLAY_INTERVAL:
            self.last_map_display = now
            self._display_map()

        if now - self.last_pose_send >= POSE_SEND_INTERVAL:
            self.last_pose_send = now
            self._send_pose_correction()

    def _send_pose_correction(self):
        """Send corrected pose to the robot."""
        t = self.tracker
        if t.confidence < 5:
            return

        self.cmd_seq += 1
        pkt = build_pose_cmd(
            seq=self.cmd_seq,
            lat_deg7=t.lat_deg7,
            lon_deg7=t.lon_deg7,
            alt_mm=t.alt_mm,
            yaw_cdeg=t.yaw_cdeg,
            confidence=t.confidence,
        )

        try:
            self.telem_sock.sendto(pkt, (self.robot_ip, self.robot_port))
            self.pose_corrections += 1
            if self.verbose:
                print(f"[POSE] Sent correction #{self.cmd_seq}: "
                      f"lat={t.lat_deg7} lon={t.lon_deg7} "
                      f"alt={t.alt_mm}mm yaw={t.yaw_cdeg}cdeg "
                      f"conf={t.confidence}")
        except OSError as e:
            if self.verbose:
                print(f"[WARN] Failed to send pose: {e}")

    def _display_map(self):
        """Print ASCII map and statistics to terminal."""
        t = self.tracker
        uptime = time.monotonic() - self.start_time

        # Clear screen (ANSI)
        sys.stdout.write("\033[2J\033[H")

        # Header
        print("=" * 50)
        print("  AzOS SLAM -- Live Map")
        print("=" * 50)

        # Statistics
        print(f"  Uptime       : {int(uptime)}s")
        print(f"  Packets      : {self.pkts_received} "
              f"(att={self.attitude_count} sns={self.sensor_count})")
        print(f"  Pose sent    : {self.pose_corrections}")
        print(f"  Grid occupied: {self.grid.occupied_count} / "
              f"{GRID_SIZE * GRID_SIZE} cells")
        print(f"  Position     : lat={t.lat_deg7} lon={t.lon_deg7} "
              f"alt={t.alt_mm}mm")
        print(f"  Yaw          : {t.yaw_cdeg}cdeg  "
              f"Confidence: {t.confidence}%")
        print(f"  Grid cell    : ({t.grid_x}, {t.grid_y})")
        print(f"  GPS          : fix={t.gps_fix} sats={t.gps_sats}")
        print()

        # Get view window centered on robot
        view = self.grid.get_view(t.grid_x, t.grid_y, VIEW_SIZE)
        half = VIEW_SIZE // 2

        # Column header
        header = "  "
        for c in range(VIEW_SIZE):
            if c % 5 == 0:
                header += str(c).ljust(1)
            else:
                header += " "
        print(header)

        # Top border
        print("  +" + "-" * VIEW_SIZE + "+")

        for r in range(VIEW_SIZE):
            row_str = ""
            for c in range(VIEW_SIZE):
                # Robot position is at center of view
                if r == half and c == half:
                    row_str += "R"
                elif view[r][c] == CELL_UNKNOWN:
                    row_str += " "
                elif view[r][c] >= 128:
                    row_str += "X"
                elif view[r][c] >= 1:
                    row_str += "."
                else:
                    row_str += " "
            # Row label
            label = f"{r:2d}"
            print(f"{label}|{row_str}|")

        # Bottom border
        print("  +" + "-" * VIEW_SIZE + "+")

        # Legend
        print()
        print("  Legend: R=robot  X=obstacle  .=free  (space)=unknown")
        print("  Map: {0}x{0} cells, {1}cm/cell = {2}m x {2}m".format(
            GRID_SIZE, CELL_SIZE_CM, GRID_SIZE * CELL_SIZE_CM // 100))
        print()
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SLAM server daemon for AzOS (Phase N3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 slam_server.py "
               "--listen-port 5000 --robot-ip 10.0.2.15 --robot-port 5001",
    )
    parser.add_argument(
        '--listen-port', type=int, default=5000,
        help='UDP port for incoming telemetry (default: 5000)',
    )
    parser.add_argument(
        '--robot-ip', type=str, default='10.0.2.15',
        help='Robot IP address for sending pose corrections (default: 10.0.2.15)',
    )
    parser.add_argument(
        '--robot-port', type=int, default=5001,
        help='Robot UDP port for pose corrections (default: 5001)',
    )
    parser.add_argument(
        '--perception-port', type=int, default=6001,
        help='UDP port for obstacle detections from perception server (default: 6001)',
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help='Print detailed packet information',
    )

    args = parser.parse_args()

    server = SlamServer(
        listen_port=args.listen_port,
        robot_ip=args.robot_ip,
        robot_port=args.robot_port,
        perception_port=args.perception_port,
        verbose=args.verbose,
    )
    server.start()


if __name__ == '__main__':
    main()
