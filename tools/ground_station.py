#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""
AzOS Ground Station — Phase L2

Receives UDP telemetry from the robot's telemetry_task and displays
live status in the terminal.  Can also send commands back.

Protocol (from domains/robot/telemetry/src/lib.rs):
  Header: [magic:4][length:2][type:1][seq:1]  (8 bytes)
  Payload: variable
  CRC-8: 1 byte (polynomial 0x31, MAXIM)

Telemetry types (Robot → Server, magic "TLMR"):
  0x01 ATTITUDE: roll/pitch/yaw (cdeg), alt (cm), lat/lon (deg7), mode, armed, sats, fix
  0x02 SENSORS:  accel[3] (mg), gyro[3] (mdps), pressure (Pa)

Command types (Server → Robot, magic "CMDS"):
  0x10 ARM:      1 byte (0=disarm, 1=arm)
  0x11 MODE:     1 byte (flight mode)
  0x12 TARGET:   roll(i32) + pitch(i32) + yaw_rate(i32) + throttle(u16) = 14 bytes
  0x13 WAYPOINT: lat(i32) + lon(i32) + alt(i32) + speed(u16) = 14 bytes

Usage:
  python3 tools/ground_station.py [--port 5000] [--robot-ip 10.0.2.15] [--robot-port 5001]
"""

import argparse
import socket
import struct
import sys
import time
import threading
import os

# ── Protocol constants ────────────────────────────────────────────────────────

TELEM_MAGIC = b"TLMR"
CMD_MAGIC   = b"CMDS"

TELEM_ATTITUDE = 0x01
TELEM_SENSORS  = 0x02
TELEM_STATUS   = 0x03

CMD_ARM      = 0x10
CMD_MODE     = 0x11
CMD_TARGET   = 0x12
CMD_WAYPOINT = 0x13

HEADER_SIZE = 8

FLIGHT_MODES = [
    "Disarmed", "Manual", "Stabilize", "AltHold",
    "PosHold", "Auto", "RTL", "Land",
]

# ── CRC-8/MAXIM ──────────────────────────────────────────────────────────────

def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc

# ── Packet building ──────────────────────────────────────────────────────────

_cmd_seq = 0

def build_command(pkt_type: int, payload: bytes) -> bytes:
    global _cmd_seq
    header = CMD_MAGIC + struct.pack("<HBB", len(payload), pkt_type, _cmd_seq & 0xFF)
    _cmd_seq += 1
    packet = header + payload
    return packet + bytes([crc8(packet)])

def cmd_arm(arm: bool) -> bytes:
    return build_command(CMD_ARM, bytes([1 if arm else 0]))

def cmd_mode(mode: int) -> bytes:
    return build_command(CMD_MODE, bytes([mode]))

def cmd_target(roll_cdeg: int, pitch_cdeg: int, yaw_rate_mdps: int, throttle: int) -> bytes:
    payload = struct.pack("<iiiH", roll_cdeg, pitch_cdeg, yaw_rate_mdps, throttle)
    return build_command(CMD_TARGET, payload)

def cmd_waypoint(lat_deg7: int, lon_deg7: int, alt_mm: int, speed_cms: int) -> bytes:
    payload = struct.pack("<iiiH", lat_deg7, lon_deg7, alt_mm, speed_cms)
    return build_command(CMD_WAYPOINT, payload)

# ── Telemetry state ──────────────────────────────────────────────────────────

class TelemetryState:
    def __init__(self):
        self.roll_cdeg  = 0
        self.pitch_cdeg = 0
        self.yaw_cdeg   = 0
        self.alt_cm     = 0
        self.lat_deg7   = 0
        self.lon_deg7   = 0
        self.mode       = 0
        self.armed      = False
        self.sats       = 0
        self.fix        = 0

        self.accel_mg   = [0, 0, 0]
        self.gyro_mdps  = [0, 0, 0]
        self.pressure_pa = 101325

        self.att_count  = 0
        self.sen_count  = 0
        self.last_att   = 0.0
        self.last_sen   = 0.0
        self.crc_errors = 0

    def parse_packet(self, data: bytes) -> bool:
        if len(data) < HEADER_SIZE + 1:
            return False

        magic = data[0:4]
        if magic != TELEM_MAGIC:
            return False

        length = struct.unpack_from("<H", data, 4)[0]
        pkt_type = data[6]
        # seq = data[7]

        total = HEADER_SIZE + length + 1  # +1 for CRC
        if len(data) < total:
            return False

        # Verify CRC
        expected = crc8(data[:HEADER_SIZE + length])
        actual = data[HEADER_SIZE + length]
        if expected != actual:
            self.crc_errors += 1
            return False

        payload = data[HEADER_SIZE:HEADER_SIZE + length]

        if pkt_type == TELEM_ATTITUDE and length >= 28:
            vals = struct.unpack_from("<iiiiiibbbb", payload, 0)
            # Actually: 6 i32 + 4 u8 = 28 bytes
            vals = struct.unpack_from("<iiiiii", payload, 0)
            self.roll_cdeg  = vals[0]
            self.pitch_cdeg = vals[1]
            self.yaw_cdeg   = vals[2]
            self.alt_cm     = vals[3]
            self.lat_deg7   = vals[4]
            self.lon_deg7   = vals[5]
            self.mode       = payload[24]
            self.armed      = payload[25] != 0
            self.sats       = payload[26]
            self.fix        = payload[27]
            self.att_count += 1
            self.last_att = time.time()
            return True

        elif pkt_type == TELEM_SENSORS and length >= 28:
            vals = struct.unpack_from("<iiiiiii", payload, 0)
            self.accel_mg   = list(vals[0:3])
            self.gyro_mdps  = list(vals[3:6])
            self.pressure_pa = vals[6]
            self.sen_count += 1
            self.last_sen = time.time()
            return True

        return False

# ── Display ──────────────────────────────────────────────────────────────────

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def format_cdeg(val: int) -> str:
    sign = "-" if val < 0 else ""
    a = abs(val)
    return f"{sign}{a // 100}.{a % 100:02d}"

def format_deg7(val: int) -> str:
    sign = "-" if val < 0 else ""
    a = abs(val)
    deg = a // 10_000_000
    frac = a % 10_000_000
    return f"{sign}{deg}.{frac:07d}"

def display(state: TelemetryState, port: int):
    now = time.time()
    att_age = now - state.last_att if state.last_att > 0 else -1
    sen_age = now - state.last_sen if state.last_sen > 0 else -1

    mode_name = FLIGHT_MODES[state.mode] if state.mode < len(FLIGHT_MODES) else f"?({state.mode})"

    lines = [
        "╔══════════════════════════════════════════════════════════╗",
        "║         AzOS Ground Station — Phase L2              ║",
        "╠══════════════════════════════════════════════════════════╣",
        f"║  Listening on UDP :{port:<6}                              ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  ATTITUDE                                               ║",
        f"║    Roll:  {format_cdeg(state.roll_cdeg):>10}°    Pitch: {format_cdeg(state.pitch_cdeg):>10}°  ║",
        f"║    Yaw:   {format_cdeg(state.yaw_cdeg):>10}°    Alt:   {format_cdeg(state.alt_cm):>10}m  ║",
        "║                                                         ║",
        "║  FLIGHT                                                 ║",
        f"║    Mode: {mode_name:<12}  Armed: {'YES' if state.armed else 'NO':<4}               ║",
        "║                                                         ║",
        "║  GPS                                                    ║",
        f"║    Lat: {format_deg7(state.lat_deg7):>15}°                          ║",
        f"║    Lon: {format_deg7(state.lon_deg7):>15}°                          ║",
        f"║    Fix: {state.fix}  Sats: {state.sats:<3}                                  ║",
        "║                                                         ║",
        "║  IMU                                                    ║",
        f"║    Accel: [{state.accel_mg[0]:>6}, {state.accel_mg[1]:>6}, {state.accel_mg[2]:>6}] mg       ║",
        f"║    Gyro:  [{state.gyro_mdps[0]:>6}, {state.gyro_mdps[1]:>6}, {state.gyro_mdps[2]:>6}] mdps   ║",
        f"║    Baro:  {state.pressure_pa} Pa                               ║",
        "║                                                         ║",
        "║  STATS                                                  ║",
        f"║    Attitude pkts: {state.att_count:<8}  age: {att_age:>5.1f}s              ║",
        f"║    Sensor pkts:   {state.sen_count:<8}  age: {sen_age:>5.1f}s              ║",
        f"║    CRC errors:    {state.crc_errors:<8}                          ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  Commands: arm | disarm | mode <N> | wp <lat> <lon>     ║",
        "║            target <roll> <pitch> <thr> | quit           ║",
        "╚══════════════════════════════════════════════════════════╝",
    ]
    clear_screen()
    print("\n".join(lines))

# ── Receiver thread ──────────────────────────────────────────────────────────

def receiver_thread(sock: socket.socket, state: TelemetryState, port: int):
    last_display = 0.0
    while True:
        try:
            data, addr = sock.recvfrom(256)
            state.parse_packet(data)

            # Refresh display at ~4 Hz
            now = time.time()
            if now - last_display > 0.25:
                last_display = now
                try:
                    display(state, port)
                except Exception:
                    pass
        except socket.timeout:
            continue
        except OSError:
            break

# ── Command handler ──────────────────────────────────────────────────────────

def command_loop(sock: socket.socket, robot_ip: str, robot_port: int):
    while True:
        try:
            line = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        try:
            if cmd == "arm":
                pkt = cmd_arm(True)
                sock.sendto(pkt, (robot_ip, robot_port))
                print(f"[CMD] ARM sent to {robot_ip}:{robot_port}")

            elif cmd == "disarm":
                pkt = cmd_arm(False)
                sock.sendto(pkt, (robot_ip, robot_port))
                print(f"[CMD] DISARM sent to {robot_ip}:{robot_port}")

            elif cmd == "mode" and len(parts) >= 2:
                mode = int(parts[1])
                pkt = cmd_mode(mode)
                sock.sendto(pkt, (robot_ip, robot_port))
                name = FLIGHT_MODES[mode] if mode < len(FLIGHT_MODES) else "?"
                print(f"[CMD] MODE {mode} ({name}) sent")

            elif cmd == "target" and len(parts) >= 4:
                roll = int(parts[1])
                pitch = int(parts[2])
                throttle = int(parts[3])
                pkt = cmd_target(roll, pitch, 0, throttle)
                sock.sendto(pkt, (robot_ip, robot_port))
                print(f"[CMD] TARGET roll={roll} pitch={pitch} thr={throttle} sent")

            elif cmd == "wp" and len(parts) >= 3:
                lat = int(float(parts[1]) * 1e7)
                lon = int(float(parts[2]) * 1e7)
                alt = int(float(parts[3]) * 1000) if len(parts) >= 4 else 50000
                speed = int(parts[4]) if len(parts) >= 5 else 200
                pkt = cmd_waypoint(lat, lon, alt, speed)
                sock.sendto(pkt, (robot_ip, robot_port))
                print(f"[CMD] WAYPOINT lat={lat} lon={lon} alt={alt}mm speed={speed}cm/s sent")

            elif cmd in ("quit", "exit", "q"):
                print("Exiting.")
                break

            elif cmd == "help":
                print("Commands:")
                print("  arm              - arm motors")
                print("  disarm           - disarm motors")
                print("  mode <0-7>       - set flight mode")
                print("  target <r> <p> <thr> - attitude target (cdeg, cdeg, 0-1000)")
                print("  wp <lat> <lon> [alt_m] [speed_cms] - upload waypoint")
                print("  quit             - exit ground station")

            else:
                print(f"Unknown command: {cmd} (type 'help')")

        except (ValueError, IndexError) as e:
            print(f"Error: {e}")

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AzOS Ground Station (Phase L2)")
    parser.add_argument("--port", type=int, default=5000,
                        help="UDP port to listen on (default: 5000)")
    parser.add_argument("--robot-ip", type=str, default="10.0.2.15",
                        help="Robot IP for sending commands (default: 10.0.2.15)")
    parser.add_argument("--robot-port", type=int, default=5001,
                        help="Robot UDP port for commands (default: 5001)")
    args = parser.parse_args()

    print(f"AzOS Ground Station — Phase L2")
    print(f"Listening on UDP :{args.port}")
    print(f"Commands → {args.robot_ip}:{args.robot_port}")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(1.0)

    state = TelemetryState()

    # Start receiver in background
    rx = threading.Thread(target=receiver_thread, args=(sock, state, args.port), daemon=True)
    rx.start()

    # Command loop in foreground
    command_loop(sock, args.robot_ip, args.robot_port)

    sock.close()

if __name__ == "__main__":
    main()
