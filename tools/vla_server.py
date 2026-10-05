#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""VLA reference server for AzOS -- Phase G1.

Protocol:
  Robot -> Server: VlaObservation (100B): RVLA + frame + sensors
  Server -> Robot: VlaAction (32B):       VACT + cmd + actions[12]
  Server -> Robot: VlaGoal (68B):         VGOL + goal_id + text

Usage:
  python3 vla_server.py [--port 9000] [--verbose] [--dummy]

In another terminal (QEMU):
  config set behavior_server_ip 10.0.2.2
  config set behavior_server_port 9000
"""

import socket
import struct
import argparse
import time
import sys
import threading

# Magic constants (must match domains/robot/behavior/src/remote.rs)
OBS_MAGIC  = b"RVLA"
ACT_MAGIC  = b"VACT"
GOAL_MAGIC = b"VGOL"

OBS_SIZE  = 100
ACT_SIZE  = 32
GOAL_SIZE = 68

# VlaAction cmd constants
CMD_NONE      = 0
CMD_MOTOR     = 1
CMD_STOP      = 2
CMD_POSE      = 3
CMD_HEARTBEAT = 255


def parse_observation(data):
    """Parse a VlaObservation packet (100 bytes)."""
    if len(data) < OBS_SIZE:
        return None
    magic = data[0:4]
    if magic != OBS_MAGIC:
        return None

    ver, w, h, _pad = struct.unpack_from('<HHHH', data, 4)
    if ver != 1:
        return None

    n_pixels = w * h
    pixels = data[12:12 + min(n_pixels, 32)]

    o = 44  # sensor data offset
    accel  = struct.unpack_from('<3i', data, o)
    gyro   = struct.unpack_from('<3i', data, o + 12)
    odom_dist, odom_hdg = struct.unpack_from('<qq', data, o + 24)
    enc_l, enc_r = struct.unpack_from('<ii', data, o + 40)
    vel, batt, _reserved = struct.unpack_from('<iHH', data, o + 48)

    return {
        'w': w, 'h': h, 'pixels': pixels,
        'accel': accel, 'gyro': gyro,
        'odom': (odom_dist, odom_hdg),
        'enc': (enc_l, enc_r),
        'vel': vel, 'battery': batt,
    }


def make_action(cmd, speed_l=0, speed_r=0):
    """Build a VlaAction packet (32 bytes)."""
    # 12 i16 actions (only first 2 used for motor)
    actions = [speed_l, speed_r, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    n_actions = 2 if cmd == CMD_MOTOR else 0
    return struct.pack('<4sBBH12h', ACT_MAGIC, cmd, n_actions, 0, *actions)


def make_goal(goal_id, text):
    """Build a VlaGoal packet (68 bytes)."""
    text_bytes = text.encode('utf-8')[:56]
    padded = text_bytes.ljust(56, b'\x00')
    return struct.pack('<4sII56s', GOAL_MAGIC, goal_id, len(text_bytes), padded)


def decide(obs):
    """Simple reactive policy -- replace with LLM/VLA model.

    Returns (cmd, speed_l, speed_r) in milli-units (-1000..+1000).
    """
    pixels = obs['pixels']
    w, h = obs['w'], obs['h']

    # Compute mean of center pixels (dist_front proxy)
    # Center region: rows 1-2, cols 2-5 (8 pixels)
    center = []
    for r in range(1, min(3, h)):
        for c in range(2, min(6, w)):
            idx = r * w + c
            if idx < len(pixels):
                center.append(pixels[idx])

    mean_front = sum(center) / len(center) if center else 128

    if mean_front < 50:
        return (CMD_STOP, 0, 0)        # obstacle -> stop
    if mean_front < 160:
        return (CMD_MOTOR, 800, 300)    # partial -> turn right
    return (CMD_MOTOR, 700, 700)        # clear -> forward


def print_obs(obs, verbose=False):
    """Print observation summary."""
    w, h = obs['w'], obs['h']
    ax, ay, az = obs['accel']
    gx, gy, gz = obs['gyro']
    d, hdg = obs['odom']
    el, er = obs['enc']

    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] OBS {w}x{h} accel=({ax},{ay},{az})mg "
          f"gyro=({gx},{gy},{gz})mdps odom=({d}mm,{hdg}cdeg) "
          f"enc=({el},{er}) bat={obs['battery']}mV")

    if verbose:
        # Print frame as ASCII art
        pixels = obs['pixels']
        print(f"  Frame ({w}x{h}):")
        for r in range(h):
            row = ""
            for c in range(w):
                idx = r * w + c
                if idx < len(pixels):
                    p = pixels[idx]
                    if p > 200:   row += "##"
                    elif p > 100: row += ".."
                    else:         row += "  "
                else:
                    row += "??"
            print(f"  |{row}|")
        # Hex dump
        print(f"  Hex: {obs['pixels'][:32].hex()}")


def handle_client(conn, addr, args):
    """Handle a single robot connection."""
    print(f"[CONN] Robot connected from {addr}")
    goal_id = 0

    try:
        while True:
            # Receive observation
            data = b""
            while len(data) < OBS_SIZE:
                chunk = conn.recv(OBS_SIZE - len(data))
                if not chunk:
                    print(f"[CONN] Robot disconnected")
                    return
                data += chunk

            obs = parse_observation(data)
            if obs is None:
                print(f"[WARN] Invalid observation packet")
                continue

            print_obs(obs, verbose=args.verbose)

            # Decide action
            if args.dummy:
                cmd, sl, sr = CMD_MOTOR, 700, 700
            else:
                cmd, sl, sr = decide(obs)

            action = make_action(cmd, sl, sr)
            conn.sendall(action)

            cmd_name = {CMD_NONE: "NONE", CMD_MOTOR: "MOTOR",
                        CMD_STOP: "STOP", CMD_POSE: "POSE"}.get(cmd, "?")
            print(f"  -> ACT cmd={cmd_name} L={sl} R={sr}")

    except (ConnectionResetError, BrokenPipeError):
        print(f"[CONN] Connection lost")
    finally:
        conn.close()


def goal_sender(conn):
    """Interactive thread: type goals to send to the robot."""
    goal_id = 0
    print("\n[GOAL] Type a goal and press Enter to send it to the robot.")
    print("[GOAL] Examples: 'go to the kitchen', 'pick up the red cube'\n")
    try:
        while True:
            text = input("goal> ").strip()
            if not text:
                continue
            goal_id += 1
            packet = make_goal(goal_id, text)
            conn.sendall(packet)
            print(f"  -> GOAL #{goal_id}: {text}")
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    parser = argparse.ArgumentParser(description="VLA reference server for AzOS")
    parser.add_argument('--port', type=int, default=9000, help='TCP port (default 9000)')
    parser.add_argument('--verbose', action='store_true', help='Print hex dump of packets')
    parser.add_argument('--dummy', action='store_true', help='Always respond forward (no policy)')
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.port))
    sock.listen(1)

    print(f"[VLA] Listening on port {args.port}")
    print(f"[VLA] Waiting for robot connection...")
    print(f"[VLA] In QEMU shell:")
    print(f"[VLA]   config set behavior_server_ip 10.0.2.2")
    print(f"[VLA]   config set behavior_server_port {args.port}")
    print()

    try:
        while True:
            conn, addr = sock.accept()
            # Start goal sender thread for interactive use
            gt = threading.Thread(target=goal_sender, args=(conn,), daemon=True)
            gt.start()
            handle_client(conn, addr, args)
    except KeyboardInterrupt:
        print("\n[VLA] Shutting down")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
