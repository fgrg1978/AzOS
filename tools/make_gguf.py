#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""
Generate build/policy.gguf — AzOS Phase C test model.

Writes a GGUF v3 file containing a 4→8→3 obstacle-avoidance policy
(same analytically-derived weights as the Phase 12/15 RMLP model)
in F32 format.  The kernel loads this file from FAT32 at boot and
runs inference via ggml_nano::gguf_mlp_infer.

GGUF v3 layout:
  [magic 4B][version u32][n_tensors u64][n_kv u64]
  KV pairs × n_kv
  Tensor infos × n_tensors
  Padding to 32-byte boundary
  Tensor data (each tensor padded to 32-byte boundary)

Tensor shapes follow ggml convention (column-major):
  w1: ne=[IN, HID]   — innermost dim = IN (columns = input features)
  b1: ne=[HID]
  w2: ne=[HID, OUT]  — innermost dim = HID
  b2: ne=[OUT]
"""

import struct, os

# ── Model dimensions ──────────────────────────────────────────────────────────
IN, HID, OUT = 4, 8, 3

# ── Analytically-derived obstacle-avoidance weights ───────────────────────────
# Same as the compile-time constants in crates/core/ml/src/lib.rs.
#
# Input:  [dist_front, dist_right, velocity, battery]  (normalised 0..1)
# Hidden: ReLU activation
# Output: [go_forward, turn_right, stop]  (raw logits, argmax for action)

W1 = [
# dist_fwd  dist_rgt   vel     batt
   1.0,      0.0,       0.0,    0.0,   # h0 = ReLU(x0 - 0.5): clearway
  -1.0,      0.0,       0.0,    0.0,   # h1 = ReLU(-x0 + 0.3): obstacle
   0.0,      1.0,       0.0,    0.0,   # h2 = ReLU(x1 - 0.2): right-clear
   0.0,     -1.0,       0.0,    0.0,   # h3 = ReLU(-x1 + 0.25): right-wall
   1.0,      0.0,       0.0,    0.0,   # h4 = ReLU(x0 - 0.3): mod. clearway
   0.0,      0.0,       0.0,    0.0,   # h5 (unused)
   0.0,      0.0,       0.0,    0.0,   # h6 (unused)
   0.0,      0.0,       0.0,    0.0,   # h7 (unused)
]
B1 = [-0.5, 0.3, -0.2, 0.25, -0.3, 0.0, 0.0, 0.0]

W2 = [
# h0    h1    h2    h3    h4    h5    h6    h7
   2.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  # go_forward = 2·h0
   0.0,  0.0,  0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  # turn_right = 3·h3
   0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  # stop       = 3·h1
]
B2 = [0.0, 0.0, 0.0]

# ── Test vectors (verified against lib.rs constants) ──────────────────────────
TESTS = [
    ([0.8, 0.3, 0.5, 0.9], "go_forward"),
    ([0.6, 0.1, 0.5, 0.9], "turn_right"),
    ([0.1, 0.5, 0.5, 0.9], "stop"),
]

# ── GGUF helpers ──────────────────────────────────────────────────────────────
GGML_TYPE_F32 = 0
ALIGN = 32

def pack_str(s: bytes) -> bytes:
    return struct.pack('<Q', len(s)) + s

def pack_kv_str(k: bytes, v: bytes) -> bytes:
    return pack_str(k) + struct.pack('<I', 8) + pack_str(v)

def pack_kv_u32(k: bytes, v: int) -> bytes:
    return pack_str(k) + struct.pack('<II', 4, v)

def pack_tensor_info(name: bytes, dims: list, ggml_type: int, offset: int) -> bytes:
    b  = pack_str(name)
    b += struct.pack('<I', len(dims))
    for d in dims: b += struct.pack('<Q', d)
    b += struct.pack('<I', ggml_type)
    b += struct.pack('<Q', offset)
    return b

def pack_f32s(data: list) -> bytes:
    return struct.pack(f'<{len(data)}f', *data)

def align_up(n: int) -> int:
    return (n + ALIGN - 1) // ALIGN * ALIGN

# ── Build KV metadata ─────────────────────────────────────────────────────────
kv  = pack_kv_str(b'general.architecture', b'robot-mlp')
kv += pack_kv_str(b'general.name',         b'obstacle-avoidance-v1')
kv += pack_kv_u32(b'robot_mlp.input_size',  IN)
kv += pack_kv_u32(b'robot_mlp.hidden_size', HID)
kv += pack_kv_u32(b'robot_mlp.output_size', OUT)
N_KV = 5

# ── Tensor payloads ───────────────────────────────────────────────────────────
# w1: shape [IN, HID] in ggml convention (dims[0]=IN, dims[1]=HID)
tensors = [
    (b'w1', [IN,  HID], GGML_TYPE_F32, pack_f32s(W1)),
    (b'b1', [HID],      GGML_TYPE_F32, pack_f32s(B1)),
    (b'w2', [HID, OUT], GGML_TYPE_F32, pack_f32s(W2)),
    (b'b2', [OUT],      GGML_TYPE_F32, pack_f32s(B2)),
]

# ── Tensor info section (with computed offsets) ───────────────────────────────
tensor_info_bytes = b''
offset = 0
for name, dims, typ, data in tensors:
    tensor_info_bytes += pack_tensor_info(name, dims, typ, offset)
    offset = align_up(offset + len(data))

# ── GGUF header + KV + tensor_info ───────────────────────────────────────────
hdr  = b'GGUF'
hdr += struct.pack('<I', 3)               # version
hdr += struct.pack('<Q', len(tensors))    # n_tensors
hdr += struct.pack('<Q', N_KV)            # n_kv
hdr_section = hdr + kv + tensor_info_bytes

# ── Padding to 32-byte boundary ───────────────────────────────────────────────
data_start  = align_up(len(hdr_section))
padding     = b'\x00' * (data_start - len(hdr_section))

# ── Tensor data region (each tensor aligned) ──────────────────────────────────
tensor_data = b''
for i, (name, dims, typ, data) in enumerate(tensors):
    tensor_data += data
    if i < len(tensors) - 1:
        tensor_data += b'\x00' * (align_up(len(data)) - len(data))

# ── Write output ──────────────────────────────────────────────────────────────
out_path = 'build/policy.gguf'
os.makedirs('build', exist_ok=True)
payload = hdr_section + padding + tensor_data
with open(out_path, 'wb') as f:
    f.write(payload)

# ── Verify test vectors (Python-side sanity check) ───────────────────────────
def relu(x): return max(0.0, x)
def dot(a, b): return sum(x*y for x,y in zip(a,b))
CLASS_NAMES = ['go_forward', 'turn_right', 'stop']

def mlp_infer(inp):
    h = [relu(dot(W1[j*IN:(j+1)*IN], inp) + B1[j]) for j in range(HID)]
    o = [dot(W2[k*HID:(k+1)*HID], h) + B2[k] for k in range(OUT)]
    return o

ok = True
for inp, expected in TESTS:
    logits = mlp_infer(inp)
    pred = CLASS_NAMES[logits.index(max(logits))]
    status = 'OK' if pred == expected else 'FAIL'
    if pred != expected: ok = False
    print(f'  [{status}] {inp} → {pred} (logits: {[f"{x:.3f}" for x in logits]})')

print()
print(f'[GGUF] Written {out_path} ({len(payload)} bytes)')
print(f'  n_kv={N_KV}, n_tensors={len(tensors)}')
print(f'  w1: {IN}×{HID} F32, w2: {HID}×{OUT} F32')
print(f'  Verification: {"PASS" if ok else "FAIL"}')
if not ok:
    raise SystemExit(1)
