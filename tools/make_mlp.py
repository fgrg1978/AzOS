#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Generate build/mlp.rmlp — Robot MLP Binary weight file.

RMLP format (292 bytes total):

  Offset  Size  Field
  ------  ----  -----
       0     4  magic: b"RMLP"
       4     4  version: u32le = 1
       8     4  in_sz:  u32le = 4   (input features)
      12     4  hid_sz: u32le = 8   (hidden neurons)
      16     4  out_sz: u32le = 3   (output classes)
      20     4  reserved: u32le = 0
      24   128  W1: [f32le; 32]   row-major [HID × IN]
     152    32  B1: [f32le; 8]
     184    96  W2: [f32le; 24]   row-major [OUT × HID]
     280    12  B2: [f32le; 3]
     ---   ---
     292  total

Weights are the analytically-designed 4→8→3 MLP for the AzOS pipeline:
  Input:  [dist_front, dist_right, velocity, battery]
  Hidden: 8 ReLU neurons (interpretable feature detectors)
  Output: [go_forward, turn_right, stop] raw logits

Verified predictions:
  [0.8, 0.3, *, *] → logits [0.600, 0.000, 0.000] → go_forward
  [0.6, 0.1, *, *] → logits [0.200, 0.450, 0.000] → turn_right
  [0.1, 0.5, *, *] → logits [0.000, 0.000, 0.594] → stop
"""

import struct
import os
import sys

# ── Network dimensions ──────────────────────────────────────────────────────
IN  = 4
HID = 8
OUT = 3

# ── Layer 1 weight matrix [HID × IN] ────────────────────────────────────────
# Row j: weights for hidden neuron j (applied to input vector).
#   h0 = ReLU(dist_front − 0.5)    clearway detector
#   h1 = ReLU(−dist_front + 0.3)   obstacle detector
#   h2 = ReLU(dist_right − 0.2)    right-clear (aux)
#   h3 = ReLU(−dist_right + 0.25)  right-wall detector
#   h4 = ReLU(dist_front − 0.3)    moderate clearway (aux)
#   h5-h7: zero (unused)
W1 = [
#   dist_fwd  dist_rgt  vel   batt
     1.0,     0.0,     0.0,  0.0,   # h0
    -1.0,     0.0,     0.0,  0.0,   # h1
     0.0,     1.0,     0.0,  0.0,   # h2
     0.0,    -1.0,     0.0,  0.0,   # h3
     1.0,     0.0,     0.0,  0.0,   # h4
     0.0,     0.0,     0.0,  0.0,   # h5 (unused)
     0.0,     0.0,     0.0,  0.0,   # h6 (unused)
     0.0,     0.0,     0.0,  0.0,   # h7 (unused)
]
assert len(W1) == HID * IN

# ── Layer 1 bias [HID] ───────────────────────────────────────────────────────
B1 = [-0.5, 0.3, -0.2, 0.25, -0.3, 0.0, 0.0, 0.0]
assert len(B1) == HID

# ── Layer 2 weight matrix [OUT × HID] ───────────────────────────────────────
#   go_forward  = 2·h0
#   turn_right  = 3·h3
#   stop        = 3·h1
W2 = [
#   h0    h1    h2    h3    h4    h5    h6    h7
    2.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  # go_forward
    0.0,  0.0,  0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  # turn_right
    0.0,  3.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  # stop
]
assert len(W2) == OUT * HID

# ── Layer 2 bias [OUT] ───────────────────────────────────────────────────────
B2 = [0.0, 0.0, 0.0]
assert len(B2) == OUT


def verify_inference(w1, b1, w2, b2):
    """Verify the weights produce correct predictions for the 3 scenarios."""
    def relu(x):
        return max(0.0, x)

    def infer(inp):
        h = [relu(sum(w1[j*IN+k]*inp[k] for k in range(IN)) + b1[j]) for j in range(HID)]
        out = [sum(w2[i*HID+j]*h[j] for j in range(HID)) + b2[i] for i in range(OUT)]
        return out

    scenarios = [
        ([0.8, 0.3, 0.5, 0.9], 0, "go_forward"),
        ([0.6, 0.1, 0.5, 0.8], 1, "turn_right"),
        ([0.1, 0.5, 0.3, 0.7], 2, "stop"),
    ]

    ok = True
    for inp, expected_class, name in scenarios:
        logits = infer(inp)
        predicted = logits.index(max(logits))
        status = "✓" if predicted == expected_class else "✗"
        print(f"  {status} [{inp[0]:.1f},{inp[1]:.1f},...] → logits "
              f"[{logits[0]:.3f},{logits[1]:.3f},{logits[2]:.3f}]"
              f" → {name}", file=sys.stderr)
        if predicted != expected_class:
            ok = False
    return ok


def main():
    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "build", "mlp.rmlp"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    print("[ML] Verifying weights:", file=sys.stderr)
    if not verify_inference(W1, B1, W2, B2):
        print("[ML] ERROR: weight verification failed!", file=sys.stderr)
        sys.exit(1)

    with open(out_path, "wb") as f:
        # Header (24 bytes)
        f.write(b"RMLP")                       # magic
        f.write(struct.pack("<I", 1))           # version
        f.write(struct.pack("<I", IN))          # in_sz
        f.write(struct.pack("<I", HID))         # hid_sz
        f.write(struct.pack("<I", OUT))         # out_sz
        f.write(struct.pack("<I", 0))           # reserved
        # Weight data (268 bytes)
        f.write(struct.pack(f"<{HID*IN}f", *W1))
        f.write(struct.pack(f"<{HID}f",    *B1))
        f.write(struct.pack(f"<{OUT*HID}f",*W2))
        f.write(struct.pack(f"<{OUT}f",    *B2))

    size = os.path.getsize(out_path)
    print(f"[ML] Generated {out_path} ({size} bytes)", file=sys.stderr)
    assert size == 292, f"Expected 292 bytes, got {size}"


if __name__ == "__main__":
    main()
