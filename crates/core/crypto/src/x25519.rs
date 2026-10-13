// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! X25519 Diffie-Hellman key exchange (RFC 7748).
//!
//! Pure software, no_std. Implements scalar multiplication on Curve25519
//! for key agreement. Uses the Montgomery ladder algorithm.
//!
//! Usage:
//!   1. Each side generates a random 32-byte private key
//!   2. Each side computes public key: `x25519(private, BASEPOINT)`
//!   3. Each side computes shared secret: `x25519(my_private, their_public)`
//!   4. Both arrive at the same 32-byte shared secret

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Curve25519 base point (u-coordinate = 9).
pub const BASEPOINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

/// Field prime: p = 2^255 - 19. Only the `legacy-x25519` field-element math
/// below uses this directly; `x25519`/`x25519_checked` go through
/// `curve25519-dalek`.
#[cfg(feature = "legacy-x25519")]
const P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute X25519 scalar multiplication: `result = scalar * point`.
///
/// - `scalar`: 32-byte private key (clamped internally per RFC 7748).
/// - `point`:  32-byte public key (or BASEPOINT for key generation).
///
/// Returns the 32-byte shared secret (or public key).
///
/// Backed by `curve25519-dalek::MontgomeryPoint::mul_clamped` — vetted,
/// constant-time, all RFC 7748 vectors pass (task #212). The legacy
/// in-tree Montgomery ladder below (decode_u_coordinate + fe_* +
/// Fermat invert) is kept as `x25519_legacy` for A/B regression
/// reference; new code must call `x25519`.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::MontgomeryPoint;
    let p = MontgomeryPoint(*point);
    p.mul_clamped(*scalar).0
}

/// Contributory-behaviour X25519: like [`x25519`], but returns `None` when
/// the shared secret is all zeros.
///
/// RFC 7748 §6.1 makes this check optional and says protocols "MAY" perform
/// it; for us it is mandatory, because of *where* the multiplication
/// happens. `EncryptLink::handle_initiator_hello` derives the shared secret
/// from a peer public key that has not been authenticated yet — the PSK
/// proof is only checked afterwards. A peer who sends one of the twelve
/// small-order Curve25519 points (all-zero, `u=1`, the two order-8 points,
/// and their `p`-offset aliases) forces the product to the identity, so
/// *both* sides derive session keys from a shared secret of 32 zero bytes,
/// independent of either private key.
///
/// That is not exploitable today: the channel only reaches `Established`
/// after CONFIRM verifies against the PSK, and both `encrypt` and `decrypt`
/// refuse to run before then, so an attacker without the PSK never gets a
/// frame encrypted under the degenerate key. The reason to check anyway is
/// that this safety rests entirely on the *ordering* of two operations in a
/// different crate. Any refactor that derives keys before verifying the
/// proof — or that adds a code path emitting a frame from `AwaitConfirm` —
/// silently converts a fragile-but-correct handshake into a key exchange an
/// unauthenticated peer can pin to a known value. Rejecting the all-zero
/// output makes the failure structural rather than ordering-dependent.
///
/// The all-zero output test catches *every* small-order input, which is why
/// it is preferred over blacklisting the twelve point encodings: the
/// blacklist has to be complete and stay complete, this does not.
pub fn x25519_checked(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519(scalar, point);
    // Constant-time all-zero test: fold every byte into one accumulator so
    // the check itself does not leak which byte was non-zero. (A timing
    // leak here would be mild, but the primitive is already available and
    // an early-exit loop over a shared secret is exactly the pattern this
    // tree is trying to stop copying around.)
    let mut acc = 0u8;
    for b in shared.iter() {
        acc |= *b;
    }
    if core::hint::black_box(acc) == 0 {
        return None;
    }
    Some(shared)
}

/// Hand-rolled X25519 — kept for A/B regression vs the dalek reference.
/// DO NOT call from new code; use [`x25519`].
///
/// Gated behind the `legacy-x25519` cargo feature (default OFF) — until
/// 2026-09-26 this was `pub fn` unconditionally, exported and callable from
/// every build despite the crate's own `Cargo.toml` claiming a feature gate,
/// and not constant-time (found during the OTA/crypto audit, unit 09 §4).
#[cfg(feature = "legacy-x25519")]
#[allow(dead_code)]
pub fn x25519_legacy(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar per RFC 7748 §5
    let mut k = *scalar;
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    // Decode u-coordinate of point
    let u = decode_u_coordinate(point);

    // Montgomery ladder
    let x_1 = u;
    let mut x_2 = fe_one();
    let mut z_2 = fe_zero();
    let mut x_3 = u;
    let mut z_3 = fe_one();
    let mut swap: u64 = 0;

    // Process bits from high to low (bit 254 down to 0)
    for pos in (0..=254).rev() {
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        let k_t = ((k[byte_idx] >> bit_idx) & 1) as u64;

        swap ^= k_t;
        fe_cswap(&mut x_2, &mut x_3, swap);
        fe_cswap(&mut z_2, &mut z_3, swap);
        swap = k_t;

        let a = fe_add(&x_2, &z_2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x_2, &z_2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x_3, &z_3);
        let d = fe_sub(&x_3, &z_3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let sum = fe_add(&da, &cb);
        let diff = fe_sub(&da, &cb);
        x_3 = fe_sq(&sum);
        let diff_sq = fe_sq(&diff);
        z_3 = fe_mul(&x_1, &diff_sq);
        x_2 = fe_mul(&aa, &bb);
        // a24 = 121665; z_2 = e * (aa + a24 * e) per RFC 7748 §5.
        // Pre-2026-05 had 121666 here — off-by-one bug that broke
        // every RFC 7748 test vector (task #212).
        let a24_e = fe_mul_small(&e, 121665);
        let inner = fe_add(&aa, &a24_e);
        z_2 = fe_mul(&e, &inner);
    }

    fe_cswap(&mut x_2, &mut x_3, swap);
    fe_cswap(&mut z_2, &mut z_3, swap);

    // Result = x_2 * z_2^(p-2) = x_2 / z_2
    let z_inv = fe_invert(&z_2);
    let result = fe_mul(&x_2, &z_inv);

    encode_u_coordinate(&result)
}

/// Generate a public key from a private key.
pub fn x25519_pubkey(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, &BASEPOINT)
}

// ---------------------------------------------------------------------------
// Field element: 4 × u64 representing integers mod p = 2^255 - 19
// ---------------------------------------------------------------------------

#[cfg(feature = "legacy-x25519")]
type Fe = [u64; 4];

#[cfg(feature = "legacy-x25519")]
fn fe_zero() -> Fe { [0; 4] }
#[cfg(feature = "legacy-x25519")]
fn fe_one() -> Fe { [1, 0, 0, 0] }

#[cfg(feature = "legacy-x25519")]
fn decode_u_coordinate(bytes: &[u8; 32]) -> Fe {
    let mut f = [0u64; 4];
    for i in 0..4 {
        let off = i * 8;
        f[i] = u64::from_le_bytes([
            bytes[off], bytes[off+1], bytes[off+2], bytes[off+3],
            bytes[off+4], bytes[off+5], bytes[off+6], bytes[off+7],
        ]);
    }
    f[3] &= 0x7FFF_FFFF_FFFF_FFFF; // mask top bit
    f
}

#[cfg(feature = "legacy-x25519")]
fn encode_u_coordinate(f: &Fe) -> [u8; 32] {
    let r = fe_reduce(f);
    let mut out = [0u8; 32];
    for i in 0..4 {
        let b = r[i].to_le_bytes();
        out[i*8..(i+1)*8].copy_from_slice(&b);
    }
    out
}

// ---------------------------------------------------------------------------
// Modular arithmetic (mod p = 2^255 - 19)
// ---------------------------------------------------------------------------

#[cfg(feature = "legacy-x25519")]
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry as u128;
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    // Reduce if >= p
    fe_reduce_once(&r)
}

#[cfg(feature = "legacy-x25519")]
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // a - b mod p: if a < b, add p
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = a[i] as i128 - b[i] as i128 - borrow;
        if diff < 0 {
            r[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = diff as u64;
            borrow = 0;
        }
    }
    if borrow != 0 {
        // Add p
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = r[i] as u128 + P[i] as u128 + carry;
            r[i] = sum as u64;
            carry = sum >> 64;
        }
    }
    r
}

#[cfg(feature = "legacy-x25519")]
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    // Schoolbook 256×256 → 512 bit multiply, then reduce mod p
    let mut t = [0u128; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = a[i] as u128 * b[j] as u128 + t[i+j] + carry;
            t[i+j] = prod & 0xFFFF_FFFF_FFFF_FFFF;
            carry = prod >> 64;
        }
        t[i+4] += carry;
    }
    reduce_512(&t)
}

#[cfg(feature = "legacy-x25519")]
fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

#[cfg(feature = "legacy-x25519")]
fn fe_mul_small(a: &Fe, small: u64) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let prod = a[i] as u128 * small as u128 + carry;
        r[i] = prod as u64;
        carry = prod >> 64;
    }
    // carry might be nonzero — reduce
    // carry * 2^256 mod p = carry * 38 (since 2^256 = 38 mod p)
    let extra = carry as u64;
    if extra > 0 {
        let add = extra as u128 * 38;
        let sum = r[0] as u128 + add;
        r[0] = sum as u64;
        let mut c2 = sum >> 64;
        for i in 1..4 {
            let s = r[i] as u128 + c2;
            r[i] = s as u64;
            c2 = s >> 64;
        }
    }
    fe_reduce_once(&r)
}

/// Conditional swap: if swap != 0, swap a and b.
#[cfg(feature = "legacy-x25519")]
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap); // all 1s if swap=1, all 0s if swap=0
    for i in 0..4 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Modular inversion: a^(p-2) mod p (Fermat's little theorem).
#[cfg(feature = "legacy-x25519")]
fn fe_invert(a: &Fe) -> Fe {
    // p - 2 = 2^255 - 21
    // Use a square-and-multiply chain optimized for 2^255-21
    let mut t0 = fe_sq(a);           // a^2
    let mut t1 = fe_sq(&t0);        // a^4
    t1 = fe_sq(&t1);                // a^8
    t1 = fe_mul(&t1, a);            // a^9
    t0 = fe_mul(&t0, &t1);          // a^11
    let mut t2 = fe_sq(&t0);        // a^22
    t1 = fe_mul(&t1, &t2);          // a^(9+22) = a^31
    t2 = fe_sq(&t1);
    for _ in 0..4 { t2 = fe_sq(&t2); } // a^(31*32) = a^992
    t1 = fe_mul(&t1, &t2);          // a^1023
    t2 = fe_sq(&t1);
    for _ in 0..9 { t2 = fe_sq(&t2); } // a^(1023*1024)
    t2 = fe_mul(&t2, &t1);
    let mut t3 = fe_sq(&t2);
    for _ in 0..19 { t3 = fe_sq(&t3); }
    t2 = fe_mul(&t2, &t3);
    t2 = fe_sq(&t2);
    for _ in 0..9 { t2 = fe_sq(&t2); }
    t1 = fe_mul(&t1, &t2);
    t2 = fe_sq(&t1);
    for _ in 0..49 { t2 = fe_sq(&t2); }
    t2 = fe_mul(&t2, &t1);
    t3 = fe_sq(&t2);
    for _ in 0..99 { t3 = fe_sq(&t3); }
    t2 = fe_mul(&t2, &t3);
    t2 = fe_sq(&t2);
    for _ in 0..49 { t2 = fe_sq(&t2); }
    t1 = fe_mul(&t1, &t2);
    t1 = fe_sq(&t1);
    t1 = fe_sq(&t1); // a^(2^253)
    t1 = fe_mul(&t1, a); // a^(2^253 + 1)
    t1 = fe_sq(&t1);
    t1 = fe_sq(&t1);
    t1 = fe_mul(&t1, a); // a^(2^255 - 21) = a^(p-2)
    t1
}

/// Reduce a 512-bit product mod p = 2^255 - 19.
/// Uses the identity: 2^256 ≡ 38 (mod p).
#[cfg(feature = "legacy-x25519")]
fn reduce_512(t: &[u128; 8]) -> Fe {
    // Split into low 256 bits and high 256 bits
    let mut r = [0u64; 4];
    let mut carry = 0u128;

    // r = low + high * 38
    for i in 0..4 {
        let sum = t[i] + t[i+4] * 38 + carry;
        r[i] = sum as u64;
        carry = sum >> 64;
    }
    // Final carry: carry * 38
    let extra = (carry as u64).wrapping_mul(38);
    let sum = r[0] as u128 + extra as u128;
    r[0] = sum as u64;
    let mut c = (sum >> 64) as u64;
    for i in 1..4 {
        let s = r[i] as u128 + c as u128;
        r[i] = s as u64;
        c = (s >> 64) as u64;
    }

    fe_reduce_once(&r)
}

/// Reduce once: if r >= p, subtract p.
#[cfg(feature = "legacy-x25519")]
fn fe_reduce_once(r: &Fe) -> Fe {
    // Check if r >= p
    let mut geq = true;
    for i in (0..4).rev() {
        if r[i] < P[i] { geq = false; break; }
        if r[i] > P[i] { break; }
    }
    if !geq { return *r; }

    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let diff = r[i] as u128 + (1u128 << 64) - P[i] as u128 - borrow;
        out[i] = diff as u64;
        borrow = 1 - (diff >> 64);
    }
    out
}

/// Full reduction to canonical form.
#[cfg(feature = "legacy-x25519")]
fn fe_reduce(f: &Fe) -> Fe {
    let mut r = fe_reduce_once(f);
    r = fe_reduce_once(&r);
    r
}
