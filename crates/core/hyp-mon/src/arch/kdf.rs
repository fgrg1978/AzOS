// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a root derives: `HKDF-SHA256(salt, ikm = root, info)`, 32 bytes, from
//! the request the kernel built. Pure over `crate::hkdf`, so the host suite
//! (`tests/host/hv-tests`) runs this file against the kernel's own `azos_crypto`.
//! Canary `hyp-kdf-salt-canary`: the salt is left out.

use crate::hkdf::hkdf;
use azos_hyp_api::{derive_req_error, DeriveReq, KEY_LEN};

pub fn derive(root: &[u8; KEY_LEN], req: &DeriveReq) -> Option<[u8; KEY_LEN]> {
    if derive_req_error(req).is_some() {
        return None;
    }
    let salt: &[u8] = if cfg!(feature = "hyp-kdf-salt-canary") { &[] } else { req.salt() };
    let mut out = [0u8; KEY_LEN];
    hkdf(salt, root, req.info(), &mut out).then_some(out)
}
