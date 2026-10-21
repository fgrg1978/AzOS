// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Finding the model bundles on the volume and loading them.
//!
//! Every `*.MBL` in `/fat` is a candidate, in directory order, up to what the
//! broker holds (`INFSRV_MODELS`). Each is streamed through
//! [`infsrv::load::load`] with the trusted key (the one `CAPS.SIG` and
//! `CONFIG.SIG` are checked with): unlike the GGUF policy file there is
//! no Kconfig switch for it, because a bundle carries the cost table the
//! admission believes.

use crate::out::Line;
use azos_libsys as sys;
use infsrv::broker::{AddError, Broker};
use infsrv::exec;
use infsrv::load::{self, Arena, Fate, LoadError};

/// Directory entries looked at (a volume holds the images and a few data
/// files, not thousands).
const SCAN_MAX: u64 = 256;

fn is_bundle(name: &[u8]) -> bool {
    let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let name = &name[..n];
    n > 4 && name[n - 4..].eq_ignore_ascii_case(b".MBL")
}

fn fate_text(f: Fate) -> &'static [u8] {
    match f {
        Fate::Loaded => b"loaded",
        Fate::OtherBackend => b"skipped: a backend this machine does not have",
        Fate::NoRoom => b"NOT LOADED: no room in the blob arena",
        Fate::Short => b"NOT LOADED: the file ends inside the blob",
        Fate::BadDigest => b"NOT LOADED: the blob's SHA-256 is not the manifest's",
        Fate::BadModel => b"NOT LOADED: not a two-layer MLP of the manifest's tensor sizes",
    }
}

/// Load every bundle on the volume into `broker`.
pub fn load_all(broker: &mut Broker, arena: &mut Arena<'_>) {
    let mut held = 0u32;
    for index in 0..SCAN_MAX {
        let mut name = [0u8; sys::READDIR_NAME_BYTES];
        let (mut size, mut is_dir) = (0u32, 0u32);
        if sys::readdir(b"/fat\0", index, &mut name, &mut size, &mut is_dir) != 0 {
            break;
        }
        if is_dir != 0 || !is_bundle(&name) {
            continue;
        }
        let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let mut path = [0u8; 5 + sys::READDIR_NAME_BYTES + 1];
        path[..5].copy_from_slice(b"/fat/");
        path[5..5 + n].copy_from_slice(&name[..n]);
        let label = &path[5..5 + n];

        let h = sys::open_root(&path[..5 + n + 1], 0);
        if h < 0 {
            Line::new(b"[infsrv] ").push(label).push(b": cannot be opened").print();
            continue;
        }
        let h = h as u32;
        let mut read = |buf: &mut [u8]| match sys::file_read_typed(h, buf) {
            r if r > 0 => r as usize,
            _ => 0,
        };
        let loaded = load::load(
            &mut read,
            arena,
            |m, sig| azos_topology::verify_signature(m, sig, &azos_topology::TRUSTED_PUBKEY).is_ok(),
            azos_crypto::sha256::sha256,
            exec::fits,
        );
        let _ = sys::close_typed(h);

        match loaded {
            Err(LoadError::Bundle(e)) => {
                Line::new(b"[infsrv] ").push(label).push(b" REFUSED: ").push(match e {
                    azos_ml::bundle::Error::Signature => b"bad signature" as &[u8],
                    azos_ml::bundle::Error::Magic => b"not a bundle",
                    azos_ml::bundle::Error::Version => b"unknown version",
                    azos_ml::bundle::Error::Short => b"too short",
                    azos_ml::bundle::Error::Layout => b"malformed manifest",
                    azos_ml::bundle::Error::Blob => b"bad blob",
                }).print();
            }
            Err(LoadError::Truncated) => {
                Line::new(b"[infsrv] ").push(label).push(b" REFUSED: the file ends inside the manifest").print();
            }
            Ok(report) => {
                let m = report.model;
                match broker.add(m) {
                    Ok(_) => {
                        held += 1;
                        let mut l = Line::new(b"[infsrv] bundle ");
                        l.push(m.name().as_bytes()).push(b" ref=").hex64(m.model_ref).push(b" variants=").num(m.n as u64)
                            .push(b" runnable=")
                            .num(m.variants().iter().filter(|s| s.span.is_some()).count() as u64)
                            .push(b" (signature verified)");
                        l.print();
                        for (id, fate) in report.fates.iter().take(m.n) {
                            if *fate != Fate::Loaded {
                                Line::new(b"[infsrv]   variant ").num(*id as u64).push(b" ").push(fate_text(*fate)).print();
                            }
                        }
                    }
                    Err(AddError::Duplicate) => {
                        Line::new(b"[infsrv] ").push(label).push(b": the same bundle is already held").print();
                    }
                    Err(AddError::Full) => {
                        Line::new(b"[infsrv] ").push(label).push(b" NOT LOADED: the model table is full").print();
                    }
                }
            }
        }
    }
    if held == 0 {
        sys::println(b"[infsrv] no model bundle loaded: every Infer call is told NO_RESOURCE");
    }
}
