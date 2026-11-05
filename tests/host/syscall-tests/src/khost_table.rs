// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the table of hosted interfaces in
// `crates/core/syscall/src/khost.rs`: which host keys have a row, which rows
// take capability entries, and what an unhosted key answers.
//
// Included inside `mod handlers { .. }` like `h3_hosts.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::key;
use azos_idl::{IdlError, MsgDesc, MSG_VERSION};
use crate::khost::Caller;

/// The keys this build hosts: every interface with ops, less the ones whose
/// server is behind a feature the build lacks.
fn expected_keys() -> Vec<u16> {
    azos_devif::IFACES
        .iter()
        .map(|i| i.key)
        .filter(|&k| k != key::TIME)
        .filter(|&k| cfg!(feature = "board-io") || k != key::ADC)
        .filter(|&k| cfg!(feature = "virtio-snd") || k != key::SOUND)
        .filter(|&k| cfg!(feature = "hv") || (k != key::VM && k != key::VCPU))
        .collect()
}

/// **Every interface with a server has exactly one row**, and no row names a
/// key outside `azos_devif::IFACES`.
///
/// **Canary.** Delete one row of `HOSTED`: its key is missing here (and a row
/// added twice does not compile).
#[test]
fn every_hosted_interface_has_exactly_one_row() {
    let mut have: Vec<u16> = crate::khost::hosted_keys().map(|(k, _)| k).collect();
    have.sort_unstable();
    let mut want = expected_keys();
    want.sort_unstable();
    assert_eq!(have, want);
}

/// **Which interfaces may carry capability entries**: the ones with an op that
/// takes a queue (`Uart`, `Adc`), a memory object and a port (`Vm`, `Display`),
/// a memory object (`MemCtl`, `Keys`) or a stream's queues (`Sound`). The row's
/// column is derived from the IDL, so this list is the check that the derivation
/// agrees with what the kernel-hosted call path (`ipc_v2::call_kernel_hosted`)
/// has always allowed.
///
/// **Canary.** Declare `takes_caps: true` for `key::GPIO`'s row (or drop the
/// `Cap` from `Uart::attach`): that line fails.
#[test]
fn only_uart_adc_vm_display_memctl_keys_and_sound_requests_may_carry_capability_entries() {
    let listed = |k: u16| {
        k == key::UART
            || k == key::ADC
            || k == key::VM
            || k == key::DISPLAY
            || k == key::MEMCTL
            || k == key::KEYS
            || k == key::SOUND
    };
    let hosted: Vec<(u16, bool)> = crate::khost::hosted_keys().collect();
    assert!(hosted.iter().any(|&(k, _)| k == key::UART));
    for (k, caps) in hosted {
        assert_eq!(caps, listed(k), "key {k}");
        assert_eq!(crate::khost::takes_caps(k), caps, "key {k}");
    }
    // `Vm` and `Vcpu` have rows only under `hv`, which the host build lacks.
    assert!(azos_devif::VmIdl::TAKES_CAPS && !azos_devif::VcpuIdl::TAKES_CAPS);
    assert!(!crate::khost::takes_caps(0));
    assert!(!crate::khost::takes_caps(key::TIME));
    assert!(!crate::khost::takes_caps(u16::MAX));
}

/// **A key with no row answers `BadInterface`**: 0, `TIME` (an interface with
/// no ops), one past the last key, and the keys of features this build lacks.
///
/// **Canary.** Answer an unknown key with the first row's dispatcher: the
/// status is not `BadInterface`.
#[test]
fn a_key_without_a_row_answers_bad_interface() {
    let _g = serial();
    let who = Caller { tid: 1, badge: 0, rights: CapPerms::RW };
    let mut req = MsgDesc { version: MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    req.words[0] = azos_idl::header(azos_devif::GpioIdl::ID, azos_devif::GpioIdl::LEVEL, azos_devif::GpioIdl::OP_READ);
    let hosted = expected_keys();
    let unhosted = (0..=azos_devif::IFACES.len() as u16 + 1).chain([u16::MAX]).filter(|k| !hosted.contains(k));
    for k in unhosted {
        let mut rep = MsgDesc::default();
        crate::khost::serve(k, &who, &req, &mut rep);
        assert_eq!(rep.words[0], IdlError::BadInterface.status(), "key {k}");
        assert_eq!(rep.n_words, 1, "key {k}");
    }
}
