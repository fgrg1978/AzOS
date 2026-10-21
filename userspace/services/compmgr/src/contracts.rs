// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The failure contracts the IDL declares, by the endpoint the interface is
//! served on.
//!
//! The contract of a service is the strongest `#[on_failure(..)]` among the
//! ops of its interface ([`OpInfo::on_failure`]): the table below names the
//! interfaces a ring-3 component serves on an endpoint of the signed
//! topology, and the op tables come straight from the generated
//! `<Name>Idl::OPS`, so a contract changed in the interface is the contract
//! the manager acts on. An endpoint not listed has no interface here: no
//! contract.
//!
//! `tests/host/topology-tests` (`compmgr_contracts`) fails when an endpoint
//! the signed topology serves is neither listed here nor named there as one
//! without an IDL interface, so a new served interface cannot silently fall
//! back to `rest_for_one`.

use azos_idl::{OnFailure, OpInfo};

/// The endpoints and the op tables of the interfaces served on them.
pub const SERVED: &[(&[u8], &[OpInfo])] = &[
    (b"endpoint.names", &azos_names::NamesIdl::OPS),
    (b"endpoint.term", &azos_term::TerminalIdl::OPS),
    // The login service. Its ops declare no failure contract, so the manager
    // restarts the terminal server behind it when it fails: the server asks
    // again from the locked console, which is where a session whose service
    // died (and whose shell died with it) has to be.
    (b"endpoint.login", &azos_login::LoginIdl::OPS),
    (b"endpoint.decisions", &azos_decisions::DecisionsIdl::OPS),
    (b"endpoint.packages", &azos_packages::PackagesIdl::OPS),
    // The buzzer's ring-3 host, one of the two hosts of a driver that moves
    // between them (`kernel/src/buzzer.rs`). Its ops declare no failure
    // contract (they are idempotent: a caller whose call was lost asks again).
    (b"endpoint.buzzer", &azos_devif::BuzzerIdl::OPS),
    // The drivers' runtime power (`DevicePower`), served for the power service.
    (b"endpoint.pm-gpio", &azos_devif::power::DevicePowerIdl::OPS),
    (b"endpoint.pm-ina", &azos_devif::power::DevicePowerIdl::OPS),
    (b"endpoint.vmctl", &azos_devif::VmCtlIdl::OPS),
    // The input server: the focus is a warrant its holders keep; its ops
    // declare no failure contract (`release` and `status` are idempotent, a
    // lost `take_focus` is asked again).
    (b"endpoint.input", &azos_devif::InputIdl::OPS),
    // The compositor: the windows clients attach and the trusted path; a failing
    // compositor is restarted (its windows go with it, and `attach` is asked
    // again; the screen is given back by the kernel when its claim's holder dies).
    (b"endpoint.compositor", &azos_compositor::CompositorIdl::OPS),
    // The inference broker (`MLSRV.ELF`) also answers `Decisions` and `InferLog`
    // on it; `Infer` is the interface the endpoint is for.
    (b"endpoint.infer", &azos_devif::infer::InferIdl::OPS),
];

/// The strongest failure contract among `ops`, `None` when none declares one.
pub fn strongest(ops: &[OpInfo]) -> Option<OnFailure> {
    ops.iter().filter_map(|o| o.on_failure).max_by_key(|f| crate::tree::severity(*f))
}

/// The failure contract of the interface served on `endpoint`.
pub fn contract_of(endpoint: &[u8]) -> Option<OnFailure> {
    SERVED.iter().find(|(e, _)| *e == endpoint).and_then(|(_, ops)| strongest(ops))
}
