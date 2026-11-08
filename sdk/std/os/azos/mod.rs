// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AzOS-specific extensions: what a native program needs that no portable std
//! API says (`std::os::azos`, the `azos_ext` feature).

#![unstable(feature = "azos_ext", issue = "none")]

pub mod terminal;
