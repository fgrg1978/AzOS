// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The images of this build: the tasks the topology's rows name. Each is an
//! ordinary function in the kernel image, run in U-mode on its own region
//! (`Kernel::boot` matches a row to an image by name, the way the main
//! kernel matches it to an ELF on the volume).

use azos_micro::kernel::Image;

mod captest;
mod echo;
mod faulter;
mod idle;
mod spawnee;
mod sys;

/// Every image, by the name a row spells.
pub static IMAGES: [Image; 5] = [
    Image { name: "IDLE.ELF", entry: idle::main },
    Image { name: "ECHO.ELF", entry: echo::main },
    Image { name: "CAPTEST.ELF", entry: captest::main },
    Image { name: "SPAWNEE.ELF", entry: spawnee::main },
    Image { name: "FAULTER.ELF", entry: faulter::main },
];
