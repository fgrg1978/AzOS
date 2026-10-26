// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System suspend on riscv64 (SBI `SUSP`) and x86_64 (ACPI S3): when the kernel
//! may call the firmware, and why not.
//!
//! The SBI call loses the hart's context and resumes at a physical address with
//! `satp` = 0, so a kernel that says "available" without a resume address
//! suspends and never comes back. The x86 half is the opposite case: S3 needs
//! the `\_S3` object of the DSDT, which only AML gives, so the answer is "not
//! available" with the reason and never a guessed `SLP_TYP`.

// The two firmware files are pulled in by path at this level (an inline
// module would move the `#[path]` base into directories that do not exist).
// `x86_s3` reads the FADT as `super::acpi`, so the parser is `acpi` here.
#[allow(dead_code)]
#[path = "../../../../arch/riscv64/src/firmware.rs"]
mod rv_firmware;
#[allow(dead_code)]
#[path = "../../../../arch/x86_64/src/firmware/acpi.rs"]
mod acpi;
#[allow(dead_code)]
#[path = "../../../../arch/x86_64/src/firmware/suspend.rs"]
mod x86_s3;

mod rv {
    use crate::suspend::rv_firmware::*;

    // SBI 2.0 and 1.0 as the version register holds them (`major << 24 | minor`).
    const V2: usize = 2 << 24;
    const V1: usize = 1 << 24;

    #[test]
    fn the_extension_and_function_ids() {
        assert_eq!(EXT_SUSP, 0x5355_5350, "ASCII \"SUSP\"");
        assert_eq!(EXT_SUSP, u32::from_be_bytes(*b"SUSP") as usize);
        assert_eq!(SUSP_SYSTEM_SUSPEND, 0);
        assert_eq!(SLEEP_TYPE_SUSPEND_TO_RAM, 0);
        assert_eq!(ERR_INVALID_ADDRESS, -5);
    }

    #[test]
    fn susp_exists_from_sbi_2_0() {
        assert!(!spec_has_system_suspend(0), "the base call failed");
        assert!(!spec_has_system_suspend(V1 | 0x03));
        assert!(!spec_has_system_suspend(V2 - 1));
        assert!(spec_has_system_suspend(V2));
        assert!(spec_has_system_suspend(V2 | 1));
        assert!(spec_has_system_suspend(3 << 24));
    }

    #[test]
    fn the_firmware_answers_first() {
        let never = || -> usize { panic!("the probe is not asked of an SBI without SUSP") };
        use SystemSuspendMissing::{Firmware, ResumeEntry};
        assert_eq!(system_suspend_available(0, never, Some(0x8020_0000)), Err(Firmware(ERR_NOT_SUPPORTED)));
        assert_eq!(system_suspend_available(V1 | 3, never, Some(0x8020_0000)), Err(Firmware(ERR_NOT_SUPPORTED)));
        // SBI 2.0 whose platform has no system-suspend operation: OpenSBI's
        // probe answers 0.
        assert_eq!(system_suspend_available(V2, || 0, Some(0x8020_0000)), Err(Firmware(ERR_NOT_SUPPORTED)));
        // A firmware without the call needs no address to say so.
        assert_eq!(system_suspend_available(V2, || 0, None), Err(Firmware(ERR_NOT_SUPPORTED)));
        // With the call, the kernel's address decides.
        assert_eq!(system_suspend_available(V2, || 1, None), Err(ResumeEntry));
        assert_eq!(system_suspend_available(V2, || 1, Some(0x8020_0000)), Ok(()));
    }

    /// The kernel has no resume address yet. This pins that it does not claim
    /// one: when the trampoline lands, the constant and this test move together.
    #[test]
    fn the_kernel_names_no_entry_it_does_not_have() {
        assert_eq!(RESUME_ENTRY, None);
        assert_eq!(system_suspend_available(V2, || 1, RESUME_ENTRY), Err(SystemSuspendMissing::ResumeEntry));
    }

    /// Off riscv64 there is no firmware and every call answers `NOT_SUPPORTED`
    /// (the file's stand-in), which is what an SBI without the extension says.
    #[test]
    fn the_call_off_target_answers_not_supported() {
        assert_eq!(system_suspend(0x8020_0000, 0), ERR_NOT_SUPPORTED);
        assert_eq!(system_suspend_support(), Err(SystemSuspendMissing::Firmware(ERR_NOT_SUPPORTED)));
    }
}

mod x86 {
    use crate::suspend::acpi::{self, Fadt};
    use crate::suspend::x86_s3::*;

    fn fadt(pm1a_cnt: u32, flags: u32) -> Fadt {
        Fadt { revision: 5, pm1a_cnt, flags, ..Fadt::default() }
    }

    #[test]
    fn no_fadt_no_s3() {
        assert_eq!(s3_available(None), Err(SystemSuspendMissing::NoFadt));
    }

    #[test]
    fn a_hardware_reduced_platform_has_no_pm1_blocks() {
        assert_eq!(s3_available(Some(&fadt(0x604, 1 << 20))), Err(SystemSuspendMissing::HardwareReduced));
    }

    #[test]
    fn no_pm1a_control_block_means_no_register_to_write() {
        assert_eq!(s3_available(Some(&fadt(0, 0))), Err(SystemSuspendMissing::NoPm1Control));
    }

    /// Everything the FADT can say is in order, and S3 is still not available:
    /// `SLP_TYPa` is in the DSDT's `\_S3` package, and the kernel has no AML.
    /// No FADT makes this `Ok`; when an interpreter exists the answer changes
    /// here, in one place, with this test.
    #[test]
    fn a_complete_fadt_still_needs_aml() {
        for flags in [0, 1 << 10, 1 << 8 | 1 << 10] {
            assert_eq!(s3_available(Some(&fadt(0x604, flags))), Err(SystemSuspendMissing::NoAml), "flags {flags:#x}");
        }
    }

    /// The FADT the parser reads off a real table feeds the same answer.
    #[test]
    fn a_parsed_table_gives_the_same_answer() {
        let mut t = vec![0u8; 244];
        t[..4].copy_from_slice(b"FACP");
        t[8] = 5;
        t[64..68].copy_from_slice(&0x604u32.to_le_bytes());
        let f = acpi::parse_fadt(&t).expect("a 244-byte FADT parses");
        assert_eq!(f.pm1a_cnt, 0x604);
        assert_eq!(s3_available(Some(&f)), Err(SystemSuspendMissing::NoAml));
        t[64..68].copy_from_slice(&0u32.to_le_bytes());
        let f = acpi::parse_fadt(&t).unwrap();
        assert_eq!(s3_available(Some(&f)), Err(SystemSuspendMissing::NoPm1Control));
    }
}
