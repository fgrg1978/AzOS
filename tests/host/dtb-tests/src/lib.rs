// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_dtb` — the Flattened Device
//! Tree (FDT) parser called from kernel boot.
//!
//! FDT is big-endian. The 40-byte header layout (Devicetree
//! Specification v0.4 §5.2):
//!
//! ```text
//!  +0  magic              u32  must be 0xd00dfeed
//!  +4  totalsize          u32  whole blob size
//!  +8  off_dt_struct      u32  offset to structure block
//! +12  off_dt_strings     u32
//! +16  off_mem_rsvmap     u32
//! +20  version            u32  must be >= 16
//! +24  last_comp_version  u32
//! +28  boot_cpuid_phys    u32
//! +32  size_dt_strings    u32
//! +36  size_dt_struct     u32
//! ```

#[cfg(test)]
mod tests {
    use azos_dtb::{dtb_compatible_str, dtb_cpu_regs, dtb_parse, DtbInfo};

    const FDT_MAGIC: u32 = 0xd00d_feed;

    /// Build a minimal valid header (40 bytes) with the given
    /// version + totalsize. Struct + strings blocks are empty
    /// (offsets point past the header into a zeroed area).
    fn minimal_header(version: u32, totalsize: u32) -> [u8; 40] {
        let mut hdr = [0u8; 40];
        hdr[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        hdr[4..8].copy_from_slice(&totalsize.to_be_bytes());
        // off_dt_struct = 40 (immediately after header).
        hdr[8..12].copy_from_slice(&40u32.to_be_bytes());
        // off_dt_strings = 40 (also empty).
        hdr[12..16].copy_from_slice(&40u32.to_be_bytes());
        // off_mem_rsvmap = 40.
        hdr[16..20].copy_from_slice(&40u32.to_be_bytes());
        // version
        hdr[20..24].copy_from_slice(&version.to_be_bytes());
        // last_comp_version
        hdr[24..28].copy_from_slice(&16u32.to_be_bytes());
        // boot_cpuid_phys
        hdr[28..32].copy_from_slice(&0u32.to_be_bytes());
        // size_dt_strings
        hdr[32..36].copy_from_slice(&0u32.to_be_bytes());
        // size_dt_struct
        hdr[36..40].copy_from_slice(&0u32.to_be_bytes());
        hdr
    }

    /// Build a buffer with the minimal header + an FDT_END token
    /// so the walker has something to terminate on without
    /// reading into uninitialised memory.
    fn minimal_blob(version: u32) -> Vec<u8> {
        const FDT_END: u32 = 9;
        let totalsize: u32 = 40 + 4; // header + one 4-byte END token
        let mut buf = minimal_header(version, totalsize).to_vec();
        buf.extend_from_slice(&FDT_END.to_be_bytes());
        buf
    }

    // ── Rejection cases (bounds & sanity) ──────────────────────

    #[test]
    fn rejects_null_pointer() {
        // SAFETY: passing a null pointer is the documented "this
        // is bogus" entry path; impl returns None.
        let result = unsafe { dtb_parse(core::ptr::null()) };
        assert!(result.is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut buf = minimal_blob(17);
        // Corrupt magic.
        buf[0] = 0xAA;
        let info = unsafe { dtb_parse(buf.as_ptr()) };
        assert!(info.is_none());
    }

    #[test]
    fn rejects_old_version() {
        // Version 15 is below the minimum (16).
        let buf = minimal_blob(15);
        let info = unsafe { dtb_parse(buf.as_ptr()) };
        assert!(info.is_none(),
            "version 15 must be rejected (impl requires >= 16)");
    }

    #[test]
    fn accepts_minimum_supported_version() {
        let buf = minimal_blob(16);
        let info = unsafe { dtb_parse(buf.as_ptr()) };
        assert!(info.is_some(),
            "version 16 is the documented minimum and must parse");
    }

    #[test]
    fn rejects_totalsize_below_header() {
        // totalsize < 40 is structurally impossible (header is
        // 40 bytes). Impl explicitly guards against this.
        let mut hdr = minimal_header(17, 30);
        // Patch totalsize back to a too-small value (minimal_header
        // already used 30, but make the rest of the field clear).
        hdr[4..8].copy_from_slice(&30u32.to_be_bytes());
        let info = unsafe { dtb_parse(hdr.as_ptr()) };
        assert!(info.is_none());
    }

    // ── Header offsets must lie inside the blob ────────────────
    //
    // The header fields are firmware-supplied u32 parsed from the raw `a1`
    // register at boot, before the trap handler is useful. `panic = "abort"`
    // makes any fault here a silent board reset, so a blob whose offsets
    // point outside itself must be rejected, not walked.

    #[test]
    fn rejects_strings_block_past_end_of_blob() {
        // The exact reported case: off_dt_strings = 0xFFFF_F000 with
        // size_dt_strings = 0x1000 makes strings_end wrap up to
        // 0x1_0000_0000. The walker's only strings guard was
        // "off < strings_end", which such a value passes trivially — so the
        // first FDT_PROP resolved its name ~4 GiB past the blob, outside
        // physical RAM on every target board.
        let mut buf = minimal_blob(17);
        buf[12..16].copy_from_slice(&0xFFFF_F000u32.to_be_bytes()); // off_dt_strings
        buf[32..36].copy_from_slice(&0x1000u32.to_be_bytes());      // size_dt_strings
        let info = unsafe { dtb_parse(buf.as_ptr()) };
        assert!(info.is_none(),
            "strings block outside totalsize must be rejected");
    }

    #[test]
    fn rejects_strings_block_overrunning_end_by_one() {
        // Boundary: a strings block ending exactly at totalsize is the
        // normal dtc layout and must be ACCEPTED (see the happy-path
        // tests); one byte more must not be.
        let mut buf = minimal_blob(17);
        // totalsize is 44, off_dt_strings is 40 → size 4 fits exactly,
        // size 5 does not.
        buf[32..36].copy_from_slice(&4u32.to_be_bytes());
        assert!(unsafe { dtb_parse(buf.as_ptr()) }.is_some(),
            "strings ending exactly at totalsize is a valid dtc layout");

        buf[32..36].copy_from_slice(&5u32.to_be_bytes());
        assert!(unsafe { dtb_parse(buf.as_ptr()) }.is_none(),
            "strings overrunning totalsize by one byte must be rejected");
    }

    #[test]
    fn rejects_struct_block_past_end_of_blob() {
        // walk() bounds its cursor relative to off_dt_struct; if that base
        // is itself outside the blob, every later bound is meaningless.
        let mut buf = minimal_blob(17);
        buf[8..12].copy_from_slice(&0xFFFF_F000u32.to_be_bytes());
        assert!(unsafe { dtb_parse(buf.as_ptr()) }.is_none());
    }

    #[test]
    fn rejects_absurd_totalsize() {
        // totalsize is the walker's only extent bound. Unclamped, a blob
        // claiming 4 GiB licenses a 4 GiB march past the end of RAM. Real
        // DTBs are tens of KiB; the parser caps at a few MiB.
        let mut buf = minimal_blob(17);
        buf[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert!(unsafe { dtb_parse(buf.as_ptr()) }.is_none(),
            "a totalsize far beyond any real DTB must be rejected");
    }

    // ── Unterminated strings must not scan out of the blob ─────

    #[test]
    fn unterminated_node_name_aborts_walk_instead_of_scanning_past_blob() {
        // A blob whose last token is FDT_BEGIN_NODE with a name that has no
        // NUL before the end of the blob. The old strlen() had no bound and
        // no totalsize, so it scanned RAM until it happened to hit a zero
        // byte.
        //
        // The buffer is sized so the blob ends exactly at the Vec's last
        // initialised byte: any read past `totalsize` is also past the
        // allocation, so Miri/ASAN would flag a regression here even though
        // a plain host run cannot observe the difference directly. What the
        // assertions pin is the contract — an unterminated name aborts the
        // walk and yields the zeroed defaults rather than guessing.
        const FDT_BEGIN_NODE: u32 = 1;
        let name = b"memory@"; // deliberately NOT NUL-terminated
        let totalsize = (40 + 4 + name.len()) as u32;

        let mut buf = minimal_header(17, totalsize).to_vec();
        // off_dt_strings = totalsize, size_dt_strings = 0 → empty strings
        // block sitting exactly at the end, which is legal.
        buf[12..16].copy_from_slice(&totalsize.to_be_bytes());
        buf[32..36].copy_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        buf.extend_from_slice(name);
        assert_eq!(buf.len(), totalsize as usize);

        let info = unsafe { dtb_parse(buf.as_ptr()) }
            .expect("header is well-formed; only the node name is truncated");
        assert_eq!(info.mem_base, 0);
        assert_eq!(info.mem_size, 0);
        assert_eq!(info.num_cpus, 0);
        assert_eq!(info.uart_base, 0);
    }

    // ── Happy-path minimal blob ────────────────────────────────

    #[test]
    fn minimal_valid_blob_parses_with_zeroed_fields() {
        let buf = minimal_blob(17);
        let info = unsafe { dtb_parse(buf.as_ptr()) }.unwrap();
        // No /memory or /cpu nodes → fields stay at their zero
        // defaults. This pins the contract that a structurally
        // valid but content-empty blob is NOT a parse error.
        assert_eq!(info.mem_base, 0);
        assert_eq!(info.mem_size, 0);
        assert_eq!(info.num_cpus, 0);
        assert_eq!(info.timer_freq, 0);
        assert_eq!(info.uart_base, 0);
        assert_eq!(info.plic_base, 0);
    }

    // ── dtb_compatible_str ─────────────────────────────────────

    #[test]
    fn compatible_str_empty_when_no_root_compatible() {
        let info = DtbInfo {
            mem_base: 0, mem_size: 0, timer_freq: 0,
            uart_base: 0, plic_base: 0, num_cpus: 0,
            compatible: [0u8; 64], isa_sstc: false,
            isa_zicboz: false, cboz_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
        };
        assert_eq!(dtb_compatible_str(&info), b"");
    }

    #[test]
    fn compatible_str_truncates_at_first_nul() {
        let mut info = DtbInfo {
            mem_base: 0, mem_size: 0, timer_freq: 0,
            uart_base: 0, plic_base: 0, num_cpus: 0,
            compatible: [0u8; 64], isa_sstc: false,
            isa_zicboz: false, cboz_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
        };
        let want = b"riscv-virtio";
        info.compatible[..want.len()].copy_from_slice(want);
        // Anything after the NUL must be hidden.
        info.compatible[want.len() + 5] = b'X';
        assert_eq!(dtb_compatible_str(&info), want);
    }

    #[test]
    fn compatible_str_caps_at_buffer_when_unterminated() {
        let info = DtbInfo {
            mem_base: 0, mem_size: 0, timer_freq: 0,
            uart_base: 0, plic_base: 0, num_cpus: 0,
            compatible: [b'A'; 64], // no NUL anywhere
            isa_sstc: false,
            isa_zicboz: false, cboz_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
        };
        let out = dtb_compatible_str(&info);
        assert_eq!(out.len(), 64);
        assert!(out.iter().all(|&b| b == b'A'));
    }

    // ── Sstc from the cpu@0 ISA properties (RFC-0041 §B) ───────
    //
    // `isa_sstc` decides whether the kernel writes `stimecmp` directly. A
    // false positive is an S-mode access to a CSR the hart may not have, so
    // the token match is exact, and these blobs are walked by the real parser.

    /// A structure-block builder: tokens, names and property payloads, with
    /// the strings block and header laid out the way dtc lays them out.
    struct Fdt {
        structs: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Fdt {
        fn new() -> Self { Fdt { structs: Vec::new(), strings: Vec::new() } }

        fn pad4(v: &mut Vec<u8>) { while v.len() % 4 != 0 { v.push(0); } }

        fn begin(&mut self, name: &str) -> &mut Self {
            self.structs.extend_from_slice(&1u32.to_be_bytes());
            self.structs.extend_from_slice(name.as_bytes());
            self.structs.push(0);
            Self::pad4(&mut self.structs);
            self
        }

        fn end(&mut self) -> &mut Self {
            self.structs.extend_from_slice(&2u32.to_be_bytes());
            self
        }

        fn prop(&mut self, name: &str, value: &[u8]) -> &mut Self {
            let nameoff = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self.structs.extend_from_slice(&3u32.to_be_bytes());
            self.structs.extend_from_slice(&(value.len() as u32).to_be_bytes());
            self.structs.extend_from_slice(&nameoff.to_be_bytes());
            self.structs.extend_from_slice(value);
            Self::pad4(&mut self.structs);
            self
        }

        fn blob(&mut self) -> Vec<u8> {
            self.structs.extend_from_slice(&9u32.to_be_bytes()); // FDT_END
            let off_struct = 40u32;
            let off_strings = off_struct + self.structs.len() as u32;
            let total = off_strings + self.strings.len() as u32;
            let mut buf = minimal_header(17, total).to_vec();
            buf[8..12].copy_from_slice(&off_struct.to_be_bytes());
            buf[12..16].copy_from_slice(&off_strings.to_be_bytes());
            buf[32..36].copy_from_slice(&(self.strings.len() as u32).to_be_bytes());
            buf[36..40].copy_from_slice(&(self.structs.len() as u32).to_be_bytes());
            buf.extend_from_slice(&self.structs);
            buf.extend_from_slice(&self.strings);
            assert_eq!(buf.len(), total as usize);
            buf
        }
    }

    /// `/ { cpus { cpu@0 { <name> = <value>; } } }`.
    fn cpu0_with(name: &str, value: &[u8]) -> Vec<u8> {
        Fdt::new().begin("").begin("cpus").begin("cpu@0")
            .prop(name, value)
            .end().end().end().blob()
    }

    fn sstc_of(blob: &[u8]) -> bool {
        unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob").isa_sstc
    }

    /// A C string property value.
    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    #[test]
    fn riscv_isa_with_an_sstc_segment_sets_isa_sstc() {
        assert!(sstc_of(&cpu0_with("riscv,isa", &cstr("rv64imafdch_zicsr_sstc"))));
        // In the middle, as QEMU writes it.
        assert!(sstc_of(&cpu0_with("riscv,isa", &cstr("rv64imac_sstc_svadu"))));
        // The blob's own control: the same cpu@0 without it.
        assert!(!sstc_of(&cpu0_with("riscv,isa", &cstr("rv64imac_zicsr_zifencei"))));
    }

    #[test]
    fn riscv_isa_segments_that_only_resemble_sstc_do_not_count() {
        for isa in [
            "rv64imac_sstcx",       // prefix of a longer extension
            "rv64imac_ssstc",       // suffix of a longer extension
            "rv64imac_zicsr_sstcx",
            "rv64imac_sst",         // truncated
            "sstc",                 // the base segment is never an extension
            "rv64imacsstc",         // no separator
        ] {
            assert!(!sstc_of(&cpu0_with("riscv,isa", &cstr(isa))), "{isa}");
        }
        // What follows the string's NUL is not part of it.
        let mut v = cstr("rv64imac");
        v.extend_from_slice(b"_sstc\0");
        assert!(!sstc_of(&cpu0_with("riscv,isa", &v)));
    }

    #[test]
    fn riscv_isa_extensions_needs_an_exact_sstc_entry() {
        let list = |entries: &[&str]| -> Vec<u8> {
            entries.iter().flat_map(|e| cstr(e)).collect()
        };
        assert!(sstc_of(&cpu0_with("riscv,isa-extensions", &list(&["i", "m", "a", "sstc"]))));
        assert!(sstc_of(&cpu0_with("riscv,isa-extensions", &list(&["sstc", "zicsr"]))));
        for entries in [&["i", "sstcx"][..], &["ssstc"][..], &["zicsr_sstc"][..], &["i", "m"][..]] {
            assert!(!sstc_of(&cpu0_with("riscv,isa-extensions", &list(entries))), "{entries:?}");
        }
    }

    #[test]
    fn only_cpu0_itself_declares_sstc() {
        // Another hart.
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac")).end()
            .begin("cpu@1").prop("riscv,isa", &cstr("rv64imac_sstc")).end()
            .end().end().blob();
        assert!(!sstc_of(&blob), "cpu@1 is not cpu@0");
        // A name that merely starts with cpu@0.
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@00").prop("riscv,isa", &cstr("rv64imac_sstc")).end()
            .end().end().blob();
        assert!(!sstc_of(&blob), "cpu@00");
        // A child of cpu@0 carrying the property.
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").begin("interrupt-controller")
            .prop("riscv,isa", &cstr("rv64imac_sstc")).end().end()
            .end().end().blob();
        assert!(!sstc_of(&blob), "a child node of cpu@0");
        // A cpu@0 outside /cpus.
        let blob = Fdt::new().begin("").begin("soc")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac_sstc")).end()
            .end().end().blob();
        assert!(!sstc_of(&blob), "cpu@0 under /soc");
        // The positive control, with cpu@1 after it.
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac_sstc")).end()
            .begin("cpu@1").prop("riscv,isa", &cstr("rv64imac")).end()
            .end().end().blob();
        assert!(sstc_of(&blob));
    }

    // ── Zicboz + cboz-block-size from cpu@0 (RFC-0045 Tier 0 item 3) ───
    //
    // `isa_zicboz` and `cboz_block_size` gate whether the kernel ever emits
    // `cbo.zero`. A false positive on `isa_zicboz`, or trusting a bogus
    // block size, means the fast path is offered to a runtime probe that
    // should never have been asked — same exact-token discipline as Sstc.

    fn zicboz_of(blob: &[u8]) -> bool {
        unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob").isa_zicboz
    }

    fn cboz_block_size_of(blob: &[u8]) -> u32 {
        unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob").cboz_block_size
    }

    #[test]
    fn riscv_isa_with_a_zicboz_segment_sets_isa_zicboz() {
        assert!(zicboz_of(&cpu0_with("riscv,isa", &cstr("rv64imafdch_zicbom_zicboz"))));
        assert!(zicboz_of(&cpu0_with("riscv,isa", &cstr("rv64imac_zicboz_svadu"))));
        // The blob's own control: the same cpu@0 without it.
        assert!(!zicboz_of(&cpu0_with("riscv,isa", &cstr("rv64imac_zicsr_zifencei"))));
    }

    #[test]
    fn riscv_isa_segments_that_only_resemble_zicboz_do_not_count() {
        for isa in [
            "rv64imac_zicbozx",     // prefix of a longer extension
            "rv64imac_zzicboz",     // not a whole segment
            "rv64imac_zicsr_zicbozx",
            "rv64imac_zicbo",       // truncated
            "zicboz",               // the base segment is never an extension
            "rv64imaczicboz",       // no separator
        ] {
            assert!(!zicboz_of(&cpu0_with("riscv,isa", &cstr(isa))), "{isa}");
        }
    }

    #[test]
    fn riscv_isa_extensions_needs_an_exact_zicboz_entry() {
        let list = |entries: &[&str]| -> Vec<u8> {
            entries.iter().flat_map(|e| cstr(e)).collect()
        };
        assert!(zicboz_of(&cpu0_with("riscv,isa-extensions", &list(&["i", "m", "a", "zicboz"]))));
        assert!(zicboz_of(&cpu0_with("riscv,isa-extensions", &list(&["zicboz", "zicsr"]))));
        for entries in [&["i", "zicbozx"][..], &["zzicboz"][..], &["zicsr_zicboz"][..], &["i", "m"][..]] {
            assert!(!zicboz_of(&cpu0_with("riscv,isa-extensions", &list(entries))), "{entries:?}");
        }
    }

    #[test]
    fn only_cpu0_itself_declares_zicboz() {
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac")).end()
            .begin("cpu@1").prop("riscv,isa", &cstr("rv64imac_zicboz")).end()
            .end().end().blob();
        assert!(!zicboz_of(&blob), "cpu@1 is not cpu@0");
    }

    #[test]
    fn cboz_block_size_reads_the_u32_cell() {
        let blob = cpu0_with("riscv,cboz-block-size", &64u32.to_be_bytes());
        assert_eq!(cboz_block_size_of(&blob), 64);

        // QEMU's virt machine currently emits 0x40 (64); a differently
        // configured board must not be silently coerced to that value.
        let blob = cpu0_with("riscv,cboz-block-size", &128u32.to_be_bytes());
        assert_eq!(cboz_block_size_of(&blob), 128);
    }

    #[test]
    fn cboz_block_size_defaults_to_zero_when_absent_or_malformed() {
        // Absent entirely.
        let blob = cpu0_with("riscv,isa", &cstr("rv64imac"));
        assert_eq!(cboz_block_size_of(&blob), 0);

        // Wrong cell count (3 bytes instead of 4) — must not be read as a
        // truncated/garbage u32 rather than rejected outright.
        let blob = cpu0_with("riscv,cboz-block-size", &[0, 0, 64]);
        assert_eq!(cboz_block_size_of(&blob), 0);
    }

    #[test]
    fn cboz_block_size_only_from_cpu0() {
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac")).end()
            .begin("cpu@1").prop("riscv,cboz-block-size", &64u32.to_be_bytes()).end()
            .end().end().blob();
        assert_eq!(cboz_block_size_of(&blob), 0, "cpu@1 is not cpu@0");
    }

    // ── dtb_cpu_regs — hart→MPIDR/hart-id table (aarch64 SMP bring-up) ─

    #[test]
    fn cpu_regs_reads_one_cell_per_node_in_document_order() {
        // aarch64 QEMU virt shape: one address cell, reg = Aff2:Aff1:Aff0.
        let blob = Fdt::new().begin("").begin("cpus")
            .prop("#address-cells", &1u32.to_be_bytes())
            .prop("#size-cells", &0u32.to_be_bytes())
            .begin("cpu@0").prop("reg", &0u32.to_be_bytes()).end()
            .begin("cpu@1").prop("reg", &1u32.to_be_bytes()).end()
            .begin("cpu@2").prop("reg", &2u32.to_be_bytes()).end()
            .begin("cpu@3").prop("reg", &3u32.to_be_bytes()).end()
            .end().end().blob();

        let mut out = [0u64; 8];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }
            .expect("well-formed blob");
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &[0, 1, 2, 3]);
    }

    #[test]
    fn cpu_regs_reads_two_cells_when_address_cells_is_two() {
        // A cluster'd MPIDR: Aff3 in the high cell, Aff2:Aff1:Aff0 in the low.
        let blob = Fdt::new().begin("").begin("cpus")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &0u32.to_be_bytes())
            .begin("cpu@0").prop("reg", &[0u32.to_be_bytes(), 0u32.to_be_bytes()].concat()).end()
            .begin("cpu@100000000")
                .prop("reg", &[1u32.to_be_bytes(), 0u32.to_be_bytes()].concat()).end()
            .end().end().blob();

        let mut out = [0u64; 8];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }
            .expect("well-formed blob");
        assert_eq!(n, 2);
        assert_eq!(out[0], 0);
        assert_eq!(out[1], 1u64 << 32, "Aff3 (high cell) must land in bits [39:32]");
    }

    #[test]
    fn cpu_regs_truncates_at_out_len_but_still_reports_the_full_count() {
        let blob = Fdt::new().begin("").begin("cpus")
            .prop("#address-cells", &1u32.to_be_bytes())
            .begin("cpu@0").prop("reg", &0u32.to_be_bytes()).end()
            .begin("cpu@1").prop("reg", &1u32.to_be_bytes()).end()
            .begin("cpu@2").prop("reg", &2u32.to_be_bytes()).end()
            .end().end().blob();

        let mut out = [0u64; 2];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }
            .expect("well-formed blob");
        assert_eq!(n, 3, "the true count, even though only 2 fit in `out`");
        assert_eq!(&out[..2], &[0, 1]);
    }

    #[test]
    fn cpu_regs_ignores_non_cpu_nodes() {
        // A `reg` on a sibling node ( /soc/uart@... ) must not be mistaken
        // for a cpu's — only children of /cpus named `cpu@...` count.
        let blob = Fdt::new().begin("")
            .begin("soc").begin("uart@9000000")
                .prop("reg", &0x0900_0000u32.to_be_bytes()).end()
            .end()
            .begin("cpus")
                .prop("#address-cells", &1u32.to_be_bytes())
                .begin("cpu@0").prop("reg", &0u32.to_be_bytes()).end()
            .end()
            .end().blob();

        let mut out = [0u64; 8];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }
            .expect("well-formed blob");
        assert_eq!(n, 1, "only the real cpu@0, not the UART's reg");
        assert_eq!(out[0], 0);
    }

    #[test]
    fn cpu_regs_null_and_bad_magic_return_none() {
        assert!(unsafe { dtb_cpu_regs(core::ptr::null(), &mut [0u64; 8]) }.is_none());
        let mut buf = minimal_blob(17);
        buf[0] = 0xAA;
        assert!(unsafe { dtb_cpu_regs(buf.as_ptr(), &mut [0u64; 8]) }.is_none());
    }

    // ── #address-cells / #size-cells values the read logic cannot encode ──
    //
    // The critical finding of this audit: `parse_mem_reg` computed its
    // bounds check (`entry_bytes = (ac + sc) * 4`) from the *actual*
    // untrusted `ac`/`sc`, but its reads assumed only 1 or 2 cells (`if ac
    // == 2 { 8 bytes } else { 4 bytes }`, same for `sc`). For `#size-cells
    // == 0` specifically, `entry_bytes` accounted only for the address
    // cells, `prop_len == ac * 4` satisfied the check with nothing to
    // spare, and the size read at `data_off + ac * 4` then ran past the
    // property's own declared data — with nothing stopping it from running
    // past the whole blob. `#size-cells` is an ordinary property with no
    // depth restriction in the parser (same as `#address-cells`), so this
    // is reachable by placing it directly on `/memory` itself, no nesting
    // required.

    #[test]
    fn mem_reg_size_cells_zero_does_not_read_past_the_declared_property() {
        // Hand-rolled (not the `Fdt` helper) so the malicious `reg`
        // property's 4-byte payload can be made the *exact* last bytes
        // counted by `totalsize` — with 4 more, deliberately different,
        // bytes physically following it in the buffer. Those trailing
        // bytes stand in for "whatever is adjacent in real memory": on
        // real hardware that is unmapped/unrelated RAM (a load fault, i.e.
        // a board reset under `panic = "abort"`); here, to keep the test
        // itself free of actual undefined behaviour, they are ordinary
        // Vec-owned bytes the DTB never claims as its own (`totalsize`
        // stops well before them). The parser must never read them.
        //
        // Layout: header(40) | strings | struct(80, ending exactly at
        // totalsize) | 4 marker bytes (0xDE 0xAD 0xBE 0xEF, NOT counted by
        // totalsize). String offsets are computed, not hand-counted, to
        // avoid exactly the kind of off-by-one this test is not about.
        //
        // struct block:
        //   BEGIN_NODE ""                                     (8 bytes)
        //   BEGIN_NODE "memory@80000000"                       (20 bytes)
        //   PROP #address-cells = 1                            (16 bytes)
        //   PROP #size-cells    = 0                            (16 bytes)
        //   PROP reg            = 0x8000_0000 (4 bytes payload) (16 bytes)
        //                                                total = 76 bytes
        // No FDT_END / END_NODE tokens: `walk()` stops on its own totalsize
        // bound (proven by `unterminated_node_name_aborts_walk_instead_of_
        // scanning_past_blob` above), so none are needed for this test.
        let mut strings: Vec<u8> = Vec::new();
        let off_addr_cells = strings.len() as u32;
        strings.extend_from_slice(b"#address-cells\0");
        let off_size_cells = strings.len() as u32;
        strings.extend_from_slice(b"#size-cells\0");
        let off_reg = strings.len() as u32;
        strings.extend_from_slice(b"reg\0");

        let mut structs: Vec<u8> = Vec::new();
        // BEGIN_NODE "" (root).
        structs.extend_from_slice(&1u32.to_be_bytes());
        structs.extend_from_slice(&[0, 0, 0, 0]); // NUL + pad4
        // BEGIN_NODE "memory@80000000" (15 chars + NUL = 16, already 4-aligned).
        structs.extend_from_slice(&1u32.to_be_bytes());
        structs.extend_from_slice(b"memory@80000000\0");
        assert_eq!(b"memory@80000000\0".len() % 4, 0, "no padding needed");
        // PROP #address-cells = 1.
        structs.extend_from_slice(&3u32.to_be_bytes());
        structs.extend_from_slice(&4u32.to_be_bytes());
        structs.extend_from_slice(&off_addr_cells.to_be_bytes());
        structs.extend_from_slice(&1u32.to_be_bytes());
        // PROP #size-cells = 0 — the trigger.
        structs.extend_from_slice(&3u32.to_be_bytes());
        structs.extend_from_slice(&4u32.to_be_bytes());
        structs.extend_from_slice(&off_size_cells.to_be_bytes());
        structs.extend_from_slice(&0u32.to_be_bytes());
        // PROP reg = 0x8000_0000 (exactly `ac * 4` = 4 bytes: entry_bytes
        // == prop_len, the tightest case).
        structs.extend_from_slice(&3u32.to_be_bytes());
        structs.extend_from_slice(&4u32.to_be_bytes());
        structs.extend_from_slice(&off_reg.to_be_bytes());
        structs.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        assert_eq!(structs.len(), 76, "layout comment above must match");

        let off_dt_strings: u32 = 40;
        let off_dt_struct: u32 = off_dt_strings + strings.len() as u32;
        let totalsize: u32 = off_dt_struct + structs.len() as u32;

        let mut hdr = minimal_header(17, totalsize);
        hdr[8..12].copy_from_slice(&off_dt_struct.to_be_bytes());
        hdr[12..16].copy_from_slice(&off_dt_strings.to_be_bytes());
        hdr[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());

        let mut buf = hdr.to_vec();
        buf.extend_from_slice(&strings);
        buf.extend_from_slice(&structs);
        assert_eq!(buf.len(), totalsize as usize,
            "the malicious reg's data must be the exact last bytes counted by totalsize");
        // Marker bytes: NOT part of the blob (past totalsize), present only
        // so the read this test guards against is Vec-owned memory rather
        // than genuine out-of-bounds UB.
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let info = unsafe { dtb_parse(buf.as_ptr()) }
            .expect("header and strings are well-formed");
        // mem_size first, deliberately: on HEAD this assertion fails with
        // `left: 0xDEADBEEF`, the marker bytes read straight back out —
        // direct, printed evidence that HEAD reads past `totalsize`.
        assert_eq!(info.mem_size, 0,
            "must never surface the marker bytes (0xDEADBEEF) as mem_size — \
             that would be the out-of-bounds read this test exists to catch");
        assert_eq!(info.mem_base, 0,
            "a #size-cells=0 /memory reg must be refused, not partially trusted");
    }

    #[test]
    fn mem_reg_refuses_size_cells_zero_even_mid_blob() {
        // Same trigger, ordinary (non-adjacent-boundary) placement: pins
        // the *semantic* contract (refuse, don't misread) independent of
        // the previous test's out-of-bounds framing.
        let blob = Fdt::new().begin("").begin("memory@80000000")
            .prop("#address-cells", &1u32.to_be_bytes())
            .prop("#size-cells", &0u32.to_be_bytes())
            .prop("reg", &0x8000_0000u32.to_be_bytes())
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0);
        assert_eq!(info.mem_size, 0);
    }

    #[test]
    fn mem_reg_refuses_address_cells_zero() {
        let blob = Fdt::new().begin("").begin("memory@80000000")
            .prop("#address-cells", &0u32.to_be_bytes())
            .prop("#size-cells", &1u32.to_be_bytes())
            .prop("reg", &0x8000_0000u32.to_be_bytes())
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0);
        assert_eq!(info.mem_size, 0);
    }

    #[test]
    fn mem_reg_refuses_address_cells_above_two() {
        let mut reg = Vec::new();
        reg.extend_from_slice(&[0u8; 12]); // 3 cells of "address"
        reg.extend_from_slice(&0x100_0000u32.to_be_bytes());
        let blob = Fdt::new().begin("").begin("memory@80000000")
            .prop("#address-cells", &3u32.to_be_bytes())
            .prop("#size-cells", &1u32.to_be_bytes())
            .prop("reg", &reg)
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0);
        assert_eq!(info.mem_size, 0);
    }

    #[test]
    fn mem_reg_still_parses_normal_one_and_two_cell_layouts() {
        // Regression control: the two shapes every real board this tree
        // supports actually emits must keep working exactly as before.
        // 1-cell address, 1-cell size (32-bit platforms).
        let blob = Fdt::new().begin("").begin("memory@80000000")
            .prop("#address-cells", &1u32.to_be_bytes())
            .prop("#size-cells", &1u32.to_be_bytes())
            .prop("reg", &[0x8000_0000u32.to_be_bytes(), 0x800_0000u32.to_be_bytes()].concat())
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0x8000_0000);
        assert_eq!(info.mem_size, 0x800_0000);

        // 2-cell address, 2-cell size (QEMU virt's actual shape).
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x8000_0000u64.to_be_bytes());
        reg.extend_from_slice(&0x1_0000_0000u64.to_be_bytes());
        let blob = Fdt::new().begin("").begin("memory@80000000")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .prop("reg", &reg)
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0x8000_0000);
        assert_eq!(info.mem_size, 0x1_0000_0000);
    }

    #[test]
    fn mem_reg_nested_child_does_not_overwrite_parents_reg() {
        // `in_memory` is not depth-scoped by itself (only reset when we
        // leave depth 2) — a `reg` on a node NESTED under /memory must not
        // be mistaken for /memory's own. Real DTBs never nest a
        // `reg`-bearing child under /memory, so this blob is adversarial by
        // construction.
        let mut good_reg = Vec::new();
        good_reg.extend_from_slice(&0x8000_0000u64.to_be_bytes());
        good_reg.extend_from_slice(&0x800_0000u64.to_be_bytes());
        let mut evil_reg = Vec::new();
        evil_reg.extend_from_slice(&0xDEAD_0000u64.to_be_bytes());
        evil_reg.extend_from_slice(&0xFFFF_FFFFu64.to_be_bytes());

        let blob = Fdt::new().begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("memory@80000000")
                .prop("reg", &good_reg)
                .begin("evil-child").prop("reg", &evil_reg).end()
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.mem_base, 0x8000_0000, "the child's reg must not win");
        assert_eq!(info.mem_size, 0x800_0000);
    }

    #[test]
    fn timebase_frequency_from_a_grandchild_of_cpus_is_ignored() {
        // `timebase-frequency` matching used to be `in_cpus || in_cpu_child`
        // with no depth check — true for every descendant of /cpus, not
        // just /cpus itself (depth 2) or a direct cpu@N child (depth 3). A
        // property on `/cpus/cpu@0/interrupt-controller` (depth 4) is
        // neither, and must not set `timer_freq`, which the kernel
        // compares against its own hardcoded constant to decide whether
        // "every µs/ms calculation... will drift" (kernel/src/main.rs).
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0")
                .begin("interrupt-controller")
                    .prop("timebase-frequency", &999u32.to_be_bytes())
                .end()
            .end()
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.timer_freq, 0,
            "a grandchild of /cpus must not set timer_freq");
    }

    // ── Same #address-cells discipline for cpu reg and UART/PLIC reg ──────

    #[test]
    fn cpu_reg_refuses_address_cells_zero() {
        let blob = Fdt::new().begin("").begin("cpus")
            .prop("#address-cells", &0u32.to_be_bytes())
            .begin("cpu@0").prop("reg", &0u32.to_be_bytes()).end()
            .end().end().blob();
        let mut out = [0u64; 8];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }.expect("well-formed blob");
        // `dtb_cpu_regs`'s returned count is `cpu_reg_count` — entries
        // actually recorded, which an unreadable `reg` must NOT inflate.
        assert_eq!(n, 0, "an address-cells=0 reg must not be recorded");
        // `DtbInfo::num_cpus` is a separate counter (every `cpu@` node,
        // incremented in `handle_begin_node` independently of whether its
        // `reg` parsed) and must still see the node.
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.num_cpus, 1);
    }

    #[test]
    fn uart_reg_refuses_address_cells_above_two() {
        // NOT `#address-cells = 0` — HEAD's `read_addr` already special-
        // cased that (`min == 0` returns 0 unconditionally), so it does not
        // discriminate before/after this fix. `ac = 3` is the case that
        // does: HEAD's `if ac >= 2 { read_be64 }` fires for ANY ac >= 2,
        // reading the first two of the three declared cells as one 64-bit
        // value instead of refusing a cell count it cannot correctly
        // decode. cell0=0, cell1=0x1000_0000, cell2=0xAAAA_AAAA (never
        // read by either version — proves neither version reads a 3rd
        // cell): HEAD's `read_be64` over cell0..cell1 yields 0x1000_0000
        // (wrong, but nonzero); the fix refuses the whole property.
        let mut reg = Vec::new();
        reg.extend_from_slice(&0u32.to_be_bytes());
        reg.extend_from_slice(&0x1000_0000u32.to_be_bytes());
        reg.extend_from_slice(&0xAAAA_AAAAu32.to_be_bytes());
        let blob = Fdt::new().begin("").begin("soc")
            .begin("uart@10000000")
                .prop("#address-cells", &3u32.to_be_bytes())
                .prop("reg", &reg)
            .end()
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.uart_base, 0,
            "an address-cells=3 reg must be refused, not misread as 2 cells");
    }

    #[test]
    fn uart_reg_nested_child_does_not_overwrite_parents_reg() {
        // The UART node deliberately has NO `reg` of its own: HEAD's
        // "take only the first one found" (`info.uart_base == 0`) guard
        // would otherwise already block the child regardless of depth
        // scoping, masking the very bug this test exists to catch. With no
        // parent `reg`, `uart_base` stays 0 until *something* sets it —
        // proving whether that something is allowed to be a nested child's
        // `reg` is exactly the depth-scoping question.
        let blob = Fdt::new().begin("").begin("soc")
            .begin("uart@10000000")
                .prop("#address-cells", &1u32.to_be_bytes())
                .begin("evil-child")
                    .prop("reg", &0xDEAD_0000u32.to_be_bytes())
                .end()
            .end()
            .end().end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.uart_base, 0,
            "a nested child's reg must not be mistaken for the UART's own");
    }

    // ── AIA (APLIC/IMSIC) discovery, RFC-0046 stage 1a ────────
    //
    // Node shapes below mirror QEMU's `-machine virt,aia=aplic-imsic
    // -smp 4` device tree (`dumpdtb=`): two `riscv,aplic`
    // nodes (an M-domain root with `riscv,children`, and the S-domain
    // leaf without it) and two `riscv,imsics` nodes (M-level raising
    // cause 11, S-level raising cause 9).

    /// A multi-string `compatible` property value: each string NUL-
    /// terminated and concatenated, exactly as dtc encodes it.
    fn compat(strs: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for s in strs {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v
    }

    /// A `reg` value for `#address-cells = <2>, #size-cells = <2>` (the
    /// real machine's root default) — `addr` and `size` each as one be64.
    fn reg64(addr: u64, size: u64) -> Vec<u8> {
        let mut v = addr.to_be_bytes().to_vec();
        v.extend_from_slice(&size.to_be_bytes());
        v
    }

    /// An `interrupts-extended` value: `n` (phandle, cause) pairs, all
    /// raising the same `cause` (phandle values are never resolved by
    /// this parser, so any nonzero placeholder is fine).
    fn interrupts_extended_same_cause(n: u32, cause: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for phandle in 1..=n {
            v.extend_from_slice(&phandle.to_be_bytes());
            v.extend_from_slice(&cause.to_be_bytes());
        }
        v
    }

    #[test]
    fn aia_selects_the_leaf_aplic_not_the_children_root() {
        let blob = Fdt::new().begin("")
            .begin("interrupt-controller@c000000") // M-domain root
                .prop("compatible", &compat(&["qemu,aplic", "riscv,aplic"]))
                .prop("riscv,children", &1u32.to_be_bytes())
                .prop("riscv,num-sources", &0x60u32.to_be_bytes())
                .prop("reg", &reg64(0xc00_0000, 0x8000))
            .end()
            .begin("interrupt-controller@d000000") // S-domain leaf
                .prop("compatible", &compat(&["qemu,aplic", "riscv,aplic"]))
                .prop("riscv,num-sources", &0x60u32.to_be_bytes())
                .prop("reg", &reg64(0xd00_0000, 0x8000))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.aplic_base, 0xd00_0000, "must pick the leaf (S-domain), not the root with riscv,children");
        assert_eq!(info.aplic_num_sources, 0x60);
    }

    #[test]
    fn aia_selects_the_s_level_imsic_by_cause_9_not_document_order() {
        // M-level (cause 11) is declared FIRST — proves the S-external
        // cause check decides this, not "first imsics node wins".
        let blob = Fdt::new().begin("")
            .begin("interrupt-controller@24000000") // M-level
                .prop("compatible", &compat(&["qemu,imsics", "riscv,imsics"]))
                .prop("riscv,num-ids", &0xffu32.to_be_bytes())
                .prop("interrupts-extended", &interrupts_extended_same_cause(4, 11))
                .prop("reg", &reg64(0x2400_0000, 0x4000))
            .end()
            .begin("interrupt-controller@28000000") // S-level
                .prop("compatible", &compat(&["qemu,imsics", "riscv,imsics"]))
                .prop("riscv,num-ids", &0xffu32.to_be_bytes())
                .prop("interrupts-extended", &interrupts_extended_same_cause(4, 9))
                .prop("reg", &reg64(0x2800_0000, 0x4000))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.imsic_base, 0x2800_0000, "must pick the S-level (cause 9) group, not the first one in document order");
        assert_eq!(info.imsic_num_ids, 0xff);
    }

    #[test]
    fn aia_reg_before_compatible_in_document_order_still_classifies_correctly() {
        // Same shape as the real dumped DTB: `reg` appears BEFORE
        // `compatible` in this node's own property list. A property-order
        // commit (the `plic_base` style) would have already had to guess;
        // this proves the end-of-node commit does not depend on order.
        let blob = Fdt::new().begin("")
            .begin("interrupt-controller@d000000")
                .prop("riscv,num-sources", &0x60u32.to_be_bytes())
                .prop("reg", &reg64(0xd00_0000, 0x8000))
                .prop("compatible", &compat(&["qemu,aplic", "riscv,aplic"]))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.aplic_base, 0xd00_0000);
    }

    #[test]
    fn aia_fields_stay_zero_with_only_a_plain_plic_present() {
        // Plain `virt` (no AIA): existing `plic_base` behaviour must be
        // completely unchanged, and the new fields must NOT false-positive.
        let blob = Fdt::new().begin("")
            .begin("plic@c000000")
                .prop("compatible", &compat(&["sifive,plic-1.0.0", "riscv,plic0"]))
                .prop("reg", &reg64(0xc00_0000, 0x40_0000))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.plic_base, 0xc00_0000, "plain-virt PLIC discovery must be unchanged");
        assert_eq!(info.aplic_base, 0, "a plain PLIC must never be mistaken for an APLIC");
        assert_eq!(info.imsic_base, 0);
    }

    #[test]
    fn aia_guest_index_bits_captured_when_present_zero_otherwise() {
        let with_guest_bits = Fdt::new().begin("")
            .begin("interrupt-controller@28000000")
                .prop("compatible", &compat(&["riscv,imsics"]))
                .prop("interrupts-extended", &interrupts_extended_same_cause(1, 9))
                .prop("riscv,guest-index-bits", &2u32.to_be_bytes())
                .prop("reg", &reg64(0x2800_0000, 0x4000))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(with_guest_bits.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.imsic_guest_index_bits, 2);

        let without = Fdt::new().begin("")
            .begin("interrupt-controller@28000000")
                .prop("compatible", &compat(&["riscv,imsics"]))
                .prop("interrupts-extended", &interrupts_extended_same_cause(1, 9))
                .prop("reg", &reg64(0x2800_0000, 0x4000))
            .end()
            .end().blob();
        let info2 = unsafe { dtb_parse(without.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info2.imsic_guest_index_bits, 0, "absent property must default to 0, not leak a stale value");
    }

    // ── dtb_pl011_irq: the aarch64 console line (wave 7 CON) ──────────────

    fn cells3(a: u32, b: u32, c: u32) -> Vec<u8> {
        let mut v = a.to_be_bytes().to_vec();
        v.extend_from_slice(&b.to_be_bytes());
        v.extend_from_slice(&c.to_be_bytes());
        v
    }

    /// QEMU `virt` (11.0, `-M virt,gic-version=3,dumpdtb=`) writes the node
    /// as `pl011@9000000 { clock-names; clocks; interrupts = <0 1 4>; reg;
    /// compatible = "arm,pl011", "arm,primecell"; }` — `interrupts` and
    /// `reg` BEFORE `compatible`, so the kind of node is unknown when they
    /// are read. Same property order here.
    fn virt_like(node: &str, interrupts: &[u8], compat_list: &[&str]) -> Vec<u8> {
        Fdt::new().begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("serial-lookalike@1000")
                .prop("interrupts", &cells3(0, 7, 4))
                .prop("reg", &reg64(0x1000, 0x1000))
                .prop("compatible", &compat(&["ns16550a"]))
            .end()
            .begin(node)
                .prop("clock-names", &compat(&["uartclk", "apb_pclk"]))
                .prop("interrupts", interrupts)
                .prop("reg", &reg64(0x0900_0000, 0x1000))
                .prop("compatible", &compat(compat_list))
            .end()
            .end().blob()
    }

    #[test]
    fn pl011_spi_1_level_is_intid_33() {
        let blob = virt_like("pl011@9000000", &cells3(0, 1, 4), &["arm,pl011", "arm,primecell"]);
        let got = unsafe { azos_dtb::dtb_pl011_irq(blob.as_ptr()) };
        assert_eq!(got, Some(azos_dtb::Pl011Irq { base: 0x0900_0000, intid: 33, edge: false }));
    }

    #[test]
    fn pl011_matched_by_compatible_not_by_name() {
        // A node named `pl011@...` that is not one, and a PL011 whose node
        // name says nothing.
        let not_one = virt_like("pl011@9000000", &cells3(0, 1, 4), &["arm,primecell"]);
        assert_eq!(unsafe { azos_dtb::dtb_pl011_irq(not_one.as_ptr()) }, None);
        let renamed = virt_like("serial@9000000", &cells3(0, 5, 1), &["arm,pl011"]);
        assert_eq!(unsafe { azos_dtb::dtb_pl011_irq(renamed.as_ptr()) },
            Some(azos_dtb::Pl011Irq { base: 0x0900_0000, intid: 37, edge: true }));
    }

    #[test]
    fn pl011_refuses_what_it_cannot_decode() {
        // Two cells (a non-GIC interrupt parent), a PPI, a special INTID,
        // and an undefined trigger nibble.
        for bad in [
            1u32.to_be_bytes().iter().chain(1u32.to_be_bytes().iter()).copied().collect::<Vec<u8>>(),
            cells3(1, 1, 4),
            cells3(0, 988, 4),
            cells3(0, 1, 0),
        ] {
            let blob = virt_like("pl011@9000000", &bad, &["arm,pl011"]);
            assert_eq!(unsafe { azos_dtb::dtb_pl011_irq(blob.as_ptr()) }, None, "{:?}", bad);
        }
    }

    #[test]
    fn pl011_props_of_a_child_do_not_leak_into_the_parent() {
        // The PL011's own `interrupts` is missing; a child node carries one.
        let blob = Fdt::new().begin("")
            .begin("pl011@9000000")
                .prop("reg", &reg64(0x0900_0000, 0x1000))
                .prop("compatible", &compat(&["arm,pl011"]))
                .begin("child")
                    .prop("interrupts", &cells3(0, 1, 4))
                .end()
            .end()
            .end().blob();
        assert_eq!(unsafe { azos_dtb::dtb_pl011_irq(blob.as_ptr()) }, None);
    }

    // ── PLIC vs AIA: `plic_base` only from a PLIC-compatible node ────────
    //
    // `plic_base` used to be the first interrupt controller's `reg`,
    // whatever it was. On `virt,aia=aplic-imsic` that is an APLIC, so the
    // boot line printed `PLIC=0xc000000` on a machine without a PLIC.

    /// The AIA machine's controllers, `reg` before `compatible` as in
    /// QEMU's own blob: an M-domain APLIC root, the S-domain leaf, and the
    /// S-level IMSIC group. No PLIC anywhere.
    fn aia_machine() -> Vec<u8> {
        Fdt::new().begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("interrupt-controller@c000000")
                .prop("riscv,children", &1u32.to_be_bytes())
                .prop("riscv,num-sources", &0x60u32.to_be_bytes())
                .prop("reg", &reg64(0xc00_0000, 0x8000))
                .prop("compatible", &compat(&["qemu,aplic", "riscv,aplic"]))
            .end()
            .begin("interrupt-controller@d000000")
                .prop("riscv,num-sources", &0x60u32.to_be_bytes())
                .prop("reg", &reg64(0xd00_0000, 0x8000))
                .prop("compatible", &compat(&["qemu,aplic", "riscv,aplic"]))
            .end()
            .begin("interrupt-controller@28000000")
                .prop("riscv,num-ids", &0xffu32.to_be_bytes())
                .prop("interrupts-extended", &interrupts_extended_same_cause(4, 9))
                .prop("reg", &reg64(0x2800_0000, 0x4000))
                .prop("compatible", &compat(&["qemu,imsics", "riscv,imsics"]))
            .end()
            .end().blob()
    }

    #[test]
    fn plic_base_is_zero_on_the_aia_machine() {
        let info = unsafe { dtb_parse(aia_machine().as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.plic_base, 0, "an APLIC is not a PLIC");
        assert_eq!(info.aplic_base, 0xd00_0000);
        assert_eq!(info.imsic_base, 0x2800_0000);
    }

    #[test]
    fn plic_base_found_when_its_compatible_follows_its_reg() {
        for c in [&["sifive,plic-1.0.0", "riscv,plic0"][..], &["riscv,plic0"][..], &["sifive,plic-1.0.0"][..]] {
            let blob = Fdt::new().begin("")
                .begin("interrupt-controller@c000000")
                    .prop("reg", &reg64(0xc00_0000, 0x60_0000))
                    .prop("compatible", &compat(c))
                .end()
                .end().blob();
            let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
            assert_eq!(info.plic_base, 0xc00_0000, "{:?}", c);
        }
    }

    #[test]
    fn plic_base_skips_a_non_plic_controller_declared_first() {
        let blob = Fdt::new().begin("")
            .begin("interrupt-controller@2000000")
                .prop("reg", &reg64(0x200_0000, 0x1000))
                .prop("compatible", &compat(&["vendor,other-intc"]))
            .end()
            .begin("plic@c000000")
                .prop("reg", &reg64(0xc00_0000, 0x60_0000))
                .prop("compatible", &compat(&["riscv,plic0"]))
            .end()
            .end().blob();
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob");
        assert_eq!(info.plic_base, 0xc00_0000);
    }

    // ── PCI host bridge: ECAM `reg` and `ranges` (`dtb_pci_host`) ────────

    /// One `ranges` entry: 3 PCI cells, 2 CPU cells, 2 size cells.
    fn range(hi: u32, bus: u64, cpu: u64, size: u64) -> Vec<u8> {
        let mut v = hi.to_be_bytes().to_vec();
        v.extend_from_slice(&bus.to_be_bytes());
        v.extend_from_slice(&cpu.to_be_bytes());
        v.extend_from_slice(&size.to_be_bytes());
        v
    }

    /// QEMU riscv64 `virt`'s host bridge (`/soc/pci@30000000`), property
    /// order as in its dumped blob (`ranges` and `reg` after the cells).
    fn riscv_virt_pci(extra_first: bool) -> Vec<u8> {
        let mut ranges = range(0x0100_0000, 0, 0x300_0000, 0x1_0000);
        ranges.extend(range(0x0200_0000, 0x4000_0000, 0x4000_0000, 0x4000_0000));
        ranges.extend(range(0x0300_0000, 0x4_0000_0000, 0x4_0000_0000, 0x4_0000_0000));
        let mut f = Fdt::new();
        f.begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("soc")
                .prop("#address-cells", &2u32.to_be_bytes())
                .prop("#size-cells", &2u32.to_be_bytes());
        if extra_first {
            // A second host bridge that is NOT ECAM-generic, before the real one.
            f.begin("pci@20000000")
                .prop("compatible", &compat(&["vendor,other-pci"]))
                .prop("reg", &reg64(0x2000_0000, 0x100_0000))
            .end();
        }
        f.begin("pci@30000000")
                .prop("interrupt-map-mask", &[0u8; 16])
                .prop("ranges", &ranges)
                .prop("reg", &reg64(0x3000_0000, 0x1000_0000))
                .prop("dma-coherent", &[])
                .prop("bus-range", &[0, 0, 0, 0, 0, 0, 0, 0xff])
                .prop("linux,pci-domain", &0u32.to_be_bytes())
                .prop("device_type", &cstr("pci"))
                .prop("compatible", &compat(&["pci-host-ecam-generic"]))
                .prop("#size-cells", &2u32.to_be_bytes())
                .prop("#interrupt-cells", &1u32.to_be_bytes())
                .prop("#address-cells", &3u32.to_be_bytes())
            .end()
            .end()
            .end();
        f.blob()
    }

    #[test]
    fn pci_host_riscv_virt_ecam_and_three_windows() {
        let got = unsafe { azos_dtb::dtb_pci_host(riscv_virt_pci(false).as_ptr()) }
            .expect("the ECAM host bridge is found");
        assert_eq!((got.ecam_base, got.ecam_size), (0x3000_0000, 0x1000_0000));
        let w = |cpu, bus, size| Some(azos_dtb::PciWindow { cpu_base: cpu, bus_base: bus, size, prefetchable: false });
        assert_eq!(got.io, w(0x300_0000, 0, 0x1_0000));
        assert_eq!(got.mem32, w(0x4000_0000, 0x4000_0000, 0x4000_0000));
        assert_eq!(got.mem64, w(0x4_0000_0000, 0x4_0000_0000, 0x4_0000_0000));
    }

    #[test]
    fn pci_host_matched_by_compatible_not_by_position() {
        let got = unsafe { azos_dtb::dtb_pci_host(riscv_virt_pci(true).as_ptr()) }
            .expect("the ECAM host bridge is found");
        assert_eq!(got.ecam_base, 0x3000_0000, "the non-ECAM bridge declared first must be skipped");
    }

    #[test]
    fn pci_host_absent_is_none() {
        assert_eq!(unsafe { azos_dtb::dtb_pci_host(aia_machine().as_ptr()) }, None);
    }

    /// aarch64 `virt` with `highmem-ecam`: the node is at the root and its
    /// ECAM `reg` has a nonzero high cell.
    #[test]
    fn pci_host_aarch64_virt_high_ecam() {
        let mut ranges = range(0x0100_0000, 0, 0x3eff_0000, 0x1_0000);
        ranges.extend(range(0x0200_0000, 0x1000_0000, 0x1000_0000, 0x2eff_0000));
        ranges.extend(range(0x0300_0000, 0x80_0000_0000, 0x80_0000_0000, 0x80_0000_0000));
        let blob = Fdt::new().begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@10000000")
                .prop("#address-cells", &3u32.to_be_bytes())
                .prop("#size-cells", &2u32.to_be_bytes())
                .prop("ranges", &ranges)
                .prop("reg", &reg64(0x40_1000_0000, 0x1000_0000))
                .prop("compatible", &compat(&["pci-host-ecam-generic"]))
                .begin("child-with-reg")
                    .prop("reg", &reg64(0xdead_0000, 0x1000))
                .end()
            .end()
            .end().blob();
        let got = unsafe { azos_dtb::dtb_pci_host(blob.as_ptr()) }.expect("found");
        assert_eq!((got.ecam_base, got.ecam_size), (0x40_1000_0000, 0x1000_0000),
            "reg is read with the PARENT's cells even though the node's own #address-cells = 3 came first");
        assert_eq!(got.mem32.map(|w| (w.cpu_base, w.size)), Some((0x1000_0000, 0x2eff_0000)));
        assert_eq!(got.mem64.map(|w| w.cpu_base), Some(0x80_0000_0000));
    }

    #[test]
    fn pci_ranges_decoder_space_codes_prefetch_and_bad_cells() {
        use azos_dtb::decode_pci_ranges;
        // Config space (00) ignored, prefetchable 64-bit memory, and a
        // trailing partial entry ignored.
        let mut r = range(0x0000_0000, 0, 0x1000, 0x1000);
        r.extend(range(0x4300_0000, 0x8000_0000, 0x1_8000_0000, 0x1000_0000));
        r.extend_from_slice(&[0u8; 12]);
        let got = decode_pci_ranges(&r, 3, 2, 2);
        assert_eq!(got.io, None);
        assert_eq!(got.mem32, None);
        assert_eq!(got.mem64, Some(azos_dtb::PciWindow {
            cpu_base: 0x1_8000_0000, bus_base: 0x8000_0000, size: 0x1000_0000, prefetchable: true,
        }));
        // First entry of a space wins.
        let mut two = range(0x0200_0000, 0x1000, 0x1000, 0x100);
        two.extend(range(0x0200_0000, 0x2000, 0x2000, 0x100));
        assert_eq!(decode_pci_ranges(&two, 3, 2, 2).mem32.map(|w| w.cpu_base), Some(0x1000));
        // One-cell CPU address and size.
        let mut one = 0x0200_0000u32.to_be_bytes().to_vec();
        one.extend_from_slice(&0x4000_0000u64.to_be_bytes());
        one.extend_from_slice(&0x4000_0000u32.to_be_bytes());
        one.extend_from_slice(&0x100_0000u32.to_be_bytes());
        assert_eq!(decode_pci_ranges(&one, 3, 1, 1).mem32.map(|w| (w.cpu_base, w.size)),
            Some((0x4000_0000, 0x100_0000)));
        // Cell counts outside the PCI binding decode as nothing.
        assert_eq!(decode_pci_ranges(&r, 2, 2, 2), azos_dtb::PciRanges::default());
        assert_eq!(decode_pci_ranges(&r, 3, 3, 2), azos_dtb::PciRanges::default());
    }

    // ── Real QEMU 11.0 blobs (`fixtures/`, `-machine ...,dumpdtb=`) ──────
    //
    // Dumped with the gate's own machine options: riscv64 `virt` and
    // `virt,aia=aplic-imsic` (`-smp 4`), aarch64 `virt,gic-version=3 -cpu
    // max,pauth=on -smp 2` (recompiled with `dtc -I dtb -O dtb` to drop
    // QEMU's 1 MiB padding; node and property order unchanged).

    fn fixture(bytes: &[u8]) -> Vec<u8> { bytes.to_vec() }

    #[test]
    fn qemu_riscv64_virt_plic_and_pci() {
        let b = fixture(include_bytes!("../fixtures/qemu-riscv64-virt.dtb"));
        let info = unsafe { dtb_parse(b.as_ptr()) }.expect("QEMU blob parses");
        assert_eq!(info.plic_base, 0xc00_0000);
        assert_eq!((info.aplic_base, info.imsic_base), (0, 0));
        let h = unsafe { azos_dtb::dtb_pci_host(b.as_ptr()) }.expect("pci@30000000");
        assert_eq!((h.ecam_base, h.ecam_size), (0x3000_0000, 0x1000_0000));
        assert_eq!(h.mem32.map(|w| (w.cpu_base, w.bus_base, w.size)),
            Some((0x4000_0000, 0x4000_0000, 0x4000_0000)));
        assert_eq!(h.mem64.map(|w| (w.cpu_base, w.size)), Some((0x4_0000_0000, 0x4_0000_0000)));
        assert_eq!(h.io.map(|w| (w.cpu_base, w.size)), Some((0x300_0000, 0x1_0000)));
    }

    #[test]
    fn qemu_riscv64_virt_aia_has_no_plic() {
        let b = fixture(include_bytes!("../fixtures/qemu-riscv64-virt-aia.dtb"));
        let info = unsafe { dtb_parse(b.as_ptr()) }.expect("QEMU blob parses");
        assert_eq!(info.plic_base, 0, "the AIA machine has no PLIC");
        assert_eq!(info.aplic_base, 0xd00_0000);
        assert_ne!(info.imsic_base, 0);
        let h = unsafe { azos_dtb::dtb_pci_host(b.as_ptr()) }.expect("pci@30000000");
        assert_eq!(h.ecam_base, 0x3000_0000);
        assert_eq!(h.mem32.map(|w| w.cpu_base), Some(0x4000_0000));
    }

    #[test]
    fn qemu_aarch64_virt_pci_high_ecam() {
        let b = fixture(include_bytes!("../fixtures/qemu-aarch64-virt.dtb"));
        let h = unsafe { azos_dtb::dtb_pci_host(b.as_ptr()) }.expect("pcie@10000000");
        assert_eq!((h.ecam_base, h.ecam_size), (0x40_1000_0000, 0x1000_0000));
        assert_eq!(h.mem32.map(|w| (w.cpu_base, w.bus_base, w.size)),
            Some((0x1000_0000, 0x1000_0000, 0x2eff_0000)));
        assert_eq!(h.mem64.map(|w| (w.cpu_base, w.size)), Some((0x80_0000_0000, 0x80_0000_0000)));
        assert_eq!(h.io.map(|w| w.cpu_base), Some(0x3eff_0000));
    }

    // ── dtb_irq_triggers: trigger type per line (wave 9 IRQ4 item 3) ─────
    //
    // Shapes from QEMU 11.0's own dumps (`dumpdtb=`): aarch64 `virt` puts
    // `interrupt-parent` on the root only (GIC phandle), virtio-mmio SPIs are
    // edge `<0 n 1>`, PL031 level `<0 2 4>`, the timer PPIs `<1 n 4>`;
    // riscv64 `virt,aia=aplic-imsic` puts `interrupts = <src 4>` BEFORE the
    // node's own `interrupt-parent`, and has an M-domain APLIC (with
    // `riscv,children`) besides the S-domain one.

    use azos_dtb::{dtb_irq_triggers, IrqController};

    fn one(v: u32) -> Vec<u8> { v.to_be_bytes().to_vec() }
    fn cells2(a: u32, b: u32) -> Vec<u8> {
        let mut v = a.to_be_bytes().to_vec();
        v.extend_from_slice(&b.to_be_bytes());
        v
    }

    fn gic_virt() -> Vec<u8> {
        let mut timer = cells3(1, 13, 4);
        timer.extend_from_slice(&cells3(1, 14, 4));
        Fdt::new().begin("")
            .prop("interrupt-parent", &one(0x8002))
            .begin("pl031@9010000")
                .prop("interrupts", &cells3(0, 2, 4))
                .prop("compatible", &compat(&["arm,pl031", "arm,primecell"]))
            .end()
            .begin("virtio_mmio@a000000")
                .prop("interrupts", &cells3(0, 16, 1))
            .end()
            .begin("intc@8000000")
                .prop("phandle", &one(0x8002))
                .prop("interrupt-controller", &[])
                .prop("#interrupt-cells", &one(3))
                .prop("compatible", &compat(&["arm,gic-v3"]))
            .end()
            .begin("timer")
                .prop("interrupts", &timer)
            .end()
            .begin("gpio-keys-lookalike")
                // Another parent: not decoded as a GIC specifier.
                .prop("interrupt-parent", &one(0x9999))
                .prop("interrupts", &cells3(0, 5, 1))
            .end()
            .end().blob()
    }

    /// Level and edge SPIs decode to their INTIDs with the right trigger; a
    /// PPI and a node under another parent are not recorded.
    ///
    /// Canary: decode `flags & 0xf == 1` as level in `decode_trigger_flags`
    /// — INTID 48 reads `Some(false)`.
    #[test]
    fn gic_spis_decode_with_their_trigger() {
        let blob = gic_virt();
        let t = unsafe { dtb_irq_triggers(blob.as_ptr(), IrqController::GicV3) }.expect("GIC found");
        assert_eq!(t.edge(34), Some(false), "PL031 <0 2 4> is level INTID 34");
        assert_eq!(t.edge(48), Some(true), "virtio-mmio <0 16 1> is edge INTID 48");
        assert_eq!(t.edge(29), None, "a PPI is not an SPI");
        assert_eq!(t.edge(37), None, "a node under another interrupt-parent");
        assert_eq!(t.counts(), (2, 1));
    }

    fn aplic_virt(s_first: bool) -> Vec<u8> {
        let mut f = Fdt::new();
        f.begin("").begin("soc");
        f.begin("rtc@101000")
            .prop("interrupts", &cells2(11, 4))
            .prop("interrupt-parent", &one(0x0c))
            .end();
        f.begin("edge-dev@2000")
            .prop("interrupts", &cells2(12, 1))
            .prop("interrupt-parent", &one(0x0c))
            .end();
        let m = |f: &mut Fdt| {
            f.begin("interrupt-controller@c000000")
                .prop("phandle", &one(0x0b))
                .prop("riscv,children", &one(0x0c))
                .prop("#interrupt-cells", &one(2))
                .prop("interrupt-controller", &[])
                .prop("compatible", &compat(&["riscv,aplic"]))
                .end();
        };
        let sdom = |f: &mut Fdt| {
            f.begin("interrupt-controller@d000000")
                .prop("phandle", &one(0x0c))
                .prop("#interrupt-cells", &one(2))
                .prop("interrupt-controller", &[])
                .prop("compatible", &compat(&["riscv,aplic"]))
                .end();
        };
        if s_first { sdom(&mut f); m(&mut f); } else { m(&mut f); sdom(&mut f); }
        f.end().end().blob()
    }

    /// The S-domain APLIC is found whichever order the two domains come in,
    /// and a node's `interrupts` is decoded against the `interrupt-parent`
    /// that FOLLOWS it in the same node.
    ///
    /// Canary: decode `interrupts` at the property (with the inherited
    /// parent, 0 here) instead of at the node's end — nothing is described.
    #[test]
    fn aplic_sources_decode_against_the_s_domain() {
        for s_first in [false, true] {
            let blob = aplic_virt(s_first);
            let t = unsafe { dtb_irq_triggers(blob.as_ptr(), IrqController::AplicS) }
                .expect("S-domain APLIC found");
            assert_eq!(t.edge(11), Some(false), "goldfish RTC <11 4> is level");
            assert_eq!(t.edge(12), Some(true), "<12 1> is edge");
            assert_eq!(t.counts(), (2, 1));
        }
    }

    /// No such controller, or a wrong cell count: `None`, not an empty map
    /// that would read as "every line level".
    #[test]
    fn a_missing_controller_is_none() {
        let blob = aplic_virt(false);
        assert_eq!(unsafe { dtb_irq_triggers(blob.as_ptr(), IrqController::GicV3) }, None);
        let gic = gic_virt();
        assert_eq!(unsafe { dtb_irq_triggers(gic.as_ptr(), IrqController::AplicS) }, None);
    }

    /// A blob cut anywhere never reads past its end (every prefix is walked
    /// by the real scanner under the test harness's bounds).
    #[test]
    fn a_truncated_blob_is_scanned_without_overrun() {
        let blob = gic_virt();
        for cut in 40..blob.len() {
            let mut b = blob[..cut].to_vec();
            b[4..8].copy_from_slice(&(cut as u32).to_be_bytes());
            let _ = unsafe { dtb_irq_triggers(b.as_ptr(), IrqController::GicV3) };
        }
    }
}

// ── Wave 13: the vDSO hwcap inputs (Zbb, Zbc, Zknh, V) ──────────────────────
#[cfg(test)]
mod hwcap_isa {
    use azos_dtb::{isa_prop_has_ext, isa_prop_has_letter};

    /// `riscv,isa` of cpu@0 as QEMU 11 `-machine virt` writes it: default
    /// `rv64` (Zbb, Zbc, no V, no Zknh) and `-cpu rv64,zknh=true,v=true`.
    const QEMU_DEFAULT: &[u8] = b"rv64imafdch_zic64b_zicbom_zicboz_zba_zbb_zbc_zbs_sstc_svadu\0";
    const QEMU_V_ZKNH: &[u8] = b"rv64imafdcvh_zicboz_zba_zbb_zbc_zbs_zknh_zve32f_zve64d\0";

    #[test]
    fn qemu_default_isa_string() {
        assert!(isa_prop_has_ext(QEMU_DEFAULT, false, b"zbb"));
        assert!(isa_prop_has_ext(QEMU_DEFAULT, false, b"zbc"));
        assert!(!isa_prop_has_ext(QEMU_DEFAULT, false, b"zknh"));
        assert!(!isa_prop_has_letter(QEMU_DEFAULT, false, b'v'));
        assert!(isa_prop_has_letter(QEMU_DEFAULT, false, b'h'));
    }

    #[test]
    fn qemu_v_and_zknh() {
        assert!(isa_prop_has_ext(QEMU_V_ZKNH, false, b"zknh"));
        assert!(isa_prop_has_letter(QEMU_V_ZKNH, false, b'v'));
    }

    /// `v` inside a multi-letter segment (`zve32f`, `svadu`) is not V, and
    /// the `rv` prefix's own `v` is not V either.
    #[test]
    fn v_only_from_the_base_letters() {
        assert!(!isa_prop_has_letter(b"rv64imac_svadu_zve32x\0", false, b'v'));
        assert!(!isa_prop_has_letter(b"rv64i\0", false, b'v'));
        assert!(!isa_prop_has_letter(b"xv64imacv\0", false, b'v'), "not an rv base");
    }

    #[test]
    fn isa_extensions_list_form() {
        let list = b"i\0m\0a\0c\0v\0zbb\0zknh\0";
        assert!(isa_prop_has_letter(list, true, b'v'));
        assert!(isa_prop_has_ext(list, true, b"zbb"));
        assert!(isa_prop_has_ext(list, true, b"zknh"));
        assert!(!isa_prop_has_ext(list, true, b"zbc"));
    }
}

