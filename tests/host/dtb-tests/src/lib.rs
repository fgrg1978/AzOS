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
            isa_zicboz: false, cboz_block_size: 0, isa_zicbom: false, cbom_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, isa_zba: false, isa_zbs: false, isa_svpbmt: false, isa_svnapot: false, isa_svadu: false, isa_zawrs: false, isa_zacas: false, isa_zihintpause: false, isa_zkr: false, isa_f: false, isa_d: false, isa_h: false, isa_ssqosid: false, isa_sscofpmf: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
        };
        assert_eq!(dtb_compatible_str(&info), b"");
    }

    #[test]
    fn compatible_str_truncates_at_first_nul() {
        let mut info = DtbInfo {
            mem_base: 0, mem_size: 0, timer_freq: 0,
            uart_base: 0, plic_base: 0, num_cpus: 0,
            compatible: [0u8; 64], isa_sstc: false,
            isa_zicboz: false, cboz_block_size: 0, isa_zicbom: false, cbom_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, isa_zba: false, isa_zbs: false, isa_svpbmt: false, isa_svnapot: false, isa_svadu: false, isa_zawrs: false, isa_zacas: false, isa_zihintpause: false, isa_zkr: false, isa_f: false, isa_d: false, isa_h: false, isa_ssqosid: false, isa_sscofpmf: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
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
            isa_zicboz: false, cboz_block_size: 0, isa_zicbom: false, cbom_block_size: 0, isa_zbb: false, isa_zbc: false, isa_zknh: false, isa_v: false, isa_zba: false, isa_zbs: false, isa_svpbmt: false, isa_svnapot: false, isa_svadu: false, isa_zawrs: false, isa_zacas: false, isa_zihintpause: false, isa_zkr: false, isa_f: false, isa_d: false, isa_h: false, isa_ssqosid: false, isa_sscofpmf: false, aplic_base: 0, aplic_num_sources: 0, imsic_base: 0, imsic_num_ids: 0, imsic_guest_index_bits: 0,
        };
        let out = dtb_compatible_str(&info);
        assert_eq!(out.len(), 64);
        assert!(out.iter().all(|&b| b == b'A'));
    }

    // ── Sstc from the cpu@0 ISA properties (trap and switch cost: Sstc timer) ───────
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

    /// Sscofpmf (RV_SSCOFPMF) reaches `isa_sscofpmf` from both property
    /// forms, as QEMU writes them with `-cpu rv64,sscofpmf=on`; its default
    /// CPU (no `sscofpmf`) leaves it clear. Canary: drop the field's token
    /// line from the parser and the first two fail.
    #[test]
    fn sscofpmf_reaches_its_field() {
        let of = |b: &[u8]| unsafe { dtb_parse(b.as_ptr()) }.expect("well-formed blob").isa_sscofpmf;
        let list: Vec<u8> = ["i", "m", "a", "sscofpmf", "sstc"].iter().flat_map(|e| cstr(e)).collect();
        assert!(of(&cpu0_with("riscv,isa-extensions", &list)));
        assert!(of(&cpu0_with("riscv,isa", &cstr("rv64imafdch_zicsr_sscofpmf_sstc"))));
        assert!(!of(&cpu0_with("riscv,isa", &cstr("rv64imafdch_zicsr_sstc_ssu64xl"))));
        assert!(!of(&cpu0_with("riscv,isa", &cstr("rv64imac_sscofpmfx"))), "an exact token");
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

    // ── Zicboz + cboz-block-size from cpu@0 (cache-block zeroing) ───
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

    // ── Zicbom: the same two inputs, for cache maintenance before DMA ──

    fn zicbom_of(blob: &[u8]) -> bool {
        unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob").isa_zicbom
    }

    fn cbom_block_size_of(blob: &[u8]) -> u32 {
        unsafe { dtb_parse(blob.as_ptr()) }.expect("well-formed blob").cbom_block_size
    }

    #[test]
    fn zicbom_needs_an_exact_token_of_cpu0() {
        assert!(zicbom_of(&cpu0_with("riscv,isa", &cstr("rv64imafdch_zicbom_zicboz"))));
        assert!(!zicbom_of(&cpu0_with("riscv,isa", &cstr("rv64imac_zicboz"))), "zicboz is not zicbom");
        for isa in ["rv64imac_zicbomx", "rv64imac_zzicbom", "rv64imac_zicbo", "zicbom", "rv64imaczicbom"] {
            assert!(!zicbom_of(&cpu0_with("riscv,isa", &cstr(isa))), "{isa}");
        }
        let list: Vec<u8> = ["i", "zicbom", "zicsr"].iter().flat_map(|e| cstr(e)).collect();
        assert!(zicbom_of(&cpu0_with("riscv,isa-extensions", &list)));
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac")).end()
            .begin("cpu@1").prop("riscv,isa", &cstr("rv64imac_zicbom")).end()
            .end().end().blob();
        assert!(!zicbom_of(&blob), "cpu@1 is not cpu@0");
    }

    #[test]
    fn cbom_block_size_reads_the_u32_cell_of_cpu0_only() {
        assert_eq!(cbom_block_size_of(&cpu0_with("riscv,cbom-block-size", &64u32.to_be_bytes())), 64);
        assert_eq!(cbom_block_size_of(&cpu0_with("riscv,cbom-block-size", &128u32.to_be_bytes())), 128);
        // Absent, or a wrong cell count: left at zero, never guessed.
        assert_eq!(cbom_block_size_of(&cpu0_with("riscv,isa", &cstr("rv64imac"))), 0);
        assert_eq!(cbom_block_size_of(&cpu0_with("riscv,cbom-block-size", &[0, 0, 64])), 0);
        // The Zicboz property is a different property.
        assert_eq!(cbom_block_size_of(&cpu0_with("riscv,cboz-block-size", &64u32.to_be_bytes())), 0);
        let blob = Fdt::new().begin("").begin("cpus")
            .begin("cpu@0").prop("riscv,isa", &cstr("rv64imac")).end()
            .begin("cpu@1").prop("riscv,cbom-block-size", &64u32.to_be_bytes()).end()
            .end().end().blob();
        assert_eq!(cbom_block_size_of(&blob), 0, "cpu@1 is not cpu@0");
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

    /// The JH7110: hart 0 is the S7 monitor core, `status = "disabled"`, and
    /// the U74s are harts 1..4. A disabled node is no CPU: out of `num_cpus`
    /// and out of the `reg` list, whichever side of `reg` its `status` sits
    /// (the hart->CPU map is built from this list). Canary: drop the end-of-node
    /// removal and the count is 5 and the list starts with the S7's hart 0.
    #[test]
    fn cpu_regs_skips_a_disabled_node_wherever_its_status_sits() {
        let blob = Fdt::new().begin("").begin("cpus")
            .prop("#address-cells", &1u32.to_be_bytes())
            .prop("#size-cells", &0u32.to_be_bytes())
            .begin("cpu@0").prop("reg", &0u32.to_be_bytes()).prop("status", b"disabled\0").end()
            .begin("cpu@1").prop("status", b"okay\0").prop("reg", &1u32.to_be_bytes()).end()
            .begin("cpu@2").prop("reg", &2u32.to_be_bytes()).end()
            .begin("cpu@3").prop("status", b"fail\0").prop("reg", &3u32.to_be_bytes()).end()
            .begin("cpu@4").prop("reg", &4u32.to_be_bytes()).prop("status", b"ok\0").end()
            .end().end().blob();

        let mut out = [0u64; 8];
        let n = unsafe { dtb_cpu_regs(blob.as_ptr(), &mut out) }.expect("well-formed blob");
        assert_eq!(n, 3, "the S7 and the failed node are no CPUs");
        assert_eq!(&out[..3], &[1, 2, 4]);
        let info = unsafe { dtb_parse(blob.as_ptr()) }.expect("parses");
        assert_eq!(info.num_cpus, 3);
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

    // ── AIA (APLIC/IMSIC) discovery ────────
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

    // ── dtb_pmu_ppi: the PMU's overflow interrupt (PROFILER_PMU) ─────────

    /// `/ { gic; <pmu node> }` with the PMU's properties in QEMU's order
    /// (`interrupts` before `compatible`).
    fn with_pmu(compat_list: &[&str], interrupts: &[u8], status: Option<&str>) -> Vec<u8> {
        let mut f = Fdt::new();
        f.begin("")
            .begin("intc@8000000").prop("compatible", &compat(&["arm,gic-v3"])).end()
            .begin("pmu").prop("interrupts", interrupts).prop("compatible", &compat(compat_list));
        if let Some(st) = status {
            f.prop("status", &cstr(st));
        }
        f.end().end().blob()
    }

    /// QEMU `virt` (11.0, `-cpu max`): `pmu { interrupts = <1 7 4>;
    /// compatible = "arm,armv8-pmuv3"; }`, PPI 7, INTID 23; a core binding
    /// names its PMU the same way.
    #[test]
    fn the_pmu_ppi_is_16_plus_its_number() {
        let virt = with_pmu(&["arm,armv8-pmuv3"], &cells3(1, 7, 4), None);
        assert_eq!(unsafe { azos_dtb::dtb_pmu_ppi(virt.as_ptr()) }, Some(23));
        let a76 = with_pmu(&["arm,cortex-a76-pmu"], &cells3(1, 7, 0xf04), Some("okay"));
        assert_eq!(unsafe { azos_dtb::dtb_pmu_ppi(a76.as_ptr()) }, Some(23), "a CPU mask in the flags");
    }

    /// An SPI-wired PMU (one line per CPU), a non-GIC parent's 2-cell
    /// specifier (the Raspberry Pi 3's local controller), a disabled node and
    /// a node that is not a PMU give nothing: the profiler samples on the
    /// tick. Canary: accept type 0 in `decode_gic_ppi` and the SPI case
    /// answers 19.
    #[test]
    fn the_pmu_ppi_refuses_what_is_not_one() {
        let spis = [cells3(0, 3, 4), cells3(0, 4, 4)].concat();
        for (compat_list, irqs, status) in [
            (&["arm,cortex-a72-pmu"][..], spis, None),
            (&["arm,cortex-a53-pmu"][..], [9u32.to_be_bytes(), 4u32.to_be_bytes()].concat(), None),
            (&["arm,armv8-pmuv3"][..], cells3(1, 7, 4), Some("disabled")),
            (&["arm,armv8-timer"][..], cells3(1, 7, 4), None),
            (&["arm,armv8-pmuv3"][..], cells3(1, 16, 4), None),
        ] {
            let blob = with_pmu(compat_list, &irqs, status);
            assert_eq!(unsafe { azos_dtb::dtb_pmu_ppi(blob.as_ptr()) }, None, "{compat_list:?} {irqs:?} {status:?}");
        }
        assert_eq!(azos_dtb::decode_gic_ppi(12, [1, 15, 4]), Some(31));
        assert_eq!(azos_dtb::decode_gic_ppi(8, [1, 7, 4]), None, "a short property");
        assert!(azos_dtb::is_arm_pmu(b"arm,cortex-a53-pmu\0arm,armv8-pmuv3\0"));
        assert!(!azos_dtb::is_arm_pmu(b"arm,-pmu\0") && !azos_dtb::is_arm_pmu(b"vendor,x-pmu\0"));
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
    fn pci_host_dma_ranges_limit_the_functions_behind_it() {
        // 3 PCI child cells, 2 CPU cells, 2 size cells: [0, 4 GiB) at CPU 0.
        let mut dma = 0u32.to_be_bytes().to_vec();
        dma.extend_from_slice(&0u64.to_be_bytes());
        dma.extend_from_slice(&0u64.to_be_bytes());
        dma.extend_from_slice(&0x1_0000_0000u64.to_be_bytes());
        let host = |dma: Option<&[u8]>| {
            let mut f = Fdt::new();
            f.begin("")
                .prop("#address-cells", &2u32.to_be_bytes())
                .prop("#size-cells", &2u32.to_be_bytes())
                .begin("pcie@10000000")
                    .prop("#address-cells", &3u32.to_be_bytes())
                    .prop("#size-cells", &2u32.to_be_bytes())
                    .prop("compatible", &compat(&["pci-host-ecam-generic"]))
                    .prop("reg", &reg64(0x1000_0000, 0x1000_0000));
            if let Some(d) = dma {
                f.prop("dma-ranges", d);
            }
            f.end().end();
            unsafe { azos_dtb::dtb_pci_host(f.blob().as_ptr()) }.expect("found")
        };
        assert_eq!(host(Some(&dma)).dma_mask, 0xffff_ffff);
        assert_eq!(host(None).dma_mask, u64::MAX, "no dma-ranges: no limit");
        assert_eq!(host(Some(&[])).dma_mask, u64::MAX, "empty dma-ranges: identity");
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

    /// QEMU's tree puts no `dma-ranges` on the PCI host; the gate's DMA-limit
    /// row (`tools/gate/nvme_dma_mask_row.sh`) adds one. `fixtures/
    /// qemu-riscv64-virt-dma-2g.dtb` is that edit made by the script's own
    /// `awk` + `dtc` (`dma-ranges = <0 0 0 0 0 0 0x80000000>` after the
    /// bridge's `compatible`).
    #[test]
    fn qemu_riscv64_virt_dma_ranges_on_the_pci_host() {
        let plain = fixture(include_bytes!("../fixtures/qemu-riscv64-virt.dtb"));
        let h = unsafe { azos_dtb::dtb_pci_host(plain.as_ptr()) }.expect("pci@30000000");
        assert_eq!(h.dma_mask, u64::MAX, "QEMU's own tree restricts nothing");

        let b = fixture(include_bytes!("../fixtures/qemu-riscv64-virt-dma-2g.dtb"));
        let h = unsafe { azos_dtb::dtb_pci_host(b.as_ptr()) }.expect("pci@30000000");
        assert_eq!(h.dma_mask, 0x7fff_ffff);
        assert_eq!(h.ecam_base, 0x3000_0000, "the rest of the node reads as before");

        // The same node as a bus device: its own `dma-ranges` describes the
        // functions behind it, so nothing is limited.
        let mut limited = Vec::new();
        let n = unsafe {
            azos_dtb::dtb_devices(b.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
                if d.dma_mask != u64::MAX {
                    limited.push((String::from_utf8_lossy(d.name).into_owned(), d.dma_mask));
                }
            })
        };
        assert!(n.is_some());
        assert!(limited.is_empty(), "{limited:?}");
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

    /// The device `stdout-path` names, among `dtb_devices`' (the console the
    /// aarch64 boot drives, `boot_hooks::console_from_dt`).
    fn stdout_device(b: &[u8]) -> Option<(Vec<u8>, u64)> {
        let node = unsafe { azos_dtb::dtb_stdout_node(b.as_ptr()) }?;
        let mut found = None;
        unsafe {
            azos_dtb::dtb_devices(b.as_ptr(), &mut |d| {
                if d.dt_node == node {
                    found = Some((d.compatible.split(|&c| c == 0).next().unwrap().to_vec(), d.base));
                }
            })
        };
        found
    }

    /// QEMU `virt` names its PL011 by path (`/pl011@9000000`).
    #[test]
    fn qemu_aarch64_virt_stdout_is_the_pl011() {
        let b = fixture(include_bytes!("../fixtures/qemu-aarch64-virt.dtb"));
        assert_eq!(stdout_device(&b), Some((b"arm,pl011".to_vec(), 0x900_0000)));
    }

    /// QEMU raspi3b with the Raspberry Pi 3 B tree (Linux's
    /// bcm2837-rpi-3-b.dts, as U-Boot 2025.07 carries it, dumped after QEMU
    /// patched `/memory`): `stdout-path = "serial1:115200n8"`, an alias, and
    /// `serial1` the mini UART on the VideoCore bus, whose `reg` 0x7e215040 is
    /// the CPU's 0x3f215040 through `/soc`'s `ranges`. Canary: a lookup that
    /// takes the alias name for a path (or keeps the `:115200n8`) finds no
    /// node; the first PL011 of the tree (0x3f201000, the Bluetooth UART on
    /// this board) is the wrong answer.
    #[test]
    fn qemu_raspi3b_stdout_is_the_mini_uart_through_an_alias() {
        let b = fixture(include_bytes!("../fixtures/qemu-raspi3b.dtb"));
        assert_eq!(stdout_device(&b), Some((b"brcm,bcm2835-aux-uart".to_vec(), 0x3f21_5040)));
        let info = unsafe { dtb_parse(b.as_ptr()) }.expect("raspi3b blob parses");
        assert_eq!((info.mem_base, info.mem_size), (0, 0x3c00_0000), "QEMU's /memory: RAM at 0, VC RAM out");
    }

    /// The Raspberry Pi 5 tree (fixtures/rpi5-bcm2712.dts, written from
    /// recollection of Linux's bcm2712 sources: the arithmetic, not the
    /// board's map). The console is `uart10` through an alias with options
    /// (`serial10:115200n8`), its `reg` under `soc`'s one-cell children and
    /// two-cell parent: the CPU's 0x10_7d00_1000, past 64 GiB. Canary: drop
    /// the `soc` ranges translation and the base reads 0x7d00_1000, inside a
    /// Pi 5's RAM.
    #[test]
    fn rpi5_stdout_is_the_debug_pl011_far_above_ram() {
        let b = fixture(include_bytes!("../fixtures/rpi5-bcm2712.dtb"));
        assert_eq!(stdout_device(&b), Some((b"arm,pl011".to_vec(), 0x10_7d00_1000)));
        let info = unsafe { dtb_parse(b.as_ptr()) }.expect("rpi5 blob parses");
        // The first /memory range only: the RAM above 1 GiB (the firmware's
        // second range) is not used yet.
        assert_eq!((info.mem_base, info.mem_size), (0, 0x3fc0_0000));
        assert_eq!(info.num_cpus, 4);
    }

    /// The Pi 5 blocks the boot drives from the tree, at their CPU addresses:
    /// the GIC-400's distributor and CPU interface (`reg` 0 and 1), the
    /// VideoCore mailbox, the PM block, and the PCIe controllers, the one
    /// marked `disabled` left out.
    #[test]
    fn rpi5_devices_are_at_their_cpu_addresses() {
        let b = fixture(include_bytes!("../fixtures/rpi5-bcm2712.dtb"));
        let mut seen = Vec::new();
        let _ = unsafe {
            azos_dtb::dtb_devices(b.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
                let c = d.compatible.split(|&c| c == 0).next().unwrap().to_vec();
                seen.push((c, d.base, d.size, d.reg2));
            })
        };
        let find = |c: &[u8]| seen.iter().filter(|s| s.0 == c).map(|s| (s.1, s.2, s.3)).collect::<Vec<_>>();
        assert_eq!(find(b"arm,gic-400"), [(0x10_7fff_9000, 0x1000, Some((0x10_7fff_a000, 0x2000)))]);
        assert_eq!(find(b"brcm,bcm2835-mbox"), [(0x10_7c01_3880, 0x40, None)]);
        assert_eq!(find(b"brcm,bcm2712-pm"), [(0x10_7d20_0000, 0x604, None)]);
        let pcie: Vec<u64> = find(b"brcm,bcm2712-pcie").iter().map(|p| p.0).collect();
        assert_eq!(pcie, [0x10_0011_0000, 0x10_0012_0000], "pcie0 is disabled");
    }

    fn cells(v: &[u32]) -> Vec<u8> { v.iter().flat_map(|c| c.to_be_bytes()).collect() }

    /// The Raspberry Pi 3 B tree starts its four Cortex-A53s through a spin
    /// table: `cpu-release-addr` 0xd8, 0xe0, 0xe8, 0xf0 (the firmware's
    /// armstub, and QEMU's), `reg` the MPIDR affinity. QEMU `virt` uses PSCI:
    /// no CPU is listed. Canary: read `cpu-release-addr` with `/cpus`'
    /// `#address-cells` (1) and every address comes out 0.
    #[test]
    fn qemu_raspi3b_cpus_are_spin_table_ones() {
        let b = fixture(include_bytes!("../fixtures/qemu-raspi3b.dtb"));
        let mut out = [azos_dtb::SpinCpu::default(); 8];
        let n = unsafe { azos_dtb::dtb_spin_table(b.as_ptr(), &mut out) };
        assert_eq!(n, Some(4));
        let got: Vec<(u64, u64)> = out[..4].iter().map(|c| (c.reg, c.release_addr)).collect();
        assert_eq!(got, [(0, 0xd8), (1, 0xe0), (2, 0xe8), (3, 0xf0)]);
        let v = fixture(include_bytes!("../fixtures/qemu-aarch64-virt.dtb"));
        assert_eq!(unsafe { azos_dtb::dtb_spin_table(v.as_ptr(), &mut out) }, Some(0));
        // A short buffer keeps the count.
        let mut one = [azos_dtb::SpinCpu::default(); 1];
        assert_eq!(unsafe { azos_dtb::dtb_spin_table(b.as_ptr(), &mut one) }, Some(4));
        assert_eq!(one[0], azos_dtb::SpinCpu { reg: 0, release_addr: 0xd8 });
    }

    /// A `stdout-path` that names nothing resolves to nothing, not to some
    /// other node.
    #[test]
    fn stdout_path_without_a_node_is_none() {
        let mut t = Fdt::new();
        t.begin("").prop("#address-cells", &cells(&[1])).prop("#size-cells", &cells(&[1]));
        t.begin("chosen").prop("stdout-path", b"serial7:115200n8\0").end();
        t.begin("aliases").prop("serial0", b"/uart@1000\0").end();
        t.begin("uart@1000").prop("compatible", b"arm,pl011\0").prop("reg", &cells(&[0x1000, 0x100])).end();
        t.end();
        let b = t.blob();
        assert_eq!(unsafe { azos_dtb::dtb_stdout_node(b.as_ptr()) }, None, "an alias /aliases lacks");
        let mut t = Fdt::new();
        t.begin("").prop("#address-cells", &cells(&[1])).prop("#size-cells", &cells(&[1]));
        t.begin("chosen").prop("stdout-path", b"/soc/uart@1000\0").end();
        t.begin("uart@1000").prop("compatible", b"arm,pl011\0").prop("reg", &cells(&[0x1000, 0x100])).end();
        t.end();
        let b = t.blob();
        assert_eq!(unsafe { azos_dtb::dtb_stdout_node(b.as_ptr()) }, None, "a path no node has");
        let mut t = Fdt::new();
        t.begin("").prop("#address-cells", &cells(&[1])).prop("#size-cells", &cells(&[1]));
        t.begin("chosen").prop("stdout-path", b"serial0\0").end();
        t.begin("aliases").prop("serial0", b"/uart@1000\0").end();
        t.begin("uart@1000").prop("compatible", b"arm,pl011\0").prop("reg", &cells(&[0x1000, 0x100])).end();
        t.end();
        let b = t.blob();
        assert_eq!(stdout_device(&b), Some((b"arm,pl011".to_vec(), 0x1000)), "an alias without options");
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

    fn gic_virt() -> Vec<u8> { gic_virt_with("arm,gic-v3") }

    fn gic_virt_with(gic: &str) -> Vec<u8> {
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
                .prop("compatible", &compat(&[gic]))
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

    /// The GICv2 bindings (`arm,gic-400`, `arm,cortex-a15-gic`) decode the same
    /// 3-cell specifiers under `IrqController::GicV2`, and each variant finds
    /// only its own compatible: a v3 tree is no v2 tree and the other way round.
    ///
    /// Canary: leave `arm,cortex-a15-gic` out of the `GicV2` list in
    /// `dtb_irq_triggers` and the second loop turn finds no GIC.
    #[test]
    fn gic_v2_nodes_decode_under_their_own_variant() {
        for name in ["arm,gic-400", "arm,cortex-a15-gic"] {
            let blob = gic_virt_with(name);
            let t = unsafe { dtb_irq_triggers(blob.as_ptr(), IrqController::GicV2) }
                .unwrap_or_else(|| panic!("{name}: GIC found"));
            assert_eq!(t.edge(34), Some(false), "{name}: PL031 level");
            assert_eq!(t.edge(48), Some(true), "{name}: virtio-mmio edge");
            assert_eq!(t.counts(), (2, 1), "{name}");
            assert_eq!(unsafe { dtb_irq_triggers(blob.as_ptr(), IrqController::GicV3) }, None,
                "{name} is not a v3 tree");
        }
        let v3 = gic_virt();
        assert_eq!(unsafe { dtb_irq_triggers(v3.as_ptr(), IrqController::GicV2) }, None,
            "a v3 tree is not a v2 tree");
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

    // ── simple-framebuffer ───────────────────────────────────────────────

    fn be32(v: u32) -> Vec<u8> { v.to_be_bytes().to_vec() }
    fn be64(v: u64) -> Vec<u8> { v.to_be_bytes().to_vec() }

    /// `/ { chosen { #address-cells #size-cells framebuffer@<base> { ... } } }`
    /// with the node's `status` and `format` given.
    fn fb_blob(status: Option<&str>, format: &str, ac: u32, base: u64) -> Vec<u8> {
        let mut f = Fdt::new();
        // The cells belong to the framebuffer's PARENT (`chosen`), not the root.
        f.begin("").prop("#address-cells", &be32(7)).begin("chosen")
            .prop("#address-cells", &be32(ac)).prop("#size-cells", &be32(1));
        f.begin("framebuffer@80000000")
            .prop("compatible", &cstr("simple-framebuffer"));
        if ac == 2 { f.prop("reg", &[be64(base), be32(0x12_0000)].concat()); }
        else { f.prop("reg", &[be32(base as u32), be32(0x12_0000)].concat()); }
        f.prop("width", &be32(640)).prop("height", &be32(480)).prop("stride", &be32(2560))
            .prop("format", &cstr(format));
        if let Some(s) = status { f.prop("status", &cstr(s)); }
        f.end().end().end().blob()
    }

    #[test]
    fn a_simple_framebuffer_node_is_read_with_the_parents_cells() {
        use azos_dtb::dtb_simple_framebuffer;
        for (ac, base) in [(2u32, 0x1_8000_0000u64), (1, 0x8000_0000)] {
            let b = fb_blob(None, "a8r8g8b8", ac, base);
            let fb = unsafe { dtb_simple_framebuffer(b.as_ptr()) }.expect("node found");
            assert_eq!((fb.base, fb.size), (base, 0x12_0000), "ac={ac}");
            assert_eq!((fb.width, fb.height, fb.stride), (640, 480, 2560));
            assert_eq!(&fb.format[..9], b"a8r8g8b8\0");
        }
    }

    #[test]
    fn a_disabled_or_incomplete_or_other_node_is_not_a_framebuffer() {
        use azos_dtb::dtb_simple_framebuffer;
        let find = |b: &[u8]| unsafe { dtb_simple_framebuffer(b.as_ptr()) };
        assert!(find(&fb_blob(Some("okay"), "r5g6b5", 2, 0x8000_0000)).is_some());
        assert!(find(&fb_blob(Some("disabled"), "r5g6b5", 2, 0x8000_0000)).is_none());
        // No width/stride/format: a node that only says it is a framebuffer.
        let bare = Fdt::new().begin("").begin("fb@1")
            .prop("compatible", &cstr("simple-framebuffer")).end().end().blob();
        assert!(find(&bare).is_none());
        // A different compatible, complete otherwise.
        let other = Fdt::new().begin("").prop("#address-cells", &be32(1)).begin("fb@1")
            .prop("compatible", &cstr("vendor,framebuffer"))
            .prop("reg", &[be32(0x1000), be32(0x1000)].concat())
            .prop("width", &be32(1)).prop("height", &be32(1)).prop("stride", &be32(4))
            .prop("format", &cstr("x8r8g8b8")).end().end().blob();
        assert!(find(&other).is_none());
        // Truncations never read out of bounds.
        let blob = fb_blob(None, "a8r8g8b8", 2, 0x8000_0000);
        for cut in 40..blob.len() {
            let mut b = blob[..cut].to_vec();
            b[4..8].copy_from_slice(&(cut as u32).to_be_bytes());
            let _ = find(&b);
        }
    }

    // ── dtb_cpu_topology: /cpus/cpu-map and capacity-dmips-mhz ──────────

    mod cpu_topology {
        use super::*;
        use azos_dtb::{dtb_cpu_topology, DtTopology, DT_TOPO_NONE};

        fn read(b: &[u8]) -> DtTopology {
            unsafe { dtb_cpu_topology(b.as_ptr()) }.expect("readable blob")
        }

        fn be(v: u32) -> [u8; 4] {
            v.to_be_bytes()
        }

        /// `cpu@<reg>` with `device_type`, `reg`, `phandle` (0: none) and
        /// `capacity-dmips-mhz` (0: none).
        fn cpu(f: &mut Fdt, reg: u32, phandle: u32, cap: u32) {
            f.begin(&format!("cpu@{reg}")).prop("device_type", &cstr("cpu")).prop("reg", &be(reg));
            if phandle != 0 {
                f.prop("phandle", &be(phandle));
            }
            if cap != 0 {
                f.prop("capacity-dmips-mhz", &be(cap));
            }
            f.end();
        }

        /// A leaf of the map: `<name> { cpu = <phandle>; }` (a `coreN` or `threadN`).
        fn leaf(f: &mut Fdt, name: &str, phandle: u32) {
            f.begin(name).prop("cpu", &be(phandle)).end();
        }

        fn ids(t: &DtTopology) -> Vec<(u64, u32, u32, u32)> {
            t.cpus().iter().map(|c| (c.reg, c.socket, c.cluster, c.core)).collect()
        }

        #[test]
        fn the_qemu_riscv64_map_is_one_cluster_of_four_cores() {
            let b = fixture(include_bytes!("../fixtures/qemu-riscv64-virt.dtb"));
            let t = read(&b);
            assert!(t.has_cpu_map && !t.truncated);
            // `-smp 4`: no socket node; cluster0 { core0..core3 }.
            assert_eq!(
                ids(&t),
                [(0, DT_TOPO_NONE, 0, 0), (1, DT_TOPO_NONE, 0, 1), (2, DT_TOPO_NONE, 0, 2), (3, DT_TOPO_NONE, 0, 3)]
            );
            assert!(t.cpus().iter().all(|c| c.capacity_dmips_mhz == 0), "QEMU states no capacity");
        }

        #[test]
        fn the_qemu_aarch64_map_has_a_socket_level() {
            let b = fixture(include_bytes!("../fixtures/qemu-aarch64-virt.dtb"));
            let t = read(&b);
            assert!(t.has_cpu_map);
            assert_eq!(ids(&t), [(0, 0, 0, 0), (1, 0, 0, 1)]);
        }

        #[test]
        fn threads_share_a_core_and_clusters_are_numbered_in_document_order() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            cpu(&mut f, 0, 1, 446);
            cpu(&mut f, 1, 2, 446);
            cpu(&mut f, 2, 3, 1024);
            cpu(&mut f, 3, 4, 1024);
            f.begin("cpu-map");
            f.begin("cluster0");
            leaf(&mut f, "core0", 1);
            leaf(&mut f, "core1", 2);
            f.end();
            f.begin("cluster1").begin("core0");
            leaf(&mut f, "thread0", 3);
            leaf(&mut f, "thread1", 4);
            f.end().end();
            f.end().end().end();
            let t = read(&f.blob());
            assert_eq!(
                ids(&t),
                [(0, DT_TOPO_NONE, 0, 0), (1, DT_TOPO_NONE, 0, 1), (2, DT_TOPO_NONE, 1, 2), (3, DT_TOPO_NONE, 1, 2)]
            );
            assert_eq!(
                t.cpus().iter().map(|c| c.capacity_dmips_mhz).collect::<Vec<_>>(),
                [446, 446, 1024, 1024]
            );
        }

        #[test]
        fn nested_clusters_give_the_innermost() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            for i in 0..3 {
                cpu(&mut f, i, i + 1, 0);
            }
            f.begin("cpu-map").begin("cluster0");
            f.begin("cluster0");
            leaf(&mut f, "core0", 1);
            leaf(&mut f, "core1", 2);
            f.end();
            f.begin("cluster1");
            leaf(&mut f, "core0", 3);
            f.end();
            f.end().end().end().end();
            let t = read(&f.blob());
            // Outer cluster0 is ordinal 0, the inner ones 1 and 2; core ordinals
            // run on across them.
            assert_eq!(
                ids(&t),
                [(0, DT_TOPO_NONE, 1, 0), (1, DT_TOPO_NONE, 1, 1), (2, DT_TOPO_NONE, 2, 2)]
            );
        }

        #[test]
        fn sockets_hold_clusters_and_the_ordinals_are_global() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            for i in 0..4 {
                cpu(&mut f, i, 10 + i, 0);
            }
            f.begin("cpu-map");
            for s in 0..2u32 {
                f.begin(&format!("socket{s}")).begin("cluster0");
                leaf(&mut f, "core0", 10 + 2 * s);
                leaf(&mut f, "core1", 11 + 2 * s);
                f.end().end();
            }
            f.end().end().end();
            let t = read(&f.blob());
            assert_eq!(ids(&t), [(0, 0, 0, 0), (1, 0, 0, 1), (2, 1, 1, 2), (3, 1, 1, 3)]);
        }

        #[test]
        fn a_cpu_the_map_does_not_name_is_outside_it() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            cpu(&mut f, 0, 1, 0);
            cpu(&mut f, 1, 0, 0); // no phandle: nothing can name it
            cpu(&mut f, 2, 3, 0); // a phandle no leaf names
            f.begin("cpu-map").begin("cluster0");
            leaf(&mut f, "core0", 1);
            f.end().end().end().end();
            let t = read(&f.blob());
            assert_eq!(
                ids(&t),
                [(0, DT_TOPO_NONE, 0, 0), (1, DT_TOPO_NONE, DT_TOPO_NONE, DT_TOPO_NONE), (2, DT_TOPO_NONE, DT_TOPO_NONE, DT_TOPO_NONE)]
            );
        }

        #[test]
        fn a_leaf_straight_in_a_cluster_is_a_core_of_its_own() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            cpu(&mut f, 0, 1, 0);
            cpu(&mut f, 1, 2, 0);
            f.begin("cpu-map").begin("cluster0").prop("cpu", &be(1)).end();
            f.begin("cluster1").prop("cpu", &be(2)).end();
            f.end().end().end();
            let t = read(&f.blob());
            assert_eq!(ids(&t), [(0, DT_TOPO_NONE, 0, 0), (1, DT_TOPO_NONE, 1, 1)]);
        }

        #[test]
        fn no_map_leaves_every_level_unnamed_but_keeps_capacity() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            cpu(&mut f, 0, 1, 700);
            cpu(&mut f, 1, 2, 900);
            f.end().end();
            let t = read(&f.blob());
            assert!(!t.has_cpu_map);
            assert_eq!(
                ids(&t),
                [(0, DT_TOPO_NONE, DT_TOPO_NONE, DT_TOPO_NONE), (1, DT_TOPO_NONE, DT_TOPO_NONE, DT_TOPO_NONE)]
            );
            assert_eq!(t.cpus()[1].capacity_dmips_mhz, 900);
        }

        #[test]
        fn a_cpu_map_that_is_not_under_cpus_is_not_the_cpu_map() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            cpu(&mut f, 0, 1, 0);
            f.end();
            f.begin("soc").begin("cpu-map").begin("cluster0");
            leaf(&mut f, "core0", 1);
            f.end().end().end().end();
            let t = read(&f.blob());
            assert!(!t.has_cpu_map);
            assert_eq!(t.cpus()[0].core, DT_TOPO_NONE);
        }

        #[test]
        fn a_64_bit_reg_and_too_many_cpus() {
            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            f.begin("cpu@0").prop("device_type", &cstr("cpu")).prop("reg", &0x1_0000_0002u64.to_be_bytes()).end();
            f.end().end();
            assert_eq!(read(&f.blob()).cpus()[0].reg, 0x1_0000_0002);

            let mut f = Fdt::new();
            f.begin("").begin("cpus");
            for i in 0..azos_dtb::DT_TOPO_CPUS as u32 + 3 {
                cpu(&mut f, i, 0, 0);
            }
            f.end().end();
            let t = read(&f.blob());
            assert!(t.truncated);
            assert_eq!(t.cpus().len(), azos_dtb::DT_TOPO_CPUS);
        }

        #[test]
        fn unreadable_blobs_give_none() {
            assert!(unsafe { dtb_cpu_topology(core::ptr::null()) }.is_none());
            let junk = [0u8; 64];
            assert!(unsafe { dtb_cpu_topology(junk.as_ptr()) }.is_none());
        }
    }

}

// ── The hardware bus: device nodes ──────────────────────────────────────────
#[cfg(test)]
mod device_nodes {
    use azos_dtb::{dtb_devices, DtDevice};

    // The blob builder of the framebuffer tests lives in `tests`; the nodes
    // here are built by hand with the same layout.
    fn be32(v: u32) -> Vec<u8> { v.to_be_bytes().to_vec() }
    fn be64(v: u64) -> Vec<u8> { v.to_be_bytes().to_vec() }
    fn cstr(s: &str) -> Vec<u8> { let mut v = s.as_bytes().to_vec(); v.push(0); v }

    struct B { structs: Vec<u8>, strings: Vec<u8> }
    impl B {
        fn new() -> Self { B { structs: vec![], strings: vec![] } }
        fn pad(v: &mut Vec<u8>) { while v.len() % 4 != 0 { v.push(0); } }
        fn begin(&mut self, n: &str) -> &mut Self {
            self.structs.extend_from_slice(&1u32.to_be_bytes());
            self.structs.extend_from_slice(n.as_bytes());
            self.structs.push(0);
            Self::pad(&mut self.structs);
            self
        }
        fn end(&mut self) -> &mut Self { self.structs.extend_from_slice(&2u32.to_be_bytes()); self }
        fn prop(&mut self, n: &str, v: &[u8]) -> &mut Self {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(n.as_bytes());
            self.strings.push(0);
            self.structs.extend_from_slice(&3u32.to_be_bytes());
            self.structs.extend_from_slice(&(v.len() as u32).to_be_bytes());
            self.structs.extend_from_slice(&off.to_be_bytes());
            self.structs.extend_from_slice(v);
            Self::pad(&mut self.structs);
            self
        }
        fn blob(&mut self) -> Vec<u8> {
            self.structs.extend_from_slice(&9u32.to_be_bytes());
            let off_struct = 40u32;
            let off_strings = off_struct + self.structs.len() as u32;
            let total = off_strings + self.strings.len() as u32;
            let mut h = vec![0u8; 40];
            h[0..4].copy_from_slice(&0xd00d_feedu32.to_be_bytes());
            h[4..8].copy_from_slice(&total.to_be_bytes());
            h[8..12].copy_from_slice(&off_struct.to_be_bytes());
            h[12..16].copy_from_slice(&off_strings.to_be_bytes());
            h[20..24].copy_from_slice(&17u32.to_be_bytes());
            h[24..28].copy_from_slice(&16u32.to_be_bytes());
            h[32..36].copy_from_slice(&(self.strings.len() as u32).to_be_bytes());
            h[36..40].copy_from_slice(&(self.structs.len() as u32).to_be_bytes());
            h.extend_from_slice(&self.structs);
            h.extend_from_slice(&self.strings);
            h
        }
    }

    #[derive(Debug, PartialEq)]
    struct Seen { name: String, compat: Vec<String>, base: u64, size: u64, irq: u32, depth: usize }

    fn walk(blob: &[u8]) -> (Option<usize>, Vec<Seen>) {
        let mut v = Vec::new();
        let r = unsafe {
            dtb_devices(blob.as_ptr(), &mut |d: &DtDevice<'_>| {
                v.push(Seen {
                    name: String::from_utf8_lossy(d.name).into_owned(),
                    compat: d.compatible.split(|&b| b == 0).filter(|s| !s.is_empty())
                        .map(|s| String::from_utf8_lossy(s).into_owned()).collect(),
                    base: d.base, size: d.size, irq: d.irq, depth: d.depth,
                });
            })
        };
        (r, v)
    }

    /// A GIC-400 as the Raspberry Pi 5 describes it: four `reg` entries (the
    /// distributor, the CPU interface, the hypervisor and virtual-CPU
    /// interfaces) under a bus whose `ranges` moves them. `reg2` is the CPU
    /// interface, translated like `base`; a node with one entry has none.
    ///
    /// Canary: read `reg2` from `second` without adding `ac` cells (the
    /// size's offset) and the size comes out as the base's low word.
    #[test]
    fn the_second_reg_entry_is_the_cpu_interface_and_goes_through_ranges() {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("soc").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1))
            .prop("ranges", &[be32(0x7c00_0000), be64(0x10_7c00_0000), be32(0x0400_0000)].concat());
        b.begin("interrupt-controller@7fff9000").prop("compatible", &cstr("arm,gic-400"))
            .prop("reg", &[be32(0x7fff_9000), be32(0x1000), be32(0x7fff_a000), be32(0x2000),
                           be32(0x7fff_c000), be32(0x2000), be32(0x7fff_e000), be32(0x2000)].concat())
            .end();
        b.begin("one@7c001000").prop("compatible", &cstr("x,one"))
            .prop("reg", &[be32(0x7c00_1000), be32(0x100)].concat()).end();
        b.end().end();
        let blob = b.blob();
        let mut seen: Vec<(String, u64, u64, Option<(u64, u64)>)> = Vec::new();
        unsafe {
            dtb_devices(blob.as_ptr(), &mut |d: &DtDevice<'_>| {
                seen.push((String::from_utf8_lossy(d.name).into_owned(), d.base, d.size, d.reg2));
            })
        }.expect("walks");
        let gic = seen.iter().find(|s| s.0.starts_with("interrupt-controller")).expect("the GIC");
        assert_eq!((gic.1, gic.2), (0x10_7fff_9000, 0x1000), "the distributor");
        assert_eq!(gic.3, Some((0x10_7fff_a000, 0x2000)), "the CPU interface");
        let one = seen.iter().find(|s| s.0.starts_with("one")).expect("the plain node");
        assert_eq!(one.3, None, "one entry, no second");
    }

    /// A RISC-V `virt`-shaped tree: 2/2 cells at the root, a UART with one
    /// interrupt cell, a PLIC, a populated virtio window, and the nodes the
    /// walk must not report.
    fn virt() -> Vec<u8> {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("uart@10000000").prop("compatible", &cstr("ns16550a"))
            .prop("reg", &[be64(0x1000_0000), be64(0x100)].concat()).prop("interrupts", &be32(10)).end();
        b.begin("plic@c000000")
            .prop("compatible", &[cstr("sifive,plic-1.0.0"), cstr("riscv,plic0")].concat())
            .prop("reg", &[be64(0xc00_0000), be64(0x60_0000)].concat()).end();
        b.begin("virtio_mmio@10001000").prop("compatible", &cstr("virtio,mmio"))
            .prop("reg", &[be64(0x1000_1000), be64(0x1000)].concat()).prop("interrupts", &be32(1)).end();
        // Not reported: disabled, no `reg`, no `compatible`.
        b.begin("off@1").prop("compatible", &cstr("vendor,off")).prop("status", &cstr("disabled"))
            .prop("reg", &[be64(0x1), be64(0x1)].concat()).end();
        b.begin("clk").prop("compatible", &cstr("fixed-clock")).end();
        b.begin("memory@80000000").prop("device_type", &cstr("memory"))
            .prop("reg", &[be64(0x8000_0000), be64(0x1000_0000)].concat()).end();
        // A bus with its own cells: 1/1 below it.
        b.begin("soc").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[]);
        b.begin("rtc@101000").prop("compatible", &cstr("google,goldfish-rtc"))
            .prop("reg", &[be32(0x10_1000), be32(0x1000)].concat())
            .prop("interrupts", &be32(11)).prop("status", &cstr("okay")).end();
        b.end().end();
        b.blob()
    }

    #[test]
    fn the_enabled_nodes_with_a_compatible_and_a_reg_are_reported() {
        let (n, seen) = walk(&virt());
        assert_eq!(n, Some(4));
        let names: Vec<_> = seen.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["uart@10000000", "plic@c000000", "virtio_mmio@10001000", "rtc@101000"]);
        assert_eq!(seen[0], Seen { name: "uart@10000000".into(), compat: vec!["ns16550a".into()],
            base: 0x1000_0000, size: 0x100, irq: 10, depth: 2 });
        assert_eq!(seen[1].compat, ["sifive,plic-1.0.0", "riscv,plic0"], "most specific first");
        assert_eq!((seen[1].base, seen[1].size, seen[1].irq), (0xc00_0000, 0x60_0000, 0));
    }

    #[test]
    fn a_node_is_read_with_its_parents_cells() {
        let (_, seen) = walk(&virt());
        let rtc = seen.iter().find(|s| s.name == "rtc@101000").unwrap();
        assert_eq!((rtc.base, rtc.size, rtc.irq, rtc.depth), (0x10_1000, 0x1000, 11, 3));
    }

    /// The `dma-coherent` flag of every reported node, by name.
    fn coherence(blob: &[u8]) -> Vec<(String, bool)> {
        let mut v = Vec::new();
        unsafe {
            dtb_devices(blob.as_ptr(), &mut |d: &DtDevice<'_>| {
                v.push((String::from_utf8_lossy(d.name).into_owned(), d.dma_coherent));
            })
        };
        v
    }

    #[test]
    fn dma_coherent_is_read_from_the_node_and_inherited_from_its_buses() {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        // On the node itself (a zero-length flag property).
        b.begin("dma@1000").prop("compatible", &cstr("vendor,dma"))
            .prop("reg", &[be64(0x1000), be64(0x100)].concat()).prop("dma-coherent", &[]).end();
        // Nothing declared.
        b.begin("plain@2000").prop("compatible", &cstr("vendor,plain"))
            .prop("reg", &[be64(0x2000), be64(0x100)].concat()).end();
        // A coherent bus: its children are, and a sibling bus's are not.
        b.begin("soc").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1))
            .prop("ranges", &[]).prop("dma-coherent", &[]);
        b.begin("behind@3000").prop("compatible", &cstr("vendor,behind"))
            .prop("reg", &[be32(0x3000), be32(0x100)].concat()).end();
        b.end();
        b.begin("other").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[]);
        b.begin("alone@4000").prop("compatible", &cstr("vendor,alone"))
            .prop("reg", &[be32(0x4000), be32(0x100)].concat()).end();
        b.end().end();
        let got = coherence(&b.blob());
        let flag = |n: &str| got.iter().find(|(name, _)| name == n).unwrap().1;
        assert!(flag("dma@1000"));
        assert!(!flag("plain@2000"));
        assert!(flag("behind@3000"), "a bus that declares it speaks for the devices behind it");
        assert!(!flag("alone@4000"), "a sibling bus does not");
    }

    /// A bus below the root with 1/1 cells and the `ranges` given, one
    /// device at bus-local 0x1000 (size 0x100) below it.
    fn behind(ranges: Option<Vec<u8>>, parent_status: Option<&str>) -> (Option<usize>, Vec<Seen>) {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("bus@0").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1));
        if let Some(r) = ranges {
            b.prop("ranges", &r);
        }
        if let Some(st) = parent_status {
            b.prop("status", &cstr(st));
        }
        b.begin("dev@1000").prop("compatible", &cstr("vendor,dev"))
            .prop("reg", &[be32(0x1000), be32(0x100)].concat()).end();
        b.end().end();
        walk(&b.blob())
    }

    #[test]
    fn a_reg_below_a_bus_is_translated_through_its_ranges() {
        // Bus-local 0x0..0x2000 is CPU 0x4000_0000.. (one 1/2/1-cell entry).
        let r = [be32(0), be64(0x4000_0000), be32(0x2000)].concat();
        let (_, seen) = behind(Some(r), None);
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].base, seen[0].size), (0x4000_1000, 0x100), "bus-local 0x1000 is not CPU 0x1000");
    }

    #[test]
    fn an_empty_ranges_is_the_identity() {
        let (_, seen) = behind(Some(vec![]), None);
        assert_eq!(seen[0].base, 0x1000);
    }

    #[test]
    fn a_window_no_range_covers_is_not_reported() {
        // The entry stops at 0x1080: the device's 0x1000..0x1100 sticks out.
        let r = [be32(0), be64(0x4000_0000), be32(0x1080)].concat();
        assert_eq!(behind(Some(r), None).1.len(), 0);
        // An entry elsewhere does not cover it either.
        let r = [be32(0x8000), be64(0x4000_0000), be32(0x1000)].concat();
        assert_eq!(behind(Some(r), None).1.len(), 0);
    }

    #[test]
    fn the_first_range_that_covers_the_window_wins() {
        let r = [
            be32(0x8000), be64(0x9000_0000), be32(0x1000),
            be32(0x1000), be64(0x5000_0000), be32(0x1000),
        ].concat();
        assert_eq!(behind(Some(r), None).1[0].base, 0x5000_0000);
    }

    #[test]
    fn a_bus_without_ranges_has_no_cpu_addresses_below_it() {
        let (n, seen) = behind(None, None);
        assert_eq!((n, seen.len()), (Some(0), 0), "an I2C slave's address is not a window");
    }

    #[test]
    fn ranges_compose_down_two_levels() {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("soc").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1))
            .prop("ranges", &[be32(0), be64(0x1_0000_0000), be32(0x1000_0000)].concat());
        b.begin("periph@100000").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1))
            // periph-local 0.. is soc-local 0x100000..
            .prop("ranges", &[be32(0), be32(0x10_0000), be32(0x1_0000)].concat());
        b.begin("dev@40").prop("compatible", &cstr("vendor,dev"))
            .prop("reg", &[be32(0x40), be32(0x10)].concat()).end();
        b.end().end().end();
        let (_, seen) = walk(&b.blob());
        assert_eq!(seen[0].base, 0x1_0010_0040);
    }

    /// The Raspberry Pi 5's RP1 as the tree describes it
    /// (arch/arm64/boot/dts/broadcom/bcm2712-rpi-5-b.dts, rp1-common.dtsi):
    /// the PCIe bridge `pcie@1000120000` (`device_type = "pci"`, 3 cells, PCI
    /// memory 0 at CPU 0x1f_0000_0000), its root port `pci@0,0` (`ranges;`),
    /// the RP1 function `dev@0,0` (3 cells: `<1 0 0>`, "BAR 1", is PCI
    /// memory 0), and the RP1's own bus `pci-ep-bus@1` (2 cells: 0x40000000
    /// is `<1 0 0>`). `space` and `bar` are the bridge's range's `phys.hi`
    /// and the function's range's first child cell.
    fn rp1(space: u32, bar: u32) -> Vec<Seen> {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("axi").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2))
            // bcm2712.dtsi's first and last windows (the last holds 0x1f_...).
            .prop("ranges", &[be64(0), be64(0), be64(0x10_0000_0000),
                              be64(0x1c_0000_0000), be64(0x1c_0000_0000), be64(0x4_0000_0000)].concat());
        b.begin("pcie@1000120000").prop("compatible", &cstr("brcm,bcm2712-pcie"))
            .prop("device_type", &cstr("pci"))
            .prop("#address-cells", &be32(3)).prop("#size-cells", &be32(2))
            .prop("ranges", &[be32(space), be64(0), be64(0x1f_0000_0000), be64(0xffff_fffc)].concat());
        b.begin("pci@0,0").prop("device_type", &cstr("pci"))
            .prop("#address-cells", &be32(3)).prop("#size-cells", &be32(2)).prop("ranges", &[]);
        b.begin("dev@0,0").prop("compatible", &cstr("pci1de4,1"))
            .prop("#address-cells", &be32(3)).prop("#size-cells", &be32(2))
            .prop("ranges", &[be32(bar), be64(0), be32(0x8201_0000), be64(0), be64(0x40_0000)].concat());
        b.begin("pci-ep-bus@1").prop("compatible", &cstr("simple-bus"))
            .prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2))
            .prop("ranges", &[be64(0x4000_0000), be32(1), be64(0), be64(0x40_0000)].concat());
        b.begin("i2c@40074000").prop("compatible", &cstr("snps,designware-i2c"))
            .prop("reg", &[be64(0x4007_4000), be64(0x1000)].concat()).end();
        b.end().end().end().end().end().end();
        walk(&b.blob()).1
    }

    /// The RP1's DesignWare I2C reaches its CPU address through the three
    /// `ranges` above it, two of them in 3-cell spaces: rp1 0x40074000 is
    /// "BAR 1" + 0x74000, PCI memory 0x74000, CPU 0x1f_0007_4000 (where the
    /// RP1's peripherals sit with the firmware's PCIe setup). Canary: the
    /// walk before this front refused any 3-cell `ranges`, and the node was
    /// not reported at all.
    #[test]
    fn the_rp1_i2c_is_translated_through_the_pcie_function_and_bridge() {
        let seen = rp1(0x0200_0000, 1);
        let i2c = seen.iter().find(|s| s.name == "i2c@40074000").expect("the RP1 I2C is a device");
        assert_eq!((i2c.base, i2c.size), (0x1f_0007_4000, 0x1000));
        assert_eq!(i2c.compat, ["snps,designware-i2c"]);
        assert!(seen.iter().all(|s| s.name != "dev@0,0" && s.name != "pci@0,0"), "a 3-cell reg is no window");
    }

    /// Below the PCI bridge only the same space matches: a range for I/O
    /// space does not carry a memory address (and 64-bit or prefetchable
    /// memory is still memory). Below the function's own 3-cell bus only the
    /// same first cell does: "BAR 2" is not BAR 1.
    #[test]
    fn a_three_cell_range_matches_only_its_own_space() {
        assert!(rp1(0x0100_0000, 1).is_empty(), "an I/O range translated a memory address");
        assert_eq!(rp1(0x4300_0000, 1)[0].base, 0x1f_0007_4000, "64-bit prefetchable memory is memory");
        assert!(rp1(0x0200_0000, 2).is_empty(), "BAR 2's range translated a BAR 1 address");
    }

    #[test]
    fn a_node_below_a_disabled_parent_is_not_reported() {
        let (n, seen) = behind(Some(vec![]), Some("disabled"));
        assert_eq!((n, seen.len()), (Some(0), 0));
        assert_eq!(behind(Some(vec![]), Some("okay")).1.len(), 1);
    }

    #[test]
    fn a_gic_specifier_is_numbered_from_its_type() {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("pl011@9000000").prop("compatible", &cstr("arm,pl011"))
            .prop("reg", &[be64(0x900_0000), be64(0x1000)].concat())
            .prop("interrupts", &[be32(0), be32(1), be32(4)].concat()).end();
        b.begin("timer@1").prop("compatible", &cstr("arm,armv8-timer"))
            .prop("reg", &[be64(0x1), be64(0x1)].concat())
            .prop("interrupts", &[be32(1), be32(13), be32(4)].concat()).end();
        b.end();
        let (n, seen) = walk(&b.blob());
        assert_eq!(n, Some(2));
        assert_eq!(seen[0].irq, 33, "SPI 1 is interrupt 33");
        assert_eq!(seen[1].irq, 29, "PPI 13 is interrupt 29");
    }

    /// The `dma_mask` each reported device carries, by node name.
    fn masks(blob: &[u8]) -> Vec<(String, u64)> {
        let mut v = Vec::new();
        let _ = unsafe {
            dtb_devices(blob.as_ptr(), &mut |d: &DtDevice<'_>| {
                v.push((String::from_utf8_lossy(d.name).into_owned(), d.dma_mask));
            })
        };
        v
    }

    /// A 2/2-cell root with `bus` (1/1 cells below it, `dma-ranges` as given,
    /// or none) holding one device.
    fn behind_dma(dma: Option<Vec<u8>>) -> Vec<u8> {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("plain@1000").prop("compatible", &cstr("vendor,plain"))
            .prop("reg", &[be64(0x1000), be64(0x100)].concat()).end();
        b.begin("bus").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[]);
        if let Some(d) = dma {
            b.prop("dma-ranges", &d);
        }
        b.begin("dev@2000").prop("compatible", &cstr("vendor,dev"))
            .prop("reg", &[be32(0x2000), be32(0x100)].concat()).end();
        b.end().end();
        b.blob()
    }

    #[test]
    fn dma_ranges_of_the_bus_limit_the_device_behind_it() {
        // child 0, parent 0 (bus child cells 1, root parent cells 2), 1 GiB.
        let dma = [be32(0), be64(0), be32(0x4000_0000)].concat();
        let m = masks(&behind_dma(Some(dma)));
        assert_eq!(m, [("plain@1000".to_string(), u64::MAX), ("dev@2000".to_string(), 0x3fff_ffff)],
            "only the node under the bus is limited");
    }

    #[test]
    fn no_dma_ranges_and_an_empty_one_restrict_nothing() {
        for dma in [None, Some(vec![])] {
            let m = masks(&behind_dma(dma));
            assert_eq!(m[1], ("dev@2000".to_string(), u64::MAX));
        }
    }

    #[test]
    fn the_highest_entry_end_wins_and_a_nested_bus_takes_the_tightest() {
        // Two entries from 0, [0, 1 GiB) and [0, 256 MiB): the limit is the larger.
        let two = [
            be32(0), be64(0), be32(0x1000_0000),
            be32(0), be64(0), be32(0x4000_0000),
        ].concat();
        assert_eq!(masks(&behind_dma(Some(two)))[1].1, 0x3fff_ffff);

        // A bus below a bus: the outer allows 4 GiB, the inner 1 GiB: 1 GiB.
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("outer").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[])
            .prop("dma-ranges", &[be32(0), be64(0), be32(0xffff_ffff)].concat());
        b.begin("inner").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[])
            .prop("dma-ranges", &[be32(0), be32(0), be32(0x4000_0000)].concat());
        b.begin("dev@10").prop("compatible", &cstr("vendor,dev"))
            .prop("reg", &[be32(0x10), be32(0x10)].concat()).end();
        b.end().end().end();
        assert_eq!(masks(&b.blob())[0].1, 0x3fff_ffff);
    }

    #[test]
    fn dma_ranges_decoder_edges() {
        use azos_dtb::dma_ranges_limit;
        let e = [be32(0), be64(0), be32(0x1000)].concat();
        assert_eq!(dma_ranges_limit(&e, 1, 2, 1), 0xfff);
        assert_eq!(dma_ranges_limit(&e[..e.len() - 1], 1, 2, 1), u64::MAX, "a partial entry is no entry");
        assert_eq!(dma_ranges_limit(&e, 0, 2, 1), u64::MAX, "cells outside the binding");
        assert_eq!(dma_ranges_limit(&e, 1, 3, 1), u64::MAX);
        let zero = [be32(0), be64(0), be32(0)].concat();
        assert_eq!(dma_ranges_limit(&zero, 1, 2, 1), u64::MAX, "a zero-size entry covers nothing");
        let top = [be32(0), be64(0), be32(0xffff_ffff)].concat();
        assert_eq!(dma_ranges_limit(&top, 1, 2, 1), 0xffff_fffe);
    }

    /// An entry the CPU address the driver allocated would not name correctly
    /// is refused, not turned into a mask (reviewer must-fix).
    #[test]
    fn dma_ranges_that_translate_or_start_above_zero_are_refused() {
        use azos_dtb::{dma_ranges_limit, DMA_UNREACHABLE};
        // The Raspberry Pi shape: bus 0xc0000000 is CPU 0.
        let alias = [be32(0xc000_0000), be64(0), be32(0x4000_0000)].concat();
        assert_eq!(dma_ranges_limit(&alias, 1, 2, 1), DMA_UNREACHABLE, "child != parent");
        // Same address on both sides but not from 0: memory under it is out of reach.
        let window = [be32(0x8000_0000), be64(0x8000_0000), be32(0x1000)].concat();
        assert_eq!(dma_ranges_limit(&window, 1, 2, 1), DMA_UNREACHABLE, "starts above 0");
        // One good entry does not save a bad one beside it.
        let mixed = [be32(0), be64(0), be32(0x4000_0000), be32(0x8000_0000), be64(0x1_0000_0000), be32(0x1000)].concat();
        assert_eq!(dma_ranges_limit(&mixed, 1, 2, 1), DMA_UNREACHABLE);
        // PCI: the high child cell is the space flags, not part of the address.
        let pci = [be32(0x4300_0000), be64(0), be64(0), be64(0x1_0000_0000)].concat();
        assert_eq!(dma_ranges_limit(&pci, 3, 2, 2), 0xffff_ffff, "flags ignored, identity from 0");
        let pci_shift = [be32(0x4300_0000), be64(0x4000_0000), be64(0), be64(0x1_0000_0000)].concat();
        assert_eq!(dma_ranges_limit(&pci_shift, 3, 2, 2), DMA_UNREACHABLE, "PCI address differs from CPU's");
    }

    /// A bus that moves its devices' DMA by one offset from CPU address 0
    /// (the Raspberry Pi's `/soc`) gives them its window and the offset, for
    /// the platform domain to apply; one that also starts above 0, or two
    /// entries that move differently, leave them unreachable. Canary: keep
    /// the old refusal of any translation and the Pi's USB host gets no DMA
    /// memory at all.
    #[test]
    fn a_translated_bus_gives_its_window_and_offset() {
        use azos_dtb::{dma_ranges_window, DMA_UNREACHABLE};
        let offsets = |blob: &[u8]| {
            let mut v = Vec::new();
            let _ = unsafe { dtb_devices(blob.as_ptr(), &mut |d: &DtDevice<'_>| v.push((d.dma_mask, d.dma_offset))) };
            v
        };
        let alias = [be32(0xc000_0000), be64(0), be32(0x4000_0000)].concat();
        assert_eq!(offsets(&behind_dma(Some(alias.clone())))[1], (0x3fff_ffff, 0xc000_0000));
        assert_eq!(offsets(&behind_dma(Some(alias)))[0], (u64::MAX, 0), "a device outside the bus");
        assert_eq!(dma_ranges_window(&[be32(0xc000_0000), be64(0), be32(0x3f00_0000)].concat(), 1, 2, 1),
            (0x3eff_ffff, 0xc000_0000), "bcm283x.dtsi's /soc");
        let above = [be32(0xc000_0000), be64(0x1000_0000), be32(0x1000)].concat();
        assert_eq!(dma_ranges_window(&above, 1, 2, 1), (DMA_UNREACHABLE, 0), "a window that starts above 0");
        let two = [be32(0xc000_0000), be64(0), be32(0x1000), be32(0x8000_0000), be64(0), be32(0x1000)].concat();
        assert_eq!(dma_ranges_window(&two, 1, 2, 1), (DMA_UNREACHABLE, 0), "two offsets");
        let same = [be32(0xc000_0000), be64(0), be32(0x1000), be32(0xc000_0000), be64(0), be32(0x4000)].concat();
        assert_eq!(dma_ranges_window(&same, 1, 2, 1), (0x3fff, 0xc000_0000), "one offset, the widest entry");
    }

    /// The Raspberry Pi 3 B tree: the USB host under `/soc` gets the VideoCore
    /// bus's window and offset.
    #[test]
    fn qemu_raspi3b_usb_is_behind_the_videocore_offset() {
        let b = include_bytes!("../fixtures/qemu-raspi3b.dtb").to_vec();
        let mut usb = None;
        let _ = unsafe {
            dtb_devices(b.as_ptr(), &mut |d: &DtDevice<'_>| {
                if d.name == b"usb@7e980000" {
                    usb = Some((d.base, d.dma_mask, d.dma_offset));
                }
            })
        };
        assert_eq!(usb, Some((0x3f98_0000, 0x3eff_ffff, 0xc000_0000)));
    }

    /// A node's `dma-ranges` describes its children's DMA, not its own: a bus
    /// that is itself a device (compatible + reg) is not limited by it
    /// (reviewer must-fix), its child is.
    #[test]
    fn a_nodes_own_dma_ranges_do_not_limit_the_node() {
        let mut b = B::new();
        b.begin("").prop("#address-cells", &be32(2)).prop("#size-cells", &be32(2));
        b.begin("bridge@5000").prop("#address-cells", &be32(1)).prop("#size-cells", &be32(1)).prop("ranges", &[])
            .prop("compatible", &cstr("vendor,bridge"))
            .prop("reg", &[be64(0x5000), be64(0x100)].concat())
            .prop("dma-ranges", &[be32(0), be64(0), be32(0x4000_0000)].concat());
        b.begin("dev@10").prop("compatible", &cstr("vendor,dev"))
            .prop("reg", &[be32(0x10), be32(0x10)].concat()).end();
        b.end().end();
        assert_eq!(masks(&b.blob()), [
            ("dev@10".to_string(), 0x3fff_ffff),
            ("bridge@5000".to_string(), u64::MAX),
        ]);
    }

    #[test]
    fn a_malformed_or_cut_blob_is_none_and_never_reads_past_its_end() {
        let blob = virt();
        for cut in 40..blob.len() {
            let mut b = blob[..cut].to_vec();
            b[4..8].copy_from_slice(&(cut as u32).to_be_bytes());
            let _ = walk(&b);
        }
        assert_eq!(walk(&[0u8; 8]).0, None);
        let mut bad = blob.clone();
        bad[0] = 0;
        assert_eq!(walk(&bad).0, None, "no magic");
        assert_eq!(unsafe { dtb_devices(core::ptr::null(), &mut |_| {}) }, None);
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

    /// Ssqosid (RV_SSQOSID) is an exact token, in both property forms, and a
    /// longer name that merely starts with it does not count.
    #[test]
    fn ssqosid_is_an_exact_token() {
        assert!(isa_prop_has_ext(b"rv64imafdc_sstc_ssqosid_svadu\0", false, b"ssqosid"));
        assert!(!isa_prop_has_ext(QEMU_DEFAULT, false, b"ssqosid"));
        assert!(!isa_prop_has_ext(b"rv64imac_ssqosidx\0", false, b"ssqosid"));
        assert!(isa_prop_has_ext(b"i\0m\0ssqosid\0", true, b"ssqosid"));
        assert!(!isa_prop_has_ext(b"i\0m\0ssqosidx\0", true, b"ssqosid"));
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

