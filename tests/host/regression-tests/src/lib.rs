// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Regression tests for previously-fixed kernel bugs.
//!
//! Each module pins a specific bug. Adding a new module here is the
//! standard procedure when fixing a kernel bug — it ensures the bug
//! cannot silently reappear after a refactor.

#![cfg(test)]

mod property;
mod crypto_tests;
mod host_microbench;

// O3.5 (H20): `driver_mocks`, `mm_tests`, `net_tests`, `sched_tests`,
// `ipc_tests`, `fs_tests`, `security_tests`, `auth_envelope_tests` used
// to be declared here. Every one of them hand-replicated the logic it
// claimed to watch — "mirrors ipc/pipe.rs", "replicate the EXACT
// bit-twiddling logic", a whole second SHA-256/HMAC/envelope that never
// touched `auth_envelope.rs` — so a real refactor and a copy's own typo
// looked identical to the gate (U15-1/U15-6: `sched_tests.rs`'s
// `RT_TIME_SLICE_TICKS = 10` against the kernel's real `0`;
// `security_tests.rs`'s `USER_STACK_TOP`/`USER_IMAGE_MAX` accepting a
// `p_vaddr` the real loader refuses). Dedicated crates that pull the
// REAL source via `#[path]` now cover the same ground for real:
// `mm-tests` (`crates/core/mm/src/pmm.rs`), `net-tests`
// (`crates/net/net/src/tcp.rs` — the exact `window_clamp`/rx-ring properties
// `tcp_ring_buffer`/`tcp_window_clamp` below used to mirror), `fs-tests`,
// `ipc-chan-tests`, `crypto-tests` (a correct, real `Aes128::encrypt_block`
// round-trip already existed there — see this crate's own
// `crypto_tests::aes128_fips_sample` fix). `sched-wake-tests` /
// `sched-policy-tests` cover the real scheduler constants and logic
// `sched_tests.rs` mirrored instead of pulling in. `driver_mocks` tested
// only that its own mocks behaved as configured — nothing in the tree
// ever exercised real driver logic against them.
//
// The eight files are still physically present in
// `tests/host/regression-tests/src/` (this session's sandbox refused a bulk
// `rm` as irreversible destruction) but are no longer compiled or run —
// dead weight, not dead code the gate counts. Deleting them for real is
// a one-line follow-up: `rm tests/host/regression-tests/src/{driver_mocks,mm_tests,net_tests,sched_tests,ipc_tests,fs_tests,security_tests,auth_envelope_tests}.rs`.

// ── DTB parser bugs (REVIEW.dtb-4) ────────────────────────────────────────
// We pull dtb's lib.rs in as a sub-module via #[path] so we exercise the
// exact code shipped in the kernel without dragging in azos_drv_*.

#[path = "../../../../crates/drivers/dtb/src/lib.rs"]
#[allow(dead_code, unused_imports, clippy::all)]
mod dtb_src;

#[cfg(test)]
mod dtb {
    use super::dtb_src;

    /// FDT magic + format constants (mirror dtb_src consts; they're private).
    const FDT_MAGIC:       u32 = 0xd00d_feed;
    const FDT_BEGIN_NODE:  u32 = 1;
    const FDT_END_NODE:    u32 = 2;
    const FDT_PROP:        u32 = 3;
    const FDT_END:         u32 = 9;

    fn align4(v: usize) -> usize { (v + 3) & !3 }

    /// Builder for a minimal FDT blob in memory. Not exhaustive — just
    /// enough to drive `dtb_parse` through the paths we care about.
    struct FdtBuilder {
        structs:  Vec<u8>,
        strings:  Vec<u8>,
    }

    impl FdtBuilder {
        fn new() -> Self {
            Self { structs: Vec::new(), strings: Vec::new() }
        }

        fn put_be32(&mut self, v: u32) {
            self.structs.extend_from_slice(&v.to_be_bytes());
        }

        /// Unused today. Kept because `FdtBuilder` mirrors the FDT wire format
        /// and a builder missing one width is how the next test hand-rolls it.
        #[allow(dead_code)]
        fn put_be64(&mut self, v: u64) {
            self.structs.extend_from_slice(&v.to_be_bytes());
        }

        fn put_str_offset(&mut self, name: &[u8]) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name);
            self.strings.push(0);
            off
        }

        fn begin_node(&mut self, name: &[u8]) {
            self.put_be32(FDT_BEGIN_NODE);
            self.structs.extend_from_slice(name);
            self.structs.push(0);
            while self.structs.len() % 4 != 0 { self.structs.push(0); }
        }

        fn end_node(&mut self) { self.put_be32(FDT_END_NODE); }

        fn prop_u32(&mut self, name: &[u8], val: u32) {
            let str_off = self.put_str_offset(name);
            self.put_be32(FDT_PROP);
            self.put_be32(4);
            self.put_be32(str_off);
            self.put_be32(val);
        }

        fn prop_bytes(&mut self, name: &[u8], data: &[u8]) {
            let str_off = self.put_str_offset(name);
            self.put_be32(FDT_PROP);
            self.put_be32(data.len() as u32);
            self.put_be32(str_off);
            self.structs.extend_from_slice(data);
            while self.structs.len() % 4 != 0 { self.structs.push(0); }
        }

        /// Serialise the full FDT (header + structs + strings).
        fn build(&mut self) -> Vec<u8> {
            self.put_be32(FDT_END);

            const HDR_SIZE: usize = 40;
            let off_dt_struct  = HDR_SIZE;
            let off_dt_strings = HDR_SIZE + align4(self.structs.len());
            let totalsize      = off_dt_strings + self.strings.len();

            let mut out = Vec::with_capacity(totalsize);
            out.extend_from_slice(&FDT_MAGIC.to_be_bytes());          //  0
            out.extend_from_slice(&(totalsize as u32).to_be_bytes()); //  4
            out.extend_from_slice(&(off_dt_struct as u32).to_be_bytes());  //  8
            out.extend_from_slice(&(off_dt_strings as u32).to_be_bytes()); // 12
            out.extend_from_slice(&0u32.to_be_bytes());               // 16 mem_rsvmap
            out.extend_from_slice(&17u32.to_be_bytes());              // 20 version
            out.extend_from_slice(&16u32.to_be_bytes());              // 24 last_comp
            out.extend_from_slice(&0u32.to_be_bytes());               // 28 boot_cpuid
            out.extend_from_slice(&(self.strings.len() as u32).to_be_bytes()); // 32
            out.extend_from_slice(&(self.structs.len() as u32).to_be_bytes()); // 36

            out.extend_from_slice(&self.structs);
            while out.len() % 4 != 0 { out.push(0); }
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// Build the typical QEMU virt FDT shape: root with #address-cells=2,
    /// then /cpus (with its OWN #address-cells=1, #size-cells=0 override),
    /// then /memory@80000000.
    ///
    /// The bug we're locking down: previously the parser stored
    /// `address_cells/size_cells` globally, so the /cpus override leaked
    /// into the /memory parse and silently returned mem_base=0, mem_size=0.
    /// Equally, the depth check was off-by-one (root child at depth==1
    /// instead of 2), so /cpus and /memory weren't recognised at all.
    fn build_qemu_virt_like_fdt(num_cpus: usize, mem_base: u64,
                                 mem_size: u64, timer_freq: u32) -> Vec<u8> {
        let mut b = FdtBuilder::new();
        b.begin_node(b"");                    // root
        b.prop_u32(b"#address-cells", 2);
        b.prop_u32(b"#size-cells",    2);
        b.prop_bytes(b"compatible", b"riscv-virtio\0");

        // /cpus  — note its OWN address-cells/size-cells (the trap)
        b.begin_node(b"cpus");
        b.prop_u32(b"#address-cells", 1);
        b.prop_u32(b"#size-cells",    0);
        b.prop_u32(b"timebase-frequency", timer_freq);
        for i in 0..num_cpus {
            let mut name = b"cpu@".to_vec();
            name.extend_from_slice(format!("{i}").as_bytes());
            b.begin_node(&name);
            b.prop_u32(b"reg", i as u32);
            b.end_node();
        }
        b.end_node(); // /cpus

        // /memory@80000000 — uses ROOT's 2/2 cells, NOT cpus' 1/0.
        b.begin_node(b"memory@80000000");
        let mut reg = Vec::new();
        reg.extend_from_slice(&mem_base.to_be_bytes());
        reg.extend_from_slice(&mem_size.to_be_bytes());
        b.prop_bytes(b"reg", &reg);
        b.end_node(); // /memory

        b.end_node(); // root
        b.build()
    }

    #[test]
    fn dtb_4_depth_bug_recognises_root_children() {
        // Before the fix, the parser checked depth==1 for root children, but
        // because the implementation increments depth ON entering root,
        // root-children sit at depth==2. The fix renamed depth==1 → 2.
        // Without the fix, num_cpus=0, mem_base=0, mem_size=0.
        let blob = build_qemu_virt_like_fdt(2, 0x8000_0000, 0x800_0000, 10_000_000);
        let info = unsafe { dtb_src::dtb_parse(blob.as_ptr()) }.expect("FDT must parse");
        assert_eq!(info.num_cpus,   2,           "num_cpus must be detected");
        assert_eq!(info.mem_base,   0x8000_0000, "mem_base must come from DTB");
        assert_eq!(info.mem_size,   0x800_0000,  "mem_size must come from DTB");
        assert_eq!(info.timer_freq, 10_000_000,  "timer_freq must come from DTB");
    }

    #[test]
    fn dtb_4_cells_stack_does_not_leak_cpus_override_into_memory() {
        // Specifically: /cpus declares 1/0, /memory must still parse with
        // root's 2/2. If the override leaked, mem_base/mem_size would be
        // wrong (we'd read only 4 bytes of the 16-byte reg).
        let blob = build_qemu_virt_like_fdt(1, 0x4000_0000, 0x4000_0000, 1_000_000);
        let info = unsafe { dtb_src::dtb_parse(blob.as_ptr()) }.expect("FDT must parse");
        assert_eq!(info.mem_base, 0x4000_0000);
        assert_eq!(info.mem_size, 0x4000_0000);
    }

    #[test]
    fn dtb_4_no_cpus_node_returns_zero_count_not_garbage() {
        // Defensive: an FDT with no /cpus node must return num_cpus=0.
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.prop_u32(b"#address-cells", 2);
        b.prop_u32(b"#size-cells",    2);
        b.begin_node(b"memory@80000000");
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x8000_0000u64.to_be_bytes());
        reg.extend_from_slice(&0x100_0000u64.to_be_bytes());
        b.prop_bytes(b"reg", &reg);
        b.end_node();
        b.end_node();
        let blob = b.build();
        let info = unsafe { dtb_src::dtb_parse(blob.as_ptr()) }.expect("FDT must parse");
        assert_eq!(info.num_cpus, 0);
        assert_eq!(info.mem_base, 0x8000_0000);
    }

    #[test]
    fn dtb_4_invalid_magic_returns_none() {
        let mut blob = build_qemu_virt_like_fdt(1, 0, 0, 0);
        // Corrupt the magic — first 4 bytes.
        blob[0] = 0xff;
        let info = unsafe { dtb_src::dtb_parse(blob.as_ptr()) };
        assert!(info.is_none(), "Bad magic must be rejected");
    }
}

// ── TCP recv buffer / window clamp / VirtIO poll / WCET ordering ─────────
// O3.5 (H20): four modules used to live here —
// `tcp_ring_buffer`/`tcp_window_clamp` hand-replicated `net::tcp.rs`'s
// rx-ring store and `window_clamp`, `virtio_poll_contract` asserted only
// on a local `Option` it built itself (U15-7: "confirms the test crate
// compiles against the exposed signature shape", never touching
// `crates/drivers/virtio/src/virtio/mod.rs`), `wcet_ordering` timed two
// synthetic loops against each other, not `kernel/src/main.rs`'s actual
// `wcet_end`/`schedule()` ordering.
//
// All four are superseded by REAL coverage that pulls the actual source
// via `#[path]`: `net-tests/src/lib.rs` (`#[path] mod tcp;` — the
// "ACK must cover exactly what was stored" property, and
// `window_clamp` at its 128 KiB/16 KiB ring sizes) and
// `drivers-tests/src/lib.rs` (`#[path] mod virtio;` —
// `virtq_poll_with_len` returning `Some((id, len))`/`None` against the
// real used-ring). `wcet_ordering` has no such counterpart; deleting it
// is a net loss of coverage for that one property, but a synthetic
// self-race that never called `kernel::` code was not coverage either.
//
// ── OTA anti-rollback (OT03) — covered exhaustively in ota-tests crate.
// ── OTA recovery slot (OT04)  — covered in ota-tests.
// ── OTA prod key infra (OT05) — build-time, exercised by `cargo build`.
