// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NVMe wire protocol: the arithmetic and encodings, nothing else.
//!
//! No MMIO, no DMA memory, no allocation, no `unsafe`: every function takes
//! numbers and returns numbers. That is what lets `tests/host/nvme-tests`
//! check each one against the NVMe 1.4 base specification's field layout on
//! the host, and why the driver (`crates/drivers/block/src/nvme.rs`) holds
//! no bit-twiddling of its own.
//!
//! Scope: the NVM command set on a controller with MSI-X or polling, 4 KiB
//! controller memory pages, one admin queue pair and I/O queue pairs whose
//! entries are 64 B (SQ) and 16 B (CQ). Namespace formats other than 512-byte
//! blocks are decoded ([`Namespace`]) but the driver refuses them.
#![no_std]

// ---------------------------------------------------------------------
// Controller registers (NVMe 1.4, section 3.1)
// ---------------------------------------------------------------------

pub const REG_CAP: usize = 0x00;
pub const REG_VS: usize = 0x08;
pub const REG_INTMS: usize = 0x0c;
pub const REG_INTMC: usize = 0x10;
pub const REG_CC: usize = 0x14;
pub const REG_CSTS: usize = 0x1c;
pub const REG_AQA: usize = 0x24;
pub const REG_ASQ: usize = 0x28;
pub const REG_ACQ: usize = 0x30;
/// First doorbell register; see [`doorbell_offset`].
pub const DOORBELL_BASE: usize = 0x1000;

pub const CC_EN: u32 = 1 << 0;
pub const CSTS_RDY: u32 = 1 << 0;
pub const CSTS_CFS: u32 = 1 << 1;

/// Size of a submission queue entry (`CC.IOSQES` = 6) and of a completion
/// queue entry (`CC.IOCQES` = 4), as powers of two.
pub const SQE_BYTES: usize = 64;
pub const CQE_BYTES: usize = 16;
pub const SQES_LOG2: u32 = 6;
pub const CQES_LOG2: u32 = 4;

/// Controller memory page size this driver programs (`CC.MPS` = 0 -> 4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Decoded `CAP` register (section 3.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    /// Maximum queue entries supported, as a count (the register is 0-based).
    pub max_queue_entries: u32,
    /// Contiguous queues required (`CQR`): the queue memory must be one
    /// physically contiguous run. Ours always is (one page each).
    pub contiguous_required: bool,
    /// Worst-case wait for `CSTS.RDY` to change, in milliseconds
    /// (`CAP.TO` is in 500 ms units).
    pub ready_timeout_ms: u64,
    /// Doorbell stride exponent: doorbells are `4 << dstrd` bytes apart.
    pub dstrd: u32,
    /// The NVM command set is supported (`CSS` bit 0).
    pub nvm_command_set: bool,
    /// Minimum / maximum controller memory page size, as `2^(12 + n)`.
    pub mps_min_shift: u32,
    pub mps_max_shift: u32,
}

pub fn decode_cap(cap: u64) -> Cap {
    Cap {
        max_queue_entries: (cap & 0xffff) as u32 + 1,
        contiguous_required: cap >> 16 & 1 != 0,
        ready_timeout_ms: (cap >> 24 & 0xff) * 500,
        dstrd: (cap >> 32 & 0xf) as u32,
        nvm_command_set: cap >> 37 & 1 != 0,
        mps_min_shift: 12 + (cap >> 48 & 0xf) as u32,
        mps_max_shift: 12 + (cap >> 52 & 0xf) as u32,
    }
}

/// `CC` value that enables the controller with the NVM command set, 4 KiB
/// pages, round-robin arbitration, 64 B SQEs and 16 B CQEs.
pub const fn cc_enable() -> u32 {
    CC_EN | (SQES_LOG2 << 16) | (CQES_LOG2 << 20)
}

/// `AQA` for an admin queue pair of `sq_entries` / `cq_entries` entries
/// (both 2..=4096; the fields are 0-based).
pub const fn aqa(sq_entries: u32, cq_entries: u32) -> u32 {
    (sq_entries - 1) | ((cq_entries - 1) << 16)
}

// ---------------------------------------------------------------------
// Queues and doorbells
// ---------------------------------------------------------------------

/// Byte offset, from the register base, of the doorbell of queue `qid`:
/// the SQ tail doorbell (`cq == false`) or the CQ head doorbell. Section
/// 3.1.10: `0x1000 + (2 * qid + cq) * (4 << CAP.DSTRD)`.
pub const fn doorbell_offset(qid: u16, cq: bool, dstrd: u32) -> usize {
    let stride = if cfg!(feature = "canary-doorbell") { 4 } else { 4usize << dstrd };
    DOORBELL_BASE + (2 * qid as usize + cq as usize) * stride
}

/// The index after `i` in a ring of `depth` entries.
pub const fn ring_next(i: u16, depth: u16) -> u16 {
    if i + 1 >= depth { 0 } else { i + 1 }
}

/// A submission queue is full when advancing the tail would make it equal to
/// the head (one slot is always left empty, so full and empty differ).
pub const fn sq_full(head: u16, tail: u16, depth: u16) -> bool {
    if cfg!(feature = "canary-full") {
        // Full and empty confused: an empty queue reads full.
        return tail == head;
    }
    ring_next(tail, depth) == head
}

/// Entries between head and tail (what is queued and not yet consumed).
pub const fn sq_used(head: u16, tail: u16, depth: u16) -> u16 {
    if tail >= head { tail - head } else { depth - head + tail }
}

/// Where the next completion will appear in a completion queue: the head
/// index and the phase tag the controller writes there. The phase starts at
/// 1 (the queue memory is zeroed) and flips every time the head wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqCursor {
    pub head: u16,
    pub phase: bool,
}

impl CqCursor {
    pub const fn new() -> Self {
        CqCursor { head: 0, phase: true }
    }

    /// Step past one consumed entry.
    pub fn advance(&mut self, depth: u16) {
        self.head = ring_next(self.head, depth);
        if self.head == 0 && !cfg!(feature = "canary-phase") {
            self.phase = !self.phase;
        }
    }
}

// ---------------------------------------------------------------------
// Completion queue entries (section 4.6)
// ---------------------------------------------------------------------

/// A completion queue entry as four little-endian dwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Cqe {
    pub dw0: u32,
    pub dw1: u32,
    pub dw2: u32,
    pub dw3: u32,
}

impl Cqe {
    /// The phase tag: equals the cursor's phase exactly when the controller
    /// has written this entry in the current lap.
    pub const fn phase(&self) -> bool {
        self.dw3 >> 16 & 1 != 0
    }
    /// The command identifier of the command this completes.
    pub const fn cid(&self) -> u16 {
        self.dw3 as u16
    }
    /// Status code (bits 7:0) and status code type (10:8): `dw3[27:17]`.
    /// The CRD, More and Do Not Retry bits above them are not part of it.
    /// 0 is success.
    pub const fn status(&self) -> u16 {
        (self.dw3 >> 17 & 0x7ff) as u16
    }
    /// The controller's submission queue head when it posted this entry:
    /// every SQ slot before it is free again.
    pub const fn sq_head(&self) -> u16 {
        self.dw2 as u16
    }
    pub const fn sq_id(&self) -> u16 {
        (self.dw2 >> 16) as u16
    }
    pub const fn is_success(&self) -> bool {
        self.status() == 0
    }
    /// Do Not Retry (`DNR`, bit 31).
    pub const fn do_not_retry(&self) -> bool {
        self.dw3 >> 31 & 1 != 0
    }
}

/// Is `cqe` new for a cursor at `phase`?
pub const fn cqe_is_new(cqe: &Cqe, phase: bool) -> bool {
    cqe.phase() == phase
}

/// Status code type (bits 10:8 of [`Cqe::status`]).
pub const fn status_type(status: u16) -> u8 {
    (status >> 8 & 7) as u8
}
/// Status code (bits 7:0 of [`Cqe::status`]).
pub const fn status_code(status: u16) -> u8 {
    status as u8
}

// ---------------------------------------------------------------------
// Submission queue entries (section 4.2)
// ---------------------------------------------------------------------

pub const OP_ADMIN_DELETE_SQ: u8 = 0x00;
pub const OP_ADMIN_CREATE_SQ: u8 = 0x01;
pub const OP_ADMIN_DELETE_CQ: u8 = 0x04;
pub const OP_ADMIN_CREATE_CQ: u8 = 0x05;
pub const OP_ADMIN_IDENTIFY: u8 = 0x06;
pub const OP_ADMIN_SET_FEATURES: u8 = 0x09;
pub const OP_NVM_FLUSH: u8 = 0x00;
pub const OP_NVM_WRITE: u8 = 0x01;
pub const OP_NVM_READ: u8 = 0x02;
/// Dataset Management (section 6.7): with the Deallocate attribute, a TRIM.
pub const OP_NVM_DSM: u8 = 0x09;

pub const CNS_NAMESPACE: u8 = 0x00;
pub const CNS_CONTROLLER: u8 = 0x01;
pub const FID_NUMBER_OF_QUEUES: u8 = 0x07;

/// A 64-byte submission queue entry as sixteen little-endian dwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sqe(pub [u32; 16]);

impl Sqe {
    const fn base(opcode: u8, cid: u16, nsid: u32) -> Self {
        let mut d = [0u32; 16];
        // CDW0: opcode 7:0, FUSE 9:8 = 0, PSDT 15:14 = 0 (PRPs), CID 31:16.
        d[0] = opcode as u32 | (cid as u32) << 16;
        d[1] = nsid;
        Sqe(d)
    }
    const fn prps(mut self, prp1: u64, prp2: u64) -> Self {
        self.0[6] = prp1 as u32;
        self.0[7] = (prp1 >> 32) as u32;
        self.0[8] = prp2 as u32;
        self.0[9] = (prp2 >> 32) as u32;
        self
    }
    pub const fn opcode(&self) -> u8 {
        self.0[0] as u8
    }
    pub const fn cid(&self) -> u16 {
        (self.0[0] >> 16) as u16
    }
    pub const fn nsid(&self) -> u32 {
        self.0[1]
    }
    pub const fn prp1(&self) -> u64 {
        self.0[6] as u64 | (self.0[7] as u64) << 32
    }
    pub const fn prp2(&self) -> u64 {
        self.0[8] as u64 | (self.0[9] as u64) << 32
    }
    /// Starting LBA of a read/write.
    pub const fn slba(&self) -> u64 {
        self.0[10] as u64 | (self.0[11] as u64) << 32
    }
    /// Number of logical blocks of a read/write, 0-based in CDW12[15:0].
    pub const fn nlb_field(&self) -> u16 {
        self.0[12] as u16
    }
    /// The entry as the bytes the controller reads.
    pub fn to_bytes(&self) -> [u8; SQE_BYTES] {
        let mut b = [0u8; SQE_BYTES];
        for (i, d) in self.0.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&d.to_le_bytes());
        }
        b
    }
}

/// Identify (CNS `cns`) into the 4 KiB page at `prp1`.
pub const fn identify(cid: u16, nsid: u32, cns: u8, prp1: u64) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_IDENTIFY, cid, nsid).prps(prp1, 0);
    s.0[10] = cns as u32;
    s
}

/// Set Features, Number of Queues: ask for `sq` submission and `cq`
/// completion I/O queues (counts, not 0-based; the field is 0-based).
pub const fn set_number_of_queues(cid: u16, sq: u16, cq: u16) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_SET_FEATURES, cid, 0);
    s.0[10] = FID_NUMBER_OF_QUEUES as u32;
    s.0[11] = (sq as u32 - 1) | (cq as u32 - 1) << 16;
    s
}

/// Create I/O Completion Queue `qid` of `entries` entries at physical
/// `queue_pa`, physically contiguous, interrupt vector `vector` when
/// `interrupts` (else polled).
pub const fn create_io_cq(cid: u16, qid: u16, entries: u16, queue_pa: u64, vector: u16, interrupts: bool) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_CREATE_CQ, cid, 0).prps(queue_pa, 0);
    s.0[10] = qid as u32 | (entries as u32 - 1) << 16;
    // CDW11: PC (bit 0) = 1, IEN (bit 1), IV (31:16).
    s.0[11] = 1 | (interrupts as u32) << 1 | (vector as u32) << 16;
    s
}

/// Create I/O Submission Queue `qid` of `entries` entries at physical
/// `queue_pa`, completing into CQ `cqid`, medium priority class unused.
pub const fn create_io_sq(cid: u16, qid: u16, entries: u16, queue_pa: u64, cqid: u16) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_CREATE_SQ, cid, 0).prps(queue_pa, 0);
    s.0[10] = qid as u32 | (entries as u32 - 1) << 16;
    // CDW11: PC (bit 0) = 1, QPRIO (2:1) = 0, CQID (31:16).
    s.0[11] = 1 | (cqid as u32) << 16;
    s
}

pub const fn delete_io_sq(cid: u16, qid: u16) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_DELETE_SQ, cid, 0);
    s.0[10] = qid as u32;
    s
}

pub const fn delete_io_cq(cid: u16, qid: u16) -> Sqe {
    let mut s = Sqe::base(OP_ADMIN_DELETE_CQ, cid, 0);
    s.0[10] = qid as u32;
    s
}

/// NVM Read (`write == false`) or Write of `count` logical blocks (1..=65536)
/// from `slba`, data described by `prp1` / `prp2` (see [`build_prps`]).
pub const fn read_write(cid: u16, nsid: u32, write: bool, slba: u64, count: u32, prp1: u64, prp2: u64) -> Sqe {
    let op = if write { OP_NVM_WRITE } else { OP_NVM_READ };
    let mut s = Sqe::base(op, cid, nsid).prps(prp1, prp2);
    s.0[10] = slba as u32;
    s.0[11] = (slba >> 32) as u32;
    // CDW12[15:0]: number of logical blocks, 0-based.
    s.0[12] = if cfg!(feature = "canary-nlb") { count } else { count - 1 } & 0xffff;
    s
}

/// NVM Flush of namespace `nsid`.
pub const fn flush(cid: u16, nsid: u32) -> Sqe {
    Sqe::base(OP_NVM_FLUSH, cid, nsid)
}

/// `sqe`, a Write, with Force Unit Access (CDW12 bit 30): the data is on
/// stable media when the command completes, whatever the volatile write
/// cache holds.
pub const fn with_fua(mut sqe: Sqe) -> Sqe {
    sqe.0[12] |= 1 << 30;
    sqe
}

/// Bytes of one Dataset Management range descriptor (section 6.7.1).
pub const DSM_RANGE_BYTES: usize = 16;

/// Dataset Management of namespace `nsid` that deallocates (TRIM) the
/// `ranges` range descriptors the data buffer at `prp1` holds
/// ([`dsm_range`] each; 1 to 256 of them).
pub const fn dataset_management_deallocate(cid: u16, nsid: u32, ranges: u32, prp1: u64) -> Sqe {
    let mut s = Sqe::base(OP_NVM_DSM, cid, nsid).prps(prp1, 0);
    // CDW10[7:0]: number of ranges, 0-based. CDW11 bit 2: AD, attribute
    // Deallocate.
    s.0[10] = (ranges - 1) & 0xff;
    s.0[11] = 1 << 2;
    s
}

/// One Dataset Management range descriptor: no context attributes, `count`
/// logical blocks from `slba`.
pub fn dsm_range(slba: u64, count: u32) -> [u8; DSM_RANGE_BYTES] {
    let mut r = [0u8; DSM_RANGE_BYTES];
    r[4..8].copy_from_slice(&count.to_le_bytes());
    r[8..16].copy_from_slice(&slba.to_le_bytes());
    r
}

// ---------------------------------------------------------------------
// PRPs (section 4.1.1)
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrpError {
    /// No data, or `pages` does not hold one entry per page touched.
    BadShape,
    /// The transfer needs more PRP list entries than the list holds (this
    /// builder does not chain lists).
    ListTooSmall,
    /// A data page address is not page aligned.
    Unaligned,
}

/// Pages a transfer of `len` bytes touches when it starts `offset` bytes
/// into a page.
pub const fn pages_spanned(offset: usize, len: usize) -> usize {
    if len == 0 { 0 } else { (offset + len).div_ceil(PAGE_SIZE) }
}

/// Fill a PRP list for a transfer of `len` bytes that starts `first_offset`
/// bytes into `pages[0]`, where `pages[i]` is the PHYSICAL address of the
/// i-th page it touches (each page-aligned; pages need not be contiguous).
/// Returns `(prp1, prp2)`:
///
/// * one page: `prp2 = 0`;
/// * two pages: `prp2` is the second page's address;
/// * more: `prp2 = list_pa`, and `list[0..n-1]` receives `pages[1..n]`.
///
/// Every page after the first must be used from its start, so the whole
/// transfer is contiguous in the device's view; only the last may be partial.
pub fn build_prps(
    pages: &[u64],
    first_offset: usize,
    len: usize,
    list_pa: u64,
    list: &mut [u64],
) -> Result<(u64, u64), PrpError> {
    let n = pages_spanned(first_offset, len);
    if n == 0 || first_offset >= PAGE_SIZE || pages.len() < n {
        return Err(PrpError::BadShape);
    }
    if pages[..n].iter().any(|p| p % PAGE_SIZE as u64 != 0) {
        return Err(PrpError::Unaligned);
    }
    let prp1 = pages[0] + first_offset as u64;
    match n {
        1 => Ok((prp1, 0)),
        2 => Ok((prp1, pages[1])),
        _ => {
            if n - 1 > list.len() {
                return Err(PrpError::ListTooSmall);
            }
            for i in 1..n {
                list[i - 1] = pages[i];
            }
            let prp2 = if cfg!(feature = "canary-prp") { pages[1] } else { list_pa };
            Ok((prp1, prp2))
        }
    }
}

/// Entries a PRP list needs for a transfer of `n_pages` pages.
pub const fn prp_list_entries(n_pages: usize) -> usize {
    if n_pages <= 2 { 0 } else { n_pages - 1 }
}

// ---------------------------------------------------------------------
// Identify data (section 5.15.2)
// ---------------------------------------------------------------------

/// What the driver needs from Identify Controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controller {
    /// Number of namespaces (`NN`).
    pub namespaces: u32,
    /// Maximum data transfer size as a power-of-two multiple of the minimum
    /// page size (`MDTS`), 0 = no limit.
    pub mdts: u8,
    /// A volatile write cache is present (`VWC` bit 0): Flush is meaningful
    /// and a write is durable only after it. Without one, Flush may be
    /// answered `Invalid Opcode` and is then a successful no-op.
    pub volatile_write_cache: bool,
    /// The controller implements Dataset Management (`ONCS` bit 2), so a
    /// deallocate (TRIM) can be sent.
    pub dataset_management: bool,
}

/// Decode a 4096-byte Identify Controller structure.
pub fn decode_controller(id: &[u8; 4096]) -> Controller {
    Controller {
        namespaces: u32::from_le_bytes([id[516], id[517], id[518], id[519]]),
        mdts: id[77],
        volatile_write_cache: id[525] & 1 != 0,
        dataset_management: id[520] & (1 << 2) != 0,
    }
}

/// The largest transfer in 512-byte sectors that `mdts` allows with 4 KiB
/// pages (`u32::MAX` for no limit).
pub const fn mdts_max_sectors(mdts: u8) -> u32 {
    if mdts == 0 || mdts >= 20 { u32::MAX } else { (PAGE_SIZE as u32 / 512) << mdts }
}

/// What the driver needs from Identify Namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Size in logical blocks (`NSZE`).
    pub blocks: u64,
    /// log2 of the block size of the formatted LBA format (`LBADS`).
    pub lba_shift: u8,
    /// Metadata bytes per block of that format (`MS`); the driver needs 0.
    pub metadata_bytes: u16,
}

/// Decode a 4096-byte Identify Namespace structure.
pub fn decode_namespace(id: &[u8; 4096]) -> Namespace {
    let mut sz = [0u8; 8];
    sz.copy_from_slice(&id[0..8]);
    let flbas = id[26];
    // FLBAS[3:0] is the format index; with more than 16 formats, [6:5] are
    // its upper bits.
    let idx = (flbas & 0xf) as usize | ((flbas >> 5 & 3) as usize) << 4;
    let o = 128 + 4 * idx;
    let lbaf = u32::from_le_bytes([id[o], id[o + 1], id[o + 2], id[o + 3]]);
    Namespace {
        blocks: u64::from_le_bytes(sz),
        lba_shift: (lbaf >> 16 & 0xff) as u8,
        metadata_bytes: lbaf as u16,
    }
}

/// Queues the controller granted: `(submission, completion)` counts from the
/// Set Features (Number of Queues) completion's dword 0 (both 0-based there).
pub const fn granted_queues(dw0: u32) -> (u16, u16) {
    ((dw0 as u16).wrapping_add(1), ((dw0 >> 16) as u16).wrapping_add(1))
}
