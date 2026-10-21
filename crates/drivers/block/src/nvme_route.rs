// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arithmetic of the NVMe driver's queue plumbing, apart from the device:
//! which MSI-X vector belongs to which route, how many I/O queue pairs a
//! machine, a controller and an interrupt controller allow, which queue a
//! command slot prefers, and whether a completion belongs to the queue it was
//! read from. `nvme.rs` is the driver; this file has no register, no static
//! and no allocation, so the host tests run it as written.

use azos_drv_virtio::virtio::blk_proto::queue_of;

/// I/O queue pairs at most (Kconfig `NVME_QUEUES`).
pub const MAXQ: usize = azos_limits::NVME_QUEUES as usize;

/// The admin pair is queue 0 on MSI-X vector 0; I/O queue index `i` is queue
/// id `i + 1` on vector `i + 1`.
pub const VEC_ADMIN: u16 = 0;
pub const fn qid_of(index: usize) -> u16 {
    index as u16 + 1
}

/// The vectors of one CPU's route: what an `MsiRoute` is, as far as the NVMe
/// driver is concerned (`nvme.rs` implements it for every `MsiRoute`; it is a
/// trait of this file so the host can drive the arithmetic below without the
/// PCI transport).
pub trait CpuVectors {
    /// Make vectors `0..n` of this route deliverable. `false`: they are not,
    /// and the caller must do without all of them.
    fn prepare(&mut self, n: u16) -> bool;
    /// The (address, data) pair for vector `vec` of this route.
    fn target(&self, vec: u16) -> (u64, u32);
    /// The number the kernel's interrupt path passes to `msi_irq` for `vec`.
    fn isr_token(&self, vec: u16) -> u32;
}

/// Where the controller's MSI-X vectors are delivered: vector 0 for the admin
/// queue, vector `q` (1-based) for I/O queue `q`, which belongs to CPU `q - 1`.
/// The kernel builds one per machine from its interrupt controller.
pub trait QueueRoute {
    /// Make the admin vector and the vectors of up to `queues` I/O queues
    /// deliverable, queue `q`'s to CPU `q - 1` where the interrupt controller
    /// can, to the boot CPU where it can only do that. Returns how many I/O
    /// vectors work (`<= queues`); 0: no route on this machine, the controller
    /// is polled.
    fn prepare(&mut self, queues: u16) -> u16;
    /// The (address, data) pair for MSI-X table entry `vec`.
    fn target(&self, vec: u16) -> (u64, u32);
    /// The number the kernel's interrupt path passes to `msi_irq` for `vec`
    /// (`MsiRoute::isr_token`).
    fn isr_token(&self, vec: u16) -> u32;
    /// `true`: queue `q`'s interrupt lands on CPU `q - 1`, so it is raised only
    /// while that CPU runs. `false`: every vector lands on the boot CPU.
    fn per_cpu(&self) -> bool;
}

/// A [`QueueRoute`] made of one single-CPU route per CPU: the IMSIC
/// identities of each hart's file on riscv64, the vectors of each CPU's local
/// APIC on x86_64. `make(cpu)` builds the route of dense CPU `cpu`; CPU 0's
/// carries the admin vector as well as queue 1's.
pub struct PerCpuRoute<R: CpuVectors, F: FnMut(usize) -> R> {
    make: F,
    routes: [Option<R>; MAXQ],
}

impl<R: CpuVectors, F: FnMut(usize) -> R> PerCpuRoute<R, F> {
    pub fn new(make: F) -> Self {
        PerCpuRoute { make, routes: [const { None }; MAXQ] }
    }

    /// Which route carries MSI-X vector `vec`, and the vector's number in it.
    pub const fn locate(vec: u16) -> (usize, u16) {
        match vec {
            VEC_ADMIN => (0, 0),
            1 => (0, 1),
            v => (v as usize - 1, 0),
        }
    }
}

impl<R: CpuVectors, F: FnMut(usize) -> R> QueueRoute for PerCpuRoute<R, F> {
    fn prepare(&mut self, queues: u16) -> u16 {
        let mut routed = 0;
        for cpu in 0..(queues as usize).min(MAXQ) {
            let mut r = (self.make)(cpu);
            // A CPU whose route cannot be made (no file to write to, an
            // identity nothing would enable) ends the run: a queue without a
            // working vector would be completed by polling only, and the
            // queues are counted from the first CPU.
            if !r.prepare(if cpu == 0 { 2 } else { 1 }) {
                break;
            }
            self.routes[cpu] = Some(r);
            routed += 1;
        }
        routed
    }

    fn target(&self, vec: u16) -> (u64, u32) {
        let (route, local) = Self::locate(vec);
        self.routes.get(route).and_then(Option::as_ref).map_or((0, 0), |r| r.target(local))
    }

    fn isr_token(&self, vec: u16) -> u32 {
        let (route, local) = Self::locate(vec);
        self.routes.get(route).and_then(Option::as_ref).map_or(u32::MAX, |r| r.isr_token(local))
    }

    fn per_cpu(&self) -> bool {
        true
    }
}

// ---- How many queue pairs ----

/// As many queue pairs as there are CPUs to use them, command slots to keep
/// them busy, and Kconfig (`maxq`) allows; never none.
pub fn queues_wanted(maxq: usize, slots: usize, cpus: usize) -> usize {
    maxq.min(slots).min(cpus).max(1)
}

/// MSI-X vectors to ask the route for: one per queue wanted, and the table
/// holds the admin vector too. Caller has checked `table_size >= 2`.
pub fn vectors_wanted(queues: usize, table_size: u16) -> u16 {
    (queues as u16).min(table_size - 1)
}

/// Queue pairs once the route has answered: with interrupts, a queue without
/// a vector would be completed only by polling, so the route's count caps
/// them; polled, nothing does.
pub fn queues_routed(queues: usize, routed: usize, irq: bool) -> usize {
    if irq { queues.min(routed) } else { queues }
}

/// Queue pairs once the controller has answered Set Features / Number of
/// Queues: submission and completion queues are granted separately, and a pair
/// needs one of each.
pub fn queues_granted(queues: usize, nsq: u16, ncq: u16) -> usize {
    queues.min(nsq as usize).min(ncq as usize)
}

// ---- Slots ----

/// Queues whose completions raise an interrupt somebody takes, as a bit mask
/// (bit `qi`): all of them when the controller is polled anyway or when every
/// vector lands on the boot CPU, else those whose CPU `qi` runs (`online`).
pub fn served_queues(queues: usize, irq: bool, per_cpu: bool, online: impl Fn(usize) -> bool) -> u32 {
    (0..queues).fold(0, |m, qi| if !irq || !per_cpu || online(qi) { m | 1 << qi } else { m })
}

/// Order in which a CPU that prefers queue `pref` takes command slot `t`:
/// 0 its own queue, 1 another queue that raises interrupts, 2 a queue only
/// polling completes (its CPU is not running; the request layer still reaps
/// every slice, so the command finishes, a slice later).
pub fn slot_rank(t: usize, queues: usize, pref: usize, served: u32) -> usize {
    let qi = queue_of(t, queues);
    if served & (1 << qi) == 0 {
        2
    } else if qi == pref {
        0
    } else {
        1
    }
}

/// The command slot a completion names, if the completion can belong to queue
/// `qi` at all: it says it came from that queue's id and names a slot that is
/// on that queue (slot `t` is on queue `t mod queues`). A completion that does
/// not is the controller breaking the protocol.
pub fn completion_slot(qi: usize, queues: usize, sq_id: u16, cid: u16, slots: usize) -> Option<usize> {
    let slot = cid as usize;
    (sq_id == qid_of(qi) && slot < slots && queue_of(slot, queues) == qi).then_some(slot)
}
