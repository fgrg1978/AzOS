# Storage

This page describes the storage stack from the block device up: the block
layer and its queues, the FAT32 driver and its power-loss ordering, the file
page cache, the native `azvol` volume format, the directory-capability
namespace that ring-3 tasks open files through, and the ext4 module set
built from the Linux tree. The memory side of the page cache
(frames, reclaim, mappings) is in [memory.md](memory.md).

Contents:

1. [Block layer and queues](#block-layer-and-queues)
2. [FAT32: journal, write ordering and the dirty bit](#fat32-journal-write-ordering-and-the-dirty-bit)
3. [The page-cache path](#the-page-cache-path)
4. [azvol](#azvol)
5. [Directory capabilities and `Cap<Dir>` namespaces](#directory-capabilities-and-capdir-namespaces)
6. [ext4 and the Linux module set](#ext4-and-the-linux-module-set)

## Block layer and queues

Every filesystem and the swap area reach the medium through one module,
`azos_drv_block::blkdev`. It forwards to a single backend chosen at build time
through the `BlockDevice` trait (`crates/drivers/api/src/block.rs`):
`init`, `capacity_sectors`, `read`, `write` and `flush`. Sectors are 512 bytes.

| Backend | Where | Notes |
|---------|-------|-------|
| `Queued` | `blkdev::Queued`, over `crates/drivers/block/src/queue.rs` | Default backend: the device bound to the block request layer. Every method is a request for the caller's Domain that waits for its outcome. |
| virtio-blk | `crates/drivers/virtio/src/virtio/blk.rs` | A hardware queue (`HwQueue`, `crates/drivers/api/src/block.rs`) the layer is bound to when no NVMe controller or AHCI disk was attached. |
| NVMe | `crates/drivers/block/src/nvme.rs` | Cargo feature `nvme` (Kconfig `DRV_NVME`), a hardware queue too; bound first when a controller was attached before `blkdev::init`. |
| AHCI | `crates/drivers/block/src/ahci.rs` | Cargo feature `ahci` (Kconfig `DRV_AHCI`), a hardware queue too: a SATA disk behind an AHCI 1.3 host (PCI class 01:06:01). Bound when no NVMe controller was attached first. One command in the device at a time (NCQ off), READ/WRITE DMA EXT through a PRDT over `AHCI_XFER_KB` of staging pages, FLUSH CACHE EXT (a disk whose IDENTIFY lacks it, or that aborts it, answers a flush `Unsupported`), no FUA (SATA has it only inside NCQ), no discard. Completes by MSI, polled without a route. |
| `Mmc` | `crates/drivers/block/src/mmc.rs`, `blkdev::Mmc` | SDHCI SD/eMMC controller driver (the SpacemiT K1, feature `k1`; QEMU's `sdhci-pci` under `mmc-pci`). Data moves by ADMA2 (one descriptor per bounce page, up to 128 sectors per command) and completes by the controller's interrupt through the `irq-thread`; until the line is routed it polls. |
| `DwMshc` | `crates/drivers/block/src/dwmshc.rs`, `blkdev::DwMshc` | Synopsys DesignWare MSHC SD driver (the VisionFive 2's microSD socket, `starfive,jh7110-mmc`, feature `vf2`), bound from the device-tree node by the hardware bus (`dw-mshc`). Data moves by the controller's IDMAC over a chain of descriptors (one per bounce page, up to 128 sectors per command; the bounce pages and the chain sit below 4 GiB and are bracketed with the DMA domain's cache maintenance); multi-block transfers are closed with an explicit CMD12. The card is identified at 400 kHz, takes 4-bit mode and 25 MHz, then high speed (50 MHz) when CMD6 says it has it; its capacity is read from the CSD. Completion is by the controller's interrupt (the waiter lists itself in a `DeviceWait`, looks again, then sleeps for at most one slice); until the line is routed it polls. Not driven: the eMMC (`non-removable`), UHS modes, tuning. |

`BlockDevice::flush` makes every completed write durable. The default is
`Err(FlushError::Unsupported)`, never `Ok`: a backend that cannot confirm
durability must say so, and a caller that claims durability passes that on.

A USB mass-storage disk (Kconfig `USB_STORAGE`, `crates/drivers/block/src/usb_msc.rs`)
is a hardware queue of the request layer too, but never a `blkdev` backend: it
keeps a request queue of its own, so a stick that comes and goes cannot take the
boot disk's place, and the kernel only reads its sector 0 when it becomes ready
(`kernel/src/boot/usb.rs`). One command at a time (Bulk-Only Transport has no
tags), `fua` false, no discard; a flush is SYNCHRONIZE CACHE(10), and a device
that answers it INVALID COMMAND OPERATION CODE reports the flush `Unsupported`.
The class driver is in [drivers.md](drivers.md).

### `blkdev` entry points

| Function | Behaviour |
|----------|-----------|
| `read`, `write` | Run the real-time check, then the device. `read` first calls the read observer, so a write-back cache owner flushes dirty sectors in the range before the read. `read_would_wait` asks the observer's probe whether that flush has anything to write, for a caller that must not wait for the device (the io_ring submit). `write` calls the write observer afterwards, whether or not the write succeeded (a failed multi-sector write may have landed in part). |
| `read_quiet`, `write_quiet` | The same without the observers. For the cache owner itself, and for the swap area. |
| `read_raw`, `write_raw` | Straight to the backend: no fault injection, no real-time check, no observers. For the ring-3 block entry, which calls `note_external_read` / `note_external_write` itself. |
| `submit_raw`, `wait_raw`, `raw_max_sectors` | The queued form of a raw transfer, for the io_ring block entries (Kconfig `IORING_ASYNC`): `submit_raw` puts a request in the request layer and returns at once, `wait_raw` runs the device and collects it. `raw_max_sectors` is `None` on a board whose disk is not behind the layer (SD/eMMC), where the entry falls back to `read_raw` / `write_raw`. |
| `write_run`, `fua_commit` | The write-back cache owner's write with `PREFLUSH` and/or `FUA` (below); `fua_commit` says whether a commit may use FUA: Kconfig `BLK_FUA` on and a bound device with a native FUA. |
| `flush` | `BlockDevice::flush` after the real-time check. |
| `set_read_observer`, `set_write_observer` | Install the single `fn(u64, u32)` observer of each kind (`write_observer.rs`). The FAT32 block cache registers both. |
| `write_observer::set_account` | The write ledger: a `fn(u32, u64)` called once per write request the device completed (the request layer's completion, and the SD/eMMC backend's write), with the owner Domain and the bytes. The kernel registers `azos_sched::domain::add_written`; the per-Domain and total counters are published under `metrics/storage`. A failed write, a flush and a discard count nothing. |
| `set_rt_io_check` | Kconfig `RT_BLOCK_IO_CHECK`: a hook run at every entry; the kernel's check panics, naming the task, when a real-time task reaches the block layer. |
| `io_errors` | Count of failed reads and writes, injected ones included (only with fault injection built in). |

Every entry that runs the real-time check also calls `lockdep::might_wait_device`, so entering the block
layer with a spinlock held, with interrupts off, or from interrupt context is
reported when lockdep is on.

### Discard and force-unit-access

Both are marked on the request (`azos_devif::block`: the op `REQ_DISCARD`, the
flags `FLAG_FUA` and `FLAG_PREFLUSH`) and the layer checks them against what the device says in
`HwCaps`: `max_discard_sectors` (0: no command, the request is refused) and
`fua` (native only: NVMe has it, virtio-blk does not and a request that asks is
refused rather than faked with a flush). A discard is cut at the device's
largest discard, which is not its largest transfer. A `PREFLUSH` the device
answers `Unsupported` (no volatile cache) counts as done: there is nothing to
order; an explicit flush so answered is `Err(FlushError::Unsupported)`.

* **`BLK_DISCARD`** (`off`, `online`, `batched`). `blkdev::discard(runs)` waits
  for every run: `online` one request at a time, `batched` all the runs in the
  device together. It is a hint, never ordered against writes by the layer, so
  its users order it themselves:
  * FAT32 discards a chain only when the write that stopped naming it is
    durable (the flush that releases a held chain, or a write-through
    barrier) and while the chain is still allocated, then frees it: a crash
    leaves a leaked chain, never a named file over erased blocks, and the
    allocator cannot hand the clusters out under the discard. `batched`
    gathers the runs of every chain one flush releases (`FS_DISCARD_RUNS` at a
    time, adjacent runs merged). A refusal switches it off until the next
    mount. Chains freed on the error and cleanup paths, which have no durable
    unlink behind them, are not discarded.
  * The swap area discards the slot of a segment it brought back. The slot is
    reserved until the discard is over: the commit frees it, and a storm that
    picks it before then is told `Busy` and asks again.
* **`BLK_FUA`**. The write-back pass of an fsync ends with the run that leaves
  no dirty line, written `PREFLUSH | FUA` (`blkdev::write_run`, where
  `blkdev::fua_commit()` says the device has a native FUA), and the explicit
  device flush is skipped; a pass whose last run is not the last dirty line, or
  a device without FUA, ends with the flush as before. An fsync still makes
  its own writes durable and none is implied by the writes before it.

### Queues: no lock across a device wait

One rule runs through every driver: no mutex or spinlock is held while
waiting for the device. A request is submitted under a short lock and then
waited for without it.

* **`DevQueue`** (`crates/drivers/block/src/dev_queue.rs`) fronts a controller
  that runs one command at a time (the SD/eMMC drivers, `mmc.rs` and
  `dwmshc.rs`). `submit()` takes a
  ticket under a mutex held only for the ticket; waiters sleep on a
  `WaitQueue` until `serving == ticket`, so requests are served FIFO. The
  returned `Turn` has `program(f)`, which runs register writes with the
  programming lock held, and `wait(f)`, which runs a device wait with no lock.
  Dropping the `Turn` serves the next ticket and wakes the waiters.
* **virtio-blk** keeps `VIRTIO_BLK_INFLIGHT` staging slots, each with its own
  request header, status byte and bounce buffer of `VIRTIO_BLK_SLOT_KB` in
  driver-owned static storage; a slot is a tag of the request layer. The
  device is never handed a pointer into caller memory: a request cannot be
  recalled once it is in the avail ring, and a caller buffer is often a popped
  stack frame. The request layer cuts a transfer into commands of one slot and
  keeps several in flight. With `VIRTIO_BLK_F_MQ` offered (QEMU
  `num-queues=N`) and Kconfig `VIRTIO_BLK_QUEUES` above one, slot `t` is on
  request queue `t mod queues` and a CPU is given the slots of its own queue
  first, each queue with its own lock and used ring; the device has one
  interrupt line, one reaper. A command that misses its deadline resets the
  device and programs it again over the same rings, once per boot; the next
  one latches the driver failed until reboot (see "A device that stops
  answering"). A completion naming no slot in flight latches it at once.
* **AHCI** has one slot: the HBA's other 31 are never used, because NCQ is
  off and the commands used are not queued. `claim` answers `Busy` while the
  slot is held and the layer keeps the rest queued. The slot owns
  `AHCI_XFER_KB` of bounce pages named by the command table's PRDT. A fatal
  port error fails the command and restarts the port; a command past its
  budget resets the HBA and brings the port up again (the same disk, by
  IDENTIFY), once per boot; the next one latches the driver dead.
* **NVMe** creates an I/O queue pair per CPU, up to `NVME_QUEUES`, the
  command slots (`NVME_INFLIGHT`), the pairs the controller grants and the
  MSI-X vectors the machine can route (one for the admin queue, one per
  pair). Slot `t` is on queue `t mod queues` and a CPU is given the slots of
  its own queue first, as virtio-blk does, so two CPUs do not share a
  submission queue while a slot of their own is free; each queue has its own
  lock, held for bookkeeping only (a submit, a reap), tail and completion
  cursor. `NVME_INFLIGHT` commands are in flight at once, each owning a slot
  of `NVME_SLOT_KB` of bounce pages plus a PRP-list page, and the slot is the
  command identifier: a completion that names a slot of another queue is a
  controller not following the protocol. A transfer larger than one slot is
  split and several chunks go out together before the first wait. Completion
  is by MSI-X where a route exists: queue `q`'s vector is delivered to CPU
  `q` (each hart's IMSIC file on riscv64, which that hart enables when it
  comes up; each CPU's local APIC on x86_64; aarch64's ITS maps one
  collection, bound to the boot CPU, so every vector goes there), and the one reaper sleeps until any of them
  wakes it, then drains every queue. A queue whose CPU is not running (never
  started, or offline) raises no interrupt: its slots are taken last, and a
  command on it is noticed by the reap that ends the reaper's 1 ms slice.
  Without a route the waiter polls the completion queues' phase tags. A
  command that misses its deadline disables the controller (which stops the
  DMA of every queue), waits for `CSTS.RDY` to drop and brings it up again
  over the same pages (admin queue, queue count, every I/O pair), once per
  boot; the next one, or a completion naming no command in flight on its
  queue, latches the driver failed.

### The request layer's scheduler (`BLK_IOSCHED`)

A device bound to the request layer (`crates/drivers/block/src/queue.rs`; the
NVMe controller) is driven through per-hart submission queues of
`BLK_QUEUE_DEPTH` request slots. Kconfig `BLK_IOSCHED` chooses which queued
request is started next:

| `BLK_IOSCHED` | Next request |
|---------------|--------------|
| `none` | The oldest. A request's own deadline still ends it with a miss if it passes before the request starts, but no longer moves it forward. |
| `mq-deadline` | The earliest deadline, then the oldest; no deadline sorts last. |
| `rt-deadline` (default) | As `mq-deadline`, with the real-time **request class** first, and one slot of every hart's queue kept for that class. |

Behind the request picked, requests of the same owner and operation that are
adjacent on the medium, queued by any hart, go to the device as one command:
up to Kconfig `BLK_MERGE_MAX` requests (default 8, 4 embedded; 1 turns merging
off) and up to the device's largest command.

The class belongs to the request. A request is real-time when it serves a
durable flight-recorder record that waits for the medium (an e-stop, the
release nonce floor, a decision refusal: pushed by a `*_durable` call and not
yet covered by an `Ok` fsync). The kernel registers one source
(`queue::set_rt_class_source`, `block_request_serves_record` in
`kernel/src/boot/sched.rs`) that answers for two cases: the flush that carries the record
(`logger::rt_request_class_now`: the log flusher's pass, or a non-real-time
`*_durable` caller's own flush, in whatever Domain's context) and, while such a
record is pending, a write-back
pass of the FAT32 cache (`fat32_wb_pass_here`: the `fs-wb` task, or an fsync
that runs a pass meanwhile), since a pass writes the dirty lines oldest epoch
first and the record's lines go out with it. Such a request never sleeps for a
free slot behind bulk traffic, is started before every other, and is not
merged with ordinary ones; the same task's next request is ordinary once the
record is durable. Hardware command slots are not reserved, so it waits for at
most the earliest command in flight. A real-time task is not let in by this:
`blkdev` runs the real-time check before a request exists (it panics only with
Kconfig `RT_BLOCK_IO_CHECK`, a development-build option), and a real-time
task's record still reaches the medium through the ring and the log flusher.

### A device that stops answering

A started command is timed by its device driver, not by the request layer: NVMe,
AHCI and virtio-blk give each command a budget, and when one runs out the driver
follows one policy (`azos_drv_api::recovery`, owner decision 2026-10-23): it
stops the controller, confirms the stop (virtio status reads 0, `CSTS.RDY`
drops, `GHC.HR` clears), programs it again over the same memory and carries on,
`DEVICE_TIMEOUT_RESETS` times per boot (default 1); the next timeout latches the
driver dead until reboot, as the first one did before. A stop that is not
confirmed, or a controller that will not program again (other features, another
size), latches at once. The command that timed out is reported
`HwStatus::Timeout`; the others a reset abandoned `HwStatus::Reset`
(`Outcome::Reset`: failed, a write may or may not be on the medium, not
retried: a started request is never recalled, and merged groups make a retry
here unsafe to reason about); the others a dead device held `Io`. While the
controller is reset, `claim` answers `Busy`, never `Dead` (the layer takes a
device offline for good on the first `Dead`). Each reset and each latch the
policy decides is a `Rule::BlockTimeout` record from the driver
(`drv_supervisor::device_timeout_sink`): `action` 2 reset and back in service,
5 latched with its resets spent, 6 the reset did not bring it back. The layer
fails the request (`Outcome::Io`: the caller gets an error, nothing hangs) and
reports it through the sink the kernel registers
(`queue::set_timeout_sink`, `drv_supervisor::block_timeout_sink`) as a
`Rule::BlockTimeout` decision record: `sector`, `waited_ms` (the time in the
device) and `action` 3 (request failed). The first `Claim::Dead` is reported
once more, `action` 4 (device offline); every later request ends `Io` at
once. A request's own `deadline_ns` is a start-by time: it ends a request that
is still queued (`Outcome::Deadline`) and never recalls a started command.
The record is ring-only (`Deny`): a durable receipt would be a block write on
the device that just died.

**A command's budget is time the guest ran.** The budget (NVMe and virtio-blk
500 ms, 2 s for a flush and for a virtio-blk discard; AHCI 5 s, 20 s for a
flush) is wall-clock, and a host that stops the guest for a second
(QEMU paused with `SIGSTOP`, an overloaded or suspended host) leaves it with
every command in flight out of budget and a device that never had a chance to
answer; the driver then reset it and latched it dead until reboot. Each of
these drivers tells an `azos_drv_api::block::StallClock` whenever it looks at the device
(a submit, a reap). Two looks more than `STALL_GAP_US` (50 ms) apart are time
the device was not asked and could not be heard: the gap is credited, and a
command is out of budget only when its deadline plus the credit gained since
it was submitted has passed. The task that waits looks at least once per
millisecond (the slice below), so a running guest never credits anything, and
a device that really died is found at its budget plus the time the guest did
not run. A gap is a stall only while a command waits in the device: an idle
disk looked at seconds apart (a tickless guest, one client write a second) is
not, and is neither credited nor said. The driver prints `guest did not run
for N ms` when it credits, at most once per `STALL_SAY_EVERY_US` (10 s), the
others counted in the next line; the log sink's write is itself the next look,
so a line per gap fed back on itself.
Decision: this, and not "retry once before latching" (a second budget after
the first expiry): that forgives one stall of any length but only one, and a
guest stopped twice during one command still lost its disk. NVMe, AHCI and
virtio-blk do it; the SD/eMMC drivers time their commands per call and do not
latch, and the USB disk, whose budget is Kconfig `USB_MSC_TIMEOUT_MS` with no
stall credit, is failed until it is unplugged when a command outlives it.
Gate rows `blk: guest stop survives` (both ISAs) pause QEMU during the boot's
disk I/O and must finish, and `blk: idle disk is no stall` boots on past its
I/O and forbids the line; `blk: guest stop canary` (feature
`blk-stall-canary`, no credit) must see a command time out. On that same
kernel the stops are the fault injection of the reset policy: `blk: timeout
resets once` must see one reset and the disk serve the rest of the boot,
`blk: second timeout latches` exactly one reset and then the latch.

**No wait in the request layer is unbounded.** A submitter that waits for its
request or for a free slot registers its TID on a small list and sleeps on a
timer for at most a slice (Kconfig `WAIT_SLICE_US`, default 1 ms; 10 slices for a free slot), through the same
`block_until` / TID wake pair the completion interrupt uses
(`queue::set_sleep_hooks`). The completing task bumps an epoch and wakes the
list; a sleeper registers first and reads the epoch second, so one of the two
sees the other and a wake cannot fall between the look and the sleep. If a wake
still does not reach a sleeper (a stamp lost, a TID that is not the sleeper's)
the slice ends it. This replaced a `WaitQueue` sleep, which has no deadline.
**The cause of the hang that prompted it is not found.** Found 20-10 with an OTA
receive and a paused QEMU: `ota-recv` blocked in the directory scan's sector
read, the wait queue empty, the epoch 300 signals on. The slice bounds it; it
does not explain it. Reading `WaitQueue` turned up three ways it drops a wake,
fixed in `crates/core/sync/src/waitqueue.rs` with host tests: a task whose
block returned unwoken (a stamp pending, a refused block) stayed listed, so
`wake_one` later popped it instead of the real sleeper and the queue filled
with such entries; `wait()` on a full list blocked with no entry; TID 0 (a CPU
with no current task) was listed and no wake reaches it.

**Is a wake still being lost? The counters say.** Every sleep that ends at its
deadline with no wake is counted per site (`azos_sync::waitstat`, exported as
`metrics/sync/<site>/{expired, lost}`; `block_done` and `block_space` are this
layer's). `lost` is the part whose condition was already true: the event came
and its wake did not within the slice. A board boot (the stop rows above, an OTA
receive with QEMU paused) that ends with `block_done/lost` at 0 refutes a lost
wake in the request layer; a nonzero value is the evidence, and the other
sites' counters say whether the fault is the layer's or the scheduler's.

**What reading the layer found (a hang, no; lost wakes, yes).** The request
layer's own register-then-check order is sound (a sleeper registers its TID,
then reads the epoch; a completer bumps the epoch, then reads the TIDs; all
`SeqCst`). The device wait is not the same code in each driver, and two of them
could sleep through an event:

- The USB disk listed itself as the waiter and blocked **without looking again**:
  the `usb` task's turn that came between the reaper's last look and its listing
  woke nobody, and the reaper slept the whole slice per protocol stage. It now
  looks at a `progress` flag the `usb` task sets, after listing.
- Virtio-blk and NVMe listed themselves with a store and then read the
  completion queue with no full fence between: on a weakly ordered core (or
  with a store buffer) the interrupt handler can read "nobody listed" while the
  sleeper reads "nothing posted", and the sleeper sleeps to its deadline with the
  completion posted. All three, and AHCI and the DW MSHC driver, share `azos_drv_api::block::DeviceWait`
  (list, fence, re-check; and the waker's event, fence, look), with a host litmus
  test of the pair.

Both are bounded by the slice (a delay, not a hang) and neither is shown to be
the 20-10 hang. A reaper that dies holding the reaper role would leave every
other waiter polling at one slice instead of sleeping in the device; nothing
makes a task die there.

The other `WaitQueue` users are sorted in `waitqueue.rs` ("Two kinds of sleep"):
the FAT claims, the pager, `Claim`, `dev_queue` and `ads1115` sleep through
`wait_if_for` (a slice, counted); the kernel mutex's park, the log flusher and
the RCU callback task keep `wait_if` with a comment at the site that proves the
wake cannot be lost (the waker publishes before it wakes, and the waiter
re-checks under the queue's lock after it is listed).

### Partitions and the ring-3 block entry

`crates/drivers/block/src/partition.rs` parses MBR and GPT at boot. The medium
is attacker-writable, so every field is checked, all arithmetic is checked, and
a table that is present but wrong publishes nothing rather than the parts that
looked right. At most `MAX_PARTS` (16) partitions are published; more is a
refusal, not a truncation. LBA 0 holding a FAT boot sector, or no `0x55AA`
signature, is `Scheme::None` with zero partitions.

A partition of type `0x82` (MBR) or the Linux swap type GUID (GPT) is the swap
area. `claim_swap` hands the first one to the kernel at boot; from then on
`partition`, `contains` and `resolve` no longer name it, so no capability can,
while its index stays reserved so other partitions keep their numbers.

A machine with no partition to spare keeps the swap area in a file instead
(Kconfig `MM_SWAP_BACKEND_FILE`; [memory.md](memory.md#stage-3-segment-swap-kconfig-mm_swap_backend)).
The file system side is two optional `FileSystem` methods, `swap_resize` (make
the file exactly this long, every block allocated, durable) and `swap_runs`
(the device sectors under its first bytes), and the VFS's `vfs_swapfile_open`,
`vfs_swapfile_resize` and `vfs_swapfile_runs`. FAT32 grows the file by
writing zeros and shrinks it by cutting the chain in place
(`fat32_trim_file`: new end of chain, then the entry's size, then the tail
freed once both are durable); azvol writes zeroed blocks through the engine and
commits, so the blocks are fixed before anything is written to them directly.
While it is the swap file, `vfs_open`, `vfs_unlink`, `vfs_truncate`,
`vfs_replace_file` and `vfs_rename` answer `Busy` for it, and `vfs_rename` and
`vfs_rmdir` for a directory above it.

Ring 3 reaches raw sectors only through the `Block` interface the kernel hosts
on the endpoint `block.part.<n>` (`crates/core/syscall/src/block_host.rs`). The
endpoint badge is `n + 1`; `READ` reads and `WRITE` writes; sector numbers are
relative to the partition, so a sector outside it cannot be spelled, and a run
past its end or one that overflows is refused and recorded. The data moves
through the io_ring ops `OP_BLOCK_READ` and `OP_BLOCK_WRITE` (with Kconfig
`IORING_ASYNC`, queued requests of the layer, see [ipc.md](ipc.md)); a write
completes `CQE_F_QUEUED`, done by the device with no flush behind it, and is
durable only after a later flush (an `OP_FSYNC` on the mounted volume). No
capability names the whole medium: badge 0 names no partition.

Source: `crates/drivers/api/src/block.rs`,
`crates/drivers/block/src/blkdev.rs`,
`crates/drivers/block/src/dev_queue.rs`,
`crates/drivers/block/src/queue.rs`,
`crates/drivers/block/src/write_observer.rs`,
`crates/drivers/block/src/partition.rs`,
`crates/drivers/block/src/nvme.rs`,
`crates/drivers/block/src/ahci.rs`,
`crates/drivers/block/src/usb_msc.rs`,
`crates/drivers/virtio/src/virtio/blk.rs`,
`crates/core/syscall/src/block_host.rs`.

## FAT32: journal, write ordering and the dirty bit

`crates/fs/src/fat32.rs` is the FAT32 driver. It sits on a shared block
cache (`bcache.rs`) and is mounted through the `FileSystem` trait
(`crates/fs/src/vfs.rs`).

### The journal

A one-sector journal lives at `JOURNAL_SECTOR` (8), inside the reserved region
every FAT32 volume has; mount refuses a volume whose FSInfo or backup boot
sectors alias it or whose reserved region cannot hold it. An entry has the
magic `JRNL`, a state, an operation, and the cluster, directory sector and
offset it concerns.

| State | Meaning |
|-------|---------|
| `JOURNAL_EMPTY` | Nothing in flight. |
| `JOURNAL_PENDING` | Written before the operation touched anything it describes. |
| `JOURNAL_COMMITTED` | The operation completed; the clear did not. |

| Operation | Written by | Recovery at mount |
|-----------|-----------|-------------------|
| `JOURNAL_OP_WRITE_DIR` (3) | Creating a file | PENDING is discarded: nothing names the chain yet. |
| `JOURNAL_OP_UNLINK` (4) | Removing a file's directory entry (any directory) | PENDING is discarded. |
| `JOURNAL_OP_OVERWRITE` (5) | Overwriting a file: one record for new chain and old dirent | PENDING is replayed (dirent pointed at the new chain, old chain freed), after checking that the dirent it names currently shows the old or the new first cluster; otherwise discarded. |
| `JOURNAL_OP_RENAME` (6) | Rename over an existing file | PENDING is replayed whole (`journal_replay_rename`); discarded if the dirents do not hold what it says. |
| 1 and 2 | Reserved, never written | Reserved numbers are never reassigned. |

A COMMITTED entry is simply cleared. The journal sector comes off a volume that
anyone with the medium can rewrite, so recovery never acts on a field it has
not bounded: `dir_sector` must lie in the data region, and an unknown or
discard-only operation is cleared without touching the FAT.

### Write order

Create (`write_file_journaled`):

1. Journal `PENDING` (`WRITE_DIR`), then a barrier.
2. Data clusters, then the FAT chain.
3. A barrier: data and chain are on the medium before the directory entry
   that makes them a file.
4. The directory entry (`dir_insert`). Extending the directory with a new
   cluster adds its own barrier between filling the cluster and linking it.
5. Journal `COMMITTED`, then clear. No barrier separates steps 4 and 5; the
   final `device_flush` of `fat32_write_file` makes all of them durable. A cut
   before it leaves a `PENDING` `WRITE_DIR` (discarded) or a `COMMITTED` one
   (cleared), and the dirent can only name a chain that the barrier of step 3
   already made durable.

Overwrite builds the entire new chain first (the old file is untouched), then
runs a barrier, writes the `OVERWRITE` record, runs a barrier, repoints the
dirent in place and frees the old chain, runs a third barrier, and then writes
`COMMITTED` and clears. Unlink journals, marks the entry deleted, and frees the
chain only after the unlink returns, so the dirent is gone from the medium
before its clusters can be handed out again.

`journal_barrier` is `order_barrier`: a device flush, or in write-back mode an
epoch boundary (below). It fails closed: anything but a confirmed flush fails
the operation, including `FsError::Unsupported` (the fat32 layer's form of `FlushError::Unsupported`), because a device that
cannot flush gives no ordering and the journal's guarantees would not hold.
The other ordering barriers (a directory extension, `mkdir`, a truncate or a
free made at once, and the first flush of `fat32_fsync`) let `Unsupported`
pass: a device that cannot flush orders nothing, and an I/O error still fails
them. `fat32_write_file` ends with one more `device_flush` so the caller is
told "written" only once the device confirmed it, or answered `Unsupported`
(only an empty-file create reaches that point on such a device; every other
path crossed a `journal_barrier`). `fat32_fsync` and `fat32_sync_checked` are
the calls that claim durability: `Ok` only after a confirmed flush.
The VFS backend's whole-file writes (`write_all`, `create`, a `truncate`
that rewrites the file) use `fat32_write_file_queued`, which under write-back skips that final flush:
the steps are ordered by epochs, and which of the old and new file a cut
leaves is settled only by the next `fsync`, `sync` or `fs-wb` pass.

A cut at any point leaves a valid volume. What it can leave is *space*:
clusters allocated by a write whose directory entry never landed, a chain
whose free reached only some FAT copies, a chain held for a free that never
ran. That is what the dirty bit and the mount check are for.

### The dirty bit and the mount check

The volume carries the standard "shut down cleanly" state in two places:

| Location | Clean when |
|----------|-----------|
| `FAT[1]` bit 27 (`FAT_STATE_CLEAN`), in every FAT copy | set |
| Boot sector byte `0x41` (`BS_Reserved1`) bit 0 (`BS_STATE_DIRTY`) | clear |
| `FAT[1]` bit 26 (`FAT_STATE_NO_HARD_ERROR`, a hard error recorded when clear) | set |

A volume is clean only when the first two agree (`volume_state`); a clear
hard-error bit asks for the check as well. Mount does, in order:

1. Recover from the journal (`fat32_journal_recover`).
2. If the volume is not clean, or a journal record was found, run
   `check_volume`: walk every directory and chain with a one-bit-per-cluster
   reachability bitmap, count FAT copies that differ (copy 0 wins), cross-linked
   chains and broken chains, and reclaim lost clusters, but only if the scan
   completed without a read error or limit and found no broken or
   cross-linked chain (past one, a "lost" cluster may be a live file's tail).
   A volume whose bitmap would exceed 1 MiB is checked for FAT-copy agreement
   only. The result is `MountReport`, readable with `fat32_mount_report`.
3. Judge the check (`check_verdict`): damage (a broken or cross-linked chain,
   a scan stopped by a read error or a damaged directory, not by its own
   limit) serves the volume **read-only** for this mount, or refuses it
   (Kconfig `FS_CHECK_FAILED`); leaked clusters and differing FAT copies are
   not damage. A read-only mount refuses every write (`write_sector_in`,
   `write_sector_direct`, the swap file's sector runs) and is never marked
   dirty, so it stays unclean and the next mount checks it again. The kernel
   prints the counts and, for a failed check, a decision record
   (`device-admission`, bus 4, partition 0, why 5 read-only or 6 refused).
4. Mark the volume **dirty for this mount, durably, before the first write**:
   `mark_volume_dirty` flushes the cache, writes the state straight to the
   device (`write_sector_direct`), and flushes again so the flag reaches the
   medium ahead of every later write. That second flush's answer is not
   checked: a device that cannot flush orders nothing, and one whose flush
   fails refuses every later journal barrier, so the first structural write
   of the mount fails.

`fat32_unmount` closes open files, syncs (writing the page cache's dirty pages
back first), flushes once more if anything is dirty, and only if every step
succeeded, no chain is still held for a deferred free, and the journal is idle
does it clear the flag, as the last write, followed by a flush. Anything short
of that (a cut, a crash, a halt that never gets there) leaves the volume dirty
and the next mount runs the check. A medium that refuses the flag write
(write-protected) still mounts, and the unmount then has nothing to clear.
The clean mark also sets the hard-error bit again: the mount that marked the
volume dirty passed its check.

The same walk runs by hand, counting only (`fat32_check`: nothing repaired or
written, so it is safe beside the volume's users; a write in flight shows as a
lost cluster), through `vfs_check` and the kernel-hosted `Volume` interface
(`volume.<n>`, the badge naming the volume): the toolbox's `fsck`. An azvol
volume's `Volume::check` runs the same two ways: after a mount that had to
rebuild the free-space map or found a superblock copy damaged
(`azvol_mount::open_plain`, the same Kconfig verdict and record, why 5 or 6
with the row's partition), and by hand.

### Write-back and epochs (Kconfig `FS_WRITEBACK`)

`bcache.rs` is the shared block cache: set-associative, with block size from
512 B to 4 KiB, in `FS_BLOCK_CACHE_KB`. With `FS_WRITEBACK` on, the FAT32 cache
runs in `Mode::WriteBack`: a write only dirties a line, stamped with the current
**epoch**, and a journal barrier closes the epoch without I/O. The ordering
rule, enforced at the single place a dirty line is written
(`BlockCache::write_line`):

> No block of epoch `e` reaches the device before every block of every epoch
> `< e` that is already on its way there has been made durable by a device
> flush.

So a cut leaves a prefix of epochs plus part of one, which is a state the
write-through journal could also leave. Dirty lines go out oldest epoch first
as coalesced multi-sector runs of up to `FS_WRITEBACK_RUN_KB`, with a flush
between epochs. A set with no clean line to evict makes the writer write back
through the blocking epoch itself (`Dirty::NeedWriteback`).

Writers of dirty lines:

| Trigger | Mechanism |
|---------|-----------|
| `device_flush` | Every journal barrier, `fat32_fsync`, `fat32_sync*`, and `fat32_write_file`'s final flush: close the epoch, write back through it, then flush the device. |
| `fs-wb` task | `fat32_writeback_tick`: when the oldest unsynced write is `FS_WRITEBACK_MAX_AGE_MS` old or the dirty share reaches `FS_WRITEBACK_WATERMARK_PCT`. |
| A writer | Whose block's line holds an older epoch, or whose set has no clean line. |
| A reader of the medium that is not the cache owner | The read observer writes back dirty lines in its range first. |

The lock order is: FAT-sector claim, then write-back claim, then the cache
lock; the device is never waited on under the cache lock, and one flusher at
a time owns a checked-out run. Mount uses write-through when the device cannot
flush. With `FS_DEFERRED_FREE`, a chain that truncate, overwrite or rename takes
away from a name stays allocated until the flush that makes the unlinking
directory entry durable, and is freed into the next epoch (`defer_free`,
`release_held`).

Source: `crates/fs/src/fat32.rs`, `crates/fs/src/bcache.rs`,
`crates/drivers/block/src/blkdev.rs`, `kernel/src/boot/sched.rs`,
`config/limits/Kconfig.limits`.

## The page-cache path

File data of a filesystem whose `FileSystem::page_cached()` is true goes
through the unified page cache. FAT32 and tmpfs return true (the kernel does
not mount tmpfs: `/tmp` is a ramfs directory); azvol does not. A backend must also be `streaming()`.

The cache is the one `mmap` maps (see [memory.md](memory.md#page-cache-as-a-paged-memobj)):
one `MemKind::Paged` MemObj per aligned 64-page window of a file, filled and
written back through `FsPageBacking` (`crates/fs/src/pagecache.rs`), which
wraps the filesystem's `read_at` and `write_at`. One `FsPageBacking` exists per
filesystem (`backing_of`, at most 8 distinct), so a `write` and a `MAP_SHARED`
store meet in one frame.

`azos_fs` cannot name the object table, so the kernel installs the cache as a
table of function pointers, `PageCacheHooks`
(`kernel/src/boot/pagecache.rs`, once, before the first volume is mounted).
With none installed every path falls back to the backend's own `read_at` and
`write_at`.

| Hook | Role |
|------|------|
| `read`, `write` | Serve bytes through the cache objects (`file_map::cache_read`, `cache_write`). `None` means "cannot serve now" and the caller uses the backend. |
| `writeback` | Write every dirty page of one file back, mapped pages included. |
| `flush_fs` | The same for every file of a filesystem. |
| `drop` | Forget pages from a byte offset on, dirty ones too (the file changed or is gone); `key: None` is every file (unmount). |
| `capacity_pages` | What the dirty share is a share of: at most `CACHE_PAGES` and at most half the machine's frames. |
| `domain`, `domain_budget` | The calling task's Domain, and the dirty pages it may hold: `FS_WRITEBACK_WATERMARK_PCT` of its frame budget, or of the cache capacity when it has none. |
| `now_ms`, `wake` | The `fs-wb` task's clock and waker. |

Rules of the path (`vfs.rs`, "The page cache seam"):

* **Writes inside the file dirty pages.** A write that reaches past the end of
  the file does not go through the cache: a cached object clamps to the size it
  was made with and never lengthens a file. The file's dirty pages are written
  back first and the extension is a plain `write_at`, so it keeps the backend's
  ordered path (data and chain, then the directory entry in a later epoch). An
  append therefore holds no dirty page and gets no write-behind. The cache is
  told the new length by the next call and re-attaches the file at it, keeping
  every page except the one that held the old end.
* **Coherence.** Everything that reads or discards a file's bytes behind the
  cache settles it first: `fsync` and `sync` write back; unlink, truncate,
  rename, replace and `O_TRUNC` write back or drop; a content stamp of an image
  is only given for bytes that are on the backend. A stale object (a forget
  that was refused) is neither served, mapped nor written back until a later
  call has forgotten it, so nothing old reaches whatever has the name now.
* **Metadata stays in the block cache.** With a page cache installed the FAT32
  block cache stops retaining file data on fills; it holds the FAT, directory
  clusters, the boot sector and the journal. A page written back still passes
  through it as dirty lines of the current epoch, because the epochs are what
  order data before the chain and directory entry that name it.
* **Policy.** `vfs.rs` keeps per file and per Domain the dirty pages and when
  the oldest was dirtied. The `fs-wb` task writes a file back at
  `FS_WRITEBACK_MAX_AGE_MS`, or the oldest files until under
  `FS_WRITEBACK_WATERMARK_PCT` of the cache. A writer whose Domain is over its
  budget writes back its own files before its write returns. A file whose
  write-back fails stays tracked and is left aside for the rest of the pass;
  the failure is kept and is the verdict of the next `fsync` or `sync`, once.
  Pages dirtied through a writable mapping reach the backend at the file's
  `fsync`, at `sync`, at `munmap`, and at the owner's exit.
* **Accounting.** The cache is system memory charged to no Domain; it goes back
  to the allocator under memory pressure (first stage of the reclaim order in
  [memory.md](memory.md#reclaim-order)).

Source: `crates/fs/src/vfs.rs`, `crates/fs/src/pagecache.rs`,
`crates/fs/src/bcache.rs`, `crates/core/syscall/src/file_map.rs`,
`crates/core/ipc/src/memobj.rs`, `kernel/src/boot/pagecache.rs`.

## azvol

`azvol` is the project's own volume format. The engine
(`crates/fs/src/azvol/`) uses only `core` and `alloc`, talks to the medium
through a `BlockDev` trait, and holds no global state; the same source runs in
the kernel and in the host tools. `tools/image/mkazvol.py` is a second implementation
that builds plain (unsealed) images. `AzvolFs`
(`crates/fs/src/azvol/mount.rs`) is the adapter that mounts it into the VFS.

### Format

Blocks are 4096 bytes and all fields are little-endian.

| Blocks | Contents |
|--------|----------|
| 0 and 64 | Superblock copies A and B |
| 1..127 except 64 | Reserved (zero); `RESERVED_BLOCKS` = 128 |
| from 128 | Free-space bitmap (one bit per volume block, with a crc32c trailer), then the per-block checksum table |
| `data_start`.. | File data, directory blocks, tree nodes, the inode table's own data |

* **Superblock.** Magic `AZVOLUME`, version, block size, a crc32c over the
  block, incompat feature bits (a bit this implementation does not know is refused),
  the commit **generation**, volume size, uuid, label, free-inode list head,
  inode-table slot count, live-block count, the key slot (algorithm id, key id,
  wrapped key; all zero = unsealed), and the records of the inode table, the
  snapshot table and the dead list. A commit with generation `g` writes copy
  `g & 1`; mount takes the valid copy with the highest generation. Geometry is
  derived from the block count and the superblock repeats it; a superblock that
  disagrees is refused.
* **Checksums.** Every data-area block has a crc32c in the side table, indexed
  by block number. A read verifies it, and a mismatch is an error, never
  silently wrong data. A side table, not a trailer, so a data block keeps all
  4096 bytes (page-aligned, mappable).
* **Inodes.** 256 bytes each: size, times, the generation of the last change,
  kind, mode, extent root. The inode table is itself a file whose record is in
  the superblock. Slot 0 is reserved, inode 1 is the root directory.
* **Extents.** A file is a sorted list of `{file_blk, disk_blk, nblocks, flags,
  gen}`. Up to six sit in the inode record; more go to tree nodes (leaf nodes
  of 127 extents, index nodes of 127 `{key, child, child_gen}`, depth up to
  three above the leaves). A node names its own block, its owner inode and its
  generation, so a misdirected or stale node is refused. A directory is a file
  of name records (`dir.rs`), scanned linearly.

### Copy on write and the commit order

A committed block is never overwritten. A write to a block whose extent carries
an older generation allocates new blocks, writes them, and swaps the mapping; a
block carrying the open transaction's generation is named by no committed tree
and is overwritten in place. Everything between two commits is one
transaction, and `commit` makes it durable in this order:

1. Each changed inode's extent tree and record, then the inode table's own tree.
2. The checksum-table and bitmap blocks changed so far (the bitmap still lists
   every block the old tree names: a superset).
3. **Flush**, then the superblock into the copy slot that does not hold the
   newest generation, then **flush**.
4. Only now are the blocks the old tree gave up freed in the bitmap.

A cut at any point leaves either the old superblock or the new one valid, and
every block either names intact. A cut between 3 and 4 leaves blocks marked
used that nothing names; the next mount sees the bitmap's population count
differ from the superblock's `used_blocks` and rebuilds the map from the trees
(`MountReport::bitmap_rebuilt`). A failed commit poisons the handle
(`Error::Poisoned`); remount to continue. The ordering argument rests on
`BlockDev::flush` being a barrier; the kernel's `BlockDev`
(`kernel/src/boot/azvol.rs`) maps every `blkdev::flush` error, `Unsupported`
included, to a failed flush, so a device that cannot flush fails the commit.

### Change groups

`begin_group`, any number of `create`, `write`, `truncate` and `unlink`, then
`commit_group` makes a set of operations across any number of files durable
together or not at all, without the temporary-file-and-rename dance. `begin_group`
first commits earlier work so an abort returns to a durable state;
`abort_group` throws the group away without touching the device. While a group
is open plain `commit`, `check` and snapshot create/delete answer
`Error::GroupOpen`. One group at a time; reads inside the group see its own
writes.

### Snapshots

A snapshot is the old tree kept past the commit that would have let it go. The
snapshot table (a file with a record in the superblock) holds one 512-byte
record per retained generation, carrying the inode table's record as of that
generation. Every extent and node carries the generation `born` that wrote it
and stays in the live tree until a commit `died` drops it; a retained
generation `s` names the block exactly when `born <= s < died`. When the live
tree drops a committed run that a snapshot still names, it goes to the **dead
list** (a file of `{run, born, died}`) instead of the free list; deleting a
snapshot frees every dead run that no remaining snapshot names, by the same
commit protocol. API: `snapshot_create`, `snapshot_delete`, `snapshot_open`
(a read-only `SnapView`), `snapshots`. `Volume::check(scrub)` walks the live
tree, every retained tree and the two auxiliary files and reports problems
(`CheckReport`).

### AEAD at rest

`seal.rs` encrypts and authenticates every block of the data area with
ChaCha20-Poly1305. Superblocks, the bitmap and the per-block table are not
sealed; they hold geometry, allocation state and tags.

* **Table.** A sealed volume's per-block table holds one 24-byte entry per
  volume block: the 16-byte tag and the 8-byte write sequence number the block
  was sealed under. A block whose tag fails is `Error::Auth`, never returned.
* **Nonce** (12 bytes): the sequence number (8 bytes) then the block number (4
  bytes, so a sealed volume holds fewer than 2^32 blocks). The sequence number
  is `generation << 28 | counter`. The generation makes copy-on-write never
  reuse a nonce; the counter covers rewrites of the same block within one
  transaction. `Volume::mount_sealed` commits a new generation before it
  returns so a cut transaction's generation is never reused. Past 2^28 block
  writes in a transaction, or generation 2^36, a write fails with
  `Error::NonceExhausted` instead of repeating a nonce.
* **Associated data** is the block number and the volume uuid, so a sealed block
  moved elsewhere, or to another volume under the same key, fails its tag.
* **Keys.** The caller passes a 32-byte master key (`VolumeKey`, wiped on
  drop). The block key is `HKDF-SHA256(salt = uuid, ikm = master)`. The
  superblock's `key_id` is a second, independent derivation, compared first so a
  wrong key is `Error::WrongKey` before any data is touched. `wrapped_key` stays
  zero. In the kernel the master key of a sealed `[volume.NAME]` row is
  `HKDF-SHA256(salt = row name, ikm = device seed, info = "azos-azvol volume
  key v1")` (`kernel/src/boot/azvol_key.rs`), the seed being the one the
  `LinkKey` endpoint keeps in its reserved sector; it is never handed to ring 3.
* **Not covered: freshness.** Whoever can write the medium can put back an old
  block together with its old table entry and the volume will take it for the
  block it was.
* Entry points: `Volume::format_sealed`, `Volume::mount_sealed`.

### Verity

A read-only volume (the system image a package installer stages) can be served
over a SHA-256 hash tree kept after it on the same partition
(`crates/fs/src/azvol/verity.rs`). The volume format does not change: the
tree is a wrapper device, `VerityDev`, between the engine and the partition.

```text
  [0, N)     the volume
  N          header: AZVERITY, version 1, algorithm 1 (SHA-256), N, levels,
             SHA-256 of the top hash block, zero padding
  N+1 ..     level 0: one 32-byte hash per volume block, 128 to a hash block;
             level 1: one hash per level-0 hash block; ... up to one block
```

* **Covered:** every block of the volume, `[0, N)`, not only the data area: the
  superblocks, the free-space map and the checksum table too. A superblock that
  could be swapped would point the files at other, individually authentic
  blocks; covering the whole volume means no read the engine makes is
  unchecked and no range needs a rule.
* **The root** is the SHA-256 of the header block. It commits to `N`, the shape
  and the top, hence to every block. It is not stored on the volume: it is the
  topology row's `verity_root`, and `tools/image/mkazvol.py create --verity` prints it
  (`verity_root HEX`). `--size` stays the size of the volume; the image file is
  longer by the tree.
* **Open.** The superblock's block count is only a hint where the header is;
  the block there must hash to the root, and then `N` is the header's.
* **Read.** The blocks are read in one device call, hashed, and compared with
  their level-0 slot; that hash block is checked against its slot a level up,
  to the header's top. A verified hash block is kept (64 of them), so a repeat
  costs the data block's hash. On a mismatch the whole call fails, the buffer
  is zeroed, and one `Tamper` goes to `Env::tampered` (`kernel/src/boot/azvol.rs`
  prints a warning for the first and each doubling). The engine sees an I/O
  error, so the VFS read returns no bytes.
* **Mount.** A failure while the mount itself reads the volume refuses the row,
  whatever block it was: the engine would otherwise mount from the second
  superblock copy or rebuild a damaged free-space map and carry on.
* **Not covered:** freshness. The root names one image; which root the device
  accepts is the signed topology's decision. A block no read touches (the
  reserved blocks, free space) is checked only when something reads it, or by
  `mkazvol.py verify --verity-root`, which recomputes the whole tree.

### Mounting into the VFS

Each `[volume.NAME]` row of the topology (`VolumeSpec`: `name`, `partition`, `mount`,
`read_only`, `aead`, `verity_root`) names a partition and a mount point.
`kernel/src/boot/azvol.rs` supplies the partition as a `BlockDev` (azvol blocks
mapped to sectors through `blkdev`, partition-relative) and the system around
the mount (`Env`: the clock, the calling task, whether a task is alive), then
calls `azvol_mount::mount_rows`. For each row, in order:

* A row with `aead = true` is mounted with `Volume::mount_sealed` and the
  row's key (see "Keys" above). A board with no device seed has no key: the
  row is refused (`Why::NoKey`), and so is a volume the key does not open
  (`Error::WrongKey`), each with a `Rule::DeviceAdmission` receipt (why 3,
  why 4); a sealed volume is never served as a plain one, and a sealed volume
  under a row without `aead` is refused (`Error::KeyRequired`). `aead`
  together with `verity_root` is refused (`Why::SealedAndHashed`).
* A row with `verity_root` set is opened through the hash tree it names
  (see "Verity" above) and served read-only, whatever its `read_only` says. A
  partition that does not open as the volume of that root is refused
  (`Why::Verity`), and so is a volume from which the mount itself reads a
  block that does not hash into the root (`Why::Tampered`).
* The partition must exist, and the probe (`probe_volume`) must find an azvol
  volume. A blank partition is never formatted by the mount.
* The engine mounts it (`Volume::mount`, refusing a bad superblock, a
  mismatched geometry, or checksum failures) and `vfs_mount_fs` serves it at
  the row's mount point. A failure leaves the other rows mounted.

`AzvolFs` implements `FileSystem` as a streaming backend; its file key is the
path beneath the mount point (no `.` or `..`, no empty component, at most
`INODE_KEY_LEN` bytes). It is not page-cached. The volume sits behind a
`Claim`, not a lock, because its owner waits on the device while holding it.

**Only `fsync` and `sync` commit.** Nothing commits on its own: no timer, no
size threshold. A writer that never calls `fsync` loses what it wrote at a power
cut. The transaction has an **owner**: the task whose change opened it. While it
is open every other task's change, `fsync` and `sync` answer `Busy`, so a
commit by someone who did not write the transaction can never make half of the
owner's multi-file change durable. If the owner exits without committing
(`Env::alive` says so; task ids are never reused), the next change or commit by
any task discards the transaction, which is what a power cut at that point
would have done. Reads see the open transaction's writes. `rename` is its own
atomic unit: it commits the caller's earlier changes, then copies and removes
inside one group and commits that. No snapshot or caller-opened change group is
reachable through `AzvolFs`.

Source: `crates/fs/src/azvol/mod.rs`, `crates/fs/src/azvol/layout.rs`,
`crates/fs/src/azvol/engine.rs`, `crates/fs/src/azvol/volume.rs`,
`crates/fs/src/azvol/group.rs`, `crates/fs/src/azvol/snap.rs`,
`crates/fs/src/azvol/seal.rs`, `crates/fs/src/azvol/check.rs`,
`crates/fs/src/azvol/mount.rs`, `crates/fs/src/azvol/dev.rs`,
`crates/fs/src/azvol/verity.rs`,
`crates/fs/src/probe.rs`, `kernel/src/boot/azvol.rs`, `kernel/src/boot/azvol_key.rs`,
`crates/core/topology/src/types.rs`, `tools/image/mkazvol.py`.

## Directory capabilities and `Cap<Dir>` namespaces

A ring-3 task has no open-by-absolute-path call. Every open names a file
**relative to a directory the task holds a capability for**, and the join of the
two cannot leave that directory. (This is the property Linux calls
`RESOLVE_BENEATH`; here it is the only way to open, not an option.)

### The capability

A directory is a tree `Cap<File>` (`crates/core/ipc/src/file_cap.rs`): the same
capability kind as an open file, with a resource number at or above
`TREE_RESOURCE_BASE` that indexes a table of interned absolute paths. A file
descriptor's resource is always below `MAX_FDS_PER_PROC`, and the two ranges
cannot meet (checked at compile time); every place that turns a `Cap<File>`
into a descriptor refuses a tree resource as the wrong kind of object.

* **The only minter is the topology.** A `cap_seed` entry of kind `"node"`
  whose target is the absolute path of the tree's root (a `node` target
  without a leading `/` is an image name to launch, not a tree). Targets are refused if
  relative, if they contain a `.` or `..` component, if longer than
  `TREE_PATH_MAX` bytes, or if they ask for more than read and/or write. A tree
  grant carries no `DUP`, so it cannot be handed on. At most `MAX_TREES` (16)
  distinct trees exist across all tasks.
* **The root directory.** The tree on `/` is always interned first
  (`ROOT_TREE_RESOURCE`), so ring 3 can find it by a constant. A task holds it
  only if its signed row grants the target `/`; it is the task's root
  `Cap<Dir>`. A task that holds no tree opens nothing, and the trees it holds
  bound everything it can open.
* **Rights.** `READ` on a directory is the right to look names up beneath it.
  Naming and writing are separate: an open that changes the tree
  (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) needs a held tree
  with `WRITE` that covers the resulting path (`write_tree_covers_open`). A row
  that grants `/` read-only therefore reads anywhere and writes only under the
  write trees it also holds. The calls that change the tree check the held
  tree as well: create, remove and rename need the directory the entry is in to
  lie strictly under a held tree's root, so a grant on `/fat` cannot remove
  `/fat`; truncate is checked against the file, which may be the tree's root
  itself or lie under it.

### The join

`azos_common::path::join_beneath(root, rel, out)`
(`crates/core/common/src/path.rs`) is the one join, shared by the filesystem,
which opens the result, and the syscall layer, which checks the authority the
result needs. Two layers that each joined a root and a name on their own would
be two definitions of "beneath".

* `root` is absolute; `.` and `..` components in it are refused.
* `rel` must be non-empty and relative: a leading `/` is refused, as is a NUL
  byte. `//` collapses and `.` is skipped.
* `..` pops the component before it and is refused when there is none, so `..`
  and `a/../..` escape and `a/../b` does not.
* The result is the root plus the normalised components, and must fit
  `MAX_PATH` (512) bytes, or the join is `JoinError::TooLong`. Every escape and
  malformed input is `JoinError::Invalid`, without saying which.

The join is lexical, which is exact here: the native namespace has no symlinks
and no bind mounts a `..` could cross.

### The calls

| Layer | Item |
|-------|------|
| Invoke op | `NODE_OPENAT` (`sys_file_openat_typed`): `a0` is the directory capability, `a1` a NUL-terminated relative name, `a2` the flags. It checks `READ` on the directory, copies the name from user space, checks write authority if the flags change the tree, joins, opens, and mints a `Cap<File>` naming the descriptor in the caller's own table. Errors: `-ECAPKIND` for a handle that is not a directory, `-ECAPPERMS` when no held tree with `WRITE` covers the result. |
| Seam | `FileOps::open_at(root, rel, flags)` in `crates/core/syscall/src/file_ops.rs` |
| VFS | `vfs_open_at(table, root, rel, flags)` joins and opens the resolved path. `vfs_open(table, path, flags)` is `vfs_open_at(ROOT_DIR, ...)` for the kernel's own boot, recovery and spawn reads. |
| User library | `azos_libsys::open_at(dir, rel, flags)` and `root_dir()` in `crates/core/libsys/src/lib.rs` |

The kernel's own files (boot files, the crash log, an image to spawn) are opened
from `ROOT_DIR`; ring 3 reaches the VFS only through `vfs_open_at` with its own
`Cap<Dir>`. Kernel code that writes on a task's behalf, such as the crash dump
for a faulting task, writes beneath that Domain's write tree
(`crates/fs/src/crash_log.rs`).

Source: `crates/core/ipc/src/file_cap.rs`, `crates/core/common/src/path.rs`,
`crates/core/syscall/src/handlers.rs`, `crates/core/syscall/src/file_ops.rs`,
`crates/fs/src/vfs.rs`, `crates/core/libsys/src/lib.rs`,
`crates/core/abi/src/invoke.rs`, `crates/fs/src/crash_log.rs`,
`kernel/src/trap/crash.rs`.

## ext4 and the Linux module set

The ext4 module set is the unmodified Linux `fs/ext4` code, built as
relocatable modules that the module loader lays out and relocates. No Kconfig
symbol selects them yet, and nothing loads the modules or mounts an ext4
volume: the imports listed below and the ring-3 filesystem server are not there.

The tree contains:

| Item | Where |
|------|-------|
| The build of the unmodified `fs/ext4`, `fs/jbd2`, `fs/mbcache.c` and `lib/crc/crc16.c` of the pinned Linux tag, for both ISAs, into `<isa>/fs/{crc16,mbcache,jbd2,ext4}.ko`, in load order | `make lx-kbuild`, `tools/build/lx_kbuild/run.sh` (`fs_modules`), pinned by the `third_party/linux` gitlink |
| The relocatable-module loader: parses an `ET_REL` object, lays out text and data regions, resolves symbols through a caller-supplied table and applies relocations | `crates/core/lx-loader/src/lib.rs` |
| The kernel half of loading: a module's file bytes are checked against a digest table built into the kernel image before they run, and text is flipped to read-execute after loading | invoke ops `DOMAIN_MODULE_VERIFY` and `DOMAIN_MODULE_MAP_X` (`crates/core/abi/src/invoke.rs`) |
| The base of the compatibility layer a ring-3 server would run modules on (memory, locks, timers, workqueues, RCU, printk, device model, reference counts, exported-symbol table) | `crates/drivers/lx/emul` |
| The list of imports of the ext4 module set that neither the host ABI (`crates/drivers/lx/HOST_ABI`) nor an earlier module exports | `crates/drivers/lx/FS_EXT4_UNRESOLVED` (the Linux VFS, page cache, buffer heads, bio, wait queues and per-CPU data are among the symbols listed) |

Linux filesystems use the native `BlockDevice` rather than a Linux block
driver (`config/axes/Kconfig.personality`).

Three details of the native side are shaped by ext4: `bcache.rs` accepts block
sizes from 512 B to 4 KiB, `NAME_MAX` in `vfs.rs` is 255 (ext4's name limit),
and `FileSystem::readdir` takes a cookie rather than an index because a hashed
directory cannot be addressed by position. An image that contains a Linux
module is GPL-2.0-only as a whole (`config/axes/Kconfig.personality`).

Source: `config/axes/Kconfig.personality`, `tools/build/lx_kbuild/run.sh`, `crates/core/lx-loader/src/lib.rs`,
`crates/drivers/lx/FS_EXT4_UNRESOLVED`, `.gitmodules`, `crates/drivers/lx/emul/src/lib.rs`,
`crates/fs/src/bcache.rs`, `crates/fs/src/vfs.rs`.
