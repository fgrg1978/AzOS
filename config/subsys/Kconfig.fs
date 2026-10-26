# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# config/subsys/Kconfig.fs — File system write-back and deferred free

config FS_WRITEBACK
    bool "FAT32 write-back block cache (writes queue in RAM; fsync/sync make them durable)"
    default y
    help
      crates/fs/src/fat32.rs, crates/fs/src/bcache.rs: FAT32 writes
      dirty the block cache (FS_BLOCK_CACHE_KB) instead of waiting on the
      device. A journal barrier closes an epoch without I/O; dirty lines go
      out oldest epoch first with a device flush between epochs, and
      contiguous dirty sectors of one epoch as one multi-sector request.
      fsync, sync and every durable record (e-stop and SAFETY records, the
      log flusher, OTA and boot-good marks, CRASH.LOG) still reach the device
      and are flushed before their call returns; a VFS close queues. The
      `fs-wb` task writes the rest back by age (FS_WRITEBACK_MAX_AGE_MS) and
      dirty-line watermark (FS_WRITEBACK_WATERMARK_PCT). Crash consistency:
      a cut leaves a prefix of epochs plus part of one, the same states the
      write-through journal's flushes allow. A device that cannot flush
      mounts write-through.

      Cost: one kernel task (KERNEL_STACK_SIZE_KB) and the run buffer
      (FS_WRITEBACK_RUN_KB) of RAM; per write, a cache copy instead of a
      device request. n: write-through, every write waits on the device
      (the pre-wave-15 behaviour) and the task and buffer are not built.

config FS_WRITEBACK_MAX_AGE_MS
    int "FAT32 write-back: oldest unsynced write before the fs-wb task writes it (ms)"
    range 50 60000
    default 1000 if USE_ROBOT
    default 5000 if HWCLASS_EMBEDDED || (HWCLASS_SBC || HWCLASS_DESKTOP) || HWCLASS_SERVER
    default 5000
    help
      The bound on how long a write that no fsync/sync followed stays only
      in RAM (and is lost at a power cut). The robot domain keeps 1 s; every
      other domain 5 s (Linux's dirty_expire is 30 s). The task wakes every
      quarter of this, so the bound is this plus a quarter.

      Cost: lower means more, smaller device requests and more flushes; a
      wake-up of the task (a few hundred instructions when nothing is dirty)
      every quarter period.

config FS_WRITEBACK_WATERMARK_PCT
    int "FAT32 write-back: dirty share of the cache that wakes the fs-wb task (%)"
    range 5 95
    default 25 if HWCLASS_EMBEDDED
    default 50 if !HWCLASS_EMBEDDED
    default 50
    help
      When this share of the cache's lines is dirty, a writer wakes the
      fs-wb task instead of waiting for the age. A writer that finds its
      set with no clean line writes back itself whatever this is.

      Cost: lower bounds the RAM held by unsynced data and the work a later
      fsync does; higher coalesces more.

config FS_DEFERRED_FREE
    bool "FAT32 write-back: free a truncated or replaced chain once its unlinking entry is durable"
    depends on FS_WRITEBACK
    default y
    help
      crates/fs/src/fat32.rs, `defer_free`: the chain that an O_TRUNC to
      zero, an overwrite or a rename over a file takes away from a name
      stays allocated in the FAT, so no allocation can hand it out, until
      the flush that makes the directory entry no longer naming it durable.
      That flush then frees it into the next epoch, with no flush of its
      own. An in-place rewrite (O_TRUNC, write, fsync) is then two epochs
      and two device flushes, not three, and a cut still leaves the old
      file, an empty one or the new one, whole. statfs counts a held chain
      as free. An allocation that finds the volume full while chains are
      held flushes once, frees them and retries instead of failing.

      Cost: FS_DEFERRED_FREE_SLOTS * 16 B of RAM; per held chain, its free
      (a few hundred instructions) moves from the truncate to the flush.
      n: the truncate frees one epoch after its entry (one more flush per
      in-place rewrite) and the journaled replacements free inside their
      record, as before.
