// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Pub/Sub message bus (AT1) — topic-based publish/subscribe.
//!
//! Typed topics for inter-task communication in the kernel.
//! Zero-copy where possible, fixed-size buffers, no heap.
//!
//! Topics: /sensors/imu, /sensors/lidar, /sensors/gps, /sensors/battery,
//!         /cmd/motor, /cmd/mode, /status, /nav/waypoint, /nav/occupancy

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use azos_sync::SpinLock;
use azos_limits::MAX_TOPICS;
use azos_limits::MAX_SUBS_PER_TOPIC as MAX_SUBSCRIBERS_PER_TOPIC;

// ---------------------------------------------------------------------------
// Constants — no magic numbers
// ---------------------------------------------------------------------------

/// Maximum length of a topic name in bytes (e.g. "/sensors/imu").
const MAX_TOPIC_NAME_LEN: usize = 32;

/// Maximum message payload size per topic in bytes.
const TOPIC_BUF_SIZE: usize = 256;

/// Sentinel value meaning "no subscriber in this slot".
const SUBSCRIBER_SLOT_EMPTY: usize = usize::MAX;

/// Initial sequence number (no messages published yet).
const INITIAL_SEQ: u32 = 0;

// ---------------------------------------------------------------------------
// Topic info
// ---------------------------------------------------------------------------

/// Metadata and latest-message buffer for a single topic.
#[derive(Clone, Copy)]
pub struct TopicInfo {
    /// Topic name stored as raw bytes (no alloc).
    name: [u8; MAX_TOPIC_NAME_LEN],
    /// Actual length of `name` in bytes.
    name_len: u8,
    /// Whether this topic slot is in use.
    active: bool,
    /// Expected size of messages on this topic (advisory; publish accepts any <= TOPIC_BUF_SIZE).
    msg_size: u16,
    /// Monotonic sequence number, incremented on each publish.
    seq: u32,
    /// Subscriber task indices; SUBSCRIBER_SLOT_EMPTY means empty.
    subscribers: [usize; MAX_SUBSCRIBERS_PER_TOPIC],
    /// Number of active subscribers.
    sub_count: u8,
    /// Latest published message.
    buf: [u8; TOPIC_BUF_SIZE],
    /// Length of the data currently in `buf`.
    buf_len: u16,
    /// Tick at which the last publish occurred (caller-provided or 0).
    last_publish_tick: u64,
}

impl TopicInfo {
    /// A blank, inactive topic.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_TOPIC_NAME_LEN],
            name_len: 0,
            active: false,
            msg_size: 0,
            seq: INITIAL_SEQ,
            subscribers: [SUBSCRIBER_SLOT_EMPTY; MAX_SUBSCRIBERS_PER_TOPIC],
            sub_count: 0,
            buf: [0u8; TOPIC_BUF_SIZE],
            buf_len: 0,
            last_publish_tick: 0,
        }
    }

    /// Compare topic name with a byte slice.
    fn name_eq(&self, other: &[u8]) -> bool {
        let len = self.name_len as usize;
        if len != other.len() {
            return false;
        }
        let mut i = 0;
        while i < len {
            if self.name[i] != other[i] {
                return false;
            }
            i += 1;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// All topic slots, protected by a spinlock for SMP safety.
static TOPICS: SpinLock<[TopicInfo; MAX_TOPICS]> = SpinLock::new([EMPTY_TOPIC; MAX_TOPICS]);

/// Constant used to initialize the array (workaround for const generics).
const EMPTY_TOPIC: TopicInfo = TopicInfo::empty();

/// Wake callback — set by the kernel at init time.
///
/// Called with a task index to wake a subscriber that may be blocked
/// waiting for new data.  This avoids a circular dependency on the
/// scheduler crate.
/// Subscriptions live across every topic, maintained under the `TOPICS`
/// lock: what lets [`topic_unsubscribe_all`] (every task exit) return
/// without taking the lock while nobody is subscribed.
static SUBS_LIVE: AtomicU32 = AtomicU32::new(0);

static WAKE_FN_SET: AtomicBool = AtomicBool::new(false);
static WAKE_FN: SpinLock<Option<fn(usize)>> = SpinLock::new(None);

/// Register the wake callback.  Should be called once during kernel init.
pub fn set_wake_callback(f: fn(usize)) {
    let mut guard = WAKE_FN.lock();
    *guard = Some(f);
    WAKE_FN_SET.store(true, Ordering::Release);
}

/// Invoke the wake callback for a single task, if registered.
fn wake_task(task_idx: usize) {
    if WAKE_FN_SET.load(Ordering::Acquire) {
        let guard = WAKE_FN.lock();
        if let Some(f) = *guard {
            // Drop the lock before calling out to avoid holding it during
            // potentially expensive scheduler operations.
            let func = f;
            drop(guard);
            func(task_idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create (register) a topic.  Returns topic_id (`0..MAX_TOPICS-1`) or `None`
/// if the name is too long, empty, or no free slots remain.
///
/// If a topic with the same name already exists, returns its existing id.
pub fn topic_create(name: &[u8], msg_size: u16) -> Option<u32> {
    if name.is_empty() || name.len() > MAX_TOPIC_NAME_LEN {
        return None;
    }

    let mut topics = TOPICS.lock();

    // Check for existing topic with the same name.
    let mut free_slot: Option<usize> = None;
    for i in 0..MAX_TOPICS {
        if topics[i].active && topics[i].name_eq(name) {
            return Some(i as u32);
        }
        if !topics[i].active && free_slot.is_none() {
            free_slot = Some(i);
        }
    }

    let slot = free_slot?;

    let t = &mut topics[slot];
    *t = TopicInfo::empty();
    t.active = true;
    t.msg_size = msg_size;
    t.name_len = name.len() as u8;
    let mut j = 0;
    while j < name.len() {
        t.name[j] = name[j];
        j += 1;
    }

    Some(slot as u32)
}

/// Find a topic by name.  Returns topic_id or `None`.
pub fn topic_find(name: &[u8]) -> Option<u32> {
    let topics = TOPICS.lock();
    for i in 0..MAX_TOPICS {
        if topics[i].active && topics[i].name_eq(name) {
            return Some(i as u32);
        }
    }
    None
}

/// Subscribe a task to a topic.  Returns `true` on success, `false` if the
/// topic is invalid or the subscriber list is full.
///
/// Duplicate subscriptions are silently ignored (returns `true`).
pub fn topic_subscribe(topic_id: u32, task_idx: usize) -> bool {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return false;
    }

    let mut topics = TOPICS.lock();
    let t = &mut topics[id];
    if !t.active {
        return false;
    }

    // Already subscribed?
    for i in 0..MAX_SUBSCRIBERS_PER_TOPIC {
        if t.subscribers[i] == task_idx {
            return true;
        }
    }

    // Find an empty slot.
    for i in 0..MAX_SUBSCRIBERS_PER_TOPIC {
        if t.subscribers[i] == SUBSCRIBER_SLOT_EMPTY {
            t.subscribers[i] = task_idx;
            t.sub_count = t.sub_count.saturating_add(1);
            SUBS_LIVE.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }

    false // full
}

/// Unsubscribe a task from a topic.
pub fn topic_unsubscribe(topic_id: u32, task_idx: usize) {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return;
    }

    let mut topics = TOPICS.lock();
    let t = &mut topics[id];
    if !t.active {
        return;
    }

    for i in 0..MAX_SUBSCRIBERS_PER_TOPIC {
        if t.subscribers[i] == task_idx {
            t.subscribers[i] = SUBSCRIBER_SLOT_EMPTY;
            t.sub_count = t.sub_count.saturating_sub(1);
            SUBS_LIVE.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    }
}

/// Task-pool slot `task_idx` is being vacated (its task exited): drop it
/// from every topic, so a later task in that slot is never woken for
/// subscriptions it did not make and a dead subscriber does not hold a
/// fan-out slot. Called from the kernel's exit hook while the slot is still
/// valid. Returns how many subscriptions were dropped. One pass over
/// `MAX_TOPICS x MAX_SUBS_PER_TOPIC` under the table lock.
pub fn topic_unsubscribe_all(task_idx: usize) -> usize {
    if cfg!(feature = "pubsub-exit-keep-canary") || SUBS_LIVE.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut topics = TOPICS.lock();
    let mut n = 0;
    for t in topics.iter_mut().filter(|t| t.active && t.sub_count != 0) {
        for s in t.subscribers.iter_mut() {
            if *s == task_idx {
                *s = SUBSCRIBER_SLOT_EMPTY;
                t.sub_count = t.sub_count.saturating_sub(1);
                n += 1;
            }
        }
    }
    SUBS_LIVE.fetch_sub(n as u32, Ordering::Relaxed);
    n
}

/// Subscribers of `topic_id` right now (0 for an invalid topic).
pub fn topic_subscriber_count(topic_id: u32) -> usize {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return 0;
    }
    let topics = TOPICS.lock();
    if topics[id].active { topics[id].sub_count as usize } else { 0 }
}

/// Publish data to a topic.  Copies `data` into the topic buffer, increments
/// the sequence counter, and wakes all subscribers.
///
/// Returns `false` if the topic is invalid or data exceeds `TOPIC_BUF_SIZE`.
pub fn topic_publish(topic_id: u32, data: &[u8]) -> bool {
    let id = topic_id as usize;
    if id >= MAX_TOPICS || data.len() > TOPIC_BUF_SIZE {
        return false;
    }

    // Collect subscribers while holding the lock, then wake outside.
    let mut wake_list = [SUBSCRIBER_SLOT_EMPTY; MAX_SUBSCRIBERS_PER_TOPIC];
    let mut wake_count = 0usize;

    {
        let mut topics = TOPICS.lock();
        let t = &mut topics[id];
        if !t.active {
            return false;
        }

        // Copy payload.
        let mut i = 0;
        while i < data.len() {
            t.buf[i] = data[i];
            i += 1;
        }
        t.buf_len = data.len() as u16;
        t.seq = t.seq.wrapping_add(1);

        // Snapshot subscribers for wake-up.
        for i in 0..MAX_SUBSCRIBERS_PER_TOPIC {
            if t.subscribers[i] != SUBSCRIBER_SLOT_EMPTY {
                wake_list[wake_count] = t.subscribers[i];
                wake_count += 1;
            }
        }
    }
    // Lock released — now wake subscribers.

    for i in 0..wake_count {
        wake_task(wake_list[i]);
    }

    true
}

/// Publish data with a timestamp (tick count).
///
/// Same as [`topic_publish`] but also records the publish tick for freshness
/// checks.
pub fn topic_publish_with_tick(topic_id: u32, data: &[u8], tick: u64) -> bool {
    let id = topic_id as usize;
    if id >= MAX_TOPICS || data.len() > TOPIC_BUF_SIZE {
        return false;
    }

    let mut wake_list = [SUBSCRIBER_SLOT_EMPTY; MAX_SUBSCRIBERS_PER_TOPIC];
    let mut wake_count = 0usize;

    {
        let mut topics = TOPICS.lock();
        let t = &mut topics[id];
        if !t.active {
            return false;
        }

        let mut i = 0;
        while i < data.len() {
            t.buf[i] = data[i];
            i += 1;
        }
        t.buf_len = data.len() as u16;
        t.seq = t.seq.wrapping_add(1);
        t.last_publish_tick = tick;

        for i in 0..MAX_SUBSCRIBERS_PER_TOPIC {
            if t.subscribers[i] != SUBSCRIBER_SLOT_EMPTY {
                wake_list[wake_count] = t.subscribers[i];
                wake_count += 1;
            }
        }
    }

    for i in 0..wake_count {
        wake_task(wake_list[i]);
    }

    true
}

/// Read the latest message from a topic into `buf`.
///
/// Returns the number of bytes copied, or 0 if the topic is invalid,
/// has no data yet, or `buf` is too small.
pub fn topic_read(topic_id: u32, buf: &mut [u8]) -> usize {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return 0;
    }

    let topics = TOPICS.lock();
    let t = &topics[id];
    if !t.active {
        return 0;
    }
    let len = t.buf_len as usize;
    if len == 0 || buf.len() < len {
        return 0;
    }

    let mut i = 0;
    while i < len {
        buf[i] = t.buf[i];
        i += 1;
    }
    len
}

/// Get the current sequence number for a topic (0 = never published).
pub fn topic_seq(topic_id: u32) -> u32 {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return INITIAL_SEQ;
    }
    let topics = TOPICS.lock();
    let t = &topics[id];
    if !t.active {
        return INITIAL_SEQ;
    }
    t.seq
}

/// Get the tick of the last publish for a topic, or 0 if never published.
pub fn topic_last_tick(topic_id: u32) -> u64 {
    let id = topic_id as usize;
    if id >= MAX_TOPICS {
        return 0;
    }
    let topics = TOPICS.lock();
    let t = &topics[id];
    if !t.active {
        return 0;
    }
    t.last_publish_tick
}

/// Iterate all active topics.  Calls `cb(name, msg_size, seq)` for each.
pub fn topic_list(mut cb: impl FnMut(&[u8], u16, u32)) {
    let topics = TOPICS.lock();
    for i in 0..MAX_TOPICS {
        if topics[i].active {
            let len = topics[i].name_len as usize;
            cb(&topics[i].name[..len], topics[i].msg_size, topics[i].seq);
        }
    }
}

/// Return the number of currently active topics.
pub fn topic_count() -> usize {
    let topics = TOPICS.lock();
    let mut count = 0usize;
    for i in 0..MAX_TOPICS {
        if topics[i].active {
            count += 1;
        }
    }
    count
}
