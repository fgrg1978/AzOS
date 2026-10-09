// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// BSD socket API — port of net/socket.c
///
/// Thin socket layer over tcp/udp. `MAX_SOCKETS` slots total (`azos_limits`,
/// per-Kconfig-profile — not a fixed 16).

use azos_sync::SpinLock;
use super::{igmp, tcp, udp};
pub use azos_limits::MAX_SOCKETS;

// Domain
pub const AF_INET: u32  = 2;

// Type
pub const SOCK_STREAM: u32 = 1;   // TCP
pub const SOCK_DGRAM:  u32 = 2;   // UDP

// Proto
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

#[derive(Clone, Copy)]
pub struct SockAddr {
    pub family: u16,
    pub port:   u16,    // host byte order
    pub addr:   [u8; 4],
}

impl SockAddr {
    pub const fn new() -> Self {
        SockAddr { family: 0, port: 0, addr: [0; 4] }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SockKind {
    Free,
    Tcp,
    Udp,
}

/// Owner stamp for sockets created from **kernel** context: the boot-time
/// brain link, the OTA listener, TFTP, and the shell's echo server. No real
/// TID can equal this (`NEXT_TID` is a wrapping counter that skips 0 and
/// would need to reach `u32::MAX` — and even then the value is only ever
/// *compared*, never used to reach a slot), so a kernel socket is
/// unreachable from userspace by construction rather than by a conditional.
pub const SOCK_OWNER_KERNEL: u32 = u32::MAX;

/// Owner stamp of a slot nobody owns (free, or created before an owner could
/// be determined). `current_task_tid()` returns 0 for "no current task", and
/// `NEXT_TID` starts at 1 and skips 0 on wrap, so 0 is never a live TID —
/// which makes it safe as the "matches nobody" value. [`socket_owner`]
/// reports it as `None`, so a caller comparing owners can never match it.
const SOCK_OWNER_NONE: u32 = 0;

#[derive(Clone, Copy)]
struct Socket {
    kind:   SockKind,
    slot:   i32,   // tcp conn index or udp socket index
    /// The TCP connection, with its generation: every TCP operation goes
    /// through this, never through `slot`. A slot freed under the socket (a
    /// peer's RST) and re-issued to another owner is then out of this fd's
    /// reach -- `close` on the old fd used to close the new owner's
    /// connection.
    tcp:    Option<tcp::TcpHandle>,
    local:  SockAddr,
    remote: SockAddr,
    /// TID that created this socket, or [`SOCK_OWNER_KERNEL`].
    ///
    /// **WHY this field exists and what reads it:** `SOCKS` is one flat
    /// 16-entry array and the fd *is* the index into it, chosen by
    /// userspace. Every entry point below used to validate only
    /// `fd < MAX_SOCKETS`, so any task could walk fd 0..15 and read another
    /// task's inbound TCP stream, inject bytes into its outbound stream, or
    /// tear down its connection — the OTA channel and the brain link
    /// included. Sixteen guesses covered the whole table.
    ///
    /// The stamp is taken at **create/accept** time, not read from the
    /// scheduler at use time: kernel-side poll paths and worker threads run
    /// with `user_pt == 0`, where a "who is running now" check silently
    /// enforces nothing.
    ///
    /// The check itself lives in `crates/core/syscall` (`socket_access_ok` in
    /// `handlers.rs`), which is where the TID comes from — `crates/net/net` is
    /// scheduler-agnostic by design and must not depend on `crates/core/sched`.
    /// Read it through [`socket_owner`]. **A field with no check is worse
    /// than no field: it reads as protection while enforcing nothing.**
    owner:  u32,
    /// IPv4 groups this socket joined, [`NO_GROUP`] in the unused entries.
    ///
    /// Each entry holds one reference in `igmp`'s table. The record is what
    /// lets [`close_slot`] give those references back: without it a socket
    /// closed while joined — or a task killed with one open — left its groups
    /// joined for the life of the board, admitting traffic nobody reads.
    mcast:  [[u8; 4]; MAX_MCAST_PER_SOCKET],
}

impl Socket {
    const fn new() -> Self {
        Socket {
            kind:   SockKind::Free,
            slot:   -1,
            tcp:    None,
            local:  SockAddr::new(),
            remote: SockAddr::new(),
            owner:  SOCK_OWNER_NONE,
            mcast:  [NO_GROUP; MAX_MCAST_PER_SOCKET],
        }
    }
}

/// Most multicast groups one socket may hold.
///
/// `igmp`'s table is machine-wide and holds `igmp::MAX_GROUPS` (8). This
/// bounds a socket, not a task on its own — see [`MAX_MCAST_GROUPS_PER_TASK`]
/// for the bound across a task's sockets, which is what stops a task with
/// several sockets from filling the table by itself.
pub const MAX_MCAST_PER_SOCKET: usize = 4;

/// Most multicast groups one task may hold across all of its sockets.
///
/// Security audit unit 6, finding F4: `igmp::MAX_GROUPS` (8) is machine-wide,
/// and [`MAX_MCAST_PER_SOCKET`] only bounds one socket. A task holding
/// [`MAX_SOCKETS_PER_TASK`] sockets could join up to `MAX_SOCKETS_PER_TASK *
/// MAX_MCAST_PER_SOCKET` groups — enough on its own to fill the whole table —
/// and every other task's join then fails with [`McastError::TableFull`]
/// until that task gives groups back.
///
/// Half the table, the same rule [`MAX_SOCKETS_PER_TASK`] and
/// `MAX_HANDLES_PER_TASK` apply to their own machine-wide pools: it closes
/// the denial without giving any one task the whole resource, at the cost two
/// tasks at the limit can still fill the table between them (4 + 4 = 8) — the
/// same trade-off those quotas accept.
pub const MAX_MCAST_GROUPS_PER_TASK: usize = igmp::MAX_GROUPS / 2;

/// An unused membership entry. `0.0.0.0` is not multicast, so it never
/// collides with a group.
const NO_GROUP: [u8; 4] = [0; 4];

struct SocketTable {
    sockets: [Socket; MAX_SOCKETS],
}

impl SocketTable {
    const fn new() -> Self {
        SocketTable { sockets: [Socket::new(); MAX_SOCKETS] }
    }

    fn alloc(&mut self) -> Option<usize> {
        for i in 0..MAX_SOCKETS {
            if self.sockets[i].kind == SockKind::Free { return Some(i); }
        }
        None
    }
}

/// Most sockets ONE ring-3 task may hold at once.
///
/// `MAX_SOCKETS` is 16 for the entire machine, not per task, and until this
/// existed a single userspace program opening sockets in a loop could take all
/// of them. The denial is silent and lands on whoever asks next: the brain
/// link's `socket()` returns -1 to a task that did nothing wrong. On a robot
/// whose e-stop arrives over TCP, "another program used up the sockets" is a
/// safety failure with a resource-accounting cause.
///
/// Half the table. Deliberately not a per-task namespace -- that is RFC-0038
/// and a much wider change -- but a quota closes the denial without
/// foreclosing it, and it is the one part of that RFC that is urgent rather
/// than merely right.
///
/// **Kernel-owned sockets are exempt.** They are created by the brain link,
/// the OTA listener and the two-node probe, all in-kernel and all bounded by
/// their own call sites; charging them against a per-task quota would mean
/// the kernel competing with userspace for its own e-stop channel.
pub const MAX_SOCKETS_PER_TASK: usize = MAX_SOCKETS / 2;

static SOCKS: SpinLock<SocketTable> = SpinLock::new(SocketTable::new());

/// Create a new socket **owned by the kernel**. Returns a
/// file-descriptor-style index or -1.
///
/// This 3-argument form is the entry point for in-kernel users (the brain
/// link and the two-node TCP probe in `kernel/src/main.rs`, the OTA listener
/// and echo server in `crates/core/shell`). Sockets it hands out carry
/// [`SOCK_OWNER_KERNEL`] and are therefore never reachable through the
/// syscall gate. Userspace goes through [`socket_create_owned`].
pub fn socket_create(domain: u32, sock_type: u32, proto: u32) -> i32 {
    socket_create_owned(domain, sock_type, proto, SOCK_OWNER_KERNEL)
}

/// Create a new socket stamped with `owner`. Returns a
/// file-descriptor-style index or -1.
///
/// `owner` is the TID the socket belongs to, supplied by the caller rather
/// than read from the scheduler here so `crates/net/net` stays scheduler-
/// agnostic. Every later entry point is gated against this stamp — see the
/// `owner` field on `Socket` for what that prevents.
pub fn socket_create_owned(domain: u32, sock_type: u32, _proto: u32, owner: u32) -> i32 {
    if domain != AF_INET { return -1; }
    let kind = match sock_type {
        SOCK_STREAM => SockKind::Tcp,
        SOCK_DGRAM  => SockKind::Udp,
        _           => return -1,
    };
    let mut t = SOCKS.lock();

    // Counted under the SAME lock that allocates. Checking the quota and then
    // taking the lock would let two of a task's own threads both pass the
    // check and both allocate, which is the whole bug one level down.
    if owner != SOCK_OWNER_KERNEL && owner != SOCK_OWNER_NONE {
        let held = t.sockets.iter()
            .filter(|s| s.kind != SockKind::Free && s.owner == owner)
            .count();
        if held >= MAX_SOCKETS_PER_TASK { return -1; }
    }

    let idx = t.alloc().ok_or(-1i32).unwrap_or_else(|_| usize::MAX);
    if idx == usize::MAX { return -1; }
    // Every field is re-initialised explicitly because slots are recycled.
    // `owner` in particular MUST be written here: leaving the previous
    // occupant's TID in place would invert the ownership check — the task
    // that created the socket could not use it, and the task that used to
    // own the slot could.
    t.sockets[idx].kind   = kind;
    t.sockets[idx].slot   = -1;
    t.sockets[idx].tcp    = None;
    t.sockets[idx].local  = SockAddr::new();
    t.sockets[idx].remote = SockAddr::new();
    t.sockets[idx].owner  = owner;
    t.sockets[idx].mcast  = [NO_GROUP; MAX_MCAST_PER_SOCKET];
    idx as i32
}

/// TID that owns `fd`, or `None` if the fd is out of range, free, or
/// unowned.
///
/// This is the accessor the syscall layer's ownership gate reads; it exists
/// so `crates/net/net` can expose the stamp without importing the scheduler.
/// Mirrors `azos_ipc::shm_owner` / `port_owner`.
pub fn socket_owner(fd: i32) -> Option<u32> {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return None; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let t = SOCKS.lock();
    let s = &t.sockets[fd as usize];
    if s.kind == SockKind::Free || s.owner == SOCK_OWNER_NONE {
        return None;
    }
    Some(s.owner)
}

/// The TCP connection behind stream socket `fd`, if it has one yet.
pub fn socket_tcp_conn(fd: i32) -> Option<tcp::TcpHandle> {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return None; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let t = SOCKS.lock();
    let s = &t.sockets[fd as usize];
    if s.kind == SockKind::Tcp { s.tcp } else { None }
}

/// Bind a socket to a local address/port.
pub fn socket_bind(fd: i32, addr: &SockAddr) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd = fd as usize;
    let kind = { SOCKS.lock().sockets[fd].kind };
    match kind {
        SockKind::Udp => {
            let slot = udp::bind(addr.port);
            if slot < 0 { return -1; }
            let mut t = SOCKS.lock();
            t.sockets[fd].slot  = slot;
            t.sockets[fd].local = *addr;
            0
        }
        SockKind::Tcp => {
            // TCP bind: just store the local port; tcp::listen() is called by socket_listen_bound().
            SOCKS.lock().sockets[fd].local = *addr;
            0
        }
        SockKind::Free => -1,
    }
}

/// Listen on a TCP socket using the local port stored during bind().
pub fn socket_listen_bound(fd: i32) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd_idx = fd as usize;
    let (kind, port) = {
        let t = SOCKS.lock();
        (t.sockets[fd_idx].kind, t.sockets[fd_idx].local.port)
    };
    if kind != SockKind::Tcp { return -1; }
    if port == 0 { return -1; }
    let Some(h) = tcp::TcpHandle::listen(port) else { return -1 };
    let mut t = SOCKS.lock();
    t.sockets[fd_idx].slot = h.slot() as i32;
    t.sockets[fd_idx].tcp  = Some(h);
    0
}

/// Accept an established connection on a listening TCP socket.
/// Returns a new socket fd for the accepted connection, or -1 if none ready yet.
pub fn socket_accept(fd: i32) -> i32 {
    socket_accept_owned(fd, SOCK_OWNER_KERNEL)
}

/// Accept a connection and stamp the **new** socket with `owner`.
///
/// `owner` is the accepting task, which is the right answer: an accepted
/// connection belongs to whoever accepted it, not to the listener's peer and
/// not to whichever task happens to be running when a later poll drains it.
/// Stamping here (rather than letting the new slot inherit whatever the
/// recycled entry held) is what stops an accepted OTA or brain connection
/// from landing in a slot another task can already reach.
///
/// Note this stamps only; the *permission* to accept on `fd` is checked by
/// the caller — `crates/core/syscall`, which knows the calling TID.
pub fn socket_accept_owned(fd: i32, owner: u32) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let port = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        if s.kind != SockKind::Tcp { return -1; }
        s.local.port
    };
    let Some(h) = tcp::TcpHandle::accept(port) else { return -1 };
    let mut t = SOCKS.lock();
    match t.alloc() {
        Some(i) => {
            t.sockets[i].kind       = SockKind::Tcp;
            t.sockets[i].slot       = h.slot() as i32;
            t.sockets[i].tcp        = Some(h);
            t.sockets[i].local      = SockAddr::new();
            t.sockets[i].local.port = port;
            t.sockets[i].remote     = SockAddr::new();
            t.sockets[i].owner      = owner;
            t.sockets[i].mcast      = [NO_GROUP; MAX_MCAST_PER_SOCKET];
            i as i32
        }
        None => -1,
    }
}

/// Connect a TCP socket to a remote address.
/// Non-blocking connect: queues the SYN and returns immediately, leaving the
/// connection in `SynSent`.
///
/// Deliberately does NOT wait for the handshake. The only in-tree caller runs
/// during boot (`kernel/src/main.rs`), before the scheduler can preempt, so a
/// wait here would have to busy-spin — and busy-spinning a hart through a
/// three-way handshake is worse than returning early and letting the caller's
/// own retry loop deal with it.
///
/// Userspace goes through [`socket_connect_with_yield`] instead, which has
/// somewhere to yield to and therefore can offer real POSIX semantics.
pub fn socket_connect(fd: i32, addr: &SockAddr, src_port: u16) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd = fd as usize;
    let kind = { SOCKS.lock().sockets[fd].kind };

    // **Connected UDP.** This used to be `if kind != SockKind::Tcp { return -1 }`
    // and left UDP with no way at all to name a destination: `sendto` in this
    // ABI **carries no address** (it dispatched to the same place as `send`),
    // so a UDP socket could be created and bound but **not sent on**. It was
    // receive-only.
    //
    // Connecting a UDP socket is long-standing BSD semantics — it fixes the
    // remote peer and `send` starts working — and it **does not touch the
    // ABI**: `connect` already took the address, it just refused it.
    if kind == SockKind::Udp {
        let mut t = SOCKS.lock();
        if t.sockets[fd].slot < 0 {
            // Not bound yet: give it an ephemeral port. A `connect` on a
            // freshly created socket is the normal client case, and demanding
            // a prior `bind` would force userspace to invent a port.
            drop(t);
            let port = ephemeral_port();
            let slot = udp::bind(port);
            if slot < 0 { return -1; }
            t = SOCKS.lock();
            t.sockets[fd].slot = slot;
            t.sockets[fd].local = SockAddr { family: 2, port, addr: [0, 0, 0, 0] };
        }
        t.sockets[fd].remote = *addr;
        return 0;
    }

    if kind != SockKind::Tcp { return -1; }
    let Some(h) = tcp::TcpHandle::connect(addr.addr, addr.port, src_port) else { return -1 };
    let mut t = SOCKS.lock();
    t.sockets[fd].slot   = h.slot() as i32;
    t.sockets[fd].tcp    = Some(h);
    t.sockets[fd].remote = *addr;
    0
}

/// Ephemeral port for a `connect` on an unbound UDP socket.
///
/// The TCP ephemeral range (`CONFIG_TCP_EPHEMERAL_PORT_MIN..=MAX`, IANA's
/// dynamic range by default) and a monotonic counter: a port is not reused
/// until the whole range wraps, so a late reply from an earlier exchange
/// does not land on the new socket.
fn ephemeral_port() -> u16 {
    use core::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let span = tcp::EPHEMERAL_MAX as u32 - tcp::EPHEMERAL_MIN as u32 + 1;
    tcp::EPHEMERAL_MIN + (NEXT.fetch_add(1, Ordering::Relaxed) % span) as u16
}

/// How long a blocking connect waits for the three-way handshake, in µs of
/// counter time (`timebase::now()`), before it answers -1.
///
/// It was 2,000,000 `yield_fn` calls: a count, whose duration depended on
/// what else was runnable and on how much CPU the host gave the guest.
pub const CONNECT_HANDSHAKE_BUDGET_US: u64 = 10_000_000;

/// Fail-safe cap on `yield_fn` calls in the handshake wait. Not the budget —
/// the deadline is; this only keeps a counter that stops advancing from
/// turning the wait into a hang (same role as `tcp::SEND_ALL_UNTIL_SPIN_CAP`).
pub const CONNECT_HANDSHAKE_SPIN_CAP: u32 = 5_000_000;

/// Connect and **wait for the handshake to finish**, calling `yield_fn`
/// between looks, for at most [`CONNECT_HANDSHAKE_BUDGET_US`]. The kernel's
/// `SYS_CONNECT` passes a 1 ms sleep.
///
/// `socket_connect` used to return 0 the moment `tcp::connect` had queued the
/// SYN, leaving the connection in `SynSent`. Since `tcp::send_data` refuses
/// anything that is not `Established`, an application doing the obvious
/// thing —
///
/// ```text
///     connect(...);          // -> 0, "Connected!"
///     send(...);             // -> -1
/// ```
///
/// — saw a successful connect followed by an immediate send failure, over and
/// over. `userspace/services/brain_client` sat in exactly that loop, and the log it
/// produced ("Connected!" then "Send failed") pointed at the transport rather
/// than at connect's semantics.
///
/// POSIX is unambiguous here: a blocking `connect()` does not report success
/// until the connection is established. `yield_fn` is injected so `crates/net/net`
/// stays scheduler-agnostic, the same pattern `connect_with_yield` and
/// `send_all_with_yield` already use.
pub fn socket_connect_with_yield<F: FnMut()>(
    fd: i32,
    addr: &SockAddr,
    src_port: u16,
    mut yield_fn: F,
) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd = fd as usize;
    let kind = { SOCKS.lock().sockets[fd].kind };

    // **UDP waits for no handshake, but it still has to be able to connect.**
    //
    // This is the path the syscall uses (`sys_connect_syscall` calls here, not
    // `socket_connect`), and it carried its own TCP-only gate. Fixing only
    // `socket_connect` left ring 3 exactly as blocked as before: the harness
    // exposed it with `rc=-4001`, i.e. `connect` returning -1 with `socket`
    // and `bind` already working.
    //
    // This is "fix the class, not the instance" in its purest form: two
    // sibling functions with the same guard, and only one of them touched.
    // All four `!= SockKind::Tcp` gates in this file were reviewed; the other
    // three — `socket_listen`, `socket_listen_bound`, `socket_accept_owned` —
    // are **correct**: UDP has neither listen nor accept.
    if kind == SockKind::Udp {
        // With no three-way handshake to complete, there is nothing to yield
        // for.
        return socket_connect(fd as i32, addr, src_port);
    }

    if kind != SockKind::Tcp { return -1; }

    let Some(h) = tcp::TcpHandle::connect_with_yield(addr.addr, addr.port, src_port,
                                                     &mut yield_fn)
    else { return -1 };

    // Wait out the handshake. Anything that is neither Established nor still
    // in SynSent (a RST closes the connection) is a failure, and reporting it
    // as such is the whole point: an unreachable peer must not look connected.
    let budget_ticks = CONNECT_HANDSHAKE_BUDGET_US
        .saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000;
    let start = azos_drv_sys::timebase::now();
    let mut yields: u32 = 0;
    // N7: the SYN-ACK (or the RST) wakes this task (see `crate::wait`).
    let armed = crate::wait::TCP_WAITERS.arm();
    loop {
        match h.state() {
            tcp::TcpState::Established => break,
            tcp::TcpState::SynSent => {}
            _ => { h.close(); return -1; }
        }
        if azos_drv_sys::timebase::now().wrapping_sub(start) >= budget_ticks
            || yields >= CONNECT_HANDSHAKE_SPIN_CAP
        {
            // Nobody holds the connection after this -1: give its slot
            // back now instead of leaving it to the SYN retry timer.
            h.close();
            return -1;
        }
        armed.wait(start.wrapping_add(budget_ticks), &mut yield_fn);
        yields += 1;
    }

    let mut t = SOCKS.lock();
    t.sockets[fd].slot   = h.slot() as i32;
    t.sockets[fd].tcp    = Some(h);
    t.sockets[fd].remote = *addr;
    0
}

/// Listen on a TCP socket.
pub fn socket_listen(fd: i32, port: u16) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd = fd as usize;
    let kind = { SOCKS.lock().sockets[fd].kind };
    if kind != SockKind::Tcp { return -1; }
    let Some(h) = tcp::TcpHandle::listen(port) else { return -1 };
    let mut t = SOCKS.lock();
    t.sockets[fd].slot = h.slot() as i32;
    t.sockets[fd].tcp  = Some(h);
    0
}

/// Send data on a connected socket.
/// [`socket_send`], but let the TCP layer resolve the peer's MAC first.
///
/// Mirrors the `socket_connect` / `socket_connect_with_yield` pair, and for the
/// same reason: this crate stays scheduler-agnostic, so the ability to yield
/// arrives as a closure from the syscall layer rather than as a dependency.
///
/// UDP has no connection and no retransmission, so it goes straight through —
/// its own `ip::send` still reports an ARP miss, and a datagram is allowed to
/// be lost.
pub fn socket_send_with_yield<F: FnMut()>(fd: i32, data: &[u8], yield_fn: F) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Tcp => h.map_or(-1, |h| h.send_data_with_yield(data, yield_fn)),
        _ => socket_send(fd, data),
    }
}

pub fn socket_send(fd: i32, data: &[u8]) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Tcp => h.map_or(-1, |h| h.send_data(data)),
        // **UDP already knew how to send.** `udp::sendto` exists and works;
        // all that was missing was this layer routing to it. The destination
        // comes from the peer fixed by `connect`, because the `sendto` ABI
        // does not carry one.
        SockKind::Udp => {
            let remote = { SOCKS.lock().sockets[fd as usize].remote };
            if remote.port == 0 || remote.addr == [0, 0, 0, 0] {
                // With no prior `connect` there is nowhere to send. Refuse
                // rather than emit to 0.0.0.0:0, which goes out as garbage.
                return -1;
            }
            // **Return bytes sent, not 0.** `udp::sendto` answers 0 on
            // success and that is not `send`'s contract, which its own doc
            // states as "returns bytes sent" — and which the TCP arm honours.
            // A caller checking `sent == len` would read a correct send as a
            // failure; the boot smoke caught it on the first try.
            match udp::sendto(slot, &remote.addr, remote.port, data) {
                r if r < 0 => r,
                _ => data.len() as i32,
            }
        }
        _ => -1,
    }
}

/// Receive data from a socket (non-blocking).
/// Send to an explicit address. Unconnected UDP.
///
/// **The machinery was already there**: `udp::sendto` has taken `dst_ip` and
/// `dst_port` all along. What was missing was a route from the ABI down to it,
/// because `SYS_SENDTO` dispatched to the same place as `SYS_SEND` and lost
/// the address on the way.
///
/// TCP has no per-message destination — the connection fixes it — so the
/// address is ignored there and it behaves as `send`, which is what POSIX
/// does.
pub fn socket_sendto(fd: i32, data: &[u8], dst: &SockAddr) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Tcp => h.map_or(-1, |h| h.send_data(data)),
        SockKind::Udp => {
            if dst.port == 0 || dst.addr == [0, 0, 0, 0] { return -1; }
            match udp::sendto(slot, &dst.addr, dst.port, data) {
                r if r < 0 => r,
                // Bytes sent, not 0: same contract as `socket_send`.
                _ => data.len() as i32,
            }
        }
        _ => -1,
    }
}

/// Receive, reporting the sender.
///
/// Same story: `udp::recvfrom` has filled `src_ip`/`src_port` all along and
/// this layer threw it away. A UDP server that does not know who spoke to it
/// cannot answer, and that is the ordinary shape of a local service.
pub fn socket_recvfrom(fd: i32, buf: &mut [u8], src: &mut SockAddr) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, _) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Udp => {
            let mut ip = [0u8; 4];
            let mut port = 0u16;
            let n = udp::recvfrom(slot, buf, &mut ip, &mut port);
            if n > 0 {
                src.family = 2;
                src.addr = ip;
                src.port = port;
            }
            n
        }
        // On TCP the sender is the connection's peer and never varies; fill
        // it from what the socket already stores instead of leaving zeros.
        SockKind::Tcp => {
            let n = socket_recv(fd, buf);
            if n > 0 { *src = SOCKS.lock().sockets[fd as usize].remote; }
            n
        }
        _ => -1,
    }
}

pub fn socket_recv(fd: i32, buf: &mut [u8]) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Tcp => {
            let Some(h) = h else { return -1 };
            let n = h.recv(buf);
            if n == 0 {
                // Return -1 when connection is closing and no data remains.
                let state = h.state();
                if state == tcp::TcpState::CloseWait || state == tcp::TcpState::Closed {
                    return -1;
                }
            }
            n
        }
        SockKind::Udp => udp::recv(slot as usize, buf),
        SockKind::Free => -1,
    }
}

/// Half-close a TCP socket: send our FIN and stop sending, but leave `fd`
/// allocated so the application can keep calling `socket_recv`/`socket_recvfrom`.
///
/// This is `shutdown(fd, SHUT_WR)`. It exists because `close()`/`socket_close`
/// couples two things POSIX keeps separate: stopping our own send direction,
/// and giving up the fd. Before this there was no way to do the first without
/// the second — `tcp::send_data` refused anything once the peer's FIN moved a
/// connection to `CloseWait` (fixed alongside this, see `tcp.rs`), and even
/// with that fixed, the only way to stop sending was `socket_close`, which
/// also frees the SOCKS entry and makes every later `socket_recv` on `fd`
/// return -1 for "no such socket" rather than whatever the peer sends next.
///
/// Deliberately does NOT call `close_slot`: that is the whole point. The
/// underlying `tcp` connection walks its ordinary `FinWait1`/`FinWait2` (or
/// `LastAck`, from `CloseWait`) teardown, all still reachable through this
/// same `fd` via `socket_recv` until the peer's own FIN or `Closed` ends it.
///
/// UDP has no send direction to half-close independently of the whole socket,
/// so this refuses anything that is not TCP.
pub fn socket_shutdown(fd: i32) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        (s.kind, s.slot, s.tcp)
    };
    if slot < 0 { return -1; }
    match kind {
        SockKind::Tcp => {
            if let Some(h) = h { h.shutdown_write(); }
            0
        }
        _ => -1,
    }
}

/// Why a multicast join or leave on a socket was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum McastError {
    /// `fd` is out of range or names a free slot.
    BadSocket,
    /// The socket is not UDP. Group traffic is datagrams; a TCP socket has
    /// nothing a group could deliver to.
    NotUdp,
    /// Not a group a socket may join — see [`mcast_group_joinable`].
    BadGroup,
    /// The socket already holds [`MAX_MCAST_PER_SOCKET`] groups, or the
    /// socket's owner task already holds [`MAX_MCAST_GROUPS_PER_TASK`] groups
    /// across all of its sockets.
    SocketFull,
    /// `igmp`'s machine-wide table is full.
    TableFull,
    /// A leave of a group this socket does not hold.
    NotJoined,
}

/// True for a group a socket may join: inside `224.0.0.0/4` and outside
/// `224.0.0.0/24`.
///
/// `224.0.0.0/24` is the Local Network Control Block (RFC 5771 §4):
/// all-hosts, all-routers and the routing protocols' groups. `224.0.0.1` is
/// joined implicitly, and the rest belong to protocols rather than
/// applications — a ring-3 socket joining one would subscribe the robot to a
/// routing protocol's traffic.
pub fn mcast_group_joinable(group: &[u8; 4]) -> bool {
    igmp::is_multicast(group) && !(group[0] == 224 && group[1] == 0 && group[2] == 0)
}

/// Join `group` on UDP socket `fd`.
///
/// A repeat join of a group the socket already holds succeeds and changes
/// nothing: memberships are per socket, so there is one record and one IGMP
/// reference to give back however many times the join was asked for. Distinct
/// sockets in one group each hold a reference, and only the first one's join
/// sends a Membership Report (`igmp::acquire`).
///
/// Before taking a new group, the socket's owner task's memberships across
/// ALL of its sockets are counted; at [`MAX_MCAST_GROUPS_PER_TASK`] the join
/// is refused with [`McastError::SocketFull`] — see that constant for why. A
/// kernel-owned socket (`owner == SOCK_OWNER_KERNEL`) is exempt, the same as
/// [`MAX_SOCKETS_PER_TASK`]: kernel sockets are bounded by their own call
/// sites, not by a quota meant for userspace.
///
/// The record and the reference are taken together under `SOCKS`, so a close
/// of the same socket sees both or neither; the report goes out after the lock
/// is released. Lock order is `SOCKS`, then `igmp`'s table — `igmp` never takes
/// `SOCKS`.
///
/// Like every function in this file it checks no ownership: the syscall layer
/// resolves `fd` from the caller's capability before calling here.
pub fn socket_mcast_join(fd: i32, group: &[u8; 4]) -> Result<(), McastError> {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return Err(McastError::BadSocket); }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    if !mcast_group_joinable(group) { return Err(McastError::BadGroup); }
    let first = {
        let mut t = SOCKS.lock();
        let fd = fd as usize;
        match t.sockets[fd].kind {
            SockKind::Udp => {}
            SockKind::Tcp => return Err(McastError::NotUdp),
            SockKind::Free => return Err(McastError::BadSocket),
        }
        if t.sockets[fd].mcast.iter().any(|g| g == group) { return Ok(()); }
        let free = match t.sockets[fd].mcast.iter().position(|g| *g == NO_GROUP) {
            Some(i) => i,
            None => return Err(McastError::SocketFull),
        };

        // Per-task quota, counted under the SAME lock that will record the
        // new membership below — the same reasoning `socket_create_owned`
        // uses for `MAX_SOCKETS_PER_TASK`: checking the count and then taking
        // the lock would let two of the task's own sockets both pass the
        // check for what would be the task's (MAX_MCAST_GROUPS_PER_TASK +
        // 1)-th group.
        let owner = t.sockets[fd].owner;
        if owner != SOCK_OWNER_KERNEL && owner != SOCK_OWNER_NONE {
            let held: usize = t.sockets.iter()
                .filter(|s| s.kind != SockKind::Free && s.owner == owner)
                .map(|s| s.mcast.iter().filter(|g| **g != NO_GROUP).count())
                .sum();
            if held >= MAX_MCAST_GROUPS_PER_TASK { return Err(McastError::SocketFull); }
        }

        let first = match igmp::acquire(group) {
            Ok(first) => first,
            Err(-1) => return Err(McastError::BadGroup),
            Err(_) => return Err(McastError::TableFull),
        };
        t.sockets[fd].mcast[free] = *group;
        first
    };
    if first { igmp::send_report(group); }
    Ok(())
}

/// Leave `group` on socket `fd`, giving back the reference its join took.
///
/// Only a group this socket holds can be left: another socket's membership is
/// not this socket's to give back, and releasing it would drop the group from
/// under a subscriber that never asked. The Leave Group message goes out only
/// when this was the group's last holder.
pub fn socket_mcast_leave(fd: i32, group: &[u8; 4]) -> Result<(), McastError> {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return Err(McastError::BadSocket); }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    if !mcast_group_joinable(group) { return Err(McastError::BadGroup); }
    let last = {
        let mut t = SOCKS.lock();
        let s = &mut t.sockets[fd as usize];
        match s.kind {
            SockKind::Udp => {}
            SockKind::Tcp => return Err(McastError::NotUdp),
            SockKind::Free => return Err(McastError::BadSocket),
        }
        let i = match s.mcast.iter().position(|g| g == group) {
            Some(i) => i,
            None => return Err(McastError::NotJoined),
        };
        s.mcast[i] = NO_GROUP;
        matches!(igmp::release(group), Ok(true))
    };
    if last { igmp::send_leave(group); }
    Ok(())
}

/// Tear down slot `fd` (already range-checked) and return it to the pool.
///
/// The transport-level close runs with `SOCKS` released, matching what
/// `socket_close` always did: `tcp::close` / `udp::unbind` take their own
/// locks, and holding `SOCKS` across them would invert the lock order that
/// `net_poll` already relies on.
fn close_slot(fd: usize) {
    let (kind, slot, h) = {
        let t = SOCKS.lock();
        (t.sockets[fd].kind, t.sockets[fd].slot, t.sockets[fd].tcp)
    };
    if slot >= 0 {
        match kind {
            SockKind::Tcp => if let Some(h) = h { h.close() },
            SockKind::Udp => udp::unbind(slot as usize),
            SockKind::Free => {}
        }
    }
    // Reset the whole entry, not just `kind`. Clearing `owner` back to
    // "nobody" matters as much as freeing the slot: a stale TID left behind
    // here is inherited by the next task that draws the same fd, which is the
    // ownership check silently passing for the wrong task.
    //
    // The multicast memberships leave in the SAME critical section that frees
    // the entry. Read any earlier, a join landing between the read and the
    // reset would take an IGMP reference no record remembers, and its group
    // would stay joined for the life of the board; after the reset a join
    // finds the slot `Free` and is refused. The Leave messages go out after
    // the lock, like the FIN above.
    let mut last = [false; MAX_MCAST_PER_SOCKET];
    let groups = {
        let mut t = SOCKS.lock();
        let groups = t.sockets[fd].mcast;
        t.sockets[fd] = Socket::new();
        for (i, g) in groups.iter().enumerate() {
            if *g != NO_GROUP {
                last[i] = matches!(igmp::release(g), Ok(true));
            }
        }
        groups
    };
    for (g, last) in groups.iter().zip(last) {
        if last { igmp::send_leave(g); }
    }
}

/// Close a socket.
pub fn socket_close(fd: i32) {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    close_slot(fd as usize);
}

/// Close every socket owned by `tid` — called from the task-exit hook.
///
/// **WHY the exit hook must do this:** the owner stamp is what gates access,
/// and `NEXT_TID` wraps, so a socket left behind by a dead task is inherited
/// wholesale by the next task that draws the same TID — the gate would then
/// hand a stranger a live TCP stream and report it as correctly owned. It
/// also leaks the underlying `tcp`/`udp` slot for the life of the board,
/// and there are only 16 of them.
///
/// Kernel-owned sockets are never touched: the brain link, the OTA listener
/// and TFTP all run with [`SOCK_OWNER_KERNEL`], and tearing one down
/// mid-flight because some unrelated task exited would drop the channel the
/// robot is being commanded over. `SOCK_OWNER_NONE` (0) is excluded for the
/// same reason — `current_task_tid()` returns 0 for "no current task", so a
/// hook firing with 0 must be a no-op rather than a table-wide sweep.
///
/// Idempotent and safe to call for a TID that owns nothing.
///
/// Re-verified 2026-09-06 (claims_check audit): the guard `if tid ==
/// SOCK_OWNER_KERNEL || tid == SOCK_OWNER_NONE { return; }` at the top of
/// this function's body means the per-fd match below (`s.owner == tid`)
/// runs only for a `tid` that is provably neither sentinel, so a
/// kernel-owned slot (`owner == SOCK_OWNER_KERNEL`) can never match and
/// therefore can never be passed to `close_slot`. The separate userspace
/// path — `SYS_SOCK_SHUTDOWN` → `sys_sock_close` → `socket_access_ok` in
/// `crates/core/syscall/src/handlers.rs` (`socket_owner(fd) == Some(caller_tid)`)
/// — is gated the same way: `socket_owner` reports `Some(SOCK_OWNER_KERNEL)`
/// for a kernel slot, which cannot equal a real caller's TID. Both paths
/// were re-checked, not just this one; if a third path to `close_slot` is
/// ever added, it needs the same ownership check or this claim breaks.
///
/// **CONTEXT NOTE for whoever wires the task-exit hook.** This is not a pure
/// bookkeeping sweep like `shm_release_all`: for a socket in `Established`
/// or `CloseWait`, `tcp::close` **transmits a FIN synchronously** through
/// `send_segment` → the NIC driver. That is the correct behaviour (the peer
/// must learn the connection is gone rather than time out), and it is the
/// same work `socket_close` has always done from ordinary task context, but
/// it does mean the exit path now touches the NIC. Specifically:
///
///  * It does **not** yield and does **not** block — a single frame is
///    pushed into the TX ring, or silently dropped if ARP is unresolved.
///  * A socket that joined multicast groups gives them back, and the LAST
///    holder of a group transmits an IGMP Leave to `224.0.0.2` — one frame per
///    group, sent the same way as the FIN.
///  * No lock is held across the transmit: `close_slot` releases `SOCKS`
///    before calling `tcp::close`, which in turn releases the `TCP` lock
///    before calling `send_segment`.
///  * `SOCKS` uses a plain `SpinLock::lock()`, not `lock_irqsave()`. That is
///    sound only because `SOCKS` is unreachable from IRQ context — the RX
///    path goes `ip::handle` → `tcp::handle_checked`, which touches `TCP`,
///    never this table. Do not add an IRQ-context caller without converting
///    the whole module to `lock_irqsave()` first; see `crates/core/ipc/port.rs`
///    for the same-hart deadlock this would otherwise create.
pub fn socket_release_all(tid: u32) {
    if tid == SOCK_OWNER_KERNEL || tid == SOCK_OWNER_NONE { return; }
    for fd in 0..MAX_SOCKETS {
        let owned = {
            let t = SOCKS.lock();
            let s = &t.sockets[fd];
            s.kind != SockKind::Free && s.owner == tid
        };
        if owned {
            close_slot(fd);
        }
    }
}
