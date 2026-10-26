// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// BSD socket API — port of net/socket.c
///
/// Thin socket layer over tcp/udp. `MAX_SOCKETS` slots total (`azos_limits`,
/// per-Kconfig-profile — not a fixed 16).

use azos_sync::SpinLock;
use super::{ethernet, igmp, ip, ipv6, tcp, udp};
pub use azos_limits::MAX_SOCKETS;
use azos_common::envelope::{classify_v4, classify_v6, DestClass};

// Domain
pub const AF_INET: u32  = 2;
/// IPv6 stream sockets. Datagram sockets over IPv6 are not offered: only
/// `ipv6::udpv6_send` and the kernel's own ICMPv6 use UDP over IPv6 today.
pub const AF_INET6: u32 = 10;

/// Raw link-layer sockets: whole Ethernet frames in and out of one
/// interface, picked by EtherType. See [`packet_rx`].
pub const AF_PACKET: u32 = 17;

// Type
pub const SOCK_STREAM: u32 = 1;   // TCP
pub const SOCK_DGRAM:  u32 = 2;   // UDP
/// The only type of an `AF_PACKET` socket.
pub const SOCK_RAW:    u32 = 3;

/// `proto` of an `AF_PACKET` socket that wants every EtherType (Linux's
/// `ETH_P_ALL`, kept so the number means the same to a port of a Linux
/// program). Any other value is the one EtherType the socket receives and
/// may send, in host byte order (`0x88F7`, not its byte-swapped form).
pub const ETH_P_ALL: u32 = 0x0003;

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

/// An IPv6 socket address. Separate from [`SockAddr`], whose four address
/// bytes and field layout the syscall layer builds by struct literal.
#[derive(Clone, Copy)]
pub struct SockAddr6 {
    pub port: u16,      // host byte order
    pub addr: [u8; 16],
}

/// Bytes of the `sockaddr_in` a task passes: the family (`u16` little
/// endian), the port (big endian), the address, 8 bytes of padding.
pub const SOCKADDR_IN_LEN: usize = 16;
/// Bytes of a `sockaddr_in6`, Linux's layout (the one `azos_stdrt::netpure`
/// writes): the family, the port (big endian), the flow info (big endian),
/// the 16 address bytes, the scope id.
pub const SOCKADDR_IN6_LEN: usize = 28;

/// The socket address a task passes to `NODE_BIND` or `NODE_CONNECT`.
#[derive(Clone, Copy)]
pub enum WireAddr {
    V4(SockAddr),
    V6(SockAddr6),
}

impl WireAddr {
    /// Read the bytes a task passed (as many as its length said, at most
    /// [`SOCKADDR_IN6_LEN`]). `AF_INET6` needs the whole `sockaddr_in6`; any
    /// other family is the 16-byte IPv4 form, as these calls have always read
    /// it. The flow info and the scope id are not kept: the stack routes on
    /// neither. `None` when the bytes are short of the family's form.
    pub fn parse(raw: &[u8]) -> Option<WireAddr> {
        if raw.len() < SOCKADDR_IN_LEN {
            return None;
        }
        let family = u16::from_le_bytes([raw[0], raw[1]]);
        let port = u16::from_be_bytes([raw[2], raw[3]]);
        if family == AF_INET6 as u16 {
            let a = raw.get(8..24).filter(|_| raw.len() >= SOCKADDR_IN6_LEN)?;
            let mut addr = [0u8; 16];
            addr.copy_from_slice(a);
            return Some(WireAddr::V6(SockAddr6 { port, addr }));
        }
        Some(WireAddr::V4(SockAddr { family, port, addr: [raw[4], raw[5], raw[6], raw[7]] }))
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SockKind {
    Free,
    Tcp,
    Udp,
    /// `AF_PACKET`: `Socket::slot` is its ring in [`PACKETS`].
    Packet,
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
    /// Created with `AF_INET6`: a stream socket that listens for, accepts and
    /// connects over IPv6 only. `local.port` holds its bound port.
    v6:     bool,
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
    /// `handlers.rs`), which is where the TID comes from — `crates/net/stack` is
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
    /// The IPv4 destination this socket was last cleared to send to by the
    /// egress gate ([`EgressGate`]), `0.0.0.0` for none. A connect clears its
    /// peer; an unconnected `sendto` clears the destination it names, once
    /// for each change of destination, so the gate is asked at the first
    /// packet to a destination and never on the ones after it.
    egress_to: [u8; 4],
}

impl Socket {
    const fn new() -> Self {
        Socket {
            kind:   SockKind::Free,
            slot:   -1,
            tcp:    None,
            local:  SockAddr::new(),
            remote: SockAddr::new(),
            v6:     false,
            owner:  SOCK_OWNER_NONE,
            mcast:  [NO_GROUP; MAX_MCAST_PER_SOCKET],
            egress_to: [0; 4],
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
/// Half the table. Deliberately not a per-task namespace -- that would be
/// a much wider change -- but a quota closes the denial without
/// foreclosing it, and it is the one part of that change that is urgent
/// rather than merely right.
///
/// **Kernel-owned sockets are exempt.** They are created by the brain link,
/// the OTA listener and the two-node probe, all in-kernel and all bounded by
/// their own call sites; charging them against a per-task quota would mean
/// the kernel competing with userspace for its own e-stop channel.
pub const MAX_SOCKETS_PER_TASK: usize = MAX_SOCKETS / 2;

static SOCKS: SpinLock<SocketTable> = SpinLock::new(SocketTable::new());

// ── The egress gate ─────────────────────────────────────────────────────────

/// The seam to the effect gate (`azos_actuation::effect_gate`,
/// `KIND_NET_EGRESS`), which this crate cannot depend on: asked when a socket
/// owned by task `owner` is about to start talking to a destination that is
/// not this node, with the destination's class, its address (IPv4; for IPv6
/// its last four bytes) and port. `true`: go ahead. `false`: the owner's
/// Domain is held by its `egress` envelope row to a nearer class, the gate has
/// written the refusal and its receipt, and the call answers
/// [`EGRESS_REFUSED`].
///
/// Asked once per connect, and by an unconnected `sendto` once per change of
/// destination ([`Socket::egress_to`]); never for loopback or the node's own
/// addresses, nor for a kernel-owned socket (the brain link, OTA, TFTP), which
/// belongs to no Domain.
pub type EgressGate = fn(owner: u32, class: DestClass, dest: u32, port: u16) -> bool;

azos_common::ro_hook! {
    static EGRESS_GATE: EgressGate;
}

/// Install the egress gate (boot, once). Unset, every destination is admitted.
pub fn set_egress_gate(f: EgressGate) {
    EGRESS_GATE.set(f);
}

/// Host tests: forget the installed egress gate (hooks are process-wide there).
#[cfg(not(target_os = "none"))]
pub fn clear_egress_gate_for_test() {
    EGRESS_GATE.clear_for_tests();
}

/// What `connect` and `sendto` answer for a destination the gate refused:
/// `-EACCES`.
pub const EGRESS_REFUSED: i32 = -13;

/// The owner whose Domain the gate has to be asked about for socket `fd`'s
/// next packet to `cache` (the IPv4 destination its answer is remembered for,
/// `None` for a socket that is asked only once): `None` when nothing has to be
/// asked. That is so with no gate installed, for a kernel-owned socket (the
/// brain link, OTA, TFTP belong to no Domain), and for a destination the
/// socket was already cleared to.
fn egress_owner(fd: usize, cache: Option<[u8; 4]>) -> Option<u32> {
    // Gate canary (host suites only): no envelope check, every packet goes.
    if cfg!(feature = "envelope-egress-canary") || !EGRESS_GATE.is_set() {
        return None;
    }
    let t = SOCKS.lock();
    let s = &t.sockets[fd];
    if cache.is_some_and(|a| a == s.egress_to) || s.owner == SOCK_OWNER_KERNEL || s.owner == SOCK_OWNER_NONE {
        return None;
    }
    Some(s.owner)
}

/// May socket `fd` start talking to the destination of class `class`
/// (`word`: the address as the gate records it; `port`)? The hook runs with no
/// lock held: it writes a decision record. On admission `cache` is remembered.
fn egress_ask(fd: usize, owner: u32, class: DestClass, word: u32, port: u16, cache: Option<[u8; 4]>) -> bool {
    let Some(gate) = EGRESS_GATE.get() else { return true };
    if !gate(owner, class, word, port) {
        return false;
    }
    if let Some(a) = cache {
        let mut t = SOCKS.lock();
        if t.sockets[fd].owner == owner {
            t.sockets[fd].egress_to = a;
        }
    }
    true
}

/// May socket `fd` start talking to the IPv4 destination `dst`? Loopback and
/// one of the node's own addresses stay on the node and are not asked about.
fn egress_admitted_v4(fd: usize, dst: &SockAddr) -> bool {
    let Some(class) = classify_v4(dst.addr) else { return true };
    let Some(owner) = egress_owner(fd, Some(dst.addr)) else { return true };
    if ip::iface_owning(&dst.addr).is_some() {
        return true;
    }
    egress_ask(fd, owner, class, u32::from_be_bytes(dst.addr), dst.port, Some(dst.addr))
}

/// [`egress_admitted_v4`] for an IPv6 destination: the word the gate records
/// is the address's last four bytes, and the socket is asked once, at its
/// connect.
fn egress_admitted_v6(fd: usize, dst: &SockAddr6) -> bool {
    let Some(class) = classify_v6(dst.addr) else { return true };
    let Some(owner) = egress_owner(fd, None) else { return true };
    let a = &dst.addr;
    egress_ask(fd, owner, class, u32::from_be_bytes([a[12], a[13], a[14], a[15]]), dst.port, None)
}

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
/// than read from the scheduler here so `crates/net/stack` stays scheduler-
/// agnostic. Every later entry point is gated against this stamp — see the
/// `owner` field on `Socket` for what that prevents.
///
/// `AF_PACKET` + `SOCK_RAW` makes a raw link-layer socket whose `proto` is the
/// EtherType it wants (see [`packet_rx`]); only the kernel may own one.
pub fn socket_create_owned(domain: u32, sock_type: u32, proto: u32, owner: u32) -> i32 {
    if domain == AF_PACKET {
        return create_packet(sock_type, proto, owner);
    }
    let v6 = match domain {
        AF_INET  => false,
        AF_INET6 => true,
        _        => return -1,
    };
    let kind = match sock_type {
        SOCK_STREAM => SockKind::Tcp,
        SOCK_DGRAM if !v6 => SockKind::Udp,
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
    t.sockets[idx].v6     = v6;
    t.sockets[idx].owner  = owner;
    t.sockets[idx].mcast  = [NO_GROUP; MAX_MCAST_PER_SOCKET];
    t.sockets[idx].egress_to = [0; 4];
    idx as i32
}

/// TID that owns `fd`, or `None` if the fd is out of range, free, or
/// unowned.
///
/// This is the accessor the syscall layer's ownership gate reads; it exists
/// so `crates/net/stack` can expose the stamp without importing the scheduler.
/// Mirrors `azos_ipc::memobj_owner` / `port_owner`.
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
        // `addr.port` carries the interface number (the 16-byte `sockaddr_in`
        // the syscall layer reads has no room for a `sockaddr_ll`): 0 binds
        // to every interface, which is also what an unbound packet socket
        // receives from.
        SockKind::Packet => {
            let slot = SOCKS.lock().sockets[fd].slot;
            packet_bind(slot, addr.port)
        }
        SockKind::Free => -1,
    }
}

/// Bind an `AF_INET6` stream socket to a local port.
///
/// `addr.addr` must be the unspecified address `::` or one of ours. The
/// listener that follows takes the whole family either way — as
/// [`socket_bind`] does for IPv4, the address does not narrow it.
pub fn socket_bind6(fd: i32, addr: &SockAddr6) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    if addr.addr != [0u8; 16] && !ipv6::is_our_addr(&addr.addr) { return -1; }
    let mut t = SOCKS.lock();
    let s = &mut t.sockets[fd as usize];
    if s.kind != SockKind::Tcp || !s.v6 { return -1; }
    s.local = SockAddr { family: AF_INET6 as u16, port: addr.port, addr: [0; 4] };
    0
}

/// `NODE_BIND` for either family: [`socket_bind`] or [`socket_bind6`].
pub fn socket_bind_wire(fd: i32, addr: &WireAddr) -> i32 {
    match addr {
        WireAddr::V4(a) => socket_bind(fd, a),
        WireAddr::V6(a) => socket_bind6(fd, a),
    }
}

/// Listen on a TCP socket using the local port stored during bind().
pub fn socket_listen_bound(fd: i32) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd_idx = fd as usize;
    let (kind, port, v6) = {
        let t = SOCKS.lock();
        (t.sockets[fd_idx].kind, t.sockets[fd_idx].local.port, t.sockets[fd_idx].v6)
    };
    if kind != SockKind::Tcp { return -1; }
    if port == 0 { return -1; }
    let Some(h) = (if v6 { tcp::TcpHandle::listen6(port) } else { tcp::TcpHandle::listen(port) })
    else { return -1 };
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
    let (port, v6) = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        if s.kind != SockKind::Tcp { return -1; }
        (s.local.port, s.v6)
    };
    let Some(h) = (if v6 { tcp::TcpHandle::accept6(port) } else { tcp::TcpHandle::accept(port) })
    else { return -1 };
    let mut t = SOCKS.lock();
    match t.alloc() {
        Some(i) => {
            t.sockets[i].kind       = SockKind::Tcp;
            t.sockets[i].slot       = h.slot() as i32;
            t.sockets[i].tcp        = Some(h);
            t.sockets[i].local      = SockAddr::new();
            t.sockets[i].local.port = port;
            t.sockets[i].remote     = SockAddr::new();
            t.sockets[i].v6         = v6;
            t.sockets[i].owner      = owner;
            t.sockets[i].mcast      = [NO_GROUP; MAX_MCAST_PER_SOCKET];
            t.sockets[i].egress_to  = [0; 4];
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
        if !egress_admitted_v4(fd, addr) { return EGRESS_REFUSED; }
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

    if kind != SockKind::Tcp || SOCKS.lock().sockets[fd].v6 { return -1; }
    if !egress_admitted_v4(fd, addr) { return EGRESS_REFUSED; }
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
/// `NODE_CONNECT` passes a 1 ms sleep.
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
/// until the connection is established. `yield_fn` is injected so `crates/net/stack`
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

    if kind != SockKind::Tcp || SOCKS.lock().sockets[fd].v6 { return -1; }
    if !egress_admitted_v4(fd, addr) { return EGRESS_REFUSED; }

    let Some(h) = tcp::TcpHandle::connect_with_yield(addr.addr, addr.port, src_port,
                                                     &mut yield_fn)
    else { return -1 };
    if !await_handshake(h, &mut yield_fn) { return -1; }

    let mut t = SOCKS.lock();
    t.sockets[fd].slot   = h.slot() as i32;
    t.sockets[fd].tcp    = Some(h);
    t.sockets[fd].remote = *addr;
    0
}

/// [`socket_connect_with_yield`] for an `AF_INET6` stream socket: dial
/// `addr` and wait for the handshake. No ARP step: IPv6 frames leave without
/// a neighbour lookup (`ethernet::send_ipv6`).
pub fn socket_connect6_with_yield<F: FnMut()>(
    fd: i32,
    addr: &SockAddr6,
    src_port: u16,
    mut yield_fn: F,
) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS);
    {
        let t = SOCKS.lock();
        let s = &t.sockets[fd];
        if s.kind != SockKind::Tcp || !s.v6 || s.tcp.is_some() { return -1; }
    }
    if !egress_admitted_v6(fd, addr) { return EGRESS_REFUSED; }
    let Some(h) = tcp::TcpHandle::connect(addr.addr, addr.port, src_port) else { return -1 };
    if !await_handshake(h, &mut yield_fn) { return -1; }
    let mut t = SOCKS.lock();
    t.sockets[fd].slot = h.slot() as i32;
    t.sockets[fd].tcp  = Some(h);
    0
}

/// `NODE_CONNECT` for either family: [`socket_connect_with_yield`] or
/// [`socket_connect6_with_yield`].
pub fn socket_connect_wire_with_yield<F: FnMut()>(fd: i32, addr: &WireAddr, src_port: u16, yield_fn: F) -> i32 {
    match addr {
        WireAddr::V4(a) => socket_connect_with_yield(fd, a, src_port, yield_fn),
        WireAddr::V6(a) => socket_connect6_with_yield(fd, a, src_port, yield_fn),
    }
}

/// Wait for the three-way handshake of `h` to finish, calling `yield_fn`
/// between looks, for at most [`CONNECT_HANDSHAKE_BUDGET_US`]. `false` after
/// giving the connection up: an unreachable peer must not look connected.
fn await_handshake<F: FnMut()>(h: tcp::TcpHandle, yield_fn: &mut F) -> bool {
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
            _ => { h.close(); return false; }
        }
        if azos_drv_sys::timebase::now().wrapping_sub(start) >= budget_ticks
            || yields >= CONNECT_HANDSHAKE_SPIN_CAP
        {
            // Nobody holds the connection after this -1: give its slot
            // back now instead of leaving it to the SYN retry timer.
            h.close();
            return false;
        }
        armed.wait(start.wrapping_add(budget_ticks), &mut *yield_fn);
        yields += 1;
    }
    true
}

/// Listen on a TCP socket.
pub fn socket_listen(fd: i32, port: u16) -> i32 {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let fd = fd as usize;
    let kind = { SOCKS.lock().sockets[fd].kind };
    if kind != SockKind::Tcp { return -1; }
    let v6 = SOCKS.lock().sockets[fd].v6;
    let Some(h) = (if v6 { tcp::TcpHandle::listen6(port) } else { tcp::TcpHandle::listen(port) })
    else { return -1 };
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
        SockKind::Packet => packet_send(slot, data),
        _ => -1,
    }
}

/// Receive data from a socket (non-blocking).
/// Send to an explicit address. Unconnected UDP.
///
/// **The machinery was already there**: `udp::sendto` has taken `dst_ip` and
/// `dst_port` all along. What was missing was a route from the ABI down to it,
/// because `NODE_SENDTO` dispatched to the same place as `NODE_SEND` and lost
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
            if !egress_admitted_v4(fd as usize, dst) { return EGRESS_REFUSED; }
            match udp::sendto(slot, &dst.addr, dst.port, data) {
                r if r < 0 => r,
                // Bytes sent, not 0: same contract as `socket_send`.
                _ => data.len() as i32,
            }
        }
        // The frame names its own link and peer; there is no other address.
        SockKind::Packet => packet_send(slot, data),
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
        // The frame names its sender; the address is the interface it came in
        // on, in `port` (as `socket_bind` takes it).
        SockKind::Packet => {
            let (n, ifindex) = packet_recv(slot, buf);
            if n > 0 {
                src.family = AF_PACKET as u16;
                src.port = ifindex as u16;
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
        // `recv` returns -1 for a closing connection with nothing left to
        // read, deciding under the lock it reads the ring with. This arm used
        // to read the state again after that call returned 0: a pass on
        // another hart that delivered the last segments and the FIN in
        // between made it report "closed" with those bytes still unread
        // (seen on the OTA stress, N8: "Connection lost (56916/65536 bytes
        // received)" after the guest had ACKed the FIN).
        SockKind::Tcp => {
            let Some(h) = h else { return -1 };
            h.recv(buf)
        }
        SockKind::Udp => udp::recv(slot as usize, buf),
        SockKind::Packet => packet_recv(slot, buf).0,
        SockKind::Free => -1,
    }
}

/// Whether `fd` is a TCP socket whose connection has ended: the answer a
/// receive that returned `-1` needs to tell "the stream is over" from a
/// refusal. A connection past the peer's FIN (or reset, or closed) holds no
/// more data, so once `socket_recv` has said `-1` for a socket that holds a
/// connection, this stays true for good.
pub fn socket_stream_ended(fd: i32) -> bool {
    if fd < 0 || fd as usize >= MAX_SOCKETS { return false; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, MAX_SOCKETS) as i32;
    let h = {
        let t = SOCKS.lock();
        let s = &t.sockets[fd as usize];
        if s.kind != SockKind::Tcp { return false; }
        s.tcp
    };
    h.is_some_and(|h| matches!(
        h.state(),
        tcp::TcpState::CloseWait | tcp::TcpState::LastAck | tcp::TcpState::TimeWait | tcp::TcpState::Closed
    ))
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
            SockKind::Tcp | SockKind::Packet => return Err(McastError::NotUdp),
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
            SockKind::Tcp | SockKind::Packet => return Err(McastError::NotUdp),
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

// ── AF_PACKET: raw link-layer sockets ───────────────────────────────────────
//
// A packet socket sees whole Ethernet frames of one interface (or all), by
// EtherType, and sends whole frames out of the interface that owns the frame's
// source MAC. It is the transport for protocols that live below IP and that
// this stack does not implement itself: gPTP (EtherType 0x88F7), LLDP, a
// bridge's spanning tree. It is a tap, not a filter: the stack still handles
// the frame as it always did (an ARP packet a socket asked for is still
// answered).
//
// **Receive is a bounded ring per socket**, filled by the receive pass
// ([`packet_rx`]) and drained by `recv`: no syscall per frame beyond the
// reader's own, nothing allocated, and a reader that stalls loses the newest
// frames (counted), never the receive path's time. **Authority:** creating one
// is the kernel's alone for now. A socket that can put any frame on the wire
// can forge any peer at layer 2; ring 3 gets one only through a capability
// the syscall layer checks, which does not exist yet, so `owner` other than
// [`SOCK_OWNER_KERNEL`] is refused.

/// Packet sockets at once (Kconfig `NET_PACKET_SOCKETS`).
pub const PACKET_SOCKETS: usize = azos_limits::NET_PACKET_SOCKETS;

/// Frames queued per packet socket (Kconfig `NET_PACKET_RX_SLOTS`).
pub const PACKET_RX_SLOTS: usize = azos_limits::NET_PACKET_RX_SLOTS;

#[derive(Clone, Copy)]
struct PacketFrame {
    len:     u16,
    /// The interface it arrived on.
    ifindex: ip::IfIndex,
    data:    [u8; ethernet::ETH_FRAME_MAX],
}

#[derive(Clone, Copy)]
struct PacketSock {
    used:      bool,
    /// [`ETH_P_ALL`] as a u16, or the one EtherType wanted.
    ethertype: u16,
    /// 0: every interface.
    ifindex:   ip::IfIndex,
    head:      u8,
    count:     u8,
    ring:      [PacketFrame; PACKET_RX_SLOTS],
}

impl PacketSock {
    const fn new() -> Self {
        PacketSock {
            used: false, ethertype: 0, ifindex: 0, head: 0, count: 0,
            ring: [PacketFrame { len: 0, ifindex: 0, data: [0; ethernet::ETH_FRAME_MAX] };
                   PACKET_RX_SLOTS],
        }
    }

    /// Does a frame of EtherType `et`, arriving on `ifindex`, belong here?
    fn wants(&self, ifindex: ip::IfIndex, et: u16) -> bool {
        self.used
            && (self.ifindex == 0 || self.ifindex == ifindex)
            && (self.ethertype == ETH_P_ALL as u16 || self.ethertype == et)
    }
}

/// Lock order: `SOCKS`, then `PACKETS`. The receive pass takes `PACKETS`
/// alone.
static PACKETS: SpinLock<[PacketSock; PACKET_SOCKETS]> =
    SpinLock::new([PacketSock::new(); PACKET_SOCKETS]);

/// Open packet sockets: the receive pass reads it first, so with none open a
/// frame costs one relaxed load and no lock.
static PACKET_OPEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static PACKET_DELIVERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PACKET_DROPPED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `(delivered, dropped)` frame counts since boot, over every packet socket.
/// `dropped` rising means a reader is too slow for `NET_PACKET_RX_SLOTS`.
pub fn packet_stats() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (PACKET_DELIVERED.load(Relaxed), PACKET_DROPPED.load(Relaxed))
}

fn create_packet(sock_type: u32, proto: u32, owner: u32) -> i32 {
    if sock_type != SOCK_RAW || owner != SOCK_OWNER_KERNEL { return -1; }
    let Ok(ethertype) = u16::try_from(proto) else { return -1 };
    let mut t = SOCKS.lock();
    let Some(idx) = t.alloc() else { return -1 };
    let mut p = PACKETS.lock();
    let Some(ps) = p.iter().position(|x| !x.used) else { return -1 };
    // Field by field: the ring is kilobytes, and a whole `PacketSock` built
    // here would sit on a task stack. Stale frames are unreachable behind
    // `count`.
    p[ps].used = true;
    p[ps].ethertype = ethertype;
    p[ps].ifindex = 0;
    p[ps].head = 0;
    p[ps].count = 0;
    PACKET_OPEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    t.sockets[idx] = Socket { kind: SockKind::Packet, slot: ps as i32, owner, ..Socket::new() };
    idx as i32
}

fn packet_bind(slot: i32, ifindex: u16) -> i32 {
    let Ok(ifindex) = ip::IfIndex::try_from(ifindex) else { return -1 };
    if ifindex != 0 && ip::iface_get(ifindex).is_none() { return -1; }
    match PACKETS.lock().get_mut(slot as usize) {
        Some(p) if p.used => { p.ifindex = ifindex; 0 }
        _ => -1,
    }
}

fn packet_release(slot: i32) {
    if let Some(p) = PACKETS.lock().get_mut(slot as usize) {
        if p.used {
            p.used = false;
            p.count = 0;
            PACKET_OPEN.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Offer a received frame to the packet sockets. Called by the receive pass
/// for every frame of interface `ifindex`, before the stack handles it.
pub fn packet_rx(ifindex: ip::IfIndex, frame: &[u8]) {
    use core::sync::atomic::Ordering::Relaxed;
    if PACKET_OPEN.load(Relaxed) == 0 || frame.len() < ethernet::EthHdr::SIZE
        || frame.len() > ethernet::ETH_FRAME_MAX
    {
        return;
    }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    let mut p = PACKETS.lock();
    for sock in p.iter_mut().filter(|s| s.wants(ifindex, et)) {
        if sock.count as usize == PACKET_RX_SLOTS {
            PACKET_DROPPED.fetch_add(1, Relaxed);
            continue;
        }
        let at = (sock.head as usize + sock.count as usize) % PACKET_RX_SLOTS;
        let slot = &mut sock.ring[at];
        slot.len = frame.len() as u16;
        slot.ifindex = ifindex;
        slot.data[..frame.len()].copy_from_slice(frame);
        sock.count += 1;
        PACKET_DELIVERED.fetch_add(1, Relaxed);
    }
}

/// The oldest queued frame into `buf` (cut to fit, as a datagram socket
/// does): `(bytes copied, interface it arrived on)`; `(0, 0)` when nothing is
/// queued, `(-1, 0)` for a bad socket.
fn packet_recv(slot: i32, buf: &mut [u8]) -> (i32, ip::IfIndex) {
    let mut p = PACKETS.lock();
    let Some(sock) = p.get_mut(slot as usize).filter(|s| s.used) else { return (-1, 0) };
    if sock.count == 0 { return (0, 0); }
    let f = &sock.ring[sock.head as usize];
    let n = (f.len as usize).min(buf.len());
    buf[..n].copy_from_slice(&f.data[..n]);
    let ifindex = f.ifindex;
    sock.head = ((sock.head as usize + 1) % PACKET_RX_SLOTS) as u8;
    sock.count -= 1;
    (n as i32, ifindex)
}

/// Put a whole frame on the wire, out of the interface that owns its source
/// MAC. Refused (-1) when no interface does, when the socket is bound to
/// another one, when the frame's EtherType is not the socket's, or when it
/// is longer than the link carries: a packet socket is not a way to speak as
/// someone else's MAC. Returns the bytes sent.
fn packet_send(slot: i32, frame: &[u8]) -> i32 {
    if frame.len() < ethernet::EthHdr::SIZE { return -1; }
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    let (want_et, bound) = match PACKETS.lock().get(slot as usize).filter(|s| s.used) {
        Some(s) => (s.ethertype, s.ifindex),
        None => return -1,
    };
    let Some(ifindex) = ip::iface_by_mac(&src) else { return -1 };
    if bound != 0 && bound != ifindex { return -1; }
    if want_et != ETH_P_ALL as u16 && want_et != et { return -1; }
    let Some(link) = ip::iface_get(ifindex) else { return -1 };
    if frame.len() > ethernet::EthHdr::SIZE + link.mtu as usize { return -1; }
    if super::net_raw_send(frame) > 0 { frame.len() as i32 } else { -1 }
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
            SockKind::Packet => packet_release(slot),
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
/// bookkeeping sweep like `memobj_release_all`: for a socket in `Established`
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
