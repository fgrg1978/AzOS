# Network

The network stack is the `azos_net` crate (`crates/net/net`). It is `no_std`,
polling-driven, and sits between the NIC drivers (`azos_drv_net`) and the
socket calls. Ring 3 reaches it through capability-typed socket operations;
the heavier protocols (TLS, QUIC) run in ring 3 on top of those sockets.

Related documents: [security.md](security.md) for the authority model the
socket capabilities belong to, [observability.md](observability.md) for the
decision records and counters the stack produces, [update.md](update.md) for
the OTA listener that uses the stack.

| Layer | Where it lives |
|-------|----------------|
| Ethernet, ARP | `crates/net/net/src/ethernet.rs`, `crates/net/net/src/arp.rs` |
| IPv4, ICMP, routing, forwarding | `crates/net/net/src/ip.rs` |
| Packet filter seam, built-in firewall | `crates/net/net/src/filter.rs` |
| NAT (NAPT) | `crates/net/net/src/nat.rs` |
| IPv6, ICMPv6, neighbour discovery | `crates/net/net/src/ipv6.rs` |
| UDP, TCP | `crates/net/net/src/udp.rs`, `crates/net/net/src/tcp.rs` |
| Sockets (kernel side) | `crates/net/net/src/socket.rs` |
| DHCP, DNS, SNTP, IGMP | `crates/net/net/src/dhcp.rs`, `dns.rs`, `ntp.rs`, `igmp.rs` |
| Socket syscalls | `crates/core/syscall/src/handlers.rs`, `crates/core/syscall/src/invoke.rs` |
| TLS, QUIC | `userspace/lib/tls`, `userspace/lib/quic` |

## Receive path

Source: `crates/net/net/src/lib.rs`, `crates/net/net/src/rx_owner.rs`,
`crates/net/net/src/wait.rs`.

The stack has no interrupt-driven protocol processing of its own. `net_poll`
runs one receive pass:

1. Every attached interface is drained in turn, each with the full budget
   (Kconfig `NET_RX_DRAIN_PER_POLL`), so a flood on one link cannot starve the
   others.
2. Each frame is first offered to the packet sockets (`socket::packet_rx`),
   then dispatched by EtherType: ARP, IPv4 or IPv6 (IPv6 is handled for the
   primary interface only).
3. The pass is one transmit batch (`net_tx_batch_begin` / `net_tx_batch_end`):
   replies and re-posted receive buffers are announced to the NIC once, at the
   end. Delayed TCP acknowledgements held during the pass are flushed at the
   end of it (Kconfig `TCP_DELACK_PASS_FLUSH`, default on).

`net_poll` returns `true` when the budget ran out, which tells the caller to
run another pass soon.

The `net-poll` task (`kernel/src/tasks/net_poll.rs`) runs the passes and
sleeps until the nearest TCP deadline. A NIC whose receive interrupt reaches
it (virtio-pci with MSI, the e1000e with MSI, and with Kconfig `NET_RX_IRQ`,
default on, the virtio-mmio line and the VisionFive 2 MAC) wakes it on
traffic, and with no deadline it sleeps at most `NET_IRQ_IDLE_CEILING_MS`;
any other NIC is polled every `NET_POLL_PERIOD_US`. The NIC drivers themselves (virtio-net, e1000e, igc,
the Cadence and DesignWare MACs, USB CDC-ECM/NCM) and their DMA are described
in [drivers.md](drivers.md).

Only one pass runs at a time (`rx_owner::PassOwner`). A caller that finds a
pass in progress leaves a request and returns; the owner runs one more pass
for it.

Tasks that wait for a network event (a handshake, an ARP reply, a DNS answer,
a send window) register in a `wait::WaitQueue` slot before testing their
condition and block until their deadline. The code that makes the condition
true calls `WaitQueue::notify` after dropping its lock. The crate does not
link the scheduler; the kernel installs the blocking and wake hooks with
`wait::set_hooks`. With no hooks installed, the caller's own yield function is
the wait.

## Interfaces and routes

Source: `crates/net/net/src/ip.rs` (section "Interfaces and routes"),
`crates/net/net/src/lib.rs`, `kernel/src/boot/net.rs`.

Every NIC the driver layer reports ready becomes an interface (`Iface`).

- Interfaces are numbered from 1 (`IfIndex`, 0 means none) in the order they
  come up and named `eth0`, `eth1`, and so on (`ip::iface_name`).
- Each carries its own MAC, MTU, IPv4 address, mask, configured gateway and
  IPv6 link-local address.
- Interface 1 is the primary interface (`PRIMARY_IF`). The single-address
  consumers read it through `net_get_ip` and related functions: TCP's source
  address, DHCP, DNS, SNTP, IGMP and the IPv6 stack.
- The registry holds `MAX_IFS` entries (Kconfig `NET_MAX_INTERFACES`). Further
  NICs are left unused and the stack says so on the console.
- A NIC that appears after boot (a USB network function) gets an interface
  through `net_nic_added`; a function plugged in again keeps its interface
  number, and frames sent while it is gone fail.

A destination leaves by the best route, chosen by longest prefix, then lowest
metric, then route kind, then lowest interface number (`ip::route`, returning
an `Egress`). There are three kinds of route, in this order of preference
at equal prefix and metric:

| Kind | Source |
|------|--------|
| Connected | Derived from each configured interface's own address and mask. Never stored, so it cannot go stale when the address changes. |
| Static | `[route.NAME]` rows of the signed topology, installed by `kernel/src/boot/net.rs` through `net_route_add` (`ip::route_add`). Capacity is `MAX_STATIC_ROUTES` (Kconfig `TOPOLOGY_MAX_ROUTES`). |
| Lease | `0.0.0.0/0` through the interface's configured gateway (a DHCP lease or the configuration file), at metric `LEASE_METRIC`. A static default route has metric 0 unless its row says otherwise, so it wins. |

A `[route.NAME]` row has the fields `dest` (a prefix), `via` (gateway, optional),
`dev` (an interface name such as `eth0`) and `metric` (default 0); the parser
is `RouteSpec` in `crates/core/topology/src/types.rs`. `route_add` refuses a
prefix longer than 32 bits, an unknown interface, a duplicate destination and
metric, and a full table (`RouteError`). A row for an interface that does not
exist is refused and reported. IPv6 route rows are counted and not installed:
the IPv6 stack is single-interface.

With no matching route, a send fails; the stack does not ARP an off-link
destination directly when it has no gateway.

`net_set_ip` changes the primary interface's address and mask (it refuses a
mask with a hole in it), updates the address TCP uses for its checksums, and
pre-resolves the gateway with an ARP request so the first binding is a
solicited one.

## IPv4

Source: `crates/net/net/src/ip.rs`, `crates/net/net/src/arp.rs`,
`crates/net/net/src/igmp.rs`.

On receive, `ip::handle` checks length, version, header checksum and rejects
fragments. **The stack performs no reassembly and no fragmentation**: a
fragment is dropped, and a forwarded packet longer than the egress MTU draws
ICMP "fragmentation needed" whether or not DF is set. TCP segments leave with
Don't Fragment set.

A packet is accepted for local delivery when its destination is the
interface's unicast address, the limited broadcast, the subnet's directed
broadcast, a multicast group the host has joined (checked at the IP level,
not left to the NIC), or any address while the host is unconfigured (so a
DHCP client can hear its server).

ARP keeps one cache per interface, so an answer on one link says nothing
about another and a flood on one cannot evict another link's gateway. When a
cache is full, a trusted insert evicts the oldest unsolicited entry first,
then the oldest entry. A packet waiting for ARP resolution is held
in a small bounded queue (`ip::ARP_TXQ_SIZE`) until the answer arrives or the
entry expires.

Each entry is marked solicited (the answer to a question the stack asked, or
written by the kernel through `arp::insert`) or unsolicited (picked up from
someone else's request). An unsolicited binding (`ArpCache::learn_unsolicited`)
only fills a free slot and never displaces an entry; a different MAC for an
address already cached is refused as a conflict and the stack asks the
question itself, so a forger has to win a race against the genuine answer.
Callers that need a trustworthy binding use the solicited lookup
(`ArpCache::get_solicited`), and a solicited entry older than the reachable
time is re-verified in the background while still being used.

IGMP (`igmp.rs`) implements group membership for UDP sockets and reports
immediately rather than after a random delay. Joining and leaving are the
socket operations `NODE_MCAST_JOIN` and `NODE_MCAST_LEAVE`.

### Forwarding

When Kconfig `NET_IP_FORWARD` is on, a unicast packet addressed to an address
no interface holds is routed instead of dropped. Forwarded packets skip the
ingress and egress filter hooks and meet the forward hook, in this order:

1. Checks: multicast is dropped silently; with the masquerade on, a packet
   arriving on the uplink that answers no mapping is refused; a source or
   destination that is not a unicast address, a directed broadcast of an
   interface, and a packet for one of this host's own addresses are refused;
   TTL must be above 1 (else ICMP "time exceeded").
2. An answer to a masqueraded flow is translated back.
3. The route lookup (else ICMP "network unreachable"). A packet that would
   leave by the interface it arrived on is refused: no hairpin, no redirect.
4. TTL is decremented and the header checksum rewritten.
5. The filter's forward hook, with the NAT's view of the flow.
6. A packet leaving by the uplink is masqueraded.
7. The packet is put on the link, queued for ARP if needed.

ICMP errors a router sends are rate-limited. Refusals made by the stack itself
go through `filter::refuse`, so they are counted and recorded like a filter's.

## IPv6

Source: `crates/net/net/src/ipv6.rs`, `crates/net/net/src/socket.rs`.

| Feature | State in the tree |
|---------|-------------------|
| Link-local address from the MAC (EUI-64) | Yes |
| Neighbour solicitation and advertisement | Yes |
| Router solicitation (sent once at init) and router advertisement (SLAAC prefix, default router) | Yes; one global `/64` address, EUI-64 interface id |
| ICMPv6 echo | Yes |
| UDP over IPv6 | `ipv6::udpv6_send` and the kernel's own ICMPv6; no UDP socket type over IPv6 |
| TCP over IPv6 | Yes: `AF_INET6` stream sockets listen, accept and connect over IPv6 only. From ring 3 such a socket can be bound (port only), listen and accept; the connect op reads a 16-byte IPv4 address and refuses it |
| Duplicate address detection, neighbour cache, DHCPv6 | No |

The IPv6 stack is one global address on the primary interface. A frame
arriving on another interface is not handed to it. With no neighbour cache, a
unicast datagram to an on-link host leaves as an Ethernet broadcast; one for
an off-link host goes to the router the last advertisement named. Neighbour
discovery messages (ICMPv6 133 to 137) are accepted only with hop limit 255.

The packet filter's ingress and egress hooks and the built-in firewall cover
IPv6 as they cover IPv4 (see below); the NAT and the forward hook are IPv4
only, as the stack does not route IPv6.

The socket ops read a 16-byte IPv4 socket address, so the ring-3
standard-library port's `std::net` is IPv4 only
(`sdk/std/sys/net/connection/azos.rs` documents what it serves and what
answers `Unsupported`).

## TCP and UDP

Source: `crates/net/net/src/tcp.rs`, `crates/net/net/src/udp.rs`.

The TCP implementation (`TCP_MAX_CONNS` connections, Kconfig-sized per
profile) provides:

- initial sequence numbers (RFC 6528): HMAC-SHA256 of the 4-tuple under a
  256-bit secret, plus the clock. The secret is drawn from the entropy pool
  once a seeded source is installed; until then it is a built-in constant
  with the boot timer value XORed into its first four bytes, which an
  observer of the binary can narrow down;
- a send queue that holds every unacknowledged byte once, several segments in
  flight, retransmission with RFC 6298 timers;
- congestion control (RFC 5681) with NewReno recovery (RFC 6582), or
  SACK-based loss recovery (RFC 6675) when the peer negotiated SACK, from an
  initial window of ten segments (RFC 6928; one after a lost SYN or SYN-ACK);
- MSS negotiation, window scaling (RFC 7323) when both SYNs carry the option,
  SACK (RFC 2018) with a scoreboard so retransmissions skip held blocks;
- Timestamps (RFC 7323, Kconfig `TCP_TIMESTAMPS`): every ACK of new data is an
  RTT sample and PAWS refuses old duplicates; the option's 12 octets come out
  of each segment's payload;
- ECN (RFC 3168, Kconfig `TCP_ECN`): asked for on our SYNs and agreed to on
  the peer's; new data leaves ECT(0), a CE mark is echoed until CWR, and an
  echo halves the window once per window of data;
- path MTU discovery from ICMP "fragmentation needed" (RFC 1191, validated per
  RFC 5927, reports below 576 ignored) and a black-hole fallback that halves
  the MSS after three timeouts of a full segment;
- delayed acknowledgements (`TCP_DELACK_MS`, `TCP_DELACK_SEGS`);
- sequence-number validation, a reset accepted only at exactly `RCV.NXT`
  (RFC 5961 section 3.2; no challenge ACK), keep-alive probes, simultaneous
  open;
- a cap of `TCP_MAX_CONNS / 2` half-open connections per listener; beyond it,
  or with the table full, a SYN is answered with a cookie (RFC 4987, Kconfig
  `TCP_SYNCOOKIES`), and without cookies it takes the slot of the oldest
  half-open one;
- a connection address that is IPv4 or IPv6 (`tcp::IpAddr`); the state machine
  does not look at the family.

Sequence arithmetic is in `crates/net/net/src/seq.rs` so a host test suite can
reach it.

UDP has a fixed table of `UDP_MAX_SOCKETS` (8, a constant in `udp.rs`) bound
ports, each with a receive ring of `UDP_RX_SLOTS` datagrams (Kconfig), each
slot sized for a full-MTU datagram. This table is separate from the socket
table (`MAX_SOCKETS`).

DHCP (`dhcp.rs`) is a client with a bounded wait per phase and a bounded option
walk. On a lease it sets the interface address, the DNS server (option 6) and
the NTP server (option 42); the request carries a parameter request list for
those options and the mask and router, since a server sends option 42 only when
asked. The lease is kept (RFC 2131 §4.4.5) by the `net-clients` task
(`dhcp::dhcp_maintain`): at T1 (option 58, or half the lease) a REQUEST is
unicast to the lease's server, at T2 (option 59, or 7/8) broadcast to any, and
at the lease's end, or on a NAK, the address is dropped and the client starts
over with a DISCOVER. SNTP (`ntp.rs`) sends a unicast request and hands the four timestamps of
each exchange to the clock discipline through `ntp::set_exchange_sink`; the
`net-clients` task starts the exchanges (see [SNTP](time.md#sntp)).

## Sockets as capabilities

Source: `crates/core/abi/src/invoke.rs`, `crates/core/abi/src/cap.rs`,
`crates/core/syscall/src/handlers.rs`, `crates/core/syscall/src/invoke.rs`,
`crates/core/syscall/src/ioring_ops.rs`, `crates/net/net/src/socket.rs`.

A ring-3 socket is a capability. `DOMAIN_SOCKET` (domain, type, protocol),
invoked on the caller's own domain handle, creates a socket and returns a
`ty::SOCKET` handle (kind `Node`, class 2) with `READ | WRITE | DUP | TRANSFER`
(`CapPerms::RW_DELEGATE`). If the capability table is full, the socket is
closed again so no slot leaks.

Operations on the handle (`SYS_INVOKE` with the handle and an op from
`azos_abi::invoke`):

| Op | Needs | Effect |
|----|-------|--------|
| `NODE_BIND` | `WRITE` | Bind to the local `sockaddr` |
| `NODE_CONNECT` | `WRITE` | Connect; for TCP waits for the handshake, sleeping between polls |
| `NODE_SEND` | `WRITE` | Send on a connected socket |
| `NODE_SENDTO` | `WRITE` | Send to an explicit address (unconnected UDP); address 0 means the connected peer |
| `NODE_RECV` | `READ` | Receive without blocking (0: nothing yet); a TCP stream that ended answers `-EEOF` |
| `NODE_RECVFROM` | `READ` | Receive and report the sender's address |
| `NODE_MCAST_JOIN` | `WRITE` | Join an IPv4 group on a UDP socket |
| `NODE_MCAST_LEAVE` | a live handle | Leave a group; containment does not keep a group joined |
| `NODE_LISTEN` | `WRITE` | Listen on the TCP port `NODE_BIND` gave the socket; -1 for no port, a port taken or no connection slot |
| `NODE_ACCEPT` | `READ` | Take one established connection without blocking (`-EAGAIN`: none waiting) as a new `ty::SOCKET` handle with `READ \| WRITE \| DUP \| TRANSFER`, owned by the caller; `-EMFILE` (connection closed) when the capability table is full |

Choosing where a socket talks to counts as a write. While degraded-mode
containment is armed, the operations that need `WRITE`, and `NODE_ACCEPT`,
answer `-EAGAIN`.

A capability refusal of a typed call (anything but containment) is recorded
as a capability denial (`Rule::CapDenial`), and the errno distinguishes a
stale handle (`ECAPSTALE`), a handle of the wrong kind (`ECAPKIND`) and missing
rights (`ECAPPERMS`). An owner-stamp refusal (below) answers a bare -1 and is
not recorded on the typed call path; the io_ring path records it.

A `connect`, and an unconnected `sendto` each time its destination changes,
asks the effect gate (`KIND_NET_EGRESS`, the Domain's `egress` envelope row;
see [effects.md](effects.md#storage-and-network-envelopes)) before a socket
talks to a destination off the node; a refusal answers `-EACCES`. Loopback,
the node's own addresses and kernel-owned sockets are not asked about, and
with no gate installed every destination is admitted.

Two checks apply, and both are load-bearing:

1. The capability is resolved in the caller's own capability table, with the
   needed right.
2. The socket table is flat and the descriptor is an index into it, so each
   socket also carries an **owner stamp**: the task id taken when the socket
   was created or accepted. `socket_access_ok` compares it with the caller
   before every operation except `NODE_MCAST_JOIN` and `NODE_MCAST_LEAVE`,
   which check only the capability. A `Cap<Socket>` that was transferred to
   another task still names the sender's socket index, so the receiver's
   handle resolves but the owner check refuses it (a multicast join or leave
   on it acts on the sender's socket).

Sockets created from kernel context carry `SOCK_OWNER_KERNEL`, which no task
id equals, so ring 3 cannot reach them. A task may hold at most
`MAX_SOCKETS_PER_TASK` sockets (half of `MAX_SOCKETS`); the quota is counted
under the same lock that allocates the slot.

The ring-3 operation set covers TCP (connect, and listen and accept, which
`SSHD.ELF` uses) and UDP (bound, connected or unconnected, with multicast).
Kernel tasks (for example the OTA listener) use `socket_listen` and
`socket_accept` in `azos_net` directly. The std port does not use the listen
and accept ops: `std::net::TcpListener` answers `Unsupported`.
An io_ring submission can also send or receive on a socket capability: the
capability is resolved in the ring owner's table with `WRITE` (send) or `READ`
(receive), the owner stamp is checked, and the bytes are queued or taken
without waiting.

The raw descriptor-style calls (`sys_socket`, `sys_bind`, ...) are in
`handlers.rs` behind the same owner check; the typed ones wrap them.

## Packet filter hooks

Source: `crates/net/net/src/filter.rs`.

The IPv4 path asks one installed object, a `PacketFilter`, at three hooks; the
IPv6 path asks the same object at the first two (`ipv6_rx` and the one send
funnel of `ipv6.rs`, the Neighbour Discovery messages it sends included):

| Hook | Asked when |
|------|-----------|
| `Hook::Ingress` | A datagram for this host, after the header checks and destination filter, before any transport sees it |
| `Hook::Egress` | A datagram this host built, before it is looped back, queued for ARP or put on the wire |
| `Hook::Forward` | A datagram this host routes for someone else (`NET_IP_FORWARD`); the NAT is its connection tracker |

The egress hook sees what leaves through `ip::send`. Frames the stack builds
whole and hands to the NIC directly do not pass it: the DHCP client's
DISCOVER and REQUEST, ARP, packet-socket frames and every IPv6 datagram.

```text
pub trait PacketFilter: Sync {
    fn check(&self, hook: Hook, pkt: &PacketView, conn: Option<&ConnState>) -> Verdict;
}
```

`check` runs on any hart, possibly concurrently; it must be quick, must not
block and must not call back into the stack's send path. A `PacketView` is a
read-only view of an IPv4 or IPv6 packet already validated by the stack: the
family (`v6`), addresses (16 bytes; an IPv4 address in the first four),
protocol or next header, header length and, for TCP and UDP, ports and the TCP
flag byte.
`ConnState` (phase `New`, `Established` or `Related`, and a reply flag) is what
a tracker knows of the flow; the stack passes `None` at ingress and egress and
the NAT's view at forward.

`set_filter` installs a filter and `clear_filter` removes it. **With no filter
installed the hooks cost one relaxed load of a flag** (`filter::active`) and
the stack behaves as if the module did not exist.

Verdicts:

| Verdict | Ingress and forward | Egress |
|---------|--------------------|--------|
| `Accept` | The packet goes on | The packet goes on |
| `Drop` | Discarded silently | Discarded; `send` reports 0 |
| `Reject` | Discarded; ICMP "administratively prohibited" (type 3, code 13) to the sender, for IPv6 ICMPv6 Destination Unreachable code 1 | Discarded; `send` reports -1 |

No ICMP is sent about a broadcast or multicast datagram, about an ICMP
datagram, or to a source that is not a single host (RFC 1122 section 3.2.2;
for IPv6, RFC 4443 section 2.4 (e)), and replies are rate-limited
(`REPLIES_PER_SEC`, `REPLY_BURST`).

Every `Drop` and `Reject` bumps a counter and is offered to the decision
recorder as `Rule::PacketRefused`. The record is rate-limited before it is
written (`RECORDS_PER_SEC`, `RECORD_BURST`, a token bucket); the refusals it
holds back are counted and the count rides in the third number of the next
record written. The first number is source and destination (32 bits each),
the second the hook, verdict, protocol, an IPv6 flag (bit 32) and the ports;
an IPv6 address is recorded by its last four bytes. `filter::stats` returns
the counters.

## The built-in firewall

Source: `crates/net/net/src/filter.rs`, `kernel/src/boot/net.rs`,
`crates/core/topology/src/types.rs`, `crates/core/topology/src/parser.rs`.

`filter::Firewall` is the simple filter every preset can have. At boot,
`install_firewall` compiles the topology's `[firewall.NAME]` rows into a rule
table (`FwRule`, at most `MAX_RULES`, Kconfig `TOPOLOGY_MAX_FIREWALL_ROWS`) and
installs the firewall only if it could refuse something (`Firewall::needed`):
no refusing rule and an accepting default leaves the stack unfiltered.

A row has these fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `dir` | yes | `in`, `out` or `forward` (the three hooks) |
| `action` | yes | `allow`, `drop` or `reject` |
| `proto` | no | `any` (default), `tcp`, `udp` or `icmp` |
| `port` | no | First destination port matched (1 to 65535); only with `tcp` or `udp` |
| `port_end` | no | Last port of a range; needs `port` |
| `addr` | no | Remote prefix such as `10.0.0.0/8` or `2001:db8::/32`: the source of an `in` packet, the destination of an `out` or `forward` one |

A row with an IPv4 prefix judges IPv4 packets only, one with an IPv6 prefix
IPv6 packets only, and a row without `addr` both; its `icmp` is ICMP for an
IPv4 packet and ICMPv6 for an IPv6 one. A `forward` row with an IPv6 prefix
never matches: the stack does not route IPv6.

Rows are tried in file order and the first match decides. A packet no row
matches gets the default policy: at the ingress and forward hooks, drop when
Kconfig `FIREWALL_INBOUND_DROP` is on (its default is on under `USE_GATEWAY`),
otherwise accept; at the egress hook, accept. The inbound default never drops
the Neighbour Discovery messages, ICMPv6 types 133 to 137 (router and
neighbour solicitation and advertisement, redirect) with hop limit 255: they
are to IPv6 what ARP is to IPv4, and SLAAC needs them. A row still decides
about them first. The topology parser rejects a row whose match (`dir`,
`proto`, ports, `addr`) is identical to an earlier row's; a row shadowed by a
broader earlier one is accepted and never matches.

The firewall is stateful for TCP and UDP. A flow that one side opened with an
accepted packet is tracked by its 5-tuple (whole addresses and the family, so
an IPv4 and an IPv6 flow never share an entry), and once the peer has answered,
packets of the flow pass in both directions whatever the rules say. The flow
table has `CT_SLOTS` entries (Kconfig `FIREWALL_CONNTRACK_MAX`, rounded to
sets of four ways), is hashed with a boot-time key (entropy-pool bytes, or the
clock when no seeded source exists) so the set index is not in an attacker's
hands, and never grows. A new flow evicts an expired entry, then the oldest
one nobody has answered or that is closing, so a flood of SYNs cannot push out
an established flow; a flow whose set holds only live answered flows is
dropped rather than started untracked. A FIN or RST starts a flow's end but
the entry stays 20 s so the closing exchange still passes. Idle timeouts are
`FIREWALL_UDP_TIMEOUT_S`, 20 s for a TCP flow nobody has answered, and
`FIREWALL_TCP_TIMEOUT_S` for an established one.

A `Reject` from the firewall is the ICMP answer described above; the filter
sends no TCP reset.

## NAT

Source: `crates/net/net/src/nat.rs`, `crates/net/net/src/ip.rs`.

With Kconfig `NET_NAT` on, traffic forwarded out of the uplink (the interface
of the best default route, `ip::uplink`) is masqueraded. The NAT is not a
`PacketFilter`: a filter cannot change a packet, a translation rewrites it. It
is called by `ip::forward`, and the order is the one a Linux gateway has so a
firewall row means the same thing: the forward hook sees the LAN addresses on
both legs, and the translation is the last step before the packet is queued.

- A forwarded packet leaving by the uplink gets the uplink's address as source
  and a port from `NAT_PORT_MIN..=NAT_PORT_MAX` as source port (an ICMP echo's
  identifier stands for the port). The range must not overlap the TCP
  ephemeral range, which is checked at compile time.
- The answer arriving on the uplink for that port, from the remote the flow
  was opened to, is translated back. An ICMP error about a translated flow is
  translated back too, including the quoted packet's addresses, ports and
  checksums.
- Only a TCP SYN, a UDP datagram or an ICMP echo request opens a mapping.
  Nothing arriving from outside opens one: there is no port forwarding. Other
  protocols are refused (`Refused::Unsupported`).
- Checksums: the IP header's is recomputed; the transport checksum is updated
  incrementally (RFC 1624), so payload is never read. A UDP checksum of 0 stays
  0.

The table has `NAT_SLOTS` mappings (Kconfig `NAT_TABLE_MAX`), four-way
set-associative, never grown. The translated port is chosen congruent to the
mapping's set, so one table is indexed from both directions: the outbound
lookup hashes the 5-tuple (boot-entropy seed) to a set, the inbound lookup
takes the set from the port. A flow whose set is full of live answered
mappings is refused (`Refused::TableFull`); a new flow evicts an expired
mapping, then the oldest unanswered or closing one. Timeouts are per protocol
(`NAT_UDP_TIMEOUT_S`, `NAT_TCP_TIMEOUT_S`, `NAT_TCP_TRANSIENT_S`,
`NAT_ICMP_TIMEOUT_S`) and every packet in either direction renews a mapping, so
there is no sweeper.

## Packet sockets

Source: `crates/net/net/src/socket.rs`.

`AF_PACKET` with `SOCK_RAW` gives a socket that sees whole Ethernet frames and
sends whole frames. The `proto` argument is the EtherType wanted (host byte
order), or `ETH_P_ALL`. `socket_bind` takes an interface index in the port
field (0 means every interface).

- It is a tap, not a filter: the stack still handles every frame it would have
  handled. The protocols meant for it are those that live below IP and that
  the stack does not implement, such as gPTP (0x88F7) or LLDP.
- Receive is a bounded ring per socket (`NET_PACKET_RX_SLOTS` frames, at most
  `NET_PACKET_SOCKETS` sockets), filled by the receive pass. A reader that
  stalls loses the newest frames, which are counted (`socket::packet_stats`).
  With no packet socket open, a frame costs one relaxed load.
- Send picks the interface that owns the frame's source MAC. It is refused if
  no interface owns it, if the socket is bound to another interface, if the
  EtherType differs from the socket's, or if the frame exceeds the link's MTU.
  A packet socket is not a way to speak as someone else's MAC.
- **Only kernel context may create one** (`create_packet` requires
  `SOCK_OWNER_KERNEL`). A socket that can put any frame on the wire can forge
  any peer at layer 2; ring 3 has no capability for it. What ring 3 gets at
  layer 2 is a whole NIC queue, taken from the stack (next section).

## NIC queues in ring 3

Source: `crates/net/net/src/nic_queue.rs`, `crates/core/syscall/src/nicq.rs`,
`crates/core/abi/src/nic_queue.rs`.

A program whose topology row holds a NIC queue (`{ kind = "device", target =
"nicq.eth1.0", perm = "rw" }`, a `Cap<NicQueue>`: kind `Queue`, class 1) may
take it from the stack and run it on a pair of rings, in the netmap and AF_XDP
shape (Kconfig `NET_NIC_QUEUES`):

- **The rings** are two regions the program made (read-write, physically
  contiguous, `SHM_KIND_CONTIG`) and hands to `QUEUE_NICQ_ATTACH`. The kernel
  lays an `azos_rings::region::SpscBytes` ring of 1,544-byte slots into each
  and writes the geometry into its header. Every slot carries an 8-byte
  descriptor (`nic_queue::Desc`) and a frame of at most 1,518 bytes.
- **Receive needs no call per frame.** The receive pass pushes every frame of
  the taken queue on the receive ring with its stamp, instead of handing it to
  the packet sockets, ARP and IP. The reader sleeps on the ring's head word
  and is woken once per pass when it said it may be asleep. A full ring drops
  the newest frame and counts it.
- **Transmit is a kick** (`QUEUE_NICQ_KICK`, the AF_XDP `sendto`): the kernel
  pops the transmit ring, checks every frame (an Ethernet header at least, a
  slot at most, the interface's own MAC as source) and hands it to the NIC. A
  slot that asks for it (`TX_STAMP`) is answered on the receive ring by a
  `DESC_TX_DONE` with its departure stamp, or `TX_REFUSED`.
- **Stamps.** A descriptor says whose stamp the slot carries: `STAMP_HW` for
  the NIC's own, `STAMP_SW` for the kernel's, read at the driver boundary (the
  frame taken off the NIC's receive ring, or just before it is handed to the
  transmit ring), in nanoseconds of the monotonic clock. No NIC driver in the
  tree reads hardware stamps yet, so every queue reports `STAMP_SW`.
- **The stack does not see a taken queue.** Nothing the stack builds leaves by
  it (`net_raw_send` refuses), and none of its frames reach a socket. The
  interface keeps its address and routes. Every NIC the stack drives has one
  queue, so taking queue 0 takes the NIC.
- **What is never handed over.** The primary interface, which every kernel
  service runs on, and the interface the route to the link peer (the brain the
  behavior task dials, which carries the e-stop) leaves by. The attach is then
  refused with `-EPERM` and recorded (`Rule::NicQueue`). These checks run at
  the attach, not at the seed: a NIC can come and go, and a route can change.
- **The attachment ends** with `QUEUE_NICQ_DETACH`, the owner's exit, or a
  ring's region going away, and the queue goes back to the stack.
- **Who uses it.** The PTP daemon (`PTPD.ELF`, Kconfig `PTPD_NIC_QUEUE`):
  IEEE 1588 over Ethernet (Annex F, EtherType 0x88F7) on the queue, every
  timestamp the queue's instead of a clock read after a socket poll. It falls
  back to UDP when the kernel keeps the queue. What one frame costs on the
  rings against the socket path is measured at boot by the
  `nicq-cost-probe` kernel feature (`kernel/src/smokes/nicq_cost.rs`).

## TLS and QUIC in ring 3

Source: `userspace/lib/tls`, `userspace/lib/quic`, `userspace/lib/tls-probe`,
`userspace/services/rpcquic`.

Neither protocol is in the kernel. Both are `std` libraries over the std
port's sockets (`std::net`), built on rustls with the `rustls-rustcrypto`
provider (no aws-lc-rs, no ring).

**`azos_tls`** (`userspace/lib/tls`):

- `client`: a client whose only trust is a list of pins, the SHA-256 of the
  server's SubjectPublicKeyInfo (`pin`, `verify`). There is no system CA store
  and no switch that adds one. A pin names a key, so a certificate can be
  renewed under the same key and the next key listed as a second pin.
- `rows`: the configuration, plain `key=value` rows (`host`, `addr`, `path`,
  `pin_1` ..., at most `MAX_PINS` pins, at least one). `addr` is a socket
  address; no DNS is involved.
- `server`: the other side of the same handshake.
- `http`: a minimal HTTP/1.0 GET over any byte stream, strict about truncation
  (a body that ends without `close_notify` or short of `Content-Length` is an
  error).
- `time`: `DeviceTime` returns no time until the system clock has been set, and
  no time means no handshake, rather than trusting a wrong clock.
- `remote` (feature `packages`): the package source of the installer
  (`HttpsRemote`). `pkgd` links it and `Packages::fetch` (`pkg fetch`) runs it;
  `tests/host/tls-tests` drives the installer's fetch over it against a pinned
  server on loopback.
- The program that links the crate registers the entropy hook for `getrandom`;
  the library cannot, because only one registration is allowed per binary.
  `userspace/services/pkgd/src/main.rs` and `userspace/lib/tls-probe/src/main.rs`
  show the hook.

**`azos_quic`** (`userspace/lib/quic`): QUIC (RFC 9000) for the transparent RPC
link, using the vendored `quinn-proto` state machine over `std::net::UdpSocket`.

- `identity` uses raw public keys (RFC 7250): the server holds an Ed25519 key
  it generates at start, and the client accepts the key it is shown after
  verifying the handshake signature with it. **TLS authenticates nobody here.**
  The RPC session inside the connection is Noise IK with the static keys the
  signed topology pins, so a peer that is not the pinned node never gets a
  session whatever it presents to QUIC. QUIC is asked for what Noise does not
  give datagrams: proof the other end can receive at its address, loss
  recovery, congestion control and flow control. Every frame is sealed twice,
  by QUIC's AEAD around Noise's.
- `pump` drives the connection, one frame per unidirectional stream.
- `relay` runs the stack as a separate process (`rpcquic`) so that `rpcsrv`,
  which is `no_std` and holds the lend rights on exported endpoints, keeps no
  network parser inside it. The relay's only authority is the network and the
  entropy pool; `rpcsrv` talks to it over UDP datagrams on this host's own
  address.

`userspace/lib/tls-probe` builds the same TLS and QUIC type graph as a program
and as a host test (a loopback handshake), so the stack can be exercised
without a network.

## DNS

Source: `crates/net/net/src/dns.rs`, `sdk/std/sys/net/connection/azos.rs`.

The resolver is a kernel-side function set in `azos_net::dns`:
`resolve_with_yield` (A record) and `resolve_aaaa_with_yield` (AAAA record), which
take the wait function the caller sleeps with. There is one outstanding query
at a time (a second caller waits its turn, for at most the query timeout,
`NET_DNS_TIMEOUT_MS`), a cache of `DNS_CACHE_SIZE` entries (one entry per name
and record type, kept five minutes whatever the record's TTL), and the server
address comes from DHCP (`set_dns_server`).

A response is accepted only if it answers the query in flight. The code checks
that:

- the query is active (an unsolicited response outside that window is
  discarded);
- the datagram comes from the server and port the query went to, and is
  addressed to the query's source port;
- the transaction id matches;
- the echoed question section equals the transmitted one byte for byte;
- the record type is the one asked for;
- the record's owner name is the name asked, compared without regard to ASCII
  case, or the target of a CNAME chain that starts at it. A chain is followed
  for at most `DNS_MAX_CNAME_HOPS` (8) links, so a loop or a longer chain gives
  no address, and a record for any other name in the answer is skipped.

The transaction id and the source port (a fresh port per query from
1024..=65535, never the mDNS port, the SNTP client port or a bound port) are
drawn from the entropy pool when it is seeded, otherwise from mixed runtime
counters, which resist blind guessing less well; the other checks carry the
weight in that case.

Ring 3 reaches the resolver through the kernel-hosted `Net` interface
(`azos_devif::net`, `endpoint = "net"`): `resolve` takes a name of up to 48
bytes and a family (A or AAAA) and answers one address. It needs `READ` and
waits for the answer, so it is not a real-time call. `TOOLBOX.ELF`'s `host` is
its caller, and the kernel's NTP client resolves the time server's name through
the same function. The same interface's `ntp_status` (toolbox `ntp`) reports
the SNTP client's state. `std::net` name lookup (`lookup_host`) answers
`Unsupported`: the std port does not call the interface, which is why the TLS and
QUIC configurations carry socket addresses rather than names.
