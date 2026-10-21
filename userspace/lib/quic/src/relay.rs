// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The relay between `rpcsrv`'s datagrams and the QUIC connection.
//!
//! `rpcsrv` is a `no_std` program that holds the lend rights on the endpoints its
//! row exports, and a QUIC stack with its TLS handshake is the largest parser of
//! network input in the system: it does not belong in that process. The relay is
//! that stack as a separate ring-3 process (`rpcquic`, the program around
//! [`run`]) whose only authority is the network and the entropy pool. `rpcsrv`
//! sends each frame as a UDP datagram to the relay on this host, the relay carries it to the peer's
//! relay on a QUIC stream of its own ([`crate::pump`]), and the peer's relay hands
//! it to the peer's `rpcsrv` the same way. The frames are sealed by the RPC
//! session (Noise IK, keys the topology pins) before they reach the relay, so a
//! relay can drop, delay or repeat them and cannot read or forge one.
//!
//! The relay answers one `rpcsrv` address only. When the QUIC connection is lost
//! it cannot tell `rpcsrv` (a datagram that is not a frame is dropped by the
//! engine), so the engine's own probes break the session. (Telling the engine at
//! once would take the QUIC stack into `rpcsrv`, which is what the relay keeps out.)
//!
//! The stack delivers a datagram sent to the host's own address to the socket bound
//! at the port (it has no 127.0.0.0/8), so `rpcsrv` and the relay address each
//! other at [`own_ip`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::pump::{Event, Pump, Role, Settings, FRAME_MAX};

/// What the relay connects.
pub struct Relay {
    /// The socket `rpcsrv` sends its frames to (bound on this host's own address).
    pub local: UdpSocket,
    /// The only address frames are accepted from and handed to: `rpcsrv`'s socket.
    pub rpcsrv: SocketAddr,
    /// Where the QUIC endpoint is bound.
    pub quic: SocketAddr,
    /// Which end of the QUIC connection this is.
    pub role: Role,
    /// The connection's settings.
    pub settings: Settings,
}

/// This host's address on the way to `toward`; unspecified (`0.0.0.0`) while the
/// stack has none yet (no lease). A UDP socket connected to `toward` names it
/// without sending anything.
pub fn own_ip(toward: SocketAddr) -> io::Result<IpAddr> {
    let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    probe.connect(toward)?;
    Ok(probe.local_addr()?.ip())
}

/// Run the relay until `stop` is set. `log` gets a line when the connection
/// changes state.
pub fn run(relay: Relay, stop: &AtomicBool, mut log: impl FnMut(&str)) -> io::Result<()> {
    let Relay { local, rpcsrv, quic, role, settings } = relay;
    let (mut pump, sender) = Pump::bind(quic, role, settings)?;
    log(&format!("QUIC endpoint at {}", pump.local_addr()?));
    local.set_read_timeout(Some(Duration::from_millis(50)))?;
    let local = &local;
    std::thread::scope(|scope| {
        // rpcsrv -> the connection: its own thread, blocking on the local socket.
        scope.spawn(|| {
            let mut buf = [0u8; FRAME_MAX + 1];
            while !stop.load(Ordering::Relaxed) {
                // A datagram from any other address is not rpcsrv's; one too large is not a frame.
                if let Ok((n, from)) = local.recv_from(&mut buf) {
                    if from == rpcsrv && n <= FRAME_MAX {
                        // A refused frame is a lost datagram, which the engine resends.
                        let _ = sender.send(&buf[..n]);
                    }
                }
            }
        });
        // The connection -> rpcsrv, and the connection itself.
        let mut result = Ok(());
        while !stop.load(Ordering::Relaxed) {
            if let Err(e) = pump.drive(Duration::from_millis(1)) {
                result = Err(e);
                break;
            }
            while let Some(ev) = pump.pop() {
                match ev {
                    Event::Frame(f) => {
                        let _ = local.send_to(&f, rpcsrv);
                    }
                    Event::Up => log("connection up"),
                    Event::Down => log("connection lost"),
                }
            }
        }
        // Stop the reader too, whatever ended the loop.
        stop.store(true, Ordering::Relaxed);
        pump.close();
        result
    })
}
