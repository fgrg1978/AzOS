// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `rpcquic`: the QUIC leg of the RPC link, as a std program of its own (see
//! `azos_quic::relay` for what it is and why `rpcsrv` does not hold it).
//!
//! It takes no arguments: a topology row starts it with none, and Kconfig is the
//! only configuration (`azos_limits`, the same constants `rpcsrv` reads). The node
//! with the lower id (`RPC_NODE_ID` against `RPC_PEER_NODE`) dials
//! `RPC_PEER_ADDR:RPC_QUIC_PORT`, as it does for the Noise session; the other
//! listens on `RPC_QUIC_PORT` for `RPC_PEER_ADDR`. The relay binds
//! `RPC_QUIC_RELAY_PORT` and answers `rpcsrv` (`RPC_UDP_PORT`) on this host's
//! own address only. Entropy is the kernel pool through the std port's random
//! source, so the program's row needs the `entropy` interface and the network.

#![cfg_attr(target_os = "azos", feature(random))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use azos_quic::relay::{self, Relay};
use azos_quic::{Identity, Role, Settings};

#[cfg(target_os = "azos")]
mod azos_random {
    use std::random::{DefaultRandomSource, RandomSource};

    /// getrandom 0.2's custom backend (rand_core 0.6, the provider's keys): the std port's random source, the kernel pool.
    fn kernel_pool(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
        DefaultRandomSource.fill_bytes(buf);
        Ok(())
    }
    getrandom02::register_custom_getrandom!(kernel_pool);

    /// getrandom 0.4's `custom` backend (`--cfg getrandom_backend="custom"`, rand 0.10, quinn-proto) calls this symbol.
    ///
    /// # Safety
    /// `dest` points to `len` writable bytes, which getrandom guarantees.
    #[no_mangle]
    pub unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom04::Error> {
        DefaultRandomSource.fill_bytes(std::slice::from_raw_parts_mut(dest, len));
        Ok(())
    }
}

fn run() -> Result<(), String> {
    use azos_limits as cfg;
    if !cfg::RPC_QUIC {
        return Err("RPC_QUIC is off: nothing to relay".into());
    }
    let peer: Ipv4Addr = cfg::RPC_PEER_ADDR.parse().map_err(|e| format!("RPC_PEER_ADDR {:?}: {e}", cfg::RPC_PEER_ADDR))?;
    let quic_port = cfg::RPC_QUIC_PORT as u16;
    // The stack may still be coming up (no lease): the address names this host to rpcsrv.
    let own = loop {
        match relay::own_ip(SocketAddr::new(IpAddr::V4(peer), quic_port)) {
            Ok(ip) if !ip.is_unspecified() => break ip,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let dial = (cfg::RPC_NODE_ID as u32) < cfg::RPC_PEER_NODE as u32;
    let role = if dial {
        Role::Dial { remote: SocketAddr::new(IpAddr::V4(peer), quic_port) }
    } else {
        Role::Listen { peer: IpAddr::V4(peer), identity: Identity::generate().map_err(|e| e.to_string())? }
    };
    let local = UdpSocket::bind(SocketAddr::new(own, cfg::RPC_QUIC_RELAY_PORT as u16)).map_err(|e| format!("bind the relay port: {e}"))?;
    println!(
        "[rpcquic] {} {peer}:{quic_port}, relay {own}:{} <-> rpcsrv {own}:{}",
        if dial { "dial" } else { "listen" },
        cfg::RPC_QUIC_RELAY_PORT,
        cfg::RPC_UDP_PORT
    );
    let relay = Relay {
        local,
        rpcsrv: SocketAddr::new(own, cfg::RPC_UDP_PORT as u16),
        quic: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), quic_port),
        role,
        settings: Settings::default(),
    };
    relay::run(relay, &AtomicBool::new(false), |line| println!("[rpcquic] {line}")).map_err(|e| format!("socket: {e}"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[rpcquic] {e}");
        std::process::exit(2);
    }
}
