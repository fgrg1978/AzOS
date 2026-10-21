// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Links rustls (rustls-rustcrypto provider) and quinn-proto into a std program
//! for `*-unknown-azos` and runs them: the first flight of a TLS 1.3 client, a
//! full client-to-server handshake over memory (certificate chain verified,
//! application data echoed), and the QUIC transport types.
//!
//! With `tls-probe <ip:port> [server-name]` it also dials a TLS server over a
//! `TcpStream` (the std port's sockets), handshakes against it with the test CA
//! as the only trust anchor and prints the first line of the reply; that is the
//! first on-device check of the whole path (socket, clock, rustls) for the
//! testing week. Entropy is the kernel pool: getrandom 0.2 (rand_core's `OsRng`,
//! used by the provider) and getrandom 0.4 (quinn-proto) both reach it through
//! the std port's random source, so the program's row needs the `entropy`
//! capability.

#![cfg_attr(target_os = "azos", feature(random))]

use std::io::Write;
use std::net::{SocketAddr, TcpStream};

use tls_probe::{quic, tls};

#[cfg(target_os = "azos")]
mod azos_random {
    use std::random::{DefaultRandomSource, RandomSource};

    /// getrandom 0.2's custom backend: the std port's random source, the kernel pool behind the `entropy` capability.
    fn kernel_pool(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
        DefaultRandomSource.fill_bytes(buf);
        Ok(())
    }
    getrandom02::register_custom_getrandom!(kernel_pool);

    /// getrandom 0.4's `custom` backend (`--cfg getrandom_backend="custom"`) calls this symbol.
    ///
    /// # Safety
    /// `dest` points to `len` writable bytes, which getrandom guarantees.
    #[no_mangle]
    pub unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom04::Error> {
        DefaultRandomSource.fill_bytes(std::slice::from_raw_parts_mut(dest, len));
        Ok(())
    }
}

fn first_flight() -> Result<usize, String> {
    use rustls::pki_types::ServerName;
    use rustls::ClientConnection;
    let config = tls::client_config(std::sync::Arc::new(tls::FixedTime)).map_err(|e| format!("client config: {e}"))?;
    let name = ServerName::try_from(tls::SERVER_NAME).map_err(|e| format!("server name: {e}"))?;
    let mut conn = ClientConnection::new(config, name).map_err(|e| format!("connection: {e}"))?;
    let mut flight = Vec::new();
    conn.write_tls(&mut flight).map_err(|e| format!("write_tls: {e}"))?;
    Ok(flight.len())
}

fn dial(addr: &str, name: &str) -> Result<String, String> {
    let addr: SocketAddr = addr.parse().map_err(|e| format!("address {addr}: {e}"))?;
    let mut sock = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let reply = tls::fetch(&mut sock, name, b"GET / HTTP/1.0\r\n\r\n", 4096, std::sync::Arc::new(tls::DeviceTime)).map_err(|e| format!("tls: {e}"))?;
    let _ = sock.flush();
    Ok(String::from_utf8_lossy(&reply).lines().next().unwrap_or("").to_owned())
}

fn main() {
    println!("tls-probe: clock {}", if tls::clock_is_set() { "set" } else { "not set (1970 + uptime): certificate checks at the device's time will fail" });
    match first_flight() {
        Ok(n) => println!("tls-probe: ClientHello {n} bytes"),
        Err(e) => println!("tls-probe: first flight: {e}"),
    }
    match tls::self_test(b"azos tls-probe loopback") {
        Ok(o) => println!("tls-probe: loopback handshake ok: {o}"),
        Err(e) => println!("tls-probe: loopback handshake FAILED: {e}"),
    }
    println!("tls-probe: quic {}", quic::config_summary());
    let args: Vec<String> = std::env::args().collect();
    if let Some(addr) = args.get(1) {
        let name = args.get(2).map_or(tls::SERVER_NAME, String::as_str);
        match dial(addr, name) {
            Ok(line) => println!("tls-probe: {addr}: {line}"),
            Err(e) => println!("tls-probe: {addr}: {e}"),
        }
    }
}
