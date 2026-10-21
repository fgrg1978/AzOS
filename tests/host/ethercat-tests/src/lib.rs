// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_ethercat`.
//!
//! `model` is a scripted slave chain (reusable by the cyclic master's tests);
//! `Harness` plays the master's side of one exchange over it.

#[cfg(test)]
mod model;
#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod reg_tests;
#[cfg(test)]
mod al_tests;
#[cfg(test)]
mod dc_tests;
#[cfg(test)]
mod process_tests;

#[cfg(test)]
mod harness {
    use super::model::Bus;
    use azos_ethercat::al::{Bringup, BringupError, Step};
    use azos_ethercat::frame::{self, Addr, Cmd, FrameBuilder, BROADCAST_MAC};

    pub const MASTER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    pub struct Harness {
        pub bus: Bus,
        pub now: u64,
        idx: u8,
    }

    impl Harness {
        pub fn new(bus: Bus) -> Harness {
            Harness { bus, now: 1_000_000, idx: 0 }
        }

        /// One datagram in one frame; returns the working counter and the data
        /// as the last slave left it. The index must come back unchanged.
        pub fn single(&mut self, cmd: Cmd, addr: Addr, data: &[u8]) -> (u16, Vec<u8>) {
            let mut buf = [0xAAu8; frame::MAX_FRAME];
            let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, MASTER_MAC).unwrap();
            self.idx = self.idx.wrapping_add(1);
            fb.push(cmd, self.idx, addr, data).unwrap();
            let len = fb.finish().unwrap();
            self.bus.exchange(&mut buf, len, self.now);
            self.now += 1_000_000;
            let f = frame::parse(&buf[..len]).unwrap();
            let mut it = f.datagrams();
            let d = it.next().unwrap().unwrap();
            assert!(it.next().is_none());
            assert_eq!((d.cmd, d.idx), (cmd, self.idx));
            (d.wkc, d.data.to_vec())
        }

        /// Drive a bring-up to its end; returns the number of exchanges.
        pub fn run(&mut self, b: &mut Bringup) -> Result<usize, BringupError> {
            let before = self.bus.frames;
            for _ in 0..10_000 {
                match b.request() {
                    Step::Send(r) => {
                        let (wkc, data) = self.single(r.cmd, r.addr, r.data());
                        b.on_reply(wkc, &data);
                    }
                    Step::Done => return Ok(self.bus.frames - before),
                    Step::Failed(e) => return Err(e),
                }
            }
            panic!("bring-up did not terminate");
        }

        /// Give slave `i` the station address `base + i`, by position.
        pub fn assign_stations(&mut self, base: u16) {
            for i in 0..self.bus.slaves.len() as u16 {
                let (wkc, _) = self.single(Cmd::Apwr, Addr::position(i, azos_ethercat::reg::STATION_ADDR), &(base + i).to_le_bytes());
                assert_eq!(wkc, 1);
            }
        }
    }
}
