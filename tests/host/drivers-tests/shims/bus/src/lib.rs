// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_drv_bus`, reduced to `i2c::{i2c_read, i2c_write}`
//! over one scripted ADS1115 (S2's tests): a config write with OS set starts
//! a conversion of the written MUX, which reads "busy" for `busy_polls`
//! config reads and then latches that channel's result; the config readback
//! carries the written MUX, as the chip's does. Every transaction is counted,
//! and an optional hook runs after each one (the interleaving test lets
//! another thread's unit in there, if the driver's queue allows it).

pub mod i2c {
    use std::sync::Mutex;

    #[derive(Default, Clone, Debug)]
    pub struct Ads {
        /// Config-register reads that see a new conversion busy.
        pub busy_polls: u32,
        /// Busy reads left for the running conversion.
        pub left: u32,
        /// The last config word written.
        pub cfg: u16,
        /// A conversion was started and has not latched yet.
        pub running: bool,
        /// Conversion result per single-ended channel 0..3.
        pub result: [i16; 4],
        /// The result latched by the last finished conversion.
        pub latched: i16,
        /// I2C transactions (reads + writes).
        pub txns: u32,
    }

    pub static ADS: Mutex<Ads> = Mutex::new(Ads {
        busy_polls: 0, left: 0, cfg: 0, running: false, result: [0; 4], latched: 0, txns: 0,
    });
    /// Called after every transaction, outside the chip's lock.
    pub static HOOK: Mutex<Option<fn()>> = Mutex::new(None);

    fn after() {
        let h = *HOOK.lock().unwrap();
        if let Some(h) = h {
            h();
        }
    }

    pub fn i2c_write(_bus: u8, _addr: u8, data: &[u8]) -> i32 {
        {
            let mut a = ADS.lock().unwrap();
            a.txns += 1;
            if data.len() == 3 && data[0] == 0x01 {
                let v = (data[1] as u16) << 8 | data[2] as u16;
                a.cfg = v & 0x7FFF;
                if v & 0x8000 != 0 {
                    a.running = true;
                    a.left = a.busy_polls;
                }
            }
        }
        after();
        0
    }

    pub fn i2c_read(_bus: u8, _addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        let v = {
            let mut a = ADS.lock().unwrap();
            a.txns += 1;
            match reg {
                0x01 => {
                    if a.running && a.left > 0 {
                        a.left -= 1;
                        a.cfg
                    } else {
                        if a.running {
                            a.running = false;
                            a.latched = a.result[((a.cfg >> 12) & 0b11) as usize];
                        }
                        a.cfg | 0x8000
                    }
                }
                0x00 => a.latched as u16,
                _ => 0,
            }
        };
        buf[0] = (v >> 8) as u8;
        buf[1] = v as u8;
        after();
        2
    }
}
