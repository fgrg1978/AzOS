// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_drv_bus`, reduced to the `I2cPort` the chip drivers
//! are given (`i2c_port`), over one scripted ADS1115 (S2's tests): a config write with OS set starts
//! a conversion of the written MUX, which reads "busy" for `busy_polls`
//! config reads and then latches that channel's result; the config readback
//! carries the written MUX, as the chip's does. Every transaction is counted,
//! and an optional hook runs after each one (the interleaving test lets
//! another thread's unit in there, if the driver's queue allows it).

pub mod i2c {
    use std::sync::Mutex;

    #[derive(Default, Clone, Debug)]
    pub struct Ads {
        /// No transaction is acknowledged.
        pub nak: bool,
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
        nak: false, busy_polls: 0, left: 0, cfg: 0, running: false, result: [0; 4], latched: 0, txns: 0,
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
            if a.nak {
                drop(a);
                after();
                return -1;
            }
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
            if a.nak {
                drop(a);
                after();
                return -1;
            }
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

pub mod i2c_port {
    use azos_devif::i2c::Bytes;
    use azos_devif::{outcome, Out};

    /// The chip's one device on one bus; the scripted chip answers whatever
    /// the bus and address.
    pub struct I2cPort;

    impl I2cPort {
        pub fn new(_bus: u8, _addr: u8) -> Self {
            I2cPort
        }
    }

    impl azos_devif::I2c for I2cPort {
        /// A refused read still carries what the chip would have said, so a
        /// caller that takes the bytes without the outcome code reads a
        /// plausible register.
        fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
            let mut buf = [0u8; 2];
            if len as usize != buf.len() {
                return Out::err(outcome::FAULT);
            }
            let nak = std::mem::take(&mut super::i2c::ADS.lock().unwrap().nak);
            let rc = super::i2c::i2c_read(0, 0, reg as u8, &mut buf);
            if nak {
                super::i2c::ADS.lock().unwrap().nak = true;
                return Out::new(outcome::FAULT, Bytes::from_slice(&buf));
            }
            if rc != 2 {
                return Out::err(outcome::FAULT);
            }
            Out::ok(Bytes::from_slice(&buf))
        }
        fn write(&mut self, data: Bytes) -> Out<()> {
            let mut buf = [0u8; 32];
            let n = data.copy_to(&mut buf);
            if super::i2c::i2c_write(0, 0, &buf[..n]) == 0 { Out::ok(()) } else { Out::err(outcome::FAULT) }
        }
        fn detect(&mut self) -> Out<u32> {
            Out::ok(1)
        }
    }
}
