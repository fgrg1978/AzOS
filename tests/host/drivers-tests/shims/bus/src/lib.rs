// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_drv_bus`, reduced to `i2c::{i2c_read, i2c_write}`
//! over one scripted ADS1115 (S2's pipeline test): a conversion started by a
//! config write with OS set reads "busy" for `busy_polls` config reads, then
//! ready; every transaction is counted. Per thread, so tests run in parallel.

pub mod i2c {
    use std::cell::RefCell;

    #[derive(Default, Clone, Debug)]
    pub struct Ads {
        /// Config-register reads that still see the conversion busy.
        pub busy_polls: u32,
        /// Busy reads left for the running conversion.
        pub left: u32,
        /// The channel's MUX of the last started conversion, if any.
        pub started_mux: Option<u16>,
        /// Conversion result per single-ended channel 0..3.
        pub result: [i16; 4],
        /// The result latched by the last finished conversion.
        pub latched: i16,
        /// I2C transactions (reads + writes).
        pub txns: u32,
        /// Config writes that started a conversion.
        pub starts: u32,
    }

    thread_local! {
        pub static ADS: RefCell<Ads> = RefCell::new(Ads::default());
    }

    fn finish(a: &mut Ads) {
        if let Some(m) = a.started_mux.take() {
            a.latched = a.result[((m >> 12) & 0b11) as usize];
        }
    }

    pub fn i2c_write(_bus: u8, _addr: u8, data: &[u8]) -> i32 {
        ADS.with(|a| {
            let mut a = a.borrow_mut();
            a.txns += 1;
            if data.len() == 3 && data[0] == 0x01 {
                let v = (data[1] as u16) << 8 | data[2] as u16;
                if v & 0x8000 != 0 {
                    a.started_mux = Some(v & 0x7000);
                    a.left = a.busy_polls;
                    a.starts += 1;
                }
            }
        });
        0
    }

    pub fn i2c_read(_bus: u8, _addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        ADS.with(|a| {
            let mut a = a.borrow_mut();
            a.txns += 1;
            let v: u16 = match reg {
                0x01 => {
                    if a.started_mux.is_some() && a.left > 0 {
                        a.left -= 1;
                        0x0000
                    } else {
                        finish(&mut a);
                        0x8000
                    }
                }
                0x00 => a.latched as u16,
                _ => 0,
            };
            buf[0] = (v >> 8) as u8;
            buf[1] = v as u8;
        });
        2
    }
}
