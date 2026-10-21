// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The toolbox's `log` (`userspace/services/toolbox/src/log_view.rs`): what it
//! shows and how it lays a line out. The file reading is system calls and is
//! covered by the testing week's boot (a `kerr!` line, then `log`).

use crate::log_view::{parse_level, render, Filter, RENDER_MAX};
use crate::wire::{self, Record, LINE_MAX};

fn parsed(level: u8, module: &str, msg: &[u8], ts: u64, flags: u8) -> Vec<u8> {
    let r = Record::make(7, ts, level, flags, 0, module, msg);
    let mut b = [0u8; LINE_MAX];
    let n = wire::line(&r, 1_000_000, &mut b);
    b[..n].to_vec()
}

fn shown(f: &Filter<'_>, line: &[u8]) -> bool {
    wire::parse(line).is_some_and(|l| f.accepts(&l))
}

#[test]
fn the_filter_keeps_by_level_and_module_and_hides_file_heads() {
    let f = Filter { max_level: wire::LEVEL_WARN, module: b"ipc" };
    assert!(shown(&f, &parsed(wire::LEVEL_ERR, "azos_ipc::trace", b"a", 0, 0)));
    assert!(shown(&f, &parsed(wire::LEVEL_WARN, "azos_ipc", b"a", 0, 0)));
    assert!(!shown(&f, &parsed(wire::LEVEL_INFO, "azos_ipc::trace", b"a", 0, 0)), "too chatty");
    assert!(!shown(&f, &parsed(wire::LEVEL_ERR, "azos_sched", b"a", 0, 0)), "another module");
    let all = Filter { max_level: wire::LEVEL_DEBUG, module: b"" };
    assert!(!shown(&all, &parsed(wire::LEVEL_INFO, "logd", b"file 3", 0, 0)), "the file's opening line is not a log line");
    assert!(shown(&all, &parsed(wire::LEVEL_WARN, "logd", b"records lost: 4", 0, 0)), "but a notice is");
    // Canary: drop the `head_serial` test and the opening line is shown (red).
}

#[test]
fn levels_parse_as_letters_words_and_numbers() {
    assert_eq!(parse_level(b"e"), Some(3));
    assert_eq!(parse_level(b"warn"), Some(4));
    assert_eq!(parse_level(b"i"), Some(6));
    assert_eq!(parse_level(b"7"), Some(7));
    for bad in [&b""[..], b"2", b"8", b"x", b"warning"] {
        assert_eq!(parse_level(bad), None, "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn a_line_is_laid_out_like_a_ring_buffer_dump() {
    let raw = parsed(wire::LEVEL_WARN, "azos_ipc::trace", b"[TRACE] op 4\tREFUSED\n", 1_234_567, 0);
    let l = wire::parse(&raw).unwrap();
    let mut out = [0u8; RENDER_MAX];
    let n = render(&l, &mut out);
    assert_eq!(&out[..n], b"[    1.234567] W ipc::trace: [TRACE] op 4\tREFUSED\n\n");
    let raw = parsed(wire::LEVEL_INFO, "", b"x", 123_456_789_000_000, wire::FLAG_PARTIAL);
    let n = render(&wire::parse(&raw).unwrap(), &mut out);
    assert_eq!(&out[..n], b"[123456789.000000] I+ x\n", "no module, a fragment, and a wide clock");
    // Canary: print `ts_us` without the six-digit pad and the first line goes red.
}

#[test]
fn a_hostile_line_cannot_overrun_the_layout() {
    // A module longer than the field and a message of escapes only: what the
    // writer never makes, a damaged file might hold.
    let mut text = b"1 2 3 E ".to_vec();
    text.extend(std::iter::repeat(b'm').take(300));
    text.push(b' ');
    text.extend(std::iter::repeat(b'\\').take(600));
    let l = wire::parse(&text).unwrap();
    let mut out = [0u8; RENDER_MAX];
    let n = render(&l, &mut out);
    assert!(n <= RENDER_MAX);
}

#[test]
fn the_files_are_read_oldest_serial_first() {
    let mut files = [(9u64, 0u8), (3, 5), (7, 2)];
    let order: Vec<u8> = crate::log_view::reading_order(&mut files).collect();
    assert_eq!(order, vec![5, 2, 0]);
}
