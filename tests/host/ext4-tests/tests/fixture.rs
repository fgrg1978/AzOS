// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The volume the ring-3 ext4 QEMU rows boot (`tools/image/make_ext4_fixture.py`)
//! reads, here, as the rows expect: what `cat`, `wc` and `rg` will print.

use azos_ext4_tests::{list, mount, read_all};
use std::path::Path;
use std::process::Command;

#[test]
fn the_gate_volume_holds_what_the_rows_read() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fixture");
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("ext4-fixture.img");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/image/make_ext4_fixture.py");
    let out = Command::new("python3").arg(&script).arg(&img).output().expect("run make_ext4_fixture.py");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let bytes = std::fs::read(&img).unwrap();
    let mut v = mount(bytes).expect("the gate volume mounts");
    let i = v.resolve(b"hello.txt", true).unwrap();
    assert_eq!(read_all(&mut v, &i).unwrap(), b"hello from ext4\n");
    let i = v.resolve(b"lines.txt", true).unwrap();
    let text = read_all(&mut v, &i).unwrap();
    // `wc` on the row: 1000 lines, 3000 words, 15000 bytes.
    assert_eq!(text.len(), 15000);
    assert_eq!(text.iter().filter(|&&c| c == b'\n').count(), 1000);
    assert!(text.starts_with(b"ext4 line 0000\n") && text.ends_with(b"ext4 line 0999\n"));
    let i = v.resolve(b"deep/a/needle.txt", true).unwrap();
    assert_eq!(read_all(&mut v, &i).unwrap(), b"the needle is here\n");
    let i = v.resolve(b"link", true).unwrap();
    assert_eq!(read_all(&mut v, &i).unwrap(), b"hello from ext4\n");
    let many = v.resolve(b"many", true).unwrap();
    assert_eq!(many.flags & 0x1000, 0x1000, "e2fsck -D indexed it");
    assert_eq!(list(&mut v, &many).unwrap().len(), 300);
}
