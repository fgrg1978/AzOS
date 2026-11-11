// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Statistics the class drivers bump once per transfer, interval or frame
//! must not abort a kernel built with overflow checks after days of traffic:
//! none of them uses a plain `+= 1`.

use std::path::Path;

#[test]
fn per_transfer_counters_saturate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../crates/drivers/usb/src/class");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&root).expect("class directory") {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let l = line.trim_start();
            if l.starts_with("self.stats.") && l.contains(" += ") {
                bad.push(format!("{}:{}: {}", path.file_name().unwrap().to_string_lossy(), n + 1, l));
            }
        }
    }
    assert!(bad.is_empty(), "plain += on a statistics field:\n{}", bad.join("\n"));
}
