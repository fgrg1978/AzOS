// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_config` (INI parser + runtime
//! atomic config).
//!
//! The config crate keeps its entries in a `static mut` table —
//! by design, because it's read by the kernel boot path before
//! the heap exists.  That means our tests share state, so each
//! one grabs `TEST_LOCK` and calls `cfg_load(b"")` first to start
//! from a clean table.

// W2-B5: the authority-checked-load tests live in their own file so they
// don't collide with concurrent edits to `mod tests` below.
#[cfg(test)]
mod signed_tests;

// W2-B5: `pub(crate)` on the module and on `TEST_LOCK` only (no test body
// touched) so `signed_tests.rs`'s tests — a separate file, so they don't
// collide with whoever else edits this `mod tests` block this wave — can
// share the SAME lock instead of racing it: this crate's tests all touch
// one `static mut` table inside `azos_config`, so two files with two
// independent locks would let a `signed_tests` test and a `tests` test run
// concurrently and corrupt each other's view of that table.
#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;
    use azos_config::{
        cfg_apply, cfg_count, cfg_get, cfg_get_i32, cfg_get_u32, cfg_load,
        cfg_serialize, cfg_set,
        unpack_ip, MAX_ENTRIES, MAX_KEY, MAX_VAL,
    };

    /// Tests touch a static-mut table inside `azos_config`, so
    /// they must run serialised.  Each test acquires this lock for
    /// its whole body.
    pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the global lock and reset the config table.
    /// Returns the lock guard the test must hold for its lifetime.
    fn fresh<'a>() -> std::sync::MutexGuard<'a, ()> {
        // `lock()` returns Err only if a previous holder panicked
        // while holding the lock; we recover via `into_inner` so a
        // single failing test doesn't poison every later test.
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cfg_load(b"").unwrap();
        g
    }

    // ── Pure helpers (no shared state, no lock needed) ─────────

    #[test]
    fn unpack_ip_be_order() {
        // Packed (a<<24)|(b<<16)|(c<<8)|d → [a, b, c, d].
        assert_eq!(unpack_ip(0xC0_A8_01_FE), [0xC0, 0xA8, 0x01, 0xFE]);
        assert_eq!(unpack_ip(0), [0, 0, 0, 0]);
        assert_eq!(unpack_ip(0xFFFF_FFFF), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // ── INI parser ─────────────────────────────────────────────

    #[test]
    fn loads_single_kv_pair() {
        let _g = fresh();
        cfg_load(b"name=value\n").unwrap();
        assert_eq!(cfg_get(b"name"), Some(b"value".as_slice()));
        assert_eq!(cfg_count(), 1);
    }

    #[test]
    fn loads_multiple_kv_pairs() {
        let _g = fresh();
        cfg_load(b"a=1\nb=2\nc=3\n").unwrap();
        assert_eq!(cfg_get(b"a"), Some(b"1".as_slice()));
        assert_eq!(cfg_get(b"b"), Some(b"2".as_slice()));
        assert_eq!(cfg_get(b"c"), Some(b"3".as_slice()));
        assert_eq!(cfg_count(), 3);
    }

    #[test]
    fn skips_blank_lines() {
        let _g = fresh();
        cfg_load(b"\n\nfoo=bar\n\n").unwrap();
        assert_eq!(cfg_get(b"foo"), Some(b"bar".as_slice()));
        assert_eq!(cfg_count(), 1);
    }

    #[test]
    fn skips_comments() {
        let _g = fresh();
        cfg_load(b"# this is a comment\nkey=val\n# another\n").unwrap();
        assert_eq!(cfg_get(b"key"), Some(b"val".as_slice()));
        assert_eq!(cfg_count(), 1);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let _g = fresh();
        cfg_load(b"k1=v1\r\nk2=v2\r\n").unwrap();
        assert_eq!(cfg_get(b"k1"), Some(b"v1".as_slice()));
        assert_eq!(cfg_get(b"k2"), Some(b"v2".as_slice()));
    }

    #[test]
    fn skips_lines_without_equals() {
        let _g = fresh();
        cfg_load(b"no_equals_here\nkey=val\n").unwrap();
        assert_eq!(cfg_get(b"key"), Some(b"val".as_slice()));
        assert_eq!(cfg_count(), 1);
    }

    #[test]
    fn skips_lines_with_empty_key() {
        let _g = fresh();
        cfg_load(b"=lonely_value\nkey=val\n").unwrap();
        assert_eq!(cfg_get(b"key"), Some(b"val".as_slice()));
        assert_eq!(cfg_count(), 1);
    }

    #[test]
    fn key_longer_than_max_is_truncated() {
        let _g = fresh();
        // 30-char key, MAX_KEY = 24 → truncated to 24.
        let mut line = Vec::new();
        for _ in 0..30 { line.push(b'x'); }
        line.push(b'=');
        line.extend_from_slice(b"v\n");
        cfg_load(&line).unwrap();
        let key_24 = vec![b'x'; MAX_KEY];
        assert_eq!(cfg_get(&key_24), Some(b"v".as_slice()),
            "first MAX_KEY ({}) bytes of key must round-trip", MAX_KEY);
    }

    #[test]
    fn value_longer_than_max_is_truncated() {
        let _g = fresh();
        // Derive the over-long length from MAX_VAL instead of hardcoding it.
        // This test asserted truncation with a literal 30 bytes, which stopped
        // being "longer than max" the moment MAX_VAL went 16 -> 48 and the
        // test failed for the wrong reason. Anything expressed in terms of a
        // tunable constant has to be written in terms of it.
        let mut line = b"k=".to_vec();
        for _ in 0..(MAX_VAL + 10) { line.push(b'V'); }
        line.push(b'\n');
        cfg_load(&line).unwrap();
        let want = vec![b'V'; MAX_VAL];
        assert_eq!(cfg_get(b"k"), Some(want.as_slice()),
            "a value longer than MAX_VAL ({}) must be cut to exactly MAX_VAL",
            MAX_VAL);
    }

    #[test]
    fn truncation_is_counted_not_silent() {
        let _g = fresh();
        // The cut itself is only half the contract. A silently truncated
        // value is a configuration nobody wrote, and the symptom shows up
        // somewhere unrelated -- a cut autorun path reads as "file not
        // found", a cut IP as an unreachable host. Boot warns off this
        // counter, so the counter has to actually move.
        let mut line = b"short=v\nlong=".to_vec();
        for _ in 0..(MAX_VAL + 1) { line.push(b'V'); }
        line.push(b'\n');
        cfg_load(&line).unwrap();
        assert_eq!(azos_config::cfg_truncated_count(), 1,
            "exactly the one over-long value must be counted");
    }

    #[test]
    fn value_of_exactly_max_is_not_counted_as_truncated() {
        let _g = fresh();
        // Boundary that bit us for real: /fat/GPIODRV.ELF and
        // /fat/SYSTEST.ELF are exactly 16 bytes and fit under the old
        // MAX_VAL by a single byte, while /fat/BRAINCLI.ELF (17) did not and
        // was silently cut to /fat/BRAINCLI.EL. A value of exactly MAX_VAL
        // must round-trip whole and must NOT be reported as truncated.
        let mut line = b"k=".to_vec();
        for _ in 0..MAX_VAL { line.push(b'V'); }
        line.push(b'\n');
        cfg_load(&line).unwrap();
        let want = vec![b'V'; MAX_VAL];
        assert_eq!(cfg_get(b"k"), Some(want.as_slice()));
        assert_eq!(azos_config::cfg_truncated_count(), 0,
            "a value of exactly MAX_VAL is not truncated");
    }

    #[test]
    fn entries_capped_at_max_entries() {
        let _g = fresh();
        let mut blob = Vec::new();
        for i in 0..(MAX_ENTRIES + 10) {
            // Keys k0, k1, ... k41.  All ≤ MAX_KEY.
            blob.extend_from_slice(format!("k{:02}=v\n", i).as_bytes());
        }
        cfg_load(&blob).unwrap();
        assert_eq!(cfg_count(), MAX_ENTRIES,
            "must stop at MAX_ENTRIES (={}), got {}",
            MAX_ENTRIES, cfg_count());
        // First entry kept, post-cap entry dropped.
        assert_eq!(cfg_get(b"k00"), Some(b"v".as_slice()));
        let beyond_cap = format!("k{:02}", MAX_ENTRIES);
        assert_eq!(cfg_get(beyond_cap.as_bytes()), None);
        // Dropping is half the contract: the 10 lines that did not fit must
        // be COUNTED, for the same reason a truncated value is. See
        // `a_key_pushed_out_of_the_table_is_reported`.
        assert_eq!(azos_config::cfg_dropped_count(), 10,
            "every line past MAX_ENTRIES is counted");
    }

    /// **A key that does not fit must not vanish quietly.**
    ///
    /// The shape that makes it matter: `autorun` is what the boot path asks
    /// for, and a CONFIG.INI whose first `MAX_ENTRIES` lines are something
    /// else pushes it out. A missing `autorun` then reads as "none
    /// configured" — a legitimate state — rather than "your file did not
    /// fit", so the symptom appears nowhere near its cause. Same failure the
    /// `MAX_VAL` truncation counter was added for, one level up.
    #[test]
    fn a_key_pushed_out_of_the_table_is_reported() {
        let _g = fresh();
        let mut blob = Vec::new();
        for i in 0..MAX_ENTRIES {
            blob.extend_from_slice(format!("pad{:02}=x\n", i).as_bytes());
        }
        blob.extend_from_slice(b"autorun=/fat/GPIODRV.ELF\n");
        cfg_load(&blob).unwrap();
        // The premise: it really was pushed out.
        assert_eq!(cfg_get(b"autorun"), None,
            "the table is full, so the last line cannot have been stored");
        // The contract: and boot can say so.
        assert_eq!(azos_config::cfg_dropped_count(), 1,
            "the dropped line is counted, so boot does not run a config \
             nobody wrote in silence");
    }

    /// A file that exactly fills the table reports nothing — so the counter
    /// cannot pass by reporting on every load.
    #[test]
    fn a_file_that_exactly_fills_the_table_drops_nothing() {
        let _g = fresh();
        let mut blob = Vec::new();
        for i in 0..MAX_ENTRIES {
            blob.extend_from_slice(format!("k{:02}=v\n", i).as_bytes());
        }
        cfg_load(&blob).unwrap();
        assert_eq!(cfg_count(), MAX_ENTRIES);
        assert_eq!(azos_config::cfg_dropped_count(), 0,
            "exactly MAX_ENTRIES entries drop nothing");
    }

    #[test]
    fn rtrim_strips_trailing_whitespace_from_key_and_val() {
        let _g = fresh();
        cfg_load(b"key   =  val   \n").unwrap();
        // Leading whitespace in value is NOT trimmed by this impl
        // (only trailing); pin behaviour so we notice if it changes.
        assert_eq!(cfg_get(b"key"), Some(b"  val".as_slice()));
    }

    // ── Typed getters ──────────────────────────────────────────

    #[test]
    fn cfg_get_u32_falls_back_to_default_when_missing() {
        let _g = fresh();
        assert_eq!(cfg_get_u32(b"absent", 42), 42);
    }

    #[test]
    fn cfg_get_u32_parses_decimal() {
        let _g = fresh();
        cfg_load(b"port=8080\nbig=4294967295\n").unwrap();
        assert_eq!(cfg_get_u32(b"port", 0), 8080);
        assert_eq!(cfg_get_u32(b"big", 0), u32::MAX);
    }

    #[test]
    fn cfg_get_u32_uses_default_on_non_numeric() {
        let _g = fresh();
        cfg_load(b"not_a_number=hello\n").unwrap();
        assert_eq!(cfg_get_u32(b"not_a_number", 7), 7);
    }

    #[test]
    fn cfg_get_i32_handles_negative() {
        let _g = fresh();
        cfg_load(b"offset=-123\npositive=456\n").unwrap();
        assert_eq!(cfg_get_i32(b"offset", 0), -123);
        assert_eq!(cfg_get_i32(b"positive", 0), 456);
    }

    // ── cfg_set ─────────────────────────────────────────────────

    #[test]
    fn cfg_set_inserts_new_key() {
        let _g = fresh();
        assert!(cfg_set(b"hello", b"world"));
        assert_eq!(cfg_get(b"hello"), Some(b"world".as_slice()));
    }

    #[test]
    fn cfg_set_updates_existing_key() {
        let _g = fresh();
        cfg_load(b"x=old\n").unwrap();
        assert!(cfg_set(b"x", b"new"));
        assert_eq!(cfg_get(b"x"), Some(b"new".as_slice()));
        assert_eq!(cfg_count(), 1, "update must not add a row");
    }

    #[test]
    fn cfg_set_rejects_oversized_key() {
        let _g = fresh();
        let huge = vec![b'k'; MAX_KEY + 1];
        assert!(!cfg_set(&huge, b"v"));
    }

    #[test]
    fn cfg_set_rejects_oversized_value() {
        let _g = fresh();
        let huge = vec![b'v'; MAX_VAL + 1];
        assert!(!cfg_set(b"k", &huge));
    }

    // ── Round-trip via cfg_serialize ───────────────────────────

    #[test]
    fn serialize_then_reload_round_trips() {
        let _g = fresh();
        cfg_load(b"a=1\nb=hello\nc=42\n").unwrap();
        let mut buf = [0u8; 256];
        let n = cfg_serialize(&mut buf);
        assert!(n > 0);

        // Reload from the serialised form and check all three keys
        // survived.
        let serialised = &buf[..n];
        cfg_load(serialised).unwrap();
        assert_eq!(cfg_get(b"a"), Some(b"1".as_slice()));
        assert_eq!(cfg_get(b"b"), Some(b"hello".as_slice()));
        assert_eq!(cfg_get(b"c"), Some(b"42".as_slice()));
    }

    // ── cfg_apply IP parsing ───────────────────────────────────

    #[test]
    fn cfg_apply_parses_dotted_ip_into_atomic() {
        use azos_config::BEHAVIOR_SERVER_IP;
        use std::sync::atomic::Ordering;
        let _g = fresh();
        cfg_load(b"behavior_server_ip=192.168.1.254\n").unwrap();
        cfg_apply();
        let packed = BEHAVIOR_SERVER_IP.load(Ordering::Acquire);
        assert_eq!(unpack_ip(packed), [192, 168, 1, 254]);
    }

    #[test]
    fn cfg_apply_skips_malformed_ip() {
        use azos_config::BEHAVIOR_SERVER_IP;
        use std::sync::atomic::Ordering;
        let _g = fresh();
        // First load a known-good IP so we can see whether the
        // malformed one overwrites it.
        cfg_load(b"behavior_server_ip=10.0.0.1\n").unwrap();
        cfg_apply();
        let baseline = BEHAVIOR_SERVER_IP.load(Ordering::Acquire);
        assert_eq!(unpack_ip(baseline), [10, 0, 0, 1]);

        // Now load garbage. Impl must silently keep the baseline.
        cfg_load(b"behavior_server_ip=not.an.ip.address\n").unwrap();
        cfg_apply();
        let after = BEHAVIOR_SERVER_IP.load(Ordering::Acquire);
        assert_eq!(unpack_ip(after), [10, 0, 0, 1],
            "malformed IP must not clobber the previous value");
    }

    // ── Q4.2 (owner decision, 2026-09-25): CONFIG.INI may only LOWER
    // sched_hz below the Kconfig compile-time default, never raise it,
    // and never below SCHED_HZ_FLOOR. `resolve_sched_hz` is a pure
    // function (no shared static, no lock needed) so the kernel boot
    // path and these tests exercise the exact same clamp logic. ────────

    #[test]
    fn sched_hz_above_default_is_clamped_down_and_flagged() {
        use azos_config::resolve_sched_hz;
        // CONFIG.INI on the removable FAT volume asks for 2000 Hz; the
        // board's compiled-in ceiling is 100 Hz. Must not be honoured.
        let r = resolve_sched_hz(2000, 100, 10);
        assert_eq!(r.effective, 100,
            "removable media must not be able to RAISE sched_hz above the \
             compile-time default");
        assert!(r.clamped);
        assert_eq!(r.requested, 2000);
    }

    #[test]
    fn sched_hz_below_default_but_in_range_is_accepted() {
        use azos_config::resolve_sched_hz;
        let r = resolve_sched_hz(50, 100, 10);
        assert_eq!(r.effective, 50, "a value below the default, but still \
            within the declared range, is the whole point of the knob");
        assert!(!r.clamped);
    }

    #[test]
    fn sched_hz_below_floor_is_rejected_to_default() {
        use azos_config::resolve_sched_hz;
        // Below SCHED_HZ_FLOOR is garbage (e.g. an operator typo), not a
        // deliberate slow-tick request -- fall back to the compile-time
        // default rather than honouring a value nothing was validated for.
        let r = resolve_sched_hz(0, 100, 10);
        assert_eq!(r.effective, 100);
        assert!(r.clamped);

        let r2 = resolve_sched_hz(3, 100, 10);
        assert_eq!(r2.effective, 100);
        assert!(r2.clamped);
    }

    #[test]
    fn sched_hz_equal_to_default_is_accepted_unclamped() {
        use azos_config::resolve_sched_hz;
        let r = resolve_sched_hz(100, 100, 10);
        assert_eq!(r.effective, 100);
        assert!(!r.clamped);
    }

    #[test]
    fn sched_hz_equal_to_floor_is_accepted_unclamped() {
        use azos_config::resolve_sched_hz;
        let r = resolve_sched_hz(10, 100, 10);
        assert_eq!(r.effective, 10);
        assert!(!r.clamped);
    }

    /// End-to-end through the real CONFIG.INI parser (not `resolve_sched_hz`
    /// called with hand-picked literals): a non-numeric `sched_hz` value is
    /// garbage and must fall back to the compile-time default, exactly the
    /// same as an absent key -- `cfg_get_u32`'s own fallback already does
    /// this before `resolve_sched_hz` ever runs.
    #[test]
    fn sched_hz_non_numeric_ini_value_falls_back_through_the_real_parser() {
        use azos_config::{cfg_get_u32, resolve_sched_hz};
        let _g = fresh();
        let compile_default = 100u32;
        let floor = 10u32;

        cfg_load(b"sched_hz=not-a-number\n").unwrap();
        let requested = cfg_get_u32(b"sched_hz", compile_default);
        assert_eq!(requested, compile_default,
            "cfg_get_u32 must already fall back to the compile-time default \
             on a non-numeric CONFIG.INI value");
        let r = resolve_sched_hz(requested, compile_default, floor);
        assert_eq!(r.effective, compile_default);
        assert!(!r.clamped, "falling back to the default via cfg_get_u32 is \
            not itself a clamp -- resolve_sched_hz never saw a deviant value");
    }

    /// Same real-parser path, but the value IS numeric and above the
    /// compile-time ceiling: this is the one `resolve_sched_hz` itself must
    /// catch, end to end.
    #[test]
    fn sched_hz_ini_value_above_default_is_clamped_through_the_real_parser() {
        use azos_config::{cfg_get_u32, resolve_sched_hz};
        let _g = fresh();
        let compile_default = 100u32;
        let floor = 10u32;

        cfg_load(b"sched_hz=2000\n").unwrap();
        let requested = cfg_get_u32(b"sched_hz", compile_default);
        assert_eq!(requested, 2000, "a numeric value parses through untouched");
        let r = resolve_sched_hz(requested, compile_default, floor);
        assert_eq!(r.effective, compile_default);
        assert!(r.clamped);
    }

    // ── Repeated keys (wave 11, HERM) ──────────────────────────

    /// A key on two lines is an error and nothing is stored. Until wave 11 the
    /// first line won and the second was dropped without a word.
    #[test]
    fn a_repeated_key_is_refused() {
        use azos_config::CfgError;
        let _g = fresh();
        let err = cfg_load(b"a=1\nautorun=/fat/A.ELF\nb=2\nautorun=/fat/B.ELF\n")
            .expect_err("two `autorun` lines must be an error");
        assert!(matches!(err, CfgError::DuplicateKey { .. }));
        assert_eq!(err.key(), b"autorun", "the error names the repeated key");
        assert_eq!(cfg_count(), 0, "a refused file stores nothing");
        assert_eq!(cfg_get(b"a"), None, "not even the lines before the repeat");
    }

    /// Same value twice is still a repeat (it is the same mistake), and so is
    /// a repeat that differs only in the whitespace around the key.
    #[test]
    fn a_repeat_with_the_same_value_or_padding_is_refused() {
        let _g = fresh();
        assert!(cfg_load(b"x=1\nx=1\n").is_err());
        assert!(cfg_load(b"x=1\n  x   =2\n").is_err());
        assert!(cfg_load(b"x=1\r\ny=2\r\nx=3\r\n").is_err());
    }

    /// Two keys longer than MAX_KEY that agree on their first MAX_KEY bytes are
    /// stored identically, so `cfg_get` would answer for the first of them.
    #[test]
    fn keys_that_collide_after_truncation_are_a_repeat() {
        let _g = fresh();
        let a = format!("{}A=1\n", "k".repeat(MAX_KEY));
        let b = format!("{}B=2\n", "k".repeat(MAX_KEY));
        let both = format!("{a}{b}");
        assert!(cfg_load(both.as_bytes()).is_err());
    }

    /// The control: distinct keys, including one that is a prefix of another
    /// and one that only differs in case, load as before.
    #[test]
    fn distinct_keys_still_load() {
        let _g = fresh();
        cfg_load(b"net_ip=1\nnet_ip2=2\nNET_IP=3\nnet=4\n").unwrap();
        assert_eq!(cfg_count(), 4);
        assert_eq!(cfg_get(b"net_ip"), Some(b"1".as_slice()));
        assert_eq!(cfg_get(b"net_ip2"), Some(b"2".as_slice()));
        assert_eq!(cfg_get(b"NET_IP"), Some(b"3".as_slice()));
        assert_eq!(cfg_get(b"net"), Some(b"4".as_slice()));
    }

    /// A refused file leaves the running configuration as it was, so a failed
    /// `config load` cannot leave a half-loaded or emptied store behind.
    #[test]
    fn a_refused_load_keeps_the_previous_configuration() {
        let _g = fresh();
        cfg_load(b"keep=me\nn=7\n").unwrap();
        assert!(cfg_load(b"keep=other\nkeep=again\nnew=1\n").is_err());
        assert_eq!(cfg_count(), 2);
        assert_eq!(cfg_get(b"keep"), Some(b"me".as_slice()));
        assert_eq!(cfg_get_u32(b"n", 0), 7);
        assert_eq!(cfg_get(b"new"), None);
    }

    /// A repeat among lines that would be dropped past MAX_ENTRIES is still a
    /// repeat: the file is ambiguous whether or not the table has room.
    #[test]
    fn a_repeat_past_the_table_is_still_refused() {
        let _g = fresh();
        let mut blob = Vec::new();
        for i in 0..MAX_ENTRIES {
            blob.extend_from_slice(format!("pad{:02}=x\n", i).as_bytes());
        }
        blob.extend_from_slice(b"late=1\nlate=2\n");
        assert!(cfg_load(&blob).is_err());
    }
}
