# Ported programs

Upstream sources of the programs ported to the native SDK std target
(`*-unknown-azos`), one directory per crate, each a standalone cargo package
(`[workspace]` in its manifest) with its own `Cargo.lock`. Their registry
dependencies are in `third_party/vendor` (`userspace/lib/tls-probe/vendor.py`).

| Directory | Upstream | Version | Licence |
|---|---|---|---|
| `ripgrep` | https://github.com/BurntSushi/ripgrep (`rg`) | 15.2.0 | Unlicense OR MIT |
| `fd-find` | https://github.com/sharkdp/fd (`fd`) | 10.5.2 | MIT OR Apache-2.0 |
| `kibi` | https://github.com/ilai-deutel/kibi | 0.3.3 | MIT OR Apache-2.0 |

The files are the crates.io packages with these changes, none of which touches
a source file:

- tests, docs, benchmarks, scripts and changelogs are not kept;
- `[dev-dependencies]` and `[[test]]` are removed, so test-only crates are not vendored;
- ripgrep: `build = false` and `build.rs` removed (it ran `git rev-parse` in the
  working directory and would have embedded this repository's commit; the
  version string falls back to no hash), and the musl-only `tikv-jemallocator`
  dependency removed (a C allocator);
- fd-find: `[features]` (`use-jemalloc`, `completions`) and the optional
  `tikv-jemallocator` and `clap_complete` dependencies removed, which is
  `--no-default-features`;
- an empty `[workspace]` table, so cargo does not merge the package into the kernel workspace;
- `Cargo.lock` is resolved with the latest releases, then lowered with
  `cargo update --precise` to the versions already in `third_party/vendor`
  where the requirements allow (`libc`, `memchr`, `cc`, `find-msvc-tools`).

Changes to sources are in later commits, each with the reason.

## Source changes for `*-unknown-azos`

The target has no `unix` and no `windows` cfg. Each change is the smallest one that
makes the program build there; `make ports` builds all three for the three ISAs.

- ripgrep: no source change (it builds as published; `memmap2` falls back to its stub). The `pcre2` feature
  is gone from its manifest and `grep` is taken from `third_party/patches/grep` (the same crate
  without the optional PCRE2 engine), so no C library is in the lock or the vendor tree. The
  release profile has `debug = 0`, `strip` and `panic = "abort"` instead of `debug = 1`.
- fd-find: `ctrlc` (signal handlers) is a dependency of `cfg(any(unix, windows))` and
  its one call in `src/walk.rs` has the same cfg; the device-type probes in
  `src/filesystem.rs` (`is_block_device` and the other three) answer `false` on every
  target that is neither unix nor redox, where upstream had only a windows arm;
  `one_file_system` is `false` where the flag does not exist (`src/main.rs`).
- kibi: `src/azos.rs`, the terminal backend selected by `target_os = "azos"`
  (`src/lib.rs`, which also enables the `azos_ext` feature there), shaped like `wasi.rs`.
  The shell lends a foreground job a terminal of its own: a call capability on the
  terminal server, badged with the job, which `SYS_SPAWN_EX` moves in as fd 0 into a row
  that `receives = ["term"]`. `enable_raw_mode`, the restore and the window size go
  through `std::os::azos::terminal`, and `stdin` is `std::io::stdin`, which the port
  layer reads through that capability (`azos_stdrt::terminal`). There is no resize signal.

## On the system volume

`rg` and `fd` are images of the system volume and of the shell volumes (Kconfig
`USERSPACE_RG`, `USERSPACE_FD`, on by default for the desktop and server presets), with a
row each in the built-in topology (the read-only root directory and the `entropy` interface),
a seccomp row (`crates/core/sched/src/seccomp.rs`) and boot rows (`sh: rg finds a string in a
file`, `sh: fd lists a directory`, each with a canary). They read through `std::fs`
(`sdk/std/sys/fs/azos.rs`), which names every path beneath the task's root `Cap<Dir>`.

`kibi` is an image too (Kconfig `USERSPACE_KIBI`, the same presets). Its row holds the
shell's write trees (only `/tmp` under the console lockdown), the root directory and the
`entropy` interface, and `receives = ["term"]`: no right on the terminal of its own. The
terminal server answers the job's badge only while the job has the focus, and when the shell
takes the focus back it revokes the badge and puts the shell's mode back, so an editor
stopped in raw mode leaves a cooked terminal. Its boot rows (`sh: kibi edits and saves a
file`, and the canary whose terminal server leaves the mode behind) are arm-phase rows
(`CI_KIBI=1`).
