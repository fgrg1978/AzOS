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
