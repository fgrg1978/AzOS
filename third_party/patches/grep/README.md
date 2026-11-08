# grep 0.4.1

ripgrep's facade crate (https://github.com/BurntSushi/ripgrep/tree/master/crates/grep,
Unlicense OR MIT) with the optional `pcre2` feature and its `grep-pcre2` dependency
removed, so the lockfile and the vendor tree carry no PCRE2 (a C library, which ripgrep
builds only with that feature). Everything else is the published crate; the manifest
drops the examples and dev-dependencies. Used through `[patch.crates-io]` in
`third_party/ports/ripgrep/Cargo.toml`.
