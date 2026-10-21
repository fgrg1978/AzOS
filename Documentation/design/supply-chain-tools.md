# Supply-chain tools

The tree carries four mechanisms that answer questions about what the build
consumes and whether it can be repeated. All of them run on a developer's
machine, none of them needs a network except where stated, and none of them
signs, publishes or uploads anything: their output is a local file or an exit
status.

| Mechanism | Question it answers | Network |
|-----------|---------------------|---------|
| `tools/sbom.sh` | Which packages, at which versions and licences, make up the kernel workspace? | No |
| `tools/repro_check.sh` | Does building the same sources twice, in different directories, give byte-identical binaries? | No |
| `deny.toml` with `cargo-deny` | Do the dependencies obey the licence, ban and source policy? | Only for the advisory database |
| `third_party/vendor` with `third_party/VENDOR_PIN` | Is the vendored registry tree exactly the one that was reviewed? | No |

`tools/sbom.sh` and `tools/repro_check.sh` are not invoked by any other script
or make target; they are run by hand. The `cargo-deny` run and the vendor check
are rows of the project's verification gate (`tools/gate_tier.sh`,
`tools/ci_check.sh`).

Source: `tools/sbom.sh`, `tools/repro_check.sh`, `deny.toml`,
`third_party/VENDOR_PIN`, `tools/gate_tier.sh`, `tools/ci_check.sh`.

## SBOM: `tools/sbom.sh`

```text
tools/sbom.sh [output-path]
```

The script writes an offline CycloneDX 1.5 JSON document. The default output
is `build/sbom.cdx.json` under the build output root (`AZOS_OUT`, resolved by
`tools/out_dir.py`); a relative path argument is taken from the repository root.

What it does:

- Runs `cargo metadata --offline --locked --format-version 1` at the repository
  root. `--offline` keeps it off the network and `--locked` makes it fail rather
  than update `Cargo.lock`. A failure of that command is the script's failure.
- Turns every package cargo reports into one component: name, version,
  `pkg:cargo/<name>@<version>` as the purl, and the licence expression from the
  package metadata where there is one. A package with a binary target is typed
  `application`, any other `library`; workspace members carry a description
  saying so.
- Does not build anything, so it can run while other work uses the tree.

What it covers and what it does not:

- It covers the dependency graph of the root cargo workspace, which is the
  kernel's. Crates the root `Cargo.toml` excludes (the ring-3 programs, each
  with its own lockfile) and the vendored tree are separate graphs and do not
  appear.
- If a sibling checkout that holds the Python brain exists (the script's
  `BRAIN_DIR`, one level above the repository root), its Python dependencies are
  added as `pkg:pypi/<name>@<version>` components. A pinned lock file
  (`requirements.lock`, `requirements-lock.txt`, `poetry.lock`, `Pipfile.lock`,
  `uv.lock`) is read for `name==version` lines only, so in practice a
  requirements-style lock. Without a lock file, `requirements.txt` is read and
  each name is recorded with the version `unknown` and a purl without a version.
  The script does not guess a resolved version. Python components carry no
  licence.

Source: `tools/sbom.sh`, `tools/out_dir.py`, `Cargo.toml` (`exclude`).

## Reproducibility check: `tools/repro_check.sh`

```text
tools/repro_check.sh [--dry-run] [--keep]
```

The script builds a fixed set of artefacts twice and compares the SHA-256 of
each pair. The target is `riscv64imac-unknown-none-elf`. The set is the table
`ARTIFACTS` at the top of the script: the kernel release image, the ring-3
programs the Makefile builds, and two assembler test programs.

How the two builds differ and what is held equal:

- **Different directories.** Build A uses the checkout. Build B uses a copy made
  with `rsync` (without `.git` and agent state) under its own temporary root.
  A result that depends on where the tree sits is a difference.
- **Clean target directories.** Each artefact has its own `CARGO_TARGET_DIR`
  under that run's temporary root, so neither run reuses a warm cache and the
  script does not race a build in progress in the shared target tree.
- **Fixed time.** `SOURCE_DATE_EPOCH` has the same value in both runs (a
  default in the script, overridable from the environment).
- **Path remapping.** Each run passes `--remap-path-prefix` for its source
  root, for `$HOME/.cargo` and for its own target directory, all mapped to
  shared placeholders. The target directory remap matters because the kernel
  crates `crates/core/limits`, `crates/core/ota` and `crates/drivers/sys` each
  `include!` a file generated under `OUT_DIR`, which sits under the target
  directory, and the release profile keeps debug information.
- **Existing rustflags are kept.** `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`
  replace, rather than merge with, a `rustflags` array in `.cargo/config.toml`.
  The script therefore reads the array for the target out of the relevant
  config file (the root one for the kernel, the crate's own for a ring-3
  program), appends the remap flags and passes the result as
  `CARGO_ENCODED_RUSTFLAGS`.
- **Ring-3 programs build as the Makefile builds them**, with
  `userspace/rustc_stable_metadata.py` as `RUSTC_WRAPPER` and its digest as a
  `--cfg`. Cargo derives `-C metadata` from the absolute path of path
  dependencies that sit outside a crate's own workspace, which changes symbol
  names with the checkout directory; the wrapper replaces it with a value derived
  from the crate name, version, type, target and cfg flags.

The output is a table with one line per artefact, `MATCH` or `DIFFER` with both
digests (or `ERROR` if a file is missing). The exit status is 1 if any line is
not `MATCH`.

Options: `--dry-run` prints every command, with the full rustflags, for both
builds and builds nothing; `--keep` keeps the two temporary roots so a `DIFFER`
can be inspected. The environment can set `CARGO`, `RISCV_AS`, `RISCV_LD` and
`SOURCE_DATE_EPOCH`.

Requirements and cost: the `rsync` command, the nightly toolchain the userspace
builds use, the RISC-V assembler and linker for the two assembler programs,
the kernel configuration `.config`, and the generated
`$AZOS_OUT/build/image_hashes.rs` (make it first; the script stops with a message
if it is missing, except in a dry run). A real run copies the tree once and
builds everything twice, so it is slow and competes for CPU and disk with other
work. Run it after a dependency or toolchain change, or when reproducibility
needs re-checking.

Source: `tools/repro_check.sh`, `userspace/rustc_stable_metadata.py`,
`Cargo.toml` (`[profile.release]`), `crates/core/limits/src/lib.rs`,
`crates/core/ota/src/secure_boot.rs`, `crates/drivers/sys/src/wcet.rs`.

## Dependency policy: `deny.toml`

`deny.toml` configures `cargo-deny` for the repository. The gate's first tier
runs it offline:

```text
cargo metadata --offline --locked --format-version 1 > md.json
cargo deny check --metadata-path md.json --disable-fetch licenses bans sources
```

The metadata comes from cargo directly because `cargo-deny`'s own `cargo fetch`
wants every optional crate in the local registry, including one that is pulled
only for `-Zbuild-std`, which an offline machine lacks. A missing `cargo-deny`
fails the row.

What the file says:

| Table | Setting |
|-------|---------|
| `graph` | Checked for four targets: `riscv64imac-unknown-none-elf`, `aarch64-unknown-none-softfloat`, `x86_64-unknown-none`, `aarch64-apple-darwin`, so a dependency that exists for only one of them cannot slip in. |
| `licenses` | Allowed: MIT, BSD-3-Clause, BSD-2-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0. The project is licensed `Apache-2.0 OR GPL-2.0-only`, so every dependency must be usable under both: a dependency licensed Apache-2.0 alone is refused, and `MIT OR Apache-2.0` passes through its MIT option. Workspace crates are `publish = false` and skipped. The confidence threshold is 0.8. |
| `bans` | Wildcard version requirements are denied (path dependencies between workspace crates are allowed); multiple versions of a crate only warn. `openssl`, `openssl-sys` and `ring` are banned: the project uses pure-Rust cryptography, and `ring` brings assembly that would need vetting per ISA. |
| `sources` | Unknown registries and unknown git sources are denied; only the crates.io index is allowed. |
| `advisories` | Yanked crates denied; the RustSec database is read from `~/.cargo/advisory-db`. Two advisories of the vendored TLS provider are ignored with a written reason: RUSTSEC-2023-0071 (`rsa`, Marvin timing attack, no fix exists: the crate only verifies signatures with public keys, and `userspace/lib/tls` accepts no RSA private key, which `tests/host/tls-tests/tests/rsa.rs` checks) and RUSTSEC-2024-0436 (`paste`, unmaintained: a build-time proc-macro). |

Advisories are not part of the offline run, because the RustSec database is a
git download. With a network, once and by hand:

```text
cargo deny fetch && cargo deny check advisories
```

Only the root workspace lockfile (the kernel's) is checked by that run. The
excluded crates carry their own lockfiles with the same registry crates. The
vendored tree is checked separately, against the same `deny.toml`, by the vendor
check below, which adds `advisories` whenever the database is on disk and
otherwise prints a note that they were not checked. `ring` stays banned there:
the vendored lockfile contains it through a WebAssembly-only edge of
`quinn-proto`, and the graph above has no WebAssembly target.

Source: `deny.toml`, `tools/gate_tier.sh`, `userspace/lib/tls-probe/vendor.py`
(`deny`).

## Vendored registry tree: `third_party/vendor` and `VENDOR_PIN`

`third_party/vendor` is a directory source for crates.io, built for the ring-3
programs that use the standard library and have registry dependencies (the TLS
and QUIC programs under `userspace/`). It holds what the lockfile of
`userspace/lib/tls-probe` names (rustls with the RustCrypto provider and
`quinn-proto` with its dependencies) plus the dependencies of the toolchain's
own `std` workspace, because `-Zbuild-std` resolves them through the same
replacement. The second half moves with `rust-toolchain.toml`: a toolchain
change means regenerating the tree.

How it is used: `tools/sdk_cargo.py --vendored` replaces crates.io by this
directory for that one cargo invocation (`--offline --locked`); the kernel
workspace's cargo config never sees it. The host test crates that need the same
crates (`tests/host/tls-tests`, `tests/host/quic-tests`) point their own
`.cargo/config.toml` at it.

### The pin

`third_party/VENDOR_PIN` has one line per package: name, version, the SHA-256 of
the `.crate` file as crates.io publishes it (the `Cargo.lock` checksum), and the
word `pruned` when the sources were replaced by a stub. Together with
`userspace/lib/tls-probe/Cargo.lock` it is the reviewed state of the tree.

Source: `third_party/VENDOR_PIN`, `userspace/lib/tls-probe/Cargo.lock`.

Pruning: cargo vendors every platform, and the `windows-*` crates are most of
the bytes. They are never built for the project's targets or a Unix host, so the
tree keeps their manifest and licence files and replaces the sources with a
library that is a `compile_error!`. A build that does reach one fails loudly
instead of using a hollow crate. The `package` checksum in each
`.cargo-checksum.json` stays the crates.io one, so `Cargo.lock` still matches;
the `files` map lists what is on disk.

### `userspace/lib/tls-probe/vendor.py`

| Command | Effect |
|---------|--------|
| `vendor.py regen` | Needs a network. Runs `cargo vendor`, prunes, and rewrites `VENDOR_PIN`. |
| `vendor.py check` | Offline. Passes only if the tree is exactly the pin and `cargo-deny` passes on it. |
| `vendor.py --self-test` | A canary for `check`: corrupts a pin, a source file and a checksum in a temporary copy, one at a time; each must make `check` fail. |
| `vendor.py test` | Offline. Runs the probe's host tests on the stable toolchain. |

`check` compares, for every package: the name, version, package checksum and
`pruned` flag against the pin (a line missing from either side is an error);
every file listed in `.cargo-checksum.json` against its SHA-256; and the files on
disk against the checksum file (a file that is not listed is an error). It then
runs `cargo metadata --offline --locked` over the probe's manifest with the
vendor source configured and runs `cargo deny` with `licenses`, `bans` and
`sources` (and `advisories` when the database is present).

The gate runs `check` and `--self-test` as two rows of `tools/ci_check.sh`,
named `vendor: tree == pin` and `vendor: canary`.

Source: `third_party/VENDOR_PIN`, `userspace/lib/tls-probe/vendor.py`
(`tree_errors`, `check`, `self_test`, `prune`), `tools/sdk_cargo.py`,
`tools/ci_check.sh`, `tests/host/tls-tests/.cargo/config.toml`,
`tests/host/quic-tests/.cargo/config.toml`, `mk/userspace.mk`.
