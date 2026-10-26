# Contributing to AzOS

Contributions are welcome. There is no review service-level agreement and no
release process; expect an informal exchange.

## Before you start

- **Open an issue first** for anything larger than a bug fix, so the design
  can be discussed before code is written. A change that does not fit the
  guarantee stated in [`README.md`](README.md) is likely to be declined however
  good it is.
- Bug fixes and small improvements can go straight to a pull request.
- To report a security problem, do **not** open a public issue: see
  [`SECURITY.md`](SECURITY.md).
- The reference documentation is indexed in
  [`Documentation/README.md`](Documentation/README.md); the overview is
  [`ARCHITECTURE.md`](ARCHITECTURE.md).

## License

AzOS is dual-licensed, `Apache-2.0 OR GPL-2.0-only` (see [`LICENSE`](LICENSE)
and [`LICENSES/`](LICENSES)). Contributions are accepted under the contributor
license agreement in [`CLA.md`](CLA.md): you keep your copyright and grant the
maintainer the right to distribute your work under both licenses, and under
other licenses later. Your first pull request must state that you agree to it,
and every commit must carry a `Signed-off-by:` line (`git commit -s`).

Do not submit code copied from other projects unless its license is compatible
with both Apache-2.0 and GPL-2.0-only (MIT, BSD-2/3-Clause, ISC and Zlib are);
say where it came from in the pull request.

## Checks

Run by hand; there is no hosted CI. Every build output goes to `$AZOS_OUT`
(see [`README.md`](README.md)), never into the checkout.

| Command | What it runs |
|---|---|
| `make check0` | `cargo check` for riscv64, aarch64 and x86_64, the output-directory lint, `cargo deny`, and the host suites the diff reaches |
| `make check1` | `check0`, then smoke boots and the QEMU scenarios the diff maps to |
| `make ci` | The full gate (`tools/gate/ci_check.sh`): every feature combination, the host suites and the QEMU scenarios |

A change is expected to leave the gate green. **Warnings count as failures.**
`make help` lists the other targets.

## Code

- Rust, edition 2021, the nightly toolchain pinned by `rust-toolchain.toml`.
- `rustfmt` with the default configuration.
- A new `unsafe` block says why it is sound, in a `// SAFETY:` comment.
- The kernel is built with `panic = "abort"`: a panic is a reset. Code
  reachable from outside the kernel (a system-call argument, a network packet,
  a file on disk) must not panic on any input; use checked or saturating
  arithmetic and `get`, not indexing.
- Public items in the crates under `crates/` carry doc comments.
- Every feature is built for all three ISAs (riscv64, aarch64, x86_64), and
  ISA-specific code lives under the ISA's own directories
  (`arch/<isa>`, `kernel/src/entry/<isa>`).
- Options are Kconfig symbols (`config/Kconfig.*`), not constants in code.

## Tests

- A fix comes with a test that fails without it. If you cannot make it fail by
  reverting the fix, the test does not prove the fix.
- Host-side tests are the crates under `tests/host/`; in-kernel tests use the
  `ktest!` macro (`crates/core/ktest`); QEMU scenarios are rows of
  `tools/gate/ci_check.sh`, mapped to paths in `tools/gate/gate_rows.tsv`.
- Say what a test does **not** cover. A green result proves only what its
  assertions look at.

## Commit messages

An imperative summary line with a scope, then a body that explains **why**:

```
ipc: fix capability generation wrap on free-then-realloc

The generation counter wrapped to a value that aliased a freed capability,
so a stale handle became valid again.
```

## Conduct

Be respectful and assume good faith. Harassment is not tolerated.
