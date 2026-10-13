# Contributing to AzOS

AzOS is a one-maintainer, early-stage project. Contributions are welcome, but
there is no review service-level agreement, no committee and no release
process: expect a slow and informal exchange.

## Before you start

- **Open an issue first** for anything larger than a bug fix, so the design
  can be discussed before code is written. A change that does not fit the
  guarantee stated in [`README.md`](README.md) is likely to be declined however
  good it is.
- Bug fixes and small improvements can go straight to a pull request.
- To report a security problem, do **not** open a public issue: see
  [`SECURITY.md`](SECURITY.md).

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

The whole gate is one command, and it is run by hand (there is no hosted CI):

```bash
make build/image_hashes.rs     # once, and after any userspace change
bash tools/ci_check.sh         # builds every feature combination, runs the
                               # host test suites and the QEMU scenarios
```

A change is expected to leave it green. **Warnings count as failures.**

## Code

- Rust, edition 2021, the nightly toolchain selected by `rust-toolchain.toml`.
- `rustfmt` with the default configuration.
- A new `unsafe` block should say why it is sound, in a `// SAFETY:` comment.
  For the nine crates on the safety/control path (`ipc`, `sched`, `mm`,
  `ota`, `crypto`, `arch`, `abi`, `topology`, `behavior`), the safety coding
  standard SC-1..SC-10 applies: no dynamic allocation in safety paths (SC-1),
  bounded loops (SC-2), no panics (SC-3), no recursion (SC-4), a `// SAFETY:`
  comment on every `unsafe` (SC-5), type-state on public APIs where possible
  (SC-6), explicit or panic-free overflow (SC-7), no floating point in
  scheduler or deadline math (SC-8), bounded proofs (SC-9), and traceability
  from requirement to code to test (SC-10). Most of these are checked in
  review, not by a lint; do not assume a rule is enforced just because it is
  listed.
- The kernel is built with `panic = "abort"`: a panic on a real board is a
  reset, which on a robot is a physical-safety event. Code reachable from
  outside the kernel (a syscall argument, a network packet, a file on disk)
  must not panic on any input; use checked or saturating arithmetic and
  `get`, not indexing.
- Public items in the crates under `crates/` carry doc comments.

## Tests

- A fix comes with a test that fails without it. If you cannot make it fail by
  reverting the fix, the test does not prove the fix.
- Host-side tests live in the `crates/*-tests` crates; QEMU scenarios are rows
  in `tools/ci_check.sh`.
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
