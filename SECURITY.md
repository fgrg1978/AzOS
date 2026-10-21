# Security policy

AzOS is in early development. It is **not for production or safety-critical
use**, and no security guarantee is offered. This policy describes how reports
are handled.

## Supported versions

There are no tagged releases and no support window. Only the current state of
`main` is looked at.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it
privately to the maintainer, through the private vulnerability reporting of
the repository on its hosting service. Include:

- the affected crate, module or commit,
- reproduction steps (a proof-of-concept program or a test vector),
- an estimated severity (a CVSS v3.1 vector if you have one),
- whether you intend to disclose publicly, and on what timeline.

The maintainer aims to acknowledge a report within **5 working days** and to
publish a fix within **30 days** for high-severity issues (code execution,
privilege escalation, capability bypass). Lower-severity issues (information
disclosure, denial of service) are batched with later changes.

## Disclosure

Disclosure is coordinated:

- the report is private until a fix exists,
- the fix is developed in a private branch,
- a CVE is requested where one is warranted,
- the fix lands on `main`,
- the advisory is published **30 days after the private report** at the
  earliest, or sooner by agreement with the reporter.

## Cryptographic trust anchors

Source: `crates/core/crypto`, `crates/core/ota`.

| Use | Implementation |
|---|---|
| Ed25519 signature verification (secure boot, configuration, topology, packages, e-stop release) | the `ed25519-dalek` crate, through `crates/core/crypto/src/ed25519.rs` |
| X25519 key agreement | the `curve25519-dalek` crate, through `crates/core/crypto/src/x25519.rs` |
| SHA-256, AES-128 | in-tree implementations (`sha256.rs`, `aes.rs`) |

The production firmware-signing key is not in the repository. The build embeds
only the public half: `crates/core/ota/build.rs` reads
`tools/keys/prod_pub.bin`, or the file named by `$PROD_PUBKEY_PATH`. Without
that file the embedded key is all zeros and the kernel treats the image as
having no trusted key.

## In scope

- The kernel and its crates: `kernel/` and everything under `crates/`.
- Ring-3 services, drivers and libraries under `userspace/`.
- The OTA and secure-boot chain (`crates/core/ota`).
- Capability-typed IPC and the capability tables (`crates/core/ipc`).
- The driver framework (`crates/drivers/api`, `crates/drivers/base`).
- The architecture crates (`crates/core/arch-riscv64`, `arch-aarch64`,
  `arch-x86_64`).

## Out of scope

- Vulnerabilities in third-party dependencies: report them upstream, and
  report here only if AzOS needs a workaround.
- Malformed device-tree blobs. The device tree is assumed to come from trusted
  firmware.
- Timing side channels of the in-tree SHA-256 and AES-128 implementations.
- Bugs in QEMU or in its firmware images.

## Supply chain

- **Dependencies.** The workspace's registry dependencies are declared in the
  root `Cargo.toml` (`[workspace.dependencies]`) and pinned in `Cargo.lock`;
  `crates/core/crypto` adds `ed25519-dalek` and `curve25519-dalek`. The
  registry tree used by the `std` programs is vendored under
  `third_party/vendor`.
- **Policy.** `deny.toml` holds the licence, ban and source policy for
  `cargo deny`.
- **SBOM.** `tools/sbom.sh` writes a CycloneDX software bill of materials.
- **Toolchain.** `rust-toolchain.toml` pins the compiler.
- **Automation.** None of these runs automatically; each is run by hand.
