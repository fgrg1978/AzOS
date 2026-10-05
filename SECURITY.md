# Security Policy

AzOS is in early development. It runs under QEMU; bring-up on real boards
(VisionFive 2, SpacemiT K1) has not happened yet. It is **not used in
production or in safety-critical deployments**, and no security guarantee is
offered. The policy below describes how reports are handled, and will change as
the project matures.

## Supported Versions

There are no tagged releases and no support window. Only the current state of
`main` is looked at, and it is a working branch that is rewritten in place.

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Instead, email the maintainer at the address listed in `Cargo.toml`'s
top-level author field, with subject line prefix `[AZOS-SECURITY]`.
Include:

- Affected crate / module / git SHA
- Reproduction steps (POC code or test vector)
- Estimated severity (CVSS v3.1 vector if known)
- Whether you intend to publicly disclose, and on what timeline

The maintainer will acknowledge within **5 working days** and aim to
ship a patched snapshot within **30 days** for high-severity issues
(remote code execution, privilege escalation, capability bypass).
Lower-severity issues (information disclosure, DoS) are batched with
the next scheduled release.

## Disclosure Policy

We follow **coordinated disclosure**:
- Researcher emails the maintainer privately.
- Patch is developed in a private branch.
- A CVE is requested from MITRE where one is warranted.
- The patch lands on `main`.
- Public disclosure (advisory + patch) happens **30 days after the
  initial private report** at the earliest, or sooner with
  researcher agreement.

## Hall of Fame

No external researchers acknowledged yet. The two security findings
closed in May 2026 (#212 broken X25519, #213 HMAC-SHA256 Ed25519
stub) were self-discovered via the in-tree crypto-tests harness.

## Cryptographic Trust Anchors

- **Secure-boot signature verify**: Ed25519 via the vetted
  `ed25519-dalek` crate (RFC 8032). Replaced an HMAC-SHA256 stub in
  task #213.
- **X25519 ECDH**: `curve25519-dalek` (RFC 7748). Replaced a
  hand-rolled Montgomery ladder that failed RFC 7748 vector 2 in
  task #212.
- **Production firmware-signing key**: no key is in the repository. The
  private half is kept offline by the maintainer; the build embeds only the
  public half (`crates/core/ota/build.rs` reads `tools/keys/prod_pub.bin`, or
  `$PROD_PUBKEY_PATH`).

## In-Scope (welcome reports)

- Kernel crates: anything under `crates/` and `kernel/`
- Brain server (Python): `AzOSRobotBrain/`
- OTA + secure-boot chain
- Capability-typed IPC (RFC-0003)
- Driver framework (RFC-0002)
- Cross-arch substrates (`arch-aarch64`, `arch-x86_64`, `arch-riscv64`)

## Out-of-Scope (please don't report)

- Issues in third-party dependencies — report upstream, then file
  here only if AZOS needs a workaround
- DoS via untrusted device-tree blobs (the bring-up assumption is
  that DTB comes from trusted firmware)
- Side-channel attacks on the hand-rolled SHA-256 / AES-128 impls
  (we know they are not constant-time; switching to vetted libs is
  task #213-follow-up if a use case demands it)
- QEMU host-environment bugs (e.g. SeaBIOS CDROM read failures —
  see task #152 for the catalogue of known QEMU limitations)
- The hardware-pending stubs in `crates/drivers/bus/src/usb_device.rs`
  (DWC2 controller is `NotImplemented` until hardware arrives)

## Supply Chain

- **Dependencies**: minimal external Rust crates. Crypto: `ed25519-dalek`,
  `curve25519-dalek`. Misc: `bitflags`, `log`, `static_assertions`,
  `linked_list_allocator`. Supply-chain policy lives in `deny.toml`
  (`cargo deny check`; run by hand, there is no hosted CI).
- **SBOM / `cargo audit` / `cargo cyclonedx`**: not wired.
- **Build reproducibility**: not hermetic. The toolchain is pinned by
  `rust-toolchain.toml`.
