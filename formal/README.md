# Formal verification

This directory holds the model-checking artefacts of AzOS. There are two
kinds, and they live in different places.

| What | Where | Tool | Run by the gate |
|---|---|---|---|
| Bounded proofs over Rust source | inline in `crates/core/ipc/src/cap.rs` and `crates/core/ipc/src/objref.rs`, under `#[cfg(kani)]` | Kani | yes, when `cargo kani` is installed |
| State-machine specs | `formal/tla/` | TLA+ / TLC | no |

The system-wide list of guarantees, with the code that enforces each one and
the test or proof that checks it, is `formal/INVARIANTS.md`.

Source: `formal/tla/`, `crates/core/ipc/src/cap.rs`, `crates/core/ipc/src/objref.rs`,
`tools/gate/ci_check.sh`.

## Kani harnesses

Source: `crates/core/ipc/src/cap.rs`, `crates/core/ipc/src/objref.rs`.

The harnesses are compiled only under `cfg(kani)`, so they cost nothing in a
normal build. There is no separate `formal/kani/` source tree.

| Harness | File | Property |
|---|---|---|
| `cap_forge_impossible_empty_slot` | `crates/core/ipc/src/cap.rs` | A handle that names an empty slot never validates, whatever its bits. |
| `cap_revoked_stale` | `crates/core/ipc/src/cap.rs` | After grant and revoke, the handle is never accepted again. |
| `cap_contained_when_degraded` | `crates/core/ipc/src/cap.rs` | In degraded mode a `WRITE` through an otherwise valid cap is refused with `CapError::Contained`; a `READ` still resolves. |
| `cap_derive_never_widens` | `crates/core/ipc/src/cap.rs` | A derived warrant has a subset of the source's rights, no later deadline, no larger quota, exactly one more link of depth (never past `WARRANT_DEPTH_MAX`), and keeps the source's caveats. |
| `cap_perms_required` | `crates/core/ipc/src/cap.rs` | A cap used without the permission bit the use needs is refused with `CapError::MissingPerms`. |
| `pack_unpack_round_trip` | `crates/core/ipc/src/objref.rs` | Every in-range `(index, generation)` pair round-trips through the packed object reference, for each packed kind's layout. |
| `a_taken_slot_generation_is_never_zero` | `crates/core/ipc/src/objref.rs` | `take_slot_gen` never hands out generation 0 or a value past `Layout::gen_max`. |
| `a_bare_index_never_matches_a_live_generation` | `crates/core/ipc/src/objref.rs` | A bare in-range index (generation 0) never equals the generation of a live slot. |

None of the harnesses covers the actuation path (`crates/core/actuation`,
`crates/domains/robot/behavior/src/safety.rs`); the e-stop and motor gate are checked
by host tests, listed in `formal/INVARIANTS.md`.

### How Kani runs

Source: `tools/gate/ci_check.sh` (row `formal: Kani harnesses`), `tests/host/cap-tests/Cargo.toml`.

`tools/gate/ci_check.sh` has a row named `formal: Kani harnesses`. It

- skips (printing `SKIP`, counted neither as pass nor fail) when
  `cargo kani` is not installed;
- otherwise runs `cargo kani --manifest-path tests/host/cap-tests/Cargo.toml`
  with its target directory under `$AZOS_OUT`, from a temporary directory
  outside the tree. `tests/host/cap-tests` pulls `cap.rs` in with `#[path]`
  (`objref.rs` is a submodule of it). The directory matters: inside the tree
  the workspace's `build-std` setting would make Kani's own pinned toolchain
  build the standard library from source, and that toolchain has no
  `rust-src`;
- passes only if Kani reports every harness verified. The expected count is
  the number of `#[kani::proof]` attributes in the two files, so a harness
  added without being verified, or one that stops being picked up, fails the
  row.

To run one harness by hand, use the same manifest path and add
`--harness <name>` after changing to a directory outside the tree.

A harness has to terminate quickly on default settings. Bound the inputs with
`kani::assume` (the harnesses above do) and, where a loop is unavoidable,
with `#[kani::unwind(N)]`.

## TLA+ specs

Source: `formal/tla/cap_table.tla`, `formal/tla/topology_load.tla`, `crates/core/topology/src/state.rs`, `crates/core/topology/src/signed.rs`.

| Spec | Config | Invariants checked |
|---|---|---|
| `formal/tla/cap_table.tla` | `cap_table.cfg` | `TypeOK`, `AtMostOneValidPerSlot`, `RevokedNeverValid`, `GenInRange`, `RetiredNeverReissued` |
| `formal/tla/topology_load.tla` | `topology_load.cfg` | `TypeOK`, `SpawnImpliesLoaded` |

How each model relates to the code:

- `cap_table.tla` models one task's table: per-slot generations that retire
  at `MaxGen` instead of wrapping. In the code, `CapTable::allocate_slot`
  skips a slot whose generation is not below `CapHandle::MAX_GENERATION`, and
  `CapTable::bump_generation` refuses to advance past it; `grant_raw` reaches
  both through `CapTable::grant_warranted`. It is per slot only. The object generation packed
  into the resource of a Port, Shm or IoRing capability (`objref.rs`) is not
  modelled.
- `topology_load.tla` models an all-or-nothing load with the states `init`,
  `loading`, `loaded` and `failed`. The kernel does not drive that state
  machine step by step. It fills a candidate topology, checks it, and
  publishes it only if every check passes (`try_init_with` in
  `crates/core/topology/src/state.rs`; the policy table is
  `signed::decide`). `StartLoading` and `LoadFail` have no direct code
  counterpart. The spec states the property the code is meant to refine: no
  user-space spawn is accepted before a topology is published.

TLC is not part of the gate, so a change to either spec's code counterpart is
not checked against the spec automatically. To run a spec, use TLC from
`tla2tools.jar` (any recent TLA+ tools release; it needs a Java runtime) from
inside `formal/tla/`:

```sh
java -jar /path/to/tla2tools.jar -workers auto -config cap_table.cfg cap_table.tla
java -jar /path/to/tla2tools.jar -workers auto -config topology_load.cfg topology_load.tla
```

TLC writes `states/` and `*_TTrace_*` files next to the spec while it runs;
`.gitignore` already excludes them.

## Maintenance

Source: `formal/INVARIANTS.md`.

- A change to the capability table, the topology admission path, or the
  object-reference layout should update the matching spec or harness in the
  same change.
- A new system-wide guarantee gets a row in `formal/INVARIANTS.md`, with the
  code that enforces it and the test or proof that checks it.
- Spec and harness names follow the code they cover: `cap_table.tla` for
  `crates/core/ipc/src/cap.rs`, `topology_load.tla` for
  `crates/core/topology`.
