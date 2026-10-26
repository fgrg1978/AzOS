# Safety coding standard

The ten rules SC-1 to SC-10 apply to the crates on the safety and control
path. They exist because a panic in the kernel is a board reset, which on a
machine that moves is a physical event, and because bounded, allocation-free
code is the code that can be reasoned about and checked.

This page says what each rule requires, why, and what checks it. Most rules
are checked in review, not by a tool; the table at the end is the honest
list.


## Scope

Source: this page. `CONTRIBUTING.md` states two of the rules (the `// SAFETY:`
comment and no panic on outside input) for the whole tree.

The rules apply to:

- `crates/core/ipc`, `crates/core/sched`, `crates/core/mm`,
  `crates/core/ota`, `crates/core/crypto`, `crates/core/abi`,
  `crates/core/topology`;
- the architecture crates (`arch/facade`, `arch/api` and the
  per-ISA `arch/*` crates);
- `crates/domains/robot/behavior`.

Other crates (drivers, file systems, networking, the ML runtime) are
encouraged to follow them. Nothing enforces it there.

Test code (`#[cfg(test)]` and the host test crates under `tests/host`) runs on
the host with `std` and is not held to SC-1, SC-3 or SC-4.

## SC-1: no dynamic allocation in safety paths

Source: `crates/core/mm/src/lib.rs`, `crates/core/mm/src/kheap.rs`.

**Rule.** Safety crates do not use `alloc` types (`Box`, `Vec`, `String`,
`BTreeMap`) at run time. Use fixed-size arrays and stack buffers. Pools such
as the capability table, the topology and the run queues are sized at
compile time, from Kconfig.

**Why.** An allocation can fail, and the kernel has no way to page memory out
to recover from it. Fixed sizes also make memory use something a topology
can be admitted against.

**State.** `ipc`, `sched`, `ota`, `crypto`, `abi`, `topology` and `behavior`
do not declare `extern crate alloc`. `crates/core/mm` does: it contains the
kernel heap (`GlobalAlloc` in `crates/core/mm/src/kheap.rs`) and the page
allocators, which is the one place the rule cannot hold.

## SC-2: all loops are bounded

Source: this page.

**Rule.** Every loop has a bound that can be read off the code. Prefer
`for _ in 0..N` with a constant or a value fixed before the loop, and
iterators over fixed-size collections. An unbounded `loop`, or a `while`
whose condition does not move monotonically toward its end, needs a comment
that gives the bound.

**Why.** A bound is what makes worst-case time and termination arguments
possible.

**Exception.** The kernel's idle and event loops sit outside the safety
crates and are unbounded by design.

## SC-3: no panics on a safety path

Source: `Cargo.toml` (`panic = "abort"`), `kernel/src/panic.rs`.

**Rule.** Code reachable from outside the kernel (a syscall argument, a
network packet, a file on disk) must not panic on any input. Do not use
`panic!`, `unwrap()` or `expect()` on a value that can fail at run time, or
slice indexing and arithmetic that can overflow on untrusted values.

**How.**

- Return `Result` or `Option` and propagate with `?`.
- Use `checked_*`, `saturating_*` or `wrapping_*` arithmetic.
- Use `get(idx)` rather than `[idx]` when the index comes from outside.
- Where a panic is the only sensible response to a broken internal invariant,
  say so in a comment and say why it cannot happen.

The kernel is built with `panic = "abort"` in both profiles, so a panic ends
in the panic handler (`kernel/src/panic.rs`), not in unwinding.

## SC-4: no recursion

Source: this page; `tools/lint/stack_chain.py`.

**Rule.** No recursive functions and no recursive types in safety crates.
Traverse trees with an explicit fixed-size stack.

**Why.** Recursion makes stack depth depend on the input, and kernel stacks
are small and fixed.

**State.** No tool refuses recursion. The gate's `stack chain` rows
(`tools/lint/stack_chain.py`, on the riscv64 kernel images) check the deepest static
call chain against the task stack; a recursive cycle is cut at its first repeat
and counted, not measured.

## SC-5: every `unsafe` has a `// SAFETY:` comment

Source: `crates/core/ota/src/lib.rs`, `crates/core/abi/src/lib.rs`,
`tools/lint/unsafe_budget.py`.

**Rule.** Every `unsafe` block and every `unsafe fn` body carries a
`// SAFETY:` comment immediately before it, stating the contract that makes
it sound.

```rust
// SAFETY: the only reference to `UPDATE_WORK`, handed out while the
// `UpdateBusy` it is borrowed under is held.
unsafe { &mut *core::ptr::addr_of_mut!(UPDATE_WORK) }
```

**State.** `crates/core/ota/src/lib.rs` enables `clippy::undocumented_unsafe_blocks`
and `clippy::missing_safety_doc` (at `warn`) together with `clippy::pedantic`,
`clippy::unwrap_used`, `clippy::expect_used` and `clippy::panic`; it lists
`clippy::indexing_slicing` too, then allows it in the same file. No other
safety crate enables a clippy lint, and neither the gate nor `make check0`
runs clippy, so the comment is a review rule everywhere. `crates/core/abi`
is `#![forbid(unsafe_code)]`, which the compiler enforces. The amount of
`unsafe` is held by the unsafe budget (`tools/lint/unsafe_budget.py`, a row of the
gate and of `make check0`): a crate whose count of unsafe blocks, functions,
impls and attributes differs from `tools/lint/unsafe_budget.tsv` fails until the
baseline is updated in the same change. It does not look at the comment.
`CONTRIBUTING.md` asks for the comment on every new `unsafe` block anywhere
in the tree.

## SC-6: type-state where the type system can say it

Source: `crates/core/ipc/src/cap.rs`, `crates/core/actuation/src/estop.rs`, `crates/core/topology/src/types.rs`.

**Rule.** When a runtime invariant can be carried by a type, carry it by a
type, so a violation is a compile error.

**Examples in the tree.**

- `Cap<T>` (`crates/core/ipc/src/cap.rs`): the target kind is in the type, so
  a capability for one kind of object cannot be passed where another is
  expected.
- `ReleaseAuthority` (`crates/core/actuation/src/estop.rs`): the e-stop latch
  can only be released by a caller that holds one, and outside tests only
  the operator signature check produces one.
- `MaybeStr<'a>` (`crates/core/topology/src/types.rs`): a string borrowed from
  already-validated input, with no allocation.

## SC-7: overflow is explicit

Source: `Cargo.toml`.

**Rule.** Arithmetic on values that can be large or untrusted uses
`checked_*`, `saturating_*` or `wrapping_*`, so the intent is written down.
Bare `a + b` is fine when the compiler can see it cannot overflow (constant
inputs) or when the bound is obvious from the surrounding code.

```rust
let next = prev.checked_add(1).ok_or(Errno::EQUOTA)?;
let deadline = now.saturating_add(period);
```

**State.** `overflow-checks = true` in `[profile.release]` in the workspace
`Cargo.toml`, so an unintended overflow aborts instead of wrapping silently.
No lint enforces the explicit form.

## SC-8: no floating point in scheduler and deadline math

Source: `crates/core/topology/src/types.rs`, `crates/core/topology/src/deadline.rs`.

**Rule.** The scheduler, budget and admission code use integers only.

**Why.** Some targets have no floating-point unit, and rounding makes
worst-case reasoning harder.

**How.** Budgets are percentages in a `u8` (`cpu_budget_min_pct` in
`crates/core/topology/src/types.rs`). Deadline feasibility is computed in
`u64` parts per million with the division rounded up, so a task's density is
never understated (`crates/core/topology/src/deadline.rs`).

**Allowed.** Floating point is fine in the ML runtime and in controllers on
platforms that have the hardware for it.

## SC-9: Kani harnesses terminate

Source: `crates/core/ipc/src/cap.rs`, `crates/core/ipc/src/objref.rs`,
`formal/README.md`.

**Rule.** A Kani harness bounds its inputs and any loop so the checker
terminates quickly on default settings.

**How.** The harnesses (`formal/README.md` lists them) constrain their inputs
with `kani::assume`; those in `objref.rs` are straight-line, those in `cap.rs`
carry `#[kani::unwind(17)]`:

```rust
let k: usize = kani::any();
kani::assume(k < KINDS.len());
```

Where a harness does need a loop, add `#[kani::unwind(N)]` with the bound.

## SC-10: traceability

Source: `formal/INVARIANTS.md`, `tools/lint/req_trace.py`.

**Rule.** Every safety property is traceable from the property to the code
that maintains it and to the test, harness or spec that checks it, and the
trace says whether the gate runs the check.

**How.** `formal/INVARIANTS.md` is that trace: one row per invariant, with
the enforcing function and the checking test in separate columns, and a
`REQ-nnn` tag that the code repeats in a `// REQ-nnn` comment above the
enforcing item and each named test. A new safety property gets a row in the
same change.

## What checks each rule

Source: `tools/gate/ci_check.sh`, `tools/gate/gate_tier.sh`, the crates named in each row.

| Rule | Checked by |
|---|---|
| SC-1 | Review. `extern crate alloc` is absent from every safety crate except `mm`. |
| SC-2 | Review. |
| SC-3 | Review. `clippy::unwrap_used`, `expect_used` and `panic` are enabled on `crates/core/ota` only, and nothing runs clippy. |
| SC-4 | Review. The `stack chain` gate rows bound the static call depth; they cut recursion, they do not refuse it. |
| SC-5 | Review; `clippy::undocumented_unsafe_blocks` on `crates/core/ota` only (not run). `#![forbid(unsafe_code)]` on `crates/core/abi`. The unsafe budget row ratchets the count of `unsafe` per crate. |
| SC-6 | Review. |
| SC-7 | `overflow-checks = true` in the release profile; review for the explicit form. |
| SC-8 | Review. No `f32` or `f64` appears in `sched`, `ipc` or `topology`. |
| SC-9 | The gate's `formal: Kani harnesses` row runs every harness of `cap.rs` and `objref.rs` and passes only if all are verified; it reports SKIP, with nothing verified, where `cargo kani` is not installed. |
| SC-10 | `formal/INVARIANTS.md`, kept in step with the code by `tools/lint/req_trace.py`, a row of `make check0` (names, tags and tests exist; whether a check is the right one is review). |
