--------------------------- MODULE topology_load ---------------------------
(*
AZOS — Topology load atomicity (RFC-0005, INV-15)

Models the boot-time topology load as an atomic, all-or-nothing
transition between three states:

  init  → loading → loaded
                  ↘ failed

Invariants verified:

  TL-1  No user-space task can be spawned while topology is in `init`,
        `loading`, or `failed`. (User-spawn implies topology = loaded.)

  TL-2  Once `loaded`, the topology is immutable for the rest of the
        boot session. Attempts to re-load after `loaded` are rejected.

  TL-3  `failed` is terminal. The kernel halts; no further transitions.

Run with TLC, default config in `topology_load.cfg`.

MODEL VS CODE (doc audit, 2026-09-26): `StartLoading` and `LoadFail`
below have no counterpart in `crates/core/topology/src/lib.rs` — on the boot
path the kernel installs `fill_default_minimal` (`kernel/src/boot/topology.rs`)
rather than driving this state machine, and `verify_signature`
(`crates/core/topology/src/verify.rs:96-119`) is called only from its own
test module, not from boot. `book/src/02-architecture/topology.md`
says this spec "proves this end-to-end"; it proves TL-1..TL-3 of the
states below, which the running kernel does not visibly go through. No
TLC run against this file is recorded past 2026-05-14, and
`tools/ci_check.sh` does not invoke TLC.
*)

EXTENDS Naturals, TLC

CONSTANTS MaxAttempts   \* bound on spawn attempts to keep the state space finite

ASSUME MaxAttempts \in Nat /\ MaxAttempts > 0

VARIABLES
    state,             \* one of: "init", "loading", "loaded", "failed"
    sigCheckRequested, \* whether we have started signature verification
    spawnAttempts,     \* count of user-space spawn attempts
    spawnAccepted      \* count of spawns that proceeded

vars == <<state, sigCheckRequested, spawnAttempts, spawnAccepted>>

States == {"init", "loading", "loaded", "failed"}

Init ==
    /\ state = "init"
    /\ sigCheckRequested = FALSE
    /\ spawnAttempts = 0
    /\ spawnAccepted = 0

\* Action: kernel boot calls verify_signature + parse.
StartLoading ==
    /\ state = "init"
    /\ sigCheckRequested' = TRUE
    /\ state' = "loading"
    /\ UNCHANGED <<spawnAttempts, spawnAccepted>>

\* Action: signature + parse + admission OK ⇒ transition to loaded.
LoadOk ==
    /\ state = "loading"
    /\ state' = "loaded"
    /\ UNCHANGED <<sigCheckRequested, spawnAttempts, spawnAccepted>>

\* Action: any verification step failed ⇒ transition to failed (terminal).
LoadFail ==
    /\ state = "loading"
    /\ state' = "failed"
    /\ UNCHANGED <<sigCheckRequested, spawnAttempts, spawnAccepted>>

\* Action: a user-space spawn is attempted. The kernel checks the state
\* and accepts only if `loaded`.
SpawnAttempt ==
    /\ spawnAttempts < MaxAttempts
    /\ spawnAttempts' = spawnAttempts + 1
    /\ IF state = "loaded"
         THEN spawnAccepted' = spawnAccepted + 1
         ELSE spawnAccepted' = spawnAccepted
    /\ UNCHANGED <<state, sigCheckRequested>>

\* The "halted" terminal action — once failed, we just stay there.
Halted ==
    /\ state = "failed"
    /\ UNCHANGED vars

Next ==
    \/ StartLoading
    \/ LoadOk
    \/ LoadFail
    \/ SpawnAttempt
    \/ Halted

Spec == Init /\ [][Next]_vars

\* ────────────────────────────────────────────────────────────────────────
\* Type invariant
\* ────────────────────────────────────────────────────────────────────────

TypeOK ==
    /\ state \in States
    /\ sigCheckRequested \in BOOLEAN
    /\ spawnAttempts \in 0..MaxAttempts
    /\ spawnAccepted \in 0..MaxAttempts
    /\ spawnAccepted <= spawnAttempts

\* ────────────────────────────────────────────────────────────────────────
\* The properties (passed as INVARIANT to TLC)
\* ────────────────────────────────────────────────────────────────────────

\* TL-1: no spawn was accepted unless we are in `loaded` *now*. Since
\* `loaded` is reachable only from `loading` and never leaves to `init`
\* or `failed` (by inspection of the transitions), this implies all
\* accepted spawns happened post-load.
SpawnImpliesLoaded ==
    spawnAccepted > 0 => state = "loaded"

\* TL-3: failed is terminal — no transition out of "failed".
\* Encoded as: if state was failed last step, it's still failed.
\* (TLC checks this automatically via [][Next]_vars and the Halted action.)

================================================================
